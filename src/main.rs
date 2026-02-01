//! CLI entry point for the agent-security scanner.

use agent_security::{
    cli::{Cli, Commands},
    config::{generate_default_config, Config},
    decoders::Decoder,
    reporters::{report, OutputFormat},
    rules::patterns::builtin_rules,
    AiAnalyzerConfig, AiBackend, AnalyzerConfig, Platform, ScanConfig, Scanner, Severity,
};
use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use std::io;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| log_level.into()))
        .with_target(false)
        .init();

    // Load config file if specified, otherwise use defaults
    let base_config = if let Some(ref config_path) = cli.config {
        Config::load(config_path)?
    } else {
        Config::load_default()
    };

    match cli.command {
        Commands::Scan {
            path,
            platform,
            ai,
            ai_backend,
            output,
            min_severity,
            fail_on,
            skip_deps,
            enable_entropy,
            trusted_packages,
        } => {
            // Parse platform
            let platform: Option<Platform> = platform
                .map(|p| p.parse())
                .transpose()
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            // Parse severity
            let min_severity = parse_severity(&min_severity)?;
            let fail_on_severity = fail_on.as_ref().map(|s| parse_severity(s)).transpose()?;

            // Build filter config from base + CLI overrides
            let mut filter_config = base_config;
            if skip_deps {
                filter_config.skip_node_modules = true;
            }
            for pkg in trusted_packages {
                if !filter_config.trusted_packages.contains(&pkg) {
                    filter_config.trusted_packages.push(pkg);
                }
            }

            // Build static analyzer config
            let mut static_config = AnalyzerConfig::default();
            if enable_entropy {
                static_config.enable_entropy = true;
            }

            // Build scan config
            let mut config = ScanConfig {
                enable_ai: ai,
                platform,
                min_severity,
                filter_config,
                static_config,
                ..Default::default()
            };

            // Configure AI if enabled
            if ai {
                let backend = match ai_backend.to_lowercase().as_str() {
                    "claude" => AiBackend::Claude,
                    "openai" => AiBackend::OpenAi,
                    "ollama" => AiBackend::Ollama,
                    _ => {
                        return Err(anyhow::anyhow!("Unknown AI backend: {}", ai_backend));
                    }
                };

                let api_key = match backend {
                    AiBackend::Claude => std::env::var("ANTHROPIC_API_KEY").ok(),
                    AiBackend::OpenAi => std::env::var("OPENAI_API_KEY").ok(),
                    AiBackend::Ollama => None,
                    AiBackend::Local => None,
                };

                config.ai_config = Some(AiAnalyzerConfig {
                    backend,
                    api_key,
                    ..Default::default()
                });
            }

            // Run scanner
            let scanner = Scanner::with_config(config)?;
            let scan_report = scanner.scan_path(&path).await?;

            // Output format
            let format: OutputFormat = cli.format.parse().map_err(|e| anyhow::anyhow!("{}", e))?;

            // Write output
            if let Some(output_path) = output {
                let mut file = std::fs::File::create(&output_path)?;
                report(&scan_report, format, &mut file)?;
                eprintln!("Report written to: {}", output_path.display());
            } else {
                let mut stdout = io::stdout().lock();
                report(&scan_report, format, &mut stdout)?;
            }

            // Check fail condition
            if let Some(fail_severity) = fail_on_severity {
                if let Some(max_sev) = scan_report.max_severity() {
                    if max_sev >= fail_severity {
                        std::process::exit(1);
                    }
                }
            }
        }

        Commands::Watch { platform, notify } => {
            let platform: Option<Platform> = platform
                .map(|p| p.parse())
                .transpose()
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            eprintln!(
                "{}",
                "Watch mode is not yet implemented.".yellow()
            );
            eprintln!("Platform: {:?}", platform);
            eprintln!("Notify: {}", notify);

            // TODO: Implement file watching with the `notify` crate
        }

        Commands::List { platform } => {
            let platform: Option<Platform> = platform
                .map(|p| p.parse())
                .transpose()
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            let resolved_platform = platform.or_else(agent_security::adapters::detect_platform);

            match resolved_platform {
                Some(p) => {
                    let adapter = agent_security::adapters::create_adapter(p);
                    let components = adapter.discover()?;

                    println!("{}", format!("Platform: {}", p).bold());
                    println!("Discovered {} components:\n", components.len());

                    for component in components {
                        println!(
                            "  {} [{}]",
                            component.path.display(),
                            format!("{}", component.component_type).dimmed()
                        );
                    }
                }
                None => {
                    eprintln!("Could not detect platform. Specify --platform.");
                    std::process::exit(1);
                }
            }
        }

        Commands::Rules { rule, json } => {
            let rules = builtin_rules();

            if let Some(rule_id) = rule {
                // Show specific rule
                if let Some(r) = rules.iter().find(|r| r.id == rule_id) {
                    if json {
                        println!("{}", serde_json::to_string_pretty(r)?);
                    } else {
                        println!("{}", format!("Rule: {}", r.id).bold());
                        println!("Title:       {}", r.title);
                        println!("Severity:    {}", r.severity);
                        println!("Category:    {}", r.category);
                        println!("Description: {}", r.description);
                        println!("Pattern:     {}", r.pattern);
                        if !r.file_extensions.is_empty() {
                            println!("Extensions:  {}", r.file_extensions.join(", "));
                        }
                        if let Some(ref rem) = r.remediation {
                            println!("Remediation: {}", rem);
                        }
                    }
                } else {
                    eprintln!("Rule not found: {}", rule_id);
                    std::process::exit(1);
                }
            } else {
                // List all rules
                if json {
                    println!("{}", serde_json::to_string_pretty(&rules)?);
                } else {
                    println!("{}", "Available Rules".bold().underline());
                    println!();

                    let mut current_category = String::new();
                    let mut sorted_rules = rules.clone();
                    sorted_rules.sort_by(|a, b| format!("{}", a.category).cmp(&format!("{}", b.category)));

                    for r in sorted_rules {
                        let cat = format!("{}", r.category);
                        if cat != current_category {
                            println!("\n{}", cat.bold());
                            current_category = cat;
                        }

                        let severity_color = match r.severity {
                            Severity::Critical => r.severity.to_string().bright_red(),
                            Severity::High => r.severity.to_string().red(),
                            Severity::Medium => r.severity.to_string().yellow(),
                            Severity::Low => r.severity.to_string().blue(),
                            Severity::Info => r.severity.to_string().white(),
                        };

                        println!(
                            "  {} [{}] - {}",
                            r.id.bright_cyan(),
                            severity_color,
                            r.title
                        );
                    }
                    println!();
                    println!("Total: {} rules", rules.len());
                }
            }
        }

        Commands::Decode { input, depth } => {
            let decoder = Decoder::new();
            let layers = decoder.decode_recursive(&input, depth);

            if layers.is_empty() {
                println!("No encodings detected in input.");
            } else {
                println!("{}", "Decoded content:".bold());
                for (i, layer) in layers.iter().enumerate() {
                    println!("\n{}", format!("Layer {} (depth {})", i + 1, i + 1).underline());
                    for decoded in layer {
                        println!("  Encoding: {}", decoded.encoding.to_string().cyan());
                        println!("  Original: {}", truncate(&decoded.original, 60).dimmed());
                        println!("  Decoded:  {}", decoded.decoded.green());
                    }
                }
            }
        }

        Commands::Init { output } => {
            if output.exists() {
                eprintln!(
                    "{}",
                    format!("Config file already exists: {}", output.display()).yellow()
                );
                eprintln!("Use a different path or remove the existing file.");
                std::process::exit(1);
            }

            std::fs::write(&output, generate_default_config())?;
            println!(
                "{}",
                format!("Created config file: {}", output.display()).green()
            );
            println!("Edit this file to customize allowlists and trusted packages.");
        }
    }

    Ok(())
}

fn parse_severity(s: &str) -> Result<Severity> {
    match s.to_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" | "med" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" | "crit" => Ok(Severity::Critical),
        _ => Err(anyhow::anyhow!("Unknown severity: {}", s)),
    }
}

fn truncate(s: &str, max: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max).collect();
        format!("{}...", truncated)
    }
}
