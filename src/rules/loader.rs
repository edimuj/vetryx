//! JSON rule loader for Vetryx.
//!
//! Loads rules from JSON files in the rules/ directory.

use super::Rule;
use crate::types::{FindingCategory, Severity};
use serde::Deserialize;
use std::path::Path;

/// JSON structure for a rule file.
#[derive(Debug, Deserialize)]
struct RuleFile {
    category: String,
    rules: Vec<JsonRule>,
}

/// JSON structure for a single rule.
#[derive(Debug, Deserialize)]
struct JsonRule {
    id: String,
    title: String,
    description: String,
    severity: String,
    pattern: String,
    #[serde(default)]
    file_extensions: Vec<String>,
    remediation: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

impl JsonRule {
    /// Convert JSON rule to internal Rule struct.
    fn to_rule(&self, category: &str) -> Rule {
        Rule {
            id: self.id.clone(),
            title: self.title.clone(),
            description: self.description.clone(),
            severity: parse_severity(&self.severity),
            category: parse_category(category),
            pattern: self.pattern.clone(),
            file_extensions: self.file_extensions.clone(),
            remediation: self.remediation.clone(),
            enabled: self.enabled,
        }
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Medium,
    }
}

fn parse_category(s: &str) -> FindingCategory {
    match s.to_lowercase().as_str() {
        "code execution" => FindingCategory::CodeExecution,
        "shell execution" => FindingCategory::ShellExecution,
        "prompt injection" => FindingCategory::PromptInjection,
        "credential access" => FindingCategory::CredentialAccess,
        "data exfiltration" => FindingCategory::DataExfiltration,
        "obfuscation" => FindingCategory::Obfuscation,
        "hidden content" => FindingCategory::HiddenInstructions,
        "sensitive file access" => FindingCategory::SensitiveFileAccess,
        "authority impersonation" => FindingCategory::AuthorityImpersonation,
        other => FindingCategory::Other(other.to_string()),
    }
}

/// Load rules from a JSON file.
pub fn load_rules_from_file(path: &Path) -> Result<Vec<Rule>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let rule_file: RuleFile = serde_json::from_str(&content)?;

    let rules: Vec<Rule> = rule_file
        .rules
        .iter()
        .map(|r| r.to_rule(&rule_file.category))
        .collect();

    Ok(rules)
}

/// Load all rules from JSON files in a directory.
pub fn load_rules_from_directory(dir: &Path) -> Result<Vec<Rule>, Box<dyn std::error::Error>> {
    let mut all_rules = Vec::new();

    if !dir.exists() {
        return Ok(all_rules);
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().map(|e| e == "json").unwrap_or(false) {
            // Skip schema file
            if path.file_name().map(|n| n == "rule-schema.json").unwrap_or(false) {
                continue;
            }

            match load_rules_from_file(&path) {
                Ok(rules) => {
                    tracing::debug!("Loaded {} rules from {:?}", rules.len(), path);
                    all_rules.extend(rules);
                }
                Err(e) => {
                    tracing::warn!("Failed to load rules from {:?}: {}", path, e);
                }
            }
        }
    }

    Ok(all_rules)
}

/// Load rules from the embedded rules directory (compile-time).
/// Falls back to runtime loading if files exist.
pub fn load_builtin_json_rules() -> Vec<Rule> {
    // Try to load from the rules/ directory relative to the crate root
    let rules_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("rules");

    match load_rules_from_directory(&rules_dir) {
        Ok(rules) if !rules.is_empty() => {
            tracing::info!("Loaded {} rules from JSON files", rules.len());
            rules
        }
        Ok(_) => {
            tracing::debug!("No JSON rules found, using compiled patterns");
            Vec::new()
        }
        Err(e) => {
            tracing::warn!("Failed to load JSON rules: {}, using compiled patterns", e);
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_severity() {
        assert!(matches!(parse_severity("critical"), Severity::Critical));
        assert!(matches!(parse_severity("HIGH"), Severity::High));
        assert!(matches!(parse_severity("Medium"), Severity::Medium));
        assert!(matches!(parse_severity("low"), Severity::Low));
        assert!(matches!(parse_severity("info"), Severity::Info));
    }

    #[test]
    fn test_load_json_rules() {
        let rules = load_builtin_json_rules();
        assert!(!rules.is_empty(), "Should load at least some JSON rules");
    }
}
