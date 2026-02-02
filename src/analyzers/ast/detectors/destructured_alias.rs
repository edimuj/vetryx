//! Detector for destructured and aliased imports.
//!
//! Detects patterns like:
//! - `const {exec: run} = require('child_process'); run(cmd)`
//! - `const {execSync: e} = require('child_process'); e(cmd)`
//! - `import {exec as run} from 'child_process'; run(cmd)`

use super::Detector;
use crate::analyzers::ast::scope::ScopeTracker;
use crate::types::{Finding, FindingCategory, Location, Severity};
use std::path::Path;
use tree_sitter::Node;

/// Dangerous modules.
const DANGEROUS_MODULES: &[&str] = &["child_process", "node:child_process"];

/// Dangerous exports from child_process.
const DANGEROUS_EXPORTS: &[&str] = &[
    "exec",
    "execSync",
    "spawn",
    "spawnSync",
    "execFile",
    "execFileSync",
    "fork",
];

pub struct DestructuredAliasDetector;

impl DestructuredAliasDetector {
    pub fn new() -> Self {
        Self
    }

    /// Extract the string value from a string node.
    fn get_string_value(node: Node, source: &str) -> Option<String> {
        let text = node.utf8_text(source.as_bytes()).ok()?;
        // Remove quotes
        if (text.starts_with('"') && text.ends_with('"'))
            || (text.starts_with('\'') && text.ends_with('\''))
        {
            Some(text[1..text.len() - 1].to_string())
        } else {
            None
        }
    }
}

impl Default for DestructuredAliasDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for DestructuredAliasDetector {
    fn rule_id(&self) -> &'static str {
        "AST-SHELL-001"
    }

    fn title(&self) -> &'static str {
        "Destructured and aliased shell execution"
    }

    fn handles_node_type(&self, node_type: &str) -> bool {
        node_type == "variable_declarator" || node_type == "import_specifier"
    }

    fn analyze(
        &self,
        node: Node,
        source: &str,
        path: &Path,
        _scope_tracker: &ScopeTracker,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        match node.kind() {
            "variable_declarator" => {
                findings.extend(self.analyze_require_destructure(node, source, path));
            }
            "import_specifier" => {
                findings.extend(self.analyze_import_alias(node, source, path));
            }
            _ => {}
        }

        findings
    }
}

impl DestructuredAliasDetector {
    /// Analyze `const {exec: run} = require('child_process')` patterns.
    fn analyze_require_destructure(
        &self,
        node: Node,
        source: &str,
        path: &Path,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Get the name pattern (left side of declarator)
        let name = match node.child_by_field_name("name") {
            Some(n) => n,
            None => return findings,
        };

        // We need an object_pattern for destructuring
        if name.kind() != "object_pattern" {
            return findings;
        }

        // Get the value (right side - should be a call to require)
        let value = match node.child_by_field_name("value") {
            Some(v) => v,
            None => return findings,
        };

        // Check if it's a call expression
        if value.kind() != "call_expression" {
            return findings;
        }

        // Get the function being called
        let func = match value.child_by_field_name("function") {
            Some(f) => f,
            None => return findings,
        };

        // Check if it's require()
        let func_name = match func.utf8_text(source.as_bytes()) {
            Ok(text) => text,
            Err(_) => return findings,
        };

        if func_name != "require" {
            return findings;
        }

        // Get the arguments to require()
        let args = match value.child_by_field_name("arguments") {
            Some(a) => a,
            None => return findings,
        };

        // Get the first argument (module name)
        let first_arg = match args.named_child(0) {
            Some(a) => a,
            None => return findings,
        };

        // Get the module name
        let module = if first_arg.kind() == "string" {
            match Self::get_string_value(first_arg, source) {
                Some(m) => m,
                None => return findings,
            }
        } else {
            return findings;
        };

        // Check if it's a dangerous module
        if !DANGEROUS_MODULES.contains(&module.as_str()) {
            return findings;
        }

        // Now check the object pattern for aliased properties
        // Look for patterns like {exec: run} where exec is dangerous
        let mut cursor = name.walk();
        for child in name.named_children(&mut cursor) {
            if child.kind() == "shorthand_property_identifier_pattern" {
                // Not aliased: const {exec} = require(...)
                let prop_name = match child.utf8_text(source.as_bytes()) {
                    Ok(text) => text,
                    Err(_) => continue,
                };

                if DANGEROUS_EXPORTS.contains(&prop_name) {
                    // Not aliased, but still destructured - let regular detection handle it
                    continue;
                }
            } else if child.kind() == "pair_pattern" {
                // Aliased: const {exec: run} = require(...)
                let key = match child.child_by_field_name("key") {
                    Some(k) => k,
                    None => continue,
                };

                let value_node = match child.child_by_field_name("value") {
                    Some(v) => v,
                    None => continue,
                };

                let original_name = match key.utf8_text(source.as_bytes()) {
                    Ok(text) => text,
                    Err(_) => continue,
                };

                let alias_name = match value_node.utf8_text(source.as_bytes()) {
                    Ok(text) => text,
                    Err(_) => continue,
                };

                // Check if the original name is a dangerous export
                if DANGEROUS_EXPORTS.contains(&original_name) && original_name != alias_name {
                    let snippet = node
                        .utf8_text(source.as_bytes())
                        .unwrap_or("")
                        .to_string();

                    let start_line = child.start_position().row + 1;
                    let end_line = child.end_position().row + 1;

                    findings.push(
                        Finding::new(
                            self.rule_id(),
                            self.title(),
                            format!(
                                "Destructuring aliases '{}' to '{}' from '{}'. \
                                Using '{}()' will execute shell commands while evading detection.",
                                original_name, alias_name, module, alias_name
                            ),
                            Severity::High,
                            FindingCategory::ShellExecution,
                            Location::new(path.to_path_buf(), start_line, end_line)
                                .with_columns(child.start_position().column + 1, child.end_position().column + 1),
                            snippet,
                        )
                        .with_remediation("Remove the aliasing or use the original function name for clarity.")
                        .with_metadata("technique", "destructured_aliasing")
                        .with_metadata("original", original_name.to_string())
                        .with_metadata("alias", alias_name.to_string())
                        .with_metadata("module", module.clone())
                        .with_metadata("ast_analyzed", "true"),
                    );
                }
            }
        }

        findings
    }

    /// Analyze `import {exec as run} from 'child_process'` patterns.
    fn analyze_import_alias(&self, node: Node, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Get the imported name (original) and local name (alias)
        let name = match node.child_by_field_name("name") {
            Some(n) => n,
            None => return findings,
        };

        let alias = match node.child_by_field_name("alias") {
            Some(a) => a,
            None => return findings, // No alias, not what we're looking for
        };

        let original_name = match name.utf8_text(source.as_bytes()) {
            Ok(text) => text,
            Err(_) => return findings,
        };

        let alias_name = match alias.utf8_text(source.as_bytes()) {
            Ok(text) => text,
            Err(_) => return findings,
        };

        // Only report if there's an actual alias (different name)
        if original_name == alias_name {
            return findings;
        }

        // Check if the original name is a dangerous export
        if !DANGEROUS_EXPORTS.contains(&original_name) {
            return findings;
        }

        // Walk up to find the import_statement and get the source
        let mut parent = node.parent();
        while let Some(p) = parent {
            if p.kind() == "import_statement" {
                // Get the source (module name)
                if let Some(source_node) = p.child_by_field_name("source") {
                    if let Some(module) = Self::get_string_value(source_node, source) {
                        if DANGEROUS_MODULES.contains(&module.as_str()) {
                            let snippet = p
                                .utf8_text(source.as_bytes())
                                .unwrap_or("")
                                .to_string();

                            let start_line = node.start_position().row + 1;
                            let end_line = node.end_position().row + 1;

                            findings.push(
                                Finding::new(
                                    self.rule_id(),
                                    self.title(),
                                    format!(
                                        "Import aliases '{}' to '{}' from '{}'. \
                                        Using '{}()' will execute shell commands while evading detection.",
                                        original_name, alias_name, module, alias_name
                                    ),
                                    Severity::High,
                                    FindingCategory::ShellExecution,
                                    Location::new(path.to_path_buf(), start_line, end_line)
                                        .with_columns(node.start_position().column + 1, node.end_position().column + 1),
                                    snippet,
                                )
                                .with_remediation("Remove the aliasing or use the original function name for clarity.")
                                .with_metadata("technique", "import_aliasing")
                                .with_metadata("original", original_name.to_string())
                                .with_metadata("alias", alias_name.to_string())
                                .with_metadata("module", module)
                                .with_metadata("ast_analyzed", "true"),
                            );
                        }
                    }
                }
                break;
            }
            parent = p.parent();
        }

        findings
    }
}
