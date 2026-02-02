//! Detector for computed property access to dangerous functions.
//!
//! Detects patterns like:
//! - `window['eval'](code)`
//! - `globalThis["eval"](code)`
//! - `global['Function'](code)`

use super::Detector;
use crate::analyzers::ast::scope::ScopeTracker;
use crate::types::{Finding, FindingCategory, Location, Severity};
use std::path::Path;
use tree_sitter::Node;

/// Dangerous global objects that can access dangerous functions.
const DANGEROUS_GLOBALS: &[&str] = &["window", "globalThis", "global", "self", "this"];

/// Dangerous function names that can be accessed via computed properties.
const DANGEROUS_FUNCTIONS: &[&str] = &[
    "eval",
    "Function",
    "setTimeout",
    "setInterval",
    "setImmediate",
];

pub struct ComputedAccessDetector;

impl ComputedAccessDetector {
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
        } else if text.starts_with('`') && text.ends_with('`') {
            Some(text[1..text.len() - 1].to_string())
        } else {
            None
        }
    }
}

impl Default for ComputedAccessDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ComputedAccessDetector {
    fn rule_id(&self) -> &'static str {
        "AST-EXEC-001"
    }

    fn title(&self) -> &'static str {
        "Computed property access to dangerous function"
    }

    fn handles_node_type(&self, node_type: &str) -> bool {
        node_type == "subscript_expression" || node_type == "call_expression"
    }

    fn analyze(
        &self,
        node: Node,
        source: &str,
        path: &Path,
        _scope_tracker: &ScopeTracker,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Handle call_expression with subscript as callee
        // e.g., window['eval'](code)
        if node.kind() == "call_expression" {
            if let Some(callee) = node.child_by_field_name("function") {
                if callee.kind() == "subscript_expression" {
                    findings.extend(self.check_subscript(callee, source, path));
                }
            }
            return findings;
        }

        // Handle subscript_expression directly
        // e.g., window['eval']
        if node.kind() == "subscript_expression" {
            findings.extend(self.check_subscript(node, source, path));
        }

        findings
    }
}

impl ComputedAccessDetector {
    fn check_subscript(&self, node: Node, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Get the object being accessed (e.g., "window" in window['eval'])
        let object = match node.child_by_field_name("object") {
            Some(obj) => obj,
            None => return findings,
        };

        let object_text = match object.utf8_text(source.as_bytes()) {
            Ok(text) => text,
            Err(_) => return findings,
        };

        // Check if accessing a dangerous global
        if !DANGEROUS_GLOBALS.contains(&object_text) {
            return findings;
        }

        // Get the index (property being accessed)
        let index = match node.child_by_field_name("index") {
            Some(idx) => idx,
            None => return findings,
        };

        // Check if it's a string literal
        if index.kind() != "string" {
            return findings;
        }

        // Get the string value
        let property = match Self::get_string_value(index, source) {
            Some(s) => s,
            None => return findings,
        };

        // Check if it's a dangerous function
        if DANGEROUS_FUNCTIONS.contains(&property.as_str()) {
            let snippet = node
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
                        "Computed property access to '{}' on '{}' can execute arbitrary code. \
                        This pattern is often used to evade regex-based detection.",
                        property, object_text
                    ),
                    Severity::Critical,
                    FindingCategory::CodeExecution,
                    Location::new(path.to_path_buf(), start_line, end_line)
                        .with_columns(node.start_position().column + 1, node.end_position().column + 1),
                    snippet,
                )
                .with_remediation("Remove dynamic property access to dangerous functions.")
                .with_metadata("technique", "computed_property_access")
                .with_metadata("function", property)
                .with_metadata("ast_analyzed", "true"),
            );
        }

        findings
    }
}
