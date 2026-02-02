//! Detector for comma operator indirect calls.
//!
//! Detects patterns like:
//! - `(0, eval)(code)` - indirect eval call
//! - `(1, Function)('return this')()` - indirect Function constructor
//!
//! The comma operator trick is used to change the `this` binding
//! and evade detection of direct calls.

use super::Detector;
use crate::analyzers::ast::scope::{is_global_dangerous_function, ScopeTracker};
use crate::types::{Finding, FindingCategory, Location, Severity};
use std::path::Path;
use tree_sitter::Node;

pub struct CommaOperatorDetector;

impl CommaOperatorDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CommaOperatorDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for CommaOperatorDetector {
    fn rule_id(&self) -> &'static str {
        "AST-EXEC-005"
    }

    fn title(&self) -> &'static str {
        "Comma operator indirect call to dangerous function"
    }

    fn handles_node_type(&self, node_type: &str) -> bool {
        node_type == "call_expression"
    }

    fn analyze(
        &self,
        node: Node,
        source: &str,
        path: &Path,
        _scope_tracker: &ScopeTracker,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        if node.kind() != "call_expression" {
            return findings;
        }

        // Get the callee (function being called)
        let callee = match node.child_by_field_name("function") {
            Some(c) => c,
            None => return findings,
        };

        // We're looking for (expr, func)(args) pattern
        // The callee should be a parenthesized_expression containing a sequence_expression
        if callee.kind() != "parenthesized_expression" {
            return findings;
        }

        // Get the inner expression
        let inner = match callee.named_child(0) {
            Some(i) => i,
            None => return findings,
        };

        // Check if it's a sequence expression (comma operator)
        if inner.kind() != "sequence_expression" {
            return findings;
        }

        // The last expression in the sequence is what's actually called
        // Find the rightmost named child in the sequence expression
        let mut cursor = inner.walk();
        let named_children: Vec<_> = inner.named_children(&mut cursor).collect();

        // The last named child is the target (e.g., "eval" in "(0, eval)")
        let target = match named_children.last() {
            Some(t) => *t,
            None => return findings,
        };

        // Check if the target is a dangerous identifier
        if target.kind() != "identifier" {
            return findings;
        }

        let target_name = match target.utf8_text(source.as_bytes()) {
            Ok(text) => text,
            Err(_) => return findings,
        };

        if is_global_dangerous_function(target_name) {
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
                        "Comma operator pattern '(expr, {})()' is used to call '{}' indirectly. \
                        This technique changes the 'this' binding and evades direct call detection.",
                        target_name, target_name
                    ),
                    Severity::Critical,
                    FindingCategory::CodeExecution,
                    Location::new(path.to_path_buf(), start_line, end_line)
                        .with_columns(callee.start_position().column + 1, callee.end_position().column + 1),
                    snippet,
                )
                .with_remediation("Remove the indirect call pattern.")
                .with_metadata("technique", "comma_operator_indirect_call")
                .with_metadata("function", target_name.to_string())
                .with_metadata("ast_analyzed", "true"),
            );
        }

        findings
    }
}
