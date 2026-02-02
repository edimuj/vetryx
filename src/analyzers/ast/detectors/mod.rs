//! Detection patterns for obfuscated malicious code.
//!
//! Each detector analyzes specific AST node types to find patterns that
//! regex-based scanning cannot catch.

mod computed_access;
mod variable_aliasing;
mod string_concat;
mod escape_sequences;
mod comma_operator;
mod destructured_alias;

pub use computed_access::ComputedAccessDetector;
pub use variable_aliasing::VariableAliasingDetector;
pub use string_concat::StringConcatDetector;
pub use escape_sequences::EscapeSequenceDetector;
pub use comma_operator::CommaOperatorDetector;
pub use destructured_alias::DestructuredAliasDetector;

use crate::types::Finding;
use std::path::Path;
use tree_sitter::Node;

use super::scope::ScopeTracker;

/// A detector that analyzes AST nodes for specific malicious patterns.
pub trait Detector: Send + Sync {
    /// Returns the unique rule ID for this detector.
    fn rule_id(&self) -> &'static str;

    /// Returns the human-readable title for findings from this detector.
    fn title(&self) -> &'static str;

    /// Check if this detector should analyze a given node type.
    fn handles_node_type(&self, node_type: &str) -> bool;

    /// Analyze a node and return any findings.
    fn analyze(
        &self,
        node: Node,
        source: &str,
        path: &Path,
        scope_tracker: &ScopeTracker,
    ) -> Vec<Finding>;
}

/// Collection of all detectors.
pub struct DetectorSet {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorSet {
    /// Create a new detector set with all built-in detectors.
    pub fn new() -> Self {
        Self {
            detectors: vec![
                Box::new(ComputedAccessDetector::new()),
                Box::new(VariableAliasingDetector::new()),
                Box::new(StringConcatDetector::new()),
                Box::new(EscapeSequenceDetector::new()),
                Box::new(CommaOperatorDetector::new()),
                Box::new(DestructuredAliasDetector::new()),
            ],
        }
    }

    /// Get all detectors that handle a specific node type.
    pub fn for_node_type(&self, node_type: &str) -> Vec<&dyn Detector> {
        self.detectors
            .iter()
            .filter(|d| d.handles_node_type(node_type))
            .map(|d| d.as_ref())
            .collect()
    }

    /// Get all detectors.
    pub fn all(&self) -> &[Box<dyn Detector>] {
        &self.detectors
    }
}

impl Default for DetectorSet {
    fn default() -> Self {
        Self::new()
    }
}
