//! Security detection rules for the scanner.

pub mod patterns;

use crate::types::{FindingCategory, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// A detection rule that matches suspicious patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique identifier for this rule.
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Detailed description of what this rule detects.
    pub description: String,
    /// Severity when this rule matches.
    pub severity: Severity,
    /// Category of the finding.
    pub category: FindingCategory,
    /// Regex pattern to match (as string for serialization).
    pub pattern: String,
    /// File extensions this rule applies to (empty = all).
    #[serde(default)]
    pub file_extensions: Vec<String>,
    /// Suggested remediation.
    pub remediation: Option<String>,
    /// Whether this rule is enabled by default.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Rule {
    /// Compile the regex pattern for this rule.
    pub fn compile(&self) -> Result<CompiledRule, regex::Error> {
        let regex = Regex::new(&self.pattern)?;
        Ok(CompiledRule {
            rule: self.clone(),
            regex,
        })
    }

    /// Check if this rule applies to a given file extension.
    pub fn applies_to_extension(&self, ext: &str) -> bool {
        if self.file_extensions.is_empty() {
            return true;
        }
        self.file_extensions
            .iter()
            .any(|e| e.eq_ignore_ascii_case(ext))
    }
}

/// A rule with its compiled regex.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule: Rule,
    pub regex: Regex,
}

impl CompiledRule {
    /// Find all matches in the given content.
    pub fn find_matches<'a>(&'a self, content: &'a str) -> impl Iterator<Item = regex::Match<'a>> {
        self.regex.find_iter(content)
    }
}

/// Collection of rules that can be loaded and managed.
#[derive(Debug, Default)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
}

impl RuleSet {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Load the built-in rules.
    pub fn with_builtin_rules(mut self) -> Result<Self, regex::Error> {
        for rule in patterns::builtin_rules() {
            if rule.enabled {
                self.rules.push(rule.compile()?);
            }
        }
        Ok(self)
    }

    /// Add a custom rule.
    pub fn add_rule(&mut self, rule: Rule) -> Result<(), regex::Error> {
        self.rules.push(rule.compile()?);
        Ok(())
    }

    /// Get all rules.
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// Get rules applicable to a file extension.
    pub fn rules_for_extension(&self, ext: &str) -> Vec<&CompiledRule> {
        self.rules
            .iter()
            .filter(|r| r.rule.applies_to_extension(ext))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_compilation() {
        let rule = Rule {
            id: "test-001".to_string(),
            title: "Test Rule".to_string(),
            description: "A test rule".to_string(),
            severity: Severity::Medium,
            category: FindingCategory::CodeExecution,
            pattern: r"eval\s*\(".to_string(),
            file_extensions: vec!["js".to_string(), "ts".to_string()],
            remediation: None,
            enabled: true,
        };

        let compiled = rule.compile().unwrap();
        assert!(compiled.regex.is_match("eval(code)"));
        assert!(compiled.regex.is_match("eval (code)"));
        assert!(!compiled.regex.is_match("evaluate(code)"));
    }
}
