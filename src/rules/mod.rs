//! Security detection rules for the scanner.

pub mod loader;
pub mod patterns;

use crate::types::{FindingCategory, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Source of a rule (official or community).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleSource {
    #[default]
    Official,
    Community,
}

impl fmt::Display for RuleSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleSource::Official => write!(f, "official"),
            RuleSource::Community => write!(f, "community"),
        }
    }
}

/// Test cases for validating rule patterns.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TestCases {
    /// Strings that should match the rule pattern.
    #[serde(default)]
    pub should_match: Vec<String>,
    /// Strings that should NOT match the rule pattern.
    #[serde(default)]
    pub should_not_match: Vec<String>,
}

/// Metadata for community-contributed rules.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleMetadata {
    /// GitHub username or name of the rule author.
    pub author: Option<String>,
    /// URL to author's profile.
    pub author_url: Option<String>,
    /// Semantic version of this rule.
    pub version: Option<String>,
    /// Date the rule was created.
    pub created: Option<String>,
    /// Date the rule was last updated.
    pub updated: Option<String>,
    /// URLs to relevant documentation or CVEs.
    #[serde(default)]
    pub references: Vec<String>,
    /// Searchable tags for categorization.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Test cases to validate the rule pattern.
    pub test_cases: Option<TestCases>,
}

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
    /// Source of the rule (official or community).
    #[serde(default)]
    pub source: RuleSource,
    /// Optional metadata for community rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<RuleMetadata>,
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

    /// Load the built-in rules from JSON files (preferred) or compiled patterns (fallback).
    pub fn with_builtin_rules(mut self) -> Result<Self, regex::Error> {
        // Try JSON rules first
        let json_rules = loader::load_builtin_json_rules();

        if !json_rules.is_empty() {
            for rule in json_rules {
                if rule.enabled {
                    self.rules.push(rule.compile()?);
                }
            }
        } else {
            // Fall back to compiled patterns
            for rule in patterns::builtin_rules() {
                if rule.enabled {
                    self.rules.push(rule.compile()?);
                }
            }
        }
        Ok(self)
    }

    /// Load rules from JSON files in a directory.
    pub fn with_rules_from_directory(mut self, dir: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let rules = loader::load_rules_from_directory(dir)?;
        for rule in rules {
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
            source: RuleSource::Official,
            metadata: None,
        };

        let compiled = rule.compile().unwrap();
        assert!(compiled.regex.is_match("eval(code)"));
        assert!(compiled.regex.is_match("eval (code)"));
        assert!(!compiled.regex.is_match("evaluate(code)"));
    }

    #[test]
    fn test_rule_with_test_cases() {
        let rule = Rule {
            id: "COMM-001".to_string(),
            title: "Test Community Rule".to_string(),
            description: "A test community rule".to_string(),
            severity: Severity::High,
            category: FindingCategory::CredentialAccess,
            pattern: r"AKIA[0-9A-Z]{16}".to_string(),
            file_extensions: vec![],
            remediation: Some("Remove hardcoded keys".to_string()),
            enabled: true,
            source: RuleSource::Community,
            metadata: Some(RuleMetadata {
                author: Some("test-author".to_string()),
                author_url: Some("https://github.com/test-author".to_string()),
                version: Some("1.0.0".to_string()),
                created: Some("2026-02-02".to_string()),
                updated: Some("2026-02-02".to_string()),
                references: vec!["https://example.com".to_string()],
                tags: vec!["aws".to_string(), "credentials".to_string()],
                test_cases: Some(TestCases {
                    should_match: vec!["AKIAIOSFODNN7EXAMPLE".to_string()],
                    should_not_match: vec!["AKIAI".to_string()],
                }),
            }),
        };

        let compiled = rule.compile().unwrap();

        // Test should_match cases
        if let Some(ref metadata) = rule.metadata {
            if let Some(ref test_cases) = metadata.test_cases {
                for case in &test_cases.should_match {
                    assert!(compiled.regex.is_match(case), "Should match: {}", case);
                }
                for case in &test_cases.should_not_match {
                    assert!(!compiled.regex.is_match(case), "Should not match: {}", case);
                }
            }
        }
    }
}
