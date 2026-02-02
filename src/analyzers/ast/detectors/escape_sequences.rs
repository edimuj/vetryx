//! Detector for escape sequence obfuscation in property access.
//!
//! Detects patterns like:
//! - `window["\x65\x76\x61\x6c"]()` - hex escapes for "eval"
//! - `window["\u0065\u0076\u0061\u006c"]()` - unicode escapes for "eval"

use super::Detector;
use crate::analyzers::ast::scope::ScopeTracker;
use crate::types::{Finding, FindingCategory, Location, Severity};
use std::path::Path;
use tree_sitter::Node;

/// Dangerous global objects.
const DANGEROUS_GLOBALS: &[&str] = &["window", "globalThis", "global", "self", "this"];

/// Dangerous function names.
const DANGEROUS_FUNCTIONS: &[&str] = &[
    "eval",
    "Function",
    "setTimeout",
    "setInterval",
    "setImmediate",
];

pub struct EscapeSequenceDetector;

impl EscapeSequenceDetector {
    pub fn new() -> Self {
        Self
    }

    /// Decode escape sequences in a string.
    fn decode_escapes(s: &str) -> Option<String> {
        let mut result = String::new();
        let mut chars = s.chars().peekable();
        let mut has_escapes = false;

        while let Some(c) = chars.next() {
            if c == '\\' {
                has_escapes = true;
                match chars.next() {
                    Some('x') => {
                        // \xHH - 2 hex digits
                        let mut hex = String::new();
                        for _ in 0..2 {
                            if let Some(&ch) = chars.peek() {
                                if ch.is_ascii_hexdigit() {
                                    hex.push(chars.next().unwrap());
                                } else {
                                    break;
                                }
                            }
                        }
                        if hex.len() == 2 {
                            if let Ok(code) = u8::from_str_radix(&hex, 16) {
                                result.push(code as char);
                            }
                        }
                    }
                    Some('u') => {
                        // \uHHHH - 4 hex digits
                        // or \u{HHHH} - variable length
                        if chars.peek() == Some(&'{') {
                            chars.next(); // consume '{'
                            let mut hex = String::new();
                            while let Some(&ch) = chars.peek() {
                                if ch == '}' {
                                    chars.next();
                                    break;
                                }
                                if ch.is_ascii_hexdigit() {
                                    hex.push(chars.next().unwrap());
                                } else {
                                    break;
                                }
                            }
                            if let Ok(code) = u32::from_str_radix(&hex, 16) {
                                if let Some(ch) = char::from_u32(code) {
                                    result.push(ch);
                                }
                            }
                        } else {
                            let mut hex = String::new();
                            for _ in 0..4 {
                                if let Some(&ch) = chars.peek() {
                                    if ch.is_ascii_hexdigit() {
                                        hex.push(chars.next().unwrap());
                                    } else {
                                        break;
                                    }
                                }
                            }
                            if hex.len() == 4 {
                                if let Ok(code) = u16::from_str_radix(&hex, 16) {
                                    result.push(char::from_u32(code as u32).unwrap_or('?'));
                                }
                            }
                        }
                    }
                    Some('n') => result.push('\n'),
                    Some('r') => result.push('\r'),
                    Some('t') => result.push('\t'),
                    Some('\\') => result.push('\\'),
                    Some('"') => result.push('"'),
                    Some('\'') => result.push('\''),
                    Some(other) => {
                        result.push('\\');
                        result.push(other);
                    }
                    None => result.push('\\'),
                }
            } else {
                result.push(c);
            }
        }

        if has_escapes {
            Some(result)
        } else {
            None
        }
    }

    /// Get the raw string content (with escapes still present).
    fn get_raw_string_content(node: Node, source: &str) -> Option<String> {
        let text = node.utf8_text(source.as_bytes()).ok()?;
        // Remove outer quotes but keep inner content raw
        if (text.starts_with('"') && text.ends_with('"'))
            || (text.starts_with('\'') && text.ends_with('\''))
        {
            Some(text[1..text.len() - 1].to_string())
        } else {
            None
        }
    }
}

impl Default for EscapeSequenceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for EscapeSequenceDetector {
    fn rule_id(&self) -> &'static str {
        "AST-EXEC-004"
    }

    fn title(&self) -> &'static str {
        "Escape sequence obfuscation of dangerous function"
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
        let subscript = if node.kind() == "call_expression" {
            match node.child_by_field_name("function") {
                Some(callee) if callee.kind() == "subscript_expression" => callee,
                _ => return findings,
            }
        } else if node.kind() == "subscript_expression" {
            node
        } else {
            return findings;
        };

        // Get the object being accessed
        let object = match subscript.child_by_field_name("object") {
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
        let index = match subscript.child_by_field_name("index") {
            Some(idx) => idx,
            None => return findings,
        };

        // Check if it's a string literal
        if index.kind() != "string" {
            return findings;
        }

        // Get the raw string content
        let raw = match Self::get_raw_string_content(index, source) {
            Some(s) => s,
            None => return findings,
        };

        // Check if it contains escape sequences and decode them
        if let Some(decoded) = Self::decode_escapes(&raw) {
            // Check if the decoded string is a dangerous function
            if DANGEROUS_FUNCTIONS.contains(&decoded.as_str()) {
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
                            "Escape sequences decode to '{}' on '{}'. \
                            This pattern uses character escapes (\\x, \\u) to hide dangerous function names.",
                            decoded, object_text
                        ),
                        Severity::Critical,
                        FindingCategory::CodeExecution,
                        Location::new(path.to_path_buf(), start_line, end_line)
                            .with_columns(index.start_position().column + 1, index.end_position().column + 1),
                        snippet,
                    )
                    .with_remediation("Remove the obfuscated dangerous function access.")
                    .with_metadata("technique", "escape_sequence_obfuscation")
                    .with_metadata("decoded_function", decoded)
                    .with_metadata("ast_analyzed", "true"),
                );
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hex_escapes() {
        // "eval" in hex: \x65\x76\x61\x6c
        let decoded = EscapeSequenceDetector::decode_escapes(r"\x65\x76\x61\x6c");
        assert_eq!(decoded, Some("eval".to_string()));
    }

    #[test]
    fn test_decode_unicode_escapes() {
        // "eval" in unicode: \u0065\u0076\u0061\u006c
        let decoded = EscapeSequenceDetector::decode_escapes(r"\u0065\u0076\u0061\u006c");
        assert_eq!(decoded, Some("eval".to_string()));
    }

    #[test]
    fn test_no_escapes_returns_none() {
        let decoded = EscapeSequenceDetector::decode_escapes("eval");
        assert_eq!(decoded, None);
    }

    #[test]
    fn test_mixed_escapes() {
        // "eval" mixed: ev\x61l
        let decoded = EscapeSequenceDetector::decode_escapes(r"ev\x61l");
        assert_eq!(decoded, Some("eval".to_string()));
    }
}
