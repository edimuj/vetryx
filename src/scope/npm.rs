//! npm package.json scope detection.
//!
//! Parses the `files` field from package.json to determine which files
//! are actually published to npm (and thus installed by users).

use globset::{Glob, GlobSet, GlobSetBuilder};
use std::path::Path;

/// Parse package.json at the scan root and build a whitelist GlobSet
/// from the `files` field. Returns `None` if no package.json or no `files` field.
pub fn detect_npm_files_whitelist(scan_root: &Path) -> Option<GlobSet> {
    let pkg_path = scan_root.join("package.json");
    let content = std::fs::read_to_string(&pkg_path).ok()?;
    let pkg: serde_json::Value = serde_json::from_str(&content).ok()?;

    let files = pkg.get("files")?.as_array()?;
    if files.is_empty() {
        return None;
    }

    let mut builder = GlobSetBuilder::new();

    // Add patterns from "files" field
    for entry in files {
        if let Some(pattern) = entry.as_str() {
            // npm treats bare names as directories, so "src" matches "src/**"
            // A glob pattern with * or { is used as-is
            if pattern.contains('*') || pattern.contains('{') {
                if let Ok(glob) = Glob::new(pattern) {
                    builder.add(glob);
                }
            } else {
                // Could be a file or directory — add both forms
                if let Ok(glob) = Glob::new(pattern) {
                    builder.add(glob);
                }
                let dir_pattern = format!("{}/**", pattern.trim_end_matches('/'));
                if let Ok(glob) = Glob::new(&dir_pattern) {
                    builder.add(glob);
                }
            }
        }
    }

    // npm always includes these regardless of "files" field
    let always_included = [
        "package.json",
        "README*",
        "readme*",
        "LICENSE*",
        "license*",
        "LICENCE*",
        "licence*",
        "CHANGELOG*",
        "changelog*",
    ];
    for pattern in &always_included {
        if let Ok(glob) = Glob::new(pattern) {
            builder.add(glob);
        }
    }

    // Also include entry points referenced in package.json fields
    let entry_fields = ["main", "module", "types", "typings", "browser"];
    for field in &entry_fields {
        if let Some(entry) = pkg.get(field).and_then(|v| v.as_str()) {
            if let Ok(glob) = Glob::new(entry) {
                builder.add(glob);
            }
        }
    }

    // Include "bin" entries
    if let Some(bin) = pkg.get("bin") {
        match bin {
            serde_json::Value::String(s) => {
                if let Ok(glob) = Glob::new(s) {
                    builder.add(glob);
                }
            }
            serde_json::Value::Object(map) => {
                for val in map.values() {
                    if let Some(s) = val.as_str() {
                        if let Ok(glob) = Glob::new(s) {
                            builder.add(glob);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    builder.build().ok()
}

/// Check if a scan root looks like an npm project.
pub fn is_npm_project(scan_root: &Path) -> bool {
    scan_root.join("package.json").exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_package_json(dir: &Path, content: &str) {
        fs::write(dir.join("package.json"), content).unwrap();
    }

    #[test]
    fn test_no_package_json() {
        let tmp = TempDir::new().unwrap();
        assert!(detect_npm_files_whitelist(tmp.path()).is_none());
    }

    #[test]
    fn test_no_files_field() {
        let tmp = TempDir::new().unwrap();
        create_package_json(tmp.path(), r#"{"name": "test", "version": "1.0.0"}"#);
        assert!(detect_npm_files_whitelist(tmp.path()).is_none());
    }

    #[test]
    fn test_files_field_with_entries() {
        let tmp = TempDir::new().unwrap();
        create_package_json(
            tmp.path(),
            r#"{"name": "test", "version": "1.0.0", "files": ["dist", "lib/*.js"], "main": "dist/index.js"}"#,
        );

        let globs = detect_npm_files_whitelist(tmp.path()).unwrap();

        // Whitelisted
        assert!(globs.is_match(Path::new("dist/index.js")));
        assert!(globs.is_match(Path::new("dist/utils/helper.js")));
        assert!(globs.is_match(Path::new("lib/main.js")));
        assert!(globs.is_match(Path::new("package.json")));
        assert!(globs.is_match(Path::new("README.md")));
        assert!(globs.is_match(Path::new("LICENSE")));

        // Not whitelisted
        assert!(!globs.is_match(Path::new("src/index.ts")));
        assert!(!globs.is_match(Path::new("tests/unit.test.js")));
        assert!(!globs.is_match(Path::new("tsconfig.json")));
    }

    #[test]
    fn test_empty_files_field() {
        let tmp = TempDir::new().unwrap();
        create_package_json(
            tmp.path(),
            r#"{"name": "test", "version": "1.0.0", "files": []}"#,
        );
        assert!(detect_npm_files_whitelist(tmp.path()).is_none());
    }
}
