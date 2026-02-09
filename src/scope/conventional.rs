//! Conventional dev-only path patterns.
//!
//! These patterns match directories and files that are typically not shipped
//! when a package is installed (tests, examples, CI configs, etc.).

use globset::{Glob, GlobSet, GlobSetBuilder};

/// Build a pre-compiled GlobSet matching conventional dev-only paths.
pub fn build_dev_only_globs() -> GlobSet {
    let mut builder = GlobSetBuilder::new();

    // Dev-only directories (any file under these)
    let dev_dirs = [
        "test/**",
        "tests/**",
        "__tests__/**",
        "spec/**",
        "examples/**",
        "example/**",
        "docs/**",
        "doc/**",
        "benchmarks/**",
        "benches/**",
        "fixtures/**",
        "__fixtures__/**",
        "__mocks__/**",
        ".github/**",
        ".circleci/**",
        ".husky/**",
        "e2e/**",
        "cypress/**",
        "playwright/**",
        "coverage/**",
        ".nyc_output/**",
    ];

    for pattern in &dev_dirs {
        if let Ok(glob) = Glob::new(pattern) {
            builder.add(glob);
        }
    }

    // Dev-only file patterns
    let dev_files = [
        "*.test.js",
        "*.test.ts",
        "*.test.jsx",
        "*.test.tsx",
        "*.test.mjs",
        "*.test.cjs",
        "*.spec.js",
        "*.spec.ts",
        "*.spec.jsx",
        "*.spec.tsx",
        "*.spec.mjs",
        "*.spec.cjs",
        "*_test.py",
        "test_*.py",
        "*_test.rs",
        "*_test.go",
        "jest.config.*",
        "vitest.config.*",
        "Dockerfile",
        "Dockerfile.*",
        "docker-compose*",
        ".editorconfig",
        ".gitattributes",
        ".eslintrc*",
        ".prettierrc*",
        "tsconfig.test.json",
        ".travis.yml",
        "Makefile",
        "Gruntfile*",
        "Gulpfile*",
        "rollup.config.*",
        "webpack.config.*",
    ];

    for pattern in &dev_files {
        if let Ok(glob) = Glob::new(pattern) {
            builder.add(glob);
        }
    }

    builder
        .build()
        .unwrap_or_else(|_| GlobSetBuilder::new().build().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_dev_dirs_match() {
        let globs = build_dev_only_globs();
        assert!(globs.is_match(Path::new("tests/sample.js")));
        assert!(globs.is_match(Path::new("test/foo/bar.ts")));
        assert!(globs.is_match(Path::new("__tests__/unit.spec.js")));
        assert!(globs.is_match(Path::new(".github/workflows/ci.yml")));
        assert!(globs.is_match(Path::new("examples/demo.py")));
        assert!(globs.is_match(Path::new("fixtures/malicious.js")));
        assert!(globs.is_match(Path::new("e2e/login.spec.ts")));
    }

    #[test]
    fn test_dev_files_match() {
        let globs = build_dev_only_globs();
        assert!(globs.is_match(Path::new("app.test.js")));
        assert!(globs.is_match(Path::new("utils.spec.tsx")));
        assert!(globs.is_match(Path::new("test_auth.py")));
        assert!(globs.is_match(Path::new("handler_test.go")));
        assert!(globs.is_match(Path::new("jest.config.ts")));
        assert!(globs.is_match(Path::new("Dockerfile")));
        assert!(globs.is_match(Path::new("docker-compose.yml")));
    }

    #[test]
    fn test_production_files_dont_match() {
        let globs = build_dev_only_globs();
        assert!(!globs.is_match(Path::new("src/index.js")));
        assert!(!globs.is_match(Path::new("lib/utils.ts")));
        assert!(!globs.is_match(Path::new("package.json")));
        assert!(!globs.is_match(Path::new("SKILL.md")));
        assert!(!globs.is_match(Path::new("README.md")));
        assert!(!globs.is_match(Path::new("dist/bundle.js")));
    }
}
