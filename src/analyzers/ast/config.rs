//! Configuration for AST-based analysis.

/// Configuration for the AST analyzer.
#[derive(Debug, Clone)]
pub struct AstAnalyzerConfig {
    /// Enable JavaScript/TypeScript AST analysis.
    pub enable_javascript: bool,
    /// Enable Python AST analysis.
    pub enable_python: bool,
    /// Maximum file size to analyze (in bytes).
    pub max_file_size: usize,
    /// Maximum scope depth for variable aliasing resolution.
    pub max_scope_depth: usize,
    /// Maximum string concatenation chain length to resolve.
    pub max_concat_depth: usize,
}

impl Default for AstAnalyzerConfig {
    fn default() -> Self {
        Self {
            enable_javascript: true,
            enable_python: true,
            max_file_size: 1024 * 1024, // 1 MB
            max_scope_depth: 10,
            max_concat_depth: 10,
        }
    }
}
