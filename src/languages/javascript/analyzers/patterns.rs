use super::Analyzer;
use crate::types::CodeIssue;
use oxc_ast::ast::*;
use std::path::Path;

pub struct PatternAnalyzer;

impl PatternAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for PatternAnalyzer {
    fn analyze(&self, program: &Program, file_path: &Path, source_code: &str) -> Vec<CodeIssue> {
        let mut issues = Vec::new();

        for stmt in &program.body {
            self.analyze_statement(&mut issues, stmt, file_path, source_code);
        }

        issues
    }
}

impl PatternAnalyzer {
    fn analyze_statement(
        &self,
        _issues: &mut Vec<CodeIssue>,
        _stmt: &Statement,
        _file_path: &Path,
        _source_code: &str,
    ) {
        // Debugger check is handled by BestPracticeAnalyzer to avoid duplication
    }
}
