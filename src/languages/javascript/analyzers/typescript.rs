use super::Analyzer;
use crate::types::{CodeIssue, Category, Severity};
use oxc_ast::ast::*;
use oxc_span::Span;
use std::path::Path;

pub struct TypeScriptAnalyzer;

impl TypeScriptAnalyzer {
    pub fn new() -> Self {
        Self
    }

    fn get_line_column(source_code: &str, span: Span) -> (usize, usize) {
        let start = span.start as usize;
        let before = &source_code[..start];
        let line = before.lines().count();
        let last_newline = before.rfind('\n').unwrap_or(0);
        let column = start - last_newline;
        (line, column)
    }

    fn add_issue(
        &self,
        issues: &mut Vec<CodeIssue>,
        file_path: &Path,
        source_code: &str,
        span: Span,
        message: String,
        rule: String,
        severity: Severity,
    ) {
        let (line, column) = Self::get_line_column(source_code, span);
        let start = span.start as usize;
        let end = span.end as usize;
        let code_snippet = source_code.get(start..end).map(|s| s.to_string());

        issues.push(CodeIssue {
            file_path: file_path.display().to_string(),
            line,
            column,
            end_line: None,
            end_column: None,
            message,
            severity,
            category: Category::TypeScript,
            rule,
            code_snippet,
        });
    }
}

impl Analyzer for TypeScriptAnalyzer {
    fn analyze(&self, program: &Program, file_path: &Path, source_code: &str) -> Vec<CodeIssue> {
        let mut issues = Vec::new();

        // Only check TypeScript files
        if !file_path.to_string_lossy().ends_with(".ts")
            && !file_path.to_string_lossy().ends_with(".tsx")
        {
            return issues;
        }

        for stmt in &program.body {
            self.analyze_statement(&mut issues, stmt, file_path, source_code);
        }

        issues
    }
}

impl TypeScriptAnalyzer {
    fn analyze_statement(
        &self,
        issues: &mut Vec<CodeIssue>,
        stmt: &Statement,
        file_path: &Path,
        source_code: &str,
    ) {
        match stmt {
            Statement::VariableDeclaration(var_decl) => {
                for var in &var_decl.declarations {
                    if let Some(type_ann) = &var.id.type_annotation {
                        self.analyze_ts_type(issues, &type_ann.type_annotation, file_path, source_code);
                    }
                    if let Some(init) = &var.init {
                        self.analyze_expression(issues, init, file_path, source_code);
                    }
                }
            }
            Statement::FunctionDeclaration(func) => {
                if func.return_type.is_none() {
                    self.add_issue(
                        issues,
                        file_path,
                        source_code,
                        func.span,
                        "Fungsi ini tidak memiliki tipe return eksplisit. Tambahkan tipe return agar TypeScript bisa mendeteksi bug lebih awal, contoh: function nama(): string { ... }. Referensi: https://www.typescriptlang.org/docs/handbook/2/functions.html".to_string(),
                        "explicit-function-return-type".to_string(),
                        Severity::Suggestion,
                    );
                } else if let Some(return_type) = &func.return_type {
                    self.analyze_ts_type(issues, &return_type.type_annotation, file_path, source_code);
                }
                // Check parameter types for `any`
                for param in &func.params.items {
                    if let Some(type_ann) = &param.pattern.type_annotation {
                        self.analyze_ts_type(issues, &type_ann.type_annotation, file_path, source_code);
                    }
                }
                // Traverse function body
                if let Some(body) = &func.body {
                    for stmt in &body.statements {
                        self.analyze_statement(issues, stmt, file_path, source_code);
                    }
                }
            }
            Statement::BlockStatement(block) => {
                for stmt in &block.body {
                    self.analyze_statement(issues, stmt, file_path, source_code);
                }
            }
            Statement::IfStatement(if_stmt) => {
                self.analyze_statement(issues, &if_stmt.consequent, file_path, source_code);
                if let Some(alternate) = &if_stmt.alternate {
                    self.analyze_statement(issues, alternate, file_path, source_code);
                }
            }
            Statement::ForStatement(for_stmt) => {
                self.analyze_statement(issues, &for_stmt.body, file_path, source_code);
            }
            Statement::WhileStatement(while_stmt) => {
                self.analyze_statement(issues, &while_stmt.body, file_path, source_code);
            }
            Statement::DoWhileStatement(do_while_stmt) => {
                self.analyze_statement(issues, &do_while_stmt.body, file_path, source_code);
            }
            Statement::ForInStatement(for_in_stmt) => {
                self.analyze_statement(issues, &for_in_stmt.body, file_path, source_code);
            }
            Statement::ForOfStatement(for_of_stmt) => {
                self.analyze_statement(issues, &for_of_stmt.body, file_path, source_code);
            }
            Statement::ReturnStatement(ret_stmt) => {
                if let Some(expr) = &ret_stmt.argument {
                    self.analyze_expression(issues, expr, file_path, source_code);
                }
            }
            Statement::ExpressionStatement(expr_stmt) => {
                self.analyze_expression(issues, &expr_stmt.expression, file_path, source_code);
            }
            _ => {}
        }
    }

    fn analyze_expression(
        &self,
        issues: &mut Vec<CodeIssue>,
        expr: &Expression,
        file_path: &Path,
        source_code: &str,
    ) {
        match expr {
            Expression::ArrowFunctionExpression(arrow) => {
                if arrow.return_type.is_none() {
                    self.add_issue(
                        issues,
                        file_path,
                        source_code,
                        arrow.span,
                        "Arrow function ini tidak memiliki tipe return eksplisit. Tambahkan tipe return agar TypeScript bisa mendeteksi bug lebih awal, contoh: const nama = (): string => { ... }. Referensi: https://www.typescriptlang.org/docs/handbook/2/functions.html".to_string(),
                        "explicit-function-return-type".to_string(),
                        Severity::Suggestion,
                    );
                } else if let Some(return_type) = &arrow.return_type {
                    self.analyze_ts_type(issues, &return_type.type_annotation, file_path, source_code);
                }
                // Check parameter types for `any`
                for param in &arrow.params.items {
                    if let Some(type_ann) = &param.pattern.type_annotation {
                        self.analyze_ts_type(issues, &type_ann.type_annotation, file_path, source_code);
                    }
                }
                for stmt in &arrow.body.statements {
                    self.analyze_statement(issues, stmt, file_path, source_code);
                }
            }
            Expression::FunctionExpression(func_expr) => {
                if func_expr.return_type.is_none() {
                    self.add_issue(
                        issues,
                        file_path,
                        source_code,
                        func_expr.span,
                        "Function expression ini tidak memiliki tipe return eksplisit. Tambahkan tipe return agar TypeScript bisa mendeteksi bug lebih awal, contoh: const nama = function(): string { ... }. Referensi: https://www.typescriptlang.org/docs/handbook/2/functions.html".to_string(),
                        "explicit-function-return-type".to_string(),
                        Severity::Suggestion,
                    );
                }
                for param in &func_expr.params.items {
                    if let Some(type_ann) = &param.pattern.type_annotation {
                        self.analyze_ts_type(issues, &type_ann.type_annotation, file_path, source_code);
                    }
                }
                if let Some(body) = &func_expr.body {
                    for stmt in &body.statements {
                        self.analyze_statement(issues, stmt, file_path, source_code);
                    }
                }
            }
            Expression::CallExpression(call_expr) => {
                self.analyze_expression(issues, &call_expr.callee, file_path, source_code);
                for arg in &call_expr.arguments {
                    if let Some(expr) = arg.as_expression() {
                        self.analyze_expression(issues, expr, file_path, source_code);
                    }
                }
            }
            _ => {}
        }
    }

    fn analyze_ts_type(
        &self,
        issues: &mut Vec<CodeIssue>,
        ts_type: &TSType,
        file_path: &Path,
        source_code: &str,
    ) {
        match ts_type {
            TSType::TSAnyKeyword(any_type) => {
                self.add_issue(
                    issues,
                    file_path,
                    source_code,
                    any_type.span,
                    "Hindari tipe 'any' karena menonaktifkan pengecekan tipe TypeScript. Gunakan tipe yang spesifik, atau 'unknown' jika tipe belum diketahui. Referensi: https://www.typescriptlang.org/docs/handbook/2/types-from-types.html".to_string(),
                    "no-any-type".to_string(),
                    Severity::Suggestion,
                );
            }
            TSType::TSArrayType(array_type) => {
                // Recursively check element type
                self.analyze_ts_type(issues, &array_type.element_type, file_path, source_code);
            }
            TSType::TSUnionType(union_type) => {
                // Check all types in union
                for type_ann in &union_type.types {
                    self.analyze_ts_type(issues, type_ann, file_path, source_code);
                }
            }
            _ => {}
        }
    }
}
