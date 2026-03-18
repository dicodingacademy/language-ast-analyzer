use super::Analyzer;
use crate::types::{CodeIssue, Category, Severity};
use oxc_ast::ast::*;
use oxc_span::Span;
use std::collections::HashMap;
use std::path::Path;

pub struct MagicNumberAnalyzer;

impl MagicNumberAnalyzer {
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
            category: Category::CodeQuality,
            rule,
            code_snippet,
        });
    }

    fn is_allowed_magic_number(value: f64) -> bool {
        // Allow common values
        if value == 0.0 || value == 1.0 || value == -1.0 {
            return true;
        }

        // Allow powers of 2 (up to 1024)
        let allowed = [2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0, 1024.0];
        if allowed.contains(&value) {
            return true;
        }

        // Allow common multiples of 10
        if value == 10.0 || value == 100.0 || value == 1000.0 {
            return true;
        }

        false
    }

    fn is_hex_literal(s: &str) -> bool {
        s.starts_with("0x") || s.starts_with("0X")
    }

    fn is_binary_literal(s: &str) -> bool {
        s.starts_with("0b") || s.starts_with("0B")
    }
}

impl Analyzer for MagicNumberAnalyzer {
    fn analyze(&self, program: &Program, file_path: &Path, source_code: &str) -> Vec<CodeIssue> {
        let mut issues = Vec::new();
        let mut string_literals: HashMap<String, usize> = HashMap::new();

        for stmt in &program.body {
            self.analyze_statement(&mut issues, stmt, file_path, source_code, &mut string_literals);
        }

        // Check for duplicate strings (potential constants)
        for (literal, count) in &string_literals {
            if *count >= 3 && literal.len() > 5 {
                // This is a heuristic - duplicated long strings should be constants
                // We don't add an issue here because we'd need to track locations
                // For now, this is just informational
            }
        }

        issues
    }
}

impl MagicNumberAnalyzer {
    fn analyze_statement(
        &self,
        issues: &mut Vec<CodeIssue>,
        stmt: &Statement,
        file_path: &Path,
        source_code: &str,
        string_literals: &mut HashMap<String, usize>,
    ) {
        match stmt {
            Statement::ExpressionStatement(expr_stmt) => {
                self.analyze_expression(issues, &expr_stmt.expression, file_path, source_code, string_literals);
            }
            Statement::BlockStatement(block) => {
                for stmt in &block.body {
                    self.analyze_statement(issues, stmt, file_path, source_code, string_literals);
                }
            }
            Statement::IfStatement(if_stmt) => {
                self.analyze_expression(issues, &if_stmt.test, file_path, source_code, string_literals);
                self.analyze_statement(issues, &if_stmt.consequent, file_path, source_code, string_literals);
                if let Some(alternate) = &if_stmt.alternate {
                    self.analyze_statement(issues, alternate, file_path, source_code, string_literals);
                }
            }
            Statement::FunctionDeclaration(func) => {
                if let Some(body) = &func.body {
                    for stmt in &body.statements {
                        self.analyze_statement(issues, stmt, file_path, source_code, string_literals);
                    }
                }
            }
            Statement::ForStatement(for_stmt) => {
                if let Some(init) = &for_stmt.init {
                    if let Some(expr) = init.as_expression() {
                        self.analyze_expression(issues, expr, file_path, source_code, string_literals);
                    }
                }
                if let Some(test) = &for_stmt.test {
                    self.analyze_expression(issues, test, file_path, source_code, string_literals);
                }
                if let Some(update) = &for_stmt.update {
                    self.analyze_expression(issues, update, file_path, source_code, string_literals);
                }
                self.analyze_statement(issues, &for_stmt.body, file_path, source_code, string_literals);
            }
            Statement::WhileStatement(while_stmt) => {
                self.analyze_expression(issues, &while_stmt.test, file_path, source_code, string_literals);
                self.analyze_statement(issues, &while_stmt.body, file_path, source_code, string_literals);
            }
            Statement::DoWhileStatement(do_while_stmt) => {
                self.analyze_expression(issues, &do_while_stmt.test, file_path, source_code, string_literals);
                self.analyze_statement(issues, &do_while_stmt.body, file_path, source_code, string_literals);
            }
            Statement::ForInStatement(for_in_stmt) => {
                self.analyze_expression(issues, &for_in_stmt.right, file_path, source_code, string_literals);
                self.analyze_statement(issues, &for_in_stmt.body, file_path, source_code, string_literals);
            }
            Statement::ForOfStatement(for_of_stmt) => {
                self.analyze_expression(issues, &for_of_stmt.right, file_path, source_code, string_literals);
                self.analyze_statement(issues, &for_of_stmt.body, file_path, source_code, string_literals);
            }
            Statement::SwitchStatement(switch_stmt) => {
                self.analyze_expression(issues, &switch_stmt.discriminant, file_path, source_code, string_literals);
                for case in &switch_stmt.cases {
                    if let Some(test) = &case.test {
                        self.analyze_expression(issues, test, file_path, source_code, string_literals);
                    }
                    for stmt in &case.consequent {
                        self.analyze_statement(issues, stmt, file_path, source_code, string_literals);
                    }
                }
            }
            Statement::TryStatement(try_stmt) => {
                for stmt in &try_stmt.block.body {
                    self.analyze_statement(issues, stmt, file_path, source_code, string_literals);
                }
                if let Some(handler) = &try_stmt.handler {
                    for stmt in &handler.body.body {
                        self.analyze_statement(issues, stmt, file_path, source_code, string_literals);
                    }
                }
                if let Some(finalizer) = &try_stmt.finalizer {
                    for stmt in &finalizer.body {
                        self.analyze_statement(issues, stmt, file_path, source_code, string_literals);
                    }
                }
            }
            Statement::ReturnStatement(ret_stmt) => {
                if let Some(expr) = &ret_stmt.argument {
                    self.analyze_expression(issues, expr, file_path, source_code, string_literals);
                }
            }
            Statement::VariableDeclaration(var_decl) => {
                for var in &var_decl.declarations {
                    if let Some(init) = &var.init {
                        self.analyze_expression(issues, init, file_path, source_code, string_literals);
                    }
                }
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
        string_literals: &mut HashMap<String, usize>,
    ) {
        match expr {
            Expression::NumericLiteral(num) => {
                let value_str = source_code.get(num.span.start as usize..num.span.end as usize)
                    .unwrap_or("");

                // Skip hex and binary literals (they're more explicit)
                if Self::is_hex_literal(value_str) || Self::is_binary_literal(value_str) {
                    return;
                }

                if !Self::is_allowed_magic_number(num.value) {
                    self.add_issue(
                        issues,
                        file_path,
                        source_code,
                        num.span,
                        format!("Angka {} adalah magic number yang maknanya tidak jelas. Pindahkan ke konstanta bernama agar kode mudah dipahami, contoh: const MAX_RETRY = {}", num.value, num.value),
                        "no-magic-numbers".to_string(),
                        Severity::Suggestion,
                    );
                }
            }
            Expression::StringLiteral(str_lit) => {
                // Track string literals for potential duplication detection
                let value = &str_lit.value;
                if value.len() > 5 {
                    *string_literals.entry(value.to_string()).or_insert(0) += 1;

                    // Warn about very long strings inline
                    if value.len() > 50 {
                        self.add_issue(
                            issues,
                            file_path,
                            source_code,
                            str_lit.span,
                            format!("String hardcoded sepanjang {} karakter. Pertimbangkan memindahkan ke konstanta atau file konfigurasi terpisah agar mudah diubah.", value.len()),
                            "no-long-hardcoded-string".to_string(),
                            Severity::Suggestion,
                        );
                    }
                }
            }
            Expression::ArrayExpression(arr_expr) => {
                for elem in &arr_expr.elements {
                    if let Some(expr) = elem.as_expression() {
                        self.analyze_expression(issues, expr, file_path, source_code, string_literals);
                    }
                }
            }
            Expression::BinaryExpression(bin_expr) => {
                self.analyze_expression(issues, &bin_expr.left, file_path, source_code, string_literals);
                self.analyze_expression(issues, &bin_expr.right, file_path, source_code, string_literals);
            }
            Expression::LogicalExpression(logical_expr) => {
                self.analyze_expression(issues, &logical_expr.left, file_path, source_code, string_literals);
                self.analyze_expression(issues, &logical_expr.right, file_path, source_code, string_literals);
            }
            Expression::CallExpression(call_expr) => {
                self.analyze_expression(issues, &call_expr.callee, file_path, source_code, string_literals);
                for arg in &call_expr.arguments {
                    if let Some(expr) = arg.as_expression() {
                        self.analyze_expression(issues, expr, file_path, source_code, string_literals);
                    }
                }
            }
            Expression::AssignmentExpression(assign_expr) => {
                self.analyze_expression(issues, &assign_expr.right, file_path, source_code, string_literals);
            }
            Expression::UnaryExpression(unary_expr) => {
                self.analyze_expression(issues, &unary_expr.argument, file_path, source_code, string_literals);
            }
            Expression::NewExpression(new_expr) => {
                self.analyze_expression(issues, &new_expr.callee, file_path, source_code, string_literals);
                for arg in &new_expr.arguments {
                    if let Some(expr) = arg.as_expression() {
                        self.analyze_expression(issues, expr, file_path, source_code, string_literals);
                    }
                }
            }
            Expression::StaticMemberExpression(static_member) => {
                self.analyze_expression(issues, &static_member.object, file_path, source_code, string_literals);
            }
            Expression::ComputedMemberExpression(comp_member) => {
                self.analyze_expression(issues, &comp_member.object, file_path, source_code, string_literals);
                self.analyze_expression(issues, &comp_member.expression, file_path, source_code, string_literals);
            }
            _ => {}
        }
    }
}
