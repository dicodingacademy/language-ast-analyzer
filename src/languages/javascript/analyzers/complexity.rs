use super::Analyzer;
use crate::types::{CodeIssue, Category, Severity};
use oxc_ast::ast::*;
use oxc_span::Span;
use std::path::Path;

pub struct ComplexityAnalyzer;

impl ComplexityAnalyzer {
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
            category: Category::Maintainability,
            rule,
            code_snippet,
        });
    }
}

impl Analyzer for ComplexityAnalyzer {
    fn analyze(&self, program: &Program, file_path: &Path, source_code: &str) -> Vec<CodeIssue> {
        let mut issues = Vec::new();

        for stmt in &program.body {
            self.analyze_statement(&mut issues, stmt, file_path, source_code, 0);
        }

        issues
    }
}

impl ComplexityAnalyzer {
    fn analyze_statement(
        &self,
        issues: &mut Vec<CodeIssue>,
        stmt: &Statement,
        file_path: &Path,
        source_code: &str,
        depth: usize,
    ) {
        match stmt {
            Statement::IfStatement(if_stmt) => {
                // Check if this if statement is too deeply nested
                if depth >= 4 {
                    self.add_issue(
                        issues,
                        file_path,
                        source_code,
                        if_stmt.span,
                        format!("Nested if statement terlalu dalam (level {}). Pertimbangkan refactoring untuk mengurangi kompleksitas", depth + 1),
                        "max-depth".to_string(),
                        Severity::Warning,
                    );
                }

                // Analyze the condition
                self.analyze_expression(issues, &if_stmt.test, file_path, source_code);

                // Analyze consequent with increased depth
                self.analyze_statement(issues, &if_stmt.consequent, file_path, source_code, depth + 1);

                // Analyze alternate with increased depth
                if let Some(alternate) = &if_stmt.alternate {
                    self.analyze_statement(issues, alternate, file_path, source_code, depth + 1);
                }
            }
            Statement::BlockStatement(block) => {
                // Check if block has too many statements
                if block.body.len() > 50 {
                    self.add_issue(
                        issues,
                        file_path,
                        source_code,
                        block.span,
                        format!("Blok memiliki terlalu banyak statement ({}). Pertimbangkan memecah menjadi fungsi-fungsi yang lebih kecil", block.body.len()),
                        "max-statements".to_string(),
                        Severity::Suggestion,
                    );
                }

                for stmt in &block.body {
                    self.analyze_statement(issues, stmt, file_path, source_code, depth);
                }
            }
            Statement::FunctionDeclaration(func) => {
                let func_name = func.id.as_ref().map_or("<anonymous>", |id| id.name.as_str());

                if let Some(body) = &func.body {
                    // Count complexity of the function
                    let complexity = self.calculate_complexity(&body.statements);

                    if complexity > 10 {
                        self.add_issue(
                            issues,
                            file_path,
                            source_code,
                            func.span,
                            format!("Fungsi '{}' memiliki cyclomatic complexity tinggi ({}). Pertimbangkan refactoring", func_name, complexity),
                            "complexity".to_string(),
                            Severity::Warning,
                        );
                    }

                    // Count parameters
                    if func.params.items.len() > 5 {
                        self.add_issue(
                            issues,
                            file_path,
                            source_code,
                            func.span,
                            format!("Fungsi '{}' memiliki terlalu banyak parameter ({}). Pertimbangkan menggunakan parameter objek", func_name, func.params.items.len()),
                            "max-params".to_string(),
                            Severity::Suggestion,
                        );
                    }

                    // Analyze function body
                    for stmt in &body.statements {
                        self.analyze_statement(issues, stmt, file_path, source_code, 0);
                    }
                }
            }
            Statement::ExpressionStatement(expr_stmt) => {
                self.analyze_expression(issues, &expr_stmt.expression, file_path, source_code);
            }
            Statement::ForStatement(for_stmt) => {
                let new_depth = depth + 1;
                if new_depth >= 4 {
                    self.add_issue(
                        issues,
                        file_path,
                        source_code,
                        for_stmt.span,
                        format!("Loop terlalu dalam (level {}). Pertimbangkan refactoring untuk mengurangi kompleksitas", new_depth),
                        "max-depth".to_string(),
                        Severity::Warning,
                    );
                }

                if let Some(init) = &for_stmt.init {
                    match init {
                        ForStatementInit::VariableDeclaration(var_decl) => {
                            for var in &var_decl.declarations {
                                if let Some(init_expr) = &var.init {
                                    self.analyze_expression(issues, init_expr, file_path, source_code);
                                }
                            }
                        }
                        _ => {
                            if let Some(expr) = init.as_expression() {
                                self.analyze_expression(issues, expr, file_path, source_code);
                            }
                        }
                    }
                }
                if let Some(test) = &for_stmt.test {
                    self.analyze_expression(issues, test, file_path, source_code);
                }
                if let Some(update) = &for_stmt.update {
                    self.analyze_expression(issues, update, file_path, source_code);
                }
                self.analyze_statement(issues, &for_stmt.body, file_path, source_code, new_depth);
            }
            Statement::WhileStatement(while_stmt) => {
                let new_depth = depth + 1;
                if new_depth >= 4 {
                    self.add_issue(
                        issues,
                        file_path,
                        source_code,
                        while_stmt.span,
                        format!("Loop terlalu dalam (level {}). Pertimbangkan refactoring untuk mengurangi kompleksitas", new_depth),
                        "max-depth".to_string(),
                        Severity::Warning,
                    );
                }
                self.analyze_expression(issues, &while_stmt.test, file_path, source_code);
                self.analyze_statement(issues, &while_stmt.body, file_path, source_code, new_depth);
            }
            Statement::DoWhileStatement(do_while_stmt) => {
                let new_depth = depth + 1;
                if new_depth >= 4 {
                    self.add_issue(
                        issues,
                        file_path,
                        source_code,
                        do_while_stmt.span,
                        format!("Loop terlalu dalam (level {}). Pertimbangkan refactoring untuk mengurangi kompleksitas", new_depth),
                        "max-depth".to_string(),
                        Severity::Warning,
                    );
                }
                self.analyze_statement(issues, &do_while_stmt.body, file_path, source_code, new_depth);
                self.analyze_expression(issues, &do_while_stmt.test, file_path, source_code);
            }
            Statement::TryStatement(try_stmt) => {
                for stmt in &try_stmt.block.body {
                    self.analyze_statement(issues, stmt, file_path, source_code, depth);
                }
                if let Some(handler) = &try_stmt.handler {
                    for stmt in &handler.body.body {
                        self.analyze_statement(issues, stmt, file_path, source_code, depth);
                    }
                }
                if let Some(finalizer) = &try_stmt.finalizer {
                    for stmt in &finalizer.body {
                        self.analyze_statement(issues, stmt, file_path, source_code, depth);
                    }
                }
            }
            Statement::SwitchStatement(switch_stmt) => {
                for case in &switch_stmt.cases {
                    for stmt in &case.consequent {
                        self.analyze_statement(issues, stmt, file_path, source_code, depth);
                    }
                }
            }
            _ => {}
        }
    }

    fn calculate_complexity(&self, statements: &[Statement]) -> usize {
        let mut complexity = 1; // Base complexity

        for stmt in statements {
            match stmt {
                Statement::IfStatement(if_stmt) => {
                    complexity += 1;
                    if let Some(alternate) = &if_stmt.alternate {
                        complexity += self.calculate_complexity_in_statement(&if_stmt.consequent);
                        complexity += self.calculate_complexity_in_statement(alternate);
                    } else {
                        complexity += self.calculate_complexity_in_statement(&if_stmt.consequent);
                    }
                }
                Statement::WhileStatement(_) | Statement::DoWhileStatement(_) | Statement::ForStatement(_) => {
                    complexity += 1;
                }
                Statement::SwitchStatement(switch_stmt) => {
                    complexity += switch_stmt.cases.len();
                }
                Statement::TryStatement(try_stmt) => {
                    complexity += 1;
                    complexity += self.calculate_complexity(&try_stmt.block.body);
                    if let Some(handler) = &try_stmt.handler {
                        complexity += self.calculate_complexity(&handler.body.body);
                    }
                }
                _ => {
                    complexity += self.calculate_complexity_in_statement(stmt);
                }
            }
        }

        complexity
    }

    fn calculate_complexity_in_statement(&self, stmt: &Statement) -> usize {
        match stmt {
            Statement::BlockStatement(block) => self.calculate_complexity(&block.body),
            Statement::IfStatement(if_stmt) => {
                let mut complexity = 1;
                complexity += self.calculate_complexity_in_statement(&if_stmt.consequent);
                if let Some(alternate) = &if_stmt.alternate {
                    complexity += self.calculate_complexity_in_statement(alternate);
                }
                complexity
            }
            _ => 0,
        }
    }

    fn analyze_expression(
        &self,
        _issues: &mut Vec<CodeIssue>,
        expr: &Expression,
        file_path: &Path,
        source_code: &str,
    ) {
        // Traverse expressions but don't add issues here
        match expr {
            Expression::BinaryExpression(bin_expr) => {
                // Check for complex conditions
                self.check_complex_condition(bin_expr, file_path, source_code);
                self.analyze_expression(_issues, &bin_expr.left, file_path, source_code);
                self.analyze_expression(_issues, &bin_expr.right, file_path, source_code);
            }
            Expression::LogicalExpression(logical_expr) => {
                self.analyze_expression(_issues, &logical_expr.left, file_path, source_code);
                self.analyze_expression(_issues, &logical_expr.right, file_path, source_code);
            }
            Expression::CallExpression(call_expr) => {
                self.analyze_expression(_issues, &call_expr.callee, file_path, source_code);
                for arg in &call_expr.arguments {
                    if let Some(expr) = arg.as_expression() {
                        self.analyze_expression(_issues, expr, file_path, source_code);
                    }
                }
            }
            _ => {}
        }
    }

    fn check_complex_condition(
        &self,
        _bin_expr: &BinaryExpression,
        _file_path: &Path,
        _source_code: &str,
    ) {
        // This is a placeholder - we could add more sophisticated condition analysis here
        // For now, we just track depth through the recursion
    }
}
