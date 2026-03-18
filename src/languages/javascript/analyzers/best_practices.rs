use super::Analyzer;
use crate::types::{CodeIssue, Category, Severity};
use oxc_ast::ast::*;
use oxc_span::Span;
use std::path::Path;

pub struct BestPracticeAnalyzer;

impl BestPracticeAnalyzer {
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
            category: Category::BestPractice,
            rule,
            code_snippet,
        });
    }
}

impl Analyzer for BestPracticeAnalyzer {
    fn analyze(&self, program: &Program, file_path: &Path, source_code: &str) -> Vec<CodeIssue> {
        let mut issues = Vec::new();

        for stmt in &program.body {
            self.analyze_statement(&mut issues, stmt, file_path, source_code);
        }

        issues
    }
}

impl BestPracticeAnalyzer {
    fn analyze_variable_declaration(
        &self,
        issues: &mut Vec<CodeIssue>,
        var_decl: &VariableDeclaration,
        file_path: &Path,
        source_code: &str,
    ) {
        if var_decl.kind == VariableDeclarationKind::Var {
            for var in &var_decl.declarations {
                if let BindingPatternKind::BindingIdentifier(ident) = &var.id.kind {
                    let var_name = &ident.name;
                    self.add_issue(
                        issues,
                        file_path,
                        source_code,
                        var.span,
                        format!("Gunakan 'const' atau 'let' sebagai pengganti 'var' untuk variabel '{}'. Var memiliki function scope yang bisa menyebabkan bug tak terduga. Referensi: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/var", var_name),
                        "no-var".to_string(),
                        Severity::Suggestion,
                    );
                }
            }
        }
    }

    fn analyze_statement(
        &self,
        issues: &mut Vec<CodeIssue>,
        stmt: &Statement,
        file_path: &Path,
        source_code: &str,
    ) {
        match stmt {
            Statement::VariableDeclaration(var_decl) => {
                self.analyze_variable_declaration(issues, var_decl, file_path, source_code);
            }
            Statement::ExpressionStatement(expr_stmt) => {
                self.analyze_expression(issues, &expr_stmt.expression, file_path, source_code);
            }
            Statement::BlockStatement(block) => {
                for stmt in &block.body {
                    self.analyze_statement(issues, stmt, file_path, source_code);
                }
            }
            Statement::IfStatement(if_stmt) => {
                self.analyze_expression(issues, &if_stmt.test, file_path, source_code);
                self.analyze_statement(issues, &if_stmt.consequent, file_path, source_code);
                if let Some(alternate) = &if_stmt.alternate {
                    self.analyze_statement(issues, alternate, file_path, source_code);
                }
            }
            Statement::FunctionDeclaration(func) => {
                if let Some(body) = &func.body {
                    for stmt in &body.statements {
                        self.analyze_statement(issues, stmt, file_path, source_code);
                    }
                }
            }
            Statement::ForStatement(for_stmt) => {
                if let Some(init) = &for_stmt.init {
                    match init {
                         ForStatementInit::VariableDeclaration(var_decl) => {
                             self.analyze_variable_declaration(issues, var_decl, file_path, source_code);
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
                self.analyze_statement(issues, &for_stmt.body, file_path, source_code);
            }
            Statement::TryStatement(try_stmt) => {
                // Check for empty catch blocks
                if let Some(handler) = &try_stmt.handler {
                    if handler.body.body.is_empty() {
                        self.add_issue(
                            issues,
                            file_path,
                            source_code,
                            handler.span,
                            "Blok catch kosong menyembunyikan error. Tambahkan penanganan error di dalamnya, atau gunakan logging minimal seperti console.error(err)".to_string(),
                            "no-empty-catch".to_string(),
                            Severity::Suggestion,
                        );
                    }
                }
                // Analyze try block
                for stmt in &try_stmt.block.body {
                    self.analyze_statement(issues, stmt, file_path, source_code);
                }
                // Analyze catch block
                if let Some(handler) = &try_stmt.handler {
                    for stmt in &handler.body.body {
                        self.analyze_statement(issues, stmt, file_path, source_code);
                    }
                }
                // Analyze finally block
                if let Some(finalizer) = &try_stmt.finalizer {
                    for stmt in &finalizer.body {
                        self.analyze_statement(issues, stmt, file_path, source_code);
                    }
                }
            }
            Statement::DebuggerStatement(debugger_stmt) => {
                self.add_issue(
                    issues,
                    file_path,
                    source_code,
                    debugger_stmt.span,
                    "Hapus debugger statement sebelum deploy ke produksi".to_string(),
                    "no-debugger".to_string(),
                    Severity::Warning,
                );
            }
            Statement::WhileStatement(while_stmt) => {
                self.analyze_expression(issues, &while_stmt.test, file_path, source_code);
                self.analyze_statement(issues, &while_stmt.body, file_path, source_code);
            }
            Statement::DoWhileStatement(do_while_stmt) => {
                self.analyze_expression(issues, &do_while_stmt.test, file_path, source_code);
                self.analyze_statement(issues, &do_while_stmt.body, file_path, source_code);
            }
            Statement::ForInStatement(for_in_stmt) => {
                self.analyze_expression(issues, &for_in_stmt.right, file_path, source_code);
                self.analyze_statement(issues, &for_in_stmt.body, file_path, source_code);
            }
            Statement::ForOfStatement(for_of_stmt) => {
                self.analyze_expression(issues, &for_of_stmt.right, file_path, source_code);
                self.analyze_statement(issues, &for_of_stmt.body, file_path, source_code);
            }
            Statement::SwitchStatement(switch_stmt) => {
                self.analyze_expression(issues, &switch_stmt.discriminant, file_path, source_code);
                for case in &switch_stmt.cases {
                    if let Some(test) = &case.test {
                        self.analyze_expression(issues, test, file_path, source_code);
                    }
                    for stmt in &case.consequent {
                        self.analyze_statement(issues, stmt, file_path, source_code);
                    }
                }
            }
            Statement::ReturnStatement(ret_stmt) => {
                if let Some(expr) = &ret_stmt.argument {
                    self.analyze_expression(issues, expr, file_path, source_code);
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
    ) {
        match expr {
            Expression::BinaryExpression(bin_expr) => {
                if matches!(bin_expr.operator, BinaryOperator::Equality | BinaryOperator::Inequality) {
                    self.add_issue(
                        issues,
                        file_path,
                        source_code,
                        bin_expr.span,
                        "Gunakan '===' (atau '!==') sebagai pengganti '==' agar tidak ada konversi tipe implisit yang bisa menyebabkan hasil tak terduga. Referensi: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Equality_comparisons_and_sameness".to_string(),
                        "eqeqeq".to_string(),
                        Severity::Suggestion,
                    );
                }
                self.analyze_expression(issues, &bin_expr.left, file_path, source_code);
                self.analyze_expression(issues, &bin_expr.right, file_path, source_code);
            }
            Expression::UnaryExpression(unary_expr) => {
                // Detect double negation (!!)
                if unary_expr.operator == UnaryOperator::LogicalNot {
                    if let Expression::UnaryExpression(inner) = &unary_expr.argument {
                        if inner.operator == UnaryOperator::LogicalNot {
                            self.add_issue(
                                issues,
                                file_path,
                                source_code,
                                unary_expr.span,
                                "Hindari double negation (!!) karena kurang ekspresif. Gunakan Boolean() untuk mengkonversi nilai ke boolean secara eksplisit.".to_string(),
                                "no-double-negation".to_string(),
                                Severity::Suggestion,
                            );
                        }
                    }
                    self.analyze_expression(issues, &unary_expr.argument, file_path, source_code);
                }
                // Detect void operator (except for void 0 which is sometimes used for undefined)
                if unary_expr.operator == UnaryOperator::Void {
                    self.add_issue(
                        issues,
                        file_path,
                        source_code,
                        unary_expr.span,
                        "Hindari operator void karena jarang diperlukan dan bisa membingungkan pembaca kode. Gunakan undefined secara langsung jika memang diperlukan.".to_string(),
                        "no-void".to_string(),
                        Severity::Suggestion,
                    );
                }
                self.analyze_expression(issues, &unary_expr.argument, file_path, source_code);
            }
            Expression::NewExpression(new_expr) => {
                // Detect 'new' for side effects without assignment
                // This is checked at the statement level, but we can also warn here
                self.analyze_expression(issues, &new_expr.callee, file_path, source_code);
                for arg in &new_expr.arguments {
                    if let Some(expr_arg) = arg.as_expression() {
                        self.analyze_expression(issues, expr_arg, file_path, source_code);
                    }
                }
            }
            Expression::SequenceExpression(seq_expr) => {
                // Comma operator can be confusing
                if seq_expr.expressions.len() > 1 {
                    self.add_issue(
                        issues,
                        file_path,
                        source_code,
                        seq_expr.span,
                        "Hindari comma operator karena membuat kode sulit dibaca. Pisahkan ekspresi menjadi statement yang berbeda.".to_string(),
                        "no-sequences".to_string(),
                        Severity::Suggestion,
                    );
                }
                for expr in &seq_expr.expressions {
                    self.analyze_expression(issues, expr, file_path, source_code);
                }
            }
            Expression::ConditionalExpression(cond_expr) => {
                self.analyze_expression(issues, &cond_expr.test, file_path, source_code);
                self.analyze_expression(issues, &cond_expr.consequent, file_path, source_code);
                self.analyze_expression(issues, &cond_expr.alternate, file_path, source_code);
            }
            Expression::TemplateLiteral(tmpl) => {
                for expr in &tmpl.expressions {
                    self.analyze_expression(issues, expr, file_path, source_code);
                }
            }
            Expression::ArrowFunctionExpression(arrow) => {
                for stmt in &arrow.body.statements {
                    self.analyze_statement(issues, stmt, file_path, source_code);
                }
            }
            Expression::FunctionExpression(func_expr) => {
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
            Expression::AssignmentExpression(assign_expr) => {
                self.analyze_expression(issues, &assign_expr.right, file_path, source_code);
            }
            Expression::LogicalExpression(logical_expr) => {
                self.analyze_expression(issues, &logical_expr.left, file_path, source_code);
                self.analyze_expression(issues, &logical_expr.right, file_path, source_code);
            }
            _ => {}
        }
    }
}
