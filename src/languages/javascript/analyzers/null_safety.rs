use super::Analyzer;
use crate::types::{Category, CodeIssue, Severity};
use oxc_ast::ast::*;
use oxc_span::Span;
use std::path::Path;

pub struct NullSafetyAnalyzer;

impl NullSafetyAnalyzer {
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
}

impl Analyzer for NullSafetyAnalyzer {
    fn analyze(&self, program: &Program, file_path: &Path, source_code: &str) -> Vec<CodeIssue> {
        let mut issues = Vec::new();

        for stmt in &program.body {
            self.analyze_statement(&mut issues, stmt, file_path, source_code);
        }

        issues
    }
}

impl NullSafetyAnalyzer {
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
                    if let Some(init) = &var.init {
                        self.analyze_expression(issues, init, file_path, source_code);
                    }

                    // Check for destructuring without defaults
                    if let BindingPatternKind::ObjectPattern(obj_pattern) = &var.id.kind {
                        for prop in &obj_pattern.properties {
                            // BindingProperty is a struct
                            if prop.value.kind.is_binding_identifier() {
                                // If it's just an identifier, it has no default value
                                // Default values are represented as BindingPatternKind::AssignmentPattern
                                self.add_issue(
                                    issues,
                                    file_path,
                                    source_code,
                                    var.span,
                                    "Destructuring objek tanpa nilai default bisa menghasilkan nilai undefined. Contoh aman: const { prop = defaultValue } = obj".to_string(),
                                    "no-unsafe-destructuring".to_string(),
                                    Severity::Suggestion,
                                );
                            }
                        }
                    }

                    if let BindingPatternKind::ArrayPattern(arr_pattern) = &var.id.kind {
                        for elem in &arr_pattern.elements {
                            if let Some(elem) = elem {
                                if elem.kind.is_binding_identifier() {
                                    self.add_issue(
                                        issues,
                                        file_path,
                                        source_code,
                                        var.span,
                                        "Destructuring array tanpa nilai default bisa menghasilkan nilai undefined. Contoh aman: const [first = defaultValue] = array".to_string(),
                                        "no-unsafe-destructuring".to_string(),
                                        Severity::Suggestion,
                                    );
                                }
                            }
                        }
                    }
                }
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
                    if let Some(expr) = init.as_expression() {
                        self.analyze_expression(issues, expr, file_path, source_code);
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
            Statement::ReturnStatement(ret_stmt) => {
                if let Some(expr) = &ret_stmt.argument {
                    self.analyze_expression(issues, expr, file_path, source_code);
                }
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
            Statement::TryStatement(try_stmt) => {
                for stmt in &try_stmt.block.body {
                    self.analyze_statement(issues, stmt, file_path, source_code);
                }
                if let Some(handler) = &try_stmt.handler {
                    for stmt in &handler.body.body {
                        self.analyze_statement(issues, stmt, file_path, source_code);
                    }
                }
                if let Some(finalizer) = &try_stmt.finalizer {
                    for stmt in &finalizer.body {
                        self.analyze_statement(issues, stmt, file_path, source_code);
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
    ) {
        match expr {
            Expression::StaticMemberExpression(member_expr) => {
                self.analyze_expression(issues, &member_expr.object, file_path, source_code);
            }
            Expression::ComputedMemberExpression(comp_member) => {
                self.analyze_expression(issues, &comp_member.object, file_path, source_code);
                self.analyze_expression(issues, &comp_member.expression, file_path, source_code);
            }
            Expression::CallExpression(call_expr) => {
                self.analyze_expression(issues, &call_expr.callee, file_path, source_code);
                for arg in &call_expr.arguments {
                    if let Some(arg_expr) = arg.as_expression() {
                        self.analyze_expression(issues, arg_expr, file_path, source_code);
                    }
                }
            }
            Expression::BinaryExpression(bin_expr) => {
                self.analyze_expression(issues, &bin_expr.left, file_path, source_code);
                self.analyze_expression(issues, &bin_expr.right, file_path, source_code);
            }
            Expression::LogicalExpression(logical_expr) => {
                self.analyze_expression(issues, &logical_expr.left, file_path, source_code);
                self.analyze_expression(issues, &logical_expr.right, file_path, source_code);
            }
            Expression::AssignmentExpression(assign_expr) => {
                self.analyze_expression(issues, &assign_expr.right, file_path, source_code);
            }
            Expression::UnaryExpression(unary_expr) => {
                self.analyze_expression(issues, &unary_expr.argument, file_path, source_code);
            }
            Expression::NewExpression(new_expr) => {
                self.analyze_expression(issues, &new_expr.callee, file_path, source_code);
                for arg in &new_expr.arguments {
                    if let Some(arg_expr) = arg.as_expression() {
                        self.analyze_expression(issues, arg_expr, file_path, source_code);
                    }
                }
            }
            Expression::ArrayExpression(arr_expr) => {
                for elem in &arr_expr.elements {
                    if let Some(elem_expr) = elem.as_expression() {
                        self.analyze_expression(issues, elem_expr, file_path, source_code);
                    }
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
            _ => {}
        }
    }
}
