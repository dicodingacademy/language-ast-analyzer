use super::Analyzer;
use crate::types::{Category, CodeIssue, Severity};
use oxc_ast::ast::*;
use oxc_span::Span;
use std::collections::HashSet;
use std::path::Path;

/// Context for naming analysis
#[derive(Clone, Copy)]
enum NamingContext {
    /// Top-level variable/const declaration
    TopLevel,
    /// Function parameter (more lenient)
    Parameter,
    /// Inside function body (same as top-level rules)
    FunctionBody,
}

pub struct NamingAnalyzer;

impl NamingAnalyzer {
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

    fn is_generic_name(name: &str, context: NamingContext) -> bool {
        match context {
            NamingContext::Parameter => {
                // More lenient for function parameters - these are commonly accepted
                let generic_names = [
                    "stuff", "things", "content", "variable", "param", // Still too generic even for params
                    "obj", "object", // Should be more specific
                ];
                generic_names.contains(&name.to_lowercase().as_str())
            }
            NamingContext::TopLevel | NamingContext::FunctionBody => {
                // Stricter for top-level variables and function body variables
                // Common JS names like data, err, opts, args are OK for parameters
                // but should be more descriptive in other contexts
                let generic_names = [
                    "stuff", "things", "content", "variable", "param", // Too generic
                    "obj", "object", // Should be more specific
                    "output", "input", // Should be more descriptive
                    "data", "result", "info", "value", "item", // Too generic for variables
                    "opts", "args", "err", // OK for params, not for variables
                ];
                generic_names.contains(&name.to_lowercase().as_str())
            }
        }
    }

    fn is_too_short(name: &str) -> bool {
        if name.len() < 3 {
            // Allow common short names
            let allowed = ["i", "j", "k", "x", "y", "z", "_", "$", "a", "b"];
            !allowed.contains(&name)
        } else {
            false
        }
    }

    fn is_generic_function_name(name: &str) -> bool {
        // Only flag truly generic function names
        // Allow common patterns: handle, handler, callback are standard in JS
        let generic_names = [
            "process", "execute", "run", "do", "perform", "action", // Too generic
            "fn", "func", // Should use more descriptive names
        ];
        generic_names.contains(&name.to_lowercase().as_str())
    }
}

impl Analyzer for NamingAnalyzer {
    fn analyze(&self, program: &Program, file_path: &Path, source_code: &str) -> Vec<CodeIssue> {
        let mut issues = Vec::new();
        let mut declared_names: HashSet<String> = HashSet::new();

        for stmt in &program.body {
            self.analyze_statement(
                &mut issues,
                stmt,
                file_path,
                source_code,
                &mut declared_names,
                NamingContext::TopLevel,
            );
        }

        issues
    }
}

impl NamingAnalyzer {
    fn analyze_statement(
        &self,
        issues: &mut Vec<CodeIssue>,
        stmt: &Statement,
        file_path: &Path,
        source_code: &str,
        declared_names: &mut HashSet<String>,
        context: NamingContext,
    ) {
        match stmt {
            Statement::VariableDeclaration(var_decl) => {
                for var in &var_decl.declarations {
                    if let BindingPatternKind::BindingIdentifier(ident) = &var.id.kind {
                        let name = ident.name.as_str();
                        declared_names.insert(name.to_string());

                        // Check for generic names (context-aware)
                        if Self::is_generic_name(name, context) {
                            self.add_issue(
                                issues,
                                file_path,
                                source_code,
                                ident.span,
                                format!("Variable '{}' memiliki penamaan yang cukup umum, bisa kamu buat agar lebih deskriptif agar tidak membingungkan ya.", name),
                                "no-generic-name".to_string(),
                                Severity::Suggestion,
                            );
                        }

                        // Check for too short names
                        if Self::is_too_short(name) {
                            self.add_issue(
                                issues,
                                file_path,
                                source_code,
                                ident.span,
                                format!("Variable '{}' memiliki penamaan yang cukup pendek. kamu bisa gunakan penamaan variable yang lebih deskriptif agar kamu tidak bingung dikemudian hari :)", name),
                                "no-short-name".to_string(),
                                Severity::Suggestion,
                            );
                        }

                        // Boolean prefix check removed - heuristic based on name alone
                        // produces too many false positives without type information
                    }
                }
            }
            Statement::FunctionDeclaration(func) => {
                let func_name = func
                    .id
                    .as_ref()
                    .map_or("<anonymous>", |id| id.name.as_str());

                // Skip anonymous functions
                if func_name != "<anonymous>" {
                    // Check for generic function names
                    if Self::is_generic_function_name(func_name) {
                        self.add_issue(
                            issues,
                            file_path,
                            source_code,
                            func.span,
                            format!("Fungsi '{}' memiliki penamaan variable yang cukup umum. Gunakan penamaan variable yang dapat menggambarkan untuk apa fungsi tersebut dibuat", func_name),
                            "no-generic-function-name".to_string(),
                            Severity::Suggestion,
                        );
                    }

                    // Check parameters with Parameter context (more lenient)
                    for param in &func.params.items {
                        self.analyze_parameter(issues, param, file_path, source_code);
                    }
                }

                if let Some(body) = &func.body {
                    for stmt in &body.statements {
                        self.analyze_statement(
                            issues,
                            stmt,
                            file_path,
                            source_code,
                            declared_names,
                            NamingContext::FunctionBody,
                        );
                    }
                }
            }
            Statement::BlockStatement(block) => {
                for stmt in &block.body {
                    self.analyze_statement(issues, stmt, file_path, source_code, declared_names, context);
                }
            }
            Statement::IfStatement(if_stmt) => {
                self.analyze_expression(issues, &if_stmt.test, file_path, source_code);
                self.analyze_statement(
                    issues,
                    &if_stmt.consequent,
                    file_path,
                    source_code,
                    declared_names,
                    context,
                );
                if let Some(alternate) = &if_stmt.alternate {
                    self.analyze_statement(
                        issues,
                        alternate,
                        file_path,
                        source_code,
                        declared_names,
                        context,
                    );
                }
            }
            Statement::ForStatement(for_stmt) => {
                if let Some(init) = &for_stmt.init {
                    match init {
                        ForStatementInit::VariableDeclaration(var_decl) => {
                            for var in &var_decl.declarations {
                                if let BindingPatternKind::BindingIdentifier(ident) = &var.id.kind {
                                    let name = ident.name.as_str();
                                    // Allow short names for loop counters
                                    if !["i", "j", "k", "x", "y"].contains(&name) {
                                        if Self::is_generic_name(name, context) {
                                            self.add_issue(
                                                issues,
                                                file_path,
                                                source_code,
                                                ident.span,
                                                format!(
                                                    "Variabel '{}' memiliki penamaan yang cukup umum, kamu bisa improve agar lebih deskriptif ya agar tidak membingungkan",
                                                    name
                                                ),
                                                "no-generic-name".to_string(),
                                                Severity::Suggestion,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(test) = &for_stmt.test {
                    self.analyze_expression(issues, test, file_path, source_code);
                }
                if let Some(update) = &for_stmt.update {
                    self.analyze_expression(issues, update, file_path, source_code);
                }
                self.analyze_statement(
                    issues,
                    &for_stmt.body,
                    file_path,
                    source_code,
                    declared_names,
                    context,
                );
            }
            Statement::ExpressionStatement(expr_stmt) => {
                self.analyze_expression(issues, &expr_stmt.expression, file_path, source_code);
            }
            Statement::WhileStatement(while_stmt) => {
                self.analyze_statement(issues, &while_stmt.body, file_path, source_code, declared_names, context);
            }
            Statement::DoWhileStatement(do_while_stmt) => {
                self.analyze_statement(issues, &do_while_stmt.body, file_path, source_code, declared_names, context);
            }
            Statement::ForInStatement(for_in_stmt) => {
                self.analyze_statement(issues, &for_in_stmt.body, file_path, source_code, declared_names, context);
            }
            Statement::ForOfStatement(for_of_stmt) => {
                self.analyze_statement(issues, &for_of_stmt.body, file_path, source_code, declared_names, context);
            }
            Statement::TryStatement(try_stmt) => {
                for stmt in &try_stmt.block.body {
                    self.analyze_statement(issues, stmt, file_path, source_code, declared_names, context);
                }
                if let Some(handler) = &try_stmt.handler {
                    for stmt in &handler.body.body {
                        self.analyze_statement(issues, stmt, file_path, source_code, declared_names, context);
                    }
                }
                if let Some(finalizer) = &try_stmt.finalizer {
                    for stmt in &finalizer.body {
                        self.analyze_statement(issues, stmt, file_path, source_code, declared_names, context);
                    }
                }
            }
            Statement::SwitchStatement(switch_stmt) => {
                for case in &switch_stmt.cases {
                    for stmt in &case.consequent {
                        self.analyze_statement(issues, stmt, file_path, source_code, declared_names, context);
                    }
                }
            }
            Statement::ReturnStatement(_) => {}
            _ => {}
        }
    }

    fn analyze_parameter(
        &self,
        issues: &mut Vec<CodeIssue>,
        param: &FormalParameter<'_>,
        file_path: &Path,
        source_code: &str,
    ) {
        if let BindingPatternKind::BindingIdentifier(ident) = &param.pattern.kind {
            let name = ident.name.as_str();

            // Use Parameter context - more lenient for function params
            if Self::is_generic_name(name, NamingContext::Parameter) {
                self.add_issue(
                    issues,
                    file_path,
                    source_code,
                    ident.span,
                    format!("Parameter '{}' memiliki penamaan yang cukup umum, agar tidak membingungkan kamu bisa gunakan penamaan yang lebih deskriptif", name),
                    "no-generic-name".to_string(),
                    Severity::Suggestion,
                );
            }
        }
    }

    fn analyze_expression(
        &self,
        _issues: &mut Vec<CodeIssue>,
        expr: &Expression,
        _file_path: &Path,
        _source_code: &str,
    ) {
        match expr {
            Expression::BinaryExpression(bin_expr) => {
                self.analyze_expression(_issues, &bin_expr.left, _file_path, _source_code);
                self.analyze_expression(_issues, &bin_expr.right, _file_path, _source_code);
            }
            Expression::LogicalExpression(logical_expr) => {
                self.analyze_expression(_issues, &logical_expr.left, _file_path, _source_code);
                self.analyze_expression(_issues, &logical_expr.right, _file_path, _source_code);
            }
            Expression::CallExpression(call_expr) => {
                self.analyze_expression(_issues, &call_expr.callee, _file_path, _source_code);
                for arg in &call_expr.arguments {
                    if let Some(expr) = arg.as_expression() {
                        self.analyze_expression(_issues, expr, _file_path, _source_code);
                    }
                }
            }
            _ => {}
        }
    }
}
