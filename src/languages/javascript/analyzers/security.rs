use super::Analyzer;
use crate::types::{CodeIssue, Category, Severity};
use oxc_ast::ast::*;
use oxc_span::Span;
use std::path::Path;

pub struct SecurityAnalyzer;

/// Common JavaScript patterns that are widely accepted and should not trigger warnings
const COMMON_PATTERNS: &[(&str, &str)] = &[
    // DOM APIs - common and safe
    ("window", "addEventListener"),
    ("window", "removeEventListener"),
    ("document", "addEventListener"),
    ("document", "removeEventListener"),
    ("document", "getElementById"),
    ("document", "querySelector"),
    ("document", "querySelectorAll"),
    ("document", "createElement"),
    ("document", "createTextNode"),
    ("document", "getElementByClassName"),
    ("document", "getElementsByTagName"),
    // Array/Object built-ins - commonly used
    ("Array", "from"),
    ("Array", "isArray"),
    ("Object", "keys"),
    ("Object", "values"),
    ("Object", "entries"),
    ("Object", "assign"),
    ("JSON", "parse"),
    ("JSON", "stringify"),
];

fn is_common_pattern(object: &str, property: &str) -> bool {
    COMMON_PATTERNS.iter().any(|(obj, prop)| *obj == object && *prop == property)
}

impl SecurityAnalyzer {
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
            severity: Severity::Warning,
            category: Category::Security,
            rule,
            code_snippet,
        });
    }
}

impl Analyzer for SecurityAnalyzer {
    fn analyze(&self, program: &Program, file_path: &Path, source_code: &str) -> Vec<CodeIssue> {
        let mut issues = Vec::new();

        for stmt in &program.body {
            self.analyze_statement(&mut issues, stmt, file_path, source_code);
        }

        issues
    }
}

impl SecurityAnalyzer {
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
                    if let BindingPatternKind::BindingIdentifier(ident) = &var.id.kind {
                        let name_lower = ident.name.to_lowercase();
                        if name_lower.contains("password") || 
                            name_lower.contains("secret") || 
                            name_lower.contains("token") || 
                            name_lower.contains("apikey") {
                            
                            if let Some(init) = &var.init {
                                if let Expression::StringLiteral(_) = init {
                                    self.add_issue(
                                        issues,
                                        file_path,
                                        source_code,
                                        var.span,
                                        format!("Kemungkinan password/rahasia di-hardcode pada variabel '{}'", ident.name),
                                        "no-hardcoded-secrets".to_string(),
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
            Statement::FunctionDeclaration(func) => {
                if let Some(body) = &func.body {
                    for stmt in &body.statements {
                        self.analyze_statement(issues, stmt, file_path, source_code);
                    }
                }
            }
            Statement::IfStatement(if_stmt) => {
                self.analyze_expression(issues, &if_stmt.test, file_path, source_code);
                self.analyze_statement(issues, &if_stmt.consequent, file_path, source_code);
                if let Some(alternate) = &if_stmt.alternate {
                    self.analyze_statement(issues, alternate, file_path, source_code);
                }
            }
            Statement::ForStatement(for_stmt) => {
                if let Some(init) = &for_stmt.init {
                    match init {
                        ForStatementInit::VariableDeclaration(var_decl) => {
                            for decl in &var_decl.declarations {
                                if let Some(init) = &decl.init {
                                    self.analyze_expression(issues, init, file_path, source_code);
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
                self.analyze_statement(issues, &for_stmt.body, file_path, source_code);
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
            Expression::CallExpression(call_expr) => {
                if let Expression::Identifier(ident) = &call_expr.callee {
                    if ident.name == "eval" {
                        self.add_issue(
                            issues,
                            file_path,
                            source_code,
                            ident.span,
                            "Hindari penggunaan eval() - ini risiko keamanan dan masalah performa".to_string(),
                            "no-eval".to_string(),
                        );
                    }
                    if ident.name == "alert" {
                        self.add_issue(
                            issues,
                            file_path,
                            source_code,
                            ident.span,
                            "Hindari penggunaan alert() - gunakan UI kustom untuk notifikasi".to_string(),
                            "no-alert".to_string(),
                        );
                    }
                    // Detect Function constructor
                    if ident.name == "Function" {
                        self.add_issue(
                            issues,
                            file_path,
                            source_code,
                            ident.span,
                            "Hindari penggunaan Function constructor - ini mirip eval() dan risiko keamanan".to_string(),
                            "no-new-func".to_string(),
                        );
                    }
                }

                // Detect setTimeout/setInterval with string argument
                if let Expression::Identifier(ident) = &call_expr.callee {
                    if ident.name == "setTimeout" || ident.name == "setInterval" {
                        if let Some(first_arg) = call_expr.arguments.first() {
                            if let Some(expr_arg) = first_arg.as_expression() {
                                if matches!(expr_arg, Expression::StringLiteral(_)) {
                                    self.add_issue(
                                        issues,
                                        file_path,
                                        source_code,
                                        call_expr.span,
                                        format!("Hindari penggunaan {} dengan argumen string - gunakan referensi fungsi", ident.name).to_string(),
                                        format!("no-{}-string", ident.name).to_string(),
                                    );
                                }
                            }
                        }
                    }
                }

                // Detect document.write()
                if let Expression::StaticMemberExpression(member) = &call_expr.callee {
                    if let Expression::Identifier(ident) = &member.object {
                        if ident.name == "document" && member.property.name == "write" {
                            self.add_issue(
                                issues,
                                file_path,
                                source_code,
                                call_expr.span,
                                "Hindari penggunaan document.write() - ini akan menghapus seluruh dokumen".to_string(),
                                "no-document-write".to_string(),
                            );
                        }
                    }
                }

                for arg in &call_expr.arguments {
                    match arg {
                        Argument::SpreadElement(spread) => {
                            self.analyze_expression(issues, &spread.argument, file_path, source_code);
                        }
                        _ => {
                            if let Some(expr) = arg.as_expression() {
                                self.analyze_expression(issues, expr, file_path, source_code);
                            }
                        }
                    }
                }

                // Check callee for expressions
                self.analyze_expression(issues, &call_expr.callee, file_path, source_code);
            }
            Expression::NewExpression(new_expr) => {
                // Detect new Function()
                if let Expression::Identifier(ident) = &new_expr.callee {
                    if ident.name == "Function" {
                        self.add_issue(
                            issues,
                            file_path,
                            source_code,
                            new_expr.span,
                            "Hindari penggunaan Function constructor - ini mirip eval() dan risiko keamanan".to_string(),
                            "no-new-func".to_string(),
                        );
                    }
                }

                // Recursively analyze callee and arguments
                self.analyze_expression(issues, &new_expr.callee, file_path, source_code);
                for arg in &new_expr.arguments {
                    if let Some(expr) = arg.as_expression() {
                        self.analyze_expression(issues, expr, file_path, source_code);
                    }
                }
            }
            Expression::AssignmentExpression(assign_expr) => {
                match &assign_expr.left {
                    AssignmentTarget::StaticMemberExpression(member) => {
                        if member.property.name == "innerHTML" {
                            self.add_issue(
                                issues,
                                file_path,
                                source_code,
                                assign_expr.span,
                                "Penggunaan innerHTML dapat menimbulkan serangan XSS. Pertimbangkan menggunakan textContent atau metode DOM".to_string(),
                                "no-inner-html".to_string(),
                            );
                        }
                        if member.property.name == "outerHTML" {
                            self.add_issue(
                                issues,
                                file_path,
                                source_code,
                                assign_expr.span,
                                "Penggunaan outerHTML dapat menimbulkan serangan XSS. Pertimbangkan menggunakan metode DOM".to_string(),
                                "no-outer-html".to_string(),
                            );
                        }
                        self.analyze_expression(issues, &member.object, file_path, source_code);
                    }
                    _ => {}
                }

                self.analyze_expression(issues, &assign_expr.right, file_path, source_code);
            }
            Expression::StaticMemberExpression(member_expr) => {
                if let Expression::Identifier(ident) = &member_expr.object {
                    let method = member_expr.property.name.as_str();

                    // Skip common patterns that are widely accepted
                    if !is_common_pattern(ident.name.as_str(), method) {
                        // Only warn about console methods if not whitelisted
                        if ident.name == "console" && matches!(method, "log" | "debug" | "info" | "warn" | "error") {
                            self.add_issue(
                                issues,
                                file_path,
                                source_code,
                                member_expr.span,
                                format!("Hapus console.{}() sebelum deploy ke produksi", method),
                                "no-console".to_string(),
                            );
                        }
                    }
                }
                self.analyze_expression(issues, &member_expr.object, file_path, source_code);
            }
            Expression::BinaryExpression(bin_expr) => {
                self.analyze_expression(issues, &bin_expr.left, file_path, source_code);
                self.analyze_expression(issues, &bin_expr.right, file_path, source_code);
            }
            Expression::LogicalExpression(logical_expr) => {
                self.analyze_expression(issues, &logical_expr.left, file_path, source_code);
                self.analyze_expression(issues, &logical_expr.right, file_path, source_code);
            }
            Expression::ComputedMemberExpression(comp_member) => {
                self.analyze_expression(issues, &comp_member.object, file_path, source_code);
                self.analyze_expression(issues, &comp_member.expression, file_path, source_code);
            }
            _ => {}
        }
    }
}
