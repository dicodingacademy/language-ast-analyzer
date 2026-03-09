use super::Analyzer;
use crate::types::{CodeIssue, Category, Severity};
use oxc_ast::ast::*;
use oxc_span::Span;
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub struct UnusedAnalyzer;

impl UnusedAnalyzer {
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

    fn analyze_scope(
        &self,
        issues: &mut Vec<CodeIssue>,
        statements: &[Statement],
        file_path: &Path,
        source_code: &str,
    ) {
        let mut declared: HashMap<String, Span> = HashMap::new();
        let mut used: HashSet<String> = HashSet::new();

        // First pass: collect declarations
        for stmt in statements {
            self.collect_declarations(stmt, &mut declared);
        }

        // Second pass: collect usages
        for stmt in statements {
            self.collect_usages(stmt, &mut used);
        }

        // Report unused variables
        for (name, span) in &declared {
            // Skip variables starting with underscore (convention for intentionally unused)
            if !used.contains(name) && !name.starts_with('_') {
                self.add_issue(
                    issues,
                    file_path,
                    source_code,
                    *span,
                    format!("Variabel '{}' dideklarasikan tapi tidak pernah digunakan", name),
                    "no-unused-vars".to_string(),
                    Severity::Suggestion,
                );
            }
        }
    }

    fn collect_declarations(&self, stmt: &Statement, declared: &mut HashMap<String, Span>) {
        match stmt {
            Statement::VariableDeclaration(var_decl) => {
                for var in &var_decl.declarations {
                    if let BindingPatternKind::BindingIdentifier(ident) = &var.id.kind {
                        declared.insert(ident.name.to_string(), ident.span);
                    }
                }
            }
            Statement::FunctionDeclaration(func) => {
                if let Some(id) = &func.id {
                    declared.insert(id.name.to_string(), id.span);
                }
            }
            Statement::BlockStatement(_block) => {
                // Don't recurse into blocks for now to avoid false positives
                // In a full implementation, we'd handle nested scopes properly
            }
            Statement::IfStatement(if_stmt) => {
                self.collect_declarations(&if_stmt.consequent, declared);
                if let Some(alternate) = &if_stmt.alternate {
                    self.collect_declarations(alternate, declared);
                }
            }
            Statement::ForStatement(for_stmt) => {
                if let Some(init) = &for_stmt.init {
                    if let ForStatementInit::VariableDeclaration(var_decl) = init {
                        for var in &var_decl.declarations {
                            if let BindingPatternKind::BindingIdentifier(ident) = &var.id.kind {
                                declared.insert(ident.name.to_string(), ident.span);
                            }
                        }
                    }
                }
                self.collect_declarations(&for_stmt.body, declared);
            }
            Statement::ForInStatement(for_in_stmt) => {
                if let ForStatementLeft::VariableDeclaration(var_decl) = &for_in_stmt.left {
                    for var in &var_decl.declarations {
                        if let BindingPatternKind::BindingIdentifier(ident) = &var.id.kind {
                            declared.insert(ident.name.to_string(), ident.span);
                        }
                    }
                }
                self.collect_declarations(&for_in_stmt.body, declared);
            }
            Statement::ForOfStatement(for_of_stmt) => {
                if let ForStatementLeft::VariableDeclaration(var_decl) = &for_of_stmt.left {
                    for var in &var_decl.declarations {
                        if let BindingPatternKind::BindingIdentifier(ident) = &var.id.kind {
                            declared.insert(ident.name.to_string(), ident.span);
                        }
                    }
                }
                self.collect_declarations(&for_of_stmt.body, declared);
            }
            Statement::WhileStatement(while_stmt) => {
                self.collect_declarations(&while_stmt.body, declared);
            }
            Statement::DoWhileStatement(do_while_stmt) => {
                self.collect_declarations(&do_while_stmt.body, declared);
            }
            Statement::TryStatement(try_stmt) => {
                for stmt in &try_stmt.block.body {
                    self.collect_declarations(stmt, declared);
                }
                if let Some(handler) = &try_stmt.handler {
                    for stmt in &handler.body.body {
                        self.collect_declarations(stmt, declared);
                    }
                }
                if let Some(finalizer) = &try_stmt.finalizer {
                    for stmt in &finalizer.body {
                        self.collect_declarations(stmt, declared);
                    }
                }
            }
            Statement::SwitchStatement(switch_stmt) => {
                for case in &switch_stmt.cases {
                    for stmt in &case.consequent {
                        self.collect_declarations(stmt, declared);
                    }
                }
            }
            _ => {}
        }
    }

    fn collect_usages(&self, stmt: &Statement, used: &mut HashSet<String>) {
        match stmt {
            Statement::ExpressionStatement(expr_stmt) => {
                self.collect_expression_usages(&expr_stmt.expression, used);
            }
            Statement::IfStatement(if_stmt) => {
                self.collect_expression_usages(&if_stmt.test, used);
                self.collect_usages(&if_stmt.consequent, used);
                if let Some(alternate) = &if_stmt.alternate {
                    self.collect_usages(alternate, used);
                }
            }
            Statement::BlockStatement(block) => {
                for stmt in &block.body {
                    self.collect_usages(stmt, used);
                }
            }
            Statement::FunctionDeclaration(func) => {
                if let Some(body) = &func.body {
                    for stmt in &body.statements {
                        self.collect_usages(stmt, used);
                    }
                }
            }
            Statement::ForStatement(for_stmt) => {
                if let Some(test) = &for_stmt.test {
                    self.collect_expression_usages(test, used);
                }
                if let Some(update) = &for_stmt.update {
                    self.collect_expression_usages(update, used);
                }
                self.collect_usages(&for_stmt.body, used);
            }
            Statement::ReturnStatement(ret_stmt) => {
                if let Some(expr) = &ret_stmt.argument {
                    self.collect_expression_usages(expr, used);
                }
            }
            Statement::WhileStatement(while_stmt) => {
                self.collect_expression_usages(&while_stmt.test, used);
                self.collect_usages(&while_stmt.body, used);
            }
            Statement::DoWhileStatement(do_while_stmt) => {
                self.collect_expression_usages(&do_while_stmt.test, used);
                self.collect_usages(&do_while_stmt.body, used);
            }
            Statement::ForInStatement(for_in_stmt) => {
                self.collect_expression_usages(&for_in_stmt.right, used);
                self.collect_usages(&for_in_stmt.body, used);
            }
            Statement::ForOfStatement(for_of_stmt) => {
                self.collect_expression_usages(&for_of_stmt.right, used);
                self.collect_usages(&for_of_stmt.body, used);
            }
            Statement::TryStatement(try_stmt) => {
                for stmt in &try_stmt.block.body {
                    self.collect_usages(stmt, used);
                }
                if let Some(handler) = &try_stmt.handler {
                    for stmt in &handler.body.body {
                        self.collect_usages(stmt, used);
                    }
                }
                if let Some(finalizer) = &try_stmt.finalizer {
                    for stmt in &finalizer.body {
                        self.collect_usages(stmt, used);
                    }
                }
            }
            Statement::SwitchStatement(switch_stmt) => {
                self.collect_expression_usages(&switch_stmt.discriminant, used);
                for case in &switch_stmt.cases {
                    if let Some(test) = &case.test {
                        self.collect_expression_usages(test, used);
                    }
                    for stmt in &case.consequent {
                        self.collect_usages(stmt, used);
                    }
                }
            }
            Statement::ThrowStatement(throw_stmt) => {
                self.collect_expression_usages(&throw_stmt.argument, used);
            }
            Statement::VariableDeclaration(var_decl) => {
                for var in &var_decl.declarations {
                    if let Some(init) = &var.init {
                        self.collect_expression_usages(init, used);
                    }
                }
            }
            _ => {}
        }
    }

    fn collect_expression_usages(&self, expr: &Expression, used: &mut HashSet<String>) {
        match expr {
            Expression::Identifier(ident) => {
                used.insert(ident.name.to_string());
            }
            Expression::CallExpression(call_expr) => {
                self.collect_expression_usages(&call_expr.callee, used);
                for arg in &call_expr.arguments {
                    if let Some(arg_expr) = arg.as_expression() {
                        self.collect_expression_usages(arg_expr, used);
                    }
                }
            }
            Expression::BinaryExpression(bin_expr) => {
                self.collect_expression_usages(&bin_expr.left, used);
                self.collect_expression_usages(&bin_expr.right, used);
            }
            Expression::LogicalExpression(logical_expr) => {
                self.collect_expression_usages(&logical_expr.left, used);
                self.collect_expression_usages(&logical_expr.right, used);
            }
            Expression::AssignmentExpression(assign_expr) => {
                match &assign_expr.left {
                    AssignmentTarget::AssignmentTargetIdentifier(ident) => {
                        used.insert(ident.name.to_string());
                    }
                    _ => {}
                }
                self.collect_expression_usages(&assign_expr.right, used);
            }
            Expression::StaticMemberExpression(member_expr) => {
                self.collect_expression_usages(&member_expr.object, used);
            }
            Expression::ComputedMemberExpression(comp_member) => {
                self.collect_expression_usages(&comp_member.object, used);
                self.collect_expression_usages(&comp_member.expression, used);
            }
            Expression::UnaryExpression(unary_expr) => {
                self.collect_expression_usages(&unary_expr.argument, used);
            }
            Expression::NewExpression(new_expr) => {
                self.collect_expression_usages(&new_expr.callee, used);
                for arg in &new_expr.arguments {
                    if let Some(arg_expr) = arg.as_expression() {
                        self.collect_expression_usages(arg_expr, used);
                    }
                }
            }
            Expression::ConditionalExpression(cond_expr) => {
                self.collect_expression_usages(&cond_expr.test, used);
                self.collect_expression_usages(&cond_expr.consequent, used);
                self.collect_expression_usages(&cond_expr.alternate, used);
            }
            Expression::ArrayExpression(arr_expr) => {
                for elem in &arr_expr.elements {
                    if let Some(expr) = elem.as_expression() {
                        self.collect_expression_usages(expr, used);
                    }
                }
            }
            Expression::ObjectExpression(obj_expr) => {
                for prop in &obj_expr.properties {
                    match prop {
                        ObjectPropertyKind::ObjectProperty(p) => {
                            self.collect_expression_usages(&p.value, used);
                        }
                        ObjectPropertyKind::SpreadProperty(spread) => {
                            self.collect_expression_usages(&spread.argument, used);
                        }
                    }
                }
            }
            Expression::TemplateLiteral(tmpl) => {
                for expr in &tmpl.expressions {
                    self.collect_expression_usages(expr, used);
                }
            }
            Expression::ArrowFunctionExpression(arrow) => {
                for stmt in &arrow.body.statements {
                    self.collect_usages(stmt, used);
                }
            }
            Expression::FunctionExpression(func_expr) => {
                if let Some(body) = &func_expr.body {
                    for stmt in &body.statements {
                        self.collect_usages(stmt, used);
                    }
                }
            }
            Expression::SequenceExpression(seq_expr) => {
                for expr in &seq_expr.expressions {
                    self.collect_expression_usages(expr, used);
                }
            }
            _ => {}
        }
    }
}

impl Analyzer for UnusedAnalyzer {
    fn analyze(&self, program: &Program, file_path: &Path, source_code: &str) -> Vec<CodeIssue> {
        let mut issues = Vec::new();

        self.analyze_scope(&mut issues, &program.body, file_path, source_code);

        issues
    }
}
