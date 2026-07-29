use crate::ast::{
    ActionKind, BinaryOp, Expr, ExprKind, Param, Span, Stmt, TypeAnnotation, UnaryOp,
};
use crate::parser::error::{ParseError, ParseErrorKind};
use crate::token::{Token, TokenKind};

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    unsafe_depth: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            pos: 0,
            unsafe_depth: 0,
        }
    }

    pub fn from_tokens(tokens: &[Token]) -> Result<Vec<Stmt>, ParseError> {
        let mut p = Parser::new(tokens.to_vec());
        p.parse_script()
    }

    pub fn parse_script(&mut self) -> Result<Vec<Stmt>, ParseError> {
        let mut stmts = Vec::new();
        while !self.is_eof() {
            if self.current().kind == TokenKind::Newline {
                self.advance();
                continue;
            }
            stmts.push(self.parse_stmt()?);
        }
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt, ParseError> {
        match &self.current().kind {
            TokenKind::Tilde => self.parse_tilde_stmt(),
            TokenKind::Dollar => {
                if self.is_assign_start() {
                    self.parse_assign()
                } else {
                    self.parse_expr_stmt()
                }
            }
            TokenKind::Bang => self.parse_action_stmt(),
            TokenKind::Caret => self.parse_return_stmt(),
            TokenKind::Import => self.parse_import_stmt(),
            _ => {
                if self.is_expr_stmt_start() {
                    self.parse_expr_stmt()
                } else {
                    Err(self.error_expected("statement"))
                }
            }
        }
    }

    fn parse_expr_stmt(&mut self) -> Result<Stmt, ParseError> {
        let expr = self.parse_expr()?;
        Ok(Stmt::Expr {
            span: expr.span.clone(),
            expr,
        })
    }

    fn is_expr_stmt_start(&self) -> bool {
        matches!(
            self.current().kind,
            TokenKind::Ident(_)
                | TokenKind::Number(_)
                | TokenKind::StringLit(_)
                | TokenKind::BytesLit(_)
                | TokenKind::LParen
                | TokenKind::LBracket
                | TokenKind::LBrace
                | TokenKind::Minus
        )
    }

    fn is_assign_start(&self) -> bool {
        if !matches!(self.current().kind, TokenKind::Dollar) {
            return false;
        }
        if !matches!(self.peek_kind(), Some(TokenKind::Ident(_))) {
            return false;
        }
        match self.peek_kind_n(2) {
            Some(TokenKind::Assign) => return true,
            Some(TokenKind::LBracket) => {}
            _ => return false,
        }

        // Support indexed assignment form: `$name[expr] = value`.
        let mut i = 2usize;
        let mut depth = 0usize;
        loop {
            match self.peek_kind_n(i) {
                Some(TokenKind::LBracket) => {
                    depth += 1;
                }
                Some(TokenKind::RBracket) => {
                    if depth == 0 {
                        return false;
                    }
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                Some(TokenKind::Eof) | None => return false,
                _ => {}
            }
            i += 1;
        }
        matches!(self.peek_kind_n(i), Some(TokenKind::Assign))
    }

    fn parse_tilde_stmt(&mut self) -> Result<Stmt, ParseError> {
        self.expect(TokenKind::Tilde)?;
        match &self.current().kind {
            TokenKind::Rite => self.parse_rite_block(),
            TokenKind::Unsafe => self.parse_unsafe_block(),
            TokenKind::Fn => self.parse_fn_block(),
            TokenKind::If => self.parse_if_block(),
            TokenKind::Loop => self.parse_loop_block(),
            TokenKind::Each => self.parse_each_block(),
            TokenKind::While => self.parse_while_block(),
            _ => Err(self.error_unexpected()),
        }
    }

    fn parse_rite_block(&mut self) -> Result<Stmt, ParseError> {
        let span = Some(self.current().span.clone());
        self.expect(TokenKind::Rite)?;
        self.optional_newlines();
        let mut body = Vec::new();
        while !(self.current().kind == TokenKind::Tilde
            && self.peek_kind() == Some(&TokenKind::End))
        {
            if self.is_eof() {
                return Err(self.error_expected("~ end"));
            }
            body.push(self.parse_stmt()?);
            self.optional_newlines();
        }
        self.expect(TokenKind::Tilde)?;
        self.expect(TokenKind::End)?;
        Ok(Stmt::Rite { body, span })
    }

    fn parse_unsafe_block(&mut self) -> Result<Stmt, ParseError> {
        let span = Some(self.current().span.clone());
        self.expect(TokenKind::Unsafe)?;
        self.optional_newlines();
        self.unsafe_depth += 1;
        let body_res: Result<Vec<Stmt>, ParseError> = (|| {
            let mut body = Vec::new();
            while !(self.current().kind == TokenKind::Tilde
                && self.peek_kind() == Some(&TokenKind::End))
            {
                if self.is_eof() {
                    return Err(self.error_expected("~ end"));
                }
                body.push(self.parse_stmt()?);
                self.optional_newlines();
            }
            Ok(body)
        })();
        self.unsafe_depth = self.unsafe_depth.saturating_sub(1);
        let body = body_res?;
        self.expect(TokenKind::Tilde)?;
        self.expect(TokenKind::End)?;
        Ok(Stmt::Unsafe { body, span })
    }

    fn parse_fn_block(&mut self) -> Result<Stmt, ParseError> {
        let span = Some(self.current().span.clone());
        self.expect(TokenKind::Fn)?;
        let name = self.parse_ident_string()?;
        self.expect(TokenKind::LParen)?;
        let mut params = Vec::new();
        if self.current().kind != TokenKind::RParen {
            loop {
                if self.current().kind == TokenKind::Dollar {
                    self.advance();
                }
                let name = self.parse_ident_string()?;
                let annotation = if self.current().kind == TokenKind::Colon {
                    self.advance();
                    Some(TypeAnnotation {
                        base: self.parse_ident_string()?,
                        predicate: None,
                    })
                } else {
                    None
                };
                params.push(Param { name, annotation });
                if self.current().kind == TokenKind::Comma {
                    self.advance();
                    continue;
                }
                break;
            }
        }
        self.expect(TokenKind::RParen)?;
        let return_type = if self.current().kind == TokenKind::Arrow {
            self.advance();
            Some(TypeAnnotation {
                base: self.parse_ident_string()?,
                predicate: None,
            })
        } else {
            None
        };
        self.optional_newlines();
        let mut body = Vec::new();
        while !(self.current().kind == TokenKind::Tilde
            && self.peek_kind() == Some(&TokenKind::End))
        {
            body.push(self.parse_stmt()?);
            self.optional_newlines();
        }
        self.expect(TokenKind::Tilde)?;
        self.expect(TokenKind::End)?;
        Ok(Stmt::FnDef {
            name,
            params,
            body,
            return_type,
            span,
        })
    }

    fn parse_if_block(&mut self) -> Result<Stmt, ParseError> {
        let span = Some(self.current().span.clone());
        self.expect(TokenKind::If)?;
        let cond = self.parse_expr()?;
        self.optional_newlines();
        let mut then_block = Vec::new();
        let mut else_block = Vec::new();
        while !(self.current().kind == TokenKind::Tilde
            && matches!(
                self.peek_kind(),
                Some(TokenKind::Else) | Some(TokenKind::End)
            ))
        {
            then_block.push(self.parse_stmt()?);
            self.optional_newlines();
        }
        if self.current().kind == TokenKind::Tilde && self.peek_kind() == Some(&TokenKind::Else) {
            self.expect(TokenKind::Tilde)?;
            self.expect(TokenKind::Else)?;
            self.optional_newlines();
            while !(self.current().kind == TokenKind::Tilde
                && self.peek_kind() == Some(&TokenKind::End))
            {
                else_block.push(self.parse_stmt()?);
                self.optional_newlines();
            }
        }
        self.expect(TokenKind::Tilde)?;
        self.expect(TokenKind::End)?;
        Ok(Stmt::If {
            cond,
            then_block,
            else_block,
            span,
        })
    }

    fn parse_loop_block(&mut self) -> Result<Stmt, ParseError> {
        let span = Some(self.current().span.clone());
        self.expect(TokenKind::Loop)?;
        let count = self.parse_expr()?;
        self.optional_newlines();
        let mut body = Vec::new();
        while !(self.current().kind == TokenKind::Tilde
            && self.peek_kind() == Some(&TokenKind::End))
        {
            body.push(self.parse_stmt()?);
            self.optional_newlines();
        }
        self.expect(TokenKind::Tilde)?;
        self.expect(TokenKind::End)?;
        Ok(Stmt::Loop { count, body, span })
    }

    fn parse_each_block(&mut self) -> Result<Stmt, ParseError> {
        let span = Some(self.current().span.clone());
        self.expect(TokenKind::Each)?;
        let var = self.parse_ident_string()?;
        self.expect(TokenKind::In)?;
        let iter = self.parse_expr()?;
        self.optional_newlines();
        let mut body = Vec::new();
        while !(self.current().kind == TokenKind::Tilde
            && self.peek_kind() == Some(&TokenKind::End))
        {
            body.push(self.parse_stmt()?);
            self.optional_newlines();
        }
        self.expect(TokenKind::Tilde)?;
        self.expect(TokenKind::End)?;
        Ok(Stmt::Each {
            var,
            iter,
            body,
            span,
        })
    }

    fn parse_while_block(&mut self) -> Result<Stmt, ParseError> {
        let span = Some(self.current().span.clone());
        self.expect(TokenKind::While)?;
        let cond = self.parse_expr()?;
        self.optional_newlines();
        let mut body = Vec::new();
        while !(self.current().kind == TokenKind::Tilde
            && self.peek_kind() == Some(&TokenKind::End))
        {
            body.push(self.parse_stmt()?);
            self.optional_newlines();
        }
        self.expect(TokenKind::Tilde)?;
        self.expect(TokenKind::End)?;
        Ok(Stmt::While { cond, body, span })
    }

    fn parse_assign(&mut self) -> Result<Stmt, ParseError> {
        let span = Some(self.current().span.clone());
        self.expect(TokenKind::Dollar)?;
        let name = self.parse_ident_string()?;
        let mut index_expr: Option<Expr> = None;
        if self.current().kind == TokenKind::LBracket {
            self.advance(); // consume '['
            let idx = self.parse_expr()?;
            self.expect(TokenKind::RBracket)?;
            index_expr = Some(idx);
        }
        self.expect(TokenKind::Assign)?;
        let value_expr = self.parse_expr()?;
        let expr = if let Some(idx) = index_expr {
            let callee = Expr::new(ExprKind::Var("__setindex".into()), span.clone());
            let target = Expr::new(ExprKind::Var(name.clone()), span.clone());
            Expr::new(
                ExprKind::Call {
                    callee: Box::new(callee),
                    args: vec![target, idx, value_expr],
                },
                span.clone(),
            )
        } else {
            value_expr
        };
        Ok(Stmt::Assign {
            name,
            annotation: None,
            expr,
            span,
        })
    }

    fn parse_return_stmt(&mut self) -> Result<Stmt, ParseError> {
        let span = Some(self.current().span.clone());
        self.expect(TokenKind::Caret)?;
        if self.current().kind == TokenKind::Newline || self.current().kind == TokenKind::Eof {
            return Ok(Stmt::Return { value: None, span });
        }
        let value = self.parse_expr()?;
        Ok(Stmt::Return {
            value: Some(value),
            span,
        })
    }

    fn parse_import_stmt(&mut self) -> Result<Stmt, ParseError> {
        let span = Some(self.current().span.clone());
        self.expect(TokenKind::Import)?;
        let path = match self.current().kind.clone() {
            TokenKind::StringLit(s) => {
                self.advance();
                s
            }
            other => {
                return Err(ParseError {
                    kind: ParseErrorKind::UnexpectedToken(other),
                    span: self.current().span.clone(),
                    message: "Expected string literal after import".into(),
                })
            }
        };
        Ok(Stmt::Import { module: path, span })
    }

    fn parse_action_stmt(&mut self) -> Result<Stmt, ParseError> {
        let span = Some(self.current().span.clone());
        self.expect(TokenKind::Bang)?;
        let action = match self.current().kind.clone() {
            TokenKind::Ident(name) => {
                self.advance();
                match name.as_str() {
                    "say" => {
                        let value = self.parse_expr()?;
                        ActionKind::Say { value }
                    }
                    "ask" => {
                        let prompt = self.parse_expr()?;
                        ActionKind::Ask { prompt }
                    }
                    "fetch" => {
                        let target = self.parse_expr()?;
                        ActionKind::Fetch { target }
                    }
                    "log" => {
                        let value = self.parse_expr()?;
                        ActionKind::Log { value }
                    }
                    "syscall" => self.parse_syscall_action()?,
                    other => return Err(self.error_custom(format!("Unknown action '!{}'", other))),
                }
            }
            other => {
                return Err(ParseError {
                    kind: ParseErrorKind::UnexpectedToken(other),
                    span: self.current().span.clone(),
                    message: "Expected action name".into(),
                })
            }
        };
        Ok(Stmt::Action { action, span })
    }

    fn parse_syscall_action(&mut self) -> Result<ActionKind, ParseError> {
        if self.unsafe_depth == 0 {
            return Err(self.error_custom("!syscall is only allowed inside `~ unsafe ... ~ end`"));
        }
        let number = self.parse_expr()?;
        let mut args: Vec<Expr> = Vec::new();
        if self.current().kind == TokenKind::Comma {
            self.advance();
            let args_expr = self.parse_expr()?;
            match args_expr.kind {
                ExprKind::List(items) => {
                    if items.len() > 6 {
                        return Err(self.error_custom("!syscall supports at most 6 arguments"));
                    }
                    args = items;
                }
                _ => {
                    return Err(
                        self.error_custom("!syscall args must be a list literal: [a0, a1, ...]")
                    )
                }
            }
        }

        let mut out: Option<String> = None;
        if self.current().kind == TokenKind::Arrow {
            self.advance();
            if self.current().kind == TokenKind::Dollar {
                self.advance();
            }
            out = Some(self.parse_ident_string()?);
        }

        Ok(ActionKind::Syscall { number, args, out })
    }

    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        self.parse_binary_expr(0)
    }

    // Pratt parser for expressions
    fn parse_binary_expr(&mut self, min_prec: u8) -> Result<Expr, ParseError> {
        let mut left = self.parse_unary_expr()?;
        while let Some((op, prec, right_assoc)) = self.peek_binary_op() {
            if prec < min_prec {
                break;
            }
            let op_span = Some(self.current().span.clone());
            self.advance(); // consume op
            let next_min_prec = if right_assoc { prec } else { prec + 1 };
            let right = self.parse_binary_expr(next_min_prec)?;
            left = Expr::new(
                ExprKind::Binary {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                },
                op_span,
            );
        }
        Ok(left)
    }

    fn parse_unary_expr(&mut self) -> Result<Expr, ParseError> {
        match self.current().kind.clone() {
            TokenKind::Bang => {
                let span = Some(self.current().span.clone());
                self.advance();
                let expr = self.parse_unary_expr()?;
                Ok(Expr::new(
                    ExprKind::Unary {
                        op: UnaryOp::Not,
                        expr: Box::new(expr),
                    },
                    span,
                ))
            }
            TokenKind::Minus => {
                let span = Some(self.current().span.clone());
                self.advance();
                let expr = self.parse_unary_expr()?;
                Ok(Expr::new(
                    ExprKind::Unary {
                        op: UnaryOp::Neg,
                        expr: Box::new(expr),
                    },
                    span,
                ))
            }
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.parse_primary()?;
        loop {
            match self.current().kind.clone() {
                TokenKind::LParen => {
                    let span = Some(self.current().span.clone());
                    self.advance(); // consume (
                    let mut args = Vec::new();
                    if self.current().kind != TokenKind::RParen {
                        loop {
                            let arg = self.parse_expr()?;
                            args.push(arg);
                            if self.current().kind == TokenKind::Comma {
                                self.advance();
                                continue;
                            }
                            break;
                        }
                    }
                    self.expect(TokenKind::RParen)?;
                    expr = Expr::new(
                        ExprKind::Call {
                            callee: Box::new(expr),
                            args,
                        },
                        span,
                    );
                }
                TokenKind::LBracket => {
                    let span = Some(self.current().span.clone());
                    self.advance();
                    let idx = self.parse_expr()?;
                    self.expect(TokenKind::RBracket)?;
                    expr = Expr::new(
                        ExprKind::Index {
                            target: Box::new(expr),
                            index: Box::new(idx),
                        },
                        span,
                    );
                }
                TokenKind::Dot => {
                    let span = Some(self.current().span.clone());
                    self.advance();
                    let field = self.parse_ident_string()?;
                    expr = Expr::new(
                        ExprKind::Field {
                            target: Box::new(expr),
                            field,
                        },
                        span,
                    );
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        let tok = self.current().clone();
        match tok.kind {
            TokenKind::Dollar => {
                let span = Some(tok.span.clone());
                self.advance();
                let name = self.parse_ident_string()?;
                Ok(Expr::new(ExprKind::Var(name), span))
            }
            TokenKind::Number(n) => {
                let span = Some(tok.span.clone());
                self.advance();
                Ok(Expr::new(ExprKind::Number(n), span))
            }
            TokenKind::StringLit(s) => {
                let span = Some(tok.span.clone());
                self.advance();
                Ok(Expr::new(ExprKind::Text(s), span))
            }
            TokenKind::BytesLit(bytes) => {
                let span = Some(tok.span.clone());
                self.advance();
                Ok(Expr::new(ExprKind::Bytes(bytes), span))
            }
            TokenKind::Ident(name) => {
                let span = Some(tok.span.clone());
                self.advance();
                if name == "true" {
                    Ok(Expr::new(ExprKind::Bool(true), span))
                } else if name == "false" {
                    Ok(Expr::new(ExprKind::Bool(false), span))
                } else {
                    Ok(Expr::new(ExprKind::Var(name), span))
                }
            }
            TokenKind::LParen => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect(TokenKind::RParen)?;
                Ok(expr)
            }
            TokenKind::LBracket => {
                let span = Some(tok.span.clone());
                self.advance();
                let mut items = Vec::new();
                if self.current().kind != TokenKind::RBracket {
                    loop {
                        let item = self.parse_expr()?;
                        items.push(item);
                        if self.current().kind == TokenKind::Comma {
                            self.advance();
                            continue;
                        }
                        break;
                    }
                }
                self.expect(TokenKind::RBracket)?;
                Ok(Expr::new(ExprKind::List(items), span))
            }
            TokenKind::LBrace => {
                let span = Some(tok.span.clone());
                self.advance();
                let mut entries = Vec::new();
                if self.current().kind != TokenKind::RBrace {
                    loop {
                        let key = self.parse_ident_string()?;
                        self.expect(TokenKind::Colon)?;
                        let val = self.parse_expr()?;
                        entries.push((key, val));
                        if self.current().kind == TokenKind::Comma {
                            self.advance();
                            continue;
                        }
                        break;
                    }
                }
                self.expect(TokenKind::RBrace)?;
                Ok(Expr::new(ExprKind::Map(entries), span))
            }
            _ => Err(self.error_custom("Expected expression")),
        }
    }

    fn peek_binary_op(&self) -> Option<(BinaryOp, u8, bool)> {
        match self.current().kind {
            TokenKind::Plus => Some((BinaryOp::Add, 10, false)),
            TokenKind::Minus => Some((BinaryOp::Sub, 10, false)),
            TokenKind::Star => Some((BinaryOp::Mul, 20, false)),
            TokenKind::Slash => Some((BinaryOp::Div, 20, false)),
            TokenKind::Percent => Some((BinaryOp::Mod, 20, false)),
            TokenKind::Op(ref s) if s == "<<" => Some((BinaryOp::Shl, 9, false)),
            TokenKind::Caret => Some((BinaryOp::Xor, 7, false)),
            TokenKind::Op(ref s) if s == "==" => Some((BinaryOp::Eq, 5, false)),
            TokenKind::Op(ref s) if s == "!=" => Some((BinaryOp::Ne, 5, false)),
            TokenKind::Op(ref s) if s == ">" => Some((BinaryOp::Gt, 5, false)),
            TokenKind::Op(ref s) if s == "<" => Some((BinaryOp::Lt, 5, false)),
            TokenKind::Op(ref s) if s == ">=" => Some((BinaryOp::Ge, 5, false)),
            TokenKind::Op(ref s) if s == "<=" => Some((BinaryOp::Le, 5, false)),
            TokenKind::AndAnd => Some((BinaryOp::And, 3, false)),
            TokenKind::OrOr => Some((BinaryOp::Or, 2, false)),
            _ => None,
        }
    }

    fn parse_ident_string(&mut self) -> Result<String, ParseError> {
        match self.current().kind.clone() {
            TokenKind::Ident(s) => {
                self.advance();
                Ok(s)
            }
            other => Err(ParseError {
                kind: ParseErrorKind::UnexpectedToken(other),
                span: self.current().span.clone(),
                message: "Expected identifier".into(),
            }),
        }
    }

    fn optional_newlines(&mut self) {
        while self.current().kind == TokenKind::Newline {
            self.advance();
        }
    }

    fn expect(&mut self, kind: TokenKind) -> Result<(), ParseError> {
        let cur = self.current().clone();
        if cur.kind == kind {
            self.advance();
            Ok(())
        } else {
            Err(ParseError {
                kind: ParseErrorKind::UnexpectedToken(cur.kind),
                span: cur.span,
                message: format!("Expected {:?}", kind),
            })
        }
    }

    fn advance(&mut self) {
        if !self.is_eof() {
            self.pos += 1;
        }
    }

    fn current(&self) -> &Token {
        self.tokens
            .get(self.pos)
            .unwrap_or_else(|| self.tokens.last().unwrap())
    }

    fn peek_kind(&self) -> Option<&TokenKind> {
        self.tokens.get(self.pos + 1).map(|t| &t.kind)
    }

    fn peek_kind_n(&self, n: usize) -> Option<&TokenKind> {
        self.tokens.get(self.pos + n).map(|t| &t.kind)
    }

    fn is_eof(&self) -> bool {
        matches!(self.current().kind, TokenKind::Eof)
    }

    fn error_unexpected(&self) -> ParseError {
        let cur = self.current();
        ParseError {
            kind: ParseErrorKind::UnexpectedToken(cur.kind.clone()),
            span: cur.span.clone(),
            message: "Unexpected token".into(),
        }
    }

    fn error_expected(&self, what: &'static str) -> ParseError {
        let cur = self.current();
        ParseError {
            kind: ParseErrorKind::ExpectedToken(what),
            span: cur.span.clone(),
            message: format!("Expected {}", what),
        }
    }

    fn error_custom(&self, msg: impl Into<String>) -> ParseError {
        let cur = self.current();
        ParseError {
            kind: ParseErrorKind::UnexpectedToken(cur.kind.clone()),
            span: cur.span.clone(),
            message: msg.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{lexer, parser::Parser};

    #[test]
    fn parse_syscall_inside_unsafe_ok() {
        let src = r#"
~ unsafe
    !syscall 39 -> $pid
~ end
"#;
        let tokens = lexer::lex(src).expect("lex");
        let ast = Parser::from_tokens(&tokens).expect("parse");
        assert!(!ast.is_empty());
    }

    #[test]
    fn parse_syscall_outside_unsafe_rejected() {
        let src = r#"
~ rite
    !syscall 39 -> $pid
~ end
"#;
        let tokens = lexer::lex(src).expect("lex");
        let err = Parser::from_tokens(&tokens).expect_err("expected parse failure");
        assert!(err.message.contains("only allowed inside"));
    }

    #[test]
    fn parse_syscall_rejects_too_many_args() {
        let src = r#"
~ unsafe
    !syscall 1, [1,2,3,4,5,6,7] -> $ret
~ end
"#;
        let tokens = lexer::lex(src).expect("lex");
        let err = Parser::from_tokens(&tokens).expect_err("expected parse failure");
        assert!(err.message.contains("at most 6"));
    }
}
