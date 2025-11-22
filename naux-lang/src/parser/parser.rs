use crate::ast::{ActionKind, BinaryOp, Expr, Stmt, UnaryOp};
use crate::parser::error::{ParseError, ParseErrorKind};
use crate::token::{Token, TokenKind};

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
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
            TokenKind::Dollar => self.parse_assign(),
            TokenKind::Bang => self.parse_action_stmt(),
            _ => Err(self.error_expected("statement")),
        }
    }

    fn parse_tilde_stmt(&mut self) -> Result<Stmt, ParseError> {
        self.expect(TokenKind::Tilde)?;
        match &self.current().kind {
            TokenKind::Rite => self.parse_rite_block(),
            TokenKind::If => self.parse_if_block(),
            TokenKind::Loop => self.parse_loop_block(),
            TokenKind::Each => self.parse_each_block(),
            TokenKind::While => self.parse_while_block(),
            _ => Err(self.error_unexpected()),
        }
    }

    fn parse_rite_block(&mut self) -> Result<Stmt, ParseError> {
        let span = self.current().span.clone();
        self.expect(TokenKind::Rite)?;
        self.optional_newlines();
        let mut body = Vec::new();
        while !(self.current().kind == TokenKind::Tilde && self.peek_kind() == Some(&TokenKind::End)) {
            if self.is_eof() {
                return Err(self.error_expected("~ end"));
            }
            body.push(self.parse_stmt()?);
            self.optional_newlines();
        }
        self.expect(TokenKind::Tilde)?;
        self.expect(TokenKind::End)?;
        Ok(Stmt::Rite { body, span: Some(span) })
    }

    fn parse_if_block(&mut self) -> Result<Stmt, ParseError> {
        let span = self.current().span.clone();
        self.expect(TokenKind::If)?;
        let cond = self.parse_expr()?;
        self.optional_newlines();
        let mut then_block = Vec::new();
        let mut else_block = Vec::new();
        while !(self.current().kind == TokenKind::Tilde && matches!(self.peek_kind(), Some(TokenKind::Else) | Some(TokenKind::End))) {
            then_block.push(self.parse_stmt()?);
            self.optional_newlines();
        }
        if self.current().kind == TokenKind::Tilde && self.peek_kind() == Some(&TokenKind::Else) {
            self.expect(TokenKind::Tilde)?;
            self.expect(TokenKind::Else)?;
            self.optional_newlines();
            while !(self.current().kind == TokenKind::Tilde && self.peek_kind() == Some(&TokenKind::End)) {
                else_block.push(self.parse_stmt()?);
                self.optional_newlines();
            }
        }
        self.expect(TokenKind::Tilde)?;
        self.expect(TokenKind::End)?;
        Ok(Stmt::If { cond, then_block, else_block, span: Some(span) })
    }

    fn parse_loop_block(&mut self) -> Result<Stmt, ParseError> {
        let span = self.current().span.clone();
        self.expect(TokenKind::Loop)?;
        let count = self.parse_expr()?;
        self.optional_newlines();
        let mut body = Vec::new();
        while !(self.current().kind == TokenKind::Tilde && self.peek_kind() == Some(&TokenKind::End)) {
            body.push(self.parse_stmt()?);
            self.optional_newlines();
        }
        self.expect(TokenKind::Tilde)?;
        self.expect(TokenKind::End)?;
        Ok(Stmt::Loop { count, body, span: Some(span) })
    }

    fn parse_each_block(&mut self) -> Result<Stmt, ParseError> {
        let span = self.current().span.clone();
        self.expect(TokenKind::Each)?;
        let var = self.parse_ident_string()?;
        self.expect(TokenKind::In)?;
        let iter = self.parse_expr()?;
        self.optional_newlines();
        let mut body = Vec::new();
        while !(self.current().kind == TokenKind::Tilde && self.peek_kind() == Some(&TokenKind::End)) {
            body.push(self.parse_stmt()?);
            self.optional_newlines();
        }
        self.expect(TokenKind::Tilde)?;
        self.expect(TokenKind::End)?;
        Ok(Stmt::Each { var, iter, body, span: Some(span) })
    }

    fn parse_while_block(&mut self) -> Result<Stmt, ParseError> {
        let span = self.current().span.clone();
        self.expect(TokenKind::While)?;
        let cond = self.parse_expr()?;
        self.optional_newlines();
        let mut body = Vec::new();
        while !(self.current().kind == TokenKind::Tilde && self.peek_kind() == Some(&TokenKind::End)) {
            body.push(self.parse_stmt()?);
            self.optional_newlines();
        }
        self.expect(TokenKind::Tilde)?;
        self.expect(TokenKind::End)?;
        Ok(Stmt::While { cond, body, span: Some(span) })
    }

    fn parse_assign(&mut self) -> Result<Stmt, ParseError> {
        let span = self.current().span.clone();
        self.expect(TokenKind::Dollar)?;
        let name = self.parse_ident_string()?;
        self.expect(TokenKind::Assign)?;
        let expr = self.parse_expr()?;
        Ok(Stmt::Assign { name, expr, span: Some(span) })
    }

    fn parse_action_stmt(&mut self) -> Result<Stmt, ParseError> {
        let span = self.current().span.clone();
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
                    other => return Err(self.error_custom(format!("Unknown action '!{}'", other))),
                }
            }
            other => return Err(ParseError {
                kind: ParseErrorKind::UnexpectedToken(other),
                span: self.current().span.clone(),
                message: "Expected action name".into(),
            }),
        };
        Ok(Stmt::Action { action, span: Some(span) })
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
            self.advance(); // consume op
            let next_min_prec = if right_assoc { prec } else { prec + 1 };
            let right = self.parse_binary_expr(next_min_prec)?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_unary_expr(&mut self) -> Result<Expr, ParseError> {
        match self.current().kind {
            TokenKind::Bang => {
                self.advance();
                let expr = self.parse_unary_expr()?;
                Ok(Expr::Unary { op: UnaryOp::Not, expr: Box::new(expr) })
            }
            TokenKind::Minus => {
                self.advance();
                let expr = self.parse_unary_expr()?;
                Ok(Expr::Unary { op: UnaryOp::Neg, expr: Box::new(expr) })
            }
            _ => self.parse_primary(),
        }
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        let tok = self.current().clone();
        match tok.kind {
            TokenKind::Number(n) => {
                self.advance();
                Ok(Expr::Number(n))
            }
            TokenKind::StringLit(s) => {
                self.advance();
                Ok(Expr::Text(s))
            }
            TokenKind::Ident(name) => {
                self.advance();
                if name == "true" {
                    Ok(Expr::Bool(true))
                } else if name == "false" {
                    Ok(Expr::Bool(false))
                } else {
                    Ok(Expr::Var(name))
                }
            }
            TokenKind::LParen => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect(TokenKind::RParen)?;
                Ok(expr)
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
            TokenKind::Op(ref s) if s == "==" => Some((BinaryOp::Eq, 5, false)),
            TokenKind::Op(ref s) if s == "!=" => Some((BinaryOp::Ne, 5, false)),
            TokenKind::Op(ref s) if s == ">" => Some((BinaryOp::Gt, 5, false)),
            TokenKind::Op(ref s) if s == "<" => Some((BinaryOp::Lt, 5, false)),
            TokenKind::Op(ref s) if s == ">=" => Some((BinaryOp::Ge, 5, false)),
            TokenKind::Op(ref s) if s == "<=" => Some((BinaryOp::Le, 5, false)),
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
        self.tokens.get(self.pos).unwrap_or_else(|| self.tokens.last().unwrap())
    }

    fn peek_kind(&self) -> Option<&TokenKind> {
        self.tokens.get(self.pos + 1).map(|t| &t.kind)
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
