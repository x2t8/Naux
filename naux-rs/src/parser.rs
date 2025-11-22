use crate::ast::{
    Action, Arg, Assign, Expr, If, Loop, Program, Ritual, Statement, VarRef,
};
use crate::lexer::{LexError, Lexer, Token, TokenKind};
use serde_json::Value;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Lex error: {0}")]
    Lex(#[from] LexError),
    #[error("{msg} at line {line}, col {col}")]
    Expected { msg: String, line: usize, col: usize },
    #[error("Unexpected token {found:?} at line {line}, col {col}")]
    Unexpected {
        found: TokenKind,
        line: usize,
        col: usize,
    },
}

pub fn format_parse_error(src: &str, err: &ParseError) -> String {
    let (msg, line, col) = match err {
        ParseError::Lex(LexError::UnexpectedChar { ch, line, col }) => {
            (format!("Unexpected character '{}'", ch), *line, *col)
        }
        ParseError::Lex(LexError::UnterminatedString { line, col }) => {
            ("Unterminated string literal".to_string(), *line, *col)
        }
        ParseError::Expected { msg, line, col } => (msg.clone(), *line, *col),
        ParseError::Unexpected { found, line, col } => (
            format!("Unexpected token {:?}", found),
            *line,
            *col,
        ),
    };
    let line_text = src.lines().nth(line.saturating_sub(1)).unwrap_or("");
    let caret = format!(
        "{}^",
        " ".repeat(col.saturating_sub(1))
    );
    format!("Parse error: {}\n --> line {}, col {}\n {}\n {}", msg, line, col, line_text, caret)
}

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub fn new(src: &str) -> Result<Self, ParseError> {
        let tokens = Lexer::new(src).tokenize()?;
        Ok(Self { tokens, pos: 0 })
    }

    fn current(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn peek(&self, offset: usize) -> &Token {
        self.tokens
            .get(self.pos + offset)
            .unwrap_or_else(|| self.tokens.last().unwrap())
    }

    fn advance(&mut self) -> Token {
        let tok = self.current().clone();
        self.pos += 1;
        tok
    }

    fn match_kind(&mut self, kind: TokenKind) -> bool {
        if self.current().kind == kind {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, kind: TokenKind, msg: &str) -> Result<Token, ParseError> {
        let tok = self.current().clone();
        if tok.kind == kind {
            self.advance();
            Ok(tok)
        } else {
            Err(ParseError::Expected {
                msg: msg.to_string(),
                line: tok.line,
                col: tok.col,
            })
        }
    }

    fn skip_newlines(&mut self) {
        while self.match_kind(TokenKind::Newline) {}
    }

    pub fn parse_program(&mut self) -> Result<Program, ParseError> {
        let mut rituals = Vec::new();
        self.skip_newlines();
        while self.current().kind != TokenKind::Eof {
            rituals.push(self.parse_ritual()?);
            self.skip_newlines();
        }
        Ok(rituals)
    }

    fn parse_ritual(&mut self) -> Result<Ritual, ParseError> {
        self.expect(TokenKind::Tilde, "Expected '~' to start ritual")?;
        let rite_kw = self.expect(TokenKind::Ident, "Expected 'rite'")?;
        if rite_kw.lexeme != "rite" {
            return Err(ParseError::Expected {
                msg: "Expected 'rite' after '~'".into(),
                line: rite_kw.line,
                col: rite_kw.col,
            });
        }
        let name_tok = self.expect(TokenKind::Ident, "Expected ritual name")?;
        self.match_kind(TokenKind::Newline);

        let mut body = Vec::new();
        self.skip_newlines();
        while !self.is_end_of_ritual() {
            let stmt = self.parse_statement()?;
            body.push(stmt);
            self.match_kind(TokenKind::Newline);
            self.skip_newlines();
        }

        self.expect(TokenKind::Tilde, "Expected '~' to close ritual")?;
        let end_kw = self.expect(TokenKind::Ident, "Expected 'end'")?;
        if end_kw.lexeme != "end" {
            return Err(ParseError::Expected {
                msg: "Expected 'end' after '~'".into(),
                line: end_kw.line,
                col: end_kw.col,
            });
        }
        self.match_kind(TokenKind::Newline);
        Ok(Ritual {
            name: name_tok.lexeme,
            body,
        })
    }

    fn is_end_of_ritual(&self) -> bool {
        self.current().kind == TokenKind::Tilde
            && self.peek(1).kind == TokenKind::Ident
            && self.peek(1).lexeme == "end"
    }

    fn parse_statement(&mut self) -> Result<Statement, ParseError> {
        match &self.current().kind {
            TokenKind::Bang => Ok(Statement::Action(self.parse_action(true)?)),
            TokenKind::Var => Ok(Statement::Assign(self.parse_assign()?)),
            TokenKind::At => self.parse_control(),
            other => Err(ParseError::Unexpected {
                found: other.clone(),
                line: self.current().line,
                col: self.current().col,
            }),
        }
    }

    fn parse_action(&mut self, allow_callback: bool) -> Result<Action, ParseError> {
        self.expect(TokenKind::Bang, "Expected '!'")?;
        let name_tok = self.expect(TokenKind::Ident, "Expected action name")?;
        let mut args = Vec::new();
        let mut callback: Option<Box<Action>> = None;

        loop {
            let cur_kind = self.current().kind.clone();
            if allow_callback && cur_kind == TokenKind::Arrow {
                self.advance();
                let cb = self.parse_action(false)?;
                callback = Some(Box::new(cb));
                break;
            }
            if matches!(cur_kind, TokenKind::Newline | TokenKind::Eof) {
                break;
            }
            if self.is_block_end_marker() {
                break;
            }

            if let Some(arg) = self.try_parse_arg()? {
                args.push(arg);
            } else {
                break;
            }
        }

        Ok(Action {
            name: name_tok.lexeme,
            args,
            callback,
        })
    }

    fn is_block_end_marker(&self) -> bool {
        if self.current().kind != TokenKind::At {
            return false;
        }
        if self.peek(1).kind != TokenKind::Ident {
            return false;
        }
        matches!(
            self.peek(1).lexeme.as_str(),
            "loop_end" | "if_end" | "else"
        )
    }

    fn try_parse_arg(&mut self) -> Result<Option<Arg>, ParseError> {
        let tok = self.current().clone();
        if tok.kind == TokenKind::Ident && self.peek(1).kind == TokenKind::Assign {
            let name = tok.lexeme.clone();
            self.advance(); // ident
            self.advance(); // =
            let expr = self.parse_expr()?;
            return Ok(Some(Arg::Named { name, value: expr }));
        }
        if tok.kind == TokenKind::Ident {
            self.advance();
            return Ok(Some(Arg::Flag { name: tok.lexeme }));
        }

        if matches!(
            tok.kind,
            TokenKind::StringLit
                | TokenKind::Number
                | TokenKind::Color
                | TokenKind::Var
                | TokenKind::Bang
                | TokenKind::LBracket
                | TokenKind::LBrace
                | TokenKind::Ident
                | TokenKind::Minus
        ) {
            let expr = self.parse_expr()?;
            return Ok(Some(Arg::Value { value: expr }));
        }
        Ok(None)
    }

    fn parse_assign(&mut self) -> Result<Assign, ParseError> {
        let target = self.parse_varref()?;
        self.expect(TokenKind::Assign, "Expected '=' in assignment")?;
        let expr = self.parse_expr()?;
        Ok(Assign { target, expr })
    }

    fn parse_control(&mut self) -> Result<Statement, ParseError> {
        self.expect(TokenKind::At, "Expected '@'")?;
        let kw = self.expect(TokenKind::Ident, "Expected control keyword")?;
        match kw.lexeme.as_str() {
            "loop" => Ok(Statement::Loop(self.parse_loop_body()?)),
            "if" => Ok(Statement::If(self.parse_if_body()?)),
            other => Err(ParseError::Expected {
                msg: format!("Unknown control '@{}'", other),
                line: kw.line,
                col: kw.col,
            }),
        }
    }

    fn parse_loop_body(&mut self) -> Result<Loop, ParseError> {
        let mut mode = "count".to_string();
        let mut source: Option<VarRef> = None;
        let mut times: Option<i64> = None;

        if self.current().kind == TokenKind::Ident && self.current().lexeme == "over" {
            mode = "over".to_string();
            self.advance(); // over
            source = Some(self.parse_varref()?);
        } else {
            let expr = self.parse_expr()?;
            if let Expr::Literal { kind, value } = &expr {
                if kind == "number" {
                    if let Some(n) = value.as_i64() {
                        times = Some(n);
                    } else if let Some(f) = value.as_f64() {
                        times = Some(f as i64);
                    }
                }
            }
            if times.is_none() {
                return Err(ParseError::Expected {
                    msg: "Counted loop expects numeric literal".into(),
                    line: self.current().line,
                    col: self.current().col,
                });
            }
        }

        self.match_kind(TokenKind::Newline);
        let mut body = Vec::new();
        self.skip_newlines();
        while !(self.current().kind == TokenKind::At
            && self.peek(1).kind == TokenKind::Ident
            && self.peek(1).lexeme == "loop_end")
        {
            body.push(self.parse_statement()?);
            self.match_kind(TokenKind::Newline);
            self.skip_newlines();
        }
        // consume @loop_end
        self.advance();
        self.advance();
        self.match_kind(TokenKind::Newline);

        Ok(Loop {
            mode,
            source,
            times,
            body,
        })
    }

    fn parse_if_body(&mut self) -> Result<If, ParseError> {
        let cond = self.parse_condition()?;
        self.match_kind(TokenKind::Newline);
        let mut then_body = Vec::new();
        let mut else_body: Option<Vec<Statement>> = None;
        self.skip_newlines();

        while !(self.current().kind == TokenKind::At
            && self.peek(1).kind == TokenKind::Ident
            && self.peek(1).lexeme == "if_end")
        {
            if self.current().kind == TokenKind::At
                && self.peek(1).kind == TokenKind::Ident
                && self.peek(1).lexeme == "else"
            {
                self.advance();
                self.advance();
                self.match_kind(TokenKind::Newline);
                else_body = Some(Vec::new());
                self.skip_newlines();
                while !(self.current().kind == TokenKind::At
                    && self.peek(1).kind == TokenKind::Ident
                    && self.peek(1).lexeme == "if_end")
                {
                    if let Some(ref mut else_vec) = else_body {
                        else_vec.push(self.parse_statement()?);
                    }
                    self.match_kind(TokenKind::Newline);
                    self.skip_newlines();
                }
                break;
            }
            then_body.push(self.parse_statement()?);
            self.match_kind(TokenKind::Newline);
            self.skip_newlines();
        }
        // consume @if_end
        self.advance();
        self.advance();
        self.match_kind(TokenKind::Newline);

        Ok(If {
            cond,
            then_body,
            else_body,
        })
    }

    fn parse_condition(&mut self) -> Result<Expr, ParseError> {
        let left = self.parse_expr()?;
        if self.current().kind == TokenKind::Op {
            let op = self.current().lexeme.clone();
            self.advance();
            let right = self.parse_expr()?;
            Ok(Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            })
        } else {
            Ok(left)
        }
    }

    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        self.parse_comparison()
    }

    fn parse_comparison(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_add()?;
        if self.current().kind == TokenKind::Op {
            let op = self.current().lexeme.clone();
            self.advance();
            let right = self.parse_add()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_add(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_mul()?;
        while self.current().kind == TokenKind::Plus || self.current().kind == TokenKind::Minus {
            let op = self.current().lexeme.clone();
            self.advance();
            let right = self.parse_mul()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_mul(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_unary()?;
        while self.current().kind == TokenKind::Star || self.current().kind == TokenKind::Slash {
            let op = self.current().lexeme.clone();
            self.advance();
            let right = self.parse_unary()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        if self.current().kind == TokenKind::Minus {
            self.advance();
            let expr = self.parse_unary()?;
            return Ok(Expr::Unary {
                op: "-".into(),
                expr: Box::new(expr),
            });
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        let tok = self.current().clone();
        match tok.kind {
            TokenKind::StringLit => {
                self.advance();
                Ok(Expr::Literal {
                    kind: "string".into(),
                    value: Value::String(tok.lexeme),
                })
            }
            TokenKind::Number => {
                self.advance();
                let num_val = tok
                    .lexeme
                    .parse::<i64>()
                    .map(Value::from)
                    .unwrap_or_else(|_| {
                        tok.lexeme
                            .parse::<f64>()
                            .map(Value::from)
                            .unwrap_or(Value::Null)
                    });
                Ok(Expr::Literal {
                    kind: "number".into(),
                    value: num_val,
                })
            }
            TokenKind::Color => {
                self.advance();
                Ok(Expr::Literal {
                    kind: "color".into(),
                    value: Value::String(tok.lexeme),
                })
            }
            TokenKind::Var => {
                let v = self.parse_varref()?;
                Ok(Expr::Var(v))
            }
            TokenKind::Ident => {
                self.advance();
                if tok.lexeme == "true" || tok.lexeme == "false" {
                    let val = tok.lexeme == "true";
                    return Ok(Expr::Literal {
                        kind: "boolean".into(),
                        value: Value::Bool(val),
                    });
                }
                Ok(Expr::Ident(tok.lexeme))
            }
            TokenKind::LBracket => self.parse_list(),
            TokenKind::LBrace => self.parse_object(),
            TokenKind::Bang => {
                let action = self.parse_action(true)?;
                Ok(Expr::Action(action))
            }
            _ => Err(ParseError::Unexpected {
                found: tok.kind,
                line: tok.line,
                col: tok.col,
            }),
        }
    }

    fn parse_varref(&mut self) -> Result<VarRef, ParseError> {
        let tok = self.expect(TokenKind::Var, "Expected variable")?;
        let base = tok.lexeme;
        let mut path = Vec::new();
        while self.current().kind == TokenKind::Dot {
            self.advance();
            let prop = self.expect(TokenKind::Ident, "Expected property after '.'")?;
            path.push(prop.lexeme);
        }
        Ok(VarRef { base, path })
    }

    fn parse_list(&mut self) -> Result<Expr, ParseError> {
        self.expect(TokenKind::LBracket, "Expected '['")?;
        let mut items = Vec::new();
        while self.current().kind != TokenKind::RBracket {
            items.push(self.parse_expr()?);
            if self.current().kind == TokenKind::Comma {
                self.advance();
            } else {
                break;
            }
        }
        self.expect(TokenKind::RBracket, "Expected ']'")?;
        Ok(Expr::List(items))
    }

    fn parse_object(&mut self) -> Result<Expr, ParseError> {
        self.expect(TokenKind::LBrace, "Expected '{'")?;
        let mut entries = Vec::new();
        while self.current().kind != TokenKind::RBrace {
            let key_tok = self.expect(TokenKind::Ident, "Expected key in object")?;
            self.expect(TokenKind::Assign, "Expected '=' after key")?;
            let val = self.parse_expr()?;
            entries.push((key_tok.lexeme, val));
            if self.current().kind == TokenKind::Comma {
                self.advance();
            } else {
                break;
            }
        }
        self.expect(TokenKind::RBrace, "Expected '}'")?;
        Ok(Expr::Object(entries))
    }
}

pub fn parse(src: &str) -> Result<Program, ParseError> {
    let mut parser = Parser::new(src)?;
    parser.parse_program()
}

pub fn parse_file(path: &std::path::Path) -> Result<Program, ParseError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ParseError::Expected { msg: format!("Failed to read file: {}", e), line: 0, col: 0 })?;
    parse(&content)
}
