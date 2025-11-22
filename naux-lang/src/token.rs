use crate::ast::Span;

#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    // Symbols
    Tilde,
    Bang,
    Dollar,
    Assign,     // =
    Arrow,      // ->
    Dot,
    Comma,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,

    // Literals / idents
    Ident(String),
    Number(f64),
    StringLit(String),

    // Keywords
    If,
    Else,
    Rite,
    Loop,
    Each,
    While,
    End,
    In,

    Newline,
    Eof,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct LexError {
    pub message: String,
    pub span: Span,
}

impl LexError {
    pub fn new(message: impl Into<String>, span: Span) -> Self {
        Self {
            message: message.into(),
            span,
        }
    }
}
