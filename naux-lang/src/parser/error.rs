use crate::ast::Span;
use crate::token::TokenKind;

#[derive(Debug, Clone)]
pub enum ParseErrorKind {
    UnexpectedToken(TokenKind),
    ExpectedToken(&'static str),
    UnexpectedEof,
}

#[derive(Debug, Clone)]
pub struct ParseError {
    pub kind: ParseErrorKind,
    pub span: Span,
    pub message: String,
}

impl ParseError {
    pub fn new(kind: ParseErrorKind, span: Span, message: impl Into<String>) -> Self {
        Self {
            kind,
            span,
            message: message.into(),
        }
    }
}

pub fn format_parse_error(src: &str, err: &ParseError, filename: &str) -> String {
    let line_idx = err.span.line.saturating_sub(1);
    let line_text = src.lines().nth(line_idx).unwrap_or("");
    let caret = format!("{}^", " ".repeat(err.span.column.saturating_sub(1)));
    format!(
        "Parse error: {}\n --> {}:{}:{}\n {}\n {}",
        err.message, filename, err.span.line, err.span.column, line_text, caret
    )
}
