use crate::ast::Span;
use crate::diagnostic::{format_source_diagnostic, DiagnosticStage};
use crate::token::TokenKind;

#[derive(Debug, Clone)]
pub enum ParseErrorKind {
    UnexpectedToken(TokenKind),
    ExpectedToken(&'static str),
    UnexpectedEof,
    BlockMismatch(&'static str),
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
    format_source_diagnostic(
        DiagnosticStage::Parse,
        &err.message,
        src,
        filename,
        Some(&err.span),
    )
}
