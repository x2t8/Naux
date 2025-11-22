#![allow(dead_code, unused_imports)]

pub mod parser;
pub mod error;
pub mod utils;

pub use parser::Parser;
pub use error::{ParseError, ParseErrorKind, format_parse_error};
use crate::token::Token;
use crate::ast::Stmt;

pub fn parse_script(tokens: &[Token]) -> Result<Vec<Stmt>, ParseError> {
    Parser::from_tokens(tokens)
}
