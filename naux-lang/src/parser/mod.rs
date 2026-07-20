#![allow(dead_code, unused_imports)]
#![allow(clippy::module_inception)]

pub mod error;
pub mod parser;
pub mod utils;

use crate::ast::Stmt;
use crate::token::Token;
pub use error::{format_parse_error, ParseError, ParseErrorKind};
pub use parser::Parser;

pub fn parse_script(tokens: &[Token]) -> Result<Vec<Stmt>, ParseError> {
    Parser::from_tokens(tokens)
}
