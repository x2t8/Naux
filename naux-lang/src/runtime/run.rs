use crate::parser::parser::Parser;
use crate::parser::error::format_parse_error;
use crate::runtime::error::RuntimeError;
use crate::runtime::eval_script;
use crate::runtime::events::RuntimeEvent;
use crate::lexer::lex;
use crate::ast::Stmt;

pub fn parse_script_wrapper(src: &str, filename: &str) -> Result<Vec<Stmt>, String> {
    let tokens = lex(src).map_err(|e| format!("Lex error at {}:{}:{}: {}", filename, e.span.line, e.span.column, e.message))?;
    let ast = Parser::from_tokens(&tokens).map_err(|e| format_parse_error(src, &e, filename))?;
    Ok(ast)
}

pub fn run_ritual(stmts: &[Stmt]) -> Result<Vec<RuntimeEvent>, RuntimeError> {
    let (_env, events, errors) = eval_script(stmts);
    if let Some(err) = errors.into_iter().next() {
        Err(err)
    } else {
        Ok(events)
    }
}
