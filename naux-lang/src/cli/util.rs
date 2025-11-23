use std::fs;
use std::path::Path;

use crate::ast::Stmt;
use crate::cli::DefaultEngine;
use crate::lexer;
use crate::parser;
use crate::parser::error::format_parse_error;
use crate::runtime;
use crate::runtime::error::format_runtime_error_with_file;
use crate::vm::run::{run_jit, run_vm};

pub fn load_ast(path: &Path) -> Result<(String, Vec<Stmt>), String> {
    let src = fs::read_to_string(path).map_err(|e| format!("Không đọc được {}: {}", path.display(), e))?;
    let tokens = lexer::lex(&src).map_err(|e| format!("Lex error: {}", e.message))?;
    let stmts = parser::Parser::from_tokens(&tokens)
        .map_err(|err| format_parse_error(&src, &err, &path.to_string_lossy()))?;
    Ok((src, stmts))
}

pub fn execute_ast(engine: DefaultEngine, ast: &[Stmt], src: &str, path: &Path) -> Result<Vec<runtime::events::RuntimeEvent>, String> {
    match engine {
        DefaultEngine::Interp => {
            let (_env, events, errors) = runtime::eval_script(ast);
            if let Some(err) = errors.first() {
                Err(format_runtime_error_with_file(src, err, &path.to_string_lossy()))
            } else {
                Ok(events)
            }
        }
        DefaultEngine::Vm => {
            let (events, _) = run_vm(ast, src, &path.to_string_lossy()).map_err(|e| e)?;
            Ok(events)
        }
        DefaultEngine::Jit => {
            let (events, _) = run_jit(ast, src, &path.to_string_lossy()).map_err(|e| e)?;
            Ok(events)
        }
        DefaultEngine::Llvm => Err("LLVM engine chưa được hỗ trợ".into()),
    }
}
