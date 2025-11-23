use std::fs;
use std::path::PathBuf;

use naux::lexer;
use naux::parser;
use naux::runtime;
use naux::vm;
use crate::cli::{DefaultEngine, DefaultMode};

pub fn handle_run(path: Option<PathBuf>, _mode: DefaultMode, engine: DefaultEngine) -> Result<(), String> {
    let target = path.unwrap_or_else(|| PathBuf::from("main.nx"));
    if !target.exists() {
        return Err(format!("Không tìm thấy file `{}`", target.display()));
    }
    let src = fs::read_to_string(&target).map_err(|e| format!("Không đọc được {}: {}", target.display(), e))?;
    let tokens = lexer::lex(&src).map_err(|e| format!("Lex error: {}", e.message))?;
    let ast = parser::parser::Parser::from_tokens(&tokens).map_err(|e| format!("Parse error: {}", e.message))?;
    match engine {
        DefaultEngine::Vm => vm::run::run_vm(&ast, &src, &target.to_string_lossy()).map(|_| ()),
        DefaultEngine::Interp => {
            runtime::eval_script(&ast);
            Ok(())
        }
        DefaultEngine::Jit => vm::run::run_jit(&ast, &src, &target.to_string_lossy()).map(|_| ()),
        DefaultEngine::Llvm => Err("LLVM not supported yet".into()),
    }
}
