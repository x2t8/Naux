#![allow(dead_code)]

use std::collections::HashMap;

use crate::runtime::env::Env;
use crate::vm::compiler::compile_script;
use crate::vm::interpreter::run_program;
use crate::vm::bytecode::VmResult;

/// Compile AST to bytecode and execute via VM using env builtins.
pub fn run_vm(stmts: &[crate::ast::Stmt]) -> VmResult {
    let mut env = Env::new();
    crate::stdlib::register_all(&mut env);
    let builtins: HashMap<String, crate::runtime::env::BuiltinFn> = env.builtins();
    let prog = compile_script(stmts);
    run_program(&prog, &builtins)
}
