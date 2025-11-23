#![allow(dead_code)]

use std::collections::HashMap;

use crate::runtime::env::Env;
use crate::runtime::events::RuntimeEvent;
use crate::runtime::value::Value;
use crate::vm::compiler::compile_script;
use crate::vm::interpreter::run_program;
use crate::vm::bytecode::VmResult;
use crate::vm::jit::run_jit as jit_entry;

/// Compile AST to bytecode and execute via VM using env builtins. Returns events and final value.
pub fn run_vm(
    stmts: &[crate::ast::Stmt],
    src: &str,
    filename: &str,
) -> VmResult<(Vec<RuntimeEvent>, crate::runtime::value::Value)> {
    let mut env = Env::new();
    crate::stdlib::register_all(&mut env);
    let builtins: HashMap<String, crate::runtime::env::BuiltinFn> = env.builtins();
    let prog = compile_script(stmts);
    let (val, events) = run_program(&prog, &builtins, src, filename)?;
    Ok((events, val))
}

/// JIT backend entry. Currently stubbed; returns Err if not available.
pub fn run_jit(
    stmts: &[crate::ast::Stmt],
    _src: &str,
    _filename: &str,
) -> VmResult<(Vec<RuntimeEvent>, crate::runtime::value::Value)> {
    let prog = compile_script(stmts);
    match jit_entry(&prog.main, prog.main_locals.len()) {
        Ok(val) => Ok((Vec::new(), Value::Float(val))),
        Err(e) => Err(e),
    }
}
