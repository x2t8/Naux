#![allow(dead_code)]

use std::collections::HashMap;

use crate::runtime::env::Env;
use crate::runtime::events::RuntimeEvent;
use crate::runtime::value::Value;
use crate::typecheck::Type;
use crate::vm::bytecode::VmResult;
use crate::vm::bytecode::{Instr, Program};
use crate::vm::compiler::compile_script;
use crate::vm::interpreter::run_program;
use crate::vm::jit;
use crate::vm::typed;

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
    src: &str,
    filename: &str,
) -> VmResult<(Vec<RuntimeEvent>, crate::runtime::value::Value, bool)> {
    let mut env = Env::new();
    crate::stdlib::register_all(&mut env);
    let builtins: HashMap<String, crate::runtime::env::BuiltinFn> = env.builtins();
    let prog = compile_script(stmts);

    if !typed::is_supported_program(&prog) {
        if can_use_baseline_jit(&prog) {
            if let Ok(exec) = jit::run_jit(&prog.main, prog.main_locals.len().max(1)) {
                let mut runtime = jit::JitRuntime::new();
                let mut locals = vec![0.0f64; prog.main_locals.len().max(1)];
                let mut stack = vec![0.0f64; jit::max_stack_depth(&prog.main)];
                let bits = exec.run(&mut locals, &mut stack, &mut runtime).to_bits();

                if runtime.error == 0 && runtime.exit_flag == 0 {
                    let value = if matches!(prog.main_return, Some(Type::Bool)) {
                        Value::Bool(f64::from_bits(bits) != 0.0)
                    } else {
                        runtime.value_from_bits(bits)
                    };
                    runtime.cleanup();
                    return Ok((Vec::new(), value, true));
                }
                runtime.cleanup();
            }
        }

        let (val, events) = run_program(&prog, &builtins, src, filename)?;
        return Ok((events, val, false));
    }

    match typed::run_typed_with_trace(&prog) {
        Ok((val, events)) => Ok((events, val, true)),
        Err(_) => {
            let (val, events) = run_program(&prog, &builtins, src, filename)?;
            Ok((events, val, false))
        }
    }
}

fn can_use_baseline_jit(prog: &Program) -> bool {
    if !prog.functions.is_empty() {
        return false;
    }
    if contains_call_fn(&prog.main) {
        return false;
    }
    jit::is_supported(&prog.main)
}

fn contains_call_fn(code: &[Instr]) -> bool {
    code.iter()
        .any(|instr| matches!(instr, Instr::CallFn(_, _)))
}
