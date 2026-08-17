#![allow(dead_code)]

#[cfg(feature = "experimental-regions")]
use std::collections::BTreeMap;
use std::collections::HashMap;

use crate::runtime::budget::{install_execution_budget, ExecutionLimits};
use crate::runtime::env::Env;
use crate::runtime::events::RuntimeEvent;
use crate::runtime::input::{register_standard_input, register_terminal_input};
use crate::runtime::value::Value;
use crate::typecheck::Type;
use crate::vm::bytecode::VmResult;
use crate::vm::bytecode::{Instr, Program};
use crate::vm::compiler::{compile_script, compile_script_with_budget_checkpoints};
#[cfg(feature = "experimental-regions")]
use crate::vm::compiler::{compile_script_with_region_plan, RegionCompiledProgram};
use crate::vm::interpreter::run_program;
use crate::vm::jit;
use crate::vm::typed;

/// Compile AST to bytecode and execute via VM using env builtins. Returns events and final value.
pub fn run_vm(
    stmts: &[crate::ast::Stmt],
    src: &str,
    filename: &str,
) -> VmResult<(Vec<RuntimeEvent>, crate::runtime::value::Value)> {
    run_vm_with_input(stmts, src, filename, "")
}

pub fn run_vm_with_input(
    stmts: &[crate::ast::Stmt],
    src: &str,
    filename: &str,
    input: &str,
) -> VmResult<(Vec<RuntimeEvent>, crate::runtime::value::Value)> {
    let mut env = Env::new();
    crate::stdlib::register_all(&mut env);
    register_standard_input(&mut env, input.to_string());
    let builtins: HashMap<String, crate::runtime::env::BuiltinFn> = env.builtins();
    let prog = compile_script(stmts);
    let (val, events) = run_program(&prog, &builtins, src, filename)?;
    Ok((events, val))
}

pub fn run_vm_with_input_and_limits(
    stmts: &[crate::ast::Stmt],
    src: &str,
    filename: &str,
    input: &str,
    limits: ExecutionLimits,
) -> VmResult<(Vec<RuntimeEvent>, crate::runtime::value::Value)> {
    let mut env = Env::new();
    crate::stdlib::register_all(&mut env);
    register_standard_input(&mut env, input.to_string());
    install_execution_budget(&mut env, limits);
    let builtins: HashMap<String, crate::runtime::env::BuiltinFn> = env.builtins();
    let prog = compile_script_with_budget_checkpoints(stmts);
    let (val, events) = run_program(&prog, &builtins, src, filename)?;
    Ok((events, val))
}

pub fn run_vm_with_terminal_input_and_limits(
    stmts: &[crate::ast::Stmt],
    src: &str,
    filename: &str,
    limits: ExecutionLimits,
) -> VmResult<(Vec<RuntimeEvent>, crate::runtime::value::Value)> {
    let mut env = Env::new();
    crate::stdlib::register_all(&mut env);
    register_terminal_input(&mut env);
    install_execution_budget(&mut env, limits);
    let builtins: HashMap<String, crate::runtime::env::BuiltinFn> = env.builtins();
    let prog = compile_script_with_budget_checkpoints(stmts);
    let (val, events) = run_program(&prog, &builtins, src, filename)?;
    Ok((events, val))
}

/// S1 limits are semantic VM/interpreter limits. Native and typed JIT paths do
/// not claim this boundary, so a bounded JIT request deterministically falls
/// back to the instrumented VM.
pub fn run_jit_with_input_and_limits(
    stmts: &[crate::ast::Stmt],
    src: &str,
    filename: &str,
    input: &str,
    limits: ExecutionLimits,
) -> VmResult<(Vec<RuntimeEvent>, crate::runtime::value::Value, bool)> {
    let (events, value) = run_vm_with_input_and_limits(stmts, src, filename, input, limits)?;
    Ok((events, value, false))
}

pub fn run_jit_with_terminal_input_and_limits(
    stmts: &[crate::ast::Stmt],
    src: &str,
    filename: &str,
    limits: ExecutionLimits,
) -> VmResult<(Vec<RuntimeEvent>, crate::runtime::value::Value, bool)> {
    let (events, value) = run_vm_with_terminal_input_and_limits(stmts, src, filename, limits)?;
    Ok((events, value, false))
}

#[cfg(feature = "experimental-regions")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegionExecutionTelemetry {
    pub certificate_verified: bool,
    pub region_local_allocations: usize,
    pub rc_fallback_allocations: usize,
    pub bulk_free_points: usize,
    pub bulk_free_allocations: usize,
    pub rc_fallback_by_reason: BTreeMap<String, usize>,
}

#[cfg(feature = "experimental-regions")]
impl RegionExecutionTelemetry {
    fn from_compilation(compiled: &RegionCompiledProgram) -> Self {
        let mut rc_fallback_by_reason = BTreeMap::new();
        for allocation in &compiled.region_plan.allocations {
            if let crate::region::RegionStorageClass::RcFallback { reason } = allocation.storage {
                *rc_fallback_by_reason
                    .entry(reason.as_str().to_string())
                    .or_default() += 1;
            }
        }
        Self {
            certificate_verified: true,
            region_local_allocations: compiled.region_plan.region_local_count,
            rc_fallback_allocations: compiled.region_plan.rc_fallback_count,
            bulk_free_points: compiled.region_plan.free_points.len(),
            bulk_free_allocations: compiled
                .region_plan
                .free_points
                .iter()
                .map(|point| point.allocation_indices.len())
                .sum(),
            rc_fallback_by_reason,
        }
    }
}

/// Execute unchanged VM bytecode while consuming the verified region sidecar
/// as observe-only telemetry.
#[cfg(feature = "experimental-regions")]
pub fn run_vm_with_region_plan(
    stmts: &[crate::ast::Stmt],
    src: &str,
    filename: &str,
) -> VmResult<(
    Vec<RuntimeEvent>,
    crate::runtime::value::Value,
    RegionExecutionTelemetry,
)> {
    let mut env = Env::new();
    crate::stdlib::register_all(&mut env);
    let builtins: HashMap<String, crate::runtime::env::BuiltinFn> = env.builtins();
    let compiled = compile_script_with_region_plan(stmts).map_err(|error| error.to_string())?;
    let telemetry = RegionExecutionTelemetry::from_compilation(&compiled);
    let (value, events) = run_program(&compiled.bytecode, &builtins, src, filename)?;
    Ok((events, value, telemetry))
}

/// Execute the ordinary JIT/fallback path and attach observe-only telemetry
/// from the separately verified region sidecar.
#[cfg(feature = "experimental-regions")]
pub fn run_jit_with_region_plan(
    stmts: &[crate::ast::Stmt],
    src: &str,
    filename: &str,
) -> VmResult<(
    Vec<RuntimeEvent>,
    crate::runtime::value::Value,
    bool,
    RegionExecutionTelemetry,
)> {
    let compiled = compile_script_with_region_plan(stmts).map_err(|error| error.to_string())?;
    let telemetry = RegionExecutionTelemetry::from_compilation(&compiled);
    let (events, value, used_jit) = run_jit(stmts, src, filename)?;
    Ok((events, value, used_jit, telemetry))
}

/// JIT backend entry. Currently stubbed; returns Err if not available.
pub fn run_jit(
    stmts: &[crate::ast::Stmt],
    src: &str,
    filename: &str,
) -> VmResult<(Vec<RuntimeEvent>, crate::runtime::value::Value, bool)> {
    run_jit_with_input(stmts, src, filename, "")
}

pub fn run_jit_with_input(
    stmts: &[crate::ast::Stmt],
    src: &str,
    filename: &str,
    input: &str,
) -> VmResult<(Vec<RuntimeEvent>, crate::runtime::value::Value, bool)> {
    let mut env = Env::new();
    crate::stdlib::register_all(&mut env);
    register_standard_input(&mut env, input.to_string());
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
