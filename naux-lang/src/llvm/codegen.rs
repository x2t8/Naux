//! LLVM codegen scaffold (sealed). VM is the primary engine.
//! Scope: Number/Bool/Null, assign, if/while/loop, fn/return, builtin math.
//! Intentionally not implemented while LLVM backend is sealed.

use crate::ast::Stmt;
use crate::runtime::events::RuntimeEvent;
use crate::runtime::value::Value;

pub struct NauxLlvmContext {
    pub _dummy: (),
}

impl NauxLlvmContext {
    pub fn new() -> Self {
        Self { _dummy: () }
    }

    pub fn compile_script(&self, _stmts: &[Stmt]) -> Result<(), String> {
        Err("LLVM backend is sealed; use VM engine".into())
    }
}

pub fn compile_and_run(_stmts: &[Stmt]) -> Result<(Vec<RuntimeEvent>, Value), String> {
    Err("LLVM backend is sealed; use VM engine".into())
}
