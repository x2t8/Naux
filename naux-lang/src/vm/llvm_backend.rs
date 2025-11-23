#![allow(dead_code)]
#[allow(dead_code)]
use crate::ast::Stmt;
use crate::runtime::events::RuntimeEvent;
use crate::runtime::value::Value;

/// Run via LLVM backend (stub). When the LLVM feature is not enabled or backend
/// is incomplete, return Err so caller can fallback to VM/interpreter.
pub fn run_llvm(_stmts: &[Stmt]) -> Result<(Vec<RuntimeEvent>, Value), String> {
    Err("LLVM backend not enabled/incomplete; falling back".into())
}

#[cfg(feature = "llvm")]
pub fn run_llvm(_stmts: &[Stmt]) -> Result<(Vec<RuntimeEvent>, Value), String> {
    // Placeholder: actual LLVM codegen to be implemented.
    Err("LLVM backend feature enabled but not implemented".into())
}
