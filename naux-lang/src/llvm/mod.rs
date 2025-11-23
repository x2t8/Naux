// LLVM backend is sealed for now; VM is the primary engine.
use crate::ast::Stmt;
use crate::runtime::events::RuntimeEvent;
use crate::runtime::value::Value;
use std::fs;
use std::path::Path;

#[cfg(feature = "llvm")]
pub mod codegen;

/// Run with LLVM backend if compiled in; otherwise return an error so caller can fallback.
pub fn run_with_llvm(_ast: &[Stmt]) -> Result<(Vec<RuntimeEvent>, Value), String> {
    #[cfg(feature = "llvm")]
    {
        // Even when feature is enabled, backend is intentionally sealed.
        Err("LLVM backend is sealed for now; falling back to VM".into())
    }
    #[cfg(not(feature = "llvm"))]
    {
        Err("LLVM backend not compiled in (feature `llvm` disabled); falling back to VM".into())
    }
}

/// Emit a stub LLVM IR file to show intent. Backend is sealed.
pub fn emit_stub_llvm<P: AsRef<Path>>(path: P) -> Result<(), String> {
    let p = path.as_ref();
    let content = r#"; NAUX LLVM backend sealed
; VM is the primary engine. This file is a placeholder.
source_filename = "naux"

define i32 @main() {
entry:
  ret i32 0
}
"#;
    fs::write(p, content).map_err(|e| e.to_string())
}
