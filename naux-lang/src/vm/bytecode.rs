// Bytecode definitions for NAUX VM
#![allow(dead_code)]

use std::collections::HashMap;

use crate::ast::Span;
use crate::runtime::value::Value;

/// Simple bytecode instruction set for NAUX VM.
#[derive(Debug, Clone)]
pub enum Instr {
    ConstNum(f64),
    ConstText(String),
    ConstBool(bool),
    PushNull,
    LoadVar(String),   // legacy name-based
    StoreVar(String),  // legacy name-based
    LoadLocal(usize),
    StoreLocal(usize),
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    And,
    Or,
    Jump(usize),
    JumpIfFalse(usize),
    CallBuiltin(String, usize),
    CallFn(String, usize),
    MakeList(usize),
    MakeMap(Vec<String>),
    LoadField(String),
    EmitSay,
    EmitAsk,
    EmitFetch,
    EmitUi(String),
    EmitText,
    EmitButton,
    EmitLog,
    Return,
}

pub type Bytecode = Vec<Instr>;

#[derive(Debug, Clone)]
pub struct FunctionBytecode {
    pub params: Vec<String>,
    pub locals: Vec<String>, // includes params first, then locals
    pub code: Bytecode,
    pub spans: Vec<Option<Span>>,
}

#[derive(Debug, Clone)]
pub struct Program {
    pub main: Bytecode,
    pub main_locals: Vec<String>,
    pub main_spans: Vec<Option<Span>>,
    pub functions: HashMap<String, FunctionBytecode>,
}

/// Result value from VM execution.
pub type VmResult<T = Value> = Result<T, String>;

/// Format a single instruction for disassembly/logging.
pub fn fmt_instr_bc(i: &Instr) -> String {
    match i {
        Instr::ConstNum(n) => format!("ConstNum {}", n),
        Instr::ConstText(s) => format!("ConstText \"{}\"", s),
        Instr::ConstBool(b) => format!("ConstBool {}", b),
        Instr::PushNull => "PushNull".into(),
        Instr::LoadVar(v) => format!("LoadVar {}", v),
        Instr::StoreVar(v) => format!("StoreVar {}", v),
        Instr::Add => "Add".into(),
        Instr::Sub => "Sub".into(),
        Instr::Mul => "Mul".into(),
        Instr::Div => "Div".into(),
        Instr::Mod => "Mod".into(),
        Instr::Eq => "Eq".into(),
        Instr::Ne => "Ne".into(),
        Instr::Gt => "Gt".into(),
        Instr::Ge => "Ge".into(),
        Instr::Lt => "Lt".into(),
        Instr::Le => "Le".into(),
        Instr::And => "And".into(),
        Instr::Or => "Or".into(),
        Instr::Jump(t) => format!("Jump {}", t),
        Instr::JumpIfFalse(t) => format!("JumpIfFalse {}", t),
        Instr::CallBuiltin(n, a) => format!("CallBuiltin {} argc={}", n, a),
        Instr::CallFn(n, a) => format!("CallFn {} argc={}", n, a),
        Instr::MakeList(n) => format!("MakeList {}", n),
        Instr::MakeMap(keys) => format!("MakeMap [{}]", keys.join(",")),
        Instr::LoadField(f) => format!("LoadField {}", f),
        Instr::EmitSay => "EmitSay".into(),
        Instr::EmitAsk => "EmitAsk".into(),
        Instr::EmitFetch => "EmitFetch".into(),
        Instr::EmitUi(k) => format!("EmitUi {}", k),
        Instr::EmitText => "EmitText".into(),
        Instr::EmitButton => "EmitButton".into(),
        Instr::EmitLog => "EmitLog".into(),
        Instr::Return => "Return".into(),
        Instr::LoadLocal(idx) => format!("LoadLocal {}", idx),
        Instr::StoreLocal(idx) => format!("StoreLocal {}", idx),
    }
}

/// Disassemble a block of bytecode into a readable string.
pub fn disasm_block(code: &[Instr]) -> String {
    let mut out = String::new();
    for (i, instr) in code.iter().enumerate() {
        use std::fmt::Write;
        writeln!(&mut out, "  {:04}: {}", i, fmt_instr_bc(instr)).ok();
    }
    out
}

/// Disassemble a small window around an instruction pointer.
pub fn disasm_window(code: &[Instr], ip: usize, window: usize) -> String {
    let start = ip.saturating_sub(window);
    let end = usize::min(code.len(), ip + window + 1);
    let mut out = String::new();
    for idx in start..end {
        use std::fmt::Write;
        let marker = if idx == ip { "-->" } else { "   " };
        writeln!(&mut out, "{} {:04}: {}", marker, idx, fmt_instr_bc(&code[idx])).ok();
    }
    out
}
