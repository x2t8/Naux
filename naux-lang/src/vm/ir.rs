// Intermediate Representation (IR) before lowering to VM bytecode.
#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt::Write;

use crate::ast::Span;

/// IR instructions (stack-based) — spec in docs/IR_SPEC.md
#[derive(Debug, Clone)]
pub enum IRInstr {
    ConstNum(f64),
    ConstText(String),
    ConstBool(bool),
    PushNull,
    LoadVar(String),
    StoreVar(String),
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

#[derive(Debug, Clone)]
pub struct IRNode {
    pub instr: IRInstr,
    pub span: Option<Span>,
}

impl IRNode {
    pub fn new(instr: IRInstr, span: Option<Span>) -> Self {
        Self { instr, span }
    }
}

pub type IRBlock = Vec<IRNode>;

#[derive(Debug, Clone)]
pub struct IRFunction {
    pub params: Vec<String>,
    pub code: IRBlock,
}

#[derive(Debug, Clone)]
pub struct IRProgram {
    pub main: IRBlock,
    pub functions: HashMap<String, IRFunction>,
}

/// Pretty-print IR for debugging (program-level).
pub fn pretty_print_ir(ir: &IRProgram) -> String {
    let mut out = String::new();
    writeln!(&mut out, "fn main:").ok();
    dump_block(&mut out, &ir.main);
    for (name, func) in ir.functions.iter() {
        writeln!(&mut out, "fn {}({}):", name, func.params.join(", ")).ok();
        dump_block(&mut out, &func.code);
    }
    out
}

/// Disassemble a single function to string.
pub fn disasm_function(name: &str, func: &IRFunction) -> String {
    let mut out = String::new();
    writeln!(&mut out, "fn {}({}):", name, func.params.join(", ")).ok();
    dump_block(&mut out, &func.code);
    out
}

fn dump_block(out: &mut String, block: &IRBlock) {
    for (i, node) in block.iter().enumerate() {
        writeln!(out, "  {:04}: {}", i, fmt_instr(&node.instr)).ok();
    }
}

/// Human-friendly opcode text (also reused by VM disasm).
pub fn fmt_instr(i: &IRInstr) -> String {
    match i {
        IRInstr::ConstNum(n) => format!("ConstNum {}", n),
        IRInstr::ConstText(s) => format!("ConstText \"{}\"", s),
        IRInstr::ConstBool(b) => format!("ConstBool {}", b),
        IRInstr::PushNull => "PushNull".into(),
        IRInstr::LoadVar(v) => format!("LoadVar {}", v),
        IRInstr::StoreVar(v) => format!("StoreVar {}", v),
        IRInstr::Add => "Add".into(),
        IRInstr::Sub => "Sub".into(),
        IRInstr::Mul => "Mul".into(),
        IRInstr::Div => "Div".into(),
        IRInstr::Mod => "Mod".into(),
        IRInstr::Eq => "Eq".into(),
        IRInstr::Ne => "Ne".into(),
        IRInstr::Gt => "Gt".into(),
        IRInstr::Ge => "Ge".into(),
        IRInstr::Lt => "Lt".into(),
        IRInstr::Le => "Le".into(),
        IRInstr::And => "And".into(),
        IRInstr::Or => "Or".into(),
        IRInstr::Jump(t) => format!("Jump {}", t),
        IRInstr::JumpIfFalse(t) => format!("JumpIfFalse {}", t),
        IRInstr::CallBuiltin(n, a) => format!("CallBuiltin {} argc={}", n, a),
        IRInstr::CallFn(n, a) => format!("CallFn {} argc={}", n, a),
        IRInstr::MakeList(n) => format!("MakeList {}", n),
        IRInstr::MakeMap(keys) => format!("MakeMap [{}]", keys.join(",")),
        IRInstr::LoadField(f) => format!("LoadField {}", f),
        IRInstr::EmitSay => "EmitSay".into(),
        IRInstr::EmitAsk => "EmitAsk".into(),
        IRInstr::EmitFetch => "EmitFetch".into(),
        IRInstr::EmitUi(k) => format!("EmitUi {}", k),
        IRInstr::EmitText => "EmitText".into(),
        IRInstr::EmitButton => "EmitButton".into(),
        IRInstr::EmitLog => "EmitLog".into(),
        IRInstr::Return => "Return".into(),
    }
}
