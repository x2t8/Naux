// TODO: bytecode definitions
#![allow(dead_code)]

use std::collections::HashMap;

use crate::runtime::value::Value;

/// Simple bytecode instruction set for NAUX VM (skeleton).
#[derive(Debug, Clone)]
pub enum Instr {
    PushNum(f64),
    PushText(String),
    PushBool(bool),
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
    CallFunction(String, usize),
    Return,
}

pub type Bytecode = Vec<Instr>;

/// Result value from VM execution.
pub type VmResult = Result<Value, String>;

#[derive(Debug, Clone)]
pub struct FunctionBytecode {
    pub params: Vec<String>,
    pub code: Bytecode,
}

#[derive(Debug, Clone)]
pub struct Program {
    pub main: Bytecode,
    pub functions: HashMap<String, FunctionBytecode>,
}
