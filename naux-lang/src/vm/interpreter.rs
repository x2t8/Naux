// TODO: bytecode interpreter
#![allow(dead_code)]

use std::collections::HashMap;

use crate::runtime::env::BuiltinFn;
use crate::runtime::value::Value;
use crate::vm::bytecode::{FunctionBytecode, Instr, Program, VmResult};

/// Execute a compiled program with a stack machine. Handles builtin and user functions.
pub fn run_program(prog: &Program, builtins: &HashMap<String, BuiltinFn>) -> VmResult {
    let mut frames: Vec<HashMap<String, Value>> = vec![HashMap::new()]; // global frame
    let mut stack: Vec<Value> = Vec::new();
    exec_code(&prog.main, builtins, &prog.functions, &mut frames, &mut stack)
}

fn exec_code(
    code: &[Instr],
    builtins: &HashMap<String, BuiltinFn>,
    functions: &HashMap<String, FunctionBytecode>,
    frames: &mut Vec<HashMap<String, Value>>,
    stack: &mut Vec<Value>,
) -> VmResult {
    let mut ip: usize = 0;
    while ip < code.len() {
        match &code[ip] {
            Instr::PushNum(n) => stack.push(Value::Number(*n)),
            Instr::PushText(s) => stack.push(Value::Text(s.clone())),
            Instr::PushBool(b) => stack.push(Value::Bool(*b)),
            Instr::PushNull => stack.push(Value::Null),
            Instr::LoadVar(name) => {
                stack.push(load_var(frames, name));
            }
            Instr::StoreVar(name) => {
                let val = pop(stack)?;
                store_var(frames, name, val);
            }
            Instr::Add => bin_op(stack, |a, b| Value::Number(a + b))?,
            Instr::Sub => bin_op(stack, |a, b| Value::Number(a - b))?,
            Instr::Mul => bin_op(stack, |a, b| Value::Number(a * b))?,
            Instr::Div => bin_op(stack, |a, b| Value::Number(a / b))?,
            Instr::Mod => bin_op(stack, |a, b| Value::Number(a % b))?,
            Instr::Eq => cmp_op(stack, |a, b| a == b)?,
            Instr::Ne => cmp_op(stack, |a, b| a != b)?,
            Instr::Gt => cmp_num(stack, |a, b| a > b)?,
            Instr::Ge => cmp_num(stack, |a, b| a >= b)?,
            Instr::Lt => cmp_num(stack, |a, b| a < b)?,
            Instr::Le => cmp_num(stack, |a, b| a <= b)?,
            Instr::And => {
                let rhs = pop(stack)?;
                let lhs = pop(stack)?;
                stack.push(Value::Bool(lhs.truthy() && rhs.truthy()));
            }
            Instr::Or => {
                let rhs = pop(stack)?;
                let lhs = pop(stack)?;
                stack.push(Value::Bool(lhs.truthy() || rhs.truthy()));
            }
            Instr::Jump(target) => {
                ip = *target;
                continue;
            }
            Instr::JumpIfFalse(target) => {
                let cond = pop(stack)?;
                if !cond.truthy() {
                    ip = *target;
                    continue;
                }
            }
            Instr::CallBuiltin(name, argc) => {
                let mut args = Vec::new();
                for _ in 0..*argc {
                    args.push(pop(stack)?);
                }
                args.reverse();
                if let Some(f) = builtins.get(name) {
                    match f(args) {
                        Ok(v) => stack.push(v),
                        Err(e) => return Err(format!("RuntimeError: {}", e.message)),
                    }
                } else {
                    return Err(format!("Unknown builtin: {}", name));
                }
            }
            Instr::CallFunction(name, argc) => {
                let func = functions.get(name).ok_or_else(|| format!("Unknown function: {}", name))?;
                let mut args = Vec::new();
                for _ in 0..*argc {
                    args.push(pop(stack)?);
                }
                args.reverse();
                frames.push(HashMap::new());
                for (i, param) in func.params.iter().enumerate() {
                    let val = args.get(i).cloned().unwrap_or(Value::Null);
                    store_var(frames, param, val);
                }
                let ret = exec_code(&func.code, builtins, functions, frames, stack)?;
                stack.push(ret.clone());
                frames.pop();
            }
            Instr::Return => {
                let ret = stack.pop().unwrap_or(Value::Null);
                return Ok(ret);
            }
        }
        ip += 1;
    }
    Ok(stack.pop().unwrap_or(Value::Null))
}

fn load_var(frames: &Vec<HashMap<String, Value>>, name: &str) -> Value {
    for frame in frames.iter().rev() {
        if let Some(v) = frame.get(name) {
            return v.clone();
        }
    }
    Value::Null
}

fn store_var(frames: &mut Vec<HashMap<String, Value>>, name: &str, val: Value) {
    if let Some(top) = frames.last_mut() {
        top.insert(name.to_string(), val);
    }
}

fn pop(stack: &mut Vec<Value>) -> Result<Value, String> {
    stack.pop().ok_or_else(|| "Stack underflow".to_string())
}

fn bin_op<F>(stack: &mut Vec<Value>, f: F) -> Result<(), String>
where
    F: Fn(f64, f64) -> Value,
{
    let rhs = pop(stack)?;
    let lhs = pop(stack)?;
    match (lhs, rhs) {
        (Value::Number(a), Value::Number(b)) => {
            stack.push(f(a, b));
            Ok(())
        }
        _ => Err("Type error in binary op".into()),
    }
}

fn cmp_op<F>(stack: &mut Vec<Value>, f: F) -> Result<(), String>
where
    F: Fn(Value, Value) -> bool,
{
    let rhs = pop(stack)?;
    let lhs = pop(stack)?;
    stack.push(Value::Bool(f(lhs, rhs)));
    Ok(())
}

fn cmp_num<F>(stack: &mut Vec<Value>, f: F) -> Result<(), String>
where
    F: Fn(f64, f64) -> bool,
{
    let rhs = pop(stack)?;
    let lhs = pop(stack)?;
    match (lhs, rhs) {
        (Value::Number(a), Value::Number(b)) => {
            stack.push(Value::Bool(f(a, b)));
            Ok(())
        }
        _ => Err("Type error in numeric comparison".into()),
    }
}
