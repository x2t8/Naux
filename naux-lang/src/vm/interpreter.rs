// VM bytecode interpreter.
#![allow(dead_code, clippy::too_many_arguments)]

use crate::ask::query_ask;
use crate::runtime::budget::{CALL_DEPTH_BUILTIN, WORK_CHECKPOINT_BUILTIN};
use crate::runtime::env::BuiltinFn;
use crate::runtime::error::{format_runtime_error_with_file, Frame as TraceFrame, RuntimeError};
use crate::runtime::events::RuntimeEvent;
use crate::runtime::value::{NauxObj, Value};
use crate::vm::bytecode::{FunctionBytecode, Instr, Program, VmResult};
use std::collections::HashMap;

#[derive(Clone, Debug)]
struct Frame {
    locals: Vec<Value>,
}

#[derive(Debug, Clone, Copy)]
pub enum DebugAction {
    Continue,
    Quit,
}

#[derive(Debug, Clone, Copy)]
pub struct DebugState<'a> {
    pub function: &'a str,
    pub frame_depth: usize,
    pub ip: usize,
    pub instr: &'a Instr,
    pub code: &'a [Instr],
    pub stack: &'a [Value],
    pub locals: &'a [Value],
    pub locals_names: &'a [String],
}

pub type DebugHook<'a> = dyn FnMut(DebugState<'_>) -> DebugAction + 'a;

/// Execute a compiled program with a stack machine. Handles builtin and user functions.
pub fn run_program(
    prog: &Program,
    builtins: &HashMap<String, BuiltinFn>,
    src: &str,
    filename: &str,
) -> VmResult<(Value, Vec<RuntimeEvent>)> {
    let mut frames: Vec<Frame> = vec![Frame {
        locals: vec![Value::Null; prog.main_locals.len()],
    }];
    let mut stack: Vec<Value> = Vec::new();
    let mut events: Vec<RuntimeEvent> = Vec::new();
    let mut trace: Vec<TraceFrame> = Vec::new();
    let val = exec_code(
        &prog.main,
        &prog.main_locals,
        &prog.main_spans,
        builtins,
        &prog.functions,
        &mut frames,
        &mut stack,
        &mut events,
        &mut trace,
        src,
        filename,
        None,
        "main",
    )?;
    Ok((val, events))
}

pub fn run_program_debug(
    prog: &Program,
    builtins: &HashMap<String, BuiltinFn>,
    src: &str,
    filename: &str,
    hook: &mut DebugHook<'_>,
) -> VmResult<(Value, Vec<RuntimeEvent>)> {
    let mut frames: Vec<Frame> = vec![Frame {
        locals: vec![Value::Null; prog.main_locals.len()],
    }];
    let mut stack: Vec<Value> = Vec::new();
    let mut events: Vec<RuntimeEvent> = Vec::new();
    let mut trace: Vec<TraceFrame> = Vec::new();
    let val = exec_code(
        &prog.main,
        &prog.main_locals,
        &prog.main_spans,
        builtins,
        &prog.functions,
        &mut frames,
        &mut stack,
        &mut events,
        &mut trace,
        src,
        filename,
        Some(hook),
        "main",
    )?;
    Ok((val, events))
}

fn exec_code(
    code: &[Instr],
    locals_names: &[String],
    spans: &[Option<crate::ast::Span>],
    builtins: &HashMap<String, BuiltinFn>,
    functions: &HashMap<String, FunctionBytecode>,
    frames: &mut Vec<Frame>,
    stack: &mut Vec<Value>,
    events: &mut Vec<RuntimeEvent>,
    trace: &mut Vec<TraceFrame>,
    src: &str,
    filename: &str,
    mut debug: Option<&mut DebugHook<'_>>,
    fn_name: &str,
) -> VmResult<Value> {
    let mut ip: usize = 0;
    while ip < code.len() {
        if let Some(hook) = debug.as_deref_mut() {
            let locals = frames.last().map(|f| f.locals.as_slice()).unwrap_or(&[]);
            let state = DebugState {
                function: fn_name,
                frame_depth: frames.len(),
                ip,
                instr: &code[ip],
                code,
                stack: stack.as_slice(),
                locals,
                locals_names,
            };
            if matches!(hook(state), DebugAction::Quit) {
                return Err("Debug quit".into());
            }
        }
        match &code[ip] {
            Instr::ConstNum(n) => {
                if n.fract().abs() < f64::EPSILON {
                    stack.push(Value::SmallInt(*n as i64));
                } else {
                    stack.push(Value::Float(*n));
                }
            }
            Instr::ConstText(s) => stack.push(Value::make_text(s.clone())),
            Instr::ConstBool(b) => stack.push(Value::Bool(*b)),
            Instr::PushNull => stack.push(Value::Null),
            Instr::LoadLocal(idx) => {
                let v = load_local(frames, *idx);
                stack.push(v);
            }
            Instr::StoreLocal(idx) => {
                let val = wrap(pop(stack), code, spans, ip, stack, src, filename, trace)?;
                store_local(frames, *idx, val);
            }
            Instr::StoreLocalKeep(idx) => {
                let val = wrap(
                    stack
                        .last()
                        .cloned()
                        .ok_or_else(|| "Stack underflow".to_string()),
                    code,
                    spans,
                    ip,
                    stack,
                    src,
                    filename,
                    trace,
                )?;
                store_local(frames, *idx, val);
            }
            Instr::AddLocalConst(idx, c) => {
                let lhs = load_local(frames, *idx);
                let rhs = const_num_value(*c);
                store_local(frames, *idx, Value::add(&lhs, &rhs));
            }
            Instr::Add => {
                let rhs = wrap(pop(stack), code, spans, ip, stack, src, filename, trace)?;
                let lhs = wrap(pop(stack), code, spans, ip, stack, src, filename, trace)?;
                stack.push(Value::add(&lhs, &rhs));
            }
            Instr::Sub => wrap(
                num_bin(stack, Some(|a, b| Value::SmallInt(a - b)), |a, b| {
                    Value::Float(a - b)
                }),
                code,
                spans,
                ip,
                stack,
                src,
                filename,
                trace,
            )?,
            Instr::Mul => wrap(
                num_bin(stack, Some(|a, b| Value::SmallInt(a * b)), |a, b| {
                    Value::Float(a * b)
                }),
                code,
                spans,
                ip,
                stack,
                src,
                filename,
                trace,
            )?,
            Instr::Div => wrap(num_div(stack), code, spans, ip, stack, src, filename, trace)?,
            Instr::Mod => wrap(num_mod(stack), code, spans, ip, stack, src, filename, trace)?,
            Instr::Xor => wrap(
                int_bin(stack, |a, b| Value::SmallInt(a ^ b)),
                code,
                spans,
                ip,
                stack,
                src,
                filename,
                trace,
            )?,
            Instr::Shl => wrap(shl_bin(stack), code, spans, ip, stack, src, filename, trace)?,
            Instr::Eq => wrap(
                cmp_op(stack, |a, b| a == b),
                code,
                spans,
                ip,
                stack,
                src,
                filename,
                trace,
            )?,
            Instr::Ne => wrap(
                cmp_op(stack, |a, b| a != b),
                code,
                spans,
                ip,
                stack,
                src,
                filename,
                trace,
            )?,
            Instr::Gt => wrap(
                cmp_num(stack, |a, b| a > b),
                code,
                spans,
                ip,
                stack,
                src,
                filename,
                trace,
            )?,
            Instr::Ge => wrap(
                cmp_num(stack, |a, b| a >= b),
                code,
                spans,
                ip,
                stack,
                src,
                filename,
                trace,
            )?,
            Instr::Lt => wrap(
                cmp_num(stack, |a, b| a < b),
                code,
                spans,
                ip,
                stack,
                src,
                filename,
                trace,
            )?,
            Instr::Le => wrap(
                cmp_num(stack, |a, b| a <= b),
                code,
                spans,
                ip,
                stack,
                src,
                filename,
                trace,
            )?,
            Instr::And => {
                let rhs = wrap(pop(stack), code, spans, ip, stack, src, filename, trace)?;
                let lhs = wrap(pop(stack), code, spans, ip, stack, src, filename, trace)?;
                stack.push(Value::Bool(lhs.truthy() && rhs.truthy()));
            }
            Instr::Or => {
                let rhs = wrap(pop(stack), code, spans, ip, stack, src, filename, trace)?;
                let lhs = wrap(pop(stack), code, spans, ip, stack, src, filename, trace)?;
                stack.push(Value::Bool(lhs.truthy() || rhs.truthy()));
            }
            Instr::Jump(target) => {
                ip = *target;
                continue;
            }
            Instr::JumpIfFalse(target) => {
                let cond = wrap(pop(stack), code, spans, ip, stack, src, filename, trace)?;
                if !cond.truthy() {
                    ip = *target;
                    continue;
                }
            }
            Instr::JumpLocalIfFalse(idx, target) => {
                let cond = load_local(frames, *idx);
                if !cond.truthy() {
                    ip = *target;
                    continue;
                }
            }
            Instr::CallBuiltin(name, argc) => {
                wrap(
                    call_builtin(name, *argc, builtins, stack),
                    code,
                    spans,
                    ip,
                    stack,
                    src,
                    filename,
                    trace,
                )?;
            }
            Instr::CallFn(name, argc) => {
                // try user function first, fall back to builtin set
                if let Some(func) = functions.get(name) {
                    let call_span = spans.get(ip).cloned().unwrap_or(None);
                    wrap(
                        call_function(
                            name,
                            func,
                            *argc,
                            builtins,
                            functions,
                            frames,
                            stack,
                            events,
                            trace,
                            call_span,
                            src,
                            filename,
                            debug.as_deref_mut(),
                        ),
                        code,
                        spans,
                        ip,
                        stack,
                        src,
                        filename,
                        trace,
                    )?;
                } else {
                    wrap(
                        call_builtin(name, *argc, builtins, stack),
                        code,
                        spans,
                        ip,
                        stack,
                        src,
                        filename,
                        trace,
                    )?;
                }
            }
            Instr::MakeList(len) => {
                let mut items = Vec::new();
                for _ in 0..*len {
                    items.push(wrap(
                        pop(stack),
                        code,
                        spans,
                        ip,
                        stack,
                        src,
                        filename,
                        trace,
                    )?);
                }
                items.reverse();
                stack.push(Value::make_list(items));
            }
            Instr::MakeMap(keys) => {
                let mut map = std::collections::HashMap::new();
                for key in keys.iter().rev() {
                    let val = wrap(pop(stack), code, spans, ip, stack, src, filename, trace)?;
                    map.insert(key.clone(), val);
                }
                stack.push(Value::make_map(map));
            }
            Instr::LoadField(field) => {
                let target = wrap(pop(stack), code, spans, ip, stack, src, filename, trace)?;
                match target {
                    Value::RcObj(rc) => match rc.as_ref() {
                        NauxObj::Map(m) => {
                            let val = m.borrow_mut().remove(field).unwrap_or(Value::Null);
                            stack.push(val);
                        }
                        _ => stack.push(Value::Null),
                    },
                    _ => stack.push(Value::Null),
                }
            }
            Instr::EmitSay => {
                let v = wrap(pop(stack), code, spans, ip, stack, src, filename, trace)?;
                events.push(RuntimeEvent::Say(format_value(&v)));
            }
            Instr::EmitAsk => {
                let v = wrap(pop(stack), code, spans, ip, stack, src, filename, trace)?;
                let prompt = format_value(&v);
                events.push(RuntimeEvent::Ask {
                    prompt: prompt.clone(),
                    answer: String::new(),
                });
                let ans = query_ask(&prompt);
                events.push(RuntimeEvent::Ask {
                    prompt,
                    answer: ans,
                });
            }
            Instr::EmitFetch => {
                let v = wrap(pop(stack), code, spans, ip, stack, src, filename, trace)?;
                events.push(RuntimeEvent::Fetch {
                    target: format_value(&v),
                });
            }
            Instr::EmitUi(kind) => {
                events.push(RuntimeEvent::Ui {
                    kind: kind.clone(),
                    props: Vec::new(),
                });
            }
            Instr::EmitText => {
                let v = wrap(pop(stack), code, spans, ip, stack, src, filename, trace)?;
                events.push(RuntimeEvent::Text(format_value(&v)));
            }
            Instr::EmitButton => {
                let v = wrap(pop(stack), code, spans, ip, stack, src, filename, trace)?;
                events.push(RuntimeEvent::Button(format_value(&v)));
            }
            Instr::EmitLog => {
                let v = wrap(pop(stack), code, spans, ip, stack, src, filename, trace)?;
                events.push(RuntimeEvent::Log(format_value(&v)));
            }
            Instr::Pop => {
                wrap(pop(stack), code, spans, ip, stack, src, filename, trace)?;
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

fn wrap<T>(
    res: VmResult<T>,
    code: &[Instr],
    spans: &[Option<crate::ast::Span>],
    ip: usize,
    stack: &[Value],
    src: &str,
    filename: &str,
    trace: &[TraceFrame],
) -> VmResult<T> {
    res.map_err(|msg| {
        if msg.starts_with("Runtime error: ") {
            // A recursive exec_code already attached the deepest source span.
            // Reformatting here would duplicate the stage and terminal-escape
            // the complete nested diagnostic at every caller frame.
            msg
        } else {
            vm_error(&msg, code, spans, ip, stack, src, filename, trace)
        }
    })
}

fn call_builtin(
    name: &str,
    argc: usize,
    builtins: &HashMap<String, BuiltinFn>,
    stack: &mut Vec<Value>,
) -> VmResult<Value> {
    // Fast paths avoid building args Vec for hot builtins.
    if name == "len" && argc == 1 {
        let arg = pop(stack)?;
        let len = match &arg {
            Value::RcObj(rc) => match rc.as_ref() {
                NauxObj::List(v) => v.borrow().len(),
                NauxObj::Text(s) => s.chars().count(),
                NauxObj::Bytes(v) => v.borrow().len(),
                NauxObj::Map(m) => m.borrow().len(),
                NauxObj::Set(s) => s.borrow().len(),
                NauxObj::PriorityQueue(pq) => pq.borrow().len(),
                _ => 0,
            },
            _ => 0,
        };
        let out = Value::SmallInt(len as i64);
        stack.push(out.clone());
        return Ok(out);
    }
    if name == "__index" && argc == 2 {
        let idx = pop(stack)?;
        let target = pop(stack)?;
        let result = match (&target, idx) {
            (Value::RcObj(rc), Value::SmallInt(n)) => match rc.as_ref() {
                NauxObj::List(v) => v.borrow().get(n as usize).cloned().unwrap_or(Value::Null),
                NauxObj::Bytes(v) => v
                    .borrow()
                    .get(n as usize)
                    .map(|b| Value::SmallInt(*b as i64))
                    .unwrap_or(Value::Null),
                _ => return Err("invalid __index operands".into()),
            },
            (Value::RcObj(rc), Value::Float(n)) => {
                if !n.is_finite() || n.fract() != 0.0 {
                    return Err("index must be an integer".into());
                }
                if n < 0.0 {
                    Value::Null
                } else {
                    match rc.as_ref() {
                        NauxObj::List(v) => {
                            v.borrow().get(n as usize).cloned().unwrap_or(Value::Null)
                        }
                        NauxObj::Bytes(v) => v
                            .borrow()
                            .get(n as usize)
                            .map(|b| Value::SmallInt(*b as i64))
                            .unwrap_or(Value::Null),
                        _ => return Err("invalid __index operands".into()),
                    }
                }
            }
            (Value::RcObj(rc), Value::RcObj(krc)) => match (rc.as_ref(), krc.as_ref()) {
                (NauxObj::Map(m), NauxObj::Text(s)) => {
                    m.borrow().get(s).cloned().unwrap_or(Value::Null)
                }
                _ => return Err("invalid __index operands".into()),
            },
            _ => return Err("invalid __index operands".into()),
        };
        stack.push(result.clone());
        return Ok(result);
    }

    let mut args = Vec::new();
    for _ in 0..argc {
        args.push(pop(stack)?);
    }
    args.reverse();

    if let Some(f) = builtins.get(name) {
        match f.call(args) {
            Ok(v) => {
                stack.push(v.clone());
                Ok(v)
            }
            Err(e) => Err(e.message),
        }
    } else {
        Err(format!("Unknown builtin: {}", name))
    }
}

fn call_function(
    fn_name: &str,
    func: &FunctionBytecode,
    argc: usize,
    builtins: &HashMap<String, BuiltinFn>,
    functions: &HashMap<String, FunctionBytecode>,
    frames: &mut Vec<Frame>,
    stack: &mut Vec<Value>,
    events: &mut Vec<RuntimeEvent>,
    trace: &mut Vec<TraceFrame>,
    call_span: Option<crate::ast::Span>,
    src: &str,
    filename: &str,
    debug: Option<&mut DebugHook<'_>>,
) -> VmResult<Value> {
    admit_internal_budget_builtin(builtins, WORK_CHECKPOINT_BUILTIN, Vec::new())?;
    let next_depth = i64::try_from(frames.len()).unwrap_or(i64::MAX);
    admit_internal_budget_builtin(
        builtins,
        CALL_DEPTH_BUILTIN,
        vec![Value::SmallInt(next_depth)],
    )?;
    let mut args = Vec::new();
    for _ in 0..argc {
        args.push(pop(stack)?);
    }
    args.reverse();
    trace.push(TraceFrame {
        name: fn_name.into(),
        span: call_span.clone(),
    });
    frames.push(Frame {
        locals: vec![Value::Null; func.locals.len()],
    });
    for (i, _param) in func.params.iter().enumerate() {
        if let Some(val) = args.get(i) {
            store_local(frames, i, val.clone());
        }
    }
    let ret = exec_code(
        &func.code,
        &func.locals,
        &func.spans,
        builtins,
        functions,
        frames,
        stack,
        events,
        trace,
        src,
        filename,
        debug,
        fn_name,
    )?;
    frames.pop();
    trace.pop();
    stack.push(ret.clone());
    Ok(ret)
}

fn admit_internal_budget_builtin(
    builtins: &HashMap<String, BuiltinFn>,
    name: &str,
    args: Vec<Value>,
) -> VmResult<()> {
    let Some(builtin) = builtins.get(name) else {
        return Ok(());
    };
    builtin
        .call(args)
        .map(|_| ())
        .map_err(|error| error.message)
}

fn load_local(frames: &[Frame], idx: usize) -> Value {
    frames
        .last()
        .and_then(|f| f.locals.get(idx))
        .cloned()
        .unwrap_or(Value::Null)
}

fn const_num_value(n: f64) -> Value {
    if n.fract().abs() < f64::EPSILON {
        Value::SmallInt(n as i64)
    } else {
        Value::Float(n)
    }
}

fn store_local(frames: &mut [Frame], idx: usize, val: Value) {
    if let Some(top) = frames.last_mut() {
        if idx < top.locals.len() {
            top.locals[idx] = val;
        }
    }
}

fn pop(stack: &mut Vec<Value>) -> Result<Value, String> {
    stack.pop().ok_or_else(|| "Stack underflow".to_string())
}

fn push_val(stack: &mut Vec<Value>, v: Value) {
    stack.push(v);
}

fn num_bin<FI, FF>(stack: &mut Vec<Value>, int_op: Option<FI>, float_op: FF) -> Result<(), String>
where
    FI: Fn(i64, i64) -> Value,
    FF: Fn(f64, f64) -> Value,
{
    let rhs = pop(stack)?;
    let lhs = pop(stack)?;
    if let Some(op) = int_op {
        if let (Value::SmallInt(a), Value::SmallInt(b)) = (&lhs, &rhs) {
            push_val(stack, op(*a, *b));
            return Ok(());
        }
    }
    match (lhs.as_f64(), rhs.as_f64()) {
        (Some(a), Some(b)) => {
            push_val(stack, float_op(a, b));
            Ok(())
        }
        _ => Err("Type error in binary op".into()),
    }
}

fn num_div(stack: &mut Vec<Value>) -> Result<(), String> {
    let rhs = pop(stack)?;
    let lhs = pop(stack)?;
    match (lhs.as_f64(), rhs.as_f64()) {
        (Some(_), Some(0.0)) => Err("Division by zero".into()),
        (Some(a), Some(b)) => {
            push_val(stack, Value::Float(a / b));
            Ok(())
        }
        _ => Err("Type error in binary op".into()),
    }
}

fn num_mod(stack: &mut Vec<Value>) -> Result<(), String> {
    let rhs = pop(stack)?;
    let lhs = pop(stack)?;
    if let (Value::SmallInt(a), Value::SmallInt(b)) = (&lhs, &rhs) {
        if *b == 0 {
            return Err("Modulo by zero".into());
        }
        push_val(stack, Value::SmallInt(a % b));
        return Ok(());
    }
    match (lhs.as_f64(), rhs.as_f64()) {
        (Some(_), Some(0.0)) => Err("Modulo by zero".into()),
        (Some(a), Some(b)) => {
            push_val(stack, Value::Float(a % b));
            Ok(())
        }
        _ => Err("Type error in binary op".into()),
    }
}

fn to_i64_exact(v: &Value) -> Option<i64> {
    match v {
        Value::SmallInt(n) => Some(*n),
        Value::Float(n) if n.fract() == 0.0 => Some(*n as i64),
        _ => None,
    }
}

fn int_bin<F>(stack: &mut Vec<Value>, op: F) -> Result<(), String>
where
    F: Fn(i64, i64) -> Value,
{
    let rhs = pop(stack)?;
    let lhs = pop(stack)?;
    match (to_i64_exact(&lhs), to_i64_exact(&rhs)) {
        (Some(a), Some(b)) => {
            push_val(stack, op(a, b));
            Ok(())
        }
        _ => Err("Type error in integer binary op".into()),
    }
}

fn shl_bin(stack: &mut Vec<Value>) -> Result<(), String> {
    let rhs = pop(stack)?;
    let lhs = pop(stack)?;
    let Some(shift) = to_i64_exact(&rhs) else {
        return Err("Shift count must be an integer".into());
    };
    if shift < 0 {
        return Err("Shift count must be non-negative".into());
    }
    let Some(value) = to_i64_exact(&lhs) else {
        return Err("Shift operand must be an integer".into());
    };
    push_val(stack, Value::SmallInt(value << (shift as u32)));
    Ok(())
}

fn bin_op<F>(stack: &mut Vec<Value>, f: F) -> Result<(), String>
where
    F: Fn(f64, f64) -> Value,
{
    let rhs = pop(stack)?;
    let lhs = pop(stack)?;
    match (lhs.as_f64(), rhs.as_f64()) {
        (Some(a), Some(b)) => {
            push_val(stack, f(a, b));
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
    push_val(stack, Value::Bool(f(lhs, rhs)));
    Ok(())
}

fn cmp_num<F>(stack: &mut Vec<Value>, f: F) -> Result<(), String>
where
    F: Fn(f64, f64) -> bool,
{
    let rhs = pop(stack)?;
    let lhs = pop(stack)?;
    if let (Value::SmallInt(a), Value::SmallInt(b)) = (&lhs, &rhs) {
        push_val(stack, Value::Bool(f(*a as f64, *b as f64)));
        return Ok(());
    }
    match (lhs.as_f64(), rhs.as_f64()) {
        (Some(a), Some(b)) => {
            push_val(stack, Value::Bool(f(a, b)));
            Ok(())
        }
        _ => Err("Type error in numeric comparison".into()),
    }
}

fn format_value(v: &Value) -> String {
    v.to_display_text()
}

fn vm_error(
    msg: &str,
    _code: &[Instr],
    spans: &[Option<crate::ast::Span>],
    ip: usize,
    _stack: &[Value],
    src: &str,
    filename: &str,
    _trace: &[TraceFrame],
) -> String {
    let error = RuntimeError::new(msg, spans.get(ip).and_then(Clone::clone));
    format_runtime_error_with_file(src, &error, filename)
}
