// TODO: bytecode interpreter
#![allow(dead_code)]

use crate::oracle::query_oracle;
use crate::runtime::env::BuiltinFn;
use crate::runtime::error::Frame as TraceFrame;
use crate::runtime::events::RuntimeEvent;
use crate::runtime::value::{NauxObj, Value};
use crate::vm::bytecode::{disasm_window, FunctionBytecode, Instr, Program, VmResult};
use crate::vm::jit::run_jit;

use std::collections::HashMap;

const JIT_HOT_THRESHOLD: usize = 128;

#[derive(Clone, Debug)]
struct Frame {
    locals: Vec<Value>,
}

/// Execute a compiled program with a stack machine. Handles builtin and user functions.
pub fn run_program(
    prog: &Program,
    builtins: &HashMap<String, BuiltinFn>,
    src: &str,
    filename: &str,
) -> VmResult<(Value, Vec<RuntimeEvent>)> {
    let mut frames: Vec<Frame> = vec![Frame { locals: vec![Value::Null; prog.main_locals.len()] }];
    let mut stack: Vec<Value> = Vec::new();
    let mut events: Vec<RuntimeEvent> = Vec::new();
    let mut trace: Vec<TraceFrame> = Vec::new();
    let mut jit_cache: HashMap<usize, f64> = HashMap::new();
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
        &mut jit_cache,
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
    jit_cache: &mut HashMap<usize, f64>,
) -> VmResult<Value> {
    let code_key = code.as_ptr() as usize;
    if let Some(&val) = jit_cache.get(&code_key) {
        return Ok(Value::Float(val));
    }
    let mut ip: usize = 0;
    let mut hot_counts = vec![0usize; code.len()];
    while ip < code.len() {
        hot_counts[ip] = hot_counts[ip].saturating_add(1);
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
            Instr::LoadVar(name) => {
                stack.push(load_var_by_name(frames, locals_names, name));
            }
            Instr::StoreVar(name) => {
                let val = wrap(pop(stack), code, spans, ip, stack, src, filename, trace, jit_cache)?;
                store_var_by_name(frames, locals_names, name, val);
            }
            Instr::LoadLocal(idx) => {
                let v = load_local(frames, *idx);
                stack.push(v);
            }
            Instr::StoreLocal(idx) => {
                let val = wrap(pop(stack), code, spans, ip, stack, src, filename, trace, jit_cache)?;
                store_local(frames, *idx, val);
            }
            Instr::Add => wrap(num_bin(stack, Some(|a, b| Value::SmallInt(a + b)), |a, b| Value::Float(a + b)), code, spans, ip, stack, src, filename, trace, jit_cache)?,
            Instr::Sub => wrap(num_bin(stack, Some(|a, b| Value::SmallInt(a - b)), |a, b| Value::Float(a - b)), code, spans, ip, stack, src, filename, trace, jit_cache)?,
            Instr::Mul => wrap(num_bin(stack, Some(|a, b| Value::SmallInt(a * b)), |a, b| Value::Float(a * b)), code, spans, ip, stack, src, filename, trace, jit_cache)?,
            Instr::Div => wrap(num_bin::<fn(i64, i64) -> Value, _>(stack, None, |a, b| Value::Float(a / b)), code, spans, ip, stack, src, filename, trace, jit_cache)?,
            Instr::Mod => wrap(num_bin(stack, Some(|a, b| Value::SmallInt(a % b)), |a, b| Value::Float(a % b)), code, spans, ip, stack, src, filename, trace, jit_cache)?,
            Instr::Eq => wrap(cmp_op(stack, |a, b| a == b), code, spans, ip, stack, src, filename, trace, jit_cache)?,
            Instr::Ne => wrap(cmp_op(stack, |a, b| a != b), code, spans, ip, stack, src, filename, trace, jit_cache)?,
            Instr::Gt => wrap(cmp_num(stack, |a, b| a > b), code, spans, ip, stack, src, filename, trace, jit_cache)?,
            Instr::Ge => wrap(cmp_num(stack, |a, b| a >= b), code, spans, ip, stack, src, filename, trace, jit_cache)?,
            Instr::Lt => wrap(cmp_num(stack, |a, b| a < b), code, spans, ip, stack, src, filename, trace, jit_cache)?,
            Instr::Le => wrap(cmp_num(stack, |a, b| a <= b), code, spans, ip, stack, src, filename, trace, jit_cache)?,
            Instr::And => {
                let rhs = wrap(pop(stack), code, spans, ip, stack, src, filename, trace, jit_cache)?;
                let lhs = wrap(pop(stack), code, spans, ip, stack, src, filename, trace, jit_cache)?;
                stack.push(Value::Bool(lhs.truthy() && rhs.truthy()));
            }
            Instr::Or => {
                let rhs = wrap(pop(stack), code, spans, ip, stack, src, filename, trace, jit_cache)?;
                let lhs = wrap(pop(stack), code, spans, ip, stack, src, filename, trace, jit_cache)?;
                stack.push(Value::Bool(lhs.truthy() || rhs.truthy()));
            }
            Instr::Jump(target) => {
                ip = *target;
                continue;
            }
            Instr::JumpIfFalse(target) => {
                let cond = wrap(pop(stack), code, spans, ip, stack, src, filename, trace, jit_cache)?;
                if !cond.truthy() {
                    ip = *target;
                    continue;
                }
            }
            Instr::CallBuiltin(name, argc) => {
                wrap(call_builtin(name, *argc, builtins, stack), code, spans, ip, stack, src, filename, trace, jit_cache)?;
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
                            jit_cache,
                        ),
                        code,
                        spans,
                        ip,
                        stack,
                        src,
                        filename,
                        trace,
                        jit_cache,
                    )?;
                } else {
                    wrap(call_builtin(name, *argc, builtins, stack), code, spans, ip, stack, src, filename, trace, jit_cache)?;
                }
            }
            Instr::MakeList(len) => {
                let mut items = Vec::new();
                for _ in 0..*len {
                    items.push(wrap(pop(stack), code, spans, ip, stack, src, filename, trace, jit_cache)?);
                }
                items.reverse();
                stack.push(Value::make_list(items));
            }
            Instr::MakeMap(keys) => {
                let mut map = std::collections::HashMap::new();
                for key in keys.iter().rev() {
                    let val = wrap(pop(stack), code, spans, ip, stack, src, filename, trace, jit_cache)?;
                    map.insert(key.clone(), val);
                }
                stack.push(Value::make_map(map));
            }
            Instr::LoadField(field) => {
                let target = wrap(pop(stack), code, spans, ip, stack, src, filename, trace, jit_cache)?;
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
                let v = wrap(pop(stack), code, spans, ip, stack, src, filename, trace, jit_cache)?;
                events.push(RuntimeEvent::Say(format_value(&v)));
            }
            Instr::EmitAsk => {
                let v = wrap(pop(stack), code, spans, ip, stack, src, filename, trace, jit_cache)?;
                let prompt = format_value(&v);
                events.push(RuntimeEvent::Ask { prompt: prompt.clone(), answer: String::new() });
                let ans = query_oracle(&prompt);
                events.push(RuntimeEvent::Ask { prompt, answer: ans });
            }
            Instr::EmitFetch => {
                let v = wrap(pop(stack), code, spans, ip, stack, src, filename, trace, jit_cache)?;
                events.push(RuntimeEvent::Fetch { target: format_value(&v) });
            }
            Instr::EmitUi(kind) => {
                events.push(RuntimeEvent::Ui { kind: kind.clone(), props: Vec::new() });
            }
            Instr::EmitText => {
                let v = wrap(pop(stack), code, spans, ip, stack, src, filename, trace, jit_cache)?;
                events.push(RuntimeEvent::Text(format_value(&v)));
            }
            Instr::EmitButton => {
                let v = wrap(pop(stack), code, spans, ip, stack, src, filename, trace, jit_cache)?;
                events.push(RuntimeEvent::Button(format_value(&v)));
            }
            Instr::EmitLog => {
                let v = wrap(pop(stack), code, spans, ip, stack, src, filename, trace, jit_cache)?;
                events.push(RuntimeEvent::Log(format_value(&v)));
            }
            Instr::Return => {
                let ret = stack.pop().unwrap_or(Value::Null);
                return Ok(ret);
            }
        }
        if hot_counts[ip] >= JIT_HOT_THRESHOLD {
            match run_jit(code, locals_names.len()) {
                Ok(res) => {
                    jit_cache.insert(code_key, res);
                    return Ok(Value::Float(res));
                }
                Err(_) => {}
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
    jit_cache: &HashMap<usize, f64>,
) -> VmResult<T> {
    res.map_err(|msg| vm_error(&msg, code, spans, ip, stack, src, filename, trace, jit_cache))
}

fn call_builtin(name: &str, argc: usize, builtins: &HashMap<String, BuiltinFn>, stack: &mut Vec<Value>) -> VmResult<Value> {
    let mut args = Vec::new();
    for _ in 0..argc {
        args.push(pop(stack)?);
    }
    args.reverse();

    // Fast paths
    if name == "len" && args.len() == 1 {
        let len = match &args[0] {
            Value::RcObj(rc) => match rc.as_ref() {
                NauxObj::List(v) => v.borrow().len(),
                NauxObj::Text(s) => s.chars().count(),
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
    if name == "__index" && args.len() == 2 {
        let result = match (&args[0], &args[1]) {
            (Value::RcObj(rc), Value::SmallInt(n)) => match rc.as_ref() {
                NauxObj::List(v) => v.borrow().get(*n as usize).cloned().unwrap_or(Value::Null),
                _ => Value::Null,
            },
            (Value::RcObj(rc), Value::Float(n)) => match rc.as_ref() {
                NauxObj::List(v) => v.borrow().get(*n as usize).cloned().unwrap_or(Value::Null),
                _ => Value::Null,
            },
            (Value::RcObj(rc), Value::RcObj(krc)) => match (rc.as_ref(), krc.as_ref()) {
                (NauxObj::Map(m), NauxObj::Text(s)) => m.borrow().get(s).cloned().unwrap_or(Value::Null),
                _ => Value::Null,
            },
            _ => Value::Null,
        };
        stack.push(result.clone());
        return Ok(result);
    }

    if let Some(f) = builtins.get(name) {
        match f(args) {
            Ok(v) => {
                stack.push(v.clone());
                Ok(v)
            }
            Err(e) => Err(format!("RuntimeError: {}", e.message)),
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
    jit_cache: &mut HashMap<usize, f64>,
) -> VmResult<Value> {
    let mut args = Vec::new();
    for _ in 0..argc {
        args.push(pop(stack)?);
    }
    args.reverse();
    trace.push(TraceFrame { name: fn_name.into(), span: call_span.clone() });
    frames.push(Frame { locals: vec![Value::Null; func.locals.len()] });
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
        jit_cache,
    )?;
    frames.pop();
    trace.pop();
    stack.push(ret.clone());
    Ok(ret)
}

fn load_local(frames: &[Frame], idx: usize) -> Value {
    frames.last().and_then(|f| f.locals.get(idx)).cloned().unwrap_or(Value::Null)
}

fn store_local(frames: &mut [Frame], idx: usize, val: Value) {
    if let Some(top) = frames.last_mut() {
        if idx < top.locals.len() {
            top.locals[idx] = val;
        }
    }
}

fn load_var_by_name(frames: &[Frame], locals_names: &[String], name: &str) -> Value {
    if let Some(idx) = locals_names.iter().position(|n| n == name) {
        return load_local(frames, idx);
    }
    Value::Null
}

fn store_var_by_name(frames: &mut [Frame], locals_names: &[String], name: &str, val: Value) {
    if let Some(idx) = locals_names.iter().position(|n| n == name) {
        store_local(frames, idx, val);
    }
}

fn pop(stack: &mut Vec<Value>) -> Result<Value, String> {
    stack.pop().ok_or_else(|| "Stack underflow".to_string())
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
            stack.push(op(*a, *b));
            return Ok(());
        }
    }
    match (lhs.as_f64(), rhs.as_f64()) {
        (Some(a), Some(b)) => {
            stack.push(float_op(a, b));
            Ok(())
        }
        _ => Err("Type error in binary op".into()),
    }
}

fn bin_op<F>(stack: &mut Vec<Value>, f: F) -> Result<(), String>
where
    F: Fn(f64, f64) -> Value,
{
    let rhs = pop(stack)?;
    let lhs = pop(stack)?;
    match (lhs.as_f64(), rhs.as_f64()) {
        (Some(a), Some(b)) => {
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
    if let (Value::SmallInt(a), Value::SmallInt(b)) = (&lhs, &rhs) {
        stack.push(Value::Bool(f(*a as f64, *b as f64)));
        return Ok(());
    }
    match (lhs.as_f64(), rhs.as_f64()) {
        (Some(a), Some(b)) => {
            stack.push(Value::Bool(f(a, b)));
            Ok(())
        }
        _ => Err("Type error in numeric comparison".into()),
    }
}

fn format_value(v: &Value) -> String {
    match v {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Text(s) => s.clone(),
            NauxObj::List(list) => {
                let items: Vec<String> = list.borrow().iter().map(format_value).collect();
                format!("List [{}]", items.join(", "))
            }
            NauxObj::Map(map) => {
                let entries: Vec<String> = map.borrow().iter().map(|(k, v)| format!("{}:{}", k, format_value(v))).collect();
                format!("Map {{{}}}", entries.join(", "))
            }
            NauxObj::Graph(g) => {
                let gb = g.borrow();
                let edges: usize = gb.adj.values().map(|v| v.len()).sum();
                format!("Graph(nodes={}, edges={})", gb.adj.len(), edges)
            }
            NauxObj::Set(s) => format!("Set len={}", s.borrow().len()),
            NauxObj::PriorityQueue(pq) => format!("PriorityQueue len={}", pq.borrow().len()),
            NauxObj::Function(_) => "<fn>".into(),
        },
        Value::SmallInt(n) => n.to_string(),
        Value::Float(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        other => format!("{:?}", other),
    }
}

fn vm_error(
    msg: &str,
    code: &[Instr],
    spans: &[Option<crate::ast::Span>],
    ip: usize,
    stack: &[Value],
    src: &str,
    filename: &str,
    trace: &[TraceFrame],
    _jit_cache: &HashMap<usize, f64>,
) -> String {
    let mut out = String::new();
    use std::fmt::Write;
    writeln!(&mut out, "VM error: {}", msg).ok();
    if let Some(sp) = spans.get(ip).and_then(|s| s.clone()) {
        let line_idx = sp.line.saturating_sub(1);
        let line_text = src.lines().nth(line_idx).unwrap_or("");
        let caret = format!("{}^", " ".repeat(sp.column.saturating_sub(1)));
        writeln!(&mut out, "  at {}:{}:{}", filename, sp.line, sp.column).ok();
        writeln!(&mut out, "  {}", line_text).ok();
        writeln!(&mut out, "  {}", caret).ok();
    } else {
        writeln!(&mut out, "  at ip={}", ip).ok();
    }
    if !trace.is_empty() {
        writeln!(&mut out, "  Traceback (most recent call last):").ok();
        for frame in trace.iter().rev() {
            if let Some(sp) = &frame.span {
                let line_idx = sp.line.saturating_sub(1);
                let line_text = src.lines().nth(line_idx).unwrap_or("");
                let caret = format!("{}^", " ".repeat(sp.column.saturating_sub(1)));
                writeln!(&mut out, "    at {} ({}:{}:{})", frame.name, filename, sp.line, sp.column).ok();
                writeln!(&mut out, "      {}", line_text).ok();
                writeln!(&mut out, "      {}", caret).ok();
            } else {
                writeln!(&mut out, "    at {}", frame.name).ok();
            }
        }
    }
    writeln!(&mut out, "  nearby:").ok();
    out.push_str(&disasm_window(code, ip, 2));
    if !stack.is_empty() {
        let top: Vec<String> = stack.iter().rev().take(3).map(|v| format_value(v)).collect();
        writeln!(&mut out, "  stack top: {}", top.join(", ")).ok();
    }
    out
}
