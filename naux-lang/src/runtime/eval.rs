use std::collections::HashMap;
use std::fs;

use crate::ast::{ActionKind, BinaryOp, Expr, ExprKind, Stmt, UnaryOp};
use crate::lexer::lex;
use crate::oracle::query_oracle;
use crate::parser::error::format_parse_error;
use crate::parser::parser::Parser;
use crate::runtime::env::{Env, FnDef};
use crate::runtime::error::{Frame, RuntimeError};
use crate::runtime::events::RuntimeEvent;
use crate::runtime::value::{NauxObj, Value};
use crate::stdlib::register_all;

pub fn eval_script(stmts: &[Stmt]) -> (Env, Vec<RuntimeEvent>, Vec<RuntimeError>) {
    let mut env = Env::new();
    register_all(&mut env);
    let mut events = Vec::new();
    let mut errors = Vec::new();
    let mut call_stack: Vec<Frame> = Vec::new();
    for stmt in stmts {
        if eval_stmt(stmt, &mut env, &mut events, &mut errors, &mut call_stack).is_some() {
            // ignore top-level returns
        }
    }
    (env, events, errors)
}

fn eval_block(
    block: &[Stmt],
    env: &mut Env,
    events: &mut Vec<RuntimeEvent>,
    errors: &mut Vec<RuntimeError>,
    call_stack: &mut Vec<Frame>,
) -> Option<Value> {
    for stmt in block {
        if let Some(rv) = eval_stmt(stmt, env, events, errors, call_stack) {
            return Some(rv);
        }
    }
    None
}

fn eval_stmt(
    stmt: &Stmt,
    env: &mut Env,
    events: &mut Vec<RuntimeEvent>,
    errors: &mut Vec<RuntimeError>,
    call_stack: &mut Vec<Frame>,
) -> Option<Value> {
    match stmt {
        Stmt::Rite { body, span } => {
            env.push_scope();
            call_stack.push(Frame { name: "rite".into(), span: span.clone() });
            let rv = eval_block(body, env, events, errors, call_stack);
            call_stack.pop();
            env.pop_scope();
            rv
        }
        Stmt::Unsafe { body, .. } => {
            env.push_unsafe(true);
            let rv = eval_block(body, env, events, errors, call_stack);
            env.pop_unsafe();
            rv
        }
        Stmt::FnDef { name, params, body, span } => {
            env.define_fn(name, params.clone(), body.clone(), span.clone());
            None
        }
        Stmt::Assign { name, expr, .. } => {
            let val = eval_expr(expr, env, events, errors, call_stack);
            env.set(name, val);
            events.push(RuntimeEvent::Log(format!("set {}", name)));
            None
        }
        Stmt::If { cond, then_block, else_block, .. } => {
            let c = eval_expr(cond, env, events, errors, call_stack);
            if c.truthy() {
                eval_block(then_block, env, events, errors, call_stack)
            } else {
                eval_block(else_block, env, events, errors, call_stack)
            }
        }
        Stmt::Loop { count, body, .. } => {
            let n = eval_expr(count, env, events, errors, call_stack);
            let times = n.as_f64().filter(|x| *x > 0.0).unwrap_or(0.0) as i64;
            for _ in 0..times {
                if let Some(rv) = eval_block(body, env, events, errors, call_stack) {
                    return Some(rv);
                }
            }
            None
        }
        Stmt::Each { var, iter, body, span } => {
            let it = eval_expr(iter, env, events, errors, call_stack);
            if let Value::RcObj(rc) = it {
                if let NauxObj::List(items) = rc.as_ref() {
                    for v in items.borrow().iter() {
                        env.push_scope();
                        env.set(var, v.clone());
                        if let Some(rv) = eval_block(body, env, events, errors, call_stack) {
                            env.pop_scope();
                            return Some(rv);
                        }
                        env.pop_scope();
                    }
                    return None;
                }
            }
            push_error(errors, "Each expects a list to iterate", span.clone(), call_stack);
            None
        }
        Stmt::While { cond, body, .. } => {
            loop {
                let c = eval_expr(cond, env, events, errors, call_stack);
                if !c.truthy() {
                    break;
                }
                if let Some(rv) = eval_block(body, env, events, errors, call_stack) {
                    return Some(rv);
                }
            }
            None
        }
        Stmt::Action { action, .. } => {
            dispatch_action(action, env, events, errors, call_stack);
            None
        }
        Stmt::Return { value, .. } => {
            let v = value
                .as_ref()
                .map(|e| eval_expr(e, env, events, errors, call_stack))
                .unwrap_or(Value::Null);
            Some(v)
        }
        Stmt::Import { module, span } => {
            eval_import(module, env, events, errors, call_stack, span.clone());
            None
        }
    }
}

fn eval_expr(
    expr: &Expr,
    env: &mut Env,
    events: &mut Vec<RuntimeEvent>,
    errors: &mut Vec<RuntimeError>,
    call_stack: &mut Vec<Frame>,
) -> Value {
    match &expr.kind {
        ExprKind::Number(n) => {
            if n.fract().abs() < f64::EPSILON {
                Value::SmallInt(*n as i64)
            } else {
                Value::Float(*n)
            }
        }
        ExprKind::Bool(b) => Value::Bool(*b),
        ExprKind::Text(s) => Value::make_text(s.clone()),
        ExprKind::List(items) => Value::make_list(items.iter().map(|e| eval_expr(e, env, events, errors, call_stack)).collect()),
        ExprKind::Map(entries) => {
            let mut m = HashMap::new();
            for (k, v) in entries {
                m.insert(k.clone(), eval_expr(v, env, events, errors, call_stack));
            }
            Value::make_map(m)
        }
        ExprKind::Var(name) => match env.get(name) {
            Some(v) => v,
            None => {
                push_error(errors, format!("Variable not found: {}", name), expr.span.clone(), call_stack);
                Value::Null
            }
        },
        ExprKind::Call { callee, args } => {
            let name_opt = if let ExprKind::Var(n) = &callee.kind { Some(n.clone()) } else { None };
            let evaled_args: Vec<Value> = args.iter().map(|a| eval_expr(a, env, events, errors, call_stack)).collect();
            if let Some(name) = name_opt {
                if let Some(fn_def) = env.get_fn(&name) {
                    call_stack.push(Frame { name: name.clone(), span: expr.span.clone() });
                    env.push_scope();
                    for (i, param) in fn_def.params.iter().enumerate() {
                        let v = evaled_args.get(i).cloned().unwrap_or(Value::Null);
                        env.set(param, v);
                    }
                    let rv = eval_block(&fn_def.body, env, events, errors, call_stack).unwrap_or(Value::Null);
                    env.pop_scope();
                    call_stack.pop();
                    rv
                } else if let Some(res) = env.call_builtin(&name, evaled_args.clone()) {
                    match res {
                        Ok(v) => v,
                        Err(mut e) => {
                            e.trace = call_stack.clone();
                            errors.push(e);
                            Value::Null
                        }
                    }
                } else {
                    push_error(errors, format!("Function not found: {}", name), expr.span.clone(), call_stack);
                    Value::Null
                }
            } else {
                push_error(errors, "Invalid call target", expr.span.clone(), call_stack);
                Value::Null
            }
        }
        ExprKind::Binary { op, left, right } => {
            let l = eval_expr(left, env, events, errors, call_stack);
            let r = eval_expr(right, env, events, errors, call_stack);
            match op {
                BinaryOp::Add => match (&l, &r) {
                    (Value::RcObj(a), Value::RcObj(b)) => match (a.as_ref(), b.as_ref()) {
                        (NauxObj::Text(la), NauxObj::Text(lb)) => Value::make_text(format!("{}{}", la, lb)),
                        _ => Value::add(&l, &r),
                    },
                    _ => Value::add(&l, &r),
                },
                BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => {
                    let a = l.as_f64();
                    let b = r.as_f64();
                    match (a, b) {
                        (_, Some(0.0)) if matches!(op, BinaryOp::Div) => {
                            push_error(errors, "Division by zero", expr.span.clone(), call_stack);
                            Value::Null
                        }
                        (Some(x), Some(y)) => match op {
                            BinaryOp::Sub => Value::Float(x - y),
                            BinaryOp::Mul => Value::Float(x * y),
                            BinaryOp::Div => Value::Float(x / y),
                            BinaryOp::Mod => Value::Float(x % y),
                            _ => Value::Null,
                        },
                        _ => {
                            push_error(errors, "Type error in binary expression", expr.span.clone(), call_stack);
                            Value::Null
                        }
                    }
                }
                BinaryOp::Eq | BinaryOp::Ne => {
                    let eq = l == r;
                    Value::Bool(if matches!(op, BinaryOp::Eq) { eq } else { !eq })
                }
                BinaryOp::Gt | BinaryOp::Ge | BinaryOp::Lt | BinaryOp::Le => {
                    let a = l.as_f64();
                    let b = r.as_f64();
                    match (a, b) {
                        (Some(x), Some(y)) => {
                            let res = match op {
                                BinaryOp::Gt => x > y,
                                BinaryOp::Ge => x >= y,
                                BinaryOp::Lt => x < y,
                                BinaryOp::Le => x <= y,
                                _ => false,
                            };
                            Value::Bool(res)
                        }
                        _ => {
                            push_error(errors, "Type error in binary expression", expr.span.clone(), call_stack);
                            Value::Null
                        }
                    }
                }
                BinaryOp::And | BinaryOp::Or => match (l.truthy(), r.truthy()) {
                    (la, ra) => Value::Bool(if matches!(op, BinaryOp::And) { la && ra } else { la || ra }),
                },
            }
        }
        ExprKind::Unary { op, expr: inner } => {
            let v = eval_expr(inner, env, events, errors, call_stack);
            match (op, v) {
                (UnaryOp::Neg, Value::SmallInt(n)) => Value::SmallInt(-n),
                (UnaryOp::Neg, Value::Float(n)) => Value::Float(-n),
                (UnaryOp::Not, val) => Value::Bool(!val.truthy()),
                _ => {
                    push_error(errors, "Type error in unary expression", expr.span.clone(), call_stack);
                    Value::Null
                }
            }
        }
        ExprKind::Index { target, index } => {
            let t = eval_expr(target, env, events, errors, call_stack);
            let idxv = eval_expr(index, env, events, errors, call_stack);
            match (t, idxv) {
                (Value::RcObj(rc), Value::RcObj(krc)) => match (rc.as_ref(), krc.as_ref()) {
                    (NauxObj::Map(map), NauxObj::Text(key)) => map.borrow().get(key).cloned().unwrap_or(Value::Null),
                    _ => {
                        push_error(errors, "Invalid index operation", expr.span.clone(), call_stack);
                        Value::Null
                    }
                },
                (Value::RcObj(rc), idx_val) => {
                    let idx_opt = match idx_val {
                        Value::SmallInt(n) => Some(n as usize),
                        Value::Float(n) => Some(n as usize),
                        _ => None,
                    };
                    if let (Some(idx), NauxObj::List(list)) = (idx_opt, rc.as_ref()) {
                        list.borrow().get(idx).cloned().unwrap_or(Value::Null)
                    } else {
                        push_error(errors, "Invalid index operation", expr.span.clone(), call_stack);
                        Value::Null
                    }
                }
                _ => {
                    push_error(errors, "Invalid index operation", expr.span.clone(), call_stack);
                    Value::Null
                }
            }
        }
        ExprKind::Field { target, field } => {
            let t = eval_expr(target, env, events, errors, call_stack);
            match t {
                Value::RcObj(rc) => match rc.as_ref() {
                    NauxObj::Map(m) => m.borrow_mut().remove(field).unwrap_or(Value::Null),
                    _ => {
                        push_error(errors, "Invalid field access", expr.span.clone(), call_stack);
                        Value::Null
                    }
                },
                _ => {
                    push_error(errors, "Invalid field access", expr.span.clone(), call_stack);
                    Value::Null
                }
            }
        }
    }
}

fn dispatch_action(action: &ActionKind, env: &mut Env, events: &mut Vec<RuntimeEvent>, errors: &mut Vec<RuntimeError>, call_stack: &mut Vec<Frame>) {
    match action {
        ActionKind::Say { value } => {
            let v = eval_expr(value, env, events, errors, call_stack);
            events.push(RuntimeEvent::Say(format_value(&v)));
        }
        ActionKind::Ask { prompt } => {
            let p = eval_expr(prompt, env, events, errors, call_stack);
            let p_str = format_value(&p);
            events.push(RuntimeEvent::Ask { prompt: p_str.clone(), answer: String::new() });
            let ans = query_oracle(&p_str);
            events.push(RuntimeEvent::Ask { prompt: p_str, answer: ans.clone() });
        }
        ActionKind::Fetch { target } => {
            let t = eval_expr(target, env, events, errors, call_stack);
            events.push(RuntimeEvent::Fetch { target: format_value(&t) });
        }
        ActionKind::Ui { kind, .. } => {
            events.push(RuntimeEvent::Ui { kind: kind.clone(), props: Vec::new() });
        }
        ActionKind::Text { value } => {
            let v = eval_expr(value, env, events, errors, call_stack);
            events.push(RuntimeEvent::Text(format_value(&v)));
        }
        ActionKind::Button { value } => {
            let v = eval_expr(value, env, events, errors, call_stack);
            events.push(RuntimeEvent::Button(format_value(&v)));
        }
        ActionKind::Log { value } => {
            let v = eval_expr(value, env, events, errors, call_stack);
            events.push(RuntimeEvent::Log(format_value(&v)));
        }
    }
}

fn eval_import(module: &str, env: &mut Env, events: &mut Vec<RuntimeEvent>, errors: &mut Vec<RuntimeError>, call_stack: &mut Vec<Frame>, span: Option<crate::ast::Span>) {
    match fs::read_to_string(module) {
        Ok(src) => {
            let tokens = match lex(&src) {
                Ok(t) => t,
                Err(e) => {
                    errors.push(RuntimeError::with_trace(format!("Lex error in import {}: {}", module, e.message), Some(e.span), call_stack.clone()));
                    return;
                }
            };
            let mut parser = Parser::new(tokens);
            match parser.parse_script() {
                Ok(ast) => {
                    for stmt in ast {
                        match stmt {
                            Stmt::FnDef { name, params, body, span } => env.define_fn(&name, params, body, span),
                            Stmt::Assign { name, expr, .. } => {
                                let v = eval_expr(&expr, env, events, errors, call_stack);
                                env.set(&name, v);
                            }
                            Stmt::Rite { .. } => {
                            }
                            _ => {}
                        }
                    }
                }
                Err(e) => {
                    let msg = format_parse_error(&src, &e, module);
                    errors.push(RuntimeError::with_trace(msg, e.span.into(), call_stack.clone()));
                }
            }
        }
        Err(err) => {
            let msg = format!("Failed to import {}: {}", module, err);
            errors.push(RuntimeError::with_trace(msg, span, call_stack.clone()));
        }
    }
}

fn format_value(v: &Value) -> String {
    match v {
        Value::RcObj(rc) => match rc.as_ref() {
            NauxObj::Text(s) => s.clone(),
            _ => format!("{:?}", v),
        },
        Value::SmallInt(n) => n.to_string(),
        Value::Float(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        other => format!("{:?}", other),
    }
}

fn push_error(errors: &mut Vec<RuntimeError>, msg: impl Into<String>, span: Option<crate::ast::Span>, call_stack: &Vec<Frame>) {
    errors.push(RuntimeError::with_trace(msg, span, call_stack.clone()));
}
