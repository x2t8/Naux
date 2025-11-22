use std::collections::HashMap;

use crate::ast::{ActionKind, BinaryOp, Expr, Stmt, UnaryOp};
use crate::oracle::query_oracle;
use crate::runtime::env::Env;
use crate::runtime::error::RuntimeError;
use crate::runtime::events::RuntimeEvent;
use crate::runtime::value::{Function, Value};
use crate::{lexer::lex, parser::parser::Parser};
use std::fs;
use std::rc::Rc;

pub fn eval_script(stmts: &[Stmt]) -> (Env, Vec<RuntimeEvent>, Vec<RuntimeError>) {
    let mut env = Env::new();
    crate::stdlib::register_all(&mut env);
    let mut events = Vec::new();
    let mut errors = Vec::new();
    for stmt in stmts {
        if eval_stmt(stmt, &mut env, &mut events, &mut errors).is_some() {
            break;
        }
    }
    (env, events, errors)
}

fn eval_block(block: &[Stmt], env: &mut Env, events: &mut Vec<RuntimeEvent>, errors: &mut Vec<RuntimeError>) -> Option<Value> {
    for stmt in block {
        if let Some(ret) = eval_stmt(stmt, env, events, errors) {
            return Some(ret);
        }
    }
    None
}

fn eval_stmt(stmt: &Stmt, env: &mut Env, events: &mut Vec<RuntimeEvent>, errors: &mut Vec<RuntimeError>) -> Option<Value> {
    match stmt {
        Stmt::Rite { body, .. } => {
            env.push_scope();
            let ret = eval_block(body, env, events, errors);
            env.pop_scope();
            ret
        }
        Stmt::Unsafe { body, .. } => {
            env.push_scope();
            env.push_unsafe(true);
            let ret = eval_block(body, env, events, errors);
            env.pop_unsafe();
            env.pop_scope();
            ret
        }
        Stmt::FnDef { name, params, body, .. } => {
            let func = Function { params: params.clone(), body: body.clone() };
            env.set(name, Value::Function(Rc::new(func)));
            None
        }
        Stmt::Assign { name, expr, .. } => {
            let val = eval_expr(expr, env, events, errors);
            env.set(name, val);
            None
        }
        Stmt::If { cond, then_block, else_block, .. } => {
            let c = eval_expr(cond, env, events, errors);
            if c.truthy() {
                eval_block(then_block, env, events, errors)
            } else {
                eval_block(else_block, env, events, errors)
            }
        }
        Stmt::Loop { count, body, .. } => {
            let n = eval_expr(count, env, events, errors);
            let times = match n {
                Value::Number(x) if x > 0.0 => x as i64,
                _ => 0,
            };
            for _ in 0..times {
                if let Some(ret) = eval_block(body, env, events, errors) {
                    return Some(ret);
                }
            }
            None
        }
        Stmt::Each { var, iter, body, .. } => {
            let it = eval_expr(iter, env, events, errors);
            if let Value::List(items) = it {
                for v in items {
                    env.push_scope();
                    env.set(var, v);
                    if let Some(ret) = eval_block(body, env, events, errors) {
                        env.pop_scope();
                        return Some(ret);
                    }
                    env.pop_scope();
                }
            }
            None
        }
        Stmt::While { cond, body, .. } => {
            loop {
                let c = eval_expr(cond, env, events, errors);
                if !c.truthy() {
                    break;
                }
                if let Some(ret) = eval_block(body, env, events, errors) {
                    return Some(ret);
                }
            }
            None
        }
        Stmt::Action { action, .. } => {
            dispatch_action(action, env, events, errors);
            None
        }
        Stmt::Return { value, .. } => Some(eval_expr(value, env, events, errors)),
        Stmt::Import { module, .. } => handle_import(module, env, events, errors),
    }
}

fn dispatch_action(action: &ActionKind, env: &mut Env, events: &mut Vec<RuntimeEvent>, errors: &mut Vec<RuntimeError>) {
    match action {
        ActionKind::Say { value } => {
            let v = eval_expr(value, env, events, errors);
            events.push(RuntimeEvent::Say(format!("{:?}", v)));
        }
        ActionKind::Ui { kind, props } => {
            let mut evaluated = Vec::new();
            for (k, v) in props {
                evaluated.push((k.clone(), eval_expr(v, env, events, errors)));
            }
            events.push(RuntimeEvent::Ui {
                kind: kind.clone(),
                props: evaluated,
            });
        }
        ActionKind::Text { value } => {
            let v = eval_expr(value, env, events, errors);
            events.push(RuntimeEvent::Text(format!("{:?}", v)));
        }
        ActionKind::Button { value } => {
            let v = eval_expr(value, env, events, errors);
            events.push(RuntimeEvent::Button(format!("{:?}", v)));
        }
        ActionKind::Fetch { target } => {
            let v = eval_expr(target, env, events, errors);
            events.push(RuntimeEvent::Fetch {
                target: format!("{:?}", v),
            });
        }
        ActionKind::Ask { prompt } => {
            let v = eval_expr(prompt, env, events, errors);
            events.push(RuntimeEvent::Ask {
                prompt: format!("{:?}", v),
                answer: query_oracle(&format!("{:?}", v)),
            });
        }
        ActionKind::Log { value } => {
            let v = eval_expr(value, env, events, errors);
            events.push(RuntimeEvent::Log(format!("{:?}", v)));
        }
    }
}

fn eval_expr(expr: &Expr, env: &mut Env, events: &mut Vec<RuntimeEvent>, errors: &mut Vec<RuntimeError>) -> Value {
    match expr {
        Expr::Number(n) => Value::Number(*n),
        Expr::Bool(b) => Value::Bool(*b),
        Expr::Text(s) => Value::Text(s.clone()),
        Expr::List(items) => Value::List(items.iter().map(|e| eval_expr(e, env, events, errors)).collect()),
        Expr::Map(entries) => {
            let mut map = HashMap::new();
            for (k, v) in entries {
                map.insert(k.clone(), eval_expr(v, env, events, errors));
            }
            Value::Map(map)
        }
        Expr::Var(name) => {
            match env.get(name) {
                Some(v) => v,
                None => {
                    errors.push(RuntimeError::new(format!("Variable not found: {}", name), None));
                    Value::Null
                }
            }
        }
        Expr::Binary { op, left, right } => {
            let l = eval_expr(left, env, events, errors);
            let r = eval_expr(right, env, events, errors);
            eval_binary(op, l, r)
        }
        Expr::Unary { op, expr } => {
            let v = eval_expr(expr, env, events, errors);
            match op {
                UnaryOp::Neg => match v {
                    Value::Number(n) => Value::Number(-n),
                    _ => Value::Null,
                },
                UnaryOp::Not => Value::Bool(!v.truthy()),
            }
        }
        Expr::Index { target, index } => {
            let t = eval_expr(target, env, events, errors);
            let idx = eval_expr(index, env, events, errors);
            match (t, idx) {
                (Value::List(list), Value::Number(n)) => {
                    let i = n as usize;
                    match list.get(i) {
                        Some(v) => v.clone(),
                        None => {
                            if !env.is_unsafe() {
                                errors.push(RuntimeError::new("Index out of bounds", None));
                            }
                            Value::Null
                        }
                    }
                }
                (Value::Map(map), Value::Text(key)) => map.get(&key).cloned().unwrap_or(Value::Null),
                _ => {
                    if !env.is_unsafe() {
                        errors.push(RuntimeError::new("Invalid index operation", None));
                    }
                    Value::Null
                }
            }
        }
        Expr::Field { target, field } => {
            let t = eval_expr(target, env, events, errors);
            match t {
                Value::Map(map) => map.get(field).cloned().unwrap_or(Value::Null),
                _ => {
                    errors.push(RuntimeError::new("Field access on non-map", None));
                    Value::Null
                }
            }
        }
        Expr::Call { callee, args } => {
            let evaluated_args: Vec<Value> = args.iter().map(|a| eval_expr(a, env, events, errors)).collect();
            // only support calling builtin by name for now
            if let Expr::Var(name) = &**callee {
                if let Some(res) = env.call_builtin(name, evaluated_args.clone()) {
                    return match res {
                        Ok(v) => v,
                        Err(e) => {
                            errors.push(e);
                            Value::Null
                        }
                    };
                } else if let Some(Value::Function(f)) = env.get(name) {
                    return call_user_function(f, evaluated_args, env, events, errors);
                } else {
                    errors.push(RuntimeError::new(format!("Unknown function: {}", name), None));
                    return Value::Null;
                }
            }
            let callee_val = eval_expr(callee, env, events, errors);
            match callee_val {
                Value::Function(f) => call_user_function(f, evaluated_args, env, events, errors),
                _ => {
                    errors.push(RuntimeError::new("Invalid callee in call", None));
                    Value::Null
                }
            }
        }
    }
}

fn eval_binary(op: &BinaryOp, l: Value, r: Value) -> Value {
    match op {
        BinaryOp::Add => match (l, r) {
            (Value::Number(a), Value::Number(b)) => Value::Number(a + b),
            (Value::Text(a), Value::Text(b)) => Value::Text(format!("{}{}", a, b)),
            (a, b) => Value::Text(format!("{:?}{:?}", a, b)),
        },
        BinaryOp::Sub => match (l, r) {
            (Value::Number(a), Value::Number(b)) => Value::Number(a - b),
            _ => Value::Null,
        },
        BinaryOp::Mul => match (l, r) {
            (Value::Number(a), Value::Number(b)) => Value::Number(a * b),
            _ => Value::Null,
        },
        BinaryOp::Div => match (l, r) {
            (Value::Number(a), Value::Number(b)) => Value::Number(a / b),
            _ => Value::Null,
        },
        BinaryOp::Mod => match (l, r) {
            (Value::Number(a), Value::Number(b)) => Value::Number(a % b),
            _ => Value::Null,
        },
        BinaryOp::Eq => Value::Bool(l == r),
        BinaryOp::Ne => Value::Bool(l != r),
        BinaryOp::Gt => match (l, r) {
            (Value::Number(a), Value::Number(b)) => Value::Bool(a > b),
            _ => Value::Null,
        },
        BinaryOp::Ge => match (l, r) {
            (Value::Number(a), Value::Number(b)) => Value::Bool(a >= b),
            _ => Value::Null,
        },
        BinaryOp::Lt => match (l, r) {
            (Value::Number(a), Value::Number(b)) => Value::Bool(a < b),
            _ => Value::Null,
        },
        BinaryOp::Le => match (l, r) {
            (Value::Number(a), Value::Number(b)) => Value::Bool(a <= b),
            _ => Value::Null,
        },
        BinaryOp::And => Value::Bool(l.truthy() && r.truthy()),
        BinaryOp::Or => Value::Bool(l.truthy() || r.truthy()),
    }
}

fn call_user_function(func: Rc<Function>, args: Vec<Value>, env: &mut Env, events: &mut Vec<RuntimeEvent>, errors: &mut Vec<RuntimeError>) -> Value {
    env.push_scope();
    for (i, param) in func.params.iter().enumerate() {
        let val = args.get(i).cloned().unwrap_or(Value::Null);
        env.set(param, val);
    }
    let ret = eval_block(&func.body, env, events, errors).unwrap_or(Value::Null);
    env.pop_scope();
    ret
}

fn handle_import(module: &str, env: &mut Env, events: &mut Vec<RuntimeEvent>, errors: &mut Vec<RuntimeError>) -> Option<Value> {
    match fs::read_to_string(module) {
        Ok(src) => match lex(&src) {
            Ok(tokens) => match Parser::from_tokens(&tokens) {
                Ok(stmts) => {
                    for stmt in stmts {
                        if let Some(ret) = eval_stmt(&stmt, env, events, errors) {
                            // imports should not return a value; ignore but stop if return found
                            return Some(ret);
                        }
                    }
                    None
                }
                Err(e) => {
                    errors.push(RuntimeError::new(format!("Import parse error in {}: {}", module, e.message), Some(e.span)));
                    None
                }
            },
            Err(e) => {
                errors.push(RuntimeError::new(format!("Import lex error in {}: {}", module, e.message), Some(e.span)));
                None
            }
        },
        Err(e) => {
            errors.push(RuntimeError::new(format!("Failed to import {}: {}", module, e), None));
            None
        }
    }
}
