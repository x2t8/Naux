use std::collections::HashMap;

use crate::ast::{ActionKind, BinaryOp, Expr, Stmt, UnaryOp};
use crate::oracle::query_oracle;
use crate::runtime::env::Env;
use crate::runtime::error::RuntimeError;
use crate::runtime::events::RuntimeEvent;
use crate::runtime::value::Value;

pub fn eval_script(stmts: &[Stmt]) -> (Env, Vec<RuntimeEvent>, Vec<RuntimeError>) {
    let mut env = Env::new();
    let mut events = Vec::new();
    let mut errors = Vec::new();
    for stmt in stmts {
        eval_stmt(stmt, &mut env, &mut events, &mut errors);
    }
    (env, events, errors)
}

fn eval_block(block: &[Stmt], env: &mut Env, events: &mut Vec<RuntimeEvent>, errors: &mut Vec<RuntimeError>) {
    for stmt in block {
        eval_stmt(stmt, env, events, errors);
    }
}

fn eval_stmt(stmt: &Stmt, env: &mut Env, events: &mut Vec<RuntimeEvent>, errors: &mut Vec<RuntimeError>) {
    match stmt {
        Stmt::Rite { body, .. } => {
            env.push_scope();
            eval_block(body, env, events, errors);
            env.pop_scope();
        }
        Stmt::Assign { name, expr, .. } => {
            let val = eval_expr(expr, env, errors);
            env.set(name, val);
        }
        Stmt::If { cond, then_block, else_block, .. } => {
            let c = eval_expr(cond, env, errors);
            if c.truthy() {
                eval_block(then_block, env, events, errors);
            } else {
                eval_block(else_block, env, events, errors);
            }
        }
        Stmt::Loop { count, body, .. } => {
            let n = eval_expr(count, env, errors);
            let times = match n {
                Value::Number(x) if x > 0.0 => x as i64,
                _ => 0,
            };
            for _ in 0..times {
                eval_block(body, env, events, errors);
            }
        }
        Stmt::Each { var, iter, body, .. } => {
            let it = eval_expr(iter, env, errors);
            if let Value::List(items) = it {
                for v in items {
                    env.push_scope();
                    env.set(var, v);
                    eval_block(body, env, events, errors);
                    env.pop_scope();
                }
            }
        }
        Stmt::While { cond, body, .. } => {
            loop {
                let c = eval_expr(cond, env, errors);
                if !c.truthy() {
                    break;
                }
                eval_block(body, env, events, errors);
            }
        }
        Stmt::Action { action, .. } => {
            dispatch_action(action, env, events, errors);
        }
        Stmt::Return { .. } => {
            // TODO: implement function returns when functions added
        }
        Stmt::Import { .. } => {
            // TODO: implement import when module system added
        }
    }
}

fn dispatch_action(action: &ActionKind, env: &mut Env, events: &mut Vec<RuntimeEvent>, errors: &mut Vec<RuntimeError>) {
    match action {
        ActionKind::Say { value } => {
            let v = eval_expr(value, env, errors);
            events.push(RuntimeEvent::Say(format!("{:?}", v)));
        }
        ActionKind::Ui { kind, props } => {
            let mut evaluated = Vec::new();
            for (k, v) in props {
                evaluated.push((k.clone(), eval_expr(v, env, errors)));
            }
            events.push(RuntimeEvent::Ui {
                kind: kind.clone(),
                props: evaluated,
            });
        }
        ActionKind::Text { value } => {
            let v = eval_expr(value, env, errors);
            events.push(RuntimeEvent::Text(format!("{:?}", v)));
        }
        ActionKind::Button { value } => {
            let v = eval_expr(value, env, errors);
            events.push(RuntimeEvent::Button(format!("{:?}", v)));
        }
        ActionKind::Fetch { target } => {
            let v = eval_expr(target, env, errors);
            events.push(RuntimeEvent::Fetch {
                target: format!("{:?}", v),
            });
        }
        ActionKind::Ask { prompt } => {
            let v = eval_expr(prompt, env, errors);
            events.push(RuntimeEvent::Ask {
                prompt: format!("{:?}", v),
                answer: query_oracle(&format!("{:?}", v)),
            });
        }
        ActionKind::Log { value } => {
            let v = eval_expr(value, env, errors);
            events.push(RuntimeEvent::Log(format!("{:?}", v)));
        }
    }
}

fn eval_expr(expr: &Expr, env: &mut Env, errors: &mut Vec<RuntimeError>) -> Value {
    match expr {
        Expr::Number(n) => Value::Number(*n),
        Expr::Bool(b) => Value::Bool(*b),
        Expr::Text(s) => Value::Text(s.clone()),
        Expr::List(items) => Value::List(items.iter().map(|e| eval_expr(e, env, errors)).collect()),
        Expr::Map(entries) => {
            let mut map = HashMap::new();
            for (k, v) in entries {
                map.insert(k.clone(), eval_expr(v, env, errors));
            }
            Value::Map(map)
        }
        Expr::Var(name) => env.get(name).unwrap_or(Value::Null),
        Expr::Binary { op, left, right } => {
            let l = eval_expr(left, env, errors);
            let r = eval_expr(right, env, errors);
            eval_binary(op, l, r)
        }
        Expr::Unary { op, expr } => {
            let v = eval_expr(expr, env, errors);
            match op {
                UnaryOp::Neg => match v {
                    Value::Number(n) => Value::Number(-n),
                    _ => Value::Null,
                },
                UnaryOp::Not => Value::Bool(!v.truthy()),
            }
        }
        Expr::Index { target, index } => {
            let t = eval_expr(target, env, errors);
            let idx = eval_expr(index, env, errors);
            match (t, idx) {
                (Value::List(list), Value::Number(n)) => {
                    let i = n as usize;
                    list.get(i).cloned().unwrap_or(Value::Null)
                }
                (Value::Map(map), Value::Text(key)) => map.get(&key).cloned().unwrap_or(Value::Null),
                _ => Value::Null,
            }
        }
        Expr::Field { target, field } => {
            let t = eval_expr(target, env, errors);
            match t {
                Value::Map(map) => map.get(field).cloned().unwrap_or(Value::Null),
                _ => Value::Null,
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
