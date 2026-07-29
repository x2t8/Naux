#![allow(clippy::too_many_arguments)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::ask::query_ask;
use crate::ast::{ActionKind, BinaryOp, Expr, ExprKind, Stmt, UnaryOp};
use crate::lexer::lex;
use crate::parser::error::format_parse_error;
use crate::parser::parser::Parser;
use crate::runtime::env::Env;
use crate::runtime::error::{Frame, RuntimeError};
use crate::runtime::events::RuntimeEvent;
use crate::runtime::value::{NauxObj, Value};
use crate::stdlib::register_all;

const MAX_ERRORS: usize = 32;

/// Represents the control flow status after evaluating a statement or block.
pub enum Control {
    /// Normal execution, no control flow jump.
    None,
    /// A `return` statement was executed.
    Return(Value),
    /// A `break` statement was executed.
    Break,
    /// A `continue` statement was executed.
    Continue,
}

pub fn eval_script(stmts: &[Stmt]) -> (Env, Vec<RuntimeEvent>, Vec<RuntimeError>) {
    eval_script_with_base_dir(stmts, None)
}

/// Evaluate a Surface program with explicit pre-bound scalar inputs.
///
/// This is primarily the differential oracle boundary for typed Surface-to-
/// Core elaboration. Bindings are installed without emitting assignment
/// events; program statements retain their ordinary event behavior.
pub fn eval_script_with_bindings(
    stmts: &[Stmt],
    bindings: &[(String, Value)],
) -> (Env, Vec<RuntimeEvent>, Vec<RuntimeError>) {
    eval_script_with_base_dir_and_bindings(stmts, None, bindings)
}

pub fn eval_script_with_base_dir(
    stmts: &[Stmt],
    base_dir: Option<&Path>,
) -> (Env, Vec<RuntimeEvent>, Vec<RuntimeError>) {
    eval_script_with_base_dir_and_bindings(stmts, base_dir, &[])
}

fn eval_script_with_base_dir_and_bindings(
    stmts: &[Stmt],
    base_dir: Option<&Path>,
    bindings: &[(String, Value)],
) -> (Env, Vec<RuntimeEvent>, Vec<RuntimeError>) {
    let mut env = Env::new();
    register_all(&mut env);
    for (name, value) in bindings {
        env.set(name, value.clone());
    }
    let mut events = Vec::new();
    let mut errors = Vec::new();
    let mut call_stack: Vec<Frame> = Vec::new();
    let mut module_cache: HashMap<String, Vec<Stmt>> = HashMap::new();
    let mut loading: HashSet<String> = HashSet::new();
    for stmt in stmts {
        if should_halt(&errors) {
            break;
        }
        // Top-level returns, breaks, and continues are ignored.
        eval_stmt(
            stmt,
            &mut env,
            &mut events,
            &mut errors,
            &mut call_stack,
            &mut module_cache,
            &mut loading,
            base_dir,
        );
    }
    (env, events, errors)
}

fn value_to_i64_exact(value: &Value) -> Option<i64> {
    match value {
        Value::SmallInt(n) => Some(*n),
        Value::Float(n) if n.fract() == 0.0 => Some(*n as i64),
        _ => None,
    }
}

fn eval_block(
    block: &[Stmt],
    env: &mut Env,
    events: &mut Vec<RuntimeEvent>,
    errors: &mut Vec<RuntimeError>,
    call_stack: &mut Vec<Frame>,
    module_cache: &mut HashMap<String, Vec<Stmt>>,
    loading: &mut HashSet<String>,
    current_dir: Option<&Path>,
) -> Control {
    if should_halt(errors) {
        return Control::None;
    }
    for stmt in block {
        if should_halt(errors) {
            return Control::None;
        }
        let control = eval_stmt(
            stmt,
            env,
            events,
            errors,
            call_stack,
            module_cache,
            loading,
            current_dir,
        );
        // If any control flow statement is encountered, stop the block execution
        // and propagate the control signal up.
        if !matches!(control, Control::None) {
            return control;
        }
    }
    Control::None
}

fn eval_stmt(
    stmt: &Stmt,
    env: &mut Env,
    events: &mut Vec<RuntimeEvent>,
    errors: &mut Vec<RuntimeError>,
    call_stack: &mut Vec<Frame>,
    module_cache: &mut HashMap<String, Vec<Stmt>>,
    loading: &mut HashSet<String>,
    current_dir: Option<&Path>,
) -> Control {
    if should_halt(errors) {
        return Control::None;
    }
    match stmt {
        Stmt::Rite { body, span } => {
            env.push_scope();
            call_stack.push(Frame {
                name: "rite".into(),
                span: span.clone(),
            });
            let control = eval_block(
                body,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            call_stack.pop();
            env.pop_scope();
            // A rite block is a boundary. It traps loop control flow.
            match control {
                Control::Return(v) => Control::Return(v),
                Control::None => Control::None,
                Control::Break | Control::Continue => {
                    push_error(
                        errors,
                        "'break' or 'continue' outside of loop.",
                        span.clone(),
                        call_stack,
                    );
                    Control::None
                }
            }
        }
        Stmt::Unsafe { body, .. } => {
            env.push_unsafe(true);
            let control = eval_block(
                body,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            env.pop_unsafe();
            control
        }
        Stmt::FnDef {
            name,
            params,
            body,
            span,
            ..
        } => {
            env.define_fn(
                name,
                params.iter().map(|p| p.name.clone()).collect(),
                body.clone(),
                span.clone(),
            );
            Control::None
        }
        Stmt::Assign { name, expr, .. } => {
            let val = eval_expr(
                expr,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            env.set(name, val);
            events.push(RuntimeEvent::Log(format!("set {}", name)));
            Control::None
        }
        Stmt::Expr { expr, .. } => {
            let _ = eval_expr(
                expr,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            Control::None
        }
        Stmt::If {
            cond,
            then_block,
            else_block,
            ..
        } => {
            let c = eval_expr(
                cond,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            if c.truthy() {
                eval_block(
                    then_block,
                    env,
                    events,
                    errors,
                    call_stack,
                    module_cache,
                    loading,
                    current_dir,
                )
            } else {
                eval_block(
                    else_block,
                    env,
                    events,
                    errors,
                    call_stack,
                    module_cache,
                    loading,
                    current_dir,
                )
            }
        }
        Stmt::Loop { count, body, span } => {
            let n_val = eval_expr(
                count,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            let times = match coerce_non_negative_int(
                &n_val,
                "Loop count must be a non-negative integer.",
                span.clone(),
                errors,
                call_stack,
            ) {
                Some(v) => v,
                None => return Control::None,
            };
            for _ in 0..times {
                if should_halt(errors) {
                    break;
                }
                let control = eval_block(
                    body,
                    env,
                    events,
                    errors,
                    call_stack,
                    module_cache,
                    loading,
                    current_dir,
                );
                match control {
                    Control::Continue => continue,
                    Control::Break => break,
                    Control::Return(v) => return Control::Return(v),
                    Control::None => {}
                }
            }
            Control::None
        }
        Stmt::Each {
            var,
            iter,
            body,
            span,
        } => {
            let it = eval_expr(
                iter,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            if let Value::RcObj(rc) = it {
                if let NauxObj::List(items) = rc.as_ref() {
                    for v in items.borrow().iter() {
                        env.push_scope();
                        env.set(var, v.clone());
                        let control = eval_block(
                            body,
                            env,
                            events,
                            errors,
                            call_stack,
                            module_cache,
                            loading,
                            current_dir,
                        );
                        env.pop_scope();
                        match control {
                            Control::Continue => continue,
                            Control::Break => break,
                            Control::Return(v) => return Control::Return(v),
                            Control::None => {}
                        }
                    }
                    return Control::None;
                }
            }
            push_error(
                errors,
                "Each expects a list to iterate",
                span.clone(),
                call_stack,
            );
            Control::None
        }
        Stmt::While { cond, body, .. } => {
            loop {
                let c = eval_expr(
                    cond,
                    env,
                    events,
                    errors,
                    call_stack,
                    module_cache,
                    loading,
                    current_dir,
                );
                if !c.truthy() {
                    break;
                }
                let control = eval_block(
                    body,
                    env,
                    events,
                    errors,
                    call_stack,
                    module_cache,
                    loading,
                    current_dir,
                );
                match control {
                    Control::Continue => continue,
                    Control::Break => break,
                    Control::Return(v) => return Control::Return(v),
                    Control::None => {}
                }
            }
            Control::None
        }
        Stmt::Action { action, .. } => {
            dispatch_action(
                action,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            Control::None
        }
        Stmt::Return { value, .. } => {
            let v = value
                .as_ref()
                .map(|e| {
                    eval_expr(
                        e,
                        env,
                        events,
                        errors,
                        call_stack,
                        module_cache,
                        loading,
                        current_dir,
                    )
                })
                .unwrap_or(Value::Null);
            Control::Return(v)
        }
        Stmt::Import { module, span } => {
            eval_import(
                module,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
                span.clone(),
            );
            Control::None
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn call_function(
    callee: &Expr,
    args: &[Expr],
    env: &mut Env,
    events: &mut Vec<RuntimeEvent>,
    errors: &mut Vec<RuntimeError>,
    call_stack: &mut Vec<Frame>,
    module_cache: &mut HashMap<String, Vec<Stmt>>,
    loading: &mut HashSet<String>,
    current_dir: Option<&Path>,
    expr_span: Option<crate::ast::Span>,
) -> Value {
    // For now, we only support calling functions by name.
    // To support first-class functions, we would first evaluate the callee:
    // `let callee_val = eval_expr(callee, ...);`
    // Then we would match on `callee_val` to see if it's a callable value
    // (e.g. a new `Value::Fn` variant).
    let name = if let ExprKind::Var(n) = &callee.kind {
        n.clone()
    } else {
        push_error(
            errors,
            "Invalid call target. Only direct function calls are supported.",
            callee.span.clone(),
            call_stack,
        );
        return Value::Null;
    };

    if should_halt(errors) {
        return Value::Null;
    }

    let evaled_args: Vec<Value> = args
        .iter()
        .map(|a| {
            eval_expr(
                a,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            )
        })
        .collect();

    // Look for user-defined function
    if let Some(fn_def) = env.get_fn(&name) {
        let fn_span = fn_def.span.clone();
        if evaled_args.len() != fn_def.params.len() {
            push_error(
                errors,
                format!(
                    "Function {} expects {} args but got {}",
                    name,
                    fn_def.params.len(),
                    evaled_args.len()
                ),
                expr_span.clone().or(fn_span.clone()),
                call_stack,
            );
            return Value::Null;
        }
        call_stack.push(Frame {
            name: name.clone(),
            span: expr_span.clone().or(fn_span.clone()),
        });
        env.push_scope();
        for (i, param) in fn_def.params.iter().enumerate() {
            let v = evaled_args.get(i).cloned().unwrap_or(Value::Null);
            env.set(param, v);
        }
        let control = eval_block(
            &fn_def.body,
            env,
            events,
            errors,
            call_stack,
            module_cache,
            loading,
            current_dir,
        );
        env.pop_scope();
        call_stack.pop();

        // Unwrap the return value from the Control enum.
        // A function that finishes without a return statement implicitly returns null.
        return match control {
            Control::Return(v) => v,
            Control::None => Value::Null,
            Control::Break | Control::Continue => {
                push_error(
                    errors,
                    "'break' or 'continue' used outside of a loop.",
                    fn_span,
                    call_stack,
                );
                Value::Null
            }
        };
    }

    // Look for built-in function
    if let Some(res) = env.call_builtin(&name, evaled_args) {
        return match res {
            Ok(v) => v,
            Err(mut e) => {
                e.trace = call_stack.clone();
                if should_halt(errors) {
                    return Value::Null;
                }
                errors.push(e);
                Value::Null
            }
        };
    }

    push_error(
        errors,
        format!("Function not found: {}", name),
        expr_span,
        call_stack,
    );
    Value::Null
}

fn eval_expr(
    expr: &Expr,
    env: &mut Env,
    events: &mut Vec<RuntimeEvent>,
    errors: &mut Vec<RuntimeError>,
    call_stack: &mut Vec<Frame>,
    module_cache: &mut HashMap<String, Vec<Stmt>>,
    loading: &mut HashSet<String>,
    current_dir: Option<&Path>,
) -> Value {
    if should_halt(errors) {
        return Value::Null;
    }
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
        ExprKind::Bytes(bytes) => Value::make_bytes(bytes.clone()),
        ExprKind::List(items) => Value::make_list(
            items
                .iter()
                .map(|e| {
                    eval_expr(
                        e,
                        env,
                        events,
                        errors,
                        call_stack,
                        module_cache,
                        loading,
                        current_dir,
                    )
                })
                .collect(),
        ),
        ExprKind::Map(entries) => {
            let mut m = HashMap::new();
            for (k, v) in entries {
                m.insert(
                    k.clone(),
                    eval_expr(
                        v,
                        env,
                        events,
                        errors,
                        call_stack,
                        module_cache,
                        loading,
                        current_dir,
                    ),
                );
            }
            Value::make_map(m)
        }
        ExprKind::Var(name) => match env.get(name) {
            Some(v) => v,
            None => {
                push_error(
                    errors,
                    format!("Variable not found: {}", name),
                    expr.span.clone(),
                    call_stack,
                );
                Value::Null
            }
        },
        ExprKind::Call { callee, args } => call_function(
            callee,
            args,
            env,
            events,
            errors,
            call_stack,
            module_cache,
            loading,
            current_dir,
            expr.span.clone(),
        ),
        ExprKind::Binary { op, left, right } => match op {
            BinaryOp::And => {
                let l = eval_expr(
                    left,
                    env,
                    events,
                    errors,
                    call_stack,
                    module_cache,
                    loading,
                    current_dir,
                );
                if !l.truthy() {
                    Value::Bool(false)
                } else {
                    let r = eval_expr(
                        right,
                        env,
                        events,
                        errors,
                        call_stack,
                        module_cache,
                        loading,
                        current_dir,
                    );
                    Value::Bool(r.truthy())
                }
            }
            BinaryOp::Or => {
                let l = eval_expr(
                    left,
                    env,
                    events,
                    errors,
                    call_stack,
                    module_cache,
                    loading,
                    current_dir,
                );
                if l.truthy() {
                    Value::Bool(true)
                } else {
                    let r = eval_expr(
                        right,
                        env,
                        events,
                        errors,
                        call_stack,
                        module_cache,
                        loading,
                        current_dir,
                    );
                    Value::Bool(r.truthy())
                }
            }
            _ => {
                let l = eval_expr(
                    left,
                    env,
                    events,
                    errors,
                    call_stack,
                    module_cache,
                    loading,
                    current_dir,
                );
                let r = eval_expr(
                    right,
                    env,
                    events,
                    errors,
                    call_stack,
                    module_cache,
                    loading,
                    current_dir,
                );
                match op {
                    BinaryOp::Add => match (&l, &r) {
                        (Value::RcObj(a), Value::RcObj(b)) => match (a.as_ref(), b.as_ref()) {
                            (NauxObj::Text(la), NauxObj::Text(lb)) => {
                                Value::make_text(format!("{}{}", la, lb))
                            }
                            _ => Value::add(&l, &r),
                        },
                        _ => Value::add(&l, &r),
                    },
                    BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => {
                        let a = l.as_f64();
                        let b = r.as_f64();
                        match (a, b) {
                            (_, Some(0.0)) if matches!(op, BinaryOp::Div | BinaryOp::Mod) => {
                                let message = if matches!(op, BinaryOp::Div) {
                                    "Division by zero"
                                } else {
                                    "Modulo by zero"
                                };
                                push_error(errors, message, expr.span.clone(), call_stack);
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
                                push_error(
                                    errors,
                                    "Type error in binary expression",
                                    expr.span.clone(),
                                    call_stack,
                                );
                                Value::Null
                            }
                        }
                    }
                    BinaryOp::Xor | BinaryOp::Shl => {
                        let a = value_to_i64_exact(&l);
                        let b = value_to_i64_exact(&r);
                        match (a, b) {
                            (Some(_), Some(y)) if matches!(op, BinaryOp::Shl) && y < 0 => {
                                push_error(
                                    errors,
                                    "Shift count must be non-negative",
                                    expr.span.clone(),
                                    call_stack,
                                );
                                Value::Null
                            }
                            (Some(x), Some(y)) if matches!(op, BinaryOp::Shl) => {
                                Value::SmallInt(x << (y as u32))
                            }
                            (Some(x), Some(y)) => Value::SmallInt(x ^ y),
                            _ => {
                                push_error(
                                    errors,
                                    "Bitwise operators require integer-compatible numbers",
                                    expr.span.clone(),
                                    call_stack,
                                );
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
                                push_error(
                                    errors,
                                    "Type error in binary expression",
                                    expr.span.clone(),
                                    call_stack,
                                );
                                Value::Null
                            }
                        }
                    }
                    _ => unreachable!(), // And, Or are handled above
                }
            }
        },
        ExprKind::Unary { op, expr: inner } => {
            let v = eval_expr(
                inner,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            match (op, v) {
                (UnaryOp::Neg, Value::SmallInt(n)) => Value::SmallInt(-n),
                (UnaryOp::Neg, Value::Float(n)) => Value::Float(-n),
                (UnaryOp::Not, val) => Value::Bool(!val.truthy()),
                _ => {
                    push_error(
                        errors,
                        "Type error in unary expression",
                        expr.span.clone(),
                        call_stack,
                    );
                    Value::Null
                }
            }
        }
        ExprKind::Index { target, index } => {
            let t = eval_expr(
                target,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            let idxv = eval_expr(
                index,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            match (t, idxv) {
                (Value::RcObj(rc), Value::RcObj(krc)) => match (rc.as_ref(), krc.as_ref()) {
                    (NauxObj::Map(map), NauxObj::Text(key)) => {
                        map.borrow().get(key).cloned().unwrap_or(Value::Null)
                    }
                    _ => {
                        push_error(
                            errors,
                            "Invalid index operation",
                            expr.span.clone(),
                            call_stack,
                        );
                        Value::Null
                    }
                },
                (Value::RcObj(rc), idx_val) => {
                    let idx_opt = match idx_val {
                        Value::SmallInt(n) => {
                            if n < 0 {
                                push_error(
                                    errors,
                                    "Index cannot be negative.",
                                    expr.span.clone(),
                                    call_stack,
                                );
                                None
                            } else {
                                Some(n as usize)
                            }
                        }
                        Value::Float(n) => {
                            if n.fract() != 0.0 || n < 0.0 {
                                push_error(
                                    errors,
                                    "Index must be a non-negative integer.",
                                    expr.span.clone(),
                                    call_stack,
                                );
                                None
                            } else {
                                Some(n as usize)
                            }
                        }
                        _ => {
                            push_error(
                                errors,
                                "Index must be an integer.",
                                expr.span.clone(),
                                call_stack,
                            );
                            None
                        }
                    };
                    if let Some(idx) = idx_opt {
                        match rc.as_ref() {
                            NauxObj::List(list) => {
                                list.borrow().get(idx).cloned().unwrap_or(Value::Null)
                            }
                            NauxObj::Bytes(bytes) => bytes
                                .borrow()
                                .get(idx)
                                .map(|b| Value::SmallInt(*b as i64))
                                .unwrap_or(Value::Null),
                            _ => {
                                push_error(
                                    errors,
                                    "Invalid index operation",
                                    expr.span.clone(),
                                    call_stack,
                                );
                                Value::Null
                            }
                        }
                    } else {
                        Value::Null
                    }
                }
                _ => {
                    push_error(
                        errors,
                        "Invalid index operation",
                        expr.span.clone(),
                        call_stack,
                    );
                    Value::Null
                }
            }
        }
        ExprKind::Field { target, field } => {
            let t = eval_expr(
                target,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            match t {
                Value::RcObj(rc) => match rc.as_ref() {
                    NauxObj::Map(m) => m.borrow().get(field).cloned().unwrap_or(Value::Null),
                    _ => {
                        push_error(
                            errors,
                            "Invalid field access",
                            expr.span.clone(),
                            call_stack,
                        );
                        Value::Null
                    }
                },
                _ => {
                    push_error(
                        errors,
                        "Invalid field access",
                        expr.span.clone(),
                        call_stack,
                    );
                    Value::Null
                }
            }
        }
        ExprKind::Fn(_) => {
            push_error(
                errors,
                "Inline function expressions are not supported in runtime yet.",
                expr.span.clone(),
                call_stack,
            );
            Value::Null
        }
    }
}

fn dispatch_action(
    action: &ActionKind,
    env: &mut Env,
    events: &mut Vec<RuntimeEvent>,
    errors: &mut Vec<RuntimeError>,
    call_stack: &mut Vec<Frame>,
    module_cache: &mut HashMap<String, Vec<Stmt>>,
    loading: &mut HashSet<String>,
    current_dir: Option<&Path>,
) {
    if should_halt(errors) {
        return;
    }
    match action {
        ActionKind::Say { value } => {
            let v = eval_expr(
                value,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            events.push(RuntimeEvent::Say(format_value(&v)));
        }
        ActionKind::Ask { prompt } => {
            let p = eval_expr(
                prompt,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            let p_str = format_value(&p);
            events.push(RuntimeEvent::Ask {
                prompt: p_str.clone(),
                answer: String::new(),
            });
            let ans = query_ask(&p_str);
            events.push(RuntimeEvent::Ask {
                prompt: p_str,
                answer: ans.clone(),
            });
        }
        ActionKind::Fetch { target } => {
            let t = eval_expr(
                target,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            events.push(RuntimeEvent::Fetch {
                target: format_value(&t),
            });
        }
        ActionKind::Syscall { number, args, out } => {
            if !env.is_unsafe() {
                push_error(
                    errors,
                    "!syscall is only allowed inside `~ unsafe ... ~ end`",
                    number.span.clone(),
                    call_stack,
                );
                return;
            }

            let mut call_args = Vec::with_capacity(args.len() + 1);
            let nr = eval_expr(
                number,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            call_args.push(nr);
            for arg in args {
                call_args.push(eval_expr(
                    arg,
                    env,
                    events,
                    errors,
                    call_stack,
                    module_cache,
                    loading,
                    current_dir,
                ));
            }

            match env.call_builtin("__syscall", call_args) {
                Some(Ok(value)) => {
                    if let Some(name) = out {
                        env.set(name, value.clone());
                        events.push(RuntimeEvent::Log(format!("set {}", name)));
                    }
                }
                Some(Err(mut err)) => {
                    err.trace = call_stack.clone();
                    if !should_halt(errors) {
                        errors.push(err);
                    }
                }
                None => {
                    push_error(
                        errors,
                        "Builtin `__syscall` is not registered",
                        number.span.clone(),
                        call_stack,
                    );
                }
            }
        }
        ActionKind::Ui { kind, .. } => {
            events.push(RuntimeEvent::Ui {
                kind: kind.clone(),
                props: Vec::new(),
            });
        }
        ActionKind::Text { value } => {
            let v = eval_expr(
                value,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            events.push(RuntimeEvent::Text(format_value(&v)));
        }
        ActionKind::Button { value } => {
            let v = eval_expr(
                value,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            events.push(RuntimeEvent::Button(format_value(&v)));
        }
        ActionKind::Log { value } => {
            let v = eval_expr(
                value,
                env,
                events,
                errors,
                call_stack,
                module_cache,
                loading,
                current_dir,
            );
            events.push(RuntimeEvent::Log(format_value(&v)));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn eval_import(
    module: &str,
    env: &mut Env,
    events: &mut Vec<RuntimeEvent>,
    errors: &mut Vec<RuntimeError>,
    call_stack: &mut Vec<Frame>,
    module_cache: &mut HashMap<String, Vec<Stmt>>,
    loading: &mut HashSet<String>,
    current_dir: Option<&Path>,
    span: Option<crate::ast::Span>,
) {
    if should_halt(errors) {
        return;
    }
    let import_path = resolve_import_path(module, current_dir);
    let cache_key = module_cache_key(&import_path);

    if module_cache.contains_key(&cache_key) {
        return;
    }
    if !loading.insert(cache_key.clone()) {
        push_error(
            errors,
            format!("Cyclic import detected: {}", module),
            span,
            call_stack,
        );
        return;
    }

    let src = match fs::read_to_string(&import_path) {
        Ok(src) => src,
        Err(err) => {
            push_error(
                errors,
                format!("Failed to import {}: {}", import_path.display(), err),
                span,
                call_stack,
            );
            loading.remove(&cache_key);
            return;
        }
    };

    let tokens = match lex(&src) {
        Ok(t) => t,
        Err(e) => {
            push_error(
                errors,
                format!(
                    "Lex error in import {}: {}",
                    import_path.display(),
                    e.message
                ),
                Some(e.span),
                call_stack,
            );
            loading.remove(&cache_key);
            return;
        }
    };

    let mut parser = Parser::new(tokens);
    match parser.parse_script() {
        Ok(ast) => {
            module_cache.insert(cache_key.clone(), ast.clone());
            let imported_dir = import_path.parent();
            for stmt in &ast {
                if should_halt(errors) {
                    break;
                }
                eval_stmt(
                    stmt,
                    env,
                    events,
                    errors,
                    call_stack,
                    module_cache,
                    loading,
                    imported_dir,
                );
            }
        }
        Err(e) => {
            let filename = import_path.to_string_lossy();
            let msg = format_parse_error(&src, &e, &filename);
            push_error(errors, msg, e.span.into(), call_stack);
        }
    }
    loading.remove(&cache_key);
}

fn resolve_import_path(module: &str, current_dir: Option<&Path>) -> PathBuf {
    let module_path = Path::new(module);
    if module_path.is_absolute() {
        module_path.to_path_buf()
    } else if let Some(base) = current_dir {
        base.join(module_path)
    } else {
        module_path.to_path_buf()
    }
}

fn module_cache_key(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn format_value(v: &Value) -> String {
    v.to_display_text()
}

fn push_error(
    errors: &mut Vec<RuntimeError>,
    msg: impl Into<String>,
    span: Option<crate::ast::Span>,
    call_stack: &[Frame],
) {
    if should_halt(errors) {
        return;
    }
    errors.push(RuntimeError::with_trace(msg, span, call_stack.to_owned()));
}

fn should_halt(errors: &[RuntimeError]) -> bool {
    !errors.is_empty() || errors.len() >= MAX_ERRORS
}

fn coerce_non_negative_int(
    v: &Value,
    msg: &str,
    span: Option<crate::ast::Span>,
    errors: &mut Vec<RuntimeError>,
    call_stack: &[Frame],
) -> Option<i64> {
    match v {
        Value::SmallInt(n) if *n >= 0 => Some(*n),
        Value::Float(f) if f.fract() == 0.0 && *f >= 0.0 && *f <= i64::MAX as f64 => {
            Some(*f as i64)
        }
        _ => {
            push_error(errors, msg, span, call_stack);
            None
        }
    }
}
