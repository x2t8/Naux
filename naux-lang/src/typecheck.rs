use std::collections::HashMap;

use crate::ast::{ActionKind, BinaryOp, Expr, ExprKind, Span, Stmt, UnaryOp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    Num,
    Bool,
    Text,
    Bytes,
    List(Box<Type>),
    Map(Box<Type>),
    Function { params: usize },
    Null,
    Any,
}

#[derive(Debug, Clone)]
pub struct TypeError {
    pub message: String,
    pub span: Option<Span>,
}

type Env = HashMap<String, Type>;
type FnTable = HashMap<String, usize>;

pub fn check_program(stmts: &[Stmt]) -> Result<(), TypeError> {
    // Thu thập chữ ký fn trước để cho phép gọi chéo/đệ quy.
    let mut fns: FnTable = HashMap::new();
    for stmt in stmts {
        if let Stmt::FnDef { name, params, .. } = stmt {
            fns.insert(name.clone(), params.len());
        }
    }

    let mut env: Env = HashMap::new();
    for stmt in stmts {
        check_stmt(stmt, &mut env, &mut fns)?;
    }
    Ok(())
}

fn check_stmt(stmt: &Stmt, env: &mut Env, fns: &mut FnTable) -> Result<(), TypeError> {
    match stmt {
        Stmt::FnDef {
            name,
            params,
            body,
            ..
        } => {
            // Đăng ký fn (nếu chưa có) và typecheck thân với env mới.
            fns.insert(name.clone(), params.len());
            let mut local_env = Env::new();
            for p in params {
                local_env.insert(p.name.clone(), Type::Any);
            }
            let mut inner_fns = fns.clone();
            for s in body {
                check_stmt(s, &mut local_env, &mut inner_fns)?;
            }
            Ok(())
        }
        Stmt::Assign {
            name,
            expr,
            ..
        } => {
            let ty = check_expr(expr, env, fns)?;
            env.insert(name.clone(), ty);
            Ok(())
        }
        Stmt::Expr { expr, span: _ } => {
            let _ = check_expr(expr, env, fns)?;
            Ok(())
        }
        Stmt::If {
            cond,
            then_block,
            else_block,
            span: _,
        } => {
            let cond_ty = check_expr(cond, env, fns)?;
            require_bool(&cond_ty, cond.span())?;
            let mut env_then = env.clone();
            for s in then_block {
                check_stmt(s, &mut env_then, &mut fns.clone())?;
            }
            let mut env_else = env.clone();
            for s in else_block {
                check_stmt(s, &mut env_else, &mut fns.clone())?;
            }
            Ok(())
        }
        Stmt::Loop {
            count,
            body,
            span: _,
        } => {
            let count_ty = check_expr(count, env, fns)?;
            require_num(&count_ty, count.span())?;
            let mut env_body = env.clone();
            for s in body {
                check_stmt(s, &mut env_body, &mut fns.clone())?;
            }
            Ok(())
        }
        Stmt::Each {
            var,
            iter,
            body,
            span: _,
        } => {
            let iter_ty = check_expr(iter, env, fns)?;
            let elem_ty = match iter_ty {
                Type::List(inner) => (*inner).clone(),
                Type::Map(inner) => (*inner).clone(),
                Type::Bytes => Type::Num,
                Type::Any => Type::Any,
                _ => {
                    return Err(TypeError {
                        message: format!("Expected iterable (list/map/bytes), got {:?}", iter_ty),
                        span: iter.span(),
                    })
                }
            };
            let mut env_body = env.clone();
            env_body.insert(var.clone(), elem_ty);
            for s in body {
                check_stmt(s, &mut env_body, &mut fns.clone())?;
            }
            Ok(())
        }
        Stmt::While {
            cond,
            body,
            span: _,
        } => {
            let cond_ty = check_expr(cond, env, fns)?;
            require_bool(&cond_ty, cond.span())?;
            let mut env_body = env.clone();
            for s in body {
                check_stmt(s, &mut env_body, &mut fns.clone())?;
            }
            Ok(())
        }
        Stmt::Action { action, span: _ } => {
            match action {
                ActionKind::Say { value }
                | ActionKind::Text { value }
                | ActionKind::Button { value }
                | ActionKind::Log { value } => {
                    let _ = check_expr(value, env, fns)?;
                }
                ActionKind::Ask { prompt } => {
                    let _ = check_expr(prompt, env, fns)?;
                }
                ActionKind::Fetch { target } => {
                    let _ = check_expr(target, env, fns)?;
                }
                ActionKind::Ui { props, .. } => {
                    for (_, value) in props {
                        let _ = check_expr(value, env, fns)?;
                    }
                }
                ActionKind::Syscall { number, args, out } => {
                    let nr_ty = check_expr(number, env, fns)?;
                    require_num(&nr_ty, number.span())?;
                    if args.len() > 6 {
                        return Err(TypeError {
                            message: "!syscall supports at most 6 arguments".into(),
                            span: number.span(),
                        });
                    }
                    for arg in args {
                        let arg_ty = check_expr(arg, env, fns)?;
                        require_num(&arg_ty, arg.span())?;
                    }
                    if let Some(name) = out {
                        env.insert(name.clone(), Type::Num);
                    }
                }
            }
            Ok(())
        }
        Stmt::Return { value, span: _ } => {
            if let Some(e) = value {
                let _ = check_expr(e, env, fns)?;
            }
            Ok(())
        }
        Stmt::Import { .. } => Ok(()),
        Stmt::Rite { body, .. } | Stmt::Unsafe { body, .. } => {
            for s in body {
                check_stmt(s, env, fns)?;
            }
            Ok(())
        }
    }
}

fn check_expr(expr: &Expr, env: &Env, fns: &FnTable) -> Result<Type, TypeError> {
    match &expr.kind {
        ExprKind::Number(_) => Ok(Type::Num),
        ExprKind::Bool(_) => Ok(Type::Bool),
        ExprKind::Text(_) => Ok(Type::Text),
        ExprKind::Bytes(_) => Ok(Type::Bytes),
        ExprKind::List(items) => {
            let mut elem_ty: Option<Type> = None;
            for it in items {
                let ty = check_expr(it, env, fns)?;
                elem_ty = Some(unify(elem_ty.clone().unwrap_or(Type::Any), ty));
            }
            Ok(Type::List(Box::new(elem_ty.unwrap_or(Type::Any))))
        }
        ExprKind::Map(entries) => {
            let mut val_ty: Option<Type> = None;
            for (_k, v) in entries {
                let ty = check_expr(v, env, fns)?;
                val_ty = Some(unify(val_ty.clone().unwrap_or(Type::Any), ty));
            }
            Ok(Type::Map(Box::new(val_ty.unwrap_or(Type::Any))))
        }
        ExprKind::Var(name) => env
            .get(name)
            .cloned()
            .or_else(|| fns.get(name).map(|n| Type::Function { params: *n }))
            .or_else(|| builtin_ret_type(name, &[]).ok())
            .ok_or(TypeError {
                message: format!("Unbound variable `{}`", name),
                span: expr.span(),
            }),
        ExprKind::Call { callee, args } => {
            let mut arg_tys = Vec::new();
            for a in args {
                arg_tys.push(check_expr(a, env, fns)?);
            }

            // 1. Xử lý trường hợp Var đặc biệt (để hỗ trợ builtins chưa có trong env/fns)
            if let ExprKind::Var(name) = &callee.kind {
                let lookup = env
                    .get(name)
                    .cloned()
                    .or_else(|| fns.get(name).map(|n| Type::Function { params: *n }));

                if let Some(ty) = lookup {
                    match ty {
                        Type::Function { params } => {
                            if params != args.len() {
                                return Err(TypeError {
                                    message: format!(
                                        "Function `{}` expects {} args, got {}",
                                        name,
                                        params,
                                        args.len()
                                    ),
                                    span: callee.span(),
                                });
                            }
                            return Ok(Type::Any);
                        }
                        Type::Any => return Ok(Type::Any),
                        _ => {
                            return Err(TypeError {
                                message: format!(
                                    "Value `{}` of type {:?} is not callable",
                                    name, ty
                                ),
                                span: callee.span(),
                            })
                        }
                    }
                } else {
                    // Không tìm thấy trong env/fns, thử builtin (fallback).
                    // Nếu vẫn không có, chấp nhận như call động (Type::Any).
                    return match builtin_ret_type(name, &arg_tys) {
                        Ok(ty) => Ok(ty),
                        Err(_) => Ok(Type::Any),
                    };
                }
            }

            // 2. Xử lý biểu thức tổng quát (First-class functions, closures)
            let callee_ty = check_expr(callee, env, fns)?;
            match callee_ty {
                Type::Function { params } => {
                    if params != args.len() {
                        return Err(TypeError {
                            message: format!(
                                "Function expects {} args, got {}",
                                params,
                                args.len()
                            ),
                            span: callee.span(),
                        });
                    }
                    Ok(Type::Any)
                }
                Type::Any => Ok(Type::Any),
                _ => Err(TypeError {
                    message: format!("Type {:?} is not callable", callee_ty),
                    span: callee.span(),
                }),
            }
        }
        ExprKind::Binary { op, left, right } => {
            let l = check_expr(left, env, fns)?;
            let r = check_expr(right, env, fns)?;
            match op {
                BinaryOp::Add => check_add_type(&l, &r, left.span(), right.span()),
                BinaryOp::Sub
                | BinaryOp::Mul
                | BinaryOp::Div
                | BinaryOp::Mod
                | BinaryOp::Xor
                | BinaryOp::Shl => {
                    require_num(&l, left.span())?;
                    require_num(&r, right.span())?;
                    Ok(Type::Num)
                }
                BinaryOp::Eq
                | BinaryOp::Ne
                | BinaryOp::Gt
                | BinaryOp::Ge
                | BinaryOp::Lt
                | BinaryOp::Le => {
                    require_num(&l, left.span())?;
                    require_num(&r, right.span())?;
                    Ok(Type::Bool)
                }
                BinaryOp::And | BinaryOp::Or => {
                    require_bool(&l, left.span())?;
                    require_bool(&r, right.span())?;
                    Ok(Type::Bool)
                }
            }
        }
        ExprKind::Unary { op, expr: e } => {
            let t = check_expr(e, env, fns)?;
            match op {
                UnaryOp::Neg => {
                    require_num(&t, e.span())?;
                    Ok(Type::Num)
                }
                UnaryOp::Not => {
                    require_bool(&t, e.span())?;
                    Ok(Type::Bool)
                }
            }
        }
        ExprKind::Index { target, index } => {
            let tgt_ty = check_expr(target, env, fns)?;
            let _idx_ty = check_expr(index, env, fns)?;
            match tgt_ty {
                Type::List(inner) => Ok(*inner),
                Type::Map(inner) => Ok(*inner),
                Type::Bytes => Ok(Type::Num),
                Type::Any => Ok(Type::Any),
                other => Err(TypeError {
                    message: format!("Indexing requires list/map/bytes, got {:?}", other),
                    span: target.span(),
                }),
            }
        }
        ExprKind::Field { target, field: _ } => {
            let tgt_ty = check_expr(target, env, fns)?;
            match tgt_ty {
                Type::Map(inner) => Ok(*inner),
                Type::Any => Ok(Type::Any),
                other => Err(TypeError {
                    message: format!("Field access requires map, got {:?}", other),
                    span: target.span(),
                }),
            }
        }
        ExprKind::Fn(func) => {
            let mut local_env = env.clone();
            for p in &func.params {
                local_env.insert(p.name.clone(), Type::Any);
            }
            let mut inner_fns = fns.clone();
            for s in &func.body {
                check_stmt(s, &mut local_env, &mut inner_fns)?;
            }
            Ok(Type::Function {
                params: func.params.len(),
            })
        }
    }
}

fn check_add_type(
    lhs: &Type,
    rhs: &Type,
    lhs_span: Option<Span>,
    rhs_span: Option<Span>,
) -> Result<Type, TypeError> {
    match (lhs, rhs) {
        (Type::Text, _) | (_, Type::Text) => Ok(Type::Text),
        (Type::Any, _) | (_, Type::Any) => Ok(Type::Any),
        _ => {
            require_num(lhs, lhs_span)?;
            require_num(rhs, rhs_span)?;
            Ok(Type::Num)
        }
    }
}

fn unify(a: Type, b: Type) -> Type {
    if a == b {
        a
    } else {
        Type::Any
    }
}

fn require_num(ty: &Type, span: Option<Span>) -> Result<(), TypeError> {
    match ty {
        Type::Num | Type::Any => Ok(()),
        other => Err(TypeError {
            message: format!("Expected number, got {:?}", other),
            span,
        }),
    }
}

fn require_bool(ty: &Type, span: Option<Span>) -> Result<(), TypeError> {
    match ty {
        Type::Bool | Type::Any => Ok(()),
        other => Err(TypeError {
            message: format!("Expected bool, got {:?}", other),
            span,
        }),
    }
}

trait SpanOf {
    fn span(&self) -> Option<Span>;
}

impl SpanOf for Expr {
    fn span(&self) -> Option<Span> {
        self.span.clone()
    }
}

fn builtin_ret_type(name: &str, args: &[Type]) -> Result<Type, String> {
    match name {
        "len" => {
            if args.len() == 1 {
                Ok(Type::Num)
            } else {
                Err(format!("`len` expects 1 arg, got {}", args.len()))
            }
        }
        "to_text" => {
            if args.len() == 1 {
                Ok(Type::Text)
            } else {
                Err(format!("`to_text` expects 1 arg, got {}", args.len()))
            }
        }
        "__index" => {
            if args.len() == 2 {
                Ok(Type::Any)
            } else {
                Err(format!("`__index` expects 2 args, got {}", args.len()))
            }
        }
        "__setindex" => {
            if args.len() == 3 {
                Ok(Type::Any)
            } else {
                Err(format!("`__setindex` expects 3 args, got {}", args.len()))
            }
        }
        "__bytes" => {
            if args.len() == 1 {
                Ok(Type::Bytes)
            } else {
                Err(format!("`__bytes` expects 1 arg, got {}", args.len()))
            }
        }
        "__syscall" => {
            if (1..=7).contains(&args.len()) {
                Ok(Type::Num)
            } else {
                Err(format!(
                    "`__syscall` expects 1..=7 args (nr + up to 6 args), got {}",
                    args.len()
                ))
            }
        }
        "__bit_xor" => {
            if args.len() == 2 {
                Ok(Type::Num)
            } else {
                Err(format!("`__bit_xor` expects 2 args, got {}", args.len()))
            }
        }
        "__bit_shl" => {
            if args.len() == 2 {
                Ok(Type::Num)
            } else {
                Err(format!("`__bit_shl` expects 2 args, got {}", args.len()))
            }
        }
        "list_range" => {
            if args.len() == 1 {
                Ok(Type::List(Box::new(Type::Num)))
            } else {
                Err(format!("`list_range` expects 1 arg, got {}", args.len()))
            }
        }
        "__call" => Ok(Type::Any),
        _ => Err(format!("Unknown function `{}`", name)),
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use crate::{lexer, parser};

    fn check_ok(src: &str) -> bool {
        let tokens = lexer::lex(src).expect("lex");
        let ast = parser::parse_script(&tokens).expect("parse");
        super::check_program(&ast).is_ok()
    }

    fn check_err(src: &str) -> bool {
        let tokens = lexer::lex(src).expect("lex");
        let ast = parser::parse_script(&tokens).expect("parse");
        super::check_program(&ast).is_err()
    }

    #[test]
    fn typecheck_pass_simple_math() {
        assert!(check_ok(
            r#"
            ~ rite
                $x = 1 + 2
                $y = $x * 3
            ~ end
            "#
        ));
    }

    #[test]
    fn typecheck_fail_bool_in_add() {
        assert!(check_err(
            r#"
            ~ rite
                $x = true + 1
            ~ end
            "#
        ));
    }

    #[test]
    fn typecheck_pass_text_number_add_concat() {
        assert!(check_ok(
            r#"
            ~ rite
                $ans = 42
                !say "Result = " + $ans
            ~ end
            "#
        ));
    }

    #[test]
    fn typecheck_pass_bytes_literal_and_index() {
        assert!(check_ok(
            r#"
            ~ rite
                $buf = <bytes:DE AD BE EF>
                $x = $buf[0]
            ~ end
            "#
        ));
    }
}
