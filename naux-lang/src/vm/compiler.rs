// TODO: compiler to bytecode
#![allow(dead_code)]

use std::collections::HashMap;

use crate::ast::{BinaryOp, Expr, Stmt, UnaryOp};
use crate::vm::bytecode::{Bytecode, FunctionBytecode, Instr, Program};

/// Compile a script (list of statements) to bytecode (skeleton).
pub fn compile_script(stmts: &[Stmt]) -> Program {
    let mut main = Bytecode::new();
    let mut functions: HashMap<String, FunctionBytecode> = HashMap::new();
    for stmt in stmts {
        match stmt {
            Stmt::FnDef { name, params, body, .. } => {
                let mut fbc = Bytecode::new();
                for s in body {
                    compile_stmt(s, &mut fbc);
                }
                fbc.push(Instr::Return);
                functions.insert(
                    name.clone(),
                    FunctionBytecode {
                        params: params.clone(),
                        code: fbc,
                    },
                );
            }
            _ => compile_stmt(stmt, &mut main),
        }
    }
    main.push(Instr::Return);
    Program { main, functions }
}

fn compile_stmt(stmt: &Stmt, bc: &mut Bytecode) {
    match stmt {
        Stmt::Assign { name, expr, .. } => {
            compile_expr(expr, bc);
            bc.push(Instr::StoreVar(name.clone()));
        }
        Stmt::If { cond, then_block, else_block, .. } => {
            compile_expr(cond, bc);
            let jmp_false_pos = bc.len();
            bc.push(Instr::JumpIfFalse(0)); // patched later

            for s in then_block {
                compile_stmt(s, bc);
            }
            let jmp_end_pos = bc.len();
            bc.push(Instr::Jump(0)); // patched later

            let else_start = bc.len();
            for s in else_block {
                compile_stmt(s, bc);
            }
            let end = bc.len();
            if let Instr::JumpIfFalse(ref mut target) = bc[jmp_false_pos] {
                *target = else_start;
            }
            if let Instr::Jump(ref mut target) = bc[jmp_end_pos] {
                *target = end;
            }
        }
        Stmt::Loop { count, body, .. } => {
            // naive loop: rem = count; while rem truthy { body; rem = rem - 1 }
            let tmp = "__loop_rem__".to_string();
            compile_expr(count, bc);
            bc.push(Instr::StoreVar(tmp.clone()));
            let start = bc.len();
            bc.push(Instr::LoadVar(tmp.clone()));
            let jmp_false = bc.len();
            bc.push(Instr::JumpIfFalse(0));
            for s in body {
                compile_stmt(s, bc);
            }
            // decrement
            bc.push(Instr::LoadVar(tmp.clone()));
            bc.push(Instr::PushNum(1.0));
            bc.push(Instr::Sub);
            bc.push(Instr::StoreVar(tmp.clone()));
            bc.push(Instr::Jump(start));
            let end = bc.len();
            if let Instr::JumpIfFalse(ref mut target) = bc[jmp_false] {
                *target = end;
            }
        }
        Stmt::While { cond, body, .. } => {
            let start = bc.len();
            compile_expr(cond, bc);
            let jmp_false = bc.len();
            bc.push(Instr::JumpIfFalse(0));
            for s in body {
                compile_stmt(s, bc);
            }
            bc.push(Instr::Jump(start));
            let end = bc.len();
            if let Instr::JumpIfFalse(ref mut target) = bc[jmp_false] {
                *target = end;
            }
        }
        Stmt::Return { value, .. } => {
            compile_expr(value, bc);
            bc.push(Instr::Return);
        }
        Stmt::Action { .. } => {
            // actions not compiled; runtime handles separately
        }
        Stmt::Rite { body, .. } => {
            for s in body {
                compile_stmt(s, bc);
            }
        }
        Stmt::FnDef { .. } => {
            // functions not yet compiled into bytecode in this skeleton
        }
        Stmt::Each { var, iter, body, .. } => {
            // compile as: tmp_iter = iter; idx=0; while idx < len(tmp_iter) { var = tmp_iter[idx]; body; idx++ }
            let tmp_iter = "__each_iter__".to_string();
            let tmp_idx = "__each_idx__".to_string();
            compile_expr(iter, bc);
            bc.push(Instr::StoreVar(tmp_iter.clone()));
            bc.push(Instr::PushNum(0.0));
            bc.push(Instr::StoreVar(tmp_idx.clone()));
            let start = bc.len();
            // condition: idx < len(iter)
            bc.push(Instr::LoadVar(tmp_idx.clone()));
            bc.push(Instr::LoadVar(tmp_iter.clone()));
            bc.push(Instr::CallBuiltin("len".into(), 1));
            bc.push(Instr::Lt);
            let jmp_false = bc.len();
            bc.push(Instr::JumpIfFalse(0));
            // var = iter[idx]
            bc.push(Instr::LoadVar(tmp_iter.clone()));
            bc.push(Instr::LoadVar(tmp_idx.clone()));
            bc.push(Instr::CallBuiltin("__index".into(), 2));
            bc.push(Instr::StoreVar(var.clone()));
            for s in body {
                compile_stmt(s, bc);
            }
            // idx++
            bc.push(Instr::LoadVar(tmp_idx.clone()));
            bc.push(Instr::PushNum(1.0));
            bc.push(Instr::Add);
            bc.push(Instr::StoreVar(tmp_idx.clone()));
            bc.push(Instr::Jump(start));
            let end = bc.len();
            if let Instr::JumpIfFalse(ref mut target) = bc[jmp_false] {
                *target = end;
            }
        }
        Stmt::Unsafe { .. } | Stmt::Import { .. } => {
            // not compiled in VM skeleton
        }
    }
}

fn compile_expr(expr: &Expr, bc: &mut Bytecode) {
    match expr {
        Expr::Number(n) => bc.push(Instr::PushNum(*n)),
        Expr::Bool(b) => bc.push(Instr::PushBool(*b)),
        Expr::Text(s) => bc.push(Instr::PushText(s.clone())),
        Expr::Var(name) => bc.push(Instr::LoadVar(name.clone())),
        Expr::Unary { op, expr } => {
            compile_expr(expr, bc);
            match op {
                UnaryOp::Neg => {
                    bc.push(Instr::PushNum(-1.0));
                    bc.push(Instr::Mul);
                }
                UnaryOp::Not => {
                    // emulate !x as (x) JumpIfFalse
                    let jmp_false_pos = bc.len();
                    bc.push(Instr::JumpIfFalse(0));
                    bc.push(Instr::PushBool(false));
                    let jmp_end = bc.len();
                    bc.push(Instr::Jump(0));
                    let false_branch = bc.len();
                    bc.push(Instr::PushBool(true));
                    let end = bc.len();
                    if let Instr::JumpIfFalse(ref mut t) = bc[jmp_false_pos] {
                        *t = false_branch;
                    }
                    if let Instr::Jump(ref mut t) = bc[jmp_end] {
                        *t = end;
                    }
                }
            }
        }
        Expr::Binary { op, left, right } => {
            compile_expr(left, bc);
            compile_expr(right, bc);
            bc.push(match op {
                BinaryOp::Add => Instr::Add,
                BinaryOp::Sub => Instr::Sub,
                BinaryOp::Mul => Instr::Mul,
                BinaryOp::Div => Instr::Div,
                BinaryOp::Mod => Instr::Mod,
                BinaryOp::Eq => Instr::Eq,
                BinaryOp::Ne => Instr::Ne,
                BinaryOp::Gt => Instr::Gt,
                BinaryOp::Ge => Instr::Ge,
                BinaryOp::Lt => Instr::Lt,
                BinaryOp::Le => Instr::Le,
                BinaryOp::And => Instr::And,
                BinaryOp::Or => Instr::Or,
            });
        }
        Expr::Call { callee, args } => {
            for arg in args {
                compile_expr(arg, bc);
            }
            if let Expr::Var(name) = &**callee {
                bc.push(Instr::CallBuiltin(name.clone(), args.len()));
            }
        }
        _ => {
            // other expression kinds not compiled in skeleton
        }
    }
}
