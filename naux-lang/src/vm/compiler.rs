// Compiler: AST -> IR -> Bytecode
#![allow(dead_code)]

use std::collections::HashMap;

use crate::ast::{ActionKind, BinaryOp, Expr, ExprKind, Span, Stmt, UnaryOp};
use crate::vm::bytecode::{Bytecode, FunctionBytecode, Instr, Program};
use crate::vm::ir::{IRBlock, IRFunction, IRInstr, IRNode, IRProgram};

/// Public entry: compile AST straight to bytecode (via IR + optimize).
pub fn compile_script(stmts: &[Stmt]) -> Program {
    let ir = compile_ir(stmts);
    let ir = optimize_ir(ir);
    lower_ir_to_bytecode(ir)
}

/// Compile AST into IR (stack-based).
pub fn compile_ir(stmts: &[Stmt]) -> IRProgram {
    let mut main: Vec<IRNode> = Vec::new();
    let mut functions: HashMap<String, IRFunction> = HashMap::new();
    for stmt in stmts {
        match stmt {
            Stmt::FnDef { name, params, body, .. } => {
                let mut code = Vec::new();
                for s in body {
                    compile_stmt_ir(s, &mut code);
                }
                code.push(IRNode::new(IRInstr::Return, None));
                functions.insert(
                    name.clone(),
                    IRFunction {
                        params: params.clone(),
                        code,
                    },
                );
            }
            _ => compile_stmt_ir(stmt, &mut main),
        }
    }
    main.push(IRNode::new(IRInstr::Return, None));
    IRProgram { main, functions }
}

/// Peephole optimizer: const-fold basic arith/compare, drop trivial jumps, prune unreachable.
fn optimize_ir(ir: IRProgram) -> IRProgram {
    let main = optimize_block(ir.main);
    let functions = ir
        .functions
        .into_iter()
        .map(|(name, f)| (name, IRFunction { params: f.params, code: optimize_block(f.code) }))
        .collect();
    IRProgram { main, functions }
}

fn optimize_block(block: Vec<IRNode>) -> Vec<IRNode> {
    // Pass 1: peephole + record mapping
    let mut out: Vec<IRNode> = Vec::new();
    let mut orig_idx: Vec<usize> = Vec::new();
    let mut map_old_to_new: Vec<Option<usize>> = vec![None; block.len()];
    let mut const_env: HashMap<String, IRInstr> = HashMap::new();
    let mut prev_const: Option<IRInstr> = None;
    let mut i = 0;
    while i < block.len() {
        // Const-fold arithmetic/compare on two consts followed by op
        if i + 2 < block.len() {
            if let (IRInstr::ConstNum(a), IRInstr::ConstNum(b), op) = (&block[i].instr, &block[i + 1].instr, &block[i + 2].instr) {
                if let Some(res_num) = fold_num(*a, *b, op) {
                    let new_idx = out.len();
                    out.push(IRNode::new(IRInstr::ConstNum(res_num), block[i].span.clone()));
                    orig_idx.push(i);
                    map_old_to_new[i] = Some(new_idx);
                    map_old_to_new[i + 1] = Some(new_idx);
                    map_old_to_new[i + 2] = Some(new_idx);
                    i += 3;
                    continue;
                }
                if let Some(res_bool) = fold_cmp(*a, *b, op) {
                    let new_idx = out.len();
                    out.push(IRNode::new(IRInstr::ConstBool(res_bool), block[i].span.clone()));
                    orig_idx.push(i);
                    map_old_to_new[i] = Some(new_idx);
                    map_old_to_new[i + 1] = Some(new_idx);
                    map_old_to_new[i + 2] = Some(new_idx);
                    i += 3;
                    continue;
                }
            }
        }

        // Simplify JumpIfFalse fed by ConstBool
        if i + 1 < block.len() {
            if let (IRInstr::ConstBool(b), IRInstr::JumpIfFalse(t)) = (&block[i].instr, &block[i + 1].instr) {
                if *b {
                    // condition true -> drop both instructions
                    map_old_to_new[i] = None;
                    map_old_to_new[i + 1] = None;
                    i += 2;
                    continue;
                } else {
                    // condition false -> always jump
                    let new_idx = out.len();
                    out.push(IRNode::new(IRInstr::Jump(*t), block[i].span.clone()));
                    orig_idx.push(i);
                    map_old_to_new[i] = Some(new_idx);
                    map_old_to_new[i + 1] = Some(new_idx);
                    i += 2;
                    continue;
                }
            }
        }

        // Drop jumps to immediate next
        if let IRInstr::Jump(t) = block[i].instr {
            if t == i + 1 {
                map_old_to_new[i] = None;
                const_env.clear();
                i += 1;
                continue;
            }
        }
        if let IRInstr::JumpIfFalse(t) = block[i].instr {
            if t == i + 1 {
                map_old_to_new[i] = None;
                const_env.clear();
                i += 1;
                continue;
            }
        }

        // Constant propagation for LoadVar
        let mut node = block[i].clone();
        if let IRInstr::LoadVar(ref name) = node.instr {
            if let Some(c) = const_env.get(name) {
                node.instr = c.clone();
            }
        }

        let new_idx = out.len();
        map_old_to_new[i] = Some(new_idx);

        // Track constants on StoreVar
        if let IRInstr::StoreVar(ref name) = node.instr {
            if let Some(c) = prev_const.clone() {
                const_env.insert(name.clone(), c);
            } else {
                const_env.remove(name);
            }
            prev_const = None;
        } else {
            prev_const = match &node.instr {
                IRInstr::ConstNum(_) | IRInstr::ConstBool(_) | IRInstr::ConstText(_) | IRInstr::PushNull => Some(node.instr.clone()),
                _ => None,
            };
            if matches!(node.instr, IRInstr::Jump(_) | IRInstr::JumpIfFalse(_)) {
                const_env.clear();
                prev_const = None;
            }
        }

        out.push(node);
        orig_idx.push(i);
        i += 1;
    }

    // Pass 2: remap jump targets to new indices
    for (pos, node) in out.iter_mut().enumerate() {
        let _orig = orig_idx[pos];
        match node.instr {
            IRInstr::Jump(ref mut tgt) | IRInstr::JumpIfFalse(ref mut tgt) => {
                if let Some(new_tgt) = remap_target(*tgt, &map_old_to_new) {
                    *tgt = new_tgt;
                }
            }
            _ => {}
        }
    }

    // Pass 3: reachability pruning
    prune_unreachable(out)
}

fn remap_target(mut old: usize, map_old_to_new: &[Option<usize>]) -> Option<usize> {
    while old < map_old_to_new.len() {
        if let Some(n) = map_old_to_new[old] {
            return Some(n);
        }
        old += 1;
    }
    map_old_to_new.iter().rev().flatten().copied().next()
}

fn prune_unreachable(block: Vec<IRNode>) -> Vec<IRNode> {
    if block.is_empty() {
        return block;
    }
    let mut reachable = vec![false; block.len()];
    // DFS
    fn dfs(idx: usize, block: &[IRNode], reach: &mut [bool]) {
        if idx >= block.len() || reach[idx] {
            return;
        }
        reach[idx] = true;
        match block[idx].instr {
            IRInstr::Jump(t) => dfs(t, block, reach),
            IRInstr::JumpIfFalse(t) => {
                dfs(idx + 1, block, reach);
                dfs(t, block, reach);
            }
            IRInstr::Return => {}
            _ => dfs(idx + 1, block, reach),
        }
    }
    dfs(0, &block, &mut reachable);

    let mut new_block: Vec<IRNode> = Vec::new();
    let mut map_old_new: Vec<Option<usize>> = vec![None; block.len()];
    for (i, instr) in block.iter().enumerate() {
        if reachable[i] {
            map_old_new[i] = Some(new_block.len());
            new_block.push(instr.clone());
        }
    }
    // Remap jumps after pruning
    for instr in new_block.iter_mut() {
        match instr {
            IRNode { instr: IRInstr::Jump(ref mut t), .. } | IRNode { instr: IRInstr::JumpIfFalse(ref mut t), .. } => {
                if let Some(nt) = remap_target(*t, &map_old_new) {
                    *t = nt;
                }
            }
            _ => {}
        }
    }
    new_block
}

fn fold_num(a: f64, b: f64, op: &IRInstr) -> Option<f64> {
    match op {
        IRInstr::Add => Some(a + b),
        IRInstr::Sub => Some(a - b),
        IRInstr::Mul => Some(a * b),
        IRInstr::Div => Some(a / b),
        IRInstr::Mod => Some(a % b),
        _ => None,
    }
}

fn fold_cmp(a: f64, b: f64, op: &IRInstr) -> Option<bool> {
    match op {
        IRInstr::Eq => Some((a - b).abs() < f64::EPSILON),
        IRInstr::Ne => Some((a - b).abs() >= f64::EPSILON),
        IRInstr::Gt => Some(a > b),
        IRInstr::Ge => Some(a >= b),
        IRInstr::Lt => Some(a < b),
        IRInstr::Le => Some(a <= b),
        _ => None,
    }
}

fn lower_ir_to_bytecode(ir: IRProgram) -> Program {
    let (main, main_locals, main_spans) = lower_block(ir.main, &[]);
    let mut functions: HashMap<String, FunctionBytecode> = HashMap::new();
    for (name, f) in ir.functions {
        let (code, locals, spans) = lower_block(f.code, &f.params);
        functions.insert(name, FunctionBytecode { params: f.params, locals, code, spans });
    }
    Program { main, main_locals, main_spans, functions }
}

fn lower_block(block: IRBlock, params: &[String]) -> (Bytecode, Vec<String>, Vec<Option<Span>>) {
    let (locals, mapping) = collect_locals(&block, params);
    let mut code = Bytecode::new();
    let mut spans: Vec<Option<Span>> = Vec::new();
    for node in block {
        code.push(lower_instr(node.instr, &mapping));
        spans.push(node.span);
    }
    let (code, spans) = optimize_bytecode_block(code, spans);
    (code, locals, spans)
}

fn lower_instr(i: IRInstr, slots: &HashMap<String, usize>) -> Instr {
    match i {
        IRInstr::ConstNum(n) => Instr::ConstNum(n),
        IRInstr::ConstText(s) => Instr::ConstText(s),
        IRInstr::ConstBool(b) => Instr::ConstBool(b),
        IRInstr::PushNull => Instr::PushNull,
        IRInstr::LoadVar(s) => Instr::LoadLocal(*slots.get(&s).expect("slot missing")),
        IRInstr::StoreVar(s) => Instr::StoreLocal(*slots.get(&s).expect("slot missing")),
        IRInstr::Add => Instr::Add,
        IRInstr::Sub => Instr::Sub,
        IRInstr::Mul => Instr::Mul,
        IRInstr::Div => Instr::Div,
        IRInstr::Mod => Instr::Mod,
        IRInstr::Eq => Instr::Eq,
        IRInstr::Ne => Instr::Ne,
        IRInstr::Gt => Instr::Gt,
        IRInstr::Ge => Instr::Ge,
        IRInstr::Lt => Instr::Lt,
        IRInstr::Le => Instr::Le,
        IRInstr::And => Instr::And,
        IRInstr::Or => Instr::Or,
        IRInstr::Jump(t) => Instr::Jump(t),
        IRInstr::JumpIfFalse(t) => Instr::JumpIfFalse(t),
        IRInstr::CallBuiltin(n, a) => Instr::CallBuiltin(n, a),
        IRInstr::CallFn(n, a) => Instr::CallFn(n, a),
        IRInstr::MakeList(n) => Instr::MakeList(n),
        IRInstr::MakeMap(keys) => Instr::MakeMap(keys),
        IRInstr::LoadField(f) => Instr::LoadField(f),
        IRInstr::EmitSay => Instr::EmitSay,
        IRInstr::EmitAsk => Instr::EmitAsk,
        IRInstr::EmitFetch => Instr::EmitFetch,
        IRInstr::EmitUi(k) => Instr::EmitUi(k),
        IRInstr::EmitText => Instr::EmitText,
        IRInstr::EmitButton => Instr::EmitButton,
        IRInstr::EmitLog => Instr::EmitLog,
        IRInstr::Return => Instr::Return,
    }
}

/// Peephole bytecode optimizer: drop immediate LoadLocal after StoreLocal when not a jump target.
fn optimize_bytecode_block(code: Bytecode, spans: Vec<Option<Span>>) -> (Bytecode, Vec<Option<Span>>) {
    let mut jump_targets: Vec<usize> = Vec::new();
    for instr in &code {
        match instr {
            Instr::Jump(t) | Instr::JumpIfFalse(t) => jump_targets.push(*t),
            _ => {}
        }
    }
    let mut out: Bytecode = Bytecode::new();
    let mut out_spans: Vec<Option<Span>> = Vec::new();
    let mut map_old_to_new: Vec<Option<usize>> = vec![None; code.len()];
    let mut i = 0;
    while i < code.len() {
        if i + 1 < code.len() {
            if let Instr::StoreLocal(a) = code[i] {
                if let Instr::LoadLocal(b) = code[i + 1] {
                    if a == b && !jump_targets.contains(&(i + 1)) {
                        let new_idx = out.len();
                        out.push(code[i].clone());
                        out_spans.push(spans.get(i).cloned().unwrap_or(None));
                        map_old_to_new[i] = Some(new_idx);
                        map_old_to_new[i + 1] = None;
                        i += 2;
                        continue;
                    }
                }
            }
        }
        let new_idx = out.len();
        map_old_to_new[i] = Some(new_idx);
        out.push(code[i].clone());
        out_spans.push(spans.get(i).cloned().unwrap_or(None));
        i += 1;
    }
    // remap jumps
    for instr in out.iter_mut() {
        match instr {
            Instr::Jump(ref mut t) | Instr::JumpIfFalse(ref mut t) => {
                if let Some(nt) = remap_target(*t, &map_old_to_new) {
                    *t = nt;
                }
            }
            _ => {}
        }
    }
    (out, out_spans)
}

fn collect_locals(block: &[IRNode], params: &[String]) -> (Vec<String>, HashMap<String, usize>) {
    let mut locals: Vec<String> = Vec::new();
    let mut map: HashMap<String, usize> = HashMap::new();
    for p in params {
        let idx = locals.len();
        locals.push(p.clone());
        map.insert(p.clone(), idx);
    }
    for node in block {
        match &node.instr {
            IRInstr::LoadVar(name) | IRInstr::StoreVar(name) => {
                if !map.contains_key(name) {
                    let idx = locals.len();
                    locals.push(name.clone());
                    map.insert(name.clone(), idx);
                }
            }
            _ => {}
        }
    }
    (locals, map)
}

fn compile_stmt_ir(stmt: &Stmt, bc: &mut Vec<IRNode>) {
    match stmt {
        Stmt::Assign { name, expr, span } => {
            compile_expr_ir(expr, bc);
            bc.push(IRNode::new(IRInstr::StoreVar(name.clone()), span.clone()));
        }
        Stmt::If { cond, then_block, else_block, span } => {
            compile_expr_ir(cond, bc);
            let jmp_false_pos = bc.len();
            bc.push(IRNode::new(IRInstr::JumpIfFalse(0), span.clone())); // patched later

            for s in then_block {
                compile_stmt_ir(s, bc);
            }
            let jmp_end_pos = bc.len();
            bc.push(IRNode::new(IRInstr::Jump(0), span.clone())); // patched later

            let else_start = bc.len();
            for s in else_block {
                compile_stmt_ir(s, bc);
            }
            let end = bc.len();
            if let IRInstr::JumpIfFalse(ref mut target) = bc[jmp_false_pos].instr {
                *target = else_start;
            }
            if let IRInstr::Jump(ref mut target) = bc[jmp_end_pos].instr {
                *target = end;
            }
        }
        Stmt::Loop { count, body, span } => {
            let tmp = "__loop_rem__".to_string();
            compile_expr_ir(count, bc);
            bc.push(IRNode::new(IRInstr::StoreVar(tmp.clone()), span.clone()));
            let start = bc.len();
            bc.push(IRNode::new(IRInstr::LoadVar(tmp.clone()), span.clone()));
            let jmp_false = bc.len();
            bc.push(IRNode::new(IRInstr::JumpIfFalse(0), span.clone()));
            for s in body {
                compile_stmt_ir(s, bc);
            }
            bc.push(IRNode::new(IRInstr::LoadVar(tmp.clone()), span.clone()));
            bc.push(IRNode::new(IRInstr::ConstNum(1.0), span.clone()));
            bc.push(IRNode::new(IRInstr::Sub, span.clone()));
            bc.push(IRNode::new(IRInstr::StoreVar(tmp.clone()), span.clone()));
            bc.push(IRNode::new(IRInstr::Jump(start), span.clone()));
            let end = bc.len();
            if let IRInstr::JumpIfFalse(ref mut target) = bc[jmp_false].instr {
                *target = end;
            }
        }
        Stmt::While { cond, body, span } => {
            let start = bc.len();
            compile_expr_ir(cond, bc);
            let jmp_false = bc.len();
            bc.push(IRNode::new(IRInstr::JumpIfFalse(0), span.clone()));
            for s in body {
                compile_stmt_ir(s, bc);
            }
            bc.push(IRNode::new(IRInstr::Jump(start), span.clone()));
            let end = bc.len();
            if let IRInstr::JumpIfFalse(ref mut target) = bc[jmp_false].instr {
                *target = end;
            }
        }
        Stmt::Return { value, span } => {
            if let Some(expr) = value {
                compile_expr_ir(expr, bc);
            } else {
                bc.push(IRNode::new(IRInstr::PushNull, span.clone()));
            }
            bc.push(IRNode::new(IRInstr::Return, span.clone()));
        }
        Stmt::Action { action, span } => {
            compile_action_ir(action, span.clone(), bc);
        }
        Stmt::Rite { body, .. } => {
            for s in body {
                compile_stmt_ir(s, bc);
            }
        }
        Stmt::FnDef { .. } => {}
        Stmt::Each { var, iter, body, span } => {
            let tmp_iter = "__each_iter__".to_string();
            let tmp_idx = "__each_idx__".to_string();
            compile_expr_ir(iter, bc);
            bc.push(IRNode::new(IRInstr::StoreVar(tmp_iter.clone()), span.clone()));
            bc.push(IRNode::new(IRInstr::ConstNum(0.0), span.clone()));
            bc.push(IRNode::new(IRInstr::StoreVar(tmp_idx.clone()), span.clone()));
            let start = bc.len();
            bc.push(IRNode::new(IRInstr::LoadVar(tmp_idx.clone()), span.clone()));
            bc.push(IRNode::new(IRInstr::LoadVar(tmp_iter.clone()), span.clone()));
            bc.push(IRNode::new(IRInstr::CallBuiltin("len".into(), 1), span.clone()));
            bc.push(IRNode::new(IRInstr::Lt, span.clone()));
            let jmp_false = bc.len();
            bc.push(IRNode::new(IRInstr::JumpIfFalse(0), span.clone()));
            bc.push(IRNode::new(IRInstr::LoadVar(tmp_iter.clone()), span.clone()));
            bc.push(IRNode::new(IRInstr::LoadVar(tmp_idx.clone()), span.clone()));
            bc.push(IRNode::new(IRInstr::CallBuiltin("__index".into(), 2), span.clone()));
            bc.push(IRNode::new(IRInstr::StoreVar(var.clone()), span.clone()));
            for s in body {
                compile_stmt_ir(s, bc);
            }
            bc.push(IRNode::new(IRInstr::LoadVar(tmp_idx.clone()), span.clone()));
            bc.push(IRNode::new(IRInstr::ConstNum(1.0), span.clone()));
            bc.push(IRNode::new(IRInstr::Add, span.clone()));
            bc.push(IRNode::new(IRInstr::StoreVar(tmp_idx.clone()), span.clone()));
            bc.push(IRNode::new(IRInstr::Jump(start), span.clone()));
            let end = bc.len();
            if let IRInstr::JumpIfFalse(ref mut target) = bc[jmp_false].instr {
                *target = end;
            }
        }
        Stmt::Unsafe { .. } | Stmt::Import { .. } => {}
    }
}

fn compile_action_ir(action: &ActionKind, span: Option<Span>, bc: &mut Vec<IRNode>) {
    match action {
        ActionKind::Say { value } => {
            compile_expr_ir(value, bc);
            bc.push(IRNode::new(IRInstr::EmitSay, span.clone()));
        }
        ActionKind::Ask { prompt } => {
            compile_expr_ir(prompt, bc);
            bc.push(IRNode::new(IRInstr::EmitAsk, span.clone()));
        }
        ActionKind::Fetch { target } => {
            compile_expr_ir(target, bc);
            bc.push(IRNode::new(IRInstr::EmitFetch, span.clone()));
        }
        ActionKind::Ui { kind, .. } => {
            bc.push(IRNode::new(IRInstr::EmitUi(kind.clone()), span.clone()));
        }
        ActionKind::Text { value } => {
            compile_expr_ir(value, bc);
            bc.push(IRNode::new(IRInstr::EmitText, span.clone()));
        }
        ActionKind::Button { value } => {
            compile_expr_ir(value, bc);
            bc.push(IRNode::new(IRInstr::EmitButton, span.clone()));
        }
        ActionKind::Log { value } => {
            compile_expr_ir(value, bc);
            bc.push(IRNode::new(IRInstr::EmitLog, span.clone()));
        }
    }
}

fn compile_expr_ir(expr: &Expr, bc: &mut Vec<IRNode>) {
    let span = expr.span.clone();
    match &expr.kind {
        ExprKind::Number(n) => bc.push(IRNode::new(IRInstr::ConstNum(*n), span)),
        ExprKind::Bool(b) => bc.push(IRNode::new(IRInstr::ConstBool(*b), span)),
        ExprKind::Text(s) => bc.push(IRNode::new(IRInstr::ConstText(s.clone()), span)),
        ExprKind::Var(name) => bc.push(IRNode::new(IRInstr::LoadVar(name.clone()), span)),
        ExprKind::Unary { op, expr } => {
            compile_expr_ir(expr, bc);
            match op {
                UnaryOp::Neg => {
                    bc.push(IRNode::new(IRInstr::ConstNum(-1.0), span.clone()));
                    bc.push(IRNode::new(IRInstr::Mul, span));
                }
                UnaryOp::Not => {
                    let jmp_false_pos = bc.len();
                    bc.push(IRNode::new(IRInstr::JumpIfFalse(0), span.clone()));
                    bc.push(IRNode::new(IRInstr::ConstBool(false), span.clone()));
                    let jmp_end = bc.len();
                    bc.push(IRNode::new(IRInstr::Jump(0), span.clone()));
                    let false_branch = bc.len();
                    bc.push(IRNode::new(IRInstr::ConstBool(true), span.clone()));
                    let end = bc.len();
                    if let IRInstr::JumpIfFalse(ref mut t) = bc[jmp_false_pos].instr {
                        *t = false_branch;
                    }
                    if let IRInstr::Jump(ref mut t) = bc[jmp_end].instr {
                        *t = end;
                    }
                }
            }
        }
        ExprKind::Binary { op, left, right } => {
            compile_expr_ir(left, bc);
            compile_expr_ir(right, bc);
            bc.push(IRNode::new(
                match op {
                    BinaryOp::Add => IRInstr::Add,
                    BinaryOp::Sub => IRInstr::Sub,
                    BinaryOp::Mul => IRInstr::Mul,
                    BinaryOp::Div => IRInstr::Div,
                    BinaryOp::Mod => IRInstr::Mod,
                    BinaryOp::Eq => IRInstr::Eq,
                    BinaryOp::Ne => IRInstr::Ne,
                    BinaryOp::Gt => IRInstr::Gt,
                    BinaryOp::Ge => IRInstr::Ge,
                    BinaryOp::Lt => IRInstr::Lt,
                    BinaryOp::Le => IRInstr::Le,
                    BinaryOp::And => IRInstr::And,
                    BinaryOp::Or => IRInstr::Or,
                },
                span,
            ));
        }
        ExprKind::Call { callee, args } => {
            for arg in args {
                compile_expr_ir(arg, bc);
            }
            if let ExprKind::Var(name) = &callee.kind {
                bc.push(IRNode::new(IRInstr::CallFn(name.clone(), args.len()), span));
            }
        }
        ExprKind::Index { target, index } => {
            compile_expr_ir(target, bc);
            compile_expr_ir(index, bc);
            bc.push(IRNode::new(IRInstr::CallBuiltin("__index".into(), 2), span));
        }
        ExprKind::List(items) => {
            for item in items {
                compile_expr_ir(item, bc);
            }
            bc.push(IRNode::new(IRInstr::MakeList(items.len()), span));
        }
        ExprKind::Map(entries) => {
            for (_, v) in entries {
                compile_expr_ir(v, bc);
            }
            bc.push(IRNode::new(IRInstr::MakeMap(entries.iter().map(|(k, _)| k.clone()).collect()), span));
        }
        ExprKind::Field { target, field } => {
            compile_expr_ir(target, bc);
            bc.push(IRNode::new(IRInstr::LoadField(field.clone()), span));
        }
    }
}
