//! Phase-1 SSA preview pipeline (linear lowering + simple passes).
//!
//! This module is intentionally non-invasive:
//! - It does not change execution semantics of VM/JIT.
//! - It provides a structural SSA layer so optimization work can move out
//!   of the stack IR in later phases.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write;

use crate::typecheck::Type;
use crate::vm::ir::{AliasingClass, CostBound, NumericProof, ProofEnv, ProofSlot, RefinedType};
use crate::vm::ir::{IRFunction, IRInstr, IRNode, IRProgram};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ValueId(pub u32);

#[derive(Clone, Debug, PartialEq)]
pub enum ConstValue {
    Num(f64),
    Bool(bool),
    Text(String),
    Null,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Xor,
    Shl,
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    And,
    Or,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmitKind {
    Say,
    Ask,
    Fetch,
    Ui,
    Text,
    Button,
    Log,
}

#[derive(Clone, Debug, PartialEq)]
pub enum InstKind {
    Const(ConstValue),
    Alias(ValueId),
    Phi {
        var: String,
        inputs: Vec<(u32, ValueId)>,
    },
    BinOp {
        op: BinOp,
        lhs: ValueId,
        rhs: ValueId,
    },
    CallBuiltin {
        name: String,
        args: Vec<ValueId>,
    },
    CallFn {
        name: String,
        args: Vec<ValueId>,
    },
    MakeList(Vec<ValueId>),
    MakeMap {
        keys: Vec<String>,
        values: Vec<ValueId>,
    },
    LoadField {
        base: ValueId,
        field: String,
    },
    Emit {
        kind: EmitKind,
        ui_kind: Option<String>,
        arg: Option<ValueId>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Inst {
    pub id: Option<ValueId>,
    pub kind: InstKind,
    pub proof: ProofSlot,
}

impl Inst {
    fn new(id: Option<ValueId>, kind: InstKind) -> Self {
        Self {
            id,
            kind,
            proof: ProofSlot::default(),
        }
    }

    fn with_proof(mut self, proof: ProofSlot) -> Self {
        self.proof = proof;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VarOp {
    Load { name: String, out: ValueId },
    Store { name: String, value: ValueId },
}

#[derive(Clone, Debug, PartialEq)]
pub enum Terminator {
    Return(Option<ValueId>),
    Jump(u32),
    Branch {
        cond: ValueId,
        true_bb: u32,
        false_bb: u32,
    },
    UnsupportedControlFlow {
        ip: usize,
        op: String,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    pub id: u32,
    pub insts: Vec<Inst>,
    pub var_ops: Vec<VarOp>,
    pub term: Terminator,
}

#[derive(Clone, Debug, PartialEq)]
pub enum BuildStatus {
    Lowered,
    Unsupported(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Function {
    pub name: String,
    pub params: Vec<String>,
    pub param_values: Vec<ValueId>,
    pub blocks: Vec<Block>,
    pub status: BuildStatus,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Program {
    pub main: Function,
    pub functions: BTreeMap<String, Function>,
}

impl Program {
    pub fn iter_functions_mut(&mut self) -> impl Iterator<Item = &mut Function> {
        std::iter::once(&mut self.main).chain(self.functions.values_mut())
    }

    pub fn iter_functions(&self) -> impl Iterator<Item = &Function> {
        std::iter::once(&self.main).chain(self.functions.values())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LowerArenaPlan {
    inst_cap: usize,
    stack_cap: usize,
    locals_cap: usize,
    var_op_cap: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LowerScratchStats {
    pub functions: usize,
    pub blocks: usize,
    pub insts: usize,
    pub var_ops: usize,
    pub var_ops_staged: usize,
    pub inst_reserved: usize,
    pub stack_reserved: usize,
    pub locals_reserved: usize,
    pub var_op_reserved: usize,
}

impl LowerScratchStats {
    fn record_plan(&mut self, plan: LowerArenaPlan) {
        self.functions = self.functions.saturating_add(1);
        self.inst_reserved = self.inst_reserved.saturating_add(plan.inst_cap);
        self.stack_reserved = self.stack_reserved.saturating_add(plan.stack_cap);
        self.locals_reserved = self.locals_reserved.saturating_add(plan.locals_cap);
        self.var_op_reserved = self.var_op_reserved.saturating_add(plan.var_op_cap);
    }

    fn record_function(&mut self, function: &Function) {
        self.blocks = self.blocks.saturating_add(function.blocks.len());
        self.insts = self
            .insts
            .saturating_add(function.blocks.iter().map(|b| b.insts.len()).sum::<usize>());
        self.var_ops = self.var_ops.saturating_add(
            function
                .blocks
                .iter()
                .map(|b| b.var_ops.len())
                .sum::<usize>(),
        );
    }

    fn record_var_ops_staged(&mut self, count: usize) {
        self.var_ops_staged = self.var_ops_staged.saturating_add(count);
    }
}

impl LowerArenaPlan {
    fn from_ir(ir: &IRFunction) -> Self {
        let inst_cap = ir.code.len().saturating_add(ir.params.len());
        let stack_cap = ir.code.len().max(4);
        let locals_cap = ir.params.len().saturating_add(ir.code.len() / 4).max(4);
        let var_op_cap = ir
            .code
            .iter()
            .filter(|node| matches!(node.instr, IRInstr::LoadVar(_) | IRInstr::StoreVar(_)))
            .count();
        Self {
            inst_cap,
            stack_cap,
            locals_cap,
            var_op_cap,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
struct InstSlab {
    entries: Vec<Inst>,
}

impl InstSlab {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn push(&mut self, inst: Inst) {
        self.entries.push(inst);
    }

    fn as_slice(&self) -> &[Inst] {
        &self.entries
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
struct VarOpSlab {
    entries: Vec<VarOp>,
    ip_ranges: Vec<(usize, usize)>,
}

impl VarOpSlab {
    fn with_capacity(ip_count: usize, capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            ip_ranges: vec![(0, 0); ip_count],
        }
    }

    fn start_ip(&mut self, ip: usize) {
        let offset = self.entries.len();
        self.ip_ranges[ip] = (offset, offset);
    }

    fn push(&mut self, ip: usize, op: VarOp) {
        let (start, _) = self.ip_ranges[ip];
        self.entries.push(op);
        self.ip_ranges[ip] = (start, self.entries.len());
    }

    fn slice(&self, ip: usize) -> &[VarOp] {
        let (start, end) = self.ip_ranges[ip];
        &self.entries[start..end]
    }

    fn range(&self, ip: usize) -> (usize, usize) {
        self.ip_ranges[ip]
    }
}

struct LowerCtx {
    next_value: u32,
    insts: InstSlab,
    stack: Vec<ValueId>,
    locals: HashMap<String, ValueId>,
}

impl LowerCtx {
    fn with_plan(plan: LowerArenaPlan) -> Self {
        Self {
            next_value: 0,
            insts: InstSlab::with_capacity(plan.inst_cap),
            stack: Vec::with_capacity(plan.stack_cap),
            locals: HashMap::with_capacity(plan.locals_cap),
        }
    }

    fn fresh(&mut self) -> ValueId {
        let id = ValueId(self.next_value);
        self.next_value = self.next_value.saturating_add(1);
        id
    }

    fn push_const(&mut self, value: ConstValue, proof: ProofSlot) -> ValueId {
        let id = self.fresh();
        self.insts
            .push(Inst::new(Some(id), InstKind::Const(value)).with_proof(proof));
        id
    }

    fn pop_or_null(&mut self) -> ValueId {
        self.stack
            .pop()
            .unwrap_or_else(|| self.push_const(ConstValue::Null, ProofSlot::default()))
    }

    fn pop_n_or_null(&mut self, n: usize) -> Vec<ValueId> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.pop_or_null());
        }
        out.reverse();
        out
    }
}

#[derive(Clone, Debug)]
enum ControlTerm {
    Return(Option<ValueId>),
    Jump {
        target_ip: usize,
    },
    Branch {
        cond: ValueId,
        false_target_ip: usize,
    },
    Unsupported {
        op: String,
    },
}

pub fn lower_program(ir: &IRProgram) -> Program {
    lower_program_internal(ir).0
}

pub fn lower_program_with_stats(ir: &IRProgram) -> (Program, LowerScratchStats) {
    lower_program_internal(ir)
}

fn lower_program_internal(ir: &IRProgram) -> (Program, LowerScratchStats) {
    let mut stats = LowerScratchStats::default();
    let main_fn = IRFunction {
        params: Vec::new(),
        code: ir.main.clone(),
        return_type: ir.main_return.clone(),
    };
    let main = lower_function("main", &main_fn, &mut stats);

    let mut functions: BTreeMap<String, Function> = BTreeMap::new();
    for (name, func) in &ir.functions {
        functions.insert(name.clone(), lower_function(name, func, &mut stats));
    }

    (Program { main, functions }, stats)
}

fn lower_function(name: &str, ir: &IRFunction, stats: &mut LowerScratchStats) -> Function {
    let plan = LowerArenaPlan::from_ir(ir);
    stats.record_plan(plan);
    let mut ctx = LowerCtx::with_plan(plan);
    let params = ir.params.clone();
    let mut param_values = Vec::with_capacity(params.len());

    for p in &params {
        let id = ctx.fresh();
        ctx.locals.insert(p.clone(), id);
        param_values.push(id);
    }

    let code_len = ir.code.len();
    let mut inst_ranges: Vec<(usize, usize)> = vec![(0, 0); code_len];
    let mut controls: Vec<Option<ControlTerm>> = vec![None; code_len];
    let mut var_ops = VarOpSlab::with_capacity(code_len, plan.var_op_cap);
    let mut unsupported: Option<String> = None;

    for (ip, node) in ir.code.iter().enumerate() {
        let before = ctx.insts.len();
        var_ops.start_ip(ip);
        match &node.instr {
            IRInstr::ConstNum(n) => {
                let id = ctx.push_const(ConstValue::Num(*n), node.proof.clone());
                ctx.stack.push(id);
            }
            IRInstr::ConstText(s) => {
                let id = ctx.push_const(ConstValue::Text(s.clone()), node.proof.clone());
                ctx.stack.push(id);
            }
            IRInstr::ConstBool(b) => {
                let id = ctx.push_const(ConstValue::Bool(*b), node.proof.clone());
                ctx.stack.push(id);
            }
            IRInstr::PushNull => {
                let id = ctx.push_const(ConstValue::Null, node.proof.clone());
                ctx.stack.push(id);
            }
            IRInstr::LoadVar(var) => {
                let src = ctx
                    .locals
                    .get(var)
                    .copied()
                    .unwrap_or_else(|| ctx.push_const(ConstValue::Null, ProofSlot::default()));
                let id = ctx.fresh();
                ctx.insts
                    .push(Inst::new(Some(id), InstKind::Alias(src)).with_proof(node.proof.clone()));
                ctx.stack.push(id);
                var_ops.push(
                    ip,
                    VarOp::Load {
                        name: var.clone(),
                        out: id,
                    },
                );
            }
            IRInstr::StoreVar(var) => {
                let value = ctx.pop_or_null();
                ctx.locals.insert(var.clone(), value);
                var_ops.push(
                    ip,
                    VarOp::Store {
                        name: var.clone(),
                        value,
                    },
                );
            }
            IRInstr::Add
            | IRInstr::Sub
            | IRInstr::Mul
            | IRInstr::Div
            | IRInstr::Mod
            | IRInstr::Xor
            | IRInstr::Shl
            | IRInstr::Eq
            | IRInstr::Ne
            | IRInstr::Gt
            | IRInstr::Ge
            | IRInstr::Lt
            | IRInstr::Le
            | IRInstr::And
            | IRInstr::Or => {
                let rhs = ctx.pop_or_null();
                let lhs = ctx.pop_or_null();
                let Some(op) = binop_from_ir(&node.instr) else {
                    continue;
                };
                let id = ctx.fresh();
                ctx.insts.push(
                    Inst::new(Some(id), InstKind::BinOp { op, lhs, rhs })
                        .with_proof(node.proof.clone()),
                );
                ctx.stack.push(id);
            }
            IRInstr::CallBuiltin(name, argc) => {
                let args = ctx.pop_n_or_null(*argc);
                let id = ctx.fresh();
                ctx.insts.push(
                    Inst::new(
                        Some(id),
                        InstKind::CallBuiltin {
                            name: name.clone(),
                            args,
                        },
                    )
                    .with_proof(node.proof.clone()),
                );
                ctx.stack.push(id);
            }
            IRInstr::CallFn(name, argc) => {
                let args = ctx.pop_n_or_null(*argc);
                let id = ctx.fresh();
                ctx.insts.push(
                    Inst::new(
                        Some(id),
                        InstKind::CallFn {
                            name: name.clone(),
                            args,
                        },
                    )
                    .with_proof(node.proof.clone()),
                );
                ctx.stack.push(id);
            }
            IRInstr::Call(argc) => {
                unsupported = Some("dynamic call lowering not implemented in phase-1 SSA".into());
                controls[ip] = Some(ControlTerm::Unsupported {
                    op: format!("Call argc={}", argc),
                });
            }
            IRInstr::MakeList(n) => {
                let values = ctx.pop_n_or_null(*n);
                let id = ctx.fresh();
                ctx.insts.push(
                    Inst::new(Some(id), InstKind::MakeList(values)).with_proof(node.proof.clone()),
                );
                ctx.stack.push(id);
            }
            IRInstr::MakeMap(keys) => {
                let values = ctx.pop_n_or_null(keys.len());
                let id = ctx.fresh();
                ctx.insts.push(
                    Inst::new(
                        Some(id),
                        InstKind::MakeMap {
                            keys: keys.clone(),
                            values,
                        },
                    )
                    .with_proof(node.proof.clone()),
                );
                ctx.stack.push(id);
            }
            IRInstr::LoadField(field) => {
                let base = ctx.pop_or_null();
                let id = ctx.fresh();
                ctx.insts.push(
                    Inst::new(
                        Some(id),
                        InstKind::LoadField {
                            base,
                            field: field.clone(),
                        },
                    )
                    .with_proof(node.proof.clone()),
                );
                ctx.stack.push(id);
            }
            IRInstr::EmitSay
            | IRInstr::EmitAsk
            | IRInstr::EmitFetch
            | IRInstr::EmitText
            | IRInstr::EmitButton
            | IRInstr::EmitLog => {
                let arg = Some(ctx.pop_or_null());
                let kind = emit_kind_from_ir(&node.instr).unwrap_or(EmitKind::Log);
                ctx.insts.push(
                    Inst::new(
                        None,
                        InstKind::Emit {
                            kind,
                            ui_kind: None,
                            arg,
                        },
                    )
                    .with_proof(node.proof.clone()),
                );
            }
            IRInstr::EmitUi(kind) => {
                ctx.insts.push(
                    Inst::new(
                        None,
                        InstKind::Emit {
                            kind: EmitKind::Ui,
                            ui_kind: Some(kind.clone()),
                            arg: None,
                        },
                    )
                    .with_proof(node.proof.clone()),
                );
            }
            IRInstr::Pop => {
                let _ = ctx.stack.pop();
            }
            IRInstr::Jump(target_ip) => {
                controls[ip] = Some(ControlTerm::Jump {
                    target_ip: *target_ip,
                });
            }
            IRInstr::JumpIfFalse(target_ip) => {
                let cond = ctx.pop_or_null();
                controls[ip] = Some(ControlTerm::Branch {
                    cond,
                    false_target_ip: *target_ip,
                });
            }
            IRInstr::Return => {
                controls[ip] = Some(ControlTerm::Return(ctx.stack.pop()));
            }
        }
        inst_ranges[ip] = (before, ctx.insts.len());
    }
    stats.record_var_ops_staged(var_ops.entries.len());

    let mut blocks = build_cfg_blocks(
        &ir.code,
        &inst_ranges,
        ctx.insts.as_slice(),
        &var_ops,
        &controls,
        &mut unsupported,
    );
    if blocks.is_empty() {
        blocks.push(Block {
            id: 0,
            insts: Vec::new(),
            var_ops: Vec::new(),
            term: Terminator::Return(None),
        });
    }
    let mut function = Function {
        name: name.to_string(),
        params,
        param_values,
        blocks,
        status: unsupported.map_or(BuildStatus::Lowered, BuildStatus::Unsupported),
    };
    if matches!(function.status, BuildStatus::Lowered) {
        if let Err(err) = construct_ssa_phi_rename(&mut function) {
            function.status = BuildStatus::Unsupported(format!("ssa construction failed: {}", err));
        }
    }
    if matches!(function.status, BuildStatus::Lowered) {
        if let Err(errors) = verify_function_ssa(&function) {
            let head = errors.into_iter().take(3).collect::<Vec<_>>().join(" | ");
            function.status = BuildStatus::Unsupported(format!("ssa verify failed: {}", head));
        }
    }
    stats.record_function(&function);
    function
}

fn build_cfg_blocks(
    code: &[IRNode],
    inst_ranges: &[(usize, usize)],
    inst_pool: &[Inst],
    var_ops: &VarOpSlab,
    controls: &[Option<ControlTerm>],
    unsupported: &mut Option<String>,
) -> Vec<Block> {
    if code.is_empty() {
        return Vec::new();
    }

    let mut leaders: Vec<usize> = vec![0];
    for (ip, node) in code.iter().enumerate() {
        match &node.instr {
            IRInstr::Jump(t) | IRInstr::JumpIfFalse(t) => {
                if *t < code.len() {
                    leaders.push(*t);
                } else if unsupported.is_none() {
                    *unsupported = Some(format!("jump target {} out of range at ip {}", t, ip));
                }
                if ip + 1 < code.len() {
                    leaders.push(ip + 1);
                }
            }
            IRInstr::Return if ip + 1 < code.len() => {
                leaders.push(ip + 1);
            }
            _ => {}
        }
    }
    leaders.sort_unstable();
    leaders.dedup();

    let mut ranges: Vec<(usize, usize)> = Vec::with_capacity(leaders.len());
    for (i, start) in leaders.iter().enumerate() {
        let end = if i + 1 < leaders.len() {
            leaders[i + 1]
        } else {
            code.len()
        };
        if *start < end {
            ranges.push((*start, end));
        }
    }

    let mut ip_to_block: Vec<Option<u32>> = vec![None; code.len()];
    for (bb, (start, end)) in ranges.iter().enumerate() {
        for slot in ip_to_block.iter_mut().take(*end).skip(*start) {
            *slot = Some(bb as u32);
        }
    }

    let mut blocks: Vec<Block> = Vec::with_capacity(ranges.len());
    for (bb, (start, end)) in ranges.iter().enumerate() {
        let inst_cap = inst_ranges
            .iter()
            .take(*end)
            .skip(*start)
            .map(|(b, e)| e.saturating_sub(*b))
            .sum();
        let var_op_cap = (*start..*end)
            .map(|ip| {
                let (range_start, range_end) = var_ops.range(ip);
                range_end.saturating_sub(range_start)
            })
            .sum();
        let mut insts: Vec<Inst> = Vec::with_capacity(inst_cap);
        let mut block_var_ops: Vec<VarOp> = Vec::with_capacity(var_op_cap);
        for (b, e) in inst_ranges.iter().take(*end).skip(*start) {
            if *b < *e && *e <= inst_pool.len() {
                insts.extend(inst_pool[*b..*e].iter().cloned());
            }
        }
        for ip in *start..*end {
            block_var_ops.extend(var_ops.slice(ip).iter().cloned());
        }

        let last_ip = end - 1;
        let next_bb = (bb + 1 < ranges.len()).then_some((bb + 1) as u32);
        let term = match controls.get(last_ip).and_then(|x| x.clone()) {
            Some(ControlTerm::Return(v)) => Terminator::Return(v),
            Some(ControlTerm::Jump { target_ip }) => {
                if let Some(target_bb) = ip_to_block.get(target_ip).and_then(|x| *x) {
                    Terminator::Jump(target_bb)
                } else {
                    if unsupported.is_none() {
                        *unsupported = Some(format!(
                            "cannot map jump target {} to block at ip {}",
                            target_ip, last_ip
                        ));
                    }
                    Terminator::UnsupportedControlFlow {
                        ip: last_ip,
                        op: format!("Jump {}", target_ip),
                    }
                }
            }
            Some(ControlTerm::Branch {
                cond,
                false_target_ip,
            }) => {
                let true_bb = next_bb.unwrap_or(bb as u32);
                if let Some(false_bb) = ip_to_block.get(false_target_ip).and_then(|x| *x) {
                    Terminator::Branch {
                        cond,
                        true_bb,
                        false_bb,
                    }
                } else {
                    if unsupported.is_none() {
                        *unsupported = Some(format!(
                            "cannot map branch target {} to block at ip {}",
                            false_target_ip, last_ip
                        ));
                    }
                    Terminator::UnsupportedControlFlow {
                        ip: last_ip,
                        op: format!("JumpIfFalse {}", false_target_ip),
                    }
                }
            }
            Some(ControlTerm::Unsupported { op }) => {
                if unsupported.is_none() {
                    *unsupported = Some(op.clone());
                }
                Terminator::UnsupportedControlFlow { ip: last_ip, op }
            }
            None => next_bb
                .map(Terminator::Jump)
                .unwrap_or(Terminator::Return(None)),
        };

        blocks.push(Block {
            id: bb as u32,
            insts,
            var_ops: block_var_ops,
            term,
        });
    }

    blocks
}

#[derive(Clone, Debug)]
struct Cfg {
    block_ids: Vec<u32>,
    id_to_index: HashMap<u32, usize>,
    succs: Vec<Vec<usize>>,
    preds: Vec<Vec<usize>>,
    entry: usize,
}

impl Cfg {
    fn from_function(function: &Function) -> Self {
        let block_ids: Vec<u32> = function.blocks.iter().map(|b| b.id).collect();
        let mut id_to_index: HashMap<u32, usize> = HashMap::with_capacity(block_ids.len());
        for (idx, id) in block_ids.iter().copied().enumerate() {
            id_to_index.insert(id, idx);
        }

        let mut succs: Vec<Vec<usize>> = vec![Vec::new(); block_ids.len()];
        for (idx, block) in function.blocks.iter().enumerate() {
            match block.term {
                Terminator::Jump(target) => {
                    if let Some(&target_idx) = id_to_index.get(&target) {
                        succs[idx].push(target_idx);
                    }
                }
                Terminator::Branch {
                    true_bb, false_bb, ..
                } => {
                    if let Some(&true_idx) = id_to_index.get(&true_bb) {
                        succs[idx].push(true_idx);
                    }
                    if let Some(&false_idx) = id_to_index.get(&false_bb) {
                        succs[idx].push(false_idx);
                    }
                }
                Terminator::Return(_) | Terminator::UnsupportedControlFlow { .. } => {}
            }
        }
        for out in &mut succs {
            out.sort_unstable();
            out.dedup();
        }

        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); block_ids.len()];
        for (from, outs) in succs.iter().enumerate() {
            for &to in outs {
                preds[to].push(from);
            }
        }
        for incoming in &mut preds {
            incoming.sort_unstable();
            incoming.dedup();
        }

        Self {
            block_ids,
            id_to_index,
            succs,
            preds,
            entry: 0,
        }
    }

    fn reachable_rpo(&self) -> (Vec<bool>, Vec<usize>) {
        let n = self.block_ids.len();
        let mut reachable = vec![false; n];
        let mut rpo = Vec::new();
        if n == 0 {
            return (reachable, rpo);
        }

        let mut postorder: Vec<usize> = Vec::new();
        let mut stack: Vec<(usize, usize)> = vec![(self.entry, 0)];
        reachable[self.entry] = true;

        while let Some((node, next_idx)) = stack.pop() {
            if next_idx < self.succs[node].len() {
                stack.push((node, next_idx + 1));
                let succ = self.succs[node][next_idx];
                if !reachable[succ] {
                    reachable[succ] = true;
                    stack.push((succ, 0));
                }
            } else {
                postorder.push(node);
            }
        }

        postorder.reverse();
        rpo.extend(postorder);
        if let Some(pos) = rpo.iter().position(|&b| b == self.entry) {
            if pos != 0 {
                rpo.remove(pos);
                rpo.insert(0, self.entry);
            }
        }
        (reachable, rpo)
    }
}

fn intersect_idom(
    mut left: usize,
    mut right: usize,
    idom: &[Option<usize>],
    rpo_rank: &[usize],
) -> usize {
    while left != right {
        while rpo_rank[left] > rpo_rank[right] {
            left = idom[left].unwrap_or(left);
        }
        while rpo_rank[right] > rpo_rank[left] {
            right = idom[right].unwrap_or(right);
        }
    }
    left
}

fn number_dom_tree(
    node: usize,
    children: &[Vec<usize>],
    pre: &mut [u32],
    post: &mut [u32],
    tick: &mut u32,
) {
    *tick = tick.saturating_add(1);
    pre[node] = *tick;
    for &child in &children[node] {
        number_dom_tree(child, children, pre, post, tick);
    }
    *tick = tick.saturating_add(1);
    post[node] = *tick;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DominatorTree {
    entry: u32,
    block_ids: Vec<u32>,
    id_to_index: HashMap<u32, usize>,
    reachable: Vec<bool>,
    idom: Vec<Option<usize>>,
    dom_children: Vec<Vec<usize>>,
    dom_pre: Vec<u32>,
    dom_post: Vec<u32>,
    rpo: Vec<usize>,
}

impl DominatorTree {
    fn from_cfg(cfg: Cfg) -> Self {
        let n = cfg.block_ids.len();
        if n == 0 {
            return Self {
                entry: 0,
                block_ids: cfg.block_ids,
                id_to_index: cfg.id_to_index,
                reachable: Vec::new(),
                idom: Vec::new(),
                dom_children: Vec::new(),
                dom_pre: Vec::new(),
                dom_post: Vec::new(),
                rpo: Vec::new(),
            };
        }

        let (reachable, rpo) = cfg.reachable_rpo();
        let mut idom: Vec<Option<usize>> = vec![None; n];
        idom[cfg.entry] = Some(cfg.entry);

        let mut rpo_rank = vec![usize::MAX; n];
        for (rank, &bb) in rpo.iter().enumerate() {
            rpo_rank[bb] = rank;
        }

        let mut changed = true;
        while changed {
            changed = false;
            for &bb in rpo.iter().skip(1) {
                let mut preds = cfg.preds[bb]
                    .iter()
                    .copied()
                    .filter(|p| reachable[*p] && idom[*p].is_some());
                let Some(mut new_idom) = preds.next() else {
                    continue;
                };
                for pred in preds {
                    new_idom = intersect_idom(pred, new_idom, &idom, &rpo_rank);
                }
                if idom[bb] != Some(new_idom) {
                    idom[bb] = Some(new_idom);
                    changed = true;
                }
            }
        }
        idom[cfg.entry] = None;

        let mut dom_children: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (bb, parent) in idom.iter().enumerate() {
            if let Some(parent) = *parent {
                dom_children[parent].push(bb);
            }
        }
        for children in &mut dom_children {
            children.sort_by_key(|idx| cfg.block_ids[*idx]);
        }

        let mut dom_pre = vec![0u32; n];
        let mut dom_post = vec![0u32; n];
        let mut tick = 0u32;
        if reachable[cfg.entry] {
            number_dom_tree(
                cfg.entry,
                &dom_children,
                &mut dom_pre,
                &mut dom_post,
                &mut tick,
            );
        }

        Self {
            entry: cfg.block_ids[cfg.entry],
            block_ids: cfg.block_ids,
            id_to_index: cfg.id_to_index,
            reachable,
            idom,
            dom_children,
            dom_pre,
            dom_post,
            rpo,
        }
    }

    pub fn entry(&self) -> u32 {
        self.entry
    }

    pub fn reverse_postorder(&self) -> Vec<u32> {
        self.rpo
            .iter()
            .map(|idx| self.block_ids[*idx])
            .collect::<Vec<_>>()
    }

    pub fn is_reachable(&self, block: u32) -> bool {
        self.id_to_index
            .get(&block)
            .map(|idx| self.reachable[*idx])
            .unwrap_or(false)
    }

    pub fn immediate_dominator(&self, block: u32) -> Option<u32> {
        let idx = *self.id_to_index.get(&block)?;
        self.idom[idx].map(|dom_idx| self.block_ids[dom_idx])
    }

    pub fn dominates(&self, dominator: u32, node: u32) -> bool {
        let Some(&dom_idx) = self.id_to_index.get(&dominator) else {
            return false;
        };
        let Some(&node_idx) = self.id_to_index.get(&node) else {
            return false;
        };
        if !self.reachable[dom_idx] || !self.reachable[node_idx] {
            return false;
        }
        self.dom_pre[dom_idx] <= self.dom_pre[node_idx]
            && self.dom_post[node_idx] <= self.dom_post[dom_idx]
    }

    pub fn dom_children(&self, block: u32) -> Option<Vec<u32>> {
        let idx = *self.id_to_index.get(&block)?;
        Some(
            self.dom_children[idx]
                .iter()
                .map(|child| self.block_ids[*child])
                .collect(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DominanceFrontier {
    block_ids: Vec<u32>,
    id_to_index: HashMap<u32, usize>,
    frontiers: Vec<Vec<u32>>,
}

impl DominanceFrontier {
    pub fn frontier(&self, block: u32) -> Option<&[u32]> {
        let idx = *self.id_to_index.get(&block)?;
        Some(&self.frontiers[idx])
    }
}

pub fn compute_dominator_tree(function: &Function) -> DominatorTree {
    DominatorTree::from_cfg(Cfg::from_function(function))
}

pub fn compute_dominance_frontier(
    function: &Function,
    dom_tree: &DominatorTree,
) -> Result<DominanceFrontier, String> {
    let cfg = Cfg::from_function(function);
    if cfg.block_ids != dom_tree.block_ids {
        return Err(
            "dominance frontier input mismatch: dominator tree and function blocks differ".into(),
        );
    }

    let n = cfg.block_ids.len();
    let mut frontier_sets: Vec<BTreeSet<u32>> = vec![BTreeSet::new(); n];
    for bb in 0..n {
        if !dom_tree.reachable[bb] {
            continue;
        }
        let live_preds: Vec<usize> = cfg.preds[bb]
            .iter()
            .copied()
            .filter(|pred| dom_tree.reachable[*pred])
            .collect();
        if live_preds.len() < 2 {
            continue;
        }
        for pred in live_preds {
            let mut runner = Some(pred);
            while let Some(node) = runner {
                if Some(node) == dom_tree.idom[bb] {
                    break;
                }
                frontier_sets[node].insert(cfg.block_ids[bb]);
                runner = dom_tree.idom[node];
            }
        }
    }

    let frontiers = frontier_sets
        .into_iter()
        .map(|set| set.into_iter().collect::<Vec<_>>())
        .collect::<Vec<_>>();

    Ok(DominanceFrontier {
        block_ids: cfg.block_ids,
        id_to_index: cfg.id_to_index,
        frontiers,
    })
}

#[derive(Clone, Copy, Debug)]
enum DefSite {
    Param,
    Inst {
        block_idx: usize,
        inst_idx: usize,
        is_phi: bool,
    },
}

fn inst_produces_value(kind: &InstKind) -> bool {
    !matches!(kind, InstKind::Emit { .. })
}

fn block_dominates_block(dom: &DominatorTree, cfg: &Cfg, lhs_idx: usize, rhs_idx: usize) -> bool {
    dom.dominates(cfg.block_ids[lhs_idx], cfg.block_ids[rhs_idx])
}

fn def_dominates_inst_use(
    def: DefSite,
    use_block_idx: usize,
    use_inst_idx: usize,
    dom: &DominatorTree,
    cfg: &Cfg,
) -> bool {
    match def {
        DefSite::Param => true,
        DefSite::Inst {
            block_idx,
            inst_idx,
            is_phi,
        } => {
            if block_idx == use_block_idx {
                is_phi || inst_idx < use_inst_idx
            } else {
                block_dominates_block(dom, cfg, block_idx, use_block_idx)
            }
        }
    }
}

fn def_dominates_term_use(
    def: DefSite,
    use_block_idx: usize,
    dom: &DominatorTree,
    cfg: &Cfg,
) -> bool {
    match def {
        DefSite::Param => true,
        DefSite::Inst { block_idx, .. } => {
            if block_idx == use_block_idx {
                true
            } else {
                block_dominates_block(dom, cfg, block_idx, use_block_idx)
            }
        }
    }
}

fn def_dominates_phi_edge(
    def: DefSite,
    pred_block_idx: usize,
    dom: &DominatorTree,
    cfg: &Cfg,
) -> bool {
    match def {
        DefSite::Param => true,
        DefSite::Inst { block_idx, .. } => {
            if block_idx == pred_block_idx {
                true
            } else {
                block_dominates_block(dom, cfg, block_idx, pred_block_idx)
            }
        }
    }
}

pub fn verify_function_ssa(function: &Function) -> Result<(), Vec<String>> {
    let mut errors: Vec<String> = Vec::new();
    if function.blocks.is_empty() {
        errors.push("function has no blocks".into());
        return Err(errors);
    }
    if function.params.len() != function.param_values.len() {
        errors.push(format!(
            "param/value mismatch: {} params vs {} param values",
            function.params.len(),
            function.param_values.len()
        ));
    }

    let cfg = Cfg::from_function(function);
    let dom = compute_dominator_tree(function);

    let mut block_seen: HashMap<u32, usize> = HashMap::new();
    for (idx, block) in function.blocks.iter().enumerate() {
        if let Some(prev_idx) = block_seen.insert(block.id, idx) {
            errors.push(format!(
                "duplicate block id b{} at indices {} and {}",
                block.id, prev_idx, idx
            ));
        }
    }

    for block in &function.blocks {
        match &block.term {
            Terminator::Jump(target) => {
                if !cfg.id_to_index.contains_key(target) {
                    errors.push(format!(
                        "b{} jump target b{} does not exist",
                        block.id, target
                    ));
                }
            }
            Terminator::Branch {
                true_bb, false_bb, ..
            } => {
                if !cfg.id_to_index.contains_key(true_bb) {
                    errors.push(format!(
                        "b{} branch true target b{} does not exist",
                        block.id, true_bb
                    ));
                }
                if !cfg.id_to_index.contains_key(false_bb) {
                    errors.push(format!(
                        "b{} branch false target b{} does not exist",
                        block.id, false_bb
                    ));
                }
            }
            Terminator::UnsupportedControlFlow { ip, op } => {
                errors.push(format!(
                    "b{} has unsupported control flow @{} ({})",
                    block.id, ip, op
                ));
            }
            Terminator::Return(_) => {}
        }
    }

    let mut defs: HashMap<ValueId, DefSite> = HashMap::new();
    for (idx, value) in function.param_values.iter().copied().enumerate() {
        if defs.insert(value, DefSite::Param).is_some() {
            errors.push(format!(
                "duplicate value definition v{} in params (at param {})",
                value.0, idx
            ));
        }
    }

    for (block_idx, block) in function.blocks.iter().enumerate() {
        let mut saw_non_phi = false;
        let mut phi_vars: HashSet<&str> = HashSet::new();
        for (inst_idx, inst) in block.insts.iter().enumerate() {
            let is_phi = matches!(inst.kind, InstKind::Phi { .. });
            if is_phi {
                if saw_non_phi {
                    errors.push(format!(
                        "b{} has phi after non-phi instruction (inst {})",
                        block.id, inst_idx
                    ));
                }
                if let InstKind::Phi { var, .. } = &inst.kind {
                    if !phi_vars.insert(var.as_str()) {
                        errors.push(format!("b{} has duplicate phi for var '{}'", block.id, var));
                    }
                }
            } else {
                saw_non_phi = true;
            }

            if inst_produces_value(&inst.kind) {
                let Some(id) = inst.id else {
                    errors.push(format!(
                        "b{} inst {} ({:?}) is value-producing but has no id",
                        block.id, inst_idx, inst.kind
                    ));
                    continue;
                };
                let site = DefSite::Inst {
                    block_idx,
                    inst_idx,
                    is_phi,
                };
                if defs.insert(id, site).is_some() {
                    errors.push(format!("duplicate value definition v{}", id.0));
                }
            } else if inst.id.is_some() {
                errors.push(format!(
                    "b{} inst {} ({:?}) should not define value id",
                    block.id, inst_idx, inst.kind
                ));
            }
        }
    }

    for (block_idx, block) in function.blocks.iter().enumerate() {
        let block_reachable = dom.is_reachable(block.id);
        for (inst_idx, inst) in block.insts.iter().enumerate() {
            if matches!(inst.kind, InstKind::Phi { .. }) {
                continue;
            }
            for input in inst_inputs(&inst.kind) {
                let Some(def_site) = defs.get(&input).copied() else {
                    errors.push(format!(
                        "b{} inst {} uses undefined value v{}",
                        block.id, inst_idx, input.0
                    ));
                    continue;
                };
                if block_reachable
                    && !def_dominates_inst_use(def_site, block_idx, inst_idx, &dom, &cfg)
                {
                    errors.push(format!(
                        "b{} inst {} uses v{} before dominating def",
                        block.id, inst_idx, input.0
                    ));
                }
            }
        }

        match block.term {
            Terminator::Return(Some(v)) => {
                let Some(def_site) = defs.get(&v).copied() else {
                    errors.push(format!("b{} return uses undefined v{}", block.id, v.0));
                    continue;
                };
                if block_reachable && !def_dominates_term_use(def_site, block_idx, &dom, &cfg) {
                    errors.push(format!(
                        "b{} return uses v{} without dominating def",
                        block.id, v.0
                    ));
                }
            }
            Terminator::Branch { cond, .. } => {
                let Some(def_site) = defs.get(&cond).copied() else {
                    errors.push(format!("b{} branch uses undefined v{}", block.id, cond.0));
                    continue;
                };
                if block_reachable && !def_dominates_term_use(def_site, block_idx, &dom, &cfg) {
                    errors.push(format!(
                        "b{} branch cond v{} has no dominating def",
                        block.id, cond.0
                    ));
                }
            }
            Terminator::Return(None)
            | Terminator::Jump(_)
            | Terminator::UnsupportedControlFlow { .. } => {}
        }
    }

    for (block_idx, block) in function.blocks.iter().enumerate() {
        let pred_indices = &cfg.preds[block_idx];
        let pred_ids: BTreeSet<u32> = pred_indices
            .iter()
            .map(|pred_idx| cfg.block_ids[*pred_idx])
            .collect();

        for (inst_idx, inst) in block.insts.iter().enumerate() {
            let InstKind::Phi { var, inputs } = &inst.kind else {
                break;
            };
            let mut seen_preds: BTreeSet<u32> = BTreeSet::new();
            for (pred, value) in inputs {
                if !pred_ids.contains(pred) {
                    errors.push(format!(
                        "b{} phi '{}' has non-predecessor input from b{}",
                        block.id, var, pred
                    ));
                }
                if !seen_preds.insert(*pred) {
                    errors.push(format!(
                        "b{} phi '{}' has duplicate input from b{}",
                        block.id, var, pred
                    ));
                }
                let Some(def_site) = defs.get(value).copied() else {
                    errors.push(format!(
                        "b{} phi '{}' input from b{} uses undefined v{}",
                        block.id, var, pred, value.0
                    ));
                    continue;
                };
                if dom.is_reachable(block.id) && dom.is_reachable(*pred) {
                    if let Some(&pred_idx) = cfg.id_to_index.get(pred) {
                        if !def_dominates_phi_edge(def_site, pred_idx, &dom, &cfg) {
                            errors.push(format!(
                                "b{} phi '{}' input from b{} uses non-dominating v{}",
                                block.id, var, pred, value.0
                            ));
                        }
                    } else {
                        errors.push(format!(
                            "b{} phi '{}' refers unknown predecessor b{} in verifier",
                            block.id, var, pred
                        ));
                    }
                }
            }
            if seen_preds.len() != pred_ids.len() {
                errors.push(format!(
                    "b{} phi '{}' has {} inputs, expected {} (inst {})",
                    block.id,
                    var,
                    seen_preds.len(),
                    pred_ids.len(),
                    inst_idx
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

pub fn verify_program_ssa(program: &Program) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    for function in program.iter_functions() {
        if !matches!(function.status, BuildStatus::Lowered) {
            continue;
        }
        if let Err(func_errors) = verify_function_ssa(function) {
            for err in func_errors {
                errors.push(format!("{}: {}", function.name, err));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn construct_ssa_phi_rename(function: &mut Function) -> Result<(), String> {
    let dom = compute_dominator_tree(function);
    let df = compute_dominance_frontier(function, &dom)?;
    place_phi_nodes(function, &df);
    rename_phi_uses_and_defs(function, &dom)?;
    Ok(())
}

fn place_phi_nodes(function: &mut Function, df: &DominanceFrontier) -> bool {
    if function.blocks.is_empty() {
        return false;
    }
    let entry = function.blocks[0].id;
    let mut def_blocks: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    for name in &function.params {
        def_blocks.entry(name.clone()).or_default().insert(entry);
    }
    for block in &function.blocks {
        for op in &block.var_ops {
            if let VarOp::Store { name, .. } = op {
                def_blocks.entry(name.clone()).or_default().insert(block.id);
            }
        }
        for inst in &block.insts {
            if let InstKind::Phi { var, .. } = &inst.kind {
                def_blocks.entry(var.clone()).or_default().insert(block.id);
            }
        }
    }

    let mut phi_sites: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    for (var, defs) in &def_blocks {
        let mut has_phi: BTreeSet<u32> = BTreeSet::new();
        let mut work: Vec<u32> = defs.iter().copied().collect();
        while let Some(block) = work.pop() {
            let Some(frontier) = df.frontier(block) else {
                continue;
            };
            for &join in frontier {
                if has_phi.insert(join) {
                    phi_sites.entry(join).or_default().insert(var.clone());
                    if !defs.contains(&join) {
                        work.push(join);
                    }
                }
            }
        }
    }

    let mut block_index_by_id: HashMap<u32, usize> = HashMap::with_capacity(function.blocks.len());
    for (idx, block) in function.blocks.iter().enumerate() {
        block_index_by_id.insert(block.id, idx);
    }

    let mut changed = false;
    for (block_id, vars) in phi_sites {
        let Some(&block_idx) = block_index_by_id.get(&block_id) else {
            continue;
        };
        let block = &mut function.blocks[block_idx];
        let mut existing: BTreeSet<String> = block
            .insts
            .iter()
            .filter_map(|inst| match &inst.kind {
                InstKind::Phi { var, .. } => Some(var.clone()),
                _ => None,
            })
            .collect();
        let mut insert_at = block
            .insts
            .iter()
            .take_while(|inst| matches!(inst.kind, InstKind::Phi { .. }))
            .count();
        for var in vars {
            if existing.contains(&var) {
                continue;
            }
            block.insts.insert(
                insert_at,
                Inst::new(
                    None,
                    InstKind::Phi {
                        var: var.clone(),
                        inputs: Vec::new(),
                    },
                ),
            );
            existing.insert(var);
            insert_at += 1;
            changed = true;
        }
    }
    changed
}

fn rename_phi_uses_and_defs(function: &mut Function, dom: &DominatorTree) -> Result<(), String> {
    let has_var_ops = function.blocks.iter().any(|b| !b.var_ops.is_empty());
    let has_phi = function.blocks.iter().any(|b| {
        b.insts
            .iter()
            .any(|inst| matches!(inst.kind, InstKind::Phi { .. }))
    });
    if !has_var_ops && !has_phi {
        return Ok(());
    }
    if function.blocks.is_empty() {
        return Ok(());
    }

    let cfg = Cfg::from_function(function);
    let mut block_index_by_id: HashMap<u32, usize> = HashMap::with_capacity(function.blocks.len());
    for (idx, block) in function.blocks.iter().enumerate() {
        block_index_by_id.insert(block.id, idx);
    }
    let entry_id = dom.entry();
    let Some(&entry_idx) = block_index_by_id.get(&entry_id) else {
        return Err("missing entry block for rename".into());
    };

    let mut next_value = function
        .param_values
        .iter()
        .map(|v| v.0)
        .chain(
            function
                .blocks
                .iter()
                .flat_map(|block| block.insts.iter().filter_map(|inst| inst.id.map(|v| v.0))),
        )
        .max()
        .map(|v| v.saturating_add(1))
        .unwrap_or(0);

    for block in &mut function.blocks {
        for inst in &mut block.insts {
            if let InstKind::Phi { inputs, .. } = &mut inst.kind {
                inputs.clear();
            }
        }
    }

    let null_value = {
        let id = ValueId(next_value);
        next_value = next_value.saturating_add(1);
        let insert_at = function.blocks[entry_idx]
            .insts
            .iter()
            .take_while(|inst| matches!(inst.kind, InstKind::Phi { .. }))
            .count();
        function.blocks[entry_idx].insts.insert(
            insert_at,
            Inst::new(Some(id), InstKind::Const(ConstValue::Null)),
        );
        id
    };

    let mut id_to_pos: HashMap<ValueId, (usize, usize)> = HashMap::new();
    for (block_idx, block) in function.blocks.iter().enumerate() {
        for (inst_idx, inst) in block.insts.iter().enumerate() {
            if let Some(id) = inst.id {
                id_to_pos.insert(id, (block_idx, inst_idx));
            }
        }
    }

    let mut stacks: HashMap<String, Vec<ValueId>> = HashMap::new();
    for (name, id) in function
        .params
        .iter()
        .cloned()
        .zip(function.param_values.iter().copied())
    {
        stacks.entry(name).or_default().push(id);
    }

    struct Renamer<'a> {
        function: &'a mut Function,
        dom: &'a DominatorTree,
        cfg: &'a Cfg,
        block_index_by_id: &'a HashMap<u32, usize>,
        id_to_pos: &'a mut HashMap<ValueId, (usize, usize)>,
        stacks: &'a mut HashMap<String, Vec<ValueId>>,
        next_value: &'a mut u32,
        null_value: ValueId,
    }

    impl<'a> Renamer<'a> {
        fn top_or_null(&self, name: &str) -> ValueId {
            self.stacks
                .get(name)
                .and_then(|stack| stack.last().copied())
                .unwrap_or(self.null_value)
        }

        fn dfs(&mut self, block_id: u32) -> Result<(), String> {
            if !self.dom.is_reachable(block_id) {
                return Ok(());
            }
            let Some(&block_idx) = self.block_index_by_id.get(&block_id) else {
                return Err(format!("missing block id {} during rename", block_id));
            };

            let mut pushed: Vec<String> = Vec::new();

            {
                let block = &mut self.function.blocks[block_idx];
                for (inst_idx, inst) in block.insts.iter_mut().enumerate() {
                    let InstKind::Phi { var, .. } = &inst.kind else {
                        break;
                    };
                    let phi_var = var.clone();
                    let phi_id = if let Some(id) = inst.id {
                        id
                    } else {
                        let id = ValueId(*self.next_value);
                        *self.next_value = self.next_value.saturating_add(1);
                        inst.id = Some(id);
                        self.id_to_pos.insert(id, (block_idx, inst_idx));
                        id
                    };
                    self.stacks.entry(phi_var.clone()).or_default().push(phi_id);
                    pushed.push(phi_var);
                }
            }

            let var_ops = std::mem::take(&mut self.function.blocks[block_idx].var_ops);
            for op in var_ops {
                match op {
                    VarOp::Load { name, out } => {
                        let current = self.top_or_null(&name);
                        let Some((owner_block, owner_inst)) = self.id_to_pos.get(&out).copied()
                        else {
                            return Err(format!("cannot find load value v{} for {}", out.0, name));
                        };
                        let inst = &mut self.function.blocks[owner_block].insts[owner_inst];
                        match &mut inst.kind {
                            InstKind::Alias(src) => {
                                *src = current;
                            }
                            _ => {
                                return Err(format!(
                                    "load value v{} is not alias instruction in {}",
                                    out.0, name
                                ));
                            }
                        }
                    }
                    VarOp::Store { name, value } => {
                        self.stacks.entry(name.clone()).or_default().push(value);
                        pushed.push(name);
                    }
                }
            }

            let succs = self.cfg.succs[block_idx].clone();
            for succ_idx in succs {
                let mut updates: Vec<(usize, ValueId)> = Vec::new();
                {
                    let succ = &self.function.blocks[succ_idx];
                    for (inst_idx, inst) in succ.insts.iter().enumerate() {
                        let InstKind::Phi { var, .. } = &inst.kind else {
                            break;
                        };
                        updates.push((inst_idx, self.top_or_null(var)));
                    }
                }
                let succ = &mut self.function.blocks[succ_idx];
                for (inst_idx, value) in updates {
                    if let InstKind::Phi { inputs, .. } = &mut succ.insts[inst_idx].kind {
                        if let Some((_, existing)) =
                            inputs.iter_mut().find(|(pred, _)| *pred == block_id)
                        {
                            *existing = value;
                        } else {
                            inputs.push((block_id, value));
                        }
                        inputs.sort_by_key(|(pred, _)| *pred);
                    }
                }
            }

            if let Some(children) = self.dom.dom_children(block_id) {
                for child in children {
                    self.dfs(child)?;
                }
            }

            for var in pushed.into_iter().rev() {
                let mut remove = false;
                if let Some(stack) = self.stacks.get_mut(&var) {
                    let _ = stack.pop();
                    remove = stack.is_empty();
                }
                if remove {
                    self.stacks.remove(&var);
                }
            }

            Ok(())
        }
    }

    {
        let mut renamer = Renamer {
            function,
            dom,
            cfg: &cfg,
            block_index_by_id: &block_index_by_id,
            id_to_pos: &mut id_to_pos,
            stacks: &mut stacks,
            next_value: &mut next_value,
            null_value,
        };
        renamer.dfs(entry_id)?;
    }

    for block in &mut function.blocks {
        for inst in &mut block.insts {
            if matches!(inst.kind, InstKind::Phi { .. }) && inst.id.is_none() {
                let id = ValueId(next_value);
                next_value = next_value.saturating_add(1);
                inst.id = Some(id);
            }
        }
        // Var ops are construction metadata and are not needed after SSA rename.
        block.var_ops.clear();
    }

    Ok(())
}

fn binop_from_ir(instr: &IRInstr) -> Option<BinOp> {
    match instr {
        IRInstr::Add => Some(BinOp::Add),
        IRInstr::Sub => Some(BinOp::Sub),
        IRInstr::Mul => Some(BinOp::Mul),
        IRInstr::Div => Some(BinOp::Div),
        IRInstr::Mod => Some(BinOp::Mod),
        IRInstr::Xor => Some(BinOp::Xor),
        IRInstr::Shl => Some(BinOp::Shl),
        IRInstr::Eq => Some(BinOp::Eq),
        IRInstr::Ne => Some(BinOp::Ne),
        IRInstr::Gt => Some(BinOp::Gt),
        IRInstr::Ge => Some(BinOp::Ge),
        IRInstr::Lt => Some(BinOp::Lt),
        IRInstr::Le => Some(BinOp::Le),
        IRInstr::And => Some(BinOp::And),
        IRInstr::Or => Some(BinOp::Or),
        _ => None,
    }
}

fn emit_kind_from_ir(instr: &IRInstr) -> Option<EmitKind> {
    match instr {
        IRInstr::EmitSay => Some(EmitKind::Say),
        IRInstr::EmitAsk => Some(EmitKind::Ask),
        IRInstr::EmitFetch => Some(EmitKind::Fetch),
        IRInstr::EmitText => Some(EmitKind::Text),
        IRInstr::EmitButton => Some(EmitKind::Button),
        IRInstr::EmitLog => Some(EmitKind::Log),
        _ => None,
    }
}

pub trait SsaPass {
    fn name(&self) -> &'static str;
    fn run(&mut self, function: &mut Function) -> bool;
}

pub struct PassManager {
    passes: Vec<Box<dyn SsaPass>>,
}

impl Default for PassManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PassManager {
    pub fn new() -> Self {
        Self { passes: Vec::new() }
    }

    pub fn with_default_pipeline() -> Self {
        let mut pm = Self::new();
        pm.add_pass(Mem2RegPass);
        pm.add_pass(SccpPass);
        pm.add_pass(ConstFoldPass);
        pm.add_pass(DeadInstElimPass);
        pm
    }

    pub fn add_pass<P: SsaPass + 'static>(&mut self, pass: P) {
        self.passes.push(Box::new(pass));
    }

    pub fn run_program(&mut self, program: &mut Program) -> Vec<String> {
        let mut log = Vec::new();
        for function in program.iter_functions_mut() {
            if !matches!(function.status, BuildStatus::Lowered) {
                continue;
            }
            for pass in &mut self.passes {
                let changed = pass.run(function);
                if changed {
                    log.push(format!("{}:{}", function.name, pass.name()));
                }
            }
        }
        log
    }
}

pub struct Mem2RegPass;

impl SsaPass for Mem2RegPass {
    fn name(&self) -> &'static str {
        "mem2reg"
    }

    fn run(&mut self, function: &mut Function) -> bool {
        let mut alias_parent: HashMap<ValueId, ValueId> = HashMap::new();
        for block in &function.blocks {
            for inst in &block.insts {
                if let (Some(id), InstKind::Alias(src)) = (inst.id, &inst.kind) {
                    if id != *src {
                        alias_parent.insert(id, *src);
                    }
                }
            }
        }
        if alias_parent.is_empty() {
            return false;
        }

        let mut cache: HashMap<ValueId, ValueId> = HashMap::new();
        let mut changed = false;
        for block in &mut function.blocks {
            for inst in &mut block.insts {
                changed |= rewrite_inst_ids(&mut inst.kind, &alias_parent, &mut cache);
            }
            changed |= rewrite_term_ids(&mut block.term, &alias_parent, &mut cache);
        }
        changed
    }
}

fn canonical_alias_value(
    value: ValueId,
    parent: &HashMap<ValueId, ValueId>,
    cache: &mut HashMap<ValueId, ValueId>,
) -> ValueId {
    if let Some(root) = cache.get(&value).copied() {
        return root;
    }

    let mut chain: Vec<ValueId> = Vec::new();
    let mut cur = value;
    let mut budget = parent.len().saturating_add(1);
    while let Some(next) = parent.get(&cur).copied() {
        if next == cur {
            break;
        }
        chain.push(cur);
        if let Some(cached) = cache.get(&next).copied() {
            cur = cached;
            break;
        }
        cur = next;
        if budget == 0 {
            break;
        }
        budget -= 1;
    }

    for id in chain {
        cache.insert(id, cur);
    }
    cache.entry(value).or_insert(cur);
    cur
}

fn rewrite_value_id(
    slot: &mut ValueId,
    parent: &HashMap<ValueId, ValueId>,
    cache: &mut HashMap<ValueId, ValueId>,
) -> bool {
    let root = canonical_alias_value(*slot, parent, cache);
    if root != *slot {
        *slot = root;
        true
    } else {
        false
    }
}

fn rewrite_inst_ids(
    kind: &mut InstKind,
    parent: &HashMap<ValueId, ValueId>,
    cache: &mut HashMap<ValueId, ValueId>,
) -> bool {
    match kind {
        InstKind::Const(_) => false,
        InstKind::Alias(v) => rewrite_value_id(v, parent, cache),
        InstKind::Phi { inputs, .. } => {
            let mut changed = false;
            for (_, v) in inputs {
                changed |= rewrite_value_id(v, parent, cache);
            }
            changed
        }
        InstKind::BinOp { lhs, rhs, .. } => {
            rewrite_value_id(lhs, parent, cache) | rewrite_value_id(rhs, parent, cache)
        }
        InstKind::CallBuiltin { args, .. } | InstKind::CallFn { args, .. } => {
            let mut changed = false;
            for arg in args {
                changed |= rewrite_value_id(arg, parent, cache);
            }
            changed
        }
        InstKind::MakeList(values) => {
            let mut changed = false;
            for value in values {
                changed |= rewrite_value_id(value, parent, cache);
            }
            changed
        }
        InstKind::MakeMap { values, .. } => {
            let mut changed = false;
            for value in values {
                changed |= rewrite_value_id(value, parent, cache);
            }
            changed
        }
        InstKind::LoadField { base, .. } => rewrite_value_id(base, parent, cache),
        InstKind::Emit { arg, .. } => {
            if let Some(v) = arg {
                rewrite_value_id(v, parent, cache)
            } else {
                false
            }
        }
    }
}

fn rewrite_term_ids(
    term: &mut Terminator,
    parent: &HashMap<ValueId, ValueId>,
    cache: &mut HashMap<ValueId, ValueId>,
) -> bool {
    match term {
        Terminator::Return(Some(v)) => rewrite_value_id(v, parent, cache),
        Terminator::Branch { cond, .. } => rewrite_value_id(cond, parent, cache),
        _ => false,
    }
}

#[derive(Clone, Debug, PartialEq)]
enum ValueFact {
    Unknown,
    Const(ConstValue),
}

#[derive(Clone, Debug, PartialEq)]
struct ConstFact {
    fact: ValueFact,
    proof: ProofSlot,
}

impl ConstFact {
    fn unknown_with_proof(proof: ProofSlot) -> Self {
        Self {
            fact: ValueFact::Unknown,
            proof,
        }
    }

    fn constant(value: ConstValue, proof: ProofSlot) -> Self {
        Self {
            fact: ValueFact::Const(value),
            proof,
        }
    }
}

fn parse_proven_const_token(token: &str) -> Option<ConstValue> {
    let token = token.trim();
    let lower = token.to_ascii_lowercase();
    match lower.as_str() {
        "true" => Some(ConstValue::Bool(true)),
        "false" => Some(ConstValue::Bool(false)),
        "null" => Some(ConstValue::Null),
        _ => token.parse::<f64>().ok().map(ConstValue::Num),
    }
}

fn const_value_from_proof(proof: &ProofSlot) -> Option<ConstValue> {
    if let Some(exact) = proof
        .numeric
        .or_else(|| proof.numeric_fallback())
        .and_then(|n| n.exact)
    {
        return Some(ConstValue::Num(exact as f64));
    }
    let refined = proof.refined_type.as_ref()?;
    let pred = refined.predicate.as_ref()?.replace(' ', "");
    if let Some(rhs) = pred.strip_prefix("v==") {
        return parse_proven_const_token(rhs);
    }
    if let Some(lhs) = pred.strip_suffix("==v") {
        return parse_proven_const_token(lhs);
    }
    None
}

fn refined_type_for_const(value: &ConstValue) -> RefinedType {
    match value {
        ConstValue::Num(n) => RefinedType {
            base: Type::Num,
            predicate: Some(format!("v == {}", n)),
        },
        ConstValue::Bool(b) => RefinedType {
            base: Type::Bool,
            predicate: Some(format!("v == {}", b)),
        },
        ConstValue::Text(_) => RefinedType {
            base: Type::Text,
            predicate: None,
        },
        ConstValue::Null => RefinedType {
            base: Type::Null,
            predicate: Some("v == null".into()),
        },
    }
}

fn numeric_proof_for_const(value: &ConstValue) -> Option<NumericProof> {
    match value {
        ConstValue::Num(n) if n.fract().abs() < f64::EPSILON => {
            Some(NumericProof::from_exact(*n as i64))
        }
        ConstValue::Num(n) => Some(NumericProof {
            exact: None,
            range: None,
            nonzero: n.abs() > f64::EPSILON,
        }),
        ConstValue::Bool(b) => Some(NumericProof::from_exact(i64::from(*b))),
        ConstValue::Null => Some(NumericProof::from_exact(0)),
        ConstValue::Text(_) => None,
    }
}

fn sum_cost_bounds(bounds: &[Option<&CostBound>]) -> Option<CostBound> {
    fn sum_field(values: impl Iterator<Item = Option<u32>>) -> Option<u32> {
        let mut saw_any = false;
        let mut acc = 0_u32;
        for value in values.flatten() {
            saw_any = true;
            acc = acc.saturating_add(value);
        }
        saw_any.then_some(acc)
    }

    let collected = bounds
        .iter()
        .filter_map(|bound| bound.as_ref().copied())
        .collect::<Vec<_>>();
    if collected.is_empty() {
        return None;
    }
    Some(CostBound {
        worst_cycles: sum_field(collected.iter().map(|b| b.worst_cycles)),
        alloc_bytes: sum_field(collected.iter().map(|b| b.alloc_bytes)),
        mem_reads: sum_field(collected.iter().map(|b| b.mem_reads)),
        mem_writes: sum_field(collected.iter().map(|b| b.mem_writes)),
    })
}

fn merge_folded_const_proof(
    value: &ConstValue,
    inst_proof: &ProofSlot,
    lhs_proof: &ProofSlot,
    rhs_proof: &ProofSlot,
) -> ProofSlot {
    ProofSlot {
        refined_type: Some(refined_type_for_const(value)),
        numeric: numeric_proof_for_const(value),
        cost_bound: sum_cost_bounds(&[
            lhs_proof.cost_bound.as_ref(),
            rhs_proof.cost_bound.as_ref(),
        ]),
        coq_cert: inst_proof
            .coq_cert
            .or(lhs_proof.coq_cert)
            .or(rhs_proof.coq_cert),
        aliasing: AliasingClass::NoAlias,
        unsafe_context: inst_proof.unsafe_context
            || lhs_proof.unsafe_context
            || rhs_proof.unsafe_context,
    }
}

fn materialize_proven_const_proof(value: &ConstValue, inst_proof: &ProofSlot) -> ProofSlot {
    ProofSlot {
        refined_type: Some(refined_type_for_const(value)),
        numeric: numeric_proof_for_const(value),
        cost_bound: inst_proof.cost_bound.clone(),
        coq_cert: inst_proof.coq_cert,
        aliasing: AliasingClass::NoAlias,
        unsafe_context: inst_proof.unsafe_context,
    }
}

#[derive(Clone, Debug, PartialEq)]
enum SccpValue {
    Unknown,
    Const(ConstValue),
    Overdefined,
}

fn merge_sccp_value(current: &SccpValue, new: &SccpValue) -> SccpValue {
    match (current, new) {
        (SccpValue::Overdefined, _) | (_, SccpValue::Overdefined) => SccpValue::Overdefined,
        (SccpValue::Unknown, other) => other.clone(),
        (current, SccpValue::Unknown) => current.clone(),
        (SccpValue::Const(lhs), SccpValue::Const(rhs)) if lhs == rhs => {
            SccpValue::Const(lhs.clone())
        }
        (SccpValue::Const(_), SccpValue::Const(_)) => SccpValue::Overdefined,
    }
}

fn const_branch_target(
    cond: &ValueId,
    true_bb: u32,
    false_bb: u32,
    facts: &HashMap<ValueId, SccpValue>,
) -> Option<u32> {
    match facts.get(cond) {
        Some(SccpValue::Const(ConstValue::Bool(true))) => Some(true_bb),
        Some(SccpValue::Const(ConstValue::Bool(false))) => Some(false_bb),
        _ => None,
    }
}

fn executable_successors(
    block_idx: usize,
    function: &Function,
    cfg: &Cfg,
    facts: &HashMap<ValueId, SccpValue>,
) -> Vec<usize> {
    match function.blocks[block_idx].term {
        Terminator::Jump(target) => cfg.id_to_index.get(&target).copied().into_iter().collect(),
        Terminator::Branch {
            cond,
            true_bb,
            false_bb,
        } => {
            if let Some(target) = const_branch_target(&cond, true_bb, false_bb, facts) {
                cfg.id_to_index.get(&target).copied().into_iter().collect()
            } else {
                cfg.succs[block_idx].clone()
            }
        }
        Terminator::Return(_) | Terminator::UnsupportedControlFlow { .. } => Vec::new(),
    }
}

fn edge_is_executable(
    pred_idx: usize,
    succ_idx: usize,
    function: &Function,
    cfg: &Cfg,
    facts: &HashMap<ValueId, SccpValue>,
    reachable: &[bool],
) -> bool {
    reachable.get(pred_idx).copied().unwrap_or(false)
        && executable_successors(pred_idx, function, cfg, facts).contains(&succ_idx)
}

fn fold_sccp_binop(op: BinOp, lhs: &SccpValue, rhs: &SccpValue) -> SccpValue {
    match (lhs, rhs) {
        (SccpValue::Const(lhs), SccpValue::Const(rhs)) => {
            fold_const_binop(op, lhs, rhs).map_or(SccpValue::Overdefined, SccpValue::Const)
        }
        (SccpValue::Overdefined, _) | (_, SccpValue::Overdefined) => SccpValue::Overdefined,
        _ => SccpValue::Unknown,
    }
}

fn evaluate_sccp_inst(
    inst: &Inst,
    block_idx: usize,
    function: &Function,
    cfg: &Cfg,
    facts: &HashMap<ValueId, SccpValue>,
    reachable: &[bool],
) -> SccpValue {
    if let Some(value) = const_value_from_proof(&inst.proof) {
        return SccpValue::Const(value);
    }
    match &inst.kind {
        InstKind::Const(value) => SccpValue::Const(value.clone()),
        InstKind::Alias(src) => facts.get(src).cloned().unwrap_or(SccpValue::Unknown),
        InstKind::Phi { inputs, .. } => {
            let mut merged = SccpValue::Unknown;
            let mut saw_exec_pred = false;
            for (pred, value) in inputs {
                let Some(&pred_idx) = cfg.id_to_index.get(pred) else {
                    continue;
                };
                if !edge_is_executable(pred_idx, block_idx, function, cfg, facts, reachable) {
                    continue;
                }
                saw_exec_pred = true;
                let incoming = facts.get(value).cloned().unwrap_or(SccpValue::Unknown);
                merged = merge_sccp_value(&merged, &incoming);
                if matches!(merged, SccpValue::Overdefined) {
                    break;
                }
            }
            if saw_exec_pred {
                merged
            } else {
                SccpValue::Unknown
            }
        }
        InstKind::BinOp { op, lhs, rhs } => fold_sccp_binop(
            *op,
            facts.get(lhs).unwrap_or(&SccpValue::Unknown),
            facts.get(rhs).unwrap_or(&SccpValue::Unknown),
        ),
        InstKind::CallBuiltin { .. }
        | InstKind::CallFn { .. }
        | InstKind::MakeList(_)
        | InstKind::MakeMap { .. }
        | InstKind::LoadField { .. } => SccpValue::Overdefined,
        InstKind::Emit { .. } => SccpValue::Unknown,
    }
}

fn merge_sccp_const_proof(
    value: &ConstValue,
    inst_proof: &ProofSlot,
    input_proofs: &[ProofSlot],
) -> ProofSlot {
    ProofSlot {
        refined_type: Some(refined_type_for_const(value)),
        numeric: numeric_proof_for_const(value),
        cost_bound: sum_cost_bounds(
            &input_proofs
                .iter()
                .map(|proof| proof.cost_bound.as_ref())
                .collect::<Vec<_>>(),
        ),
        coq_cert: inst_proof
            .coq_cert
            .or_else(|| input_proofs.iter().find_map(|proof| proof.coq_cert)),
        aliasing: AliasingClass::NoAlias,
        unsafe_context: inst_proof.unsafe_context
            || input_proofs.iter().any(|proof| proof.unsafe_context),
    }
}

pub struct SccpPass;

impl SsaPass for SccpPass {
    fn name(&self) -> &'static str {
        "sccp"
    }

    fn run(&mut self, function: &mut Function) -> bool {
        if function.blocks.is_empty() {
            return false;
        }

        let original = function.clone();
        let cfg = Cfg::from_function(&original);
        let mut reachable = vec![false; original.blocks.len()];
        if !reachable.is_empty() {
            reachable[cfg.entry] = true;
        }

        let mut facts: HashMap<ValueId, SccpValue> = HashMap::new();
        for value in &original.param_values {
            facts.insert(*value, SccpValue::Overdefined);
        }

        let mut changed = true;
        while changed {
            changed = false;

            for block_idx in 0..original.blocks.len() {
                if !reachable[block_idx] {
                    continue;
                }
                let block = &original.blocks[block_idx];

                for inst in &block.insts {
                    let Some(id) = inst.id else {
                        continue;
                    };
                    let evaluated =
                        evaluate_sccp_inst(inst, block_idx, &original, &cfg, &facts, &reachable);
                    let entry = facts.entry(id).or_insert(SccpValue::Unknown);
                    let merged = merge_sccp_value(entry, &evaluated);
                    if *entry != merged {
                        *entry = merged;
                        changed = true;
                    }
                }

                for succ_idx in executable_successors(block_idx, &original, &cfg, &facts) {
                    if !reachable[succ_idx] {
                        reachable[succ_idx] = true;
                        changed = true;
                    }
                }
            }
        }

        let mut proof_by_value: HashMap<ValueId, ProofSlot> = HashMap::new();
        for block in &original.blocks {
            for inst in &block.insts {
                if let Some(id) = inst.id {
                    proof_by_value.insert(id, inst.proof.clone());
                }
            }
        }

        let mut changed = false;
        for (block_idx, (block, original_block)) in function
            .blocks
            .iter_mut()
            .zip(original.blocks.iter())
            .enumerate()
        {
            for (inst, original_inst) in block.insts.iter_mut().zip(original_block.insts.iter()) {
                let Some(id) = inst.id else {
                    continue;
                };
                let Some(SccpValue::Const(value)) = facts.get(&id) else {
                    continue;
                };

                let new_proof = match &original_inst.kind {
                    InstKind::Const(_) => {
                        materialize_proven_const_proof(value, &original_inst.proof)
                    }
                    InstKind::Alias(src) => merge_sccp_const_proof(
                        value,
                        &original_inst.proof,
                        &[proof_by_value
                            .get(src)
                            .cloned()
                            .unwrap_or_else(ProofSlot::default)],
                    ),
                    InstKind::Phi { inputs, .. } => {
                        let mut input_proofs = Vec::new();
                        for (pred, incoming) in inputs {
                            let Some(&pred_idx) = cfg.id_to_index.get(pred) else {
                                continue;
                            };
                            if edge_is_executable(
                                pred_idx, block_idx, &original, &cfg, &facts, &reachable,
                            ) {
                                input_proofs.push(
                                    proof_by_value
                                        .get(incoming)
                                        .cloned()
                                        .unwrap_or_else(ProofSlot::default),
                                );
                            }
                        }
                        merge_sccp_const_proof(value, &original_inst.proof, &input_proofs)
                    }
                    InstKind::BinOp { lhs, rhs, .. } => merge_folded_const_proof(
                        value,
                        &original_inst.proof,
                        &proof_by_value
                            .get(lhs)
                            .cloned()
                            .unwrap_or_else(ProofSlot::default),
                        &proof_by_value
                            .get(rhs)
                            .cloned()
                            .unwrap_or_else(ProofSlot::default),
                    ),
                    _ => materialize_proven_const_proof(value, &original_inst.proof),
                };

                if !matches!(&inst.kind, InstKind::Const(existing) if existing == value) {
                    inst.kind = InstKind::Const(value.clone());
                    changed = true;
                }
                if inst.proof != new_proof {
                    inst.proof = new_proof.clone();
                    changed = true;
                }
                proof_by_value.insert(id, new_proof);
            }

            if let Terminator::Branch {
                cond,
                true_bb,
                false_bb,
            } = original_block.term
            {
                if let Some(target) = const_branch_target(&cond, true_bb, false_bb, &facts) {
                    let new_term = Terminator::Jump(target);
                    if block.term != new_term {
                        block.term = new_term;
                        changed = true;
                    }
                }
            }
        }

        changed
    }
}

fn ir_instr_produces_value(instr: &IRInstr) -> bool {
    matches!(
        instr,
        IRInstr::ConstNum(_)
            | IRInstr::ConstText(_)
            | IRInstr::ConstBool(_)
            | IRInstr::PushNull
            | IRInstr::LoadVar(_)
            | IRInstr::Add
            | IRInstr::Sub
            | IRInstr::Mul
            | IRInstr::Div
            | IRInstr::Mod
            | IRInstr::Xor
            | IRInstr::Shl
            | IRInstr::Eq
            | IRInstr::Ne
            | IRInstr::Gt
            | IRInstr::Ge
            | IRInstr::Lt
            | IRInstr::Le
            | IRInstr::And
            | IRInstr::Or
            | IRInstr::CallBuiltin(_, _)
            | IRInstr::CallFn(_, _)
            | IRInstr::MakeList(_)
            | IRInstr::MakeMap(_)
            | IRInstr::LoadField(_)
    )
}

fn is_sccp_exportable_inst(inst: &Inst) -> bool {
    inst.id.is_some() && !matches!(inst.kind, InstKind::Phi { .. })
}

fn merge_exported_proof(base: &ProofSlot, upgraded: &ProofSlot) -> ProofSlot {
    let base_numeric = base.numeric.or_else(|| base.numeric_fallback());
    let upgraded_numeric = upgraded.numeric.or_else(|| upgraded.numeric_fallback());
    let numeric = match (base_numeric, upgraded_numeric) {
        (Some(base), Some(upgraded)) => base.merge(upgraded).or(Some(upgraded)),
        (Some(base), None) => Some(base),
        (None, Some(upgraded)) => Some(upgraded),
        (None, None) => None,
    };

    ProofSlot {
        refined_type: upgraded
            .refined_type
            .clone()
            .or_else(|| base.refined_type.clone()),
        numeric,
        cost_bound: upgraded
            .cost_bound
            .clone()
            .or_else(|| base.cost_bound.clone()),
        coq_cert: upgraded.coq_cert.or(base.coq_cert),
        aliasing: if upgraded.aliasing != AliasingClass::Unknown {
            upgraded.aliasing
        } else {
            base.aliasing
        },
        unsafe_context: base.unsafe_context || upgraded.unsafe_context,
    }
}

/// Export upgraded SCCP evidence back into IR-node keyed form.
///
/// v1 uses a conservative linear mapping: value-producing IR nodes are matched to
/// non-phi SSA value instructions in order. This works with the current lowering
/// pipeline because lowering preserves producer order and SCCP only mutates
/// instruction kinds/proofs in place.
pub fn collect_sccp_proof_env(function: &Function, block: &[IRNode]) -> ProofEnv {
    let mut env = ProofEnv::default();
    let mut ssa_values = function
        .blocks
        .iter()
        .flat_map(|bb| bb.insts.iter())
        .filter(|inst| is_sccp_exportable_inst(inst));

    for node in block {
        let mut slot = node.proof.clone();
        if ir_instr_produces_value(&node.instr) {
            if let Some(inst) = ssa_values.next() {
                slot = merge_exported_proof(&slot, &inst.proof);
            }
        }
        env.unsafe_context |= slot.unsafe_context;
        env.by_node.insert(node.id, slot);
    }
    env
}

pub struct ConstFoldPass;

impl SsaPass for ConstFoldPass {
    fn name(&self) -> &'static str {
        "const-fold"
    }

    fn run(&mut self, function: &mut Function) -> bool {
        let mut changed = false;
        for block in &mut function.blocks {
            let mut facts: HashMap<ValueId, ConstFact> = HashMap::new();
            for inst in &mut block.insts {
                if let Some(id) = inst.id {
                    if let InstKind::Const(c) = &inst.kind {
                        facts.insert(id, ConstFact::constant(c.clone(), inst.proof.clone()));
                        continue;
                    }
                    let base_fact = const_value_from_proof(&inst.proof)
                        .map(|value| ConstFact::constant(value, inst.proof.clone()))
                        .unwrap_or_else(|| ConstFact::unknown_with_proof(inst.proof.clone()));
                    if let ValueFact::Const(value) = &base_fact.fact {
                        if matches!(inst.kind, InstKind::Alias(_) | InstKind::BinOp { .. }) {
                            let merged = materialize_proven_const_proof(value, &inst.proof);
                            inst.kind = InstKind::Const(value.clone());
                            inst.proof = merged.clone();
                            facts.insert(id, ConstFact::constant(value.clone(), merged));
                            changed = true;
                            continue;
                        }
                    }
                    if let InstKind::Alias(src) = &inst.kind {
                        if let Some(ConstFact {
                            fact: ValueFact::Const(value),
                            proof,
                        }) = facts.get(src).cloned()
                        {
                            let merged = merge_folded_const_proof(
                                &value,
                                &inst.proof,
                                &proof,
                                &ProofSlot::default(),
                            );
                            inst.kind = InstKind::Const(value.clone());
                            inst.proof = merged.clone();
                            facts.insert(id, ConstFact::constant(value, merged));
                            changed = true;
                            continue;
                        }
                    }
                    if let InstKind::BinOp { op, lhs, rhs } = &inst.kind {
                        let lhs_fact = facts
                            .get(lhs)
                            .cloned()
                            .unwrap_or_else(|| ConstFact::unknown_with_proof(ProofSlot::default()));
                        let rhs_fact = facts
                            .get(rhs)
                            .cloned()
                            .unwrap_or_else(|| ConstFact::unknown_with_proof(ProofSlot::default()));
                        if let (ValueFact::Const(l), ValueFact::Const(r)) =
                            (&lhs_fact.fact, &rhs_fact.fact)
                        {
                            if let Some(folded) = fold_const_binop(*op, l, r) {
                                let merged = merge_folded_const_proof(
                                    &folded,
                                    &inst.proof,
                                    &lhs_fact.proof,
                                    &rhs_fact.proof,
                                );
                                inst.kind = InstKind::Const(folded.clone());
                                inst.proof = merged.clone();
                                facts.insert(id, ConstFact::constant(folded, merged));
                                changed = true;
                                continue;
                            }
                        }
                    }
                    facts.insert(id, base_fact);
                }
            }
        }
        changed
    }
}

fn fold_const_binop(op: BinOp, lhs: &ConstValue, rhs: &ConstValue) -> Option<ConstValue> {
    match op {
        BinOp::Add => fold_num2(lhs, rhs, |a, b| ConstValue::Num(a + b)),
        BinOp::Sub => fold_num2(lhs, rhs, |a, b| ConstValue::Num(a - b)),
        BinOp::Mul => fold_num2(lhs, rhs, |a, b| ConstValue::Num(a * b)),
        BinOp::Div if matches!(rhs, ConstValue::Num(b) if *b == 0.0) => None,
        BinOp::Div => fold_num2(lhs, rhs, |a, b| ConstValue::Num(a / b)),
        BinOp::Mod if matches!(rhs, ConstValue::Num(b) if *b == 0.0) => None,
        BinOp::Mod => fold_num2(lhs, rhs, |a, b| ConstValue::Num(a % b)),
        BinOp::Xor => fold_int2(lhs, rhs, |a, b| ConstValue::Num((a ^ b) as f64)),
        BinOp::Shl => match (lhs, rhs) {
            (ConstValue::Num(a), ConstValue::Num(b))
                if a.fract() == 0.0 && b.fract() == 0.0 && *b >= 0.0 =>
            {
                Some(ConstValue::Num(((*a as i64) << (*b as u32)) as f64))
            }
            _ => None,
        },
        BinOp::Eq => fold_num2(lhs, rhs, |a, b| {
            ConstValue::Bool((a - b).abs() < f64::EPSILON)
        }),
        BinOp::Ne => fold_num2(lhs, rhs, |a, b| {
            ConstValue::Bool((a - b).abs() >= f64::EPSILON)
        }),
        BinOp::Gt => fold_num2(lhs, rhs, |a, b| ConstValue::Bool(a > b)),
        BinOp::Ge => fold_num2(lhs, rhs, |a, b| ConstValue::Bool(a >= b)),
        BinOp::Lt => fold_num2(lhs, rhs, |a, b| ConstValue::Bool(a < b)),
        BinOp::Le => fold_num2(lhs, rhs, |a, b| ConstValue::Bool(a <= b)),
        BinOp::And => fold_bool2(lhs, rhs, |a, b| ConstValue::Bool(a && b)),
        BinOp::Or => fold_bool2(lhs, rhs, |a, b| ConstValue::Bool(a || b)),
    }
}

fn fold_num2(
    lhs: &ConstValue,
    rhs: &ConstValue,
    f: impl FnOnce(f64, f64) -> ConstValue,
) -> Option<ConstValue> {
    if let (ConstValue::Num(a), ConstValue::Num(b)) = (lhs, rhs) {
        Some(f(*a, *b))
    } else {
        None
    }
}

fn fold_int2(
    lhs: &ConstValue,
    rhs: &ConstValue,
    f: impl FnOnce(i64, i64) -> ConstValue,
) -> Option<ConstValue> {
    match (lhs, rhs) {
        (ConstValue::Num(a), ConstValue::Num(b)) if a.fract() == 0.0 && b.fract() == 0.0 => {
            Some(f(*a as i64, *b as i64))
        }
        _ => None,
    }
}

fn fold_bool2(
    lhs: &ConstValue,
    rhs: &ConstValue,
    f: impl FnOnce(bool, bool) -> ConstValue,
) -> Option<ConstValue> {
    if let (ConstValue::Bool(a), ConstValue::Bool(b)) = (lhs, rhs) {
        Some(f(*a, *b))
    } else {
        None
    }
}

pub struct DeadInstElimPass;

impl SsaPass for DeadInstElimPass {
    fn name(&self) -> &'static str {
        "dead-inst-elim"
    }

    fn run(&mut self, function: &mut Function) -> bool {
        let mut def_inputs: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
        let mut removable_defs: HashSet<ValueId> = HashSet::new();
        let mut live: HashSet<ValueId> = HashSet::new();
        let mut worklist: Vec<ValueId> = Vec::new();

        for block in &function.blocks {
            for inst in &block.insts {
                let inputs = inst_inputs(&inst.kind);
                if let Some(id) = inst.id {
                    def_inputs.insert(id, inputs.clone());
                    if is_removable_pure_inst(&inst.kind) {
                        removable_defs.insert(id);
                    } else {
                        for input in inputs {
                            if live.insert(input) {
                                worklist.push(input);
                            }
                        }
                    }
                } else {
                    for input in inputs {
                        if live.insert(input) {
                            worklist.push(input);
                        }
                    }
                }
            }
            match block.term {
                Terminator::Return(Some(v)) => {
                    if live.insert(v) {
                        worklist.push(v);
                    }
                }
                Terminator::Branch { cond, .. } if live.insert(cond) => {
                    worklist.push(cond);
                }
                _ => {}
            }
        }

        while let Some(value) = worklist.pop() {
            if let Some(inputs) = def_inputs.get(&value) {
                for input in inputs {
                    if live.insert(*input) {
                        worklist.push(*input);
                    }
                }
            }
        }

        let mut changed = false;
        for block in &mut function.blocks {
            let before = block.insts.len();
            block.insts.retain(|inst| {
                if let Some(id) = inst.id {
                    if removable_defs.contains(&id) {
                        return live.contains(&id);
                    }
                }
                true
            });
            if block.insts.len() != before {
                changed = true;
            }
        }
        changed
    }
}

fn is_removable_pure_inst(kind: &InstKind) -> bool {
    matches!(
        kind,
        InstKind::Const(_)
            | InstKind::Alias(_)
            | InstKind::Phi { .. }
            | InstKind::BinOp { .. }
            | InstKind::MakeList(_)
            | InstKind::MakeMap { .. }
            | InstKind::LoadField { .. }
    )
}

fn inst_inputs(kind: &InstKind) -> Vec<ValueId> {
    match kind {
        InstKind::Const(_) => Vec::new(),
        InstKind::Alias(v) => vec![*v],
        InstKind::Phi { inputs, .. } => inputs.iter().map(|(_, v)| *v).collect(),
        InstKind::BinOp { lhs, rhs, .. } => vec![*lhs, *rhs],
        InstKind::CallBuiltin { args, .. } | InstKind::CallFn { args, .. } => args.clone(),
        InstKind::MakeList(values) => values.clone(),
        InstKind::MakeMap { values, .. } => values.clone(),
        InstKind::LoadField { base, .. } => vec![*base],
        InstKind::Emit { arg, .. } => arg.iter().copied().collect(),
    }
}

pub fn pretty_print_program(program: &Program) -> String {
    let mut out = String::new();
    dump_function(&mut out, &program.main);
    for func in program.functions.values() {
        dump_function(&mut out, func);
    }
    out
}

fn dump_function(out: &mut String, function: &Function) {
    writeln!(
        out,
        "ssa fn {}({})  // {:?}",
        function.name,
        function.params.join(", "),
        function.status
    )
    .ok();
    for block in &function.blocks {
        writeln!(out, "  b{}:", block.id).ok();
        for inst in &block.insts {
            let head = inst
                .id
                .map(|v| format!("v{} = ", v.0))
                .unwrap_or_else(|| "      ".to_string());
            writeln!(out, "    {}{}", head, fmt_inst(&inst.kind)).ok();
        }
        writeln!(out, "    {}", fmt_term(&block.term)).ok();
    }
}

fn fmt_inst(kind: &InstKind) -> String {
    match kind {
        InstKind::Const(ConstValue::Num(n)) => format!("const.num {}", n),
        InstKind::Const(ConstValue::Bool(b)) => format!("const.bool {}", b),
        InstKind::Const(ConstValue::Text(s)) => format!("const.text \"{}\"", s),
        InstKind::Const(ConstValue::Null) => "const.null".into(),
        InstKind::Alias(v) => format!("alias v{}", v.0),
        InstKind::Phi { var, inputs } => {
            let incoming = inputs
                .iter()
                .map(|(pred, value)| format!("b{}:v{}", pred, value.0))
                .collect::<Vec<_>>()
                .join(", ");
            format!("phi {} <- [{}]", var, incoming)
        }
        InstKind::BinOp { op, lhs, rhs } => {
            format!("binop.{:?} v{}, v{}", op, lhs.0, rhs.0)
        }
        InstKind::CallBuiltin { name, args } => {
            let args = args
                .iter()
                .map(|a| format!("v{}", a.0))
                .collect::<Vec<_>>()
                .join(", ");
            format!("call_builtin {}({})", name, args)
        }
        InstKind::CallFn { name, args } => {
            let args = args
                .iter()
                .map(|a| format!("v{}", a.0))
                .collect::<Vec<_>>()
                .join(", ");
            format!("call_fn {}({})", name, args)
        }
        InstKind::MakeList(values) => {
            let values = values
                .iter()
                .map(|a| format!("v{}", a.0))
                .collect::<Vec<_>>()
                .join(", ");
            format!("make_list [{}]", values)
        }
        InstKind::MakeMap { keys, values } => {
            let values = values
                .iter()
                .map(|a| format!("v{}", a.0))
                .collect::<Vec<_>>()
                .join(", ");
            format!("make_map [{}] <- [{}]", keys.join(","), values)
        }
        InstKind::LoadField { base, field } => {
            format!("load_field v{}.{}", base.0, field)
        }
        InstKind::Emit { kind, ui_kind, arg } => match kind {
            EmitKind::Ui => format!("emit.ui {}", ui_kind.clone().unwrap_or_default()),
            _ => format!(
                "emit.{:?} {}",
                kind,
                arg.map(|v| format!("v{}", v.0))
                    .unwrap_or_else(|| "_".to_string())
            ),
        },
    }
}

fn fmt_term(term: &Terminator) -> String {
    match term {
        Terminator::Return(Some(v)) => format!("ret v{}", v.0),
        Terminator::Return(None) => "ret".into(),
        Terminator::Jump(bb) => format!("jmp b{}", bb),
        Terminator::Branch {
            cond,
            true_bb,
            false_bb,
        } => format!("br v{} ? b{} : b{}", cond.0, true_bb, false_bb),
        Terminator::UnsupportedControlFlow { ip, op } => {
            format!("unsupported_cf @{} ({})", ip, op)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::typecheck::Type;
    use crate::vm::ir::{
        AliasingClass, CostBound, IRInstr, IRNode, IRProgram, NumericProof, ProofSlot, RefinedType,
    };

    use super::{
        compute_dominance_frontier, compute_dominator_tree, lower_program,
        lower_program_with_stats, verify_function_ssa, verify_program_ssa, BinOp, Block,
        BuildStatus, ConstFoldPass, ConstValue, DeadInstElimPass, Function, Inst, InstKind,
        Mem2RegPass, PassManager, SccpPass, SsaPass, Terminator, ValueId,
    };

    fn num_eq_proof(value: f64) -> ProofSlot {
        ProofSlot {
            refined_type: Some(RefinedType {
                base: Type::Num,
                predicate: Some(format!("v == {}", value)),
            }),
            numeric: (value.fract() == 0.0).then_some(NumericProof::from_exact(value as i64)),
            cost_bound: None,
            coq_cert: None,
            aliasing: AliasingClass::Unknown,
            unsafe_context: false,
        }
    }

    #[test]
    fn lower_and_optimize_linear_main() {
        let ir = IRProgram {
            main: vec![
                IRNode::new(IRInstr::ConstNum(1.0), None, None),
                IRNode::new(IRInstr::ConstNum(2.0), None, None),
                IRNode::new(IRInstr::Add, None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };

        let mut ssa = lower_program(&ir);
        assert!(matches!(ssa.main.status, BuildStatus::Lowered));

        let mut pm = PassManager::with_default_pipeline();
        let changed = pm.run_program(&mut ssa);
        assert!(!changed.is_empty());

        let block = &ssa.main.blocks[0];
        assert_eq!(block.insts.len(), 1);
        match &block.insts[0].kind {
            InstKind::Const(ConstValue::Num(n)) => assert_eq!(*n, 3.0),
            other => panic!("unexpected inst: {:?}", other),
        }
        assert!(matches!(block.term, Terminator::Return(Some(_))));
    }

    #[test]
    fn lower_program_with_stats_tracks_scratch_usage() {
        let ir = IRProgram {
            main: vec![
                IRNode::new(IRInstr::ConstNum(1.0), None, None),
                IRNode::new(IRInstr::StoreVar("x".into()), None, None),
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };

        let (ssa, stats) = lower_program_with_stats(&ir);
        assert!(matches!(ssa.main.status, BuildStatus::Lowered));
        let actual_insts = ssa
            .main
            .blocks
            .iter()
            .map(|block| block.insts.len())
            .sum::<usize>();
        let actual_var_ops = ssa
            .main
            .blocks
            .iter()
            .map(|block| block.var_ops.len())
            .sum::<usize>();
        assert_eq!(stats.functions, 1);
        assert_eq!(stats.blocks, 1);
        assert_eq!(stats.insts, actual_insts);
        assert_eq!(stats.var_ops, actual_var_ops);
        assert_eq!(stats.var_ops_staged, 2);
        assert!(stats.inst_reserved >= stats.insts);
        assert!(stats.var_op_reserved >= stats.var_ops);
        assert!(stats.var_op_reserved >= 2);
        assert!(stats.stack_reserved >= 4);
        assert!(stats.locals_reserved >= 4);
    }

    #[test]
    fn const_fold_uses_proof_backed_alias_facts() {
        let mut function = Function {
            name: "proof_fold".into(),
            params: vec!["x".into()],
            param_values: vec![ValueId(0)],
            blocks: vec![Block {
                id: 0,
                insts: vec![
                    Inst::new(Some(ValueId(1)), InstKind::Alias(ValueId(0)))
                        .with_proof(num_eq_proof(1.0)),
                    Inst::new(Some(ValueId(2)), InstKind::Const(ConstValue::Num(2.0))),
                    Inst::new(
                        Some(ValueId(3)),
                        InstKind::BinOp {
                            op: BinOp::Add,
                            lhs: ValueId(1),
                            rhs: ValueId(2),
                        },
                    )
                    .with_proof(ProofSlot {
                        refined_type: None,
                        numeric: None,
                        cost_bound: Some(CostBound {
                            worst_cycles: Some(9),
                            alloc_bytes: None,
                            mem_reads: None,
                            mem_writes: None,
                        }),
                        coq_cert: Some(99),
                        aliasing: AliasingClass::Unknown,
                        unsafe_context: true,
                    }),
                ],
                var_ops: Vec::new(),
                term: Terminator::Return(Some(ValueId(3))),
            }],
            status: BuildStatus::Lowered,
        };

        let mut pass = ConstFoldPass;
        assert!(
            pass.run(&mut function),
            "proof-aware const fold should change SSA"
        );

        match &function.blocks[0].insts[0].kind {
            InstKind::Const(ConstValue::Num(n)) => assert_eq!(*n, 1.0),
            other => panic!("expected alias to fold into const, got {:?}", other),
        }
        match &function.blocks[0].insts[2].kind {
            InstKind::Const(ConstValue::Num(n)) => assert_eq!(*n, 3.0),
            other => panic!("expected binop to fold into const, got {:?}", other),
        }

        let folded_proof = &function.blocks[0].insts[2].proof;
        assert_eq!(folded_proof.coq_cert, Some(99));
        assert!(folded_proof.unsafe_context);
        assert_eq!(folded_proof.aliasing, AliasingClass::NoAlias);
        assert_eq!(
            folded_proof
                .refined_type
                .as_ref()
                .and_then(|r| r.predicate.as_deref()),
            Some("v == 3")
        );
    }

    #[test]
    fn sccp_prunes_unreachable_constant_branch() {
        let mut function = Function {
            name: "sccp_prune_branch".into(),
            params: Vec::new(),
            param_values: Vec::new(),
            blocks: vec![
                Block {
                    id: 0,
                    insts: vec![Inst::new(
                        Some(ValueId(1)),
                        InstKind::Const(ConstValue::Bool(true)),
                    )],
                    var_ops: Vec::new(),
                    term: Terminator::Branch {
                        cond: ValueId(1),
                        true_bb: 1,
                        false_bb: 2,
                    },
                },
                Block {
                    id: 1,
                    insts: vec![Inst::new(
                        Some(ValueId(2)),
                        InstKind::Const(ConstValue::Num(7.0)),
                    )],
                    var_ops: Vec::new(),
                    term: Terminator::Return(Some(ValueId(2))),
                },
                Block {
                    id: 2,
                    insts: vec![Inst::new(
                        Some(ValueId(3)),
                        InstKind::Const(ConstValue::Num(9.0)),
                    )],
                    var_ops: Vec::new(),
                    term: Terminator::Return(Some(ValueId(3))),
                },
            ],
            status: BuildStatus::Lowered,
        };

        let mut pass = SccpPass;
        assert!(pass.run(&mut function), "SCCP should prune constant branch");
        assert_eq!(function.blocks[0].term, Terminator::Jump(1));
    }

    #[test]
    fn sccp_merges_phi_when_executable_inputs_are_same_constant() {
        let mut function = Function {
            name: "sccp_phi_merge".into(),
            params: vec!["cond".into()],
            param_values: vec![ValueId(0)],
            blocks: vec![
                Block {
                    id: 0,
                    insts: Vec::new(),
                    var_ops: Vec::new(),
                    term: Terminator::Branch {
                        cond: ValueId(0),
                        true_bb: 1,
                        false_bb: 2,
                    },
                },
                Block {
                    id: 1,
                    insts: vec![Inst::new(
                        Some(ValueId(1)),
                        InstKind::Const(ConstValue::Num(5.0)),
                    )],
                    var_ops: Vec::new(),
                    term: Terminator::Jump(3),
                },
                Block {
                    id: 2,
                    insts: vec![Inst::new(
                        Some(ValueId(2)),
                        InstKind::Const(ConstValue::Num(5.0)),
                    )],
                    var_ops: Vec::new(),
                    term: Terminator::Jump(3),
                },
                Block {
                    id: 3,
                    insts: vec![Inst::new(
                        Some(ValueId(3)),
                        InstKind::Phi {
                            var: "x".into(),
                            inputs: vec![(1, ValueId(1)), (2, ValueId(2))],
                        },
                    )],
                    var_ops: Vec::new(),
                    term: Terminator::Return(Some(ValueId(3))),
                },
            ],
            status: BuildStatus::Lowered,
        };

        let mut pass = SccpPass;
        assert!(pass.run(&mut function), "SCCP should fold constant phi");
        match &function.blocks[3].insts[0].kind {
            InstKind::Const(ConstValue::Num(n)) => assert_eq!(*n, 5.0),
            other => panic!("expected phi to fold into const, got {:?}", other),
        }
    }

    #[test]
    fn sccp_upgrades_proof_slot_for_proven_constants() {
        let mut function = Function {
            name: "sccp_proof_upgrade".into(),
            params: vec!["x".into()],
            param_values: vec![ValueId(0)],
            blocks: vec![Block {
                id: 0,
                insts: vec![
                    Inst::new(Some(ValueId(1)), InstKind::Alias(ValueId(0)))
                        .with_proof(num_eq_proof(1.0)),
                    Inst::new(Some(ValueId(2)), InstKind::Const(ConstValue::Num(2.0))),
                    Inst::new(
                        Some(ValueId(3)),
                        InstKind::BinOp {
                            op: BinOp::Add,
                            lhs: ValueId(1),
                            rhs: ValueId(2),
                        },
                    )
                    .with_proof(ProofSlot {
                        refined_type: None,
                        numeric: None,
                        cost_bound: Some(CostBound {
                            worst_cycles: Some(11),
                            alloc_bytes: None,
                            mem_reads: Some(2),
                            mem_writes: None,
                        }),
                        coq_cert: Some(77),
                        aliasing: AliasingClass::Unknown,
                        unsafe_context: true,
                    }),
                ],
                var_ops: Vec::new(),
                term: Terminator::Return(Some(ValueId(3))),
            }],
            status: BuildStatus::Lowered,
        };

        let mut pass = SccpPass;
        assert!(pass.run(&mut function), "SCCP should change SSA");

        match &function.blocks[0].insts[0].kind {
            InstKind::Const(ConstValue::Num(n)) => assert_eq!(*n, 1.0),
            other => panic!("expected alias to become const, got {:?}", other),
        }
        match &function.blocks[0].insts[2].kind {
            InstKind::Const(ConstValue::Num(n)) => assert_eq!(*n, 3.0),
            other => panic!("expected binop to become const, got {:?}", other),
        }

        let proof = &function.blocks[0].insts[2].proof;
        assert_eq!(proof.coq_cert, Some(77));
        assert!(proof.unsafe_context);
        assert_eq!(proof.aliasing, AliasingClass::NoAlias);
        assert_eq!(
            proof
                .refined_type
                .as_ref()
                .and_then(|slot| slot.predicate.as_deref()),
            Some("v == 3")
        );
    }

    #[test]
    fn mem2reg_eliminates_alias_chain_in_return_path() {
        let ir = IRProgram {
            main: vec![
                IRNode::new(IRInstr::ConstNum(1.0), None, None),
                IRNode::new(IRInstr::StoreVar("x".into()), None, None),
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::StoreVar("y".into()), None, None),
                IRNode::new(IRInstr::LoadVar("y".into()), None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };

        let mut ssa = lower_program(&ir);
        assert!(matches!(ssa.main.status, BuildStatus::Lowered));

        let mut pm = PassManager::with_default_pipeline();
        let changed = pm.run_program(&mut ssa);
        assert!(
            changed.iter().any(|step| step.ends_with(":mem2reg")),
            "pipeline should run mem2reg, got {:?}",
            changed
        );

        let block = &ssa.main.blocks[0];
        assert!(
            block
                .insts
                .iter()
                .all(|inst| !matches!(inst.kind, InstKind::Alias(_))),
            "all alias nodes should be eliminated after mem2reg + dce: {:?}",
            block.insts
        );

        let ret_id = match block.term {
            Terminator::Return(Some(v)) => v,
            _ => panic!("expected return value"),
        };
        let ret_inst = block
            .insts
            .iter()
            .find(|inst| inst.id == Some(ret_id))
            .expect("return producer");
        match &ret_inst.kind {
            InstKind::Const(ConstValue::Num(n)) => assert_eq!(*n, 1.0),
            other => panic!("return should be rooted at original const, got {:?}", other),
        }
    }

    #[test]
    fn dce_eliminates_dead_pure_constructors_and_field_loads() {
        let mut function = Function {
            name: "dce_pure_graph".into(),
            params: Vec::new(),
            param_values: Vec::new(),
            blocks: vec![Block {
                id: 0,
                insts: vec![
                    Inst::new(Some(ValueId(1)), InstKind::Const(ConstValue::Num(1.0))),
                    Inst::new(Some(ValueId(2)), InstKind::Const(ConstValue::Num(2.0))),
                    Inst::new(
                        Some(ValueId(3)),
                        InstKind::MakeList(vec![ValueId(1), ValueId(2)]),
                    ),
                    Inst::new(
                        Some(ValueId(4)),
                        InstKind::MakeMap {
                            keys: vec!["pair".into()],
                            values: vec![ValueId(3)],
                        },
                    ),
                    Inst::new(
                        Some(ValueId(5)),
                        InstKind::LoadField {
                            base: ValueId(4),
                            field: "pair".into(),
                        },
                    ),
                    Inst::new(Some(ValueId(6)), InstKind::Const(ConstValue::Num(99.0))),
                ],
                var_ops: Vec::new(),
                term: Terminator::Return(Some(ValueId(6))),
            }],
            status: BuildStatus::Lowered,
        };

        let mut pass = DeadInstElimPass;
        assert!(pass.run(&mut function), "DCE should remove dead pure graph");

        let insts = &function.blocks[0].insts;
        assert_eq!(insts.len(), 1, "only live return producer should remain");
        match &insts[0].kind {
            InstKind::Const(ConstValue::Num(n)) => assert_eq!(*n, 99.0),
            other => panic!("expected live const return producer, got {:?}", other),
        }
    }

    #[test]
    fn mem2reg_rewrites_return_to_phi_directly() {
        let ir = IRProgram {
            main: vec![
                IRNode::new(IRInstr::ConstBool(true), None, None),
                IRNode::new(IRInstr::JumpIfFalse(5), None, None),
                IRNode::new(IRInstr::ConstNum(1.0), None, None),
                IRNode::new(IRInstr::StoreVar("x".into()), None, None),
                IRNode::new(IRInstr::Jump(7), None, None),
                IRNode::new(IRInstr::ConstNum(2.0), None, None),
                IRNode::new(IRInstr::StoreVar("x".into()), None, None),
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };

        let mut ssa = lower_program(&ir);
        assert!(matches!(ssa.main.status, BuildStatus::Lowered));

        let mut pass = Mem2RegPass;
        assert!(
            pass.run(&mut ssa.main),
            "mem2reg should rewrite alias chain"
        );

        let join = ssa
            .main
            .blocks
            .iter()
            .find(|block| matches!(block.term, Terminator::Return(Some(_))))
            .expect("join/return block");
        let phi_id = join
            .insts
            .iter()
            .find_map(|inst| match &inst.kind {
                InstKind::Phi { var, .. } if var == "x" => inst.id,
                _ => None,
            })
            .expect("x phi in join");
        let ret_id = match join.term {
            Terminator::Return(Some(v)) => v,
            _ => unreachable!(),
        };
        assert_eq!(
            ret_id, phi_id,
            "mem2reg should rewrite return alias to direct phi"
        );
    }

    #[test]
    fn cfg_blocks_have_explicit_terminators() {
        let ir = IRProgram {
            main: vec![
                IRNode::new(IRInstr::ConstBool(true), None, None),
                IRNode::new(IRInstr::JumpIfFalse(4), None, None),
                IRNode::new(IRInstr::PushNull, None, None),
                IRNode::new(IRInstr::Pop, None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };
        let ssa = lower_program(&ir);
        assert!(matches!(ssa.main.status, BuildStatus::Lowered));
        assert!(ssa.main.blocks.len() >= 2);
        for block in &ssa.main.blocks {
            assert!(
                !matches!(block.term, Terminator::UnsupportedControlFlow { .. }),
                "block {} has unsupported terminator: {:?}",
                block.id,
                block.term
            );
        }
    }

    #[test]
    fn dynamic_call_is_marked_unsupported() {
        let ir = IRProgram {
            main: vec![
                IRNode::new(IRInstr::ConstNum(1.0), None, None),
                IRNode::new(IRInstr::Call(1), None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };
        let ssa = lower_program(&ir);
        assert!(matches!(ssa.main.status, BuildStatus::Unsupported(_)));
    }

    #[test]
    fn dominator_tree_branch_join_shape() {
        let ir = IRProgram {
            main: vec![
                IRNode::new(IRInstr::ConstBool(true), None, None),
                IRNode::new(IRInstr::JumpIfFalse(3), None, None),
                IRNode::new(IRInstr::Jump(4), None, None),
                IRNode::new(IRInstr::Jump(4), None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };
        let ssa = lower_program(&ir);
        assert!(matches!(ssa.main.status, BuildStatus::Lowered));
        assert_eq!(ssa.main.blocks.len(), 4);

        let entry = ssa.main.blocks[0].id;
        let left = ssa.main.blocks[1].id;
        let right = ssa.main.blocks[2].id;
        let join = ssa.main.blocks[3].id;

        let dom = compute_dominator_tree(&ssa.main);
        assert_eq!(dom.entry(), entry);
        assert_eq!(dom.immediate_dominator(entry), None);
        assert_eq!(dom.immediate_dominator(left), Some(entry));
        assert_eq!(dom.immediate_dominator(right), Some(entry));
        assert_eq!(dom.immediate_dominator(join), Some(entry));
        assert!(dom.dominates(entry, join));
        assert!(!dom.dominates(left, join));

        let df = compute_dominance_frontier(&ssa.main, &dom).expect("dominance frontier");
        assert_eq!(df.frontier(entry), Some(&[][..]));
        assert_eq!(df.frontier(left), Some(&[join][..]));
        assert_eq!(df.frontier(right), Some(&[join][..]));
        assert_eq!(df.frontier(join), Some(&[][..]));
    }

    #[test]
    fn dominance_frontier_loop_header_has_self_frontier() {
        let ir = IRProgram {
            main: vec![
                IRNode::new(IRInstr::Jump(1), None, None),
                IRNode::new(IRInstr::ConstBool(true), None, None),
                IRNode::new(IRInstr::JumpIfFalse(4), None, None),
                IRNode::new(IRInstr::Jump(1), None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };
        let ssa = lower_program(&ir);
        assert!(matches!(ssa.main.status, BuildStatus::Lowered));

        let entry = ssa.main.blocks[0].id;
        let header = ssa
            .main
            .blocks
            .iter()
            .find_map(|b| match b.term {
                Terminator::Branch { .. } => Some(b.id),
                _ => None,
            })
            .expect("loop header");
        let body = ssa
            .main
            .blocks
            .iter()
            .find_map(|b| match b.term {
                Terminator::Jump(t) if b.id != entry && t == header => Some(b.id),
                _ => None,
            })
            .expect("loop body");

        let dom = compute_dominator_tree(&ssa.main);
        assert_eq!(dom.immediate_dominator(header), Some(entry));
        assert_eq!(dom.immediate_dominator(body), Some(header));
        assert!(dom.dominates(header, body));

        let df = compute_dominance_frontier(&ssa.main, &dom).expect("dominance frontier");
        assert_eq!(df.frontier(header), Some(&[header][..]));
        assert_eq!(df.frontier(body), Some(&[header][..]));
    }

    #[test]
    fn phi_inserted_and_renamed_for_diamond_var() {
        let ir = IRProgram {
            main: vec![
                IRNode::new(IRInstr::ConstBool(true), None, None),
                IRNode::new(IRInstr::JumpIfFalse(5), None, None),
                IRNode::new(IRInstr::ConstNum(1.0), None, None),
                IRNode::new(IRInstr::StoreVar("x".into()), None, None),
                IRNode::new(IRInstr::Jump(7), None, None),
                IRNode::new(IRInstr::ConstNum(2.0), None, None),
                IRNode::new(IRInstr::StoreVar("x".into()), None, None),
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };
        let ssa = lower_program(&ir);
        assert!(matches!(ssa.main.status, BuildStatus::Lowered));

        let join = ssa
            .main
            .blocks
            .iter()
            .find(|block| {
                block
                    .insts
                    .iter()
                    .any(|inst| matches!(&inst.kind, InstKind::Phi { var, .. } if var == "x"))
            })
            .expect("join block with phi");

        let (phi_id, phi_inputs) = join
            .insts
            .iter()
            .find_map(|inst| match &inst.kind {
                InstKind::Phi { var, inputs } if var == "x" => inst.id.map(|id| (id, inputs)),
                _ => None,
            })
            .expect("x phi");
        assert_eq!(phi_inputs.len(), 2);

        let ret_id = match join.term {
            Terminator::Return(Some(v)) => v,
            _ => panic!("expected return value in join"),
        };
        let ret_inst = join
            .insts
            .iter()
            .find(|inst| inst.id == Some(ret_id))
            .expect("return producer");
        match ret_inst.kind {
            InstKind::Alias(src) => assert_eq!(src, phi_id),
            _ => panic!("return should come from renamed load alias"),
        }
    }

    #[test]
    fn phi_inserted_for_loop_header_var() {
        let ir = IRProgram {
            main: vec![
                IRNode::new(IRInstr::ConstNum(0.0), None, None),
                IRNode::new(IRInstr::StoreVar("x".into()), None, None),
                IRNode::new(IRInstr::ConstBool(true), None, None),
                IRNode::new(IRInstr::JumpIfFalse(9), None, None),
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::ConstNum(1.0), None, None),
                IRNode::new(IRInstr::Add, None, None),
                IRNode::new(IRInstr::StoreVar("x".into()), None, None),
                IRNode::new(IRInstr::Jump(2), None, None),
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };
        let ssa = lower_program(&ir);
        assert!(matches!(ssa.main.status, BuildStatus::Lowered));

        let header =
            ssa.main
                .blocks
                .iter()
                .find(|block| {
                    matches!(block.term, Terminator::Branch { .. })
                        && block.insts.iter().any(
                            |inst| matches!(&inst.kind, InstKind::Phi { var, .. } if var == "x"),
                        )
                })
                .expect("loop header with x phi");

        let (phi_id, phi_inputs) = header
            .insts
            .iter()
            .find_map(|inst| match &inst.kind {
                InstKind::Phi { var, inputs } if var == "x" => inst.id.map(|id| (id, inputs)),
                _ => None,
            })
            .expect("header phi");
        assert_eq!(phi_inputs.len(), 2);

        let exit = ssa
            .main
            .blocks
            .iter()
            .find(|block| matches!(block.term, Terminator::Return(Some(_))))
            .expect("exit block");
        let ret_id = match exit.term {
            Terminator::Return(Some(v)) => v,
            _ => unreachable!(),
        };
        let ret_inst = exit
            .insts
            .iter()
            .find(|inst| inst.id == Some(ret_id))
            .expect("return producer");
        match ret_inst.kind {
            InstKind::Alias(src) => assert_eq!(src, phi_id),
            _ => panic!("return should use loop phi"),
        }
    }

    #[test]
    fn ssa_verifier_passes_on_lowered_program() {
        let ir = IRProgram {
            main: vec![
                IRNode::new(IRInstr::ConstNum(1.0), None, None),
                IRNode::new(IRInstr::StoreVar("x".into()), None, None),
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };
        let ssa = lower_program(&ir);
        assert!(matches!(ssa.main.status, BuildStatus::Lowered));
        assert!(verify_function_ssa(&ssa.main).is_ok());
        assert!(verify_program_ssa(&ssa).is_ok());
    }

    #[test]
    fn ssa_verifier_rejects_duplicate_value_definition() {
        let ir = IRProgram {
            main: vec![
                IRNode::new(IRInstr::ConstNum(1.0), None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };
        let mut ssa = lower_program(&ir);
        assert!(matches!(ssa.main.status, BuildStatus::Lowered));

        let block0 = ssa.main.blocks.first_mut().expect("entry block");
        let dup = block0
            .insts
            .iter()
            .find_map(|inst| inst.id)
            .expect("existing value id");
        block0
            .insts
            .push(Inst::new(Some(dup), InstKind::Const(ConstValue::Num(99.0))));

        let errors = verify_function_ssa(&ssa.main).expect_err("must fail verifier");
        assert!(
            errors
                .iter()
                .any(|e| e.contains("duplicate value definition")),
            "errors: {:?}",
            errors
        );
    }

    #[test]
    fn ssa_verifier_rejects_undefined_terminator_value() {
        let ir = IRProgram {
            main: vec![
                IRNode::new(IRInstr::ConstNum(1.0), None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };
        let mut ssa = lower_program(&ir);
        assert!(matches!(ssa.main.status, BuildStatus::Lowered));
        ssa.main.blocks[0].term = Terminator::Return(Some(ValueId(999_999)));

        let errors = verify_function_ssa(&ssa.main).expect_err("must fail verifier");
        assert!(
            errors
                .iter()
                .any(|e| e.contains("return uses undefined v999999")),
            "errors: {:?}",
            errors
        );
    }
}
