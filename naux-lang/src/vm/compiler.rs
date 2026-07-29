// Compiler: AST -> IR -> Bytecode
#![allow(dead_code)]

use std::collections::HashMap;

use crate::ast::{ActionKind, BinaryOp, Expr, ExprKind, Span, Stmt, UnaryOp};
use crate::typecheck::Type;
use crate::vm::bytecode::{Bytecode, FunctionBytecode, Instr, LoweringContext, Program};
use crate::vm::egraph::{
    build_from_ir_block, run_saturation_with_proof_env, NauxExpr, ObligationBatch, SaturationResult,
};
use crate::vm::ir::{
    AliasingClass, CostBound, IRBlock, IRFunction, IRInstr, IRNode, IRProgram, NumericProof,
    ProofEnv, ProofSlot,
};
use crate::vm::ssa::{
    collect_sccp_proof_env, lower_program as lower_ssa_program, BuildStatus as SsaBuildStatus,
    Mem2RegPass, SccpPass, SsaPass,
};

type LoweredBlock = (
    Bytecode,
    Vec<String>,
    Vec<Option<Span>>,
    Vec<Option<Type>>,
    Vec<bool>,
    LoweringContext,
);
type OptimizedBytecodeBlock = (Bytecode, Vec<Option<Span>>, Vec<Option<Type>>, Vec<bool>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptimizerStopReason {
    SkippedSmallBlock,
    EmptyBuild,
    FixedPoint,
    DiminishingReturns,
    IterationCap,
    ProofChurnEarlyStop,
}

impl OptimizerStopReason {
    pub fn as_str(self) -> &'static str {
        match self {
            OptimizerStopReason::SkippedSmallBlock => "skipped_small_block",
            OptimizerStopReason::EmptyBuild => "empty_build",
            OptimizerStopReason::FixedPoint => "fixed_point",
            OptimizerStopReason::DiminishingReturns => "diminishing_returns",
            OptimizerStopReason::IterationCap => "iteration_cap",
            OptimizerStopReason::ProofChurnEarlyStop => "proof_churn_early_stop",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FeedbackConfig {
    max_iters: usize,
    min_evidence_growth: usize,
    max_block_delta: usize,
    patience: usize,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct MaterializationStats {
    pub identity_from_lhs: usize,
    pub identity_from_rhs: usize,
    pub const_zero_result: usize,
    pub const_one_result: usize,
    pub mul_to_shl: usize,
    pub block_len_before: usize,
    pub block_len_after: usize,
}

impl MaterializationStats {
    fn accumulate(&mut self, round: &MaterializationStats) {
        if self.block_len_before == 0 {
            self.block_len_before = round.block_len_before;
        }
        self.identity_from_lhs = self
            .identity_from_lhs
            .saturating_add(round.identity_from_lhs);
        self.identity_from_rhs = self
            .identity_from_rhs
            .saturating_add(round.identity_from_rhs);
        self.const_zero_result = self
            .const_zero_result
            .saturating_add(round.const_zero_result);
        self.const_one_result = self.const_one_result.saturating_add(round.const_one_result);
        self.mul_to_shl = self.mul_to_shl.saturating_add(round.mul_to_shl);
        self.block_len_after = round.block_len_after;
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct FeedbackRoundStats {
    pub round: usize,
    pub proof_grew: bool,
    pub evidence_growth: usize,
    pub block_delta: usize,
    pub shape_delta: usize,
    pub proof_delta: usize,
    pub block_len_before: usize,
    pub block_len_after: usize,
    pub materialization: MaterializationStats,
    pub obligations: Vec<ObligationBatch>,
}

#[derive(Debug, Clone, PartialEq)]
struct FeedbackLoopResult {
    block: Vec<IRNode>,
    stop_reason: OptimizerStopReason,
    materialization: MaterializationStats,
    rounds: Vec<FeedbackRoundStats>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptimizationReport {
    pub main_feedback_stop: OptimizerStopReason,
    pub function_feedback_stops: HashMap<String, OptimizerStopReason>,
    pub main_materialization: MaterializationStats,
    pub function_materialization: Vec<MaterializationStats>,
    pub main_feedback_rounds: Vec<FeedbackRoundStats>,
    pub function_feedback_rounds: Vec<Vec<FeedbackRoundStats>>,
}

pub fn validate_optimization_proof_contract(
    ir: &IRProgram,
    report: &OptimizationReport,
) -> Result<(), String> {
    crate::vm::ir::validate_program_proof_slots(ir)?;
    validate_feedback_proof_contract(
        "main",
        &report.main_materialization,
        &report.main_feedback_rounds,
    )?;
    for (idx, (materialization, rounds)) in report
        .function_materialization
        .iter()
        .zip(report.function_feedback_rounds.iter())
        .enumerate()
    {
        validate_feedback_proof_contract(&format!("function[{idx}]"), materialization, rounds)?;
    }
    Ok(())
}

fn validate_feedback_proof_contract(
    block_name: &str,
    materialization: &MaterializationStats,
    rounds: &[FeedbackRoundStats],
) -> Result<(), String> {
    if materialization.const_one_result == 0 {
        return Ok(());
    }

    let total_round_const_one = rounds
        .iter()
        .map(|round| round.materialization.const_one_result)
        .sum::<usize>();
    if total_round_const_one < materialization.const_one_result {
        return Err(format!(
            "proof contract failed in `{}`: div-self materialization count {} exceeds round evidence {}",
            block_name, materialization.const_one_result, total_round_const_one
        ));
    }

    for round in rounds {
        if round.materialization.const_one_result > 0
            && !round_has_discharged_rewrite(round, "div-self-nonzero")
        {
            return Err(format!(
                "proof contract failed in `{}` round {}: div-self materialized {} time(s) without discharged `div-self-nonzero` obligation",
                block_name, round.round, round.materialization.const_one_result
            ));
        }
    }
    Ok(())
}

fn round_has_discharged_rewrite(round: &FeedbackRoundStats, rewrite_name: &str) -> bool {
    round.obligations.iter().any(|batch| {
        batch.obligations.iter().any(|obligation| {
            obligation.rewrite_name == rewrite_name
                && matches!(
                    obligation.status,
                    crate::vm::egraph::ObligationStatus::Discharged
                )
        })
    })
}

fn unify_types(a: Type, b: Type) -> Type {
    if a == b {
        a
    } else {
        Type::Any
    }
}

fn unify_opt(a: Option<Type>, b: Option<Type>) -> Option<Type> {
    match (a, b) {
        (Some(x), Some(y)) => Some(unify_types(x, y)),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    }
}

fn merge_proof_slots(slots: &[&ProofSlot]) -> ProofSlot {
    let mut out = ProofSlot::default();
    for slot in slots {
        if out.refined_type.is_none() && slot.refined_type.is_some() {
            out.refined_type = slot.refined_type.clone();
        }
        out.numeric = match (
            out.numeric.or_else(|| out.numeric_fallback()),
            slot.numeric.or_else(|| slot.numeric_fallback()),
        ) {
            (None, None) => None,
            (Some(current), Some(next)) => current.merge(next),
            (Some(current), None) => Some(current),
            (None, Some(next)) => Some(next),
        };
        if out.cost_bound.is_none() && slot.cost_bound.is_some() {
            out.cost_bound = slot.cost_bound.clone();
        }
        if out.coq_cert.is_none() && slot.coq_cert.is_some() {
            out.coq_cert = slot.coq_cert;
        }
        if matches!(out.aliasing, AliasingClass::Unknown)
            && !matches!(slot.aliasing, AliasingClass::Unknown)
        {
            out.aliasing = slot.aliasing;
        }
        if slot.unsafe_context {
            out.unsafe_context = true;
        }
    }
    out
}

fn merge_cost_bounds(bounds: &[&CostBound]) -> CostBound {
    fn sum_field(values: impl Iterator<Item = Option<u32>>) -> Option<u32> {
        let mut saw_any = false;
        let mut acc = 0_u32;
        for value in values.flatten() {
            saw_any = true;
            acc = acc.saturating_add(value);
        }
        saw_any.then_some(acc)
    }

    CostBound {
        worst_cycles: sum_field(bounds.iter().map(|b| b.worst_cycles)),
        alloc_bytes: sum_field(bounds.iter().map(|b| b.alloc_bytes)),
        mem_reads: sum_field(bounds.iter().map(|b| b.mem_reads)),
        mem_writes: sum_field(bounds.iter().map(|b| b.mem_writes)),
    }
}

fn lowering_context_for_block(block: &[IRNode], incoming: &LoweringContext) -> LoweringContext {
    let mut proof_slots: Vec<&ProofSlot> = vec![&incoming.proof];
    let mut cost_bounds: Vec<&CostBound> = vec![&incoming.cost_acc];
    let mut unsafe_ctx = incoming.unsafe_ctx;

    for node in block {
        proof_slots.push(&node.proof);
        if let Some(cost) = node.proof.cost_bound.as_ref() {
            cost_bounds.push(cost);
        }
        unsafe_ctx |= node.proof.unsafe_context;
    }

    LoweringContext {
        proof: merge_proof_slots(&proof_slots),
        cost_acc: merge_cost_bounds(&cost_bounds),
        unsafe_ctx,
    }
}

/// Public entry: compile AST straight to bytecode (via IR + optimize).
pub fn compile_script(stmts: &[Stmt]) -> Program {
    let (ir, report) = compile_ir_with_report(stmts);
    if ir_proof_strict_enabled() {
        if let Err(err) = validate_optimization_proof_contract(&ir, &report) {
            panic!("{}", err);
        }
    }
    lower_ir_to_bytecode(ir)
}

#[cfg(feature = "experimental-regions")]
#[derive(Debug, Clone)]
pub struct RegionCompiledProgram {
    pub bytecode: Program,
    pub region_report: crate::region::analyze::RegionReport,
    pub region_plan: crate::region::RegionLoweringPlan,
}

/// Compile ordinary bytecode together with a verified sidecar region plan.
///
/// The bytecode is intentionally identical to `compile_script` in this
/// admission stage. A future region runtime must consume the verified sidecar
/// rather than infer lifetimes again from bytecode shapes.
#[cfg(feature = "experimental-regions")]
pub fn compile_script_with_region_plan(
    stmts: &[Stmt],
) -> Result<RegionCompiledProgram, crate::region::RegionLoweringError> {
    let region_report = crate::region::infer_regions(stmts);
    if !region_report.violations.is_empty() {
        return Err(crate::region::RegionLoweringError {
            message: format!(
                "region analysis has {} unresolved constraint(s)",
                region_report.violations.len()
            ),
        });
    }
    let region_plan = crate::region::lower_region_report(&region_report);
    crate::region::verify_region_lowering_plan(&region_report, &region_plan)?;
    Ok(RegionCompiledProgram {
        bytecode: compile_script(stmts),
        region_report,
        region_plan,
    })
}

/// Compile AST into IR (stack-based).
pub fn compile_ir(stmts: &[Stmt]) -> IRProgram {
    compile_ir_with_report(stmts).0
}

pub fn compile_ir_with_report(stmts: &[Stmt]) -> (IRProgram, OptimizationReport) {
    let proof_catalog = crate::refinement::check_refinements(stmts)
        .map(|report| report.proof_slots)
        .unwrap_or_default();

    // Thu chữ ký hàm trước để biết arity.
    let mut fn_sigs: HashMap<String, usize> = HashMap::new();
    for stmt in stmts {
        if let Stmt::FnDef { name, params, .. } = stmt {
            fn_sigs.insert(name.clone(), params.len());
        }
    }

    let mut main: Vec<IRNode> = Vec::new();
    let mut main_ret: Option<Type> = None;
    let mut functions: HashMap<String, IRFunction> = HashMap::new();
    let mut env: HashMap<String, Type> = HashMap::new();
    let mut proof_state = CompileProofState::new(proof_catalog.clone());
    for stmt in stmts {
        match stmt {
            Stmt::FnDef {
                name, params, body, ..
            } => {
                let mut code: Vec<IRNode> = Vec::new();
                let mut local_env: HashMap<String, Type> = HashMap::new();
                let mut local_proof_state = CompileProofState::new(proof_catalog.clone());
                for p in params {
                    local_env.insert(p.name.clone(), Type::Any);
                }
                let mut ret_ty: Option<Type> = None;
                for s in body {
                    if let Some(t) = compile_stmt_ir(
                        s,
                        &mut code,
                        &mut local_env,
                        &fn_sigs,
                        &mut local_proof_state,
                    ) {
                        ret_ty = Some(ret_ty.map(|old| unify_types(old, t.clone())).unwrap_or(t));
                    }
                }
                code.push(IRNode::new(IRInstr::Return, None, ret_ty.clone()));
                functions.insert(
                    name.clone(),
                    IRFunction {
                        params: params.iter().map(|p| p.name.clone()).collect(),
                        code,
                        return_type: ret_ty.clone(),
                    },
                );
            }
            _ => {
                if let Some(t) =
                    compile_stmt_ir(stmt, &mut main, &mut env, &fn_sigs, &mut proof_state)
                {
                    main_ret = Some(main_ret.map(|old| unify_types(old, t.clone())).unwrap_or(t));
                }
            }
        }
    }
    main.push(IRNode::new(IRInstr::Return, None, main_ret.clone()));
    let ir = IRProgram {
        main,
        functions,
        main_return: main_ret,
    };

    optimize_ir_with_report(ir)
}

fn integer_literal(expr: &Expr) -> Option<i64> {
    match &expr.kind {
        ExprKind::Number(n) if n.fract().abs() < f64::EPSILON => Some(*n as i64),
        _ => None,
    }
}

#[derive(Debug, Clone, Default)]
struct CompileProofState {
    catalog: HashMap<String, ProofSlot>,
    current: HashMap<String, ProofSlot>,
}

impl CompileProofState {
    fn new(catalog: HashMap<String, ProofSlot>) -> Self {
        Self {
            catalog,
            current: HashMap::new(),
        }
    }

    fn load(&self, name: &str) -> Option<ProofSlot> {
        self.current.get(name).cloned()
    }

    fn assign(&mut self, name: &str, expr: &Expr) -> Option<ProofSlot> {
        let proof = self.proof_for_assignment(name, expr);
        if let Some(slot) = proof.clone() {
            self.current.insert(name.to_string(), slot);
        } else {
            self.current.remove(name);
        }
        proof
    }

    fn proof_for_assignment(&self, name: &str, expr: &Expr) -> Option<ProofSlot> {
        let exact = integer_literal(expr)?;
        let exact_slot = ProofSlot {
            numeric: Some(NumericProof::from_exact(exact)),
            ..ProofSlot::default()
        };
        let Some(catalog_slot) = self.catalog.get(name) else {
            return Some(exact_slot);
        };
        let merged = catalog_slot
            .numeric
            .or_else(|| catalog_slot.numeric_fallback())
            .and_then(|numeric| numeric.merge(NumericProof::from_exact(exact)))?;
        Some(merge_feedback_proof(
            &exact_slot,
            &ProofSlot {
                numeric: Some(merged),
                ..catalog_slot.clone()
            },
        ))
    }

    fn refine_from_condition(&mut self, cond: &Expr, branch_true: bool) {
        let Some((name, slot)) = condition_proof(cond, branch_true) else {
            return;
        };
        let merged = self
            .current
            .get(&name)
            .map(|current| merge_feedback_proof(current, &slot))
            .unwrap_or(slot);
        self.current.insert(name, merged);
    }
}

fn condition_proof(cond: &Expr, branch_true: bool) -> Option<(String, ProofSlot)> {
    let ExprKind::Binary { op, left, right } = &cond.kind else {
        return None;
    };
    let (ExprKind::Var(name), ExprKind::Number(n)) = (&left.kind, &right.kind) else {
        return None;
    };
    if n.fract().abs() >= f64::EPSILON {
        return None;
    }
    let value = *n as i64;
    let numeric = match (op, branch_true) {
        (BinaryOp::Eq, true) => Some(NumericProof::from_exact(value)),
        (BinaryOp::Ne, true) if value == 0 => Some(NumericProof {
            nonzero: true,
            ..NumericProof::default()
        }),
        (BinaryOp::Eq, false) if value == 0 => Some(NumericProof {
            nonzero: true,
            ..NumericProof::default()
        }),
        (BinaryOp::Gt, true) if value >= 0 => Some(NumericProof {
            range: Some(((value as u64).saturating_add(1), u64::MAX)),
            nonzero: true,
            ..NumericProof::default()
        }),
        (BinaryOp::Ge, true) if value > 0 => Some(NumericProof {
            range: Some((value as u64, u64::MAX)),
            nonzero: true,
            ..NumericProof::default()
        }),
        (BinaryOp::Lt, true) if value <= 0 => Some(NumericProof {
            nonzero: true,
            ..NumericProof::default()
        }),
        (BinaryOp::Le, true) if value < 0 => Some(NumericProof {
            nonzero: true,
            ..NumericProof::default()
        }),
        _ => None,
    }?;
    Some((
        name.clone(),
        ProofSlot {
            numeric: Some(numeric),
            ..ProofSlot::default()
        },
    ))
}

/// Peephole optimizer: const-fold basic arith/compare, drop trivial jumps, prune unreachable.
fn optimize_ir(ir: IRProgram) -> IRProgram {
    optimize_ir_with_report(ir).0
}

fn optimize_ir_with_report(ir: IRProgram) -> (IRProgram, OptimizationReport) {
    let main_result = optimize_block(ir.main);
    let mut function_feedback_stops = HashMap::new();
    let mut function_materialization = Vec::new();
    let mut function_feedback_rounds = Vec::new();
    let mut function_entries = ir.functions.into_iter().collect::<Vec<_>>();
    function_entries.sort_by(|(lhs, _), (rhs, _)| lhs.cmp(rhs));
    let functions = function_entries
        .into_iter()
        .map(|(name, f)| {
            let optimized = optimize_block(f.code);
            function_feedback_stops.insert(name.clone(), optimized.stop_reason);
            function_materialization.push(optimized.materialization.clone());
            function_feedback_rounds.push(optimized.rounds.clone());
            (
                name,
                IRFunction {
                    params: f.params,
                    code: optimized.block,
                    return_type: f.return_type,
                },
            )
        })
        .collect();
    (
        IRProgram {
            main: main_result.block,
            functions,
            main_return: ir.main_return,
        },
        OptimizationReport {
            main_feedback_stop: main_result.stop_reason,
            function_feedback_stops,
            main_materialization: main_result.materialization,
            function_materialization,
            main_feedback_rounds: main_result.rounds,
            function_feedback_rounds,
        },
    )
}

fn optimize_block(block: Vec<IRNode>) -> FeedbackLoopResult {
    // Pass 1: peephole + record mapping
    let mut out: Vec<IRNode> = Vec::new();
    let mut orig_idx: Vec<usize> = Vec::new();
    let mut map_old_to_new: Vec<Option<usize>> = vec![None; block.len()];
    // NOTE: keep optimizer conservative to preserve control-flow correctness.
    let mut i = 0;
    while i < block.len() {
        // Const-fold arithmetic/compare on two consts followed by op
        if i + 2 < block.len() {
            if let (IRInstr::ConstNum(a), IRInstr::ConstNum(b), op) =
                (&block[i].instr, &block[i + 1].instr, &block[i + 2].instr)
            {
                if let Some(res_num) = fold_num(*a, *b, op) {
                    let new_idx = out.len();
                    out.push(
                        IRNode::new(
                            IRInstr::ConstNum(res_num),
                            block[i].span.clone(),
                            Some(Type::Num),
                        )
                        .with_proof(merge_proof_slots(&[
                            &block[i].proof,
                            &block[i + 1].proof,
                            &block[i + 2].proof,
                        ])),
                    );
                    orig_idx.push(i);
                    map_old_to_new[i] = Some(new_idx);
                    map_old_to_new[i + 1] = Some(new_idx);
                    map_old_to_new[i + 2] = Some(new_idx);
                    i += 3;
                    continue;
                }
                if let Some(res_bool) = fold_cmp(*a, *b, op) {
                    let new_idx = out.len();
                    out.push(
                        IRNode::new(
                            IRInstr::ConstBool(res_bool),
                            block[i].span.clone(),
                            Some(Type::Bool),
                        )
                        .with_proof(merge_proof_slots(&[
                            &block[i].proof,
                            &block[i + 1].proof,
                            &block[i + 2].proof,
                        ])),
                    );
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
            if let (IRInstr::ConstBool(b), IRInstr::JumpIfFalse(t)) =
                (&block[i].instr, &block[i + 1].instr)
            {
                if *b {
                    // condition true -> drop both instructions
                    map_old_to_new[i] = None;
                    map_old_to_new[i + 1] = None;
                    i += 2;
                    continue;
                } else {
                    // condition false -> always jump
                    let new_idx = out.len();
                    out.push(
                        IRNode::new(IRInstr::Jump(*t), block[i].span.clone(), None)
                            .with_proof(merge_proof_slots(&[&block[i].proof, &block[i + 1].proof])),
                    );
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
                i += 1;
                continue;
            }
        }
        if let IRInstr::JumpIfFalse(t) = block[i].instr {
            if t == i + 1 {
                map_old_to_new[i] = None;
                i += 1;
                continue;
            }
        }

        let node = block[i].clone();

        let new_idx = out.len();
        map_old_to_new[i] = Some(new_idx);

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
    let pruned = prune_unreachable(out);
    if pruned.len() < 3 || pruned.len() < egraph_min_block_len() {
        return FeedbackLoopResult {
            block: pruned,
            stop_reason: OptimizerStopReason::SkippedSmallBlock,
            materialization: MaterializationStats::default(),
            rounds: Vec::new(),
        };
    }
    // Pass 4: E-graph guided canonicalization before lowering.
    run_egraph_feedback_loop(pruned, snapshot_feedback_config())
}

fn apply_egraph_guided_rewrites(block: Vec<IRNode>) -> Vec<IRNode> {
    if block.len() < 3 || block.len() < egraph_min_block_len() {
        return block;
    }
    run_egraph_feedback_loop(block, snapshot_feedback_config()).block
}

fn run_egraph_feedback_loop(block: Vec<IRNode>, config: FeedbackConfig) -> FeedbackLoopResult {
    const PROOF_CHURN_PATIENCE: usize = 2;
    const NUMERIC_PROOF_SKIP_MIN_BLOCK_LEN: usize = 64;

    if block.len() < 3 {
        return FeedbackLoopResult {
            block,
            stop_reason: OptimizerStopReason::SkippedSmallBlock,
            materialization: MaterializationStats::default(),
            rounds: Vec::new(),
        };
    }

    let mut current = block;
    let mut prev_env: Option<ProofEnv> = None;
    let mut low_yield_rounds = 0_usize;
    let mut churn_rounds = 0_usize;

    let seed_env = extract_proof_env(&current);
    if current.len() >= NUMERIC_PROOF_SKIP_MIN_BLOCK_LEN
        && (!has_numeric_proof_potential(&seed_env)
            || !has_proof_gated_numeric_rewrite_surface(&current))
    {
        return FeedbackLoopResult {
            block: current,
            stop_reason: OptimizerStopReason::FixedPoint,
            materialization: MaterializationStats::default(),
            rounds: Vec::new(),
        };
    }

    if config.max_iters == 0 {
        return FeedbackLoopResult {
            block: current,
            stop_reason: OptimizerStopReason::IterationCap,
            materialization: MaterializationStats::default(),
            rounds: Vec::new(),
        };
    }

    let mut materialization = MaterializationStats::default();
    let mut rounds = Vec::new();
    for round_idx in 0..config.max_iters {
        let mut proof_env = extract_proof_env(&current);
        if sccp_feedback_enabled() {
            proof_env = merge_proof_envs(
                &proof_env,
                &collect_sccp_feedback_env(&current).unwrap_or_default(),
            );
        }
        let mut block_with_env = apply_proof_env_to_block(&current, &proof_env);
        let build = build_from_ir_block(&block_with_env);
        if build.roots.is_empty() {
            return FeedbackLoopResult {
                block: block_with_env,
                stop_reason: OptimizerStopReason::EmptyBuild,
                materialization,
                rounds,
            };
        }
        let saturated = run_saturation_with_proof_env(build, 8, 10_000, &proof_env);
        if let Some(egraph_feedback_env) = collect_egraph_feedback_env(&block_with_env, &saturated)
        {
            proof_env = merge_proof_envs(&proof_env, &egraph_feedback_env);
            let egraph_upgraded_block = apply_proof_env_to_block(&current, &proof_env);
            if sccp_feedback_enabled() {
                if let Some(sccp_feedback_env) = collect_sccp_feedback_env(&egraph_upgraded_block) {
                    proof_env = merge_proof_envs(&proof_env, &sccp_feedback_env);
                }
            }
            block_with_env = apply_proof_env_to_block(&current, &proof_env);
        }
        let proof_grew = prev_env.as_ref() != Some(&proof_env);
        let evidence_growth = prev_env
            .as_ref()
            .map(|prev| proof_env.evidence_growth(prev))
            .unwrap_or_else(|| proof_env.evidence_score());
        let (next, round_materialization) = materialize_egraph_rewrites(block_with_env, &saturated);
        materialization.accumulate(&round_materialization);
        let block_delta = block_delta_count(&current, &next);
        let shape_delta = shape_delta_count(&current, &next);
        let proof_delta = proof_delta_count(&current, &next);
        rounds.push(FeedbackRoundStats {
            round: round_idx + 1,
            proof_grew,
            evidence_growth,
            block_delta,
            shape_delta,
            proof_delta,
            block_len_before: current.len(),
            block_len_after: next.len(),
            materialization: round_materialization.clone(),
            obligations: saturated.obligation_batches.clone(),
        });
        if next == current && !proof_grew {
            return FeedbackLoopResult {
                block: next,
                stop_reason: OptimizerStopReason::FixedPoint,
                materialization,
                rounds,
            };
        }

        let total_mat = round_materialization.identity_from_lhs
            + round_materialization.identity_from_rhs
            + round_materialization.const_zero_result
            + round_materialization.const_one_result
            + round_materialization.mul_to_shl;
        if shape_delta == 0 && total_mat == 0 {
            churn_rounds = churn_rounds.saturating_add(1);
            if churn_rounds >= PROOF_CHURN_PATIENCE {
                return FeedbackLoopResult {
                    block: next,
                    stop_reason: OptimizerStopReason::ProofChurnEarlyStop,
                    materialization,
                    rounds,
                };
            }
        } else {
            churn_rounds = 0;
        }

        if evidence_growth <= config.min_evidence_growth && block_delta <= config.max_block_delta {
            low_yield_rounds = low_yield_rounds.saturating_add(1);
            if low_yield_rounds >= config.patience {
                return FeedbackLoopResult {
                    block: next,
                    stop_reason: OptimizerStopReason::DiminishingReturns,
                    materialization,
                    rounds,
                };
            }
        } else {
            low_yield_rounds = 0;
        }

        prev_env = Some(proof_env);
        current = next;
    }
    FeedbackLoopResult {
        block: current,
        stop_reason: OptimizerStopReason::IterationCap,
        materialization,
        rounds,
    }
}

fn sccp_feedback_enabled() -> bool {
    std::env::var("NAUX_EGRAPH_ENABLE_SCCP_FEEDBACK")
        .ok()
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn egraph_min_block_len() -> usize {
    std::env::var("NAUX_EGRAPH_MIN_BLOCK_LEN")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(64)
}

fn snapshot_feedback_config() -> FeedbackConfig {
    FeedbackConfig {
        max_iters: parse_feedback_env("NAUX_EGRAPH_FEEDBACK_ITERS", 2),
        min_evidence_growth: parse_feedback_env("NAUX_EGRAPH_FEEDBACK_MIN_EVIDENCE_GROWTH", 0),
        max_block_delta: parse_feedback_env("NAUX_EGRAPH_FEEDBACK_MAX_BLOCK_DELTA", 1),
        patience: parse_feedback_env("NAUX_EGRAPH_FEEDBACK_PATIENCE", 2).max(1),
    }
}

fn parse_feedback_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn block_delta_count(prev: &[IRNode], next: &[IRNode]) -> usize {
    let shared = prev.len().min(next.len());
    let mut delta = prev.len().max(next.len()) - shared;
    for i in 0..shared {
        if prev[i] != next[i] {
            delta += 1;
        }
    }
    delta
}

fn shape_delta_count(prev: &[IRNode], next: &[IRNode]) -> usize {
    prev.iter()
        .zip(next.iter())
        .filter(|(a, b)| a.instr != b.instr || a.result_type != b.result_type)
        .count()
        + prev.len().abs_diff(next.len())
}

fn proof_delta_count(prev: &[IRNode], next: &[IRNode]) -> usize {
    prev.iter()
        .zip(next.iter())
        .filter(|(a, b)| a.proof != b.proof)
        .count()
}

fn extract_proof_env(block: &[IRNode]) -> ProofEnv {
    let mut out = ProofEnv::default();
    for node in block {
        if node.proof.unsafe_context {
            out.unsafe_context = true;
        }
        out.by_node.insert(node.id, node.proof.clone());
    }
    out
}

fn has_numeric_proof_potential(env: &ProofEnv) -> bool {
    env.by_node
        .values()
        .any(|slot| slot.proven_nonzero() || slot.numeric_range().is_some())
}

fn has_proof_gated_numeric_rewrite_surface(block: &[IRNode]) -> bool {
    for i in 2..block.len() {
        match block[i].instr {
            IRInstr::Div if matches!(block[i].result_type, Some(Type::Num)) => return true,
            IRInstr::And
                if matches!(block[i].result_type, Some(Type::Num))
                    && (is_const_num(&block[i - 1], 255.0)
                        || is_const_num(&block[i - 2], 255.0)) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn merge_feedback_proof(base: &ProofSlot, feedback: &ProofSlot) -> ProofSlot {
    ProofSlot {
        refined_type: feedback
            .refined_type
            .clone()
            .or_else(|| base.refined_type.clone()),
        numeric: match (
            base.numeric.or_else(|| base.numeric_fallback()),
            feedback.numeric.or_else(|| feedback.numeric_fallback()),
        ) {
            (Some(current), Some(next)) => current.merge(next),
            (Some(current), None) => Some(current),
            (None, Some(next)) => Some(next),
            (None, None) => None,
        },
        cost_bound: feedback
            .cost_bound
            .clone()
            .or_else(|| base.cost_bound.clone()),
        coq_cert: feedback.coq_cert.or(base.coq_cert),
        aliasing: if feedback.aliasing != AliasingClass::Unknown {
            feedback.aliasing
        } else {
            base.aliasing
        },
        unsafe_context: base.unsafe_context || feedback.unsafe_context,
    }
}

fn merge_proof_envs(base: &ProofEnv, feedback: &ProofEnv) -> ProofEnv {
    let mut merged = base.clone();
    merged.unsafe_context |= feedback.unsafe_context;
    for (node_id, slot) in &feedback.by_node {
        let next = if let Some(existing) = merged.by_node.get(node_id) {
            merge_feedback_proof(existing, slot)
        } else {
            slot.clone()
        };
        merged.by_node.insert(*node_id, next);
    }
    merged
}

fn apply_proof_env_to_block(block: &[IRNode], env: &ProofEnv) -> Vec<IRNode> {
    block
        .iter()
        .cloned()
        .map(|mut node| {
            if let Some(slot) = env.by_node.get(&node.id) {
                node.proof = merge_feedback_proof(&node.proof, slot);
            }
            node
        })
        .collect()
}

fn collect_sccp_feedback_env(block: &[IRNode]) -> Option<ProofEnv> {
    let ir = IRProgram {
        main: block.to_vec(),
        functions: HashMap::new(),
        main_return: None,
    };
    let mut ssa = lower_ssa_program(&ir);
    if !matches!(ssa.main.status, SsaBuildStatus::Lowered) {
        return None;
    }
    let mut mem2reg = Mem2RegPass;
    let _ = mem2reg.run(&mut ssa.main);
    let mut sccp = SccpPass;
    let _ = sccp.run(&mut ssa.main);
    Some(collect_sccp_proof_env(&ssa.main, block))
}

fn collect_egraph_feedback_env(block: &[IRNode], saturated: &SaturationResult) -> Option<ProofEnv> {
    let summary = saturated.extract_eclass_proof_summary();
    if summary.is_empty() {
        return None;
    }

    let mut env = ProofEnv::default();
    let mut grew = false;
    for node in block {
        let Some(eclass) = saturated.node_to_eclass.get(&node.id) else {
            continue;
        };
        let root = saturated.egraph.find(*eclass);
        let Some(eclass_slot) = summary.by_eclass.get(&root) else {
            continue;
        };
        let merged = merge_feedback_proof(&node.proof, eclass_slot);
        grew |= merged != node.proof;
        env.unsafe_context |= merged.unsafe_context;
        env.by_node.insert(node.id, merged);
    }

    grew.then_some(env)
}

fn materialize_egraph_rewrites(
    mut block: Vec<IRNode>,
    saturated: &SaturationResult,
) -> (Vec<IRNode>, MaterializationStats) {
    let mut stats = MaterializationStats {
        block_len_before: block.len(),
        ..MaterializationStats::default()
    };
    for i in 2..block.len() {
        let lhs = block[i - 2].clone();
        let rhs = block[i - 1].clone();
        let merged_proof = merge_proof_slots(&[&lhs.proof, &rhs.proof, &block[i].proof]);
        match block[i].instr {
            IRInstr::Add if matches!(block[i].result_type, Some(Type::Num)) => {
                if is_const_num(&rhs, 0.0)
                    && materialize_identity_from_lhs(&mut block, i, &lhs, &merged_proof)
                {
                    stats.identity_from_lhs = stats.identity_from_lhs.saturating_add(1);
                    continue;
                }
                if is_const_num(&lhs, 0.0)
                    && materialize_identity_from_rhs(&mut block, i, &rhs, &merged_proof)
                {
                    stats.identity_from_rhs = stats.identity_from_rhs.saturating_add(1);
                    continue;
                }
            }
            IRInstr::Sub if matches!(block[i].result_type, Some(Type::Num)) => {
                if is_const_num(&rhs, 0.0)
                    && materialize_identity_from_lhs(&mut block, i, &lhs, &merged_proof)
                {
                    stats.identity_from_lhs = stats.identity_from_lhs.saturating_add(1);
                    continue;
                }
            }
            IRInstr::Mul if matches!(block[i].result_type, Some(Type::Num)) => {
                if let IRInstr::ConstNum(v) = rhs.instr {
                    if v.fract() == 0.0 {
                        if let Some(sh_amt) = eclass_shl_shift_amount(saturated, block[i].id) {
                            let expected = match v as i64 {
                                2 => Some(1_i64),
                                4 => Some(2_i64),
                                8 => Some(3_i64),
                                _ => None,
                            };
                            if let Some(expected) = expected {
                                if sh_amt == expected {
                                    block[i - 1].instr = IRInstr::ConstNum(sh_amt as f64);
                                    block[i - 1].result_type = Some(Type::Num);
                                    block[i].instr = IRInstr::Shl;
                                    block[i].result_type = Some(Type::Num);
                                    block[i].proof = merged_proof.clone();
                                    stats.mul_to_shl = stats.mul_to_shl.saturating_add(1);
                                    continue;
                                }
                            }
                        }
                    }
                }
                if is_const_num(&rhs, 0.0) {
                    materialize_const_num_result(&mut block, i, 0.0, &merged_proof);
                    stats.const_zero_result = stats.const_zero_result.saturating_add(1);
                    continue;
                }
                if is_const_num(&rhs, 1.0)
                    && materialize_identity_from_lhs(&mut block, i, &lhs, &merged_proof)
                {
                    stats.identity_from_lhs = stats.identity_from_lhs.saturating_add(1);
                    continue;
                }
                if is_const_num(&lhs, 1.0)
                    && materialize_identity_from_rhs(&mut block, i, &rhs, &merged_proof)
                {
                    stats.identity_from_rhs = stats.identity_from_rhs.saturating_add(1);
                    continue;
                }
            }
            IRInstr::Div if matches!(block[i].result_type, Some(Type::Num)) => {
                let operand_proof = merge_feedback_proof(&lhs.proof, &rhs.proof);
                if cloneable_leaf_equal(&lhs, &rhs)
                    && operand_proof.proven_nonzero()
                    && eclass_contains_num(saturated, block[i].id, 1)
                {
                    let result_proof = materialized_const_proof(&block[i].proof, 1);
                    materialize_const_num_result(&mut block, i, 1.0, &result_proof);
                    stats.const_one_result = stats.const_one_result.saturating_add(1);
                    continue;
                }
                if is_const_num(&rhs, 1.0)
                    && materialize_identity_from_lhs(&mut block, i, &lhs, &merged_proof)
                {
                    stats.identity_from_lhs = stats.identity_from_lhs.saturating_add(1);
                    continue;
                }
            }
            IRInstr::Xor => {
                if cloneable_leaf_equal(&lhs, &rhs) {
                    materialize_const_num_result(&mut block, i, 0.0, &merged_proof);
                    stats.const_zero_result = stats.const_zero_result.saturating_add(1);
                    continue;
                }
                if !matches!(block[i].result_type, Some(Type::Num)) {
                    continue;
                }
                if is_const_num(&rhs, 0.0)
                    && materialize_identity_from_lhs(&mut block, i, &lhs, &merged_proof)
                {
                    stats.identity_from_lhs = stats.identity_from_lhs.saturating_add(1);
                    continue;
                }
                if is_const_num(&lhs, 0.0)
                    && materialize_identity_from_rhs(&mut block, i, &rhs, &merged_proof)
                {
                    stats.identity_from_rhs = stats.identity_from_rhs.saturating_add(1);
                    continue;
                }
            }
            IRInstr::And if matches!(block[i].result_type, Some(Type::Num)) => {
                if is_const_num(&rhs, 0.0) {
                    materialize_const_num_result(&mut block, i, 0.0, &merged_proof);
                    stats.const_zero_result = stats.const_zero_result.saturating_add(1);
                    continue;
                }
                if is_const_num(&rhs, 255.0)
                    && merged_proof.range_within(0, 255)
                    && materialize_identity_from_lhs(&mut block, i, &lhs, &merged_proof)
                {
                    stats.identity_from_lhs = stats.identity_from_lhs.saturating_add(1);
                    continue;
                }
                if is_const_num(&lhs, 255.0)
                    && merged_proof.range_within(0, 255)
                    && materialize_identity_from_rhs(&mut block, i, &rhs, &merged_proof)
                {
                    stats.identity_from_rhs = stats.identity_from_rhs.saturating_add(1);
                    continue;
                }
                if cloneable_leaf_equal(&lhs, &rhs)
                    && materialize_identity_from_lhs(&mut block, i, &lhs, &merged_proof)
                {
                    stats.identity_from_lhs = stats.identity_from_lhs.saturating_add(1);
                    continue;
                }
            }
            IRInstr::Or if matches!(block[i].result_type, Some(Type::Num)) => {
                if is_const_num(&rhs, 0.0)
                    && materialize_identity_from_lhs(&mut block, i, &lhs, &merged_proof)
                {
                    stats.identity_from_lhs = stats.identity_from_lhs.saturating_add(1);
                    continue;
                }
                if is_const_num(&lhs, 0.0)
                    && materialize_identity_from_rhs(&mut block, i, &rhs, &merged_proof)
                {
                    stats.identity_from_rhs = stats.identity_from_rhs.saturating_add(1);
                    continue;
                }
                if cloneable_leaf_equal(&lhs, &rhs)
                    && materialize_identity_from_lhs(&mut block, i, &lhs, &merged_proof)
                {
                    stats.identity_from_lhs = stats.identity_from_lhs.saturating_add(1);
                    continue;
                }
            }
            _ => {}
        }
    }
    stats.block_len_after = block.len();
    (block, stats)
}

fn is_const_num(node: &IRNode, expected: f64) -> bool {
    matches!(node.instr, IRInstr::ConstNum(v) if (v - expected).abs() < f64::EPSILON)
}

fn materialized_const_proof(base: &ProofSlot, value: i64) -> ProofSlot {
    let exact = NumericProof::from_exact(value);
    let base_numeric = base.numeric.or_else(|| base.numeric_fallback());
    let merged_numeric = base_numeric.and_then(|numeric| numeric.merge(exact));
    let mut out = base.clone();
    out.numeric = merged_numeric.or(Some(exact));
    if merged_numeric.is_none()
        || out
            .refined_type
            .as_ref()
            .is_some_and(|refined| refined.base != Type::Num)
    {
        out.refined_type = None;
    }
    out
}

fn cloneable_leaf(node: &IRNode) -> Option<(IRInstr, Option<Type>)> {
    let instr = match &node.instr {
        IRInstr::ConstNum(v) => IRInstr::ConstNum(*v),
        IRInstr::ConstText(s) => IRInstr::ConstText(s.clone()),
        IRInstr::ConstBool(b) => IRInstr::ConstBool(*b),
        IRInstr::PushNull => IRInstr::PushNull,
        IRInstr::LoadVar(name) => IRInstr::LoadVar(name.clone()),
        _ => return None,
    };
    Some((instr, node.result_type.clone()))
}

fn cloneable_leaf_equal(lhs: &IRNode, rhs: &IRNode) -> bool {
    match (&lhs.instr, &rhs.instr) {
        (IRInstr::ConstNum(a), IRInstr::ConstNum(b)) => (a - b).abs() < f64::EPSILON,
        (IRInstr::ConstText(a), IRInstr::ConstText(b)) => a == b,
        (IRInstr::ConstBool(a), IRInstr::ConstBool(b)) => a == b,
        (IRInstr::PushNull, IRInstr::PushNull) => true,
        (IRInstr::LoadVar(a), IRInstr::LoadVar(b)) => a == b,
        _ => false,
    }
}

fn materialize_identity_from_lhs(
    block: &mut [IRNode],
    op_idx: usize,
    lhs: &IRNode,
    merged_proof: &ProofSlot,
) -> bool {
    let Some((instr, result_type)) = cloneable_leaf(lhs) else {
        return false;
    };
    block[op_idx - 1].instr = IRInstr::Pop;
    block[op_idx - 1].result_type = None;
    block[op_idx].instr = instr;
    block[op_idx].result_type = result_type;
    block[op_idx].proof = merged_proof.clone();
    true
}

fn materialize_identity_from_rhs(
    block: &mut [IRNode],
    op_idx: usize,
    rhs: &IRNode,
    merged_proof: &ProofSlot,
) -> bool {
    let Some((instr, result_type)) = cloneable_leaf(rhs) else {
        return false;
    };
    block[op_idx - 1].instr = IRInstr::Pop;
    block[op_idx - 1].result_type = None;
    block[op_idx].instr = instr;
    block[op_idx].result_type = result_type;
    block[op_idx].proof = merged_proof.clone();
    true
}

fn materialize_const_num_result(
    block: &mut [IRNode],
    op_idx: usize,
    value: f64,
    merged_proof: &ProofSlot,
) {
    block[op_idx - 1].instr = IRInstr::Pop;
    block[op_idx - 1].result_type = None;
    block[op_idx].instr = IRInstr::ConstNum(value);
    block[op_idx].result_type = Some(Type::Num);
    block[op_idx].proof = merged_proof.clone();
}

fn eclass_contains_num(saturated: &SaturationResult, node_id: u32, needle: i64) -> bool {
    let Some(root_id) = saturated.node_to_eclass.get(&node_id) else {
        return false;
    };
    let root = saturated.egraph.find(*root_id);
    saturated.egraph[root]
        .nodes
        .iter()
        .any(|n| matches!(n, NauxExpr::Num(v) if *v == needle))
}

fn eclass_shl_shift_amount(saturated: &SaturationResult, node_id: u32) -> Option<i64> {
    let root_id = *saturated.node_to_eclass.get(&node_id)?;
    let root = saturated.egraph.find(root_id);
    for n in &saturated.egraph[root].nodes {
        if let NauxExpr::Shl([_, rhs]) = n {
            let rhs_root = saturated.egraph.find(*rhs);
            if let Some(v) = saturated.egraph[rhs_root].nodes.iter().find_map(|node| {
                if let NauxExpr::Num(v) = node {
                    Some(*v)
                } else {
                    None
                }
            }) {
                return Some(v);
            }
        }
    }
    None
}

fn ir_proof_strict_enabled() -> bool {
    std::env::var("NAUX_IR_PROOF_STRICT")
        .map(|v| {
            let t = v.trim();
            t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false)
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
            IRNode {
                instr: IRInstr::Jump(ref mut t),
                ..
            }
            | IRNode {
                instr: IRInstr::JumpIfFalse(ref mut t),
                ..
            } => {
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
    let int_pair = || {
        if a.fract() == 0.0 && b.fract() == 0.0 {
            Some((a as i64, b as i64))
        } else {
            None
        }
    };
    match op {
        IRInstr::Add => Some(a + b),
        IRInstr::Sub => Some(a - b),
        IRInstr::Mul => Some(a * b),
        IRInstr::Div if b != 0.0 => Some(a / b),
        IRInstr::Mod if b != 0.0 => Some(a % b),
        IRInstr::Xor => int_pair().map(|(x, y)| (x ^ y) as f64),
        IRInstr::Shl => int_pair()
            .and_then(|(x, y)| if y >= 0 { Some(x << (y as u32)) } else { None })
            .map(|v| v as f64),
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
    let (
        main,
        main_locals,
        main_spans,
        main_result_types,
        main_unsafe_flags,
        main_lowering_context,
    ) = lower_block(ir.main, &[], LoweringContext::default());
    let mut functions: HashMap<String, FunctionBytecode> = HashMap::new();
    for (name, f) in ir.functions {
        let (code, locals, spans, result_types, unsafe_flags, lowering_context) =
            lower_block(f.code, &f.params, LoweringContext::default());
        functions.insert(
            name,
            FunctionBytecode {
                params: f.params,
                locals,
                code,
                spans,
                result_types,
                unsafe_flags,
                lowering_context,
                return_type: f.return_type,
            },
        );
    }
    Program {
        main,
        main_locals,
        main_spans,
        main_result_types,
        main_unsafe_flags,
        main_lowering_context,
        main_return: ir.main_return,
        functions,
    }
}

fn lower_block(block: IRBlock, params: &[String], incoming: LoweringContext) -> LoweredBlock {
    let lowering_context = lowering_context_for_block(&block, &incoming);
    let (locals, mapping) = collect_locals(&block, params);
    let mut code = Bytecode::new();
    let mut spans: Vec<Option<Span>> = Vec::new();
    let mut result_types: Vec<Option<Type>> = Vec::new();
    let mut unsafe_flags: Vec<bool> = Vec::new();
    for node in block {
        code.push(lower_instr(node.instr, &mapping));
        spans.push(node.span);
        result_types.push(node.result_type);
        unsafe_flags.push(node.proof.unsafe_context);
    }
    let (code, spans, result_types, unsafe_flags) =
        optimize_bytecode_block(code, spans, result_types, unsafe_flags);
    if result_types.len() != code.len() || unsafe_flags.len() != code.len() {
        let len = code.len();
        let mut result_types = result_types;
        result_types.truncate(len);
        let mut unsafe_flags = unsafe_flags;
        unsafe_flags.truncate(len);
        return (
            code,
            locals,
            spans,
            result_types,
            unsafe_flags,
            lowering_context,
        );
    }
    (
        code,
        locals,
        spans,
        result_types,
        unsafe_flags,
        lowering_context,
    )
}

fn lower_instr(i: IRInstr, slots: &HashMap<String, usize>) -> Instr {
    match i {
        IRInstr::ConstNum(n) => Instr::ConstNum(n),
        IRInstr::ConstText(s) => Instr::ConstText(s),
        IRInstr::ConstBool(b) => Instr::ConstBool(b),
        IRInstr::PushNull => Instr::PushNull,
        IRInstr::Add => Instr::Add,
        IRInstr::Sub => Instr::Sub,
        IRInstr::Mul => Instr::Mul,
        IRInstr::Div => Instr::Div,
        IRInstr::Mod => Instr::Mod,
        IRInstr::Xor => Instr::Xor,
        IRInstr::Shl => Instr::Shl,
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
        IRInstr::Call(a) => Instr::CallBuiltin("__call".into(), a),
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
        IRInstr::Pop => Instr::Pop,
        IRInstr::Return => Instr::Return,
        IRInstr::LoadVar(name) => {
            if let Some(idx) = slots.get(&name) {
                Instr::LoadLocal(*idx)
            } else {
                debug_assert!(
                    false,
                    "Compiler invariant broken: missing slot for variable `{}`",
                    name
                );
                // Keep compilation non-panicking: unresolved reads become null-like values.
                Instr::PushNull
            }
        }
        IRInstr::StoreVar(name) => {
            if let Some(idx) = slots.get(&name) {
                Instr::StoreLocal(*idx)
            } else {
                debug_assert!(
                    false,
                    "Compiler invariant broken: missing slot for variable `{}`",
                    name
                );
                // Preserve stack balance if lowering cannot resolve a store target.
                Instr::Pop
            }
        }
    }
}

/// Peephole bytecode optimizer.
///
/// The first executable SSA-style materialization is intentionally tiny:
/// `StoreLocal x; LoadLocal x` becomes `StoreLocalKeep x` when neither
/// instruction is a jump target. This preserves the post-load stack shape
/// without reloading from the locals array.
///
/// `LoadLocal x; ConstNum c; Add; StoreLocal x` becomes `AddLocalConst x c`.
/// `LoadLocal x; ConstNum c; Sub; StoreLocal x` becomes `AddLocalConst x -c`.
/// Both forms require a statically numeric op and no jump into the fused sequence.
///
/// `LoadLocal x; JumpIfFalse t` becomes `JumpLocalIfFalse x t` when no jump
/// targets the second instruction. A jump may target the first instruction so
/// loop backedges can still enter the fused condition.
fn optimize_bytecode_block(
    code: Bytecode,
    spans: Vec<Option<Span>>,
    result_types: Vec<Option<Type>>,
    unsafe_flags: Vec<bool>,
) -> OptimizedBytecodeBlock {
    let mut jump_targets: Vec<usize> = Vec::new();
    for instr in &code {
        match instr {
            Instr::Jump(t) | Instr::JumpIfFalse(t) | Instr::JumpLocalIfFalse(_, t) => {
                jump_targets.push(*t)
            }
            _ => {}
        }
    }
    let mut out: Bytecode = Bytecode::new();
    let mut out_spans: Vec<Option<Span>> = Vec::new();
    let mut out_result_types: Vec<Option<Type>> = Vec::new();
    let mut out_unsafe_flags: Vec<bool> = Vec::new();
    let mut map_old_to_new: Vec<Option<usize>> = vec![None; code.len()];
    let mut i = 0;
    while i < code.len() {
        if i + 3 < code.len() {
            if let (
                Instr::LoadLocal(load_idx),
                Instr::ConstNum(c),
                op @ (Instr::Add | Instr::Sub),
                Instr::StoreLocal(store_idx),
            ) = (&code[i], &code[i + 1], &code[i + 2], &code[i + 3])
            {
                let has_jump_target_inside = jump_targets.contains(&i)
                    || jump_targets.contains(&(i + 1))
                    || jump_targets.contains(&(i + 2))
                    || jump_targets.contains(&(i + 3));
                if load_idx == store_idx
                    && !has_jump_target_inside
                    && matches!(result_types.get(i + 2), Some(Some(Type::Num)))
                {
                    let new_idx = out.len();
                    for mapped in map_old_to_new.iter_mut().skip(i).take(4) {
                        *mapped = Some(new_idx);
                    }
                    let delta = if matches!(op, Instr::Sub) { -*c } else { *c };
                    out.push(Instr::AddLocalConst(*load_idx, delta));
                    out_spans.push(spans.get(i + 3).cloned().unwrap_or(None));
                    out_result_types.push(None);
                    out_unsafe_flags.push(
                        (i..=i + 3).any(|old| unsafe_flags.get(old).copied().unwrap_or(false)),
                    );
                    i += 4;
                    continue;
                }
            }
        }
        if i + 1 < code.len() {
            if let (Instr::LoadLocal(idx), Instr::JumpIfFalse(target)) = (&code[i], &code[i + 1]) {
                if !jump_targets.contains(&(i + 1)) {
                    let new_idx = out.len();
                    map_old_to_new[i] = Some(new_idx);
                    map_old_to_new[i + 1] = Some(new_idx);
                    out.push(Instr::JumpLocalIfFalse(*idx, *target));
                    out_spans.push(
                        spans
                            .get(i + 1)
                            .cloned()
                            .unwrap_or_else(|| spans.get(i).cloned().unwrap_or(None)),
                    );
                    out_result_types.push(None);
                    out_unsafe_flags.push(
                        unsafe_flags.get(i).copied().unwrap_or(false)
                            || unsafe_flags.get(i + 1).copied().unwrap_or(false),
                    );
                    i += 2;
                    continue;
                }
            }
            if let (Instr::StoreLocal(lhs), Instr::LoadLocal(rhs)) = (&code[i], &code[i + 1]) {
                if lhs == rhs && !jump_targets.contains(&i) && !jump_targets.contains(&(i + 1)) {
                    let new_idx = out.len();
                    map_old_to_new[i] = Some(new_idx);
                    map_old_to_new[i + 1] = Some(new_idx);
                    out.push(Instr::StoreLocalKeep(*lhs));
                    out_spans.push(spans.get(i).cloned().unwrap_or(None));
                    out_result_types.push(result_types.get(i + 1).cloned().unwrap_or(None));
                    out_unsafe_flags.push(
                        unsafe_flags.get(i).copied().unwrap_or(false)
                            || unsafe_flags.get(i + 1).copied().unwrap_or(false),
                    );
                    i += 2;
                    continue;
                }
            }
        }
        let new_idx = out.len();
        map_old_to_new[i] = Some(new_idx);
        out.push(code[i].clone());
        out_spans.push(spans.get(i).cloned().unwrap_or(None));
        out_result_types.push(result_types.get(i).cloned().unwrap_or(None));
        out_unsafe_flags.push(unsafe_flags.get(i).copied().unwrap_or(false));
        i += 1;
    }
    // remap jumps
    for instr in out.iter_mut() {
        match instr {
            Instr::Jump(ref mut t)
            | Instr::JumpIfFalse(ref mut t)
            | Instr::JumpLocalIfFalse(_, ref mut t) => {
                if let Some(nt) = remap_target(*t, &map_old_to_new) {
                    *t = nt;
                }
            }
            _ => {}
        }
    }
    (out, out_spans, out_result_types, out_unsafe_flags)
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
            IRInstr::LoadVar(name) | IRInstr::StoreVar(name) if !map.contains_key(name) => {
                let idx = locals.len();
                locals.push(name.clone());
                map.insert(name.clone(), idx);
            }
            _ => {}
        }
    }
    (locals, map)
}

fn compile_stmt_ir(
    stmt: &Stmt,
    bc: &mut Vec<IRNode>,
    env: &mut HashMap<String, Type>,
    fns: &HashMap<String, usize>,
    proof_state: &mut CompileProofState,
) -> Option<Type> {
    match stmt {
        Stmt::Assign {
            name, expr, span, ..
        } => {
            let ty = compile_expr_ir(expr, bc, env, fns, proof_state);
            let mut node = IRNode::new(IRInstr::StoreVar(name.clone()), span.clone(), None);
            if let Some(slot) = proof_state.assign(name, expr) {
                node.proof = merge_feedback_proof(&node.proof, &slot);
            }
            bc.push(node);
            env.insert(name.clone(), ty);
            None
        }
        Stmt::Expr { expr, span } => {
            let _ = compile_expr_ir(expr, bc, env, fns, proof_state);
            bc.push(IRNode::new(IRInstr::Pop, span.clone(), None));
            None
        }
        Stmt::If {
            cond,
            then_block,
            else_block,
            span,
        } => {
            compile_expr_ir(cond, bc, env, fns, proof_state);
            let jmp_false_pos = bc.len();
            bc.push(IRNode::new(IRInstr::JumpIfFalse(0), span.clone(), None)); // patched later

            let mut then_ret: Option<Type> = None;
            let mut then_proof_state = proof_state.clone();
            then_proof_state.refine_from_condition(cond, true);
            for s in then_block {
                if let Some(t) =
                    compile_stmt_ir(s, bc, &mut env.clone(), fns, &mut then_proof_state)
                {
                    then_ret = Some(then_ret.map(|old| unify_types(old, t.clone())).unwrap_or(t));
                }
            }
            let jmp_end_pos = bc.len();
            bc.push(IRNode::new(IRInstr::Jump(0), span.clone(), None)); // patched later

            let else_start = bc.len();
            let mut else_ret: Option<Type> = None;
            let mut else_proof_state = proof_state.clone();
            else_proof_state.refine_from_condition(cond, false);
            for s in else_block {
                if let Some(t) =
                    compile_stmt_ir(s, bc, &mut env.clone(), fns, &mut else_proof_state)
                {
                    else_ret = Some(else_ret.map(|old| unify_types(old, t.clone())).unwrap_or(t));
                }
            }
            let end = bc.len();
            if let IRInstr::JumpIfFalse(ref mut target) = bc[jmp_false_pos].instr {
                *target = else_start;
            }
            if let IRInstr::Jump(ref mut target) = bc[jmp_end_pos].instr {
                *target = end;
            }
            unify_opt(then_ret, else_ret)
        }
        Stmt::Loop { count, body, span } => {
            let tmp = format!("__loop_rem__{}", bc.len());
            compile_expr_ir(count, bc, env, fns, proof_state);
            proof_state.current.remove(&tmp);
            bc.push(IRNode::new(
                IRInstr::StoreVar(tmp.clone()),
                span.clone(),
                None,
            ));
            let start = bc.len();
            bc.push(IRNode::new(
                IRInstr::LoadVar(tmp.clone()),
                span.clone(),
                env.get(&tmp).cloned(),
            ));
            let jmp_false = bc.len();
            bc.push(IRNode::new(IRInstr::JumpIfFalse(0), span.clone(), None));
            for s in body {
                compile_stmt_ir(s, bc, &mut env.clone(), fns, &mut proof_state.clone());
            }
            bc.push(IRNode::new(
                IRInstr::LoadVar(tmp.clone()),
                span.clone(),
                env.get(&tmp).cloned(),
            ));
            bc.push(IRNode::new(
                IRInstr::ConstNum(1.0),
                span.clone(),
                Some(Type::Num),
            ));
            bc.push(IRNode::new(IRInstr::Sub, span.clone(), Some(Type::Num)));
            bc.push(IRNode::new(
                IRInstr::StoreVar(tmp.clone()),
                span.clone(),
                None,
            ));
            bc.push(IRNode::new(IRInstr::Jump(start), span.clone(), None));
            let end = bc.len();
            if let IRInstr::JumpIfFalse(ref mut target) = bc[jmp_false].instr {
                *target = end;
            }
            None
        }
        Stmt::While { cond, body, span } => {
            let start = bc.len();
            compile_expr_ir(cond, bc, env, fns, proof_state);
            let jmp_false = bc.len();
            bc.push(IRNode::new(IRInstr::JumpIfFalse(0), span.clone(), None));
            let mut body_proof_state = proof_state.clone();
            body_proof_state.refine_from_condition(cond, true);
            for s in body {
                compile_stmt_ir(s, bc, &mut env.clone(), fns, &mut body_proof_state);
            }
            bc.push(IRNode::new(IRInstr::Jump(start), span.clone(), None));
            let end = bc.len();
            if let IRInstr::JumpIfFalse(ref mut target) = bc[jmp_false].instr {
                *target = end;
            }
            None
        }
        Stmt::Return { value, span } => {
            if let Some(expr) = value {
                let ret_ty = compile_expr_ir(expr, bc, env, fns, proof_state);
                bc.push(IRNode::new(
                    IRInstr::Return,
                    span.clone(),
                    Some(ret_ty.clone()),
                ));
                Some(ret_ty)
            } else {
                bc.push(IRNode::new(
                    IRInstr::PushNull,
                    span.clone(),
                    Some(Type::Null),
                ));
                bc.push(IRNode::new(IRInstr::Return, span.clone(), Some(Type::Null)));
                Some(Type::Null)
            }
        }
        Stmt::Action { action, span } => {
            compile_action_ir(action, span.clone(), bc, env, fns, proof_state);
            None
        }
        Stmt::Rite { body, .. } => {
            let mut block_ret = None;
            for s in body {
                if let Some(t) = compile_stmt_ir(s, bc, env, fns, proof_state) {
                    block_ret = Some(
                        block_ret
                            .map(|old| unify_types(old, t.clone()))
                            .unwrap_or(t),
                    );
                }
            }
            block_ret
        }
        Stmt::FnDef { .. } => None,
        Stmt::Each {
            var,
            iter,
            body,
            span,
        } => {
            let tmp_iter = "__each_iter__".to_string();
            let tmp_idx = "__each_idx__".to_string();
            compile_expr_ir(iter, bc, env, fns, proof_state);
            proof_state.current.remove(&tmp_iter);
            bc.push(IRNode::new(
                IRInstr::StoreVar(tmp_iter.clone()),
                span.clone(),
                None,
            ));
            bc.push(IRNode::new(
                IRInstr::ConstNum(0.0),
                span.clone(),
                Some(Type::Num),
            ));
            proof_state.current.remove(&tmp_idx);
            bc.push(IRNode::new(
                IRInstr::StoreVar(tmp_idx.clone()),
                span.clone(),
                None,
            ));
            let start = bc.len();
            bc.push(IRNode::new(
                IRInstr::LoadVar(tmp_idx.clone()),
                span.clone(),
                Some(Type::Num),
            ));
            bc.push(IRNode::new(
                IRInstr::LoadVar(tmp_iter.clone()),
                span.clone(),
                None,
            ));
            bc.push(IRNode::new(
                IRInstr::CallBuiltin("len".into(), 1),
                span.clone(),
                Some(Type::Num),
            ));
            bc.push(IRNode::new(IRInstr::Lt, span.clone(), Some(Type::Bool)));
            let jmp_false = bc.len();
            bc.push(IRNode::new(IRInstr::JumpIfFalse(0), span.clone(), None));
            bc.push(IRNode::new(
                IRInstr::LoadVar(tmp_iter.clone()),
                span.clone(),
                None,
            ));
            bc.push(IRNode::new(
                IRInstr::LoadVar(tmp_idx.clone()),
                span.clone(),
                Some(Type::Num),
            ));
            bc.push(IRNode::new(
                IRInstr::CallBuiltin("__index".into(), 2),
                span.clone(),
                Some(Type::Any),
            ));
            bc.push(IRNode::new(
                IRInstr::StoreVar(var.clone()),
                span.clone(),
                None,
            ));
            proof_state.current.remove(var);
            let mut body_proof_state = proof_state.clone();
            for s in body {
                compile_stmt_ir(s, bc, &mut env.clone(), fns, &mut body_proof_state);
            }
            bc.push(IRNode::new(
                IRInstr::LoadVar(tmp_idx.clone()),
                span.clone(),
                Some(Type::Num),
            ));
            bc.push(IRNode::new(
                IRInstr::ConstNum(1.0),
                span.clone(),
                Some(Type::Num),
            ));
            bc.push(IRNode::new(IRInstr::Add, span.clone(), Some(Type::Num)));
            bc.push(IRNode::new(
                IRInstr::StoreVar(tmp_idx.clone()),
                span.clone(),
                None,
            ));
            bc.push(IRNode::new(IRInstr::Jump(start), span.clone(), None));
            let end = bc.len();
            if let IRInstr::JumpIfFalse(ref mut target) = bc[jmp_false].instr {
                *target = end;
            }
            None
        }
        Stmt::Unsafe { body, .. } => {
            let start = bc.len();
            let mut block_ret = None;
            for s in body {
                if let Some(t) = compile_stmt_ir(s, bc, env, fns, proof_state) {
                    block_ret = Some(
                        block_ret
                            .map(|old| unify_types(old, t.clone()))
                            .unwrap_or(t),
                    );
                }
            }
            for node in bc.iter_mut().skip(start) {
                node.proof.unsafe_context = true;
            }
            block_ret
        }
        Stmt::Import { .. } => None,
    }
}

fn compile_action_ir(
    action: &ActionKind,
    span: Option<Span>,
    bc: &mut Vec<IRNode>,
    env: &mut HashMap<String, Type>,
    fns: &HashMap<String, usize>,
    proof_state: &mut CompileProofState,
) {
    match action {
        ActionKind::Say { value } => {
            compile_expr_ir(value, bc, env, fns, proof_state);
            bc.push(IRNode::new(IRInstr::EmitSay, span.clone(), None));
        }
        ActionKind::Ask { prompt } => {
            compile_expr_ir(prompt, bc, env, fns, proof_state);
            bc.push(IRNode::new(IRInstr::EmitAsk, span.clone(), None));
        }
        ActionKind::Fetch { target } => {
            compile_expr_ir(target, bc, env, fns, proof_state);
            bc.push(IRNode::new(IRInstr::EmitFetch, span.clone(), None));
        }
        ActionKind::Ui { kind, .. } => {
            bc.push(IRNode::new(
                IRInstr::EmitUi(kind.clone()),
                span.clone(),
                None,
            ));
        }
        ActionKind::Text { value } => {
            compile_expr_ir(value, bc, env, fns, proof_state);
            bc.push(IRNode::new(IRInstr::EmitText, span.clone(), None));
        }
        ActionKind::Button { value } => {
            compile_expr_ir(value, bc, env, fns, proof_state);
            bc.push(IRNode::new(IRInstr::EmitButton, span.clone(), None));
        }
        ActionKind::Log { value } => {
            compile_expr_ir(value, bc, env, fns, proof_state);
            bc.push(IRNode::new(IRInstr::EmitLog, span.clone(), None));
        }
        ActionKind::Syscall { number, args, out } => {
            compile_expr_ir(number, bc, env, fns, proof_state);
            for arg in args {
                compile_expr_ir(arg, bc, env, fns, proof_state);
            }
            bc.push(IRNode::new(
                IRInstr::CallBuiltin("__syscall".into(), args.len() + 1),
                span.clone(),
                Some(Type::Num),
            ));
            if let Some(name) = out {
                env.insert(name.clone(), Type::Num);
                proof_state.current.remove(name);
                bc.push(IRNode::new(IRInstr::StoreVar(name.clone()), span, None));
            } else {
                bc.push(IRNode::new(IRInstr::Pop, span, None));
            }
        }
    }
}

fn compile_expr_ir(
    expr: &Expr,
    bc: &mut Vec<IRNode>,
    env: &mut HashMap<String, Type>,
    fns: &HashMap<String, usize>,
    proof_state: &mut CompileProofState,
) -> Type {
    let span = expr.span.clone();
    match &expr.kind {
        ExprKind::Number(n) => {
            bc.push(IRNode::new(IRInstr::ConstNum(*n), span, Some(Type::Num)));
            Type::Num
        }
        ExprKind::Bool(b) => {
            bc.push(IRNode::new(IRInstr::ConstBool(*b), span, Some(Type::Bool)));
            Type::Bool
        }
        ExprKind::Text(s) => {
            bc.push(IRNode::new(
                IRInstr::ConstText(s.clone()),
                span,
                Some(Type::Text),
            ));
            Type::Text
        }
        ExprKind::Bytes(bytes) => {
            for byte in bytes {
                bc.push(IRNode::new(
                    IRInstr::ConstNum(*byte as f64),
                    span.clone(),
                    Some(Type::Num),
                ));
            }
            bc.push(IRNode::new(
                IRInstr::MakeList(bytes.len()),
                span.clone(),
                Some(Type::List(Box::new(Type::Num))),
            ));
            bc.push(IRNode::new(
                IRInstr::CallBuiltin("__bytes".into(), 1),
                span,
                Some(Type::Bytes),
            ));
            Type::Bytes
        }
        ExprKind::Var(name) => {
            let mut node =
                IRNode::new(IRInstr::LoadVar(name.clone()), span, env.get(name).cloned());
            if let Some(slot) = proof_state.load(name) {
                node.proof = merge_feedback_proof(&node.proof, &slot);
            }
            bc.push(node);
            env.get(name)
                .cloned()
                .or_else(|| fns.get(name).map(|n| Type::Function { params: *n }))
                .unwrap_or(Type::Any)
        }
        ExprKind::Unary { op, expr } => {
            let _t = compile_expr_ir(expr, bc, env, fns, proof_state);
            match op {
                UnaryOp::Neg => {
                    bc.push(IRNode::new(
                        IRInstr::ConstNum(-1.0),
                        span.clone(),
                        Some(Type::Num),
                    ));
                    bc.push(IRNode::new(IRInstr::Mul, span, Some(Type::Num)));
                    Type::Num
                }
                UnaryOp::Not => {
                    bc.push(IRNode::new(
                        IRInstr::ConstBool(false),
                        span.clone(),
                        Some(Type::Bool),
                    ));
                    bc.push(IRNode::new(IRInstr::Eq, span, Some(Type::Bool)));
                    Type::Bool
                }
            }
        }
        ExprKind::Binary { op, left, right } => {
            let lt = compile_expr_ir(left, bc, env, fns, proof_state);
            let rt = compile_expr_ir(right, bc, env, fns, proof_state);
            let instr = match op {
                BinaryOp::Add => IRInstr::Add,
                BinaryOp::Sub => IRInstr::Sub,
                BinaryOp::Mul => IRInstr::Mul,
                BinaryOp::Div => IRInstr::Div,
                BinaryOp::Mod => IRInstr::Mod,
                BinaryOp::Xor => IRInstr::Xor,
                BinaryOp::Shl => IRInstr::Shl,
                BinaryOp::Eq => IRInstr::Eq,
                BinaryOp::Ne => IRInstr::Ne,
                BinaryOp::Gt => IRInstr::Gt,
                BinaryOp::Ge => IRInstr::Ge,
                BinaryOp::Lt => IRInstr::Lt,
                BinaryOp::Le => IRInstr::Le,
                BinaryOp::And => IRInstr::And,
                BinaryOp::Or => IRInstr::Or,
            };
            let ret_ty = match op {
                BinaryOp::Add => infer_add_type(&lt, &rt),
                BinaryOp::Sub
                | BinaryOp::Mul
                | BinaryOp::Div
                | BinaryOp::Mod
                | BinaryOp::Xor
                | BinaryOp::Shl => Type::Num,
                _ => Type::Bool,
            };
            bc.push(IRNode::new(instr, span, Some(ret_ty.clone())));
            ret_ty
        }
        ExprKind::Call { callee, args } => {
            for arg in args {
                compile_expr_ir(arg, bc, env, fns, proof_state);
            }
            if let ExprKind::Var(name) = &callee.kind {
                // Nếu là builtin đã biết → CallBuiltin, gán type trả về; ngược lại CallFn (type chưa biết).
                if fns.get(name).is_none()
                    && matches!(
                        name.as_str(),
                        "len"
                            | "to_text"
                            | "__index"
                            | "__setindex"
                            | "list_range"
                            | "__bytes"
                            | "__syscall"
                            | "__bit_xor"
                            | "__bit_shl"
                    )
                {
                    let ret_ty = builtin_return_type(name);
                    bc.push(IRNode::new(
                        IRInstr::CallBuiltin(name.clone(), args.len()),
                        span,
                        Some(ret_ty.clone()),
                    ));
                    ret_ty
                } else {
                    bc.push(IRNode::new(
                        IRInstr::CallFn(name.clone(), args.len()),
                        span,
                        Some(Type::Any),
                    ));
                    Type::Any
                }
            } else {
                // Callee không phải var → gọi như dynamic fn, giữ Any.
                bc.push(IRNode::new(
                    IRInstr::CallBuiltin("__call".into(), args.len() + 1),
                    span,
                    Some(Type::Any),
                ));
                Type::Any
            }
        }
        ExprKind::Index { target, index } => {
            let tgt_ty = compile_expr_ir(target, bc, env, fns, proof_state);
            compile_expr_ir(index, bc, env, fns, proof_state);
            bc.push(IRNode::new(
                IRInstr::CallBuiltin("__index".into(), 2),
                span,
                Some(builtin_return_type("__index")),
            ));
            match tgt_ty {
                Type::List(inner) | Type::Map(inner) => *inner,
                Type::Bytes => Type::Num,
                _ => Type::Any,
            }
        }
        ExprKind::List(items) => {
            for item in items {
                compile_expr_ir(item, bc, env, fns, proof_state);
            }
            bc.push(IRNode::new(
                IRInstr::MakeList(items.len()),
                span,
                Some(Type::List(Box::new(Type::Any))),
            ));
            Type::List(Box::new(Type::Any))
        }
        ExprKind::Map(entries) => {
            for (_, v) in entries {
                compile_expr_ir(v, bc, env, fns, proof_state);
            }
            bc.push(IRNode::new(
                IRInstr::MakeMap(entries.iter().map(|(k, _)| k.clone()).collect()),
                span,
                Some(Type::Map(Box::new(Type::Any))),
            ));
            Type::Map(Box::new(Type::Any))
        }
        ExprKind::Field { target, field } => {
            let tgt_ty = compile_expr_ir(target, bc, env, fns, proof_state);
            bc.push(IRNode::new(
                IRInstr::LoadField(field.clone()),
                span,
                Some(Type::Any),
            ));
            match tgt_ty {
                Type::Map(inner) => *inner,
                _ => Type::Any,
            }
        }
        ExprKind::Fn(_func) => {
            // Inline function expressions are not compiled yet.
            bc.push(IRNode::new(IRInstr::PushNull, span, Some(Type::Any)));
            Type::Any
        }
    }
}

fn infer_add_type(lhs: &Type, rhs: &Type) -> Type {
    match (lhs, rhs) {
        (Type::Text, _) | (_, Type::Text) => Type::Text,
        (Type::Any, _) | (_, Type::Any) => Type::Any,
        _ => Type::Num,
    }
}

fn builtin_return_type(name: &str) -> Type {
    match name {
        "len" => Type::Num,
        "to_text" => Type::Text,
        "__index" => Type::Any,
        "__setindex" => Type::Any,
        "list_range" => Type::List(Box::new(Type::Num)),
        "__bytes" => Type::Bytes,
        "__syscall" => Type::Num,
        "__bit_xor" => Type::Num,
        "__bit_shl" => Type::Num,
        _ => Type::Any,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    use crate::vm::ir::{CostBound, IRFunction, RefinedType};

    fn optimizer_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock poisoned")
    }

    fn sample_cost(
        worst_cycles: Option<u32>,
        alloc_bytes: Option<u32>,
        mem_reads: Option<u32>,
        mem_writes: Option<u32>,
    ) -> CostBound {
        CostBound {
            worst_cycles,
            alloc_bytes,
            mem_reads,
            mem_writes,
        }
    }

    fn empty_optimization_report() -> OptimizationReport {
        OptimizationReport {
            main_feedback_stop: OptimizerStopReason::FixedPoint,
            function_feedback_stops: HashMap::new(),
            main_materialization: MaterializationStats::default(),
            function_materialization: Vec::new(),
            main_feedback_rounds: Vec::new(),
            function_feedback_rounds: Vec::new(),
        }
    }

    #[test]
    fn lowering_context_accumulates_proof_cost_and_unsafe_state_for_main() {
        let first =
            IRNode::new(IRInstr::ConstNum(1.0), None, Some(Type::Num)).with_proof(ProofSlot {
                refined_type: Some(RefinedType {
                    base: Type::Num,
                    predicate: Some("v != 0".into()),
                }),
                numeric: None,
                cost_bound: Some(sample_cost(Some(2), Some(8), Some(1), None)),
                coq_cert: None,
                aliasing: AliasingClass::Unknown,
                unsafe_context: false,
            });
        let second =
            IRNode::new(IRInstr::ConstNum(2.0), None, Some(Type::Num)).with_proof(ProofSlot {
                refined_type: None,
                numeric: None,
                cost_bound: Some(sample_cost(Some(3), None, Some(2), Some(1))),
                coq_cert: None,
                aliasing: AliasingClass::Unknown,
                unsafe_context: false,
            });
        let add = IRNode::new(IRInstr::Add, None, Some(Type::Num)).with_proof(ProofSlot {
            refined_type: None,
            numeric: None,
            cost_bound: None,
            coq_cert: Some(7),
            aliasing: AliasingClass::NoAlias,
            unsafe_context: true,
        });
        let ret = IRNode::new(IRInstr::Return, None, None);
        let prog = lower_ir_to_bytecode(IRProgram {
            main: vec![first, second, add, ret],
            functions: HashMap::new(),
            main_return: Some(Type::Num),
        });

        assert!(prog.main_lowering_context.unsafe_ctx);
        assert_eq!(prog.main_lowering_context.proof.coq_cert, Some(7));
        assert_eq!(
            prog.main_lowering_context
                .proof
                .refined_type
                .as_ref()
                .and_then(|r| r.predicate.as_deref()),
            Some("v != 0")
        );
        assert_eq!(
            prog.main_lowering_context.proof.aliasing,
            AliasingClass::NoAlias
        );
        assert_eq!(
            prog.main_lowering_context.cost_acc,
            sample_cost(Some(5), Some(8), Some(3), Some(1))
        );
    }

    #[test]
    fn lowering_context_is_recorded_for_functions() {
        let func = IRFunction {
            params: vec!["x".into()],
            code: vec![
                IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)).with_proof(
                    ProofSlot {
                        refined_type: Some(RefinedType {
                            base: Type::Num,
                            predicate: Some("v >= 0".into()),
                        }),
                        numeric: None,
                        cost_bound: Some(sample_cost(Some(1), None, Some(1), None)),
                        coq_cert: Some(11),
                        aliasing: AliasingClass::Unknown,
                        unsafe_context: false,
                    },
                ),
                IRNode::new(IRInstr::Return, None, None),
            ],
            return_type: Some(Type::Num),
        };
        let prog = lower_ir_to_bytecode(IRProgram {
            main: vec![IRNode::new(IRInstr::Return, None, None)],
            functions: HashMap::from([("f".into(), func)]),
            main_return: None,
        });

        let func = prog.functions.get("f").expect("function lowering");
        assert_eq!(func.lowering_context.proof.coq_cert, Some(11));
        assert_eq!(
            func.lowering_context
                .proof
                .refined_type
                .as_ref()
                .and_then(|r| r.predicate.as_deref()),
            Some("v >= 0")
        );
        assert_eq!(
            func.lowering_context.cost_acc,
            sample_cost(Some(1), None, Some(1), None)
        );
    }

    #[test]
    fn bytecode_materializes_store_reload_as_store_keep() {
        let prog = lower_ir_to_bytecode(IRProgram {
            main: vec![
                IRNode::new(IRInstr::ConstNum(7.0), None, Some(Type::Num)),
                IRNode::new(IRInstr::StoreVar("x".into()), None, None),
                IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: Some(Type::Num),
        });

        assert!(matches!(
            prog.main.as_slice(),
            [Instr::ConstNum(v), Instr::StoreLocalKeep(0), Instr::Return]
                if (*v - 7.0).abs() < f64::EPSILON
        ));
    }

    #[test]
    fn bytecode_does_not_materialize_store_reload_at_jump_target() {
        let prog = lower_ir_to_bytecode(IRProgram {
            main: vec![
                IRNode::new(IRInstr::Jump(3), None, None),
                IRNode::new(IRInstr::ConstNum(7.0), None, Some(Type::Num)),
                IRNode::new(IRInstr::StoreVar("x".into()), None, None),
                IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: Some(Type::Num),
        });

        assert!(matches!(
            prog.main.as_slice(),
            [
                Instr::Jump(3),
                Instr::ConstNum(v),
                Instr::StoreLocal(0),
                Instr::LoadLocal(0),
                Instr::Return
            ] if (*v - 7.0).abs() < f64::EPSILON
        ));
    }

    #[test]
    fn bytecode_does_not_materialize_store_reload_when_store_is_jump_target() {
        let prog = lower_ir_to_bytecode(IRProgram {
            main: vec![
                IRNode::new(IRInstr::Jump(2), None, None),
                IRNode::new(IRInstr::ConstNum(7.0), None, Some(Type::Num)),
                IRNode::new(IRInstr::StoreVar("x".into()), None, None),
                IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: Some(Type::Num),
        });

        assert!(matches!(
            prog.main.as_slice(),
            [
                Instr::Jump(2),
                Instr::ConstNum(v),
                Instr::StoreLocal(0),
                Instr::LoadLocal(0),
                Instr::Return
            ] if (*v - 7.0).abs() < f64::EPSILON
        ));
    }

    #[test]
    fn bytecode_materializes_numeric_local_add_const() {
        let prog = lower_ir_to_bytecode(IRProgram {
            main: vec![
                IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)),
                IRNode::new(IRInstr::ConstNum(2.0), None, Some(Type::Num)),
                IRNode::new(IRInstr::Add, None, Some(Type::Num)),
                IRNode::new(IRInstr::StoreVar("x".into()), None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        });

        assert!(matches!(
            prog.main.as_slice(),
            [Instr::AddLocalConst(0, c), Instr::Return]
                if (*c - 2.0).abs() < f64::EPSILON
        ));
    }

    #[test]
    fn bytecode_materializes_numeric_local_sub_const() {
        let prog = lower_ir_to_bytecode(IRProgram {
            main: vec![
                IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)),
                IRNode::new(IRInstr::ConstNum(2.0), None, Some(Type::Num)),
                IRNode::new(IRInstr::Sub, None, Some(Type::Num)),
                IRNode::new(IRInstr::StoreVar("x".into()), None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        });

        assert!(matches!(
            prog.main.as_slice(),
            [Instr::AddLocalConst(0, c), Instr::Return]
                if (*c + 2.0).abs() < f64::EPSILON
        ));
    }

    #[test]
    fn bytecode_does_not_materialize_local_add_const_at_jump_target() {
        let prog = lower_ir_to_bytecode(IRProgram {
            main: vec![
                IRNode::new(IRInstr::Jump(1), None, None),
                IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)),
                IRNode::new(IRInstr::ConstNum(2.0), None, Some(Type::Num)),
                IRNode::new(IRInstr::Add, None, Some(Type::Num)),
                IRNode::new(IRInstr::StoreVar("x".into()), None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        });

        assert!(matches!(
            prog.main.as_slice(),
            [
                Instr::Jump(1),
                Instr::LoadLocal(0),
                Instr::ConstNum(c),
                Instr::Add,
                Instr::StoreLocal(0),
                Instr::Return
            ] if (*c - 2.0).abs() < f64::EPSILON
        ));
    }

    #[test]
    fn bytecode_materializes_local_branch_condition() {
        let prog = lower_ir_to_bytecode(IRProgram {
            main: vec![
                IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Bool)),
                IRNode::new(IRInstr::JumpIfFalse(3), None, None),
                IRNode::new(IRInstr::ConstNum(1.0), None, Some(Type::Num)),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        });

        assert!(matches!(
            prog.main.as_slice(),
            [Instr::JumpLocalIfFalse(0, 2), Instr::ConstNum(v), Instr::Return]
                if (*v - 1.0).abs() < f64::EPSILON
        ));
    }

    #[test]
    fn bytecode_materializes_local_branch_condition_at_backedge_target() {
        let prog = lower_ir_to_bytecode(IRProgram {
            main: vec![
                IRNode::new(IRInstr::Jump(1), None, None),
                IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Bool)),
                IRNode::new(IRInstr::JumpIfFalse(4), None, None),
                IRNode::new(IRInstr::ConstNum(1.0), None, Some(Type::Num)),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        });

        assert!(matches!(
            prog.main.as_slice(),
            [
                Instr::Jump(1),
                Instr::JumpLocalIfFalse(0, 3),
                Instr::ConstNum(v),
                Instr::Return
            ] if (*v - 1.0).abs() < f64::EPSILON
        ));
    }

    #[test]
    fn bytecode_does_not_materialize_local_branch_when_branch_is_jump_target() {
        let prog = lower_ir_to_bytecode(IRProgram {
            main: vec![
                IRNode::new(IRInstr::Jump(2), None, None),
                IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Bool)),
                IRNode::new(IRInstr::JumpIfFalse(4), None, None),
                IRNode::new(IRInstr::ConstNum(1.0), None, Some(Type::Num)),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        });

        assert!(matches!(
            prog.main.as_slice(),
            [
                Instr::Jump(2),
                Instr::LoadLocal(0),
                Instr::JumpIfFalse(4),
                Instr::ConstNum(v),
                Instr::Return
            ] if (*v - 1.0).abs() < f64::EPSILON
        ));
    }

    #[test]
    fn block_delta_count_tracks_local_changes() {
        let before = vec![
            IRNode::new(IRInstr::ConstNum(1.0), None, Some(Type::Num)),
            IRNode::new(IRInstr::ConstNum(2.0), None, Some(Type::Num)),
            IRNode::new(IRInstr::Add, None, Some(Type::Num)),
        ];
        let after = vec![
            before[0].clone(),
            before[1].clone(),
            IRNode::new(IRInstr::ConstNum(3.0), None, Some(Type::Num)),
        ];
        assert_eq!(block_delta_count(&before, &after), 1);
    }

    #[test]
    fn feedback_loop_can_stop_on_diminishing_returns() {
        let _guard = optimizer_env_lock();
        unsafe {
            std::env::set_var("NAUX_EGRAPH_ENABLE_SCCP_FEEDBACK", "1");
        }
        let block = vec![
            IRNode::new(IRInstr::ConstNum(1.0), None, Some(Type::Num)),
            IRNode::new(IRInstr::ConstNum(2.0), None, Some(Type::Num)),
            IRNode::new(IRInstr::Add, None, Some(Type::Num)),
            IRNode::new(IRInstr::Return, None, None),
        ];
        let result = run_egraph_feedback_loop(
            block.clone(),
            FeedbackConfig {
                max_iters: 4,
                min_evidence_growth: usize::MAX,
                max_block_delta: usize::MAX,
                patience: 1,
            },
        );

        assert_eq!(result.stop_reason, OptimizerStopReason::DiminishingReturns);
        assert_eq!(result.block.len(), block.len());
        assert!(matches!(result.block[0].instr, IRInstr::ConstNum(1.0)));
        assert!(matches!(result.block[1].instr, IRInstr::ConstNum(2.0)));
        assert!(matches!(result.block[2].instr, IRInstr::Add));
        assert_eq!(
            result.block[2]
                .proof
                .refined_type
                .as_ref()
                .and_then(|ty| ty.predicate.as_deref()),
            Some("v == 3")
        );
        unsafe {
            std::env::remove_var("NAUX_EGRAPH_ENABLE_SCCP_FEEDBACK");
        }
    }

    #[test]
    fn feedback_loop_materializes_div_self_when_nonzero_proof_exists() {
        let nonzero = ProofSlot {
            refined_type: Some(RefinedType {
                base: Type::Num,
                predicate: Some("v != 0".into()),
            }),
            ..ProofSlot::default()
        };
        let block = vec![
            IRNode::new(IRInstr::ConstNum(7.0), None, Some(Type::Num)).with_proof(nonzero.clone()),
            IRNode::new(IRInstr::ConstNum(7.0), None, Some(Type::Num)).with_proof(nonzero),
            IRNode::new(IRInstr::Div, None, Some(Type::Num)),
            IRNode::new(IRInstr::Return, None, None),
        ];
        let result = run_egraph_feedback_loop(
            block,
            FeedbackConfig {
                max_iters: 4,
                min_evidence_growth: 0,
                max_block_delta: 0,
                patience: 4,
            },
        );

        assert!(
            matches!(result.block[2].instr, IRInstr::ConstNum(v) if (v - 1.0).abs() < f64::EPSILON)
        );
        assert_eq!(result.materialization.const_one_result, 1);
        assert_eq!(result.rounds[0].shape_delta, 2);
        assert_eq!(result.rounds[0].materialization.const_one_result, 1);
    }

    #[test]
    fn strict_proof_contract_accepts_discharged_div_self_materialization() {
        let nonzero = ProofSlot {
            refined_type: Some(RefinedType {
                base: Type::Num,
                predicate: Some("v != 0".into()),
            }),
            ..ProofSlot::default()
        };
        let result = run_egraph_feedback_loop(
            vec![
                IRNode::new(IRInstr::ConstNum(7.0), None, Some(Type::Num))
                    .with_proof(nonzero.clone()),
                IRNode::new(IRInstr::ConstNum(7.0), None, Some(Type::Num)).with_proof(nonzero),
                IRNode::new(IRInstr::Div, None, Some(Type::Num)),
                IRNode::new(IRInstr::Return, None, None),
            ],
            FeedbackConfig {
                max_iters: 4,
                min_evidence_growth: 0,
                max_block_delta: 0,
                patience: 4,
            },
        );
        let mut report = empty_optimization_report();
        report.main_materialization = result.materialization;
        report.main_feedback_rounds = result.rounds;
        let ir = IRProgram {
            main: result.block,
            functions: HashMap::new(),
            main_return: Some(Type::Num),
        };

        validate_optimization_proof_contract(&ir, &report)
            .expect("discharged div-self materialization should satisfy strict contract");
    }

    #[test]
    fn strict_proof_contract_rejects_unbacked_div_self_materialization() {
        let mut report = empty_optimization_report();
        report.main_materialization.const_one_result = 1;
        let ir = IRProgram {
            main: vec![
                IRNode::new(IRInstr::ConstNum(1.0), None, Some(Type::Num)),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: Some(Type::Num),
        };

        let err = validate_optimization_proof_contract(&ir, &report)
            .expect_err("strict contract should reject missing div-self proof evidence");
        assert!(err.contains("div-self"), "unexpected error: {err}");
    }

    #[test]
    fn strict_proof_contract_rejects_invalid_proof_slot_shape() {
        let ir = IRProgram {
            main: vec![
                IRNode::new(IRInstr::ConstNum(1.0), None, Some(Type::Num)).with_proof(ProofSlot {
                    coq_cert: Some(1),
                    ..ProofSlot::default()
                }),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: Some(Type::Num),
        };

        let err = validate_optimization_proof_contract(&ir, &empty_optimization_report())
            .expect_err("strict contract should reject orphan cert payloads");
        assert!(err.contains("cert"), "unexpected error: {err}");
    }

    #[test]
    fn collect_egraph_feedback_env_maps_div_eclass_fact_back_to_node() {
        let nonzero = ProofSlot {
            refined_type: Some(RefinedType {
                base: Type::Num,
                predicate: Some("v != 0".into()),
            }),
            ..ProofSlot::default()
        };
        let lhs = IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num))
            .with_proof(nonzero.clone());
        let rhs =
            IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)).with_proof(nonzero);
        let div = IRNode::new(IRInstr::Div, None, Some(Type::Num));
        let block = vec![
            lhs,
            rhs,
            div.clone(),
            IRNode::new(IRInstr::Return, None, None),
        ];

        let seed_env = extract_proof_env(&block);
        let block_with_env = apply_proof_env_to_block(&block, &seed_env);
        let saturated = run_saturation_with_proof_env(
            build_from_ir_block(&block_with_env),
            8,
            10_000,
            &seed_env,
        );
        let feedback = collect_egraph_feedback_env(&block_with_env, &saturated)
            .expect("div-self rewrite should produce egraph feedback");
        let div_slot = feedback
            .by_node
            .get(&div.id)
            .expect("div node proof should be mapped back from eclass");
        assert_eq!(div_slot.numeric.and_then(|numeric| numeric.exact), Some(1));
        assert!(div_slot.proven_nonzero());
    }

    #[test]
    fn feedback_loop_enriches_div_proof_from_egraph_without_sccp_seed_flag() {
        let _guard = optimizer_env_lock();
        unsafe {
            std::env::remove_var("NAUX_EGRAPH_ENABLE_SCCP_FEEDBACK");
        }

        let nonzero = ProofSlot {
            refined_type: Some(RefinedType {
                base: Type::Num,
                predicate: Some("v != 0".into()),
            }),
            ..ProofSlot::default()
        };
        let block = vec![
            IRNode::new(IRInstr::ConstNum(9.0), None, Some(Type::Num)).with_proof(nonzero.clone()),
            IRNode::new(IRInstr::ConstNum(9.0), None, Some(Type::Num)).with_proof(nonzero),
            IRNode::new(IRInstr::Div, None, Some(Type::Num)),
            IRNode::new(IRInstr::Return, None, None),
        ];
        let result = run_egraph_feedback_loop(
            block,
            FeedbackConfig {
                max_iters: 3,
                min_evidence_growth: 0,
                max_block_delta: 0,
                patience: 3,
            },
        );

        assert!(
            matches!(result.block[2].instr, IRInstr::ConstNum(v) if (v - 1.0).abs() < f64::EPSILON)
        );
        assert_eq!(
            result.block[2]
                .proof
                .numeric
                .and_then(|numeric| numeric.exact),
            Some(1)
        );
    }

    #[test]
    fn feedback_loop_materializes_and_mask_identity_when_range_proof_exists() {
        let ranged = ProofSlot {
            refined_type: Some(RefinedType {
                base: Type::Num,
                predicate: Some("range:[0,255]".into()),
            }),
            numeric: Some(crate::vm::ir::NumericProof::from_range(0, 255)),
            ..ProofSlot::default()
        };
        let block = vec![
            IRNode::new(IRInstr::ConstNum(42.0), None, Some(Type::Num)).with_proof(ranged),
            IRNode::new(IRInstr::ConstNum(255.0), None, Some(Type::Num)),
            IRNode::new(IRInstr::And, None, Some(Type::Num)),
            IRNode::new(IRInstr::Return, None, None),
        ];
        let result = run_egraph_feedback_loop(
            block,
            FeedbackConfig {
                max_iters: 4,
                min_evidence_growth: 0,
                max_block_delta: 0,
                patience: 4,
            },
        );

        assert!(
            matches!(result.block[2].instr, IRInstr::ConstNum(v) if (v - 42.0).abs() < f64::EPSILON)
        );
        assert_eq!(result.materialization.identity_from_lhs, 1);
        assert_eq!(result.rounds[0].shape_delta, 2);
    }

    #[test]
    fn feedback_loop_skips_large_block_without_numeric_proof_potential() {
        let mut block = Vec::new();
        for i in 0..70 {
            block.push(IRNode::new(
                IRInstr::LoadVar(format!("k{}", i)),
                None,
                Some(Type::Any),
            ));
        }
        block.push(IRNode::new(IRInstr::Return, None, None));

        let result = run_egraph_feedback_loop(
            block.clone(),
            FeedbackConfig {
                max_iters: 4,
                min_evidence_growth: 0,
                max_block_delta: 0,
                patience: 2,
            },
        );

        assert_eq!(result.stop_reason, OptimizerStopReason::FixedPoint);
        assert!(result.rounds.is_empty());
        assert_eq!(result.block, block);
    }

    #[test]
    fn feedback_loop_skips_large_block_without_proof_gated_surface() {
        let nonzero = ProofSlot {
            refined_type: Some(RefinedType {
                base: Type::Num,
                predicate: Some("v != 0".into()),
            }),
            ..ProofSlot::default()
        };
        let mut block = Vec::new();
        block.push(
            IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)).with_proof(nonzero),
        );
        for i in 0..69 {
            block.push(IRNode::new(
                IRInstr::LoadVar(format!("k{}", i)),
                None,
                Some(Type::Any),
            ));
        }
        block.push(IRNode::new(IRInstr::Return, None, None));

        let result = run_egraph_feedback_loop(
            block.clone(),
            FeedbackConfig {
                max_iters: 4,
                min_evidence_growth: 0,
                max_block_delta: 0,
                patience: 2,
            },
        );

        assert_eq!(result.stop_reason, OptimizerStopReason::FixedPoint);
        assert!(result.rounds.is_empty());
        assert_eq!(result.block, block);
    }

    #[test]
    fn feedback_loop_keeps_large_block_with_proof_gated_surface() {
        let _guard = optimizer_env_lock();
        unsafe {
            std::env::remove_var("NAUX_EGRAPH_ENABLE_SCCP_FEEDBACK");
        }
        let nonzero = ProofSlot {
            refined_type: Some(RefinedType {
                base: Type::Num,
                predicate: Some("v != 0".into()),
            }),
            ..ProofSlot::default()
        };
        let mut block = Vec::new();
        for i in 0..64 {
            block.push(IRNode::new(
                IRInstr::LoadVar(format!("k{}", i)),
                None,
                Some(Type::Any),
            ));
        }
        block.push(
            IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num))
                .with_proof(nonzero.clone()),
        );
        block.push(
            IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)).with_proof(nonzero),
        );
        block.push(IRNode::new(IRInstr::Div, None, Some(Type::Num)));
        block.push(IRNode::new(IRInstr::Return, None, None));

        let result = run_egraph_feedback_loop(
            block,
            FeedbackConfig {
                max_iters: 4,
                min_evidence_growth: 0,
                max_block_delta: 0,
                patience: 2,
            },
        );

        assert!(!result.rounds.is_empty());
        assert!(result.materialization.const_one_result >= 1);
    }

    #[test]
    fn compile_ir_with_report_exposes_optimizer_stop_reason() {
        let _guard = optimizer_env_lock();
        unsafe {
            std::env::set_var("NAUX_EGRAPH_MIN_BLOCK_LEN", "0");
        }
        let stmts = crate::parser::parse_script(&crate::lexer::lex("!say \"hi\"").expect("lex"))
            .expect("parse");
        let (_ir, report) = compile_ir_with_report(&stmts);
        unsafe {
            std::env::remove_var("NAUX_EGRAPH_MIN_BLOCK_LEN");
        }
        assert!(
            matches!(
                report.main_feedback_stop,
                OptimizerStopReason::FixedPoint | OptimizerStopReason::ProofChurnEarlyStop
            ),
            "unexpected stop reason: {:?}",
            report.main_feedback_stop
        );
    }

    #[cfg(feature = "experimental-regions")]
    #[test]
    fn region_sidecar_compilation_preserves_ordinary_bytecode() {
        let source = r#"
~ fn work()
    $scratch = [1, 2, 3]
    ^ len($scratch)
~ end
^ work()
"#;
        let stmts =
            crate::parser::parse_script(&crate::lexer::lex(source).expect("lex")).expect("parse");
        let ordinary = compile_script(&stmts);
        let region_compiled =
            compile_script_with_region_plan(&stmts).expect("verified region sidecar");

        assert_eq!(
            format!("{:?}", ordinary.main),
            format!("{:?}", region_compiled.bytecode.main)
        );
        assert_eq!(region_compiled.region_plan.region_local_count, 1);
        crate::region::verify_region_lowering_plan(
            &region_compiled.region_report,
            &region_compiled.region_plan,
        )
        .expect("region certificate");
    }
}
