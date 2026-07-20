#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use egg::{
    define_language, rewrite, Applier, ConditionalApplier, CostFunction, DidMerge, EGraph, Id,
    Language, Pattern, PatternAst, RecExpr, Rewrite, Runner, SearchMatches, Searcher, Subst,
    Symbol, Var,
};

use crate::vm::ir::{
    AliasingClass, CostBound, EClassId, IRBlock, IRInstr, NodeId, NumericProof, ProofEnv,
    ProofSlot, SeaOfNodesGraph,
};

define_language! {
    pub enum NauxExpr {
        Num(i64),
        Symbol(egg::Symbol),
        "+" = Add([Id; 2]),
        "-" = Sub([Id; 2]),
        "*" = Mul([Id; 2]),
        "/" = Div([Id; 2]),
        "^" = Xor([Id; 2]),
        "<<" = Shl([Id; 2]),
        "&" = And([Id; 2]),
        "|" = Or([Id; 2]),
    }
}

#[derive(Debug, Default, Clone)]
pub struct NauxAnalysis;

impl egg::Analysis<NauxExpr> for NauxAnalysis {
    type Data = ProofSlot;

    fn make(_egraph: &mut EGraph<NauxExpr, Self>, _enode: &NauxExpr) -> Self::Data {
        ProofSlot::default()
    }

    fn merge(&mut self, to: &mut Self::Data, from: Self::Data) -> DidMerge {
        let before = to.clone();
        let merged = merge_proof_slots(to, &from);
        let to_changed = merged != before;
        let from_changed = merged != from;
        *to = merged;
        DidMerge(to_changed, from_changed)
    }
}

#[derive(Debug)]
pub struct BuildResult {
    pub egraph: EGraph<NauxExpr, NauxAnalysis>,
    pub roots: Vec<Id>,
    pub node_to_eclass: HashMap<NodeId, Id>,
}

#[derive(Debug, Clone)]
pub struct EClassProof {
    pub eclass: EClassId,
    pub node_ids: Vec<NodeId>,
    pub merged_proof: ProofSlot,
}

#[derive(Debug)]
pub struct SaturationResult {
    pub egraph: EGraph<NauxExpr, NauxAnalysis>,
    pub best_expr: Option<RecExpr<NauxExpr>>,
    pub best_cost: Option<u64>,
    pub node_to_eclass: HashMap<NodeId, Id>,
    pub obligation_batches: Vec<ObligationBatch>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationStatus {
    Discharged,
    Blocked,
    Deferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaturationStopReason {
    Saturated,
    IterationLimit,
    NodeLimit,
    TimeLimit,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofObligation {
    pub rewrite_name: String,
    pub requirement: ProofRequirement,
    pub status: ObligationStatus,
    pub eclass: Option<EClassId>,
    pub matched_subst: Option<String>,
    pub timestamp: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObligationBatch {
    pub stage: String,
    pub saturation_stop_reason: SaturationStopReason,
    pub obligations: Vec<ProofObligation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceEvent {
    rewrite_name: String,
    eclass: EClassId,
    matched_subst: String,
    timestamp: u64,
}

type TraceSink = Arc<Mutex<Vec<TraceEvent>>>;
type TraceClock = Arc<AtomicU64>;

struct DelegatingSearcher {
    inner: Arc<dyn Searcher<NauxExpr, NauxAnalysis> + Sync + Send>,
}

impl Searcher<NauxExpr, NauxAnalysis> for DelegatingSearcher {
    fn search_eclass_with_limit(
        &self,
        egraph: &EGraph<NauxExpr, NauxAnalysis>,
        eclass: Id,
        limit: usize,
    ) -> Option<SearchMatches<'_, NauxExpr>> {
        self.inner.search_eclass_with_limit(egraph, eclass, limit)
    }

    fn get_pattern_ast(&self) -> Option<&PatternAst<NauxExpr>> {
        self.inner.get_pattern_ast()
    }

    fn vars(&self) -> Vec<Var> {
        self.inner.vars()
    }
}

struct TracingApplier {
    inner: Arc<dyn Applier<NauxExpr, NauxAnalysis> + Sync + Send>,
    sink: TraceSink,
    clock: TraceClock,
}

impl Applier<NauxExpr, NauxAnalysis> for TracingApplier {
    fn get_pattern_ast(&self) -> Option<&PatternAst<NauxExpr>> {
        self.inner.get_pattern_ast()
    }

    fn apply_one(
        &self,
        egraph: &mut EGraph<NauxExpr, NauxAnalysis>,
        eclass: Id,
        subst: &Subst,
        searcher_ast: Option<&PatternAst<NauxExpr>>,
        rule_name: Symbol,
    ) -> Vec<Id> {
        let ids = self
            .inner
            .apply_one(egraph, eclass, subst, searcher_ast, rule_name);
        if !ids.is_empty() {
            let event = TraceEvent {
                rewrite_name: rule_name.to_string(),
                eclass: usize::from(eclass) as EClassId,
                matched_subst: format!("{subst:?}"),
                timestamp: self.clock.fetch_add(1, Ordering::Relaxed),
            };
            match self.sink.lock() {
                Ok(mut sink) => sink.push(event),
                Err(poisoned) => poisoned.into_inner().push(event),
            }
        }
        ids
    }

    fn vars(&self) -> Vec<Var> {
        self.inner.vars()
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct EclassProofSummary {
    pub by_eclass: HashMap<Id, ProofSlot>,
}

impl EclassProofSummary {
    pub fn is_empty(&self) -> bool {
        self.by_eclass.is_empty()
    }
}

impl SaturationResult {
    pub fn extract_eclass_proof_summary(&self) -> EclassProofSummary {
        let mut by_eclass: HashMap<Id, ProofSlot> = HashMap::new();
        for class in self.egraph.classes() {
            let root = self.egraph.find(class.id);
            if by_eclass.contains_key(&root) {
                continue;
            }
            let summary =
                summarize_eclass_slot(&self.egraph[root].data, self.egraph[root].nodes.as_slice());
            if !summary.is_empty() {
                by_eclass.insert(root, summary);
            }
        }
        EclassProofSummary { by_eclass }
    }
}

#[derive(Default)]
pub struct NauxCostModel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CostRank {
    pub score: u64,
    pub children: u64,
    pub rank: u64,
    pub nodes: u64,
}

impl CostRank {
    fn zero() -> Self {
        Self {
            score: 0,
            children: 0,
            rank: 0,
            nodes: 0,
        }
    }
}

fn node_base_cost(enode: &NauxExpr) -> u64 {
    match enode {
        NauxExpr::Shl(_) => 1,
        NauxExpr::And(_) => 1,
        NauxExpr::Or(_) => 1,
        NauxExpr::Xor(_) => 1,
        NauxExpr::Add(_) => 2,
        NauxExpr::Sub(_) => 2,
        NauxExpr::Mul(_) => 5,
        NauxExpr::Div(_) => 8,
        NauxExpr::Num(_) => 0,
        NauxExpr::Symbol(_) => 0,
    }
}

fn node_rank(enode: &NauxExpr) -> u64 {
    match enode {
        NauxExpr::Num(_) => 0,
        NauxExpr::Symbol(_) => 1,
        NauxExpr::Shl(_) => 2,
        NauxExpr::And(_) => 3,
        NauxExpr::Or(_) => 4,
        NauxExpr::Xor(_) => 5,
        NauxExpr::Add(_) => 6,
        NauxExpr::Sub(_) => 7,
        NauxExpr::Mul(_) => 8,
        NauxExpr::Div(_) => 9,
    }
}

impl CostFunction<NauxExpr> for NauxCostModel {
    type Cost = CostRank;

    fn cost<C>(&mut self, enode: &NauxExpr, mut costs: C) -> Self::Cost
    where
        C: FnMut(Id) -> Self::Cost,
    {
        let mut total = CostRank::zero();
        for child in enode.children() {
            let child_cost = costs(*child);
            total.score = total.score.saturating_add(child_cost.score);
            total.children = total.children.saturating_add(child_cost.children);
            total.rank = total.rank.saturating_add(child_cost.rank);
            total.nodes = total.nodes.saturating_add(child_cost.nodes);
        }
        total.score = total.score.saturating_add(node_base_cost(enode));
        total.children = total.children.saturating_add(enode.children().len() as u64);
        total.rank = total.rank.saturating_add(node_rank(enode));
        total.nodes = total.nodes.saturating_add(1);
        total
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofRequirement {
    None,
    NonZero,
    InRange(u64, u64),
    UnsafeContext,
    NoAlias,
}

pub fn can_apply(req: &ProofRequirement, slot: &ProofSlot) -> bool {
    match req {
        ProofRequirement::None => true,
        ProofRequirement::NonZero => slot.proven_nonzero(),
        ProofRequirement::InRange(lo, hi) => slot.range_within(*lo, *hi),
        ProofRequirement::UnsafeContext => slot.is_unsafe_context(),
        ProofRequirement::NoAlias => slot.aliasing == AliasingClass::NoAlias,
    }
}

#[derive(Debug)]
pub struct GuardedRewrite {
    pub requirement: ProofRequirement,
    pub rewrite: Rewrite<NauxExpr, NauxAnalysis>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ProofStrata {
    nonzero: bool,
    range: bool,
    unsafe_context: bool,
    no_alias: bool,
}

pub fn default_guarded_rewrites() -> Vec<GuardedRewrite> {
    let mut rewrites = vec![
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("add-0-r"; "(+ ?a 0)" => "?a"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("add-0-l"; "(+ 0 ?a)" => "?a"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("mul-1-r"; "(* ?a 1)" => "?a"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("mul-1-l"; "(* 1 ?a)" => "?a"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("mul-0-r"; "(* ?a 0)" => "0"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("mul-0-l"; "(* 0 ?a)" => "0"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("mul-2-to-shl"; "(* ?a 2)" => "(<< ?a 1)"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("mul-4-to-shl"; "(* ?a 4)" => "(<< ?a 2)"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("mul-8-to-shl"; "(* ?a 8)" => "(<< ?a 3)"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("sub-0"; "(- ?a 0)" => "?a"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("div-1"; "(/ ?a 1)" => "?a"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::NonZero,
            rewrite: rewrite!("div-self-nonzero"; "(/ ?a ?a)" => "1" if proven_nonzero_var("?a")),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("xor-idem"; "(^ ?a ?a)" => "0"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("xor-0-r"; "(^ ?a 0)" => "?a"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("xor-0-l"; "(^ 0 ?a)" => "?a"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("shl-0"; "(<< ?a 0)" => "?a"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("and-idem"; "(& ?a ?a)" => "?a"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("or-idem"; "(| ?a ?a)" => "?a"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("and-0-r"; "(& ?a 0)" => "0"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("and-0-l"; "(& 0 ?a)" => "0"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("or-0-r"; "(| ?a 0)" => "?a"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("or-0-l"; "(| 0 ?a)" => "?a"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("add-comm"; "(+ ?a ?b)" => "(+ ?b ?a)"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("mul-comm"; "(* ?a ?b)" => "(* ?b ?a)"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("xor-comm"; "(^ ?a ?b)" => "(^ ?b ?a)"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("and-comm"; "(& ?a ?b)" => "(& ?b ?a)"),
        },
        GuardedRewrite {
            requirement: ProofRequirement::None,
            rewrite: rewrite!("or-comm"; "(| ?a ?b)" => "(| ?b ?a)"),
        },
    ];
    rewrites.extend(and_mask_family_rewrites());
    rewrites
}

fn and_mask_family_rewrites() -> Vec<GuardedRewrite> {
    const AND_MASK_BITS: &[u32] = &[1, 2, 4, 7, 8, 15, 16, 31, 32, 63];
    let mut out = Vec::with_capacity(AND_MASK_BITS.len() * 2);
    for &bits in AND_MASK_BITS {
        let mask = ((1_u128 << bits) - 1) as u64;
        out.push(GuardedRewrite {
            requirement: ProofRequirement::InRange(0, mask),
            rewrite: and_mask_identity_rewrite(mask, false),
        });
        out.push(GuardedRewrite {
            requirement: ProofRequirement::InRange(0, mask),
            rewrite: and_mask_identity_rewrite(mask, true),
        });
    }
    out
}

fn and_mask_identity_rewrite(mask: u64, mask_on_lhs: bool) -> Rewrite<NauxExpr, NauxAnalysis> {
    let side = if mask_on_lhs { "l" } else { "r" };
    let name = format!("and-mask-{mask}-{side}");
    let lhs = if mask_on_lhs {
        format!("(& {mask} ?a)")
    } else {
        format!("(& ?a {mask})")
    };
    let searcher: Pattern<NauxExpr> = lhs
        .parse()
        .expect("and-mask family rule search pattern should parse");
    let applier: Pattern<NauxExpr> = "?a"
        .parse()
        .expect("and-mask family rule applier pattern should parse");
    let conditional = ConditionalApplier {
        condition: in_range_var("?a", 0, mask),
        applier,
    };
    Rewrite::new(name, searcher, conditional)
        .expect("and-mask family rewrite should preserve bound vars")
}

fn selected_rewrites_for_slot(
    guarded: Vec<GuardedRewrite>,
    slot: &ProofSlot,
) -> Vec<Rewrite<NauxExpr, NauxAnalysis>> {
    guarded
        .into_iter()
        .filter(|entry| can_apply(&entry.requirement, slot))
        .map(|entry| entry.rewrite)
        .collect()
}

pub fn default_rewrites() -> Vec<Rewrite<NauxExpr, NauxAnalysis>> {
    selected_rewrites_for_slot(default_guarded_rewrites(), &ProofSlot::default())
}

pub fn build_from_ir_block(block: &IRBlock) -> BuildResult {
    let mut egraph = EGraph::<NauxExpr, NauxAnalysis>::default();
    let mut stack: Vec<Id> = Vec::new();
    let mut roots: Vec<Id> = Vec::new();
    let mut node_to_eclass: HashMap<NodeId, Id> = HashMap::new();
    let mut var_versions: HashMap<String, u64> = HashMap::new();

    for node in block {
        let produced = match &node.instr {
            IRInstr::ConstNum(n) if n.fract() == 0.0 => Some(egraph.add(NauxExpr::Num(*n as i64))),
            IRInstr::ConstNum(n) => {
                Some(egraph.add(NauxExpr::Symbol(egg::Symbol::from(format!("f64:${}", n)))))
            }
            IRInstr::ConstBool(b) => Some(egraph.add(NauxExpr::Num(if *b { 1 } else { 0 }))),
            IRInstr::ConstText(s) => {
                Some(egraph.add(NauxExpr::Symbol(egg::Symbol::from(format!("text:${}", s)))))
            }
            IRInstr::LoadVar(name) => {
                let version = var_versions.get(name).copied().unwrap_or(0);
                Some(egraph.add(NauxExpr::Symbol(egg::Symbol::from(format!(
                    "var:${}@{}",
                    name, version
                )))))
            }
            IRInstr::PushNull => Some(egraph.add(NauxExpr::Symbol(egg::Symbol::from("null")))),
            IRInstr::Add
            | IRInstr::Sub
            | IRInstr::Mul
            | IRInstr::Div
            | IRInstr::Xor
            | IRInstr::Shl
            | IRInstr::And
            | IRInstr::Or => {
                if let (Some(rhs), Some(lhs)) = (stack.pop(), stack.pop()) {
                    let enode = match node.instr {
                        IRInstr::Add => NauxExpr::Add([lhs, rhs]),
                        IRInstr::Sub => NauxExpr::Sub([lhs, rhs]),
                        IRInstr::Mul => NauxExpr::Mul([lhs, rhs]),
                        IRInstr::Div => NauxExpr::Div([lhs, rhs]),
                        IRInstr::Xor => NauxExpr::Xor([lhs, rhs]),
                        IRInstr::Shl => NauxExpr::Shl([lhs, rhs]),
                        IRInstr::And => NauxExpr::And([lhs, rhs]),
                        IRInstr::Or => NauxExpr::Or([lhs, rhs]),
                        _ => unreachable!("handled above"),
                    };
                    Some(egraph.add(enode))
                } else {
                    None
                }
            }
            IRInstr::StoreVar(name) => {
                let _ = stack.pop();
                *var_versions.entry(name.clone()).or_insert(0) += 1;
                None
            }
            IRInstr::Pop | IRInstr::JumpIfFalse(_) => {
                let _ = stack.pop();
                None
            }
            IRInstr::CallBuiltin(name, argc) => {
                for _ in 0..*argc {
                    let _ = stack.pop();
                }
                if node.result_type.is_some() {
                    Some(egraph.add(NauxExpr::Symbol(egg::Symbol::from(format!(
                        "call:{}",
                        name
                    )))))
                } else {
                    None
                }
            }
            IRInstr::CallFn(name, argc) => {
                for _ in 0..*argc {
                    let _ = stack.pop();
                }
                if node.result_type.is_some() {
                    Some(egraph.add(NauxExpr::Symbol(egg::Symbol::from(format!("fn:{}", name)))))
                } else {
                    None
                }
            }
            IRInstr::Call(argc) => {
                for _ in 0..*argc {
                    let _ = stack.pop();
                }
                if node.result_type.is_some() {
                    Some(egraph.add(NauxExpr::Symbol(egg::Symbol::from("call"))))
                } else {
                    None
                }
            }
            IRInstr::MakeList(n) => {
                for _ in 0..*n {
                    let _ = stack.pop();
                }
                Some(egraph.add(NauxExpr::Symbol(egg::Symbol::from("list"))))
            }
            IRInstr::MakeMap(keys) => {
                for _ in 0..keys.len() {
                    let _ = stack.pop();
                }
                Some(egraph.add(NauxExpr::Symbol(egg::Symbol::from("map"))))
            }
            IRInstr::LoadField(_) => {
                let _ = stack.pop();
                Some(egraph.add(NauxExpr::Symbol(egg::Symbol::from("field"))))
            }
            IRInstr::Eq
            | IRInstr::Ne
            | IRInstr::Gt
            | IRInstr::Ge
            | IRInstr::Lt
            | IRInstr::Le
            | IRInstr::Mod => {
                let _ = stack.pop();
                let _ = stack.pop();
                Some(egraph.add(NauxExpr::Symbol(egg::Symbol::from("pred"))))
            }
            IRInstr::Jump(_) => None,
            IRInstr::EmitSay
            | IRInstr::EmitAsk
            | IRInstr::EmitFetch
            | IRInstr::EmitUi(_)
            | IRInstr::EmitText
            | IRInstr::EmitButton
            | IRInstr::EmitLog
            | IRInstr::Return => None,
        };

        if let Some(id) = produced {
            stack.push(id);
            roots.push(id);
            node_to_eclass.insert(node.id, id);
        }
    }

    BuildResult {
        egraph,
        roots,
        node_to_eclass,
    }
}

pub fn run_saturation(
    build: BuildResult,
    iter_limit: usize,
    node_limit: usize,
) -> SaturationResult {
    run_saturation_with_proof_env(build, iter_limit, node_limit, &ProofEnv::default())
}

pub fn run_saturation_with_proof_env(
    mut build: BuildResult,
    iter_limit: usize,
    node_limit: usize,
    env: &ProofEnv,
) -> SaturationResult {
    seed_egraph_with_proof_env(&mut build.egraph, &build.node_to_eclass, env);
    let stratified = run_stratified_saturation(
        build.egraph,
        default_guarded_rewrites(),
        proof_strata_for_env(env),
        iter_limit,
        node_limit,
    );
    let egraph = stratified.egraph;
    let extractor = egg::Extractor::new(&egraph, NauxCostModel);

    let mut best_expr: Option<RecExpr<NauxExpr>> = None;
    let mut best_rank: Option<CostRank> = None;
    let mut best_cost: Option<u64> = None;
    for root in &build.roots {
        let (cost, expr) = extractor.find_best(*root);
        let take = match best_rank {
            Some(c) => cost < c,
            None => true,
        };
        if take {
            best_rank = Some(cost);
            best_cost = Some(cost.score);
            best_expr = Some(expr);
        }
    }

    SaturationResult {
        egraph,
        best_expr,
        best_cost,
        node_to_eclass: build.node_to_eclass,
        obligation_batches: stratified.obligation_batches,
    }
}

fn proven_nonzero_var(
    var: &'static str,
) -> impl Fn(&mut EGraph<NauxExpr, NauxAnalysis>, Id, &Subst) -> bool {
    let var: Var = var.parse().expect("valid rewrite variable");
    move |egraph, _, subst| egraph[subst[var]].data.proven_nonzero()
}

fn in_range_var(
    var: &'static str,
    lo: u64,
    hi: u64,
) -> impl Fn(&mut EGraph<NauxExpr, NauxAnalysis>, Id, &Subst) -> bool {
    let var: Var = var.parse().expect("valid rewrite variable");
    move |egraph, _, subst| egraph[subst[var]].data.range_within(lo, hi)
}

fn proof_strata_for_env(env: &ProofEnv) -> ProofStrata {
    let mut out = ProofStrata {
        unsafe_context: env.unsafe_context,
        ..ProofStrata::default()
    };
    for slot in env.by_node.values() {
        out.nonzero |= slot.numeric_nonzero();
        out.range |= slot.numeric_range().is_some();
        out.unsafe_context |= slot.unsafe_context;
        out.no_alias |= slot.aliasing == AliasingClass::NoAlias;
    }
    out
}

fn stratum_allows_requirement(strata: ProofStrata, requirement: &ProofRequirement) -> bool {
    match requirement {
        ProofRequirement::None => true,
        ProofRequirement::NonZero => strata.nonzero,
        ProofRequirement::InRange(..) => strata.range,
        ProofRequirement::UnsafeContext => strata.unsafe_context,
        ProofRequirement::NoAlias => strata.no_alias,
    }
}

fn should_trace_proof_rewrite(rule_name: Symbol) -> bool {
    if rule_name == Symbol::from("div-self-nonzero") {
        return true;
    }
    let name = rule_name.to_string();
    name.starts_with("and-mask-") && (name.ends_with("-r") || name.ends_with("-l"))
}

fn wrap_rewrite_with_trace(
    rewrite: &Rewrite<NauxExpr, NauxAnalysis>,
    sink: &TraceSink,
    clock: &TraceClock,
) -> Rewrite<NauxExpr, NauxAnalysis> {
    Rewrite::new(
        rewrite.name,
        DelegatingSearcher {
            inner: rewrite.searcher.clone(),
        },
        TracingApplier {
            inner: rewrite.applier.clone(),
            sink: Arc::clone(sink),
            clock: Arc::clone(clock),
        },
    )
    .expect("tracing rewrite wrapper should preserve bound vars")
}

fn rewrites_for_strata(
    guarded: &[GuardedRewrite],
    strata: ProofStrata,
    trace_sink: Option<&TraceSink>,
    trace_clock: Option<&TraceClock>,
) -> Vec<Rewrite<NauxExpr, NauxAnalysis>> {
    guarded
        .iter()
        .filter(|entry| stratum_allows_requirement(strata, &entry.requirement))
        .map(|entry| {
            let rewrite = entry.rewrite.clone();
            if let (Some(sink), Some(clock)) = (trace_sink, trace_clock) {
                if should_trace_proof_rewrite(rewrite.name) {
                    return wrap_rewrite_with_trace(&rewrite, sink, clock);
                }
            }
            rewrite
        })
        .collect()
}

#[derive(Debug)]
struct StratifiedSaturationOutput {
    egraph: EGraph<NauxExpr, NauxAnalysis>,
    obligation_batches: Vec<ObligationBatch>,
}

fn drain_trace_events(sink: &TraceSink) -> Vec<TraceEvent> {
    match sink.lock() {
        Ok(mut events) => {
            let mut drained = std::mem::take(&mut *events);
            drained.sort_by_key(|event| event.timestamp);
            drained
        }
        Err(poisoned) => {
            let mut events = poisoned.into_inner();
            let mut drained = std::mem::take(&mut *events);
            drained.sort_by_key(|event| event.timestamp);
            drained
        }
    }
}

fn run_stage_with_trace(
    stage: &str,
    egraph: EGraph<NauxExpr, NauxAnalysis>,
    guarded: &[GuardedRewrite],
    stage_strata: ProofStrata,
    iter_limit: usize,
    node_limit: usize,
) -> (EGraph<NauxExpr, NauxAnalysis>, ObligationBatch) {
    let trace_sink: TraceSink = Arc::new(Mutex::new(Vec::new()));
    let trace_clock: TraceClock = Arc::new(AtomicU64::new(0));
    let runner = Runner::default()
        .with_egraph(egraph)
        .with_iter_limit(iter_limit)
        .with_node_limit(node_limit)
        .run(&rewrites_for_strata(
            guarded,
            stage_strata,
            Some(&trace_sink),
            Some(&trace_clock),
        ));
    let trace_events = drain_trace_events(&trace_sink);
    let batch = obligation_batch_for_stage(
        stage,
        guarded,
        stage_strata,
        to_saturation_stop_reason(runner.stop_reason.as_ref()),
        &trace_events,
    );
    (runner.egraph, batch)
}

fn run_stratified_saturation(
    mut egraph: EGraph<NauxExpr, NauxAnalysis>,
    guarded: Vec<GuardedRewrite>,
    strata: ProofStrata,
    iter_limit: usize,
    node_limit: usize,
) -> StratifiedSaturationOutput {
    let mut obligation_batches = Vec::new();
    let base_strata = ProofStrata {
        nonzero: false,
        range: false,
        unsafe_context: strata.unsafe_context,
        no_alias: strata.no_alias,
    };
    let (next, batch) = run_stage_with_trace(
        "base",
        egraph,
        &guarded,
        base_strata,
        iter_limit,
        node_limit,
    );
    egraph = next;
    obligation_batches.push(batch);

    if strata.nonzero {
        let nonzero_strata = ProofStrata {
            nonzero: true,
            range: false,
            unsafe_context: strata.unsafe_context,
            no_alias: strata.no_alias,
        };
        let (next, batch) = run_stage_with_trace(
            "nonzero",
            egraph,
            &guarded,
            nonzero_strata,
            iter_limit,
            node_limit,
        );
        egraph = next;
        obligation_batches.push(batch);
    }

    if strata.range {
        let (next, batch) =
            run_stage_with_trace("range", egraph, &guarded, strata, iter_limit, node_limit);
        egraph = next;
        obligation_batches.push(batch);
    }

    StratifiedSaturationOutput {
        egraph,
        obligation_batches,
    }
}

fn obligation_batch_for_stage(
    stage: &str,
    guarded: &[GuardedRewrite],
    strata: ProofStrata,
    saturation_stop_reason: SaturationStopReason,
    trace_events: &[TraceEvent],
) -> ObligationBatch {
    let mut trace_by_rewrite: HashMap<String, Vec<&TraceEvent>> = HashMap::new();
    for event in trace_events {
        trace_by_rewrite
            .entry(event.rewrite_name.clone())
            .or_default()
            .push(event);
    }
    let mut obligations = Vec::new();
    for entry in guarded
        .iter()
        .filter(|entry| !matches!(entry.requirement, ProofRequirement::None))
    {
        let rewrite_name = entry.rewrite.name.to_string();
        if !stratum_allows_requirement(strata, &entry.requirement) {
            obligations.push(ProofObligation {
                rewrite_name,
                requirement: entry.requirement,
                status: ObligationStatus::Blocked,
                eclass: None,
                matched_subst: None,
                timestamp: None,
            });
            continue;
        }
        if let Some(events) = trace_by_rewrite.get(&rewrite_name) {
            if !events.is_empty() {
                for event in events {
                    obligations.push(ProofObligation {
                        rewrite_name: rewrite_name.clone(),
                        requirement: entry.requirement,
                        status: ObligationStatus::Discharged,
                        eclass: Some(event.eclass),
                        matched_subst: Some(event.matched_subst.clone()),
                        timestamp: Some(event.timestamp),
                    });
                }
                continue;
            }
        }
        obligations.push(ProofObligation {
            rewrite_name,
            requirement: entry.requirement,
            status: ObligationStatus::Deferred,
            eclass: None,
            matched_subst: None,
            timestamp: None,
        });
    }
    ObligationBatch {
        stage: stage.to_string(),
        saturation_stop_reason,
        obligations,
    }
}

fn to_saturation_stop_reason(reason: Option<&egg::StopReason>) -> SaturationStopReason {
    match reason {
        Some(egg::StopReason::Saturated) => SaturationStopReason::Saturated,
        Some(egg::StopReason::IterationLimit(_)) => SaturationStopReason::IterationLimit,
        Some(egg::StopReason::NodeLimit(_)) => SaturationStopReason::NodeLimit,
        Some(egg::StopReason::TimeLimit(_)) => SaturationStopReason::TimeLimit,
        Some(egg::StopReason::Other(_)) | None => SaturationStopReason::Other,
    }
}

fn seed_egraph_with_proof_env(
    egraph: &mut EGraph<NauxExpr, NauxAnalysis>,
    node_to_eclass: &HashMap<NodeId, Id>,
    env: &ProofEnv,
) {
    for (node_id, slot) in &env.by_node {
        let Some(eclass) = node_to_eclass.get(node_id) else {
            continue;
        };
        let current = egraph[*eclass].data.clone();
        egraph[*eclass].data = merge_proof_slots(&current, slot);
    }
    if env.unsafe_context {
        for class in egraph.classes_mut() {
            class.data.unsafe_context = true;
        }
    }
}

pub fn merge_eclass_proofs(
    graph: &SeaOfNodesGraph,
    node_to_eclass: &HashMap<NodeId, Id>,
) -> Vec<EClassProof> {
    let mut grouped: HashMap<EClassId, EClassProof> = HashMap::new();

    for (node_id, eclass) in node_to_eclass {
        let eclass_id = usize::from(*eclass) as EClassId;
        let Some(node) = graph.node(*node_id) else {
            continue;
        };
        let entry = grouped.entry(eclass_id).or_insert_with(|| EClassProof {
            eclass: eclass_id,
            node_ids: Vec::new(),
            merged_proof: ProofSlot::default(),
        });
        entry.node_ids.push(*node_id);
        entry.merged_proof = merge_proof_slots(&entry.merged_proof, &node.proof);
    }

    let mut out: Vec<EClassProof> = grouped.into_values().collect();
    out.sort_by_key(|x| x.eclass);
    out
}

fn merge_proof_slots(a: &ProofSlot, b: &ProofSlot) -> ProofSlot {
    let refined_type = match (&a.refined_type, &b.refined_type) {
        (Some(x), Some(y)) if x == y => Some(x.clone()),
        (Some(x), None) => Some(x.clone()),
        (None, Some(y)) => Some(y.clone()),
        _ => None,
    };

    let numeric = match (
        a.numeric.or_else(|| a.numeric_fallback()),
        b.numeric.or_else(|| b.numeric_fallback()),
    ) {
        (Some(x), Some(y)) => x.merge(y),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    };

    let cost_bound = match (&a.cost_bound, &b.cost_bound) {
        (Some(x), Some(y)) => Some(CostBound {
            worst_cycles: min_opt(x.worst_cycles, y.worst_cycles),
            alloc_bytes: min_opt(x.alloc_bytes, y.alloc_bytes),
            mem_reads: min_opt(x.mem_reads, y.mem_reads),
            mem_writes: min_opt(x.mem_writes, y.mem_writes),
        }),
        (Some(x), None) => Some(x.clone()),
        (None, Some(y)) => Some(y.clone()),
        (None, None) => None,
    };

    let coq_cert = match (a.coq_cert, b.coq_cert) {
        (Some(x), Some(y)) if x == y => Some(x),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        _ => None,
    };

    let aliasing = if a.aliasing == b.aliasing {
        a.aliasing
    } else {
        AliasingClass::Unknown
    };

    let unsafe_context = if a.is_empty() {
        b.unsafe_context
    } else if b.is_empty() {
        a.unsafe_context
    } else {
        a.unsafe_context && b.unsafe_context
    };

    ProofSlot {
        refined_type,
        numeric,
        cost_bound,
        coq_cert,
        aliasing,
        unsafe_context,
    }
}

fn summarize_eclass_slot(base: &ProofSlot, nodes: &[NauxExpr]) -> ProofSlot {
    let mut summary = base.clone();
    if let Some(literal_numeric) = summarize_numeric_from_eclass_nodes(nodes) {
        summary = merge_proof_slots(
            &summary,
            &ProofSlot {
                numeric: Some(literal_numeric),
                ..ProofSlot::default()
            },
        );
    }
    summary
}

fn summarize_numeric_from_eclass_nodes(nodes: &[NauxExpr]) -> Option<NumericProof> {
    let mut summary: Option<NumericProof> = None;
    for node in nodes {
        let NauxExpr::Num(value) = node else {
            continue;
        };
        let numeric = NumericProof::from_exact(*value);
        summary = match summary {
            Some(current) => current.merge(numeric),
            None => Some(numeric),
        };
        if summary.is_none() {
            break;
        }
    }
    summary
}

fn min_opt(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typecheck::Type;
    use crate::vm::ir::{IRNode, IRProgram, RefinedType};

    #[test]
    fn build_and_saturate_basic_arith() {
        let prog = IRProgram {
            main: vec![
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::ConstNum(0.0), None, None),
                IRNode::new(IRInstr::Add, None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };

        let build = build_from_ir_block(&prog.main);
        let saturated = run_saturation(build, 8, 10_000);
        assert!(saturated.best_cost.is_some());
        assert!(saturated.best_expr.is_some());
    }

    #[test]
    fn rewrites_mul_by_two_into_shl_form() {
        let prog = IRProgram {
            main: vec![
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::ConstNum(2.0), None, None),
                IRNode::new(IRInstr::Mul, None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };

        let build = build_from_ir_block(&prog.main);
        let root = *build
            .roots
            .last()
            .expect("mul expression root should be present");
        let saturated = run_saturation(build, 8, 10_000);

        let root_class = saturated.egraph.find(root);
        let has_shl = saturated.egraph[root_class]
            .nodes
            .iter()
            .any(|n| matches!(n, NauxExpr::Shl(_)));
        assert!(
            has_shl,
            "expected mul-by-2 rewrite to introduce ShiftLeft node"
        );
    }

    #[test]
    fn rewrites_and_idempotent() {
        let prog = IRProgram {
            main: vec![
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::And, None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };

        let build = build_from_ir_block(&prog.main);
        let root = *build
            .roots
            .last()
            .expect("and expression root should be present");
        let saturated = run_saturation(build, 8, 10_000);

        let root_class = saturated.egraph.find(root);
        let has_symbol_x = saturated.egraph[root_class]
            .nodes
            .iter()
            .any(|n| matches!(n, NauxExpr::Symbol(sym) if sym.as_str() == "var:$x@0"));
        assert!(
            has_symbol_x,
            "expected and-idempotent rewrite to collapse to var:$x@0"
        );
    }

    #[test]
    fn rewrites_xor_idempotent_to_zero() {
        let prog = IRProgram {
            main: vec![
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::Xor, None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };

        let build = build_from_ir_block(&prog.main);
        let root = *build
            .roots
            .last()
            .expect("xor expression root should be present");
        let saturated = run_saturation(build, 8, 10_000);

        let root_class = saturated.egraph.find(root);
        let has_zero = saturated.egraph[root_class]
            .nodes
            .iter()
            .any(|n| matches!(n, NauxExpr::Num(0)));
        assert!(
            has_zero,
            "expected xor-idempotent rewrite to introduce zero"
        );
    }

    #[test]
    fn extraction_prefers_shl_over_mul_for_mul_by_two() {
        let prog = IRProgram {
            main: vec![
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::ConstNum(2.0), None, None),
                IRNode::new(IRInstr::Mul, None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };
        let build = build_from_ir_block(&prog.main);
        let root = *build.roots.last().expect("root");
        let saturated = run_saturation(build, 8, 10_000);
        let extractor = egg::Extractor::new(&saturated.egraph, NauxCostModel);
        let (_cost, expr) = extractor.find_best(root);
        let rendered = expr.to_string();
        assert!(
            rendered.contains("<<"),
            "expected extraction to prefer shift form, got: {}",
            rendered
        );
    }

    #[test]
    fn extraction_prefers_single_shift_for_mul_by_eight() {
        let prog = IRProgram {
            main: vec![
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::ConstNum(8.0), None, None),
                IRNode::new(IRInstr::Mul, None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };
        let build = build_from_ir_block(&prog.main);
        let root = *build.roots.last().expect("root");
        let saturated = run_saturation(build, 8, 10_000);
        let extractor = egg::Extractor::new(&saturated.egraph, NauxCostModel);
        let (_cost, expr) = extractor.find_best(root);
        let rendered = expr.to_string();
        let shl_count = rendered.matches("<<").count();
        assert_eq!(
            shl_count, 1,
            "expected single-shift representation, got: {}",
            rendered
        );
        assert!(
            rendered.contains("3"),
            "expected mul-by-8 extraction to shift by 3, got: {}",
            rendered
        );
    }

    #[test]
    fn extraction_prefers_idempotent_and_to_symbol() {
        let prog = IRProgram {
            main: vec![
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::And, None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };
        let build = build_from_ir_block(&prog.main);
        let root = *build.roots.last().expect("root");
        let saturated = run_saturation(build, 8, 10_000);
        let extractor = egg::Extractor::new(&saturated.egraph, NauxCostModel);
        let (_cost, expr) = extractor.find_best(root);
        let rendered = expr.to_string();
        assert!(
            rendered.contains("var:$x"),
            "expected idempotent and to extract symbol, got: {}",
            rendered
        );
    }

    #[test]
    fn extraction_is_deterministic_across_runs() {
        let prog = IRProgram {
            main: vec![
                IRNode::new(IRInstr::LoadVar("x".into()), None, None),
                IRNode::new(IRInstr::ConstNum(2.0), None, None),
                IRNode::new(IRInstr::Mul, None, None),
                IRNode::new(IRInstr::ConstNum(0.0), None, None),
                IRNode::new(IRInstr::Or, None, None),
                IRNode::new(IRInstr::Return, None, None),
            ],
            functions: HashMap::new(),
            main_return: None,
        };

        let mut first: Option<String> = None;
        for _ in 0..8 {
            let build = build_from_ir_block(&prog.main);
            let root = *build.roots.last().expect("root");
            let saturated = run_saturation(build, 8, 10_000);
            let extractor = egg::Extractor::new(&saturated.egraph, NauxCostModel);
            let (_cost, expr) = extractor.find_best(root);
            let rendered = expr.to_string();
            if let Some(prev) = &first {
                assert_eq!(prev, &rendered);
            } else {
                first = Some(rendered);
            }
        }
    }

    #[test]
    fn proof_guard_checks_requirements() {
        let plain = ProofSlot::default();
        assert!(can_apply(&ProofRequirement::None, &plain));
        assert!(!can_apply(&ProofRequirement::NonZero, &plain));
        assert!(!can_apply(&ProofRequirement::UnsafeContext, &plain));
        assert!(!can_apply(&ProofRequirement::NoAlias, &plain));
        assert!(!can_apply(&ProofRequirement::InRange(0, 63), &plain));

        let ranged = ProofSlot {
            refined_type: Some(RefinedType {
                base: Type::Num,
                predicate: Some("range:[1,63]".to_string()),
            }),
            ..ProofSlot::default()
        };
        assert!(can_apply(&ProofRequirement::NonZero, &ranged));
        assert!(can_apply(&ProofRequirement::InRange(0, 63), &ranged));
        assert!(!can_apply(&ProofRequirement::InRange(0, 32), &ranged));

        let unsafe_slot = ProofSlot {
            unsafe_context: true,
            ..ProofSlot::default()
        };
        assert!(can_apply(&ProofRequirement::UnsafeContext, &unsafe_slot));

        let no_alias = ProofSlot {
            aliasing: AliasingClass::NoAlias,
            ..ProofSlot::default()
        };
        assert!(can_apply(&ProofRequirement::NoAlias, &no_alias));
    }

    #[test]
    fn proof_guard_filters_rewrites_by_slot() {
        let guarded = vec![
            GuardedRewrite {
                requirement: ProofRequirement::None,
                rewrite: rewrite!("t-add-0-r"; "(+ ?a 0)" => "?a"),
            },
            GuardedRewrite {
                requirement: ProofRequirement::UnsafeContext,
                rewrite: rewrite!("t-shl-0"; "(<< ?a 0)" => "?a"),
            },
        ];

        let plain = ProofSlot::default();
        let enabled_plain = selected_rewrites_for_slot(guarded, &plain);
        assert_eq!(enabled_plain.len(), 1);

        let guarded = vec![
            GuardedRewrite {
                requirement: ProofRequirement::None,
                rewrite: rewrite!("t2-add-0-r"; "(+ ?a 0)" => "?a"),
            },
            GuardedRewrite {
                requirement: ProofRequirement::UnsafeContext,
                rewrite: rewrite!("t2-shl-0"; "(<< ?a 0)" => "?a"),
            },
        ];
        let unsafe_slot = ProofSlot {
            unsafe_context: true,
            ..ProofSlot::default()
        };
        let enabled_unsafe = selected_rewrites_for_slot(guarded, &unsafe_slot);
        assert_eq!(enabled_unsafe.len(), 2);
    }

    #[test]
    fn nonzero_proof_env_unlocks_div_self_rewrite() {
        let lhs = IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)).with_proof(
            ProofSlot {
                refined_type: Some(RefinedType {
                    base: Type::Num,
                    predicate: Some("v != 0".into()),
                }),
                ..ProofSlot::default()
            },
        );
        let rhs = IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)).with_proof(
            ProofSlot {
                refined_type: Some(RefinedType {
                    base: Type::Num,
                    predicate: Some("v != 0".into()),
                }),
                ..ProofSlot::default()
            },
        );
        let div = IRNode::new(IRInstr::Div, None, Some(Type::Num));
        let block = vec![lhs.clone(), rhs.clone(), div];

        let build_plain = build_from_ir_block(&block);
        let plain_root = *build_plain.roots.last().expect("plain root");
        let plain = run_saturation_with_proof_env(build_plain, 8, 10_000, &ProofEnv::default());
        let plain_expr = egg::Extractor::new(&plain.egraph, NauxCostModel)
            .find_best(plain_root)
            .1
            .to_string();
        assert_ne!(plain_expr, "1");

        let env = ProofEnv {
            by_node: HashMap::from([(lhs.id, lhs.proof.clone()), (rhs.id, rhs.proof.clone())]),
            unsafe_context: false,
        };
        let build_proven = build_from_ir_block(&block);
        let proven_root = *build_proven.roots.last().expect("proven root");
        let proven = run_saturation_with_proof_env(build_proven, 8, 10_000, &env);
        let proven_expr = egg::Extractor::new(&proven.egraph, NauxCostModel)
            .find_best(proven_root)
            .1
            .to_string();
        assert_eq!(proven_expr, "1");
    }

    fn mask_identity_best_expr(mask: u64, lhs: IRNode, env: &ProofEnv) -> String {
        let rhs = IRNode::new(IRInstr::ConstNum(mask as f64), None, Some(Type::Num));
        let and = IRNode::new(IRInstr::And, None, Some(Type::Num));
        let block = vec![lhs, rhs, and];
        let build = build_from_ir_block(&block);
        let root = *build.roots.last().expect("and-mask root");
        let saturated = run_saturation_with_proof_env(build, 8, 10_000, env);
        egg::Extractor::new(&saturated.egraph, NauxCostModel)
            .find_best(root)
            .1
            .to_string()
    }

    #[test]
    fn range_proof_env_unlocks_and_mask_1_identity_rewrite() {
        let lhs = IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)).with_proof(
            ProofSlot {
                numeric: Some(crate::vm::ir::NumericProof::from_range(0, 1)),
                ..ProofSlot::default()
            },
        );
        let plain_expr = mask_identity_best_expr(1, lhs.clone(), &ProofEnv::default());
        assert_ne!(plain_expr, "var:$x@0");

        let env = ProofEnv {
            by_node: HashMap::from([(lhs.id, lhs.proof.clone())]),
            unsafe_context: false,
        };
        let proven_expr = mask_identity_best_expr(1, lhs, &env);
        assert_eq!(proven_expr, "var:$x@0");
    }

    #[test]
    fn range_proof_env_unlocks_and_mask_identity_rewrite() {
        let lhs = IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)).with_proof(
            ProofSlot {
                refined_type: Some(RefinedType {
                    base: Type::Num,
                    predicate: Some("range:[0,255]".into()),
                }),
                numeric: Some(crate::vm::ir::NumericProof::from_range(0, 255)),
                ..ProofSlot::default()
            },
        );
        let rhs = IRNode::new(IRInstr::ConstNum(255.0), None, Some(Type::Num));
        let and = IRNode::new(IRInstr::And, None, Some(Type::Num));
        let block = vec![lhs.clone(), rhs, and];

        let build_plain = build_from_ir_block(&block);
        let plain_root = *build_plain.roots.last().expect("plain root");
        let plain = run_saturation_with_proof_env(build_plain, 8, 10_000, &ProofEnv::default());
        let plain_expr = egg::Extractor::new(&plain.egraph, NauxCostModel)
            .find_best(plain_root)
            .1
            .to_string();
        assert_ne!(plain_expr, "x");

        let env = ProofEnv {
            by_node: HashMap::from([(lhs.id, lhs.proof.clone())]),
            unsafe_context: false,
        };
        let build_proven = build_from_ir_block(&block);
        let proven_root = *build_proven.roots.last().expect("proven root");
        let proven = run_saturation_with_proof_env(build_proven, 8, 10_000, &env);
        let proven_expr = egg::Extractor::new(&proven.egraph, NauxCostModel)
            .find_best(proven_root)
            .1
            .to_string();
        assert_eq!(proven_expr, "var:$x@0");
    }

    #[test]
    fn range_proof_env_unlocks_and_mask_32bit_identity_rewrite() {
        let mask = 0xFFFF_FFFF_u64;
        let lhs = IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)).with_proof(
            ProofSlot {
                numeric: Some(crate::vm::ir::NumericProof::from_range(0, mask)),
                ..ProofSlot::default()
            },
        );
        let plain_expr = mask_identity_best_expr(mask, lhs.clone(), &ProofEnv::default());
        assert_ne!(plain_expr, "var:$x@0");

        let env = ProofEnv {
            by_node: HashMap::from([(lhs.id, lhs.proof.clone())]),
            unsafe_context: false,
        };
        let proven_expr = mask_identity_best_expr(mask, lhs, &env);
        assert_eq!(proven_expr, "var:$x@0");
    }

    #[test]
    fn and_mask_255_rejects_range_that_exceeds_mask() {
        let lhs = IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)).with_proof(
            ProofSlot {
                numeric: Some(crate::vm::ir::NumericProof::from_range(0, 300)),
                ..ProofSlot::default()
            },
        );
        let env = ProofEnv {
            by_node: HashMap::from([(lhs.id, lhs.proof.clone())]),
            unsafe_context: false,
        };
        let expr = mask_identity_best_expr(255, lhs, &env);
        assert_ne!(expr, "var:$x");
    }

    #[test]
    fn obligation_batches_mark_nonzero_rule_blocked_without_proof() {
        let lhs = IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num));
        let rhs = IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num));
        let div = IRNode::new(IRInstr::Div, None, Some(Type::Num));
        let block = vec![lhs, rhs, div];
        let saturated = run_saturation_with_proof_env(
            build_from_ir_block(&block),
            8,
            10_000,
            &ProofEnv::default(),
        );

        let nonzero = saturated
            .obligation_batches
            .iter()
            .flat_map(|batch| batch.obligations.iter())
            .find(|obligation| obligation.rewrite_name == "div-self-nonzero")
            .expect("must emit obligation for div-self-nonzero");
        assert_eq!(nonzero.requirement, ProofRequirement::NonZero);
        assert_eq!(nonzero.status, ObligationStatus::Blocked);
    }

    #[test]
    fn obligation_batches_mark_nonzero_rule_discharged_when_rule_fires() {
        let lhs = IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)).with_proof(
            ProofSlot {
                refined_type: Some(RefinedType {
                    base: Type::Num,
                    predicate: Some("v != 0".into()),
                }),
                ..ProofSlot::default()
            },
        );
        let rhs = IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)).with_proof(
            ProofSlot {
                refined_type: Some(RefinedType {
                    base: Type::Num,
                    predicate: Some("v != 0".into()),
                }),
                ..ProofSlot::default()
            },
        );
        let div = IRNode::new(IRInstr::Div, None, Some(Type::Num));
        let block = vec![lhs.clone(), rhs.clone(), div];
        let env = ProofEnv {
            by_node: HashMap::from([(lhs.id, lhs.proof.clone()), (rhs.id, rhs.proof.clone())]),
            unsafe_context: false,
        };
        let saturated = run_saturation_with_proof_env(build_from_ir_block(&block), 8, 10_000, &env);

        let statuses = saturated
            .obligation_batches
            .iter()
            .flat_map(|batch| batch.obligations.iter())
            .filter(|obligation| obligation.rewrite_name == "div-self-nonzero")
            .collect::<Vec<_>>();
        let status_kinds = statuses
            .iter()
            .map(|obligation| obligation.status)
            .collect::<Vec<_>>();
        assert!(
            status_kinds.contains(&ObligationStatus::Discharged),
            "expected nonzero obligation to discharge when rule instance fires"
        );
        assert!(
            status_kinds.contains(&ObligationStatus::Blocked),
            "base stage should still report blocked before nonzero stratum unlocks"
        );
        assert!(
            statuses.iter().any(
                |obligation| obligation.status == ObligationStatus::Discharged
                    && obligation.eclass.is_some()
                    && obligation.timestamp.is_some()
            ),
            "discharged obligations should carry eclass and timestamp from per-rewrite trace"
        );
    }

    #[test]
    fn obligation_batches_keep_nonzero_rule_deferred_without_matching_instance() {
        let lhs = IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)).with_proof(
            ProofSlot {
                refined_type: Some(RefinedType {
                    base: Type::Num,
                    predicate: Some("v != 0".into()),
                }),
                ..ProofSlot::default()
            },
        );
        let rhs = IRNode::new(IRInstr::LoadVar("y".into()), None, Some(Type::Num));
        let div = IRNode::new(IRInstr::Div, None, Some(Type::Num));
        let block = vec![lhs.clone(), rhs, div];
        let env = ProofEnv {
            by_node: HashMap::from([(lhs.id, lhs.proof.clone())]),
            unsafe_context: false,
        };
        let saturated = run_saturation_with_proof_env(build_from_ir_block(&block), 8, 10_000, &env);

        let statuses = saturated
            .obligation_batches
            .iter()
            .flat_map(|batch| batch.obligations.iter())
            .filter(|obligation| obligation.rewrite_name == "div-self-nonzero")
            .map(|obligation| obligation.status)
            .collect::<Vec<_>>();
        assert!(
            statuses.contains(&ObligationStatus::Deferred),
            "nonzero stratum allows the rule, but no matching fire should keep obligation deferred"
        );
        assert!(
            statuses.contains(&ObligationStatus::Blocked),
            "base stage should still emit blocked before proof strata"
        );
        assert!(
            !statuses.contains(&ObligationStatus::Discharged),
            "without a real rewrite fire there should be no discharged obligation"
        );
    }

    #[test]
    fn obligation_batches_mark_mask_rule_discharged_when_rule_fires() {
        let lhs = IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)).with_proof(
            ProofSlot {
                numeric: Some(crate::vm::ir::NumericProof::from_range(0, 255)),
                ..ProofSlot::default()
            },
        );
        let rhs = IRNode::new(IRInstr::ConstNum(255.0), None, Some(Type::Num));
        let and = IRNode::new(IRInstr::And, None, Some(Type::Num));
        let block = vec![lhs.clone(), rhs, and];
        let env = ProofEnv {
            by_node: HashMap::from([(lhs.id, lhs.proof.clone())]),
            unsafe_context: false,
        };
        let saturated = run_saturation_with_proof_env(build_from_ir_block(&block), 8, 10_000, &env);

        let statuses = saturated
            .obligation_batches
            .iter()
            .flat_map(|batch| batch.obligations.iter())
            .filter(|obligation| obligation.rewrite_name == "and-mask-255-r")
            .collect::<Vec<_>>();
        let status_kinds = statuses
            .iter()
            .map(|obligation| obligation.status)
            .collect::<Vec<_>>();
        assert!(
            status_kinds.contains(&ObligationStatus::Discharged),
            "expected and-mask-255-r to discharge when its instance fires"
        );
        assert!(
            status_kinds.contains(&ObligationStatus::Blocked),
            "base stage should still report blocked before range stratum unlocks"
        );
        assert!(
            statuses.iter().any(
                |obligation| obligation.status == ObligationStatus::Discharged
                    && obligation.eclass.is_some()
                    && obligation.timestamp.is_some()
            ),
            "discharged mask obligation should carry eclass and timestamp"
        );
    }

    #[test]
    fn saturation_extracts_eclass_numeric_summary_from_div_self_rewrite() {
        let lhs = IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)).with_proof(
            ProofSlot {
                refined_type: Some(RefinedType {
                    base: Type::Num,
                    predicate: Some("v != 0".into()),
                }),
                ..ProofSlot::default()
            },
        );
        let rhs = IRNode::new(IRInstr::LoadVar("x".into()), None, Some(Type::Num)).with_proof(
            ProofSlot {
                refined_type: Some(RefinedType {
                    base: Type::Num,
                    predicate: Some("v != 0".into()),
                }),
                ..ProofSlot::default()
            },
        );
        let div = IRNode::new(IRInstr::Div, None, Some(Type::Num));
        let block = vec![lhs.clone(), rhs.clone(), div.clone()];
        let env = ProofEnv {
            by_node: HashMap::from([(lhs.id, lhs.proof.clone()), (rhs.id, rhs.proof.clone())]),
            unsafe_context: false,
        };
        let saturated = run_saturation_with_proof_env(build_from_ir_block(&block), 8, 10_000, &env);

        let summary = saturated.extract_eclass_proof_summary();
        let div_eclass = saturated.egraph.find(
            *saturated
                .node_to_eclass
                .get(&div.id)
                .expect("div node should map to eclass"),
        );
        let slot = summary
            .by_eclass
            .get(&div_eclass)
            .expect("div eclass should have summary");
        assert_eq!(slot.numeric.and_then(|n| n.exact), Some(1));
        assert!(slot.proven_nonzero());
    }
}
