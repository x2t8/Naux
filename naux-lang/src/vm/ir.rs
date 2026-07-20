// Intermediate Representation (IR) before lowering to VM bytecode.
#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::ast::Span;
use crate::typecheck::Type;

/// IR instructions (stack-based) — spec in docs/IR_SPEC.md
#[derive(Debug, Clone, PartialEq)]
pub enum IRInstr {
    ConstNum(f64),
    ConstText(String),
    ConstBool(bool),
    PushNull,
    LoadVar(String),
    StoreVar(String),
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
    Jump(usize),
    JumpIfFalse(usize),
    CallBuiltin(String, usize),
    CallFn(String, usize),
    Call(usize),
    MakeList(usize),
    MakeMap(Vec<String>),
    LoadField(String),
    EmitSay,
    EmitAsk,
    EmitFetch,
    EmitUi(String),
    EmitText,
    EmitButton,
    EmitLog,
    Pop,
    Return,
}

pub type NodeId = u32;
pub type EClassId = u32;
pub type CoqCertId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AliasingClass {
    #[default]
    Unknown,
    NoAlias,
    MustAlias,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CostBound {
    pub worst_cycles: Option<u32>,
    pub alloc_bytes: Option<u32>,
    pub mem_reads: Option<u32>,
    pub mem_writes: Option<u32>,
}

impl CostBound {
    pub fn is_empty(&self) -> bool {
        self.worst_cycles.is_none()
            && self.alloc_bytes.is_none()
            && self.mem_reads.is_none()
            && self.mem_writes.is_none()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RefinedType {
    pub base: Type,
    /// v0: predicate as string form. Later can migrate to predicate AST.
    pub predicate: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofTerm {
    NonZero,
    InRange { lo: u64, hi: u64 },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NumericProof {
    pub exact: Option<i64>,
    pub range: Option<(u64, u64)>,
    pub nonzero: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NumericProofLattice {
    #[default]
    Top,
    Facts(NumericProof),
    Bottom,
}

impl NumericProofLattice {
    pub fn from_term(term: ProofTerm) -> Self {
        match term {
            ProofTerm::NonZero => Self::Facts(NumericProof {
                nonzero: true,
                ..NumericProof::default()
            }),
            ProofTerm::InRange { lo, hi } => {
                let facts = NumericProof::from_range(lo, hi);
                if facts.normalize().is_some() {
                    Self::Facts(facts)
                } else {
                    Self::Bottom
                }
            }
        }
    }

    pub fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Top, rhs) => rhs,
            (lhs, Self::Top) => lhs,
            (Self::Facts(lhs), Self::Facts(rhs)) => lhs
                .meet_facts(rhs)
                .map(Self::Facts)
                .unwrap_or(Self::Bottom),
        }
    }

    pub fn is_bottom(self) -> bool {
        matches!(self, Self::Bottom)
    }

    pub fn into_facts(self) -> Option<NumericProof> {
        match self {
            Self::Facts(facts) => Some(facts),
            _ => None,
        }
    }
}

impl NumericProof {
    pub fn from_exact(value: i64) -> Self {
        Self {
            exact: Some(value),
            range: (value >= 0).then_some((value as u64, value as u64)),
            nonzero: value != 0,
        }
    }

    pub fn from_range(lo: u64, hi: u64) -> Self {
        Self {
            exact: (lo == hi).then_some(lo as i64),
            range: Some((lo, hi)),
            nonzero: lo > 0,
        }
    }

    fn normalize(self) -> Option<Self> {
        let mut exact = self.exact;
        let mut range = self.range;
        if let Some((lo, hi)) = range {
            if lo > hi {
                return None;
            }
        }

        if let Some(value) = exact {
            if let Some((lo, hi)) = range {
                if value < 0 {
                    return None;
                }
                let unsigned = value as u64;
                if unsigned < lo || unsigned > hi {
                    return None;
                }
            }
            if value >= 0 {
                let unsigned = value as u64;
                range = Some((unsigned, unsigned));
            }
        } else if let Some((lo, hi)) = range {
            if lo == hi {
                exact = Some(lo as i64);
            }
        }

        let mut nonzero = self.nonzero;
        if let Some(value) = exact {
            if value == 0 && nonzero {
                return None;
            }
            nonzero |= value != 0;
        }
        if let Some((lo, hi)) = range {
            if lo > 0 {
                nonzero = true;
            }
            if lo == 0 && hi == 0 && nonzero {
                return None;
            }
        }

        Some(Self {
            exact,
            range,
            nonzero,
        })
    }

    fn meet_facts(self, other: Self) -> Option<Self> {
        let lhs = self.normalize()?;
        let rhs = other.normalize()?;

        let exact = match (lhs.exact, rhs.exact) {
            (Some(a), Some(b)) if a == b => Some(a),
            (Some(_), Some(_)) => return None,
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        let range = match (lhs.range, rhs.range) {
            (Some((a_lo, a_hi)), Some((b_lo, b_hi))) => {
                let lo = a_lo.max(b_lo);
                let hi = a_hi.min(b_hi);
                if lo > hi {
                    return None;
                }
                Some((lo, hi))
            }
            (Some(r), None) => Some(r),
            (None, Some(r)) => Some(r),
            (None, None) => None,
        };

        Self {
            exact,
            range,
            nonzero: lhs.nonzero || rhs.nonzero,
        }
        .normalize()
    }

    pub fn merge(self, other: Self) -> Option<Self> {
        NumericProofLattice::Facts(self)
            .meet(NumericProofLattice::Facts(other))
            .into_facts()
    }

    pub fn evidence_score(self) -> usize {
        usize::from(self.exact.is_some())
            + usize::from(self.range.is_some())
            + usize::from(self.nonzero)
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProofSlot {
    pub refined_type: Option<RefinedType>,
    pub numeric: Option<NumericProof>,
    pub cost_bound: Option<CostBound>,
    pub coq_cert: Option<CoqCertId>,
    pub aliasing: AliasingClass,
    pub unsafe_context: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProofEnv {
    pub by_node: HashMap<NodeId, ProofSlot>,
    pub unsafe_context: bool,
}

impl ProofEnv {
    pub fn aggregate_slot(&self) -> ProofSlot {
        let mut out = ProofSlot {
            unsafe_context: self.unsafe_context,
            ..ProofSlot::default()
        };

        let mut shared_refined: Option<Option<RefinedType>> = None;
        let mut merged_numeric: Option<NumericProof> = None;
        let mut shared_coq: Option<Option<CoqCertId>> = None;
        let mut all_no_alias = !self.by_node.is_empty();
        let mut all_must_alias = !self.by_node.is_empty();

        let cost_bounds = self
            .by_node
            .values()
            .filter_map(|slot| slot.cost_bound.as_ref())
            .collect::<Vec<_>>();

        for slot in self.by_node.values() {
            out.unsafe_context |= slot.unsafe_context;

            match &shared_refined {
                None => shared_refined = Some(slot.refined_type.clone()),
                Some(current) if *current == slot.refined_type => {}
                Some(_) => shared_refined = Some(None),
            }

            merged_numeric = match (
                merged_numeric,
                slot.numeric.or_else(|| slot.numeric_fallback()),
            ) {
                (None, None) => None,
                (Some(current), Some(next)) => current.merge(next),
                (Some(current), None) => Some(current),
                (None, Some(next)) => Some(next),
            };

            match shared_coq {
                None => shared_coq = Some(slot.coq_cert),
                Some(current) if current == slot.coq_cert => {}
                Some(_) => shared_coq = Some(None),
            }

            if slot.aliasing != AliasingClass::NoAlias {
                all_no_alias = false;
            }
            if slot.aliasing != AliasingClass::MustAlias {
                all_must_alias = false;
            }
        }

        out.refined_type = shared_refined.flatten();
        out.numeric = merged_numeric;
        out.coq_cert = shared_coq.flatten();
        out.cost_bound = if cost_bounds.is_empty() {
            None
        } else {
            Some(CostBound {
                worst_cycles: sum_cost_field(cost_bounds.iter().map(|b| b.worst_cycles)),
                alloc_bytes: sum_cost_field(cost_bounds.iter().map(|b| b.alloc_bytes)),
                mem_reads: sum_cost_field(cost_bounds.iter().map(|b| b.mem_reads)),
                mem_writes: sum_cost_field(cost_bounds.iter().map(|b| b.mem_writes)),
            })
        };
        out.aliasing = if all_no_alias {
            AliasingClass::NoAlias
        } else if all_must_alias {
            AliasingClass::MustAlias
        } else {
            AliasingClass::Unknown
        };
        out
    }

    pub fn evidence_score(&self) -> usize {
        let slot_score = self
            .by_node
            .values()
            .map(ProofSlot::evidence_score)
            .sum::<usize>();
        slot_score + usize::from(self.unsafe_context)
    }

    pub fn evidence_growth(&self, previous: &ProofEnv) -> usize {
        self.evidence_score()
            .saturating_sub(previous.evidence_score())
    }
}

fn sum_cost_field(values: impl Iterator<Item = Option<u32>>) -> Option<u32> {
    let mut saw_any = false;
    let mut acc = 0_u32;
    for value in values.flatten() {
        saw_any = true;
        acc = acc.saturating_add(value);
    }
    saw_any.then_some(acc)
}

impl ProofSlot {
    pub fn is_empty(&self) -> bool {
        self.refined_type.is_none()
            && self.numeric.is_none()
            && self.cost_bound.is_none()
            && self.coq_cert.is_none()
            && self.aliasing == AliasingClass::Unknown
            && !self.unsafe_context
    }

    pub fn is_unsafe_context(&self) -> bool {
        self.unsafe_context
    }

    pub fn proven_nonzero(&self) -> bool {
        if self.numeric_nonzero() {
            return true;
        }
        let Some(pred) = self
            .refined_type
            .as_ref()
            .and_then(|r| r.predicate.as_ref())
        else {
            return false;
        };
        let p = pred.to_ascii_lowercase();
        if p.contains("nonzero") || p.contains("!=0") || p.contains("!= 0") {
            return true;
        }
        if let Some(value) = parse_exact_numeric_equality(&p) {
            return value.abs() > f64::EPSILON;
        }
        if let Some((lo, _hi)) = parse_u64_range(&p) {
            return lo > 0;
        }
        false
    }

    pub fn range_within(&self, lo: u64, hi: u64) -> bool {
        if let Some((r_lo, r_hi)) = self.numeric_range() {
            return r_lo >= lo && r_hi <= hi;
        }
        let Some(pred) = self
            .refined_type
            .as_ref()
            .and_then(|r| r.predicate.as_ref())
        else {
            return false;
        };
        let p = pred.to_ascii_lowercase();
        if let Some(value) = parse_exact_numeric_equality(&p) {
            if value.fract().abs() > f64::EPSILON || value < 0.0 {
                return false;
            }
            let exact = value as u64;
            return exact >= lo && exact <= hi;
        }
        let Some((r_lo, r_hi)) = parse_u64_range(&p) else {
            return false;
        };
        r_lo >= lo && r_hi <= hi
    }

    pub fn evidence_score(&self) -> usize {
        usize::from(self.refined_type.is_some())
            + self.numeric.map(NumericProof::evidence_score).unwrap_or(0)
            + usize::from(self.cost_bound.is_some())
            + usize::from(self.coq_cert.is_some())
            + usize::from(self.aliasing != AliasingClass::Unknown)
            + usize::from(self.unsafe_context)
    }

    pub fn numeric_nonzero(&self) -> bool {
        self.numeric
            .or_else(|| self.numeric_fallback())
            .map(|n| n.nonzero)
            .unwrap_or(false)
    }

    pub fn numeric_range(&self) -> Option<(u64, u64)> {
        self.numeric
            .or_else(|| self.numeric_fallback())
            .and_then(|n| n.range)
    }

    pub fn numeric_fallback(&self) -> Option<NumericProof> {
        let pred = self
            .refined_type
            .as_ref()
            .and_then(|r| r.predicate.as_ref())?
            .to_ascii_lowercase();
        if let Some(value) = parse_exact_numeric_equality(&pred) {
            if value.fract().abs() < f64::EPSILON {
                return Some(NumericProof::from_exact(value as i64));
            }
            return Some(NumericProof {
                exact: None,
                range: None,
                nonzero: value.abs() > f64::EPSILON,
            });
        }
        if let Some((lo, hi)) = parse_u64_range(&pred) {
            return Some(NumericProof::from_range(lo, hi));
        }
        if pred.contains("nonzero") || pred.contains("!=0") || pred.contains("!= 0") {
            return Some(NumericProof {
                exact: None,
                range: None,
                nonzero: true,
            });
        }
        None
    }
}

fn parse_u64_range(predicate: &str) -> Option<(u64, u64)> {
    // Supported v0 shapes:
    // - "range:[0,63]"
    // - "range(0,63)"
    if let Some(rest) = predicate.strip_prefix("range:[") {
        let end = rest.find(']')?;
        return parse_pair_u64(&rest[..end]);
    }
    if let Some(rest) = predicate.strip_prefix("range(") {
        let end = rest.find(')')?;
        return parse_pair_u64(&rest[..end]);
    }
    None
}

fn parse_pair_u64(s: &str) -> Option<(u64, u64)> {
    let mut parts = s.split(',');
    let lo = parts.next()?.trim().parse::<u64>().ok()?;
    let hi = parts.next()?.trim().parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((lo, hi))
}

fn parse_exact_numeric_equality(predicate: &str) -> Option<f64> {
    let value = predicate.strip_prefix("v == ")?.trim();
    value.parse::<f64>().ok()
}

#[derive(Debug, Clone, PartialEq)]
pub struct IRNode {
    pub id: NodeId,
    pub instr: IRInstr,
    /// Sea-of-Nodes-style input edges (v0 scaffold; may be empty for stack IR).
    pub inputs: Vec<NodeId>,
    pub span: Option<Span>,
    /// Loại giá trị được push (nếu có). None nếu instr không push gì.
    pub result_type: Option<Type>,
    pub proof: ProofSlot,
    pub eclass: Option<EClassId>,
}

impl IRNode {
    pub fn new(instr: IRInstr, span: Option<Span>, result_type: Option<Type>) -> Self {
        Self {
            id: next_node_id(),
            instr,
            inputs: Vec::new(),
            span,
            result_type,
            proof: ProofSlot::default(),
            eclass: None,
        }
    }

    pub fn new_with_inputs(
        instr: IRInstr,
        span: Option<Span>,
        result_type: Option<Type>,
        inputs: Vec<NodeId>,
    ) -> Self {
        Self {
            id: next_node_id(),
            instr,
            inputs,
            span,
            result_type,
            proof: ProofSlot::default(),
            eclass: None,
        }
    }

    pub fn with_proof(mut self, proof: ProofSlot) -> Self {
        self.proof = proof;
        self
    }

    pub fn set_eclass(&mut self, eclass: EClassId) {
        self.eclass = Some(eclass);
    }
}

pub type IRBlock = Vec<IRNode>;

#[derive(Debug, Clone)]
pub struct IRFunction {
    pub params: Vec<String>,
    pub code: IRBlock,
    pub return_type: Option<Type>,
}

#[derive(Debug, Clone)]
pub struct IRProgram {
    pub main: IRBlock,
    pub functions: HashMap<String, IRFunction>,
    pub main_return: Option<Type>,
}

#[derive(Debug, Clone)]
pub struct SoNNode {
    pub id: NodeId,
    pub instr: IRInstr,
    pub inputs: Vec<NodeId>,
    pub span: Option<Span>,
    pub result_type: Option<Type>,
    pub proof: ProofSlot,
    pub eclass: Option<EClassId>,
}

#[derive(Debug, Clone, Default)]
pub struct SeaOfNodesGraph {
    pub nodes: Vec<SoNNode>,
    pub by_id: HashMap<NodeId, usize>,
}

impl SeaOfNodesGraph {
    pub fn from_block(block: &IRBlock) -> Self {
        let mut graph = Self {
            nodes: Vec::with_capacity(block.len()),
            by_id: HashMap::with_capacity(block.len()),
        };
        for (idx, node) in block.iter().enumerate() {
            graph.by_id.insert(node.id, idx);
            graph.nodes.push(SoNNode {
                id: node.id,
                instr: node.instr.clone(),
                inputs: node.inputs.clone(),
                span: node.span.clone(),
                result_type: node.result_type.clone(),
                proof: node.proof.clone(),
                eclass: node.eclass,
            });
        }
        graph
    }

    pub fn node(&self, id: NodeId) -> Option<&SoNNode> {
        self.by_id.get(&id).and_then(|idx| self.nodes.get(*idx))
    }
}

/// Pretty-print IR for debugging (program-level).
pub fn pretty_print_ir(ir: &IRProgram) -> String {
    let mut out = String::new();
    writeln!(&mut out, "fn main:").ok();
    dump_block(&mut out, &ir.main);
    for (name, func) in ir.functions.iter() {
        writeln!(&mut out, "fn {}({}):", name, func.params.join(", ")).ok();
        dump_block(&mut out, &func.code);
    }
    out
}

/// Disassemble a single function to string.
pub fn disasm_function(name: &str, func: &IRFunction) -> String {
    let mut out = String::new();
    writeln!(&mut out, "fn {}({}):", name, func.params.join(", ")).ok();
    dump_block(&mut out, &func.code);
    out
}

fn dump_block(out: &mut String, block: &IRBlock) {
    for (i, node) in block.iter().enumerate() {
        let ty = node
            .result_type
            .as_ref()
            .map(|t| format!(" : {:?}", t))
            .unwrap_or_default();
        let eclass = node
            .eclass
            .map(|id| format!(" eclass={}", id))
            .unwrap_or_default();
        let proof = fmt_proof_slot(&node.proof);
        writeln!(
            out,
            "  {:04}: #{} {}{}{}{}",
            i,
            node.id,
            fmt_instr(&node.instr),
            ty,
            eclass,
            proof
        )
        .ok();
    }
}

fn fmt_proof_slot(proof: &ProofSlot) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(rt) = &proof.refined_type {
        if let Some(pred) = &rt.predicate {
            parts.push(format!("rt={:?}{{{}}}", rt.base, pred));
        } else {
            parts.push(format!("rt={:?}", rt.base));
        }
    }
    if let Some(cost) = &proof.cost_bound {
        if !cost.is_empty() {
            parts.push(format!(
                "cost(cyc={:?},alloc={:?},r={:?},w={:?})",
                cost.worst_cycles, cost.alloc_bytes, cost.mem_reads, cost.mem_writes
            ));
        }
    }
    if let Some(cert) = proof.coq_cert {
        parts.push(format!("cert={}", cert));
    }
    if proof.aliasing != AliasingClass::Unknown {
        parts.push(format!("alias={:?}", proof.aliasing));
    }
    if proof.unsafe_context {
        parts.push("unsafe".to_string());
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" [{}]", parts.join(", "))
    }
}

pub fn validate_program_proof_slots(ir: &IRProgram) -> Result<(), String> {
    validate_block_proof_slots("main", &ir.main)?;
    for (name, f) in &ir.functions {
        validate_block_proof_slots(name, &f.code)?;
    }
    Ok(())
}

pub fn validate_block_proof_slots(name: &str, block: &IRBlock) -> Result<(), String> {
    let mut ids = HashMap::with_capacity(block.len());
    for (idx, node) in block.iter().enumerate() {
        if let Some(prev) = ids.insert(node.id, idx) {
            return Err(format!(
                "IR proof validation failed in `{}`: duplicate node id {} at {} and {}",
                name, node.id, prev, idx
            ));
        }
        if node.inputs.contains(&node.id) {
            return Err(format!(
                "IR proof validation failed in `{}`: node #{} has self-edge",
                name, node.id
            ));
        }
        if let Some(rt) = &node.proof.refined_type {
            if let Some(result_ty) = &node.result_type {
                if &rt.base != result_ty && *result_ty != Type::Any {
                    return Err(format!(
                        "IR proof validation failed in `{}`: node #{} refined base {:?} mismatches result type {:?}",
                        name, node.id, rt.base, result_ty
                    ));
                }
            }
        }
        if node.proof.coq_cert.is_some()
            && node.proof.refined_type.is_none()
            && node.proof.cost_bound.is_none()
        {
            return Err(format!(
                "IR proof validation failed in `{}`: node #{} has cert but no refined/cost payload",
                name, node.id
            ));
        }
    }
    Ok(())
}

/// Human-friendly opcode text (also reused by VM disasm).
pub fn fmt_instr(i: &IRInstr) -> String {
    match i {
        IRInstr::ConstNum(n) => format!("ConstNum {}", n),
        IRInstr::ConstText(s) => format!("ConstText \"{}\"", s),
        IRInstr::ConstBool(b) => format!("ConstBool {}", b),
        IRInstr::PushNull => "PushNull".into(),
        IRInstr::LoadVar(v) => format!("LoadVar {}", v),
        IRInstr::StoreVar(v) => format!("StoreVar {}", v),
        IRInstr::Add => "Add".into(),
        IRInstr::Sub => "Sub".into(),
        IRInstr::Mul => "Mul".into(),
        IRInstr::Div => "Div".into(),
        IRInstr::Mod => "Mod".into(),
        IRInstr::Xor => "Xor".into(),
        IRInstr::Shl => "Shl".into(),
        IRInstr::Eq => "Eq".into(),
        IRInstr::Ne => "Ne".into(),
        IRInstr::Gt => "Gt".into(),
        IRInstr::Ge => "Ge".into(),
        IRInstr::Lt => "Lt".into(),
        IRInstr::Le => "Le".into(),
        IRInstr::And => "And".into(),
        IRInstr::Or => "Or".into(),
        IRInstr::Jump(t) => format!("Jump {}", t),
        IRInstr::JumpIfFalse(t) => format!("JumpIfFalse {}", t),
        IRInstr::CallBuiltin(n, a) => format!("CallBuiltin {} argc={}", n, a),
        IRInstr::CallFn(n, a) => format!("CallFn {} argc={}", n, a),
        IRInstr::Call(a) => format!("Call argc={}", a),
        IRInstr::MakeList(n) => format!("MakeList {}", n),
        IRInstr::MakeMap(keys) => format!("MakeMap [{}]", keys.join(",")),
        IRInstr::LoadField(f) => format!("LoadField {}", f),
        IRInstr::EmitSay => "EmitSay".into(),
        IRInstr::EmitAsk => "EmitAsk".into(),
        IRInstr::EmitFetch => "EmitFetch".into(),
        IRInstr::EmitUi(k) => format!("EmitUi {}", k),
        IRInstr::EmitText => "EmitText".into(),
        IRInstr::EmitButton => "EmitButton".into(),
        IRInstr::EmitLog => "EmitLog".into(),
        IRInstr::Pop => "Pop".into(),
        IRInstr::Return => "Return".into(),
    }
}

fn next_node_id() -> NodeId {
    static NEXT_NODE_ID: AtomicU32 = AtomicU32::new(1);
    NEXT_NODE_ID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proven_nonzero_accepts_exact_numeric_equality() {
        let slot = ProofSlot {
            refined_type: Some(RefinedType {
                base: Type::Num,
                predicate: Some("v == 7".into()),
            }),
            ..ProofSlot::default()
        };
        assert!(slot.proven_nonzero());
    }

    #[test]
    fn range_within_accepts_exact_numeric_equality() {
        let slot = ProofSlot {
            refined_type: Some(RefinedType {
                base: Type::Num,
                predicate: Some("v == 7".into()),
            }),
            ..ProofSlot::default()
        };
        assert!(slot.range_within(0, 63));
        assert!(!slot.range_within(8, 63));
    }

    #[test]
    fn numeric_lattice_meet_nonzero_and_range_is_consistent() {
        let nonzero = NumericProofLattice::from_term(ProofTerm::NonZero);
        let in_range = NumericProofLattice::from_term(ProofTerm::InRange { lo: 0, hi: 255 });
        let out = nonzero.meet(in_range).into_facts().expect("must stay in Facts");
        assert_eq!(out.range, Some((0, 255)));
        assert!(out.nonzero);
    }

    #[test]
    fn numeric_lattice_meet_conflicting_ranges_is_bottom() {
        let a = NumericProofLattice::from_term(ProofTerm::InRange { lo: 0, hi: 63 });
        let b = NumericProofLattice::from_term(ProofTerm::InRange { lo: 128, hi: 255 });
        assert!(a.meet(b).is_bottom());
    }

    #[test]
    fn numeric_lattice_meet_nonzero_and_zero_exact_is_bottom() {
        let nonzero = NumericProofLattice::from_term(ProofTerm::NonZero);
        let exact_zero = NumericProofLattice::Facts(NumericProof::from_exact(0));
        assert!(nonzero.meet(exact_zero).is_bottom());
    }

    #[test]
    fn numeric_lattice_invalid_inrange_term_is_bottom() {
        let bad = NumericProofLattice::from_term(ProofTerm::InRange { lo: 10, hi: 3 });
        assert!(bad.is_bottom());
    }
}
