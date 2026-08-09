//! Proof-only ADR-0061 persistent-region body bindings and frontier state
//! obligations.
//!
//! This module emits no machine bytes and imports no raw/native/process path.
//! It closes the semantic gap between tail-only allocation and future body
//! realization by replaying CFG liveness over exact typed word locations.

use super::encoding::sha256;
use super::machine_ir::MachineType;
use super::schema::SemanticHash;
use super::x64_tail_candidate_capsule::{
    verify_x64_tail_candidate_capsule, X64TailCandidateCapsule, X64TailCandidateCapsuleError,
};
use super::x64_tail_state_allocation::{
    X64TailPhysicalAllocation, X64TailPhysicalAllocationError, X64TailPhysicalLocation,
    X64TailPhysicalRegionDisposition, X64TailPhysicalRegister,
};
use super::x64_tail_state_plan::{
    X64TailEdgeDisposition, X64TailFrontierKind, X64TailImmediateWord, X64TailStatePlan,
    X64TailWordLocation, X64TailWordSource, X64TailWordType,
};
use super::x64_tail_template_realization::{
    X64TailPreservationSite, X64TailProgramTemplateKind, X64TailTemplateRealization,
    X64TailTemplateRealizationError, X64TailTemplateRegister, X64TailTemplateSitePosition,
};
use super::x64_target::{
    X64Block, X64BlockId, X64FunctionId, X64Home, X64Immediate, X64InstructionKind, X64LabelId,
    X64Operand, X64TargetArtifact, X64TargetProgram, X64Terminator,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const X64_TAIL_SITE_BINDING_SCHEMA_VERSION: (u16, u16, u16) = (1, 1, 0);
pub const X64_TAIL_SITE_BINDING_POLICY_VERSION: (u16, u16, u16) = (1, 2, 0);
pub const X64_TAIL_SITE_BINDING_MAX_REGIONS: u32 = 4_096;
pub const X64_TAIL_SITE_BINDING_MAX_SITES: u32 = 1_000_000;
pub const X64_TAIL_SITE_BINDING_MAX_BOUND_WORDS: u64 = 8_000_000;
pub const X64_TAIL_SITE_BINDING_MAX_CFG_EDGES: u32 = 2_000_000;
pub const X64_TAIL_SITE_BINDING_MAX_FIXED_POINT_ROUNDS: u32 = 4_096;
pub const X64_TAIL_SITE_BINDING_MAX_WORDS_PER_REGION: u32 = 64;
pub const X64_TAIL_SITE_BINDING_MAX_FRONTIER_ROWS: u32 = 32_000;
pub const X64_TAIL_SITE_BINDING_MAX_ANALYSIS_WORK: u64 = 16_000_000;
pub const X64_TAIL_SITE_BINDING_MAX_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;

const PROOF_DOMAIN: &[u8] = b"NAUX:x86-64:tail-site-binding-proof:v2\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailBoundRead {
    Immediate(X64TailImmediateWord),
    Location {
        logical: X64TailWordLocation,
        physical: X64TailPhysicalLocation,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailBoundDefinition {
    pub logical: X64TailWordLocation,
    pub physical: X64TailPhysicalLocation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailSiteAliasConflict {
    pub left: X64TailWordLocation,
    pub right: X64TailWordLocation,
    pub physical: X64TailPhysicalLocation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailSiteBinding {
    pub region: u32,
    pub function: X64FunctionId,
    pub block: X64BlockId,
    pub label: X64LabelId,
    pub position: X64TailTemplateSitePosition,
    pub template: X64TailProgramTemplateKind,
    pub reads: Vec<X64TailBoundRead>,
    pub definitions: Vec<X64TailBoundDefinition>,
    pub live_before: Vec<X64TailBoundDefinition>,
    pub live_after: Vec<X64TailBoundDefinition>,
    pub destructive_reuses: Vec<X64TailSiteAliasConflict>,
    pub conflicts: Vec<X64TailSiteAliasConflict>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailSiteRegionStatus {
    Ready,
    RequiresDestructiveProof,
    RefusedLiveAlias,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailSiteRegionReceipt {
    pub region: u32,
    pub status: X64TailSiteRegionStatus,
    pub site_count: u32,
    pub conflict_count: u32,
    pub destructive_reuse_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailAdapterWord {
    pub logical: X64TailWordLocation,
    pub register: X64TailPhysicalRegister,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailFrontierBindingKind {
    Entry,
    BranchThen,
    BranchElse,
    PersistentTail { edge_ordinal: u32 },
    MaterializedTail { edge_ordinal: u32 },
    RefusedTail { edge_ordinal: u32 },
    Return,
    Bounds { instruction: u32 },
    Declared { kind: X64TailFrontierKind },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailFrontierAction {
    Preserve,
    PersistentTransition,
    Hydrate,
    Flush,
    FlushThenHydrate,
    ObserveAfterFlush,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailFrontierBindingRow {
    pub ordinal: u32,
    pub kind: X64TailFrontierBindingKind,
    pub source_label: Option<X64LabelId>,
    pub target_label: Option<X64LabelId>,
    pub source_region: Option<u32>,
    pub target_region: Option<u32>,
    pub action: X64TailFrontierAction,
    pub source_live: Vec<X64TailBoundDefinition>,
    pub target_live: Vec<X64TailBoundDefinition>,
    pub flush: Vec<X64TailAdapterWord>,
    pub hydrate: Vec<X64TailAdapterWord>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X64TailSiteBindingTotals {
    pub regions: u32,
    pub ready_regions: u32,
    pub destructive_proof_regions: u32,
    pub refused_regions: u32,
    pub sites: u32,
    pub bound_reads: u64,
    pub bound_definitions: u64,
    pub live_word_rows: u64,
    pub destructive_reuses: u32,
    pub alias_conflicts: u32,
    pub cfg_edges: u32,
    pub fixed_point_rounds: u32,
    pub frontier_rows: u32,
    pub frontier_source_live_words: u64,
    pub frontier_target_live_words: u64,
    pub flush_words: u64,
    pub hydrate_words: u64,
    pub analysis_work: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailSiteBindingProof {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    source_target_semantic_hash: SemanticHash,
    source_logical_plan_hash: SemanticHash,
    source_physical_allocation_hash: SemanticHash,
    source_template_realization_hash: SemanticHash,
    source_candidate_capsule_hash: SemanticHash,
    regions: Vec<X64TailSiteRegionReceipt>,
    sites: Vec<X64TailSiteBinding>,
    frontiers: Vec<X64TailFrontierBindingRow>,
    totals: X64TailSiteBindingTotals,
    proof_hash: SemanticHash,
}

impl X64TailSiteBindingProof {
    pub const fn source_target_semantic_hash(&self) -> SemanticHash {
        self.source_target_semantic_hash
    }

    pub const fn source_logical_plan_hash(&self) -> SemanticHash {
        self.source_logical_plan_hash
    }

    pub const fn source_physical_allocation_hash(&self) -> SemanticHash {
        self.source_physical_allocation_hash
    }

    pub const fn source_template_realization_hash(&self) -> SemanticHash {
        self.source_template_realization_hash
    }

    pub const fn source_candidate_capsule_hash(&self) -> SemanticHash {
        self.source_candidate_capsule_hash
    }

    pub fn regions(&self) -> &[X64TailSiteRegionReceipt] {
        &self.regions
    }

    pub fn sites(&self) -> &[X64TailSiteBinding] {
        &self.sites
    }

    pub fn frontiers(&self) -> &[X64TailFrontierBindingRow] {
        &self.frontiers
    }

    pub const fn totals(&self) -> X64TailSiteBindingTotals {
        self.totals
    }

    pub const fn proof_hash(&self) -> SemanticHash {
        self.proof_hash
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedX64TailSiteBindingProof<'proof> {
    proof: &'proof X64TailSiteBindingProof,
}

impl<'proof> VerifiedX64TailSiteBindingProof<'proof> {
    pub const fn proof(self) -> &'proof X64TailSiteBindingProof {
        self.proof
    }
}

#[derive(Debug)]
pub enum X64TailSiteBindingError {
    Template(X64TailTemplateRealizationError),
    Capsule(X64TailCandidateCapsuleError),
    Physical(X64TailPhysicalAllocationError),
    InvalidField {
        field: &'static str,
    },
    MissingTarget {
        field: &'static str,
    },
    LimitExceeded {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    ArithmeticOverflow {
        field: &'static str,
    },
    EncodingLimit {
        actual: usize,
    },
    ProofHashMismatch,
    ReplayMismatch,
}

impl fmt::Display for X64TailSiteBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Template(error) => write!(formatter, "site binding template input failed: {error}"),
            Self::Capsule(error) => write!(formatter, "site binding capsule input failed: {error}"),
            Self::Physical(error) => write!(formatter, "site binding physical input failed: {error}"),
            Self::InvalidField { field } => write!(formatter, "site binding has invalid {field}"),
            Self::MissingTarget { field } => write!(formatter, "site binding is missing {field}"),
            Self::LimitExceeded { field, limit, actual } => {
                write!(formatter, "site binding {field} uses {actual}; limit is {limit}")
            }
            Self::ArithmeticOverflow { field } => write!(formatter, "site binding overflowed {field}"),
            Self::EncodingLimit { actual } => write!(
                formatter,
                "site binding evidence uses {actual} bytes; limit is {X64_TAIL_SITE_BINDING_MAX_EVIDENCE_BYTES}"
            ),
            Self::ProofHashMismatch => formatter.write_str("site binding proof seal does not replay"),
            Self::ReplayMismatch => formatter.write_str("site binding proof differs from canonical regeneration"),
        }
    }
}

impl std::error::Error for X64TailSiteBindingError {}

impl From<X64TailTemplateRealizationError> for X64TailSiteBindingError {
    fn from(value: X64TailTemplateRealizationError) -> Self {
        Self::Template(value)
    }
}

impl From<X64TailCandidateCapsuleError> for X64TailSiteBindingError {
    fn from(value: X64TailCandidateCapsuleError) -> Self {
        Self::Capsule(value)
    }
}

impl From<X64TailPhysicalAllocationError> for X64TailSiteBindingError {
    fn from(value: X64TailPhysicalAllocationError) -> Self {
        Self::Physical(value)
    }
}

pub fn emit_x64_tail_site_binding_proof(
    target: &X64TargetArtifact,
    logical: &X64TailStatePlan,
    physical: &X64TailPhysicalAllocation,
    realization: &X64TailTemplateRealization,
    capsule: &X64TailCandidateCapsule,
) -> Result<X64TailSiteBindingProof, X64TailSiteBindingError> {
    verify_x64_tail_candidate_capsule(capsule, realization, physical, logical, target)?;
    construct_proof(target, logical, physical, realization, capsule)
}

pub fn verify_x64_tail_site_binding_proof<'proof>(
    proof: &'proof X64TailSiteBindingProof,
    capsule: &X64TailCandidateCapsule,
    realization: &X64TailTemplateRealization,
    physical: &X64TailPhysicalAllocation,
    logical: &X64TailStatePlan,
    target: &X64TargetArtifact,
) -> Result<VerifiedX64TailSiteBindingProof<'proof>, X64TailSiteBindingError> {
    verify_x64_tail_candidate_capsule(capsule, realization, physical, logical, target)?;
    validate_envelope(proof, capsule, realization, physical, logical, target)?;
    if x64_tail_site_binding_proof_hash(proof)? != proof.proof_hash {
        return Err(X64TailSiteBindingError::ProofHashMismatch);
    }
    let replayed = construct_proof(target, logical, physical, realization, capsule)?;
    if replayed != *proof {
        return Err(X64TailSiteBindingError::ReplayMismatch);
    }
    Ok(VerifiedX64TailSiteBindingProof { proof })
}

pub fn x64_tail_site_binding_proof_hash(
    proof: &X64TailSiteBindingProof,
) -> Result<SemanticHash, X64TailSiteBindingError> {
    Ok(SemanticHash(sha256(&proof_bytes_without_seal(proof)?)))
}

#[derive(Clone, Debug, Default)]
struct BlockLiveness {
    live_in: BTreeSet<X64TailWordLocation>,
    live_out: BTreeSet<X64TailWordLocation>,
    instruction_before: Vec<BTreeSet<X64TailWordLocation>>,
    instruction_after: Vec<BTreeSet<X64TailWordLocation>>,
    terminator_before: BTreeSet<X64TailWordLocation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LogicalRead {
    Immediate(X64TailImmediateWord),
    Location(X64TailWordLocation),
}

fn construct_proof(
    target: &X64TargetArtifact,
    logical: &X64TailStatePlan,
    physical: &X64TailPhysicalAllocation,
    realization: &X64TailTemplateRealization,
    capsule: &X64TailCandidateCapsule,
) -> Result<X64TailSiteBindingProof, X64TailSiteBindingError> {
    let mut work = 0_u64;
    let (liveness, fixed_point_rounds, cfg_edges) = derive_liveness(&target.program, &mut work)?;
    let region_maps = derive_region_maps(physical)?;
    let label_regions = derive_label_regions(logical, physical)?;

    let mut sites = Vec::with_capacity(realization.sites().len());
    let mut conflicts_by_region = BTreeMap::<u32, u32>::new();
    let mut destructive_by_region = BTreeMap::<u32, u32>::new();
    for source_site in realization.sites() {
        charge(&mut work, 1, "site binding")?;
        let region_map =
            region_maps
                .get(&source_site.region)
                .ok_or(X64TailSiteBindingError::MissingTarget {
                    field: "site region allocation",
                })?;
        let block = find_block(&target.program, source_site.function, source_site.block)?;
        let block_liveness = liveness
            .get(&(source_site.function, source_site.block))
            .ok_or(X64TailSiteBindingError::MissingTarget {
                field: "site block liveness",
            })?;
        let (logical_reads, logical_definitions, live_before, live_after) =
            site_logical_state(source_site, block, block_liveness)?;
        let reads = logical_reads
            .iter()
            .copied()
            .map(|read| bind_read(read, region_map))
            .collect::<Result<Vec<_>, _>>()?;
        let definitions = bind_set(&logical_definitions, region_map)?;
        let live_before_bound = bind_set(&live_before, region_map)?;
        let live_after_bound = bind_set(&live_after, region_map)?;
        validate_live_clobbers(source_site, &live_before_bound, &live_after_bound)?;
        let mut conflicts = injection_conflicts(&live_before_bound);
        conflicts.extend(injection_conflicts(&live_after_bound));
        let definition_conflicts = definition_conflicts(&definitions, &live_after_bound);
        conflicts.extend(definition_conflicts);
        conflicts.sort_by_key(|conflict| (conflict.left, conflict.right, conflict.physical));
        conflicts.dedup();
        let destructive_reuses = destructive_reuses(&reads, &definitions, &live_after);
        let conflict_count = usize_to_u32(conflicts.len(), "site conflicts")?;
        let destructive_count = usize_to_u32(destructive_reuses.len(), "site destructive reuses")?;
        add_u32_map(
            &mut conflicts_by_region,
            source_site.region,
            conflict_count,
            "region conflicts",
        )?;
        add_u32_map(
            &mut destructive_by_region,
            source_site.region,
            destructive_count,
            "region destructive reuses",
        )?;
        sites.push(X64TailSiteBinding {
            region: source_site.region,
            function: source_site.function,
            block: source_site.block,
            label: source_site.label,
            position: source_site.position,
            template: source_site.template,
            reads,
            definitions,
            live_before: live_before_bound,
            live_after: live_after_bound,
            destructive_reuses,
            conflicts,
        });
    }
    ensure_limit("sites", X64_TAIL_SITE_BINDING_MAX_SITES, sites.len())?;

    let mut regions = Vec::with_capacity(region_maps.len());
    for region in physical
        .regions()
        .iter()
        .filter(|region| region.disposition == X64TailPhysicalRegionDisposition::Allocated)
    {
        let site_count = usize_to_u32(
            sites
                .iter()
                .filter(|site| site.region == region.region)
                .count(),
            "region site count",
        )?;
        let conflict_count = conflicts_by_region
            .get(&region.region)
            .copied()
            .unwrap_or(0);
        let destructive_reuse_count = destructive_by_region
            .get(&region.region)
            .copied()
            .unwrap_or(0);
        let status = if conflict_count != 0 {
            X64TailSiteRegionStatus::RefusedLiveAlias
        } else if destructive_reuse_count != 0 {
            X64TailSiteRegionStatus::RequiresDestructiveProof
        } else {
            X64TailSiteRegionStatus::Ready
        };
        regions.push(X64TailSiteRegionReceipt {
            region: region.region,
            status,
            site_count,
            conflict_count,
            destructive_reuse_count,
        });
    }
    ensure_limit("regions", X64_TAIL_SITE_BINDING_MAX_REGIONS, regions.len())?;
    let frontiers = derive_frontiers(
        &target.program,
        logical,
        capsule,
        &label_regions,
        &region_maps,
        &liveness,
        &mut work,
    )?;
    ensure_limit(
        "frontier rows",
        X64_TAIL_SITE_BINDING_MAX_FRONTIER_ROWS,
        frontiers.len(),
    )?;
    let totals = compute_totals(
        &regions,
        &sites,
        &frontiers,
        cfg_edges,
        fixed_point_rounds,
        work,
    )?;
    let mut proof = X64TailSiteBindingProof {
        schema_version: X64_TAIL_SITE_BINDING_SCHEMA_VERSION,
        policy_version: X64_TAIL_SITE_BINDING_POLICY_VERSION,
        source_target_semantic_hash: target.semantic_hash,
        source_logical_plan_hash: logical.plan_hash(),
        source_physical_allocation_hash: physical.allocation_hash(),
        source_template_realization_hash: realization.realization_hash(),
        source_candidate_capsule_hash: capsule.capsule_hash(),
        regions,
        sites,
        frontiers,
        totals,
        proof_hash: SemanticHash::ZERO,
    };
    proof.proof_hash = x64_tail_site_binding_proof_hash(&proof)?;
    Ok(proof)
}

type BlockKey = (X64FunctionId, X64BlockId);
type SiteLogicalState = (
    Vec<LogicalRead>,
    Vec<X64TailWordLocation>,
    BTreeSet<X64TailWordLocation>,
    BTreeSet<X64TailWordLocation>,
);

fn derive_liveness(
    program: &X64TargetProgram,
    work: &mut u64,
) -> Result<(BTreeMap<BlockKey, BlockLiveness>, u32, u32), X64TailSiteBindingError> {
    let mut label_blocks = BTreeMap::new();
    let mut blocks = BTreeMap::new();
    for function in &program.functions {
        for block in &function.blocks {
            if label_blocks
                .insert(block.label, (function.id, block.id))
                .is_some()
                || blocks.insert((function.id, block.id), block).is_some()
            {
                return Err(X64TailSiteBindingError::InvalidField {
                    field: "unique CFG block identity",
                });
            }
        }
    }
    let mut successors = BTreeMap::<BlockKey, Vec<BlockKey>>::new();
    let mut cfg_edges = 0_u32;
    for (key, block) in &blocks {
        let rows = match &block.terminator {
            X64Terminator::BranchRel32 {
                then_label,
                else_label,
                ..
            } => {
                cfg_edges = checked_add_u32(cfg_edges, 2, "CFG edges")?;
                vec![
                    *label_blocks.get(then_label).ok_or(
                        X64TailSiteBindingError::MissingTarget {
                            field: "branch then block",
                        },
                    )?,
                    *label_blocks.get(else_label).ok_or(
                        X64TailSiteBindingError::MissingTarget {
                            field: "branch else block",
                        },
                    )?,
                ]
            }
            X64Terminator::TailJumpRel32 { .. } => {
                cfg_edges = checked_add_u32(cfg_edges, 1, "CFG edges")?;
                Vec::new()
            }
            X64Terminator::Return { .. } => Vec::new(),
        };
        successors.insert(*key, rows);
    }
    if cfg_edges > X64_TAIL_SITE_BINDING_MAX_CFG_EDGES {
        return Err(X64TailSiteBindingError::LimitExceeded {
            field: "CFG edges",
            limit: u64::from(X64_TAIL_SITE_BINDING_MAX_CFG_EDGES),
            actual: u64::from(cfg_edges),
        });
    }

    let mut summaries =
        BTreeMap::<BlockKey, (BTreeSet<X64TailWordLocation>, BTreeSet<X64TailWordLocation>)>::new();
    for (key, block) in &blocks {
        summaries.insert(*key, block_use_def(block)?);
    }
    let mut liveness = blocks
        .keys()
        .copied()
        .map(|key| (key, BlockLiveness::default()))
        .collect::<BTreeMap<_, _>>();
    let block_order = blocks.keys().copied().rev().collect::<Vec<_>>();
    let mut rounds = 0_u32;
    loop {
        rounds = checked_add_u32(rounds, 1, "liveness rounds")?;
        if rounds > X64_TAIL_SITE_BINDING_MAX_FIXED_POINT_ROUNDS {
            return Err(X64TailSiteBindingError::LimitExceeded {
                field: "liveness rounds",
                limit: u64::from(X64_TAIL_SITE_BINDING_MAX_FIXED_POINT_ROUNDS),
                actual: u64::from(rounds),
            });
        }
        let mut changed = false;
        for key in &block_order {
            charge(work, 1, "liveness block")?;
            let mut live_out = BTreeSet::new();
            for successor in successors.get(key).into_iter().flatten() {
                let successor_live = &liveness
                    .get(successor)
                    .ok_or(X64TailSiteBindingError::MissingTarget {
                        field: "successor liveness",
                    })?
                    .live_in;
                charge(
                    work,
                    usize_to_u64(successor_live.len(), "successor live words")?,
                    "successor live union",
                )?;
                live_out.extend(successor_live.iter().copied());
            }
            let (uses, definitions) =
                summaries
                    .get(key)
                    .ok_or(X64TailSiteBindingError::MissingTarget {
                        field: "block use/definition summary",
                    })?;
            let mut live_in = live_out
                .difference(definitions)
                .copied()
                .collect::<BTreeSet<_>>();
            live_in.extend(uses.iter().copied());
            let row = liveness
                .get_mut(key)
                .ok_or(X64TailSiteBindingError::MissingTarget {
                    field: "mutable block liveness",
                })?;
            if row.live_in != live_in || row.live_out != live_out {
                row.live_in = live_in;
                row.live_out = live_out;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    for (key, block) in blocks {
        let row = liveness
            .get_mut(&key)
            .ok_or(X64TailSiteBindingError::MissingTarget {
                field: "detailed block liveness",
            })?;
        let mut live = row.live_out.clone();
        for read in terminator_reads(&block.terminator)? {
            if let LogicalRead::Location(location) = read {
                live.insert(location);
            }
        }
        row.terminator_before = live.clone();
        let mut before = vec![BTreeSet::new(); block.instructions.len()];
        let mut after = vec![BTreeSet::new(); block.instructions.len()];
        for index in (0..block.instructions.len()).rev() {
            charge(work, 1, "instruction liveness")?;
            after[index] = live.clone();
            for definition in home_words(block.instructions[index].result)? {
                live.remove(&definition);
            }
            for read in instruction_reads(&block.instructions[index].kind)? {
                if let LogicalRead::Location(location) = read {
                    live.insert(location);
                }
            }
            before[index] = live.clone();
        }
        if live != row.live_in {
            return Err(X64TailSiteBindingError::InvalidField {
                field: "detailed liveness fixed point",
            });
        }
        row.instruction_before = before;
        row.instruction_after = after;
    }
    Ok((liveness, rounds, cfg_edges))
}

fn block_use_def(
    block: &X64Block,
) -> Result<(BTreeSet<X64TailWordLocation>, BTreeSet<X64TailWordLocation>), X64TailSiteBindingError>
{
    let mut uses = BTreeSet::new();
    let mut definitions = BTreeSet::new();
    for instruction in &block.instructions {
        for read in instruction_reads(&instruction.kind)? {
            if let LogicalRead::Location(location) = read {
                if !definitions.contains(&location) {
                    uses.insert(location);
                }
            }
        }
        definitions.extend(home_words(instruction.result)?);
    }
    for read in terminator_reads(&block.terminator)? {
        if let LogicalRead::Location(location) = read {
            if !definitions.contains(&location) {
                uses.insert(location);
            }
        }
    }
    Ok((uses, definitions))
}

fn instruction_reads(
    instruction: &X64InstructionKind,
) -> Result<Vec<LogicalRead>, X64TailSiteBindingError> {
    let operands: [Option<&X64Operand>; 2] = match instruction {
        X64InstructionKind::Move(value) | X64InstructionKind::ArrayLenF64 { array: value } => {
            [Some(value), None]
        }
        X64InstructionKind::I64Wrapping { left, right, .. }
        | X64InstructionKind::Sse2F64 { left, right, .. }
        | X64InstructionKind::I64Setcc { left, right, .. }
        | X64InstructionKind::ArrayGetF64Checked {
            array: left,
            index: right,
        } => [Some(left), Some(right)],
    };
    operands
        .into_iter()
        .flatten()
        .try_fold(Vec::new(), |mut reads, operand| {
            reads.extend(operand_reads(operand)?);
            Ok(reads)
        })
}

fn terminator_reads(
    terminator: &X64Terminator,
) -> Result<Vec<LogicalRead>, X64TailSiteBindingError> {
    match terminator {
        X64Terminator::Return { value, .. }
        | X64Terminator::BranchRel32 {
            condition: value, ..
        } => operand_reads(value),
        X64Terminator::TailJumpRel32 { arguments, .. } => {
            arguments
                .iter()
                .try_fold(Vec::new(), |mut reads, argument| {
                    reads.extend(operand_reads(argument)?);
                    Ok(reads)
                })
        }
    }
}

fn operand_reads(operand: &X64Operand) -> Result<Vec<LogicalRead>, X64TailSiteBindingError> {
    match operand {
        X64Operand::Home(home) => Ok(home_words(*home)?
            .into_iter()
            .map(LogicalRead::Location)
            .collect()),
        X64Operand::Immediate { ty, value } => match (ty, value) {
            (MachineType::Unit, X64Immediate::Unit) => Ok(Vec::new()),
            (MachineType::Bool, X64Immediate::Bool(value)) => Ok(vec![LogicalRead::Immediate(
                X64TailImmediateWord::Bool(*value),
            )]),
            (MachineType::I64, X64Immediate::I64(value)) => Ok(vec![LogicalRead::Immediate(
                X64TailImmediateWord::I64(*value),
            )]),
            (MachineType::F64, X64Immediate::F64Bits(bits)) => Ok(vec![LogicalRead::Immediate(
                X64TailImmediateWord::F64Bits(*bits),
            )]),
            _ => Err(X64TailSiteBindingError::InvalidField {
                field: "typed immediate operand",
            }),
        },
    }
}

fn home_words(home: X64Home) -> Result<Vec<X64TailWordLocation>, X64TailSiteBindingError> {
    let types: &[X64TailWordType] = match home.ty {
        MachineType::Unit => &[],
        MachineType::Bool => &[X64TailWordType::Bool],
        MachineType::I64 => &[X64TailWordType::I64],
        MachineType::F64 => &[X64TailWordType::F64],
        MachineType::F64Array => &[X64TailWordType::ArrayData, X64TailWordType::ArrayLength],
    };
    // Canonical home layout reserves one deterministic zeroed word for Unit,
    // while Unit contributes no liveness or persistent-state word.
    let expected_width = if home.ty == MachineType::Unit {
        8
    } else {
        u8::try_from(types.len().checked_mul(8).ok_or(
            X64TailSiteBindingError::ArithmeticOverflow {
                field: "home word width",
            },
        )?)
        .map_err(|_| X64TailSiteBindingError::ArithmeticOverflow {
            field: "home word width",
        })?
    };
    if home.width != expected_width {
        return Err(X64TailSiteBindingError::InvalidField {
            field: "canonical home word width",
        });
    }
    types
        .iter()
        .enumerate()
        .map(|(index, word_type)| {
            let delta = u32::try_from(index)
                .ok()
                .and_then(|value| value.checked_mul(8))
                .ok_or(X64TailSiteBindingError::ArithmeticOverflow {
                    field: "home word offset",
                })?;
            Ok(X64TailWordLocation {
                offset: home.offset.checked_add(delta).ok_or(
                    X64TailSiteBindingError::ArithmeticOverflow {
                        field: "home word offset",
                    },
                )?,
                word_type: *word_type,
            })
        })
        .collect()
}

fn derive_region_maps(
    physical: &X64TailPhysicalAllocation,
) -> Result<
    BTreeMap<u32, BTreeMap<X64TailWordLocation, X64TailPhysicalLocation>>,
    X64TailSiteBindingError,
> {
    let mut maps = BTreeMap::new();
    for region in physical
        .regions()
        .iter()
        .filter(|region| region.disposition == X64TailPhysicalRegionDisposition::Allocated)
    {
        ensure_limit(
            "words per region",
            X64_TAIL_SITE_BINDING_MAX_WORDS_PER_REGION,
            region.values.len(),
        )?;
        let mut values = BTreeMap::new();
        for value in &region.values {
            if value.logical.word_type != value.physical.word_type()
                || values.insert(value.logical, value.physical).is_some()
            {
                return Err(X64TailSiteBindingError::InvalidField {
                    field: "typed unique region physical map",
                });
            }
        }
        if maps.insert(region.region, values).is_some() {
            return Err(X64TailSiteBindingError::InvalidField {
                field: "unique physical region",
            });
        }
    }
    Ok(maps)
}

fn derive_label_regions(
    logical: &X64TailStatePlan,
    physical: &X64TailPhysicalAllocation,
) -> Result<BTreeMap<X64LabelId, u32>, X64TailSiteBindingError> {
    let allocated = physical
        .regions()
        .iter()
        .filter_map(|region| {
            (region.disposition == X64TailPhysicalRegionDisposition::Allocated)
                .then_some(region.region)
        })
        .collect::<BTreeSet<_>>();
    let mut labels = BTreeMap::new();
    for region in logical
        .regions()
        .iter()
        .filter(|region| allocated.contains(&region.id))
    {
        for label in &region.labels {
            if labels.insert(*label, region.id).is_some() {
                return Err(X64TailSiteBindingError::InvalidField {
                    field: "unique region label ownership",
                });
            }
        }
    }
    Ok(labels)
}

fn site_logical_state(
    site: &X64TailPreservationSite,
    block: &X64Block,
    liveness: &BlockLiveness,
) -> Result<SiteLogicalState, X64TailSiteBindingError> {
    match site.position {
        X64TailTemplateSitePosition::Instruction(index) => {
            let index = usize::try_from(index).map_err(|_| {
                X64TailSiteBindingError::ArithmeticOverflow {
                    field: "instruction site index",
                }
            })?;
            let instruction =
                block
                    .instructions
                    .get(index)
                    .ok_or(X64TailSiteBindingError::MissingTarget {
                        field: "instruction site",
                    })?;
            Ok((
                instruction_reads(&instruction.kind)?,
                home_words(instruction.result)?,
                liveness.instruction_before.get(index).cloned().ok_or(
                    X64TailSiteBindingError::MissingTarget {
                        field: "instruction live-before",
                    },
                )?,
                liveness.instruction_after.get(index).cloned().ok_or(
                    X64TailSiteBindingError::MissingTarget {
                        field: "instruction live-after",
                    },
                )?,
            ))
        }
        X64TailTemplateSitePosition::BranchCondition => {
            if !matches!(block.terminator, X64Terminator::BranchRel32 { .. }) {
                return Err(X64TailSiteBindingError::InvalidField {
                    field: "branch-condition site",
                });
            }
            Ok((
                terminator_reads(&block.terminator)?,
                Vec::new(),
                liveness.terminator_before.clone(),
                liveness.live_out.clone(),
            ))
        }
        X64TailTemplateSitePosition::BranchElse => {
            if !matches!(block.terminator, X64Terminator::BranchRel32 { .. }) {
                return Err(X64TailSiteBindingError::InvalidField {
                    field: "branch-else site",
                });
            }
            Ok((
                Vec::new(),
                Vec::new(),
                liveness.live_out.clone(),
                liveness.live_out.clone(),
            ))
        }
        X64TailTemplateSitePosition::TailTransition { .. }
        | X64TailTemplateSitePosition::TailFrontier { .. } => {
            if !matches!(block.terminator, X64Terminator::TailJumpRel32 { .. }) {
                return Err(X64TailSiteBindingError::InvalidField { field: "tail site" });
            }
            Ok((
                terminator_reads(&block.terminator)?,
                Vec::new(),
                liveness.terminator_before.clone(),
                BTreeSet::new(),
            ))
        }
    }
}

fn bind_read(
    read: LogicalRead,
    region: &BTreeMap<X64TailWordLocation, X64TailPhysicalLocation>,
) -> Result<X64TailBoundRead, X64TailSiteBindingError> {
    Ok(match read {
        LogicalRead::Immediate(immediate) => X64TailBoundRead::Immediate(immediate),
        LogicalRead::Location(logical) => X64TailBoundRead::Location {
            logical,
            physical: bind_location(logical, region)?,
        },
    })
}

fn bind_set<'a>(
    logical: impl IntoIterator<Item = &'a X64TailWordLocation>,
    region: &BTreeMap<X64TailWordLocation, X64TailPhysicalLocation>,
) -> Result<Vec<X64TailBoundDefinition>, X64TailSiteBindingError> {
    logical
        .into_iter()
        .copied()
        .map(|logical| {
            Ok(X64TailBoundDefinition {
                logical,
                physical: bind_location(logical, region)?,
            })
        })
        .collect()
}

fn bind_location(
    logical: X64TailWordLocation,
    region: &BTreeMap<X64TailWordLocation, X64TailPhysicalLocation>,
) -> Result<X64TailPhysicalLocation, X64TailSiteBindingError> {
    let physical = region
        .get(&logical)
        .copied()
        .unwrap_or(X64TailPhysicalLocation::Frame(logical));
    if physical.word_type() != logical.word_type {
        return Err(X64TailSiteBindingError::InvalidField {
            field: "bound physical word type",
        });
    }
    Ok(physical)
}

fn injection_conflicts(bound: &[X64TailBoundDefinition]) -> Vec<X64TailSiteAliasConflict> {
    let mut conflicts = Vec::new();
    for left in 0..bound.len() {
        for right in left.saturating_add(1)..bound.len() {
            if bound[left].logical != bound[right].logical
                && bound[left].physical == bound[right].physical
            {
                conflicts.push(X64TailSiteAliasConflict {
                    left: bound[left].logical.min(bound[right].logical),
                    right: bound[left].logical.max(bound[right].logical),
                    physical: bound[left].physical,
                });
            }
        }
    }
    conflicts
}

fn definition_conflicts(
    definitions: &[X64TailBoundDefinition],
    live_after: &[X64TailBoundDefinition],
) -> Vec<X64TailSiteAliasConflict> {
    let mut conflicts = Vec::new();
    for definition in definitions {
        for live in live_after {
            if definition.logical != live.logical && definition.physical == live.physical {
                conflicts.push(X64TailSiteAliasConflict {
                    left: definition.logical.min(live.logical),
                    right: definition.logical.max(live.logical),
                    physical: definition.physical,
                });
            }
        }
    }
    conflicts
}

fn destructive_reuses(
    reads: &[X64TailBoundRead],
    definitions: &[X64TailBoundDefinition],
    live_after: &BTreeSet<X64TailWordLocation>,
) -> Vec<X64TailSiteAliasConflict> {
    let mut reuses = Vec::new();
    for definition in definitions {
        for read in reads {
            let X64TailBoundRead::Location { logical, physical } = *read else {
                continue;
            };
            if logical != definition.logical
                && physical == definition.physical
                && !live_after.contains(&logical)
            {
                reuses.push(X64TailSiteAliasConflict {
                    left: logical.min(definition.logical),
                    right: logical.max(definition.logical),
                    physical,
                });
            }
        }
    }
    reuses.sort_by_key(|reuse| (reuse.left, reuse.right, reuse.physical));
    reuses.dedup();
    reuses
}

fn add_u32_map(
    map: &mut BTreeMap<u32, u32>,
    key: u32,
    amount: u32,
    field: &'static str,
) -> Result<(), X64TailSiteBindingError> {
    let value = map.get(&key).copied().unwrap_or(0);
    map.insert(key, checked_add_u32(value, amount, field)?);
    Ok(())
}

fn derive_frontiers(
    program: &X64TargetProgram,
    logical: &X64TailStatePlan,
    capsule: &X64TailCandidateCapsule,
    label_regions: &BTreeMap<X64LabelId, u32>,
    region_maps: &BTreeMap<u32, BTreeMap<X64TailWordLocation, X64TailPhysicalLocation>>,
    liveness: &BTreeMap<BlockKey, BlockLiveness>,
    work: &mut u64,
) -> Result<Vec<X64TailFrontierBindingRow>, X64TailSiteBindingError> {
    let capsule_edges = capsule
        .transition_receipts()
        .iter()
        .map(|receipt| receipt.edge_ordinal)
        .collect::<BTreeSet<_>>();
    if capsule_edges.len() != capsule.transition_receipts().len() {
        return Err(X64TailSiteBindingError::InvalidField {
            field: "unique capsule transition edges",
        });
    }
    let mut rows = Vec::new();

    let entry_function = program
        .functions
        .iter()
        .find(|function| function.id == program.entry)
        .ok_or(X64TailSiteBindingError::MissingTarget {
            field: "entry function",
        })?;
    let entry_block = entry_function
        .blocks
        .iter()
        .find(|block| block.id == entry_function.entry_block)
        .ok_or(X64TailSiteBindingError::MissingTarget {
            field: "entry block",
        })?;
    if let Some(target_region) = label_regions.get(&entry_block.label).copied() {
        let target_words = live_for_label(program, liveness, entry_block.label)?
            .live_in
            .clone();
        let target_live = bind_frontier_live(&target_words, Some(target_region), region_maps)?;
        push_frontier(
            &mut rows,
            X64TailFrontierBindingKind::Entry,
            None,
            Some(entry_block.label),
            None,
            Some(target_region),
            X64TailFrontierAction::Hydrate,
            Vec::new(),
            target_live.clone(),
            Vec::new(),
            adapters_from_live(&target_live)?,
        )?;
    }

    for function in &program.functions {
        for block in &function.blocks {
            charge(work, 1, "frontier CFG site")?;
            let source_region = label_regions.get(&block.label).copied();
            match &block.terminator {
                X64Terminator::BranchRel32 {
                    then_label,
                    else_label,
                    ..
                } => {
                    for (kind, target) in [
                        (X64TailFrontierBindingKind::BranchThen, *then_label),
                        (X64TailFrontierBindingKind::BranchElse, *else_label),
                    ] {
                        let target_region = label_regions.get(&target).copied();
                        if source_region.is_none() && target_region.is_none() {
                            continue;
                        }
                        let edge_words = live_for_label(program, liveness, target)?.live_in.clone();
                        let source_live =
                            bind_frontier_live(&edge_words, source_region, region_maps)?;
                        let target_live =
                            bind_frontier_live(&edge_words, target_region, region_maps)?;
                        let (action, flush, hydrate) = edge_adapter(
                            source_region,
                            target_region,
                            false,
                            &source_live,
                            &target_live,
                        )?;
                        push_frontier(
                            &mut rows,
                            kind,
                            Some(block.label),
                            Some(target),
                            source_region,
                            target_region,
                            action,
                            source_live,
                            target_live,
                            flush,
                            hydrate,
                        )?;
                    }
                }
                X64Terminator::Return { .. } => {
                    let source_words = liveness
                        .get(&(function.id, block.id))
                        .ok_or(X64TailSiteBindingError::MissingTarget {
                            field: "return block liveness",
                        })?
                        .terminator_before
                        .clone();
                    let source_live =
                        bind_frontier_live(&source_words, source_region, region_maps)?;
                    let flush = if source_region.is_some() {
                        adapters_from_live(&source_live)?
                    } else {
                        Vec::new()
                    };
                    // A Return row is a control-completeness bridge as well as
                    // a persistent-state adapter. Even a block outside every
                    // persistent region must jump to the sovereign return
                    // epilogue instead of falling through into the next laid
                    // out program.
                    push_frontier(
                        &mut rows,
                        X64TailFrontierBindingKind::Return,
                        Some(block.label),
                        None,
                        source_region,
                        None,
                        X64TailFrontierAction::ObserveAfterFlush,
                        source_live,
                        Vec::new(),
                        flush,
                        Vec::new(),
                    )?;
                }
                X64Terminator::TailJumpRel32 { .. } => {}
            }
            if let Some(region) = source_region {
                for (index, instruction) in block.instructions.iter().enumerate() {
                    if matches!(
                        instruction.kind,
                        X64InstructionKind::ArrayGetF64Checked { .. }
                    ) {
                        let source_words = liveness
                            .get(&(function.id, block.id))
                            .and_then(|row| row.instruction_before.get(index))
                            .cloned()
                            .ok_or(X64TailSiteBindingError::MissingTarget {
                                field: "Bounds instruction liveness",
                            })?;
                        let source_live =
                            bind_frontier_live(&source_words, Some(region), region_maps)?;
                        push_frontier(
                            &mut rows,
                            X64TailFrontierBindingKind::Bounds {
                                instruction: usize_to_u32(index, "Bounds instruction")?,
                            },
                            Some(block.label),
                            None,
                            Some(region),
                            None,
                            X64TailFrontierAction::ObserveAfterFlush,
                            source_live.clone(),
                            Vec::new(),
                            adapters_from_live(&source_live)?,
                            Vec::new(),
                        )?;
                    }
                }
            }
        }
    }

    for edge in logical.edges() {
        let source_region = label_regions.get(&edge.source_label).copied();
        let target_region = label_regions.get(&edge.target_label).copied();
        let source_words = edge
            .assignments
            .iter()
            .filter_map(|assignment| match assignment.source {
                X64TailWordSource::Location(location) => Some(location),
                X64TailWordSource::Immediate(_) => None,
            })
            .collect::<BTreeSet<_>>();
        let target_words = edge
            .assignments
            .iter()
            .map(|assignment| assignment.destination)
            .collect::<BTreeSet<_>>();
        let source_live = bind_frontier_live(&source_words, source_region, region_maps)?;
        let target_live = bind_frontier_live(&target_words, target_region, region_maps)?;
        match &edge.disposition {
            X64TailEdgeDisposition::Persistent { region } => {
                if source_region != Some(*region)
                    || target_region != Some(*region)
                    || !capsule_edges.contains(&edge.ordinal)
                {
                    return Err(X64TailSiteBindingError::InvalidField {
                        field: "persistent frontier/capsule binding",
                    });
                }
                push_frontier(
                    &mut rows,
                    X64TailFrontierBindingKind::PersistentTail {
                        edge_ordinal: edge.ordinal,
                    },
                    Some(edge.source_label),
                    Some(edge.target_label),
                    source_region,
                    target_region,
                    X64TailFrontierAction::PersistentTransition,
                    source_live,
                    target_live,
                    Vec::new(),
                    Vec::new(),
                )?;
            }
            X64TailEdgeDisposition::Materialize { .. } => {
                if source_region.is_none() && target_region.is_none() {
                    continue;
                }
                let (action, flush, hydrate) = edge_adapter(
                    source_region,
                    target_region,
                    true,
                    &source_live,
                    &target_live,
                )?;
                push_frontier(
                    &mut rows,
                    X64TailFrontierBindingKind::MaterializedTail {
                        edge_ordinal: edge.ordinal,
                    },
                    Some(edge.source_label),
                    Some(edge.target_label),
                    source_region,
                    target_region,
                    action,
                    source_live,
                    target_live,
                    flush,
                    hydrate,
                )?;
            }
            X64TailEdgeDisposition::Refused { .. } => {
                if source_region.is_none() && target_region.is_none() {
                    continue;
                }
                let (action, flush, hydrate) = edge_adapter(
                    source_region,
                    target_region,
                    true,
                    &source_live,
                    &target_live,
                )?;
                push_frontier(
                    &mut rows,
                    X64TailFrontierBindingKind::RefusedTail {
                        edge_ordinal: edge.ordinal,
                    },
                    Some(edge.source_label),
                    Some(edge.target_label),
                    source_region,
                    target_region,
                    action,
                    source_live,
                    target_live,
                    flush,
                    hydrate,
                )?;
            }
        }
    }

    Ok(rows)
}

fn live_for_label<'a>(
    program: &X64TargetProgram,
    liveness: &'a BTreeMap<BlockKey, BlockLiveness>,
    label: X64LabelId,
) -> Result<&'a BlockLiveness, X64TailSiteBindingError> {
    let key = program
        .functions
        .iter()
        .flat_map(|function| {
            function
                .blocks
                .iter()
                .map(move |block| (function.id, block))
        })
        .find_map(|(function, block)| (block.label == label).then_some((function, block.id)))
        .ok_or(X64TailSiteBindingError::MissingTarget {
            field: "frontier target label",
        })?;
    liveness
        .get(&key)
        .ok_or(X64TailSiteBindingError::MissingTarget {
            field: "frontier target liveness",
        })
}

fn bind_frontier_live(
    live: &BTreeSet<X64TailWordLocation>,
    region: Option<u32>,
    regions: &BTreeMap<u32, BTreeMap<X64TailWordLocation, X64TailPhysicalLocation>>,
) -> Result<Vec<X64TailBoundDefinition>, X64TailSiteBindingError> {
    let empty = BTreeMap::new();
    let map = region
        .map(|region| {
            regions
                .get(&region)
                .ok_or(X64TailSiteBindingError::MissingTarget {
                    field: "frontier region physical map",
                })
        })
        .transpose()?
        .unwrap_or(&empty);
    let bound = bind_set(live, map)?;
    if !injection_conflicts(&bound).is_empty() {
        return Err(X64TailSiteBindingError::InvalidField {
            field: "frontier live physical injectivity",
        });
    }
    ensure_limit(
        "frontier live words",
        X64_TAIL_SITE_BINDING_MAX_WORDS_PER_REGION,
        bound.len(),
    )?;
    Ok(bound)
}

fn adapters_from_live(
    live: &[X64TailBoundDefinition],
) -> Result<Vec<X64TailAdapterWord>, X64TailSiteBindingError> {
    let mut words = live
        .iter()
        .filter_map(|value| match value.physical {
            X64TailPhysicalLocation::Register {
                register,
                word_type,
            } if word_type == value.logical.word_type => Some(Ok(X64TailAdapterWord {
                logical: value.logical,
                register,
            })),
            X64TailPhysicalLocation::Register { .. } => {
                Some(Err(X64TailSiteBindingError::InvalidField {
                    field: "adapter word type",
                }))
            }
            X64TailPhysicalLocation::Frame(_) => None,
        })
        .collect::<Result<Vec<_>, _>>()?;
    words.sort_by_key(|word| word.logical);
    if words
        .windows(2)
        .any(|pair| pair[0].logical == pair[1].logical)
    {
        return Err(X64TailSiteBindingError::InvalidField {
            field: "unique adapter words",
        });
    }
    let registers = words
        .iter()
        .map(|word| word.register)
        .collect::<BTreeSet<_>>();
    if registers.len() != words.len() {
        return Err(X64TailSiteBindingError::InvalidField {
            field: "frontier adapter register injectivity",
        });
    }
    ensure_limit(
        "adapter words",
        X64_TAIL_SITE_BINDING_MAX_WORDS_PER_REGION,
        words.len(),
    )?;
    Ok(words)
}

fn edge_adapter(
    source: Option<u32>,
    target: Option<u32>,
    force_materialize: bool,
    source_live: &[X64TailBoundDefinition],
    target_live: &[X64TailBoundDefinition],
) -> Result<
    (
        X64TailFrontierAction,
        Vec<X64TailAdapterWord>,
        Vec<X64TailAdapterWord>,
    ),
    X64TailSiteBindingError,
> {
    if source == target && source.is_some() && !force_materialize && source_live == target_live {
        return Ok((X64TailFrontierAction::Preserve, Vec::new(), Vec::new()));
    }
    let flush = if source.is_some() {
        adapters_from_live(source_live)?
    } else {
        Vec::new()
    };
    let hydrate = if target.is_some() {
        adapters_from_live(target_live)?
    } else {
        Vec::new()
    };
    let action = match (flush.is_empty(), hydrate.is_empty()) {
        (true, true) => match (source, target) {
            (None, Some(_)) => X64TailFrontierAction::Hydrate,
            (Some(_), None) => X64TailFrontierAction::Flush,
            (Some(_), Some(_)) if source == target && !force_materialize => {
                X64TailFrontierAction::Preserve
            }
            // Crossing region identities still crosses a materialized frame
            // boundary even when every live value is already frame-resident.
            _ => X64TailFrontierAction::FlushThenHydrate,
        },
        (true, false) => X64TailFrontierAction::Hydrate,
        (false, true) => X64TailFrontierAction::Flush,
        (false, false) => X64TailFrontierAction::FlushThenHydrate,
    };
    Ok((action, flush, hydrate))
}

#[allow(clippy::too_many_arguments)]
fn push_frontier(
    rows: &mut Vec<X64TailFrontierBindingRow>,
    kind: X64TailFrontierBindingKind,
    source_label: Option<X64LabelId>,
    target_label: Option<X64LabelId>,
    source_region: Option<u32>,
    target_region: Option<u32>,
    action: X64TailFrontierAction,
    source_live: Vec<X64TailBoundDefinition>,
    target_live: Vec<X64TailBoundDefinition>,
    flush: Vec<X64TailAdapterWord>,
    hydrate: Vec<X64TailAdapterWord>,
) -> Result<(), X64TailSiteBindingError> {
    validate_frontier_state(
        source_region,
        target_region,
        action,
        &source_live,
        &target_live,
        &flush,
        &hydrate,
    )?;
    let ordinal = usize_to_u32(rows.len(), "frontier ordinal")?;
    rows.push(X64TailFrontierBindingRow {
        ordinal,
        kind,
        source_label,
        target_label,
        source_region,
        target_region,
        action,
        source_live,
        target_live,
        flush,
        hydrate,
    });
    ensure_limit(
        "frontier rows",
        X64_TAIL_SITE_BINDING_MAX_FRONTIER_ROWS,
        rows.len(),
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_frontier_state(
    source_region: Option<u32>,
    target_region: Option<u32>,
    action: X64TailFrontierAction,
    source_live: &[X64TailBoundDefinition],
    target_live: &[X64TailBoundDefinition],
    flush: &[X64TailAdapterWord],
    hydrate: &[X64TailAdapterWord],
) -> Result<(), X64TailSiteBindingError> {
    for live in [source_live, target_live] {
        if live
            .windows(2)
            .any(|pair| pair[0].logical >= pair[1].logical)
            || !injection_conflicts(live).is_empty()
        {
            return Err(X64TailSiteBindingError::InvalidField {
                field: "canonical injective frontier live set",
            });
        }
    }
    let expected_flush = if source_region.is_some() {
        adapters_from_live(source_live)?
    } else {
        Vec::new()
    };
    let expected_hydrate = if target_region.is_some() {
        adapters_from_live(target_live)?
    } else {
        Vec::new()
    };
    let valid = match action {
        X64TailFrontierAction::Preserve => {
            source_region == target_region
                && source_region.is_some()
                && source_live == target_live
                && flush.is_empty()
                && hydrate.is_empty()
        }
        X64TailFrontierAction::PersistentTransition => flush.is_empty() && hydrate.is_empty(),
        X64TailFrontierAction::Hydrate => {
            expected_flush.is_empty() && flush.is_empty() && hydrate == expected_hydrate
        }
        X64TailFrontierAction::Flush => {
            expected_hydrate.is_empty() && flush == expected_flush && hydrate.is_empty()
        }
        X64TailFrontierAction::FlushThenHydrate => {
            flush == expected_flush && hydrate == expected_hydrate
        }
        X64TailFrontierAction::ObserveAfterFlush => {
            expected_hydrate.is_empty() && flush == expected_flush && hydrate.is_empty()
        }
    };
    if !valid {
        return Err(X64TailSiteBindingError::InvalidField {
            field: "frontier live adapter projection",
        });
    }
    Ok(())
}

fn compute_totals(
    regions: &[X64TailSiteRegionReceipt],
    sites: &[X64TailSiteBinding],
    frontiers: &[X64TailFrontierBindingRow],
    cfg_edges: u32,
    fixed_point_rounds: u32,
    analysis_work: u64,
) -> Result<X64TailSiteBindingTotals, X64TailSiteBindingError> {
    let mut totals = X64TailSiteBindingTotals {
        regions: usize_to_u32(regions.len(), "region total")?,
        sites: usize_to_u32(sites.len(), "site total")?,
        cfg_edges,
        fixed_point_rounds,
        frontier_rows: usize_to_u32(frontiers.len(), "frontier total")?,
        analysis_work,
        ..X64TailSiteBindingTotals::default()
    };
    for region in regions {
        match region.status {
            X64TailSiteRegionStatus::Ready => {
                totals.ready_regions = checked_add_u32(totals.ready_regions, 1, "ready regions")?;
            }
            X64TailSiteRegionStatus::RequiresDestructiveProof => {
                totals.destructive_proof_regions = checked_add_u32(
                    totals.destructive_proof_regions,
                    1,
                    "destructive-proof regions",
                )?;
            }
            X64TailSiteRegionStatus::RefusedLiveAlias => {
                totals.refused_regions =
                    checked_add_u32(totals.refused_regions, 1, "refused regions")?;
            }
        }
        totals.destructive_reuses = checked_add_u32(
            totals.destructive_reuses,
            region.destructive_reuse_count,
            "destructive reuses",
        )?;
        totals.alias_conflicts = checked_add_u32(
            totals.alias_conflicts,
            region.conflict_count,
            "alias conflicts",
        )?;
    }
    for site in sites {
        totals.bound_reads = checked_add_u64(
            totals.bound_reads,
            usize_to_u64(site.reads.len(), "bound reads")?,
            "bound reads",
        )?;
        totals.bound_definitions = checked_add_u64(
            totals.bound_definitions,
            usize_to_u64(site.definitions.len(), "bound definitions")?,
            "bound definitions",
        )?;
        let live_words = site
            .live_before
            .len()
            .checked_add(site.live_after.len())
            .ok_or(X64TailSiteBindingError::ArithmeticOverflow {
                field: "live word rows",
            })?;
        totals.live_word_rows = checked_add_u64(
            totals.live_word_rows,
            usize_to_u64(live_words, "live word rows")?,
            "live word rows",
        )?;
    }
    for frontier in frontiers {
        totals.frontier_source_live_words = checked_add_u64(
            totals.frontier_source_live_words,
            usize_to_u64(frontier.source_live.len(), "frontier source live words")?,
            "frontier source live words",
        )?;
        totals.frontier_target_live_words = checked_add_u64(
            totals.frontier_target_live_words,
            usize_to_u64(frontier.target_live.len(), "frontier target live words")?,
            "frontier target live words",
        )?;
        totals.flush_words = checked_add_u64(
            totals.flush_words,
            usize_to_u64(frontier.flush.len(), "flush words")?,
            "flush words",
        )?;
        totals.hydrate_words = checked_add_u64(
            totals.hydrate_words,
            usize_to_u64(frontier.hydrate.len(), "hydrate words")?,
            "hydrate words",
        )?;
    }
    let bound_words = totals
        .bound_reads
        .checked_add(totals.bound_definitions)
        .and_then(|value| value.checked_add(totals.live_word_rows))
        .and_then(|value| value.checked_add(totals.frontier_source_live_words))
        .and_then(|value| value.checked_add(totals.frontier_target_live_words))
        .and_then(|value| value.checked_add(totals.flush_words))
        .and_then(|value| value.checked_add(totals.hydrate_words))
        .ok_or(X64TailSiteBindingError::ArithmeticOverflow {
            field: "bound word total",
        })?;
    if bound_words > X64_TAIL_SITE_BINDING_MAX_BOUND_WORDS {
        return Err(X64TailSiteBindingError::LimitExceeded {
            field: "bound words",
            limit: X64_TAIL_SITE_BINDING_MAX_BOUND_WORDS,
            actual: bound_words,
        });
    }
    Ok(totals)
}

fn validate_live_clobbers(
    site: &X64TailPreservationSite,
    live_before: &[X64TailBoundDefinition],
    live_after: &[X64TailBoundDefinition],
) -> Result<(), X64TailSiteBindingError> {
    for binding in live_before.iter().chain(live_after) {
        let X64TailPhysicalLocation::Register { register, .. } = binding.physical else {
            continue;
        };
        if site
            .clobbers
            .contains(&physical_template_register(register))
        {
            return Err(X64TailSiteBindingError::InvalidField {
                field: "live persistent template clobber",
            });
        }
    }
    Ok(())
}

const fn physical_template_register(register: X64TailPhysicalRegister) -> X64TailTemplateRegister {
    match register {
        X64TailPhysicalRegister::Rdi => X64TailTemplateRegister::Rdi,
        X64TailPhysicalRegister::Rsi => X64TailTemplateRegister::Rsi,
        X64TailPhysicalRegister::R9 => X64TailTemplateRegister::R9,
        X64TailPhysicalRegister::R10 => X64TailTemplateRegister::R10,
        X64TailPhysicalRegister::R11 => X64TailTemplateRegister::R11,
        X64TailPhysicalRegister::Xmm3 => X64TailTemplateRegister::Xmm3,
        X64TailPhysicalRegister::Xmm4 => X64TailTemplateRegister::Xmm4,
        X64TailPhysicalRegister::Xmm5 => X64TailTemplateRegister::Xmm5,
        X64TailPhysicalRegister::Xmm6 => X64TailTemplateRegister::Xmm6,
        X64TailPhysicalRegister::Xmm7 => X64TailTemplateRegister::Xmm7,
    }
}

fn validate_envelope(
    proof: &X64TailSiteBindingProof,
    capsule: &X64TailCandidateCapsule,
    realization: &X64TailTemplateRealization,
    physical: &X64TailPhysicalAllocation,
    logical: &X64TailStatePlan,
    target: &X64TargetArtifact,
) -> Result<(), X64TailSiteBindingError> {
    if proof.schema_version != X64_TAIL_SITE_BINDING_SCHEMA_VERSION {
        return Err(X64TailSiteBindingError::InvalidField {
            field: "schema version",
        });
    }
    if proof.policy_version != X64_TAIL_SITE_BINDING_POLICY_VERSION {
        return Err(X64TailSiteBindingError::InvalidField {
            field: "policy version",
        });
    }
    if proof.source_target_semantic_hash != target.semantic_hash
        || proof.source_logical_plan_hash != logical.plan_hash()
        || proof.source_physical_allocation_hash != physical.allocation_hash()
        || proof.source_template_realization_hash != realization.realization_hash()
        || proof.source_candidate_capsule_hash != capsule.capsule_hash()
    {
        return Err(X64TailSiteBindingError::InvalidField {
            field: "source identity",
        });
    }
    Ok(())
}

fn proof_bytes_without_seal(
    proof: &X64TailSiteBindingProof,
) -> Result<Vec<u8>, X64TailSiteBindingError> {
    let mut encoder = EvidenceEncoder::new();
    encoder.bytes(PROOF_DOMAIN)?;
    encoder.version(proof.schema_version)?;
    encoder.version(proof.policy_version)?;
    encoder.hash(proof.source_target_semantic_hash)?;
    encoder.hash(proof.source_logical_plan_hash)?;
    encoder.hash(proof.source_physical_allocation_hash)?;
    encoder.hash(proof.source_template_realization_hash)?;
    encoder.hash(proof.source_candidate_capsule_hash)?;
    encoder.len(proof.regions.len())?;
    for region in &proof.regions {
        encoder.u32(region.region)?;
        encoder.u8(region_status_tag(region.status))?;
        encoder.u32(region.site_count)?;
        encoder.u32(region.conflict_count)?;
        encoder.u32(region.destructive_reuse_count)?;
    }
    encoder.len(proof.sites.len())?;
    for site in &proof.sites {
        encoder.u32(site.region)?;
        encoder.u32(site.function.0)?;
        encoder.u32(site.block.0)?;
        encoder.u32(site.label.0)?;
        encode_site_position(&mut encoder, site.position)?;
        encoder.u8(template_tag(site.template))?;
        encoder.len(site.reads.len())?;
        for read in &site.reads {
            encode_bound_read(&mut encoder, *read)?;
        }
        encode_bindings(&mut encoder, &site.definitions)?;
        encode_bindings(&mut encoder, &site.live_before)?;
        encode_bindings(&mut encoder, &site.live_after)?;
        encode_conflicts(&mut encoder, &site.destructive_reuses)?;
        encode_conflicts(&mut encoder, &site.conflicts)?;
    }
    encoder.len(proof.frontiers.len())?;
    for row in &proof.frontiers {
        encoder.u32(row.ordinal)?;
        encode_frontier_kind(&mut encoder, row.kind)?;
        encoder.option_u32(row.source_label.map(|label| label.0))?;
        encoder.option_u32(row.target_label.map(|label| label.0))?;
        encoder.option_u32(row.source_region)?;
        encoder.option_u32(row.target_region)?;
        encoder.u8(frontier_action_tag(row.action))?;
        encode_bindings(&mut encoder, &row.source_live)?;
        encode_bindings(&mut encoder, &row.target_live)?;
        encode_adapter_words(&mut encoder, &row.flush)?;
        encode_adapter_words(&mut encoder, &row.hydrate)?;
    }
    encode_totals(&mut encoder, proof.totals)?;
    Ok(encoder.finish())
}

fn encode_bindings(
    encoder: &mut EvidenceEncoder,
    bindings: &[X64TailBoundDefinition],
) -> Result<(), X64TailSiteBindingError> {
    encoder.len(bindings.len())?;
    for binding in bindings {
        encode_logical(encoder, binding.logical)?;
        encode_physical(encoder, binding.physical)?;
    }
    Ok(())
}

fn encode_conflicts(
    encoder: &mut EvidenceEncoder,
    conflicts: &[X64TailSiteAliasConflict],
) -> Result<(), X64TailSiteBindingError> {
    encoder.len(conflicts.len())?;
    for conflict in conflicts {
        encode_logical(encoder, conflict.left)?;
        encode_logical(encoder, conflict.right)?;
        encode_physical(encoder, conflict.physical)?;
    }
    Ok(())
}

fn encode_bound_read(
    encoder: &mut EvidenceEncoder,
    read: X64TailBoundRead,
) -> Result<(), X64TailSiteBindingError> {
    match read {
        X64TailBoundRead::Immediate(immediate) => {
            encoder.u8(0)?;
            encode_immediate(encoder, immediate)
        }
        X64TailBoundRead::Location { logical, physical } => {
            encoder.u8(1)?;
            encode_logical(encoder, logical)?;
            encode_physical(encoder, physical)
        }
    }
}

fn encode_adapter_words(
    encoder: &mut EvidenceEncoder,
    words: &[X64TailAdapterWord],
) -> Result<(), X64TailSiteBindingError> {
    encoder.len(words.len())?;
    for word in words {
        encode_logical(encoder, word.logical)?;
        encoder.u8(register_tag(word.register))?;
    }
    Ok(())
}

fn encode_logical(
    encoder: &mut EvidenceEncoder,
    logical: X64TailWordLocation,
) -> Result<(), X64TailSiteBindingError> {
    encoder.u32(logical.offset)?;
    encoder.u8(word_type_tag(logical.word_type))
}

fn encode_physical(
    encoder: &mut EvidenceEncoder,
    physical: X64TailPhysicalLocation,
) -> Result<(), X64TailSiteBindingError> {
    match physical {
        X64TailPhysicalLocation::Register {
            register,
            word_type,
        } => {
            encoder.u8(0)?;
            encoder.u8(register_tag(register))?;
            encoder.u8(word_type_tag(word_type))
        }
        X64TailPhysicalLocation::Frame(logical) => {
            encoder.u8(1)?;
            encode_logical(encoder, logical)
        }
    }
}

fn encode_immediate(
    encoder: &mut EvidenceEncoder,
    immediate: X64TailImmediateWord,
) -> Result<(), X64TailSiteBindingError> {
    match immediate {
        X64TailImmediateWord::Bool(value) => {
            encoder.u8(0)?;
            encoder.u8(u8::from(value))
        }
        X64TailImmediateWord::I64(value) => {
            encoder.u8(1)?;
            encoder.u64(value as u64)
        }
        X64TailImmediateWord::F64Bits(bits) => {
            encoder.u8(2)?;
            encoder.u64(bits)
        }
    }
}

fn encode_site_position(
    encoder: &mut EvidenceEncoder,
    position: X64TailTemplateSitePosition,
) -> Result<(), X64TailSiteBindingError> {
    match position {
        X64TailTemplateSitePosition::Instruction(index) => {
            encoder.u8(0)?;
            encoder.u32(index)
        }
        X64TailTemplateSitePosition::BranchCondition => encoder.u8(1),
        X64TailTemplateSitePosition::BranchElse => encoder.u8(2),
        X64TailTemplateSitePosition::TailTransition { edge_ordinal } => {
            encoder.u8(3)?;
            encoder.u32(edge_ordinal)
        }
        X64TailTemplateSitePosition::TailFrontier { edge_ordinal } => {
            encoder.u8(4)?;
            encoder.u32(edge_ordinal)
        }
    }
}

fn encode_frontier_kind(
    encoder: &mut EvidenceEncoder,
    kind: X64TailFrontierBindingKind,
) -> Result<(), X64TailSiteBindingError> {
    match kind {
        X64TailFrontierBindingKind::Entry => encoder.u8(0),
        X64TailFrontierBindingKind::BranchThen => encoder.u8(1),
        X64TailFrontierBindingKind::BranchElse => encoder.u8(2),
        X64TailFrontierBindingKind::PersistentTail { edge_ordinal } => {
            encoder.u8(3)?;
            encoder.u32(edge_ordinal)
        }
        X64TailFrontierBindingKind::MaterializedTail { edge_ordinal } => {
            encoder.u8(4)?;
            encoder.u32(edge_ordinal)
        }
        X64TailFrontierBindingKind::RefusedTail { edge_ordinal } => {
            encoder.u8(5)?;
            encoder.u32(edge_ordinal)
        }
        X64TailFrontierBindingKind::Return => encoder.u8(6),
        X64TailFrontierBindingKind::Bounds { instruction } => {
            encoder.u8(7)?;
            encoder.u32(instruction)
        }
        X64TailFrontierBindingKind::Declared { kind } => {
            encoder.u8(8)?;
            encoder.u8(frontier_kind_tag(kind))
        }
    }
}

fn encode_totals(
    encoder: &mut EvidenceEncoder,
    totals: X64TailSiteBindingTotals,
) -> Result<(), X64TailSiteBindingError> {
    encoder.u32(totals.regions)?;
    encoder.u32(totals.ready_regions)?;
    encoder.u32(totals.destructive_proof_regions)?;
    encoder.u32(totals.refused_regions)?;
    encoder.u32(totals.sites)?;
    encoder.u64(totals.bound_reads)?;
    encoder.u64(totals.bound_definitions)?;
    encoder.u64(totals.live_word_rows)?;
    encoder.u32(totals.destructive_reuses)?;
    encoder.u32(totals.alias_conflicts)?;
    encoder.u32(totals.cfg_edges)?;
    encoder.u32(totals.fixed_point_rounds)?;
    encoder.u32(totals.frontier_rows)?;
    encoder.u64(totals.frontier_source_live_words)?;
    encoder.u64(totals.frontier_target_live_words)?;
    encoder.u64(totals.flush_words)?;
    encoder.u64(totals.hydrate_words)?;
    encoder.u64(totals.analysis_work)
}

const fn region_status_tag(status: X64TailSiteRegionStatus) -> u8 {
    match status {
        X64TailSiteRegionStatus::Ready => 0,
        X64TailSiteRegionStatus::RequiresDestructiveProof => 1,
        X64TailSiteRegionStatus::RefusedLiveAlias => 2,
    }
}

const fn frontier_action_tag(action: X64TailFrontierAction) -> u8 {
    match action {
        X64TailFrontierAction::Preserve => 0,
        X64TailFrontierAction::PersistentTransition => 1,
        X64TailFrontierAction::Hydrate => 2,
        X64TailFrontierAction::Flush => 3,
        X64TailFrontierAction::FlushThenHydrate => 4,
        X64TailFrontierAction::ObserveAfterFlush => 5,
    }
}

const fn frontier_kind_tag(kind: X64TailFrontierKind) -> u8 {
    match kind {
        X64TailFrontierKind::EntryAbi => 0,
        X64TailFrontierKind::SharedJoin => 1,
        X64TailFrontierKind::Bounds => 2,
        X64TailFrontierKind::Return => 3,
        X64TailFrontierKind::Budget => 4,
    }
}

const fn word_type_tag(word_type: X64TailWordType) -> u8 {
    match word_type {
        X64TailWordType::Bool => 0,
        X64TailWordType::I64 => 1,
        X64TailWordType::F64 => 2,
        X64TailWordType::ArrayData => 3,
        X64TailWordType::ArrayLength => 4,
    }
}

const fn register_tag(register: X64TailPhysicalRegister) -> u8 {
    match register {
        X64TailPhysicalRegister::Rdi => 0,
        X64TailPhysicalRegister::Rsi => 1,
        X64TailPhysicalRegister::R9 => 2,
        X64TailPhysicalRegister::R10 => 3,
        X64TailPhysicalRegister::R11 => 4,
        X64TailPhysicalRegister::Xmm3 => 5,
        X64TailPhysicalRegister::Xmm4 => 6,
        X64TailPhysicalRegister::Xmm5 => 7,
        X64TailPhysicalRegister::Xmm6 => 8,
        X64TailPhysicalRegister::Xmm7 => 9,
    }
}

const fn template_tag(template: X64TailProgramTemplateKind) -> u8 {
    match template {
        X64TailProgramTemplateKind::MoveScalar => 0,
        X64TailProgramTemplateKind::MoveF64 => 1,
        X64TailProgramTemplateKind::MoveArrayPair => 2,
        X64TailProgramTemplateKind::I64Wrapping => 3,
        X64TailProgramTemplateKind::Sse2F64 => 4,
        X64TailProgramTemplateKind::I64Setcc => 5,
        X64TailProgramTemplateKind::ArrayLenF64 => 6,
        X64TailProgramTemplateKind::ArrayGetF64Checked => 7,
        X64TailProgramTemplateKind::BranchCondition => 8,
        X64TailProgramTemplateKind::BranchElseRel32 => 9,
        X64TailProgramTemplateKind::PersistentTailTransition => 10,
        X64TailProgramTemplateKind::MaterializedTailFrontier => 11,
        X64TailProgramTemplateKind::RefusedTailFrontier => 12,
    }
}

fn find_block(
    program: &X64TargetProgram,
    function: X64FunctionId,
    block: X64BlockId,
) -> Result<&X64Block, X64TailSiteBindingError> {
    program
        .functions
        .iter()
        .find(|candidate| candidate.id == function)
        .and_then(|function| {
            function
                .blocks
                .iter()
                .find(|candidate| candidate.id == block)
        })
        .ok_or(X64TailSiteBindingError::MissingTarget {
            field: "target block",
        })
}

fn ensure_limit(
    field: &'static str,
    limit: u32,
    actual: usize,
) -> Result<(), X64TailSiteBindingError> {
    let limit_usize =
        usize::try_from(limit).map_err(|_| X64TailSiteBindingError::ArithmeticOverflow {
            field: "host limit width",
        })?;
    if actual > limit_usize {
        Err(X64TailSiteBindingError::LimitExceeded {
            field,
            limit: u64::from(limit),
            actual: usize_to_u64(actual, field)?,
        })
    } else {
        Ok(())
    }
}

fn charge(work: &mut u64, amount: u64, field: &'static str) -> Result<(), X64TailSiteBindingError> {
    *work = work
        .checked_add(amount)
        .ok_or(X64TailSiteBindingError::ArithmeticOverflow { field })?;
    if *work > X64_TAIL_SITE_BINDING_MAX_ANALYSIS_WORK {
        return Err(X64TailSiteBindingError::LimitExceeded {
            field: "analysis work",
            limit: X64_TAIL_SITE_BINDING_MAX_ANALYSIS_WORK,
            actual: *work,
        });
    }
    Ok(())
}

fn checked_add_u32(
    left: u32,
    right: u32,
    field: &'static str,
) -> Result<u32, X64TailSiteBindingError> {
    left.checked_add(right)
        .ok_or(X64TailSiteBindingError::ArithmeticOverflow { field })
}

fn checked_add_u64(
    left: u64,
    right: u64,
    field: &'static str,
) -> Result<u64, X64TailSiteBindingError> {
    left.checked_add(right)
        .ok_or(X64TailSiteBindingError::ArithmeticOverflow { field })
}

fn usize_to_u32(value: usize, field: &'static str) -> Result<u32, X64TailSiteBindingError> {
    u32::try_from(value).map_err(|_| X64TailSiteBindingError::ArithmeticOverflow { field })
}

fn usize_to_u64(value: usize, field: &'static str) -> Result<u64, X64TailSiteBindingError> {
    u64::try_from(value).map_err(|_| X64TailSiteBindingError::ArithmeticOverflow { field })
}

struct EvidenceEncoder {
    bytes: Vec<u8>,
}

impl EvidenceEncoder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn reserve(&mut self, additional: usize) -> Result<(), X64TailSiteBindingError> {
        let actual = self.bytes.len().checked_add(additional).ok_or(
            X64TailSiteBindingError::ArithmeticOverflow {
                field: "evidence length",
            },
        )?;
        if actual > X64_TAIL_SITE_BINDING_MAX_EVIDENCE_BYTES {
            return Err(X64TailSiteBindingError::EncodingLimit { actual });
        }
        self.bytes
            .try_reserve(additional)
            .map_err(|_| X64TailSiteBindingError::EncodingLimit { actual })
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), X64TailSiteBindingError> {
        self.reserve(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), X64TailSiteBindingError> {
        self.bytes(&[value])
    }

    fn u32(&mut self, value: u32) -> Result<(), X64TailSiteBindingError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), X64TailSiteBindingError> {
        self.bytes(&value.to_le_bytes())
    }

    fn len(&mut self, value: usize) -> Result<(), X64TailSiteBindingError> {
        self.u32(usize_to_u32(value, "evidence collection length")?)
    }

    fn version(&mut self, value: (u16, u16, u16)) -> Result<(), X64TailSiteBindingError> {
        self.bytes(&value.0.to_le_bytes())?;
        self.bytes(&value.1.to_le_bytes())?;
        self.bytes(&value.2.to_le_bytes())
    }

    fn hash(&mut self, value: SemanticHash) -> Result<(), X64TailSiteBindingError> {
        self.bytes(&value.0)
    }

    fn option_u32(&mut self, value: Option<u32>) -> Result<(), X64TailSiteBindingError> {
        match value {
            Some(value) => {
                self.u8(1)?;
                self.u32(value)
            }
            None => self.u8(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::corevm0_gate_a::CoreVmGateAWorkload;
    use crate::core::x64_native_lighthouse::X64NativeLighthousePackage;
    use crate::core::{
        emit_x64_tail_candidate_capsule, emit_x64_tail_physical_allocation,
        emit_x64_tail_state_plan, emit_x64_tail_template_realization,
        X64_TARGET_ENCODER_POLICY_VERSION,
    };

    fn build(
        workload: CoreVmGateAWorkload,
    ) -> (
        X64NativeLighthousePackage,
        X64TailStatePlan,
        X64TailPhysicalAllocation,
        X64TailTemplateRealization,
        X64TailCandidateCapsule,
        X64TailSiteBindingProof,
    ) {
        let package =
            X64NativeLighthousePackage::build(workload).expect("lighthouse package must build");
        let logical = emit_x64_tail_state_plan(package.target()).expect("logical plan must emit");
        let physical = emit_x64_tail_physical_allocation(package.target(), &logical)
            .expect("physical allocation must emit");
        let realization = emit_x64_tail_template_realization(package.target(), &logical, &physical)
            .expect("template realization must emit");
        let capsule =
            emit_x64_tail_candidate_capsule(package.target(), &logical, &physical, &realization)
                .expect("candidate capsule must emit");
        let proof = emit_x64_tail_site_binding_proof(
            package.target(),
            &logical,
            &physical,
            &realization,
            &capsule,
        )
        .expect("site binding proof must emit");
        (package, logical, physical, realization, capsule, proof)
    }

    #[test]
    fn branch_lighthouse_exposes_instruction_aware_readiness_and_frontiers() {
        let (package, logical, physical, realization, capsule, first) =
            build(CoreVmGateAWorkload::BranchMix);
        let second = emit_x64_tail_site_binding_proof(
            package.target(),
            &logical,
            &physical,
            &realization,
            &capsule,
        )
        .expect("site binding proof must replay");
        assert_eq!(first, second);
        verify_x64_tail_site_binding_proof(
            &first,
            &capsule,
            &realization,
            &physical,
            &logical,
            package.target(),
        )
        .expect("site binding proof must verify");
        assert_eq!(first.sites.len(), realization.sites().len());
        assert_eq!(
            first
                .frontiers
                .iter()
                .filter(|row| matches!(row.kind, X64TailFrontierBindingKind::PersistentTail { .. }))
                .count(),
            realization.transitions().len()
        );
        assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
        assert_eq!(
            first.proof_hash().to_hex(),
            "b463794482025164e936a6d88400e145d084bb0df7a7de33540eedb6c001bba2"
        );
        assert_eq!(
            first.totals(),
            X64TailSiteBindingTotals {
                regions: 31,
                ready_regions: 31,
                destructive_proof_regions: 0,
                refused_regions: 0,
                sites: 168,
                bound_reads: 1_346,
                bound_definitions: 23,
                live_word_rows: 2_059,
                destructive_reuses: 0,
                alias_conflicts: 0,
                cfg_edges: 145,
                fixed_point_rounds: 2,
                frontier_rows: 151,
                frontier_source_live_words: 1_417,
                frontier_target_live_words: 1_476,
                flush_words: 207,
                hydrate_words: 189,
                analysis_work: 976,
            }
        );
        for frontier in &first.frontiers {
            assert!(injection_conflicts(&frontier.source_live).is_empty());
            assert!(injection_conflicts(&frontier.target_live).is_empty());
            let flush_registers = frontier
                .flush
                .iter()
                .map(|word| word.register)
                .collect::<BTreeSet<_>>();
            let hydrate_registers = frontier
                .hydrate
                .iter()
                .map(|word| word.register)
                .collect::<BTreeSet<_>>();
            assert_eq!(flush_registers.len(), frontier.flush.len());
            assert_eq!(hydrate_registers.len(), frontier.hydrate.len());
        }

        let mut wrong_site = first.clone();
        wrong_site.sites[0].live_before.clear();
        wrong_site.proof_hash = x64_tail_site_binding_proof_hash(&wrong_site)
            .expect("site mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_site_binding_proof(
                &wrong_site,
                &capsule,
                &realization,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailSiteBindingError::ReplayMismatch)
        ));

        let mut wrong_frontier = first.clone();
        wrong_frontier.frontiers[0].action = X64TailFrontierAction::Preserve;
        wrong_frontier.proof_hash = x64_tail_site_binding_proof_hash(&wrong_frontier)
            .expect("frontier mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_site_binding_proof(
                &wrong_frontier,
                &capsule,
                &realization,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailSiteBindingError::ReplayMismatch)
        ));

        let mut wrong_live = first.clone();
        wrong_live.frontiers[0].target_live.clear();
        wrong_live.proof_hash = x64_tail_site_binding_proof_hash(&wrong_live)
            .expect("frontier live mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_site_binding_proof(
                &wrong_live,
                &capsule,
                &realization,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailSiteBindingError::ReplayMismatch)
        ));

        let mut duplicate_register = first.clone();
        let duplicate_row = duplicate_register
            .frontiers
            .iter_mut()
            .find(|row| row.flush.len() >= 2)
            .expect("fixture must expose a multi-register flush");
        duplicate_row.flush[1].register = duplicate_row.flush[0].register;
        duplicate_register.proof_hash = x64_tail_site_binding_proof_hash(&duplicate_register)
            .expect("duplicate-register mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_site_binding_proof(
                &duplicate_register,
                &capsule,
                &realization,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailSiteBindingError::ReplayMismatch)
        ));

        let mut wrong_source = first.clone();
        wrong_source.source_candidate_capsule_hash.0[0] ^= 1;
        wrong_source.proof_hash = x64_tail_site_binding_proof_hash(&wrong_source)
            .expect("source mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_site_binding_proof(
                &wrong_source,
                &capsule,
                &realization,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailSiteBindingError::InvalidField {
                field: "source identity"
            })
        ));

        let mut wrong_region = first.clone();
        wrong_region.regions[0].status = X64TailSiteRegionStatus::RefusedLiveAlias;
        wrong_region.proof_hash = x64_tail_site_binding_proof_hash(&wrong_region)
            .expect("region mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_site_binding_proof(
                &wrong_region,
                &capsule,
                &realization,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailSiteBindingError::ReplayMismatch)
        ));

        let mut wrong_total = first.clone();
        wrong_total.totals.analysis_work = wrong_total.totals.analysis_work.saturating_add(1);
        wrong_total.proof_hash = x64_tail_site_binding_proof_hash(&wrong_total)
            .expect("total mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_site_binding_proof(
                &wrong_total,
                &capsule,
                &realization,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailSiteBindingError::ReplayMismatch)
        ));

        let mut wrong_seal = first.clone();
        wrong_seal.proof_hash.0[0] ^= 1;
        assert!(matches!(
            verify_x64_tail_site_binding_proof(
                &wrong_seal,
                &capsule,
                &realization,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailSiteBindingError::ProofHashMismatch)
        ));
    }

    #[test]
    fn bounds_lighthouse_remains_proof_only_and_source_bound() {
        let (package, logical, physical, realization, capsule, proof) =
            build(CoreVmGateAWorkload::BoundsOrderedArrayGet);
        verify_x64_tail_site_binding_proof(
            &proof,
            &capsule,
            &realization,
            &physical,
            &logical,
            package.target(),
        )
        .expect("Bounds site binding proof must verify");
        assert_eq!(
            proof.source_target_semantic_hash(),
            package.target().semantic_hash
        );
        assert_eq!(
            proof.source_candidate_capsule_hash(),
            capsule.capsule_hash()
        );
        assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
    }

    #[test]
    fn tail_only_interference_counterexample_is_detected_at_a_body_site() {
        let left = X64TailWordLocation {
            offset: 32,
            word_type: X64TailWordType::I64,
        };
        let right = X64TailWordLocation {
            offset: 40,
            word_type: X64TailWordType::I64,
        };
        let aliased = X64TailPhysicalLocation::Register {
            register: X64TailPhysicalRegister::R9,
            word_type: X64TailWordType::I64,
        };
        let conflicts = injection_conflicts(&[
            X64TailBoundDefinition {
                logical: left,
                physical: aliased,
            },
            X64TailBoundDefinition {
                logical: right,
                physical: aliased,
            },
        ]);
        assert_eq!(
            conflicts,
            vec![X64TailSiteAliasConflict {
                left,
                right,
                physical: aliased,
            }]
        );
    }
}
