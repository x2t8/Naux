//! Deterministic weighted execution profiling for a verified x86-64 target.
//!
//! The canonical plan evaluator supplies logical event counts. The raw
//! encoder independently supplies the exact policy-selected byte span owned
//! by each event. Multiplication happens only after both sides replay. This
//! never instruments native code and therefore cannot perturb Gate B timing.

use super::super::encoding::sha256;
use super::eval::{
    evaluate_program_with_observer, PlanExecutionError, PlanExecutionEvent, PlanExecutionObserver,
};
use super::prospective_semantics::verify_prospective_register_semantics;
use super::raw::{
    self, RawExecutionEvent, RawProspectiveExecutionAuthority, RawProspectiveLabelDisposition,
    RawProspectiveShadow, RawProspectiveSharedJoinPartition, RawProspectiveSharedJoinRealization,
    RawRealization, RawRealizationAtom, RawSharedJoinBranchPath, RawSharedJoinComposition,
    RawSharedJoinCompositionStep, RawSharedJoinKind, RawSharedJoinLineageEvent,
    RawSharedJoinOpportunity, RawTemplateClass,
};
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const X64_TARGET_PROFILE_SCHEMA_VERSION: (u16, u16, u16) = (1, 6, 0);
pub const X64_TARGET_PROFILE_POLICY_VERSION: (u16, u16, u16) = (1, 5, 0);

const PROSPECTIVE_SHARED_JOIN_CODE_DOMAIN: &[u8] = b"NAUX:x86-64:prospective-shared-join:code:v1\0";
const PROSPECTIVE_SHARED_JOIN_REALIZATION_DOMAIN: &[u8] =
    b"NAUX:x86-64:prospective-shared-join:realization:v2\0";
const MAX_PROSPECTIVE_SHARED_JOIN_TARGETS: usize = 16;
const MAX_PROSPECTIVE_SHARED_JOIN_INGRESSES: usize = 8;
const MAX_PROSPECTIVE_SHARED_JOIN_REPLICAS: u32 = 64;
const MAX_PROSPECTIVE_ATOMS_PER_REPLICA: u64 = 3;
const MAX_PROSPECTIVE_FIXUPS_PER_REPLICA: u64 = 2;
const MAX_PROSPECTIVE_POSITIVE_CODE_GROWTH: u64 = 64 * 1024;
const MAX_PROSPECTIVE_REPLAY_WORK: u64 = 32_000_000;
const MAX_PROSPECTIVE_REALIZATION_HASH_PREIMAGE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum X64TargetProfileTemplateClass {
    EntryPrologue,
    OrdinaryInstruction,
    RegisterInstruction,
    TailTransfer,
    ReturnTransfer,
    BranchCondition,
    BranchElseJump,
    FusedCompareInstruction,
    ReturnEpilogue,
    BoundsEpilogue,
    Tombstone,
}

impl From<RawTemplateClass> for X64TargetProfileTemplateClass {
    fn from(value: RawTemplateClass) -> Self {
        match value {
            RawTemplateClass::EntryPrologue => Self::EntryPrologue,
            RawTemplateClass::OrdinaryInstruction => Self::OrdinaryInstruction,
            RawTemplateClass::RegisterInstruction => Self::RegisterInstruction,
            RawTemplateClass::TailTransfer => Self::TailTransfer,
            RawTemplateClass::ReturnTransfer => Self::ReturnTransfer,
            RawTemplateClass::BranchCondition => Self::BranchCondition,
            RawTemplateClass::BranchElseJump => Self::BranchElseJump,
            RawTemplateClass::FusedCompareInstruction => Self::FusedCompareInstruction,
            RawTemplateClass::ReturnEpilogue => Self::ReturnEpilogue,
            RawTemplateClass::BoundsEpilogue => Self::BoundsEpilogue,
            RawTemplateClass::Tombstone => Self::Tombstone,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum X64TargetProfileEvent {
    Entry,
    Instruction { label: X64LabelId, index: u32 },
    Tail { label: X64LabelId },
    Return { label: X64LabelId },
    Branch { label: X64LabelId },
    BranchElse { label: X64LabelId },
    ReturnEpilogue,
    BoundsEpilogue,
    Static,
}

impl From<RawExecutionEvent> for X64TargetProfileEvent {
    fn from(value: RawExecutionEvent) -> Self {
        match value {
            RawExecutionEvent::Entry => Self::Entry,
            RawExecutionEvent::Instruction { label, index } => Self::Instruction { label, index },
            RawExecutionEvent::Tail { label } => Self::Tail { label },
            RawExecutionEvent::Return { label } => Self::Return { label },
            RawExecutionEvent::Branch { label } => Self::Branch { label },
            RawExecutionEvent::BranchElse { label } => Self::BranchElse { label },
            RawExecutionEvent::ReturnEpilogue => Self::ReturnEpilogue,
            RawExecutionEvent::BoundsEpilogue => Self::BoundsEpilogue,
            RawExecutionEvent::Static => Self::Static,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X64TargetProfileInstructionCounts {
    pub moves: u64,
    pub i64_adds: u64,
    pub i64_subtracts: u64,
    pub i64_multiplies: u64,
    pub f64_adds: u64,
    pub f64_subtracts: u64,
    pub i64_less_than: u64,
    pub i64_greater_or_equal: u64,
    pub array_lengths: u64,
    pub checked_array_gets: u64,
}

impl X64TargetProfileInstructionCounts {
    pub fn total(self) -> Result<u64, X64TargetProfileError> {
        [
            self.moves,
            self.i64_adds,
            self.i64_subtracts,
            self.i64_multiplies,
            self.f64_adds,
            self.f64_subtracts,
            self.i64_less_than,
            self.i64_greater_or_equal,
            self.array_lengths,
            self.checked_array_gets,
        ]
        .into_iter()
        .try_fold(0_u64, |total, count| {
            total
                .checked_add(count)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "instruction total",
                })
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X64TargetProfileControlCounts {
    pub entries: u64,
    pub returns: u64,
    pub branches: u64,
    pub branch_then: u64,
    pub branch_else: u64,
    pub tail_transfers: u64,
    pub tail_argument_values: u64,
    pub tail_argument_words: u64,
    pub bounds_exits: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TargetProfileBlockCount {
    pub label: X64LabelId,
    pub entries: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TargetProfileEdgeCount {
    pub source: X64LabelId,
    pub target: X64LabelId,
    pub traversals: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum X64TargetSharedJoinKind {
    RegisterInstruction,
    FusedCompare,
}

impl From<RawSharedJoinKind> for X64TargetSharedJoinKind {
    fn from(value: RawSharedJoinKind) -> Self {
        match value {
            RawSharedJoinKind::RegisterInstruction => Self::RegisterInstruction,
            RawSharedJoinKind::FusedCompare => Self::FusedCompare,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TargetSharedJoinIngress {
    pub root: X64LabelId,
    pub trigger: X64LabelId,
    pub executions: u64,
    pub frame_accesses_per_execution: u32,
    pub weighted_frame_accesses: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TargetSharedJoinOpportunity {
    pub target: X64LabelId,
    pub kind: X64TargetSharedJoinKind,
    pub executions: u64,
    pub ingresses: Vec<X64TargetSharedJoinIngress>,
    pub weighted_ingress_frame_accesses: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TargetSharedJoinBranchArmCounts {
    pub then_executions: u64,
    pub else_executions: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TargetSharedJoinRouteEvent {
    Instruction {
        label: X64LabelId,
        index: u32,
    },
    Tail {
        source: X64LabelId,
        target: X64LabelId,
    },
}

impl From<RawSharedJoinLineageEvent> for X64TargetSharedJoinRouteEvent {
    fn from(value: RawSharedJoinLineageEvent) -> Self {
        match value {
            RawSharedJoinLineageEvent::Instruction { label, index } => {
                Self::Instruction { label, index }
            }
            RawSharedJoinLineageEvent::Tail { source, target } => Self::Tail { source, target },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TargetSharedJoinCompositionIngress {
    pub root: X64LabelId,
    pub authority_trigger: X64LabelId,
    /// Exact canonical logical-event route from the authority tail through
    /// the cloned target. Fused-compare routes end at the compare-to-branch
    /// bridge tail; register routes end at the target's outgoing tail.
    pub route: Vec<X64TargetSharedJoinRouteEvent>,
    pub executions: u64,
    pub frame_accesses_per_execution: u32,
    pub weighted_frame_accesses: u128,
    pub branch_arm_counts: Option<X64TargetSharedJoinBranchArmCounts>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TargetSharedJoinCompositionStep {
    pub target: X64LabelId,
    pub kind: X64TargetSharedJoinKind,
    /// Canonically sorted transitive set of earlier selected shared targets
    /// whose cloned paths feed at least one ingress of this step.
    pub ancestors: Vec<X64LabelId>,
    pub executions: u64,
    pub ingresses: Vec<X64TargetSharedJoinCompositionIngress>,
    pub weighted_ingress_frame_accesses: u128,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct X64TargetSharedJoinComposition {
    /// `false` means the metadata proof refused and policy 1.4 bytes were
    /// retained unchanged; no partial composition may be consumed.
    pub complete: bool,
    pub steps: Vec<X64TargetSharedJoinCompositionStep>,
    pub body_replicas: u32,
    /// Sum of selected target-body executions. This is not a unique-visit
    /// count because an upstream and downstream selected body may execute on
    /// the same dynamic path.
    pub body_executions: u64,
    pub weighted_ingress_frame_accesses: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum X64TargetProspectiveSharedJoinPartition {
    All,
    Else,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum X64TargetProspectiveExecutionAuthority {
    Semantic {
        event: X64TargetProfileEvent,
    },
    SharedJoin {
        target: X64LabelId,
        root: X64LabelId,
        authority_trigger: X64LabelId,
        partition: X64TargetProspectiveSharedJoinPartition,
    },
    Static,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TargetProspectiveRealizationAtom {
    pub physical_owner: X64LabelId,
    pub semantic_event: X64TargetProfileEvent,
    pub execution_authority: X64TargetProspectiveExecutionAuthority,
    pub class: X64TargetProfileTemplateClass,
    pub start: u32,
    pub end: u32,
    pub static_bytes: u32,
    pub executions: u64,
    pub weighted_bytes: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum X64TargetProspectiveLabelDisposition {
    Live,
    UnreachableTombstone,
    Policy14ConsumedTombstone,
    SharedJoinConsumedTombstone,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TargetProspectiveLabelReceipt {
    pub label: X64LabelId,
    pub owner: X64LabelOwner,
    pub code_offset: u32,
    pub owning_atom: u32,
    pub disposition: X64TargetProspectiveLabelDisposition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TargetProspectiveFixupReceipt {
    pub fixup_index: u32,
    pub owning_atom: u32,
    pub patch_offset: u32,
    pub target: X64LabelId,
    pub addend: i32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct X64TargetProspectiveMachineSemanticProof {
    /// `false` means no partial decoder result may be consumed.
    pub complete: bool,
    pub register_rows: u32,
    pub decoded_bytes: u64,
    pub decoded_instructions: u32,
    pub symbolic_nodes: u32,
    pub reference_route_events: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct X64TargetProspectiveSharedJoinRealization {
    /// `false` is the exact fail-closed policy-1.4 fallback: every other
    /// field and vector in this structure is zero or empty.
    pub complete: bool,
    pub baseline_code_bytes: u64,
    pub baseline_code_hash: SemanticHash,
    pub candidate_code_bytes: u64,
    pub candidate_code_hash: SemanticHash,
    pub code_bytes_added: u64,
    pub code_bytes_removed: u64,
    pub baseline_atom_count: u64,
    pub candidate_atom_count: u64,
    pub atom_count_added: u64,
    pub atom_count_removed: u64,
    pub label_count: u64,
    pub baseline_fixup_count: u64,
    pub candidate_fixup_count: u64,
    pub fixup_count_added: u64,
    pub fixup_count_removed: u64,
    pub body_replicas: u32,
    pub shared_join_authority_atoms: u32,
    pub candidate_weighted_template_bytes: u128,
    pub machine_semantic_proof: X64TargetProspectiveMachineSemanticProof,
    pub atoms: Vec<X64TargetProspectiveRealizationAtom>,
    pub labels: Vec<X64TargetProspectiveLabelReceipt>,
    pub fixups: Vec<X64TargetProspectiveFixupReceipt>,
    pub realization_hash: SemanticHash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TargetProfileSite {
    pub event: X64TargetProfileEvent,
    pub class: X64TargetProfileTemplateClass,
    pub start: u32,
    pub end: u32,
    pub static_bytes: u32,
    pub executions: u64,
    /// `static_bytes * executions`, an exact deterministic template-weight
    /// proxy. It is deliberately not a hardware-cycle claim.
    pub weighted_bytes: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TargetProfileClassTotal {
    pub class: X64TargetProfileTemplateClass,
    pub sites: u32,
    pub static_bytes: u64,
    pub executions: u64,
    pub weighted_bytes: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TargetExecutionProfile {
    pub schema_version: (u16, u16, u16),
    pub policy_version: (u16, u16, u16),
    pub target_semantic_hash: SemanticHash,
    pub target_plan_hash: SemanticHash,
    pub target_code_hash: SemanticHash,
    pub encoder_policy_version: (u16, u16, u16),
    pub optimized_realization: bool,
    pub evaluation_steps: u64,
    pub observer_updates: u64,
    pub instruction_counts: X64TargetProfileInstructionCounts,
    pub control_counts: X64TargetProfileControlCounts,
    pub block_counts: Vec<X64TargetProfileBlockCount>,
    pub edge_counts: Vec<X64TargetProfileEdgeCount>,
    pub shared_join_opportunities: Vec<X64TargetSharedJoinOpportunity>,
    pub shared_join_composition: X64TargetSharedJoinComposition,
    pub prospective_shared_join_realization: X64TargetProspectiveSharedJoinRealization,
    pub sites: Vec<X64TargetProfileSite>,
    pub class_totals: Vec<X64TargetProfileClassTotal>,
    pub static_code_bytes: u64,
    pub weighted_template_bytes: u128,
}

#[derive(Clone, Debug, PartialEq)]
pub struct X64TargetProfiledEvaluation {
    pub evaluation: Evaluation,
    pub profile: X64TargetExecutionProfile,
}

#[derive(Debug)]
pub enum X64TargetProfileError {
    InvalidArtifact(X64TargetVerificationErrors),
    Execution(PlanExecutionError),
    EncoderReplay(String),
    EncoderReplayMismatch { field: &'static str },
    CounterOverflow { field: &'static str },
    InternalInvariant(String),
}

impl fmt::Display for X64TargetProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArtifact(errors) => write!(formatter, "{errors}"),
            Self::Execution(error) => write!(formatter, "{error}"),
            Self::EncoderReplay(error) => {
                write!(
                    formatter,
                    "x86-64 target profile encoder replay failed: {error}"
                )
            }
            Self::EncoderReplayMismatch { field } => {
                write!(formatter, "x86-64 target profile replay differs at {field}")
            }
            Self::CounterOverflow { field } => {
                write!(
                    formatter,
                    "x86-64 target profile counter overflowed {field}"
                )
            }
            Self::InternalInvariant(message) => {
                write!(
                    formatter,
                    "x86-64 target profile invariant failed: {message}"
                )
            }
        }
    }
}

impl std::error::Error for X64TargetProfileError {}

pub fn profile_x64_target_plan(
    artifact: &X64TargetArtifact,
    arguments: Vec<CoreValue>,
    budget: EvaluationBudget,
) -> Result<X64TargetProfiledEvaluation, X64TargetProfileError> {
    let verified =
        verify_x64_target_r1_s7a(artifact).map_err(X64TargetProfileError::InvalidArtifact)?;
    profile_verified_program(
        verified.program(),
        verified.semantic_hash(),
        arguments,
        budget,
    )
}

pub fn profile_source_bound_x64_target_plan(
    bound: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
    arguments: Vec<CoreValue>,
    budget: EvaluationBudget,
) -> Result<X64TargetProfiledEvaluation, X64TargetProfileError> {
    profile_verified_program(bound.program(), bound.semantic_hash(), arguments, budget)
}

fn profile_verified_program(
    program: &X64TargetProgram,
    semantic_hash: SemanticHash,
    arguments: Vec<CoreValue>,
    budget: EvaluationBudget,
) -> Result<X64TargetProfiledEvaluation, X64TargetProfileError> {
    let replayed = raw::encode(program)
        .map_err(|error| X64TargetProfileError::EncoderReplay(error.to_string()))?;
    if replayed.labels != program.labels {
        return Err(X64TargetProfileError::EncoderReplayMismatch { field: "labels" });
    }
    if replayed.fixups != program.fixups {
        return Err(X64TargetProfileError::EncoderReplayMismatch { field: "fixups" });
    }
    if replayed.code != program.code {
        return Err(X64TargetProfileError::EncoderReplayMismatch { field: "code" });
    }

    let observer = ProfileObserver::new(program, &replayed.realization.shared_join_composition)?;
    let (evaluation, observer) = evaluate_program_with_observer(
        program,
        arguments,
        budget,
        X64_TARGET_MAX_PROFILE_EVAL_WORK,
        observer,
    )
    .map_err(X64TargetProfileError::Execution)?;
    let profile = build_profile(
        program,
        semantic_hash,
        evaluation.steps,
        observer,
        replayed.realization,
        replayed.prospective_shadow,
    )?;
    Ok(X64TargetProfiledEvaluation {
        evaluation,
        profile,
    })
}

#[derive(Clone, Copy, Debug)]
struct ActiveSharedJoinBranch {
    step: usize,
    ingress: usize,
    next_event: usize,
}

struct SharedJoinBranchDescriptor {
    target: X64LabelId,
    path: RawSharedJoinBranchPath,
    routes: Vec<Vec<RawSharedJoinLineageEvent>>,
}

struct SharedJoinBranchObserver {
    activation_by_tail: Vec<Option<(usize, usize)>>,
    step_by_compare: Vec<Option<usize>>,
    known_branch_labels: Vec<bool>,
    descriptors: Vec<SharedJoinBranchDescriptor>,
    active: Option<ActiveSharedJoinBranch>,
    branch_then: Vec<Vec<u64>>,
    branch_else: Vec<Vec<u64>>,
}

impl SharedJoinBranchObserver {
    fn new(
        program: &X64TargetProgram,
        composition: &RawSharedJoinComposition,
    ) -> Result<Self, X64TargetProfileError> {
        let label_count = program.labels.len();
        let mut observer = Self {
            activation_by_tail: vec![None; label_count],
            step_by_compare: vec![None; label_count],
            known_branch_labels: vec![false; label_count],
            descriptors: Vec::new(),
            active: None,
            branch_then: Vec::new(),
            branch_else: Vec::new(),
        };
        if !composition.complete {
            if !composition.steps.is_empty() || composition.body_replicas != 0 {
                return Err(X64TargetProfileError::InternalInvariant(
                    "incomplete shared-join composition contains branch authority".to_owned(),
                ));
            }
            return Ok(observer);
        }

        let mut seen_targets = BTreeSet::new();
        let mut previous_targets = BTreeMap::new();
        for step in &composition.steps {
            if !seen_targets.insert(step.target) {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "shared-join branch preflight repeats target {}",
                    step.target.0
                )));
            }
            let mut previous_ancestor = None;
            for ancestor in &step.ancestors {
                if previous_ancestor.is_some_and(|previous| previous >= *ancestor)
                    || previous_targets.get(ancestor)
                        != Some(&RawSharedJoinKind::RegisterInstruction)
                {
                    return Err(X64TargetProfileError::InternalInvariant(format!(
                        "shared-join branch preflight rejects target {} ancestors",
                        step.target.0
                    )));
                }
                previous_ancestor = Some(*ancestor);
            }

            match (step.kind, step.branch_path) {
                (RawSharedJoinKind::RegisterInstruction, None) => {}
                (RawSharedJoinKind::FusedCompare, Some(path)) => {
                    observer.add_compare_step(program, step, path)?;
                }
                _ => {
                    return Err(X64TargetProfileError::InternalInvariant(format!(
                        "shared-join target {} has inconsistent branch path metadata",
                        step.target.0
                    )));
                }
            }
            previous_targets.insert(step.target, step.kind);
        }
        for descriptor in &observer.descriptors {
            for route in &descriptor.routes {
                for event in route.iter().skip(1) {
                    let RawSharedJoinLineageEvent::Tail { source, .. } = event else {
                        continue;
                    };
                    if observer
                        .activation_by_tail
                        .get(source.0 as usize)
                        .copied()
                        .flatten()
                        .is_some()
                    {
                        return Err(X64TargetProfileError::InternalInvariant(format!(
                            "shared-join route to target {} crosses another branch authority {}",
                            descriptor.target.0, source.0
                        )));
                    }
                }
            }
        }
        Ok(observer)
    }

    fn add_compare_step(
        &mut self,
        program: &X64TargetProgram,
        step: &RawSharedJoinCompositionStep,
        path: RawSharedJoinBranchPath,
    ) -> Result<(), X64TargetProfileError> {
        let branch_step = self.descriptors.len();
        let compare_slot = self
            .step_by_compare
            .get_mut(step.target.0 as usize)
            .ok_or_else(|| {
                X64TargetProfileError::InternalInvariant(format!(
                    "shared-join compare target {} is outside dense authority state",
                    step.target.0
                ))
            })?;
        if compare_slot.replace(branch_step).is_some() {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "shared-join compare target {} repeats",
                step.target.0
            )));
        }
        let branch_slot = self
            .known_branch_labels
            .get_mut(path.branch_label.0 as usize)
            .ok_or_else(|| {
                X64TargetProfileError::InternalInvariant(format!(
                    "shared-join branch label {} is outside dense authority state",
                    path.branch_label.0
                ))
            })?;
        *branch_slot = true;
        let branch = block_for_label(program, path.branch_label)?;
        if !branch.instructions.is_empty()
            || !matches!(
                &branch.terminator,
                X64Terminator::BranchRel32 {
                    then_label,
                    else_label,
                    ..
                } if *then_label == path.then_label
                    && *else_label == path.else_label
                    && then_label != else_label
            )
        {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "shared-join branch label {} has a non-canonical exact path",
                path.branch_label.0
            )));
        }
        for label in [path.then_label, path.else_label] {
            if label.0 as usize >= self.known_branch_labels.len() {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "shared-join branch successor {} is outside dense authority state",
                    label.0
                )));
            }
        }

        let mut routes = Vec::with_capacity(step.ingresses.len());
        for (ingress_index, ingress) in step.ingresses.iter().enumerate() {
            let activation = self
                .activation_by_tail
                .get_mut(ingress.authority_trigger.0 as usize)
                .ok_or_else(|| {
                    X64TargetProfileError::InternalInvariant(format!(
                        "shared-join authority {} is outside dense authority state",
                        ingress.authority_trigger.0
                    ))
                })?;
            if activation.replace((branch_step, ingress_index)).is_some() {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "shared-join authority {} is ambiguous across compare clones",
                    ingress.authority_trigger.0
                )));
            }
            let route =
                canonical_shared_join_route(program, ingress.authority_trigger, step.target)?;
            let Some(raw_prefix) = route.get(..route.len().saturating_sub(2)) else {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "shared-join authority {} has an incomplete route",
                    ingress.authority_trigger.0
                )));
            };
            if raw_prefix != ingress.lineage.as_slice()
                || !matches!(
                    route.get(route.len().saturating_sub(2)),
                    Some(RawSharedJoinLineageEvent::Instruction { label, index: 0 })
                        if *label == step.target
                )
                || !matches!(
                    route.last(),
                    Some(RawSharedJoinLineageEvent::Tail { source, target })
                        if *source == step.target && *target == path.branch_label
                )
            {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "shared-join authority {} has a non-canonical exact route",
                    ingress.authority_trigger.0
                )));
            }
            routes.push(route);
        }
        self.descriptors.push(SharedJoinBranchDescriptor {
            target: step.target,
            path,
            routes,
        });
        self.branch_then.push(vec![0; step.ingresses.len()]);
        self.branch_else.push(vec![0; step.ingresses.len()]);
        Ok(())
    }

    fn observe_instruction(
        &mut self,
        label: X64LabelId,
        index: u32,
    ) -> Result<(), PlanExecutionError> {
        let Some(active) = self.active.as_mut() else {
            if self
                .step_by_compare
                .get(label.0 as usize)
                .copied()
                .flatten()
                .is_some()
            {
                return Err(PlanExecutionError::InternalInvariant(format!(
                    "shared-join compare target {} executed without an authority",
                    label.0
                )));
            }
            return Ok(());
        };
        let descriptor = &self.descriptors[active.step];
        let route = &descriptor.routes[active.ingress];
        if matches!(
            route.get(active.next_event),
            Some(RawSharedJoinLineageEvent::Instruction {
                label: expected_label,
                index: expected_index,
            }) if *expected_label == label && *expected_index == index
        ) {
            active.next_event = active.next_event.checked_add(1).ok_or_else(|| {
                PlanExecutionError::InternalInvariant(
                    "shared-join exact-route cursor overflowed".to_owned(),
                )
            })?;
            return Ok(());
        }
        Err(PlanExecutionError::InternalInvariant(format!(
            "shared-join authority for target {} crossed non-canonical instruction {}",
            descriptor.target.0, label.0
        )))
    }

    fn observe_tail(
        &mut self,
        source: X64LabelId,
        target: X64LabelId,
    ) -> Result<(), PlanExecutionError> {
        if let Some((step, ingress)) = self
            .activation_by_tail
            .get(source.0 as usize)
            .copied()
            .flatten()
        {
            if self.active.is_some() {
                return Err(PlanExecutionError::InternalInvariant(
                    "shared-join branch authority reactivated before consumption".to_owned(),
                ));
            }
            let descriptor = &self.descriptors[step];
            let route = &descriptor.routes[ingress];
            if !matches!(
                route.first(),
                Some(RawSharedJoinLineageEvent::Tail {
                    source: expected_source,
                    target: expected_target,
                }) if *expected_source == source && *expected_target == target
            ) {
                return Err(PlanExecutionError::InternalInvariant(format!(
                    "shared-join authority {} activated on a non-canonical tail edge",
                    source.0
                )));
            }
            self.active = Some(ActiveSharedJoinBranch {
                step,
                ingress,
                next_event: 1,
            });
            return Ok(());
        }

        let Some(active) = self.active.as_mut() else {
            return Ok(());
        };
        let descriptor = &self.descriptors[active.step];
        let route = &descriptor.routes[active.ingress];
        if matches!(
            route.get(active.next_event),
            Some(RawSharedJoinLineageEvent::Tail {
                source: expected_source,
                target: expected_target,
            }) if *expected_source == source && *expected_target == target
        ) {
            active.next_event = active.next_event.checked_add(1).ok_or_else(|| {
                PlanExecutionError::InternalInvariant(
                    "shared-join exact-route cursor overflowed".to_owned(),
                )
            })?;
            return Ok(());
        }
        Err(PlanExecutionError::InternalInvariant(format!(
            "shared-join authority for target {} crossed a non-canonical tail edge",
            descriptor.target.0
        )))
    }

    fn observe_branch(
        &mut self,
        source: X64LabelId,
        target: X64LabelId,
        then_selected: bool,
    ) -> Result<(), PlanExecutionError> {
        let Some(active) = self.active.take() else {
            if self
                .known_branch_labels
                .get(source.0 as usize)
                .copied()
                .unwrap_or(false)
            {
                return Err(PlanExecutionError::InternalInvariant(format!(
                    "shared-join branch label {} executed without an authority",
                    source.0
                )));
            }
            return Ok(());
        };
        let descriptor = &self.descriptors[active.step];
        let route = &descriptor.routes[active.ingress];
        let expected_target = if then_selected {
            descriptor.path.then_label
        } else {
            descriptor.path.else_label
        };
        if active.next_event != route.len()
            || source != descriptor.path.branch_label
            || target != expected_target
        {
            return Err(PlanExecutionError::InternalInvariant(format!(
                "shared-join authority for target {} reached a different branch outcome",
                descriptor.target.0
            )));
        }
        let counts = if then_selected {
            &mut self.branch_then
        } else {
            &mut self.branch_else
        };
        let count = counts
            .get_mut(active.step)
            .and_then(|counts| counts.get_mut(active.ingress))
            .ok_or_else(|| {
                PlanExecutionError::InternalInvariant(
                    "shared-join branch authority index is outside dense counts".to_owned(),
                )
            })?;
        increment_counter(count, 1, "shared-join branch cross-tab")?;
        Ok(())
    }

    fn observe_terminal(&self) -> Result<(), PlanExecutionError> {
        if self.active.is_some() {
            return Err(PlanExecutionError::InternalInvariant(
                "shared-join branch authority reached a terminal outcome".to_owned(),
            ));
        }
        Ok(())
    }
}

struct ProfileObserver {
    block_counts: Vec<u64>,
    instruction_counts: Vec<Vec<u64>>,
    return_counts: Vec<u64>,
    branch_then_counts: Vec<u64>,
    branch_else_counts: Vec<u64>,
    tail_counts: Vec<u64>,
    entries: u64,
    bounds_exits: u64,
    tail_argument_values: u64,
    tail_argument_words: u64,
    tail_transfer_work: u64,
    updates: u64,
    shared_join_branches: SharedJoinBranchObserver,
}

impl ProfileObserver {
    fn new(
        program: &X64TargetProgram,
        composition: &RawSharedJoinComposition,
    ) -> Result<Self, X64TargetProfileError> {
        let label_count = program.labels.len();
        let mut instruction_counts = vec![Vec::new(); label_count];
        for function in &program.functions {
            for block in &function.blocks {
                instruction_counts[block.label.0 as usize] = vec![0; block.instructions.len()];
            }
        }
        Ok(Self {
            block_counts: vec![0; label_count],
            instruction_counts,
            return_counts: vec![0; label_count],
            branch_then_counts: vec![0; label_count],
            branch_else_counts: vec![0; label_count],
            tail_counts: vec![0; label_count],
            entries: 0,
            bounds_exits: 0,
            tail_argument_values: 0,
            tail_argument_words: 0,
            tail_transfer_work: 0,
            updates: 0,
            shared_join_branches: SharedJoinBranchObserver::new(program, composition)?,
        })
    }

    fn raw_event_count(&self, event: RawExecutionEvent) -> Result<u64, X64TargetProfileError> {
        let label_count = |counts: &[u64], label: X64LabelId| {
            counts.get(label.0 as usize).copied().ok_or_else(|| {
                X64TargetProfileError::InternalInvariant(format!(
                    "realization event names missing label {}",
                    label.0
                ))
            })
        };
        match event {
            RawExecutionEvent::Entry => Ok(self.entries),
            RawExecutionEvent::Instruction { label, index } => self
                .instruction_counts
                .get(label.0 as usize)
                .and_then(|counts| counts.get(index as usize))
                .copied()
                .ok_or_else(|| {
                    X64TargetProfileError::InternalInvariant(format!(
                        "realization event names missing instruction {}:{}",
                        label.0, index
                    ))
                }),
            RawExecutionEvent::Tail { label } => label_count(&self.tail_counts, label),
            RawExecutionEvent::Return { label } => label_count(&self.return_counts, label),
            RawExecutionEvent::Branch { label } => label_count(&self.branch_then_counts, label)?
                .checked_add(label_count(&self.branch_else_counts, label)?)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "raw branch event count",
                }),
            RawExecutionEvent::BranchElse { label } => label_count(&self.branch_else_counts, label),
            RawExecutionEvent::ReturnEpilogue => checked_sum(
                self.return_counts.iter().copied(),
                "return epilogue event count",
            ),
            RawExecutionEvent::BoundsEpilogue => Ok(self.bounds_exits),
            RawExecutionEvent::Static => Ok(0),
        }
    }
}

impl PlanExecutionObserver for ProfileObserver {
    fn observe(&mut self, event: PlanExecutionEvent) -> Result<(), PlanExecutionError> {
        self.updates =
            self.updates
                .checked_add(1)
                .ok_or(PlanExecutionError::ProfileCounterOverflow {
                    field: "observer updates",
                })?;
        match event {
            PlanExecutionEvent::Entry { label } => {
                increment_dense(&mut self.block_counts, label, "entry block count")?;
                increment_counter(&mut self.entries, 1, "entry count")?;
            }
            PlanExecutionEvent::Instruction { label, index } => {
                self.shared_join_branches
                    .observe_instruction(label, index)?;
                let counts = self
                    .instruction_counts
                    .get_mut(label.0 as usize)
                    .and_then(|counts| counts.get_mut(index as usize))
                    .ok_or_else(|| {
                        PlanExecutionError::InternalInvariant(format!(
                            "profile instruction event {}:{} is outside the verified plan",
                            label.0, index
                        ))
                    })?;
                increment_counter(counts, 1, "instruction count")?;
            }
            PlanExecutionEvent::BranchThen {
                label: source,
                target,
            } => {
                self.shared_join_branches
                    .observe_branch(source, target, true)?;
                increment_dense(&mut self.branch_then_counts, source, "then-branch count")?;
                increment_dense(&mut self.block_counts, target, "branch target count")?;
            }
            PlanExecutionEvent::BranchElse {
                label: source,
                target,
            } => {
                self.shared_join_branches
                    .observe_branch(source, target, false)?;
                increment_dense(&mut self.branch_else_counts, source, "else-branch count")?;
                increment_dense(&mut self.block_counts, target, "branch target count")?;
            }
            PlanExecutionEvent::Tail {
                label: source,
                target,
                argument_count,
                argument_words,
            } => {
                self.shared_join_branches.observe_tail(source, target)?;
                increment_dense(&mut self.tail_counts, source, "tail count")?;
                increment_dense(&mut self.block_counts, target, "tail target count")?;
                increment_counter(
                    &mut self.tail_argument_values,
                    u64::from(argument_count),
                    "tail argument value count",
                )?;
                increment_counter(
                    &mut self.tail_argument_words,
                    u64::from(argument_words),
                    "tail argument word count",
                )?;
                let work = u64::from(argument_count)
                    .checked_mul(2)
                    .and_then(|work| work.checked_add(1))
                    .ok_or(PlanExecutionError::ProfileCounterOverflow {
                        field: "tail transfer work",
                    })?;
                increment_counter(&mut self.tail_transfer_work, work, "tail transfer work")?;
            }
            PlanExecutionEvent::Return { label } => {
                self.shared_join_branches.observe_terminal()?;
                increment_dense(&mut self.return_counts, label, "return count")?;
            }
            PlanExecutionEvent::Bounds { .. } => {
                self.shared_join_branches.observe_terminal()?;
                increment_counter(&mut self.bounds_exits, 1, "Bounds exit count")?;
            }
        }
        Ok(())
    }
}

fn increment_dense(
    counts: &mut [u64],
    label: X64LabelId,
    field: &'static str,
) -> Result<(), PlanExecutionError> {
    let count = counts.get_mut(label.0 as usize).ok_or_else(|| {
        PlanExecutionError::InternalInvariant(format!(
            "profile event label {} is outside the verified plan",
            label.0
        ))
    })?;
    increment_counter(count, 1, field)
}

fn increment_counter(
    count: &mut u64,
    increment: u64,
    field: &'static str,
) -> Result<(), PlanExecutionError> {
    *count = count
        .checked_add(increment)
        .ok_or(PlanExecutionError::ProfileCounterOverflow { field })?;
    Ok(())
}

fn build_profile(
    program: &X64TargetProgram,
    semantic_hash: SemanticHash,
    evaluation_steps: u64,
    observer: ProfileObserver,
    realization: RawRealization,
    prospective_shadow: Option<RawProspectiveShadow>,
) -> Result<X64TargetExecutionProfile, X64TargetProfileError> {
    let mut instruction_counts = X64TargetProfileInstructionCounts::default();
    for function in &program.functions {
        for block in &function.blocks {
            let label_index = block.label.0 as usize;
            let counts = observer
                .instruction_counts
                .get(label_index)
                .ok_or_else(|| {
                    X64TargetProfileError::InternalInvariant(format!(
                        "missing dense instruction counters for label {}",
                        block.label.0
                    ))
                })?;
            for (index, count) in counts.iter().copied().enumerate() {
                if count == 0 {
                    continue;
                }
                let index =
                    u32::try_from(index).map_err(|_| X64TargetProfileError::CounterOverflow {
                        field: "instruction counter index",
                    })?;
                count_instruction(program, block.label, index, count, &mut instruction_counts)?;
            }
        }
    }

    let returns = checked_sum(observer.return_counts.iter().copied(), "return count")?;
    let branch_then = checked_sum(
        observer.branch_then_counts.iter().copied(),
        "then-branch count",
    )?;
    let branch_else = checked_sum(
        observer.branch_else_counts.iter().copied(),
        "else-branch count",
    )?;
    let branches =
        branch_then
            .checked_add(branch_else)
            .ok_or(X64TargetProfileError::CounterOverflow {
                field: "branch count",
            })?;
    let tail_transfers = checked_sum(observer.tail_counts.iter().copied(), "tail-transfer count")?;
    let control_counts = X64TargetProfileControlCounts {
        entries: observer.entries,
        returns,
        branches,
        branch_then,
        branch_else,
        tail_transfers,
        tail_argument_values: observer.tail_argument_values,
        tail_argument_words: observer.tail_argument_words,
        bounds_exits: observer.bounds_exits,
    };

    validate_control_flow(
        program,
        evaluation_steps,
        &observer,
        instruction_counts,
        control_counts,
    )?;

    let shared_join_opportunities =
        build_shared_join_opportunities(&observer, &realization.shared_join_opportunities)?;
    let shared_join_composition = build_shared_join_composition(
        program,
        &observer,
        &realization.shared_join_composition,
        &shared_join_opportunities,
    )?;
    let prospective_shared_join_realization = build_prospective_shared_join_realization(
        program,
        &observer,
        &realization.atoms,
        &realization.prospective_shared_join_realization,
        prospective_shadow.as_ref(),
        &shared_join_composition,
    )?;
    let mut class_totals =
        BTreeMap::<X64TargetProfileTemplateClass, X64TargetProfileClassTotal>::new();
    let mut sites = Vec::with_capacity(realization.atoms.len());
    let mut weighted_template_bytes = 0_u128;
    for atom in realization.atoms {
        let executions = observer.raw_event_count(atom.event)?;
        let static_bytes = atom.byte_len();
        let weighted_bytes = u128::from(static_bytes)
            .checked_mul(u128::from(executions))
            .ok_or(X64TargetProfileError::CounterOverflow {
                field: "site weighted bytes",
            })?;
        weighted_template_bytes = weighted_template_bytes.checked_add(weighted_bytes).ok_or(
            X64TargetProfileError::CounterOverflow {
                field: "total weighted bytes",
            },
        )?;
        let class = X64TargetProfileTemplateClass::from(atom.class);
        let total = class_totals
            .entry(class)
            .or_insert(X64TargetProfileClassTotal {
                class,
                sites: 0,
                static_bytes: 0,
                executions: 0,
                weighted_bytes: 0,
            });
        total.sites = total
            .sites
            .checked_add(1)
            .ok_or(X64TargetProfileError::CounterOverflow {
                field: "class site count",
            })?;
        total.static_bytes = total
            .static_bytes
            .checked_add(u64::from(static_bytes))
            .ok_or(X64TargetProfileError::CounterOverflow {
                field: "class static bytes",
            })?;
        total.executions = total.executions.checked_add(executions).ok_or(
            X64TargetProfileError::CounterOverflow {
                field: "class executions",
            },
        )?;
        total.weighted_bytes = total.weighted_bytes.checked_add(weighted_bytes).ok_or(
            X64TargetProfileError::CounterOverflow {
                field: "class weighted bytes",
            },
        )?;
        sites.push(X64TargetProfileSite {
            event: X64TargetProfileEvent::from(atom.event),
            class,
            start: atom.start,
            end: atom.end,
            static_bytes,
            executions,
            weighted_bytes,
        });
    }

    let static_code_bytes =
        u64::try_from(program.code.len()).map_err(|_| X64TargetProfileError::CounterOverflow {
            field: "static code bytes",
        })?;
    let block_counts = observer
        .block_counts
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, entries)| *entries != 0)
        .map(|(label, entries)| {
            u32::try_from(label)
                .map(|label| X64TargetProfileBlockCount {
                    label: X64LabelId(label),
                    entries,
                })
                .map_err(|_| X64TargetProfileError::CounterOverflow {
                    field: "block count label",
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut edge_map = BTreeMap::<(X64LabelId, X64LabelId), u64>::new();
    for function in &program.functions {
        for block in &function.blocks {
            let source_index = block.label.0 as usize;
            match &block.terminator {
                X64Terminator::Return { .. } => {}
                X64Terminator::BranchRel32 {
                    then_label,
                    else_label,
                    ..
                } => {
                    let then_count = observer.branch_then_counts[source_index];
                    if then_count != 0 {
                        checked_increment(&mut edge_map, (block.label, *then_label), then_count)?;
                    }
                    let else_count = observer.branch_else_counts[source_index];
                    if else_count != 0 {
                        checked_increment(&mut edge_map, (block.label, *else_label), else_count)?;
                    }
                }
                X64Terminator::TailJumpRel32 { target_label, .. } => {
                    let count = observer.tail_counts[source_index];
                    if count != 0 {
                        checked_increment(&mut edge_map, (block.label, *target_label), count)?;
                    }
                }
            }
        }
    }
    let edge_counts = edge_map
        .into_iter()
        .map(|((source, target), traversals)| X64TargetProfileEdgeCount {
            source,
            target,
            traversals,
        })
        .collect();

    Ok(X64TargetExecutionProfile {
        schema_version: X64_TARGET_PROFILE_SCHEMA_VERSION,
        policy_version: X64_TARGET_PROFILE_POLICY_VERSION,
        target_semantic_hash: semantic_hash,
        target_plan_hash: program.plan_hash,
        target_code_hash: program.code_hash,
        encoder_policy_version: program.encoder_policy_version,
        optimized_realization: realization.optimized,
        evaluation_steps,
        observer_updates: observer.updates,
        instruction_counts,
        control_counts,
        block_counts,
        edge_counts,
        shared_join_opportunities,
        shared_join_composition,
        prospective_shared_join_realization,
        sites,
        class_totals: class_totals.into_values().collect(),
        static_code_bytes,
        weighted_template_bytes,
    })
}

fn build_shared_join_opportunities(
    observer: &ProfileObserver,
    raw: &[RawSharedJoinOpportunity],
) -> Result<Vec<X64TargetSharedJoinOpportunity>, X64TargetProfileError> {
    let mut opportunities = Vec::with_capacity(raw.len());
    let mut previous_target = None;
    for opportunity in raw {
        if previous_target.is_some_and(|previous| previous >= opportunity.target) {
            return Err(X64TargetProfileError::InternalInvariant(
                "shared-join opportunities are not strictly target ordered".to_owned(),
            ));
        }
        previous_target = Some(opportunity.target);
        let target_executions = observer
            .block_counts
            .get(opportunity.target.0 as usize)
            .copied()
            .ok_or_else(|| {
                X64TargetProfileError::InternalInvariant(format!(
                    "shared-join target {} is outside dense counters",
                    opportunity.target.0
                ))
            })?;
        let mut executions = 0_u64;
        let mut weighted_ingress_frame_accesses = 0_u128;
        let mut ingresses = Vec::with_capacity(opportunity.ingresses.len());
        let mut roots = BTreeMap::new();
        for ingress in &opportunity.ingresses {
            if roots.insert(ingress.root, ingress.trigger).is_some() {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "shared-join target {} repeats root {}",
                    opportunity.target.0, ingress.root.0
                )));
            }
            let count = observer.raw_event_count(RawExecutionEvent::Tail {
                label: ingress.trigger,
            })?;
            executions =
                executions
                    .checked_add(count)
                    .ok_or(X64TargetProfileError::CounterOverflow {
                        field: "shared-join executions",
                    })?;
            let weighted_frame_accesses = u128::from(ingress.frame_accesses)
                .checked_mul(u128::from(count))
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "shared-join ingress weighted frame accesses",
                })?;
            weighted_ingress_frame_accesses = weighted_ingress_frame_accesses
                .checked_add(weighted_frame_accesses)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "shared-join weighted frame accesses",
                })?;
            ingresses.push(X64TargetSharedJoinIngress {
                root: ingress.root,
                trigger: ingress.trigger,
                executions: count,
                frame_accesses_per_execution: ingress.frame_accesses,
                weighted_frame_accesses,
            });
        }
        if executions != target_executions {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "shared-join target {} has {target_executions} entries but {executions} proven incoming tails",
                opportunity.target.0
            )));
        }
        opportunities.push(X64TargetSharedJoinOpportunity {
            target: opportunity.target,
            kind: X64TargetSharedJoinKind::from(opportunity.kind),
            executions,
            ingresses,
            weighted_ingress_frame_accesses,
        });
    }
    Ok(opportunities)
}

fn build_shared_join_composition(
    program: &X64TargetProgram,
    observer: &ProfileObserver,
    raw: &RawSharedJoinComposition,
    opportunities: &[X64TargetSharedJoinOpportunity],
) -> Result<X64TargetSharedJoinComposition, X64TargetProfileError> {
    if !raw.complete {
        if !raw.steps.is_empty() || raw.body_replicas != 0 {
            return Err(X64TargetProfileError::InternalInvariant(
                "incomplete shared-join composition contains partial evidence".to_owned(),
            ));
        }
        return Ok(X64TargetSharedJoinComposition::default());
    }

    let opportunity_kinds = opportunities
        .iter()
        .map(|opportunity| (opportunity.target, opportunity.kind))
        .collect::<BTreeMap<_, _>>();
    if opportunity_kinds.len() != opportunities.len() || raw.steps.len() != opportunities.len() {
        return Err(X64TargetProfileError::InternalInvariant(
            "shared-join composition does not cover every independent opportunity".to_owned(),
        ));
    }

    let mut seen_targets = BTreeSet::new();
    let mut body_replicas = 0_u32;
    let mut total_executions = 0_u64;
    let mut total_weighted_frame_accesses = 0_u128;
    let mut steps = Vec::with_capacity(raw.steps.len());
    let mut branch_step = 0_usize;
    for step in &raw.steps {
        let kind = X64TargetSharedJoinKind::from(step.kind);
        if opportunity_kinds.get(&step.target).copied() != Some(kind)
            || !seen_targets.insert(step.target)
        {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "shared-join composition repeats or changes target {}",
                step.target.0
            )));
        }
        validate_shared_join_ancestors(step, &seen_targets)?;
        let branch_rows = match step.kind {
            RawSharedJoinKind::RegisterInstruction => {
                if step.branch_path.is_some() {
                    return Err(X64TargetProfileError::InternalInvariant(format!(
                        "register shared-join target {} carries branch metadata",
                        step.target.0
                    )));
                }
                None
            }
            RawSharedJoinKind::FusedCompare => {
                if step.branch_path.is_none()
                    || observer
                        .shared_join_branches
                        .descriptors
                        .get(branch_step)
                        .is_none_or(|descriptor| descriptor.target != step.target)
                {
                    return Err(X64TargetProfileError::InternalInvariant(format!(
                        "fused shared-join target {} has no canonical branch observer",
                        step.target.0
                    )));
                }
                let rows = (
                    observer
                        .shared_join_branches
                        .branch_then
                        .get(branch_step)
                        .ok_or_else(|| {
                            X64TargetProfileError::InternalInvariant(
                                "shared-join then cross-tab is incomplete".to_owned(),
                            )
                        })?,
                    observer
                        .shared_join_branches
                        .branch_else
                        .get(branch_step)
                        .ok_or_else(|| {
                            X64TargetProfileError::InternalInvariant(
                                "shared-join else cross-tab is incomplete".to_owned(),
                            )
                        })?,
                );
                branch_step =
                    branch_step
                        .checked_add(1)
                        .ok_or(X64TargetProfileError::CounterOverflow {
                            field: "shared-join branch step index",
                        })?;
                Some(rows)
            }
        };

        let target_executions = observer
            .block_counts
            .get(step.target.0 as usize)
            .copied()
            .ok_or_else(|| {
                X64TargetProfileError::InternalInvariant(format!(
                    "shared-join composition target {} is outside dense counters",
                    step.target.0
                ))
            })?;
        let mut previous_ingress = None;
        let mut roots = BTreeSet::new();
        let mut authorities = BTreeSet::new();
        let mut executions = 0_u64;
        let mut branch_then = 0_u64;
        let mut branch_else = 0_u64;
        let mut weighted_frame_accesses = 0_u128;
        let mut ingresses = Vec::with_capacity(step.ingresses.len());
        for (ingress_index, ingress) in step.ingresses.iter().enumerate() {
            let key = (ingress.root, ingress.authority_trigger);
            if previous_ingress.is_some_and(|previous| previous >= key)
                || !roots.insert(ingress.root)
                || !authorities.insert(ingress.authority_trigger)
            {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "shared-join composition target {} has non-canonical ingress ownership",
                    step.target.0
                )));
            }
            previous_ingress = Some(key);

            let count = observer.raw_event_count(RawExecutionEvent::Tail {
                label: ingress.authority_trigger,
            })?;
            executions =
                executions
                    .checked_add(count)
                    .ok_or(X64TargetProfileError::CounterOverflow {
                        field: "shared-join composition executions",
                    })?;
            let weighted = u128::from(ingress.frame_accesses)
                .checked_mul(u128::from(count))
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "shared-join composition ingress weighted frame accesses",
                })?;
            weighted_frame_accesses = weighted_frame_accesses.checked_add(weighted).ok_or(
                X64TargetProfileError::CounterOverflow {
                    field: "shared-join composition step weighted frame accesses",
                },
            )?;
            let branch_arm_counts = branch_rows
                .map(|(then_rows, else_rows)| {
                    let then_executions = then_rows.get(ingress_index).copied().ok_or_else(|| {
                        X64TargetProfileError::InternalInvariant(format!(
                            "shared-join target {} has no then row {}",
                            step.target.0, ingress_index
                        ))
                    })?;
                    let else_executions = else_rows.get(ingress_index).copied().ok_or_else(|| {
                        X64TargetProfileError::InternalInvariant(format!(
                            "shared-join target {} has no else row {}",
                            step.target.0, ingress_index
                        ))
                    })?;
                    let outcomes = then_executions.checked_add(else_executions).ok_or(
                        X64TargetProfileError::CounterOverflow {
                            field: "shared-join branch ingress outcomes",
                        },
                    )?;
                    if outcomes != count {
                        return Err(X64TargetProfileError::InternalInvariant(format!(
                            "shared-join target {} authority {} has {count} executions but {outcomes} branch outcomes",
                            step.target.0, ingress.authority_trigger.0
                        )));
                    }
                    branch_then = branch_then.checked_add(then_executions).ok_or(
                        X64TargetProfileError::CounterOverflow {
                            field: "shared-join branch then total",
                        },
                    )?;
                    branch_else = branch_else.checked_add(else_executions).ok_or(
                        X64TargetProfileError::CounterOverflow {
                            field: "shared-join branch else total",
                        },
                    )?;
                    Ok(X64TargetSharedJoinBranchArmCounts {
                        then_executions,
                        else_executions,
                    })
                })
                .transpose()?;
            let route =
                canonical_shared_join_route(program, ingress.authority_trigger, step.target)?;
            let raw_prefix = route.get(..route.len().saturating_sub(2)).ok_or_else(|| {
                X64TargetProfileError::InternalInvariant(format!(
                    "shared-join authority {} has an incomplete route",
                    ingress.authority_trigger.0
                ))
            })?;
            if raw_prefix != ingress.lineage.as_slice() {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "shared-join authority {} route differs from raw composition proof",
                    ingress.authority_trigger.0
                )));
            }
            ingresses.push(X64TargetSharedJoinCompositionIngress {
                root: ingress.root,
                authority_trigger: ingress.authority_trigger,
                route: route
                    .into_iter()
                    .map(X64TargetSharedJoinRouteEvent::from)
                    .collect(),
                executions: count,
                frame_accesses_per_execution: ingress.frame_accesses,
                weighted_frame_accesses: weighted,
                branch_arm_counts,
            });
        }
        if ingresses.len() < 2 || executions != target_executions {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "shared-join composition target {} has {target_executions} entries but {executions} uniquely owned incoming executions",
                step.target.0
            )));
        }
        if step.kind == RawSharedJoinKind::FusedCompare {
            let branch_executions = branch_then.checked_add(branch_else).ok_or(
                X64TargetProfileError::CounterOverflow {
                    field: "shared-join branch target outcomes",
                },
            )?;
            let instruction_executions = observer
                .instruction_counts
                .get(step.target.0 as usize)
                .and_then(|counts| counts.first())
                .copied()
                .ok_or_else(|| {
                    X64TargetProfileError::InternalInvariant(format!(
                        "shared-join compare target {} has no instruction counter",
                        step.target.0
                    ))
                })?;
            let tail_executions = observer
                .tail_counts
                .get(step.target.0 as usize)
                .copied()
                .ok_or_else(|| {
                    X64TargetProfileError::InternalInvariant(format!(
                        "shared-join compare target {} has no tail counter",
                        step.target.0
                    ))
                })?;
            if branch_executions != executions
                || instruction_executions != executions
                || tail_executions != executions
            {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "shared-join compare target {} branch cross-tab is not conservative",
                    step.target.0
                )));
            }
        }

        let replicas =
            u32::try_from(ingresses.len()).map_err(|_| X64TargetProfileError::CounterOverflow {
                field: "shared-join composition body replicas",
            })?;
        body_replicas =
            body_replicas
                .checked_add(replicas)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "shared-join composition total body replicas",
                })?;
        total_executions = total_executions.checked_add(executions).ok_or(
            X64TargetProfileError::CounterOverflow {
                field: "shared-join composition total executions",
            },
        )?;
        total_weighted_frame_accesses = total_weighted_frame_accesses
            .checked_add(weighted_frame_accesses)
            .ok_or(X64TargetProfileError::CounterOverflow {
                field: "shared-join composition total weighted frame accesses",
            })?;
        steps.push(X64TargetSharedJoinCompositionStep {
            target: step.target,
            kind,
            ancestors: step.ancestors.clone(),
            executions,
            ingresses,
            weighted_ingress_frame_accesses: weighted_frame_accesses,
        });
    }
    if seen_targets != opportunity_kinds.keys().copied().collect::<BTreeSet<_>>()
        || body_replicas != raw.body_replicas
        || branch_step != observer.shared_join_branches.descriptors.len()
        || observer.shared_join_branches.active.is_some()
    {
        return Err(X64TargetProfileError::InternalInvariant(
            "shared-join composition coverage or replica count mismatch".to_owned(),
        ));
    }

    Ok(X64TargetSharedJoinComposition {
        complete: true,
        steps,
        body_replicas,
        body_executions: total_executions,
        weighted_ingress_frame_accesses: total_weighted_frame_accesses,
    })
}

#[derive(Clone, Copy)]
struct ExpectedProspectiveAtom {
    class: RawTemplateClass,
    authority: X64TargetProspectiveExecutionAuthority,
    executions: u64,
}

fn build_prospective_shared_join_realization(
    program: &X64TargetProgram,
    observer: &ProfileObserver,
    baseline_atoms: &[RawRealizationAtom],
    raw: &RawProspectiveSharedJoinRealization,
    shadow: Option<&RawProspectiveShadow>,
    composition: &X64TargetSharedJoinComposition,
) -> Result<X64TargetProspectiveSharedJoinRealization, X64TargetProfileError> {
    if !raw.complete {
        if raw != &RawProspectiveSharedJoinRealization::default() || shadow.is_some() {
            return Err(X64TargetProfileError::InternalInvariant(
                "incomplete prospective realization retains partial evidence".to_owned(),
            ));
        }
        return Ok(X64TargetProspectiveSharedJoinRealization::default());
    }
    let shadow = shadow.ok_or_else(|| {
        X64TargetProfileError::InternalInvariant(
            "complete prospective realization has no transient shadow".to_owned(),
        )
    })?;
    if !composition.complete
        || composition.steps.is_empty()
        || composition.steps.len() > MAX_PROSPECTIVE_SHARED_JOIN_TARGETS
        || composition.body_replicas == 0
        || composition.body_replicas > MAX_PROSPECTIVE_SHARED_JOIN_REPLICAS
    {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective realization has no admissible composition".to_owned(),
        ));
    }
    let mut replay_budget =
        prospective_replay_budget(program, baseline_atoms, shadow, composition)?;

    let baseline_code_bytes =
        checked_usize_to_u64(program.code.len(), "prospective baseline code")?;
    let candidate_code_bytes =
        checked_usize_to_u64(shadow.code.len(), "prospective candidate code")?;
    let baseline_atom_count =
        checked_usize_to_u64(baseline_atoms.len(), "prospective baseline atom count")?;
    let candidate_atom_count =
        checked_usize_to_u64(shadow.atoms.len(), "prospective candidate atom count")?;
    let baseline_fixup_count =
        checked_usize_to_u64(program.fixups.len(), "prospective baseline fixup count")?;
    let candidate_fixup_count =
        checked_usize_to_u64(shadow.fixups.len(), "prospective candidate fixup count")?;
    let label_count = checked_usize_to_u64(shadow.labels.len(), "prospective label count")?;
    let (code_bytes_added, code_bytes_removed) =
        normalized_prospective_delta(baseline_code_bytes, candidate_code_bytes)?;
    let (atom_count_added, atom_count_removed) =
        normalized_prospective_delta(baseline_atom_count, candidate_atom_count)?;
    let (fixup_count_added, fixup_count_removed) =
        normalized_prospective_delta(baseline_fixup_count, candidate_fixup_count)?;

    replay_budget.charge_usize(shadow.code.len(), "prospective candidate hash byte replay")?;
    let candidate_code_hash = prospective_shared_join_code_hash(&shadow.code)?;
    let global_code_limit = program.limits.max_code_bytes.min(X64_TARGET_MAX_CODE_BYTES);
    let global_fixup_limit = program.limits.max_fixups.min(X64_TARGET_MAX_FIXUPS);
    let growth_cap = (baseline_code_bytes / 4).min(MAX_PROSPECTIVE_POSITIVE_CODE_GROWTH);
    let atom_cap = baseline_atom_count
        .checked_add(
            u64::from(composition.body_replicas)
                .checked_mul(MAX_PROSPECTIVE_ATOMS_PER_REPLICA)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "prospective atom cap",
                })?,
        )
        .ok_or(X64TargetProfileError::CounterOverflow {
            field: "prospective atom cap",
        })?;
    let fixup_cap = baseline_fixup_count
        .checked_add(
            u64::from(composition.body_replicas)
                .checked_mul(MAX_PROSPECTIVE_FIXUPS_PER_REPLICA)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "prospective fixup cap",
                })?,
        )
        .ok_or(X64TargetProfileError::CounterOverflow {
            field: "prospective fixup cap",
        })?;
    if baseline_code_bytes != raw.baseline_code_bytes
        || program.code_hash != raw.baseline_code_hash
        || candidate_code_bytes != raw.candidate_code_bytes
        || candidate_code_hash != raw.candidate_code_hash
        || code_bytes_added != raw.code_bytes_added
        || code_bytes_removed != raw.code_bytes_removed
        || baseline_atom_count != raw.baseline_atom_count
        || candidate_atom_count != raw.candidate_atom_count
        || atom_count_added != raw.atom_count_added
        || atom_count_removed != raw.atom_count_removed
        || baseline_fixup_count != raw.baseline_fixup_count
        || candidate_fixup_count != raw.candidate_fixup_count
        || fixup_count_added != raw.fixup_count_added
        || fixup_count_removed != raw.fixup_count_removed
        || raw.body_replicas != composition.body_replicas
        || label_count != checked_usize_to_u64(program.labels.len(), "target label count")?
        || candidate_code_bytes > global_code_limit
        || candidate_fixup_count > global_fixup_limit
        || code_bytes_added > growth_cap
        || candidate_atom_count > atom_cap
        || candidate_fixup_count > fixup_cap
    {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective realization summary or cap differs from independent replay".to_owned(),
        ));
    }

    validate_prospective_atom_coverage(&shadow.atoms, candidate_code_bytes)?;
    let baseline_atom_starts = realization_atom_starts(baseline_atoms)?;
    let candidate_atom_starts = realization_atom_starts(&shadow.atoms)?;
    let selected_targets = composition
        .steps
        .iter()
        .map(|step| step.target)
        .collect::<BTreeSet<_>>();
    if selected_targets.len() != composition.steps.len() {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective realization repeats selected target".to_owned(),
        ));
    }
    let policy14_consumed_labels = prospective_policy14_consumed_labels(program, baseline_atoms)?;

    let mut label_offsets = BTreeMap::<u32, X64LabelId>::new();
    let mut label_dispositions = BTreeMap::new();
    let mut labels = Vec::with_capacity(shadow.labels.len());
    let mut previous_candidate_label_offset = None;
    if shadow.labels.len() != program.labels.len() || raw.labels.len() != shadow.labels.len() {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective realization changes the declared label set".to_owned(),
        ));
    }
    for ((declared, candidate), receipt) in
        program.labels.iter().zip(&shadow.labels).zip(&raw.labels)
    {
        if previous_candidate_label_offset.is_some_and(|previous| candidate.code_offset <= previous)
        {
            return Err(X64TargetProfileError::InternalInvariant(
                "prospective labels are not strictly offset ordered by declared identity"
                    .to_owned(),
            ));
        }
        previous_candidate_label_offset = Some(candidate.code_offset);
        if candidate.id != declared.id
            || candidate.owner != declared.owner
            || receipt.label != candidate.id
            || receipt.owner != candidate.owner
            || receipt.code_offset != candidate.code_offset
            || label_offsets
                .insert(candidate.code_offset, candidate.id)
                .is_some()
        {
            return Err(X64TargetProfileError::InternalInvariant(
                "prospective label identity, order, or offset is non-canonical".to_owned(),
            ));
        }
        let owning_atom = *candidate_atom_starts
            .get(&candidate.code_offset)
            .ok_or_else(|| {
                X64TargetProfileError::InternalInvariant(format!(
                    "prospective label {} does not own an atom start",
                    candidate.id.0
                ))
            })?;
        let owning_atom_u32 =
            u32::try_from(owning_atom).map_err(|_| X64TargetProfileError::CounterOverflow {
                field: "prospective label owning atom",
            })?;
        if receipt.owning_atom != owning_atom_u32 {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "prospective label {} names a different atom owner",
                candidate.id.0
            )));
        }
        let atom = &shadow.atoms[owning_atom];
        let baseline_atom = baseline_atom_starts
            .get(&declared.code_offset)
            .and_then(|index| baseline_atoms.get(*index))
            .ok_or_else(|| {
                X64TargetProfileError::InternalInvariant(format!(
                    "baseline label {} does not own an atom start",
                    declared.id.0
                ))
            })?;
        let disposition = prospective_label_disposition(receipt.disposition);
        let selected = selected_targets.contains(&candidate.id);
        let expected_disposition = if selected {
            X64TargetProspectiveLabelDisposition::SharedJoinConsumedTombstone
        } else if baseline_atom.class == RawTemplateClass::Tombstone {
            if policy14_consumed_labels.contains(&candidate.id) {
                X64TargetProspectiveLabelDisposition::Policy14ConsumedTombstone
            } else {
                X64TargetProspectiveLabelDisposition::UnreachableTombstone
            }
        } else {
            X64TargetProspectiveLabelDisposition::Live
        };
        if disposition != expected_disposition {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "prospective label {} disposition {disposition:?} differs from independent policy-1.4 replay {expected_disposition:?}",
                candidate.id.0,
            )));
        }
        match disposition {
            X64TargetProspectiveLabelDisposition::Live => {
                if selected
                    || atom.class == RawTemplateClass::Tombstone
                    || baseline_atom.class == RawTemplateClass::Tombstone
                {
                    return Err(X64TargetProfileError::InternalInvariant(format!(
                        "prospective live label {} has non-live ownership",
                        candidate.id.0
                    )));
                }
            }
            X64TargetProspectiveLabelDisposition::UnreachableTombstone
            | X64TargetProspectiveLabelDisposition::Policy14ConsumedTombstone => {
                if selected || baseline_atom.class != RawTemplateClass::Tombstone {
                    return Err(X64TargetProfileError::InternalInvariant(format!(
                        "prospective label {} changes an accepted policy-1.4 tombstone",
                        candidate.id.0
                    )));
                }
                validate_prospective_tombstone(&shadow.code, atom, candidate.id)?;
            }
            X64TargetProspectiveLabelDisposition::SharedJoinConsumedTombstone => {
                if !selected || baseline_atom.class == RawTemplateClass::Tombstone {
                    return Err(X64TargetProfileError::InternalInvariant(format!(
                        "prospective label {} is not an exact selected shared target",
                        candidate.id.0
                    )));
                }
                validate_prospective_tombstone(&shadow.code, atom, candidate.id)?;
            }
        }
        if label_dispositions
            .insert(candidate.id, disposition)
            .is_some()
        {
            return Err(X64TargetProfileError::InternalInvariant(
                "prospective realization repeats label disposition".to_owned(),
            ));
        }
        labels.push(X64TargetProspectiveLabelReceipt {
            label: candidate.id,
            owner: candidate.owner,
            code_offset: candidate.code_offset,
            owning_atom: owning_atom_u32,
            disposition,
        });
    }
    let replayed_selected_targets = labels
        .iter()
        .filter_map(|receipt| {
            (receipt.disposition
                == X64TargetProspectiveLabelDisposition::SharedJoinConsumedTombstone)
                .then_some(receipt.label)
        })
        .collect::<BTreeSet<_>>();
    if replayed_selected_targets != selected_targets {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective shared-target tombstone set differs from composition".to_owned(),
        ));
    }
    let declared_tombstone_offsets = labels
        .iter()
        .filter_map(|receipt| {
            (receipt.disposition != X64TargetProspectiveLabelDisposition::Live)
                .then_some(receipt.code_offset)
        })
        .collect::<BTreeSet<_>>();

    let (mut expected_atoms, selected_events, mut expected_atoms_by_root) =
        expected_prospective_atoms(program, composition)?;
    let mut expected_shared_order = Vec::with_capacity(expected_atoms.len());
    for owner in label_offsets.values() {
        if let Some(events) = expected_atoms_by_root.remove(owner) {
            expected_shared_order.extend(events.into_iter().map(|event| (*owner, event)));
        }
    }
    if !expected_atoms_by_root.is_empty() {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective shared atom order names an unknown physical root".to_owned(),
        ));
    }
    let eliminable_authority_tails = composition
        .steps
        .iter()
        .filter(|step| step.kind == X64TargetSharedJoinKind::RegisterInstruction)
        .flat_map(|step| step.ingresses.iter())
        .map(|ingress| RawExecutionEvent::Tail {
            label: ingress.authority_trigger,
        })
        .collect::<BTreeSet<_>>();
    let baseline_owner_offsets = program
        .labels
        .iter()
        .map(|label| (label.code_offset, label.id))
        .collect::<BTreeMap<_, _>>();
    if baseline_owner_offsets.len() != program.labels.len() {
        return Err(X64TargetProfileError::InternalInvariant(
            "accepted policy-1.4 labels repeat a physical offset".to_owned(),
        ));
    }
    let mut baseline_semantic_events = BTreeSet::new();
    let mut baseline_event_layout = BTreeMap::new();
    let mut baseline_normalized_payloads = BTreeMap::new();
    let mut expected_ordinary_order = BTreeMap::<X64LabelId, Vec<RawExecutionEvent>>::new();
    for (index, atom) in baseline_atoms.iter().enumerate() {
        validate_prospective_event_class(program, atom.event, atom.class)?;
        if atom.event != RawExecutionEvent::Static && !baseline_semantic_events.insert(atom.event) {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "accepted policy-1.4 realization repeats semantic event at atom {index}"
            )));
        }
        if atom.event != RawExecutionEvent::Static {
            let normalized_payload = normalized_prospective_atom_payload(
                &program.code,
                &program.fixups,
                atom,
                "prospective baseline payload",
                &mut replay_budget,
            )?;
            let physical_owner =
                prospective_physical_owner(&baseline_owner_offsets, atom.start, atom.end)?;
            if baseline_event_layout
                .insert(atom.event, (atom.class, physical_owner, index))
                .is_some()
            {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "accepted policy-1.4 realization repeats layout event at atom {index}"
                )));
            }
            if baseline_normalized_payloads
                .insert(atom.event, normalized_payload)
                .is_some()
            {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "accepted policy-1.4 realization repeats normalized payload at atom {index}"
                )));
            }
            if !selected_events.contains(&atom.event)
                && !eliminable_authority_tails.contains(&atom.event)
            {
                expected_ordinary_order
                    .entry(physical_owner)
                    .or_default()
                    .push(atom.event);
            }
        }
    }
    if !eliminable_authority_tails
        .iter()
        .all(|event| baseline_semantic_events.contains(event))
    {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective register composition eliminates a missing authority tail".to_owned(),
        ));
    }
    let expected_shared_atom_count = u32::try_from(expected_atoms.len()).map_err(|_| {
        X64TargetProfileError::CounterOverflow {
            field: "prospective shared authority atom count",
        }
    })?;
    let mut shared_event_counts = BTreeMap::<RawExecutionEvent, u64>::new();
    let mut candidate_semantic_events = BTreeSet::new();
    let mut candidate_ordinary_order = BTreeMap::<X64LabelId, Vec<RawExecutionEvent>>::new();
    let mut shared_order_cursor = 0_usize;
    let mut previous_shared_atom = None::<(usize, X64LabelId)>;
    let mut last_shared_end_by_owner = BTreeMap::<X64LabelId, u32>::new();
    let mut atoms = Vec::with_capacity(shadow.atoms.len());
    let mut candidate_weighted_template_bytes = 0_u128;
    if raw.atoms.len() != shadow.atoms.len() {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective atom receipt count differs from shadow".to_owned(),
        ));
    }
    for (index, (atom, receipt)) in shadow.atoms.iter().zip(&raw.atoms).enumerate() {
        validate_prospective_event_class(program, atom.event, atom.class)?;
        let physical_owner = prospective_physical_owner(&label_offsets, atom.start, atom.end)?;
        let key = (physical_owner, atom.event);
        let expected = expected_atoms.remove(&key);
        let (authority, executions) = if let Some(expected) = expected {
            if expected_shared_order.get(shared_order_cursor).copied() != Some(key) {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "prospective shared atom {index} differs from ordered composition replay"
                )));
            }
            if previous_shared_atom.is_some_and(|(previous_index, previous_owner)| {
                previous_owner == physical_owner && previous_index + 1 != index
            }) {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "prospective shared atom group at owner {} is not contiguous",
                    physical_owner.0
                )));
            }
            shared_order_cursor += 1;
            previous_shared_atom = Some((index, physical_owner));
            last_shared_end_by_owner.insert(physical_owner, atom.end);
            if atom.class != expected.class {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "prospective shared atom {index} has a different template class"
                )));
            }
            if atom.class == RawTemplateClass::FusedCompareInstruction {
                validate_prospective_payload_equality(
                    baseline_normalized_payloads
                        .get(&atom.event)
                        .ok_or_else(|| {
                            X64TargetProfileError::InternalInvariant(format!(
                                "prospective fused atom {index} has no normalized baseline payload"
                            ))
                        })?,
                    &shadow.code,
                    &shadow.fixups,
                    atom,
                    "fused clone",
                    &mut replay_budget,
                )?;
            }
            checked_increment(&mut shared_event_counts, atom.event, expected.executions)?;
            (expected.authority, expected.executions)
        } else {
            if selected_events.contains(&atom.event) {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "prospective atom {index} duplicates a selected semantic event"
                )));
            }
            match atom.event {
                RawExecutionEvent::Static if atom.class == RawTemplateClass::Tombstone => {
                    if !declared_tombstone_offsets.contains(&atom.start) {
                        return Err(X64TargetProfileError::InternalInvariant(format!(
                            "prospective static tombstone atom {index} has no declared tombstone label"
                        )));
                    }
                    (X64TargetProspectiveExecutionAuthority::Static, 0)
                }
                RawExecutionEvent::Static => {
                    return Err(X64TargetProfileError::InternalInvariant(format!(
                        "prospective static atom {index} is not a tombstone"
                    )));
                }
                event => {
                    let Some((baseline_class, baseline_owner, baseline_index)) =
                        baseline_event_layout.get(&event).copied()
                    else {
                        return Err(X64TargetProfileError::InternalInvariant(format!(
                            "prospective atom {index} introduces semantic event {event:?}"
                        )));
                    };
                    if eliminable_authority_tails.contains(&event)
                        || baseline_class != atom.class
                        || baseline_owner != physical_owner
                        || !candidate_semantic_events.insert(event)
                    {
                        return Err(X64TargetProfileError::InternalInvariant(format!(
                            "prospective atom {index} introduces or repeats semantic event {event:?}"
                        )));
                    }
                    let baseline_atom = &baseline_atoms[baseline_index];
                    let (candidate_fixup_first, candidate_fixup_last) = prospective_fixup_range(
                        &shadow.fixups,
                        atom,
                        "prospective candidate atom fixup lookup",
                        &mut replay_budget,
                    )?;
                    let (baseline_fixup_first, baseline_fixup_last) = prospective_fixup_range(
                        &program.fixups,
                        baseline_atom,
                        "prospective baseline atom fixup lookup",
                        &mut replay_budget,
                    )?;
                    let no_fixup_tail = matches!(event, RawExecutionEvent::Tail { .. })
                        && candidate_fixup_first == candidate_fixup_last;
                    if no_fixup_tail && baseline_fixup_last - baseline_fixup_first == 1 {
                        validate_prospective_trimmed_tail_payload(
                            &program.code,
                            &program.fixups,
                            baseline_atom,
                            &shadow.code,
                            &shadow.fixups,
                            atom,
                            &mut replay_budget,
                        )?;
                    } else if !no_fixup_tail || baseline_fixup_first == baseline_fixup_last {
                        validate_prospective_payload_equality(
                            baseline_normalized_payloads.get(&event).ok_or_else(|| {
                                X64TargetProfileError::InternalInvariant(format!(
                                    "prospective atom {index} has no normalized baseline payload"
                                ))
                            })?,
                            &shadow.code,
                            &shadow.fixups,
                            atom,
                            "retained ordinary atom",
                            &mut replay_budget,
                        )?;
                    } else {
                        return Err(X64TargetProfileError::InternalInvariant(format!(
                            "prospective no-fixup tail atom {index} has a non-canonical baseline fixup count"
                        )));
                    }
                    candidate_ordinary_order
                        .entry(physical_owner)
                        .or_default()
                        .push(event);
                    (
                        X64TargetProspectiveExecutionAuthority::Semantic {
                            event: X64TargetProfileEvent::from(event),
                        },
                        observer.raw_event_count(event)?,
                    )
                }
            }
        };
        let receipt_authority = prospective_execution_authority(receipt.execution_authority)?;
        if receipt.physical_owner != physical_owner
            || receipt.semantic_event != atom.event
            || receipt.class != atom.class
            || receipt.start != atom.start
            || receipt.end != atom.end
            || receipt_authority != authority
        {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "prospective atom receipt {index} differs from independent replay"
            )));
        }
        let static_bytes = atom.byte_len();
        let weighted_bytes = u128::from(static_bytes)
            .checked_mul(u128::from(executions))
            .ok_or(X64TargetProfileError::CounterOverflow {
                field: "prospective atom weighted bytes",
            })?;
        candidate_weighted_template_bytes = candidate_weighted_template_bytes
            .checked_add(weighted_bytes)
            .ok_or(X64TargetProfileError::CounterOverflow {
                field: "prospective candidate weighted bytes",
            })?;
        atoms.push(X64TargetProspectiveRealizationAtom {
            physical_owner,
            semantic_event: X64TargetProfileEvent::from(atom.event),
            execution_authority: authority,
            class: X64TargetProfileTemplateClass::from(atom.class),
            start: atom.start,
            end: atom.end,
            static_bytes,
            executions,
            weighted_bytes,
        });
    }
    if !expected_atoms.is_empty()
        || shared_order_cursor != expected_shared_order.len()
        || expected_shared_atom_count != raw.shared_join_authority_atoms
    {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective realization misses a structural shared-authority atom".to_owned(),
        ));
    }
    let candidate_code_end = u32::try_from(candidate_code_bytes).map_err(|_| {
        X64TargetProfileError::CounterOverflow {
            field: "prospective candidate owner end",
        }
    })?;
    for (owner, shared_end) in last_shared_end_by_owner {
        replay_budget.charge(
            prospective_index_lookup_work(labels.len())
                .checked_mul(2)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "prospective shared suffix owner lookup",
                })?,
            "prospective shared suffix owner lookup",
        )?;
        let owner_start = labels
            .binary_search_by_key(&owner, |receipt| receipt.label)
            .ok()
            .map(|index| labels[index].code_offset)
            .ok_or_else(|| {
                X64TargetProfileError::InternalInvariant(format!(
                    "prospective shared owner {} has no declared label",
                    owner.0
                ))
            })?;
        let owner_end = label_offsets
            .range((
                std::ops::Bound::Excluded(owner_start),
                std::ops::Bound::Unbounded,
            ))
            .next()
            .map(|(offset, _)| *offset)
            .unwrap_or(candidate_code_end);
        if shared_end != owner_end {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "prospective shared atom group at owner {} is not its terminal suffix",
                owner.0
            )));
        }
    }
    for event in &selected_events {
        let expected = observer.raw_event_count(*event)?;
        let actual = shared_event_counts.get(event).copied().unwrap_or(0);
        if actual != expected {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "prospective cloned event {event:?} has {actual} executions, expected {expected}"
            )));
        }
    }
    let expected_candidate_semantic_events = baseline_semantic_events
        .iter()
        .copied()
        .filter(|event| {
            !selected_events.contains(event) && !eliminable_authority_tails.contains(event)
        })
        .collect::<BTreeSet<_>>();
    if candidate_semantic_events != expected_candidate_semantic_events
        || candidate_ordinary_order != expected_ordinary_order
    {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective ordinary atoms differ from baseline owner/order conservation".to_owned(),
        ));
    }

    let mut fused_predecessors = expected_prospective_fused_predecessors(composition)?;
    fused_predecessors.extend(accepted_no_fixup_fused_predecessors(
        program,
        baseline_atoms,
        &mut replay_budget,
    )?);
    let fixups = replay_prospective_fixups(
        program,
        &shadow.code,
        &shadow.labels,
        &shadow.fixups,
        &shadow.atoms,
        &raw.fixups,
        &label_dispositions,
        &fused_predecessors,
        &mut replay_budget,
    )?;
    let semantic_summary = verify_prospective_register_semantics(program, raw, shadow, composition)
        .map_err(|error| {
            X64TargetProfileError::InternalInvariant(format!(
                "prospective register machine semantics failed: {error}"
            ))
        })?;
    let expected_semantic_rows = composition
        .steps
        .iter()
        .filter(|step| step.kind == X64TargetSharedJoinKind::RegisterInstruction)
        .try_fold(0_u32, |total, step| {
            let rows = u32::try_from(step.ingresses.len()).map_err(|_| {
                X64TargetProfileError::CounterOverflow {
                    field: "prospective semantic row count",
                }
            })?;
            total
                .checked_add(rows)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "prospective semantic row count",
                })
        })?;
    if semantic_summary.rows != expected_semantic_rows
        || (semantic_summary.rows > 0
            && (semantic_summary.decoded_bytes == 0
                || semantic_summary.decoded_instructions == 0
                || semantic_summary.symbolic_nodes == 0
                || semantic_summary.reference_route_events == 0))
    {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective register semantic coverage is incomplete".to_owned(),
        ));
    }

    let mut result = X64TargetProspectiveSharedJoinRealization {
        complete: true,
        baseline_code_bytes,
        baseline_code_hash: program.code_hash,
        candidate_code_bytes,
        candidate_code_hash,
        code_bytes_added,
        code_bytes_removed,
        baseline_atom_count,
        candidate_atom_count,
        atom_count_added,
        atom_count_removed,
        label_count,
        baseline_fixup_count,
        candidate_fixup_count,
        fixup_count_added,
        fixup_count_removed,
        body_replicas: composition.body_replicas,
        shared_join_authority_atoms: expected_shared_atom_count,
        candidate_weighted_template_bytes,
        machine_semantic_proof: X64TargetProspectiveMachineSemanticProof {
            complete: true,
            register_rows: semantic_summary.rows,
            decoded_bytes: semantic_summary.decoded_bytes,
            decoded_instructions: semantic_summary.decoded_instructions,
            symbolic_nodes: semantic_summary.symbolic_nodes,
            reference_route_events: semantic_summary.reference_route_events,
        },
        atoms,
        labels,
        fixups,
        realization_hash: SemanticHash::ZERO,
    };
    result.realization_hash = x64_target_prospective_shared_join_realization_hash(&result)?;
    Ok(result)
}

struct ProspectiveReplayBudget {
    work: u64,
}

impl ProspectiveReplayBudget {
    fn charge(&mut self, amount: u64, field: &'static str) -> Result<(), X64TargetProfileError> {
        self.work = self
            .work
            .checked_add(amount)
            .ok_or(X64TargetProfileError::CounterOverflow { field })?;
        if self.work > MAX_PROSPECTIVE_REPLAY_WORK {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "prospective independent replay work {} exceeds {MAX_PROSPECTIVE_REPLAY_WORK}",
                self.work
            )));
        }
        Ok(())
    }

    fn charge_usize(
        &mut self,
        amount: usize,
        field: &'static str,
    ) -> Result<(), X64TargetProfileError> {
        self.charge(checked_usize_to_u64(amount, field)?, field)
    }

    fn charge_index_lookup(
        &mut self,
        length: usize,
        count: u64,
        field: &'static str,
    ) -> Result<(), X64TargetProfileError> {
        let work = prospective_index_lookup_work(length)
            .checked_mul(count)
            .ok_or(X64TargetProfileError::CounterOverflow { field })?;
        self.charge(work, field)
    }
}

fn prospective_index_lookup_work(length: usize) -> u64 {
    if length <= 1 {
        1
    } else {
        u64::from(usize::BITS - (length - 1).leading_zeros()) + 1
    }
}

fn prospective_replay_budget(
    program: &X64TargetProgram,
    baseline_atoms: &[RawRealizationAtom],
    shadow: &RawProspectiveShadow,
    composition: &X64TargetSharedJoinComposition,
) -> Result<ProspectiveReplayBudget, X64TargetProfileError> {
    if program
        .fixups
        .windows(2)
        .any(|pair| pair[0].patch_offset >= pair[1].patch_offset)
        || shadow
            .fixups
            .windows(2)
            .any(|pair| pair[0].patch_offset >= pair[1].patch_offset)
    {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective replay fixups are not strictly patch ordered".to_owned(),
        ));
    }
    let mut budget = ProspectiveReplayBudget { work: 0 };
    {
        let mut charge = |amount: usize, field: &'static str| {
            let amount = checked_usize_to_u64(amount, field)?;
            budget.charge(amount, field)
        };
        charge(
            program
                .labels
                .len()
                .checked_mul(8)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "prospective replay indexed label work",
                })?,
            "prospective replay indexed label work",
        )?;
        charge(program.code.len(), "prospective replay baseline bytes")?;
        charge(shadow.code.len(), "prospective replay candidate bytes")?;
        charge(
            baseline_atoms
                .len()
                .checked_mul(4)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "prospective replay baseline atom work",
                })?,
            "prospective replay baseline atom work",
        )?;
        charge(
            shadow
                .atoms
                .len()
                .checked_mul(8)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "prospective replay candidate atom work",
                })?,
            "prospective replay candidate atom work",
        )?;
        charge(
            program
                .fixups
                .len()
                .checked_mul(4)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "prospective replay baseline fixup work",
                })?,
            "prospective replay baseline fixup work",
        )?;
        charge(
            shadow
                .fixups
                .len()
                .checked_mul(4)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "prospective replay candidate fixup work",
                })?,
            "prospective replay candidate fixup work",
        )?;
        charge(
            composition.steps.len(),
            "prospective replay composition steps",
        )?;
        for step in &composition.steps {
            charge(step.ingresses.len(), "prospective replay ingress rows")?;
            for ingress in &step.ingresses {
                charge(ingress.route.len(), "prospective replay route events")?;
            }
        }
    }
    let label_lookup = prospective_index_lookup_work(program.labels.len());
    let function_lookup = prospective_index_lookup_work(program.functions.len());
    let max_blocks = program
        .functions
        .iter()
        .map(|function| function.blocks.len())
        .max()
        .unwrap_or(1);
    let block_lookup = prospective_index_lookup_work(max_blocks);
    let indexed_block_lookup = label_lookup
        .checked_add(function_lookup)
        .and_then(|work| work.checked_add(block_lookup))
        .ok_or(X64TargetProfileError::CounterOverflow {
            field: "prospective indexed block lookup work",
        })?;
    let ingress_count = composition.steps.iter().try_fold(0_usize, |count, step| {
        count
            .checked_add(step.ingresses.len())
            .ok_or(X64TargetProfileError::CounterOverflow {
                field: "prospective ingress lookup count",
            })
    })?;
    let block_lookups = baseline_atoms
        .len()
        .checked_mul(2)
        .and_then(|count| {
            shadow
                .atoms
                .len()
                .checked_mul(3)
                .and_then(|candidate| count.checked_add(candidate))
        })
        .and_then(|count| count.checked_add(ingress_count))
        .ok_or(X64TargetProfileError::CounterOverflow {
            field: "prospective conservative block lookup count",
        })?;
    budget.charge(
        checked_usize_to_u64(block_lookups, "prospective conservative block lookup count")?
            .checked_mul(indexed_block_lookup)
            .ok_or(X64TargetProfileError::CounterOverflow {
                field: "prospective conservative block lookup work",
            })?,
        "prospective conservative block lookup work",
    )?;
    let physical_owner_lookups = baseline_atoms
        .len()
        .checked_mul(4)
        .and_then(|count| {
            shadow
                .atoms
                .len()
                .checked_mul(5)
                .and_then(|candidate| count.checked_add(candidate))
        })
        .and_then(|count| count.checked_add(composition.steps.len()))
        .ok_or(X64TargetProfileError::CounterOverflow {
            field: "prospective conservative owner lookup count",
        })?;
    budget.charge(
        checked_usize_to_u64(
            physical_owner_lookups,
            "prospective conservative owner lookup count",
        )?
        .checked_mul(label_lookup)
        .and_then(|work| work.checked_mul(2))
        .ok_or(X64TargetProfileError::CounterOverflow {
            field: "prospective conservative owner lookup work",
        })?,
        "prospective conservative owner lookup work",
    )?;
    let maximum_route_hops = checked_usize_to_u64(
        program
            .labels
            .len()
            .checked_add(program.functions.len())
            .and_then(|count| count.checked_add(2))
            .ok_or(X64TargetProfileError::CounterOverflow {
                field: "prospective maximum route hops",
            })?,
        "prospective maximum route hops",
    )?;
    budget.charge(
        checked_usize_to_u64(shadow.fixups.len(), "prospective routed fixup count")?
            .checked_mul(maximum_route_hops)
            .and_then(|work| work.checked_mul(indexed_block_lookup))
            .ok_or(X64TargetProfileError::CounterOverflow {
                field: "prospective conservative route lookup work",
            })?,
        "prospective conservative route lookup work",
    )?;
    Ok(budget)
}

fn checked_usize_to_u64(value: usize, field: &'static str) -> Result<u64, X64TargetProfileError> {
    u64::try_from(value).map_err(|_| X64TargetProfileError::CounterOverflow { field })
}

fn normalized_prospective_delta(
    baseline: u64,
    candidate: u64,
) -> Result<(u64, u64), X64TargetProfileError> {
    if candidate >= baseline {
        Ok((
            candidate
                .checked_sub(baseline)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "prospective positive delta",
                })?,
            0,
        ))
    } else {
        Ok((
            0,
            baseline
                .checked_sub(candidate)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "prospective negative delta",
                })?,
        ))
    }
}

fn normalized_prospective_atom_payload(
    code: &[u8],
    fixups: &[X64Fixup],
    atom: &RawRealizationAtom,
    field: &'static str,
    replay_budget: &mut ProspectiveReplayBudget,
) -> Result<Vec<u8>, X64TargetProfileError> {
    let start = usize::try_from(atom.start)
        .map_err(|_| X64TargetProfileError::CounterOverflow { field })?;
    let end =
        usize::try_from(atom.end).map_err(|_| X64TargetProfileError::CounterOverflow { field })?;
    let source = code.get(start..end).ok_or_else(|| {
        X64TargetProfileError::InternalInvariant(format!("{field} atom payload is outside code"))
    })?;
    replay_budget.charge_usize(source.len(), "prospective normalized payload bytes")?;
    let mut payload = Vec::new();
    payload.try_reserve_exact(source.len()).map_err(|_| {
        X64TargetProfileError::InternalInvariant(
            "prospective normalized payload allocation failed".to_owned(),
        )
    })?;
    payload.extend_from_slice(source);
    let (first, last) = prospective_fixup_range(
        fixups,
        atom,
        "prospective normalized fixup lookup",
        replay_budget,
    )?;
    if first != 0
        && fixups[first - 1]
            .patch_offset
            .checked_add(4)
            .is_none_or(|patch_end| patch_end > atom.start)
    {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "{field} fixup crosses atom start"
        )));
    }
    replay_budget.charge_usize(
        last.checked_sub(first)
            .ok_or(X64TargetProfileError::CounterOverflow {
                field: "prospective normalized fixup range",
            })?,
        "prospective normalized fixup fields",
    )?;
    for fixup in &fixups[first..last] {
        let patch_end =
            fixup
                .patch_offset
                .checked_add(4)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "prospective normalized fixup end",
                })?;
        if fixup.patch_offset >= atom.end || patch_end <= atom.start {
            continue;
        }
        if fixup.patch_offset < atom.start || patch_end > atom.end {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "{field} fixup crosses atom payload"
            )));
        }
        let relative_start = usize::try_from(fixup.patch_offset - atom.start).map_err(|_| {
            X64TargetProfileError::CounterOverflow {
                field: "prospective normalized fixup start",
            }
        })?;
        let relative_end =
            relative_start
                .checked_add(4)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "prospective normalized fixup end",
                })?;
        payload[relative_start..relative_end].fill(0);
    }
    Ok(payload)
}

fn validate_prospective_payload_equality(
    baseline_payload: &[u8],
    candidate_code: &[u8],
    candidate_fixups: &[X64Fixup],
    candidate_atom: &RawRealizationAtom,
    context: &'static str,
    replay_budget: &mut ProspectiveReplayBudget,
) -> Result<(), X64TargetProfileError> {
    let candidate = normalized_prospective_atom_payload(
        candidate_code,
        candidate_fixups,
        candidate_atom,
        "prospective candidate payload",
        replay_budget,
    )?;
    replay_budget.charge_usize(
        baseline_payload.len().max(candidate.len()),
        "prospective normalized payload comparison",
    )?;
    if candidate != baseline_payload {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "prospective {context} normalized payload differs from accepted policy-1.4 bytes"
        )));
    }
    Ok(())
}

fn validate_prospective_trimmed_tail_payload(
    baseline_code: &[u8],
    baseline_fixups: &[X64Fixup],
    baseline_atom: &RawRealizationAtom,
    candidate_code: &[u8],
    candidate_fixups: &[X64Fixup],
    candidate_atom: &RawRealizationAtom,
    replay_budget: &mut ProspectiveReplayBudget,
) -> Result<(), X64TargetProfileError> {
    let (baseline_first, baseline_last) = prospective_fixup_range(
        baseline_fixups,
        baseline_atom,
        "prospective trimmed baseline fixup lookup",
        replay_budget,
    )?;
    let (candidate_first, candidate_last) = prospective_fixup_range(
        candidate_fixups,
        candidate_atom,
        "prospective trimmed candidate fixup lookup",
        replay_budget,
    )?;
    let [baseline_fixup] = &baseline_fixups[baseline_first..baseline_last] else {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective trimmed tail baseline does not own one rel32".to_owned(),
        ));
    };
    let opcode_offset = baseline_fixup.patch_offset.checked_sub(1).ok_or_else(|| {
        X64TargetProfileError::InternalInvariant(
            "prospective trimmed tail has no jump opcode".to_owned(),
        )
    })?;
    if candidate_first != candidate_last
        || baseline_fixup.addend != 0
        || baseline_fixup.patch_offset.checked_add(4) != Some(baseline_atom.end)
        || baseline_code.get(opcode_offset as usize) != Some(&0xe9)
    {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective trimmed tail has a non-canonical terminal rel32".to_owned(),
        ));
    }
    let baseline_start = usize::try_from(baseline_atom.start).map_err(|_| {
        X64TargetProfileError::CounterOverflow {
            field: "prospective trimmed baseline start",
        }
    })?;
    let baseline_end =
        usize::try_from(opcode_offset).map_err(|_| X64TargetProfileError::CounterOverflow {
            field: "prospective trimmed baseline end",
        })?;
    let candidate_start = usize::try_from(candidate_atom.start).map_err(|_| {
        X64TargetProfileError::CounterOverflow {
            field: "prospective trimmed candidate start",
        }
    })?;
    let candidate_end = usize::try_from(candidate_atom.end).map_err(|_| {
        X64TargetProfileError::CounterOverflow {
            field: "prospective trimmed candidate end",
        }
    })?;
    replay_budget.charge_usize(
        baseline_end
            .saturating_sub(baseline_start)
            .max(candidate_end.saturating_sub(candidate_start)),
        "prospective trimmed payload comparison",
    )?;
    if baseline_code.get(baseline_start..baseline_end)
        != candidate_code.get(candidate_start..candidate_end)
    {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective fused-predecessor tail differs beyond its removed terminal rel32"
                .to_owned(),
        ));
    }
    Ok(())
}

fn prospective_fixup_range(
    fixups: &[X64Fixup],
    atom: &RawRealizationAtom,
    field: &'static str,
    replay_budget: &mut ProspectiveReplayBudget,
) -> Result<(usize, usize), X64TargetProfileError> {
    replay_budget.charge_index_lookup(fixups.len(), 2, field)?;
    let first = fixups.partition_point(|fixup| fixup.patch_offset < atom.start);
    let last = fixups.partition_point(|fixup| fixup.patch_offset < atom.end);
    Ok((first, last))
}

fn prospective_shared_join_code_hash(code: &[u8]) -> Result<SemanticHash, X64TargetProfileError> {
    let length = checked_usize_to_u64(code.len(), "prospective candidate hash length")?;
    let capacity = PROSPECTIVE_SHARED_JOIN_CODE_DOMAIN
        .len()
        .checked_add(8)
        .and_then(|capacity| capacity.checked_add(code.len()))
        .ok_or(X64TargetProfileError::CounterOverflow {
            field: "prospective candidate hash preimage",
        })?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(PROSPECTIVE_SHARED_JOIN_CODE_DOMAIN);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(code);
    Ok(SemanticHash(sha256(&bytes)))
}

fn validate_prospective_atom_coverage(
    atoms: &[RawRealizationAtom],
    candidate_code_bytes: u64,
) -> Result<(), X64TargetProfileError> {
    let mut cursor = 0_u32;
    for atom in atoms {
        if atom.start != cursor || atom.end <= atom.start {
            return Err(X64TargetProfileError::InternalInvariant(
                "prospective atoms do not cover the candidate contiguously".to_owned(),
            ));
        }
        cursor = atom.end;
    }
    if u64::from(cursor) != candidate_code_bytes {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective atom coverage differs from candidate bytes".to_owned(),
        ));
    }
    Ok(())
}

fn realization_atom_starts(
    atoms: &[RawRealizationAtom],
) -> Result<BTreeMap<u32, usize>, X64TargetProfileError> {
    let starts = atoms
        .iter()
        .enumerate()
        .map(|(index, atom)| (atom.start, index))
        .collect::<BTreeMap<_, _>>();
    if starts.len() != atoms.len() {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective realization repeats an atom start".to_owned(),
        ));
    }
    Ok(starts)
}

fn prospective_label_disposition(
    disposition: RawProspectiveLabelDisposition,
) -> X64TargetProspectiveLabelDisposition {
    match disposition {
        RawProspectiveLabelDisposition::Live => X64TargetProspectiveLabelDisposition::Live,
        RawProspectiveLabelDisposition::ReachabilityTombstone => {
            X64TargetProspectiveLabelDisposition::UnreachableTombstone
        }
        RawProspectiveLabelDisposition::UniqueChainTombstone => {
            X64TargetProspectiveLabelDisposition::Policy14ConsumedTombstone
        }
        RawProspectiveLabelDisposition::SharedJoinTombstone => {
            X64TargetProspectiveLabelDisposition::SharedJoinConsumedTombstone
        }
    }
}

fn validate_prospective_tombstone(
    code: &[u8],
    atom: &RawRealizationAtom,
    label: X64LabelId,
) -> Result<(), X64TargetProfileError> {
    let start =
        usize::try_from(atom.start).map_err(|_| X64TargetProfileError::CounterOverflow {
            field: "prospective tombstone offset",
        })?;
    let end = usize::try_from(atom.end).map_err(|_| X64TargetProfileError::CounterOverflow {
        field: "prospective tombstone offset",
    })?;
    if atom.class != RawTemplateClass::Tombstone
        || atom.byte_len() != 1
        || code.get(start..end) != Some([0x90].as_slice())
    {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "prospective label {} does not own an exact one-byte NOP tombstone",
            label.0
        )));
    }
    Ok(())
}

fn prospective_policy14_consumed_labels(
    program: &X64TargetProgram,
    baseline_atoms: &[RawRealizationAtom],
) -> Result<BTreeSet<X64LabelId>, X64TargetProfileError> {
    let owner_offsets = program
        .labels
        .iter()
        .map(|label| (label.code_offset, label.id))
        .collect::<BTreeMap<_, _>>();
    if owner_offsets.len() != program.labels.len() {
        return Err(X64TargetProfileError::InternalInvariant(
            "accepted policy-1.4 labels repeat a physical offset".to_owned(),
        ));
    }
    let atom_starts = realization_atom_starts(baseline_atoms)?;
    let mut consumed = BTreeSet::new();
    for atom in baseline_atoms {
        let RawExecutionEvent::Instruction { label, index: 0 } = atom.event else {
            continue;
        };
        if !matches!(
            atom.class,
            RawTemplateClass::RegisterInstruction | RawTemplateClass::FusedCompareInstruction
        ) {
            continue;
        }
        let physical_owner = prospective_physical_owner(&owner_offsets, atom.start, atom.end)?;
        if physical_owner == label {
            continue;
        }
        let block = block_for_label(program, label)?;
        if block.instructions.len() != 1
            || !matches!(block.terminator, X64Terminator::TailJumpRel32 { .. })
        {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "accepted policy-1.4 relocated event {} is not a one-instruction tail body",
                label.0
            )));
        }
        let declared = program
            .labels
            .binary_search_by_key(&label, |candidate| candidate.id)
            .ok()
            .map(|index| &program.labels[index])
            .ok_or_else(|| {
                X64TargetProfileError::InternalInvariant(format!(
                    "accepted policy-1.4 relocated event {} has no label",
                    label.0
                ))
            })?;
        let owning_atom = atom_starts
            .get(&declared.code_offset)
            .and_then(|index| baseline_atoms.get(*index))
            .ok_or_else(|| {
                X64TargetProfileError::InternalInvariant(format!(
                    "accepted policy-1.4 relocated event {} has no declared atom",
                    label.0
                ))
            })?;
        if owning_atom.class != RawTemplateClass::Tombstone || !consumed.insert(label) {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "accepted policy-1.4 relocated event {} has non-canonical ownership",
                label.0
            )));
        }
    }
    Ok(consumed)
}

type ExpectedProspectiveAtoms = (
    BTreeMap<(X64LabelId, RawExecutionEvent), ExpectedProspectiveAtom>,
    BTreeSet<RawExecutionEvent>,
    BTreeMap<X64LabelId, Vec<RawExecutionEvent>>,
);

fn expected_prospective_atoms(
    program: &X64TargetProgram,
    composition: &X64TargetSharedJoinComposition,
) -> Result<ExpectedProspectiveAtoms, X64TargetProfileError> {
    let mut expected = BTreeMap::new();
    let mut selected_events = BTreeSet::new();
    let mut ordered_by_root = BTreeMap::<X64LabelId, Vec<RawExecutionEvent>>::new();
    for step in &composition.steps {
        if step.ingresses.len() < 2 || step.ingresses.len() > MAX_PROSPECTIVE_SHARED_JOIN_INGRESSES
        {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "prospective target {} has an inadmissible ingress count",
                step.target.0
            )));
        }
        for ingress in &step.ingresses {
            let make_authority = |partition| X64TargetProspectiveExecutionAuthority::SharedJoin {
                target: step.target,
                root: ingress.root,
                authority_trigger: ingress.authority_trigger,
                partition,
            };
            let mut insert = |event, class, partition, executions| {
                selected_events.insert(event);
                if expected
                    .insert(
                        (ingress.root, event),
                        ExpectedProspectiveAtom {
                            class,
                            authority: make_authority(partition),
                            executions,
                        },
                    )
                    .is_some()
                {
                    return Err(X64TargetProfileError::InternalInvariant(format!(
                        "prospective target {} repeats physical atom authority",
                        step.target.0
                    )));
                }
                ordered_by_root.entry(ingress.root).or_default().push(event);
                Ok(())
            };
            match step.kind {
                X64TargetSharedJoinKind::RegisterInstruction => {
                    if ingress.branch_arm_counts.is_some() {
                        return Err(X64TargetProfileError::InternalInvariant(format!(
                            "prospective register target {} has branch authority",
                            step.target.0
                        )));
                    }
                    insert(
                        RawExecutionEvent::Instruction {
                            label: step.target,
                            index: 0,
                        },
                        RawTemplateClass::RegisterInstruction,
                        X64TargetProspectiveSharedJoinPartition::All,
                        ingress.executions,
                    )?;
                    insert(
                        RawExecutionEvent::Tail { label: step.target },
                        RawTemplateClass::TailTransfer,
                        X64TargetProspectiveSharedJoinPartition::All,
                        ingress.executions,
                    )?;
                }
                X64TargetSharedJoinKind::FusedCompare => {
                    let branch_counts = ingress.branch_arm_counts.ok_or_else(|| {
                        X64TargetProfileError::InternalInvariant(format!(
                            "prospective fused target {} has no branch cells",
                            step.target.0
                        ))
                    })?;
                    let branch_label = match ingress.route.last() {
                        Some(X64TargetSharedJoinRouteEvent::Tail { source, target })
                            if *source == step.target =>
                        {
                            *target
                        }
                        _ => {
                            return Err(X64TargetProfileError::InternalInvariant(format!(
                                "prospective fused target {} has no exact branch bridge",
                                step.target.0
                            )));
                        }
                    };
                    let branch = block_for_label(program, branch_label)?;
                    if !branch.instructions.is_empty()
                        || !matches!(
                            &branch.terminator,
                            X64Terminator::BranchRel32 {
                                then_label,
                                else_label,
                                ..
                            } if then_label != else_label
                        )
                    {
                        return Err(X64TargetProfileError::InternalInvariant(format!(
                            "prospective fused target {} has a non-canonical branch bridge",
                            step.target.0
                        )));
                    }
                    insert(
                        RawExecutionEvent::Instruction {
                            label: step.target,
                            index: 0,
                        },
                        RawTemplateClass::FusedCompareInstruction,
                        X64TargetProspectiveSharedJoinPartition::All,
                        ingress.executions,
                    )?;
                    insert(
                        RawExecutionEvent::Branch {
                            label: branch_label,
                        },
                        RawTemplateClass::BranchCondition,
                        X64TargetProspectiveSharedJoinPartition::All,
                        ingress.executions,
                    )?;
                    insert(
                        RawExecutionEvent::BranchElse {
                            label: branch_label,
                        },
                        RawTemplateClass::BranchElseJump,
                        X64TargetProspectiveSharedJoinPartition::Else,
                        branch_counts.else_executions,
                    )?;
                }
            }
        }
    }
    Ok((expected, selected_events, ordered_by_root))
}

fn expected_prospective_fused_predecessors(
    composition: &X64TargetSharedJoinComposition,
) -> Result<BTreeSet<(X64LabelId, X64LabelId, X64LabelId)>, X64TargetProfileError> {
    let mut last_register_by_root = BTreeMap::<X64LabelId, X64LabelId>::new();
    let mut predecessors = BTreeSet::new();
    for step in &composition.steps {
        for ingress in &step.ingresses {
            match step.kind {
                X64TargetSharedJoinKind::RegisterInstruction => {
                    last_register_by_root.insert(ingress.root, step.target);
                }
                X64TargetSharedJoinKind::FusedCompare => {
                    let predecessor = last_register_by_root
                        .get(&ingress.root)
                        .copied()
                        .unwrap_or(ingress.authority_trigger);
                    if predecessor != ingress.authority_trigger
                        && !step.ancestors.contains(&predecessor)
                    {
                        return Err(X64TargetProfileError::InternalInvariant(format!(
                            "prospective fused target {} follows unrelated register target {} at root {}",
                            step.target.0, predecessor.0, ingress.root.0
                        )));
                    }
                    if !predecessors.insert((ingress.root, predecessor, step.target)) {
                        return Err(X64TargetProfileError::InternalInvariant(format!(
                            "prospective fused target {} repeats predecessor authority at root {}",
                            step.target.0, ingress.root.0
                        )));
                    }
                }
            }
        }
    }
    Ok(predecessors)
}

fn accepted_no_fixup_fused_predecessors(
    program: &X64TargetProgram,
    atoms: &[RawRealizationAtom],
    replay_budget: &mut ProspectiveReplayBudget,
) -> Result<BTreeSet<(X64LabelId, X64LabelId, X64LabelId)>, X64TargetProfileError> {
    let owner_offsets = program
        .labels
        .iter()
        .map(|label| (label.code_offset, label.id))
        .collect::<BTreeMap<_, _>>();
    let mut predecessors = BTreeSet::new();
    for (index, atom) in atoms.iter().enumerate() {
        replay_budget.charge(1, "prospective accepted no-fixup atom replay")?;
        let RawExecutionEvent::Tail { label } = atom.event else {
            continue;
        };
        let (first, last) = prospective_fixup_range(
            &program.fixups,
            atom,
            "prospective accepted no-fixup lookup",
            replay_budget,
        )?;
        if first != last {
            continue;
        }
        let next = atoms.get(index + 1).ok_or_else(|| {
            X64TargetProfileError::InternalInvariant(format!(
                "accepted no-fixup tail atom {index} has no fused successor"
            ))
        })?;
        let RawExecutionEvent::Instruction {
            label: fused_target,
            index: 0,
        } = next.event
        else {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "accepted no-fixup tail atom {index} has no fused instruction successor"
            )));
        };
        let owner = prospective_physical_owner(&owner_offsets, atom.start, atom.end)?;
        let next_owner = prospective_physical_owner(&owner_offsets, next.start, next.end)?;
        if next.start != atom.end
            || next.class != RawTemplateClass::FusedCompareInstruction
            || next_owner != owner
            || !predecessors.insert((owner, label, fused_target))
        {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "accepted no-fixup tail atom {index} has non-canonical fused ownership"
            )));
        }
    }
    Ok(predecessors)
}

fn prospective_execution_authority(
    authority: RawProspectiveExecutionAuthority,
) -> Result<X64TargetProspectiveExecutionAuthority, X64TargetProfileError> {
    match authority {
        RawProspectiveExecutionAuthority::SemanticEvent(RawExecutionEvent::Static) => {
            Err(X64TargetProfileError::InternalInvariant(
                "prospective static authority must use the dedicated raw variant".to_owned(),
            ))
        }
        RawProspectiveExecutionAuthority::SemanticEvent(event) => {
            Ok(X64TargetProspectiveExecutionAuthority::Semantic {
                event: X64TargetProfileEvent::from(event),
            })
        }
        RawProspectiveExecutionAuthority::Static => {
            Ok(X64TargetProspectiveExecutionAuthority::Static)
        }
        RawProspectiveExecutionAuthority::SharedJoin {
            target,
            root,
            authority_trigger,
            partition,
        } => {
            let partition = match partition {
                RawProspectiveSharedJoinPartition::All => {
                    X64TargetProspectiveSharedJoinPartition::All
                }
                RawProspectiveSharedJoinPartition::Else => {
                    X64TargetProspectiveSharedJoinPartition::Else
                }
            };
            Ok(X64TargetProspectiveExecutionAuthority::SharedJoin {
                target,
                root,
                authority_trigger,
                partition,
            })
        }
    }
}

fn prospective_physical_owner(
    label_offsets: &BTreeMap<u32, X64LabelId>,
    start: u32,
    end: u32,
) -> Result<X64LabelId, X64TargetProfileError> {
    let owner = label_offsets
        .range(..=start)
        .next_back()
        .map(|(_, label)| *label)
        .ok_or_else(|| {
            X64TargetProfileError::InternalInvariant(
                "prospective atom has no physical owner".to_owned(),
            )
        })?;
    if label_offsets
        .range((std::ops::Bound::Excluded(start), std::ops::Bound::Unbounded))
        .next()
        .is_some_and(|(offset, _)| *offset < end)
    {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective atom crosses a physical-owner boundary".to_owned(),
        ));
    }
    Ok(owner)
}

fn validate_prospective_event_class(
    program: &X64TargetProgram,
    event: RawExecutionEvent,
    class: RawTemplateClass,
) -> Result<(), X64TargetProfileError> {
    let compatible = matches!(
        (event, class),
        (RawExecutionEvent::Entry, RawTemplateClass::EntryPrologue)
            | (
                RawExecutionEvent::Instruction { .. },
                RawTemplateClass::OrdinaryInstruction
                    | RawTemplateClass::RegisterInstruction
                    | RawTemplateClass::FusedCompareInstruction
            )
            | (
                RawExecutionEvent::Tail { .. },
                RawTemplateClass::TailTransfer
            )
            | (
                RawExecutionEvent::Return { .. },
                RawTemplateClass::ReturnTransfer
            )
            | (
                RawExecutionEvent::Branch { .. },
                RawTemplateClass::BranchCondition
            )
            | (
                RawExecutionEvent::BranchElse { .. },
                RawTemplateClass::BranchElseJump
            )
            | (
                RawExecutionEvent::ReturnEpilogue,
                RawTemplateClass::ReturnEpilogue
            )
            | (
                RawExecutionEvent::BoundsEpilogue,
                RawTemplateClass::BoundsEpilogue
            )
            | (RawExecutionEvent::Static, RawTemplateClass::Tombstone)
    );
    if !compatible {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "prospective event {event:?} has incompatible class {class:?}"
        )));
    }
    match event {
        RawExecutionEvent::Instruction { label, index } => {
            let block = block_for_label(program, label)?;
            if block.instructions.get(index as usize).is_none() {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "prospective instruction event {}:{index} is not in the target",
                    label.0
                )));
            }
        }
        RawExecutionEvent::Tail { label } => {
            if !matches!(
                block_for_label(program, label)?.terminator,
                X64Terminator::TailJumpRel32 { .. }
            ) {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "prospective tail event {} has no tail terminator",
                    label.0
                )));
            }
        }
        RawExecutionEvent::Return { label } => {
            if !matches!(
                block_for_label(program, label)?.terminator,
                X64Terminator::Return { .. }
            ) {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "prospective return event {} has no return terminator",
                    label.0
                )));
            }
        }
        RawExecutionEvent::Branch { label } | RawExecutionEvent::BranchElse { label } => {
            if !matches!(
                block_for_label(program, label)?.terminator,
                X64Terminator::BranchRel32 { .. }
            ) {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "prospective branch event {} has no branch terminator",
                    label.0
                )));
            }
        }
        RawExecutionEvent::Entry
        | RawExecutionEvent::ReturnEpilogue
        | RawExecutionEvent::BoundsEpilogue
        | RawExecutionEvent::Static => {}
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn replay_prospective_fixups(
    program: &X64TargetProgram,
    code: &[u8],
    labels: &[X64Label],
    fixups: &[X64Fixup],
    atoms: &[RawRealizationAtom],
    raw: &[super::raw::RawProspectiveFixupReceipt],
    dispositions: &BTreeMap<X64LabelId, X64TargetProspectiveLabelDisposition>,
    fused_predecessors: &BTreeSet<(X64LabelId, X64LabelId, X64LabelId)>,
    replay_budget: &mut ProspectiveReplayBudget,
) -> Result<Vec<X64TargetProspectiveFixupReceipt>, X64TargetProfileError> {
    if fixups.len() != raw.len() {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective fixup receipt count differs from shadow".to_owned(),
        ));
    }
    let label_offsets = labels
        .iter()
        .map(|label| (label.id, label.code_offset))
        .collect::<BTreeMap<_, _>>();
    if label_offsets.len() != labels.len() {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective fixup target map repeats a label".to_owned(),
        ));
    }
    let physical_owner_offsets = labels
        .iter()
        .map(|label| (label.code_offset, label.id))
        .collect::<BTreeMap<_, _>>();
    if physical_owner_offsets.len() != labels.len() {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective physical-owner map repeats an offset".to_owned(),
        ));
    }
    let mut return_epilogue = None;
    let mut bounds_epilogue = None;
    for label in &program.labels {
        let slot = match label.owner {
            X64LabelOwner::ReturnEpilogue => Some(&mut return_epilogue),
            X64LabelOwner::BoundsEpilogue => Some(&mut bounds_epilogue),
            _ => None,
        };
        if let Some(slot) = slot {
            if slot.replace(label.id).is_some() {
                return Err(X64TargetProfileError::InternalInvariant(
                    "prospective fixup has duplicate epilogue labels".to_owned(),
                ));
            }
        }
    }
    let return_epilogue = return_epilogue.ok_or_else(|| {
        X64TargetProfileError::InternalInvariant(
            "prospective fixup has no return epilogue label".to_owned(),
        )
    })?;
    let bounds_epilogue = bounds_epilogue.ok_or_else(|| {
        X64TargetProfileError::InternalInvariant(
            "prospective fixup has no bounds epilogue label".to_owned(),
        )
    })?;
    let mut result = Vec::with_capacity(fixups.len());
    let mut fixups_by_atom = vec![Vec::<&X64Fixup>::new(); atoms.len()];
    let mut previous_patch = None;
    for (index, (fixup, receipt)) in fixups.iter().zip(raw).enumerate() {
        replay_budget.charge(1, "prospective candidate fixup replay")?;
        replay_budget.charge_index_lookup(
            atoms.len(),
            1,
            "prospective candidate fixup owning atom lookup",
        )?;
        replay_budget.charge_index_lookup(
            labels.len(),
            2,
            "prospective candidate fixup label lookup",
        )?;
        if previous_patch.is_some_and(|previous| fixup.patch_offset <= previous) {
            return Err(X64TargetProfileError::InternalInvariant(
                "prospective fixups are not strictly patch ordered".to_owned(),
            ));
        }
        previous_patch = Some(fixup.patch_offset);
        if dispositions.get(&fixup.target) != Some(&X64TargetProspectiveLabelDisposition::Live) {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "prospective fixup at {} targets a tombstone",
                fixup.patch_offset
            )));
        }
        if fixup.addend != 0 {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "prospective fixup at {} has a non-canonical addend",
                fixup.patch_offset
            )));
        }
        let patch_end =
            fixup
                .patch_offset
                .checked_add(4)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "prospective fixup patch end",
                })?;
        let owning_atom = atoms
            .partition_point(|atom| atom.start <= fixup.patch_offset)
            .checked_sub(1)
            .ok_or_else(|| {
                X64TargetProfileError::InternalInvariant(
                    "prospective fixup has no owning atom".to_owned(),
                )
            })?;
        let atom = &atoms[owning_atom];
        if fixup.patch_offset < atom.start
            || patch_end > atom.end
            || atom.class == RawTemplateClass::Tombstone
        {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "prospective fixup at {} crosses its atom",
                fixup.patch_offset
            )));
        }
        let patch_start = usize::try_from(fixup.patch_offset).map_err(|_| {
            X64TargetProfileError::CounterOverflow {
                field: "prospective fixup patch offset",
            }
        })?;
        let patch_end_usize =
            usize::try_from(patch_end).map_err(|_| X64TargetProfileError::CounterOverflow {
                field: "prospective fixup patch end",
            })?;
        let encoded = code.get(patch_start..patch_end_usize).ok_or_else(|| {
            X64TargetProfileError::InternalInvariant(
                "prospective fixup patch is outside candidate bytes".to_owned(),
            )
        })?;
        let displacement = i32::from_le_bytes(encoded.try_into().map_err(|_| {
            X64TargetProfileError::InternalInvariant(
                "prospective fixup displacement has a non-rel32 width".to_owned(),
            )
        })?);
        let target_offset = label_offsets.get(&fixup.target).copied().ok_or_else(|| {
            X64TargetProfileError::InternalInvariant(format!(
                "prospective fixup targets unknown label {}",
                fixup.target.0
            ))
        })?;
        let expected = i64::from(target_offset)
            .checked_add(i64::from(fixup.addend))
            .and_then(|target| target.checked_sub(i64::from(fixup.patch_offset) + 4))
            .ok_or(X64TargetProfileError::CounterOverflow {
                field: "prospective fixup displacement",
            })?;
        if i64::from(displacement) != expected {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "prospective fixup at {} has a different rel32 displacement",
                fixup.patch_offset
            )));
        }
        let fixup_index =
            u32::try_from(index).map_err(|_| X64TargetProfileError::CounterOverflow {
                field: "prospective fixup index",
            })?;
        let owning_atom_u32 =
            u32::try_from(owning_atom).map_err(|_| X64TargetProfileError::CounterOverflow {
                field: "prospective fixup owning atom",
            })?;
        if receipt.fixup_index != fixup_index
            || receipt.owning_atom != owning_atom_u32
            || receipt.patch_offset != fixup.patch_offset
            || receipt.target != fixup.target
            || receipt.addend != fixup.addend
        {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "prospective fixup receipt {index} differs from independent replay"
            )));
        }
        fixups_by_atom[owning_atom].push(fixup);
        result.push(X64TargetProspectiveFixupReceipt {
            fixup_index,
            owning_atom: owning_atom_u32,
            patch_offset: fixup.patch_offset,
            target: fixup.target,
            addend: fixup.addend,
        });
    }
    for (index, (atom, owned_fixups)) in atoms.iter().zip(&fixups_by_atom).enumerate() {
        replay_budget.charge(1, "prospective candidate atom fixup replay")?;
        replay_budget.charge_usize(
            owned_fixups.len(),
            "prospective candidate owned fixup replay",
        )?;
        validate_prospective_atom_fixups(
            program,
            code,
            atoms,
            &physical_owner_offsets,
            index,
            atom,
            owned_fixups,
            fused_predecessors,
            replay_budget,
            return_epilogue,
            bounds_epilogue,
        )?;
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn validate_prospective_atom_fixups(
    program: &X64TargetProgram,
    code: &[u8],
    atoms: &[RawRealizationAtom],
    physical_owner_offsets: &BTreeMap<u32, X64LabelId>,
    atom_index: usize,
    atom: &RawRealizationAtom,
    fixups: &[&X64Fixup],
    fused_predecessors: &BTreeSet<(X64LabelId, X64LabelId, X64LabelId)>,
    replay_budget: &mut ProspectiveReplayBudget,
    return_epilogue: X64LabelId,
    bounds_epilogue: X64LabelId,
) -> Result<(), X64TargetProfileError> {
    let expected_targets = match atom.event {
        RawExecutionEvent::Entry => {
            require_prospective_fixup_count(fixups, 1, atom_index)?;
            replay_budget.charge_index_lookup(
                program.functions.len(),
                1,
                "prospective entry function lookup",
            )?;
            let entry_function = prospective_function_by_id(program, program.entry)?;
            replay_budget.charge_index_lookup(
                entry_function.blocks.len(),
                1,
                "prospective entry block lookup",
            )?;
            let entry = prospective_function_entry(entry_function)?;
            vec![prospective_thread_noop_target(
                program,
                entry.label,
                replay_budget,
            )?]
        }
        RawExecutionEvent::Tail { label } => {
            if fixups.is_empty() {
                let next = atoms.get(atom_index + 1).ok_or_else(|| {
                    X64TargetProfileError::InternalInvariant(format!(
                        "prospective tail atom {atom_index} omits a non-fused rel32"
                    ))
                })?;
                let owner =
                    prospective_physical_owner(physical_owner_offsets, atom.start, atom.end)?;
                let next_owner =
                    prospective_physical_owner(physical_owner_offsets, next.start, next.end)?;
                let RawExecutionEvent::Instruction {
                    label: fused_target,
                    index: 0,
                } = next.event
                else {
                    return Err(X64TargetProfileError::InternalInvariant(format!(
                        "prospective tail atom {atom_index} has no exact fused successor event"
                    )));
                };
                if next.start != atom.end
                    || next.class != RawTemplateClass::FusedCompareInstruction
                    || owner != next_owner
                    || !fused_predecessors.contains(&(owner, label, fused_target))
                {
                    return Err(X64TargetProfileError::InternalInvariant(format!(
                        "prospective tail atom {atom_index} omits a non-fused rel32"
                    )));
                }
                Vec::new()
            } else {
                require_prospective_fixup_count(fixups, 1, atom_index)?;
                let block = block_for_label(program, label)?;
                let X64Terminator::TailJumpRel32 {
                    function,
                    target_label,
                    arguments,
                    ..
                } = &block.terminator
                else {
                    return Err(X64TargetProfileError::InternalInvariant(format!(
                        "prospective tail atom {atom_index} has no logical target"
                    )));
                };
                vec![prospective_direct_composed_tail_target(
                    program,
                    *function,
                    *target_label,
                    arguments,
                    replay_budget,
                )?]
            }
        }
        RawExecutionEvent::Return { .. } => {
            require_prospective_fixup_count(fixups, 1, atom_index)?;
            vec![return_epilogue]
        }
        RawExecutionEvent::Branch { label } => {
            require_prospective_fixup_count(fixups, 1, atom_index)?;
            let block = block_for_label(program, label)?;
            let X64Terminator::BranchRel32 { then_label, .. } = &block.terminator else {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "prospective branch atom {atom_index} has no then target"
                )));
            };
            vec![prospective_thread_noop_target(
                program,
                *then_label,
                replay_budget,
            )?]
        }
        RawExecutionEvent::BranchElse { label } => {
            require_prospective_fixup_count(fixups, 1, atom_index)?;
            let block = block_for_label(program, label)?;
            let X64Terminator::BranchRel32 { else_label, .. } = &block.terminator else {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "prospective branch-else atom {atom_index} has no else target"
                )));
            };
            vec![prospective_thread_noop_target(
                program,
                *else_label,
                replay_budget,
            )?]
        }
        RawExecutionEvent::Instruction { label, index } => {
            let block = block_for_label(program, label)?;
            let instruction = block.instructions.get(index as usize).ok_or_else(|| {
                X64TargetProfileError::InternalInvariant(format!(
                    "prospective instruction atom {atom_index} has no instruction"
                ))
            })?;
            if matches!(
                instruction.kind,
                X64InstructionKind::ArrayGetF64Checked { .. }
            ) && atom.class == RawTemplateClass::OrdinaryInstruction
            {
                require_prospective_fixup_count(fixups, 2, atom_index)?;
                vec![bounds_epilogue; 2]
            } else {
                require_prospective_fixup_count(fixups, 0, atom_index)?;
                Vec::new()
            }
        }
        RawExecutionEvent::ReturnEpilogue
        | RawExecutionEvent::BoundsEpilogue
        | RawExecutionEvent::Static => {
            require_prospective_fixup_count(fixups, 0, atom_index)?;
            Vec::new()
        }
    };
    if fixups.windows(2).any(|pair| {
        pair[0]
            .patch_offset
            .checked_add(4)
            .is_none_or(|end| end > pair[1].patch_offset)
    }) {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "prospective atom {atom_index} has overlapping rel32 fields"
        )));
    }
    let branch_condition_opcode = if atom.class == RawTemplateClass::BranchCondition {
        Some(prospective_branch_condition_opcode(
            program,
            atoms,
            physical_owner_offsets,
            atom_index,
            atom,
        )?)
    } else {
        None
    };
    for (ordinal, (fixup, expected_target)) in fixups.iter().zip(expected_targets).enumerate() {
        if fixup.target != expected_target {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "prospective fixup in atom {atom_index} targets a different logical label"
            )));
        }
        let conditional_opcode = match atom.class {
            RawTemplateClass::BranchCondition => branch_condition_opcode,
            RawTemplateClass::OrdinaryInstruction => match ordinal {
                0 => Some(0x88),
                1 => Some(0x83),
                _ => None,
            },
            _ => None,
        };
        validate_prospective_rel32_opcode(code, atom, fixup, atom_index, conditional_opcode)?;
    }
    Ok(())
}

fn prospective_branch_condition_opcode(
    program: &X64TargetProgram,
    atoms: &[RawRealizationAtom],
    physical_owner_offsets: &BTreeMap<u32, X64LabelId>,
    atom_index: usize,
    atom: &RawRealizationAtom,
) -> Result<u8, X64TargetProfileError> {
    let Some(previous) = atom_index.checked_sub(1).and_then(|index| atoms.get(index)) else {
        return Ok(0x85);
    };
    if previous.end != atom.start || previous.class != RawTemplateClass::FusedCompareInstruction {
        return Ok(0x85);
    }
    let previous_owner =
        prospective_physical_owner(physical_owner_offsets, previous.start, previous.end)?;
    let owner = prospective_physical_owner(physical_owner_offsets, atom.start, atom.end)?;
    if previous_owner != owner {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "prospective fused branch atom {atom_index} crosses its physical owner"
        )));
    }
    let RawExecutionEvent::Instruction { label, index } = previous.event else {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "prospective fused branch atom {atom_index} has no source comparison"
        )));
    };
    let instruction = block_for_label(program, label)?
        .instructions
        .get(index as usize)
        .ok_or_else(|| {
            X64TargetProfileError::InternalInvariant(format!(
                "prospective fused branch atom {atom_index} has no source instruction"
            ))
        })?;
    let X64InstructionKind::I64Setcc { condition, .. } = &instruction.kind else {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "prospective fused branch atom {atom_index} source is not I64Setcc"
        )));
    };
    Ok(match condition {
        X64SetCondition::SignedLessThan => 0x8c,
        X64SetCondition::SignedGreaterOrEqual => 0x8d,
    })
}

fn require_prospective_fixup_count(
    fixups: &[&X64Fixup],
    expected: usize,
    atom: usize,
) -> Result<(), X64TargetProfileError> {
    if fixups.len() != expected {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "prospective atom {atom} owns {} fixups, expected {expected}",
            fixups.len()
        )));
    }
    Ok(())
}

fn validate_prospective_rel32_opcode(
    code: &[u8],
    atom: &RawRealizationAtom,
    fixup: &X64Fixup,
    atom_index: usize,
    expected_conditional_opcode: Option<u8>,
) -> Result<(), X64TargetProfileError> {
    let patch = usize::try_from(fixup.patch_offset).map_err(|_| {
        X64TargetProfileError::CounterOverflow {
            field: "prospective fixup opcode offset",
        }
    })?;
    let is_unconditional = patch
        .checked_sub(1)
        .and_then(|offset| code.get(offset))
        .copied()
        == Some(0xe9);
    let conditional_opcode = patch
        .checked_sub(2)
        .and_then(|offset| code.get(offset..patch))
        .and_then(|opcode| (opcode.len() == 2 && opcode[0] == 0x0f).then_some(opcode[1]));
    let valid = expected_conditional_opcode.map_or(is_unconditional, |expected| {
        conditional_opcode == Some(expected)
    });
    if !valid {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "prospective fixup in atom {atom_index} is not a canonical rel32 template field"
        )));
    }
    match atom.class {
        RawTemplateClass::BranchCondition
            if atom.byte_len() != 6 || fixup.patch_offset != atom.start.saturating_add(2) =>
        {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "prospective branch atom {atom_index} is not an exact six-byte template"
            )));
        }
        RawTemplateClass::BranchElseJump
            if atom.byte_len() != 5 || fixup.patch_offset != atom.start.saturating_add(1) =>
        {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "prospective branch-else atom {atom_index} is not an exact five-byte template"
            )));
        }
        _ => {}
    }
    if !matches!(atom.class, RawTemplateClass::OrdinaryInstruction)
        && fixup.patch_offset.checked_add(4) != Some(atom.end)
    {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "prospective fixup in atom {atom_index} is not the terminal rel32 field"
        )));
    }
    Ok(())
}

#[derive(Debug)]
struct ProspectiveDirectTailRoute {
    callee: X64FunctionId,
    target_label: X64LabelId,
    arguments: Vec<X64Operand>,
}

fn prospective_function_by_id(
    program: &X64TargetProgram,
    id: X64FunctionId,
) -> Result<&X64Function, X64TargetProfileError> {
    program
        .functions
        .binary_search_by_key(&id, |function| function.id)
        .ok()
        .map(|index| &program.functions[index])
        .ok_or_else(|| {
            X64TargetProfileError::InternalInvariant(format!(
                "prospective direct tail names missing function {}",
                id.0
            ))
        })
}

fn prospective_function_entry(function: &X64Function) -> Result<&X64Block, X64TargetProfileError> {
    function
        .blocks
        .binary_search_by_key(&function.entry_block, |block| block.id)
        .ok()
        .map(|index| &function.blocks[index])
        .ok_or_else(|| {
            X64TargetProfileError::InternalInvariant(format!(
                "prospective direct tail function {} has no entry block",
                function.id.0
            ))
        })
}

fn prospective_validate_tail_transfer<'program>(
    program: &'program X64TargetProgram,
    callee: X64FunctionId,
    arguments: &[X64Operand],
    replay_budget: &mut ProspectiveReplayBudget,
) -> Result<&'program X64Function, X64TargetProfileError> {
    replay_budget.charge_index_lookup(
        program.functions.len(),
        1,
        "prospective tail function lookup",
    )?;
    let function = prospective_function_by_id(program, callee)?;
    replay_budget.charge_usize(arguments.len(), "prospective tail transfer arguments")?;
    if arguments.len() != function.parameters.len()
        || arguments
            .iter()
            .zip(&function.parameters)
            .any(|(argument, parameter)| argument.ty() != parameter.home.ty)
    {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "prospective direct tail has an invalid transfer to function {}",
            callee.0
        )));
    }
    Ok(function)
}

fn prospective_substitute_tail_arguments(
    parameters: &[X64Parameter],
    current_arguments: &[X64Operand],
    next_arguments: &[X64Operand],
    replay_budget: &mut ProspectiveReplayBudget,
) -> Result<Option<Vec<X64Operand>>, X64TargetProfileError> {
    replay_budget.charge_usize(parameters.len(), "prospective tail substitution parameters")?;
    if parameters.len() != current_arguments.len() {
        return Ok(None);
    }
    let mut parameter_by_home = BTreeMap::new();
    for (index, parameter) in parameters.iter().enumerate() {
        replay_budget.charge_index_lookup(
            parameter_by_home.len(),
            1,
            "prospective tail substitution home index",
        )?;
        if parameter_by_home
            .insert(prospective_home_key(parameter.home), index)
            .is_some()
        {
            return Ok(None);
        }
    }
    let substitution_lookup = prospective_index_lookup_work(parameter_by_home.len());
    replay_budget.charge_usize(
        next_arguments.len(),
        "prospective tail substituted argument allocation",
    )?;
    let mut substituted = Vec::new();
    substituted
        .try_reserve_exact(next_arguments.len())
        .map_err(|_| {
            X64TargetProfileError::InternalInvariant(
                "prospective tail substitution allocation failed".to_owned(),
            )
        })?;
    for argument in next_arguments {
        replay_budget.charge(
            substitution_lookup,
            "prospective tail substitution argument lookup",
        )?;
        let argument = match argument {
            X64Operand::Immediate { .. } => argument.clone(),
            X64Operand::Home(home) => {
                let Some(index) = parameter_by_home.get(&prospective_home_key(*home)).copied()
                else {
                    return Ok(None);
                };
                current_arguments[index].clone()
            }
        };
        substituted.push(argument);
    }
    Ok(Some(substituted))
}

fn prospective_home_key(home: X64Home) -> (X64HomeSlot, u32, u8, MachineType) {
    (home.slot, home.offset, home.width, home.ty)
}

fn prospective_home_word_offsets(home: X64Home) -> impl Iterator<Item = u32> {
    (0..u32::from(home.width / 8)).map(move |word| home.offset + word * 8)
}

fn prospective_direct_tail_schedule_exists(
    arguments: &[X64Operand],
    parameters: &[X64Parameter],
    replay_budget: &mut ProspectiveReplayBudget,
) -> Result<bool, X64TargetProfileError> {
    replay_budget.charge_usize(
        arguments.len().max(parameters.len()),
        "prospective direct-tail schedule arity",
    )?;
    if arguments.len() != parameters.len() {
        return Ok(false);
    }
    let mut destination_words = BTreeSet::new();
    for parameter in parameters {
        for offset in prospective_home_word_offsets(parameter.home) {
            replay_budget.charge_index_lookup(
                destination_words.len(),
                1,
                "prospective direct-tail destination word",
            )?;
            if !destination_words.insert(offset) {
                return Ok(false);
            }
        }
    }
    let mut pending = Vec::new();
    pending.try_reserve_exact(arguments.len()).map_err(|_| {
        X64TargetProfileError::InternalInvariant(
            "prospective direct-tail pending allocation failed".to_owned(),
        )
    })?;
    pending.extend(arguments.iter().zip(parameters).enumerate().filter_map(
        |(index, (argument, parameter))| {
            (!matches!(argument, X64Operand::Home(home) if *home == parameter.home))
                .then_some(index)
        },
    ));
    while !pending.is_empty() {
        let mut source_words = BTreeSet::new();
        for index in &pending {
            if let X64Operand::Home(home) = arguments[*index] {
                for offset in prospective_home_word_offsets(home) {
                    replay_budget.charge_index_lookup(
                        source_words.len(),
                        1,
                        "prospective direct-tail source word",
                    )?;
                    source_words.insert(offset);
                }
            }
        }
        let mut schedulable_position = None;
        for (position, index) in pending.iter().copied().enumerate() {
            let mut schedulable = true;
            for offset in prospective_home_word_offsets(parameters[index].home) {
                replay_budget.charge_index_lookup(
                    source_words.len(),
                    1,
                    "prospective direct-tail schedule dependency",
                )?;
                if source_words.contains(&offset) {
                    schedulable = false;
                    break;
                }
            }
            if schedulable {
                schedulable_position = Some(position);
                break;
            }
        }
        let Some(position) = schedulable_position else {
            return Ok(false);
        };
        replay_budget.charge_usize(
            pending.len().saturating_sub(position),
            "prospective direct-tail pending compaction",
        )?;
        pending.remove(position);
    }
    Ok(true)
}

fn prospective_direct_composed_tail_target(
    program: &X64TargetProgram,
    callee: X64FunctionId,
    target_label: X64LabelId,
    arguments: &[X64Operand],
    replay_budget: &mut ProspectiveReplayBudget,
) -> Result<X64LabelId, X64TargetProfileError> {
    replay_budget.charge_usize(arguments.len(), "prospective direct-tail initial arguments")?;
    let mut original_arguments = Vec::new();
    original_arguments
        .try_reserve_exact(arguments.len())
        .map_err(|_| {
            X64TargetProfileError::InternalInvariant(
                "prospective direct-tail argument allocation failed".to_owned(),
            )
        })?;
    original_arguments.extend_from_slice(arguments);
    let mut route = ProspectiveDirectTailRoute {
        callee,
        target_label,
        arguments: original_arguments,
    };
    let mut composed = false;
    let mut visited = BTreeSet::new();
    for _ in 0..=program.functions.len() {
        replay_budget.charge(1, "prospective direct-tail route hop")?;
        replay_budget.charge_index_lookup(
            visited.len(),
            1,
            "prospective direct-tail visited function",
        )?;
        if !visited.insert(route.callee) {
            return prospective_thread_noop_target(program, target_label, replay_budget);
        }
        let current = prospective_validate_tail_transfer(
            program,
            route.callee,
            &route.arguments,
            replay_budget,
        )?;
        replay_budget.charge_index_lookup(
            current.blocks.len(),
            1,
            "prospective direct-tail entry lookup",
        )?;
        let entry = prospective_function_entry(current)?;
        if entry.label != route.target_label {
            return prospective_thread_noop_target(program, target_label, replay_budget);
        }
        if !entry.instructions.is_empty() {
            break;
        }
        let X64Terminator::TailJumpRel32 {
            function: next_callee,
            target_label: next_target,
            arguments: next_arguments,
            ..
        } = &entry.terminator
        else {
            break;
        };
        replay_budget.charge_index_lookup(
            program.functions.len(),
            1,
            "prospective direct-tail next function lookup",
        )?;
        let next = prospective_function_by_id(program, *next_callee)?;
        replay_budget.charge_index_lookup(
            next.blocks.len(),
            1,
            "prospective direct-tail next entry lookup",
        )?;
        if prospective_function_entry(next)?.label != *next_target {
            return prospective_thread_noop_target(program, target_label, replay_budget);
        }
        let Some(arguments) = prospective_substitute_tail_arguments(
            &current.parameters,
            &route.arguments,
            next_arguments,
            replay_budget,
        )?
        else {
            return prospective_thread_noop_target(program, target_label, replay_budget);
        };
        prospective_validate_tail_transfer(program, *next_callee, &arguments, replay_budget)?;
        route = ProspectiveDirectTailRoute {
            callee: *next_callee,
            target_label: *next_target,
            arguments,
        };
        composed = true;
    }
    if composed {
        let final_callee = prospective_validate_tail_transfer(
            program,
            route.callee,
            &route.arguments,
            replay_budget,
        )?;
        if !prospective_direct_tail_schedule_exists(
            &route.arguments,
            &final_callee.parameters,
            replay_budget,
        )? {
            return prospective_thread_noop_target(program, target_label, replay_budget);
        }
    }
    prospective_thread_noop_target(program, route.target_label, replay_budget)
}

fn prospective_thread_noop_target(
    program: &X64TargetProgram,
    start: X64LabelId,
    replay_budget: &mut ProspectiveReplayBudget,
) -> Result<X64LabelId, X64TargetProfileError> {
    let original = start;
    let mut current = start;
    let mut visited = BTreeSet::new();
    loop {
        replay_budget.charge(1, "prospective no-op-tail route hop")?;
        replay_budget.charge_index_lookup(
            visited.len(),
            1,
            "prospective no-op-tail visited label",
        )?;
        if !visited.insert(current) {
            return Ok(original);
        }
        replay_budget.charge_index_lookup(
            program.labels.len(),
            1,
            "prospective no-op-tail label lookup",
        )?;
        let label = program
            .labels
            .binary_search_by_key(&current, |label| label.id)
            .ok()
            .map(|index| &program.labels[index])
            .ok_or_else(|| {
                X64TargetProfileError::InternalInvariant(format!(
                    "prospective fixup target names unknown label {}",
                    current.0
                ))
            })?;
        let X64LabelOwner::Block {
            function: function_id,
            block: block_id,
        } = label.owner
        else {
            return Ok(current);
        };
        replay_budget.charge_index_lookup(
            program.functions.len(),
            1,
            "prospective no-op-tail function lookup",
        )?;
        let target_function = prospective_function_by_id(program, function_id)?;
        replay_budget.charge_index_lookup(
            target_function.blocks.len(),
            1,
            "prospective no-op-tail block lookup",
        )?;
        let target_block = target_function
            .blocks
            .binary_search_by_key(&block_id, |block| block.id)
            .ok()
            .map(|index| &target_function.blocks[index])
            .ok_or_else(|| {
                X64TargetProfileError::InternalInvariant(format!(
                    "prospective fixup target label {} has no block",
                    current.0
                ))
            })?;
        if !target_block.instructions.is_empty() {
            return Ok(current);
        };
        let X64Terminator::TailJumpRel32 {
            function: callee_id,
            target_label,
            arguments,
            ..
        } = &target_block.terminator
        else {
            return Ok(current);
        };
        replay_budget.charge_index_lookup(
            program.functions.len(),
            1,
            "prospective no-op-tail callee lookup",
        )?;
        let callee = prospective_function_by_id(program, *callee_id)?;
        replay_budget.charge_usize(
            arguments.len().max(callee.parameters.len()),
            "prospective no-op-tail identity arguments",
        )?;
        if arguments.len() != callee.parameters.len()
            || !arguments
                .iter()
                .zip(&callee.parameters)
                .all(|(argument, parameter)| {
                    matches!(argument, X64Operand::Home(home) if *home == parameter.home)
                })
        {
            return Ok(current);
        }
        replay_budget.charge_index_lookup(
            callee.blocks.len(),
            1,
            "prospective no-op-tail callee entry lookup",
        )?;
        let entry = callee
            .blocks
            .binary_search_by_key(&callee.entry_block, |block| block.id)
            .ok()
            .map(|index| &callee.blocks[index])
            .ok_or_else(|| {
                X64TargetProfileError::InternalInvariant(format!(
                    "prospective fixup target label {} has no callee entry",
                    current.0
                ))
            })?;
        if entry.label != *target_label {
            return Ok(current);
        }
        current = *target_label;
    }
}

pub fn x64_target_prospective_shared_join_realization_hash(
    realization: &X64TargetProspectiveSharedJoinRealization,
) -> Result<SemanticHash, X64TargetProfileError> {
    let capacity = prospective_realization_hash_preimage_len(realization)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|_| {
        X64TargetProfileError::InternalInvariant(
            "prospective realization hash preimage allocation failed".to_owned(),
        )
    })?;
    bytes.extend_from_slice(PROSPECTIVE_SHARED_JOIN_REALIZATION_DOMAIN);
    prospective_put_bool(&mut bytes, realization.complete);
    prospective_put_u64(&mut bytes, realization.baseline_code_bytes);
    prospective_put_hash(&mut bytes, realization.baseline_code_hash);
    prospective_put_u64(&mut bytes, realization.candidate_code_bytes);
    prospective_put_hash(&mut bytes, realization.candidate_code_hash);
    for value in [
        realization.code_bytes_added,
        realization.code_bytes_removed,
        realization.baseline_atom_count,
        realization.candidate_atom_count,
        realization.atom_count_added,
        realization.atom_count_removed,
        realization.label_count,
        realization.baseline_fixup_count,
        realization.candidate_fixup_count,
        realization.fixup_count_added,
        realization.fixup_count_removed,
    ] {
        prospective_put_u64(&mut bytes, value);
    }
    prospective_put_u32(&mut bytes, realization.body_replicas);
    prospective_put_u32(&mut bytes, realization.shared_join_authority_atoms);
    prospective_put_u128(&mut bytes, realization.candidate_weighted_template_bytes);
    prospective_put_bool(&mut bytes, realization.machine_semantic_proof.complete);
    prospective_put_u32(&mut bytes, realization.machine_semantic_proof.register_rows);
    prospective_put_u64(&mut bytes, realization.machine_semantic_proof.decoded_bytes);
    prospective_put_u32(
        &mut bytes,
        realization.machine_semantic_proof.decoded_instructions,
    );
    prospective_put_u32(
        &mut bytes,
        realization.machine_semantic_proof.symbolic_nodes,
    );
    prospective_put_u32(
        &mut bytes,
        realization.machine_semantic_proof.reference_route_events,
    );
    prospective_put_len(
        &mut bytes,
        realization.atoms.len(),
        "prospective atom count",
    )?;
    for atom in &realization.atoms {
        prospective_put_u32(&mut bytes, atom.physical_owner.0);
        prospective_encode_event(&mut bytes, atom.semantic_event);
        prospective_encode_authority(&mut bytes, atom.execution_authority);
        prospective_put_u8(&mut bytes, prospective_template_tag(atom.class));
        prospective_put_u32(&mut bytes, atom.start);
        prospective_put_u32(&mut bytes, atom.end);
        prospective_put_u32(&mut bytes, atom.static_bytes);
        prospective_put_u64(&mut bytes, atom.executions);
        prospective_put_u128(&mut bytes, atom.weighted_bytes);
    }
    prospective_put_len(
        &mut bytes,
        realization.labels.len(),
        "prospective label receipt count",
    )?;
    for label in &realization.labels {
        prospective_put_u32(&mut bytes, label.label.0);
        prospective_encode_label_owner(&mut bytes, label.owner);
        prospective_put_u32(&mut bytes, label.code_offset);
        prospective_put_u32(&mut bytes, label.owning_atom);
        prospective_put_u8(&mut bytes, prospective_disposition_tag(label.disposition));
    }
    prospective_put_len(
        &mut bytes,
        realization.fixups.len(),
        "prospective fixup receipt count",
    )?;
    for fixup in &realization.fixups {
        prospective_put_u32(&mut bytes, fixup.fixup_index);
        prospective_put_u32(&mut bytes, fixup.owning_atom);
        prospective_put_u32(&mut bytes, fixup.patch_offset);
        prospective_put_u32(&mut bytes, fixup.target.0);
        prospective_put_i32(&mut bytes, fixup.addend);
    }
    if bytes.len() != capacity {
        return Err(X64TargetProfileError::InternalInvariant(
            "prospective realization hash preimage length differs from canonical sizing replay"
                .to_owned(),
        ));
    }
    Ok(SemanticHash(sha256(&bytes)))
}

fn prospective_realization_hash_preimage_len(
    realization: &X64TargetProspectiveSharedJoinRealization,
) -> Result<usize, X64TargetProfileError> {
    for (length, field) in [
        (realization.atoms.len(), "prospective atom count"),
        (realization.labels.len(), "prospective label receipt count"),
        (realization.fixups.len(), "prospective fixup receipt count"),
    ] {
        u32::try_from(length).map_err(|_| X64TargetProfileError::CounterOverflow { field })?;
    }

    let mut length = PROSPECTIVE_SHARED_JOIN_REALIZATION_DOMAIN.len();
    for bytes in [1_usize, 8, 32, 8, 32, 11 * 8, 4, 4, 16, 25, 4] {
        prospective_add_hash_preimage_bytes(&mut length, bytes)?;
    }
    for atom in &realization.atoms {
        let atom_bytes = 41_usize
            .checked_add(prospective_event_encoded_len(atom.semantic_event))
            .and_then(|bytes| {
                bytes.checked_add(prospective_authority_encoded_len(atom.execution_authority))
            })
            .ok_or(X64TargetProfileError::CounterOverflow {
                field: "prospective realization hash atom bytes",
            })?;
        prospective_add_hash_preimage_bytes(&mut length, atom_bytes)?;
    }
    prospective_add_hash_preimage_bytes(&mut length, 4)?;
    for label in &realization.labels {
        let label_bytes = 13_usize
            .checked_add(prospective_label_owner_encoded_len(label.owner))
            .ok_or(X64TargetProfileError::CounterOverflow {
                field: "prospective realization hash label bytes",
            })?;
        prospective_add_hash_preimage_bytes(&mut length, label_bytes)?;
    }
    prospective_add_hash_preimage_bytes(&mut length, 4)?;
    let fixup_bytes =
        realization
            .fixups
            .len()
            .checked_mul(20)
            .ok_or(X64TargetProfileError::CounterOverflow {
                field: "prospective realization hash fixup bytes",
            })?;
    prospective_add_hash_preimage_bytes(&mut length, fixup_bytes)?;
    Ok(length)
}

fn prospective_add_hash_preimage_bytes(
    length: &mut usize,
    amount: usize,
) -> Result<(), X64TargetProfileError> {
    *length = length
        .checked_add(amount)
        .ok_or(X64TargetProfileError::CounterOverflow {
            field: "prospective realization hash preimage bytes",
        })?;
    if *length > MAX_PROSPECTIVE_REALIZATION_HASH_PREIMAGE_BYTES {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "prospective realization hash preimage {} exceeds {MAX_PROSPECTIVE_REALIZATION_HASH_PREIMAGE_BYTES}",
            *length
        )));
    }
    Ok(())
}

const fn prospective_event_encoded_len(event: X64TargetProfileEvent) -> usize {
    match event {
        X64TargetProfileEvent::Instruction { .. } => 9,
        X64TargetProfileEvent::Tail { .. }
        | X64TargetProfileEvent::Return { .. }
        | X64TargetProfileEvent::Branch { .. }
        | X64TargetProfileEvent::BranchElse { .. } => 5,
        X64TargetProfileEvent::Entry
        | X64TargetProfileEvent::ReturnEpilogue
        | X64TargetProfileEvent::BoundsEpilogue
        | X64TargetProfileEvent::Static => 1,
    }
}

const fn prospective_authority_encoded_len(
    authority: X64TargetProspectiveExecutionAuthority,
) -> usize {
    match authority {
        X64TargetProspectiveExecutionAuthority::Semantic { event } => {
            1 + prospective_event_encoded_len(event)
        }
        X64TargetProspectiveExecutionAuthority::SharedJoin { .. } => 14,
        X64TargetProspectiveExecutionAuthority::Static => 1,
    }
}

const fn prospective_label_owner_encoded_len(owner: X64LabelOwner) -> usize {
    match owner {
        X64LabelOwner::Block { .. } => 9,
        X64LabelOwner::EntryAdapter
        | X64LabelOwner::ReturnEpilogue
        | X64LabelOwner::BoundsEpilogue => 1,
    }
}

fn prospective_put_len(
    bytes: &mut Vec<u8>,
    length: usize,
    field: &'static str,
) -> Result<(), X64TargetProfileError> {
    let length =
        u32::try_from(length).map_err(|_| X64TargetProfileError::CounterOverflow { field })?;
    prospective_put_u32(bytes, length);
    Ok(())
}

fn prospective_put_bool(bytes: &mut Vec<u8>, value: bool) {
    prospective_put_u8(bytes, u8::from(value));
}

fn prospective_put_u8(bytes: &mut Vec<u8>, value: u8) {
    bytes.push(value);
}

fn prospective_put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn prospective_put_i32(bytes: &mut Vec<u8>, value: i32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn prospective_put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn prospective_put_u128(bytes: &mut Vec<u8>, value: u128) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn prospective_put_hash(bytes: &mut Vec<u8>, hash: SemanticHash) {
    bytes.extend_from_slice(&hash.0);
}

fn prospective_encode_event(bytes: &mut Vec<u8>, event: X64TargetProfileEvent) {
    match event {
        X64TargetProfileEvent::Entry => prospective_put_u8(bytes, 0),
        X64TargetProfileEvent::Instruction { label, index } => {
            prospective_put_u8(bytes, 1);
            prospective_put_u32(bytes, label.0);
            prospective_put_u32(bytes, index);
        }
        X64TargetProfileEvent::Tail { label } => {
            prospective_put_u8(bytes, 2);
            prospective_put_u32(bytes, label.0);
        }
        X64TargetProfileEvent::Return { label } => {
            prospective_put_u8(bytes, 3);
            prospective_put_u32(bytes, label.0);
        }
        X64TargetProfileEvent::Branch { label } => {
            prospective_put_u8(bytes, 4);
            prospective_put_u32(bytes, label.0);
        }
        X64TargetProfileEvent::BranchElse { label } => {
            prospective_put_u8(bytes, 5);
            prospective_put_u32(bytes, label.0);
        }
        X64TargetProfileEvent::ReturnEpilogue => prospective_put_u8(bytes, 6),
        X64TargetProfileEvent::BoundsEpilogue => prospective_put_u8(bytes, 7),
        X64TargetProfileEvent::Static => prospective_put_u8(bytes, 8),
    }
}

fn prospective_encode_authority(
    bytes: &mut Vec<u8>,
    authority: X64TargetProspectiveExecutionAuthority,
) {
    match authority {
        X64TargetProspectiveExecutionAuthority::Semantic { event } => {
            prospective_put_u8(bytes, 0);
            prospective_encode_event(bytes, event);
        }
        X64TargetProspectiveExecutionAuthority::SharedJoin {
            target,
            root,
            authority_trigger,
            partition,
        } => {
            prospective_put_u8(bytes, 1);
            prospective_put_u32(bytes, target.0);
            prospective_put_u32(bytes, root.0);
            prospective_put_u32(bytes, authority_trigger.0);
            prospective_put_u8(
                bytes,
                match partition {
                    X64TargetProspectiveSharedJoinPartition::All => 0,
                    X64TargetProspectiveSharedJoinPartition::Else => 1,
                },
            );
        }
        X64TargetProspectiveExecutionAuthority::Static => prospective_put_u8(bytes, 2),
    }
}

fn prospective_template_tag(class: X64TargetProfileTemplateClass) -> u8 {
    match class {
        X64TargetProfileTemplateClass::EntryPrologue => 0,
        X64TargetProfileTemplateClass::OrdinaryInstruction => 1,
        X64TargetProfileTemplateClass::RegisterInstruction => 2,
        X64TargetProfileTemplateClass::TailTransfer => 3,
        X64TargetProfileTemplateClass::ReturnTransfer => 4,
        X64TargetProfileTemplateClass::BranchCondition => 5,
        X64TargetProfileTemplateClass::BranchElseJump => 6,
        X64TargetProfileTemplateClass::FusedCompareInstruction => 7,
        X64TargetProfileTemplateClass::ReturnEpilogue => 8,
        X64TargetProfileTemplateClass::BoundsEpilogue => 9,
        X64TargetProfileTemplateClass::Tombstone => 10,
    }
}

fn prospective_encode_label_owner(bytes: &mut Vec<u8>, owner: X64LabelOwner) {
    match owner {
        X64LabelOwner::EntryAdapter => prospective_put_u8(bytes, 0),
        X64LabelOwner::Block { function, block } => {
            prospective_put_u8(bytes, 1);
            prospective_put_u32(bytes, function.0);
            prospective_put_u32(bytes, block.0);
        }
        X64LabelOwner::ReturnEpilogue => prospective_put_u8(bytes, 2),
        X64LabelOwner::BoundsEpilogue => prospective_put_u8(bytes, 3),
    }
}

fn prospective_disposition_tag(disposition: X64TargetProspectiveLabelDisposition) -> u8 {
    match disposition {
        X64TargetProspectiveLabelDisposition::Live => 0,
        X64TargetProspectiveLabelDisposition::UnreachableTombstone => 1,
        X64TargetProspectiveLabelDisposition::Policy14ConsumedTombstone => 2,
        X64TargetProspectiveLabelDisposition::SharedJoinConsumedTombstone => 3,
    }
}

fn validate_shared_join_ancestors(
    step: &RawSharedJoinCompositionStep,
    seen_targets: &BTreeSet<X64LabelId>,
) -> Result<(), X64TargetProfileError> {
    let mut previous = None;
    for ancestor in &step.ancestors {
        if previous.is_some_and(|previous| previous >= *ancestor)
            || !seen_targets.contains(ancestor)
            || *ancestor == step.target
        {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "shared-join composition target {} has non-canonical ancestors",
                step.target.0
            )));
        }
        previous = Some(*ancestor);
    }
    let mut route_ancestors = BTreeSet::new();
    for ingress in &step.ingresses {
        for event in &ingress.lineage {
            if let RawSharedJoinLineageEvent::Instruction { label, index } = event {
                if *index != 0 || !seen_targets.contains(label) || *label == step.target {
                    return Err(X64TargetProfileError::InternalInvariant(format!(
                        "shared-join composition target {} has a non-canonical ingress route instruction",
                        step.target.0
                    )));
                }
                route_ancestors.insert(*label);
            }
        }
    }
    if route_ancestors.into_iter().collect::<Vec<_>>() != step.ancestors {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "shared-join composition target {} ancestor summary differs from ingress routes",
            step.target.0
        )));
    }
    Ok(())
}

fn count_instruction(
    program: &X64TargetProgram,
    label: X64LabelId,
    index: u32,
    count: u64,
    counts: &mut X64TargetProfileInstructionCounts,
) -> Result<(), X64TargetProfileError> {
    let block = block_for_label(program, label)?;
    let index = usize::try_from(index).map_err(|_| {
        X64TargetProfileError::InternalInvariant(format!(
            "instruction index {index} does not fit usize"
        ))
    })?;
    let instruction = block.instructions.get(index).ok_or_else(|| {
        X64TargetProfileError::InternalInvariant(format!(
            "label {} has no instruction {index}",
            label.0
        ))
    })?;
    let field = match instruction.kind {
        X64InstructionKind::Move(_) => &mut counts.moves,
        X64InstructionKind::I64Wrapping {
            opcode: X64I64Opcode::Add,
            ..
        } => &mut counts.i64_adds,
        X64InstructionKind::I64Wrapping {
            opcode: X64I64Opcode::Sub,
            ..
        } => &mut counts.i64_subtracts,
        X64InstructionKind::I64Wrapping {
            opcode: X64I64Opcode::Mul,
            ..
        } => &mut counts.i64_multiplies,
        X64InstructionKind::Sse2F64 {
            opcode: X64Sse2F64Opcode::AddSd,
            ..
        } => &mut counts.f64_adds,
        X64InstructionKind::Sse2F64 {
            opcode: X64Sse2F64Opcode::SubSd,
            ..
        } => &mut counts.f64_subtracts,
        X64InstructionKind::I64Setcc {
            condition: X64SetCondition::SignedLessThan,
            ..
        } => &mut counts.i64_less_than,
        X64InstructionKind::I64Setcc {
            condition: X64SetCondition::SignedGreaterOrEqual,
            ..
        } => &mut counts.i64_greater_or_equal,
        X64InstructionKind::ArrayLenF64 { .. } => &mut counts.array_lengths,
        X64InstructionKind::ArrayGetF64Checked { .. } => &mut counts.checked_array_gets,
    };
    checked_add(field, count, "instruction class count")
}

fn block_for_label(
    program: &X64TargetProgram,
    label: X64LabelId,
) -> Result<&X64Block, X64TargetProfileError> {
    let owner = program
        .labels
        .binary_search_by_key(&label, |candidate| candidate.id)
        .ok()
        .map(|index| program.labels[index].owner)
        .ok_or_else(|| {
            X64TargetProfileError::InternalInvariant(format!("missing target label {}", label.0))
        })?;
    let X64LabelOwner::Block { function, block } = owner else {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "profile event label {} does not own a block",
            label.0
        )));
    };
    let function = program
        .functions
        .binary_search_by_key(&function, |candidate| candidate.id)
        .ok()
        .map(|index| &program.functions[index])
        .ok_or_else(|| {
            X64TargetProfileError::InternalInvariant(format!(
                "profile label {} names a missing function",
                label.0
            ))
        })?;
    function
        .blocks
        .binary_search_by_key(&block, |candidate| candidate.id)
        .ok()
        .map(|index| &function.blocks[index])
        .ok_or_else(|| {
            X64TargetProfileError::InternalInvariant(format!(
                "profile label {} names a missing block",
                label.0
            ))
        })
}

fn canonical_shared_join_route(
    program: &X64TargetProgram,
    authority_trigger: X64LabelId,
    target: X64LabelId,
) -> Result<Vec<RawSharedJoinLineageEvent>, X64TargetProfileError> {
    let mut route = Vec::new();
    let mut seen = BTreeSet::new();
    let mut source = authority_trigger;

    loop {
        if !seen.insert(source) || seen.len() > program.labels.len() {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "shared-join authority {} has a cyclic exact route to target {}",
                authority_trigger.0, target.0
            )));
        }
        let source_block = block_for_label(program, source)?;
        let X64Terminator::TailJumpRel32 { target_label, .. } = source_block.terminator else {
            return Err(X64TargetProfileError::InternalInvariant(format!(
                "shared-join authority {} crosses non-tail source {}",
                authority_trigger.0, source.0
            )));
        };
        route.push(RawSharedJoinLineageEvent::Tail {
            source,
            target: target_label,
        });
        source = target_label;

        let block = block_for_label(program, source)?;
        if source == target {
            if block.instructions.len() != 1 {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "shared-join target {} has a non-canonical instruction shape",
                    target.0
                )));
            }
            route.push(RawSharedJoinLineageEvent::Instruction {
                label: target,
                index: 0,
            });
            let X64Terminator::TailJumpRel32 { target_label, .. } = block.terminator else {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "shared-join target {} has a non-tail exact route",
                    target.0
                )));
            };
            route.push(RawSharedJoinLineageEvent::Tail {
                source: target,
                target: target_label,
            });
            return Ok(route);
        }

        match block.instructions.len() {
            0 => {}
            1 => route.push(RawSharedJoinLineageEvent::Instruction {
                label: source,
                index: 0,
            }),
            _ => {
                return Err(X64TargetProfileError::InternalInvariant(format!(
                    "shared-join authority {} crosses multi-instruction target {}",
                    authority_trigger.0, source.0
                )));
            }
        }
    }
}

fn validate_control_flow(
    program: &X64TargetProgram,
    evaluation_steps: u64,
    observer: &ProfileObserver,
    instruction_counts: X64TargetProfileInstructionCounts,
    control_counts: X64TargetProfileControlCounts,
) -> Result<(), X64TargetProfileError> {
    if control_counts.entries != 1 {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "complete evaluation observed {} entries",
            control_counts.entries
        )));
    }
    let selected_branches = control_counts
        .branch_then
        .checked_add(control_counts.branch_else)
        .ok_or(X64TargetProfileError::CounterOverflow {
            field: "selected branch total",
        })?;
    if selected_branches != control_counts.branches {
        return Err(X64TargetProfileError::InternalInvariant(
            "then/else counts do not partition branches".to_owned(),
        ));
    }
    if control_counts
        .returns
        .checked_add(control_counts.bounds_exits)
        .ok_or(X64TargetProfileError::CounterOverflow {
            field: "outcome count",
        })?
        != 1
    {
        return Err(X64TargetProfileError::InternalInvariant(
            "complete evaluation must have exactly one return or Bounds exit".to_owned(),
        ));
    }
    let block_entry_total = observer
        .block_counts
        .iter()
        .try_fold(0_u64, |total, count| {
            total
                .checked_add(*count)
                .ok_or(X64TargetProfileError::CounterOverflow {
                    field: "block entry total",
                })
        })?;
    let expected_block_entries = 1_u64
        .checked_add(control_counts.branches)
        .and_then(|count| count.checked_add(control_counts.tail_transfers))
        .ok_or(X64TargetProfileError::CounterOverflow {
            field: "expected block entries",
        })?;
    if block_entry_total != expected_block_entries {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "observed {block_entry_total} block entries; expected {expected_block_entries}"
        )));
    }

    let entry = program
        .functions
        .binary_search_by_key(&program.entry, |function| function.id)
        .ok()
        .map(|index| &program.functions[index])
        .ok_or_else(|| {
            X64TargetProfileError::InternalInvariant("entry function disappeared".to_owned())
        })?;
    let entry_transfer = u64::try_from(entry.parameters.len())
        .ok()
        .and_then(|count| count.checked_mul(2))
        .and_then(|count| count.checked_add(1))
        .ok_or(X64TargetProfileError::CounterOverflow {
            field: "entry transfer work",
        })?;
    let instruction_total = instruction_counts.total()?;
    let expected_steps = entry_transfer
        .checked_add(instruction_total)
        .and_then(|steps| steps.checked_add(control_counts.returns))
        .and_then(|steps| steps.checked_add(control_counts.branches))
        .and_then(|steps| steps.checked_add(observer.tail_transfer_work))
        .ok_or(X64TargetProfileError::CounterOverflow {
            field: "profile step equation",
        })?;
    if expected_steps != evaluation_steps {
        return Err(X64TargetProfileError::InternalInvariant(format!(
            "profile step equation yields {expected_steps}; evaluator reports {evaluation_steps}"
        )));
    }
    Ok(())
}

fn checked_increment<Key: Ord>(
    counts: &mut BTreeMap<Key, u64>,
    key: Key,
    increment: u64,
) -> Result<(), X64TargetProfileError> {
    let entry = counts.entry(key).or_default();
    checked_add(entry, increment, "raw event aggregation")
}

fn checked_add(
    target: &mut u64,
    increment: u64,
    field: &'static str,
) -> Result<(), X64TargetProfileError> {
    *target = target
        .checked_add(increment)
        .ok_or(X64TargetProfileError::CounterOverflow { field })?;
    Ok(())
}

fn checked_sum(
    values: impl IntoIterator<Item = u64>,
    field: &'static str,
) -> Result<u64, X64TargetProfileError> {
    values.into_iter().try_fold(0_u64, |total, value| {
        total
            .checked_add(value)
            .ok_or(X64TargetProfileError::CounterOverflow { field })
    })
}

#[cfg(test)]
mod tests {
    use super::super::evaluate_x64_target_plan;
    use super::*;
    use crate::core::corevm0_gate_a::{
        CoreVmGateAWorkload, COREVM0_GATE_A_CALL_DEPTH_LIMIT, COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
    };
    use crate::core::x64_native_lighthouse::{
        x64_native_lighthouse_case, X64NativeLighthousePackage,
    };

    fn observe_shared_join_route(
        observer: &mut SharedJoinBranchObserver,
        step: usize,
        ingress: usize,
    ) {
        let route = observer.descriptors[step].routes[ingress].clone();
        for event in route {
            match event {
                RawSharedJoinLineageEvent::Instruction { label, index } => {
                    observer.observe_instruction(label, index).unwrap();
                }
                RawSharedJoinLineageEvent::Tail { source, target } => {
                    observer.observe_tail(source, target).unwrap();
                }
            }
        }
    }

    fn first_shared_join_tail(
        observer: &SharedJoinBranchObserver,
        step: usize,
        ingress: usize,
    ) -> (X64LabelId, X64LabelId) {
        match observer.descriptors[step].routes[ingress].first() {
            Some(RawSharedJoinLineageEvent::Tail { source, target }) => (*source, *target),
            _ => panic!("shared-join route must start with its authority tail"),
        }
    }

    fn rejected_prospective_mutation(
        mutate: impl FnOnce(&mut super::raw::RawEncoding),
    ) -> X64TargetProfileError {
        let case = x64_native_lighthouse_case(0).expect("canonical case");
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("branch package");
        let program = &package.target().program;
        let arguments = package.case_arguments(&case).expect("typed arguments");
        let mut replayed = super::raw::encode(program).expect("raw replay");
        let observer = ProfileObserver::new(program, &replayed.realization.shared_join_composition)
            .expect("profile observer");
        let budget = EvaluationBudget::new(
            COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
            COREVM0_GATE_A_CALL_DEPTH_LIMIT,
        );
        let (evaluation, observer) = evaluate_program_with_observer(
            program,
            arguments,
            budget,
            X64_TARGET_MAX_PROFILE_EVAL_WORK,
            observer,
        )
        .expect("profile evaluation");
        mutate(&mut replayed);
        build_profile(
            program,
            package.target().semantic_hash,
            evaluation.steps,
            observer,
            replayed.realization,
            replayed.prospective_shadow,
        )
        .expect_err("mutated prospective replay must fail closed")
    }

    #[test]
    fn profiled_evaluation_preserves_semantics_and_has_complete_byte_coverage() {
        let case = x64_native_lighthouse_case(0).expect("canonical case");
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("branch package");
        let arguments = package.case_arguments(&case).expect("typed arguments");
        let budget = EvaluationBudget::new(
            COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
            COREVM0_GATE_A_CALL_DEPTH_LIMIT,
        );
        let expected = evaluate_x64_target_plan(package.target(), arguments.clone(), budget)
            .expect("ordinary plan evaluation");
        let profiled = profile_x64_target_plan(package.target(), arguments, budget)
            .expect("profiled plan evaluation");

        assert_eq!(profiled.evaluation, expected);
        assert_eq!(profiled.profile.control_counts.entries, 1);
        assert!(profiled.profile.optimized_realization);
        assert_eq!(
            profiled.profile.static_code_bytes as usize,
            package.target().program.code.len()
        );
        assert_eq!(
            profiled
                .profile
                .sites
                .iter()
                .map(|site| u64::from(site.static_bytes))
                .sum::<u64>(),
            profiled.profile.static_code_bytes
        );
        for pair in profiled.profile.sites.windows(2) {
            assert_eq!(pair[0].end, pair[1].start);
        }
        assert_eq!(
            profiled.profile.sites.first().map(|site| site.start),
            Some(0)
        );
        assert_eq!(
            profiled.profile.sites.last().map(|site| site.end as usize),
            Some(package.target().program.code.len())
        );
        assert_eq!(
            profiled
                .profile
                .shared_join_opportunities
                .iter()
                .map(|opportunity| opportunity.target.0)
                .collect::<Vec<_>>(),
            vec![48, 49, 92, 93, 121]
        );
        for opportunity in &profiled.profile.shared_join_opportunities {
            assert!(opportunity.ingresses.len() >= 2);
            assert_eq!(
                opportunity.executions,
                opportunity
                    .ingresses
                    .iter()
                    .map(|ingress| ingress.executions)
                    .sum::<u64>()
            );
            assert_eq!(
                opportunity.weighted_ingress_frame_accesses,
                opportunity
                    .ingresses
                    .iter()
                    .map(|ingress| ingress.weighted_frame_accesses)
                    .sum::<u128>()
            );
        }
        let composition = &profiled.profile.shared_join_composition;
        assert!(composition.complete);
        assert_eq!(composition.body_replicas, 11);
        assert_eq!(
            composition
                .steps
                .iter()
                .map(|step| step.target.0)
                .collect::<Vec<_>>(),
            vec![49, 92, 93, 121, 48]
        );
        assert_eq!(
            composition
                .steps
                .last()
                .map(|step| step.ancestors.as_slice()),
            Some([X64LabelId(121)].as_slice())
        );
        assert_eq!(
            composition.body_executions,
            composition
                .steps
                .iter()
                .map(|step| step.executions)
                .sum::<u64>()
        );
        assert_eq!(
            composition.weighted_ingress_frame_accesses,
            composition
                .steps
                .iter()
                .map(|step| step.weighted_ingress_frame_accesses)
                .sum::<u128>()
        );
        for step in &composition.steps {
            let branch_outcomes = step
                .ingresses
                .iter()
                .map(|ingress| match ingress.branch_arm_counts {
                    Some(counts) => counts
                        .then_executions
                        .checked_add(counts.else_executions)
                        .expect("bounded branch row"),
                    None => 0,
                })
                .sum::<u64>();
            match step.kind {
                X64TargetSharedJoinKind::RegisterInstruction => {
                    assert!(step
                        .ingresses
                        .iter()
                        .all(|ingress| ingress.branch_arm_counts.is_none()));
                }
                X64TargetSharedJoinKind::FusedCompare => {
                    assert!(step
                        .ingresses
                        .iter()
                        .all(|ingress| ingress.branch_arm_counts.is_some()));
                    assert_eq!(branch_outcomes, step.executions);
                }
            }
        }
        let prospective = &profiled.profile.prospective_shared_join_realization;
        assert!(prospective.complete);
        assert_eq!(
            (
                prospective.baseline_code_bytes,
                prospective.candidate_code_bytes,
                prospective.code_bytes_added,
                prospective.code_bytes_removed,
                prospective.baseline_atom_count,
                prospective.candidate_atom_count,
                prospective.atom_count_added,
                prospective.atom_count_removed,
            ),
            (3_097, 3_214, 117, 0, 179, 199, 20, 0,)
        );
        assert_eq!(
            (
                prospective.label_count,
                prospective.baseline_fixup_count,
                prospective.candidate_fixup_count,
                prospective.fixup_count_added,
                prospective.fixup_count_removed,
                prospective.body_replicas,
                prospective.shared_join_authority_atoms,
            ),
            (142, 51, 51, 0, 0, 11, 31,)
        );
        assert_eq!(
            prospective.candidate_code_hash.to_hex(),
            "0e392caf51dbc65f9e36e08c678118e78b8f6aed90bf1df0edbf4b5c6a5f5173"
        );
        let semantic = &prospective.machine_semantic_proof;
        assert!(semantic.complete);
        assert_eq!(
            (
                semantic.register_rows,
                semantic.decoded_bytes,
                semantic.decoded_instructions,
                semantic.symbolic_nodes,
                semantic.reference_route_events,
            ),
            (2, 310, 42, 15, 25)
        );
        assert_eq!(
            prospective
                .atoms
                .iter()
                .map(|atom| u64::from(atom.static_bytes))
                .sum::<u64>(),
            prospective.candidate_code_bytes
        );
        assert_eq!(
            prospective
                .atoms
                .iter()
                .map(|atom| atom.weighted_bytes)
                .sum::<u128>(),
            prospective.candidate_weighted_template_bytes
        );
        assert_eq!(
            x64_target_prospective_shared_join_realization_hash(prospective).unwrap(),
            prospective.realization_hash
        );
        assert_eq!(
            prospective.realization_hash.to_hex(),
            "eb718521922d5169bd41660e2301573379397fcf34a6951556353ca4193353cd"
        );
        let target_49 = prospective
            .atoms
            .iter()
            .filter_map(|atom| {
                let X64TargetProspectiveExecutionAuthority::SharedJoin {
                    target,
                    root,
                    authority_trigger,
                    partition,
                } = atom.execution_authority
                else {
                    return None;
                };
                (target == X64LabelId(49)).then_some((
                    root,
                    authority_trigger,
                    partition,
                    atom.class,
                    atom.executions,
                    atom.weighted_bytes,
                ))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            target_49,
            vec![
                (
                    X64LabelId(30),
                    X64LabelId(39),
                    X64TargetProspectiveSharedJoinPartition::All,
                    X64TargetProfileTemplateClass::FusedCompareInstruction,
                    0,
                    0,
                ),
                (
                    X64LabelId(30),
                    X64LabelId(39),
                    X64TargetProspectiveSharedJoinPartition::All,
                    X64TargetProfileTemplateClass::BranchCondition,
                    0,
                    0,
                ),
                (
                    X64LabelId(30),
                    X64LabelId(39),
                    X64TargetProspectiveSharedJoinPartition::Else,
                    X64TargetProfileTemplateClass::BranchElseJump,
                    0,
                    0,
                ),
                (
                    X64LabelId(31),
                    X64LabelId(40),
                    X64TargetProspectiveSharedJoinPartition::All,
                    X64TargetProfileTemplateClass::FusedCompareInstruction,
                    0,
                    0,
                ),
                (
                    X64LabelId(31),
                    X64LabelId(40),
                    X64TargetProspectiveSharedJoinPartition::All,
                    X64TargetProfileTemplateClass::BranchCondition,
                    0,
                    0,
                ),
                (
                    X64LabelId(31),
                    X64LabelId(40),
                    X64TargetProspectiveSharedJoinPartition::Else,
                    X64TargetProfileTemplateClass::BranchElseJump,
                    0,
                    0,
                ),
            ]
        );
    }

    #[test]
    fn prospective_replay_rejects_resealed_payload_and_authority_mutations() {
        let retained_error = rejected_prospective_mutation(|replayed| {
            let shadow = replayed
                .prospective_shadow
                .as_mut()
                .expect("prospective shadow");
            let atom = shadow
                .atoms
                .iter()
                .find(|atom| atom.event == RawExecutionEvent::Entry)
                .copied()
                .expect("retained entry atom");
            shadow.code[atom.start as usize] ^= 1;
            replayed
                .realization
                .prospective_shared_join_realization
                .candidate_code_hash =
                prospective_shared_join_code_hash(&shadow.code).expect("resealed candidate code");
        });
        assert!(retained_error
            .to_string()
            .contains("retained ordinary atom normalized payload"));

        let fused_error = rejected_prospective_mutation(|replayed| {
            let atom_index = replayed
                .realization
                .prospective_shared_join_realization
                .atoms
                .iter()
                .position(|atom| {
                    atom.class == RawTemplateClass::FusedCompareInstruction
                        && matches!(
                            atom.execution_authority,
                            RawProspectiveExecutionAuthority::SharedJoin { .. }
                        )
                })
                .expect("shared fused clone receipt");
            let shadow = replayed
                .prospective_shadow
                .as_mut()
                .expect("prospective shadow");
            let atom = shadow.atoms[atom_index];
            shadow.code[atom.start as usize] ^= 1;
            replayed
                .realization
                .prospective_shared_join_realization
                .candidate_code_hash =
                prospective_shared_join_code_hash(&shadow.code).expect("resealed candidate code");
        });
        assert!(
            fused_error
                .to_string()
                .contains("fused clone normalized payload"),
            "unexpected fused mutation rejection: {fused_error}"
        );

        let register_opcode_error = rejected_prospective_mutation(|replayed| {
            let atom_index = replayed
                .realization
                .prospective_shared_join_realization
                .atoms
                .iter()
                .position(|atom| {
                    atom.class == RawTemplateClass::RegisterInstruction
                        && atom.semantic_event
                            == RawExecutionEvent::Instruction {
                                label: X64LabelId(121),
                                index: 0,
                            }
                        && matches!(
                            atom.execution_authority,
                            RawProspectiveExecutionAuthority::SharedJoin {
                                target: X64LabelId(121),
                                root: X64LabelId(106),
                                ..
                            }
                        )
                })
                .expect("shared register clone receipt");
            let shadow = replayed
                .prospective_shadow
                .as_mut()
                .expect("prospective shadow");
            let atom = shadow.atoms[atom_index];
            let bytes = &mut shadow.code[atom.start as usize..atom.end as usize];
            let opcode = bytes
                .windows(3)
                .position(|window| window == [0x48, 0x01, 0xc8])
                .expect("canonical add instruction");
            bytes[opcode + 1] = 0x29;
            replayed
                .realization
                .prospective_shared_join_realization
                .candidate_code_hash =
                prospective_shared_join_code_hash(&shadow.code).expect("resealed candidate code");
        });
        assert!(
            register_opcode_error.to_string().contains(
                "prospective register machine semantics failed: register semantic mismatch"
            ),
            "unexpected register opcode rejection: {register_opcode_error}"
        );

        let register_immediate_error = rejected_prospective_mutation(|replayed| {
            let atom_index = replayed
                .realization
                .prospective_shared_join_realization
                .atoms
                .iter()
                .position(|atom| {
                    atom.class == RawTemplateClass::RegisterInstruction
                        && atom.semantic_event
                            == RawExecutionEvent::Instruction {
                                label: X64LabelId(121),
                                index: 0,
                            }
                        && matches!(
                            atom.execution_authority,
                            RawProspectiveExecutionAuthority::SharedJoin {
                                target: X64LabelId(121),
                                root: X64LabelId(106),
                                ..
                            }
                        )
                })
                .expect("shared register clone receipt");
            let shadow = replayed
                .prospective_shadow
                .as_mut()
                .expect("prospective shadow");
            let atom = shadow.atoms[atom_index];
            let bytes = &mut shadow.code[atom.start as usize..atom.end as usize];
            let immediate = bytes
                .windows(10)
                .position(|window| window == [0x48, 0xb9, 1, 0, 0, 0, 0, 0, 0, 0])
                .expect("canonical movabs immediate");
            bytes[immediate + 2] = 2;
            replayed
                .realization
                .prospective_shared_join_realization
                .candidate_code_hash =
                prospective_shared_join_code_hash(&shadow.code).expect("resealed candidate code");
        });
        assert!(
            register_immediate_error.to_string().contains(
                "prospective register machine semantics failed: register semantic mismatch"
            ),
            "unexpected register immediate rejection: {register_immediate_error}"
        );

        let register_modrm_error = rejected_prospective_mutation(|replayed| {
            let atom_index = replayed
                .realization
                .prospective_shared_join_realization
                .atoms
                .iter()
                .position(|atom| {
                    atom.class == RawTemplateClass::RegisterInstruction
                        && atom.semantic_event
                            == RawExecutionEvent::Instruction {
                                label: X64LabelId(121),
                                index: 0,
                            }
                        && matches!(
                            atom.execution_authority,
                            RawProspectiveExecutionAuthority::SharedJoin {
                                target: X64LabelId(121),
                                root: X64LabelId(106),
                                ..
                            }
                        )
                })
                .expect("shared register clone receipt");
            let shadow = replayed
                .prospective_shadow
                .as_mut()
                .expect("prospective shadow");
            let atom = shadow.atoms[atom_index];
            let bytes = &mut shadow.code[atom.start as usize..atom.end as usize];
            let transfer = bytes
                .windows(3)
                .position(|window| window == [0x49, 0x89, 0xc0])
                .expect("canonical result register transfer");
            bytes[transfer + 2] = 0xc1;
            replayed
                .realization
                .prospective_shared_join_realization
                .candidate_code_hash =
                prospective_shared_join_code_hash(&shadow.code).expect("resealed candidate code");
        });
        assert!(
            register_modrm_error
                .to_string()
                .contains("prospective register machine semantics failed"),
            "unexpected register ModRM rejection: {register_modrm_error}"
        );

        let register_decode_error = rejected_prospective_mutation(|replayed| {
            let atom_index = replayed
                .realization
                .prospective_shared_join_realization
                .atoms
                .iter()
                .position(|atom| {
                    atom.class == RawTemplateClass::RegisterInstruction
                        && atom.semantic_event
                            == RawExecutionEvent::Instruction {
                                label: X64LabelId(121),
                                index: 0,
                            }
                        && matches!(
                            atom.execution_authority,
                            RawProspectiveExecutionAuthority::SharedJoin {
                                target: X64LabelId(121),
                                root: X64LabelId(106),
                                ..
                            }
                        )
                })
                .expect("shared register clone receipt");
            let shadow = replayed
                .prospective_shadow
                .as_mut()
                .expect("prospective shadow");
            let atom = shadow.atoms[atom_index];
            shadow.code[atom.start as usize] = 0x90;
            replayed
                .realization
                .prospective_shared_join_realization
                .candidate_code_hash =
                prospective_shared_join_code_hash(&shadow.code).expect("resealed candidate code");
        });
        assert!(
            register_decode_error
                .to_string()
                .contains("prospective register machine semantics failed"),
            "unexpected register decode rejection: {register_decode_error}"
        );

        let register_tail_error = rejected_prospective_mutation(|replayed| {
            let atom_index = replayed
                .realization
                .prospective_shared_join_realization
                .atoms
                .iter()
                .position(|atom| {
                    atom.class == RawTemplateClass::TailTransfer
                        && atom.semantic_event
                            == RawExecutionEvent::Tail {
                                label: X64LabelId(121),
                            }
                        && matches!(
                            atom.execution_authority,
                            RawProspectiveExecutionAuthority::SharedJoin {
                                target: X64LabelId(121),
                                root: X64LabelId(106),
                                ..
                            }
                        )
                })
                .expect("shared register tail receipt");
            let shadow = replayed
                .prospective_shadow
                .as_mut()
                .expect("prospective shadow");
            let atom = shadow.atoms[atom_index];
            let bytes = &mut shadow.code[atom.start as usize..atom.end as usize];
            let store = bytes
                .windows(8)
                .position(|window| window == [0x4c, 0x89, 0x84, 0x24, 0x38, 0, 0, 0])
                .expect("canonical first tail store");
            bytes[store + 4] = 0x40;
            replayed
                .realization
                .prospective_shared_join_realization
                .candidate_code_hash =
                prospective_shared_join_code_hash(&shadow.code).expect("resealed candidate code");
        });
        assert!(
            register_tail_error.to_string().contains(
                "prospective register machine semantics failed: register semantic mismatch"
            ),
            "unexpected register tail rejection: {register_tail_error}"
        );

        for (mutation, expected_context) in [
            ("direction", "load/store direction"),
            ("order", "instruction order"),
        ] {
            let error = rejected_prospective_mutation(|replayed| {
                let atom_index = replayed
                    .realization
                    .prospective_shared_join_realization
                    .atoms
                    .iter()
                    .position(|atom| {
                        atom.class == RawTemplateClass::RegisterInstruction
                            && atom.semantic_event
                                == RawExecutionEvent::Instruction {
                                    label: X64LabelId(121),
                                    index: 0,
                                }
                            && matches!(
                                atom.execution_authority,
                                RawProspectiveExecutionAuthority::SharedJoin {
                                    target: X64LabelId(121),
                                    root: X64LabelId(106),
                                    ..
                                }
                            )
                    })
                    .expect("shared register tail receipt");
                let shadow = replayed
                    .prospective_shadow
                    .as_mut()
                    .expect("prospective shadow");
                let atom = shadow.atoms[atom_index];
                let bytes = &mut shadow.code[atom.start as usize..atom.end as usize];
                let load = bytes
                    .windows(8)
                    .position(|window| window == [0x48, 0x8b, 0x84, 0x24, 0x70, 0, 0, 0])
                    .expect("canonical selected load");
                match mutation {
                    "direction" => bytes[load + 1] = 0x89,
                    "order" => bytes[load..load + 21].rotate_left(8),
                    _ => unreachable!("closed mutation table"),
                }
                replayed
                    .realization
                    .prospective_shared_join_realization
                    .candidate_code_hash = prospective_shared_join_code_hash(&shadow.code)
                    .expect("resealed candidate code");
            });
            assert!(
                error
                    .to_string()
                    .contains("prospective register machine semantics failed"),
                "unexpected {expected_context} rejection: {error}"
            );
        }

        let authority_error = rejected_prospective_mutation(|replayed| {
            let atom = replayed
                .realization
                .prospective_shared_join_realization
                .atoms
                .iter_mut()
                .find(|atom| {
                    matches!(
                        atom.execution_authority,
                        RawProspectiveExecutionAuthority::SharedJoin {
                            target,
                            root,
                            ..
                        } if target == X64LabelId(49) && root == X64LabelId(30)
                    )
                })
                .expect("target49/root30 authority atom");
            let RawProspectiveExecutionAuthority::SharedJoin { root, .. } =
                &mut atom.execution_authority
            else {
                unreachable!("selected atom must have shared authority");
            };
            *root = X64LabelId(31);
        });
        assert!(
            authority_error.to_string().contains("receipt")
                || authority_error.to_string().contains("ordered composition")
        );

        let partition_error = rejected_prospective_mutation(|replayed| {
            let atom = replayed
                .realization
                .prospective_shared_join_realization
                .atoms
                .iter_mut()
                .find(|atom| {
                    atom.class == RawTemplateClass::BranchElseJump
                        && matches!(
                            atom.execution_authority,
                            RawProspectiveExecutionAuthority::SharedJoin {
                                partition: RawProspectiveSharedJoinPartition::Else,
                                ..
                            }
                        )
                })
                .expect("shared else-partition atom");
            let RawProspectiveExecutionAuthority::SharedJoin { partition, .. } =
                &mut atom.execution_authority
            else {
                unreachable!("selected atom must have shared authority");
            };
            *partition = RawProspectiveSharedJoinPartition::All;
        });
        assert!(partition_error.to_string().contains("receipt"));

        let span_error = rejected_prospective_mutation(|replayed| {
            let atom = replayed
                .realization
                .prospective_shared_join_realization
                .atoms
                .first_mut()
                .expect("prospective atom receipt");
            atom.start = atom.start.checked_add(1).expect("bounded atom offset");
        });
        assert!(span_error.to_string().contains("receipt"));

        let disposition_error = rejected_prospective_mutation(|replayed| {
            let label = replayed
                .realization
                .prospective_shared_join_realization
                .labels
                .iter_mut()
                .find(|label| {
                    label.disposition == RawProspectiveLabelDisposition::SharedJoinTombstone
                })
                .expect("shared-join tombstone receipt");
            label.disposition = RawProspectiveLabelDisposition::Live;
        });
        assert!(disposition_error.to_string().contains("disposition"));

        let total_error = rejected_prospective_mutation(|replayed| {
            let realization = &mut replayed.realization.prospective_shared_join_realization;
            realization.candidate_code_bytes = realization
                .candidate_code_bytes
                .checked_add(1)
                .expect("bounded candidate byte total");
        });
        assert!(total_error.to_string().contains("summary or cap"));

        let fixup_owner_error = rejected_prospective_mutation(|replayed| {
            let fixup = replayed
                .realization
                .prospective_shared_join_realization
                .fixups
                .first_mut()
                .expect("prospective fixup receipt");
            fixup.owning_atom = fixup
                .owning_atom
                .checked_add(1)
                .expect("bounded fixup owner");
        });
        assert!(fixup_owner_error.to_string().contains("fixup receipt"));

        let hash_error = rejected_prospective_mutation(|replayed| {
            replayed
                .realization
                .prospective_shared_join_realization
                .candidate_code_hash = SemanticHash::ZERO;
        });
        assert!(hash_error.to_string().contains("summary or cap"));
    }

    #[test]
    fn profiling_rejects_an_unverified_target_before_observation() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("branch package");
        let mut invalid = package.target().clone();
        invalid.semantic_hash = SemanticHash::ZERO;
        assert!(matches!(
            profile_x64_target_plan(
                &invalid,
                Vec::new(),
                EvaluationBudget::new(1, COREVM0_GATE_A_CALL_DEPTH_LIMIT),
            ),
            Err(X64TargetProfileError::InvalidArtifact(_))
        ));
    }

    #[test]
    fn composition_profile_rejects_partial_and_ambiguous_authority_evidence() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("branch package");
        let program = &package.target().program;
        let observer = ProfileObserver::new(program, &RawSharedJoinComposition::default()).unwrap();
        let opportunity = X64TargetSharedJoinOpportunity {
            target: X64LabelId(49),
            kind: X64TargetSharedJoinKind::FusedCompare,
            executions: 0,
            ingresses: Vec::new(),
            weighted_ingress_frame_accesses: 0,
        };
        let mut step = super::raw::encode(program)
            .unwrap()
            .realization
            .shared_join_composition
            .steps
            .into_iter()
            .find(|step| step.target == X64LabelId(49))
            .unwrap();
        let mut zero_count_route_tampered = step.clone();
        zero_count_route_tampered.ingresses[0].lineage.remove(1);
        assert!(matches!(
            ProfileObserver::new(
                program,
                &RawSharedJoinComposition {
                    complete: true,
                    steps: vec![zero_count_route_tampered],
                    body_replicas: 2,
                },
            ),
            Err(X64TargetProfileError::InternalInvariant(message))
                if message.contains("non-canonical exact route")
        ));

        let mut swapped_routes = step.clone();
        let (left, right) = swapped_routes.ingresses.split_at_mut(1);
        std::mem::swap(&mut left[0].lineage, &mut right[0].lineage);
        assert!(matches!(
            ProfileObserver::new(
                program,
                &RawSharedJoinComposition {
                    complete: true,
                    steps: vec![swapped_routes],
                    body_replicas: 2,
                },
            ),
            Err(X64TargetProfileError::InternalInvariant(message))
                if message.contains("non-canonical exact route")
        ));

        // Target 49's frozen profile never selects its then arm. Structural
        // preflight must still reject a raw proof that aliases that unobserved
        // successor to the observed else arm; dynamic branch replay alone
        // cannot detect this mutation.
        let mut unobserved_arm_tampered = step.clone();
        let path = unobserved_arm_tampered.branch_path.as_mut().unwrap();
        path.then_label = path.else_label;
        assert!(matches!(
            ProfileObserver::new(
                program,
                &RawSharedJoinComposition {
                    complete: true,
                    steps: vec![unobserved_arm_tampered],
                    body_replicas: 2,
                },
            ),
            Err(X64TargetProfileError::InternalInvariant(message))
                if message.contains("non-canonical exact path")
        ));

        step.ingresses[1].authority_trigger = step.ingresses[0].authority_trigger;

        let partial = RawSharedJoinComposition {
            complete: false,
            steps: vec![step.clone()],
            body_replicas: 2,
        };
        assert!(matches!(
            build_shared_join_composition(
                program,
                &observer,
                &partial,
                std::slice::from_ref(&opportunity),
            ),
            Err(X64TargetProfileError::InternalInvariant(message))
                if message.contains("partial evidence")
        ));

        let ambiguous = RawSharedJoinComposition {
            complete: true,
            steps: vec![step],
            body_replicas: 2,
        };
        assert!(matches!(
            ProfileObserver::new(program, &ambiguous),
            Err(X64TargetProfileError::InternalInvariant(message))
                if message.contains("ambiguous across compare clones")
        ));
    }

    #[test]
    fn shared_join_branch_observer_tracks_exact_phases_and_refuses_ambiguity() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("branch package");
        let program = &package.target().program;
        let composition = super::raw::encode(program)
            .unwrap()
            .realization
            .shared_join_composition;

        let mut observer = SharedJoinBranchObserver::new(program, &composition).unwrap();
        let (step, ingress) = observer.activation_by_tail[X64LabelId(39).0 as usize].unwrap();
        let path = observer.descriptors[step].path;
        observe_shared_join_route(&mut observer, step, ingress);
        observer
            .observe_branch(path.branch_label, path.then_label, true)
            .unwrap();
        observe_shared_join_route(&mut observer, step, ingress);
        observer
            .observe_branch(path.branch_label, path.else_label, false)
            .unwrap();
        assert_eq!(observer.branch_then[step][ingress], 1);
        assert_eq!(observer.branch_else[step][ingress], 1);
        observer.observe_terminal().unwrap();

        let mut transitive = SharedJoinBranchObserver::new(program, &composition).unwrap();
        let (step, ingress) = transitive.activation_by_tail[X64LabelId(107).0 as usize].unwrap();
        let path = transitive.descriptors[step].path;
        assert_eq!(transitive.descriptors[step].target, X64LabelId(48));
        observe_shared_join_route(&mut transitive, step, ingress);
        transitive
            .observe_branch(path.branch_label, path.else_label, false)
            .unwrap();
        assert_eq!(transitive.branch_else[step][ingress], 1);

        let mut missing = SharedJoinBranchObserver::new(program, &composition).unwrap();
        assert!(matches!(
            missing.observe_branch(path.branch_label, path.then_label, true),
            Err(PlanExecutionError::InternalInvariant(message))
                if message.contains("without an authority")
        ));

        let mut repeated = SharedJoinBranchObserver::new(program, &composition).unwrap();
        let (step, ingress) = repeated.activation_by_tail[X64LabelId(107).0 as usize].unwrap();
        let first_tail = first_shared_join_tail(&repeated, step, ingress);
        repeated.observe_tail(first_tail.0, first_tail.1).unwrap();
        assert!(matches!(
            repeated.observe_tail(first_tail.0, first_tail.1),
            Err(PlanExecutionError::InternalInvariant(message))
                if message.contains("reactivated")
        ));

        let mut dangling = SharedJoinBranchObserver::new(program, &composition).unwrap();
        let (step, ingress) = dangling.activation_by_tail[X64LabelId(107).0 as usize].unwrap();
        let first_tail = first_shared_join_tail(&dangling, step, ingress);
        dangling.observe_tail(first_tail.0, first_tail.1).unwrap();
        assert!(matches!(
            dangling.observe_terminal(),
            Err(PlanExecutionError::InternalInvariant(message))
                if message.contains("terminal")
        ));

        let mut wrong_activation = SharedJoinBranchObserver::new(program, &composition).unwrap();
        assert!(matches!(
            wrong_activation.observe_tail(X64LabelId(38), X64LabelId(121)),
            Err(PlanExecutionError::InternalInvariant(message))
                if message.contains("non-canonical tail edge")
        ));

        let mut skipped = SharedJoinBranchObserver::new(program, &composition).unwrap();
        let (step, ingress) = skipped.activation_by_tail[X64LabelId(107).0 as usize].unwrap();
        let first_tail = first_shared_join_tail(&skipped, step, ingress);
        skipped.observe_tail(first_tail.0, first_tail.1).unwrap();
        assert!(matches!(
            skipped.observe_instruction(X64LabelId(121), 0),
            Err(PlanExecutionError::InternalInvariant(message))
                if message.contains("non-canonical instruction")
        ));

        let mut inserted = SharedJoinBranchObserver::new(program, &composition).unwrap();
        let (step, ingress) = inserted.activation_by_tail[X64LabelId(38).0 as usize].unwrap();
        let first_tail = first_shared_join_tail(&inserted, step, ingress);
        inserted.observe_tail(first_tail.0, first_tail.1).unwrap();
        assert!(matches!(
            inserted.observe_instruction(X64LabelId(121), 0),
            Err(PlanExecutionError::InternalInvariant(message))
                if message.contains("non-canonical instruction")
        ));

        let mut repeated_ancestor = SharedJoinBranchObserver::new(program, &composition).unwrap();
        let (step, ingress) =
            repeated_ancestor.activation_by_tail[X64LabelId(107).0 as usize].unwrap();
        let route = repeated_ancestor.descriptors[step].routes[ingress].clone();
        let ancestor_position = route
            .iter()
            .position(|event| {
                *event
                    == (RawSharedJoinLineageEvent::Instruction {
                        label: X64LabelId(121),
                        index: 0,
                    })
            })
            .unwrap();
        for event in route.into_iter().take(ancestor_position + 1) {
            match event {
                RawSharedJoinLineageEvent::Instruction { label, index } => {
                    repeated_ancestor.observe_instruction(label, index).unwrap();
                }
                RawSharedJoinLineageEvent::Tail { source, target } => {
                    repeated_ancestor.observe_tail(source, target).unwrap();
                }
            }
        }
        assert!(matches!(
            repeated_ancestor.observe_instruction(X64LabelId(121), 0),
            Err(PlanExecutionError::InternalInvariant(message))
                if message.contains("non-canonical instruction")
        ));
    }
}
