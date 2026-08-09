//! Proof-only persistent typed state planning across x86-64 tail edges.
//!
//! The plan contains no machine code and grants no execution or encoder
//! authority. Construction starts from an already valid policy-1.4 target;
//! verification revalidates that target, regenerates the complete plan, and
//! independently replays every parallel-copy schedule over symbolic values.

use super::encoding::sha256;
use super::machine_ir::MachineType;
use super::schema::SemanticHash;
use super::x64_target::{
    verify_x64_target_r1_s7a, X64BlockId, X64FunctionId, X64Home, X64Immediate, X64InstructionKind,
    X64LabelId, X64LabelOwner, X64Operand, X64TargetArtifact, X64TargetProgram,
    X64TargetVerificationErrors, X64Terminator,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

pub const X64_TAIL_STATE_PLAN_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_STATE_PLAN_POLICY_VERSION: (u16, u16, u16) = (1, 2, 0);
pub const X64_TAIL_STATE_MAX_EDGES: u32 = 4_096;
pub const X64_TAIL_STATE_MAX_WORDS_PER_EDGE: u32 = 32;
pub const X64_TAIL_STATE_MAX_SCHEDULE_STEPS: u32 = 16_384;
pub const X64_TAIL_STATE_MAX_REGIONS: u32 = 4_096;
pub const X64_TAIL_STATE_MAX_FRONTIERS: u32 = 4_096;
pub const X64_TAIL_STATE_MAX_REGION_EDGES: u32 = 64;
pub const X64_TAIL_STATE_MAX_BYTES_PER_OPERATION: u32 = 15;

const PLAN_DOMAIN: &[u8] = b"NAUX:x86-64:tail-state-plan:v1\0";
const MAX_PLAN_BYTES: usize = 16 * 1024 * 1024;
const TAIL_BRANCH_BYTE_UPPER_BOUND: u64 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum X64TailWordType {
    Bool,
    I64,
    F64,
    ArrayData,
    ArrayLength,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct X64TailWordLocation {
    pub offset: u32,
    pub word_type: X64TailWordType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailImmediateWord {
    Bool(bool),
    I64(i64),
    F64Bits(u64),
}

impl X64TailImmediateWord {
    const fn word_type(self) -> X64TailWordType {
        match self {
            Self::Bool(_) => X64TailWordType::Bool,
            Self::I64(_) => X64TailWordType::I64,
            Self::F64Bits(_) => X64TailWordType::F64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailWordSource {
    Location(X64TailWordLocation),
    Immediate(X64TailImmediateWord),
}

impl X64TailWordSource {
    const fn word_type(self) -> X64TailWordType {
        match self {
            Self::Location(location) => location.word_type,
            Self::Immediate(immediate) => immediate.word_type(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailWordAssignment {
    pub source: X64TailWordSource,
    pub destination: X64TailWordLocation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailScheduledSource {
    Location(X64TailWordLocation),
    Immediate(X64TailImmediateWord),
    Scratch { id: u32, word_type: X64TailWordType },
}

impl X64TailScheduledSource {
    const fn word_type(self) -> X64TailWordType {
        match self {
            Self::Location(location) => location.word_type,
            Self::Immediate(immediate) => immediate.word_type(),
            Self::Scratch { word_type, .. } => word_type,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailCopyStep {
    SaveScratch {
        source: X64TailWordLocation,
        scratch_id: u32,
    },
    Move {
        source: X64TailScheduledSource,
        destination: X64TailWordLocation,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum X64TailFrontierKind {
    EntryAbi,
    SharedJoin,
    Bounds,
    Return,
    Budget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct X64TailFrontier {
    pub kind: X64TailFrontierKind,
    pub function: X64FunctionId,
    pub block: X64BlockId,
    pub label: X64LabelId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailRefusalReason {
    EdgeWordBudget,
    RegionEdgeBudget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailEdgeDisposition {
    Persistent { region: u32 },
    Materialize { frontiers: Vec<X64TailFrontierKind> },
    Refused { reason: X64TailRefusalReason },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailEdgePlan {
    pub ordinal: u32,
    pub source_function: X64FunctionId,
    pub source_block: X64BlockId,
    pub source_label: X64LabelId,
    pub target_function: X64FunctionId,
    pub target_label: X64LabelId,
    pub assignments: Vec<X64TailWordAssignment>,
    pub schedule: Vec<X64TailCopyStep>,
    pub disposition: X64TailEdgeDisposition,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailStateRegion {
    pub id: u32,
    pub labels: Vec<X64LabelId>,
    pub edge_ordinals: Vec<u32>,
    pub word_capacity: u32,
    pub scratch_saves: u32,
    pub logical_moves: u32,
    pub machine_byte_upper_bound: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct X64TailStateTotals {
    pub tail_edges: u32,
    pub persistent_edges: u32,
    pub materialized_edges: u32,
    pub refused_edges: u32,
    pub argument_words: u64,
    pub identity_words: u64,
    pub logical_moves: u64,
    pub scratch_saves: u64,
    pub current_frame_traffic_upper_bound: u64,
    pub proposed_frame_traffic_upper_bound: u64,
    pub candidate_machine_byte_upper_bound: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailStatePlan {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    source_semantic_hash: SemanticHash,
    source_plan_hash: SemanticHash,
    source_code_hash: SemanticHash,
    edges: Vec<X64TailEdgePlan>,
    regions: Vec<X64TailStateRegion>,
    frontiers: Vec<X64TailFrontier>,
    totals: X64TailStateTotals,
    plan_hash: SemanticHash,
}

impl X64TailStatePlan {
    pub const fn source_semantic_hash(&self) -> SemanticHash {
        self.source_semantic_hash
    }

    pub fn edges(&self) -> &[X64TailEdgePlan] {
        &self.edges
    }

    pub fn regions(&self) -> &[X64TailStateRegion] {
        &self.regions
    }

    pub fn frontiers(&self) -> &[X64TailFrontier] {
        &self.frontiers
    }

    pub const fn totals(&self) -> X64TailStateTotals {
        self.totals
    }

    pub const fn plan_hash(&self) -> SemanticHash {
        self.plan_hash
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedX64TailStatePlan<'plan> {
    plan: &'plan X64TailStatePlan,
}

impl<'plan> VerifiedX64TailStatePlan<'plan> {
    pub const fn plan(self) -> &'plan X64TailStatePlan {
        self.plan
    }
}

#[derive(Debug)]
pub enum X64TailStatePlanError {
    InvalidTarget(X64TargetVerificationErrors),
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
    PlanHashMismatch,
    ReplayMismatch,
    ScheduleMismatch {
        edge: u32,
        reason: &'static str,
    },
}

impl fmt::Display for X64TailStatePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTarget(errors) => write!(formatter, "tail-state target failed: {errors}"),
            Self::InvalidField { field } => {
                write!(formatter, "tail-state plan has invalid {field}")
            }
            Self::MissingTarget { field } => {
                write!(formatter, "tail-state plan cannot resolve {field}")
            }
            Self::LimitExceeded {
                field,
                limit,
                actual,
            } => write!(
                formatter,
                "tail-state plan {field} uses {actual}; limit is {limit}"
            ),
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "tail-state plan overflowed {field}")
            }
            Self::EncodingLimit { actual } => write!(
                formatter,
                "tail-state plan encoding uses {actual} bytes; limit is {MAX_PLAN_BYTES}"
            ),
            Self::PlanHashMismatch => formatter.write_str("tail-state plan seal does not replay"),
            Self::ReplayMismatch => {
                formatter.write_str("tail-state plan differs from canonical source replay")
            }
            Self::ScheduleMismatch { edge, reason } => {
                write!(
                    formatter,
                    "tail-state edge {edge} schedule failed: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for X64TailStatePlanError {}

/// Build a sealed proof-only plan from an exact accepted R1-S7a artifact.
pub fn emit_x64_tail_state_plan(
    artifact: &X64TargetArtifact,
) -> Result<X64TailStatePlan, X64TailStatePlanError> {
    let verified =
        verify_x64_target_r1_s7a(artifact).map_err(X64TailStatePlanError::InvalidTarget)?;
    construct_plan(verified.program(), artifact.semantic_hash)
}

/// Revalidate the target, seal, complete canonical reconstruction, limits,
/// and symbolic parallel-copy semantics. No executable authority is returned.
pub fn verify_x64_tail_state_plan<'plan>(
    plan: &'plan X64TailStatePlan,
    artifact: &X64TargetArtifact,
) -> Result<VerifiedX64TailStatePlan<'plan>, X64TailStatePlanError> {
    let verified =
        verify_x64_target_r1_s7a(artifact).map_err(X64TailStatePlanError::InvalidTarget)?;
    validate_plan_shape(plan, verified.program(), artifact.semantic_hash)?;
    if x64_tail_state_plan_hash(plan)? != plan.plan_hash {
        return Err(X64TailStatePlanError::PlanHashMismatch);
    }
    for edge in &plan.edges {
        replay_schedule(edge)?;
    }
    let replayed = construct_plan(verified.program(), artifact.semantic_hash)?;
    if replayed != *plan {
        return Err(X64TailStatePlanError::ReplayMismatch);
    }
    Ok(VerifiedX64TailStatePlan { plan })
}

pub fn x64_tail_state_plan_hash(
    plan: &X64TailStatePlan,
) -> Result<SemanticHash, X64TailStatePlanError> {
    let bytes = x64_tail_state_plan_bytes_without_seal(plan)?;
    Ok(SemanticHash(sha256(&bytes)))
}

fn construct_plan(
    program: &X64TargetProgram,
    source_semantic_hash: SemanticHash,
) -> Result<X64TailStatePlan, X64TailStatePlanError> {
    let predecessors = predecessor_map(program)?;
    let mut frontiers = discover_frontiers(program, &predecessors)?;
    let mut edges = Vec::new();

    for function in &program.functions {
        for block in &function.blocks {
            let X64Terminator::TailJumpRel32 {
                function: target_function,
                target_label,
                arguments,
                ..
            } = &block.terminator
            else {
                continue;
            };
            ensure_limit(
                "tail edges",
                X64_TAIL_STATE_MAX_EDGES,
                edges.len().saturating_add(1),
            )?;
            let target = find_function(program, *target_function)?;
            let assignments = expand_assignments(arguments, &target.parameters)?;
            let schedule = schedule_parallel_copy(&assignments)?;
            let mut forced = frontiers
                .iter()
                .filter_map(|frontier| (frontier.label == *target_label).then_some(frontier.kind))
                .collect::<Vec<_>>();
            // A checked operation is also a barrier for state leaving the
            // block: no future region may silently assume that the Bounds
            // side exit preserved unmaterialized state.
            if block.instructions.iter().any(|instruction| {
                matches!(
                    instruction.kind,
                    X64InstructionKind::ArrayGetF64Checked { .. }
                )
            }) {
                forced.push(X64TailFrontierKind::Bounds);
            }
            forced.sort_unstable();
            forced.dedup();
            let disposition = if assignments.len() > X64_TAIL_STATE_MAX_WORDS_PER_EDGE as usize {
                X64TailEdgeDisposition::Refused {
                    reason: X64TailRefusalReason::EdgeWordBudget,
                }
            } else if forced.is_empty() {
                X64TailEdgeDisposition::Persistent { region: u32::MAX }
            } else {
                X64TailEdgeDisposition::Materialize { frontiers: forced }
            };
            edges.push(X64TailEdgePlan {
                ordinal: u32::try_from(edges.len()).map_err(|_| {
                    X64TailStatePlanError::ArithmeticOverflow {
                        field: "tail edge ordinal",
                    }
                })?,
                source_function: function.id,
                source_block: block.id,
                source_label: block.label,
                target_function: *target_function,
                target_label: *target_label,
                assignments,
                schedule,
                disposition,
            });
        }
    }

    let schedule_steps = edges.iter().try_fold(0_usize, |total, edge| {
        total
            .checked_add(edge.schedule.len())
            .ok_or(X64TailStatePlanError::ArithmeticOverflow {
                field: "schedule step total",
            })
    })?;
    ensure_limit(
        "schedule steps",
        X64_TAIL_STATE_MAX_SCHEDULE_STEPS,
        schedule_steps,
    )?;

    let mut regions = assign_regions(program, &mut edges, &mut frontiers)?;
    frontiers.sort_unstable();
    frontiers.dedup();
    ensure_limit("frontiers", X64_TAIL_STATE_MAX_FRONTIERS, frontiers.len())?;
    regions.sort_by_key(|region| region.id);
    let totals = compute_totals(program, &edges, &frontiers)?;
    let mut plan = X64TailStatePlan {
        schema_version: X64_TAIL_STATE_PLAN_SCHEMA_VERSION,
        policy_version: X64_TAIL_STATE_PLAN_POLICY_VERSION,
        source_semantic_hash,
        source_plan_hash: program.plan_hash,
        source_code_hash: program.code_hash,
        edges,
        regions,
        frontiers,
        totals,
        plan_hash: SemanticHash([0; 32]),
    };
    plan.plan_hash = x64_tail_state_plan_hash(&plan)?;
    Ok(plan)
}

fn predecessor_map(
    program: &X64TargetProgram,
) -> Result<BTreeMap<X64LabelId, BTreeSet<X64LabelId>>, X64TailStatePlanError> {
    let mut result = BTreeMap::new();
    for function in &program.functions {
        for block in &function.blocks {
            result.entry(block.label).or_insert_with(BTreeSet::new);
        }
    }
    for function in &program.functions {
        for block in &function.blocks {
            let targets = match &block.terminator {
                X64Terminator::Return { .. } => Vec::new(),
                X64Terminator::BranchRel32 {
                    then_label,
                    else_label,
                    ..
                } => vec![*then_label, *else_label],
                X64Terminator::TailJumpRel32 { target_label, .. } => vec![*target_label],
            };
            for target in targets {
                let Some(sources) = result.get_mut(&target) else {
                    return Err(X64TailStatePlanError::MissingTarget {
                        field: "control-flow target label",
                    });
                };
                sources.insert(block.label);
            }
        }
    }
    Ok(result)
}

fn discover_frontiers(
    program: &X64TargetProgram,
    predecessors: &BTreeMap<X64LabelId, BTreeSet<X64LabelId>>,
) -> Result<Vec<X64TailFrontier>, X64TailStatePlanError> {
    let mut frontiers = Vec::new();
    let entry_function = find_function(program, program.entry)?;
    let entry_block = find_block(entry_function, entry_function.entry_block)?;
    frontiers.push(frontier(
        X64TailFrontierKind::EntryAbi,
        entry_function.id,
        entry_block,
    ));
    for function in &program.functions {
        for block in &function.blocks {
            if predecessors
                .get(&block.label)
                .is_some_and(|sources| sources.len() > 1)
            {
                frontiers.push(frontier(
                    X64TailFrontierKind::SharedJoin,
                    function.id,
                    block,
                ));
            }
            if block.instructions.iter().any(|instruction| {
                matches!(
                    instruction.kind,
                    X64InstructionKind::ArrayGetF64Checked { .. }
                )
            }) {
                frontiers.push(frontier(X64TailFrontierKind::Bounds, function.id, block));
            }
            if matches!(block.terminator, X64Terminator::Return { .. }) {
                frontiers.push(frontier(X64TailFrontierKind::Return, function.id, block));
            }
        }
    }
    Ok(frontiers)
}

const fn frontier(
    kind: X64TailFrontierKind,
    function: X64FunctionId,
    block: &super::x64_target::X64Block,
) -> X64TailFrontier {
    X64TailFrontier {
        kind,
        function,
        block: block.id,
        label: block.label,
    }
}

fn expand_assignments(
    arguments: &[X64Operand],
    parameters: &[super::x64_target::X64Parameter],
) -> Result<Vec<X64TailWordAssignment>, X64TailStatePlanError> {
    if arguments.len() != parameters.len() {
        return Err(X64TailStatePlanError::InvalidField {
            field: "tail arity",
        });
    }
    let mut assignments = Vec::new();
    for (argument, parameter) in arguments.iter().zip(parameters) {
        let destination_words = home_words(parameter.home)?;
        let source_words = operand_words(argument)?;
        if destination_words.len() != source_words.len() {
            return Err(X64TailStatePlanError::InvalidField {
                field: "tail word width",
            });
        }
        for (source, destination) in source_words.into_iter().zip(destination_words) {
            if source.word_type() != destination.word_type {
                return Err(X64TailStatePlanError::InvalidField {
                    field: "tail word type",
                });
            }
            assignments.push(X64TailWordAssignment {
                source,
                destination,
            });
        }
    }
    assignments.sort_by_key(|assignment| assignment.destination);
    if assignments
        .windows(2)
        .any(|pair| pair[0].destination == pair[1].destination)
    {
        return Err(X64TailStatePlanError::InvalidField {
            field: "duplicate tail destination",
        });
    }
    Ok(assignments)
}

fn operand_words(operand: &X64Operand) -> Result<Vec<X64TailWordSource>, X64TailStatePlanError> {
    match operand {
        X64Operand::Home(home) => Ok(home_words(*home)?
            .into_iter()
            .map(X64TailWordSource::Location)
            .collect()),
        X64Operand::Immediate { ty, value } => match (ty, value) {
            (MachineType::Unit, X64Immediate::Unit) => Ok(Vec::new()),
            (MachineType::Bool, X64Immediate::Bool(value)) => {
                Ok(vec![X64TailWordSource::Immediate(
                    X64TailImmediateWord::Bool(*value),
                )])
            }
            (MachineType::I64, X64Immediate::I64(value)) => Ok(vec![X64TailWordSource::Immediate(
                X64TailImmediateWord::I64(*value),
            )]),
            (MachineType::F64, X64Immediate::F64Bits(bits)) => {
                Ok(vec![X64TailWordSource::Immediate(
                    X64TailImmediateWord::F64Bits(*bits),
                )])
            }
            _ => Err(X64TailStatePlanError::InvalidField {
                field: "tail immediate",
            }),
        },
    }
}

fn home_words(home: X64Home) -> Result<Vec<X64TailWordLocation>, X64TailStatePlanError> {
    let types: &[X64TailWordType] = match home.ty {
        MachineType::Unit => &[],
        MachineType::Bool => &[X64TailWordType::Bool],
        MachineType::I64 => &[X64TailWordType::I64],
        MachineType::F64 => &[X64TailWordType::F64],
        MachineType::F64Array => &[X64TailWordType::ArrayData, X64TailWordType::ArrayLength],
    };
    // Canonical home layout reserves one deterministic zeroed word for Unit,
    // while Unit contributes no semantic tail-state words.
    let expected_width = if home.ty == MachineType::Unit {
        8
    } else {
        u8::try_from(types.len() * 8).map_err(|_| X64TailStatePlanError::ArithmeticOverflow {
            field: "home word width",
        })?
    };
    if home.width != expected_width {
        return Err(X64TailStatePlanError::InvalidField {
            field: "canonical home width",
        });
    }
    types
        .iter()
        .enumerate()
        .map(|(word, word_type)| {
            let delta = u32::try_from(word)
                .ok()
                .and_then(|word| word.checked_mul(8))
                .ok_or(X64TailStatePlanError::ArithmeticOverflow {
                    field: "home word offset",
                })?;
            Ok(X64TailWordLocation {
                offset: home.offset.checked_add(delta).ok_or(
                    X64TailStatePlanError::ArithmeticOverflow {
                        field: "home word offset",
                    },
                )?,
                word_type: *word_type,
            })
        })
        .collect()
}

fn schedule_parallel_copy(
    assignments: &[X64TailWordAssignment],
) -> Result<Vec<X64TailCopyStep>, X64TailStatePlanError> {
    let mut pending = assignments
        .iter()
        .copied()
        .filter(|assignment| {
            !matches!(assignment.source, X64TailWordSource::Location(source) if source == assignment.destination)
        })
        .map(|assignment| MutableAssignment {
            source: match assignment.source {
                X64TailWordSource::Location(location) => {
                    X64TailScheduledSource::Location(location)
                }
                X64TailWordSource::Immediate(immediate) => {
                    X64TailScheduledSource::Immediate(immediate)
                }
            },
            destination: assignment.destination,
        })
        .collect::<Vec<_>>();
    pending.sort_by_key(|assignment| assignment.destination);
    let mut steps = Vec::new();
    let mut next_scratch = 0_u32;

    while !pending.is_empty() {
        let source_offsets = pending
            .iter()
            .filter_map(|assignment| match assignment.source {
                X64TailScheduledSource::Location(location) => Some(location.offset),
                X64TailScheduledSource::Immediate(_) | X64TailScheduledSource::Scratch { .. } => {
                    None
                }
            })
            .collect::<BTreeSet<_>>();
        if let Some(position) = pending
            .iter()
            .position(|assignment| !source_offsets.contains(&assignment.destination.offset))
        {
            let assignment = pending.remove(position);
            steps.push(X64TailCopyStep::Move {
                source: assignment.source,
                destination: assignment.destination,
            });
            continue;
        }

        let cycle_offset = pending[0].destination.offset;
        let cycle_source = pending
            .iter()
            .find_map(|assignment| match assignment.source {
                X64TailScheduledSource::Location(location) if location.offset == cycle_offset => {
                    Some(location)
                }
                X64TailScheduledSource::Location(_)
                | X64TailScheduledSource::Immediate(_)
                | X64TailScheduledSource::Scratch { .. } => None,
            })
            .ok_or(X64TailStatePlanError::InvalidField {
                field: "irreducible parallel-copy cycle",
            })?;
        let scratch_id = next_scratch;
        next_scratch =
            next_scratch
                .checked_add(1)
                .ok_or(X64TailStatePlanError::ArithmeticOverflow {
                    field: "tail scratch identity",
                })?;
        steps.push(X64TailCopyStep::SaveScratch {
            source: cycle_source,
            scratch_id,
        });
        let mut replaced = false;
        for assignment in &mut pending {
            if let X64TailScheduledSource::Location(location) = assignment.source {
                if location.offset == cycle_offset {
                    if location.word_type != cycle_source.word_type {
                        return Err(X64TailStatePlanError::InvalidField {
                            field: "cross-typed parallel-copy cycle",
                        });
                    }
                    assignment.source = X64TailScheduledSource::Scratch {
                        id: scratch_id,
                        word_type: cycle_source.word_type,
                    };
                    replaced = true;
                }
            }
        }
        if !replaced {
            return Err(X64TailStatePlanError::InvalidField {
                field: "irreducible parallel-copy cycle",
            });
        }
    }
    ensure_limit(
        "schedule steps",
        X64_TAIL_STATE_MAX_SCHEDULE_STEPS,
        steps.len(),
    )?;
    Ok(steps)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MutableAssignment {
    source: X64TailScheduledSource,
    destination: X64TailWordLocation,
}

fn assign_regions(
    program: &X64TargetProgram,
    edges: &mut [X64TailEdgePlan],
    frontiers: &mut Vec<X64TailFrontier>,
) -> Result<Vec<X64TailStateRegion>, X64TailStatePlanError> {
    let mut adjacency = BTreeMap::<X64LabelId, BTreeSet<X64LabelId>>::new();
    for edge in edges.iter() {
        if matches!(edge.disposition, X64TailEdgeDisposition::Persistent { .. }) {
            adjacency
                .entry(edge.source_label)
                .or_default()
                .insert(edge.target_label);
            adjacency
                .entry(edge.target_label)
                .or_default()
                .insert(edge.source_label);
        }
    }
    let mut visited = BTreeSet::new();
    let mut regions = Vec::new();
    for root in adjacency.keys().copied().collect::<Vec<_>>() {
        if !visited.insert(root) {
            continue;
        }
        let mut queue = VecDeque::from([root]);
        let mut labels = Vec::new();
        while let Some(label) = queue.pop_front() {
            labels.push(label);
            if let Some(neighbors) = adjacency.get(&label) {
                for neighbor in neighbors {
                    if visited.insert(*neighbor) {
                        queue.push_back(*neighbor);
                    }
                }
            }
        }
        labels.sort_unstable();
        let label_set = labels.iter().copied().collect::<BTreeSet<_>>();
        let edge_indexes = edges
            .iter()
            .enumerate()
            .filter_map(|(index, edge)| {
                (matches!(edge.disposition, X64TailEdgeDisposition::Persistent { .. })
                    && label_set.contains(&edge.source_label)
                    && label_set.contains(&edge.target_label))
                .then_some(index)
            })
            .collect::<Vec<_>>();
        if edge_indexes.len() > X64_TAIL_STATE_MAX_REGION_EDGES as usize {
            for index in edge_indexes {
                edges[index].disposition = X64TailEdgeDisposition::Refused {
                    reason: X64TailRefusalReason::RegionEdgeBudget,
                };
            }
            let frontier_label = labels[0];
            let (function, block) = label_owner(program, frontier_label)?;
            frontiers.push(X64TailFrontier {
                kind: X64TailFrontierKind::Budget,
                function,
                block,
                label: frontier_label,
            });
            continue;
        }
        ensure_limit(
            "persistent regions",
            X64_TAIL_STATE_MAX_REGIONS,
            regions.len().saturating_add(1),
        )?;
        let id = u32::try_from(regions.len()).map_err(|_| {
            X64TailStatePlanError::ArithmeticOverflow {
                field: "tail region identity",
            }
        })?;
        let mut word_capacity = 0_u32;
        let mut scratch_saves = 0_u32;
        let mut logical_moves = 0_u32;
        let mut edge_ordinals = Vec::new();
        for index in edge_indexes {
            edges[index].disposition = X64TailEdgeDisposition::Persistent { region: id };
            edge_ordinals.push(edges[index].ordinal);
            word_capacity =
                word_capacity.max(u32::try_from(edges[index].assignments.len()).map_err(|_| {
                    X64TailStatePlanError::ArithmeticOverflow {
                        field: "tail region word capacity",
                    }
                })?);
            for step in &edges[index].schedule {
                match step {
                    X64TailCopyStep::SaveScratch { .. } => {
                        scratch_saves =
                            checked_add_u32(scratch_saves, 1, "tail region scratch saves")?;
                    }
                    X64TailCopyStep::Move { .. } => {
                        logical_moves =
                            checked_add_u32(logical_moves, 1, "tail region logical moves")?;
                    }
                }
            }
        }
        edge_ordinals.sort_unstable();
        let operations = u64::from(scratch_saves)
            .checked_add(u64::from(logical_moves))
            .and_then(|value| value.checked_add(edge_ordinals.len() as u64))
            .ok_or(X64TailStatePlanError::ArithmeticOverflow {
                field: "tail region machine operations",
            })?;
        let machine_byte_upper_bound = operations
            .checked_mul(u64::from(X64_TAIL_STATE_MAX_BYTES_PER_OPERATION))
            .ok_or(X64TailStatePlanError::ArithmeticOverflow {
                field: "tail region byte upper bound",
            })?;
        regions.push(X64TailStateRegion {
            id,
            labels,
            edge_ordinals,
            word_capacity,
            scratch_saves,
            logical_moves,
            machine_byte_upper_bound,
        });
    }

    // A state region is also the ownership boundary for body realization.
    // Persistent-edge components alone are not complete: a checked,
    // materialized, entry, or return block can sit between two such
    // components and still own executable instructions. Give every remaining
    // block a canonical-frame singleton region so later binding and byte
    // composition cannot silently collapse an instruction-bearing label onto
    // its successor.
    let mut owned_labels = regions
        .iter()
        .flat_map(|region| region.labels.iter().copied())
        .collect::<BTreeSet<_>>();
    for function in &program.functions {
        for block in &function.blocks {
            if !owned_labels.insert(block.label) {
                continue;
            }
            ensure_limit(
                "state regions",
                X64_TAIL_STATE_MAX_REGIONS,
                regions.len().saturating_add(1),
            )?;
            let id = u32::try_from(regions.len()).map_err(|_| {
                X64TailStatePlanError::ArithmeticOverflow {
                    field: "state region identity",
                }
            })?;
            regions.push(X64TailStateRegion {
                id,
                labels: vec![block.label],
                edge_ordinals: Vec::new(),
                word_capacity: 0,
                scratch_saves: 0,
                logical_moves: 0,
                machine_byte_upper_bound: 0,
            });
        }
    }
    Ok(regions)
}

fn compute_totals(
    program: &X64TargetProgram,
    edges: &[X64TailEdgePlan],
    frontiers: &[X64TailFrontier],
) -> Result<X64TailStateTotals, X64TailStatePlanError> {
    let tail_edges =
        u32::try_from(edges.len()).map_err(|_| X64TailStatePlanError::ArithmeticOverflow {
            field: "tail edge total",
        })?;
    let mut totals = X64TailStateTotals {
        tail_edges,
        ..X64TailStateTotals::default()
    };
    for edge in edges {
        match edge.disposition {
            X64TailEdgeDisposition::Persistent { .. } => {
                totals.persistent_edges =
                    checked_add_u32(totals.persistent_edges, 1, "persistent edge total")?;
            }
            X64TailEdgeDisposition::Materialize { .. } => {
                totals.materialized_edges =
                    checked_add_u32(totals.materialized_edges, 1, "materialized edge total")?;
            }
            X64TailEdgeDisposition::Refused { .. } => {
                totals.refused_edges =
                    checked_add_u32(totals.refused_edges, 1, "refused edge total")?;
            }
        }
        let words = u64::try_from(edge.assignments.len()).map_err(|_| {
            X64TailStatePlanError::ArithmeticOverflow {
                field: "tail argument words",
            }
        })?;
        totals.argument_words = checked_add_u64(totals.argument_words, words, "argument words")?;
        let identities = edge
            .assignments
            .iter()
            .filter(|assignment| {
                matches!(assignment.source, X64TailWordSource::Location(source) if source == assignment.destination)
            })
            .count() as u64;
        totals.identity_words =
            checked_add_u64(totals.identity_words, identities, "identity words")?;
        for step in &edge.schedule {
            match step {
                X64TailCopyStep::SaveScratch { .. } => {
                    totals.scratch_saves =
                        checked_add_u64(totals.scratch_saves, 1, "scratch saves")?;
                }
                X64TailCopyStep::Move { .. } => {
                    totals.logical_moves =
                        checked_add_u64(totals.logical_moves, 1, "logical moves")?;
                }
            }
        }
        totals.current_frame_traffic_upper_bound = checked_add_u64(
            totals.current_frame_traffic_upper_bound,
            words
                .checked_mul(4)
                .ok_or(X64TailStatePlanError::ArithmeticOverflow {
                    field: "current frame traffic",
                })?,
            "current frame traffic",
        )?;
        if !matches!(edge.disposition, X64TailEdgeDisposition::Persistent { .. }) {
            totals.proposed_frame_traffic_upper_bound = checked_add_u64(
                totals.proposed_frame_traffic_upper_bound,
                words
                    .checked_mul(4)
                    .ok_or(X64TailStatePlanError::ArithmeticOverflow {
                        field: "proposed frontier traffic",
                    })?,
                "proposed frontier traffic",
            )?;
        }
    }

    let frame_words = u64::from(program.frame.max_home_bytes.div_ceil(8));
    let forced_flushes =
        u64::try_from(frontiers.len()).map_err(|_| X64TailStatePlanError::ArithmeticOverflow {
            field: "frontier flushes",
        })?;
    totals.proposed_frame_traffic_upper_bound = checked_add_u64(
        totals.proposed_frame_traffic_upper_bound,
        forced_flushes
            .checked_mul(frame_words)
            .and_then(|value| value.checked_mul(2))
            .ok_or(X64TailStatePlanError::ArithmeticOverflow {
                field: "frontier flush traffic",
            })?,
        "proposed frame traffic",
    )?;
    let logical_operations = totals
        .logical_moves
        .checked_add(totals.scratch_saves)
        .and_then(|value| value.checked_add(totals.proposed_frame_traffic_upper_bound))
        .ok_or(X64TailStatePlanError::ArithmeticOverflow {
            field: "candidate logical operations",
        })?;
    totals.candidate_machine_byte_upper_bound = logical_operations
        .checked_mul(u64::from(X64_TAIL_STATE_MAX_BYTES_PER_OPERATION))
        .and_then(|value| {
            value.checked_add(
                u64::from(totals.tail_edges).checked_mul(TAIL_BRANCH_BYTE_UPPER_BOUND)?,
            )
        })
        .ok_or(X64TailStatePlanError::ArithmeticOverflow {
            field: "candidate machine byte upper bound",
        })?;
    Ok(totals)
}

fn validate_plan_shape(
    plan: &X64TailStatePlan,
    program: &X64TargetProgram,
    semantic_hash: SemanticHash,
) -> Result<(), X64TailStatePlanError> {
    if plan.schema_version != X64_TAIL_STATE_PLAN_SCHEMA_VERSION {
        return Err(X64TailStatePlanError::InvalidField {
            field: "schema version",
        });
    }
    if plan.policy_version != X64_TAIL_STATE_PLAN_POLICY_VERSION {
        return Err(X64TailStatePlanError::InvalidField {
            field: "policy version",
        });
    }
    if plan.source_semantic_hash != semantic_hash
        || plan.source_plan_hash != program.plan_hash
        || plan.source_code_hash != program.code_hash
    {
        return Err(X64TailStatePlanError::InvalidField {
            field: "source identity",
        });
    }
    ensure_limit("tail edges", X64_TAIL_STATE_MAX_EDGES, plan.edges.len())?;
    ensure_limit(
        "persistent regions",
        X64_TAIL_STATE_MAX_REGIONS,
        plan.regions.len(),
    )?;
    ensure_limit(
        "frontiers",
        X64_TAIL_STATE_MAX_FRONTIERS,
        plan.frontiers.len(),
    )?;
    let schedule_steps = plan.edges.iter().try_fold(0_usize, |total, edge| {
        total
            .checked_add(edge.schedule.len())
            .ok_or(X64TailStatePlanError::ArithmeticOverflow {
                field: "schedule step total",
            })
    })?;
    ensure_limit(
        "schedule steps",
        X64_TAIL_STATE_MAX_SCHEDULE_STEPS,
        schedule_steps,
    )?;
    if plan.frontiers.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(X64TailStatePlanError::InvalidField {
            field: "frontier ordering",
        });
    }
    if plan
        .edges
        .iter()
        .enumerate()
        .any(|(index, edge)| edge.ordinal as usize != index)
    {
        return Err(X64TailStatePlanError::InvalidField {
            field: "edge ordering",
        });
    }
    if plan
        .regions
        .iter()
        .enumerate()
        .any(|(index, region)| region.id as usize != index)
    {
        return Err(X64TailStatePlanError::InvalidField {
            field: "region ordering",
        });
    }
    let block_labels = program
        .functions
        .iter()
        .flat_map(|function| function.blocks.iter().map(|block| block.label))
        .collect::<BTreeSet<_>>();
    let mut region_labels = BTreeSet::new();
    for region in &plan.regions {
        if region.labels.is_empty()
            || region.labels.windows(2).any(|pair| pair[0] >= pair[1])
            || region
                .labels
                .iter()
                .any(|label| !region_labels.insert(*label))
        {
            return Err(X64TailStatePlanError::InvalidField {
                field: "canonical unique region label ownership",
            });
        }
        if region.edge_ordinals.is_empty() && region.labels.len() != 1 {
            return Err(X64TailStatePlanError::InvalidField {
                field: "canonical-frame singleton region",
            });
        }
    }
    if region_labels != block_labels {
        return Err(X64TailStatePlanError::InvalidField {
            field: "complete block label region coverage",
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SymbolicWord {
    Original(X64TailWordLocation),
    Immediate(X64TailImmediateWord),
}

impl SymbolicWord {
    const fn word_type(self) -> X64TailWordType {
        match self {
            Self::Original(location) => location.word_type,
            Self::Immediate(immediate) => immediate.word_type(),
        }
    }
}

fn replay_schedule(edge: &X64TailEdgePlan) -> Result<(), X64TailStatePlanError> {
    if edge.assignments.len() > X64_TAIL_STATE_MAX_WORDS_PER_EDGE as usize
        && !matches!(
            edge.disposition,
            X64TailEdgeDisposition::Refused {
                reason: X64TailRefusalReason::EdgeWordBudget
            }
        )
    {
        return schedule_error(edge.ordinal, "over-budget edge is not refused");
    }
    let mut destination_offsets = BTreeSet::new();
    let mut memory = BTreeMap::<u32, SymbolicWord>::new();
    let mut expected = BTreeMap::new();
    let mut required_writes = BTreeSet::new();
    // Source snapshots must be installed before destination-only storage.
    // A typed home may reuse an existing byte offset at a different edge, but
    // the physical bytes still have one identity during this parallel copy.
    for assignment in &edge.assignments {
        if let X64TailWordSource::Location(location) = assignment.source {
            if let Some(existing) = memory.get(&location.offset) {
                if existing.word_type() != location.word_type {
                    return schedule_error(edge.ordinal, "cross-typed source storage alias");
                }
            } else {
                memory.insert(location.offset, SymbolicWord::Original(location));
            }
        }
    }
    for assignment in &edge.assignments {
        if assignment.source.word_type() != assignment.destination.word_type {
            return schedule_error(edge.ordinal, "assignment type mismatch");
        }
        if !destination_offsets.insert(assignment.destination.offset) {
            return schedule_error(edge.ordinal, "duplicate destination storage");
        }
        memory
            .entry(assignment.destination.offset)
            .or_insert(SymbolicWord::Original(assignment.destination));
        let token = match assignment.source {
            X64TailWordSource::Location(location) => memory.get(&location.offset).copied().ok_or(
                X64TailStatePlanError::ScheduleMismatch {
                    edge: edge.ordinal,
                    reason: "initial source storage is unavailable",
                },
            )?,
            X64TailWordSource::Immediate(immediate) => SymbolicWord::Immediate(immediate),
        };
        expected.insert(assignment.destination, token);
        if !matches!(assignment.source, X64TailWordSource::Location(source) if source == assignment.destination)
        {
            required_writes.insert(assignment.destination);
        }
    }
    let mut writes = BTreeMap::<X64TailWordLocation, u32>::new();
    let mut scratches = BTreeMap::<(u32, X64TailWordType), SymbolicWord>::new();
    for step in &edge.schedule {
        match *step {
            X64TailCopyStep::SaveScratch { source, scratch_id } => {
                let Some(value) = memory.get(&source.offset).copied() else {
                    return schedule_error(edge.ordinal, "scratch source is unavailable");
                };
                if value.word_type() != source.word_type {
                    return schedule_error(edge.ordinal, "scratch source storage type mismatch");
                }
                let key = (scratch_id, source.word_type);
                if scratches.insert(key, value).is_some() {
                    return schedule_error(edge.ordinal, "scratch identity is reused");
                }
            }
            X64TailCopyStep::Move {
                source,
                destination,
            } => {
                if source.word_type() != destination.word_type {
                    return schedule_error(edge.ordinal, "scheduled move type mismatch");
                }
                if !destination_offsets.contains(&destination.offset) {
                    return schedule_error(edge.ordinal, "move writes a non-destination");
                }
                let value = match source {
                    X64TailScheduledSource::Location(location) => memory
                        .get(&location.offset)
                        .copied()
                        .ok_or(X64TailStatePlanError::ScheduleMismatch {
                            edge: edge.ordinal,
                            reason: "move source is unavailable",
                        })?,
                    X64TailScheduledSource::Immediate(immediate) => {
                        SymbolicWord::Immediate(immediate)
                    }
                    X64TailScheduledSource::Scratch { id, word_type } => scratches
                        .get(&(id, word_type))
                        .copied()
                        .ok_or(X64TailStatePlanError::ScheduleMismatch {
                            edge: edge.ordinal,
                            reason: "scratch read is stale or unavailable",
                        })?,
                };
                if value.word_type() != destination.word_type {
                    return schedule_error(edge.ordinal, "symbolic value type mismatch");
                }
                memory.insert(destination.offset, value);
                let count = writes.entry(destination).or_default();
                *count = count
                    .checked_add(1)
                    .ok_or(X64TailStatePlanError::ArithmeticOverflow {
                        field: "schedule destination writes",
                    })?;
                if *count != 1 {
                    return schedule_error(edge.ordinal, "destination is written more than once");
                }
            }
        }
    }
    if writes.keys().copied().collect::<BTreeSet<_>>() != required_writes {
        return schedule_error(edge.ordinal, "schedule write coverage mismatch");
    }
    for (destination, expected) in expected {
        if memory.get(&destination.offset) != Some(&expected) {
            return schedule_error(edge.ordinal, "parallel snapshot result mismatch");
        }
    }
    Ok(())
}

fn schedule_error<T>(edge: u32, reason: &'static str) -> Result<T, X64TailStatePlanError> {
    Err(X64TailStatePlanError::ScheduleMismatch { edge, reason })
}

fn find_function(
    program: &X64TargetProgram,
    id: X64FunctionId,
) -> Result<&super::x64_target::X64Function, X64TailStatePlanError> {
    program
        .functions
        .binary_search_by_key(&id, |function| function.id)
        .ok()
        .map(|index| &program.functions[index])
        .ok_or(X64TailStatePlanError::MissingTarget { field: "function" })
}

fn find_block(
    function: &super::x64_target::X64Function,
    id: X64BlockId,
) -> Result<&super::x64_target::X64Block, X64TailStatePlanError> {
    function
        .blocks
        .binary_search_by_key(&id, |block| block.id)
        .ok()
        .map(|index| &function.blocks[index])
        .ok_or(X64TailStatePlanError::MissingTarget { field: "block" })
}

fn label_owner(
    program: &X64TargetProgram,
    label: X64LabelId,
) -> Result<(X64FunctionId, X64BlockId), X64TailStatePlanError> {
    let owner = program
        .labels
        .binary_search_by_key(&label, |entry| entry.id)
        .ok()
        .map(|index| program.labels[index].owner)
        .ok_or(X64TailStatePlanError::MissingTarget { field: "label" })?;
    match owner {
        X64LabelOwner::Block { function, block } => Ok((function, block)),
        X64LabelOwner::EntryAdapter
        | X64LabelOwner::ReturnEpilogue
        | X64LabelOwner::BoundsEpilogue => Err(X64TailStatePlanError::InvalidField {
            field: "non-block tail region label",
        }),
    }
}

fn ensure_limit(
    field: &'static str,
    limit: u32,
    actual: usize,
) -> Result<(), X64TailStatePlanError> {
    let actual = u64::try_from(actual).map_err(|_| X64TailStatePlanError::ArithmeticOverflow {
        field: "limit conversion",
    })?;
    if actual > u64::from(limit) {
        Err(X64TailStatePlanError::LimitExceeded {
            field,
            limit: u64::from(limit),
            actual,
        })
    } else {
        Ok(())
    }
}

fn checked_add_u32(
    left: u32,
    right: u32,
    field: &'static str,
) -> Result<u32, X64TailStatePlanError> {
    left.checked_add(right)
        .ok_or(X64TailStatePlanError::ArithmeticOverflow { field })
}

fn checked_add_u64(
    left: u64,
    right: u64,
    field: &'static str,
) -> Result<u64, X64TailStatePlanError> {
    left.checked_add(right)
        .ok_or(X64TailStatePlanError::ArithmeticOverflow { field })
}

fn x64_tail_state_plan_bytes_without_seal(
    plan: &X64TailStatePlan,
) -> Result<Vec<u8>, X64TailStatePlanError> {
    let mut encoder = PlanEncoder::new();
    encoder.bytes(PLAN_DOMAIN)?;
    encoder.version(plan.schema_version)?;
    encoder.version(plan.policy_version)?;
    encoder.hash(plan.source_semantic_hash)?;
    encoder.hash(plan.source_plan_hash)?;
    encoder.hash(plan.source_code_hash)?;
    encoder.len(plan.edges.len())?;
    for edge in &plan.edges {
        encoder.u32(edge.ordinal)?;
        encoder.u32(edge.source_function.0)?;
        encoder.u32(edge.source_block.0)?;
        encoder.u32(edge.source_label.0)?;
        encoder.u32(edge.target_function.0)?;
        encoder.u32(edge.target_label.0)?;
        encoder.len(edge.assignments.len())?;
        for assignment in &edge.assignments {
            encode_source(&mut encoder, assignment.source)?;
            encode_location(&mut encoder, assignment.destination)?;
        }
        encoder.len(edge.schedule.len())?;
        for step in &edge.schedule {
            match *step {
                X64TailCopyStep::SaveScratch { source, scratch_id } => {
                    encoder.u8(0)?;
                    encode_location(&mut encoder, source)?;
                    encoder.u32(scratch_id)?;
                }
                X64TailCopyStep::Move {
                    source,
                    destination,
                } => {
                    encoder.u8(1)?;
                    encode_scheduled_source(&mut encoder, source)?;
                    encode_location(&mut encoder, destination)?;
                }
            }
        }
        match &edge.disposition {
            X64TailEdgeDisposition::Persistent { region } => {
                encoder.u8(0)?;
                encoder.u32(*region)?;
            }
            X64TailEdgeDisposition::Materialize { frontiers } => {
                encoder.u8(1)?;
                encoder.len(frontiers.len())?;
                for frontier in frontiers {
                    encoder.u8(frontier_tag(*frontier))?;
                }
            }
            X64TailEdgeDisposition::Refused { reason } => {
                encoder.u8(2)?;
                encoder.u8(match reason {
                    X64TailRefusalReason::EdgeWordBudget => 0,
                    X64TailRefusalReason::RegionEdgeBudget => 1,
                })?;
            }
        }
    }
    encoder.len(plan.regions.len())?;
    for region in &plan.regions {
        encoder.u32(region.id)?;
        encoder.len(region.labels.len())?;
        for label in &region.labels {
            encoder.u32(label.0)?;
        }
        encoder.len(region.edge_ordinals.len())?;
        for ordinal in &region.edge_ordinals {
            encoder.u32(*ordinal)?;
        }
        encoder.u32(region.word_capacity)?;
        encoder.u32(region.scratch_saves)?;
        encoder.u32(region.logical_moves)?;
        encoder.u64(region.machine_byte_upper_bound)?;
    }
    encoder.len(plan.frontiers.len())?;
    for frontier in &plan.frontiers {
        encoder.u8(frontier_tag(frontier.kind))?;
        encoder.u32(frontier.function.0)?;
        encoder.u32(frontier.block.0)?;
        encoder.u32(frontier.label.0)?;
    }
    encode_totals(&mut encoder, plan.totals)?;
    Ok(encoder.finish())
}

fn encode_source(
    encoder: &mut PlanEncoder,
    source: X64TailWordSource,
) -> Result<(), X64TailStatePlanError> {
    match source {
        X64TailWordSource::Location(location) => {
            encoder.u8(0)?;
            encode_location(encoder, location)
        }
        X64TailWordSource::Immediate(immediate) => {
            encoder.u8(1)?;
            encode_immediate(encoder, immediate)
        }
    }
}

fn encode_scheduled_source(
    encoder: &mut PlanEncoder,
    source: X64TailScheduledSource,
) -> Result<(), X64TailStatePlanError> {
    match source {
        X64TailScheduledSource::Location(location) => {
            encoder.u8(0)?;
            encode_location(encoder, location)
        }
        X64TailScheduledSource::Immediate(immediate) => {
            encoder.u8(1)?;
            encode_immediate(encoder, immediate)
        }
        X64TailScheduledSource::Scratch { id, word_type } => {
            encoder.u8(2)?;
            encoder.u32(id)?;
            encoder.u8(word_type_tag(word_type))
        }
    }
}

fn encode_location(
    encoder: &mut PlanEncoder,
    location: X64TailWordLocation,
) -> Result<(), X64TailStatePlanError> {
    encoder.u32(location.offset)?;
    encoder.u8(word_type_tag(location.word_type))
}

fn encode_immediate(
    encoder: &mut PlanEncoder,
    immediate: X64TailImmediateWord,
) -> Result<(), X64TailStatePlanError> {
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

const fn word_type_tag(word_type: X64TailWordType) -> u8 {
    match word_type {
        X64TailWordType::Bool => 0,
        X64TailWordType::I64 => 1,
        X64TailWordType::F64 => 2,
        X64TailWordType::ArrayData => 3,
        X64TailWordType::ArrayLength => 4,
    }
}

const fn frontier_tag(kind: X64TailFrontierKind) -> u8 {
    match kind {
        X64TailFrontierKind::EntryAbi => 0,
        X64TailFrontierKind::SharedJoin => 1,
        X64TailFrontierKind::Bounds => 2,
        X64TailFrontierKind::Return => 3,
        X64TailFrontierKind::Budget => 4,
    }
}

fn encode_totals(
    encoder: &mut PlanEncoder,
    totals: X64TailStateTotals,
) -> Result<(), X64TailStatePlanError> {
    encoder.u32(totals.tail_edges)?;
    encoder.u32(totals.persistent_edges)?;
    encoder.u32(totals.materialized_edges)?;
    encoder.u32(totals.refused_edges)?;
    encoder.u64(totals.argument_words)?;
    encoder.u64(totals.identity_words)?;
    encoder.u64(totals.logical_moves)?;
    encoder.u64(totals.scratch_saves)?;
    encoder.u64(totals.current_frame_traffic_upper_bound)?;
    encoder.u64(totals.proposed_frame_traffic_upper_bound)?;
    encoder.u64(totals.candidate_machine_byte_upper_bound)
}

struct PlanEncoder {
    bytes: Vec<u8>,
}

impl PlanEncoder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn reserve(&mut self, additional: usize) -> Result<(), X64TailStatePlanError> {
        let actual = self.bytes.len().checked_add(additional).ok_or(
            X64TailStatePlanError::ArithmeticOverflow {
                field: "plan encoding length",
            },
        )?;
        if actual > MAX_PLAN_BYTES {
            return Err(X64TailStatePlanError::EncodingLimit { actual });
        }
        self.bytes
            .try_reserve(additional)
            .map_err(|_| X64TailStatePlanError::EncodingLimit { actual })
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), X64TailStatePlanError> {
        self.reserve(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), X64TailStatePlanError> {
        self.bytes(&[value])
    }

    fn u32(&mut self, value: u32) -> Result<(), X64TailStatePlanError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), X64TailStatePlanError> {
        self.bytes(&value.to_le_bytes())
    }

    fn len(&mut self, value: usize) -> Result<(), X64TailStatePlanError> {
        let value =
            u32::try_from(value).map_err(|_| X64TailStatePlanError::ArithmeticOverflow {
                field: "plan encoding collection length",
            })?;
        self.u32(value)
    }

    fn version(&mut self, version: (u16, u16, u16)) -> Result<(), X64TailStatePlanError> {
        self.bytes(&version.0.to_le_bytes())?;
        self.bytes(&version.1.to_le_bytes())?;
        self.bytes(&version.2.to_le_bytes())
    }

    fn hash(&mut self, hash: SemanticHash) -> Result<(), X64TailStatePlanError> {
        self.bytes(&hash.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::corevm0_gate_a::CoreVmGateAWorkload;
    use crate::core::x64_native_lighthouse::X64NativeLighthousePackage;
    use crate::core::X64_TARGET_ENCODER_POLICY_VERSION;

    fn location(offset: u32, word_type: X64TailWordType) -> X64TailWordLocation {
        X64TailWordLocation { offset, word_type }
    }

    fn assignment(source: u32, destination: u32) -> X64TailWordAssignment {
        X64TailWordAssignment {
            source: X64TailWordSource::Location(location(source, X64TailWordType::I64)),
            destination: location(destination, X64TailWordType::I64),
        }
    }

    fn edge(assignments: Vec<X64TailWordAssignment>) -> X64TailEdgePlan {
        let schedule = schedule_parallel_copy(&assignments).expect("parallel copy must schedule");
        X64TailEdgePlan {
            ordinal: 0,
            source_function: X64FunctionId(0),
            source_block: X64BlockId(0),
            source_label: X64LabelId(0),
            target_function: X64FunctionId(1),
            target_label: X64LabelId(1),
            assignments,
            schedule,
            disposition: X64TailEdgeDisposition::Persistent { region: 0 },
        }
    }

    #[test]
    fn parallel_copy_replays_identity_acyclic_and_duplicate_sources() {
        let cases = [
            vec![assignment(8, 8)],
            vec![assignment(8, 16), assignment(24, 32)],
            vec![assignment(8, 24), assignment(8, 32)],
            vec![
                X64TailWordAssignment {
                    source: X64TailWordSource::Immediate(X64TailImmediateWord::I64(41)),
                    destination: location(8, X64TailWordType::I64),
                },
                assignment(8, 16),
            ],
        ];
        for assignments in cases {
            replay_schedule(&edge(assignments)).expect("snapshot semantics must replay");
        }
    }

    #[test]
    fn parallel_copy_replays_two_and_three_cycles_with_typed_scratch() {
        for assignments in [
            vec![assignment(8, 16), assignment(16, 8)],
            vec![assignment(8, 16), assignment(16, 24), assignment(24, 8)],
        ] {
            let edge = edge(assignments);
            assert_eq!(
                edge.schedule
                    .iter()
                    .filter(|step| matches!(step, X64TailCopyStep::SaveScratch { .. }))
                    .count(),
                1
            );
            replay_schedule(&edge).expect("cyclic snapshot semantics must replay");
        }
    }

    #[test]
    fn ordered_array_pair_keeps_data_and_length_types_distinct() {
        let assignments = vec![
            X64TailWordAssignment {
                source: X64TailWordSource::Location(location(32, X64TailWordType::ArrayData)),
                destination: location(48, X64TailWordType::ArrayData),
            },
            X64TailWordAssignment {
                source: X64TailWordSource::Location(location(40, X64TailWordType::ArrayLength)),
                destination: location(56, X64TailWordType::ArrayLength),
            },
        ];
        replay_schedule(&edge(assignments)).expect("array pair must replay in word order");
    }

    #[test]
    fn typed_homes_that_alias_one_byte_offset_preserve_the_source_snapshot() {
        let assignments = vec![
            X64TailWordAssignment {
                source: X64TailWordSource::Location(location(40, X64TailWordType::ArrayLength)),
                destination: location(72, X64TailWordType::ArrayLength),
            },
            X64TailWordAssignment {
                source: X64TailWordSource::Location(location(72, X64TailWordType::I64)),
                destination: location(80, X64TailWordType::I64),
            },
        ];
        let scheduled = edge(assignments);
        assert!(matches!(
            scheduled.schedule.first(),
            Some(X64TailCopyStep::Move {
                source: X64TailScheduledSource::Location(X64TailWordLocation {
                    offset: 72,
                    word_type: X64TailWordType::I64,
                }),
                destination: X64TailWordLocation {
                    offset: 80,
                    word_type: X64TailWordType::I64,
                },
            })
        ));
        replay_schedule(&scheduled).expect("physical byte aliases must preserve snapshot order");

        let mut reordered = scheduled;
        reordered.schedule.reverse();
        assert!(matches!(
            replay_schedule(&reordered),
            Err(X64TailStatePlanError::ScheduleMismatch { .. })
        ));
    }

    #[test]
    fn stale_scratch_and_type_confusion_fail_closed() {
        let mut stale = edge(vec![assignment(8, 16)]);
        stale.schedule[0] = X64TailCopyStep::Move {
            source: X64TailScheduledSource::Scratch {
                id: 7,
                word_type: X64TailWordType::I64,
            },
            destination: location(16, X64TailWordType::I64),
        };
        assert!(matches!(
            replay_schedule(&stale),
            Err(X64TailStatePlanError::ScheduleMismatch { .. })
        ));

        let mut wrong_type = edge(vec![assignment(8, 16)]);
        wrong_type.schedule[0] = X64TailCopyStep::Move {
            source: X64TailScheduledSource::Location(location(8, X64TailWordType::F64)),
            destination: location(16, X64TailWordType::I64),
        };
        assert!(matches!(
            replay_schedule(&wrong_type),
            Err(X64TailStatePlanError::ScheduleMismatch { .. })
        ));

        let mut reordered_cycle = edge(vec![assignment(8, 16), assignment(16, 8)]);
        reordered_cycle.schedule.swap(0, 1);
        assert!(matches!(
            replay_schedule(&reordered_cycle),
            Err(X64TailStatePlanError::ScheduleMismatch { .. })
        ));
    }

    #[test]
    fn edge_and_region_budgets_refuse_without_partial_selection() {
        let over_word_budget = edge(
            (0..=X64_TAIL_STATE_MAX_WORDS_PER_EDGE)
                .map(|word| assignment(word * 16, word * 16 + 8))
                .collect(),
        );
        assert!(matches!(
            replay_schedule(&over_word_budget),
            Err(X64TailStatePlanError::ScheduleMismatch { .. })
        ));

        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("branch lighthouse must build");
        let plan = emit_x64_tail_state_plan(package.target()).expect("plan must emit");
        let seed = plan
            .edges
            .iter()
            .find(|edge| matches!(edge.disposition, X64TailEdgeDisposition::Persistent { .. }))
            .expect("lighthouse must contain a persistent edge")
            .clone();
        let mut edges = (0..=X64_TAIL_STATE_MAX_REGION_EDGES)
            .map(|ordinal| {
                let mut edge = seed.clone();
                edge.ordinal = ordinal;
                edge
            })
            .collect::<Vec<_>>();
        let mut frontiers = Vec::new();
        let regions = assign_regions(&package.target().program, &mut edges, &mut frontiers)
            .expect("over-budget region must classify");
        assert!(regions
            .iter()
            .all(|region| region.labels.len() == 1 && region.edge_ordinals.is_empty()));
        assert_eq!(
            regions.len(),
            package
                .target()
                .program
                .functions
                .iter()
                .map(|function| function.blocks.len())
                .sum::<usize>()
        );
        assert!(edges.iter().all(|edge| matches!(
            edge.disposition,
            X64TailEdgeDisposition::Refused {
                reason: X64TailRefusalReason::RegionEdgeBudget
            }
        )));
        assert_eq!(frontiers.len(), 1);
        assert_eq!(frontiers[0].kind, X64TailFrontierKind::Budget);
    }

    #[test]
    fn bounds_and_shared_join_frontiers_force_materialization() {
        let bounds = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BoundsOrderedArrayGet)
            .expect("Bounds lighthouse must build");
        let bounds_plan = emit_x64_tail_state_plan(bounds.target()).expect("Bounds plan must emit");
        verify_x64_tail_state_plan(&bounds_plan, bounds.target())
            .expect("Bounds plan must independently replay");
        assert!(bounds_plan
            .frontiers
            .iter()
            .any(|frontier| frontier.kind == X64TailFrontierKind::Bounds));
        assert!(bounds_plan.edges.iter().any(|edge| matches!(
            &edge.disposition,
            X64TailEdgeDisposition::Materialize { frontiers }
                if frontiers.contains(&X64TailFrontierKind::Bounds)
        )));

        let branch = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("branch lighthouse must build");
        let branch_plan = emit_x64_tail_state_plan(branch.target()).expect("branch plan must emit");
        assert!(branch_plan
            .frontiers
            .iter()
            .any(|frontier| frontier.kind == X64TailFrontierKind::SharedJoin));
        assert!(branch_plan.edges.iter().any(|edge| matches!(
            &edge.disposition,
            X64TailEdgeDisposition::Materialize { frontiers }
                if frontiers.contains(&X64TailFrontierKind::SharedJoin)
        )));
    }

    #[test]
    fn branch_lighthouse_plan_is_deterministic_and_locally_resealed_mutation_fails() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("branch lighthouse must build");
        let first = emit_x64_tail_state_plan(package.target()).expect("tail-state plan must emit");
        let second = emit_x64_tail_state_plan(package.target()).expect("plan must replay");
        assert_eq!(first, second);
        assert!(!first.edges().is_empty());
        assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
        assert_eq!(
            first.plan_hash().to_hex(),
            "576041d7747cf3d7e871307b04edf3b21bd3e87ddea0443cad8fea4b436bfa0b"
        );
        assert_eq!(
            first.totals(),
            X64TailStateTotals {
                tail_edges: 127,
                persistent_edges: 108,
                materialized_edges: 19,
                refused_edges: 0,
                argument_words: 1_289,
                identity_words: 1_100,
                logical_moves: 189,
                scratch_saves: 2,
                current_frame_traffic_upper_bound: 5_156,
                proposed_frame_traffic_upper_bound: 1_158,
                candidate_machine_byte_upper_bound: 20_870,
            }
        );
        verify_x64_tail_state_plan(&first, package.target())
            .expect("plan must independently verify");
        let block_labels = package
            .target()
            .program
            .functions
            .iter()
            .flat_map(|function| function.blocks.iter().map(|block| block.label))
            .collect::<BTreeSet<_>>();
        let region_labels = first
            .regions()
            .iter()
            .flat_map(|region| region.labels.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(region_labels.len(), block_labels.len());
        assert_eq!(
            region_labels.into_iter().collect::<BTreeSet<_>>(),
            block_labels
        );
        let mut mutated = first.clone();
        mutated.totals.logical_moves = mutated.totals.logical_moves.saturating_add(1);
        mutated.plan_hash =
            x64_tail_state_plan_hash(&mutated).expect("mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_state_plan(&mutated, package.target()),
            Err(X64TailStatePlanError::ReplayMismatch)
        ));

        let mut wrong_source = first.clone();
        wrong_source.source_plan_hash.0[0] ^= 1;
        wrong_source.plan_hash =
            x64_tail_state_plan_hash(&wrong_source).expect("source mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_state_plan(&wrong_source, package.target()),
            Err(X64TailStatePlanError::InvalidField {
                field: "source identity"
            })
        ));

        let mut wrong_frontier = first.clone();
        wrong_frontier.frontiers.remove(0);
        wrong_frontier.plan_hash = x64_tail_state_plan_hash(&wrong_frontier)
            .expect("frontier mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_state_plan(&wrong_frontier, package.target()),
            Err(X64TailStatePlanError::ReplayMismatch)
        ));

        let mut wrong_region = first.clone();
        wrong_region.regions[0].edge_ordinals[0] = u32::MAX;
        wrong_region.plan_hash =
            x64_tail_state_plan_hash(&wrong_region).expect("region mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_state_plan(&wrong_region, package.target()),
            Err(X64TailStatePlanError::ReplayMismatch)
        ));

        let mut missing_move = first.clone();
        let edge = missing_move
            .edges
            .iter_mut()
            .find(|edge| !edge.schedule.is_empty())
            .expect("lighthouse must contain a scheduled move");
        edge.schedule.remove(0);
        missing_move.plan_hash =
            x64_tail_state_plan_hash(&missing_move).expect("schedule mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_state_plan(&missing_move, package.target()),
            Err(X64TailStatePlanError::ScheduleMismatch { .. })
        ));

        let mut wrong_disposition = first.clone();
        let edge = wrong_disposition
            .edges
            .iter_mut()
            .find(|edge| matches!(edge.disposition, X64TailEdgeDisposition::Persistent { .. }))
            .expect("lighthouse must contain a persistent edge");
        edge.disposition = X64TailEdgeDisposition::Refused {
            reason: X64TailRefusalReason::RegionEdgeBudget,
        };
        wrong_disposition.plan_hash = x64_tail_state_plan_hash(&wrong_disposition)
            .expect("disposition mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_state_plan(&wrong_disposition, package.target()),
            Err(X64TailStatePlanError::ReplayMismatch)
        ));
    }
}
