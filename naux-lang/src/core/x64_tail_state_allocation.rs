//! Proof-only finite physical register allocation for ADR-0057 tail-state
//! regions.
//!
//! This module does not emit machine code. It binds a verified logical plan to
//! an explicit x86-64 GPR/XMM bank, records every spill and physical
//! transition, and independently replays both interference and parallel-copy
//! semantics before returning a non-executable witness.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_state_plan::{
    verify_x64_tail_state_plan, X64TailEdgeDisposition, X64TailEdgePlan, X64TailImmediateWord,
    X64TailStatePlan, X64TailStatePlanError, X64TailStateRegion, X64TailWordLocation,
    X64TailWordSource, X64TailWordType,
};
use super::x64_target::X64TargetArtifact;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const X64_TAIL_PHYSICAL_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_PHYSICAL_POLICY_VERSION: (u16, u16, u16) = (1, 1, 0);
pub const X64_TAIL_PHYSICAL_GPR_LANES: u32 = 5;
pub const X64_TAIL_PHYSICAL_XMM_LANES: u32 = 5;
pub const X64_TAIL_PHYSICAL_MAX_LOCATIONS_PER_REGION: u32 = 256;
pub const X64_TAIL_PHYSICAL_MAX_INTERFERENCE_PAIRS: u32 = 32_768;
pub const X64_TAIL_PHYSICAL_MAX_TRANSITION_STEPS: u32 = 16_384;
pub const X64_TAIL_PHYSICAL_MAX_ALLOCATION_WORK: u64 = 1_000_000;
pub const X64_TAIL_PHYSICAL_MAX_BYTES_PER_OPERATION: u32 = 15;

const ALLOCATION_DOMAIN: &[u8] = b"NAUX:x86-64:tail-physical-allocation:v1\0";
const MAX_ALLOCATION_BYTES: usize = 16 * 1024 * 1024;
const TAIL_BRANCH_BYTE_UPPER_BOUND: u64 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum X64TailRegisterBank {
    Gpr,
    Xmm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum X64TailPhysicalRegister {
    Rdi,
    Rsi,
    R9,
    R10,
    R11,
    Xmm3,
    Xmm4,
    Xmm5,
    Xmm6,
    Xmm7,
}

impl X64TailPhysicalRegister {
    pub const fn bank(self) -> X64TailRegisterBank {
        match self {
            Self::Rdi | Self::Rsi | Self::R9 | Self::R10 | Self::R11 => X64TailRegisterBank::Gpr,
            Self::Xmm3 | Self::Xmm4 | Self::Xmm5 | Self::Xmm6 | Self::Xmm7 => {
                X64TailRegisterBank::Xmm
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum X64TailScratchRegister {
    Rax,
    Xmm0,
}

impl X64TailScratchRegister {
    pub const fn bank(self) -> X64TailRegisterBank {
        match self {
            Self::Rax => X64TailRegisterBank::Gpr,
            Self::Xmm0 => X64TailRegisterBank::Xmm,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum X64TailPhysicalLocation {
    Register {
        register: X64TailPhysicalRegister,
        word_type: X64TailWordType,
    },
    Frame(X64TailWordLocation),
}

impl X64TailPhysicalLocation {
    pub const fn word_type(self) -> X64TailWordType {
        match self {
            Self::Register { word_type, .. } => word_type,
            Self::Frame(location) => location.word_type,
        }
    }

    pub const fn bank(self) -> X64TailRegisterBank {
        word_bank(self.word_type())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum X64TailPhysicalStorage {
    Register(X64TailPhysicalRegister),
    Frame(u32),
}

const fn physical_storage(location: X64TailPhysicalLocation) -> X64TailPhysicalStorage {
    match location {
        X64TailPhysicalLocation::Register { register, .. } => {
            X64TailPhysicalStorage::Register(register)
        }
        X64TailPhysicalLocation::Frame(location) => X64TailPhysicalStorage::Frame(location.offset),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailPhysicalSource {
    Location(X64TailPhysicalLocation),
    Immediate(X64TailImmediateWord),
}

impl X64TailPhysicalSource {
    const fn word_type(self) -> X64TailWordType {
        match self {
            Self::Location(location) => location.word_type(),
            Self::Immediate(immediate) => immediate_word_type(immediate),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailPhysicalAssignment {
    pub source: X64TailPhysicalSource,
    pub destination: X64TailPhysicalLocation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailPhysicalScheduledSource {
    Location(X64TailPhysicalLocation),
    Immediate(X64TailImmediateWord),
    Scratch {
        register: X64TailScratchRegister,
        word_type: X64TailWordType,
    },
}

impl X64TailPhysicalScheduledSource {
    const fn word_type(self) -> X64TailWordType {
        match self {
            Self::Location(location) => location.word_type(),
            Self::Immediate(immediate) => immediate_word_type(immediate),
            Self::Scratch { word_type, .. } => word_type,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailPhysicalStep {
    SaveScratch {
        source: X64TailPhysicalLocation,
        scratch: X64TailScratchRegister,
    },
    Move {
        source: X64TailPhysicalScheduledSource,
        destination: X64TailPhysicalLocation,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailValueAllocation {
    pub logical: X64TailWordLocation,
    pub physical: X64TailPhysicalLocation,
    pub occurrences: u32,
    pub interference_degree: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailPhysicalRefusalReason {
    LocationBudget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailPhysicalRegionDisposition {
    Allocated,
    Refused {
        reason: X64TailPhysicalRefusalReason,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailPhysicalRegion {
    pub region: u32,
    pub edge_ordinals: Vec<u32>,
    pub logical_locations: u32,
    pub interference_pairs: u32,
    pub gpr_peak_live: u32,
    pub xmm_peak_live: u32,
    pub register_locations: u32,
    pub spilled_locations: u32,
    pub values: Vec<X64TailValueAllocation>,
    pub disposition: X64TailPhysicalRegionDisposition,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailPhysicalTransition {
    pub edge_ordinal: u32,
    pub region: u32,
    pub assignments: Vec<X64TailPhysicalAssignment>,
    pub schedule: Vec<X64TailPhysicalStep>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X64TailPhysicalTotals {
    pub regions: u32,
    pub allocated_regions: u32,
    pub refused_regions: u32,
    pub logical_locations: u64,
    pub register_locations: u64,
    pub spilled_locations: u64,
    pub interference_pairs: u64,
    pub transitions: u32,
    pub physical_moves: u64,
    pub scratch_saves: u64,
    pub frame_loads: u64,
    pub frame_stores: u64,
    pub immediate_materializations: u64,
    pub machine_byte_upper_bound: u64,
    pub allocation_work: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailPhysicalAllocation {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    source_target_semantic_hash: SemanticHash,
    source_logical_plan_hash: SemanticHash,
    regions: Vec<X64TailPhysicalRegion>,
    transitions: Vec<X64TailPhysicalTransition>,
    totals: X64TailPhysicalTotals,
    allocation_hash: SemanticHash,
}

impl X64TailPhysicalAllocation {
    pub const fn source_target_semantic_hash(&self) -> SemanticHash {
        self.source_target_semantic_hash
    }

    pub const fn source_logical_plan_hash(&self) -> SemanticHash {
        self.source_logical_plan_hash
    }

    pub fn regions(&self) -> &[X64TailPhysicalRegion] {
        &self.regions
    }

    pub fn transitions(&self) -> &[X64TailPhysicalTransition] {
        &self.transitions
    }

    pub const fn totals(&self) -> X64TailPhysicalTotals {
        self.totals
    }

    pub const fn allocation_hash(&self) -> SemanticHash {
        self.allocation_hash
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedX64TailPhysicalAllocation<'allocation> {
    allocation: &'allocation X64TailPhysicalAllocation,
}

impl<'allocation> VerifiedX64TailPhysicalAllocation<'allocation> {
    pub const fn allocation(self) -> &'allocation X64TailPhysicalAllocation {
        self.allocation
    }
}

#[derive(Debug)]
pub enum X64TailPhysicalAllocationError {
    Logical(X64TailStatePlanError),
    InvalidField {
        field: &'static str,
    },
    MissingEdge {
        ordinal: u32,
    },
    MissingLocation {
        region: u32,
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
    AllocationHashMismatch,
    ReplayMismatch,
    InterferenceViolation {
        region: u32,
    },
    TransitionMismatch {
        edge: u32,
        reason: &'static str,
    },
}

impl fmt::Display for X64TailPhysicalAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Logical(error) => write!(formatter, "physical tail allocation input failed: {error}"),
            Self::InvalidField { field } => write!(formatter, "physical tail allocation has invalid {field}"),
            Self::MissingEdge { ordinal } => write!(formatter, "physical tail allocation cannot resolve edge {ordinal}"),
            Self::MissingLocation { region } => write!(formatter, "physical tail region {region} has an unallocated logical location"),
            Self::LimitExceeded { field, limit, actual } => write!(formatter, "physical tail allocation {field} uses {actual}; limit is {limit}"),
            Self::ArithmeticOverflow { field } => write!(formatter, "physical tail allocation overflowed {field}"),
            Self::EncodingLimit { actual } => write!(formatter, "physical tail allocation encoding uses {actual} bytes; limit is {MAX_ALLOCATION_BYTES}"),
            Self::AllocationHashMismatch => formatter.write_str("physical tail allocation seal does not replay"),
            Self::ReplayMismatch => formatter.write_str("physical tail allocation differs from canonical replay"),
            Self::InterferenceViolation { region } => write!(formatter, "physical tail region {region} aliases interfering logical locations"),
            Self::TransitionMismatch { edge, reason } => write!(formatter, "physical tail edge {edge} transition failed: {reason}"),
        }
    }
}

impl std::error::Error for X64TailPhysicalAllocationError {}

impl From<X64TailStatePlanError> for X64TailPhysicalAllocationError {
    fn from(value: X64TailStatePlanError) -> Self {
        Self::Logical(value)
    }
}

/// Allocate the accepted logical tail-state regions into the frozen finite
/// physical bank. The result is metadata only and has no encoding API.
pub fn emit_x64_tail_physical_allocation(
    artifact: &X64TargetArtifact,
    logical: &X64TailStatePlan,
) -> Result<X64TailPhysicalAllocation, X64TailPhysicalAllocationError> {
    verify_x64_tail_state_plan(logical, artifact)?;
    construct_allocation(artifact.semantic_hash, logical)
}

/// Reverify target/logical provenance, physical interference, every symbolic
/// transition, the seal, and complete canonical regeneration.
pub fn verify_x64_tail_physical_allocation<'allocation>(
    allocation: &'allocation X64TailPhysicalAllocation,
    logical: &X64TailStatePlan,
    artifact: &X64TargetArtifact,
) -> Result<VerifiedX64TailPhysicalAllocation<'allocation>, X64TailPhysicalAllocationError> {
    verify_x64_tail_state_plan(logical, artifact)?;
    validate_envelope(allocation, logical, artifact.semantic_hash)?;
    if x64_tail_physical_allocation_hash(allocation)? != allocation.allocation_hash {
        return Err(X64TailPhysicalAllocationError::AllocationHashMismatch);
    }
    audit_allocation(allocation, logical)?;
    let replayed = construct_allocation(artifact.semantic_hash, logical)?;
    if replayed != *allocation {
        return Err(X64TailPhysicalAllocationError::ReplayMismatch);
    }
    Ok(VerifiedX64TailPhysicalAllocation { allocation })
}

pub fn x64_tail_physical_allocation_hash(
    allocation: &X64TailPhysicalAllocation,
) -> Result<SemanticHash, X64TailPhysicalAllocationError> {
    Ok(SemanticHash(sha256(&allocation_bytes_without_seal(
        allocation,
    )?)))
}

fn construct_allocation(
    target_semantic_hash: SemanticHash,
    logical: &X64TailStatePlan,
) -> Result<X64TailPhysicalAllocation, X64TailPhysicalAllocationError> {
    let edge_index = logical
        .edges()
        .iter()
        .map(|edge| (edge.ordinal, edge))
        .collect::<BTreeMap<_, _>>();
    let mut regions = Vec::new();
    let mut transitions = Vec::new();
    let mut allocation_work = 0_u64;
    let mut total_pairs = 0_u64;

    for logical_region in logical.regions() {
        let facts = derive_region_facts(logical_region, &edge_index, &mut allocation_work)?;
        total_pairs = checked_add_u64(
            total_pairs,
            u64::from(facts.interference_pairs),
            "interference pair total",
        )?;
        if total_pairs > u64::from(X64_TAIL_PHYSICAL_MAX_INTERFERENCE_PAIRS) {
            return Err(X64TailPhysicalAllocationError::LimitExceeded {
                field: "interference pairs",
                limit: u64::from(X64_TAIL_PHYSICAL_MAX_INTERFERENCE_PAIRS),
                actual: total_pairs,
            });
        }

        if let Some(reason) = region_refusal(&facts) {
            regions.push(X64TailPhysicalRegion {
                region: logical_region.id,
                edge_ordinals: logical_region.edge_ordinals.clone(),
                logical_locations: usize_to_u32(
                    facts.locations.len(),
                    "refused logical locations",
                )?,
                interference_pairs: facts.interference_pairs,
                gpr_peak_live: facts.gpr_peak_live,
                xmm_peak_live: facts.xmm_peak_live,
                register_locations: 0,
                spilled_locations: usize_to_u32(
                    facts.locations.len(),
                    "refused spilled locations",
                )?,
                values: Vec::new(),
                disposition: X64TailPhysicalRegionDisposition::Refused { reason },
            });
            continue;
        }

        let values = allocate_region_values(&facts, &mut allocation_work)?;
        let register_locations = usize_to_u32(
            values
                .iter()
                .filter(|value| matches!(value.physical, X64TailPhysicalLocation::Register { .. }))
                .count(),
            "register locations",
        )?;
        let spilled_locations = usize_to_u32(
            values
                .iter()
                .filter(|value| matches!(value.physical, X64TailPhysicalLocation::Frame(_)))
                .count(),
            "spilled locations",
        )?;
        let value_map = values
            .iter()
            .map(|value| (value.logical, value.physical))
            .collect::<BTreeMap<_, _>>();
        for ordinal in &logical_region.edge_ordinals {
            let edge = edge_index
                .get(ordinal)
                .copied()
                .ok_or(X64TailPhysicalAllocationError::MissingEdge { ordinal: *ordinal })?;
            let assignments = project_physical_assignments(edge, &value_map, logical_region.id)?;
            let schedule = schedule_physical_copy(&assignments)?;
            transitions.push(X64TailPhysicalTransition {
                edge_ordinal: *ordinal,
                region: logical_region.id,
                assignments,
                schedule,
            });
        }
        regions.push(X64TailPhysicalRegion {
            region: logical_region.id,
            edge_ordinals: logical_region.edge_ordinals.clone(),
            logical_locations: usize_to_u32(facts.locations.len(), "logical locations")?,
            interference_pairs: facts.interference_pairs,
            gpr_peak_live: facts.gpr_peak_live,
            xmm_peak_live: facts.xmm_peak_live,
            register_locations,
            spilled_locations,
            values,
            disposition: X64TailPhysicalRegionDisposition::Allocated,
        });
    }

    if allocation_work > X64_TAIL_PHYSICAL_MAX_ALLOCATION_WORK {
        return Err(X64TailPhysicalAllocationError::LimitExceeded {
            field: "allocation work",
            limit: X64_TAIL_PHYSICAL_MAX_ALLOCATION_WORK,
            actual: allocation_work,
        });
    }
    transitions.sort_by_key(|transition| transition.edge_ordinal);
    let step_count = transitions.iter().try_fold(0_usize, |total, transition| {
        total.checked_add(transition.schedule.len()).ok_or(
            X64TailPhysicalAllocationError::ArithmeticOverflow {
                field: "physical transition steps",
            },
        )
    })?;
    ensure_limit(
        "physical transition steps",
        X64_TAIL_PHYSICAL_MAX_TRANSITION_STEPS,
        step_count,
    )?;
    let totals = compute_totals(&regions, &transitions, allocation_work)?;
    let mut allocation = X64TailPhysicalAllocation {
        schema_version: X64_TAIL_PHYSICAL_SCHEMA_VERSION,
        policy_version: X64_TAIL_PHYSICAL_POLICY_VERSION,
        source_target_semantic_hash: target_semantic_hash,
        source_logical_plan_hash: logical.plan_hash(),
        regions,
        transitions,
        totals,
        allocation_hash: SemanticHash::ZERO,
    };
    allocation.allocation_hash = x64_tail_physical_allocation_hash(&allocation)?;
    Ok(allocation)
}

fn region_refusal(facts: &RegionFacts) -> Option<X64TailPhysicalRefusalReason> {
    (facts.locations.len() > X64_TAIL_PHYSICAL_MAX_LOCATIONS_PER_REGION as usize)
        .then_some(X64TailPhysicalRefusalReason::LocationBudget)
}

#[derive(Debug)]
struct RegionFacts {
    locations: Vec<X64TailWordLocation>,
    occurrences: BTreeMap<X64TailWordLocation, u32>,
    interference: BTreeMap<X64TailWordLocation, BTreeSet<X64TailWordLocation>>,
    interference_pairs: u32,
    gpr_peak_live: u32,
    xmm_peak_live: u32,
}

fn derive_region_facts(
    region: &X64TailStateRegion,
    edges: &BTreeMap<u32, &X64TailEdgePlan>,
    work: &mut u64,
) -> Result<RegionFacts, X64TailPhysicalAllocationError> {
    let mut locations = BTreeSet::new();
    let mut occurrences = BTreeMap::<X64TailWordLocation, u32>::new();
    for ordinal in &region.edge_ordinals {
        charge(work, 1, "region edge discovery")?;
        let edge = edges
            .get(ordinal)
            .copied()
            .ok_or(X64TailPhysicalAllocationError::MissingEdge { ordinal: *ordinal })?;
        if edge_region(edge) != Some(region.id) {
            return Err(X64TailPhysicalAllocationError::InvalidField {
                field: "logical region edge membership",
            });
        }
        for assignment in &edge.assignments {
            charge(work, 1, "logical location discovery")?;
            if let X64TailWordSource::Location(source) = assignment.source {
                locations.insert(source);
                increment_occurrence(&mut occurrences, source)?;
            }
            locations.insert(assignment.destination);
            increment_occurrence(&mut occurrences, assignment.destination)?;
        }
    }

    let mut interference = locations
        .iter()
        .copied()
        .map(|location| (location, BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    let mut pairs = BTreeSet::new();
    // A region can carry a word across several edges where it does not appear
    // in the local parallel-copy set.  Per-edge interference therefore permits
    // two loop-carried values to alias one register and lets an intermediate
    // edge overwrite a still-live value.  Until path-sensitive liveness is a
    // separately replayable authority, make every same-bank region location
    // interfere.  This is conservative, bounded, and correctness-preserving.
    let region_locations = locations.iter().copied().collect::<Vec<_>>();
    for left in 0..region_locations.len() {
        for right in left.saturating_add(1)..region_locations.len() {
            charge(work, 1, "region-wide interference discovery")?;
            if word_bank(region_locations[left].word_type)
                != word_bank(region_locations[right].word_type)
            {
                continue;
            }
            let pair = (region_locations[left], region_locations[right]);
            pairs.insert(pair);
            interference
                .get_mut(&pair.0)
                .ok_or(X64TailPhysicalAllocationError::InvalidField {
                    field: "interference left endpoint",
                })?
                .insert(pair.1);
            interference
                .get_mut(&pair.1)
                .ok_or(X64TailPhysicalAllocationError::InvalidField {
                    field: "interference right endpoint",
                })?
                .insert(pair.0);
        }
    }
    let gpr_peak_live = usize_to_u32(
        region_locations
            .iter()
            .filter(|location| word_bank(location.word_type) == X64TailRegisterBank::Gpr)
            .count(),
        "GPR region live",
    )?;
    let xmm_peak_live = usize_to_u32(
        region_locations
            .len()
            .saturating_sub(gpr_peak_live as usize),
        "XMM region live",
    )?;
    Ok(RegionFacts {
        locations: locations.into_iter().collect(),
        occurrences,
        interference,
        interference_pairs: usize_to_u32(pairs.len(), "interference pairs")?,
        gpr_peak_live,
        xmm_peak_live,
    })
}

fn allocate_region_values(
    facts: &RegionFacts,
    work: &mut u64,
) -> Result<Vec<X64TailValueAllocation>, X64TailPhysicalAllocationError> {
    let mut ordered = facts.locations.clone();
    ordered.sort_by(|left, right| {
        word_bank(left.word_type)
            .cmp(&word_bank(right.word_type))
            .then_with(|| {
                facts
                    .interference
                    .get(right)
                    .map_or(0, BTreeSet::len)
                    .cmp(&facts.interference.get(left).map_or(0, BTreeSet::len))
            })
            .then_with(|| {
                facts
                    .occurrences
                    .get(right)
                    .copied()
                    .unwrap_or(0)
                    .cmp(&facts.occurrences.get(left).copied().unwrap_or(0))
            })
            .then_with(|| left.cmp(right))
    });
    let mut assigned = BTreeMap::new();
    for location in ordered {
        charge(work, 1, "physical location allocation")?;
        let occupied = facts
            .interference
            .get(&location)
            .into_iter()
            .flatten()
            .filter_map(|neighbor| match assigned.get(neighbor) {
                Some(X64TailPhysicalLocation::Register { register, .. }) => Some(*register),
                Some(X64TailPhysicalLocation::Frame(_)) | None => None,
            })
            .collect::<BTreeSet<_>>();
        let physical = registers_for_bank(word_bank(location.word_type))
            .iter()
            .copied()
            .find(|register| !occupied.contains(register))
            .map_or(X64TailPhysicalLocation::Frame(location), |register| {
                X64TailPhysicalLocation::Register {
                    register,
                    word_type: location.word_type,
                }
            });
        assigned.insert(location, physical);
    }
    facts
        .locations
        .iter()
        .map(|location| {
            Ok(X64TailValueAllocation {
                logical: *location,
                physical: assigned.get(location).copied().ok_or(
                    X64TailPhysicalAllocationError::InvalidField {
                        field: "allocated physical location",
                    },
                )?,
                occurrences: facts.occurrences.get(location).copied().unwrap_or(0),
                interference_degree: usize_to_u32(
                    facts.interference.get(location).map_or(0, BTreeSet::len),
                    "interference degree",
                )?,
            })
        })
        .collect()
}

fn project_physical_assignments(
    edge: &X64TailEdgePlan,
    values: &BTreeMap<X64TailWordLocation, X64TailPhysicalLocation>,
    region: u32,
) -> Result<Vec<X64TailPhysicalAssignment>, X64TailPhysicalAllocationError> {
    let mut assignments = Vec::with_capacity(edge.assignments.len());
    for logical in &edge.assignments {
        let destination = values
            .get(&logical.destination)
            .copied()
            .ok_or(X64TailPhysicalAllocationError::MissingLocation { region })?;
        let source = match logical.source {
            X64TailWordSource::Location(location) => X64TailPhysicalSource::Location(
                values
                    .get(&location)
                    .copied()
                    .ok_or(X64TailPhysicalAllocationError::MissingLocation { region })?,
            ),
            X64TailWordSource::Immediate(immediate) => X64TailPhysicalSource::Immediate(immediate),
        };
        if source.word_type() != destination.word_type() {
            return Err(X64TailPhysicalAllocationError::InvalidField {
                field: "projected physical word type",
            });
        }
        assignments.push(X64TailPhysicalAssignment {
            source,
            destination,
        });
    }
    assignments.sort_by_key(|assignment| assignment.destination);
    if assignments
        .windows(2)
        .any(|pair| physical_storage(pair[0].destination) == physical_storage(pair[1].destination))
    {
        return Err(X64TailPhysicalAllocationError::InterferenceViolation { region });
    }
    Ok(assignments)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MutablePhysicalAssignment {
    source: X64TailPhysicalScheduledSource,
    destination: X64TailPhysicalLocation,
}

fn schedule_physical_copy(
    assignments: &[X64TailPhysicalAssignment],
) -> Result<Vec<X64TailPhysicalStep>, X64TailPhysicalAllocationError> {
    let mut pending = assignments
        .iter()
        .copied()
        .filter(|assignment| {
            !matches!(assignment.source, X64TailPhysicalSource::Location(source) if physical_storage(source) == physical_storage(assignment.destination))
        })
        .map(|assignment| MutablePhysicalAssignment {
            source: match assignment.source {
                X64TailPhysicalSource::Location(location) => {
                    X64TailPhysicalScheduledSource::Location(location)
                }
                X64TailPhysicalSource::Immediate(immediate) => {
                    X64TailPhysicalScheduledSource::Immediate(immediate)
                }
            },
            destination: assignment.destination,
        })
        .collect::<Vec<_>>();
    pending.sort_by_key(|assignment| assignment.destination);
    let mut schedule = Vec::new();
    while !pending.is_empty() {
        let source_storage = pending
            .iter()
            .filter_map(|assignment| match assignment.source {
                X64TailPhysicalScheduledSource::Location(location) => {
                    Some(physical_storage(location))
                }
                X64TailPhysicalScheduledSource::Immediate(_)
                | X64TailPhysicalScheduledSource::Scratch { .. } => None,
            })
            .collect::<BTreeSet<_>>();
        if let Some(position) = pending.iter().position(|assignment| {
            !source_storage.contains(&physical_storage(assignment.destination))
        }) {
            let assignment = pending.remove(position);
            schedule.push(X64TailPhysicalStep::Move {
                source: assignment.source,
                destination: assignment.destination,
            });
            continue;
        }
        let cycle_storage = physical_storage(pending[0].destination);
        let cycle_source = pending
            .iter()
            .find_map(|assignment| match assignment.source {
                X64TailPhysicalScheduledSource::Location(location)
                    if physical_storage(location) == cycle_storage =>
                {
                    Some(location)
                }
                X64TailPhysicalScheduledSource::Location(_)
                | X64TailPhysicalScheduledSource::Immediate(_)
                | X64TailPhysicalScheduledSource::Scratch { .. } => None,
            })
            .ok_or(X64TailPhysicalAllocationError::InvalidField {
                field: "irreducible physical copy cycle",
            })?;
        let scratch = scratch_for_bank(cycle_source.bank());
        schedule.push(X64TailPhysicalStep::SaveScratch {
            source: cycle_source,
            scratch,
        });
        let mut replaced = false;
        for assignment in &mut pending {
            if let X64TailPhysicalScheduledSource::Location(location) = assignment.source {
                if physical_storage(location) == cycle_storage {
                    if location.word_type() != cycle_source.word_type() {
                        return Err(X64TailPhysicalAllocationError::InvalidField {
                            field: "cross-typed physical copy cycle",
                        });
                    }
                    assignment.source = X64TailPhysicalScheduledSource::Scratch {
                        register: scratch,
                        word_type: cycle_source.word_type(),
                    };
                    replaced = true;
                }
            }
        }
        if !replaced {
            return Err(X64TailPhysicalAllocationError::InvalidField {
                field: "irreducible physical copy cycle",
            });
        }
    }
    Ok(schedule)
}

fn audit_allocation(
    allocation: &X64TailPhysicalAllocation,
    logical: &X64TailStatePlan,
) -> Result<(), X64TailPhysicalAllocationError> {
    let edge_index = logical
        .edges()
        .iter()
        .map(|edge| (edge.ordinal, edge))
        .collect::<BTreeMap<_, _>>();
    let logical_regions = logical
        .regions()
        .iter()
        .map(|region| (region.id, region))
        .collect::<BTreeMap<_, _>>();
    let transition_index = allocation
        .transitions
        .iter()
        .map(|transition| (transition.edge_ordinal, transition))
        .collect::<BTreeMap<_, _>>();
    if transition_index.len() != allocation.transitions.len() {
        return Err(X64TailPhysicalAllocationError::InvalidField {
            field: "duplicate physical transition",
        });
    }

    let mut expected_transition_edges = BTreeSet::new();
    for region in &allocation.regions {
        let logical_region = logical_regions.get(&region.region).copied().ok_or(
            X64TailPhysicalAllocationError::InvalidField {
                field: "physical region identity",
            },
        )?;
        if region.edge_ordinals != logical_region.edge_ordinals {
            return Err(X64TailPhysicalAllocationError::InvalidField {
                field: "physical region edge coverage",
            });
        }
        match region.disposition {
            X64TailPhysicalRegionDisposition::Allocated => {
                audit_allocated_region(region, logical_region, &edge_index)?;
                for ordinal in &region.edge_ordinals {
                    expected_transition_edges.insert(*ordinal);
                    let edge = edge_index
                        .get(ordinal)
                        .copied()
                        .ok_or(X64TailPhysicalAllocationError::MissingEdge { ordinal: *ordinal })?;
                    let transition = transition_index
                        .get(ordinal)
                        .copied()
                        .ok_or(X64TailPhysicalAllocationError::MissingEdge { ordinal: *ordinal })?;
                    audit_transition(transition, edge, region)?;
                }
            }
            X64TailPhysicalRegionDisposition::Refused { .. } => {
                if !region.values.is_empty()
                    || region.register_locations != 0
                    || transition_index
                        .values()
                        .any(|transition| transition.region == region.region)
                {
                    return Err(X64TailPhysicalAllocationError::InvalidField {
                        field: "partial refused region allocation",
                    });
                }
            }
        }
    }
    if transition_index.keys().copied().collect::<BTreeSet<_>>() != expected_transition_edges {
        return Err(X64TailPhysicalAllocationError::InvalidField {
            field: "physical transition coverage",
        });
    }
    Ok(())
}

fn audit_allocated_region(
    region: &X64TailPhysicalRegion,
    logical_region: &X64TailStateRegion,
    edges: &BTreeMap<u32, &X64TailEdgePlan>,
) -> Result<(), X64TailPhysicalAllocationError> {
    if region
        .values
        .windows(2)
        .any(|pair| pair[0].logical >= pair[1].logical)
    {
        return Err(X64TailPhysicalAllocationError::InvalidField {
            field: "physical value ordering",
        });
    }
    let values = region
        .values
        .iter()
        .map(|value| (value.logical, value))
        .collect::<BTreeMap<_, _>>();
    if values.len() != region.values.len() {
        return Err(X64TailPhysicalAllocationError::InvalidField {
            field: "duplicate physical value",
        });
    }
    let mut expected_locations = BTreeSet::new();
    let mut occurrences = BTreeMap::<X64TailWordLocation, u32>::new();
    let mut pairs = BTreeSet::new();
    for ordinal in &logical_region.edge_ordinals {
        let edge = edges
            .get(ordinal)
            .copied()
            .ok_or(X64TailPhysicalAllocationError::MissingEdge { ordinal: *ordinal })?;
        for assignment in &edge.assignments {
            if let X64TailWordSource::Location(source) = assignment.source {
                expected_locations.insert(source);
                increment_occurrence(&mut occurrences, source)?;
            }
            expected_locations.insert(assignment.destination);
            increment_occurrence(&mut occurrences, assignment.destination)?;
        }
    }
    let region_locations = expected_locations.iter().copied().collect::<Vec<_>>();
    for left in 0..region_locations.len() {
        for right in left.saturating_add(1)..region_locations.len() {
            if word_bank(region_locations[left].word_type)
                == word_bank(region_locations[right].word_type)
            {
                pairs.insert((region_locations[left], region_locations[right]));
            }
        }
    }
    let gpr_peak = usize_to_u32(
        region_locations
            .iter()
            .filter(|location| word_bank(location.word_type) == X64TailRegisterBank::Gpr)
            .count(),
        "audited GPR region live",
    )?;
    let xmm_peak = usize_to_u32(
        region_locations.len().saturating_sub(gpr_peak as usize),
        "audited XMM region live",
    )?;
    if values.keys().copied().collect::<BTreeSet<_>>() != expected_locations
        || region.logical_locations as usize != expected_locations.len()
        || region.interference_pairs as usize != pairs.len()
        || region.gpr_peak_live != gpr_peak
        || region.xmm_peak_live != xmm_peak
    {
        return Err(X64TailPhysicalAllocationError::InvalidField {
            field: "independent region facts",
        });
    }
    let mut degrees = BTreeMap::<X64TailWordLocation, u32>::new();
    for (left, right) in &pairs {
        *degrees.entry(*left).or_default() = degrees
            .get(left)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(X64TailPhysicalAllocationError::ArithmeticOverflow {
                field: "audited interference degree",
            })?;
        *degrees.entry(*right).or_default() = degrees
            .get(right)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(X64TailPhysicalAllocationError::ArithmeticOverflow {
                field: "audited interference degree",
            })?;
    }
    for value in &region.values {
        if value.occurrences != occurrences.get(&value.logical).copied().unwrap_or(0)
            || value.interference_degree != degrees.get(&value.logical).copied().unwrap_or(0)
            || value.physical.word_type() != value.logical.word_type
            || value.physical.bank() != word_bank(value.logical.word_type)
        {
            return Err(X64TailPhysicalAllocationError::InvalidField {
                field: "physical value facts",
            });
        }
        if let X64TailPhysicalLocation::Frame(frame) = value.physical {
            if frame != value.logical {
                return Err(X64TailPhysicalAllocationError::InvalidField {
                    field: "noncanonical spill home",
                });
            }
        }
    }
    for (left, right) in pairs {
        if let (
            X64TailPhysicalLocation::Register {
                register: left_register,
                ..
            },
            X64TailPhysicalLocation::Register {
                register: right_register,
                ..
            },
        ) = (values[&left].physical, values[&right].physical)
        {
            if left_register == right_register {
                return Err(X64TailPhysicalAllocationError::InterferenceViolation {
                    region: region.region,
                });
            }
        }
    }
    let register_count = region
        .values
        .iter()
        .filter(|value| matches!(value.physical, X64TailPhysicalLocation::Register { .. }))
        .count();
    if region.register_locations as usize != register_count
        || region.spilled_locations as usize != region.values.len().saturating_sub(register_count)
    {
        return Err(X64TailPhysicalAllocationError::InvalidField {
            field: "physical residency totals",
        });
    }
    Ok(())
}

fn audit_transition(
    transition: &X64TailPhysicalTransition,
    logical_edge: &X64TailEdgePlan,
    region: &X64TailPhysicalRegion,
) -> Result<(), X64TailPhysicalAllocationError> {
    if transition.edge_ordinal != logical_edge.ordinal || transition.region != region.region {
        return transition_error(logical_edge.ordinal, "transition identity mismatch");
    }
    let values = region
        .values
        .iter()
        .map(|value| (value.logical, value.physical))
        .collect::<BTreeMap<_, _>>();
    let expected = project_physical_assignments(logical_edge, &values, region.region)?;
    if transition.assignments != expected {
        return transition_error(
            logical_edge.ordinal,
            "physical assignment projection mismatch",
        );
    }
    replay_physical_schedule(
        logical_edge.ordinal,
        &transition.assignments,
        &transition.schedule,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PhysicalToken {
    Original(X64TailPhysicalLocation),
    Immediate(X64TailImmediateWord),
}

impl PhysicalToken {
    const fn word_type(self) -> X64TailWordType {
        match self {
            Self::Original(location) => location.word_type(),
            Self::Immediate(immediate) => immediate_word_type(immediate),
        }
    }
}

fn replay_physical_schedule(
    edge: u32,
    assignments: &[X64TailPhysicalAssignment],
    schedule: &[X64TailPhysicalStep],
) -> Result<(), X64TailPhysicalAllocationError> {
    let mut destination_storage = BTreeSet::new();
    let mut state = BTreeMap::<X64TailPhysicalStorage, PhysicalToken>::new();
    let mut expected = BTreeMap::new();
    let mut required_writes = BTreeSet::new();
    for assignment in assignments {
        if let X64TailPhysicalSource::Location(location) = assignment.source {
            let storage = physical_storage(location);
            if let Some(existing) = state.get(&storage) {
                if existing.word_type() != location.word_type() {
                    return transition_error(edge, "cross-typed physical source storage alias");
                }
            } else {
                state.insert(storage, PhysicalToken::Original(location));
            }
        }
    }
    for assignment in assignments {
        if assignment.source.word_type() != assignment.destination.word_type() {
            return transition_error(edge, "physical assignment type mismatch");
        }
        let destination_key = physical_storage(assignment.destination);
        if !destination_storage.insert(destination_key) {
            return transition_error(edge, "duplicate physical destination storage");
        }
        state
            .entry(destination_key)
            .or_insert(PhysicalToken::Original(assignment.destination));
        let token = match assignment.source {
            X64TailPhysicalSource::Location(location) => state
                .get(&physical_storage(location))
                .copied()
                .ok_or(X64TailPhysicalAllocationError::TransitionMismatch {
                    edge,
                    reason: "initial physical source storage unavailable",
                })?,
            X64TailPhysicalSource::Immediate(immediate) => PhysicalToken::Immediate(immediate),
        };
        expected.insert(assignment.destination, token);
        if !matches!(assignment.source, X64TailPhysicalSource::Location(source) if source == assignment.destination)
        {
            required_writes.insert(assignment.destination);
        }
    }
    let mut scratch = BTreeMap::<X64TailScratchRegister, PhysicalToken>::new();
    let mut writes = BTreeSet::new();
    for step in schedule {
        match *step {
            X64TailPhysicalStep::SaveScratch {
                source,
                scratch: scratch_register,
            } => {
                if source.bank() != scratch_register.bank() {
                    return transition_error(edge, "scratch bank mismatch");
                }
                let value = state.get(&physical_storage(source)).copied().ok_or(
                    X64TailPhysicalAllocationError::TransitionMismatch {
                        edge,
                        reason: "scratch source unavailable",
                    },
                )?;
                if value.word_type() != source.word_type() {
                    return transition_error(edge, "scratch source storage type mismatch");
                }
                scratch.insert(scratch_register, value);
            }
            X64TailPhysicalStep::Move {
                source,
                destination,
            } => {
                if source.word_type() != destination.word_type() {
                    return transition_error(edge, "physical move type mismatch");
                }
                if !destination_storage.contains(&physical_storage(destination))
                    || !writes.insert(destination)
                {
                    return transition_error(edge, "physical move write coverage mismatch");
                }
                let value = match source {
                    X64TailPhysicalScheduledSource::Location(location) => state
                        .get(&physical_storage(location))
                        .copied()
                        .ok_or(X64TailPhysicalAllocationError::TransitionMismatch {
                            edge,
                            reason: "physical move source unavailable",
                        })?,
                    X64TailPhysicalScheduledSource::Immediate(immediate) => {
                        PhysicalToken::Immediate(immediate)
                    }
                    X64TailPhysicalScheduledSource::Scratch {
                        register,
                        word_type,
                    } => {
                        if register.bank() != word_bank(word_type) {
                            return transition_error(edge, "scratch read bank mismatch");
                        }
                        scratch.get(&register).copied().ok_or(
                            X64TailPhysicalAllocationError::TransitionMismatch {
                                edge,
                                reason: "stale scratch read",
                            },
                        )?
                    }
                };
                if value.word_type() != destination.word_type() {
                    return transition_error(edge, "physical token type mismatch");
                }
                state.insert(physical_storage(destination), value);
            }
        }
    }
    if writes != required_writes {
        return transition_error(edge, "physical schedule misses a destination");
    }
    for (destination, token) in expected {
        if state.get(&physical_storage(destination)) != Some(&token) {
            return transition_error(edge, "physical snapshot refinement mismatch");
        }
    }
    Ok(())
}

fn compute_totals(
    regions: &[X64TailPhysicalRegion],
    transitions: &[X64TailPhysicalTransition],
    allocation_work: u64,
) -> Result<X64TailPhysicalTotals, X64TailPhysicalAllocationError> {
    let mut totals = X64TailPhysicalTotals {
        regions: usize_to_u32(regions.len(), "physical regions")?,
        transitions: usize_to_u32(transitions.len(), "physical transitions")?,
        allocation_work,
        ..X64TailPhysicalTotals::default()
    };
    for region in regions {
        match region.disposition {
            X64TailPhysicalRegionDisposition::Allocated => {
                totals.allocated_regions =
                    checked_add_u32(totals.allocated_regions, 1, "allocated region total")?;
            }
            X64TailPhysicalRegionDisposition::Refused { .. } => {
                totals.refused_regions =
                    checked_add_u32(totals.refused_regions, 1, "refused region total")?;
            }
        }
        totals.logical_locations = checked_add_u64(
            totals.logical_locations,
            u64::from(region.logical_locations),
            "logical location total",
        )?;
        totals.register_locations = checked_add_u64(
            totals.register_locations,
            u64::from(region.register_locations),
            "register location total",
        )?;
        totals.spilled_locations = checked_add_u64(
            totals.spilled_locations,
            u64::from(region.spilled_locations),
            "spilled location total",
        )?;
        totals.interference_pairs = checked_add_u64(
            totals.interference_pairs,
            u64::from(region.interference_pairs),
            "interference pair total",
        )?;
    }
    for transition in transitions {
        for step in &transition.schedule {
            match *step {
                X64TailPhysicalStep::SaveScratch { source, .. } => {
                    totals.scratch_saves =
                        checked_add_u64(totals.scratch_saves, 1, "scratch save total")?;
                    if matches!(source, X64TailPhysicalLocation::Frame(_)) {
                        totals.frame_loads =
                            checked_add_u64(totals.frame_loads, 1, "frame load total")?;
                    }
                }
                X64TailPhysicalStep::Move {
                    source,
                    destination,
                } => {
                    totals.physical_moves =
                        checked_add_u64(totals.physical_moves, 1, "physical move total")?;
                    match source {
                        X64TailPhysicalScheduledSource::Location(
                            X64TailPhysicalLocation::Frame(_),
                        ) => {
                            totals.frame_loads =
                                checked_add_u64(totals.frame_loads, 1, "frame load total")?;
                        }
                        X64TailPhysicalScheduledSource::Immediate(_) => {
                            totals.immediate_materializations = checked_add_u64(
                                totals.immediate_materializations,
                                1,
                                "immediate materialization total",
                            )?;
                        }
                        X64TailPhysicalScheduledSource::Location(
                            X64TailPhysicalLocation::Register { .. },
                        )
                        | X64TailPhysicalScheduledSource::Scratch { .. } => {}
                    }
                    if matches!(destination, X64TailPhysicalLocation::Frame(_)) {
                        totals.frame_stores =
                            checked_add_u64(totals.frame_stores, 1, "frame store total")?;
                    }
                }
            }
        }
    }
    let operations = totals
        .physical_moves
        .checked_add(totals.scratch_saves)
        .ok_or(X64TailPhysicalAllocationError::ArithmeticOverflow {
            field: "physical operations",
        })?;
    totals.machine_byte_upper_bound = operations
        .checked_mul(u64::from(X64_TAIL_PHYSICAL_MAX_BYTES_PER_OPERATION))
        .and_then(|bytes| {
            bytes.checked_add(
                u64::from(totals.transitions).checked_mul(TAIL_BRANCH_BYTE_UPPER_BOUND)?,
            )
        })
        .ok_or(X64TailPhysicalAllocationError::ArithmeticOverflow {
            field: "physical byte upper bound",
        })?;
    Ok(totals)
}

fn validate_envelope(
    allocation: &X64TailPhysicalAllocation,
    logical: &X64TailStatePlan,
    target_semantic_hash: SemanticHash,
) -> Result<(), X64TailPhysicalAllocationError> {
    if allocation.schema_version != X64_TAIL_PHYSICAL_SCHEMA_VERSION {
        return Err(X64TailPhysicalAllocationError::InvalidField {
            field: "schema version",
        });
    }
    if allocation.policy_version != X64_TAIL_PHYSICAL_POLICY_VERSION {
        return Err(X64TailPhysicalAllocationError::InvalidField {
            field: "policy version",
        });
    }
    if allocation.source_target_semantic_hash != target_semantic_hash
        || allocation.source_logical_plan_hash != logical.plan_hash()
    {
        return Err(X64TailPhysicalAllocationError::InvalidField {
            field: "source identity",
        });
    }
    if allocation
        .regions
        .iter()
        .enumerate()
        .any(|(index, region)| region.region as usize != index)
    {
        return Err(X64TailPhysicalAllocationError::InvalidField {
            field: "region ordering",
        });
    }
    if allocation
        .transitions
        .windows(2)
        .any(|pair| pair[0].edge_ordinal >= pair[1].edge_ordinal)
    {
        return Err(X64TailPhysicalAllocationError::InvalidField {
            field: "transition ordering",
        });
    }
    let steps = allocation
        .transitions
        .iter()
        .try_fold(0_usize, |total, transition| {
            total.checked_add(transition.schedule.len()).ok_or(
                X64TailPhysicalAllocationError::ArithmeticOverflow {
                    field: "verified physical steps",
                },
            )
        })?;
    ensure_limit(
        "physical transition steps",
        X64_TAIL_PHYSICAL_MAX_TRANSITION_STEPS,
        steps,
    )?;
    Ok(())
}

fn edge_region(edge: &X64TailEdgePlan) -> Option<u32> {
    match edge.disposition {
        X64TailEdgeDisposition::Persistent { region } => Some(region),
        X64TailEdgeDisposition::Materialize { .. } | X64TailEdgeDisposition::Refused { .. } => None,
    }
}

const GPR_REGISTERS: [X64TailPhysicalRegister; 5] = [
    X64TailPhysicalRegister::Rdi,
    X64TailPhysicalRegister::Rsi,
    X64TailPhysicalRegister::R9,
    X64TailPhysicalRegister::R10,
    X64TailPhysicalRegister::R11,
];
const XMM_REGISTERS: [X64TailPhysicalRegister; 5] = [
    X64TailPhysicalRegister::Xmm3,
    X64TailPhysicalRegister::Xmm4,
    X64TailPhysicalRegister::Xmm5,
    X64TailPhysicalRegister::Xmm6,
    X64TailPhysicalRegister::Xmm7,
];

const fn registers_for_bank(bank: X64TailRegisterBank) -> &'static [X64TailPhysicalRegister; 5] {
    match bank {
        X64TailRegisterBank::Gpr => &GPR_REGISTERS,
        X64TailRegisterBank::Xmm => &XMM_REGISTERS,
    }
}

const fn scratch_for_bank(bank: X64TailRegisterBank) -> X64TailScratchRegister {
    match bank {
        X64TailRegisterBank::Gpr => X64TailScratchRegister::Rax,
        X64TailRegisterBank::Xmm => X64TailScratchRegister::Xmm0,
    }
}

const fn word_bank(word_type: X64TailWordType) -> X64TailRegisterBank {
    match word_type {
        X64TailWordType::Bool
        | X64TailWordType::I64
        | X64TailWordType::ArrayData
        | X64TailWordType::ArrayLength => X64TailRegisterBank::Gpr,
        X64TailWordType::F64 => X64TailRegisterBank::Xmm,
    }
}

const fn immediate_word_type(immediate: X64TailImmediateWord) -> X64TailWordType {
    match immediate {
        X64TailImmediateWord::Bool(_) => X64TailWordType::Bool,
        X64TailImmediateWord::I64(_) => X64TailWordType::I64,
        X64TailImmediateWord::F64Bits(_) => X64TailWordType::F64,
    }
}

fn increment_occurrence(
    occurrences: &mut BTreeMap<X64TailWordLocation, u32>,
    location: X64TailWordLocation,
) -> Result<(), X64TailPhysicalAllocationError> {
    let count = occurrences.entry(location).or_default();
    *count = count
        .checked_add(1)
        .ok_or(X64TailPhysicalAllocationError::ArithmeticOverflow {
            field: "logical location occurrence",
        })?;
    Ok(())
}

fn charge(
    work: &mut u64,
    amount: u64,
    field: &'static str,
) -> Result<(), X64TailPhysicalAllocationError> {
    *work = work
        .checked_add(amount)
        .ok_or(X64TailPhysicalAllocationError::ArithmeticOverflow { field })?;
    if *work > X64_TAIL_PHYSICAL_MAX_ALLOCATION_WORK {
        return Err(X64TailPhysicalAllocationError::LimitExceeded {
            field: "allocation work",
            limit: X64_TAIL_PHYSICAL_MAX_ALLOCATION_WORK,
            actual: *work,
        });
    }
    Ok(())
}

fn ensure_limit(
    field: &'static str,
    limit: u32,
    actual: usize,
) -> Result<(), X64TailPhysicalAllocationError> {
    let actual =
        u64::try_from(actual).map_err(|_| X64TailPhysicalAllocationError::ArithmeticOverflow {
            field: "limit conversion",
        })?;
    if actual > u64::from(limit) {
        Err(X64TailPhysicalAllocationError::LimitExceeded {
            field,
            limit: u64::from(limit),
            actual,
        })
    } else {
        Ok(())
    }
}

fn usize_to_u32(value: usize, field: &'static str) -> Result<u32, X64TailPhysicalAllocationError> {
    u32::try_from(value).map_err(|_| X64TailPhysicalAllocationError::ArithmeticOverflow { field })
}

fn checked_add_u32(
    left: u32,
    right: u32,
    field: &'static str,
) -> Result<u32, X64TailPhysicalAllocationError> {
    left.checked_add(right)
        .ok_or(X64TailPhysicalAllocationError::ArithmeticOverflow { field })
}

fn checked_add_u64(
    left: u64,
    right: u64,
    field: &'static str,
) -> Result<u64, X64TailPhysicalAllocationError> {
    left.checked_add(right)
        .ok_or(X64TailPhysicalAllocationError::ArithmeticOverflow { field })
}

fn transition_error<T>(
    edge: u32,
    reason: &'static str,
) -> Result<T, X64TailPhysicalAllocationError> {
    Err(X64TailPhysicalAllocationError::TransitionMismatch { edge, reason })
}

fn allocation_bytes_without_seal(
    allocation: &X64TailPhysicalAllocation,
) -> Result<Vec<u8>, X64TailPhysicalAllocationError> {
    let mut encoder = AllocationEncoder::new();
    encoder.bytes(ALLOCATION_DOMAIN)?;
    encoder.version(allocation.schema_version)?;
    encoder.version(allocation.policy_version)?;
    encoder.hash(allocation.source_target_semantic_hash)?;
    encoder.hash(allocation.source_logical_plan_hash)?;
    encoder.len(allocation.regions.len())?;
    for region in &allocation.regions {
        encoder.u32(region.region)?;
        encoder.len(region.edge_ordinals.len())?;
        for ordinal in &region.edge_ordinals {
            encoder.u32(*ordinal)?;
        }
        encoder.u32(region.logical_locations)?;
        encoder.u32(region.interference_pairs)?;
        encoder.u32(region.gpr_peak_live)?;
        encoder.u32(region.xmm_peak_live)?;
        encoder.u32(region.register_locations)?;
        encoder.u32(region.spilled_locations)?;
        encoder.len(region.values.len())?;
        for value in &region.values {
            encode_word_location(&mut encoder, value.logical)?;
            encode_physical_location(&mut encoder, value.physical)?;
            encoder.u32(value.occurrences)?;
            encoder.u32(value.interference_degree)?;
        }
        match region.disposition {
            X64TailPhysicalRegionDisposition::Allocated => encoder.u8(0)?,
            X64TailPhysicalRegionDisposition::Refused { reason } => {
                encoder.u8(1)?;
                encoder.u8(match reason {
                    X64TailPhysicalRefusalReason::LocationBudget => 0,
                })?;
            }
        }
    }
    encoder.len(allocation.transitions.len())?;
    for transition in &allocation.transitions {
        encoder.u32(transition.edge_ordinal)?;
        encoder.u32(transition.region)?;
        encoder.len(transition.assignments.len())?;
        for assignment in &transition.assignments {
            encode_physical_source(&mut encoder, assignment.source)?;
            encode_physical_location(&mut encoder, assignment.destination)?;
        }
        encoder.len(transition.schedule.len())?;
        for step in &transition.schedule {
            match *step {
                X64TailPhysicalStep::SaveScratch { source, scratch } => {
                    encoder.u8(0)?;
                    encode_physical_location(&mut encoder, source)?;
                    encoder.u8(scratch_tag(scratch))?;
                }
                X64TailPhysicalStep::Move {
                    source,
                    destination,
                } => {
                    encoder.u8(1)?;
                    encode_scheduled_source(&mut encoder, source)?;
                    encode_physical_location(&mut encoder, destination)?;
                }
            }
        }
    }
    encode_totals(&mut encoder, allocation.totals)?;
    Ok(encoder.finish())
}

fn encode_word_location(
    encoder: &mut AllocationEncoder,
    location: X64TailWordLocation,
) -> Result<(), X64TailPhysicalAllocationError> {
    encoder.u32(location.offset)?;
    encoder.u8(word_type_tag(location.word_type))
}

fn encode_physical_location(
    encoder: &mut AllocationEncoder,
    location: X64TailPhysicalLocation,
) -> Result<(), X64TailPhysicalAllocationError> {
    match location {
        X64TailPhysicalLocation::Register {
            register,
            word_type,
        } => {
            encoder.u8(0)?;
            encoder.u8(register_tag(register))?;
            encoder.u8(word_type_tag(word_type))
        }
        X64TailPhysicalLocation::Frame(location) => {
            encoder.u8(1)?;
            encode_word_location(encoder, location)
        }
    }
}

fn encode_physical_source(
    encoder: &mut AllocationEncoder,
    source: X64TailPhysicalSource,
) -> Result<(), X64TailPhysicalAllocationError> {
    match source {
        X64TailPhysicalSource::Location(location) => {
            encoder.u8(0)?;
            encode_physical_location(encoder, location)
        }
        X64TailPhysicalSource::Immediate(immediate) => {
            encoder.u8(1)?;
            encode_immediate(encoder, immediate)
        }
    }
}

fn encode_scheduled_source(
    encoder: &mut AllocationEncoder,
    source: X64TailPhysicalScheduledSource,
) -> Result<(), X64TailPhysicalAllocationError> {
    match source {
        X64TailPhysicalScheduledSource::Location(location) => {
            encoder.u8(0)?;
            encode_physical_location(encoder, location)
        }
        X64TailPhysicalScheduledSource::Immediate(immediate) => {
            encoder.u8(1)?;
            encode_immediate(encoder, immediate)
        }
        X64TailPhysicalScheduledSource::Scratch {
            register,
            word_type,
        } => {
            encoder.u8(2)?;
            encoder.u8(scratch_tag(register))?;
            encoder.u8(word_type_tag(word_type))
        }
    }
}

fn encode_immediate(
    encoder: &mut AllocationEncoder,
    immediate: X64TailImmediateWord,
) -> Result<(), X64TailPhysicalAllocationError> {
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

fn encode_totals(
    encoder: &mut AllocationEncoder,
    totals: X64TailPhysicalTotals,
) -> Result<(), X64TailPhysicalAllocationError> {
    encoder.u32(totals.regions)?;
    encoder.u32(totals.allocated_regions)?;
    encoder.u32(totals.refused_regions)?;
    encoder.u64(totals.logical_locations)?;
    encoder.u64(totals.register_locations)?;
    encoder.u64(totals.spilled_locations)?;
    encoder.u64(totals.interference_pairs)?;
    encoder.u32(totals.transitions)?;
    encoder.u64(totals.physical_moves)?;
    encoder.u64(totals.scratch_saves)?;
    encoder.u64(totals.frame_loads)?;
    encoder.u64(totals.frame_stores)?;
    encoder.u64(totals.immediate_materializations)?;
    encoder.u64(totals.machine_byte_upper_bound)?;
    encoder.u64(totals.allocation_work)
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

const fn scratch_tag(register: X64TailScratchRegister) -> u8 {
    match register {
        X64TailScratchRegister::Rax => 0,
        X64TailScratchRegister::Xmm0 => 1,
    }
}

struct AllocationEncoder {
    bytes: Vec<u8>,
}

impl AllocationEncoder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn reserve(&mut self, additional: usize) -> Result<(), X64TailPhysicalAllocationError> {
        let actual = self.bytes.len().checked_add(additional).ok_or(
            X64TailPhysicalAllocationError::ArithmeticOverflow {
                field: "allocation encoding length",
            },
        )?;
        if actual > MAX_ALLOCATION_BYTES {
            return Err(X64TailPhysicalAllocationError::EncodingLimit { actual });
        }
        self.bytes
            .try_reserve(additional)
            .map_err(|_| X64TailPhysicalAllocationError::EncodingLimit { actual })
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), X64TailPhysicalAllocationError> {
        self.reserve(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), X64TailPhysicalAllocationError> {
        self.bytes(&[value])
    }

    fn u32(&mut self, value: u32) -> Result<(), X64TailPhysicalAllocationError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), X64TailPhysicalAllocationError> {
        self.bytes(&value.to_le_bytes())
    }

    fn len(&mut self, value: usize) -> Result<(), X64TailPhysicalAllocationError> {
        self.u32(usize_to_u32(
            value,
            "allocation encoding collection length",
        )?)
    }

    fn version(&mut self, version: (u16, u16, u16)) -> Result<(), X64TailPhysicalAllocationError> {
        self.bytes(&version.0.to_le_bytes())?;
        self.bytes(&version.1.to_le_bytes())?;
        self.bytes(&version.2.to_le_bytes())
    }

    fn hash(&mut self, hash: SemanticHash) -> Result<(), X64TailPhysicalAllocationError> {
        self.bytes(&hash.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::corevm0_gate_a::CoreVmGateAWorkload;
    use crate::core::x64_native_lighthouse::X64NativeLighthousePackage;
    use crate::core::{emit_x64_tail_state_plan, X64_TARGET_ENCODER_POLICY_VERSION};

    fn word(offset: u32, word_type: X64TailWordType) -> X64TailWordLocation {
        X64TailWordLocation { offset, word_type }
    }

    fn register(
        register: X64TailPhysicalRegister,
        word_type: X64TailWordType,
    ) -> X64TailPhysicalLocation {
        X64TailPhysicalLocation::Register {
            register,
            word_type,
        }
    }

    fn physical_assignment(
        source: X64TailPhysicalLocation,
        destination: X64TailPhysicalLocation,
    ) -> X64TailPhysicalAssignment {
        X64TailPhysicalAssignment {
            source: X64TailPhysicalSource::Location(source),
            destination,
        }
    }

    #[test]
    fn physical_scheduler_replays_register_frame_immediate_and_both_bank_cycles() {
        let rdi = register(X64TailPhysicalRegister::Rdi, X64TailWordType::I64);
        let rsi = register(X64TailPhysicalRegister::Rsi, X64TailWordType::I64);
        let frame = X64TailPhysicalLocation::Frame(word(32, X64TailWordType::I64));
        let xmm3 = register(X64TailPhysicalRegister::Xmm3, X64TailWordType::F64);
        let xmm4 = register(X64TailPhysicalRegister::Xmm4, X64TailWordType::F64);
        let assignments = vec![
            physical_assignment(rdi, rsi),
            physical_assignment(rsi, rdi),
            physical_assignment(
                frame,
                register(X64TailPhysicalRegister::R9, X64TailWordType::I64),
            ),
            X64TailPhysicalAssignment {
                source: X64TailPhysicalSource::Immediate(X64TailImmediateWord::I64(17)),
                destination: frame,
            },
            physical_assignment(xmm3, xmm4),
            physical_assignment(xmm4, xmm3),
        ];
        let schedule = schedule_physical_copy(&assignments).expect("physical schedule must emit");
        assert!(schedule.iter().any(|step| matches!(
            step,
            X64TailPhysicalStep::SaveScratch {
                scratch: X64TailScratchRegister::Rax,
                ..
            }
        )));
        assert!(schedule.iter().any(|step| matches!(
            step,
            X64TailPhysicalStep::SaveScratch {
                scratch: X64TailScratchRegister::Xmm0,
                ..
            }
        )));
        replay_physical_schedule(0, &assignments, &schedule)
            .expect("mixed physical snapshot must replay");
    }

    #[test]
    fn physical_frame_aliases_preserve_the_source_before_a_typed_overwrite() {
        let source_length = X64TailPhysicalLocation::Frame(word(40, X64TailWordType::ArrayLength));
        let overwritten_state = X64TailPhysicalLocation::Frame(word(72, X64TailWordType::I64));
        let destination_length =
            X64TailPhysicalLocation::Frame(word(72, X64TailWordType::ArrayLength));
        let destination_state = X64TailPhysicalLocation::Frame(word(80, X64TailWordType::I64));
        let assignments = vec![
            physical_assignment(source_length, destination_length),
            physical_assignment(overwritten_state, destination_state),
        ];
        let schedule = schedule_physical_copy(&assignments)
            .expect("typed physical aliases must schedule by byte storage");
        assert!(matches!(
            schedule.first(),
            Some(X64TailPhysicalStep::Move {
                source: X64TailPhysicalScheduledSource::Location(X64TailPhysicalLocation::Frame(
                    X64TailWordLocation {
                        offset: 72,
                        word_type: X64TailWordType::I64,
                    }
                ),),
                destination: X64TailPhysicalLocation::Frame(X64TailWordLocation {
                    offset: 80,
                    word_type: X64TailWordType::I64,
                }),
            })
        ));
        replay_physical_schedule(0, &assignments, &schedule)
            .expect("physical byte aliases must preserve snapshot order");

        let mut reordered = schedule;
        reordered.reverse();
        assert!(matches!(
            replay_physical_schedule(0, &assignments, &reordered),
            Err(X64TailPhysicalAllocationError::TransitionMismatch { .. })
        ));
    }

    #[test]
    fn stale_scratch_wrong_bank_and_schedule_reordering_fail_closed() {
        let rdi = register(X64TailPhysicalRegister::Rdi, X64TailWordType::I64);
        let rsi = register(X64TailPhysicalRegister::Rsi, X64TailWordType::I64);
        let assignments = vec![physical_assignment(rdi, rsi)];
        let stale = vec![X64TailPhysicalStep::Move {
            source: X64TailPhysicalScheduledSource::Scratch {
                register: X64TailScratchRegister::Rax,
                word_type: X64TailWordType::I64,
            },
            destination: rsi,
        }];
        assert!(matches!(
            replay_physical_schedule(0, &assignments, &stale),
            Err(X64TailPhysicalAllocationError::TransitionMismatch { .. })
        ));

        let mut cycle = vec![physical_assignment(rdi, rsi), physical_assignment(rsi, rdi)];
        cycle.sort_by_key(|assignment| assignment.destination);
        let mut reordered = schedule_physical_copy(&cycle).expect("cycle must schedule");
        reordered.swap(0, 1);
        assert!(matches!(
            replay_physical_schedule(0, &cycle, &reordered),
            Err(X64TailPhysicalAllocationError::TransitionMismatch { .. })
        ));

        let wrong_bank = vec![X64TailPhysicalStep::SaveScratch {
            source: rdi,
            scratch: X64TailScratchRegister::Xmm0,
        }];
        assert!(matches!(
            replay_physical_schedule(0, &assignments, &wrong_bank),
            Err(X64TailPhysicalAllocationError::TransitionMismatch { .. })
        ));
    }

    #[test]
    fn physical_bank_is_finite_disjoint_and_location_budget_refuses_whole_region() {
        assert_eq!(GPR_REGISTERS.len(), X64_TAIL_PHYSICAL_GPR_LANES as usize);
        assert_eq!(XMM_REGISTERS.len(), X64_TAIL_PHYSICAL_XMM_LANES as usize);
        assert!(GPR_REGISTERS
            .iter()
            .all(|register| register.bank() == X64TailRegisterBank::Gpr));
        assert!(XMM_REGISTERS
            .iter()
            .all(|register| register.bank() == X64TailRegisterBank::Xmm));
        assert_eq!(X64TailScratchRegister::Rax.bank(), X64TailRegisterBank::Gpr);
        assert_eq!(
            X64TailScratchRegister::Xmm0.bank(),
            X64TailRegisterBank::Xmm
        );

        let locations = (0..=X64_TAIL_PHYSICAL_MAX_LOCATIONS_PER_REGION)
            .map(|index| word(index * 8, X64TailWordType::I64))
            .collect::<Vec<_>>();
        let facts = RegionFacts {
            occurrences: locations
                .iter()
                .copied()
                .map(|location| (location, 1))
                .collect(),
            interference: locations
                .iter()
                .copied()
                .map(|location| (location, BTreeSet::new()))
                .collect(),
            locations,
            interference_pairs: 0,
            gpr_peak_live: 1,
            xmm_peak_live: 0,
        };
        assert_eq!(
            region_refusal(&facts),
            Some(X64TailPhysicalRefusalReason::LocationBudget)
        );
    }

    #[test]
    fn branch_lighthouse_allocation_is_deterministic_and_resealed_mutations_fail() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("branch lighthouse must build");
        let logical = emit_x64_tail_state_plan(package.target()).expect("logical plan must emit");
        let first = emit_x64_tail_physical_allocation(package.target(), &logical)
            .expect("physical allocation must emit");
        let second = emit_x64_tail_physical_allocation(package.target(), &logical)
            .expect("physical allocation must replay");
        assert_eq!(first, second);
        assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
        assert_eq!(
            first.allocation_hash().to_hex(),
            "7153bd9997b4d2af85149ba172f3cd2a0d3a2d20d3d42c765742b5f3294841ae"
        );
        assert_eq!(
            first.totals(),
            X64TailPhysicalTotals {
                regions: 31,
                allocated_regions: 31,
                refused_regions: 0,
                logical_locations: 346,
                register_locations: 176,
                spilled_locations: 170,
                interference_pairs: 1_675,
                transitions: 108,
                physical_moves: 150,
                scratch_saves: 0,
                frame_loads: 61,
                frame_stores: 100,
                immediate_materializations: 17,
                machine_byte_upper_bound: 2_790,
                allocation_work: 3_745,
            }
        );
        assert_eq!(first.totals.refused_regions, 0);
        assert!(first.totals.register_locations > 0);
        assert!(first.totals.transitions > 0);
        verify_x64_tail_physical_allocation(&first, &logical, package.target())
            .expect("physical allocation must independently verify");
        let mut wrong_total = first.clone();
        wrong_total.totals.frame_loads = wrong_total.totals.frame_loads.saturating_add(1);
        wrong_total.allocation_hash = x64_tail_physical_allocation_hash(&wrong_total)
            .expect("total mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_physical_allocation(&wrong_total, &logical, package.target()),
            Err(X64TailPhysicalAllocationError::ReplayMismatch)
        ));

        let mut wrong_source = first.clone();
        wrong_source.source_logical_plan_hash.0[0] ^= 1;
        wrong_source.allocation_hash = x64_tail_physical_allocation_hash(&wrong_source)
            .expect("source mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_physical_allocation(&wrong_source, &logical, package.target()),
            Err(X64TailPhysicalAllocationError::InvalidField {
                field: "source identity"
            })
        ));

        let mut missing_step = first.clone();
        let transition = missing_step
            .transitions
            .iter_mut()
            .find(|transition| !transition.schedule.is_empty())
            .expect("lighthouse must have a physical move");
        transition.schedule.remove(0);
        missing_step.allocation_hash = x64_tail_physical_allocation_hash(&missing_step)
            .expect("schedule mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_physical_allocation(&missing_step, &logical, package.target()),
            Err(X64TailPhysicalAllocationError::TransitionMismatch { .. })
        ));

        let mut alias = first.clone();
        let mut selected = None;
        for edge in logical.edges() {
            let Some(region_id) = edge_region(edge) else {
                continue;
            };
            let live = edge
                .assignments
                .iter()
                .flat_map(|assignment| {
                    let mut locations = vec![assignment.destination];
                    if let X64TailWordSource::Location(source) = assignment.source {
                        locations.push(source);
                    }
                    locations
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            for left in 0..live.len() {
                for right in left.saturating_add(1)..live.len() {
                    if word_bank(live[left].word_type) != word_bank(live[right].word_type) {
                        continue;
                    }
                    let region = &alias.regions[region_id as usize];
                    let left_index = region
                        .values
                        .iter()
                        .position(|value| value.logical == live[left]);
                    let right_index = region
                        .values
                        .iter()
                        .position(|value| value.logical == live[right]);
                    let (Some(left_index), Some(right_index)) = (left_index, right_index) else {
                        continue;
                    };
                    let X64TailPhysicalLocation::Register { register, .. } =
                        region.values[left_index].physical
                    else {
                        continue;
                    };
                    if !matches!(
                        region.values[right_index].physical,
                        X64TailPhysicalLocation::Register { .. }
                    ) {
                        continue;
                    }
                    selected = Some((region_id as usize, right_index, register));
                    break;
                }
                if selected.is_some() {
                    break;
                }
            }
            if selected.is_some() {
                break;
            }
        }
        let (region_index, value_index, register) =
            selected.expect("lighthouse must have two interfering registered locations");
        let word_type = alias.regions[region_index].values[value_index]
            .logical
            .word_type;
        alias.regions[region_index].values[value_index].physical =
            X64TailPhysicalLocation::Register {
                register,
                word_type,
            };
        alias.allocation_hash = x64_tail_physical_allocation_hash(&alias)
            .expect("interference mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_physical_allocation(&alias, &logical, package.target()),
            Err(X64TailPhysicalAllocationError::InterferenceViolation { .. })
        ));
    }

    #[test]
    fn bounds_lighthouse_allocation_remains_proof_only_and_complete() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BoundsOrderedArrayGet)
            .expect("Bounds lighthouse must build");
        let logical = emit_x64_tail_state_plan(package.target()).expect("logical plan must emit");
        let allocation = emit_x64_tail_physical_allocation(package.target(), &logical)
            .expect("Bounds allocation must emit");
        verify_x64_tail_physical_allocation(&allocation, &logical, package.target())
            .expect("Bounds allocation must independently replay");
        let expected = logical.totals().persistent_edges;
        assert_eq!(allocation.totals().transitions, expected);
        assert_eq!(allocation.totals().refused_regions, 0);
        assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
    }
}
