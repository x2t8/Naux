//! Proof-only ADR-0059 preservation census and symbolic x86-64 template
//! realization for ADR-0058 physical tail transitions.
//!
//! The artifact deliberately contains no raw bytes and grants no execution
//! authority. It makes instruction clobbers, physical scratch use, exact
//! prospective template lengths, and rel32 fixups independently replayable.

use super::encoding::sha256;
use super::machine_ir::MachineType;
use super::schema::SemanticHash;
use super::x64_tail_state_allocation::{
    verify_x64_tail_physical_allocation, X64TailPhysicalAllocation, X64TailPhysicalAllocationError,
    X64TailPhysicalLocation, X64TailPhysicalRegionDisposition, X64TailPhysicalRegister,
    X64TailPhysicalScheduledSource, X64TailPhysicalSource, X64TailPhysicalStep,
    X64TailPhysicalTransition, X64TailScratchRegister,
};
use super::x64_tail_state_plan::{
    X64TailEdgeDisposition, X64TailImmediateWord, X64TailStatePlan, X64TailWordLocation,
    X64TailWordType,
};
use super::x64_target::{
    X64BlockId, X64FunctionId, X64InstructionKind, X64LabelId, X64TargetArtifact, X64TargetProgram,
    X64Terminator,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const X64_TAIL_TEMPLATE_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_TEMPLATE_POLICY_VERSION: (u16, u16, u16) = (1, 2, 0);
pub const X64_TAIL_TEMPLATE_MAX_SITES: u32 = 1_000_000;
pub const X64_TAIL_TEMPLATE_MAX_TRANSITIONS: u32 = 4_096;
pub const X64_TAIL_TEMPLATE_MAX_ATOMS: u32 = 65_536;
pub const X64_TAIL_TEMPLATE_MAX_FIXUPS: u32 = 4_096;
pub const X64_TAIL_TEMPLATE_MAX_LAYOUT_BYTES: u64 = 64 * 1024 * 1024;
pub const X64_TAIL_TEMPLATE_MAX_REPLAY_WORK: u64 = 2_000_000;

const REALIZATION_DOMAIN: &[u8] = b"NAUX:x86-64:tail-template-realization:v1\0";
const MAX_REALIZATION_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum X64TailTemplateRegister {
    Rax,
    Rcx,
    Rdx,
    Rdi,
    Rsi,
    R8,
    R9,
    R10,
    R11,
    Xmm0,
    Xmm1,
    Xmm2,
    Xmm3,
    Xmm4,
    Xmm5,
    Xmm6,
    Xmm7,
    Flags,
}

impl X64TailTemplateRegister {
    pub const fn is_persistent(self) -> bool {
        matches!(
            self,
            Self::Rdi
                | Self::Rsi
                | Self::R9
                | Self::R10
                | Self::R11
                | Self::Xmm3
                | Self::Xmm4
                | Self::Xmm5
                | Self::Xmm6
                | Self::Xmm7
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum X64TailProgramTemplateKind {
    MoveScalar,
    MoveF64,
    MoveArrayPair,
    I64Wrapping,
    Sse2F64,
    I64Setcc,
    ArrayLenF64,
    ArrayGetF64Checked,
    BranchCondition,
    BranchElseRel32,
    PersistentTailTransition,
    MaterializedTailFrontier,
    RefusedTailFrontier,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum X64TailTemplateSitePosition {
    Instruction(u32),
    BranchCondition,
    BranchElse,
    TailTransition { edge_ordinal: u32 },
    TailFrontier { edge_ordinal: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailPreservationSite {
    pub region: u32,
    pub function: X64FunctionId,
    pub block: X64BlockId,
    pub label: X64LabelId,
    pub position: X64TailTemplateSitePosition,
    pub template: X64TailProgramTemplateKind,
    pub clobbers: Vec<X64TailTemplateRegister>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum X64TailTemplateGpr {
    Rax,
    Rcx,
    Rdi,
    Rsi,
    R9,
    R10,
    R11,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum X64TailTemplateXmm {
    Xmm0,
    Xmm1,
    Xmm3,
    Xmm4,
    Xmm5,
    Xmm6,
    Xmm7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailTemplateInstruction {
    GprCopy {
        source: X64TailTemplateGpr,
        destination: X64TailTemplateGpr,
        word_type: X64TailWordType,
    },
    GprFrameLoad {
        source: X64TailWordLocation,
        destination: X64TailTemplateGpr,
    },
    GprFrameStore {
        source: X64TailTemplateGpr,
        destination: X64TailWordLocation,
    },
    XmmCopy {
        source: X64TailTemplateXmm,
        destination: X64TailTemplateXmm,
    },
    XmmFrameLoad {
        source: X64TailWordLocation,
        destination: X64TailTemplateXmm,
    },
    XmmFrameStore {
        source: X64TailTemplateXmm,
        destination: X64TailWordLocation,
    },
    GprImmediate {
        immediate: X64TailImmediateWord,
        destination: X64TailTemplateGpr,
    },
    GprBitsToXmm {
        source: X64TailTemplateGpr,
        destination: X64TailTemplateXmm,
    },
    TailJumpRel32 {
        target: X64LabelId,
    },
}

impl X64TailTemplateInstruction {
    pub const fn byte_len(self) -> u32 {
        match self {
            Self::GprCopy { .. } => 3,
            Self::GprFrameLoad { .. } | Self::GprFrameStore { .. } => 8,
            Self::XmmCopy { .. } => 4,
            Self::XmmFrameLoad { .. } | Self::XmmFrameStore { .. } => 9,
            Self::GprImmediate { .. } => 10,
            Self::GprBitsToXmm { .. } | Self::TailJumpRel32 { .. } => 5,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailTemplateAtom {
    pub ordinal: u32,
    pub start: u32,
    pub end: u32,
    pub instruction: X64TailTemplateInstruction,
    pub clobbers: Vec<X64TailTemplateRegister>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailTemplateFixup {
    pub atom_ordinal: u32,
    pub patch_offset: u32,
    pub target: X64LabelId,
    pub width: u8,
    pub addend: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailTemplateTransition {
    pub edge_ordinal: u32,
    pub region: u32,
    pub source_label: X64LabelId,
    pub target_label: X64LabelId,
    pub atoms: Vec<X64TailTemplateAtom>,
    pub fixups: Vec<X64TailTemplateFixup>,
    pub layout_bytes: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X64TailTemplateTotals {
    pub preservation_sites: u32,
    pub persistent_transitions: u32,
    pub template_atoms: u64,
    pub retained_fixups: u32,
    pub gpr_atoms: u64,
    pub xmm_atoms: u64,
    pub immediate_atoms: u64,
    pub frame_load_atoms: u64,
    pub frame_store_atoms: u64,
    pub prospective_layout_bytes: u64,
    pub max_transition_bytes: u32,
    pub replay_work: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailTemplateRealization {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    source_target_semantic_hash: SemanticHash,
    source_logical_plan_hash: SemanticHash,
    source_physical_allocation_hash: SemanticHash,
    sites: Vec<X64TailPreservationSite>,
    transitions: Vec<X64TailTemplateTransition>,
    totals: X64TailTemplateTotals,
    realization_hash: SemanticHash,
}

impl X64TailTemplateRealization {
    pub const fn source_target_semantic_hash(&self) -> SemanticHash {
        self.source_target_semantic_hash
    }

    pub const fn source_logical_plan_hash(&self) -> SemanticHash {
        self.source_logical_plan_hash
    }

    pub const fn source_physical_allocation_hash(&self) -> SemanticHash {
        self.source_physical_allocation_hash
    }

    pub fn sites(&self) -> &[X64TailPreservationSite] {
        &self.sites
    }

    pub fn transitions(&self) -> &[X64TailTemplateTransition] {
        &self.transitions
    }

    pub const fn totals(&self) -> X64TailTemplateTotals {
        self.totals
    }

    pub const fn realization_hash(&self) -> SemanticHash {
        self.realization_hash
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedX64TailTemplateRealization<'realization> {
    realization: &'realization X64TailTemplateRealization,
}

impl<'realization> VerifiedX64TailTemplateRealization<'realization> {
    pub const fn realization(self) -> &'realization X64TailTemplateRealization {
        self.realization
    }
}

#[derive(Debug)]
pub enum X64TailTemplateRealizationError {
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
    PersistentClobber {
        region: u32,
        label: X64LabelId,
        register: X64TailTemplateRegister,
    },
    TransitionMismatch {
        edge: u32,
        reason: &'static str,
    },
    RealizationHashMismatch,
    ReplayMismatch,
}

impl fmt::Display for X64TailTemplateRealizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Physical(error) => write!(formatter, "tail template input failed: {error}"),
            Self::InvalidField { field } => {
                write!(formatter, "tail template realization has invalid {field}")
            }
            Self::MissingTarget { field } => {
                write!(formatter, "tail template realization cannot resolve {field}")
            }
            Self::LimitExceeded {
                field,
                limit,
                actual,
            } => write!(
                formatter,
                "tail template realization {field} uses {actual}; limit is {limit}"
            ),
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "tail template realization overflowed {field}")
            }
            Self::EncodingLimit { actual } => write!(
                formatter,
                "tail template realization encoding uses {actual} bytes; limit is {MAX_REALIZATION_BYTES}"
            ),
            Self::PersistentClobber {
                region,
                label,
                register,
            } => write!(
                formatter,
                "tail region {region} label {} clobbers persistent register {register:?}",
                label.0
            ),
            Self::TransitionMismatch { edge, reason } => {
                write!(formatter, "tail template edge {edge} failed: {reason}")
            }
            Self::RealizationHashMismatch => {
                formatter.write_str("tail template realization seal does not replay")
            }
            Self::ReplayMismatch => {
                formatter.write_str("tail template realization differs from canonical replay")
            }
        }
    }
}

impl std::error::Error for X64TailTemplateRealizationError {}

impl From<X64TailPhysicalAllocationError> for X64TailTemplateRealizationError {
    fn from(value: X64TailPhysicalAllocationError) -> Self {
        Self::Physical(value)
    }
}

/// Derive a sealed proof-only template realization. No method in this module
/// emits raw bytes or exposes an executable witness.
pub fn emit_x64_tail_template_realization(
    target: &X64TargetArtifact,
    logical: &X64TailStatePlan,
    physical: &X64TailPhysicalAllocation,
) -> Result<X64TailTemplateRealization, X64TailTemplateRealizationError> {
    verify_x64_tail_physical_allocation(physical, logical, target)?;
    construct_realization(target, logical, physical)
}

/// Reverify every predecessor, preservation site, symbolic instruction
/// effect, exact layout/fixup, seal, and complete canonical regeneration.
pub fn verify_x64_tail_template_realization<'realization>(
    realization: &'realization X64TailTemplateRealization,
    physical: &X64TailPhysicalAllocation,
    logical: &X64TailStatePlan,
    target: &X64TargetArtifact,
) -> Result<VerifiedX64TailTemplateRealization<'realization>, X64TailTemplateRealizationError> {
    verify_x64_tail_physical_allocation(physical, logical, target)?;
    validate_envelope(realization, physical, logical, target)?;
    if x64_tail_template_realization_hash(realization)? != realization.realization_hash {
        return Err(X64TailTemplateRealizationError::RealizationHashMismatch);
    }
    audit_realization(realization, physical, logical, &target.program)?;
    let replayed = construct_realization(target, logical, physical)?;
    if replayed != *realization {
        return Err(X64TailTemplateRealizationError::ReplayMismatch);
    }
    Ok(VerifiedX64TailTemplateRealization { realization })
}

pub fn x64_tail_template_realization_hash(
    realization: &X64TailTemplateRealization,
) -> Result<SemanticHash, X64TailTemplateRealizationError> {
    Ok(SemanticHash(sha256(&realization_bytes_without_seal(
        realization,
    )?)))
}

fn construct_realization(
    target: &X64TargetArtifact,
    logical: &X64TailStatePlan,
    physical: &X64TailPhysicalAllocation,
) -> Result<X64TailTemplateRealization, X64TailTemplateRealizationError> {
    let sites = derive_preservation_sites(&target.program, logical, physical)?;
    let logical_edges = logical
        .edges()
        .iter()
        .map(|edge| (edge.ordinal, edge))
        .collect::<BTreeMap<_, _>>();
    let mut transitions = Vec::with_capacity(physical.transitions().len());
    for transition in physical.transitions() {
        let edge = logical_edges.get(&transition.edge_ordinal).ok_or(
            X64TailTemplateRealizationError::MissingTarget {
                field: "logical transition edge",
            },
        )?;
        transitions.push(lower_transition(
            transition,
            edge.source_label,
            edge.target_label,
        )?);
    }
    transitions.sort_by_key(|transition| transition.edge_ordinal);
    ensure_limit(
        "persistent transitions",
        X64_TAIL_TEMPLATE_MAX_TRANSITIONS,
        transitions.len(),
    )?;
    let totals = compute_totals(&sites, &transitions, physical)?;
    let mut realization = X64TailTemplateRealization {
        schema_version: X64_TAIL_TEMPLATE_SCHEMA_VERSION,
        policy_version: X64_TAIL_TEMPLATE_POLICY_VERSION,
        source_target_semantic_hash: target.semantic_hash,
        source_logical_plan_hash: logical.plan_hash(),
        source_physical_allocation_hash: physical.allocation_hash(),
        sites,
        transitions,
        totals,
        realization_hash: SemanticHash([0; 32]),
    };
    realization.realization_hash = x64_tail_template_realization_hash(&realization)?;
    Ok(realization)
}

fn derive_preservation_sites(
    program: &X64TargetProgram,
    logical: &X64TailStatePlan,
    physical: &X64TailPhysicalAllocation,
) -> Result<Vec<X64TailPreservationSite>, X64TailTemplateRealizationError> {
    let logical_regions = logical
        .regions()
        .iter()
        .map(|region| (region.id, region))
        .collect::<BTreeMap<_, _>>();
    let mut label_regions = BTreeMap::new();
    for region in physical.regions() {
        if region.disposition != X64TailPhysicalRegionDisposition::Allocated {
            continue;
        }
        let logical_region = logical_regions.get(&region.region).ok_or(
            X64TailTemplateRealizationError::MissingTarget {
                field: "logical region",
            },
        )?;
        for label in &logical_region.labels {
            if label_regions.insert(*label, region.region).is_some() {
                return Err(X64TailTemplateRealizationError::InvalidField {
                    field: "region label ownership",
                });
            }
        }
    }

    let edge_by_source = logical
        .edges()
        .iter()
        .map(|edge| ((edge.source_function, edge.source_block), edge))
        .collect::<BTreeMap<_, _>>();
    let mut sites = Vec::new();
    for function in &program.functions {
        for block in &function.blocks {
            let Some(region) = label_regions.get(&block.label).copied() else {
                continue;
            };
            for (index, instruction) in block.instructions.iter().enumerate() {
                let index = usize_to_u32(index, "instruction site index")?;
                let template = classify_instruction(instruction);
                let site = X64TailPreservationSite {
                    region,
                    function: function.id,
                    block: block.id,
                    label: block.label,
                    position: X64TailTemplateSitePosition::Instruction(index),
                    template,
                    clobbers: program_template_clobbers(template),
                };
                validate_site_preservation(&site)?;
                sites.push(site);
            }
            match &block.terminator {
                X64Terminator::BranchRel32 { .. } => {
                    for (position, template) in [
                        (
                            X64TailTemplateSitePosition::BranchCondition,
                            X64TailProgramTemplateKind::BranchCondition,
                        ),
                        (
                            X64TailTemplateSitePosition::BranchElse,
                            X64TailProgramTemplateKind::BranchElseRel32,
                        ),
                    ] {
                        let site = X64TailPreservationSite {
                            region,
                            function: function.id,
                            block: block.id,
                            label: block.label,
                            position,
                            template,
                            clobbers: program_template_clobbers(template),
                        };
                        validate_site_preservation(&site)?;
                        sites.push(site);
                    }
                }
                X64Terminator::TailJumpRel32 { .. } => {
                    let edge = edge_by_source.get(&(function.id, block.id)).ok_or(
                        X64TailTemplateRealizationError::MissingTarget {
                            field: "persistent tail edge",
                        },
                    )?;
                    let (position, template) = match &edge.disposition {
                        X64TailEdgeDisposition::Persistent {
                            region: edge_region,
                        } if *edge_region == region => (
                            X64TailTemplateSitePosition::TailTransition {
                                edge_ordinal: edge.ordinal,
                            },
                            X64TailProgramTemplateKind::PersistentTailTransition,
                        ),
                        X64TailEdgeDisposition::Materialize { .. } => (
                            X64TailTemplateSitePosition::TailFrontier {
                                edge_ordinal: edge.ordinal,
                            },
                            X64TailProgramTemplateKind::MaterializedTailFrontier,
                        ),
                        X64TailEdgeDisposition::Refused { .. } => (
                            X64TailTemplateSitePosition::TailFrontier {
                                edge_ordinal: edge.ordinal,
                            },
                            X64TailProgramTemplateKind::RefusedTailFrontier,
                        ),
                        X64TailEdgeDisposition::Persistent { .. } => {
                            return Err(X64TailTemplateRealizationError::InvalidField {
                                field: "cross-region persistent tail site",
                            });
                        }
                    };
                    sites.push(X64TailPreservationSite {
                        region,
                        function: function.id,
                        block: block.id,
                        label: block.label,
                        position,
                        template,
                        clobbers: program_template_clobbers(template),
                    });
                }
                // The return transfer itself is owned by the independently
                // replayed Return frontier. Instructions preceding it still
                // belong to this region and must remain in the body census.
                X64Terminator::Return { .. } => {}
            }
            ensure_limit(
                "preservation sites",
                X64_TAIL_TEMPLATE_MAX_SITES,
                sites.len(),
            )?;
        }
    }
    Ok(sites)
}

fn classify_instruction(
    instruction: &super::x64_target::X64Instruction,
) -> X64TailProgramTemplateKind {
    match &instruction.kind {
        X64InstructionKind::Move(_) => match instruction.result.ty {
            MachineType::Unit | MachineType::Bool | MachineType::I64 => {
                X64TailProgramTemplateKind::MoveScalar
            }
            MachineType::F64 => X64TailProgramTemplateKind::MoveF64,
            MachineType::F64Array => X64TailProgramTemplateKind::MoveArrayPair,
        },
        X64InstructionKind::I64Wrapping { .. } => X64TailProgramTemplateKind::I64Wrapping,
        X64InstructionKind::Sse2F64 { .. } => X64TailProgramTemplateKind::Sse2F64,
        X64InstructionKind::I64Setcc { .. } => X64TailProgramTemplateKind::I64Setcc,
        X64InstructionKind::ArrayLenF64 { .. } => X64TailProgramTemplateKind::ArrayLenF64,
        X64InstructionKind::ArrayGetF64Checked { .. } => {
            X64TailProgramTemplateKind::ArrayGetF64Checked
        }
    }
}

fn program_template_clobbers(template: X64TailProgramTemplateKind) -> Vec<X64TailTemplateRegister> {
    use X64TailTemplateRegister as R;
    match template {
        X64TailProgramTemplateKind::MoveScalar => vec![R::Rax, R::R8],
        X64TailProgramTemplateKind::MoveF64 => vec![R::Rax, R::R8, R::Xmm2],
        X64TailProgramTemplateKind::MoveArrayPair => vec![R::Rax, R::Rdx],
        X64TailProgramTemplateKind::I64Wrapping => vec![R::Rax, R::Rcx, R::R8, R::Flags],
        X64TailProgramTemplateKind::Sse2F64 => {
            vec![R::Rax, R::Rcx, R::Xmm0, R::Xmm1, R::Xmm2]
        }
        X64TailProgramTemplateKind::I64Setcc => vec![R::Rax, R::Rcx, R::R8, R::Flags],
        X64TailProgramTemplateKind::ArrayLenF64 => vec![R::Rax, R::R8],
        X64TailProgramTemplateKind::ArrayGetF64Checked => {
            vec![R::Rax, R::Rcx, R::Rdx, R::Xmm0, R::Flags]
        }
        X64TailProgramTemplateKind::BranchCondition => vec![R::Rax, R::Flags],
        X64TailProgramTemplateKind::BranchElseRel32
        | X64TailProgramTemplateKind::PersistentTailTransition => Vec::new(),
        X64TailProgramTemplateKind::MaterializedTailFrontier
        | X64TailProgramTemplateKind::RefusedTailFrontier => {
            vec![R::Rax, R::Rdx, R::R8, R::Xmm2]
        }
    }
}

fn validate_site_preservation(
    site: &X64TailPreservationSite,
) -> Result<(), X64TailTemplateRealizationError> {
    if site.clobbers.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(X64TailTemplateRealizationError::InvalidField {
            field: "canonical site clobbers",
        });
    }
    if let Some(register) = site
        .clobbers
        .iter()
        .copied()
        .find(|register| register.is_persistent())
    {
        return Err(X64TailTemplateRealizationError::PersistentClobber {
            region: site.region,
            label: site.label,
            register,
        });
    }
    Ok(())
}

fn lower_transition(
    transition: &X64TailPhysicalTransition,
    source_label: X64LabelId,
    target_label: X64LabelId,
) -> Result<X64TailTemplateTransition, X64TailTemplateRealizationError> {
    let mut builder = TransitionBuilder::default();
    for step in &transition.schedule {
        match *step {
            X64TailPhysicalStep::SaveScratch { source, scratch } => {
                lower_save_scratch(&mut builder, source, scratch)?;
            }
            X64TailPhysicalStep::Move {
                source,
                destination,
            } => lower_move(&mut builder, source, destination)?,
        }
    }
    let jump_ordinal = builder.push(X64TailTemplateInstruction::TailJumpRel32 {
        target: target_label,
    })?;
    let patch_offset = builder
        .atoms
        .last()
        .ok_or(X64TailTemplateRealizationError::InvalidField {
            field: "tail jump atom",
        })?
        .start
        .checked_add(1)
        .ok_or(X64TailTemplateRealizationError::ArithmeticOverflow {
            field: "rel32 patch offset",
        })?;
    Ok(X64TailTemplateTransition {
        edge_ordinal: transition.edge_ordinal,
        region: transition.region,
        source_label,
        target_label,
        atoms: builder.atoms,
        fixups: vec![X64TailTemplateFixup {
            atom_ordinal: jump_ordinal,
            patch_offset,
            target: target_label,
            width: 4,
            addend: 0,
        }],
        layout_bytes: builder.cursor,
    })
}

#[derive(Default)]
struct TransitionBuilder {
    atoms: Vec<X64TailTemplateAtom>,
    cursor: u32,
}

impl TransitionBuilder {
    fn push(
        &mut self,
        instruction: X64TailTemplateInstruction,
    ) -> Result<u32, X64TailTemplateRealizationError> {
        let ordinal = usize_to_u32(self.atoms.len(), "template atom ordinal")?;
        let start = self.cursor;
        let end = start.checked_add(instruction.byte_len()).ok_or(
            X64TailTemplateRealizationError::ArithmeticOverflow {
                field: "template atom end",
            },
        )?;
        self.atoms.push(X64TailTemplateAtom {
            ordinal,
            start,
            end,
            instruction,
            clobbers: instruction_clobbers(instruction),
        });
        self.cursor = end;
        Ok(ordinal)
    }
}

fn lower_save_scratch(
    builder: &mut TransitionBuilder,
    source: X64TailPhysicalLocation,
    scratch: X64TailScratchRegister,
) -> Result<(), X64TailTemplateRealizationError> {
    if source.bank() != scratch.bank() {
        return Err(X64TailTemplateRealizationError::InvalidField {
            field: "scratch bank",
        });
    }
    match (source, scratch) {
        (
            X64TailPhysicalLocation::Register {
                register,
                word_type,
            },
            X64TailScratchRegister::Rax,
        ) => {
            builder.push(X64TailTemplateInstruction::GprCopy {
                source: persistent_gpr(register)?,
                destination: X64TailTemplateGpr::Rax,
                word_type,
            })?;
        }
        (X64TailPhysicalLocation::Frame(source), X64TailScratchRegister::Rax) => {
            builder.push(X64TailTemplateInstruction::GprFrameLoad {
                source,
                destination: X64TailTemplateGpr::Rax,
            })?;
        }
        (X64TailPhysicalLocation::Register { register, .. }, X64TailScratchRegister::Xmm0) => {
            builder.push(X64TailTemplateInstruction::XmmCopy {
                source: persistent_xmm(register)?,
                destination: X64TailTemplateXmm::Xmm0,
            })?;
        }
        (X64TailPhysicalLocation::Frame(source), X64TailScratchRegister::Xmm0) => {
            require_xmm_word(source.word_type)?;
            builder.push(X64TailTemplateInstruction::XmmFrameLoad {
                source,
                destination: X64TailTemplateXmm::Xmm0,
            })?;
        }
    }
    Ok(())
}

fn lower_move(
    builder: &mut TransitionBuilder,
    source: X64TailPhysicalScheduledSource,
    destination: X64TailPhysicalLocation,
) -> Result<(), X64TailTemplateRealizationError> {
    if scheduled_source_word_type(source) != destination.word_type() {
        return Err(X64TailTemplateRealizationError::InvalidField {
            field: "physical move word type",
        });
    }
    match destination.bank() {
        super::x64_tail_state_allocation::X64TailRegisterBank::Gpr => {
            lower_gpr_move(builder, source, destination)
        }
        super::x64_tail_state_allocation::X64TailRegisterBank::Xmm => {
            lower_xmm_move(builder, source, destination)
        }
    }
}

fn lower_gpr_move(
    builder: &mut TransitionBuilder,
    source: X64TailPhysicalScheduledSource,
    destination: X64TailPhysicalLocation,
) -> Result<(), X64TailTemplateRealizationError> {
    let source_register = match source {
        X64TailPhysicalScheduledSource::Location(X64TailPhysicalLocation::Register {
            register,
            ..
        }) => Some(persistent_gpr(register)?),
        X64TailPhysicalScheduledSource::Scratch {
            register: X64TailScratchRegister::Rax,
            ..
        } => Some(X64TailTemplateGpr::Rax),
        X64TailPhysicalScheduledSource::Location(X64TailPhysicalLocation::Frame(source)) => {
            let temporary = match destination {
                X64TailPhysicalLocation::Register { register, .. } => persistent_gpr(register)?,
                X64TailPhysicalLocation::Frame(_) => X64TailTemplateGpr::Rcx,
            };
            builder.push(X64TailTemplateInstruction::GprFrameLoad {
                source,
                destination: temporary,
            })?;
            Some(temporary)
        }
        X64TailPhysicalScheduledSource::Immediate(immediate) => {
            let temporary = match destination {
                X64TailPhysicalLocation::Register { register, .. } => persistent_gpr(register)?,
                X64TailPhysicalLocation::Frame(_) => X64TailTemplateGpr::Rcx,
            };
            builder.push(X64TailTemplateInstruction::GprImmediate {
                immediate,
                destination: temporary,
            })?;
            Some(temporary)
        }
        X64TailPhysicalScheduledSource::Scratch { .. } => {
            return Err(X64TailTemplateRealizationError::InvalidField {
                field: "GPR move source bank",
            });
        }
    };
    let source_register = source_register.ok_or(X64TailTemplateRealizationError::InvalidField {
        field: "GPR move source",
    })?;
    match destination {
        X64TailPhysicalLocation::Register {
            register,
            word_type,
        } => {
            let destination = persistent_gpr(register)?;
            if source_register != destination
                && !matches!(source, X64TailPhysicalScheduledSource::Immediate(_))
                && !matches!(
                    source,
                    X64TailPhysicalScheduledSource::Location(X64TailPhysicalLocation::Frame(_))
                )
            {
                builder.push(X64TailTemplateInstruction::GprCopy {
                    source: source_register,
                    destination,
                    word_type,
                })?;
            }
        }
        X64TailPhysicalLocation::Frame(destination) => {
            builder.push(X64TailTemplateInstruction::GprFrameStore {
                source: source_register,
                destination,
            })?;
        }
    }
    Ok(())
}

fn lower_xmm_move(
    builder: &mut TransitionBuilder,
    source: X64TailPhysicalScheduledSource,
    destination: X64TailPhysicalLocation,
) -> Result<(), X64TailTemplateRealizationError> {
    let destination_register = match destination {
        X64TailPhysicalLocation::Register { register, .. } => Some(persistent_xmm(register)?),
        X64TailPhysicalLocation::Frame(location) => {
            require_xmm_word(location.word_type)?;
            None
        }
    };
    let source_register = match source {
        X64TailPhysicalScheduledSource::Location(X64TailPhysicalLocation::Register {
            register,
            ..
        }) => persistent_xmm(register)?,
        X64TailPhysicalScheduledSource::Scratch {
            register: X64TailScratchRegister::Xmm0,
            ..
        } => X64TailTemplateXmm::Xmm0,
        X64TailPhysicalScheduledSource::Location(X64TailPhysicalLocation::Frame(source)) => {
            require_xmm_word(source.word_type)?;
            let temporary = destination_register.unwrap_or(X64TailTemplateXmm::Xmm1);
            builder.push(X64TailTemplateInstruction::XmmFrameLoad {
                source,
                destination: temporary,
            })?;
            temporary
        }
        X64TailPhysicalScheduledSource::Immediate(immediate) => {
            if !matches!(immediate, X64TailImmediateWord::F64Bits(_)) {
                return Err(X64TailTemplateRealizationError::InvalidField {
                    field: "XMM immediate type",
                });
            }
            builder.push(X64TailTemplateInstruction::GprImmediate {
                immediate,
                destination: X64TailTemplateGpr::Rcx,
            })?;
            if let Some(destination) = destination_register {
                builder.push(X64TailTemplateInstruction::GprBitsToXmm {
                    source: X64TailTemplateGpr::Rcx,
                    destination,
                })?;
                destination
            } else {
                let X64TailPhysicalLocation::Frame(destination) = destination else {
                    unreachable!()
                };
                builder.push(X64TailTemplateInstruction::GprFrameStore {
                    source: X64TailTemplateGpr::Rcx,
                    destination,
                })?;
                return Ok(());
            }
        }
        X64TailPhysicalScheduledSource::Scratch { .. } => {
            return Err(X64TailTemplateRealizationError::InvalidField {
                field: "XMM move source bank",
            });
        }
    };
    match destination {
        X64TailPhysicalLocation::Register { .. } => {
            let destination =
                destination_register.ok_or(X64TailTemplateRealizationError::InvalidField {
                    field: "XMM destination register",
                })?;
            if source_register != destination
                && !matches!(source, X64TailPhysicalScheduledSource::Immediate(_))
                && !matches!(
                    source,
                    X64TailPhysicalScheduledSource::Location(X64TailPhysicalLocation::Frame(_))
                )
            {
                builder.push(X64TailTemplateInstruction::XmmCopy {
                    source: source_register,
                    destination,
                })?;
            }
        }
        X64TailPhysicalLocation::Frame(destination) => {
            builder.push(X64TailTemplateInstruction::XmmFrameStore {
                source: source_register,
                destination,
            })?;
        }
    }
    Ok(())
}

fn persistent_gpr(
    register: X64TailPhysicalRegister,
) -> Result<X64TailTemplateGpr, X64TailTemplateRealizationError> {
    match register {
        X64TailPhysicalRegister::Rdi => Ok(X64TailTemplateGpr::Rdi),
        X64TailPhysicalRegister::Rsi => Ok(X64TailTemplateGpr::Rsi),
        X64TailPhysicalRegister::R9 => Ok(X64TailTemplateGpr::R9),
        X64TailPhysicalRegister::R10 => Ok(X64TailTemplateGpr::R10),
        X64TailPhysicalRegister::R11 => Ok(X64TailTemplateGpr::R11),
        _ => Err(X64TailTemplateRealizationError::InvalidField {
            field: "persistent GPR",
        }),
    }
}

fn persistent_xmm(
    register: X64TailPhysicalRegister,
) -> Result<X64TailTemplateXmm, X64TailTemplateRealizationError> {
    match register {
        X64TailPhysicalRegister::Xmm3 => Ok(X64TailTemplateXmm::Xmm3),
        X64TailPhysicalRegister::Xmm4 => Ok(X64TailTemplateXmm::Xmm4),
        X64TailPhysicalRegister::Xmm5 => Ok(X64TailTemplateXmm::Xmm5),
        X64TailPhysicalRegister::Xmm6 => Ok(X64TailTemplateXmm::Xmm6),
        X64TailPhysicalRegister::Xmm7 => Ok(X64TailTemplateXmm::Xmm7),
        _ => Err(X64TailTemplateRealizationError::InvalidField {
            field: "persistent XMM",
        }),
    }
}

fn require_xmm_word(word_type: X64TailWordType) -> Result<(), X64TailTemplateRealizationError> {
    if word_type == X64TailWordType::F64 {
        Ok(())
    } else {
        Err(X64TailTemplateRealizationError::InvalidField {
            field: "XMM word type",
        })
    }
}

const fn scheduled_source_word_type(source: X64TailPhysicalScheduledSource) -> X64TailWordType {
    match source {
        X64TailPhysicalScheduledSource::Location(location) => location.word_type(),
        X64TailPhysicalScheduledSource::Immediate(X64TailImmediateWord::Bool(_)) => {
            X64TailWordType::Bool
        }
        X64TailPhysicalScheduledSource::Immediate(X64TailImmediateWord::I64(_)) => {
            X64TailWordType::I64
        }
        X64TailPhysicalScheduledSource::Immediate(X64TailImmediateWord::F64Bits(_)) => {
            X64TailWordType::F64
        }
        X64TailPhysicalScheduledSource::Scratch { word_type, .. } => word_type,
    }
}

fn instruction_clobbers(instruction: X64TailTemplateInstruction) -> Vec<X64TailTemplateRegister> {
    match instruction {
        X64TailTemplateInstruction::GprCopy { destination, .. }
        | X64TailTemplateInstruction::GprFrameLoad { destination, .. }
        | X64TailTemplateInstruction::GprImmediate { destination, .. } => {
            vec![template_gpr_register(destination)]
        }
        X64TailTemplateInstruction::XmmCopy { destination, .. }
        | X64TailTemplateInstruction::XmmFrameLoad { destination, .. }
        | X64TailTemplateInstruction::GprBitsToXmm { destination, .. } => {
            vec![template_xmm_register(destination)]
        }
        X64TailTemplateInstruction::GprFrameStore { .. }
        | X64TailTemplateInstruction::XmmFrameStore { .. }
        | X64TailTemplateInstruction::TailJumpRel32 { .. } => Vec::new(),
    }
}

const fn template_gpr_register(register: X64TailTemplateGpr) -> X64TailTemplateRegister {
    match register {
        X64TailTemplateGpr::Rax => X64TailTemplateRegister::Rax,
        X64TailTemplateGpr::Rcx => X64TailTemplateRegister::Rcx,
        X64TailTemplateGpr::Rdi => X64TailTemplateRegister::Rdi,
        X64TailTemplateGpr::Rsi => X64TailTemplateRegister::Rsi,
        X64TailTemplateGpr::R9 => X64TailTemplateRegister::R9,
        X64TailTemplateGpr::R10 => X64TailTemplateRegister::R10,
        X64TailTemplateGpr::R11 => X64TailTemplateRegister::R11,
    }
}

const fn template_xmm_register(register: X64TailTemplateXmm) -> X64TailTemplateRegister {
    match register {
        X64TailTemplateXmm::Xmm0 => X64TailTemplateRegister::Xmm0,
        X64TailTemplateXmm::Xmm1 => X64TailTemplateRegister::Xmm1,
        X64TailTemplateXmm::Xmm3 => X64TailTemplateRegister::Xmm3,
        X64TailTemplateXmm::Xmm4 => X64TailTemplateRegister::Xmm4,
        X64TailTemplateXmm::Xmm5 => X64TailTemplateRegister::Xmm5,
        X64TailTemplateXmm::Xmm6 => X64TailTemplateRegister::Xmm6,
        X64TailTemplateXmm::Xmm7 => X64TailTemplateRegister::Xmm7,
    }
}

fn validate_envelope(
    realization: &X64TailTemplateRealization,
    physical: &X64TailPhysicalAllocation,
    logical: &X64TailStatePlan,
    target: &X64TargetArtifact,
) -> Result<(), X64TailTemplateRealizationError> {
    if realization.schema_version != X64_TAIL_TEMPLATE_SCHEMA_VERSION {
        return Err(X64TailTemplateRealizationError::InvalidField {
            field: "schema version",
        });
    }
    if realization.policy_version != X64_TAIL_TEMPLATE_POLICY_VERSION {
        return Err(X64TailTemplateRealizationError::InvalidField {
            field: "policy version",
        });
    }
    if realization.source_target_semantic_hash != target.semantic_hash
        || realization.source_logical_plan_hash != logical.plan_hash()
        || realization.source_physical_allocation_hash != physical.allocation_hash()
    {
        return Err(X64TailTemplateRealizationError::InvalidField {
            field: "source identity",
        });
    }
    Ok(())
}

fn audit_realization(
    realization: &X64TailTemplateRealization,
    physical: &X64TailPhysicalAllocation,
    logical: &X64TailStatePlan,
    program: &X64TargetProgram,
) -> Result<(), X64TailTemplateRealizationError> {
    let expected_sites = derive_preservation_sites(program, logical, physical)?;
    if realization.sites != expected_sites {
        return Err(X64TailTemplateRealizationError::InvalidField {
            field: "preservation site census",
        });
    }
    for site in &realization.sites {
        if site.clobbers != program_template_clobbers(site.template) {
            return Err(X64TailTemplateRealizationError::InvalidField {
                field: "site clobber contract",
            });
        }
        validate_site_preservation(site)?;
    }

    let physical_index = physical
        .transitions()
        .iter()
        .map(|transition| (transition.edge_ordinal, transition))
        .collect::<BTreeMap<_, _>>();
    let logical_index = logical
        .edges()
        .iter()
        .map(|edge| (edge.ordinal, edge))
        .collect::<BTreeMap<_, _>>();
    if realization.transitions.len() != physical_index.len() {
        return Err(X64TailTemplateRealizationError::InvalidField {
            field: "transition coverage",
        });
    }
    let mut seen = BTreeSet::new();
    for transition in &realization.transitions {
        if !seen.insert(transition.edge_ordinal) {
            return Err(X64TailTemplateRealizationError::InvalidField {
                field: "duplicate transition",
            });
        }
        let physical_transition = physical_index.get(&transition.edge_ordinal).ok_or(
            X64TailTemplateRealizationError::MissingTarget {
                field: "physical transition",
            },
        )?;
        let edge = logical_index.get(&transition.edge_ordinal).ok_or(
            X64TailTemplateRealizationError::MissingTarget {
                field: "logical transition",
            },
        )?;
        audit_transition(transition, physical_transition, edge.target_label, program)?;
    }
    let expected_totals = compute_totals(&realization.sites, &realization.transitions, physical)?;
    if realization.totals != expected_totals {
        return Err(X64TailTemplateRealizationError::InvalidField {
            field: "realization totals",
        });
    }
    Ok(())
}

fn audit_transition(
    transition: &X64TailTemplateTransition,
    physical: &X64TailPhysicalTransition,
    target_label: X64LabelId,
    program: &X64TargetProgram,
) -> Result<(), X64TailTemplateRealizationError> {
    if transition.region != physical.region || transition.target_label != target_label {
        return Err(X64TailTemplateRealizationError::TransitionMismatch {
            edge: transition.edge_ordinal,
            reason: "source binding mismatch",
        });
    }
    if transition.atoms.is_empty() || transition.fixups.len() != 1 {
        return Err(X64TailTemplateRealizationError::TransitionMismatch {
            edge: transition.edge_ordinal,
            reason: "tail jump coverage",
        });
    }
    let mut cursor = 0u32;
    for (index, atom) in transition.atoms.iter().enumerate() {
        let ordinal = usize_to_u32(index, "audited atom ordinal")?;
        let end = cursor.checked_add(atom.instruction.byte_len()).ok_or(
            X64TailTemplateRealizationError::ArithmeticOverflow {
                field: "audited atom end",
            },
        )?;
        if atom.ordinal != ordinal
            || atom.start != cursor
            || atom.end != end
            || atom.clobbers != instruction_clobbers(atom.instruction)
        {
            return Err(X64TailTemplateRealizationError::TransitionMismatch {
                edge: transition.edge_ordinal,
                reason: "noncanonical atom",
            });
        }
        validate_instruction_frames(atom.instruction, program)?;
        cursor = end;
    }
    if cursor != transition.layout_bytes
        || !matches!(
            transition.atoms.last().map(|atom| atom.instruction),
            Some(X64TailTemplateInstruction::TailJumpRel32 { target }) if target == target_label
        )
    {
        return Err(X64TailTemplateRealizationError::TransitionMismatch {
            edge: transition.edge_ordinal,
            reason: "layout or final jump",
        });
    }
    let jump = transition.atoms.last().expect("checked nonempty");
    let expected_fixup = X64TailTemplateFixup {
        atom_ordinal: jump.ordinal,
        patch_offset: jump.start.checked_add(1).ok_or(
            X64TailTemplateRealizationError::ArithmeticOverflow {
                field: "audited fixup offset",
            },
        )?,
        target: target_label,
        width: 4,
        addend: 0,
    };
    if transition.fixups != [expected_fixup]
        || !program.labels.iter().any(|label| label.id == target_label)
    {
        return Err(X64TailTemplateRealizationError::TransitionMismatch {
            edge: transition.edge_ordinal,
            reason: "rel32 fixup",
        });
    }
    let expected = lower_transition(physical, transition.source_label, target_label)?;
    if expected != *transition {
        return Err(X64TailTemplateRealizationError::TransitionMismatch {
            edge: transition.edge_ordinal,
            reason: "template regeneration",
        });
    }
    replay_transition(transition, physical)
}

fn validate_instruction_frames(
    instruction: X64TailTemplateInstruction,
    program: &X64TargetProgram,
) -> Result<(), X64TailTemplateRealizationError> {
    let location = match instruction {
        X64TailTemplateInstruction::GprFrameLoad { source, .. }
        | X64TailTemplateInstruction::XmmFrameLoad { source, .. } => Some(source),
        X64TailTemplateInstruction::GprFrameStore { destination, .. }
        | X64TailTemplateInstruction::XmmFrameStore { destination, .. } => Some(destination),
        _ => None,
    };
    if let Some(location) = location {
        let end = location.offset.checked_add(8).ok_or(
            X64TailTemplateRealizationError::ArithmeticOverflow {
                field: "frame word end",
            },
        )?;
        if location.offset % 8 != 0 || end > program.frame.frame_bytes {
            return Err(X64TailTemplateRealizationError::InvalidField {
                field: "template frame location",
            });
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SymbolicToken {
    Original(X64TailPhysicalLocation),
    Immediate(X64TailImmediateWord),
}

impl SymbolicToken {
    const fn word_type(self) -> X64TailWordType {
        match self {
            Self::Original(location) => location.word_type(),
            Self::Immediate(X64TailImmediateWord::Bool(_)) => X64TailWordType::Bool,
            Self::Immediate(X64TailImmediateWord::I64(_)) => X64TailWordType::I64,
            Self::Immediate(X64TailImmediateWord::F64Bits(_)) => X64TailWordType::F64,
        }
    }
}

#[derive(Default)]
struct SymbolicMachine {
    gprs: BTreeMap<X64TailTemplateGpr, SymbolicToken>,
    xmms: BTreeMap<X64TailTemplateXmm, SymbolicToken>,
    frames: BTreeMap<X64TailWordLocation, SymbolicToken>,
}

fn replay_transition(
    transition: &X64TailTemplateTransition,
    physical: &X64TailPhysicalTransition,
) -> Result<(), X64TailTemplateRealizationError> {
    let mut machine = SymbolicMachine::default();
    let mut expected = Vec::new();
    for assignment in &physical.assignments {
        initialize_location(&mut machine, assignment.destination)?;
        let token = match assignment.source {
            X64TailPhysicalSource::Location(location) => {
                initialize_location(&mut machine, location)?;
                SymbolicToken::Original(location)
            }
            X64TailPhysicalSource::Immediate(immediate) => SymbolicToken::Immediate(immediate),
        };
        expected.push((assignment.destination, token));
    }
    for atom in &transition.atoms {
        execute_symbolic(&mut machine, atom.instruction, transition.edge_ordinal)?;
    }
    for (destination, token) in expected {
        let actual = read_physical(&machine, destination).ok_or(
            X64TailTemplateRealizationError::TransitionMismatch {
                edge: transition.edge_ordinal,
                reason: "missing final destination",
            },
        )?;
        if actual != token {
            return Err(X64TailTemplateRealizationError::TransitionMismatch {
                edge: transition.edge_ordinal,
                reason: "symbolic snapshot mismatch",
            });
        }
    }
    Ok(())
}

fn initialize_location(
    machine: &mut SymbolicMachine,
    location: X64TailPhysicalLocation,
) -> Result<(), X64TailTemplateRealizationError> {
    let token = SymbolicToken::Original(location);
    match location {
        X64TailPhysicalLocation::Register { register, .. } => match register.bank() {
            super::x64_tail_state_allocation::X64TailRegisterBank::Gpr => {
                let register = persistent_gpr(register)?;
                if let Some(existing) = machine.gprs.insert(register, token) {
                    if existing != token {
                        return Err(X64TailTemplateRealizationError::InvalidField {
                            field: "typed GPR alias",
                        });
                    }
                }
            }
            super::x64_tail_state_allocation::X64TailRegisterBank::Xmm => {
                let register = persistent_xmm(register)?;
                if let Some(existing) = machine.xmms.insert(register, token) {
                    if existing != token {
                        return Err(X64TailTemplateRealizationError::InvalidField {
                            field: "typed XMM alias",
                        });
                    }
                }
            }
        },
        X64TailPhysicalLocation::Frame(frame) => {
            if let Some(existing) = machine.frames.insert(frame, token) {
                if existing != token {
                    return Err(X64TailTemplateRealizationError::InvalidField {
                        field: "typed frame alias",
                    });
                }
            }
        }
    }
    Ok(())
}

fn read_physical(
    machine: &SymbolicMachine,
    location: X64TailPhysicalLocation,
) -> Option<SymbolicToken> {
    match location {
        X64TailPhysicalLocation::Register { register, .. } => match register {
            X64TailPhysicalRegister::Rdi => machine.gprs.get(&X64TailTemplateGpr::Rdi).copied(),
            X64TailPhysicalRegister::Rsi => machine.gprs.get(&X64TailTemplateGpr::Rsi).copied(),
            X64TailPhysicalRegister::R9 => machine.gprs.get(&X64TailTemplateGpr::R9).copied(),
            X64TailPhysicalRegister::R10 => machine.gprs.get(&X64TailTemplateGpr::R10).copied(),
            X64TailPhysicalRegister::R11 => machine.gprs.get(&X64TailTemplateGpr::R11).copied(),
            X64TailPhysicalRegister::Xmm3 => machine.xmms.get(&X64TailTemplateXmm::Xmm3).copied(),
            X64TailPhysicalRegister::Xmm4 => machine.xmms.get(&X64TailTemplateXmm::Xmm4).copied(),
            X64TailPhysicalRegister::Xmm5 => machine.xmms.get(&X64TailTemplateXmm::Xmm5).copied(),
            X64TailPhysicalRegister::Xmm6 => machine.xmms.get(&X64TailTemplateXmm::Xmm6).copied(),
            X64TailPhysicalRegister::Xmm7 => machine.xmms.get(&X64TailTemplateXmm::Xmm7).copied(),
        },
        X64TailPhysicalLocation::Frame(frame) => machine.frames.get(&frame).copied(),
    }
}

fn execute_symbolic(
    machine: &mut SymbolicMachine,
    instruction: X64TailTemplateInstruction,
    edge: u32,
) -> Result<(), X64TailTemplateRealizationError> {
    let missing = || X64TailTemplateRealizationError::TransitionMismatch {
        edge,
        reason: "read of uninitialized template storage",
    };
    match instruction {
        X64TailTemplateInstruction::GprCopy {
            source,
            destination,
            word_type,
        } => {
            let token = machine.gprs.get(&source).copied().ok_or_else(missing)?;
            require_token_type(token, word_type, edge)?;
            machine.gprs.insert(destination, token);
        }
        X64TailTemplateInstruction::GprFrameLoad {
            source,
            destination,
        } => {
            let token = machine.frames.get(&source).copied().ok_or_else(missing)?;
            require_token_type(token, source.word_type, edge)?;
            machine.gprs.insert(destination, token);
        }
        X64TailTemplateInstruction::GprFrameStore {
            source,
            destination,
        } => {
            let token = machine.gprs.get(&source).copied().ok_or_else(missing)?;
            require_token_type(token, destination.word_type, edge)?;
            machine.frames.insert(destination, token);
        }
        X64TailTemplateInstruction::XmmCopy {
            source,
            destination,
        } => {
            let token = machine.xmms.get(&source).copied().ok_or_else(missing)?;
            require_token_type(token, X64TailWordType::F64, edge)?;
            machine.xmms.insert(destination, token);
        }
        X64TailTemplateInstruction::XmmFrameLoad {
            source,
            destination,
        } => {
            let token = machine.frames.get(&source).copied().ok_or_else(missing)?;
            require_token_type(token, X64TailWordType::F64, edge)?;
            machine.xmms.insert(destination, token);
        }
        X64TailTemplateInstruction::XmmFrameStore {
            source,
            destination,
        } => {
            let token = machine.xmms.get(&source).copied().ok_or_else(missing)?;
            require_token_type(token, X64TailWordType::F64, edge)?;
            machine.frames.insert(destination, token);
        }
        X64TailTemplateInstruction::GprImmediate {
            immediate,
            destination,
        } => {
            machine
                .gprs
                .insert(destination, SymbolicToken::Immediate(immediate));
        }
        X64TailTemplateInstruction::GprBitsToXmm {
            source,
            destination,
        } => {
            let token = machine.gprs.get(&source).copied().ok_or_else(missing)?;
            require_token_type(token, X64TailWordType::F64, edge)?;
            machine.xmms.insert(destination, token);
        }
        X64TailTemplateInstruction::TailJumpRel32 { .. } => {}
    }
    Ok(())
}

fn require_token_type(
    token: SymbolicToken,
    expected: X64TailWordType,
    edge: u32,
) -> Result<(), X64TailTemplateRealizationError> {
    if token.word_type() == expected {
        Ok(())
    } else {
        Err(X64TailTemplateRealizationError::TransitionMismatch {
            edge,
            reason: "symbolic word type mismatch",
        })
    }
}

fn compute_totals(
    sites: &[X64TailPreservationSite],
    transitions: &[X64TailTemplateTransition],
    physical: &X64TailPhysicalAllocation,
) -> Result<X64TailTemplateTotals, X64TailTemplateRealizationError> {
    let mut totals = X64TailTemplateTotals {
        preservation_sites: usize_to_u32(sites.len(), "preservation site total")?,
        persistent_transitions: usize_to_u32(transitions.len(), "transition total")?,
        ..X64TailTemplateTotals::default()
    };
    let mut atom_count = 0usize;
    for transition in transitions {
        atom_count = atom_count.checked_add(transition.atoms.len()).ok_or(
            X64TailTemplateRealizationError::ArithmeticOverflow {
                field: "template atom count",
            },
        )?;
        totals.template_atoms = checked_add_u64(
            totals.template_atoms,
            usize_to_u64(transition.atoms.len(), "template atoms")?,
            "template atom total",
        )?;
        totals.retained_fixups = totals
            .retained_fixups
            .checked_add(usize_to_u32(transition.fixups.len(), "fixup total")?)
            .ok_or(X64TailTemplateRealizationError::ArithmeticOverflow {
                field: "fixup total",
            })?;
        totals.prospective_layout_bytes = checked_add_u64(
            totals.prospective_layout_bytes,
            u64::from(transition.layout_bytes),
            "prospective layout bytes",
        )?;
        totals.max_transition_bytes = totals.max_transition_bytes.max(transition.layout_bytes);
        for atom in &transition.atoms {
            match atom.instruction {
                X64TailTemplateInstruction::GprCopy { .. }
                | X64TailTemplateInstruction::GprFrameLoad { .. }
                | X64TailTemplateInstruction::GprFrameStore { .. }
                | X64TailTemplateInstruction::GprImmediate { .. } => {
                    totals.gpr_atoms = checked_add_u64(totals.gpr_atoms, 1, "GPR atoms")?;
                }
                X64TailTemplateInstruction::XmmCopy { .. }
                | X64TailTemplateInstruction::XmmFrameLoad { .. }
                | X64TailTemplateInstruction::XmmFrameStore { .. }
                | X64TailTemplateInstruction::GprBitsToXmm { .. } => {
                    totals.xmm_atoms = checked_add_u64(totals.xmm_atoms, 1, "XMM atoms")?;
                }
                X64TailTemplateInstruction::TailJumpRel32 { .. } => {}
            }
            match atom.instruction {
                X64TailTemplateInstruction::GprImmediate { .. } => {
                    totals.immediate_atoms =
                        checked_add_u64(totals.immediate_atoms, 1, "immediate atoms")?;
                }
                X64TailTemplateInstruction::GprFrameLoad { .. }
                | X64TailTemplateInstruction::XmmFrameLoad { .. } => {
                    totals.frame_load_atoms =
                        checked_add_u64(totals.frame_load_atoms, 1, "frame load atoms")?;
                }
                X64TailTemplateInstruction::GprFrameStore { .. }
                | X64TailTemplateInstruction::XmmFrameStore { .. } => {
                    totals.frame_store_atoms =
                        checked_add_u64(totals.frame_store_atoms, 1, "frame store atoms")?;
                }
                _ => {}
            }
        }
    }
    ensure_limit("template atoms", X64_TAIL_TEMPLATE_MAX_ATOMS, atom_count)?;
    ensure_limit(
        "retained fixups",
        X64_TAIL_TEMPLATE_MAX_FIXUPS,
        usize::try_from(totals.retained_fixups).unwrap_or(usize::MAX),
    )?;
    if totals.prospective_layout_bytes > X64_TAIL_TEMPLATE_MAX_LAYOUT_BYTES {
        return Err(X64TailTemplateRealizationError::LimitExceeded {
            field: "prospective layout bytes",
            limit: X64_TAIL_TEMPLATE_MAX_LAYOUT_BYTES,
            actual: totals.prospective_layout_bytes,
        });
    }
    let assignments = physical
        .transitions()
        .iter()
        .try_fold(0u64, |total, transition| {
            checked_add_u64(
                total,
                usize_to_u64(transition.assignments.len(), "physical assignments")?,
                "physical assignment total",
            )
        })?;
    totals.replay_work = checked_add_u64(
        u64::from(totals.preservation_sites),
        totals.template_atoms,
        "replay work",
    )?;
    totals.replay_work = checked_add_u64(totals.replay_work, assignments, "replay work")?;
    if totals.replay_work > X64_TAIL_TEMPLATE_MAX_REPLAY_WORK {
        return Err(X64TailTemplateRealizationError::LimitExceeded {
            field: "replay work",
            limit: X64_TAIL_TEMPLATE_MAX_REPLAY_WORK,
            actual: totals.replay_work,
        });
    }
    Ok(totals)
}

fn ensure_limit(
    field: &'static str,
    limit: u32,
    actual: usize,
) -> Result<(), X64TailTemplateRealizationError> {
    if actual > limit as usize {
        Err(X64TailTemplateRealizationError::LimitExceeded {
            field,
            limit: u64::from(limit),
            actual: usize_to_u64(actual, field)?,
        })
    } else {
        Ok(())
    }
}

fn checked_add_u64(
    left: u64,
    right: u64,
    field: &'static str,
) -> Result<u64, X64TailTemplateRealizationError> {
    left.checked_add(right)
        .ok_or(X64TailTemplateRealizationError::ArithmeticOverflow { field })
}

fn usize_to_u32(value: usize, field: &'static str) -> Result<u32, X64TailTemplateRealizationError> {
    u32::try_from(value).map_err(|_| X64TailTemplateRealizationError::ArithmeticOverflow { field })
}

fn usize_to_u64(value: usize, field: &'static str) -> Result<u64, X64TailTemplateRealizationError> {
    u64::try_from(value).map_err(|_| X64TailTemplateRealizationError::ArithmeticOverflow { field })
}

fn realization_bytes_without_seal(
    realization: &X64TailTemplateRealization,
) -> Result<Vec<u8>, X64TailTemplateRealizationError> {
    let mut encoder = RealizationEncoder::new();
    encoder.bytes(REALIZATION_DOMAIN)?;
    encoder.version(realization.schema_version)?;
    encoder.version(realization.policy_version)?;
    encoder.hash(realization.source_target_semantic_hash)?;
    encoder.hash(realization.source_logical_plan_hash)?;
    encoder.hash(realization.source_physical_allocation_hash)?;
    encoder.len(realization.sites.len())?;
    for site in &realization.sites {
        encoder.u32(site.region)?;
        encoder.u32(site.function.0)?;
        encoder.u32(site.block.0)?;
        encoder.u32(site.label.0)?;
        encode_site_position(&mut encoder, site.position)?;
        encoder.u8(program_template_tag(site.template))?;
        encoder.len(site.clobbers.len())?;
        for register in &site.clobbers {
            encoder.u8(template_register_tag(*register))?;
        }
    }
    encoder.len(realization.transitions.len())?;
    for transition in &realization.transitions {
        encoder.u32(transition.edge_ordinal)?;
        encoder.u32(transition.region)?;
        encoder.u32(transition.source_label.0)?;
        encoder.u32(transition.target_label.0)?;
        encoder.len(transition.atoms.len())?;
        for atom in &transition.atoms {
            encoder.u32(atom.ordinal)?;
            encoder.u32(atom.start)?;
            encoder.u32(atom.end)?;
            encode_template_instruction(&mut encoder, atom.instruction)?;
            encoder.len(atom.clobbers.len())?;
            for register in &atom.clobbers {
                encoder.u8(template_register_tag(*register))?;
            }
        }
        encoder.len(transition.fixups.len())?;
        for fixup in &transition.fixups {
            encoder.u32(fixup.atom_ordinal)?;
            encoder.u32(fixup.patch_offset)?;
            encoder.u32(fixup.target.0)?;
            encoder.u8(fixup.width)?;
            encoder.i32(fixup.addend)?;
        }
        encoder.u32(transition.layout_bytes)?;
    }
    encode_totals(&mut encoder, realization.totals)?;
    Ok(encoder.finish())
}

fn encode_site_position(
    encoder: &mut RealizationEncoder,
    position: X64TailTemplateSitePosition,
) -> Result<(), X64TailTemplateRealizationError> {
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

fn encode_template_instruction(
    encoder: &mut RealizationEncoder,
    instruction: X64TailTemplateInstruction,
) -> Result<(), X64TailTemplateRealizationError> {
    match instruction {
        X64TailTemplateInstruction::GprCopy {
            source,
            destination,
            word_type,
        } => {
            encoder.u8(0)?;
            encoder.u8(gpr_tag(source))?;
            encoder.u8(gpr_tag(destination))?;
            encoder.u8(word_type_tag(word_type))
        }
        X64TailTemplateInstruction::GprFrameLoad {
            source,
            destination,
        } => {
            encoder.u8(1)?;
            encode_word_location(encoder, source)?;
            encoder.u8(gpr_tag(destination))
        }
        X64TailTemplateInstruction::GprFrameStore {
            source,
            destination,
        } => {
            encoder.u8(2)?;
            encoder.u8(gpr_tag(source))?;
            encode_word_location(encoder, destination)
        }
        X64TailTemplateInstruction::XmmCopy {
            source,
            destination,
        } => {
            encoder.u8(3)?;
            encoder.u8(xmm_tag(source))?;
            encoder.u8(xmm_tag(destination))
        }
        X64TailTemplateInstruction::XmmFrameLoad {
            source,
            destination,
        } => {
            encoder.u8(4)?;
            encode_word_location(encoder, source)?;
            encoder.u8(xmm_tag(destination))
        }
        X64TailTemplateInstruction::XmmFrameStore {
            source,
            destination,
        } => {
            encoder.u8(5)?;
            encoder.u8(xmm_tag(source))?;
            encode_word_location(encoder, destination)
        }
        X64TailTemplateInstruction::GprImmediate {
            immediate,
            destination,
        } => {
            encoder.u8(6)?;
            encode_immediate(encoder, immediate)?;
            encoder.u8(gpr_tag(destination))
        }
        X64TailTemplateInstruction::GprBitsToXmm {
            source,
            destination,
        } => {
            encoder.u8(7)?;
            encoder.u8(gpr_tag(source))?;
            encoder.u8(xmm_tag(destination))
        }
        X64TailTemplateInstruction::TailJumpRel32 { target } => {
            encoder.u8(8)?;
            encoder.u32(target.0)
        }
    }
}

fn encode_word_location(
    encoder: &mut RealizationEncoder,
    location: X64TailWordLocation,
) -> Result<(), X64TailTemplateRealizationError> {
    encoder.u32(location.offset)?;
    encoder.u8(word_type_tag(location.word_type))
}

fn encode_immediate(
    encoder: &mut RealizationEncoder,
    immediate: X64TailImmediateWord,
) -> Result<(), X64TailTemplateRealizationError> {
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
    encoder: &mut RealizationEncoder,
    totals: X64TailTemplateTotals,
) -> Result<(), X64TailTemplateRealizationError> {
    encoder.u32(totals.preservation_sites)?;
    encoder.u32(totals.persistent_transitions)?;
    encoder.u64(totals.template_atoms)?;
    encoder.u32(totals.retained_fixups)?;
    encoder.u64(totals.gpr_atoms)?;
    encoder.u64(totals.xmm_atoms)?;
    encoder.u64(totals.immediate_atoms)?;
    encoder.u64(totals.frame_load_atoms)?;
    encoder.u64(totals.frame_store_atoms)?;
    encoder.u64(totals.prospective_layout_bytes)?;
    encoder.u32(totals.max_transition_bytes)?;
    encoder.u64(totals.replay_work)
}

const fn program_template_tag(template: X64TailProgramTemplateKind) -> u8 {
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

const fn template_register_tag(register: X64TailTemplateRegister) -> u8 {
    match register {
        X64TailTemplateRegister::Rax => 0,
        X64TailTemplateRegister::Rcx => 1,
        X64TailTemplateRegister::Rdx => 2,
        X64TailTemplateRegister::Rdi => 3,
        X64TailTemplateRegister::Rsi => 4,
        X64TailTemplateRegister::R8 => 5,
        X64TailTemplateRegister::R9 => 6,
        X64TailTemplateRegister::R10 => 7,
        X64TailTemplateRegister::R11 => 8,
        X64TailTemplateRegister::Xmm0 => 9,
        X64TailTemplateRegister::Xmm1 => 10,
        X64TailTemplateRegister::Xmm2 => 11,
        X64TailTemplateRegister::Xmm3 => 12,
        X64TailTemplateRegister::Xmm4 => 13,
        X64TailTemplateRegister::Xmm5 => 14,
        X64TailTemplateRegister::Xmm6 => 15,
        X64TailTemplateRegister::Xmm7 => 16,
        X64TailTemplateRegister::Flags => 17,
    }
}

const fn gpr_tag(register: X64TailTemplateGpr) -> u8 {
    match register {
        X64TailTemplateGpr::Rax => 0,
        X64TailTemplateGpr::Rcx => 6,
        X64TailTemplateGpr::Rdi => 1,
        X64TailTemplateGpr::Rsi => 2,
        X64TailTemplateGpr::R9 => 3,
        X64TailTemplateGpr::R10 => 4,
        X64TailTemplateGpr::R11 => 5,
    }
}

const fn xmm_tag(register: X64TailTemplateXmm) -> u8 {
    match register {
        X64TailTemplateXmm::Xmm0 => 0,
        X64TailTemplateXmm::Xmm1 => 6,
        X64TailTemplateXmm::Xmm3 => 1,
        X64TailTemplateXmm::Xmm4 => 2,
        X64TailTemplateXmm::Xmm5 => 3,
        X64TailTemplateXmm::Xmm6 => 4,
        X64TailTemplateXmm::Xmm7 => 5,
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

struct RealizationEncoder {
    bytes: Vec<u8>,
}

impl RealizationEncoder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn reserve(&mut self, additional: usize) -> Result<(), X64TailTemplateRealizationError> {
        let actual = self.bytes.len().checked_add(additional).ok_or(
            X64TailTemplateRealizationError::ArithmeticOverflow {
                field: "realization encoding length",
            },
        )?;
        if actual > MAX_REALIZATION_BYTES {
            return Err(X64TailTemplateRealizationError::EncodingLimit { actual });
        }
        self.bytes
            .try_reserve(additional)
            .map_err(|_| X64TailTemplateRealizationError::EncodingLimit { actual })
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), X64TailTemplateRealizationError> {
        self.reserve(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), X64TailTemplateRealizationError> {
        self.bytes(&[value])
    }

    fn u32(&mut self, value: u32) -> Result<(), X64TailTemplateRealizationError> {
        self.bytes(&value.to_le_bytes())
    }

    fn i32(&mut self, value: i32) -> Result<(), X64TailTemplateRealizationError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), X64TailTemplateRealizationError> {
        self.bytes(&value.to_le_bytes())
    }

    fn len(&mut self, value: usize) -> Result<(), X64TailTemplateRealizationError> {
        self.u32(usize_to_u32(value, "realization collection length")?)
    }

    fn version(&mut self, value: (u16, u16, u16)) -> Result<(), X64TailTemplateRealizationError> {
        self.bytes(&value.0.to_le_bytes())?;
        self.bytes(&value.1.to_le_bytes())?;
        self.bytes(&value.2.to_le_bytes())
    }

    fn hash(&mut self, value: SemanticHash) -> Result<(), X64TailTemplateRealizationError> {
        self.bytes(&value.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::corevm0_gate_a::CoreVmGateAWorkload;
    use crate::core::x64_native_lighthouse::X64NativeLighthousePackage;
    use crate::core::{
        emit_x64_tail_physical_allocation, emit_x64_tail_state_plan,
        X64_TARGET_ENCODER_POLICY_VERSION,
    };

    fn word(offset: u32, word_type: X64TailWordType) -> X64TailWordLocation {
        X64TailWordLocation { offset, word_type }
    }

    fn physical_register(
        register: X64TailPhysicalRegister,
        word_type: X64TailWordType,
    ) -> X64TailPhysicalLocation {
        X64TailPhysicalLocation::Register {
            register,
            word_type,
        }
    }

    fn physical_source(location: X64TailPhysicalLocation) -> X64TailPhysicalScheduledSource {
        X64TailPhysicalScheduledSource::Location(location)
    }

    fn assignment(
        source: X64TailPhysicalSource,
        destination: X64TailPhysicalLocation,
    ) -> super::super::x64_tail_state_allocation::X64TailPhysicalAssignment {
        super::super::x64_tail_state_allocation::X64TailPhysicalAssignment {
            source,
            destination,
        }
    }

    #[test]
    fn frozen_program_catalog_never_clobbers_a_persistent_lane() {
        let templates = [
            X64TailProgramTemplateKind::MoveScalar,
            X64TailProgramTemplateKind::MoveF64,
            X64TailProgramTemplateKind::MoveArrayPair,
            X64TailProgramTemplateKind::I64Wrapping,
            X64TailProgramTemplateKind::Sse2F64,
            X64TailProgramTemplateKind::I64Setcc,
            X64TailProgramTemplateKind::ArrayLenF64,
            X64TailProgramTemplateKind::ArrayGetF64Checked,
            X64TailProgramTemplateKind::BranchCondition,
            X64TailProgramTemplateKind::BranchElseRel32,
            X64TailProgramTemplateKind::PersistentTailTransition,
            X64TailProgramTemplateKind::MaterializedTailFrontier,
            X64TailProgramTemplateKind::RefusedTailFrontier,
        ];
        for template in templates {
            let clobbers = program_template_clobbers(template);
            assert!(clobbers.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(clobbers.iter().all(|register| !register.is_persistent()));
        }

        let site = X64TailPreservationSite {
            region: 7,
            function: X64FunctionId(0),
            block: X64BlockId(0),
            label: X64LabelId(9),
            position: X64TailTemplateSitePosition::Instruction(0),
            template: X64TailProgramTemplateKind::MoveScalar,
            clobbers: vec![X64TailTemplateRegister::Rdi],
        };
        assert!(matches!(
            validate_site_preservation(&site),
            Err(X64TailTemplateRealizationError::PersistentClobber {
                register: X64TailTemplateRegister::Rdi,
                ..
            })
        ));
    }

    #[test]
    fn symbolic_templates_replay_cycles_and_reject_cross_bank_scratch_destruction() {
        let rdi = physical_register(X64TailPhysicalRegister::Rdi, X64TailWordType::I64);
        let rsi = physical_register(X64TailPhysicalRegister::Rsi, X64TailWordType::I64);
        let xmm3 = physical_register(X64TailPhysicalRegister::Xmm3, X64TailWordType::F64);
        let immediate = X64TailImmediateWord::F64Bits(0x3ff0_0000_0000_0000);
        let assignments = vec![
            assignment(X64TailPhysicalSource::Location(rsi), rdi),
            assignment(X64TailPhysicalSource::Location(rdi), rsi),
            assignment(X64TailPhysicalSource::Immediate(immediate), xmm3),
        ];
        let safe = X64TailPhysicalTransition {
            edge_ordinal: 0,
            region: 0,
            assignments: assignments.clone(),
            schedule: vec![
                X64TailPhysicalStep::SaveScratch {
                    source: rdi,
                    scratch: X64TailScratchRegister::Rax,
                },
                X64TailPhysicalStep::Move {
                    source: physical_source(rsi),
                    destination: rdi,
                },
                X64TailPhysicalStep::Move {
                    source: X64TailPhysicalScheduledSource::Scratch {
                        register: X64TailScratchRegister::Rax,
                        word_type: X64TailWordType::I64,
                    },
                    destination: rsi,
                },
                X64TailPhysicalStep::Move {
                    source: X64TailPhysicalScheduledSource::Immediate(immediate),
                    destination: xmm3,
                },
            ],
        };
        let safe_realization = lower_transition(&safe, X64LabelId(1), X64LabelId(2))
            .expect("safe mixed-bank schedule must lower");
        replay_transition(&safe_realization, &safe)
            .expect("safe mixed-bank schedule must refine its snapshot");
        assert_eq!(safe_realization.fixups.len(), 1);
        assert!(matches!(
            safe_realization.atoms.last().map(|atom| atom.instruction),
            Some(X64TailTemplateInstruction::TailJumpRel32 {
                target: X64LabelId(2)
            })
        ));

        let stale = X64TailPhysicalTransition {
            schedule: vec![
                X64TailPhysicalStep::SaveScratch {
                    source: rdi,
                    scratch: X64TailScratchRegister::Rax,
                },
                X64TailPhysicalStep::Move {
                    source: X64TailPhysicalScheduledSource::Immediate(immediate),
                    destination: xmm3,
                },
                X64TailPhysicalStep::Move {
                    source: physical_source(rsi),
                    destination: rdi,
                },
                X64TailPhysicalStep::Move {
                    source: X64TailPhysicalScheduledSource::Scratch {
                        register: X64TailScratchRegister::Rax,
                        word_type: X64TailWordType::I64,
                    },
                    destination: rsi,
                },
            ],
            ..safe
        };
        let stale_realization = lower_transition(&stale, X64LabelId(1), X64LabelId(2))
            .expect("cross-bank schedule must reserve the live GPR scratch");
        replay_transition(&stale_realization, &stale)
            .expect("RCX/XMM1 temporaries must preserve the RAX scratch");

        let mut corrupted = stale_realization;
        for atom in &mut corrupted.atoms {
            atom.instruction = match atom.instruction {
                X64TailTemplateInstruction::GprImmediate {
                    immediate,
                    destination: X64TailTemplateGpr::Rcx,
                } => X64TailTemplateInstruction::GprImmediate {
                    immediate,
                    destination: X64TailTemplateGpr::Rax,
                },
                X64TailTemplateInstruction::GprBitsToXmm {
                    source: X64TailTemplateGpr::Rcx,
                    destination,
                } => X64TailTemplateInstruction::GprBitsToXmm {
                    source: X64TailTemplateGpr::Rax,
                    destination,
                },
                instruction => instruction,
            };
            atom.clobbers = instruction_clobbers(atom.instruction);
        }
        assert!(matches!(
            replay_transition(&corrupted, &stale),
            Err(X64TailTemplateRealizationError::TransitionMismatch { .. })
        ));
    }

    #[test]
    fn branch_lighthouse_realization_is_deterministic_and_resealed_mutations_fail() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("BranchMix lighthouse must build");
        let logical = emit_x64_tail_state_plan(package.target()).expect("logical plan must emit");
        let physical = emit_x64_tail_physical_allocation(package.target(), &logical)
            .expect("physical allocation must emit");
        let first = emit_x64_tail_template_realization(package.target(), &logical, &physical)
            .expect("template realization must emit");
        let second = emit_x64_tail_template_realization(package.target(), &logical, &physical)
            .expect("template realization must replay");
        assert_eq!(first, second);
        verify_x64_tail_template_realization(&first, &physical, &logical, package.target())
            .expect("template realization must independently verify");
        assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
        assert_eq!(
            first.realization_hash().to_hex(),
            "d976fd91769b210b4e13a28ebd57a8ffa238d71d5285b62fff781fa74995b266"
        );
        assert_eq!(
            first.totals(),
            X64TailTemplateTotals {
                preservation_sites: 168,
                persistent_transitions: 108,
                template_atoms: 314,
                retained_fixups: 108,
                gpr_atoms: 186,
                xmm_atoms: 20,
                immediate_atoms: 17,
                frame_load_atoms: 61,
                frame_store_atoms: 100,
                prospective_layout_bytes: 2_103,
                max_transition_bytes: 92,
                replay_work: 1_566,
            }
        );
        for function in &package.target().program.functions {
            for block in &function.blocks {
                for index in 0..block.instructions.len() {
                    assert!(first.sites().iter().any(|site| {
                        site.function == function.id
                            && site.block == block.id
                            && site.position
                                == X64TailTemplateSitePosition::Instruction(index as u32)
                    }));
                }
            }
        }
        let mut wrong_total = first.clone();
        wrong_total.totals.gpr_atoms = wrong_total.totals.gpr_atoms.saturating_add(1);
        wrong_total.realization_hash = x64_tail_template_realization_hash(&wrong_total)
            .expect("total mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_template_realization(
                &wrong_total,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailTemplateRealizationError::InvalidField {
                field: "realization totals"
            })
        ));

        let mut wrong_source = first.clone();
        wrong_source.source_physical_allocation_hash.0[0] ^= 1;
        wrong_source.realization_hash = x64_tail_template_realization_hash(&wrong_source)
            .expect("source mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_template_realization(
                &wrong_source,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailTemplateRealizationError::InvalidField {
                field: "source identity"
            })
        ));

        let mut wrong_atom = first.clone();
        wrong_atom.transitions[0].atoms[0].end =
            wrong_atom.transitions[0].atoms[0].end.saturating_add(1);
        wrong_atom.realization_hash = x64_tail_template_realization_hash(&wrong_atom)
            .expect("atom mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_template_realization(
                &wrong_atom,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailTemplateRealizationError::TransitionMismatch { .. })
        ));

        let mut wrong_fixup = first.clone();
        wrong_fixup.transitions[0].fixups[0].patch_offset = wrong_fixup.transitions[0].fixups[0]
            .patch_offset
            .saturating_add(1);
        wrong_fixup.realization_hash = x64_tail_template_realization_hash(&wrong_fixup)
            .expect("fixup mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_template_realization(
                &wrong_fixup,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailTemplateRealizationError::TransitionMismatch { .. })
        ));

        let mut wrong_site_clobber = first.clone();
        wrong_site_clobber.sites[0]
            .clobbers
            .push(X64TailTemplateRegister::Rdi);
        wrong_site_clobber.sites[0].clobbers.sort_unstable();
        wrong_site_clobber.sites[0].clobbers.dedup();
        wrong_site_clobber.realization_hash =
            x64_tail_template_realization_hash(&wrong_site_clobber)
                .expect("site clobber mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_template_realization(
                &wrong_site_clobber,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailTemplateRealizationError::InvalidField {
                field: "preservation site census"
            })
        ));

        let mut wrong_atom_clobber = first.clone();
        wrong_atom_clobber.transitions[0].atoms[0]
            .clobbers
            .push(X64TailTemplateRegister::Rdi);
        wrong_atom_clobber.transitions[0].atoms[0]
            .clobbers
            .sort_unstable();
        wrong_atom_clobber.transitions[0].atoms[0].clobbers.dedup();
        wrong_atom_clobber.realization_hash =
            x64_tail_template_realization_hash(&wrong_atom_clobber)
                .expect("atom clobber mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_template_realization(
                &wrong_atom_clobber,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailTemplateRealizationError::TransitionMismatch { .. })
        ));
    }

    #[test]
    fn bounds_lighthouse_realization_is_complete_and_proof_only() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BoundsOrderedArrayGet)
            .expect("Bounds lighthouse must build");
        let original_code = package.target().program.code.clone();
        let logical = emit_x64_tail_state_plan(package.target()).expect("logical plan must emit");
        let physical = emit_x64_tail_physical_allocation(package.target(), &logical)
            .expect("physical allocation must emit");
        let realization = emit_x64_tail_template_realization(package.target(), &logical, &physical)
            .expect("Bounds realization must emit");
        verify_x64_tail_template_realization(&realization, &physical, &logical, package.target())
            .expect("Bounds realization must verify");
        assert_eq!(
            realization.totals().persistent_transitions,
            physical.totals().transitions
        );
        assert_eq!(package.target().program.code, original_code);
        assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
    }

    #[test]
    fn symbolic_frame_templates_keep_exact_lengths() {
        let gpr = X64TailTemplateInstruction::GprFrameLoad {
            source: word(32, X64TailWordType::I64),
            destination: X64TailTemplateGpr::Rax,
        };
        let xmm = X64TailTemplateInstruction::XmmFrameStore {
            source: X64TailTemplateXmm::Xmm0,
            destination: word(40, X64TailWordType::F64),
        };
        assert_eq!(gpr.byte_len(), 8);
        assert_eq!(xmm.byte_len(), 9);
        assert_eq!(
            X64TailTemplateInstruction::GprImmediate {
                immediate: X64TailImmediateWord::I64(7),
                destination: X64TailTemplateGpr::Rax,
            }
            .byte_len(),
            10
        );
        assert_eq!(
            X64TailTemplateInstruction::TailJumpRel32 {
                target: X64LabelId(1)
            }
            .byte_len(),
            5
        );
    }
}
