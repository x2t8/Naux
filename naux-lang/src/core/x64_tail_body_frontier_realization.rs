//! Bounded symbolic body/frontier realization for ADR-0062.
//!
//! This module owns no machine bytes. It consumes the accepted ADR-0061
//! binding proof, lowers ready body sites and frontier obligations to a closed
//! symbolic x86-64 vocabulary, and replays typed token preservation before a
//! later encoder is allowed to exist.

use super::encoding::sha256;
use super::machine_ir::MachineType;
use super::schema::SemanticHash;
use super::x64_tail_candidate_capsule::{X64TailCandidateCapsule, X64TailCandidateCapsuleError};
use super::x64_tail_site_binding::{
    verify_x64_tail_site_binding_proof, X64TailAdapterWord, X64TailBoundDefinition,
    X64TailBoundRead, X64TailFrontierAction, X64TailFrontierBindingKind, X64TailFrontierBindingRow,
    X64TailSiteBinding, X64TailSiteBindingError, X64TailSiteBindingProof, X64TailSiteRegionStatus,
};
use super::x64_tail_state_allocation::{
    X64TailPhysicalAllocation, X64TailPhysicalLocation, X64TailPhysicalRegister,
};
use super::x64_tail_state_plan::{
    X64TailCopyStep, X64TailEdgeDisposition, X64TailImmediateWord, X64TailScheduledSource,
    X64TailStatePlan, X64TailWordLocation, X64TailWordType,
};
use super::x64_tail_template_realization::{
    X64TailProgramTemplateKind, X64TailTemplateRealization, X64TailTemplateRegister,
    X64TailTemplateSitePosition,
};
use super::x64_target::{
    X64Block, X64BlockId, X64FunctionId, X64I64Opcode, X64Immediate, X64InstructionKind,
    X64LabelId, X64LabelOwner, X64Operand, X64SetCondition, X64Sse2F64Opcode, X64TargetArtifact,
    X64TargetProgram, X64Terminator,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const X64_TAIL_BODY_FRONTIER_SCHEMA_VERSION: (u16, u16, u16) = (1, 1, 0);
pub const X64_TAIL_BODY_FRONTIER_POLICY_VERSION: (u16, u16, u16) = (1, 2, 0);
pub const X64_TAIL_BODY_FRONTIER_MAX_SITE_PROGRAMS: u32 = 1_000_000;
pub const X64_TAIL_BODY_FRONTIER_MAX_FRONTIER_PROGRAMS: u32 = 32_000;
pub const X64_TAIL_BODY_FRONTIER_MAX_ATOMS: u32 = 8_000_000;
pub const X64_TAIL_BODY_FRONTIER_MAX_FIXUPS: u32 = 2_000_000;
pub const X64_TAIL_BODY_FRONTIER_MAX_ATOMS_PER_SITE: u32 = 64;
pub const X64_TAIL_BODY_FRONTIER_MAX_ATOMS_PER_FRONTIER: u32 = 512;
pub const X64_TAIL_BODY_FRONTIER_MAX_REPLAY_WORK: u64 = 32_000_000;
pub const X64_TAIL_BODY_FRONTIER_MAX_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;

const REALIZATION_DOMAIN: &[u8] = b"NAUX:x86-64:tail-body-frontier-realization:v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum X64TailBodyScratch {
    Rax,
    Rcx,
    Rdx,
    Xmm0,
    Xmm1,
}

impl X64TailBodyScratch {
    const fn register(self) -> X64TailTemplateRegister {
        match self {
            Self::Rax => X64TailTemplateRegister::Rax,
            Self::Rcx => X64TailTemplateRegister::Rcx,
            Self::Rdx => X64TailTemplateRegister::Rdx,
            Self::Xmm0 => X64TailTemplateRegister::Xmm0,
            Self::Xmm1 => X64TailTemplateRegister::Xmm1,
        }
    }

    const fn is_gpr(self) -> bool {
        matches!(self, Self::Rax | Self::Rcx | Self::Rdx)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailBodyControlTarget {
    Label(X64LabelId),
    Frontier(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailBodyAtomInstruction {
    Acquire {
        read: X64TailBoundRead,
        destination: X64TailBodyScratch,
    },
    Define {
        source: X64TailBodyScratch,
        definition: X64TailBoundDefinition,
    },
    I64Wrapping {
        opcode: X64I64Opcode,
        definition: X64TailWordLocation,
    },
    Sse2F64 {
        opcode: X64Sse2F64Opcode,
        definition: X64TailWordLocation,
    },
    I64Setcc {
        condition: X64SetCondition,
        definition: X64TailWordLocation,
    },
    TestBool,
    BranchNonZeroRel32 {
        target: X64TailBodyControlTarget,
    },
    JumpRel32 {
        target: X64TailBodyControlTarget,
    },
    BoundsNegativeRel32 {
        target: X64TailBodyControlTarget,
    },
    BoundsUpperRel32 {
        target: X64TailBodyControlTarget,
    },
    ArrayGetF64 {
        definition: X64TailWordLocation,
    },
    AdapterFlush {
        word: X64TailAdapterWord,
    },
    AdapterHydrate {
        word: X64TailAdapterWord,
    },
    FrameScratchSave {
        source: X64TailWordLocation,
        scratch_id: u32,
    },
    FrameMove {
        source: X64TailScheduledSource,
        destination: X64TailWordLocation,
    },
    ReturnWord {
        source: X64TailScheduledSource,
        destination: X64TailBodyScratch,
    },
    MoveReturnF64BitsToXmm0,
    CanonicalizeReturnF64,
    CapsuleTransition {
        edge_ordinal: u32,
        capsule_start: u32,
        capsule_end: u32,
    },
}

impl X64TailBodyAtomInstruction {
    fn prospective_len(self) -> Result<u32, X64TailBodyFrontierError> {
        Ok(match self {
            Self::Acquire { read, destination } => acquire_len(read, destination)?,
            Self::Define { source, definition } => define_len(source, definition)?,
            Self::I64Wrapping { opcode, .. } => match opcode {
                X64I64Opcode::Add | X64I64Opcode::Sub => 3,
                X64I64Opcode::Mul => 4,
            },
            Self::Sse2F64 { .. } => 4,
            Self::I64Setcc { .. } => 10,
            Self::TestBool => 3,
            Self::BranchNonZeroRel32 { .. } => 6,
            Self::JumpRel32 { .. } => 5,
            Self::BoundsNegativeRel32 { .. } | Self::BoundsUpperRel32 { .. } => 9,
            Self::ArrayGetF64 { .. } => 5,
            Self::AdapterFlush { word } | Self::AdapterHydrate { word } => {
                adapter_len(word.logical.word_type)
            }
            Self::FrameScratchSave { source, .. } => adapter_len(source.word_type),
            Self::FrameMove {
                source,
                destination,
            } => frame_move_len(source, destination)?,
            Self::ReturnWord {
                source,
                destination,
            } => return_word_len(source, destination)?,
            Self::MoveReturnF64BitsToXmm0 => 5,
            Self::CanonicalizeReturnF64 => 18,
            Self::CapsuleTransition {
                capsule_start,
                capsule_end,
                ..
            } => capsule_end.checked_sub(capsule_start).ok_or(
                X64TailBodyFrontierError::InvalidField {
                    field: "capsule transition extent",
                },
            )?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailBodyAtom {
    pub ordinal: u32,
    pub start: u32,
    pub end: u32,
    pub instruction: X64TailBodyAtomInstruction,
    pub clobbers: Vec<X64TailTemplateRegister>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailBodyFixup {
    pub atom_ordinal: u32,
    pub patch_offset: u32,
    pub target: X64TailBodyControlTarget,
    pub width: u8,
    pub addend: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailBodySiteProgram {
    pub ordinal: u32,
    pub region: u32,
    pub function: X64FunctionId,
    pub block: X64BlockId,
    pub label: X64LabelId,
    pub position: X64TailTemplateSitePosition,
    pub template: X64TailProgramTemplateKind,
    pub atoms: Vec<X64TailBodyAtom>,
    pub fixups: Vec<X64TailBodyFixup>,
    pub prospective_bytes: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailFrontierPlacement {
    BeforeLabel,
    EdgeStub,
    CheckedExit,
    ExitStub,
    CapsuleReference,
    EvidenceOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailFrontierProgramDisposition {
    Operational,
    NoOp,
    CapsuleReference { site_ordinal: u32 },
    EvidenceAlias { owner_ordinal: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailFrontierProgram {
    pub row_ordinal: u32,
    pub kind: X64TailFrontierBindingKind,
    pub action: X64TailFrontierAction,
    pub placement: X64TailFrontierPlacement,
    pub disposition: X64TailFrontierProgramDisposition,
    pub atoms: Vec<X64TailBodyAtom>,
    pub fixups: Vec<X64TailBodyFixup>,
    pub prospective_bytes: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X64TailBodyFrontierTotals {
    pub site_programs: u32,
    pub frontier_programs: u32,
    pub operational_frontiers: u32,
    pub noop_frontiers: u32,
    pub capsule_frontiers: u32,
    pub aliased_frontiers: u32,
    pub atoms: u32,
    pub fixups: u32,
    pub body_prospective_bytes: u64,
    pub frontier_prospective_bytes: u64,
    pub retained_capsule_bytes: u64,
    pub adapter_flushes: u64,
    pub adapter_hydrates: u64,
    pub materialized_tail_steps: u64,
    pub replay_work: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailBodyFrontierRealization {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    source_target_semantic_hash: SemanticHash,
    source_logical_plan_hash: SemanticHash,
    source_physical_allocation_hash: SemanticHash,
    source_template_realization_hash: SemanticHash,
    source_candidate_capsule_hash: SemanticHash,
    source_site_binding_hash: SemanticHash,
    sites: Vec<X64TailBodySiteProgram>,
    frontiers: Vec<X64TailFrontierProgram>,
    totals: X64TailBodyFrontierTotals,
    realization_hash: SemanticHash,
}

impl X64TailBodyFrontierRealization {
    pub const fn source_target_semantic_hash(&self) -> SemanticHash {
        self.source_target_semantic_hash
    }

    pub const fn source_site_binding_hash(&self) -> SemanticHash {
        self.source_site_binding_hash
    }

    pub fn sites(&self) -> &[X64TailBodySiteProgram] {
        &self.sites
    }

    pub fn frontiers(&self) -> &[X64TailFrontierProgram] {
        &self.frontiers
    }

    pub const fn totals(&self) -> X64TailBodyFrontierTotals {
        self.totals
    }

    pub const fn realization_hash(&self) -> SemanticHash {
        self.realization_hash
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedX64TailBodyFrontierRealization<'realization> {
    realization: &'realization X64TailBodyFrontierRealization,
}

impl<'realization> VerifiedX64TailBodyFrontierRealization<'realization> {
    pub const fn realization(self) -> &'realization X64TailBodyFrontierRealization {
        self.realization
    }
}

#[derive(Debug)]
pub enum X64TailBodyFrontierError {
    SiteBinding(X64TailSiteBindingError),
    Capsule(X64TailCandidateCapsuleError),
    InvalidField {
        field: &'static str,
    },
    MissingTarget {
        field: &'static str,
    },
    Unsupported {
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
    TokenMismatch {
        field: &'static str,
    },
    RealizationHashMismatch,
    ReplayMismatch,
}

impl fmt::Display for X64TailBodyFrontierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SiteBinding(error) => write!(formatter, "body/frontier site input failed: {error}"),
            Self::Capsule(error) => write!(formatter, "body/frontier capsule input failed: {error}"),
            Self::InvalidField { field } => write!(formatter, "body/frontier realization has invalid {field}"),
            Self::MissingTarget { field } => write!(formatter, "body/frontier realization is missing {field}"),
            Self::Unsupported { field } => write!(formatter, "body/frontier realization refuses unsupported {field}"),
            Self::LimitExceeded { field, limit, actual } => write!(formatter, "body/frontier {field} uses {actual}; limit is {limit}"),
            Self::ArithmeticOverflow { field } => write!(formatter, "body/frontier realization overflowed {field}"),
            Self::EncodingLimit { actual } => write!(formatter, "body/frontier evidence uses {actual} bytes; limit is {X64_TAIL_BODY_FRONTIER_MAX_EVIDENCE_BYTES}"),
            Self::TokenMismatch { field } => write!(formatter, "body/frontier token replay failed at {field}"),
            Self::RealizationHashMismatch => formatter.write_str("body/frontier realization seal does not replay"),
            Self::ReplayMismatch => formatter.write_str("body/frontier realization differs from canonical regeneration"),
        }
    }
}

impl std::error::Error for X64TailBodyFrontierError {}

impl From<X64TailSiteBindingError> for X64TailBodyFrontierError {
    fn from(value: X64TailSiteBindingError) -> Self {
        Self::SiteBinding(value)
    }
}

impl From<X64TailCandidateCapsuleError> for X64TailBodyFrontierError {
    fn from(value: X64TailCandidateCapsuleError) -> Self {
        Self::Capsule(value)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn emit_x64_tail_body_frontier_realization(
    target: &X64TargetArtifact,
    logical: &X64TailStatePlan,
    physical: &X64TailPhysicalAllocation,
    tail_templates: &X64TailTemplateRealization,
    capsule: &X64TailCandidateCapsule,
    binding: &X64TailSiteBindingProof,
) -> Result<X64TailBodyFrontierRealization, X64TailBodyFrontierError> {
    verify_x64_tail_site_binding_proof(
        binding,
        capsule,
        tail_templates,
        physical,
        logical,
        target,
    )?;
    construct_realization(target, logical, tail_templates, capsule, binding)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_x64_tail_body_frontier_realization<'realization>(
    realization: &'realization X64TailBodyFrontierRealization,
    binding: &X64TailSiteBindingProof,
    capsule: &X64TailCandidateCapsule,
    tail_templates: &X64TailTemplateRealization,
    physical: &X64TailPhysicalAllocation,
    logical: &X64TailStatePlan,
    target: &X64TargetArtifact,
) -> Result<VerifiedX64TailBodyFrontierRealization<'realization>, X64TailBodyFrontierError> {
    verify_x64_tail_site_binding_proof(
        binding,
        capsule,
        tail_templates,
        physical,
        logical,
        target,
    )?;
    validate_envelope(
        realization,
        target,
        logical,
        physical,
        tail_templates,
        capsule,
        binding,
    )?;
    if x64_tail_body_frontier_realization_hash(realization)? != realization.realization_hash {
        return Err(X64TailBodyFrontierError::RealizationHashMismatch);
    }
    audit_realization(realization, binding, capsule, tail_templates)?;
    let replayed = construct_realization(target, logical, tail_templates, capsule, binding)?;
    if replayed != *realization {
        return Err(X64TailBodyFrontierError::ReplayMismatch);
    }
    Ok(VerifiedX64TailBodyFrontierRealization { realization })
}

pub fn x64_tail_body_frontier_realization_hash(
    realization: &X64TailBodyFrontierRealization,
) -> Result<SemanticHash, X64TailBodyFrontierError> {
    Ok(SemanticHash(sha256(&realization_bytes_without_seal(
        realization,
    )?)))
}

fn construct_realization(
    target: &X64TargetArtifact,
    logical: &X64TailStatePlan,
    tail_templates: &X64TailTemplateRealization,
    capsule: &X64TailCandidateCapsule,
    binding: &X64TailSiteBindingProof,
) -> Result<X64TailBodyFrontierRealization, X64TailBodyFrontierError> {
    if binding
        .regions()
        .iter()
        .any(|region| region.status != X64TailSiteRegionStatus::Ready)
    {
        return Err(X64TailBodyFrontierError::Unsupported {
            field: "non-ready persistent region",
        });
    }
    let bounds_label = unique_owner_label(&target.program, X64LabelOwner::BoundsEpilogue)?;
    let return_label = unique_owner_label(&target.program, X64LabelOwner::ReturnEpilogue)?;
    let mut sites = Vec::with_capacity(binding.sites().len());
    for (ordinal, site) in binding.sites().iter().enumerate() {
        sites.push(lower_site(
            usize_to_u32(ordinal, "site ordinal")?,
            site,
            &target.program,
            binding.frontiers(),
            tail_templates,
            capsule,
        )?);
    }
    ensure_limit(
        "site programs",
        X64_TAIL_BODY_FRONTIER_MAX_SITE_PROGRAMS,
        sites.len(),
    )?;
    let frontiers = lower_frontiers(
        binding.frontiers(),
        &sites,
        &target.program,
        logical,
        bounds_label,
        return_label,
    )?;
    let mut work = 0_u64;
    audit_site_tokens(&sites, binding.sites(), &mut work)?;
    audit_frontier_programs(&frontiers, binding.frontiers(), &mut work)?;
    let totals = compute_totals(&sites, &frontiers, work)?;
    let mut realization = X64TailBodyFrontierRealization {
        schema_version: X64_TAIL_BODY_FRONTIER_SCHEMA_VERSION,
        policy_version: X64_TAIL_BODY_FRONTIER_POLICY_VERSION,
        source_target_semantic_hash: target.semantic_hash,
        source_logical_plan_hash: logical.plan_hash(),
        source_physical_allocation_hash: binding.source_physical_allocation_hash(),
        source_template_realization_hash: tail_templates.realization_hash(),
        source_candidate_capsule_hash: capsule.capsule_hash(),
        source_site_binding_hash: binding.proof_hash(),
        sites,
        frontiers,
        totals,
        realization_hash: SemanticHash::ZERO,
    };
    realization.realization_hash = x64_tail_body_frontier_realization_hash(&realization)?;
    Ok(realization)
}

fn lower_site(
    ordinal: u32,
    site: &X64TailSiteBinding,
    program: &X64TargetProgram,
    frontiers: &[X64TailFrontierBindingRow],
    tail_templates: &X64TailTemplateRealization,
    capsule: &X64TailCandidateCapsule,
) -> Result<X64TailBodySiteProgram, X64TailBodyFrontierError> {
    if !site.conflicts.is_empty() || !site.destructive_reuses.is_empty() {
        return Err(X64TailBodyFrontierError::Unsupported {
            field: "site alias or destructive reuse",
        });
    }
    let block = find_block(program, site.function, site.block)?;
    let mut builder = AtomBuilder::default();
    match site.position {
        X64TailTemplateSitePosition::Instruction(index) => {
            let instruction = block
                .instructions
                .get(u32_to_usize(index, "instruction index")?)
                .ok_or(X64TailBodyFrontierError::MissingTarget {
                    field: "site instruction",
                })?;
            lower_instruction_site(site, &instruction.kind, index, frontiers, &mut builder)?;
        }
        X64TailTemplateSitePosition::BranchCondition => {
            let X64Terminator::BranchRel32 { then_label, .. } = block.terminator else {
                return Err(X64TailBodyFrontierError::InvalidField {
                    field: "branch-condition terminator",
                });
            };
            require_counts(site, 1, 0, "branch condition")?;
            builder.push(X64TailBodyAtomInstruction::Acquire {
                read: site.reads[0],
                destination: X64TailBodyScratch::Rax,
            })?;
            builder.push(X64TailBodyAtomInstruction::TestBool)?;
            let target = edge_control_target(
                frontiers,
                site.label,
                then_label,
                X64TailFrontierBindingKind::BranchThen,
            )?;
            builder.push(X64TailBodyAtomInstruction::BranchNonZeroRel32 { target })?;
        }
        X64TailTemplateSitePosition::BranchElse => {
            let X64Terminator::BranchRel32 { else_label, .. } = block.terminator else {
                return Err(X64TailBodyFrontierError::InvalidField {
                    field: "branch-else terminator",
                });
            };
            require_counts(site, 0, 0, "branch else")?;
            let target = edge_control_target(
                frontiers,
                site.label,
                else_label,
                X64TailFrontierBindingKind::BranchElse,
            )?;
            builder.push(X64TailBodyAtomInstruction::JumpRel32 { target })?;
        }
        X64TailTemplateSitePosition::TailTransition { edge_ordinal } => {
            let receipt = capsule
                .transition_receipts()
                .iter()
                .find(|receipt| receipt.edge_ordinal == edge_ordinal)
                .ok_or(X64TailBodyFrontierError::MissingTarget {
                    field: "capsule transition receipt",
                })?;
            let transition = tail_templates
                .transitions()
                .iter()
                .find(|transition| transition.edge_ordinal == edge_ordinal)
                .ok_or(X64TailBodyFrontierError::MissingTarget {
                    field: "tail template transition",
                })?;
            builder.push_capsule(
                X64TailBodyAtomInstruction::CapsuleTransition {
                    edge_ordinal,
                    capsule_start: receipt.start,
                    capsule_end: receipt.end,
                },
                transition,
            )?;
        }
        X64TailTemplateSitePosition::TailFrontier { edge_ordinal } => {
            if site.template == X64TailProgramTemplateKind::RefusedTailFrontier {
                return Err(X64TailBodyFrontierError::Unsupported {
                    field: "refused tail frontier",
                });
            }
            let row = unique_frontier(frontiers, |row| {
                matches!(
                    row.kind,
                    X64TailFrontierBindingKind::MaterializedTail { edge_ordinal: candidate }
                        if candidate == edge_ordinal
                )
            })?;
            builder.push(X64TailBodyAtomInstruction::JumpRel32 {
                target: X64TailBodyControlTarget::Frontier(row.ordinal),
            })?;
        }
    }
    builder.finish_site(ordinal, site)
}

fn lower_instruction_site(
    site: &X64TailSiteBinding,
    instruction: &X64InstructionKind,
    instruction_index: u32,
    frontiers: &[X64TailFrontierBindingRow],
    builder: &mut AtomBuilder,
) -> Result<(), X64TailBodyFrontierError> {
    match instruction {
        X64InstructionKind::Move(_) => match site.template {
            X64TailProgramTemplateKind::MoveScalar => {
                if site.definitions.is_empty() && site.reads.is_empty() {
                    return Ok(());
                }
                require_counts(site, 1, 1, "scalar move")?;
                lower_copy(site.reads[0], site.definitions[0], builder)?;
            }
            X64TailProgramTemplateKind::MoveF64 => {
                require_counts(site, 1, 1, "F64 move")?;
                lower_copy(site.reads[0], site.definitions[0], builder)?;
            }
            X64TailProgramTemplateKind::MoveArrayPair => {
                require_counts(site, 2, 2, "array-pair move")?;
                for index in 0..2 {
                    lower_copy(site.reads[index], site.definitions[index], builder)?;
                }
            }
            _ => {
                return Err(X64TailBodyFrontierError::InvalidField {
                    field: "move template kind",
                });
            }
        },
        X64InstructionKind::I64Wrapping { opcode, .. } => {
            require_counts(site, 2, 1, "I64 wrapping")?;
            acquire_gpr_pair(site, builder)?;
            builder.push(X64TailBodyAtomInstruction::I64Wrapping {
                opcode: *opcode,
                definition: site.definitions[0].logical,
            })?;
            builder.push(X64TailBodyAtomInstruction::Define {
                source: X64TailBodyScratch::Rax,
                definition: site.definitions[0],
            })?;
        }
        X64InstructionKind::Sse2F64 { opcode, .. } => {
            require_counts(site, 2, 1, "SSE2 F64")?;
            builder.push(X64TailBodyAtomInstruction::Acquire {
                read: site.reads[0],
                destination: X64TailBodyScratch::Xmm0,
            })?;
            builder.push(X64TailBodyAtomInstruction::Acquire {
                read: site.reads[1],
                destination: X64TailBodyScratch::Xmm1,
            })?;
            builder.push(X64TailBodyAtomInstruction::Sse2F64 {
                opcode: *opcode,
                definition: site.definitions[0].logical,
            })?;
            builder.push(X64TailBodyAtomInstruction::Define {
                source: X64TailBodyScratch::Xmm0,
                definition: site.definitions[0],
            })?;
        }
        X64InstructionKind::I64Setcc { condition, .. } => {
            require_counts(site, 2, 1, "I64 setcc")?;
            acquire_gpr_pair(site, builder)?;
            builder.push(X64TailBodyAtomInstruction::I64Setcc {
                condition: *condition,
                definition: site.definitions[0].logical,
            })?;
            builder.push(X64TailBodyAtomInstruction::Define {
                source: X64TailBodyScratch::Rax,
                definition: site.definitions[0],
            })?;
        }
        X64InstructionKind::ArrayLenF64 { .. } => {
            require_counts(site, 2, 1, "F64 array length")?;
            lower_copy(site.reads[1], site.definitions[0], builder)?;
        }
        X64InstructionKind::ArrayGetF64Checked { .. } => {
            require_counts(site, 3, 1, "checked F64 array access")?;
            let bounds = unique_frontier(frontiers, |row| {
                row.source_label == Some(site.label)
                    && matches!(
                        row.kind,
                        X64TailFrontierBindingKind::Bounds { instruction }
                            if instruction == instruction_index
                    )
            })?;
            let target = X64TailBodyControlTarget::Frontier(bounds.ordinal);
            builder.push(X64TailBodyAtomInstruction::Acquire {
                read: site.reads[2],
                destination: X64TailBodyScratch::Rdx,
            })?;
            builder.push(X64TailBodyAtomInstruction::BoundsNegativeRel32 { target })?;
            builder.push(X64TailBodyAtomInstruction::Acquire {
                read: site.reads[1],
                destination: X64TailBodyScratch::Rcx,
            })?;
            builder.push(X64TailBodyAtomInstruction::BoundsUpperRel32 { target })?;
            builder.push(X64TailBodyAtomInstruction::Acquire {
                read: site.reads[0],
                destination: X64TailBodyScratch::Rax,
            })?;
            builder.push(X64TailBodyAtomInstruction::ArrayGetF64 {
                definition: site.definitions[0].logical,
            })?;
            builder.push(X64TailBodyAtomInstruction::Define {
                source: X64TailBodyScratch::Xmm0,
                definition: site.definitions[0],
            })?;
        }
    }
    Ok(())
}

fn lower_copy(
    read: X64TailBoundRead,
    definition: X64TailBoundDefinition,
    builder: &mut AtomBuilder,
) -> Result<(), X64TailBodyFrontierError> {
    let scratch = if definition.logical.word_type == X64TailWordType::F64 {
        X64TailBodyScratch::Xmm0
    } else {
        X64TailBodyScratch::Rax
    };
    builder.push(X64TailBodyAtomInstruction::Acquire {
        read,
        destination: scratch,
    })?;
    builder.push(X64TailBodyAtomInstruction::Define {
        source: scratch,
        definition,
    })?;
    Ok(())
}

fn acquire_gpr_pair(
    site: &X64TailSiteBinding,
    builder: &mut AtomBuilder,
) -> Result<(), X64TailBodyFrontierError> {
    builder.push(X64TailBodyAtomInstruction::Acquire {
        read: site.reads[0],
        destination: X64TailBodyScratch::Rax,
    })?;
    builder.push(X64TailBodyAtomInstruction::Acquire {
        read: site.reads[1],
        destination: X64TailBodyScratch::Rcx,
    })?;
    Ok(())
}

fn lower_frontiers(
    rows: &[X64TailFrontierBindingRow],
    sites: &[X64TailBodySiteProgram],
    program: &X64TargetProgram,
    logical: &X64TailStatePlan,
    bounds_label: X64LabelId,
    return_label: X64LabelId,
) -> Result<Vec<X64TailFrontierProgram>, X64TailBodyFrontierError> {
    let mut programs = Vec::with_capacity(rows.len());
    for row in rows {
        let alias = declared_alias(row, rows)?;
        if let Some(owner_ordinal) = alias {
            programs.push(X64TailFrontierProgram {
                row_ordinal: row.ordinal,
                kind: row.kind,
                action: row.action,
                placement: X64TailFrontierPlacement::EvidenceOnly,
                disposition: X64TailFrontierProgramDisposition::EvidenceAlias { owner_ordinal },
                atoms: Vec::new(),
                fixups: Vec::new(),
                prospective_bytes: 0,
            });
            continue;
        }
        if row.action == X64TailFrontierAction::Preserve {
            programs.push(empty_frontier(
                row,
                X64TailFrontierPlacement::EdgeStub,
                X64TailFrontierProgramDisposition::NoOp,
            ));
            continue;
        }
        if let X64TailFrontierBindingKind::PersistentTail { edge_ordinal } = row.kind {
            let site_ordinal = sites
                .iter()
                .find(|site| {
                    site.position == X64TailTemplateSitePosition::TailTransition { edge_ordinal }
                })
                .map(|site| site.ordinal)
                .ok_or(X64TailBodyFrontierError::MissingTarget {
                    field: "persistent transition site program",
                })?;
            programs.push(empty_frontier(
                row,
                X64TailFrontierPlacement::CapsuleReference,
                X64TailFrontierProgramDisposition::CapsuleReference { site_ordinal },
            ));
            continue;
        }
        if matches!(row.kind, X64TailFrontierBindingKind::RefusedTail { .. }) {
            return Err(X64TailBodyFrontierError::Unsupported {
                field: "refused tail frontier program",
            });
        }
        let placement = frontier_placement(row.kind);
        let mut builder = AtomBuilder::default();
        for word in &row.flush {
            builder.push(X64TailBodyAtomInstruction::AdapterFlush { word: *word })?;
        }
        if row.kind == X64TailFrontierBindingKind::Return {
            lower_return_transfer(row, program, &mut builder)?;
        }
        if let X64TailFrontierBindingKind::MaterializedTail { edge_ordinal } = row.kind {
            let edge = logical
                .edges()
                .iter()
                .find(|edge| edge.ordinal == edge_ordinal)
                .ok_or(X64TailBodyFrontierError::MissingTarget {
                    field: "materialized logical edge",
                })?;
            if !matches!(edge.disposition, X64TailEdgeDisposition::Materialize { .. }) {
                return Err(X64TailBodyFrontierError::InvalidField {
                    field: "materialized edge disposition",
                });
            }
            for step in &edge.schedule {
                match *step {
                    X64TailCopyStep::SaveScratch { source, scratch_id } => {
                        builder.push(X64TailBodyAtomInstruction::FrameScratchSave {
                            source,
                            scratch_id,
                        })?;
                    }
                    X64TailCopyStep::Move {
                        source,
                        destination,
                    } => {
                        builder.push(X64TailBodyAtomInstruction::FrameMove {
                            source,
                            destination,
                        })?;
                    }
                }
            }
        }
        for word in &row.hydrate {
            builder.push(X64TailBodyAtomInstruction::AdapterHydrate { word: *word })?;
        }
        if let Some(target) = frontier_continuation(row, bounds_label, return_label)? {
            builder.push(X64TailBodyAtomInstruction::JumpRel32 {
                target: X64TailBodyControlTarget::Label(target),
            })?;
        }
        programs.push(builder.finish_frontier(row, placement)?);
    }
    ensure_limit(
        "frontier programs",
        X64_TAIL_BODY_FRONTIER_MAX_FRONTIER_PROGRAMS,
        programs.len(),
    )?;
    Ok(programs)
}

fn lower_return_transfer(
    row: &X64TailFrontierBindingRow,
    program: &X64TargetProgram,
    builder: &mut AtomBuilder,
) -> Result<(), X64TailBodyFrontierError> {
    let source_label = row
        .source_label
        .ok_or(X64TailBodyFrontierError::MissingTarget {
            field: "return source label",
        })?;
    let block = program
        .functions
        .iter()
        .flat_map(|function| function.blocks.iter())
        .find(|block| block.label == source_label)
        .ok_or(X64TailBodyFrontierError::MissingTarget {
            field: "return source block",
        })?;
    let X64Terminator::Return { value, .. } = &block.terminator else {
        return Err(X64TailBodyFrontierError::InvalidField {
            field: "return frontier terminator",
        });
    };
    let zero = X64TailScheduledSource::Immediate(X64TailImmediateWord::I64(0));
    match value.ty() {
        MachineType::Unit => {
            builder.push(X64TailBodyAtomInstruction::ReturnWord {
                source: zero,
                destination: X64TailBodyScratch::Rax,
            })?;
            builder.push(X64TailBodyAtomInstruction::ReturnWord {
                source: zero,
                destination: X64TailBodyScratch::Rdx,
            })?;
        }
        MachineType::Bool | MachineType::I64 => {
            builder.push(X64TailBodyAtomInstruction::ReturnWord {
                source: return_scalar_source(value)?,
                destination: X64TailBodyScratch::Rax,
            })?;
            builder.push(X64TailBodyAtomInstruction::ReturnWord {
                source: zero,
                destination: X64TailBodyScratch::Rdx,
            })?;
        }
        MachineType::F64 => {
            builder.push(X64TailBodyAtomInstruction::ReturnWord {
                source: return_scalar_source(value)?,
                destination: X64TailBodyScratch::Rax,
            })?;
            builder.push(X64TailBodyAtomInstruction::MoveReturnF64BitsToXmm0)?;
            builder.push(X64TailBodyAtomInstruction::CanonicalizeReturnF64)?;
            builder.push(X64TailBodyAtomInstruction::ReturnWord {
                source: zero,
                destination: X64TailBodyScratch::Rdx,
            })?;
        }
        MachineType::F64Array => {
            let X64Operand::Home(home) = value else {
                return Err(X64TailBodyFrontierError::InvalidField {
                    field: "F64Array return home",
                });
            };
            if home.width != 16 {
                return Err(X64TailBodyFrontierError::InvalidField {
                    field: "F64Array return width",
                });
            }
            let length_offset =
                home.offset
                    .checked_add(8)
                    .ok_or(X64TailBodyFrontierError::ArithmeticOverflow {
                        field: "F64Array return length",
                    })?;
            builder.push(X64TailBodyAtomInstruction::ReturnWord {
                source: X64TailScheduledSource::Location(X64TailWordLocation {
                    offset: home.offset,
                    word_type: X64TailWordType::ArrayData,
                }),
                destination: X64TailBodyScratch::Rax,
            })?;
            builder.push(X64TailBodyAtomInstruction::ReturnWord {
                source: X64TailScheduledSource::Location(X64TailWordLocation {
                    offset: length_offset,
                    word_type: X64TailWordType::ArrayLength,
                }),
                destination: X64TailBodyScratch::Rdx,
            })?;
        }
    }
    Ok(())
}

fn return_scalar_source(
    value: &X64Operand,
) -> Result<X64TailScheduledSource, X64TailBodyFrontierError> {
    Ok(match value {
        X64Operand::Home(home) if home.width == 8 => {
            let word_type = match home.ty {
                MachineType::Bool => X64TailWordType::Bool,
                MachineType::I64 => X64TailWordType::I64,
                MachineType::F64 => X64TailWordType::F64,
                _ => {
                    return Err(X64TailBodyFrontierError::InvalidField {
                        field: "scalar return home type",
                    });
                }
            };
            X64TailScheduledSource::Location(X64TailWordLocation {
                offset: home.offset,
                word_type,
            })
        }
        X64Operand::Immediate {
            ty: MachineType::Bool,
            value: X64Immediate::Bool(value),
        } => X64TailScheduledSource::Immediate(X64TailImmediateWord::Bool(*value)),
        X64Operand::Immediate {
            ty: MachineType::I64,
            value: X64Immediate::I64(value),
        } => X64TailScheduledSource::Immediate(X64TailImmediateWord::I64(*value)),
        X64Operand::Immediate {
            ty: MachineType::F64,
            value: X64Immediate::F64Bits(bits),
        } => X64TailScheduledSource::Immediate(X64TailImmediateWord::F64Bits(*bits)),
        _ => {
            return Err(X64TailBodyFrontierError::InvalidField {
                field: "scalar return operand",
            });
        }
    })
}

fn declared_alias(
    row: &X64TailFrontierBindingRow,
    rows: &[X64TailFrontierBindingRow],
) -> Result<Option<u32>, X64TailBodyFrontierError> {
    let X64TailFrontierBindingKind::Declared { kind } = row.kind else {
        return Ok(None);
    };
    let owner = rows
        .iter()
        .take(u32_to_usize(row.ordinal, "frontier alias ordinal")?)
        .find(|candidate| {
            candidate.action == row.action
                && candidate.flush == row.flush
                && candidate.hydrate == row.hydrate
                && match (kind, candidate.kind) {
                    (
                        super::x64_tail_state_plan::X64TailFrontierKind::EntryAbi,
                        X64TailFrontierBindingKind::Entry,
                    ) => candidate.target_label == row.target_label,
                    (
                        super::x64_tail_state_plan::X64TailFrontierKind::Bounds,
                        X64TailFrontierBindingKind::Bounds { .. },
                    ) => candidate.source_label == row.source_label,
                    (
                        super::x64_tail_state_plan::X64TailFrontierKind::Return,
                        X64TailFrontierBindingKind::Return,
                    ) => candidate.source_label == row.source_label,
                    _ => false,
                }
        });
    Ok(owner.map(|owner| owner.ordinal))
}

fn edge_control_target(
    rows: &[X64TailFrontierBindingRow],
    source: X64LabelId,
    target: X64LabelId,
    kind: X64TailFrontierBindingKind,
) -> Result<X64TailBodyControlTarget, X64TailBodyFrontierError> {
    let row = unique_frontier(rows, |row| {
        row.kind == kind && row.source_label == Some(source) && row.target_label == Some(target)
    })?;
    Ok(if row.action == X64TailFrontierAction::Preserve {
        X64TailBodyControlTarget::Label(target)
    } else {
        X64TailBodyControlTarget::Frontier(row.ordinal)
    })
}

fn frontier_placement(kind: X64TailFrontierBindingKind) -> X64TailFrontierPlacement {
    match kind {
        X64TailFrontierBindingKind::Entry | X64TailFrontierBindingKind::Declared { .. } => {
            X64TailFrontierPlacement::BeforeLabel
        }
        X64TailFrontierBindingKind::Bounds { .. } => X64TailFrontierPlacement::CheckedExit,
        X64TailFrontierBindingKind::Return => X64TailFrontierPlacement::ExitStub,
        X64TailFrontierBindingKind::BranchThen
        | X64TailFrontierBindingKind::BranchElse
        | X64TailFrontierBindingKind::MaterializedTail { .. }
        | X64TailFrontierBindingKind::RefusedTail { .. } => X64TailFrontierPlacement::EdgeStub,
        X64TailFrontierBindingKind::PersistentTail { .. } => {
            X64TailFrontierPlacement::CapsuleReference
        }
    }
}

fn frontier_continuation(
    row: &X64TailFrontierBindingRow,
    bounds_label: X64LabelId,
    return_label: X64LabelId,
) -> Result<Option<X64LabelId>, X64TailBodyFrontierError> {
    Ok(match row.kind {
        X64TailFrontierBindingKind::BranchThen
        | X64TailFrontierBindingKind::BranchElse
        | X64TailFrontierBindingKind::MaterializedTail { .. }
        | X64TailFrontierBindingKind::RefusedTail { .. } => Some(row.target_label.ok_or(
            X64TailBodyFrontierError::MissingTarget {
                field: "frontier continuation label",
            },
        )?),
        X64TailFrontierBindingKind::Bounds { .. } => Some(bounds_label),
        X64TailFrontierBindingKind::Return => Some(return_label),
        X64TailFrontierBindingKind::Entry
        | X64TailFrontierBindingKind::PersistentTail { .. }
        | X64TailFrontierBindingKind::Declared { .. } => None,
    })
}

fn empty_frontier(
    row: &X64TailFrontierBindingRow,
    placement: X64TailFrontierPlacement,
    disposition: X64TailFrontierProgramDisposition,
) -> X64TailFrontierProgram {
    X64TailFrontierProgram {
        row_ordinal: row.ordinal,
        kind: row.kind,
        action: row.action,
        placement,
        disposition,
        atoms: Vec::new(),
        fixups: Vec::new(),
        prospective_bytes: 0,
    }
}

#[derive(Default)]
struct AtomBuilder {
    atoms: Vec<X64TailBodyAtom>,
    fixups: Vec<X64TailBodyFixup>,
    cursor: u32,
}

impl AtomBuilder {
    fn push(
        &mut self,
        instruction: X64TailBodyAtomInstruction,
    ) -> Result<u32, X64TailBodyFrontierError> {
        let ordinal = usize_to_u32(self.atoms.len(), "body atom ordinal")?;
        let start = self.cursor;
        let length = instruction.prospective_len()?;
        let end =
            start
                .checked_add(length)
                .ok_or(X64TailBodyFrontierError::ArithmeticOverflow {
                    field: "body atom end",
                })?;
        let clobbers = instruction_clobbers(instruction)?;
        self.atoms.push(X64TailBodyAtom {
            ordinal,
            start,
            end,
            instruction,
            clobbers,
        });
        if let Some((relative_patch, target)) = instruction_fixup(instruction)? {
            let patch_offset = start.checked_add(relative_patch).ok_or(
                X64TailBodyFrontierError::ArithmeticOverflow {
                    field: "body fixup offset",
                },
            )?;
            self.fixups.push(X64TailBodyFixup {
                atom_ordinal: ordinal,
                patch_offset,
                target,
                width: 4,
                addend: 0,
            });
        }
        self.cursor = end;
        Ok(ordinal)
    }

    fn push_capsule(
        &mut self,
        instruction: X64TailBodyAtomInstruction,
        transition: &super::x64_tail_template_realization::X64TailTemplateTransition,
    ) -> Result<(), X64TailBodyFrontierError> {
        let ordinal = self.push(instruction)?;
        let atom = self
            .atoms
            .last_mut()
            .ok_or(X64TailBodyFrontierError::MissingTarget {
                field: "capsule atom",
            })?;
        let mut clobbers = transition
            .atoms
            .iter()
            .flat_map(|atom| atom.clobbers.iter().copied())
            .collect::<Vec<_>>();
        clobbers.sort_unstable();
        clobbers.dedup();
        atom.clobbers = clobbers;
        for fixup in &transition.fixups {
            self.fixups.push(X64TailBodyFixup {
                atom_ordinal: ordinal,
                patch_offset: atom.start.checked_add(fixup.patch_offset).ok_or(
                    X64TailBodyFrontierError::ArithmeticOverflow {
                        field: "capsule fixup offset",
                    },
                )?,
                target: X64TailBodyControlTarget::Label(fixup.target),
                width: fixup.width,
                addend: fixup.addend,
            });
        }
        Ok(())
    }

    fn finish_site(
        self,
        ordinal: u32,
        source: &X64TailSiteBinding,
    ) -> Result<X64TailBodySiteProgram, X64TailBodyFrontierError> {
        ensure_limit(
            "atoms per site",
            X64_TAIL_BODY_FRONTIER_MAX_ATOMS_PER_SITE,
            self.atoms.len(),
        )?;
        Ok(X64TailBodySiteProgram {
            ordinal,
            region: source.region,
            function: source.function,
            block: source.block,
            label: source.label,
            position: source.position,
            template: source.template,
            atoms: self.atoms,
            fixups: self.fixups,
            prospective_bytes: self.cursor,
        })
    }

    fn finish_frontier(
        self,
        row: &X64TailFrontierBindingRow,
        placement: X64TailFrontierPlacement,
    ) -> Result<X64TailFrontierProgram, X64TailBodyFrontierError> {
        ensure_limit(
            "atoms per frontier",
            X64_TAIL_BODY_FRONTIER_MAX_ATOMS_PER_FRONTIER,
            self.atoms.len(),
        )?;
        Ok(X64TailFrontierProgram {
            row_ordinal: row.ordinal,
            kind: row.kind,
            action: row.action,
            placement,
            disposition: X64TailFrontierProgramDisposition::Operational,
            atoms: self.atoms,
            fixups: self.fixups,
            prospective_bytes: self.cursor,
        })
    }
}

fn require_counts(
    site: &X64TailSiteBinding,
    reads: usize,
    definitions: usize,
    field: &'static str,
) -> Result<(), X64TailBodyFrontierError> {
    if site.reads.len() != reads || site.definitions.len() != definitions {
        return Err(X64TailBodyFrontierError::InvalidField { field });
    }
    Ok(())
}

fn unique_frontier(
    rows: &[X64TailFrontierBindingRow],
    predicate: impl Fn(&X64TailFrontierBindingRow) -> bool,
) -> Result<&X64TailFrontierBindingRow, X64TailBodyFrontierError> {
    let mut matches = rows.iter().filter(|row| predicate(row));
    let row = matches
        .next()
        .ok_or(X64TailBodyFrontierError::MissingTarget {
            field: "unique frontier row",
        })?;
    if matches.next().is_some() {
        return Err(X64TailBodyFrontierError::InvalidField {
            field: "unique frontier row",
        });
    }
    Ok(row)
}

fn find_block(
    program: &X64TargetProgram,
    function: X64FunctionId,
    block: X64BlockId,
) -> Result<&X64Block, X64TailBodyFrontierError> {
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
        .ok_or(X64TailBodyFrontierError::MissingTarget {
            field: "source block",
        })
}

fn unique_owner_label(
    program: &X64TargetProgram,
    owner: X64LabelOwner,
) -> Result<X64LabelId, X64TailBodyFrontierError> {
    let mut labels = program
        .labels
        .iter()
        .filter(|label| label.owner == owner)
        .map(|label| label.id);
    let label = labels
        .next()
        .ok_or(X64TailBodyFrontierError::MissingTarget {
            field: "epilogue label",
        })?;
    if labels.next().is_some() {
        return Err(X64TailBodyFrontierError::InvalidField {
            field: "unique epilogue label",
        });
    }
    Ok(label)
}

fn acquire_len(
    read: X64TailBoundRead,
    destination: X64TailBodyScratch,
) -> Result<u32, X64TailBodyFrontierError> {
    let word_type = bound_read_word_type(read);
    if destination.is_gpr() == (word_type == X64TailWordType::F64) {
        return Err(X64TailBodyFrontierError::InvalidField {
            field: "typed scratch acquisition",
        });
    }
    Ok(match (read, destination.is_gpr()) {
        (X64TailBoundRead::Immediate(_), true) => 10,
        (X64TailBoundRead::Immediate(X64TailImmediateWord::F64Bits(_)), false) => 15,
        (X64TailBoundRead::Immediate(_), false) => {
            return Err(X64TailBodyFrontierError::InvalidField {
                field: "XMM immediate acquisition",
            });
        }
        (X64TailBoundRead::Location { physical, .. }, true) => match physical {
            X64TailPhysicalLocation::Register { .. } => 3,
            X64TailPhysicalLocation::Frame(_) => 8,
        },
        (X64TailBoundRead::Location { physical, .. }, false) => match physical {
            X64TailPhysicalLocation::Register { .. } => 4,
            X64TailPhysicalLocation::Frame(_) => 9,
        },
    })
}

fn define_len(
    source: X64TailBodyScratch,
    definition: X64TailBoundDefinition,
) -> Result<u32, X64TailBodyFrontierError> {
    if source.is_gpr() == (definition.logical.word_type == X64TailWordType::F64)
        || definition.logical.word_type != definition.physical.word_type()
    {
        return Err(X64TailBodyFrontierError::InvalidField {
            field: "typed definition scratch",
        });
    }
    Ok(match (definition.physical, source.is_gpr()) {
        (X64TailPhysicalLocation::Register { .. }, true) => 3,
        (X64TailPhysicalLocation::Frame(_), true) => 8,
        (X64TailPhysicalLocation::Register { .. }, false) => 4,
        (X64TailPhysicalLocation::Frame(_), false) => 9,
    })
}

const fn adapter_len(word_type: X64TailWordType) -> u32 {
    if matches!(word_type, X64TailWordType::F64) {
        9
    } else {
        8
    }
}

fn frame_move_len(
    source: X64TailScheduledSource,
    destination: X64TailWordLocation,
) -> Result<u32, X64TailBodyFrontierError> {
    if scheduled_word_type(source) != destination.word_type {
        return Err(X64TailBodyFrontierError::InvalidField {
            field: "typed frame tail move",
        });
    }
    Ok(match source {
        X64TailScheduledSource::Location(location) => adapter_len(location.word_type)
            .checked_add(adapter_len(destination.word_type))
            .ok_or(X64TailBodyFrontierError::ArithmeticOverflow {
                field: "frame move length",
            })?,
        X64TailScheduledSource::Immediate(_) => 18,
        X64TailScheduledSource::Scratch { .. } => adapter_len(destination.word_type),
    })
}

fn return_word_len(
    source: X64TailScheduledSource,
    destination: X64TailBodyScratch,
) -> Result<u32, X64TailBodyFrontierError> {
    if !matches!(
        destination,
        X64TailBodyScratch::Rax | X64TailBodyScratch::Rdx
    ) {
        return Err(X64TailBodyFrontierError::InvalidField {
            field: "return word destination",
        });
    }
    Ok(match source {
        X64TailScheduledSource::Location(_) => 8,
        X64TailScheduledSource::Immediate(value) => {
            if return_immediate_bits(value) == 0 {
                2
            } else {
                10
            }
        }
        X64TailScheduledSource::Scratch { .. } => {
            return Err(X64TailBodyFrontierError::InvalidField {
                field: "return scratch source",
            });
        }
    })
}

const fn return_immediate_bits(value: X64TailImmediateWord) -> u64 {
    match value {
        X64TailImmediateWord::Bool(value) => value as u64,
        X64TailImmediateWord::I64(value) => value as u64,
        X64TailImmediateWord::F64Bits(bits) => bits,
    }
}

const fn bound_read_word_type(read: X64TailBoundRead) -> X64TailWordType {
    match read {
        X64TailBoundRead::Immediate(X64TailImmediateWord::Bool(_)) => X64TailWordType::Bool,
        X64TailBoundRead::Immediate(X64TailImmediateWord::I64(_)) => X64TailWordType::I64,
        X64TailBoundRead::Immediate(X64TailImmediateWord::F64Bits(_)) => X64TailWordType::F64,
        X64TailBoundRead::Location { logical, .. } => logical.word_type,
    }
}

const fn scheduled_word_type(source: X64TailScheduledSource) -> X64TailWordType {
    match source {
        X64TailScheduledSource::Location(location) => location.word_type,
        X64TailScheduledSource::Immediate(X64TailImmediateWord::Bool(_)) => X64TailWordType::Bool,
        X64TailScheduledSource::Immediate(X64TailImmediateWord::I64(_)) => X64TailWordType::I64,
        X64TailScheduledSource::Immediate(X64TailImmediateWord::F64Bits(_)) => X64TailWordType::F64,
        X64TailScheduledSource::Scratch { word_type, .. } => word_type,
    }
}

fn instruction_clobbers(
    instruction: X64TailBodyAtomInstruction,
) -> Result<Vec<X64TailTemplateRegister>, X64TailBodyFrontierError> {
    let mut clobbers = match instruction {
        X64TailBodyAtomInstruction::Acquire { read, destination } => {
            let mut values = vec![destination.register()];
            if matches!(
                read,
                X64TailBoundRead::Immediate(X64TailImmediateWord::F64Bits(_))
            ) && !destination.is_gpr()
            {
                values.push(X64TailTemplateRegister::Rax);
            }
            values
        }
        X64TailBodyAtomInstruction::Define { definition, .. } => match definition.physical {
            X64TailPhysicalLocation::Register { register, .. } => {
                vec![physical_template_register(register)]
            }
            X64TailPhysicalLocation::Frame(_) => Vec::new(),
        },
        X64TailBodyAtomInstruction::I64Wrapping { .. } => {
            vec![X64TailTemplateRegister::Rax, X64TailTemplateRegister::Flags]
        }
        X64TailBodyAtomInstruction::Sse2F64 { .. } => vec![X64TailTemplateRegister::Xmm0],
        X64TailBodyAtomInstruction::I64Setcc { .. } => {
            vec![X64TailTemplateRegister::Rax, X64TailTemplateRegister::Flags]
        }
        X64TailBodyAtomInstruction::TestBool
        | X64TailBodyAtomInstruction::BoundsNegativeRel32 { .. }
        | X64TailBodyAtomInstruction::BoundsUpperRel32 { .. } => {
            vec![X64TailTemplateRegister::Flags]
        }
        X64TailBodyAtomInstruction::ArrayGetF64 { .. } => {
            vec![X64TailTemplateRegister::Xmm0]
        }
        X64TailBodyAtomInstruction::AdapterHydrate { word } => {
            vec![physical_template_register(word.register)]
        }
        X64TailBodyAtomInstruction::FrameScratchSave { source, .. } => {
            vec![if source.word_type == X64TailWordType::F64 {
                X64TailTemplateRegister::Xmm0
            } else {
                X64TailTemplateRegister::Rax
            }]
        }
        X64TailBodyAtomInstruction::FrameMove { source, .. } => match source {
            X64TailScheduledSource::Scratch { .. } => Vec::new(),
            X64TailScheduledSource::Location(X64TailWordLocation { word_type, .. }) => {
                vec![if word_type == X64TailWordType::F64 {
                    X64TailTemplateRegister::Xmm1
                } else {
                    X64TailTemplateRegister::Rcx
                }]
            }
            X64TailScheduledSource::Immediate(_) => vec![X64TailTemplateRegister::Rcx],
        },
        X64TailBodyAtomInstruction::ReturnWord { destination, .. } => {
            vec![destination.register()]
        }
        X64TailBodyAtomInstruction::MoveReturnF64BitsToXmm0 => {
            vec![X64TailTemplateRegister::Xmm0]
        }
        X64TailBodyAtomInstruction::CanonicalizeReturnF64 => vec![
            X64TailTemplateRegister::Rax,
            X64TailTemplateRegister::Rcx,
            X64TailTemplateRegister::Xmm0,
            X64TailTemplateRegister::Flags,
        ],
        X64TailBodyAtomInstruction::BranchNonZeroRel32 { .. }
        | X64TailBodyAtomInstruction::JumpRel32 { .. }
        | X64TailBodyAtomInstruction::AdapterFlush { .. }
        | X64TailBodyAtomInstruction::CapsuleTransition { .. } => Vec::new(),
    };
    clobbers.sort_unstable();
    clobbers.dedup();
    Ok(clobbers)
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

fn instruction_fixup(
    instruction: X64TailBodyAtomInstruction,
) -> Result<Option<(u32, X64TailBodyControlTarget)>, X64TailBodyFrontierError> {
    Ok(match instruction {
        X64TailBodyAtomInstruction::BranchNonZeroRel32 { target } => Some((2, target)),
        X64TailBodyAtomInstruction::JumpRel32 { target } => Some((1, target)),
        X64TailBodyAtomInstruction::BoundsNegativeRel32 { target }
        | X64TailBodyAtomInstruction::BoundsUpperRel32 { target } => Some((5, target)),
        _ => None,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SymbolicToken {
    Immediate(X64TailImmediateWord),
    Logical(X64TailWordLocation),
}

fn audit_site_tokens(
    programs: &[X64TailBodySiteProgram],
    sources: &[X64TailSiteBinding],
    work: &mut u64,
) -> Result<(), X64TailBodyFrontierError> {
    if programs.len() != sources.len() {
        return Err(X64TailBodyFrontierError::InvalidField {
            field: "site/source cardinality",
        });
    }
    for (program, source) in programs.iter().zip(sources) {
        charge(work, 1, "site replay")?;
        audit_atom_layout(&program.atoms, &program.fixups, program.prospective_bytes)?;
        let mut physical = source
            .live_before
            .iter()
            .map(|binding| (binding.physical, SymbolicToken::Logical(binding.logical)))
            .collect::<BTreeMap<_, _>>();
        let mut scratch = BTreeMap::<X64TailBodyScratch, SymbolicToken>::new();
        for atom in &program.atoms {
            charge(work, 1, "site atom replay")?;
            match atom.instruction {
                X64TailBodyAtomInstruction::Acquire { read, destination } => {
                    let token = match read {
                        X64TailBoundRead::Immediate(value) => SymbolicToken::Immediate(value),
                        X64TailBoundRead::Location {
                            logical,
                            physical: location,
                        } => {
                            if physical.get(&location) != Some(&SymbolicToken::Logical(logical)) {
                                return Err(X64TailBodyFrontierError::TokenMismatch {
                                    field: "site acquisition",
                                });
                            }
                            SymbolicToken::Logical(logical)
                        }
                    };
                    scratch.insert(destination, token);
                }
                X64TailBodyAtomInstruction::Define { source, definition } => {
                    if !scratch.contains_key(&source) {
                        return Err(X64TailBodyFrontierError::TokenMismatch {
                            field: "definition scratch",
                        });
                    }
                    physical.insert(
                        definition.physical,
                        SymbolicToken::Logical(definition.logical),
                    );
                }
                X64TailBodyAtomInstruction::I64Wrapping { definition, .. }
                | X64TailBodyAtomInstruction::I64Setcc { definition, .. } => {
                    require_scratch(&scratch, X64TailBodyScratch::Rax, "I64 left")?;
                    require_scratch(&scratch, X64TailBodyScratch::Rcx, "I64 right")?;
                    scratch.insert(X64TailBodyScratch::Rax, SymbolicToken::Logical(definition));
                }
                X64TailBodyAtomInstruction::Sse2F64 { definition, .. } => {
                    require_scratch(&scratch, X64TailBodyScratch::Xmm0, "F64 left")?;
                    require_scratch(&scratch, X64TailBodyScratch::Xmm1, "F64 right")?;
                    scratch.insert(X64TailBodyScratch::Xmm0, SymbolicToken::Logical(definition));
                }
                X64TailBodyAtomInstruction::TestBool => {
                    require_scratch(&scratch, X64TailBodyScratch::Rax, "branch condition")?;
                }
                X64TailBodyAtomInstruction::BoundsNegativeRel32 { .. } => {
                    require_scratch(&scratch, X64TailBodyScratch::Rdx, "negative bound index")?;
                }
                X64TailBodyAtomInstruction::BoundsUpperRel32 { .. } => {
                    require_scratch(&scratch, X64TailBodyScratch::Rdx, "upper bound index")?;
                    require_scratch(&scratch, X64TailBodyScratch::Rcx, "upper bound length")?;
                }
                X64TailBodyAtomInstruction::ArrayGetF64 { definition } => {
                    require_scratch(&scratch, X64TailBodyScratch::Rax, "array data")?;
                    require_scratch(&scratch, X64TailBodyScratch::Rdx, "array index")?;
                    scratch.insert(X64TailBodyScratch::Xmm0, SymbolicToken::Logical(definition));
                }
                X64TailBodyAtomInstruction::BranchNonZeroRel32 { .. }
                | X64TailBodyAtomInstruction::JumpRel32 { .. }
                | X64TailBodyAtomInstruction::CapsuleTransition { .. } => {}
                X64TailBodyAtomInstruction::AdapterFlush { .. }
                | X64TailBodyAtomInstruction::AdapterHydrate { .. }
                | X64TailBodyAtomInstruction::FrameScratchSave { .. }
                | X64TailBodyAtomInstruction::FrameMove { .. }
                | X64TailBodyAtomInstruction::ReturnWord { .. }
                | X64TailBodyAtomInstruction::MoveReturnF64BitsToXmm0
                | X64TailBodyAtomInstruction::CanonicalizeReturnF64 => {
                    return Err(X64TailBodyFrontierError::InvalidField {
                        field: "frontier atom inside site",
                    });
                }
            }
        }
        for expected in &source.live_after {
            if physical.get(&expected.physical) != Some(&SymbolicToken::Logical(expected.logical)) {
                return Err(X64TailBodyFrontierError::TokenMismatch {
                    field: "site live-after",
                });
            }
        }
    }
    Ok(())
}

fn audit_frontier_programs(
    programs: &[X64TailFrontierProgram],
    rows: &[X64TailFrontierBindingRow],
    work: &mut u64,
) -> Result<(), X64TailBodyFrontierError> {
    if programs.len() != rows.len() {
        return Err(X64TailBodyFrontierError::InvalidField {
            field: "frontier/source cardinality",
        });
    }
    for (program, row) in programs.iter().zip(rows) {
        charge(work, 1, "frontier replay")?;
        if program.row_ordinal != row.ordinal
            || program.kind != row.kind
            || program.action != row.action
        {
            return Err(X64TailBodyFrontierError::InvalidField {
                field: "frontier identity",
            });
        }
        audit_atom_layout(&program.atoms, &program.fixups, program.prospective_bytes)?;
        if let X64TailFrontierProgramDisposition::EvidenceAlias { owner_ordinal } =
            program.disposition
        {
            if owner_ordinal >= program.row_ordinal || !program.atoms.is_empty() {
                return Err(X64TailBodyFrontierError::InvalidField {
                    field: "frontier evidence alias",
                });
            }
        }
        let actual_flush = program
            .atoms
            .iter()
            .filter_map(|atom| match atom.instruction {
                X64TailBodyAtomInstruction::AdapterFlush { word } => Some(word),
                _ => None,
            })
            .collect::<Vec<_>>();
        let actual_hydrate = program
            .atoms
            .iter()
            .filter_map(|atom| match atom.instruction {
                X64TailBodyAtomInstruction::AdapterHydrate { word } => Some(word),
                _ => None,
            })
            .collect::<Vec<_>>();
        if matches!(
            program.disposition,
            X64TailFrontierProgramDisposition::Operational
        ) && (actual_flush != row.flush || actual_hydrate != row.hydrate)
        {
            return Err(X64TailBodyFrontierError::TokenMismatch {
                field: "frontier adapter words",
            });
        }
        let mut frame = BTreeMap::<X64TailWordLocation, SymbolicToken>::new();
        let mut registers = BTreeMap::<X64TailPhysicalRegister, SymbolicToken>::new();
        let mut tail_scratch = BTreeMap::<u32, (SymbolicToken, X64TailWordType)>::new();
        let mut live_gpr_tail_scratch = None;
        let mut live_xmm_tail_scratch = None;
        for word in &row.flush {
            registers.insert(word.register, SymbolicToken::Logical(word.logical));
        }
        for word in &row.hydrate {
            frame.insert(word.logical, SymbolicToken::Logical(word.logical));
        }
        for atom in &program.atoms {
            charge(work, 1, "frontier atom replay")?;
            if live_gpr_tail_scratch.is_some()
                && atom.clobbers.contains(&X64TailTemplateRegister::Rax)
            {
                return Err(X64TailBodyFrontierError::TokenMismatch {
                    field: "live GPR tail scratch clobber",
                });
            }
            if live_xmm_tail_scratch.is_some()
                && atom.clobbers.contains(&X64TailTemplateRegister::Xmm0)
            {
                return Err(X64TailBodyFrontierError::TokenMismatch {
                    field: "live XMM tail scratch clobber",
                });
            }
            match atom.instruction {
                X64TailBodyAtomInstruction::AdapterFlush { word } => {
                    if registers.get(&word.register) != Some(&SymbolicToken::Logical(word.logical))
                    {
                        return Err(X64TailBodyFrontierError::TokenMismatch {
                            field: "frontier flush source",
                        });
                    }
                    frame.insert(word.logical, SymbolicToken::Logical(word.logical));
                }
                X64TailBodyAtomInstruction::AdapterHydrate { word } => {
                    if frame.get(&word.logical) != Some(&SymbolicToken::Logical(word.logical)) {
                        return Err(X64TailBodyFrontierError::TokenMismatch {
                            field: "frontier hydrate source",
                        });
                    }
                    registers.insert(word.register, SymbolicToken::Logical(word.logical));
                }
                X64TailBodyAtomInstruction::FrameScratchSave { source, scratch_id } => {
                    let token = frame
                        .get(&source)
                        .copied()
                        .unwrap_or(SymbolicToken::Logical(source));
                    let live = if source.word_type == X64TailWordType::F64 {
                        &mut live_xmm_tail_scratch
                    } else {
                        &mut live_gpr_tail_scratch
                    };
                    if live.replace(scratch_id).is_some()
                        || tail_scratch
                            .insert(scratch_id, (token, source.word_type))
                            .is_some()
                    {
                        return Err(X64TailBodyFrontierError::TokenMismatch {
                            field: "unique live tail scratch",
                        });
                    }
                }
                X64TailBodyAtomInstruction::FrameMove {
                    source,
                    destination,
                } => {
                    match source {
                        X64TailScheduledSource::Location(location) => {
                            let _ = frame
                                .get(&location)
                                .copied()
                                .unwrap_or(SymbolicToken::Logical(location));
                        }
                        X64TailScheduledSource::Immediate(_) => {}
                        X64TailScheduledSource::Scratch { id, word_type } => {
                            let (_, saved_type) = tail_scratch.remove(&id).ok_or(
                                X64TailBodyFrontierError::TokenMismatch {
                                    field: "materialized tail scratch read",
                                },
                            )?;
                            if saved_type != word_type {
                                return Err(X64TailBodyFrontierError::TokenMismatch {
                                    field: "materialized tail scratch type",
                                });
                            }
                            let live = if word_type == X64TailWordType::F64 {
                                &mut live_xmm_tail_scratch
                            } else {
                                &mut live_gpr_tail_scratch
                            };
                            if live.take() != Some(id) {
                                return Err(X64TailBodyFrontierError::TokenMismatch {
                                    field: "materialized physical tail scratch identity",
                                });
                            }
                        }
                    }
                    frame.insert(destination, SymbolicToken::Logical(destination));
                }
                X64TailBodyAtomInstruction::ReturnWord { .. }
                | X64TailBodyAtomInstruction::MoveReturnF64BitsToXmm0
                | X64TailBodyAtomInstruction::CanonicalizeReturnF64
                    if program.kind == X64TailFrontierBindingKind::Return => {}
                X64TailBodyAtomInstruction::JumpRel32 { .. } => {}
                _ => {
                    return Err(X64TailBodyFrontierError::InvalidField {
                        field: "body atom inside frontier",
                    });
                }
            }
        }
        if !tail_scratch.is_empty()
            || live_gpr_tail_scratch.is_some()
            || live_xmm_tail_scratch.is_some()
        {
            return Err(X64TailBodyFrontierError::TokenMismatch {
                field: "unconsumed materialized tail scratch",
            });
        }
        let first_hydrate = program.atoms.iter().position(|atom| {
            matches!(
                atom.instruction,
                X64TailBodyAtomInstruction::AdapterHydrate { .. }
            )
        });
        let last_flush = program.atoms.iter().rposition(|atom| {
            matches!(
                atom.instruction,
                X64TailBodyAtomInstruction::AdapterFlush { .. }
            )
        });
        if matches!((last_flush, first_hydrate), (Some(flush), Some(hydrate)) if flush >= hydrate) {
            return Err(X64TailBodyFrontierError::TokenMismatch {
                field: "flush-before-hydrate order",
            });
        }
    }
    Ok(())
}

fn audit_atom_layout(
    atoms: &[X64TailBodyAtom],
    fixups: &[X64TailBodyFixup],
    prospective_bytes: u32,
) -> Result<(), X64TailBodyFrontierError> {
    let mut cursor = 0_u32;
    let mut expected_fixups = Vec::new();
    for (index, atom) in atoms.iter().enumerate() {
        let ordinal = usize_to_u32(index, "audit atom ordinal")?;
        let end = cursor
            .checked_add(atom.instruction.prospective_len()?)
            .ok_or(X64TailBodyFrontierError::ArithmeticOverflow {
                field: "audit atom end",
            })?;
        if atom.ordinal != ordinal
            || atom.start != cursor
            || atom.end != end
            || (!matches!(
                atom.instruction,
                X64TailBodyAtomInstruction::CapsuleTransition { .. }
            ) && atom.clobbers != instruction_clobbers(atom.instruction)?)
        {
            return Err(X64TailBodyFrontierError::InvalidField {
                field: "canonical atom layout",
            });
        }
        if let Some((relative, target)) = instruction_fixup(atom.instruction)? {
            expected_fixups.push(X64TailBodyFixup {
                atom_ordinal: ordinal,
                patch_offset: cursor.checked_add(relative).ok_or(
                    X64TailBodyFrontierError::ArithmeticOverflow {
                        field: "audit fixup offset",
                    },
                )?,
                target,
                width: 4,
                addend: 0,
            });
        }
        cursor = end;
    }
    let mut ordinary_fixups = Vec::new();
    for fixup in fixups {
        let atom = atoms
            .get(u32_to_usize(fixup.atom_ordinal, "fixup atom ordinal")?)
            .ok_or(X64TailBodyFrontierError::InvalidField {
                field: "fixup atom",
            })?;
        if !matches!(
            atom.instruction,
            X64TailBodyAtomInstruction::CapsuleTransition { .. }
        ) {
            ordinary_fixups.push(*fixup);
        }
    }
    if cursor != prospective_bytes || ordinary_fixups != expected_fixups {
        return Err(X64TailBodyFrontierError::InvalidField {
            field: "atom layout/fixups",
        });
    }
    Ok(())
}

fn require_scratch(
    scratch: &BTreeMap<X64TailBodyScratch, SymbolicToken>,
    register: X64TailBodyScratch,
    field: &'static str,
) -> Result<(), X64TailBodyFrontierError> {
    if scratch.contains_key(&register) {
        Ok(())
    } else {
        Err(X64TailBodyFrontierError::TokenMismatch { field })
    }
}

fn compute_totals(
    sites: &[X64TailBodySiteProgram],
    frontiers: &[X64TailFrontierProgram],
    replay_work: u64,
) -> Result<X64TailBodyFrontierTotals, X64TailBodyFrontierError> {
    let mut totals = X64TailBodyFrontierTotals {
        site_programs: usize_to_u32(sites.len(), "site total")?,
        frontier_programs: usize_to_u32(frontiers.len(), "frontier total")?,
        replay_work,
        ..X64TailBodyFrontierTotals::default()
    };
    for site in sites {
        totals.body_prospective_bytes = checked_add_u64(
            totals.body_prospective_bytes,
            u64::from(site.prospective_bytes),
            "body prospective bytes",
        )?;
        for atom in &site.atoms {
            totals.atoms = checked_add_u32(totals.atoms, 1, "atom total")?;
            if matches!(
                atom.instruction,
                X64TailBodyAtomInstruction::CapsuleTransition { .. }
            ) {
                totals.retained_capsule_bytes = checked_add_u64(
                    totals.retained_capsule_bytes,
                    u64::from(atom.end - atom.start),
                    "retained capsule bytes",
                )?;
            }
        }
        totals.fixups = checked_add_u32(
            totals.fixups,
            usize_to_u32(site.fixups.len(), "site fixups")?,
            "fixup total",
        )?;
    }
    for frontier in frontiers {
        match frontier.disposition {
            X64TailFrontierProgramDisposition::Operational => {
                totals.operational_frontiers =
                    checked_add_u32(totals.operational_frontiers, 1, "operational frontiers")?;
            }
            X64TailFrontierProgramDisposition::NoOp => {
                totals.noop_frontiers =
                    checked_add_u32(totals.noop_frontiers, 1, "noop frontiers")?;
            }
            X64TailFrontierProgramDisposition::CapsuleReference { .. } => {
                totals.capsule_frontiers =
                    checked_add_u32(totals.capsule_frontiers, 1, "capsule frontiers")?;
            }
            X64TailFrontierProgramDisposition::EvidenceAlias { .. } => {
                totals.aliased_frontiers =
                    checked_add_u32(totals.aliased_frontiers, 1, "aliased frontiers")?;
            }
        }
        totals.frontier_prospective_bytes = checked_add_u64(
            totals.frontier_prospective_bytes,
            u64::from(frontier.prospective_bytes),
            "frontier prospective bytes",
        )?;
        totals.fixups = checked_add_u32(
            totals.fixups,
            usize_to_u32(frontier.fixups.len(), "frontier fixups")?,
            "fixup total",
        )?;
        for atom in &frontier.atoms {
            totals.atoms = checked_add_u32(totals.atoms, 1, "atom total")?;
            match atom.instruction {
                X64TailBodyAtomInstruction::AdapterFlush { .. } => {
                    totals.adapter_flushes =
                        checked_add_u64(totals.adapter_flushes, 1, "adapter flushes")?;
                }
                X64TailBodyAtomInstruction::AdapterHydrate { .. } => {
                    totals.adapter_hydrates =
                        checked_add_u64(totals.adapter_hydrates, 1, "adapter hydrates")?;
                }
                X64TailBodyAtomInstruction::FrameScratchSave { .. }
                | X64TailBodyAtomInstruction::FrameMove { .. } => {
                    totals.materialized_tail_steps = checked_add_u64(
                        totals.materialized_tail_steps,
                        1,
                        "materialized tail steps",
                    )?;
                }
                _ => {}
            }
        }
    }
    if totals.atoms > X64_TAIL_BODY_FRONTIER_MAX_ATOMS {
        return Err(X64TailBodyFrontierError::LimitExceeded {
            field: "atoms",
            limit: u64::from(X64_TAIL_BODY_FRONTIER_MAX_ATOMS),
            actual: u64::from(totals.atoms),
        });
    }
    if totals.fixups > X64_TAIL_BODY_FRONTIER_MAX_FIXUPS {
        return Err(X64TailBodyFrontierError::LimitExceeded {
            field: "fixups",
            limit: u64::from(X64_TAIL_BODY_FRONTIER_MAX_FIXUPS),
            actual: u64::from(totals.fixups),
        });
    }
    Ok(totals)
}

fn validate_envelope(
    realization: &X64TailBodyFrontierRealization,
    target: &X64TargetArtifact,
    logical: &X64TailStatePlan,
    physical: &X64TailPhysicalAllocation,
    tail_templates: &X64TailTemplateRealization,
    capsule: &X64TailCandidateCapsule,
    binding: &X64TailSiteBindingProof,
) -> Result<(), X64TailBodyFrontierError> {
    if realization.schema_version != X64_TAIL_BODY_FRONTIER_SCHEMA_VERSION
        || realization.policy_version != X64_TAIL_BODY_FRONTIER_POLICY_VERSION
        || realization.source_target_semantic_hash != target.semantic_hash
        || realization.source_logical_plan_hash != logical.plan_hash()
        || realization.source_physical_allocation_hash != physical.allocation_hash()
        || realization.source_template_realization_hash != tail_templates.realization_hash()
        || realization.source_candidate_capsule_hash != capsule.capsule_hash()
        || realization.source_site_binding_hash != binding.proof_hash()
    {
        return Err(X64TailBodyFrontierError::InvalidField {
            field: "source identity",
        });
    }
    Ok(())
}

fn audit_realization(
    realization: &X64TailBodyFrontierRealization,
    binding: &X64TailSiteBindingProof,
    capsule: &X64TailCandidateCapsule,
    tail_templates: &X64TailTemplateRealization,
) -> Result<(), X64TailBodyFrontierError> {
    let mut work = 0_u64;
    audit_site_tokens(&realization.sites, binding.sites(), &mut work)?;
    audit_frontier_programs(&realization.frontiers, binding.frontiers(), &mut work)?;
    for site in &realization.sites {
        for atom in &site.atoms {
            if let X64TailBodyAtomInstruction::CapsuleTransition {
                edge_ordinal,
                capsule_start,
                capsule_end,
            } = atom.instruction
            {
                let receipt = capsule
                    .transition_receipts()
                    .iter()
                    .find(|receipt| receipt.edge_ordinal == edge_ordinal)
                    .ok_or(X64TailBodyFrontierError::MissingTarget {
                        field: "audit capsule receipt",
                    })?;
                let transition = tail_templates
                    .transitions()
                    .iter()
                    .find(|transition| transition.edge_ordinal == edge_ordinal)
                    .ok_or(X64TailBodyFrontierError::MissingTarget {
                        field: "audit tail transition",
                    })?;
                let expected_clobbers = transition
                    .atoms
                    .iter()
                    .flat_map(|atom| atom.clobbers.iter().copied())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                if receipt.start != capsule_start
                    || receipt.end != capsule_end
                    || atom.clobbers != expected_clobbers
                {
                    return Err(X64TailBodyFrontierError::InvalidField {
                        field: "capsule transition reference",
                    });
                }
                let expected_fixups = transition
                    .fixups
                    .iter()
                    .map(|fixup| {
                        Ok(X64TailBodyFixup {
                            atom_ordinal: atom.ordinal,
                            patch_offset: atom.start.checked_add(fixup.patch_offset).ok_or(
                                X64TailBodyFrontierError::ArithmeticOverflow {
                                    field: "audit capsule fixup",
                                },
                            )?,
                            target: X64TailBodyControlTarget::Label(fixup.target),
                            width: fixup.width,
                            addend: fixup.addend,
                        })
                    })
                    .collect::<Result<Vec<_>, X64TailBodyFrontierError>>()?;
                let actual_fixups = site
                    .fixups
                    .iter()
                    .copied()
                    .filter(|fixup| fixup.atom_ordinal == atom.ordinal)
                    .collect::<Vec<_>>();
                if actual_fixups != expected_fixups {
                    return Err(X64TailBodyFrontierError::InvalidField {
                        field: "capsule transition fixups",
                    });
                }
            }
        }
    }
    let totals = compute_totals(&realization.sites, &realization.frontiers, work)?;
    if totals != realization.totals {
        return Err(X64TailBodyFrontierError::ReplayMismatch);
    }
    Ok(())
}

fn realization_bytes_without_seal(
    realization: &X64TailBodyFrontierRealization,
) -> Result<Vec<u8>, X64TailBodyFrontierError> {
    let mut encoder = EvidenceEncoder::default();
    encoder.bytes(REALIZATION_DOMAIN)?;
    encoder.version(realization.schema_version)?;
    encoder.version(realization.policy_version)?;
    encoder.hash(realization.source_target_semantic_hash)?;
    encoder.hash(realization.source_logical_plan_hash)?;
    encoder.hash(realization.source_physical_allocation_hash)?;
    encoder.hash(realization.source_template_realization_hash)?;
    encoder.hash(realization.source_candidate_capsule_hash)?;
    encoder.hash(realization.source_site_binding_hash)?;
    encoder.len(realization.sites.len())?;
    for site in &realization.sites {
        encoder.u32(site.ordinal)?;
        encoder.u32(site.region)?;
        encoder.u32(site.function.0)?;
        encoder.u32(site.block.0)?;
        encoder.u32(site.label.0)?;
        encode_site_position(&mut encoder, site.position)?;
        encoder.u8(template_tag(site.template))?;
        encode_atoms(&mut encoder, &site.atoms)?;
        encode_fixups(&mut encoder, &site.fixups)?;
        encoder.u32(site.prospective_bytes)?;
    }
    encoder.len(realization.frontiers.len())?;
    for frontier in &realization.frontiers {
        encoder.u32(frontier.row_ordinal)?;
        encode_frontier_kind(&mut encoder, frontier.kind)?;
        encoder.u8(frontier_action_tag(frontier.action))?;
        encoder.u8(frontier_placement_tag(frontier.placement))?;
        encode_frontier_disposition(&mut encoder, frontier.disposition)?;
        encode_atoms(&mut encoder, &frontier.atoms)?;
        encode_fixups(&mut encoder, &frontier.fixups)?;
        encoder.u32(frontier.prospective_bytes)?;
    }
    encode_totals(&mut encoder, realization.totals)?;
    Ok(encoder.finish())
}

fn encode_atoms(
    encoder: &mut EvidenceEncoder,
    atoms: &[X64TailBodyAtom],
) -> Result<(), X64TailBodyFrontierError> {
    encoder.len(atoms.len())?;
    for atom in atoms {
        encoder.u32(atom.ordinal)?;
        encoder.u32(atom.start)?;
        encoder.u32(atom.end)?;
        encode_instruction(encoder, atom.instruction)?;
        encoder.len(atom.clobbers.len())?;
        for register in &atom.clobbers {
            encoder.u8(template_register_tag(*register))?;
        }
    }
    Ok(())
}

fn encode_fixups(
    encoder: &mut EvidenceEncoder,
    fixups: &[X64TailBodyFixup],
) -> Result<(), X64TailBodyFrontierError> {
    encoder.len(fixups.len())?;
    for fixup in fixups {
        encoder.u32(fixup.atom_ordinal)?;
        encoder.u32(fixup.patch_offset)?;
        encode_control_target(encoder, fixup.target)?;
        encoder.u8(fixup.width)?;
        encoder.i32(fixup.addend)?;
    }
    Ok(())
}

fn encode_instruction(
    encoder: &mut EvidenceEncoder,
    instruction: X64TailBodyAtomInstruction,
) -> Result<(), X64TailBodyFrontierError> {
    match instruction {
        X64TailBodyAtomInstruction::Acquire { read, destination } => {
            encoder.u8(0)?;
            encode_bound_read(encoder, read)?;
            encoder.u8(scratch_tag(destination))
        }
        X64TailBodyAtomInstruction::Define { source, definition } => {
            encoder.u8(1)?;
            encoder.u8(scratch_tag(source))?;
            encode_bound_definition(encoder, definition)
        }
        X64TailBodyAtomInstruction::I64Wrapping { opcode, definition } => {
            encoder.u8(2)?;
            encoder.u8(i64_opcode_tag(opcode))?;
            encode_word_location(encoder, definition)
        }
        X64TailBodyAtomInstruction::Sse2F64 { opcode, definition } => {
            encoder.u8(3)?;
            encoder.u8(f64_opcode_tag(opcode))?;
            encode_word_location(encoder, definition)
        }
        X64TailBodyAtomInstruction::I64Setcc {
            condition,
            definition,
        } => {
            encoder.u8(4)?;
            encoder.u8(setcc_tag(condition))?;
            encode_word_location(encoder, definition)
        }
        X64TailBodyAtomInstruction::TestBool => encoder.u8(5),
        X64TailBodyAtomInstruction::BranchNonZeroRel32 { target } => {
            encoder.u8(6)?;
            encode_control_target(encoder, target)
        }
        X64TailBodyAtomInstruction::JumpRel32 { target } => {
            encoder.u8(7)?;
            encode_control_target(encoder, target)
        }
        X64TailBodyAtomInstruction::BoundsNegativeRel32 { target } => {
            encoder.u8(8)?;
            encode_control_target(encoder, target)
        }
        X64TailBodyAtomInstruction::BoundsUpperRel32 { target } => {
            encoder.u8(9)?;
            encode_control_target(encoder, target)
        }
        X64TailBodyAtomInstruction::ArrayGetF64 { definition } => {
            encoder.u8(10)?;
            encode_word_location(encoder, definition)
        }
        X64TailBodyAtomInstruction::AdapterFlush { word } => {
            encoder.u8(11)?;
            encode_adapter_word(encoder, word)
        }
        X64TailBodyAtomInstruction::AdapterHydrate { word } => {
            encoder.u8(12)?;
            encode_adapter_word(encoder, word)
        }
        X64TailBodyAtomInstruction::FrameScratchSave { source, scratch_id } => {
            encoder.u8(13)?;
            encode_word_location(encoder, source)?;
            encoder.u32(scratch_id)
        }
        X64TailBodyAtomInstruction::FrameMove {
            source,
            destination,
        } => {
            encoder.u8(14)?;
            encode_scheduled_source(encoder, source)?;
            encode_word_location(encoder, destination)
        }
        X64TailBodyAtomInstruction::CapsuleTransition {
            edge_ordinal,
            capsule_start,
            capsule_end,
        } => {
            encoder.u8(15)?;
            encoder.u32(edge_ordinal)?;
            encoder.u32(capsule_start)?;
            encoder.u32(capsule_end)
        }
        X64TailBodyAtomInstruction::ReturnWord {
            source,
            destination,
        } => {
            encoder.u8(16)?;
            encode_scheduled_source(encoder, source)?;
            encoder.u8(scratch_tag(destination))
        }
        X64TailBodyAtomInstruction::MoveReturnF64BitsToXmm0 => encoder.u8(17),
        X64TailBodyAtomInstruction::CanonicalizeReturnF64 => encoder.u8(18),
    }
}

fn encode_bound_read(
    encoder: &mut EvidenceEncoder,
    read: X64TailBoundRead,
) -> Result<(), X64TailBodyFrontierError> {
    match read {
        X64TailBoundRead::Immediate(value) => {
            encoder.u8(0)?;
            encode_immediate(encoder, value)
        }
        X64TailBoundRead::Location { logical, physical } => {
            encoder.u8(1)?;
            encode_word_location(encoder, logical)?;
            encode_physical(encoder, physical)
        }
    }
}

fn encode_bound_definition(
    encoder: &mut EvidenceEncoder,
    definition: X64TailBoundDefinition,
) -> Result<(), X64TailBodyFrontierError> {
    encode_word_location(encoder, definition.logical)?;
    encode_physical(encoder, definition.physical)
}

fn encode_adapter_word(
    encoder: &mut EvidenceEncoder,
    word: X64TailAdapterWord,
) -> Result<(), X64TailBodyFrontierError> {
    encode_word_location(encoder, word.logical)?;
    encoder.u8(physical_register_tag(word.register))
}

fn encode_physical(
    encoder: &mut EvidenceEncoder,
    physical: X64TailPhysicalLocation,
) -> Result<(), X64TailBodyFrontierError> {
    match physical {
        X64TailPhysicalLocation::Register {
            register,
            word_type,
        } => {
            encoder.u8(0)?;
            encoder.u8(physical_register_tag(register))?;
            encoder.u8(word_type_tag(word_type))
        }
        X64TailPhysicalLocation::Frame(location) => {
            encoder.u8(1)?;
            encode_word_location(encoder, location)
        }
    }
}

fn encode_scheduled_source(
    encoder: &mut EvidenceEncoder,
    source: X64TailScheduledSource,
) -> Result<(), X64TailBodyFrontierError> {
    match source {
        X64TailScheduledSource::Location(location) => {
            encoder.u8(0)?;
            encode_word_location(encoder, location)
        }
        X64TailScheduledSource::Immediate(value) => {
            encoder.u8(1)?;
            encode_immediate(encoder, value)
        }
        X64TailScheduledSource::Scratch { id, word_type } => {
            encoder.u8(2)?;
            encoder.u32(id)?;
            encoder.u8(word_type_tag(word_type))
        }
    }
}

fn encode_immediate(
    encoder: &mut EvidenceEncoder,
    value: X64TailImmediateWord,
) -> Result<(), X64TailBodyFrontierError> {
    match value {
        X64TailImmediateWord::Bool(value) => {
            encoder.u8(0)?;
            encoder.u8(u8::from(value))
        }
        X64TailImmediateWord::I64(value) => {
            encoder.u8(1)?;
            encoder.i64(value)
        }
        X64TailImmediateWord::F64Bits(value) => {
            encoder.u8(2)?;
            encoder.u64(value)
        }
    }
}

fn encode_word_location(
    encoder: &mut EvidenceEncoder,
    location: X64TailWordLocation,
) -> Result<(), X64TailBodyFrontierError> {
    encoder.u32(location.offset)?;
    encoder.u8(word_type_tag(location.word_type))
}

fn encode_control_target(
    encoder: &mut EvidenceEncoder,
    target: X64TailBodyControlTarget,
) -> Result<(), X64TailBodyFrontierError> {
    match target {
        X64TailBodyControlTarget::Label(label) => {
            encoder.u8(0)?;
            encoder.u32(label.0)
        }
        X64TailBodyControlTarget::Frontier(ordinal) => {
            encoder.u8(1)?;
            encoder.u32(ordinal)
        }
    }
}

fn encode_site_position(
    encoder: &mut EvidenceEncoder,
    position: X64TailTemplateSitePosition,
) -> Result<(), X64TailBodyFrontierError> {
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
) -> Result<(), X64TailBodyFrontierError> {
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
            encoder.u8(match kind {
                super::x64_tail_state_plan::X64TailFrontierKind::EntryAbi => 0,
                super::x64_tail_state_plan::X64TailFrontierKind::SharedJoin => 1,
                super::x64_tail_state_plan::X64TailFrontierKind::Bounds => 2,
                super::x64_tail_state_plan::X64TailFrontierKind::Return => 3,
                super::x64_tail_state_plan::X64TailFrontierKind::Budget => 4,
            })
        }
    }
}

fn encode_frontier_disposition(
    encoder: &mut EvidenceEncoder,
    disposition: X64TailFrontierProgramDisposition,
) -> Result<(), X64TailBodyFrontierError> {
    match disposition {
        X64TailFrontierProgramDisposition::Operational => encoder.u8(0),
        X64TailFrontierProgramDisposition::NoOp => encoder.u8(1),
        X64TailFrontierProgramDisposition::CapsuleReference { site_ordinal } => {
            encoder.u8(2)?;
            encoder.u32(site_ordinal)
        }
        X64TailFrontierProgramDisposition::EvidenceAlias { owner_ordinal } => {
            encoder.u8(3)?;
            encoder.u32(owner_ordinal)
        }
    }
}

fn encode_totals(
    encoder: &mut EvidenceEncoder,
    totals: X64TailBodyFrontierTotals,
) -> Result<(), X64TailBodyFrontierError> {
    encoder.u32(totals.site_programs)?;
    encoder.u32(totals.frontier_programs)?;
    encoder.u32(totals.operational_frontiers)?;
    encoder.u32(totals.noop_frontiers)?;
    encoder.u32(totals.capsule_frontiers)?;
    encoder.u32(totals.aliased_frontiers)?;
    encoder.u32(totals.atoms)?;
    encoder.u32(totals.fixups)?;
    encoder.u64(totals.body_prospective_bytes)?;
    encoder.u64(totals.frontier_prospective_bytes)?;
    encoder.u64(totals.retained_capsule_bytes)?;
    encoder.u64(totals.adapter_flushes)?;
    encoder.u64(totals.adapter_hydrates)?;
    encoder.u64(totals.materialized_tail_steps)?;
    encoder.u64(totals.replay_work)
}

const fn scratch_tag(scratch: X64TailBodyScratch) -> u8 {
    match scratch {
        X64TailBodyScratch::Rax => 0,
        X64TailBodyScratch::Rcx => 1,
        X64TailBodyScratch::Rdx => 2,
        X64TailBodyScratch::Xmm0 => 3,
        X64TailBodyScratch::Xmm1 => 4,
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

const fn frontier_placement_tag(placement: X64TailFrontierPlacement) -> u8 {
    match placement {
        X64TailFrontierPlacement::BeforeLabel => 0,
        X64TailFrontierPlacement::EdgeStub => 1,
        X64TailFrontierPlacement::CheckedExit => 2,
        X64TailFrontierPlacement::ExitStub => 3,
        X64TailFrontierPlacement::CapsuleReference => 4,
        X64TailFrontierPlacement::EvidenceOnly => 5,
    }
}

const fn i64_opcode_tag(opcode: X64I64Opcode) -> u8 {
    match opcode {
        X64I64Opcode::Add => 0,
        X64I64Opcode::Sub => 1,
        X64I64Opcode::Mul => 2,
    }
}

const fn f64_opcode_tag(opcode: X64Sse2F64Opcode) -> u8 {
    match opcode {
        X64Sse2F64Opcode::AddSd => 0,
        X64Sse2F64Opcode::SubSd => 1,
    }
}

const fn setcc_tag(condition: X64SetCondition) -> u8 {
    match condition {
        X64SetCondition::SignedLessThan => 0,
        X64SetCondition::SignedGreaterOrEqual => 1,
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

const fn physical_register_tag(register: X64TailPhysicalRegister) -> u8 {
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

fn ensure_limit(
    field: &'static str,
    limit: u32,
    actual: usize,
) -> Result<(), X64TailBodyFrontierError> {
    let actual = usize_to_u64(actual, field)?;
    if actual > u64::from(limit) {
        return Err(X64TailBodyFrontierError::LimitExceeded {
            field,
            limit: u64::from(limit),
            actual,
        });
    }
    Ok(())
}

fn charge(
    work: &mut u64,
    amount: u64,
    field: &'static str,
) -> Result<(), X64TailBodyFrontierError> {
    *work = checked_add_u64(*work, amount, field)?;
    if *work > X64_TAIL_BODY_FRONTIER_MAX_REPLAY_WORK {
        return Err(X64TailBodyFrontierError::LimitExceeded {
            field: "replay work",
            limit: X64_TAIL_BODY_FRONTIER_MAX_REPLAY_WORK,
            actual: *work,
        });
    }
    Ok(())
}

fn checked_add_u32(
    left: u32,
    right: u32,
    field: &'static str,
) -> Result<u32, X64TailBodyFrontierError> {
    left.checked_add(right)
        .ok_or(X64TailBodyFrontierError::ArithmeticOverflow { field })
}

fn checked_add_u64(
    left: u64,
    right: u64,
    field: &'static str,
) -> Result<u64, X64TailBodyFrontierError> {
    left.checked_add(right)
        .ok_or(X64TailBodyFrontierError::ArithmeticOverflow { field })
}

fn usize_to_u32(value: usize, field: &'static str) -> Result<u32, X64TailBodyFrontierError> {
    u32::try_from(value).map_err(|_| X64TailBodyFrontierError::ArithmeticOverflow { field })
}

fn usize_to_u64(value: usize, field: &'static str) -> Result<u64, X64TailBodyFrontierError> {
    u64::try_from(value).map_err(|_| X64TailBodyFrontierError::ArithmeticOverflow { field })
}

fn u32_to_usize(value: u32, field: &'static str) -> Result<usize, X64TailBodyFrontierError> {
    usize::try_from(value).map_err(|_| X64TailBodyFrontierError::ArithmeticOverflow { field })
}

#[derive(Default)]
struct EvidenceEncoder {
    bytes: Vec<u8>,
}

impl EvidenceEncoder {
    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), X64TailBodyFrontierError> {
        let end = self.bytes.len().checked_add(value.len()).ok_or(
            X64TailBodyFrontierError::ArithmeticOverflow {
                field: "evidence bytes",
            },
        )?;
        if end > X64_TAIL_BODY_FRONTIER_MAX_EVIDENCE_BYTES {
            return Err(X64TailBodyFrontierError::EncodingLimit { actual: end });
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), X64TailBodyFrontierError> {
        self.bytes(&[value])
    }

    fn u32(&mut self, value: u32) -> Result<(), X64TailBodyFrontierError> {
        self.bytes(&value.to_le_bytes())
    }

    fn i32(&mut self, value: i32) -> Result<(), X64TailBodyFrontierError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), X64TailBodyFrontierError> {
        self.bytes(&value.to_le_bytes())
    }

    fn i64(&mut self, value: i64) -> Result<(), X64TailBodyFrontierError> {
        self.bytes(&value.to_le_bytes())
    }

    fn len(&mut self, value: usize) -> Result<(), X64TailBodyFrontierError> {
        self.u32(usize_to_u32(value, "evidence collection length")?)
    }

    fn version(&mut self, value: (u16, u16, u16)) -> Result<(), X64TailBodyFrontierError> {
        self.bytes(&value.0.to_le_bytes())?;
        self.bytes(&value.1.to_le_bytes())?;
        self.bytes(&value.2.to_le_bytes())
    }

    fn hash(&mut self, value: SemanticHash) -> Result<(), X64TailBodyFrontierError> {
        self.bytes(&value.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::corevm0_gate_a::CoreVmGateAWorkload;
    use crate::core::x64_native_lighthouse::X64NativeLighthousePackage;
    use crate::core::{
        emit_x64_tail_candidate_capsule, emit_x64_tail_physical_allocation,
        emit_x64_tail_site_binding_proof, emit_x64_tail_state_plan,
        emit_x64_tail_template_realization, X64_TARGET_ENCODER_POLICY_VERSION,
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
        let tail_templates =
            emit_x64_tail_template_realization(package.target(), &logical, &physical)
                .expect("tail template realization must emit");
        let capsule =
            emit_x64_tail_candidate_capsule(package.target(), &logical, &physical, &tail_templates)
                .expect("candidate capsule must emit");
        let binding = emit_x64_tail_site_binding_proof(
            package.target(),
            &logical,
            &physical,
            &tail_templates,
            &capsule,
        )
        .expect("site binding proof must emit");
        (package, logical, physical, tail_templates, capsule, binding)
    }

    #[test]
    fn branch_lighthouse_realizes_body_and_frontier_state_without_new_bytes() {
        let (package, logical, physical, tail_templates, capsule, binding) =
            build(CoreVmGateAWorkload::BranchMix);
        let original_code = package.target().program.code.clone();
        let original_code_hash = package.target().program.code_hash;
        let first = emit_x64_tail_body_frontier_realization(
            package.target(),
            &logical,
            &physical,
            &tail_templates,
            &capsule,
            &binding,
        )
        .expect("body/frontier realization must emit");
        let second = emit_x64_tail_body_frontier_realization(
            package.target(),
            &logical,
            &physical,
            &tail_templates,
            &capsule,
            &binding,
        )
        .expect("body/frontier realization must be deterministic");
        assert_eq!(first, second);
        verify_x64_tail_body_frontier_realization(
            &first,
            &binding,
            &capsule,
            &tail_templates,
            &physical,
            &logical,
            package.target(),
        )
        .expect("body/frontier realization must replay");
        assert_eq!(
            first.realization_hash().to_hex(),
            "93e281cba92c985043dc2401167f4a051eb9a6f322bda032362846ec0250ffff"
        );
        assert_eq!(
            first.totals(),
            X64TailBodyFrontierTotals {
                site_programs: 168,
                frontier_programs: 151,
                operational_frontiers: 43,
                noop_frontiers: 0,
                capsule_frontiers: 108,
                aliased_frontiers: 0,
                atoms: 746,
                fixups: 191,
                body_prospective_bytes: 3_073,
                frontier_prospective_bytes: 4_199,
                retained_capsule_bytes: 2_103,
                adapter_flushes: 207,
                adapter_hydrates: 189,
                materialized_tail_steps: 41,
                replay_work: 1_065,
            }
        );
        assert_eq!(first.sites.len(), binding.sites().len());
        assert_eq!(first.frontiers.len(), binding.frontiers().len());
        assert_eq!(package.target().program.code, original_code);
        assert_eq!(package.target().program.code_hash, original_code_hash);
        assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));

        let mut wrong_clobber = first.clone();
        let clobber_atom = wrong_clobber
            .sites
            .iter_mut()
            .flat_map(|site| site.atoms.iter_mut())
            .find(|atom| {
                !matches!(
                    atom.instruction,
                    X64TailBodyAtomInstruction::CapsuleTransition { .. }
                )
            })
            .expect("fixture must expose a body atom");
        clobber_atom.clobbers.clear();
        wrong_clobber.realization_hash = x64_tail_body_frontier_realization_hash(&wrong_clobber)
            .expect("clobber mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_body_frontier_realization(
                &wrong_clobber,
                &binding,
                &capsule,
                &tail_templates,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailBodyFrontierError::InvalidField { .. })
        ));

        let mut wrong_fixup = first.clone();
        let fixup = wrong_fixup
            .sites
            .iter_mut()
            .find_map(|site| site.fixups.first_mut())
            .expect("fixture must expose a site fixup");
        fixup.patch_offset = fixup.patch_offset.saturating_add(1);
        wrong_fixup.realization_hash = x64_tail_body_frontier_realization_hash(&wrong_fixup)
            .expect("fixup mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_body_frontier_realization(
                &wrong_fixup,
                &binding,
                &capsule,
                &tail_templates,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailBodyFrontierError::InvalidField { .. })
        ));

        let mut wrong_frontier_order = first.clone();
        let frontier = wrong_frontier_order
            .frontiers
            .iter_mut()
            .find(|frontier| frontier.atoms.len() >= 2)
            .expect("fixture must expose a multi-atom frontier");
        frontier.atoms.swap(0, 1);
        wrong_frontier_order.realization_hash =
            x64_tail_body_frontier_realization_hash(&wrong_frontier_order)
                .expect("frontier order mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_body_frontier_realization(
                &wrong_frontier_order,
                &binding,
                &capsule,
                &tail_templates,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailBodyFrontierError::InvalidField { .. })
                | Err(X64TailBodyFrontierError::TokenMismatch { .. })
        ));
    }

    #[test]
    fn mutations_fail_closed_after_local_reseal() {
        let (package, logical, physical, tail_templates, capsule, binding) =
            build(CoreVmGateAWorkload::BoundsOrderedArrayGet);
        let first = emit_x64_tail_body_frontier_realization(
            package.target(),
            &logical,
            &physical,
            &tail_templates,
            &capsule,
            &binding,
        )
        .expect("Bounds body/frontier realization must emit");

        let mut wrong_atom = first.clone();
        if let Some(atom) = wrong_atom
            .sites
            .iter_mut()
            .find_map(|site| site.atoms.first_mut())
        {
            atom.end = atom.end.saturating_add(1);
        }
        wrong_atom.realization_hash = x64_tail_body_frontier_realization_hash(&wrong_atom)
            .expect("atom mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_body_frontier_realization(
                &wrong_atom,
                &binding,
                &capsule,
                &tail_templates,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailBodyFrontierError::InvalidField { .. })
                | Err(X64TailBodyFrontierError::ReplayMismatch)
        ));

        let mut wrong_source = first.clone();
        wrong_source.source_site_binding_hash.0[0] ^= 1;
        wrong_source.realization_hash = x64_tail_body_frontier_realization_hash(&wrong_source)
            .expect("source mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_body_frontier_realization(
                &wrong_source,
                &binding,
                &capsule,
                &tail_templates,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailBodyFrontierError::InvalidField {
                field: "source identity"
            })
        ));

        let mut wrong_total = first.clone();
        wrong_total.totals.replay_work = wrong_total.totals.replay_work.saturating_add(1);
        wrong_total.realization_hash = x64_tail_body_frontier_realization_hash(&wrong_total)
            .expect("total mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_body_frontier_realization(
                &wrong_total,
                &binding,
                &capsule,
                &tail_templates,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailBodyFrontierError::ReplayMismatch)
        ));

        let mut wrong_seal = first.clone();
        wrong_seal.realization_hash.0[0] ^= 1;
        assert!(matches!(
            verify_x64_tail_body_frontier_realization(
                &wrong_seal,
                &binding,
                &capsule,
                &tail_templates,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailBodyFrontierError::RealizationHashMismatch)
        ));
    }
}
