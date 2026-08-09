//! Closed non-executable ADR-0065 semantic image composition.
//!
//! The image combines only bytes already owned by ADR-0060 and ADR-0064.
//! Rel32 fields are relocated into one finite address space; entry, return,
//! and Bounds remain typed `INT3` proof terminals. This module exposes bytes
//! as immutable data and contains no mapping or execution API.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_body_frontier_capsule::{
    verify_x64_tail_body_frontier_capsule, X64TailBodyCapsuleProgramKind,
    X64TailBodyFrontierCapsule, X64TailBodyFrontierCapsuleError,
};
use super::x64_tail_body_frontier_realization::{
    X64TailBodyAtomInstruction, X64TailBodyControlTarget, X64TailBodyFrontierRealization,
    X64TailFrontierPlacement, X64TailFrontierProgramDisposition,
};
use super::x64_tail_candidate_capsule::{
    verify_x64_tail_candidate_capsule, X64TailCandidateCapsule, X64TailCandidateCapsuleError,
};
use super::x64_tail_closed_image_decode::{
    decode_x64_tail_closed_image, X64TailClosedImageDecodeError, X64TailDecodedClosedImage,
};
use super::x64_tail_site_binding::{X64TailFrontierBindingKind, X64TailSiteBindingProof};
use super::x64_tail_state_allocation::X64TailPhysicalAllocation;
use super::x64_tail_state_plan::X64TailStatePlan;
use super::x64_tail_template_realization::X64TailTemplateRealization;
use super::x64_target::{X64LabelId, X64LabelOwner, X64TargetArtifact, X64TargetProgram};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const X64_TAIL_CLOSED_IMAGE_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_CLOSED_IMAGE_POLICY_VERSION: (u16, u16, u16) = (1, 1, 0);
pub const X64_TAIL_CLOSED_IMAGE_MAX_CODE_BYTES: u64 = 128 * 1024 * 1024;
pub const X64_TAIL_CLOSED_IMAGE_MAX_PROGRAMS: u32 = 1_032_000;
pub const X64_TAIL_CLOSED_IMAGE_MAX_LABELS: u32 = 2_032_000;
pub const X64_TAIL_CLOSED_IMAGE_MAX_RELOCATIONS: u32 = 2_004_096;
pub const X64_TAIL_CLOSED_IMAGE_MAX_SOURCE_RANGES: u32 = 8_000_000;
pub const X64_TAIL_CLOSED_IMAGE_MAX_WORK: u64 = 64_000_000;
pub const X64_TAIL_CLOSED_IMAGE_MAX_EVIDENCE_BYTES: usize = 128 * 1024 * 1024;

const CODE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-closed-image-code:v1\0";
const IMAGE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-closed-image:v1\0";
pub(super) const TERMINAL_BYTE: u8 = 0xcc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum X64TailClosedProgramKind {
    Site,
    Frontier,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailClosedProgramReceipt {
    pub kind: X64TailClosedProgramKind,
    pub ordinal: u32,
    pub start: u32,
    pub end: u32,
    pub atoms: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailClosedLabelReceipt {
    pub label: X64LabelId,
    pub offset: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailClosedFrontierReceipt {
    pub ordinal: u32,
    pub offset: u32,
    pub end: u32,
    pub owner_ordinal: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum X64TailClosedTerminalKind {
    EntryAdapter,
    ReturnEpilogue,
    BoundsEpilogue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailClosedTerminalReceipt {
    pub kind: X64TailClosedTerminalKind,
    pub label: X64LabelId,
    pub offset: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailClosedSourceKind {
    Body,
    Transition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailClosedSourceReceipt {
    pub source_kind: X64TailClosedSourceKind,
    pub program_kind: X64TailClosedProgramKind,
    pub program_ordinal: u32,
    pub atom_ordinal: u32,
    pub source_start: u32,
    pub source_end: u32,
    pub image_start: u32,
    pub image_end: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailClosedRelocationReceipt {
    pub source_kind: X64TailClosedSourceKind,
    pub program_kind: X64TailClosedProgramKind,
    pub program_ordinal: u32,
    pub atom_ordinal: u32,
    pub patch_offset: u32,
    pub target: X64TailBodyControlTarget,
    pub target_offset: u32,
    pub displacement: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailClosedCfgEdgeKind {
    Entry,
    FrontierFallthrough,
    ConditionalFallthrough,
    Rel32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailClosedCfgDestination {
    Label {
        label: X64LabelId,
        offset: u32,
    },
    Frontier {
        ordinal: u32,
        offset: u32,
    },
    InstructionBoundary {
        program_kind: X64TailClosedProgramKind,
        program_ordinal: u32,
        offset: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailClosedCfgEdge {
    pub kind: X64TailClosedCfgEdgeKind,
    pub source_offset: u32,
    pub destination: X64TailClosedCfgDestination,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X64TailClosedImageTotals {
    pub programs: u32,
    pub labels: u32,
    pub frontiers: u32,
    pub terminals: u32,
    pub source_ranges: u32,
    pub body_ranges: u32,
    pub transition_ranges: u32,
    pub relocations: u32,
    pub cfg_edges: u32,
    pub body_bytes: u32,
    pub transition_bytes: u32,
    pub terminal_bytes: u32,
    pub code_bytes: u32,
    pub compose_work: u64,
    pub decode_work: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailClosedImage {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    decoder_policy_version: (u16, u16, u16),
    source_target_semantic_hash: SemanticHash,
    source_transition_capsule_hash: SemanticHash,
    source_body_capsule_hash: SemanticHash,
    source_realization_hash: SemanticHash,
    source_binding_hash: SemanticHash,
    entry_successor: X64TailBodyControlTarget,
    program_receipts: Vec<X64TailClosedProgramReceipt>,
    label_receipts: Vec<X64TailClosedLabelReceipt>,
    frontier_receipts: Vec<X64TailClosedFrontierReceipt>,
    terminal_receipts: Vec<X64TailClosedTerminalReceipt>,
    source_receipts: Vec<X64TailClosedSourceReceipt>,
    relocation_receipts: Vec<X64TailClosedRelocationReceipt>,
    cfg_edges: Vec<X64TailClosedCfgEdge>,
    code: Vec<u8>,
    code_hash: SemanticHash,
    totals: X64TailClosedImageTotals,
    image_hash: SemanticHash,
}

impl X64TailClosedImage {
    pub const fn source_target_semantic_hash(&self) -> SemanticHash {
        self.source_target_semantic_hash
    }
    pub const fn source_transition_capsule_hash(&self) -> SemanticHash {
        self.source_transition_capsule_hash
    }
    pub const fn source_body_capsule_hash(&self) -> SemanticHash {
        self.source_body_capsule_hash
    }
    pub const fn source_realization_hash(&self) -> SemanticHash {
        self.source_realization_hash
    }
    pub const fn source_binding_hash(&self) -> SemanticHash {
        self.source_binding_hash
    }
    pub const fn entry_successor(&self) -> X64TailBodyControlTarget {
        self.entry_successor
    }
    pub fn program_receipts(&self) -> &[X64TailClosedProgramReceipt] {
        &self.program_receipts
    }
    pub fn label_receipts(&self) -> &[X64TailClosedLabelReceipt] {
        &self.label_receipts
    }
    pub fn frontier_receipts(&self) -> &[X64TailClosedFrontierReceipt] {
        &self.frontier_receipts
    }
    pub fn terminal_receipts(&self) -> &[X64TailClosedTerminalReceipt] {
        &self.terminal_receipts
    }
    pub fn source_receipts(&self) -> &[X64TailClosedSourceReceipt] {
        &self.source_receipts
    }
    pub fn relocation_receipts(&self) -> &[X64TailClosedRelocationReceipt] {
        &self.relocation_receipts
    }
    pub fn cfg_edges(&self) -> &[X64TailClosedCfgEdge] {
        &self.cfg_edges
    }
    pub fn code(&self) -> &[u8] {
        &self.code
    }
    pub const fn code_hash(&self) -> SemanticHash {
        self.code_hash
    }
    pub const fn totals(&self) -> X64TailClosedImageTotals {
        self.totals
    }
    pub const fn image_hash(&self) -> SemanticHash {
        self.image_hash
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedX64TailClosedImage<'image> {
    image: &'image X64TailClosedImage,
    decoded: X64TailDecodedClosedImage,
}

impl<'image> VerifiedX64TailClosedImage<'image> {
    pub const fn image(&self) -> &'image X64TailClosedImage {
        self.image
    }
    pub const fn decoded(&self) -> &X64TailDecodedClosedImage {
        &self.decoded
    }
}

#[derive(Debug)]
pub enum X64TailClosedImageError {
    Body(X64TailBodyFrontierCapsuleError),
    Transition(X64TailCandidateCapsuleError),
    Decode(X64TailClosedImageDecodeError),
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
    Rel32OutOfRange {
        patch: u32,
        displacement: i64,
    },
    EncodingLimit {
        actual: usize,
    },
    CodeHashMismatch,
    ImageHashMismatch,
    ReceiptMismatch,
    ReplayMismatch,
}

impl fmt::Display for X64TailClosedImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Body(error) => write!(formatter, "closed image body input failed: {error}"),
            Self::Transition(error) => write!(formatter, "closed image transition input failed: {error}"),
            Self::Decode(error) => write!(formatter, "closed image decode failed: {error}"),
            Self::InvalidField { field } => write!(formatter, "closed image has invalid {field}"),
            Self::MissingTarget { field } => write!(formatter, "closed image is missing {field}"),
            Self::LimitExceeded { field, limit, actual } => write!(formatter, "closed image {field} uses {actual}; limit is {limit}"),
            Self::ArithmeticOverflow { field } => write!(formatter, "closed image overflowed {field}"),
            Self::Rel32OutOfRange { patch, displacement } => write!(formatter, "closed image rel32 at {patch} has out-of-range displacement {displacement}"),
            Self::EncodingLimit { actual } => write!(formatter, "closed image evidence uses {actual} bytes; limit is {X64_TAIL_CLOSED_IMAGE_MAX_EVIDENCE_BYTES}"),
            Self::CodeHashMismatch => formatter.write_str("closed image code hash does not replay"),
            Self::ImageHashMismatch => formatter.write_str("closed image seal does not replay"),
            Self::ReceiptMismatch => formatter.write_str("closed image receipts differ from independent decode"),
            Self::ReplayMismatch => formatter.write_str("closed image differs from canonical regeneration"),
        }
    }
}

impl std::error::Error for X64TailClosedImageError {}
impl From<X64TailBodyFrontierCapsuleError> for X64TailClosedImageError {
    fn from(value: X64TailBodyFrontierCapsuleError) -> Self {
        Self::Body(value)
    }
}
impl From<X64TailCandidateCapsuleError> for X64TailClosedImageError {
    fn from(value: X64TailCandidateCapsuleError) -> Self {
        Self::Transition(value)
    }
}
impl From<X64TailClosedImageDecodeError> for X64TailClosedImageError {
    fn from(value: X64TailClosedImageDecodeError) -> Self {
        Self::Decode(value)
    }
}

#[derive(Clone)]
pub(super) struct X64TailClosedDerivedLayout {
    pub programs: Vec<X64TailClosedProgramReceipt>,
    pub labels: Vec<X64TailClosedLabelReceipt>,
    pub frontiers: Vec<X64TailClosedFrontierReceipt>,
    pub terminals: Vec<X64TailClosedTerminalReceipt>,
    pub label_offsets: BTreeMap<X64LabelId, u32>,
    pub frontier_offsets: BTreeMap<u32, u32>,
    pub entry_successor: X64TailBodyControlTarget,
    pub code_bytes: u32,
}

#[allow(clippy::too_many_arguments)]
pub fn emit_x64_tail_closed_image(
    target: &X64TargetArtifact,
    logical: &X64TailStatePlan,
    physical: &X64TailPhysicalAllocation,
    templates: &X64TailTemplateRealization,
    transition: &X64TailCandidateCapsule,
    binding: &X64TailSiteBindingProof,
    realization: &X64TailBodyFrontierRealization,
    body: &X64TailBodyFrontierCapsule,
) -> Result<X64TailClosedImage, X64TailClosedImageError> {
    verify_predecessors(
        target,
        logical,
        physical,
        templates,
        transition,
        binding,
        realization,
        body,
    )?;
    construct_image(target, templates, transition, binding, realization, body)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_x64_tail_closed_image<'image>(
    image: &'image X64TailClosedImage,
    body: &X64TailBodyFrontierCapsule,
    realization: &X64TailBodyFrontierRealization,
    binding: &X64TailSiteBindingProof,
    transition: &X64TailCandidateCapsule,
    templates: &X64TailTemplateRealization,
    physical: &X64TailPhysicalAllocation,
    logical: &X64TailStatePlan,
    target: &X64TargetArtifact,
) -> Result<VerifiedX64TailClosedImage<'image>, X64TailClosedImageError> {
    verify_predecessors(
        target,
        logical,
        physical,
        templates,
        transition,
        binding,
        realization,
        body,
    )?;
    validate_envelope(image, body, realization, binding, transition, target)?;
    if x64_tail_closed_image_code_hash(&image.code)? != image.code_hash {
        return Err(X64TailClosedImageError::CodeHashMismatch);
    }
    if x64_tail_closed_image_hash(image)? != image.image_hash {
        return Err(X64TailClosedImageError::ImageHashMismatch);
    }
    let decoded = decode_x64_tail_closed_image(
        &image.code,
        body,
        realization,
        binding,
        transition,
        templates,
        target,
    )?;
    if image.entry_successor != decoded.entry_successor
        || image.program_receipts != decoded.programs
        || image.label_receipts != decoded.labels
        || image.frontier_receipts != decoded.frontiers
        || image.terminal_receipts != decoded.terminals
        || image.source_receipts != decoded.sources
        || image.relocation_receipts != decoded.relocations
        || image.cfg_edges != decoded.cfg_edges
        || image.totals != decoded.totals
    {
        return Err(X64TailClosedImageError::ReceiptMismatch);
    }
    let replayed = construct_image(target, templates, transition, binding, realization, body)?;
    if replayed != *image {
        return Err(X64TailClosedImageError::ReplayMismatch);
    }
    Ok(VerifiedX64TailClosedImage { image, decoded })
}

#[allow(clippy::too_many_arguments)]
fn verify_predecessors(
    target: &X64TargetArtifact,
    logical: &X64TailStatePlan,
    physical: &X64TailPhysicalAllocation,
    templates: &X64TailTemplateRealization,
    transition: &X64TailCandidateCapsule,
    binding: &X64TailSiteBindingProof,
    realization: &X64TailBodyFrontierRealization,
    body: &X64TailBodyFrontierCapsule,
) -> Result<(), X64TailClosedImageError> {
    verify_x64_tail_candidate_capsule(transition, templates, physical, logical, target)?;
    verify_x64_tail_body_frontier_capsule(
        body,
        realization,
        binding,
        transition,
        templates,
        physical,
        logical,
        target,
    )?;
    Ok(())
}

fn construct_image(
    target: &X64TargetArtifact,
    templates: &X64TailTemplateRealization,
    transition: &X64TailCandidateCapsule,
    binding: &X64TailSiteBindingProof,
    realization: &X64TailBodyFrontierRealization,
    body: &X64TailBodyFrontierCapsule,
) -> Result<X64TailClosedImage, X64TailClosedImageError> {
    let layout = derive_x64_tail_closed_layout(target, binding, realization)?;
    let capacity = usize::try_from(layout.code_bytes).map_err(|_| {
        X64TailClosedImageError::ArithmeticOverflow {
            field: "code capacity",
        }
    })?;
    let mut code = Vec::new();
    code.try_reserve_exact(capacity)
        .map_err(|_| X64TailClosedImageError::EncodingLimit { actual: capacity })?;
    let mut sources = Vec::new();
    let mut relocations = Vec::new();
    let mut work = 0u64;
    let program_map = layout
        .programs
        .iter()
        .map(|p| ((p.kind, p.ordinal), *p))
        .collect::<BTreeMap<_, _>>();

    {
        let mut composer = ProgramComposer {
            code: &mut code,
            body,
            transition,
            layout: &layout,
            sources: &mut sources,
            relocations: &mut relocations,
            work: &mut work,
        };
        for receipt in &layout.programs {
            if receipt.start == receipt.end {
                continue;
            }
            if usize_to_u32(composer.code.len(), "program placement")? != receipt.start {
                return Err(X64TailClosedImageError::InvalidField {
                    field: "program placement coverage",
                });
            }
            match receipt.kind {
                X64TailClosedProgramKind::Site => {
                    let site = realization
                        .sites()
                        .iter()
                        .find(|site| site.ordinal == receipt.ordinal)
                        .ok_or(X64TailClosedImageError::MissingTarget {
                            field: "site program",
                        })?;
                    compose_program(&mut composer, receipt, &site.atoms)?;
                }
                X64TailClosedProgramKind::Frontier => {
                    let frontier = realization
                        .frontiers()
                        .iter()
                        .find(|frontier| frontier.row_ordinal == receipt.ordinal)
                        .ok_or(X64TailClosedImageError::MissingTarget {
                            field: "frontier program",
                        })?;
                    compose_program(&mut composer, receipt, &frontier.atoms)?;
                }
            }
            if usize_to_u32(composer.code.len(), "program end")? != receipt.end {
                return Err(X64TailClosedImageError::InvalidField {
                    field: "program byte extent",
                });
            }
        }
    }
    let terminal_start = layout
        .terminals
        .first()
        .map_or(layout.code_bytes, |terminal| terminal.offset);
    if usize_to_u32(code.len(), "terminal start")? != terminal_start {
        return Err(X64TailClosedImageError::InvalidField {
            field: "pre-terminal byte coverage",
        });
    }
    for terminal in &layout.terminals {
        if usize_to_u32(code.len(), "terminal placement")? != terminal.offset {
            return Err(X64TailClosedImageError::InvalidField {
                field: "terminal placement",
            });
        }
        code.push(TERMINAL_BYTE);
        work = charge(work, 1)?;
    }
    if usize_to_u32(code.len(), "code bytes")? != layout.code_bytes {
        return Err(X64TailClosedImageError::InvalidField {
            field: "exact image coverage",
        });
    }
    ensure_limit(
        "source ranges",
        X64_TAIL_CLOSED_IMAGE_MAX_SOURCE_RANGES,
        sources.len(),
    )?;
    ensure_limit(
        "relocations",
        X64_TAIL_CLOSED_IMAGE_MAX_RELOCATIONS,
        relocations.len(),
    )?;
    let cfg_edges = derive_cfg_edges(realization, binding, &layout, &relocations, &program_map)?;
    let body_ranges = sources
        .iter()
        .filter(|source| source.source_kind == X64TailClosedSourceKind::Body)
        .count();
    let transition_ranges = sources.len().checked_sub(body_ranges).ok_or(
        X64TailClosedImageError::ArithmeticOverflow {
            field: "transition range count",
        },
    )?;
    let body_bytes = sources
        .iter()
        .filter(|source| source.source_kind == X64TailClosedSourceKind::Body)
        .try_fold(0u32, |total, source| {
            checked_add(
                total,
                source.image_end.checked_sub(source.image_start).ok_or(
                    X64TailClosedImageError::InvalidField {
                        field: "source range",
                    },
                )?,
                "body bytes",
            )
        })?;
    let transition_bytes = sources
        .iter()
        .filter(|source| source.source_kind == X64TailClosedSourceKind::Transition)
        .try_fold(0u32, |total, source| {
            checked_add(
                total,
                source.image_end.checked_sub(source.image_start).ok_or(
                    X64TailClosedImageError::InvalidField {
                        field: "source range",
                    },
                )?,
                "transition bytes",
            )
        })?;
    let totals = X64TailClosedImageTotals {
        programs: usize_to_u32(layout.programs.len(), "programs")?,
        labels: usize_to_u32(layout.labels.len(), "labels")?,
        frontiers: usize_to_u32(layout.frontiers.len(), "frontiers")?,
        terminals: usize_to_u32(layout.terminals.len(), "terminals")?,
        source_ranges: usize_to_u32(sources.len(), "source ranges")?,
        body_ranges: usize_to_u32(body_ranges, "body ranges")?,
        transition_ranges: usize_to_u32(transition_ranges, "transition ranges")?,
        relocations: usize_to_u32(relocations.len(), "relocations")?,
        cfg_edges: usize_to_u32(cfg_edges.len(), "CFG edges")?,
        body_bytes,
        transition_bytes,
        terminal_bytes: usize_to_u32(layout.terminals.len(), "terminal bytes")?,
        code_bytes: layout.code_bytes,
        compose_work: work,
        decode_work: 0,
    };
    let code_hash = x64_tail_closed_image_code_hash(&code)?;
    let mut image = X64TailClosedImage {
        schema_version: X64_TAIL_CLOSED_IMAGE_SCHEMA_VERSION,
        policy_version: X64_TAIL_CLOSED_IMAGE_POLICY_VERSION,
        decoder_policy_version:
            super::x64_tail_closed_image_decode::X64_TAIL_CLOSED_IMAGE_DECODER_POLICY_VERSION,
        source_target_semantic_hash: target.semantic_hash,
        source_transition_capsule_hash: transition.capsule_hash(),
        source_body_capsule_hash: body.capsule_hash(),
        source_realization_hash: realization.realization_hash(),
        source_binding_hash: binding.proof_hash(),
        entry_successor: layout.entry_successor,
        program_receipts: layout.programs,
        label_receipts: layout.labels,
        frontier_receipts: layout.frontiers,
        terminal_receipts: layout.terminals,
        source_receipts: sources,
        relocation_receipts: relocations,
        cfg_edges,
        code,
        code_hash,
        totals,
        image_hash: SemanticHash::ZERO,
    };
    // The decoder work is structural and deterministic; obtain it before sealing.
    let decoded = decode_x64_tail_closed_image(
        &image.code,
        body,
        realization,
        binding,
        transition,
        templates,
        target,
    )?;
    image.totals.decode_work = decoded.totals.decode_work;
    image.image_hash = x64_tail_closed_image_hash(&image)?;
    Ok(image)
}

struct ProgramComposer<'a> {
    code: &'a mut Vec<u8>,
    body: &'a X64TailBodyFrontierCapsule,
    transition: &'a X64TailCandidateCapsule,
    layout: &'a X64TailClosedDerivedLayout,
    sources: &'a mut Vec<X64TailClosedSourceReceipt>,
    relocations: &'a mut Vec<X64TailClosedRelocationReceipt>,
    work: &'a mut u64,
}

#[derive(Clone, Copy)]
struct RelocationOrigin {
    source_kind: X64TailClosedSourceKind,
    program_kind: X64TailClosedProgramKind,
    program_ordinal: u32,
    atom_ordinal: u32,
}

fn compose_program(
    composer: &mut ProgramComposer<'_>,
    program: &X64TailClosedProgramReceipt,
    atoms: &[super::x64_tail_body_frontier_realization::X64TailBodyAtom],
) -> Result<(), X64TailClosedImageError> {
    let body_kind = match program.kind {
        X64TailClosedProgramKind::Site => X64TailBodyCapsuleProgramKind::Site,
        X64TailClosedProgramKind::Frontier => X64TailBodyCapsuleProgramKind::Frontier,
    };
    let source_program = composer
        .body
        .program_receipts()
        .iter()
        .find(|receipt| receipt.kind == body_kind && receipt.ordinal == program.ordinal)
        .copied()
        .ok_or(X64TailClosedImageError::MissingTarget {
            field: "body capsule program receipt",
        })?;
    let mut body_cursor = source_program.start;
    for atom in atoms {
        let image_start = usize_to_u32(composer.code.len(), "atom image start")?;
        let atom_len =
            atom.end
                .checked_sub(atom.start)
                .ok_or(X64TailClosedImageError::InvalidField {
                    field: "atom extent",
                })?;
        match atom.instruction {
            X64TailBodyAtomInstruction::CapsuleTransition {
                edge_ordinal,
                capsule_start,
                capsule_end,
            } => {
                if program.kind != X64TailClosedProgramKind::Site
                    || capsule_end.checked_sub(capsule_start) != Some(atom_len)
                {
                    return Err(X64TailClosedImageError::InvalidField {
                        field: "transition atom extent",
                    });
                }
                let receipt = composer
                    .transition
                    .transition_receipts()
                    .iter()
                    .find(|receipt| receipt.edge_ordinal == edge_ordinal)
                    .copied()
                    .ok_or(X64TailClosedImageError::MissingTarget {
                        field: "transition receipt",
                    })?;
                if receipt.start != capsule_start || receipt.end != capsule_end {
                    return Err(X64TailClosedImageError::InvalidField {
                        field: "transition source span",
                    });
                }
                append_source(
                    composer.code,
                    composer.transition.code(),
                    capsule_start,
                    capsule_end,
                )?;
                composer.sources.push(X64TailClosedSourceReceipt {
                    source_kind: X64TailClosedSourceKind::Transition,
                    program_kind: program.kind,
                    program_ordinal: program.ordinal,
                    atom_ordinal: atom.ordinal,
                    source_start: capsule_start,
                    source_end: capsule_end,
                    image_start,
                    image_end: image_start.checked_add(atom_len).ok_or(
                        X64TailClosedImageError::ArithmeticOverflow {
                            field: "transition image end",
                        },
                    )?,
                });
                let fixups = composer
                    .transition
                    .fixup_receipts()
                    .iter()
                    .filter(|fixup| fixup.edge_ordinal == edge_ordinal)
                    .copied()
                    .collect::<Vec<_>>();
                for fixup in fixups {
                    let relative = fixup.patch_offset.checked_sub(capsule_start).ok_or(
                        X64TailClosedImageError::InvalidField {
                            field: "transition patch span",
                        },
                    )?;
                    relocate(
                        composer,
                        RelocationOrigin {
                            source_kind: X64TailClosedSourceKind::Transition,
                            program_kind: program.kind,
                            program_ordinal: program.ordinal,
                            atom_ordinal: atom.ordinal,
                        },
                        image_start.checked_add(relative).ok_or(
                            X64TailClosedImageError::ArithmeticOverflow {
                                field: "transition patch",
                            },
                        )?,
                        X64TailBodyControlTarget::Label(fixup.target),
                    )?;
                }
            }
            _ => {
                let source_start = body_cursor;
                let source_end = source_start.checked_add(atom_len).ok_or(
                    X64TailClosedImageError::ArithmeticOverflow {
                        field: "body source end",
                    },
                )?;
                if source_end > source_program.end {
                    return Err(X64TailClosedImageError::InvalidField {
                        field: "body source program span",
                    });
                }
                append_source(
                    composer.code,
                    composer.body.code(),
                    source_start,
                    source_end,
                )?;
                composer.sources.push(X64TailClosedSourceReceipt {
                    source_kind: X64TailClosedSourceKind::Body,
                    program_kind: program.kind,
                    program_ordinal: program.ordinal,
                    atom_ordinal: atom.ordinal,
                    source_start,
                    source_end,
                    image_start,
                    image_end: image_start.checked_add(atom_len).ok_or(
                        X64TailClosedImageError::ArithmeticOverflow {
                            field: "body image end",
                        },
                    )?,
                });
                let fixups = composer
                    .body
                    .fixup_receipts()
                    .iter()
                    .filter(|fixup| {
                        fixup.program_kind == body_kind
                            && fixup.program_ordinal == program.ordinal
                            && fixup.atom_ordinal == atom.ordinal
                    })
                    .copied()
                    .collect::<Vec<_>>();
                for fixup in fixups {
                    let relative = fixup.patch_offset.checked_sub(source_start).ok_or(
                        X64TailClosedImageError::InvalidField {
                            field: "body patch span",
                        },
                    )?;
                    relocate(
                        composer,
                        RelocationOrigin {
                            source_kind: X64TailClosedSourceKind::Body,
                            program_kind: program.kind,
                            program_ordinal: program.ordinal,
                            atom_ordinal: atom.ordinal,
                        },
                        image_start.checked_add(relative).ok_or(
                            X64TailClosedImageError::ArithmeticOverflow {
                                field: "body patch",
                            },
                        )?,
                        fixup.target,
                    )?;
                }
                body_cursor = source_end;
            }
        }
        if usize_to_u32(composer.code.len(), "atom image end")?
            != image_start.checked_add(atom_len).ok_or(
                X64TailClosedImageError::ArithmeticOverflow {
                    field: "atom image end",
                },
            )?
        {
            return Err(X64TailClosedImageError::InvalidField {
                field: "atom image extent",
            });
        }
        *composer.work = charge(
            *composer.work,
            u64::from(atom_len).checked_add(1).ok_or(
                X64TailClosedImageError::ArithmeticOverflow {
                    field: "compose work",
                },
            )?,
        )?;
    }
    if body_cursor != source_program.end {
        return Err(X64TailClosedImageError::InvalidField {
            field: "body program source coverage",
        });
    }
    Ok(())
}

fn append_source(
    code: &mut Vec<u8>,
    source: &[u8],
    start: u32,
    end: u32,
) -> Result<(), X64TailClosedImageError> {
    let start =
        usize::try_from(start).map_err(|_| X64TailClosedImageError::ArithmeticOverflow {
            field: "source start",
        })?;
    let end = usize::try_from(end).map_err(|_| X64TailClosedImageError::ArithmeticOverflow {
        field: "source end",
    })?;
    let bytes = source
        .get(start..end)
        .ok_or(X64TailClosedImageError::InvalidField {
            field: "source byte range",
        })?;
    code.extend_from_slice(bytes);
    Ok(())
}

fn relocate(
    composer: &mut ProgramComposer<'_>,
    origin: RelocationOrigin,
    patch_offset: u32,
    target: X64TailBodyControlTarget,
) -> Result<(), X64TailClosedImageError> {
    let target_offset = match target {
        X64TailBodyControlTarget::Label(label) => {
            composer.layout.label_offsets.get(&label).copied()
        }
        X64TailBodyControlTarget::Frontier(ordinal) => {
            composer.layout.frontier_offsets.get(&ordinal).copied()
        }
    }
    .ok_or(X64TailClosedImageError::MissingTarget {
        field: "relocation target",
    })?;
    let after = patch_offset
        .checked_add(4)
        .ok_or(X64TailClosedImageError::ArithmeticOverflow { field: "rel32 end" })?;
    let displacement64 = i64::from(target_offset) - i64::from(after);
    let displacement =
        i32::try_from(displacement64).map_err(|_| X64TailClosedImageError::Rel32OutOfRange {
            patch: patch_offset,
            displacement: displacement64,
        })?;
    let start =
        usize::try_from(patch_offset).map_err(|_| X64TailClosedImageError::ArithmeticOverflow {
            field: "patch offset",
        })?;
    let end = start
        .checked_add(4)
        .ok_or(X64TailClosedImageError::ArithmeticOverflow { field: "patch end" })?;
    composer
        .code
        .get_mut(start..end)
        .ok_or(X64TailClosedImageError::InvalidField {
            field: "patch range",
        })?
        .copy_from_slice(&displacement.to_le_bytes());
    composer.relocations.push(X64TailClosedRelocationReceipt {
        source_kind: origin.source_kind,
        program_kind: origin.program_kind,
        program_ordinal: origin.program_ordinal,
        atom_ordinal: origin.atom_ordinal,
        patch_offset,
        target,
        target_offset,
        displacement,
    });
    Ok(())
}

pub(super) fn derive_x64_tail_closed_layout(
    target: &X64TargetArtifact,
    binding: &X64TailSiteBindingProof,
    realization: &X64TailBodyFrontierRealization,
) -> Result<X64TailClosedDerivedLayout, X64TailClosedImageError> {
    ensure_limit(
        "programs",
        X64_TAIL_CLOSED_IMAGE_MAX_PROGRAMS,
        realization
            .sites()
            .len()
            .checked_add(realization.frontiers().len())
            .ok_or(X64TailClosedImageError::ArithmeticOverflow {
                field: "program count",
            })?,
    )?;
    ensure_limit(
        "labels",
        X64_TAIL_CLOSED_IMAGE_MAX_LABELS,
        target.program.labels.len(),
    )?;
    if binding.frontiers().len() != realization.frontiers().len() {
        return Err(X64TailClosedImageError::InvalidField {
            field: "frontier cardinality",
        });
    }
    let mut cursor = 0u32;
    let mut programs = Vec::new();
    let mut labels = Vec::new();
    let mut frontiers = Vec::new();
    let mut label_offsets = BTreeMap::new();
    let mut frontier_offsets = BTreeMap::new();
    let mut placed_sites = BTreeSet::new();
    let mut placed_frontiers = BTreeSet::new();

    for function in &target.program.functions {
        for block in &function.blocks {
            for frontier in realization.frontiers().iter().filter(|frontier| {
                frontier.placement == X64TailFrontierPlacement::BeforeLabel
                    && matches!(
                        frontier.disposition,
                        X64TailFrontierProgramDisposition::Operational
                    )
            }) {
                let row = frontier_row(binding, frontier.row_ordinal)?;
                if row.target_label == Some(block.label) {
                    place_frontier(
                        frontier,
                        &mut cursor,
                        &mut programs,
                        &mut frontiers,
                        &mut frontier_offsets,
                        &mut placed_frontiers,
                    )?;
                }
            }
            if label_offsets.insert(block.label, cursor).is_some() {
                return Err(X64TailClosedImageError::InvalidField {
                    field: "unique block label",
                });
            }
            labels.push(X64TailClosedLabelReceipt {
                label: block.label,
                offset: cursor,
            });
            for site in realization.sites().iter().filter(|site| {
                site.function == function.id && site.block == block.id && site.label == block.label
            }) {
                let start = cursor;
                cursor = cursor.checked_add(site.prospective_bytes).ok_or(
                    X64TailClosedImageError::ArithmeticOverflow {
                        field: "site layout",
                    },
                )?;
                programs.push(X64TailClosedProgramReceipt {
                    kind: X64TailClosedProgramKind::Site,
                    ordinal: site.ordinal,
                    start,
                    end: cursor,
                    atoms: usize_to_u32(site.atoms.len(), "site atoms")?,
                });
                if !placed_sites.insert(site.ordinal) {
                    return Err(X64TailClosedImageError::InvalidField {
                        field: "unique site placement",
                    });
                }
            }
            for frontier in realization.frontiers().iter().filter(|frontier| {
                frontier.placement == X64TailFrontierPlacement::ExitStub
                    && matches!(
                        frontier.disposition,
                        X64TailFrontierProgramDisposition::Operational
                    )
            }) {
                let row = frontier_row(binding, frontier.row_ordinal)?;
                if row.source_label == Some(block.label) {
                    place_frontier(
                        frontier,
                        &mut cursor,
                        &mut programs,
                        &mut frontiers,
                        &mut frontier_offsets,
                        &mut placed_frontiers,
                    )?;
                }
            }
        }
    }
    for frontier in realization.frontiers().iter().filter(|frontier| {
        matches!(
            frontier.placement,
            X64TailFrontierPlacement::EdgeStub | X64TailFrontierPlacement::CheckedExit
        ) && matches!(
            frontier.disposition,
            X64TailFrontierProgramDisposition::Operational
        )
    }) {
        place_frontier(
            frontier,
            &mut cursor,
            &mut programs,
            &mut frontiers,
            &mut frontier_offsets,
            &mut placed_frontiers,
        )?;
    }
    if placed_sites.len() != realization.sites().len() {
        return Err(X64TailClosedImageError::InvalidField {
            field: "complete site placement",
        });
    }
    let operational = realization
        .frontiers()
        .iter()
        .filter(|frontier| {
            matches!(
                frontier.disposition,
                X64TailFrontierProgramDisposition::Operational
            )
        })
        .count();
    if placed_frontiers.len() != operational {
        return Err(X64TailClosedImageError::InvalidField {
            field: "complete operational frontier placement",
        });
    }

    // Resolve zero-byte evidence rows without granting byte ownership.
    for frontier in realization.frontiers() {
        if frontier_offsets.contains_key(&frontier.row_ordinal) {
            continue;
        }
        let (offset, owner) = match frontier.disposition {
            X64TailFrontierProgramDisposition::NoOp => {
                let row = frontier_row(binding, frontier.row_ordinal)?;
                let label = row.target_label.or(row.source_label).ok_or(
                    X64TailClosedImageError::MissingTarget {
                        field: "no-op frontier label",
                    },
                )?;
                (
                    *label_offsets
                        .get(&label)
                        .ok_or(X64TailClosedImageError::MissingTarget {
                            field: "no-op label offset",
                        })?,
                    frontier.row_ordinal,
                )
            }
            X64TailFrontierProgramDisposition::CapsuleReference { site_ordinal } => {
                let program = programs
                    .iter()
                    .find(|program| {
                        program.kind == X64TailClosedProgramKind::Site
                            && program.ordinal == site_ordinal
                    })
                    .ok_or(X64TailClosedImageError::MissingTarget {
                        field: "capsule-reference site",
                    })?;
                (program.start, frontier.row_ordinal)
            }
            X64TailFrontierProgramDisposition::EvidenceAlias { owner_ordinal } => {
                let offset = *frontier_offsets.get(&owner_ordinal).ok_or(
                    X64TailClosedImageError::MissingTarget {
                        field: "frontier alias owner",
                    },
                )?;
                (offset, owner_ordinal)
            }
            X64TailFrontierProgramDisposition::Operational => {
                return Err(X64TailClosedImageError::InvalidField {
                    field: "unplaced operational frontier",
                })
            }
        };
        frontier_offsets.insert(frontier.row_ordinal, offset);
        frontiers.push(X64TailClosedFrontierReceipt {
            ordinal: frontier.row_ordinal,
            offset,
            end: offset,
            owner_ordinal: owner,
        });
        programs.push(X64TailClosedProgramReceipt {
            kind: X64TailClosedProgramKind::Frontier,
            ordinal: frontier.row_ordinal,
            start: offset,
            end: offset,
            atoms: 0,
        });
    }

    let terminal_specs = [
        (
            X64TailClosedTerminalKind::EntryAdapter,
            X64LabelOwner::EntryAdapter,
        ),
        (
            X64TailClosedTerminalKind::ReturnEpilogue,
            X64LabelOwner::ReturnEpilogue,
        ),
        (
            X64TailClosedTerminalKind::BoundsEpilogue,
            X64LabelOwner::BoundsEpilogue,
        ),
    ];
    let mut terminals = Vec::new();
    for (kind, owner) in terminal_specs {
        let label = unique_owner_label(&target.program, owner)?;
        if label_offsets.insert(label, cursor).is_some() {
            return Err(X64TailClosedImageError::InvalidField {
                field: "terminal label collision",
            });
        }
        labels.push(X64TailClosedLabelReceipt {
            label,
            offset: cursor,
        });
        terminals.push(X64TailClosedTerminalReceipt {
            kind,
            label,
            offset: cursor,
        });
        cursor = cursor
            .checked_add(1)
            .ok_or(X64TailClosedImageError::ArithmeticOverflow {
                field: "terminal layout",
            })?;
    }
    if u64::from(cursor) > X64_TAIL_CLOSED_IMAGE_MAX_CODE_BYTES {
        return Err(X64TailClosedImageError::LimitExceeded {
            field: "code bytes",
            limit: X64_TAIL_CLOSED_IMAGE_MAX_CODE_BYTES,
            actual: u64::from(cursor),
        });
    }
    programs.sort_by_key(|program| (program.start, program.end, program.kind, program.ordinal));
    labels.sort_by_key(|label| label.label);
    frontiers.sort_by_key(|frontier| frontier.ordinal);
    let entry_function = target
        .program
        .functions
        .iter()
        .find(|function| function.id == target.program.entry)
        .ok_or(X64TailClosedImageError::MissingTarget {
            field: "entry function",
        })?;
    let entry_block = entry_function
        .blocks
        .iter()
        .find(|block| block.id == entry_function.entry_block)
        .ok_or(X64TailClosedImageError::MissingTarget {
            field: "entry block",
        })?;
    let entry_frontier = realization
        .frontiers()
        .iter()
        .filter(|frontier| {
            matches!(frontier.kind, X64TailFrontierBindingKind::Entry)
                && matches!(
                    frontier.disposition,
                    X64TailFrontierProgramDisposition::Operational
                )
        })
        .collect::<Vec<_>>();
    let entry_successor = match entry_frontier.as_slice() {
        [] => X64TailBodyControlTarget::Label(entry_block.label),
        [frontier] => X64TailBodyControlTarget::Frontier(frontier.row_ordinal),
        _ => {
            return Err(X64TailClosedImageError::InvalidField {
                field: "unique entry frontier",
            })
        }
    };
    Ok(X64TailClosedDerivedLayout {
        programs,
        labels,
        frontiers,
        terminals,
        label_offsets,
        frontier_offsets,
        entry_successor,
        code_bytes: cursor,
    })
}

fn place_frontier(
    frontier: &super::x64_tail_body_frontier_realization::X64TailFrontierProgram,
    cursor: &mut u32,
    programs: &mut Vec<X64TailClosedProgramReceipt>,
    frontiers: &mut Vec<X64TailClosedFrontierReceipt>,
    offsets: &mut BTreeMap<u32, u32>,
    placed: &mut BTreeSet<u32>,
) -> Result<(), X64TailClosedImageError> {
    let start = *cursor;
    *cursor = cursor.checked_add(frontier.prospective_bytes).ok_or(
        X64TailClosedImageError::ArithmeticOverflow {
            field: "frontier layout",
        },
    )?;
    if offsets.insert(frontier.row_ordinal, start).is_some() || !placed.insert(frontier.row_ordinal)
    {
        return Err(X64TailClosedImageError::InvalidField {
            field: "unique frontier placement",
        });
    }
    programs.push(X64TailClosedProgramReceipt {
        kind: X64TailClosedProgramKind::Frontier,
        ordinal: frontier.row_ordinal,
        start,
        end: *cursor,
        atoms: usize_to_u32(frontier.atoms.len(), "frontier atoms")?,
    });
    frontiers.push(X64TailClosedFrontierReceipt {
        ordinal: frontier.row_ordinal,
        offset: start,
        end: *cursor,
        owner_ordinal: frontier.row_ordinal,
    });
    Ok(())
}

fn frontier_row(
    binding: &X64TailSiteBindingProof,
    ordinal: u32,
) -> Result<&super::x64_tail_site_binding::X64TailFrontierBindingRow, X64TailClosedImageError> {
    binding
        .frontiers()
        .iter()
        .find(|row| row.ordinal == ordinal)
        .ok_or(X64TailClosedImageError::MissingTarget {
            field: "frontier binding row",
        })
}

fn unique_owner_label(
    program: &X64TargetProgram,
    owner: X64LabelOwner,
) -> Result<X64LabelId, X64TailClosedImageError> {
    let mut labels = program.labels.iter().filter(|label| label.owner == owner);
    let label = labels
        .next()
        .ok_or(X64TailClosedImageError::MissingTarget {
            field: "terminal owner label",
        })?;
    if labels.next().is_some() {
        return Err(X64TailClosedImageError::InvalidField {
            field: "unique terminal owner label",
        });
    }
    Ok(label.id)
}

fn derive_cfg_edges(
    realization: &X64TailBodyFrontierRealization,
    binding: &X64TailSiteBindingProof,
    layout: &X64TailClosedDerivedLayout,
    relocations: &[X64TailClosedRelocationReceipt],
    programs: &BTreeMap<(X64TailClosedProgramKind, u32), X64TailClosedProgramReceipt>,
) -> Result<Vec<X64TailClosedCfgEdge>, X64TailClosedImageError> {
    let mut edges = Vec::new();
    let entry_anchor = layout
        .terminals
        .iter()
        .find(|terminal| terminal.kind == X64TailClosedTerminalKind::EntryAdapter)
        .ok_or(X64TailClosedImageError::MissingTarget {
            field: "entry terminal",
        })?;
    edges.push(X64TailClosedCfgEdge {
        kind: X64TailClosedCfgEdgeKind::Entry,
        source_offset: entry_anchor.offset,
        destination: control_destination(layout, layout.entry_successor)?,
    });
    for relocation in relocations {
        edges.push(X64TailClosedCfgEdge {
            kind: X64TailClosedCfgEdgeKind::Rel32,
            source_offset: relocation.patch_offset,
            destination: control_destination(layout, relocation.target)?,
        });
        let atom = match relocation.program_kind {
            X64TailClosedProgramKind::Site => realization
                .sites()
                .iter()
                .find(|site| site.ordinal == relocation.program_ordinal)
                .and_then(|site| {
                    site.atoms
                        .iter()
                        .find(|atom| atom.ordinal == relocation.atom_ordinal)
                }),
            X64TailClosedProgramKind::Frontier => realization
                .frontiers()
                .iter()
                .find(|frontier| frontier.row_ordinal == relocation.program_ordinal)
                .and_then(|frontier| {
                    frontier
                        .atoms
                        .iter()
                        .find(|atom| atom.ordinal == relocation.atom_ordinal)
                }),
        }
        .ok_or(X64TailClosedImageError::MissingTarget {
            field: "relocation atom",
        })?;
        if matches!(
            atom.instruction,
            X64TailBodyAtomInstruction::BranchNonZeroRel32 { .. }
                | X64TailBodyAtomInstruction::BoundsNegativeRel32 { .. }
                | X64TailBodyAtomInstruction::BoundsUpperRel32 { .. }
        ) {
            let program = programs
                .get(&(relocation.program_kind, relocation.program_ordinal))
                .ok_or(X64TailClosedImageError::MissingTarget {
                    field: "conditional program",
                })?;
            let atom_end = program.start.checked_add(atom.end).ok_or(
                X64TailClosedImageError::ArithmeticOverflow {
                    field: "conditional fallthrough",
                },
            )?;
            edges.push(X64TailClosedCfgEdge {
                kind: X64TailClosedCfgEdgeKind::ConditionalFallthrough,
                source_offset: atom_end,
                destination: X64TailClosedCfgDestination::InstructionBoundary {
                    program_kind: relocation.program_kind,
                    program_ordinal: relocation.program_ordinal,
                    offset: atom_end,
                },
            });
        }
    }
    for frontier in realization.frontiers().iter().filter(|frontier| {
        matches!(
            frontier.disposition,
            X64TailFrontierProgramDisposition::Operational
        )
    }) {
        let receipt = layout
            .frontiers
            .iter()
            .find(|receipt| receipt.ordinal == frontier.row_ordinal)
            .ok_or(X64TailClosedImageError::MissingTarget {
                field: "frontier receipt",
            })?;
        let row = frontier_row(binding, frontier.row_ordinal)?;
        if frontier.placement == X64TailFrontierPlacement::BeforeLabel {
            let label = row
                .target_label
                .ok_or(X64TailClosedImageError::MissingTarget {
                    field: "before-label continuation",
                })?;
            edges.push(X64TailClosedCfgEdge {
                kind: X64TailClosedCfgEdgeKind::FrontierFallthrough,
                source_offset: receipt.end,
                destination: control_destination(layout, X64TailBodyControlTarget::Label(label))?,
            });
        } else if frontier.placement == X64TailFrontierPlacement::ExitStub {
            let source = row
                .source_label
                .ok_or(X64TailClosedImageError::MissingTarget {
                    field: "exit frontier source",
                })?;
            edges.push(X64TailClosedCfgEdge {
                kind: X64TailClosedCfgEdgeKind::FrontierFallthrough,
                source_offset: receipt.offset,
                destination: X64TailClosedCfgDestination::Frontier {
                    ordinal: frontier.row_ordinal,
                    offset: receipt.offset,
                },
            });
            let has_source_site = realization.sites().iter().any(|site| site.label == source);
            let empty_source_starts_at_frontier =
                layout.label_offsets.get(&source).copied() == Some(receipt.offset);
            if !has_source_site && !empty_source_starts_at_frontier {
                return Err(X64TailClosedImageError::InvalidField {
                    field: "exit frontier source coverage",
                });
            }
        }
    }
    edges.sort_by_key(|edge| {
        (
            edge.source_offset,
            cfg_tag(edge.kind),
            cfg_destination_key(edge.destination),
        )
    });
    edges.dedup();
    Ok(edges)
}

fn control_offset(
    layout: &X64TailClosedDerivedLayout,
    target: X64TailBodyControlTarget,
) -> Result<u32, X64TailClosedImageError> {
    match target {
        X64TailBodyControlTarget::Label(label) => layout.label_offsets.get(&label),
        X64TailBodyControlTarget::Frontier(ordinal) => layout.frontier_offsets.get(&ordinal),
    }
    .copied()
    .ok_or(X64TailClosedImageError::MissingTarget {
        field: "control offset",
    })
}

fn control_destination(
    layout: &X64TailClosedDerivedLayout,
    target: X64TailBodyControlTarget,
) -> Result<X64TailClosedCfgDestination, X64TailClosedImageError> {
    let offset = control_offset(layout, target)?;
    Ok(match target {
        X64TailBodyControlTarget::Label(label) => {
            X64TailClosedCfgDestination::Label { label, offset }
        }
        X64TailBodyControlTarget::Frontier(ordinal) => {
            X64TailClosedCfgDestination::Frontier { ordinal, offset }
        }
    })
}

fn validate_envelope(
    image: &X64TailClosedImage,
    body: &X64TailBodyFrontierCapsule,
    realization: &X64TailBodyFrontierRealization,
    binding: &X64TailSiteBindingProof,
    transition: &X64TailCandidateCapsule,
    target: &X64TargetArtifact,
) -> Result<(), X64TailClosedImageError> {
    if image.schema_version != X64_TAIL_CLOSED_IMAGE_SCHEMA_VERSION
        || image.policy_version != X64_TAIL_CLOSED_IMAGE_POLICY_VERSION
        || image.decoder_policy_version
            != super::x64_tail_closed_image_decode::X64_TAIL_CLOSED_IMAGE_DECODER_POLICY_VERSION
    {
        return Err(X64TailClosedImageError::InvalidField {
            field: "schema or policy version",
        });
    }
    if image.source_target_semantic_hash != target.semantic_hash
        || image.source_transition_capsule_hash != transition.capsule_hash()
        || image.source_body_capsule_hash != body.capsule_hash()
        || image.source_realization_hash != realization.realization_hash()
        || image.source_binding_hash != binding.proof_hash()
    {
        return Err(X64TailClosedImageError::InvalidField {
            field: "predecessor identity",
        });
    }
    if image.totals.code_bytes != usize_to_u32(image.code.len(), "code bytes")? {
        return Err(X64TailClosedImageError::InvalidField {
            field: "code total",
        });
    }
    Ok(())
}

pub fn x64_tail_closed_image_code_hash(
    code: &[u8],
) -> Result<SemanticHash, X64TailClosedImageError> {
    if code.len() as u64 > X64_TAIL_CLOSED_IMAGE_MAX_CODE_BYTES {
        return Err(X64TailClosedImageError::LimitExceeded {
            field: "code bytes",
            limit: X64_TAIL_CLOSED_IMAGE_MAX_CODE_BYTES,
            actual: code.len() as u64,
        });
    }
    let mut bytes = Vec::with_capacity(CODE_DOMAIN.len() + 8 + code.len());
    bytes.extend_from_slice(CODE_DOMAIN);
    bytes.extend_from_slice(&(code.len() as u64).to_le_bytes());
    bytes.extend_from_slice(code);
    Ok(SemanticHash(sha256(&bytes)))
}

pub fn x64_tail_closed_image_hash(
    image: &X64TailClosedImage,
) -> Result<SemanticHash, X64TailClosedImageError> {
    let mut e = EvidenceEncoder::new();
    e.bytes(IMAGE_DOMAIN)?;
    e.version(image.schema_version);
    e.version(image.policy_version);
    e.version(image.decoder_policy_version);
    e.hash(image.source_target_semantic_hash);
    e.hash(image.source_transition_capsule_hash);
    e.hash(image.source_body_capsule_hash);
    e.hash(image.source_realization_hash);
    e.hash(image.source_binding_hash);
    e.control(image.entry_successor);
    e.vec_len(image.program_receipts.len())?;
    for p in &image.program_receipts {
        e.u8(program_tag(p.kind));
        e.u32(p.ordinal);
        e.u32(p.start);
        e.u32(p.end);
        e.u32(p.atoms);
    }
    e.vec_len(image.label_receipts.len())?;
    for r in &image.label_receipts {
        e.u32(r.label.0);
        e.u32(r.offset);
    }
    e.vec_len(image.frontier_receipts.len())?;
    for r in &image.frontier_receipts {
        e.u32(r.ordinal);
        e.u32(r.offset);
        e.u32(r.end);
        e.u32(r.owner_ordinal);
    }
    e.vec_len(image.terminal_receipts.len())?;
    for r in &image.terminal_receipts {
        e.u8(terminal_tag(r.kind));
        e.u32(r.label.0);
        e.u32(r.offset);
    }
    e.vec_len(image.source_receipts.len())?;
    for r in &image.source_receipts {
        e.u8(source_tag(r.source_kind));
        e.u8(program_tag(r.program_kind));
        e.u32(r.program_ordinal);
        e.u32(r.atom_ordinal);
        e.u32(r.source_start);
        e.u32(r.source_end);
        e.u32(r.image_start);
        e.u32(r.image_end);
    }
    e.vec_len(image.relocation_receipts.len())?;
    for r in &image.relocation_receipts {
        e.u8(source_tag(r.source_kind));
        e.u8(program_tag(r.program_kind));
        e.u32(r.program_ordinal);
        e.u32(r.atom_ordinal);
        e.u32(r.patch_offset);
        e.control(r.target);
        e.u32(r.target_offset);
        e.i32(r.displacement);
    }
    e.vec_len(image.cfg_edges.len())?;
    for edge in &image.cfg_edges {
        e.u8(cfg_tag(edge.kind));
        e.u32(edge.source_offset);
        encode_cfg_destination(&mut e, edge.destination);
    }
    e.bytes(&image.code_hash.0)?;
    encode_totals(&mut e, image.totals);
    e.bytes(&image.code)?;
    Ok(SemanticHash(sha256(&e.finish())))
}

fn encode_totals(e: &mut EvidenceEncoder, t: X64TailClosedImageTotals) {
    for value in [
        t.programs,
        t.labels,
        t.frontiers,
        t.terminals,
        t.source_ranges,
        t.body_ranges,
        t.transition_ranges,
        t.relocations,
        t.cfg_edges,
        t.body_bytes,
        t.transition_bytes,
        t.terminal_bytes,
        t.code_bytes,
    ] {
        e.u32(value);
    }
    e.u64(t.compose_work);
    e.u64(t.decode_work);
}
fn program_tag(value: X64TailClosedProgramKind) -> u8 {
    match value {
        X64TailClosedProgramKind::Site => 0,
        X64TailClosedProgramKind::Frontier => 1,
    }
}
fn terminal_tag(value: X64TailClosedTerminalKind) -> u8 {
    match value {
        X64TailClosedTerminalKind::EntryAdapter => 0,
        X64TailClosedTerminalKind::ReturnEpilogue => 1,
        X64TailClosedTerminalKind::BoundsEpilogue => 2,
    }
}
fn source_tag(value: X64TailClosedSourceKind) -> u8 {
    match value {
        X64TailClosedSourceKind::Body => 0,
        X64TailClosedSourceKind::Transition => 1,
    }
}
fn cfg_tag(value: X64TailClosedCfgEdgeKind) -> u8 {
    match value {
        X64TailClosedCfgEdgeKind::Entry => 0,
        X64TailClosedCfgEdgeKind::FrontierFallthrough => 1,
        X64TailClosedCfgEdgeKind::ConditionalFallthrough => 2,
        X64TailClosedCfgEdgeKind::Rel32 => 3,
    }
}
fn encode_cfg_destination(e: &mut EvidenceEncoder, value: X64TailClosedCfgDestination) {
    match value {
        X64TailClosedCfgDestination::Label { label, offset } => {
            e.u8(0);
            e.u32(label.0);
            e.u32(offset);
        }
        X64TailClosedCfgDestination::Frontier { ordinal, offset } => {
            e.u8(1);
            e.u32(ordinal);
            e.u32(offset);
        }
        X64TailClosedCfgDestination::InstructionBoundary {
            program_kind,
            program_ordinal,
            offset,
        } => {
            e.u8(2);
            e.u8(program_tag(program_kind));
            e.u32(program_ordinal);
            e.u32(offset);
        }
    }
}
fn cfg_destination_key(value: X64TailClosedCfgDestination) -> (u8, u8, u32, u32) {
    match value {
        X64TailClosedCfgDestination::Label { label, offset } => (0, 0, label.0, offset),
        X64TailClosedCfgDestination::Frontier { ordinal, offset } => (1, 0, ordinal, offset),
        X64TailClosedCfgDestination::InstructionBoundary {
            program_kind,
            program_ordinal,
            offset,
        } => (2, program_tag(program_kind), program_ordinal, offset),
    }
}
fn control_tag(value: X64TailBodyControlTarget) -> u8 {
    match value {
        X64TailBodyControlTarget::Label(_) => 0,
        X64TailBodyControlTarget::Frontier(_) => 1,
    }
}
fn control_value(value: X64TailBodyControlTarget) -> u32 {
    match value {
        X64TailBodyControlTarget::Label(label) => label.0,
        X64TailBodyControlTarget::Frontier(ordinal) => ordinal,
    }
}

struct EvidenceEncoder {
    bytes: Vec<u8>,
}
impl EvidenceEncoder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }
    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn i32(&mut self, value: i32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn version(&mut self, value: (u16, u16, u16)) {
        self.bytes.extend_from_slice(&value.0.to_le_bytes());
        self.bytes.extend_from_slice(&value.1.to_le_bytes());
        self.bytes.extend_from_slice(&value.2.to_le_bytes());
    }
    fn hash(&mut self, value: SemanticHash) {
        self.bytes.extend_from_slice(&value.0);
    }
    fn control(&mut self, value: X64TailBodyControlTarget) {
        self.u8(control_tag(value));
        self.u32(control_value(value));
    }
    fn vec_len(&mut self, len: usize) -> Result<(), X64TailClosedImageError> {
        self.u32(usize_to_u32(len, "evidence vector")?);
        Ok(())
    }
    fn bytes(&mut self, value: &[u8]) -> Result<(), X64TailClosedImageError> {
        let next = self.bytes.len().checked_add(value.len()).ok_or(
            X64TailClosedImageError::ArithmeticOverflow {
                field: "evidence bytes",
            },
        )?;
        if next > X64_TAIL_CLOSED_IMAGE_MAX_EVIDENCE_BYTES {
            return Err(X64TailClosedImageError::EncodingLimit { actual: next });
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }
    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn checked_add(left: u32, right: u32, field: &'static str) -> Result<u32, X64TailClosedImageError> {
    left.checked_add(right)
        .ok_or(X64TailClosedImageError::ArithmeticOverflow { field })
}
fn usize_to_u32(value: usize, field: &'static str) -> Result<u32, X64TailClosedImageError> {
    u32::try_from(value).map_err(|_| X64TailClosedImageError::ArithmeticOverflow { field })
}
fn ensure_limit(
    field: &'static str,
    limit: u32,
    actual: usize,
) -> Result<(), X64TailClosedImageError> {
    if actual as u64 > u64::from(limit) {
        Err(X64TailClosedImageError::LimitExceeded {
            field,
            limit: u64::from(limit),
            actual: actual as u64,
        })
    } else {
        Ok(())
    }
}
fn charge(work: u64, amount: u64) -> Result<u64, X64TailClosedImageError> {
    let work = work
        .checked_add(amount)
        .ok_or(X64TailClosedImageError::ArithmeticOverflow {
            field: "compose work",
        })?;
    if work > X64_TAIL_CLOSED_IMAGE_MAX_WORK {
        return Err(X64TailClosedImageError::LimitExceeded {
            field: "compose work",
            limit: X64_TAIL_CLOSED_IMAGE_MAX_WORK,
            actual: work,
        });
    }
    Ok(work)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::corevm0_gate_a::CoreVmGateAWorkload;
    use crate::core::x64_native_lighthouse::X64NativeLighthousePackage;
    use crate::core::{
        emit_x64_tail_body_frontier_capsule, emit_x64_tail_body_frontier_realization,
        emit_x64_tail_candidate_capsule, emit_x64_tail_physical_allocation,
        emit_x64_tail_site_binding_proof, emit_x64_tail_state_plan,
        emit_x64_tail_template_realization, X64_TARGET_ENCODER_POLICY_VERSION,
    };

    type Build = (
        X64NativeLighthousePackage,
        X64TailStatePlan,
        X64TailPhysicalAllocation,
        X64TailTemplateRealization,
        X64TailCandidateCapsule,
        X64TailSiteBindingProof,
        X64TailBodyFrontierRealization,
        X64TailBodyFrontierCapsule,
    );

    fn build(workload: CoreVmGateAWorkload) -> Build {
        let package =
            X64NativeLighthousePackage::build(workload).expect("lighthouse package must build");
        let logical = emit_x64_tail_state_plan(package.target()).expect("logical plan must emit");
        let physical = emit_x64_tail_physical_allocation(package.target(), &logical)
            .expect("physical allocation must emit");
        let templates = emit_x64_tail_template_realization(package.target(), &logical, &physical)
            .expect("tail templates must emit");
        let transition =
            emit_x64_tail_candidate_capsule(package.target(), &logical, &physical, &templates)
                .expect("transition capsule must emit");
        let binding = emit_x64_tail_site_binding_proof(
            package.target(),
            &logical,
            &physical,
            &templates,
            &transition,
        )
        .expect("site binding must emit");
        let realization = emit_x64_tail_body_frontier_realization(
            package.target(),
            &logical,
            &physical,
            &templates,
            &transition,
            &binding,
        )
        .expect("body realization must emit");
        let body = emit_x64_tail_body_frontier_capsule(
            package.target(),
            &logical,
            &physical,
            &templates,
            &transition,
            &binding,
            &realization,
        )
        .expect("body capsule must emit");
        (
            package,
            logical,
            physical,
            templates,
            transition,
            binding,
            realization,
            body,
        )
    }

    #[test]
    fn branch_lighthouse_composes_one_closed_semantic_image() {
        let (package, logical, physical, templates, transition, binding, realization, body) =
            build(CoreVmGateAWorkload::BranchMix);
        let original = package.target().program.code.clone();
        let original_hash = package.target().program.code_hash;
        let first = emit_x64_tail_closed_image(
            package.target(),
            &logical,
            &physical,
            &templates,
            &transition,
            &binding,
            &realization,
            &body,
        )
        .expect("closed image must compose");
        let second = emit_x64_tail_closed_image(
            package.target(),
            &logical,
            &physical,
            &templates,
            &transition,
            &binding,
            &realization,
            &body,
        )
        .expect("closed image must be deterministic");
        assert_eq!(first, second);
        let verified = verify_x64_tail_closed_image(
            &first,
            &body,
            &realization,
            &binding,
            &transition,
            &templates,
            &physical,
            &logical,
            package.target(),
        )
        .expect("closed image must independently replay");
        assert_eq!(verified.decoded().totals, first.totals());

        let mut byte_owners = vec![0u8; first.code().len()];
        for source in first.source_receipts() {
            let start = usize::try_from(source.image_start).expect("source start must fit");
            let end = usize::try_from(source.image_end).expect("source end must fit");
            for owner in &mut byte_owners[start..end] {
                *owner = owner.checked_add(1).expect("byte ownership must fit");
            }
        }
        for terminal in first.terminal_receipts() {
            let offset = usize::try_from(terminal.offset).expect("terminal offset must fit");
            byte_owners[offset] = byte_owners[offset]
                .checked_add(1)
                .expect("terminal ownership must fit");
        }
        assert!(byte_owners.iter().all(|owners| *owners == 1));

        let patch_offsets = first
            .relocation_receipts()
            .iter()
            .map(|relocation| relocation.patch_offset)
            .collect::<BTreeSet<_>>();
        assert_eq!(patch_offsets.len(), first.relocation_receipts().len());
        for relocation in first.relocation_receipts() {
            assert!(first.source_receipts().iter().any(|source| {
                source.source_kind == relocation.source_kind
                    && source.program_kind == relocation.program_kind
                    && source.program_ordinal == relocation.program_ordinal
                    && source.atom_ordinal == relocation.atom_ordinal
                    && relocation.patch_offset >= source.image_start
                    && relocation.patch_offset.checked_add(4) <= Some(source.image_end)
            }));
        }
        for edge in first.cfg_edges() {
            match edge.destination {
                X64TailClosedCfgDestination::Label { label, offset } => assert!(first
                    .label_receipts()
                    .iter()
                    .any(|receipt| receipt.label == label && receipt.offset == offset)),
                X64TailClosedCfgDestination::Frontier { ordinal, offset } => assert!(first
                    .frontier_receipts()
                    .iter()
                    .any(|receipt| receipt.ordinal == ordinal && receipt.offset == offset)),
                X64TailClosedCfgDestination::InstructionBoundary {
                    program_kind,
                    program_ordinal,
                    offset,
                } => assert!(first.program_receipts().iter().any(|receipt| {
                    receipt.kind == program_kind
                        && receipt.ordinal == program_ordinal
                        && offset > receipt.start
                        && offset <= receipt.end
                })),
            }
        }
        assert_eq!(
            first.image_hash().to_hex(),
            "44d504cddf12cc7f9766f3f33b90968cca9b1fb46f65aaa2d8aa02c1e1e960aa"
        );
        assert_eq!(
            first.code_hash().to_hex(),
            "c0b7aa0d92401e9b98e26adc4aa28d3d8f52dc29695820aa895ce53d9e09abd5"
        );
        assert_eq!(
            first.totals(),
            X64TailClosedImageTotals {
                programs: 319,
                labels: 142,
                frontiers: 151,
                terminals: 3,
                source_ranges: 746,
                body_ranges: 638,
                transition_ranges: 108,
                relocations: 191,
                cfg_edges: 209,
                body_bytes: 5_169,
                transition_bytes: 2_103,
                terminal_bytes: 3,
                code_bytes: 7_275,
                compose_work: 8_021,
                decode_work: 8_021,
            }
        );
        assert_eq!(
            first.totals.body_bytes,
            body.totals().site_bytes + body.totals().frontier_bytes
        );
        assert_eq!(
            first.totals.transition_bytes,
            transition.totals().transition_bytes
        );
        assert_eq!(first.totals.terminal_bytes, 3);
        assert_eq!(
            first.totals.code_bytes,
            first.totals.body_bytes + first.totals.transition_bytes + 3
        );
        assert_eq!(package.target().program.code, original);
        assert_eq!(package.target().program.code_hash, original_hash);
        assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
    }

    #[test]
    fn every_image_bit_and_resealed_evidence_mutation_fails_closed() {
        let (package, logical, physical, templates, transition, binding, realization, body) =
            build(CoreVmGateAWorkload::BranchMix);
        let image = emit_x64_tail_closed_image(
            package.target(),
            &logical,
            &physical,
            &templates,
            &transition,
            &binding,
            &realization,
            &body,
        )
        .expect("closed image must compose");

        for byte in 0..image.code.len() {
            for bit in 0..8 {
                let mut code = image.code.clone();
                code[byte] ^= 1 << bit;
                assert!(decode_x64_tail_closed_image(
                    &code,
                    &body,
                    &realization,
                    &binding,
                    &transition,
                    &templates,
                    package.target(),
                )
                .is_err());
            }
        }
        assert!(decode_x64_tail_closed_image(
            &image.code[..image.code.len() - 1],
            &body,
            &realization,
            &binding,
            &transition,
            &templates,
            package.target(),
        )
        .is_err());
        let mut trailing = image.code.clone();
        trailing.push(TERMINAL_BYTE);
        assert!(decode_x64_tail_closed_image(
            &trailing,
            &body,
            &realization,
            &binding,
            &transition,
            &templates,
            package.target(),
        )
        .is_err());

        macro_rules! reject_resealed {
            ($mutated:ident) => {{
                $mutated.image_hash = x64_tail_closed_image_hash(&$mutated)
                    .expect("mutated evidence must reseal locally");
                assert!(verify_x64_tail_closed_image(
                    &$mutated,
                    &body,
                    &realization,
                    &binding,
                    &transition,
                    &templates,
                    &physical,
                    &logical,
                    package.target(),
                )
                .is_err());
            }};
        }

        let mut program = image.clone();
        program.program_receipts[0].end ^= 1;
        reject_resealed!(program);

        let mut label = image.clone();
        label.label_receipts[0].offset ^= 1;
        reject_resealed!(label);

        let mut frontier = image.clone();
        frontier.frontier_receipts[0].owner_ordinal ^= 1;
        reject_resealed!(frontier);

        let mut terminal = image.clone();
        terminal.terminal_receipts[0].offset ^= 1;
        reject_resealed!(terminal);

        let mut source = image.clone();
        source.source_receipts[0].source_start ^= 1;
        reject_resealed!(source);

        let mut relocation = image.clone();
        relocation.relocation_receipts[0].target_offset ^= 1;
        reject_resealed!(relocation);

        let mut cfg = image.clone();
        cfg.cfg_edges[0].source_offset ^= 1;
        reject_resealed!(cfg);

        let mut totals = image.clone();
        totals.totals.source_ranges ^= 1;
        reject_resealed!(totals);

        let mut predecessor = image.clone();
        predecessor.source_body_capsule_hash.0[0] ^= 1;
        reject_resealed!(predecessor);

        let mut code_hash = image.clone();
        code_hash.code_hash.0[0] ^= 1;
        reject_resealed!(code_hash);

        let mut seal = image;
        seal.image_hash.0[0] ^= 1;
        assert!(verify_x64_tail_closed_image(
            &seal,
            &body,
            &realization,
            &binding,
            &transition,
            &templates,
            &physical,
            &logical,
            package.target(),
        )
        .is_err());
    }
}
