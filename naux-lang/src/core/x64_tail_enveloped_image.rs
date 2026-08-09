//! Fully enveloped, non-executable ADR-0067 semantic image composition.
//!
//! The artifact composes only verified ADR-0065 and ADR-0066 bytes. It owns
//! final placement and checked rel32 repatching, but exposes no mapping,
//! execution, native, process, standalone, or measurement authority.

use super::encoding::sha256;
use super::machine_ir::MachineType;
use super::schema::SemanticHash;
use super::x64_tail_abi_envelope::{
    VerifiedX64TailAbiEnvelopeCapsule, X64TailAbiEnvelopeEffect,
    X64TailAbiEnvelopeInstructionReceipt, X64TailAbiEnvelopeProgramKind,
    X64TailAbiEnvelopeProgramReceipt,
};
use super::x64_tail_body_frontier_realization::X64TailBodyControlTarget;
use super::x64_tail_closed_image::{
    VerifiedX64TailClosedImage, X64TailClosedCfgDestination, X64TailClosedCfgEdge,
    X64TailClosedCfgEdgeKind, X64TailClosedFrontierReceipt, X64TailClosedLabelReceipt,
    X64TailClosedProgramKind, X64TailClosedProgramReceipt, X64TailClosedSourceKind,
    X64TailClosedSourceReceipt, X64TailClosedTerminalKind,
};
use super::x64_tail_enveloped_image_decode::{
    decode_x64_tail_enveloped_image, X64TailDecodedEnvelopedImage, X64TailEnvelopedImageDecodeError,
};
use super::x64_target::{verify_x64_target_r1_s7a, X64AbiRegister, X64LabelId, X64TargetArtifact};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const X64_TAIL_ENVELOPED_IMAGE_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_ENVELOPED_IMAGE_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_ENVELOPED_IMAGE_MAX_CODE_BYTES: u64 = 128 * 1024 * 1024;
pub const X64_TAIL_ENVELOPED_IMAGE_MAX_RELOCATIONS: u32 = 2_004_097;
pub const X64_TAIL_ENVELOPED_IMAGE_MAX_WORK: u64 = 64_000_000;
pub const X64_TAIL_ENVELOPED_IMAGE_MAX_EVIDENCE_BYTES: usize = 128 * 1024 * 1024;

const CODE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-enveloped-image-code:v1\0";
const IMAGE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-enveloped-image:v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum X64TailEnvelopedSourceKind {
    ClosedPrefix,
    EntryAdapter,
    ReturnEpilogue,
    BoundsEpilogue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailEnvelopedSourceReceipt {
    pub kind: X64TailEnvelopedSourceKind,
    pub source_start: u32,
    pub source_end: u32,
    pub image_start: u32,
    pub image_end: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailEnvelopedRelocationOrigin {
    ClosedImage {
        source_kind: X64TailClosedSourceKind,
        program_kind: X64TailClosedProgramKind,
        program_ordinal: u32,
        atom_ordinal: u32,
    },
    EntryAdapter {
        instruction_ordinal: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailEnvelopedRelocationReceipt {
    pub origin: X64TailEnvelopedRelocationOrigin,
    pub patch_offset: u32,
    pub target: X64TailBodyControlTarget,
    pub target_offset: u32,
    pub displacement: i32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X64TailEnvelopedImageTotals {
    pub closed_programs: u32,
    pub abi_programs: u32,
    pub labels: u32,
    pub frontiers: u32,
    pub closed_source_ranges: u32,
    pub composition_source_spans: u32,
    pub abi_instructions: u32,
    pub abi_effects: u32,
    pub relocations: u32,
    pub cfg_edges: u32,
    pub closed_prefix_bytes: u32,
    pub entry_bytes: u32,
    pub return_bytes: u32,
    pub bounds_bytes: u32,
    pub code_bytes: u32,
    pub compose_work: u64,
    pub decode_work: u64,
    pub projection_work: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailEnvelopedImage {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    decoder_policy_version: (u16, u16, u16),
    source_target_semantic_hash: SemanticHash,
    source_closed_image_hash: SemanticHash,
    source_abi_capsule_hash: SemanticHash,
    entry_successor: X64TailBodyControlTarget,
    entry_point: u32,
    source_spans: Vec<X64TailEnvelopedSourceReceipt>,
    closed_programs: Vec<X64TailClosedProgramReceipt>,
    label_receipts: Vec<X64TailClosedLabelReceipt>,
    frontier_receipts: Vec<X64TailClosedFrontierReceipt>,
    closed_sources: Vec<X64TailClosedSourceReceipt>,
    abi_programs: Vec<X64TailAbiEnvelopeProgramReceipt>,
    abi_instructions: Vec<X64TailAbiEnvelopeInstructionReceipt>,
    relocation_receipts: Vec<X64TailEnvelopedRelocationReceipt>,
    cfg_edges: Vec<X64TailClosedCfgEdge>,
    code: Vec<u8>,
    code_hash: SemanticHash,
    totals: X64TailEnvelopedImageTotals,
    image_hash: SemanticHash,
}

impl X64TailEnvelopedImage {
    pub const fn source_target_semantic_hash(&self) -> SemanticHash {
        self.source_target_semantic_hash
    }
    pub const fn source_closed_image_hash(&self) -> SemanticHash {
        self.source_closed_image_hash
    }
    pub const fn source_abi_capsule_hash(&self) -> SemanticHash {
        self.source_abi_capsule_hash
    }
    pub const fn entry_successor(&self) -> X64TailBodyControlTarget {
        self.entry_successor
    }
    pub const fn entry_point(&self) -> u32 {
        self.entry_point
    }
    pub fn source_spans(&self) -> &[X64TailEnvelopedSourceReceipt] {
        &self.source_spans
    }
    pub fn closed_programs(&self) -> &[X64TailClosedProgramReceipt] {
        &self.closed_programs
    }
    pub fn label_receipts(&self) -> &[X64TailClosedLabelReceipt] {
        &self.label_receipts
    }
    pub fn frontier_receipts(&self) -> &[X64TailClosedFrontierReceipt] {
        &self.frontier_receipts
    }
    pub fn closed_sources(&self) -> &[X64TailClosedSourceReceipt] {
        &self.closed_sources
    }
    pub fn abi_programs(&self) -> &[X64TailAbiEnvelopeProgramReceipt] {
        &self.abi_programs
    }
    pub fn abi_instructions(&self) -> &[X64TailAbiEnvelopeInstructionReceipt] {
        &self.abi_instructions
    }
    pub fn relocation_receipts(&self) -> &[X64TailEnvelopedRelocationReceipt] {
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
    pub const fn totals(&self) -> X64TailEnvelopedImageTotals {
        self.totals
    }
    pub const fn image_hash(&self) -> SemanticHash {
        self.image_hash
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedX64TailEnvelopedImage<'image> {
    image: &'image X64TailEnvelopedImage,
    decoded: X64TailDecodedEnvelopedImage,
}

impl<'image> VerifiedX64TailEnvelopedImage<'image> {
    pub const fn image(&self) -> &'image X64TailEnvelopedImage {
        self.image
    }
    pub const fn decoded(&self) -> &X64TailDecodedEnvelopedImage {
        &self.decoded
    }
}

#[derive(Debug)]
pub enum X64TailEnvelopedImageError {
    Decode(X64TailEnvelopedImageDecodeError),
    InvalidPredecessor {
        field: &'static str,
    },
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

impl fmt::Display for X64TailEnvelopedImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(formatter, "enveloped image decode failed: {error}"),
            Self::InvalidPredecessor { field } => {
                write!(formatter, "enveloped image has invalid predecessor {field}")
            }
            Self::InvalidField { field } => {
                write!(formatter, "enveloped image has invalid {field}")
            }
            Self::MissingTarget { field } => {
                write!(formatter, "enveloped image is missing {field}")
            }
            Self::LimitExceeded { field, limit, actual } => {
                write!(formatter, "enveloped image {field} uses {actual}; limit is {limit}")
            }
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "enveloped image overflowed {field}")
            }
            Self::Rel32OutOfRange { patch, displacement } => write!(
                formatter,
                "enveloped image rel32 at {patch} has out-of-range displacement {displacement}"
            ),
            Self::EncodingLimit { actual } => write!(
                formatter,
                "enveloped image evidence uses {actual} bytes; limit is {X64_TAIL_ENVELOPED_IMAGE_MAX_EVIDENCE_BYTES}"
            ),
            Self::CodeHashMismatch => formatter.write_str("enveloped image code hash does not replay"),
            Self::ImageHashMismatch => formatter.write_str("enveloped image seal does not replay"),
            Self::ReceiptMismatch => formatter.write_str("enveloped image receipts differ from independent decode"),
            Self::ReplayMismatch => formatter.write_str("enveloped image differs from canonical regeneration"),
        }
    }
}

impl std::error::Error for X64TailEnvelopedImageError {}

impl From<X64TailEnvelopedImageDecodeError> for X64TailEnvelopedImageError {
    fn from(value: X64TailEnvelopedImageDecodeError) -> Self {
        Self::Decode(value)
    }
}

#[derive(Clone)]
struct Layout {
    prefix_bytes: u32,
    code_bytes: u32,
    entry_point: u32,
    source_spans: Vec<X64TailEnvelopedSourceReceipt>,
    labels: Vec<X64TailClosedLabelReceipt>,
    abi_programs: Vec<X64TailAbiEnvelopeProgramReceipt>,
    abi_instructions: Vec<X64TailAbiEnvelopeInstructionReceipt>,
    label_offsets: BTreeMap<X64LabelId, u32>,
    frontier_offsets: BTreeMap<u32, u32>,
}

pub fn emit_x64_tail_enveloped_image(
    target: &X64TargetArtifact,
    closed: &VerifiedX64TailClosedImage<'_>,
    abi: &VerifiedX64TailAbiEnvelopeCapsule<'_>,
) -> Result<X64TailEnvelopedImage, X64TailEnvelopedImageError> {
    verify_predecessors(target, closed, abi)?;
    construct_image(target, closed, abi)
}

pub fn verify_x64_tail_enveloped_image<'image>(
    image: &'image X64TailEnvelopedImage,
    target: &X64TargetArtifact,
    closed: &VerifiedX64TailClosedImage<'_>,
    abi: &VerifiedX64TailAbiEnvelopeCapsule<'_>,
) -> Result<VerifiedX64TailEnvelopedImage<'image>, X64TailEnvelopedImageError> {
    verify_predecessors(target, closed, abi)?;
    validate_envelope(image, target, closed, abi)?;
    if x64_tail_enveloped_image_code_hash(&image.code)? != image.code_hash {
        return Err(X64TailEnvelopedImageError::CodeHashMismatch);
    }
    if x64_tail_enveloped_image_hash(image)? != image.image_hash {
        return Err(X64TailEnvelopedImageError::ImageHashMismatch);
    }
    let decoded = decode_x64_tail_enveloped_image(&image.code, target, closed, abi)?;
    if image.entry_successor != decoded.entry_successor
        || image.entry_point != decoded.entry_point
        || image.source_spans != decoded.source_spans
        || image.closed_programs != decoded.closed_programs
        || image.label_receipts != decoded.labels
        || image.frontier_receipts != decoded.frontiers
        || image.closed_sources != decoded.closed_sources
        || image.abi_programs != decoded.abi_programs
        || image.abi_instructions != decoded.abi_instructions
        || image.relocation_receipts != decoded.relocations
        || image.cfg_edges != decoded.cfg_edges
        || image.code_hash != decoded.code_hash
        || image.totals != decoded.totals
    {
        return Err(X64TailEnvelopedImageError::ReceiptMismatch);
    }
    let replayed = construct_image(target, closed, abi)?;
    if replayed != *image {
        return Err(X64TailEnvelopedImageError::ReplayMismatch);
    }
    Ok(VerifiedX64TailEnvelopedImage { image, decoded })
}

fn verify_predecessors(
    target: &X64TargetArtifact,
    closed: &VerifiedX64TailClosedImage<'_>,
    abi: &VerifiedX64TailAbiEnvelopeCapsule<'_>,
) -> Result<(), X64TailEnvelopedImageError> {
    verify_x64_target_r1_s7a(target).map_err(|_| {
        X64TailEnvelopedImageError::InvalidPredecessor {
            field: "verified x86-64 target",
        }
    })?;
    if closed.image().source_target_semantic_hash() != target.semantic_hash
        || abi.capsule().source_target_semantic_hash() != target.semantic_hash
        || abi.capsule().source_closed_image_hash() != closed.image().image_hash()
        || abi.capsule().entry_successor() != closed.image().entry_successor()
    {
        return Err(X64TailEnvelopedImageError::InvalidPredecessor {
            field: "target/closed-image/ABI identity chain",
        });
    }
    Ok(())
}

fn construct_image(
    target: &X64TargetArtifact,
    closed: &VerifiedX64TailClosedImage<'_>,
    abi: &VerifiedX64TailAbiEnvelopeCapsule<'_>,
) -> Result<X64TailEnvelopedImage, X64TailEnvelopedImageError> {
    let layout = derive_layout(closed, abi)?;
    let capacity = usize::try_from(layout.code_bytes).map_err(|_| {
        X64TailEnvelopedImageError::ArithmeticOverflow {
            field: "code capacity",
        }
    })?;
    let mut code = Vec::new();
    code.try_reserve_exact(capacity)
        .map_err(|_| X64TailEnvelopedImageError::EncodingLimit { actual: capacity })?;
    let prefix = usize::try_from(layout.prefix_bytes).map_err(|_| {
        X64TailEnvelopedImageError::ArithmeticOverflow {
            field: "closed prefix",
        }
    })?;
    code.extend_from_slice(&closed.image().code()[..prefix]);
    let anchor = usize::try_from(abi.capsule().anchor().offset).map_err(|_| {
        X64TailEnvelopedImageError::ArithmeticOverflow {
            field: "ABI anchor",
        }
    })?;
    code.extend_from_slice(&abi.capsule().code()[..anchor]);
    if code.len() != capacity {
        return Err(X64TailEnvelopedImageError::InvalidField {
            field: "gap-free code coverage",
        });
    }

    let mut patched_bytes = BTreeSet::new();
    let mut relocations = Vec::new();
    for source in &closed.decoded().relocations {
        let target_offset = control_offset(&layout, source.target)?;
        let displacement = patch_rel32(
            &mut code,
            &mut patched_bytes,
            source.patch_offset,
            target_offset,
        )?;
        relocations.push(X64TailEnvelopedRelocationReceipt {
            origin: X64TailEnvelopedRelocationOrigin::ClosedImage {
                source_kind: source.source_kind,
                program_kind: source.program_kind,
                program_ordinal: source.program_ordinal,
                atom_ordinal: source.atom_ordinal,
            },
            patch_offset: source.patch_offset,
            target: source.target,
            target_offset,
            displacement,
        });
    }
    let source_entry = abi.capsule().relocation();
    let entry_patch = layout
        .prefix_bytes
        .checked_add(source_entry.patch_offset)
        .ok_or(X64TailEnvelopedImageError::ArithmeticOverflow {
            field: "entry patch",
        })?;
    let entry_target = control_offset(&layout, source_entry.target)?;
    let entry_displacement = patch_rel32(&mut code, &mut patched_bytes, entry_patch, entry_target)?;
    relocations.push(X64TailEnvelopedRelocationReceipt {
        origin: X64TailEnvelopedRelocationOrigin::EntryAdapter {
            instruction_ordinal: source_entry.instruction_ordinal,
        },
        patch_offset: entry_patch,
        target: source_entry.target,
        target_offset: entry_target,
        displacement: entry_displacement,
    });
    relocations.sort_by_key(|relocation| relocation.patch_offset);
    ensure_limit(
        "relocations",
        X64_TAIL_ENVELOPED_IMAGE_MAX_RELOCATIONS,
        relocations.len(),
    )?;
    let cfg_edges = derive_cfg_edges(closed, &layout, entry_patch)?;
    let totals = totals(closed, abi, &layout, relocations.len(), cfg_edges.len())?;
    let code_hash = x64_tail_enveloped_image_code_hash(&code)?;
    let mut image = X64TailEnvelopedImage {
        schema_version: X64_TAIL_ENVELOPED_IMAGE_SCHEMA_VERSION,
        policy_version: X64_TAIL_ENVELOPED_IMAGE_POLICY_VERSION,
        decoder_policy_version:
            super::x64_tail_enveloped_image_decode::X64_TAIL_ENVELOPED_IMAGE_DECODER_POLICY_VERSION,
        source_target_semantic_hash: target.semantic_hash,
        source_closed_image_hash: closed.image().image_hash(),
        source_abi_capsule_hash: abi.capsule().capsule_hash(),
        entry_successor: closed.image().entry_successor(),
        entry_point: layout.entry_point,
        source_spans: layout.source_spans,
        closed_programs: closed.decoded().programs.clone(),
        label_receipts: layout.labels,
        frontier_receipts: closed.decoded().frontiers.clone(),
        closed_sources: closed.decoded().sources.clone(),
        abi_programs: layout.abi_programs,
        abi_instructions: layout.abi_instructions,
        relocation_receipts: relocations,
        cfg_edges,
        code,
        code_hash,
        totals,
        image_hash: SemanticHash::ZERO,
    };
    let decoded = decode_x64_tail_enveloped_image(&image.code, target, closed, abi)?;
    image.totals.decode_work = decoded.totals.decode_work;
    image.totals.projection_work = decoded.totals.projection_work;
    image.image_hash = x64_tail_enveloped_image_hash(&image)?;
    Ok(image)
}

fn derive_layout(
    closed: &VerifiedX64TailClosedImage<'_>,
    abi: &VerifiedX64TailAbiEnvelopeCapsule<'_>,
) -> Result<Layout, X64TailEnvelopedImageError> {
    let terminals = &closed.decoded().terminals;
    if terminals.len() != 3 {
        return Err(X64TailEnvelopedImageError::InvalidField {
            field: "three closed terminals",
        });
    }
    let terminal = |kind| {
        let mut values = terminals.iter().filter(|terminal| terminal.kind == kind);
        let value = values
            .next()
            .copied()
            .ok_or(X64TailEnvelopedImageError::MissingTarget {
                field: "closed terminal",
            })?;
        if values.next().is_some() {
            return Err(X64TailEnvelopedImageError::InvalidField {
                field: "unique closed terminal",
            });
        }
        Ok(value)
    };
    let entry_terminal = terminal(X64TailClosedTerminalKind::EntryAdapter)?;
    let return_terminal = terminal(X64TailClosedTerminalKind::ReturnEpilogue)?;
    let bounds_terminal = terminal(X64TailClosedTerminalKind::BoundsEpilogue)?;
    let prefix_bytes = entry_terminal.offset;
    if return_terminal.offset
        != prefix_bytes
            .checked_add(1)
            .ok_or(X64TailEnvelopedImageError::ArithmeticOverflow {
                field: "terminal layout",
            })?
        || bounds_terminal.offset
            != prefix_bytes.checked_add(2).ok_or(
                X64TailEnvelopedImageError::ArithmeticOverflow {
                    field: "terminal layout",
                },
            )?
        || closed.image().code().len() as u64 != u64::from(prefix_bytes) + 3
    {
        return Err(X64TailEnvelopedImageError::InvalidField {
            field: "terminal suffix layout",
        });
    }

    let source_programs = abi.decoded().programs.as_slice();
    if source_programs.len() != 3 {
        return Err(X64TailEnvelopedImageError::InvalidField {
            field: "three ABI programs",
        });
    }
    let program = |kind| {
        let mut values = source_programs
            .iter()
            .filter(|program| program.kind == kind);
        let value = values
            .next()
            .copied()
            .ok_or(X64TailEnvelopedImageError::MissingTarget {
                field: "ABI program",
            })?;
        if values.next().is_some() {
            return Err(X64TailEnvelopedImageError::InvalidField {
                field: "unique ABI program",
            });
        }
        Ok(value)
    };
    let source_entry = program(X64TailAbiEnvelopeProgramKind::EntryAdapter)?;
    let source_return = program(X64TailAbiEnvelopeProgramKind::ReturnEpilogue)?;
    let source_bounds = program(X64TailAbiEnvelopeProgramKind::BoundsEpilogue)?;
    let anchor = abi.capsule().anchor();
    if source_entry.start != 0
        || source_entry.end != source_return.start
        || source_return.end != source_bounds.start
        || source_bounds.end != anchor.offset
        || u64::from(anchor.offset) + 1 != abi.capsule().code().len() as u64
        || source_entry.label != entry_terminal.label
        || source_return.label != return_terminal.label
        || source_bounds.label != bounds_terminal.label
        || anchor.target != closed.image().entry_successor()
    {
        return Err(X64TailEnvelopedImageError::InvalidField {
            field: "canonical ABI source layout",
        });
    }
    let code_bytes = prefix_bytes.checked_add(anchor.offset).ok_or(
        X64TailEnvelopedImageError::ArithmeticOverflow {
            field: "enveloped code bytes",
        },
    )?;
    if u64::from(code_bytes) > X64_TAIL_ENVELOPED_IMAGE_MAX_CODE_BYTES {
        return Err(X64TailEnvelopedImageError::LimitExceeded {
            field: "code bytes",
            limit: X64_TAIL_ENVELOPED_IMAGE_MAX_CODE_BYTES,
            actual: u64::from(code_bytes),
        });
    }
    let rebase = |offset: u32| {
        prefix_bytes
            .checked_add(offset)
            .ok_or(X64TailEnvelopedImageError::ArithmeticOverflow {
                field: "ABI rebase",
            })
    };
    let mut abi_programs = Vec::new();
    for source in [source_entry, source_return, source_bounds] {
        abi_programs.push(X64TailAbiEnvelopeProgramReceipt {
            kind: source.kind,
            label: source.label,
            start: rebase(source.start)?,
            end: rebase(source.end)?,
            instructions: source.instructions,
        });
    }
    let mut abi_instructions = Vec::new();
    for source in &abi.decoded().instructions {
        abi_instructions.push(X64TailAbiEnvelopeInstructionReceipt {
            program: source.program,
            ordinal: source.ordinal,
            start: rebase(source.start)?,
            end: rebase(source.end)?,
            effect: source.effect,
        });
    }
    let source_spans = vec![
        X64TailEnvelopedSourceReceipt {
            kind: X64TailEnvelopedSourceKind::ClosedPrefix,
            source_start: 0,
            source_end: prefix_bytes,
            image_start: 0,
            image_end: prefix_bytes,
        },
        X64TailEnvelopedSourceReceipt {
            kind: X64TailEnvelopedSourceKind::EntryAdapter,
            source_start: source_entry.start,
            source_end: source_entry.end,
            image_start: rebase(source_entry.start)?,
            image_end: rebase(source_entry.end)?,
        },
        X64TailEnvelopedSourceReceipt {
            kind: X64TailEnvelopedSourceKind::ReturnEpilogue,
            source_start: source_return.start,
            source_end: source_return.end,
            image_start: rebase(source_return.start)?,
            image_end: rebase(source_return.end)?,
        },
        X64TailEnvelopedSourceReceipt {
            kind: X64TailEnvelopedSourceKind::BoundsEpilogue,
            source_start: source_bounds.start,
            source_end: source_bounds.end,
            image_start: rebase(source_bounds.start)?,
            image_end: rebase(source_bounds.end)?,
        },
    ];
    let mut labels = closed.decoded().labels.clone();
    let replacements = BTreeMap::from([
        (entry_terminal.label, rebase(source_entry.start)?),
        (return_terminal.label, rebase(source_return.start)?),
        (bounds_terminal.label, rebase(source_bounds.start)?),
    ]);
    for label in &mut labels {
        if let Some(offset) = replacements.get(&label.label) {
            label.offset = *offset;
        }
    }
    let label_offsets = labels
        .iter()
        .map(|label| (label.label, label.offset))
        .collect::<BTreeMap<_, _>>();
    if label_offsets.len() != labels.len() {
        return Err(X64TailEnvelopedImageError::InvalidField {
            field: "unique labels",
        });
    }
    let frontier_offsets = closed
        .decoded()
        .frontiers
        .iter()
        .map(|frontier| (frontier.ordinal, frontier.offset))
        .collect::<BTreeMap<_, _>>();
    if frontier_offsets.len() != closed.decoded().frontiers.len()
        || closed
            .decoded()
            .programs
            .iter()
            .any(|program| program.end > prefix_bytes)
        || closed
            .decoded()
            .sources
            .iter()
            .any(|source| source.image_end > prefix_bytes)
    {
        return Err(X64TailEnvelopedImageError::InvalidField {
            field: "closed prefix ownership",
        });
    }
    Ok(Layout {
        prefix_bytes,
        code_bytes,
        entry_point: rebase(source_entry.start)?,
        source_spans,
        labels,
        abi_programs,
        abi_instructions,
        label_offsets,
        frontier_offsets,
    })
}

fn patch_rel32(
    code: &mut [u8],
    patched: &mut BTreeSet<u32>,
    patch: u32,
    target: u32,
) -> Result<i32, X64TailEnvelopedImageError> {
    let end = patch
        .checked_add(4)
        .ok_or(X64TailEnvelopedImageError::ArithmeticOverflow {
            field: "rel32 patch end",
        })?;
    if u64::from(end) > code.len() as u64 {
        return Err(X64TailEnvelopedImageError::InvalidField {
            field: "rel32 patch range",
        });
    }
    for byte in patch..end {
        if !patched.insert(byte) {
            return Err(X64TailEnvelopedImageError::InvalidField {
                field: "overlapping rel32 patch",
            });
        }
    }
    let next = i64::from(end);
    let displacement = i64::from(target).checked_sub(next).ok_or(
        X64TailEnvelopedImageError::ArithmeticOverflow {
            field: "rel32 displacement",
        },
    )?;
    let displacement =
        i32::try_from(displacement).map_err(|_| X64TailEnvelopedImageError::Rel32OutOfRange {
            patch,
            displacement,
        })?;
    let start =
        usize::try_from(patch).map_err(|_| X64TailEnvelopedImageError::ArithmeticOverflow {
            field: "rel32 patch index",
        })?;
    code[start..start + 4].copy_from_slice(&displacement.to_le_bytes());
    Ok(displacement)
}

fn control_offset(
    layout: &Layout,
    target: X64TailBodyControlTarget,
) -> Result<u32, X64TailEnvelopedImageError> {
    match target {
        X64TailBodyControlTarget::Label(label) => layout.label_offsets.get(&label),
        X64TailBodyControlTarget::Frontier(ordinal) => layout.frontier_offsets.get(&ordinal),
    }
    .copied()
    .ok_or(X64TailEnvelopedImageError::MissingTarget {
        field: "control target",
    })
}

fn derive_cfg_edges(
    closed: &VerifiedX64TailClosedImage<'_>,
    layout: &Layout,
    entry_patch: u32,
) -> Result<Vec<X64TailClosedCfgEdge>, X64TailEnvelopedImageError> {
    let mut entry_edges = 0u32;
    let mut edges = Vec::new();
    for source in &closed.decoded().cfg_edges {
        let source_offset = if source.kind == X64TailClosedCfgEdgeKind::Entry {
            entry_edges = entry_edges.checked_add(1).ok_or(
                X64TailEnvelopedImageError::ArithmeticOverflow {
                    field: "entry CFG count",
                },
            )?;
            entry_patch
        } else {
            source.source_offset
        };
        edges.push(X64TailClosedCfgEdge {
            kind: source.kind,
            source_offset,
            destination: rebase_destination(source.destination, layout)?,
        });
    }
    if entry_edges != 1 {
        return Err(X64TailEnvelopedImageError::InvalidField {
            field: "unique entry CFG edge",
        });
    }
    edges.sort_by_key(|edge| {
        (
            edge.source_offset,
            cfg_tag(edge.kind),
            cfg_destination_key(edge.destination),
        )
    });
    edges.dedup();
    if edges.len() != closed.decoded().cfg_edges.len() {
        return Err(X64TailEnvelopedImageError::InvalidField {
            field: "CFG edge conservation",
        });
    }
    Ok(edges)
}

fn rebase_destination(
    destination: X64TailClosedCfgDestination,
    layout: &Layout,
) -> Result<X64TailClosedCfgDestination, X64TailEnvelopedImageError> {
    Ok(match destination {
        X64TailClosedCfgDestination::Label { label, .. } => X64TailClosedCfgDestination::Label {
            label,
            offset: *layout
                .label_offsets
                .get(&label)
                .ok_or(X64TailEnvelopedImageError::MissingTarget { field: "CFG label" })?,
        },
        X64TailClosedCfgDestination::Frontier { ordinal, .. } => {
            X64TailClosedCfgDestination::Frontier {
                ordinal,
                offset: *layout.frontier_offsets.get(&ordinal).ok_or(
                    X64TailEnvelopedImageError::MissingTarget {
                        field: "CFG frontier",
                    },
                )?,
            }
        }
        X64TailClosedCfgDestination::InstructionBoundary {
            program_kind,
            program_ordinal,
            offset,
        } => X64TailClosedCfgDestination::InstructionBoundary {
            program_kind,
            program_ordinal,
            offset,
        },
    })
}

fn totals(
    closed: &VerifiedX64TailClosedImage<'_>,
    abi: &VerifiedX64TailAbiEnvelopeCapsule<'_>,
    layout: &Layout,
    relocations: usize,
    cfg_edges: usize,
) -> Result<X64TailEnvelopedImageTotals, X64TailEnvelopedImageError> {
    let entry = layout.abi_programs[0];
    let returned = layout.abi_programs[1];
    let bounds = layout.abi_programs[2];
    let compose_work = work(
        layout.code_bytes,
        relocations,
        layout.source_spans.len(),
        closed.decoded().sources.len(),
        layout.abi_instructions.len(),
    )?;
    let projection_work = u64::try_from(closed.image().code().len())
        .ok()
        .and_then(|value| value.checked_add(abi.capsule().code().len() as u64))
        .and_then(|value| value.checked_add((relocations as u64).checked_mul(4)?))
        .ok_or(X64TailEnvelopedImageError::ArithmeticOverflow {
            field: "projection work",
        })?;
    if projection_work > X64_TAIL_ENVELOPED_IMAGE_MAX_WORK {
        return Err(X64TailEnvelopedImageError::LimitExceeded {
            field: "projection work",
            limit: X64_TAIL_ENVELOPED_IMAGE_MAX_WORK,
            actual: projection_work,
        });
    }
    Ok(X64TailEnvelopedImageTotals {
        closed_programs: usize_to_u32(closed.decoded().programs.len(), "closed programs")?,
        abi_programs: usize_to_u32(layout.abi_programs.len(), "ABI programs")?,
        labels: usize_to_u32(layout.labels.len(), "labels")?,
        frontiers: usize_to_u32(closed.decoded().frontiers.len(), "frontiers")?,
        closed_source_ranges: usize_to_u32(closed.decoded().sources.len(), "closed source ranges")?,
        composition_source_spans: usize_to_u32(layout.source_spans.len(), "source spans")?,
        abi_instructions: usize_to_u32(layout.abi_instructions.len(), "ABI instructions")?,
        abi_effects: usize_to_u32(layout.abi_instructions.len(), "ABI effects")?,
        relocations: usize_to_u32(relocations, "relocations")?,
        cfg_edges: usize_to_u32(cfg_edges, "CFG edges")?,
        closed_prefix_bytes: layout.prefix_bytes,
        entry_bytes: entry.end - entry.start,
        return_bytes: returned.end - returned.start,
        bounds_bytes: bounds.end - bounds.start,
        code_bytes: layout.code_bytes,
        compose_work,
        decode_work: compose_work,
        projection_work,
    })
}

fn work(
    code_bytes: u32,
    relocations: usize,
    spans: usize,
    closed_sources: usize,
    abi_instructions: usize,
) -> Result<u64, X64TailEnvelopedImageError> {
    let value = u64::from(code_bytes)
        .checked_add((relocations as u64).checked_mul(4).ok_or(
            X64TailEnvelopedImageError::ArithmeticOverflow {
                field: "relocation work",
            },
        )?)
        .and_then(|value| value.checked_add(spans as u64))
        .and_then(|value| value.checked_add(closed_sources as u64))
        .and_then(|value| value.checked_add(abi_instructions as u64))
        .ok_or(X64TailEnvelopedImageError::ArithmeticOverflow {
            field: "compose work",
        })?;
    if value > X64_TAIL_ENVELOPED_IMAGE_MAX_WORK {
        return Err(X64TailEnvelopedImageError::LimitExceeded {
            field: "compose work",
            limit: X64_TAIL_ENVELOPED_IMAGE_MAX_WORK,
            actual: value,
        });
    }
    Ok(value)
}

fn validate_envelope(
    image: &X64TailEnvelopedImage,
    target: &X64TargetArtifact,
    closed: &VerifiedX64TailClosedImage<'_>,
    abi: &VerifiedX64TailAbiEnvelopeCapsule<'_>,
) -> Result<(), X64TailEnvelopedImageError> {
    if image.schema_version != X64_TAIL_ENVELOPED_IMAGE_SCHEMA_VERSION
        || image.policy_version != X64_TAIL_ENVELOPED_IMAGE_POLICY_VERSION
        || image.decoder_policy_version
            != super::x64_tail_enveloped_image_decode::X64_TAIL_ENVELOPED_IMAGE_DECODER_POLICY_VERSION
    {
        return Err(X64TailEnvelopedImageError::InvalidField {
            field: "schema or policy version",
        });
    }
    if image.source_target_semantic_hash != target.semantic_hash
        || image.source_closed_image_hash != closed.image().image_hash()
        || image.source_abi_capsule_hash != abi.capsule().capsule_hash()
    {
        return Err(X64TailEnvelopedImageError::InvalidPredecessor {
            field: "sealed identity",
        });
    }
    if image.totals.code_bytes as u64 != image.code.len() as u64 {
        return Err(X64TailEnvelopedImageError::InvalidField {
            field: "code total",
        });
    }
    Ok(())
}

pub fn x64_tail_enveloped_image_code_hash(
    code: &[u8],
) -> Result<SemanticHash, X64TailEnvelopedImageError> {
    if code.len() as u64 > X64_TAIL_ENVELOPED_IMAGE_MAX_CODE_BYTES {
        return Err(X64TailEnvelopedImageError::LimitExceeded {
            field: "code bytes",
            limit: X64_TAIL_ENVELOPED_IMAGE_MAX_CODE_BYTES,
            actual: code.len() as u64,
        });
    }
    let mut bytes = Vec::with_capacity(CODE_DOMAIN.len() + 8 + code.len());
    bytes.extend_from_slice(CODE_DOMAIN);
    bytes.extend_from_slice(&(code.len() as u64).to_le_bytes());
    bytes.extend_from_slice(code);
    Ok(SemanticHash(sha256(&bytes)))
}

pub fn x64_tail_enveloped_image_hash(
    image: &X64TailEnvelopedImage,
) -> Result<SemanticHash, X64TailEnvelopedImageError> {
    let mut encoder = EvidenceEncoder::new();
    encoder.bytes(IMAGE_DOMAIN)?;
    encoder.version(image.schema_version)?;
    encoder.version(image.policy_version)?;
    encoder.version(image.decoder_policy_version)?;
    encoder.hash(image.source_target_semantic_hash)?;
    encoder.hash(image.source_closed_image_hash)?;
    encoder.hash(image.source_abi_capsule_hash)?;
    encoder.control(image.entry_successor)?;
    encoder.u32(image.entry_point)?;
    encoder.vec_len(image.source_spans.len())?;
    for source in &image.source_spans {
        encoder.u8(source_tag(source.kind))?;
        encoder.u32(source.source_start)?;
        encoder.u32(source.source_end)?;
        encoder.u32(source.image_start)?;
        encoder.u32(source.image_end)?;
    }
    encoder.vec_len(image.closed_programs.len())?;
    for program in &image.closed_programs {
        encoder.u8(closed_program_tag(program.kind))?;
        encoder.u32(program.ordinal)?;
        encoder.u32(program.start)?;
        encoder.u32(program.end)?;
        encoder.u32(program.atoms)?;
    }
    encoder.vec_len(image.label_receipts.len())?;
    for label in &image.label_receipts {
        encoder.u32(label.label.0)?;
        encoder.u32(label.offset)?;
    }
    encoder.vec_len(image.frontier_receipts.len())?;
    for frontier in &image.frontier_receipts {
        encoder.u32(frontier.ordinal)?;
        encoder.u32(frontier.offset)?;
        encoder.u32(frontier.end)?;
        encoder.u32(frontier.owner_ordinal)?;
    }
    encoder.vec_len(image.closed_sources.len())?;
    for source in &image.closed_sources {
        encoder.u8(closed_source_tag(source.source_kind))?;
        encoder.u8(closed_program_tag(source.program_kind))?;
        encoder.u32(source.program_ordinal)?;
        encoder.u32(source.atom_ordinal)?;
        encoder.u32(source.source_start)?;
        encoder.u32(source.source_end)?;
        encoder.u32(source.image_start)?;
        encoder.u32(source.image_end)?;
    }
    encoder.vec_len(image.abi_programs.len())?;
    for program in &image.abi_programs {
        encoder.u8(abi_program_tag(program.kind))?;
        encoder.u32(program.label.0)?;
        encoder.u32(program.start)?;
        encoder.u32(program.end)?;
        encoder.u32(program.instructions)?;
    }
    encoder.vec_len(image.abi_instructions.len())?;
    for instruction in &image.abi_instructions {
        encoder.u8(abi_program_tag(instruction.program))?;
        encoder.u32(instruction.ordinal)?;
        encoder.u32(instruction.start)?;
        encoder.u32(instruction.end)?;
        encode_effect(&mut encoder, instruction.effect)?;
    }
    encoder.vec_len(image.relocation_receipts.len())?;
    for relocation in &image.relocation_receipts {
        encode_relocation_origin(&mut encoder, relocation.origin)?;
        encoder.u32(relocation.patch_offset)?;
        encoder.control(relocation.target)?;
        encoder.u32(relocation.target_offset)?;
        encoder.i32(relocation.displacement)?;
    }
    encoder.vec_len(image.cfg_edges.len())?;
    for edge in &image.cfg_edges {
        encoder.u8(cfg_tag(edge.kind))?;
        encoder.u32(edge.source_offset)?;
        encode_cfg_destination(&mut encoder, edge.destination)?;
    }
    encoder.hash(image.code_hash)?;
    encode_totals(&mut encoder, image.totals)?;
    encoder.bytes(&image.code)?;
    Ok(SemanticHash(sha256(&encoder.finish())))
}

fn encode_relocation_origin(
    encoder: &mut EvidenceEncoder,
    origin: X64TailEnvelopedRelocationOrigin,
) -> Result<(), X64TailEnvelopedImageError> {
    match origin {
        X64TailEnvelopedRelocationOrigin::ClosedImage {
            source_kind,
            program_kind,
            program_ordinal,
            atom_ordinal,
        } => {
            encoder.u8(0)?;
            encoder.u8(closed_source_tag(source_kind))?;
            encoder.u8(closed_program_tag(program_kind))?;
            encoder.u32(program_ordinal)?;
            encoder.u32(atom_ordinal)
        }
        X64TailEnvelopedRelocationOrigin::EntryAdapter {
            instruction_ordinal,
        } => {
            encoder.u8(1)?;
            encoder.u32(instruction_ordinal)
        }
    }
}

fn encode_effect(
    encoder: &mut EvidenceEncoder,
    effect: X64TailAbiEnvelopeEffect,
) -> Result<(), X64TailEnvelopedImageError> {
    match effect {
        X64TailAbiEnvelopeEffect::PushCallerRbp => encoder.u8(0),
        X64TailAbiEnvelopeEffect::EstablishFramePointer => encoder.u8(1),
        X64TailAbiEnvelopeEffect::AllocateFrame { bytes } => {
            encoder.u8(2)?;
            encoder.u32(bytes)
        }
        X64TailAbiEnvelopeEffect::SaveCallerMxcsr { offset } => {
            encoder.u8(3)?;
            encoder.u32(offset)
        }
        X64TailAbiEnvelopeEffect::StoreCanonicalMxcsr { offset, value } => {
            encoder.u8(4)?;
            encoder.u32(offset)?;
            encoder.u32(value)
        }
        X64TailAbiEnvelopeEffect::LoadCanonicalMxcsr { offset } => {
            encoder.u8(5)?;
            encoder.u32(offset)
        }
        X64TailAbiEnvelopeEffect::SaveOutputPointer { offset, register } => {
            encoder.u8(6)?;
            encoder.u32(offset)?;
            encoder.u8(register_tag(register))
        }
        X64TailAbiEnvelopeEffect::ZeroReservedWord { offset } => {
            encoder.u8(7)?;
            encoder.u32(offset)
        }
        X64TailAbiEnvelopeEffect::ZeroUnitHome { parameter, offset } => {
            encoder.u8(8)?;
            encoder.u32(parameter)?;
            encoder.u32(offset)
        }
        X64TailAbiEnvelopeEffect::StoreInputLane {
            parameter,
            word,
            register,
            offset,
            ty,
        } => {
            encoder.u8(9)?;
            encoder.u32(parameter)?;
            encoder.u8(word)?;
            encoder.u8(register_tag(register))?;
            encoder.u32(offset)?;
            encoder.u8(type_tag(ty))
        }
        X64TailAbiEnvelopeEffect::JumpEntrySuccessor { target } => {
            encoder.u8(10)?;
            encoder.control(target)
        }
        X64TailAbiEnvelopeEffect::LoadOutputPointer { offset } => {
            encoder.u8(11)?;
            encoder.u32(offset)
        }
        X64TailAbiEnvelopeEffect::StoreResultWord { word } => {
            encoder.u8(12)?;
            encoder.u8(word)
        }
        X64TailAbiEnvelopeEffect::ZeroResultRegister => encoder.u8(13),
        X64TailAbiEnvelopeEffect::StoreZeroResultWord { word } => {
            encoder.u8(14)?;
            encoder.u8(word)
        }
        X64TailAbiEnvelopeEffect::SetStatus { value } => {
            encoder.u8(15)?;
            encoder.u32(value)
        }
        X64TailAbiEnvelopeEffect::RestoreCallerMxcsr { offset } => {
            encoder.u8(16)?;
            encoder.u32(offset)
        }
        X64TailAbiEnvelopeEffect::ReleaseFrame { bytes } => {
            encoder.u8(17)?;
            encoder.u32(bytes)
        }
        X64TailAbiEnvelopeEffect::RestoreCallerRbp => encoder.u8(18),
        X64TailAbiEnvelopeEffect::Return => encoder.u8(19),
    }
}

fn encode_cfg_destination(
    encoder: &mut EvidenceEncoder,
    destination: X64TailClosedCfgDestination,
) -> Result<(), X64TailEnvelopedImageError> {
    match destination {
        X64TailClosedCfgDestination::Label { label, offset } => {
            encoder.u8(0)?;
            encoder.u32(label.0)?;
            encoder.u32(offset)
        }
        X64TailClosedCfgDestination::Frontier { ordinal, offset } => {
            encoder.u8(1)?;
            encoder.u32(ordinal)?;
            encoder.u32(offset)
        }
        X64TailClosedCfgDestination::InstructionBoundary {
            program_kind,
            program_ordinal,
            offset,
        } => {
            encoder.u8(2)?;
            encoder.u8(closed_program_tag(program_kind))?;
            encoder.u32(program_ordinal)?;
            encoder.u32(offset)
        }
    }
}

fn encode_totals(
    encoder: &mut EvidenceEncoder,
    totals: X64TailEnvelopedImageTotals,
) -> Result<(), X64TailEnvelopedImageError> {
    for value in [
        totals.closed_programs,
        totals.abi_programs,
        totals.labels,
        totals.frontiers,
        totals.closed_source_ranges,
        totals.composition_source_spans,
        totals.abi_instructions,
        totals.abi_effects,
        totals.relocations,
        totals.cfg_edges,
        totals.closed_prefix_bytes,
        totals.entry_bytes,
        totals.return_bytes,
        totals.bounds_bytes,
        totals.code_bytes,
    ] {
        encoder.u32(value)?;
    }
    encoder.u64(totals.compose_work)?;
    encoder.u64(totals.decode_work)?;
    encoder.u64(totals.projection_work)
}

fn source_tag(kind: X64TailEnvelopedSourceKind) -> u8 {
    match kind {
        X64TailEnvelopedSourceKind::ClosedPrefix => 0,
        X64TailEnvelopedSourceKind::EntryAdapter => 1,
        X64TailEnvelopedSourceKind::ReturnEpilogue => 2,
        X64TailEnvelopedSourceKind::BoundsEpilogue => 3,
    }
}

fn closed_program_tag(kind: X64TailClosedProgramKind) -> u8 {
    match kind {
        X64TailClosedProgramKind::Site => 0,
        X64TailClosedProgramKind::Frontier => 1,
    }
}

fn closed_source_tag(kind: X64TailClosedSourceKind) -> u8 {
    match kind {
        X64TailClosedSourceKind::Body => 0,
        X64TailClosedSourceKind::Transition => 1,
    }
}

fn abi_program_tag(kind: X64TailAbiEnvelopeProgramKind) -> u8 {
    match kind {
        X64TailAbiEnvelopeProgramKind::EntryAdapter => 0,
        X64TailAbiEnvelopeProgramKind::ReturnEpilogue => 1,
        X64TailAbiEnvelopeProgramKind::BoundsEpilogue => 2,
    }
}

fn register_tag(register: X64AbiRegister) -> u8 {
    match register {
        X64AbiRegister::Rdi => 0,
        X64AbiRegister::Rsi => 1,
        X64AbiRegister::Rdx => 2,
        X64AbiRegister::Rcx => 3,
        X64AbiRegister::R8 => 4,
        X64AbiRegister::R9 => 5,
    }
}

fn type_tag(ty: MachineType) -> u8 {
    match ty {
        MachineType::Unit => 0,
        MachineType::Bool => 1,
        MachineType::I64 => 2,
        MachineType::F64 => 3,
        MachineType::F64Array => 4,
    }
}

fn cfg_tag(kind: X64TailClosedCfgEdgeKind) -> u8 {
    match kind {
        X64TailClosedCfgEdgeKind::Entry => 0,
        X64TailClosedCfgEdgeKind::FrontierFallthrough => 1,
        X64TailClosedCfgEdgeKind::ConditionalFallthrough => 2,
        X64TailClosedCfgEdgeKind::Rel32 => 3,
    }
}

fn cfg_destination_key(destination: X64TailClosedCfgDestination) -> (u8, u8, u32, u32) {
    match destination {
        X64TailClosedCfgDestination::Label { label, offset } => (0, 0, label.0, offset),
        X64TailClosedCfgDestination::Frontier { ordinal, offset } => (1, 0, ordinal, offset),
        X64TailClosedCfgDestination::InstructionBoundary {
            program_kind,
            program_ordinal,
            offset,
        } => (2, closed_program_tag(program_kind), program_ordinal, offset),
    }
}

fn usize_to_u32(value: usize, field: &'static str) -> Result<u32, X64TailEnvelopedImageError> {
    u32::try_from(value).map_err(|_| X64TailEnvelopedImageError::ArithmeticOverflow { field })
}

fn ensure_limit(
    field: &'static str,
    limit: u32,
    actual: usize,
) -> Result<(), X64TailEnvelopedImageError> {
    if actual as u64 > u64::from(limit) {
        Err(X64TailEnvelopedImageError::LimitExceeded {
            field,
            limit: u64::from(limit),
            actual: actual as u64,
        })
    } else {
        Ok(())
    }
}

struct EvidenceEncoder {
    bytes: Vec<u8>,
}

impl EvidenceEncoder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }
    fn reserve(&mut self, additional: usize) -> Result<(), X64TailEnvelopedImageError> {
        let next = self.bytes.len().checked_add(additional).ok_or(
            X64TailEnvelopedImageError::ArithmeticOverflow {
                field: "evidence bytes",
            },
        )?;
        if next > X64_TAIL_ENVELOPED_IMAGE_MAX_EVIDENCE_BYTES {
            return Err(X64TailEnvelopedImageError::EncodingLimit { actual: next });
        }
        self.bytes
            .try_reserve(additional)
            .map_err(|_| X64TailEnvelopedImageError::EncodingLimit { actual: next })
    }
    fn bytes(&mut self, value: &[u8]) -> Result<(), X64TailEnvelopedImageError> {
        self.reserve(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }
    fn u8(&mut self, value: u8) -> Result<(), X64TailEnvelopedImageError> {
        self.bytes(&[value])
    }
    fn u16(&mut self, value: u16) -> Result<(), X64TailEnvelopedImageError> {
        self.bytes(&value.to_le_bytes())
    }
    fn u32(&mut self, value: u32) -> Result<(), X64TailEnvelopedImageError> {
        self.bytes(&value.to_le_bytes())
    }
    fn u64(&mut self, value: u64) -> Result<(), X64TailEnvelopedImageError> {
        self.bytes(&value.to_le_bytes())
    }
    fn i32(&mut self, value: i32) -> Result<(), X64TailEnvelopedImageError> {
        self.bytes(&value.to_le_bytes())
    }
    fn version(&mut self, value: (u16, u16, u16)) -> Result<(), X64TailEnvelopedImageError> {
        self.u16(value.0)?;
        self.u16(value.1)?;
        self.u16(value.2)
    }
    fn hash(&mut self, value: SemanticHash) -> Result<(), X64TailEnvelopedImageError> {
        self.bytes(&value.0)
    }
    fn control(
        &mut self,
        value: X64TailBodyControlTarget,
    ) -> Result<(), X64TailEnvelopedImageError> {
        match value {
            X64TailBodyControlTarget::Label(label) => {
                self.u8(0)?;
                self.u32(label.0)
            }
            X64TailBodyControlTarget::Frontier(ordinal) => {
                self.u8(1)?;
                self.u32(ordinal)
            }
        }
    }
    fn vec_len(&mut self, value: usize) -> Result<(), X64TailEnvelopedImageError> {
        self.u32(usize_to_u32(value, "evidence vector length")?)
    }
    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::corevm0_gate_a::CoreVmGateAWorkload::BranchMix;
    use crate::core::x64_native_lighthouse::X64NativeLighthousePackage;
    use crate::core::{
        emit_x64_tail_abi_envelope_capsule, emit_x64_tail_body_frontier_capsule,
        emit_x64_tail_body_frontier_realization, emit_x64_tail_candidate_capsule,
        emit_x64_tail_closed_image, emit_x64_tail_physical_allocation,
        emit_x64_tail_site_binding_proof, emit_x64_tail_state_plan,
        emit_x64_tail_template_realization, verify_x64_tail_abi_envelope_capsule,
        verify_x64_tail_closed_image, X64TailAbiEnvelopeCapsule, X64TailBodyFrontierCapsule,
        X64TailBodyFrontierRealization, X64TailCandidateCapsule, X64TailClosedImage,
        X64TailPhysicalAllocation, X64TailSiteBindingProof, X64TailStatePlan,
        X64TailTemplateRealization, X64_TARGET_ENCODER_POLICY_VERSION,
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
        X64TailClosedImage,
        X64TailAbiEnvelopeCapsule,
    );

    fn build() -> Build {
        let package =
            X64NativeLighthousePackage::build(BranchMix).expect("lighthouse package must build");
        let logical = emit_x64_tail_state_plan(package.target()).expect("logical plan must emit");
        let physical = emit_x64_tail_physical_allocation(package.target(), &logical)
            .expect("allocation must emit");
        let templates = emit_x64_tail_template_realization(package.target(), &logical, &physical)
            .expect("templates must emit");
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
        .expect("binding must emit");
        let realization = emit_x64_tail_body_frontier_realization(
            package.target(),
            &logical,
            &physical,
            &templates,
            &transition,
            &binding,
        )
        .expect("realization must emit");
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
        let closed = emit_x64_tail_closed_image(
            package.target(),
            &logical,
            &physical,
            &templates,
            &transition,
            &binding,
            &realization,
            &body,
        )
        .expect("closed image must emit");
        let verified_closed = verify_x64_tail_closed_image(
            &closed,
            &body,
            &realization,
            &binding,
            &transition,
            &templates,
            &physical,
            &logical,
            package.target(),
        )
        .expect("closed image must verify");
        let abi = emit_x64_tail_abi_envelope_capsule(package.target(), &verified_closed)
            .expect("ABI capsule must emit");
        (
            package,
            logical,
            physical,
            templates,
            transition,
            binding,
            realization,
            body,
            closed,
            abi,
        )
    }

    #[test]
    fn branch_mix_composes_one_fully_enveloped_non_executable_image() {
        let (
            package,
            logical,
            physical,
            templates,
            transition,
            binding,
            realization,
            body,
            closed,
            abi,
        ) = build();
        let verified_closed = verify_x64_tail_closed_image(
            &closed,
            &body,
            &realization,
            &binding,
            &transition,
            &templates,
            &physical,
            &logical,
            package.target(),
        )
        .expect("closed image must verify");
        let verified_abi =
            verify_x64_tail_abi_envelope_capsule(&abi, package.target(), &verified_closed)
                .expect("ABI capsule must verify");
        let original_target = package.target().program.code.clone();
        let original_target_hash = package.target().program.code_hash;
        let original_closed = closed.clone();
        let original_abi = abi.clone();
        let first =
            emit_x64_tail_enveloped_image(package.target(), &verified_closed, &verified_abi)
                .expect("enveloped image must emit");
        let second =
            emit_x64_tail_enveloped_image(package.target(), &verified_closed, &verified_abi)
                .expect("enveloped image must be deterministic");
        assert_eq!(first, second);
        let verified = verify_x64_tail_enveloped_image(
            &first,
            package.target(),
            &verified_closed,
            &verified_abi,
        )
        .expect("enveloped image must independently replay");
        assert_eq!(verified.decoded().totals, first.totals());
        assert_eq!(first.source_closed_image_hash(), closed.image_hash());
        assert_eq!(first.source_abi_capsule_hash(), abi.capsule_hash());
        assert_eq!(first.entry_successor(), closed.entry_successor());
        assert_eq!(first.entry_point(), 7_272);
        assert_eq!(first.source_spans().len(), 4);
        assert_eq!(first.abi_programs().len(), 3);
        assert_eq!(first.abi_instructions().len(), 30);
        assert_eq!(first.relocation_receipts().len(), 192);
        assert_eq!(first.cfg_edges().len(), 209);
        assert_eq!(first.abi_programs()[0].start, 7_272);
        assert_eq!(first.abi_programs()[0].end, 7_371);
        assert_eq!(first.abi_programs()[1].start, 7_371);
        assert_eq!(first.abi_programs()[1].end, 7_408);
        assert_eq!(first.abi_programs()[2].start, 7_408);
        assert_eq!(first.abi_programs()[2].end, 7_450);
        assert_eq!(
            first.image_hash().to_hex(),
            "51f5498479257a50798e5c43ee0b46d9a656bff80a760701ab1fbccd535b31a8"
        );
        assert_eq!(
            first.code_hash().to_hex(),
            "b363c66803c90b7cfe9d760df39e9051a0f93fd65a1857870ebfb72717866998"
        );
        assert_eq!(
            first.totals(),
            X64TailEnvelopedImageTotals {
                closed_programs: 319,
                abi_programs: 3,
                labels: 142,
                frontiers: 151,
                closed_source_ranges: 746,
                composition_source_spans: 4,
                abi_instructions: 30,
                abi_effects: 30,
                relocations: 192,
                cfg_edges: 209,
                closed_prefix_bytes: 7_272,
                entry_bytes: 99,
                return_bytes: 37,
                bounds_bytes: 42,
                code_bytes: 7_450,
                compose_work: 8_998,
                decode_work: 8_998,
                projection_work: 8_222,
            }
        );

        let mut owners = vec![0u8; first.code().len()];
        for source in first.source_spans() {
            for owner in &mut owners[source.image_start as usize..source.image_end as usize] {
                *owner = owner.checked_add(1).expect("owner count must fit");
            }
        }
        assert!(owners.iter().all(|owner| *owner == 1));
        let patches = first
            .relocation_receipts()
            .iter()
            .flat_map(|relocation| relocation.patch_offset..relocation.patch_offset + 4)
            .collect::<BTreeSet<_>>();
        assert_eq!(patches.len(), first.relocation_receipts().len() * 4);
        assert!(first.cfg_edges().iter().any(|edge| {
            edge.kind == X64TailClosedCfgEdgeKind::Entry
                && edge.source_offset
                    == first
                        .relocation_receipts()
                        .iter()
                        .find_map(|relocation| match relocation.origin {
                            X64TailEnvelopedRelocationOrigin::EntryAdapter { .. } => {
                                Some(relocation.patch_offset)
                            }
                            _ => None,
                        })
                        .expect("entry relocation must exist")
        }));
        assert_eq!(closed, original_closed);
        assert_eq!(abi, original_abi);
        assert_eq!(package.target().program.code, original_target);
        assert_eq!(package.target().program.code_hash, original_target_hash);
        assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
    }

    #[test]
    fn every_enveloped_image_bit_and_resealed_evidence_mutation_fails_closed() {
        let (
            package,
            logical,
            physical,
            templates,
            transition,
            binding,
            realization,
            body,
            closed,
            abi,
        ) = build();
        let verified_closed = verify_x64_tail_closed_image(
            &closed,
            &body,
            &realization,
            &binding,
            &transition,
            &templates,
            &physical,
            &logical,
            package.target(),
        )
        .expect("closed image must verify");
        let verified_abi =
            verify_x64_tail_abi_envelope_capsule(&abi, package.target(), &verified_closed)
                .expect("ABI capsule must verify");
        let image =
            emit_x64_tail_enveloped_image(package.target(), &verified_closed, &verified_abi)
                .expect("enveloped image must emit");

        // Preserve the exhaustive public-verifier gate while distributing
        // disjoint byte ranges over a fixed finite worker set. Each worker
        // reuses one private buffer; every one of the code_len * 8 mutations
        // still crosses the complete production decoder independently.
        let workers = std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get)
            .min(8)
            .min(image.code.len());
        let chunk = image.code.len().div_ceil(workers);
        std::thread::scope(|scope| {
            for start in (0..image.code.len()).step_by(chunk) {
                let end = start.saturating_add(chunk).min(image.code.len());
                let original = &image.code;
                let target = package.target();
                let verified_closed = &verified_closed;
                let verified_abi = &verified_abi;
                scope.spawn(move || {
                    let mut code = original.clone();
                    for byte in start..end {
                        for bit in 0..8 {
                            code[byte] ^= 1 << bit;
                            assert!(decode_x64_tail_enveloped_image(
                                &code,
                                target,
                                verified_closed,
                                verified_abi,
                            )
                            .is_err());
                            code[byte] ^= 1 << bit;
                        }
                    }
                });
            }
        });
        assert!(decode_x64_tail_enveloped_image(
            &image.code[..image.code.len() - 1],
            package.target(),
            &verified_closed,
            &verified_abi,
        )
        .is_err());
        let mut trailing = image.code.clone();
        trailing.push(0xcc);
        assert!(decode_x64_tail_enveloped_image(
            &trailing,
            package.target(),
            &verified_closed,
            &verified_abi,
        )
        .is_err());

        macro_rules! reject_resealed {
            ($mutated:ident) => {{
                $mutated.image_hash = x64_tail_enveloped_image_hash(&$mutated)
                    .expect("mutated evidence must locally reseal");
                assert!(verify_x64_tail_enveloped_image(
                    &$mutated,
                    package.target(),
                    &verified_closed,
                    &verified_abi,
                )
                .is_err());
            }};
        }

        let mut source_span = image.clone();
        source_span.source_spans[0].source_end ^= 1;
        reject_resealed!(source_span);

        let mut program = image.clone();
        program.closed_programs[0].end ^= 1;
        reject_resealed!(program);

        let mut label = image.clone();
        label.label_receipts[0].offset ^= 1;
        reject_resealed!(label);

        let mut frontier = image.clone();
        frontier.frontier_receipts[0].owner_ordinal ^= 1;
        reject_resealed!(frontier);

        let mut closed_source = image.clone();
        closed_source.closed_sources[0].source_start ^= 1;
        reject_resealed!(closed_source);

        let mut abi_program = image.clone();
        abi_program.abi_programs[0].end ^= 1;
        reject_resealed!(abi_program);

        let mut abi_instruction = image.clone();
        abi_instruction.abi_instructions[0].ordinal ^= 1;
        reject_resealed!(abi_instruction);

        let mut relocation = image.clone();
        relocation.relocation_receipts[0].target_offset ^= 1;
        reject_resealed!(relocation);

        let mut cfg = image.clone();
        cfg.cfg_edges[0].source_offset ^= 1;
        reject_resealed!(cfg);

        let mut total = image.clone();
        total.totals.code_bytes ^= 1;
        reject_resealed!(total);

        let mut entry_point = image.clone();
        entry_point.entry_point ^= 1;
        reject_resealed!(entry_point);

        let mut predecessor = image.clone();
        predecessor.source_abi_capsule_hash.0[0] ^= 1;
        reject_resealed!(predecessor);

        let mut policy = image.clone();
        policy.policy_version.2 ^= 1;
        reject_resealed!(policy);

        let mut code_hash = image.clone();
        code_hash.code_hash.0[0] ^= 1;
        reject_resealed!(code_hash);

        let mut resealed_code = image.clone();
        resealed_code.code[0] ^= 1;
        resealed_code.code_hash = x64_tail_enveloped_image_code_hash(&resealed_code.code)
            .expect("mutated code hash must compute");
        reject_resealed!(resealed_code);
    }
}
