//! Independent inverse proof for the ADR-0067 fully enveloped image.
//!
//! This decoder derives final placement from verified predecessor manifests,
//! validates every final rel32 directly from bytes, and projects the image
//! back to the exact independently decoded ADR-0065 and ADR-0066 artifacts.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_abi_envelope::{
    VerifiedX64TailAbiEnvelopeCapsule, X64TailAbiEnvelopeInstructionReceipt,
    X64TailAbiEnvelopeProgramKind, X64TailAbiEnvelopeProgramReceipt,
};
use super::x64_tail_abi_envelope_decode::decode_x64_tail_abi_envelope_capsule;
use super::x64_tail_body_frontier_realization::X64TailBodyControlTarget;
use super::x64_tail_closed_image::{
    VerifiedX64TailClosedImage, X64TailClosedCfgDestination, X64TailClosedCfgEdge,
    X64TailClosedCfgEdgeKind, X64TailClosedFrontierReceipt, X64TailClosedLabelReceipt,
    X64TailClosedProgramReceipt, X64TailClosedSourceReceipt, X64TailClosedTerminalKind,
};
use super::x64_tail_enveloped_image::{
    X64TailEnvelopedImageTotals, X64TailEnvelopedRelocationOrigin,
    X64TailEnvelopedRelocationReceipt, X64TailEnvelopedSourceKind, X64TailEnvelopedSourceReceipt,
    X64_TAIL_ENVELOPED_IMAGE_MAX_CODE_BYTES, X64_TAIL_ENVELOPED_IMAGE_MAX_RELOCATIONS,
    X64_TAIL_ENVELOPED_IMAGE_MAX_WORK,
};
use super::x64_target::{verify_x64_target_r1_s7a, X64LabelId, X64TargetArtifact};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const X64_TAIL_ENVELOPED_IMAGE_DECODER_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);

const CODE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-enveloped-image-code:v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailDecodedEnvelopedImage {
    pub entry_successor: X64TailBodyControlTarget,
    pub entry_point: u32,
    pub source_spans: Vec<X64TailEnvelopedSourceReceipt>,
    pub closed_programs: Vec<X64TailClosedProgramReceipt>,
    pub labels: Vec<X64TailClosedLabelReceipt>,
    pub frontiers: Vec<X64TailClosedFrontierReceipt>,
    pub closed_sources: Vec<X64TailClosedSourceReceipt>,
    pub abi_programs: Vec<X64TailAbiEnvelopeProgramReceipt>,
    pub abi_instructions: Vec<X64TailAbiEnvelopeInstructionReceipt>,
    pub relocations: Vec<X64TailEnvelopedRelocationReceipt>,
    pub cfg_edges: Vec<X64TailClosedCfgEdge>,
    pub code_hash: SemanticHash,
    pub totals: X64TailEnvelopedImageTotals,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailEnvelopedImageDecodeError {
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
    Truncated {
        offset: u32,
    },
    TrailingBytes {
        expected: u32,
        actual: u32,
    },
    RelocationMismatch {
        patch: u32,
    },
    SourceProjectionMismatch {
        source: &'static str,
    },
    AbiProjectionDecode,
}

impl fmt::Display for X64TailEnvelopedImageDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPredecessor { field } => {
                write!(
                    formatter,
                    "enveloped decoder has invalid predecessor {field}"
                )
            }
            Self::InvalidField { field } => {
                write!(formatter, "enveloped decoder has invalid {field}")
            }
            Self::MissingTarget { field } => {
                write!(formatter, "enveloped decoder is missing {field}")
            }
            Self::LimitExceeded {
                field,
                limit,
                actual,
            } => write!(
                formatter,
                "enveloped decoder {field} uses {actual}; limit is {limit}"
            ),
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "enveloped decoder overflowed {field}")
            }
            Self::Truncated { offset } => {
                write!(formatter, "enveloped decoder truncated at {offset}")
            }
            Self::TrailingBytes { expected, actual } => write!(
                formatter,
                "enveloped decoder expected {expected} bytes but received {actual}"
            ),
            Self::RelocationMismatch { patch } => {
                write!(formatter, "enveloped decoder rel32 mismatch at {patch}")
            }
            Self::SourceProjectionMismatch { source } => {
                write!(
                    formatter,
                    "enveloped decoder {source} projection mismatches"
                )
            }
            Self::AbiProjectionDecode => formatter
                .write_str("enveloped decoder ABI projection does not independently decode"),
        }
    }
}

impl std::error::Error for X64TailEnvelopedImageDecodeError {}

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

pub fn decode_x64_tail_enveloped_image(
    code: &[u8],
    target: &X64TargetArtifact,
    closed: &VerifiedX64TailClosedImage<'_>,
    abi: &VerifiedX64TailAbiEnvelopeCapsule<'_>,
) -> Result<X64TailDecodedEnvelopedImage, X64TailEnvelopedImageDecodeError> {
    if code.len() as u64 > X64_TAIL_ENVELOPED_IMAGE_MAX_CODE_BYTES {
        return Err(X64TailEnvelopedImageDecodeError::LimitExceeded {
            field: "code bytes",
            limit: X64_TAIL_ENVELOPED_IMAGE_MAX_CODE_BYTES,
            actual: code.len() as u64,
        });
    }
    verify_predecessors(target, closed, abi)?;
    let layout = derive_layout(closed, abi)?;
    let actual = to_u32(code.len(), "code length")?;
    if actual < layout.code_bytes {
        return Err(X64TailEnvelopedImageDecodeError::Truncated { offset: actual });
    }
    if actual > layout.code_bytes {
        return Err(X64TailEnvelopedImageDecodeError::TrailingBytes {
            expected: layout.code_bytes,
            actual,
        });
    }

    let mut patch_bytes = BTreeSet::new();
    let mut relocations = Vec::new();
    for source in &closed.decoded().relocations {
        let target_offset = control_offset(&layout, source.target)?;
        let displacement = exact_rel32(code, &mut patch_bytes, source.patch_offset, target_offset)?;
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
    let source_entry = abi.decoded().relocation;
    let entry_patch = layout
        .prefix_bytes
        .checked_add(source_entry.patch_offset)
        .ok_or(X64TailEnvelopedImageDecodeError::ArithmeticOverflow {
            field: "entry patch",
        })?;
    let entry_target = control_offset(&layout, source_entry.target)?;
    let entry_displacement = exact_rel32(code, &mut patch_bytes, entry_patch, entry_target)?;
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
    if relocations.len() as u64 > u64::from(X64_TAIL_ENVELOPED_IMAGE_MAX_RELOCATIONS) {
        return Err(X64TailEnvelopedImageDecodeError::LimitExceeded {
            field: "relocations",
            limit: u64::from(X64_TAIL_ENVELOPED_IMAGE_MAX_RELOCATIONS),
            actual: relocations.len() as u64,
        });
    }

    project_closed(code, &layout, closed)?;
    project_abi(code, &layout, target, closed, abi)?;
    let cfg_edges = derive_cfg_edges(closed, &layout, entry_patch)?;
    let totals = decoded_totals(closed, abi, &layout, relocations.len(), cfg_edges.len())?;
    let code_hash = decoded_code_hash(code)?;
    Ok(X64TailDecodedEnvelopedImage {
        entry_successor: closed.image().entry_successor(),
        entry_point: layout.entry_point,
        source_spans: layout.source_spans,
        closed_programs: closed.decoded().programs.clone(),
        labels: layout.labels,
        frontiers: closed.decoded().frontiers.clone(),
        closed_sources: closed.decoded().sources.clone(),
        abi_programs: layout.abi_programs,
        abi_instructions: layout.abi_instructions,
        relocations,
        cfg_edges,
        code_hash,
        totals,
    })
}

fn verify_predecessors(
    target: &X64TargetArtifact,
    closed: &VerifiedX64TailClosedImage<'_>,
    abi: &VerifiedX64TailAbiEnvelopeCapsule<'_>,
) -> Result<(), X64TailEnvelopedImageDecodeError> {
    verify_x64_target_r1_s7a(target).map_err(|_| {
        X64TailEnvelopedImageDecodeError::InvalidPredecessor {
            field: "verified x86-64 target",
        }
    })?;
    if closed.image().source_target_semantic_hash() != target.semantic_hash
        || abi.capsule().source_target_semantic_hash() != target.semantic_hash
        || abi.capsule().source_closed_image_hash() != closed.image().image_hash()
        || abi.capsule().entry_successor() != closed.image().entry_successor()
    {
        return Err(X64TailEnvelopedImageDecodeError::InvalidPredecessor {
            field: "target/closed-image/ABI identity chain",
        });
    }
    Ok(())
}

fn derive_layout(
    closed: &VerifiedX64TailClosedImage<'_>,
    abi: &VerifiedX64TailAbiEnvelopeCapsule<'_>,
) -> Result<Layout, X64TailEnvelopedImageDecodeError> {
    if closed.decoded().terminals.len() != 3 || abi.decoded().programs.len() != 3 {
        return Err(X64TailEnvelopedImageDecodeError::InvalidField {
            field: "terminal/program cardinality",
        });
    }
    let terminal = |kind| {
        let mut values = closed
            .decoded()
            .terminals
            .iter()
            .filter(|terminal| terminal.kind == kind);
        let value =
            values
                .next()
                .copied()
                .ok_or(X64TailEnvelopedImageDecodeError::MissingTarget {
                    field: "closed terminal",
                })?;
        if values.next().is_some() {
            return Err(X64TailEnvelopedImageDecodeError::InvalidField {
                field: "unique closed terminal",
            });
        }
        Ok(value)
    };
    let entry_terminal = terminal(X64TailClosedTerminalKind::EntryAdapter)?;
    let return_terminal = terminal(X64TailClosedTerminalKind::ReturnEpilogue)?;
    let bounds_terminal = terminal(X64TailClosedTerminalKind::BoundsEpilogue)?;
    let prefix_bytes = entry_terminal.offset;
    if return_terminal.offset != checked_add(prefix_bytes, 1, "terminal layout")?
        || bounds_terminal.offset != checked_add(prefix_bytes, 2, "terminal layout")?
        || closed.image().code().len() as u64 != u64::from(prefix_bytes) + 3
    {
        return Err(X64TailEnvelopedImageDecodeError::InvalidField {
            field: "terminal suffix layout",
        });
    }
    let program = |kind| {
        let mut values = abi
            .decoded()
            .programs
            .iter()
            .filter(|program| program.kind == kind);
        let value =
            values
                .next()
                .copied()
                .ok_or(X64TailEnvelopedImageDecodeError::MissingTarget {
                    field: "ABI program",
                })?;
        if values.next().is_some() {
            return Err(X64TailEnvelopedImageDecodeError::InvalidField {
                field: "unique ABI program",
            });
        }
        Ok(value)
    };
    let source_entry = program(X64TailAbiEnvelopeProgramKind::EntryAdapter)?;
    let source_return = program(X64TailAbiEnvelopeProgramKind::ReturnEpilogue)?;
    let source_bounds = program(X64TailAbiEnvelopeProgramKind::BoundsEpilogue)?;
    let anchor = abi.decoded().anchor;
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
        return Err(X64TailEnvelopedImageDecodeError::InvalidField {
            field: "canonical ABI source layout",
        });
    }
    let code_bytes = checked_add(prefix_bytes, anchor.offset, "code bytes")?;
    if u64::from(code_bytes) > X64_TAIL_ENVELOPED_IMAGE_MAX_CODE_BYTES {
        return Err(X64TailEnvelopedImageDecodeError::LimitExceeded {
            field: "code bytes",
            limit: X64_TAIL_ENVELOPED_IMAGE_MAX_CODE_BYTES,
            actual: u64::from(code_bytes),
        });
    }
    let rebase = |offset| checked_add(prefix_bytes, offset, "ABI rebase");
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
    let replacements = BTreeMap::from([
        (entry_terminal.label, rebase(source_entry.start)?),
        (return_terminal.label, rebase(source_return.start)?),
        (bounds_terminal.label, rebase(source_bounds.start)?),
    ]);
    let mut labels = closed.decoded().labels.clone();
    for label in &mut labels {
        if let Some(offset) = replacements.get(&label.label) {
            label.offset = *offset;
        }
    }
    let label_offsets = labels
        .iter()
        .map(|label| (label.label, label.offset))
        .collect::<BTreeMap<_, _>>();
    let frontier_offsets = closed
        .decoded()
        .frontiers
        .iter()
        .map(|frontier| (frontier.ordinal, frontier.offset))
        .collect::<BTreeMap<_, _>>();
    if label_offsets.len() != labels.len()
        || frontier_offsets.len() != closed.decoded().frontiers.len()
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
        return Err(X64TailEnvelopedImageDecodeError::InvalidField {
            field: "unique prefix ownership",
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

fn exact_rel32(
    code: &[u8],
    patch_bytes: &mut BTreeSet<u32>,
    patch: u32,
    target: u32,
) -> Result<i32, X64TailEnvelopedImageDecodeError> {
    let end = checked_add(patch, 4, "rel32 patch end")?;
    if u64::from(end) > code.len() as u64 {
        return Err(X64TailEnvelopedImageDecodeError::Truncated { offset: patch });
    }
    for byte in patch..end {
        if !patch_bytes.insert(byte) {
            return Err(X64TailEnvelopedImageDecodeError::InvalidField {
                field: "overlapping rel32 patch",
            });
        }
    }
    let displacement = read_i32(code, patch)?;
    let resolved = i64::from(end).checked_add(i64::from(displacement)).ok_or(
        X64TailEnvelopedImageDecodeError::ArithmeticOverflow {
            field: "rel32 resolution",
        },
    )?;
    if resolved != i64::from(target) {
        return Err(X64TailEnvelopedImageDecodeError::RelocationMismatch { patch });
    }
    let expected = i64::from(target).checked_sub(i64::from(end)).ok_or(
        X64TailEnvelopedImageDecodeError::ArithmeticOverflow {
            field: "rel32 displacement",
        },
    )?;
    if i64::from(displacement) != expected {
        return Err(X64TailEnvelopedImageDecodeError::RelocationMismatch { patch });
    }
    Ok(displacement)
}

fn project_closed(
    code: &[u8],
    layout: &Layout,
    closed: &VerifiedX64TailClosedImage<'_>,
) -> Result<(), X64TailEnvelopedImageDecodeError> {
    let prefix = usize::try_from(layout.prefix_bytes).map_err(|_| {
        X64TailEnvelopedImageDecodeError::ArithmeticOverflow {
            field: "closed projection prefix",
        }
    })?;
    let mut projection = code[..prefix].to_vec();
    for relocation in &closed.decoded().relocations {
        copy_patch(
            &mut projection,
            closed.image().code(),
            relocation.patch_offset,
        )?;
    }
    projection.extend_from_slice(&closed.image().code()[prefix..]);
    if projection != closed.image().code() {
        return Err(X64TailEnvelopedImageDecodeError::SourceProjectionMismatch {
            source: "ADR-0065",
        });
    }
    Ok(())
}

fn project_abi(
    code: &[u8],
    layout: &Layout,
    target: &X64TargetArtifact,
    closed: &VerifiedX64TailClosedImage<'_>,
    abi: &VerifiedX64TailAbiEnvelopeCapsule<'_>,
) -> Result<(), X64TailEnvelopedImageDecodeError> {
    let prefix = usize::try_from(layout.prefix_bytes).map_err(|_| {
        X64TailEnvelopedImageDecodeError::ArithmeticOverflow {
            field: "ABI projection prefix",
        }
    })?;
    let mut projection = code[prefix..].to_vec();
    copy_patch(
        &mut projection,
        abi.capsule().code(),
        abi.decoded().relocation.patch_offset,
    )?;
    let anchor = usize::try_from(abi.decoded().anchor.offset).map_err(|_| {
        X64TailEnvelopedImageDecodeError::ArithmeticOverflow {
            field: "ABI projection anchor",
        }
    })?;
    projection.extend_from_slice(&abi.capsule().code()[anchor..]);
    if projection != abi.capsule().code() {
        return Err(X64TailEnvelopedImageDecodeError::SourceProjectionMismatch {
            source: "ADR-0066",
        });
    }
    let decoded = decode_x64_tail_abi_envelope_capsule(&projection, target, closed)
        .map_err(|_| X64TailEnvelopedImageDecodeError::AbiProjectionDecode)?;
    if decoded != *abi.decoded() {
        return Err(X64TailEnvelopedImageDecodeError::AbiProjectionDecode);
    }
    Ok(())
}

fn copy_patch(
    destination: &mut [u8],
    source: &[u8],
    patch: u32,
) -> Result<(), X64TailEnvelopedImageDecodeError> {
    let start = usize::try_from(patch).map_err(|_| {
        X64TailEnvelopedImageDecodeError::ArithmeticOverflow {
            field: "projection patch",
        }
    })?;
    let end = start
        .checked_add(4)
        .ok_or(X64TailEnvelopedImageDecodeError::ArithmeticOverflow {
            field: "projection patch end",
        })?;
    if end > destination.len() || end > source.len() {
        return Err(X64TailEnvelopedImageDecodeError::InvalidField {
            field: "projection patch range",
        });
    }
    destination[start..end].copy_from_slice(&source[start..end]);
    Ok(())
}

fn control_offset(
    layout: &Layout,
    target: X64TailBodyControlTarget,
) -> Result<u32, X64TailEnvelopedImageDecodeError> {
    match target {
        X64TailBodyControlTarget::Label(label) => layout.label_offsets.get(&label),
        X64TailBodyControlTarget::Frontier(ordinal) => layout.frontier_offsets.get(&ordinal),
    }
    .copied()
    .ok_or(X64TailEnvelopedImageDecodeError::MissingTarget {
        field: "control target",
    })
}

fn derive_cfg_edges(
    closed: &VerifiedX64TailClosedImage<'_>,
    layout: &Layout,
    entry_patch: u32,
) -> Result<Vec<X64TailClosedCfgEdge>, X64TailEnvelopedImageDecodeError> {
    let mut entry_edges = 0u32;
    let mut edges = Vec::new();
    for source in &closed.decoded().cfg_edges {
        let source_offset = if source.kind == X64TailClosedCfgEdgeKind::Entry {
            entry_edges = checked_add(entry_edges, 1, "entry CFG count")?;
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
        return Err(X64TailEnvelopedImageDecodeError::InvalidField {
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
        return Err(X64TailEnvelopedImageDecodeError::InvalidField {
            field: "CFG edge conservation",
        });
    }
    Ok(edges)
}

fn rebase_destination(
    destination: X64TailClosedCfgDestination,
    layout: &Layout,
) -> Result<X64TailClosedCfgDestination, X64TailEnvelopedImageDecodeError> {
    Ok(match destination {
        X64TailClosedCfgDestination::Label { label, .. } => X64TailClosedCfgDestination::Label {
            label,
            offset: *layout
                .label_offsets
                .get(&label)
                .ok_or(X64TailEnvelopedImageDecodeError::MissingTarget { field: "CFG label" })?,
        },
        X64TailClosedCfgDestination::Frontier { ordinal, .. } => {
            X64TailClosedCfgDestination::Frontier {
                ordinal,
                offset: *layout.frontier_offsets.get(&ordinal).ok_or(
                    X64TailEnvelopedImageDecodeError::MissingTarget {
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

fn decoded_totals(
    closed: &VerifiedX64TailClosedImage<'_>,
    abi: &VerifiedX64TailAbiEnvelopeCapsule<'_>,
    layout: &Layout,
    relocations: usize,
    cfg_edges: usize,
) -> Result<X64TailEnvelopedImageTotals, X64TailEnvelopedImageDecodeError> {
    let decode_work = work(
        layout.code_bytes,
        relocations,
        layout.source_spans.len(),
        closed.decoded().sources.len(),
        layout.abi_instructions.len(),
    )?;
    let projection_work = closed
        .image()
        .code()
        .len()
        .checked_add(abi.capsule().code().len())
        .and_then(|value| value.checked_add(relocations.checked_mul(4)?))
        .ok_or(X64TailEnvelopedImageDecodeError::ArithmeticOverflow {
            field: "projection work",
        })? as u64;
    if projection_work > X64_TAIL_ENVELOPED_IMAGE_MAX_WORK {
        return Err(X64TailEnvelopedImageDecodeError::LimitExceeded {
            field: "projection work",
            limit: X64_TAIL_ENVELOPED_IMAGE_MAX_WORK,
            actual: projection_work,
        });
    }
    Ok(X64TailEnvelopedImageTotals {
        closed_programs: to_u32(closed.decoded().programs.len(), "closed programs")?,
        abi_programs: to_u32(layout.abi_programs.len(), "ABI programs")?,
        labels: to_u32(layout.labels.len(), "labels")?,
        frontiers: to_u32(closed.decoded().frontiers.len(), "frontiers")?,
        closed_source_ranges: to_u32(closed.decoded().sources.len(), "closed sources")?,
        composition_source_spans: to_u32(layout.source_spans.len(), "source spans")?,
        abi_instructions: to_u32(layout.abi_instructions.len(), "ABI instructions")?,
        abi_effects: to_u32(layout.abi_instructions.len(), "ABI effects")?,
        relocations: to_u32(relocations, "relocations")?,
        cfg_edges: to_u32(cfg_edges, "CFG edges")?,
        closed_prefix_bytes: layout.prefix_bytes,
        entry_bytes: layout.abi_programs[0].end - layout.abi_programs[0].start,
        return_bytes: layout.abi_programs[1].end - layout.abi_programs[1].start,
        bounds_bytes: layout.abi_programs[2].end - layout.abi_programs[2].start,
        code_bytes: layout.code_bytes,
        compose_work: decode_work,
        decode_work,
        projection_work,
    })
}

fn work(
    code_bytes: u32,
    relocations: usize,
    spans: usize,
    closed_sources: usize,
    abi_instructions: usize,
) -> Result<u64, X64TailEnvelopedImageDecodeError> {
    let value = u64::from(code_bytes)
        .checked_add((relocations as u64).checked_mul(4).ok_or(
            X64TailEnvelopedImageDecodeError::ArithmeticOverflow {
                field: "relocation work",
            },
        )?)
        .and_then(|value| value.checked_add(spans as u64))
        .and_then(|value| value.checked_add(closed_sources as u64))
        .and_then(|value| value.checked_add(abi_instructions as u64))
        .ok_or(X64TailEnvelopedImageDecodeError::ArithmeticOverflow {
            field: "decode work",
        })?;
    if value > X64_TAIL_ENVELOPED_IMAGE_MAX_WORK {
        return Err(X64TailEnvelopedImageDecodeError::LimitExceeded {
            field: "decode work",
            limit: X64_TAIL_ENVELOPED_IMAGE_MAX_WORK,
            actual: value,
        });
    }
    Ok(value)
}

fn decoded_code_hash(code: &[u8]) -> Result<SemanticHash, X64TailEnvelopedImageDecodeError> {
    if code.len() as u64 > X64_TAIL_ENVELOPED_IMAGE_MAX_CODE_BYTES {
        return Err(X64TailEnvelopedImageDecodeError::LimitExceeded {
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

fn read_i32(code: &[u8], offset: u32) -> Result<i32, X64TailEnvelopedImageDecodeError> {
    let start = usize::try_from(offset).map_err(|_| {
        X64TailEnvelopedImageDecodeError::ArithmeticOverflow {
            field: "rel32 index",
        }
    })?;
    let end = start
        .checked_add(4)
        .ok_or(X64TailEnvelopedImageDecodeError::ArithmeticOverflow {
            field: "rel32 read end",
        })?;
    let bytes = code
        .get(start..end)
        .ok_or(X64TailEnvelopedImageDecodeError::Truncated { offset })?;
    Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn checked_add(
    left: u32,
    right: u32,
    field: &'static str,
) -> Result<u32, X64TailEnvelopedImageDecodeError> {
    left.checked_add(right)
        .ok_or(X64TailEnvelopedImageDecodeError::ArithmeticOverflow { field })
}

fn to_u32(value: usize, field: &'static str) -> Result<u32, X64TailEnvelopedImageDecodeError> {
    u32::try_from(value).map_err(|_| X64TailEnvelopedImageDecodeError::ArithmeticOverflow { field })
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
        } => (
            2,
            match program_kind {
                super::x64_tail_closed_image::X64TailClosedProgramKind::Site => 0,
                super::x64_tail_closed_image::X64TailClosedProgramKind::Frontier => 1,
            },
            program_ordinal,
            offset,
        ),
    }
}
