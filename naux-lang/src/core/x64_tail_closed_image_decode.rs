//! Independent inverse proof for the ADR-0065 closed semantic image.
//!
//! This module has no byte-emission or composer helper. It derives canonical
//! placement from predecessor semantics, consumes the image forward, proves
//! every non-relocation byte against its accepted source capsule, and rebuilds
//! relocation and CFG evidence without consulting image receipts.

use super::x64_tail_body_frontier_capsule::{
    X64TailBodyCapsuleProgramKind, X64TailBodyFrontierCapsule,
};
use super::x64_tail_body_frontier_decode::decode_x64_tail_body_frontier_bytes;
use super::x64_tail_body_frontier_realization::{
    X64TailBodyAtom, X64TailBodyAtomInstruction, X64TailBodyControlTarget,
    X64TailBodyFrontierRealization, X64TailFrontierPlacement, X64TailFrontierProgramDisposition,
};
use super::x64_tail_candidate_capsule::X64TailCandidateCapsule;
use super::x64_tail_candidate_decode::decode_x64_tail_candidate_bytes;
use super::x64_tail_closed_image::{
    X64TailClosedCfgDestination, X64TailClosedCfgEdge, X64TailClosedCfgEdgeKind,
    X64TailClosedFrontierReceipt, X64TailClosedImageTotals, X64TailClosedLabelReceipt,
    X64TailClosedProgramKind, X64TailClosedProgramReceipt, X64TailClosedRelocationReceipt,
    X64TailClosedSourceKind, X64TailClosedSourceReceipt, X64TailClosedTerminalKind,
    X64TailClosedTerminalReceipt, TERMINAL_BYTE, X64_TAIL_CLOSED_IMAGE_MAX_CODE_BYTES,
    X64_TAIL_CLOSED_IMAGE_MAX_LABELS, X64_TAIL_CLOSED_IMAGE_MAX_PROGRAMS,
    X64_TAIL_CLOSED_IMAGE_MAX_RELOCATIONS, X64_TAIL_CLOSED_IMAGE_MAX_SOURCE_RANGES,
    X64_TAIL_CLOSED_IMAGE_MAX_WORK,
};
use super::x64_tail_site_binding::{
    X64TailFrontierBindingKind, X64TailFrontierBindingRow, X64TailSiteBindingProof,
};
use super::x64_tail_template_realization::X64TailTemplateRealization;
use super::x64_target::{X64LabelId, X64LabelOwner, X64TargetArtifact, X64TargetProgram};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const X64_TAIL_CLOSED_IMAGE_DECODER_POLICY_VERSION: (u16, u16, u16) = (1, 1, 0);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailDecodedClosedImage {
    pub entry_successor: X64TailBodyControlTarget,
    pub programs: Vec<X64TailClosedProgramReceipt>,
    pub labels: Vec<X64TailClosedLabelReceipt>,
    pub frontiers: Vec<X64TailClosedFrontierReceipt>,
    pub terminals: Vec<X64TailClosedTerminalReceipt>,
    pub sources: Vec<X64TailClosedSourceReceipt>,
    pub relocations: Vec<X64TailClosedRelocationReceipt>,
    pub cfg_edges: Vec<X64TailClosedCfgEdge>,
    pub totals: X64TailClosedImageTotals,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailClosedImageDecodeError {
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
    SourceByteMismatch {
        offset: u32,
    },
    RelocationMismatch {
        patch: u32,
    },
    TerminalMismatch {
        offset: u32,
    },
    PredecessorDecode,
}

impl fmt::Display for X64TailClosedImageDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField { field } => {
                write!(formatter, "closed-image decoder has invalid {field}")
            }
            Self::MissingTarget { field } => {
                write!(formatter, "closed-image decoder is missing {field}")
            }
            Self::LimitExceeded {
                field,
                limit,
                actual,
            } => write!(
                formatter,
                "closed-image decoder {field} uses {actual}; limit is {limit}"
            ),
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "closed-image decoder overflowed {field}")
            }
            Self::Truncated { offset } => write!(formatter, "closed image truncates at {offset}"),
            Self::TrailingBytes { expected, actual } => write!(
                formatter,
                "closed image has {actual} bytes; expected exactly {expected}"
            ),
            Self::SourceByteMismatch { offset } => write!(
                formatter,
                "closed image byte at {offset} differs from its sole source owner"
            ),
            Self::RelocationMismatch { patch } => write!(
                formatter,
                "closed image rel32 at {patch} does not resolve to its typed target"
            ),
            Self::TerminalMismatch { offset } => write!(
                formatter,
                "closed image terminal at {offset} is not the canonical typed trap"
            ),
            Self::PredecessorDecode => formatter.write_str(
                "closed-image decoder could not independently decode ADR-0064 source bytes",
            ),
        }
    }
}
impl std::error::Error for X64TailClosedImageDecodeError {}

#[derive(Clone)]
struct Layout {
    programs: Vec<X64TailClosedProgramReceipt>,
    labels: Vec<X64TailClosedLabelReceipt>,
    frontiers: Vec<X64TailClosedFrontierReceipt>,
    terminals: Vec<X64TailClosedTerminalReceipt>,
    label_offsets: BTreeMap<X64LabelId, u32>,
    frontier_offsets: BTreeMap<u32, u32>,
    entry_successor: X64TailBodyControlTarget,
    code_bytes: u32,
}

/// Independently recover complete closed-image ownership and internal CFG.
pub fn decode_x64_tail_closed_image(
    code: &[u8],
    body: &X64TailBodyFrontierCapsule,
    realization: &X64TailBodyFrontierRealization,
    binding: &X64TailSiteBindingProof,
    transition: &X64TailCandidateCapsule,
    templates: &X64TailTemplateRealization,
    target: &X64TargetArtifact,
) -> Result<X64TailDecodedClosedImage, X64TailClosedImageDecodeError> {
    if code.len() as u64 > X64_TAIL_CLOSED_IMAGE_MAX_CODE_BYTES {
        return Err(X64TailClosedImageDecodeError::LimitExceeded {
            field: "code bytes",
            limit: X64_TAIL_CLOSED_IMAGE_MAX_CODE_BYTES,
            actual: code.len() as u64,
        });
    }
    // Reparse ADR-0064 source bytes; the composed-image parser never trusts its
    // program/fixup receipts as proof that the source grammar was valid.
    decode_x64_tail_body_frontier_bytes(body.code(), realization, transition)
        .map_err(|_| X64TailClosedImageDecodeError::PredecessorDecode)?;
    decode_x64_tail_candidate_bytes(transition.code(), templates, target)
        .map_err(|_| X64TailClosedImageDecodeError::PredecessorDecode)?;
    let layout = derive_layout(target, binding, realization)?;
    let actual = u32::try_from(code.len()).map_err(|_| {
        X64TailClosedImageDecodeError::ArithmeticOverflow {
            field: "code length",
        }
    })?;
    if actual < layout.code_bytes {
        return Err(X64TailClosedImageDecodeError::Truncated { offset: actual });
    }
    if actual > layout.code_bytes {
        return Err(X64TailClosedImageDecodeError::TrailingBytes {
            expected: layout.code_bytes,
            actual,
        });
    }
    let mut sources = Vec::new();
    let mut relocations = Vec::new();
    let mut compose_work = 0u64;
    let mut decode_work = 0u64;
    let programs = layout
        .programs
        .iter()
        .map(|program| ((program.kind, program.ordinal), *program))
        .collect::<BTreeMap<_, _>>();

    for program in &layout.programs {
        if program.start == program.end {
            continue;
        }
        let atoms = match program.kind {
            X64TailClosedProgramKind::Site => {
                &realization
                    .sites()
                    .iter()
                    .find(|site| site.ordinal == program.ordinal)
                    .ok_or(X64TailClosedImageDecodeError::MissingTarget {
                        field: "site program",
                    })?
                    .atoms
            }
            X64TailClosedProgramKind::Frontier => {
                &realization
                    .frontiers()
                    .iter()
                    .find(|frontier| frontier.row_ordinal == program.ordinal)
                    .ok_or(X64TailClosedImageDecodeError::MissingTarget {
                        field: "frontier program",
                    })?
                    .atoms
            }
        };
        decode_program(
            code,
            program,
            atoms,
            body,
            transition,
            &layout,
            &mut sources,
            &mut relocations,
            &mut compose_work,
            &mut decode_work,
        )?;
    }
    for terminal in &layout.terminals {
        let offset = usize::try_from(terminal.offset).map_err(|_| {
            X64TailClosedImageDecodeError::ArithmeticOverflow {
                field: "terminal offset",
            }
        })?;
        if code.get(offset) != Some(&TERMINAL_BYTE) {
            return Err(X64TailClosedImageDecodeError::TerminalMismatch {
                offset: terminal.offset,
            });
        }
        compose_work = charge(compose_work, 1)?;
        decode_work = charge(decode_work, 1)?;
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
    let cfg_edges = derive_cfg_edges(realization, binding, &layout, &relocations, &programs)?;
    let body_ranges = sources
        .iter()
        .filter(|source| source.source_kind == X64TailClosedSourceKind::Body)
        .count();
    let transition_ranges = sources.len().checked_sub(body_ranges).ok_or(
        X64TailClosedImageDecodeError::ArithmeticOverflow {
            field: "transition ranges",
        },
    )?;
    let body_bytes = source_bytes(&sources, X64TailClosedSourceKind::Body)?;
    let transition_bytes = source_bytes(&sources, X64TailClosedSourceKind::Transition)?;
    let totals = X64TailClosedImageTotals {
        programs: to_u32(layout.programs.len(), "programs")?,
        labels: to_u32(layout.labels.len(), "labels")?,
        frontiers: to_u32(layout.frontiers.len(), "frontiers")?,
        terminals: to_u32(layout.terminals.len(), "terminals")?,
        source_ranges: to_u32(sources.len(), "source ranges")?,
        body_ranges: to_u32(body_ranges, "body ranges")?,
        transition_ranges: to_u32(transition_ranges, "transition ranges")?,
        relocations: to_u32(relocations.len(), "relocations")?,
        cfg_edges: to_u32(cfg_edges.len(), "CFG edges")?,
        body_bytes,
        transition_bytes,
        terminal_bytes: to_u32(layout.terminals.len(), "terminal bytes")?,
        code_bytes: layout.code_bytes,
        compose_work,
        decode_work,
    };
    Ok(X64TailDecodedClosedImage {
        entry_successor: layout.entry_successor,
        programs: layout.programs,
        labels: layout.labels,
        frontiers: layout.frontiers,
        terminals: layout.terminals,
        sources,
        relocations,
        cfg_edges,
        totals,
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_program(
    code: &[u8],
    program: &X64TailClosedProgramReceipt,
    atoms: &[X64TailBodyAtom],
    body: &X64TailBodyFrontierCapsule,
    transition: &X64TailCandidateCapsule,
    layout: &Layout,
    sources: &mut Vec<X64TailClosedSourceReceipt>,
    relocations: &mut Vec<X64TailClosedRelocationReceipt>,
    compose_work: &mut u64,
    decode_work: &mut u64,
) -> Result<(), X64TailClosedImageDecodeError> {
    let body_kind = match program.kind {
        X64TailClosedProgramKind::Site => X64TailBodyCapsuleProgramKind::Site,
        X64TailClosedProgramKind::Frontier => X64TailBodyCapsuleProgramKind::Frontier,
    };
    let source_program = body
        .program_receipts()
        .iter()
        .find(|receipt| receipt.kind == body_kind && receipt.ordinal == program.ordinal)
        .ok_or(X64TailClosedImageDecodeError::MissingTarget {
            field: "body source program",
        })?;
    let mut body_cursor = source_program.start;
    for atom in atoms {
        let image_start = program.start.checked_add(atom.start).ok_or(
            X64TailClosedImageDecodeError::ArithmeticOverflow {
                field: "image atom start",
            },
        )?;
        let image_end = program.start.checked_add(atom.end).ok_or(
            X64TailClosedImageDecodeError::ArithmeticOverflow {
                field: "image atom end",
            },
        )?;
        let atom_len = atom.end.checked_sub(atom.start).ok_or(
            X64TailClosedImageDecodeError::InvalidField {
                field: "atom extent",
            },
        )?;
        let (source_kind, source_start, source_end, patches) = match atom.instruction {
            X64TailBodyAtomInstruction::CapsuleTransition {
                edge_ordinal,
                capsule_start,
                capsule_end,
            } => {
                let receipt = transition
                    .transition_receipts()
                    .iter()
                    .find(|receipt| receipt.edge_ordinal == edge_ordinal)
                    .ok_or(X64TailClosedImageDecodeError::MissingTarget {
                        field: "transition source",
                    })?;
                if receipt.start != capsule_start
                    || receipt.end != capsule_end
                    || capsule_end.checked_sub(capsule_start) != Some(atom_len)
                {
                    return Err(X64TailClosedImageDecodeError::InvalidField {
                        field: "transition span",
                    });
                }
                let patches = transition
                    .fixup_receipts()
                    .iter()
                    .filter(|fixup| fixup.edge_ordinal == edge_ordinal)
                    .map(|fixup| {
                        let relative = fixup.patch_offset.checked_sub(capsule_start).ok_or(
                            X64TailClosedImageDecodeError::InvalidField {
                                field: "transition patch span",
                            },
                        )?;
                        Ok((relative, X64TailBodyControlTarget::Label(fixup.target)))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                (
                    X64TailClosedSourceKind::Transition,
                    capsule_start,
                    capsule_end,
                    patches,
                )
            }
            _ => {
                let source_start = body_cursor;
                let source_end = source_start.checked_add(atom_len).ok_or(
                    X64TailClosedImageDecodeError::ArithmeticOverflow {
                        field: "body source end",
                    },
                )?;
                if source_end > source_program.end {
                    return Err(X64TailClosedImageDecodeError::InvalidField {
                        field: "body source span",
                    });
                }
                let patches = body
                    .fixup_receipts()
                    .iter()
                    .filter(|fixup| {
                        fixup.program_kind == body_kind
                            && fixup.program_ordinal == program.ordinal
                            && fixup.atom_ordinal == atom.ordinal
                    })
                    .map(|fixup| {
                        let relative = fixup.patch_offset.checked_sub(source_start).ok_or(
                            X64TailClosedImageDecodeError::InvalidField {
                                field: "body patch span",
                            },
                        )?;
                        Ok((relative, fixup.target))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                body_cursor = source_end;
                (
                    X64TailClosedSourceKind::Body,
                    source_start,
                    source_end,
                    patches,
                )
            }
        };
        let source_code = match source_kind {
            X64TailClosedSourceKind::Body => body.code(),
            X64TailClosedSourceKind::Transition => transition.code(),
        };
        let patch_offsets = patches
            .iter()
            .map(|(relative, _)| *relative)
            .collect::<BTreeSet<_>>();
        for relative in 0..atom_len {
            if patch_offsets
                .iter()
                .any(|patch| relative >= *patch && relative < patch.saturating_add(4))
            {
                continue;
            }
            let image_offset = image_start.checked_add(relative).ok_or(
                X64TailClosedImageDecodeError::ArithmeticOverflow {
                    field: "image byte",
                },
            )?;
            let source_offset = source_start.checked_add(relative).ok_or(
                X64TailClosedImageDecodeError::ArithmeticOverflow {
                    field: "source byte",
                },
            )?;
            if byte(code, image_offset)? != byte(source_code, source_offset)? {
                return Err(X64TailClosedImageDecodeError::SourceByteMismatch {
                    offset: image_offset,
                });
            }
            *decode_work = charge(*decode_work, 1)?;
        }
        sources.push(X64TailClosedSourceReceipt {
            source_kind,
            program_kind: program.kind,
            program_ordinal: program.ordinal,
            atom_ordinal: atom.ordinal,
            source_start,
            source_end,
            image_start,
            image_end,
        });
        for (relative, target) in patches {
            let patch_offset = image_start.checked_add(relative).ok_or(
                X64TailClosedImageDecodeError::ArithmeticOverflow {
                    field: "image patch",
                },
            )?;
            let target_offset = control_offset(layout, target)?;
            let after = patch_offset
                .checked_add(4)
                .ok_or(X64TailClosedImageDecodeError::ArithmeticOverflow { field: "rel32 end" })?;
            let expected64 = i64::from(target_offset) - i64::from(after);
            let expected = i32::try_from(expected64).map_err(|_| {
                X64TailClosedImageDecodeError::RelocationMismatch {
                    patch: patch_offset,
                }
            })?;
            let actual = read_i32(code, patch_offset)?;
            if actual != expected {
                return Err(X64TailClosedImageDecodeError::RelocationMismatch {
                    patch: patch_offset,
                });
            }
            relocations.push(X64TailClosedRelocationReceipt {
                source_kind,
                program_kind: program.kind,
                program_ordinal: program.ordinal,
                atom_ordinal: atom.ordinal,
                patch_offset,
                target,
                target_offset,
                displacement: actual,
            });
            *decode_work = charge(*decode_work, 4)?;
        }
        *compose_work = charge(
            *compose_work,
            u64::from(atom_len).checked_add(1).ok_or(
                X64TailClosedImageDecodeError::ArithmeticOverflow {
                    field: "compose work",
                },
            )?,
        )?;
        *decode_work = charge(*decode_work, 1)?;
    }
    if body_cursor != source_program.end {
        return Err(X64TailClosedImageDecodeError::InvalidField {
            field: "body source coverage",
        });
    }
    Ok(())
}

fn derive_layout(
    target: &X64TargetArtifact,
    binding: &X64TailSiteBindingProof,
    realization: &X64TailBodyFrontierRealization,
) -> Result<Layout, X64TailClosedImageDecodeError> {
    ensure_limit(
        "programs",
        X64_TAIL_CLOSED_IMAGE_MAX_PROGRAMS,
        realization
            .sites()
            .len()
            .checked_add(realization.frontiers().len())
            .ok_or(X64TailClosedImageDecodeError::ArithmeticOverflow {
                field: "program count",
            })?,
    )?;
    ensure_limit(
        "labels",
        X64_TAIL_CLOSED_IMAGE_MAX_LABELS,
        target.program.labels.len(),
    )?;
    if binding.frontiers().len() != realization.frontiers().len() {
        return Err(X64TailClosedImageDecodeError::InvalidField {
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
                if row(binding, frontier.row_ordinal)?.target_label == Some(block.label) {
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
                return Err(X64TailClosedImageDecodeError::InvalidField {
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
                    X64TailClosedImageDecodeError::ArithmeticOverflow {
                        field: "site layout",
                    },
                )?;
                programs.push(X64TailClosedProgramReceipt {
                    kind: X64TailClosedProgramKind::Site,
                    ordinal: site.ordinal,
                    start,
                    end: cursor,
                    atoms: to_u32(site.atoms.len(), "site atoms")?,
                });
                if !placed_sites.insert(site.ordinal) {
                    return Err(X64TailClosedImageDecodeError::InvalidField {
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
                if row(binding, frontier.row_ordinal)?.source_label == Some(block.label) {
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
        return Err(X64TailClosedImageDecodeError::InvalidField {
            field: "complete site placement",
        });
    }
    if placed_frontiers.len()
        != realization
            .frontiers()
            .iter()
            .filter(|frontier| {
                matches!(
                    frontier.disposition,
                    X64TailFrontierProgramDisposition::Operational
                )
            })
            .count()
    {
        return Err(X64TailClosedImageDecodeError::InvalidField {
            field: "complete operational frontier placement",
        });
    }
    for frontier in realization.frontiers() {
        if frontier_offsets.contains_key(&frontier.row_ordinal) {
            continue;
        }
        let (offset, owner) = match frontier.disposition {
            X64TailFrontierProgramDisposition::NoOp => {
                let row = row(binding, frontier.row_ordinal)?;
                let label = row.target_label.or(row.source_label).ok_or(
                    X64TailClosedImageDecodeError::MissingTarget {
                        field: "no-op label",
                    },
                )?;
                (
                    *label_offsets.get(&label).ok_or(
                        X64TailClosedImageDecodeError::MissingTarget {
                            field: "no-op label offset",
                        },
                    )?,
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
                    .ok_or(X64TailClosedImageDecodeError::MissingTarget {
                        field: "capsule-reference site",
                    })?;
                (program.start, frontier.row_ordinal)
            }
            X64TailFrontierProgramDisposition::EvidenceAlias { owner_ordinal } => (
                *frontier_offsets.get(&owner_ordinal).ok_or(
                    X64TailClosedImageDecodeError::MissingTarget {
                        field: "alias owner",
                    },
                )?,
                owner_ordinal,
            ),
            X64TailFrontierProgramDisposition::Operational => {
                return Err(X64TailClosedImageDecodeError::InvalidField {
                    field: "unplaced frontier",
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
    let mut terminals = Vec::new();
    for (kind, owner) in [
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
    ] {
        let label = owner_label(&target.program, owner)?;
        if label_offsets.insert(label, cursor).is_some() {
            return Err(X64TailClosedImageDecodeError::InvalidField {
                field: "terminal collision",
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
        cursor =
            cursor
                .checked_add(1)
                .ok_or(X64TailClosedImageDecodeError::ArithmeticOverflow {
                    field: "terminal layout",
                })?;
    }
    if u64::from(cursor) > X64_TAIL_CLOSED_IMAGE_MAX_CODE_BYTES {
        return Err(X64TailClosedImageDecodeError::LimitExceeded {
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
        .ok_or(X64TailClosedImageDecodeError::MissingTarget {
            field: "entry function",
        })?;
    let entry_block = entry_function
        .blocks
        .iter()
        .find(|block| block.id == entry_function.entry_block)
        .ok_or(X64TailClosedImageDecodeError::MissingTarget {
            field: "entry block",
        })?;
    let entries = realization
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
    let entry_successor = match entries.as_slice() {
        [] => X64TailBodyControlTarget::Label(entry_block.label),
        [frontier] => X64TailBodyControlTarget::Frontier(frontier.row_ordinal),
        _ => {
            return Err(X64TailClosedImageDecodeError::InvalidField {
                field: "unique entry frontier",
            })
        }
    };
    Ok(Layout {
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
) -> Result<(), X64TailClosedImageDecodeError> {
    let start = *cursor;
    *cursor = cursor.checked_add(frontier.prospective_bytes).ok_or(
        X64TailClosedImageDecodeError::ArithmeticOverflow {
            field: "frontier layout",
        },
    )?;
    if offsets.insert(frontier.row_ordinal, start).is_some() || !placed.insert(frontier.row_ordinal)
    {
        return Err(X64TailClosedImageDecodeError::InvalidField {
            field: "unique frontier",
        });
    }
    programs.push(X64TailClosedProgramReceipt {
        kind: X64TailClosedProgramKind::Frontier,
        ordinal: frontier.row_ordinal,
        start,
        end: *cursor,
        atoms: to_u32(frontier.atoms.len(), "frontier atoms")?,
    });
    frontiers.push(X64TailClosedFrontierReceipt {
        ordinal: frontier.row_ordinal,
        offset: start,
        end: *cursor,
        owner_ordinal: frontier.row_ordinal,
    });
    Ok(())
}

fn derive_cfg_edges(
    realization: &X64TailBodyFrontierRealization,
    binding: &X64TailSiteBindingProof,
    layout: &Layout,
    relocations: &[X64TailClosedRelocationReceipt],
    programs: &BTreeMap<(X64TailClosedProgramKind, u32), X64TailClosedProgramReceipt>,
) -> Result<Vec<X64TailClosedCfgEdge>, X64TailClosedImageDecodeError> {
    let mut edges = Vec::new();
    let entry = layout
        .terminals
        .iter()
        .find(|terminal| terminal.kind == X64TailClosedTerminalKind::EntryAdapter)
        .ok_or(X64TailClosedImageDecodeError::MissingTarget {
            field: "entry terminal",
        })?;
    edges.push(X64TailClosedCfgEdge {
        kind: X64TailClosedCfgEdgeKind::Entry,
        source_offset: entry.offset,
        destination: control_destination(layout, layout.entry_successor)?,
    });
    for relocation in relocations {
        edges.push(X64TailClosedCfgEdge {
            kind: X64TailClosedCfgEdgeKind::Rel32,
            source_offset: relocation.patch_offset,
            destination: control_destination(layout, relocation.target)?,
        });
        let atom = atom(
            realization,
            relocation.program_kind,
            relocation.program_ordinal,
            relocation.atom_ordinal,
        )?;
        if matches!(
            atom.instruction,
            X64TailBodyAtomInstruction::BranchNonZeroRel32 { .. }
                | X64TailBodyAtomInstruction::BoundsNegativeRel32 { .. }
                | X64TailBodyAtomInstruction::BoundsUpperRel32 { .. }
        ) {
            let program = programs
                .get(&(relocation.program_kind, relocation.program_ordinal))
                .ok_or(X64TailClosedImageDecodeError::MissingTarget {
                    field: "conditional program",
                })?;
            let end = program.start.checked_add(atom.end).ok_or(
                X64TailClosedImageDecodeError::ArithmeticOverflow {
                    field: "fallthrough",
                },
            )?;
            edges.push(X64TailClosedCfgEdge {
                kind: X64TailClosedCfgEdgeKind::ConditionalFallthrough,
                source_offset: end,
                destination: X64TailClosedCfgDestination::InstructionBoundary {
                    program_kind: relocation.program_kind,
                    program_ordinal: relocation.program_ordinal,
                    offset: end,
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
            .ok_or(X64TailClosedImageDecodeError::MissingTarget {
                field: "frontier receipt",
            })?;
        let binding_row = row(binding, frontier.row_ordinal)?;
        if frontier.placement == X64TailFrontierPlacement::BeforeLabel {
            let label =
                binding_row
                    .target_label
                    .ok_or(X64TailClosedImageDecodeError::MissingTarget {
                        field: "before-label target",
                    })?;
            edges.push(X64TailClosedCfgEdge {
                kind: X64TailClosedCfgEdgeKind::FrontierFallthrough,
                source_offset: receipt.end,
                destination: control_destination(layout, X64TailBodyControlTarget::Label(label))?,
            });
        } else if frontier.placement == X64TailFrontierPlacement::ExitStub {
            edges.push(X64TailClosedCfgEdge {
                kind: X64TailClosedCfgEdgeKind::FrontierFallthrough,
                source_offset: receipt.offset,
                destination: X64TailClosedCfgDestination::Frontier {
                    ordinal: frontier.row_ordinal,
                    offset: receipt.offset,
                },
            });
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

fn atom(
    realization: &X64TailBodyFrontierRealization,
    kind: X64TailClosedProgramKind,
    ordinal: u32,
    atom_ordinal: u32,
) -> Result<&X64TailBodyAtom, X64TailClosedImageDecodeError> {
    match kind {
        X64TailClosedProgramKind::Site => realization
            .sites()
            .iter()
            .find(|site| site.ordinal == ordinal)
            .and_then(|site| site.atoms.iter().find(|atom| atom.ordinal == atom_ordinal)),
        X64TailClosedProgramKind::Frontier => realization
            .frontiers()
            .iter()
            .find(|frontier| frontier.row_ordinal == ordinal)
            .and_then(|frontier| {
                frontier
                    .atoms
                    .iter()
                    .find(|atom| atom.ordinal == atom_ordinal)
            }),
    }
    .ok_or(X64TailClosedImageDecodeError::MissingTarget {
        field: "relocation atom",
    })
}
fn row(
    binding: &X64TailSiteBindingProof,
    ordinal: u32,
) -> Result<&X64TailFrontierBindingRow, X64TailClosedImageDecodeError> {
    binding
        .frontiers()
        .iter()
        .find(|row| row.ordinal == ordinal)
        .ok_or(X64TailClosedImageDecodeError::MissingTarget {
            field: "frontier row",
        })
}
fn owner_label(
    program: &X64TargetProgram,
    owner: X64LabelOwner,
) -> Result<X64LabelId, X64TailClosedImageDecodeError> {
    let mut labels = program.labels.iter().filter(|label| label.owner == owner);
    let label = labels
        .next()
        .ok_or(X64TailClosedImageDecodeError::MissingTarget {
            field: "terminal label",
        })?;
    if labels.next().is_some() {
        return Err(X64TailClosedImageDecodeError::InvalidField {
            field: "unique terminal label",
        });
    }
    Ok(label.id)
}
fn control_offset(
    layout: &Layout,
    target: X64TailBodyControlTarget,
) -> Result<u32, X64TailClosedImageDecodeError> {
    match target {
        X64TailBodyControlTarget::Label(label) => layout.label_offsets.get(&label),
        X64TailBodyControlTarget::Frontier(ordinal) => layout.frontier_offsets.get(&ordinal),
    }
    .copied()
    .ok_or(X64TailClosedImageDecodeError::MissingTarget {
        field: "control target",
    })
}
fn control_destination(
    layout: &Layout,
    target: X64TailBodyControlTarget,
) -> Result<X64TailClosedCfgDestination, X64TailClosedImageDecodeError> {
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
fn source_bytes(
    sources: &[X64TailClosedSourceReceipt],
    kind: X64TailClosedSourceKind,
) -> Result<u32, X64TailClosedImageDecodeError> {
    sources
        .iter()
        .filter(|source| source.source_kind == kind)
        .try_fold(0u32, |total, source| {
            total
                .checked_add(source.image_end.checked_sub(source.image_start).ok_or(
                    X64TailClosedImageDecodeError::InvalidField {
                        field: "source extent",
                    },
                )?)
                .ok_or(X64TailClosedImageDecodeError::ArithmeticOverflow {
                    field: "source bytes",
                })
        })
}
fn byte(code: &[u8], offset: u32) -> Result<u8, X64TailClosedImageDecodeError> {
    code.get(usize::try_from(offset).map_err(|_| {
        X64TailClosedImageDecodeError::ArithmeticOverflow {
            field: "byte offset",
        }
    })?)
    .copied()
    .ok_or(X64TailClosedImageDecodeError::Truncated { offset })
}
fn read_i32(code: &[u8], offset: u32) -> Result<i32, X64TailClosedImageDecodeError> {
    let start =
        usize::try_from(offset).map_err(|_| X64TailClosedImageDecodeError::ArithmeticOverflow {
            field: "rel32 offset",
        })?;
    let end = start
        .checked_add(4)
        .ok_or(X64TailClosedImageDecodeError::ArithmeticOverflow { field: "rel32 end" })?;
    let bytes: [u8; 4] = code
        .get(start..end)
        .ok_or(X64TailClosedImageDecodeError::Truncated { offset })?
        .try_into()
        .map_err(|_| X64TailClosedImageDecodeError::Truncated { offset })?;
    Ok(i32::from_le_bytes(bytes))
}
fn ensure_limit(
    field: &'static str,
    limit: u32,
    actual: usize,
) -> Result<(), X64TailClosedImageDecodeError> {
    if actual as u64 > u64::from(limit) {
        Err(X64TailClosedImageDecodeError::LimitExceeded {
            field,
            limit: u64::from(limit),
            actual: actual as u64,
        })
    } else {
        Ok(())
    }
}
fn to_u32(value: usize, field: &'static str) -> Result<u32, X64TailClosedImageDecodeError> {
    u32::try_from(value).map_err(|_| X64TailClosedImageDecodeError::ArithmeticOverflow { field })
}
fn charge(work: u64, amount: u64) -> Result<u64, X64TailClosedImageDecodeError> {
    let work =
        work.checked_add(amount)
            .ok_or(X64TailClosedImageDecodeError::ArithmeticOverflow {
                field: "decode work",
            })?;
    if work > X64_TAIL_CLOSED_IMAGE_MAX_WORK {
        return Err(X64TailClosedImageDecodeError::LimitExceeded {
            field: "decode work",
            limit: X64_TAIL_CLOSED_IMAGE_MAX_WORK,
            actual: work,
        });
    }
    Ok(work)
}
fn cfg_tag(kind: X64TailClosedCfgEdgeKind) -> u8 {
    match kind {
        X64TailClosedCfgEdgeKind::Entry => 0,
        X64TailClosedCfgEdgeKind::FrontierFallthrough => 1,
        X64TailClosedCfgEdgeKind::ConditionalFallthrough => 2,
        X64TailClosedCfgEdgeKind::Rel32 => 3,
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
        } => (
            2,
            match program_kind {
                X64TailClosedProgramKind::Site => 0,
                X64TailClosedProgramKind::Frontier => 1,
            },
            program_ordinal,
            offset,
        ),
    }
}
