//! Independent bounded decoder for the ADR-0060 tail-template capsule.
//!
//! This module deliberately contains no opcode emission helper. It derives
//! layout from verified ADR-0059 evidence, parses candidate bytes forward,
//! resolves rel32 destinations against independently placed trap anchors, and
//! only then binds type-erased machine shapes to typed predecessor atoms.

use super::x64_tail_template_realization::{
    X64TailTemplateAtom, X64TailTemplateGpr, X64TailTemplateInstruction,
    X64TailTemplateRealization, X64TailTemplateRegister, X64TailTemplateXmm,
};
use super::x64_target::{X64LabelId, X64TargetArtifact};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const X64_TAIL_CANDIDATE_DECODER_POLICY_VERSION: (u16, u16, u16) = (1, 1, 0);
pub const X64_TAIL_CANDIDATE_MAX_DECODE_WORK: u64 = 2_000_000;
pub const X64_TAIL_CANDIDATE_MAX_CODE_BYTES: usize = 65 * 1024 * 1024;
pub const X64_TAIL_CANDIDATE_MAX_ANCHORS: usize = 4_096;
pub const X64_TAIL_CANDIDATE_MAX_DECODED_ATOMS: usize = 65_536;

const TARGET_ANCHOR_BYTE: u8 = 0xcc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailDecodedInstruction {
    GprCopy {
        source: X64TailTemplateGpr,
        destination: X64TailTemplateGpr,
    },
    GprFrameLoad {
        source_offset: u32,
        destination: X64TailTemplateGpr,
    },
    GprFrameStore {
        source: X64TailTemplateGpr,
        destination_offset: u32,
    },
    XmmCopy {
        source: X64TailTemplateXmm,
        destination: X64TailTemplateXmm,
    },
    XmmFrameLoad {
        source_offset: u32,
        destination: X64TailTemplateXmm,
    },
    XmmFrameStore {
        source: X64TailTemplateXmm,
        destination_offset: u32,
    },
    GprImmediate {
        bits: u64,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailDecodedAtom {
    pub ordinal: u32,
    pub start: u32,
    pub end: u32,
    pub instruction: X64TailDecodedInstruction,
    pub clobbers: Vec<X64TailTemplateRegister>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailDecodedTransition {
    pub edge_ordinal: u32,
    pub start: u32,
    pub end: u32,
    pub atoms: Vec<X64TailDecodedAtom>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailDecodedAnchor {
    pub label: X64LabelId,
    pub offset: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailDecodedFixup {
    pub edge_ordinal: u32,
    pub atom_ordinal: u32,
    pub patch_offset: u32,
    pub target: X64LabelId,
    pub target_offset: u32,
    pub displacement: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailDecodedCapsule {
    pub transitions: Vec<X64TailDecodedTransition>,
    pub anchors: Vec<X64TailDecodedAnchor>,
    pub fixups: Vec<X64TailDecodedFixup>,
    pub transition_bytes: u32,
    pub code_bytes: u32,
    pub decoded_atoms: u32,
    pub decode_work: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailCandidateDecodeError {
    InvalidField {
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
    UnknownOpcode {
        offset: u32,
    },
    NonCanonical {
        offset: u32,
        field: &'static str,
    },
    UnknownRegister {
        offset: u32,
    },
    UnknownJumpTarget {
        offset: u32,
    },
    TemplateMismatch {
        edge: u32,
        atom: u32,
    },
}

impl fmt::Display for X64TailCandidateDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField { field } => {
                write!(formatter, "candidate decoder has invalid {field}")
            }
            Self::LimitExceeded {
                field,
                limit,
                actual,
            } => write!(
                formatter,
                "candidate decoder {field} uses {actual}; limit is {limit}"
            ),
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "candidate decoder overflowed {field}")
            }
            Self::Truncated { offset } => write!(formatter, "candidate bytes truncate at {offset}"),
            Self::UnknownOpcode { offset } => {
                write!(formatter, "candidate opcode at {offset} is not admitted")
            }
            Self::NonCanonical { offset, field } => write!(
                formatter,
                "candidate encoding at {offset} has noncanonical {field}"
            ),
            Self::UnknownRegister { offset } => write!(
                formatter,
                "candidate encoding at {offset} names an unowned register"
            ),
            Self::UnknownJumpTarget { offset } => write!(
                formatter,
                "candidate rel32 at {offset} does not resolve to a canonical anchor"
            ),
            Self::TemplateMismatch { edge, atom } => write!(
                formatter,
                "candidate edge {edge} atom {atom} differs from ADR-0059"
            ),
        }
    }
}

impl std::error::Error for X64TailCandidateDecodeError {}

/// Decode and bind candidate bytes without consulting encoder receipts.
pub fn decode_x64_tail_candidate_bytes(
    code: &[u8],
    realization: &X64TailTemplateRealization,
    target: &X64TargetArtifact,
) -> Result<X64TailDecodedCapsule, X64TailCandidateDecodeError> {
    if code.len() > X64_TAIL_CANDIDATE_MAX_CODE_BYTES {
        return Err(X64TailCandidateDecodeError::LimitExceeded {
            field: "code bytes",
            limit: usize_to_u64(X64_TAIL_CANDIDATE_MAX_CODE_BYTES, "code byte limit")?,
            actual: usize_to_u64(code.len(), "code bytes")?,
        });
    }
    let mut transition_bytes = 0u32;
    let mut previous_edge = None;
    for transition in realization.transitions() {
        if previous_edge.is_some_and(|previous| previous >= transition.edge_ordinal) {
            return Err(X64TailCandidateDecodeError::InvalidField {
                field: "transition order",
            });
        }
        previous_edge = Some(transition.edge_ordinal);
        transition_bytes = transition_bytes
            .checked_add(transition.layout_bytes)
            .ok_or(X64TailCandidateDecodeError::ArithmeticOverflow {
                field: "transition bytes",
            })?;
    }

    let target_labels = realization
        .transitions()
        .iter()
        .map(|transition| transition.target_label)
        .collect::<BTreeSet<_>>();
    if target_labels.len() > X64_TAIL_CANDIDATE_MAX_ANCHORS {
        return Err(X64TailCandidateDecodeError::LimitExceeded {
            field: "target anchors",
            limit: usize_to_u64(X64_TAIL_CANDIDATE_MAX_ANCHORS, "target anchor limit")?,
            actual: usize_to_u64(target_labels.len(), "target anchors")?,
        });
    }
    let mut anchors = Vec::with_capacity(target_labels.len());
    let mut anchor_by_offset = BTreeMap::new();
    let mut anchor_cursor = transition_bytes;
    for label in target_labels {
        if !target
            .program
            .labels
            .iter()
            .any(|candidate| candidate.id == label)
        {
            return Err(X64TailCandidateDecodeError::InvalidField {
                field: "target anchor label",
            });
        }
        let anchor = X64TailDecodedAnchor {
            label,
            offset: anchor_cursor,
        };
        anchors.push(anchor);
        if anchor_by_offset.insert(anchor_cursor, label).is_some() {
            return Err(X64TailCandidateDecodeError::InvalidField {
                field: "target anchor offset",
            });
        }
        anchor_cursor = anchor_cursor.checked_add(1).ok_or(
            X64TailCandidateDecodeError::ArithmeticOverflow {
                field: "anchor end",
            },
        )?;
    }
    let expected_len = usize::try_from(anchor_cursor).map_err(|_| {
        X64TailCandidateDecodeError::ArithmeticOverflow {
            field: "capsule code length",
        }
    })?;
    if code.len() != expected_len {
        return Err(X64TailCandidateDecodeError::InvalidField {
            field: "exact capsule code length",
        });
    }
    for anchor in &anchors {
        let offset = usize::try_from(anchor.offset).map_err(|_| {
            X64TailCandidateDecodeError::ArithmeticOverflow {
                field: "anchor offset",
            }
        })?;
        if code[offset] != TARGET_ANCHOR_BYTE {
            return Err(X64TailCandidateDecodeError::NonCanonical {
                offset: anchor.offset,
                field: "target anchor",
            });
        }
    }

    let mut transitions = Vec::with_capacity(realization.transitions().len());
    let mut fixups = Vec::with_capacity(realization.transitions().len());
    let mut global_cursor = 0u32;
    let mut decoded_atom_count = 0usize;
    let mut decode_work = 0u64;
    for expected_transition in realization.transitions() {
        let start = global_cursor;
        let end = start.checked_add(expected_transition.layout_bytes).ok_or(
            X64TailCandidateDecodeError::ArithmeticOverflow {
                field: "decoded transition end",
            },
        )?;
        let mut local_cursor = 0u32;
        let mut atoms = Vec::new();
        while local_cursor < expected_transition.layout_bytes {
            let global = start.checked_add(local_cursor).ok_or(
                X64TailCandidateDecodeError::ArithmeticOverflow {
                    field: "decoded atom offset",
                },
            )?;
            let (instruction, byte_len, maybe_fixup) = decode_one(
                code,
                global,
                &anchor_by_offset,
                expected_transition.edge_ordinal,
            )?;
            let atom_end = local_cursor.checked_add(byte_len).ok_or(
                X64TailCandidateDecodeError::ArithmeticOverflow {
                    field: "decoded atom end",
                },
            )?;
            if atom_end > expected_transition.layout_bytes {
                return Err(X64TailCandidateDecodeError::Truncated { offset: global });
            }
            let ordinal = usize_to_u32(atoms.len(), "decoded atom ordinal")?;
            if let Some((target, target_offset, displacement)) = maybe_fixup {
                fixups.push(X64TailDecodedFixup {
                    edge_ordinal: expected_transition.edge_ordinal,
                    atom_ordinal: ordinal,
                    patch_offset: global.checked_add(1).ok_or(
                        X64TailCandidateDecodeError::ArithmeticOverflow {
                            field: "decoded patch offset",
                        },
                    )?,
                    target,
                    target_offset,
                    displacement,
                });
            }
            atoms.push(X64TailDecodedAtom {
                ordinal,
                start: local_cursor,
                end: atom_end,
                instruction,
                clobbers: decoded_clobbers(instruction),
            });
            local_cursor = atom_end;
            decoded_atom_count = decoded_atom_count.checked_add(1).ok_or(
                X64TailCandidateDecodeError::ArithmeticOverflow {
                    field: "decoded atom count",
                },
            )?;
            if decoded_atom_count > X64_TAIL_CANDIDATE_MAX_DECODED_ATOMS {
                return Err(X64TailCandidateDecodeError::LimitExceeded {
                    field: "decoded atoms",
                    limit: usize_to_u64(
                        X64_TAIL_CANDIDATE_MAX_DECODED_ATOMS,
                        "decoded atom limit",
                    )?,
                    actual: usize_to_u64(decoded_atom_count, "decoded atoms")?,
                });
            }
            let atom_work = u64::from(byte_len).checked_add(1).ok_or(
                X64TailCandidateDecodeError::ArithmeticOverflow {
                    field: "decoded atom work",
                },
            )?;
            decode_work = decode_work.checked_add(atom_work).ok_or(
                X64TailCandidateDecodeError::ArithmeticOverflow {
                    field: "decode work",
                },
            )?;
        }
        bind_transition(
            &atoms,
            &expected_transition.atoms,
            expected_transition.edge_ordinal,
        )?;
        transitions.push(X64TailDecodedTransition {
            edge_ordinal: expected_transition.edge_ordinal,
            start,
            end,
            atoms,
        });
        global_cursor = end;
    }
    if global_cursor != transition_bytes {
        return Err(X64TailCandidateDecodeError::InvalidField {
            field: "transition byte coverage",
        });
    }
    decode_work = decode_work
        .checked_add(usize_to_u64(anchors.len(), "anchor work")?)
        .ok_or(X64TailCandidateDecodeError::ArithmeticOverflow {
            field: "decode work",
        })?;
    if decode_work > X64_TAIL_CANDIDATE_MAX_DECODE_WORK {
        return Err(X64TailCandidateDecodeError::LimitExceeded {
            field: "decode work",
            limit: X64_TAIL_CANDIDATE_MAX_DECODE_WORK,
            actual: decode_work,
        });
    }
    Ok(X64TailDecodedCapsule {
        transitions,
        anchors,
        fixups,
        transition_bytes,
        code_bytes: anchor_cursor,
        decoded_atoms: usize_to_u32(decoded_atom_count, "decoded atom total")?,
        decode_work,
    })
}

type DecodeOne = (
    X64TailDecodedInstruction,
    u32,
    Option<(X64LabelId, u32, i32)>,
);

fn decode_one(
    code: &[u8],
    offset: u32,
    anchors: &BTreeMap<u32, X64LabelId>,
    _edge: u32,
) -> Result<DecodeOne, X64TailCandidateDecodeError> {
    let cursor =
        usize::try_from(offset).map_err(|_| X64TailCandidateDecodeError::ArithmeticOverflow {
            field: "decoder cursor",
        })?;
    let first = *code
        .get(cursor)
        .ok_or(X64TailCandidateDecodeError::Truncated { offset })?;
    match first {
        0xe9 => {
            let bytes = read_exact::<5>(code, cursor, offset)?;
            let displacement = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            let next = i64::from(offset) + 5;
            let target_i64 = next + i64::from(displacement);
            let target_offset = u32::try_from(target_i64)
                .map_err(|_| X64TailCandidateDecodeError::UnknownJumpTarget { offset })?;
            let target = anchors
                .get(&target_offset)
                .copied()
                .ok_or(X64TailCandidateDecodeError::UnknownJumpTarget { offset })?;
            Ok((
                X64TailDecodedInstruction::TailJumpRel32 { target },
                5,
                Some((target, target_offset, displacement)),
            ))
        }
        0xf2 => decode_xmm(code, cursor, offset),
        0x66 => decode_gpr_bits_to_xmm(code, cursor, offset),
        0x48..=0x4d => decode_gpr(code, cursor, offset),
        _ => Err(X64TailCandidateDecodeError::UnknownOpcode { offset }),
    }
}

fn decode_gpr(
    code: &[u8],
    cursor: usize,
    offset: u32,
) -> Result<DecodeOne, X64TailCandidateDecodeError> {
    let header = read_exact::<3>(code, cursor, offset)?;
    let rex = header[0];
    if !matches!(rex, 0x48 | 0x49 | 0x4c | 0x4d) {
        return Err(X64TailCandidateDecodeError::NonCanonical {
            offset,
            field: "GPR REX",
        });
    }
    let rex_r = u8::from(rex & 0x04 != 0);
    let rex_b = u8::from(rex & 0x01 != 0);
    let opcode = header[1];
    if (0xb8..=0xbf).contains(&opcode) {
        if rex_r != 0 {
            return Err(X64TailCandidateDecodeError::NonCanonical {
                offset,
                field: "movabs REX.R",
            });
        }
        let bytes = read_exact::<10>(code, cursor, offset)?;
        let number = (opcode - 0xb8) | (rex_b << 3);
        let destination = decode_gpr_number(number, offset)?;
        let bits = u64::from_le_bytes(bytes[2..10].try_into().expect("fixed slice"));
        return Ok((
            X64TailDecodedInstruction::GprImmediate { bits, destination },
            10,
            None,
        ));
    }
    let modrm = header[2];
    let mode = modrm >> 6;
    let reg_number = ((modrm >> 3) & 7) | (rex_r << 3);
    let rm_number = (modrm & 7) | (rex_b << 3);
    match (opcode, mode) {
        (0x89, 3) => {
            let source = decode_gpr_number(reg_number, offset)?;
            let destination = decode_gpr_number(rm_number, offset)?;
            if source == destination {
                return Err(X64TailCandidateDecodeError::NonCanonical {
                    offset,
                    field: "redundant GPR copy",
                });
            }
            Ok((
                X64TailDecodedInstruction::GprCopy {
                    source,
                    destination,
                },
                3,
                None,
            ))
        }
        (0x8b, 2) => {
            let bytes = read_exact::<8>(code, cursor, offset)?;
            require_rsp_disp32(bytes[2], bytes[3], rex_b, offset)?;
            let destination = decode_gpr_number(reg_number, offset)?;
            let source_offset = u32::from_le_bytes(bytes[4..8].try_into().expect("fixed slice"));
            Ok((
                X64TailDecodedInstruction::GprFrameLoad {
                    source_offset,
                    destination,
                },
                8,
                None,
            ))
        }
        (0x89, 2) => {
            let bytes = read_exact::<8>(code, cursor, offset)?;
            require_rsp_disp32(bytes[2], bytes[3], rex_b, offset)?;
            let source = decode_gpr_number(reg_number, offset)?;
            let destination_offset =
                u32::from_le_bytes(bytes[4..8].try_into().expect("fixed slice"));
            Ok((
                X64TailDecodedInstruction::GprFrameStore {
                    source,
                    destination_offset,
                },
                8,
                None,
            ))
        }
        _ => Err(X64TailCandidateDecodeError::NonCanonical {
            offset,
            field: "GPR opcode or ModR/M",
        }),
    }
}

fn decode_xmm(
    code: &[u8],
    cursor: usize,
    offset: u32,
) -> Result<DecodeOne, X64TailCandidateDecodeError> {
    let header = read_exact::<4>(code, cursor, offset)?;
    if header[1] != 0x0f || !matches!(header[2], 0x10 | 0x11) {
        return Err(X64TailCandidateDecodeError::NonCanonical {
            offset,
            field: "XMM opcode",
        });
    }
    let opcode = header[2];
    let modrm = header[3];
    let mode = modrm >> 6;
    let reg = decode_xmm_number((modrm >> 3) & 7, offset)?;
    match (opcode, mode) {
        (0x10, 3) => {
            let source = decode_xmm_number(modrm & 7, offset)?;
            if source == reg {
                return Err(X64TailCandidateDecodeError::NonCanonical {
                    offset,
                    field: "redundant XMM copy",
                });
            }
            Ok((
                X64TailDecodedInstruction::XmmCopy {
                    source,
                    destination: reg,
                },
                4,
                None,
            ))
        }
        (0x10, 2) | (0x11, 2) => {
            let bytes = read_exact::<9>(code, cursor, offset)?;
            require_rsp_disp32(bytes[3], bytes[4], 0, offset)?;
            let frame_offset = u32::from_le_bytes(bytes[5..9].try_into().expect("fixed slice"));
            let instruction = if opcode == 0x10 {
                X64TailDecodedInstruction::XmmFrameLoad {
                    source_offset: frame_offset,
                    destination: reg,
                }
            } else {
                X64TailDecodedInstruction::XmmFrameStore {
                    source: reg,
                    destination_offset: frame_offset,
                }
            };
            Ok((instruction, 9, None))
        }
        _ => Err(X64TailCandidateDecodeError::NonCanonical {
            offset,
            field: "XMM ModR/M",
        }),
    }
}

fn decode_gpr_bits_to_xmm(
    code: &[u8],
    cursor: usize,
    offset: u32,
) -> Result<DecodeOne, X64TailCandidateDecodeError> {
    let bytes = read_exact::<5>(code, cursor, offset)?;
    let rex = bytes[1];
    if !matches!(rex, 0x48 | 0x49) || bytes[2] != 0x0f || bytes[3] != 0x6e {
        return Err(X64TailCandidateDecodeError::NonCanonical {
            offset,
            field: "GPR bits to XMM prefix/opcode",
        });
    }
    let modrm = bytes[4];
    if modrm >> 6 != 3 {
        return Err(X64TailCandidateDecodeError::NonCanonical {
            offset,
            field: "GPR bits to XMM ModR/M",
        });
    }
    let destination = decode_xmm_number((modrm >> 3) & 7, offset)?;
    let source = decode_gpr_number((modrm & 7) | (u8::from(rex == 0x49) << 3), offset)?;
    Ok((
        X64TailDecodedInstruction::GprBitsToXmm {
            source,
            destination,
        },
        5,
        None,
    ))
}

fn require_rsp_disp32(
    modrm: u8,
    sib: u8,
    rex_b: u8,
    offset: u32,
) -> Result<(), X64TailCandidateDecodeError> {
    if modrm >> 6 != 2 || modrm & 7 != 4 || sib != 0x24 || rex_b != 0 {
        Err(X64TailCandidateDecodeError::NonCanonical {
            offset,
            field: "RSP disp32 address",
        })
    } else {
        Ok(())
    }
}

fn decode_gpr_number(
    number: u8,
    offset: u32,
) -> Result<X64TailTemplateGpr, X64TailCandidateDecodeError> {
    match number {
        0 => Ok(X64TailTemplateGpr::Rax),
        1 => Ok(X64TailTemplateGpr::Rcx),
        6 => Ok(X64TailTemplateGpr::Rsi),
        7 => Ok(X64TailTemplateGpr::Rdi),
        9 => Ok(X64TailTemplateGpr::R9),
        10 => Ok(X64TailTemplateGpr::R10),
        11 => Ok(X64TailTemplateGpr::R11),
        _ => Err(X64TailCandidateDecodeError::UnknownRegister { offset }),
    }
}

fn decode_xmm_number(
    number: u8,
    offset: u32,
) -> Result<X64TailTemplateXmm, X64TailCandidateDecodeError> {
    match number {
        0 => Ok(X64TailTemplateXmm::Xmm0),
        1 => Ok(X64TailTemplateXmm::Xmm1),
        3 => Ok(X64TailTemplateXmm::Xmm3),
        4 => Ok(X64TailTemplateXmm::Xmm4),
        5 => Ok(X64TailTemplateXmm::Xmm5),
        6 => Ok(X64TailTemplateXmm::Xmm6),
        7 => Ok(X64TailTemplateXmm::Xmm7),
        _ => Err(X64TailCandidateDecodeError::UnknownRegister { offset }),
    }
}

fn bind_transition(
    decoded: &[X64TailDecodedAtom],
    expected: &[X64TailTemplateAtom],
    edge: u32,
) -> Result<(), X64TailCandidateDecodeError> {
    if decoded.len() != expected.len() {
        return Err(X64TailCandidateDecodeError::TemplateMismatch {
            edge,
            atom: u32::MAX,
        });
    }
    for (decoded, expected) in decoded.iter().zip(expected) {
        if decoded.ordinal != expected.ordinal
            || decoded.start != expected.start
            || decoded.end != expected.end
            || decoded.clobbers != expected.clobbers
            || !machine_shape_matches(decoded.instruction, expected.instruction)
        {
            return Err(X64TailCandidateDecodeError::TemplateMismatch {
                edge,
                atom: expected.ordinal,
            });
        }
    }
    Ok(())
}

fn machine_shape_matches(
    decoded: X64TailDecodedInstruction,
    expected: X64TailTemplateInstruction,
) -> bool {
    match (decoded, expected) {
        (
            X64TailDecodedInstruction::GprCopy {
                source,
                destination,
            },
            X64TailTemplateInstruction::GprCopy {
                source: expected_source,
                destination: expected_destination,
                ..
            },
        ) => source == expected_source && destination == expected_destination,
        (
            X64TailDecodedInstruction::GprFrameLoad {
                source_offset,
                destination,
            },
            X64TailTemplateInstruction::GprFrameLoad {
                source,
                destination: expected_destination,
            },
        ) => source_offset == source.offset && destination == expected_destination,
        (
            X64TailDecodedInstruction::GprFrameStore {
                source,
                destination_offset,
            },
            X64TailTemplateInstruction::GprFrameStore {
                source: expected_source,
                destination,
            },
        ) => source == expected_source && destination_offset == destination.offset,
        (
            X64TailDecodedInstruction::XmmCopy {
                source,
                destination,
            },
            X64TailTemplateInstruction::XmmCopy {
                source: expected_source,
                destination: expected_destination,
            },
        ) => source == expected_source && destination == expected_destination,
        (
            X64TailDecodedInstruction::XmmFrameLoad {
                source_offset,
                destination,
            },
            X64TailTemplateInstruction::XmmFrameLoad {
                source,
                destination: expected_destination,
            },
        ) => source_offset == source.offset && destination == expected_destination,
        (
            X64TailDecodedInstruction::XmmFrameStore {
                source,
                destination_offset,
            },
            X64TailTemplateInstruction::XmmFrameStore {
                source: expected_source,
                destination,
            },
        ) => source == expected_source && destination_offset == destination.offset,
        (
            X64TailDecodedInstruction::GprImmediate { bits, destination },
            X64TailTemplateInstruction::GprImmediate {
                immediate,
                destination: expected_destination,
            },
        ) => bits == immediate_bits(immediate) && destination == expected_destination,
        (
            X64TailDecodedInstruction::GprBitsToXmm {
                source,
                destination,
            },
            X64TailTemplateInstruction::GprBitsToXmm {
                source: expected_source,
                destination: expected_destination,
            },
        ) => source == expected_source && destination == expected_destination,
        (
            X64TailDecodedInstruction::TailJumpRel32 { target },
            X64TailTemplateInstruction::TailJumpRel32 {
                target: expected_target,
            },
        ) => target == expected_target,
        _ => false,
    }
}

const fn immediate_bits(immediate: super::x64_tail_state_plan::X64TailImmediateWord) -> u64 {
    match immediate {
        super::x64_tail_state_plan::X64TailImmediateWord::Bool(value) => value as u64,
        super::x64_tail_state_plan::X64TailImmediateWord::I64(value) => value as u64,
        super::x64_tail_state_plan::X64TailImmediateWord::F64Bits(bits) => bits,
    }
}

fn decoded_clobbers(instruction: X64TailDecodedInstruction) -> Vec<X64TailTemplateRegister> {
    match instruction {
        X64TailDecodedInstruction::GprCopy { destination, .. }
        | X64TailDecodedInstruction::GprFrameLoad { destination, .. }
        | X64TailDecodedInstruction::GprImmediate { destination, .. } => {
            vec![gpr_register(destination)]
        }
        X64TailDecodedInstruction::XmmCopy { destination, .. }
        | X64TailDecodedInstruction::XmmFrameLoad { destination, .. }
        | X64TailDecodedInstruction::GprBitsToXmm { destination, .. } => {
            vec![xmm_register(destination)]
        }
        X64TailDecodedInstruction::GprFrameStore { .. }
        | X64TailDecodedInstruction::XmmFrameStore { .. }
        | X64TailDecodedInstruction::TailJumpRel32 { .. } => Vec::new(),
    }
}

const fn gpr_register(register: X64TailTemplateGpr) -> X64TailTemplateRegister {
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

const fn xmm_register(register: X64TailTemplateXmm) -> X64TailTemplateRegister {
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

fn read_exact<const N: usize>(
    code: &[u8],
    cursor: usize,
    offset: u32,
) -> Result<&[u8; N], X64TailCandidateDecodeError> {
    let end = cursor
        .checked_add(N)
        .ok_or(X64TailCandidateDecodeError::ArithmeticOverflow {
            field: "instruction read end",
        })?;
    code.get(cursor..end)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(X64TailCandidateDecodeError::Truncated { offset })
}

fn usize_to_u32(value: usize, field: &'static str) -> Result<u32, X64TailCandidateDecodeError> {
    u32::try_from(value).map_err(|_| X64TailCandidateDecodeError::ArithmeticOverflow { field })
}

fn usize_to_u64(value: usize, field: &'static str) -> Result<u64, X64TailCandidateDecodeError> {
    u64::try_from(value).map_err(|_| X64TailCandidateDecodeError::ArithmeticOverflow { field })
}
