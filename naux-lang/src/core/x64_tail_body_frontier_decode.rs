//! Independent bounded decoder for the ADR-0064 body/frontier byte capsule.
//!
//! This module contains no byte-emission helper. It derives slice and anchor
//! layout from verified ADR-0062 evidence, parses candidate bytes forward, and
//! binds recovered machine forms to the exact typed symbolic atoms. Persistent
//! transition atoms remain external references to ADR-0060 and consume no byte
//! in this capsule.

use super::x64_tail_body_frontier_realization::{
    X64TailBodyAtom, X64TailBodyAtomInstruction, X64TailBodyControlTarget,
    X64TailBodyFrontierRealization, X64TailBodyScratch,
};
use super::x64_tail_candidate_capsule::X64TailCandidateCapsule;
use super::x64_tail_site_binding::{X64TailBoundDefinition, X64TailBoundRead};
use super::x64_tail_state_allocation::{X64TailPhysicalLocation, X64TailPhysicalRegister};
use super::x64_tail_state_plan::{
    X64TailImmediateWord, X64TailScheduledSource, X64TailWordLocation, X64TailWordType,
};
use super::x64_tail_template_realization::X64TailTemplateRegister;
use super::x64_target::{X64I64Opcode, X64SetCondition, X64Sse2F64Opcode};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const X64_TAIL_BODY_DECODER_POLICY_VERSION: (u16, u16, u16) = (1, 2, 0);
pub const X64_TAIL_BODY_DECODER_MAX_CODE_BYTES: usize = 64 * 1024 * 1024;
pub const X64_TAIL_BODY_DECODER_MAX_PROGRAMS: usize = 1_032_000;
pub const X64_TAIL_BODY_DECODER_MAX_ATOMS: usize = 8_000_000;
pub const X64_TAIL_BODY_DECODER_MAX_FIXUPS: usize = 2_000_000;
pub const X64_TAIL_BODY_DECODER_MAX_REFERENCES: usize = 4_096;
pub const X64_TAIL_BODY_DECODER_MAX_ANCHORS: usize = 2_032_000;
pub const X64_TAIL_BODY_DECODER_MAX_WORK: u64 = 32_000_000;

const PROOF_ANCHOR_BYTE: u8 = 0xcc;
const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailBodyDecodedProgramKind {
    Site,
    Frontier,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailBodyDecodedAtom {
    pub ordinal: u32,
    pub start: u32,
    pub end: u32,
    pub instruction: X64TailBodyAtomInstruction,
    pub primitive_instructions: u8,
    pub clobbers: Vec<X64TailTemplateRegister>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailBodyDecodedProgram {
    pub kind: X64TailBodyDecodedProgramKind,
    pub ordinal: u32,
    pub start: u32,
    pub end: u32,
    pub atoms: Vec<X64TailBodyDecodedAtom>,
    pub external_references: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailBodyDecodedAnchor {
    pub target: X64TailBodyControlTarget,
    pub offset: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailBodyDecodedFixup {
    pub program_kind: X64TailBodyDecodedProgramKind,
    pub program_ordinal: u32,
    pub atom_ordinal: u32,
    pub patch_offset: u32,
    pub target: X64TailBodyControlTarget,
    pub target_offset: u32,
    pub displacement: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailBodyDecodedExternalReference {
    pub site_ordinal: u32,
    pub atom_ordinal: u32,
    pub edge_ordinal: u32,
    pub capsule_start: u32,
    pub capsule_end: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailBodyDecodedCapsule {
    pub programs: Vec<X64TailBodyDecodedProgram>,
    pub anchors: Vec<X64TailBodyDecodedAnchor>,
    pub fixups: Vec<X64TailBodyDecodedFixup>,
    pub external_references: Vec<X64TailBodyDecodedExternalReference>,
    pub site_bytes: u32,
    pub frontier_bytes: u32,
    pub anchor_bytes: u32,
    pub code_bytes: u32,
    pub decoded_atoms: u32,
    pub primitive_instructions: u32,
    pub retained_transition_bytes: u32,
    pub decode_work: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailBodyDecodeError {
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
    UnknownControlTarget {
        offset: u32,
    },
    AtomMismatch {
        program: u32,
        atom: u32,
    },
    ExternalReferenceMismatch {
        edge: u32,
    },
}

impl fmt::Display for X64TailBodyDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField { field } => write!(formatter, "body decoder has invalid {field}"),
            Self::LimitExceeded {
                field,
                limit,
                actual,
            } => write!(
                formatter,
                "body decoder {field} uses {actual}; limit is {limit}"
            ),
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "body decoder overflowed {field}")
            }
            Self::Truncated { offset } => write!(formatter, "body bytes truncate at {offset}"),
            Self::UnknownOpcode { offset } => {
                write!(formatter, "body opcode at {offset} is not admitted")
            }
            Self::NonCanonical { offset, field } => write!(
                formatter,
                "body encoding at {offset} has noncanonical {field}"
            ),
            Self::UnknownRegister { offset } => {
                write!(
                    formatter,
                    "body encoding at {offset} names an unowned register"
                )
            }
            Self::UnknownControlTarget { offset } => write!(
                formatter,
                "body rel32 at {offset} does not resolve to a typed proof anchor"
            ),
            Self::AtomMismatch { program, atom } => write!(
                formatter,
                "body program {program} atom {atom} differs from ADR-0062"
            ),
            Self::ExternalReferenceMismatch { edge } => write!(
                formatter,
                "body external transition reference for edge {edge} differs from ADR-0060"
            ),
        }
    }
}

impl std::error::Error for X64TailBodyDecodeError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AnchorKey {
    tag: u8,
    value: u32,
}

impl AnchorKey {
    const fn from_target(target: X64TailBodyControlTarget) -> Self {
        match target {
            X64TailBodyControlTarget::Label(label) => Self {
                tag: 0,
                value: label.0,
            },
            X64TailBodyControlTarget::Frontier(ordinal) => Self {
                tag: 1,
                value: ordinal,
            },
        }
    }

    const fn target(self) -> X64TailBodyControlTarget {
        if self.tag == 0 {
            X64TailBodyControlTarget::Label(super::x64_target::X64LabelId(self.value))
        } else {
            X64TailBodyControlTarget::Frontier(self.value)
        }
    }
}

struct DerivedLayout {
    program_bytes: u32,
    site_bytes: u32,
    frontier_bytes: u32,
    anchors: Vec<X64TailBodyDecodedAnchor>,
    target_by_offset: BTreeMap<u32, X64TailBodyControlTarget>,
    exact_code_bytes: u32,
}

/// Parse and bind ADR-0064 bytes without consulting encoder receipts.
pub fn decode_x64_tail_body_frontier_bytes(
    code: &[u8],
    realization: &X64TailBodyFrontierRealization,
    transition_capsule: &X64TailCandidateCapsule,
) -> Result<X64TailBodyDecodedCapsule, X64TailBodyDecodeError> {
    ensure_usize_limit(
        "code bytes",
        X64_TAIL_BODY_DECODER_MAX_CODE_BYTES,
        code.len(),
    )?;
    let program_count = realization
        .sites()
        .len()
        .checked_add(realization.frontiers().len())
        .ok_or(X64TailBodyDecodeError::ArithmeticOverflow {
            field: "program count",
        })?;
    ensure_usize_limit(
        "programs",
        X64_TAIL_BODY_DECODER_MAX_PROGRAMS,
        program_count,
    )?;

    let layout = derive_layout(realization)?;
    let exact_len = u32_to_usize(layout.exact_code_bytes, "exact code bytes")?;
    if code.len() != exact_len {
        return Err(X64TailBodyDecodeError::InvalidField {
            field: "exact capsule code length",
        });
    }
    for anchor in &layout.anchors {
        let offset = u32_to_usize(anchor.offset, "anchor offset")?;
        if code[offset] != PROOF_ANCHOR_BYTE {
            return Err(X64TailBodyDecodeError::NonCanonical {
                offset: anchor.offset,
                field: "typed proof anchor",
            });
        }
    }

    let mut programs = Vec::with_capacity(program_count);
    let mut fixups = Vec::new();
    let mut references = Vec::new();
    let mut cursor = 0u32;
    let mut decoded_atoms = 0u32;
    let mut primitive_instructions = 0u32;
    let mut retained_transition_bytes = 0u32;
    let mut work = 0u64;

    for site in realization.sites() {
        let decoded = decode_program(
            code,
            X64TailBodyDecodedProgramKind::Site,
            site.ordinal,
            &site.atoms,
            transition_capsule,
            &layout.target_by_offset,
            &mut cursor,
            &mut fixups,
            &mut references,
            &mut decoded_atoms,
            &mut primitive_instructions,
            &mut retained_transition_bytes,
            &mut work,
        )?;
        programs.push(decoded);
    }
    if cursor != layout.site_bytes {
        return Err(X64TailBodyDecodeError::InvalidField {
            field: "site byte coverage",
        });
    }
    for frontier in realization.frontiers() {
        let decoded = decode_program(
            code,
            X64TailBodyDecodedProgramKind::Frontier,
            frontier.row_ordinal,
            &frontier.atoms,
            transition_capsule,
            &layout.target_by_offset,
            &mut cursor,
            &mut fixups,
            &mut references,
            &mut decoded_atoms,
            &mut primitive_instructions,
            &mut retained_transition_bytes,
            &mut work,
        )?;
        programs.push(decoded);
    }
    if cursor != layout.program_bytes {
        return Err(X64TailBodyDecodeError::InvalidField {
            field: "program byte coverage",
        });
    }
    work = charge(work, usize_to_u64(layout.anchors.len(), "anchor work")?)?;
    ensure_usize_limit(
        "decoded atoms",
        X64_TAIL_BODY_DECODER_MAX_ATOMS,
        u32_to_usize(decoded_atoms, "decoded atom count")?,
    )?;
    ensure_usize_limit(
        "resolved fixups",
        X64_TAIL_BODY_DECODER_MAX_FIXUPS,
        fixups.len(),
    )?;
    ensure_usize_limit(
        "external references",
        X64_TAIL_BODY_DECODER_MAX_REFERENCES,
        references.len(),
    )?;

    Ok(X64TailBodyDecodedCapsule {
        programs,
        anchors: layout.anchors,
        fixups,
        external_references: references,
        site_bytes: layout.site_bytes,
        frontier_bytes: layout.frontier_bytes,
        anchor_bytes: layout
            .exact_code_bytes
            .checked_sub(layout.program_bytes)
            .ok_or(X64TailBodyDecodeError::ArithmeticOverflow {
                field: "anchor bytes",
            })?,
        code_bytes: layout.exact_code_bytes,
        decoded_atoms,
        primitive_instructions,
        retained_transition_bytes,
        decode_work: work,
    })
}

fn derive_layout(
    realization: &X64TailBodyFrontierRealization,
) -> Result<DerivedLayout, X64TailBodyDecodeError> {
    let mut targets = BTreeSet::new();
    let mut site_bytes = 0u32;
    let mut frontier_bytes = 0u32;
    let mut encoded_atoms = 0usize;
    let mut references = 0usize;
    for site in realization.sites() {
        derive_atoms(
            &site.atoms,
            &mut site_bytes,
            &mut encoded_atoms,
            &mut references,
            &mut targets,
        )?;
    }
    for frontier in realization.frontiers() {
        derive_atoms(
            &frontier.atoms,
            &mut frontier_bytes,
            &mut encoded_atoms,
            &mut references,
            &mut targets,
        )?;
    }
    ensure_usize_limit(
        "derived atoms",
        X64_TAIL_BODY_DECODER_MAX_ATOMS,
        encoded_atoms,
    )?;
    ensure_usize_limit(
        "derived references",
        X64_TAIL_BODY_DECODER_MAX_REFERENCES,
        references,
    )?;
    ensure_usize_limit(
        "typed anchors",
        X64_TAIL_BODY_DECODER_MAX_ANCHORS,
        targets.len(),
    )?;
    let program_bytes = site_bytes.checked_add(frontier_bytes).ok_or(
        X64TailBodyDecodeError::ArithmeticOverflow {
            field: "program bytes",
        },
    )?;
    let mut anchors = Vec::with_capacity(targets.len());
    let mut target_by_offset = BTreeMap::new();
    let mut cursor = program_bytes;
    for key in targets {
        let target = key.target();
        anchors.push(X64TailBodyDecodedAnchor {
            target,
            offset: cursor,
        });
        if target_by_offset.insert(cursor, target).is_some() {
            return Err(X64TailBodyDecodeError::InvalidField {
                field: "unique anchor offset",
            });
        }
        cursor = cursor
            .checked_add(1)
            .ok_or(X64TailBodyDecodeError::ArithmeticOverflow {
                field: "anchor layout",
            })?;
    }
    if u64::from(cursor) > usize_to_u64(X64_TAIL_BODY_DECODER_MAX_CODE_BYTES, "code limit")? {
        return Err(X64TailBodyDecodeError::LimitExceeded {
            field: "code bytes",
            limit: usize_to_u64(X64_TAIL_BODY_DECODER_MAX_CODE_BYTES, "code limit")?,
            actual: u64::from(cursor),
        });
    }
    Ok(DerivedLayout {
        program_bytes,
        site_bytes,
        frontier_bytes,
        anchors,
        target_by_offset,
        exact_code_bytes: cursor,
    })
}

fn derive_atoms(
    atoms: &[X64TailBodyAtom],
    bytes: &mut u32,
    encoded_atoms: &mut usize,
    references: &mut usize,
    targets: &mut BTreeSet<AnchorKey>,
) -> Result<(), X64TailBodyDecodeError> {
    for atom in atoms {
        if matches!(
            atom.instruction,
            X64TailBodyAtomInstruction::CapsuleTransition { .. }
        ) {
            *references =
                references
                    .checked_add(1)
                    .ok_or(X64TailBodyDecodeError::ArithmeticOverflow {
                        field: "reference count",
                    })?;
        } else {
            let length =
                atom.end
                    .checked_sub(atom.start)
                    .ok_or(X64TailBodyDecodeError::InvalidField {
                        field: "atom extent",
                    })?;
            if length > 18 {
                return Err(X64TailBodyDecodeError::LimitExceeded {
                    field: "owned atom bytes",
                    limit: 18,
                    actual: u64::from(length),
                });
            }
            *bytes =
                bytes
                    .checked_add(length)
                    .ok_or(X64TailBodyDecodeError::ArithmeticOverflow {
                        field: "owned program bytes",
                    })?;
            *encoded_atoms =
                encoded_atoms
                    .checked_add(1)
                    .ok_or(X64TailBodyDecodeError::ArithmeticOverflow {
                        field: "encoded atom count",
                    })?;
            if let Some(target) = instruction_target(atom.instruction) {
                targets.insert(AnchorKey::from_target(target));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn decode_program(
    code: &[u8],
    kind: X64TailBodyDecodedProgramKind,
    ordinal: u32,
    atoms: &[X64TailBodyAtom],
    transition_capsule: &X64TailCandidateCapsule,
    target_by_offset: &BTreeMap<u32, X64TailBodyControlTarget>,
    cursor: &mut u32,
    fixups: &mut Vec<X64TailBodyDecodedFixup>,
    references: &mut Vec<X64TailBodyDecodedExternalReference>,
    decoded_atoms: &mut u32,
    primitive_instructions: &mut u32,
    retained_transition_bytes: &mut u32,
    work: &mut u64,
) -> Result<X64TailBodyDecodedProgram, X64TailBodyDecodeError> {
    let start = *cursor;
    let mut decoded = Vec::new();
    let mut external_count = 0u32;
    for atom in atoms {
        if let X64TailBodyAtomInstruction::CapsuleTransition {
            edge_ordinal,
            capsule_start,
            capsule_end,
        } = atom.instruction
        {
            if kind != X64TailBodyDecodedProgramKind::Site {
                return Err(X64TailBodyDecodeError::InvalidField {
                    field: "frontier external transition",
                });
            }
            let receipt = transition_capsule
                .transition_receipts()
                .iter()
                .find(|candidate| candidate.edge_ordinal == edge_ordinal)
                .ok_or(X64TailBodyDecodeError::ExternalReferenceMismatch { edge: edge_ordinal })?;
            if receipt.start != capsule_start || receipt.end != capsule_end {
                return Err(X64TailBodyDecodeError::ExternalReferenceMismatch {
                    edge: edge_ordinal,
                });
            }
            references.push(X64TailBodyDecodedExternalReference {
                site_ordinal: ordinal,
                atom_ordinal: atom.ordinal,
                edge_ordinal,
                capsule_start,
                capsule_end,
            });
            external_count = external_count.checked_add(1).ok_or(
                X64TailBodyDecodeError::ArithmeticOverflow {
                    field: "program reference count",
                },
            )?;
            let retained = capsule_end.checked_sub(capsule_start).ok_or(
                X64TailBodyDecodeError::InvalidField {
                    field: "external transition extent",
                },
            )?;
            *retained_transition_bytes = retained_transition_bytes.checked_add(retained).ok_or(
                X64TailBodyDecodeError::ArithmeticOverflow {
                    field: "retained transition bytes",
                },
            )?;
            *work = charge(*work, 1)?;
            continue;
        }

        let atom_start = *cursor;
        let expected_length =
            atom.end
                .checked_sub(atom.start)
                .ok_or(X64TailBodyDecodeError::InvalidField {
                    field: "decoded atom extent",
                })?;
        let (primitive_count, maybe_fixup) =
            decode_atom(code, atom_start, atom, target_by_offset, ordinal)?;
        let atom_end = atom_start.checked_add(expected_length).ok_or(
            X64TailBodyDecodeError::ArithmeticOverflow {
                field: "decoded atom end",
            },
        )?;
        if let Some((patch_offset, target, target_offset, displacement)) = maybe_fixup {
            fixups.push(X64TailBodyDecodedFixup {
                program_kind: kind,
                program_ordinal: ordinal,
                atom_ordinal: atom.ordinal,
                patch_offset,
                target,
                target_offset,
                displacement,
            });
        }
        decoded.push(X64TailBodyDecodedAtom {
            ordinal: atom.ordinal,
            start: atom_start,
            end: atom_end,
            instruction: atom.instruction,
            primitive_instructions: primitive_count,
            clobbers: decoded_clobbers(atom.instruction),
        });
        *cursor = atom_end;
        *decoded_atoms =
            decoded_atoms
                .checked_add(1)
                .ok_or(X64TailBodyDecodeError::ArithmeticOverflow {
                    field: "decoded atom count",
                })?;
        *primitive_instructions = primitive_instructions
            .checked_add(u32::from(primitive_count))
            .ok_or(X64TailBodyDecodeError::ArithmeticOverflow {
                field: "primitive instruction count",
            })?;
        *work = charge(
            *work,
            u64::from(expected_length).checked_add(1).ok_or(
                X64TailBodyDecodeError::ArithmeticOverflow {
                    field: "decode work",
                },
            )?,
        )?;
    }
    Ok(X64TailBodyDecodedProgram {
        kind,
        ordinal,
        start,
        end: *cursor,
        atoms: decoded,
        external_references: external_count,
    })
}

type DecodedFixup = Option<(u32, X64TailBodyControlTarget, u32, i32)>;

fn decode_atom(
    code: &[u8],
    offset: u32,
    atom: &X64TailBodyAtom,
    targets: &BTreeMap<u32, X64TailBodyControlTarget>,
    program: u32,
) -> Result<(u8, DecodedFixup), X64TailBodyDecodeError> {
    let mismatch = || X64TailBodyDecodeError::AtomMismatch {
        program,
        atom: atom.ordinal,
    };
    match atom.instruction {
        X64TailBodyAtomInstruction::Acquire { read, destination } => match read {
            X64TailBoundRead::Immediate(immediate) => {
                let bits = immediate_bits(immediate);
                if scratch_gpr(destination).is_some() {
                    let (register, actual, length) = decode_movabs(code, offset)?;
                    if register != scratch_gpr(destination).ok_or_else(mismatch)?
                        || actual != bits
                        || length != atom_len(atom)?
                    {
                        return Err(mismatch());
                    }
                    Ok((1, None))
                } else {
                    let (register, actual, first) = decode_movabs(code, offset)?;
                    let second_offset = checked_add_u32(offset, first, "movq offset")?;
                    let (source, destination_register, second) =
                        decode_gpr_to_xmm(code, second_offset)?;
                    if register != 0
                        || source != 0
                        || destination_register != scratch_xmm(destination).ok_or_else(mismatch)?
                        || actual != bits
                        || checked_add_u32(first, second, "F64 immediate length")?
                            != atom_len(atom)?
                    {
                        return Err(mismatch());
                    }
                    Ok((2, None))
                }
            }
            X64TailBoundRead::Location { physical, .. } => {
                decode_acquire_location(code, offset, physical, destination, atom, mismatch)
            }
        },
        X64TailBodyAtomInstruction::Define { source, definition } => {
            decode_definition(code, offset, source, definition, atom, mismatch)
        }
        X64TailBodyAtomInstruction::I64Wrapping { opcode, .. } => {
            let expected: &[u8] = match opcode {
                X64I64Opcode::Add => &[0x48, 0x01, 0xc8],
                X64I64Opcode::Sub => &[0x48, 0x29, 0xc8],
                X64I64Opcode::Mul => &[0x48, 0x0f, 0xaf, 0xc1],
            };
            expect_exact(code, offset, expected)?;
            ensure_expected_len(atom, expected.len(), program)?;
            Ok((1, None))
        }
        X64TailBodyAtomInstruction::Sse2F64 { opcode, .. } => {
            let opcode = match opcode {
                X64Sse2F64Opcode::AddSd => 0x58,
                X64Sse2F64Opcode::SubSd => 0x5c,
            };
            let bytes = read_exact::<4>(code, offset)?;
            if bytes != [0xf2, 0x0f, opcode, 0xc1] {
                return Err(mismatch());
            }
            ensure_expected_len(atom, 4, program)?;
            Ok((1, None))
        }
        X64TailBodyAtomInstruction::I64Setcc { condition, .. } => {
            let setcc = match condition {
                X64SetCondition::SignedLessThan => 0x9c,
                X64SetCondition::SignedGreaterOrEqual => 0x9d,
            };
            let bytes = read_exact::<10>(code, offset)?;
            if bytes != [0x48, 0x39, 0xc8, 0x0f, setcc, 0xc0, 0x48, 0x0f, 0xb6, 0xc0] {
                return Err(mismatch());
            }
            ensure_expected_len(atom, 10, program)?;
            Ok((3, None))
        }
        X64TailBodyAtomInstruction::TestBool => {
            expect_exact(code, offset, &[0x48, 0x85, 0xc0])?;
            ensure_expected_len(atom, 3, program)?;
            Ok((1, None))
        }
        X64TailBodyAtomInstruction::BranchNonZeroRel32 { target } => {
            let fixup = decode_rel32(code, offset, &[0x0f, 0x85], 2, 6, target, targets)?;
            ensure_expected_len(atom, 6, program)?;
            Ok((1, Some(fixup)))
        }
        X64TailBodyAtomInstruction::JumpRel32 { target } => {
            let fixup = decode_rel32(code, offset, &[0xe9], 1, 5, target, targets)?;
            ensure_expected_len(atom, 5, program)?;
            Ok((1, Some(fixup)))
        }
        X64TailBodyAtomInstruction::BoundsNegativeRel32 { target } => {
            expect_exact(code, offset, &[0x48, 0x85, 0xd2])?;
            let branch = checked_add_u32(offset, 3, "negative branch offset")?;
            let fixup = decode_rel32(code, branch, &[0x0f, 0x88], 2, 6, target, targets)?;
            ensure_expected_len(atom, 9, program)?;
            Ok((2, Some(fixup)))
        }
        X64TailBodyAtomInstruction::BoundsUpperRel32 { target } => {
            expect_exact(code, offset, &[0x48, 0x39, 0xca])?;
            let branch = checked_add_u32(offset, 3, "upper branch offset")?;
            let fixup = decode_rel32(code, branch, &[0x0f, 0x83], 2, 6, target, targets)?;
            ensure_expected_len(atom, 9, program)?;
            Ok((2, Some(fixup)))
        }
        X64TailBodyAtomInstruction::ArrayGetF64 { .. } => {
            expect_exact(code, offset, &[0xf2, 0x0f, 0x10, 0x04, 0xd0])?;
            ensure_expected_len(atom, 5, program)?;
            Ok((1, None))
        }
        X64TailBodyAtomInstruction::AdapterFlush { word } => decode_adapter(
            code,
            offset,
            word.logical,
            word.register,
            true,
            atom,
            mismatch,
        ),
        X64TailBodyAtomInstruction::AdapterHydrate { word } => decode_adapter(
            code,
            offset,
            word.logical,
            word.register,
            false,
            atom,
            mismatch,
        ),
        X64TailBodyAtomInstruction::FrameScratchSave { source, .. } => {
            if source.word_type == X64TailWordType::F64 {
                let (frame, destination, length) = decode_xmm_frame_load(code, offset)?;
                if frame != source.offset || destination != 0 || length != atom_len(atom)? {
                    return Err(mismatch());
                }
            } else {
                let (frame, destination, length) = decode_gpr_frame_load(code, offset)?;
                if frame != source.offset || destination != 0 || length != atom_len(atom)? {
                    return Err(mismatch());
                }
            }
            Ok((1, None))
        }
        X64TailBodyAtomInstruction::FrameMove {
            source,
            destination,
        } => decode_frame_move(code, offset, source, destination, atom, mismatch),
        X64TailBodyAtomInstruction::ReturnWord {
            source,
            destination,
        } => decode_return_word(code, offset, source, destination, atom, mismatch),
        X64TailBodyAtomInstruction::MoveReturnF64BitsToXmm0 => {
            expect_exact(code, offset, &[0x66, 0x48, 0x0f, 0x6e, 0xc0])?;
            ensure_expected_len(atom, 5, program)?;
            Ok((1, None))
        }
        X64TailBodyAtomInstruction::CanonicalizeReturnF64 => {
            let mut expected = vec![0x66, 0x0f, 0x2e, 0xc0, 0x48, 0xb9];
            expected.extend_from_slice(&CANONICAL_NAN_BITS.to_le_bytes());
            expected.extend_from_slice(&[0x48, 0x0f, 0x4a, 0xc1]);
            expect_exact(code, offset, &expected)?;
            ensure_expected_len(atom, expected.len(), program)?;
            Ok((3, None))
        }
        X64TailBodyAtomInstruction::CapsuleTransition { .. } => {
            Err(X64TailBodyDecodeError::InvalidField {
                field: "byte-backed capsule transition",
            })
        }
    }
}

fn decode_acquire_location(
    code: &[u8],
    offset: u32,
    physical: X64TailPhysicalLocation,
    destination: X64TailBodyScratch,
    atom: &X64TailBodyAtom,
    mismatch: impl Fn() -> X64TailBodyDecodeError,
) -> Result<(u8, DecodedFixup), X64TailBodyDecodeError> {
    match physical {
        X64TailPhysicalLocation::Register { register, .. } => {
            if let (Some(source), Some(destination)) =
                (physical_gpr(register), scratch_gpr(destination))
            {
                let (actual_source, actual_destination, length) = decode_gpr_copy(code, offset)?;
                if (actual_source, actual_destination, length)
                    != (source, destination, atom_len(atom)?)
                {
                    return Err(mismatch());
                }
            } else if let (Some(source), Some(destination)) =
                (physical_xmm(register), scratch_xmm(destination))
            {
                let (actual_source, actual_destination, length) = decode_xmm_copy(code, offset)?;
                if (actual_source, actual_destination, length)
                    != (source, destination, atom_len(atom)?)
                {
                    return Err(mismatch());
                }
            } else {
                return Err(mismatch());
            }
        }
        X64TailPhysicalLocation::Frame(frame) => {
            if let Some(destination) = scratch_gpr(destination) {
                let (actual_frame, actual_destination, length) =
                    decode_gpr_frame_load(code, offset)?;
                if (actual_frame, actual_destination, length)
                    != (frame.offset, destination, atom_len(atom)?)
                {
                    return Err(mismatch());
                }
            } else if let Some(destination) = scratch_xmm(destination) {
                let (actual_frame, actual_destination, length) =
                    decode_xmm_frame_load(code, offset)?;
                if (actual_frame, actual_destination, length)
                    != (frame.offset, destination, atom_len(atom)?)
                {
                    return Err(mismatch());
                }
            } else {
                return Err(mismatch());
            }
        }
    }
    Ok((1, None))
}

fn decode_definition(
    code: &[u8],
    offset: u32,
    source: X64TailBodyScratch,
    definition: X64TailBoundDefinition,
    atom: &X64TailBodyAtom,
    mismatch: impl Fn() -> X64TailBodyDecodeError,
) -> Result<(u8, DecodedFixup), X64TailBodyDecodeError> {
    match definition.physical {
        X64TailPhysicalLocation::Register { register, .. } => {
            if let (Some(source), Some(destination)) = (scratch_gpr(source), physical_gpr(register))
            {
                let decoded = decode_gpr_copy(code, offset)?;
                if decoded != (source, destination, atom_len(atom)?) {
                    return Err(mismatch());
                }
            } else if let (Some(source), Some(destination)) =
                (scratch_xmm(source), physical_xmm(register))
            {
                let decoded = decode_xmm_copy(code, offset)?;
                if decoded != (source, destination, atom_len(atom)?) {
                    return Err(mismatch());
                }
            } else {
                return Err(mismatch());
            }
        }
        X64TailPhysicalLocation::Frame(frame) => {
            if let Some(source) = scratch_gpr(source) {
                let decoded = decode_gpr_frame_store(code, offset)?;
                if decoded != (source, frame.offset, atom_len(atom)?) {
                    return Err(mismatch());
                }
            } else if let Some(source) = scratch_xmm(source) {
                let decoded = decode_xmm_frame_store(code, offset)?;
                if decoded != (source, frame.offset, atom_len(atom)?) {
                    return Err(mismatch());
                }
            } else {
                return Err(mismatch());
            }
        }
    }
    Ok((1, None))
}

fn decode_adapter(
    code: &[u8],
    offset: u32,
    logical: X64TailWordLocation,
    register: X64TailPhysicalRegister,
    flush: bool,
    atom: &X64TailBodyAtom,
    mismatch: impl Fn() -> X64TailBodyDecodeError,
) -> Result<(u8, DecodedFixup), X64TailBodyDecodeError> {
    if let Some(register) = physical_gpr(register) {
        let valid = if flush {
            let (source, frame, length) = decode_gpr_frame_store(code, offset)?;
            (source, frame, length) == (register, logical.offset, atom_len(atom)?)
        } else {
            let (frame, destination, length) = decode_gpr_frame_load(code, offset)?;
            (frame, destination, length) == (logical.offset, register, atom_len(atom)?)
        };
        if !valid {
            return Err(mismatch());
        }
    } else if let Some(register) = physical_xmm(register) {
        let valid = if flush {
            let (source, frame, length) = decode_xmm_frame_store(code, offset)?;
            (source, frame, length) == (register, logical.offset, atom_len(atom)?)
        } else {
            let (frame, destination, length) = decode_xmm_frame_load(code, offset)?;
            (frame, destination, length) == (logical.offset, register, atom_len(atom)?)
        };
        if !valid {
            return Err(mismatch());
        }
    } else {
        return Err(mismatch());
    }
    Ok((1, None))
}

fn decode_frame_move(
    code: &[u8],
    offset: u32,
    source: X64TailScheduledSource,
    destination: X64TailWordLocation,
    atom: &X64TailBodyAtom,
    mismatch: impl Fn() -> X64TailBodyDecodeError,
) -> Result<(u8, DecodedFixup), X64TailBodyDecodeError> {
    match source {
        X64TailScheduledSource::Location(source) => {
            if source.word_type == X64TailWordType::F64 {
                let (frame, register, first) = decode_xmm_frame_load(code, offset)?;
                let second_offset = checked_add_u32(offset, first, "frame move store")?;
                let (stored, target, second) = decode_xmm_frame_store(code, second_offset)?;
                if frame != source.offset
                    || register != 1
                    || stored != 1
                    || target != destination.offset
                    || checked_add_u32(first, second, "frame move length")? != atom_len(atom)?
                {
                    return Err(mismatch());
                }
            } else {
                let (frame, register, first) = decode_gpr_frame_load(code, offset)?;
                let second_offset = checked_add_u32(offset, first, "frame move store")?;
                let (stored, target, second) = decode_gpr_frame_store(code, second_offset)?;
                if frame != source.offset
                    || register != 1
                    || stored != 1
                    || target != destination.offset
                    || checked_add_u32(first, second, "frame move length")? != atom_len(atom)?
                {
                    return Err(mismatch());
                }
            }
            Ok((2, None))
        }
        X64TailScheduledSource::Immediate(immediate) => {
            let (register, bits, first) = decode_movabs(code, offset)?;
            let second_offset = checked_add_u32(offset, first, "immediate frame store")?;
            let (stored, target, second) = decode_gpr_frame_store(code, second_offset)?;
            if register != 1
                || stored != 1
                || bits != immediate_bits(immediate)
                || target != destination.offset
                || checked_add_u32(first, second, "immediate move length")? != atom_len(atom)?
            {
                return Err(mismatch());
            }
            Ok((2, None))
        }
        X64TailScheduledSource::Scratch { word_type, .. } => {
            if word_type == X64TailWordType::F64 {
                let decoded = decode_xmm_frame_store(code, offset)?;
                if decoded != (0, destination.offset, atom_len(atom)?) {
                    return Err(mismatch());
                }
            } else {
                let decoded = decode_gpr_frame_store(code, offset)?;
                if decoded != (0, destination.offset, atom_len(atom)?) {
                    return Err(mismatch());
                }
            }
            Ok((1, None))
        }
    }
}

fn decode_return_word(
    code: &[u8],
    offset: u32,
    source: X64TailScheduledSource,
    destination: X64TailBodyScratch,
    atom: &X64TailBodyAtom,
    mismatch: impl Fn() -> X64TailBodyDecodeError,
) -> Result<(u8, DecodedFixup), X64TailBodyDecodeError> {
    let destination = scratch_gpr(destination).ok_or_else(&mismatch)?;
    if !matches!(destination, 0 | 2) {
        return Err(mismatch());
    }
    match source {
        X64TailScheduledSource::Location(location) => {
            let decoded = decode_gpr_frame_load(code, offset)?;
            if decoded != (location.offset, destination, atom_len(atom)?) {
                return Err(mismatch());
            }
        }
        X64TailScheduledSource::Immediate(value) => {
            let bits = immediate_bits(value);
            if bits == 0 {
                let expected = [0x31, 0xc0 | (destination << 3) | destination];
                expect_exact(code, offset, &expected)?;
                if atom_len(atom)? != 2 {
                    return Err(mismatch());
                }
            } else {
                let decoded = decode_movabs(code, offset)?;
                if decoded != (destination, bits, atom_len(atom)?) {
                    return Err(mismatch());
                }
            }
        }
        X64TailScheduledSource::Scratch { .. } => return Err(mismatch()),
    }
    Ok((1, None))
}

fn decode_movabs(code: &[u8], offset: u32) -> Result<(u8, u64, u32), X64TailBodyDecodeError> {
    let bytes = read_exact::<10>(code, offset)?;
    if !matches!(bytes[0], 0x48 | 0x49) || !(0xb8..=0xbf).contains(&bytes[1]) {
        return Err(X64TailBodyDecodeError::UnknownOpcode { offset });
    }
    let register = (bytes[1] - 0xb8) + ((bytes[0] & 1) << 3);
    let bits = u64::from_le_bytes(
        bytes[2..10]
            .try_into()
            .map_err(|_| X64TailBodyDecodeError::Truncated { offset })?,
    );
    Ok((register, bits, 10))
}

fn decode_gpr_copy(code: &[u8], offset: u32) -> Result<(u8, u8, u32), X64TailBodyDecodeError> {
    let bytes = read_exact::<3>(code, offset)?;
    let rex = bytes[0];
    if !(0x48..=0x4d).contains(&rex)
        || rex & 0x02 != 0
        || bytes[1] != 0x89
        || bytes[2] & 0xc0 != 0xc0
    {
        return Err(X64TailBodyDecodeError::UnknownOpcode { offset });
    }
    let source = ((bytes[2] >> 3) & 7) + (((rex >> 2) & 1) << 3);
    let destination = (bytes[2] & 7) + ((rex & 1) << 3);
    Ok((source, destination, 3))
}

fn decode_gpr_frame_load(
    code: &[u8],
    offset: u32,
) -> Result<(u32, u8, u32), X64TailBodyDecodeError> {
    let bytes = read_exact::<8>(code, offset)?;
    if !matches!(bytes[0], 0x48 | 0x4c)
        || bytes[1] != 0x8b
        || bytes[2] & 0xc7 != 0x84
        || bytes[3] != 0x24
    {
        return Err(X64TailBodyDecodeError::NonCanonical {
            offset,
            field: "GPR frame load",
        });
    }
    let destination = ((bytes[2] >> 3) & 7) + (((bytes[0] >> 2) & 1) << 3);
    let frame = u32::from_le_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| X64TailBodyDecodeError::Truncated { offset })?,
    );
    Ok((frame, destination, 8))
}

fn decode_gpr_frame_store(
    code: &[u8],
    offset: u32,
) -> Result<(u8, u32, u32), X64TailBodyDecodeError> {
    let bytes = read_exact::<8>(code, offset)?;
    if !matches!(bytes[0], 0x48 | 0x4c)
        || bytes[1] != 0x89
        || bytes[2] & 0xc7 != 0x84
        || bytes[3] != 0x24
    {
        return Err(X64TailBodyDecodeError::NonCanonical {
            offset,
            field: "GPR frame store",
        });
    }
    let source = ((bytes[2] >> 3) & 7) + (((bytes[0] >> 2) & 1) << 3);
    let frame = u32::from_le_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| X64TailBodyDecodeError::Truncated { offset })?,
    );
    Ok((source, frame, 8))
}

fn decode_xmm_copy(code: &[u8], offset: u32) -> Result<(u8, u8, u32), X64TailBodyDecodeError> {
    let bytes = read_exact::<4>(code, offset)?;
    if bytes[0..3] != [0xf2, 0x0f, 0x10] || bytes[3] & 0xc0 != 0xc0 {
        return Err(X64TailBodyDecodeError::UnknownOpcode { offset });
    }
    Ok((bytes[3] & 7, (bytes[3] >> 3) & 7, 4))
}

fn decode_xmm_frame_load(
    code: &[u8],
    offset: u32,
) -> Result<(u32, u8, u32), X64TailBodyDecodeError> {
    let bytes = read_exact::<9>(code, offset)?;
    if bytes[0..3] != [0xf2, 0x0f, 0x10] || bytes[3] & 0xc7 != 0x84 || bytes[4] != 0x24 {
        return Err(X64TailBodyDecodeError::NonCanonical {
            offset,
            field: "XMM frame load",
        });
    }
    let frame = u32::from_le_bytes(
        bytes[5..9]
            .try_into()
            .map_err(|_| X64TailBodyDecodeError::Truncated { offset })?,
    );
    Ok((frame, (bytes[3] >> 3) & 7, 9))
}

fn decode_xmm_frame_store(
    code: &[u8],
    offset: u32,
) -> Result<(u8, u32, u32), X64TailBodyDecodeError> {
    let bytes = read_exact::<9>(code, offset)?;
    if bytes[0..3] != [0xf2, 0x0f, 0x11] || bytes[3] & 0xc7 != 0x84 || bytes[4] != 0x24 {
        return Err(X64TailBodyDecodeError::NonCanonical {
            offset,
            field: "XMM frame store",
        });
    }
    let frame = u32::from_le_bytes(
        bytes[5..9]
            .try_into()
            .map_err(|_| X64TailBodyDecodeError::Truncated { offset })?,
    );
    Ok(((bytes[3] >> 3) & 7, frame, 9))
}

fn decode_gpr_to_xmm(code: &[u8], offset: u32) -> Result<(u8, u8, u32), X64TailBodyDecodeError> {
    let bytes = read_exact::<5>(code, offset)?;
    if bytes[0..4] != [0x66, 0x48, 0x0f, 0x6e] || bytes[4] & 0xc0 != 0xc0 {
        return Err(X64TailBodyDecodeError::UnknownOpcode { offset });
    }
    Ok((bytes[4] & 7, (bytes[4] >> 3) & 7, 5))
}

fn decode_rel32(
    code: &[u8],
    offset: u32,
    prefix: &[u8],
    patch_relative: u32,
    length: u32,
    expected: X64TailBodyControlTarget,
    targets: &BTreeMap<u32, X64TailBodyControlTarget>,
) -> Result<(u32, X64TailBodyControlTarget, u32, i32), X64TailBodyDecodeError> {
    let prefix_bytes = read_slice(code, offset, prefix.len())?;
    if prefix_bytes != prefix {
        return Err(X64TailBodyDecodeError::UnknownOpcode { offset });
    }
    let patch_offset = checked_add_u32(offset, patch_relative, "rel32 patch")?;
    let patch = read_exact::<4>(code, patch_offset)?;
    let displacement = i32::from_le_bytes(patch);
    let next = i64::from(offset) + i64::from(length);
    let target_i64 = next.checked_add(i64::from(displacement)).ok_or(
        X64TailBodyDecodeError::ArithmeticOverflow {
            field: "rel32 target",
        },
    )?;
    let target_offset = u32::try_from(target_i64)
        .map_err(|_| X64TailBodyDecodeError::UnknownControlTarget { offset })?;
    let target = targets
        .get(&target_offset)
        .copied()
        .ok_or(X64TailBodyDecodeError::UnknownControlTarget { offset })?;
    if target != expected {
        return Err(X64TailBodyDecodeError::UnknownControlTarget { offset });
    }
    Ok((patch_offset, target, target_offset, displacement))
}

fn decoded_clobbers(instruction: X64TailBodyAtomInstruction) -> Vec<X64TailTemplateRegister> {
    let mut clobbers = match instruction {
        X64TailBodyAtomInstruction::Acquire { read, destination } => {
            let mut values = vec![scratch_template_register(destination)];
            if matches!(
                read,
                X64TailBoundRead::Immediate(X64TailImmediateWord::F64Bits(_))
            ) && scratch_xmm(destination).is_some()
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
        X64TailBodyAtomInstruction::I64Wrapping { .. }
        | X64TailBodyAtomInstruction::I64Setcc { .. } => {
            vec![X64TailTemplateRegister::Rax, X64TailTemplateRegister::Flags]
        }
        X64TailBodyAtomInstruction::Sse2F64 { .. }
        | X64TailBodyAtomInstruction::ArrayGetF64 { .. } => {
            vec![X64TailTemplateRegister::Xmm0]
        }
        X64TailBodyAtomInstruction::TestBool
        | X64TailBodyAtomInstruction::BoundsNegativeRel32 { .. }
        | X64TailBodyAtomInstruction::BoundsUpperRel32 { .. } => {
            vec![X64TailTemplateRegister::Flags]
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
            X64TailScheduledSource::Location(location) => {
                vec![if location.word_type == X64TailWordType::F64 {
                    X64TailTemplateRegister::Xmm1
                } else {
                    X64TailTemplateRegister::Rcx
                }]
            }
            X64TailScheduledSource::Immediate(_) => vec![X64TailTemplateRegister::Rcx],
        },
        X64TailBodyAtomInstruction::ReturnWord { destination, .. } => {
            vec![scratch_template_register(destination)]
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
    clobbers
}

const fn instruction_target(
    instruction: X64TailBodyAtomInstruction,
) -> Option<X64TailBodyControlTarget> {
    match instruction {
        X64TailBodyAtomInstruction::BranchNonZeroRel32 { target }
        | X64TailBodyAtomInstruction::JumpRel32 { target }
        | X64TailBodyAtomInstruction::BoundsNegativeRel32 { target }
        | X64TailBodyAtomInstruction::BoundsUpperRel32 { target } => Some(target),
        _ => None,
    }
}

const fn scratch_gpr(scratch: X64TailBodyScratch) -> Option<u8> {
    match scratch {
        X64TailBodyScratch::Rax => Some(0),
        X64TailBodyScratch::Rcx => Some(1),
        X64TailBodyScratch::Rdx => Some(2),
        X64TailBodyScratch::Xmm0 | X64TailBodyScratch::Xmm1 => None,
    }
}

const fn scratch_xmm(scratch: X64TailBodyScratch) -> Option<u8> {
    match scratch {
        X64TailBodyScratch::Xmm0 => Some(0),
        X64TailBodyScratch::Xmm1 => Some(1),
        X64TailBodyScratch::Rax | X64TailBodyScratch::Rcx | X64TailBodyScratch::Rdx => None,
    }
}

const fn physical_gpr(register: X64TailPhysicalRegister) -> Option<u8> {
    match register {
        X64TailPhysicalRegister::Rdi => Some(7),
        X64TailPhysicalRegister::Rsi => Some(6),
        X64TailPhysicalRegister::R9 => Some(9),
        X64TailPhysicalRegister::R10 => Some(10),
        X64TailPhysicalRegister::R11 => Some(11),
        X64TailPhysicalRegister::Xmm3
        | X64TailPhysicalRegister::Xmm4
        | X64TailPhysicalRegister::Xmm5
        | X64TailPhysicalRegister::Xmm6
        | X64TailPhysicalRegister::Xmm7 => None,
    }
}

const fn physical_xmm(register: X64TailPhysicalRegister) -> Option<u8> {
    match register {
        X64TailPhysicalRegister::Xmm3 => Some(3),
        X64TailPhysicalRegister::Xmm4 => Some(4),
        X64TailPhysicalRegister::Xmm5 => Some(5),
        X64TailPhysicalRegister::Xmm6 => Some(6),
        X64TailPhysicalRegister::Xmm7 => Some(7),
        X64TailPhysicalRegister::Rdi
        | X64TailPhysicalRegister::Rsi
        | X64TailPhysicalRegister::R9
        | X64TailPhysicalRegister::R10
        | X64TailPhysicalRegister::R11 => None,
    }
}

const fn scratch_template_register(scratch: X64TailBodyScratch) -> X64TailTemplateRegister {
    match scratch {
        X64TailBodyScratch::Rax => X64TailTemplateRegister::Rax,
        X64TailBodyScratch::Rcx => X64TailTemplateRegister::Rcx,
        X64TailBodyScratch::Rdx => X64TailTemplateRegister::Rdx,
        X64TailBodyScratch::Xmm0 => X64TailTemplateRegister::Xmm0,
        X64TailBodyScratch::Xmm1 => X64TailTemplateRegister::Xmm1,
    }
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

const fn immediate_bits(immediate: X64TailImmediateWord) -> u64 {
    match immediate {
        X64TailImmediateWord::Bool(value) => value as u64,
        X64TailImmediateWord::I64(value) => value as u64,
        X64TailImmediateWord::F64Bits(bits) => bits,
    }
}

fn atom_len(atom: &X64TailBodyAtom) -> Result<u32, X64TailBodyDecodeError> {
    atom.end
        .checked_sub(atom.start)
        .ok_or(X64TailBodyDecodeError::InvalidField {
            field: "atom length",
        })
}

fn ensure_expected_len(
    atom: &X64TailBodyAtom,
    actual: usize,
    program: u32,
) -> Result<(), X64TailBodyDecodeError> {
    if atom_len(atom)? != usize_to_u32(actual, "decoded instruction length")? {
        return Err(X64TailBodyDecodeError::AtomMismatch {
            program,
            atom: atom.ordinal,
        });
    }
    Ok(())
}

fn expect_exact(code: &[u8], offset: u32, expected: &[u8]) -> Result<(), X64TailBodyDecodeError> {
    if read_slice(code, offset, expected.len())? != expected {
        return Err(X64TailBodyDecodeError::UnknownOpcode { offset });
    }
    Ok(())
}

fn read_exact<const N: usize>(code: &[u8], offset: u32) -> Result<[u8; N], X64TailBodyDecodeError> {
    read_slice(code, offset, N)?
        .try_into()
        .map_err(|_| X64TailBodyDecodeError::Truncated { offset })
}

fn read_slice(code: &[u8], offset: u32, length: usize) -> Result<&[u8], X64TailBodyDecodeError> {
    let start = u32_to_usize(offset, "decode offset")?;
    let end = start
        .checked_add(length)
        .ok_or(X64TailBodyDecodeError::ArithmeticOverflow {
            field: "decode range",
        })?;
    code.get(start..end)
        .ok_or(X64TailBodyDecodeError::Truncated { offset })
}

fn ensure_usize_limit(
    field: &'static str,
    limit: usize,
    actual: usize,
) -> Result<(), X64TailBodyDecodeError> {
    if actual > limit {
        return Err(X64TailBodyDecodeError::LimitExceeded {
            field,
            limit: usize_to_u64(limit, "limit")?,
            actual: usize_to_u64(actual, field)?,
        });
    }
    Ok(())
}

fn charge(work: u64, amount: u64) -> Result<u64, X64TailBodyDecodeError> {
    let work = work
        .checked_add(amount)
        .ok_or(X64TailBodyDecodeError::ArithmeticOverflow {
            field: "decode work",
        })?;
    if work > X64_TAIL_BODY_DECODER_MAX_WORK {
        return Err(X64TailBodyDecodeError::LimitExceeded {
            field: "decode work",
            limit: X64_TAIL_BODY_DECODER_MAX_WORK,
            actual: work,
        });
    }
    Ok(work)
}

fn checked_add_u32(
    left: u32,
    right: u32,
    field: &'static str,
) -> Result<u32, X64TailBodyDecodeError> {
    left.checked_add(right)
        .ok_or(X64TailBodyDecodeError::ArithmeticOverflow { field })
}

fn usize_to_u32(value: usize, field: &'static str) -> Result<u32, X64TailBodyDecodeError> {
    u32::try_from(value).map_err(|_| X64TailBodyDecodeError::ArithmeticOverflow { field })
}

fn usize_to_u64(value: usize, field: &'static str) -> Result<u64, X64TailBodyDecodeError> {
    u64::try_from(value).map_err(|_| X64TailBodyDecodeError::ArithmeticOverflow { field })
}

fn u32_to_usize(value: u32, field: &'static str) -> Result<usize, X64TailBodyDecodeError> {
    usize::try_from(value).map_err(|_| X64TailBodyDecodeError::ArithmeticOverflow { field })
}
