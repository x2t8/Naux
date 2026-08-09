//! Independent decoder and symbolic ABI-state replay for ADR-0066.
//!
//! This module imports receipt types and frozen limits, but no byte-emission
//! helper. It consumes the capsule forward and derives every instruction,
//! effect, boundary, relocation, anchor, and total from verified predecessors.

use super::encoding::sha256;
use super::machine_ir::MachineType;
use super::schema::SemanticHash;
use super::x64_tail_abi_envelope::{
    X64TailAbiEnvelopeAnchorReceipt, X64TailAbiEnvelopeEffect,
    X64TailAbiEnvelopeInstructionReceipt, X64TailAbiEnvelopeProgramKind,
    X64TailAbiEnvelopeProgramReceipt, X64TailAbiEnvelopeRelocationReceipt,
    X64TailAbiEnvelopeTotals, ENTRY_TARGET_ANCHOR_BYTE, X64_TAIL_ABI_ENVELOPE_MAX_CODE_BYTES,
    X64_TAIL_ABI_ENVELOPE_MAX_INSTRUCTIONS, X64_TAIL_ABI_ENVELOPE_MAX_WORK,
};
use super::x64_tail_body_frontier_realization::X64TailBodyControlTarget;
use super::x64_tail_closed_image::{VerifiedX64TailClosedImage, X64TailClosedTerminalKind};
use super::x64_target::{
    verify_x64_target_r1_s7a, X64AbiRegister, X64Function, X64LabelId, X64LabelOwner,
    X64TargetArtifact, X64TargetProgram, X64_TARGET_MAX_ENTRY_INPUT_LANES,
};
use std::collections::BTreeSet;
use std::fmt;

pub const X64_TAIL_ABI_ENVELOPE_DECODER_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);

const FRAME_HEADER_BYTES: u32 = 32;
const SAVED_MXCSR_OFFSET: u32 = 0;
const CANONICAL_MXCSR_OFFSET: u32 = 4;
const OUTPUT_POINTER_OFFSET: u32 = 8;
const RESERVED_WORD_0_OFFSET: u32 = 16;
const RESERVED_WORD_1_OFFSET: u32 = 24;
const CODE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-abi-envelope-code:v1\0";
const ABI_REGISTERS: [X64AbiRegister; 6] = [
    X64AbiRegister::Rdi,
    X64AbiRegister::Rsi,
    X64AbiRegister::Rdx,
    X64AbiRegister::Rcx,
    X64AbiRegister::R8,
    X64AbiRegister::R9,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailDecodedAbiEnvelope {
    pub entry_successor: X64TailBodyControlTarget,
    pub programs: Vec<X64TailAbiEnvelopeProgramReceipt>,
    pub instructions: Vec<X64TailAbiEnvelopeInstructionReceipt>,
    pub relocation: X64TailAbiEnvelopeRelocationReceipt,
    pub anchor: X64TailAbiEnvelopeAnchorReceipt,
    pub code_hash: SemanticHash,
    pub totals: X64TailAbiEnvelopeTotals,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailAbiEnvelopeDecodeError {
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
    InstructionMismatch {
        offset: u32,
    },
    RelocationMismatch {
        patch: u32,
    },
    AnchorMismatch {
        offset: u32,
    },
    TrailingBytes {
        expected: u32,
        actual: u32,
    },
    StateReplay {
        field: &'static str,
    },
    CodeHash,
}

impl fmt::Display for X64TailAbiEnvelopeDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPredecessor { field } => {
                write!(formatter, "ABI decoder rejected predecessor {field}")
            }
            Self::InvalidField { field } => write!(formatter, "ABI decoder has invalid {field}"),
            Self::MissingTarget { field } => write!(formatter, "ABI decoder is missing {field}"),
            Self::LimitExceeded {
                field,
                limit,
                actual,
            } => write!(formatter, "ABI decoder {field} {actual} exceeds {limit}"),
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "ABI decoder arithmetic overflow in {field}")
            }
            Self::Truncated { offset } => write!(formatter, "ABI capsule is truncated at {offset}"),
            Self::InstructionMismatch { offset } => write!(
                formatter,
                "ABI capsule has a noncanonical instruction at {offset}"
            ),
            Self::RelocationMismatch { patch } => {
                write!(formatter, "ABI capsule relocation at {patch} is invalid")
            }
            Self::AnchorMismatch { offset } => {
                write!(formatter, "ABI capsule anchor at {offset} is invalid")
            }
            Self::TrailingBytes { expected, actual } => write!(
                formatter,
                "ABI capsule expected {expected} bytes, found {actual}"
            ),
            Self::StateReplay { field } => {
                write!(formatter, "ABI symbolic state replay failed at {field}")
            }
            Self::CodeHash => write!(formatter, "ABI decoder could not hash code"),
        }
    }
}

impl std::error::Error for X64TailAbiEnvelopeDecodeError {}

pub fn decode_x64_tail_abi_envelope_capsule(
    code: &[u8],
    target: &X64TargetArtifact,
    image: &VerifiedX64TailClosedImage<'_>,
) -> Result<X64TailDecodedAbiEnvelope, X64TailAbiEnvelopeDecodeError> {
    if code.len() as u64 > u64::from(X64_TAIL_ABI_ENVELOPE_MAX_CODE_BYTES) {
        return Err(X64TailAbiEnvelopeDecodeError::LimitExceeded {
            field: "code bytes",
            limit: u64::from(X64_TAIL_ABI_ENVELOPE_MAX_CODE_BYTES),
            actual: code.len() as u64,
        });
    }
    verify_x64_target_r1_s7a(target).map_err(|_| {
        X64TailAbiEnvelopeDecodeError::InvalidPredecessor {
            field: "verified x86-64 target",
        }
    })?;
    if image.image().source_target_semantic_hash() != target.semantic_hash {
        return Err(X64TailAbiEnvelopeDecodeError::InvalidPredecessor {
            field: "closed-image target identity",
        });
    }
    let program = &target.program;
    let entry = entry_function(program)?;
    validate_manifest(program, entry)?;
    let labels = terminal_labels(program, image)?;
    let entry_successor = image.image().entry_successor();
    let mut decoder = Decoder::new(code);

    decoder.begin(X64TailAbiEnvelopeProgramKind::EntryAdapter, labels[0])?;
    decoder.fixed(X64TailAbiEnvelopeEffect::PushCallerRbp, &[0x55])?;
    decoder.fixed(
        X64TailAbiEnvelopeEffect::EstablishFramePointer,
        &[0x48, 0x89, 0xe5],
    )?;
    let mut allocate = vec![0x48, 0x81, 0xec];
    allocate.extend_from_slice(&program.frame.frame_bytes.to_le_bytes());
    decoder.fixed(
        X64TailAbiEnvelopeEffect::AllocateFrame {
            bytes: program.frame.frame_bytes,
        },
        &allocate,
    )?;
    decoder.fixed(
        X64TailAbiEnvelopeEffect::SaveCallerMxcsr {
            offset: SAVED_MXCSR_OFFSET,
        },
        &expected_mxcsr(false, SAVED_MXCSR_OFFSET),
    )?;
    decoder.fixed(
        X64TailAbiEnvelopeEffect::StoreCanonicalMxcsr {
            offset: CANONICAL_MXCSR_OFFSET,
            value: program.abi.canonical_mxcsr,
        },
        &expected_mem32_imm(CANONICAL_MXCSR_OFFSET, program.abi.canonical_mxcsr),
    )?;
    decoder.fixed(
        X64TailAbiEnvelopeEffect::LoadCanonicalMxcsr {
            offset: CANONICAL_MXCSR_OFFSET,
        },
        &expected_mxcsr(true, CANONICAL_MXCSR_OFFSET),
    )?;
    decoder.fixed(
        X64TailAbiEnvelopeEffect::SaveOutputPointer {
            offset: OUTPUT_POINTER_OFFSET,
            register: program.entry_abi.output_register,
        },
        &expected_store_frame(OUTPUT_POINTER_OFFSET, program.entry_abi.output_register),
    )?;
    for offset in [RESERVED_WORD_0_OFFSET, RESERVED_WORD_1_OFFSET] {
        decoder.fixed(
            X64TailAbiEnvelopeEffect::ZeroReservedWord { offset },
            &expected_mem64_imm(offset, 0),
        )?;
    }
    for (parameter_index, parameter) in entry.parameters.iter().enumerate() {
        let parameter_index = usize_to_u32(parameter_index, "parameter index")?;
        if parameter.home.ty == MachineType::Unit {
            decoder.fixed(
                X64TailAbiEnvelopeEffect::ZeroUnitHome {
                    parameter: parameter_index,
                    offset: parameter.home.offset,
                },
                &expected_mem64_imm(parameter.home.offset, 0),
            )?;
            continue;
        }
        let mut lanes = program
            .entry_abi
            .input_lanes
            .iter()
            .filter(|lane| lane.parameter == parameter_index)
            .copied()
            .collect::<Vec<_>>();
        lanes.sort_by_key(|lane| lane.word);
        for lane in lanes {
            let offset = parameter
                .home
                .offset
                .checked_add(u32::from(lane.word) * 8)
                .ok_or(X64TailAbiEnvelopeDecodeError::ArithmeticOverflow {
                    field: "lane offset",
                })?;
            decoder.fixed(
                X64TailAbiEnvelopeEffect::StoreInputLane {
                    parameter: parameter_index,
                    word: lane.word,
                    register: lane.register,
                    offset,
                    ty: parameter.home.ty,
                },
                &expected_store_frame(offset, lane.register),
            )?;
        }
    }
    let (jump_ordinal, jump_start) = decoder.next_instruction();
    decoder.expect(&[0xe9])?;
    let patch_offset = decoder.cursor_u32()?;
    let displacement = decoder.i32()?;
    decoder.record_from(
        jump_start,
        X64TailAbiEnvelopeEffect::JumpEntrySuccessor {
            target: entry_successor,
        },
    )?;
    decoder.end()?;

    decoder.begin(X64TailAbiEnvelopeProgramKind::ReturnEpilogue, labels[1])?;
    decode_return(&mut decoder, program.frame.frame_bytes)?;
    decoder.end()?;

    decoder.begin(X64TailAbiEnvelopeProgramKind::BoundsEpilogue, labels[2])?;
    decode_bounds(&mut decoder, program.frame.frame_bytes)?;
    decoder.end()?;

    let anchor_offset = decoder.cursor_u32()?;
    if decoder.byte()? != ENTRY_TARGET_ANCHOR_BYTE {
        return Err(X64TailAbiEnvelopeDecodeError::AnchorMismatch {
            offset: anchor_offset,
        });
    }
    if decoder.cursor != code.len() {
        return Err(X64TailAbiEnvelopeDecodeError::TrailingBytes {
            expected: decoder.cursor_u32()?,
            actual: usize_to_u32(code.len(), "actual code bytes")?,
        });
    }
    let resolved = i64::from(patch_offset)
        .checked_add(4)
        .and_then(|value| value.checked_add(i64::from(displacement)))
        .ok_or(X64TailAbiEnvelopeDecodeError::ArithmeticOverflow {
            field: "rel32 resolution",
        })?;
    if resolved != i64::from(anchor_offset) {
        return Err(X64TailAbiEnvelopeDecodeError::RelocationMismatch {
            patch: patch_offset,
        });
    }
    let relocation = X64TailAbiEnvelopeRelocationReceipt {
        program: X64TailAbiEnvelopeProgramKind::EntryAdapter,
        instruction_ordinal: jump_ordinal,
        patch_offset,
        target: entry_successor,
        target_offset: anchor_offset,
        displacement,
    };
    let anchor = X64TailAbiEnvelopeAnchorReceipt {
        offset: anchor_offset,
        target: entry_successor,
    };
    replay_state(program, &decoder.programs, &decoder.instructions)?;
    let totals = decoded_totals(
        program,
        &decoder.programs,
        &decoder.instructions,
        code.len(),
    )?;
    let code_hash = decoded_code_hash(code)?;
    Ok(X64TailDecodedAbiEnvelope {
        entry_successor,
        programs: decoder.programs,
        instructions: decoder.instructions,
        relocation,
        anchor,
        code_hash,
        totals,
    })
}

fn decode_return(
    decoder: &mut Decoder<'_>,
    frame_bytes: u32,
) -> Result<(), X64TailAbiEnvelopeDecodeError> {
    decoder.fixed(
        X64TailAbiEnvelopeEffect::LoadOutputPointer {
            offset: OUTPUT_POINTER_OFFSET,
        },
        &expected_load_rcx(OUTPUT_POINTER_OFFSET),
    )?;
    decoder.fixed(
        X64TailAbiEnvelopeEffect::StoreResultWord { word: 0 },
        &[0x48, 0x89, 0x01],
    )?;
    let mut word_one = vec![0x48, 0x89, 0x91];
    word_one.extend_from_slice(&8_u32.to_le_bytes());
    decoder.fixed(
        X64TailAbiEnvelopeEffect::StoreResultWord { word: 1 },
        &word_one,
    )?;
    decoder.fixed(
        X64TailAbiEnvelopeEffect::SetStatus { value: 0 },
        &[0x31, 0xc0],
    )?;
    decode_common_exit(decoder, frame_bytes)
}

fn decode_bounds(
    decoder: &mut Decoder<'_>,
    frame_bytes: u32,
) -> Result<(), X64TailAbiEnvelopeDecodeError> {
    decoder.fixed(
        X64TailAbiEnvelopeEffect::LoadOutputPointer {
            offset: OUTPUT_POINTER_OFFSET,
        },
        &expected_load_rcx(OUTPUT_POINTER_OFFSET),
    )?;
    decoder.fixed(X64TailAbiEnvelopeEffect::ZeroResultRegister, &[0x31, 0xc0])?;
    decoder.fixed(
        X64TailAbiEnvelopeEffect::StoreZeroResultWord { word: 0 },
        &[0x48, 0x89, 0x01],
    )?;
    let mut word_one = vec![0x48, 0x89, 0x81];
    word_one.extend_from_slice(&8_u32.to_le_bytes());
    decoder.fixed(
        X64TailAbiEnvelopeEffect::StoreZeroResultWord { word: 1 },
        &word_one,
    )?;
    let mut status = vec![0xb8];
    status.extend_from_slice(&1_u32.to_le_bytes());
    decoder.fixed(X64TailAbiEnvelopeEffect::SetStatus { value: 1 }, &status)?;
    decode_common_exit(decoder, frame_bytes)
}

fn decode_common_exit(
    decoder: &mut Decoder<'_>,
    frame_bytes: u32,
) -> Result<(), X64TailAbiEnvelopeDecodeError> {
    decoder.fixed(
        X64TailAbiEnvelopeEffect::RestoreCallerMxcsr {
            offset: SAVED_MXCSR_OFFSET,
        },
        &expected_mxcsr(true, SAVED_MXCSR_OFFSET),
    )?;
    let mut release = vec![0x48, 0x81, 0xc4];
    release.extend_from_slice(&frame_bytes.to_le_bytes());
    decoder.fixed(
        X64TailAbiEnvelopeEffect::ReleaseFrame { bytes: frame_bytes },
        &release,
    )?;
    decoder.fixed(X64TailAbiEnvelopeEffect::RestoreCallerRbp, &[0x5d])?;
    decoder.fixed(X64TailAbiEnvelopeEffect::Return, &[0xc3])
}

fn replay_state(
    program: &X64TargetProgram,
    programs: &[X64TailAbiEnvelopeProgramReceipt],
    instructions: &[X64TailAbiEnvelopeInstructionReceipt],
) -> Result<(), X64TailAbiEnvelopeDecodeError> {
    if programs.len() != 3 || program.abi.stack_alignment == 0 {
        return Err(X64TailAbiEnvelopeDecodeError::StateReplay {
            field: "program/stack manifest",
        });
    }
    let entry = effects_for(instructions, X64TailAbiEnvelopeProgramKind::EntryAdapter);
    if entry.len() < 10
        || entry[0] != X64TailAbiEnvelopeEffect::PushCallerRbp
        || entry[1] != X64TailAbiEnvelopeEffect::EstablishFramePointer
        || entry[2]
            != (X64TailAbiEnvelopeEffect::AllocateFrame {
                bytes: program.frame.frame_bytes,
            })
        || entry[3]
            != (X64TailAbiEnvelopeEffect::SaveCallerMxcsr {
                offset: SAVED_MXCSR_OFFSET,
            })
        || entry[4]
            != (X64TailAbiEnvelopeEffect::StoreCanonicalMxcsr {
                offset: CANONICAL_MXCSR_OFFSET,
                value: program.abi.canonical_mxcsr,
            })
        || entry[5]
            != (X64TailAbiEnvelopeEffect::LoadCanonicalMxcsr {
                offset: CANONICAL_MXCSR_OFFSET,
            })
        || entry[6]
            != (X64TailAbiEnvelopeEffect::SaveOutputPointer {
                offset: OUTPUT_POINTER_OFFSET,
                register: program.entry_abi.output_register,
            })
        || entry[7]
            != (X64TailAbiEnvelopeEffect::ZeroReservedWord {
                offset: RESERVED_WORD_0_OFFSET,
            })
        || entry[8]
            != (X64TailAbiEnvelopeEffect::ZeroReservedWord {
                offset: RESERVED_WORD_1_OFFSET,
            })
        || !matches!(
            entry.last(),
            Some(X64TailAbiEnvelopeEffect::JumpEntrySuccessor { .. })
        )
    {
        return Err(X64TailAbiEnvelopeDecodeError::StateReplay {
            field: "entry prefix/transfer",
        });
    }
    let mut expected_homes = BTreeSet::new();
    let entry_function = entry_function(program)?;
    for (parameter, descriptor) in entry_function.parameters.iter().enumerate() {
        let parameter = usize_to_u32(parameter, "state parameter")?;
        if descriptor.home.ty == MachineType::Unit {
            expected_homes.insert((parameter, u8::MAX));
        } else {
            for word in 0..words(descriptor.home.ty) {
                expected_homes.insert((parameter, word as u8));
            }
        }
    }
    let mut observed_homes = BTreeSet::new();
    for effect in &entry[9..entry.len() - 1] {
        match effect {
            X64TailAbiEnvelopeEffect::ZeroUnitHome { parameter, .. } => {
                if !observed_homes.insert((*parameter, u8::MAX)) {
                    return Err(X64TailAbiEnvelopeDecodeError::StateReplay {
                        field: "duplicate Unit home",
                    });
                }
            }
            X64TailAbiEnvelopeEffect::StoreInputLane {
                parameter, word, ..
            } => {
                if !observed_homes.insert((*parameter, *word)) {
                    return Err(X64TailAbiEnvelopeDecodeError::StateReplay {
                        field: "duplicate input home",
                    });
                }
            }
            _ => {
                return Err(X64TailAbiEnvelopeDecodeError::StateReplay {
                    field: "entry materialization effect",
                })
            }
        }
    }
    if observed_homes != expected_homes {
        return Err(X64TailAbiEnvelopeDecodeError::StateReplay {
            field: "complete entry homes",
        });
    }
    if !program
        .frame
        .frame_bytes
        .is_multiple_of(program.abi.stack_alignment)
    {
        return Err(X64TailAbiEnvelopeDecodeError::StateReplay {
            field: "frame alignment",
        });
    }
    let expected_return = vec![
        X64TailAbiEnvelopeEffect::LoadOutputPointer {
            offset: OUTPUT_POINTER_OFFSET,
        },
        X64TailAbiEnvelopeEffect::StoreResultWord { word: 0 },
        X64TailAbiEnvelopeEffect::StoreResultWord { word: 1 },
        X64TailAbiEnvelopeEffect::SetStatus { value: 0 },
        X64TailAbiEnvelopeEffect::RestoreCallerMxcsr {
            offset: SAVED_MXCSR_OFFSET,
        },
        X64TailAbiEnvelopeEffect::ReleaseFrame {
            bytes: program.frame.frame_bytes,
        },
        X64TailAbiEnvelopeEffect::RestoreCallerRbp,
        X64TailAbiEnvelopeEffect::Return,
    ];
    if effects_for(instructions, X64TailAbiEnvelopeProgramKind::ReturnEpilogue) != expected_return {
        return Err(X64TailAbiEnvelopeDecodeError::StateReplay {
            field: "return conservation",
        });
    }
    let expected_bounds = vec![
        X64TailAbiEnvelopeEffect::LoadOutputPointer {
            offset: OUTPUT_POINTER_OFFSET,
        },
        X64TailAbiEnvelopeEffect::ZeroResultRegister,
        X64TailAbiEnvelopeEffect::StoreZeroResultWord { word: 0 },
        X64TailAbiEnvelopeEffect::StoreZeroResultWord { word: 1 },
        X64TailAbiEnvelopeEffect::SetStatus { value: 1 },
        X64TailAbiEnvelopeEffect::RestoreCallerMxcsr {
            offset: SAVED_MXCSR_OFFSET,
        },
        X64TailAbiEnvelopeEffect::ReleaseFrame {
            bytes: program.frame.frame_bytes,
        },
        X64TailAbiEnvelopeEffect::RestoreCallerRbp,
        X64TailAbiEnvelopeEffect::Return,
    ];
    if effects_for(instructions, X64TailAbiEnvelopeProgramKind::BoundsEpilogue) != expected_bounds {
        return Err(X64TailAbiEnvelopeDecodeError::StateReplay {
            field: "Bounds conservation",
        });
    }
    Ok(())
}

fn effects_for(
    instructions: &[X64TailAbiEnvelopeInstructionReceipt],
    program: X64TailAbiEnvelopeProgramKind,
) -> Vec<X64TailAbiEnvelopeEffect> {
    instructions
        .iter()
        .filter(|instruction| instruction.program == program)
        .map(|instruction| instruction.effect)
        .collect()
}

fn decoded_totals(
    program: &X64TargetProgram,
    programs: &[X64TailAbiEnvelopeProgramReceipt],
    instructions: &[X64TailAbiEnvelopeInstructionReceipt],
    code_len: usize,
) -> Result<X64TailAbiEnvelopeTotals, X64TailAbiEnvelopeDecodeError> {
    if programs.len() != 3
        || instructions.len() as u64 > u64::from(X64_TAIL_ABI_ENVELOPE_MAX_INSTRUCTIONS)
    {
        return Err(X64TailAbiEnvelopeDecodeError::LimitExceeded {
            field: "program/instruction count",
            limit: u64::from(X64_TAIL_ABI_ENVELOPE_MAX_INSTRUCTIONS),
            actual: instructions.len() as u64,
        });
    }
    let code_bytes = usize_to_u32(code_len, "code bytes")?;
    let instruction_count = usize_to_u32(instructions.len(), "instructions")?;
    let common_work = u64::from(code_bytes)
        .checked_add(u64::from(instruction_count) * 2)
        .and_then(|value| value.checked_add(4))
        .ok_or(X64TailAbiEnvelopeDecodeError::ArithmeticOverflow {
            field: "decode work",
        })?;
    let replay_work = u64::from(instruction_count)
        .checked_add(program.entry_abi.input_lanes.len() as u64)
        .and_then(|value| value.checked_add(3))
        .ok_or(X64TailAbiEnvelopeDecodeError::ArithmeticOverflow {
            field: "replay work",
        })?;
    if common_work > X64_TAIL_ABI_ENVELOPE_MAX_WORK || replay_work > X64_TAIL_ABI_ENVELOPE_MAX_WORK
    {
        return Err(X64TailAbiEnvelopeDecodeError::LimitExceeded {
            field: "work",
            limit: X64_TAIL_ABI_ENVELOPE_MAX_WORK,
            actual: common_work.max(replay_work),
        });
    }
    Ok(X64TailAbiEnvelopeTotals {
        programs: 3,
        instructions: instruction_count,
        effects: instruction_count,
        input_lanes: usize_to_u32(program.entry_abi.input_lanes.len(), "input lanes")?,
        relocations: 1,
        anchors: 1,
        entry_bytes: programs[0].end - programs[0].start,
        return_bytes: programs[1].end - programs[1].start,
        bounds_bytes: programs[2].end - programs[2].start,
        anchor_bytes: 1,
        code_bytes,
        encode_work: common_work,
        decode_work: common_work,
        replay_work,
    })
}

fn entry_function(
    program: &X64TargetProgram,
) -> Result<&X64Function, X64TailAbiEnvelopeDecodeError> {
    program
        .functions
        .iter()
        .find(|function| function.id == program.entry)
        .ok_or(X64TailAbiEnvelopeDecodeError::MissingTarget {
            field: "entry function",
        })
}

fn validate_manifest(
    program: &X64TargetProgram,
    entry: &X64Function,
) -> Result<(), X64TailAbiEnvelopeDecodeError> {
    if program.frame.header_bytes != FRAME_HEADER_BYTES
        || program.frame.home_base != FRAME_HEADER_BYTES
        || program.frame.frame_bytes < FRAME_HEADER_BYTES
        || program.abi.stack_alignment == 0
        || !program
            .frame
            .frame_bytes
            .is_multiple_of(program.abi.stack_alignment)
        || program.entry_abi.parameter_types.len() != entry.parameters.len()
        || program.entry_abi.output_words != 2
        || program.entry_abi.input_lanes.len() as u64 > u64::from(X64_TARGET_MAX_ENTRY_INPUT_LANES)
    {
        return Err(X64TailAbiEnvelopeDecodeError::InvalidField {
            field: "canonical ABI/frame manifest",
        });
    }
    let mut occupied = BTreeSet::new();
    let mut expected = Vec::new();
    for (index, parameter) in entry.parameters.iter().enumerate() {
        if program.entry_abi.parameter_types[index] != parameter.home.ty {
            return Err(X64TailAbiEnvelopeDecodeError::InvalidField {
                field: "entry parameter type",
            });
        }
        let word_count = words(parameter.home.ty);
        let width = if word_count == 0 { 8 } else { word_count * 8 };
        if u32::from(parameter.home.width) != width || parameter.home.offset < FRAME_HEADER_BYTES {
            return Err(X64TailAbiEnvelopeDecodeError::InvalidField {
                field: "entry home shape",
            });
        }
        let end = parameter
            .home
            .offset
            .checked_add(u32::from(parameter.home.width))
            .ok_or(X64TailAbiEnvelopeDecodeError::ArithmeticOverflow {
                field: "entry home end",
            })?;
        if end > program.frame.frame_bytes {
            return Err(X64TailAbiEnvelopeDecodeError::InvalidField {
                field: "entry home extent",
            });
        }
        for byte in parameter.home.offset..end {
            if !occupied.insert(byte) {
                return Err(X64TailAbiEnvelopeDecodeError::InvalidField {
                    field: "overlapping entry homes",
                });
            }
        }
        let parameter = usize_to_u32(index, "entry parameter index")?;
        for word in 0..word_count {
            expected.push((parameter, word as u8));
        }
    }
    if expected.len() != program.entry_abi.input_lanes.len() {
        return Err(X64TailAbiEnvelopeDecodeError::InvalidField {
            field: "entry lane count",
        });
    }
    for (ordinal, ((parameter, word), lane)) in expected
        .iter()
        .zip(&program.entry_abi.input_lanes)
        .enumerate()
    {
        if lane.parameter != *parameter
            || lane.word != *word
            || lane.register != ABI_REGISTERS[ordinal]
        {
            return Err(X64TailAbiEnvelopeDecodeError::InvalidField {
                field: "canonical entry lane order",
            });
        }
    }
    if program.entry_abi.output_register != ABI_REGISTERS[expected.len()] {
        return Err(X64TailAbiEnvelopeDecodeError::InvalidField {
            field: "canonical output-pointer register",
        });
    }
    Ok(())
}

fn terminal_labels(
    program: &X64TargetProgram,
    image: &VerifiedX64TailClosedImage<'_>,
) -> Result<[X64LabelId; 3], X64TailAbiEnvelopeDecodeError> {
    let specs = [
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
    let mut labels = [X64LabelId(0); 3];
    for (index, (kind, owner)) in specs.into_iter().enumerate() {
        let candidates = program
            .labels
            .iter()
            .filter(|label| label.owner == owner)
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            return Err(X64TailAbiEnvelopeDecodeError::InvalidField {
                field: "unique terminal label",
            });
        }
        let image_candidates = image
            .image()
            .terminal_receipts()
            .iter()
            .filter(|terminal| terminal.kind == kind)
            .collect::<Vec<_>>();
        if image_candidates.len() != 1 || image_candidates[0].label != candidates[0].id {
            return Err(X64TailAbiEnvelopeDecodeError::InvalidPredecessor {
                field: "closed-image terminal label",
            });
        }
        labels[index] = candidates[0].id;
    }
    Ok(labels)
}

fn words(ty: MachineType) -> u32 {
    match ty {
        MachineType::Unit => 0,
        MachineType::Bool | MachineType::I64 | MachineType::F64 => 1,
        MachineType::F64Array => 2,
    }
}

fn expected_store_frame(offset: u32, register: X64AbiRegister) -> Vec<u8> {
    let number = register_number(register);
    let rex = 0x48 | if number >= 8 { 0x04 } else { 0 };
    let modrm = 0x84 | ((number & 7) << 3);
    let mut bytes = vec![rex, 0x89, modrm, 0x24];
    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes
}

fn expected_load_rcx(offset: u32) -> Vec<u8> {
    let mut bytes = vec![0x48, 0x8b, 0x8c, 0x24];
    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes
}

fn expected_mem32_imm(offset: u32, value: u32) -> Vec<u8> {
    let mut bytes = vec![0xc7, 0x84, 0x24];
    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes
}

fn expected_mem64_imm(offset: u32, value: u32) -> Vec<u8> {
    let mut bytes = vec![0x48, 0xc7, 0x84, 0x24];
    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes
}

fn expected_mxcsr(load: bool, offset: u32) -> Vec<u8> {
    let mut bytes = vec![0x0f, 0xae, if load { 0x94 } else { 0x9c }, 0x24];
    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes
}

fn register_number(register: X64AbiRegister) -> u8 {
    match register {
        X64AbiRegister::Rdi => 7,
        X64AbiRegister::Rsi => 6,
        X64AbiRegister::Rdx => 2,
        X64AbiRegister::Rcx => 1,
        X64AbiRegister::R8 => 8,
        X64AbiRegister::R9 => 9,
    }
}

fn decoded_code_hash(code: &[u8]) -> Result<SemanticHash, X64TailAbiEnvelopeDecodeError> {
    if code.len() as u64 > u64::from(X64_TAIL_ABI_ENVELOPE_MAX_CODE_BYTES) {
        return Err(X64TailAbiEnvelopeDecodeError::LimitExceeded {
            field: "code bytes",
            limit: u64::from(X64_TAIL_ABI_ENVELOPE_MAX_CODE_BYTES),
            actual: code.len() as u64,
        });
    }
    let mut bytes = Vec::with_capacity(CODE_DOMAIN.len() + 8 + code.len());
    bytes.extend_from_slice(CODE_DOMAIN);
    bytes.extend_from_slice(&(code.len() as u64).to_le_bytes());
    bytes.extend_from_slice(code);
    Ok(SemanticHash(sha256(&bytes)))
}

struct OpenProgram {
    kind: X64TailAbiEnvelopeProgramKind,
    label: X64LabelId,
    start: u32,
    instruction_start: usize,
}

struct Decoder<'code> {
    code: &'code [u8],
    cursor: usize,
    programs: Vec<X64TailAbiEnvelopeProgramReceipt>,
    instructions: Vec<X64TailAbiEnvelopeInstructionReceipt>,
    open: Option<OpenProgram>,
}

impl<'code> Decoder<'code> {
    fn new(code: &'code [u8]) -> Self {
        Self {
            code,
            cursor: 0,
            programs: Vec::new(),
            instructions: Vec::new(),
            open: None,
        }
    }
    fn begin(
        &mut self,
        kind: X64TailAbiEnvelopeProgramKind,
        label: X64LabelId,
    ) -> Result<(), X64TailAbiEnvelopeDecodeError> {
        if self.open.is_some() {
            return Err(X64TailAbiEnvelopeDecodeError::InvalidField {
                field: "nested program",
            });
        }
        self.open = Some(OpenProgram {
            kind,
            label,
            start: self.cursor_u32()?,
            instruction_start: self.instructions.len(),
        });
        Ok(())
    }
    fn end(&mut self) -> Result<(), X64TailAbiEnvelopeDecodeError> {
        let open = self
            .open
            .take()
            .ok_or(X64TailAbiEnvelopeDecodeError::InvalidField {
                field: "program end",
            })?;
        self.programs.push(X64TailAbiEnvelopeProgramReceipt {
            kind: open.kind,
            label: open.label,
            start: open.start,
            end: self.cursor_u32()?,
            instructions: usize_to_u32(
                self.instructions.len() - open.instruction_start,
                "program instructions",
            )?,
        });
        Ok(())
    }
    fn fixed(
        &mut self,
        effect: X64TailAbiEnvelopeEffect,
        expected: &[u8],
    ) -> Result<(), X64TailAbiEnvelopeDecodeError> {
        let start = self.cursor_u32()?;
        self.expect(expected)?;
        self.record_from(start, effect)
    }
    fn next_instruction(&self) -> (u32, u32) {
        let ordinal = self.open.as_ref().map_or(0, |open| {
            (self.instructions.len() - open.instruction_start) as u32
        });
        (ordinal, self.cursor as u32)
    }
    fn record_from(
        &mut self,
        start: u32,
        effect: X64TailAbiEnvelopeEffect,
    ) -> Result<(), X64TailAbiEnvelopeDecodeError> {
        let open = self
            .open
            .as_ref()
            .ok_or(X64TailAbiEnvelopeDecodeError::InvalidField {
                field: "instruction outside program",
            })?;
        let ordinal = usize_to_u32(
            self.instructions.len() - open.instruction_start,
            "instruction ordinal",
        )?;
        self.instructions
            .push(X64TailAbiEnvelopeInstructionReceipt {
                program: open.kind,
                ordinal,
                start,
                end: self.cursor_u32()?,
                effect,
            });
        if self.instructions.len() as u64 > u64::from(X64_TAIL_ABI_ENVELOPE_MAX_INSTRUCTIONS) {
            return Err(X64TailAbiEnvelopeDecodeError::LimitExceeded {
                field: "instructions",
                limit: u64::from(X64_TAIL_ABI_ENVELOPE_MAX_INSTRUCTIONS),
                actual: self.instructions.len() as u64,
            });
        }
        Ok(())
    }
    fn expect(&mut self, expected: &[u8]) -> Result<(), X64TailAbiEnvelopeDecodeError> {
        let start = self.cursor_u32()?;
        let end = self.cursor.checked_add(expected.len()).ok_or(
            X64TailAbiEnvelopeDecodeError::ArithmeticOverflow {
                field: "instruction extent",
            },
        )?;
        let actual = self
            .code
            .get(self.cursor..end)
            .ok_or(X64TailAbiEnvelopeDecodeError::Truncated { offset: start })?;
        if actual != expected {
            return Err(X64TailAbiEnvelopeDecodeError::InstructionMismatch { offset: start });
        }
        self.cursor = end;
        Ok(())
    }
    fn i32(&mut self) -> Result<i32, X64TailAbiEnvelopeDecodeError> {
        let start = self.cursor_u32()?;
        let end = self.cursor.checked_add(4).ok_or(
            X64TailAbiEnvelopeDecodeError::ArithmeticOverflow {
                field: "i32 extent",
            },
        )?;
        let bytes: [u8; 4] = self
            .code
            .get(self.cursor..end)
            .ok_or(X64TailAbiEnvelopeDecodeError::Truncated { offset: start })?
            .try_into()
            .map_err(|_| X64TailAbiEnvelopeDecodeError::Truncated { offset: start })?;
        self.cursor = end;
        Ok(i32::from_le_bytes(bytes))
    }
    fn byte(&mut self) -> Result<u8, X64TailAbiEnvelopeDecodeError> {
        let offset = self.cursor_u32()?;
        let byte = *self
            .code
            .get(self.cursor)
            .ok_or(X64TailAbiEnvelopeDecodeError::Truncated { offset })?;
        self.cursor += 1;
        Ok(byte)
    }
    fn cursor_u32(&self) -> Result<u32, X64TailAbiEnvelopeDecodeError> {
        usize_to_u32(self.cursor, "decoder cursor")
    }
}

fn usize_to_u32(value: usize, field: &'static str) -> Result<u32, X64TailAbiEnvelopeDecodeError> {
    u32::try_from(value).map_err(|_| X64TailAbiEnvelopeDecodeError::ArithmeticOverflow { field })
}
