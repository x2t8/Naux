//! Sovereign non-executable ABI-envelope byte capsule for ADR-0066.
//!
//! This module owns the entry, return, and Bounds byte templates needed by
//! ADR-0065, but it does not replace the closed image's typed terminals and
//! exposes no mapping or execution API. It deliberately imports no raw/native
//! encoder, runner, process, standalone, or measurement implementation.

use super::encoding::sha256;
use super::machine_ir::MachineType;
use super::schema::SemanticHash;
use super::x64_tail_abi_envelope_decode::{
    decode_x64_tail_abi_envelope_capsule, X64TailAbiEnvelopeDecodeError, X64TailDecodedAbiEnvelope,
    X64_TAIL_ABI_ENVELOPE_DECODER_POLICY_VERSION,
};
use super::x64_tail_body_frontier_realization::X64TailBodyControlTarget;
use super::x64_tail_closed_image::{VerifiedX64TailClosedImage, X64TailClosedTerminalKind};
use super::x64_target::{
    verify_x64_target_r1_s7a, X64AbiRegister, X64Function, X64LabelId, X64LabelOwner,
    X64TargetArtifact, X64TargetProgram, X64_TARGET_MAX_ENTRY_INPUT_LANES,
};
use std::collections::BTreeSet;
use std::fmt;

pub const X64_TAIL_ABI_ENVELOPE_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_ABI_ENVELOPE_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_ABI_ENVELOPE_MAX_CODE_BYTES: u32 = 4 * 1024;
pub const X64_TAIL_ABI_ENVELOPE_MAX_INSTRUCTIONS: u32 = 3 * 64;
pub const X64_TAIL_ABI_ENVELOPE_MAX_WORK: u64 = 16_384;
pub const X64_TAIL_ABI_ENVELOPE_MAX_EVIDENCE_BYTES: usize = 1024 * 1024;

const CODE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-abi-envelope-code:v1\0";
const CAPSULE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-abi-envelope:v1\0";
pub(super) const ENTRY_TARGET_ANCHOR_BYTE: u8 = 0xcc;
const FRAME_HEADER_BYTES: u32 = 32;
const SAVED_MXCSR_OFFSET: u32 = 0;
const CANONICAL_MXCSR_OFFSET: u32 = 4;
const OUTPUT_POINTER_OFFSET: u32 = 8;
const RESERVED_WORD_0_OFFSET: u32 = 16;
const RESERVED_WORD_1_OFFSET: u32 = 24;
const ABI_REGISTERS: [X64AbiRegister; 6] = [
    X64AbiRegister::Rdi,
    X64AbiRegister::Rsi,
    X64AbiRegister::Rdx,
    X64AbiRegister::Rcx,
    X64AbiRegister::R8,
    X64AbiRegister::R9,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum X64TailAbiEnvelopeProgramKind {
    EntryAdapter,
    ReturnEpilogue,
    BoundsEpilogue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailAbiEnvelopeEffect {
    PushCallerRbp,
    EstablishFramePointer,
    AllocateFrame {
        bytes: u32,
    },
    SaveCallerMxcsr {
        offset: u32,
    },
    StoreCanonicalMxcsr {
        offset: u32,
        value: u32,
    },
    LoadCanonicalMxcsr {
        offset: u32,
    },
    SaveOutputPointer {
        offset: u32,
        register: X64AbiRegister,
    },
    ZeroReservedWord {
        offset: u32,
    },
    ZeroUnitHome {
        parameter: u32,
        offset: u32,
    },
    StoreInputLane {
        parameter: u32,
        word: u8,
        register: X64AbiRegister,
        offset: u32,
        ty: MachineType,
    },
    JumpEntrySuccessor {
        target: X64TailBodyControlTarget,
    },
    LoadOutputPointer {
        offset: u32,
    },
    StoreResultWord {
        word: u8,
    },
    ZeroResultRegister,
    StoreZeroResultWord {
        word: u8,
    },
    SetStatus {
        value: u32,
    },
    RestoreCallerMxcsr {
        offset: u32,
    },
    ReleaseFrame {
        bytes: u32,
    },
    RestoreCallerRbp,
    Return,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailAbiEnvelopeProgramReceipt {
    pub kind: X64TailAbiEnvelopeProgramKind,
    pub label: X64LabelId,
    pub start: u32,
    pub end: u32,
    pub instructions: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailAbiEnvelopeInstructionReceipt {
    pub program: X64TailAbiEnvelopeProgramKind,
    pub ordinal: u32,
    pub start: u32,
    pub end: u32,
    pub effect: X64TailAbiEnvelopeEffect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailAbiEnvelopeRelocationReceipt {
    pub program: X64TailAbiEnvelopeProgramKind,
    pub instruction_ordinal: u32,
    pub patch_offset: u32,
    pub target: X64TailBodyControlTarget,
    pub target_offset: u32,
    pub displacement: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailAbiEnvelopeAnchorReceipt {
    pub offset: u32,
    pub target: X64TailBodyControlTarget,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X64TailAbiEnvelopeTotals {
    pub programs: u32,
    pub instructions: u32,
    pub effects: u32,
    pub input_lanes: u32,
    pub relocations: u32,
    pub anchors: u32,
    pub entry_bytes: u32,
    pub return_bytes: u32,
    pub bounds_bytes: u32,
    pub anchor_bytes: u32,
    pub code_bytes: u32,
    pub encode_work: u64,
    pub decode_work: u64,
    pub replay_work: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailAbiEnvelopeCapsule {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    decoder_policy_version: (u16, u16, u16),
    source_target_semantic_hash: SemanticHash,
    source_closed_image_hash: SemanticHash,
    entry_successor: X64TailBodyControlTarget,
    programs: Vec<X64TailAbiEnvelopeProgramReceipt>,
    instructions: Vec<X64TailAbiEnvelopeInstructionReceipt>,
    relocation: X64TailAbiEnvelopeRelocationReceipt,
    anchor: X64TailAbiEnvelopeAnchorReceipt,
    code: Vec<u8>,
    code_hash: SemanticHash,
    totals: X64TailAbiEnvelopeTotals,
    capsule_hash: SemanticHash,
}

impl X64TailAbiEnvelopeCapsule {
    pub const fn source_target_semantic_hash(&self) -> SemanticHash {
        self.source_target_semantic_hash
    }
    pub const fn source_closed_image_hash(&self) -> SemanticHash {
        self.source_closed_image_hash
    }
    pub const fn entry_successor(&self) -> X64TailBodyControlTarget {
        self.entry_successor
    }
    pub fn programs(&self) -> &[X64TailAbiEnvelopeProgramReceipt] {
        &self.programs
    }
    pub fn instructions(&self) -> &[X64TailAbiEnvelopeInstructionReceipt] {
        &self.instructions
    }
    pub const fn relocation(&self) -> X64TailAbiEnvelopeRelocationReceipt {
        self.relocation
    }
    pub const fn anchor(&self) -> X64TailAbiEnvelopeAnchorReceipt {
        self.anchor
    }
    pub fn code(&self) -> &[u8] {
        &self.code
    }
    pub const fn code_hash(&self) -> SemanticHash {
        self.code_hash
    }
    pub const fn totals(&self) -> X64TailAbiEnvelopeTotals {
        self.totals
    }
    pub const fn capsule_hash(&self) -> SemanticHash {
        self.capsule_hash
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedX64TailAbiEnvelopeCapsule<'capsule> {
    capsule: &'capsule X64TailAbiEnvelopeCapsule,
    decoded: X64TailDecodedAbiEnvelope,
}

impl<'capsule> VerifiedX64TailAbiEnvelopeCapsule<'capsule> {
    pub const fn capsule(&self) -> &'capsule X64TailAbiEnvelopeCapsule {
        self.capsule
    }
    pub const fn decoded(&self) -> &X64TailDecodedAbiEnvelope {
        &self.decoded
    }
}

#[derive(Debug)]
pub enum X64TailAbiEnvelopeError {
    Decode(X64TailAbiEnvelopeDecodeError),
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
    EncodingLimit {
        actual: usize,
    },
    CodeHashMismatch,
    CapsuleHashMismatch,
    ReplayMismatch,
}

impl fmt::Display for X64TailAbiEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(formatter, "ABI-envelope decode failed: {error}"),
            Self::InvalidPredecessor { field } => write!(formatter, "invalid predecessor {field}"),
            Self::InvalidField { field } => write!(formatter, "invalid ABI-envelope field {field}"),
            Self::MissingTarget { field } => {
                write!(formatter, "missing ABI-envelope target {field}")
            }
            Self::LimitExceeded {
                field,
                limit,
                actual,
            } => write!(formatter, "ABI-envelope {field} {actual} exceeds {limit}"),
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "ABI-envelope arithmetic overflow in {field}")
            }
            Self::EncodingLimit { actual } => write!(
                formatter,
                "ABI-envelope evidence size {actual} exceeds its cap"
            ),
            Self::CodeHashMismatch => write!(formatter, "ABI-envelope code hash mismatch"),
            Self::CapsuleHashMismatch => write!(formatter, "ABI-envelope capsule hash mismatch"),
            Self::ReplayMismatch => write!(formatter, "ABI-envelope independent replay mismatch"),
        }
    }
}

impl std::error::Error for X64TailAbiEnvelopeError {}

impl From<X64TailAbiEnvelopeDecodeError> for X64TailAbiEnvelopeError {
    fn from(value: X64TailAbiEnvelopeDecodeError) -> Self {
        Self::Decode(value)
    }
}

pub fn emit_x64_tail_abi_envelope_capsule(
    target: &X64TargetArtifact,
    image: &VerifiedX64TailClosedImage<'_>,
) -> Result<X64TailAbiEnvelopeCapsule, X64TailAbiEnvelopeError> {
    preflight(target, image)?;
    let program = &target.program;
    let entry = entry_function(program)?;
    validate_manifest(program, entry)?;
    let entry_successor = image.image().entry_successor();
    let labels = terminal_labels(program, image)?;
    let mut builder = CodeBuilder::new();

    builder.begin(X64TailAbiEnvelopeProgramKind::EntryAdapter, labels[0])?;
    builder.instruction(X64TailAbiEnvelopeEffect::PushCallerRbp, &[0x55])?;
    builder.instruction(
        X64TailAbiEnvelopeEffect::EstablishFramePointer,
        &[0x48, 0x89, 0xe5],
    )?;
    let mut bytes = vec![0x48, 0x81, 0xec];
    bytes.extend_from_slice(&program.frame.frame_bytes.to_le_bytes());
    builder.instruction(
        X64TailAbiEnvelopeEffect::AllocateFrame {
            bytes: program.frame.frame_bytes,
        },
        &bytes,
    )?;
    builder.instruction(
        X64TailAbiEnvelopeEffect::SaveCallerMxcsr {
            offset: SAVED_MXCSR_OFFSET,
        },
        &mxcsr_bytes(false, SAVED_MXCSR_OFFSET),
    )?;
    builder.instruction(
        X64TailAbiEnvelopeEffect::StoreCanonicalMxcsr {
            offset: CANONICAL_MXCSR_OFFSET,
            value: program.abi.canonical_mxcsr,
        },
        &mem32_imm32_bytes(CANONICAL_MXCSR_OFFSET, program.abi.canonical_mxcsr),
    )?;
    builder.instruction(
        X64TailAbiEnvelopeEffect::LoadCanonicalMxcsr {
            offset: CANONICAL_MXCSR_OFFSET,
        },
        &mxcsr_bytes(true, CANONICAL_MXCSR_OFFSET),
    )?;
    builder.instruction(
        X64TailAbiEnvelopeEffect::SaveOutputPointer {
            offset: OUTPUT_POINTER_OFFSET,
            register: program.entry_abi.output_register,
        },
        &store_frame_gpr_bytes(OUTPUT_POINTER_OFFSET, program.entry_abi.output_register),
    )?;
    for offset in [RESERVED_WORD_0_OFFSET, RESERVED_WORD_1_OFFSET] {
        builder.instruction(
            X64TailAbiEnvelopeEffect::ZeroReservedWord { offset },
            &mem64_imm32_bytes(offset, 0),
        )?;
    }
    for (parameter_index, parameter) in entry.parameters.iter().enumerate() {
        let parameter_index = usize_to_u32(parameter_index, "entry parameter index")?;
        if parameter.home.ty == MachineType::Unit {
            builder.instruction(
                X64TailAbiEnvelopeEffect::ZeroUnitHome {
                    parameter: parameter_index,
                    offset: parameter.home.offset,
                },
                &mem64_imm32_bytes(parameter.home.offset, 0),
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
                .ok_or(X64TailAbiEnvelopeError::ArithmeticOverflow {
                    field: "entry lane offset",
                })?;
            builder.instruction(
                X64TailAbiEnvelopeEffect::StoreInputLane {
                    parameter: parameter_index,
                    word: lane.word,
                    register: lane.register,
                    offset,
                    ty: parameter.home.ty,
                },
                &store_frame_gpr_bytes(offset, lane.register),
            )?;
        }
    }
    let jump_ordinal = builder.next_instruction_ordinal();
    let jump_start = builder.code_len()?;
    builder.instruction(
        X64TailAbiEnvelopeEffect::JumpEntrySuccessor {
            target: entry_successor,
        },
        &[0xe9, 0, 0, 0, 0],
    )?;
    builder.end()?;

    builder.begin(X64TailAbiEnvelopeProgramKind::ReturnEpilogue, labels[1])?;
    emit_return_program(&mut builder, program.frame.frame_bytes)?;
    builder.end()?;

    builder.begin(X64TailAbiEnvelopeProgramKind::BoundsEpilogue, labels[2])?;
    emit_bounds_program(&mut builder, program.frame.frame_bytes)?;
    builder.end()?;

    let anchor_offset = builder.code_len()?;
    builder.push_anchor()?;
    let patch_offset =
        jump_start
            .checked_add(1)
            .ok_or(X64TailAbiEnvelopeError::ArithmeticOverflow {
                field: "entry jump patch",
            })?;
    let displacement = rel32(patch_offset, anchor_offset)?;
    builder.patch_i32(patch_offset, displacement)?;
    let (code, programs, instructions) = builder.finish()?;
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
    let totals = totals(program, &programs, &instructions, code.len())?;
    let code_hash = x64_tail_abi_envelope_code_hash(&code)?;
    let mut capsule = X64TailAbiEnvelopeCapsule {
        schema_version: X64_TAIL_ABI_ENVELOPE_SCHEMA_VERSION,
        policy_version: X64_TAIL_ABI_ENVELOPE_POLICY_VERSION,
        decoder_policy_version: X64_TAIL_ABI_ENVELOPE_DECODER_POLICY_VERSION,
        source_target_semantic_hash: target.semantic_hash,
        source_closed_image_hash: image.image().image_hash(),
        entry_successor,
        programs,
        instructions,
        relocation,
        anchor,
        code,
        code_hash,
        totals,
        capsule_hash: SemanticHash::ZERO,
    };
    capsule.capsule_hash = x64_tail_abi_envelope_capsule_hash(&capsule)?;
    Ok(capsule)
}

pub fn verify_x64_tail_abi_envelope_capsule<'capsule>(
    capsule: &'capsule X64TailAbiEnvelopeCapsule,
    target: &X64TargetArtifact,
    image: &VerifiedX64TailClosedImage<'_>,
) -> Result<VerifiedX64TailAbiEnvelopeCapsule<'capsule>, X64TailAbiEnvelopeError> {
    preflight(target, image)?;
    if capsule.schema_version != X64_TAIL_ABI_ENVELOPE_SCHEMA_VERSION
        || capsule.policy_version != X64_TAIL_ABI_ENVELOPE_POLICY_VERSION
        || capsule.decoder_policy_version != X64_TAIL_ABI_ENVELOPE_DECODER_POLICY_VERSION
        || capsule.source_target_semantic_hash != target.semantic_hash
        || capsule.source_closed_image_hash != image.image().image_hash()
        || capsule.entry_successor != image.image().entry_successor()
    {
        return Err(X64TailAbiEnvelopeError::InvalidField {
            field: "capsule envelope",
        });
    }
    if x64_tail_abi_envelope_code_hash(&capsule.code)? != capsule.code_hash {
        return Err(X64TailAbiEnvelopeError::CodeHashMismatch);
    }
    if x64_tail_abi_envelope_capsule_hash(capsule)? != capsule.capsule_hash {
        return Err(X64TailAbiEnvelopeError::CapsuleHashMismatch);
    }
    let decoded = decode_x64_tail_abi_envelope_capsule(&capsule.code, target, image)?;
    if capsule.programs != decoded.programs
        || capsule.instructions != decoded.instructions
        || capsule.relocation != decoded.relocation
        || capsule.anchor != decoded.anchor
        || capsule.code_hash != decoded.code_hash
        || capsule.totals != decoded.totals
    {
        return Err(X64TailAbiEnvelopeError::ReplayMismatch);
    }
    Ok(VerifiedX64TailAbiEnvelopeCapsule { capsule, decoded })
}

fn emit_return_program(
    builder: &mut CodeBuilder,
    frame_bytes: u32,
) -> Result<(), X64TailAbiEnvelopeError> {
    builder.instruction(
        X64TailAbiEnvelopeEffect::LoadOutputPointer {
            offset: OUTPUT_POINTER_OFFSET,
        },
        &load_frame_rcx_bytes(OUTPUT_POINTER_OFFSET),
    )?;
    builder.instruction(
        X64TailAbiEnvelopeEffect::StoreResultWord { word: 0 },
        &[0x48, 0x89, 0x01],
    )?;
    let mut word_one = vec![0x48, 0x89, 0x91];
    word_one.extend_from_slice(&8_u32.to_le_bytes());
    builder.instruction(
        X64TailAbiEnvelopeEffect::StoreResultWord { word: 1 },
        &word_one,
    )?;
    builder.instruction(
        X64TailAbiEnvelopeEffect::SetStatus { value: 0 },
        &[0x31, 0xc0],
    )?;
    emit_common_exit(builder, frame_bytes)
}

fn emit_bounds_program(
    builder: &mut CodeBuilder,
    frame_bytes: u32,
) -> Result<(), X64TailAbiEnvelopeError> {
    builder.instruction(
        X64TailAbiEnvelopeEffect::LoadOutputPointer {
            offset: OUTPUT_POINTER_OFFSET,
        },
        &load_frame_rcx_bytes(OUTPUT_POINTER_OFFSET),
    )?;
    builder.instruction(X64TailAbiEnvelopeEffect::ZeroResultRegister, &[0x31, 0xc0])?;
    builder.instruction(
        X64TailAbiEnvelopeEffect::StoreZeroResultWord { word: 0 },
        &[0x48, 0x89, 0x01],
    )?;
    let mut word_one = vec![0x48, 0x89, 0x81];
    word_one.extend_from_slice(&8_u32.to_le_bytes());
    builder.instruction(
        X64TailAbiEnvelopeEffect::StoreZeroResultWord { word: 1 },
        &word_one,
    )?;
    let mut status = vec![0xb8];
    status.extend_from_slice(&1_u32.to_le_bytes());
    builder.instruction(X64TailAbiEnvelopeEffect::SetStatus { value: 1 }, &status)?;
    emit_common_exit(builder, frame_bytes)
}

fn emit_common_exit(
    builder: &mut CodeBuilder,
    frame_bytes: u32,
) -> Result<(), X64TailAbiEnvelopeError> {
    builder.instruction(
        X64TailAbiEnvelopeEffect::RestoreCallerMxcsr {
            offset: SAVED_MXCSR_OFFSET,
        },
        &mxcsr_bytes(true, SAVED_MXCSR_OFFSET),
    )?;
    let mut release = vec![0x48, 0x81, 0xc4];
    release.extend_from_slice(&frame_bytes.to_le_bytes());
    builder.instruction(
        X64TailAbiEnvelopeEffect::ReleaseFrame { bytes: frame_bytes },
        &release,
    )?;
    builder.instruction(X64TailAbiEnvelopeEffect::RestoreCallerRbp, &[0x5d])?;
    builder.instruction(X64TailAbiEnvelopeEffect::Return, &[0xc3])
}

fn preflight(
    target: &X64TargetArtifact,
    image: &VerifiedX64TailClosedImage<'_>,
) -> Result<(), X64TailAbiEnvelopeError> {
    verify_x64_target_r1_s7a(target).map_err(|_| X64TailAbiEnvelopeError::InvalidPredecessor {
        field: "verified x86-64 target",
    })?;
    if image.image().source_target_semantic_hash() != target.semantic_hash {
        return Err(X64TailAbiEnvelopeError::InvalidPredecessor {
            field: "closed-image target identity",
        });
    }
    Ok(())
}

fn entry_function(program: &X64TargetProgram) -> Result<&X64Function, X64TailAbiEnvelopeError> {
    program
        .functions
        .iter()
        .find(|function| function.id == program.entry)
        .ok_or(X64TailAbiEnvelopeError::MissingTarget {
            field: "entry function",
        })
}

fn validate_manifest(
    program: &X64TargetProgram,
    entry: &X64Function,
) -> Result<(), X64TailAbiEnvelopeError> {
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
        return Err(X64TailAbiEnvelopeError::InvalidField {
            field: "canonical ABI/frame manifest",
        });
    }
    let mut ranges = BTreeSet::new();
    let mut expected_lanes = Vec::new();
    for (index, parameter) in entry.parameters.iter().enumerate() {
        if program.entry_abi.parameter_types[index] != parameter.home.ty {
            return Err(X64TailAbiEnvelopeError::InvalidField {
                field: "entry parameter type",
            });
        }
        let words = words(parameter.home.ty);
        let expected_width = if words == 0 { 8 } else { words * 8 };
        if u32::from(parameter.home.width) != expected_width
            || parameter.home.offset < FRAME_HEADER_BYTES
        {
            return Err(X64TailAbiEnvelopeError::InvalidField {
                field: "entry home shape",
            });
        }
        let end = parameter
            .home
            .offset
            .checked_add(u32::from(parameter.home.width))
            .ok_or(X64TailAbiEnvelopeError::ArithmeticOverflow {
                field: "entry home end",
            })?;
        if end > program.frame.frame_bytes {
            return Err(X64TailAbiEnvelopeError::InvalidField {
                field: "entry home extent",
            });
        }
        for byte in parameter.home.offset..end {
            if !ranges.insert(byte) {
                return Err(X64TailAbiEnvelopeError::InvalidField {
                    field: "overlapping entry homes",
                });
            }
        }
        let parameter = usize_to_u32(index, "entry parameter index")?;
        for word in 0..words {
            expected_lanes.push((parameter, word as u8));
        }
    }
    if expected_lanes.len() != program.entry_abi.input_lanes.len() {
        return Err(X64TailAbiEnvelopeError::InvalidField {
            field: "entry lane count",
        });
    }
    for (ordinal, ((parameter, word), lane)) in expected_lanes
        .iter()
        .zip(&program.entry_abi.input_lanes)
        .enumerate()
    {
        if lane.parameter != *parameter
            || lane.word != *word
            || lane.register != ABI_REGISTERS[ordinal]
        {
            return Err(X64TailAbiEnvelopeError::InvalidField {
                field: "canonical entry lane order",
            });
        }
    }
    if program.entry_abi.output_register != ABI_REGISTERS[expected_lanes.len()] {
        return Err(X64TailAbiEnvelopeError::InvalidField {
            field: "canonical output-pointer register",
        });
    }
    Ok(())
}

fn words(ty: MachineType) -> u32 {
    match ty {
        MachineType::Unit => 0,
        MachineType::Bool | MachineType::I64 | MachineType::F64 => 1,
        MachineType::F64Array => 2,
    }
}

fn terminal_labels(
    program: &X64TargetProgram,
    image: &VerifiedX64TailClosedImage<'_>,
) -> Result<[X64LabelId; 3], X64TailAbiEnvelopeError> {
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
        let mut target_labels = program.labels.iter().filter(|label| label.owner == owner);
        let target_label = target_labels
            .next()
            .ok_or(X64TailAbiEnvelopeError::MissingTarget {
                field: "terminal label",
            })?;
        if target_labels.next().is_some() {
            return Err(X64TailAbiEnvelopeError::InvalidField {
                field: "unique terminal label",
            });
        }
        let image_labels = image
            .image()
            .terminal_receipts()
            .iter()
            .filter(|terminal| terminal.kind == kind)
            .collect::<Vec<_>>();
        if image_labels.len() != 1 || image_labels[0].label != target_label.id {
            return Err(X64TailAbiEnvelopeError::InvalidPredecessor {
                field: "closed-image terminal label",
            });
        }
        labels[index] = target_label.id;
    }
    Ok(labels)
}

fn totals(
    program: &X64TargetProgram,
    programs: &[X64TailAbiEnvelopeProgramReceipt],
    instructions: &[X64TailAbiEnvelopeInstructionReceipt],
    code_len: usize,
) -> Result<X64TailAbiEnvelopeTotals, X64TailAbiEnvelopeError> {
    if programs.len() != 3
        || instructions.len() as u64 > u64::from(X64_TAIL_ABI_ENVELOPE_MAX_INSTRUCTIONS)
    {
        return Err(X64TailAbiEnvelopeError::LimitExceeded {
            field: "program/instruction count",
            limit: u64::from(X64_TAIL_ABI_ENVELOPE_MAX_INSTRUCTIONS),
            actual: instructions.len() as u64,
        });
    }
    let code_bytes = usize_to_u32(code_len, "code bytes")?;
    if code_bytes > X64_TAIL_ABI_ENVELOPE_MAX_CODE_BYTES {
        return Err(X64TailAbiEnvelopeError::LimitExceeded {
            field: "code bytes",
            limit: u64::from(X64_TAIL_ABI_ENVELOPE_MAX_CODE_BYTES),
            actual: u64::from(code_bytes),
        });
    }
    let instructions_len = usize_to_u32(instructions.len(), "instructions")?;
    let common_work = u64::from(code_bytes)
        .checked_add(u64::from(instructions_len) * 2)
        .and_then(|value| value.checked_add(4))
        .ok_or(X64TailAbiEnvelopeError::ArithmeticOverflow {
            field: "capsule work",
        })?;
    let replay_work = u64::from(instructions_len)
        .checked_add(program.entry_abi.input_lanes.len() as u64)
        .and_then(|value| value.checked_add(3))
        .ok_or(X64TailAbiEnvelopeError::ArithmeticOverflow {
            field: "replay work",
        })?;
    if common_work > X64_TAIL_ABI_ENVELOPE_MAX_WORK || replay_work > X64_TAIL_ABI_ENVELOPE_MAX_WORK
    {
        return Err(X64TailAbiEnvelopeError::LimitExceeded {
            field: "work",
            limit: X64_TAIL_ABI_ENVELOPE_MAX_WORK,
            actual: common_work.max(replay_work),
        });
    }
    Ok(X64TailAbiEnvelopeTotals {
        programs: 3,
        instructions: instructions_len,
        effects: instructions_len,
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

pub fn x64_tail_abi_envelope_code_hash(
    code: &[u8],
) -> Result<SemanticHash, X64TailAbiEnvelopeError> {
    if code.len() as u64 > u64::from(X64_TAIL_ABI_ENVELOPE_MAX_CODE_BYTES) {
        return Err(X64TailAbiEnvelopeError::LimitExceeded {
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

pub fn x64_tail_abi_envelope_capsule_hash(
    capsule: &X64TailAbiEnvelopeCapsule,
) -> Result<SemanticHash, X64TailAbiEnvelopeError> {
    let mut encoder = EvidenceEncoder::new();
    encoder.bytes(CAPSULE_DOMAIN)?;
    encoder.version(capsule.schema_version);
    encoder.version(capsule.policy_version);
    encoder.version(capsule.decoder_policy_version);
    encoder.hash(capsule.source_target_semantic_hash);
    encoder.hash(capsule.source_closed_image_hash);
    encoder.control(capsule.entry_successor);
    encoder.vec_len(capsule.programs.len())?;
    for program in &capsule.programs {
        encoder.u8(program_tag(program.kind));
        encoder.u32(program.label.0);
        encoder.u32(program.start);
        encoder.u32(program.end);
        encoder.u32(program.instructions);
    }
    encoder.vec_len(capsule.instructions.len())?;
    for instruction in &capsule.instructions {
        encoder.u8(program_tag(instruction.program));
        encoder.u32(instruction.ordinal);
        encoder.u32(instruction.start);
        encoder.u32(instruction.end);
        encode_effect(&mut encoder, instruction.effect);
    }
    let relocation = capsule.relocation;
    encoder.u8(program_tag(relocation.program));
    encoder.u32(relocation.instruction_ordinal);
    encoder.u32(relocation.patch_offset);
    encoder.control(relocation.target);
    encoder.u32(relocation.target_offset);
    encoder.i32(relocation.displacement);
    encoder.u32(capsule.anchor.offset);
    encoder.control(capsule.anchor.target);
    encoder.hash(capsule.code_hash);
    encode_totals(&mut encoder, capsule.totals);
    encoder.bytes(&capsule.code)?;
    Ok(SemanticHash(sha256(&encoder.finish())))
}

fn encode_totals(encoder: &mut EvidenceEncoder, totals: X64TailAbiEnvelopeTotals) {
    for value in [
        totals.programs,
        totals.instructions,
        totals.effects,
        totals.input_lanes,
        totals.relocations,
        totals.anchors,
        totals.entry_bytes,
        totals.return_bytes,
        totals.bounds_bytes,
        totals.anchor_bytes,
        totals.code_bytes,
    ] {
        encoder.u32(value);
    }
    encoder.u64(totals.encode_work);
    encoder.u64(totals.decode_work);
    encoder.u64(totals.replay_work);
}

fn encode_effect(encoder: &mut EvidenceEncoder, effect: X64TailAbiEnvelopeEffect) {
    match effect {
        X64TailAbiEnvelopeEffect::PushCallerRbp => encoder.u8(0),
        X64TailAbiEnvelopeEffect::EstablishFramePointer => encoder.u8(1),
        X64TailAbiEnvelopeEffect::AllocateFrame { bytes } => {
            encoder.u8(2);
            encoder.u32(bytes);
        }
        X64TailAbiEnvelopeEffect::SaveCallerMxcsr { offset } => {
            encoder.u8(3);
            encoder.u32(offset);
        }
        X64TailAbiEnvelopeEffect::StoreCanonicalMxcsr { offset, value } => {
            encoder.u8(4);
            encoder.u32(offset);
            encoder.u32(value);
        }
        X64TailAbiEnvelopeEffect::LoadCanonicalMxcsr { offset } => {
            encoder.u8(5);
            encoder.u32(offset);
        }
        X64TailAbiEnvelopeEffect::SaveOutputPointer { offset, register } => {
            encoder.u8(6);
            encoder.u32(offset);
            encoder.u8(register_tag(register));
        }
        X64TailAbiEnvelopeEffect::ZeroReservedWord { offset } => {
            encoder.u8(7);
            encoder.u32(offset);
        }
        X64TailAbiEnvelopeEffect::ZeroUnitHome { parameter, offset } => {
            encoder.u8(8);
            encoder.u32(parameter);
            encoder.u32(offset);
        }
        X64TailAbiEnvelopeEffect::StoreInputLane {
            parameter,
            word,
            register,
            offset,
            ty,
        } => {
            encoder.u8(9);
            encoder.u32(parameter);
            encoder.u8(word);
            encoder.u8(register_tag(register));
            encoder.u32(offset);
            encoder.u8(type_tag(ty));
        }
        X64TailAbiEnvelopeEffect::JumpEntrySuccessor { target } => {
            encoder.u8(10);
            encoder.control(target);
        }
        X64TailAbiEnvelopeEffect::LoadOutputPointer { offset } => {
            encoder.u8(11);
            encoder.u32(offset);
        }
        X64TailAbiEnvelopeEffect::StoreResultWord { word } => {
            encoder.u8(12);
            encoder.u8(word);
        }
        X64TailAbiEnvelopeEffect::ZeroResultRegister => encoder.u8(13),
        X64TailAbiEnvelopeEffect::StoreZeroResultWord { word } => {
            encoder.u8(14);
            encoder.u8(word);
        }
        X64TailAbiEnvelopeEffect::SetStatus { value } => {
            encoder.u8(15);
            encoder.u32(value);
        }
        X64TailAbiEnvelopeEffect::RestoreCallerMxcsr { offset } => {
            encoder.u8(16);
            encoder.u32(offset);
        }
        X64TailAbiEnvelopeEffect::ReleaseFrame { bytes } => {
            encoder.u8(17);
            encoder.u32(bytes);
        }
        X64TailAbiEnvelopeEffect::RestoreCallerRbp => encoder.u8(18),
        X64TailAbiEnvelopeEffect::Return => encoder.u8(19),
    }
}

fn program_tag(kind: X64TailAbiEnvelopeProgramKind) -> u8 {
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

fn type_tag(ty: MachineType) -> u8 {
    match ty {
        MachineType::Unit => 0,
        MachineType::Bool => 1,
        MachineType::I64 => 2,
        MachineType::F64 => 3,
        MachineType::F64Array => 4,
    }
}

fn store_frame_gpr_bytes(offset: u32, register: X64AbiRegister) -> Vec<u8> {
    let number = register_number(register);
    let rex = 0x48 | if number >= 8 { 0x04 } else { 0 };
    let modrm = 0x84 | ((number & 7) << 3);
    let mut bytes = vec![rex, 0x89, modrm, 0x24];
    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes
}

fn load_frame_rcx_bytes(offset: u32) -> Vec<u8> {
    let mut bytes = vec![0x48, 0x8b, 0x8c, 0x24];
    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes
}

fn mem32_imm32_bytes(offset: u32, value: u32) -> Vec<u8> {
    let mut bytes = vec![0xc7, 0x84, 0x24];
    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes
}

fn mem64_imm32_bytes(offset: u32, value: u32) -> Vec<u8> {
    let mut bytes = vec![0x48, 0xc7, 0x84, 0x24];
    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes
}

fn mxcsr_bytes(load: bool, offset: u32) -> Vec<u8> {
    let mut bytes = vec![0x0f, 0xae, if load { 0x94 } else { 0x9c }, 0x24];
    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes
}

fn rel32(patch_offset: u32, target_offset: u32) -> Result<i32, X64TailAbiEnvelopeError> {
    let source_end = i64::from(patch_offset).checked_add(4).ok_or(
        X64TailAbiEnvelopeError::ArithmeticOverflow {
            field: "rel32 source end",
        },
    )?;
    let displacement = i64::from(target_offset).checked_sub(source_end).ok_or(
        X64TailAbiEnvelopeError::ArithmeticOverflow {
            field: "rel32 displacement",
        },
    )?;
    i32::try_from(displacement).map_err(|_| X64TailAbiEnvelopeError::InvalidField {
        field: "rel32 range",
    })
}

struct OpenProgram {
    kind: X64TailAbiEnvelopeProgramKind,
    label: X64LabelId,
    start: u32,
    instruction_start: usize,
}

struct CodeBuilder {
    code: Vec<u8>,
    programs: Vec<X64TailAbiEnvelopeProgramReceipt>,
    instructions: Vec<X64TailAbiEnvelopeInstructionReceipt>,
    open: Option<OpenProgram>,
}

type FinishedCode = (
    Vec<u8>,
    Vec<X64TailAbiEnvelopeProgramReceipt>,
    Vec<X64TailAbiEnvelopeInstructionReceipt>,
);

impl CodeBuilder {
    fn new() -> Self {
        Self {
            code: Vec::new(),
            programs: Vec::new(),
            instructions: Vec::new(),
            open: None,
        }
    }
    fn begin(
        &mut self,
        kind: X64TailAbiEnvelopeProgramKind,
        label: X64LabelId,
    ) -> Result<(), X64TailAbiEnvelopeError> {
        if self.open.is_some() {
            return Err(X64TailAbiEnvelopeError::InvalidField {
                field: "nested program",
            });
        }
        self.open = Some(OpenProgram {
            kind,
            label,
            start: self.code_len()?,
            instruction_start: self.instructions.len(),
        });
        Ok(())
    }
    fn instruction(
        &mut self,
        effect: X64TailAbiEnvelopeEffect,
        bytes: &[u8],
    ) -> Result<(), X64TailAbiEnvelopeError> {
        let open = self
            .open
            .as_ref()
            .ok_or(X64TailAbiEnvelopeError::InvalidField {
                field: "instruction outside program",
            })?;
        if bytes.is_empty() {
            return Err(X64TailAbiEnvelopeError::InvalidField {
                field: "empty instruction",
            });
        }
        let start = self.code_len()?;
        let next = self.code.len().checked_add(bytes.len()).ok_or(
            X64TailAbiEnvelopeError::ArithmeticOverflow {
                field: "code bytes",
            },
        )?;
        if next > X64_TAIL_ABI_ENVELOPE_MAX_CODE_BYTES as usize {
            return Err(X64TailAbiEnvelopeError::LimitExceeded {
                field: "code bytes",
                limit: u64::from(X64_TAIL_ABI_ENVELOPE_MAX_CODE_BYTES),
                actual: next as u64,
            });
        }
        self.code.extend_from_slice(bytes);
        let end = self.code_len()?;
        let ordinal = usize_to_u32(
            self.instructions.len() - open.instruction_start,
            "instruction ordinal",
        )?;
        self.instructions
            .push(X64TailAbiEnvelopeInstructionReceipt {
                program: open.kind,
                ordinal,
                start,
                end,
                effect,
            });
        if self.instructions.len() as u64 > u64::from(X64_TAIL_ABI_ENVELOPE_MAX_INSTRUCTIONS) {
            return Err(X64TailAbiEnvelopeError::LimitExceeded {
                field: "instructions",
                limit: u64::from(X64_TAIL_ABI_ENVELOPE_MAX_INSTRUCTIONS),
                actual: self.instructions.len() as u64,
            });
        }
        Ok(())
    }
    fn next_instruction_ordinal(&self) -> u32 {
        self.open.as_ref().map_or(0, |open| {
            (self.instructions.len() - open.instruction_start) as u32
        })
    }
    fn end(&mut self) -> Result<(), X64TailAbiEnvelopeError> {
        let open = self
            .open
            .take()
            .ok_or(X64TailAbiEnvelopeError::InvalidField {
                field: "program end",
            })?;
        self.programs.push(X64TailAbiEnvelopeProgramReceipt {
            kind: open.kind,
            label: open.label,
            start: open.start,
            end: self.code_len()?,
            instructions: usize_to_u32(
                self.instructions.len() - open.instruction_start,
                "program instructions",
            )?,
        });
        Ok(())
    }
    fn push_anchor(&mut self) -> Result<(), X64TailAbiEnvelopeError> {
        if self.open.is_some() {
            return Err(X64TailAbiEnvelopeError::InvalidField {
                field: "anchor inside program",
            });
        }
        self.code.push(ENTRY_TARGET_ANCHOR_BYTE);
        Ok(())
    }
    fn patch_i32(&mut self, offset: u32, value: i32) -> Result<(), X64TailAbiEnvelopeError> {
        let start =
            usize::try_from(offset).map_err(|_| X64TailAbiEnvelopeError::ArithmeticOverflow {
                field: "patch offset",
            })?;
        let end = start
            .checked_add(4)
            .ok_or(X64TailAbiEnvelopeError::ArithmeticOverflow { field: "patch end" })?;
        let slice = self
            .code
            .get_mut(start..end)
            .ok_or(X64TailAbiEnvelopeError::InvalidField {
                field: "patch range",
            })?;
        slice.copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn code_len(&self) -> Result<u32, X64TailAbiEnvelopeError> {
        usize_to_u32(self.code.len(), "code length")
    }
    fn finish(self) -> Result<FinishedCode, X64TailAbiEnvelopeError> {
        if self.open.is_some() || self.programs.len() != 3 {
            return Err(X64TailAbiEnvelopeError::InvalidField {
                field: "complete programs",
            });
        }
        Ok((self.code, self.programs, self.instructions))
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
        match value {
            X64TailBodyControlTarget::Label(label) => {
                self.u8(0);
                self.u32(label.0);
            }
            X64TailBodyControlTarget::Frontier(ordinal) => {
                self.u8(1);
                self.u32(ordinal);
            }
        }
    }
    fn vec_len(&mut self, length: usize) -> Result<(), X64TailAbiEnvelopeError> {
        self.u32(usize_to_u32(length, "evidence vector")?);
        Ok(())
    }
    fn bytes(&mut self, value: &[u8]) -> Result<(), X64TailAbiEnvelopeError> {
        let next = self.bytes.len().checked_add(value.len()).ok_or(
            X64TailAbiEnvelopeError::ArithmeticOverflow {
                field: "evidence bytes",
            },
        )?;
        if next > X64_TAIL_ABI_ENVELOPE_MAX_EVIDENCE_BYTES {
            return Err(X64TailAbiEnvelopeError::EncodingLimit { actual: next });
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }
    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn usize_to_u32(value: usize, field: &'static str) -> Result<u32, X64TailAbiEnvelopeError> {
    u32::try_from(value).map_err(|_| X64TailAbiEnvelopeError::ArithmeticOverflow { field })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::corevm0_gate_a::{CoreVmGateAWorkload, CoreVmGateAWorkload::BranchMix};
    use crate::core::x64_native_lighthouse::X64NativeLighthousePackage;
    use crate::core::{
        emit_x64_tail_body_frontier_capsule, emit_x64_tail_body_frontier_realization,
        emit_x64_tail_candidate_capsule, emit_x64_tail_closed_image,
        emit_x64_tail_physical_allocation, emit_x64_tail_site_binding_proof,
        emit_x64_tail_state_plan, emit_x64_tail_template_realization, verify_x64_tail_closed_image,
        X64TailBodyFrontierCapsule, X64TailBodyFrontierRealization, X64TailCandidateCapsule,
        X64TailClosedImage, X64TailPhysicalAllocation, X64TailSiteBindingProof, X64TailStatePlan,
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
    );

    fn build(workload: CoreVmGateAWorkload) -> Build {
        let package =
            X64NativeLighthousePackage::build(workload).expect("lighthouse package must build");
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
        .expect("closed image must emit");
        (
            package,
            logical,
            physical,
            templates,
            transition,
            binding,
            realization,
            body,
            image,
        )
    }

    #[test]
    fn branch_mix_owns_one_sovereign_non_executable_abi_capsule() {
        let (package, logical, physical, templates, transition, binding, realization, body, image) =
            build(BranchMix);
        let verified_image = verify_x64_tail_closed_image(
            &image,
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
        let original_target = package.target().program.code.clone();
        let original_target_hash = package.target().program.code_hash;
        let original_image = image.clone();
        let first = emit_x64_tail_abi_envelope_capsule(package.target(), &verified_image)
            .expect("ABI capsule must emit");
        let second = emit_x64_tail_abi_envelope_capsule(package.target(), &verified_image)
            .expect("ABI capsule must be deterministic");
        assert_eq!(first, second);
        let verified =
            verify_x64_tail_abi_envelope_capsule(&first, package.target(), &verified_image)
                .expect("ABI capsule must independently replay");
        assert_eq!(verified.decoded().totals, first.totals());
        assert_eq!(first.programs().len(), 3);
        assert_eq!(first.relocation().target, image.entry_successor());
        assert_eq!(first.anchor().target, image.entry_successor());
        assert_eq!(
            first.code()[first.anchor().offset as usize],
            ENTRY_TARGET_ANCHOR_BYTE
        );
        assert_eq!(first.totals().programs, 3);
        assert_eq!(first.totals().relocations, 1);
        assert_eq!(first.totals().anchors, 1);
        assert_eq!(first.totals().input_lanes, 3);
        assert_eq!(
            first.capsule_hash().to_hex(),
            "6bdf9fd8d8221557728bb183877ebddbc954b4fa426393a1d98deddad51bf937"
        );
        assert_eq!(
            first.code_hash().to_hex(),
            "5f83b79e74e85dc2d77eb30c0b6eacb63c100030feaf3a6107e0b50a7ba64bbb"
        );
        assert_eq!(
            first.totals(),
            X64TailAbiEnvelopeTotals {
                programs: 3,
                instructions: 30,
                effects: 30,
                input_lanes: 3,
                relocations: 1,
                anchors: 1,
                entry_bytes: 99,
                return_bytes: 37,
                bounds_bytes: 42,
                anchor_bytes: 1,
                code_bytes: 179,
                encode_work: 243,
                decode_work: 243,
                replay_work: 36,
            }
        );

        // The historical raw blob is redundant test evidence only. The new
        // capsule does not import its encoder or consume these bytes.
        let target_program = &package.target().program;
        let label_offset = |owner| {
            target_program
                .labels
                .iter()
                .find(|label| label.owner == owner)
                .expect("historical label must exist")
                .code_offset as usize
        };
        let entry_start = label_offset(X64LabelOwner::EntryAdapter);
        let entry_end = target_program
            .labels
            .iter()
            .filter_map(|label| match label.owner {
                X64LabelOwner::Block { .. } => Some(label.code_offset as usize),
                _ => None,
            })
            .min()
            .expect("historical first block must exist");
        let return_start = label_offset(X64LabelOwner::ReturnEpilogue);
        let bounds_start = label_offset(X64LabelOwner::BoundsEpilogue);
        let entry_program = first.programs()[0];
        let return_program = first.programs()[1];
        let bounds_program = first.programs()[2];
        let new_entry = &first.code()[entry_program.start as usize..entry_program.end as usize];
        let old_entry = &target_program.code[entry_start..entry_end];
        assert_eq!(new_entry.len(), old_entry.len());
        let patch = (first.relocation().patch_offset - entry_program.start) as usize;
        assert_eq!(&new_entry[..patch], &old_entry[..patch]);
        assert_eq!(&new_entry[patch + 4..], &old_entry[patch + 4..]);
        assert_eq!(
            &first.code()[return_program.start as usize..return_program.end as usize],
            &target_program.code[return_start..bounds_start]
        );
        assert_eq!(
            &first.code()[bounds_program.start as usize..bounds_program.end as usize],
            &target_program.code[bounds_start..]
        );
        assert_eq!(image, original_image);
        assert_eq!(package.target().program.code, original_target);
        assert_eq!(package.target().program.code_hash, original_target_hash);
        assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
    }

    #[test]
    fn every_abi_capsule_bit_and_resealed_evidence_mutation_fails_closed() {
        let (package, logical, physical, templates, transition, binding, realization, body, image) =
            build(BranchMix);
        let verified_image = verify_x64_tail_closed_image(
            &image,
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
        let capsule = emit_x64_tail_abi_envelope_capsule(package.target(), &verified_image)
            .expect("ABI capsule must emit");

        for byte in 0..capsule.code.len() {
            for bit in 0..8 {
                let mut code = capsule.code.clone();
                code[byte] ^= 1 << bit;
                assert!(decode_x64_tail_abi_envelope_capsule(
                    &code,
                    package.target(),
                    &verified_image,
                )
                .is_err());
            }
        }
        assert!(decode_x64_tail_abi_envelope_capsule(
            &capsule.code[..capsule.code.len() - 1],
            package.target(),
            &verified_image,
        )
        .is_err());
        let mut trailing = capsule.code.clone();
        trailing.push(ENTRY_TARGET_ANCHOR_BYTE);
        assert!(
            decode_x64_tail_abi_envelope_capsule(&trailing, package.target(), &verified_image,)
                .is_err()
        );

        macro_rules! reject_resealed {
            ($mutated:ident) => {{
                $mutated.capsule_hash = x64_tail_abi_envelope_capsule_hash(&$mutated)
                    .expect("mutation must locally reseal");
                assert!(verify_x64_tail_abi_envelope_capsule(
                    &$mutated,
                    package.target(),
                    &verified_image,
                )
                .is_err());
            }};
        }

        let mut program = capsule.clone();
        program.programs[0].end ^= 1;
        reject_resealed!(program);

        let mut instruction = capsule.clone();
        instruction.instructions[0].end ^= 1;
        reject_resealed!(instruction);

        let mut effect = capsule.clone();
        effect.instructions[0].effect = X64TailAbiEnvelopeEffect::Return;
        reject_resealed!(effect);

        let mut relocation = capsule.clone();
        relocation.relocation.target_offset ^= 1;
        reject_resealed!(relocation);

        let mut anchor = capsule.clone();
        anchor.anchor.offset ^= 1;
        reject_resealed!(anchor);

        let mut totals = capsule.clone();
        totals.totals.instructions ^= 1;
        reject_resealed!(totals);

        let mut predecessor = capsule.clone();
        predecessor.source_closed_image_hash.0[0] ^= 1;
        reject_resealed!(predecessor);

        let mut target_predecessor = capsule.clone();
        target_predecessor.source_target_semantic_hash.0[0] ^= 1;
        reject_resealed!(target_predecessor);

        let mut version = capsule.clone();
        version.policy_version.2 ^= 1;
        reject_resealed!(version);

        let mut code = capsule.clone();
        code.code[0] ^= 1;
        code.code_hash =
            x64_tail_abi_envelope_code_hash(&code.code).expect("mutated code must locally hash");
        reject_resealed!(code);

        let mut code_hash = capsule.clone();
        code_hash.code_hash.0[0] ^= 1;
        reject_resealed!(code_hash);

        let mut seal = capsule;
        seal.capsule_hash.0[0] ^= 1;
        assert!(
            verify_x64_tail_abi_envelope_capsule(&seal, package.target(), &verified_image,)
                .is_err()
        );
    }
}
