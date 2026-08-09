//! Owned non-executable ADR-0060 x86-64 byte capsule for ADR-0059 tail
//! templates.
//!
//! This module is a closed encoder and evidence owner. It exposes immutable
//! bytes as data only; it has no mapping, linking, process, ELF, timing, or
//! native-call API. Verification delegates inverse parsing to the separately
//! implemented decoder module.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_candidate_decode::{
    decode_x64_tail_candidate_bytes, X64TailCandidateDecodeError, X64TailDecodedCapsule,
};
use super::x64_tail_state_allocation::X64TailPhysicalAllocation;
use super::x64_tail_state_plan::{X64TailImmediateWord, X64TailStatePlan};
use super::x64_tail_template_realization::{
    verify_x64_tail_template_realization, X64TailTemplateGpr, X64TailTemplateInstruction,
    X64TailTemplateRealization, X64TailTemplateRealizationError, X64TailTemplateXmm,
};
use super::x64_target::{X64LabelId, X64TargetArtifact};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const X64_TAIL_CANDIDATE_CAPSULE_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_CANDIDATE_CAPSULE_POLICY_VERSION: (u16, u16, u16) = (1, 1, 0);
pub const X64_TAIL_CANDIDATE_CAPSULE_MAX_TRANSITIONS: u32 = 4_096;
pub const X64_TAIL_CANDIDATE_CAPSULE_MAX_ATOMS: u32 = 65_536;
pub const X64_TAIL_CANDIDATE_CAPSULE_MAX_ANCHORS: u32 = 4_096;
pub const X64_TAIL_CANDIDATE_CAPSULE_MAX_FIXUPS: u32 = 4_096;
pub const X64_TAIL_CANDIDATE_CAPSULE_MAX_CODE_BYTES: u64 = 65 * 1024 * 1024;
pub const X64_TAIL_CANDIDATE_CAPSULE_MAX_ENCODER_WORK: u64 = 2_000_000;

const CODE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-candidate-code:v1\0";
const CAPSULE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-candidate-capsule:v1\0";
const MAX_CAPSULE_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;
const TARGET_ANCHOR_BYTE: u8 = 0xcc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailCandidateTransitionReceipt {
    pub edge_ordinal: u32,
    pub start: u32,
    pub end: u32,
    pub atom_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailCandidateAnchorReceipt {
    pub label: X64LabelId,
    pub offset: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailCandidateFixupReceipt {
    pub edge_ordinal: u32,
    pub atom_ordinal: u32,
    pub patch_offset: u32,
    pub target: X64LabelId,
    pub target_offset: u32,
    pub displacement: i32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X64TailCandidateCapsuleTotals {
    pub transitions: u32,
    pub atoms: u32,
    pub anchors: u32,
    pub resolved_fixups: u32,
    pub transition_bytes: u32,
    pub anchor_bytes: u32,
    pub code_bytes: u32,
    pub encoder_work: u64,
    pub decoder_work: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailCandidateCapsule {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    source_target_semantic_hash: SemanticHash,
    source_logical_plan_hash: SemanticHash,
    source_physical_allocation_hash: SemanticHash,
    source_template_realization_hash: SemanticHash,
    transition_receipts: Vec<X64TailCandidateTransitionReceipt>,
    anchor_receipts: Vec<X64TailCandidateAnchorReceipt>,
    fixup_receipts: Vec<X64TailCandidateFixupReceipt>,
    code: Vec<u8>,
    code_hash: SemanticHash,
    totals: X64TailCandidateCapsuleTotals,
    capsule_hash: SemanticHash,
}

impl X64TailCandidateCapsule {
    pub const fn source_target_semantic_hash(&self) -> SemanticHash {
        self.source_target_semantic_hash
    }

    pub const fn source_logical_plan_hash(&self) -> SemanticHash {
        self.source_logical_plan_hash
    }

    pub const fn source_physical_allocation_hash(&self) -> SemanticHash {
        self.source_physical_allocation_hash
    }

    pub const fn source_template_realization_hash(&self) -> SemanticHash {
        self.source_template_realization_hash
    }

    pub fn transition_receipts(&self) -> &[X64TailCandidateTransitionReceipt] {
        &self.transition_receipts
    }

    pub fn anchor_receipts(&self) -> &[X64TailCandidateAnchorReceipt] {
        &self.anchor_receipts
    }

    pub fn fixup_receipts(&self) -> &[X64TailCandidateFixupReceipt] {
        &self.fixup_receipts
    }

    pub fn code(&self) -> &[u8] {
        &self.code
    }

    pub const fn code_hash(&self) -> SemanticHash {
        self.code_hash
    }

    pub const fn totals(&self) -> X64TailCandidateCapsuleTotals {
        self.totals
    }

    pub const fn capsule_hash(&self) -> SemanticHash {
        self.capsule_hash
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedX64TailCandidateCapsule<'capsule> {
    capsule: &'capsule X64TailCandidateCapsule,
    decoded: X64TailDecodedCapsule,
}

impl<'capsule> VerifiedX64TailCandidateCapsule<'capsule> {
    pub const fn capsule(&self) -> &'capsule X64TailCandidateCapsule {
        self.capsule
    }

    pub const fn decoded(&self) -> &X64TailDecodedCapsule {
        &self.decoded
    }
}

#[derive(Debug)]
pub enum X64TailCandidateCapsuleError {
    Template(X64TailTemplateRealizationError),
    Decode(X64TailCandidateDecodeError),
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
    Rel32OutOfRange {
        edge: u32,
        displacement: i64,
    },
    EncodingLimit {
        actual: usize,
    },
    CodeHashMismatch,
    CapsuleHashMismatch,
    ReplayMismatch,
}

impl fmt::Display for X64TailCandidateCapsuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Template(error) => write!(formatter, "tail candidate input failed: {error}"),
            Self::Decode(error) => write!(formatter, "tail candidate decode failed: {error}"),
            Self::InvalidField { field } => write!(formatter, "tail candidate capsule has invalid {field}"),
            Self::LimitExceeded { field, limit, actual } => write!(formatter, "tail candidate capsule {field} uses {actual}; limit is {limit}"),
            Self::ArithmeticOverflow { field } => write!(formatter, "tail candidate capsule overflowed {field}"),
            Self::Rel32OutOfRange { edge, displacement } => write!(formatter, "tail candidate edge {edge} rel32 displacement {displacement} is out of range"),
            Self::EncodingLimit { actual } => write!(formatter, "tail candidate capsule encoding uses {actual} bytes; limit is {MAX_CAPSULE_EVIDENCE_BYTES}"),
            Self::CodeHashMismatch => formatter.write_str("tail candidate code hash does not replay"),
            Self::CapsuleHashMismatch => formatter.write_str("tail candidate capsule seal does not replay"),
            Self::ReplayMismatch => formatter.write_str("tail candidate capsule differs from canonical regeneration"),
        }
    }
}

impl std::error::Error for X64TailCandidateCapsuleError {}

impl From<X64TailTemplateRealizationError> for X64TailCandidateCapsuleError {
    fn from(value: X64TailTemplateRealizationError) -> Self {
        Self::Template(value)
    }
}

impl From<X64TailCandidateDecodeError> for X64TailCandidateCapsuleError {
    fn from(value: X64TailCandidateDecodeError) -> Self {
        Self::Decode(value)
    }
}

/// Encode the exact ADR-0059 vocabulary into a sealed non-executable capsule.
pub fn emit_x64_tail_candidate_capsule(
    target: &X64TargetArtifact,
    logical: &X64TailStatePlan,
    physical: &X64TailPhysicalAllocation,
    realization: &X64TailTemplateRealization,
) -> Result<X64TailCandidateCapsule, X64TailCandidateCapsuleError> {
    verify_x64_tail_template_realization(realization, physical, logical, target)?;
    construct_capsule(target, logical, physical, realization)
}

/// Reverify all predecessors, seals, owned encoding, independently decoded
/// machine shape, concrete rel32 targets, redundant receipts, and exact
/// canonical regeneration.
pub fn verify_x64_tail_candidate_capsule<'capsule>(
    capsule: &'capsule X64TailCandidateCapsule,
    realization: &X64TailTemplateRealization,
    physical: &X64TailPhysicalAllocation,
    logical: &X64TailStatePlan,
    target: &X64TargetArtifact,
) -> Result<VerifiedX64TailCandidateCapsule<'capsule>, X64TailCandidateCapsuleError> {
    verify_x64_tail_template_realization(realization, physical, logical, target)?;
    validate_envelope(capsule, realization, physical, logical, target)?;
    if x64_tail_candidate_code_hash(&capsule.code)? != capsule.code_hash {
        return Err(X64TailCandidateCapsuleError::CodeHashMismatch);
    }
    if x64_tail_candidate_capsule_hash(capsule)? != capsule.capsule_hash {
        return Err(X64TailCandidateCapsuleError::CapsuleHashMismatch);
    }
    let decoded = decode_x64_tail_candidate_bytes(&capsule.code, realization, target)?;
    audit_receipts_and_totals(capsule, &decoded)?;
    let replayed = construct_capsule(target, logical, physical, realization)?;
    if replayed != *capsule {
        return Err(X64TailCandidateCapsuleError::ReplayMismatch);
    }
    Ok(VerifiedX64TailCandidateCapsule { capsule, decoded })
}

pub fn x64_tail_candidate_code_hash(
    code: &[u8],
) -> Result<SemanticHash, X64TailCandidateCapsuleError> {
    let code_bytes = usize_to_u64(code.len(), "code bytes")?;
    if code_bytes > X64_TAIL_CANDIDATE_CAPSULE_MAX_CODE_BYTES {
        return Err(X64TailCandidateCapsuleError::LimitExceeded {
            field: "code bytes",
            limit: X64_TAIL_CANDIDATE_CAPSULE_MAX_CODE_BYTES,
            actual: code_bytes,
        });
    }
    let mut encoder = EvidenceEncoder::new();
    encoder.bytes(CODE_DOMAIN)?;
    encoder.len(code.len())?;
    encoder.bytes(code)?;
    Ok(SemanticHash(sha256(&encoder.finish())))
}

pub fn x64_tail_candidate_capsule_hash(
    capsule: &X64TailCandidateCapsule,
) -> Result<SemanticHash, X64TailCandidateCapsuleError> {
    Ok(SemanticHash(sha256(&capsule_bytes_without_seal(capsule)?)))
}

fn construct_capsule(
    target: &X64TargetArtifact,
    logical: &X64TailStatePlan,
    physical: &X64TailPhysicalAllocation,
    realization: &X64TailTemplateRealization,
) -> Result<X64TailCandidateCapsule, X64TailCandidateCapsuleError> {
    ensure_limit(
        "transitions",
        X64_TAIL_CANDIDATE_CAPSULE_MAX_TRANSITIONS,
        realization.transitions().len(),
    )?;
    let atom_count = realization
        .transitions()
        .iter()
        .try_fold(0usize, |total, transition| {
            total.checked_add(transition.atoms.len()).ok_or(
                X64TailCandidateCapsuleError::ArithmeticOverflow {
                    field: "atom count",
                },
            )
        })?;
    ensure_limit("atoms", X64_TAIL_CANDIDATE_CAPSULE_MAX_ATOMS, atom_count)?;

    let mut transition_bytes = 0u32;
    let mut transition_starts = BTreeMap::new();
    for transition in realization.transitions() {
        transition_starts.insert(transition.edge_ordinal, transition_bytes);
        transition_bytes = transition_bytes
            .checked_add(transition.layout_bytes)
            .ok_or(X64TailCandidateCapsuleError::ArithmeticOverflow {
                field: "transition layout",
            })?;
    }
    let labels = realization
        .transitions()
        .iter()
        .map(|transition| transition.target_label)
        .collect::<BTreeSet<_>>();
    ensure_limit(
        "target anchors",
        X64_TAIL_CANDIDATE_CAPSULE_MAX_ANCHORS,
        labels.len(),
    )?;
    let mut anchor_offsets = BTreeMap::new();
    let mut anchor_receipts = Vec::with_capacity(labels.len());
    let mut cursor = transition_bytes;
    for label in labels {
        if !target
            .program
            .labels
            .iter()
            .any(|candidate| candidate.id == label)
        {
            return Err(X64TailCandidateCapsuleError::InvalidField {
                field: "target anchor label",
            });
        }
        anchor_offsets.insert(label, cursor);
        anchor_receipts.push(X64TailCandidateAnchorReceipt {
            label,
            offset: cursor,
        });
        cursor = cursor
            .checked_add(1)
            .ok_or(X64TailCandidateCapsuleError::ArithmeticOverflow {
                field: "anchor layout",
            })?;
    }
    if u64::from(cursor) > X64_TAIL_CANDIDATE_CAPSULE_MAX_CODE_BYTES {
        return Err(X64TailCandidateCapsuleError::LimitExceeded {
            field: "code bytes",
            limit: X64_TAIL_CANDIDATE_CAPSULE_MAX_CODE_BYTES,
            actual: u64::from(cursor),
        });
    }
    let code_capacity =
        usize::try_from(cursor).map_err(|_| X64TailCandidateCapsuleError::ArithmeticOverflow {
            field: "code capacity",
        })?;
    let mut code = Vec::new();
    code.try_reserve_exact(code_capacity).map_err(|_| {
        X64TailCandidateCapsuleError::EncodingLimit {
            actual: code_capacity,
        }
    })?;
    let mut transition_receipts = Vec::with_capacity(realization.transitions().len());
    let mut fixup_receipts = Vec::with_capacity(realization.transitions().len());
    let mut global_cursor = 0u32;
    for transition in realization.transitions() {
        let start = global_cursor;
        for atom in &transition.atoms {
            let before = code.len();
            encode_instruction(
                &mut code,
                atom.instruction,
                global_cursor,
                transition.edge_ordinal,
                atom.ordinal,
                &anchor_offsets,
                &mut fixup_receipts,
            )?;
            let emitted = code.len().checked_sub(before).ok_or(
                X64TailCandidateCapsuleError::ArithmeticOverflow {
                    field: "emitted atom bytes",
                },
            )?;
            let expected_emitted = usize::try_from(atom.instruction.byte_len()).map_err(|_| {
                X64TailCandidateCapsuleError::ArithmeticOverflow {
                    field: "atom byte length",
                }
            })?;
            if emitted != expected_emitted {
                return Err(X64TailCandidateCapsuleError::InvalidField {
                    field: "exact atom byte length",
                });
            }
            global_cursor = global_cursor
                .checked_add(atom.instruction.byte_len())
                .ok_or(X64TailCandidateCapsuleError::ArithmeticOverflow {
                    field: "encoded atom end",
                })?;
        }
        let expected_start = transition_starts
            .get(&transition.edge_ordinal)
            .copied()
            .ok_or(X64TailCandidateCapsuleError::InvalidField {
                field: "transition start",
            })?;
        if start != expected_start || global_cursor - start != transition.layout_bytes {
            return Err(X64TailCandidateCapsuleError::InvalidField {
                field: "transition byte layout",
            });
        }
        transition_receipts.push(X64TailCandidateTransitionReceipt {
            edge_ordinal: transition.edge_ordinal,
            start,
            end: global_cursor,
            atom_count: usize_to_u32(transition.atoms.len(), "transition atoms")?,
        });
    }
    if global_cursor != transition_bytes {
        return Err(X64TailCandidateCapsuleError::InvalidField {
            field: "transition byte total",
        });
    }
    code.extend(std::iter::repeat_n(
        TARGET_ANCHOR_BYTE,
        anchor_receipts.len(),
    ));
    if code.len() != code_capacity {
        return Err(X64TailCandidateCapsuleError::InvalidField {
            field: "complete code layout",
        });
    }
    ensure_limit(
        "resolved fixups",
        X64_TAIL_CANDIDATE_CAPSULE_MAX_FIXUPS,
        fixup_receipts.len(),
    )?;
    let code_hash = x64_tail_candidate_code_hash(&code)?;
    let encoder_code_work = usize_to_u64(code.len(), "encoder code work")?;
    let encoder_atom_work = usize_to_u64(atom_count, "encoder atom work")?;
    let encoder_anchor_work = usize_to_u64(anchor_receipts.len(), "encoder anchor work")?;
    let encoder_work = encoder_code_work
        .checked_add(encoder_atom_work)
        .and_then(|work| work.checked_add(encoder_anchor_work))
        .ok_or(X64TailCandidateCapsuleError::ArithmeticOverflow {
            field: "encoder work",
        })?;
    if encoder_work > X64_TAIL_CANDIDATE_CAPSULE_MAX_ENCODER_WORK {
        return Err(X64TailCandidateCapsuleError::LimitExceeded {
            field: "encoder work",
            limit: X64_TAIL_CANDIDATE_CAPSULE_MAX_ENCODER_WORK,
            actual: encoder_work,
        });
    }
    let decoded = decode_x64_tail_candidate_bytes(&code, realization, target)?;
    let totals = X64TailCandidateCapsuleTotals {
        transitions: usize_to_u32(transition_receipts.len(), "transition total")?,
        atoms: usize_to_u32(atom_count, "atom total")?,
        anchors: usize_to_u32(anchor_receipts.len(), "anchor total")?,
        resolved_fixups: usize_to_u32(fixup_receipts.len(), "fixup total")?,
        transition_bytes,
        anchor_bytes: usize_to_u32(anchor_receipts.len(), "anchor bytes")?,
        code_bytes: usize_to_u32(code.len(), "code bytes")?,
        encoder_work,
        decoder_work: decoded.decode_work,
    };
    let mut capsule = X64TailCandidateCapsule {
        schema_version: X64_TAIL_CANDIDATE_CAPSULE_SCHEMA_VERSION,
        policy_version: X64_TAIL_CANDIDATE_CAPSULE_POLICY_VERSION,
        source_target_semantic_hash: target.semantic_hash,
        source_logical_plan_hash: logical.plan_hash(),
        source_physical_allocation_hash: physical.allocation_hash(),
        source_template_realization_hash: realization.realization_hash(),
        transition_receipts,
        anchor_receipts,
        fixup_receipts,
        code,
        code_hash,
        totals,
        capsule_hash: SemanticHash([0; 32]),
    };
    capsule.capsule_hash = x64_tail_candidate_capsule_hash(&capsule)?;
    Ok(capsule)
}

fn encode_instruction(
    code: &mut Vec<u8>,
    instruction: X64TailTemplateInstruction,
    global_start: u32,
    edge: u32,
    atom_ordinal: u32,
    anchors: &BTreeMap<X64LabelId, u32>,
    fixups: &mut Vec<X64TailCandidateFixupReceipt>,
) -> Result<(), X64TailCandidateCapsuleError> {
    match instruction {
        X64TailTemplateInstruction::GprCopy {
            source,
            destination,
            ..
        } => {
            let source = gpr_number(source);
            let destination = gpr_number(destination);
            code.push(rex_w(source >= 8, destination >= 8));
            code.push(0x89);
            code.push(0xc0 | ((source & 7) << 3) | (destination & 7));
        }
        X64TailTemplateInstruction::GprFrameLoad {
            source,
            destination,
        } => {
            let destination = gpr_number(destination);
            code.extend_from_slice(&[
                rex_w(destination >= 8, false),
                0x8b,
                0x84 | ((destination & 7) << 3),
                0x24,
            ]);
            code.extend_from_slice(&source.offset.to_le_bytes());
        }
        X64TailTemplateInstruction::GprFrameStore {
            source,
            destination,
        } => {
            let source = gpr_number(source);
            code.extend_from_slice(&[
                rex_w(source >= 8, false),
                0x89,
                0x84 | ((source & 7) << 3),
                0x24,
            ]);
            code.extend_from_slice(&destination.offset.to_le_bytes());
        }
        X64TailTemplateInstruction::XmmCopy {
            source,
            destination,
        } => code.extend_from_slice(&[
            0xf2,
            0x0f,
            0x10,
            0xc0 | (xmm_number(destination) << 3) | xmm_number(source),
        ]),
        X64TailTemplateInstruction::XmmFrameLoad {
            source,
            destination,
        } => {
            code.extend_from_slice(&[
                0xf2,
                0x0f,
                0x10,
                0x84 | (xmm_number(destination) << 3),
                0x24,
            ]);
            code.extend_from_slice(&source.offset.to_le_bytes());
        }
        X64TailTemplateInstruction::XmmFrameStore {
            source,
            destination,
        } => {
            code.extend_from_slice(&[0xf2, 0x0f, 0x11, 0x84 | (xmm_number(source) << 3), 0x24]);
            code.extend_from_slice(&destination.offset.to_le_bytes());
        }
        X64TailTemplateInstruction::GprImmediate {
            immediate,
            destination,
        } => {
            let destination = gpr_number(destination);
            code.extend_from_slice(&[rex_w(false, destination >= 8), 0xb8 | (destination & 7)]);
            code.extend_from_slice(&immediate_bits(immediate).to_le_bytes());
        }
        X64TailTemplateInstruction::GprBitsToXmm {
            source,
            destination,
        } => {
            let source = gpr_number(source);
            code.extend_from_slice(&[
                0x66,
                rex_w(false, source >= 8),
                0x0f,
                0x6e,
                0xc0 | (xmm_number(destination) << 3) | (source & 7),
            ]);
        }
        X64TailTemplateInstruction::TailJumpRel32 { target } => {
            let target_offset = anchors.get(&target).copied().ok_or(
                X64TailCandidateCapsuleError::InvalidField {
                    field: "jump target anchor",
                },
            )?;
            let next = i64::from(global_start) + 5;
            let displacement = i64::from(target_offset) - next;
            let displacement_i32 = i32::try_from(displacement).map_err(|_| {
                X64TailCandidateCapsuleError::Rel32OutOfRange { edge, displacement }
            })?;
            code.push(0xe9);
            code.extend_from_slice(&displacement_i32.to_le_bytes());
            fixups.push(X64TailCandidateFixupReceipt {
                edge_ordinal: edge,
                atom_ordinal,
                patch_offset: global_start.checked_add(1).ok_or(
                    X64TailCandidateCapsuleError::ArithmeticOverflow {
                        field: "fixup patch offset",
                    },
                )?,
                target,
                target_offset,
                displacement: displacement_i32,
            });
        }
    }
    Ok(())
}

const fn rex_w(rex_r: bool, rex_b: bool) -> u8 {
    0x48 | ((rex_r as u8) << 2) | (rex_b as u8)
}

const fn gpr_number(register: X64TailTemplateGpr) -> u8 {
    match register {
        X64TailTemplateGpr::Rax => 0,
        X64TailTemplateGpr::Rcx => 1,
        X64TailTemplateGpr::Rsi => 6,
        X64TailTemplateGpr::Rdi => 7,
        X64TailTemplateGpr::R9 => 9,
        X64TailTemplateGpr::R10 => 10,
        X64TailTemplateGpr::R11 => 11,
    }
}

const fn xmm_number(register: X64TailTemplateXmm) -> u8 {
    match register {
        X64TailTemplateXmm::Xmm0 => 0,
        X64TailTemplateXmm::Xmm1 => 1,
        X64TailTemplateXmm::Xmm3 => 3,
        X64TailTemplateXmm::Xmm4 => 4,
        X64TailTemplateXmm::Xmm5 => 5,
        X64TailTemplateXmm::Xmm6 => 6,
        X64TailTemplateXmm::Xmm7 => 7,
    }
}

const fn immediate_bits(immediate: X64TailImmediateWord) -> u64 {
    match immediate {
        X64TailImmediateWord::Bool(value) => value as u64,
        X64TailImmediateWord::I64(value) => value as u64,
        X64TailImmediateWord::F64Bits(bits) => bits,
    }
}

fn validate_envelope(
    capsule: &X64TailCandidateCapsule,
    realization: &X64TailTemplateRealization,
    physical: &X64TailPhysicalAllocation,
    logical: &X64TailStatePlan,
    target: &X64TargetArtifact,
) -> Result<(), X64TailCandidateCapsuleError> {
    if capsule.schema_version != X64_TAIL_CANDIDATE_CAPSULE_SCHEMA_VERSION {
        return Err(X64TailCandidateCapsuleError::InvalidField {
            field: "schema version",
        });
    }
    if capsule.policy_version != X64_TAIL_CANDIDATE_CAPSULE_POLICY_VERSION {
        return Err(X64TailCandidateCapsuleError::InvalidField {
            field: "policy version",
        });
    }
    if capsule.source_target_semantic_hash != target.semantic_hash
        || capsule.source_logical_plan_hash != logical.plan_hash()
        || capsule.source_physical_allocation_hash != physical.allocation_hash()
        || capsule.source_template_realization_hash != realization.realization_hash()
    {
        return Err(X64TailCandidateCapsuleError::InvalidField {
            field: "source identity",
        });
    }
    Ok(())
}

fn audit_receipts_and_totals(
    capsule: &X64TailCandidateCapsule,
    decoded: &X64TailDecodedCapsule,
) -> Result<(), X64TailCandidateCapsuleError> {
    let mut transitions = Vec::with_capacity(decoded.transitions.len());
    for transition in &decoded.transitions {
        transitions.push(X64TailCandidateTransitionReceipt {
            edge_ordinal: transition.edge_ordinal,
            start: transition.start,
            end: transition.end,
            atom_count: usize_to_u32(transition.atoms.len(), "decoded receipt atoms")?,
        });
    }
    let anchors = decoded
        .anchors
        .iter()
        .map(|anchor| X64TailCandidateAnchorReceipt {
            label: anchor.label,
            offset: anchor.offset,
        })
        .collect::<Vec<_>>();
    let fixups = decoded
        .fixups
        .iter()
        .map(|fixup| X64TailCandidateFixupReceipt {
            edge_ordinal: fixup.edge_ordinal,
            atom_ordinal: fixup.atom_ordinal,
            patch_offset: fixup.patch_offset,
            target: fixup.target,
            target_offset: fixup.target_offset,
            displacement: fixup.displacement,
        })
        .collect::<Vec<_>>();
    if capsule.transition_receipts != transitions
        || capsule.anchor_receipts != anchors
        || capsule.fixup_receipts != fixups
    {
        return Err(X64TailCandidateCapsuleError::InvalidField {
            field: "independently decoded receipts",
        });
    }
    let transition_count = usize_to_u32(transitions.len(), "decoded transitions")?;
    let anchor_count = usize_to_u32(anchors.len(), "decoded anchors")?;
    let fixup_count = usize_to_u32(fixups.len(), "decoded fixups")?;
    if capsule.totals.transitions != transition_count
        || capsule.totals.atoms != decoded.decoded_atoms
        || capsule.totals.anchors != anchor_count
        || capsule.totals.resolved_fixups != fixup_count
        || capsule.totals.transition_bytes != decoded.transition_bytes
        || capsule.totals.anchor_bytes != anchor_count
        || capsule.totals.code_bytes != decoded.code_bytes
        || capsule.totals.decoder_work != decoded.decode_work
    {
        return Err(X64TailCandidateCapsuleError::InvalidField {
            field: "independently decoded totals",
        });
    }
    Ok(())
}

fn capsule_bytes_without_seal(
    capsule: &X64TailCandidateCapsule,
) -> Result<Vec<u8>, X64TailCandidateCapsuleError> {
    let mut encoder = EvidenceEncoder::new();
    encoder.bytes(CAPSULE_DOMAIN)?;
    encoder.version(capsule.schema_version)?;
    encoder.version(capsule.policy_version)?;
    encoder.hash(capsule.source_target_semantic_hash)?;
    encoder.hash(capsule.source_logical_plan_hash)?;
    encoder.hash(capsule.source_physical_allocation_hash)?;
    encoder.hash(capsule.source_template_realization_hash)?;
    encoder.len(capsule.transition_receipts.len())?;
    for receipt in &capsule.transition_receipts {
        encoder.u32(receipt.edge_ordinal)?;
        encoder.u32(receipt.start)?;
        encoder.u32(receipt.end)?;
        encoder.u32(receipt.atom_count)?;
    }
    encoder.len(capsule.anchor_receipts.len())?;
    for receipt in &capsule.anchor_receipts {
        encoder.u32(receipt.label.0)?;
        encoder.u32(receipt.offset)?;
    }
    encoder.len(capsule.fixup_receipts.len())?;
    for receipt in &capsule.fixup_receipts {
        encoder.u32(receipt.edge_ordinal)?;
        encoder.u32(receipt.atom_ordinal)?;
        encoder.u32(receipt.patch_offset)?;
        encoder.u32(receipt.target.0)?;
        encoder.u32(receipt.target_offset)?;
        encoder.i32(receipt.displacement)?;
    }
    encoder.len(capsule.code.len())?;
    encoder.bytes(&capsule.code)?;
    encoder.hash(capsule.code_hash)?;
    encode_totals(&mut encoder, capsule.totals)?;
    Ok(encoder.finish())
}

fn encode_totals(
    encoder: &mut EvidenceEncoder,
    totals: X64TailCandidateCapsuleTotals,
) -> Result<(), X64TailCandidateCapsuleError> {
    encoder.u32(totals.transitions)?;
    encoder.u32(totals.atoms)?;
    encoder.u32(totals.anchors)?;
    encoder.u32(totals.resolved_fixups)?;
    encoder.u32(totals.transition_bytes)?;
    encoder.u32(totals.anchor_bytes)?;
    encoder.u32(totals.code_bytes)?;
    encoder.u64(totals.encoder_work)?;
    encoder.u64(totals.decoder_work)
}

fn ensure_limit(
    field: &'static str,
    limit: u32,
    actual: usize,
) -> Result<(), X64TailCandidateCapsuleError> {
    let limit_usize =
        usize::try_from(limit).map_err(|_| X64TailCandidateCapsuleError::ArithmeticOverflow {
            field: "host limit width",
        })?;
    if actual > limit_usize {
        Err(X64TailCandidateCapsuleError::LimitExceeded {
            field,
            limit: u64::from(limit),
            actual: usize_to_u64(actual, field)?,
        })
    } else {
        Ok(())
    }
}

fn usize_to_u32(value: usize, field: &'static str) -> Result<u32, X64TailCandidateCapsuleError> {
    u32::try_from(value).map_err(|_| X64TailCandidateCapsuleError::ArithmeticOverflow { field })
}

fn usize_to_u64(value: usize, field: &'static str) -> Result<u64, X64TailCandidateCapsuleError> {
    u64::try_from(value).map_err(|_| X64TailCandidateCapsuleError::ArithmeticOverflow { field })
}

struct EvidenceEncoder {
    bytes: Vec<u8>,
}

impl EvidenceEncoder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn reserve(&mut self, additional: usize) -> Result<(), X64TailCandidateCapsuleError> {
        let actual = self.bytes.len().checked_add(additional).ok_or(
            X64TailCandidateCapsuleError::ArithmeticOverflow {
                field: "capsule evidence length",
            },
        )?;
        if actual > MAX_CAPSULE_EVIDENCE_BYTES {
            return Err(X64TailCandidateCapsuleError::EncodingLimit { actual });
        }
        self.bytes
            .try_reserve(additional)
            .map_err(|_| X64TailCandidateCapsuleError::EncodingLimit { actual })
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), X64TailCandidateCapsuleError> {
        self.reserve(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u32(&mut self, value: u32) -> Result<(), X64TailCandidateCapsuleError> {
        self.bytes(&value.to_le_bytes())
    }

    fn i32(&mut self, value: i32) -> Result<(), X64TailCandidateCapsuleError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), X64TailCandidateCapsuleError> {
        self.bytes(&value.to_le_bytes())
    }

    fn len(&mut self, value: usize) -> Result<(), X64TailCandidateCapsuleError> {
        self.u32(usize_to_u32(value, "capsule collection length")?)
    }

    fn version(&mut self, value: (u16, u16, u16)) -> Result<(), X64TailCandidateCapsuleError> {
        self.bytes(&value.0.to_le_bytes())?;
        self.bytes(&value.1.to_le_bytes())?;
        self.bytes(&value.2.to_le_bytes())
    }

    fn hash(&mut self, value: SemanticHash) -> Result<(), X64TailCandidateCapsuleError> {
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
        emit_x64_tail_template_realization, X64TailWordLocation, X64TailWordType,
        X64_TARGET_ENCODER_POLICY_VERSION,
    };

    fn encode_one(
        instruction: X64TailTemplateInstruction,
    ) -> Result<Vec<u8>, X64TailCandidateCapsuleError> {
        let mut code = Vec::new();
        encode_instruction(
            &mut code,
            instruction,
            0,
            0,
            0,
            &BTreeMap::new(),
            &mut Vec::new(),
        )?;
        Ok(code)
    }

    fn frame(offset: u32, word_type: X64TailWordType) -> X64TailWordLocation {
        X64TailWordLocation { offset, word_type }
    }

    #[test]
    fn owned_encoder_has_locked_vectors_for_every_template_family() {
        assert_eq!(
            encode_one(X64TailTemplateInstruction::GprCopy {
                source: X64TailTemplateGpr::R9,
                destination: X64TailTemplateGpr::R10,
                word_type: X64TailWordType::I64,
            })
            .expect("GPR copy must encode"),
            vec![0x4d, 0x89, 0xca]
        );
        assert_eq!(
            encode_one(X64TailTemplateInstruction::GprFrameLoad {
                source: frame(0x20, X64TailWordType::I64),
                destination: X64TailTemplateGpr::R11,
            })
            .expect("GPR load must encode"),
            vec![0x4c, 0x8b, 0x9c, 0x24, 0x20, 0, 0, 0]
        );
        assert_eq!(
            encode_one(X64TailTemplateInstruction::GprFrameStore {
                source: X64TailTemplateGpr::R10,
                destination: frame(0x28, X64TailWordType::ArrayLength),
            })
            .expect("GPR store must encode"),
            vec![0x4c, 0x89, 0x94, 0x24, 0x28, 0, 0, 0]
        );
        assert_eq!(
            encode_one(X64TailTemplateInstruction::XmmCopy {
                source: X64TailTemplateXmm::Xmm3,
                destination: X64TailTemplateXmm::Xmm7,
            })
            .expect("XMM copy must encode"),
            vec![0xf2, 0x0f, 0x10, 0xfb]
        );
        assert_eq!(
            encode_one(X64TailTemplateInstruction::XmmFrameLoad {
                source: frame(0x30, X64TailWordType::F64),
                destination: X64TailTemplateXmm::Xmm6,
            })
            .expect("XMM load must encode"),
            vec![0xf2, 0x0f, 0x10, 0xb4, 0x24, 0x30, 0, 0, 0]
        );
        assert_eq!(
            encode_one(X64TailTemplateInstruction::XmmFrameStore {
                source: X64TailTemplateXmm::Xmm5,
                destination: frame(0x38, X64TailWordType::F64),
            })
            .expect("XMM store must encode"),
            vec![0xf2, 0x0f, 0x11, 0xac, 0x24, 0x38, 0, 0, 0]
        );
        assert_eq!(
            encode_one(X64TailTemplateInstruction::GprImmediate {
                immediate: X64TailImmediateWord::I64(0x0102_0304_0506_0708),
                destination: X64TailTemplateGpr::R11,
            })
            .expect("movabs must encode"),
            vec![0x49, 0xbb, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(
            encode_one(X64TailTemplateInstruction::GprBitsToXmm {
                source: X64TailTemplateGpr::R9,
                destination: X64TailTemplateXmm::Xmm3,
            })
            .expect("GPR bits to XMM must encode"),
            vec![0x66, 0x49, 0x0f, 0x6e, 0xd9]
        );

        let mut code = Vec::new();
        let mut anchors = BTreeMap::new();
        anchors.insert(X64LabelId(7), 100);
        let mut fixups = Vec::new();
        encode_instruction(
            &mut code,
            X64TailTemplateInstruction::TailJumpRel32 {
                target: X64LabelId(7),
            },
            10,
            4,
            9,
            &anchors,
            &mut fixups,
        )
        .expect("rel32 must encode");
        assert_eq!(code, vec![0xe9, 0x55, 0, 0, 0]);
        assert_eq!(
            fixups,
            vec![X64TailCandidateFixupReceipt {
                edge_ordinal: 4,
                atom_ordinal: 9,
                patch_offset: 11,
                target: X64LabelId(7),
                target_offset: 100,
                displacement: 85,
            }]
        );
    }

    #[test]
    fn branch_lighthouse_capsule_is_deterministic_and_every_single_byte_is_bound() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("BranchMix lighthouse must build");
        let logical = emit_x64_tail_state_plan(package.target()).expect("logical plan must emit");
        let physical = emit_x64_tail_physical_allocation(package.target(), &logical)
            .expect("physical allocation must emit");
        let realization = emit_x64_tail_template_realization(package.target(), &logical, &physical)
            .expect("template realization must emit");
        let first =
            emit_x64_tail_candidate_capsule(package.target(), &logical, &physical, &realization)
                .expect("candidate capsule must emit");
        let second =
            emit_x64_tail_candidate_capsule(package.target(), &logical, &physical, &realization)
                .expect("candidate capsule must replay");
        assert_eq!(first, second);
        let verified = verify_x64_tail_candidate_capsule(
            &first,
            &realization,
            &physical,
            &logical,
            package.target(),
        )
        .expect("candidate capsule must independently decode");
        assert_eq!(verified.decoded().decoded_atoms, 314);
        assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
        assert_eq!(
            first.capsule_hash().to_hex(),
            "bbaaf8a209b29194cdc19765b16b4c4ccc6108b3774e24d70d215979c8cf85f4"
        );
        assert_eq!(
            first.code_hash().to_hex(),
            "abb57afc62f6de04a25ab1c97ef648a0975b6c0bde2fd2035337efbc55c474d6"
        );
        assert_eq!(
            first.totals(),
            X64TailCandidateCapsuleTotals {
                transitions: 108,
                atoms: 314,
                anchors: 108,
                resolved_fixups: 108,
                transition_bytes: 2_103,
                anchor_bytes: 108,
                code_bytes: 2_211,
                encoder_work: 2_633,
                decoder_work: 2_525,
            }
        );

        for index in 0..first.code.len() {
            let mut mutated = first.code.clone();
            mutated[index] ^= 1;
            assert!(
                decode_x64_tail_candidate_bytes(&mutated, &realization, package.target()).is_err(),
                "single-byte mutation {index} must fail"
            );
        }
        let mut truncated = first.code.clone();
        truncated.pop();
        assert!(
            decode_x64_tail_candidate_bytes(&truncated, &realization, package.target()).is_err()
        );
        let mut trailing = first.code.clone();
        trailing.push(0xcc);
        assert!(
            decode_x64_tail_candidate_bytes(&trailing, &realization, package.target()).is_err()
        );

        let mut wrong_code = first.clone();
        wrong_code.code[0] ^= 1;
        wrong_code.code_hash =
            x64_tail_candidate_code_hash(&wrong_code.code).expect("mutation can rehash code");
        wrong_code.capsule_hash = x64_tail_candidate_capsule_hash(&wrong_code)
            .expect("mutation can locally reseal capsule");
        assert!(matches!(
            verify_x64_tail_candidate_capsule(
                &wrong_code,
                &realization,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailCandidateCapsuleError::Decode(_))
        ));

        let mut wrong_receipt = first.clone();
        wrong_receipt.transition_receipts[0].end =
            wrong_receipt.transition_receipts[0].end.saturating_add(1);
        wrong_receipt.capsule_hash = x64_tail_candidate_capsule_hash(&wrong_receipt)
            .expect("receipt mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_candidate_capsule(
                &wrong_receipt,
                &realization,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailCandidateCapsuleError::InvalidField {
                field: "independently decoded receipts"
            })
        ));

        let mut wrong_total = first.clone();
        wrong_total.totals.decoder_work = wrong_total.totals.decoder_work.saturating_add(1);
        wrong_total.capsule_hash = x64_tail_candidate_capsule_hash(&wrong_total)
            .expect("total mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_candidate_capsule(
                &wrong_total,
                &realization,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailCandidateCapsuleError::InvalidField {
                field: "independently decoded totals"
            })
        ));

        let mut wrong_source = first.clone();
        wrong_source.source_template_realization_hash.0[0] ^= 1;
        wrong_source.capsule_hash = x64_tail_candidate_capsule_hash(&wrong_source)
            .expect("source mutation can locally reseal");
        assert!(matches!(
            verify_x64_tail_candidate_capsule(
                &wrong_source,
                &realization,
                &physical,
                &logical,
                package.target()
            ),
            Err(X64TailCandidateCapsuleError::InvalidField {
                field: "source identity"
            })
        ));
    }

    #[test]
    fn bounds_lighthouse_capsule_remains_non_executable_and_complete() {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BoundsOrderedArrayGet)
            .expect("Bounds lighthouse must build");
        let original_code = package.target().program.code.clone();
        let logical = emit_x64_tail_state_plan(package.target()).expect("logical plan must emit");
        let physical = emit_x64_tail_physical_allocation(package.target(), &logical)
            .expect("physical allocation must emit");
        let realization = emit_x64_tail_template_realization(package.target(), &logical, &physical)
            .expect("template realization must emit");
        let capsule =
            emit_x64_tail_candidate_capsule(package.target(), &logical, &physical, &realization)
                .expect("Bounds capsule must emit");
        verify_x64_tail_candidate_capsule(
            &capsule,
            &realization,
            &physical,
            &logical,
            package.target(),
        )
        .expect("Bounds capsule must independently decode");
        assert_eq!(capsule.totals().transitions, physical.totals().transitions);
        assert_eq!(package.target().program.code, original_code);
        assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
    }
}
