//! Owned non-executable ADR-0064 x86-64 body/frontier byte capsule.
//!
//! This module owns the canonical encoding for ADR-0062 body/frontier atoms.
//! It does not map, link, execute, package, time, or select these bytes.
//! Persistent transition bytes remain owned by ADR-0060 and are represented
//! only by exact external references. Verification uses the separately
//! implemented decoder module.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_body_frontier_decode::{
    decode_x64_tail_body_frontier_bytes, X64TailBodyDecodeError, X64TailBodyDecodedCapsule,
    X64TailBodyDecodedProgramKind,
};
use super::x64_tail_body_frontier_realization::{
    verify_x64_tail_body_frontier_realization, X64TailBodyAtom, X64TailBodyAtomInstruction,
    X64TailBodyControlTarget, X64TailBodyFrontierError, X64TailBodyFrontierRealization,
    X64TailBodyScratch,
};
use super::x64_tail_candidate_capsule::X64TailCandidateCapsule;
use super::x64_tail_site_binding::{X64TailBoundRead, X64TailSiteBindingProof};
use super::x64_tail_state_allocation::{
    X64TailPhysicalAllocation, X64TailPhysicalLocation, X64TailPhysicalRegister,
};
use super::x64_tail_state_plan::{
    X64TailImmediateWord, X64TailScheduledSource, X64TailStatePlan, X64TailWordLocation,
    X64TailWordType,
};
use super::x64_tail_template_realization::X64TailTemplateRealization;
use super::x64_target::{X64I64Opcode, X64SetCondition, X64Sse2F64Opcode, X64TargetArtifact};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const X64_TAIL_BODY_CAPSULE_SCHEMA_VERSION: (u16, u16, u16) = (1, 1, 0);
pub const X64_TAIL_BODY_CAPSULE_POLICY_VERSION: (u16, u16, u16) = (1, 2, 0);
pub const X64_TAIL_BODY_CAPSULE_MAX_SITE_PROGRAMS: u32 = 1_000_000;
pub const X64_TAIL_BODY_CAPSULE_MAX_FRONTIER_PROGRAMS: u32 = 32_000;
pub const X64_TAIL_BODY_CAPSULE_MAX_ATOMS: u32 = 8_000_000;
pub const X64_TAIL_BODY_CAPSULE_MAX_FIXUPS: u32 = 2_000_000;
pub const X64_TAIL_BODY_CAPSULE_MAX_REFERENCES: u32 = 4_096;
pub const X64_TAIL_BODY_CAPSULE_MAX_ANCHORS: u32 = 2_032_000;
pub const X64_TAIL_BODY_CAPSULE_MAX_CODE_BYTES: u64 = 64 * 1024 * 1024;
pub const X64_TAIL_BODY_CAPSULE_MAX_ENCODER_WORK: u64 = 32_000_000;
pub const X64_TAIL_BODY_CAPSULE_MAX_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;

const CODE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-body-frontier-code:v1\0";
const CAPSULE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-body-frontier-capsule:v1\0";
const PROOF_ANCHOR_BYTE: u8 = 0xcc;
const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailBodyCapsuleProgramKind {
    Site,
    Frontier,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailBodyCapsuleProgramReceipt {
    pub kind: X64TailBodyCapsuleProgramKind,
    pub ordinal: u32,
    pub start: u32,
    pub end: u32,
    pub encoded_atoms: u32,
    pub external_references: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailBodyCapsuleAnchorReceipt {
    pub target: X64TailBodyControlTarget,
    pub offset: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailBodyCapsuleFixupReceipt {
    pub program_kind: X64TailBodyCapsuleProgramKind,
    pub program_ordinal: u32,
    pub atom_ordinal: u32,
    pub patch_offset: u32,
    pub target: X64TailBodyControlTarget,
    pub target_offset: u32,
    pub displacement: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailBodyCapsuleExternalReference {
    pub site_ordinal: u32,
    pub atom_ordinal: u32,
    pub edge_ordinal: u32,
    pub capsule_start: u32,
    pub capsule_end: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X64TailBodyFrontierCapsuleTotals {
    pub programs: u32,
    pub site_programs: u32,
    pub frontier_programs: u32,
    pub encoded_atoms: u32,
    pub primitive_instructions: u32,
    pub external_references: u32,
    pub typed_anchors: u32,
    pub resolved_fixups: u32,
    pub site_bytes: u32,
    pub frontier_bytes: u32,
    pub anchor_bytes: u32,
    pub code_bytes: u32,
    pub retained_transition_bytes: u32,
    pub encoder_work: u64,
    pub decoder_work: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailBodyFrontierCapsule {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    decoder_policy_version: (u16, u16, u16),
    source_target_semantic_hash: SemanticHash,
    source_transition_capsule_hash: SemanticHash,
    source_body_frontier_realization_hash: SemanticHash,
    program_receipts: Vec<X64TailBodyCapsuleProgramReceipt>,
    anchor_receipts: Vec<X64TailBodyCapsuleAnchorReceipt>,
    fixup_receipts: Vec<X64TailBodyCapsuleFixupReceipt>,
    external_references: Vec<X64TailBodyCapsuleExternalReference>,
    code: Vec<u8>,
    code_hash: SemanticHash,
    totals: X64TailBodyFrontierCapsuleTotals,
    capsule_hash: SemanticHash,
}

impl X64TailBodyFrontierCapsule {
    pub const fn source_target_semantic_hash(&self) -> SemanticHash {
        self.source_target_semantic_hash
    }

    pub const fn source_transition_capsule_hash(&self) -> SemanticHash {
        self.source_transition_capsule_hash
    }

    pub const fn source_body_frontier_realization_hash(&self) -> SemanticHash {
        self.source_body_frontier_realization_hash
    }

    pub fn program_receipts(&self) -> &[X64TailBodyCapsuleProgramReceipt] {
        &self.program_receipts
    }

    pub fn anchor_receipts(&self) -> &[X64TailBodyCapsuleAnchorReceipt] {
        &self.anchor_receipts
    }

    pub fn fixup_receipts(&self) -> &[X64TailBodyCapsuleFixupReceipt] {
        &self.fixup_receipts
    }

    pub fn external_references(&self) -> &[X64TailBodyCapsuleExternalReference] {
        &self.external_references
    }

    pub fn code(&self) -> &[u8] {
        &self.code
    }

    pub const fn code_hash(&self) -> SemanticHash {
        self.code_hash
    }

    pub const fn totals(&self) -> X64TailBodyFrontierCapsuleTotals {
        self.totals
    }

    pub const fn capsule_hash(&self) -> SemanticHash {
        self.capsule_hash
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedX64TailBodyFrontierCapsule<'capsule> {
    capsule: &'capsule X64TailBodyFrontierCapsule,
    decoded: X64TailBodyDecodedCapsule,
}

impl<'capsule> VerifiedX64TailBodyFrontierCapsule<'capsule> {
    pub const fn capsule(&self) -> &'capsule X64TailBodyFrontierCapsule {
        self.capsule
    }

    pub const fn decoded(&self) -> &X64TailBodyDecodedCapsule {
        &self.decoded
    }
}

#[derive(Debug)]
pub enum X64TailBodyFrontierCapsuleError {
    Realization(X64TailBodyFrontierError),
    Decode(X64TailBodyDecodeError),
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
    EncodingLimit {
        actual: usize,
    },
    Rel32OutOfRange {
        program: u32,
        atom: u32,
        displacement: i64,
    },
    CodeHashMismatch,
    CapsuleHashMismatch,
    ReceiptMismatch,
    ReplayMismatch,
}

impl fmt::Display for X64TailBodyFrontierCapsuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Realization(error) => write!(formatter, "body capsule realization failed: {error}"),
            Self::Decode(error) => write!(formatter, "body capsule decode failed: {error}"),
            Self::InvalidField { field } => write!(formatter, "body capsule has invalid {field}"),
            Self::LimitExceeded {
                field,
                limit,
                actual,
            } => write!(
                formatter,
                "body capsule {field} uses {actual}; limit is {limit}"
            ),
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "body capsule overflowed {field}")
            }
            Self::EncodingLimit { actual } => write!(
                formatter,
                "body capsule evidence uses {actual} bytes; limit is {X64_TAIL_BODY_CAPSULE_MAX_EVIDENCE_BYTES}"
            ),
            Self::Rel32OutOfRange {
                program,
                atom,
                displacement,
            } => write!(
                formatter,
                "body capsule program {program} atom {atom} rel32 displacement {displacement} is out of range"
            ),
            Self::CodeHashMismatch => formatter.write_str("body capsule code hash does not replay"),
            Self::CapsuleHashMismatch => formatter.write_str("body capsule seal does not replay"),
            Self::ReceiptMismatch => {
                formatter.write_str("body capsule receipts differ from independent decode")
            }
            Self::ReplayMismatch => {
                formatter.write_str("body capsule differs from canonical regeneration")
            }
        }
    }
}

impl std::error::Error for X64TailBodyFrontierCapsuleError {}

impl From<X64TailBodyFrontierError> for X64TailBodyFrontierCapsuleError {
    fn from(value: X64TailBodyFrontierError) -> Self {
        Self::Realization(value)
    }
}

impl From<X64TailBodyDecodeError> for X64TailBodyFrontierCapsuleError {
    fn from(value: X64TailBodyDecodeError) -> Self {
        Self::Decode(value)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn emit_x64_tail_body_frontier_capsule(
    target: &X64TargetArtifact,
    logical: &X64TailStatePlan,
    physical: &X64TailPhysicalAllocation,
    tail_templates: &X64TailTemplateRealization,
    transition_capsule: &X64TailCandidateCapsule,
    binding: &X64TailSiteBindingProof,
    realization: &X64TailBodyFrontierRealization,
) -> Result<X64TailBodyFrontierCapsule, X64TailBodyFrontierCapsuleError> {
    verify_x64_tail_body_frontier_realization(
        realization,
        binding,
        transition_capsule,
        tail_templates,
        physical,
        logical,
        target,
    )?;
    construct_capsule(realization, transition_capsule)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_x64_tail_body_frontier_capsule<'capsule>(
    capsule: &'capsule X64TailBodyFrontierCapsule,
    realization: &X64TailBodyFrontierRealization,
    binding: &X64TailSiteBindingProof,
    transition_capsule: &X64TailCandidateCapsule,
    tail_templates: &X64TailTemplateRealization,
    physical: &X64TailPhysicalAllocation,
    logical: &X64TailStatePlan,
    target: &X64TargetArtifact,
) -> Result<VerifiedX64TailBodyFrontierCapsule<'capsule>, X64TailBodyFrontierCapsuleError> {
    verify_x64_tail_body_frontier_realization(
        realization,
        binding,
        transition_capsule,
        tail_templates,
        physical,
        logical,
        target,
    )?;
    validate_envelope(capsule, realization, transition_capsule)?;
    if x64_tail_body_frontier_code_hash(&capsule.code)? != capsule.code_hash {
        return Err(X64TailBodyFrontierCapsuleError::CodeHashMismatch);
    }
    if x64_tail_body_frontier_capsule_hash(capsule)? != capsule.capsule_hash {
        return Err(X64TailBodyFrontierCapsuleError::CapsuleHashMismatch);
    }
    let decoded =
        decode_x64_tail_body_frontier_bytes(&capsule.code, realization, transition_capsule)?;
    audit_decoded(capsule, &decoded)?;
    let replayed = construct_capsule(realization, transition_capsule)?;
    if replayed != *capsule {
        return Err(X64TailBodyFrontierCapsuleError::ReplayMismatch);
    }
    Ok(VerifiedX64TailBodyFrontierCapsule { capsule, decoded })
}

pub fn x64_tail_body_frontier_code_hash(
    code: &[u8],
) -> Result<SemanticHash, X64TailBodyFrontierCapsuleError> {
    let length = usize_to_u64(code.len(), "code bytes")?;
    if length > X64_TAIL_BODY_CAPSULE_MAX_CODE_BYTES {
        return Err(X64TailBodyFrontierCapsuleError::LimitExceeded {
            field: "code bytes",
            limit: X64_TAIL_BODY_CAPSULE_MAX_CODE_BYTES,
            actual: length,
        });
    }
    let mut encoder = EvidenceEncoder::new();
    encoder.bytes(CODE_DOMAIN)?;
    encoder.len(code.len())?;
    encoder.bytes(code)?;
    Ok(SemanticHash(sha256(&encoder.finish())))
}

pub fn x64_tail_body_frontier_capsule_hash(
    capsule: &X64TailBodyFrontierCapsule,
) -> Result<SemanticHash, X64TailBodyFrontierCapsuleError> {
    Ok(SemanticHash(sha256(&capsule_bytes_without_seal(capsule)?)))
}

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

struct Layout {
    site_bytes: u32,
    frontier_bytes: u32,
    anchors: Vec<X64TailBodyCapsuleAnchorReceipt>,
    anchor_offsets: BTreeMap<AnchorKey, u32>,
    code_bytes: u32,
}

fn construct_capsule(
    realization: &X64TailBodyFrontierRealization,
    transition_capsule: &X64TailCandidateCapsule,
) -> Result<X64TailBodyFrontierCapsule, X64TailBodyFrontierCapsuleError> {
    ensure_limit(
        "site programs",
        X64_TAIL_BODY_CAPSULE_MAX_SITE_PROGRAMS,
        realization.sites().len(),
    )?;
    ensure_limit(
        "frontier programs",
        X64_TAIL_BODY_CAPSULE_MAX_FRONTIER_PROGRAMS,
        realization.frontiers().len(),
    )?;
    let layout = derive_layout(realization)?;
    let capacity = u32_to_usize(layout.code_bytes, "code capacity")?;
    let mut code = Vec::new();
    code.try_reserve_exact(capacity)
        .map_err(|_| X64TailBodyFrontierCapsuleError::EncodingLimit { actual: capacity })?;
    let mut programs = Vec::with_capacity(
        realization
            .sites()
            .len()
            .checked_add(realization.frontiers().len())
            .ok_or(X64TailBodyFrontierCapsuleError::ArithmeticOverflow {
                field: "program capacity",
            })?,
    );
    let mut fixups = Vec::new();
    let mut references = Vec::new();
    let mut encoder_work = 0u64;

    for site in realization.sites() {
        let receipt = encode_program(
            &mut code,
            X64TailBodyCapsuleProgramKind::Site,
            site.ordinal,
            &site.atoms,
            transition_capsule,
            &layout.anchor_offsets,
            &mut fixups,
            &mut references,
            &mut encoder_work,
        )?;
        programs.push(receipt);
    }
    if usize_to_u32(code.len(), "site code bytes")? != layout.site_bytes {
        return Err(X64TailBodyFrontierCapsuleError::InvalidField {
            field: "site byte coverage",
        });
    }
    for frontier in realization.frontiers() {
        let receipt = encode_program(
            &mut code,
            X64TailBodyCapsuleProgramKind::Frontier,
            frontier.row_ordinal,
            &frontier.atoms,
            transition_capsule,
            &layout.anchor_offsets,
            &mut fixups,
            &mut references,
            &mut encoder_work,
        )?;
        programs.push(receipt);
    }
    let program_bytes = layout.site_bytes.checked_add(layout.frontier_bytes).ok_or(
        X64TailBodyFrontierCapsuleError::ArithmeticOverflow {
            field: "program bytes",
        },
    )?;
    if usize_to_u32(code.len(), "program code bytes")? != program_bytes {
        return Err(X64TailBodyFrontierCapsuleError::InvalidField {
            field: "frontier byte coverage",
        });
    }
    for anchor in &layout.anchors {
        if usize_to_u32(code.len(), "anchor offset")? != anchor.offset {
            return Err(X64TailBodyFrontierCapsuleError::InvalidField {
                field: "anchor placement",
            });
        }
        code.push(PROOF_ANCHOR_BYTE);
        encoder_work = charge(encoder_work, 1)?;
    }
    if usize_to_u32(code.len(), "exact code bytes")? != layout.code_bytes {
        return Err(X64TailBodyFrontierCapsuleError::InvalidField {
            field: "exact code coverage",
        });
    }
    ensure_limit(
        "resolved fixups",
        X64_TAIL_BODY_CAPSULE_MAX_FIXUPS,
        fixups.len(),
    )?;
    ensure_limit(
        "external references",
        X64_TAIL_BODY_CAPSULE_MAX_REFERENCES,
        references.len(),
    )?;

    let decoded = decode_x64_tail_body_frontier_bytes(&code, realization, transition_capsule)?;
    audit_raw_receipts(&programs, &layout.anchors, &fixups, &references, &decoded)?;
    let encoded_atoms = programs.iter().try_fold(0u32, |total, program| {
        total.checked_add(program.encoded_atoms).ok_or(
            X64TailBodyFrontierCapsuleError::ArithmeticOverflow {
                field: "encoded atom total",
            },
        )
    })?;
    let retained_transition_bytes = references.iter().try_fold(0u32, |total, reference| {
        total
            .checked_add(
                reference
                    .capsule_end
                    .checked_sub(reference.capsule_start)
                    .ok_or(X64TailBodyFrontierCapsuleError::InvalidField {
                        field: "reference extent",
                    })?,
            )
            .ok_or(X64TailBodyFrontierCapsuleError::ArithmeticOverflow {
                field: "retained transition bytes",
            })
    })?;
    let totals = X64TailBodyFrontierCapsuleTotals {
        programs: usize_to_u32(programs.len(), "program total")?,
        site_programs: usize_to_u32(realization.sites().len(), "site program total")?,
        frontier_programs: usize_to_u32(realization.frontiers().len(), "frontier program total")?,
        encoded_atoms,
        primitive_instructions: decoded.primitive_instructions,
        external_references: usize_to_u32(references.len(), "reference total")?,
        typed_anchors: usize_to_u32(layout.anchors.len(), "anchor total")?,
        resolved_fixups: usize_to_u32(fixups.len(), "fixup total")?,
        site_bytes: layout.site_bytes,
        frontier_bytes: layout.frontier_bytes,
        anchor_bytes: usize_to_u32(layout.anchors.len(), "anchor bytes")?,
        code_bytes: layout.code_bytes,
        retained_transition_bytes,
        encoder_work,
        decoder_work: decoded.decode_work,
    };
    let code_hash = x64_tail_body_frontier_code_hash(&code)?;
    let mut capsule = X64TailBodyFrontierCapsule {
        schema_version: X64_TAIL_BODY_CAPSULE_SCHEMA_VERSION,
        policy_version: X64_TAIL_BODY_CAPSULE_POLICY_VERSION,
        decoder_policy_version:
            super::x64_tail_body_frontier_decode::X64_TAIL_BODY_DECODER_POLICY_VERSION,
        source_target_semantic_hash: realization.source_target_semantic_hash(),
        source_transition_capsule_hash: transition_capsule.capsule_hash(),
        source_body_frontier_realization_hash: realization.realization_hash(),
        program_receipts: programs,
        anchor_receipts: layout.anchors,
        fixup_receipts: fixups,
        external_references: references,
        code,
        code_hash,
        totals,
        capsule_hash: SemanticHash([0; 32]),
    };
    capsule.capsule_hash = x64_tail_body_frontier_capsule_hash(&capsule)?;
    Ok(capsule)
}

fn derive_layout(
    realization: &X64TailBodyFrontierRealization,
) -> Result<Layout, X64TailBodyFrontierCapsuleError> {
    let mut targets = BTreeSet::new();
    let mut site_bytes = 0u32;
    let mut frontier_bytes = 0u32;
    let mut atoms = 0usize;
    let mut references = 0usize;
    for site in realization.sites() {
        derive_atoms(
            &site.atoms,
            &mut site_bytes,
            &mut atoms,
            &mut references,
            &mut targets,
        )?;
    }
    for frontier in realization.frontiers() {
        derive_atoms(
            &frontier.atoms,
            &mut frontier_bytes,
            &mut atoms,
            &mut references,
            &mut targets,
        )?;
    }
    ensure_limit("encoded atoms", X64_TAIL_BODY_CAPSULE_MAX_ATOMS, atoms)?;
    ensure_limit(
        "external references",
        X64_TAIL_BODY_CAPSULE_MAX_REFERENCES,
        references,
    )?;
    ensure_limit(
        "typed anchors",
        X64_TAIL_BODY_CAPSULE_MAX_ANCHORS,
        targets.len(),
    )?;
    let mut cursor = site_bytes.checked_add(frontier_bytes).ok_or(
        X64TailBodyFrontierCapsuleError::ArithmeticOverflow {
            field: "program bytes",
        },
    )?;
    let mut anchors = Vec::with_capacity(targets.len());
    let mut anchor_offsets = BTreeMap::new();
    for key in targets {
        anchors.push(X64TailBodyCapsuleAnchorReceipt {
            target: key.target(),
            offset: cursor,
        });
        if anchor_offsets.insert(key, cursor).is_some() {
            return Err(X64TailBodyFrontierCapsuleError::InvalidField {
                field: "unique typed anchor",
            });
        }
        cursor =
            cursor
                .checked_add(1)
                .ok_or(X64TailBodyFrontierCapsuleError::ArithmeticOverflow {
                    field: "anchor layout",
                })?;
    }
    if u64::from(cursor) > X64_TAIL_BODY_CAPSULE_MAX_CODE_BYTES {
        return Err(X64TailBodyFrontierCapsuleError::LimitExceeded {
            field: "code bytes",
            limit: X64_TAIL_BODY_CAPSULE_MAX_CODE_BYTES,
            actual: u64::from(cursor),
        });
    }
    Ok(Layout {
        site_bytes,
        frontier_bytes,
        anchors,
        anchor_offsets,
        code_bytes: cursor,
    })
}

fn derive_atoms(
    atoms: &[X64TailBodyAtom],
    bytes: &mut u32,
    encoded_atoms: &mut usize,
    references: &mut usize,
    targets: &mut BTreeSet<AnchorKey>,
) -> Result<(), X64TailBodyFrontierCapsuleError> {
    for atom in atoms {
        if matches!(
            atom.instruction,
            X64TailBodyAtomInstruction::CapsuleTransition { .. }
        ) {
            *references = references.checked_add(1).ok_or(
                X64TailBodyFrontierCapsuleError::ArithmeticOverflow {
                    field: "reference count",
                },
            )?;
        } else {
            let length = atom_len(atom)?;
            if length > 18 {
                return Err(X64TailBodyFrontierCapsuleError::LimitExceeded {
                    field: "owned atom bytes",
                    limit: 18,
                    actual: u64::from(length),
                });
            }
            *bytes = bytes.checked_add(length).ok_or(
                X64TailBodyFrontierCapsuleError::ArithmeticOverflow {
                    field: "program bytes",
                },
            )?;
            *encoded_atoms = encoded_atoms.checked_add(1).ok_or(
                X64TailBodyFrontierCapsuleError::ArithmeticOverflow {
                    field: "encoded atom count",
                },
            )?;
            if let Some(target) = instruction_target(atom.instruction) {
                targets.insert(AnchorKey::from_target(target));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encode_program(
    code: &mut Vec<u8>,
    kind: X64TailBodyCapsuleProgramKind,
    ordinal: u32,
    atoms: &[X64TailBodyAtom],
    transition_capsule: &X64TailCandidateCapsule,
    anchors: &BTreeMap<AnchorKey, u32>,
    fixups: &mut Vec<X64TailBodyCapsuleFixupReceipt>,
    references: &mut Vec<X64TailBodyCapsuleExternalReference>,
    work: &mut u64,
) -> Result<X64TailBodyCapsuleProgramReceipt, X64TailBodyFrontierCapsuleError> {
    let start = usize_to_u32(code.len(), "program start")?;
    let mut encoded_atoms = 0u32;
    let mut external_references = 0u32;
    for atom in atoms {
        if let X64TailBodyAtomInstruction::CapsuleTransition {
            edge_ordinal,
            capsule_start,
            capsule_end,
        } = atom.instruction
        {
            if kind != X64TailBodyCapsuleProgramKind::Site {
                return Err(X64TailBodyFrontierCapsuleError::InvalidField {
                    field: "frontier transition reference",
                });
            }
            let source = transition_capsule
                .transition_receipts()
                .iter()
                .find(|candidate| candidate.edge_ordinal == edge_ordinal)
                .ok_or(X64TailBodyFrontierCapsuleError::InvalidField {
                    field: "external transition edge",
                })?;
            if source.start != capsule_start || source.end != capsule_end {
                return Err(X64TailBodyFrontierCapsuleError::InvalidField {
                    field: "external transition span",
                });
            }
            references.push(X64TailBodyCapsuleExternalReference {
                site_ordinal: ordinal,
                atom_ordinal: atom.ordinal,
                edge_ordinal,
                capsule_start,
                capsule_end,
            });
            external_references =
                checked_add_u32(external_references, 1, "program external references")?;
            *work = charge(*work, 1)?;
            continue;
        }
        let before = code.len();
        encode_atom(code, kind, ordinal, atom, anchors, fixups)?;
        let emitted = code.len().checked_sub(before).ok_or(
            X64TailBodyFrontierCapsuleError::ArithmeticOverflow {
                field: "emitted bytes",
            },
        )?;
        if usize_to_u32(emitted, "emitted atom bytes")? != atom_len(atom)? {
            return Err(X64TailBodyFrontierCapsuleError::InvalidField {
                field: "exact atom byte length",
            });
        }
        encoded_atoms = checked_add_u32(encoded_atoms, 1, "program encoded atoms")?;
        *work = charge(
            *work,
            usize_to_u64(emitted, "emitted work")?
                .checked_add(1)
                .ok_or(X64TailBodyFrontierCapsuleError::ArithmeticOverflow {
                    field: "encoder work",
                })?,
        )?;
    }
    Ok(X64TailBodyCapsuleProgramReceipt {
        kind,
        ordinal,
        start,
        end: usize_to_u32(code.len(), "program end")?,
        encoded_atoms,
        external_references,
    })
}

fn encode_atom(
    code: &mut Vec<u8>,
    program_kind: X64TailBodyCapsuleProgramKind,
    program_ordinal: u32,
    atom: &X64TailBodyAtom,
    anchors: &BTreeMap<AnchorKey, u32>,
    fixups: &mut Vec<X64TailBodyCapsuleFixupReceipt>,
) -> Result<(), X64TailBodyFrontierCapsuleError> {
    match atom.instruction {
        X64TailBodyAtomInstruction::Acquire { read, destination } => {
            encode_acquire(code, read, destination)?
        }
        X64TailBodyAtomInstruction::Define { source, definition } => {
            encode_define(code, source, definition.physical)?
        }
        X64TailBodyAtomInstruction::I64Wrapping { opcode, .. } => match opcode {
            X64I64Opcode::Add => code.extend_from_slice(&[0x48, 0x01, 0xc8]),
            X64I64Opcode::Sub => code.extend_from_slice(&[0x48, 0x29, 0xc8]),
            X64I64Opcode::Mul => code.extend_from_slice(&[0x48, 0x0f, 0xaf, 0xc1]),
        },
        X64TailBodyAtomInstruction::Sse2F64 { opcode, .. } => code.extend_from_slice(&[
            0xf2,
            0x0f,
            match opcode {
                X64Sse2F64Opcode::AddSd => 0x58,
                X64Sse2F64Opcode::SubSd => 0x5c,
            },
            0xc1,
        ]),
        X64TailBodyAtomInstruction::I64Setcc { condition, .. } => {
            code.extend_from_slice(&[
                0x48,
                0x39,
                0xc8,
                0x0f,
                match condition {
                    X64SetCondition::SignedLessThan => 0x9c,
                    X64SetCondition::SignedGreaterOrEqual => 0x9d,
                },
                0xc0,
                0x48,
                0x0f,
                0xb6,
                0xc0,
            ]);
        }
        X64TailBodyAtomInstruction::TestBool => code.extend_from_slice(&[0x48, 0x85, 0xc0]),
        X64TailBodyAtomInstruction::BranchNonZeroRel32 { target } => emit_rel32(
            code,
            &[0x0f, 0x85],
            6,
            2,
            target,
            program_kind,
            program_ordinal,
            atom.ordinal,
            anchors,
            fixups,
        )?,
        X64TailBodyAtomInstruction::JumpRel32 { target } => emit_rel32(
            code,
            &[0xe9],
            5,
            1,
            target,
            program_kind,
            program_ordinal,
            atom.ordinal,
            anchors,
            fixups,
        )?,
        X64TailBodyAtomInstruction::BoundsNegativeRel32 { target } => {
            code.extend_from_slice(&[0x48, 0x85, 0xd2]);
            emit_rel32(
                code,
                &[0x0f, 0x88],
                6,
                2,
                target,
                program_kind,
                program_ordinal,
                atom.ordinal,
                anchors,
                fixups,
            )?;
        }
        X64TailBodyAtomInstruction::BoundsUpperRel32 { target } => {
            code.extend_from_slice(&[0x48, 0x39, 0xca]);
            emit_rel32(
                code,
                &[0x0f, 0x83],
                6,
                2,
                target,
                program_kind,
                program_ordinal,
                atom.ordinal,
                anchors,
                fixups,
            )?;
        }
        X64TailBodyAtomInstruction::ArrayGetF64 { .. } => {
            code.extend_from_slice(&[0xf2, 0x0f, 0x10, 0x04, 0xd0]);
        }
        X64TailBodyAtomInstruction::AdapterFlush { word } => {
            encode_adapter(code, word.logical, word.register, true)?;
        }
        X64TailBodyAtomInstruction::AdapterHydrate { word } => {
            encode_adapter(code, word.logical, word.register, false)?;
        }
        X64TailBodyAtomInstruction::FrameScratchSave { source, .. } => {
            if source.word_type == X64TailWordType::F64 {
                emit_xmm_frame_load(code, source.offset, 0);
            } else {
                emit_gpr_frame_load(code, source.offset, 0);
            }
        }
        X64TailBodyAtomInstruction::FrameMove {
            source,
            destination,
        } => encode_frame_move(code, source, destination)?,
        X64TailBodyAtomInstruction::ReturnWord {
            source,
            destination,
        } => encode_return_word(code, source, destination)?,
        X64TailBodyAtomInstruction::MoveReturnF64BitsToXmm0 => {
            code.extend_from_slice(&[0x66, 0x48, 0x0f, 0x6e, 0xc0]);
        }
        X64TailBodyAtomInstruction::CanonicalizeReturnF64 => {
            code.extend_from_slice(&[0x66, 0x0f, 0x2e, 0xc0]);
            emit_movabs(code, 1, CANONICAL_NAN_BITS);
            code.extend_from_slice(&[0x48, 0x0f, 0x4a, 0xc1]);
        }
        X64TailBodyAtomInstruction::CapsuleTransition { .. } => {
            return Err(X64TailBodyFrontierCapsuleError::InvalidField {
                field: "encoded capsule transition",
            });
        }
    }
    Ok(())
}

fn encode_acquire(
    code: &mut Vec<u8>,
    read: X64TailBoundRead,
    destination: X64TailBodyScratch,
) -> Result<(), X64TailBodyFrontierCapsuleError> {
    match read {
        X64TailBoundRead::Immediate(immediate) => {
            let bits = immediate_bits(immediate);
            if let Some(destination) = scratch_gpr(destination) {
                emit_movabs(code, destination, bits);
            } else if let Some(destination) = scratch_xmm(destination) {
                emit_movabs(code, 0, bits);
                emit_gpr_to_xmm(code, 0, destination);
            } else {
                return Err(X64TailBodyFrontierCapsuleError::InvalidField {
                    field: "acquire scratch",
                });
            }
        }
        X64TailBoundRead::Location { physical, .. } => match physical {
            X64TailPhysicalLocation::Register { register, .. } => {
                if let (Some(source), Some(destination)) =
                    (physical_gpr(register), scratch_gpr(destination))
                {
                    emit_gpr_copy(code, source, destination);
                } else if let (Some(source), Some(destination)) =
                    (physical_xmm(register), scratch_xmm(destination))
                {
                    emit_xmm_copy(code, source, destination);
                } else {
                    return Err(X64TailBodyFrontierCapsuleError::InvalidField {
                        field: "typed register acquire",
                    });
                }
            }
            X64TailPhysicalLocation::Frame(frame) => {
                if let Some(destination) = scratch_gpr(destination) {
                    emit_gpr_frame_load(code, frame.offset, destination);
                } else if let Some(destination) = scratch_xmm(destination) {
                    emit_xmm_frame_load(code, frame.offset, destination);
                } else {
                    return Err(X64TailBodyFrontierCapsuleError::InvalidField {
                        field: "typed frame acquire",
                    });
                }
            }
        },
    }
    Ok(())
}

fn encode_define(
    code: &mut Vec<u8>,
    source: X64TailBodyScratch,
    destination: X64TailPhysicalLocation,
) -> Result<(), X64TailBodyFrontierCapsuleError> {
    match destination {
        X64TailPhysicalLocation::Register { register, .. } => {
            if let (Some(source), Some(destination)) = (scratch_gpr(source), physical_gpr(register))
            {
                emit_gpr_copy(code, source, destination);
            } else if let (Some(source), Some(destination)) =
                (scratch_xmm(source), physical_xmm(register))
            {
                emit_xmm_copy(code, source, destination);
            } else {
                return Err(X64TailBodyFrontierCapsuleError::InvalidField {
                    field: "typed register definition",
                });
            }
        }
        X64TailPhysicalLocation::Frame(frame) => {
            if let Some(source) = scratch_gpr(source) {
                emit_gpr_frame_store(code, source, frame.offset);
            } else if let Some(source) = scratch_xmm(source) {
                emit_xmm_frame_store(code, source, frame.offset);
            } else {
                return Err(X64TailBodyFrontierCapsuleError::InvalidField {
                    field: "typed frame definition",
                });
            }
        }
    }
    Ok(())
}

fn encode_adapter(
    code: &mut Vec<u8>,
    logical: X64TailWordLocation,
    register: X64TailPhysicalRegister,
    flush: bool,
) -> Result<(), X64TailBodyFrontierCapsuleError> {
    if let Some(register) = physical_gpr(register) {
        if flush {
            emit_gpr_frame_store(code, register, logical.offset);
        } else {
            emit_gpr_frame_load(code, logical.offset, register);
        }
    } else if let Some(register) = physical_xmm(register) {
        if flush {
            emit_xmm_frame_store(code, register, logical.offset);
        } else {
            emit_xmm_frame_load(code, logical.offset, register);
        }
    } else {
        return Err(X64TailBodyFrontierCapsuleError::InvalidField {
            field: "adapter register",
        });
    }
    Ok(())
}

fn encode_frame_move(
    code: &mut Vec<u8>,
    source: X64TailScheduledSource,
    destination: X64TailWordLocation,
) -> Result<(), X64TailBodyFrontierCapsuleError> {
    match source {
        X64TailScheduledSource::Location(source) => {
            if source.word_type == X64TailWordType::F64 {
                emit_xmm_frame_load(code, source.offset, 1);
                emit_xmm_frame_store(code, 1, destination.offset);
            } else {
                emit_gpr_frame_load(code, source.offset, 1);
                emit_gpr_frame_store(code, 1, destination.offset);
            }
        }
        X64TailScheduledSource::Immediate(immediate) => {
            emit_movabs(code, 1, immediate_bits(immediate));
            emit_gpr_frame_store(code, 1, destination.offset);
        }
        X64TailScheduledSource::Scratch { word_type, .. } => {
            if word_type == X64TailWordType::F64 {
                emit_xmm_frame_store(code, 0, destination.offset);
            } else {
                emit_gpr_frame_store(code, 0, destination.offset);
            }
        }
    }
    Ok(())
}

fn encode_return_word(
    code: &mut Vec<u8>,
    source: X64TailScheduledSource,
    destination: X64TailBodyScratch,
) -> Result<(), X64TailBodyFrontierCapsuleError> {
    let destination =
        scratch_gpr(destination).ok_or(X64TailBodyFrontierCapsuleError::InvalidField {
            field: "return word destination",
        })?;
    if !matches!(destination, 0 | 2) {
        return Err(X64TailBodyFrontierCapsuleError::InvalidField {
            field: "return ABI word destination",
        });
    }
    match source {
        X64TailScheduledSource::Location(location) => {
            emit_gpr_frame_load(code, location.offset, destination);
        }
        X64TailScheduledSource::Immediate(value) => {
            let bits = immediate_bits(value);
            if bits == 0 {
                code.extend_from_slice(&[0x31, 0xc0 | (destination << 3) | destination]);
            } else {
                emit_movabs(code, destination, bits);
            }
        }
        X64TailScheduledSource::Scratch { .. } => {
            return Err(X64TailBodyFrontierCapsuleError::InvalidField {
                field: "return scratch source",
            });
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_rel32(
    code: &mut Vec<u8>,
    prefix: &[u8],
    instruction_length: u32,
    patch_relative: u32,
    target: X64TailBodyControlTarget,
    program_kind: X64TailBodyCapsuleProgramKind,
    program_ordinal: u32,
    atom_ordinal: u32,
    anchors: &BTreeMap<AnchorKey, u32>,
    fixups: &mut Vec<X64TailBodyCapsuleFixupReceipt>,
) -> Result<(), X64TailBodyFrontierCapsuleError> {
    let instruction_start = usize_to_u32(code.len(), "rel32 instruction start")?;
    let target_offset = anchors
        .get(&AnchorKey::from_target(target))
        .copied()
        .ok_or(X64TailBodyFrontierCapsuleError::InvalidField {
            field: "rel32 typed anchor",
        })?;
    let next = i64::from(instruction_start)
        .checked_add(i64::from(instruction_length))
        .ok_or(X64TailBodyFrontierCapsuleError::ArithmeticOverflow {
            field: "rel32 next instruction",
        })?;
    let displacement_i64 = i64::from(target_offset) - next;
    let displacement = i32::try_from(displacement_i64).map_err(|_| {
        X64TailBodyFrontierCapsuleError::Rel32OutOfRange {
            program: program_ordinal,
            atom: atom_ordinal,
            displacement: displacement_i64,
        }
    })?;
    code.extend_from_slice(prefix);
    let patch_offset = instruction_start.checked_add(patch_relative).ok_or(
        X64TailBodyFrontierCapsuleError::ArithmeticOverflow {
            field: "rel32 patch offset",
        },
    )?;
    code.extend_from_slice(&displacement.to_le_bytes());
    fixups.push(X64TailBodyCapsuleFixupReceipt {
        program_kind,
        program_ordinal,
        atom_ordinal,
        patch_offset,
        target,
        target_offset,
        displacement,
    });
    Ok(())
}

fn emit_movabs(code: &mut Vec<u8>, register: u8, bits: u64) {
    code.push(0x48 | ((register >> 3) & 1));
    code.push(0xb8 | (register & 7));
    code.extend_from_slice(&bits.to_le_bytes());
}

fn emit_gpr_copy(code: &mut Vec<u8>, source: u8, destination: u8) {
    code.push(0x48 | (((source >> 3) & 1) << 2) | ((destination >> 3) & 1));
    code.push(0x89);
    code.push(0xc0 | ((source & 7) << 3) | (destination & 7));
}

fn emit_gpr_frame_load(code: &mut Vec<u8>, offset: u32, destination: u8) {
    code.extend_from_slice(&[
        0x48 | (((destination >> 3) & 1) << 2),
        0x8b,
        0x84 | ((destination & 7) << 3),
        0x24,
    ]);
    code.extend_from_slice(&offset.to_le_bytes());
}

fn emit_gpr_frame_store(code: &mut Vec<u8>, source: u8, offset: u32) {
    code.extend_from_slice(&[
        0x48 | (((source >> 3) & 1) << 2),
        0x89,
        0x84 | ((source & 7) << 3),
        0x24,
    ]);
    code.extend_from_slice(&offset.to_le_bytes());
}

fn emit_xmm_copy(code: &mut Vec<u8>, source: u8, destination: u8) {
    code.extend_from_slice(&[
        0xf2,
        0x0f,
        0x10,
        0xc0 | ((destination & 7) << 3) | (source & 7),
    ]);
}

fn emit_xmm_frame_load(code: &mut Vec<u8>, offset: u32, destination: u8) {
    code.extend_from_slice(&[0xf2, 0x0f, 0x10, 0x84 | ((destination & 7) << 3), 0x24]);
    code.extend_from_slice(&offset.to_le_bytes());
}

fn emit_xmm_frame_store(code: &mut Vec<u8>, source: u8, offset: u32) {
    code.extend_from_slice(&[0xf2, 0x0f, 0x11, 0x84 | ((source & 7) << 3), 0x24]);
    code.extend_from_slice(&offset.to_le_bytes());
}

fn emit_gpr_to_xmm(code: &mut Vec<u8>, source: u8, destination: u8) {
    code.extend_from_slice(&[
        0x66,
        0x48,
        0x0f,
        0x6e,
        0xc0 | ((destination & 7) << 3) | (source & 7),
    ]);
}

fn validate_envelope(
    capsule: &X64TailBodyFrontierCapsule,
    realization: &X64TailBodyFrontierRealization,
    transition_capsule: &X64TailCandidateCapsule,
) -> Result<(), X64TailBodyFrontierCapsuleError> {
    if capsule.schema_version != X64_TAIL_BODY_CAPSULE_SCHEMA_VERSION
        || capsule.policy_version != X64_TAIL_BODY_CAPSULE_POLICY_VERSION
        || capsule.decoder_policy_version
            != super::x64_tail_body_frontier_decode::X64_TAIL_BODY_DECODER_POLICY_VERSION
        || capsule.source_target_semantic_hash != realization.source_target_semantic_hash()
        || capsule.source_transition_capsule_hash != transition_capsule.capsule_hash()
        || capsule.source_body_frontier_realization_hash != realization.realization_hash()
    {
        return Err(X64TailBodyFrontierCapsuleError::InvalidField {
            field: "provenance envelope",
        });
    }
    Ok(())
}

fn audit_decoded(
    capsule: &X64TailBodyFrontierCapsule,
    decoded: &X64TailBodyDecodedCapsule,
) -> Result<(), X64TailBodyFrontierCapsuleError> {
    audit_raw_receipts(
        &capsule.program_receipts,
        &capsule.anchor_receipts,
        &capsule.fixup_receipts,
        &capsule.external_references,
        decoded,
    )?;
    let decoded_totals = X64TailBodyFrontierCapsuleTotals {
        programs: usize_to_u32(decoded.programs.len(), "decoded programs")?,
        site_programs: usize_to_u32(
            decoded
                .programs
                .iter()
                .filter(|program| program.kind == X64TailBodyDecodedProgramKind::Site)
                .count(),
            "decoded sites",
        )?,
        frontier_programs: usize_to_u32(
            decoded
                .programs
                .iter()
                .filter(|program| program.kind == X64TailBodyDecodedProgramKind::Frontier)
                .count(),
            "decoded frontiers",
        )?,
        encoded_atoms: decoded.decoded_atoms,
        primitive_instructions: decoded.primitive_instructions,
        external_references: usize_to_u32(decoded.external_references.len(), "decoded references")?,
        typed_anchors: usize_to_u32(decoded.anchors.len(), "decoded anchors")?,
        resolved_fixups: usize_to_u32(decoded.fixups.len(), "decoded fixups")?,
        site_bytes: decoded.site_bytes,
        frontier_bytes: decoded.frontier_bytes,
        anchor_bytes: decoded.anchor_bytes,
        code_bytes: decoded.code_bytes,
        retained_transition_bytes: decoded.retained_transition_bytes,
        encoder_work: capsule.totals.encoder_work,
        decoder_work: decoded.decode_work,
    };
    if capsule.totals != decoded_totals {
        return Err(X64TailBodyFrontierCapsuleError::ReceiptMismatch);
    }
    Ok(())
}

fn audit_raw_receipts(
    programs: &[X64TailBodyCapsuleProgramReceipt],
    anchors: &[X64TailBodyCapsuleAnchorReceipt],
    fixups: &[X64TailBodyCapsuleFixupReceipt],
    references: &[X64TailBodyCapsuleExternalReference],
    decoded: &X64TailBodyDecodedCapsule,
) -> Result<(), X64TailBodyFrontierCapsuleError> {
    if programs.len() != decoded.programs.len()
        || anchors.len() != decoded.anchors.len()
        || fixups.len() != decoded.fixups.len()
        || references.len() != decoded.external_references.len()
    {
        return Err(X64TailBodyFrontierCapsuleError::ReceiptMismatch);
    }
    for (receipt, recovered) in programs.iter().zip(&decoded.programs) {
        let kind = match recovered.kind {
            X64TailBodyDecodedProgramKind::Site => X64TailBodyCapsuleProgramKind::Site,
            X64TailBodyDecodedProgramKind::Frontier => X64TailBodyCapsuleProgramKind::Frontier,
        };
        if *receipt
            != (X64TailBodyCapsuleProgramReceipt {
                kind,
                ordinal: recovered.ordinal,
                start: recovered.start,
                end: recovered.end,
                encoded_atoms: usize_to_u32(recovered.atoms.len(), "recovered atoms")?,
                external_references: recovered.external_references,
            })
        {
            return Err(X64TailBodyFrontierCapsuleError::ReceiptMismatch);
        }
    }
    for (receipt, recovered) in anchors.iter().zip(&decoded.anchors) {
        if receipt.target != recovered.target || receipt.offset != recovered.offset {
            return Err(X64TailBodyFrontierCapsuleError::ReceiptMismatch);
        }
    }
    for (receipt, recovered) in fixups.iter().zip(&decoded.fixups) {
        let kind = match recovered.program_kind {
            X64TailBodyDecodedProgramKind::Site => X64TailBodyCapsuleProgramKind::Site,
            X64TailBodyDecodedProgramKind::Frontier => X64TailBodyCapsuleProgramKind::Frontier,
        };
        if *receipt
            != (X64TailBodyCapsuleFixupReceipt {
                program_kind: kind,
                program_ordinal: recovered.program_ordinal,
                atom_ordinal: recovered.atom_ordinal,
                patch_offset: recovered.patch_offset,
                target: recovered.target,
                target_offset: recovered.target_offset,
                displacement: recovered.displacement,
            })
        {
            return Err(X64TailBodyFrontierCapsuleError::ReceiptMismatch);
        }
    }
    for (receipt, recovered) in references.iter().zip(&decoded.external_references) {
        if *receipt
            != (X64TailBodyCapsuleExternalReference {
                site_ordinal: recovered.site_ordinal,
                atom_ordinal: recovered.atom_ordinal,
                edge_ordinal: recovered.edge_ordinal,
                capsule_start: recovered.capsule_start,
                capsule_end: recovered.capsule_end,
            })
        {
            return Err(X64TailBodyFrontierCapsuleError::ReceiptMismatch);
        }
    }
    Ok(())
}

fn capsule_bytes_without_seal(
    capsule: &X64TailBodyFrontierCapsule,
) -> Result<Vec<u8>, X64TailBodyFrontierCapsuleError> {
    let mut encoder = EvidenceEncoder::new();
    encoder.bytes(CAPSULE_DOMAIN)?;
    encoder.version(capsule.schema_version)?;
    encoder.version(capsule.policy_version)?;
    encoder.version(capsule.decoder_policy_version)?;
    encoder.hash(capsule.source_target_semantic_hash)?;
    encoder.hash(capsule.source_transition_capsule_hash)?;
    encoder.hash(capsule.source_body_frontier_realization_hash)?;
    encoder.len(capsule.program_receipts.len())?;
    for receipt in &capsule.program_receipts {
        encoder.u8(program_kind_tag(receipt.kind))?;
        encoder.u32(receipt.ordinal)?;
        encoder.u32(receipt.start)?;
        encoder.u32(receipt.end)?;
        encoder.u32(receipt.encoded_atoms)?;
        encoder.u32(receipt.external_references)?;
    }
    encoder.len(capsule.anchor_receipts.len())?;
    for receipt in &capsule.anchor_receipts {
        encode_target(&mut encoder, receipt.target)?;
        encoder.u32(receipt.offset)?;
    }
    encoder.len(capsule.fixup_receipts.len())?;
    for receipt in &capsule.fixup_receipts {
        encoder.u8(program_kind_tag(receipt.program_kind))?;
        encoder.u32(receipt.program_ordinal)?;
        encoder.u32(receipt.atom_ordinal)?;
        encoder.u32(receipt.patch_offset)?;
        encode_target(&mut encoder, receipt.target)?;
        encoder.u32(receipt.target_offset)?;
        encoder.i32(receipt.displacement)?;
    }
    encoder.len(capsule.external_references.len())?;
    for reference in &capsule.external_references {
        encoder.u32(reference.site_ordinal)?;
        encoder.u32(reference.atom_ordinal)?;
        encoder.u32(reference.edge_ordinal)?;
        encoder.u32(reference.capsule_start)?;
        encoder.u32(reference.capsule_end)?;
    }
    encoder.len(capsule.code.len())?;
    encoder.bytes(&capsule.code)?;
    encoder.hash(capsule.code_hash)?;
    encode_totals(&mut encoder, capsule.totals)?;
    Ok(encoder.finish())
}

fn encode_target(
    encoder: &mut EvidenceEncoder,
    target: X64TailBodyControlTarget,
) -> Result<(), X64TailBodyFrontierCapsuleError> {
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

fn encode_totals(
    encoder: &mut EvidenceEncoder,
    totals: X64TailBodyFrontierCapsuleTotals,
) -> Result<(), X64TailBodyFrontierCapsuleError> {
    encoder.u32(totals.programs)?;
    encoder.u32(totals.site_programs)?;
    encoder.u32(totals.frontier_programs)?;
    encoder.u32(totals.encoded_atoms)?;
    encoder.u32(totals.primitive_instructions)?;
    encoder.u32(totals.external_references)?;
    encoder.u32(totals.typed_anchors)?;
    encoder.u32(totals.resolved_fixups)?;
    encoder.u32(totals.site_bytes)?;
    encoder.u32(totals.frontier_bytes)?;
    encoder.u32(totals.anchor_bytes)?;
    encoder.u32(totals.code_bytes)?;
    encoder.u32(totals.retained_transition_bytes)?;
    encoder.u64(totals.encoder_work)?;
    encoder.u64(totals.decoder_work)
}

const fn program_kind_tag(kind: X64TailBodyCapsuleProgramKind) -> u8 {
    match kind {
        X64TailBodyCapsuleProgramKind::Site => 0,
        X64TailBodyCapsuleProgramKind::Frontier => 1,
    }
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

const fn immediate_bits(immediate: X64TailImmediateWord) -> u64 {
    match immediate {
        X64TailImmediateWord::Bool(value) => value as u64,
        X64TailImmediateWord::I64(value) => value as u64,
        X64TailImmediateWord::F64Bits(bits) => bits,
    }
}

fn atom_len(atom: &X64TailBodyAtom) -> Result<u32, X64TailBodyFrontierCapsuleError> {
    atom.end
        .checked_sub(atom.start)
        .ok_or(X64TailBodyFrontierCapsuleError::InvalidField {
            field: "atom extent",
        })
}

fn ensure_limit(
    field: &'static str,
    limit: u32,
    actual: usize,
) -> Result<(), X64TailBodyFrontierCapsuleError> {
    let actual = usize_to_u64(actual, field)?;
    if actual > u64::from(limit) {
        return Err(X64TailBodyFrontierCapsuleError::LimitExceeded {
            field,
            limit: u64::from(limit),
            actual,
        });
    }
    Ok(())
}

fn charge(work: u64, amount: u64) -> Result<u64, X64TailBodyFrontierCapsuleError> {
    let work =
        work.checked_add(amount)
            .ok_or(X64TailBodyFrontierCapsuleError::ArithmeticOverflow {
                field: "encoder work",
            })?;
    if work > X64_TAIL_BODY_CAPSULE_MAX_ENCODER_WORK {
        return Err(X64TailBodyFrontierCapsuleError::LimitExceeded {
            field: "encoder work",
            limit: X64_TAIL_BODY_CAPSULE_MAX_ENCODER_WORK,
            actual: work,
        });
    }
    Ok(work)
}

fn checked_add_u32(
    left: u32,
    right: u32,
    field: &'static str,
) -> Result<u32, X64TailBodyFrontierCapsuleError> {
    left.checked_add(right)
        .ok_or(X64TailBodyFrontierCapsuleError::ArithmeticOverflow { field })
}

fn usize_to_u32(value: usize, field: &'static str) -> Result<u32, X64TailBodyFrontierCapsuleError> {
    u32::try_from(value).map_err(|_| X64TailBodyFrontierCapsuleError::ArithmeticOverflow { field })
}

fn usize_to_u64(value: usize, field: &'static str) -> Result<u64, X64TailBodyFrontierCapsuleError> {
    u64::try_from(value).map_err(|_| X64TailBodyFrontierCapsuleError::ArithmeticOverflow { field })
}

fn u32_to_usize(value: u32, field: &'static str) -> Result<usize, X64TailBodyFrontierCapsuleError> {
    usize::try_from(value)
        .map_err(|_| X64TailBodyFrontierCapsuleError::ArithmeticOverflow { field })
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

    fn reserve(&mut self, additional: usize) -> Result<(), X64TailBodyFrontierCapsuleError> {
        let actual = self.bytes.len().checked_add(additional).ok_or(
            X64TailBodyFrontierCapsuleError::ArithmeticOverflow {
                field: "capsule evidence length",
            },
        )?;
        if actual > X64_TAIL_BODY_CAPSULE_MAX_EVIDENCE_BYTES {
            return Err(X64TailBodyFrontierCapsuleError::EncodingLimit { actual });
        }
        self.bytes
            .try_reserve(additional)
            .map_err(|_| X64TailBodyFrontierCapsuleError::EncodingLimit { actual })
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), X64TailBodyFrontierCapsuleError> {
        self.reserve(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), X64TailBodyFrontierCapsuleError> {
        self.bytes(&[value])
    }

    fn u32(&mut self, value: u32) -> Result<(), X64TailBodyFrontierCapsuleError> {
        self.bytes(&value.to_le_bytes())
    }

    fn i32(&mut self, value: i32) -> Result<(), X64TailBodyFrontierCapsuleError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), X64TailBodyFrontierCapsuleError> {
        self.bytes(&value.to_le_bytes())
    }

    fn len(&mut self, value: usize) -> Result<(), X64TailBodyFrontierCapsuleError> {
        self.u32(usize_to_u32(value, "evidence collection length")?)
    }

    fn version(&mut self, value: (u16, u16, u16)) -> Result<(), X64TailBodyFrontierCapsuleError> {
        self.bytes(&value.0.to_le_bytes())?;
        self.bytes(&value.1.to_le_bytes())?;
        self.bytes(&value.2.to_le_bytes())
    }

    fn hash(&mut self, value: SemanticHash) -> Result<(), X64TailBodyFrontierCapsuleError> {
        self.bytes(&value.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::corevm0_gate_a::CoreVmGateAWorkload;
    use crate::core::x64_native_lighthouse::X64NativeLighthousePackage;
    use crate::core::{
        emit_x64_tail_body_frontier_realization, emit_x64_tail_candidate_capsule,
        emit_x64_tail_physical_allocation, emit_x64_tail_site_binding_proof,
        emit_x64_tail_state_plan, emit_x64_tail_template_realization, X64TailAdapterWord,
        X64TailBodyFrontierRealization, X64TailBoundDefinition, X64TailSiteBindingProof,
        X64_TARGET_ENCODER_POLICY_VERSION,
    };

    type Build = (
        X64NativeLighthousePackage,
        X64TailStatePlan,
        X64TailPhysicalAllocation,
        X64TailTemplateRealization,
        X64TailCandidateCapsule,
        X64TailSiteBindingProof,
        X64TailBodyFrontierRealization,
    );

    fn build(workload: CoreVmGateAWorkload) -> Build {
        let package =
            X64NativeLighthousePackage::build(workload).expect("lighthouse package must build");
        let logical = emit_x64_tail_state_plan(package.target()).expect("logical plan must emit");
        let physical = emit_x64_tail_physical_allocation(package.target(), &logical)
            .expect("physical allocation must emit");
        let templates = emit_x64_tail_template_realization(package.target(), &logical, &physical)
            .expect("tail templates must emit");
        let transition_capsule =
            emit_x64_tail_candidate_capsule(package.target(), &logical, &physical, &templates)
                .expect("transition capsule must emit");
        let binding = emit_x64_tail_site_binding_proof(
            package.target(),
            &logical,
            &physical,
            &templates,
            &transition_capsule,
        )
        .expect("site binding must emit");
        let realization = emit_x64_tail_body_frontier_realization(
            package.target(),
            &logical,
            &physical,
            &templates,
            &transition_capsule,
            &binding,
        )
        .expect("body realization must emit");
        (
            package,
            logical,
            physical,
            templates,
            transition_capsule,
            binding,
            realization,
        )
    }

    fn frame(offset: u32, word_type: X64TailWordType) -> X64TailWordLocation {
        X64TailWordLocation { offset, word_type }
    }

    fn encode_one(
        instruction: X64TailBodyAtomInstruction,
        length: u32,
    ) -> (Vec<u8>, Vec<X64TailBodyCapsuleFixupReceipt>) {
        let mut anchors = BTreeMap::new();
        if let Some(target) = instruction_target(instruction) {
            anchors.insert(AnchorKey::from_target(target), 100);
        }
        let atom = X64TailBodyAtom {
            ordinal: 0,
            start: 0,
            end: length,
            instruction,
            clobbers: Vec::new(),
        };
        let mut code = Vec::new();
        let mut fixups = Vec::new();
        encode_atom(
            &mut code,
            X64TailBodyCapsuleProgramKind::Site,
            7,
            &atom,
            &anchors,
            &mut fixups,
        )
        .expect("locked vector must encode");
        assert_eq!(
            code.len(),
            usize::try_from(length).expect("length must fit")
        );
        (code, fixups)
    }

    #[test]
    fn owned_encoder_has_locked_vectors_for_every_body_family() {
        assert_eq!(
            encode_one(
                X64TailBodyAtomInstruction::Acquire {
                    read: X64TailBoundRead::Immediate(X64TailImmediateWord::I64(
                        0x0102_0304_0506_0708,
                    )),
                    destination: X64TailBodyScratch::Rdx,
                },
                10,
            )
            .0,
            vec![0x48, 0xba, 8, 7, 6, 5, 4, 3, 2, 1]
        );
        assert_eq!(
            encode_one(
                X64TailBodyAtomInstruction::Acquire {
                    read: X64TailBoundRead::Immediate(X64TailImmediateWord::F64Bits(
                        0x3ff0_0000_0000_0000,
                    )),
                    destination: X64TailBodyScratch::Xmm1,
                },
                15,
            )
            .0,
            vec![0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0xf0, 0x3f, 0x66, 0x48, 0x0f, 0x6e, 0xc8,]
        );
        assert_eq!(
            encode_one(
                X64TailBodyAtomInstruction::Acquire {
                    read: X64TailBoundRead::Location {
                        logical: frame(0x20, X64TailWordType::I64),
                        physical: X64TailPhysicalLocation::Register {
                            register: X64TailPhysicalRegister::R9,
                            word_type: X64TailWordType::I64,
                        },
                    },
                    destination: X64TailBodyScratch::Rcx,
                },
                3,
            )
            .0,
            vec![0x4c, 0x89, 0xc9]
        );
        assert_eq!(
            encode_one(
                X64TailBodyAtomInstruction::Acquire {
                    read: X64TailBoundRead::Location {
                        logical: frame(0x30, X64TailWordType::F64),
                        physical: X64TailPhysicalLocation::Frame(
                            frame(0x30, X64TailWordType::F64,)
                        ),
                    },
                    destination: X64TailBodyScratch::Xmm0,
                },
                9,
            )
            .0,
            vec![0xf2, 0x0f, 0x10, 0x84, 0x24, 0x30, 0, 0, 0]
        );
        assert_eq!(
            encode_one(
                X64TailBodyAtomInstruction::Define {
                    source: X64TailBodyScratch::Rdx,
                    definition: X64TailBoundDefinition {
                        logical: frame(0x38, X64TailWordType::I64),
                        physical: X64TailPhysicalLocation::Register {
                            register: X64TailPhysicalRegister::R10,
                            word_type: X64TailWordType::I64,
                        },
                    },
                },
                3,
            )
            .0,
            vec![0x49, 0x89, 0xd2]
        );
        assert_eq!(
            encode_one(
                X64TailBodyAtomInstruction::Define {
                    source: X64TailBodyScratch::Xmm1,
                    definition: X64TailBoundDefinition {
                        logical: frame(0x40, X64TailWordType::F64),
                        physical: X64TailPhysicalLocation::Frame(
                            frame(0x40, X64TailWordType::F64,)
                        ),
                    },
                },
                9,
            )
            .0,
            vec![0xf2, 0x0f, 0x11, 0x8c, 0x24, 0x40, 0, 0, 0]
        );
        assert_eq!(
            encode_one(
                X64TailBodyAtomInstruction::I64Wrapping {
                    opcode: X64I64Opcode::Mul,
                    definition: frame(0, X64TailWordType::I64),
                },
                4,
            )
            .0,
            vec![0x48, 0x0f, 0xaf, 0xc1]
        );
        assert_eq!(
            encode_one(
                X64TailBodyAtomInstruction::Sse2F64 {
                    opcode: X64Sse2F64Opcode::SubSd,
                    definition: frame(0, X64TailWordType::F64),
                },
                4,
            )
            .0,
            vec![0xf2, 0x0f, 0x5c, 0xc1]
        );
        assert_eq!(
            encode_one(
                X64TailBodyAtomInstruction::I64Setcc {
                    condition: X64SetCondition::SignedLessThan,
                    definition: frame(0, X64TailWordType::Bool),
                },
                10,
            )
            .0,
            vec![0x48, 0x39, 0xc8, 0x0f, 0x9c, 0xc0, 0x48, 0x0f, 0xb6, 0xc0]
        );
        assert_eq!(
            encode_one(X64TailBodyAtomInstruction::TestBool, 3).0,
            vec![0x48, 0x85, 0xc0]
        );
        let target = X64TailBodyControlTarget::Frontier(9);
        assert_eq!(
            encode_one(X64TailBodyAtomInstruction::BranchNonZeroRel32 { target }, 6,).0,
            vec![0x0f, 0x85, 94, 0, 0, 0]
        );
        assert_eq!(
            encode_one(X64TailBodyAtomInstruction::JumpRel32 { target }, 5).0,
            vec![0xe9, 95, 0, 0, 0]
        );
        assert_eq!(
            encode_one(
                X64TailBodyAtomInstruction::BoundsNegativeRel32 { target },
                9,
            )
            .0,
            vec![0x48, 0x85, 0xd2, 0x0f, 0x88, 91, 0, 0, 0]
        );
        assert_eq!(
            encode_one(X64TailBodyAtomInstruction::BoundsUpperRel32 { target }, 9,).0,
            vec![0x48, 0x39, 0xca, 0x0f, 0x83, 91, 0, 0, 0]
        );
        assert_eq!(
            encode_one(
                X64TailBodyAtomInstruction::ArrayGetF64 {
                    definition: frame(0, X64TailWordType::F64),
                },
                5,
            )
            .0,
            vec![0xf2, 0x0f, 0x10, 0x04, 0xd0]
        );
        assert_eq!(
            encode_one(
                X64TailBodyAtomInstruction::AdapterFlush {
                    word: X64TailAdapterWord {
                        logical: frame(0x48, X64TailWordType::ArrayLength),
                        register: X64TailPhysicalRegister::R11,
                    },
                },
                8,
            )
            .0,
            vec![0x4c, 0x89, 0x9c, 0x24, 0x48, 0, 0, 0]
        );
        assert_eq!(
            encode_one(
                X64TailBodyAtomInstruction::AdapterHydrate {
                    word: X64TailAdapterWord {
                        logical: frame(0x50, X64TailWordType::F64),
                        register: X64TailPhysicalRegister::Xmm7,
                    },
                },
                9,
            )
            .0,
            vec![0xf2, 0x0f, 0x10, 0xbc, 0x24, 0x50, 0, 0, 0]
        );
        assert_eq!(
            encode_one(
                X64TailBodyAtomInstruction::FrameScratchSave {
                    source: frame(0x58, X64TailWordType::F64),
                    scratch_id: 3,
                },
                9,
            )
            .0,
            vec![0xf2, 0x0f, 0x10, 0x84, 0x24, 0x58, 0, 0, 0]
        );
        assert_eq!(
            encode_one(
                X64TailBodyAtomInstruction::FrameMove {
                    source: X64TailScheduledSource::Location(frame(0x60, X64TailWordType::I64)),
                    destination: frame(0x68, X64TailWordType::I64),
                },
                16,
            )
            .0,
            vec![0x48, 0x8b, 0x8c, 0x24, 0x60, 0, 0, 0, 0x48, 0x89, 0x8c, 0x24, 0x68, 0, 0, 0,]
        );
        assert_eq!(
            encode_one(
                X64TailBodyAtomInstruction::FrameMove {
                    source: X64TailScheduledSource::Immediate(X64TailImmediateWord::F64Bits(
                        0x4000_0000_0000_0000,
                    )),
                    destination: frame(0x70, X64TailWordType::F64),
                },
                18,
            )
            .0,
            vec![0x48, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0x40, 0x48, 0x89, 0x8c, 0x24, 0x70, 0, 0, 0,]
        );
    }

    #[test]
    fn branch_lighthouse_owns_only_new_body_frontier_bytes() {
        let (package, logical, physical, templates, transition_capsule, binding, realization) =
            build(CoreVmGateAWorkload::BranchMix);
        let original = package.target().program.code.clone();
        let original_hash = package.target().program.code_hash;
        let first = emit_x64_tail_body_frontier_capsule(
            package.target(),
            &logical,
            &physical,
            &templates,
            &transition_capsule,
            &binding,
            &realization,
        )
        .expect("body capsule must emit");
        let second = emit_x64_tail_body_frontier_capsule(
            package.target(),
            &logical,
            &physical,
            &templates,
            &transition_capsule,
            &binding,
            &realization,
        )
        .expect("body capsule must be deterministic");
        assert_eq!(first, second);
        let verified = verify_x64_tail_body_frontier_capsule(
            &first,
            &realization,
            &binding,
            &transition_capsule,
            &templates,
            &physical,
            &logical,
            package.target(),
        )
        .expect("body capsule must replay");
        assert_eq!(verified.decoded().decoded_atoms, first.totals.encoded_atoms);
        assert_eq!(
            first.totals.retained_transition_bytes,
            transition_capsule.totals().transition_bytes
        );
        assert_eq!(
            first.totals.code_bytes,
            first
                .totals
                .site_bytes
                .checked_add(first.totals.frontier_bytes)
                .and_then(|bytes| bytes.checked_add(first.totals.anchor_bytes))
                .expect("code total must fit")
        );
        assert_eq!(
            first.capsule_hash().to_hex(),
            "64f470d5b7a7d1536c2100f104e606fb5a9313b8c21685ee08a333c273d1364a"
        );
        assert_eq!(
            first.code_hash().to_hex(),
            "80de9349e0abd8604147ca1b8b3495eaa9139c58840d19eba541461e40a44c13"
        );
        assert_eq!(
            first.totals(),
            X64TailBodyFrontierCapsuleTotals {
                programs: 319,
                site_programs: 168,
                frontier_programs: 151,
                encoded_atoms: 638,
                primitive_instructions: 703,
                external_references: 108,
                typed_anchors: 71,
                resolved_fixups: 83,
                site_bytes: 970,
                frontier_bytes: 4_199,
                anchor_bytes: 71,
                code_bytes: 5_240,
                retained_transition_bytes: 2_103,
                encoder_work: 5_986,
                decoder_work: 5_986,
            }
        );
        assert_eq!(package.target().program.code, original);
        assert_eq!(package.target().program.code_hash, original_hash);
        assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
    }

    #[test]
    fn every_owned_code_bit_and_resealed_receipt_mutation_fails_closed() {
        let (package, logical, physical, templates, transition_capsule, binding, realization) =
            build(CoreVmGateAWorkload::BranchMix);
        let capsule = emit_x64_tail_body_frontier_capsule(
            package.target(),
            &logical,
            &physical,
            &templates,
            &transition_capsule,
            &binding,
            &realization,
        )
        .expect("body capsule must emit");

        for byte in 0..capsule.code.len() {
            for bit in 0..8 {
                let mut code = capsule.code.clone();
                code[byte] ^= 1 << bit;
                assert!(decode_x64_tail_body_frontier_bytes(
                    &code,
                    &realization,
                    &transition_capsule
                )
                .is_err());
            }
        }
        assert!(decode_x64_tail_body_frontier_bytes(
            &capsule.code[..capsule.code.len() - 1],
            &realization,
            &transition_capsule
        )
        .is_err());
        let mut trailing = capsule.code.clone();
        trailing.push(PROOF_ANCHOR_BYTE);
        assert!(
            decode_x64_tail_body_frontier_bytes(&trailing, &realization, &transition_capsule)
                .is_err()
        );

        let mut receipt = capsule.clone();
        receipt.program_receipts[0].end = receipt.program_receipts[0]
            .end
            .checked_add(1)
            .expect("mutation must fit");
        receipt.capsule_hash = x64_tail_body_frontier_capsule_hash(&receipt)
            .expect("mutated receipt must reseal locally");
        assert!(verify_x64_tail_body_frontier_capsule(
            &receipt,
            &realization,
            &binding,
            &transition_capsule,
            &templates,
            &physical,
            &logical,
            package.target()
        )
        .is_err());

        let mut reference = capsule.clone();
        reference.external_references[0].capsule_start ^= 1;
        reference.capsule_hash = x64_tail_body_frontier_capsule_hash(&reference)
            .expect("mutated reference must reseal locally");
        assert!(verify_x64_tail_body_frontier_capsule(
            &reference,
            &realization,
            &binding,
            &transition_capsule,
            &templates,
            &physical,
            &logical,
            package.target()
        )
        .is_err());

        let mut anchor = capsule.clone();
        anchor.anchor_receipts[0].offset ^= 1;
        anchor.capsule_hash = x64_tail_body_frontier_capsule_hash(&anchor)
            .expect("mutated anchor must reseal locally");
        assert!(verify_x64_tail_body_frontier_capsule(
            &anchor,
            &realization,
            &binding,
            &transition_capsule,
            &templates,
            &physical,
            &logical,
            package.target()
        )
        .is_err());

        let mut fixup = capsule.clone();
        fixup.fixup_receipts[0].patch_offset ^= 1;
        fixup.capsule_hash =
            x64_tail_body_frontier_capsule_hash(&fixup).expect("mutated fixup must reseal locally");
        assert!(verify_x64_tail_body_frontier_capsule(
            &fixup,
            &realization,
            &binding,
            &transition_capsule,
            &templates,
            &physical,
            &logical,
            package.target()
        )
        .is_err());

        let mut totals = capsule.clone();
        totals.totals.encoded_atoms ^= 1;
        totals.capsule_hash = x64_tail_body_frontier_capsule_hash(&totals)
            .expect("mutated totals must reseal locally");
        assert!(verify_x64_tail_body_frontier_capsule(
            &totals,
            &realization,
            &binding,
            &transition_capsule,
            &templates,
            &physical,
            &logical,
            package.target()
        )
        .is_err());

        let mut code_hash = capsule.clone();
        code_hash.code_hash.0[0] ^= 1;
        code_hash.capsule_hash = x64_tail_body_frontier_capsule_hash(&code_hash)
            .expect("mutated code hash must reseal locally");
        assert!(verify_x64_tail_body_frontier_capsule(
            &code_hash,
            &realization,
            &binding,
            &transition_capsule,
            &templates,
            &physical,
            &logical,
            package.target()
        )
        .is_err());

        let mut provenance = capsule.clone();
        provenance.source_body_frontier_realization_hash.0[0] ^= 1;
        provenance.capsule_hash = x64_tail_body_frontier_capsule_hash(&provenance)
            .expect("mutated provenance must reseal locally");
        assert!(verify_x64_tail_body_frontier_capsule(
            &provenance,
            &realization,
            &binding,
            &transition_capsule,
            &templates,
            &physical,
            &logical,
            package.target()
        )
        .is_err());

        let mut seal = capsule;
        seal.capsule_hash.0[0] ^= 1;
        assert!(verify_x64_tail_body_frontier_capsule(
            &seal,
            &realization,
            &binding,
            &transition_capsule,
            &templates,
            &physical,
            &logical,
            package.target()
        )
        .is_err());
    }
}
