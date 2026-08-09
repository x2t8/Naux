//! Canonical bounded ADR-0069 IPC for one complete ADR-0068 observation.
//!
//! The decoder treats every child byte as hostile. It owns its cursor, tags,
//! lengths and frame digest; no encoder receipt or historical IPC grammar is
//! consulted.

use super::corevm0_gate_a::{
    CoreVmGateAEffect, CoreVmGateAF64, CoreVmGateAOutcome, CoreVmGateAWorkload,
};
use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_enveloped_correspondence::{
    X64TailEnvelopedCorrespondenceEvidence, X64TailEnvelopedCorrespondenceRecord,
    X64_TAIL_ENVELOPED_CORRESPONDENCE_CASES,
    X64_TAIL_ENVELOPED_CORRESPONDENCE_MAX_EFFECTS_PER_RECORD,
    X64_TAIL_ENVELOPED_CORRESPONDENCE_MAX_RECORDS,
};
use super::x64_tail_enveloped_native::X64TailEnvelopedNativeMappingState;
use std::fmt;

pub const X64_TAIL_ENVELOPED_IPC_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_ENVELOPED_IPC_MAX_FRAME_BYTES: u32 = 32 * 1024;

const MAGIC: &[u8; 8] = b"NAUXP069";
const FRAME_DOMAIN: &[u8] = b"NAUX:x86-64:tail-enveloped-process-frame:v1\0";
const FRAME_LENGTH_OFFSET: usize = 8 + 6 + 6 + 6;
const FRAME_HASH_BYTES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailEnvelopedIpcError {
    FrameLimit { limit: u32, actual: u64 },
    Truncated { field: &'static str },
    TrailingBytes { actual: u64 },
    InvalidMagic,
    InvalidSchema,
    DeclaredLength { declared: u32, actual: u32 },
    FrameHashMismatch,
    InvalidTag { field: &'static str, tag: u8 },
    InvalidCount { field: &'static str, actual: u32 },
    NonCanonicalF64,
    ArithmeticOverflow,
}

impl fmt::Display for X64TailEnvelopedIpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameLimit { limit, actual } => {
                write!(
                    formatter,
                    "ADR-0069 IPC frame has {actual} bytes; limit is {limit}"
                )
            }
            Self::Truncated { field } => write!(formatter, "ADR-0069 IPC is truncated at {field}"),
            Self::TrailingBytes { actual } => {
                write!(formatter, "ADR-0069 IPC has {actual} trailing bytes")
            }
            Self::InvalidMagic => formatter.write_str("ADR-0069 IPC magic mismatch"),
            Self::InvalidSchema => formatter.write_str("ADR-0069 IPC schema mismatch"),
            Self::DeclaredLength { declared, actual } => write!(
                formatter,
                "ADR-0069 IPC declares {declared} bytes but contains {actual}"
            ),
            Self::FrameHashMismatch => formatter.write_str("ADR-0069 IPC frame hash mismatch"),
            Self::InvalidTag { field, tag } => {
                write!(formatter, "ADR-0069 IPC {field} tag {tag} is invalid")
            }
            Self::InvalidCount { field, actual } => {
                write!(formatter, "ADR-0069 IPC {field} count {actual} is invalid")
            }
            Self::NonCanonicalF64 => {
                formatter.write_str("ADR-0069 IPC encodes NaN as exact F64 bits")
            }
            Self::ArithmeticOverflow => formatter.write_str("ADR-0069 IPC arithmetic overflow"),
        }
    }
}

impl std::error::Error for X64TailEnvelopedIpcError {}

/// Encode one exact fixed-corpus observation. The child owns this operation;
/// parent admission always starts from the independent decoder below.
pub fn encode_x64_tail_enveloped_ipc(
    evidence: &X64TailEnvelopedCorrespondenceEvidence,
) -> Result<Vec<u8>, X64TailEnvelopedIpcError> {
    if evidence.records.len() != X64_TAIL_ENVELOPED_CORRESPONDENCE_CASES as usize
        || evidence.records.len() > X64_TAIL_ENVELOPED_CORRESPONDENCE_MAX_RECORDS as usize
    {
        return Err(X64TailEnvelopedIpcError::InvalidCount {
            field: "record",
            actual: usize_to_u32(evidence.records.len())?,
        });
    }

    let mut bytes = Vec::with_capacity(16 * 1024);
    bytes.extend_from_slice(MAGIC);
    put_version(&mut bytes, X64_TAIL_ENVELOPED_IPC_SCHEMA_VERSION);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_u32(&mut bytes, 0);
    for hash in [
        evidence.corpus_manifest_hash,
        evidence.branch_target_semantic_hash,
        evidence.branch_image_hash,
        evidence.branch_code_hash,
        evidence.bounds_target_semantic_hash,
        evidence.bounds_image_hash,
        evidence.bounds_code_hash,
        evidence.results_hash,
        evidence.evidence_hash,
    ] {
        put_hash(&mut bytes, hash);
    }
    put_u32(&mut bytes, usize_to_u32(evidence.records.len())?);
    for record in &evidence.records {
        encode_record(&mut bytes, record)?;
    }

    let total_length = bytes
        .len()
        .checked_add(FRAME_HASH_BYTES)
        .ok_or(X64TailEnvelopedIpcError::ArithmeticOverflow)?;
    let total_length = usize_to_u32(total_length)?;
    if total_length > X64_TAIL_ENVELOPED_IPC_MAX_FRAME_BYTES {
        return Err(X64TailEnvelopedIpcError::FrameLimit {
            limit: X64_TAIL_ENVELOPED_IPC_MAX_FRAME_BYTES,
            actual: u64::from(total_length),
        });
    }
    bytes[FRAME_LENGTH_OFFSET..FRAME_LENGTH_OFFSET + 4]
        .copy_from_slice(&total_length.to_le_bytes());
    let frame_hash = frame_hash(&bytes);
    put_hash(&mut bytes, frame_hash);
    Ok(bytes)
}

/// Decode one exact frame without consulting the encoder's structure or any
/// historical IPC representation.
pub fn decode_x64_tail_enveloped_ipc(
    frame: &[u8],
) -> Result<X64TailEnvelopedCorrespondenceEvidence, X64TailEnvelopedIpcError> {
    if frame.len() > X64_TAIL_ENVELOPED_IPC_MAX_FRAME_BYTES as usize {
        return Err(X64TailEnvelopedIpcError::FrameLimit {
            limit: X64_TAIL_ENVELOPED_IPC_MAX_FRAME_BYTES,
            actual: usize_to_u64(frame.len())?,
        });
    }
    if frame.len() < FRAME_LENGTH_OFFSET + 4 + FRAME_HASH_BYTES {
        return Err(X64TailEnvelopedIpcError::Truncated { field: "header" });
    }
    let payload_length = frame
        .len()
        .checked_sub(FRAME_HASH_BYTES)
        .ok_or(X64TailEnvelopedIpcError::ArithmeticOverflow)?;
    let (payload, declared_hash_bytes) = frame.split_at(payload_length);
    let declared_hash = SemanticHash(declared_hash_bytes.try_into().map_err(|_| {
        X64TailEnvelopedIpcError::Truncated {
            field: "frame hash",
        }
    })?);
    if frame_hash(payload) != declared_hash {
        return Err(X64TailEnvelopedIpcError::FrameHashMismatch);
    }

    let mut reader = Reader::new(payload);
    if reader.array::<8>("magic")? != *MAGIC {
        return Err(X64TailEnvelopedIpcError::InvalidMagic);
    }
    if reader.version("IPC schema")? != X64_TAIL_ENVELOPED_IPC_SCHEMA_VERSION {
        return Err(X64TailEnvelopedIpcError::InvalidSchema);
    }
    let schema_version = reader.version("correspondence schema")?;
    let policy_version = reader.version("correspondence policy")?;
    let declared_length = reader.u32("frame length")?;
    let actual_length = usize_to_u32(frame.len())?;
    if declared_length != actual_length {
        return Err(X64TailEnvelopedIpcError::DeclaredLength {
            declared: declared_length,
            actual: actual_length,
        });
    }
    let corpus_manifest_hash = reader.hash("corpus manifest hash")?;
    let branch_target_semantic_hash = reader.hash("branch target hash")?;
    let branch_image_hash = reader.hash("branch image hash")?;
    let branch_code_hash = reader.hash("branch code hash")?;
    let bounds_target_semantic_hash = reader.hash("Bounds target hash")?;
    let bounds_image_hash = reader.hash("Bounds image hash")?;
    let bounds_code_hash = reader.hash("Bounds code hash")?;
    let results_hash = reader.hash("results hash")?;
    let evidence_hash = reader.hash("evidence hash")?;
    let record_count = reader.u32("record count")?;
    if record_count != X64_TAIL_ENVELOPED_CORRESPONDENCE_CASES
        || record_count > X64_TAIL_ENVELOPED_CORRESPONDENCE_MAX_RECORDS
    {
        return Err(X64TailEnvelopedIpcError::InvalidCount {
            field: "record",
            actual: record_count,
        });
    }
    let mut records = Vec::with_capacity(record_count as usize);
    for _ in 0..record_count {
        records.push(decode_record(&mut reader)?);
    }
    if reader.remaining() != 0 {
        return Err(X64TailEnvelopedIpcError::TrailingBytes {
            actual: usize_to_u64(reader.remaining())?,
        });
    }

    Ok(X64TailEnvelopedCorrespondenceEvidence {
        schema_version,
        policy_version,
        corpus_manifest_hash,
        branch_target_semantic_hash,
        branch_image_hash,
        branch_code_hash,
        bounds_target_semantic_hash,
        bounds_image_hash,
        bounds_code_hash,
        records,
        results_hash,
        evidence_hash,
    })
}

pub fn x64_tail_enveloped_ipc_frame_hash(
    frame: &[u8],
) -> Result<SemanticHash, X64TailEnvelopedIpcError> {
    if frame.len() > X64_TAIL_ENVELOPED_IPC_MAX_FRAME_BYTES as usize {
        return Err(X64TailEnvelopedIpcError::FrameLimit {
            limit: X64_TAIL_ENVELOPED_IPC_MAX_FRAME_BYTES,
            actual: usize_to_u64(frame.len())?,
        });
    }
    Ok(SemanticHash(sha256(frame)))
}

fn encode_record(
    bytes: &mut Vec<u8>,
    record: &X64TailEnvelopedCorrespondenceRecord,
) -> Result<(), X64TailEnvelopedIpcError> {
    put_u32(bytes, record.case_ordinal);
    bytes.push(workload_tag(record.workload));
    for hash in [
        record.input_hash,
        record.target_semantic_hash,
        record.target_plan_hash,
        record.image_hash,
        record.code_hash,
    ] {
        put_hash(bytes, hash);
    }
    put_u32(bytes, record.entry_point);
    bytes.push(record.input_lanes);
    put_hash(bytes, record.copied_rw_code_hash);
    put_hash(bytes, record.readback_rx_code_hash);
    for state in record.mapping_trace {
        bytes.push(mapping_tag(state));
    }
    put_u32(bytes, record.mxcsr_before);
    put_u32(bytes, record.mxcsr_after);
    encode_outcome(bytes, record.outcome);
    if record.effect_trace.len() > X64_TAIL_ENVELOPED_CORRESPONDENCE_MAX_EFFECTS_PER_RECORD as usize
    {
        return Err(X64TailEnvelopedIpcError::InvalidCount {
            field: "effect",
            actual: usize_to_u32(record.effect_trace.len())?,
        });
    }
    put_u32(bytes, usize_to_u32(record.effect_trace.len())?);
    for effect in &record.effect_trace {
        bytes.push(effect_tag(*effect));
    }
    bytes.push(u8::from(record.teardown));
    bytes.push(u8::from(record.fallback));
    put_hash(bytes, record.record_hash);
    Ok(())
}

fn decode_record(
    reader: &mut Reader<'_>,
) -> Result<X64TailEnvelopedCorrespondenceRecord, X64TailEnvelopedIpcError> {
    let case_ordinal = reader.u32("case ordinal")?;
    let workload = match reader.u8("workload")? {
        0 => CoreVmGateAWorkload::BranchMix,
        1 => CoreVmGateAWorkload::BoundsOrderedArrayGet,
        tag => {
            return Err(X64TailEnvelopedIpcError::InvalidTag {
                field: "workload",
                tag,
            })
        }
    };
    let input_hash = reader.hash("input hash")?;
    let target_semantic_hash = reader.hash("target hash")?;
    let target_plan_hash = reader.hash("target plan hash")?;
    let image_hash = reader.hash("image hash")?;
    let code_hash = reader.hash("code hash")?;
    let entry_point = reader.u32("entry point")?;
    let input_lanes = reader.u8("input lanes")?;
    let copied_rw_code_hash = reader.hash("RW code hash")?;
    let readback_rx_code_hash = reader.hash("RX code hash")?;
    let mut mapping_trace = [X64TailEnvelopedNativeMappingState::Unmapped; 4];
    for state in &mut mapping_trace {
        *state = match reader.u8("mapping state")? {
            0 => X64TailEnvelopedNativeMappingState::Unmapped,
            1 => X64TailEnvelopedNativeMappingState::ReadWrite,
            2 => X64TailEnvelopedNativeMappingState::ReadExecute,
            tag => {
                return Err(X64TailEnvelopedIpcError::InvalidTag {
                    field: "mapping state",
                    tag,
                });
            }
        };
    }
    let mxcsr_before = reader.u32("MXCSR before")?;
    let mxcsr_after = reader.u32("MXCSR after")?;
    let outcome = decode_outcome(reader)?;
    let effect_count = reader.u32("effect count")?;
    if effect_count > X64_TAIL_ENVELOPED_CORRESPONDENCE_MAX_EFFECTS_PER_RECORD {
        return Err(X64TailEnvelopedIpcError::InvalidCount {
            field: "effect",
            actual: effect_count,
        });
    }
    let mut effect_trace = Vec::with_capacity(effect_count as usize);
    for _ in 0..effect_count {
        let tag = reader.u8("effect")?;
        match tag {
            0 => effect_trace.push(CoreVmGateAEffect::Bounds),
            tag => {
                return Err(X64TailEnvelopedIpcError::InvalidTag {
                    field: "effect",
                    tag,
                })
            }
        }
    }
    let teardown = decode_bool(reader.u8("teardown")?, "teardown")?;
    let fallback = decode_bool(reader.u8("fallback")?, "fallback")?;
    let record_hash = reader.hash("record hash")?;
    Ok(X64TailEnvelopedCorrespondenceRecord {
        case_ordinal,
        workload,
        input_hash,
        target_semantic_hash,
        target_plan_hash,
        image_hash,
        code_hash,
        entry_point,
        input_lanes,
        copied_rw_code_hash,
        readback_rx_code_hash,
        mapping_trace,
        mxcsr_before,
        mxcsr_after,
        outcome,
        effect_trace,
        teardown,
        fallback,
        record_hash,
    })
}

fn encode_outcome(bytes: &mut Vec<u8>, outcome: CoreVmGateAOutcome) {
    match outcome {
        CoreVmGateAOutcome::ReturnF64(CoreVmGateAF64::ExactBits(bits)) => {
            bytes.push(0);
            put_u64(bytes, bits);
        }
        CoreVmGateAOutcome::ReturnF64(CoreVmGateAF64::CanonicalNaN) => bytes.push(1),
        CoreVmGateAOutcome::Bounds => bytes.push(2),
    }
}

fn decode_outcome(reader: &mut Reader<'_>) -> Result<CoreVmGateAOutcome, X64TailEnvelopedIpcError> {
    match reader.u8("outcome")? {
        0 => {
            let bits = reader.u64("F64 outcome")?;
            if f64::from_bits(bits).is_nan() {
                return Err(X64TailEnvelopedIpcError::NonCanonicalF64);
            }
            Ok(CoreVmGateAOutcome::ReturnF64(CoreVmGateAF64::ExactBits(
                bits,
            )))
        }
        1 => Ok(CoreVmGateAOutcome::ReturnF64(CoreVmGateAF64::CanonicalNaN)),
        2 => Ok(CoreVmGateAOutcome::Bounds),
        tag => Err(X64TailEnvelopedIpcError::InvalidTag {
            field: "outcome",
            tag,
        }),
    }
}

fn workload_tag(workload: CoreVmGateAWorkload) -> u8 {
    match workload {
        CoreVmGateAWorkload::BranchMix => 0,
        CoreVmGateAWorkload::BoundsOrderedArrayGet => 1,
    }
}

fn mapping_tag(state: X64TailEnvelopedNativeMappingState) -> u8 {
    match state {
        X64TailEnvelopedNativeMappingState::Unmapped => 0,
        X64TailEnvelopedNativeMappingState::ReadWrite => 1,
        X64TailEnvelopedNativeMappingState::ReadExecute => 2,
    }
}

fn effect_tag(effect: CoreVmGateAEffect) -> u8 {
    match effect {
        CoreVmGateAEffect::Bounds => 0,
    }
}

fn decode_bool(value: u8, field: &'static str) -> Result<bool, X64TailEnvelopedIpcError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        tag => Err(X64TailEnvelopedIpcError::InvalidTag { field, tag }),
    }
}

fn frame_hash(bytes: &[u8]) -> SemanticHash {
    let mut preimage = Vec::with_capacity(FRAME_DOMAIN.len() + bytes.len());
    preimage.extend_from_slice(FRAME_DOMAIN);
    preimage.extend_from_slice(bytes);
    SemanticHash(sha256(&preimage))
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    put_u16(bytes, version.0);
    put_u16(bytes, version.1);
    put_u16(bytes, version.2);
}

fn put_hash(bytes: &mut Vec<u8>, hash: SemanticHash) {
    bytes.extend_from_slice(&hash.0);
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn usize_to_u32(value: usize) -> Result<u32, X64TailEnvelopedIpcError> {
    u32::try_from(value).map_err(|_| X64TailEnvelopedIpcError::ArithmeticOverflow)
}

fn usize_to_u64(value: usize) -> Result<u64, X64TailEnvelopedIpcError> {
    u64::try_from(value).map_err(|_| X64TailEnvelopedIpcError::ArithmeticOverflow)
}

struct Reader<'bytes> {
    bytes: &'bytes [u8],
    cursor: usize,
}

impl<'bytes> Reader<'bytes> {
    const fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.cursor)
    }

    fn take(
        &mut self,
        count: usize,
        field: &'static str,
    ) -> Result<&'bytes [u8], X64TailEnvelopedIpcError> {
        let end = self
            .cursor
            .checked_add(count)
            .ok_or(X64TailEnvelopedIpcError::ArithmeticOverflow)?;
        let slice = self
            .bytes
            .get(self.cursor..end)
            .ok_or(X64TailEnvelopedIpcError::Truncated { field })?;
        self.cursor = end;
        Ok(slice)
    }

    fn array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], X64TailEnvelopedIpcError> {
        self.take(N, field)?
            .try_into()
            .map_err(|_| X64TailEnvelopedIpcError::Truncated { field })
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, X64TailEnvelopedIpcError> {
        Ok(self.array::<1>(field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, X64TailEnvelopedIpcError> {
        Ok(u16::from_le_bytes(self.array(field)?))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, X64TailEnvelopedIpcError> {
        Ok(u32::from_le_bytes(self.array(field)?))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, X64TailEnvelopedIpcError> {
        Ok(u64::from_le_bytes(self.array(field)?))
    }

    fn version(
        &mut self,
        field: &'static str,
    ) -> Result<(u16, u16, u16), X64TailEnvelopedIpcError> {
        Ok((self.u16(field)?, self.u16(field)?, self.u16(field)?))
    }

    fn hash(&mut self, field: &'static str) -> Result<SemanticHash, X64TailEnvelopedIpcError> {
        Ok(SemanticHash(self.array(field)?))
    }
}
