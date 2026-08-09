//! Bounded canonical IPC records for the process-isolated R1-S7b-c harness.
//!
//! The wire format is deliberately independent of Rust layout, enum
//! discriminants, text formatting, serde, and the semantic evidence domains
//! used by R1-S7b-b. A successful child writes exactly one frame and EOF. The
//! parent admits that frame only after its outer seal, nested execution seal,
//! canonical Gate A case binding, and byte-for-byte canonical encoding all
//! verify.

use super::corevm0_gate_a::{
    corevm0_gate_a_case_input_hash, corevm0_gate_a_manifest, CoreVmGateAError,
};
use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_native::{
    verify_x64_native_execution_record, X64NativeCorrespondenceEffect, X64NativeCorrespondenceF64,
    X64NativeCorrespondenceObservation, X64NativeCorrespondenceOutcome, X64NativeEvidenceError,
    X64NativeExecutionRecord, X64NativeLimits, X64NativeMappingState,
    X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS, X64_NATIVE_MAPPING_STATE_EVENTS,
    X64_NATIVE_MAX_EFFECTS_PER_ENGINE, X64_NATIVE_MAX_RECORD_BYTES,
};
use std::fmt;

pub const X64_NATIVE_IPC_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_NATIVE_PROCESS_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_NATIVE_IPC_RECORD_DOMAIN: &[u8] = b"NAUX:x86-64:r1-s7b:ipc:record:v1\0";

const HASH_BYTES: usize = 32;
const VERSION_BYTES: usize = 6;
const FRAME_PREFIX_BYTES: usize =
    X64_NATIVE_IPC_RECORD_DOMAIN.len() + VERSION_BYTES + VERSION_BYTES + HASH_BYTES + 4 + 4;

/// One verified success frame produced by an R1-S7b-c child process.
///
/// Process IDs, addresses, elapsed time, signal numbers, stderr, and timeout
/// telemetry are intentionally absent. The parent may construct this value
/// only by sealing a canonical execution record or decoding a complete
/// canonical frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64NativeIpcRecord {
    pub(super) ipc_schema_version: (u16, u16, u16),
    pub(super) process_policy_version: (u16, u16, u16),
    pub(super) corpus_manifest_hash: SemanticHash,
    pub(super) case_ordinal: u32,
    pub(super) native_execution: X64NativeExecutionRecord,
    pub(super) frame_hash: SemanticHash,
}

impl X64NativeIpcRecord {
    pub fn ipc_schema_version(&self) -> (u16, u16, u16) {
        self.ipc_schema_version
    }

    pub fn process_policy_version(&self) -> (u16, u16, u16) {
        self.process_policy_version
    }

    pub fn corpus_manifest_hash(&self) -> SemanticHash {
        self.corpus_manifest_hash
    }

    pub fn case_ordinal(&self) -> u32 {
        self.case_ordinal
    }

    pub fn native_execution(&self) -> &X64NativeExecutionRecord {
        &self.native_execution
    }

    pub fn frame_hash(&self) -> SemanticHash {
        self.frame_hash
    }
}

#[derive(Debug)]
pub enum X64NativeIpcError {
    CorpusManifest(CoreVmGateAError),
    NativeEvidence(X64NativeEvidenceError),
    RecordByteLimit {
        limit: usize,
        actual: usize,
    },
    InvalidDomain,
    InvalidSchema {
        actual: (u16, u16, u16),
    },
    InvalidProcessPolicy {
        actual: (u16, u16, u16),
    },
    CorpusManifestHashMismatch,
    CaseOrdinalLimit {
        limit: u32,
        actual: u32,
    },
    WrongCaseOrdinal {
        expected: u32,
        actual: u32,
    },
    InputHashMismatch {
        case_ordinal: u32,
    },
    Truncated {
        field: &'static str,
        needed: usize,
        remaining: usize,
    },
    TrailingBytes {
        scope: &'static str,
        actual: usize,
    },
    LengthOverflow {
        field: &'static str,
    },
    InvalidCount {
        field: &'static str,
        expected: u32,
        actual: u32,
    },
    CountLimit {
        field: &'static str,
        limit: u32,
        actual: u32,
    },
    UnknownTag {
        field: &'static str,
        actual: u8,
    },
    NonCanonicalBoolean {
        field: &'static str,
        actual: u8,
    },
    FrameHashMismatch,
    NonCanonicalEncoding,
}

impl fmt::Display for X64NativeIpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CorpusManifest(error) => {
                write!(
                    formatter,
                    "R1-S7b IPC cannot regenerate Gate A corpus: {error}"
                )
            }
            Self::NativeEvidence(error) => {
                write!(
                    formatter,
                    "R1-S7b IPC nested execution record is invalid: {error}"
                )
            }
            Self::RecordByteLimit { limit, actual } => write!(
                formatter,
                "R1-S7b IPC frame uses {actual} bytes; limit is {limit}"
            ),
            Self::InvalidDomain => {
                formatter.write_str("R1-S7b IPC frame has a noncanonical domain")
            }
            Self::InvalidSchema { actual } => {
                write!(formatter, "R1-S7b IPC schema {actual:?} is not canonical")
            }
            Self::InvalidProcessPolicy { actual } => write!(
                formatter,
                "R1-S7b process policy {actual:?} is not canonical"
            ),
            Self::CorpusManifestHashMismatch => {
                formatter.write_str("R1-S7b IPC frame does not bind the canonical Gate A manifest")
            }
            Self::CaseOrdinalLimit { limit, actual } => write!(
                formatter,
                "R1-S7b IPC case ordinal {actual} exceeds fixed corpus limit {limit}"
            ),
            Self::WrongCaseOrdinal { expected, actual } => write!(
                formatter,
                "R1-S7b IPC expected case ordinal {expected}, found {actual}"
            ),
            Self::InputHashMismatch { case_ordinal } => write!(
                formatter,
                "R1-S7b IPC case {case_ordinal} does not bind its canonical Gate A input"
            ),
            Self::Truncated {
                field,
                needed,
                remaining,
            } => write!(
                formatter,
                "R1-S7b IPC {field} needs {needed} bytes; only {remaining} remain"
            ),
            Self::TrailingBytes { scope, actual } => {
                write!(formatter, "R1-S7b IPC {scope} has {actual} trailing bytes")
            }
            Self::LengthOverflow { field } => {
                write!(formatter, "R1-S7b IPC {field} length overflow")
            }
            Self::InvalidCount {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "R1-S7b IPC {field} count is {actual}; canonical count is {expected}"
            ),
            Self::CountLimit {
                field,
                limit,
                actual,
            } => write!(
                formatter,
                "R1-S7b IPC {field} count {actual} exceeds limit {limit}"
            ),
            Self::UnknownTag { field, actual } => {
                write!(formatter, "R1-S7b IPC {field} has unknown tag {actual}")
            }
            Self::NonCanonicalBoolean { field, actual } => write!(
                formatter,
                "R1-S7b IPC {field} Boolean byte {actual} is noncanonical"
            ),
            Self::FrameHashMismatch => {
                formatter.write_str("R1-S7b IPC frame has an invalid outer seal")
            }
            Self::NonCanonicalEncoding => {
                formatter.write_str("R1-S7b IPC frame has a noncanonical byte encoding")
            }
        }
    }
}

impl std::error::Error for X64NativeIpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CorpusManifest(error) => Some(error),
            Self::NativeEvidence(error) => Some(error),
            _ => None,
        }
    }
}

impl From<X64NativeEvidenceError> for X64NativeIpcError {
    fn from(error: X64NativeEvidenceError) -> Self {
        Self::NativeEvidence(error)
    }
}

/// Seal one already verified semantic execution record into the canonical
/// process-success envelope for `case_ordinal`.
pub fn seal_x64_native_ipc_record(
    case_ordinal: u32,
    native_execution: X64NativeExecutionRecord,
) -> Result<X64NativeIpcRecord, X64NativeIpcError> {
    let (corpus_manifest_hash, input_hash) = canonical_case_binding(case_ordinal)?;
    verify_x64_native_execution_record(&native_execution)?;
    if native_execution.input_hash != input_hash {
        return Err(X64NativeIpcError::InputHashMismatch { case_ordinal });
    }

    let mut record = X64NativeIpcRecord {
        ipc_schema_version: X64_NATIVE_IPC_SCHEMA_VERSION,
        process_policy_version: X64_NATIVE_PROCESS_POLICY_VERSION,
        corpus_manifest_hash,
        case_ordinal,
        native_execution,
        frame_hash: SemanticHash::ZERO,
    };
    record.frame_hash = x64_native_ipc_record_hash(&record)?;
    Ok(record)
}

/// Produce one complete canonical success frame, including its outer seal.
pub fn encode_x64_native_ipc_record(
    case_ordinal: u32,
    native_execution: &X64NativeExecutionRecord,
) -> Result<Vec<u8>, X64NativeIpcError> {
    let record = seal_x64_native_ipc_record(case_ordinal, native_execution.clone())?;
    x64_native_ipc_record_bytes(&record)
}

/// Canonical bytes for a previously sealed IPC record.
pub fn x64_native_ipc_record_bytes(
    record: &X64NativeIpcRecord,
) -> Result<Vec<u8>, X64NativeIpcError> {
    verify_x64_native_ipc_record(record, record.case_ordinal)?;
    let mut bytes = encode_frame_without_hash(record)?;
    bytes.extend_from_slice(&record.frame_hash.0);
    enforce_frame_byte_limit(bytes.len())?;
    Ok(bytes)
}

/// Recompute the domain-separated outer seal without trusting `frame_hash`.
pub fn x64_native_ipc_record_hash(
    record: &X64NativeIpcRecord,
) -> Result<SemanticHash, X64NativeIpcError> {
    validate_ipc_record_shape(record, record.case_ordinal)?;
    let bytes = encode_frame_without_hash(record)?;
    enforce_complete_frame_limit(bytes.len())?;
    Ok(SemanticHash(sha256(&bytes)))
}

/// Verify a typed IPC record against the exact parent-selected case.
pub fn verify_x64_native_ipc_record(
    record: &X64NativeIpcRecord,
    expected_case_ordinal: u32,
) -> Result<(), X64NativeIpcError> {
    validate_ipc_record_shape(record, expected_case_ordinal)?;
    let actual = {
        let bytes = encode_frame_without_hash(record)?;
        enforce_complete_frame_limit(bytes.len())?;
        SemanticHash(sha256(&bytes))
    };
    if actual != record.frame_hash {
        return Err(X64NativeIpcError::FrameHashMismatch);
    }
    Ok(())
}

/// Decode exactly one bounded frame and reject truncation, concatenation,
/// alternate encodings, an invalid nested record, or a wrong canonical case.
pub fn decode_x64_native_ipc_record(
    bytes: &[u8],
    expected_case_ordinal: u32,
) -> Result<X64NativeIpcRecord, X64NativeIpcError> {
    enforce_frame_byte_limit(bytes.len())?;

    let mut cursor = Cursor::new(bytes);
    let domain = cursor.take(X64_NATIVE_IPC_RECORD_DOMAIN.len(), "record domain")?;
    if domain != X64_NATIVE_IPC_RECORD_DOMAIN {
        return Err(X64NativeIpcError::InvalidDomain);
    }
    let ipc_schema_version = cursor.version("IPC schema")?;
    let process_policy_version = cursor.version("process policy")?;
    let corpus_manifest_hash = cursor.hash("corpus manifest hash")?;
    let case_ordinal = cursor.u32("case ordinal")?;
    let body_length_u32 = cursor.u32("body length")?;
    let body_length = usize::try_from(body_length_u32)
        .map_err(|_| X64NativeIpcError::LengthOverflow { field: "body" })?;
    let expected_total = cursor
        .position()
        .checked_add(body_length)
        .and_then(|length| length.checked_add(HASH_BYTES))
        .ok_or(X64NativeIpcError::LengthOverflow { field: "frame" })?;
    match expected_total.cmp(&bytes.len()) {
        std::cmp::Ordering::Greater => {
            return Err(X64NativeIpcError::Truncated {
                field: "declared body and frame hash",
                needed: expected_total - cursor.position(),
                remaining: bytes.len() - cursor.position(),
            });
        }
        std::cmp::Ordering::Less => {
            return Err(X64NativeIpcError::TrailingBytes {
                scope: "frame",
                actual: bytes.len() - expected_total,
            });
        }
        std::cmp::Ordering::Equal => {}
    }

    let body = cursor.take(body_length, "record body")?;
    let frame_hash = cursor.hash("frame hash")?;
    cursor.finish("frame")?;

    let frame_hash_start =
        bytes
            .len()
            .checked_sub(HASH_BYTES)
            .ok_or(X64NativeIpcError::LengthOverflow {
                field: "frame hash",
            })?;
    let actual_frame_hash = SemanticHash(sha256(&bytes[..frame_hash_start]));
    if actual_frame_hash != frame_hash {
        return Err(X64NativeIpcError::FrameHashMismatch);
    }
    if body.len() < HASH_BYTES {
        return Err(X64NativeIpcError::Truncated {
            field: "nested execution record hash",
            needed: HASH_BYTES,
            remaining: body.len(),
        });
    }

    let fields_end = body.len() - HASH_BYTES;
    let record_hash = SemanticHash(
        body[fields_end..]
            .try_into()
            .expect("the exact 32-byte suffix was checked"),
    );
    let native_execution = decode_execution_record_fields(&body[..fields_end], record_hash)?;
    let record = X64NativeIpcRecord {
        ipc_schema_version,
        process_policy_version,
        corpus_manifest_hash,
        case_ordinal,
        native_execution,
        frame_hash,
    };
    verify_x64_native_ipc_record(&record, expected_case_ordinal)?;

    let canonical = x64_native_ipc_record_bytes(&record)?;
    if canonical.as_slice() != bytes {
        return Err(X64NativeIpcError::NonCanonicalEncoding);
    }
    Ok(record)
}

fn validate_ipc_record_shape(
    record: &X64NativeIpcRecord,
    expected_case_ordinal: u32,
) -> Result<(), X64NativeIpcError> {
    if record.ipc_schema_version != X64_NATIVE_IPC_SCHEMA_VERSION {
        return Err(X64NativeIpcError::InvalidSchema {
            actual: record.ipc_schema_version,
        });
    }
    if record.process_policy_version != X64_NATIVE_PROCESS_POLICY_VERSION {
        return Err(X64NativeIpcError::InvalidProcessPolicy {
            actual: record.process_policy_version,
        });
    }
    if record.case_ordinal != expected_case_ordinal {
        return Err(X64NativeIpcError::WrongCaseOrdinal {
            expected: expected_case_ordinal,
            actual: record.case_ordinal,
        });
    }

    let (manifest_hash, input_hash) = canonical_case_binding(record.case_ordinal)?;
    if record.corpus_manifest_hash != manifest_hash {
        return Err(X64NativeIpcError::CorpusManifestHashMismatch);
    }
    verify_x64_native_execution_record(&record.native_execution)?;
    if record.native_execution.input_hash != input_hash {
        return Err(X64NativeIpcError::InputHashMismatch {
            case_ordinal: record.case_ordinal,
        });
    }
    Ok(())
}

fn canonical_case_binding(
    case_ordinal: u32,
) -> Result<(SemanticHash, SemanticHash), X64NativeIpcError> {
    if case_ordinal >= X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS {
        return Err(X64NativeIpcError::CaseOrdinalLimit {
            limit: X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS,
            actual: case_ordinal,
        });
    }
    let manifest = corevm0_gate_a_manifest().map_err(X64NativeIpcError::CorpusManifest)?;
    if manifest.total_cases != X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS
        || manifest.cases.len() != X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS as usize
    {
        return Err(X64NativeIpcError::CorpusManifestHashMismatch);
    }
    let case =
        manifest
            .cases
            .get(case_ordinal as usize)
            .ok_or(X64NativeIpcError::CaseOrdinalLimit {
                limit: X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS,
                actual: case_ordinal,
            })?;
    if case.ordinal != case_ordinal {
        return Err(X64NativeIpcError::WrongCaseOrdinal {
            expected: case_ordinal,
            actual: case.ordinal,
        });
    }
    let input_hash =
        corevm0_gate_a_case_input_hash(case).map_err(X64NativeIpcError::CorpusManifest)?;
    if input_hash != case.input_hash {
        return Err(X64NativeIpcError::InputHashMismatch { case_ordinal });
    }
    Ok((manifest.manifest_hash, input_hash))
}

fn encode_frame_without_hash(record: &X64NativeIpcRecord) -> Result<Vec<u8>, X64NativeIpcError> {
    let mut body = Vec::with_capacity(512);
    encode_execution_record_fields(&mut body, &record.native_execution)?;
    body.extend_from_slice(&record.native_execution.record_hash.0);
    let body_length = u32::try_from(body.len()).map_err(|_| X64NativeIpcError::LengthOverflow {
        field: "record body",
    })?;

    let capacity = FRAME_PREFIX_BYTES
        .checked_add(body.len())
        .ok_or(X64NativeIpcError::LengthOverflow { field: "frame" })?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(X64_NATIVE_IPC_RECORD_DOMAIN);
    put_version(&mut bytes, record.ipc_schema_version);
    put_version(&mut bytes, record.process_policy_version);
    bytes.extend_from_slice(&record.corpus_manifest_hash.0);
    put_u32(&mut bytes, record.case_ordinal);
    put_u32(&mut bytes, body_length);
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

fn encode_execution_record_fields(
    bytes: &mut Vec<u8>,
    record: &X64NativeExecutionRecord,
) -> Result<(), X64NativeIpcError> {
    put_version(bytes, record.evidence_schema_version);
    put_version(bytes, record.runner_schema_version);
    put_version(bytes, record.runner_policy_version);
    put_version(bytes, record.syscall_policy_version);
    put_version(bytes, record.entry_policy_version);
    encode_limits(bytes, record.limits);
    bytes.extend_from_slice(&record.target_artifact_hash.0);
    bytes.extend_from_slice(&record.target_plan_hash.0);
    bytes.extend_from_slice(&record.target_code_hash.0);
    bytes.extend_from_slice(&record.source_machine_ir_hash.0);
    put_u32(bytes, record.entry_offset);
    bytes.extend_from_slice(&record.canonical_abi_hash.0);
    bytes.extend_from_slice(&record.input_hash.0);
    bytes.extend_from_slice(&record.copied_rw_code_hash.0);
    bytes.extend_from_slice(&record.readback_rx_code_hash.0);
    bytes.push(record.input_lanes);
    put_u32(bytes, X64_NATIVE_MAPPING_STATE_EVENTS);
    for state in record.mapping_trace {
        bytes.push(mapping_state_tag(state));
    }
    put_u32(bytes, record.mxcsr_before);
    put_u32(bytes, record.mxcsr_after);
    encode_observation(bytes, &record.native)?;
    bytes.push(u8::from(record.fallback));
    Ok(())
}

fn decode_execution_record_fields(
    bytes: &[u8],
    record_hash: SemanticHash,
) -> Result<X64NativeExecutionRecord, X64NativeIpcError> {
    let mut cursor = Cursor::new(bytes);
    let evidence_schema_version = cursor.version("evidence schema")?;
    let runner_schema_version = cursor.version("runner schema")?;
    let runner_policy_version = cursor.version("runner policy")?;
    let syscall_policy_version = cursor.version("syscall policy")?;
    let entry_policy_version = cursor.version("entry policy")?;
    let limits = decode_limits(&mut cursor)?;
    let target_artifact_hash = cursor.hash("target artifact hash")?;
    let target_plan_hash = cursor.hash("target plan hash")?;
    let target_code_hash = cursor.hash("target code hash")?;
    let source_machine_ir_hash = cursor.hash("source Machine IR hash")?;
    let entry_offset = cursor.u32("entry offset")?;
    let canonical_abi_hash = cursor.hash("canonical ABI hash")?;
    let input_hash = cursor.hash("input hash")?;
    let copied_rw_code_hash = cursor.hash("copied RW code hash")?;
    let readback_rx_code_hash = cursor.hash("read-back RX code hash")?;
    let input_lanes = cursor.u8("input lane count")?;

    let mapping_count = cursor.u32("mapping-state count")?;
    if mapping_count != X64_NATIVE_MAPPING_STATE_EVENTS {
        return Err(X64NativeIpcError::InvalidCount {
            field: "mapping-state",
            expected: X64_NATIVE_MAPPING_STATE_EVENTS,
            actual: mapping_count,
        });
    }
    let mut mapping_trace = [X64NativeMappingState::Unmapped; 4];
    for state in &mut mapping_trace {
        *state = decode_mapping_state(cursor.u8("mapping-state tag")?)?;
    }

    let mxcsr_before = cursor.u32("MXCSR before")?;
    let mxcsr_after = cursor.u32("MXCSR after")?;
    let native = decode_observation(&mut cursor)?;
    let fallback_byte = cursor.u8("fallback")?;
    let fallback = decode_bool("fallback", fallback_byte)?;
    cursor.finish("execution record fields")?;

    Ok(X64NativeExecutionRecord {
        evidence_schema_version,
        runner_schema_version,
        runner_policy_version,
        syscall_policy_version,
        entry_policy_version,
        limits,
        target_artifact_hash,
        target_plan_hash,
        target_code_hash,
        source_machine_ir_hash,
        entry_offset,
        canonical_abi_hash,
        input_hash,
        copied_rw_code_hash,
        readback_rx_code_hash,
        input_lanes,
        mapping_trace,
        mxcsr_before,
        mxcsr_after,
        native,
        fallback,
        record_hash,
    })
}

fn encode_limits(bytes: &mut Vec<u8>, limits: X64NativeLimits) {
    put_u32(bytes, limits.code_mappings_per_invocation);
    put_u64(bytes, limits.max_mapping_bytes);
    put_u32(bytes, limits.max_entry_lanes);
    put_u32(bytes, limits.max_borrowed_f64_arrays);
    put_u32(bytes, limits.output_words);
    put_u32(bytes, limits.mapping_state_events);
    put_u32(bytes, limits.max_effects_per_engine);
    put_u32(bytes, limits.max_correspondence_records);
    put_u32(bytes, limits.fixed_lighthouse_records);
    put_u32(bytes, limits.max_record_bytes);
    put_u32(bytes, limits.max_diagnostics);
}

fn decode_limits(cursor: &mut Cursor<'_>) -> Result<X64NativeLimits, X64NativeIpcError> {
    Ok(X64NativeLimits {
        code_mappings_per_invocation: cursor.u32("code-mapping limit")?,
        max_mapping_bytes: cursor.u64("mapping-byte limit")?,
        max_entry_lanes: cursor.u32("entry-lane limit")?,
        max_borrowed_f64_arrays: cursor.u32("borrowed-array limit")?,
        output_words: cursor.u32("output-word limit")?,
        mapping_state_events: cursor.u32("mapping-state-event limit")?,
        max_effects_per_engine: cursor.u32("effect limit")?,
        max_correspondence_records: cursor.u32("correspondence-record limit")?,
        fixed_lighthouse_records: cursor.u32("fixed-corpus limit")?,
        max_record_bytes: cursor.u32("record-byte limit")?,
        max_diagnostics: cursor.u32("diagnostic limit")?,
    })
}

fn encode_observation(
    bytes: &mut Vec<u8>,
    observation: &X64NativeCorrespondenceObservation,
) -> Result<(), X64NativeIpcError> {
    match observation.outcome {
        X64NativeCorrespondenceOutcome::ReturnF64(X64NativeCorrespondenceF64::ExactBits(bits)) => {
            bytes.push(0);
            put_u64(bytes, bits);
        }
        X64NativeCorrespondenceOutcome::ReturnF64(X64NativeCorrespondenceF64::CanonicalNaN) => {
            bytes.push(1)
        }
        X64NativeCorrespondenceOutcome::Bounds => bytes.push(2),
    }
    let effect_count = u32::try_from(observation.effect_trace.len()).map_err(|_| {
        X64NativeIpcError::LengthOverflow {
            field: "effect trace",
        }
    })?;
    put_u32(bytes, effect_count);
    for effect in &observation.effect_trace {
        bytes.push(match effect {
            X64NativeCorrespondenceEffect::Bounds => 0,
        });
    }
    Ok(())
}

fn decode_observation(
    cursor: &mut Cursor<'_>,
) -> Result<X64NativeCorrespondenceObservation, X64NativeIpcError> {
    let outcome = match cursor.u8("outcome tag")? {
        0 => X64NativeCorrespondenceOutcome::ReturnF64(X64NativeCorrespondenceF64::ExactBits(
            cursor.u64("F64 result bits")?,
        )),
        1 => X64NativeCorrespondenceOutcome::ReturnF64(X64NativeCorrespondenceF64::CanonicalNaN),
        2 => X64NativeCorrespondenceOutcome::Bounds,
        actual => {
            return Err(X64NativeIpcError::UnknownTag {
                field: "outcome",
                actual,
            });
        }
    };
    let effect_count = cursor.u32("effect count")?;
    if effect_count > X64_NATIVE_MAX_EFFECTS_PER_ENGINE {
        return Err(X64NativeIpcError::CountLimit {
            field: "effect",
            limit: X64_NATIVE_MAX_EFFECTS_PER_ENGINE,
            actual: effect_count,
        });
    }
    let mut effect_trace = Vec::with_capacity(effect_count as usize);
    for _ in 0..effect_count {
        effect_trace.push(match cursor.u8("effect tag")? {
            0 => X64NativeCorrespondenceEffect::Bounds,
            actual => {
                return Err(X64NativeIpcError::UnknownTag {
                    field: "effect",
                    actual,
                });
            }
        });
    }
    Ok(X64NativeCorrespondenceObservation {
        outcome,
        effect_trace,
    })
}

fn mapping_state_tag(state: X64NativeMappingState) -> u8 {
    match state {
        X64NativeMappingState::Unmapped => 0,
        X64NativeMappingState::ReadWrite => 1,
        X64NativeMappingState::ReadExecute => 2,
    }
}

fn decode_mapping_state(tag: u8) -> Result<X64NativeMappingState, X64NativeIpcError> {
    match tag {
        0 => Ok(X64NativeMappingState::Unmapped),
        1 => Ok(X64NativeMappingState::ReadWrite),
        2 => Ok(X64NativeMappingState::ReadExecute),
        actual => Err(X64NativeIpcError::UnknownTag {
            field: "mapping state",
            actual,
        }),
    }
}

fn decode_bool(field: &'static str, byte: u8) -> Result<bool, X64NativeIpcError> {
    match byte {
        0 => Ok(false),
        1 => Ok(true),
        actual => Err(X64NativeIpcError::NonCanonicalBoolean { field, actual }),
    }
}

fn enforce_complete_frame_limit(prefix_length: usize) -> Result<(), X64NativeIpcError> {
    let complete = prefix_length
        .checked_add(HASH_BYTES)
        .ok_or(X64NativeIpcError::LengthOverflow { field: "frame" })?;
    enforce_frame_byte_limit(complete)
}

fn enforce_frame_byte_limit(length: usize) -> Result<(), X64NativeIpcError> {
    let limit = X64_NATIVE_MAX_RECORD_BYTES as usize;
    if length > limit {
        return Err(X64NativeIpcError::RecordByteLimit {
            limit,
            actual: length,
        });
    }
    Ok(())
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    put_u16(bytes, version.0);
    put_u16(bytes, version.1);
    put_u16(bytes, version.2);
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

struct Cursor<'bytes> {
    bytes: &'bytes [u8],
    position: usize,
}

impl<'bytes> Cursor<'bytes> {
    fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn take(
        &mut self,
        length: usize,
        field: &'static str,
    ) -> Result<&'bytes [u8], X64NativeIpcError> {
        let remaining = self.bytes.len().saturating_sub(self.position);
        if length > remaining {
            return Err(X64NativeIpcError::Truncated {
                field,
                needed: length,
                remaining,
            });
        }
        let end = self
            .position
            .checked_add(length)
            .ok_or(X64NativeIpcError::LengthOverflow { field })?;
        let result = &self.bytes[self.position..end];
        self.position = end;
        Ok(result)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, X64NativeIpcError> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, X64NativeIpcError> {
        let bytes: [u8; 2] = self
            .take(2, field)?
            .try_into()
            .expect("the exact two-byte slice was checked");
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, X64NativeIpcError> {
        let bytes: [u8; 4] = self
            .take(4, field)?
            .try_into()
            .expect("the exact four-byte slice was checked");
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, X64NativeIpcError> {
        let bytes: [u8; 8] = self
            .take(8, field)?
            .try_into()
            .expect("the exact eight-byte slice was checked");
        Ok(u64::from_be_bytes(bytes))
    }

    fn version(&mut self, field: &'static str) -> Result<(u16, u16, u16), X64NativeIpcError> {
        Ok((self.u16(field)?, self.u16(field)?, self.u16(field)?))
    }

    fn hash(&mut self, field: &'static str) -> Result<SemanticHash, X64NativeIpcError> {
        let bytes: [u8; HASH_BYTES] = self
            .take(HASH_BYTES, field)?
            .try_into()
            .expect("the exact hash-width slice was checked");
        Ok(SemanticHash(bytes))
    }

    fn finish(self, scope: &'static str) -> Result<(), X64NativeIpcError> {
        if self.position != self.bytes.len() {
            return Err(X64NativeIpcError::TrailingBytes {
                scope,
                actual: self.bytes.len() - self.position,
            });
        }
        Ok(())
    }
}
