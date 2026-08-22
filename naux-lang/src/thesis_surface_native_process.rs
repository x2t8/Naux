//! Fresh-process evidence for the exact Scope-3 Surface-native T1 carrier.
//!
//! The parent never executes T1 native bytes. It reconstructs the accepted
//! Surface-to-target chain, launches one fresh child per canonical ordinal,
//! treats each fixed frame as hostile input, and binds the admitted child
//! observation to its own reconstruction.

use crate::core::encoding::sha256;
use crate::core::{
    run_x64_worker_frame_bounded, SemanticHash, X64NativeMappingState, X64NativeProcessError,
    X64TargetAbi,
};
use crate::elaboration::NormalizedScalar;
#[cfg(debug_assertions)]
use crate::thesis_surface_native::probe_surface_native_t1_resealed_observation_mutation;
use crate::thesis_surface_native::{
    execute_prepared_surface_native_t1_case, expected_surface_native_t1_evidence,
    observe_prepared_surface_native_t1_case, prepare_surface_native_t1, PreparedSurfaceNativeT1,
    SurfaceNativeT1Error, SurfaceNativeT1Evidence, SurfaceNativeT1ExecutedCase,
    SurfaceNativeT1ExpectedCase, SurfaceNativeT1Record, SURFACE_NATIVE_T1_CASES,
};
use std::fmt;
use std::path::Path;
use std::time::Duration;

pub const SURFACE_NATIVE_T1_PROCESS_SCHEMA_VERSION: (u16, u16, u16) = (0, 1, 0);
pub const SURFACE_NATIVE_T1_PROCESS_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const SURFACE_NATIVE_T1_IPC_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const SURFACE_NATIVE_T1_PROCESS_TIMEOUT_MILLIS: u64 = 30_000;
pub const SURFACE_NATIVE_T1_PROCESS_MAX_RECORD_BYTES: u64 = 2_048;
pub const SURFACE_NATIVE_T1_PROCESS_DEBUG_ENV: &str = "NAUX_SURFACE_T1_WORKER_DEBUG_PROBE";

const IPC_DOMAIN: &[u8] = b"NAUX:thesis:surface-native-t1:process:ipc:v1\0";
const RECEIPT_DOMAIN: &[u8] = b"NAUX:thesis:surface-native-t1:process:receipt:v1\0";
const RESULTS_DOMAIN: &[u8] = b"NAUX:thesis:surface-native-t1:process:results:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:thesis:surface-native-t1:process:evidence:v1\0";
const REPORT_DOMAIN: &[u8] = b"NAUX:thesis:surface-native-t1:process:report:v1\0";
const HASH_BYTES: usize = 32;
const VERSION_BYTES: usize = 6;
const NORMALIZED_SCALAR_BYTES: usize = 9;
const GLOBAL_HASHES: usize = 9;
const NATIVE_HASHES: usize = 6;
pub const SURFACE_NATIVE_T1_PROCESS_FRAME_BYTES: usize = IPC_DOMAIN.len()
    + VERSION_BYTES * 3
    + 4
    + HASH_BYTES * GLOBAL_HASHES
    + HASH_BYTES
    + NORMALIZED_SCALAR_BYTES * 6
    + HASH_BYTES
    + HASH_BYTES * NATIVE_HASHES
    + 4
    + 1
    + 4
    + 4
    + 1
    + 4
    + HASH_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurfaceNativeT1ProcessReceipt {
    schema_version: (u16, u16, u16),
    process_policy_version: (u16, u16, u16),
    ipc_schema_version: (u16, u16, u16),
    case_ordinal: u32,
    input_hash: SemanticHash,
    carrier_record_hash: SemanticHash,
    ipc_frame_hash: SemanticHash,
    receipt_hash: SemanticHash,
}

impl SurfaceNativeT1ProcessReceipt {
    pub fn case_ordinal(&self) -> u32 {
        self.case_ordinal
    }

    pub fn input_hash(&self) -> SemanticHash {
        self.input_hash
    }

    pub fn carrier_record_hash(&self) -> SemanticHash {
        self.carrier_record_hash
    }

    pub fn ipc_frame_hash(&self) -> SemanticHash {
        self.ipc_frame_hash
    }

    pub fn receipt_hash(&self) -> SemanticHash {
        self.receipt_hash
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SurfaceNativeT1ProcessEvidence {
    schema_version: (u16, u16, u16),
    process_policy_version: (u16, u16, u16),
    ipc_schema_version: (u16, u16, u16),
    carrier: SurfaceNativeT1Evidence,
    receipts: Vec<SurfaceNativeT1ProcessReceipt>,
    results_hash: SemanticHash,
    evidence_hash: SemanticHash,
}

impl SurfaceNativeT1ProcessEvidence {
    pub fn schema_version(&self) -> (u16, u16, u16) {
        self.schema_version
    }

    pub fn process_policy_version(&self) -> (u16, u16, u16) {
        self.process_policy_version
    }

    pub fn ipc_schema_version(&self) -> (u16, u16, u16) {
        self.ipc_schema_version
    }

    pub fn carrier(&self) -> &SurfaceNativeT1Evidence {
        &self.carrier
    }

    pub fn receipts(&self) -> &[SurfaceNativeT1ProcessReceipt] {
        &self.receipts
    }

    pub fn results_hash(&self) -> SemanticHash {
        self.results_hash
    }

    pub fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedSurfaceNativeT1ProcessEvidence<'evidence> {
    evidence: &'evidence SurfaceNativeT1ProcessEvidence,
}

impl<'evidence> VerifiedSurfaceNativeT1ProcessEvidence<'evidence> {
    pub fn evidence(self) -> &'evidence SurfaceNativeT1ProcessEvidence {
        self.evidence
    }
}

#[derive(Debug)]
pub enum SurfaceNativeT1ProcessError {
    Carrier(SurfaceNativeT1Error),
    Process(X64NativeProcessError),
    FrameSize {
        expected: usize,
        actual: usize,
    },
    InvalidFrameField {
        case_ordinal: u32,
        field: &'static str,
    },
    Truncated {
        field: &'static str,
    },
    UnknownScalarTag {
        field: &'static str,
        actual: u8,
    },
    NonCanonicalScalar {
        field: &'static str,
    },
    FrameHashMismatch {
        case_ordinal: u32,
    },
    FixedCorpusCount {
        expected: usize,
        actual: usize,
    },
    EvidenceMismatch,
    MetricOverflow,
}

impl fmt::Display for SurfaceNativeT1ProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Carrier(error) => write!(formatter, "Surface-native carrier failed: {error}"),
            Self::Process(error) => write!(formatter, "Surface-native worker failed: {error}"),
            Self::FrameSize { expected, actual } => write!(
                formatter,
                "Surface-native IPC frame uses {actual} bytes; exact size is {expected}"
            ),
            Self::InvalidFrameField {
                case_ordinal,
                field,
            } => write!(
                formatter,
                "Surface-native IPC case {case_ordinal} has invalid `{field}`"
            ),
            Self::Truncated { field } => {
                write!(
                    formatter,
                    "Surface-native IPC frame is truncated at `{field}`"
                )
            }
            Self::UnknownScalarTag { field, actual } => write!(
                formatter,
                "Surface-native IPC `{field}` has unknown scalar tag {actual}"
            ),
            Self::NonCanonicalScalar { field } => {
                write!(formatter, "Surface-native IPC `{field}` is noncanonical")
            }
            Self::FrameHashMismatch { case_ordinal } => write!(
                formatter,
                "Surface-native IPC case {case_ordinal} has an invalid frame seal"
            ),
            Self::FixedCorpusCount { expected, actual } => write!(
                formatter,
                "Surface-native process evidence requires {expected} receipts, found {actual}"
            ),
            Self::EvidenceMismatch => formatter.write_str(
                "Surface-native process evidence differs from exact regenerative replay",
            ),
            Self::MetricOverflow => formatter.write_str("Surface-native process metric overflow"),
        }
    }
}

impl std::error::Error for SurfaceNativeT1ProcessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Carrier(error) => Some(error),
            Self::Process(error) => Some(error),
            _ => None,
        }
    }
}

impl From<SurfaceNativeT1Error> for SurfaceNativeT1ProcessError {
    fn from(error: SurfaceNativeT1Error) -> Self {
        Self::Carrier(error)
    }
}

impl From<X64NativeProcessError> for SurfaceNativeT1ProcessError {
    fn from(error: X64NativeProcessError) -> Self {
        Self::Process(error)
    }
}

#[derive(Clone, Debug)]
struct DecodedFrame {
    record: SurfaceNativeT1Record,
    frame_hash: SemanticHash,
}

/// Child-only fixed operation. No source, corpus, budget, target, or argument
/// override is accepted.
#[doc(hidden)]
pub fn emit_surface_native_t1_worker_frame(
    case_ordinal: u32,
) -> Result<Vec<u8>, SurfaceNativeT1ProcessError> {
    let prepared = prepare_surface_native_t1()?;
    let executed = execute_prepared_surface_native_t1_case(&prepared, case_ordinal)?;
    encode_frame(&prepared, &executed)
}

/// Emit exact twelve-case process evidence from a caller-reviewed worker path.
/// The path is a trust input, not executable attestation.
pub fn emit_surface_native_t1_process_evidence(
    worker_path: &Path,
) -> Result<SurfaceNativeT1ProcessEvidence, SurfaceNativeT1ProcessError> {
    let prepared = prepare_surface_native_t1()?;
    let carrier = expected_surface_native_t1_evidence(&prepared)?;
    let mut receipts = Vec::with_capacity(SURFACE_NATIVE_T1_CASES);
    for ordinal in 0..SURFACE_NATIVE_T1_CASES {
        let ordinal =
            u32::try_from(ordinal).map_err(|_| SurfaceNativeT1ProcessError::MetricOverflow)?;
        let frame = run_x64_worker_frame_bounded(
            worker_path,
            ordinal,
            Duration::from_millis(SURFACE_NATIVE_T1_PROCESS_TIMEOUT_MILLIS),
            SURFACE_NATIVE_T1_PROCESS_DEBUG_ENV,
            None,
            SURFACE_NATIVE_T1_PROCESS_MAX_RECORD_BYTES,
        )?;
        let expected = observe_prepared_surface_native_t1_case(&prepared, ordinal)?;
        let decoded = decode_and_bind_frame(&frame, &prepared, &expected)?;
        receipts.push(seal_receipt(&decoded));
    }
    seal_evidence(carrier, receipts)
}

/// Regenerate the complete fixed process carrier using the same reviewed
/// worker path, then compare every supplied field.
pub fn verify_surface_native_t1_process_evidence<'evidence>(
    evidence: &'evidence SurfaceNativeT1ProcessEvidence,
    worker_path: &Path,
) -> Result<VerifiedSurfaceNativeT1ProcessEvidence<'evidence>, SurfaceNativeT1ProcessError> {
    preflight_evidence(evidence)?;
    let expected = emit_surface_native_t1_process_evidence(worker_path)?;
    if evidence != &expected {
        return Err(SurfaceNativeT1ProcessError::EvidenceMismatch);
    }
    Ok(VerifiedSurfaceNativeT1ProcessEvidence { evidence })
}

/// Debug-only process-failure seam used by the adversarial integration test.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn probe_surface_native_t1_worker_debug(
    worker_path: &Path,
    case_ordinal: u32,
    mode: &str,
) -> Result<(), SurfaceNativeT1ProcessError> {
    if !matches!(mode, "timeout" | "descendant-pipe")
        && !matches!(
            mode,
            "abort"
                | "abnormal"
                | "missing"
                | "malformed"
                | "oversized"
                | "diagnostics-limit"
                | "diagnostics-one-over"
                | "diagnostic-bytes-limit"
                | "diagnostic-bytes-one-over"
                | "record-limit"
                | "trailing"
                | "truncated"
                | "double-frame"
                | "valid-abnormal"
                | "valid-abort"
                | "wrong-case"
                | "resealed-observation"
                | "resealed-identity"
                | "resealed-mapping"
        )
    {
        return Err(SurfaceNativeT1ProcessError::EvidenceMismatch);
    }
    let timeout = if matches!(mode, "timeout" | "descendant-pipe") {
        Duration::from_millis(40)
    } else {
        Duration::from_millis(SURFACE_NATIVE_T1_PROCESS_TIMEOUT_MILLIS)
    };
    let frame = run_x64_worker_frame_bounded(
        worker_path,
        case_ordinal,
        timeout,
        SURFACE_NATIVE_T1_PROCESS_DEBUG_ENV,
        Some(mode),
        SURFACE_NATIVE_T1_PROCESS_MAX_RECORD_BYTES,
    )?;
    let prepared = prepare_surface_native_t1()?;
    let expected = observe_prepared_surface_native_t1_case(&prepared, case_ordinal)?;
    decode_and_bind_frame(&frame, &prepared, &expected)?;
    Ok(())
}

/// Construct an internally valid but semantically altered child frame. This
/// proves that parent reconstruction, rather than the child frame seal, owns
/// the admitted source and observation.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn probe_surface_native_t1_resealed_worker_frame(
    case_ordinal: u32,
    mode: &str,
) -> Result<Vec<u8>, SurfaceNativeT1ProcessError> {
    let prepared = prepare_surface_native_t1()?;
    let executed = execute_prepared_surface_native_t1_case(&prepared, case_ordinal)?;
    let mut frame = encode_frame(&prepared, &executed)?;
    let global_start = IPC_DOMAIN.len() + VERSION_BYTES * 3 + 4;
    match mode {
        "resealed-identity" => frame[global_start] ^= 1,
        "resealed-observation" => {
            let values_start = global_start + HASH_BYTES * GLOBAL_HASHES + HASH_BYTES;
            let native_payload_last = values_start + NORMALIZED_SCALAR_BYTES * 6 - 1;
            frame[native_payload_last] ^= 1;
        }
        "resealed-mapping" => {
            let mapping_start = global_start
                + HASH_BYTES * GLOBAL_HASHES
                + HASH_BYTES
                + NORMALIZED_SCALAR_BYTES * 6
                + HASH_BYTES
                + HASH_BYTES * NATIVE_HASHES;
            frame[mapping_start] = 2;
        }
        _ => return Err(SurfaceNativeT1ProcessError::EvidenceMismatch),
    }
    let seal_start = frame.len() - HASH_BYTES;
    let seal = sha256(&frame[..seal_start]);
    frame[seal_start..].copy_from_slice(&seal);
    Ok(frame)
}

pub fn render_surface_native_t1_process_report(
    evidence: &SurfaceNativeT1ProcessEvidence,
) -> String {
    let mut report = String::from("NAUX-SURFACE-NATIVE-T1-PROCESS\n");
    report.push_str(&format!(
        "schema\t{}.{}.{}\nprocess-policy\t{}.{}.{}\nipc\t{}.{}.{}\n",
        evidence.schema_version.0,
        evidence.schema_version.1,
        evidence.schema_version.2,
        evidence.process_policy_version.0,
        evidence.process_policy_version.1,
        evidence.process_policy_version.2,
        evidence.ipc_schema_version.0,
        evidence.ipc_schema_version.1,
        evidence.ipc_schema_version.2,
    ));
    report.push_str(&format!(
        "frame-bytes\t{}\n",
        SURFACE_NATIVE_T1_PROCESS_FRAME_BYTES
    ));
    for (name, hash) in [
        ("source", evidence.carrier.source_hash),
        ("corpus", evidence.carrier.corpus_hash),
        ("carrier-results", evidence.carrier.results_hash),
        ("process-results", evidence.results_hash),
        ("process-evidence", evidence.evidence_hash),
    ] {
        report.push_str(&format!("root\t{name}\t{hash}\n"));
    }
    report.push_str("columns\tordinal\tinput\tcarrier-record\tipc-frame\treceipt\n");
    for receipt in &evidence.receipts {
        report.push_str(&format!(
            "case\t{}\t{}\t{}\t{}\t{}\n",
            receipt.case_ordinal,
            receipt.input_hash,
            receipt.carrier_record_hash,
            receipt.ipc_frame_hash,
            receipt.receipt_hash,
        ));
    }
    report.push_str(&format!("records\t{}\n", evidence.receipts.len()));
    report
}

pub fn surface_native_t1_process_report_hash(
    evidence: &SurfaceNativeT1ProcessEvidence,
) -> SemanticHash {
    hash_domain(
        REPORT_DOMAIN,
        render_surface_native_t1_process_report(evidence).as_bytes(),
    )
}

/// Adversarial seam: alter a receipt binding, then coherently reseal every
/// process-owned aggregate field. Regenerative verification must still reject
/// the result.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn probe_surface_native_t1_process_resealed_receipt_mutation(
    evidence: &SurfaceNativeT1ProcessEvidence,
) -> SurfaceNativeT1ProcessEvidence {
    let mut mutated = evidence.clone();
    if let Some(receipt) = mutated.receipts.first_mut() {
        receipt.input_hash.0[0] ^= 1;
        receipt.receipt_hash = receipt_hash(receipt);
    }
    mutated.results_hash = process_results_hash(&mutated.carrier, &mutated.receipts);
    mutated.evidence_hash = process_evidence_hash(&mutated);
    mutated
}

/// Adversarial seam: coherently mutate the nested carrier and rebind every
/// process receipt/aggregate that a self-authenticating verifier might trust.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn probe_surface_native_t1_process_resealed_carrier_mutation(
    evidence: &SurfaceNativeT1ProcessEvidence,
) -> SurfaceNativeT1ProcessEvidence {
    let mut mutated = evidence.clone();
    mutated.carrier = probe_surface_native_t1_resealed_observation_mutation(&mutated.carrier);
    for (receipt, record) in mutated.receipts.iter_mut().zip(&mutated.carrier.records) {
        receipt.carrier_record_hash = record.record_hash;
        receipt.receipt_hash = receipt_hash(receipt);
    }
    mutated.results_hash = process_results_hash(&mutated.carrier, &mutated.receipts);
    mutated.evidence_hash = process_evidence_hash(&mutated);
    mutated
}

fn encode_frame(
    prepared: &PreparedSurfaceNativeT1,
    executed: &SurfaceNativeT1ExecutedCase,
) -> Result<Vec<u8>, SurfaceNativeT1ProcessError> {
    let mut bytes = Vec::with_capacity(SURFACE_NATIVE_T1_PROCESS_FRAME_BYTES);
    bytes.extend_from_slice(IPC_DOMAIN);
    put_version(&mut bytes, SURFACE_NATIVE_T1_PROCESS_SCHEMA_VERSION);
    put_version(&mut bytes, SURFACE_NATIVE_T1_PROCESS_POLICY_VERSION);
    put_version(&mut bytes, SURFACE_NATIVE_T1_IPC_SCHEMA_VERSION);
    put_u32(&mut bytes, executed.record.ordinal);
    for hash in global_hashes(prepared) {
        put_hash(&mut bytes, hash);
    }
    put_hash(&mut bytes, executed.record.input_hash);
    for value in record_values(&executed.record) {
        put_scalar(&mut bytes, value);
    }
    put_hash(&mut bytes, executed.record.record_hash);
    for hash in [
        executed.target_artifact_hash,
        executed.target_plan_hash,
        executed.source_machine_ir_hash,
        executed.verified_code_hash,
        executed.copied_rw_code_hash,
        executed.readback_rx_code_hash,
    ] {
        put_hash(&mut bytes, hash);
    }
    for state in executed.mapping_trace {
        bytes.push(mapping_state_tag(state));
    }
    bytes.push(executed.input_lanes);
    put_u32(&mut bytes, executed.mxcsr_before);
    put_u32(&mut bytes, executed.mxcsr_after);
    bytes.push(u8::from(executed.fallback));
    put_u32(&mut bytes, executed.effect_count);
    let frame_hash = SemanticHash(sha256(&bytes));
    put_hash(&mut bytes, frame_hash);
    if bytes.len() != SURFACE_NATIVE_T1_PROCESS_FRAME_BYTES {
        return Err(SurfaceNativeT1ProcessError::FrameSize {
            expected: SURFACE_NATIVE_T1_PROCESS_FRAME_BYTES,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

fn decode_and_bind_frame(
    bytes: &[u8],
    prepared: &PreparedSurfaceNativeT1,
    expected: &SurfaceNativeT1ExpectedCase,
) -> Result<DecodedFrame, SurfaceNativeT1ProcessError> {
    if bytes.len() != SURFACE_NATIVE_T1_PROCESS_FRAME_BYTES {
        return Err(SurfaceNativeT1ProcessError::FrameSize {
            expected: SURFACE_NATIVE_T1_PROCESS_FRAME_BYTES,
            actual: bytes.len(),
        });
    }
    let sealed_prefix = &bytes[..bytes.len() - HASH_BYTES];
    let mut cursor = Cursor::new(bytes);
    require_field(
        expected.ordinal,
        "IPC domain",
        cursor.take(IPC_DOMAIN.len(), "IPC domain")? == IPC_DOMAIN,
    )?;
    require_field(
        expected.ordinal,
        "process schema",
        cursor.version("process schema")? == SURFACE_NATIVE_T1_PROCESS_SCHEMA_VERSION,
    )?;
    require_field(
        expected.ordinal,
        "process policy",
        cursor.version("process policy")? == SURFACE_NATIVE_T1_PROCESS_POLICY_VERSION,
    )?;
    require_field(
        expected.ordinal,
        "IPC schema",
        cursor.version("IPC schema")? == SURFACE_NATIVE_T1_IPC_SCHEMA_VERSION,
    )?;
    require_field(
        expected.ordinal,
        "case ordinal",
        cursor.u32("case ordinal")? == expected.ordinal,
    )?;
    for (field, wanted) in [
        ("source hash", prepared.source_hash),
        ("request hash", prepared.request_hash),
        ("corpus hash", prepared.corpus_hash),
        ("Core hash", prepared.report.artifact.semantic_hash),
        ("SSA hash", prepared.ssa.semantic_hash),
        ("Machine IR hash", prepared.machine_ir.semantic_hash),
        ("target artifact hash", prepared.target.semantic_hash),
        ("target plan hash", prepared.target.program.plan_hash),
        ("target code hash", prepared.target.program.code_hash),
    ] {
        require_field(expected.ordinal, field, cursor.hash(field)? == wanted)?;
    }
    require_field(
        expected.ordinal,
        "input hash",
        cursor.hash("input hash")? == expected.input_hash,
    )?;
    let wanted_record = expected.expected_record();
    let mut values = [NormalizedScalar::Bool(false); 6];
    for (index, field) in [
        "Surface value",
        "Core value",
        "SSA value",
        "Machine IR value",
        "target-plan value",
        "native value",
    ]
    .into_iter()
    .enumerate()
    {
        values[index] = cursor.scalar(field)?;
    }
    let record = SurfaceNativeT1Record {
        ordinal: expected.ordinal,
        name: expected.name,
        input_hash: expected.input_hash,
        surface: values[0],
        core: values[1],
        ssa: values[2],
        machine_ir: values[3],
        target_plan: values[4],
        native: values[5],
        record_hash: cursor.hash("carrier record hash")?,
    };
    require_field(expected.ordinal, "carrier record", record == wanted_record)?;
    for (field, wanted) in [
        ("native target artifact hash", prepared.target.semantic_hash),
        ("native target plan hash", prepared.target.program.plan_hash),
        (
            "native source Machine IR hash",
            prepared.machine_ir.semantic_hash,
        ),
        (
            "native verified code hash",
            prepared.target.program.code_hash,
        ),
        ("native copied RW hash", prepared.target.program.code_hash),
        ("native readback RX hash", prepared.target.program.code_hash),
    ] {
        require_field(expected.ordinal, field, cursor.hash(field)? == wanted)?;
    }
    for (field, wanted) in [
        ("mapping state 0 (unmapped)", 0_u8),
        ("mapping state 1 (read-write)", 1),
        ("mapping state 2 (read-execute)", 2),
        ("mapping state 3 (unmapped)", 0),
    ] {
        require_field(
            expected.ordinal,
            field,
            cursor.u8("mapping state")? == wanted,
        )?;
    }
    require_field(
        expected.ordinal,
        "five-lane ABI",
        cursor.u8("input lanes")? == 5,
    )?;
    let mxcsr_before = cursor.u32("MXCSR before")?;
    let mxcsr_after = cursor.u32("MXCSR after")?;
    const MXCSR_STATUS_FLAGS: u32 = 0x3f;
    let canonical_mxcsr = X64TargetAbi::r1_s7a().canonical_mxcsr;
    require_field(
        expected.ordinal,
        "canonical MXCSR control",
        mxcsr_before & !MXCSR_STATUS_FLAGS == canonical_mxcsr & !MXCSR_STATUS_FLAGS,
    )?;
    require_field(
        expected.ordinal,
        "restored MXCSR",
        mxcsr_after == mxcsr_before,
    )?;
    require_field(expected.ordinal, "fallback", cursor.u8("fallback")? == 0)?;
    require_field(
        expected.ordinal,
        "effect count",
        cursor.u32("effect count")? == 0,
    )?;
    let frame_hash = cursor.hash("frame hash")?;
    if cursor.remaining() != 0 {
        return Err(SurfaceNativeT1ProcessError::FrameSize {
            expected: SURFACE_NATIVE_T1_PROCESS_FRAME_BYTES,
            actual: bytes.len(),
        });
    }
    if frame_hash != SemanticHash(sha256(sealed_prefix)) {
        return Err(SurfaceNativeT1ProcessError::FrameHashMismatch {
            case_ordinal: expected.ordinal,
        });
    }
    Ok(DecodedFrame { record, frame_hash })
}

fn seal_receipt(frame: &DecodedFrame) -> SurfaceNativeT1ProcessReceipt {
    let mut receipt = SurfaceNativeT1ProcessReceipt {
        schema_version: SURFACE_NATIVE_T1_PROCESS_SCHEMA_VERSION,
        process_policy_version: SURFACE_NATIVE_T1_PROCESS_POLICY_VERSION,
        ipc_schema_version: SURFACE_NATIVE_T1_IPC_SCHEMA_VERSION,
        case_ordinal: frame.record.ordinal,
        input_hash: frame.record.input_hash,
        carrier_record_hash: frame.record.record_hash,
        ipc_frame_hash: frame.frame_hash,
        receipt_hash: SemanticHash::ZERO,
    };
    receipt.receipt_hash = receipt_hash(&receipt);
    receipt
}

fn seal_evidence(
    carrier: SurfaceNativeT1Evidence,
    receipts: Vec<SurfaceNativeT1ProcessReceipt>,
) -> Result<SurfaceNativeT1ProcessEvidence, SurfaceNativeT1ProcessError> {
    if receipts.len() != SURFACE_NATIVE_T1_CASES {
        return Err(SurfaceNativeT1ProcessError::FixedCorpusCount {
            expected: SURFACE_NATIVE_T1_CASES,
            actual: receipts.len(),
        });
    }
    for (ordinal, (receipt, record)) in receipts.iter().zip(&carrier.records).enumerate() {
        let ordinal =
            u32::try_from(ordinal).map_err(|_| SurfaceNativeT1ProcessError::MetricOverflow)?;
        if receipt.case_ordinal != ordinal
            || receipt.input_hash != record.input_hash
            || receipt.carrier_record_hash != record.record_hash
            || receipt.receipt_hash != receipt_hash(receipt)
        {
            return Err(SurfaceNativeT1ProcessError::InvalidFrameField {
                case_ordinal: ordinal,
                field: "receipt binding",
            });
        }
    }
    let results_hash = process_results_hash(&carrier, &receipts);
    let mut evidence = SurfaceNativeT1ProcessEvidence {
        schema_version: SURFACE_NATIVE_T1_PROCESS_SCHEMA_VERSION,
        process_policy_version: SURFACE_NATIVE_T1_PROCESS_POLICY_VERSION,
        ipc_schema_version: SURFACE_NATIVE_T1_IPC_SCHEMA_VERSION,
        carrier,
        receipts,
        results_hash,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = process_evidence_hash(&evidence);
    Ok(evidence)
}

fn preflight_evidence(
    evidence: &SurfaceNativeT1ProcessEvidence,
) -> Result<(), SurfaceNativeT1ProcessError> {
    if evidence.schema_version != SURFACE_NATIVE_T1_PROCESS_SCHEMA_VERSION
        || evidence.process_policy_version != SURFACE_NATIVE_T1_PROCESS_POLICY_VERSION
        || evidence.ipc_schema_version != SURFACE_NATIVE_T1_IPC_SCHEMA_VERSION
    {
        return Err(SurfaceNativeT1ProcessError::EvidenceMismatch);
    }
    if evidence.receipts.len() != SURFACE_NATIVE_T1_CASES
        || evidence.carrier.records.len() != SURFACE_NATIVE_T1_CASES
    {
        return Err(SurfaceNativeT1ProcessError::FixedCorpusCount {
            expected: SURFACE_NATIVE_T1_CASES,
            actual: evidence.receipts.len(),
        });
    }
    Ok(())
}

fn receipt_hash(receipt: &SurfaceNativeT1ProcessReceipt) -> SemanticHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(RECEIPT_DOMAIN);
    put_version(&mut bytes, receipt.schema_version);
    put_version(&mut bytes, receipt.process_policy_version);
    put_version(&mut bytes, receipt.ipc_schema_version);
    put_u32(&mut bytes, receipt.case_ordinal);
    for hash in [
        receipt.input_hash,
        receipt.carrier_record_hash,
        receipt.ipc_frame_hash,
    ] {
        put_hash(&mut bytes, hash);
    }
    SemanticHash(sha256(&bytes))
}

fn process_results_hash(
    carrier: &SurfaceNativeT1Evidence,
    receipts: &[SurfaceNativeT1ProcessReceipt],
) -> SemanticHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(RESULTS_DOMAIN);
    put_hash(&mut bytes, carrier.results_hash);
    put_u32(&mut bytes, receipts.len() as u32);
    for receipt in receipts {
        put_hash(&mut bytes, receipt.receipt_hash);
    }
    SemanticHash(sha256(&bytes))
}

fn process_evidence_hash(evidence: &SurfaceNativeT1ProcessEvidence) -> SemanticHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.process_policy_version);
    put_version(&mut bytes, evidence.ipc_schema_version);
    for hash in [
        evidence.carrier.source_hash,
        evidence.carrier.request_hash,
        evidence.carrier.corpus_hash,
        evidence.carrier.core_hash,
        evidence.carrier.ssa_hash,
        evidence.carrier.machine_ir_hash,
        evidence.carrier.target_hash,
        evidence.carrier.target_plan_hash,
        evidence.carrier.target_code_hash,
        evidence.carrier.results_hash,
        evidence.carrier.evidence_hash,
        evidence.results_hash,
    ] {
        put_hash(&mut bytes, hash);
    }
    put_u32(&mut bytes, evidence.receipts.len() as u32);
    SemanticHash(sha256(&bytes))
}

fn global_hashes(prepared: &PreparedSurfaceNativeT1) -> [SemanticHash; GLOBAL_HASHES] {
    [
        prepared.source_hash,
        prepared.request_hash,
        prepared.corpus_hash,
        prepared.report.artifact.semantic_hash,
        prepared.ssa.semantic_hash,
        prepared.machine_ir.semantic_hash,
        prepared.target.semantic_hash,
        prepared.target.program.plan_hash,
        prepared.target.program.code_hash,
    ]
}

fn record_values(record: &SurfaceNativeT1Record) -> [NormalizedScalar; 6] {
    [
        record.surface,
        record.core,
        record.ssa,
        record.machine_ir,
        record.target_plan,
        record.native,
    ]
}

fn require_field(
    case_ordinal: u32,
    field: &'static str,
    valid: bool,
) -> Result<(), SurfaceNativeT1ProcessError> {
    if valid {
        Ok(())
    } else {
        Err(SurfaceNativeT1ProcessError::InvalidFrameField {
            case_ordinal,
            field,
        })
    }
}

fn hash_domain(domain: &[u8], payload: &[u8]) -> SemanticHash {
    let mut bytes = Vec::with_capacity(domain.len() + payload.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(payload);
    SemanticHash(sha256(&bytes))
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_be_bytes());
    bytes.extend_from_slice(&version.1.to_be_bytes());
    bytes.extend_from_slice(&version.2.to_be_bytes());
}

fn put_hash(bytes: &mut Vec<u8>, hash: SemanticHash) {
    bytes.extend_from_slice(&hash.0);
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

const fn mapping_state_tag(state: X64NativeMappingState) -> u8 {
    match state {
        X64NativeMappingState::Unmapped => 0,
        X64NativeMappingState::ReadWrite => 1,
        X64NativeMappingState::ReadExecute => 2,
    }
}

fn put_scalar(bytes: &mut Vec<u8>, value: NormalizedScalar) {
    match value {
        NormalizedScalar::Bool(value) => {
            bytes.push(0);
            bytes.push(u8::from(value));
            bytes.extend_from_slice(&[0; 7]);
        }
        NormalizedScalar::I64(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        NormalizedScalar::F64Bits(value) => {
            bytes.push(2);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    }
}

struct Cursor<'bytes> {
    bytes: &'bytes [u8],
    position: usize,
}

impl<'bytes> Cursor<'bytes> {
    fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(
        &mut self,
        length: usize,
        field: &'static str,
    ) -> Result<&'bytes [u8], SurfaceNativeT1ProcessError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(SurfaceNativeT1ProcessError::Truncated { field })?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(SurfaceNativeT1ProcessError::Truncated { field })?;
        self.position = end;
        Ok(slice)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, SurfaceNativeT1ProcessError> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, SurfaceNativeT1ProcessError> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, SurfaceNativeT1ProcessError> {
        let bytes = self.take(4, field)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn version(
        &mut self,
        field: &'static str,
    ) -> Result<(u16, u16, u16), SurfaceNativeT1ProcessError> {
        Ok((self.u16(field)?, self.u16(field)?, self.u16(field)?))
    }

    fn hash(&mut self, field: &'static str) -> Result<SemanticHash, SurfaceNativeT1ProcessError> {
        let bytes = self.take(HASH_BYTES, field)?;
        let mut hash = [0; HASH_BYTES];
        hash.copy_from_slice(bytes);
        Ok(SemanticHash(hash))
    }

    fn scalar(
        &mut self,
        field: &'static str,
    ) -> Result<NormalizedScalar, SurfaceNativeT1ProcessError> {
        let tag = self.u8(field)?;
        let payload = self.take(8, field)?;
        let mut word = [0; 8];
        word.copy_from_slice(payload);
        match tag {
            0 if payload[0] <= 1 && payload[1..].iter().all(|byte| *byte == 0) => {
                Ok(NormalizedScalar::Bool(payload[0] == 1))
            }
            0 => Err(SurfaceNativeT1ProcessError::NonCanonicalScalar { field }),
            1 => Ok(NormalizedScalar::I64(i64::from_be_bytes(word))),
            2 => Ok(NormalizedScalar::F64Bits(u64::from_be_bytes(word))),
            actual => Err(SurfaceNativeT1ProcessError::UnknownScalarTag { field, actual }),
        }
    }
}

#[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn fixed_frame_round_trips_and_binds_parent_reconstruction() {
        let prepared = prepare_surface_native_t1().expect("fixed T1 must prepare");
        let expected = observe_prepared_surface_native_t1_case(&prepared, 0)
            .expect("fixed case must evaluate");
        let executed =
            execute_prepared_surface_native_t1_case(&prepared, 0).expect("fixed case must execute");
        let frame = encode_frame(&prepared, &executed).expect("frame must encode");
        assert_eq!(frame.len(), SURFACE_NATIVE_T1_PROCESS_FRAME_BYTES);
        let decoded =
            decode_and_bind_frame(&frame, &prepared, &expected).expect("canonical frame must bind");
        assert_eq!(decoded.record, expected.expected_record());

        let mut corrupted = frame;
        corrupted[IPC_DOMAIN.len() + VERSION_BYTES * 3 + 4] ^= 1;
        assert!(decode_and_bind_frame(&corrupted, &prepared, &expected).is_err());
    }
}
