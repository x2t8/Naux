//! Process-isolated fixed-corpus evidence for R1-S7b-c.
//!
//! A dedicated child receives only one canonical Gate A ordinal, rebuilds
//! the complete source-bound target chain, performs one native invocation,
//! and publishes one bounded IPC record. The parent independently rebuilds
//! the expected target and Machine IR observation before it admits that
//! untrusted record into correspondence evidence.

use super::corevm0_gate_a::{
    corevm0_gate_a_manifest, CoreVmGateACase, CoreVmGateAError, CoreVmGateAWorkload,
};
use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_native::{
    execute_x64_native_case_r1_s7b, seal_x64_native_correspondence_evidence,
    seal_x64_native_correspondence_record, seal_x64_native_execution_record,
    verify_x64_native_correspondence_evidence, X64NativeCorrespondenceEvidence,
    X64NativeCorrespondenceRecord, X64NativeEvidenceError, X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS,
    X64_NATIVE_MAX_DIAGNOSTICS, X64_NATIVE_MAX_RECORD_BYTES,
};
use super::x64_native_ipc::{
    decode_x64_native_ipc_record, encode_x64_native_ipc_record, seal_x64_native_ipc_record,
    verify_x64_native_ipc_record, X64NativeIpcError, X64NativeIpcRecord,
    X64_NATIVE_IPC_SCHEMA_VERSION, X64_NATIVE_PROCESS_POLICY_VERSION,
};
use super::x64_native_lighthouse::{
    x64_native_lighthouse_case, X64NativeLighthouseError, X64NativeLighthousePackage,
};
use std::fmt;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const X64_NATIVE_PROCESS_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_NATIVE_PROCESS_TIMEOUT_MILLIS: u64 = 30_000;
pub const X64_NATIVE_PROCESS_MAX_DIAGNOSTIC_BYTES: u64 = 16_384;

const X64_NATIVE_PROCESS_RECEIPT_DOMAIN: &[u8] = b"NAUX:x86-64:r1-s7b:process:receipt:v1\0";
const X64_NATIVE_PROCESS_RESULTS_DOMAIN: &[u8] = b"NAUX:x86-64:r1-s7b:process:results:v1\0";
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const PROCESS_REAP_TIMEOUT: Duration = Duration::from_secs(1);
const PIPE_READER_JOIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Deterministic receipt for one normally exited child and one complete IPC
/// frame. Exit status, PID, signal number, ASLR, and elapsed time are
/// construction preconditions or telemetry and never enter this identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64NativeProcessReceipt {
    schema_version: (u16, u16, u16),
    process_policy_version: (u16, u16, u16),
    ipc_schema_version: (u16, u16, u16),
    case_ordinal: u32,
    input_hash: SemanticHash,
    native_execution_record_hash: SemanticHash,
    ipc_frame_hash: SemanticHash,
    receipt_hash: SemanticHash,
}

impl X64NativeProcessReceipt {
    pub(super) const fn schema_version(&self) -> (u16, u16, u16) {
        self.schema_version
    }

    pub(super) const fn process_policy_version(&self) -> (u16, u16, u16) {
        self.process_policy_version
    }

    pub(super) const fn ipc_schema_version(&self) -> (u16, u16, u16) {
        self.ipc_schema_version
    }

    pub fn case_ordinal(&self) -> u32 {
        self.case_ordinal
    }

    pub fn input_hash(&self) -> SemanticHash {
        self.input_hash
    }

    pub fn native_execution_record_hash(&self) -> SemanticHash {
        self.native_execution_record_hash
    }

    pub fn ipc_frame_hash(&self) -> SemanticHash {
        self.ipc_frame_hash
    }

    pub fn receipt_hash(&self) -> SemanticHash {
        self.receipt_hash
    }
}

/// Claim package for the exact 51 process-isolated lighthouse cases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64NativeProcessEvidence {
    schema_version: (u16, u16, u16),
    process_policy_version: (u16, u16, u16),
    ipc_schema_version: (u16, u16, u16),
    corpus_manifest_hash: SemanticHash,
    receipts: Vec<X64NativeProcessReceipt>,
    correspondence: X64NativeCorrespondenceEvidence,
    results_hash: SemanticHash,
}

impl X64NativeProcessEvidence {
    pub(super) const fn schema_version(&self) -> (u16, u16, u16) {
        self.schema_version
    }

    pub(super) const fn process_policy_version(&self) -> (u16, u16, u16) {
        self.process_policy_version
    }

    pub(super) const fn ipc_schema_version(&self) -> (u16, u16, u16) {
        self.ipc_schema_version
    }

    pub fn corpus_manifest_hash(&self) -> SemanticHash {
        self.corpus_manifest_hash
    }

    pub fn receipts(&self) -> &[X64NativeProcessReceipt] {
        &self.receipts
    }

    pub fn correspondence(&self) -> &X64NativeCorrespondenceEvidence {
        &self.correspondence
    }

    pub fn semantic_results_hash(&self) -> SemanticHash {
        self.correspondence.results_hash
    }

    pub fn results_hash(&self) -> SemanticHash {
        self.results_hash
    }
}

/// Opaque authority proving that one immutable R1-S7b-c evidence package
/// passed complete ordinary verification.
///
/// The token borrows the verified package and cannot outlive or mutate it. It
/// is finite native-seed authority only; later standalone construction must
/// still regenerate and match the exact lighthouse source chain.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedX64NativeProcessEvidence<'evidence> {
    evidence: &'evidence X64NativeProcessEvidence,
}

impl<'evidence> VerifiedX64NativeProcessEvidence<'evidence> {
    pub fn evidence(self) -> &'evidence X64NativeProcessEvidence {
        self.evidence
    }

    pub fn semantic_results_hash(self) -> SemanticHash {
        self.evidence.semantic_results_hash()
    }

    pub fn process_results_hash(self) -> SemanticHash {
        self.evidence.results_hash()
    }
}

#[derive(Debug)]
pub enum X64NativeProcessError {
    UnsupportedHost,
    CorpusManifest(CoreVmGateAError),
    Lighthouse {
        message: String,
    },
    NativeEvidence(X64NativeEvidenceError),
    Ipc(X64NativeIpcError),
    Spawn {
        case_ordinal: u32,
        kind: io::ErrorKind,
    },
    MissingPipe {
        case_ordinal: u32,
        stream: &'static str,
    },
    PipeRead {
        case_ordinal: u32,
        stream: &'static str,
        kind: io::ErrorKind,
    },
    PipeReaderSpawn {
        case_ordinal: u32,
        stream: &'static str,
        kind: io::ErrorKind,
    },
    PipeReaderPanicked {
        case_ordinal: u32,
        stream: &'static str,
    },
    PipeReaderTimeout {
        case_ordinal: u32,
        stream: &'static str,
    },
    Wait {
        case_ordinal: u32,
        kind: io::ErrorKind,
    },
    Kill {
        case_ordinal: u32,
        kind: io::ErrorKind,
    },
    NativeTimeout {
        case_ordinal: u32,
        timeout_millis: u64,
    },
    NativeFault {
        case_ordinal: u32,
    },
    AbnormalExit {
        case_ordinal: u32,
        code: Option<i32>,
    },
    MissingRecord {
        case_ordinal: u32,
    },
    RecordByteLimit {
        case_ordinal: u32,
        limit: u64,
        actual: u64,
    },
    DiagnosticByteLimit {
        case_ordinal: u32,
        limit: u64,
        actual: u64,
    },
    DiagnosticLimit {
        case_ordinal: u32,
        limit: u32,
        actual: u32,
    },
    UnexpectedDiagnostics {
        case_ordinal: u32,
        actual: u32,
    },
    InvalidSchema,
    InvalidReceipt {
        case_ordinal: u32,
        field: &'static str,
    },
    FixedCorpusCount {
        expected: u32,
        actual: u32,
    },
    ReceiptHashMismatch {
        case_ordinal: u32,
    },
    ResultsHashMismatch,
    MetricOverflow,
    InvalidDebugProbe,
}

impl fmt::Display for X64NativeProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost => {
                formatter.write_str("R1-S7b-c process evidence requires Linux x86-64")
            }
            Self::CorpusManifest(error) => {
                write!(formatter, "cannot regenerate the R1-S7b-c corpus: {error}")
            }
            Self::Lighthouse { message } => write!(formatter, "{message}"),
            Self::NativeEvidence(error) => write!(formatter, "{error}"),
            Self::Ipc(error) => write!(formatter, "{error}"),
            Self::Spawn { case_ordinal, kind } => {
                write!(
                    formatter,
                    "cannot spawn R1-S7b-c case {case_ordinal}: {kind}"
                )
            }
            Self::MissingPipe {
                case_ordinal,
                stream,
            } => write!(
                formatter,
                "R1-S7b-c case {case_ordinal} has no captured {stream} pipe"
            ),
            Self::PipeRead {
                case_ordinal,
                stream,
                kind,
            } => write!(
                formatter,
                "cannot read R1-S7b-c case {case_ordinal} {stream}: {kind}"
            ),
            Self::PipeReaderSpawn {
                case_ordinal,
                stream,
                kind,
            } => write!(
                formatter,
                "cannot start R1-S7b-c case {case_ordinal} {stream} reader: {kind}"
            ),
            Self::PipeReaderPanicked {
                case_ordinal,
                stream,
            } => write!(
                formatter,
                "R1-S7b-c case {case_ordinal} {stream} reader panicked"
            ),
            Self::PipeReaderTimeout {
                case_ordinal,
                stream,
            } => write!(
                formatter,
                "R1-S7b-c case {case_ordinal} {stream} reader did not terminate"
            ),
            Self::Wait { case_ordinal, kind } => {
                write!(
                    formatter,
                    "cannot wait for R1-S7b-c case {case_ordinal}: {kind}"
                )
            }
            Self::Kill { case_ordinal, kind } => {
                write!(
                    formatter,
                    "cannot terminate R1-S7b-c case {case_ordinal}: {kind}"
                )
            }
            Self::NativeTimeout {
                case_ordinal,
                timeout_millis,
            } => write!(
                formatter,
                "R1-S7b-c case {case_ordinal} exceeded {timeout_millis} ms"
            ),
            Self::NativeFault { case_ordinal } => {
                write!(
                    formatter,
                    "R1-S7b-c case {case_ordinal} terminated by signal"
                )
            }
            Self::AbnormalExit { case_ordinal, code } => write!(
                formatter,
                "R1-S7b-c case {case_ordinal} exited abnormally with code {code:?}"
            ),
            Self::MissingRecord { case_ordinal } => {
                write!(
                    formatter,
                    "R1-S7b-c case {case_ordinal} emitted no IPC record"
                )
            }
            Self::RecordByteLimit {
                case_ordinal,
                limit,
                actual,
            } => write!(
                formatter,
                "R1-S7b-c case {case_ordinal} emitted {actual} bytes; limit is {limit}"
            ),
            Self::DiagnosticByteLimit {
                case_ordinal,
                limit,
                actual,
            } => write!(
                formatter,
                "R1-S7b-c case {case_ordinal} emitted {actual} diagnostic bytes; limit is {limit}"
            ),
            Self::DiagnosticLimit {
                case_ordinal,
                limit,
                actual,
            } => write!(
                formatter,
                "R1-S7b-c case {case_ordinal} emitted {actual} diagnostics; limit is {limit}"
            ),
            Self::UnexpectedDiagnostics {
                case_ordinal,
                actual,
            } => write!(
                formatter,
                "successful R1-S7b-c case {case_ordinal} emitted {actual} diagnostics"
            ),
            Self::InvalidSchema => {
                formatter.write_str("R1-S7b-c evidence uses a noncanonical schema or policy")
            }
            Self::InvalidReceipt {
                case_ordinal,
                field,
            } => write!(
                formatter,
                "R1-S7b-c receipt {case_ordinal} has an invalid {field}"
            ),
            Self::FixedCorpusCount { expected, actual } => write!(
                formatter,
                "R1-S7b-c requires {expected} receipts, found {actual}"
            ),
            Self::ReceiptHashMismatch { case_ordinal } => {
                write!(
                    formatter,
                    "R1-S7b-c receipt {case_ordinal} has an invalid seal"
                )
            }
            Self::ResultsHashMismatch => {
                formatter.write_str("R1-S7b-c isolated result hash is invalid")
            }
            Self::MetricOverflow => formatter.write_str("R1-S7b-c metric overflow"),
            Self::InvalidDebugProbe => formatter.write_str("unknown R1-S7b-c debug worker probe"),
        }
    }
}

impl std::error::Error for X64NativeProcessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CorpusManifest(error) => Some(error),
            Self::NativeEvidence(error) => Some(error),
            Self::Ipc(error) => Some(error),
            _ => None,
        }
    }
}

impl From<X64NativeLighthouseError> for X64NativeProcessError {
    fn from(error: X64NativeLighthouseError) -> Self {
        Self::Lighthouse {
            message: error.to_string(),
        }
    }
}

impl From<X64NativeEvidenceError> for X64NativeProcessError {
    fn from(error: X64NativeEvidenceError) -> Self {
        Self::NativeEvidence(error)
    }
}

impl From<X64NativeIpcError> for X64NativeProcessError {
    fn from(error: X64NativeIpcError) -> Self {
        Self::Ipc(error)
    }
}

/// Child-side operation. Regenerate one canonical source chain, establish the
/// claim MXCSR, execute once, and return one complete bounded IPC frame.
#[doc(hidden)]
pub fn emit_x64_native_worker_frame_r1_s7bc(
    case_ordinal: u32,
) -> Result<Vec<u8>, X64NativeProcessError> {
    require_supported_host()?;
    let case = x64_native_lighthouse_case(case_ordinal)?;
    let package = X64NativeLighthousePackage::build(case.workload)?;
    let target = package.source_bound()?;
    let _mxcsr_guard = ClaimMxcsrGuard::establish();
    let execution = execute_x64_native_case_r1_s7b(target, &case)?;
    let record = seal_x64_native_execution_record(target, &execution)?;
    Ok(encode_x64_native_ipc_record(case_ordinal, &record)?)
}

/// Parent-side exact 51-case emission. Each case receives a fresh child,
/// without retry or fallback.
///
/// `worker_path` is a caller-provided trust anchor and must name the reviewed
/// `naux-r1-s7b-worker` built from the same source snapshot. The resulting
/// evidence verifies the canonical protocol and semantic bindings; it is not
/// binary attestation, launch-environment attestation, or replay prevention.
pub fn emit_x64_native_process_evidence_r1_s7bc(
    worker_path: &Path,
) -> Result<X64NativeProcessEvidence, X64NativeProcessError> {
    require_supported_host()?;
    let manifest = corevm0_gate_a_manifest().map_err(X64NativeProcessError::CorpusManifest)?;
    let branch = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)?;
    let bounds = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BoundsOrderedArrayGet)?;
    let mut receipts = Vec::with_capacity(manifest.cases.len());
    let mut correspondence = Vec::with_capacity(manifest.cases.len());

    for case in &manifest.cases {
        let ipc = run_worker_case(
            worker_path,
            case,
            Duration::from_millis(X64_NATIVE_PROCESS_TIMEOUT_MILLIS),
            None,
        )?;
        let package = match case.workload {
            CoreVmGateAWorkload::BranchMix => &branch,
            CoreVmGateAWorkload::BoundsOrderedArrayGet => &bounds,
        };
        let record = bind_worker_ipc_to_source(case, package, &ipc)?;
        receipts.push(seal_process_receipt(case, &ipc)?);
        correspondence.push(record);
    }

    let correspondence = seal_x64_native_correspondence_evidence(correspondence)?;
    seal_process_evidence(receipts, correspondence)
}

/// Run one canonical worker process with the frozen timeout and return its
/// fully verified IPC record. This is a diagnostic primitive; only the fixed
/// 51-case aggregate above carries the R1-S7b-c claim.
///
/// As with the aggregate emitter, `worker_path` is a caller-supplied trust
/// anchor rather than an attested executable identity.
pub fn execute_x64_native_worker_case_r1_s7bc(
    worker_path: &Path,
    case_ordinal: u32,
) -> Result<X64NativeIpcRecord, X64NativeProcessError> {
    require_supported_host()?;
    let case = x64_native_lighthouse_case(case_ordinal)?;
    let ipc = run_worker_case(
        worker_path,
        &case,
        Duration::from_millis(X64_NATIVE_PROCESS_TIMEOUT_MILLIS),
        None,
    )?;
    let package = X64NativeLighthousePackage::build(case.workload)?;
    bind_worker_ipc_to_source(&case, &package, &ipc)?;
    Ok(ipc)
}

fn bind_worker_ipc_to_source(
    case: &CoreVmGateACase,
    package: &X64NativeLighthousePackage,
    ipc: &X64NativeIpcRecord,
) -> Result<X64NativeCorrespondenceRecord, X64NativeProcessError> {
    let target = package.source_bound()?;
    let _mxcsr_guard = ClaimMxcsrGuard::establish();
    let machine_ir = package.evaluate_machine_ir_case(case)?;
    Ok(seal_x64_native_correspondence_record(
        case,
        target,
        &machine_ir,
        ipc.native_execution.clone(),
    )?)
}

pub fn verify_x64_native_process_evidence_r1_s7bc(
    evidence: &X64NativeProcessEvidence,
) -> Result<VerifiedX64NativeProcessEvidence<'_>, X64NativeProcessError> {
    if evidence.schema_version != X64_NATIVE_PROCESS_SCHEMA_VERSION
        || evidence.process_policy_version != X64_NATIVE_PROCESS_POLICY_VERSION
        || evidence.ipc_schema_version != X64_NATIVE_IPC_SCHEMA_VERSION
    {
        return Err(X64NativeProcessError::InvalidSchema);
    }
    let manifest = corevm0_gate_a_manifest().map_err(X64NativeProcessError::CorpusManifest)?;
    if evidence.corpus_manifest_hash != manifest.manifest_hash
        || evidence.correspondence.corpus_manifest_hash != manifest.manifest_hash
    {
        return Err(X64NativeProcessError::InvalidReceipt {
            case_ordinal: 0,
            field: "corpus manifest hash",
        });
    }
    verify_x64_native_correspondence_evidence(&evidence.correspondence)?;
    validate_process_receipts(&evidence.receipts, &evidence.correspondence.records)?;
    let actual =
        x64_native_process_results_hash(&evidence.receipts, evidence.correspondence.results_hash)?;
    if actual != evidence.results_hash {
        return Err(X64NativeProcessError::ResultsHashMismatch);
    }
    Ok(VerifiedX64NativeProcessEvidence { evidence })
}

pub fn x64_native_process_results_hash(
    receipts: &[X64NativeProcessReceipt],
    semantic_results_hash: SemanticHash,
) -> Result<SemanticHash, X64NativeProcessError> {
    let count = u32::try_from(receipts.len()).map_err(|_| X64NativeProcessError::MetricOverflow)?;
    if count != X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS {
        return Err(X64NativeProcessError::FixedCorpusCount {
            expected: X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS,
            actual: count,
        });
    }
    let manifest = corevm0_gate_a_manifest().map_err(X64NativeProcessError::CorpusManifest)?;
    if semantic_results_hash == SemanticHash::ZERO {
        return Err(X64NativeProcessError::InvalidReceipt {
            case_ordinal: 0,
            field: "semantic results hash",
        });
    }

    let mut bytes = Vec::with_capacity(
        X64_NATIVE_PROCESS_RESULTS_DOMAIN.len()
            + 18
            + 32
            + 4
            + receipts.len().saturating_mul(32)
            + 32,
    );
    bytes.extend_from_slice(X64_NATIVE_PROCESS_RESULTS_DOMAIN);
    put_version(&mut bytes, X64_NATIVE_PROCESS_SCHEMA_VERSION);
    put_version(&mut bytes, X64_NATIVE_PROCESS_POLICY_VERSION);
    put_version(&mut bytes, X64_NATIVE_IPC_SCHEMA_VERSION);
    bytes.extend_from_slice(&manifest.manifest_hash.0);
    put_u32(&mut bytes, count);
    for (ordinal, receipt) in receipts.iter().enumerate() {
        let expected = u32::try_from(ordinal).map_err(|_| X64NativeProcessError::MetricOverflow)?;
        validate_process_receipt(receipt, expected)?;
        bytes.extend_from_slice(&receipt.receipt_hash.0);
    }
    bytes.extend_from_slice(&semantic_results_hash.0);
    Ok(SemanticHash(sha256(&bytes)))
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn probe_x64_native_worker_debug_r1_s7bc(
    worker_path: &Path,
    case_ordinal: u32,
    mode: &str,
    timeout_millis: u64,
) -> Result<X64NativeIpcRecord, X64NativeProcessError> {
    const MODES: &[&str] = &[
        "abort",
        "abnormal",
        "timeout",
        "descendant-pipe",
        "missing",
        "malformed",
        "oversized",
        "diagnostics-one-over",
        "diagnostics-limit",
        "diagnostic-bytes-limit",
        "diagnostic-bytes-one-over",
        "record-limit",
        "trailing",
        "truncated",
        "double-frame",
        "valid-abnormal",
        "valid-abort",
        "wrong-case",
    ];
    if !MODES.contains(&mode) {
        return Err(X64NativeProcessError::InvalidDebugProbe);
    }
    require_supported_host()?;
    let case = x64_native_lighthouse_case(case_ordinal)?;
    run_worker_case(
        worker_path,
        &case,
        Duration::from_millis(timeout_millis),
        Some(mode),
    )
}

fn seal_process_evidence(
    receipts: Vec<X64NativeProcessReceipt>,
    correspondence: X64NativeCorrespondenceEvidence,
) -> Result<X64NativeProcessEvidence, X64NativeProcessError> {
    validate_process_receipts(&receipts, &correspondence.records)?;
    let manifest = corevm0_gate_a_manifest().map_err(X64NativeProcessError::CorpusManifest)?;
    let results_hash = x64_native_process_results_hash(&receipts, correspondence.results_hash)?;
    let evidence = X64NativeProcessEvidence {
        schema_version: X64_NATIVE_PROCESS_SCHEMA_VERSION,
        process_policy_version: X64_NATIVE_PROCESS_POLICY_VERSION,
        ipc_schema_version: X64_NATIVE_IPC_SCHEMA_VERSION,
        corpus_manifest_hash: manifest.manifest_hash,
        receipts,
        correspondence,
        results_hash,
    };
    verify_x64_native_process_evidence_r1_s7bc(&evidence)?;
    Ok(evidence)
}

fn seal_process_receipt(
    case: &CoreVmGateACase,
    ipc: &X64NativeIpcRecord,
) -> Result<X64NativeProcessReceipt, X64NativeProcessError> {
    verify_x64_native_ipc_record(ipc, case.ordinal)?;
    if ipc.native_execution.input_hash != case.input_hash {
        return Err(X64NativeProcessError::InvalidReceipt {
            case_ordinal: case.ordinal,
            field: "input hash",
        });
    }
    let mut receipt = X64NativeProcessReceipt {
        schema_version: X64_NATIVE_PROCESS_SCHEMA_VERSION,
        process_policy_version: X64_NATIVE_PROCESS_POLICY_VERSION,
        ipc_schema_version: X64_NATIVE_IPC_SCHEMA_VERSION,
        case_ordinal: case.ordinal,
        input_hash: case.input_hash,
        native_execution_record_hash: ipc.native_execution.record_hash,
        ipc_frame_hash: ipc.frame_hash,
        receipt_hash: SemanticHash::ZERO,
    };
    receipt.receipt_hash = process_receipt_hash(&receipt)?;
    Ok(receipt)
}

fn process_receipt_hash(
    receipt: &X64NativeProcessReceipt,
) -> Result<SemanticHash, X64NativeProcessError> {
    validate_process_receipt_shape(receipt)?;
    let mut bytes = Vec::with_capacity(X64_NATIVE_PROCESS_RECEIPT_DOMAIN.len() + 18 + 4 + 128);
    bytes.extend_from_slice(X64_NATIVE_PROCESS_RECEIPT_DOMAIN);
    put_version(&mut bytes, receipt.schema_version);
    put_version(&mut bytes, receipt.process_policy_version);
    put_version(&mut bytes, receipt.ipc_schema_version);
    put_u32(&mut bytes, receipt.case_ordinal);
    bytes.extend_from_slice(&receipt.input_hash.0);
    bytes.extend_from_slice(&receipt.native_execution_record_hash.0);
    bytes.extend_from_slice(&receipt.ipc_frame_hash.0);
    Ok(SemanticHash(sha256(&bytes)))
}

fn validate_process_receipt(
    receipt: &X64NativeProcessReceipt,
    expected_ordinal: u32,
) -> Result<(), X64NativeProcessError> {
    if receipt.case_ordinal != expected_ordinal {
        return Err(X64NativeProcessError::InvalidReceipt {
            case_ordinal: expected_ordinal,
            field: "case ordinal",
        });
    }
    validate_process_receipt_shape(receipt)?;
    let case = x64_native_lighthouse_case(expected_ordinal)?;
    if receipt.input_hash != case.input_hash {
        return Err(X64NativeProcessError::InvalidReceipt {
            case_ordinal: expected_ordinal,
            field: "canonical input hash",
        });
    }
    let actual = process_receipt_hash(receipt)?;
    if actual != receipt.receipt_hash {
        return Err(X64NativeProcessError::ReceiptHashMismatch {
            case_ordinal: expected_ordinal,
        });
    }
    Ok(())
}

fn validate_process_receipt_shape(
    receipt: &X64NativeProcessReceipt,
) -> Result<(), X64NativeProcessError> {
    if receipt.schema_version != X64_NATIVE_PROCESS_SCHEMA_VERSION
        || receipt.process_policy_version != X64_NATIVE_PROCESS_POLICY_VERSION
        || receipt.ipc_schema_version != X64_NATIVE_IPC_SCHEMA_VERSION
    {
        return Err(X64NativeProcessError::InvalidSchema);
    }
    if receipt.case_ordinal >= X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS {
        return Err(X64NativeProcessError::InvalidReceipt {
            case_ordinal: receipt.case_ordinal,
            field: "case ordinal",
        });
    }
    for (field, hash) in [
        ("input hash", receipt.input_hash),
        (
            "native execution record hash",
            receipt.native_execution_record_hash,
        ),
        ("IPC frame hash", receipt.ipc_frame_hash),
    ] {
        if hash == SemanticHash::ZERO {
            return Err(X64NativeProcessError::InvalidReceipt {
                case_ordinal: receipt.case_ordinal,
                field,
            });
        }
    }
    Ok(())
}

fn validate_process_receipts(
    receipts: &[X64NativeProcessReceipt],
    correspondence: &[X64NativeCorrespondenceRecord],
) -> Result<(), X64NativeProcessError> {
    let receipt_count =
        u32::try_from(receipts.len()).map_err(|_| X64NativeProcessError::MetricOverflow)?;
    let correspondence_count =
        u32::try_from(correspondence.len()).map_err(|_| X64NativeProcessError::MetricOverflow)?;
    if receipt_count != X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS {
        return Err(X64NativeProcessError::FixedCorpusCount {
            expected: X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS,
            actual: receipt_count,
        });
    }
    if correspondence_count != receipt_count {
        return Err(X64NativeProcessError::FixedCorpusCount {
            expected: receipt_count,
            actual: correspondence_count,
        });
    }
    let manifest = corevm0_gate_a_manifest().map_err(X64NativeProcessError::CorpusManifest)?;
    for (ordinal, ((receipt, record), case)) in receipts
        .iter()
        .zip(correspondence)
        .zip(&manifest.cases)
        .enumerate()
    {
        let ordinal = u32::try_from(ordinal).map_err(|_| X64NativeProcessError::MetricOverflow)?;
        validate_process_receipt(receipt, ordinal)?;
        validate_process_receipt_binding(receipt, record, case, ordinal)?;
    }
    Ok(())
}

fn validate_process_receipt_binding(
    receipt: &X64NativeProcessReceipt,
    record: &X64NativeCorrespondenceRecord,
    case: &CoreVmGateACase,
    ordinal: u32,
) -> Result<(), X64NativeProcessError> {
    if case.ordinal != ordinal
        || receipt.input_hash != case.input_hash
        || receipt.native_execution_record_hash != record.native_execution.record_hash
        || receipt.input_hash != record.input_hash
    {
        return Err(X64NativeProcessError::InvalidReceipt {
            case_ordinal: ordinal,
            field: "correspondence binding",
        });
    }
    let canonical_ipc = seal_x64_native_ipc_record(ordinal, record.native_execution.clone())?;
    if receipt.ipc_frame_hash != canonical_ipc.frame_hash {
        return Err(X64NativeProcessError::InvalidReceipt {
            case_ordinal: ordinal,
            field: "IPC frame binding",
        });
    }
    Ok(())
}

fn run_worker_case(
    worker_path: &Path,
    case: &CoreVmGateACase,
    timeout: Duration,
    debug_probe: Option<&str>,
) -> Result<X64NativeIpcRecord, X64NativeProcessError> {
    let frame = run_x64_worker_frame_bounded(
        worker_path,
        case.ordinal,
        timeout,
        "NAUX_S7B_WORKER_DEBUG_PROBE",
        debug_probe,
        u64::from(X64_NATIVE_MAX_RECORD_BYTES),
    )?;
    Ok(decode_x64_native_ipc_record(&frame, case.ordinal)?)
}

/// Shared reviewed child-process lifecycle for fixed NAUX native workers.
/// Protocol owners retain their own strict decoders and identity checks.
pub(crate) fn run_x64_worker_frame_bounded(
    worker_path: &Path,
    case_ordinal: u32,
    timeout: Duration,
    debug_environment: &'static str,
    debug_probe: Option<&str>,
    max_record_bytes: u64,
) -> Result<Vec<u8>, X64NativeProcessError> {
    let mut command = Command::new(worker_path);
    command
        .arg(case_ordinal.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(mode) = debug_probe {
        command.env(debug_environment, mode);
    } else {
        command.env_remove(debug_environment);
    }
    configure_worker_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| X64NativeProcessError::Spawn {
            case_ordinal,
            kind: error.kind(),
        })?;
    let Some(stdout) = child.stdout.take() else {
        terminate_and_reap_bounded(&mut child);
        return Err(X64NativeProcessError::MissingPipe {
            case_ordinal,
            stream: "stdout",
        });
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_and_reap_bounded(&mut child);
        return Err(X64NativeProcessError::MissingPipe {
            case_ordinal,
            stream: "stderr",
        });
    };
    let stdout_reader =
        spawn_pipe_reader(stdout, max_record_bytes, false, "stdout").map_err(|error| {
            terminate_and_reap_bounded(&mut child);
            X64NativeProcessError::PipeReaderSpawn {
                case_ordinal,
                stream: "stdout",
                kind: error.kind(),
            }
        })?;
    let stderr_reader = match spawn_pipe_reader(
        stderr,
        X64_NATIVE_PROCESS_MAX_DIAGNOSTIC_BYTES,
        true,
        "stderr",
    ) {
        Ok(reader) => reader,
        Err(error) => {
            terminate_and_reap_bounded(&mut child);
            let _ = join_pipe_reader_bounded(stdout_reader, case_ordinal, "stdout");
            return Err(X64NativeProcessError::PipeReaderSpawn {
                case_ordinal,
                stream: "stderr",
                kind: error.kind(),
            });
        }
    };

    let status = wait_for_child(&mut child, case_ordinal, timeout);
    let stdout = join_pipe_reader_bounded(stdout_reader, case_ordinal, "stdout");
    let stderr = join_pipe_reader_bounded(stderr_reader, case_ordinal, "stderr");
    let status = status?;
    let stdout = stdout?;
    let stderr = stderr?;
    validate_child_status(case_ordinal, status)?;
    validate_capture(case_ordinal, "stdout", &stdout)?;
    validate_capture(case_ordinal, "stderr", &stderr)?;
    if stderr.total_bytes > X64_NATIVE_PROCESS_MAX_DIAGNOSTIC_BYTES {
        return Err(X64NativeProcessError::DiagnosticByteLimit {
            case_ordinal,
            limit: X64_NATIVE_PROCESS_MAX_DIAGNOSTIC_BYTES,
            actual: stderr.total_bytes,
        });
    }
    if stderr.diagnostics > X64_NATIVE_MAX_DIAGNOSTICS {
        return Err(X64NativeProcessError::DiagnosticLimit {
            case_ordinal,
            limit: X64_NATIVE_MAX_DIAGNOSTICS,
            actual: stderr.diagnostics,
        });
    }
    if stderr.total_bytes != 0 {
        return Err(X64NativeProcessError::UnexpectedDiagnostics {
            case_ordinal,
            actual: stderr.diagnostics,
        });
    }
    if stdout.total_bytes == 0 {
        return Err(X64NativeProcessError::MissingRecord { case_ordinal });
    }
    if stdout.total_bytes > max_record_bytes {
        return Err(X64NativeProcessError::RecordByteLimit {
            case_ordinal,
            limit: max_record_bytes,
            actual: stdout.total_bytes,
        });
    }
    Ok(stdout.bytes)
}

fn wait_for_child(
    child: &mut Child,
    case_ordinal: u32,
    timeout: Duration,
) -> Result<ExitStatus, X64NativeProcessError> {
    let started = Instant::now();
    loop {
        match observe_child_exit_without_reaping(child.id()) {
            Ok(true) => {
                let kill_result = terminate_worker_process_group(child.id());
                let reap_result = reap_child_bounded(child, PROCESS_REAP_TIMEOUT);
                kill_result.map_err(|error| X64NativeProcessError::Kill {
                    case_ordinal,
                    kind: error.kind(),
                })?;
                return reap_result.map_err(|error| X64NativeProcessError::Wait {
                    case_ordinal,
                    kind: error.kind(),
                });
            }
            Ok(false) if started.elapsed() < timeout => thread::sleep(POLL_INTERVAL),
            Ok(false) => {
                let kill_result = terminate_worker_process_group(child.id());
                let reap_result = reap_child_bounded(child, PROCESS_REAP_TIMEOUT);
                kill_result.map_err(|error| X64NativeProcessError::Kill {
                    case_ordinal,
                    kind: error.kind(),
                })?;
                reap_result.map_err(|error| X64NativeProcessError::Wait {
                    case_ordinal,
                    kind: error.kind(),
                })?;
                let timeout_millis = u64::try_from(timeout.as_millis())
                    .map_err(|_| X64NativeProcessError::MetricOverflow)?;
                return Err(X64NativeProcessError::NativeTimeout {
                    case_ordinal,
                    timeout_millis,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                // ECHILD means another reaper or SIGCHLD policy may already
                // have released the numeric PID. Do not risk targeting a
                // newly reused process group in that case.
                const LINUX_ECHILD: i32 = 10;
                if error.raw_os_error() != Some(LINUX_ECHILD) {
                    terminate_and_reap_bounded(child);
                }
                return Err(X64NativeProcessError::Wait {
                    case_ordinal,
                    kind: error.kind(),
                });
            }
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn observe_child_exit_without_reaping(process_id: u32) -> Result<bool, io::Error> {
    const LINUX_X86_64_WAITID_SYSCALL: i64 = 247;
    const P_PID: i64 = 1;
    const WNOHANG: i64 = 0x0000_0001;
    const WEXITED: i64 = 0x0000_0004;
    const WNOWAIT: i64 = 0x0100_0000;
    const SIGINFO_BYTES: usize = 128;
    const SIGINFO_PID_OFFSET: usize = 16;

    let process_id = i32::try_from(process_id).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "R1-S7b-c child id exceeds Linux pid_t",
        )
    })?;
    #[repr(C, align(8))]
    struct LinuxSigInfo {
        bytes: [u8; SIGINFO_BYTES],
    }
    let mut signal_info = LinuxSigInfo {
        bytes: [0; SIGINFO_BYTES],
    };
    let mut result = LINUX_X86_64_WAITID_SYSCALL;
    // SAFETY: Linux x86-64 syscall 247 receives P_PID, one positive pid_t,
    // a writable, correctly sized/aligned siginfo_t buffer, the documented
    // WEXITED|WNOHANG|WNOWAIT option mask, and a null rusage pointer. WNOWAIT
    // observes an exit without releasing the leader's PID/process-group
    // identity; rcx/r11 are declared clobbered as required by `syscall`.
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") result,
            in("rdi") P_PID,
            in("rsi") i64::from(process_id),
            in("rdx") signal_info.bytes.as_mut_ptr(),
            in("r10") WEXITED | WNOHANG | WNOWAIT,
            in("r8") 0_i64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if result < 0 {
        let errno = i32::try_from(result.saturating_neg()).unwrap_or(i32::MAX);
        return Err(io::Error::from_raw_os_error(errno));
    }

    let observed_pid = i32::from_ne_bytes([
        signal_info.bytes[SIGINFO_PID_OFFSET],
        signal_info.bytes[SIGINFO_PID_OFFSET + 1],
        signal_info.bytes[SIGINFO_PID_OFFSET + 2],
        signal_info.bytes[SIGINFO_PID_OFFSET + 3],
    ]);
    if observed_pid == 0 {
        return Ok(false);
    }
    if observed_pid != process_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "R1-S7b-c waitid observed a different child",
        ));
    }
    Ok(true)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn observe_child_exit_without_reaping(_process_id: u32) -> Result<bool, io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "R1-S7b-c waitid observation requires Linux x86-64",
    ))
}

fn configure_worker_process_group(command: &mut Command) {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
}

fn terminate_and_reap_bounded(child: &mut Child) {
    let _ = terminate_worker_process_group(child.id());
    let _ = reap_child_bounded(child, PROCESS_REAP_TIMEOUT);
}

fn reap_child_bounded(child: &mut Child, timeout: Duration) -> Result<ExitStatus, io::Error> {
    let started = Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) => return Ok(status),
            None if started.elapsed() < timeout => thread::sleep(POLL_INTERVAL),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "R1-S7b-c child did not terminate after group kill",
                ));
            }
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn terminate_worker_process_group(process_group_id: u32) -> Result<(), io::Error> {
    const LINUX_X86_64_KILL_SYSCALL: i64 = 62;
    const SIGKILL: i64 = 9;
    const ESRCH: i32 = 3;

    let process_group_id = i32::try_from(process_group_id).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "R1-S7b-c process-group id exceeds Linux pid_t",
        )
    })?;
    let mut result = LINUX_X86_64_KILL_SYSCALL;
    // SAFETY: Linux x86-64 syscall 62 accepts only the numeric process-group
    // id and SIGKILL value supplied here. It neither dereferences memory nor
    // aliases Rust state; rcx/r11 are declared clobbered as required by
    // `syscall`.
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") result,
            in("rdi") -i64::from(process_group_id),
            in("rsi") SIGKILL,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if result >= 0 {
        return Ok(());
    }
    let errno = i32::try_from(result.saturating_neg()).unwrap_or(i32::MAX);
    if errno == ESRCH {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(errno))
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn terminate_worker_process_group(_process_group_id: u32) -> Result<(), io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "R1-S7b-c process groups require Linux x86-64",
    ))
}

fn validate_child_status(
    case_ordinal: u32,
    status: ExitStatus,
) -> Result<(), X64NativeProcessError> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if status.signal().is_some() {
            return Err(X64NativeProcessError::NativeFault { case_ordinal });
        }
    }
    if !status.success() {
        return Err(X64NativeProcessError::AbnormalExit {
            case_ordinal,
            code: status.code(),
        });
    }
    Ok(())
}

struct PipeCapture {
    bytes: Vec<u8>,
    total_bytes: u64,
    diagnostics: u32,
    error: Option<io::ErrorKind>,
}

fn spawn_pipe_reader<R: Read + Send + 'static>(
    reader: R,
    byte_limit: u64,
    count_diagnostics: bool,
    stream: &'static str,
) -> Result<JoinHandle<PipeCapture>, io::Error> {
    thread::Builder::new()
        .name(format!("naux-s7bc-{stream}-reader"))
        .spawn(move || read_pipe_bounded(reader, byte_limit, count_diagnostics))
}

fn read_pipe_bounded(
    mut reader: impl Read,
    byte_limit: u64,
    count_diagnostics: bool,
) -> PipeCapture {
    let retained_limit = byte_limit.saturating_add(1);
    let mut capture = PipeCapture {
        bytes: Vec::new(),
        total_bytes: 0,
        diagnostics: 0,
        error: None,
    };
    let mut buffer = [0_u8; 1024];
    let mut saw_diagnostic_byte = false;
    let mut ended_with_newline = false;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                capture.error = Some(error.kind());
                break;
            }
        };
        capture.total_bytes = capture.total_bytes.saturating_add(read as u64);
        if count_diagnostics {
            saw_diagnostic_byte = true;
            for byte in &buffer[..read] {
                if *byte == b'\n' {
                    capture.diagnostics = capture.diagnostics.saturating_add(1);
                }
            }
            ended_with_newline = buffer[read - 1] == b'\n';
        }
        let retained = u64::try_from(capture.bytes.len()).unwrap_or(u64::MAX);
        if retained < retained_limit {
            let remaining = retained_limit - retained;
            let copy = usize::try_from(remaining).unwrap_or(usize::MAX).min(read);
            capture.bytes.extend_from_slice(&buffer[..copy]);
        }
    }
    if count_diagnostics && saw_diagnostic_byte && !ended_with_newline {
        capture.diagnostics = capture.diagnostics.saturating_add(1);
    }
    capture
}

fn join_pipe_reader_bounded(
    reader: JoinHandle<PipeCapture>,
    case_ordinal: u32,
    stream: &'static str,
) -> Result<PipeCapture, X64NativeProcessError> {
    let started = Instant::now();
    while !reader.is_finished() {
        if started.elapsed() >= PIPE_READER_JOIN_TIMEOUT {
            return Err(X64NativeProcessError::PipeReaderTimeout {
                case_ordinal,
                stream,
            });
        }
        thread::sleep(POLL_INTERVAL);
    }
    reader
        .join()
        .map_err(|_| X64NativeProcessError::PipeReaderPanicked {
            case_ordinal,
            stream,
        })
}

fn validate_capture(
    case_ordinal: u32,
    stream: &'static str,
    capture: &PipeCapture,
) -> Result<(), X64NativeProcessError> {
    if let Some(kind) = capture.error {
        return Err(X64NativeProcessError::PipeRead {
            case_ordinal,
            stream,
            kind,
        });
    }
    Ok(())
}

fn require_supported_host() -> Result<(), X64NativeProcessError> {
    if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        Ok(())
    } else {
        Err(X64NativeProcessError::UnsupportedHost)
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
struct ClaimMxcsrGuard {
    previous: u32,
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
impl ClaimMxcsrGuard {
    #[must_use]
    fn establish() -> Self {
        let mut previous = 0_u32;
        let canonical = 0x0000_1f80_u32;
        // SAFETY: both operands point to valid u32 storage. `stmxcsr` saves
        // the caller state before `ldmxcsr` installs the architecturally
        // admitted canonical claim state on this thread.
        unsafe {
            std::arch::asm!(
                "stmxcsr [{pointer}]",
                pointer = in(reg) &mut previous,
                options(nostack, preserves_flags),
            );
            std::arch::asm!(
                "ldmxcsr [{pointer}]",
                pointer = in(reg) &canonical,
                options(nostack, preserves_flags),
            );
        }
        Self { previous }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
impl Drop for ClaimMxcsrGuard {
    fn drop(&mut self) {
        // SAFETY: `previous` came from `stmxcsr` on this same thread and is
        // therefore an architecturally valid MXCSR value.
        unsafe {
            std::arch::asm!(
                "ldmxcsr [{pointer}]",
                pointer = in(reg) &self.previous,
                options(nostack, preserves_flags),
            );
        }
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
struct ClaimMxcsrGuard;

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
impl ClaimMxcsrGuard {
    #[must_use]
    fn establish() -> Self {
        Self
    }
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_be_bytes());
    bytes.extend_from_slice(&version.1.to_be_bytes());
    bytes.extend_from_slice(&version.2.to_be_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_receipts() -> Vec<X64NativeProcessReceipt> {
        let manifest = corevm0_gate_a_manifest().expect("fixed manifest must regenerate");
        manifest
            .cases
            .iter()
            .map(|case| {
                let byte = u8::try_from(case.ordinal + 1).expect("ordinal is at most 50");
                let mut receipt = X64NativeProcessReceipt {
                    schema_version: X64_NATIVE_PROCESS_SCHEMA_VERSION,
                    process_policy_version: X64_NATIVE_PROCESS_POLICY_VERSION,
                    ipc_schema_version: X64_NATIVE_IPC_SCHEMA_VERSION,
                    case_ordinal: case.ordinal,
                    input_hash: case.input_hash,
                    native_execution_record_hash: SemanticHash([byte; 32]),
                    ipc_frame_hash: SemanticHash([byte.wrapping_add(64); 32]),
                    receipt_hash: SemanticHash::ZERO,
                };
                receipt.receipt_hash =
                    process_receipt_hash(&receipt).expect("synthetic receipt must seal");
                receipt
            })
            .collect()
    }

    #[test]
    fn receipt_results_are_order_sensitive_and_fail_closed() {
        let receipts = synthetic_receipts();
        let semantic_results_hash = SemanticHash([0xa5; 32]);
        let expected = x64_native_process_results_hash(&receipts, semantic_results_hash)
            .expect("fixed synthetic receipt vector must hash");
        assert_eq!(
            x64_native_process_results_hash(&receipts, semantic_results_hash)
                .expect("same vector must be deterministic"),
            expected
        );

        let mut omitted = receipts.clone();
        omitted.pop();
        assert!(matches!(
            x64_native_process_results_hash(&omitted, semantic_results_hash),
            Err(X64NativeProcessError::FixedCorpusCount {
                expected: 51,
                actual: 50
            })
        ));

        let mut reordered = receipts.clone();
        reordered.swap(0, 1);
        assert!(matches!(
            x64_native_process_results_hash(&reordered, semantic_results_hash),
            Err(X64NativeProcessError::InvalidReceipt {
                case_ordinal: 0,
                field: "case ordinal"
            })
        ));

        let mut wrong_input = receipts.clone();
        wrong_input[0].input_hash = receipts[1].input_hash;
        wrong_input[0].receipt_hash =
            process_receipt_hash(&wrong_input[0]).expect("local mutation can reseal");
        assert!(matches!(
            x64_native_process_results_hash(&wrong_input, semantic_results_hash),
            Err(X64NativeProcessError::InvalidReceipt {
                case_ordinal: 0,
                field: "canonical input hash"
            })
        ));

        let mut broken_seal = receipts;
        broken_seal[0].receipt_hash = SemanticHash::ZERO;
        assert!(matches!(
            x64_native_process_results_hash(&broken_seal, semantic_results_hash),
            Err(X64NativeProcessError::ReceiptHashMismatch { case_ordinal: 0 })
        ));
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    #[test]
    fn claim_mxcsr_guard_restores_the_calling_thread() {
        fn current_mxcsr() -> u32 {
            let mut value = 0_u32;
            // SAFETY: `value` is valid writable u32 storage for `stmxcsr`.
            unsafe {
                std::arch::asm!(
                    "stmxcsr [{pointer}]",
                    pointer = in(reg) &mut value,
                    options(nostack, preserves_flags),
                );
            }
            value
        }

        fn install_mxcsr(value: u32) {
            // SAFETY: `value` is derived from a prior `stmxcsr` result with
            // only the architecturally defined rounding-control bits changed.
            unsafe {
                std::arch::asm!(
                    "ldmxcsr [{pointer}]",
                    pointer = in(reg) &value,
                    options(nostack, preserves_flags),
                );
            }
        }

        let original = current_mxcsr();
        let altered_rounding = if original & 0x0000_6000 == 0x0000_6000 {
            0
        } else {
            0x0000_6000
        };
        let altered = (original & !0x0000_6000) | altered_rounding;
        assert_ne!(altered, original);
        install_mxcsr(altered);
        {
            let _guard = ClaimMxcsrGuard::establish();
            assert_eq!(current_mxcsr(), 0x0000_1f80);
        }
        assert_eq!(current_mxcsr(), altered);
        install_mxcsr(original);
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    #[test]
    fn receipt_rejects_a_locally_resealed_noncanonical_ipc_identity() {
        let case = x64_native_lighthouse_case(0).expect("case zero must be canonical");
        let package = X64NativeLighthousePackage::build(case.workload)
            .expect("case-zero package must regenerate");
        let target = package
            .source_bound()
            .expect("case-zero target must replay");
        let machine_ir = package
            .evaluate_machine_ir_case(&case)
            .expect("case-zero Machine IR must evaluate");
        let _mxcsr_guard = ClaimMxcsrGuard::establish();
        let execution = execute_x64_native_case_r1_s7b(target, &case)
            .expect("case-zero native execution must complete");
        let native_execution = seal_x64_native_execution_record(target, &execution)
            .expect("case-zero native execution must seal");
        let ipc = seal_x64_native_ipc_record(case.ordinal, native_execution.clone())
            .expect("case-zero IPC record must seal");
        let mut receipt =
            seal_process_receipt(&case, &ipc).expect("case-zero process receipt must seal");
        let correspondence =
            seal_x64_native_correspondence_record(&case, target, &machine_ir, native_execution)
                .expect("case-zero correspondence must seal");

        validate_process_receipt_binding(&receipt, &correspondence, &case, case.ordinal)
            .expect("the original receipt must bind to its canonical IPC frame");

        receipt.ipc_frame_hash.0[0] ^= 1;
        receipt.receipt_hash =
            process_receipt_hash(&receipt).expect("the locally mutated receipt can reseal");
        assert!(matches!(
            validate_process_receipt_binding(&receipt, &correspondence, &case, case.ordinal),
            Err(X64NativeProcessError::InvalidReceipt {
                case_ordinal: 0,
                field: "IPC frame binding"
            })
        ));
    }

    #[test]
    fn pipe_capture_enforces_exact_diagnostic_and_byte_boundaries() {
        let at_diagnostic_limit = (0..X64_NATIVE_MAX_DIAGNOSTICS)
            .flat_map(|_| b"d\n")
            .copied()
            .collect::<Vec<_>>();
        let capture = read_pipe_bounded(
            at_diagnostic_limit.as_slice(),
            X64_NATIVE_PROCESS_MAX_DIAGNOSTIC_BYTES,
            true,
        );
        assert_eq!(capture.diagnostics, X64_NATIVE_MAX_DIAGNOSTICS);
        assert_eq!(capture.total_bytes, at_diagnostic_limit.len() as u64);

        let at_diagnostic_byte_limit = vec![b'd'; X64_NATIVE_PROCESS_MAX_DIAGNOSTIC_BYTES as usize];
        let capture = read_pipe_bounded(
            at_diagnostic_byte_limit.as_slice(),
            X64_NATIVE_PROCESS_MAX_DIAGNOSTIC_BYTES,
            true,
        );
        assert_eq!(capture.total_bytes, X64_NATIVE_PROCESS_MAX_DIAGNOSTIC_BYTES);
        assert_eq!(
            capture.bytes.len(),
            X64_NATIVE_PROCESS_MAX_DIAGNOSTIC_BYTES as usize
        );

        let one_over_diagnostic_byte_limit = [at_diagnostic_byte_limit, vec![b'd']].concat();
        let capture = read_pipe_bounded(
            one_over_diagnostic_byte_limit.as_slice(),
            X64_NATIVE_PROCESS_MAX_DIAGNOSTIC_BYTES,
            true,
        );
        assert_eq!(
            capture.total_bytes,
            X64_NATIVE_PROCESS_MAX_DIAGNOSTIC_BYTES + 1
        );
        assert_eq!(
            capture.bytes.len(),
            X64_NATIVE_PROCESS_MAX_DIAGNOSTIC_BYTES as usize + 1
        );

        let one_over = [vec![b'x'; X64_NATIVE_MAX_RECORD_BYTES as usize], vec![b'y']].concat();
        let capture = read_pipe_bounded(
            one_over.as_slice(),
            u64::from(X64_NATIVE_MAX_RECORD_BYTES),
            false,
        );
        assert_eq!(
            capture.total_bytes,
            u64::from(X64_NATIVE_MAX_RECORD_BYTES) + 1
        );
        assert_eq!(
            capture.bytes.len(),
            X64_NATIVE_MAX_RECORD_BYTES as usize + 1
        );
    }
}
