//! Fresh-child correspondence evidence for the exact ADR-0052 candidate.
//!
//! Aggregate authority requires an opaque verified ADR-0052 witness. The
//! worker path is an explicit reviewed trust anchor, not binary attestation.

use super::corevm0_gate_a::{corevm0_gate_a_manifest, CoreVmGateAError, CoreVmGateAWorkload};
use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_gate_b_candidate_admission::{
    emit_x64_gate_b_policy15_candidate_process_record,
    x64_gate_b_policy15_candidate_accepted_correctness_results_hash,
    VerifiedX64GateBPolicy15CandidateCorrectness, X64GateBPolicy15CandidateCorrectnessError,
    X64GateBPolicy15CandidateCorrectnessRecord, X64GateBPolicy15CandidateSelection,
    X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_CASES, X64_GATE_B_POLICY15_CANDIDATE_EXECUTION_CASES,
    X64_GATE_B_POLICY15_CANDIDATE_FALLBACK_CASES,
};
use super::x64_gate_b_candidate_ipc::{
    decode_x64_gate_b_policy15_candidate_ipc_record,
    encode_x64_gate_b_policy15_candidate_ipc_record, seal_x64_gate_b_policy15_candidate_ipc_record,
    X64GateBPolicy15CandidateIpcError, X64GateBPolicy15CandidateIpcRecord,
    X64_GATE_B_POLICY15_CANDIDATE_IPC_MAX_FRAME_BYTES,
    X64_GATE_B_POLICY15_CANDIDATE_IPC_SCHEMA_VERSION,
    X64_GATE_B_POLICY15_CANDIDATE_PROCESS_POLICY_VERSION,
};
use super::x64_native_process::{
    run_x64_worker_frame_bounded, X64NativeProcessError, X64_NATIVE_PROCESS_TIMEOUT_MILLIS,
};
use super::x64_target::x64_target_policy15_accepted_candidate_capsule_hash;
use std::fmt;
use std::path::Path;
use std::time::Duration;

pub const X64_GATE_B_POLICY15_CANDIDATE_PROCESS_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);

const RECEIPT_DOMAIN: &[u8] = b"NAUX:x86-64:policy-1.5:candidate-process:receipt:v1\0";
const RESULTS_DOMAIN: &[u8] = b"NAUX:x86-64:policy-1.5:candidate-process:results:v1\0";
const DEBUG_ENVIRONMENT: &str = "NAUX_POLICY15_CANDIDATE_WORKER_DEBUG_PROBE";
const FROZEN_PROCESS_RESULTS_HASH: SemanticHash = SemanticHash([
    0x88, 0x72, 0x74, 0xdd, 0x8e, 0x5e, 0x5f, 0x08, 0x9c, 0xba, 0x60, 0xee, 0x51, 0x3e, 0x61, 0x58,
    0x0c, 0xb1, 0xd6, 0xcf, 0xe1, 0x3a, 0x7c, 0x94, 0xff, 0x93, 0x6a, 0xa4, 0x8d, 0x5b, 0x53, 0x65,
]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64GateBPolicy15CandidateProcessReceipt {
    schema_version: (u16, u16, u16),
    process_policy_version: (u16, u16, u16),
    ipc_schema_version: (u16, u16, u16),
    case_ordinal: u32,
    workload: CoreVmGateAWorkload,
    selection: X64GateBPolicy15CandidateSelection,
    input_hash: SemanticHash,
    candidate_capsule_hash: SemanticHash,
    correctness_results_hash: SemanticHash,
    correctness_record_hash: SemanticHash,
    ipc_frame_hash: SemanticHash,
    receipt_hash: SemanticHash,
}

impl X64GateBPolicy15CandidateProcessReceipt {
    pub const fn case_ordinal(&self) -> u32 {
        self.case_ordinal
    }

    pub const fn workload(&self) -> CoreVmGateAWorkload {
        self.workload
    }

    pub const fn selection(&self) -> X64GateBPolicy15CandidateSelection {
        self.selection
    }

    pub const fn input_hash(&self) -> SemanticHash {
        self.input_hash
    }

    pub const fn correctness_record_hash(&self) -> SemanticHash {
        self.correctness_record_hash
    }

    pub const fn ipc_frame_hash(&self) -> SemanticHash {
        self.ipc_frame_hash
    }

    pub const fn receipt_hash(&self) -> SemanticHash {
        self.receipt_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64GateBPolicy15CandidateProcessEvidence {
    schema_version: (u16, u16, u16),
    process_policy_version: (u16, u16, u16),
    ipc_schema_version: (u16, u16, u16),
    corpus_manifest_hash: SemanticHash,
    candidate_capsule_hash: SemanticHash,
    correctness_results_hash: SemanticHash,
    candidate_execution_cases: u32,
    fallback_cases: u32,
    receipts: Vec<X64GateBPolicy15CandidateProcessReceipt>,
    results_hash: SemanticHash,
}

impl X64GateBPolicy15CandidateProcessEvidence {
    pub const fn corpus_manifest_hash(&self) -> SemanticHash {
        self.corpus_manifest_hash
    }

    pub const fn candidate_capsule_hash(&self) -> SemanticHash {
        self.candidate_capsule_hash
    }

    pub const fn correctness_results_hash(&self) -> SemanticHash {
        self.correctness_results_hash
    }

    pub const fn candidate_execution_cases(&self) -> u32 {
        self.candidate_execution_cases
    }

    pub const fn fallback_cases(&self) -> u32 {
        self.fallback_cases
    }

    pub fn receipts(&self) -> &[X64GateBPolicy15CandidateProcessReceipt] {
        &self.receipts
    }

    pub const fn results_hash(&self) -> SemanticHash {
        self.results_hash
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedX64GateBPolicy15CandidateProcess<'evidence> {
    evidence: &'evidence X64GateBPolicy15CandidateProcessEvidence,
}

impl<'evidence> VerifiedX64GateBPolicy15CandidateProcess<'evidence> {
    pub const fn evidence(self) -> &'evidence X64GateBPolicy15CandidateProcessEvidence {
        self.evidence
    }
}

#[derive(Debug)]
pub enum X64GateBPolicy15CandidateProcessError {
    Corpus(CoreVmGateAError),
    Correctness(X64GateBPolicy15CandidateCorrectnessError),
    Ipc(X64GateBPolicy15CandidateIpcError),
    Process(X64NativeProcessError),
    InvalidField {
        case_ordinal: u32,
        field: &'static str,
    },
    NonCanonicalOrdinal {
        expected: u32,
        actual: u32,
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

impl fmt::Display for X64GateBPolicy15CandidateProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corpus(error) => write!(formatter, "candidate process corpus failed: {error}"),
            Self::Correctness(error) => {
                write!(formatter, "candidate process record failed: {error}")
            }
            Self::Ipc(error) => write!(formatter, "{error}"),
            Self::Process(error) => write!(formatter, "{error}"),
            Self::InvalidField {
                case_ordinal,
                field,
            } => write!(
                formatter,
                "candidate process case {case_ordinal} has invalid {field}"
            ),
            Self::NonCanonicalOrdinal { expected, actual } => write!(
                formatter,
                "candidate process expected case {expected}, found {actual}"
            ),
            Self::FixedCorpusCount { expected, actual } => write!(
                formatter,
                "candidate process requires {expected} cases, found {actual}"
            ),
            Self::ReceiptHashMismatch { case_ordinal } => write!(
                formatter,
                "candidate process receipt {case_ordinal} has invalid seal"
            ),
            Self::ResultsHashMismatch => {
                formatter.write_str("candidate process aggregate seal is invalid")
            }
            Self::MetricOverflow => formatter.write_str("candidate process metric overflow"),
            Self::InvalidDebugProbe => formatter.write_str("unknown candidate worker debug probe"),
        }
    }
}

impl std::error::Error for X64GateBPolicy15CandidateProcessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Corpus(error) => Some(error),
            Self::Correctness(error) => Some(error),
            Self::Ipc(error) => Some(error),
            Self::Process(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CoreVmGateAError> for X64GateBPolicy15CandidateProcessError {
    fn from(value: CoreVmGateAError) -> Self {
        Self::Corpus(value)
    }
}

impl From<X64GateBPolicy15CandidateCorrectnessError> for X64GateBPolicy15CandidateProcessError {
    fn from(value: X64GateBPolicy15CandidateCorrectnessError) -> Self {
        Self::Correctness(value)
    }
}

impl From<X64GateBPolicy15CandidateIpcError> for X64GateBPolicy15CandidateProcessError {
    fn from(value: X64GateBPolicy15CandidateIpcError) -> Self {
        Self::Ipc(value)
    }
}

impl From<X64NativeProcessError> for X64GateBPolicy15CandidateProcessError {
    fn from(value: X64NativeProcessError) -> Self {
        Self::Process(value)
    }
}

/// Child entry: reconstruct, execute, seal one correctness record, and emit
/// exactly one canonical fixed-width frame.
#[doc(hidden)]
pub fn emit_x64_gate_b_policy15_candidate_worker_frame(
    case_ordinal: u32,
) -> Result<Vec<u8>, X64GateBPolicy15CandidateProcessError> {
    let correctness = emit_x64_gate_b_policy15_candidate_process_record(case_ordinal)?;
    let ipc = seal_x64_gate_b_policy15_candidate_ipc_record(&correctness)?;
    Ok(encode_x64_gate_b_policy15_candidate_ipc_record(&ipc)?)
}

/// Run the exact 51-case fresh-child gate. The witness proves that the parent
/// already replayed ADR-0052; no raw evidence or candidate bytes are accepted.
pub fn emit_x64_gate_b_policy15_candidate_process_evidence(
    worker_path: &Path,
    correctness: VerifiedX64GateBPolicy15CandidateCorrectness<'_>,
) -> Result<X64GateBPolicy15CandidateProcessEvidence, X64GateBPolicy15CandidateProcessError> {
    let expected = correctness.evidence();
    validate_correctness_root(expected)?;
    let mut receipts = Vec::with_capacity(expected.records().len());
    for record in expected.records() {
        let frame = run_x64_worker_frame_bounded(
            worker_path,
            record.case_ordinal(),
            Duration::from_millis(X64_NATIVE_PROCESS_TIMEOUT_MILLIS),
            DEBUG_ENVIRONMENT,
            None,
            X64_GATE_B_POLICY15_CANDIDATE_IPC_MAX_FRAME_BYTES,
        )?;
        let ipc = decode_x64_gate_b_policy15_candidate_ipc_record(&frame, record.case_ordinal())?;
        receipts.push(seal_receipt(&ipc, record)?);
    }
    seal_process_evidence(receipts, expected)
}

/// Structural verification against a previously verified ADR-0052 witness.
pub fn verify_x64_gate_b_policy15_candidate_process_evidence<'evidence>(
    correctness: VerifiedX64GateBPolicy15CandidateCorrectness<'_>,
    evidence: &'evidence X64GateBPolicy15CandidateProcessEvidence,
) -> Result<
    VerifiedX64GateBPolicy15CandidateProcess<'evidence>,
    X64GateBPolicy15CandidateProcessError,
> {
    verify_process_evidence_against_records(evidence, correctness.evidence())?;
    Ok(VerifiedX64GateBPolicy15CandidateProcess { evidence })
}

/// Diagnostic one-case process execution. It grants no aggregate authority;
/// the expected record is independently reconstructed in the parent.
pub fn execute_x64_gate_b_policy15_candidate_worker_case(
    worker_path: &Path,
    case_ordinal: u32,
) -> Result<X64GateBPolicy15CandidateIpcRecord, X64GateBPolicy15CandidateProcessError> {
    let frame = run_x64_worker_frame_bounded(
        worker_path,
        case_ordinal,
        Duration::from_millis(X64_NATIVE_PROCESS_TIMEOUT_MILLIS),
        DEBUG_ENVIRONMENT,
        None,
        X64_GATE_B_POLICY15_CANDIDATE_IPC_MAX_FRAME_BYTES,
    )?;
    let ipc = decode_x64_gate_b_policy15_candidate_ipc_record(&frame, case_ordinal)?;
    let expected = emit_x64_gate_b_policy15_candidate_process_record(case_ordinal)?;
    bind_ipc_to_correctness(&ipc, &expected)?;
    Ok(ipc)
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn probe_x64_gate_b_policy15_candidate_worker_debug(
    worker_path: &Path,
    case_ordinal: u32,
    mode: &str,
    timeout_millis: u64,
) -> Result<X64GateBPolicy15CandidateIpcRecord, X64GateBPolicy15CandidateProcessError> {
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
        "trailing",
        "truncated",
        "double-frame",
        "valid-abnormal",
        "valid-abort",
        "wrong-case",
    ];
    if !MODES.contains(&mode) {
        return Err(X64GateBPolicy15CandidateProcessError::InvalidDebugProbe);
    }
    let frame = run_x64_worker_frame_bounded(
        worker_path,
        case_ordinal,
        Duration::from_millis(timeout_millis),
        DEBUG_ENVIRONMENT,
        Some(mode),
        X64_GATE_B_POLICY15_CANDIDATE_IPC_MAX_FRAME_BYTES,
    )?;
    let ipc = decode_x64_gate_b_policy15_candidate_ipc_record(&frame, case_ordinal)?;
    let expected = emit_x64_gate_b_policy15_candidate_process_record(case_ordinal)?;
    bind_ipc_to_correctness(&ipc, &expected)?;
    Ok(ipc)
}

fn validate_correctness_root(
    correctness: &super::x64_gate_b_candidate_admission::X64GateBPolicy15CandidateCorrectnessEvidence,
) -> Result<(), X64GateBPolicy15CandidateProcessError> {
    if correctness.results_hash()
        != x64_gate_b_policy15_candidate_accepted_correctness_results_hash()
        || correctness.candidate_capsule_hash()
            != x64_target_policy15_accepted_candidate_capsule_hash()
    {
        return Err(X64GateBPolicy15CandidateProcessError::InvalidField {
            case_ordinal: 0,
            field: "accepted correctness root",
        });
    }
    Ok(())
}

fn bind_ipc_to_correctness(
    ipc: &X64GateBPolicy15CandidateIpcRecord,
    expected: &X64GateBPolicy15CandidateCorrectnessRecord,
) -> Result<(), X64GateBPolicy15CandidateProcessError> {
    if ipc.case_ordinal() != expected.case_ordinal()
        || ipc.workload() != expected.workload()
        || ipc.selection() != expected.selection()
        || ipc.input_hash() != expected.input_hash()
        || ipc.candidate_capsule_hash() != expected.candidate_capsule_hash()
        || ipc.correctness_results_hash()
            != x64_gate_b_policy15_candidate_accepted_correctness_results_hash()
        || ipc.correctness_record_hash() != expected.record_hash()
    {
        return Err(X64GateBPolicy15CandidateProcessError::InvalidField {
            case_ordinal: expected.case_ordinal(),
            field: "ADR-0052 record binding",
        });
    }
    Ok(())
}

fn seal_receipt(
    ipc: &X64GateBPolicy15CandidateIpcRecord,
    expected: &X64GateBPolicy15CandidateCorrectnessRecord,
) -> Result<X64GateBPolicy15CandidateProcessReceipt, X64GateBPolicy15CandidateProcessError> {
    bind_ipc_to_correctness(ipc, expected)?;
    let mut receipt = X64GateBPolicy15CandidateProcessReceipt {
        schema_version: X64_GATE_B_POLICY15_CANDIDATE_PROCESS_SCHEMA_VERSION,
        process_policy_version: X64_GATE_B_POLICY15_CANDIDATE_PROCESS_POLICY_VERSION,
        ipc_schema_version: X64_GATE_B_POLICY15_CANDIDATE_IPC_SCHEMA_VERSION,
        case_ordinal: ipc.case_ordinal(),
        workload: ipc.workload(),
        selection: ipc.selection(),
        input_hash: ipc.input_hash(),
        candidate_capsule_hash: ipc.candidate_capsule_hash(),
        correctness_results_hash: ipc.correctness_results_hash(),
        correctness_record_hash: ipc.correctness_record_hash(),
        ipc_frame_hash: ipc.frame_hash(),
        receipt_hash: SemanticHash::ZERO,
    };
    receipt.receipt_hash = receipt_hash(&receipt)?;
    Ok(receipt)
}

fn seal_process_evidence(
    receipts: Vec<X64GateBPolicy15CandidateProcessReceipt>,
    correctness: &super::x64_gate_b_candidate_admission::X64GateBPolicy15CandidateCorrectnessEvidence,
) -> Result<X64GateBPolicy15CandidateProcessEvidence, X64GateBPolicy15CandidateProcessError> {
    let manifest = corevm0_gate_a_manifest()?;
    let mut evidence = X64GateBPolicy15CandidateProcessEvidence {
        schema_version: X64_GATE_B_POLICY15_CANDIDATE_PROCESS_SCHEMA_VERSION,
        process_policy_version: X64_GATE_B_POLICY15_CANDIDATE_PROCESS_POLICY_VERSION,
        ipc_schema_version: X64_GATE_B_POLICY15_CANDIDATE_IPC_SCHEMA_VERSION,
        corpus_manifest_hash: manifest.manifest_hash,
        candidate_capsule_hash: correctness.candidate_capsule_hash(),
        correctness_results_hash: correctness.results_hash(),
        candidate_execution_cases: correctness.candidate_execution_cases(),
        fallback_cases: correctness.fallback_cases(),
        receipts,
        results_hash: SemanticHash::ZERO,
    };
    evidence.results_hash = process_results_hash(&evidence)?;
    verify_process_evidence_against_records(&evidence, correctness)?;
    Ok(evidence)
}

#[cfg(test)]
pub(super) fn emit_synthetic_candidate_process_evidence_for_tests(
    correctness: VerifiedX64GateBPolicy15CandidateCorrectness<'_>,
) -> Result<X64GateBPolicy15CandidateProcessEvidence, X64GateBPolicy15CandidateProcessError> {
    let receipts = correctness
        .evidence()
        .records()
        .iter()
        .map(|record| {
            let ipc = seal_x64_gate_b_policy15_candidate_ipc_record(record)?;
            seal_receipt(&ipc, record)
        })
        .collect::<Result<Vec<_>, X64GateBPolicy15CandidateProcessError>>()?;
    seal_process_evidence(receipts, correctness.evidence())
}

fn verify_process_evidence_against_records(
    evidence: &X64GateBPolicy15CandidateProcessEvidence,
    correctness: &super::x64_gate_b_candidate_admission::X64GateBPolicy15CandidateCorrectnessEvidence,
) -> Result<(), X64GateBPolicy15CandidateProcessError> {
    validate_correctness_root(correctness)?;
    validate_evidence_envelope(evidence)?;
    if evidence.corpus_manifest_hash != correctness.corpus_manifest_hash()
        || evidence.candidate_capsule_hash != correctness.candidate_capsule_hash()
        || evidence.correctness_results_hash != correctness.results_hash()
        || evidence.candidate_execution_cases != correctness.candidate_execution_cases()
        || evidence.fallback_cases != correctness.fallback_cases()
    {
        return Err(X64GateBPolicy15CandidateProcessError::InvalidField {
            case_ordinal: 0,
            field: "aggregate correctness binding",
        });
    }
    for (index, (receipt, expected)) in evidence
        .receipts
        .iter()
        .zip(correctness.records())
        .enumerate()
    {
        let ordinal = u32::try_from(index)
            .map_err(|_| X64GateBPolicy15CandidateProcessError::MetricOverflow)?;
        validate_receipt(receipt, expected, ordinal)?;
    }
    if process_results_hash(evidence)? != evidence.results_hash
        || evidence.results_hash != FROZEN_PROCESS_RESULTS_HASH
    {
        return Err(X64GateBPolicy15CandidateProcessError::ResultsHashMismatch);
    }
    Ok(())
}

fn validate_evidence_envelope(
    evidence: &X64GateBPolicy15CandidateProcessEvidence,
) -> Result<(), X64GateBPolicy15CandidateProcessError> {
    let actual = u32::try_from(evidence.receipts.len())
        .map_err(|_| X64GateBPolicy15CandidateProcessError::MetricOverflow)?;
    if actual != X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_CASES {
        return Err(X64GateBPolicy15CandidateProcessError::FixedCorpusCount {
            expected: X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_CASES,
            actual,
        });
    }
    let manifest = corevm0_gate_a_manifest()?;
    if evidence.schema_version != X64_GATE_B_POLICY15_CANDIDATE_PROCESS_SCHEMA_VERSION
        || evidence.process_policy_version != X64_GATE_B_POLICY15_CANDIDATE_PROCESS_POLICY_VERSION
        || evidence.ipc_schema_version != X64_GATE_B_POLICY15_CANDIDATE_IPC_SCHEMA_VERSION
        || evidence.corpus_manifest_hash != manifest.manifest_hash
        || evidence.candidate_capsule_hash != x64_target_policy15_accepted_candidate_capsule_hash()
        || evidence.correctness_results_hash
            != x64_gate_b_policy15_candidate_accepted_correctness_results_hash()
        || evidence.candidate_execution_cases != X64_GATE_B_POLICY15_CANDIDATE_EXECUTION_CASES
        || evidence.fallback_cases != X64_GATE_B_POLICY15_CANDIDATE_FALLBACK_CASES
    {
        return Err(X64GateBPolicy15CandidateProcessError::InvalidField {
            case_ordinal: 0,
            field: "aggregate envelope",
        });
    }
    Ok(())
}

fn validate_receipt(
    receipt: &X64GateBPolicy15CandidateProcessReceipt,
    expected: &X64GateBPolicy15CandidateCorrectnessRecord,
    expected_ordinal: u32,
) -> Result<(), X64GateBPolicy15CandidateProcessError> {
    if receipt.case_ordinal != expected_ordinal {
        return Err(X64GateBPolicy15CandidateProcessError::NonCanonicalOrdinal {
            expected: expected_ordinal,
            actual: receipt.case_ordinal,
        });
    }
    if receipt.schema_version != X64_GATE_B_POLICY15_CANDIDATE_PROCESS_SCHEMA_VERSION
        || receipt.process_policy_version != X64_GATE_B_POLICY15_CANDIDATE_PROCESS_POLICY_VERSION
        || receipt.ipc_schema_version != X64_GATE_B_POLICY15_CANDIDATE_IPC_SCHEMA_VERSION
        || receipt.workload != expected.workload()
        || receipt.selection != expected.selection()
        || receipt.input_hash != expected.input_hash()
        || receipt.candidate_capsule_hash != expected.candidate_capsule_hash()
        || receipt.correctness_results_hash
            != x64_gate_b_policy15_candidate_accepted_correctness_results_hash()
        || receipt.correctness_record_hash != expected.record_hash()
        || receipt.ipc_frame_hash == SemanticHash::ZERO
    {
        return Err(X64GateBPolicy15CandidateProcessError::InvalidField {
            case_ordinal: expected_ordinal,
            field: "receipt binding",
        });
    }
    if receipt_hash(receipt)? != receipt.receipt_hash {
        return Err(X64GateBPolicy15CandidateProcessError::ReceiptHashMismatch {
            case_ordinal: expected_ordinal,
        });
    }
    Ok(())
}

fn receipt_hash(
    receipt: &X64GateBPolicy15CandidateProcessReceipt,
) -> Result<SemanticHash, X64GateBPolicy15CandidateProcessError> {
    let mut bytes = Vec::with_capacity(RECEIPT_DOMAIN.len() + 20 + (6 * 32));
    bytes.extend_from_slice(RECEIPT_DOMAIN);
    put_version(&mut bytes, receipt.schema_version);
    put_version(&mut bytes, receipt.process_policy_version);
    put_version(&mut bytes, receipt.ipc_schema_version);
    bytes.extend_from_slice(&receipt.case_ordinal.to_be_bytes());
    bytes.push(workload_tag(receipt.workload));
    bytes.push(selection_tag(receipt.selection));
    for hash in [
        receipt.input_hash,
        receipt.candidate_capsule_hash,
        receipt.correctness_results_hash,
        receipt.correctness_record_hash,
        receipt.ipc_frame_hash,
    ] {
        if hash == SemanticHash::ZERO {
            return Err(X64GateBPolicy15CandidateProcessError::InvalidField {
                case_ordinal: receipt.case_ordinal,
                field: "receipt hash input",
            });
        }
        bytes.extend_from_slice(&hash.0);
    }
    Ok(SemanticHash(sha256(&bytes)))
}

pub fn x64_gate_b_policy15_candidate_process_results_hash(
    evidence: &X64GateBPolicy15CandidateProcessEvidence,
) -> Result<SemanticHash, X64GateBPolicy15CandidateProcessError> {
    process_results_hash(evidence)
}

pub const fn x64_gate_b_policy15_candidate_accepted_process_results_hash() -> SemanticHash {
    FROZEN_PROCESS_RESULTS_HASH
}

fn process_results_hash(
    evidence: &X64GateBPolicy15CandidateProcessEvidence,
) -> Result<SemanticHash, X64GateBPolicy15CandidateProcessError> {
    validate_evidence_envelope(evidence)?;
    let mut bytes =
        Vec::with_capacity(RESULTS_DOMAIN.len() + 30 + (4 * 32) + evidence.receipts.len() * 32);
    bytes.extend_from_slice(RESULTS_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.process_policy_version);
    put_version(&mut bytes, evidence.ipc_schema_version);
    for hash in [
        evidence.corpus_manifest_hash,
        evidence.candidate_capsule_hash,
        evidence.correctness_results_hash,
    ] {
        bytes.extend_from_slice(&hash.0);
    }
    bytes.extend_from_slice(&evidence.candidate_execution_cases.to_be_bytes());
    bytes.extend_from_slice(&evidence.fallback_cases.to_be_bytes());
    let count = u32::try_from(evidence.receipts.len())
        .map_err(|_| X64GateBPolicy15CandidateProcessError::MetricOverflow)?;
    bytes.extend_from_slice(&count.to_be_bytes());
    for receipt in &evidence.receipts {
        if receipt.receipt_hash == SemanticHash::ZERO {
            return Err(X64GateBPolicy15CandidateProcessError::InvalidField {
                case_ordinal: receipt.case_ordinal,
                field: "receipt seal",
            });
        }
        bytes.extend_from_slice(&receipt.receipt_hash.0);
    }
    Ok(SemanticHash(sha256(&bytes)))
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_be_bytes());
    bytes.extend_from_slice(&version.1.to_be_bytes());
    bytes.extend_from_slice(&version.2.to_be_bytes());
}

const fn workload_tag(workload: CoreVmGateAWorkload) -> u8 {
    match workload {
        CoreVmGateAWorkload::BranchMix => 0,
        CoreVmGateAWorkload::BoundsOrderedArrayGet => 1,
    }
}

const fn selection_tag(selection: X64GateBPolicy15CandidateSelection) -> u8 {
    match selection {
        X64GateBPolicy15CandidateSelection::Policy15Candidate => 0,
        X64GateBPolicy15CandidateSelection::Policy14Fallback => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::x64_gate_b_candidate_admission::emit_reconstructed_candidate_correctness_for_process_tests;

    fn synthetic_evidence(
        correctness: &super::super::x64_gate_b_candidate_admission::X64GateBPolicy15CandidateCorrectnessEvidence,
    ) -> X64GateBPolicy15CandidateProcessEvidence {
        let receipts = correctness
            .records()
            .iter()
            .map(|record| {
                let ipc = seal_x64_gate_b_policy15_candidate_ipc_record(record).unwrap();
                seal_receipt(&ipc, record).unwrap()
            })
            .collect::<Vec<_>>();
        seal_process_evidence(receipts, correctness).unwrap()
    }

    #[test]
    fn receipts_bind_exact_reconstructed_records_and_reject_self_resealing() {
        let correctness = emit_reconstructed_candidate_correctness_for_process_tests()
            .expect("complete reconstructed ADR-0052 vector");
        let evidence = synthetic_evidence(&correctness);
        verify_process_evidence_against_records(&evidence, &correctness).unwrap();
        println!(
            "candidate process results={}",
            evidence.results_hash.to_hex()
        );

        let mut mutated = evidence.clone();
        mutated.receipts[0].correctness_record_hash = correctness.records()[1].record_hash();
        mutated.receipts[0].receipt_hash = receipt_hash(&mutated.receipts[0]).unwrap();
        mutated.results_hash = process_results_hash(&mutated).unwrap();
        assert!(verify_process_evidence_against_records(&mutated, &correctness).is_err());

        let mut reordered = evidence.clone();
        reordered.receipts.swap(0, 1);
        reordered.results_hash = process_results_hash(&reordered).unwrap();
        assert!(verify_process_evidence_against_records(&reordered, &correctness).is_err());

        let mut wrong_input = evidence.clone();
        wrong_input.receipts[0].input_hash = correctness.records()[1].input_hash();
        wrong_input.receipts[0].receipt_hash = receipt_hash(&wrong_input.receipts[0]).unwrap();
        wrong_input.results_hash = process_results_hash(&wrong_input).unwrap();
        assert!(verify_process_evidence_against_records(&wrong_input, &correctness).is_err());

        let mut wrong_root = evidence.clone();
        wrong_root.correctness_results_hash = SemanticHash::ZERO;
        assert!(process_results_hash(&wrong_root).is_err());

        let mut wrong_result = evidence.clone();
        wrong_result.results_hash = SemanticHash::ZERO;
        assert!(verify_process_evidence_against_records(&wrong_result, &correctness).is_err());
    }
}
