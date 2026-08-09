//! Untimed direct-process correspondence for ADR-0054 candidate ELF images.
//!
//! Deadlines are enforced by the shared containment harness, but elapsed time
//! is deliberately discarded and absent from every public type and identity.

use super::corevm0_gate_a::{
    corevm0_gate_a_case_input_hash, corevm0_gate_a_manifest, CoreVmGateAError, CoreVmGateAWorkload,
    COREVM0_GATE_A_BOUNDS_CASES, COREVM0_GATE_A_TOTAL_CASES,
};
use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_gate_b_candidate_admission::{
    X64GateBPolicy15CandidateCorrectnessRecord, X64GateBPolicy15CandidateSelection,
};
use super::x64_gate_b_candidate_process::X64GateBPolicy15CandidateProcessReceipt;
use super::x64_gate_b_candidate_standalone_artifact::{
    verify_x64_gate_b_policy15_standalone_artifact, VerifiedX64GateBPolicy15StandaloneArtifact,
    X64GateBPolicy15StandaloneArtifactError,
};
use super::x64_gate_b_candidate_standalone_authority::{
    X64GateBPolicy15StandaloneAuthority, X64GateBPolicy15StandaloneAuthorityError,
};
use super::x64_native::{
    X64NativeCorrespondenceEffect, X64NativeCorrespondenceF64, X64NativeCorrespondenceObservation,
    X64NativeCorrespondenceOutcome,
};
use super::x64_standalone_process::{
    run_admitted_x64_standalone_process, PreparedX64StandaloneExecutable,
    X64StandaloneProcessError, X64_STANDALONE_PROCESS_TIMEOUT_MILLIS,
};
use super::x64_standalone_protocol::{
    decode_x64_standalone_output_for_profile, encode_x64_standalone_input,
    encode_x64_standalone_output, X64StandaloneInput, X64StandaloneOutcome, X64StandaloneOutput,
    X64StandaloneProfile, X64StandaloneProtocolError,
};
use std::fmt;

pub const X64_GATE_B_POLICY15_STANDALONE_PROCESS_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_POLICY15_STANDALONE_PROCESS_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_POLICY15_STANDALONE_RESULTS_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_POLICY15_STANDALONE_PROCESS_CASES: u32 = COREVM0_GATE_A_TOTAL_CASES;

const RECORD_DOMAIN: &[u8] = b"NAUX:x86-64:policy-1.5:candidate-standalone:process-record:v1\0";
const RESULTS_DOMAIN: &[u8] = b"NAUX:x86-64:policy-1.5:candidate-standalone:process-results:v1\0";
const FROZEN_RESULTS_HASH: SemanticHash = SemanticHash([
    0xf0, 0x09, 0xce, 0x38, 0x05, 0xfe, 0x8e, 0x07, 0x7b, 0x22, 0xc7, 0xfe, 0x57, 0xfe, 0xb4, 0x57,
    0x4a, 0xcc, 0xb2, 0x72, 0x47, 0x8b, 0x52, 0x4e, 0xb3, 0x22, 0x85, 0x14, 0xe8, 0xe3, 0x5d, 0x5d,
]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64GateBPolicy15StandaloneExecutionRecord {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    case_ordinal: u32,
    workload: CoreVmGateAWorkload,
    profile: X64StandaloneProfile,
    selection: X64GateBPolicy15CandidateSelection,
    input_hash: SemanticHash,
    candidate_capsule_hash: SemanticHash,
    correctness_results_hash: SemanticHash,
    process_results_hash: SemanticHash,
    correctness_record_hash: SemanticHash,
    process_receipt_hash: SemanticHash,
    standalone_artifact_hash: SemanticHash,
    elf_image_hash: SemanticHash,
    target_code_hash: SemanticHash,
    input_frame_bytes: u64,
    input_frame_hash: SemanticHash,
    output_frame: [u8; 40],
    output_frame_hash: SemanticHash,
    direct: X64NativeCorrespondenceObservation,
    record_hash: SemanticHash,
}

impl X64GateBPolicy15StandaloneExecutionRecord {
    pub const fn case_ordinal(&self) -> u32 {
        self.case_ordinal
    }

    pub const fn workload(&self) -> CoreVmGateAWorkload {
        self.workload
    }

    pub const fn profile(&self) -> X64StandaloneProfile {
        self.profile
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

    pub const fn process_receipt_hash(&self) -> SemanticHash {
        self.process_receipt_hash
    }

    pub const fn standalone_artifact_hash(&self) -> SemanticHash {
        self.standalone_artifact_hash
    }

    pub const fn output_frame(&self) -> &[u8; 40] {
        &self.output_frame
    }

    pub const fn direct(&self) -> &X64NativeCorrespondenceObservation {
        &self.direct
    }

    pub const fn record_hash(&self) -> SemanticHash {
        self.record_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64GateBPolicy15StandaloneProcessEvidence {
    schema_version: (u16, u16, u16),
    process_policy_version: (u16, u16, u16),
    results_policy_version: (u16, u16, u16),
    manifest_hash: SemanticHash,
    candidate_capsule_hash: SemanticHash,
    correctness_results_hash: SemanticHash,
    process_results_hash: SemanticHash,
    branch_artifact_hash: SemanticHash,
    branch_elf_image_hash: SemanticHash,
    bounds_artifact_hash: SemanticHash,
    bounds_elf_image_hash: SemanticHash,
    candidate_execution_cases: u32,
    fallback_cases: u32,
    records: Vec<X64GateBPolicy15StandaloneExecutionRecord>,
    results_hash: SemanticHash,
}

impl X64GateBPolicy15StandaloneProcessEvidence {
    pub const fn manifest_hash(&self) -> SemanticHash {
        self.manifest_hash
    }

    pub const fn candidate_capsule_hash(&self) -> SemanticHash {
        self.candidate_capsule_hash
    }

    pub const fn correctness_results_hash(&self) -> SemanticHash {
        self.correctness_results_hash
    }

    pub const fn process_results_hash(&self) -> SemanticHash {
        self.process_results_hash
    }

    pub const fn branch_artifact_hash(&self) -> SemanticHash {
        self.branch_artifact_hash
    }

    pub const fn branch_elf_image_hash(&self) -> SemanticHash {
        self.branch_elf_image_hash
    }

    pub const fn bounds_artifact_hash(&self) -> SemanticHash {
        self.bounds_artifact_hash
    }

    pub const fn bounds_elf_image_hash(&self) -> SemanticHash {
        self.bounds_elf_image_hash
    }

    pub const fn candidate_execution_cases(&self) -> u32 {
        self.candidate_execution_cases
    }

    pub const fn fallback_cases(&self) -> u32 {
        self.fallback_cases
    }

    pub fn records(&self) -> &[X64GateBPolicy15StandaloneExecutionRecord] {
        &self.records
    }

    pub const fn results_hash(&self) -> SemanticHash {
        self.results_hash
    }
}

trait CandidateStandaloneAuthorityLifetimeAnchor: fmt::Debug {}

impl CandidateStandaloneAuthorityLifetimeAnchor for X64GateBPolicy15StandaloneAuthority<'_, '_> {}

trait CandidateStandaloneArtifactLifetimeAnchor: fmt::Debug {}

impl CandidateStandaloneArtifactLifetimeAnchor
    for VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_>
{
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedX64GateBPolicy15StandaloneProcess<
    'evidence,
    'branch_authority,
    'branch_artifact,
    'bounds_authority,
    'bounds_artifact,
> {
    evidence: &'evidence X64GateBPolicy15StandaloneProcessEvidence,
    _branch_authority: &'branch_authority dyn CandidateStandaloneAuthorityLifetimeAnchor,
    _branch_artifact: &'branch_artifact dyn CandidateStandaloneArtifactLifetimeAnchor,
    _bounds_authority: &'bounds_authority dyn CandidateStandaloneAuthorityLifetimeAnchor,
    _bounds_artifact: &'bounds_artifact dyn CandidateStandaloneArtifactLifetimeAnchor,
}

impl VerifiedX64GateBPolicy15StandaloneProcess<'_, '_, '_, '_, '_> {
    pub const fn evidence(&self) -> &X64GateBPolicy15StandaloneProcessEvidence {
        self.evidence
    }
}

#[derive(Debug)]
pub enum X64GateBPolicy15StandaloneProcessError {
    Corpus(CoreVmGateAError),
    Authority(X64GateBPolicy15StandaloneAuthorityError),
    Artifact(X64GateBPolicy15StandaloneArtifactError),
    Process(X64StandaloneProcessError),
    Protocol {
        case_ordinal: u32,
        message: String,
    },
    InvalidField {
        case_ordinal: u32,
        field: &'static str,
    },
    SemanticMismatch {
        case_ordinal: u32,
    },
    RecordHashMismatch {
        case_ordinal: u32,
    },
    ResultsHashMismatch,
    MetricOverflow {
        field: &'static str,
    },
}

impl fmt::Display for X64GateBPolicy15StandaloneProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corpus(error) => {
                write!(formatter, "candidate direct-process corpus failed: {error}")
            }
            Self::Authority(error) => write!(formatter, "{error}"),
            Self::Artifact(error) => write!(formatter, "{error}"),
            Self::Process(error) => write!(formatter, "{error}"),
            Self::Protocol {
                case_ordinal,
                message,
            } => write!(
                formatter,
                "candidate direct-process case {case_ordinal} protocol failed: {message}"
            ),
            Self::InvalidField {
                case_ordinal,
                field,
            } => write!(
                formatter,
                "candidate direct-process case {case_ordinal} has invalid {field}"
            ),
            Self::SemanticMismatch { case_ordinal } => write!(
                formatter,
                "candidate direct-process case {case_ordinal} differs from ADR-0052 Machine IR"
            ),
            Self::RecordHashMismatch { case_ordinal } => write!(
                formatter,
                "candidate direct-process case {case_ordinal} has an invalid record seal"
            ),
            Self::ResultsHashMismatch => {
                formatter.write_str("candidate direct-process aggregate seal is invalid")
            }
            Self::MetricOverflow { field } => {
                write!(formatter, "candidate direct-process {field} overflowed")
            }
        }
    }
}

impl std::error::Error for X64GateBPolicy15StandaloneProcessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Corpus(error) => Some(error),
            Self::Authority(error) => Some(error),
            Self::Artifact(error) => Some(error),
            Self::Process(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CoreVmGateAError> for X64GateBPolicy15StandaloneProcessError {
    fn from(value: CoreVmGateAError) -> Self {
        Self::Corpus(value)
    }
}

impl From<X64GateBPolicy15StandaloneAuthorityError> for X64GateBPolicy15StandaloneProcessError {
    fn from(value: X64GateBPolicy15StandaloneAuthorityError) -> Self {
        Self::Authority(value)
    }
}

impl From<X64GateBPolicy15StandaloneArtifactError> for X64GateBPolicy15StandaloneProcessError {
    fn from(value: X64GateBPolicy15StandaloneArtifactError) -> Self {
        Self::Artifact(value)
    }
}

impl From<X64StandaloneProcessError> for X64GateBPolicy15StandaloneProcessError {
    fn from(value: X64StandaloneProcessError) -> Self {
        Self::Process(value)
    }
}

/// Launch the exact fixed corpus through two independently verified images.
/// No elapsed duration is copied out of the containment harness.
pub fn emit_x64_gate_b_policy15_standalone_process_evidence(
    branch_authority: &X64GateBPolicy15StandaloneAuthority<'_, '_>,
    branch_artifact: &VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_>,
    bounds_authority: &X64GateBPolicy15StandaloneAuthority<'_, '_>,
    bounds_artifact: &VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_>,
) -> Result<X64GateBPolicy15StandaloneProcessEvidence, X64GateBPolicy15StandaloneProcessError> {
    validate_cross_profile(
        branch_authority,
        branch_artifact,
        bounds_authority,
        bounds_artifact,
    )?;
    let manifest = corevm0_gate_a_manifest()?;
    let mut branch_executable = PreparedX64StandaloneExecutable::create(
        X64StandaloneProfile::BranchMix,
        branch_artifact.image_bytes(),
    )?;
    let mut bounds_executable = PreparedX64StandaloneExecutable::create(
        X64StandaloneProfile::Bounds,
        bounds_artifact.image_bytes(),
    )?;
    let run = (|| {
        let mut records = Vec::with_capacity(manifest.cases.len());
        for (index, case) in manifest.cases.iter().enumerate() {
            let ordinal = u32::try_from(index).map_err(|_| {
                X64GateBPolicy15StandaloneProcessError::MetricOverflow {
                    field: "case ordinal",
                }
            })?;
            if case.ordinal != ordinal {
                return Err(X64GateBPolicy15StandaloneProcessError::InvalidField {
                    case_ordinal: ordinal,
                    field: "manifest ordinal",
                });
            }
            let (authority, artifact, executable) = match case.workload {
                CoreVmGateAWorkload::BranchMix => {
                    (branch_authority, branch_artifact, &branch_executable)
                }
                CoreVmGateAWorkload::BoundsOrderedArrayGet => {
                    (bounds_authority, bounds_artifact, &bounds_executable)
                }
            };
            records.push(execute_case(authority, artifact, executable, case)?);
        }
        seal_evidence(branch_authority, branch_artifact, bounds_artifact, records)
    })();
    let branch_cleanup = branch_executable.cleanup();
    let bounds_cleanup = bounds_executable.cleanup();
    match run {
        Err(error) => Err(error),
        Ok(evidence) => {
            branch_cleanup?;
            bounds_cleanup?;
            Ok(evidence)
        }
    }
}

/// Rebuild both artifacts and every deterministic evidence binding.  This
/// verifies recorded direct observations without re-running the processes.
pub fn verify_x64_gate_b_policy15_standalone_process_evidence<
    'evidence,
    'branch_authority,
    'branch_artifact,
    'bounds_authority,
    'bounds_artifact,
>(
    branch_authority: &'branch_authority X64GateBPolicy15StandaloneAuthority<'_, '_>,
    branch_artifact: &'branch_artifact VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_>,
    bounds_authority: &'bounds_authority X64GateBPolicy15StandaloneAuthority<'_, '_>,
    bounds_artifact: &'bounds_artifact VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_>,
    evidence: &'evidence X64GateBPolicy15StandaloneProcessEvidence,
) -> Result<
    VerifiedX64GateBPolicy15StandaloneProcess<
        'evidence,
        'branch_authority,
        'branch_artifact,
        'bounds_authority,
        'bounds_artifact,
    >,
    X64GateBPolicy15StandaloneProcessError,
> {
    validate_cross_profile(
        branch_authority,
        branch_artifact,
        bounds_authority,
        bounds_artifact,
    )?;
    let _ = verify_x64_gate_b_policy15_standalone_artifact(
        branch_authority,
        branch_artifact.image_bytes(),
    )?;
    let _ = verify_x64_gate_b_policy15_standalone_artifact(
        bounds_authority,
        bounds_artifact.image_bytes(),
    )?;
    let manifest = corevm0_gate_a_manifest()?;
    if evidence.schema_version != X64_GATE_B_POLICY15_STANDALONE_PROCESS_SCHEMA_VERSION
        || evidence.process_policy_version != X64_GATE_B_POLICY15_STANDALONE_PROCESS_POLICY_VERSION
        || evidence.results_policy_version != X64_GATE_B_POLICY15_STANDALONE_RESULTS_POLICY_VERSION
        || evidence.manifest_hash != manifest.manifest_hash
        || evidence.candidate_capsule_hash != branch_authority.candidate_capsule_hash()
        || evidence.correctness_results_hash != branch_authority.correctness_results_hash()
        || evidence.process_results_hash != branch_authority.process_results_hash()
        || evidence.branch_artifact_hash != branch_artifact.artifact_hash()
        || evidence.branch_elf_image_hash != branch_artifact.elf_image_hash()
        || evidence.bounds_artifact_hash != bounds_artifact.artifact_hash()
        || evidence.bounds_elf_image_hash != bounds_artifact.elf_image_hash()
        || evidence.candidate_execution_cases
            != COREVM0_GATE_A_TOTAL_CASES - COREVM0_GATE_A_BOUNDS_CASES
        || evidence.fallback_cases != COREVM0_GATE_A_BOUNDS_CASES
        || evidence.records.len() != manifest.cases.len()
    {
        return Err(X64GateBPolicy15StandaloneProcessError::InvalidField {
            case_ordinal: 0,
            field: "aggregate envelope",
        });
    }
    for (index, (case, record)) in manifest.cases.iter().zip(&evidence.records).enumerate() {
        let ordinal = u32::try_from(index).map_err(|_| {
            X64GateBPolicy15StandaloneProcessError::MetricOverflow {
                field: "case ordinal",
            }
        })?;
        if case.ordinal != ordinal || record.case_ordinal != ordinal {
            return Err(X64GateBPolicy15StandaloneProcessError::InvalidField {
                case_ordinal: ordinal,
                field: "record order",
            });
        }
        let (authority, artifact) = match case.workload {
            CoreVmGateAWorkload::BranchMix => (branch_authority, branch_artifact),
            CoreVmGateAWorkload::BoundsOrderedArrayGet => (bounds_authority, bounds_artifact),
        };
        verify_record(authority, artifact, case, record)?;
    }
    if standalone_results_hash(evidence) != evidence.results_hash
        || evidence.results_hash != FROZEN_RESULTS_HASH
    {
        return Err(X64GateBPolicy15StandaloneProcessError::ResultsHashMismatch);
    }
    Ok(VerifiedX64GateBPolicy15StandaloneProcess {
        evidence,
        _branch_authority: branch_authority,
        _branch_artifact: branch_artifact,
        _bounds_authority: bounds_authority,
        _bounds_artifact: bounds_artifact,
    })
}

fn validate_cross_profile(
    branch_authority: &X64GateBPolicy15StandaloneAuthority<'_, '_>,
    branch_artifact: &VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_>,
    bounds_authority: &X64GateBPolicy15StandaloneAuthority<'_, '_>,
    bounds_artifact: &VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_>,
) -> Result<(), X64GateBPolicy15StandaloneProcessError> {
    branch_authority.revalidate_complete()?;
    bounds_authority.revalidate_complete()?;
    if branch_authority.profile() != X64StandaloneProfile::BranchMix
        || branch_authority.selection() != X64GateBPolicy15CandidateSelection::Policy15Candidate
        || branch_artifact.profile() != X64StandaloneProfile::BranchMix
        || branch_artifact.selection() != X64GateBPolicy15CandidateSelection::Policy15Candidate
        || bounds_authority.profile() != X64StandaloneProfile::Bounds
        || bounds_authority.selection() != X64GateBPolicy15CandidateSelection::Policy14Fallback
        || bounds_artifact.profile() != X64StandaloneProfile::Bounds
        || bounds_artifact.selection() != X64GateBPolicy15CandidateSelection::Policy14Fallback
    {
        return Err(X64GateBPolicy15StandaloneProcessError::InvalidField {
            case_ordinal: 0,
            field: "closed profile selection",
        });
    }
    if branch_authority.manifest_hash() != bounds_authority.manifest_hash()
        || branch_authority.candidate_capsule_hash() != bounds_authority.candidate_capsule_hash()
        || branch_authority.correctness_results_hash()
            != bounds_authority.correctness_results_hash()
        || branch_authority.process_results_hash() != bounds_authority.process_results_hash()
    {
        return Err(X64GateBPolicy15StandaloneProcessError::InvalidField {
            case_ordinal: 0,
            field: "cross-profile upstream roots",
        });
    }
    Ok(())
}

fn execute_case(
    authority: &X64GateBPolicy15StandaloneAuthority<'_, '_>,
    artifact: &VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_>,
    executable: &PreparedX64StandaloneExecutable,
    case: &super::corevm0_gate_a::CoreVmGateACase,
) -> Result<X64GateBPolicy15StandaloneExecutionRecord, X64GateBPolicy15StandaloneProcessError> {
    let (expected_record, expected_receipt) = upstream_case(authority, case.ordinal)?;
    validate_upstream_case(authority, case, expected_record, expected_receipt)?;
    let input = X64StandaloneInput::new(
        authority.profile(),
        case.input.array_f64_bits.clone(),
        case.input.repetitions,
    )
    .map_err(|error| protocol_error(case.ordinal, error))?;
    let input_frame =
        encode_x64_standalone_input(&input).map_err(|error| protocol_error(case.ordinal, error))?;
    let admitted = run_admitted_x64_standalone_process(
        executable,
        case.ordinal,
        input_frame.clone(),
        authority.profile(),
        X64_STANDALONE_PROCESS_TIMEOUT_MILLIS,
    )?;
    let direct = normalize_output(admitted.output());
    if &direct != expected_record.machine_ir() {
        return Err(X64GateBPolicy15StandaloneProcessError::SemanticMismatch {
            case_ordinal: case.ordinal,
        });
    }
    let input_frame_bytes = u64::try_from(input_frame.len()).map_err(|_| {
        X64GateBPolicy15StandaloneProcessError::MetricOverflow {
            field: "input frame length",
        }
    })?;
    let mut record = X64GateBPolicy15StandaloneExecutionRecord {
        schema_version: X64_GATE_B_POLICY15_STANDALONE_PROCESS_SCHEMA_VERSION,
        policy_version: X64_GATE_B_POLICY15_STANDALONE_PROCESS_POLICY_VERSION,
        case_ordinal: case.ordinal,
        workload: case.workload,
        profile: authority.profile(),
        selection: authority.selection(),
        input_hash: case.input_hash,
        candidate_capsule_hash: authority.candidate_capsule_hash(),
        correctness_results_hash: authority.correctness_results_hash(),
        process_results_hash: authority.process_results_hash(),
        correctness_record_hash: expected_record.record_hash(),
        process_receipt_hash: expected_receipt.receipt_hash(),
        standalone_artifact_hash: artifact.artifact_hash(),
        elf_image_hash: artifact.elf_image_hash(),
        target_code_hash: artifact.target_code_hash(),
        input_frame_bytes,
        input_frame_hash: hash_bytes(&input_frame),
        output_frame: *admitted.output_frame(),
        output_frame_hash: hash_bytes(admitted.output_frame()),
        direct,
        record_hash: SemanticHash::ZERO,
    };
    record.record_hash = standalone_record_hash(&record);
    Ok(record)
}

fn verify_record(
    authority: &X64GateBPolicy15StandaloneAuthority<'_, '_>,
    artifact: &VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_>,
    case: &super::corevm0_gate_a::CoreVmGateACase,
    record: &X64GateBPolicy15StandaloneExecutionRecord,
) -> Result<(), X64GateBPolicy15StandaloneProcessError> {
    let (expected_record, expected_receipt) = upstream_case(authority, case.ordinal)?;
    validate_upstream_case(authority, case, expected_record, expected_receipt)?;
    let regenerated_input = corevm0_gate_a_case_input_hash(case)?;
    let input = X64StandaloneInput::new(
        authority.profile(),
        case.input.array_f64_bits.clone(),
        case.input.repetitions,
    )
    .map_err(|error| protocol_error(case.ordinal, error))?;
    let input_frame =
        encode_x64_standalone_input(&input).map_err(|error| protocol_error(case.ordinal, error))?;
    let decoded =
        decode_x64_standalone_output_for_profile(&record.output_frame, authority.profile())
            .map_err(|error| protocol_error(case.ordinal, error))?;
    let canonical = encode_x64_standalone_output(decoded)
        .map_err(|error| protocol_error(case.ordinal, error))?;
    let direct = normalize_output(decoded);
    let exact = record.schema_version == X64_GATE_B_POLICY15_STANDALONE_PROCESS_SCHEMA_VERSION
        && record.policy_version == X64_GATE_B_POLICY15_STANDALONE_PROCESS_POLICY_VERSION
        && record.case_ordinal == case.ordinal
        && record.workload == case.workload
        && record.profile == authority.profile()
        && record.selection == authority.selection()
        && regenerated_input == case.input_hash
        && record.input_hash == case.input_hash
        && record.candidate_capsule_hash == authority.candidate_capsule_hash()
        && record.correctness_results_hash == authority.correctness_results_hash()
        && record.process_results_hash == authority.process_results_hash()
        && record.correctness_record_hash == expected_record.record_hash()
        && record.process_receipt_hash == expected_receipt.receipt_hash()
        && record.standalone_artifact_hash == artifact.artifact_hash()
        && record.elf_image_hash == artifact.elf_image_hash()
        && record.target_code_hash == artifact.target_code_hash()
        && record.input_frame_bytes == input_frame.len() as u64
        && record.input_frame_hash == hash_bytes(&input_frame)
        && canonical.as_slice() == record.output_frame
        && record.output_frame_hash == hash_bytes(&record.output_frame)
        && record.direct == direct
        && &record.direct == expected_record.machine_ir();
    if !exact {
        return Err(X64GateBPolicy15StandaloneProcessError::InvalidField {
            case_ordinal: case.ordinal,
            field: "exact record binding",
        });
    }
    if standalone_record_hash(record) != record.record_hash {
        return Err(X64GateBPolicy15StandaloneProcessError::RecordHashMismatch {
            case_ordinal: case.ordinal,
        });
    }
    Ok(())
}

fn validate_upstream_case(
    authority: &X64GateBPolicy15StandaloneAuthority<'_, '_>,
    case: &super::corevm0_gate_a::CoreVmGateACase,
    record: &X64GateBPolicy15CandidateCorrectnessRecord,
    receipt: &X64GateBPolicy15CandidateProcessReceipt,
) -> Result<(), X64GateBPolicy15StandaloneProcessError> {
    if record.case_ordinal() != case.ordinal
        || receipt.case_ordinal() != case.ordinal
        || record.workload() != case.workload
        || receipt.workload() != case.workload
        || record.selection() != authority.selection()
        || receipt.selection() != authority.selection()
        || record.input_hash() != case.input_hash
        || receipt.input_hash() != case.input_hash
        || record.candidate_capsule_hash() != authority.candidate_capsule_hash()
        || receipt.correctness_record_hash() != record.record_hash()
        || record.source_machine_ir_hash() != authority.source_machine_ir_hash()
        || record.executed_target_semantic_hash() != authority.target_artifact_hash()
        || record.executed_target_plan_hash() != authority.target_plan_hash()
        || record.executed_target_code_hash() != authority.target_code_hash()
    {
        return Err(X64GateBPolicy15StandaloneProcessError::InvalidField {
            case_ordinal: case.ordinal,
            field: "ADR-0052/0053 upstream record",
        });
    }
    Ok(())
}

fn upstream_case<'a>(
    authority: &'a X64GateBPolicy15StandaloneAuthority<'_, '_>,
    ordinal: u32,
) -> Result<
    (
        &'a X64GateBPolicy15CandidateCorrectnessRecord,
        &'a X64GateBPolicy15CandidateProcessReceipt,
    ),
    X64GateBPolicy15StandaloneProcessError,
> {
    let index = usize::try_from(ordinal).map_err(|_| {
        X64GateBPolicy15StandaloneProcessError::MetricOverflow {
            field: "case index",
        }
    })?;
    let record = authority
        .correctness()
        .evidence()
        .records()
        .get(index)
        .ok_or(X64GateBPolicy15StandaloneProcessError::InvalidField {
            case_ordinal: ordinal,
            field: "ADR-0052 record index",
        })?;
    let receipt = authority.process().evidence().receipts().get(index).ok_or(
        X64GateBPolicy15StandaloneProcessError::InvalidField {
            case_ordinal: ordinal,
            field: "ADR-0053 receipt index",
        },
    )?;
    Ok((record, receipt))
}

fn seal_evidence(
    authority: &X64GateBPolicy15StandaloneAuthority<'_, '_>,
    branch_artifact: &VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_>,
    bounds_artifact: &VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_>,
    records: Vec<X64GateBPolicy15StandaloneExecutionRecord>,
) -> Result<X64GateBPolicy15StandaloneProcessEvidence, X64GateBPolicy15StandaloneProcessError> {
    if records.len() != COREVM0_GATE_A_TOTAL_CASES as usize {
        return Err(X64GateBPolicy15StandaloneProcessError::InvalidField {
            case_ordinal: 0,
            field: "fixed record count",
        });
    }
    let mut evidence = X64GateBPolicy15StandaloneProcessEvidence {
        schema_version: X64_GATE_B_POLICY15_STANDALONE_PROCESS_SCHEMA_VERSION,
        process_policy_version: X64_GATE_B_POLICY15_STANDALONE_PROCESS_POLICY_VERSION,
        results_policy_version: X64_GATE_B_POLICY15_STANDALONE_RESULTS_POLICY_VERSION,
        manifest_hash: authority.manifest_hash(),
        candidate_capsule_hash: authority.candidate_capsule_hash(),
        correctness_results_hash: authority.correctness_results_hash(),
        process_results_hash: authority.process_results_hash(),
        branch_artifact_hash: branch_artifact.artifact_hash(),
        branch_elf_image_hash: branch_artifact.elf_image_hash(),
        bounds_artifact_hash: bounds_artifact.artifact_hash(),
        bounds_elf_image_hash: bounds_artifact.elf_image_hash(),
        candidate_execution_cases: COREVM0_GATE_A_TOTAL_CASES - COREVM0_GATE_A_BOUNDS_CASES,
        fallback_cases: COREVM0_GATE_A_BOUNDS_CASES,
        records,
        results_hash: SemanticHash::ZERO,
    };
    evidence.results_hash = standalone_results_hash(&evidence);
    if evidence.results_hash != FROZEN_RESULTS_HASH {
        return Err(X64GateBPolicy15StandaloneProcessError::ResultsHashMismatch);
    }
    Ok(evidence)
}

/// Frozen ADR-0054 ordered direct-process identity.
pub const fn x64_gate_b_policy15_accepted_standalone_results_hash() -> SemanticHash {
    FROZEN_RESULTS_HASH
}

pub fn x64_gate_b_policy15_standalone_record_hash(
    record: &X64GateBPolicy15StandaloneExecutionRecord,
) -> SemanticHash {
    standalone_record_hash(record)
}

pub fn x64_gate_b_policy15_standalone_results_hash(
    evidence: &X64GateBPolicy15StandaloneProcessEvidence,
) -> SemanticHash {
    standalone_results_hash(evidence)
}

fn standalone_record_hash(record: &X64GateBPolicy15StandaloneExecutionRecord) -> SemanticHash {
    let mut bytes = Vec::with_capacity(RECORD_DOMAIN.len() + 600);
    bytes.extend_from_slice(RECORD_DOMAIN);
    put_version(&mut bytes, record.schema_version);
    put_version(&mut bytes, record.policy_version);
    bytes.extend_from_slice(&record.case_ordinal.to_le_bytes());
    bytes.push(workload_tag(record.workload));
    bytes.extend_from_slice(&record.profile.wire_tag().to_le_bytes());
    bytes.push(selection_tag(record.selection));
    for hash in [
        record.input_hash,
        record.candidate_capsule_hash,
        record.correctness_results_hash,
        record.process_results_hash,
        record.correctness_record_hash,
        record.process_receipt_hash,
        record.standalone_artifact_hash,
        record.elf_image_hash,
        record.target_code_hash,
    ] {
        bytes.extend_from_slice(&hash.0);
    }
    bytes.extend_from_slice(&record.input_frame_bytes.to_le_bytes());
    bytes.extend_from_slice(&record.input_frame_hash.0);
    bytes.extend_from_slice(&record.output_frame);
    bytes.extend_from_slice(&record.output_frame_hash.0);
    encode_observation(&mut bytes, &record.direct);
    SemanticHash(sha256(&bytes))
}

fn standalone_results_hash(evidence: &X64GateBPolicy15StandaloneProcessEvidence) -> SemanticHash {
    let mut bytes = Vec::with_capacity(RESULTS_DOMAIN.len() + 512 + evidence.records.len() * 32);
    bytes.extend_from_slice(RESULTS_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.process_policy_version);
    put_version(&mut bytes, evidence.results_policy_version);
    for hash in [
        evidence.manifest_hash,
        evidence.candidate_capsule_hash,
        evidence.correctness_results_hash,
        evidence.process_results_hash,
        evidence.branch_artifact_hash,
        evidence.branch_elf_image_hash,
        evidence.bounds_artifact_hash,
        evidence.bounds_elf_image_hash,
    ] {
        bytes.extend_from_slice(&hash.0);
    }
    bytes.extend_from_slice(&evidence.candidate_execution_cases.to_le_bytes());
    bytes.extend_from_slice(&evidence.fallback_cases.to_le_bytes());
    bytes.extend_from_slice(&(evidence.records.len() as u32).to_le_bytes());
    for record in &evidence.records {
        bytes.extend_from_slice(&record.record_hash.0);
    }
    SemanticHash(sha256(&bytes))
}

fn normalize_output(output: X64StandaloneOutput) -> X64NativeCorrespondenceObservation {
    match output.outcome() {
        X64StandaloneOutcome::ReturnF64 { bits } => X64NativeCorrespondenceObservation {
            outcome: X64NativeCorrespondenceOutcome::ReturnF64(if f64::from_bits(bits).is_nan() {
                X64NativeCorrespondenceF64::CanonicalNaN
            } else {
                X64NativeCorrespondenceF64::ExactBits(bits)
            }),
            effect_trace: Vec::new(),
        },
        X64StandaloneOutcome::Bounds => X64NativeCorrespondenceObservation {
            outcome: X64NativeCorrespondenceOutcome::Bounds,
            effect_trace: vec![X64NativeCorrespondenceEffect::Bounds],
        },
    }
}

fn encode_observation(bytes: &mut Vec<u8>, observation: &X64NativeCorrespondenceObservation) {
    match observation.outcome {
        X64NativeCorrespondenceOutcome::ReturnF64(X64NativeCorrespondenceF64::ExactBits(bits)) => {
            bytes.push(0);
            bytes.extend_from_slice(&bits.to_le_bytes());
        }
        X64NativeCorrespondenceOutcome::ReturnF64(X64NativeCorrespondenceF64::CanonicalNaN) => {
            bytes.push(1);
            bytes.extend_from_slice(&0_u64.to_le_bytes());
        }
        X64NativeCorrespondenceOutcome::Bounds => {
            bytes.push(2);
            bytes.extend_from_slice(&0_u64.to_le_bytes());
        }
    }
    bytes.extend_from_slice(&(observation.effect_trace.len() as u32).to_le_bytes());
    for effect in &observation.effect_trace {
        bytes.push(match effect {
            X64NativeCorrespondenceEffect::Bounds => 1,
        });
    }
}

fn hash_bytes(bytes: &[u8]) -> SemanticHash {
    SemanticHash(sha256(bytes))
}

fn protocol_error(
    case_ordinal: u32,
    error: X64StandaloneProtocolError,
) -> X64GateBPolicy15StandaloneProcessError {
    X64GateBPolicy15StandaloneProcessError::Protocol {
        case_ordinal,
        message: error.to_string(),
    }
}

const fn workload_tag(workload: CoreVmGateAWorkload) -> u8 {
    match workload {
        CoreVmGateAWorkload::BranchMix => 1,
        CoreVmGateAWorkload::BoundsOrderedArrayGet => 2,
    }
}

const fn selection_tag(selection: X64GateBPolicy15CandidateSelection) -> u8 {
    match selection {
        X64GateBPolicy15CandidateSelection::Policy15Candidate => 1,
        X64GateBPolicy15CandidateSelection::Policy14Fallback => 2,
    }
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_le_bytes());
    bytes.extend_from_slice(&version.1.to_le_bytes());
    bytes.extend_from_slice(&version.2.to_le_bytes());
}

#[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
mod tests {
    use super::*;
    use crate::core::x64_gate_b_candidate_admission::{
        emit_reconstructed_candidate_correctness_for_process_tests,
        verify_reconstructed_candidate_correctness_for_tests,
    };
    use crate::core::x64_gate_b_candidate_process::{
        emit_synthetic_candidate_process_evidence_for_tests,
        verify_x64_gate_b_policy15_candidate_process_evidence,
    };
    use crate::core::x64_gate_b_candidate_standalone_artifact::{
        build_x64_gate_b_policy15_standalone_artifact,
        verify_x64_gate_b_policy15_standalone_artifact,
    };
    use crate::core::x64_gate_b_candidate_standalone_authority::authorize_x64_gate_b_policy15_standalone;

    #[test]
    fn direct_candidate_records_reject_resealed_semantic_and_order_mutations() {
        let correctness = emit_reconstructed_candidate_correctness_for_process_tests().unwrap();
        let verified_correctness =
            verify_reconstructed_candidate_correctness_for_tests(&correctness).unwrap();
        let process =
            emit_synthetic_candidate_process_evidence_for_tests(verified_correctness).unwrap();
        let verified_process =
            verify_x64_gate_b_policy15_candidate_process_evidence(verified_correctness, &process)
                .unwrap();
        let branch = authorize_x64_gate_b_policy15_standalone(
            verified_correctness,
            verified_process,
            X64StandaloneProfile::BranchMix,
        )
        .unwrap();
        let bounds = authorize_x64_gate_b_policy15_standalone(
            verified_correctness,
            verified_process,
            X64StandaloneProfile::Bounds,
        )
        .unwrap();
        let branch_image = build_x64_gate_b_policy15_standalone_artifact(&branch).unwrap();
        let bounds_image = build_x64_gate_b_policy15_standalone_artifact(&bounds).unwrap();
        let branch_artifact =
            verify_x64_gate_b_policy15_standalone_artifact(&branch, branch_image.image_bytes())
                .unwrap();
        let bounds_artifact =
            verify_x64_gate_b_policy15_standalone_artifact(&bounds, bounds_image.image_bytes())
                .unwrap();
        let evidence = emit_x64_gate_b_policy15_standalone_process_evidence(
            &branch,
            &branch_artifact,
            &bounds,
            &bounds_artifact,
        )
        .unwrap();
        verify_x64_gate_b_policy15_standalone_process_evidence(
            &branch,
            &branch_artifact,
            &bounds,
            &bounds_artifact,
            &evidence,
        )
        .unwrap();

        let mut wrong_input = evidence.clone();
        wrong_input.records[0].input_hash = SemanticHash::ZERO;
        wrong_input.records[0].record_hash = standalone_record_hash(&wrong_input.records[0]);
        wrong_input.results_hash = standalone_results_hash(&wrong_input);
        assert!(verify_x64_gate_b_policy15_standalone_process_evidence(
            &branch,
            &branch_artifact,
            &bounds,
            &bounds_artifact,
            &wrong_input,
        )
        .is_err());

        let mut wrong_upstream = evidence.clone();
        wrong_upstream.records[0].correctness_record_hash = evidence.records[1].record_hash;
        wrong_upstream.records[0].record_hash = standalone_record_hash(&wrong_upstream.records[0]);
        wrong_upstream.results_hash = standalone_results_hash(&wrong_upstream);
        assert!(verify_x64_gate_b_policy15_standalone_process_evidence(
            &branch,
            &branch_artifact,
            &bounds,
            &bounds_artifact,
            &wrong_upstream,
        )
        .is_err());

        let mut wrong_output = evidence.clone();
        wrong_output.records[0].output_frame[0] ^= 1;
        wrong_output.records[0].output_frame_hash =
            hash_bytes(&wrong_output.records[0].output_frame);
        wrong_output.records[0].record_hash = standalone_record_hash(&wrong_output.records[0]);
        wrong_output.results_hash = standalone_results_hash(&wrong_output);
        assert!(verify_x64_gate_b_policy15_standalone_process_evidence(
            &branch,
            &branch_artifact,
            &bounds,
            &bounds_artifact,
            &wrong_output,
        )
        .is_err());

        let mut reordered = evidence.clone();
        reordered.records.swap(0, 1);
        reordered.results_hash = standalone_results_hash(&reordered);
        assert!(verify_x64_gate_b_policy15_standalone_process_evidence(
            &branch,
            &branch_artifact,
            &bounds,
            &bounds_artifact,
            &reordered,
        )
        .is_err());

        let mut wrong_root = evidence.clone();
        wrong_root.process_results_hash = SemanticHash::ZERO;
        wrong_root.results_hash = standalone_results_hash(&wrong_root);
        assert!(verify_x64_gate_b_policy15_standalone_process_evidence(
            &branch,
            &branch_artifact,
            &bounds,
            &bounds_artifact,
            &wrong_root,
        )
        .is_err());

        println!(
            "ADR-0054 fast direct results={} branch={} bounds={}",
            evidence.results_hash.to_hex(),
            branch_artifact.artifact_hash().to_hex(),
            bounds_artifact.artifact_hash().to_hex(),
        );
    }
}
