//! Finite native-correctness admission for the policy-1.5 candidate.
//!
//! This is the sole consumer of the crate-private candidate execution seam.
//! It owns no general execution, process, standalone, ELF, or timing authority.

use super::corevm0_gate_a::{
    corevm0_gate_a_manifest, CoreVmGateAError, CoreVmGateAWorkload, COREVM0_GATE_A_BOUNDS_CASES,
    COREVM0_GATE_A_TOTAL_CASES,
};
use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_gate_b_candidate::{
    verify_x64_gate_b_policy15_candidate_capsule, X64GateBPolicy15CandidateError,
};
use super::x64_native::{
    execute_x64_native_policy14_candidate_fallback, execute_x64_native_policy15_candidate,
    execute_x64_native_policy15_process_reconstruction, normalize_native_observation,
    validate_native_observation, X64NativeCorrespondenceEffect, X64NativeCorrespondenceF64,
    X64NativeCorrespondenceObservation, X64NativeCorrespondenceOutcome, X64NativeEvidenceError,
    X64NativeExecution, X64NativeMappingState, X64NativeRunnerError,
    X64_NATIVE_ENTRY_POLICY_VERSION, X64_NATIVE_RUNNER_POLICY_VERSION,
    X64_NATIVE_RUNNER_SCHEMA_VERSION, X64_NATIVE_SYSCALL_POLICY_VERSION,
};
use super::x64_native_lighthouse::{
    x64_native_lighthouse_case, X64NativeLighthouseError, X64NativeLighthousePackage,
};
use super::x64_target::{
    reconstruct_frozen_x64_target_policy15_candidate_for_process,
    ProcessReconstructedX64TargetPolicy15Candidate, VerifiedX64TargetPolicy15CandidateCapsule,
    X64TargetAbi, X64TargetPolicy15CandidateCapsule, X64_TARGET_ENCODER_POLICY_VERSION,
    X64_TARGET_POLICY15_ENCODER_POLICY_VERSION,
};
use std::fmt;

pub const X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_CASES: u32 = COREVM0_GATE_A_TOTAL_CASES;
pub const X64_GATE_B_POLICY15_CANDIDATE_FALLBACK_CASES: u32 = COREVM0_GATE_A_BOUNDS_CASES;
pub const X64_GATE_B_POLICY15_CANDIDATE_EXECUTION_CASES: u32 =
    COREVM0_GATE_A_TOTAL_CASES - COREVM0_GATE_A_BOUNDS_CASES;

const RECORD_DOMAIN: &[u8] = b"NAUX:x86-64:policy-1.5:candidate-correctness:record:v1\0";
const RESULTS_DOMAIN: &[u8] = b"NAUX:x86-64:policy-1.5:candidate-correctness:results:v1\0";
const FROZEN_CORRECTNESS_RESULTS_HASH: SemanticHash = SemanticHash([
    0x35, 0x01, 0x8a, 0xd7, 0x57, 0x1d, 0xe6, 0xe9, 0x46, 0xf7, 0x0d, 0xd5, 0xdb, 0x23, 0x7e, 0x8a,
    0x52, 0x02, 0x44, 0x47, 0xbc, 0xce, 0x01, 0x3d, 0x65, 0x22, 0x8a, 0xab, 0xa5, 0xe3, 0x61, 0xba,
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64GateBPolicy15CandidateSelection {
    Policy15Candidate,
    Policy14Fallback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64GateBPolicy15CandidateCorrectnessRecord {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    runner_schema_version: (u16, u16, u16),
    runner_policy_version: (u16, u16, u16),
    syscall_policy_version: (u16, u16, u16),
    entry_policy_version: (u16, u16, u16),
    case_ordinal: u32,
    workload: CoreVmGateAWorkload,
    selection: X64GateBPolicy15CandidateSelection,
    input_hash: SemanticHash,
    candidate_capsule_hash: SemanticHash,
    source_machine_ir_hash: SemanticHash,
    baseline_target_semantic_hash: SemanticHash,
    executed_target_semantic_hash: SemanticHash,
    executed_target_plan_hash: SemanticHash,
    executed_target_code_hash: SemanticHash,
    copied_rw_code_hash: SemanticHash,
    readback_rx_code_hash: SemanticHash,
    input_lanes: u8,
    mapping_trace: [X64NativeMappingState; 4],
    mxcsr_before: u32,
    mxcsr_after: u32,
    machine_ir: X64NativeCorrespondenceObservation,
    native: X64NativeCorrespondenceObservation,
    record_hash: SemanticHash,
}

impl X64GateBPolicy15CandidateCorrectnessRecord {
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

    pub const fn candidate_capsule_hash(&self) -> SemanticHash {
        self.candidate_capsule_hash
    }

    pub const fn source_machine_ir_hash(&self) -> SemanticHash {
        self.source_machine_ir_hash
    }

    pub const fn executed_target_semantic_hash(&self) -> SemanticHash {
        self.executed_target_semantic_hash
    }

    pub const fn executed_target_plan_hash(&self) -> SemanticHash {
        self.executed_target_plan_hash
    }

    pub const fn executed_target_code_hash(&self) -> SemanticHash {
        self.executed_target_code_hash
    }

    pub const fn record_hash(&self) -> SemanticHash {
        self.record_hash
    }

    pub const fn machine_ir(&self) -> &X64NativeCorrespondenceObservation {
        &self.machine_ir
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64GateBPolicy15CandidateCorrectnessEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    corpus_manifest_hash: SemanticHash,
    candidate_capsule_hash: SemanticHash,
    candidate_target_semantic_hash: SemanticHash,
    candidate_target_plan_hash: SemanticHash,
    candidate_target_code_hash: SemanticHash,
    branch_baseline_target_semantic_hash: SemanticHash,
    bounds_fallback_target_semantic_hash: SemanticHash,
    candidate_execution_cases: u32,
    fallback_cases: u32,
    records: Vec<X64GateBPolicy15CandidateCorrectnessRecord>,
    results_hash: SemanticHash,
}

impl X64GateBPolicy15CandidateCorrectnessEvidence {
    pub const fn corpus_manifest_hash(&self) -> SemanticHash {
        self.corpus_manifest_hash
    }

    pub const fn candidate_capsule_hash(&self) -> SemanticHash {
        self.candidate_capsule_hash
    }

    pub const fn candidate_target_semantic_hash(&self) -> SemanticHash {
        self.candidate_target_semantic_hash
    }

    pub const fn candidate_target_plan_hash(&self) -> SemanticHash {
        self.candidate_target_plan_hash
    }

    pub const fn candidate_target_code_hash(&self) -> SemanticHash {
        self.candidate_target_code_hash
    }

    pub const fn branch_baseline_target_semantic_hash(&self) -> SemanticHash {
        self.branch_baseline_target_semantic_hash
    }

    pub const fn bounds_fallback_target_semantic_hash(&self) -> SemanticHash {
        self.bounds_fallback_target_semantic_hash
    }

    pub const fn candidate_execution_cases(&self) -> u32 {
        self.candidate_execution_cases
    }

    pub const fn fallback_cases(&self) -> u32 {
        self.fallback_cases
    }

    pub fn records(&self) -> &[X64GateBPolicy15CandidateCorrectnessRecord] {
        &self.records
    }

    pub const fn results_hash(&self) -> SemanticHash {
        self.results_hash
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedX64GateBPolicy15CandidateCorrectness<'evidence> {
    evidence: &'evidence X64GateBPolicy15CandidateCorrectnessEvidence,
}

impl<'evidence> VerifiedX64GateBPolicy15CandidateCorrectness<'evidence> {
    pub const fn evidence(self) -> &'evidence X64GateBPolicy15CandidateCorrectnessEvidence {
        self.evidence
    }
}

/// Frozen ADR-0052 aggregate identity carried by every ADR-0053 child frame.
pub const fn x64_gate_b_policy15_candidate_accepted_correctness_results_hash() -> SemanticHash {
    FROZEN_CORRECTNESS_RESULTS_HASH
}

#[derive(Debug)]
pub enum X64GateBPolicy15CandidateCorrectnessError {
    Candidate(X64GateBPolicy15CandidateError),
    Corpus(CoreVmGateAError),
    Lighthouse(String),
    Native(X64NativeRunnerError),
    NativeEvidence(X64NativeEvidenceError),
    InvalidField { field: &'static str },
    NonCanonicalOrdinal { expected: u32, actual: u32 },
    InvalidSelection { case_ordinal: u32 },
    SemanticMismatch { case_ordinal: u32 },
    RecordHashMismatch { case_ordinal: u32 },
    ResultsHashMismatch,
    ReplayMismatch,
    MetricOverflow,
}

impl fmt::Display for X64GateBPolicy15CandidateCorrectnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Candidate(error) => write!(formatter, "{error}"),
            Self::Corpus(error) => write!(formatter, "cannot regenerate Gate A corpus: {error}"),
            Self::Lighthouse(error) => write!(formatter, "candidate lighthouse failed: {error}"),
            Self::Native(error) => write!(formatter, "candidate native execution failed: {error}"),
            Self::NativeEvidence(error) => write!(formatter, "{error}"),
            Self::InvalidField { field } => {
                write!(formatter, "candidate correctness has invalid {field}")
            }
            Self::NonCanonicalOrdinal { expected, actual } => write!(
                formatter,
                "candidate correctness expected case {expected}, found {actual}"
            ),
            Self::InvalidSelection { case_ordinal } => write!(
                formatter,
                "candidate correctness case {case_ordinal} uses the wrong execution authority"
            ),
            Self::SemanticMismatch { case_ordinal } => write!(
                formatter,
                "candidate native execution differs from Machine IR in case {case_ordinal}"
            ),
            Self::RecordHashMismatch { case_ordinal } => write!(
                formatter,
                "candidate correctness record {case_ordinal} has an invalid seal"
            ),
            Self::ResultsHashMismatch => {
                formatter.write_str("candidate correctness aggregate seal is invalid")
            }
            Self::ReplayMismatch => formatter.write_str(
                "candidate correctness evidence differs from complete independent regeneration",
            ),
            Self::MetricOverflow => formatter.write_str("candidate correctness metric overflow"),
        }
    }
}

impl std::error::Error for X64GateBPolicy15CandidateCorrectnessError {}

impl From<X64GateBPolicy15CandidateError> for X64GateBPolicy15CandidateCorrectnessError {
    fn from(value: X64GateBPolicy15CandidateError) -> Self {
        Self::Candidate(value)
    }
}

impl From<CoreVmGateAError> for X64GateBPolicy15CandidateCorrectnessError {
    fn from(value: CoreVmGateAError) -> Self {
        Self::Corpus(value)
    }
}

impl From<X64NativeRunnerError> for X64GateBPolicy15CandidateCorrectnessError {
    fn from(value: X64NativeRunnerError) -> Self {
        Self::Native(value)
    }
}

impl From<X64NativeEvidenceError> for X64GateBPolicy15CandidateCorrectnessError {
    fn from(value: X64NativeEvidenceError) -> Self {
        Self::NativeEvidence(value)
    }
}

impl From<X64NativeLighthouseError> for X64GateBPolicy15CandidateCorrectnessError {
    fn from(value: X64NativeLighthouseError) -> Self {
        Self::Lighthouse(value.to_string())
    }
}

/// Verify a capsule through fresh Gate B replay, then execute the fixed
/// 51-case candidate/fallback table and seal its Machine-IR correspondence.
pub fn emit_x64_gate_b_policy15_candidate_correctness(
    candidate: &X64TargetPolicy15CandidateCapsule,
) -> Result<X64GateBPolicy15CandidateCorrectnessEvidence, X64GateBPolicy15CandidateCorrectnessError>
{
    let verified = verify_x64_gate_b_policy15_candidate_capsule(candidate)?;
    emit_from_verified_candidate(verified)
}

/// Independently regenerate the verified capsule and all 51 native records.
pub fn verify_x64_gate_b_policy15_candidate_correctness<'evidence>(
    candidate: &X64TargetPolicy15CandidateCapsule,
    evidence: &'evidence X64GateBPolicy15CandidateCorrectnessEvidence,
) -> Result<
    VerifiedX64GateBPolicy15CandidateCorrectness<'evidence>,
    X64GateBPolicy15CandidateCorrectnessError,
> {
    let verified = verify_x64_gate_b_policy15_candidate_capsule(candidate)?;
    validate_evidence_shape(verified, evidence)?;
    let replayed = emit_from_verified_candidate(verified)?;
    if replayed != *evidence {
        return Err(X64GateBPolicy15CandidateCorrectnessError::ReplayMismatch);
    }
    Ok(VerifiedX64GateBPolicy15CandidateCorrectness { evidence })
}

/// ADR-0053 child-side reconstruction and execution for one canonical case.
/// The only caller input is an ordinal; candidate bytes, selection, input,
/// identities, and policies are regenerated internally.
#[doc(hidden)]
pub fn emit_x64_gate_b_policy15_candidate_process_record(
    case_ordinal: u32,
) -> Result<X64GateBPolicy15CandidateCorrectnessRecord, X64GateBPolicy15CandidateCorrectnessError> {
    let case = x64_native_lighthouse_case(case_ordinal)?;
    let branch = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)?;
    let bounds = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BoundsOrderedArrayGet)?;
    let reconstructed =
        reconstruct_frozen_x64_target_policy15_candidate_for_process(branch.source_bound()?)
            .map_err(X64GateBPolicy15CandidateError::Candidate)?;
    emit_process_record_with_reconstruction(&case, &branch, &bounds, &reconstructed)
}

fn emit_process_record_with_reconstruction(
    case: &super::corevm0_gate_a::CoreVmGateACase,
    branch: &X64NativeLighthousePackage,
    bounds: &X64NativeLighthousePackage,
    reconstructed: &ProcessReconstructedX64TargetPolicy15Candidate,
) -> Result<X64GateBPolicy15CandidateCorrectnessRecord, X64GateBPolicy15CandidateCorrectnessError> {
    let capsule = reconstructed.candidate();
    let (package, selection, execution) = match case.workload {
        CoreVmGateAWorkload::BranchMix => {
            let arguments = branch.case_arguments(case)?;
            let execution =
                execute_x64_native_policy15_process_reconstruction(reconstructed, &arguments)?;
            (
                &branch,
                X64GateBPolicy15CandidateSelection::Policy15Candidate,
                execution,
            )
        }
        CoreVmGateAWorkload::BoundsOrderedArrayGet => {
            let execution =
                execute_x64_native_policy14_candidate_fallback(bounds.source_bound()?, case)?;
            (
                &bounds,
                X64GateBPolicy15CandidateSelection::Policy14Fallback,
                execution.execution().clone(),
            )
        }
    };
    seal_correctness_record(case, package, capsule, selection, execution)
}

#[cfg(test)]
pub(super) fn emit_reconstructed_candidate_correctness_for_process_tests(
) -> Result<X64GateBPolicy15CandidateCorrectnessEvidence, X64GateBPolicy15CandidateCorrectnessError>
{
    let manifest = corevm0_gate_a_manifest()?;
    let branch = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)?;
    let bounds = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BoundsOrderedArrayGet)?;
    let reconstructed =
        reconstruct_frozen_x64_target_policy15_candidate_for_process(branch.source_bound()?)
            .map_err(X64GateBPolicy15CandidateError::Candidate)?;
    let capsule = reconstructed.candidate();
    let artifact = capsule.candidate_artifact();
    let mut records = Vec::with_capacity(manifest.cases.len());
    for case in &manifest.cases {
        records.push(emit_process_record_with_reconstruction(
            case,
            &branch,
            &bounds,
            &reconstructed,
        )?);
    }
    let mut evidence = X64GateBPolicy15CandidateCorrectnessEvidence {
        schema_version: X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_SCHEMA_VERSION,
        policy_version: X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_POLICY_VERSION,
        corpus_manifest_hash: manifest.manifest_hash,
        candidate_capsule_hash: capsule.capsule_hash(),
        candidate_target_semantic_hash: artifact.semantic_hash,
        candidate_target_plan_hash: artifact.program.plan_hash,
        candidate_target_code_hash: artifact.program.code_hash,
        branch_baseline_target_semantic_hash: branch.target().semantic_hash,
        bounds_fallback_target_semantic_hash: bounds.target().semantic_hash,
        candidate_execution_cases: X64_GATE_B_POLICY15_CANDIDATE_EXECUTION_CASES,
        fallback_cases: X64_GATE_B_POLICY15_CANDIDATE_FALLBACK_CASES,
        records,
        results_hash: SemanticHash::ZERO,
    };
    evidence.results_hash = x64_gate_b_policy15_candidate_correctness_results_hash(&evidence)?;
    if evidence.results_hash != FROZEN_CORRECTNESS_RESULTS_HASH {
        return Err(X64GateBPolicy15CandidateCorrectnessError::ResultsHashMismatch);
    }
    Ok(evidence)
}

#[cfg(test)]
pub(super) fn verify_reconstructed_candidate_correctness_for_tests<'evidence>(
    evidence: &'evidence X64GateBPolicy15CandidateCorrectnessEvidence,
) -> Result<
    VerifiedX64GateBPolicy15CandidateCorrectness<'evidence>,
    X64GateBPolicy15CandidateCorrectnessError,
> {
    let replayed = emit_reconstructed_candidate_correctness_for_process_tests()?;
    if replayed != *evidence {
        return Err(X64GateBPolicy15CandidateCorrectnessError::ReplayMismatch);
    }
    Ok(VerifiedX64GateBPolicy15CandidateCorrectness { evidence })
}

fn emit_from_verified_candidate(
    candidate: VerifiedX64TargetPolicy15CandidateCapsule<'_>,
) -> Result<X64GateBPolicy15CandidateCorrectnessEvidence, X64GateBPolicy15CandidateCorrectnessError>
{
    let manifest = corevm0_gate_a_manifest()?;
    if manifest.total_cases != X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_CASES
        || manifest.cases.len() != X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_CASES as usize
    {
        return Err(X64GateBPolicy15CandidateCorrectnessError::InvalidField {
            field: "fixed corpus size",
        });
    }
    let branch = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)?;
    let bounds = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BoundsOrderedArrayGet)?;
    let capsule = candidate.candidate();
    let candidate_artifact = capsule.candidate_artifact();

    if candidate_artifact.program.encoder_policy_version
        != X64_TARGET_POLICY15_ENCODER_POLICY_VERSION
        || branch.target().program.encoder_policy_version != X64_TARGET_ENCODER_POLICY_VERSION
        || bounds.target().program.encoder_policy_version != X64_TARGET_ENCODER_POLICY_VERSION
        || candidate_artifact.program.source_machine_ir_hash != branch.machine_ir().semantic_hash
        || capsule.baseline_target_semantic_hash() != branch.target().semantic_hash
    {
        return Err(X64GateBPolicy15CandidateCorrectnessError::InvalidField {
            field: "candidate/source policy envelope",
        });
    }

    let mut records = Vec::with_capacity(manifest.cases.len());
    let mut candidate_execution_cases = 0_u32;
    let mut fallback_cases = 0_u32;
    for (index, case) in manifest.cases.iter().enumerate() {
        let expected = u32::try_from(index)
            .map_err(|_| X64GateBPolicy15CandidateCorrectnessError::MetricOverflow)?;
        if case.ordinal != expected {
            return Err(
                X64GateBPolicy15CandidateCorrectnessError::NonCanonicalOrdinal {
                    expected,
                    actual: case.ordinal,
                },
            );
        }
        let (package, selection, execution) = match case.workload {
            CoreVmGateAWorkload::BranchMix => {
                let arguments = branch.case_arguments(case)?;
                let execution = execute_x64_native_policy15_candidate(candidate, &arguments)?;
                candidate_execution_cases = candidate_execution_cases
                    .checked_add(1)
                    .ok_or(X64GateBPolicy15CandidateCorrectnessError::MetricOverflow)?;
                (
                    &branch,
                    X64GateBPolicy15CandidateSelection::Policy15Candidate,
                    execution,
                )
            }
            CoreVmGateAWorkload::BoundsOrderedArrayGet => {
                let case_execution =
                    execute_x64_native_policy14_candidate_fallback(bounds.source_bound()?, case)?;
                fallback_cases = fallback_cases
                    .checked_add(1)
                    .ok_or(X64GateBPolicy15CandidateCorrectnessError::MetricOverflow)?;
                (
                    &bounds,
                    X64GateBPolicy15CandidateSelection::Policy14Fallback,
                    case_execution.execution().clone(),
                )
            }
        };
        records.push(seal_correctness_record(
            case, package, capsule, selection, execution,
        )?);
    }

    if candidate_execution_cases != X64_GATE_B_POLICY15_CANDIDATE_EXECUTION_CASES
        || fallback_cases != X64_GATE_B_POLICY15_CANDIDATE_FALLBACK_CASES
    {
        return Err(X64GateBPolicy15CandidateCorrectnessError::InvalidField {
            field: "candidate/fallback case counts",
        });
    }

    let mut evidence = X64GateBPolicy15CandidateCorrectnessEvidence {
        schema_version: X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_SCHEMA_VERSION,
        policy_version: X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_POLICY_VERSION,
        corpus_manifest_hash: manifest.manifest_hash,
        candidate_capsule_hash: capsule.capsule_hash(),
        candidate_target_semantic_hash: candidate_artifact.semantic_hash,
        candidate_target_plan_hash: candidate_artifact.program.plan_hash,
        candidate_target_code_hash: candidate_artifact.program.code_hash,
        branch_baseline_target_semantic_hash: branch.target().semantic_hash,
        bounds_fallback_target_semantic_hash: bounds.target().semantic_hash,
        candidate_execution_cases,
        fallback_cases,
        records,
        results_hash: SemanticHash::ZERO,
    };
    evidence.results_hash = x64_gate_b_policy15_candidate_correctness_results_hash(&evidence)?;
    validate_evidence_shape(candidate, &evidence)?;
    Ok(evidence)
}

fn seal_correctness_record(
    case: &super::corevm0_gate_a::CoreVmGateACase,
    package: &X64NativeLighthousePackage,
    capsule: &X64TargetPolicy15CandidateCapsule,
    selection: X64GateBPolicy15CandidateSelection,
    execution: X64NativeExecution,
) -> Result<X64GateBPolicy15CandidateCorrectnessRecord, X64GateBPolicy15CandidateCorrectnessError> {
    let machine_evaluation = package.evaluate_machine_ir_case(case)?;
    let machine_ir = normalize_native_observation(
        "candidate reference Machine IR",
        case.ordinal,
        &machine_evaluation.outcome,
        &machine_evaluation.effect_trace,
    )?;
    let native = normalize_native_observation(
        "candidate native execution",
        case.ordinal,
        execution.outcome(),
        execution.effect_trace(),
    )?;
    if machine_ir != native {
        return Err(
            X64GateBPolicy15CandidateCorrectnessError::SemanticMismatch {
                case_ordinal: case.ordinal,
            },
        );
    }

    let mut record = X64GateBPolicy15CandidateCorrectnessRecord {
        schema_version: X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_SCHEMA_VERSION,
        policy_version: X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_POLICY_VERSION,
        runner_schema_version: X64_NATIVE_RUNNER_SCHEMA_VERSION,
        runner_policy_version: X64_NATIVE_RUNNER_POLICY_VERSION,
        syscall_policy_version: X64_NATIVE_SYSCALL_POLICY_VERSION,
        entry_policy_version: X64_NATIVE_ENTRY_POLICY_VERSION,
        case_ordinal: case.ordinal,
        workload: case.workload,
        selection,
        input_hash: case.input_hash,
        candidate_capsule_hash: capsule.capsule_hash(),
        source_machine_ir_hash: package.machine_ir().semantic_hash,
        baseline_target_semantic_hash: package.target().semantic_hash,
        executed_target_semantic_hash: execution.target_artifact_hash(),
        executed_target_plan_hash: execution.target_plan_hash(),
        executed_target_code_hash: execution.verified_code_hash(),
        copied_rw_code_hash: execution.copied_rw_code_hash(),
        readback_rx_code_hash: execution.readback_rx_code_hash(),
        input_lanes: execution.input_lanes(),
        mapping_trace: execution.mapping_trace(),
        mxcsr_before: execution.mxcsr_before(),
        mxcsr_after: execution.mxcsr_after(),
        machine_ir,
        native,
        record_hash: SemanticHash::ZERO,
    };
    validate_record_against_sources(&record, case, package, capsule)?;
    record.record_hash = x64_gate_b_policy15_candidate_correctness_record_hash(&record)?;
    Ok(record)
}

pub fn x64_gate_b_policy15_candidate_correctness_record_hash(
    record: &X64GateBPolicy15CandidateCorrectnessRecord,
) -> Result<SemanticHash, X64GateBPolicy15CandidateCorrectnessError> {
    validate_record_shape(record)?;
    let mut bytes = Vec::with_capacity(RECORD_DOMAIN.len() + 512);
    bytes.extend_from_slice(RECORD_DOMAIN);
    put_version(&mut bytes, record.schema_version);
    put_version(&mut bytes, record.policy_version);
    put_version(&mut bytes, record.runner_schema_version);
    put_version(&mut bytes, record.runner_policy_version);
    put_version(&mut bytes, record.syscall_policy_version);
    put_version(&mut bytes, record.entry_policy_version);
    put_u32(&mut bytes, record.case_ordinal);
    bytes.push(workload_tag(record.workload));
    bytes.push(selection_tag(record.selection));
    for hash in [
        record.input_hash,
        record.candidate_capsule_hash,
        record.source_machine_ir_hash,
        record.baseline_target_semantic_hash,
        record.executed_target_semantic_hash,
        record.executed_target_plan_hash,
        record.executed_target_code_hash,
        record.copied_rw_code_hash,
        record.readback_rx_code_hash,
    ] {
        put_hash(&mut bytes, hash);
    }
    bytes.push(record.input_lanes);
    for state in record.mapping_trace {
        bytes.push(mapping_state_tag(state));
    }
    put_u32(&mut bytes, record.mxcsr_before);
    put_u32(&mut bytes, record.mxcsr_after);
    encode_observation(&mut bytes, &record.machine_ir)?;
    encode_observation(&mut bytes, &record.native)?;
    Ok(SemanticHash(sha256(&bytes)))
}

pub fn x64_gate_b_policy15_candidate_correctness_results_hash(
    evidence: &X64GateBPolicy15CandidateCorrectnessEvidence,
) -> Result<SemanticHash, X64GateBPolicy15CandidateCorrectnessError> {
    validate_evidence_envelope(evidence)?;
    let mut bytes = Vec::with_capacity(RESULTS_DOMAIN.len() + 320 + evidence.records.len() * 32);
    bytes.extend_from_slice(RESULTS_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    for hash in [
        evidence.corpus_manifest_hash,
        evidence.candidate_capsule_hash,
        evidence.candidate_target_semantic_hash,
        evidence.candidate_target_plan_hash,
        evidence.candidate_target_code_hash,
        evidence.branch_baseline_target_semantic_hash,
        evidence.bounds_fallback_target_semantic_hash,
    ] {
        put_hash(&mut bytes, hash);
    }
    put_u32(&mut bytes, evidence.candidate_execution_cases);
    put_u32(&mut bytes, evidence.fallback_cases);
    put_u32(
        &mut bytes,
        u32::try_from(evidence.records.len())
            .map_err(|_| X64GateBPolicy15CandidateCorrectnessError::MetricOverflow)?,
    );
    for record in &evidence.records {
        put_hash(&mut bytes, record.record_hash);
    }
    Ok(SemanticHash(sha256(&bytes)))
}

fn validate_evidence_shape(
    candidate: VerifiedX64TargetPolicy15CandidateCapsule<'_>,
    evidence: &X64GateBPolicy15CandidateCorrectnessEvidence,
) -> Result<(), X64GateBPolicy15CandidateCorrectnessError> {
    validate_evidence_envelope(evidence)?;
    let manifest = corevm0_gate_a_manifest()?;
    let branch = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)?;
    let bounds = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BoundsOrderedArrayGet)?;
    let capsule = candidate.candidate();
    let artifact = capsule.candidate_artifact();
    if evidence.corpus_manifest_hash != manifest.manifest_hash
        || evidence.candidate_capsule_hash != capsule.capsule_hash()
        || evidence.candidate_target_semantic_hash != artifact.semantic_hash
        || evidence.candidate_target_plan_hash != artifact.program.plan_hash
        || evidence.candidate_target_code_hash != artifact.program.code_hash
        || evidence.branch_baseline_target_semantic_hash != capsule.baseline_target_semantic_hash()
        || evidence.branch_baseline_target_semantic_hash != branch.target().semantic_hash
        || evidence.bounds_fallback_target_semantic_hash != bounds.target().semantic_hash
    {
        return Err(X64GateBPolicy15CandidateCorrectnessError::InvalidField {
            field: "aggregate source identities",
        });
    }
    let mut candidate_count = 0_u32;
    let mut fallback_count = 0_u32;
    for (index, (case, record)) in manifest.cases.iter().zip(&evidence.records).enumerate() {
        let expected = u32::try_from(index)
            .map_err(|_| X64GateBPolicy15CandidateCorrectnessError::MetricOverflow)?;
        if record.case_ordinal != expected || case.ordinal != expected {
            return Err(
                X64GateBPolicy15CandidateCorrectnessError::NonCanonicalOrdinal {
                    expected,
                    actual: record.case_ordinal,
                },
            );
        }
        if record.workload != case.workload
            || record.input_hash != case.input_hash
            || record.candidate_capsule_hash != evidence.candidate_capsule_hash
        {
            return Err(X64GateBPolicy15CandidateCorrectnessError::InvalidField {
                field: "record corpus binding",
            });
        }
        let expected_selection = match case.workload {
            CoreVmGateAWorkload::BranchMix => {
                candidate_count = candidate_count
                    .checked_add(1)
                    .ok_or(X64GateBPolicy15CandidateCorrectnessError::MetricOverflow)?;
                X64GateBPolicy15CandidateSelection::Policy15Candidate
            }
            CoreVmGateAWorkload::BoundsOrderedArrayGet => {
                fallback_count = fallback_count
                    .checked_add(1)
                    .ok_or(X64GateBPolicy15CandidateCorrectnessError::MetricOverflow)?;
                X64GateBPolicy15CandidateSelection::Policy14Fallback
            }
        };
        if record.selection != expected_selection {
            return Err(
                X64GateBPolicy15CandidateCorrectnessError::InvalidSelection {
                    case_ordinal: record.case_ordinal,
                },
            );
        }
        let package = match case.workload {
            CoreVmGateAWorkload::BranchMix => &branch,
            CoreVmGateAWorkload::BoundsOrderedArrayGet => &bounds,
        };
        validate_record_against_sources(record, case, package, candidate.candidate())?;
        if record.machine_ir != record.native {
            return Err(
                X64GateBPolicy15CandidateCorrectnessError::SemanticMismatch {
                    case_ordinal: record.case_ordinal,
                },
            );
        }
        if x64_gate_b_policy15_candidate_correctness_record_hash(record)? != record.record_hash {
            return Err(
                X64GateBPolicy15CandidateCorrectnessError::RecordHashMismatch {
                    case_ordinal: record.case_ordinal,
                },
            );
        }
    }
    if candidate_count != evidence.candidate_execution_cases
        || fallback_count != evidence.fallback_cases
        || x64_gate_b_policy15_candidate_correctness_results_hash(evidence)?
            != evidence.results_hash
    {
        return Err(X64GateBPolicy15CandidateCorrectnessError::ResultsHashMismatch);
    }
    Ok(())
}

fn validate_evidence_envelope(
    evidence: &X64GateBPolicy15CandidateCorrectnessEvidence,
) -> Result<(), X64GateBPolicy15CandidateCorrectnessError> {
    if evidence.schema_version != X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_SCHEMA_VERSION
        || evidence.policy_version != X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_POLICY_VERSION
        || evidence.candidate_execution_cases != X64_GATE_B_POLICY15_CANDIDATE_EXECUTION_CASES
        || evidence.fallback_cases != X64_GATE_B_POLICY15_CANDIDATE_FALLBACK_CASES
        || evidence.records.len() != X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_CASES as usize
    {
        return Err(X64GateBPolicy15CandidateCorrectnessError::InvalidField {
            field: "aggregate envelope",
        });
    }
    for (field, hash) in [
        ("manifest hash", evidence.corpus_manifest_hash),
        ("candidate capsule hash", evidence.candidate_capsule_hash),
        (
            "candidate target semantic hash",
            evidence.candidate_target_semantic_hash,
        ),
        (
            "candidate target plan hash",
            evidence.candidate_target_plan_hash,
        ),
        (
            "candidate target code hash",
            evidence.candidate_target_code_hash,
        ),
        (
            "BranchMix baseline target hash",
            evidence.branch_baseline_target_semantic_hash,
        ),
        (
            "Bounds fallback target hash",
            evidence.bounds_fallback_target_semantic_hash,
        ),
    ] {
        require_nonzero(field, hash)?;
    }
    Ok(())
}

fn validate_record_against_sources(
    record: &X64GateBPolicy15CandidateCorrectnessRecord,
    case: &super::corevm0_gate_a::CoreVmGateACase,
    package: &X64NativeLighthousePackage,
    capsule: &X64TargetPolicy15CandidateCapsule,
) -> Result<(), X64GateBPolicy15CandidateCorrectnessError> {
    validate_record_shape(record)?;
    let candidate_artifact = capsule.candidate_artifact();
    if record.case_ordinal != case.ordinal
        || record.workload != case.workload
        || record.input_hash != case.input_hash
        || record.candidate_capsule_hash != capsule.capsule_hash()
        || record.source_machine_ir_hash != package.machine_ir().semantic_hash
        || record.baseline_target_semantic_hash != package.target().semantic_hash
        || record.executed_target_code_hash != record.copied_rw_code_hash
        || record.executed_target_code_hash != record.readback_rx_code_hash
        || record.mxcsr_before != record.mxcsr_after
        || record.mxcsr_before != package.target().program.abi.canonical_mxcsr
        || record.mapping_trace
            != [
                X64NativeMappingState::Unmapped,
                X64NativeMappingState::ReadWrite,
                X64NativeMappingState::ReadExecute,
                X64NativeMappingState::Unmapped,
            ]
    {
        return Err(X64GateBPolicy15CandidateCorrectnessError::InvalidField {
            field: "record execution/source binding",
        });
    }
    let (semantic, plan, code) = match record.selection {
        X64GateBPolicy15CandidateSelection::Policy15Candidate
            if case.workload == CoreVmGateAWorkload::BranchMix =>
        {
            (
                candidate_artifact.semantic_hash,
                candidate_artifact.program.plan_hash,
                candidate_artifact.program.code_hash,
            )
        }
        X64GateBPolicy15CandidateSelection::Policy14Fallback
            if case.workload == CoreVmGateAWorkload::BoundsOrderedArrayGet =>
        {
            (
                package.target().semantic_hash,
                package.target().program.plan_hash,
                package.target().program.code_hash,
            )
        }
        _ => {
            return Err(
                X64GateBPolicy15CandidateCorrectnessError::InvalidSelection {
                    case_ordinal: case.ordinal,
                },
            );
        }
    };
    if record.executed_target_semantic_hash != semantic
        || record.executed_target_plan_hash != plan
        || record.executed_target_code_hash != code
    {
        return Err(X64GateBPolicy15CandidateCorrectnessError::InvalidField {
            field: "selected target identity",
        });
    }
    Ok(())
}

fn validate_record_shape(
    record: &X64GateBPolicy15CandidateCorrectnessRecord,
) -> Result<(), X64GateBPolicy15CandidateCorrectnessError> {
    if record.schema_version != X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_SCHEMA_VERSION
        || record.policy_version != X64_GATE_B_POLICY15_CANDIDATE_CORRECTNESS_POLICY_VERSION
        || record.runner_schema_version != X64_NATIVE_RUNNER_SCHEMA_VERSION
        || record.runner_policy_version != X64_NATIVE_RUNNER_POLICY_VERSION
        || record.syscall_policy_version != X64_NATIVE_SYSCALL_POLICY_VERSION
        || record.entry_policy_version != X64_NATIVE_ENTRY_POLICY_VERSION
        || u32::from(record.input_lanes) > 5
        || record.executed_target_code_hash != record.copied_rw_code_hash
        || record.executed_target_code_hash != record.readback_rx_code_hash
        || record.mapping_trace
            != [
                X64NativeMappingState::Unmapped,
                X64NativeMappingState::ReadWrite,
                X64NativeMappingState::ReadExecute,
                X64NativeMappingState::Unmapped,
            ]
        || record.mxcsr_before != record.mxcsr_after
        || record.mxcsr_before != X64TargetAbi::r1_s7a().canonical_mxcsr
    {
        return Err(X64GateBPolicy15CandidateCorrectnessError::InvalidField {
            field: "record envelope",
        });
    }
    for (field, hash) in [
        ("input hash", record.input_hash),
        ("candidate capsule hash", record.candidate_capsule_hash),
        ("source Machine IR hash", record.source_machine_ir_hash),
        (
            "baseline target semantic hash",
            record.baseline_target_semantic_hash,
        ),
        (
            "executed target semantic hash",
            record.executed_target_semantic_hash,
        ),
        (
            "executed target plan hash",
            record.executed_target_plan_hash,
        ),
        (
            "executed target code hash",
            record.executed_target_code_hash,
        ),
        ("copied RW code hash", record.copied_rw_code_hash),
        ("readback RX code hash", record.readback_rx_code_hash),
    ] {
        require_nonzero(field, hash)?;
    }
    validate_native_observation(
        "candidate reference Machine IR",
        record.case_ordinal,
        &record.machine_ir,
    )?;
    validate_native_observation(
        "candidate native execution",
        record.case_ordinal,
        &record.native,
    )?;
    Ok(())
}

fn require_nonzero(
    field: &'static str,
    hash: SemanticHash,
) -> Result<(), X64GateBPolicy15CandidateCorrectnessError> {
    if hash == SemanticHash::ZERO {
        return Err(X64GateBPolicy15CandidateCorrectnessError::InvalidField { field });
    }
    Ok(())
}

fn encode_observation(
    bytes: &mut Vec<u8>,
    observation: &X64NativeCorrespondenceObservation,
) -> Result<(), X64GateBPolicy15CandidateCorrectnessError> {
    match observation.outcome {
        X64NativeCorrespondenceOutcome::ReturnF64(X64NativeCorrespondenceF64::ExactBits(bits)) => {
            bytes.push(0);
            bytes.extend_from_slice(&bits.to_be_bytes());
        }
        X64NativeCorrespondenceOutcome::ReturnF64(X64NativeCorrespondenceF64::CanonicalNaN) => {
            bytes.push(1);
        }
        X64NativeCorrespondenceOutcome::Bounds => bytes.push(2),
    }
    put_u32(
        bytes,
        u32::try_from(observation.effect_trace.len())
            .map_err(|_| X64GateBPolicy15CandidateCorrectnessError::MetricOverflow)?,
    );
    for effect in &observation.effect_trace {
        match effect {
            X64NativeCorrespondenceEffect::Bounds => bytes.push(0),
        }
    }
    Ok(())
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

const fn mapping_state_tag(state: X64NativeMappingState) -> u8 {
    match state {
        X64NativeMappingState::Unmapped => 0,
        X64NativeMappingState::ReadWrite => 1,
        X64NativeMappingState::ReadExecute => 2,
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

fn put_hash(bytes: &mut Vec<u8>, hash: SemanticHash) {
    bytes.extend_from_slice(&hash.0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::corevm0_gate_a::{
        COREVM0_GATE_A_CALL_DEPTH_LIMIT, COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
    };
    use crate::core::interpret::EvaluationBudget;
    use crate::core::x64_native_lighthouse::x64_native_lighthouse_case;
    use crate::core::x64_target::candidate::{
        build_x64_target_policy15_candidate_capsule, verify_x64_target_policy15_candidate_capsule,
    };
    use crate::core::x64_target::profile_source_bound_x64_target_plan;

    #[test]
    #[ignore = "full Gate B profile/candidate is regenerated three times around two exact 51-case native passes; run explicitly in release mode"]
    fn frozen_candidate_correctness_emits_and_independently_replays() {
        let candidate = crate::core::emit_x64_gate_b_policy15_candidate_capsule()
            .expect("frozen candidate capsule");
        let evidence = emit_x64_gate_b_policy15_candidate_correctness(&candidate)
            .expect("candidate correctness evidence");
        let verified = verify_x64_gate_b_policy15_candidate_correctness(&candidate, &evidence)
            .expect("independent candidate correctness replay");

        assert_eq!(verified.evidence(), &evidence);
        assert_eq!(evidence.records().len(), 51);
        assert_eq!(evidence.candidate_execution_cases(), 46);
        assert_eq!(evidence.fallback_cases(), 5);
        assert_eq!(
            evidence.candidate_capsule_hash().to_hex(),
            "12fce4c6336b3c34a34ad05961b4fb75ae45427ca7b75b7bace98efdab886d24"
        );
        assert_eq!(
            evidence.results_hash().to_hex(),
            "35018ad7571de6e946f70dd5db237e8a52024447bcce013d65228aaba5e361ba"
        );
    }

    fn fixture() -> (
        X64NativeLighthousePackage,
        X64TargetPolicy15CandidateCapsule,
    ) {
        let package = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("BranchMix package");
        let case = x64_native_lighthouse_case(0).expect("canonical case");
        let arguments = package.case_arguments(&case).expect("typed arguments");
        let profiled = profile_source_bound_x64_target_plan(
            package.source_bound().expect("source-bound target"),
            arguments,
            EvaluationBudget::new(
                COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
                COREVM0_GATE_A_CALL_DEPTH_LIMIT,
            ),
        )
        .expect("profile");
        let capsule = build_x64_target_policy15_candidate_capsule(
            package.source_bound().expect("source-bound target"),
            &profiled.profile,
            SemanticHash([0x52; 32]),
        )
        .expect("candidate capsule");
        (package, capsule)
    }

    fn verified_fixture<'candidate>(
        package: &X64NativeLighthousePackage,
        candidate: &'candidate X64TargetPolicy15CandidateCapsule,
    ) -> VerifiedX64TargetPolicy15CandidateCapsule<'candidate> {
        let case = x64_native_lighthouse_case(0).expect("canonical case");
        let arguments = package.case_arguments(&case).expect("typed arguments");
        let profiled = profile_source_bound_x64_target_plan(
            package.source_bound().expect("source-bound target"),
            arguments,
            EvaluationBudget::new(
                COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
                COREVM0_GATE_A_CALL_DEPTH_LIMIT,
            ),
        )
        .expect("profile");
        verify_x64_target_policy15_candidate_capsule(
            candidate,
            package.source_bound().expect("source-bound target"),
            &profiled.profile,
            SemanticHash([0x52; 32]),
        )
        .expect("verified candidate")
    }

    #[test]
    fn finite_candidate_correctness_uses_exact_candidate_and_fallback_table() {
        let (package, capsule) = fixture();
        let verified = verified_fixture(&package, &capsule);
        let evidence = emit_from_verified_candidate(verified).expect("finite evidence");
        validate_evidence_shape(verified, &evidence).expect("finite evidence replay");

        assert_eq!(evidence.records.len(), 51);
        assert_eq!(evidence.candidate_execution_cases, 46);
        assert_eq!(evidence.fallback_cases, 5);
        assert_eq!(
            evidence.records[0].selection,
            X64GateBPolicy15CandidateSelection::Policy15Candidate
        );
        assert_eq!(
            evidence.records[46].selection,
            X64GateBPolicy15CandidateSelection::Policy14Fallback
        );
        assert_eq!(
            evidence.records[0].executed_target_semantic_hash,
            capsule.candidate_artifact().semantic_hash
        );
        assert_eq!(
            evidence.records[46].executed_target_semantic_hash,
            evidence.bounds_fallback_target_semantic_hash
        );
        assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
    }

    #[test]
    fn finite_candidate_correctness_rejects_self_resealed_mutations() {
        let (package, capsule) = fixture();
        let verified = verified_fixture(&package, &capsule);
        let evidence = emit_from_verified_candidate(verified).expect("finite evidence");

        let mut wrong_selection = evidence.clone();
        wrong_selection.records[0].selection = X64GateBPolicy15CandidateSelection::Policy14Fallback;
        wrong_selection.records[0].record_hash =
            x64_gate_b_policy15_candidate_correctness_record_hash(&wrong_selection.records[0])
                .expect("resealed record");
        wrong_selection.results_hash =
            x64_gate_b_policy15_candidate_correctness_results_hash(&wrong_selection)
                .expect("resealed results");
        assert!(matches!(
            validate_evidence_shape(verified, &wrong_selection),
            Err(X64GateBPolicy15CandidateCorrectnessError::InvalidSelection { case_ordinal: 0 })
        ));

        let mut wrong_order = evidence.clone();
        wrong_order.records.swap(0, 1);
        wrong_order.results_hash =
            x64_gate_b_policy15_candidate_correctness_results_hash(&wrong_order)
                .expect("resealed results");
        assert!(matches!(
            validate_evidence_shape(verified, &wrong_order),
            Err(X64GateBPolicy15CandidateCorrectnessError::NonCanonicalOrdinal { .. })
        ));

        let mut wrong_native = evidence.clone();
        wrong_native.records[0].native = X64NativeCorrespondenceObservation {
            outcome: X64NativeCorrespondenceOutcome::Bounds,
            effect_trace: vec![X64NativeCorrespondenceEffect::Bounds],
        };
        wrong_native.records[0].record_hash =
            x64_gate_b_policy15_candidate_correctness_record_hash(&wrong_native.records[0])
                .expect("resealed record");
        wrong_native.results_hash =
            x64_gate_b_policy15_candidate_correctness_results_hash(&wrong_native)
                .expect("resealed results");
        assert!(matches!(
            validate_evidence_shape(verified, &wrong_native),
            Err(X64GateBPolicy15CandidateCorrectnessError::SemanticMismatch { case_ordinal: 0 })
        ));

        let mut wrong_capsule = evidence.clone();
        wrong_capsule.candidate_capsule_hash = SemanticHash([0x53; 32]);
        for record in &mut wrong_capsule.records {
            record.candidate_capsule_hash = wrong_capsule.candidate_capsule_hash;
            record.record_hash = x64_gate_b_policy15_candidate_correctness_record_hash(record)
                .expect("resealed record");
        }
        wrong_capsule.results_hash =
            x64_gate_b_policy15_candidate_correctness_results_hash(&wrong_capsule)
                .expect("resealed results");
        assert!(matches!(
            validate_evidence_shape(verified, &wrong_capsule),
            Err(X64GateBPolicy15CandidateCorrectnessError::InvalidField {
                field: "aggregate source identities"
            })
        ));

        let mut wrong_input = evidence.clone();
        wrong_input.records[0].input_hash = SemanticHash([0x54; 32]);
        wrong_input.records[0].record_hash =
            x64_gate_b_policy15_candidate_correctness_record_hash(&wrong_input.records[0])
                .expect("resealed record");
        wrong_input.results_hash =
            x64_gate_b_policy15_candidate_correctness_results_hash(&wrong_input)
                .expect("resealed results");
        assert!(matches!(
            validate_evidence_shape(verified, &wrong_input),
            Err(X64GateBPolicy15CandidateCorrectnessError::InvalidField {
                field: "record corpus binding"
            })
        ));

        let mut wrong_target = evidence.clone();
        wrong_target.records[0].executed_target_semantic_hash = SemanticHash([0x55; 32]);
        wrong_target.records[0].record_hash =
            x64_gate_b_policy15_candidate_correctness_record_hash(&wrong_target.records[0])
                .expect("resealed record");
        wrong_target.results_hash =
            x64_gate_b_policy15_candidate_correctness_results_hash(&wrong_target)
                .expect("resealed results");
        assert!(matches!(
            validate_evidence_shape(verified, &wrong_target),
            Err(X64GateBPolicy15CandidateCorrectnessError::InvalidField {
                field: "selected target identity"
            })
        ));

        let mut wrong_manifest = evidence.clone();
        wrong_manifest.corpus_manifest_hash = SemanticHash([0x56; 32]);
        wrong_manifest.results_hash =
            x64_gate_b_policy15_candidate_correctness_results_hash(&wrong_manifest)
                .expect("resealed results");
        assert!(matches!(
            validate_evidence_shape(verified, &wrong_manifest),
            Err(X64GateBPolicy15CandidateCorrectnessError::InvalidField {
                field: "aggregate source identities"
            })
        ));

        let mut wrong_results = evidence.clone();
        wrong_results.results_hash = SemanticHash([0x57; 32]);
        assert!(matches!(
            validate_evidence_shape(verified, &wrong_results),
            Err(X64GateBPolicy15CandidateCorrectnessError::ResultsHashMismatch)
        ));

        let mut wrong_count = evidence.clone();
        wrong_count.fallback_cases -= 1;
        assert!(matches!(
            validate_evidence_shape(verified, &wrong_count),
            Err(X64GateBPolicy15CandidateCorrectnessError::InvalidField {
                field: "aggregate envelope"
            })
        ));
    }
}
