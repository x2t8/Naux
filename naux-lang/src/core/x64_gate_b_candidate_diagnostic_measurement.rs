//! Matched fixed-process versus incremental-work timing diagnosis for
//! ADR-0056.
//!
//! This executes the exact ADR-0054 candidate and admitted hand baseline with
//! zero-work and frozen full-work inputs. The resulting deltas are diagnostic
//! evidence only: they are not target-only cycles and cannot mint a Gate B
//! claim or select an encoder policy.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_gate_b_baseline::{
    build_x64_gate_b_baseline_artifact, verify_x64_gate_b_baseline_artifact, X64GateBBaselineError,
};
use super::x64_gate_b_baseline_admission::VerifiedX64GateBBaselineAdmission;
use super::x64_gate_b_candidate_diagnosis::{
    VerifiedX64GateBPolicy15CostInventory, X64GateBSuccessorOptimizationClass,
};
use super::x64_gate_b_candidate_measurement::{validate_inputs, X64GateBPolicy15MeasurementError};
use super::x64_gate_b_candidate_standalone_artifact::VerifiedX64GateBPolicy15StandaloneArtifact;
use super::x64_gate_b_candidate_standalone_authority::X64GateBPolicy15StandaloneAuthority;
use super::x64_gate_b_candidate_standalone_process::VerifiedX64GateBPolicy15StandaloneProcess;
use super::x64_gate_b_measurement::{
    affinity_logical_cpu_count, compute_statistics, frozen_workload, put_statistics, require_host,
    X64GateBMeasurementError, X64GateBSampleStatistics, X64_GATE_B_MEASURED_PAIRS,
    X64_GATE_B_PROCESS_TIMEOUT_MILLIS, X64_GATE_B_WARMUP_PAIRS,
};
use super::x64_standalone_process::{
    run_admitted_x64_standalone_process, PreparedX64StandaloneExecutable, X64StandaloneProcessError,
};
use super::x64_standalone_protocol::{
    encode_x64_standalone_input, encode_x64_standalone_output, X64StandaloneInput,
    X64StandaloneOutcome, X64StandaloneOutput, X64StandaloneProfile, X64_STANDALONE_OUTPUT_BYTES,
};
use std::fmt;

pub const X64_GATE_B_POLICY15_DIAGNOSTIC_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_POLICY15_DIAGNOSTIC_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_POLICY15_SUCCESSOR_DECISION_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_POLICY15_SUCCESSOR_DECISION_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_POLICY15_FIXED_SYMMETRY_NUMERATOR: u32 = 5;
pub const X64_GATE_B_POLICY15_FIXED_SYMMETRY_DENOMINATOR: u32 = 4;
pub const X64_GATE_B_POLICY15_INCREMENTAL_SHARE_NUMERATOR: u32 = 3;
pub const X64_GATE_B_POLICY15_INCREMENTAL_SHARE_DENOMINATOR: u32 = 4;
pub const X64_GATE_B_POLICY15_INCREMENTAL_SLOWDOWN_NUMERATOR: u32 = 2;
pub const X64_GATE_B_POLICY15_INCREMENTAL_SLOWDOWN_DENOMINATOR: u32 = 1;

const OBSERVATION_DOMAIN: &[u8] = b"NAUX:gate-b:policy-1.5:body-process-diagnostic:v1\0";
const DECISION_DOMAIN: &[u8] = b"NAUX:gate-b:policy-1.5:successor-decision:v1\0";
const INPUT_FRAME_DOMAIN: &[u8] = b"NAUX:gate-b:policy-1.5:diagnostic:input-frame:v1\0";
const OUTPUT_FRAME_DOMAIN: &[u8] = b"NAUX:gate-b:policy-1.5:diagnostic:output-frame:v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64GateBDiagnosticMember {
    CandidateZero,
    BaselineZero,
    CandidateFull,
    BaselineFull,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64GateBDiagnosticSample {
    ordinal: u32,
    first: X64GateBDiagnosticMember,
    candidate_zero_nanoseconds: u64,
    candidate_full_nanoseconds: u64,
    baseline_zero_nanoseconds: u64,
    baseline_full_nanoseconds: u64,
    candidate_incremental_nanoseconds: u64,
    baseline_incremental_nanoseconds: u64,
    candidate_zero_output_hash: SemanticHash,
    candidate_full_output_hash: SemanticHash,
    baseline_zero_output_hash: SemanticHash,
    baseline_full_output_hash: SemanticHash,
}

impl X64GateBDiagnosticSample {
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub const fn first(&self) -> X64GateBDiagnosticMember {
        self.first
    }

    pub const fn candidate_zero_nanoseconds(&self) -> u64 {
        self.candidate_zero_nanoseconds
    }

    pub const fn candidate_full_nanoseconds(&self) -> u64 {
        self.candidate_full_nanoseconds
    }

    pub const fn baseline_zero_nanoseconds(&self) -> u64 {
        self.baseline_zero_nanoseconds
    }

    pub const fn baseline_full_nanoseconds(&self) -> u64 {
        self.baseline_full_nanoseconds
    }

    pub const fn candidate_incremental_nanoseconds(&self) -> u64 {
        self.candidate_incremental_nanoseconds
    }

    pub const fn baseline_incremental_nanoseconds(&self) -> u64 {
        self.baseline_incremental_nanoseconds
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64GateBPolicy15DiagnosticObservation {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    manifest_hash: SemanticHash,
    candidate_capsule_hash: SemanticHash,
    correctness_results_hash: SemanticHash,
    worker_process_results_hash: SemanticHash,
    standalone_process_results_hash: SemanticHash,
    candidate_artifact_hash: SemanticHash,
    candidate_elf_image_hash: SemanticHash,
    candidate_target_code_hash: SemanticHash,
    baseline_target_hash: SemanticHash,
    baseline_elf_image_hash: SemanticHash,
    baseline_artifact_hash: SemanticHash,
    baseline_admission_results_hash: SemanticHash,
    zero_input_frame_hash: SemanticHash,
    full_input_frame_hash: SemanticHash,
    zero_output_frame_hash: SemanticHash,
    full_output_frame_hash: SemanticHash,
    warmup_ordinals: u32,
    measured_ordinals: u32,
    invocations_per_ordinal: u32,
    process_timeout_millis: u32,
    rotating_schedule: bool,
    sample_deletion_permitted: bool,
    release_build: bool,
    affinity_logical_cpus: u32,
    samples: Vec<X64GateBDiagnosticSample>,
    candidate_zero_statistics: X64GateBSampleStatistics,
    candidate_full_statistics: X64GateBSampleStatistics,
    candidate_incremental_statistics: X64GateBSampleStatistics,
    baseline_zero_statistics: X64GateBSampleStatistics,
    baseline_full_statistics: X64GateBSampleStatistics,
    baseline_incremental_statistics: X64GateBSampleStatistics,
    observation_hash: SemanticHash,
}

impl X64GateBPolicy15DiagnosticObservation {
    pub fn samples(&self) -> &[X64GateBDiagnosticSample] {
        &self.samples
    }

    pub const fn candidate_zero_statistics(&self) -> X64GateBSampleStatistics {
        self.candidate_zero_statistics
    }

    pub const fn candidate_full_statistics(&self) -> X64GateBSampleStatistics {
        self.candidate_full_statistics
    }

    pub const fn candidate_incremental_statistics(&self) -> X64GateBSampleStatistics {
        self.candidate_incremental_statistics
    }

    pub const fn baseline_zero_statistics(&self) -> X64GateBSampleStatistics {
        self.baseline_zero_statistics
    }

    pub const fn baseline_full_statistics(&self) -> X64GateBSampleStatistics {
        self.baseline_full_statistics
    }

    pub const fn baseline_incremental_statistics(&self) -> X64GateBSampleStatistics {
        self.baseline_incremental_statistics
    }

    pub const fn release_build(&self) -> bool {
        self.release_build
    }

    pub const fn affinity_logical_cpus(&self) -> u32 {
        self.affinity_logical_cpus
    }

    pub const fn observation_hash(&self) -> SemanticHash {
        self.observation_hash
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedX64GateBPolicy15Diagnostic<'observation> {
    observation: &'observation X64GateBPolicy15DiagnosticObservation,
}

impl<'observation> VerifiedX64GateBPolicy15Diagnostic<'observation> {
    pub const fn observation(self) -> &'observation X64GateBPolicy15DiagnosticObservation {
        self.observation
    }
}

/// Joint structural/runtime decision. This token is proof-only and has no
/// consumer in encoding, execution, standalone packaging, claim admission,
/// or global policy selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64GateBPolicy15SuccessorDecision {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    inventory_hash: SemanticHash,
    diagnostic_observation_hash: SemanticHash,
    fixed_symmetry_numerator: u32,
    fixed_symmetry_denominator: u32,
    incremental_share_numerator: u32,
    incremental_share_denominator: u32,
    incremental_slowdown_numerator: u32,
    incremental_slowdown_denominator: u32,
    release_build: bool,
    pinned_logical_cpus: u32,
    selection: X64GateBSuccessorOptimizationClass,
    decision_hash: SemanticHash,
}

impl X64GateBPolicy15SuccessorDecision {
    pub const fn selection(&self) -> X64GateBSuccessorOptimizationClass {
        self.selection
    }

    pub const fn inventory_hash(&self) -> SemanticHash {
        self.inventory_hash
    }

    pub const fn diagnostic_observation_hash(&self) -> SemanticHash {
        self.diagnostic_observation_hash
    }

    pub const fn decision_hash(&self) -> SemanticHash {
        self.decision_hash
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedX64GateBPolicy15SuccessorDecision<'decision> {
    decision: &'decision X64GateBPolicy15SuccessorDecision,
}

impl<'decision> VerifiedX64GateBPolicy15SuccessorDecision<'decision> {
    pub const fn decision(self) -> &'decision X64GateBPolicy15SuccessorDecision {
        self.decision
    }
}

#[derive(Debug)]
pub enum X64GateBPolicy15DiagnosticError {
    Upstream(X64GateBPolicy15MeasurementError),
    Baseline(X64GateBBaselineError),
    Mechanical(X64GateBMeasurementError),
    Protocol(String),
    Process {
        member: X64GateBDiagnosticMember,
        phase: &'static str,
        ordinal: u32,
        source: X64StandaloneProcessError,
    },
    Cleanup {
        member: X64GateBDiagnosticMember,
        source: X64StandaloneProcessError,
    },
    FailureDuringCleanup {
        primary: String,
        cleanup: String,
    },
    InvalidField {
        field: &'static str,
    },
    NegativeIncrementalTime {
        member: X64GateBDiagnosticMember,
        ordinal: u32,
        zero_nanoseconds: u64,
        full_nanoseconds: u64,
    },
    SelectionRejected {
        field: &'static str,
    },
    ObservationHashMismatch,
    DecisionHashMismatch,
    DecisionReplayMismatch,
}

impl fmt::Display for X64GateBPolicy15DiagnosticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Upstream(error) => write!(formatter, "diagnostic upstream failed: {error}"),
            Self::Baseline(error) => write!(formatter, "diagnostic baseline failed: {error}"),
            Self::Mechanical(error) => write!(formatter, "diagnostic statistics failed: {error}"),
            Self::Protocol(error) => write!(formatter, "diagnostic protocol failed: {error}"),
            Self::Process {
                member,
                phase,
                ordinal,
                source,
            } => write!(
                formatter,
                "diagnostic {member:?} {phase} ordinal {ordinal} failed: {source}"
            ),
            Self::Cleanup { member, source } => {
                write!(formatter, "diagnostic {member:?} cleanup failed: {source}")
            }
            Self::FailureDuringCleanup { primary, cleanup } => write!(
                formatter,
                "diagnostic failed ({primary}) and cleanup also failed ({cleanup})"
            ),
            Self::InvalidField { field } => {
                write!(formatter, "diagnostic observation has invalid {field}")
            }
            Self::NegativeIncrementalTime {
                member,
                ordinal,
                zero_nanoseconds,
                full_nanoseconds,
            } => write!(
                formatter,
                "diagnostic {member:?} ordinal {ordinal} full time {full_nanoseconds}ns is below zero-work time {zero_nanoseconds}ns"
            ),
            Self::SelectionRejected { field } => {
                write!(formatter, "successor selection rejected by {field}")
            }
            Self::ObservationHashMismatch => {
                formatter.write_str("diagnostic observation seal does not replay")
            }
            Self::DecisionHashMismatch => {
                formatter.write_str("successor decision seal does not replay")
            }
            Self::DecisionReplayMismatch => {
                formatter.write_str("successor decision differs from joint evidence replay")
            }
        }
    }
}

impl std::error::Error for X64GateBPolicy15DiagnosticError {}

impl From<X64GateBPolicy15MeasurementError> for X64GateBPolicy15DiagnosticError {
    fn from(value: X64GateBPolicy15MeasurementError) -> Self {
        Self::Upstream(value)
    }
}

impl From<X64GateBBaselineError> for X64GateBPolicy15DiagnosticError {
    fn from(value: X64GateBBaselineError) -> Self {
        Self::Baseline(value)
    }
}

impl From<X64GateBMeasurementError> for X64GateBPolicy15DiagnosticError {
    fn from(value: X64GateBMeasurementError) -> Self {
        Self::Mechanical(value)
    }
}

struct DiagnosticWorkload {
    input_frame: Vec<u8>,
    input_frame_hash: SemanticHash,
    expected_output: X64StandaloneOutcome,
    expected_output_frame: [u8; X64_STANDALONE_OUTPUT_BYTES],
    expected_output_frame_hash: SemanticHash,
}

pub fn emit_x64_gate_b_policy15_diagnostic_observation(
    authority: &X64GateBPolicy15StandaloneAuthority<'_, '_>,
    artifact: &VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_>,
    direct_process: VerifiedX64GateBPolicy15StandaloneProcess<'_, '_, '_, '_, '_>,
    baseline_admission: VerifiedX64GateBBaselineAdmission<'_>,
) -> Result<X64GateBPolicy15DiagnosticObservation, X64GateBPolicy15DiagnosticError> {
    require_host()?;
    validate_inputs(authority, artifact, direct_process, baseline_admission)?;
    let baseline = build_x64_gate_b_baseline_artifact()?;
    let verified_baseline = verify_x64_gate_b_baseline_artifact(baseline.image_bytes())?;
    let zero = zero_workload()?;
    let full = full_workload()?;
    let affinity_logical_cpus = affinity_logical_cpu_count()?;

    let mut candidate = PreparedX64StandaloneExecutable::create(
        X64StandaloneProfile::BranchMix,
        artifact.image_bytes(),
    )
    .map_err(|source| {
        process_error(
            X64GateBDiagnosticMember::CandidateZero,
            "materialization",
            0,
            source,
        )
    })?;
    let baseline_executable = PreparedX64StandaloneExecutable::create(
        X64StandaloneProfile::BranchMix,
        verified_baseline.image_bytes(),
    );
    let mut baseline_executable = match baseline_executable {
        Ok(executable) => executable,
        Err(source) => {
            let primary = Err(process_error(
                X64GateBDiagnosticMember::BaselineZero,
                "materialization",
                0,
                source,
            ));
            let cleanup =
                candidate
                    .cleanup()
                    .map_err(|source| X64GateBPolicy15DiagnosticError::Cleanup {
                        member: X64GateBDiagnosticMember::CandidateZero,
                        source,
                    });
            return merge_cleanup(primary, cleanup);
        }
    };

    let measurement = (|| {
        for ordinal in 0..X64_GATE_B_WARMUP_PAIRS {
            let _ = execute_ordinal(
                &candidate,
                &baseline_executable,
                &zero,
                &full,
                "warmup",
                ordinal,
            )?;
        }
        let mut samples = Vec::with_capacity(X64_GATE_B_MEASURED_PAIRS as usize);
        for ordinal in 0..X64_GATE_B_MEASURED_PAIRS {
            samples.push(execute_ordinal(
                &candidate,
                &baseline_executable,
                &zero,
                &full,
                "measured",
                ordinal,
            )?);
        }
        let statistics = diagnostic_statistics(&samples)?;
        let direct = direct_process.evidence();
        let mut observation = X64GateBPolicy15DiagnosticObservation {
            schema_version: X64_GATE_B_POLICY15_DIAGNOSTIC_SCHEMA_VERSION,
            policy_version: X64_GATE_B_POLICY15_DIAGNOSTIC_POLICY_VERSION,
            manifest_hash: authority.manifest_hash(),
            candidate_capsule_hash: authority.candidate_capsule_hash(),
            correctness_results_hash: authority.correctness_results_hash(),
            worker_process_results_hash: authority.process_results_hash(),
            standalone_process_results_hash: direct.results_hash(),
            candidate_artifact_hash: artifact.artifact_hash(),
            candidate_elf_image_hash: artifact.elf_image_hash(),
            candidate_target_code_hash: artifact.target_code_hash(),
            baseline_target_hash: verified_baseline.target_hash(),
            baseline_elf_image_hash: verified_baseline.elf_image_hash(),
            baseline_artifact_hash: verified_baseline.artifact_hash(),
            baseline_admission_results_hash: baseline_admission.results_hash(),
            zero_input_frame_hash: zero.input_frame_hash,
            full_input_frame_hash: full.input_frame_hash,
            zero_output_frame_hash: zero.expected_output_frame_hash,
            full_output_frame_hash: full.expected_output_frame_hash,
            warmup_ordinals: X64_GATE_B_WARMUP_PAIRS,
            measured_ordinals: X64_GATE_B_MEASURED_PAIRS,
            invocations_per_ordinal: 4,
            process_timeout_millis: X64_GATE_B_PROCESS_TIMEOUT_MILLIS,
            rotating_schedule: true,
            sample_deletion_permitted: false,
            release_build: !cfg!(debug_assertions),
            affinity_logical_cpus,
            samples,
            candidate_zero_statistics: statistics[0],
            candidate_full_statistics: statistics[1],
            candidate_incremental_statistics: statistics[2],
            baseline_zero_statistics: statistics[3],
            baseline_full_statistics: statistics[4],
            baseline_incremental_statistics: statistics[5],
            observation_hash: SemanticHash::ZERO,
        };
        observation.observation_hash = observation_hash(&observation)?;
        let _ = verify_x64_gate_b_policy15_diagnostic_observation(
            &observation,
            authority,
            artifact,
            direct_process,
            baseline_admission,
        )?;
        Ok(observation)
    })();

    let candidate_cleanup =
        candidate
            .cleanup()
            .map_err(|source| X64GateBPolicy15DiagnosticError::Cleanup {
                member: X64GateBDiagnosticMember::CandidateZero,
                source,
            });
    let baseline_cleanup =
        baseline_executable
            .cleanup()
            .map_err(|source| X64GateBPolicy15DiagnosticError::Cleanup {
                member: X64GateBDiagnosticMember::BaselineZero,
                source,
            });
    merge_cleanup(
        merge_cleanup(measurement, candidate_cleanup),
        baseline_cleanup,
    )
}

pub fn verify_x64_gate_b_policy15_diagnostic_observation<'observation>(
    observation: &'observation X64GateBPolicy15DiagnosticObservation,
    authority: &X64GateBPolicy15StandaloneAuthority<'_, '_>,
    artifact: &VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_>,
    direct_process: VerifiedX64GateBPolicy15StandaloneProcess<'_, '_, '_, '_, '_>,
    baseline_admission: VerifiedX64GateBBaselineAdmission<'_>,
) -> Result<VerifiedX64GateBPolicy15Diagnostic<'observation>, X64GateBPolicy15DiagnosticError> {
    validate_inputs(authority, artifact, direct_process, baseline_admission)?;
    let baseline = build_x64_gate_b_baseline_artifact()?;
    let verified_baseline = verify_x64_gate_b_baseline_artifact(baseline.image_bytes())?;
    let zero = zero_workload()?;
    let full = full_workload()?;
    let direct = direct_process.evidence();
    if observation.schema_version != X64_GATE_B_POLICY15_DIAGNOSTIC_SCHEMA_VERSION
        || observation.policy_version != X64_GATE_B_POLICY15_DIAGNOSTIC_POLICY_VERSION
        || observation.manifest_hash != authority.manifest_hash()
        || observation.candidate_capsule_hash != authority.candidate_capsule_hash()
        || observation.correctness_results_hash != authority.correctness_results_hash()
        || observation.worker_process_results_hash != authority.process_results_hash()
        || observation.standalone_process_results_hash != direct.results_hash()
        || observation.candidate_artifact_hash != artifact.artifact_hash()
        || observation.candidate_elf_image_hash != artifact.elf_image_hash()
        || observation.candidate_target_code_hash != artifact.target_code_hash()
        || observation.baseline_target_hash != verified_baseline.target_hash()
        || observation.baseline_elf_image_hash != verified_baseline.elf_image_hash()
        || observation.baseline_artifact_hash != verified_baseline.artifact_hash()
        || observation.baseline_admission_results_hash != baseline_admission.results_hash()
        || observation.zero_input_frame_hash != zero.input_frame_hash
        || observation.full_input_frame_hash != full.input_frame_hash
        || observation.zero_output_frame_hash != zero.expected_output_frame_hash
        || observation.full_output_frame_hash != full.expected_output_frame_hash
        || observation.warmup_ordinals != X64_GATE_B_WARMUP_PAIRS
        || observation.measured_ordinals != X64_GATE_B_MEASURED_PAIRS
        || observation.invocations_per_ordinal != 4
        || observation.process_timeout_millis != X64_GATE_B_PROCESS_TIMEOUT_MILLIS
        || !observation.rotating_schedule
        || observation.sample_deletion_permitted
        || observation.release_build == cfg!(debug_assertions)
        || observation.affinity_logical_cpus == 0
    {
        return Err(X64GateBPolicy15DiagnosticError::InvalidField {
            field: "policy, provenance, workload, or host envelope",
        });
    }
    validate_samples(&observation.samples, &zero, &full)?;
    let statistics = diagnostic_statistics(&observation.samples)?;
    if statistics
        != [
            observation.candidate_zero_statistics,
            observation.candidate_full_statistics,
            observation.candidate_incremental_statistics,
            observation.baseline_zero_statistics,
            observation.baseline_full_statistics,
            observation.baseline_incremental_statistics,
        ]
    {
        return Err(X64GateBPolicy15DiagnosticError::InvalidField {
            field: "replayed statistics",
        });
    }
    if observation_hash(observation)? != observation.observation_hash {
        return Err(X64GateBPolicy15DiagnosticError::ObservationHashMismatch);
    }
    Ok(VerifiedX64GateBPolicy15Diagnostic { observation })
}

pub fn select_x64_gate_b_policy15_successor(
    inventory: VerifiedX64GateBPolicy15CostInventory<'_>,
    diagnostic: VerifiedX64GateBPolicy15Diagnostic<'_>,
) -> Result<X64GateBPolicy15SuccessorDecision, X64GateBPolicy15DiagnosticError> {
    let inventory = inventory.inventory();
    let observation = diagnostic.observation();
    if inventory.structural_leader()
        != super::x64_target::X64TargetProfileTemplateClass::TailTransfer
        || inventory.proof_only_successor()
            != X64GateBSuccessorOptimizationClass::TailStateTransferElimination
    {
        return Err(X64GateBPolicy15DiagnosticError::SelectionRejected {
            field: "structural leader",
        });
    }
    if !observation.release_build || observation.affinity_logical_cpus != 1 {
        return Err(X64GateBPolicy15DiagnosticError::SelectionRejected {
            field: "release pinned host",
        });
    }
    let candidate_zero = observation
        .candidate_zero_statistics
        .median_twice_nanoseconds();
    let candidate_full = observation
        .candidate_full_statistics
        .median_twice_nanoseconds();
    let candidate_incremental = observation
        .candidate_incremental_statistics
        .median_twice_nanoseconds();
    let baseline_zero = observation
        .baseline_zero_statistics
        .median_twice_nanoseconds();
    let baseline_incremental = observation
        .baseline_incremental_statistics
        .median_twice_nanoseconds();
    if !ratio_within_symmetric_limit(
        candidate_zero,
        baseline_zero,
        X64_GATE_B_POLICY15_FIXED_SYMMETRY_NUMERATOR,
        X64_GATE_B_POLICY15_FIXED_SYMMETRY_DENOMINATOR,
    )? {
        return Err(X64GateBPolicy15DiagnosticError::SelectionRejected {
            field: "fixed process/startup symmetry",
        });
    }
    if !ratio_at_least(
        candidate_incremental,
        candidate_full,
        X64_GATE_B_POLICY15_INCREMENTAL_SHARE_NUMERATOR,
        X64_GATE_B_POLICY15_INCREMENTAL_SHARE_DENOMINATOR,
    )? {
        return Err(X64GateBPolicy15DiagnosticError::SelectionRejected {
            field: "candidate incremental-work share",
        });
    }
    if !ratio_strictly_above(
        candidate_incremental,
        baseline_incremental,
        X64_GATE_B_POLICY15_INCREMENTAL_SLOWDOWN_NUMERATOR,
        X64_GATE_B_POLICY15_INCREMENTAL_SLOWDOWN_DENOMINATOR,
    )? {
        return Err(X64GateBPolicy15DiagnosticError::SelectionRejected {
            field: "incremental-work slowdown",
        });
    }
    let mut decision = X64GateBPolicy15SuccessorDecision {
        schema_version: X64_GATE_B_POLICY15_SUCCESSOR_DECISION_SCHEMA_VERSION,
        policy_version: X64_GATE_B_POLICY15_SUCCESSOR_DECISION_POLICY_VERSION,
        inventory_hash: inventory.inventory_hash(),
        diagnostic_observation_hash: observation.observation_hash(),
        fixed_symmetry_numerator: X64_GATE_B_POLICY15_FIXED_SYMMETRY_NUMERATOR,
        fixed_symmetry_denominator: X64_GATE_B_POLICY15_FIXED_SYMMETRY_DENOMINATOR,
        incremental_share_numerator: X64_GATE_B_POLICY15_INCREMENTAL_SHARE_NUMERATOR,
        incremental_share_denominator: X64_GATE_B_POLICY15_INCREMENTAL_SHARE_DENOMINATOR,
        incremental_slowdown_numerator: X64_GATE_B_POLICY15_INCREMENTAL_SLOWDOWN_NUMERATOR,
        incremental_slowdown_denominator: X64_GATE_B_POLICY15_INCREMENTAL_SLOWDOWN_DENOMINATOR,
        release_build: observation.release_build,
        pinned_logical_cpus: observation.affinity_logical_cpus,
        selection: X64GateBSuccessorOptimizationClass::TailStateTransferElimination,
        decision_hash: SemanticHash::ZERO,
    };
    decision.decision_hash = decision_hash(&decision);
    Ok(decision)
}

pub fn verify_x64_gate_b_policy15_successor_decision<'decision>(
    decision: &'decision X64GateBPolicy15SuccessorDecision,
    inventory: VerifiedX64GateBPolicy15CostInventory<'_>,
    diagnostic: VerifiedX64GateBPolicy15Diagnostic<'_>,
) -> Result<VerifiedX64GateBPolicy15SuccessorDecision<'decision>, X64GateBPolicy15DiagnosticError> {
    if decision_hash(decision) != decision.decision_hash {
        return Err(X64GateBPolicy15DiagnosticError::DecisionHashMismatch);
    }
    let replayed = select_x64_gate_b_policy15_successor(inventory, diagnostic)?;
    if replayed != *decision {
        return Err(X64GateBPolicy15DiagnosticError::DecisionReplayMismatch);
    }
    Ok(VerifiedX64GateBPolicy15SuccessorDecision { decision })
}

fn ratio_within_symmetric_limit(
    left: u128,
    right: u128,
    numerator: u32,
    denominator: u32,
) -> Result<bool, X64GateBPolicy15DiagnosticError> {
    Ok(checked_product(left, denominator, "fixed symmetry left")?
        <= checked_product(right, numerator, "fixed symmetry right")?
        && checked_product(right, denominator, "fixed symmetry reverse left")?
            <= checked_product(left, numerator, "fixed symmetry reverse right")?)
}

fn ratio_at_least(
    part: u128,
    whole: u128,
    numerator: u32,
    denominator: u32,
) -> Result<bool, X64GateBPolicy15DiagnosticError> {
    Ok(
        checked_product(part, denominator, "incremental share left")?
            >= checked_product(whole, numerator, "incremental share right")?,
    )
}

fn ratio_strictly_above(
    left: u128,
    right: u128,
    numerator: u32,
    denominator: u32,
) -> Result<bool, X64GateBPolicy15DiagnosticError> {
    Ok(
        checked_product(left, denominator, "incremental slowdown left")?
            > checked_product(right, numerator, "incremental slowdown right")?,
    )
}

fn checked_product(
    value: u128,
    multiplier: u32,
    field: &'static str,
) -> Result<u128, X64GateBPolicy15DiagnosticError> {
    value
        .checked_mul(u128::from(multiplier))
        .ok_or(X64GateBPolicy15DiagnosticError::InvalidField { field })
}

fn decision_hash(decision: &X64GateBPolicy15SuccessorDecision) -> SemanticHash {
    let mut bytes = Vec::with_capacity(DECISION_DOMAIN.len() + 128);
    bytes.extend_from_slice(DECISION_DOMAIN);
    put_version(&mut bytes, decision.schema_version);
    put_version(&mut bytes, decision.policy_version);
    bytes.extend_from_slice(&decision.inventory_hash.0);
    bytes.extend_from_slice(&decision.diagnostic_observation_hash.0);
    for value in [
        decision.fixed_symmetry_numerator,
        decision.fixed_symmetry_denominator,
        decision.incremental_share_numerator,
        decision.incremental_share_denominator,
        decision.incremental_slowdown_numerator,
        decision.incremental_slowdown_denominator,
        decision.pinned_logical_cpus,
    ] {
        put_u32(&mut bytes, value);
    }
    bytes.push(u8::from(decision.release_build));
    bytes.push(match decision.selection {
        X64GateBSuccessorOptimizationClass::TailStateTransferElimination => 0,
    });
    SemanticHash(sha256(&bytes))
}

fn zero_workload() -> Result<DiagnosticWorkload, X64GateBPolicy15DiagnosticError> {
    let input = X64StandaloneInput::new(X64StandaloneProfile::BranchMix, Vec::new(), 0)
        .map_err(|error| X64GateBPolicy15DiagnosticError::Protocol(error.to_string()))?;
    let input_frame = encode_x64_standalone_input(&input)
        .map_err(|error| X64GateBPolicy15DiagnosticError::Protocol(error.to_string()))?;
    let expected =
        X64StandaloneOutput::return_f64(X64StandaloneProfile::BranchMix, 0.0_f64.to_bits());
    let expected_output_frame = encode_x64_standalone_output(expected)
        .map_err(|error| X64GateBPolicy15DiagnosticError::Protocol(error.to_string()))?;
    Ok(DiagnosticWorkload {
        input_frame_hash: frame_hash(INPUT_FRAME_DOMAIN, &input_frame),
        input_frame,
        expected_output: expected.outcome(),
        expected_output_frame_hash: frame_hash(OUTPUT_FRAME_DOMAIN, &expected_output_frame),
        expected_output_frame,
    })
}

fn full_workload() -> Result<DiagnosticWorkload, X64GateBPolicy15DiagnosticError> {
    let workload = frozen_workload()?;
    Ok(DiagnosticWorkload {
        input_frame_hash: frame_hash(INPUT_FRAME_DOMAIN, &workload.input_frame),
        input_frame: workload.input_frame,
        expected_output: workload.expected_output,
        expected_output_frame_hash: frame_hash(
            OUTPUT_FRAME_DOMAIN,
            &workload.expected_output_frame,
        ),
        expected_output_frame: workload.expected_output_frame,
    })
}

fn execute_ordinal(
    candidate: &PreparedX64StandaloneExecutable,
    baseline: &PreparedX64StandaloneExecutable,
    zero: &DiagnosticWorkload,
    full: &DiagnosticWorkload,
    phase: &'static str,
    ordinal: u32,
) -> Result<X64GateBDiagnosticSample, X64GateBPolicy15DiagnosticError> {
    let order = member_order(ordinal);
    let mut durations = [0_u64; 4];
    let mut hashes = [SemanticHash::ZERO; 4];
    for member in order {
        let (executable, workload) = match member {
            X64GateBDiagnosticMember::CandidateZero => (candidate, zero),
            X64GateBDiagnosticMember::BaselineZero => (baseline, zero),
            X64GateBDiagnosticMember::CandidateFull => (candidate, full),
            X64GateBDiagnosticMember::BaselineFull => (baseline, full),
        };
        let process_ordinal = ordinal
            .checked_mul(4)
            .and_then(|value| value.checked_add(u32::from(member_tag(member))))
            .ok_or(X64GateBPolicy15DiagnosticError::InvalidField {
                field: "process ordinal",
            })?;
        let process = run_admitted_x64_standalone_process(
            executable,
            process_ordinal,
            workload.input_frame.clone(),
            X64StandaloneProfile::BranchMix,
            X64_GATE_B_PROCESS_TIMEOUT_MILLIS,
        )
        .map_err(|source| process_error(member, phase, ordinal, source))?;
        if process.output().outcome() != workload.expected_output
            || process.output_frame() != &workload.expected_output_frame
        {
            return Err(X64GateBPolicy15DiagnosticError::InvalidField {
                field: "process output",
            });
        }
        let index = usize::from(member_tag(member));
        durations[index] = process.elapsed_nanoseconds();
        hashes[index] = frame_hash(OUTPUT_FRAME_DOMAIN, process.output_frame());
    }
    build_sample(ordinal, order[0], durations, hashes)
}

fn build_sample(
    ordinal: u32,
    first: X64GateBDiagnosticMember,
    durations: [u64; 4],
    hashes: [SemanticHash; 4],
) -> Result<X64GateBDiagnosticSample, X64GateBPolicy15DiagnosticError> {
    let candidate_incremental_nanoseconds = checked_delta(
        X64GateBDiagnosticMember::CandidateFull,
        ordinal,
        durations[0],
        durations[2],
    )?;
    let baseline_incremental_nanoseconds = checked_delta(
        X64GateBDiagnosticMember::BaselineFull,
        ordinal,
        durations[1],
        durations[3],
    )?;
    Ok(X64GateBDiagnosticSample {
        ordinal,
        first,
        candidate_zero_nanoseconds: durations[0],
        candidate_full_nanoseconds: durations[2],
        baseline_zero_nanoseconds: durations[1],
        baseline_full_nanoseconds: durations[3],
        candidate_incremental_nanoseconds,
        baseline_incremental_nanoseconds,
        candidate_zero_output_hash: hashes[0],
        candidate_full_output_hash: hashes[2],
        baseline_zero_output_hash: hashes[1],
        baseline_full_output_hash: hashes[3],
    })
}

fn checked_delta(
    member: X64GateBDiagnosticMember,
    ordinal: u32,
    zero_nanoseconds: u64,
    full_nanoseconds: u64,
) -> Result<u64, X64GateBPolicy15DiagnosticError> {
    full_nanoseconds.checked_sub(zero_nanoseconds).ok_or(
        X64GateBPolicy15DiagnosticError::NegativeIncrementalTime {
            member,
            ordinal,
            zero_nanoseconds,
            full_nanoseconds,
        },
    )
}

fn member_order(ordinal: u32) -> [X64GateBDiagnosticMember; 4] {
    let base = [
        X64GateBDiagnosticMember::CandidateZero,
        X64GateBDiagnosticMember::BaselineZero,
        X64GateBDiagnosticMember::CandidateFull,
        X64GateBDiagnosticMember::BaselineFull,
    ];
    let rotation = (ordinal % 4) as usize;
    std::array::from_fn(|index| base[(index + rotation) % 4])
}

fn validate_samples(
    samples: &[X64GateBDiagnosticSample],
    zero: &DiagnosticWorkload,
    full: &DiagnosticWorkload,
) -> Result<(), X64GateBPolicy15DiagnosticError> {
    if samples.len() != X64_GATE_B_MEASURED_PAIRS as usize {
        return Err(X64GateBPolicy15DiagnosticError::InvalidField {
            field: "sample count",
        });
    }
    for (index, sample) in samples.iter().enumerate() {
        let ordinal =
            u32::try_from(index).map_err(|_| X64GateBPolicy15DiagnosticError::InvalidField {
                field: "sample ordinal",
            })?;
        if sample.ordinal != ordinal
            || sample.first != member_order(ordinal)[0]
            || [
                sample.candidate_zero_nanoseconds,
                sample.candidate_full_nanoseconds,
                sample.baseline_zero_nanoseconds,
                sample.baseline_full_nanoseconds,
                sample.candidate_incremental_nanoseconds,
                sample.baseline_incremental_nanoseconds,
            ]
            .contains(&0)
            || sample.candidate_zero_output_hash != zero.expected_output_frame_hash
            || sample.baseline_zero_output_hash != zero.expected_output_frame_hash
            || sample.candidate_full_output_hash != full.expected_output_frame_hash
            || sample.baseline_full_output_hash != full.expected_output_frame_hash
            || sample.candidate_incremental_nanoseconds
                != checked_delta(
                    X64GateBDiagnosticMember::CandidateFull,
                    ordinal,
                    sample.candidate_zero_nanoseconds,
                    sample.candidate_full_nanoseconds,
                )?
            || sample.baseline_incremental_nanoseconds
                != checked_delta(
                    X64GateBDiagnosticMember::BaselineFull,
                    ordinal,
                    sample.baseline_zero_nanoseconds,
                    sample.baseline_full_nanoseconds,
                )?
        {
            return Err(X64GateBPolicy15DiagnosticError::InvalidField {
                field: "sample order, duration, delta, or output",
            });
        }
    }
    Ok(())
}

fn diagnostic_statistics(
    samples: &[X64GateBDiagnosticSample],
) -> Result<[X64GateBSampleStatistics; 6], X64GateBPolicy15DiagnosticError> {
    let columns = [
        samples
            .iter()
            .map(|sample| sample.candidate_zero_nanoseconds)
            .collect::<Vec<_>>(),
        samples
            .iter()
            .map(|sample| sample.candidate_full_nanoseconds)
            .collect::<Vec<_>>(),
        samples
            .iter()
            .map(|sample| sample.candidate_incremental_nanoseconds)
            .collect::<Vec<_>>(),
        samples
            .iter()
            .map(|sample| sample.baseline_zero_nanoseconds)
            .collect::<Vec<_>>(),
        samples
            .iter()
            .map(|sample| sample.baseline_full_nanoseconds)
            .collect::<Vec<_>>(),
        samples
            .iter()
            .map(|sample| sample.baseline_incremental_nanoseconds)
            .collect::<Vec<_>>(),
    ];
    Ok([
        compute_statistics(&columns[0])?,
        compute_statistics(&columns[1])?,
        compute_statistics(&columns[2])?,
        compute_statistics(&columns[3])?,
        compute_statistics(&columns[4])?,
        compute_statistics(&columns[5])?,
    ])
}

fn observation_hash(
    observation: &X64GateBPolicy15DiagnosticObservation,
) -> Result<SemanticHash, X64GateBPolicy15DiagnosticError> {
    let mut bytes =
        Vec::with_capacity(OBSERVATION_DOMAIN.len() + 1_024 + observation.samples.len() * 184);
    bytes.extend_from_slice(OBSERVATION_DOMAIN);
    put_version(&mut bytes, observation.schema_version);
    put_version(&mut bytes, observation.policy_version);
    for hash in [
        observation.manifest_hash,
        observation.candidate_capsule_hash,
        observation.correctness_results_hash,
        observation.worker_process_results_hash,
        observation.standalone_process_results_hash,
        observation.candidate_artifact_hash,
        observation.candidate_elf_image_hash,
        observation.candidate_target_code_hash,
        observation.baseline_target_hash,
        observation.baseline_elf_image_hash,
        observation.baseline_artifact_hash,
        observation.baseline_admission_results_hash,
        observation.zero_input_frame_hash,
        observation.full_input_frame_hash,
        observation.zero_output_frame_hash,
        observation.full_output_frame_hash,
    ] {
        bytes.extend_from_slice(&hash.0);
    }
    for value in [
        observation.warmup_ordinals,
        observation.measured_ordinals,
        observation.invocations_per_ordinal,
        observation.process_timeout_millis,
        observation.affinity_logical_cpus,
    ] {
        put_u32(&mut bytes, value);
    }
    bytes.push(u8::from(observation.rotating_schedule));
    bytes.push(u8::from(observation.sample_deletion_permitted));
    bytes.push(u8::from(observation.release_build));
    put_u32(
        &mut bytes,
        u32::try_from(observation.samples.len()).map_err(|_| {
            X64GateBPolicy15DiagnosticError::InvalidField {
                field: "sample encoding count",
            }
        })?,
    );
    for sample in &observation.samples {
        put_u32(&mut bytes, sample.ordinal);
        bytes.push(member_tag(sample.first));
        for value in [
            sample.candidate_zero_nanoseconds,
            sample.candidate_full_nanoseconds,
            sample.baseline_zero_nanoseconds,
            sample.baseline_full_nanoseconds,
            sample.candidate_incremental_nanoseconds,
            sample.baseline_incremental_nanoseconds,
        ] {
            put_u64(&mut bytes, value);
        }
        for hash in [
            sample.candidate_zero_output_hash,
            sample.candidate_full_output_hash,
            sample.baseline_zero_output_hash,
            sample.baseline_full_output_hash,
        ] {
            bytes.extend_from_slice(&hash.0);
        }
    }
    for statistics in [
        observation.candidate_zero_statistics,
        observation.candidate_full_statistics,
        observation.candidate_incremental_statistics,
        observation.baseline_zero_statistics,
        observation.baseline_full_statistics,
        observation.baseline_incremental_statistics,
    ] {
        put_statistics(&mut bytes, statistics);
    }
    Ok(SemanticHash(sha256(&bytes)))
}

fn member_tag(member: X64GateBDiagnosticMember) -> u8 {
    match member {
        X64GateBDiagnosticMember::CandidateZero => 0,
        X64GateBDiagnosticMember::BaselineZero => 1,
        X64GateBDiagnosticMember::CandidateFull => 2,
        X64GateBDiagnosticMember::BaselineFull => 3,
    }
}

fn process_error(
    member: X64GateBDiagnosticMember,
    phase: &'static str,
    ordinal: u32,
    source: X64StandaloneProcessError,
) -> X64GateBPolicy15DiagnosticError {
    X64GateBPolicy15DiagnosticError::Process {
        member,
        phase,
        ordinal,
        source,
    }
}

fn merge_cleanup<T>(
    primary: Result<T, X64GateBPolicy15DiagnosticError>,
    cleanup: Result<(), X64GateBPolicy15DiagnosticError>,
) -> Result<T, X64GateBPolicy15DiagnosticError> {
    match (primary, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => {
            Err(X64GateBPolicy15DiagnosticError::FailureDuringCleanup {
                primary: primary.to_string(),
                cleanup: cleanup.to_string(),
            })
        }
    }
}

fn frame_hash(domain: &[u8], frame: &[u8]) -> SemanticHash {
    let mut bytes = Vec::with_capacity(domain.len() + 8 + frame.len());
    bytes.extend_from_slice(domain);
    put_u64(&mut bytes, frame.len() as u64);
    bytes.extend_from_slice(frame);
    SemanticHash(sha256(&bytes))
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_be_bytes());
    bytes.extend_from_slice(&version.1.to_be_bytes());
    bytes.extend_from_slice(&version.2.to_be_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotating_schedule_and_negative_delta_are_fail_closed() {
        assert_eq!(member_order(0)[0], X64GateBDiagnosticMember::CandidateZero);
        assert_eq!(member_order(1)[0], X64GateBDiagnosticMember::BaselineZero);
        assert_eq!(member_order(2)[0], X64GateBDiagnosticMember::CandidateFull);
        assert_eq!(member_order(3)[0], X64GateBDiagnosticMember::BaselineFull);
        assert_eq!(member_order(4), member_order(0));

        assert!(matches!(
            checked_delta(X64GateBDiagnosticMember::CandidateFull, 0, 101, 100),
            Err(X64GateBPolicy15DiagnosticError::NegativeIncrementalTime { .. })
        ));
        assert_eq!(
            checked_delta(X64GateBDiagnosticMember::CandidateFull, 0, 100, 101)
                .expect("positive delta"),
            1
        );
    }

    #[test]
    fn zero_and_full_workloads_have_distinct_exact_frames() {
        let zero = zero_workload().expect("zero workload");
        let full = full_workload().expect("full workload");
        assert_eq!(
            zero.expected_output.returned_f64_bits(),
            Some(0.0_f64.to_bits())
        );
        assert_ne!(zero.input_frame_hash, full.input_frame_hash);
        assert_ne!(
            zero.expected_output_frame_hash,
            full.expected_output_frame_hash
        );
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    #[test]
    #[ignore = "requires release mode pinned to one logical CPU; replays ADR-0052/0053/0054 and executes the complete 5+30 four-member ADR-0056 diagnostic"]
    fn full_body_process_diagnostic_replays() {
        use super::super::x64_gate_b_baseline_admission::{
            emit_x64_gate_b_baseline_admission, verify_x64_gate_b_baseline_admission,
        };
        use super::super::x64_gate_b_candidate_admission::{
            emit_reconstructed_candidate_correctness_for_process_tests,
            verify_reconstructed_candidate_correctness_for_tests,
        };
        use super::super::x64_gate_b_candidate_diagnosis::{
            frozen_x64_gate_b_policy15_cost_inventory, verify_x64_gate_b_policy15_cost_inventory,
        };
        use super::super::x64_gate_b_candidate_process::{
            emit_synthetic_candidate_process_evidence_for_tests,
            verify_x64_gate_b_policy15_candidate_process_evidence,
        };
        use super::super::x64_gate_b_candidate_standalone_artifact::{
            build_x64_gate_b_policy15_standalone_artifact,
            verify_x64_gate_b_policy15_standalone_artifact,
        };
        use super::super::x64_gate_b_candidate_standalone_authority::authorize_x64_gate_b_policy15_standalone;
        use super::super::x64_gate_b_candidate_standalone_process::{
            emit_x64_gate_b_policy15_standalone_process_evidence,
            verify_x64_gate_b_policy15_standalone_process_evidence,
        };

        let correctness =
            emit_reconstructed_candidate_correctness_for_process_tests().expect("correctness");
        let verified_correctness =
            verify_reconstructed_candidate_correctness_for_tests(&correctness)
                .expect("correctness replay");
        let process = emit_synthetic_candidate_process_evidence_for_tests(verified_correctness)
            .expect("process transport");
        let verified_process =
            verify_x64_gate_b_policy15_candidate_process_evidence(verified_correctness, &process)
                .expect("process replay");
        let branch = authorize_x64_gate_b_policy15_standalone(
            verified_correctness,
            verified_process,
            X64StandaloneProfile::BranchMix,
        )
        .expect("Branch authority");
        let bounds = authorize_x64_gate_b_policy15_standalone(
            verified_correctness,
            verified_process,
            X64StandaloneProfile::Bounds,
        )
        .expect("Bounds authority");
        let branch_image =
            build_x64_gate_b_policy15_standalone_artifact(&branch).expect("Branch ELF");
        let bounds_image =
            build_x64_gate_b_policy15_standalone_artifact(&bounds).expect("Bounds ELF");
        let branch_artifact =
            verify_x64_gate_b_policy15_standalone_artifact(&branch, branch_image.image_bytes())
                .expect("Branch ELF replay");
        let bounds_artifact =
            verify_x64_gate_b_policy15_standalone_artifact(&bounds, bounds_image.image_bytes())
                .expect("Bounds ELF replay");
        let direct = emit_x64_gate_b_policy15_standalone_process_evidence(
            &branch,
            &branch_artifact,
            &bounds,
            &bounds_artifact,
        )
        .expect("direct processes");
        let verified_direct = verify_x64_gate_b_policy15_standalone_process_evidence(
            &branch,
            &branch_artifact,
            &bounds,
            &bounds_artifact,
            &direct,
        )
        .expect("direct replay");
        let baseline = emit_x64_gate_b_baseline_admission().expect("baseline admission");
        let verified_baseline =
            verify_x64_gate_b_baseline_admission(&baseline).expect("baseline replay");

        let observation = emit_x64_gate_b_policy15_diagnostic_observation(
            &branch,
            &branch_artifact,
            verified_direct,
            verified_baseline,
        )
        .expect("body/process diagnostic");
        let verified = verify_x64_gate_b_policy15_diagnostic_observation(
            &observation,
            &branch,
            &branch_artifact,
            verified_direct,
            verified_baseline,
        )
        .expect("diagnostic replay");
        assert_eq!(verified.observation(), &observation);
        assert_eq!(observation.samples.len(), 30);
        let inventory = frozen_x64_gate_b_policy15_cost_inventory().expect("frozen cost inventory");
        let verified_inventory =
            verify_x64_gate_b_policy15_cost_inventory(&inventory).expect("cost inventory replay");
        let decision = select_x64_gate_b_policy15_successor(verified_inventory, verified)
            .expect("joint successor selection");
        let verified_decision =
            verify_x64_gate_b_policy15_successor_decision(&decision, verified_inventory, verified)
                .expect("successor decision replay");
        assert_eq!(verified_decision.decision(), &decision);
        println!(
            "diagnostic hash={} decision={} selection={:?} affinity={} candidate zero/full/delta median*2={}/{}/{} baseline zero/full/delta median*2={}/{}/{} candidate delta p95={} baseline delta p95={}",
            observation.observation_hash.to_hex(),
            decision.decision_hash.to_hex(),
            decision.selection,
            observation.affinity_logical_cpus,
            observation.candidate_zero_statistics.median_twice_nanoseconds(),
            observation.candidate_full_statistics.median_twice_nanoseconds(),
            observation.candidate_incremental_statistics.median_twice_nanoseconds(),
            observation.baseline_zero_statistics.median_twice_nanoseconds(),
            observation.baseline_full_statistics.median_twice_nanoseconds(),
            observation.baseline_incremental_statistics.median_twice_nanoseconds(),
            observation.candidate_incremental_statistics.p95_nanoseconds(),
            observation.baseline_incremental_statistics.p95_nanoseconds(),
        );

        let mut wrong_order = observation.clone();
        wrong_order.samples.swap(0, 1);
        wrong_order.observation_hash = observation_hash(&wrong_order).expect("local reseal");
        assert!(verify_x64_gate_b_policy15_diagnostic_observation(
            &wrong_order,
            &branch,
            &branch_artifact,
            verified_direct,
            verified_baseline,
        )
        .is_err());

        let mut wrong_delta = observation;
        wrong_delta.samples[0].candidate_incremental_nanoseconds += 1;
        wrong_delta.observation_hash = observation_hash(&wrong_delta).expect("local reseal");
        assert!(verify_x64_gate_b_policy15_diagnostic_observation(
            &wrong_delta,
            &branch,
            &branch_artifact,
            verified_direct,
            verified_baseline,
        )
        .is_err());
    }
}
