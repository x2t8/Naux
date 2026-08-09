//! Candidate-matched Gate B measurement and claim admission for ADR-0055.
//!
//! This module reuses only ADR-0041's frozen workload, process containment,
//! paired schedule, statistics, and threshold mechanics.  Its evidence and
//! claim types are deliberately disjoint from the ordinary policy-1.4 Gate B
//! domain and grant no encoder-selection or execution authority.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_gate_b_baseline::{
    build_x64_gate_b_baseline_artifact, verify_x64_gate_b_baseline_artifact, X64GateBBaselineError,
};
use super::x64_gate_b_baseline_admission::VerifiedX64GateBBaselineAdmission;
use super::x64_gate_b_candidate_admission::X64GateBPolicy15CandidateSelection;
use super::x64_gate_b_candidate_standalone_artifact::{
    verify_x64_gate_b_policy15_standalone_artifact,
    x64_gate_b_policy15_accepted_standalone_artifact_hash,
    VerifiedX64GateBPolicy15StandaloneArtifact, X64GateBPolicy15StandaloneArtifactError,
};
use super::x64_gate_b_candidate_standalone_authority::{
    X64GateBPolicy15StandaloneAuthority, X64GateBPolicy15StandaloneAuthorityError,
};
use super::x64_gate_b_candidate_standalone_process::{
    x64_gate_b_policy15_accepted_standalone_results_hash, VerifiedX64GateBPolicy15StandaloneProcess,
};
use super::x64_gate_b_measurement::{
    affinity_logical_cpu_count, compute_statistics, frozen_workload, performance_threshold,
    put_statistics, require_host, run_measured_pairs, run_warmups, X64GateBEngine,
    X64GateBMeasurementError, X64GateBPairSample, X64GateBSampleStatistics,
    X64_GATE_B_ARRAY_ELEMENTS, X64_GATE_B_ELEMENT_VISITS, X64_GATE_B_MAX_CV_PERCENT,
    X64_GATE_B_MAX_SLOWDOWN_DENOMINATOR, X64_GATE_B_MAX_SLOWDOWN_NUMERATOR,
    X64_GATE_B_MEASURED_PAIRS, X64_GATE_B_PROCESS_TIMEOUT_MILLIS, X64_GATE_B_REPETITIONS,
    X64_GATE_B_WARMUP_PAIRS, X64_GATE_B_WORKLOAD_GENERATOR_SEED,
    X64_GATE_B_WORKLOAD_GENERATOR_VERSION,
};
use super::x64_standalone_process::{PreparedX64StandaloneExecutable, X64StandaloneProcessError};
use super::x64_standalone_protocol::{X64StandaloneOutcome, X64StandaloneProfile};
use std::fmt;

pub const X64_GATE_B_POLICY15_MEASUREMENT_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_POLICY15_MEASUREMENT_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_POLICY15_STATISTICS_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_POLICY15_THRESHOLD_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);

const OBSERVATION_DOMAIN: &[u8] =
    b"NAUX:gate-b:policy-1.5:candidate-matched:measurement:observation:v1\0";

/// Exact local observation for the accepted ADR-0054 BranchMix candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64GateBPolicy15MeasurementObservation {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    selection: X64GateBPolicy15CandidateSelection,
    generator_version: (u16, u16, u16),
    generator_seed: u64,
    array_elements: u32,
    repetitions: i64,
    element_visits: u64,
    input_values_hash: SemanticHash,
    input_frame_hash: SemanticHash,
    expected_output: X64StandaloneOutcome,
    expected_output_frame_hash: SemanticHash,
    manifest_hash: SemanticHash,
    candidate_capsule_hash: SemanticHash,
    correctness_results_hash: SemanticHash,
    worker_process_results_hash: SemanticHash,
    standalone_process_results_hash: SemanticHash,
    candidate_artifact_hash: SemanticHash,
    candidate_elf_image_hash: SemanticHash,
    candidate_startup_plan_hash: SemanticHash,
    candidate_startup_code_hash: SemanticHash,
    candidate_target_artifact_hash: SemanticHash,
    candidate_target_plan_hash: SemanticHash,
    candidate_target_code_hash: SemanticHash,
    bounds_fallback_artifact_hash: SemanticHash,
    bounds_fallback_elf_image_hash: SemanticHash,
    baseline_target_hash: SemanticHash,
    baseline_elf_image_hash: SemanticHash,
    baseline_artifact_hash: SemanticHash,
    baseline_admission_results_hash: SemanticHash,
    warmup_pairs: u32,
    measured_pairs: u32,
    process_timeout_millis: u32,
    paired_alternating_schedule: bool,
    sample_deletion_permitted: bool,
    statistics_policy_version: (u16, u16, u16),
    maximum_cv_percent: u32,
    threshold_policy_version: (u16, u16, u16),
    maximum_slowdown_numerator: u32,
    maximum_slowdown_denominator: u32,
    release_build: bool,
    affinity_logical_cpus: u32,
    repository_state_recorded: bool,
    repository_revision_hash: SemanticHash,
    repository_dirty: bool,
    samples: Vec<X64GateBPairSample>,
    candidate_statistics: X64GateBSampleStatistics,
    baseline_statistics: X64GateBSampleStatistics,
    performance_threshold_met: bool,
    observation_hash: SemanticHash,
}

impl X64GateBPolicy15MeasurementObservation {
    pub const fn candidate_artifact_hash(&self) -> SemanticHash {
        self.candidate_artifact_hash
    }

    pub const fn standalone_process_results_hash(&self) -> SemanticHash {
        self.standalone_process_results_hash
    }

    pub const fn baseline_artifact_hash(&self) -> SemanticHash {
        self.baseline_artifact_hash
    }

    pub fn samples(&self) -> &[X64GateBPairSample] {
        &self.samples
    }

    pub const fn candidate_statistics(&self) -> X64GateBSampleStatistics {
        self.candidate_statistics
    }

    pub const fn baseline_statistics(&self) -> X64GateBSampleStatistics {
        self.baseline_statistics
    }

    pub const fn performance_threshold_met(&self) -> bool {
        self.performance_threshold_met
    }

    pub const fn release_build(&self) -> bool {
        self.release_build
    }

    pub const fn affinity_logical_cpus(&self) -> u32 {
        self.affinity_logical_cpus
    }

    pub const fn repository_state_recorded(&self) -> bool {
        self.repository_state_recorded
    }

    pub const fn repository_dirty(&self) -> bool {
        self.repository_dirty
    }

    pub const fn observation_hash(&self) -> SemanticHash {
        self.observation_hash
    }
}

/// Replay-verified candidate measurement.  This is evidence only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedX64GateBPolicy15Measurement<'observation> {
    observation: &'observation X64GateBPolicy15MeasurementObservation,
}

impl<'observation> VerifiedX64GateBPolicy15Measurement<'observation> {
    pub const fn observation(&self) -> &'observation X64GateBPolicy15MeasurementObservation {
        self.observation
    }
}

/// Candidate performance claim only.  It has no conversion into ordinary
/// Gate B, standalone execution, target, or global encoder authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmittedX64GateBPolicy15Claim<'observation> {
    verified: VerifiedX64GateBPolicy15Measurement<'observation>,
}

impl<'observation> AdmittedX64GateBPolicy15Claim<'observation> {
    pub const fn observation(&self) -> &'observation X64GateBPolicy15MeasurementObservation {
        self.verified.observation
    }
}

#[derive(Debug)]
pub enum X64GateBPolicy15MeasurementError {
    Mechanical(X64GateBMeasurementError),
    Authority(X64GateBPolicy15StandaloneAuthorityError),
    Artifact(X64GateBPolicy15StandaloneArtifactError),
    Baseline(X64GateBBaselineError),
    InvalidField { field: &'static str },
    ObservationHashMismatch,
}

impl fmt::Display for X64GateBPolicy15MeasurementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mechanical(error) => write!(formatter, "candidate measurement failed: {error}"),
            Self::Authority(error) => write!(formatter, "{error}"),
            Self::Artifact(error) => write!(formatter, "{error}"),
            Self::Baseline(error) => write!(formatter, "{error}"),
            Self::InvalidField { field } => {
                write!(formatter, "candidate measurement has invalid {field}")
            }
            Self::ObservationHashMismatch => {
                formatter.write_str("candidate measurement observation seal does not replay")
            }
        }
    }
}

impl std::error::Error for X64GateBPolicy15MeasurementError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Mechanical(error) => Some(error),
            Self::Authority(error) => Some(error),
            Self::Artifact(error) => Some(error),
            Self::Baseline(error) => Some(error),
            _ => None,
        }
    }
}

impl From<X64GateBMeasurementError> for X64GateBPolicy15MeasurementError {
    fn from(value: X64GateBMeasurementError) -> Self {
        Self::Mechanical(value)
    }
}

impl From<X64GateBPolicy15StandaloneAuthorityError> for X64GateBPolicy15MeasurementError {
    fn from(value: X64GateBPolicy15StandaloneAuthorityError) -> Self {
        Self::Authority(value)
    }
}

impl From<X64GateBPolicy15StandaloneArtifactError> for X64GateBPolicy15MeasurementError {
    fn from(value: X64GateBPolicy15StandaloneArtifactError) -> Self {
        Self::Artifact(value)
    }
}

impl From<X64GateBBaselineError> for X64GateBPolicy15MeasurementError {
    fn from(value: X64GateBBaselineError) -> Self {
        Self::Baseline(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64GateBPolicy15ClaimRejection {
    DebugBuild,
    CpuNotPinned { logical_cpus: u32 },
    RepositoryStateMissing,
    DirtyRepository,
    CandidateCoefficientOfVariation,
    BaselineCoefficientOfVariation,
    PerformanceThreshold,
}

impl fmt::Display for X64GateBPolicy15ClaimRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DebugBuild => formatter.write_str("candidate claim requires a release build"),
            Self::CpuNotPinned { logical_cpus } => write!(
                formatter,
                "candidate claim requires one pinned logical CPU; affinity admits {logical_cpus}"
            ),
            Self::RepositoryStateMissing => formatter
                .write_str("candidate claim lacks an independently recorded repository revision"),
            Self::DirtyRepository => {
                formatter.write_str("candidate claim requires a clean recorded revision")
            }
            Self::CandidateCoefficientOfVariation => {
                formatter.write_str("candidate samples exceed 5% CV")
            }
            Self::BaselineCoefficientOfVariation => {
                formatter.write_str("candidate-matched baseline samples exceed 5% CV")
            }
            Self::PerformanceThreshold => {
                formatter.write_str("candidate median exceeds 2x the baseline median")
            }
        }
    }
}

impl std::error::Error for X64GateBPolicy15ClaimRejection {}

/// Execute the exact accepted candidate/baseline pair. Repository provenance
/// is deliberately unavailable here, so this local emitter cannot mint a
/// performance claim by itself.
pub fn emit_x64_gate_b_policy15_measurement_observation(
    authority: &X64GateBPolicy15StandaloneAuthority<'_, '_>,
    artifact: &VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_>,
    direct_process: VerifiedX64GateBPolicy15StandaloneProcess<'_, '_, '_, '_, '_>,
    baseline_admission: VerifiedX64GateBBaselineAdmission<'_>,
) -> Result<X64GateBPolicy15MeasurementObservation, X64GateBPolicy15MeasurementError> {
    require_host()?;
    validate_inputs(authority, artifact, direct_process, baseline_admission)?;
    let baseline = build_x64_gate_b_baseline_artifact()?;
    let verified_baseline = verify_x64_gate_b_baseline_artifact(baseline.image_bytes())?;
    let workload = frozen_workload()?;
    let affinity_logical_cpus = affinity_logical_cpu_count()?;

    let mut candidate_executable = PreparedX64StandaloneExecutable::create(
        X64StandaloneProfile::BranchMix,
        artifact.image_bytes(),
    )
    .map_err(|source| materialization_error(X64GateBEngine::Naux, source))?;
    let baseline_executable = PreparedX64StandaloneExecutable::create(
        X64StandaloneProfile::BranchMix,
        verified_baseline.image_bytes(),
    );
    let mut baseline_executable = match baseline_executable {
        Ok(executable) => executable,
        Err(source) => {
            let primary = Err(materialization_error(X64GateBEngine::HandBaseline, source));
            let cleanup = candidate_executable
                .cleanup()
                .map_err(|source| cleanup_error(X64GateBEngine::Naux, source));
            return merge_cleanup(primary, cleanup);
        }
    };

    let measurement = (|| {
        run_warmups(&candidate_executable, &baseline_executable, &workload)?;
        let samples = run_measured_pairs(&candidate_executable, &baseline_executable, &workload)?;
        let candidate_samples = samples
            .iter()
            .map(X64GateBPairSample::naux_nanoseconds)
            .collect::<Vec<_>>();
        let baseline_samples = samples
            .iter()
            .map(X64GateBPairSample::baseline_nanoseconds)
            .collect::<Vec<_>>();
        let candidate_statistics = compute_statistics(&candidate_samples)?;
        let baseline_statistics = compute_statistics(&baseline_samples)?;
        let performance_threshold_met =
            performance_threshold(candidate_statistics, baseline_statistics)?;
        let direct = direct_process.evidence();
        let mut observation = X64GateBPolicy15MeasurementObservation {
            schema_version: X64_GATE_B_POLICY15_MEASUREMENT_SCHEMA_VERSION,
            policy_version: X64_GATE_B_POLICY15_MEASUREMENT_POLICY_VERSION,
            selection: X64GateBPolicy15CandidateSelection::Policy15Candidate,
            generator_version: X64_GATE_B_WORKLOAD_GENERATOR_VERSION,
            generator_seed: X64_GATE_B_WORKLOAD_GENERATOR_SEED,
            array_elements: X64_GATE_B_ARRAY_ELEMENTS,
            repetitions: X64_GATE_B_REPETITIONS,
            element_visits: X64_GATE_B_ELEMENT_VISITS,
            input_values_hash: workload.input_values_hash,
            input_frame_hash: workload.input_frame_hash,
            expected_output: workload.expected_output,
            expected_output_frame_hash: workload.expected_output_frame_hash,
            manifest_hash: authority.manifest_hash(),
            candidate_capsule_hash: authority.candidate_capsule_hash(),
            correctness_results_hash: authority.correctness_results_hash(),
            worker_process_results_hash: authority.process_results_hash(),
            standalone_process_results_hash: direct.results_hash(),
            candidate_artifact_hash: artifact.artifact_hash(),
            candidate_elf_image_hash: artifact.elf_image_hash(),
            candidate_startup_plan_hash: artifact.startup_plan_hash(),
            candidate_startup_code_hash: artifact.startup_code_hash(),
            candidate_target_artifact_hash: authority.target_artifact_hash(),
            candidate_target_plan_hash: authority.target_plan_hash(),
            candidate_target_code_hash: authority.target_code_hash(),
            bounds_fallback_artifact_hash: direct.bounds_artifact_hash(),
            bounds_fallback_elf_image_hash: direct.bounds_elf_image_hash(),
            baseline_target_hash: verified_baseline.target_hash(),
            baseline_elf_image_hash: verified_baseline.elf_image_hash(),
            baseline_artifact_hash: verified_baseline.artifact_hash(),
            baseline_admission_results_hash: baseline_admission.results_hash(),
            warmup_pairs: X64_GATE_B_WARMUP_PAIRS,
            measured_pairs: X64_GATE_B_MEASURED_PAIRS,
            process_timeout_millis: X64_GATE_B_PROCESS_TIMEOUT_MILLIS,
            paired_alternating_schedule: true,
            sample_deletion_permitted: false,
            statistics_policy_version: X64_GATE_B_POLICY15_STATISTICS_POLICY_VERSION,
            maximum_cv_percent: X64_GATE_B_MAX_CV_PERCENT,
            threshold_policy_version: X64_GATE_B_POLICY15_THRESHOLD_POLICY_VERSION,
            maximum_slowdown_numerator: X64_GATE_B_MAX_SLOWDOWN_NUMERATOR,
            maximum_slowdown_denominator: X64_GATE_B_MAX_SLOWDOWN_DENOMINATOR,
            release_build: !cfg!(debug_assertions),
            affinity_logical_cpus,
            repository_state_recorded: false,
            repository_revision_hash: SemanticHash::ZERO,
            repository_dirty: true,
            samples,
            candidate_statistics,
            baseline_statistics,
            performance_threshold_met,
            observation_hash: SemanticHash::ZERO,
        };
        observation.observation_hash = observation_hash(&observation)?;
        let _ = verify_x64_gate_b_policy15_measurement_observation(
            &observation,
            authority,
            artifact,
            direct_process,
            baseline_admission,
        )?;
        Ok(observation)
    })();

    let candidate_cleanup = candidate_executable
        .cleanup()
        .map_err(|source| cleanup_error(X64GateBEngine::Naux, source));
    let baseline_cleanup = baseline_executable
        .cleanup()
        .map_err(|source| cleanup_error(X64GateBEngine::HandBaseline, source));
    merge_cleanup(
        merge_cleanup(measurement, candidate_cleanup),
        baseline_cleanup,
    )
}

/// Recompute every deterministic relation without rerunning timed samples.
pub fn verify_x64_gate_b_policy15_measurement_observation<'observation>(
    observation: &'observation X64GateBPolicy15MeasurementObservation,
    authority: &X64GateBPolicy15StandaloneAuthority<'_, '_>,
    artifact: &VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_>,
    direct_process: VerifiedX64GateBPolicy15StandaloneProcess<'_, '_, '_, '_, '_>,
    baseline_admission: VerifiedX64GateBBaselineAdmission<'_>,
) -> Result<VerifiedX64GateBPolicy15Measurement<'observation>, X64GateBPolicy15MeasurementError> {
    validate_inputs(authority, artifact, direct_process, baseline_admission)?;
    if observation.schema_version != X64_GATE_B_POLICY15_MEASUREMENT_SCHEMA_VERSION
        || observation.policy_version != X64_GATE_B_POLICY15_MEASUREMENT_POLICY_VERSION
        || observation.selection != X64GateBPolicy15CandidateSelection::Policy15Candidate
        || observation.generator_version != X64_GATE_B_WORKLOAD_GENERATOR_VERSION
        || observation.generator_seed != X64_GATE_B_WORKLOAD_GENERATOR_SEED
        || observation.array_elements != X64_GATE_B_ARRAY_ELEMENTS
        || observation.repetitions != X64_GATE_B_REPETITIONS
        || observation.element_visits != X64_GATE_B_ELEMENT_VISITS
        || observation.warmup_pairs != X64_GATE_B_WARMUP_PAIRS
        || observation.measured_pairs != X64_GATE_B_MEASURED_PAIRS
        || observation.process_timeout_millis != X64_GATE_B_PROCESS_TIMEOUT_MILLIS
        || !observation.paired_alternating_schedule
        || observation.sample_deletion_permitted
        || observation.statistics_policy_version != X64_GATE_B_POLICY15_STATISTICS_POLICY_VERSION
        || observation.maximum_cv_percent != X64_GATE_B_MAX_CV_PERCENT
        || observation.threshold_policy_version != X64_GATE_B_POLICY15_THRESHOLD_POLICY_VERSION
        || observation.maximum_slowdown_numerator != X64_GATE_B_MAX_SLOWDOWN_NUMERATOR
        || observation.maximum_slowdown_denominator != X64_GATE_B_MAX_SLOWDOWN_DENOMINATOR
        || observation.release_build == cfg!(debug_assertions)
        || observation.affinity_logical_cpus == 0
    {
        return Err(X64GateBPolicy15MeasurementError::InvalidField {
            field: "frozen policy or host shape",
        });
    }
    if observation.repository_state_recorded
        || observation.repository_revision_hash != SemanticHash::ZERO
        || !observation.repository_dirty
    {
        return Err(X64GateBPolicy15MeasurementError::InvalidField {
            field: "local-only repository state",
        });
    }
    let workload = frozen_workload()?;
    if observation.input_values_hash != workload.input_values_hash
        || observation.input_frame_hash != workload.input_frame_hash
        || observation.expected_output != workload.expected_output
        || observation.expected_output_frame_hash != workload.expected_output_frame_hash
    {
        return Err(X64GateBPolicy15MeasurementError::InvalidField {
            field: "workload identity",
        });
    }
    let direct = direct_process.evidence();
    if observation.manifest_hash != authority.manifest_hash()
        || observation.candidate_capsule_hash != authority.candidate_capsule_hash()
        || observation.correctness_results_hash != authority.correctness_results_hash()
        || observation.worker_process_results_hash != authority.process_results_hash()
        || observation.standalone_process_results_hash != direct.results_hash()
        || observation.candidate_artifact_hash != artifact.artifact_hash()
        || observation.candidate_elf_image_hash != artifact.elf_image_hash()
        || observation.candidate_startup_plan_hash != artifact.startup_plan_hash()
        || observation.candidate_startup_code_hash != artifact.startup_code_hash()
        || observation.candidate_target_artifact_hash != authority.target_artifact_hash()
        || observation.candidate_target_plan_hash != authority.target_plan_hash()
        || observation.candidate_target_code_hash != authority.target_code_hash()
        || observation.bounds_fallback_artifact_hash != direct.bounds_artifact_hash()
        || observation.bounds_fallback_elf_image_hash != direct.bounds_elf_image_hash()
    {
        return Err(X64GateBPolicy15MeasurementError::InvalidField {
            field: "candidate provenance identity",
        });
    }
    let baseline = build_x64_gate_b_baseline_artifact()?;
    let verified_baseline = verify_x64_gate_b_baseline_artifact(baseline.image_bytes())?;
    if observation.baseline_target_hash != verified_baseline.target_hash()
        || observation.baseline_elf_image_hash != verified_baseline.elf_image_hash()
        || observation.baseline_artifact_hash != verified_baseline.artifact_hash()
        || observation.baseline_target_hash != baseline_admission.evidence().target_hash()
        || observation.baseline_elf_image_hash != baseline_admission.evidence().elf_image_hash()
        || observation.baseline_artifact_hash != baseline_admission.evidence().artifact_hash()
        || observation.baseline_admission_results_hash != baseline_admission.results_hash()
    {
        return Err(X64GateBPolicy15MeasurementError::InvalidField {
            field: "baseline identity",
        });
    }
    if observation.samples.len() != X64_GATE_B_MEASURED_PAIRS as usize {
        return Err(X64GateBMeasurementError::SampleCount {
            expected: X64_GATE_B_MEASURED_PAIRS,
            actual: observation.samples.len(),
        }
        .into());
    }
    for (index, sample) in observation.samples.iter().enumerate() {
        let ordinal =
            u32::try_from(index).map_err(|_| X64GateBMeasurementError::ArithmeticOverflow {
                field: "candidate pair ordinal",
            })?;
        let expected_first = if ordinal.is_multiple_of(2) {
            X64GateBEngine::Naux
        } else {
            X64GateBEngine::HandBaseline
        };
        if sample.pair_ordinal() != ordinal
            || sample.first() != expected_first
            || sample.naux_nanoseconds() == 0
            || sample.baseline_nanoseconds() == 0
            || sample.naux_output_frame_hash() != workload.expected_output_frame_hash
            || sample.baseline_output_frame_hash() != workload.expected_output_frame_hash
        {
            return Err(X64GateBPolicy15MeasurementError::InvalidField {
                field: "sample schedule, duration, or output",
            });
        }
    }
    let candidate_samples = observation
        .samples
        .iter()
        .map(X64GateBPairSample::naux_nanoseconds)
        .collect::<Vec<_>>();
    let baseline_samples = observation
        .samples
        .iter()
        .map(X64GateBPairSample::baseline_nanoseconds)
        .collect::<Vec<_>>();
    if observation.candidate_statistics != compute_statistics(&candidate_samples)? {
        return Err(X64GateBPolicy15MeasurementError::InvalidField {
            field: "candidate statistics",
        });
    }
    if observation.baseline_statistics != compute_statistics(&baseline_samples)? {
        return Err(X64GateBPolicy15MeasurementError::InvalidField {
            field: "baseline statistics",
        });
    }
    if observation.performance_threshold_met
        != performance_threshold(
            observation.candidate_statistics,
            observation.baseline_statistics,
        )?
    {
        return Err(X64GateBPolicy15MeasurementError::InvalidField {
            field: "performance threshold decision",
        });
    }
    if observation.observation_hash != observation_hash(observation)? {
        return Err(X64GateBPolicy15MeasurementError::ObservationHashMismatch);
    }
    Ok(VerifiedX64GateBPolicy15Measurement { observation })
}

pub fn admit_x64_gate_b_policy15_measurement_claim(
    verified: VerifiedX64GateBPolicy15Measurement<'_>,
) -> Result<AdmittedX64GateBPolicy15Claim<'_>, X64GateBPolicy15ClaimRejection> {
    let observation = verified.observation;
    if !observation.release_build {
        return Err(X64GateBPolicy15ClaimRejection::DebugBuild);
    }
    if observation.affinity_logical_cpus != 1 {
        return Err(X64GateBPolicy15ClaimRejection::CpuNotPinned {
            logical_cpus: observation.affinity_logical_cpus,
        });
    }
    if !observation.repository_state_recorded
        || observation.repository_revision_hash == SemanticHash::ZERO
    {
        return Err(X64GateBPolicy15ClaimRejection::RepositoryStateMissing);
    }
    if observation.repository_dirty {
        return Err(X64GateBPolicy15ClaimRejection::DirtyRepository);
    }
    if !observation.candidate_statistics.cv_within_limit() {
        return Err(X64GateBPolicy15ClaimRejection::CandidateCoefficientOfVariation);
    }
    if !observation.baseline_statistics.cv_within_limit() {
        return Err(X64GateBPolicy15ClaimRejection::BaselineCoefficientOfVariation);
    }
    if !observation.performance_threshold_met {
        return Err(X64GateBPolicy15ClaimRejection::PerformanceThreshold);
    }
    Ok(AdmittedX64GateBPolicy15Claim { verified })
}

pub(super) fn validate_inputs(
    authority: &X64GateBPolicy15StandaloneAuthority<'_, '_>,
    artifact: &VerifiedX64GateBPolicy15StandaloneArtifact<'_, '_, '_, '_>,
    direct_process: VerifiedX64GateBPolicy15StandaloneProcess<'_, '_, '_, '_, '_>,
    baseline_admission: VerifiedX64GateBBaselineAdmission<'_>,
) -> Result<(), X64GateBPolicy15MeasurementError> {
    authority.revalidate_complete()?;
    let _ = verify_x64_gate_b_policy15_standalone_artifact(authority, artifact.image_bytes())?;
    let direct = direct_process.evidence();
    if authority.profile() != X64StandaloneProfile::BranchMix
        || authority.selection() != X64GateBPolicy15CandidateSelection::Policy15Candidate
        || artifact.profile() != X64StandaloneProfile::BranchMix
        || artifact.selection() != X64GateBPolicy15CandidateSelection::Policy15Candidate
        || artifact.artifact_hash()
            != x64_gate_b_policy15_accepted_standalone_artifact_hash(
                X64StandaloneProfile::BranchMix,
            )
        || artifact.interpreter_dependency()
        || artifact.external_symbol_dependency()
        || artifact.dynamic_loader_dependency()
        || artifact.system_linker_dependency()
        || artifact.fallback()
    {
        return Err(X64GateBPolicy15MeasurementError::InvalidField {
            field: "candidate authority/artifact envelope",
        });
    }
    if direct.manifest_hash() != authority.manifest_hash()
        || direct.candidate_capsule_hash() != authority.candidate_capsule_hash()
        || direct.correctness_results_hash() != authority.correctness_results_hash()
        || direct.process_results_hash() != authority.process_results_hash()
        || direct.branch_artifact_hash() != artifact.artifact_hash()
        || direct.branch_elf_image_hash() != artifact.elf_image_hash()
        || direct.results_hash() != x64_gate_b_policy15_accepted_standalone_results_hash()
        || direct.candidate_execution_cases() != 46
        || direct.fallback_cases() != 5
        || direct.records().len() != 51
    {
        return Err(X64GateBPolicy15MeasurementError::InvalidField {
            field: "ADR-0054 direct-process witness",
        });
    }
    let baseline = build_x64_gate_b_baseline_artifact()?;
    let verified_baseline = verify_x64_gate_b_baseline_artifact(baseline.image_bytes())?;
    let admitted = baseline_admission.evidence();
    if admitted.target_hash() != verified_baseline.target_hash()
        || admitted.elf_image_hash() != verified_baseline.elf_image_hash()
        || admitted.artifact_hash() != verified_baseline.artifact_hash()
        || admitted.interpreter_dependency()
        || admitted.generated_target_dependency()
        || admitted.dynamic_loader_dependency()
        || admitted.external_symbol_dependency()
        || admitted.fallback()
    {
        return Err(X64GateBPolicy15MeasurementError::InvalidField {
            field: "baseline admission/artifact envelope",
        });
    }
    Ok(())
}

fn materialization_error(
    engine: X64GateBEngine,
    source: X64StandaloneProcessError,
) -> X64GateBPolicy15MeasurementError {
    X64GateBMeasurementError::Process {
        engine,
        phase: "materialization",
        pair_ordinal: 0,
        source,
    }
    .into()
}

fn cleanup_error(
    engine: X64GateBEngine,
    source: X64StandaloneProcessError,
) -> X64GateBPolicy15MeasurementError {
    X64GateBMeasurementError::Cleanup { engine, source }.into()
}

fn merge_cleanup<T>(
    primary: Result<T, X64GateBPolicy15MeasurementError>,
    cleanup: Result<(), X64GateBPolicy15MeasurementError>,
) -> Result<T, X64GateBPolicy15MeasurementError> {
    match (primary, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(X64GateBPolicy15MeasurementError::Mechanical(
            X64GateBMeasurementError::FailureDuringCleanup {
                primary: Box::new(into_mechanical(primary)),
                cleanup: Box::new(into_mechanical(cleanup)),
            },
        )),
    }
}

fn into_mechanical(error: X64GateBPolicy15MeasurementError) -> X64GateBMeasurementError {
    match error {
        X64GateBPolicy15MeasurementError::Mechanical(error) => error,
        other => X64GateBMeasurementError::Protocol {
            message: other.to_string(),
        },
    }
}

fn observation_hash(
    observation: &X64GateBPolicy15MeasurementObservation,
) -> Result<SemanticHash, X64GateBPolicy15MeasurementError> {
    let sample_count = u32::try_from(observation.samples.len()).map_err(|_| {
        X64GateBMeasurementError::ArithmeticOverflow {
            field: "candidate observation sample count",
        }
    })?;
    let mut bytes =
        Vec::with_capacity(OBSERVATION_DOMAIN.len() + 1_024 + observation.samples.len() * 88);
    bytes.extend_from_slice(OBSERVATION_DOMAIN);
    put_version(&mut bytes, observation.schema_version);
    put_version(&mut bytes, observation.policy_version);
    bytes.push(selection_tag(observation.selection));
    put_version(&mut bytes, observation.generator_version);
    put_u64(&mut bytes, observation.generator_seed);
    put_u32(&mut bytes, observation.array_elements);
    put_i64(&mut bytes, observation.repetitions);
    put_u64(&mut bytes, observation.element_visits);
    put_hash(&mut bytes, observation.input_values_hash);
    put_hash(&mut bytes, observation.input_frame_hash);
    put_outcome(&mut bytes, observation.expected_output);
    put_hash(&mut bytes, observation.expected_output_frame_hash);
    for hash in [
        observation.manifest_hash,
        observation.candidate_capsule_hash,
        observation.correctness_results_hash,
        observation.worker_process_results_hash,
        observation.standalone_process_results_hash,
        observation.candidate_artifact_hash,
        observation.candidate_elf_image_hash,
        observation.candidate_startup_plan_hash,
        observation.candidate_startup_code_hash,
        observation.candidate_target_artifact_hash,
        observation.candidate_target_plan_hash,
        observation.candidate_target_code_hash,
        observation.bounds_fallback_artifact_hash,
        observation.bounds_fallback_elf_image_hash,
        observation.baseline_target_hash,
        observation.baseline_elf_image_hash,
        observation.baseline_artifact_hash,
        observation.baseline_admission_results_hash,
    ] {
        put_hash(&mut bytes, hash);
    }
    put_u32(&mut bytes, observation.warmup_pairs);
    put_u32(&mut bytes, observation.measured_pairs);
    put_u32(&mut bytes, observation.process_timeout_millis);
    put_bool(&mut bytes, observation.paired_alternating_schedule);
    put_bool(&mut bytes, observation.sample_deletion_permitted);
    put_version(&mut bytes, observation.statistics_policy_version);
    put_u32(&mut bytes, observation.maximum_cv_percent);
    put_version(&mut bytes, observation.threshold_policy_version);
    put_u32(&mut bytes, observation.maximum_slowdown_numerator);
    put_u32(&mut bytes, observation.maximum_slowdown_denominator);
    put_bool(&mut bytes, observation.release_build);
    put_u32(&mut bytes, observation.affinity_logical_cpus);
    put_bool(&mut bytes, observation.repository_state_recorded);
    put_hash(&mut bytes, observation.repository_revision_hash);
    put_bool(&mut bytes, observation.repository_dirty);
    put_u32(&mut bytes, sample_count);
    for sample in &observation.samples {
        put_u32(&mut bytes, sample.pair_ordinal());
        bytes.push(engine_tag(sample.first()));
        put_u64(&mut bytes, sample.naux_nanoseconds());
        put_u64(&mut bytes, sample.baseline_nanoseconds());
        put_hash(&mut bytes, sample.naux_output_frame_hash());
        put_hash(&mut bytes, sample.baseline_output_frame_hash());
    }
    put_statistics(&mut bytes, observation.candidate_statistics);
    put_statistics(&mut bytes, observation.baseline_statistics);
    put_bool(&mut bytes, observation.performance_threshold_met);
    Ok(SemanticHash(sha256(&bytes)))
}

fn selection_tag(selection: X64GateBPolicy15CandidateSelection) -> u8 {
    match selection {
        X64GateBPolicy15CandidateSelection::Policy15Candidate => 0,
        X64GateBPolicy15CandidateSelection::Policy14Fallback => 1,
    }
}

fn engine_tag(engine: X64GateBEngine) -> u8 {
    match engine {
        X64GateBEngine::Naux => 0,
        X64GateBEngine::HandBaseline => 1,
    }
}

fn put_outcome(bytes: &mut Vec<u8>, outcome: X64StandaloneOutcome) {
    match outcome {
        X64StandaloneOutcome::ReturnF64 { bits } => {
            bytes.push(0);
            put_u64(bytes, bits);
        }
        X64StandaloneOutcome::Bounds => {
            bytes.push(1);
            put_u64(bytes, 0);
        }
    }
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_be_bytes());
    bytes.extend_from_slice(&version.1.to_be_bytes());
    bytes.extend_from_slice(&version.2.to_be_bytes());
}

fn put_bool(bytes: &mut Vec<u8>, value: bool) {
    bytes.push(u8::from(value));
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_i64(bytes: &mut Vec<u8>, value: i64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_hash(bytes: &mut Vec<u8>, value: SemanticHash) {
    bytes.extend_from_slice(&value.0);
}

#[cfg(test)]
mod tests {
    use super::super::x64_gate_b_measurement::pair_sample_for_tests;
    use super::*;

    fn synthetic_observation() -> X64GateBPolicy15MeasurementObservation {
        let workload = frozen_workload().expect("frozen workload");
        let samples = (0..X64_GATE_B_MEASURED_PAIRS)
            .map(|ordinal| {
                super::super::x64_gate_b_measurement::pair_sample_for_tests(
                    ordinal,
                    if ordinal.is_multiple_of(2) {
                        X64GateBEngine::Naux
                    } else {
                        X64GateBEngine::HandBaseline
                    },
                    100,
                    100,
                    workload.expected_output_frame_hash,
                    workload.expected_output_frame_hash,
                )
            })
            .collect::<Vec<_>>();
        let statistics = compute_statistics(&vec![100; 30]).expect("statistics");
        X64GateBPolicy15MeasurementObservation {
            schema_version: X64_GATE_B_POLICY15_MEASUREMENT_SCHEMA_VERSION,
            policy_version: X64_GATE_B_POLICY15_MEASUREMENT_POLICY_VERSION,
            selection: X64GateBPolicy15CandidateSelection::Policy15Candidate,
            generator_version: X64_GATE_B_WORKLOAD_GENERATOR_VERSION,
            generator_seed: X64_GATE_B_WORKLOAD_GENERATOR_SEED,
            array_elements: X64_GATE_B_ARRAY_ELEMENTS,
            repetitions: X64_GATE_B_REPETITIONS,
            element_visits: X64_GATE_B_ELEMENT_VISITS,
            input_values_hash: workload.input_values_hash,
            input_frame_hash: workload.input_frame_hash,
            expected_output: workload.expected_output,
            expected_output_frame_hash: workload.expected_output_frame_hash,
            manifest_hash: SemanticHash([1; 32]),
            candidate_capsule_hash: SemanticHash([2; 32]),
            correctness_results_hash: SemanticHash([3; 32]),
            worker_process_results_hash: SemanticHash([4; 32]),
            standalone_process_results_hash: SemanticHash([5; 32]),
            candidate_artifact_hash: SemanticHash([6; 32]),
            candidate_elf_image_hash: SemanticHash([7; 32]),
            candidate_startup_plan_hash: SemanticHash([8; 32]),
            candidate_startup_code_hash: SemanticHash([9; 32]),
            candidate_target_artifact_hash: SemanticHash([10; 32]),
            candidate_target_plan_hash: SemanticHash([11; 32]),
            candidate_target_code_hash: SemanticHash([12; 32]),
            bounds_fallback_artifact_hash: SemanticHash([13; 32]),
            bounds_fallback_elf_image_hash: SemanticHash([14; 32]),
            baseline_target_hash: SemanticHash([15; 32]),
            baseline_elf_image_hash: SemanticHash([16; 32]),
            baseline_artifact_hash: SemanticHash([17; 32]),
            baseline_admission_results_hash: SemanticHash([18; 32]),
            warmup_pairs: X64_GATE_B_WARMUP_PAIRS,
            measured_pairs: X64_GATE_B_MEASURED_PAIRS,
            process_timeout_millis: X64_GATE_B_PROCESS_TIMEOUT_MILLIS,
            paired_alternating_schedule: true,
            sample_deletion_permitted: false,
            statistics_policy_version: X64_GATE_B_POLICY15_STATISTICS_POLICY_VERSION,
            maximum_cv_percent: X64_GATE_B_MAX_CV_PERCENT,
            threshold_policy_version: X64_GATE_B_POLICY15_THRESHOLD_POLICY_VERSION,
            maximum_slowdown_numerator: X64_GATE_B_MAX_SLOWDOWN_NUMERATOR,
            maximum_slowdown_denominator: X64_GATE_B_MAX_SLOWDOWN_DENOMINATOR,
            release_build: true,
            affinity_logical_cpus: 1,
            repository_state_recorded: true,
            repository_revision_hash: SemanticHash([19; 32]),
            repository_dirty: false,
            samples,
            candidate_statistics: statistics,
            baseline_statistics: statistics,
            performance_threshold_met: true,
            observation_hash: SemanticHash::ZERO,
        }
    }

    #[test]
    fn claim_rejection_is_fail_closed_and_candidate_specific() {
        let mut observation = synthetic_observation();

        let verified = VerifiedX64GateBPolicy15Measurement {
            observation: &observation,
        };
        assert!(admit_x64_gate_b_policy15_measurement_claim(verified).is_ok());

        observation.release_build = false;
        let verified = VerifiedX64GateBPolicy15Measurement {
            observation: &observation,
        };
        assert_eq!(
            admit_x64_gate_b_policy15_measurement_claim(verified),
            Err(X64GateBPolicy15ClaimRejection::DebugBuild)
        );

        observation.release_build = true;
        observation.affinity_logical_cpus = 2;
        let verified = VerifiedX64GateBPolicy15Measurement {
            observation: &observation,
        };
        assert_eq!(
            admit_x64_gate_b_policy15_measurement_claim(verified),
            Err(X64GateBPolicy15ClaimRejection::CpuNotPinned { logical_cpus: 2 })
        );

        observation.affinity_logical_cpus = 1;
        observation.repository_state_recorded = false;
        let verified = VerifiedX64GateBPolicy15Measurement {
            observation: &observation,
        };
        assert_eq!(
            admit_x64_gate_b_policy15_measurement_claim(verified),
            Err(X64GateBPolicy15ClaimRejection::RepositoryStateMissing)
        );

        observation.repository_state_recorded = true;
        observation.repository_dirty = true;
        let verified = VerifiedX64GateBPolicy15Measurement {
            observation: &observation,
        };
        assert_eq!(
            admit_x64_gate_b_policy15_measurement_claim(verified),
            Err(X64GateBPolicy15ClaimRejection::DirtyRepository)
        );

        observation.repository_dirty = false;
        observation.candidate_statistics =
            compute_statistics(&(1_u64..=30).collect::<Vec<_>>()).expect("noisy candidate");
        let verified = VerifiedX64GateBPolicy15Measurement {
            observation: &observation,
        };
        assert_eq!(
            admit_x64_gate_b_policy15_measurement_claim(verified),
            Err(X64GateBPolicy15ClaimRejection::CandidateCoefficientOfVariation)
        );

        observation.candidate_statistics =
            compute_statistics(&vec![100; 30]).expect("stable candidate");
        observation.baseline_statistics =
            compute_statistics(&(1_u64..=30).collect::<Vec<_>>()).expect("noisy baseline");
        let verified = VerifiedX64GateBPolicy15Measurement {
            observation: &observation,
        };
        assert_eq!(
            admit_x64_gate_b_policy15_measurement_claim(verified),
            Err(X64GateBPolicy15ClaimRejection::BaselineCoefficientOfVariation)
        );

        observation.baseline_statistics =
            compute_statistics(&vec![100; 30]).expect("stable baseline");
        observation.performance_threshold_met = false;
        let verified = VerifiedX64GateBPolicy15Measurement {
            observation: &observation,
        };
        assert_eq!(
            admit_x64_gate_b_policy15_measurement_claim(verified),
            Err(X64GateBPolicy15ClaimRejection::PerformanceThreshold)
        );
    }

    #[test]
    fn observation_seal_covers_provenance_samples_and_decisions() {
        let mut observation = synthetic_observation();
        let original = observation_hash(&observation).expect("original seal");

        observation.worker_process_results_hash = SemanticHash([77; 32]);
        assert_ne!(
            observation_hash(&observation).expect("mutated root"),
            original
        );
        observation = synthetic_observation();
        observation.performance_threshold_met = false;
        assert_ne!(
            observation_hash(&observation).expect("mutated decision"),
            original
        );
        observation = synthetic_observation();
        observation.samples.swap(0, 1);
        assert_ne!(
            observation_hash(&observation).expect("mutated order"),
            original
        );
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    #[test]
    #[ignore = "launches exact ADR-0054 candidate/fallback and baseline admission processes, then executes the complete 5+30 paired ADR-0055 measurement; run explicitly in release mode"]
    fn full_candidate_matched_measurement_replays_and_rejects_resealed_mutations() {
        use super::super::x64_gate_b_baseline_admission::{
            emit_x64_gate_b_baseline_admission, verify_x64_gate_b_baseline_admission,
        };
        use super::super::x64_gate_b_candidate_admission::{
            emit_reconstructed_candidate_correctness_for_process_tests,
            verify_reconstructed_candidate_correctness_for_tests,
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
            .expect("synthetic process transport");
        let verified_process =
            verify_x64_gate_b_policy15_candidate_process_evidence(verified_correctness, &process)
                .expect("process replay");
        let branch = authorize_x64_gate_b_policy15_standalone(
            verified_correctness,
            verified_process,
            X64StandaloneProfile::BranchMix,
        )
        .expect("BranchMix authority");
        let bounds = authorize_x64_gate_b_policy15_standalone(
            verified_correctness,
            verified_process,
            X64StandaloneProfile::Bounds,
        )
        .expect("Bounds authority");
        let branch_image =
            build_x64_gate_b_policy15_standalone_artifact(&branch).expect("BranchMix ELF");
        let bounds_image =
            build_x64_gate_b_policy15_standalone_artifact(&bounds).expect("Bounds ELF");
        let branch_artifact =
            verify_x64_gate_b_policy15_standalone_artifact(&branch, branch_image.image_bytes())
                .expect("BranchMix ELF replay");
        let bounds_artifact =
            verify_x64_gate_b_policy15_standalone_artifact(&bounds, bounds_image.image_bytes())
                .expect("Bounds ELF replay");
        let direct = emit_x64_gate_b_policy15_standalone_process_evidence(
            &branch,
            &branch_artifact,
            &bounds,
            &bounds_artifact,
        )
        .expect("ADR-0054 direct processes");
        let verified_direct = verify_x64_gate_b_policy15_standalone_process_evidence(
            &branch,
            &branch_artifact,
            &bounds,
            &bounds_artifact,
            &direct,
        )
        .expect("ADR-0054 replay");
        let baseline = emit_x64_gate_b_baseline_admission().expect("baseline admission");
        let verified_baseline =
            verify_x64_gate_b_baseline_admission(&baseline).expect("baseline replay");
        let observation = emit_x64_gate_b_policy15_measurement_observation(
            &branch,
            &branch_artifact,
            verified_direct,
            verified_baseline,
        )
        .expect("candidate-matched observation");
        let verified = verify_x64_gate_b_policy15_measurement_observation(
            &observation,
            &branch,
            &branch_artifact,
            verified_direct,
            verified_baseline,
        )
        .expect("candidate-matched observation replay");
        assert_eq!(verified.observation(), &observation);
        assert_eq!(observation.samples.len(), 30);
        assert!(matches!(
            admit_x64_gate_b_policy15_measurement_claim(verified),
            Err(X64GateBPolicy15ClaimRejection::DebugBuild
                | X64GateBPolicy15ClaimRejection::CpuNotPinned { .. }
                | X64GateBPolicy15ClaimRejection::RepositoryStateMissing)
        ));

        let mut wrong_root = observation.clone();
        wrong_root.worker_process_results_hash = SemanticHash([0x55; 32]);
        wrong_root.observation_hash = observation_hash(&wrong_root).expect("reseal root");
        assert!(verify_x64_gate_b_policy15_measurement_observation(
            &wrong_root,
            &branch,
            &branch_artifact,
            verified_direct,
            verified_baseline,
        )
        .is_err());

        let mut wrong_baseline = observation.clone();
        wrong_baseline.baseline_artifact_hash = SemanticHash([0x66; 32]);
        wrong_baseline.observation_hash =
            observation_hash(&wrong_baseline).expect("reseal baseline");
        assert!(verify_x64_gate_b_policy15_measurement_observation(
            &wrong_baseline,
            &branch,
            &branch_artifact,
            verified_direct,
            verified_baseline,
        )
        .is_err());

        let mut wrong_schedule = observation.clone();
        wrong_schedule.samples.swap(0, 1);
        wrong_schedule.observation_hash = observation_hash(&wrong_schedule).expect("reseal order");
        assert!(verify_x64_gate_b_policy15_measurement_observation(
            &wrong_schedule,
            &branch,
            &branch_artifact,
            verified_direct,
            verified_baseline,
        )
        .is_err());

        let mut wrong_sample = observation.clone();
        let first = &wrong_sample.samples[0];
        wrong_sample.samples[0] = pair_sample_for_tests(
            first.pair_ordinal(),
            first.first(),
            first.naux_nanoseconds() + 1,
            first.baseline_nanoseconds(),
            first.naux_output_frame_hash(),
            first.baseline_output_frame_hash(),
        );
        wrong_sample.observation_hash = observation_hash(&wrong_sample).expect("reseal sample");
        assert!(verify_x64_gate_b_policy15_measurement_observation(
            &wrong_sample,
            &branch,
            &branch_artifact,
            verified_direct,
            verified_baseline,
        )
        .is_err());

        let mut wrong_statistics = observation.clone();
        wrong_statistics.candidate_statistics =
            compute_statistics(&vec![1; 30]).expect("wrong statistics");
        wrong_statistics.observation_hash =
            observation_hash(&wrong_statistics).expect("reseal statistics");
        assert!(verify_x64_gate_b_policy15_measurement_observation(
            &wrong_statistics,
            &branch,
            &branch_artifact,
            verified_direct,
            verified_baseline,
        )
        .is_err());

        let mut wrong_decision = observation.clone();
        wrong_decision.performance_threshold_met = !wrong_decision.performance_threshold_met;
        wrong_decision.observation_hash =
            observation_hash(&wrong_decision).expect("reseal decision");
        assert!(verify_x64_gate_b_policy15_measurement_observation(
            &wrong_decision,
            &branch,
            &branch_artifact,
            verified_direct,
            verified_baseline,
        )
        .is_err());

        println!(
            "ADR-0055 observation={} candidate-median-x2={} baseline-median-x2={} candidate-p95={} baseline-p95={} candidate-cv={} baseline-cv={} threshold={}",
            observation.observation_hash().to_hex(),
            observation.candidate_statistics().median_twice_nanoseconds(),
            observation.baseline_statistics().median_twice_nanoseconds(),
            observation.candidate_statistics().p95_nanoseconds(),
            observation.baseline_statistics().p95_nanoseconds(),
            observation.candidate_statistics().cv_within_limit(),
            observation.baseline_statistics().cv_within_limit(),
            observation.performance_threshold_met(),
        );
    }
}
