//! Bounded alternating end-to-end measurement for Gate B.
//!
//! Observation verification and performance-claim admission are separate.
//! A local, dirty, debug, unpinned, noisy, or slow observation remains useful
//! evidence but cannot close Gate B.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_gate_b_baseline::{
    build_x64_gate_b_baseline_artifact, verify_x64_gate_b_baseline_artifact, X64GateBBaselineError,
};
use super::x64_gate_b_baseline_admission::VerifiedX64GateBBaselineAdmission;
use super::x64_standalone_artifact::VerifiedX64StandaloneArtifact;
use super::x64_standalone_process::{
    run_admitted_x64_standalone_process, PreparedX64StandaloneExecutable, X64StandaloneProcessError,
};
use super::x64_standalone_protocol::{
    encode_x64_standalone_input, encode_x64_standalone_output, X64StandaloneInput,
    X64StandaloneOutcome, X64StandaloneOutput, X64StandaloneProfile, X64StandaloneProtocolError,
    X64_STANDALONE_OUTPUT_BYTES,
};
use std::fmt;

pub const X64_GATE_B_MEASUREMENT_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_MEASUREMENT_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_WORKLOAD_GENERATOR_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_WORKLOAD_GENERATOR_SEED: u64 = 0x4e41_5558_4742_5431;
pub const X64_GATE_B_ARRAY_ELEMENTS: u32 = 65_536;
pub const X64_GATE_B_REPETITIONS: i64 = 64;
pub const X64_GATE_B_ELEMENT_VISITS: u64 = 4_194_304;
pub const X64_GATE_B_WARMUP_PAIRS: u32 = 5;
pub const X64_GATE_B_MEASURED_PAIRS: u32 = 30;
pub const X64_GATE_B_PROCESS_TIMEOUT_MILLIS: u32 = 30_000;
pub const X64_GATE_B_MAX_CV_PERCENT: u32 = 5;
pub const X64_GATE_B_MAX_SLOWDOWN_NUMERATOR: u32 = 2;
pub const X64_GATE_B_MAX_SLOWDOWN_DENOMINATOR: u32 = 1;

const OBSERVATION_DOMAIN: &[u8] = b"NAUX:gate-b:standalone:measurement:observation:v1\0";
const INPUT_VALUES_DOMAIN: &[u8] = b"NAUX:gate-b:standalone:measurement:input-values:v1\0";
const INPUT_FRAME_DOMAIN: &[u8] = b"NAUX:gate-b:standalone:measurement:input-frame:v1\0";
const OUTPUT_FRAME_DOMAIN: &[u8] = b"NAUX:gate-b:standalone:measurement:output-frame:v1\0";
const CANONICAL_MXCSR: u32 = 0x0000_1f80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64GateBEngine {
    Naux,
    HandBaseline,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64GateBPairSample {
    pair_ordinal: u32,
    first: X64GateBEngine,
    naux_nanoseconds: u64,
    baseline_nanoseconds: u64,
    naux_output_frame_hash: SemanticHash,
    baseline_output_frame_hash: SemanticHash,
}

impl X64GateBPairSample {
    pub const fn pair_ordinal(&self) -> u32 {
        self.pair_ordinal
    }

    pub const fn first(&self) -> X64GateBEngine {
        self.first
    }

    pub const fn naux_nanoseconds(&self) -> u64 {
        self.naux_nanoseconds
    }

    pub const fn baseline_nanoseconds(&self) -> u64 {
        self.baseline_nanoseconds
    }

    pub const fn naux_output_frame_hash(&self) -> SemanticHash {
        self.naux_output_frame_hash
    }

    pub const fn baseline_output_frame_hash(&self) -> SemanticHash {
        self.baseline_output_frame_hash
    }
}

#[cfg(test)]
pub(super) const fn pair_sample_for_tests(
    pair_ordinal: u32,
    first: X64GateBEngine,
    naux_nanoseconds: u64,
    baseline_nanoseconds: u64,
    naux_output_frame_hash: SemanticHash,
    baseline_output_frame_hash: SemanticHash,
) -> X64GateBPairSample {
    X64GateBPairSample {
        pair_ordinal,
        first,
        naux_nanoseconds,
        baseline_nanoseconds,
        naux_output_frame_hash,
        baseline_output_frame_hash,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64GateBSampleStatistics {
    sample_count: u32,
    median_twice_nanoseconds: u128,
    p95_nanoseconds: u64,
    sum_nanoseconds: u128,
    scaled_squared_deviation_sum: u128,
    cv_comparison_left: u128,
    cv_comparison_right: u128,
    cv_within_limit: bool,
}

impl X64GateBSampleStatistics {
    pub const fn sample_count(self) -> u32 {
        self.sample_count
    }

    /// Exact `2 * median`; odd values represent a half-nanosecond median.
    pub const fn median_twice_nanoseconds(self) -> u128 {
        self.median_twice_nanoseconds
    }

    pub const fn median_floor_nanoseconds(self) -> u128 {
        self.median_twice_nanoseconds / 2
    }

    pub const fn p95_nanoseconds(self) -> u64 {
        self.p95_nanoseconds
    }

    pub const fn sum_nanoseconds(self) -> u128 {
        self.sum_nanoseconds
    }

    pub const fn cv_within_limit(self) -> bool {
        self.cv_within_limit
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64GateBMeasurementObservation {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    generator_version: (u16, u16, u16),
    generator_seed: u64,
    array_elements: u32,
    repetitions: i64,
    element_visits: u64,
    input_values_hash: SemanticHash,
    input_frame_hash: SemanticHash,
    expected_output: X64StandaloneOutcome,
    expected_output_frame: [u8; X64_STANDALONE_OUTPUT_BYTES],
    expected_output_frame_hash: SemanticHash,
    naux_artifact_hash: SemanticHash,
    naux_elf_image_hash: SemanticHash,
    naux_startup_code_hash: SemanticHash,
    baseline_target_hash: SemanticHash,
    baseline_artifact_hash: SemanticHash,
    baseline_admission_results_hash: SemanticHash,
    warmup_pairs: u32,
    measured_pairs: u32,
    process_timeout_millis: u32,
    release_build: bool,
    affinity_logical_cpus: u32,
    repository_state_recorded: bool,
    repository_revision_hash: SemanticHash,
    repository_dirty: bool,
    samples: Vec<X64GateBPairSample>,
    naux_statistics: X64GateBSampleStatistics,
    baseline_statistics: X64GateBSampleStatistics,
    performance_threshold_met: bool,
    observation_hash: SemanticHash,
}

impl X64GateBMeasurementObservation {
    pub const fn input_values_hash(&self) -> SemanticHash {
        self.input_values_hash
    }

    pub const fn input_frame_hash(&self) -> SemanticHash {
        self.input_frame_hash
    }

    pub const fn expected_output(&self) -> X64StandaloneOutcome {
        self.expected_output
    }

    pub const fn naux_artifact_hash(&self) -> SemanticHash {
        self.naux_artifact_hash
    }

    pub const fn baseline_artifact_hash(&self) -> SemanticHash {
        self.baseline_artifact_hash
    }

    pub fn samples(&self) -> &[X64GateBPairSample] {
        &self.samples
    }

    pub const fn naux_statistics(&self) -> X64GateBSampleStatistics {
        self.naux_statistics
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedX64GateBMeasurement<'observation> {
    observation: &'observation X64GateBMeasurementObservation,
}

impl<'observation> VerifiedX64GateBMeasurement<'observation> {
    pub const fn observation(&self) -> &'observation X64GateBMeasurementObservation {
        self.observation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmittedX64GateBClaim<'observation> {
    verified: VerifiedX64GateBMeasurement<'observation>,
}

impl<'observation> AdmittedX64GateBClaim<'observation> {
    pub const fn observation(&self) -> &'observation X64GateBMeasurementObservation {
        self.verified.observation
    }
}

#[derive(Debug)]
pub enum X64GateBMeasurementError {
    UnsupportedHost,
    InvalidNauxArtifact {
        field: &'static str,
    },
    BaselineArtifact(X64GateBBaselineError),
    Protocol {
        message: String,
    },
    Affinity {
        message: String,
    },
    Process {
        engine: X64GateBEngine,
        phase: &'static str,
        pair_ordinal: u32,
        source: X64StandaloneProcessError,
    },
    OutputMismatch {
        engine: X64GateBEngine,
        phase: &'static str,
        pair_ordinal: u32,
    },
    Cleanup {
        engine: X64GateBEngine,
        source: X64StandaloneProcessError,
    },
    FailureDuringCleanup {
        primary: Box<X64GateBMeasurementError>,
        cleanup: Box<X64GateBMeasurementError>,
    },
    SampleCount {
        expected: u32,
        actual: usize,
    },
    ZeroSample {
        index: usize,
    },
    ArithmeticOverflow {
        field: &'static str,
    },
    InvalidObservation {
        field: &'static str,
    },
    InvalidSchedule {
        expected_ordinal: u32,
        actual_ordinal: u32,
    },
    StatisticsMismatch {
        engine: X64GateBEngine,
    },
    ObservationHashMismatch,
}

impl fmt::Display for X64GateBMeasurementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost => {
                formatter.write_str("Gate B measurement requires Linux x86-64")
            }
            Self::InvalidNauxArtifact { field } => {
                write!(formatter, "Gate B NAUX artifact has invalid {field}")
            }
            Self::BaselineArtifact(error) => write!(formatter, "{error}"),
            Self::Protocol { message } => write!(formatter, "Gate B protocol failed: {message}"),
            Self::Affinity { message } => {
                write!(formatter, "Gate B affinity probe failed: {message}")
            }
            Self::Process {
                engine,
                phase,
                pair_ordinal,
                source,
            } => write!(
                formatter,
                "Gate B {engine:?} {phase} pair {pair_ordinal} failed: {source}"
            ),
            Self::OutputMismatch {
                engine,
                phase,
                pair_ordinal,
            } => write!(
                formatter,
                "Gate B {engine:?} {phase} pair {pair_ordinal} produced a different output"
            ),
            Self::Cleanup { engine, source } => {
                write!(formatter, "Gate B {engine:?} cleanup failed: {source}")
            }
            Self::FailureDuringCleanup { primary, cleanup } => {
                write!(
                    formatter,
                    "Gate B failed ({primary}) and cleanup failed ({cleanup})"
                )
            }
            Self::SampleCount { expected, actual } => {
                write!(
                    formatter,
                    "Gate B requires {expected} samples; found {actual}"
                )
            }
            Self::ZeroSample { index } => {
                write!(formatter, "Gate B sample {index} has zero nanoseconds")
            }
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "Gate B {field} arithmetic overflow")
            }
            Self::InvalidObservation { field } => {
                write!(formatter, "Gate B observation has invalid {field}")
            }
            Self::InvalidSchedule {
                expected_ordinal,
                actual_ordinal,
            } => write!(
                formatter,
                "Gate B expected pair {expected_ordinal}; found {actual_ordinal}"
            ),
            Self::StatisticsMismatch { engine } => {
                write!(formatter, "Gate B {engine:?} statistics do not replay")
            }
            Self::ObservationHashMismatch => {
                formatter.write_str("Gate B observation hash does not replay")
            }
        }
    }
}

impl std::error::Error for X64GateBMeasurementError {}

impl From<X64GateBBaselineError> for X64GateBMeasurementError {
    fn from(error: X64GateBBaselineError) -> Self {
        Self::BaselineArtifact(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64GateBClaimRejection {
    DebugBuild,
    CpuNotPinned { logical_cpus: u32 },
    RepositoryStateMissing,
    DirtyRepository,
    NauxCoefficientOfVariation,
    BaselineCoefficientOfVariation,
    PerformanceThreshold,
}

impl fmt::Display for X64GateBClaimRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DebugBuild => formatter.write_str("Gate B claim requires a release build"),
            Self::CpuNotPinned { logical_cpus } => write!(
                formatter,
                "Gate B claim requires one pinned logical CPU; affinity admits {logical_cpus}"
            ),
            Self::RepositoryStateMissing => {
                formatter.write_str("Gate B claim lacks an independently recorded revision")
            }
            Self::DirtyRepository => {
                formatter.write_str("Gate B claim requires a clean recorded revision")
            }
            Self::NauxCoefficientOfVariation => {
                formatter.write_str("Gate B NAUX samples exceed 5% CV")
            }
            Self::BaselineCoefficientOfVariation => {
                formatter.write_str("Gate B baseline samples exceed 5% CV")
            }
            Self::PerformanceThreshold => {
                formatter.write_str("Gate B NAUX median exceeds 2x the baseline median")
            }
        }
    }
}

impl std::error::Error for X64GateBClaimRejection {}

pub(super) struct FrozenWorkload {
    pub(super) values: Vec<u64>,
    pub(super) input_frame: Vec<u8>,
    pub(super) input_values_hash: SemanticHash,
    pub(super) input_frame_hash: SemanticHash,
    pub(super) expected_output: X64StandaloneOutcome,
    pub(super) expected_output_frame: [u8; X64_STANDALONE_OUTPUT_BYTES],
    pub(super) expected_output_frame_hash: SemanticHash,
}

/// Emit one local observation. Repository state is deliberately marked
/// unrecorded, so this API alone can never close Gate B.
pub fn emit_x64_gate_b_measurement_observation(
    naux_artifact: &VerifiedX64StandaloneArtifact<'_, '_, '_>,
    baseline_admission: VerifiedX64GateBBaselineAdmission<'_>,
) -> Result<X64GateBMeasurementObservation, X64GateBMeasurementError> {
    require_host()?;
    validate_naux_artifact(naux_artifact)?;
    let baseline = build_x64_gate_b_baseline_artifact()?;
    let verified_baseline = verify_x64_gate_b_baseline_artifact(baseline.image_bytes())?;
    if verified_baseline.target_hash() != baseline_admission.evidence().target_hash()
        || verified_baseline.elf_image_hash() != baseline_admission.evidence().elf_image_hash()
        || verified_baseline.artifact_hash() != baseline_admission.evidence().artifact_hash()
    {
        return Err(X64GateBMeasurementError::InvalidObservation {
            field: "baseline admission/artifact identity",
        });
    }
    let workload = frozen_workload()?;
    let affinity_logical_cpus = affinity_logical_cpu_count()?;

    let mut naux_executable = PreparedX64StandaloneExecutable::create(
        X64StandaloneProfile::BranchMix,
        naux_artifact.image_bytes(),
    )
    .map_err(|source| X64GateBMeasurementError::Process {
        engine: X64GateBEngine::Naux,
        phase: "materialization",
        pair_ordinal: 0,
        source,
    })?;
    let baseline_executable = PreparedX64StandaloneExecutable::create(
        X64StandaloneProfile::BranchMix,
        verified_baseline.image_bytes(),
    );
    let mut baseline_executable = match baseline_executable {
        Ok(executable) => executable,
        Err(source) => {
            let primary = X64GateBMeasurementError::Process {
                engine: X64GateBEngine::HandBaseline,
                phase: "materialization",
                pair_ordinal: 0,
                source,
            };
            let cleanup =
                naux_executable
                    .cleanup()
                    .map_err(|source| X64GateBMeasurementError::Cleanup {
                        engine: X64GateBEngine::Naux,
                        source,
                    });
            return merge_one_cleanup(Err(primary), cleanup);
        }
    };

    let measurement = (|| {
        run_warmups(&naux_executable, &baseline_executable, &workload)?;
        let samples = run_measured_pairs(&naux_executable, &baseline_executable, &workload)?;
        let naux_samples = samples
            .iter()
            .map(X64GateBPairSample::naux_nanoseconds)
            .collect::<Vec<_>>();
        let baseline_samples = samples
            .iter()
            .map(X64GateBPairSample::baseline_nanoseconds)
            .collect::<Vec<_>>();
        let naux_statistics = compute_statistics(&naux_samples)?;
        let baseline_statistics = compute_statistics(&baseline_samples)?;
        let performance_threshold_met =
            performance_threshold(naux_statistics, baseline_statistics)?;
        let mut observation = X64GateBMeasurementObservation {
            schema_version: X64_GATE_B_MEASUREMENT_SCHEMA_VERSION,
            policy_version: X64_GATE_B_MEASUREMENT_POLICY_VERSION,
            generator_version: X64_GATE_B_WORKLOAD_GENERATOR_VERSION,
            generator_seed: X64_GATE_B_WORKLOAD_GENERATOR_SEED,
            array_elements: X64_GATE_B_ARRAY_ELEMENTS,
            repetitions: X64_GATE_B_REPETITIONS,
            element_visits: X64_GATE_B_ELEMENT_VISITS,
            input_values_hash: workload.input_values_hash,
            input_frame_hash: workload.input_frame_hash,
            expected_output: workload.expected_output,
            expected_output_frame: workload.expected_output_frame,
            expected_output_frame_hash: workload.expected_output_frame_hash,
            naux_artifact_hash: naux_artifact.artifact_hash(),
            naux_elf_image_hash: naux_artifact.elf_image_hash(),
            naux_startup_code_hash: naux_artifact.startup_code_hash(),
            baseline_target_hash: verified_baseline.target_hash(),
            baseline_artifact_hash: verified_baseline.artifact_hash(),
            baseline_admission_results_hash: baseline_admission.results_hash(),
            warmup_pairs: X64_GATE_B_WARMUP_PAIRS,
            measured_pairs: X64_GATE_B_MEASURED_PAIRS,
            process_timeout_millis: X64_GATE_B_PROCESS_TIMEOUT_MILLIS,
            release_build: !cfg!(debug_assertions),
            affinity_logical_cpus,
            repository_state_recorded: false,
            repository_revision_hash: SemanticHash::ZERO,
            repository_dirty: true,
            samples,
            naux_statistics,
            baseline_statistics,
            performance_threshold_met,
            observation_hash: SemanticHash::ZERO,
        };
        observation.observation_hash = observation_hash(&observation)?;
        let _ = verify_x64_gate_b_measurement_observation(
            &observation,
            naux_artifact,
            baseline_admission,
        )?;
        Ok(observation)
    })();

    let first_cleanup =
        naux_executable
            .cleanup()
            .map_err(|source| X64GateBMeasurementError::Cleanup {
                engine: X64GateBEngine::Naux,
                source,
            });
    let second_cleanup =
        baseline_executable
            .cleanup()
            .map_err(|source| X64GateBMeasurementError::Cleanup {
                engine: X64GateBEngine::HandBaseline,
                source,
            });
    merge_two_cleanups(measurement, first_cleanup, second_cleanup)
}

pub fn verify_x64_gate_b_measurement_observation<'observation>(
    observation: &'observation X64GateBMeasurementObservation,
    naux_artifact: &VerifiedX64StandaloneArtifact<'_, '_, '_>,
    baseline_admission: VerifiedX64GateBBaselineAdmission<'_>,
) -> Result<VerifiedX64GateBMeasurement<'observation>, X64GateBMeasurementError> {
    validate_naux_artifact(naux_artifact)?;
    if observation.schema_version != X64_GATE_B_MEASUREMENT_SCHEMA_VERSION
        || observation.policy_version != X64_GATE_B_MEASUREMENT_POLICY_VERSION
        || observation.generator_version != X64_GATE_B_WORKLOAD_GENERATOR_VERSION
        || observation.generator_seed != X64_GATE_B_WORKLOAD_GENERATOR_SEED
        || observation.array_elements != X64_GATE_B_ARRAY_ELEMENTS
        || observation.repetitions != X64_GATE_B_REPETITIONS
        || observation.element_visits != X64_GATE_B_ELEMENT_VISITS
        || observation.warmup_pairs != X64_GATE_B_WARMUP_PAIRS
        || observation.measured_pairs != X64_GATE_B_MEASURED_PAIRS
        || observation.process_timeout_millis != X64_GATE_B_PROCESS_TIMEOUT_MILLIS
        || observation.release_build == cfg!(debug_assertions)
        || observation.affinity_logical_cpus == 0
    {
        return Err(X64GateBMeasurementError::InvalidObservation {
            field: "frozen policy or host shape",
        });
    }
    if observation.repository_state_recorded
        || observation.repository_revision_hash != SemanticHash::ZERO
        || !observation.repository_dirty
    {
        return Err(X64GateBMeasurementError::InvalidObservation {
            field: "local-only repository state",
        });
    }
    let workload = frozen_workload()?;
    if observation.input_values_hash != workload.input_values_hash
        || observation.input_frame_hash != workload.input_frame_hash
        || observation.expected_output != workload.expected_output
        || observation.expected_output_frame != workload.expected_output_frame
        || observation.expected_output_frame_hash != workload.expected_output_frame_hash
    {
        return Err(X64GateBMeasurementError::InvalidObservation {
            field: "workload identity",
        });
    }
    if observation.naux_artifact_hash != naux_artifact.artifact_hash()
        || observation.naux_elf_image_hash != naux_artifact.elf_image_hash()
        || observation.naux_startup_code_hash != naux_artifact.startup_code_hash()
    {
        return Err(X64GateBMeasurementError::InvalidObservation {
            field: "NAUX artifact identity",
        });
    }
    let baseline = build_x64_gate_b_baseline_artifact()?;
    let verified_baseline = verify_x64_gate_b_baseline_artifact(baseline.image_bytes())?;
    if observation.baseline_target_hash != verified_baseline.target_hash()
        || observation.baseline_artifact_hash != verified_baseline.artifact_hash()
        || observation.baseline_target_hash != baseline_admission.evidence().target_hash()
        || observation.baseline_artifact_hash != baseline_admission.evidence().artifact_hash()
        || observation.baseline_admission_results_hash != baseline_admission.results_hash()
    {
        return Err(X64GateBMeasurementError::InvalidObservation {
            field: "baseline identity",
        });
    }
    if observation.samples.len() != X64_GATE_B_MEASURED_PAIRS as usize {
        return Err(X64GateBMeasurementError::SampleCount {
            expected: X64_GATE_B_MEASURED_PAIRS,
            actual: observation.samples.len(),
        });
    }
    for (expected_index, sample) in observation.samples.iter().enumerate() {
        let expected_ordinal = u32::try_from(expected_index).map_err(|_| {
            X64GateBMeasurementError::ArithmeticOverflow {
                field: "pair ordinal",
            }
        })?;
        if sample.pair_ordinal != expected_ordinal {
            return Err(X64GateBMeasurementError::InvalidSchedule {
                expected_ordinal,
                actual_ordinal: sample.pair_ordinal,
            });
        }
        if sample.first != first_engine(expected_ordinal)
            || sample.naux_nanoseconds == 0
            || sample.baseline_nanoseconds == 0
            || sample.naux_output_frame_hash != workload.expected_output_frame_hash
            || sample.baseline_output_frame_hash != workload.expected_output_frame_hash
        {
            return Err(X64GateBMeasurementError::InvalidObservation {
                field: "sample schedule, duration, or output",
            });
        }
    }
    let naux_samples = observation
        .samples
        .iter()
        .map(X64GateBPairSample::naux_nanoseconds)
        .collect::<Vec<_>>();
    let baseline_samples = observation
        .samples
        .iter()
        .map(X64GateBPairSample::baseline_nanoseconds)
        .collect::<Vec<_>>();
    if observation.naux_statistics != compute_statistics(&naux_samples)? {
        return Err(X64GateBMeasurementError::StatisticsMismatch {
            engine: X64GateBEngine::Naux,
        });
    }
    if observation.baseline_statistics != compute_statistics(&baseline_samples)? {
        return Err(X64GateBMeasurementError::StatisticsMismatch {
            engine: X64GateBEngine::HandBaseline,
        });
    }
    if observation.performance_threshold_met
        != performance_threshold(observation.naux_statistics, observation.baseline_statistics)?
    {
        return Err(X64GateBMeasurementError::InvalidObservation {
            field: "performance threshold result",
        });
    }
    if observation.observation_hash != observation_hash(observation)? {
        return Err(X64GateBMeasurementError::ObservationHashMismatch);
    }
    Ok(VerifiedX64GateBMeasurement { observation })
}

pub fn admit_x64_gate_b_measurement_claim(
    verified: VerifiedX64GateBMeasurement<'_>,
) -> Result<AdmittedX64GateBClaim<'_>, X64GateBClaimRejection> {
    let observation = verified.observation;
    if !observation.release_build {
        return Err(X64GateBClaimRejection::DebugBuild);
    }
    if observation.affinity_logical_cpus != 1 {
        return Err(X64GateBClaimRejection::CpuNotPinned {
            logical_cpus: observation.affinity_logical_cpus,
        });
    }
    if !observation.repository_state_recorded
        || observation.repository_revision_hash == SemanticHash::ZERO
    {
        return Err(X64GateBClaimRejection::RepositoryStateMissing);
    }
    if observation.repository_dirty {
        return Err(X64GateBClaimRejection::DirtyRepository);
    }
    if !observation.naux_statistics.cv_within_limit {
        return Err(X64GateBClaimRejection::NauxCoefficientOfVariation);
    }
    if !observation.baseline_statistics.cv_within_limit {
        return Err(X64GateBClaimRejection::BaselineCoefficientOfVariation);
    }
    if !observation.performance_threshold_met {
        return Err(X64GateBClaimRejection::PerformanceThreshold);
    }
    Ok(AdmittedX64GateBClaim { verified })
}

pub(super) fn run_warmups(
    naux: &PreparedX64StandaloneExecutable,
    baseline: &PreparedX64StandaloneExecutable,
    workload: &FrozenWorkload,
) -> Result<(), X64GateBMeasurementError> {
    for pair_ordinal in 0..X64_GATE_B_WARMUP_PAIRS {
        for engine in engine_order(pair_ordinal) {
            let executable = match engine {
                X64GateBEngine::Naux => naux,
                X64GateBEngine::HandBaseline => baseline,
            };
            let _ = execute_sample(executable, engine, "warmup", pair_ordinal, workload)?;
        }
    }
    Ok(())
}

pub(super) fn run_measured_pairs(
    naux: &PreparedX64StandaloneExecutable,
    baseline: &PreparedX64StandaloneExecutable,
    workload: &FrozenWorkload,
) -> Result<Vec<X64GateBPairSample>, X64GateBMeasurementError> {
    let mut pairs = Vec::with_capacity(X64_GATE_B_MEASURED_PAIRS as usize);
    for pair_ordinal in 0..X64_GATE_B_MEASURED_PAIRS {
        let mut naux_result = None;
        let mut baseline_result = None;
        for engine in engine_order(pair_ordinal) {
            let executable = match engine {
                X64GateBEngine::Naux => naux,
                X64GateBEngine::HandBaseline => baseline,
            };
            let result = execute_sample(executable, engine, "measured", pair_ordinal, workload)?;
            match engine {
                X64GateBEngine::Naux => naux_result = Some(result),
                X64GateBEngine::HandBaseline => baseline_result = Some(result),
            }
        }
        let (naux_nanoseconds, naux_output_frame_hash) =
            naux_result.ok_or(X64GateBMeasurementError::InvalidObservation {
                field: "missing NAUX pair member",
            })?;
        let (baseline_nanoseconds, baseline_output_frame_hash) =
            baseline_result.ok_or(X64GateBMeasurementError::InvalidObservation {
                field: "missing baseline pair member",
            })?;
        pairs.push(X64GateBPairSample {
            pair_ordinal,
            first: first_engine(pair_ordinal),
            naux_nanoseconds,
            baseline_nanoseconds,
            naux_output_frame_hash,
            baseline_output_frame_hash,
        });
    }
    Ok(pairs)
}

fn execute_sample(
    executable: &PreparedX64StandaloneExecutable,
    engine: X64GateBEngine,
    phase: &'static str,
    pair_ordinal: u32,
    workload: &FrozenWorkload,
) -> Result<(u64, SemanticHash), X64GateBMeasurementError> {
    let process = run_admitted_x64_standalone_process(
        executable,
        pair_ordinal,
        workload.input_frame.clone(),
        X64StandaloneProfile::BranchMix,
        X64_GATE_B_PROCESS_TIMEOUT_MILLIS,
    )
    .map_err(|source| X64GateBMeasurementError::Process {
        engine,
        phase,
        pair_ordinal,
        source,
    })?;
    if process.output().outcome() != workload.expected_output
        || process.output_frame() != &workload.expected_output_frame
    {
        return Err(X64GateBMeasurementError::OutputMismatch {
            engine,
            phase,
            pair_ordinal,
        });
    }
    Ok((
        process.elapsed_nanoseconds(),
        frame_hash(OUTPUT_FRAME_DOMAIN, process.output_frame()),
    ))
}

fn first_engine(pair_ordinal: u32) -> X64GateBEngine {
    if pair_ordinal.is_multiple_of(2) {
        X64GateBEngine::Naux
    } else {
        X64GateBEngine::HandBaseline
    }
}

fn engine_order(pair_ordinal: u32) -> [X64GateBEngine; 2] {
    let first = first_engine(pair_ordinal);
    match first {
        X64GateBEngine::Naux => [X64GateBEngine::Naux, X64GateBEngine::HandBaseline],
        X64GateBEngine::HandBaseline => [X64GateBEngine::HandBaseline, X64GateBEngine::Naux],
    }
}

pub(super) fn compute_statistics(
    samples: &[u64],
) -> Result<X64GateBSampleStatistics, X64GateBMeasurementError> {
    if samples.len() != X64_GATE_B_MEASURED_PAIRS as usize {
        return Err(X64GateBMeasurementError::SampleCount {
            expected: X64_GATE_B_MEASURED_PAIRS,
            actual: samples.len(),
        });
    }
    for (index, sample) in samples.iter().enumerate() {
        if *sample == 0 {
            return Err(X64GateBMeasurementError::ZeroSample { index });
        }
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let median_twice_nanoseconds = u128::from(sorted[14])
        .checked_add(u128::from(sorted[15]))
        .ok_or(X64GateBMeasurementError::ArithmeticOverflow { field: "median" })?;
    let p95_nanoseconds = sorted[28];
    let sum_nanoseconds = samples.iter().try_fold(0_u128, |sum, sample| {
        sum.checked_add(u128::from(*sample))
            .ok_or(X64GateBMeasurementError::ArithmeticOverflow {
                field: "sample sum",
            })
    })?;
    let sample_count = u128::from(X64_GATE_B_MEASURED_PAIRS);
    let scaled_squared_deviation_sum = samples.iter().try_fold(0_u128, |sum, sample| {
        let scaled = sample_count.checked_mul(u128::from(*sample)).ok_or(
            X64GateBMeasurementError::ArithmeticOverflow {
                field: "scaled sample",
            },
        )?;
        let distance = scaled.abs_diff(sum_nanoseconds);
        let square =
            distance
                .checked_mul(distance)
                .ok_or(X64GateBMeasurementError::ArithmeticOverflow {
                    field: "squared deviation",
                })?;
        sum.checked_add(square)
            .ok_or(X64GateBMeasurementError::ArithmeticOverflow {
                field: "squared deviation sum",
            })
    })?;
    let cv_scale =
        u128::from((100 / X64_GATE_B_MAX_CV_PERCENT) * (100 / X64_GATE_B_MAX_CV_PERCENT));
    let cv_comparison_left = cv_scale.checked_mul(scaled_squared_deviation_sum).ok_or(
        X64GateBMeasurementError::ArithmeticOverflow {
            field: "CV left side",
        },
    )?;
    let cv_comparison_right = sample_count
        .checked_mul(sum_nanoseconds)
        .and_then(|value| value.checked_mul(sum_nanoseconds))
        .ok_or(X64GateBMeasurementError::ArithmeticOverflow {
            field: "CV right side",
        })?;
    Ok(X64GateBSampleStatistics {
        sample_count: X64_GATE_B_MEASURED_PAIRS,
        median_twice_nanoseconds,
        p95_nanoseconds,
        sum_nanoseconds,
        scaled_squared_deviation_sum,
        cv_comparison_left,
        cv_comparison_right,
        cv_within_limit: cv_comparison_left <= cv_comparison_right,
    })
}

pub(super) fn performance_threshold(
    naux: X64GateBSampleStatistics,
    baseline: X64GateBSampleStatistics,
) -> Result<bool, X64GateBMeasurementError> {
    let left = naux
        .median_twice_nanoseconds
        .checked_mul(u128::from(X64_GATE_B_MAX_SLOWDOWN_DENOMINATOR))
        .ok_or(X64GateBMeasurementError::ArithmeticOverflow {
            field: "performance ratio left side",
        })?;
    let right = baseline
        .median_twice_nanoseconds
        .checked_mul(u128::from(X64_GATE_B_MAX_SLOWDOWN_NUMERATOR))
        .ok_or(X64GateBMeasurementError::ArithmeticOverflow {
            field: "performance ratio right side",
        })?;
    Ok(left <= right)
}

pub(super) fn frozen_workload() -> Result<FrozenWorkload, X64GateBMeasurementError> {
    let element_capacity = usize::try_from(X64_GATE_B_ARRAY_ELEMENTS).map_err(|_| {
        X64GateBMeasurementError::ArithmeticOverflow {
            field: "workload element count",
        }
    })?;
    let mut state = X64_GATE_B_WORKLOAD_GENERATOR_SEED;
    let mut values = Vec::with_capacity(element_capacity);
    for _ in 0..X64_GATE_B_ARRAY_ELEMENTS {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let magnitude = ((state >> 20) & 0x0fff) as i64;
        let signed = magnitude - 2_048;
        values.push(((signed as f64) / 256.0).to_bits());
    }
    let expected_bits = strict_branch_mix_reference(&values, X64_GATE_B_REPETITIONS)?;
    let expected_output =
        X64StandaloneOutput::return_f64(X64StandaloneProfile::BranchMix, expected_bits);
    let expected_output_frame =
        encode_x64_standalone_output(expected_output).map_err(protocol_error)?;
    let input = X64StandaloneInput::new(
        X64StandaloneProfile::BranchMix,
        values.clone(),
        X64_GATE_B_REPETITIONS,
    )
    .map_err(protocol_error)?;
    let input_frame = encode_x64_standalone_input(&input).map_err(protocol_error)?;
    Ok(FrozenWorkload {
        input_values_hash: values_hash(&values),
        input_frame_hash: frame_hash(INPUT_FRAME_DOMAIN, &input_frame),
        input_frame,
        expected_output: expected_output.outcome(),
        expected_output_frame,
        expected_output_frame_hash: frame_hash(OUTPUT_FRAME_DOMAIN, &expected_output_frame),
        values,
    })
}

#[inline(never)]
fn strict_branch_mix_reference(
    values: &[u64],
    repetitions: i64,
) -> Result<u64, X64GateBMeasurementError> {
    #[cfg(target_arch = "x86_64")]
    let original_mxcsr = read_mxcsr();
    #[cfg(target_arch = "x86_64")]
    write_mxcsr(CANONICAL_MXCSR);

    let mut state = 0_i64;
    let mut sum = 0.0_f64;
    let mut repetition = 0_i64;
    while repetition < repetitions {
        for bits in values {
            state = state.wrapping_add(17);
            if state >= 97 {
                state = state.wrapping_sub(97);
            }
            let value = f64::from_bits(*bits);
            if state < 48 {
                sum += value;
            } else {
                sum -= value;
            }
        }
        repetition = repetition.wrapping_add(1);
    }
    let result = if sum.is_nan() {
        super::x64_standalone_protocol::X64_STANDALONE_CANONICAL_NAN_BITS
    } else {
        sum.to_bits()
    };

    #[cfg(target_arch = "x86_64")]
    write_mxcsr(original_mxcsr);
    Ok(result)
}

#[cfg(target_arch = "x86_64")]
fn read_mxcsr() -> u32 {
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

#[cfg(target_arch = "x86_64")]
fn write_mxcsr(value: u32) {
    // SAFETY: callers use either the canonical value or a value returned by
    // `stmxcsr`; the pointer references readable u32 storage.
    unsafe {
        std::arch::asm!(
            "ldmxcsr [{pointer}]",
            pointer = in(reg) &value,
            options(nostack, preserves_flags),
        );
    }
}

fn validate_naux_artifact(
    artifact: &VerifiedX64StandaloneArtifact<'_, '_, '_>,
) -> Result<(), X64GateBMeasurementError> {
    if artifact.profile() != X64StandaloneProfile::BranchMix {
        return Err(X64GateBMeasurementError::InvalidNauxArtifact { field: "profile" });
    }
    if artifact.interpreter_dependency()
        || artifact.external_symbol_dependency()
        || artifact.dynamic_loader_dependency()
        || artifact.system_linker_dependency()
        || artifact.fallback()
    {
        return Err(X64GateBMeasurementError::InvalidNauxArtifact {
            field: "dependency/fallback vector",
        });
    }
    Ok(())
}

fn observation_hash(
    observation: &X64GateBMeasurementObservation,
) -> Result<SemanticHash, X64GateBMeasurementError> {
    let sample_count = u32::try_from(observation.samples.len()).map_err(|_| {
        X64GateBMeasurementError::ArithmeticOverflow {
            field: "observation sample count",
        }
    })?;
    let mut bytes =
        Vec::with_capacity(OBSERVATION_DOMAIN.len() + 640 + observation.samples.len() * 88);
    bytes.extend_from_slice(OBSERVATION_DOMAIN);
    put_version(&mut bytes, observation.schema_version);
    put_version(&mut bytes, observation.policy_version);
    put_version(&mut bytes, observation.generator_version);
    put_u64(&mut bytes, observation.generator_seed);
    put_u32(&mut bytes, observation.array_elements);
    put_i64(&mut bytes, observation.repetitions);
    put_u64(&mut bytes, observation.element_visits);
    put_hash(&mut bytes, observation.input_values_hash);
    put_hash(&mut bytes, observation.input_frame_hash);
    put_outcome(&mut bytes, observation.expected_output);
    bytes.extend_from_slice(&observation.expected_output_frame);
    put_hash(&mut bytes, observation.expected_output_frame_hash);
    for hash in [
        observation.naux_artifact_hash,
        observation.naux_elf_image_hash,
        observation.naux_startup_code_hash,
        observation.baseline_target_hash,
        observation.baseline_artifact_hash,
        observation.baseline_admission_results_hash,
    ] {
        put_hash(&mut bytes, hash);
    }
    put_u32(&mut bytes, observation.warmup_pairs);
    put_u32(&mut bytes, observation.measured_pairs);
    put_u32(&mut bytes, observation.process_timeout_millis);
    put_bool(&mut bytes, observation.release_build);
    put_u32(&mut bytes, observation.affinity_logical_cpus);
    put_bool(&mut bytes, observation.repository_state_recorded);
    put_hash(&mut bytes, observation.repository_revision_hash);
    put_bool(&mut bytes, observation.repository_dirty);
    put_u32(&mut bytes, sample_count);
    for sample in &observation.samples {
        put_u32(&mut bytes, sample.pair_ordinal);
        bytes.push(engine_tag(sample.first));
        put_u64(&mut bytes, sample.naux_nanoseconds);
        put_u64(&mut bytes, sample.baseline_nanoseconds);
        put_hash(&mut bytes, sample.naux_output_frame_hash);
        put_hash(&mut bytes, sample.baseline_output_frame_hash);
    }
    put_statistics(&mut bytes, observation.naux_statistics);
    put_statistics(&mut bytes, observation.baseline_statistics);
    put_bool(&mut bytes, observation.performance_threshold_met);
    Ok(SemanticHash(sha256(&bytes)))
}

pub(super) fn put_statistics(bytes: &mut Vec<u8>, statistics: X64GateBSampleStatistics) {
    put_u32(bytes, statistics.sample_count);
    put_u128(bytes, statistics.median_twice_nanoseconds);
    put_u64(bytes, statistics.p95_nanoseconds);
    put_u128(bytes, statistics.sum_nanoseconds);
    put_u128(bytes, statistics.scaled_squared_deviation_sum);
    put_u128(bytes, statistics.cv_comparison_left);
    put_u128(bytes, statistics.cv_comparison_right);
    put_bool(bytes, statistics.cv_within_limit);
}

fn values_hash(values: &[u64]) -> SemanticHash {
    let mut bytes = Vec::with_capacity(INPUT_VALUES_DOMAIN.len() + 8 + values.len() * 8);
    bytes.extend_from_slice(INPUT_VALUES_DOMAIN);
    put_u64(&mut bytes, values.len() as u64);
    for bits in values {
        put_u64(&mut bytes, *bits);
    }
    SemanticHash(sha256(&bytes))
}

fn frame_hash(domain: &[u8], frame: &[u8]) -> SemanticHash {
    let mut bytes = Vec::with_capacity(domain.len() + 8 + frame.len());
    bytes.extend_from_slice(domain);
    put_u64(&mut bytes, frame.len() as u64);
    bytes.extend_from_slice(frame);
    SemanticHash(sha256(&bytes))
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

fn put_u128(bytes: &mut Vec<u8>, value: u128) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_hash(bytes: &mut Vec<u8>, value: SemanticHash) {
    bytes.extend_from_slice(&value.0);
}

fn protocol_error(error: X64StandaloneProtocolError) -> X64GateBMeasurementError {
    X64GateBMeasurementError::Protocol {
        message: error.to_string(),
    }
}

fn merge_one_cleanup<T>(
    primary: Result<T, X64GateBMeasurementError>,
    cleanup: Result<(), X64GateBMeasurementError>,
) -> Result<T, X64GateBMeasurementError> {
    match (primary, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(X64GateBMeasurementError::FailureDuringCleanup {
            primary: Box::new(primary),
            cleanup: Box::new(cleanup),
        }),
    }
}

fn merge_two_cleanups<T>(
    primary: Result<T, X64GateBMeasurementError>,
    first: Result<(), X64GateBMeasurementError>,
    second: Result<(), X64GateBMeasurementError>,
) -> Result<T, X64GateBMeasurementError> {
    merge_one_cleanup(merge_one_cleanup(primary, first), second)
}

pub(super) fn require_host() -> Result<(), X64GateBMeasurementError> {
    if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        Ok(())
    } else {
        Err(X64GateBMeasurementError::UnsupportedHost)
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub(super) fn affinity_logical_cpu_count() -> Result<u32, X64GateBMeasurementError> {
    const SCHED_GETAFFINITY_SYSCALL: i64 = 204;
    let mut mask = [0_u8; 128];
    let mut result = SCHED_GETAFFINITY_SYSCALL;
    // SAFETY: Linux x86-64 syscall 204 receives the current-process selector,
    // the exact writable mask size, and a valid mask pointer.
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") result,
            in("rdi") 0_i64,
            in("rsi") mask.len(),
            in("rdx") mask.as_mut_ptr(),
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if result < 0 {
        return Err(X64GateBMeasurementError::Affinity {
            message: format!("sched_getaffinity returned errno {}", -result),
        });
    }
    let returned = usize::try_from(result).map_err(|_| X64GateBMeasurementError::Affinity {
        message: "sched_getaffinity returned an invalid width".to_owned(),
    })?;
    if returned == 0 || returned > mask.len() {
        return Err(X64GateBMeasurementError::Affinity {
            message: format!("sched_getaffinity returned {returned} mask bytes"),
        });
    }
    mask[..returned].iter().try_fold(0_u32, |count, byte| {
        count
            .checked_add(byte.count_ones())
            .ok_or(X64GateBMeasurementError::ArithmeticOverflow {
                field: "affinity CPU count",
            })
    })
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
pub(super) fn affinity_logical_cpu_count() -> Result<u32, X64GateBMeasurementError> {
    Err(X64GateBMeasurementError::UnsupportedHost)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_workload_has_exact_shape_and_deterministic_identity() {
        let first = frozen_workload().expect("frozen workload");
        let second = frozen_workload().expect("repeated frozen workload");
        assert_eq!(first.input_frame.len(), 40 + 65_536 * 8);
        assert_eq!(first.input_values_hash, second.input_values_hash);
        assert_eq!(first.input_frame_hash, second.input_frame_hash);
        assert_eq!(first.expected_output, second.expected_output);
        assert_eq!(
            first.expected_output_frame_hash,
            second.expected_output_frame_hash
        );
    }

    #[test]
    fn exact_statistics_reject_noise_and_preserve_half_nanosecond_median() {
        let stable = (1_u64..=30).collect::<Vec<_>>();
        let statistics = compute_statistics(&stable).expect("exact statistics");
        assert_eq!(statistics.median_twice_nanoseconds(), 31);
        assert_eq!(statistics.median_floor_nanoseconds(), 15);
        assert_eq!(statistics.p95_nanoseconds(), 29);
        assert!(!statistics.cv_within_limit());

        let low_noise = vec![1_000_000_u64; 30];
        assert!(compute_statistics(&low_noise)
            .expect("constant samples")
            .cv_within_limit());
        let mut zero = low_noise;
        zero[17] = 0;
        assert!(matches!(
            compute_statistics(&zero),
            Err(X64GateBMeasurementError::ZeroSample { index: 17 })
        ));
    }

    #[test]
    fn threshold_uses_exact_median_numerators() {
        let baseline = compute_statistics(&vec![100_u64; 30]).expect("baseline statistics");
        let equal_limit = compute_statistics(&vec![200_u64; 30]).expect("limit statistics");
        let over_limit = compute_statistics(&vec![201_u64; 30]).expect("over-limit statistics");
        assert!(performance_threshold(equal_limit, baseline).expect("exact ratio"));
        assert!(!performance_threshold(over_limit, baseline).expect("exact ratio"));
    }
}
