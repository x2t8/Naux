//! R1-S5 Gate A finite behavioral validation for the frozen CoreVM0
//! `branch_mix` lighthouse.
//!
//! This gate is deliberately a finite, deterministic validation corpus.  It
//! is not a theorem over every possible input.  Admission first replays the
//! existing R1-S4 artifact evidence and then regenerates every case and every
//! three-engine observation from raw inputs.  Broader seed-only oracle/fuzz
//! suites remain separate evidence and are not claimed by this three-engine
//! gate.

use super::corevm0::{
    branch_mix_kernel_program, corevm0_program_bytes, evaluate_corevm0, verify_corevm0_program,
    CoreVmEvaluation, CoreVmInstruction, CoreVmOutcome, CoreVmProgram, CoreVmType,
    CoreVmTypedError, CoreVmValue, VerifiedCoreVmProgram, COREVM0_SCHEMA_VERSION,
};
use super::corevm0_definitional::{
    build_definitional_corevm0, evaluate_definitional_corevm0, DefinitionalCoreVmArtifact,
    DefinitionalCoreVmEvaluation,
};
use super::corevm0_r1_s4::{
    corevm0_r1_s4_evidence_hash, emit_corevm0_r1_s4_evidence, specialize_corevm0_r1_s4,
    verify_corevm0_r1_s4_evidence, CoreVmR1S4Evidence, CoreVmR1S4ReplayError,
    CoreVmR1S4Specialization,
};
use super::encoding::sha256;
use super::interpret::{
    evaluate, CoreValue, EffectEvent, Evaluation, EvaluationBudget, EvaluationOutcome,
};
use super::polyvariant_r1_s4::PolyvariantR1S4Budget;
use super::schema::{CoreArtifact, ErrorKind, Mutability, RegionId, SemanticHash, Type};
use super::specialization::{
    validate_specialization_r0a_request, SpecializationBudget, SpecializationRequest,
    SpecializationSlot,
};
use super::staging::{
    certify_binding_time_b0d, validate_binding_time_b0_request, BindingTime, BindingTimeBudget,
    BindingTimeCertificate, BindingTimeRequest,
};
use std::fmt;

pub const COREVM0_GATE_A_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const COREVM0_GATE_A_REPLAY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const COREVM0_GATE_A_CORPUS_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const COREVM0_GATE_A_GENERATOR_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const COREVM0_GATE_A_NUMERIC_CONTRACT_VERSION: (u16, u16, u16) = (1, 0, 0);

pub const COREVM0_GATE_A_EDGE_CASES: u32 = 10;
pub const COREVM0_GATE_A_EXHAUSTIVE_CASES: u32 = 20;
pub const COREVM0_GATE_A_GENERATED_CASES: u32 = 16;
pub const COREVM0_GATE_A_BOUNDS_CASES: u32 = 5;
pub const COREVM0_GATE_A_TOTAL_CASES: u32 = 51;
pub const COREVM0_GATE_A_MAX_CASES: u32 = 64;
pub const COREVM0_GATE_A_MAX_ARRAY_ELEMENTS_PER_CASE: u32 = 31;
pub const COREVM0_GATE_A_MAX_TOTAL_ARRAY_ELEMENTS: u64 = 4_096;
pub const COREVM0_GATE_A_MAX_EFFECTS_PER_ENGINE: u32 = 1;

pub const COREVM0_GATE_A_SEED_STEP_LIMIT: u64 = 1_000_000;
pub const COREVM0_GATE_A_CORE_STEP_LIMIT: u64 = 10_000_000;
pub const COREVM0_GATE_A_RESIDUAL_STEP_LIMIT: u64 = 10_000_000;
pub const COREVM0_GATE_A_CALL_DEPTH_LIMIT: u32 = 256;
pub const COREVM0_GATE_A_MAX_TOTAL_SEED_STEPS: u64 = 100_000_000;
pub const COREVM0_GATE_A_MAX_TOTAL_CORE_STEPS: u64 = 1_000_000_000;
pub const COREVM0_GATE_A_MAX_TOTAL_RESIDUAL_STEPS: u64 = 1_000_000_000;
pub const COREVM0_GATE_A_GENERATOR_SEED: u64 = 0x8a5c_d789_635d_2dff;

const INPUT_DOMAIN: &[u8] = b"NAUX:corevm0:r1-s5:gate-a:input:v1\0";
const CORPUS_DOMAIN: &[u8] = b"NAUX:corevm0:r1-s5:gate-a:corpus:v1\0";
const RECORD_DOMAIN: &[u8] = b"NAUX:corevm0:r1-s5:gate-a:record:v1\0";
const RESULTS_DOMAIN: &[u8] = b"NAUX:corevm0:r1-s5:gate-a:results:v1\0";
const TELEMETRY_DOMAIN: &[u8] = b"NAUX:corevm0:r1-s5:gate-a:telemetry:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:corevm0:r1-s5:gate-a:evidence:v1\0";
const NUMERIC_DOMAIN: &[u8] = b"NAUX:corevm0:r1-s5:gate-a:numeric-contract:v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreVmGateAAssurance {
    /// Reproducible evidence over the exact bounded corpus, not a proof over
    /// the unbounded input domain.
    FiniteBoundedValidation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreVmGateAWorkload {
    BranchMix,
    BoundsOrderedArrayGet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreVmGateACaseClass {
    Edge,
    BoundedExhaustive,
    DeterministicGenerated,
    BoundsEffect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreVmGateAInput {
    /// Exact IEEE-754 input bits.  Inputs are not NaN-normalized.
    pub array_f64_bits: Vec<u64>,
    /// Canonically zero for the Bounds workload.
    pub repetitions: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreVmGateACase {
    pub workload: CoreVmGateAWorkload,
    pub class: CoreVmGateACaseClass,
    pub ordinal: u32,
    pub input: CoreVmGateAInput,
    pub input_hash: SemanticHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreVmGateACorpusManifest {
    pub corpus_version: (u16, u16, u16),
    pub generator_version: (u16, u16, u16),
    pub generator_seed: u64,
    pub edge_cases: u32,
    pub exhaustive_cases: u32,
    pub generated_cases: u32,
    pub bounds_cases: u32,
    pub total_cases: u32,
    pub total_array_elements: u64,
    pub cases: Vec<CoreVmGateACase>,
    pub manifest_hash: SemanticHash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreVmGateAF64 {
    /// Every non-NaN result is compared by exact IEEE-754 bits, including
    /// signed zero.
    ExactBits(u64),
    /// NAUX P1V0 does not expose NaN payload identity.
    CanonicalNaN,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreVmGateAOutcome {
    ReturnF64(CoreVmGateAF64),
    Bounds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreVmGateAEffect {
    Bounds,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreVmGateAObservation {
    pub outcome: CoreVmGateAOutcome,
    pub effect_trace: Vec<CoreVmGateAEffect>,
    /// Deterministic engine-local work usage.  Work counts are evidence, but
    /// are not compared across engines as semantic results.
    pub steps: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreVmGateAThreeWayRecord {
    pub case_ordinal: u32,
    pub input_hash: SemanticHash,
    pub seed: CoreVmGateAObservation,
    pub definitional_core: CoreVmGateAObservation,
    pub residual_core: CoreVmGateAObservation,
    pub record_hash: SemanticHash,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoreVmGateAUsage {
    pub seed_steps: u64,
    pub definitional_core_steps: u64,
    pub residual_core_steps: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreVmGateAExecutionBudget {
    pub max_cases: u32,
    pub max_array_elements_per_case: u32,
    pub max_total_array_elements: u64,
    pub seed_steps_per_case: u64,
    pub definitional_core_steps_per_case: u64,
    pub residual_core_steps_per_case: u64,
    pub core_call_depth_per_case: u32,
    pub max_total_seed_steps: u64,
    pub max_total_definitional_core_steps: u64,
    pub max_total_residual_core_steps: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreVmGateAEvidence {
    pub schema_version: (u16, u16, u16),
    pub replay_version: (u16, u16, u16),
    pub assurance: CoreVmGateAAssurance,
    pub numeric_contract_version: (u16, u16, u16),
    pub numeric_contract_hash: SemanticHash,

    // A1: exact linkage to the already sealed R1-S4 source/residual package.
    pub s4_evidence_hash: SemanticHash,
    pub source_program_hash: SemanticHash,
    pub source_program_image_hash: SemanticHash,
    pub definitional_artifact_hash: SemanticHash,
    pub core_interpreter_semantics_hash: SemanticHash,
    pub residual_hash: SemanticHash,
    pub s4_binding_hash: SemanticHash,
    pub s4_erasure_hash: SemanticHash,

    // The Bounds package is a separate internally regenerated S4 projection.
    pub bounds_program_hash: SemanticHash,
    pub bounds_definitional_artifact_hash: SemanticHash,
    pub bounds_residual_hash: SemanticHash,
    pub bounds_s4_evidence_hash: SemanticHash,

    // A2: one sealed corpus and exact three-engine observations.
    pub corpus: CoreVmGateACorpusManifest,
    pub records: Vec<CoreVmGateAThreeWayRecord>,
    pub results_hash: SemanticHash,
    pub execution_budget: CoreVmGateAExecutionBudget,
    pub usage: CoreVmGateAUsage,
    pub telemetry_hash: SemanticHash,
    pub evidence_hash: SemanticHash,
}

#[derive(Clone, Debug)]
pub struct VerifiedCoreVmGateA {
    specialization: CoreVmR1S4Specialization,
    evidence: CoreVmGateAEvidence,
}

impl VerifiedCoreVmGateA {
    pub fn specialization(&self) -> &CoreVmR1S4Specialization {
        &self.specialization
    }

    pub fn residual(&self) -> &CoreArtifact {
        self.specialization.artifact()
    }

    pub fn evidence(&self) -> &CoreVmGateAEvidence {
        &self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreVmGateAError {
    NotFrozenLighthouse,
    S4IdentityMismatch,
    CorpusInvariant(&'static str),
    Pipeline {
        stage: &'static str,
        message: String,
    },
    UnsupportedOutcome {
        engine: &'static str,
        case_ordinal: u32,
    },
    ThreeWayMismatch {
        case_ordinal: u32,
    },
    MetricOverflow,
    ExecutionCapExceeded {
        engine: &'static str,
        limit: u64,
        actual: u64,
    },
}

impl fmt::Display for CoreVmGateAError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFrozenLighthouse => {
                formatter.write_str("Gate A admits only the frozen branch_mix lighthouse")
            }
            Self::S4IdentityMismatch => {
                formatter.write_str("Gate A inputs do not preserve the exact R1-S4 identities")
            }
            Self::CorpusInvariant(message) => {
                write!(formatter, "Gate A corpus invariant: {message}")
            }
            Self::Pipeline { stage, message } => write!(formatter, "{stage} failed: {message}"),
            Self::UnsupportedOutcome {
                engine,
                case_ordinal,
            } => write!(
                formatter,
                "{engine} produced an unsupported outcome in Gate A case {case_ordinal}"
            ),
            Self::ThreeWayMismatch { case_ordinal } => write!(
                formatter,
                "seed, definitional Core, and residual Core differ in Gate A case {case_ordinal}"
            ),
            Self::MetricOverflow => formatter.write_str("Gate A checked metric overflow"),
            Self::ExecutionCapExceeded {
                engine,
                limit,
                actual,
            } => write!(
                formatter,
                "{engine} Gate A usage {actual} exceeds fixed cap {limit}"
            ),
        }
    }
}

impl std::error::Error for CoreVmGateAError {}

#[derive(Debug)]
pub enum CoreVmGateAReplayError {
    InvalidClaimShape(CoreVmGateAError),
    InvalidEvidenceHash,
    InvalidNestedEvidence,
    S4(CoreVmR1S4ReplayError),
    Regeneration(CoreVmGateAError),
    EvidenceMismatch,
}

impl fmt::Display for CoreVmGateAReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidClaimShape(error) => {
                write!(formatter, "R1-S5 Gate A claim shape is invalid: {error}")
            }
            Self::InvalidEvidenceHash => {
                formatter.write_str("R1-S5 Gate A evidence hash is not canonical")
            }
            Self::InvalidNestedEvidence => {
                formatter.write_str("R1-S5 Gate A nested evidence seal is invalid")
            }
            Self::S4(error) => write!(formatter, "R1-S5 Gate A S4 replay failed: {error}"),
            Self::Regeneration(error) => {
                write!(formatter, "R1-S5 Gate A regeneration failed: {error}")
            }
            Self::EvidenceMismatch => {
                formatter.write_str("R1-S5 Gate A regenerated different finite evidence")
            }
        }
    }
}

impl std::error::Error for CoreVmGateAReplayError {}

/// Return the sole, internally generated R1-S5 corpus.  Callers cannot supply
/// a seed, case list, execution budget, or corpus limit.
pub fn corevm0_gate_a_manifest() -> Result<CoreVmGateACorpusManifest, CoreVmGateAError> {
    let mut cases = Vec::new();

    let edge_inputs = vec![
        (vec![], 0),
        (vec![], 7),
        (vec![1.0], 0),
        (vec![1.0], -3),
        (vec![1.0], 1),
        (vec![1.0, -2.0, 3.5, f64::MAX, -f64::MAX], 2),
        (
            vec![
                0.0,
                -0.0,
                f64::MIN_POSITIVE,
                -f64::MIN_POSITIVE,
                f64::from_bits(1),
                f64::from_bits((1_u64 << 63) | 1),
            ],
            2,
        ),
        (vec![f64::INFINITY, 1.0, f64::NEG_INFINITY], 2),
        (
            vec![
                f64::from_bits(0x7ff8_0000_0000_0001),
                f64::from_bits(0xfff8_0000_0000_0002),
                1.0,
            ],
            1,
        ),
        ((0..31).map(|index| index as f64 * 0.25 - 2.0).collect(), 1),
    ];
    for (values, repetitions) in edge_inputs {
        push_case(
            &mut cases,
            CoreVmGateAWorkload::BranchMix,
            CoreVmGateACaseClass::Edge,
            values,
            repetitions,
        )?;
    }

    let alphabet = [-1.0_f64, -0.0, 0.0, 1.0];
    let mut vectors = vec![vec![]];
    for length in 1_u32..=1 {
        let count = alphabet.len().pow(length);
        for encoded in 0..count {
            let mut cursor = encoded;
            let mut values = Vec::with_capacity(length as usize);
            for _ in 0..length {
                values.push(alphabet[cursor % alphabet.len()]);
                cursor /= alphabet.len();
            }
            vectors.push(values);
        }
    }
    for values in vectors {
        for repetitions in -1_i64..=2 {
            push_case(
                &mut cases,
                CoreVmGateAWorkload::BranchMix,
                CoreVmGateACaseClass::BoundedExhaustive,
                values.clone(),
                repetitions,
            )?;
        }
    }

    let mut state = COREVM0_GATE_A_GENERATOR_SEED;
    for _ in 0..COREVM0_GATE_A_GENERATED_CASES {
        state = lcg(state);
        let length = (state as usize) % 4;
        let repetitions = ((state >> 8) % 4) as i64 - 1;
        let mut values = Vec::with_capacity(length);
        for _ in 0..length {
            state = lcg(state);
            let signed = (state >> 11) as i64;
            values.push((signed % 20_001) as f64 / 64.0);
        }
        push_case(
            &mut cases,
            CoreVmGateAWorkload::BranchMix,
            CoreVmGateACaseClass::DeterministicGenerated,
            values,
            repetitions,
        )?;
    }

    for values in [
        vec![],
        vec![3.25],
        vec![3.25, -0.0],
        vec![3.25, f64::NAN],
        vec![f64::INFINITY, f64::NEG_INFINITY],
    ] {
        push_case(
            &mut cases,
            CoreVmGateAWorkload::BoundsOrderedArrayGet,
            CoreVmGateACaseClass::BoundsEffect,
            values,
            0,
        )?;
    }

    let total_cases = u32::try_from(cases.len()).map_err(|_| CoreVmGateAError::MetricOverflow)?;
    if total_cases != COREVM0_GATE_A_TOTAL_CASES || total_cases > COREVM0_GATE_A_MAX_CASES {
        return Err(CoreVmGateAError::CorpusInvariant(
            "generated case count differs from the locked count",
        ));
    }
    let total_array_elements = cases.iter().try_fold(0_u64, |total, case| {
        let length = u64::try_from(case.input.array_f64_bits.len())
            .map_err(|_| CoreVmGateAError::MetricOverflow)?;
        total
            .checked_add(length)
            .ok_or(CoreVmGateAError::MetricOverflow)
    })?;
    if total_array_elements > COREVM0_GATE_A_MAX_TOTAL_ARRAY_ELEMENTS {
        return Err(CoreVmGateAError::CorpusInvariant(
            "total input elements exceed the hard cap",
        ));
    }

    let mut manifest = CoreVmGateACorpusManifest {
        corpus_version: COREVM0_GATE_A_CORPUS_VERSION,
        generator_version: COREVM0_GATE_A_GENERATOR_VERSION,
        generator_seed: COREVM0_GATE_A_GENERATOR_SEED,
        edge_cases: COREVM0_GATE_A_EDGE_CASES,
        exhaustive_cases: COREVM0_GATE_A_EXHAUSTIVE_CASES,
        generated_cases: COREVM0_GATE_A_GENERATED_CASES,
        bounds_cases: COREVM0_GATE_A_BOUNDS_CASES,
        total_cases,
        total_array_elements,
        cases,
        manifest_hash: SemanticHash::ZERO,
    };
    manifest.manifest_hash = corevm0_gate_a_manifest_hash(&manifest)?;
    Ok(manifest)
}

pub const fn corevm0_gate_a_execution_budget() -> CoreVmGateAExecutionBudget {
    CoreVmGateAExecutionBudget {
        max_cases: COREVM0_GATE_A_MAX_CASES,
        max_array_elements_per_case: COREVM0_GATE_A_MAX_ARRAY_ELEMENTS_PER_CASE,
        max_total_array_elements: COREVM0_GATE_A_MAX_TOTAL_ARRAY_ELEMENTS,
        seed_steps_per_case: COREVM0_GATE_A_SEED_STEP_LIMIT,
        definitional_core_steps_per_case: COREVM0_GATE_A_CORE_STEP_LIMIT,
        residual_core_steps_per_case: COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
        core_call_depth_per_case: COREVM0_GATE_A_CALL_DEPTH_LIMIT,
        max_total_seed_steps: COREVM0_GATE_A_MAX_TOTAL_SEED_STEPS,
        max_total_definitional_core_steps: COREVM0_GATE_A_MAX_TOTAL_CORE_STEPS,
        max_total_residual_core_steps: COREVM0_GATE_A_MAX_TOTAL_RESIDUAL_STEPS,
    }
}

pub fn corevm0_gate_a_numeric_contract_hash() -> SemanticHash {
    let mut bytes = NUMERIC_DOMAIN.to_vec();
    put_version(&mut bytes, COREVM0_GATE_A_NUMERIC_CONTRACT_VERSION);
    // I64 is wrapping; F64 is strict left-to-right binary64; non-NaNs are
    // bit-observable; NaN payloads are not; signed zero is observable; Bounds
    // is typed and the ordered sequence of observable effect kinds is exact.
    bytes.extend_from_slice(
        b"i64=wrapping;f64=binary64-left-to-right-no-reassociation-no-contraction;\
non-nan=exact-bits;nan=payload-unobservable;signed-zero=observable;\
bounds=typed;effect-trace=exact-order",
    );
    SemanticHash(sha256(&bytes))
}

pub fn corevm0_gate_a_manifest_hash(
    manifest: &CoreVmGateACorpusManifest,
) -> Result<SemanticHash, CoreVmGateAError> {
    preflight_manifest_shape(manifest)?;
    let mut bytes = CORPUS_DOMAIN.to_vec();
    encode_manifest(&mut bytes, manifest, false)?;
    Ok(SemanticHash(sha256(&bytes)))
}

/// Recompute the canonical raw-input identity of one bounded corpus case.
///
/// This is public because independent verifiers and adversarial tests must be
/// able to model an attacker who recomputes every exposed nested seal.
pub fn corevm0_gate_a_case_input_hash(
    case: &CoreVmGateACase,
) -> Result<SemanticHash, CoreVmGateAError> {
    preflight_case_shape(case)?;
    input_hash(case.workload, case.class, case.ordinal, &case.input)
}

pub fn corevm0_gate_a_record_hash(
    record: &CoreVmGateAThreeWayRecord,
) -> Result<SemanticHash, CoreVmGateAError> {
    preflight_record_shape(record)?;
    let mut bytes = RECORD_DOMAIN.to_vec();
    encode_record(&mut bytes, record, false, false)?;
    Ok(SemanticHash(sha256(&bytes)))
}

pub fn corevm0_gate_a_telemetry_hash(
    records: &[CoreVmGateAThreeWayRecord],
    execution_budget: CoreVmGateAExecutionBudget,
    usage: CoreVmGateAUsage,
) -> Result<SemanticHash, CoreVmGateAError> {
    preflight_records_shape(records)?;
    let mut bytes = TELEMETRY_DOMAIN.to_vec();
    encode_execution_budget(&mut bytes, execution_budget);
    put_len(&mut bytes, records.len())?;
    for record in records {
        put_u32(&mut bytes, record.case_ordinal);
        bytes.extend_from_slice(&record.input_hash.0);
        put_u64(&mut bytes, record.seed.steps);
        put_u64(&mut bytes, record.definitional_core.steps);
        put_u64(&mut bytes, record.residual_core.steps);
    }
    encode_usage(&mut bytes, usage);
    Ok(SemanticHash(sha256(&bytes)))
}

pub fn corevm0_gate_a_evidence_hash(
    evidence: &CoreVmGateAEvidence,
) -> Result<SemanticHash, CoreVmGateAError> {
    preflight_evidence_shape(evidence)?;
    let mut bytes = EVIDENCE_DOMAIN.to_vec();
    encode_evidence(&mut bytes, evidence, false)?;
    Ok(SemanticHash(sha256(&bytes)))
}

pub fn corevm0_gate_a_results_hash(
    records: &[CoreVmGateAThreeWayRecord],
) -> Result<SemanticHash, CoreVmGateAError> {
    preflight_records_shape(records)?;
    let mut bytes = RESULTS_DOMAIN.to_vec();
    put_len(&mut bytes, records.len())?;
    for record in records {
        bytes.extend_from_slice(&record.record_hash.0);
    }
    Ok(SemanticHash(sha256(&bytes)))
}

pub fn emit_corevm0_gate_a_r1_s5(
    program: &CoreVmProgram,
    specialization: &CoreVmR1S4Specialization,
    s4_evidence: &CoreVmR1S4Evidence,
) -> Result<CoreVmGateAEvidence, CoreVmGateAError> {
    let frozen = branch_mix_kernel_program();
    let actual_bytes = corevm0_program_bytes(program)
        .map_err(|error| pipeline("lighthouse program encoding", error))?;
    let frozen_bytes = corevm0_program_bytes(&frozen)
        .map_err(|error| pipeline("frozen lighthouse encoding", error))?;
    if actual_bytes != frozen_bytes {
        return Err(CoreVmGateAError::NotFrozenLighthouse);
    }
    if corevm0_r1_s4_evidence_hash(s4_evidence) != s4_evidence.evidence_hash
        || emit_corevm0_r1_s4_evidence(specialization) != *s4_evidence
    {
        return Err(CoreVmGateAError::S4IdentityMismatch);
    }

    let bound =
        build_definitional_corevm0(program).map_err(|error| pipeline("CoreVM0 build", error))?;
    if bound.program_hash() != specialization.report().program_hash()
        || bound.program_image_hash() != specialization.report().program_image_hash()
        || bound.artifact().semantic_hash != specialization.report().artifact_hash()
        || specialization.artifact().semantic_hash != s4_evidence.residual_hash
    {
        return Err(CoreVmGateAError::S4IdentityMismatch);
    }

    let bounds = build_bounds_package()?;
    let corpus = corevm0_gate_a_manifest()?;
    let branch_seed = verify_corevm0_program(program)
        .map_err(|error| pipeline("branch_mix seed verification", error))?;
    let bounds_seed = verify_corevm0_program(&bounds.program)
        .map_err(|error| pipeline("Bounds seed verification", error))?;
    let mut records = Vec::with_capacity(corpus.cases.len());
    let mut usage = CoreVmGateAUsage::default();

    for case in &corpus.cases {
        let (seed, definitional_core, residual_core) = match case.workload {
            CoreVmGateAWorkload::BranchMix => {
                evaluate_three_way(case, branch_seed, &bound, specialization.artifact())?
            }
            CoreVmGateAWorkload::BoundsOrderedArrayGet => evaluate_three_way(
                case,
                bounds_seed,
                &bounds.bound,
                bounds.specialization.artifact(),
            )?,
        };
        if !same_semantics(&seed, &definitional_core) || !same_semantics(&seed, &residual_core) {
            return Err(CoreVmGateAError::ThreeWayMismatch {
                case_ordinal: case.ordinal,
            });
        }
        usage.seed_steps = usage
            .seed_steps
            .checked_add(seed.steps)
            .ok_or(CoreVmGateAError::MetricOverflow)?;
        usage.definitional_core_steps = usage
            .definitional_core_steps
            .checked_add(definitional_core.steps)
            .ok_or(CoreVmGateAError::MetricOverflow)?;
        usage.residual_core_steps = usage
            .residual_core_steps
            .checked_add(residual_core.steps)
            .ok_or(CoreVmGateAError::MetricOverflow)?;

        let mut record = CoreVmGateAThreeWayRecord {
            case_ordinal: case.ordinal,
            input_hash: case.input_hash,
            seed,
            definitional_core,
            residual_core,
            record_hash: SemanticHash::ZERO,
        };
        record.record_hash = corevm0_gate_a_record_hash(&record)?;
        records.push(record);
    }
    let execution_budget = corevm0_gate_a_execution_budget();
    enforce_usage_caps(execution_budget, usage)?;
    let results_hash = corevm0_gate_a_results_hash(&records)?;
    let telemetry_hash = corevm0_gate_a_telemetry_hash(&records, execution_budget, usage)?;

    let mut evidence = CoreVmGateAEvidence {
        schema_version: COREVM0_GATE_A_SCHEMA_VERSION,
        replay_version: COREVM0_GATE_A_REPLAY_VERSION,
        assurance: CoreVmGateAAssurance::FiniteBoundedValidation,
        numeric_contract_version: COREVM0_GATE_A_NUMERIC_CONTRACT_VERSION,
        numeric_contract_hash: corevm0_gate_a_numeric_contract_hash(),
        s4_evidence_hash: s4_evidence.evidence_hash,
        source_program_hash: bound.program_hash(),
        source_program_image_hash: bound.program_image_hash(),
        definitional_artifact_hash: bound.artifact().semantic_hash,
        core_interpreter_semantics_hash: bound.core_interpreter_semantics_hash(),
        residual_hash: specialization.artifact().semantic_hash,
        s4_binding_hash: specialization.report().binding_hash(),
        s4_erasure_hash: specialization.report().erasure().erasure_hash(),
        bounds_program_hash: bounds.bound.program_hash(),
        bounds_definitional_artifact_hash: bounds.bound.artifact().semantic_hash,
        bounds_residual_hash: bounds.specialization.artifact().semantic_hash,
        bounds_s4_evidence_hash: bounds.evidence.evidence_hash,
        corpus,
        records,
        results_hash,
        execution_budget,
        usage,
        telemetry_hash,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = corevm0_gate_a_evidence_hash(&evidence)?;
    Ok(evidence)
}

/// Fail-closed raw admission. Shape caps, the top-level seal, nested seals, and
/// the canonical manifest are checked before expensive S4 replay, followed by
/// complete deterministic corpus and observation regeneration.
#[allow(clippy::too_many_arguments)]
pub fn verify_corevm0_gate_a_r1_s5(
    program: &CoreVmProgram,
    binding_time_request: &BindingTimeRequest,
    binding_time_certificate: &BindingTimeCertificate,
    specialization_request: &SpecializationRequest,
    s4_budget: PolyvariantR1S4Budget,
    claimed_residual: &CoreArtifact,
    s4_evidence: &CoreVmR1S4Evidence,
    gate_a_evidence: &CoreVmGateAEvidence,
) -> Result<VerifiedCoreVmGateA, CoreVmGateAReplayError> {
    // Shape caps are checked before any attacker-sized vector is encoded or
    // any expensive S4 replay begins.
    preflight_evidence_shape(gate_a_evidence).map_err(CoreVmGateAReplayError::InvalidClaimShape)?;
    let sealed = corevm0_gate_a_evidence_hash(gate_a_evidence)
        .map_err(CoreVmGateAReplayError::Regeneration)?;
    if sealed != gate_a_evidence.evidence_hash {
        return Err(CoreVmGateAReplayError::InvalidEvidenceHash);
    }

    if !claimed_nested_seals_are_valid(gate_a_evidence)
        .map_err(CoreVmGateAReplayError::Regeneration)?
    {
        return Err(CoreVmGateAReplayError::InvalidNestedEvidence);
    }
    let canonical_manifest =
        corevm0_gate_a_manifest().map_err(CoreVmGateAReplayError::Regeneration)?;
    if gate_a_evidence.schema_version != COREVM0_GATE_A_SCHEMA_VERSION
        || gate_a_evidence.replay_version != COREVM0_GATE_A_REPLAY_VERSION
        || gate_a_evidence.assurance != CoreVmGateAAssurance::FiniteBoundedValidation
        || gate_a_evidence.numeric_contract_version != COREVM0_GATE_A_NUMERIC_CONTRACT_VERSION
        || gate_a_evidence.numeric_contract_hash != corevm0_gate_a_numeric_contract_hash()
        || gate_a_evidence.execution_budget != corevm0_gate_a_execution_budget()
        || gate_a_evidence.corpus != canonical_manifest
    {
        return Err(CoreVmGateAReplayError::EvidenceMismatch);
    }

    let specialization = verify_corevm0_r1_s4_evidence(
        program,
        binding_time_request,
        binding_time_certificate,
        specialization_request,
        s4_budget,
        claimed_residual,
        s4_evidence,
    )
    .map_err(CoreVmGateAReplayError::S4)?;
    let regenerated = emit_corevm0_gate_a_r1_s5(program, &specialization, s4_evidence)
        .map_err(CoreVmGateAReplayError::Regeneration)?;
    if regenerated != *gate_a_evidence {
        return Err(CoreVmGateAReplayError::EvidenceMismatch);
    }
    Ok(VerifiedCoreVmGateA {
        specialization,
        evidence: regenerated,
    })
}

fn claimed_nested_seals_are_valid(
    evidence: &CoreVmGateAEvidence,
) -> Result<bool, CoreVmGateAError> {
    if corevm0_gate_a_manifest_hash(&evidence.corpus)? != evidence.corpus.manifest_hash
        || evidence.corpus.total_cases as usize != evidence.corpus.cases.len()
        || evidence.corpus.cases.len() != evidence.records.len()
    {
        return Ok(false);
    }
    for (expected_ordinal, (case, record)) in evidence
        .corpus
        .cases
        .iter()
        .zip(&evidence.records)
        .enumerate()
    {
        let expected_ordinal =
            u32::try_from(expected_ordinal).map_err(|_| CoreVmGateAError::MetricOverflow)?;
        if case.ordinal != expected_ordinal
            || case.input_hash != input_hash(case.workload, case.class, case.ordinal, &case.input)?
            || record.case_ordinal != case.ordinal
            || record.input_hash != case.input_hash
            || corevm0_gate_a_record_hash(record)? != record.record_hash
        {
            return Ok(false);
        }
    }
    if corevm0_gate_a_results_hash(&evidence.records)? != evidence.results_hash
        || corevm0_gate_a_telemetry_hash(
            &evidence.records,
            evidence.execution_budget,
            evidence.usage,
        )? != evidence.telemetry_hash
    {
        return Ok(false);
    }
    enforce_usage_caps(evidence.execution_budget, evidence.usage)?;
    Ok(true)
}

struct BoundsPackage {
    program: CoreVmProgram,
    bound: DefinitionalCoreVmArtifact,
    specialization: CoreVmR1S4Specialization,
    evidence: CoreVmR1S4Evidence,
}

fn build_bounds_package() -> Result<BoundsPackage, CoreVmGateAError> {
    let program = bounds_ordered_array_get_program();
    let bound = build_definitional_corevm0(&program)
        .map_err(|error| pipeline("Bounds definitional build", error))?;
    let binding = BindingTimeRequest::p1v0(
        bound.artifact(),
        vec![BindingTime::Static, BindingTime::Dynamic],
        BindingTimeBudget::new(1_000_000, 1_000_000, 10_000),
    )
    .map_err(|error| pipeline("Bounds B0 request construction", error))?;
    let validated_binding = validate_binding_time_b0_request(bound.artifact(), &binding)
        .map_err(|error| pipeline("Bounds B0 request validation", error))?;
    let certificate = certify_binding_time_b0d(&validated_binding)
        .map_err(|error| pipeline("Bounds B0 certificate", error))?;
    let request = SpecializationRequest::p1v0(
        bound.artifact(),
        &binding,
        &certificate,
        vec![
            SpecializationSlot::Static(bound.program_image().clone()),
            SpecializationSlot::Dynamic(array_type()),
        ],
        SpecializationBudget::new(1_000_000, 1_000_000, 100_000_000, 1_000_000, 1_000_000_000),
    )
    .map_err(|error| pipeline("Bounds R0 request construction", error))?;
    let validated =
        validate_specialization_r0a_request(bound.artifact(), &binding, &certificate, &request)
            .map_err(|error| pipeline("Bounds R0 request validation", error))?;
    let specialization = specialize_corevm0_r1_s4(&bound, &validated, fixed_s4_budget())
        .map_err(|error| pipeline("Bounds R1-S4 specialization", error))?;
    let evidence = emit_corevm0_r1_s4_evidence(&specialization);
    Ok(BoundsPackage {
        program,
        bound,
        specialization,
        evidence,
    })
}

pub(super) fn bounds_ordered_array_get_program() -> CoreVmProgram {
    CoreVmProgram {
        schema_version: COREVM0_SCHEMA_VERSION,
        arguments: vec![CoreVmType::ArrayF64],
        locals: vec![CoreVmType::F64],
        max_stack: 2,
        instructions: vec![
            CoreVmInstruction::LoadArg(0),
            CoreVmInstruction::ConstI64(0),
            CoreVmInstruction::ArrayGetF64,
            CoreVmInstruction::StoreLocal(0),
            CoreVmInstruction::LoadArg(0),
            CoreVmInstruction::ConstI64(1),
            CoreVmInstruction::ArrayGetF64,
            CoreVmInstruction::ReturnF64,
        ],
    }
}

fn evaluate_three_way(
    case: &CoreVmGateACase,
    seed_program: VerifiedCoreVmProgram<'_>,
    bound: &DefinitionalCoreVmArtifact,
    residual: &CoreArtifact,
) -> Result<
    (
        CoreVmGateAObservation,
        CoreVmGateAObservation,
        CoreVmGateAObservation,
    ),
    CoreVmGateAError,
> {
    let values = case
        .input
        .array_f64_bits
        .iter()
        .copied()
        .map(f64::from_bits)
        .collect::<Vec<_>>();
    let mut seed_arguments = vec![CoreVmValue::array_f64(values.clone())];
    let mut residual_arguments = vec![CoreValue::array_f64(values)];
    if case.workload == CoreVmGateAWorkload::BranchMix {
        seed_arguments.push(CoreVmValue::I64(case.input.repetitions));
        residual_arguments.push(CoreValue::I64(case.input.repetitions));
    }

    let seed = evaluate_corevm0(
        seed_program,
        seed_arguments.clone(),
        COREVM0_GATE_A_SEED_STEP_LIMIT,
    )
    .map_err(|error| pipeline("Gate A seed evaluation", error))?;
    let definitional = evaluate_definitional_corevm0(
        bound,
        seed_arguments,
        EvaluationBudget::new(
            COREVM0_GATE_A_CORE_STEP_LIMIT,
            COREVM0_GATE_A_CALL_DEPTH_LIMIT,
        ),
    )
    .map_err(|error| pipeline("Gate A definitional evaluation", error))?;
    let residual = evaluate(
        residual,
        residual_arguments,
        EvaluationBudget::new(
            COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
            COREVM0_GATE_A_CALL_DEPTH_LIMIT,
        ),
    )
    .map_err(|error| pipeline("Gate A residual evaluation", error))?;

    Ok((
        normalize_seed(case.ordinal, seed)?,
        normalize_definitional(case.ordinal, definitional)?,
        normalize_residual(case.ordinal, residual)?,
    ))
}

fn normalize_seed(
    _ordinal: u32,
    evaluation: CoreVmEvaluation,
) -> Result<CoreVmGateAObservation, CoreVmGateAError> {
    Ok(CoreVmGateAObservation {
        outcome: normalize_vm_outcome(evaluation.outcome),
        effect_trace: normalize_vm_trace(evaluation.effect_trace),
        steps: evaluation.steps,
    })
}

fn normalize_definitional(
    _ordinal: u32,
    evaluation: DefinitionalCoreVmEvaluation,
) -> Result<CoreVmGateAObservation, CoreVmGateAError> {
    Ok(CoreVmGateAObservation {
        outcome: normalize_vm_outcome(evaluation.outcome),
        effect_trace: normalize_vm_trace(evaluation.effect_trace),
        steps: evaluation.core_steps,
    })
}

fn normalize_residual(
    ordinal: u32,
    evaluation: Evaluation,
) -> Result<CoreVmGateAObservation, CoreVmGateAError> {
    let outcome = match evaluation.outcome {
        EvaluationOutcome::Return(CoreValue::F64(value)) => normalize_f64(value),
        EvaluationOutcome::Error(ErrorKind::Bounds) => CoreVmGateAOutcome::Bounds,
        _ => {
            return Err(CoreVmGateAError::UnsupportedOutcome {
                engine: "residual Core",
                case_ordinal: ordinal,
            });
        }
    };
    let mut effect_trace = Vec::with_capacity(evaluation.effect_trace.len());
    for effect in evaluation.effect_trace {
        match effect {
            EffectEvent::Error(ErrorKind::Bounds) => {
                effect_trace.push(CoreVmGateAEffect::Bounds);
            }
            _ => {
                return Err(CoreVmGateAError::UnsupportedOutcome {
                    engine: "residual Core effect trace",
                    case_ordinal: ordinal,
                });
            }
        }
    }
    Ok(CoreVmGateAObservation {
        outcome,
        effect_trace,
        steps: evaluation.steps,
    })
}

fn normalize_vm_outcome(outcome: CoreVmOutcome) -> CoreVmGateAOutcome {
    match outcome {
        CoreVmOutcome::ReturnF64(value) => normalize_f64(value),
        CoreVmOutcome::Error(CoreVmTypedError::Bounds) => CoreVmGateAOutcome::Bounds,
    }
}

fn normalize_f64(value: f64) -> CoreVmGateAOutcome {
    if value.is_nan() {
        CoreVmGateAOutcome::ReturnF64(CoreVmGateAF64::CanonicalNaN)
    } else {
        CoreVmGateAOutcome::ReturnF64(CoreVmGateAF64::ExactBits(value.to_bits()))
    }
}

fn normalize_vm_trace(trace: Vec<CoreVmTypedError>) -> Vec<CoreVmGateAEffect> {
    trace
        .into_iter()
        .map(|effect| match effect {
            CoreVmTypedError::Bounds => CoreVmGateAEffect::Bounds,
        })
        .collect()
}

fn same_semantics(left: &CoreVmGateAObservation, right: &CoreVmGateAObservation) -> bool {
    left.outcome == right.outcome && left.effect_trace == right.effect_trace
}

fn enforce_usage_caps(
    budget: CoreVmGateAExecutionBudget,
    usage: CoreVmGateAUsage,
) -> Result<(), CoreVmGateAError> {
    for (engine, actual, limit) in [
        ("seed", usage.seed_steps, budget.max_total_seed_steps),
        (
            "definitional Core",
            usage.definitional_core_steps,
            budget.max_total_definitional_core_steps,
        ),
        (
            "residual Core",
            usage.residual_core_steps,
            budget.max_total_residual_core_steps,
        ),
    ] {
        if actual > limit {
            return Err(CoreVmGateAError::ExecutionCapExceeded {
                engine,
                limit,
                actual,
            });
        }
    }
    Ok(())
}

fn push_case(
    cases: &mut Vec<CoreVmGateACase>,
    workload: CoreVmGateAWorkload,
    class: CoreVmGateACaseClass,
    values: Vec<f64>,
    repetitions: i64,
) -> Result<(), CoreVmGateAError> {
    let length = u32::try_from(values.len()).map_err(|_| CoreVmGateAError::MetricOverflow)?;
    if length > COREVM0_GATE_A_MAX_ARRAY_ELEMENTS_PER_CASE {
        return Err(CoreVmGateAError::CorpusInvariant(
            "case input exceeds the per-case array cap",
        ));
    }
    if workload == CoreVmGateAWorkload::BoundsOrderedArrayGet && repetitions != 0 {
        return Err(CoreVmGateAError::CorpusInvariant(
            "Bounds input repetitions must be canonical zero",
        ));
    }
    let ordinal = u32::try_from(cases.len()).map_err(|_| CoreVmGateAError::MetricOverflow)?;
    let input = CoreVmGateAInput {
        array_f64_bits: values.into_iter().map(f64::to_bits).collect(),
        repetitions,
    };
    let input_hash = input_hash(workload, class, ordinal, &input)?;
    cases.push(CoreVmGateACase {
        workload,
        class,
        ordinal,
        input,
        input_hash,
    });
    Ok(())
}

fn preflight_evidence_shape(evidence: &CoreVmGateAEvidence) -> Result<(), CoreVmGateAError> {
    preflight_manifest_shape(&evidence.corpus)?;
    preflight_records_shape(&evidence.records)?;
    Ok(())
}

fn preflight_manifest_shape(manifest: &CoreVmGateACorpusManifest) -> Result<(), CoreVmGateAError> {
    let case_count =
        u32::try_from(manifest.cases.len()).map_err(|_| CoreVmGateAError::MetricOverflow)?;
    if case_count > COREVM0_GATE_A_MAX_CASES {
        return Err(CoreVmGateAError::CorpusInvariant(
            "claimed case vector exceeds the hard cap",
        ));
    }
    let mut total_elements = 0_u64;
    for case in &manifest.cases {
        preflight_case_shape(case)?;
        let elements = u64::try_from(case.input.array_f64_bits.len())
            .map_err(|_| CoreVmGateAError::MetricOverflow)?;
        total_elements = total_elements
            .checked_add(elements)
            .ok_or(CoreVmGateAError::MetricOverflow)?;
        if total_elements > COREVM0_GATE_A_MAX_TOTAL_ARRAY_ELEMENTS {
            return Err(CoreVmGateAError::CorpusInvariant(
                "claimed input elements exceed the hard cap",
            ));
        }
    }
    Ok(())
}

fn preflight_case_shape(case: &CoreVmGateACase) -> Result<(), CoreVmGateAError> {
    let elements = u32::try_from(case.input.array_f64_bits.len())
        .map_err(|_| CoreVmGateAError::MetricOverflow)?;
    if elements > COREVM0_GATE_A_MAX_ARRAY_ELEMENTS_PER_CASE {
        return Err(CoreVmGateAError::CorpusInvariant(
            "claimed case input exceeds the hard cap",
        ));
    }
    Ok(())
}

fn preflight_records_shape(records: &[CoreVmGateAThreeWayRecord]) -> Result<(), CoreVmGateAError> {
    let record_count =
        u32::try_from(records.len()).map_err(|_| CoreVmGateAError::MetricOverflow)?;
    if record_count > COREVM0_GATE_A_MAX_CASES {
        return Err(CoreVmGateAError::CorpusInvariant(
            "claimed record vector exceeds the hard cap",
        ));
    }
    for record in records {
        preflight_record_shape(record)?;
    }
    Ok(())
}

fn preflight_record_shape(record: &CoreVmGateAThreeWayRecord) -> Result<(), CoreVmGateAError> {
    for observation in [
        &record.seed,
        &record.definitional_core,
        &record.residual_core,
    ] {
        let effects = u32::try_from(observation.effect_trace.len())
            .map_err(|_| CoreVmGateAError::MetricOverflow)?;
        if effects > COREVM0_GATE_A_MAX_EFFECTS_PER_ENGINE {
            return Err(CoreVmGateAError::CorpusInvariant(
                "claimed effect trace exceeds the hard cap",
            ));
        }
    }
    Ok(())
}

fn input_hash(
    workload: CoreVmGateAWorkload,
    class: CoreVmGateACaseClass,
    ordinal: u32,
    input: &CoreVmGateAInput,
) -> Result<SemanticHash, CoreVmGateAError> {
    let mut bytes = INPUT_DOMAIN.to_vec();
    put_u8(&mut bytes, workload_tag(workload));
    put_u8(&mut bytes, class_tag(class));
    put_u32(&mut bytes, ordinal);
    encode_input(&mut bytes, input)?;
    Ok(SemanticHash(sha256(&bytes)))
}

fn encode_evidence(
    bytes: &mut Vec<u8>,
    evidence: &CoreVmGateAEvidence,
    include_seal: bool,
) -> Result<(), CoreVmGateAError> {
    put_version(bytes, evidence.schema_version);
    put_version(bytes, evidence.replay_version);
    put_u8(
        bytes,
        match evidence.assurance {
            CoreVmGateAAssurance::FiniteBoundedValidation => 0,
        },
    );
    put_version(bytes, evidence.numeric_contract_version);
    for hash in [
        evidence.numeric_contract_hash,
        evidence.s4_evidence_hash,
        evidence.source_program_hash,
        evidence.source_program_image_hash,
        evidence.definitional_artifact_hash,
        evidence.core_interpreter_semantics_hash,
        evidence.residual_hash,
        evidence.s4_binding_hash,
        evidence.s4_erasure_hash,
        evidence.bounds_program_hash,
        evidence.bounds_definitional_artifact_hash,
        evidence.bounds_residual_hash,
        evidence.bounds_s4_evidence_hash,
    ] {
        bytes.extend_from_slice(&hash.0);
    }
    encode_manifest(bytes, &evidence.corpus, true)?;
    put_len(bytes, evidence.records.len())?;
    for record in &evidence.records {
        encode_record(bytes, record, true, true)?;
    }
    bytes.extend_from_slice(&evidence.results_hash.0);
    encode_execution_budget(bytes, evidence.execution_budget);
    encode_usage(bytes, evidence.usage);
    bytes.extend_from_slice(&evidence.telemetry_hash.0);
    if include_seal {
        bytes.extend_from_slice(&evidence.evidence_hash.0);
    }
    Ok(())
}

fn encode_manifest(
    bytes: &mut Vec<u8>,
    manifest: &CoreVmGateACorpusManifest,
    include_seal: bool,
) -> Result<(), CoreVmGateAError> {
    put_version(bytes, manifest.corpus_version);
    put_version(bytes, manifest.generator_version);
    put_u64(bytes, manifest.generator_seed);
    for count in [
        manifest.edge_cases,
        manifest.exhaustive_cases,
        manifest.generated_cases,
        manifest.bounds_cases,
        manifest.total_cases,
    ] {
        put_u32(bytes, count);
    }
    put_u64(bytes, manifest.total_array_elements);
    put_len(bytes, manifest.cases.len())?;
    for case in &manifest.cases {
        put_u8(bytes, workload_tag(case.workload));
        put_u8(bytes, class_tag(case.class));
        put_u32(bytes, case.ordinal);
        encode_input(bytes, &case.input)?;
        bytes.extend_from_slice(&case.input_hash.0);
    }
    if include_seal {
        bytes.extend_from_slice(&manifest.manifest_hash.0);
    }
    Ok(())
}

fn encode_input(bytes: &mut Vec<u8>, input: &CoreVmGateAInput) -> Result<(), CoreVmGateAError> {
    put_len(bytes, input.array_f64_bits.len())?;
    for value in &input.array_f64_bits {
        put_u64(bytes, *value);
    }
    bytes.extend_from_slice(&input.repetitions.to_be_bytes());
    Ok(())
}

fn encode_record(
    bytes: &mut Vec<u8>,
    record: &CoreVmGateAThreeWayRecord,
    include_seal: bool,
    include_steps: bool,
) -> Result<(), CoreVmGateAError> {
    put_u32(bytes, record.case_ordinal);
    bytes.extend_from_slice(&record.input_hash.0);
    encode_observation(bytes, &record.seed, include_steps)?;
    encode_observation(bytes, &record.definitional_core, include_steps)?;
    encode_observation(bytes, &record.residual_core, include_steps)?;
    if include_seal {
        bytes.extend_from_slice(&record.record_hash.0);
    }
    Ok(())
}

fn encode_observation(
    bytes: &mut Vec<u8>,
    observation: &CoreVmGateAObservation,
    include_steps: bool,
) -> Result<(), CoreVmGateAError> {
    match observation.outcome {
        CoreVmGateAOutcome::ReturnF64(CoreVmGateAF64::ExactBits(bits)) => {
            put_u8(bytes, 0);
            put_u64(bytes, bits);
        }
        CoreVmGateAOutcome::ReturnF64(CoreVmGateAF64::CanonicalNaN) => {
            put_u8(bytes, 1);
        }
        CoreVmGateAOutcome::Bounds => {
            put_u8(bytes, 2);
        }
    }
    put_len(bytes, observation.effect_trace.len())?;
    for effect in &observation.effect_trace {
        put_u8(
            bytes,
            match effect {
                CoreVmGateAEffect::Bounds => 0,
            },
        );
    }
    if include_steps {
        put_u64(bytes, observation.steps);
    }
    Ok(())
}

fn encode_execution_budget(bytes: &mut Vec<u8>, budget: CoreVmGateAExecutionBudget) {
    put_u32(bytes, budget.max_cases);
    put_u32(bytes, budget.max_array_elements_per_case);
    put_u64(bytes, budget.max_total_array_elements);
    put_u64(bytes, budget.seed_steps_per_case);
    put_u64(bytes, budget.definitional_core_steps_per_case);
    put_u64(bytes, budget.residual_core_steps_per_case);
    put_u32(bytes, budget.core_call_depth_per_case);
    put_u64(bytes, budget.max_total_seed_steps);
    put_u64(bytes, budget.max_total_definitional_core_steps);
    put_u64(bytes, budget.max_total_residual_core_steps);
}

fn encode_usage(bytes: &mut Vec<u8>, usage: CoreVmGateAUsage) {
    put_u64(bytes, usage.seed_steps);
    put_u64(bytes, usage.definitional_core_steps);
    put_u64(bytes, usage.residual_core_steps);
}

fn workload_tag(value: CoreVmGateAWorkload) -> u8 {
    match value {
        CoreVmGateAWorkload::BranchMix => 0,
        CoreVmGateAWorkload::BoundsOrderedArrayGet => 1,
    }
}

fn class_tag(value: CoreVmGateACaseClass) -> u8 {
    match value {
        CoreVmGateACaseClass::Edge => 0,
        CoreVmGateACaseClass::BoundedExhaustive => 1,
        CoreVmGateACaseClass::DeterministicGenerated => 2,
        CoreVmGateACaseClass::BoundsEffect => 3,
    }
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_be_bytes());
    bytes.extend_from_slice(&version.1.to_be_bytes());
    bytes.extend_from_slice(&version.2.to_be_bytes());
}

fn put_u8(bytes: &mut Vec<u8>, value: u8) {
    bytes.push(value);
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_len(bytes: &mut Vec<u8>, length: usize) -> Result<(), CoreVmGateAError> {
    let length = u32::try_from(length).map_err(|_| CoreVmGateAError::MetricOverflow)?;
    put_u32(bytes, length);
    Ok(())
}

fn array_type() -> Type {
    Type::Array {
        region: RegionId(0),
        mutability: Mutability::Read,
        element: Box::new(Type::F64),
    }
}

fn fixed_s4_budget() -> PolyvariantR1S4Budget {
    PolyvariantR1S4Budget::new(
        100_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000_000,
    )
}

fn lcg(state: u64) -> u64 {
    state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407)
}

fn pipeline(stage: &'static str, error: impl fmt::Display) -> CoreVmGateAError {
    CoreVmGateAError::Pipeline {
        stage,
        message: error.to_string(),
    }
}
