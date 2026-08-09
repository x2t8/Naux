//! Sealed finite translation correspondence for the two predecessor handoffs
//! that predate the R1-S7a target correspondence contract.
//!
//! R1-S5 binds Residual Core to its deterministic Core SSA translation.
//! R1-S6 independently binds that source-bound Core SSA to its deterministic
//! Machine IR translation. Both evidence lines replay the exact ordered
//! 51-case Gate-A manifest. They are finite validation evidence, not proofs
//! over an unbounded input domain.

use super::core_ssa::{
    evaluate_core_ssa_translation, verify_core_ssa_source, CoreSsaArtifact, CoreSsaSourceError,
    CoreSsaTranslationExecutionError,
};
use super::corevm0_gate_a::{
    corevm0_gate_a_case_input_hash, corevm0_gate_a_manifest, CoreVmGateACase, CoreVmGateACaseClass,
    CoreVmGateAError, CoreVmGateAWorkload, COREVM0_GATE_A_BOUNDS_CASES,
    COREVM0_GATE_A_CALL_DEPTH_LIMIT, COREVM0_GATE_A_EDGE_CASES, COREVM0_GATE_A_EXHAUSTIVE_CASES,
    COREVM0_GATE_A_GENERATED_CASES, COREVM0_GATE_A_MAX_ARRAY_ELEMENTS_PER_CASE,
    COREVM0_GATE_A_MAX_EFFECTS_PER_ENGINE, COREVM0_GATE_A_MAX_TOTAL_ARRAY_ELEMENTS,
    COREVM0_GATE_A_MAX_TOTAL_RESIDUAL_STEPS, COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
    COREVM0_GATE_A_TOTAL_CASES,
};
use super::encoding::sha256;
use super::interpret::{
    evaluate, CoreValue, EffectEvent, Evaluation, EvaluationBudget, EvaluationOutcome,
    ExecutionError,
};
use super::machine_ir::{
    evaluate_machine_ir_translation, verify_machine_ir_source, MachineIrArtifact,
    MachineIrSourceError, MachineIrTranslationExecutionError,
};
use super::schema::{CoreArtifact, ErrorKind, SemanticHash};
use std::fmt;

pub const R1_S5_CORE_SSA_CORRESPONDENCE_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const R1_S5_CORE_SSA_CORRESPONDENCE_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const R1_S6_MACHINE_IR_CORRESPONDENCE_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const R1_S6_MACHINE_IR_CORRESPONDENCE_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);

/// These domains are public protocol constants. They are deliberately
/// distinct from Gate A, artifact semantic identities, and R1-S7a.
pub const R1_S5_CORE_SSA_CORRESPONDENCE_RECORD_DOMAIN: &[u8] =
    b"NAUX:core-ssa:r1-s5:translation-correspondence:record:v1\0";
pub const R1_S5_CORE_SSA_CORRESPONDENCE_RESULTS_DOMAIN: &[u8] =
    b"NAUX:core-ssa:r1-s5:translation-correspondence:results:v1\0";
pub const R1_S6_MACHINE_IR_CORRESPONDENCE_RECORD_DOMAIN: &[u8] =
    b"NAUX:machine-ir:r1-s6:translation-correspondence:record:v1\0";
pub const R1_S6_MACHINE_IR_CORRESPONDENCE_RESULTS_DOMAIN: &[u8] =
    b"NAUX:machine-ir:r1-s6:translation-correspondence:results:v1\0";

pub const TRANSLATION_CORRESPONDENCE_TOTAL_CASES: u32 = COREVM0_GATE_A_TOTAL_CASES;
pub const TRANSLATION_CORRESPONDENCE_BRANCH_CASES: u32 =
    COREVM0_GATE_A_EDGE_CASES + COREVM0_GATE_A_EXHAUSTIVE_CASES + COREVM0_GATE_A_GENERATED_CASES;
pub const TRANSLATION_CORRESPONDENCE_BOUNDS_CASES: u32 = COREVM0_GATE_A_BOUNDS_CASES;
pub const TRANSLATION_CORRESPONDENCE_MAX_EFFECTS_PER_OBSERVATION: u32 =
    COREVM0_GATE_A_MAX_EFFECTS_PER_ENGINE;
pub const TRANSLATION_CORRESPONDENCE_STEP_LIMIT_PER_CASE: u64 = COREVM0_GATE_A_RESIDUAL_STEP_LIMIT;
pub const TRANSLATION_CORRESPONDENCE_CALL_DEPTH_LIMIT: u32 = COREVM0_GATE_A_CALL_DEPTH_LIMIT;
pub const TRANSLATION_CORRESPONDENCE_MAX_TOTAL_STEPS_PER_ENGINE: u64 =
    COREVM0_GATE_A_MAX_TOTAL_RESIDUAL_STEPS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranslationCorrespondenceLimits {
    pub total_cases: u32,
    pub branch_cases: u32,
    pub bounds_cases: u32,
    pub max_array_elements_per_case: u32,
    pub max_total_array_elements: u64,
    pub max_effects_per_observation: u32,
    pub steps_per_case: u64,
    pub call_depth: u32,
    pub max_total_steps_per_engine: u64,
}

impl TranslationCorrespondenceLimits {
    pub const fn r1() -> Self {
        Self {
            total_cases: TRANSLATION_CORRESPONDENCE_TOTAL_CASES,
            branch_cases: TRANSLATION_CORRESPONDENCE_BRANCH_CASES,
            bounds_cases: TRANSLATION_CORRESPONDENCE_BOUNDS_CASES,
            max_array_elements_per_case: COREVM0_GATE_A_MAX_ARRAY_ELEMENTS_PER_CASE,
            max_total_array_elements: COREVM0_GATE_A_MAX_TOTAL_ARRAY_ELEMENTS,
            max_effects_per_observation: TRANSLATION_CORRESPONDENCE_MAX_EFFECTS_PER_OBSERVATION,
            steps_per_case: TRANSLATION_CORRESPONDENCE_STEP_LIMIT_PER_CASE,
            call_depth: TRANSLATION_CORRESPONDENCE_CALL_DEPTH_LIMIT,
            max_total_steps_per_engine: TRANSLATION_CORRESPONDENCE_MAX_TOTAL_STEPS_PER_ENGINE,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranslationCorrespondenceF64 {
    /// Exact IEEE-754 bits for every non-NaN, including signed zero.
    ExactBits(u64),
    /// NaN payload and sign are deliberately unobservable.
    CanonicalNaN,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranslationCorrespondenceOutcome {
    ReturnF64(TranslationCorrespondenceF64),
    Bounds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranslationCorrespondenceEffect {
    Bounds,
}

/// Engine-local work counters are excluded from this semantic observation.
/// The fixed execution budgets remain part of each aggregate results root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranslationCorrespondenceObservation {
    pub outcome: TranslationCorrespondenceOutcome,
    pub effect_trace: Vec<TranslationCorrespondenceEffect>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1S5CoreSsaCorrespondenceRecord {
    pub schema_version: (u16, u16, u16),
    pub policy_version: (u16, u16, u16),
    pub case_ordinal: u32,
    pub workload: CoreVmGateAWorkload,
    pub class: CoreVmGateACaseClass,
    pub input_hash: SemanticHash,
    pub source_core_hash: SemanticHash,
    pub core_ssa_hash: SemanticHash,
    pub residual_core: TranslationCorrespondenceObservation,
    pub core_ssa: TranslationCorrespondenceObservation,
    pub record_hash: SemanticHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1S5CoreSsaCorrespondenceEvidence {
    pub schema_version: (u16, u16, u16),
    pub policy_version: (u16, u16, u16),
    pub limits: TranslationCorrespondenceLimits,
    pub manifest_hash: SemanticHash,
    pub branch_source_core_hash: SemanticHash,
    pub branch_core_ssa_hash: SemanticHash,
    pub bounds_source_core_hash: SemanticHash,
    pub bounds_core_ssa_hash: SemanticHash,
    pub records: Vec<R1S5CoreSsaCorrespondenceRecord>,
    pub results_hash: SemanticHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1S6MachineIrCorrespondenceRecord {
    pub schema_version: (u16, u16, u16),
    pub policy_version: (u16, u16, u16),
    pub case_ordinal: u32,
    pub workload: CoreVmGateAWorkload,
    pub class: CoreVmGateACaseClass,
    pub input_hash: SemanticHash,
    pub source_core_hash: SemanticHash,
    pub source_core_ssa_hash: SemanticHash,
    pub machine_ir_hash: SemanticHash,
    pub core_ssa: TranslationCorrespondenceObservation,
    pub machine_ir: TranslationCorrespondenceObservation,
    pub record_hash: SemanticHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1S6MachineIrCorrespondenceEvidence {
    pub schema_version: (u16, u16, u16),
    pub policy_version: (u16, u16, u16),
    pub limits: TranslationCorrespondenceLimits,
    pub manifest_hash: SemanticHash,
    pub branch_source_core_hash: SemanticHash,
    pub branch_source_core_ssa_hash: SemanticHash,
    pub branch_machine_ir_hash: SemanticHash,
    pub bounds_source_core_hash: SemanticHash,
    pub bounds_source_core_ssa_hash: SemanticHash,
    pub bounds_machine_ir_hash: SemanticHash,
    pub records: Vec<R1S6MachineIrCorrespondenceRecord>,
    pub results_hash: SemanticHash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranslationCorrespondenceStage {
    R1S5CoreSsa,
    R1S6MachineIr,
}

#[derive(Debug)]
pub enum TranslationCorrespondenceError {
    Manifest(CoreVmGateAError),
    ManifestInvariant(&'static str),
    InvalidSchema {
        stage: TranslationCorrespondenceStage,
        actual: (u16, u16, u16),
    },
    InvalidPolicy {
        stage: TranslationCorrespondenceStage,
        actual: (u16, u16, u16),
    },
    InvalidLimits {
        stage: TranslationCorrespondenceStage,
    },
    RecordCount {
        stage: TranslationCorrespondenceStage,
        expected: u32,
        actual: u32,
    },
    NonCanonicalOrdinal {
        stage: TranslationCorrespondenceStage,
        expected: u32,
        actual: u32,
    },
    CanonicalCaseMismatch {
        stage: TranslationCorrespondenceStage,
        case_ordinal: u32,
        field: &'static str,
    },
    SourceIdentityMismatch {
        stage: TranslationCorrespondenceStage,
        case_ordinal: u32,
        field: &'static str,
    },
    CoreSsaSource {
        workload: CoreVmGateAWorkload,
        error: CoreSsaSourceError,
    },
    MachineIrSource {
        workload: CoreVmGateAWorkload,
        error: MachineIrSourceError,
    },
    CoreExecution {
        workload: CoreVmGateAWorkload,
        case_ordinal: u32,
        error: ExecutionError,
    },
    CoreSsaExecution {
        stage: TranslationCorrespondenceStage,
        workload: CoreVmGateAWorkload,
        case_ordinal: u32,
        error: CoreSsaTranslationExecutionError,
    },
    MachineIrExecution {
        workload: CoreVmGateAWorkload,
        case_ordinal: u32,
        error: MachineIrTranslationExecutionError,
    },
    UnsupportedOutcome {
        stage: TranslationCorrespondenceStage,
        engine: &'static str,
        case_ordinal: u32,
    },
    UnsupportedEffect {
        stage: TranslationCorrespondenceStage,
        engine: &'static str,
        case_ordinal: u32,
    },
    EffectLimit {
        stage: TranslationCorrespondenceStage,
        engine: &'static str,
        case_ordinal: u32,
        limit: u32,
        actual: u32,
    },
    NonCanonicalObservation {
        stage: TranslationCorrespondenceStage,
        engine: &'static str,
        case_ordinal: u32,
    },
    SemanticMismatch {
        stage: TranslationCorrespondenceStage,
        case_ordinal: u32,
    },
    RecordHashMismatch {
        stage: TranslationCorrespondenceStage,
        case_ordinal: u32,
    },
    ResultsHashMismatch {
        stage: TranslationCorrespondenceStage,
    },
    EvidenceMismatch {
        stage: TranslationCorrespondenceStage,
    },
    ExecutionCapExceeded {
        stage: TranslationCorrespondenceStage,
        engine: &'static str,
        limit: u64,
        actual: u64,
    },
    MetricOverflow,
}

impl fmt::Display for TranslationCorrespondenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(error) => {
                write!(formatter, "Gate-A manifest generation failed: {error}")
            }
            Self::ManifestInvariant(message) => {
                write!(
                    formatter,
                    "Gate-A correspondence manifest invariant: {message}"
                )
            }
            Self::InvalidSchema { stage, actual } => {
                write!(
                    formatter,
                    "{stage:?} correspondence schema {actual:?} is not admitted"
                )
            }
            Self::InvalidPolicy { stage, actual } => {
                write!(
                    formatter,
                    "{stage:?} correspondence policy {actual:?} is not admitted"
                )
            }
            Self::InvalidLimits { stage } => {
                write!(
                    formatter,
                    "{stage:?} correspondence limits are not canonical"
                )
            }
            Self::RecordCount {
                stage,
                expected,
                actual,
            } => write!(
                formatter,
                "{stage:?} correspondence requires exactly {expected} records; found {actual}"
            ),
            Self::NonCanonicalOrdinal {
                stage,
                expected,
                actual,
            } => write!(
                formatter,
                "{stage:?} correspondence expected ordinal {expected}; found {actual}"
            ),
            Self::CanonicalCaseMismatch {
                stage,
                case_ordinal,
                field,
            } => write!(
                formatter,
                "{stage:?} record {case_ordinal} differs from the canonical Gate-A {field}"
            ),
            Self::SourceIdentityMismatch {
                stage,
                case_ordinal,
                field,
            } => write!(
                formatter,
                "{stage:?} record {case_ordinal} carries a different {field} identity"
            ),
            Self::CoreSsaSource { workload, error } => {
                write!(
                    formatter,
                    "{workload:?} Core SSA source replay failed: {error}"
                )
            }
            Self::MachineIrSource { workload, error } => {
                write!(
                    formatter,
                    "{workload:?} Machine IR source replay failed: {error}"
                )
            }
            Self::CoreExecution {
                workload,
                case_ordinal,
                error,
            } => write!(
                formatter,
                "{workload:?} Residual Core execution failed in case {case_ordinal}: {error}"
            ),
            Self::CoreSsaExecution {
                stage,
                workload,
                case_ordinal,
                error,
            } => write!(
                formatter,
                "{stage:?} {workload:?} Core SSA execution failed in case {case_ordinal}: {error}"
            ),
            Self::MachineIrExecution {
                workload,
                case_ordinal,
                error,
            } => write!(
                formatter,
                "{workload:?} Machine IR execution failed in case {case_ordinal}: {error}"
            ),
            Self::UnsupportedOutcome {
                stage,
                engine,
                case_ordinal,
            } => write!(
                formatter,
                "{stage:?} {engine} produced an unsupported outcome in case {case_ordinal}"
            ),
            Self::UnsupportedEffect {
                stage,
                engine,
                case_ordinal,
            } => write!(
                formatter,
                "{stage:?} {engine} produced an unsupported effect in case {case_ordinal}"
            ),
            Self::EffectLimit {
                stage,
                engine,
                case_ordinal,
                limit,
                actual,
            } => write!(
                formatter,
                "{stage:?} {engine} case {case_ordinal} has {actual} effects; limit is {limit}"
            ),
            Self::NonCanonicalObservation {
                stage,
                engine,
                case_ordinal,
            } => write!(
                formatter,
                "{stage:?} {engine} case {case_ordinal} observation is not canonical"
            ),
            Self::SemanticMismatch {
                stage,
                case_ordinal,
            } => write!(
                formatter,
                "{stage:?} source and translation differ in case {case_ordinal}"
            ),
            Self::RecordHashMismatch {
                stage,
                case_ordinal,
            } => write!(
                formatter,
                "{stage:?} record {case_ordinal} seal is not canonical"
            ),
            Self::ResultsHashMismatch { stage } => {
                write!(
                    formatter,
                    "{stage:?} aggregate results seal is not canonical"
                )
            }
            Self::EvidenceMismatch { stage } => write!(
                formatter,
                "{stage:?} evidence differs from full deterministic regeneration"
            ),
            Self::ExecutionCapExceeded {
                stage,
                engine,
                limit,
                actual,
            } => write!(
                formatter,
                "{stage:?} {engine} execution usage {actual} exceeds fixed cap {limit}"
            ),
            Self::MetricOverflow => formatter.write_str("checked correspondence metric overflow"),
        }
    }
}

impl std::error::Error for TranslationCorrespondenceError {}

/// Opaque authority that keeps the complete R1-S5 source chain immutable for
/// the lifetime of the verified finite evidence.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedR1S5CoreSsaCorrespondence<'evidence, 'artifacts> {
    evidence: &'evidence R1S5CoreSsaCorrespondenceEvidence,
    branch_source: &'artifacts CoreArtifact,
    branch_ssa: &'artifacts CoreSsaArtifact,
    bounds_source: &'artifacts CoreArtifact,
    bounds_ssa: &'artifacts CoreSsaArtifact,
}

impl<'evidence, 'artifacts> VerifiedR1S5CoreSsaCorrespondence<'evidence, 'artifacts> {
    pub fn evidence(self) -> &'evidence R1S5CoreSsaCorrespondenceEvidence {
        self.evidence
    }

    pub fn results_hash(self) -> SemanticHash {
        self.evidence.results_hash
    }

    pub fn branch_source(self) -> &'artifacts CoreArtifact {
        self.branch_source
    }

    pub fn branch_ssa(self) -> &'artifacts CoreSsaArtifact {
        self.branch_ssa
    }

    pub fn bounds_source(self) -> &'artifacts CoreArtifact {
        self.bounds_source
    }

    pub fn bounds_ssa(self) -> &'artifacts CoreSsaArtifact {
        self.bounds_ssa
    }
}

/// Opaque authority that keeps the complete R1-S6 source chain immutable for
/// the lifetime of the verified finite evidence.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedR1S6MachineIrCorrespondence<'evidence, 'artifacts> {
    evidence: &'evidence R1S6MachineIrCorrespondenceEvidence,
    branch_source: &'artifacts CoreArtifact,
    branch_ssa: &'artifacts CoreSsaArtifact,
    branch_machine_ir: &'artifacts MachineIrArtifact,
    bounds_source: &'artifacts CoreArtifact,
    bounds_ssa: &'artifacts CoreSsaArtifact,
    bounds_machine_ir: &'artifacts MachineIrArtifact,
}

impl<'evidence, 'artifacts> VerifiedR1S6MachineIrCorrespondence<'evidence, 'artifacts> {
    pub fn evidence(self) -> &'evidence R1S6MachineIrCorrespondenceEvidence {
        self.evidence
    }

    pub fn results_hash(self) -> SemanticHash {
        self.evidence.results_hash
    }

    pub fn branch_source(self) -> &'artifacts CoreArtifact {
        self.branch_source
    }

    pub fn branch_ssa(self) -> &'artifacts CoreSsaArtifact {
        self.branch_ssa
    }

    pub fn branch_machine_ir(self) -> &'artifacts MachineIrArtifact {
        self.branch_machine_ir
    }

    pub fn bounds_source(self) -> &'artifacts CoreArtifact {
        self.bounds_source
    }

    pub fn bounds_ssa(self) -> &'artifacts CoreSsaArtifact {
        self.bounds_ssa
    }

    pub fn bounds_machine_ir(self) -> &'artifacts MachineIrArtifact {
        self.bounds_machine_ir
    }
}

/// Emit the complete ordered R1-S5 Residual Core ↔ Core SSA evidence.
///
/// All identities are derived from the supplied artifacts after deterministic
/// source replay. No detached hash tuple is accepted.
pub fn emit_r1_s5_core_ssa_correspondence(
    branch_source: &CoreArtifact,
    branch_ssa: &CoreSsaArtifact,
    bounds_source: &CoreArtifact,
    bounds_ssa: &CoreSsaArtifact,
) -> Result<R1S5CoreSsaCorrespondenceEvidence, TranslationCorrespondenceError> {
    verify_core_ssa_source(branch_ssa, branch_source).map_err(|error| {
        TranslationCorrespondenceError::CoreSsaSource {
            workload: CoreVmGateAWorkload::BranchMix,
            error,
        }
    })?;
    verify_core_ssa_source(bounds_ssa, bounds_source).map_err(|error| {
        TranslationCorrespondenceError::CoreSsaSource {
            workload: CoreVmGateAWorkload::BoundsOrderedArrayGet,
            error,
        }
    })?;

    let manifest = canonical_manifest()?;
    let limits = TranslationCorrespondenceLimits::r1();
    let budget = EvaluationBudget::new(limits.steps_per_case, limits.call_depth);
    let mut source_steps = 0_u64;
    let mut ssa_steps = 0_u64;
    let mut records = Vec::new();

    for case in &manifest.cases {
        let (source, ssa) = match case.workload {
            CoreVmGateAWorkload::BranchMix => (branch_source, branch_ssa),
            CoreVmGateAWorkload::BoundsOrderedArrayGet => (bounds_source, bounds_ssa),
        };
        let arguments = case_arguments(case);
        let residual_core = evaluate(source, arguments.clone(), budget).map_err(|error| {
            TranslationCorrespondenceError::CoreExecution {
                workload: case.workload,
                case_ordinal: case.ordinal,
                error,
            }
        })?;
        let core_ssa =
            evaluate_core_ssa_translation(ssa, source, arguments, budget).map_err(|error| {
                TranslationCorrespondenceError::CoreSsaExecution {
                    stage: TranslationCorrespondenceStage::R1S5CoreSsa,
                    workload: case.workload,
                    case_ordinal: case.ordinal,
                    error,
                }
            })?;
        accumulate_steps(
            TranslationCorrespondenceStage::R1S5CoreSsa,
            "Residual Core",
            &mut source_steps,
            residual_core.steps,
            limits,
        )?;
        accumulate_steps(
            TranslationCorrespondenceStage::R1S5CoreSsa,
            "Core SSA",
            &mut ssa_steps,
            core_ssa.steps,
            limits,
        )?;

        let residual_core = normalize_observation(
            TranslationCorrespondenceStage::R1S5CoreSsa,
            "Residual Core",
            case.ordinal,
            &residual_core,
        )?;
        let core_ssa = normalize_observation(
            TranslationCorrespondenceStage::R1S5CoreSsa,
            "Core SSA",
            case.ordinal,
            &core_ssa,
        )?;
        if residual_core != core_ssa {
            return Err(TranslationCorrespondenceError::SemanticMismatch {
                stage: TranslationCorrespondenceStage::R1S5CoreSsa,
                case_ordinal: case.ordinal,
            });
        }

        let mut record = R1S5CoreSsaCorrespondenceRecord {
            schema_version: R1_S5_CORE_SSA_CORRESPONDENCE_SCHEMA_VERSION,
            policy_version: R1_S5_CORE_SSA_CORRESPONDENCE_POLICY_VERSION,
            case_ordinal: case.ordinal,
            workload: case.workload,
            class: case.class,
            input_hash: case.input_hash,
            source_core_hash: source.semantic_hash,
            core_ssa_hash: ssa.semantic_hash,
            residual_core,
            core_ssa,
            record_hash: SemanticHash::ZERO,
        };
        record.record_hash = r1_s5_core_ssa_correspondence_record_hash(&record)?;
        records.push(record);
    }

    let mut evidence = R1S5CoreSsaCorrespondenceEvidence {
        schema_version: R1_S5_CORE_SSA_CORRESPONDENCE_SCHEMA_VERSION,
        policy_version: R1_S5_CORE_SSA_CORRESPONDENCE_POLICY_VERSION,
        limits,
        manifest_hash: manifest.manifest_hash,
        branch_source_core_hash: branch_source.semantic_hash,
        branch_core_ssa_hash: branch_ssa.semantic_hash,
        bounds_source_core_hash: bounds_source.semantic_hash,
        bounds_core_ssa_hash: bounds_ssa.semantic_hash,
        records,
        results_hash: SemanticHash::ZERO,
    };
    evidence.results_hash = r1_s5_core_ssa_correspondence_results_hash(&evidence)?;
    Ok(evidence)
}

/// Fail-closed R1-S5 admission. Nested seals and exact corpus shape are
/// checked first; all 51 executions are then regenerated before authority is
/// returned.
pub fn verify_r1_s5_core_ssa_correspondence<'evidence, 'artifacts>(
    branch_source: &'artifacts CoreArtifact,
    branch_ssa: &'artifacts CoreSsaArtifact,
    bounds_source: &'artifacts CoreArtifact,
    bounds_ssa: &'artifacts CoreSsaArtifact,
    evidence: &'evidence R1S5CoreSsaCorrespondenceEvidence,
) -> Result<VerifiedR1S5CoreSsaCorrespondence<'evidence, 'artifacts>, TranslationCorrespondenceError>
{
    validate_r1_s5_evidence_shape(evidence)?;
    let regenerated =
        emit_r1_s5_core_ssa_correspondence(branch_source, branch_ssa, bounds_source, bounds_ssa)?;
    if regenerated != *evidence {
        return Err(TranslationCorrespondenceError::EvidenceMismatch {
            stage: TranslationCorrespondenceStage::R1S5CoreSsa,
        });
    }
    Ok(VerifiedR1S5CoreSsaCorrespondence {
        evidence,
        branch_source,
        branch_ssa,
        bounds_source,
        bounds_ssa,
    })
}

/// Emit the complete ordered R1-S6 Core SSA ↔ Machine IR evidence.
pub fn emit_r1_s6_machine_ir_correspondence(
    branch_source: &CoreArtifact,
    branch_ssa: &CoreSsaArtifact,
    branch_machine_ir: &MachineIrArtifact,
    bounds_source: &CoreArtifact,
    bounds_ssa: &CoreSsaArtifact,
    bounds_machine_ir: &MachineIrArtifact,
) -> Result<R1S6MachineIrCorrespondenceEvidence, TranslationCorrespondenceError> {
    verify_core_ssa_source(branch_ssa, branch_source).map_err(|error| {
        TranslationCorrespondenceError::CoreSsaSource {
            workload: CoreVmGateAWorkload::BranchMix,
            error,
        }
    })?;
    verify_core_ssa_source(bounds_ssa, bounds_source).map_err(|error| {
        TranslationCorrespondenceError::CoreSsaSource {
            workload: CoreVmGateAWorkload::BoundsOrderedArrayGet,
            error,
        }
    })?;
    verify_machine_ir_source(branch_machine_ir, branch_ssa, branch_source).map_err(|error| {
        TranslationCorrespondenceError::MachineIrSource {
            workload: CoreVmGateAWorkload::BranchMix,
            error,
        }
    })?;
    verify_machine_ir_source(bounds_machine_ir, bounds_ssa, bounds_source).map_err(|error| {
        TranslationCorrespondenceError::MachineIrSource {
            workload: CoreVmGateAWorkload::BoundsOrderedArrayGet,
            error,
        }
    })?;

    let manifest = canonical_manifest()?;
    let limits = TranslationCorrespondenceLimits::r1();
    let budget = EvaluationBudget::new(limits.steps_per_case, limits.call_depth);
    let mut ssa_steps = 0_u64;
    let mut machine_steps = 0_u64;
    let mut records = Vec::new();

    for case in &manifest.cases {
        let (source, ssa, machine_ir) = match case.workload {
            CoreVmGateAWorkload::BranchMix => (branch_source, branch_ssa, branch_machine_ir),
            CoreVmGateAWorkload::BoundsOrderedArrayGet => {
                (bounds_source, bounds_ssa, bounds_machine_ir)
            }
        };
        let arguments = case_arguments(case);
        let core_ssa = evaluate_core_ssa_translation(ssa, source, arguments.clone(), budget)
            .map_err(|error| TranslationCorrespondenceError::CoreSsaExecution {
                stage: TranslationCorrespondenceStage::R1S6MachineIr,
                workload: case.workload,
                case_ordinal: case.ordinal,
                error,
            })?;
        let machine_ir = evaluate_machine_ir_translation(
            machine_ir, ssa, source, arguments, budget,
        )
        .map_err(|error| TranslationCorrespondenceError::MachineIrExecution {
            workload: case.workload,
            case_ordinal: case.ordinal,
            error,
        })?;
        accumulate_steps(
            TranslationCorrespondenceStage::R1S6MachineIr,
            "Core SSA",
            &mut ssa_steps,
            core_ssa.steps,
            limits,
        )?;
        accumulate_steps(
            TranslationCorrespondenceStage::R1S6MachineIr,
            "Machine IR",
            &mut machine_steps,
            machine_ir.steps,
            limits,
        )?;

        let core_ssa = normalize_observation(
            TranslationCorrespondenceStage::R1S6MachineIr,
            "Core SSA",
            case.ordinal,
            &core_ssa,
        )?;
        let machine_ir = normalize_observation(
            TranslationCorrespondenceStage::R1S6MachineIr,
            "Machine IR",
            case.ordinal,
            &machine_ir,
        )?;
        if core_ssa != machine_ir {
            return Err(TranslationCorrespondenceError::SemanticMismatch {
                stage: TranslationCorrespondenceStage::R1S6MachineIr,
                case_ordinal: case.ordinal,
            });
        }

        let mut record = R1S6MachineIrCorrespondenceRecord {
            schema_version: R1_S6_MACHINE_IR_CORRESPONDENCE_SCHEMA_VERSION,
            policy_version: R1_S6_MACHINE_IR_CORRESPONDENCE_POLICY_VERSION,
            case_ordinal: case.ordinal,
            workload: case.workload,
            class: case.class,
            input_hash: case.input_hash,
            source_core_hash: source.semantic_hash,
            source_core_ssa_hash: ssa.semantic_hash,
            machine_ir_hash: machine_ir_hash_for_workload(
                case.workload,
                branch_machine_ir,
                bounds_machine_ir,
            ),
            core_ssa,
            machine_ir,
            record_hash: SemanticHash::ZERO,
        };
        record.record_hash = r1_s6_machine_ir_correspondence_record_hash(&record)?;
        records.push(record);
    }

    let mut evidence = R1S6MachineIrCorrespondenceEvidence {
        schema_version: R1_S6_MACHINE_IR_CORRESPONDENCE_SCHEMA_VERSION,
        policy_version: R1_S6_MACHINE_IR_CORRESPONDENCE_POLICY_VERSION,
        limits,
        manifest_hash: manifest.manifest_hash,
        branch_source_core_hash: branch_source.semantic_hash,
        branch_source_core_ssa_hash: branch_ssa.semantic_hash,
        branch_machine_ir_hash: branch_machine_ir.semantic_hash,
        bounds_source_core_hash: bounds_source.semantic_hash,
        bounds_source_core_ssa_hash: bounds_ssa.semantic_hash,
        bounds_machine_ir_hash: bounds_machine_ir.semantic_hash,
        records,
        results_hash: SemanticHash::ZERO,
    };
    evidence.results_hash = r1_s6_machine_ir_correspondence_results_hash(&evidence)?;
    Ok(evidence)
}

/// Fail-closed R1-S6 admission with complete source replay and 51-case
/// deterministic regeneration.
pub fn verify_r1_s6_machine_ir_correspondence<'evidence, 'artifacts>(
    branch_source: &'artifacts CoreArtifact,
    branch_ssa: &'artifacts CoreSsaArtifact,
    branch_machine_ir: &'artifacts MachineIrArtifact,
    bounds_source: &'artifacts CoreArtifact,
    bounds_ssa: &'artifacts CoreSsaArtifact,
    bounds_machine_ir: &'artifacts MachineIrArtifact,
    evidence: &'evidence R1S6MachineIrCorrespondenceEvidence,
) -> Result<
    VerifiedR1S6MachineIrCorrespondence<'evidence, 'artifacts>,
    TranslationCorrespondenceError,
> {
    validate_r1_s6_evidence_shape(evidence)?;
    let regenerated = emit_r1_s6_machine_ir_correspondence(
        branch_source,
        branch_ssa,
        branch_machine_ir,
        bounds_source,
        bounds_ssa,
        bounds_machine_ir,
    )?;
    if regenerated != *evidence {
        return Err(TranslationCorrespondenceError::EvidenceMismatch {
            stage: TranslationCorrespondenceStage::R1S6MachineIr,
        });
    }
    Ok(VerifiedR1S6MachineIrCorrespondence {
        evidence,
        branch_source,
        branch_ssa,
        branch_machine_ir,
        bounds_source,
        bounds_ssa,
        bounds_machine_ir,
    })
}

pub fn r1_s5_core_ssa_correspondence_record_hash(
    record: &R1S5CoreSsaCorrespondenceRecord,
) -> Result<SemanticHash, TranslationCorrespondenceError> {
    validate_r1_s5_record_shape(record)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(R1_S5_CORE_SSA_CORRESPONDENCE_RECORD_DOMAIN);
    put_version(&mut bytes, record.schema_version);
    put_version(&mut bytes, record.policy_version);
    put_u32(&mut bytes, record.case_ordinal);
    put_workload(&mut bytes, record.workload);
    put_class(&mut bytes, record.class);
    bytes.extend_from_slice(&record.input_hash.0);
    bytes.extend_from_slice(&record.source_core_hash.0);
    bytes.extend_from_slice(&record.core_ssa_hash.0);
    put_observation(&mut bytes, &record.residual_core)?;
    put_observation(&mut bytes, &record.core_ssa)?;
    Ok(SemanticHash(sha256(&bytes)))
}

pub fn r1_s6_machine_ir_correspondence_record_hash(
    record: &R1S6MachineIrCorrespondenceRecord,
) -> Result<SemanticHash, TranslationCorrespondenceError> {
    validate_r1_s6_record_shape(record)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(R1_S6_MACHINE_IR_CORRESPONDENCE_RECORD_DOMAIN);
    put_version(&mut bytes, record.schema_version);
    put_version(&mut bytes, record.policy_version);
    put_u32(&mut bytes, record.case_ordinal);
    put_workload(&mut bytes, record.workload);
    put_class(&mut bytes, record.class);
    bytes.extend_from_slice(&record.input_hash.0);
    bytes.extend_from_slice(&record.source_core_hash.0);
    bytes.extend_from_slice(&record.source_core_ssa_hash.0);
    bytes.extend_from_slice(&record.machine_ir_hash.0);
    put_observation(&mut bytes, &record.core_ssa)?;
    put_observation(&mut bytes, &record.machine_ir)?;
    Ok(SemanticHash(sha256(&bytes)))
}

/// Order-sensitive aggregate identity. It admits exactly the regenerated
/// Gate-A order `0..50`, including 46 BranchMix then five Bounds records.
pub fn r1_s5_core_ssa_correspondence_results_hash(
    evidence: &R1S5CoreSsaCorrespondenceEvidence,
) -> Result<SemanticHash, TranslationCorrespondenceError> {
    validate_r1_s5_header(evidence)?;
    let manifest = canonical_manifest()?;
    validate_record_count(
        TranslationCorrespondenceStage::R1S5CoreSsa,
        evidence.records.len(),
    )?;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(R1_S5_CORE_SSA_CORRESPONDENCE_RESULTS_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_limits(&mut bytes, evidence.limits);
    bytes.extend_from_slice(&evidence.manifest_hash.0);
    bytes.extend_from_slice(&evidence.branch_source_core_hash.0);
    bytes.extend_from_slice(&evidence.branch_core_ssa_hash.0);
    bytes.extend_from_slice(&evidence.bounds_source_core_hash.0);
    bytes.extend_from_slice(&evidence.bounds_core_ssa_hash.0);
    put_u32(&mut bytes, TRANSLATION_CORRESPONDENCE_TOTAL_CASES);

    for (index, (record, case)) in evidence.records.iter().zip(&manifest.cases).enumerate() {
        let expected_ordinal =
            u32::try_from(index).map_err(|_| TranslationCorrespondenceError::MetricOverflow)?;
        validate_r1_s5_record_against_case(evidence, record, case, expected_ordinal)?;
        let actual_hash = r1_s5_core_ssa_correspondence_record_hash(record)?;
        if actual_hash != record.record_hash {
            return Err(TranslationCorrespondenceError::RecordHashMismatch {
                stage: TranslationCorrespondenceStage::R1S5CoreSsa,
                case_ordinal: record.case_ordinal,
            });
        }
        bytes.extend_from_slice(&record.record_hash.0);
    }
    Ok(SemanticHash(sha256(&bytes)))
}

/// Order-sensitive aggregate identity for the independent R1-S6 evidence
/// line. It does not reuse either the R1-S5 or R1-S7a hash domain.
pub fn r1_s6_machine_ir_correspondence_results_hash(
    evidence: &R1S6MachineIrCorrespondenceEvidence,
) -> Result<SemanticHash, TranslationCorrespondenceError> {
    validate_r1_s6_header(evidence)?;
    let manifest = canonical_manifest()?;
    validate_record_count(
        TranslationCorrespondenceStage::R1S6MachineIr,
        evidence.records.len(),
    )?;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(R1_S6_MACHINE_IR_CORRESPONDENCE_RESULTS_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_limits(&mut bytes, evidence.limits);
    bytes.extend_from_slice(&evidence.manifest_hash.0);
    bytes.extend_from_slice(&evidence.branch_source_core_hash.0);
    bytes.extend_from_slice(&evidence.branch_source_core_ssa_hash.0);
    bytes.extend_from_slice(&evidence.branch_machine_ir_hash.0);
    bytes.extend_from_slice(&evidence.bounds_source_core_hash.0);
    bytes.extend_from_slice(&evidence.bounds_source_core_ssa_hash.0);
    bytes.extend_from_slice(&evidence.bounds_machine_ir_hash.0);
    put_u32(&mut bytes, TRANSLATION_CORRESPONDENCE_TOTAL_CASES);

    for (index, (record, case)) in evidence.records.iter().zip(&manifest.cases).enumerate() {
        let expected_ordinal =
            u32::try_from(index).map_err(|_| TranslationCorrespondenceError::MetricOverflow)?;
        validate_r1_s6_record_against_case(evidence, record, case, expected_ordinal)?;
        let actual_hash = r1_s6_machine_ir_correspondence_record_hash(record)?;
        if actual_hash != record.record_hash {
            return Err(TranslationCorrespondenceError::RecordHashMismatch {
                stage: TranslationCorrespondenceStage::R1S6MachineIr,
                case_ordinal: record.case_ordinal,
            });
        }
        bytes.extend_from_slice(&record.record_hash.0);
    }
    Ok(SemanticHash(sha256(&bytes)))
}

fn validate_r1_s5_evidence_shape(
    evidence: &R1S5CoreSsaCorrespondenceEvidence,
) -> Result<(), TranslationCorrespondenceError> {
    let actual = r1_s5_core_ssa_correspondence_results_hash(evidence)?;
    if actual != evidence.results_hash {
        return Err(TranslationCorrespondenceError::ResultsHashMismatch {
            stage: TranslationCorrespondenceStage::R1S5CoreSsa,
        });
    }
    Ok(())
}

fn validate_r1_s6_evidence_shape(
    evidence: &R1S6MachineIrCorrespondenceEvidence,
) -> Result<(), TranslationCorrespondenceError> {
    let actual = r1_s6_machine_ir_correspondence_results_hash(evidence)?;
    if actual != evidence.results_hash {
        return Err(TranslationCorrespondenceError::ResultsHashMismatch {
            stage: TranslationCorrespondenceStage::R1S6MachineIr,
        });
    }
    Ok(())
}

fn validate_r1_s5_header(
    evidence: &R1S5CoreSsaCorrespondenceEvidence,
) -> Result<(), TranslationCorrespondenceError> {
    validate_header(
        TranslationCorrespondenceStage::R1S5CoreSsa,
        evidence.schema_version,
        R1_S5_CORE_SSA_CORRESPONDENCE_SCHEMA_VERSION,
        evidence.policy_version,
        R1_S5_CORE_SSA_CORRESPONDENCE_POLICY_VERSION,
        evidence.limits,
    )?;
    let manifest = canonical_manifest()?;
    if evidence.manifest_hash != manifest.manifest_hash {
        return Err(TranslationCorrespondenceError::CanonicalCaseMismatch {
            stage: TranslationCorrespondenceStage::R1S5CoreSsa,
            case_ordinal: 0,
            field: "manifest identity",
        });
    }
    Ok(())
}

fn validate_r1_s6_header(
    evidence: &R1S6MachineIrCorrespondenceEvidence,
) -> Result<(), TranslationCorrespondenceError> {
    validate_header(
        TranslationCorrespondenceStage::R1S6MachineIr,
        evidence.schema_version,
        R1_S6_MACHINE_IR_CORRESPONDENCE_SCHEMA_VERSION,
        evidence.policy_version,
        R1_S6_MACHINE_IR_CORRESPONDENCE_POLICY_VERSION,
        evidence.limits,
    )?;
    let manifest = canonical_manifest()?;
    if evidence.manifest_hash != manifest.manifest_hash {
        return Err(TranslationCorrespondenceError::CanonicalCaseMismatch {
            stage: TranslationCorrespondenceStage::R1S6MachineIr,
            case_ordinal: 0,
            field: "manifest identity",
        });
    }
    Ok(())
}

fn validate_header(
    stage: TranslationCorrespondenceStage,
    schema: (u16, u16, u16),
    expected_schema: (u16, u16, u16),
    policy: (u16, u16, u16),
    expected_policy: (u16, u16, u16),
    limits: TranslationCorrespondenceLimits,
) -> Result<(), TranslationCorrespondenceError> {
    if schema != expected_schema {
        return Err(TranslationCorrespondenceError::InvalidSchema {
            stage,
            actual: schema,
        });
    }
    if policy != expected_policy {
        return Err(TranslationCorrespondenceError::InvalidPolicy {
            stage,
            actual: policy,
        });
    }
    if limits != TranslationCorrespondenceLimits::r1() {
        return Err(TranslationCorrespondenceError::InvalidLimits { stage });
    }
    Ok(())
}

fn validate_r1_s5_record_shape(
    record: &R1S5CoreSsaCorrespondenceRecord,
) -> Result<(), TranslationCorrespondenceError> {
    validate_header(
        TranslationCorrespondenceStage::R1S5CoreSsa,
        record.schema_version,
        R1_S5_CORE_SSA_CORRESPONDENCE_SCHEMA_VERSION,
        record.policy_version,
        R1_S5_CORE_SSA_CORRESPONDENCE_POLICY_VERSION,
        TranslationCorrespondenceLimits::r1(),
    )?;
    validate_ordinal(
        TranslationCorrespondenceStage::R1S5CoreSsa,
        record.case_ordinal,
    )?;
    validate_observation(
        TranslationCorrespondenceStage::R1S5CoreSsa,
        "Residual Core",
        record.case_ordinal,
        &record.residual_core,
    )?;
    validate_observation(
        TranslationCorrespondenceStage::R1S5CoreSsa,
        "Core SSA",
        record.case_ordinal,
        &record.core_ssa,
    )?;
    if record.residual_core != record.core_ssa {
        return Err(TranslationCorrespondenceError::SemanticMismatch {
            stage: TranslationCorrespondenceStage::R1S5CoreSsa,
            case_ordinal: record.case_ordinal,
        });
    }
    Ok(())
}

fn validate_r1_s6_record_shape(
    record: &R1S6MachineIrCorrespondenceRecord,
) -> Result<(), TranslationCorrespondenceError> {
    validate_header(
        TranslationCorrespondenceStage::R1S6MachineIr,
        record.schema_version,
        R1_S6_MACHINE_IR_CORRESPONDENCE_SCHEMA_VERSION,
        record.policy_version,
        R1_S6_MACHINE_IR_CORRESPONDENCE_POLICY_VERSION,
        TranslationCorrespondenceLimits::r1(),
    )?;
    validate_ordinal(
        TranslationCorrespondenceStage::R1S6MachineIr,
        record.case_ordinal,
    )?;
    validate_observation(
        TranslationCorrespondenceStage::R1S6MachineIr,
        "Core SSA",
        record.case_ordinal,
        &record.core_ssa,
    )?;
    validate_observation(
        TranslationCorrespondenceStage::R1S6MachineIr,
        "Machine IR",
        record.case_ordinal,
        &record.machine_ir,
    )?;
    if record.core_ssa != record.machine_ir {
        return Err(TranslationCorrespondenceError::SemanticMismatch {
            stage: TranslationCorrespondenceStage::R1S6MachineIr,
            case_ordinal: record.case_ordinal,
        });
    }
    Ok(())
}

fn validate_r1_s5_record_against_case(
    evidence: &R1S5CoreSsaCorrespondenceEvidence,
    record: &R1S5CoreSsaCorrespondenceRecord,
    case: &CoreVmGateACase,
    expected_ordinal: u32,
) -> Result<(), TranslationCorrespondenceError> {
    validate_case_fields(
        TranslationCorrespondenceStage::R1S5CoreSsa,
        record.case_ordinal,
        record.workload,
        record.class,
        record.input_hash,
        case,
        expected_ordinal,
    )?;
    let (source_hash, ssa_hash) = match record.workload {
        CoreVmGateAWorkload::BranchMix => (
            evidence.branch_source_core_hash,
            evidence.branch_core_ssa_hash,
        ),
        CoreVmGateAWorkload::BoundsOrderedArrayGet => (
            evidence.bounds_source_core_hash,
            evidence.bounds_core_ssa_hash,
        ),
    };
    if record.source_core_hash != source_hash {
        return Err(TranslationCorrespondenceError::SourceIdentityMismatch {
            stage: TranslationCorrespondenceStage::R1S5CoreSsa,
            case_ordinal: record.case_ordinal,
            field: "Residual Core",
        });
    }
    if record.core_ssa_hash != ssa_hash {
        return Err(TranslationCorrespondenceError::SourceIdentityMismatch {
            stage: TranslationCorrespondenceStage::R1S5CoreSsa,
            case_ordinal: record.case_ordinal,
            field: "Core SSA",
        });
    }
    Ok(())
}

fn validate_r1_s6_record_against_case(
    evidence: &R1S6MachineIrCorrespondenceEvidence,
    record: &R1S6MachineIrCorrespondenceRecord,
    case: &CoreVmGateACase,
    expected_ordinal: u32,
) -> Result<(), TranslationCorrespondenceError> {
    validate_case_fields(
        TranslationCorrespondenceStage::R1S6MachineIr,
        record.case_ordinal,
        record.workload,
        record.class,
        record.input_hash,
        case,
        expected_ordinal,
    )?;
    let (core_hash, ssa_hash, machine_hash) = match record.workload {
        CoreVmGateAWorkload::BranchMix => (
            evidence.branch_source_core_hash,
            evidence.branch_source_core_ssa_hash,
            evidence.branch_machine_ir_hash,
        ),
        CoreVmGateAWorkload::BoundsOrderedArrayGet => (
            evidence.bounds_source_core_hash,
            evidence.bounds_source_core_ssa_hash,
            evidence.bounds_machine_ir_hash,
        ),
    };
    for (field, actual, expected) in [
        ("Residual Core", record.source_core_hash, core_hash),
        ("Core SSA", record.source_core_ssa_hash, ssa_hash),
        ("Machine IR", record.machine_ir_hash, machine_hash),
    ] {
        if actual != expected {
            return Err(TranslationCorrespondenceError::SourceIdentityMismatch {
                stage: TranslationCorrespondenceStage::R1S6MachineIr,
                case_ordinal: record.case_ordinal,
                field,
            });
        }
    }
    Ok(())
}

fn validate_case_fields(
    stage: TranslationCorrespondenceStage,
    record_ordinal: u32,
    workload: CoreVmGateAWorkload,
    class: CoreVmGateACaseClass,
    input_hash: SemanticHash,
    case: &CoreVmGateACase,
    expected_ordinal: u32,
) -> Result<(), TranslationCorrespondenceError> {
    if record_ordinal != expected_ordinal {
        return Err(TranslationCorrespondenceError::NonCanonicalOrdinal {
            stage,
            expected: expected_ordinal,
            actual: record_ordinal,
        });
    }
    if case.ordinal != expected_ordinal {
        return Err(TranslationCorrespondenceError::ManifestInvariant(
            "case ordinals are not exactly 0..50",
        ));
    }
    if workload != case.workload {
        return Err(TranslationCorrespondenceError::CanonicalCaseMismatch {
            stage,
            case_ordinal: record_ordinal,
            field: "workload",
        });
    }
    if class != case.class {
        return Err(TranslationCorrespondenceError::CanonicalCaseMismatch {
            stage,
            case_ordinal: record_ordinal,
            field: "class",
        });
    }
    if input_hash != case.input_hash {
        return Err(TranslationCorrespondenceError::CanonicalCaseMismatch {
            stage,
            case_ordinal: record_ordinal,
            field: "input identity",
        });
    }
    Ok(())
}

fn canonical_manifest(
) -> Result<super::corevm0_gate_a::CoreVmGateACorpusManifest, TranslationCorrespondenceError> {
    let manifest = corevm0_gate_a_manifest().map_err(TranslationCorrespondenceError::Manifest)?;
    let expected = usize::try_from(TRANSLATION_CORRESPONDENCE_TOTAL_CASES)
        .map_err(|_| TranslationCorrespondenceError::MetricOverflow)?;
    if manifest.total_cases != TRANSLATION_CORRESPONDENCE_TOTAL_CASES
        || manifest.cases.len() != expected
    {
        return Err(TranslationCorrespondenceError::ManifestInvariant(
            "case count is not exactly 51",
        ));
    }

    let mut branch_cases = 0_u32;
    let mut bounds_cases = 0_u32;
    let mut total_elements = 0_u64;
    for (index, case) in manifest.cases.iter().enumerate() {
        let ordinal =
            u32::try_from(index).map_err(|_| TranslationCorrespondenceError::MetricOverflow)?;
        if case.ordinal != ordinal {
            return Err(TranslationCorrespondenceError::ManifestInvariant(
                "case ordinals are not exactly 0..50",
            ));
        }
        let expected_workload = if ordinal < TRANSLATION_CORRESPONDENCE_BRANCH_CASES {
            CoreVmGateAWorkload::BranchMix
        } else {
            CoreVmGateAWorkload::BoundsOrderedArrayGet
        };
        if case.workload != expected_workload {
            return Err(TranslationCorrespondenceError::ManifestInvariant(
                "workloads are not exactly 46 BranchMix followed by five Bounds cases",
            ));
        }
        if corevm0_gate_a_case_input_hash(case).map_err(TranslationCorrespondenceError::Manifest)?
            != case.input_hash
        {
            return Err(TranslationCorrespondenceError::ManifestInvariant(
                "a case input seal is not canonical",
            ));
        }
        let element_count = u32::try_from(case.input.array_f64_bits.len())
            .map_err(|_| TranslationCorrespondenceError::MetricOverflow)?;
        if element_count > COREVM0_GATE_A_MAX_ARRAY_ELEMENTS_PER_CASE {
            return Err(TranslationCorrespondenceError::ManifestInvariant(
                "a case exceeds the fixed array-element cap",
            ));
        }
        total_elements = total_elements
            .checked_add(u64::from(element_count))
            .ok_or(TranslationCorrespondenceError::MetricOverflow)?;
        match case.workload {
            CoreVmGateAWorkload::BranchMix => {
                branch_cases = branch_cases
                    .checked_add(1)
                    .ok_or(TranslationCorrespondenceError::MetricOverflow)?;
            }
            CoreVmGateAWorkload::BoundsOrderedArrayGet => {
                bounds_cases = bounds_cases
                    .checked_add(1)
                    .ok_or(TranslationCorrespondenceError::MetricOverflow)?;
            }
        }
    }
    if branch_cases != TRANSLATION_CORRESPONDENCE_BRANCH_CASES
        || bounds_cases != TRANSLATION_CORRESPONDENCE_BOUNDS_CASES
    {
        return Err(TranslationCorrespondenceError::ManifestInvariant(
            "workload split is not exactly 46 BranchMix plus five Bounds",
        ));
    }
    if total_elements != manifest.total_array_elements
        || total_elements > COREVM0_GATE_A_MAX_TOTAL_ARRAY_ELEMENTS
    {
        return Err(TranslationCorrespondenceError::ManifestInvariant(
            "total array-element usage is not canonical",
        ));
    }
    Ok(manifest)
}

fn validate_record_count(
    stage: TranslationCorrespondenceStage,
    count: usize,
) -> Result<(), TranslationCorrespondenceError> {
    let actual =
        u32::try_from(count).map_err(|_| TranslationCorrespondenceError::MetricOverflow)?;
    if actual != TRANSLATION_CORRESPONDENCE_TOTAL_CASES {
        return Err(TranslationCorrespondenceError::RecordCount {
            stage,
            expected: TRANSLATION_CORRESPONDENCE_TOTAL_CASES,
            actual,
        });
    }
    Ok(())
}

fn validate_ordinal(
    stage: TranslationCorrespondenceStage,
    ordinal: u32,
) -> Result<(), TranslationCorrespondenceError> {
    if ordinal >= TRANSLATION_CORRESPONDENCE_TOTAL_CASES {
        return Err(TranslationCorrespondenceError::NonCanonicalOrdinal {
            stage,
            expected: TRANSLATION_CORRESPONDENCE_TOTAL_CASES - 1,
            actual: ordinal,
        });
    }
    Ok(())
}

fn case_arguments(case: &CoreVmGateACase) -> Vec<CoreValue> {
    let values = case
        .input
        .array_f64_bits
        .iter()
        .copied()
        .map(f64::from_bits)
        .collect::<Vec<_>>();
    let mut arguments = vec![CoreValue::array_f64(values)];
    if case.workload == CoreVmGateAWorkload::BranchMix {
        arguments.push(CoreValue::I64(case.input.repetitions));
    }
    arguments
}

fn machine_ir_hash_for_workload(
    workload: CoreVmGateAWorkload,
    branch: &MachineIrArtifact,
    bounds: &MachineIrArtifact,
) -> SemanticHash {
    match workload {
        CoreVmGateAWorkload::BranchMix => branch.semantic_hash,
        CoreVmGateAWorkload::BoundsOrderedArrayGet => bounds.semantic_hash,
    }
}

fn accumulate_steps(
    stage: TranslationCorrespondenceStage,
    engine: &'static str,
    total: &mut u64,
    steps: u64,
    limits: TranslationCorrespondenceLimits,
) -> Result<(), TranslationCorrespondenceError> {
    if steps > limits.steps_per_case {
        return Err(TranslationCorrespondenceError::ExecutionCapExceeded {
            stage,
            engine,
            limit: limits.steps_per_case,
            actual: steps,
        });
    }
    *total = total
        .checked_add(steps)
        .ok_or(TranslationCorrespondenceError::MetricOverflow)?;
    if *total > limits.max_total_steps_per_engine {
        return Err(TranslationCorrespondenceError::ExecutionCapExceeded {
            stage,
            engine,
            limit: limits.max_total_steps_per_engine,
            actual: *total,
        });
    }
    Ok(())
}

fn normalize_observation(
    stage: TranslationCorrespondenceStage,
    engine: &'static str,
    case_ordinal: u32,
    evaluation: &Evaluation,
) -> Result<TranslationCorrespondenceObservation, TranslationCorrespondenceError> {
    let outcome = match &evaluation.outcome {
        EvaluationOutcome::Return(CoreValue::F64(value)) if value.is_nan() => {
            TranslationCorrespondenceOutcome::ReturnF64(TranslationCorrespondenceF64::CanonicalNaN)
        }
        EvaluationOutcome::Return(CoreValue::F64(value)) => {
            TranslationCorrespondenceOutcome::ReturnF64(TranslationCorrespondenceF64::ExactBits(
                value.to_bits(),
            ))
        }
        EvaluationOutcome::Error(ErrorKind::Bounds) => TranslationCorrespondenceOutcome::Bounds,
        _ => {
            return Err(TranslationCorrespondenceError::UnsupportedOutcome {
                stage,
                engine,
                case_ordinal,
            });
        }
    };
    let effect_count = u32::try_from(evaluation.effect_trace.len())
        .map_err(|_| TranslationCorrespondenceError::MetricOverflow)?;
    if effect_count > TRANSLATION_CORRESPONDENCE_MAX_EFFECTS_PER_OBSERVATION {
        return Err(TranslationCorrespondenceError::EffectLimit {
            stage,
            engine,
            case_ordinal,
            limit: TRANSLATION_CORRESPONDENCE_MAX_EFFECTS_PER_OBSERVATION,
            actual: effect_count,
        });
    }
    let effect_trace = evaluation
        .effect_trace
        .iter()
        .map(|effect| match effect {
            EffectEvent::Error(ErrorKind::Bounds) => Ok(TranslationCorrespondenceEffect::Bounds),
            _ => Err(TranslationCorrespondenceError::UnsupportedEffect {
                stage,
                engine,
                case_ordinal,
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let observation = TranslationCorrespondenceObservation {
        outcome,
        effect_trace,
    };
    validate_observation(stage, engine, case_ordinal, &observation)?;
    Ok(observation)
}

fn validate_observation(
    stage: TranslationCorrespondenceStage,
    engine: &'static str,
    case_ordinal: u32,
    observation: &TranslationCorrespondenceObservation,
) -> Result<(), TranslationCorrespondenceError> {
    let effect_count = u32::try_from(observation.effect_trace.len())
        .map_err(|_| TranslationCorrespondenceError::MetricOverflow)?;
    if effect_count > TRANSLATION_CORRESPONDENCE_MAX_EFFECTS_PER_OBSERVATION {
        return Err(TranslationCorrespondenceError::EffectLimit {
            stage,
            engine,
            case_ordinal,
            limit: TRANSLATION_CORRESPONDENCE_MAX_EFFECTS_PER_OBSERVATION,
            actual: effect_count,
        });
    }
    let canonical = match observation.outcome {
        TranslationCorrespondenceOutcome::ReturnF64(TranslationCorrespondenceF64::ExactBits(
            bits,
        )) => !f64::from_bits(bits).is_nan() && observation.effect_trace.is_empty(),
        TranslationCorrespondenceOutcome::ReturnF64(TranslationCorrespondenceF64::CanonicalNaN) => {
            observation.effect_trace.is_empty()
        }
        TranslationCorrespondenceOutcome::Bounds => {
            observation.effect_trace == [TranslationCorrespondenceEffect::Bounds]
        }
    };
    if !canonical {
        return Err(TranslationCorrespondenceError::NonCanonicalObservation {
            stage,
            engine,
            case_ordinal,
        });
    }
    Ok(())
}

fn put_observation(
    bytes: &mut Vec<u8>,
    observation: &TranslationCorrespondenceObservation,
) -> Result<(), TranslationCorrespondenceError> {
    match observation.outcome {
        TranslationCorrespondenceOutcome::ReturnF64(TranslationCorrespondenceF64::ExactBits(
            bits,
        )) => {
            bytes.push(0);
            put_u64(bytes, bits);
        }
        TranslationCorrespondenceOutcome::ReturnF64(TranslationCorrespondenceF64::CanonicalNaN) => {
            bytes.push(1)
        }
        TranslationCorrespondenceOutcome::Bounds => bytes.push(2),
    }
    let effect_count = u32::try_from(observation.effect_trace.len())
        .map_err(|_| TranslationCorrespondenceError::MetricOverflow)?;
    put_u32(bytes, effect_count);
    for effect in &observation.effect_trace {
        bytes.push(match effect {
            TranslationCorrespondenceEffect::Bounds => 0,
        });
    }
    Ok(())
}

fn put_limits(bytes: &mut Vec<u8>, limits: TranslationCorrespondenceLimits) {
    put_u32(bytes, limits.total_cases);
    put_u32(bytes, limits.branch_cases);
    put_u32(bytes, limits.bounds_cases);
    put_u32(bytes, limits.max_array_elements_per_case);
    put_u64(bytes, limits.max_total_array_elements);
    put_u32(bytes, limits.max_effects_per_observation);
    put_u64(bytes, limits.steps_per_case);
    put_u32(bytes, limits.call_depth);
    put_u64(bytes, limits.max_total_steps_per_engine);
}

fn put_workload(bytes: &mut Vec<u8>, workload: CoreVmGateAWorkload) {
    bytes.push(match workload {
        CoreVmGateAWorkload::BranchMix => 0,
        CoreVmGateAWorkload::BoundsOrderedArrayGet => 1,
    });
}

fn put_class(bytes: &mut Vec<u8>, class: CoreVmGateACaseClass) {
    bytes.push(match class {
        CoreVmGateACaseClass::Edge => 0,
        CoreVmGateACaseClass::BoundedExhaustive => 1,
        CoreVmGateACaseClass::DeterministicGenerated => 2,
        CoreVmGateACaseClass::BoundsEffect => 3,
    });
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::x64_native_lighthouse::X64NativeLighthousePackage;

    fn hash(byte: u8) -> SemanticHash {
        SemanticHash([byte; 32])
    }

    fn exact_zero() -> TranslationCorrespondenceObservation {
        TranslationCorrespondenceObservation {
            outcome: TranslationCorrespondenceOutcome::ReturnF64(
                TranslationCorrespondenceF64::ExactBits(0),
            ),
            effect_trace: vec![],
        }
    }

    fn s5_fixture() -> R1S5CoreSsaCorrespondenceEvidence {
        let manifest = canonical_manifest().expect("fixed manifest");
        let mut evidence = R1S5CoreSsaCorrespondenceEvidence {
            schema_version: R1_S5_CORE_SSA_CORRESPONDENCE_SCHEMA_VERSION,
            policy_version: R1_S5_CORE_SSA_CORRESPONDENCE_POLICY_VERSION,
            limits: TranslationCorrespondenceLimits::r1(),
            manifest_hash: manifest.manifest_hash,
            branch_source_core_hash: hash(1),
            branch_core_ssa_hash: hash(2),
            bounds_source_core_hash: hash(3),
            bounds_core_ssa_hash: hash(4),
            records: Vec::new(),
            results_hash: SemanticHash::ZERO,
        };
        for case in &manifest.cases {
            let (source_core_hash, core_ssa_hash) = match case.workload {
                CoreVmGateAWorkload::BranchMix => (hash(1), hash(2)),
                CoreVmGateAWorkload::BoundsOrderedArrayGet => (hash(3), hash(4)),
            };
            let mut record = R1S5CoreSsaCorrespondenceRecord {
                schema_version: R1_S5_CORE_SSA_CORRESPONDENCE_SCHEMA_VERSION,
                policy_version: R1_S5_CORE_SSA_CORRESPONDENCE_POLICY_VERSION,
                case_ordinal: case.ordinal,
                workload: case.workload,
                class: case.class,
                input_hash: case.input_hash,
                source_core_hash,
                core_ssa_hash,
                residual_core: exact_zero(),
                core_ssa: exact_zero(),
                record_hash: SemanticHash::ZERO,
            };
            record.record_hash =
                r1_s5_core_ssa_correspondence_record_hash(&record).expect("record hash");
            evidence.records.push(record);
        }
        evidence.results_hash =
            r1_s5_core_ssa_correspondence_results_hash(&evidence).expect("results hash");
        evidence
    }

    fn s6_fixture() -> R1S6MachineIrCorrespondenceEvidence {
        let manifest = canonical_manifest().expect("fixed manifest");
        let mut evidence = R1S6MachineIrCorrespondenceEvidence {
            schema_version: R1_S6_MACHINE_IR_CORRESPONDENCE_SCHEMA_VERSION,
            policy_version: R1_S6_MACHINE_IR_CORRESPONDENCE_POLICY_VERSION,
            limits: TranslationCorrespondenceLimits::r1(),
            manifest_hash: manifest.manifest_hash,
            branch_source_core_hash: hash(1),
            branch_source_core_ssa_hash: hash(2),
            branch_machine_ir_hash: hash(3),
            bounds_source_core_hash: hash(4),
            bounds_source_core_ssa_hash: hash(5),
            bounds_machine_ir_hash: hash(6),
            records: Vec::new(),
            results_hash: SemanticHash::ZERO,
        };
        for case in &manifest.cases {
            let (source_core_hash, source_core_ssa_hash, machine_ir_hash) = match case.workload {
                CoreVmGateAWorkload::BranchMix => (hash(1), hash(2), hash(3)),
                CoreVmGateAWorkload::BoundsOrderedArrayGet => (hash(4), hash(5), hash(6)),
            };
            let mut record = R1S6MachineIrCorrespondenceRecord {
                schema_version: R1_S6_MACHINE_IR_CORRESPONDENCE_SCHEMA_VERSION,
                policy_version: R1_S6_MACHINE_IR_CORRESPONDENCE_POLICY_VERSION,
                case_ordinal: case.ordinal,
                workload: case.workload,
                class: case.class,
                input_hash: case.input_hash,
                source_core_hash,
                source_core_ssa_hash,
                machine_ir_hash,
                core_ssa: exact_zero(),
                machine_ir: exact_zero(),
                record_hash: SemanticHash::ZERO,
            };
            record.record_hash =
                r1_s6_machine_ir_correspondence_record_hash(&record).expect("record hash");
            evidence.records.push(record);
        }
        evidence.results_hash =
            r1_s6_machine_ir_correspondence_results_hash(&evidence).expect("results hash");
        evidence
    }

    #[test]
    fn aggregate_roots_are_stage_separated_deterministic_and_order_sensitive() {
        let first_s5 = s5_fixture();
        let second_s5 = s5_fixture();
        let s6 = s6_fixture();
        assert_eq!(first_s5.results_hash, second_s5.results_hash);
        assert_ne!(first_s5.results_hash, s6.results_hash);
        assert_eq!(
            first_s5.results_hash,
            SemanticHash([
                251, 68, 212, 248, 5, 216, 158, 29, 198, 233, 158, 194, 121, 248, 173, 123, 178,
                214, 65, 40, 189, 253, 174, 2, 49, 233, 66, 44, 77, 69, 113, 156,
            ])
        );
        assert_eq!(
            s6.results_hash,
            SemanticHash([
                199, 79, 80, 104, 251, 183, 215, 139, 181, 215, 64, 195, 190, 255, 95, 9, 168, 200,
                164, 168, 221, 171, 0, 237, 129, 30, 55, 252, 97, 211, 234, 17,
            ])
        );

        let mut reordered = first_s5;
        reordered.records.swap(0, 1);
        assert!(matches!(
            r1_s5_core_ssa_correspondence_results_hash(&reordered),
            Err(TranslationCorrespondenceError::NonCanonicalOrdinal { .. })
        ));
    }

    #[test]
    fn all_nested_fields_are_sealed_and_nan_bits_must_be_canonical() {
        let mut s5 = s5_fixture();
        s5.records[0].input_hash.0[0] ^= 1;
        assert!(matches!(
            r1_s5_core_ssa_correspondence_results_hash(&s5),
            Err(TranslationCorrespondenceError::CanonicalCaseMismatch { .. })
                | Err(TranslationCorrespondenceError::RecordHashMismatch { .. })
        ));

        let mut s6 = s6_fixture();
        s6.records[0].machine_ir.outcome = TranslationCorrespondenceOutcome::ReturnF64(
            TranslationCorrespondenceF64::ExactBits(0x7ff8_0000_0000_0001),
        );
        assert!(matches!(
            r1_s6_machine_ir_correspondence_record_hash(&s6.records[0]),
            Err(TranslationCorrespondenceError::NonCanonicalObservation { .. })
        ));
    }

    #[test]
    fn exact_limits_and_exact_51_case_split_are_locked() {
        let evidence = s5_fixture();
        assert_eq!(evidence.records.len(), 51);
        assert_eq!(
            evidence
                .records
                .iter()
                .filter(|record| record.workload == CoreVmGateAWorkload::BranchMix)
                .count(),
            46
        );
        assert_eq!(
            evidence
                .records
                .iter()
                .filter(|record| { record.workload == CoreVmGateAWorkload::BoundsOrderedArrayGet })
                .count(),
            5
        );

        let mut widened = evidence;
        widened.limits.steps_per_case += 1;
        assert!(matches!(
            r1_s5_core_ssa_correspondence_results_hash(&widened),
            Err(TranslationCorrespondenceError::InvalidLimits { .. })
        ));
    }

    #[test]
    fn real_lighthouse_chains_emit_and_fully_replay_both_evidence_lines() {
        let branch = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BranchMix)
            .expect("branch package");
        let bounds = X64NativeLighthousePackage::build(CoreVmGateAWorkload::BoundsOrderedArrayGet)
            .expect("Bounds package");

        let s5 = emit_r1_s5_core_ssa_correspondence(
            branch.residual(),
            branch.ssa(),
            bounds.residual(),
            bounds.ssa(),
        )
        .expect("S5 evidence");
        let verified_s5 = verify_r1_s5_core_ssa_correspondence(
            branch.residual(),
            branch.ssa(),
            bounds.residual(),
            bounds.ssa(),
            &s5,
        )
        .expect("S5 full replay");
        assert_eq!(verified_s5.results_hash(), s5.results_hash);
        assert_eq!(verified_s5.evidence().records.len(), 51);

        let s6 = emit_r1_s6_machine_ir_correspondence(
            branch.residual(),
            branch.ssa(),
            branch.machine_ir(),
            bounds.residual(),
            bounds.ssa(),
            bounds.machine_ir(),
        )
        .expect("S6 evidence");
        let verified_s6 = verify_r1_s6_machine_ir_correspondence(
            branch.residual(),
            branch.ssa(),
            branch.machine_ir(),
            bounds.residual(),
            bounds.ssa(),
            bounds.machine_ir(),
            &s6,
        )
        .expect("S6 full replay");
        assert_eq!(verified_s6.results_hash(), s6.results_hash);
        assert_eq!(verified_s6.evidence().records.len(), 51);
        assert_ne!(verified_s5.results_hash(), verified_s6.results_hash());
        assert_eq!(
            verified_s5.results_hash(),
            SemanticHash([
                24, 219, 3, 71, 9, 77, 250, 208, 0, 231, 166, 64, 28, 209, 217, 137, 237, 213, 127,
                68, 189, 11, 49, 169, 84, 77, 128, 243, 128, 59, 165, 139,
            ])
        );
        assert_eq!(
            verified_s6.results_hash(),
            SemanticHash([
                60, 199, 203, 216, 118, 83, 30, 166, 248, 140, 86, 245, 12, 133, 30, 177, 104, 172,
                118, 175, 226, 217, 160, 90, 230, 131, 86, 135, 191, 65, 18, 5,
            ])
        );

        // Exposed hashes can be recomputed by an attacker. Only complete
        // deterministic source replay can mint the opaque authority.
        let mut fully_resealed = s5.clone();
        let fabricated = TranslationCorrespondenceObservation {
            outcome: TranslationCorrespondenceOutcome::ReturnF64(
                TranslationCorrespondenceF64::ExactBits(1),
            ),
            effect_trace: vec![],
        };
        fully_resealed.records[0].residual_core = fabricated.clone();
        fully_resealed.records[0].core_ssa = fabricated;
        fully_resealed.records[0].record_hash =
            r1_s5_core_ssa_correspondence_record_hash(&fully_resealed.records[0])
                .expect("fabricated record can be structurally resealed");
        fully_resealed.results_hash = r1_s5_core_ssa_correspondence_results_hash(&fully_resealed)
            .expect("fabricated aggregate can be structurally resealed");
        assert!(matches!(
            verify_r1_s5_core_ssa_correspondence(
                branch.residual(),
                branch.ssa(),
                bounds.residual(),
                bounds.ssa(),
                &fully_resealed,
            ),
            Err(TranslationCorrespondenceError::EvidenceMismatch {
                stage: TranslationCorrespondenceStage::R1S5CoreSsa,
            })
        ));
    }
}
