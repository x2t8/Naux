//! Bounded Surface-to-native differential carrier for Scope 3.
//!
//! This module deliberately lives outside `crate::core`: Surface parsing and
//! runtime values are bridge concerns and must not become dependencies of the
//! canonical Core semantic nucleus. Every behavior-changing backend boundary
//! is replayed through its source-bound verifier before the result is admitted.

use crate::core::encoding::sha256;
use crate::core::{
    evaluate, evaluate_core_ssa_translation, evaluate_machine_ir_translation,
    evaluate_x64_target_translation, execute_x64_native_r1_s7b, lower_core_ssa_r1_s5,
    lower_machine_ir_r1_s6, lower_x64_target_r1_s7a, verify_x64_target_source, Evaluation,
    EvaluationBudget, EvaluationOutcome, SemanticHash, X64TargetAbi,
};
use crate::elaboration::{
    bind_surface_t2a_inputs, elaborate_surface_t2a, normalize_core_scalar,
    normalize_surface_scalar, ElaborationBudget, NormalizedScalar, SurfaceInput, SurfaceScalarType,
    SurfaceScalarValue, T2A_MAX_CORE_NODES, T2A_MAX_SOURCE_STEPS,
};
use crate::runtime::budget::ExecutionLimits;
use crate::runtime::eval::eval_script_with_bindings_and_limits;
use crate::{lexer, parser};
use std::fmt;

pub const SURFACE_NATIVE_T1_SCHEMA_VERSION: (u16, u16, u16) = (0, 1, 0);
pub const SURFACE_NATIVE_T1_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const SURFACE_NATIVE_T1_CASES: usize = 12;
pub const SURFACE_NATIVE_T1_MAX_EXECUTION_STEPS: u64 = 10_000;
pub const SURFACE_NATIVE_T1_MAX_CALL_DEPTH: u32 = 64;
pub const SURFACE_NATIVE_T1_RESULT: &str = "result";
pub const SURFACE_NATIVE_T1_SOURCE: &str = "$base = $x + $offset\n\
~ if $flag\n\
    $result = $base + $delta\n\
~ else\n\
    $result = $base - $delta\n\
~ end\n\
$result = $result + $tail\n";

const SOURCE_DOMAIN: &[u8] = b"NAUX:thesis:surface-native-t1:source:v1\0";
const REQUEST_DOMAIN: &[u8] = b"NAUX:thesis:surface-native-t1:request:v1\0";
const CASE_DOMAIN: &[u8] = b"NAUX:thesis:surface-native-t1:case:v1\0";
const CORPUS_DOMAIN: &[u8] = b"NAUX:thesis:surface-native-t1:corpus:v1\0";
const RECORD_DOMAIN: &[u8] = b"NAUX:thesis:surface-native-t1:record:v1\0";
const RESULTS_DOMAIN: &[u8] = b"NAUX:thesis:surface-native-t1:results:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:thesis:surface-native-t1:evidence:v1\0";
const REPORT_DOMAIN: &[u8] = b"NAUX:thesis:surface-native-t1:report:v1\0";

#[derive(Clone, Debug, PartialEq)]
pub struct SurfaceNativeT1Case {
    pub ordinal: u32,
    pub name: &'static str,
    pub arguments: Vec<SurfaceScalarValue>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SurfaceNativeT1Record {
    pub ordinal: u32,
    pub name: &'static str,
    pub input_hash: SemanticHash,
    pub surface: NormalizedScalar,
    pub core: NormalizedScalar,
    pub ssa: NormalizedScalar,
    pub machine_ir: NormalizedScalar,
    pub target_plan: NormalizedScalar,
    pub native: NormalizedScalar,
    pub record_hash: SemanticHash,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SurfaceNativeT1Evidence {
    pub schema_version: (u16, u16, u16),
    pub policy_version: (u16, u16, u16),
    pub source_hash: SemanticHash,
    pub request_hash: SemanticHash,
    pub corpus_hash: SemanticHash,
    pub core_hash: SemanticHash,
    pub ssa_hash: SemanticHash,
    pub machine_ir_hash: SemanticHash,
    pub target_hash: SemanticHash,
    pub target_plan_hash: SemanticHash,
    pub target_code_hash: SemanticHash,
    pub records: Vec<SurfaceNativeT1Record>,
    pub results_hash: SemanticHash,
    pub evidence_hash: SemanticHash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceNativeT1Stage {
    Lex,
    Parse,
    Elaborate,
    Bind,
    Surface,
    Core,
    SsaLower,
    Ssa,
    MachineIrLower,
    MachineIr,
    TargetLower,
    TargetPlan,
    Native,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SurfaceNativeT1Error {
    UnsupportedHost,
    Stage {
        stage: SurfaceNativeT1Stage,
        case_ordinal: Option<u32>,
        message: String,
    },
    MissingSurfaceResult {
        case_ordinal: u32,
    },
    ObservableEffects {
        stage: SurfaceNativeT1Stage,
        case_ordinal: u32,
    },
    SemanticMismatch {
        case_ordinal: u32,
        stage: SurfaceNativeT1Stage,
        expected: NormalizedScalar,
        actual: NormalizedScalar,
    },
    NativeFallback {
        case_ordinal: u32,
    },
    NativeIdentityMismatch {
        case_ordinal: u32,
        field: &'static str,
    },
    EvidenceMismatch,
}

impl fmt::Display for SurfaceNativeT1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost => formatter.write_str(
                "Surface-native T1 requires the admitted Linux x86-64 native runner",
            ),
            Self::Stage {
                stage,
                case_ordinal,
                message,
            } => match case_ordinal {
                Some(case) => write!(formatter, "{stage:?} failed in T1 case {case}: {message}"),
                None => write!(formatter, "{stage:?} failed before T1 execution: {message}"),
            },
            Self::MissingSurfaceResult { case_ordinal } => {
                write!(formatter, "Surface T1 case {case_ordinal} did not bind `$result`")
            }
            Self::ObservableEffects {
                stage,
                case_ordinal,
            } => write!(
                formatter,
                "{stage:?} produced effects in pure Surface T1 case {case_ordinal}"
            ),
            Self::SemanticMismatch {
                case_ordinal,
                stage,
                expected,
                actual,
            } => write!(
                formatter,
                "{stage:?} differs in Surface T1 case {case_ordinal}: expected {expected:?}, found {actual:?}"
            ),
            Self::NativeFallback { case_ordinal } => {
                write!(formatter, "native T1 case {case_ordinal} reported fallback")
            }
            Self::NativeIdentityMismatch {
                case_ordinal,
                field,
            } => write!(
                formatter,
                "native T1 case {case_ordinal} did not preserve `{field}` identity"
            ),
            Self::EvidenceMismatch => formatter.write_str(
                "Surface-native T1 evidence differs from exact regenerative replay",
            ),
        }
    }
}

impl std::error::Error for SurfaceNativeT1Error {}

pub fn canonical_surface_native_t1_inputs() -> Vec<SurfaceInput> {
    vec![
        surface_input("x", SurfaceScalarType::F64),
        surface_input("offset", SurfaceScalarType::F64),
        surface_input("flag", SurfaceScalarType::Bool),
        surface_input("delta", SurfaceScalarType::F64),
        surface_input("tail", SurfaceScalarType::F64),
    ]
}

pub fn canonical_surface_native_t1_cases() -> Vec<SurfaceNativeT1Case> {
    use SurfaceScalarValue::{Bool, F64};

    let rows = [
        ("positive-then", 10.0, 0.25, true, 3.5, 0.125),
        ("positive-else", 10.0, 0.25, false, 3.5, 0.125),
        ("negative-then", -17.0, 2.0, true, 0.5, -4.0),
        ("negative-else", -17.0, 2.0, false, 0.5, -4.0),
        ("signed-zero", -0.0, -0.0, true, 0.0, -0.0),
        (
            "positive-subnormal",
            f64::MIN_POSITIVE / 2.0,
            0.0,
            true,
            0.0,
            0.0,
        ),
        ("positive-overflow", f64::MAX, f64::MAX, true, 0.0, 0.0),
        ("positive-infinity", f64::INFINITY, 1.0, false, 2.0, 3.0),
        ("negative-infinity", f64::NEG_INFINITY, -1.0, true, 2.0, 3.0),
        (
            "canonical-nan",
            f64::from_bits(0x7ff8_0000_0000_0000),
            1.0,
            true,
            2.0,
            3.0,
        ),
        (
            "noncanonical-nan",
            f64::from_bits(0x7ff8_0000_0000_0042),
            1.0,
            false,
            2.0,
            3.0,
        ),
        ("cancellation", 1.0e16, 1.0, true, -1.0e16, 1.0),
    ];
    rows.into_iter()
        .enumerate()
        .map(
            |(ordinal, (name, x, offset, flag, delta, tail))| SurfaceNativeT1Case {
                ordinal: ordinal as u32,
                name,
                arguments: vec![F64(x), F64(offset), Bool(flag), F64(delta), F64(tail)],
            },
        )
        .collect()
}

/// Emit the exact first Scope-3 Surface-to-native carrier.
///
/// There is no generic-source escape hatch: this slice is intentionally fixed
/// to one versioned source program, manifest, corpus, budget, and Linux x86-64
/// native authority.
pub fn emit_surface_native_t1() -> Result<SurfaceNativeT1Evidence, SurfaceNativeT1Error> {
    if !cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        return Err(SurfaceNativeT1Error::UnsupportedHost);
    }

    let tokens = lexer::lex(SURFACE_NATIVE_T1_SOURCE)
        .map_err(|error| stage(SurfaceNativeT1Stage::Lex, None, error))?;
    let statements = parser::parse_script(&tokens)
        .map_err(|error| stage(SurfaceNativeT1Stage::Parse, None, error))?;
    let inputs = canonical_surface_native_t1_inputs();
    let report = elaborate_surface_t2a(
        &statements,
        &inputs,
        SURFACE_NATIVE_T1_RESULT,
        ElaborationBudget::new(T2A_MAX_SOURCE_STEPS, T2A_MAX_CORE_NODES),
    )
    .map_err(|error| stage(SurfaceNativeT1Stage::Elaborate, None, error))?;
    let core = &report.artifact;
    let ssa = lower_core_ssa_r1_s5(core)
        .map_err(|error| stage(SurfaceNativeT1Stage::SsaLower, None, error))?;
    let machine_ir = lower_machine_ir_r1_s6(&ssa, core)
        .map_err(|error| stage(SurfaceNativeT1Stage::MachineIrLower, None, error))?;
    let target = lower_x64_target_r1_s7a(&machine_ir, &ssa, core)
        .map_err(|error| stage(SurfaceNativeT1Stage::TargetLower, None, error))?;

    let source_hash = hash_domain(SOURCE_DOMAIN, SURFACE_NATIVE_T1_SOURCE.as_bytes());
    let request_hash = surface_native_t1_request_hash(source_hash, &inputs);
    let cases = canonical_surface_native_t1_cases();
    let corpus_hash = surface_native_t1_corpus_hash(&cases);
    let mut records = Vec::with_capacity(cases.len());
    for case in &cases {
        let bound = bind_surface_t2a_inputs(&report, &case.arguments)
            .map_err(|error| stage(SurfaceNativeT1Stage::Bind, Some(case.ordinal), error))?;
        let surface_limits = ExecutionLimits {
            max_work: SURFACE_NATIVE_T1_MAX_EXECUTION_STEPS,
            max_call_depth: SURFACE_NATIVE_T1_MAX_CALL_DEPTH as usize,
        };
        let (surface_env, _surface_events, surface_errors) = eval_script_with_bindings_and_limits(
            &statements,
            &bound.surface_bindings,
            surface_limits,
        );
        if !surface_errors.is_empty() {
            return Err(SurfaceNativeT1Error::Stage {
                stage: SurfaceNativeT1Stage::Surface,
                case_ordinal: Some(case.ordinal),
                message: format!("Surface oracle produced {} error(s)", surface_errors.len()),
            });
        }
        let surface_value = surface_env.get(SURFACE_NATIVE_T1_RESULT).ok_or(
            SurfaceNativeT1Error::MissingSurfaceResult {
                case_ordinal: case.ordinal,
            },
        )?;
        let surface = normalize_surface_scalar(&surface_value)
            .map_err(|error| stage(SurfaceNativeT1Stage::Surface, Some(case.ordinal), error))?;

        let core_evaluation = evaluate(
            core,
            bound.core_arguments.clone(),
            surface_native_t1_evaluation_budget(),
        )
        .map_err(|error| stage(SurfaceNativeT1Stage::Core, Some(case.ordinal), error))?;
        let core_result =
            normalize_evaluation(SurfaceNativeT1Stage::Core, case.ordinal, &core_evaluation)?;
        require_match(
            case.ordinal,
            SurfaceNativeT1Stage::Core,
            surface,
            core_result,
        )?;

        let ssa_evaluation = evaluate_core_ssa_translation(
            &ssa,
            core,
            bound.core_arguments.clone(),
            surface_native_t1_evaluation_budget(),
        )
        .map_err(|error| stage(SurfaceNativeT1Stage::Ssa, Some(case.ordinal), error))?;
        let ssa_result =
            normalize_evaluation(SurfaceNativeT1Stage::Ssa, case.ordinal, &ssa_evaluation)?;
        require_match(case.ordinal, SurfaceNativeT1Stage::Ssa, surface, ssa_result)?;

        let machine_evaluation = evaluate_machine_ir_translation(
            &machine_ir,
            &ssa,
            core,
            bound.core_arguments.clone(),
            surface_native_t1_evaluation_budget(),
        )
        .map_err(|error| stage(SurfaceNativeT1Stage::MachineIr, Some(case.ordinal), error))?;
        let machine_result = normalize_evaluation(
            SurfaceNativeT1Stage::MachineIr,
            case.ordinal,
            &machine_evaluation,
        )?;
        require_match(
            case.ordinal,
            SurfaceNativeT1Stage::MachineIr,
            surface,
            machine_result,
        )?;

        let target_evaluation = evaluate_x64_target_translation(
            &target,
            &machine_ir,
            &ssa,
            core,
            bound.core_arguments.clone(),
            surface_native_t1_evaluation_budget(),
        )
        .map_err(|error| stage(SurfaceNativeT1Stage::TargetPlan, Some(case.ordinal), error))?;
        let target_result = normalize_evaluation(
            SurfaceNativeT1Stage::TargetPlan,
            case.ordinal,
            &target_evaluation,
        )?;
        require_match(
            case.ordinal,
            SurfaceNativeT1Stage::TargetPlan,
            surface,
            target_result,
        )?;

        let source_bound = verify_x64_target_source(&target, &machine_ir, &ssa, core)
            .map_err(|error| stage(SurfaceNativeT1Stage::Native, Some(case.ordinal), error))?;
        let native_execution = execute_x64_native_r1_s7b(source_bound, &bound.core_arguments)
            .map_err(|error| stage(SurfaceNativeT1Stage::Native, Some(case.ordinal), error))?;
        if native_execution.fallback() {
            return Err(SurfaceNativeT1Error::NativeFallback {
                case_ordinal: case.ordinal,
            });
        }
        const MXCSR_STATUS_FLAGS: u32 = 0x3f;
        let canonical_mxcsr = X64TargetAbi::r1_s7a().canonical_mxcsr;
        let mxcsr_before = native_execution.mxcsr_before();
        if mxcsr_before & !MXCSR_STATUS_FLAGS != canonical_mxcsr & !MXCSR_STATUS_FLAGS
            || native_execution.mxcsr_after() != mxcsr_before
        {
            return Err(SurfaceNativeT1Error::NativeIdentityMismatch {
                case_ordinal: case.ordinal,
                field: "canonical MXCSR control and restored status",
            });
        }
        if native_execution.input_lanes() != inputs.len() as u8 {
            return Err(SurfaceNativeT1Error::NativeIdentityMismatch {
                case_ordinal: case.ordinal,
                field: "five-lane entry ABI",
            });
        }
        for (field, actual, expected) in [
            (
                "target artifact hash",
                native_execution.target_artifact_hash(),
                target.semantic_hash,
            ),
            (
                "target plan hash",
                native_execution.target_plan_hash(),
                target.program.plan_hash,
            ),
            (
                "source Machine IR hash",
                native_execution.source_machine_ir_hash(),
                machine_ir.semantic_hash,
            ),
            (
                "verified code hash",
                native_execution.verified_code_hash(),
                target.program.code_hash,
            ),
            (
                "copied RW code hash",
                native_execution.copied_rw_code_hash(),
                target.program.code_hash,
            ),
            (
                "readback RX code hash",
                native_execution.readback_rx_code_hash(),
                target.program.code_hash,
            ),
        ] {
            if actual != expected {
                return Err(SurfaceNativeT1Error::NativeIdentityMismatch {
                    case_ordinal: case.ordinal,
                    field,
                });
            }
        }
        if !native_execution.effect_trace().is_empty() {
            return Err(SurfaceNativeT1Error::ObservableEffects {
                stage: SurfaceNativeT1Stage::Native,
                case_ordinal: case.ordinal,
            });
        }
        let native_result = normalize_outcome(
            SurfaceNativeT1Stage::Native,
            case.ordinal,
            native_execution.outcome(),
        )?;
        require_match(
            case.ordinal,
            SurfaceNativeT1Stage::Native,
            surface,
            native_result,
        )?;

        let input_hash = surface_native_t1_case_hash(case);
        let record_hash = surface_native_t1_record_hash(
            case.ordinal,
            input_hash,
            surface,
            core_result,
            ssa_result,
            machine_result,
            target_result,
            native_result,
        );
        records.push(SurfaceNativeT1Record {
            ordinal: case.ordinal,
            name: case.name,
            input_hash,
            surface,
            core: core_result,
            ssa: ssa_result,
            machine_ir: machine_result,
            target_plan: target_result,
            native: native_result,
            record_hash,
        });
    }

    let results_hash = surface_native_t1_results_hash(&records);
    let mut evidence = SurfaceNativeT1Evidence {
        schema_version: SURFACE_NATIVE_T1_SCHEMA_VERSION,
        policy_version: SURFACE_NATIVE_T1_POLICY_VERSION,
        source_hash,
        request_hash,
        corpus_hash,
        core_hash: core.semantic_hash,
        ssa_hash: ssa.semantic_hash,
        machine_ir_hash: machine_ir.semantic_hash,
        target_hash: target.semantic_hash,
        target_plan_hash: target.program.plan_hash,
        target_code_hash: target.program.code_hash,
        records,
        results_hash,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = surface_native_t1_evidence_hash(&evidence);
    Ok(evidence)
}

/// Regenerate the fixed carrier from canonical source and compare every field.
/// Mutating semantic observations, provenance, hashes, order, or cardinality
/// is therefore rejected rather than being accepted after a convenient reseal.
pub fn verify_surface_native_t1(
    evidence: &SurfaceNativeT1Evidence,
) -> Result<(), SurfaceNativeT1Error> {
    if evidence.schema_version != SURFACE_NATIVE_T1_SCHEMA_VERSION
        || evidence.policy_version != SURFACE_NATIVE_T1_POLICY_VERSION
        || evidence.records.len() != SURFACE_NATIVE_T1_CASES
    {
        return Err(SurfaceNativeT1Error::EvidenceMismatch);
    }
    let expected = emit_surface_native_t1()?;
    if evidence == &expected {
        Ok(())
    } else {
        Err(SurfaceNativeT1Error::EvidenceMismatch)
    }
}

/// Render a canonical line-oriented report suitable for checked-in or
/// redirected thesis evidence. Rendering alone grants no authority; callers
/// must successfully run `verify_surface_native_t1` first.
pub fn render_surface_native_t1_report(evidence: &SurfaceNativeT1Evidence) -> String {
    let mut report = String::new();
    report.push_str("NAUX-SURFACE-NATIVE-T1\n");
    report.push_str(&format!(
        "schema\t{}.{}.{}\npolicy\t{}.{}.{}\n",
        evidence.schema_version.0,
        evidence.schema_version.1,
        evidence.schema_version.2,
        evidence.policy_version.0,
        evidence.policy_version.1,
        evidence.policy_version.2,
    ));
    for (name, hash) in [
        ("source", evidence.source_hash),
        ("request", evidence.request_hash),
        ("corpus", evidence.corpus_hash),
        ("core", evidence.core_hash),
        ("ssa", evidence.ssa_hash),
        ("machine-ir", evidence.machine_ir_hash),
        ("target", evidence.target_hash),
        ("target-plan", evidence.target_plan_hash),
        ("target-code", evidence.target_code_hash),
        ("results", evidence.results_hash),
        ("evidence", evidence.evidence_hash),
    ] {
        report.push_str("root\t");
        report.push_str(name);
        report.push('\t');
        report.push_str(&hash.to_hex());
        report.push('\n');
    }
    report.push_str(
        "columns\tcase\tordinal\tname\tinput\tsurface\tcore\tssa\tmachine-ir\ttarget-plan\tnative\trecord\n",
    );
    for record in &evidence.records {
        report.push_str(&format!(
            "case\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            record.ordinal,
            record.name,
            record.input_hash,
            render_normalized_scalar(record.surface),
            render_normalized_scalar(record.core),
            render_normalized_scalar(record.ssa),
            render_normalized_scalar(record.machine_ir),
            render_normalized_scalar(record.target_plan),
            render_normalized_scalar(record.native),
            record.record_hash,
        ));
    }
    report.push_str(&format!("records\t{}\n", evidence.records.len()));
    report
}

pub fn surface_native_t1_report_hash(evidence: &SurfaceNativeT1Evidence) -> SemanticHash {
    hash_domain(
        REPORT_DOMAIN,
        render_surface_native_t1_report(evidence).as_bytes(),
    )
}

/// Test-only adversarial seam: change one native observation and coherently
/// reseal every aggregate field that a naive self-authenticating verifier
/// might trust. Regenerative verification must still reject the result.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn probe_surface_native_t1_resealed_observation_mutation(
    evidence: &SurfaceNativeT1Evidence,
) -> SurfaceNativeT1Evidence {
    let mut mutated = evidence.clone();
    if let Some(record) = mutated.records.first_mut() {
        record.native = match record.native {
            NormalizedScalar::Bool(value) => NormalizedScalar::Bool(!value),
            NormalizedScalar::I64(value) => NormalizedScalar::I64(value.wrapping_add(1)),
            NormalizedScalar::F64Bits(value) => NormalizedScalar::F64Bits(value ^ 1),
        };
        record.record_hash = surface_native_t1_record_hash(
            record.ordinal,
            record.input_hash,
            record.surface,
            record.core,
            record.ssa,
            record.machine_ir,
            record.target_plan,
            record.native,
        );
    }
    mutated.results_hash = surface_native_t1_results_hash(&mutated.records);
    mutated.evidence_hash = surface_native_t1_evidence_hash(&mutated);
    mutated
}

fn surface_input(name: &str, ty: SurfaceScalarType) -> SurfaceInput {
    SurfaceInput {
        name: name.to_owned(),
        ty,
    }
}

fn surface_native_t1_evaluation_budget() -> EvaluationBudget {
    EvaluationBudget::new(
        SURFACE_NATIVE_T1_MAX_EXECUTION_STEPS,
        SURFACE_NATIVE_T1_MAX_CALL_DEPTH,
    )
}

fn normalize_evaluation(
    stage_name: SurfaceNativeT1Stage,
    case_ordinal: u32,
    evaluation: &Evaluation,
) -> Result<NormalizedScalar, SurfaceNativeT1Error> {
    if !evaluation.effect_trace.is_empty() {
        return Err(SurfaceNativeT1Error::ObservableEffects {
            stage: stage_name,
            case_ordinal,
        });
    }
    normalize_outcome(stage_name, case_ordinal, &evaluation.outcome)
}

fn normalize_outcome(
    stage_name: SurfaceNativeT1Stage,
    case_ordinal: u32,
    outcome: &EvaluationOutcome,
) -> Result<NormalizedScalar, SurfaceNativeT1Error> {
    let EvaluationOutcome::Return(value) = outcome else {
        return Err(SurfaceNativeT1Error::Stage {
            stage: stage_name,
            case_ordinal: Some(case_ordinal),
            message: "pure carrier did not return a scalar value".to_owned(),
        });
    };
    normalize_core_scalar(value).map_err(|error| stage(stage_name, Some(case_ordinal), error))
}

fn require_match(
    case_ordinal: u32,
    stage: SurfaceNativeT1Stage,
    expected: NormalizedScalar,
    actual: NormalizedScalar,
) -> Result<(), SurfaceNativeT1Error> {
    if expected == actual {
        Ok(())
    } else {
        Err(SurfaceNativeT1Error::SemanticMismatch {
            case_ordinal,
            stage,
            expected,
            actual,
        })
    }
}

fn stage(
    stage: SurfaceNativeT1Stage,
    case_ordinal: Option<u32>,
    error: impl fmt::Debug,
) -> SurfaceNativeT1Error {
    SurfaceNativeT1Error::Stage {
        stage,
        case_ordinal,
        message: format!("{error:?}"),
    }
}

fn hash_domain(domain: &[u8], payload: &[u8]) -> SemanticHash {
    let mut bytes = Vec::with_capacity(domain.len() + payload.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(payload);
    SemanticHash(sha256(&bytes))
}

fn surface_native_t1_request_hash(
    source_hash: SemanticHash,
    inputs: &[SurfaceInput],
) -> SemanticHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(REQUEST_DOMAIN);
    put_version(&mut bytes, SURFACE_NATIVE_T1_SCHEMA_VERSION);
    put_version(&mut bytes, SURFACE_NATIVE_T1_POLICY_VERSION);
    put_hash(&mut bytes, source_hash);
    put_string(&mut bytes, SURFACE_NATIVE_T1_RESULT);
    put_u64(&mut bytes, T2A_MAX_SOURCE_STEPS);
    put_u64(&mut bytes, T2A_MAX_CORE_NODES);
    put_u64(&mut bytes, SURFACE_NATIVE_T1_MAX_EXECUTION_STEPS);
    put_u32(&mut bytes, SURFACE_NATIVE_T1_MAX_CALL_DEPTH);
    put_u32(&mut bytes, inputs.len() as u32);
    for input in inputs {
        put_string(&mut bytes, &input.name);
        bytes.push(scalar_type_tag(input.ty));
    }
    SemanticHash(sha256(&bytes))
}

fn surface_native_t1_case_hash(case: &SurfaceNativeT1Case) -> SemanticHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CASE_DOMAIN);
    put_u32(&mut bytes, case.ordinal);
    put_string(&mut bytes, case.name);
    put_u32(&mut bytes, case.arguments.len() as u32);
    for argument in &case.arguments {
        put_surface_value(&mut bytes, *argument);
    }
    SemanticHash(sha256(&bytes))
}

fn surface_native_t1_corpus_hash(cases: &[SurfaceNativeT1Case]) -> SemanticHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CORPUS_DOMAIN);
    put_u32(&mut bytes, cases.len() as u32);
    for case in cases {
        put_hash(&mut bytes, surface_native_t1_case_hash(case));
    }
    SemanticHash(sha256(&bytes))
}

#[allow(clippy::too_many_arguments)]
fn surface_native_t1_record_hash(
    ordinal: u32,
    input_hash: SemanticHash,
    surface: NormalizedScalar,
    core: NormalizedScalar,
    ssa: NormalizedScalar,
    machine_ir: NormalizedScalar,
    target_plan: NormalizedScalar,
    native: NormalizedScalar,
) -> SemanticHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(RECORD_DOMAIN);
    put_u32(&mut bytes, ordinal);
    put_hash(&mut bytes, input_hash);
    for value in [surface, core, ssa, machine_ir, target_plan, native] {
        put_normalized_scalar(&mut bytes, value);
    }
    SemanticHash(sha256(&bytes))
}

fn surface_native_t1_results_hash(records: &[SurfaceNativeT1Record]) -> SemanticHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(RESULTS_DOMAIN);
    put_u32(&mut bytes, records.len() as u32);
    for record in records {
        put_hash(&mut bytes, record.record_hash);
    }
    SemanticHash(sha256(&bytes))
}

fn surface_native_t1_evidence_hash(evidence: &SurfaceNativeT1Evidence) -> SemanticHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    for hash in [
        evidence.source_hash,
        evidence.request_hash,
        evidence.corpus_hash,
        evidence.core_hash,
        evidence.ssa_hash,
        evidence.machine_ir_hash,
        evidence.target_hash,
        evidence.target_plan_hash,
        evidence.target_code_hash,
        evidence.results_hash,
    ] {
        put_hash(&mut bytes, hash);
    }
    put_u32(&mut bytes, evidence.records.len() as u32);
    SemanticHash(sha256(&bytes))
}

fn scalar_type_tag(value: SurfaceScalarType) -> u8 {
    match value {
        SurfaceScalarType::Bool => 0,
        SurfaceScalarType::I64 => 1,
        SurfaceScalarType::F64 => 2,
    }
}

fn put_surface_value(bytes: &mut Vec<u8>, value: SurfaceScalarValue) {
    match value {
        SurfaceScalarValue::Bool(value) => {
            bytes.push(0);
            bytes.push(u8::from(value));
        }
        SurfaceScalarValue::I64(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        SurfaceScalarValue::F64(value) => {
            bytes.push(2);
            bytes.extend_from_slice(&value.to_bits().to_be_bytes());
        }
    }
}

fn put_normalized_scalar(bytes: &mut Vec<u8>, value: NormalizedScalar) {
    match value {
        NormalizedScalar::Bool(value) => {
            bytes.push(0);
            bytes.push(u8::from(value));
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

fn put_version(bytes: &mut Vec<u8>, value: (u16, u16, u16)) {
    bytes.extend_from_slice(&value.0.to_be_bytes());
    bytes.extend_from_slice(&value.1.to_be_bytes());
    bytes.extend_from_slice(&value.2.to_be_bytes());
}

fn put_hash(bytes: &mut Vec<u8>, value: SemanticHash) {
    bytes.extend_from_slice(&value.0);
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_string(bytes: &mut Vec<u8>, value: &str) {
    put_u32(bytes, value.len() as u32);
    bytes.extend_from_slice(value.as_bytes());
}

fn render_normalized_scalar(value: NormalizedScalar) -> String {
    match value {
        NormalizedScalar::Bool(value) => format!("bool:{value}"),
        NormalizedScalar::I64(value) => format!("i64:{value}"),
        NormalizedScalar::F64Bits(value) => format!("f64:0x{value:016x}"),
    }
}
