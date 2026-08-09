//! Finite direct-process semantic admission for the Gate B hand baseline.
//!
//! The baseline is admitted only after one fresh process for every frozen
//! BranchMix Gate A case agrees with the canonical CoreVM0 semantics. The
//! five Bounds cases are intentionally outside this BranchMix-only baseline.

use super::corevm0::{
    branch_mix_kernel_program, evaluate_corevm0, verify_corevm0_program, CoreVmOutcome,
    CoreVmValue, VerifiedCoreVmProgram,
};
use super::corevm0_gate_a::{
    corevm0_gate_a_case_input_hash, corevm0_gate_a_manifest, CoreVmGateACase, CoreVmGateAWorkload,
    COREVM0_GATE_A_BOUNDS_CASES, COREVM0_GATE_A_SEED_STEP_LIMIT, COREVM0_GATE_A_TOTAL_CASES,
};
use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_gate_b_baseline::{
    build_x64_gate_b_baseline_artifact, verify_x64_gate_b_baseline_artifact, X64GateBBaselineError,
};
use super::x64_standalone_process::{
    run_admitted_x64_standalone_process, PreparedX64StandaloneExecutable,
    X64StandaloneProcessError, X64_STANDALONE_PROCESS_TIMEOUT_MILLIS,
};
use super::x64_standalone_protocol::{
    encode_x64_standalone_input, encode_x64_standalone_output, X64StandaloneInput,
    X64StandaloneOutcome, X64StandaloneOutput, X64StandaloneProfile, X64StandaloneProtocolError,
    X64_STANDALONE_OUTPUT_BYTES,
};
use std::fmt;

pub const X64_GATE_B_BASELINE_ADMISSION_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_BASELINE_ADMISSION_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_BASELINE_ADMISSION_CASES: u32 =
    COREVM0_GATE_A_TOTAL_CASES - COREVM0_GATE_A_BOUNDS_CASES;

const RECORD_DOMAIN: &[u8] = b"NAUX:gate-b:hand-baseline:admission:record:v1\0";
const RESULTS_DOMAIN: &[u8] = b"NAUX:gate-b:hand-baseline:admission:results:v1\0";
const INPUT_FRAME_DOMAIN: &[u8] = b"NAUX:gate-b:hand-baseline:input-frame:v1\0";
const OUTPUT_FRAME_DOMAIN: &[u8] = b"NAUX:gate-b:hand-baseline:output-frame:v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64GateBBaselineAdmissionRecord {
    case_ordinal: u32,
    gate_a_input_hash: SemanticHash,
    input_frame_hash: SemanticHash,
    expected: X64StandaloneOutcome,
    actual: X64StandaloneOutcome,
    output_frame: [u8; X64_STANDALONE_OUTPUT_BYTES],
    output_frame_hash: SemanticHash,
    target_hash: SemanticHash,
    artifact_hash: SemanticHash,
    record_hash: SemanticHash,
}

impl X64GateBBaselineAdmissionRecord {
    pub const fn case_ordinal(&self) -> u32 {
        self.case_ordinal
    }

    pub const fn expected(&self) -> X64StandaloneOutcome {
        self.expected
    }

    pub const fn actual(&self) -> X64StandaloneOutcome {
        self.actual
    }

    pub const fn input_frame_hash(&self) -> SemanticHash {
        self.input_frame_hash
    }

    pub const fn output_frame(&self) -> &[u8; X64_STANDALONE_OUTPUT_BYTES] {
        &self.output_frame
    }

    pub const fn output_frame_hash(&self) -> SemanticHash {
        self.output_frame_hash
    }

    pub const fn record_hash(&self) -> SemanticHash {
        self.record_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64GateBBaselineAdmissionEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    manifest_hash: SemanticHash,
    target_hash: SemanticHash,
    elf_image_hash: SemanticHash,
    artifact_hash: SemanticHash,
    case_count: u32,
    per_process_timeout_millis: u32,
    interpreter_dependency: bool,
    generated_target_dependency: bool,
    dynamic_loader_dependency: bool,
    external_symbol_dependency: bool,
    fallback: bool,
    records: Vec<X64GateBBaselineAdmissionRecord>,
    results_hash: SemanticHash,
}

impl X64GateBBaselineAdmissionEvidence {
    pub const fn manifest_hash(&self) -> SemanticHash {
        self.manifest_hash
    }

    pub const fn target_hash(&self) -> SemanticHash {
        self.target_hash
    }

    pub const fn elf_image_hash(&self) -> SemanticHash {
        self.elf_image_hash
    }

    pub const fn artifact_hash(&self) -> SemanticHash {
        self.artifact_hash
    }

    pub const fn case_count(&self) -> u32 {
        self.case_count
    }

    pub fn records(&self) -> &[X64GateBBaselineAdmissionRecord] {
        &self.records
    }

    pub const fn results_hash(&self) -> SemanticHash {
        self.results_hash
    }

    pub const fn interpreter_dependency(&self) -> bool {
        self.interpreter_dependency
    }

    pub const fn generated_target_dependency(&self) -> bool {
        self.generated_target_dependency
    }

    pub const fn dynamic_loader_dependency(&self) -> bool {
        self.dynamic_loader_dependency
    }

    pub const fn external_symbol_dependency(&self) -> bool {
        self.external_symbol_dependency
    }

    pub const fn fallback(&self) -> bool {
        self.fallback
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedX64GateBBaselineAdmission<'evidence> {
    evidence: &'evidence X64GateBBaselineAdmissionEvidence,
}

impl<'evidence> VerifiedX64GateBBaselineAdmission<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64GateBBaselineAdmissionEvidence {
        self.evidence
    }

    pub const fn results_hash(&self) -> SemanticHash {
        self.evidence.results_hash
    }
}

#[derive(Debug)]
pub enum X64GateBBaselineAdmissionError {
    UnsupportedHost,
    Artifact(X64GateBBaselineError),
    Manifest {
        message: String,
    },
    Protocol {
        case_ordinal: u32,
        message: String,
    },
    Reference {
        case_ordinal: u32,
        message: String,
    },
    Process(X64StandaloneProcessError),
    SemanticMismatch {
        case_ordinal: u32,
        expected: X64StandaloneOutcome,
        actual: X64StandaloneOutcome,
    },
    Cleanup(X64StandaloneProcessError),
    FailureDuringCleanup {
        primary: Box<X64GateBBaselineAdmissionError>,
        cleanup: Box<X64GateBBaselineAdmissionError>,
    },
    InvalidSchema,
    InvalidCorpusCount {
        expected: u32,
        actual: usize,
    },
    InvalidOrder {
        expected: u32,
        actual: u32,
    },
    InvalidRecord {
        case_ordinal: u32,
        field: &'static str,
    },
    RecordHashMismatch {
        case_ordinal: u32,
    },
    ResultsHashMismatch,
    MetricOverflow {
        field: &'static str,
    },
}

impl fmt::Display for X64GateBBaselineAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost => {
                formatter.write_str("Gate B hand baseline admission requires Linux x86-64")
            }
            Self::Artifact(error) => write!(formatter, "{error}"),
            Self::Manifest { message } => {
                write!(formatter, "Gate B hand baseline manifest failed: {message}")
            }
            Self::Protocol {
                case_ordinal,
                message,
            } => write!(
                formatter,
                "Gate B hand baseline case {case_ordinal} protocol failed: {message}"
            ),
            Self::Reference {
                case_ordinal,
                message,
            } => write!(
                formatter,
                "Gate B hand baseline case {case_ordinal} reference failed: {message}"
            ),
            Self::Process(error) => write!(formatter, "{error}"),
            Self::SemanticMismatch {
                case_ordinal,
                expected,
                actual,
            } => write!(
                formatter,
                "Gate B hand baseline case {case_ordinal} produced {actual:?}; expected {expected:?}"
            ),
            Self::Cleanup(error) => {
                write!(formatter, "Gate B hand baseline cleanup failed: {error}")
            }
            Self::FailureDuringCleanup { primary, cleanup } => write!(
                formatter,
                "Gate B hand baseline failed ({primary}) and cleanup also failed ({cleanup})"
            ),
            Self::InvalidSchema => {
                formatter.write_str("Gate B hand baseline admission schema/policy is invalid")
            }
            Self::InvalidCorpusCount { expected, actual } => write!(
                formatter,
                "Gate B hand baseline requires {expected} BranchMix cases; found {actual}"
            ),
            Self::InvalidOrder { expected, actual } => write!(
                formatter,
                "Gate B hand baseline expected case ordinal {expected}; found {actual}"
            ),
            Self::InvalidRecord {
                case_ordinal,
                field,
            } => write!(
                formatter,
                "Gate B hand baseline case {case_ordinal} has invalid {field}"
            ),
            Self::RecordHashMismatch { case_ordinal } => write!(
                formatter,
                "Gate B hand baseline case {case_ordinal} record hash differs"
            ),
            Self::ResultsHashMismatch => {
                formatter.write_str("Gate B hand baseline ordered results hash differs")
            }
            Self::MetricOverflow { field } => {
                write!(formatter, "Gate B hand baseline {field} overflows its frozen width")
            }
        }
    }
}

impl std::error::Error for X64GateBBaselineAdmissionError {}

impl From<X64GateBBaselineError> for X64GateBBaselineAdmissionError {
    fn from(error: X64GateBBaselineError) -> Self {
        Self::Artifact(error)
    }
}

/// Launch the complete frozen BranchMix corpus against the independently
/// verified hand baseline and seal the deterministic semantic observations.
pub fn emit_x64_gate_b_baseline_admission(
) -> Result<X64GateBBaselineAdmissionEvidence, X64GateBBaselineAdmissionError> {
    require_host()?;
    let manifest =
        corevm0_gate_a_manifest().map_err(|error| X64GateBBaselineAdmissionError::Manifest {
            message: error.to_string(),
        })?;
    let artifact = build_x64_gate_b_baseline_artifact()?;
    let verified_artifact = verify_x64_gate_b_baseline_artifact(artifact.image_bytes())?;
    let mut executable = PreparedX64StandaloneExecutable::create(
        X64StandaloneProfile::BranchMix,
        verified_artifact.image_bytes(),
    )
    .map_err(X64GateBBaselineAdmissionError::Process)?;

    let execution = (|| {
        let program = branch_mix_kernel_program();
        let verified_program = verify_corevm0_program(&program).map_err(|error| {
            X64GateBBaselineAdmissionError::Reference {
                case_ordinal: 0,
                message: error.to_string(),
            }
        })?;
        let branch_cases = manifest
            .cases
            .iter()
            .filter(|case| case.workload == CoreVmGateAWorkload::BranchMix)
            .collect::<Vec<_>>();
        if branch_cases.len() != X64_GATE_B_BASELINE_ADMISSION_CASES as usize {
            return Err(X64GateBBaselineAdmissionError::InvalidCorpusCount {
                expected: X64_GATE_B_BASELINE_ADMISSION_CASES,
                actual: branch_cases.len(),
            });
        }
        let mut records = Vec::with_capacity(branch_cases.len());
        for (expected_index, case) in branch_cases.into_iter().enumerate() {
            let expected_ordinal = u32::try_from(expected_index).map_err(|_| {
                X64GateBBaselineAdmissionError::MetricOverflow {
                    field: "case ordinal",
                }
            })?;
            if case.ordinal != expected_ordinal {
                return Err(X64GateBBaselineAdmissionError::InvalidOrder {
                    expected: expected_ordinal,
                    actual: case.ordinal,
                });
            }
            records.push(execute_case(
                &executable,
                verified_artifact.target_hash(),
                verified_artifact.artifact_hash(),
                case,
                verified_program,
            )?);
        }
        let mut evidence = X64GateBBaselineAdmissionEvidence {
            schema_version: X64_GATE_B_BASELINE_ADMISSION_SCHEMA_VERSION,
            policy_version: X64_GATE_B_BASELINE_ADMISSION_POLICY_VERSION,
            manifest_hash: manifest.manifest_hash,
            target_hash: verified_artifact.target_hash(),
            elf_image_hash: verified_artifact.elf_image_hash(),
            artifact_hash: verified_artifact.artifact_hash(),
            case_count: X64_GATE_B_BASELINE_ADMISSION_CASES,
            per_process_timeout_millis: X64_STANDALONE_PROCESS_TIMEOUT_MILLIS,
            interpreter_dependency: false,
            generated_target_dependency: false,
            dynamic_loader_dependency: false,
            external_symbol_dependency: false,
            fallback: false,
            records,
            results_hash: SemanticHash::ZERO,
        };
        evidence.results_hash = admission_results_hash(&evidence)?;
        let _ = verify_x64_gate_b_baseline_admission(&evidence)?;
        Ok(evidence)
    })();
    let cleanup = executable
        .cleanup()
        .map_err(X64GateBBaselineAdmissionError::Cleanup);
    merge_cleanup(execution, cleanup)
}

/// Replay all deterministic corpus, frame, reference, identity, and seal
/// relations. A claim-bearing run must still call the emitter to relaunch the
/// processes at the current revision.
pub fn verify_x64_gate_b_baseline_admission(
    evidence: &X64GateBBaselineAdmissionEvidence,
) -> Result<VerifiedX64GateBBaselineAdmission<'_>, X64GateBBaselineAdmissionError> {
    if evidence.schema_version != X64_GATE_B_BASELINE_ADMISSION_SCHEMA_VERSION
        || evidence.policy_version != X64_GATE_B_BASELINE_ADMISSION_POLICY_VERSION
        || evidence.case_count != X64_GATE_B_BASELINE_ADMISSION_CASES
        || evidence.per_process_timeout_millis != X64_STANDALONE_PROCESS_TIMEOUT_MILLIS
        || evidence.interpreter_dependency
        || evidence.generated_target_dependency
        || evidence.dynamic_loader_dependency
        || evidence.external_symbol_dependency
        || evidence.fallback
    {
        return Err(X64GateBBaselineAdmissionError::InvalidSchema);
    }
    if evidence.records.len() != X64_GATE_B_BASELINE_ADMISSION_CASES as usize {
        return Err(X64GateBBaselineAdmissionError::InvalidCorpusCount {
            expected: X64_GATE_B_BASELINE_ADMISSION_CASES,
            actual: evidence.records.len(),
        });
    }

    let manifest =
        corevm0_gate_a_manifest().map_err(|error| X64GateBBaselineAdmissionError::Manifest {
            message: error.to_string(),
        })?;
    if evidence.manifest_hash != manifest.manifest_hash {
        return Err(X64GateBBaselineAdmissionError::InvalidRecord {
            case_ordinal: 0,
            field: "manifest hash",
        });
    }
    let artifact = build_x64_gate_b_baseline_artifact()?;
    let verified_artifact = verify_x64_gate_b_baseline_artifact(artifact.image_bytes())?;
    if evidence.target_hash != verified_artifact.target_hash()
        || evidence.elf_image_hash != verified_artifact.elf_image_hash()
        || evidence.artifact_hash != verified_artifact.artifact_hash()
    {
        return Err(X64GateBBaselineAdmissionError::InvalidRecord {
            case_ordinal: 0,
            field: "baseline artifact identity",
        });
    }

    let program = branch_mix_kernel_program();
    let verified_program = verify_corevm0_program(&program).map_err(|error| {
        X64GateBBaselineAdmissionError::Reference {
            case_ordinal: 0,
            message: error.to_string(),
        }
    })?;
    let branch_cases = manifest
        .cases
        .iter()
        .filter(|case| case.workload == CoreVmGateAWorkload::BranchMix);
    for (expected_index, (case, record)) in branch_cases.zip(&evidence.records).enumerate() {
        let expected_ordinal = u32::try_from(expected_index).map_err(|_| {
            X64GateBBaselineAdmissionError::MetricOverflow {
                field: "case ordinal",
            }
        })?;
        if case.ordinal != expected_ordinal || record.case_ordinal != expected_ordinal {
            return Err(X64GateBBaselineAdmissionError::InvalidOrder {
                expected: expected_ordinal,
                actual: record.case_ordinal,
            });
        }
        verify_record(
            record,
            case,
            verified_program,
            evidence.target_hash,
            evidence.artifact_hash,
        )?;
    }
    let expected_results_hash = admission_results_hash(evidence)?;
    if evidence.results_hash != expected_results_hash {
        return Err(X64GateBBaselineAdmissionError::ResultsHashMismatch);
    }
    Ok(VerifiedX64GateBBaselineAdmission { evidence })
}

fn execute_case(
    executable: &PreparedX64StandaloneExecutable,
    target_hash: SemanticHash,
    artifact_hash: SemanticHash,
    case: &CoreVmGateACase,
    verified_program: VerifiedCoreVmProgram<'_>,
) -> Result<X64GateBBaselineAdmissionRecord, X64GateBBaselineAdmissionError> {
    let regenerated = corevm0_gate_a_case_input_hash(case).map_err(|error| {
        X64GateBBaselineAdmissionError::Manifest {
            message: error.to_string(),
        }
    })?;
    if regenerated != case.input_hash {
        return Err(X64GateBBaselineAdmissionError::InvalidRecord {
            case_ordinal: case.ordinal,
            field: "Gate A input hash",
        });
    }
    let input = X64StandaloneInput::new(
        X64StandaloneProfile::BranchMix,
        case.input.array_f64_bits.clone(),
        case.input.repetitions,
    )
    .map_err(|error| protocol_error(case.ordinal, error))?;
    let input_frame =
        encode_x64_standalone_input(&input).map_err(|error| protocol_error(case.ordinal, error))?;
    let expected = reference_outcome(case, verified_program)?;
    let process = run_admitted_x64_standalone_process(
        executable,
        case.ordinal,
        input_frame.clone(),
        X64StandaloneProfile::BranchMix,
        X64_STANDALONE_PROCESS_TIMEOUT_MILLIS,
    )
    .map_err(X64GateBBaselineAdmissionError::Process)?;
    let _ = process.elapsed_nanoseconds();
    let actual = process.output().outcome();
    if actual != expected {
        return Err(X64GateBBaselineAdmissionError::SemanticMismatch {
            case_ordinal: case.ordinal,
            expected,
            actual,
        });
    }
    let output_frame = *process.output_frame();
    let mut record = X64GateBBaselineAdmissionRecord {
        case_ordinal: case.ordinal,
        gate_a_input_hash: case.input_hash,
        input_frame_hash: frame_hash(INPUT_FRAME_DOMAIN, &input_frame),
        expected,
        actual,
        output_frame,
        output_frame_hash: frame_hash(OUTPUT_FRAME_DOMAIN, &output_frame),
        target_hash,
        artifact_hash,
        record_hash: SemanticHash::ZERO,
    };
    record.record_hash = admission_record_hash(&record);
    Ok(record)
}

fn verify_record(
    record: &X64GateBBaselineAdmissionRecord,
    case: &CoreVmGateACase,
    verified_program: VerifiedCoreVmProgram<'_>,
    target_hash: SemanticHash,
    artifact_hash: SemanticHash,
) -> Result<(), X64GateBBaselineAdmissionError> {
    let regenerated = corevm0_gate_a_case_input_hash(case).map_err(|error| {
        X64GateBBaselineAdmissionError::Manifest {
            message: error.to_string(),
        }
    })?;
    let input = X64StandaloneInput::new(
        X64StandaloneProfile::BranchMix,
        case.input.array_f64_bits.clone(),
        case.input.repetitions,
    )
    .map_err(|error| protocol_error(case.ordinal, error))?;
    let input_frame =
        encode_x64_standalone_input(&input).map_err(|error| protocol_error(case.ordinal, error))?;
    let expected = reference_outcome(case, verified_program)?;
    let canonical_output =
        X64StandaloneOutput::return_f64(X64StandaloneProfile::BranchMix, returned_bits(expected)?);
    let canonical_frame = encode_x64_standalone_output(canonical_output)
        .map_err(|error| protocol_error(case.ordinal, error))?;
    if regenerated != case.input_hash
        || record.gate_a_input_hash != case.input_hash
        || record.input_frame_hash != frame_hash(INPUT_FRAME_DOMAIN, &input_frame)
        || record.expected != expected
        || record.actual != expected
        || record.output_frame != canonical_frame
        || record.output_frame_hash != frame_hash(OUTPUT_FRAME_DOMAIN, &record.output_frame)
        || record.target_hash != target_hash
        || record.artifact_hash != artifact_hash
    {
        return Err(X64GateBBaselineAdmissionError::InvalidRecord {
            case_ordinal: case.ordinal,
            field: "canonical semantic/frame/identity relation",
        });
    }
    if record.record_hash != admission_record_hash(record) {
        return Err(X64GateBBaselineAdmissionError::RecordHashMismatch {
            case_ordinal: case.ordinal,
        });
    }
    Ok(())
}

fn reference_outcome(
    case: &CoreVmGateACase,
    verified_program: VerifiedCoreVmProgram<'_>,
) -> Result<X64StandaloneOutcome, X64GateBBaselineAdmissionError> {
    let values = case
        .input
        .array_f64_bits
        .iter()
        .copied()
        .map(f64::from_bits)
        .collect::<Vec<_>>();
    let evaluation = evaluate_corevm0(
        verified_program,
        vec![
            CoreVmValue::array_f64(values),
            CoreVmValue::I64(case.input.repetitions),
        ],
        COREVM0_GATE_A_SEED_STEP_LIMIT,
    )
    .map_err(|error| X64GateBBaselineAdmissionError::Reference {
        case_ordinal: case.ordinal,
        message: error.to_string(),
    })?;
    match evaluation.outcome {
        CoreVmOutcome::ReturnF64(value) => Ok(X64StandaloneOutput::return_f64(
            X64StandaloneProfile::BranchMix,
            value.to_bits(),
        )
        .outcome()),
        CoreVmOutcome::Error(error) => Err(X64GateBBaselineAdmissionError::Reference {
            case_ordinal: case.ordinal,
            message: format!("unexpected typed error {error:?}"),
        }),
    }
}

fn returned_bits(outcome: X64StandaloneOutcome) -> Result<u64, X64GateBBaselineAdmissionError> {
    outcome
        .returned_f64_bits()
        .ok_or(X64GateBBaselineAdmissionError::InvalidRecord {
            case_ordinal: 0,
            field: "BranchMix reference outcome",
        })
}

fn admission_record_hash(record: &X64GateBBaselineAdmissionRecord) -> SemanticHash {
    let mut bytes = Vec::with_capacity(RECORD_DOMAIN.len() + 196);
    bytes.extend_from_slice(RECORD_DOMAIN);
    put_version(&mut bytes, X64_GATE_B_BASELINE_ADMISSION_SCHEMA_VERSION);
    put_version(&mut bytes, X64_GATE_B_BASELINE_ADMISSION_POLICY_VERSION);
    bytes.extend_from_slice(&record.case_ordinal.to_be_bytes());
    bytes.extend_from_slice(&record.gate_a_input_hash.0);
    bytes.extend_from_slice(&record.input_frame_hash.0);
    put_outcome(&mut bytes, record.expected);
    put_outcome(&mut bytes, record.actual);
    bytes.extend_from_slice(&record.output_frame);
    bytes.extend_from_slice(&record.output_frame_hash.0);
    bytes.extend_from_slice(&record.target_hash.0);
    bytes.extend_from_slice(&record.artifact_hash.0);
    SemanticHash(sha256(&bytes))
}

fn admission_results_hash(
    evidence: &X64GateBBaselineAdmissionEvidence,
) -> Result<SemanticHash, X64GateBBaselineAdmissionError> {
    let record_count = u32::try_from(evidence.records.len()).map_err(|_| {
        X64GateBBaselineAdmissionError::MetricOverflow {
            field: "record count",
        }
    })?;
    let mut bytes = Vec::with_capacity(RESULTS_DOMAIN.len() + 182 + evidence.records.len() * 32);
    bytes.extend_from_slice(RESULTS_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    bytes.extend_from_slice(&evidence.manifest_hash.0);
    bytes.extend_from_slice(&evidence.target_hash.0);
    bytes.extend_from_slice(&evidence.elf_image_hash.0);
    bytes.extend_from_slice(&evidence.artifact_hash.0);
    bytes.extend_from_slice(&evidence.case_count.to_be_bytes());
    bytes.extend_from_slice(&evidence.per_process_timeout_millis.to_be_bytes());
    for dependency in [
        evidence.interpreter_dependency,
        evidence.generated_target_dependency,
        evidence.dynamic_loader_dependency,
        evidence.external_symbol_dependency,
        evidence.fallback,
    ] {
        bytes.push(u8::from(dependency));
    }
    bytes.extend_from_slice(&record_count.to_be_bytes());
    for record in &evidence.records {
        bytes.extend_from_slice(&record.record_hash.0);
    }
    Ok(SemanticHash(sha256(&bytes)))
}

fn put_outcome(bytes: &mut Vec<u8>, outcome: X64StandaloneOutcome) {
    match outcome {
        X64StandaloneOutcome::ReturnF64 { bits } => {
            bytes.push(0);
            bytes.extend_from_slice(&bits.to_be_bytes());
        }
        X64StandaloneOutcome::Bounds => {
            bytes.push(1);
            bytes.extend_from_slice(&0_u64.to_be_bytes());
        }
    }
}

fn frame_hash(domain: &[u8], frame: &[u8]) -> SemanticHash {
    let mut bytes = Vec::with_capacity(domain.len() + 8 + frame.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&(frame.len() as u64).to_be_bytes());
    bytes.extend_from_slice(frame);
    SemanticHash(sha256(&bytes))
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_be_bytes());
    bytes.extend_from_slice(&version.1.to_be_bytes());
    bytes.extend_from_slice(&version.2.to_be_bytes());
}

fn protocol_error(
    case_ordinal: u32,
    error: X64StandaloneProtocolError,
) -> X64GateBBaselineAdmissionError {
    X64GateBBaselineAdmissionError::Protocol {
        case_ordinal,
        message: error.to_string(),
    }
}

fn merge_cleanup<T>(
    primary: Result<T, X64GateBBaselineAdmissionError>,
    cleanup: Result<(), X64GateBBaselineAdmissionError>,
) -> Result<T, X64GateBBaselineAdmissionError> {
    match (primary, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(X64GateBBaselineAdmissionError::FailureDuringCleanup {
            primary: Box::new(primary),
            cleanup: Box::new(cleanup),
        }),
    }
}

fn require_host() -> Result<(), X64GateBBaselineAdmissionError> {
    if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        Ok(())
    } else {
        Err(X64GateBBaselineAdmissionError::UnsupportedHost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    #[test]
    fn hand_baseline_matches_all_frozen_branch_cases_in_direct_processes() {
        let evidence = emit_x64_gate_b_baseline_admission().expect("baseline corpus admission");
        let verified =
            verify_x64_gate_b_baseline_admission(&evidence).expect("baseline evidence replay");
        assert_eq!(
            verified.evidence().records().len(),
            X64_GATE_B_BASELINE_ADMISSION_CASES as usize
        );
        assert!(verified
            .evidence()
            .records()
            .iter()
            .all(|record| record.actual() == record.expected()));

        let mut mutated = evidence.clone();
        mutated.results_hash.0[0] ^= 1;
        assert!(matches!(
            verify_x64_gate_b_baseline_admission(&mutated),
            Err(X64GateBBaselineAdmissionError::ResultsHashMismatch)
        ));
    }
}
