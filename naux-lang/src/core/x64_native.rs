//! Verifier-gated Linux x86-64 execution for the first R1-S7b slice.
//!
//! This module deliberately does not import the bridge JIT, libc, runtime
//! callbacks, or fallback engines. It accepts only the opaque source-bound
//! R1-S7a view, creates one anonymous RW mapping through the Linux x86-64
//! syscall ABI, copies and hashes the exact canonical bytes, changes the
//! mapping to RX, invokes the fixed lighthouse ABI, and unmaps it.
//!
//! R1-S7b-b adds canonical execution/correspondence identities for the fixed
//! 51-case Gate A corpus. Process isolation remains R1-S7b-c: an in-process
//! native fault cannot be converted into a Rust error.

use super::corevm0_gate_a::{
    corevm0_gate_a_case_input_hash, corevm0_gate_a_manifest, CoreVmGateACase, CoreVmGateAError,
    CoreVmGateAWorkload,
};
use super::encoding::sha256;
use super::interpret::{CoreValue, EffectEvent, Evaluation, EvaluationOutcome};
use super::machine_ir::MachineType;
use super::schema::{ErrorKind, SemanticHash};
use super::x64_target::{
    x64_target_code_hash, SourceBoundX64TargetArtifact, X64AbiRegister, X64EntryAbi, X64TargetAbi,
    X64TargetEncodeError, X64_TARGET_MAX_CODE_BYTES,
};
use std::fmt;

pub const X64_NATIVE_RUNNER_SCHEMA_VERSION: (u16, u16, u16) = (0, 1, 0);
pub const X64_NATIVE_RUNNER_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_NATIVE_SYSCALL_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_NATIVE_ENTRY_DISPATCH_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_NATIVE_ENTRY_POLICY_VERSION: (u16, u16, u16) =
    X64_NATIVE_ENTRY_DISPATCH_POLICY_VERSION;
pub const X64_NATIVE_EVIDENCE_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);

pub const X64_NATIVE_MAX_CODE_MAPPINGS: u32 = 1;
pub const X64_NATIVE_MAX_MAPPING_BYTES: u64 = 64 * 1024 * 1024;
pub const X64_NATIVE_MAX_ENTRY_LANES: u32 = 5;
pub const X64_NATIVE_MAX_BORROWED_F64_ARRAYS: u32 = 2;
pub const X64_NATIVE_OUTPUT_WORDS: u32 = 2;
pub const X64_NATIVE_MAPPING_STATE_EVENTS: u32 = 4;
pub const X64_NATIVE_MAX_EFFECTS_PER_ENGINE: u32 = 1;
pub const X64_NATIVE_MAX_CORRESPONDENCE_RECORDS: u32 = 64;
pub const X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS: u32 = 51;
pub const X64_NATIVE_MAX_RECORD_BYTES: u32 = 16_384;
pub const X64_NATIVE_MAX_DIAGNOSTICS: u32 = 128;

const X64_NATIVE_ABI_DOMAIN: &[u8] = b"NAUX:x86-64:r1-s7b:abi:v1\0";
const X64_NATIVE_EXECUTION_RECORD_DOMAIN: &[u8] = b"NAUX:x86-64:r1-s7b:execution:record:v1\0";
const X64_NATIVE_CORRESPONDENCE_RECORD_DOMAIN: &[u8] =
    b"NAUX:x86-64:r1-s7b:correspondence:record:v1\0";
const X64_NATIVE_CORPUS_RESULTS_DOMAIN: &[u8] = b"NAUX:x86-64:r1-s7b:correspondence:results:v1\0";

const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;
const OUTPUT_SENTINEL: u64 = 0xa5c3_d7e9_1b2f_4068;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64NativeLimits {
    pub code_mappings_per_invocation: u32,
    pub max_mapping_bytes: u64,
    pub max_entry_lanes: u32,
    pub max_borrowed_f64_arrays: u32,
    pub output_words: u32,
    pub mapping_state_events: u32,
    pub max_effects_per_engine: u32,
    pub max_correspondence_records: u32,
    pub fixed_lighthouse_records: u32,
    pub max_record_bytes: u32,
    pub max_diagnostics: u32,
}

impl X64NativeLimits {
    pub const fn r1_s7b() -> Self {
        Self {
            code_mappings_per_invocation: X64_NATIVE_MAX_CODE_MAPPINGS,
            max_mapping_bytes: X64_NATIVE_MAX_MAPPING_BYTES,
            max_entry_lanes: X64_NATIVE_MAX_ENTRY_LANES,
            max_borrowed_f64_arrays: X64_NATIVE_MAX_BORROWED_F64_ARRAYS,
            output_words: X64_NATIVE_OUTPUT_WORDS,
            mapping_state_events: X64_NATIVE_MAPPING_STATE_EVENTS,
            max_effects_per_engine: X64_NATIVE_MAX_EFFECTS_PER_ENGINE,
            max_correspondence_records: X64_NATIVE_MAX_CORRESPONDENCE_RECORDS,
            fixed_lighthouse_records: X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS,
            max_record_bytes: X64_NATIVE_MAX_RECORD_BYTES,
            max_diagnostics: X64_NATIVE_MAX_DIAGNOSTICS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64NativeMappingState {
    Unmapped,
    ReadWrite,
    ReadExecute,
}

#[derive(Clone, Debug, PartialEq)]
pub struct X64NativeExecution {
    runner_schema_version: (u16, u16, u16),
    runner_policy_version: (u16, u16, u16),
    syscall_policy_version: (u16, u16, u16),
    entry_policy_version: (u16, u16, u16),
    limits: X64NativeLimits,
    target_artifact_hash: SemanticHash,
    target_plan_hash: SemanticHash,
    source_machine_ir_hash: SemanticHash,
    verified_code_hash: SemanticHash,
    copied_rw_code_hash: SemanticHash,
    readback_rx_code_hash: SemanticHash,
    entry_offset: u32,
    input_lanes: u8,
    mapping_trace: [X64NativeMappingState; 4],
    mxcsr_before: u32,
    mxcsr_after: u32,
    outcome: EvaluationOutcome,
    effect_trace: Vec<EffectEvent>,
    fallback: bool,
}

impl X64NativeExecution {
    pub fn target_artifact_hash(&self) -> SemanticHash {
        self.target_artifact_hash
    }

    pub fn target_plan_hash(&self) -> SemanticHash {
        self.target_plan_hash
    }

    pub fn source_machine_ir_hash(&self) -> SemanticHash {
        self.source_machine_ir_hash
    }

    pub fn verified_code_hash(&self) -> SemanticHash {
        self.verified_code_hash
    }

    pub fn copied_rw_code_hash(&self) -> SemanticHash {
        self.copied_rw_code_hash
    }

    pub fn readback_rx_code_hash(&self) -> SemanticHash {
        self.readback_rx_code_hash
    }

    pub fn input_lanes(&self) -> u8 {
        self.input_lanes
    }

    pub fn mapping_trace(&self) -> [X64NativeMappingState; 4] {
        self.mapping_trace
    }

    pub fn mxcsr_before(&self) -> u32 {
        self.mxcsr_before
    }

    pub fn mxcsr_after(&self) -> u32 {
        self.mxcsr_after
    }

    pub fn outcome(&self) -> &EvaluationOutcome {
        &self.outcome
    }

    pub fn effect_trace(&self) -> &[EffectEvent] {
        &self.effect_trace
    }

    pub fn fallback(&self) -> bool {
        self.fallback
    }
}

/// Opaque proof that one safe invocation used arguments derived from a
/// concrete Gate A case. This prevents a caller from pairing an unrelated
/// invocation with a convenient canonical input hash.
#[derive(Clone, Debug, PartialEq)]
pub struct X64NativeCaseExecution {
    case_ordinal: u32,
    input_hash: SemanticHash,
    execution: X64NativeExecution,
}

impl X64NativeCaseExecution {
    pub fn case_ordinal(&self) -> u32 {
        self.case_ordinal
    }

    pub fn input_hash(&self) -> SemanticHash {
        self.input_hash
    }

    pub fn execution(&self) -> &X64NativeExecution {
        &self.execution
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64NativeCorrespondenceF64 {
    ExactBits(u64),
    CanonicalNaN,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64NativeCorrespondenceOutcome {
    ReturnF64(X64NativeCorrespondenceF64),
    Bounds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64NativeCorrespondenceEffect {
    Bounds,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64NativeCorrespondenceObservation {
    pub outcome: X64NativeCorrespondenceOutcome,
    pub effect_trace: Vec<X64NativeCorrespondenceEffect>,
}

/// Canonical semantic evidence for one completed native invocation.
///
/// Raw process addresses, PID, ASLR, syscall return values, and wall-clock
/// telemetry are intentionally absent. `input_hash` arrives only through an
/// opaque case execution that derived the actual native arguments from the
/// already-sealed Gate A case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64NativeExecutionRecord {
    pub evidence_schema_version: (u16, u16, u16),
    pub runner_schema_version: (u16, u16, u16),
    pub runner_policy_version: (u16, u16, u16),
    pub syscall_policy_version: (u16, u16, u16),
    pub entry_policy_version: (u16, u16, u16),
    pub limits: X64NativeLimits,
    pub target_artifact_hash: SemanticHash,
    pub target_plan_hash: SemanticHash,
    pub target_code_hash: SemanticHash,
    pub source_machine_ir_hash: SemanticHash,
    pub entry_offset: u32,
    pub canonical_abi_hash: SemanticHash,
    pub input_hash: SemanticHash,
    pub copied_rw_code_hash: SemanticHash,
    pub readback_rx_code_hash: SemanticHash,
    pub input_lanes: u8,
    pub mapping_trace: [X64NativeMappingState; 4],
    pub mxcsr_before: u32,
    pub mxcsr_after: u32,
    pub native: X64NativeCorrespondenceObservation,
    pub fallback: bool,
    pub record_hash: SemanticHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64NativeCorrespondenceRecord {
    pub schema_version: (u16, u16, u16),
    pub case_ordinal: u32,
    pub input_hash: SemanticHash,
    pub source_machine_ir_hash: SemanticHash,
    pub target_artifact_hash: SemanticHash,
    pub target_code_hash: SemanticHash,
    pub machine_ir: X64NativeCorrespondenceObservation,
    pub native: X64NativeCorrespondenceObservation,
    pub native_execution: X64NativeExecutionRecord,
    pub record_hash: SemanticHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64NativeCorrespondenceEvidence {
    pub schema_version: (u16, u16, u16),
    pub corpus_manifest_hash: SemanticHash,
    pub records: Vec<X64NativeCorrespondenceRecord>,
    pub results_hash: SemanticHash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64NativeHashStage {
    ReadWrite,
    ReadExecute,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64NativeRunnerError {
    UnsupportedHost,
    InvalidRunnerEnvelope {
        message: &'static str,
    },
    InputArity {
        expected: usize,
        actual: usize,
    },
    InputType {
        parameter: usize,
        expected: MachineType,
    },
    InputSpanOverflow {
        parameter: usize,
    },
    InputOutputOverlap {
        parameter: usize,
    },
    CodeLimit {
        limit: u64,
        actual: u64,
    },
    CodeHashEncoding(X64TargetEncodeError),
    CodeHashMismatch {
        stage: X64NativeHashStage,
        expected: SemanticHash,
        actual: SemanticHash,
    },
    MappingFailed {
        operation: &'static str,
        errno: i32,
    },
    UnknownOutcomeTag {
        tag: u32,
    },
    NonCanonicalOutput {
        result: MachineType,
        word0: u64,
        word1: u64,
    },
    ForeignArrayResult {
        data: u64,
        length: u64,
    },
    MxcsrNotRestored {
        before: u32,
        after: u32,
    },
}

impl fmt::Display for X64NativeRunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost => {
                formatter.write_str("R1-S7b native execution requires Linux x86-64")
            }
            Self::InvalidRunnerEnvelope { message } => {
                write!(formatter, "invalid R1-S7b runner envelope: {message}")
            }
            Self::InputArity { expected, actual } => write!(
                formatter,
                "R1-S7b input arity is {actual}; target entry requires {expected}"
            ),
            Self::InputType {
                parameter,
                expected,
            } => write!(
                formatter,
                "R1-S7b input {parameter} does not have required type {expected:?}"
            ),
            Self::InputSpanOverflow { parameter } => write!(
                formatter,
                "R1-S7b F64 array input {parameter} has an overflowing host span"
            ),
            Self::InputOutputOverlap { parameter } => write!(
                formatter,
                "R1-S7b output area overlaps F64 array input {parameter}"
            ),
            Self::CodeLimit { limit, actual } => {
                write!(
                    formatter,
                    "R1-S7b code uses {actual} bytes; limit is {limit}"
                )
            }
            Self::CodeHashEncoding(error) => {
                write!(formatter, "R1-S7b cannot hash copied target code: {error}")
            }
            Self::CodeHashMismatch {
                stage,
                expected,
                actual,
            } => write!(
                formatter,
                "R1-S7b {stage:?} code hash {actual} differs from verified hash {expected}"
            ),
            Self::MappingFailed { operation, errno } => {
                write!(
                    formatter,
                    "R1-S7b {operation} syscall failed with errno {errno}"
                )
            }
            Self::UnknownOutcomeTag { tag } => {
                write!(formatter, "R1-S7b native entry returned unknown tag {tag}")
            }
            Self::NonCanonicalOutput {
                result,
                word0,
                word1,
            } => write!(
                formatter,
                "R1-S7b native {result:?} payload is noncanonical: {word0:#018x}, {word1:#018x}"
            ),
            Self::ForeignArrayResult { data, length } => write!(
                formatter,
                "R1-S7b native array result ({data:#018x}, {length}) is not an admitted input"
            ),
            Self::MxcsrNotRestored { before, after } => write!(
                formatter,
                "R1-S7b native entry changed caller MXCSR from {before:#010x} to {after:#010x}"
            ),
        }
    }
}

impl std::error::Error for X64NativeRunnerError {}

impl From<X64TargetEncodeError> for X64NativeRunnerError {
    fn from(error: X64TargetEncodeError) -> Self {
        Self::CodeHashEncoding(error)
    }
}

#[derive(Debug)]
pub enum X64NativeEvidenceError {
    CorpusManifest(CoreVmGateAError),
    Runner(X64NativeRunnerError),
    InvalidSchema {
        actual: (u16, u16, u16),
    },
    InvalidPolicy {
        field: &'static str,
        actual: (u16, u16, u16),
    },
    InvalidLimits,
    RecordLimit {
        limit: u32,
        actual: u32,
    },
    FixedCorpusCount {
        expected: u32,
        actual: u32,
    },
    RecordByteLimit {
        limit: u32,
        actual: u32,
    },
    EffectLimit {
        engine: &'static str,
        case_ordinal: u32,
        limit: u32,
        actual: u32,
    },
    InvalidIdentity {
        field: &'static str,
    },
    IdentityMismatch {
        field: &'static str,
    },
    InvalidMappingTrace,
    MxcsrNotRestored {
        before: u32,
        after: u32,
    },
    NonCanonicalClaimMxcsr {
        expected: u32,
        actual: u32,
    },
    FallbackObserved,
    UnsupportedOutcome {
        engine: &'static str,
        case_ordinal: u32,
    },
    UnsupportedEffect {
        engine: &'static str,
        case_ordinal: u32,
    },
    NonCanonicalObservation {
        engine: &'static str,
        case_ordinal: u32,
    },
    SemanticMismatch {
        case_ordinal: u32,
    },
    NonCanonicalOrdinal {
        expected: u32,
        actual: u32,
    },
    InputHashMismatch {
        case_ordinal: u32,
    },
    MixedTargetArtifact {
        case_ordinal: u32,
    },
    ExecutionRecordHashMismatch,
    CorrespondenceRecordHashMismatch {
        case_ordinal: u32,
    },
    CorpusManifestHashMismatch,
    ResultsHashMismatch,
    MetricOverflow,
}

impl fmt::Display for X64NativeEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CorpusManifest(error) => {
                write!(formatter, "R1-S7b cannot regenerate Gate A corpus: {error}")
            }
            Self::Runner(error) => write!(formatter, "R1-S7b case execution failed: {error}"),
            Self::InvalidSchema { actual } => {
                write!(formatter, "R1-S7b evidence schema {actual:?} is not canonical")
            }
            Self::InvalidPolicy { field, actual } => {
                write!(formatter, "R1-S7b {field} policy {actual:?} is not canonical")
            }
            Self::InvalidLimits => {
                formatter.write_str("R1-S7b evidence limits are not the frozen v1 vector")
            }
            Self::RecordLimit { limit, actual } => write!(
                formatter,
                "R1-S7b record count or ordinal {actual} exceeds hard cap {limit}"
            ),
            Self::FixedCorpusCount { expected, actual } => write!(
                formatter,
                "R1-S7b fixed corpus requires {expected} records, found {actual}"
            ),
            Self::RecordByteLimit { limit, actual } => write!(
                formatter,
                "R1-S7b canonical record uses {actual} bytes; limit is {limit}"
            ),
            Self::EffectLimit {
                engine,
                case_ordinal,
                limit,
                actual,
            } => write!(
                formatter,
                "{engine} effect count {actual} in R1-S7b case {case_ordinal} exceeds hard cap {limit}"
            ),
            Self::InvalidIdentity { field } => {
                write!(formatter, "R1-S7b {field} identity is zero")
            }
            Self::IdentityMismatch { field } => {
                write!(formatter, "R1-S7b {field} identity does not match its source")
            }
            Self::InvalidMappingTrace => {
                formatter.write_str("R1-S7b mapping trace is not Unmapped→RW→RX→Unmapped")
            }
            Self::MxcsrNotRestored { before, after } => write!(
                formatter,
                "R1-S7b evidence records caller MXCSR {before:#010x}→{after:#010x}"
            ),
            Self::NonCanonicalClaimMxcsr { expected, actual } => write!(
                formatter,
                "R1-S7b claim execution requires caller MXCSR {expected:#010x}, found {actual:#010x}"
            ),
            Self::FallbackObserved => {
                formatter.write_str("R1-S7b evidence records a forbidden fallback")
            }
            Self::UnsupportedOutcome {
                engine,
                case_ordinal,
            } => write!(
                formatter,
                "{engine} produced an unsupported R1-S7b outcome in case {case_ordinal}"
            ),
            Self::UnsupportedEffect {
                engine,
                case_ordinal,
            } => write!(
                formatter,
                "{engine} produced an unsupported R1-S7b effect in case {case_ordinal}"
            ),
            Self::NonCanonicalObservation {
                engine,
                case_ordinal,
            } => write!(
                formatter,
                "{engine} produced a noncanonical R1-S7b observation in case {case_ordinal}"
            ),
            Self::SemanticMismatch { case_ordinal } => write!(
                formatter,
                "Machine IR and native execution differ in R1-S7b case {case_ordinal}"
            ),
            Self::NonCanonicalOrdinal { expected, actual } => write!(
                formatter,
                "R1-S7b expected case ordinal {expected}, found {actual}"
            ),
            Self::InputHashMismatch { case_ordinal } => write!(
                formatter,
                "R1-S7b case {case_ordinal} does not bind the canonical Gate A input"
            ),
            Self::MixedTargetArtifact { case_ordinal } => write!(
                formatter,
                "R1-S7b case {case_ordinal} mixes target identity within one workload"
            ),
            Self::ExecutionRecordHashMismatch => {
                formatter.write_str("R1-S7b native execution record has an invalid seal")
            }
            Self::CorrespondenceRecordHashMismatch { case_ordinal } => write!(
                formatter,
                "R1-S7b correspondence record {case_ordinal} has an invalid seal"
            ),
            Self::CorpusManifestHashMismatch => {
                formatter.write_str("R1-S7b evidence does not bind the fixed Gate A manifest")
            }
            Self::ResultsHashMismatch => {
                formatter.write_str("R1-S7b native correspondence results hash is invalid")
            }
            Self::MetricOverflow => {
                formatter.write_str("R1-S7b evidence checked metric overflow")
            }
        }
    }
}

impl std::error::Error for X64NativeEvidenceError {}

#[derive(Clone, Copy)]
struct ArraySpan<'value> {
    parameter: usize,
    data: u64,
    length: u64,
    end: u64,
    value: &'value CoreValue,
}

/// Execute one already source-bound R1-S7a artifact through the fixed
/// lighthouse ABI.
///
/// This is the in-process R1-S7b-a slice. Callers that need claim-bearing
/// fault containment must use the later process-isolated evidence harness.
pub fn execute_x64_native_r1_s7b(
    target: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
    arguments: &[CoreValue],
) -> Result<X64NativeExecution, X64NativeRunnerError> {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        execute_supported(target, arguments)
    }

    #[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
    {
        let _ = (target, arguments);
        Err(X64NativeRunnerError::UnsupportedHost)
    }
}

/// Execute one canonical Gate A case and retain an opaque binding between the
/// exact case identity and the actual argument vector passed to native code.
pub fn execute_x64_native_case_r1_s7b(
    target: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
    case: &CoreVmGateACase,
) -> Result<X64NativeCaseExecution, X64NativeEvidenceError> {
    if case.ordinal >= X64_NATIVE_MAX_CORRESPONDENCE_RECORDS {
        return Err(X64NativeEvidenceError::RecordLimit {
            limit: X64_NATIVE_MAX_CORRESPONDENCE_RECORDS,
            actual: case.ordinal,
        });
    }
    let regenerated =
        corevm0_gate_a_case_input_hash(case).map_err(X64NativeEvidenceError::CorpusManifest)?;
    if regenerated != case.input_hash {
        return Err(X64NativeEvidenceError::InputHashMismatch {
            case_ordinal: case.ordinal,
        });
    }
    let values = case
        .input
        .array_f64_bits
        .iter()
        .copied()
        .map(f64::from_bits)
        .collect::<Vec<_>>();
    let arguments = match case.workload {
        CoreVmGateAWorkload::BranchMix => vec![
            CoreValue::array_f64(values),
            CoreValue::I64(case.input.repetitions),
        ],
        CoreVmGateAWorkload::BoundsOrderedArrayGet => {
            vec![CoreValue::array_f64(values)]
        }
    };
    let execution =
        execute_x64_native_r1_s7b(target, &arguments).map_err(X64NativeEvidenceError::Runner)?;
    Ok(X64NativeCaseExecution {
        case_ordinal: case.ordinal,
        input_hash: case.input_hash,
        execution,
    })
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn execute_supported(
    target: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
    arguments: &[CoreValue],
) -> Result<X64NativeExecution, X64NativeRunnerError> {
    let artifact = target.artifact();
    let program = &artifact.program;
    if program.abi != X64TargetAbi::r1_s7a() {
        return Err(X64NativeRunnerError::InvalidRunnerEnvelope {
            message: "target ABI is not the frozen R1-S7a ABI",
        });
    }
    if program.entry_offset != 0 {
        return Err(X64NativeRunnerError::InvalidRunnerEnvelope {
            message: "entry offset is not canonical zero",
        });
    }
    if program.entry_abi.output_words != 2 {
        return Err(X64NativeRunnerError::InvalidRunnerEnvelope {
            message: "output area is not exactly two words",
        });
    }
    if program.code.is_empty() {
        return Err(X64NativeRunnerError::InvalidRunnerEnvelope {
            message: "code blob is empty",
        });
    }
    let code_len =
        u64::try_from(program.code.len()).map_err(|_| X64NativeRunnerError::CodeLimit {
            limit: X64_TARGET_MAX_CODE_BYTES,
            actual: u64::MAX,
        })?;
    if code_len > X64_TARGET_MAX_CODE_BYTES {
        return Err(X64NativeRunnerError::CodeLimit {
            limit: X64_TARGET_MAX_CODE_BYTES,
            actual: code_len,
        });
    }

    let (lanes, arrays) = flatten_arguments(&program.entry_abi.parameter_types, arguments)?;
    validate_entry_registers(
        lanes.len(),
        program.entry_abi.input_lanes.len(),
        program.entry_abi.output_register,
    )?;

    let mut output = [OUTPUT_SENTINEL; 2];
    validate_output_disjoint(&arrays, output.as_ptr() as u64)?;

    let mut mapping = platform::NativeMapping::allocate(program.code.len())?;
    mapping.copy_from(&program.code);
    let copied_rw_code_hash = x64_target_code_hash(mapping.bytes())?;
    if copied_rw_code_hash != program.code_hash {
        return Err(X64NativeRunnerError::CodeHashMismatch {
            stage: X64NativeHashStage::ReadWrite,
            expected: program.code_hash,
            actual: copied_rw_code_hash,
        });
    }

    mapping.protect_rx()?;
    let readback_rx_code_hash = x64_target_code_hash(mapping.bytes())?;
    if readback_rx_code_hash != program.code_hash {
        return Err(X64NativeRunnerError::CodeHashMismatch {
            stage: X64NativeHashStage::ReadExecute,
            expected: program.code_hash,
            actual: readback_rx_code_hash,
        });
    }

    let mxcsr_before = platform::read_mxcsr();
    // SAFETY: `mapping` is RX, contains the exact source-bound and rehashed
    // R1-S7a bytes, `entry_offset` is verified zero, the selected signature is
    // derived from the exact ABI lane count, every input span remains borrowed
    // for this call, and `output` owns two writable words.
    let tag = unsafe {
        platform::call_entry(
            mapping.entry(program.entry_offset),
            &lanes,
            output.as_mut_ptr(),
        )
    };
    let mxcsr_after = platform::read_mxcsr();
    let decoded = decode_output(tag, program.entry_abi.result, output, &arrays);
    mapping.unmap()?;
    if mxcsr_after != mxcsr_before {
        return Err(X64NativeRunnerError::MxcsrNotRestored {
            before: mxcsr_before,
            after: mxcsr_after,
        });
    }

    let (outcome, effect_trace) = decoded?;

    Ok(X64NativeExecution {
        runner_schema_version: X64_NATIVE_RUNNER_SCHEMA_VERSION,
        runner_policy_version: X64_NATIVE_RUNNER_POLICY_VERSION,
        syscall_policy_version: X64_NATIVE_SYSCALL_POLICY_VERSION,
        entry_policy_version: X64_NATIVE_ENTRY_POLICY_VERSION,
        limits: X64NativeLimits::r1_s7b(),
        target_artifact_hash: artifact.semantic_hash,
        target_plan_hash: program.plan_hash,
        source_machine_ir_hash: program.source_machine_ir_hash,
        verified_code_hash: program.code_hash,
        copied_rw_code_hash,
        readback_rx_code_hash,
        entry_offset: program.entry_offset,
        input_lanes: lanes.len() as u8,
        mapping_trace: [
            X64NativeMappingState::Unmapped,
            X64NativeMappingState::ReadWrite,
            X64NativeMappingState::ReadExecute,
            X64NativeMappingState::Unmapped,
        ],
        mxcsr_before,
        mxcsr_after,
        outcome,
        effect_trace,
        fallback: false,
    })
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn flatten_arguments<'value>(
    parameter_types: &[MachineType],
    arguments: &'value [CoreValue],
) -> Result<(Vec<u64>, Vec<ArraySpan<'value>>), X64NativeRunnerError> {
    if arguments.len() != parameter_types.len() {
        return Err(X64NativeRunnerError::InputArity {
            expected: parameter_types.len(),
            actual: arguments.len(),
        });
    }

    let mut lanes = Vec::with_capacity(5);
    let mut arrays = Vec::with_capacity(2);
    for (parameter, (ty, value)) in parameter_types.iter().zip(arguments).enumerate() {
        match (ty, value) {
            (MachineType::Unit, CoreValue::Unit) => {}
            (MachineType::Bool, CoreValue::Bool(value)) => lanes.push(u64::from(*value)),
            (MachineType::I64, CoreValue::I64(value)) => lanes.push(*value as u64),
            (MachineType::F64, CoreValue::F64(value)) => lanes.push(value.to_bits()),
            (MachineType::F64Array, CoreValue::ArrayF64(values)) => {
                let length = u64::try_from(values.len())
                    .map_err(|_| X64NativeRunnerError::InputSpanOverflow { parameter })?;
                if length > i64::MAX as u64 {
                    return Err(X64NativeRunnerError::InputSpanOverflow { parameter });
                }
                let data = values.as_ptr() as usize as u64;
                let bytes = length
                    .checked_mul(8)
                    .ok_or(X64NativeRunnerError::InputSpanOverflow { parameter })?;
                let end = data
                    .checked_add(bytes)
                    .ok_or(X64NativeRunnerError::InputSpanOverflow { parameter })?;
                if length > 0 && data == 0 {
                    return Err(X64NativeRunnerError::InputSpanOverflow { parameter });
                }
                lanes.push(data);
                lanes.push(length);
                arrays.push(ArraySpan {
                    parameter,
                    data,
                    length,
                    end,
                    value,
                });
            }
            _ => {
                return Err(X64NativeRunnerError::InputType {
                    parameter,
                    expected: *ty,
                });
            }
        }
    }
    if lanes.len() > 5 {
        return Err(X64NativeRunnerError::InvalidRunnerEnvelope {
            message: "flattened input exceeds five lanes",
        });
    }
    Ok((lanes, arrays))
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn validate_entry_registers(
    flattened_lanes: usize,
    declared_lanes: usize,
    output_register: X64AbiRegister,
) -> Result<(), X64NativeRunnerError> {
    const REGISTERS: [X64AbiRegister; 6] = [
        X64AbiRegister::Rdi,
        X64AbiRegister::Rsi,
        X64AbiRegister::Rdx,
        X64AbiRegister::Rcx,
        X64AbiRegister::R8,
        X64AbiRegister::R9,
    ];
    if flattened_lanes != declared_lanes
        || flattened_lanes > 5
        || output_register != REGISTERS[flattened_lanes]
    {
        return Err(X64NativeRunnerError::InvalidRunnerEnvelope {
            message: "entry lane count or output register is inconsistent",
        });
    }
    Ok(())
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn validate_output_disjoint(
    arrays: &[ArraySpan<'_>],
    output_start: u64,
) -> Result<(), X64NativeRunnerError> {
    let output_end =
        output_start
            .checked_add(16)
            .ok_or(X64NativeRunnerError::InvalidRunnerEnvelope {
                message: "output span overflows the host address space",
            })?;
    for array in arrays {
        if array.length > 0 && output_start < array.end && array.data < output_end {
            return Err(X64NativeRunnerError::InputOutputOverlap {
                parameter: array.parameter,
            });
        }
    }
    Ok(())
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn decode_output(
    tag: u32,
    result: MachineType,
    output: [u64; 2],
    arrays: &[ArraySpan<'_>],
) -> Result<(EvaluationOutcome, Vec<EffectEvent>), X64NativeRunnerError> {
    match tag {
        0 => {
            let value = match result {
                MachineType::Unit if output == [0, 0] => CoreValue::Unit,
                MachineType::Bool if output[0] <= 1 && output[1] == 0 => {
                    CoreValue::Bool(output[0] == 1)
                }
                MachineType::I64 if output[1] == 0 => CoreValue::I64(output[0] as i64),
                MachineType::F64
                    if output[1] == 0
                        && (!f64::from_bits(output[0]).is_nan()
                            || output[0] == CANONICAL_NAN_BITS) =>
                {
                    CoreValue::F64(f64::from_bits(output[0]))
                }
                MachineType::F64Array => {
                    let Some(array) = arrays
                        .iter()
                        .find(|array| array.data == output[0] && array.length == output[1])
                    else {
                        return Err(X64NativeRunnerError::ForeignArrayResult {
                            data: output[0],
                            length: output[1],
                        });
                    };
                    array.value.clone()
                }
                _ => {
                    return Err(X64NativeRunnerError::NonCanonicalOutput {
                        result,
                        word0: output[0],
                        word1: output[1],
                    });
                }
            };
            Ok((EvaluationOutcome::Return(value), Vec::new()))
        }
        1 if output == [0, 0] => Ok((
            EvaluationOutcome::Error(ErrorKind::Bounds),
            vec![EffectEvent::Error(ErrorKind::Bounds)],
        )),
        1 => Err(X64NativeRunnerError::NonCanonicalOutput {
            result,
            word0: output[0],
            word1: output[1],
        }),
        tag => Err(X64NativeRunnerError::UnknownOutcomeTag { tag }),
    }
}

/// Bind the exact R1-S7a platform descriptor and entry signature without
/// admitting Rust layout or enum discriminants into evidence identity.
pub fn x64_native_canonical_abi_hash(
    target: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
) -> Result<SemanticHash, X64NativeEvidenceError> {
    let program = target.program();
    let mut bytes = X64_NATIVE_ABI_DOMAIN.to_vec();
    // Every descriptor enum has exactly one v1-admitted value. Explicit tags
    // remain stable if Rust later changes its representation.
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    native_put_u16(&mut bytes, program.abi.pointer_bits);
    native_put_u32(&mut bytes, program.abi.canonical_mxcsr);
    native_put_u32(&mut bytes, program.abi.stack_alignment);
    encode_entry_abi(&mut bytes, &program.entry_abi)?;
    Ok(SemanticHash(sha256(&bytes)))
}

/// Seal one completed safe invocation against a canonical Gate A case input.
///
/// The opaque source-bound target is required again at sealing time so a
/// caller cannot turn a locally fabricated execution structure into evidence.
pub fn seal_x64_native_execution_record(
    target: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
    case_execution: &X64NativeCaseExecution,
) -> Result<X64NativeExecutionRecord, X64NativeEvidenceError> {
    let case_ordinal = case_execution.case_ordinal;
    let input_hash = case_execution.input_hash;
    let execution = &case_execution.execution;
    if case_ordinal >= X64_NATIVE_MAX_CORRESPONDENCE_RECORDS {
        return Err(X64NativeEvidenceError::RecordLimit {
            limit: X64_NATIVE_MAX_CORRESPONDENCE_RECORDS,
            actual: case_ordinal,
        });
    }
    require_nonzero_identity("input", input_hash)?;
    validate_execution_against_target(execution, target)?;
    let native = normalize_native_observation(
        "native execution",
        case_ordinal,
        &execution.outcome,
        &execution.effect_trace,
    )?;
    let mut record = X64NativeExecutionRecord {
        evidence_schema_version: X64_NATIVE_EVIDENCE_SCHEMA_VERSION,
        runner_schema_version: execution.runner_schema_version,
        runner_policy_version: execution.runner_policy_version,
        syscall_policy_version: execution.syscall_policy_version,
        entry_policy_version: execution.entry_policy_version,
        limits: execution.limits,
        target_artifact_hash: execution.target_artifact_hash,
        target_plan_hash: execution.target_plan_hash,
        target_code_hash: execution.verified_code_hash,
        source_machine_ir_hash: execution.source_machine_ir_hash,
        entry_offset: execution.entry_offset,
        canonical_abi_hash: x64_native_canonical_abi_hash(target)?,
        input_hash,
        copied_rw_code_hash: execution.copied_rw_code_hash,
        readback_rx_code_hash: execution.readback_rx_code_hash,
        input_lanes: execution.input_lanes,
        mapping_trace: execution.mapping_trace,
        mxcsr_before: execution.mxcsr_before,
        mxcsr_after: execution.mxcsr_after,
        native,
        fallback: execution.fallback,
        record_hash: SemanticHash::ZERO,
    };
    record.record_hash = x64_native_execution_record_hash(&record)?;
    Ok(record)
}

pub fn x64_native_execution_record_hash(
    record: &X64NativeExecutionRecord,
) -> Result<SemanticHash, X64NativeEvidenceError> {
    validate_execution_record_shape(record)?;
    let bytes = encode_execution_record(record)?;
    enforce_record_byte_limit(bytes.len())?;
    Ok(SemanticHash(sha256(&bytes)))
}

pub fn verify_x64_native_execution_record(
    record: &X64NativeExecutionRecord,
) -> Result<(), X64NativeEvidenceError> {
    let actual = x64_native_execution_record_hash(record)?;
    if actual != record.record_hash {
        return Err(X64NativeEvidenceError::ExecutionRecordHashMismatch);
    }
    Ok(())
}

/// Seal one Machine-IR ↔ native observation after the nested execution record
/// and the exact source-bound target identities have been checked.
pub fn seal_x64_native_correspondence_record(
    case: &CoreVmGateACase,
    target: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
    machine_ir: &Evaluation,
    native_execution: X64NativeExecutionRecord,
) -> Result<X64NativeCorrespondenceRecord, X64NativeEvidenceError> {
    let case_ordinal = case.ordinal;
    let regenerated =
        corevm0_gate_a_case_input_hash(case).map_err(X64NativeEvidenceError::CorpusManifest)?;
    if regenerated != case.input_hash {
        return Err(X64NativeEvidenceError::InputHashMismatch { case_ordinal });
    }
    let input_hash = case.input_hash;
    if case_ordinal >= X64_NATIVE_MAX_CORRESPONDENCE_RECORDS {
        return Err(X64NativeEvidenceError::RecordLimit {
            limit: X64_NATIVE_MAX_CORRESPONDENCE_RECORDS,
            actual: case_ordinal,
        });
    }
    verify_x64_native_execution_record(&native_execution)?;
    let artifact = target.artifact();
    if native_execution.input_hash != input_hash {
        return Err(X64NativeEvidenceError::InputHashMismatch { case_ordinal });
    }
    for (field, actual, expected) in [
        (
            "target artifact",
            native_execution.target_artifact_hash,
            artifact.semantic_hash,
        ),
        (
            "target plan",
            native_execution.target_plan_hash,
            artifact.program.plan_hash,
        ),
        (
            "target code",
            native_execution.target_code_hash,
            artifact.program.code_hash,
        ),
        (
            "source Machine IR",
            native_execution.source_machine_ir_hash,
            target.source_machine_ir().semantic_hash,
        ),
    ] {
        if actual != expected {
            return Err(X64NativeEvidenceError::IdentityMismatch { field });
        }
    }
    let machine_ir = normalize_native_observation(
        "Machine IR",
        case_ordinal,
        &machine_ir.outcome,
        &machine_ir.effect_trace,
    )?;
    let native = native_execution.native.clone();
    if machine_ir != native {
        return Err(X64NativeEvidenceError::SemanticMismatch { case_ordinal });
    }
    let mut record = X64NativeCorrespondenceRecord {
        schema_version: X64_NATIVE_EVIDENCE_SCHEMA_VERSION,
        case_ordinal,
        input_hash,
        source_machine_ir_hash: target.source_machine_ir().semantic_hash,
        target_artifact_hash: artifact.semantic_hash,
        target_code_hash: artifact.program.code_hash,
        machine_ir,
        native,
        native_execution,
        record_hash: SemanticHash::ZERO,
    };
    record.record_hash = x64_native_correspondence_record_hash(&record)?;
    Ok(record)
}

pub fn x64_native_correspondence_record_hash(
    record: &X64NativeCorrespondenceRecord,
) -> Result<SemanticHash, X64NativeEvidenceError> {
    validate_correspondence_record_shape(record)?;
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(X64_NATIVE_CORRESPONDENCE_RECORD_DOMAIN);
    native_put_version(&mut bytes, record.schema_version);
    native_put_u32(&mut bytes, record.case_ordinal);
    bytes.extend_from_slice(&record.input_hash.0);
    bytes.extend_from_slice(&record.source_machine_ir_hash.0);
    bytes.extend_from_slice(&record.target_artifact_hash.0);
    bytes.extend_from_slice(&record.target_code_hash.0);
    encode_native_observation(&mut bytes, &record.machine_ir);
    encode_native_observation(&mut bytes, &record.native);
    bytes.extend_from_slice(&record.native_execution.record_hash.0);
    enforce_record_byte_limit(bytes.len())?;
    Ok(SemanticHash(sha256(&bytes)))
}

pub fn verify_x64_native_correspondence_record(
    record: &X64NativeCorrespondenceRecord,
) -> Result<(), X64NativeEvidenceError> {
    let actual = x64_native_correspondence_record_hash(record)?;
    if actual != record.record_hash {
        return Err(X64NativeEvidenceError::CorrespondenceRecordHashMismatch {
            case_ordinal: record.case_ordinal,
        });
    }
    Ok(())
}

/// Compute the order-sensitive identity for exactly the fixed 51-case Gate A
/// corpus. The canonical manifest is regenerated internally; caller-provided
/// manifests or arbitrary input hashes never become authority.
pub fn x64_native_correspondence_results_hash(
    records: &[X64NativeCorrespondenceRecord],
) -> Result<SemanticHash, X64NativeEvidenceError> {
    let manifest_hash = validate_fixed_correspondence_records(records)?;
    let record_count =
        u32::try_from(records.len()).map_err(|_| X64NativeEvidenceError::MetricOverflow)?;
    let mut bytes = Vec::with_capacity(
        X64_NATIVE_CORPUS_RESULTS_DOMAIN.len() + 6 + 32 + 4 + records.len().saturating_mul(32),
    );
    bytes.extend_from_slice(X64_NATIVE_CORPUS_RESULTS_DOMAIN);
    native_put_version(&mut bytes, X64_NATIVE_EVIDENCE_SCHEMA_VERSION);
    bytes.extend_from_slice(&manifest_hash.0);
    native_put_u32(&mut bytes, record_count);
    for record in records {
        bytes.extend_from_slice(&record.record_hash.0);
    }
    Ok(SemanticHash(sha256(&bytes)))
}

pub fn seal_x64_native_correspondence_evidence(
    records: Vec<X64NativeCorrespondenceRecord>,
) -> Result<X64NativeCorrespondenceEvidence, X64NativeEvidenceError> {
    let manifest = corevm0_gate_a_manifest().map_err(X64NativeEvidenceError::CorpusManifest)?;
    let results_hash = x64_native_correspondence_results_hash(&records)?;
    Ok(X64NativeCorrespondenceEvidence {
        schema_version: X64_NATIVE_EVIDENCE_SCHEMA_VERSION,
        corpus_manifest_hash: manifest.manifest_hash,
        records,
        results_hash,
    })
}

pub fn verify_x64_native_correspondence_evidence(
    evidence: &X64NativeCorrespondenceEvidence,
) -> Result<(), X64NativeEvidenceError> {
    if evidence.schema_version != X64_NATIVE_EVIDENCE_SCHEMA_VERSION {
        return Err(X64NativeEvidenceError::InvalidSchema {
            actual: evidence.schema_version,
        });
    }
    let manifest = corevm0_gate_a_manifest().map_err(X64NativeEvidenceError::CorpusManifest)?;
    if evidence.corpus_manifest_hash != manifest.manifest_hash {
        return Err(X64NativeEvidenceError::CorpusManifestHashMismatch);
    }
    if x64_native_correspondence_results_hash(&evidence.records)? != evidence.results_hash {
        return Err(X64NativeEvidenceError::ResultsHashMismatch);
    }
    Ok(())
}

fn validate_execution_against_target(
    execution: &X64NativeExecution,
    target: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
) -> Result<(), X64NativeEvidenceError> {
    validate_policy_versions(
        execution.runner_schema_version,
        execution.runner_policy_version,
        execution.syscall_policy_version,
        execution.entry_policy_version,
    )?;
    if execution.limits != X64NativeLimits::r1_s7b() {
        return Err(X64NativeEvidenceError::InvalidLimits);
    }
    let artifact = target.artifact();
    for (field, actual, expected) in [
        (
            "target artifact",
            execution.target_artifact_hash,
            artifact.semantic_hash,
        ),
        (
            "target plan",
            execution.target_plan_hash,
            artifact.program.plan_hash,
        ),
        (
            "source Machine IR",
            execution.source_machine_ir_hash,
            target.source_machine_ir().semantic_hash,
        ),
        (
            "verified target code",
            execution.verified_code_hash,
            artifact.program.code_hash,
        ),
        (
            "copied RW target code",
            execution.copied_rw_code_hash,
            artifact.program.code_hash,
        ),
        (
            "read-back RX target code",
            execution.readback_rx_code_hash,
            artifact.program.code_hash,
        ),
    ] {
        if actual != expected {
            return Err(X64NativeEvidenceError::IdentityMismatch { field });
        }
    }
    if execution.entry_offset != artifact.program.entry_offset {
        return Err(X64NativeEvidenceError::IdentityMismatch {
            field: "entry offset",
        });
    }
    let expected_lanes = u8::try_from(artifact.program.entry_abi.input_lanes.len())
        .map_err(|_| X64NativeEvidenceError::MetricOverflow)?;
    if execution.input_lanes != expected_lanes {
        return Err(X64NativeEvidenceError::IdentityMismatch {
            field: "entry lane count",
        });
    }
    validate_mapping_and_numeric_state(
        execution.mapping_trace,
        execution.mxcsr_before,
        execution.mxcsr_after,
        execution.fallback,
    )?;
    if execution.mxcsr_before != artifact.program.abi.canonical_mxcsr {
        return Err(X64NativeEvidenceError::NonCanonicalClaimMxcsr {
            expected: artifact.program.abi.canonical_mxcsr,
            actual: execution.mxcsr_before,
        });
    }
    Ok(())
}

fn validate_execution_record_shape(
    record: &X64NativeExecutionRecord,
) -> Result<(), X64NativeEvidenceError> {
    if record.evidence_schema_version != X64_NATIVE_EVIDENCE_SCHEMA_VERSION {
        return Err(X64NativeEvidenceError::InvalidSchema {
            actual: record.evidence_schema_version,
        });
    }
    validate_policy_versions(
        record.runner_schema_version,
        record.runner_policy_version,
        record.syscall_policy_version,
        record.entry_policy_version,
    )?;
    if record.limits != X64NativeLimits::r1_s7b() {
        return Err(X64NativeEvidenceError::InvalidLimits);
    }
    for (field, identity) in [
        ("target artifact", record.target_artifact_hash),
        ("target plan", record.target_plan_hash),
        ("target code", record.target_code_hash),
        ("source Machine IR", record.source_machine_ir_hash),
        ("canonical ABI", record.canonical_abi_hash),
        ("input", record.input_hash),
        ("copied RW target code", record.copied_rw_code_hash),
        ("read-back RX target code", record.readback_rx_code_hash),
    ] {
        require_nonzero_identity(field, identity)?;
    }
    if record.target_code_hash != record.copied_rw_code_hash
        || record.target_code_hash != record.readback_rx_code_hash
    {
        return Err(X64NativeEvidenceError::IdentityMismatch {
            field: "copied target code",
        });
    }
    if record.entry_offset != 0 || u32::from(record.input_lanes) > X64_NATIVE_MAX_ENTRY_LANES {
        return Err(X64NativeEvidenceError::IdentityMismatch { field: "entry ABI" });
    }
    validate_mapping_and_numeric_state(
        record.mapping_trace,
        record.mxcsr_before,
        record.mxcsr_after,
        record.fallback,
    )?;
    let canonical_mxcsr = X64TargetAbi::r1_s7a().canonical_mxcsr;
    if record.mxcsr_before != canonical_mxcsr {
        return Err(X64NativeEvidenceError::NonCanonicalClaimMxcsr {
            expected: canonical_mxcsr,
            actual: record.mxcsr_before,
        });
    }
    validate_native_observation("native execution", 0, &record.native)
}

fn validate_policy_versions(
    runner_schema: (u16, u16, u16),
    runner_policy: (u16, u16, u16),
    syscall_policy: (u16, u16, u16),
    entry_policy: (u16, u16, u16),
) -> Result<(), X64NativeEvidenceError> {
    for (field, actual, expected) in [
        (
            "runner schema",
            runner_schema,
            X64_NATIVE_RUNNER_SCHEMA_VERSION,
        ),
        ("runner", runner_policy, X64_NATIVE_RUNNER_POLICY_VERSION),
        ("syscall", syscall_policy, X64_NATIVE_SYSCALL_POLICY_VERSION),
        ("entry", entry_policy, X64_NATIVE_ENTRY_POLICY_VERSION),
    ] {
        if actual != expected {
            return Err(X64NativeEvidenceError::InvalidPolicy { field, actual });
        }
    }
    Ok(())
}

fn validate_mapping_and_numeric_state(
    mapping_trace: [X64NativeMappingState; 4],
    mxcsr_before: u32,
    mxcsr_after: u32,
    fallback: bool,
) -> Result<(), X64NativeEvidenceError> {
    if mapping_trace
        != [
            X64NativeMappingState::Unmapped,
            X64NativeMappingState::ReadWrite,
            X64NativeMappingState::ReadExecute,
            X64NativeMappingState::Unmapped,
        ]
    {
        return Err(X64NativeEvidenceError::InvalidMappingTrace);
    }
    if mxcsr_before != mxcsr_after {
        return Err(X64NativeEvidenceError::MxcsrNotRestored {
            before: mxcsr_before,
            after: mxcsr_after,
        });
    }
    if fallback {
        return Err(X64NativeEvidenceError::FallbackObserved);
    }
    Ok(())
}

fn validate_correspondence_record_shape(
    record: &X64NativeCorrespondenceRecord,
) -> Result<(), X64NativeEvidenceError> {
    if record.schema_version != X64_NATIVE_EVIDENCE_SCHEMA_VERSION {
        return Err(X64NativeEvidenceError::InvalidSchema {
            actual: record.schema_version,
        });
    }
    if record.case_ordinal >= X64_NATIVE_MAX_CORRESPONDENCE_RECORDS {
        return Err(X64NativeEvidenceError::RecordLimit {
            limit: X64_NATIVE_MAX_CORRESPONDENCE_RECORDS,
            actual: record.case_ordinal,
        });
    }
    verify_x64_native_execution_record(&record.native_execution)?;
    for (field, outer, nested) in [
        (
            "input",
            record.input_hash,
            record.native_execution.input_hash,
        ),
        (
            "source Machine IR",
            record.source_machine_ir_hash,
            record.native_execution.source_machine_ir_hash,
        ),
        (
            "target artifact",
            record.target_artifact_hash,
            record.native_execution.target_artifact_hash,
        ),
        (
            "target code",
            record.target_code_hash,
            record.native_execution.target_code_hash,
        ),
    ] {
        if outer != nested {
            return Err(X64NativeEvidenceError::IdentityMismatch { field });
        }
    }
    validate_native_observation("Machine IR", record.case_ordinal, &record.machine_ir)?;
    validate_native_observation("native execution", record.case_ordinal, &record.native)?;
    if record.native != record.native_execution.native {
        return Err(X64NativeEvidenceError::IdentityMismatch {
            field: "nested native observation",
        });
    }
    if record.machine_ir != record.native {
        return Err(X64NativeEvidenceError::SemanticMismatch {
            case_ordinal: record.case_ordinal,
        });
    }
    Ok(())
}

fn validate_fixed_correspondence_records(
    records: &[X64NativeCorrespondenceRecord],
) -> Result<SemanticHash, X64NativeEvidenceError> {
    let record_count =
        u32::try_from(records.len()).map_err(|_| X64NativeEvidenceError::MetricOverflow)?;
    if record_count > X64_NATIVE_MAX_CORRESPONDENCE_RECORDS {
        return Err(X64NativeEvidenceError::RecordLimit {
            limit: X64_NATIVE_MAX_CORRESPONDENCE_RECORDS,
            actual: record_count,
        });
    }
    if record_count != X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS {
        return Err(X64NativeEvidenceError::FixedCorpusCount {
            expected: X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS,
            actual: record_count,
        });
    }
    let manifest = corevm0_gate_a_manifest().map_err(X64NativeEvidenceError::CorpusManifest)?;
    if manifest.total_cases != X64_NATIVE_FIXED_LIGHTHOUSE_RECORDS
        || manifest.cases.len() != records.len()
    {
        return Err(X64NativeEvidenceError::CorpusManifestHashMismatch);
    }

    type TargetIdentity = (
        SemanticHash,
        SemanticHash,
        SemanticHash,
        SemanticHash,
        SemanticHash,
    );
    let mut branch_identity: Option<TargetIdentity> = None;
    let mut bounds_identity: Option<TargetIdentity> = None;
    for (expected_ordinal, (case, record)) in manifest.cases.iter().zip(records).enumerate() {
        let expected_ordinal =
            u32::try_from(expected_ordinal).map_err(|_| X64NativeEvidenceError::MetricOverflow)?;
        if record.case_ordinal != expected_ordinal || case.ordinal != expected_ordinal {
            return Err(X64NativeEvidenceError::NonCanonicalOrdinal {
                expected: expected_ordinal,
                actual: record.case_ordinal,
            });
        }
        if record.input_hash != case.input_hash {
            return Err(X64NativeEvidenceError::InputHashMismatch {
                case_ordinal: expected_ordinal,
            });
        }
        verify_x64_native_correspondence_record(record)?;
        let identity = (
            record.source_machine_ir_hash,
            record.target_artifact_hash,
            record.native_execution.target_plan_hash,
            record.target_code_hash,
            record.native_execution.canonical_abi_hash,
        );
        let workload_identity = match case.workload {
            CoreVmGateAWorkload::BranchMix => &mut branch_identity,
            CoreVmGateAWorkload::BoundsOrderedArrayGet => &mut bounds_identity,
        };
        match workload_identity {
            Some(expected) if *expected != identity => {
                return Err(X64NativeEvidenceError::MixedTargetArtifact {
                    case_ordinal: expected_ordinal,
                });
            }
            Some(_) => {}
            None => *workload_identity = Some(identity),
        }
    }
    Ok(manifest.manifest_hash)
}

fn normalize_native_observation(
    engine: &'static str,
    case_ordinal: u32,
    outcome: &EvaluationOutcome,
    effect_trace: &[EffectEvent],
) -> Result<X64NativeCorrespondenceObservation, X64NativeEvidenceError> {
    let outcome = match outcome {
        EvaluationOutcome::Return(CoreValue::F64(value)) if value.is_nan() => {
            X64NativeCorrespondenceOutcome::ReturnF64(X64NativeCorrespondenceF64::CanonicalNaN)
        }
        EvaluationOutcome::Return(CoreValue::F64(value)) => {
            X64NativeCorrespondenceOutcome::ReturnF64(X64NativeCorrespondenceF64::ExactBits(
                value.to_bits(),
            ))
        }
        EvaluationOutcome::Error(ErrorKind::Bounds) => X64NativeCorrespondenceOutcome::Bounds,
        _ => {
            return Err(X64NativeEvidenceError::UnsupportedOutcome {
                engine,
                case_ordinal,
            });
        }
    };
    let effect_count =
        u32::try_from(effect_trace.len()).map_err(|_| X64NativeEvidenceError::MetricOverflow)?;
    if effect_count > X64_NATIVE_MAX_EFFECTS_PER_ENGINE {
        return Err(X64NativeEvidenceError::EffectLimit {
            engine,
            case_ordinal,
            limit: X64_NATIVE_MAX_EFFECTS_PER_ENGINE,
            actual: effect_count,
        });
    }
    let effect_trace = effect_trace
        .iter()
        .map(|effect| match effect {
            EffectEvent::Error(ErrorKind::Bounds) => Ok(X64NativeCorrespondenceEffect::Bounds),
            _ => Err(X64NativeEvidenceError::UnsupportedEffect {
                engine,
                case_ordinal,
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let observation = X64NativeCorrespondenceObservation {
        outcome,
        effect_trace,
    };
    validate_native_observation(engine, case_ordinal, &observation)?;
    Ok(observation)
}

fn validate_native_observation(
    engine: &'static str,
    case_ordinal: u32,
    observation: &X64NativeCorrespondenceObservation,
) -> Result<(), X64NativeEvidenceError> {
    let effect_count = u32::try_from(observation.effect_trace.len())
        .map_err(|_| X64NativeEvidenceError::MetricOverflow)?;
    if effect_count > X64_NATIVE_MAX_EFFECTS_PER_ENGINE {
        return Err(X64NativeEvidenceError::EffectLimit {
            engine,
            case_ordinal,
            limit: X64_NATIVE_MAX_EFFECTS_PER_ENGINE,
            actual: effect_count,
        });
    }
    let canonical = match observation.outcome {
        X64NativeCorrespondenceOutcome::ReturnF64(X64NativeCorrespondenceF64::ExactBits(bits)) => {
            !f64::from_bits(bits).is_nan() && observation.effect_trace.is_empty()
        }
        X64NativeCorrespondenceOutcome::ReturnF64(X64NativeCorrespondenceF64::CanonicalNaN) => {
            observation.effect_trace.is_empty()
        }
        X64NativeCorrespondenceOutcome::Bounds => {
            observation.effect_trace == [X64NativeCorrespondenceEffect::Bounds]
        }
    };
    if !canonical {
        return Err(X64NativeEvidenceError::NonCanonicalObservation {
            engine,
            case_ordinal,
        });
    }
    Ok(())
}

fn encode_execution_record(
    record: &X64NativeExecutionRecord,
) -> Result<Vec<u8>, X64NativeEvidenceError> {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(X64_NATIVE_EXECUTION_RECORD_DOMAIN);
    native_put_version(&mut bytes, record.evidence_schema_version);
    native_put_version(&mut bytes, record.runner_schema_version);
    native_put_version(&mut bytes, record.runner_policy_version);
    native_put_version(&mut bytes, record.syscall_policy_version);
    native_put_version(&mut bytes, record.entry_policy_version);
    encode_native_limits(&mut bytes, record.limits);
    bytes.extend_from_slice(&record.target_artifact_hash.0);
    bytes.extend_from_slice(&record.target_plan_hash.0);
    bytes.extend_from_slice(&record.target_code_hash.0);
    bytes.extend_from_slice(&record.source_machine_ir_hash.0);
    native_put_u32(&mut bytes, record.entry_offset);
    bytes.extend_from_slice(&record.canonical_abi_hash.0);
    bytes.extend_from_slice(&record.input_hash.0);
    bytes.extend_from_slice(&record.copied_rw_code_hash.0);
    bytes.extend_from_slice(&record.readback_rx_code_hash.0);
    bytes.push(record.input_lanes);
    native_put_u32(&mut bytes, X64_NATIVE_MAPPING_STATE_EVENTS);
    for state in record.mapping_trace {
        bytes.push(mapping_state_tag(state));
    }
    native_put_u32(&mut bytes, record.mxcsr_before);
    native_put_u32(&mut bytes, record.mxcsr_after);
    encode_native_observation(&mut bytes, &record.native);
    bytes.push(u8::from(record.fallback));
    Ok(bytes)
}

fn encode_entry_abi(
    bytes: &mut Vec<u8>,
    entry: &X64EntryAbi,
) -> Result<(), X64NativeEvidenceError> {
    native_put_len(bytes, entry.parameter_types.len())?;
    for ty in &entry.parameter_types {
        bytes.push(machine_type_tag(*ty));
    }
    native_put_len(bytes, entry.input_lanes.len())?;
    for lane in &entry.input_lanes {
        native_put_u32(bytes, lane.parameter);
        bytes.push(lane.word);
        bytes.push(abi_register_tag(lane.register));
    }
    bytes.push(abi_register_tag(entry.output_register));
    bytes.push(machine_type_tag(entry.result));
    bytes.push(entry.output_words);
    Ok(())
}

fn encode_native_limits(bytes: &mut Vec<u8>, limits: X64NativeLimits) {
    native_put_u32(bytes, limits.code_mappings_per_invocation);
    native_put_u64(bytes, limits.max_mapping_bytes);
    native_put_u32(bytes, limits.max_entry_lanes);
    native_put_u32(bytes, limits.max_borrowed_f64_arrays);
    native_put_u32(bytes, limits.output_words);
    native_put_u32(bytes, limits.mapping_state_events);
    native_put_u32(bytes, limits.max_effects_per_engine);
    native_put_u32(bytes, limits.max_correspondence_records);
    native_put_u32(bytes, limits.fixed_lighthouse_records);
    native_put_u32(bytes, limits.max_record_bytes);
    native_put_u32(bytes, limits.max_diagnostics);
}

fn encode_native_observation(
    bytes: &mut Vec<u8>,
    observation: &X64NativeCorrespondenceObservation,
) {
    match observation.outcome {
        X64NativeCorrespondenceOutcome::ReturnF64(X64NativeCorrespondenceF64::ExactBits(bits)) => {
            bytes.push(0);
            native_put_u64(bytes, bits);
        }
        X64NativeCorrespondenceOutcome::ReturnF64(X64NativeCorrespondenceF64::CanonicalNaN) => {
            bytes.push(1)
        }
        X64NativeCorrespondenceOutcome::Bounds => bytes.push(2),
    }
    native_put_u32(bytes, observation.effect_trace.len() as u32);
    for effect in &observation.effect_trace {
        bytes.push(match effect {
            X64NativeCorrespondenceEffect::Bounds => 0,
        });
    }
}

fn require_nonzero_identity(
    field: &'static str,
    identity: SemanticHash,
) -> Result<(), X64NativeEvidenceError> {
    if identity == SemanticHash::ZERO {
        Err(X64NativeEvidenceError::InvalidIdentity { field })
    } else {
        Ok(())
    }
}

fn enforce_record_byte_limit(length: usize) -> Result<(), X64NativeEvidenceError> {
    let actual = u32::try_from(length).map_err(|_| X64NativeEvidenceError::MetricOverflow)?;
    if actual > X64_NATIVE_MAX_RECORD_BYTES {
        return Err(X64NativeEvidenceError::RecordByteLimit {
            limit: X64_NATIVE_MAX_RECORD_BYTES,
            actual,
        });
    }
    Ok(())
}

fn machine_type_tag(ty: MachineType) -> u8 {
    match ty {
        MachineType::Unit => 0,
        MachineType::Bool => 1,
        MachineType::I64 => 2,
        MachineType::F64 => 3,
        MachineType::F64Array => 4,
    }
}

fn abi_register_tag(register: X64AbiRegister) -> u8 {
    match register {
        X64AbiRegister::Rdi => 0,
        X64AbiRegister::Rsi => 1,
        X64AbiRegister::Rdx => 2,
        X64AbiRegister::Rcx => 3,
        X64AbiRegister::R8 => 4,
        X64AbiRegister::R9 => 5,
    }
}

fn mapping_state_tag(state: X64NativeMappingState) -> u8 {
    match state {
        X64NativeMappingState::Unmapped => 0,
        X64NativeMappingState::ReadWrite => 1,
        X64NativeMappingState::ReadExecute => 2,
    }
}

fn native_put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    native_put_u16(bytes, version.0);
    native_put_u16(bytes, version.1);
    native_put_u16(bytes, version.2);
}

fn native_put_len(bytes: &mut Vec<u8>, length: usize) -> Result<(), X64NativeEvidenceError> {
    let length = u32::try_from(length).map_err(|_| X64NativeEvidenceError::MetricOverflow)?;
    native_put_u32(bytes, length);
    Ok(())
}

fn native_put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn native_put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn native_put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod platform {
    use super::X64NativeRunnerError;
    use std::arch::asm;
    use std::sync::atomic::{fence, Ordering};

    const SYS_MMAP: usize = 9;
    const SYS_MPROTECT: usize = 10;
    const SYS_MUNMAP: usize = 11;

    const PROT_READ: usize = 0x1;
    const PROT_WRITE: usize = 0x2;
    const PROT_EXEC: usize = 0x4;
    const MAP_PRIVATE: usize = 0x02;
    const MAP_ANONYMOUS: usize = 0x20;

    pub(super) struct NativeMapping {
        pointer: *mut u8,
        length: usize,
        rx: bool,
    }

    impl NativeMapping {
        pub(super) fn allocate(length: usize) -> Result<Self, X64NativeRunnerError> {
            // SAFETY: raw Linux syscall ABI with scalar arguments only.
            let result = unsafe {
                syscall6(
                    SYS_MMAP,
                    0,
                    length,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    usize::MAX,
                    0,
                )
            };
            let pointer = syscall_pointer("mmap", result)?;
            if pointer.is_null() {
                return Err(X64NativeRunnerError::MappingFailed {
                    operation: "mmap",
                    errno: 0,
                });
            }
            Ok(Self {
                pointer,
                length,
                rx: false,
            })
        }

        pub(super) fn copy_from(&mut self, code: &[u8]) {
            debug_assert_eq!(code.len(), self.length);
            // SAFETY: the mapping is RW and exactly `self.length` bytes; the
            // source slice has the same length and cannot overlap it.
            unsafe {
                std::ptr::copy_nonoverlapping(code.as_ptr(), self.pointer, self.length);
            }
            fence(Ordering::SeqCst);
        }

        pub(super) fn protect_rx(&mut self) -> Result<(), X64NativeRunnerError> {
            // SAFETY: the mapping came from mmap and remains live.
            let result = unsafe {
                syscall6(
                    SYS_MPROTECT,
                    self.pointer as usize,
                    self.length,
                    PROT_READ | PROT_EXEC,
                    0,
                    0,
                    0,
                )
            };
            syscall_unit("mprotect", result)?;
            self.rx = true;
            fence(Ordering::SeqCst);
            Ok(())
        }

        pub(super) fn bytes(&self) -> &[u8] {
            // SAFETY: the live mapping is readable in both RW and RX states.
            unsafe { std::slice::from_raw_parts(self.pointer, self.length) }
        }

        pub(super) fn entry(&self, offset: u32) -> *const u8 {
            debug_assert!(self.rx);
            // SAFETY: the caller verified `offset` lies in the code blob.
            unsafe { self.pointer.add(offset as usize) as *const u8 }
        }

        pub(super) fn unmap(&mut self) -> Result<(), X64NativeRunnerError> {
            if self.pointer.is_null() {
                return Ok(());
            }
            // SAFETY: the mapping came from mmap and has not been unmapped.
            let result =
                unsafe { syscall6(SYS_MUNMAP, self.pointer as usize, self.length, 0, 0, 0, 0) };
            syscall_unit("munmap", result)?;
            self.pointer = std::ptr::null_mut();
            self.length = 0;
            self.rx = false;
            Ok(())
        }
    }

    impl Drop for NativeMapping {
        fn drop(&mut self) {
            if !self.pointer.is_null() {
                // SAFETY: best-effort cleanup of the still-live mapping.
                let _ =
                    unsafe { syscall6(SYS_MUNMAP, self.pointer as usize, self.length, 0, 0, 0, 0) };
            }
        }
    }

    fn syscall_pointer(
        operation: &'static str,
        result: isize,
    ) -> Result<*mut u8, X64NativeRunnerError> {
        if let Some(errno) = syscall_errno(result) {
            Err(X64NativeRunnerError::MappingFailed { operation, errno })
        } else {
            Ok(result as usize as *mut u8)
        }
    }

    fn syscall_unit(operation: &'static str, result: isize) -> Result<(), X64NativeRunnerError> {
        if let Some(errno) = syscall_errno(result) {
            Err(X64NativeRunnerError::MappingFailed { operation, errno })
        } else if result == 0 {
            Ok(())
        } else {
            Err(X64NativeRunnerError::MappingFailed {
                operation,
                errno: 0,
            })
        }
    }

    fn syscall_errno(result: isize) -> Option<i32> {
        (-4095..=-1).contains(&result).then_some((-result) as i32)
    }

    unsafe fn syscall6(
        number: usize,
        argument0: usize,
        argument1: usize,
        argument2: usize,
        argument3: usize,
        argument4: usize,
        argument5: usize,
    ) -> isize {
        let mut result = number as isize;
        // SAFETY: the operands follow the Linux x86-64 syscall ABI. `syscall`
        // always clobbers RCX and R11. Omitting `nomem` makes this a compiler
        // memory barrier for mapping/protection operations.
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") result,
                in("rdi") argument0,
                in("rsi") argument1,
                in("rdx") argument2,
                in("r10") argument3,
                in("r8") argument4,
                in("r9") argument5,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        result
    }

    pub(super) fn read_mxcsr() -> u32 {
        let mut value = 0_u32;
        // SAFETY: `stmxcsr` writes exactly four bytes to an aligned Rust local.
        unsafe {
            asm!(
                "stmxcsr [{pointer}]",
                pointer = in(reg) &mut value,
                options(nostack, preserves_flags),
            );
        }
        value
    }

    pub(super) unsafe fn call_entry(entry: *const u8, lanes: &[u64], output: *mut u64) -> u32 {
        type Entry0 = unsafe extern "C" fn(*mut u64) -> u32;
        type Entry1 = unsafe extern "C" fn(u64, *mut u64) -> u32;
        type Entry2 = unsafe extern "C" fn(u64, u64, *mut u64) -> u32;
        type Entry3 = unsafe extern "C" fn(u64, u64, u64, *mut u64) -> u32;
        type Entry4 = unsafe extern "C" fn(u64, u64, u64, u64, *mut u64) -> u32;
        type Entry5 = unsafe extern "C" fn(u64, u64, u64, u64, u64, *mut u64) -> u32;

        match lanes {
            [] => {
                // SAFETY: the caller proves the entry has the zero-lane ABI.
                let function = unsafe { std::mem::transmute::<*const u8, Entry0>(entry) };
                unsafe { function(output) }
            }
            [a0] => {
                // SAFETY: the caller proves the entry has the one-lane ABI.
                let function = unsafe { std::mem::transmute::<*const u8, Entry1>(entry) };
                unsafe { function(*a0, output) }
            }
            [a0, a1] => {
                // SAFETY: the caller proves the entry has the two-lane ABI.
                let function = unsafe { std::mem::transmute::<*const u8, Entry2>(entry) };
                unsafe { function(*a0, *a1, output) }
            }
            [a0, a1, a2] => {
                // SAFETY: the caller proves the entry has the three-lane ABI.
                let function = unsafe { std::mem::transmute::<*const u8, Entry3>(entry) };
                unsafe { function(*a0, *a1, *a2, output) }
            }
            [a0, a1, a2, a3] => {
                // SAFETY: the caller proves the entry has the four-lane ABI.
                let function = unsafe { std::mem::transmute::<*const u8, Entry4>(entry) };
                unsafe { function(*a0, *a1, *a2, *a3, output) }
            }
            [a0, a1, a2, a3, a4] => {
                // SAFETY: the caller proves the entry has the five-lane ABI.
                let function = unsafe { std::mem::transmute::<*const u8, Entry5>(entry) };
                unsafe { function(*a0, *a1, *a2, *a3, *a4, output) }
            }
            _ => unreachable!("R1-S7b preflight admits at most five lanes"),
        }
    }
}
