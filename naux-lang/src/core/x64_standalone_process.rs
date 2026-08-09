//! Direct-process finite correspondence evidence for R1-S8c.
//!
//! This layer launches only independently verified standalone ELF views.  It
//! never treats a path, copied image, process status, or caller-supplied hash
//! as execution authority.  Every canonical Gate A case receives one fresh
//! process, one exact input frame followed by EOF, bounded concurrent pipe
//! capture, and one independent source-bound Machine-IR evaluation.

use super::corevm0_gate_a::{
    corevm0_gate_a_case_input_hash, corevm0_gate_a_manifest, CoreVmGateACase, CoreVmGateACaseClass,
    CoreVmGateAError, CoreVmGateAWorkload, COREVM0_GATE_A_BOUNDS_CASES,
    COREVM0_GATE_A_CALL_DEPTH_LIMIT, COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
    COREVM0_GATE_A_TOTAL_CASES,
};
use super::encoding::sha256;
use super::interpret::{CoreValue, EffectEvent, Evaluation, EvaluationBudget, EvaluationOutcome};
use super::machine_ir::evaluate_machine_ir_translation;
use super::schema::{ErrorKind, SemanticHash};
use super::x64_standalone_artifact::{
    verify_x64_standalone_artifact_r1_s8, VerifiedX64StandaloneArtifact, X64StandaloneArtifactError,
};
use super::x64_standalone_authority::{X64StandaloneAuthorityError, X64StandaloneSeedAuthority};
use super::x64_standalone_protocol::{
    decode_x64_standalone_output_for_profile, encode_x64_standalone_input,
    encode_x64_standalone_output, X64StandaloneInput, X64StandaloneOutcome, X64StandaloneOutput,
    X64StandaloneProfile, X64StandaloneProtocolError, X64_STANDALONE_OUTPUT_BYTES,
};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const X64_STANDALONE_EXECUTION_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_STANDALONE_EXECUTION_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_STANDALONE_EXECUTION_RESULTS_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_STANDALONE_PROCESS_TIMEOUT_MILLIS: u32 = 30_000;
pub const X64_STANDALONE_PROCESS_MAX_DIAGNOSTIC_BYTES: u32 = 16_384;
pub const X64_STANDALONE_PROCESS_MAX_DIAGNOSTIC_RECORDS: u32 = 128;
pub const X64_STANDALONE_PROCESS_EXECUTABLE_MODE: u32 = 0o500;

pub const X64_STANDALONE_EXECUTION_RECORD_DOMAIN: &[u8] =
    b"NAUX:x86-64:r1-s8:execution:record:v1\0";
pub const X64_STANDALONE_EXECUTION_RESULTS_DOMAIN: &[u8] =
    b"NAUX:x86-64:r1-s8:execution:results:v1\0";
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const PROCESS_REAP_TIMEOUT: Duration = Duration::from_secs(1);
const PIPE_TASK_JOIN_TIMEOUT: Duration = Duration::from_secs(1);
const TEMP_CREATE_ATTEMPTS: u32 = 128;
const TEMP_CREATE_MODE: u32 = 0o600;
const BRANCH_CASES: u32 = COREVM0_GATE_A_TOTAL_CASES - COREVM0_GATE_A_BOUNDS_CASES;
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Exact finite semantic observation carried on both sides of one R1-S8c
/// correspondence comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64StandaloneExecutionObservation {
    outcome: X64StandaloneExecutionOutcome,
    effects: Vec<X64StandaloneExecutionEffect>,
}

impl X64StandaloneExecutionObservation {
    pub const fn outcome(&self) -> X64StandaloneExecutionOutcome {
        self.outcome
    }

    pub fn effects(&self) -> &[X64StandaloneExecutionEffect] {
        &self.effects
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64StandaloneExecutionOutcome {
    ReturnF64(X64StandaloneExecutionF64),
    Bounds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64StandaloneExecutionF64 {
    ExactBits(u64),
    CanonicalNaN,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64StandaloneExecutionEffect {
    Bounds,
}

/// One admitted fresh-process execution.
///
/// PID, temporary path, filesystem metadata, ASLR addresses, elapsed time,
/// errno text, and parent diagnostics are intentionally absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64StandaloneExecutionRecord {
    execution_schema_version: (u16, u16, u16),
    execution_policy_version: (u16, u16, u16),
    case_ordinal: u32,
    total_cases: u32,
    manifest_hash: SemanticHash,
    profile: X64StandaloneProfile,
    case_class: CoreVmGateACaseClass,
    gate_a_input_hash: SemanticHash,
    source_core_hash: SemanticHash,
    source_ssa_hash: SemanticHash,
    source_machine_ir_hash: SemanticHash,
    target_artifact_hash: SemanticHash,
    target_plan_hash: SemanticHash,
    target_code_hash: SemanticHash,
    canonical_abi_hash: SemanticHash,
    target_entry_offset: u32,
    target_input_lanes: u8,
    inherited_semantic_results_hash: SemanticHash,
    inherited_process_results_hash: SemanticHash,
    standalone_artifact_hash: SemanticHash,
    elf_image_hash: SemanticHash,
    startup_plan_hash: SemanticHash,
    startup_code_hash: SemanticHash,
    io_contract_hash: SemanticHash,
    input_frame_bytes: u64,
    input_frame_hash: SemanticHash,
    normal_exit_code: u32,
    output_frame: [u8; X64_STANDALONE_OUTPUT_BYTES],
    output_frame_hash: SemanticHash,
    standalone: X64StandaloneExecutionObservation,
    machine_ir: X64StandaloneExecutionObservation,
    stdout_bytes: u64,
    stderr_bytes: u64,
    per_process_timeout_ms: u32,
    max_captured_diagnostic_bytes: u32,
    max_captured_diagnostic_records: u32,
    timeout: bool,
    fault: bool,
    abnormal_status: bool,
    interpreter_dependency: bool,
    external_symbol_dependency: bool,
    dynamic_loader_dependency: bool,
    system_linker_dependency: bool,
    fallback: bool,
    record_hash: SemanticHash,
}

impl X64StandaloneExecutionRecord {
    pub const fn execution_schema_version(&self) -> (u16, u16, u16) {
        self.execution_schema_version
    }

    pub const fn execution_policy_version(&self) -> (u16, u16, u16) {
        self.execution_policy_version
    }

    pub const fn case_ordinal(&self) -> u32 {
        self.case_ordinal
    }

    pub const fn total_cases(&self) -> u32 {
        self.total_cases
    }

    pub const fn manifest_hash(&self) -> SemanticHash {
        self.manifest_hash
    }

    pub const fn profile(&self) -> X64StandaloneProfile {
        self.profile
    }

    pub const fn case_class(&self) -> CoreVmGateACaseClass {
        self.case_class
    }

    pub const fn gate_a_input_hash(&self) -> SemanticHash {
        self.gate_a_input_hash
    }

    pub const fn source_core_hash(&self) -> SemanticHash {
        self.source_core_hash
    }

    pub const fn source_ssa_hash(&self) -> SemanticHash {
        self.source_ssa_hash
    }

    pub const fn source_machine_ir_hash(&self) -> SemanticHash {
        self.source_machine_ir_hash
    }

    pub const fn target_artifact_hash(&self) -> SemanticHash {
        self.target_artifact_hash
    }

    pub const fn target_plan_hash(&self) -> SemanticHash {
        self.target_plan_hash
    }

    pub const fn target_code_hash(&self) -> SemanticHash {
        self.target_code_hash
    }

    pub const fn canonical_abi_hash(&self) -> SemanticHash {
        self.canonical_abi_hash
    }

    pub const fn target_entry_offset(&self) -> u32 {
        self.target_entry_offset
    }

    pub const fn target_input_lanes(&self) -> u8 {
        self.target_input_lanes
    }

    pub const fn inherited_semantic_results_hash(&self) -> SemanticHash {
        self.inherited_semantic_results_hash
    }

    pub const fn inherited_process_results_hash(&self) -> SemanticHash {
        self.inherited_process_results_hash
    }

    pub const fn input_frame_bytes(&self) -> u64 {
        self.input_frame_bytes
    }

    pub const fn input_frame_hash(&self) -> SemanticHash {
        self.input_frame_hash
    }

    pub const fn output_frame_hash(&self) -> SemanticHash {
        self.output_frame_hash
    }

    pub const fn output_frame(&self) -> &[u8; X64_STANDALONE_OUTPUT_BYTES] {
        &self.output_frame
    }

    pub const fn standalone_observation(&self) -> &X64StandaloneExecutionObservation {
        &self.standalone
    }

    pub const fn machine_ir_observation(&self) -> &X64StandaloneExecutionObservation {
        &self.machine_ir
    }

    pub const fn standalone_artifact_hash(&self) -> SemanticHash {
        self.standalone_artifact_hash
    }

    pub const fn elf_image_hash(&self) -> SemanticHash {
        self.elf_image_hash
    }

    pub const fn startup_plan_hash(&self) -> SemanticHash {
        self.startup_plan_hash
    }

    pub const fn startup_code_hash(&self) -> SemanticHash {
        self.startup_code_hash
    }

    pub const fn io_contract_hash(&self) -> SemanticHash {
        self.io_contract_hash
    }

    pub const fn stdout_bytes(&self) -> u64 {
        self.stdout_bytes
    }

    pub const fn stderr_bytes(&self) -> u64 {
        self.stderr_bytes
    }

    pub const fn normal_exit_code(&self) -> u32 {
        self.normal_exit_code
    }

    pub const fn per_process_timeout_ms(&self) -> u32 {
        self.per_process_timeout_ms
    }

    pub const fn max_captured_diagnostic_bytes(&self) -> u32 {
        self.max_captured_diagnostic_bytes
    }

    pub const fn max_captured_diagnostic_records(&self) -> u32 {
        self.max_captured_diagnostic_records
    }

    pub const fn timeout(&self) -> bool {
        self.timeout
    }

    pub const fn fault(&self) -> bool {
        self.fault
    }

    pub const fn abnormal_status(&self) -> bool {
        self.abnormal_status
    }

    pub const fn record_hash(&self) -> SemanticHash {
        self.record_hash
    }

    pub const fn fallback(&self) -> bool {
        self.fallback
    }

    pub const fn interpreter_dependency(&self) -> bool {
        self.interpreter_dependency
    }

    pub const fn external_symbol_dependency(&self) -> bool {
        self.external_symbol_dependency
    }

    pub const fn dynamic_loader_dependency(&self) -> bool {
        self.dynamic_loader_dependency
    }

    pub const fn system_linker_dependency(&self) -> bool {
        self.system_linker_dependency
    }
}

/// Exact ordered 46+5 direct-process corpus result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64StandaloneProcessEvidence {
    execution_schema_version: (u16, u16, u16),
    execution_policy_version: (u16, u16, u16),
    results_policy_version: (u16, u16, u16),
    manifest_hash: SemanticHash,
    branch_artifact_hash: SemanticHash,
    branch_elf_image_hash: SemanticHash,
    branch_io_contract_hash: SemanticHash,
    bounds_artifact_hash: SemanticHash,
    bounds_elf_image_hash: SemanticHash,
    bounds_io_contract_hash: SemanticHash,
    records: Vec<X64StandaloneExecutionRecord>,
    results_hash: SemanticHash,
}

impl X64StandaloneProcessEvidence {
    pub const fn execution_schema_version(&self) -> (u16, u16, u16) {
        self.execution_schema_version
    }

    pub const fn execution_policy_version(&self) -> (u16, u16, u16) {
        self.execution_policy_version
    }

    pub const fn results_policy_version(&self) -> (u16, u16, u16) {
        self.results_policy_version
    }

    pub const fn manifest_hash(&self) -> SemanticHash {
        self.manifest_hash
    }

    pub const fn branch_artifact_hash(&self) -> SemanticHash {
        self.branch_artifact_hash
    }

    pub const fn branch_elf_image_hash(&self) -> SemanticHash {
        self.branch_elf_image_hash
    }

    pub const fn branch_io_contract_hash(&self) -> SemanticHash {
        self.branch_io_contract_hash
    }

    pub const fn bounds_artifact_hash(&self) -> SemanticHash {
        self.bounds_artifact_hash
    }

    pub const fn bounds_elf_image_hash(&self) -> SemanticHash {
        self.bounds_elf_image_hash
    }

    pub const fn bounds_io_contract_hash(&self) -> SemanticHash {
        self.bounds_io_contract_hash
    }

    pub fn records(&self) -> &[X64StandaloneExecutionRecord] {
        &self.records
    }

    pub const fn results_hash(&self) -> SemanticHash {
        self.results_hash
    }
}

/// Opaque replay result.  Construction remains available only through the
/// verifier that consumes both live authorities and verified image views.
trait StandaloneAuthorityLifetimeAnchor: fmt::Debug {}

impl StandaloneAuthorityLifetimeAnchor for X64StandaloneSeedAuthority<'_> {}

trait StandaloneArtifactLifetimeAnchor: fmt::Debug {}

impl StandaloneArtifactLifetimeAnchor for VerifiedX64StandaloneArtifact<'_, '_, '_> {}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedX64StandaloneProcessEvidence<
    'evidence,
    'branch_authority,
    'branch_artifact,
    'bounds_authority,
    'bounds_artifact,
> {
    evidence: &'evidence X64StandaloneProcessEvidence,
    _branch_authority: &'branch_authority dyn StandaloneAuthorityLifetimeAnchor,
    _branch_artifact: &'branch_artifact dyn StandaloneArtifactLifetimeAnchor,
    _bounds_authority: &'bounds_authority dyn StandaloneAuthorityLifetimeAnchor,
    _bounds_artifact: &'bounds_artifact dyn StandaloneArtifactLifetimeAnchor,
}

impl<'evidence, 'branch_authority, 'branch_artifact, 'bounds_authority, 'bounds_artifact>
    VerifiedX64StandaloneProcessEvidence<
        'evidence,
        'branch_authority,
        'branch_artifact,
        'bounds_authority,
        'bounds_artifact,
    >
{
    pub const fn evidence(self) -> &'evidence X64StandaloneProcessEvidence {
        self.evidence
    }

    pub const fn results_hash(self) -> SemanticHash {
        self.evidence.results_hash
    }

    /// Accepted absence for only the frozen, ordered 51-case R1-S8c claim.
    /// This is not an infinite-domain or general x86-64 theorem.
    pub const fn interpreter_dependency(self) -> bool {
        false
    }

    /// Accepted absence for only the frozen, ordered 51-case R1-S8c claim.
    /// No retry, skip, worker, interpreter, or generic fallback is admitted.
    pub const fn fallback(self) -> bool {
        false
    }
}

/// Complete result of an attempted failed-child teardown.
///
/// Every populated field is surfaced; group-kill failure still triggers a
/// leader-kill fallback and a bounded reap attempt before this value exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64StandaloneTeardownFailure {
    group_kill: Option<io::ErrorKind>,
    leader_kill: Option<io::ErrorKind>,
    reap: Option<io::ErrorKind>,
}

impl X64StandaloneTeardownFailure {
    pub const fn group_kill(self) -> Option<io::ErrorKind> {
        self.group_kill
    }

    pub const fn leader_kill(self) -> Option<io::ErrorKind> {
        self.leader_kill
    }

    pub const fn reap(self) -> Option<io::ErrorKind> {
        self.reap
    }
}

#[derive(Debug)]
pub enum X64StandaloneProcessError {
    UnsupportedHost,
    Manifest(CoreVmGateAError),
    Authority {
        profile: X64StandaloneProfile,
        message: String,
    },
    Artifact {
        profile: X64StandaloneProfile,
        message: String,
    },
    Protocol {
        case_ordinal: u32,
        message: String,
    },
    MachineIr {
        case_ordinal: u32,
        message: String,
    },
    AuthorityBinding {
        profile: X64StandaloneProfile,
        field: &'static str,
    },
    ProfileMismatch {
        case_ordinal: u32,
        expected: X64StandaloneProfile,
        actual: X64StandaloneProfile,
    },
    Spawn {
        case_ordinal: u32,
        kind: io::ErrorKind,
    },
    MissingPipe {
        case_ordinal: u32,
        stream: &'static str,
    },
    PipeThreadSpawn {
        case_ordinal: u32,
        stream: &'static str,
        kind: io::ErrorKind,
    },
    PipeThreadPanicked {
        case_ordinal: u32,
        stream: &'static str,
    },
    PipeThreadTimeout {
        case_ordinal: u32,
        stream: &'static str,
    },
    PipeIo {
        case_ordinal: u32,
        stream: &'static str,
        kind: io::ErrorKind,
    },
    Wait {
        case_ordinal: u32,
        kind: io::ErrorKind,
    },
    Teardown {
        case_ordinal: u32,
        failure: X64StandaloneTeardownFailure,
    },
    FailureDuringContainment {
        case_ordinal: u32,
        primary: Box<X64StandaloneProcessError>,
        cleanup: Box<X64StandaloneProcessError>,
    },
    Timeout {
        case_ordinal: u32,
        timeout_millis: u32,
    },
    Fault {
        case_ordinal: u32,
        signal: Option<i32>,
    },
    AbnormalExit {
        case_ordinal: u32,
        code: Option<i32>,
    },
    StdoutLength {
        case_ordinal: u32,
        expected: u64,
        actual: u64,
    },
    StderrByteLimit {
        case_ordinal: u32,
        limit: u64,
        actual: u64,
    },
    StderrRecordLimit {
        case_ordinal: u32,
        limit: u32,
        actual: u32,
    },
    UnexpectedStderr {
        case_ordinal: u32,
        actual: u64,
    },
    CaptureOverflow {
        case_ordinal: u32,
        stream: &'static str,
    },
    SemanticMismatch {
        case_ordinal: u32,
    },
    InvalidSchema,
    FixedCorpusCount {
        expected: u32,
        actual: usize,
    },
    DuplicateOrdinal {
        ordinal: u32,
    },
    NonCanonicalOrder {
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
    TempCreate {
        kind: io::ErrorKind,
    },
    TempCreateExhausted {
        attempts: u32,
    },
    TempWrite {
        kind: io::ErrorKind,
    },
    TempMode {
        kind: io::ErrorKind,
    },
    TempReadback {
        kind: io::ErrorKind,
    },
    TempReadbackMismatch,
    TempCleanup {
        kind: io::ErrorKind,
    },
}

impl fmt::Display for X64StandaloneProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost => {
                formatter.write_str("R1-S8c direct evidence requires Linux x86-64")
            }
            Self::Manifest(error) => write!(formatter, "cannot regenerate Gate A: {error}"),
            Self::Authority { profile, message } => {
                write!(
                    formatter,
                    "cannot replay {profile:?} standalone authority: {message}"
                )
            }
            Self::Artifact { profile, message } => {
                write!(
                    formatter,
                    "cannot verify {profile:?} standalone image: {message}"
                )
            }
            Self::Protocol {
                case_ordinal,
                message,
            } => write!(
                formatter,
                "R1-S8c case {case_ordinal} has an invalid canonical frame: {message}"
            ),
            Self::MachineIr {
                case_ordinal,
                message,
            } => write!(
                formatter,
                "R1-S8c case {case_ordinal} Machine-IR replay failed: {message}"
            ),
            Self::AuthorityBinding { profile, field } => write!(
                formatter,
                "R1-S8c {profile:?} authority/artifact has an invalid {field}"
            ),
            Self::ProfileMismatch {
                case_ordinal,
                expected,
                actual,
            } => write!(
                formatter,
                "R1-S8c case {case_ordinal} requires {expected:?}, found {actual:?}"
            ),
            Self::Spawn { case_ordinal, kind } => {
                write!(
                    formatter,
                    "cannot launch R1-S8c case {case_ordinal}: {kind}"
                )
            }
            Self::MissingPipe {
                case_ordinal,
                stream,
            } => write!(
                formatter,
                "R1-S8c case {case_ordinal} has no captured {stream}"
            ),
            Self::PipeThreadSpawn {
                case_ordinal,
                stream,
                kind,
            } => write!(
                formatter,
                "cannot start R1-S8c case {case_ordinal} {stream} task: {kind}"
            ),
            Self::PipeThreadPanicked {
                case_ordinal,
                stream,
            } => write!(
                formatter,
                "R1-S8c case {case_ordinal} {stream} task panicked"
            ),
            Self::PipeThreadTimeout {
                case_ordinal,
                stream,
            } => write!(
                formatter,
                "R1-S8c case {case_ordinal} {stream} task did not terminate"
            ),
            Self::PipeIo {
                case_ordinal,
                stream,
                kind,
            } => write!(
                formatter,
                "R1-S8c case {case_ordinal} {stream} I/O failed: {kind}"
            ),
            Self::Wait { case_ordinal, kind } => {
                write!(
                    formatter,
                    "cannot wait for R1-S8c case {case_ordinal}: {kind}"
                )
            }
            Self::Teardown {
                case_ordinal,
                failure,
            } => write!(
                formatter,
                "cannot completely tear down R1-S8c case {case_ordinal}: \
                 group-kill={:?}, leader-kill={:?}, reap={:?}",
                failure.group_kill, failure.leader_kill, failure.reap
            ),
            Self::FailureDuringContainment {
                case_ordinal,
                primary,
                cleanup,
            } => write!(
                formatter,
                "R1-S8c case {case_ordinal} failed with {primary}; \
                 containment cleanup also failed with {cleanup}"
            ),
            Self::Timeout {
                case_ordinal,
                timeout_millis,
            } => write!(
                formatter,
                "R1-S8c case {case_ordinal} exceeded {timeout_millis} ms"
            ),
            Self::Fault {
                case_ordinal,
                signal,
            } => write!(
                formatter,
                "R1-S8c case {case_ordinal} terminated by signal {signal:?}"
            ),
            Self::AbnormalExit { case_ordinal, code } => write!(
                formatter,
                "R1-S8c case {case_ordinal} exited abnormally with code {code:?}"
            ),
            Self::StdoutLength {
                case_ordinal,
                expected,
                actual,
            } => write!(
                formatter,
                "R1-S8c case {case_ordinal} wrote {actual} stdout bytes; expected {expected}"
            ),
            Self::StderrByteLimit {
                case_ordinal,
                limit,
                actual,
            } => write!(
                formatter,
                "R1-S8c case {case_ordinal} wrote {actual} stderr bytes; limit is {limit}"
            ),
            Self::StderrRecordLimit {
                case_ordinal,
                limit,
                actual,
            } => write!(
                formatter,
                "R1-S8c case {case_ordinal} wrote {actual} diagnostic records; limit is {limit}"
            ),
            Self::UnexpectedStderr {
                case_ordinal,
                actual,
            } => write!(
                formatter,
                "R1-S8c case {case_ordinal} wrote {actual} unexpected stderr bytes"
            ),
            Self::CaptureOverflow {
                case_ordinal,
                stream,
            } => write!(
                formatter,
                "R1-S8c case {case_ordinal} {stream} byte counter overflowed"
            ),
            Self::SemanticMismatch { case_ordinal } => write!(
                formatter,
                "R1-S8c case {case_ordinal} differs from independent Machine IR"
            ),
            Self::InvalidSchema => {
                formatter.write_str("R1-S8c evidence uses a noncanonical schema or policy")
            }
            Self::FixedCorpusCount { expected, actual } => write!(
                formatter,
                "R1-S8c requires {expected} records; found {actual}"
            ),
            Self::DuplicateOrdinal { ordinal } => {
                write!(formatter, "R1-S8c contains duplicate ordinal {ordinal}")
            }
            Self::NonCanonicalOrder { expected, actual } => write!(
                formatter,
                "R1-S8c expected ordinal {expected}; found {actual}"
            ),
            Self::InvalidRecord {
                case_ordinal,
                field,
            } => write!(
                formatter,
                "R1-S8c record {case_ordinal} has an invalid {field}"
            ),
            Self::RecordHashMismatch { case_ordinal } => {
                write!(
                    formatter,
                    "R1-S8c record {case_ordinal} has an invalid seal"
                )
            }
            Self::ResultsHashMismatch => {
                formatter.write_str("R1-S8c ordered results have an invalid seal")
            }
            Self::MetricOverflow { field } => {
                write!(formatter, "R1-S8c {field} does not fit its frozen width")
            }
            Self::TempCreate { kind } => {
                write!(formatter, "cannot create bounded R1-S8c executable: {kind}")
            }
            Self::TempCreateExhausted { attempts } => write!(
                formatter,
                "cannot reserve a unique R1-S8c executable after {attempts} attempts"
            ),
            Self::TempWrite { kind } => {
                write!(formatter, "cannot write complete R1-S8c executable: {kind}")
            }
            Self::TempMode { kind } => {
                write!(formatter, "cannot establish exact R1-S8c file mode: {kind}")
            }
            Self::TempReadback { kind } => {
                write!(formatter, "cannot read back R1-S8c executable: {kind}")
            }
            Self::TempReadbackMismatch => {
                formatter.write_str("R1-S8c executable readback differs from verified image")
            }
            Self::TempCleanup { kind } => {
                write!(
                    formatter,
                    "cannot remove R1-S8c temporary executable: {kind}"
                )
            }
        }
    }
}

impl std::error::Error for X64StandaloneProcessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Manifest(error) => Some(error),
            Self::FailureDuringContainment { primary, .. } => Some(primary.as_ref()),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
struct ArtifactBinding {
    profile: X64StandaloneProfile,
    artifact_hash: SemanticHash,
    elf_image_hash: SemanticHash,
    startup_plan_hash: SemanticHash,
    startup_code_hash: SemanticHash,
    io_contract_hash: SemanticHash,
}

/// Emit the complete frozen 51-case R1-S8c direct-process package.
///
/// Both inputs are live opaque authorities plus independently verified image
/// views.  The image bytes are reverified against the supplied authority
/// before any temporary executable is created.
pub fn emit_x64_standalone_process_evidence_r1_s8c(
    branch_authority: &X64StandaloneSeedAuthority<'_>,
    branch_artifact: &VerifiedX64StandaloneArtifact<'_, '_, '_>,
    bounds_authority: &X64StandaloneSeedAuthority<'_>,
    bounds_artifact: &VerifiedX64StandaloneArtifact<'_, '_, '_>,
) -> Result<X64StandaloneProcessEvidence, X64StandaloneProcessError> {
    require_supported_host()?;
    let manifest = corevm0_gate_a_manifest().map_err(X64StandaloneProcessError::Manifest)?;
    let branch_binding = verify_live_binding(
        X64StandaloneProfile::BranchMix,
        branch_authority,
        branch_artifact,
    )?;
    let bounds_binding = verify_live_binding(
        X64StandaloneProfile::Bounds,
        bounds_authority,
        bounds_artifact,
    )?;
    require_cross_profile_binding(branch_authority, bounds_authority, manifest.manifest_hash)?;

    let mut branch_file = TempExecutable::create(
        X64StandaloneProfile::BranchMix,
        branch_artifact.image_bytes(),
    )?;
    let mut bounds_file =
        match TempExecutable::create(X64StandaloneProfile::Bounds, bounds_artifact.image_bytes()) {
            Ok(file) => file,
            Err(error) => {
                branch_file.cleanup()?;
                return Err(error);
            }
        };

    let execution = (|| {
        let mut records = Vec::with_capacity(manifest.cases.len());
        for case in &manifest.cases {
            let (authority, binding, path) = match profile_for_workload(case.workload) {
                X64StandaloneProfile::BranchMix => {
                    (branch_authority, branch_binding, branch_file.path())
                }
                X64StandaloneProfile::Bounds => {
                    (bounds_authority, bounds_binding, bounds_file.path())
                }
            };
            records.push(execute_direct_case(authority, binding, path, case)?);
        }
        seal_process_evidence(
            manifest.manifest_hash,
            branch_binding,
            bounds_binding,
            records,
        )
    })();

    let bounds_cleanup = bounds_file.cleanup();
    let branch_cleanup = branch_file.cleanup();
    bounds_cleanup?;
    branch_cleanup?;
    let evidence = execution?;

    // Construction does not publish a writer-created verification flag.
    let _ = verify_x64_standalone_process_evidence_r1_s8c(
        &evidence,
        branch_authority,
        branch_artifact,
        bounds_authority,
        bounds_artifact,
    )?;
    Ok(evidence)
}

/// Replay all deterministic identity and semantic checks against the two live
/// authorities and their independently verified image views.
///
/// This verifier does not relaunch processes.  A new claim-bearing run must
/// call [`emit_x64_standalone_process_evidence_r1_s8c`].
pub fn verify_x64_standalone_process_evidence_r1_s8c<
    'evidence,
    'branch_authority,
    'branch_artifact,
    'bounds_authority,
    'bounds_artifact,
>(
    evidence: &'evidence X64StandaloneProcessEvidence,
    branch_authority: &'branch_authority X64StandaloneSeedAuthority<'_>,
    branch_artifact: &'branch_artifact VerifiedX64StandaloneArtifact<'_, '_, '_>,
    bounds_authority: &'bounds_authority X64StandaloneSeedAuthority<'_>,
    bounds_artifact: &'bounds_artifact VerifiedX64StandaloneArtifact<'_, '_, '_>,
) -> Result<
    VerifiedX64StandaloneProcessEvidence<
        'evidence,
        'branch_authority,
        'branch_artifact,
        'bounds_authority,
        'bounds_artifact,
    >,
    X64StandaloneProcessError,
> {
    require_supported_host()?;
    if evidence.execution_schema_version != X64_STANDALONE_EXECUTION_SCHEMA_VERSION
        || evidence.execution_policy_version != X64_STANDALONE_EXECUTION_POLICY_VERSION
        || evidence.results_policy_version != X64_STANDALONE_EXECUTION_RESULTS_POLICY_VERSION
    {
        return Err(X64StandaloneProcessError::InvalidSchema);
    }
    let manifest = corevm0_gate_a_manifest().map_err(X64StandaloneProcessError::Manifest)?;
    let branch_binding = verify_live_binding(
        X64StandaloneProfile::BranchMix,
        branch_authority,
        branch_artifact,
    )?;
    let bounds_binding = verify_live_binding(
        X64StandaloneProfile::Bounds,
        bounds_authority,
        bounds_artifact,
    )?;
    require_cross_profile_binding(branch_authority, bounds_authority, manifest.manifest_hash)?;
    if evidence.manifest_hash != manifest.manifest_hash
        || evidence.branch_artifact_hash != branch_binding.artifact_hash
        || evidence.branch_elf_image_hash != branch_binding.elf_image_hash
        || evidence.branch_io_contract_hash != branch_binding.io_contract_hash
        || evidence.bounds_artifact_hash != bounds_binding.artifact_hash
        || evidence.bounds_elf_image_hash != bounds_binding.elf_image_hash
        || evidence.bounds_io_contract_hash != bounds_binding.io_contract_hash
    {
        return Err(X64StandaloneProcessError::InvalidRecord {
            case_ordinal: 0,
            field: "aggregate authority/artifact binding",
        });
    }
    validate_order_and_uniqueness(&evidence.records)?;

    for (record, case) in evidence.records.iter().zip(&manifest.cases) {
        let (authority, binding) = match profile_for_workload(case.workload) {
            X64StandaloneProfile::BranchMix => (branch_authority, branch_binding),
            X64StandaloneProfile::Bounds => (bounds_authority, bounds_binding),
        };
        validate_record_against_case(record, case, authority, binding, true)?;
    }
    let expected = x64_standalone_execution_results_hash(evidence)?;
    if evidence.results_hash != expected {
        return Err(X64StandaloneProcessError::ResultsHashMismatch);
    }
    Ok(VerifiedX64StandaloneProcessEvidence {
        evidence,
        _branch_authority: branch_authority,
        _branch_artifact: branch_artifact,
        _bounds_authority: bounds_authority,
        _bounds_artifact: bounds_artifact,
    })
}

/// Recompute one canonical R1-S8c record identity.
pub fn x64_standalone_execution_record_hash(
    record: &X64StandaloneExecutionRecord,
) -> Result<SemanticHash, X64StandaloneProcessError> {
    validate_record_local_shape(record)?;
    Ok(SemanticHash(sha256(&encode_execution_record(record)?)))
}

/// Recompute the frozen order-sensitive aggregate identity.
pub fn x64_standalone_execution_results_hash(
    evidence: &X64StandaloneProcessEvidence,
) -> Result<SemanticHash, X64StandaloneProcessError> {
    if evidence.execution_schema_version != X64_STANDALONE_EXECUTION_SCHEMA_VERSION
        || evidence.execution_policy_version != X64_STANDALONE_EXECUTION_POLICY_VERSION
        || evidence.results_policy_version != X64_STANDALONE_EXECUTION_RESULTS_POLICY_VERSION
    {
        return Err(X64StandaloneProcessError::InvalidSchema);
    }
    validate_order_and_uniqueness(&evidence.records)?;
    let mut bytes = Vec::with_capacity(
        X64_STANDALONE_EXECUTION_RESULTS_DOMAIN.len()
            + 18
            + 32 * 7
            + 4
            + evidence.records.len() * 32,
    );
    bytes.extend_from_slice(X64_STANDALONE_EXECUTION_RESULTS_DOMAIN);
    put_version(&mut bytes, evidence.execution_schema_version);
    put_version(&mut bytes, evidence.execution_policy_version);
    put_version(&mut bytes, evidence.results_policy_version);
    put_hash(&mut bytes, evidence.manifest_hash);
    put_hash(&mut bytes, evidence.branch_artifact_hash);
    put_hash(&mut bytes, evidence.branch_elf_image_hash);
    put_hash(&mut bytes, evidence.branch_io_contract_hash);
    put_hash(&mut bytes, evidence.bounds_artifact_hash);
    put_hash(&mut bytes, evidence.bounds_elf_image_hash);
    put_hash(&mut bytes, evidence.bounds_io_contract_hash);
    put_u32(
        &mut bytes,
        u32::try_from(evidence.records.len()).map_err(|_| {
            X64StandaloneProcessError::MetricOverflow {
                field: "execution result count",
            }
        })?,
    );
    for record in &evidence.records {
        let actual = x64_standalone_execution_record_hash(record)?;
        if actual != record.record_hash {
            return Err(X64StandaloneProcessError::RecordHashMismatch {
                case_ordinal: record.case_ordinal,
            });
        }
        put_hash(&mut bytes, record.record_hash);
    }
    Ok(SemanticHash(sha256(&bytes)))
}

fn verify_live_binding(
    expected_profile: X64StandaloneProfile,
    authority: &X64StandaloneSeedAuthority<'_>,
    supplied: &VerifiedX64StandaloneArtifact<'_, '_, '_>,
) -> Result<ArtifactBinding, X64StandaloneProcessError> {
    if authority.profile() != expected_profile || supplied.profile() != expected_profile {
        return Err(X64StandaloneProcessError::AuthorityBinding {
            profile: expected_profile,
            field: "baked profile",
        });
    }
    let verified = verify_x64_standalone_artifact_r1_s8(authority, supplied.image_bytes())
        .map_err(|error| artifact_error(expected_profile, error))?;
    if verified.interpreter_dependency()
        || verified.external_symbol_dependency()
        || verified.dynamic_loader_dependency()
        || verified.system_linker_dependency()
        || verified.fallback()
        || !authority.structural_erasure()
        || authority.upstream_interpreter_dependency()
        || authority.fallback()
    {
        return Err(X64StandaloneProcessError::AuthorityBinding {
            profile: expected_profile,
            field: "dependency/fallback proof",
        });
    }
    let expected_cases = match expected_profile {
        X64StandaloneProfile::BranchMix => BRANCH_CASES,
        X64StandaloneProfile::Bounds => COREVM0_GATE_A_BOUNDS_CASES,
    };
    if authority.canonical_case_count() != expected_cases {
        return Err(X64StandaloneProcessError::AuthorityBinding {
            profile: expected_profile,
            field: "profile corpus count",
        });
    }
    let limits = verified.limits();
    if limits.fixed_corpus_cases() != COREVM0_GATE_A_TOTAL_CASES
        || limits.per_process_timeout_ms() != X64_STANDALONE_PROCESS_TIMEOUT_MILLIS
        || limits.max_captured_diagnostic_bytes() != X64_STANDALONE_PROCESS_MAX_DIAGNOSTIC_BYTES
        || limits.max_captured_diagnostic_records() != X64_STANDALONE_PROCESS_MAX_DIAGNOSTIC_RECORDS
        || limits.output_frame_bytes() != X64_STANDALONE_OUTPUT_BYTES as u64
    {
        return Err(X64StandaloneProcessError::AuthorityBinding {
            profile: expected_profile,
            field: "process hard-limit vector",
        });
    }
    Ok(ArtifactBinding {
        profile: verified.profile(),
        artifact_hash: verified.artifact_hash(),
        elf_image_hash: verified.elf_image_hash(),
        startup_plan_hash: verified.startup_plan_hash(),
        startup_code_hash: verified.startup_code_hash(),
        io_contract_hash: verified.io_contract_hash(),
    })
}

fn require_cross_profile_binding(
    branch: &X64StandaloneSeedAuthority<'_>,
    bounds: &X64StandaloneSeedAuthority<'_>,
    manifest_hash: SemanticHash,
) -> Result<(), X64StandaloneProcessError> {
    if branch.manifest_hash() != manifest_hash || bounds.manifest_hash() != manifest_hash {
        return Err(X64StandaloneProcessError::AuthorityBinding {
            profile: X64StandaloneProfile::BranchMix,
            field: "Gate A manifest",
        });
    }
    if branch.semantic_results_hash() != bounds.semantic_results_hash()
        || branch.process_results_hash() != bounds.process_results_hash()
    {
        return Err(X64StandaloneProcessError::AuthorityBinding {
            profile: X64StandaloneProfile::Bounds,
            field: "inherited ordered S7b results",
        });
    }
    Ok(())
}

fn execute_direct_case(
    authority: &X64StandaloneSeedAuthority<'_>,
    binding: ArtifactBinding,
    executable: &Path,
    case: &CoreVmGateACase,
) -> Result<X64StandaloneExecutionRecord, X64StandaloneProcessError> {
    let expected_profile = profile_for_workload(case.workload);
    if authority.profile() != expected_profile || binding.profile != expected_profile {
        return Err(X64StandaloneProcessError::ProfileMismatch {
            case_ordinal: case.ordinal,
            expected: expected_profile,
            actual: authority.profile(),
        });
    }
    let regenerated =
        corevm0_gate_a_case_input_hash(case).map_err(X64StandaloneProcessError::Manifest)?;
    if regenerated != case.input_hash {
        return Err(X64StandaloneProcessError::InvalidRecord {
            case_ordinal: case.ordinal,
            field: "Gate A input hash",
        });
    }
    let input = X64StandaloneInput::new(
        expected_profile,
        case.input.array_f64_bits.clone(),
        case.input.repetitions,
    )
    .map_err(|error| protocol_error(case.ordinal, error))?;
    let input_frame =
        encode_x64_standalone_input(&input).map_err(|error| protocol_error(case.ordinal, error))?;
    let process = run_direct_process(executable, case.ordinal, input_frame.clone())?;
    admit_timeout(case.ordinal, process.timed_out)?;
    let normal_exit_code = admit_process_status(case.ordinal, process.status)?;
    let (output_frame, output) = admit_stdout(case.ordinal, expected_profile, &process.stdout)?;
    admit_stderr(case.ordinal, &process.stderr)?;

    let standalone = normalize_standalone_output(output);
    let machine_ir = evaluate_machine_ir_observation(authority, case)?;
    if standalone != machine_ir {
        return Err(X64StandaloneProcessError::SemanticMismatch {
            case_ordinal: case.ordinal,
        });
    }
    let input_frame_bytes = u64::try_from(input_frame.len()).map_err(|_| {
        X64StandaloneProcessError::MetricOverflow {
            field: "input frame length",
        }
    })?;
    let mut record = X64StandaloneExecutionRecord {
        execution_schema_version: X64_STANDALONE_EXECUTION_SCHEMA_VERSION,
        execution_policy_version: X64_STANDALONE_EXECUTION_POLICY_VERSION,
        case_ordinal: case.ordinal,
        total_cases: COREVM0_GATE_A_TOTAL_CASES,
        manifest_hash: authority.manifest_hash(),
        profile: expected_profile,
        case_class: case.class,
        gate_a_input_hash: case.input_hash,
        source_core_hash: authority.source_core_hash(),
        source_ssa_hash: authority.source_ssa_hash(),
        source_machine_ir_hash: authority.source_machine_ir_hash(),
        target_artifact_hash: authority.target_artifact_hash(),
        target_plan_hash: authority.target_plan_hash(),
        target_code_hash: authority.target_code_hash(),
        canonical_abi_hash: authority.canonical_abi_hash(),
        target_entry_offset: authority.entry_offset(),
        target_input_lanes: authority.input_lanes(),
        inherited_semantic_results_hash: authority.semantic_results_hash(),
        inherited_process_results_hash: authority.process_results_hash(),
        standalone_artifact_hash: binding.artifact_hash,
        elf_image_hash: binding.elf_image_hash,
        startup_plan_hash: binding.startup_plan_hash,
        startup_code_hash: binding.startup_code_hash,
        io_contract_hash: binding.io_contract_hash,
        input_frame_bytes,
        input_frame_hash: raw_frame_hash(&input_frame),
        normal_exit_code,
        output_frame,
        output_frame_hash: raw_frame_hash(&output_frame),
        standalone,
        machine_ir,
        stdout_bytes: process.stdout.total_bytes,
        stderr_bytes: process.stderr.total_bytes,
        per_process_timeout_ms: X64_STANDALONE_PROCESS_TIMEOUT_MILLIS,
        max_captured_diagnostic_bytes: X64_STANDALONE_PROCESS_MAX_DIAGNOSTIC_BYTES,
        max_captured_diagnostic_records: X64_STANDALONE_PROCESS_MAX_DIAGNOSTIC_RECORDS,
        timeout: false,
        fault: false,
        abnormal_status: false,
        interpreter_dependency: false,
        external_symbol_dependency: false,
        dynamic_loader_dependency: false,
        system_linker_dependency: false,
        fallback: false,
        record_hash: SemanticHash::ZERO,
    };
    record.record_hash = x64_standalone_execution_record_hash(&record)?;
    Ok(record)
}

fn evaluate_machine_ir_observation(
    authority: &X64StandaloneSeedAuthority<'_>,
    case: &CoreVmGateACase,
) -> Result<X64StandaloneExecutionObservation, X64StandaloneProcessError> {
    let target = authority
        .source_bound()
        .map_err(|error| authority_error(authority.profile(), error))?;
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
    let evaluation = evaluate_machine_ir_translation(
        target.source_machine_ir(),
        target.source_ssa(),
        target.source_core(),
        arguments,
        EvaluationBudget::new(
            COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
            COREVM0_GATE_A_CALL_DEPTH_LIMIT,
        ),
    )
    .map_err(|error| X64StandaloneProcessError::MachineIr {
        case_ordinal: case.ordinal,
        message: error.to_string(),
    })?;
    normalize_machine_ir(case.ordinal, &evaluation)
}

fn normalize_machine_ir(
    case_ordinal: u32,
    evaluation: &Evaluation,
) -> Result<X64StandaloneExecutionObservation, X64StandaloneProcessError> {
    let outcome = match &evaluation.outcome {
        EvaluationOutcome::Return(CoreValue::F64(value)) if value.is_nan() => {
            X64StandaloneExecutionOutcome::ReturnF64(X64StandaloneExecutionF64::CanonicalNaN)
        }
        EvaluationOutcome::Return(CoreValue::F64(value)) => {
            X64StandaloneExecutionOutcome::ReturnF64(X64StandaloneExecutionF64::ExactBits(
                value.to_bits(),
            ))
        }
        EvaluationOutcome::Error(ErrorKind::Bounds) => X64StandaloneExecutionOutcome::Bounds,
        _ => {
            return Err(X64StandaloneProcessError::InvalidRecord {
                case_ordinal,
                field: "Machine-IR outcome",
            });
        }
    };
    let effects = evaluation
        .effect_trace
        .iter()
        .map(|effect| match effect {
            EffectEvent::Error(ErrorKind::Bounds) => Ok(X64StandaloneExecutionEffect::Bounds),
            _ => Err(X64StandaloneProcessError::InvalidRecord {
                case_ordinal,
                field: "Machine-IR effect",
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let observation = X64StandaloneExecutionObservation { outcome, effects };
    validate_observation(case_ordinal, &observation)?;
    Ok(observation)
}

fn normalize_standalone_output(output: X64StandaloneOutput) -> X64StandaloneExecutionObservation {
    match output.outcome() {
        X64StandaloneOutcome::ReturnF64 { bits } if f64::from_bits(bits).is_nan() => {
            X64StandaloneExecutionObservation {
                outcome: X64StandaloneExecutionOutcome::ReturnF64(
                    X64StandaloneExecutionF64::CanonicalNaN,
                ),
                effects: Vec::new(),
            }
        }
        X64StandaloneOutcome::ReturnF64 { bits } => X64StandaloneExecutionObservation {
            outcome: X64StandaloneExecutionOutcome::ReturnF64(
                X64StandaloneExecutionF64::ExactBits(bits),
            ),
            effects: Vec::new(),
        },
        X64StandaloneOutcome::Bounds => X64StandaloneExecutionObservation {
            outcome: X64StandaloneExecutionOutcome::Bounds,
            effects: vec![X64StandaloneExecutionEffect::Bounds],
        },
    }
}

fn seal_process_evidence(
    manifest_hash: SemanticHash,
    branch: ArtifactBinding,
    bounds: ArtifactBinding,
    records: Vec<X64StandaloneExecutionRecord>,
) -> Result<X64StandaloneProcessEvidence, X64StandaloneProcessError> {
    validate_order_and_uniqueness(&records)?;
    let mut evidence = X64StandaloneProcessEvidence {
        execution_schema_version: X64_STANDALONE_EXECUTION_SCHEMA_VERSION,
        execution_policy_version: X64_STANDALONE_EXECUTION_POLICY_VERSION,
        results_policy_version: X64_STANDALONE_EXECUTION_RESULTS_POLICY_VERSION,
        manifest_hash,
        branch_artifact_hash: branch.artifact_hash,
        branch_elf_image_hash: branch.elf_image_hash,
        branch_io_contract_hash: branch.io_contract_hash,
        bounds_artifact_hash: bounds.artifact_hash,
        bounds_elf_image_hash: bounds.elf_image_hash,
        bounds_io_contract_hash: bounds.io_contract_hash,
        records,
        results_hash: SemanticHash::ZERO,
    };
    evidence.results_hash = x64_standalone_execution_results_hash(&evidence)?;
    Ok(evidence)
}

fn validate_record_against_case(
    record: &X64StandaloneExecutionRecord,
    case: &CoreVmGateACase,
    authority: &X64StandaloneSeedAuthority<'_>,
    binding: ArtifactBinding,
    replay_machine_ir: bool,
) -> Result<(), X64StandaloneProcessError> {
    validate_record_local_shape(record)?;
    let profile = profile_for_workload(case.workload);
    let regenerated =
        corevm0_gate_a_case_input_hash(case).map_err(X64StandaloneProcessError::Manifest)?;
    let input = X64StandaloneInput::new(
        profile,
        case.input.array_f64_bits.clone(),
        case.input.repetitions,
    )
    .map_err(|error| protocol_error(case.ordinal, error))?;
    let input_frame =
        encode_x64_standalone_input(&input).map_err(|error| protocol_error(case.ordinal, error))?;
    let expected_output = decode_x64_standalone_output_for_profile(&record.output_frame, profile)
        .map_err(|error| protocol_error(case.ordinal, error))?;
    let canonical_output = encode_x64_standalone_output(expected_output)
        .map_err(|error| protocol_error(case.ordinal, error))?;
    let expected_input_bytes = u64::try_from(input_frame.len()).map_err(|_| {
        X64StandaloneProcessError::MetricOverflow {
            field: "input frame length",
        }
    })?;

    let exact = record.case_ordinal == case.ordinal
        && record.total_cases == COREVM0_GATE_A_TOTAL_CASES
        && record.manifest_hash == authority.manifest_hash()
        && record.profile == profile
        && record.case_class == case.class
        && regenerated == case.input_hash
        && record.gate_a_input_hash == case.input_hash
        && record.source_core_hash == authority.source_core_hash()
        && record.source_ssa_hash == authority.source_ssa_hash()
        && record.source_machine_ir_hash == authority.source_machine_ir_hash()
        && record.target_artifact_hash == authority.target_artifact_hash()
        && record.target_plan_hash == authority.target_plan_hash()
        && record.target_code_hash == authority.target_code_hash()
        && record.canonical_abi_hash == authority.canonical_abi_hash()
        && record.target_entry_offset == authority.entry_offset()
        && record.target_input_lanes == authority.input_lanes()
        && record.inherited_semantic_results_hash == authority.semantic_results_hash()
        && record.inherited_process_results_hash == authority.process_results_hash()
        && record.standalone_artifact_hash == binding.artifact_hash
        && record.elf_image_hash == binding.elf_image_hash
        && record.startup_plan_hash == binding.startup_plan_hash
        && record.startup_code_hash == binding.startup_code_hash
        && record.io_contract_hash == binding.io_contract_hash
        && record.input_frame_bytes == expected_input_bytes
        && record.input_frame_hash == raw_frame_hash(&input_frame)
        && record.output_frame == canonical_output
        && record.output_frame_hash == raw_frame_hash(&record.output_frame)
        && record.standalone == normalize_standalone_output(expected_output);
    if !exact {
        return Err(X64StandaloneProcessError::InvalidRecord {
            case_ordinal: case.ordinal,
            field: "canonical case/authority/artifact binding",
        });
    }
    if replay_machine_ir {
        let machine_ir = evaluate_machine_ir_observation(authority, case)?;
        if record.machine_ir != machine_ir || record.standalone != machine_ir {
            return Err(X64StandaloneProcessError::SemanticMismatch {
                case_ordinal: case.ordinal,
            });
        }
    }
    let actual = x64_standalone_execution_record_hash(record)?;
    if actual != record.record_hash {
        return Err(X64StandaloneProcessError::RecordHashMismatch {
            case_ordinal: case.ordinal,
        });
    }
    Ok(())
}

fn validate_record_local_shape(
    record: &X64StandaloneExecutionRecord,
) -> Result<(), X64StandaloneProcessError> {
    if record.execution_schema_version != X64_STANDALONE_EXECUTION_SCHEMA_VERSION
        || record.execution_policy_version != X64_STANDALONE_EXECUTION_POLICY_VERSION
    {
        return Err(X64StandaloneProcessError::InvalidSchema);
    }
    if record.total_cases != COREVM0_GATE_A_TOTAL_CASES
        || record.case_ordinal >= COREVM0_GATE_A_TOTAL_CASES
    {
        return Err(X64StandaloneProcessError::InvalidRecord {
            case_ordinal: record.case_ordinal,
            field: "ordinal/total",
        });
    }
    let expected_profile = if record.case_ordinal < BRANCH_CASES {
        X64StandaloneProfile::BranchMix
    } else {
        X64StandaloneProfile::Bounds
    };
    if record.profile != expected_profile {
        return Err(X64StandaloneProcessError::InvalidRecord {
            case_ordinal: record.case_ordinal,
            field: "ordered workload profile",
        });
    }
    for (field, hash) in [
        ("manifest hash", record.manifest_hash),
        ("Gate A input hash", record.gate_a_input_hash),
        ("source Core hash", record.source_core_hash),
        ("source SSA hash", record.source_ssa_hash),
        ("source Machine-IR hash", record.source_machine_ir_hash),
        ("target artifact hash", record.target_artifact_hash),
        ("target plan hash", record.target_plan_hash),
        ("target code hash", record.target_code_hash),
        ("canonical ABI hash", record.canonical_abi_hash),
        (
            "inherited semantic results hash",
            record.inherited_semantic_results_hash,
        ),
        (
            "inherited process results hash",
            record.inherited_process_results_hash,
        ),
        ("standalone artifact hash", record.standalone_artifact_hash),
        ("ELF image hash", record.elf_image_hash),
        ("startup plan hash", record.startup_plan_hash),
        ("startup code hash", record.startup_code_hash),
        ("I/O contract hash", record.io_contract_hash),
        ("input frame hash", record.input_frame_hash),
        ("output frame hash", record.output_frame_hash),
    ] {
        if hash == SemanticHash::ZERO {
            return Err(X64StandaloneProcessError::InvalidRecord {
                case_ordinal: record.case_ordinal,
                field,
            });
        }
    }
    if record.normal_exit_code != 0
        || record.stdout_bytes != X64_STANDALONE_OUTPUT_BYTES as u64
        || record.stderr_bytes != 0
        || record.per_process_timeout_ms != X64_STANDALONE_PROCESS_TIMEOUT_MILLIS
        || record.max_captured_diagnostic_bytes != X64_STANDALONE_PROCESS_MAX_DIAGNOSTIC_BYTES
        || record.max_captured_diagnostic_records != X64_STANDALONE_PROCESS_MAX_DIAGNOSTIC_RECORDS
        || record.timeout
        || record.fault
        || record.abnormal_status
        || record.interpreter_dependency
        || record.external_symbol_dependency
        || record.dynamic_loader_dependency
        || record.system_linker_dependency
        || record.fallback
    {
        return Err(X64StandaloneProcessError::InvalidRecord {
            case_ordinal: record.case_ordinal,
            field: "process admission/dependency flags",
        });
    }
    validate_observation(record.case_ordinal, &record.standalone)?;
    validate_observation(record.case_ordinal, &record.machine_ir)?;
    if record.standalone != record.machine_ir {
        return Err(X64StandaloneProcessError::SemanticMismatch {
            case_ordinal: record.case_ordinal,
        });
    }
    let output = decode_x64_standalone_output_for_profile(&record.output_frame, record.profile)
        .map_err(|error| protocol_error(record.case_ordinal, error))?;
    let canonical = encode_x64_standalone_output(output)
        .map_err(|error| protocol_error(record.case_ordinal, error))?;
    if record.output_frame != canonical
        || record.output_frame_hash != raw_frame_hash(&record.output_frame)
        || record.standalone != normalize_standalone_output(output)
    {
        return Err(X64StandaloneProcessError::InvalidRecord {
            case_ordinal: record.case_ordinal,
            field: "canonical output frame",
        });
    }
    Ok(())
}

fn validate_observation(
    case_ordinal: u32,
    observation: &X64StandaloneExecutionObservation,
) -> Result<(), X64StandaloneProcessError> {
    let canonical = match observation.outcome {
        X64StandaloneExecutionOutcome::ReturnF64(X64StandaloneExecutionF64::ExactBits(bits)) => {
            !f64::from_bits(bits).is_nan() && observation.effects.is_empty()
        }
        X64StandaloneExecutionOutcome::ReturnF64(X64StandaloneExecutionF64::CanonicalNaN) => {
            observation.effects.is_empty()
        }
        X64StandaloneExecutionOutcome::Bounds => {
            observation.effects == [X64StandaloneExecutionEffect::Bounds]
        }
    };
    if !canonical {
        return Err(X64StandaloneProcessError::InvalidRecord {
            case_ordinal,
            field: "semantic observation",
        });
    }
    Ok(())
}

fn validate_order_and_uniqueness(
    records: &[X64StandaloneExecutionRecord],
) -> Result<(), X64StandaloneProcessError> {
    if records.len() != COREVM0_GATE_A_TOTAL_CASES as usize {
        return Err(X64StandaloneProcessError::FixedCorpusCount {
            expected: COREVM0_GATE_A_TOTAL_CASES,
            actual: records.len(),
        });
    }
    let mut seen = [false; COREVM0_GATE_A_TOTAL_CASES as usize];
    for record in records {
        let index = usize::try_from(record.case_ordinal).map_err(|_| {
            X64StandaloneProcessError::MetricOverflow {
                field: "case ordinal",
            }
        })?;
        if index >= seen.len() {
            return Err(X64StandaloneProcessError::InvalidRecord {
                case_ordinal: record.case_ordinal,
                field: "case ordinal",
            });
        }
        if seen[index] {
            return Err(X64StandaloneProcessError::DuplicateOrdinal {
                ordinal: record.case_ordinal,
            });
        }
        seen[index] = true;
    }
    for (expected, record) in records.iter().enumerate() {
        let expected =
            u32::try_from(expected).map_err(|_| X64StandaloneProcessError::MetricOverflow {
                field: "case ordinal",
            })?;
        if record.case_ordinal != expected {
            return Err(X64StandaloneProcessError::NonCanonicalOrder {
                expected,
                actual: record.case_ordinal,
            });
        }
    }
    Ok(())
}

fn encode_execution_record(
    record: &X64StandaloneExecutionRecord,
) -> Result<Vec<u8>, X64StandaloneProcessError> {
    let mut bytes = Vec::with_capacity(1_024);
    bytes.extend_from_slice(X64_STANDALONE_EXECUTION_RECORD_DOMAIN);
    put_version(&mut bytes, record.execution_schema_version);
    put_version(&mut bytes, record.execution_policy_version);
    put_u32(&mut bytes, record.case_ordinal);
    put_u32(&mut bytes, record.total_cases);
    put_hash(&mut bytes, record.manifest_hash);
    put_u16(&mut bytes, record.profile.wire_tag());
    bytes.push(case_class_tag(record.case_class));
    put_hash(&mut bytes, record.gate_a_input_hash);
    put_hash(&mut bytes, record.source_core_hash);
    put_hash(&mut bytes, record.source_ssa_hash);
    put_hash(&mut bytes, record.source_machine_ir_hash);
    put_hash(&mut bytes, record.target_artifact_hash);
    put_hash(&mut bytes, record.target_plan_hash);
    put_hash(&mut bytes, record.target_code_hash);
    put_hash(&mut bytes, record.canonical_abi_hash);
    put_u32(&mut bytes, record.target_entry_offset);
    bytes.push(record.target_input_lanes);
    put_hash(&mut bytes, record.inherited_semantic_results_hash);
    put_hash(&mut bytes, record.inherited_process_results_hash);
    put_hash(&mut bytes, record.standalone_artifact_hash);
    put_hash(&mut bytes, record.elf_image_hash);
    put_hash(&mut bytes, record.startup_plan_hash);
    put_hash(&mut bytes, record.startup_code_hash);
    put_hash(&mut bytes, record.io_contract_hash);
    put_u64(&mut bytes, record.input_frame_bytes);
    put_hash(&mut bytes, record.input_frame_hash);
    put_u32(&mut bytes, record.normal_exit_code);
    put_u32(
        &mut bytes,
        u32::try_from(record.output_frame.len()).map_err(|_| {
            X64StandaloneProcessError::MetricOverflow {
                field: "output frame length",
            }
        })?,
    );
    bytes.extend_from_slice(&record.output_frame);
    put_hash(&mut bytes, record.output_frame_hash);
    encode_observation(&mut bytes, &record.standalone)?;
    encode_observation(&mut bytes, &record.machine_ir)?;
    put_u64(&mut bytes, record.stdout_bytes);
    put_u64(&mut bytes, record.stderr_bytes);
    put_u32(&mut bytes, record.per_process_timeout_ms);
    put_u32(&mut bytes, record.max_captured_diagnostic_bytes);
    put_u32(&mut bytes, record.max_captured_diagnostic_records);
    for flag in [
        record.timeout,
        record.fault,
        record.abnormal_status,
        record.interpreter_dependency,
        record.external_symbol_dependency,
        record.dynamic_loader_dependency,
        record.system_linker_dependency,
        record.fallback,
    ] {
        bytes.push(u8::from(flag));
    }
    Ok(bytes)
}

fn encode_observation(
    bytes: &mut Vec<u8>,
    observation: &X64StandaloneExecutionObservation,
) -> Result<(), X64StandaloneProcessError> {
    match observation.outcome {
        X64StandaloneExecutionOutcome::ReturnF64(X64StandaloneExecutionF64::ExactBits(bits)) => {
            bytes.push(0);
            put_u64(bytes, bits);
        }
        X64StandaloneExecutionOutcome::ReturnF64(X64StandaloneExecutionF64::CanonicalNaN) => {
            bytes.push(1)
        }
        X64StandaloneExecutionOutcome::Bounds => bytes.push(2),
    }
    put_u32(
        bytes,
        u32::try_from(observation.effects.len()).map_err(|_| {
            X64StandaloneProcessError::MetricOverflow {
                field: "effect count",
            }
        })?,
    );
    for effect in &observation.effects {
        bytes.push(match effect {
            X64StandaloneExecutionEffect::Bounds => 0,
        });
    }
    Ok(())
}

struct ProcessCapture {
    status: ProcessStatusObservation,
    timed_out: bool,
    stdout: PipeCapture,
    stderr: PipeCapture,
    elapsed: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessStatusObservation {
    code: Option<i32>,
    signal: Option<i32>,
}

fn run_direct_process(
    executable: &Path,
    case_ordinal: u32,
    input_frame: Vec<u8>,
) -> Result<ProcessCapture, X64StandaloneProcessError> {
    run_direct_process_with_timeout(
        executable,
        case_ordinal,
        input_frame,
        X64_STANDALONE_PROCESS_TIMEOUT_MILLIS,
    )
}

fn run_direct_process_with_timeout(
    executable: &Path,
    case_ordinal: u32,
    input_frame: Vec<u8>,
    timeout_millis: u32,
) -> Result<ProcessCapture, X64StandaloneProcessError> {
    let mut command = Command::new(executable);
    command
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_direct_process_group(&mut command);
    let process_started = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| X64StandaloneProcessError::Spawn {
            case_ordinal,
            kind: error.kind(),
        })?;
    let Some(stdin) = child.stdin.take() else {
        let primary = X64StandaloneProcessError::MissingPipe {
            case_ordinal,
            stream: "stdin",
        };
        return Err(teardown_after_primary(&mut child, case_ordinal, primary));
    };
    let Some(stdout) = child.stdout.take() else {
        drop(stdin);
        let primary = X64StandaloneProcessError::MissingPipe {
            case_ordinal,
            stream: "stdout",
        };
        return Err(teardown_after_primary(&mut child, case_ordinal, primary));
    };
    let Some(stderr) = child.stderr.take() else {
        drop(stdin);
        drop(stdout);
        let primary = X64StandaloneProcessError::MissingPipe {
            case_ordinal,
            stream: "stderr",
        };
        return Err(teardown_after_primary(&mut child, case_ordinal, primary));
    };

    let stdout_reader =
        match spawn_pipe_reader(stdout, X64_STANDALONE_OUTPUT_BYTES as u64, false, "stdout") {
            Ok(reader) => reader,
            Err(error) => {
                drop(stdin);
                drop(stderr);
                let primary = X64StandaloneProcessError::PipeThreadSpawn {
                    case_ordinal,
                    stream: "stdout",
                    kind: error.kind(),
                };
                return Err(teardown_after_primary(&mut child, case_ordinal, primary));
            }
        };
    let stderr_reader = match spawn_pipe_reader(
        stderr,
        u64::from(X64_STANDALONE_PROCESS_MAX_DIAGNOSTIC_BYTES),
        true,
        "stderr",
    ) {
        Ok(reader) => reader,
        Err(error) => {
            drop(stdin);
            let primary = X64StandaloneProcessError::PipeThreadSpawn {
                case_ordinal,
                stream: "stderr",
                kind: error.kind(),
            };
            let mut failure = teardown_after_primary(&mut child, case_ordinal, primary);
            if let Err(cleanup) = join_pipe_reader_bounded(stdout_reader, case_ordinal, "stdout") {
                failure = combine_containment_failure(case_ordinal, failure, cleanup);
            }
            return Err(failure);
        }
    };
    let stdin_writer = match spawn_stdin_writer(stdin, input_frame) {
        Ok(writer) => writer,
        Err(error) => {
            let primary = X64StandaloneProcessError::PipeThreadSpawn {
                case_ordinal,
                stream: "stdin",
                kind: error.kind(),
            };
            let mut failure = teardown_after_primary(&mut child, case_ordinal, primary);
            if let Err(cleanup) = join_pipe_reader_bounded(stdout_reader, case_ordinal, "stdout") {
                failure = combine_containment_failure(case_ordinal, failure, cleanup);
            }
            if let Err(cleanup) = join_pipe_reader_bounded(stderr_reader, case_ordinal, "stderr") {
                failure = combine_containment_failure(case_ordinal, failure, cleanup);
            }
            return Err(failure);
        }
    };

    let wait = wait_for_child(
        &mut child,
        process_started,
        Duration::from_millis(u64::from(timeout_millis)),
    );

    let stdin_result = join_stdin_writer_bounded(stdin_writer, case_ordinal);
    let stdout = join_pipe_reader_bounded(stdout_reader, case_ordinal, "stdout");
    let stderr = join_pipe_reader_bounded(stderr_reader, case_ordinal, "stderr");
    let containment_timed_out = deadline_expired(
        process_started.elapsed(),
        Duration::from_millis(u64::from(timeout_millis)),
    );
    let wait = match wait {
        Ok(status) => status,
        Err(outcome) => {
            let primary = process_error_from_wait_outcome(case_ordinal, timeout_millis, outcome);
            let cleanup = resolve_pipe_tasks(case_ordinal, stdin_result, stdout, stderr);
            return Err(match cleanup {
                Ok(_) => primary,
                Err(cleanup) => combine_containment_failure(case_ordinal, primary, cleanup),
            });
        }
    };
    if containment_timed_out {
        let primary = X64StandaloneProcessError::Timeout {
            case_ordinal,
            timeout_millis,
        };
        let cleanup = resolve_pipe_tasks(case_ordinal, stdin_result, stdout, stderr);
        return Err(match cleanup {
            Ok(_) => primary,
            Err(cleanup) => combine_containment_failure(case_ordinal, primary, cleanup),
        });
    }
    let (stdout, stderr) = resolve_pipe_tasks(case_ordinal, stdin_result, stdout, stderr)?;
    let elapsed = process_started.elapsed();
    Ok(ProcessCapture {
        status: status_observation(wait),
        timed_out: false,
        stdout,
        stderr,
        elapsed,
    })
}

fn process_error_from_wait_outcome(
    case_ordinal: u32,
    timeout_millis: u32,
    outcome: WaitOutcome,
) -> X64StandaloneProcessError {
    match outcome {
        WaitOutcome::Timeout => X64StandaloneProcessError::Timeout {
            case_ordinal,
            timeout_millis,
        },
        WaitOutcome::TimeoutAndTeardown(teardown) => combine_containment_failure(
            case_ordinal,
            X64StandaloneProcessError::Timeout {
                case_ordinal,
                timeout_millis,
            },
            X64StandaloneProcessError::Teardown {
                case_ordinal,
                failure: teardown,
            },
        ),
        WaitOutcome::Io(kind) => X64StandaloneProcessError::Wait { case_ordinal, kind },
        WaitOutcome::Teardown(failure) => X64StandaloneProcessError::Teardown {
            case_ordinal,
            failure,
        },
        WaitOutcome::IoAndTeardown { kind, teardown } => combine_containment_failure(
            case_ordinal,
            X64StandaloneProcessError::Wait { case_ordinal, kind },
            X64StandaloneProcessError::Teardown {
                case_ordinal,
                failure: teardown,
            },
        ),
    }
}

fn teardown_after_primary(
    child: &mut Child,
    case_ordinal: u32,
    primary: X64StandaloneProcessError,
) -> X64StandaloneProcessError {
    match teardown_direct_child(child) {
        Ok(_) => primary,
        Err(failure) => combine_containment_failure(
            case_ordinal,
            primary,
            X64StandaloneProcessError::Teardown {
                case_ordinal,
                failure,
            },
        ),
    }
}

fn combine_containment_failure(
    case_ordinal: u32,
    primary: X64StandaloneProcessError,
    cleanup: X64StandaloneProcessError,
) -> X64StandaloneProcessError {
    X64StandaloneProcessError::FailureDuringContainment {
        case_ordinal,
        primary: Box::new(primary),
        cleanup: Box::new(cleanup),
    }
}

fn resolve_pipe_tasks(
    case_ordinal: u32,
    stdin: Result<(), X64StandaloneProcessError>,
    stdout: Result<PipeCapture, X64StandaloneProcessError>,
    stderr: Result<PipeCapture, X64StandaloneProcessError>,
) -> Result<(PipeCapture, PipeCapture), X64StandaloneProcessError> {
    let mut failure = None;
    if let Err(error) = stdin {
        append_cleanup_failure(case_ordinal, &mut failure, error);
    }
    let stdout = match stdout {
        Ok(capture) => Some(capture),
        Err(error) => {
            append_cleanup_failure(case_ordinal, &mut failure, error);
            None
        }
    };
    let stderr = match stderr {
        Ok(capture) => Some(capture),
        Err(error) => {
            append_cleanup_failure(case_ordinal, &mut failure, error);
            None
        }
    };
    if let Some(failure) = failure {
        return Err(failure);
    }
    match (stdout, stderr) {
        (Some(stdout), Some(stderr)) => Ok((stdout, stderr)),
        _ => Err(X64StandaloneProcessError::InvalidRecord {
            case_ordinal,
            field: "pipe task completion",
        }),
    }
}

fn append_cleanup_failure(
    case_ordinal: u32,
    slot: &mut Option<X64StandaloneProcessError>,
    cleanup: X64StandaloneProcessError,
) {
    *slot = Some(match slot.take() {
        Some(primary) => combine_containment_failure(case_ordinal, primary, cleanup),
        None => cleanup,
    });
}

enum WaitOutcome {
    Timeout,
    TimeoutAndTeardown(X64StandaloneTeardownFailure),
    Io(io::ErrorKind),
    Teardown(X64StandaloneTeardownFailure),
    IoAndTeardown {
        kind: io::ErrorKind,
        teardown: X64StandaloneTeardownFailure,
    },
}

fn wait_for_child(
    child: &mut Child,
    process_started: Instant,
    timeout: Duration,
) -> Result<ExitStatus, WaitOutcome> {
    loop {
        if deadline_expired(process_started.elapsed(), timeout) {
            return match teardown_direct_child(child) {
                Ok(_) => Err(WaitOutcome::Timeout),
                Err(teardown) => Err(WaitOutcome::TimeoutAndTeardown(teardown)),
            };
        }
        match observe_child_exit_without_reaping(child.id()) {
            Ok(true) => {
                if deadline_expired(process_started.elapsed(), timeout) {
                    return match teardown_direct_child(child) {
                        Ok(_) => Err(WaitOutcome::Timeout),
                        Err(teardown) => Err(WaitOutcome::TimeoutAndTeardown(teardown)),
                    };
                }
                return teardown_direct_child(child).map_err(WaitOutcome::Teardown);
            }
            Ok(false) => {
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                // Once ECHILD is observed, targeting the numeric process-group
                // id could hit a reused PID.  Other observation failures still
                // receive a best-effort bounded teardown.
                const LINUX_ECHILD: i32 = 10;
                if error.raw_os_error() != Some(LINUX_ECHILD) {
                    return match teardown_direct_child(child) {
                        Ok(_) => Err(WaitOutcome::Io(error.kind())),
                        Err(teardown) => Err(WaitOutcome::IoAndTeardown {
                            kind: error.kind(),
                            teardown,
                        }),
                    };
                }
                return Err(WaitOutcome::Io(error.kind()));
            }
        }
    }
}

fn deadline_expired(elapsed: Duration, timeout: Duration) -> bool {
    elapsed >= timeout
}

fn teardown_direct_child(child: &mut Child) -> Result<ExitStatus, X64StandaloneTeardownFailure> {
    let group_kill = terminate_direct_process_group(child.id());
    let group_kill_error = group_kill.err().map(|error| error.kind());
    let leader_kill_error = if group_kill_error.is_some() {
        // The PID is still stable because waitid used WNOWAIT or because the
        // child has not exited. This fallback closes the verified leader even
        // if process-group termination itself failed.
        child.kill().err().map(|error| error.kind())
    } else {
        None
    };
    match reap_child_bounded(child, PROCESS_REAP_TIMEOUT) {
        Ok(status) if group_kill_error.is_none() && leader_kill_error.is_none() => Ok(status),
        Ok(_) => Err(X64StandaloneTeardownFailure {
            group_kill: group_kill_error,
            leader_kill: leader_kill_error,
            reap: None,
        }),
        Err(error) => Err(X64StandaloneTeardownFailure {
            group_kill: group_kill_error,
            leader_kill: leader_kill_error,
            reap: Some(error.kind()),
        }),
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn observe_child_exit_without_reaping(process_id: u32) -> Result<bool, io::Error> {
    const LINUX_X86_64_WAITID_SYSCALL: i64 = 247;
    const P_PID: i64 = 1;
    const WNOHANG: i64 = 0x0000_0001;
    const WEXITED: i64 = 0x0000_0004;
    const WNOWAIT: i64 = 0x0100_0000;
    const SIGINFO_BYTES: usize = 128;
    const SIGINFO_PID_OFFSET: usize = 16;

    let process_id = i32::try_from(process_id).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "R1-S8c child id exceeds Linux pid_t",
        )
    })?;
    #[repr(C, align(8))]
    struct LinuxSigInfo {
        bytes: [u8; SIGINFO_BYTES],
    }
    let mut signal_info = LinuxSigInfo {
        bytes: [0; SIGINFO_BYTES],
    };
    let mut result = LINUX_X86_64_WAITID_SYSCALL;
    // SAFETY: Linux x86-64 syscall 247 receives P_PID, one positive pid_t,
    // a writable, correctly sized/aligned siginfo_t buffer, the documented
    // WEXITED|WNOHANG|WNOWAIT mask, and a null rusage pointer. WNOWAIT keeps
    // the leader PID/PGID stable until the complete process group is killed
    // and the leader is reaped; rcx/r11 are declared syscall clobbers.
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") result,
            in("rdi") P_PID,
            in("rsi") i64::from(process_id),
            in("rdx") signal_info.bytes.as_mut_ptr(),
            in("r10") WEXITED | WNOHANG | WNOWAIT,
            in("r8") 0_i64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if result < 0 {
        let errno = result
            .checked_neg()
            .and_then(|value| i32::try_from(value).ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "R1-S8c waitid returned an invalid errno",
                )
            })?;
        return Err(io::Error::from_raw_os_error(errno));
    }
    let observed_pid = i32::from_ne_bytes([
        signal_info.bytes[SIGINFO_PID_OFFSET],
        signal_info.bytes[SIGINFO_PID_OFFSET + 1],
        signal_info.bytes[SIGINFO_PID_OFFSET + 2],
        signal_info.bytes[SIGINFO_PID_OFFSET + 3],
    ]);
    if observed_pid == 0 {
        return Ok(false);
    }
    if observed_pid != process_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "R1-S8c waitid observed a different child",
        ));
    }
    Ok(true)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn observe_child_exit_without_reaping(_process_id: u32) -> Result<bool, io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "R1-S8c waitid observation requires Linux x86-64",
    ))
}

fn configure_direct_process_group(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
}

fn reap_child_bounded(child: &mut Child, timeout: Duration) -> Result<ExitStatus, io::Error> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if started.elapsed() < timeout => thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "R1-S8c child did not terminate after process-group kill",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn terminate_direct_process_group(process_group_id: u32) -> Result<(), io::Error> {
    const LINUX_X86_64_KILL_SYSCALL: i64 = 62;
    const SIGKILL: i64 = 9;
    const ESRCH: i32 = 3;

    let process_group_id = i32::try_from(process_group_id).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "R1-S8c process-group id exceeds Linux pid_t",
        )
    })?;
    let mut result = LINUX_X86_64_KILL_SYSCALL;
    // SAFETY: Linux x86-64 syscall 62 receives only the negative, validated
    // process-group id and SIGKILL. It dereferences no memory and aliases no
    // Rust state; rcx/r11 are declared syscall clobbers.
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") result,
            in("rdi") -i64::from(process_group_id),
            in("rsi") SIGKILL,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if result >= 0 {
        return Ok(());
    }
    let errno = result
        .checked_neg()
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "R1-S8c kill returned an invalid errno",
            )
        })?;
    if errno == ESRCH {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(errno))
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn terminate_direct_process_group(_process_group_id: u32) -> Result<(), io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "R1-S8c process groups require Linux x86-64",
    ))
}

struct PipeCapture {
    bytes: Vec<u8>,
    total_bytes: u64,
    diagnostic_records: u32,
    error: Option<io::ErrorKind>,
    overflow: bool,
}

fn spawn_pipe_reader<R: Read + Send + 'static>(
    reader: R,
    byte_limit: u64,
    count_diagnostics: bool,
    stream: &'static str,
) -> Result<JoinHandle<PipeCapture>, io::Error> {
    thread::Builder::new()
        .name(format!("naux-r1-s8c-{stream}-reader"))
        .spawn(move || read_pipe_bounded(reader, byte_limit, count_diagnostics))
}

fn read_pipe_bounded(
    mut reader: impl Read,
    byte_limit: u64,
    count_diagnostics: bool,
) -> PipeCapture {
    let mut capture = PipeCapture {
        bytes: Vec::new(),
        total_bytes: 0,
        diagnostic_records: 0,
        error: None,
        overflow: false,
    };
    let Some(retained_limit) = byte_limit.checked_add(1) else {
        capture.overflow = true;
        return capture;
    };
    let mut buffer = [0_u8; 1_024];
    let mut saw_diagnostic_byte = false;
    let mut ended_with_newline = false;
    'read_loop: loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                capture.error = Some(error.kind());
                break;
            }
        };
        let read_u64 = match u64::try_from(read) {
            Ok(read) => read,
            Err(_) => {
                capture.overflow = true;
                break;
            }
        };
        match capture.total_bytes.checked_add(read_u64) {
            Some(total) => capture.total_bytes = total,
            None => {
                capture.overflow = true;
                break;
            }
        }
        if count_diagnostics {
            saw_diagnostic_byte = true;
            for byte in &buffer[..read] {
                if *byte == b'\n' {
                    capture.diagnostic_records = match capture.diagnostic_records.checked_add(1) {
                        Some(records) => records,
                        None => {
                            capture.overflow = true;
                            break 'read_loop;
                        }
                    };
                }
            }
            ended_with_newline = buffer[read - 1] == b'\n';
        }
        match u64::try_from(capture.bytes.len()) {
            Ok(retained) if retained < retained_limit => {
                let remaining = retained_limit - retained;
                let copy = match usize::try_from(remaining) {
                    Ok(remaining) => remaining.min(read),
                    Err(_) => {
                        capture.overflow = true;
                        break;
                    }
                };
                capture.bytes.extend_from_slice(&buffer[..copy]);
            }
            Ok(_) => {}
            Err(_) => {
                capture.overflow = true;
                break;
            }
        }
    }
    if count_diagnostics && saw_diagnostic_byte && !ended_with_newline {
        if let Some(records) = capture.diagnostic_records.checked_add(1) {
            capture.diagnostic_records = records;
        } else {
            capture.overflow = true;
        }
    }
    capture
}

fn join_pipe_reader_bounded(
    reader: JoinHandle<PipeCapture>,
    case_ordinal: u32,
    stream: &'static str,
) -> Result<PipeCapture, X64StandaloneProcessError> {
    let started = Instant::now();
    while !reader.is_finished() {
        if started.elapsed() >= PIPE_TASK_JOIN_TIMEOUT {
            return Err(X64StandaloneProcessError::PipeThreadTimeout {
                case_ordinal,
                stream,
            });
        }
        thread::sleep(POLL_INTERVAL);
    }
    reader
        .join()
        .map_err(|_| X64StandaloneProcessError::PipeThreadPanicked {
            case_ordinal,
            stream,
        })
}

fn spawn_stdin_writer(
    mut stdin: impl Write + Send + 'static,
    input_frame: Vec<u8>,
) -> Result<JoinHandle<Result<(), io::ErrorKind>>, io::Error> {
    thread::Builder::new()
        .name("naux-r1-s8c-stdin-writer".to_string())
        .spawn(move || {
            stdin
                .write_all(&input_frame)
                .and_then(|()| stdin.flush())
                .map_err(|error| error.kind())
            // Dropping the sole ChildStdin here supplies exact EOF.
        })
}

fn join_stdin_writer_bounded(
    writer: JoinHandle<Result<(), io::ErrorKind>>,
    case_ordinal: u32,
) -> Result<(), X64StandaloneProcessError> {
    let started = Instant::now();
    while !writer.is_finished() {
        if started.elapsed() >= PIPE_TASK_JOIN_TIMEOUT {
            return Err(X64StandaloneProcessError::PipeThreadTimeout {
                case_ordinal,
                stream: "stdin",
            });
        }
        thread::sleep(POLL_INTERVAL);
    }
    writer
        .join()
        .map_err(|_| X64StandaloneProcessError::PipeThreadPanicked {
            case_ordinal,
            stream: "stdin",
        })?
        .map_err(|kind| X64StandaloneProcessError::PipeIo {
            case_ordinal,
            stream: "stdin",
            kind,
        })
}

fn admit_timeout(case_ordinal: u32, timed_out: bool) -> Result<(), X64StandaloneProcessError> {
    if timed_out {
        Err(X64StandaloneProcessError::Timeout {
            case_ordinal,
            timeout_millis: X64_STANDALONE_PROCESS_TIMEOUT_MILLIS,
        })
    } else {
        Ok(())
    }
}

fn admit_process_status(
    case_ordinal: u32,
    status: ProcessStatusObservation,
) -> Result<u32, X64StandaloneProcessError> {
    if status.signal.is_some() {
        return Err(X64StandaloneProcessError::Fault {
            case_ordinal,
            signal: status.signal,
        });
    }
    match status.code {
        Some(0) => Ok(0),
        code => Err(X64StandaloneProcessError::AbnormalExit { case_ordinal, code }),
    }
}

fn admit_stdout(
    case_ordinal: u32,
    profile: X64StandaloneProfile,
    capture: &PipeCapture,
) -> Result<([u8; X64_STANDALONE_OUTPUT_BYTES], X64StandaloneOutput), X64StandaloneProcessError> {
    admit_capture_io(case_ordinal, "stdout", capture)?;
    if capture.total_bytes != X64_STANDALONE_OUTPUT_BYTES as u64
        || capture.bytes.len() != X64_STANDALONE_OUTPUT_BYTES
    {
        return Err(X64StandaloneProcessError::StdoutLength {
            case_ordinal,
            expected: X64_STANDALONE_OUTPUT_BYTES as u64,
            actual: capture.total_bytes,
        });
    }
    let frame: [u8; X64_STANDALONE_OUTPUT_BYTES] =
        capture.bytes.as_slice().try_into().map_err(|_| {
            X64StandaloneProcessError::StdoutLength {
                case_ordinal,
                expected: X64_STANDALONE_OUTPUT_BYTES as u64,
                actual: capture.total_bytes,
            }
        })?;
    let output = decode_x64_standalone_output_for_profile(&frame, profile)
        .map_err(|error| protocol_error(case_ordinal, error))?;
    Ok((frame, output))
}

fn admit_stderr(case_ordinal: u32, capture: &PipeCapture) -> Result<(), X64StandaloneProcessError> {
    admit_capture_io(case_ordinal, "stderr", capture)?;
    let byte_limit = u64::from(X64_STANDALONE_PROCESS_MAX_DIAGNOSTIC_BYTES);
    if capture.total_bytes > byte_limit {
        return Err(X64StandaloneProcessError::StderrByteLimit {
            case_ordinal,
            limit: byte_limit,
            actual: capture.total_bytes,
        });
    }
    if capture.diagnostic_records > X64_STANDALONE_PROCESS_MAX_DIAGNOSTIC_RECORDS {
        return Err(X64StandaloneProcessError::StderrRecordLimit {
            case_ordinal,
            limit: X64_STANDALONE_PROCESS_MAX_DIAGNOSTIC_RECORDS,
            actual: capture.diagnostic_records,
        });
    }
    if capture.total_bytes != 0 {
        return Err(X64StandaloneProcessError::UnexpectedStderr {
            case_ordinal,
            actual: capture.total_bytes,
        });
    }
    Ok(())
}

fn admit_capture_io(
    case_ordinal: u32,
    stream: &'static str,
    capture: &PipeCapture,
) -> Result<(), X64StandaloneProcessError> {
    if capture.overflow {
        return Err(X64StandaloneProcessError::CaptureOverflow {
            case_ordinal,
            stream,
        });
    }
    if let Some(kind) = capture.error {
        return Err(X64StandaloneProcessError::PipeIo {
            case_ordinal,
            stream,
            kind,
        });
    }
    Ok(())
}

fn status_observation(status: ExitStatus) -> ProcessStatusObservation {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        ProcessStatusObservation {
            code: status.code(),
            signal: status.signal(),
        }
    }
    #[cfg(not(unix))]
    {
        ProcessStatusObservation {
            code: status.code(),
            signal: None,
        }
    }
}

struct TempExecutable {
    path: PathBuf,
    live: bool,
}

impl TempExecutable {
    fn create(
        profile: X64StandaloneProfile,
        verified_image: &[u8],
    ) -> Result<Self, X64StandaloneProcessError> {
        #[cfg(not(unix))]
        {
            let _ = profile;
            let _ = verified_image;
            return Err(X64StandaloneProcessError::UnsupportedHost);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

            let directory = fs::canonicalize(std::env::temp_dir())
                .map_err(|error| X64StandaloneProcessError::TempCreate { kind: error.kind() })?;
            let process_id = std::process::id();
            for _ in 0..TEMP_CREATE_ATTEMPTS {
                let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                let name = format!(
                    ".naux-r1-s8c-{process_id}-{}-{sequence:016x}",
                    profile.wire_tag()
                );
                let path = directory.join(name);
                let opened = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(TEMP_CREATE_MODE)
                    .open(&path);
                let mut file = match opened {
                    Ok(file) => file,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        continue;
                    }
                    Err(error) => {
                        return Err(X64StandaloneProcessError::TempCreate { kind: error.kind() });
                    }
                };
                let write = file
                    .write_all(verified_image)
                    .and_then(|()| file.sync_all());
                if let Err(error) = write {
                    drop(file);
                    remove_partial_temp(&path)?;
                    return Err(X64StandaloneProcessError::TempWrite { kind: error.kind() });
                }
                drop(file);
                let readback = match fs::read(&path) {
                    Ok(readback) => readback,
                    Err(error) => {
                        remove_partial_temp(&path)?;
                        return Err(X64StandaloneProcessError::TempReadback { kind: error.kind() });
                    }
                };
                if readback != verified_image {
                    remove_partial_temp(&path)?;
                    return Err(X64StandaloneProcessError::TempReadbackMismatch);
                }
                if let Err(error) = fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(X64_STANDALONE_PROCESS_EXECUTABLE_MODE),
                ) {
                    remove_partial_temp(&path)?;
                    return Err(X64StandaloneProcessError::TempMode { kind: error.kind() });
                }
                let metadata = match fs::metadata(&path) {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        remove_partial_temp(&path)?;
                        return Err(X64StandaloneProcessError::TempMode { kind: error.kind() });
                    }
                };
                if !metadata.file_type().is_file()
                    || metadata.permissions().mode() & 0o7777
                        != X64_STANDALONE_PROCESS_EXECUTABLE_MODE
                {
                    remove_partial_temp(&path)?;
                    return Err(X64StandaloneProcessError::TempMode {
                        kind: io::ErrorKind::InvalidData,
                    });
                }
                return Ok(Self { path, live: true });
            }
            Err(X64StandaloneProcessError::TempCreateExhausted {
                attempts: TEMP_CREATE_ATTEMPTS,
            })
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn cleanup(&mut self) -> Result<(), X64StandaloneProcessError> {
        if !self.live {
            return Ok(());
        }
        fs::remove_file(&self.path)
            .map_err(|error| X64StandaloneProcessError::TempCleanup { kind: error.kind() })?;
        self.live = false;
        Ok(())
    }
}

fn remove_partial_temp(path: &Path) -> Result<(), X64StandaloneProcessError> {
    fs::remove_file(path)
        .map_err(|error| X64StandaloneProcessError::TempCleanup { kind: error.kind() })
}

impl Drop for TempExecutable {
    fn drop(&mut self) {
        if self.live {
            let _ = fs::remove_file(&self.path);
            self.live = false;
        }
    }
}

/// One temporary executable whose bytes and exact mode were read back before
/// this handle was returned.  Callers in the Gate B layer must first retain
/// the appropriate lifetime-bound artifact verification token.
pub(super) struct PreparedX64StandaloneExecutable {
    inner: TempExecutable,
}

impl PreparedX64StandaloneExecutable {
    pub(super) fn create(
        profile: X64StandaloneProfile,
        verified_image: &[u8],
    ) -> Result<Self, X64StandaloneProcessError> {
        Ok(Self {
            inner: TempExecutable::create(profile, verified_image)?,
        })
    }

    pub(super) fn path(&self) -> &Path {
        self.inner.path()
    }

    pub(super) fn cleanup(&mut self) -> Result<(), X64StandaloneProcessError> {
        self.inner.cleanup()
    }
}

/// Fully admitted output of one fresh standalone process.  The elapsed value
/// stops after exact pipe capture, process-group containment, and child reap,
/// but before semantic output decoding and comparison.
pub(super) struct AdmittedX64StandaloneProcess {
    output_frame: [u8; X64_STANDALONE_OUTPUT_BYTES],
    output: X64StandaloneOutput,
    elapsed_nanoseconds: u64,
}

impl AdmittedX64StandaloneProcess {
    pub(super) const fn output_frame(&self) -> &[u8; X64_STANDALONE_OUTPUT_BYTES] {
        &self.output_frame
    }

    pub(super) const fn output(&self) -> X64StandaloneOutput {
        self.output
    }

    pub(super) const fn elapsed_nanoseconds(&self) -> u64 {
        self.elapsed_nanoseconds
    }
}

/// Run and fully admit one canonical direct-process invocation using the same
/// containment harness as R1-S8c.
pub(super) fn run_admitted_x64_standalone_process(
    executable: &PreparedX64StandaloneExecutable,
    case_ordinal: u32,
    input_frame: Vec<u8>,
    profile: X64StandaloneProfile,
    timeout_millis: u32,
) -> Result<AdmittedX64StandaloneProcess, X64StandaloneProcessError> {
    let process = run_direct_process_with_timeout(
        executable.path(),
        case_ordinal,
        input_frame,
        timeout_millis,
    )?;
    admit_timeout(case_ordinal, process.timed_out)?;
    let _ = admit_process_status(case_ordinal, process.status)?;
    let (output_frame, output) = admit_stdout(case_ordinal, profile, &process.stdout)?;
    admit_stderr(case_ordinal, &process.stderr)?;
    let elapsed_nanoseconds = u64::try_from(process.elapsed.as_nanos()).map_err(|_| {
        X64StandaloneProcessError::MetricOverflow {
            field: "direct process elapsed nanoseconds",
        }
    })?;
    if elapsed_nanoseconds == 0 {
        return Err(X64StandaloneProcessError::InvalidRecord {
            case_ordinal,
            field: "zero direct process elapsed nanoseconds",
        });
    }
    Ok(AdmittedX64StandaloneProcess {
        output_frame,
        output,
        elapsed_nanoseconds,
    })
}

fn profile_for_workload(workload: CoreVmGateAWorkload) -> X64StandaloneProfile {
    match workload {
        CoreVmGateAWorkload::BranchMix => X64StandaloneProfile::BranchMix,
        CoreVmGateAWorkload::BoundsOrderedArrayGet => X64StandaloneProfile::Bounds,
    }
}

fn case_class_tag(class: CoreVmGateACaseClass) -> u8 {
    match class {
        CoreVmGateACaseClass::Edge => 0,
        CoreVmGateACaseClass::BoundedExhaustive => 1,
        CoreVmGateACaseClass::DeterministicGenerated => 2,
        CoreVmGateACaseClass::BoundsEffect => 3,
    }
}

fn raw_frame_hash(frame: &[u8]) -> SemanticHash {
    SemanticHash(sha256(frame))
}

fn protocol_error(
    case_ordinal: u32,
    error: X64StandaloneProtocolError,
) -> X64StandaloneProcessError {
    X64StandaloneProcessError::Protocol {
        case_ordinal,
        message: error.to_string(),
    }
}

fn artifact_error(
    profile: X64StandaloneProfile,
    error: X64StandaloneArtifactError,
) -> X64StandaloneProcessError {
    X64StandaloneProcessError::Artifact {
        profile,
        message: error.to_string(),
    }
}

fn authority_error(
    profile: X64StandaloneProfile,
    error: X64StandaloneAuthorityError,
) -> X64StandaloneProcessError {
    X64StandaloneProcessError::Authority {
        profile,
        message: error.to_string(),
    }
}

fn require_supported_host() -> Result<(), X64StandaloneProcessError> {
    if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        Ok(())
    } else {
        Err(X64StandaloneProcessError::UnsupportedHost)
    }
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

fn put_hash(bytes: &mut Vec<u8>, hash: SemanticHash) {
    bytes.extend_from_slice(&hash.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonzero(byte: u8) -> SemanticHash {
        SemanticHash([byte; 32])
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    struct FixtureProgram {
        code: Vec<u8>,
        payloads: Vec<(usize, Vec<u8>)>,
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    impl FixtureProgram {
        fn new() -> Self {
            Self {
                code: Vec::new(),
                payloads: Vec::new(),
            }
        }

        /// Emit one raw Linux `write(fd, payload, payload.len())`.
        fn write(&mut self, descriptor: u32, payload: &[u8]) {
            let payload_bytes =
                u32::try_from(payload.len()).expect("fixture payload length fits u32");
            self.code.extend_from_slice(&[0xb8, 1, 0, 0, 0]); // mov eax, SYS_write
            self.code.push(0xbf); // mov edi, descriptor
            self.code.extend_from_slice(&descriptor.to_le_bytes());
            self.code.extend_from_slice(&[0x48, 0x8d, 0x35]); // lea rsi, [rip + disp32]
            let displacement_offset = self.code.len();
            self.code.extend_from_slice(&[0; 4]);
            self.code.push(0xba); // mov edx, payload_bytes
            self.code.extend_from_slice(&payload_bytes.to_le_bytes());
            self.code.extend_from_slice(&[0x0f, 0x05]); // syscall
            self.payloads.push((displacement_offset, payload.to_vec()));
        }

        /// Emit raw Linux `exit_group(code)`.
        fn exit(&mut self, code: u32) {
            self.code.extend_from_slice(&[0xb8, 0xe7, 0, 0, 0]); // mov eax, SYS_exit_group
            self.code.push(0xbf); // mov edi, code
            self.code.extend_from_slice(&code.to_le_bytes());
            self.code.extend_from_slice(&[0x0f, 0x05]); // syscall
            self.code.extend_from_slice(&[0x0f, 0x0b]); // fail closed if syscall returns
        }

        fn finish(self) -> Vec<u8> {
            let Self { mut code, payloads } = self;
            for (displacement_offset, payload) in payloads {
                let payload_offset = code.len();
                let next_instruction = displacement_offset
                    .checked_add(4)
                    .expect("fixture RIP offset fits usize");
                let payload_offset =
                    i64::try_from(payload_offset).expect("fixture payload offset fits i64");
                let next_instruction =
                    i64::try_from(next_instruction).expect("fixture RIP offset fits i64");
                let displacement = i32::try_from(payload_offset - next_instruction)
                    .expect("fixture RIP displacement fits i32");
                code[displacement_offset..displacement_offset + 4]
                    .copy_from_slice(&displacement.to_le_bytes());
                code.extend_from_slice(&payload);
            }
            code
        }
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn run_fixture_process(
        code: Vec<u8>,
        timeout_millis: u32,
    ) -> Result<ProcessCapture, X64StandaloneProcessError> {
        let image =
            super::super::x64_standalone_elf::build_x64_standalone_elf_r1_s8(&code, &[0xcc])
                .expect("fixture ELF construction succeeds");
        let mut executable = TempExecutable::create(X64StandaloneProfile::BranchMix, image.bytes())
            .expect("fixture executable creation succeeds");
        let result =
            run_direct_process_with_timeout(executable.path(), 0, Vec::new(), timeout_millis);
        executable
            .cleanup()
            .expect("fixture executable cleanup succeeds");
        result
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn run_admitted_fixture(
        code: Vec<u8>,
        timeout_millis: u32,
    ) -> Result<(), X64StandaloneProcessError> {
        let process = run_fixture_process(code, timeout_millis)?;
        admit_timeout(0, process.timed_out)?;
        let _ = admit_process_status(0, process.status)?;
        let _ = admit_stdout(0, X64StandaloneProfile::BranchMix, &process.stdout)?;
        admit_stderr(0, &process.stderr)
    }

    fn fixture_record(case: &CoreVmGateACase) -> X64StandaloneExecutionRecord {
        let profile = profile_for_workload(case.workload);
        let input = X64StandaloneInput::new(
            profile,
            case.input.array_f64_bits.clone(),
            case.input.repetitions,
        )
        .unwrap();
        let input_frame = encode_x64_standalone_input(&input).unwrap();
        let output = X64StandaloneOutput::return_f64(profile, 0);
        let output_frame = encode_x64_standalone_output(output).unwrap();
        let observation = normalize_standalone_output(output);
        let mut record = X64StandaloneExecutionRecord {
            execution_schema_version: X64_STANDALONE_EXECUTION_SCHEMA_VERSION,
            execution_policy_version: X64_STANDALONE_EXECUTION_POLICY_VERSION,
            case_ordinal: case.ordinal,
            total_cases: COREVM0_GATE_A_TOTAL_CASES,
            manifest_hash: nonzero(1),
            profile,
            case_class: case.class,
            gate_a_input_hash: case.input_hash,
            source_core_hash: nonzero(2),
            source_ssa_hash: nonzero(3),
            source_machine_ir_hash: nonzero(4),
            target_artifact_hash: nonzero(5),
            target_plan_hash: nonzero(6),
            target_code_hash: nonzero(7),
            canonical_abi_hash: nonzero(8),
            target_entry_offset: 0,
            target_input_lanes: if profile == X64StandaloneProfile::BranchMix {
                3
            } else {
                2
            },
            inherited_semantic_results_hash: nonzero(9),
            inherited_process_results_hash: nonzero(10),
            standalone_artifact_hash: if profile == X64StandaloneProfile::BranchMix {
                nonzero(11)
            } else {
                nonzero(12)
            },
            elf_image_hash: if profile == X64StandaloneProfile::BranchMix {
                nonzero(13)
            } else {
                nonzero(14)
            },
            startup_plan_hash: nonzero(15),
            startup_code_hash: nonzero(16),
            io_contract_hash: if profile == X64StandaloneProfile::BranchMix {
                nonzero(17)
            } else {
                nonzero(18)
            },
            input_frame_bytes: input_frame.len() as u64,
            input_frame_hash: raw_frame_hash(&input_frame),
            normal_exit_code: 0,
            output_frame,
            output_frame_hash: raw_frame_hash(&output_frame),
            standalone: observation.clone(),
            machine_ir: observation,
            stdout_bytes: X64_STANDALONE_OUTPUT_BYTES as u64,
            stderr_bytes: 0,
            per_process_timeout_ms: X64_STANDALONE_PROCESS_TIMEOUT_MILLIS,
            max_captured_diagnostic_bytes: X64_STANDALONE_PROCESS_MAX_DIAGNOSTIC_BYTES,
            max_captured_diagnostic_records: X64_STANDALONE_PROCESS_MAX_DIAGNOSTIC_RECORDS,
            timeout: false,
            fault: false,
            abnormal_status: false,
            interpreter_dependency: false,
            external_symbol_dependency: false,
            dynamic_loader_dependency: false,
            system_linker_dependency: false,
            fallback: false,
            record_hash: SemanticHash::ZERO,
        };
        record.record_hash = x64_standalone_execution_record_hash(&record).unwrap();
        record
    }

    fn fixture_evidence() -> X64StandaloneProcessEvidence {
        let manifest = corevm0_gate_a_manifest().unwrap();
        let records = manifest.cases.iter().map(fixture_record).collect();
        let mut evidence = X64StandaloneProcessEvidence {
            execution_schema_version: X64_STANDALONE_EXECUTION_SCHEMA_VERSION,
            execution_policy_version: X64_STANDALONE_EXECUTION_POLICY_VERSION,
            results_policy_version: X64_STANDALONE_EXECUTION_RESULTS_POLICY_VERSION,
            manifest_hash: nonzero(1),
            branch_artifact_hash: nonzero(11),
            branch_elf_image_hash: nonzero(13),
            branch_io_contract_hash: nonzero(17),
            bounds_artifact_hash: nonzero(12),
            bounds_elf_image_hash: nonzero(14),
            bounds_io_contract_hash: nonzero(18),
            records,
            results_hash: SemanticHash::ZERO,
        };
        evidence.results_hash = x64_standalone_execution_results_hash(&evidence).unwrap();
        evidence
    }

    #[test]
    fn canonical_record_encoder_is_domain_first_and_big_endian() {
        let manifest = corevm0_gate_a_manifest().unwrap();
        let record = fixture_record(&manifest.cases[0]);
        let encoded = encode_execution_record(&record).unwrap();
        assert!(encoded.starts_with(X64_STANDALONE_EXECUTION_RECORD_DOMAIN));
        let cursor = X64_STANDALONE_EXECUTION_RECORD_DOMAIN.len();
        assert_eq!(&encoded[cursor..cursor + 6], &[0, 1, 0, 0, 0, 0]);
        assert_eq!(&encoded[cursor + 12..cursor + 16], &0_u32.to_be_bytes());
        assert_eq!(
            x64_standalone_execution_record_hash(&record).unwrap(),
            record.record_hash
        );
        assert_eq!(
            record.record_hash.to_hex(),
            "3e8e0086b42589a093b0b3dc9c1bb1766081123cb7b9161abbf8660f0c3332c4"
        );
    }

    #[test]
    fn canonical_results_encoder_is_order_sensitive() {
        let evidence = fixture_evidence();
        let canonical = x64_standalone_execution_results_hash(&evidence).unwrap();
        assert_eq!(canonical, evidence.results_hash);
        assert_eq!(
            canonical.to_hex(),
            "a36ec2859772702c14e4b6c3b5c059bab96ba343326743d5d959d899ca19366a"
        );
        let mut reordered = evidence.clone();
        reordered.records.swap(0, 1);
        assert!(matches!(
            x64_standalone_execution_results_hash(&reordered),
            Err(X64StandaloneProcessError::NonCanonicalOrder { .. })
        ));
    }

    #[test]
    fn duplicate_ordinal_is_rejected_before_hashing() {
        let mut evidence = fixture_evidence();
        evidence.records[1].case_ordinal = evidence.records[0].case_ordinal;
        assert!(matches!(
            validate_order_and_uniqueness(&evidence.records),
            Err(X64StandaloneProcessError::DuplicateOrdinal { ordinal: 0 })
        ));
    }

    #[test]
    fn status_admission_requires_normal_zero_exit() {
        assert_eq!(
            admit_process_status(
                0,
                ProcessStatusObservation {
                    code: Some(0),
                    signal: None,
                }
            )
            .unwrap(),
            0
        );
        assert!(matches!(
            admit_process_status(
                0,
                ProcessStatusObservation {
                    code: Some(64),
                    signal: None,
                }
            ),
            Err(X64StandaloneProcessError::AbnormalExit { code: Some(64), .. })
        ));
        assert!(matches!(
            admit_process_status(
                0,
                ProcessStatusObservation {
                    code: None,
                    signal: Some(11),
                }
            ),
            Err(X64StandaloneProcessError::Fault {
                signal: Some(11),
                ..
            })
        ));
    }

    #[test]
    fn stdout_admission_requires_one_exact_canonical_frame() {
        let frame = encode_x64_standalone_output(X64StandaloneOutput::return_f64(
            X64StandaloneProfile::BranchMix,
            1.25_f64.to_bits(),
        ))
        .unwrap();
        let capture = PipeCapture {
            bytes: frame.to_vec(),
            total_bytes: frame.len() as u64,
            diagnostic_records: 0,
            error: None,
            overflow: false,
        };
        let (admitted, output) =
            admit_stdout(0, X64StandaloneProfile::BranchMix, &capture).unwrap();
        assert_eq!(admitted, frame);
        assert_eq!(
            output.outcome(),
            X64StandaloneOutcome::ReturnF64 {
                bits: 1.25_f64.to_bits()
            }
        );
        let mut trailing = capture;
        trailing.bytes.push(0);
        trailing.total_bytes += 1;
        assert!(matches!(
            admit_stdout(0, X64StandaloneProfile::BranchMix, &trailing),
            Err(X64StandaloneProcessError::StdoutLength { .. })
        ));
    }

    #[test]
    fn stderr_and_timeout_admission_are_fail_closed() {
        let empty = PipeCapture {
            bytes: Vec::new(),
            total_bytes: 0,
            diagnostic_records: 0,
            error: None,
            overflow: false,
        };
        assert!(admit_stderr(0, &empty).is_ok());
        let one_byte = PipeCapture {
            bytes: vec![b'x'],
            total_bytes: 1,
            diagnostic_records: 1,
            error: None,
            overflow: false,
        };
        assert!(matches!(
            admit_stderr(0, &one_byte),
            Err(X64StandaloneProcessError::UnexpectedStderr { actual: 1, .. })
        ));
        assert!(admit_timeout(0, false).is_ok());
        assert!(matches!(
            admit_timeout(0, true),
            Err(X64StandaloneProcessError::Timeout { .. })
        ));
        let timeout = Duration::from_millis(u64::from(X64_STANDALONE_PROCESS_TIMEOUT_MILLIS));
        assert!(!deadline_expired(
            timeout.checked_sub(Duration::from_nanos(1)).unwrap(),
            timeout
        ));
        assert!(deadline_expired(timeout, timeout));
        assert!(deadline_expired(
            timeout.checked_add(Duration::from_nanos(1)).unwrap(),
            timeout
        ));
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    #[test]
    fn real_process_failure_fixture_matrix_is_fail_closed() {
        const FIXTURE_TIMEOUT_MILLIS: u32 = 200;
        const FIXTURE_COMPLETION_MILLIS: u32 = 2_000;

        let timeout_error = match run_fixture_process(
            // A direct two-byte spin loop; the production wrapper still uses
            // the frozen 30-second timeout.
            vec![0xeb, 0xfe],
            FIXTURE_TIMEOUT_MILLIS,
        ) {
            Err(error) => error,
            Ok(_) => panic!("timeout fixture unexpectedly completed"),
        };
        assert!(matches!(
            timeout_error,
            X64StandaloneProcessError::Timeout {
                case_ordinal: 0,
                timeout_millis: FIXTURE_TIMEOUT_MILLIS
            }
        ));

        let signal_error = run_admitted_fixture(
            vec![
                0xb8, 0x27, 0, 0, 0, // mov eax, SYS_getpid
                0x0f, 0x05, // syscall
                0x89, 0xc7, // mov edi, eax
                0xbe, 9, 0, 0, 0, // mov esi, SIGKILL
                0xb8, 0x3e, 0, 0, 0, // mov eax, SYS_kill
                0x0f, 0x05, // syscall
                0xeb, 0xfe, // fail closed if kill unexpectedly returns
            ],
            FIXTURE_COMPLETION_MILLIS,
        )
        .expect_err("self-signal fixture must be rejected");
        assert!(matches!(
            signal_error,
            X64StandaloneProcessError::Fault {
                case_ordinal: 0,
                signal: Some(9)
            }
        ));

        let abort_error = run_admitted_fixture(
            vec![
                0xb8, 0x9d, 0, 0, 0, // mov eax, SYS_prctl
                0xbf, 4, 0, 0, 0, // mov edi, PR_SET_DUMPABLE
                0x31, 0xf6, // xor esi, esi
                0x0f, 0x05, // syscall: disable core-dump creation
                0xb8, 0x27, 0, 0, 0, // mov eax, SYS_getpid
                0x0f, 0x05, // syscall
                0x89, 0xc7, // mov edi, eax
                0xbe, 6, 0, 0, 0, // mov esi, SIGABRT
                0xb8, 0x3e, 0, 0, 0, // mov eax, SYS_kill
                0x0f, 0x05, // syscall
                0xeb, 0xfe, // fail closed if abort unexpectedly returns
            ],
            FIXTURE_COMPLETION_MILLIS,
        )
        .expect_err("self-SIGABRT fixture must be rejected");
        assert!(matches!(
            abort_error,
            X64StandaloneProcessError::Fault {
                case_ordinal: 0,
                signal: Some(6)
            }
        ));

        let mut missing = FixtureProgram::new();
        missing.exit(0);
        let missing_error = run_admitted_fixture(missing.finish(), FIXTURE_COMPLETION_MILLIS)
            .expect_err("missing stdout fixture must be rejected");
        assert!(matches!(
            missing_error,
            X64StandaloneProcessError::StdoutLength {
                case_ordinal: 0,
                expected,
                actual: 0
            } if expected == X64_STANDALONE_OUTPUT_BYTES as u64
        ));

        let valid_frame = encode_x64_standalone_output(X64StandaloneOutput::return_f64(
            X64StandaloneProfile::BranchMix,
            0x3ff4_0000_0000_0000,
        ))
        .expect("fixture output frame encodes");
        let mut trailing_frame = valid_frame.to_vec();
        trailing_frame.push(0xa5);
        let mut trailing = FixtureProgram::new();
        trailing.write(1, &trailing_frame);
        trailing.exit(0);
        let trailing_error = run_admitted_fixture(trailing.finish(), FIXTURE_COMPLETION_MILLIS)
            .expect_err("trailing stdout fixture must be rejected");
        assert!(matches!(
            trailing_error,
            X64StandaloneProcessError::StdoutLength {
                case_ordinal: 0,
                expected,
                actual
            } if expected == X64_STANDALONE_OUTPUT_BYTES as u64
                && actual == X64_STANDALONE_OUTPUT_BYTES as u64 + 1
        ));

        let mut stderr = FixtureProgram::new();
        stderr.write(1, &valid_frame);
        stderr.write(2, b"unexpected diagnostic\n");
        stderr.exit(0);
        let stderr_error = run_admitted_fixture(stderr.finish(), FIXTURE_COMPLETION_MILLIS)
            .expect_err("unexpected stderr fixture must be rejected");
        assert!(matches!(
            stderr_error,
            X64StandaloneProcessError::UnexpectedStderr {
                case_ordinal: 0,
                actual: 22
            }
        ));

        let mut abnormal = FixtureProgram::new();
        abnormal.write(1, &valid_frame);
        abnormal.exit(64);
        let abnormal_error = run_admitted_fixture(abnormal.finish(), FIXTURE_COMPLETION_MILLIS)
            .expect_err("valid frame followed by abnormal exit must be rejected");
        assert!(matches!(
            abnormal_error,
            X64StandaloneProcessError::AbnormalExit {
                case_ordinal: 0,
                code: Some(64)
            }
        ));

        let mut unknown_exit = FixtureProgram::new();
        unknown_exit.exit(127);
        let unknown_exit_error =
            run_admitted_fixture(unknown_exit.finish(), FIXTURE_COMPLETION_MILLIS)
                .expect_err("unknown exit-code fixture must be rejected");
        assert!(matches!(
            unknown_exit_error,
            X64StandaloneProcessError::AbnormalExit {
                case_ordinal: 0,
                code: Some(127)
            }
        ));

        let descendant_started = Instant::now();
        let descendant_error = run_admitted_fixture(
            vec![
                0xb8, 0x39, 0, 0, 0, // mov eax, SYS_fork
                0x0f, 0x05, // syscall
                0x85, 0xc0, // test eax, eax
                0x74, 0x0b, // child -> spin loop
                0xb8, 0xe7, 0, 0, 0, // parent: mov eax, SYS_exit_group
                0x31, 0xff, // xor edi, edi
                0x0f, 0x05, // syscall
                0x0f, 0x0b, // fail closed if exit unexpectedly returns
                0xeb, 0xfe, // child retains all inherited pipes
            ],
            FIXTURE_COMPLETION_MILLIS,
        )
        .expect_err("pipe-holding descendant fixture must be rejected");
        assert!(
            descendant_started.elapsed() < Duration::from_secs(1),
            "process-group teardown must close descendant-held pipes promptly"
        );
        assert!(matches!(
            descendant_error,
            X64StandaloneProcessError::StdoutLength {
                case_ordinal: 0,
                actual: 0,
                ..
            }
        ));
    }

    #[test]
    fn primary_and_teardown_failures_have_stable_precedence() {
        let teardown = X64StandaloneTeardownFailure {
            group_kill: Some(io::ErrorKind::PermissionDenied),
            leader_kill: Some(io::ErrorKind::PermissionDenied),
            reap: Some(io::ErrorKind::TimedOut),
        };
        let combined = combine_containment_failure(
            7,
            X64StandaloneProcessError::MissingPipe {
                case_ordinal: 7,
                stream: "stdout",
            },
            X64StandaloneProcessError::Teardown {
                case_ordinal: 7,
                failure: teardown,
            },
        );
        match combined {
            X64StandaloneProcessError::FailureDuringContainment {
                case_ordinal,
                primary,
                cleanup,
            } => {
                assert_eq!(case_ordinal, 7);
                assert!(matches!(
                    *primary,
                    X64StandaloneProcessError::MissingPipe {
                        case_ordinal: 7,
                        stream: "stdout"
                    }
                ));
                assert!(matches!(
                    *cleanup,
                    X64StandaloneProcessError::Teardown {
                        case_ordinal: 7,
                        failure
                    } if failure == teardown
                ));
            }
            other => panic!("unexpected containment precedence: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn temporary_executable_is_hardened_to_owner_read_execute() {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(X64_STANDALONE_PROCESS_EXECUTABLE_MODE, 0o500);
        let mut executable =
            TempExecutable::create(X64StandaloneProfile::BranchMix, b"locked-test-image").unwrap();
        let path = executable.path().to_path_buf();
        let metadata = fs::metadata(&path).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(
            metadata.permissions().mode() & 0o7777,
            X64_STANDALONE_PROCESS_EXECUTABLE_MODE
        );
        executable.cleanup().unwrap();
        assert!(!path.exists());
    }
}
