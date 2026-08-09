//! ADR-0069 one-child containment for the exact ADR-0068 observation.
//!
//! This module owns a new process lifecycle. It does not import the historical
//! raw/native-process/standalone stack, and its parent verification path never
//! maps or calls machine code.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_enveloped_correspondence::{
    verify_x64_tail_enveloped_observations, VerifiedX64TailEnvelopedObservations,
    X64TailEnvelopedCorrespondenceError, X64TailEnvelopedCorrespondenceEvidence,
    X64_TAIL_ENVELOPED_CORRESPONDENCE_ACCEPTED_ROOT,
};
use super::x64_tail_enveloped_ipc::{
    decode_x64_tail_enveloped_ipc, encode_x64_tail_enveloped_ipc,
    x64_tail_enveloped_ipc_frame_hash, X64TailEnvelopedIpcError,
    X64_TAIL_ENVELOPED_IPC_MAX_FRAME_BYTES, X64_TAIL_ENVELOPED_IPC_SCHEMA_VERSION,
};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const X64_TAIL_ENVELOPED_PROCESS_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_ENVELOPED_PROCESS_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_ENVELOPED_PROCESS_CHILDREN: u32 = 1;
pub const X64_TAIL_ENVELOPED_PROCESS_TIMEOUT_MILLIS: u64 = 180_000;
pub const X64_TAIL_ENVELOPED_PROCESS_MAX_STDERR_BYTES: u64 = 4_096;
pub const X64_TAIL_ENVELOPED_PROCESS_EVIDENCE_ROOT: SemanticHash = SemanticHash([
    0xe3, 0xf9, 0x76, 0x22, 0xdf, 0x1a, 0x3e, 0x12, 0xb9, 0x9e, 0x66, 0x67, 0x86, 0x54, 0x88, 0x1b,
    0xc5, 0x21, 0x76, 0x1a, 0x6b, 0x7d, 0xf6, 0xab, 0x02, 0xb6, 0xd9, 0xf4, 0x59, 0xe1, 0xd7, 0xae,
]);

const RECEIPT_DOMAIN: &[u8] = b"NAUX:x86-64:tail-enveloped-process-receipt:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-enveloped-process-evidence:v1\0";
const DEBUG_ENVIRONMENT: &str = "NAUX_TAIL_ENVELOPED_WORKER_DEBUG_PROBE";
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const REAP_TIMEOUT: Duration = Duration::from_secs(1);
const PIPE_JOIN_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailEnvelopedProcessReceipt {
    schema_version: (u16, u16, u16),
    process_policy_version: (u16, u16, u16),
    ipc_schema_version: (u16, u16, u16),
    children: u32,
    correspondence_root: SemanticHash,
    ipc_frame_hash: SemanticHash,
    normal_exit: bool,
    stderr_bytes: u64,
    receipt_hash: SemanticHash,
}

impl X64TailEnvelopedProcessReceipt {
    pub const fn correspondence_root(&self) -> SemanticHash {
        self.correspondence_root
    }

    pub const fn ipc_frame_hash(&self) -> SemanticHash {
        self.ipc_frame_hash
    }

    pub const fn receipt_hash(&self) -> SemanticHash {
        self.receipt_hash
    }

    pub const fn children(&self) -> u32 {
        self.children
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailEnvelopedProcessEvidence {
    schema_version: (u16, u16, u16),
    process_policy_version: (u16, u16, u16),
    ipc_schema_version: (u16, u16, u16),
    receipt: X64TailEnvelopedProcessReceipt,
    correspondence: X64TailEnvelopedCorrespondenceEvidence,
    evidence_hash: SemanticHash,
}

impl X64TailEnvelopedProcessEvidence {
    pub const fn receipt(&self) -> &X64TailEnvelopedProcessReceipt {
        &self.receipt
    }

    pub const fn correspondence(&self) -> &X64TailEnvelopedCorrespondenceEvidence {
        &self.correspondence
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailEnvelopedProcess<'evidence> {
    evidence: &'evidence X64TailEnvelopedProcessEvidence,
}

impl<'evidence> VerifiedX64TailEnvelopedProcess<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64TailEnvelopedProcessEvidence {
        self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailEnvelopedProcessError {
    UnsupportedHost,
    Correspondence(X64TailEnvelopedCorrespondenceError),
    Ipc(X64TailEnvelopedIpcError),
    Spawn(io::ErrorKind),
    MissingPipe(&'static str),
    PipeReaderSpawn {
        stream: &'static str,
        kind: io::ErrorKind,
    },
    PipeRead {
        stream: &'static str,
        kind: io::ErrorKind,
    },
    PipeReaderPanicked(&'static str),
    PipeReaderTimeout(&'static str),
    Wait(io::ErrorKind),
    Kill(io::ErrorKind),
    Timeout {
        timeout_millis: u64,
    },
    NativeFault,
    AbnormalExit {
        code: Option<i32>,
    },
    MissingFrame,
    FrameByteLimit {
        limit: u64,
        actual: u64,
    },
    DiagnosticByteLimit {
        limit: u64,
        actual: u64,
    },
    UnexpectedDiagnostics {
        actual: u64,
    },
    InvalidField(&'static str),
    ReceiptHashMismatch,
    EvidenceHashMismatch,
}

impl fmt::Display for X64TailEnvelopedProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost => formatter.write_str("ADR-0069 requires Linux x86-64"),
            Self::Correspondence(error) => {
                write!(formatter, "ADR-0069 correspondence failed: {error}")
            }
            Self::Ipc(error) => write!(formatter, "{error}"),
            Self::Spawn(kind) => write!(formatter, "ADR-0069 worker spawn failed: {kind:?}"),
            Self::MissingPipe(stream) => write!(formatter, "ADR-0069 worker has no {stream} pipe"),
            Self::PipeReaderSpawn { stream, kind } => {
                write!(formatter, "ADR-0069 {stream} reader spawn failed: {kind:?}")
            }
            Self::PipeRead { stream, kind } => {
                write!(formatter, "ADR-0069 {stream} read failed: {kind:?}")
            }
            Self::PipeReaderPanicked(stream) => {
                write!(formatter, "ADR-0069 {stream} reader panicked")
            }
            Self::PipeReaderTimeout(stream) => {
                write!(formatter, "ADR-0069 {stream} reader did not terminate")
            }
            Self::Wait(kind) => write!(formatter, "ADR-0069 worker wait failed: {kind:?}"),
            Self::Kill(kind) => write!(formatter, "ADR-0069 worker group kill failed: {kind:?}"),
            Self::Timeout { timeout_millis } => {
                write!(formatter, "ADR-0069 worker exceeded {timeout_millis} ms")
            }
            Self::NativeFault => formatter.write_str("ADR-0069 worker terminated by signal"),
            Self::AbnormalExit { code } => {
                write!(formatter, "ADR-0069 worker exited abnormally with {code:?}")
            }
            Self::MissingFrame => formatter.write_str("ADR-0069 worker emitted no frame"),
            Self::FrameByteLimit { limit, actual } => {
                write!(
                    formatter,
                    "ADR-0069 stdout has {actual} bytes; limit is {limit}"
                )
            }
            Self::DiagnosticByteLimit { limit, actual } => {
                write!(
                    formatter,
                    "ADR-0069 stderr has {actual} bytes; limit is {limit}"
                )
            }
            Self::UnexpectedDiagnostics { actual } => {
                write!(
                    formatter,
                    "ADR-0069 worker emitted {actual} diagnostic bytes"
                )
            }
            Self::InvalidField(field) => write!(formatter, "invalid ADR-0069 {field}"),
            Self::ReceiptHashMismatch => formatter.write_str("ADR-0069 receipt hash mismatch"),
            Self::EvidenceHashMismatch => formatter.write_str("ADR-0069 evidence hash mismatch"),
        }
    }
}

impl std::error::Error for X64TailEnvelopedProcessError {}

impl From<X64TailEnvelopedCorrespondenceError> for X64TailEnvelopedProcessError {
    fn from(value: X64TailEnvelopedCorrespondenceError) -> Self {
        Self::Correspondence(value)
    }
}

impl From<X64TailEnvelopedIpcError> for X64TailEnvelopedProcessError {
    fn from(value: X64TailEnvelopedIpcError) -> Self {
        Self::Ipc(value)
    }
}

/// Launch exactly one reviewed worker, decode its hostile stdout and verify
/// every observation against a parent-regenerated oracle without native code.
pub fn emit_x64_tail_enveloped_process_evidence(
    worker_path: &Path,
) -> Result<X64TailEnvelopedProcessEvidence, X64TailEnvelopedProcessError> {
    require_supported_host()?;
    emit_process_evidence_with(
        WorkerLaunch::Path(worker_path),
        Duration::from_millis(X64_TAIL_ENVELOPED_PROCESS_TIMEOUT_MILLIS),
        None,
    )
}

pub(super) fn emit_x64_tail_enveloped_process_evidence_from_exact_fd(
    worker: &File,
) -> Result<X64TailEnvelopedProcessEvidence, X64TailEnvelopedProcessError> {
    require_supported_host()?;
    emit_process_evidence_with(
        WorkerLaunch::ExactFd(worker),
        Duration::from_millis(X64_TAIL_ENVELOPED_PROCESS_TIMEOUT_MILLIS),
        None,
    )
}

#[derive(Clone, Copy)]
enum WorkerLaunch<'worker> {
    Path(&'worker Path),
    ExactFd(&'worker File),
}

fn emit_process_evidence_with(
    worker: WorkerLaunch<'_>,
    timeout: Duration,
    debug_probe: Option<&str>,
) -> Result<X64TailEnvelopedProcessEvidence, X64TailEnvelopedProcessError> {
    let frame = run_worker_frame(worker, timeout, debug_probe)?;
    let ipc_frame_hash = x64_tail_enveloped_ipc_frame_hash(&frame)?;
    let correspondence = decode_x64_tail_enveloped_ipc(&frame)?;
    let verified = verify_x64_tail_enveloped_observations(&correspondence)?;
    validate_accepted_observation(&verified)?;
    let receipt = seal_receipt(correspondence.evidence_hash(), ipc_frame_hash)?;
    seal_process_evidence(receipt, correspondence)
}

pub fn verify_x64_tail_enveloped_process_evidence<'evidence>(
    evidence: &'evidence X64TailEnvelopedProcessEvidence,
) -> Result<VerifiedX64TailEnvelopedProcess<'evidence>, X64TailEnvelopedProcessError> {
    if evidence.schema_version != X64_TAIL_ENVELOPED_PROCESS_SCHEMA_VERSION
        || evidence.process_policy_version != X64_TAIL_ENVELOPED_PROCESS_POLICY_VERSION
        || evidence.ipc_schema_version != X64_TAIL_ENVELOPED_IPC_SCHEMA_VERSION
    {
        return Err(X64TailEnvelopedProcessError::InvalidField("schema"));
    }
    let verified = verify_x64_tail_enveloped_observations(&evidence.correspondence)?;
    validate_accepted_observation(&verified)?;
    validate_receipt(&evidence.receipt, &evidence.correspondence)?;
    if process_evidence_hash(evidence) != evidence.evidence_hash
        || evidence.evidence_hash != X64_TAIL_ENVELOPED_PROCESS_EVIDENCE_ROOT
    {
        return Err(X64TailEnvelopedProcessError::EvidenceHashMismatch);
    }
    Ok(VerifiedX64TailEnvelopedProcess { evidence })
}

fn validate_accepted_observation(
    verified: &VerifiedX64TailEnvelopedObservations<'_>,
) -> Result<(), X64TailEnvelopedProcessError> {
    if verified.evidence().evidence_hash() != X64_TAIL_ENVELOPED_CORRESPONDENCE_ACCEPTED_ROOT {
        return Err(X64TailEnvelopedProcessError::InvalidField(
            "accepted correspondence root",
        ));
    }
    Ok(())
}

fn seal_receipt(
    correspondence_root: SemanticHash,
    ipc_frame_hash: SemanticHash,
) -> Result<X64TailEnvelopedProcessReceipt, X64TailEnvelopedProcessError> {
    let mut receipt = X64TailEnvelopedProcessReceipt {
        schema_version: X64_TAIL_ENVELOPED_PROCESS_SCHEMA_VERSION,
        process_policy_version: X64_TAIL_ENVELOPED_PROCESS_POLICY_VERSION,
        ipc_schema_version: X64_TAIL_ENVELOPED_IPC_SCHEMA_VERSION,
        children: X64_TAIL_ENVELOPED_PROCESS_CHILDREN,
        correspondence_root,
        ipc_frame_hash,
        normal_exit: true,
        stderr_bytes: 0,
        receipt_hash: SemanticHash::ZERO,
    };
    receipt.receipt_hash = process_receipt_hash(&receipt);
    Ok(receipt)
}

fn validate_receipt(
    receipt: &X64TailEnvelopedProcessReceipt,
    correspondence: &X64TailEnvelopedCorrespondenceEvidence,
) -> Result<(), X64TailEnvelopedProcessError> {
    if receipt.schema_version != X64_TAIL_ENVELOPED_PROCESS_SCHEMA_VERSION
        || receipt.process_policy_version != X64_TAIL_ENVELOPED_PROCESS_POLICY_VERSION
        || receipt.ipc_schema_version != X64_TAIL_ENVELOPED_IPC_SCHEMA_VERSION
        || receipt.children != X64_TAIL_ENVELOPED_PROCESS_CHILDREN
        || !receipt.normal_exit
        || receipt.stderr_bytes != 0
        || receipt.correspondence_root != correspondence.evidence_hash()
    {
        return Err(X64TailEnvelopedProcessError::InvalidField("receipt"));
    }
    let canonical_frame = encode_x64_tail_enveloped_ipc(correspondence)?;
    if receipt.ipc_frame_hash != x64_tail_enveloped_ipc_frame_hash(&canonical_frame)? {
        return Err(X64TailEnvelopedProcessError::InvalidField(
            "IPC frame binding",
        ));
    }
    if process_receipt_hash(receipt) != receipt.receipt_hash {
        return Err(X64TailEnvelopedProcessError::ReceiptHashMismatch);
    }
    Ok(())
}

fn seal_process_evidence(
    receipt: X64TailEnvelopedProcessReceipt,
    correspondence: X64TailEnvelopedCorrespondenceEvidence,
) -> Result<X64TailEnvelopedProcessEvidence, X64TailEnvelopedProcessError> {
    let mut evidence = X64TailEnvelopedProcessEvidence {
        schema_version: X64_TAIL_ENVELOPED_PROCESS_SCHEMA_VERSION,
        process_policy_version: X64_TAIL_ENVELOPED_PROCESS_POLICY_VERSION,
        ipc_schema_version: X64_TAIL_ENVELOPED_IPC_SCHEMA_VERSION,
        receipt,
        correspondence,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = process_evidence_hash(&evidence);
    verify_x64_tail_enveloped_process_evidence(&evidence)?;
    Ok(evidence)
}

fn process_receipt_hash(receipt: &X64TailEnvelopedProcessReceipt) -> SemanticHash {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(RECEIPT_DOMAIN);
    put_version(&mut bytes, receipt.schema_version);
    put_version(&mut bytes, receipt.process_policy_version);
    put_version(&mut bytes, receipt.ipc_schema_version);
    put_u32(&mut bytes, receipt.children);
    put_hash(&mut bytes, receipt.correspondence_root);
    put_hash(&mut bytes, receipt.ipc_frame_hash);
    bytes.push(u8::from(receipt.normal_exit));
    put_u64(&mut bytes, receipt.stderr_bytes);
    SemanticHash(sha256(&bytes))
}

fn process_evidence_hash(evidence: &X64TailEnvelopedProcessEvidence) -> SemanticHash {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.process_policy_version);
    put_version(&mut bytes, evidence.ipc_schema_version);
    put_hash(&mut bytes, evidence.receipt.receipt_hash);
    put_hash(&mut bytes, evidence.correspondence.evidence_hash());
    SemanticHash(sha256(&bytes))
}

fn run_worker_frame(
    worker: WorkerLaunch<'_>,
    timeout: Duration,
    debug_probe: Option<&str>,
) -> Result<Vec<u8>, X64TailEnvelopedProcessError> {
    let mut command = match worker {
        WorkerLaunch::Path(worker_path) => Command::new(worker_path),
        WorkerLaunch::ExactFd(worker) => exact_fd_command(worker, debug_probe)?,
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if matches!(worker, WorkerLaunch::Path(_)) {
        if let Some(probe) = debug_probe {
            command.env(DEBUG_ENVIRONMENT, probe);
        } else {
            command.env_remove(DEBUG_ENVIRONMENT);
        }
    }
    configure_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| X64TailEnvelopedProcessError::Spawn(error.kind()))?;
    let stdout = child.stdout.take().ok_or_else(|| {
        terminate_and_reap(&mut child);
        X64TailEnvelopedProcessError::MissingPipe("stdout")
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        terminate_and_reap(&mut child);
        X64TailEnvelopedProcessError::MissingPipe("stderr")
    })?;
    let stdout_reader = spawn_reader(
        stdout,
        u64::from(X64_TAIL_ENVELOPED_IPC_MAX_FRAME_BYTES),
        "stdout",
    )
    .map_err(|error| {
        terminate_and_reap(&mut child);
        X64TailEnvelopedProcessError::PipeReaderSpawn {
            stream: "stdout",
            kind: error.kind(),
        }
    })?;
    let stderr_reader = match spawn_reader(
        stderr,
        X64_TAIL_ENVELOPED_PROCESS_MAX_STDERR_BYTES,
        "stderr",
    ) {
        Ok(reader) => reader,
        Err(error) => {
            terminate_and_reap(&mut child);
            let _ = join_reader(stdout_reader, "stdout");
            return Err(X64TailEnvelopedProcessError::PipeReaderSpawn {
                stream: "stderr",
                kind: error.kind(),
            });
        }
    };

    let status = wait_for_child(&mut child, timeout);
    let stdout = join_reader(stdout_reader, "stdout");
    let stderr = join_reader(stderr_reader, "stderr");
    let status = status?;
    let stdout = stdout?;
    let stderr = stderr?;
    validate_status(status)?;
    validate_capture(&stdout, "stdout")?;
    validate_capture(&stderr, "stderr")?;
    if stderr.total_bytes > X64_TAIL_ENVELOPED_PROCESS_MAX_STDERR_BYTES {
        return Err(X64TailEnvelopedProcessError::DiagnosticByteLimit {
            limit: X64_TAIL_ENVELOPED_PROCESS_MAX_STDERR_BYTES,
            actual: stderr.total_bytes,
        });
    }
    if stderr.total_bytes != 0 {
        return Err(X64TailEnvelopedProcessError::UnexpectedDiagnostics {
            actual: stderr.total_bytes,
        });
    }
    if stdout.total_bytes == 0 {
        return Err(X64TailEnvelopedProcessError::MissingFrame);
    }
    if stdout.total_bytes > u64::from(X64_TAIL_ENVELOPED_IPC_MAX_FRAME_BYTES) {
        return Err(X64TailEnvelopedProcessError::FrameByteLimit {
            limit: u64::from(X64_TAIL_ENVELOPED_IPC_MAX_FRAME_BYTES),
            actual: stdout.total_bytes,
        });
    }
    Ok(stdout.bytes)
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn exact_fd_command(
    worker: &File,
    debug_probe: Option<&str>,
) -> Result<Command, X64TailEnvelopedProcessError> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    let argv0 = CString::new("naux-tail-enveloped-worker")
        .map_err(|_| X64TailEnvelopedProcessError::InvalidField("worker argv0"))?;
    let environment = debug_probe
        .map(|probe| CString::new(format!("{DEBUG_ENVIRONMENT}={probe}")))
        .transpose()
        .map_err(|_| X64TailEnvelopedProcessError::InvalidField("debug probe"))?;
    let worker_fd = worker.as_raw_fd();
    // The ordinary program is an inert absolute fallback. A failed pre-exec
    // hook returns an error to the parent; it never reaches this pathname.
    let mut command = Command::new("/proc/self/exe");
    command.env_clear();
    // SAFETY: the hook owns its CString arguments, performs only one raw
    // execveat syscall, and returns the syscall errno if replacement fails.
    unsafe {
        command.pre_exec(move || execveat_exact_fd(worker_fd, &argv0, environment.as_deref()));
    }
    Ok(command)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn exact_fd_command(
    _worker: &File,
    _debug_probe: Option<&str>,
) -> Result<Command, X64TailEnvelopedProcessError> {
    Err(X64TailEnvelopedProcessError::UnsupportedHost)
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn execveat_exact_fd(
    worker_fd: std::os::fd::RawFd,
    argv0: &std::ffi::CStr,
    environment: Option<&std::ffi::CStr>,
) -> Result<(), io::Error> {
    use std::ffi::c_char;

    const EXECVEAT_SYSCALL: i64 = 322;
    const AT_EMPTY_PATH: i64 = 0x1000;
    let empty_path = [0 as c_char];
    let argv = [argv0.as_ptr(), std::ptr::null()];
    let environment_pointer = environment.map_or(std::ptr::null(), |value| value.as_ptr());
    let envp = [environment_pointer, std::ptr::null()];
    let mut result = EXECVEAT_SYSCALL;
    // SAFETY: worker_fd remains open across fork and until this syscall. The
    // empty pathname is NUL-terminated, argv/envp are NUL-terminated pointer
    // arrays backed by live CStrings, and AT_EMPTY_PATH selects the descriptor.
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") result,
            in("rdi") i64::from(worker_fd),
            in("rsi") empty_path.as_ptr(),
            in("rdx") argv.as_ptr(),
            in("r10") envp.as_ptr(),
            in("r8") AT_EMPTY_PATH,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    let errno = i32::try_from(result.saturating_neg()).unwrap_or(i32::MAX);
    Err(io::Error::from_raw_os_error(errno))
}

fn wait_for_child(
    child: &mut Child,
    timeout: Duration,
) -> Result<ExitStatus, X64TailEnvelopedProcessError> {
    let started = Instant::now();
    loop {
        match observe_child_exit_without_reaping(child.id()) {
            Ok(true) => {
                let kill = terminate_process_group(child.id());
                let reap = reap_bounded(child);
                kill.map_err(|error| X64TailEnvelopedProcessError::Kill(error.kind()))?;
                return reap.map_err(|error| X64TailEnvelopedProcessError::Wait(error.kind()));
            }
            Ok(false) if started.elapsed() < timeout => thread::sleep(POLL_INTERVAL),
            Ok(false) => {
                let kill = terminate_process_group(child.id());
                let reap = reap_bounded(child);
                kill.map_err(|error| X64TailEnvelopedProcessError::Kill(error.kind()))?;
                reap.map_err(|error| X64TailEnvelopedProcessError::Wait(error.kind()))?;
                return Err(X64TailEnvelopedProcessError::Timeout {
                    timeout_millis: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                const ECHILD: i32 = 10;
                if error.raw_os_error() != Some(ECHILD) {
                    terminate_and_reap(child);
                }
                return Err(X64TailEnvelopedProcessError::Wait(error.kind()));
            }
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn observe_child_exit_without_reaping(process_id: u32) -> Result<bool, io::Error> {
    const WAITID_SYSCALL: i64 = 247;
    const P_PID: i64 = 1;
    const WNOHANG: i64 = 0x0000_0001;
    const WEXITED: i64 = 0x0000_0004;
    const WNOWAIT: i64 = 0x0100_0000;
    const SIGINFO_BYTES: usize = 128;
    const SIGINFO_PID_OFFSET: usize = 16;

    let pid = i32::try_from(process_id)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ADR-0069 pid exceeds pid_t"))?;
    #[repr(C, align(8))]
    struct LinuxSigInfo {
        bytes: [u8; SIGINFO_BYTES],
    }
    let mut signal_info = LinuxSigInfo {
        bytes: [0; SIGINFO_BYTES],
    };
    let mut result = WAITID_SYSCALL;
    // SAFETY: Linux x86-64 waitid receives P_PID, one positive pid_t, one
    // aligned writable siginfo buffer, WEXITED|WNOHANG|WNOWAIT and null rusage.
    // WNOWAIT preserves the leader's PID/process-group identity until kill and
    // reap complete; rcx/r11 are syscall clobbers.
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") result,
            in("rdi") P_PID,
            in("rsi") i64::from(pid),
            in("rdx") signal_info.bytes.as_mut_ptr(),
            in("r10") WEXITED | WNOHANG | WNOWAIT,
            in("r8") 0_i64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if result < 0 {
        let errno = i32::try_from(result.saturating_neg()).unwrap_or(i32::MAX);
        return Err(io::Error::from_raw_os_error(errno));
    }
    let observed_pid = i32::from_ne_bytes(
        signal_info.bytes[SIGINFO_PID_OFFSET..SIGINFO_PID_OFFSET + 4]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ADR-0069 siginfo pid"))?,
    );
    if observed_pid == 0 {
        return Ok(false);
    }
    if observed_pid != pid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ADR-0069 waitid observed a different child",
        ));
    }
    Ok(true)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn observe_child_exit_without_reaping(_process_id: u32) -> Result<bool, io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "ADR-0069 waitid requires Linux x86-64",
    ))
}

fn validate_status(status: ExitStatus) -> Result<(), X64TailEnvelopedProcessError> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if status.signal().is_some() {
            return Err(X64TailEnvelopedProcessError::NativeFault);
        }
    }
    if status.success() {
        Ok(())
    } else {
        Err(X64TailEnvelopedProcessError::AbnormalExit {
            code: status.code(),
        })
    }
}

fn configure_process_group(command: &mut Command) {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
}

fn terminate_and_reap(child: &mut Child) {
    let _ = terminate_process_group(child.id());
    let _ = reap_bounded(child);
}

fn reap_bounded(child: &mut Child) -> Result<ExitStatus, io::Error> {
    let started = Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) => return Ok(status),
            None if started.elapsed() < REAP_TIMEOUT => thread::sleep(POLL_INTERVAL),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ADR-0069 child did not reap",
                ))
            }
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn terminate_process_group(process_group_id: u32) -> Result<(), io::Error> {
    const KILL_SYSCALL: i64 = 62;
    const SIGKILL: i64 = 9;
    const ESRCH: i32 = 3;
    let pid = i32::try_from(process_group_id)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ADR-0069 pid exceeds pid_t"))?;
    let mut result = KILL_SYSCALL;
    // SAFETY: Linux x86-64 syscall 62 receives only a negative process-group
    // id and SIGKILL. It dereferences no memory; rcx/r11 are syscall clobbers.
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") result,
            in("rdi") -i64::from(pid),
            in("rsi") SIGKILL,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if result >= 0 {
        return Ok(());
    }
    let errno = i32::try_from(result.saturating_neg()).unwrap_or(i32::MAX);
    if errno == ESRCH {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(errno))
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn terminate_process_group(_process_group_id: u32) -> Result<(), io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "ADR-0069 process groups require Linux x86-64",
    ))
}

struct Capture {
    bytes: Vec<u8>,
    total_bytes: u64,
    error: Option<io::ErrorKind>,
}

fn spawn_reader<R: Read + Send + 'static>(
    reader: R,
    limit: u64,
    stream: &'static str,
) -> Result<JoinHandle<Capture>, io::Error> {
    thread::Builder::new()
        .name(format!("naux-adr0069-{stream}"))
        .spawn(move || read_bounded(reader, limit))
}

fn read_bounded(mut reader: impl Read, limit: u64) -> Capture {
    let retained_limit = limit.saturating_add(1);
    let mut capture = Capture {
        bytes: Vec::new(),
        total_bytes: 0,
        error: None,
    };
    let mut buffer = [0_u8; 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                capture.error = Some(error.kind());
                break;
            }
        };
        capture.total_bytes = capture.total_bytes.saturating_add(read as u64);
        let retained = u64::try_from(capture.bytes.len()).unwrap_or(u64::MAX);
        if retained < retained_limit {
            let remaining = retained_limit - retained;
            let copied = usize::try_from(remaining).unwrap_or(usize::MAX).min(read);
            capture.bytes.extend_from_slice(&buffer[..copied]);
        }
    }
    capture
}

fn join_reader(
    reader: JoinHandle<Capture>,
    stream: &'static str,
) -> Result<Capture, X64TailEnvelopedProcessError> {
    let started = Instant::now();
    while !reader.is_finished() {
        if started.elapsed() >= PIPE_JOIN_TIMEOUT {
            return Err(X64TailEnvelopedProcessError::PipeReaderTimeout(stream));
        }
        thread::sleep(POLL_INTERVAL);
    }
    reader
        .join()
        .map_err(|_| X64TailEnvelopedProcessError::PipeReaderPanicked(stream))
}

fn validate_capture(
    capture: &Capture,
    stream: &'static str,
) -> Result<(), X64TailEnvelopedProcessError> {
    if let Some(kind) = capture.error {
        return Err(X64TailEnvelopedProcessError::PipeRead { stream, kind });
    }
    Ok(())
}

fn require_supported_host() -> Result<(), X64TailEnvelopedProcessError> {
    if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        Ok(())
    } else {
        Err(X64TailEnvelopedProcessError::UnsupportedHost)
    }
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_le_bytes());
    bytes.extend_from_slice(&version.1.to_le_bytes());
    bytes.extend_from_slice(&version.2.to_le_bytes());
}

fn put_hash(bytes: &mut Vec<u8>, hash: SemanticHash) {
    bytes.extend_from_slice(&hash.0);
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn probe_x64_tail_enveloped_worker(
    worker_path: &Path,
    probe: &str,
    timeout: Duration,
) -> Result<(), X64TailEnvelopedProcessError> {
    emit_process_evidence_with(WorkerLaunch::Path(worker_path), timeout, Some(probe)).map(|_| ())
}
