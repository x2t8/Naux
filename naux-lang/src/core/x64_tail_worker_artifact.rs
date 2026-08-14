//! ADR-0070 reviewed worker identity and immutable exact-FD launch.
//!
//! An expectation is authority only when it came from review outside this
//! admission call. The implementation copies matching bytes into a sealed
//! anonymous file and launches that descriptor through the accepted ADR-0069
//! lifecycle; it never reopens the caller pathname for execution.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_enveloped_process::{
    emit_x64_tail_enveloped_process_evidence_from_exact_fd,
    verify_x64_tail_enveloped_process_evidence, X64TailEnvelopedProcessError,
    X64TailEnvelopedProcessEvidence, X64_TAIL_ENVELOPED_PROCESS_EVIDENCE_ROOT,
};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const X64_TAIL_WORKER_ARTIFACT_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_ARTIFACT_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_ARTIFACT_MAX_BYTES: u64 = 256 * 1024 * 1024;
pub const X64_TAIL_WORKER_ARTIFACT_REQUIRED_SEALS: u32 = 0x000f;
pub const X64_TAIL_WORKER_ARTIFACT_EXECVEAT_FLAGS: u32 = 0x1000;
pub const X64_TAIL_WORKER_ARTIFACT_LAUNCH_MODE: u8 = 1;
pub const X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT: SemanticHash = SemanticHash([
    0x96, 0x72, 0x82, 0x49, 0x44, 0x99, 0x03, 0x5a, 0xa1, 0x3f, 0xe3, 0xda, 0xaf, 0x05, 0xd6, 0x18,
    0x25, 0xfb, 0x7a, 0xb9, 0x02, 0x70, 0x52, 0xc6, 0xde, 0xc5, 0x1f, 0x34, 0x20, 0xa5, 0x31, 0x7d,
]);

const EXPECTATION_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-expectation:v1\0";
const POLICY_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-policy:v1\0";
const RECEIPT_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-launch-receipt:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-launch-evidence:v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerArtifactExpectation {
    schema_version: (u16, u16, u16),
    byte_len: u64,
    artifact_hash: SemanticHash,
    expectation_hash: SemanticHash,
}

impl X64TailWorkerArtifactExpectation {
    pub fn new(
        byte_len: u64,
        artifact_hash: SemanticHash,
    ) -> Result<Self, X64TailWorkerArtifactError> {
        validate_byte_len(byte_len)?;
        let mut expectation = Self {
            schema_version: X64_TAIL_WORKER_ARTIFACT_SCHEMA_VERSION,
            byte_len,
            artifact_hash,
            expectation_hash: SemanticHash::ZERO,
        };
        expectation.expectation_hash = expectation_hash(&expectation);
        Ok(expectation)
    }

    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub const fn artifact_hash(&self) -> SemanticHash {
        self.artifact_hash
    }

    pub const fn expectation_hash(&self) -> SemanticHash {
        self.expectation_hash
    }
}

/// Convenience for a review tool or test fixture. Calling this on the same
/// untrusted candidate immediately before admission is measurement, not trust.
pub fn x64_tail_worker_expectation_from_reviewed_bytes(
    bytes: &[u8],
) -> Result<X64TailWorkerArtifactExpectation, X64TailWorkerArtifactError> {
    let byte_len = u64::try_from(bytes.len())
        .map_err(|_| X64TailWorkerArtifactError::ByteLimit { actual: u64::MAX })?;
    X64TailWorkerArtifactExpectation::new(byte_len, SemanticHash(sha256(bytes)))
}

pub struct X64TailWorkerArtifact {
    expectation: X64TailWorkerArtifactExpectation,
    sealed_file: File,
    seals: u32,
}

impl fmt::Debug for X64TailWorkerArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("X64TailWorkerArtifact")
            .field("expectation", &self.expectation)
            .field("seals", &self.seals)
            .finish_non_exhaustive()
    }
}

impl X64TailWorkerArtifact {
    pub const fn expectation(&self) -> &X64TailWorkerArtifactExpectation {
        &self.expectation
    }

    pub const fn seals(&self) -> u32 {
        self.seals
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailWorkerArtifact<'artifact> {
    artifact: &'artifact X64TailWorkerArtifact,
}

impl<'artifact> VerifiedX64TailWorkerArtifact<'artifact> {
    pub const fn artifact(&self) -> &'artifact X64TailWorkerArtifact {
        self.artifact
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerLaunchReceipt {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    policy_hash: SemanticHash,
    expectation_hash: SemanticHash,
    artifact_hash: SemanticHash,
    byte_len: u64,
    seals: u32,
    access_mode: u8,
    launch_mode: u8,
    execveat_flags: u32,
    process_root: SemanticHash,
    receipt_hash: SemanticHash,
}

impl X64TailWorkerLaunchReceipt {
    pub const fn policy_hash(&self) -> SemanticHash {
        self.policy_hash
    }

    pub const fn artifact_hash(&self) -> SemanticHash {
        self.artifact_hash
    }

    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub const fn seals(&self) -> u32 {
        self.seals
    }

    pub const fn process_root(&self) -> SemanticHash {
        self.process_root
    }

    pub const fn receipt_hash(&self) -> SemanticHash {
        self.receipt_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerLaunchEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    expectation: X64TailWorkerArtifactExpectation,
    receipt: X64TailWorkerLaunchReceipt,
    process: X64TailEnvelopedProcessEvidence,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerLaunchEvidence {
    pub const fn expectation(&self) -> &X64TailWorkerArtifactExpectation {
        &self.expectation
    }

    pub const fn receipt(&self) -> &X64TailWorkerLaunchReceipt {
        &self.receipt
    }

    pub const fn process(&self) -> &X64TailEnvelopedProcessEvidence {
        &self.process
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailWorkerLaunch<'evidence> {
    evidence: &'evidence X64TailWorkerLaunchEvidence,
}

impl<'evidence> VerifiedX64TailWorkerLaunch<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64TailWorkerLaunchEvidence {
        self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailWorkerArtifactError {
    UnsupportedHost,
    InvalidExpectation,
    ByteLimit { actual: u64 },
    SourceOpen(io::ErrorKind),
    SourceMetadata(io::ErrorKind),
    SourceSymlink,
    SourceNotRegular,
    SourceSetId,
    SourceChanged,
    SourceRead(io::ErrorKind),
    LengthMismatch { expected: u64, actual: u64 },
    ArtifactHashMismatch,
    MemfdCreate(io::ErrorKind),
    MemfdWrite(io::ErrorKind),
    MemfdPermission(io::ErrorKind),
    MemfdRead(io::ErrorKind),
    MemfdSeal(io::ErrorKind),
    MemfdReopen(io::ErrorKind),
    InvalidSealMask { actual: u32 },
    WritableLaunchDescriptor,
    Process(X64TailEnvelopedProcessError),
    InvalidReceipt,
    ReceiptHashMismatch,
    EvidenceHashMismatch,
}

impl fmt::Display for X64TailWorkerArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost => formatter.write_str("ADR-0070 requires Linux x86-64"),
            Self::InvalidExpectation => formatter.write_str("invalid ADR-0070 expectation"),
            Self::ByteLimit { actual } => write!(
                formatter,
                "ADR-0070 artifact has {actual} bytes; limit is {X64_TAIL_WORKER_ARTIFACT_MAX_BYTES}"
            ),
            Self::SourceOpen(kind) => write!(formatter, "ADR-0070 source open failed: {kind:?}"),
            Self::SourceMetadata(kind) => {
                write!(formatter, "ADR-0070 source metadata failed: {kind:?}")
            }
            Self::SourceSymlink => formatter.write_str("ADR-0070 source is a symlink"),
            Self::SourceNotRegular => formatter.write_str("ADR-0070 source is not regular"),
            Self::SourceSetId => formatter.write_str("ADR-0070 source has set-id mode bits"),
            Self::SourceChanged => formatter.write_str("ADR-0070 source changed during admission"),
            Self::SourceRead(kind) => write!(formatter, "ADR-0070 source read failed: {kind:?}"),
            Self::LengthMismatch { expected, actual } => {
                write!(formatter, "ADR-0070 length {actual} does not match {expected}")
            }
            Self::ArtifactHashMismatch => formatter.write_str("ADR-0070 artifact hash mismatch"),
            Self::MemfdCreate(kind) => write!(formatter, "ADR-0070 memfd failed: {kind:?}"),
            Self::MemfdWrite(kind) => write!(formatter, "ADR-0070 memfd write failed: {kind:?}"),
            Self::MemfdPermission(kind) => {
                write!(formatter, "ADR-0070 memfd permission failed: {kind:?}")
            }
            Self::MemfdRead(kind) => write!(formatter, "ADR-0070 memfd read failed: {kind:?}"),
            Self::MemfdSeal(kind) => write!(formatter, "ADR-0070 memfd seal failed: {kind:?}"),
            Self::MemfdReopen(kind) => write!(formatter, "ADR-0070 memfd reopen failed: {kind:?}"),
            Self::InvalidSealMask { actual } => {
                write!(formatter, "ADR-0070 seal mask {actual:#x} is not exact")
            }
            Self::WritableLaunchDescriptor => {
                formatter.write_str("ADR-0070 launch descriptor remains writable")
            }
            Self::Process(error) => write!(formatter, "ADR-0070 process failed: {error}"),
            Self::InvalidReceipt => formatter.write_str("invalid ADR-0070 receipt"),
            Self::ReceiptHashMismatch => formatter.write_str("ADR-0070 receipt hash mismatch"),
            Self::EvidenceHashMismatch => formatter.write_str("ADR-0070 evidence hash mismatch"),
        }
    }
}

impl std::error::Error for X64TailWorkerArtifactError {}

impl From<X64TailEnvelopedProcessError> for X64TailWorkerArtifactError {
    fn from(value: X64TailEnvelopedProcessError) -> Self {
        Self::Process(value)
    }
}

pub fn admit_x64_tail_worker_artifact(
    path: &Path,
    expectation: X64TailWorkerArtifactExpectation,
) -> Result<X64TailWorkerArtifact, X64TailWorkerArtifactError> {
    require_supported_host()?;
    verify_expectation(&expectation)?;
    let mut source = open_source(path)?;
    let before = source_identity(&source)?;
    validate_source_identity(&before, &expectation)?;
    let bytes = read_exact_artifact(&mut source, expectation.byte_len)
        .map_err(|error| X64TailWorkerArtifactError::SourceRead(error.kind()))?;
    let after = source_identity(&source)?;
    if before != after {
        return Err(X64TailWorkerArtifactError::SourceChanged);
    }
    if SemanticHash(sha256(&bytes)) != expectation.artifact_hash {
        return Err(X64TailWorkerArtifactError::ArtifactHashMismatch);
    }
    let sealed_file = seal_artifact_bytes(&bytes, expectation.artifact_hash)?;
    let seals = get_seals(&sealed_file)
        .map_err(|error| X64TailWorkerArtifactError::MemfdSeal(error.kind()))?;
    let artifact = X64TailWorkerArtifact {
        expectation,
        sealed_file,
        seals,
    };
    verify_x64_tail_worker_artifact(&artifact)?;
    Ok(artifact)
}

pub fn verify_x64_tail_worker_artifact<'artifact>(
    artifact: &'artifact X64TailWorkerArtifact,
) -> Result<VerifiedX64TailWorkerArtifact<'artifact>, X64TailWorkerArtifactError> {
    verify_expectation(&artifact.expectation)?;
    if x64_tail_worker_artifact_policy_hash() != X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT {
        return Err(X64TailWorkerArtifactError::InvalidReceipt);
    }
    if artifact.seals != X64_TAIL_WORKER_ARTIFACT_REQUIRED_SEALS
        || get_seals(&artifact.sealed_file)
            .map_err(|error| X64TailWorkerArtifactError::MemfdSeal(error.kind()))?
            != X64_TAIL_WORKER_ARTIFACT_REQUIRED_SEALS
    {
        return Err(X64TailWorkerArtifactError::InvalidSealMask {
            actual: artifact.seals,
        });
    }
    if descriptor_access_mode(&artifact.sealed_file)
        .map_err(|error| X64TailWorkerArtifactError::MemfdReopen(error.kind()))?
        != 0
    {
        return Err(X64TailWorkerArtifactError::WritableLaunchDescriptor);
    }
    let mut readback = artifact
        .sealed_file
        .try_clone()
        .map_err(|error| X64TailWorkerArtifactError::MemfdRead(error.kind()))?;
    readback
        .seek(SeekFrom::Start(0))
        .map_err(|error| X64TailWorkerArtifactError::MemfdRead(error.kind()))?;
    let bytes = read_exact_artifact(&mut readback, artifact.expectation.byte_len)
        .map_err(|error| X64TailWorkerArtifactError::MemfdRead(error.kind()))?;
    if SemanticHash(sha256(&bytes)) != artifact.expectation.artifact_hash {
        return Err(X64TailWorkerArtifactError::ArtifactHashMismatch);
    }
    Ok(VerifiedX64TailWorkerArtifact { artifact })
}

pub(super) fn x64_tail_worker_artifact_bytes(
    verified: &VerifiedX64TailWorkerArtifact<'_>,
) -> Result<Vec<u8>, X64TailWorkerArtifactError> {
    let artifact = verified.artifact;
    let mut readback = artifact
        .sealed_file
        .try_clone()
        .map_err(|error| X64TailWorkerArtifactError::MemfdRead(error.kind()))?;
    readback
        .seek(SeekFrom::Start(0))
        .map_err(|error| X64TailWorkerArtifactError::MemfdRead(error.kind()))?;
    read_exact_artifact(&mut readback, artifact.expectation.byte_len)
        .map_err(|error| X64TailWorkerArtifactError::MemfdRead(error.kind()))
}

pub fn emit_x64_tail_worker_launch_evidence(
    artifact: &X64TailWorkerArtifact,
) -> Result<X64TailWorkerLaunchEvidence, X64TailWorkerArtifactError> {
    verify_x64_tail_worker_artifact(artifact)?;
    let process = emit_x64_tail_enveloped_process_evidence_from_exact_fd(&artifact.sealed_file)?;
    let mut receipt = X64TailWorkerLaunchReceipt {
        schema_version: X64_TAIL_WORKER_ARTIFACT_SCHEMA_VERSION,
        policy_version: X64_TAIL_WORKER_ARTIFACT_POLICY_VERSION,
        policy_hash: X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT,
        expectation_hash: artifact.expectation.expectation_hash,
        artifact_hash: artifact.expectation.artifact_hash,
        byte_len: artifact.expectation.byte_len,
        seals: artifact.seals,
        access_mode: 0,
        launch_mode: X64_TAIL_WORKER_ARTIFACT_LAUNCH_MODE,
        execveat_flags: X64_TAIL_WORKER_ARTIFACT_EXECVEAT_FLAGS,
        process_root: process.evidence_hash(),
        receipt_hash: SemanticHash::ZERO,
    };
    receipt.receipt_hash = launch_receipt_hash(&receipt);
    let mut evidence = X64TailWorkerLaunchEvidence {
        schema_version: X64_TAIL_WORKER_ARTIFACT_SCHEMA_VERSION,
        policy_version: X64_TAIL_WORKER_ARTIFACT_POLICY_VERSION,
        expectation: artifact.expectation.clone(),
        receipt,
        process,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = launch_evidence_hash(&evidence);
    verify_x64_tail_worker_launch_evidence(&evidence)?;
    Ok(evidence)
}

pub fn verify_x64_tail_worker_launch_evidence<'evidence>(
    evidence: &'evidence X64TailWorkerLaunchEvidence,
) -> Result<VerifiedX64TailWorkerLaunch<'evidence>, X64TailWorkerArtifactError> {
    if evidence.schema_version != X64_TAIL_WORKER_ARTIFACT_SCHEMA_VERSION
        || evidence.policy_version != X64_TAIL_WORKER_ARTIFACT_POLICY_VERSION
    {
        return Err(X64TailWorkerArtifactError::InvalidReceipt);
    }
    verify_expectation(&evidence.expectation)?;
    verify_x64_tail_enveloped_process_evidence(&evidence.process)?;
    let receipt = &evidence.receipt;
    if receipt.schema_version != X64_TAIL_WORKER_ARTIFACT_SCHEMA_VERSION
        || receipt.policy_version != X64_TAIL_WORKER_ARTIFACT_POLICY_VERSION
        || receipt.policy_hash != X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT
        || x64_tail_worker_artifact_policy_hash() != X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT
        || receipt.expectation_hash != evidence.expectation.expectation_hash
        || receipt.artifact_hash != evidence.expectation.artifact_hash
        || receipt.byte_len != evidence.expectation.byte_len
        || receipt.seals != X64_TAIL_WORKER_ARTIFACT_REQUIRED_SEALS
        || receipt.access_mode != 0
        || receipt.launch_mode != X64_TAIL_WORKER_ARTIFACT_LAUNCH_MODE
        || receipt.execveat_flags != X64_TAIL_WORKER_ARTIFACT_EXECVEAT_FLAGS
        || receipt.process_root != X64_TAIL_ENVELOPED_PROCESS_EVIDENCE_ROOT
        || receipt.process_root != evidence.process.evidence_hash()
    {
        return Err(X64TailWorkerArtifactError::InvalidReceipt);
    }
    if launch_receipt_hash(receipt) != receipt.receipt_hash {
        return Err(X64TailWorkerArtifactError::ReceiptHashMismatch);
    }
    if launch_evidence_hash(evidence) != evidence.evidence_hash {
        return Err(X64TailWorkerArtifactError::EvidenceHashMismatch);
    }
    Ok(VerifiedX64TailWorkerLaunch { evidence })
}

pub fn x64_tail_worker_artifact_policy_hash() -> SemanticHash {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(POLICY_DOMAIN);
    put_version(&mut bytes, X64_TAIL_WORKER_ARTIFACT_SCHEMA_VERSION);
    put_version(&mut bytes, X64_TAIL_WORKER_ARTIFACT_POLICY_VERSION);
    put_u64(&mut bytes, X64_TAIL_WORKER_ARTIFACT_MAX_BYTES);
    put_u32(&mut bytes, X64_TAIL_WORKER_ARTIFACT_REQUIRED_SEALS);
    put_u32(&mut bytes, X64_TAIL_WORKER_ARTIFACT_EXECVEAT_FLAGS);
    bytes.push(X64_TAIL_WORKER_ARTIFACT_LAUNCH_MODE);
    put_hash(&mut bytes, X64_TAIL_ENVELOPED_PROCESS_EVIDENCE_ROOT);
    SemanticHash(sha256(&bytes))
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn probe_x64_tail_worker_launch_evidence_mutations(
    evidence: &X64TailWorkerLaunchEvidence,
) -> bool {
    let mut stale_expectation = evidence.clone();
    stale_expectation.expectation.byte_len ^= 1;

    let mut stale_seals = evidence.clone();
    stale_seals.receipt.seals ^= 1;

    let mut stale_receipt_hash = evidence.clone();
    stale_receipt_hash.receipt.receipt_hash.0[0] ^= 1;

    let mut stale_evidence_hash = evidence.clone();
    stale_evidence_hash.evidence_hash.0[0] ^= 1;

    let mut resealed_wrong_process = evidence.clone();
    resealed_wrong_process.receipt.process_root.0[0] ^= 1;
    resealed_wrong_process.receipt.receipt_hash =
        launch_receipt_hash(&resealed_wrong_process.receipt);
    resealed_wrong_process.evidence_hash = launch_evidence_hash(&resealed_wrong_process);

    [
        stale_expectation,
        stale_seals,
        stale_receipt_hash,
        stale_evidence_hash,
        resealed_wrong_process,
    ]
    .iter()
    .all(|mutation| verify_x64_tail_worker_launch_evidence(mutation).is_err())
}

fn verify_expectation(
    expectation: &X64TailWorkerArtifactExpectation,
) -> Result<(), X64TailWorkerArtifactError> {
    validate_byte_len(expectation.byte_len)?;
    if expectation.schema_version != X64_TAIL_WORKER_ARTIFACT_SCHEMA_VERSION
        || expectation_hash(expectation) != expectation.expectation_hash
    {
        return Err(X64TailWorkerArtifactError::InvalidExpectation);
    }
    Ok(())
}

fn validate_byte_len(byte_len: u64) -> Result<(), X64TailWorkerArtifactError> {
    if byte_len == 0 || byte_len > X64_TAIL_WORKER_ARTIFACT_MAX_BYTES {
        Err(X64TailWorkerArtifactError::ByteLimit { actual: byte_len })
    } else {
        Ok(())
    }
}

fn expectation_hash(expectation: &X64TailWorkerArtifactExpectation) -> SemanticHash {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(EXPECTATION_DOMAIN);
    put_version(&mut bytes, expectation.schema_version);
    put_u64(&mut bytes, expectation.byte_len);
    put_hash(&mut bytes, expectation.artifact_hash);
    SemanticHash(sha256(&bytes))
}

fn launch_receipt_hash(receipt: &X64TailWorkerLaunchReceipt) -> SemanticHash {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(RECEIPT_DOMAIN);
    put_version(&mut bytes, receipt.schema_version);
    put_version(&mut bytes, receipt.policy_version);
    put_hash(&mut bytes, receipt.policy_hash);
    put_hash(&mut bytes, receipt.expectation_hash);
    put_hash(&mut bytes, receipt.artifact_hash);
    put_u64(&mut bytes, receipt.byte_len);
    put_u32(&mut bytes, receipt.seals);
    bytes.push(receipt.access_mode);
    bytes.push(receipt.launch_mode);
    put_u32(&mut bytes, receipt.execveat_flags);
    put_hash(&mut bytes, receipt.process_root);
    SemanticHash(sha256(&bytes))
}

fn launch_evidence_hash(evidence: &X64TailWorkerLaunchEvidence) -> SemanticHash {
    let mut bytes = Vec::with_capacity(192);
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_hash(&mut bytes, evidence.expectation.expectation_hash);
    put_hash(&mut bytes, evidence.receipt.receipt_hash);
    put_hash(&mut bytes, evidence.process.evidence_hash());
    SemanticHash(sha256(&bytes))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    user: u32,
    group: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn open_source(path: &Path) -> Result<File, X64TailWorkerArtifactError> {
    use std::os::unix::fs::OpenOptionsExt;

    const O_NOFOLLOW: i32 = 0x0002_0000;
    const O_CLOEXEC: i32 = 0x0008_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            const ELOOP: i32 = 40;
            if error.raw_os_error() == Some(ELOOP) {
                X64TailWorkerArtifactError::SourceSymlink
            } else {
                X64TailWorkerArtifactError::SourceOpen(error.kind())
            }
        })
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn open_source(_path: &Path) -> Result<File, X64TailWorkerArtifactError> {
    Err(X64TailWorkerArtifactError::UnsupportedHost)
}

#[cfg(unix)]
fn source_identity(file: &File) -> Result<SourceIdentity, X64TailWorkerArtifactError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file
        .metadata()
        .map_err(|error| X64TailWorkerArtifactError::SourceMetadata(error.kind()))?;
    Ok(SourceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        user: metadata.uid(),
        group: metadata.gid(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

#[cfg(not(unix))]
fn source_identity(_file: &File) -> Result<SourceIdentity, X64TailWorkerArtifactError> {
    Err(X64TailWorkerArtifactError::UnsupportedHost)
}

fn validate_source_identity(
    identity: &SourceIdentity,
    expectation: &X64TailWorkerArtifactExpectation,
) -> Result<(), X64TailWorkerArtifactError> {
    const FILE_TYPE_MASK: u32 = 0o170000;
    const REGULAR_FILE: u32 = 0o100000;
    const SET_ID_MASK: u32 = 0o6000;
    if identity.mode & FILE_TYPE_MASK != REGULAR_FILE {
        return Err(X64TailWorkerArtifactError::SourceNotRegular);
    }
    if identity.mode & SET_ID_MASK != 0 {
        return Err(X64TailWorkerArtifactError::SourceSetId);
    }
    if identity.size != expectation.byte_len {
        return Err(X64TailWorkerArtifactError::LengthMismatch {
            expected: expectation.byte_len,
            actual: identity.size,
        });
    }
    Ok(())
}

fn read_exact_artifact(file: &mut File, expected: u64) -> Result<Vec<u8>, io::Error> {
    let retained = expected
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ADR-0070 read overflow"))?;
    let capacity = usize::try_from(retained)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ADR-0070 host usize"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(retained).read_to_end(&mut bytes)?;
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("ADR-0070 expected {expected} bytes, read {actual}"),
        ));
    }
    Ok(bytes)
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn seal_artifact_bytes(
    bytes: &[u8],
    expected_hash: SemanticHash,
) -> Result<File, X64TailWorkerArtifactError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let raw_fd =
        create_memfd().map_err(|error| X64TailWorkerArtifactError::MemfdCreate(error.kind()))?;
    // SAFETY: create_memfd returned one newly owned descriptor.
    let mut writable = unsafe { File::from_raw_fd(raw_fd) };
    writable
        .write_all(bytes)
        .map_err(|error| X64TailWorkerArtifactError::MemfdWrite(error.kind()))?;
    writable
        .flush()
        .map_err(|error| X64TailWorkerArtifactError::MemfdWrite(error.kind()))?;
    writable
        .set_permissions(std::fs::Permissions::from_mode(0o500))
        .map_err(|error| X64TailWorkerArtifactError::MemfdPermission(error.kind()))?;
    writable
        .seek(SeekFrom::Start(0))
        .map_err(|error| X64TailWorkerArtifactError::MemfdRead(error.kind()))?;
    let readback = read_exact_artifact(
        &mut writable,
        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    )
    .map_err(|error| X64TailWorkerArtifactError::MemfdRead(error.kind()))?;
    if SemanticHash(sha256(&readback)) != expected_hash {
        return Err(X64TailWorkerArtifactError::ArtifactHashMismatch);
    }
    add_seals(
        writable.as_raw_fd(),
        X64_TAIL_WORKER_ARTIFACT_REQUIRED_SEALS,
    )
    .map_err(|error| X64TailWorkerArtifactError::MemfdSeal(error.kind()))?;
    let seals = get_seals(&writable)
        .map_err(|error| X64TailWorkerArtifactError::MemfdSeal(error.kind()))?;
    if seals != X64_TAIL_WORKER_ARTIFACT_REQUIRED_SEALS {
        return Err(X64TailWorkerArtifactError::InvalidSealMask { actual: seals });
    }

    // Reopen the already pinned anonymous object read-only, then close the
    // writable file description. This procfs path names only our live fd; it
    // never consults the caller pathname or PATH search.
    const O_CLOEXEC: i32 = 0x0008_0000;
    let descriptor_path = format!("/proc/self/fd/{}", writable.as_raw_fd());
    let readonly = OpenOptions::new()
        .read(true)
        .custom_flags(O_CLOEXEC)
        .open(descriptor_path)
        .map_err(|error| X64TailWorkerArtifactError::MemfdReopen(error.kind()))?;
    drop(writable);
    if descriptor_access_mode(&readonly)
        .map_err(|error| X64TailWorkerArtifactError::MemfdReopen(error.kind()))?
        != 0
    {
        return Err(X64TailWorkerArtifactError::WritableLaunchDescriptor);
    }
    Ok(readonly)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn seal_artifact_bytes(
    _bytes: &[u8],
    _expected_hash: SemanticHash,
) -> Result<File, X64TailWorkerArtifactError> {
    Err(X64TailWorkerArtifactError::UnsupportedHost)
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn create_memfd() -> Result<std::os::fd::RawFd, io::Error> {
    const MEMFD_CREATE_SYSCALL: i64 = 319;
    const MFD_CLOEXEC: i64 = 0x0001;
    const MFD_ALLOW_SEALING: i64 = 0x0002;
    let name = b"naux-adr0070-worker\0";
    let mut result = MEMFD_CREATE_SYSCALL;
    // SAFETY: memfd_create reads one NUL-terminated static name and flags.
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") result,
            in("rdi") name.as_ptr(),
            in("rsi") MFD_CLOEXEC | MFD_ALLOW_SEALING,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if result < 0 {
        let errno = i32::try_from(result.saturating_neg()).unwrap_or(i32::MAX);
        Err(io::Error::from_raw_os_error(errno))
    } else {
        i32::try_from(result)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ADR-0070 memfd fd"))
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn fcntl(fd: std::os::fd::RawFd, command: i64, argument: i64) -> Result<i64, io::Error> {
    const FCNTL_SYSCALL: i64 = 72;
    let mut result = FCNTL_SYSCALL;
    // SAFETY: fcntl receives one live descriptor and integer-only commands.
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") result,
            in("rdi") i64::from(fd),
            in("rsi") command,
            in("rdx") argument,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if result < 0 {
        let errno = i32::try_from(result.saturating_neg()).unwrap_or(i32::MAX);
        Err(io::Error::from_raw_os_error(errno))
    } else {
        Ok(result)
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn add_seals(fd: std::os::fd::RawFd, seals: u32) -> Result<(), io::Error> {
    const F_ADD_SEALS: i64 = 1033;
    fcntl(fd, F_ADD_SEALS, i64::from(seals)).map(|_| ())
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn get_seals(file: &File) -> Result<u32, io::Error> {
    use std::os::fd::AsRawFd;

    const F_GET_SEALS: i64 = 1034;
    let result = fcntl(file.as_raw_fd(), F_GET_SEALS, 0)?;
    u32::try_from(result)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ADR-0070 seal mask"))
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn get_seals(_file: &File) -> Result<u32, io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "ADR-0070 seals require Linux x86-64",
    ))
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn descriptor_access_mode(file: &File) -> Result<i64, io::Error> {
    use std::os::fd::AsRawFd;

    const F_GETFL: i64 = 3;
    const O_ACCMODE: i64 = 3;
    fcntl(file.as_raw_fd(), F_GETFL, 0).map(|flags| flags & O_ACCMODE)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn descriptor_access_mode(_file: &File) -> Result<i64, io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "ADR-0070 descriptor mode requires Linux x86-64",
    ))
}

fn require_supported_host() -> Result<(), X64TailWorkerArtifactError> {
    if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        Ok(())
    } else {
        Err(X64TailWorkerArtifactError::UnsupportedHost)
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

#[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::FileExt;

    #[test]
    fn sealed_capsule_rejects_write_truncate_and_more_seals() {
        let bytes = b"not an executable, but an exact sealing fixture";
        let hash = SemanticHash(sha256(bytes));
        let file = seal_artifact_bytes(bytes, hash).expect("fixture must seal");
        assert_eq!(get_seals(&file).expect("seals"), 0x000f);
        assert!(file.write_at(b"x", 0).is_err());
        assert!(file.set_len(1).is_err());
        assert!(add_seals(file.as_raw_fd(), 0x0002).is_err());
    }
}
