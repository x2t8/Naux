//! ADR-0073 proof-only exact dependency-object byte admission.
//!
//! A pathname is only a reviewed locator. Authority comes from the caller's
//! independently reviewed declaration, byte length, and SHA-256 digest. Each
//! matching object is copied into a private read-only sealed descriptor and
//! its ELF identity is decoded again from those immutable bytes. This module
//! never asks the host loader to resolve, map, or execute an object.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_worker_artifact::X64TailWorkerArtifact;
use super::x64_tail_worker_dependency_admission::{
    verify_x64_tail_worker_dependency_admission, X64TailWorkerDependencyAdmissionError,
    X64TailWorkerDependencyAdmissionEvidence, X64TailWorkerDependencyExpectation,
    X64_TAIL_WORKER_DEPENDENCY_ADMISSION_POLICY_ROOT,
};
use super::x64_tail_worker_elf::X64TailWorkerElfEvidence;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const X64_TAIL_WORKER_DEPENDENCY_OBJECT_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_DEPENDENCY_OBJECT_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_OBJECTS: u16 = 65;
pub const X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_PATH_BYTES: u64 = 4_096;
pub const X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_BYTES: u64 = 256 * 1024 * 1024;
pub const X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
pub const X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_PROGRAM_HEADERS: u16 = 64;
pub const X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_SECTION_HEADERS: u16 = 4_096;
pub const X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_LOAD_SEGMENTS: u16 = 16;
pub const X64_TAIL_WORKER_DEPENDENCY_OBJECT_REQUIRED_SEALS: u32 = 0x000f;
pub const X64_TAIL_WORKER_DEPENDENCY_OBJECT_POLICY_ROOT: SemanticHash = SemanticHash([
    0xc9, 0x78, 0x0e, 0xa7, 0x1b, 0x48, 0xbe, 0xcf, 0x88, 0x4b, 0x4b, 0xc4, 0xbc, 0x19, 0x63, 0xfa,
    0x67, 0x94, 0xb4, 0xda, 0x4c, 0x83, 0xc5, 0x48, 0x6b, 0xc3, 0xae, 0x70, 0xc3, 0x73, 0x7b, 0xc9,
]);

const POLICY_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-object-policy:v1\0";
const OBJECT_EXPECTATION_DOMAIN: &[u8] =
    b"NAUX:x86-64:tail-worker-dependency-object-expectation:v1\0";
const MANIFEST_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-object-manifest:v1\0";
const OBJECT_EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-object-evidence:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-objects-evidence:v1\0";
const POLICY_CAPABILITIES: &[&str] = &[
    "external-reviewed-declaration-path-length-sha256-v1",
    "lexical-absolute-path-final-component-no-follow-v1",
    "before-after-open-source-identity-v1",
    "private-read-only-four-seal-memfd-v1",
    "source-path-independent-descriptor-replay-v1",
    "independent-elf64-little-endian-x86-64-et-dyn-v1",
    "system-v-or-gnu-abi-zero-padding-v1",
    "bounded-header-table-and-load-segment-v1",
    "reject-writable-executable-load-and-executable-stack-v1",
    "exact-one-dynamic-and-one-stack-segment-v1",
    "accepted-adr0072-full-replay-v1",
    "proof-only-no-resolve-map-load-or-execute-v1",
];

const ELF_HEADER_BYTES: u16 = 64;
const PROGRAM_HEADER_BYTES: u16 = 56;
const SECTION_HEADER_BYTES: u16 = 64;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_X: u32 = 1;
const PF_W: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum X64TailWorkerDependencyObjectKind {
    Interpreter = 0,
    DirectDependency = 1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyObjectExpectation {
    schema_version: (u16, u16, u16),
    kind: X64TailWorkerDependencyObjectKind,
    declaration: String,
    source_path: String,
    byte_len: u64,
    object_hash: SemanticHash,
    expectation_hash: SemanticHash,
}

impl X64TailWorkerDependencyObjectExpectation {
    pub fn interpreter(
        declaration: String,
        source_path: String,
        byte_len: u64,
        object_hash: SemanticHash,
    ) -> Result<Self, X64TailWorkerDependencyObjectError> {
        Self::new(
            X64TailWorkerDependencyObjectKind::Interpreter,
            declaration,
            source_path,
            byte_len,
            object_hash,
        )
    }

    pub fn direct_dependency(
        declaration: String,
        source_path: String,
        byte_len: u64,
        object_hash: SemanticHash,
    ) -> Result<Self, X64TailWorkerDependencyObjectError> {
        Self::new(
            X64TailWorkerDependencyObjectKind::DirectDependency,
            declaration,
            source_path,
            byte_len,
            object_hash,
        )
    }

    pub fn interpreter_from_reviewed_bytes(
        declaration: String,
        source_path: String,
        bytes: &[u8],
    ) -> Result<Self, X64TailWorkerDependencyObjectError> {
        Self::from_reviewed_bytes(
            X64TailWorkerDependencyObjectKind::Interpreter,
            declaration,
            source_path,
            bytes,
        )
    }

    pub fn direct_dependency_from_reviewed_bytes(
        declaration: String,
        source_path: String,
        bytes: &[u8],
    ) -> Result<Self, X64TailWorkerDependencyObjectError> {
        Self::from_reviewed_bytes(
            X64TailWorkerDependencyObjectKind::DirectDependency,
            declaration,
            source_path,
            bytes,
        )
    }

    fn new(
        kind: X64TailWorkerDependencyObjectKind,
        declaration: String,
        source_path: String,
        byte_len: u64,
        object_hash: SemanticHash,
    ) -> Result<Self, X64TailWorkerDependencyObjectError> {
        let mut expectation = Self {
            schema_version: X64_TAIL_WORKER_DEPENDENCY_OBJECT_SCHEMA_VERSION,
            kind,
            declaration,
            source_path,
            byte_len,
            object_hash,
            expectation_hash: SemanticHash::ZERO,
        };
        validate_object_expectation_shape(&expectation)?;
        expectation.expectation_hash = object_expectation_hash(&expectation);
        Ok(expectation)
    }

    fn from_reviewed_bytes(
        kind: X64TailWorkerDependencyObjectKind,
        declaration: String,
        source_path: String,
        bytes: &[u8],
    ) -> Result<Self, X64TailWorkerDependencyObjectError> {
        let byte_len =
            u64::try_from(bytes.len()).map_err(|_| X64TailWorkerDependencyObjectError::Limit {
                field: "object bytes",
                limit: X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_BYTES,
                actual: u64::MAX,
            })?;
        Self::new(
            kind,
            declaration,
            source_path,
            byte_len,
            SemanticHash(sha256(bytes)),
        )
    }

    pub const fn kind(&self) -> X64TailWorkerDependencyObjectKind {
        self.kind
    }

    pub fn declaration(&self) -> &str {
        &self.declaration
    }

    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub const fn object_hash(&self) -> SemanticHash {
        self.object_hash
    }

    pub const fn expectation_hash(&self) -> SemanticHash {
        self.expectation_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyObjectManifest {
    schema_version: (u16, u16, u16),
    declaration_expectation_hash: SemanticHash,
    objects: Vec<X64TailWorkerDependencyObjectExpectation>,
    manifest_hash: SemanticHash,
}

impl X64TailWorkerDependencyObjectManifest {
    pub fn new(
        declaration_expectation: &X64TailWorkerDependencyExpectation,
        interpreter: X64TailWorkerDependencyObjectExpectation,
        dependencies: Vec<X64TailWorkerDependencyObjectExpectation>,
    ) -> Result<Self, X64TailWorkerDependencyObjectError> {
        let mut objects = Vec::with_capacity(dependencies.len().saturating_add(1));
        objects.push(interpreter);
        objects.extend(dependencies);
        let mut manifest = Self {
            schema_version: X64_TAIL_WORKER_DEPENDENCY_OBJECT_SCHEMA_VERSION,
            declaration_expectation_hash: declaration_expectation.expectation_hash(),
            objects,
            manifest_hash: SemanticHash::ZERO,
        };
        validate_manifest_shape(&manifest, declaration_expectation)?;
        manifest.manifest_hash = dependency_object_manifest_hash(&manifest);
        Ok(manifest)
    }

    pub const fn declaration_expectation_hash(&self) -> SemanticHash {
        self.declaration_expectation_hash
    }

    pub fn objects(&self) -> &[X64TailWorkerDependencyObjectExpectation] {
        &self.objects
    }

    pub const fn manifest_hash(&self) -> SemanticHash {
        self.manifest_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyObjectElfIdentity {
    os_abi: u8,
    abi_version: u8,
    entry: u64,
    program_header_count: u16,
    section_header_count: u16,
    load_segment_count: u16,
    dynamic_segment_count: u16,
    stack_segment_count: u16,
}

impl X64TailWorkerDependencyObjectElfIdentity {
    pub const fn os_abi(&self) -> u8 {
        self.os_abi
    }

    pub const fn program_header_count(&self) -> u16 {
        self.program_header_count
    }

    pub const fn section_header_count(&self) -> u16 {
        self.section_header_count
    }

    pub const fn load_segment_count(&self) -> u16 {
        self.load_segment_count
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyObjectEvidence {
    ordinal: u16,
    kind: X64TailWorkerDependencyObjectKind,
    declaration: String,
    source_path: String,
    expectation_hash: SemanticHash,
    object_hash: SemanticHash,
    byte_len: u64,
    seals: u32,
    access_mode: u8,
    elf: X64TailWorkerDependencyObjectElfIdentity,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerDependencyObjectEvidence {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub const fn kind(&self) -> X64TailWorkerDependencyObjectKind {
        self.kind
    }

    pub fn declaration(&self) -> &str {
        &self.declaration
    }

    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    pub const fn object_hash(&self) -> SemanticHash {
        self.object_hash
    }

    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub const fn seals(&self) -> u32 {
        self.seals
    }

    pub const fn elf(&self) -> &X64TailWorkerDependencyObjectElfIdentity {
        &self.elf
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyObjectsEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    policy_hash: SemanticHash,
    worker_artifact_hash: SemanticHash,
    declaration_policy_hash: SemanticHash,
    declaration_evidence_hash: SemanticHash,
    declaration_expectation_hash: SemanticHash,
    manifest_hash: SemanticHash,
    object_count: u16,
    total_bytes: u64,
    objects: Vec<X64TailWorkerDependencyObjectEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerDependencyObjectsEvidence {
    pub const fn policy_hash(&self) -> SemanticHash {
        self.policy_hash
    }

    pub const fn worker_artifact_hash(&self) -> SemanticHash {
        self.worker_artifact_hash
    }

    pub const fn declaration_evidence_hash(&self) -> SemanticHash {
        self.declaration_evidence_hash
    }

    pub const fn manifest_hash(&self) -> SemanticHash {
        self.manifest_hash
    }

    pub const fn object_count(&self) -> u16 {
        self.object_count
    }

    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn objects(&self) -> &[X64TailWorkerDependencyObjectEvidence] {
        &self.objects
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

struct SealedDependencyObject {
    expectation: X64TailWorkerDependencyObjectExpectation,
    sealed_file: File,
}

pub struct X64TailWorkerDependencyObjectSet {
    objects: Vec<SealedDependencyObject>,
    evidence: X64TailWorkerDependencyObjectsEvidence,
}

impl fmt::Debug for X64TailWorkerDependencyObjectSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("X64TailWorkerDependencyObjectSet")
            .field("object_count", &self.objects.len())
            .field("evidence", &self.evidence)
            .finish_non_exhaustive()
    }
}

impl X64TailWorkerDependencyObjectSet {
    pub const fn evidence(&self) -> &X64TailWorkerDependencyObjectsEvidence {
        &self.evidence
    }

    pub fn object_count(&self) -> usize {
        self.objects.len()
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailWorkerDependencyObjectSet<'object_set> {
    object_set: &'object_set X64TailWorkerDependencyObjectSet,
}

impl<'object_set> VerifiedX64TailWorkerDependencyObjectSet<'object_set> {
    pub const fn object_set(&self) -> &'object_set X64TailWorkerDependencyObjectSet {
        self.object_set
    }

    pub const fn evidence(&self) -> &'object_set X64TailWorkerDependencyObjectsEvidence {
        &self.object_set.evidence
    }
}

pub(super) fn x64_tail_worker_dependency_object_bytes(
    verified: &VerifiedX64TailWorkerDependencyObjectSet<'_>,
    ordinal: u16,
) -> Result<Vec<u8>, X64TailWorkerDependencyObjectError> {
    let object = verified
        .object_set
        .objects
        .get(usize::from(ordinal))
        .ok_or(X64TailWorkerDependencyObjectError::InvalidManifest(
            "object ordinal",
        ))?;
    let mut readback = object.sealed_file.try_clone().map_err(|error| {
        X64TailWorkerDependencyObjectError::Memfd {
            ordinal,
            operation: "internal-clone",
            kind: error.kind(),
        }
    })?;
    readback.seek(SeekFrom::Start(0)).map_err(|error| {
        X64TailWorkerDependencyObjectError::Memfd {
            ordinal,
            operation: "internal-seek",
            kind: error.kind(),
        }
    })?;
    read_exact_object(&mut readback, object.expectation.byte_len).map_err(|error| {
        X64TailWorkerDependencyObjectError::Memfd {
            ordinal,
            operation: "internal-read",
            kind: error.kind(),
        }
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailWorkerDependencyObjectError {
    Declaration(X64TailWorkerDependencyAdmissionError),
    UnsupportedHost,
    InvalidExpectation(&'static str),
    InvalidManifest(&'static str),
    ExpectationHashMismatch,
    ManifestHashMismatch,
    Limit {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    SourceOpen {
        ordinal: u16,
        kind: io::ErrorKind,
    },
    SourceMetadata {
        ordinal: u16,
        kind: io::ErrorKind,
    },
    SourceSymlink {
        ordinal: u16,
    },
    SourceNotRegular {
        ordinal: u16,
    },
    SourceSetId {
        ordinal: u16,
    },
    SourceChanged {
        ordinal: u16,
    },
    SourceRead {
        ordinal: u16,
        kind: io::ErrorKind,
    },
    LengthMismatch {
        ordinal: u16,
        expected: u64,
        actual: u64,
    },
    ObjectHashMismatch {
        ordinal: u16,
    },
    Memfd {
        ordinal: u16,
        operation: &'static str,
        kind: io::ErrorKind,
    },
    InvalidSealMask {
        ordinal: u16,
        actual: u32,
    },
    WritableDescriptor {
        ordinal: u16,
    },
    InvalidElf {
        ordinal: u16,
        field: &'static str,
    },
    Overflow(&'static str),
    EvidenceMismatch,
}

impl fmt::Display for X64TailWorkerDependencyObjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Declaration(error) => write!(formatter, "ADR-0073 declaration failed: {error}"),
            Self::UnsupportedHost => formatter.write_str("ADR-0073 requires Linux x86-64"),
            Self::InvalidExpectation(field) => {
                write!(formatter, "invalid ADR-0073 object expectation {field}")
            }
            Self::InvalidManifest(field) => write!(formatter, "invalid ADR-0073 manifest {field}"),
            Self::ExpectationHashMismatch => {
                formatter.write_str("ADR-0073 object expectation hash mismatch")
            }
            Self::ManifestHashMismatch => formatter.write_str("ADR-0073 manifest hash mismatch"),
            Self::Limit {
                field,
                limit,
                actual,
            } => write!(formatter, "ADR-0073 {field} {actual} exceeds limit {limit}"),
            Self::SourceOpen { ordinal, kind } => {
                write!(formatter, "ADR-0073 object {ordinal} open failed: {kind:?}")
            }
            Self::SourceMetadata { ordinal, kind } => {
                write!(
                    formatter,
                    "ADR-0073 object {ordinal} metadata failed: {kind:?}"
                )
            }
            Self::SourceSymlink { ordinal } => {
                write!(formatter, "ADR-0073 object {ordinal} source is a symlink")
            }
            Self::SourceNotRegular { ordinal } => {
                write!(formatter, "ADR-0073 object {ordinal} source is not regular")
            }
            Self::SourceSetId { ordinal } => {
                write!(
                    formatter,
                    "ADR-0073 object {ordinal} source has set-id bits"
                )
            }
            Self::SourceChanged { ordinal } => {
                write!(
                    formatter,
                    "ADR-0073 object {ordinal} source changed during admission"
                )
            }
            Self::SourceRead { ordinal, kind } => {
                write!(formatter, "ADR-0073 object {ordinal} read failed: {kind:?}")
            }
            Self::LengthMismatch {
                ordinal,
                expected,
                actual,
            } => write!(
                formatter,
                "ADR-0073 object {ordinal} length {actual} does not match {expected}"
            ),
            Self::ObjectHashMismatch { ordinal } => {
                write!(formatter, "ADR-0073 object {ordinal} digest mismatch")
            }
            Self::Memfd {
                ordinal,
                operation,
                kind,
            } => write!(
                formatter,
                "ADR-0073 object {ordinal} memfd {operation} failed: {kind:?}"
            ),
            Self::InvalidSealMask { ordinal, actual } => write!(
                formatter,
                "ADR-0073 object {ordinal} seal mask {actual:#x} is not exact"
            ),
            Self::WritableDescriptor { ordinal } => {
                write!(
                    formatter,
                    "ADR-0073 object {ordinal} descriptor is writable"
                )
            }
            Self::InvalidElf { ordinal, field } => {
                write!(formatter, "invalid ADR-0073 object {ordinal} ELF {field}")
            }
            Self::Overflow(field) => write!(formatter, "ADR-0073 {field} overflow"),
            Self::EvidenceMismatch => formatter.write_str("ADR-0073 evidence mismatch"),
        }
    }
}

impl std::error::Error for X64TailWorkerDependencyObjectError {}

impl From<X64TailWorkerDependencyAdmissionError> for X64TailWorkerDependencyObjectError {
    fn from(value: X64TailWorkerDependencyAdmissionError) -> Self {
        Self::Declaration(value)
    }
}

pub fn admit_x64_tail_worker_dependency_objects(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
) -> Result<X64TailWorkerDependencyObjectSet, X64TailWorkerDependencyObjectError> {
    require_supported_host()?;
    validate_manifest(manifest, declaration_expectation)?;
    verify_x64_tail_worker_dependency_admission(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
    )?;

    let mut objects = Vec::with_capacity(manifest.objects.len());
    for (ordinal, expectation) in manifest.objects.iter().enumerate() {
        objects.push(admit_dependency_object(
            u16::try_from(ordinal)
                .map_err(|_| X64TailWorkerDependencyObjectError::Overflow("object ordinal"))?,
            expectation,
        )?);
    }
    let evidence = rebuild_evidence(declaration_evidence, manifest, &objects)?;
    let object_set = X64TailWorkerDependencyObjectSet { objects, evidence };
    verify_x64_tail_worker_dependency_objects(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        &object_set,
    )?;
    Ok(object_set)
}

pub fn verify_x64_tail_worker_dependency_objects<'object_set>(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &'object_set X64TailWorkerDependencyObjectSet,
) -> Result<VerifiedX64TailWorkerDependencyObjectSet<'object_set>, X64TailWorkerDependencyObjectError>
{
    verify_dependency_objects_with_evidence(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
        &object_set.evidence,
    )?;
    Ok(VerifiedX64TailWorkerDependencyObjectSet { object_set })
}

#[allow(clippy::too_many_arguments)]
fn verify_dependency_objects_with_evidence(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    evidence: &X64TailWorkerDependencyObjectsEvidence,
) -> Result<(), X64TailWorkerDependencyObjectError> {
    require_supported_host()?;
    validate_manifest(manifest, declaration_expectation)?;
    preflight_evidence(declaration_evidence, manifest, object_set, evidence)?;
    verify_x64_tail_worker_dependency_admission(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
    )?;
    let expected = rebuild_evidence(declaration_evidence, manifest, &object_set.objects)?;
    if &expected != evidence || dependency_objects_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerDependencyObjectError::EvidenceMismatch);
    }
    Ok(())
}

fn preflight_evidence(
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    evidence: &X64TailWorkerDependencyObjectsEvidence,
) -> Result<(), X64TailWorkerDependencyObjectError> {
    let object_count = u16::try_from(object_set.objects.len()).unwrap_or(u16::MAX);
    let expected_total = manifest
        .objects
        .iter()
        .try_fold(0u64, |total, object| total.checked_add(object.byte_len))
        .ok_or(X64TailWorkerDependencyObjectError::Overflow("total bytes"))?;
    if evidence.schema_version != X64_TAIL_WORKER_DEPENDENCY_OBJECT_SCHEMA_VERSION
        || evidence.policy_version != X64_TAIL_WORKER_DEPENDENCY_OBJECT_POLICY_VERSION
        || evidence.policy_hash != x64_tail_worker_dependency_object_policy_hash()
        || evidence.worker_artifact_hash != declaration_evidence.artifact_hash()
        || evidence.declaration_policy_hash != X64_TAIL_WORKER_DEPENDENCY_ADMISSION_POLICY_ROOT
        || evidence.declaration_evidence_hash != declaration_evidence.evidence_hash()
        || evidence.declaration_expectation_hash != manifest.declaration_expectation_hash
        || evidence.manifest_hash != manifest.manifest_hash
        || evidence.object_count != object_count
        || evidence.total_bytes != expected_total
        || manifest.objects.len() != object_set.objects.len()
        || evidence.objects.len() != manifest.objects.len()
        || dependency_objects_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerDependencyObjectError::EvidenceMismatch);
    }
    for (ordinal, ((record, object), expected)) in evidence
        .objects
        .iter()
        .zip(&object_set.objects)
        .zip(&manifest.objects)
        .enumerate()
    {
        if record.ordinal != u16::try_from(ordinal).unwrap_or(u16::MAX)
            || &object.expectation != expected
            || record.kind != expected.kind
            || record.declaration != expected.declaration
            || record.source_path != expected.source_path
            || record.expectation_hash != expected.expectation_hash
            || record.object_hash != expected.object_hash
            || record.byte_len != expected.byte_len
            || record.seals != X64_TAIL_WORKER_DEPENDENCY_OBJECT_REQUIRED_SEALS
            || record.access_mode != 0
            || dependency_object_evidence_hash(record) != record.evidence_hash
        {
            return Err(X64TailWorkerDependencyObjectError::EvidenceMismatch);
        }
    }
    Ok(())
}

fn admit_dependency_object(
    ordinal: u16,
    expectation: &X64TailWorkerDependencyObjectExpectation,
) -> Result<SealedDependencyObject, X64TailWorkerDependencyObjectError> {
    validate_object_expectation(expectation)?;
    let mut source = open_source(Path::new(&expectation.source_path), ordinal)?;
    let before = source_identity(&source, ordinal)?;
    validate_source_identity(&before, expectation, ordinal)?;
    let bytes = read_exact_object(&mut source, expectation.byte_len).map_err(|error| {
        X64TailWorkerDependencyObjectError::SourceRead {
            ordinal,
            kind: error.kind(),
        }
    })?;
    let after = source_identity(&source, ordinal)?;
    if before != after {
        return Err(X64TailWorkerDependencyObjectError::SourceChanged { ordinal });
    }
    if SemanticHash(sha256(&bytes)) != expectation.object_hash {
        return Err(X64TailWorkerDependencyObjectError::ObjectHashMismatch { ordinal });
    }
    inspect_dependency_elf(&bytes, ordinal)?;
    let sealed_file = seal_object_bytes(&bytes, expectation.object_hash, ordinal)?;
    Ok(SealedDependencyObject {
        expectation: expectation.clone(),
        sealed_file,
    })
}

fn rebuild_evidence(
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    objects: &[SealedDependencyObject],
) -> Result<X64TailWorkerDependencyObjectsEvidence, X64TailWorkerDependencyObjectError> {
    if objects.len() != manifest.objects.len() {
        return Err(X64TailWorkerDependencyObjectError::EvidenceMismatch);
    }
    let mut object_evidence = Vec::with_capacity(objects.len());
    let mut total_bytes = 0u64;
    for (ordinal, (object, expected)) in objects.iter().zip(&manifest.objects).enumerate() {
        if &object.expectation != expected {
            return Err(X64TailWorkerDependencyObjectError::EvidenceMismatch);
        }
        let ordinal = u16::try_from(ordinal)
            .map_err(|_| X64TailWorkerDependencyObjectError::Overflow("object ordinal"))?;
        let replayed = replay_sealed_object(ordinal, object)?;
        total_bytes = total_bytes
            .checked_add(replayed.byte_len)
            .ok_or(X64TailWorkerDependencyObjectError::Overflow("total bytes"))?;
        object_evidence.push(replayed);
    }
    if total_bytes > X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_TOTAL_BYTES {
        return Err(X64TailWorkerDependencyObjectError::Limit {
            field: "total bytes",
            limit: X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_TOTAL_BYTES,
            actual: total_bytes,
        });
    }
    let mut evidence = X64TailWorkerDependencyObjectsEvidence {
        schema_version: X64_TAIL_WORKER_DEPENDENCY_OBJECT_SCHEMA_VERSION,
        policy_version: X64_TAIL_WORKER_DEPENDENCY_OBJECT_POLICY_VERSION,
        policy_hash: x64_tail_worker_dependency_object_policy_hash(),
        worker_artifact_hash: declaration_evidence.artifact_hash(),
        declaration_policy_hash: X64_TAIL_WORKER_DEPENDENCY_ADMISSION_POLICY_ROOT,
        declaration_evidence_hash: declaration_evidence.evidence_hash(),
        declaration_expectation_hash: manifest.declaration_expectation_hash,
        manifest_hash: manifest.manifest_hash,
        object_count: u16::try_from(object_evidence.len())
            .map_err(|_| X64TailWorkerDependencyObjectError::Overflow("object count"))?,
        total_bytes,
        objects: object_evidence,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = dependency_objects_evidence_hash(&evidence);
    Ok(evidence)
}

fn replay_sealed_object(
    ordinal: u16,
    object: &SealedDependencyObject,
) -> Result<X64TailWorkerDependencyObjectEvidence, X64TailWorkerDependencyObjectError> {
    validate_object_expectation(&object.expectation)?;
    let seals = get_seals(&object.sealed_file).map_err(|error| {
        X64TailWorkerDependencyObjectError::Memfd {
            ordinal,
            operation: "get-seals",
            kind: error.kind(),
        }
    })?;
    if seals != X64_TAIL_WORKER_DEPENDENCY_OBJECT_REQUIRED_SEALS {
        return Err(X64TailWorkerDependencyObjectError::InvalidSealMask {
            ordinal,
            actual: seals,
        });
    }
    let access_mode = descriptor_access_mode(&object.sealed_file).map_err(|error| {
        X64TailWorkerDependencyObjectError::Memfd {
            ordinal,
            operation: "access-mode",
            kind: error.kind(),
        }
    })?;
    if access_mode != 0 {
        return Err(X64TailWorkerDependencyObjectError::WritableDescriptor { ordinal });
    }
    let mut readback = object.sealed_file.try_clone().map_err(|error| {
        X64TailWorkerDependencyObjectError::Memfd {
            ordinal,
            operation: "clone",
            kind: error.kind(),
        }
    })?;
    readback.seek(SeekFrom::Start(0)).map_err(|error| {
        X64TailWorkerDependencyObjectError::Memfd {
            ordinal,
            operation: "seek",
            kind: error.kind(),
        }
    })?;
    let bytes = read_exact_object(&mut readback, object.expectation.byte_len).map_err(|error| {
        X64TailWorkerDependencyObjectError::Memfd {
            ordinal,
            operation: "read",
            kind: error.kind(),
        }
    })?;
    if SemanticHash(sha256(&bytes)) != object.expectation.object_hash {
        return Err(X64TailWorkerDependencyObjectError::ObjectHashMismatch { ordinal });
    }
    let elf = inspect_dependency_elf(&bytes, ordinal)?;
    let mut evidence = X64TailWorkerDependencyObjectEvidence {
        ordinal,
        kind: object.expectation.kind,
        declaration: object.expectation.declaration.clone(),
        source_path: object.expectation.source_path.clone(),
        expectation_hash: object.expectation.expectation_hash,
        object_hash: object.expectation.object_hash,
        byte_len: object.expectation.byte_len,
        seals,
        access_mode: u8::try_from(access_mode)
            .map_err(|_| X64TailWorkerDependencyObjectError::Overflow("access mode"))?,
        elf,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = dependency_object_evidence_hash(&evidence);
    Ok(evidence)
}

pub fn x64_tail_worker_dependency_object_policy_hash() -> SemanticHash {
    let mut bytes = Vec::with_capacity(192);
    bytes.extend_from_slice(POLICY_DOMAIN);
    put_version(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_OBJECT_SCHEMA_VERSION);
    put_version(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_OBJECT_POLICY_VERSION);
    put_hash(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_ADMISSION_POLICY_ROOT);
    put_u16(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_OBJECTS);
    put_u64(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_PATH_BYTES);
    put_u64(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_BYTES);
    put_u64(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_TOTAL_BYTES,
    );
    put_u32(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_OBJECT_REQUIRED_SEALS);
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_PROGRAM_HEADERS,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_SECTION_HEADERS,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_LOAD_SEGMENTS,
    );
    put_u16(&mut bytes, ELF_HEADER_BYTES);
    put_u16(&mut bytes, PROGRAM_HEADER_BYTES);
    put_u16(&mut bytes, SECTION_HEADER_BYTES);
    put_u16(&mut bytes, ET_DYN);
    put_u16(&mut bytes, EM_X86_64);
    put_u16(
        &mut bytes,
        u16::try_from(POLICY_CAPABILITIES.len()).unwrap_or(u16::MAX),
    );
    for capability in POLICY_CAPABILITIES {
        put_string(&mut bytes, capability);
    }
    SemanticHash(sha256(&bytes))
}

fn object_expectation_hash(expectation: &X64TailWorkerDependencyObjectExpectation) -> SemanticHash {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(OBJECT_EXPECTATION_DOMAIN);
    put_version(&mut bytes, expectation.schema_version);
    put_hash(&mut bytes, x64_tail_worker_dependency_object_policy_hash());
    bytes.push(expectation.kind as u8);
    put_string(&mut bytes, &expectation.declaration);
    put_string(&mut bytes, &expectation.source_path);
    put_u64(&mut bytes, expectation.byte_len);
    put_hash(&mut bytes, expectation.object_hash);
    SemanticHash(sha256(&bytes))
}

pub fn dependency_object_manifest_hash(
    manifest: &X64TailWorkerDependencyObjectManifest,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(MANIFEST_DOMAIN);
    put_version(&mut bytes, manifest.schema_version);
    put_hash(&mut bytes, x64_tail_worker_dependency_object_policy_hash());
    put_hash(&mut bytes, manifest.declaration_expectation_hash);
    put_u16(
        &mut bytes,
        u16::try_from(manifest.objects.len()).unwrap_or(u16::MAX),
    );
    for object in &manifest.objects {
        put_hash(&mut bytes, object.expectation_hash);
    }
    SemanticHash(sha256(&bytes))
}

fn dependency_object_evidence_hash(
    evidence: &X64TailWorkerDependencyObjectEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(320);
    bytes.extend_from_slice(OBJECT_EVIDENCE_DOMAIN);
    put_u16(&mut bytes, evidence.ordinal);
    bytes.push(evidence.kind as u8);
    put_string(&mut bytes, &evidence.declaration);
    put_string(&mut bytes, &evidence.source_path);
    put_hash(&mut bytes, evidence.expectation_hash);
    put_hash(&mut bytes, evidence.object_hash);
    put_u64(&mut bytes, evidence.byte_len);
    put_u32(&mut bytes, evidence.seals);
    bytes.push(evidence.access_mode);
    encode_elf_identity(&mut bytes, &evidence.elf);
    SemanticHash(sha256(&bytes))
}

pub fn dependency_objects_evidence_hash(
    evidence: &X64TailWorkerDependencyObjectsEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_hash(&mut bytes, evidence.policy_hash);
    put_hash(&mut bytes, evidence.worker_artifact_hash);
    put_hash(&mut bytes, evidence.declaration_policy_hash);
    put_hash(&mut bytes, evidence.declaration_evidence_hash);
    put_hash(&mut bytes, evidence.declaration_expectation_hash);
    put_hash(&mut bytes, evidence.manifest_hash);
    put_u16(&mut bytes, evidence.object_count);
    put_u64(&mut bytes, evidence.total_bytes);
    for object in &evidence.objects {
        put_hash(&mut bytes, object.evidence_hash);
    }
    SemanticHash(sha256(&bytes))
}

fn validate_manifest(
    manifest: &X64TailWorkerDependencyObjectManifest,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
) -> Result<(), X64TailWorkerDependencyObjectError> {
    if x64_tail_worker_dependency_object_policy_hash()
        != X64_TAIL_WORKER_DEPENDENCY_OBJECT_POLICY_ROOT
    {
        return Err(X64TailWorkerDependencyObjectError::InvalidManifest(
            "policy root",
        ));
    }
    validate_manifest_shape(manifest, declaration_expectation)?;
    for object in &manifest.objects {
        validate_object_expectation(object)?;
    }
    if dependency_object_manifest_hash(manifest) != manifest.manifest_hash {
        return Err(X64TailWorkerDependencyObjectError::ManifestHashMismatch);
    }
    Ok(())
}

fn validate_manifest_shape(
    manifest: &X64TailWorkerDependencyObjectManifest,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
) -> Result<(), X64TailWorkerDependencyObjectError> {
    if manifest.schema_version != X64_TAIL_WORKER_DEPENDENCY_OBJECT_SCHEMA_VERSION
        || manifest.declaration_expectation_hash != declaration_expectation.expectation_hash()
    {
        return Err(X64TailWorkerDependencyObjectError::InvalidManifest(
            "declaration authority",
        ));
    }
    let expected_count = declaration_expectation
        .dependencies()
        .len()
        .checked_add(1)
        .ok_or(X64TailWorkerDependencyObjectError::Overflow("object count"))?;
    if manifest.objects.len() != expected_count
        || manifest.objects.is_empty()
        || manifest.objects.len() > usize::from(X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_OBJECTS)
    {
        return Err(X64TailWorkerDependencyObjectError::Limit {
            field: "objects",
            limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_OBJECTS),
            actual: u64::try_from(manifest.objects.len()).unwrap_or(u64::MAX),
        });
    }
    let interpreter = &manifest.objects[0];
    if interpreter.kind != X64TailWorkerDependencyObjectKind::Interpreter
        || interpreter.declaration != declaration_expectation.interpreter()
    {
        return Err(X64TailWorkerDependencyObjectError::InvalidManifest(
            "interpreter mapping",
        ));
    }
    for (object, declaration) in manifest.objects[1..]
        .iter()
        .zip(declaration_expectation.dependencies())
    {
        if object.kind != X64TailWorkerDependencyObjectKind::DirectDependency
            || object.declaration != *declaration
        {
            return Err(X64TailWorkerDependencyObjectError::InvalidManifest(
                "dependency mapping",
            ));
        }
    }
    let mut paths = BTreeMap::<&str, (u64, SemanticHash)>::new();
    let mut total_bytes = 0u64;
    for object in &manifest.objects {
        validate_object_expectation_shape(object)?;
        total_bytes = total_bytes
            .checked_add(object.byte_len)
            .ok_or(X64TailWorkerDependencyObjectError::Overflow("total bytes"))?;
        if let Some((byte_len, object_hash)) = paths.insert(
            object.source_path.as_str(),
            (object.byte_len, object.object_hash),
        ) {
            if byte_len != object.byte_len || object_hash != object.object_hash {
                return Err(X64TailWorkerDependencyObjectError::InvalidManifest(
                    "one path has conflicting identities",
                ));
            }
        }
    }
    if total_bytes > X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_TOTAL_BYTES {
        return Err(X64TailWorkerDependencyObjectError::Limit {
            field: "total bytes",
            limit: X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_TOTAL_BYTES,
            actual: total_bytes,
        });
    }
    Ok(())
}

fn validate_object_expectation(
    expectation: &X64TailWorkerDependencyObjectExpectation,
) -> Result<(), X64TailWorkerDependencyObjectError> {
    validate_object_expectation_shape(expectation)?;
    if object_expectation_hash(expectation) != expectation.expectation_hash {
        return Err(X64TailWorkerDependencyObjectError::ExpectationHashMismatch);
    }
    Ok(())
}

fn validate_object_expectation_shape(
    expectation: &X64TailWorkerDependencyObjectExpectation,
) -> Result<(), X64TailWorkerDependencyObjectError> {
    if expectation.schema_version != X64_TAIL_WORKER_DEPENDENCY_OBJECT_SCHEMA_VERSION {
        return Err(X64TailWorkerDependencyObjectError::InvalidExpectation(
            "schema version",
        ));
    }
    let declaration_bytes = u64::try_from(expectation.declaration.len()).unwrap_or(u64::MAX);
    if expectation.declaration.is_empty()
        || declaration_bytes > 256
        || expectation
            .declaration
            .bytes()
            .any(|byte| !(0x21..=0x7e).contains(&byte))
    {
        return Err(X64TailWorkerDependencyObjectError::InvalidExpectation(
            "declaration",
        ));
    }
    validate_canonical_path(&expectation.source_path)?;
    if expectation.byte_len == 0
        || expectation.byte_len > X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_BYTES
    {
        return Err(X64TailWorkerDependencyObjectError::Limit {
            field: "object bytes",
            limit: X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_BYTES,
            actual: expectation.byte_len,
        });
    }
    if expectation.object_hash == SemanticHash::ZERO {
        return Err(X64TailWorkerDependencyObjectError::InvalidExpectation(
            "zero object digest",
        ));
    }
    Ok(())
}

fn validate_canonical_path(path: &str) -> Result<(), X64TailWorkerDependencyObjectError> {
    let path_bytes = u64::try_from(path.len()).unwrap_or(u64::MAX);
    if path.is_empty()
        || path_bytes > X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_PATH_BYTES
        || !path.starts_with('/')
        || path == "/"
        || path.ends_with('/')
        || path[1..]
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        || path.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
    {
        return Err(X64TailWorkerDependencyObjectError::InvalidExpectation(
            "canonical source path",
        ));
    }
    Ok(())
}

fn inspect_dependency_elf(
    bytes: &[u8],
    ordinal: u16,
) -> Result<X64TailWorkerDependencyObjectElfIdentity, X64TailWorkerDependencyObjectError> {
    if bytes.len() < usize::from(ELF_HEADER_BYTES) {
        return invalid_elf(ordinal, "header range");
    }
    if &bytes[0..4] != b"\x7fELF" {
        return invalid_elf(ordinal, "magic");
    }
    if bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 {
        return invalid_elf(ordinal, "class/data/version");
    }
    let os_abi = bytes[7];
    let abi_version = bytes[8];
    if !matches!(os_abi, 0 | 3) || abi_version != 0 || bytes[9..16].iter().any(|byte| *byte != 0) {
        return invalid_elf(ordinal, "ABI identification");
    }
    if read_u16(bytes, 16, ordinal)? != ET_DYN
        || read_u16(bytes, 18, ordinal)? != EM_X86_64
        || read_u32(bytes, 20, ordinal)? != 1
        || read_u32(bytes, 48, ordinal)? != 0
        || read_u16(bytes, 52, ordinal)? != ELF_HEADER_BYTES
    {
        return invalid_elf(ordinal, "typed header");
    }
    let entry = read_u64(bytes, 24, ordinal)?;
    let program_header_offset = read_u64(bytes, 32, ordinal)?;
    let section_header_offset = read_u64(bytes, 40, ordinal)?;
    let program_header_size = read_u16(bytes, 54, ordinal)?;
    let program_header_count = read_u16(bytes, 56, ordinal)?;
    let section_header_size = read_u16(bytes, 58, ordinal)?;
    let section_header_count = read_u16(bytes, 60, ordinal)?;
    let section_name_index = read_u16(bytes, 62, ordinal)?;
    if program_header_size != PROGRAM_HEADER_BYTES
        || program_header_count == 0
        || program_header_count > X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_PROGRAM_HEADERS
    {
        return invalid_elf(ordinal, "program-header shape");
    }
    if section_header_count > X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_SECTION_HEADERS
        || (section_header_count == 0
            && (section_header_offset != 0 || section_name_index != 0 || section_header_size != 0))
        || (section_header_count != 0
            && (section_header_size != SECTION_HEADER_BYTES
                || section_name_index >= section_header_count))
    {
        return invalid_elf(ordinal, "section-header shape");
    }
    checked_table_range(
        bytes.len(),
        program_header_offset,
        program_header_size,
        program_header_count,
        ordinal,
        "program-header table",
    )?;
    if section_header_count != 0 {
        checked_table_range(
            bytes.len(),
            section_header_offset,
            section_header_size,
            section_header_count,
            ordinal,
            "section-header table",
        )?;
    }

    let mut load_segment_count = 0u16;
    let mut dynamic_segment_count = 0u16;
    let mut stack_segment_count = 0u16;
    for index in 0..program_header_count {
        let offset = program_header_offset
            .checked_add(u64::from(index) * u64::from(PROGRAM_HEADER_BYTES))
            .ok_or(X64TailWorkerDependencyObjectError::Overflow(
                "program-header offset",
            ))?;
        let offset = usize::try_from(offset)
            .map_err(|_| X64TailWorkerDependencyObjectError::Overflow("host offset"))?;
        let segment_type = read_u32(bytes, offset, ordinal)?;
        let flags = read_u32(bytes, offset + 4, ordinal)?;
        let file_offset = read_u64(bytes, offset + 8, ordinal)?;
        let file_size = read_u64(bytes, offset + 32, ordinal)?;
        let memory_size = read_u64(bytes, offset + 40, ordinal)?;
        let alignment = read_u64(bytes, offset + 48, ordinal)?;
        if file_size > memory_size
            || (alignment != 0 && !alignment.is_power_of_two())
            || range_end(file_offset, file_size, ordinal, "segment file range")?
                > u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        {
            return invalid_elf(ordinal, "segment range/alignment");
        }
        match segment_type {
            PT_LOAD => {
                load_segment_count = load_segment_count.checked_add(1).ok_or(
                    X64TailWorkerDependencyObjectError::Overflow("load segments"),
                )?;
                if flags & (PF_W | PF_X) == (PF_W | PF_X) {
                    return invalid_elf(ordinal, "writable executable load");
                }
            }
            PT_DYNAMIC => {
                dynamic_segment_count = dynamic_segment_count.checked_add(1).ok_or(
                    X64TailWorkerDependencyObjectError::Overflow("dynamic segments"),
                )?;
            }
            PT_GNU_STACK => {
                stack_segment_count = stack_segment_count.checked_add(1).ok_or(
                    X64TailWorkerDependencyObjectError::Overflow("stack segments"),
                )?;
                if flags & PF_X != 0 {
                    return invalid_elf(ordinal, "executable stack");
                }
            }
            _ => {}
        }
    }
    if load_segment_count == 0
        || load_segment_count > X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_LOAD_SEGMENTS
        || dynamic_segment_count != 1
        || stack_segment_count != 1
    {
        return invalid_elf(ordinal, "required segment cardinality");
    }
    Ok(X64TailWorkerDependencyObjectElfIdentity {
        os_abi,
        abi_version,
        entry,
        program_header_count,
        section_header_count,
        load_segment_count,
        dynamic_segment_count,
        stack_segment_count,
    })
}

fn invalid_elf<T>(
    ordinal: u16,
    field: &'static str,
) -> Result<T, X64TailWorkerDependencyObjectError> {
    Err(X64TailWorkerDependencyObjectError::InvalidElf { ordinal, field })
}

fn checked_table_range(
    file_len: usize,
    offset: u64,
    entry_size: u16,
    count: u16,
    ordinal: u16,
    field: &'static str,
) -> Result<(), X64TailWorkerDependencyObjectError> {
    let size = u64::from(entry_size)
        .checked_mul(u64::from(count))
        .ok_or(X64TailWorkerDependencyObjectError::Overflow(field))?;
    let end = range_end(offset, size, ordinal, field)?;
    if end > u64::try_from(file_len).unwrap_or(u64::MAX) {
        return invalid_elf(ordinal, field);
    }
    Ok(())
}

fn range_end(
    offset: u64,
    size: u64,
    _ordinal: u16,
    field: &'static str,
) -> Result<u64, X64TailWorkerDependencyObjectError> {
    offset
        .checked_add(size)
        .ok_or(X64TailWorkerDependencyObjectError::Overflow(field))
}

fn read_u16(
    bytes: &[u8],
    offset: usize,
    ordinal: u16,
) -> Result<u16, X64TailWorkerDependencyObjectError> {
    let value = bytes.get(offset..offset.saturating_add(2)).ok_or(
        X64TailWorkerDependencyObjectError::InvalidElf {
            ordinal,
            field: "u16 range",
        },
    )?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(
    bytes: &[u8],
    offset: usize,
    ordinal: u16,
) -> Result<u32, X64TailWorkerDependencyObjectError> {
    let value = bytes.get(offset..offset.saturating_add(4)).ok_or(
        X64TailWorkerDependencyObjectError::InvalidElf {
            ordinal,
            field: "u32 range",
        },
    )?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(
    bytes: &[u8],
    offset: usize,
    ordinal: u16,
) -> Result<u64, X64TailWorkerDependencyObjectError> {
    let value = bytes.get(offset..offset.saturating_add(8)).ok_or(
        X64TailWorkerDependencyObjectError::InvalidElf {
            ordinal,
            field: "u64 range",
        },
    )?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn encode_elf_identity(bytes: &mut Vec<u8>, identity: &X64TailWorkerDependencyObjectElfIdentity) {
    bytes.push(identity.os_abi);
    bytes.push(identity.abi_version);
    put_u64(bytes, identity.entry);
    put_u16(bytes, identity.program_header_count);
    put_u16(bytes, identity.section_header_count);
    put_u16(bytes, identity.load_segment_count);
    put_u16(bytes, identity.dynamic_segment_count);
    put_u16(bytes, identity.stack_segment_count);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn open_source(path: &Path, ordinal: u16) -> Result<File, X64TailWorkerDependencyObjectError> {
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
                X64TailWorkerDependencyObjectError::SourceSymlink { ordinal }
            } else {
                X64TailWorkerDependencyObjectError::SourceOpen {
                    ordinal,
                    kind: error.kind(),
                }
            }
        })
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn open_source(_path: &Path, _ordinal: u16) -> Result<File, X64TailWorkerDependencyObjectError> {
    Err(X64TailWorkerDependencyObjectError::UnsupportedHost)
}

#[cfg(unix)]
fn source_identity(
    file: &File,
    ordinal: u16,
) -> Result<SourceIdentity, X64TailWorkerDependencyObjectError> {
    use std::os::unix::fs::MetadataExt;

    let metadata =
        file.metadata()
            .map_err(|error| X64TailWorkerDependencyObjectError::SourceMetadata {
                ordinal,
                kind: error.kind(),
            })?;
    Ok(SourceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

#[cfg(not(unix))]
fn source_identity(
    _file: &File,
    _ordinal: u16,
) -> Result<SourceIdentity, X64TailWorkerDependencyObjectError> {
    Err(X64TailWorkerDependencyObjectError::UnsupportedHost)
}

fn validate_source_identity(
    identity: &SourceIdentity,
    expectation: &X64TailWorkerDependencyObjectExpectation,
    ordinal: u16,
) -> Result<(), X64TailWorkerDependencyObjectError> {
    const FILE_TYPE_MASK: u32 = 0o170000;
    const REGULAR_FILE: u32 = 0o100000;
    const SET_ID_MASK: u32 = 0o6000;
    if identity.mode & FILE_TYPE_MASK != REGULAR_FILE {
        return Err(X64TailWorkerDependencyObjectError::SourceNotRegular { ordinal });
    }
    if identity.mode & SET_ID_MASK != 0 {
        return Err(X64TailWorkerDependencyObjectError::SourceSetId { ordinal });
    }
    if identity.size != expectation.byte_len {
        return Err(X64TailWorkerDependencyObjectError::LengthMismatch {
            ordinal,
            expected: expectation.byte_len,
            actual: identity.size,
        });
    }
    Ok(())
}

fn read_exact_object(file: &mut File, expected: u64) -> Result<Vec<u8>, io::Error> {
    let retained = expected
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ADR-0073 read overflow"))?;
    let capacity = usize::try_from(retained)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ADR-0073 host usize"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(retained).read_to_end(&mut bytes)?;
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("ADR-0073 expected {expected} bytes, read {actual}"),
        ));
    }
    Ok(bytes)
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn seal_object_bytes(
    bytes: &[u8],
    expected_hash: SemanticHash,
    ordinal: u16,
) -> Result<File, X64TailWorkerDependencyObjectError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let raw_fd = create_memfd().map_err(|error| X64TailWorkerDependencyObjectError::Memfd {
        ordinal,
        operation: "create",
        kind: error.kind(),
    })?;
    // SAFETY: create_memfd returned one newly owned descriptor.
    let mut writable = unsafe { File::from_raw_fd(raw_fd) };
    writable
        .write_all(bytes)
        .map_err(|error| X64TailWorkerDependencyObjectError::Memfd {
            ordinal,
            operation: "write",
            kind: error.kind(),
        })?;
    writable
        .flush()
        .map_err(|error| X64TailWorkerDependencyObjectError::Memfd {
            ordinal,
            operation: "flush",
            kind: error.kind(),
        })?;
    writable
        .set_permissions(std::fs::Permissions::from_mode(0o400))
        .map_err(|error| X64TailWorkerDependencyObjectError::Memfd {
            ordinal,
            operation: "permission",
            kind: error.kind(),
        })?;
    writable.seek(SeekFrom::Start(0)).map_err(|error| {
        X64TailWorkerDependencyObjectError::Memfd {
            ordinal,
            operation: "seek",
            kind: error.kind(),
        }
    })?;
    let readback = read_exact_object(
        &mut writable,
        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    )
    .map_err(|error| X64TailWorkerDependencyObjectError::Memfd {
        ordinal,
        operation: "readback",
        kind: error.kind(),
    })?;
    if SemanticHash(sha256(&readback)) != expected_hash {
        return Err(X64TailWorkerDependencyObjectError::ObjectHashMismatch { ordinal });
    }
    add_seals(
        writable.as_raw_fd(),
        X64_TAIL_WORKER_DEPENDENCY_OBJECT_REQUIRED_SEALS,
    )
    .map_err(|error| X64TailWorkerDependencyObjectError::Memfd {
        ordinal,
        operation: "seal",
        kind: error.kind(),
    })?;
    let seals =
        get_seals(&writable).map_err(|error| X64TailWorkerDependencyObjectError::Memfd {
            ordinal,
            operation: "get-seals",
            kind: error.kind(),
        })?;
    if seals != X64_TAIL_WORKER_DEPENDENCY_OBJECT_REQUIRED_SEALS {
        return Err(X64TailWorkerDependencyObjectError::InvalidSealMask {
            ordinal,
            actual: seals,
        });
    }
    const O_CLOEXEC: i32 = 0x0008_0000;
    let descriptor_path = format!("/proc/self/fd/{}", writable.as_raw_fd());
    let readonly = OpenOptions::new()
        .read(true)
        .custom_flags(O_CLOEXEC)
        .open(descriptor_path)
        .map_err(|error| X64TailWorkerDependencyObjectError::Memfd {
            ordinal,
            operation: "reopen",
            kind: error.kind(),
        })?;
    drop(writable);
    if descriptor_access_mode(&readonly).map_err(|error| {
        X64TailWorkerDependencyObjectError::Memfd {
            ordinal,
            operation: "access-mode",
            kind: error.kind(),
        }
    })? != 0
    {
        return Err(X64TailWorkerDependencyObjectError::WritableDescriptor { ordinal });
    }
    Ok(readonly)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn seal_object_bytes(
    _bytes: &[u8],
    _expected_hash: SemanticHash,
    _ordinal: u16,
) -> Result<File, X64TailWorkerDependencyObjectError> {
    Err(X64TailWorkerDependencyObjectError::UnsupportedHost)
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn create_memfd() -> Result<std::os::fd::RawFd, io::Error> {
    const MEMFD_CREATE_SYSCALL: i64 = 319;
    const MFD_CLOEXEC: i64 = 0x0001;
    const MFD_ALLOW_SEALING: i64 = 0x0002;
    let name = b"naux-adr0073-dependency\0";
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
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ADR-0073 memfd fd"))
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
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ADR-0073 seal mask"))
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn get_seals(_file: &File) -> Result<u32, io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "ADR-0073 seals require Linux x86-64",
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
        "ADR-0073 descriptor mode requires Linux x86-64",
    ))
}

fn require_supported_host() -> Result<(), X64TailWorkerDependencyObjectError> {
    if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        Ok(())
    } else {
        Err(X64TailWorkerDependencyObjectError::UnsupportedHost)
    }
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    put_u16(bytes, version.0);
    put_u16(bytes, version.1);
    put_u16(bytes, version.2);
}

fn put_hash(bytes: &mut Vec<u8>, hash: SemanticHash) {
    bytes.extend_from_slice(&hash.0);
}

fn put_string(bytes: &mut Vec<u8>, value: &str) {
    put_u16(bytes, u16::try_from(value.len()).unwrap_or(u16::MAX));
    bytes.extend_from_slice(value.as_bytes());
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn probe_x64_tail_worker_dependency_object_elf_mutations(bytes: &[u8]) -> bool {
    if inspect_dependency_elf(bytes, 0).is_err() {
        return false;
    }
    let Ok(program_header_offset) = read_u64(bytes, 32, 0) else {
        return false;
    };
    let Ok(program_header_count) = read_u16(bytes, 56, 0) else {
        return false;
    };
    let mut load_offset = None;
    let mut dynamic_offset = None;
    let mut stack_offset = None;
    for ordinal in 0..program_header_count {
        let Some(offset) = program_header_offset
            .checked_add(u64::from(ordinal) * u64::from(PROGRAM_HEADER_BYTES))
            .and_then(|offset| usize::try_from(offset).ok())
        else {
            return false;
        };
        match read_u32(bytes, offset, 0) {
            Ok(PT_LOAD) if load_offset.is_none() => load_offset = Some(offset),
            Ok(PT_DYNAMIC) if dynamic_offset.is_none() => dynamic_offset = Some(offset),
            Ok(PT_GNU_STACK) if stack_offset.is_none() => stack_offset = Some(offset),
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    let (Some(load_offset), Some(dynamic_offset), Some(stack_offset)) =
        (load_offset, dynamic_offset, stack_offset)
    else {
        return false;
    };
    let file_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    [
        elf_mutation_rejected(bytes, |value| value[0] ^= 1),
        elf_mutation_rejected(bytes, |value| value[4] = 1),
        elf_mutation_rejected(bytes, |value| value[5] = 2),
        elf_mutation_rejected(bytes, |value| value[6] = 0),
        elf_mutation_rejected(bytes, |value| value[7] = 0xff),
        elf_mutation_rejected(bytes, |value| value[9] = 1),
        elf_mutation_rejected(bytes, |value| {
            value[16..18].copy_from_slice(&2u16.to_le_bytes())
        }),
        elf_mutation_rejected(bytes, |value| {
            value[18..20].copy_from_slice(&3u16.to_le_bytes())
        }),
        elf_mutation_rejected(bytes, |value| {
            value[20..24].copy_from_slice(&2u32.to_le_bytes())
        }),
        elf_mutation_rejected(bytes, |value| {
            value[48..52].copy_from_slice(&1u32.to_le_bytes())
        }),
        elf_mutation_rejected(bytes, |value| {
            value[52..54].copy_from_slice(&63u16.to_le_bytes())
        }),
        elf_mutation_rejected(bytes, |value| {
            value[54..56].copy_from_slice(&55u16.to_le_bytes())
        }),
        elf_mutation_rejected(bytes, |value| {
            value[56..58].copy_from_slice(&0u16.to_le_bytes())
        }),
        elf_mutation_rejected(bytes, |value| {
            value[56..58].copy_from_slice(
                &X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_PROGRAM_HEADERS
                    .saturating_add(1)
                    .to_le_bytes(),
            )
        }),
        elf_mutation_rejected(bytes, |value| {
            value[32..40].copy_from_slice(&file_len.to_le_bytes())
        }),
        elf_mutation_rejected(bytes, |value| {
            value[60..62].copy_from_slice(
                &X64_TAIL_WORKER_DEPENDENCY_OBJECT_MAX_SECTION_HEADERS
                    .saturating_add(1)
                    .to_le_bytes(),
            )
        }),
        elf_mutation_rejected(bytes, |value| {
            value[load_offset + 4..load_offset + 8].copy_from_slice(&(PF_W | PF_X).to_le_bytes())
        }),
        elf_mutation_rejected(bytes, |value| {
            value[stack_offset + 4..stack_offset + 8].copy_from_slice(&PF_X.to_le_bytes())
        }),
        elf_mutation_rejected(bytes, |value| {
            value[dynamic_offset..dynamic_offset + 4].copy_from_slice(&4u32.to_le_bytes())
        }),
        elf_mutation_rejected(bytes, |value| {
            value[stack_offset..stack_offset + 4].copy_from_slice(&4u32.to_le_bytes())
        }),
        elf_mutation_rejected(bytes, |value| {
            value[load_offset + 48..load_offset + 56].copy_from_slice(&3u64.to_le_bytes())
        }),
        elf_mutation_rejected(bytes, |value| {
            value[load_offset + 8..load_offset + 16].copy_from_slice(&file_len.to_le_bytes());
            value[load_offset + 32..load_offset + 40].copy_from_slice(&1u64.to_le_bytes());
            value[load_offset + 40..load_offset + 48].copy_from_slice(&1u64.to_le_bytes());
        }),
        inspect_dependency_elf(&bytes[..usize::from(ELF_HEADER_BYTES) - 1], 0).is_err(),
    ]
    .into_iter()
    .all(|rejected| rejected)
}

#[cfg(debug_assertions)]
fn elf_mutation_rejected(bytes: &[u8], mutate: impl FnOnce(&mut [u8])) -> bool {
    let mut mutation = bytes.to_vec();
    mutate(&mut mutation);
    inspect_dependency_elf(&mutation, 0).is_err()
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn probe_x64_tail_worker_dependency_object_mutations(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
) -> bool {
    let mut stale_policy = object_set.evidence.clone();
    stale_policy.policy_hash.0[0] ^= 1;

    let mut stale_declaration = object_set.evidence.clone();
    stale_declaration.declaration_evidence_hash.0[0] ^= 1;

    let mut stale_manifest = object_set.evidence.clone();
    stale_manifest.manifest_hash.0[0] ^= 1;

    let mut stale_total = object_set.evidence.clone();
    stale_total.total_bytes = stale_total.total_bytes.saturating_add(1);

    let mut stale_record = object_set.evidence.clone();
    stale_record.objects[0].object_hash.0[0] ^= 1;

    let mut resealed_record = object_set.evidence.clone();
    resealed_record.objects[0].source_path.push('x');
    resealed_record.objects[0].evidence_hash =
        dependency_object_evidence_hash(&resealed_record.objects[0]);
    resealed_record.evidence_hash = dependency_objects_evidence_hash(&resealed_record);

    [
        stale_policy,
        stale_declaration,
        stale_manifest,
        stale_total,
        stale_record,
        resealed_record,
    ]
    .iter()
    .all(|mutation| {
        verify_dependency_objects_with_evidence(
            artifact,
            inventory,
            declaration_expectation,
            declaration_evidence,
            manifest,
            object_set,
            mutation,
        )
        .is_err()
    })
}
