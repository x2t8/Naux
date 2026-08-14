//! ADR-0072 reviewed dependency-declaration admission.
//!
//! The caller-supplied expectation is authority only when it came from review
//! outside this admission call. This boundary proves that the independently
//! replayed ADR-0071 inventory declares exactly the reviewed interpreter,
//! ordered dependency names, and hardening flags. It does not resolve, open,
//! hash, load, or execute any dependency.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_worker_artifact::X64TailWorkerArtifact;
use super::x64_tail_worker_elf::{
    verify_x64_tail_worker_elf_evidence, X64TailWorkerElfError, X64TailWorkerElfEvidence,
    X64_TAIL_WORKER_ELF_MAX_DEPENDENCIES, X64_TAIL_WORKER_ELF_MAX_NAME_BYTES,
    X64_TAIL_WORKER_ELF_POLICY_ROOT,
};
use std::collections::BTreeSet;
use std::fmt;

pub const X64_TAIL_WORKER_DEPENDENCY_ADMISSION_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_DEPENDENCY_ADMISSION_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_DEPENDENCY_REQUIRED_FLAGS: u64 = 0x0000_0008;
pub const X64_TAIL_WORKER_DEPENDENCY_REQUIRED_FLAGS_1: u64 = 0x0800_0001;
pub const X64_TAIL_WORKER_DEPENDENCY_ADMISSION_POLICY_ROOT: SemanticHash = SemanticHash([
    0x5a, 0x69, 0x47, 0x05, 0x30, 0xec, 0x8f, 0x65, 0xbe, 0x01, 0x8f, 0x53, 0x92, 0x73, 0x79, 0x38,
    0x1a, 0x6d, 0x20, 0xce, 0xc7, 0xca, 0x90, 0x76, 0xa6, 0x94, 0x41, 0xa8, 0x01, 0x83, 0xec, 0x22,
]);

const POLICY_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-admission-policy:v1\0";
const EXPECTATION_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-expectation:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-admission-evidence:v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyExpectation {
    schema_version: (u16, u16, u16),
    interpreter: String,
    dependencies: Vec<String>,
    dynamic_flags: u64,
    dynamic_flags_1: u64,
    expectation_hash: SemanticHash,
}

impl X64TailWorkerDependencyExpectation {
    pub fn new(
        interpreter: String,
        dependencies: Vec<String>,
        dynamic_flags: u64,
        dynamic_flags_1: u64,
    ) -> Result<Self, X64TailWorkerDependencyAdmissionError> {
        let mut expectation = Self {
            schema_version: X64_TAIL_WORKER_DEPENDENCY_ADMISSION_SCHEMA_VERSION,
            interpreter,
            dependencies,
            dynamic_flags,
            dynamic_flags_1,
            expectation_hash: SemanticHash::ZERO,
        };
        validate_expectation_shape(&expectation)?;
        expectation.expectation_hash = dependency_expectation_hash(&expectation);
        Ok(expectation)
    }

    pub fn interpreter(&self) -> &str {
        &self.interpreter
    }

    pub fn dependencies(&self) -> &[String] {
        &self.dependencies
    }

    pub const fn dynamic_flags(&self) -> u64 {
        self.dynamic_flags
    }

    pub const fn dynamic_flags_1(&self) -> u64 {
        self.dynamic_flags_1
    }

    pub const fn expectation_hash(&self) -> SemanticHash {
        self.expectation_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyAdmissionEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    policy_hash: SemanticHash,
    artifact_hash: SemanticHash,
    inventory_policy_hash: SemanticHash,
    inventory_evidence_hash: SemanticHash,
    expectation_hash: SemanticHash,
    dependency_count: u16,
    dynamic_flags: u64,
    dynamic_flags_1: u64,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerDependencyAdmissionEvidence {
    pub const fn policy_hash(&self) -> SemanticHash {
        self.policy_hash
    }

    pub const fn artifact_hash(&self) -> SemanticHash {
        self.artifact_hash
    }

    pub const fn inventory_evidence_hash(&self) -> SemanticHash {
        self.inventory_evidence_hash
    }

    pub const fn expectation_hash(&self) -> SemanticHash {
        self.expectation_hash
    }

    pub const fn dependency_count(&self) -> u16 {
        self.dependency_count
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailWorkerDependencyAdmission<'evidence> {
    evidence: &'evidence X64TailWorkerDependencyAdmissionEvidence,
}

impl<'evidence> VerifiedX64TailWorkerDependencyAdmission<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64TailWorkerDependencyAdmissionEvidence {
        self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailWorkerDependencyAdmissionError {
    Inventory(X64TailWorkerElfError),
    InvalidExpectation(&'static str),
    Limit {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    ExpectationHashMismatch,
    InterpreterMismatch,
    DependencyCountMismatch {
        expected: u16,
        actual: u16,
    },
    DependencyMismatch {
        ordinal: u16,
    },
    DynamicFlagsMismatch,
    DynamicFlags1Mismatch,
    EvidenceMismatch,
}

impl fmt::Display for X64TailWorkerDependencyAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inventory(error) => write!(formatter, "ADR-0072 inventory failed: {error}"),
            Self::InvalidExpectation(field) => {
                write!(formatter, "invalid ADR-0072 expectation {field}")
            }
            Self::Limit {
                field,
                limit,
                actual,
            } => write!(formatter, "ADR-0072 {field} {actual} exceeds limit {limit}"),
            Self::ExpectationHashMismatch => {
                formatter.write_str("ADR-0072 expectation hash mismatch")
            }
            Self::InterpreterMismatch => formatter.write_str("ADR-0072 interpreter mismatch"),
            Self::DependencyCountMismatch { expected, actual } => write!(
                formatter,
                "ADR-0072 dependency count mismatch: expected {expected}, actual {actual}"
            ),
            Self::DependencyMismatch { ordinal } => {
                write!(
                    formatter,
                    "ADR-0072 dependency mismatch at ordinal {ordinal}"
                )
            }
            Self::DynamicFlagsMismatch => formatter.write_str("ADR-0072 DT_FLAGS mismatch"),
            Self::DynamicFlags1Mismatch => formatter.write_str("ADR-0072 DT_FLAGS_1 mismatch"),
            Self::EvidenceMismatch => formatter.write_str("ADR-0072 evidence mismatch"),
        }
    }
}

impl std::error::Error for X64TailWorkerDependencyAdmissionError {}

impl From<X64TailWorkerElfError> for X64TailWorkerDependencyAdmissionError {
    fn from(value: X64TailWorkerElfError) -> Self {
        Self::Inventory(value)
    }
}

pub fn admit_x64_tail_worker_dependency_declarations(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    expectation: &X64TailWorkerDependencyExpectation,
) -> Result<X64TailWorkerDependencyAdmissionEvidence, X64TailWorkerDependencyAdmissionError> {
    validate_expectation(expectation)?;
    compare_inventory_to_expectation(inventory, expectation)?;
    let verified_inventory = verify_x64_tail_worker_elf_evidence(artifact, inventory)?;
    let inventory = verified_inventory.evidence();

    let mut evidence = X64TailWorkerDependencyAdmissionEvidence {
        schema_version: X64_TAIL_WORKER_DEPENDENCY_ADMISSION_SCHEMA_VERSION,
        policy_version: X64_TAIL_WORKER_DEPENDENCY_ADMISSION_POLICY_VERSION,
        policy_hash: x64_tail_worker_dependency_admission_policy_hash(),
        artifact_hash: inventory.artifact_hash(),
        inventory_policy_hash: inventory.policy_hash(),
        inventory_evidence_hash: inventory.evidence_hash(),
        expectation_hash: expectation.expectation_hash,
        dependency_count: u16::try_from(inventory.dependencies().len()).map_err(|_| {
            X64TailWorkerDependencyAdmissionError::Limit {
                field: "dependency count",
                limit: u64::from(X64_TAIL_WORKER_ELF_MAX_DEPENDENCIES),
                actual: u64::try_from(inventory.dependencies().len()).unwrap_or(u64::MAX),
            }
        })?,
        dynamic_flags: inventory.dynamic_flags(),
        dynamic_flags_1: inventory.dynamic_flags_1(),
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = x64_tail_worker_dependency_admission_evidence_hash(&evidence);
    Ok(evidence)
}

pub fn verify_x64_tail_worker_dependency_admission<'evidence>(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    expectation: &X64TailWorkerDependencyExpectation,
    evidence: &'evidence X64TailWorkerDependencyAdmissionEvidence,
) -> Result<
    VerifiedX64TailWorkerDependencyAdmission<'evidence>,
    X64TailWorkerDependencyAdmissionError,
> {
    validate_expectation(expectation)?;
    preflight_evidence(inventory, expectation, evidence)?;
    let expected = admit_x64_tail_worker_dependency_declarations(artifact, inventory, expectation)?;
    if &expected != evidence
        || x64_tail_worker_dependency_admission_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerDependencyAdmissionError::EvidenceMismatch);
    }
    Ok(VerifiedX64TailWorkerDependencyAdmission { evidence })
}

fn preflight_evidence(
    inventory: &X64TailWorkerElfEvidence,
    expectation: &X64TailWorkerDependencyExpectation,
    evidence: &X64TailWorkerDependencyAdmissionEvidence,
) -> Result<(), X64TailWorkerDependencyAdmissionError> {
    let dependency_count = u16::try_from(inventory.dependencies().len()).unwrap_or(u16::MAX);
    if evidence.schema_version != X64_TAIL_WORKER_DEPENDENCY_ADMISSION_SCHEMA_VERSION
        || evidence.policy_version != X64_TAIL_WORKER_DEPENDENCY_ADMISSION_POLICY_VERSION
        || evidence.policy_hash != x64_tail_worker_dependency_admission_policy_hash()
        || evidence.artifact_hash != inventory.artifact_hash()
        || evidence.inventory_policy_hash != inventory.policy_hash()
        || evidence.inventory_evidence_hash != inventory.evidence_hash()
        || evidence.expectation_hash != expectation.expectation_hash
        || evidence.dependency_count != dependency_count
        || evidence.dynamic_flags != inventory.dynamic_flags()
        || evidence.dynamic_flags_1 != inventory.dynamic_flags_1()
        || x64_tail_worker_dependency_admission_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerDependencyAdmissionError::EvidenceMismatch);
    }
    Ok(())
}

pub fn x64_tail_worker_dependency_admission_policy_hash() -> SemanticHash {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(POLICY_DOMAIN);
    put_version(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_ADMISSION_SCHEMA_VERSION,
    );
    put_version(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_ADMISSION_POLICY_VERSION,
    );
    put_hash(&mut bytes, X64_TAIL_WORKER_ELF_POLICY_ROOT);
    put_u16(&mut bytes, X64_TAIL_WORKER_ELF_MAX_DEPENDENCIES);
    put_u64(&mut bytes, X64_TAIL_WORKER_ELF_MAX_NAME_BYTES);
    put_u64(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_REQUIRED_FLAGS);
    put_u64(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_REQUIRED_FLAGS_1);
    SemanticHash(sha256(&bytes))
}

pub fn x64_tail_worker_dependency_admission_evidence_hash(
    evidence: &X64TailWorkerDependencyAdmissionEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_hash(&mut bytes, evidence.policy_hash);
    put_hash(&mut bytes, evidence.artifact_hash);
    put_hash(&mut bytes, evidence.inventory_policy_hash);
    put_hash(&mut bytes, evidence.inventory_evidence_hash);
    put_hash(&mut bytes, evidence.expectation_hash);
    put_u16(&mut bytes, evidence.dependency_count);
    put_u64(&mut bytes, evidence.dynamic_flags);
    put_u64(&mut bytes, evidence.dynamic_flags_1);
    SemanticHash(sha256(&bytes))
}

fn validate_expectation(
    expectation: &X64TailWorkerDependencyExpectation,
) -> Result<(), X64TailWorkerDependencyAdmissionError> {
    validate_expectation_shape(expectation)?;
    if dependency_expectation_hash(expectation) != expectation.expectation_hash {
        return Err(X64TailWorkerDependencyAdmissionError::ExpectationHashMismatch);
    }
    Ok(())
}

fn validate_expectation_shape(
    expectation: &X64TailWorkerDependencyExpectation,
) -> Result<(), X64TailWorkerDependencyAdmissionError> {
    if expectation.schema_version != X64_TAIL_WORKER_DEPENDENCY_ADMISSION_SCHEMA_VERSION {
        return Err(X64TailWorkerDependencyAdmissionError::InvalidExpectation(
            "schema version",
        ));
    }
    validate_interpreter(&expectation.interpreter)?;
    if expectation.dependencies.is_empty()
        || expectation.dependencies.len() > usize::from(X64_TAIL_WORKER_ELF_MAX_DEPENDENCIES)
    {
        return Err(X64TailWorkerDependencyAdmissionError::Limit {
            field: "dependencies",
            limit: u64::from(X64_TAIL_WORKER_ELF_MAX_DEPENDENCIES),
            actual: u64::try_from(expectation.dependencies.len()).unwrap_or(u64::MAX),
        });
    }
    let mut names = BTreeSet::new();
    for dependency in &expectation.dependencies {
        validate_dependency_name(dependency)?;
        if !names.insert(dependency.as_str()) {
            return Err(X64TailWorkerDependencyAdmissionError::InvalidExpectation(
                "duplicate dependency",
            ));
        }
    }
    if expectation.dynamic_flags != X64_TAIL_WORKER_DEPENDENCY_REQUIRED_FLAGS {
        return Err(X64TailWorkerDependencyAdmissionError::DynamicFlagsMismatch);
    }
    if expectation.dynamic_flags_1 != X64_TAIL_WORKER_DEPENDENCY_REQUIRED_FLAGS_1 {
        return Err(X64TailWorkerDependencyAdmissionError::DynamicFlags1Mismatch);
    }
    Ok(())
}

fn compare_inventory_to_expectation(
    inventory: &X64TailWorkerElfEvidence,
    expectation: &X64TailWorkerDependencyExpectation,
) -> Result<(), X64TailWorkerDependencyAdmissionError> {
    if inventory.policy_hash() != X64_TAIL_WORKER_ELF_POLICY_ROOT {
        return Err(X64TailWorkerDependencyAdmissionError::Inventory(
            X64TailWorkerElfError::EvidenceMismatch,
        ));
    }
    if inventory.interpreter() != expectation.interpreter {
        return Err(X64TailWorkerDependencyAdmissionError::InterpreterMismatch);
    }
    let actual_count = u16::try_from(inventory.dependencies().len()).unwrap_or(u16::MAX);
    let expected_count = u16::try_from(expectation.dependencies.len()).unwrap_or(u16::MAX);
    if actual_count != expected_count {
        return Err(
            X64TailWorkerDependencyAdmissionError::DependencyCountMismatch {
                expected: expected_count,
                actual: actual_count,
            },
        );
    }
    for (ordinal, (actual, expected)) in inventory
        .dependencies()
        .iter()
        .zip(&expectation.dependencies)
        .enumerate()
    {
        if actual.name() != expected {
            return Err(X64TailWorkerDependencyAdmissionError::DependencyMismatch {
                ordinal: u16::try_from(ordinal).unwrap_or(u16::MAX),
            });
        }
    }
    if inventory.dynamic_flags() != expectation.dynamic_flags {
        return Err(X64TailWorkerDependencyAdmissionError::DynamicFlagsMismatch);
    }
    if inventory.dynamic_flags_1() != expectation.dynamic_flags_1 {
        return Err(X64TailWorkerDependencyAdmissionError::DynamicFlags1Mismatch);
    }
    Ok(())
}

fn validate_interpreter(value: &str) -> Result<(), X64TailWorkerDependencyAdmissionError> {
    validate_name_bytes(value, "interpreter")?;
    if !value.starts_with('/')
        || value == "/"
        || value.ends_with('/')
        || value[1..]
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(X64TailWorkerDependencyAdmissionError::InvalidExpectation(
            "interpreter path",
        ));
    }
    Ok(())
}

fn validate_dependency_name(value: &str) -> Result<(), X64TailWorkerDependencyAdmissionError> {
    validate_name_bytes(value, "dependency name")?;
    if value.contains('/') || value.contains('\\') || matches!(value, "." | "..") {
        return Err(X64TailWorkerDependencyAdmissionError::InvalidExpectation(
            "dependency name",
        ));
    }
    Ok(())
}

fn validate_name_bytes(
    value: &str,
    field: &'static str,
) -> Result<(), X64TailWorkerDependencyAdmissionError> {
    let actual = u64::try_from(value.len()).unwrap_or(u64::MAX);
    if value.is_empty() || actual > X64_TAIL_WORKER_ELF_MAX_NAME_BYTES {
        return Err(X64TailWorkerDependencyAdmissionError::Limit {
            field,
            limit: X64_TAIL_WORKER_ELF_MAX_NAME_BYTES,
            actual,
        });
    }
    if value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte)) {
        return Err(X64TailWorkerDependencyAdmissionError::InvalidExpectation(
            field,
        ));
    }
    Ok(())
}

fn dependency_expectation_hash(expectation: &X64TailWorkerDependencyExpectation) -> SemanticHash {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(EXPECTATION_DOMAIN);
    put_version(&mut bytes, expectation.schema_version);
    put_hash(
        &mut bytes,
        x64_tail_worker_dependency_admission_policy_hash(),
    );
    put_string(&mut bytes, &expectation.interpreter);
    put_u16(
        &mut bytes,
        u16::try_from(expectation.dependencies.len()).unwrap_or(u16::MAX),
    );
    for dependency in &expectation.dependencies {
        put_string(&mut bytes, dependency);
    }
    put_u64(&mut bytes, expectation.dynamic_flags);
    put_u64(&mut bytes, expectation.dynamic_flags_1);
    SemanticHash(sha256(&bytes))
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

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn probe_x64_tail_worker_dependency_admission_mutations(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    expectation: &X64TailWorkerDependencyExpectation,
    evidence: &X64TailWorkerDependencyAdmissionEvidence,
) -> bool {
    let mut stale_policy = evidence.clone();
    stale_policy.policy_hash.0[0] ^= 1;

    let mut stale_inventory = evidence.clone();
    stale_inventory.inventory_evidence_hash.0[0] ^= 1;

    let mut stale_expectation = evidence.clone();
    stale_expectation.expectation_hash.0[0] ^= 1;

    let mut stale_count = evidence.clone();
    stale_count.dependency_count = stale_count.dependency_count.saturating_add(1);

    let mut stale_hash = evidence.clone();
    stale_hash.evidence_hash.0[0] ^= 1;

    let mut resealed = evidence.clone();
    resealed.artifact_hash.0[0] ^= 1;
    resealed.evidence_hash = x64_tail_worker_dependency_admission_evidence_hash(&resealed);

    let evidence_mutations_fail = [
        stale_policy,
        stale_inventory,
        stale_expectation,
        stale_count,
        stale_hash,
        resealed,
    ]
    .iter()
    .all(|mutation| {
        verify_x64_tail_worker_dependency_admission(artifact, inventory, expectation, mutation)
            .is_err()
    });

    let mut resealed_expectation = expectation.clone();
    resealed_expectation.dependencies.swap(0, 1);
    resealed_expectation.expectation_hash = dependency_expectation_hash(&resealed_expectation);

    evidence_mutations_fail
        && verify_x64_tail_worker_dependency_admission(
            artifact,
            inventory,
            &resealed_expectation,
            evidence,
        )
        .is_err()
}
