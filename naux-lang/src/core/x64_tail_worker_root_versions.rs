//! ADR-0080 proof-only root-worker GNU version-requirement inventory.
//!
//! This decoder consumes only the immutable ADR-0070 artifact after replaying
//! ADR-0071, ADR-0072, and ADR-0075. It inventories the root requester's
//! `Verneed`/`Vernaux` chains; it never matches a definition or resolves a
//! symbol, relocation, path, or loader scope.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_worker_artifact::{
    verify_x64_tail_worker_artifact, x64_tail_worker_artifact_bytes, X64TailWorkerArtifact,
    X64TailWorkerArtifactError, X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT,
};
use super::x64_tail_worker_dependency_admission::{
    X64TailWorkerDependencyAdmissionEvidence, X64TailWorkerDependencyExpectation,
    X64_TAIL_WORKER_DEPENDENCY_ADMISSION_POLICY_ROOT,
};
use super::x64_tail_worker_dependency_closure::{
    verify_x64_tail_worker_dependency_closure, X64TailWorkerDependencyClosureError,
    X64TailWorkerDependencyClosureEvidence, X64TailWorkerDependencyClosureExpectation,
    X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT,
};
use super::x64_tail_worker_dependency_dynamic::X64TailWorkerDependencyDynamicEvidence;
use super::x64_tail_worker_dependency_objects::{
    X64TailWorkerDependencyObjectManifest, X64TailWorkerDependencyObjectSet,
};
use super::x64_tail_worker_elf::{X64TailWorkerElfEvidence, X64_TAIL_WORKER_ELF_POLICY_ROOT};
use std::collections::BTreeSet;
use std::fmt;

pub const X64_TAIL_WORKER_ROOT_VERSION_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_ROOT_VERSION_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_ROOT_VERSION_MAX_PROGRAM_HEADERS: u16 = 64;
pub const X64_TAIL_WORKER_ROOT_VERSION_MAX_LOAD_SEGMENTS: u16 = 16;
pub const X64_TAIL_WORKER_ROOT_VERSION_MAX_DYNAMIC_ENTRIES: u16 = 4_096;
pub const X64_TAIL_WORKER_ROOT_VERSION_MAX_REQUIREMENTS: u16 = 64;
pub const X64_TAIL_WORKER_ROOT_VERSION_MAX_AUX_PER_REQUIREMENT: u16 = 64;
pub const X64_TAIL_WORKER_ROOT_VERSION_MAX_TOTAL_AUX: u16 = 4_096;
pub const X64_TAIL_WORKER_ROOT_VERSION_MAX_STRING_TABLE_BYTES: u64 = 1024 * 1024;
pub const X64_TAIL_WORKER_ROOT_VERSION_MAX_NAME_BYTES: u16 = 256;
pub const X64_TAIL_WORKER_ROOT_VERSION_POLICY_ROOT: SemanticHash = SemanticHash([
    0x1e, 0x72, 0x83, 0x41, 0xf6, 0x9e, 0x0c, 0xb1, 0xba, 0x9d, 0x5c, 0xe8, 0xa6, 0x40, 0x0c, 0xdb,
    0xe7, 0x2c, 0x88, 0x66, 0xa1, 0xed, 0x8e, 0xc8, 0xe5, 0x2a, 0x1a, 0x50, 0xfa, 0x9f, 0xec, 0xdf,
]);

const POLICY_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-version-policy:v1\0";
const AUX_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-version-aux:v1\0";
const REQUIREMENT_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-version-requirement:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-version-evidence:v1\0";
const POLICY_CAPABILITIES: &[&str] = &[
    "immutable-verified-adr0070-root-byte-source-v1",
    "full-adr0071-adr0072-adr0075-predecessor-replay-v1",
    "independent-elf64-x86-64-root-layout-decoder-v1",
    "paired-bounded-root-verneed-tag-inventory-v1",
    "ordered-nonoverlapping-root-verneed-vernaux-chain-v1",
    "exact-direct-declaration-and-provider-soname-binding-v1",
    "sovereign-elf-version-name-hash-validation-v1",
    "bounded-supported-version-flags-and-indices-v1",
    "domain-separated-record-and-aggregate-replay-v1",
    "proof-only-no-definition-symbol-resolution-or-execution-v1",
];

const ELF_HEADER_BYTES: u16 = 64;
const PROGRAM_HEADER_BYTES: u16 = 56;
const DYNAMIC_ENTRY_BYTES: u64 = 16;
const VERNEED_BYTES: u64 = 16;
const VERNAUX_BYTES: u64 = 16;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_W: u32 = 2;
const DT_NULL: i64 = 0;
const DT_STRTAB: i64 = 5;
const DT_STRSZ: i64 = 10;
const DT_VERNEED: i64 = 0x6fff_fffe;
const DT_VERNEEDNUM: i64 = 0x6fff_ffff;
const VERNEED_CURRENT: u16 = 1;
const VER_FLG_WEAK: u16 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerRootVersionAuxEvidence {
    ordinal: u16,
    file_offset: u64,
    name_hash: u32,
    flags: u16,
    version_index: u16,
    name_offset: u32,
    name: String,
    next_offset: u32,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerRootVersionAuxEvidence {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub const fn file_offset(&self) -> u64 {
        self.file_offset
    }

    pub const fn name_hash(&self) -> u32 {
        self.name_hash
    }

    pub const fn flags(&self) -> u16 {
        self.flags
    }

    pub const fn version_index(&self) -> u16 {
        self.version_index
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerRootVersionRequirementEvidence {
    ordinal: u16,
    file_offset: u64,
    version: u16,
    file_name_offset: u32,
    file_name: String,
    declaration_ordinal: u16,
    provider_ordinal: u16,
    provider_evidence_hash: SemanticHash,
    auxiliary_count: u16,
    aux_offset: u32,
    next_offset: u32,
    auxiliaries: Vec<X64TailWorkerRootVersionAuxEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerRootVersionRequirementEvidence {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    pub const fn declaration_ordinal(&self) -> u16 {
        self.declaration_ordinal
    }

    pub const fn provider_ordinal(&self) -> u16 {
        self.provider_ordinal
    }

    pub const fn provider_evidence_hash(&self) -> SemanticHash {
        self.provider_evidence_hash
    }

    pub const fn auxiliary_count(&self) -> u16 {
        self.auxiliary_count
    }

    pub fn auxiliaries(&self) -> &[X64TailWorkerRootVersionAuxEvidence] {
        &self.auxiliaries
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerRootVersionEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    policy_hash: SemanticHash,
    artifact_policy_hash: SemanticHash,
    artifact_expectation_hash: SemanticHash,
    artifact_hash: SemanticHash,
    inventory_policy_hash: SemanticHash,
    inventory_evidence_hash: SemanticHash,
    declaration_policy_hash: SemanticHash,
    declaration_expectation_hash: SemanticHash,
    declaration_evidence_hash: SemanticHash,
    closure_policy_hash: SemanticHash,
    closure_evidence_hash: SemanticHash,
    requirement_count: u16,
    auxiliary_count: u16,
    requirements: Vec<X64TailWorkerRootVersionRequirementEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerRootVersionEvidence {
    pub const fn policy_hash(&self) -> SemanticHash {
        self.policy_hash
    }

    pub const fn artifact_hash(&self) -> SemanticHash {
        self.artifact_hash
    }

    pub const fn requirement_count(&self) -> u16 {
        self.requirement_count
    }

    pub const fn auxiliary_count(&self) -> u16 {
        self.auxiliary_count
    }

    pub fn requirements(&self) -> &[X64TailWorkerRootVersionRequirementEvidence] {
        &self.requirements
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailWorkerRootVersions<'evidence> {
    evidence: &'evidence X64TailWorkerRootVersionEvidence,
}

impl<'evidence> VerifiedX64TailWorkerRootVersions<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64TailWorkerRootVersionEvidence {
        self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailWorkerRootVersionError {
    Artifact(X64TailWorkerArtifactError),
    Closure(X64TailWorkerDependencyClosureError),
    Invalid(&'static str),
    Limit {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    Overflow(&'static str),
    EvidenceMismatch,
}

impl fmt::Display for X64TailWorkerRootVersionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Artifact(error) => write!(formatter, "ADR-0080 artifact failed: {error}"),
            Self::Closure(error) => write!(formatter, "ADR-0080 closure failed: {error}"),
            Self::Invalid(field) => write!(formatter, "invalid ADR-0080 {field}"),
            Self::Limit {
                field,
                limit,
                actual,
            } => write!(formatter, "ADR-0080 {field} {actual} exceeds limit {limit}"),
            Self::Overflow(field) => write!(formatter, "ADR-0080 {field} overflow"),
            Self::EvidenceMismatch => formatter.write_str("ADR-0080 evidence mismatch"),
        }
    }
}

impl std::error::Error for X64TailWorkerRootVersionError {}

impl From<X64TailWorkerArtifactError> for X64TailWorkerRootVersionError {
    fn from(value: X64TailWorkerArtifactError) -> Self {
        Self::Artifact(value)
    }
}

impl From<X64TailWorkerDependencyClosureError> for X64TailWorkerRootVersionError {
    fn from(value: X64TailWorkerDependencyClosureError) -> Self {
        Self::Closure(value)
    }
}

struct LoadSegment {
    flags: u32,
    file_offset: u64,
    virtual_address: u64,
    file_size: u64,
}

struct DynamicSegment {
    file_offset: u64,
    file_size: u64,
}

#[allow(clippy::too_many_arguments)]
pub fn emit_x64_tail_worker_root_version_evidence(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure_evidence: &X64TailWorkerDependencyClosureEvidence,
) -> Result<X64TailWorkerRootVersionEvidence, X64TailWorkerRootVersionError> {
    if x64_tail_worker_root_version_policy_hash() != X64_TAIL_WORKER_ROOT_VERSION_POLICY_ROOT {
        return Err(X64TailWorkerRootVersionError::Invalid("policy root"));
    }
    verify_x64_tail_worker_dependency_closure(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
        dynamic_evidence,
        closure_expectation,
        closure_evidence,
    )?;
    let verified_artifact = verify_x64_tail_worker_artifact(artifact)?;
    let bytes = x64_tail_worker_artifact_bytes(&verified_artifact)?;
    let requirements = decode_root_versions(&bytes, declaration_expectation, closure_evidence)?;
    let auxiliary_count = requirements.iter().try_fold(0u16, |total, requirement| {
        total
            .checked_add(
                u16::try_from(requirement.auxiliaries.len())
                    .map_err(|_| X64TailWorkerRootVersionError::Overflow("root auxiliaries"))?,
            )
            .ok_or(X64TailWorkerRootVersionError::Overflow("root auxiliaries"))
    })?;
    if auxiliary_count > X64_TAIL_WORKER_ROOT_VERSION_MAX_TOTAL_AUX {
        return Err(X64TailWorkerRootVersionError::Limit {
            field: "total root auxiliaries",
            limit: u64::from(X64_TAIL_WORKER_ROOT_VERSION_MAX_TOTAL_AUX),
            actual: u64::from(auxiliary_count),
        });
    }
    let mut evidence = X64TailWorkerRootVersionEvidence {
        schema_version: X64_TAIL_WORKER_ROOT_VERSION_SCHEMA_VERSION,
        policy_version: X64_TAIL_WORKER_ROOT_VERSION_POLICY_VERSION,
        policy_hash: x64_tail_worker_root_version_policy_hash(),
        artifact_policy_hash: X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT,
        artifact_expectation_hash: artifact.expectation().expectation_hash(),
        artifact_hash: artifact.expectation().artifact_hash(),
        inventory_policy_hash: X64_TAIL_WORKER_ELF_POLICY_ROOT,
        inventory_evidence_hash: inventory.evidence_hash(),
        declaration_policy_hash: X64_TAIL_WORKER_DEPENDENCY_ADMISSION_POLICY_ROOT,
        declaration_expectation_hash: declaration_expectation.expectation_hash(),
        declaration_evidence_hash: declaration_evidence.evidence_hash(),
        closure_policy_hash: X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT,
        closure_evidence_hash: closure_evidence.evidence_hash(),
        requirement_count: u16::try_from(requirements.len())
            .map_err(|_| X64TailWorkerRootVersionError::Overflow("root requirements"))?,
        auxiliary_count,
        requirements,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = x64_tail_worker_root_version_evidence_hash(&evidence);
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_x64_tail_worker_root_version_evidence<'evidence>(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure_evidence: &X64TailWorkerDependencyClosureEvidence,
    evidence: &'evidence X64TailWorkerRootVersionEvidence,
) -> Result<VerifiedX64TailWorkerRootVersions<'evidence>, X64TailWorkerRootVersionError> {
    preflight_root_version_evidence(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        closure_evidence,
        evidence,
    )?;
    let expected = emit_x64_tail_worker_root_version_evidence(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
        dynamic_evidence,
        closure_expectation,
        closure_evidence,
    )?;
    if &expected != evidence
        || x64_tail_worker_root_version_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerRootVersionError::EvidenceMismatch);
    }
    Ok(VerifiedX64TailWorkerRootVersions { evidence })
}

fn decode_root_versions(
    bytes: &[u8],
    declaration: &X64TailWorkerDependencyExpectation,
    closure: &X64TailWorkerDependencyClosureEvidence,
) -> Result<Vec<X64TailWorkerRootVersionRequirementEvidence>, X64TailWorkerRootVersionError> {
    let (loads, dynamic) = decode_layout(bytes)?;
    let (string_address, string_bytes, version_address, version_count) =
        decode_dynamic_version_tags(bytes, &dynamic)?;
    if string_bytes > X64_TAIL_WORKER_ROOT_VERSION_MAX_STRING_TABLE_BYTES {
        return Err(X64TailWorkerRootVersionError::Limit {
            field: "string table bytes",
            limit: X64_TAIL_WORKER_ROOT_VERSION_MAX_STRING_TABLE_BYTES,
            actual: string_bytes,
        });
    }
    let strings = map_virtual_readonly_range(bytes, &loads, string_address, string_bytes)?;
    let mut requirements = Vec::with_capacity(usize::from(version_count));
    let mut occupied = Vec::new();
    let mut version_indices = BTreeSet::new();
    let mut current_address = version_address.unwrap_or(0);
    for ordinal in 0..version_count {
        let (record, file_offset) = map_virtual_readonly_record(
            bytes,
            &loads,
            current_address,
            VERNEED_BYTES,
            "root Verneed record",
        )?;
        claim_record_range(&mut occupied, file_offset, VERNEED_BYTES)?;
        let version = read_u16(record, 0, "vn_version")?;
        let auxiliary_count = read_u16(record, 2, "vn_cnt")?;
        let file_name_offset = read_u32(record, 4, "vn_file")?;
        let aux_offset = read_u32(record, 8, "vn_aux")?;
        let next_offset = read_u32(record, 12, "vn_next")?;
        if version != VERNEED_CURRENT {
            return Err(X64TailWorkerRootVersionError::Invalid("Verneed version"));
        }
        if auxiliary_count == 0
            || auxiliary_count > X64_TAIL_WORKER_ROOT_VERSION_MAX_AUX_PER_REQUIREMENT
        {
            return Err(X64TailWorkerRootVersionError::Limit {
                field: "Vernaux records",
                limit: u64::from(X64_TAIL_WORKER_ROOT_VERSION_MAX_AUX_PER_REQUIREMENT),
                actual: u64::from(auxiliary_count),
            });
        }
        validate_relative_offset(aux_offset, "vn_aux")?;
        validate_chain_next(next_offset, ordinal + 1 == version_count, "vn_next")?;
        let file_name = decode_string_at(
            strings,
            string_bytes,
            u64::from(file_name_offset),
            "root version requirement file",
        )?;
        if requirements.iter().any(
            |requirement: &X64TailWorkerRootVersionRequirementEvidence| {
                requirement.file_name == file_name
            },
        ) {
            return Err(X64TailWorkerRootVersionError::Invalid(
                "duplicate root requirement file",
            ));
        }
        let declaration_ordinal = unique_name_ordinal(declaration.dependencies(), &file_name)
            .ok_or(X64TailWorkerRootVersionError::Invalid(
                "root requirement outside direct declarations",
            ))?;
        let provider_ordinal = unique_provider_ordinal(closure, &file_name).ok_or(
            X64TailWorkerRootVersionError::Invalid("root requirement provider"),
        )?;
        let provider = &closure.providers()[usize::from(provider_ordinal)];

        let mut auxiliaries = Vec::with_capacity(usize::from(auxiliary_count));
        let mut auxiliary_names = BTreeSet::new();
        let mut auxiliary_address = current_address
            .checked_add(u64::from(aux_offset))
            .ok_or(X64TailWorkerRootVersionError::Overflow("vn_aux"))?;
        for auxiliary_ordinal in 0..auxiliary_count {
            let (auxiliary, auxiliary_file_offset) = map_virtual_readonly_record(
                bytes,
                &loads,
                auxiliary_address,
                VERNAUX_BYTES,
                "root Vernaux record",
            )?;
            claim_record_range(&mut occupied, auxiliary_file_offset, VERNAUX_BYTES)?;
            let name_hash = read_u32(auxiliary, 0, "vna_hash")?;
            let flags = read_u16(auxiliary, 4, "vna_flags")?;
            let version_index = read_u16(auxiliary, 6, "vna_other")?;
            let name_offset = read_u32(auxiliary, 8, "vna_name")?;
            let auxiliary_next_offset = read_u32(auxiliary, 12, "vna_next")?;
            if flags != 0 && flags != VER_FLG_WEAK {
                return Err(X64TailWorkerRootVersionError::Invalid("Vernaux flags"));
            }
            if !(2..=0x7fff).contains(&version_index) || !version_indices.insert(version_index) {
                return Err(X64TailWorkerRootVersionError::Invalid(
                    "Vernaux version index",
                ));
            }
            validate_chain_next(
                auxiliary_next_offset,
                auxiliary_ordinal + 1 == auxiliary_count,
                "vna_next",
            )?;
            let name = decode_string_at(
                strings,
                string_bytes,
                u64::from(name_offset),
                "root version requirement name",
            )?;
            if !auxiliary_names.insert(name.clone()) {
                return Err(X64TailWorkerRootVersionError::Invalid(
                    "duplicate root version requirement name",
                ));
            }
            if elf_hash(name.as_bytes()) != name_hash {
                return Err(X64TailWorkerRootVersionError::Invalid(
                    "root version requirement hash",
                ));
            }
            let mut evidence = X64TailWorkerRootVersionAuxEvidence {
                ordinal: auxiliary_ordinal,
                file_offset: auxiliary_file_offset,
                name_hash,
                flags,
                version_index,
                name_offset,
                name,
                next_offset: auxiliary_next_offset,
                evidence_hash: SemanticHash::ZERO,
            };
            evidence.evidence_hash = root_version_aux_evidence_hash(&evidence);
            auxiliaries.push(evidence);
            if auxiliary_next_offset != 0 {
                auxiliary_address = auxiliary_address
                    .checked_add(u64::from(auxiliary_next_offset))
                    .ok_or(X64TailWorkerRootVersionError::Overflow("vna_next"))?;
            }
        }
        let mut evidence = X64TailWorkerRootVersionRequirementEvidence {
            ordinal,
            file_offset,
            version,
            file_name_offset,
            file_name,
            declaration_ordinal,
            provider_ordinal,
            provider_evidence_hash: provider.evidence_hash(),
            auxiliary_count,
            aux_offset,
            next_offset,
            auxiliaries,
            evidence_hash: SemanticHash::ZERO,
        };
        evidence.evidence_hash = root_version_requirement_evidence_hash(&evidence);
        requirements.push(evidence);
        if next_offset != 0 {
            current_address = current_address
                .checked_add(u64::from(next_offset))
                .ok_or(X64TailWorkerRootVersionError::Overflow("vn_next"))?;
        }
    }
    Ok(requirements)
}

fn unique_name_ordinal(names: &[String], wanted: &str) -> Option<u16> {
    let mut matches = names
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate.as_str() == wanted);
    let ordinal = matches.next()?.0;
    if matches.next().is_some() {
        return None;
    }
    u16::try_from(ordinal).ok()
}

fn unique_provider_ordinal(
    closure: &X64TailWorkerDependencyClosureEvidence,
    wanted: &str,
) -> Option<u16> {
    let mut matches = closure
        .providers()
        .iter()
        .filter(|provider| provider.soname() == wanted);
    let provider = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(provider.ordinal())
}

fn decode_layout(
    bytes: &[u8],
) -> Result<(Vec<LoadSegment>, DynamicSegment), X64TailWorkerRootVersionError> {
    require_range(bytes, 0, u64::from(ELF_HEADER_BYTES), "ELF header")?;
    if &bytes[..4] != b"\x7fELF"
        || bytes[4] != 2
        || bytes[5] != 1
        || bytes[6] != 1
        || (bytes[7] != 0 && bytes[7] != 3)
        || bytes[8] != 0
        || bytes[9..16].iter().any(|byte| *byte != 0)
        || read_u16(bytes, 16, "ELF type")? != ET_DYN
        || read_u16(bytes, 18, "ELF machine")? != EM_X86_64
        || read_u32(bytes, 20, "ELF version")? != 1
        || read_u16(bytes, 52, "ELF header size")? != ELF_HEADER_BYTES
        || read_u16(bytes, 54, "program-header size")? != PROGRAM_HEADER_BYTES
    {
        return Err(X64TailWorkerRootVersionError::Invalid("ELF identity"));
    }
    let program_offset = read_u64(bytes, 32, "program-header offset")?;
    let program_count = read_u16(bytes, 56, "program-header count")?;
    if program_count == 0 || program_count > X64_TAIL_WORKER_ROOT_VERSION_MAX_PROGRAM_HEADERS {
        return Err(X64TailWorkerRootVersionError::Limit {
            field: "program headers",
            limit: u64::from(X64_TAIL_WORKER_ROOT_VERSION_MAX_PROGRAM_HEADERS),
            actual: u64::from(program_count),
        });
    }
    require_range(
        bytes,
        program_offset,
        u64::from(program_count) * u64::from(PROGRAM_HEADER_BYTES),
        "program-header table",
    )?;
    let mut loads = Vec::new();
    let mut dynamic = None;
    for ordinal in 0..program_count {
        let offset = program_offset
            .checked_add(u64::from(ordinal) * u64::from(PROGRAM_HEADER_BYTES))
            .ok_or(X64TailWorkerRootVersionError::Overflow("program header"))?;
        let kind = read_u32(bytes, offset, "program-header type")?;
        let flags = read_u32(bytes, offset + 4, "segment flags")?;
        if flags & !7 != 0 {
            return Err(X64TailWorkerRootVersionError::Invalid("segment flags"));
        }
        let file_offset = read_u64(bytes, offset + 8, "segment offset")?;
        let virtual_address = read_u64(bytes, offset + 16, "segment address")?;
        let file_size = read_u64(bytes, offset + 32, "segment file size")?;
        let memory_size = read_u64(bytes, offset + 40, "segment memory size")?;
        if file_size > memory_size {
            return Err(X64TailWorkerRootVersionError::Invalid("segment sizes"));
        }
        require_range(bytes, file_offset, file_size, "segment file range")?;
        match kind {
            PT_LOAD => loads.push(LoadSegment {
                flags,
                file_offset,
                virtual_address,
                file_size,
            }),
            PT_DYNAMIC if dynamic.is_some() => {
                return Err(X64TailWorkerRootVersionError::Invalid(
                    "duplicate dynamic segment",
                ));
            }
            PT_DYNAMIC => {
                dynamic = Some(DynamicSegment {
                    file_offset,
                    file_size,
                });
            }
            _ => {}
        }
    }
    if loads.is_empty() || loads.len() > usize::from(X64_TAIL_WORKER_ROOT_VERSION_MAX_LOAD_SEGMENTS)
    {
        return Err(X64TailWorkerRootVersionError::Limit {
            field: "load segments",
            limit: u64::from(X64_TAIL_WORKER_ROOT_VERSION_MAX_LOAD_SEGMENTS),
            actual: u64::try_from(loads.len()).unwrap_or(u64::MAX),
        });
    }
    Ok((
        loads,
        dynamic.ok_or(X64TailWorkerRootVersionError::Invalid(
            "missing dynamic segment",
        ))?,
    ))
}

fn decode_dynamic_version_tags(
    bytes: &[u8],
    dynamic: &DynamicSegment,
) -> Result<(u64, u64, Option<u64>, u16), X64TailWorkerRootVersionError> {
    if dynamic.file_size == 0 || !dynamic.file_size.is_multiple_of(DYNAMIC_ENTRY_BYTES) {
        return Err(X64TailWorkerRootVersionError::Invalid(
            "dynamic segment size",
        ));
    }
    let entry_count = dynamic.file_size / DYNAMIC_ENTRY_BYTES;
    if entry_count > u64::from(X64_TAIL_WORKER_ROOT_VERSION_MAX_DYNAMIC_ENTRIES) {
        return Err(X64TailWorkerRootVersionError::Limit {
            field: "dynamic entries",
            limit: u64::from(X64_TAIL_WORKER_ROOT_VERSION_MAX_DYNAMIC_ENTRIES),
            actual: entry_count,
        });
    }
    let mut string_address = None;
    let mut string_bytes = None;
    let mut version_address = None;
    let mut version_count = None;
    let mut terminated = false;
    for ordinal in 0..entry_count {
        let offset = dynamic
            .file_offset
            .checked_add(ordinal * DYNAMIC_ENTRY_BYTES)
            .ok_or(X64TailWorkerRootVersionError::Overflow("dynamic entry"))?;
        let tag = read_i64(bytes, offset, "dynamic tag")?;
        let value = read_u64(bytes, offset + 8, "dynamic value")?;
        if terminated {
            if tag != DT_NULL || value != 0 {
                return Err(X64TailWorkerRootVersionError::Invalid(
                    "dynamic trailing entries",
                ));
            }
            continue;
        }
        match tag {
            DT_NULL => {
                if value != 0 {
                    return Err(X64TailWorkerRootVersionError::Invalid("dynamic terminator"));
                }
                terminated = true;
            }
            DT_STRTAB => set_once(&mut string_address, value, "DT_STRTAB")?,
            DT_STRSZ => set_once(&mut string_bytes, value, "DT_STRSZ")?,
            DT_VERNEED => set_once(&mut version_address, value, "DT_VERNEED")?,
            DT_VERNEEDNUM => set_once(&mut version_count, value, "DT_VERNEEDNUM")?,
            _ => {}
        }
    }
    if !terminated {
        return Err(X64TailWorkerRootVersionError::Invalid(
            "missing dynamic terminator",
        ));
    }
    let string_address =
        string_address.ok_or(X64TailWorkerRootVersionError::Invalid("missing DT_STRTAB"))?;
    let string_bytes =
        string_bytes.ok_or(X64TailWorkerRootVersionError::Invalid("missing DT_STRSZ"))?;
    if string_bytes == 0 {
        return Err(X64TailWorkerRootVersionError::Invalid("empty string table"));
    }
    match (version_address, version_count) {
        (None, None) => Ok((string_address, string_bytes, None, 0)),
        (Some(address), Some(count)) => {
            let count = u16::try_from(count).map_err(|_| X64TailWorkerRootVersionError::Limit {
                field: "version requirements",
                limit: u64::from(X64_TAIL_WORKER_ROOT_VERSION_MAX_REQUIREMENTS),
                actual: count,
            })?;
            if address == 0 || count == 0 || count > X64_TAIL_WORKER_ROOT_VERSION_MAX_REQUIREMENTS {
                return Err(X64TailWorkerRootVersionError::Limit {
                    field: "version requirements",
                    limit: u64::from(X64_TAIL_WORKER_ROOT_VERSION_MAX_REQUIREMENTS),
                    actual: u64::from(count),
                });
            }
            Ok((string_address, string_bytes, Some(address), count))
        }
        _ => Err(X64TailWorkerRootVersionError::Invalid(
            "unpaired version requirement tags",
        )),
    }
}

fn preflight_root_version_evidence(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    closure: &X64TailWorkerDependencyClosureEvidence,
    evidence: &X64TailWorkerRootVersionEvidence,
) -> Result<(), X64TailWorkerRootVersionError> {
    if evidence.schema_version != X64_TAIL_WORKER_ROOT_VERSION_SCHEMA_VERSION
        || evidence.policy_version != X64_TAIL_WORKER_ROOT_VERSION_POLICY_VERSION
        || evidence.policy_hash != X64_TAIL_WORKER_ROOT_VERSION_POLICY_ROOT
        || evidence.policy_hash != x64_tail_worker_root_version_policy_hash()
        || evidence.artifact_policy_hash != X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT
        || evidence.artifact_expectation_hash != artifact.expectation().expectation_hash()
        || evidence.artifact_hash != artifact.expectation().artifact_hash()
        || evidence.inventory_policy_hash != X64_TAIL_WORKER_ELF_POLICY_ROOT
        || evidence.inventory_evidence_hash != inventory.evidence_hash()
        || evidence.declaration_policy_hash != X64_TAIL_WORKER_DEPENDENCY_ADMISSION_POLICY_ROOT
        || evidence.declaration_expectation_hash != declaration.expectation_hash()
        || evidence.declaration_evidence_hash != declaration_evidence.evidence_hash()
        || evidence.closure_policy_hash != X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT
        || evidence.closure_evidence_hash != closure.evidence_hash()
        || usize::from(evidence.requirement_count) != evidence.requirements.len()
        || evidence.requirement_count > X64_TAIL_WORKER_ROOT_VERSION_MAX_REQUIREMENTS
        || evidence.auxiliary_count > X64_TAIL_WORKER_ROOT_VERSION_MAX_TOTAL_AUX
        || x64_tail_worker_root_version_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerRootVersionError::EvidenceMismatch);
    }
    let mut total_auxiliaries = 0u16;
    let mut version_indices = BTreeSet::new();
    for (ordinal, requirement) in evidence.requirements.iter().enumerate() {
        total_auxiliaries = total_auxiliaries
            .checked_add(
                u16::try_from(requirement.auxiliaries.len())
                    .map_err(|_| X64TailWorkerRootVersionError::Overflow("evidence auxiliaries"))?,
            )
            .ok_or(X64TailWorkerRootVersionError::Overflow(
                "evidence auxiliaries",
            ))?;
        let provider = closure
            .providers()
            .get(usize::from(requirement.provider_ordinal));
        if requirement.ordinal != u16::try_from(ordinal).unwrap_or(u16::MAX)
            || requirement.version != VERNEED_CURRENT
            || unique_name_ordinal(declaration.dependencies(), &requirement.file_name)
                != Some(requirement.declaration_ordinal)
            || provider.is_none()
            || provider.is_some_and(|value| {
                value.soname() != requirement.file_name
                    || value.evidence_hash() != requirement.provider_evidence_hash
            })
            || usize::from(requirement.auxiliary_count) != requirement.auxiliaries.len()
            || requirement.auxiliaries.is_empty()
            || requirement.auxiliaries.len()
                > usize::from(X64_TAIL_WORKER_ROOT_VERSION_MAX_AUX_PER_REQUIREMENT)
            || root_version_requirement_evidence_hash(requirement) != requirement.evidence_hash
        {
            return Err(X64TailWorkerRootVersionError::EvidenceMismatch);
        }
        for (auxiliary_ordinal, auxiliary) in requirement.auxiliaries.iter().enumerate() {
            if auxiliary.ordinal != u16::try_from(auxiliary_ordinal).unwrap_or(u16::MAX)
                || (auxiliary.flags != 0 && auxiliary.flags != VER_FLG_WEAK)
                || !(2..=0x7fff).contains(&auxiliary.version_index)
                || !version_indices.insert(auxiliary.version_index)
                || elf_hash(auxiliary.name.as_bytes()) != auxiliary.name_hash
                || root_version_aux_evidence_hash(auxiliary) != auxiliary.evidence_hash
            {
                return Err(X64TailWorkerRootVersionError::EvidenceMismatch);
            }
        }
    }
    if total_auxiliaries != evidence.auxiliary_count {
        return Err(X64TailWorkerRootVersionError::EvidenceMismatch);
    }
    Ok(())
}

fn map_virtual_readonly_record<'bytes>(
    bytes: &'bytes [u8],
    loads: &[LoadSegment],
    address: u64,
    size: u64,
    field: &'static str,
) -> Result<(&'bytes [u8], u64), X64TailWorkerRootVersionError> {
    let end = address
        .checked_add(size)
        .ok_or(X64TailWorkerRootVersionError::Overflow(field))?;
    let mut matches = loads.iter().filter(|load| {
        load.flags & PF_W == 0
            && address >= load.virtual_address
            && load
                .virtual_address
                .checked_add(load.file_size)
                .is_some_and(|load_end| end <= load_end)
    });
    let load = matches
        .next()
        .ok_or(X64TailWorkerRootVersionError::Invalid(field))?;
    if matches.next().is_some() {
        return Err(X64TailWorkerRootVersionError::Invalid(
            "ambiguous read-only virtual mapping",
        ));
    }
    let file_offset = load
        .file_offset
        .checked_add(address - load.virtual_address)
        .ok_or(X64TailWorkerRootVersionError::Overflow(field))?;
    Ok((slice_range(bytes, file_offset, size, field)?, file_offset))
}

fn map_virtual_readonly_range<'bytes>(
    bytes: &'bytes [u8],
    loads: &[LoadSegment],
    address: u64,
    size: u64,
) -> Result<&'bytes [u8], X64TailWorkerRootVersionError> {
    map_virtual_readonly_record(bytes, loads, address, size, "dynamic string table")
        .map(|(value, _)| value)
}

fn claim_record_range(
    occupied: &mut Vec<(u64, u64)>,
    offset: u64,
    size: u64,
) -> Result<(), X64TailWorkerRootVersionError> {
    let end = offset
        .checked_add(size)
        .ok_or(X64TailWorkerRootVersionError::Overflow(
            "version record range",
        ))?;
    if occupied
        .iter()
        .any(|(existing_start, existing_end)| offset < *existing_end && *existing_start < end)
    {
        return Err(X64TailWorkerRootVersionError::Invalid(
            "overlapping version records",
        ));
    }
    occupied.push((offset, end));
    Ok(())
}

fn validate_relative_offset(
    offset: u32,
    field: &'static str,
) -> Result<(), X64TailWorkerRootVersionError> {
    if offset < 16 || !offset.is_multiple_of(4) {
        return Err(X64TailWorkerRootVersionError::Invalid(field));
    }
    Ok(())
}

fn validate_chain_next(
    offset: u32,
    is_last: bool,
    field: &'static str,
) -> Result<(), X64TailWorkerRootVersionError> {
    if (is_last && offset != 0) || (!is_last && (offset < 16 || !offset.is_multiple_of(4))) {
        return Err(X64TailWorkerRootVersionError::Invalid(field));
    }
    Ok(())
}

fn decode_string_at(
    strings: &[u8],
    string_bytes: u64,
    offset: u64,
    field: &'static str,
) -> Result<String, X64TailWorkerRootVersionError> {
    if offset >= string_bytes {
        return Err(X64TailWorkerRootVersionError::Invalid(field));
    }
    let start =
        usize::try_from(offset).map_err(|_| X64TailWorkerRootVersionError::Overflow(field))?;
    let retained = usize::from(X64_TAIL_WORKER_ROOT_VERSION_MAX_NAME_BYTES)
        .min(strings.len().saturating_sub(start));
    let value = &strings[start..start + retained];
    let end = value
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(X64TailWorkerRootVersionError::Invalid(field))?;
    let name = &value[..end];
    if name.is_empty()
        || name.iter().any(|byte| !(0x21..=0x7e).contains(byte))
        || name.contains(&b'/')
        || name.contains(&b'\\')
    {
        return Err(X64TailWorkerRootVersionError::Invalid(field));
    }
    std::str::from_utf8(name)
        .map(str::to_owned)
        .map_err(|_| X64TailWorkerRootVersionError::Invalid(field))
}

fn elf_hash(name: &[u8]) -> u32 {
    let mut hash = 0u32;
    for byte in name {
        hash = hash.wrapping_shl(4).wrapping_add(u32::from(*byte));
        let high = hash & 0xf000_0000;
        if high != 0 {
            hash ^= high >> 24;
        }
        hash &= !high;
    }
    hash
}

fn require_range(
    bytes: &[u8],
    offset: u64,
    size: u64,
    field: &'static str,
) -> Result<(), X64TailWorkerRootVersionError> {
    let end = offset
        .checked_add(size)
        .ok_or(X64TailWorkerRootVersionError::Overflow(field))?;
    if end > u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
        return Err(X64TailWorkerRootVersionError::Invalid(field));
    }
    Ok(())
}

fn slice_range<'bytes>(
    bytes: &'bytes [u8],
    offset: u64,
    size: u64,
    field: &'static str,
) -> Result<&'bytes [u8], X64TailWorkerRootVersionError> {
    require_range(bytes, offset, size, field)?;
    let start =
        usize::try_from(offset).map_err(|_| X64TailWorkerRootVersionError::Overflow(field))?;
    let end = usize::try_from(offset + size)
        .map_err(|_| X64TailWorkerRootVersionError::Overflow(field))?;
    Ok(&bytes[start..end])
}

fn read_u16(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<u16, X64TailWorkerRootVersionError> {
    let value = slice_range(bytes, offset, 2, field)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<u32, X64TailWorkerRootVersionError> {
    let value = slice_range(bytes, offset, 4, field)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<u64, X64TailWorkerRootVersionError> {
    let value = slice_range(bytes, offset, 8, field)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn read_i64(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<i64, X64TailWorkerRootVersionError> {
    Ok(read_u64(bytes, offset, field)? as i64)
}

fn set_once(
    slot: &mut Option<u64>,
    value: u64,
    field: &'static str,
) -> Result<(), X64TailWorkerRootVersionError> {
    if slot.replace(value).is_some() {
        Err(X64TailWorkerRootVersionError::Invalid(field))
    } else {
        Ok(())
    }
}

pub fn x64_tail_worker_root_version_policy_hash() -> SemanticHash {
    let mut bytes = Vec::with_capacity(768);
    bytes.extend_from_slice(POLICY_DOMAIN);
    put_version(&mut bytes, X64_TAIL_WORKER_ROOT_VERSION_SCHEMA_VERSION);
    put_version(&mut bytes, X64_TAIL_WORKER_ROOT_VERSION_POLICY_VERSION);
    put_hash(&mut bytes, X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT);
    put_hash(&mut bytes, X64_TAIL_WORKER_ELF_POLICY_ROOT);
    put_hash(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_ADMISSION_POLICY_ROOT);
    put_hash(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT);
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_VERSION_MAX_PROGRAM_HEADERS);
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_VERSION_MAX_LOAD_SEGMENTS);
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_VERSION_MAX_DYNAMIC_ENTRIES);
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_VERSION_MAX_REQUIREMENTS);
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_ROOT_VERSION_MAX_AUX_PER_REQUIREMENT,
    );
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_VERSION_MAX_TOTAL_AUX);
    put_u64(
        &mut bytes,
        X64_TAIL_WORKER_ROOT_VERSION_MAX_STRING_TABLE_BYTES,
    );
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_VERSION_MAX_NAME_BYTES);
    put_u16(&mut bytes, ELF_HEADER_BYTES);
    put_u16(&mut bytes, PROGRAM_HEADER_BYTES);
    put_u64(&mut bytes, DYNAMIC_ENTRY_BYTES);
    put_u64(&mut bytes, VERNEED_BYTES);
    put_u64(&mut bytes, VERNAUX_BYTES);
    put_u16(&mut bytes, ET_DYN);
    put_u16(&mut bytes, EM_X86_64);
    put_u32(&mut bytes, PT_LOAD);
    put_u32(&mut bytes, PT_DYNAMIC);
    put_u32(&mut bytes, PF_W);
    put_i64(&mut bytes, DT_NULL);
    put_i64(&mut bytes, DT_STRTAB);
    put_i64(&mut bytes, DT_STRSZ);
    put_i64(&mut bytes, DT_VERNEED);
    put_i64(&mut bytes, DT_VERNEEDNUM);
    put_u16(&mut bytes, VERNEED_CURRENT);
    put_u16(&mut bytes, VER_FLG_WEAK);
    put_u16(
        &mut bytes,
        u16::try_from(POLICY_CAPABILITIES.len()).unwrap_or(u16::MAX),
    );
    for capability in POLICY_CAPABILITIES {
        put_string(&mut bytes, capability);
    }
    SemanticHash(sha256(&bytes))
}

fn root_version_aux_evidence_hash(evidence: &X64TailWorkerRootVersionAuxEvidence) -> SemanticHash {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(AUX_DOMAIN);
    put_u16(&mut bytes, evidence.ordinal);
    put_u64(&mut bytes, evidence.file_offset);
    put_u32(&mut bytes, evidence.name_hash);
    put_u16(&mut bytes, evidence.flags);
    put_u16(&mut bytes, evidence.version_index);
    put_u32(&mut bytes, evidence.name_offset);
    put_string(&mut bytes, &evidence.name);
    put_u32(&mut bytes, evidence.next_offset);
    SemanticHash(sha256(&bytes))
}

fn root_version_requirement_evidence_hash(
    evidence: &X64TailWorkerRootVersionRequirementEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(REQUIREMENT_DOMAIN);
    put_u16(&mut bytes, evidence.ordinal);
    put_u64(&mut bytes, evidence.file_offset);
    put_u16(&mut bytes, evidence.version);
    put_u32(&mut bytes, evidence.file_name_offset);
    put_string(&mut bytes, &evidence.file_name);
    put_u16(&mut bytes, evidence.declaration_ordinal);
    put_u16(&mut bytes, evidence.provider_ordinal);
    put_hash(&mut bytes, evidence.provider_evidence_hash);
    put_u16(&mut bytes, evidence.auxiliary_count);
    put_u32(&mut bytes, evidence.aux_offset);
    put_u32(&mut bytes, evidence.next_offset);
    put_u16(
        &mut bytes,
        u16::try_from(evidence.auxiliaries.len()).unwrap_or(u16::MAX),
    );
    for auxiliary in &evidence.auxiliaries {
        put_hash(&mut bytes, auxiliary.evidence_hash);
    }
    SemanticHash(sha256(&bytes))
}

pub fn x64_tail_worker_root_version_evidence_hash(
    evidence: &X64TailWorkerRootVersionEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(640);
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_hash(&mut bytes, evidence.policy_hash);
    put_hash(&mut bytes, evidence.artifact_policy_hash);
    put_hash(&mut bytes, evidence.artifact_expectation_hash);
    put_hash(&mut bytes, evidence.artifact_hash);
    put_hash(&mut bytes, evidence.inventory_policy_hash);
    put_hash(&mut bytes, evidence.inventory_evidence_hash);
    put_hash(&mut bytes, evidence.declaration_policy_hash);
    put_hash(&mut bytes, evidence.declaration_expectation_hash);
    put_hash(&mut bytes, evidence.declaration_evidence_hash);
    put_hash(&mut bytes, evidence.closure_policy_hash);
    put_hash(&mut bytes, evidence.closure_evidence_hash);
    put_u16(&mut bytes, evidence.requirement_count);
    put_u16(&mut bytes, evidence.auxiliary_count);
    for requirement in &evidence.requirements {
        put_hash(&mut bytes, requirement.evidence_hash);
    }
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

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_i64(bytes: &mut Vec<u8>, value: i64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn probe_x64_tail_worker_root_version_decoder_mutations(
    bytes: &[u8],
    declaration: &X64TailWorkerDependencyExpectation,
    closure: &X64TailWorkerDependencyClosureEvidence,
) -> bool {
    if decode_root_versions(bytes, declaration, closure).is_err() {
        return false;
    }
    let Ok((loads, dynamic)) = decode_layout(bytes) else {
        return false;
    };
    let Ok((_, _, Some(version_address), version_count)) =
        decode_dynamic_version_tags(bytes, &dynamic)
    else {
        return false;
    };
    let Ok((first, first_file_offset)) = map_virtual_readonly_record(
        bytes,
        &loads,
        version_address,
        VERNEED_BYTES,
        "probe Verneed",
    ) else {
        return false;
    };
    let Ok(aux_offset) = read_u32(first, 8, "probe vn_aux") else {
        return false;
    };
    let Some(aux_address) = version_address.checked_add(u64::from(aux_offset)) else {
        return false;
    };
    let Ok((_, first_aux_file_offset)) =
        map_virtual_readonly_record(bytes, &loads, aux_address, VERNAUX_BYTES, "probe Vernaux")
    else {
        return false;
    };
    let Some(version_tag) = find_dynamic_tag_offset(bytes, &dynamic, DT_VERNEED) else {
        return false;
    };
    let Some(version_count_tag) = find_dynamic_tag_offset(bytes, &dynamic, DT_VERNEEDNUM) else {
        return false;
    };
    let first_aux_count = read_u16(bytes, first_file_offset + 2, "probe vn_cnt").unwrap_or(0);
    let first_file_name_offset =
        read_u32(bytes, first_file_offset + 4, "probe vn_file").unwrap_or(0);
    let first_next = read_u32(bytes, first_file_offset + 12, "probe vn_next").unwrap_or(0);
    let second_file_offset = (version_count > 1 && first_next != 0)
        .then(|| version_address.checked_add(u64::from(first_next)))
        .flatten()
        .and_then(|address| {
            map_virtual_readonly_record(bytes, &loads, address, VERNEED_BYTES, "probe second")
                .ok()
                .map(|(_, offset)| offset)
        });
    [
        root_decoder_mutation_rejected(bytes, declaration, closure, |value| {
            write_i64(value, version_tag, 0x1234)
        }),
        root_decoder_mutation_rejected(bytes, declaration, closure, |value| {
            write_u64(
                value,
                version_count_tag + 8,
                u64::from(X64_TAIL_WORKER_ROOT_VERSION_MAX_REQUIREMENTS) + 1,
            )
        }),
        root_decoder_mutation_rejected(bytes, declaration, closure, |value| {
            write_u16(value, first_file_offset, VERNEED_CURRENT + 1)
        }),
        root_decoder_mutation_rejected(bytes, declaration, closure, |value| {
            write_u16(value, first_file_offset + 2, 0)
        }),
        root_decoder_mutation_rejected(bytes, declaration, closure, |value| {
            write_u32(value, first_file_offset + 4, u32::MAX)
        }),
        second_file_offset.is_some_and(|second| {
            root_decoder_mutation_rejected(bytes, declaration, closure, |value| {
                write_u32(value, second + 4, first_file_name_offset)
            })
        }),
        root_decoder_mutation_rejected(bytes, declaration, closure, |value| {
            write_u32(value, first_file_offset + 8, 0)
        }),
        root_decoder_mutation_rejected(bytes, declaration, closure, |value| {
            let current = read_u32(value, first_aux_file_offset, "probe hash").unwrap_or(0);
            write_u32(value, first_aux_file_offset, current ^ 1)
        }),
        root_decoder_mutation_rejected(bytes, declaration, closure, |value| {
            write_u16(value, first_aux_file_offset + 4, 1)
        }),
        root_decoder_mutation_rejected(bytes, declaration, closure, |value| {
            write_u16(value, first_aux_file_offset + 6, 1)
        }),
        root_decoder_mutation_rejected(bytes, declaration, closure, |value| {
            write_u32(value, first_aux_file_offset + 8, u32::MAX)
        }),
        root_decoder_mutation_rejected(bytes, declaration, closure, |value| {
            if first_aux_count > 1 {
                write_u32(value, first_aux_file_offset + 12, 0);
            } else if version_count > 1 {
                write_u32(value, first_file_offset + 12, 0);
            } else {
                write_u32(value, first_aux_file_offset + 12, 16);
            }
        }),
    ]
    .into_iter()
    .all(|rejected| rejected)
}

#[cfg(debug_assertions)]
fn root_decoder_mutation_rejected(
    bytes: &[u8],
    declaration: &X64TailWorkerDependencyExpectation,
    closure: &X64TailWorkerDependencyClosureEvidence,
    mutate: impl FnOnce(&mut [u8]),
) -> bool {
    let mut mutation = bytes.to_vec();
    mutate(&mut mutation);
    decode_root_versions(&mutation, declaration, closure).is_err()
}

#[cfg(debug_assertions)]
fn find_dynamic_tag_offset(bytes: &[u8], dynamic: &DynamicSegment, wanted: i64) -> Option<u64> {
    let count = dynamic.file_size / DYNAMIC_ENTRY_BYTES;
    (0..count).find_map(|ordinal| {
        let offset = dynamic
            .file_offset
            .checked_add(ordinal * DYNAMIC_ENTRY_BYTES)?;
        (read_i64(bytes, offset, "probe dynamic tag").ok()? == wanted).then_some(offset)
    })
}

#[cfg(debug_assertions)]
fn write_u16(bytes: &mut [u8], offset: u64, value: u16) {
    if let Ok(offset) = usize::try_from(offset) {
        if let Some(target) = bytes.get_mut(offset..offset.saturating_add(2)) {
            target.copy_from_slice(&value.to_le_bytes());
        }
    }
}

#[cfg(debug_assertions)]
fn write_u32(bytes: &mut [u8], offset: u64, value: u32) {
    if let Ok(offset) = usize::try_from(offset) {
        if let Some(target) = bytes.get_mut(offset..offset.saturating_add(4)) {
            target.copy_from_slice(&value.to_le_bytes());
        }
    }
}

#[cfg(debug_assertions)]
fn write_u64(bytes: &mut [u8], offset: u64, value: u64) {
    if let Ok(offset) = usize::try_from(offset) {
        if let Some(target) = bytes.get_mut(offset..offset.saturating_add(8)) {
            target.copy_from_slice(&value.to_le_bytes());
        }
    }
}

#[cfg(debug_assertions)]
fn write_i64(bytes: &mut [u8], offset: u64, value: i64) {
    write_u64(bytes, offset, value as u64);
}

#[cfg(debug_assertions)]
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn probe_x64_tail_worker_root_version_mutations(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure: &X64TailWorkerDependencyClosureEvidence,
    evidence: &X64TailWorkerRootVersionEvidence,
) -> bool {
    if evidence.requirements.is_empty() || evidence.requirements[0].auxiliaries.is_empty() {
        return false;
    }
    let mut stale_policy = evidence.clone();
    stale_policy.policy_hash.0[0] ^= 1;
    let mut stale_closure = evidence.clone();
    stale_closure.closure_evidence_hash.0[0] ^= 1;
    let mut stale_count = evidence.clone();
    stale_count.auxiliary_count = stale_count.auxiliary_count.saturating_add(1);
    let mut stale_requirement = evidence.clone();
    stale_requirement.requirements[0].file_name.push('x');
    let mut stale_auxiliary = evidence.clone();
    stale_auxiliary.requirements[0].auxiliaries[0]
        .name
        .push('x');
    let shallow_rejected = [
        stale_policy,
        stale_closure,
        stale_count,
        stale_requirement,
        stale_auxiliary,
    ]
    .iter()
    .all(|mutation| {
        verify_x64_tail_worker_root_version_evidence(
            artifact,
            inventory,
            declaration,
            declaration_evidence,
            manifest,
            object_set,
            dynamic_evidence,
            closure_expectation,
            closure,
            mutation,
        )
        .is_err()
    });

    let original = &evidence.requirements[0];
    let alternate = declaration
        .dependencies()
        .iter()
        .enumerate()
        .find(|(_, name)| name.as_str() != original.file_name)
        .and_then(|(declaration_ordinal, name)| {
            let provider_ordinal = unique_provider_ordinal(closure, name)?;
            Some((
                u16::try_from(declaration_ordinal).ok()?,
                name.clone(),
                provider_ordinal,
                closure.providers()[usize::from(provider_ordinal)].evidence_hash(),
            ))
        });
    let Some((declaration_ordinal, file_name, provider_ordinal, provider_evidence_hash)) =
        alternate
    else {
        return false;
    };
    let mut resealed = evidence.clone();
    let requirement = &mut resealed.requirements[0];
    requirement.file_name = file_name;
    requirement.declaration_ordinal = declaration_ordinal;
    requirement.provider_ordinal = provider_ordinal;
    requirement.provider_evidence_hash = provider_evidence_hash;
    requirement.evidence_hash = root_version_requirement_evidence_hash(requirement);
    resealed.evidence_hash = x64_tail_worker_root_version_evidence_hash(&resealed);
    let resealed_rejected = verify_x64_tail_worker_root_version_evidence(
        artifact,
        inventory,
        declaration,
        declaration_evidence,
        manifest,
        object_set,
        dynamic_evidence,
        closure_expectation,
        closure,
        &resealed,
    )
    .is_err();
    shallow_rejected && resealed_rejected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_version_policy_root_is_frozen() {
        let actual = x64_tail_worker_root_version_policy_hash();
        assert_eq!(actual, X64_TAIL_WORKER_ROOT_VERSION_POLICY_ROOT, "{actual}");
    }

    #[test]
    fn production_module_has_no_forbidden_authority() {
        let source = include_str!("x64_tail_worker_root_versions.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        for forbidden in [
            "std::fs",
            "std::path",
            "std::process",
            "readelf",
            "section_header",
            "dependency_definitions::",
            "dependency_symbols::",
            "Command::",
            "Instant::now",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden authority: {forbidden}"
            );
        }
    }
}
