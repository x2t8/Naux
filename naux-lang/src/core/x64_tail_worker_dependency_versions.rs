//! ADR-0076 proof-only GNU symbol-version requirement inventory.
//!
//! The decoder reads only independently verified ADR-0073 sealed bytes after
//! replaying ADR-0075. It inventories `Verneed`/`Vernaux` requirements but
//! never resolves a version definition, symbol, relocation, path, or loader.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_worker_artifact::X64TailWorkerArtifact;
use super::x64_tail_worker_dependency_admission::{
    X64TailWorkerDependencyAdmissionEvidence, X64TailWorkerDependencyExpectation,
};
use super::x64_tail_worker_dependency_closure::{
    verify_x64_tail_worker_dependency_closure, X64TailWorkerDependencyClosureError,
    X64TailWorkerDependencyClosureEvidence, X64TailWorkerDependencyClosureExpectation,
    X64TailWorkerDependencyClosureProviderEvidence, X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT,
};
use super::x64_tail_worker_dependency_dynamic::X64TailWorkerDependencyDynamicEvidence;
use super::x64_tail_worker_dependency_objects::{
    verify_x64_tail_worker_dependency_objects, x64_tail_worker_dependency_object_bytes,
    X64TailWorkerDependencyObjectError, X64TailWorkerDependencyObjectManifest,
    X64TailWorkerDependencyObjectSet,
};
use super::x64_tail_worker_elf::X64TailWorkerElfEvidence;
use std::collections::BTreeSet;
use std::fmt;

pub const X64_TAIL_WORKER_DEPENDENCY_VERSION_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_PROVIDERS: u16 = 65;
pub const X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_PROGRAM_HEADERS: u16 = 64;
pub const X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_LOAD_SEGMENTS: u16 = 16;
pub const X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_DYNAMIC_ENTRIES: u16 = 4_096;
pub const X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_REQUIREMENTS: u16 = 64;
pub const X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_AUX_PER_REQUIREMENT: u16 = 64;
pub const X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_TOTAL_AUX: u16 = 4_096;
pub const X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_STRING_TABLE_BYTES: u64 = 1024 * 1024;
pub const X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_NAME_BYTES: u16 = 256;
pub const X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_ROOT: SemanticHash = SemanticHash([
    0x7c, 0x27, 0x8c, 0xc0, 0xcd, 0xf4, 0x0c, 0xc4, 0x15, 0xce, 0xa9, 0x18, 0x39, 0x43, 0x4d, 0xfb,
    0x4b, 0xcb, 0xd5, 0x30, 0x5d, 0x2a, 0x6b, 0x73, 0xeb, 0x2c, 0xc4, 0x1c, 0x22, 0xe4, 0x5b, 0x32,
]);

const POLICY_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-version-policy:v1\0";
const AUX_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-version-aux:v1\0";
const REQUIREMENT_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-version-requirement:v1\0";
const OBJECT_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-version-object:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-version-evidence:v1\0";
const POLICY_CAPABILITIES: &[&str] = &[
    "opaque-verified-adr0073-byte-source-v1",
    "full-adr0075-closure-replay-v1",
    "independent-elf64-x86-64-layout-decoder-v1",
    "paired-bounded-verneed-tag-inventory-v1",
    "ordered-nonoverlapping-verneed-vernaux-chain-v1",
    "exact-file-provider-and-needed-membership-binding-v1",
    "sovereign-elf-version-name-hash-validation-v1",
    "bounded-supported-version-flags-and-indices-v1",
    "domain-separated-record-and-aggregate-replay-v1",
    "proof-only-no-version-definition-symbol-resolution-or-execution-v1",
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
const DT_NULL: i64 = 0;
const DT_STRTAB: i64 = 5;
const DT_STRSZ: i64 = 10;
const DT_VERNEED: i64 = 0x6fff_fffe;
const DT_VERNEEDNUM: i64 = 0x6fff_ffff;
const VERNEED_CURRENT: u16 = 1;
const VER_FLG_WEAK: u16 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyVersionAuxEvidence {
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

impl X64TailWorkerDependencyVersionAuxEvidence {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
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
pub struct X64TailWorkerDependencyVersionRequirementEvidence {
    ordinal: u16,
    file_offset: u64,
    version: u16,
    file_name_offset: u32,
    file_name: String,
    provider_ordinal: u16,
    aux_offset: u32,
    next_offset: u32,
    auxiliaries: Vec<X64TailWorkerDependencyVersionAuxEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerDependencyVersionRequirementEvidence {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    pub const fn provider_ordinal(&self) -> u16 {
        self.provider_ordinal
    }

    pub fn auxiliaries(&self) -> &[X64TailWorkerDependencyVersionAuxEvidence] {
        &self.auxiliaries
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyVersionObjectEvidence {
    provider_ordinal: u16,
    source_object_ordinal: u16,
    closure_provider_evidence_hash: SemanticHash,
    object_hash: SemanticHash,
    soname: String,
    requirement_count: u16,
    auxiliary_count: u16,
    requirements: Vec<X64TailWorkerDependencyVersionRequirementEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerDependencyVersionObjectEvidence {
    pub const fn provider_ordinal(&self) -> u16 {
        self.provider_ordinal
    }

    pub fn soname(&self) -> &str {
        &self.soname
    }

    pub const fn requirement_count(&self) -> u16 {
        self.requirement_count
    }

    pub const fn auxiliary_count(&self) -> u16 {
        self.auxiliary_count
    }

    pub fn requirements(&self) -> &[X64TailWorkerDependencyVersionRequirementEvidence] {
        &self.requirements
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyVersionEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    policy_hash: SemanticHash,
    closure_policy_hash: SemanticHash,
    closure_evidence_hash: SemanticHash,
    object_set_evidence_hash: SemanticHash,
    provider_count: u16,
    total_requirements: u16,
    total_auxiliaries: u16,
    objects: Vec<X64TailWorkerDependencyVersionObjectEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerDependencyVersionEvidence {
    pub const fn policy_hash(&self) -> SemanticHash {
        self.policy_hash
    }

    pub const fn closure_evidence_hash(&self) -> SemanticHash {
        self.closure_evidence_hash
    }

    pub const fn provider_count(&self) -> u16 {
        self.provider_count
    }

    pub const fn total_requirements(&self) -> u16 {
        self.total_requirements
    }

    pub const fn total_auxiliaries(&self) -> u16 {
        self.total_auxiliaries
    }

    pub fn objects(&self) -> &[X64TailWorkerDependencyVersionObjectEvidence] {
        &self.objects
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailWorkerDependencyVersions<'evidence> {
    evidence: &'evidence X64TailWorkerDependencyVersionEvidence,
}

impl<'evidence> VerifiedX64TailWorkerDependencyVersions<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64TailWorkerDependencyVersionEvidence {
        self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailWorkerDependencyVersionError {
    Closure(X64TailWorkerDependencyClosureError),
    Objects(X64TailWorkerDependencyObjectError),
    Invalid(&'static str),
    Limit {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    Overflow(&'static str),
    EvidenceMismatch,
}

impl fmt::Display for X64TailWorkerDependencyVersionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closure(error) => write!(formatter, "ADR-0076 closure failed: {error}"),
            Self::Objects(error) => write!(formatter, "ADR-0076 objects failed: {error}"),
            Self::Invalid(field) => write!(formatter, "invalid ADR-0076 {field}"),
            Self::Limit {
                field,
                limit,
                actual,
            } => write!(formatter, "ADR-0076 {field} {actual} exceeds limit {limit}"),
            Self::Overflow(field) => write!(formatter, "ADR-0076 {field} overflow"),
            Self::EvidenceMismatch => formatter.write_str("ADR-0076 evidence mismatch"),
        }
    }
}

impl std::error::Error for X64TailWorkerDependencyVersionError {}

impl From<X64TailWorkerDependencyClosureError> for X64TailWorkerDependencyVersionError {
    fn from(value: X64TailWorkerDependencyClosureError) -> Self {
        Self::Closure(value)
    }
}

impl From<X64TailWorkerDependencyObjectError> for X64TailWorkerDependencyVersionError {
    fn from(value: X64TailWorkerDependencyObjectError) -> Self {
        Self::Objects(value)
    }
}

struct LoadSegment {
    file_offset: u64,
    virtual_address: u64,
    file_size: u64,
}

struct DynamicSegment {
    file_offset: u64,
    file_size: u64,
}

#[allow(clippy::too_many_arguments)]
pub fn emit_x64_tail_worker_dependency_version_evidence(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure_evidence: &X64TailWorkerDependencyClosureEvidence,
) -> Result<X64TailWorkerDependencyVersionEvidence, X64TailWorkerDependencyVersionError> {
    if x64_tail_worker_dependency_version_policy_hash()
        != X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_ROOT
    {
        return Err(X64TailWorkerDependencyVersionError::Invalid("policy root"));
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
    let verified_objects = verify_x64_tail_worker_dependency_objects(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
    )?;
    if closure_evidence.providers().len()
        > usize::from(X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_PROVIDERS)
    {
        return Err(X64TailWorkerDependencyVersionError::Limit {
            field: "providers",
            limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_PROVIDERS),
            actual: u64::try_from(closure_evidence.providers().len()).unwrap_or(u64::MAX),
        });
    }

    let mut objects = Vec::with_capacity(closure_evidence.providers().len());
    let mut total_requirements = 0u16;
    let mut total_auxiliaries = 0u16;
    for provider in closure_evidence.providers() {
        let source_ordinal = provider.source_object_ordinals().first().copied().ok_or(
            X64TailWorkerDependencyVersionError::Invalid("provider source ordinal"),
        )?;
        let object = object_set
            .evidence()
            .objects()
            .get(usize::from(source_ordinal))
            .ok_or(X64TailWorkerDependencyVersionError::Invalid(
                "provider source object",
            ))?;
        if object.object_hash() != provider.object_hash() {
            return Err(X64TailWorkerDependencyVersionError::EvidenceMismatch);
        }
        let bytes = x64_tail_worker_dependency_object_bytes(&verified_objects, source_ordinal)?;
        let decoded = decode_version_object(
            &bytes,
            source_ordinal,
            object.object_hash(),
            provider,
            closure_evidence.providers(),
        )?;
        total_requirements = total_requirements
            .checked_add(decoded.requirement_count)
            .ok_or(X64TailWorkerDependencyVersionError::Overflow(
                "total requirements",
            ))?;
        total_auxiliaries = total_auxiliaries
            .checked_add(decoded.auxiliary_count)
            .ok_or(X64TailWorkerDependencyVersionError::Overflow(
                "total auxiliaries",
            ))?;
        if total_auxiliaries > X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_TOTAL_AUX {
            return Err(X64TailWorkerDependencyVersionError::Limit {
                field: "total auxiliaries",
                limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_TOTAL_AUX),
                actual: u64::from(total_auxiliaries),
            });
        }
        objects.push(decoded);
    }
    let mut evidence = X64TailWorkerDependencyVersionEvidence {
        schema_version: X64_TAIL_WORKER_DEPENDENCY_VERSION_SCHEMA_VERSION,
        policy_version: X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_VERSION,
        policy_hash: x64_tail_worker_dependency_version_policy_hash(),
        closure_policy_hash: X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT,
        closure_evidence_hash: closure_evidence.evidence_hash(),
        object_set_evidence_hash: object_set.evidence().evidence_hash(),
        provider_count: u16::try_from(objects.len())
            .map_err(|_| X64TailWorkerDependencyVersionError::Overflow("provider count"))?,
        total_requirements,
        total_auxiliaries,
        objects,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = x64_tail_worker_dependency_version_evidence_hash(&evidence);
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_x64_tail_worker_dependency_version_evidence<'evidence>(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure_evidence: &X64TailWorkerDependencyClosureEvidence,
    evidence: &'evidence X64TailWorkerDependencyVersionEvidence,
) -> Result<VerifiedX64TailWorkerDependencyVersions<'evidence>, X64TailWorkerDependencyVersionError>
{
    preflight_version_evidence(object_set, closure_evidence, evidence)?;
    let expected = emit_x64_tail_worker_dependency_version_evidence(
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
        || x64_tail_worker_dependency_version_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerDependencyVersionError::EvidenceMismatch);
    }
    Ok(VerifiedX64TailWorkerDependencyVersions { evidence })
}

fn decode_version_object(
    bytes: &[u8],
    source_object_ordinal: u16,
    object_hash: SemanticHash,
    provider: &X64TailWorkerDependencyClosureProviderEvidence,
    providers: &[X64TailWorkerDependencyClosureProviderEvidence],
) -> Result<X64TailWorkerDependencyVersionObjectEvidence, X64TailWorkerDependencyVersionError> {
    let (loads, dynamic) = decode_layout(bytes)?;
    let (string_address, string_bytes, version_address, version_count) =
        decode_dynamic_version_tags(bytes, &dynamic)?;
    if string_bytes > X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_STRING_TABLE_BYTES {
        return Err(X64TailWorkerDependencyVersionError::Limit {
            field: "string table bytes",
            limit: X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_STRING_TABLE_BYTES,
            actual: string_bytes,
        });
    }
    let strings = map_virtual_file_range(bytes, &loads, string_address, string_bytes)?;
    let mut requirements = Vec::with_capacity(usize::from(version_count));
    let mut occupied = Vec::new();
    let mut version_indices = BTreeSet::new();
    let mut current_address = version_address.unwrap_or(0);
    for ordinal in 0..version_count {
        let (record, file_offset) = map_virtual_file_record(
            bytes,
            &loads,
            current_address,
            VERNEED_BYTES,
            "Verneed record",
        )?;
        claim_record_range(&mut occupied, file_offset, VERNEED_BYTES)?;
        let version = read_u16(record, 0, "vn_version")?;
        let auxiliary_count = read_u16(record, 2, "vn_cnt")?;
        let file_name_offset = read_u32(record, 4, "vn_file")?;
        let aux_offset = read_u32(record, 8, "vn_aux")?;
        let next_offset = read_u32(record, 12, "vn_next")?;
        if version != VERNEED_CURRENT {
            return Err(X64TailWorkerDependencyVersionError::Invalid(
                "Verneed version",
            ));
        }
        if auxiliary_count == 0
            || auxiliary_count > X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_AUX_PER_REQUIREMENT
        {
            return Err(X64TailWorkerDependencyVersionError::Limit {
                field: "Vernaux records",
                limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_AUX_PER_REQUIREMENT),
                actual: u64::from(auxiliary_count),
            });
        }
        validate_relative_offset(aux_offset, "vn_aux")?;
        validate_chain_next(next_offset, ordinal + 1 == version_count, "vn_next")?;
        let file_name = decode_string_at(
            strings,
            string_bytes,
            u64::from(file_name_offset),
            "version requirement file",
        )?;
        if requirements.iter().any(
            |requirement: &X64TailWorkerDependencyVersionRequirementEvidence| {
                requirement.file_name == file_name
            },
        ) {
            return Err(X64TailWorkerDependencyVersionError::Invalid(
                "duplicate version requirement file",
            ));
        }
        if !provider.needed().contains(&file_name) {
            return Err(X64TailWorkerDependencyVersionError::Invalid(
                "version requirement outside DT_NEEDED",
            ));
        }
        let provider_ordinal = providers
            .iter()
            .position(|candidate| candidate.soname() == file_name)
            .ok_or(X64TailWorkerDependencyVersionError::Invalid(
                "version requirement provider",
            ))?;
        if providers
            .iter()
            .filter(|candidate| candidate.soname() == file_name)
            .count()
            != 1
        {
            return Err(X64TailWorkerDependencyVersionError::Invalid(
                "ambiguous version requirement provider",
            ));
        }

        let mut auxiliaries = Vec::with_capacity(usize::from(auxiliary_count));
        let mut auxiliary_names = BTreeSet::new();
        let mut auxiliary_address = current_address
            .checked_add(u64::from(aux_offset))
            .ok_or(X64TailWorkerDependencyVersionError::Overflow("vn_aux"))?;
        for aux_ordinal in 0..auxiliary_count {
            let (auxiliary, auxiliary_file_offset) = map_virtual_file_record(
                bytes,
                &loads,
                auxiliary_address,
                VERNAUX_BYTES,
                "Vernaux record",
            )?;
            claim_record_range(&mut occupied, auxiliary_file_offset, VERNAUX_BYTES)?;
            let name_hash = read_u32(auxiliary, 0, "vna_hash")?;
            let flags = read_u16(auxiliary, 4, "vna_flags")?;
            let version_index = read_u16(auxiliary, 6, "vna_other")?;
            let name_offset = read_u32(auxiliary, 8, "vna_name")?;
            let aux_next_offset = read_u32(auxiliary, 12, "vna_next")?;
            if flags != 0 && flags != VER_FLG_WEAK {
                return Err(X64TailWorkerDependencyVersionError::Invalid(
                    "Vernaux flags",
                ));
            }
            if !(2..=0x7fff).contains(&version_index) || !version_indices.insert(version_index) {
                return Err(X64TailWorkerDependencyVersionError::Invalid(
                    "Vernaux version index",
                ));
            }
            validate_chain_next(
                aux_next_offset,
                aux_ordinal + 1 == auxiliary_count,
                "vna_next",
            )?;
            let name = decode_string_at(
                strings,
                string_bytes,
                u64::from(name_offset),
                "version requirement name",
            )?;
            if !auxiliary_names.insert(name.clone()) {
                return Err(X64TailWorkerDependencyVersionError::Invalid(
                    "duplicate version requirement name",
                ));
            }
            if elf_hash(name.as_bytes()) != name_hash {
                return Err(X64TailWorkerDependencyVersionError::Invalid(
                    "version requirement hash",
                ));
            }
            let mut evidence = X64TailWorkerDependencyVersionAuxEvidence {
                ordinal: aux_ordinal,
                file_offset: auxiliary_file_offset,
                name_hash,
                flags,
                version_index,
                name_offset,
                name,
                next_offset: aux_next_offset,
                evidence_hash: SemanticHash::ZERO,
            };
            evidence.evidence_hash = version_aux_evidence_hash(&evidence);
            auxiliaries.push(evidence);
            if aux_next_offset != 0 {
                auxiliary_address = auxiliary_address
                    .checked_add(u64::from(aux_next_offset))
                    .ok_or(X64TailWorkerDependencyVersionError::Overflow("vna_next"))?;
            }
        }
        let mut evidence = X64TailWorkerDependencyVersionRequirementEvidence {
            ordinal,
            file_offset,
            version,
            file_name_offset,
            file_name,
            provider_ordinal: u16::try_from(provider_ordinal).map_err(|_| {
                X64TailWorkerDependencyVersionError::Overflow("requirement provider ordinal")
            })?,
            aux_offset,
            next_offset,
            auxiliaries,
            evidence_hash: SemanticHash::ZERO,
        };
        evidence.evidence_hash = version_requirement_evidence_hash(&evidence);
        requirements.push(evidence);
        if next_offset != 0 {
            current_address = current_address
                .checked_add(u64::from(next_offset))
                .ok_or(X64TailWorkerDependencyVersionError::Overflow("vn_next"))?;
        }
    }
    let auxiliary_count =
        requirements.iter().try_fold(0u16, |total, requirement| {
            total
                .checked_add(u16::try_from(requirement.auxiliaries.len()).map_err(|_| {
                    X64TailWorkerDependencyVersionError::Overflow("object auxiliaries")
                })?)
                .ok_or(X64TailWorkerDependencyVersionError::Overflow(
                    "object auxiliaries",
                ))
        })?;
    let mut evidence = X64TailWorkerDependencyVersionObjectEvidence {
        provider_ordinal: provider.ordinal(),
        source_object_ordinal,
        closure_provider_evidence_hash: provider.evidence_hash(),
        object_hash,
        soname: provider.soname().to_owned(),
        requirement_count: u16::try_from(requirements.len())
            .map_err(|_| X64TailWorkerDependencyVersionError::Overflow("object requirements"))?,
        auxiliary_count,
        requirements,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = version_object_evidence_hash(&evidence);
    Ok(evidence)
}

fn decode_layout(
    bytes: &[u8],
) -> Result<(Vec<LoadSegment>, DynamicSegment), X64TailWorkerDependencyVersionError> {
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
        return Err(X64TailWorkerDependencyVersionError::Invalid("ELF identity"));
    }
    let program_offset = read_u64(bytes, 32, "program-header offset")?;
    let program_count = read_u16(bytes, 56, "program-header count")?;
    if program_count == 0 || program_count > X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_PROGRAM_HEADERS
    {
        return Err(X64TailWorkerDependencyVersionError::Limit {
            field: "program headers",
            limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_PROGRAM_HEADERS),
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
            .ok_or(X64TailWorkerDependencyVersionError::Overflow(
                "program header",
            ))?;
        let kind = read_u32(bytes, offset, "program-header type")?;
        let file_offset = read_u64(bytes, offset + 8, "segment offset")?;
        let virtual_address = read_u64(bytes, offset + 16, "segment address")?;
        let file_size = read_u64(bytes, offset + 32, "segment file size")?;
        let memory_size = read_u64(bytes, offset + 40, "segment memory size")?;
        if file_size > memory_size {
            return Err(X64TailWorkerDependencyVersionError::Invalid(
                "segment sizes",
            ));
        }
        require_range(bytes, file_offset, file_size, "segment file range")?;
        match kind {
            PT_LOAD => loads.push(LoadSegment {
                file_offset,
                virtual_address,
                file_size,
            }),
            PT_DYNAMIC if dynamic.is_some() => {
                return Err(X64TailWorkerDependencyVersionError::Invalid(
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
    if loads.is_empty()
        || loads.len() > usize::from(X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_LOAD_SEGMENTS)
    {
        return Err(X64TailWorkerDependencyVersionError::Limit {
            field: "load segments",
            limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_LOAD_SEGMENTS),
            actual: u64::try_from(loads.len()).unwrap_or(u64::MAX),
        });
    }
    Ok((
        loads,
        dynamic.ok_or(X64TailWorkerDependencyVersionError::Invalid(
            "missing dynamic segment",
        ))?,
    ))
}

fn decode_dynamic_version_tags(
    bytes: &[u8],
    dynamic: &DynamicSegment,
) -> Result<(u64, u64, Option<u64>, u16), X64TailWorkerDependencyVersionError> {
    if dynamic.file_size == 0 || !dynamic.file_size.is_multiple_of(DYNAMIC_ENTRY_BYTES) {
        return Err(X64TailWorkerDependencyVersionError::Invalid(
            "dynamic segment size",
        ));
    }
    let entry_count = dynamic.file_size / DYNAMIC_ENTRY_BYTES;
    if entry_count > u64::from(X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_DYNAMIC_ENTRIES) {
        return Err(X64TailWorkerDependencyVersionError::Limit {
            field: "dynamic entries",
            limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_DYNAMIC_ENTRIES),
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
            .ok_or(X64TailWorkerDependencyVersionError::Overflow(
                "dynamic entry",
            ))?;
        let tag = read_i64(bytes, offset, "dynamic tag")?;
        let value = read_u64(bytes, offset + 8, "dynamic value")?;
        if terminated {
            if tag != DT_NULL || value != 0 {
                return Err(X64TailWorkerDependencyVersionError::Invalid(
                    "dynamic trailing entries",
                ));
            }
            continue;
        }
        match tag {
            DT_NULL => {
                if value != 0 {
                    return Err(X64TailWorkerDependencyVersionError::Invalid(
                        "dynamic terminator",
                    ));
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
        return Err(X64TailWorkerDependencyVersionError::Invalid(
            "missing dynamic terminator",
        ));
    }
    let string_address = string_address.ok_or(X64TailWorkerDependencyVersionError::Invalid(
        "missing DT_STRTAB",
    ))?;
    let string_bytes = string_bytes.ok_or(X64TailWorkerDependencyVersionError::Invalid(
        "missing DT_STRSZ",
    ))?;
    if string_bytes == 0 {
        return Err(X64TailWorkerDependencyVersionError::Invalid(
            "empty string table",
        ));
    }
    match (version_address, version_count) {
        (None, None) => Ok((string_address, string_bytes, None, 0)),
        (Some(address), Some(count)) => {
            let count =
                u16::try_from(count).map_err(|_| X64TailWorkerDependencyVersionError::Limit {
                    field: "version requirements",
                    limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_REQUIREMENTS),
                    actual: count,
                })?;
            if address == 0
                || count == 0
                || count > X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_REQUIREMENTS
            {
                return Err(X64TailWorkerDependencyVersionError::Limit {
                    field: "version requirements",
                    limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_REQUIREMENTS),
                    actual: u64::from(count),
                });
            }
            Ok((string_address, string_bytes, Some(address), count))
        }
        _ => Err(X64TailWorkerDependencyVersionError::Invalid(
            "unpaired version requirement tags",
        )),
    }
}

fn preflight_version_evidence(
    object_set: &X64TailWorkerDependencyObjectSet,
    closure: &X64TailWorkerDependencyClosureEvidence,
    evidence: &X64TailWorkerDependencyVersionEvidence,
) -> Result<(), X64TailWorkerDependencyVersionError> {
    if evidence.schema_version != X64_TAIL_WORKER_DEPENDENCY_VERSION_SCHEMA_VERSION
        || evidence.policy_version != X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_VERSION
        || evidence.policy_hash != X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_ROOT
        || evidence.policy_hash != x64_tail_worker_dependency_version_policy_hash()
        || evidence.closure_policy_hash != X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT
        || evidence.closure_evidence_hash != closure.evidence_hash()
        || evidence.object_set_evidence_hash != object_set.evidence().evidence_hash()
        || usize::from(evidence.provider_count) != closure.providers().len()
        || evidence.objects.len() != closure.providers().len()
        || evidence.total_auxiliaries > X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_TOTAL_AUX
        || x64_tail_worker_dependency_version_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerDependencyVersionError::EvidenceMismatch);
    }
    let mut total_requirements = 0u16;
    let mut total_auxiliaries = 0u16;
    for (ordinal, (object, provider)) in
        evidence.objects.iter().zip(closure.providers()).enumerate()
    {
        let source_ordinal = provider.source_object_ordinals().first().copied();
        total_requirements = total_requirements
            .checked_add(object.requirement_count)
            .ok_or(X64TailWorkerDependencyVersionError::Overflow(
                "evidence requirements",
            ))?;
        total_auxiliaries = total_auxiliaries
            .checked_add(object.auxiliary_count)
            .ok_or(X64TailWorkerDependencyVersionError::Overflow(
                "evidence auxiliaries",
            ))?;
        if object.provider_ordinal != u16::try_from(ordinal).unwrap_or(u16::MAX)
            || object.provider_ordinal != provider.ordinal()
            || Some(object.source_object_ordinal) != source_ordinal
            || object.closure_provider_evidence_hash != provider.evidence_hash()
            || object.object_hash != provider.object_hash()
            || object.soname != provider.soname()
            || usize::from(object.requirement_count) != object.requirements.len()
            || usize::from(object.auxiliary_count)
                != object
                    .requirements
                    .iter()
                    .map(|requirement| requirement.auxiliaries.len())
                    .sum::<usize>()
            || version_object_evidence_hash(object) != object.evidence_hash
        {
            return Err(X64TailWorkerDependencyVersionError::EvidenceMismatch);
        }
        for (requirement_ordinal, requirement) in object.requirements.iter().enumerate() {
            if requirement.ordinal != u16::try_from(requirement_ordinal).unwrap_or(u16::MAX)
                || requirement.version != VERNEED_CURRENT
                || requirement.provider_ordinal as usize >= closure.providers().len()
                || closure.providers()[usize::from(requirement.provider_ordinal)].soname()
                    != requirement.file_name
                || !provider.needed().contains(&requirement.file_name)
                || requirement.auxiliaries.is_empty()
                || version_requirement_evidence_hash(requirement) != requirement.evidence_hash
            {
                return Err(X64TailWorkerDependencyVersionError::EvidenceMismatch);
            }
            for (aux_ordinal, auxiliary) in requirement.auxiliaries.iter().enumerate() {
                if auxiliary.ordinal != u16::try_from(aux_ordinal).unwrap_or(u16::MAX)
                    || (auxiliary.flags != 0 && auxiliary.flags != VER_FLG_WEAK)
                    || !(2..=0x7fff).contains(&auxiliary.version_index)
                    || elf_hash(auxiliary.name.as_bytes()) != auxiliary.name_hash
                    || version_aux_evidence_hash(auxiliary) != auxiliary.evidence_hash
                {
                    return Err(X64TailWorkerDependencyVersionError::EvidenceMismatch);
                }
            }
        }
    }
    if total_requirements != evidence.total_requirements
        || total_auxiliaries != evidence.total_auxiliaries
    {
        return Err(X64TailWorkerDependencyVersionError::EvidenceMismatch);
    }
    Ok(())
}

fn map_virtual_file_record<'bytes>(
    bytes: &'bytes [u8],
    loads: &[LoadSegment],
    address: u64,
    size: u64,
    field: &'static str,
) -> Result<(&'bytes [u8], u64), X64TailWorkerDependencyVersionError> {
    let end = address
        .checked_add(size)
        .ok_or(X64TailWorkerDependencyVersionError::Overflow(field))?;
    let mut matches = loads.iter().filter(|load| {
        address >= load.virtual_address
            && load
                .virtual_address
                .checked_add(load.file_size)
                .is_some_and(|load_end| end <= load_end)
    });
    let load = matches
        .next()
        .ok_or(X64TailWorkerDependencyVersionError::Invalid(field))?;
    if matches.next().is_some() {
        return Err(X64TailWorkerDependencyVersionError::Invalid(
            "ambiguous virtual mapping",
        ));
    }
    let file_offset = load
        .file_offset
        .checked_add(address - load.virtual_address)
        .ok_or(X64TailWorkerDependencyVersionError::Overflow(field))?;
    Ok((slice_range(bytes, file_offset, size, field)?, file_offset))
}

fn map_virtual_file_range<'bytes>(
    bytes: &'bytes [u8],
    loads: &[LoadSegment],
    address: u64,
    size: u64,
) -> Result<&'bytes [u8], X64TailWorkerDependencyVersionError> {
    map_virtual_file_record(bytes, loads, address, size, "dynamic string table")
        .map(|(value, _)| value)
}

fn claim_record_range(
    occupied: &mut Vec<(u64, u64)>,
    offset: u64,
    size: u64,
) -> Result<(), X64TailWorkerDependencyVersionError> {
    let end = offset
        .checked_add(size)
        .ok_or(X64TailWorkerDependencyVersionError::Overflow(
            "version record range",
        ))?;
    if occupied
        .iter()
        .any(|(existing_start, existing_end)| offset < *existing_end && *existing_start < end)
    {
        return Err(X64TailWorkerDependencyVersionError::Invalid(
            "overlapping version records",
        ));
    }
    occupied.push((offset, end));
    Ok(())
}

fn validate_relative_offset(
    offset: u32,
    field: &'static str,
) -> Result<(), X64TailWorkerDependencyVersionError> {
    if offset < 16 || !offset.is_multiple_of(4) {
        return Err(X64TailWorkerDependencyVersionError::Invalid(field));
    }
    Ok(())
}

fn validate_chain_next(
    offset: u32,
    is_last: bool,
    field: &'static str,
) -> Result<(), X64TailWorkerDependencyVersionError> {
    if (is_last && offset != 0) || (!is_last && (offset < 16 || !offset.is_multiple_of(4))) {
        return Err(X64TailWorkerDependencyVersionError::Invalid(field));
    }
    Ok(())
}

fn decode_string_at(
    strings: &[u8],
    string_bytes: u64,
    offset: u64,
    field: &'static str,
) -> Result<String, X64TailWorkerDependencyVersionError> {
    if offset >= string_bytes {
        return Err(X64TailWorkerDependencyVersionError::Invalid(field));
    }
    let start = usize::try_from(offset)
        .map_err(|_| X64TailWorkerDependencyVersionError::Overflow(field))?;
    let retained = usize::from(X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_NAME_BYTES)
        .min(strings.len().saturating_sub(start));
    let value = &strings[start..start + retained];
    let end = value
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(X64TailWorkerDependencyVersionError::Invalid(field))?;
    let name = &value[..end];
    if name.is_empty()
        || name.iter().any(|byte| !(0x21..=0x7e).contains(byte))
        || name.contains(&b'/')
        || name.contains(&b'\\')
    {
        return Err(X64TailWorkerDependencyVersionError::Invalid(field));
    }
    std::str::from_utf8(name)
        .map(str::to_owned)
        .map_err(|_| X64TailWorkerDependencyVersionError::Invalid(field))
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
) -> Result<(), X64TailWorkerDependencyVersionError> {
    let end = offset
        .checked_add(size)
        .ok_or(X64TailWorkerDependencyVersionError::Overflow(field))?;
    if end > u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
        return Err(X64TailWorkerDependencyVersionError::Invalid(field));
    }
    Ok(())
}

fn slice_range<'bytes>(
    bytes: &'bytes [u8],
    offset: u64,
    size: u64,
    field: &'static str,
) -> Result<&'bytes [u8], X64TailWorkerDependencyVersionError> {
    require_range(bytes, offset, size, field)?;
    let start = usize::try_from(offset)
        .map_err(|_| X64TailWorkerDependencyVersionError::Overflow(field))?;
    let end = usize::try_from(offset + size)
        .map_err(|_| X64TailWorkerDependencyVersionError::Overflow(field))?;
    Ok(&bytes[start..end])
}

fn read_u16(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<u16, X64TailWorkerDependencyVersionError> {
    let value = slice_range(bytes, offset, 2, field)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<u32, X64TailWorkerDependencyVersionError> {
    let value = slice_range(bytes, offset, 4, field)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<u64, X64TailWorkerDependencyVersionError> {
    let value = slice_range(bytes, offset, 8, field)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn read_i64(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<i64, X64TailWorkerDependencyVersionError> {
    Ok(read_u64(bytes, offset, field)? as i64)
}

fn set_once(
    slot: &mut Option<u64>,
    value: u64,
    field: &'static str,
) -> Result<(), X64TailWorkerDependencyVersionError> {
    if slot.replace(value).is_some() {
        Err(X64TailWorkerDependencyVersionError::Invalid(field))
    } else {
        Ok(())
    }
}

pub fn x64_tail_worker_dependency_version_policy_hash() -> SemanticHash {
    let mut bytes = Vec::with_capacity(768);
    bytes.extend_from_slice(POLICY_DOMAIN);
    put_version(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_VERSION_SCHEMA_VERSION,
    );
    put_version(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_VERSION,
    );
    put_hash(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT);
    put_u16(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_PROVIDERS);
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_PROGRAM_HEADERS,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_LOAD_SEGMENTS,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_DYNAMIC_ENTRIES,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_REQUIREMENTS,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_AUX_PER_REQUIREMENT,
    );
    put_u16(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_TOTAL_AUX);
    put_u64(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_STRING_TABLE_BYTES,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_NAME_BYTES,
    );
    put_u16(&mut bytes, ELF_HEADER_BYTES);
    put_u16(&mut bytes, PROGRAM_HEADER_BYTES);
    put_u64(&mut bytes, DYNAMIC_ENTRY_BYTES);
    put_u64(&mut bytes, VERNEED_BYTES);
    put_u64(&mut bytes, VERNAUX_BYTES);
    put_u16(
        &mut bytes,
        u16::try_from(POLICY_CAPABILITIES.len()).unwrap_or(u16::MAX),
    );
    for capability in POLICY_CAPABILITIES {
        put_string(&mut bytes, capability);
    }
    SemanticHash(sha256(&bytes))
}

fn version_aux_evidence_hash(evidence: &X64TailWorkerDependencyVersionAuxEvidence) -> SemanticHash {
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

fn version_requirement_evidence_hash(
    evidence: &X64TailWorkerDependencyVersionRequirementEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(384);
    bytes.extend_from_slice(REQUIREMENT_DOMAIN);
    put_u16(&mut bytes, evidence.ordinal);
    put_u64(&mut bytes, evidence.file_offset);
    put_u16(&mut bytes, evidence.version);
    put_u32(&mut bytes, evidence.file_name_offset);
    put_string(&mut bytes, &evidence.file_name);
    put_u16(&mut bytes, evidence.provider_ordinal);
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

fn version_object_evidence_hash(
    evidence: &X64TailWorkerDependencyVersionObjectEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(384);
    bytes.extend_from_slice(OBJECT_DOMAIN);
    put_u16(&mut bytes, evidence.provider_ordinal);
    put_u16(&mut bytes, evidence.source_object_ordinal);
    put_hash(&mut bytes, evidence.closure_provider_evidence_hash);
    put_hash(&mut bytes, evidence.object_hash);
    put_string(&mut bytes, &evidence.soname);
    put_u16(&mut bytes, evidence.requirement_count);
    put_u16(&mut bytes, evidence.auxiliary_count);
    for requirement in &evidence.requirements {
        put_hash(&mut bytes, requirement.evidence_hash);
    }
    SemanticHash(sha256(&bytes))
}

pub fn x64_tail_worker_dependency_version_evidence_hash(
    evidence: &X64TailWorkerDependencyVersionEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_hash(&mut bytes, evidence.policy_hash);
    put_hash(&mut bytes, evidence.closure_policy_hash);
    put_hash(&mut bytes, evidence.closure_evidence_hash);
    put_hash(&mut bytes, evidence.object_set_evidence_hash);
    put_u16(&mut bytes, evidence.provider_count);
    put_u16(&mut bytes, evidence.total_requirements);
    put_u16(&mut bytes, evidence.total_auxiliaries);
    for object in &evidence.objects {
        put_hash(&mut bytes, object.evidence_hash);
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

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn probe_x64_tail_worker_dependency_version_decoder_mutations(
    bytes: &[u8],
    provider_ordinal: u16,
    closure: &X64TailWorkerDependencyClosureEvidence,
) -> bool {
    let Some(provider) = closure.providers().get(usize::from(provider_ordinal)) else {
        return false;
    };
    if decode_version_object(
        bytes,
        provider.source_object_ordinals()[0],
        provider.object_hash(),
        provider,
        closure.providers(),
    )
    .is_err()
    {
        return false;
    }
    let Ok((loads, dynamic)) = decode_layout(bytes) else {
        return false;
    };
    let Ok((string_address, string_bytes, Some(version_address), version_count)) =
        decode_dynamic_version_tags(bytes, &dynamic)
    else {
        return false;
    };
    let Ok(strings) = map_virtual_file_range(bytes, &loads, string_address, string_bytes) else {
        return false;
    };
    let Some(self_name_offset) = strings
        .windows(provider.soname().len().saturating_add(1))
        .position(|window| {
            window[..provider.soname().len()] == *provider.soname().as_bytes()
                && window[provider.soname().len()] == 0
        })
        .and_then(|offset| u32::try_from(offset).ok())
    else {
        return false;
    };
    let Ok((version, version_file_offset)) = map_virtual_file_record(
        bytes,
        &loads,
        version_address,
        VERNEED_BYTES,
        "probe Verneed",
    ) else {
        return false;
    };
    let Ok(aux_offset) = read_u32(version, 8, "probe vn_aux") else {
        return false;
    };
    let Some(aux_address) = version_address.checked_add(u64::from(aux_offset)) else {
        return false;
    };
    let Ok((_, auxiliary_file_offset)) =
        map_virtual_file_record(bytes, &loads, aux_address, VERNAUX_BYTES, "probe Vernaux")
    else {
        return false;
    };
    let Some(version_tag) = find_dynamic_tag_offset(bytes, &dynamic, DT_VERNEED) else {
        return false;
    };
    let Some(version_count_tag) = find_dynamic_tag_offset(bytes, &dynamic, DT_VERNEEDNUM) else {
        return false;
    };
    let aux_count = read_u16(bytes, version_file_offset + 2, "probe vn_cnt").unwrap_or(0);
    [
        version_decoder_mutation_rejected(bytes, provider, closure, |value| {
            write_i64(value, version_tag, 0x1234)
        }),
        version_decoder_mutation_rejected(bytes, provider, closure, |value| {
            write_u64(
                value,
                version_count_tag + 8,
                u64::from(X64_TAIL_WORKER_DEPENDENCY_VERSION_MAX_REQUIREMENTS) + 1,
            )
        }),
        version_decoder_mutation_rejected(bytes, provider, closure, |value| {
            write_u16(value, version_file_offset, VERNEED_CURRENT + 1)
        }),
        version_decoder_mutation_rejected(bytes, provider, closure, |value| {
            write_u16(value, version_file_offset + 2, 0)
        }),
        version_decoder_mutation_rejected(bytes, provider, closure, |value| {
            write_u32(value, version_file_offset + 4, u32::MAX)
        }),
        version_decoder_mutation_rejected(bytes, provider, closure, |value| {
            write_u32(value, version_file_offset + 4, self_name_offset)
        }),
        version_decoder_mutation_rejected(bytes, provider, closure, |value| {
            write_u32(value, version_file_offset + 8, 0)
        }),
        version_decoder_mutation_rejected(bytes, provider, closure, |value| {
            let current = read_u32(value, auxiliary_file_offset, "probe hash").unwrap_or(0);
            write_u32(value, auxiliary_file_offset, current ^ 1)
        }),
        version_decoder_mutation_rejected(bytes, provider, closure, |value| {
            write_u16(value, auxiliary_file_offset + 4, 1)
        }),
        version_decoder_mutation_rejected(bytes, provider, closure, |value| {
            write_u16(value, auxiliary_file_offset + 6, 1)
        }),
        version_decoder_mutation_rejected(bytes, provider, closure, |value| {
            write_u32(value, auxiliary_file_offset + 8, u32::MAX)
        }),
        version_decoder_mutation_rejected(bytes, provider, closure, |value| {
            if aux_count > 1 {
                write_u32(value, auxiliary_file_offset + 12, 0);
            } else if version_count > 1 {
                write_u32(value, version_file_offset + 12, 0);
            } else {
                write_u32(value, auxiliary_file_offset + 12, 16);
            }
        }),
    ]
    .into_iter()
    .all(|rejected| rejected)
}

#[cfg(debug_assertions)]
fn version_decoder_mutation_rejected(
    bytes: &[u8],
    provider: &X64TailWorkerDependencyClosureProviderEvidence,
    closure: &X64TailWorkerDependencyClosureEvidence,
    mutate: impl FnOnce(&mut [u8]),
) -> bool {
    let mut mutation = bytes.to_vec();
    mutate(&mut mutation);
    decode_version_object(
        &mutation,
        provider.source_object_ordinals()[0],
        provider.object_hash(),
        provider,
        closure.providers(),
    )
    .is_err()
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
pub fn probe_x64_tail_worker_dependency_version_mutations(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure_evidence: &X64TailWorkerDependencyClosureEvidence,
    evidence: &X64TailWorkerDependencyVersionEvidence,
) -> bool {
    let mut stale_policy = evidence.clone();
    stale_policy.policy_hash.0[0] ^= 1;
    let mut stale_closure = evidence.clone();
    stale_closure.closure_evidence_hash.0[0] ^= 1;
    let mut stale_count = evidence.clone();
    stale_count.total_auxiliaries = stale_count.total_auxiliaries.saturating_add(1);
    let mut stale_object = evidence.clone();
    stale_object.objects[0].soname.push('x');
    let mut stale_auxiliary = evidence.clone();
    let Some(auxiliary) = stale_auxiliary
        .objects
        .iter_mut()
        .flat_map(|object| object.requirements.iter_mut())
        .flat_map(|requirement| requirement.auxiliaries.iter_mut())
        .next()
    else {
        return false;
    };
    auxiliary.name.push('x');

    let shallow_rejected = [
        stale_policy,
        stale_closure,
        stale_count,
        stale_object,
        stale_auxiliary,
    ]
    .iter()
    .all(|mutation| {
        verify_x64_tail_worker_dependency_version_evidence(
            artifact,
            inventory,
            declaration_expectation,
            declaration_evidence,
            manifest,
            object_set,
            dynamic_evidence,
            closure_expectation,
            closure_evidence,
            mutation,
        )
        .is_err()
    });

    let mut resealed = evidence.clone();
    let Some((object_ordinal, requirement_ordinal, auxiliary_ordinal)) =
        resealed
            .objects
            .iter()
            .enumerate()
            .find_map(|(object_ordinal, object)| {
                object.requirements.iter().enumerate().find_map(
                    |(requirement_ordinal, requirement)| {
                        (!requirement.auxiliaries.is_empty()).then_some((
                            object_ordinal,
                            requirement_ordinal,
                            0usize,
                        ))
                    },
                )
            })
    else {
        return false;
    };
    let auxiliary = &mut resealed.objects[object_ordinal].requirements[requirement_ordinal]
        .auxiliaries[auxiliary_ordinal];
    auxiliary.name.push('x');
    auxiliary.name_hash = elf_hash(auxiliary.name.as_bytes());
    auxiliary.evidence_hash = version_aux_evidence_hash(auxiliary);
    let requirement = &mut resealed.objects[object_ordinal].requirements[requirement_ordinal];
    requirement.evidence_hash = version_requirement_evidence_hash(requirement);
    let object = &mut resealed.objects[object_ordinal];
    object.evidence_hash = version_object_evidence_hash(object);
    resealed.evidence_hash = x64_tail_worker_dependency_version_evidence_hash(&resealed);
    let resealed_rejected = verify_x64_tail_worker_dependency_version_evidence(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
        dynamic_evidence,
        closure_expectation,
        closure_evidence,
        &resealed,
    )
    .is_err();
    shallow_rejected && resealed_rejected
}
