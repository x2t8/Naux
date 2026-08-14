//! ADR-0077 proof-only GNU symbol-version definition inventory.
//!
//! The decoder reads only independently verified ADR-0073 sealed bytes after
//! replaying ADR-0076. It inventories `Verdef`/`Verdaux` definitions but never
//! matches a requirement, resolves a symbol, relocates, maps, or executes.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_worker_artifact::X64TailWorkerArtifact;
use super::x64_tail_worker_dependency_admission::{
    X64TailWorkerDependencyAdmissionEvidence, X64TailWorkerDependencyExpectation,
};
use super::x64_tail_worker_dependency_closure::{
    X64TailWorkerDependencyClosureError, X64TailWorkerDependencyClosureEvidence,
    X64TailWorkerDependencyClosureExpectation, X64TailWorkerDependencyClosureProviderEvidence,
    X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT,
};
use super::x64_tail_worker_dependency_dynamic::X64TailWorkerDependencyDynamicEvidence;
use super::x64_tail_worker_dependency_objects::{
    verify_x64_tail_worker_dependency_objects, x64_tail_worker_dependency_object_bytes,
    X64TailWorkerDependencyObjectError, X64TailWorkerDependencyObjectManifest,
    X64TailWorkerDependencyObjectSet,
};
use super::x64_tail_worker_dependency_versions::{
    verify_x64_tail_worker_dependency_version_evidence, X64TailWorkerDependencyVersionError,
    X64TailWorkerDependencyVersionEvidence, X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_ROOT,
};
use super::x64_tail_worker_elf::X64TailWorkerElfEvidence;
use std::collections::BTreeSet;
use std::fmt;

pub const X64_TAIL_WORKER_DEPENDENCY_DEFINITION_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_PROVIDERS: u16 = 65;
pub const X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_PROGRAM_HEADERS: u16 = 64;
pub const X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_LOAD_SEGMENTS: u16 = 16;
pub const X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_DYNAMIC_ENTRIES: u16 = 4_096;
pub const X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_DEFINITIONS: u16 = 256;
pub const X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_AUX_PER_DEFINITION: u16 = 64;
pub const X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_TOTAL_AUX: u16 = 8_192;
pub const X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_STRING_TABLE_BYTES: u64 = 1024 * 1024;
pub const X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_NAME_BYTES: u16 = 256;
pub const X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_ROOT: SemanticHash = SemanticHash([
    0xf4, 0x47, 0x53, 0x33, 0x03, 0x53, 0x3a, 0xca, 0x4f, 0x76, 0x1a, 0x20, 0x2a, 0xaf, 0xec, 0xdf,
    0xf1, 0x1a, 0x42, 0x8b, 0x48, 0xaa, 0x3b, 0x51, 0xfa, 0x7b, 0xd8, 0x1c, 0xda, 0x91, 0x72, 0xce,
]);

const POLICY_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-definition-policy:v1\0";
const AUX_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-definition-aux:v1\0";
const DEFINITION_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-definition-record:v1\0";
const OBJECT_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-definition-object:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-definition-evidence:v1\0";
const POLICY_CAPABILITIES: &[&str] = &[
    "opaque-verified-adr0073-byte-source-v1",
    "full-adr0075-closure-replay-v1",
    "full-adr0076-version-requirement-replay-v1",
    "independent-elf64-x86-64-layout-decoder-v1",
    "paired-bounded-verdef-tag-inventory-v1",
    "ordered-nonoverlapping-verdef-verdaux-chain-v1",
    "exact-base-soname-definition-v1",
    "sovereign-primary-name-elf-hash-validation-v1",
    "bounded-unique-definition-name-and-index-inventory-v1",
    "domain-separated-record-and-aggregate-replay-v1",
    "proof-only-no-requirement-matching-symbol-resolution-or-execution-v1",
];

const ELF_HEADER_BYTES: u16 = 64;
const PROGRAM_HEADER_BYTES: u16 = 56;
const DYNAMIC_ENTRY_BYTES: u64 = 16;
const VERDEF_BYTES: u64 = 20;
const VERDAUX_BYTES: u64 = 8;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_STRTAB: i64 = 5;
const DT_STRSZ: i64 = 10;
const DT_VERDEF: i64 = 0x6fff_fffc;
const DT_VERDEFNUM: i64 = 0x6fff_fffd;
const VERDEF_CURRENT: u16 = 1;
const VER_FLG_BASE: u16 = 1;
const VER_FLG_WEAK: u16 = 2;
const VER_NDX_GLOBAL: u16 = 1;
const VER_NDX_LORESERVE: u16 = 0xff00;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyDefinitionAuxEvidence {
    ordinal: u16,
    file_offset: u64,
    name_offset: u32,
    name: String,
    next_offset: u32,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerDependencyDefinitionAuxEvidence {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyDefinitionRecordEvidence {
    ordinal: u16,
    file_offset: u64,
    version: u16,
    flags: u16,
    version_index: u16,
    auxiliary_count: u16,
    name_hash: u32,
    aux_offset: u32,
    next_offset: u32,
    auxiliaries: Vec<X64TailWorkerDependencyDefinitionAuxEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerDependencyDefinitionRecordEvidence {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub const fn flags(&self) -> u16 {
        self.flags
    }

    pub const fn version_index(&self) -> u16 {
        self.version_index
    }

    pub const fn name_hash(&self) -> u32 {
        self.name_hash
    }

    pub fn primary_name(&self) -> &str {
        self.auxiliaries.first().map_or("", |value| value.name())
    }

    pub fn auxiliaries(&self) -> &[X64TailWorkerDependencyDefinitionAuxEvidence] {
        &self.auxiliaries
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyDefinitionObjectEvidence {
    provider_ordinal: u16,
    source_object_ordinal: u16,
    closure_provider_evidence_hash: SemanticHash,
    object_hash: SemanticHash,
    soname: String,
    definition_count: u16,
    auxiliary_count: u16,
    definitions: Vec<X64TailWorkerDependencyDefinitionRecordEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerDependencyDefinitionObjectEvidence {
    pub const fn provider_ordinal(&self) -> u16 {
        self.provider_ordinal
    }

    pub fn soname(&self) -> &str {
        &self.soname
    }

    pub const fn definition_count(&self) -> u16 {
        self.definition_count
    }

    pub const fn auxiliary_count(&self) -> u16 {
        self.auxiliary_count
    }

    pub fn definitions(&self) -> &[X64TailWorkerDependencyDefinitionRecordEvidence] {
        &self.definitions
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyDefinitionEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    policy_hash: SemanticHash,
    closure_policy_hash: SemanticHash,
    closure_evidence_hash: SemanticHash,
    version_policy_hash: SemanticHash,
    version_evidence_hash: SemanticHash,
    object_set_evidence_hash: SemanticHash,
    provider_count: u16,
    total_definitions: u16,
    total_auxiliaries: u16,
    objects: Vec<X64TailWorkerDependencyDefinitionObjectEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerDependencyDefinitionEvidence {
    pub const fn policy_hash(&self) -> SemanticHash {
        self.policy_hash
    }

    pub const fn closure_evidence_hash(&self) -> SemanticHash {
        self.closure_evidence_hash
    }

    pub const fn version_evidence_hash(&self) -> SemanticHash {
        self.version_evidence_hash
    }

    pub const fn provider_count(&self) -> u16 {
        self.provider_count
    }

    pub const fn total_definitions(&self) -> u16 {
        self.total_definitions
    }

    pub const fn total_auxiliaries(&self) -> u16 {
        self.total_auxiliaries
    }

    pub fn objects(&self) -> &[X64TailWorkerDependencyDefinitionObjectEvidence] {
        &self.objects
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailWorkerDependencyDefinitions<'evidence> {
    evidence: &'evidence X64TailWorkerDependencyDefinitionEvidence,
}

impl<'evidence> VerifiedX64TailWorkerDependencyDefinitions<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64TailWorkerDependencyDefinitionEvidence {
        self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailWorkerDependencyDefinitionError {
    Closure(X64TailWorkerDependencyClosureError),
    Objects(X64TailWorkerDependencyObjectError),
    Versions(X64TailWorkerDependencyVersionError),
    Invalid(&'static str),
    Limit {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    Overflow(&'static str),
    EvidenceMismatch,
}

impl fmt::Display for X64TailWorkerDependencyDefinitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closure(error) => write!(formatter, "ADR-0077 closure failed: {error}"),
            Self::Objects(error) => write!(formatter, "ADR-0077 objects failed: {error}"),
            Self::Versions(error) => write!(formatter, "ADR-0077 requirements failed: {error}"),
            Self::Invalid(field) => write!(formatter, "invalid ADR-0077 {field}"),
            Self::Limit {
                field,
                limit,
                actual,
            } => write!(formatter, "ADR-0077 {field} {actual} exceeds limit {limit}"),
            Self::Overflow(field) => write!(formatter, "ADR-0077 {field} overflow"),
            Self::EvidenceMismatch => formatter.write_str("ADR-0077 evidence mismatch"),
        }
    }
}

impl std::error::Error for X64TailWorkerDependencyDefinitionError {}

impl From<X64TailWorkerDependencyClosureError> for X64TailWorkerDependencyDefinitionError {
    fn from(value: X64TailWorkerDependencyClosureError) -> Self {
        Self::Closure(value)
    }
}

impl From<X64TailWorkerDependencyObjectError> for X64TailWorkerDependencyDefinitionError {
    fn from(value: X64TailWorkerDependencyObjectError) -> Self {
        Self::Objects(value)
    }
}

impl From<X64TailWorkerDependencyVersionError> for X64TailWorkerDependencyDefinitionError {
    fn from(value: X64TailWorkerDependencyVersionError) -> Self {
        Self::Versions(value)
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
pub fn emit_x64_tail_worker_dependency_definition_evidence(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure_evidence: &X64TailWorkerDependencyClosureEvidence,
    version_evidence: &X64TailWorkerDependencyVersionEvidence,
) -> Result<X64TailWorkerDependencyDefinitionEvidence, X64TailWorkerDependencyDefinitionError> {
    if x64_tail_worker_dependency_definition_policy_hash()
        != X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_ROOT
    {
        return Err(X64TailWorkerDependencyDefinitionError::Invalid(
            "policy root",
        ));
    }
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
        version_evidence,
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
        > usize::from(X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_PROVIDERS)
    {
        return Err(X64TailWorkerDependencyDefinitionError::Limit {
            field: "providers",
            limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_PROVIDERS),
            actual: u64::try_from(closure_evidence.providers().len()).unwrap_or(u64::MAX),
        });
    }

    let mut objects = Vec::with_capacity(closure_evidence.providers().len());
    let mut total_definitions = 0u16;
    let mut total_auxiliaries = 0u16;
    for provider in closure_evidence.providers() {
        let source_ordinal = provider.source_object_ordinals().first().copied().ok_or(
            X64TailWorkerDependencyDefinitionError::Invalid("provider source ordinal"),
        )?;
        let object = object_set
            .evidence()
            .objects()
            .get(usize::from(source_ordinal))
            .ok_or(X64TailWorkerDependencyDefinitionError::Invalid(
                "provider source object",
            ))?;
        if object.object_hash() != provider.object_hash() {
            return Err(X64TailWorkerDependencyDefinitionError::EvidenceMismatch);
        }
        let bytes = x64_tail_worker_dependency_object_bytes(&verified_objects, source_ordinal)?;
        let decoded =
            decode_definition_object(&bytes, source_ordinal, object.object_hash(), provider)?;
        total_definitions = total_definitions
            .checked_add(decoded.definition_count)
            .ok_or(X64TailWorkerDependencyDefinitionError::Overflow(
                "total definitions",
            ))?;
        total_auxiliaries = total_auxiliaries
            .checked_add(decoded.auxiliary_count)
            .ok_or(X64TailWorkerDependencyDefinitionError::Overflow(
                "total auxiliaries",
            ))?;
        if total_auxiliaries > X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_TOTAL_AUX {
            return Err(X64TailWorkerDependencyDefinitionError::Limit {
                field: "total auxiliaries",
                limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_TOTAL_AUX),
                actual: u64::from(total_auxiliaries),
            });
        }
        objects.push(decoded);
    }
    let mut evidence = X64TailWorkerDependencyDefinitionEvidence {
        schema_version: X64_TAIL_WORKER_DEPENDENCY_DEFINITION_SCHEMA_VERSION,
        policy_version: X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_VERSION,
        policy_hash: x64_tail_worker_dependency_definition_policy_hash(),
        closure_policy_hash: X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT,
        closure_evidence_hash: closure_evidence.evidence_hash(),
        version_policy_hash: X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_ROOT,
        version_evidence_hash: version_evidence.evidence_hash(),
        object_set_evidence_hash: object_set.evidence().evidence_hash(),
        provider_count: u16::try_from(objects.len())
            .map_err(|_| X64TailWorkerDependencyDefinitionError::Overflow("provider count"))?,
        total_definitions,
        total_auxiliaries,
        objects,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = x64_tail_worker_dependency_definition_evidence_hash(&evidence);
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_x64_tail_worker_dependency_definition_evidence<'evidence>(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure_evidence: &X64TailWorkerDependencyClosureEvidence,
    version_evidence: &X64TailWorkerDependencyVersionEvidence,
    evidence: &'evidence X64TailWorkerDependencyDefinitionEvidence,
) -> Result<
    VerifiedX64TailWorkerDependencyDefinitions<'evidence>,
    X64TailWorkerDependencyDefinitionError,
> {
    preflight_definition_evidence(object_set, closure_evidence, version_evidence, evidence)?;
    let expected = emit_x64_tail_worker_dependency_definition_evidence(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
        dynamic_evidence,
        closure_expectation,
        closure_evidence,
        version_evidence,
    )?;
    if &expected != evidence
        || x64_tail_worker_dependency_definition_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerDependencyDefinitionError::EvidenceMismatch);
    }
    Ok(VerifiedX64TailWorkerDependencyDefinitions { evidence })
}

fn decode_definition_object(
    bytes: &[u8],
    source_object_ordinal: u16,
    object_hash: SemanticHash,
    provider: &X64TailWorkerDependencyClosureProviderEvidence,
) -> Result<X64TailWorkerDependencyDefinitionObjectEvidence, X64TailWorkerDependencyDefinitionError>
{
    let (loads, dynamic) = decode_layout(bytes)?;
    let (string_address, string_bytes, definition_address, definition_count) =
        decode_dynamic_definition_tags(bytes, &dynamic)?;
    if string_bytes > X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_STRING_TABLE_BYTES {
        return Err(X64TailWorkerDependencyDefinitionError::Limit {
            field: "string table bytes",
            limit: X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_STRING_TABLE_BYTES,
            actual: string_bytes,
        });
    }
    let strings = map_virtual_file_range(bytes, &loads, string_address, string_bytes)?;
    let mut definitions = Vec::with_capacity(usize::from(definition_count));
    let mut occupied = Vec::new();
    let mut version_indices = BTreeSet::new();
    let mut primary_names = BTreeSet::new();
    let mut base_count = 0u16;
    let mut current_address = definition_address.unwrap_or(0);
    for ordinal in 0..definition_count {
        let (record, file_offset) = map_virtual_file_record(
            bytes,
            &loads,
            current_address,
            VERDEF_BYTES,
            "Verdef record",
        )?;
        claim_record_range(&mut occupied, file_offset, VERDEF_BYTES)?;
        let version = read_u16(record, 0, "vd_version")?;
        let flags = read_u16(record, 2, "vd_flags")?;
        let version_index = read_u16(record, 4, "vd_ndx")?;
        let auxiliary_count = read_u16(record, 6, "vd_cnt")?;
        let name_hash = read_u32(record, 8, "vd_hash")?;
        let aux_offset = read_u32(record, 12, "vd_aux")?;
        let next_offset = read_u32(record, 16, "vd_next")?;
        if version != VERDEF_CURRENT {
            return Err(X64TailWorkerDependencyDefinitionError::Invalid(
                "Verdef version",
            ));
        }
        if flags & !(VER_FLG_BASE | VER_FLG_WEAK) != 0 {
            return Err(X64TailWorkerDependencyDefinitionError::Invalid(
                "Verdef flags",
            ));
        }
        let is_base = flags & VER_FLG_BASE != 0;
        if is_base {
            base_count = base_count.checked_add(1).ok_or(
                X64TailWorkerDependencyDefinitionError::Overflow("base definitions"),
            )?;
            if version_index != VER_NDX_GLOBAL || auxiliary_count != 1 {
                return Err(X64TailWorkerDependencyDefinitionError::Invalid(
                    "base definition shape",
                ));
            }
        } else if !(2..VER_NDX_LORESERVE).contains(&version_index) {
            return Err(X64TailWorkerDependencyDefinitionError::Invalid(
                "Verdef version index",
            ));
        }
        if !version_indices.insert(version_index) {
            return Err(X64TailWorkerDependencyDefinitionError::Invalid(
                "duplicate Verdef version index",
            ));
        }
        if auxiliary_count == 0
            || auxiliary_count > X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_AUX_PER_DEFINITION
        {
            return Err(X64TailWorkerDependencyDefinitionError::Limit {
                field: "Verdaux records",
                limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_AUX_PER_DEFINITION),
                actual: u64::from(auxiliary_count),
            });
        }
        validate_relative_offset(aux_offset, VERDEF_BYTES, "vd_aux")?;
        validate_chain_next(
            next_offset,
            ordinal + 1 == definition_count,
            VERDEF_BYTES,
            "vd_next",
        )?;

        let mut auxiliaries = Vec::with_capacity(usize::from(auxiliary_count));
        let mut auxiliary_names = BTreeSet::new();
        let mut auxiliary_address = current_address
            .checked_add(u64::from(aux_offset))
            .ok_or(X64TailWorkerDependencyDefinitionError::Overflow("vd_aux"))?;
        for aux_ordinal in 0..auxiliary_count {
            let (auxiliary, auxiliary_file_offset) = map_virtual_file_record(
                bytes,
                &loads,
                auxiliary_address,
                VERDAUX_BYTES,
                "Verdaux record",
            )?;
            claim_record_range(&mut occupied, auxiliary_file_offset, VERDAUX_BYTES)?;
            let name_offset = read_u32(auxiliary, 0, "vda_name")?;
            let aux_next_offset = read_u32(auxiliary, 4, "vda_next")?;
            validate_chain_next(
                aux_next_offset,
                aux_ordinal + 1 == auxiliary_count,
                VERDAUX_BYTES,
                "vda_next",
            )?;
            let name = decode_string_at(
                strings,
                string_bytes,
                u64::from(name_offset),
                "version definition name",
            )?;
            if !auxiliary_names.insert(name.clone()) {
                return Err(X64TailWorkerDependencyDefinitionError::Invalid(
                    "duplicate version definition name",
                ));
            }
            let mut evidence = X64TailWorkerDependencyDefinitionAuxEvidence {
                ordinal: aux_ordinal,
                file_offset: auxiliary_file_offset,
                name_offset,
                name,
                next_offset: aux_next_offset,
                evidence_hash: SemanticHash::ZERO,
            };
            evidence.evidence_hash = definition_aux_evidence_hash(&evidence);
            auxiliaries.push(evidence);
            if aux_next_offset != 0 {
                auxiliary_address = auxiliary_address
                    .checked_add(u64::from(aux_next_offset))
                    .ok_or(X64TailWorkerDependencyDefinitionError::Overflow("vda_next"))?;
            }
        }
        let primary_name = auxiliaries
            .first()
            .ok_or(X64TailWorkerDependencyDefinitionError::Invalid(
                "missing definition primary name",
            ))?
            .name();
        if elf_hash(primary_name.as_bytes()) != name_hash {
            return Err(X64TailWorkerDependencyDefinitionError::Invalid(
                "version definition hash",
            ));
        }
        if !primary_names.insert(primary_name.to_owned()) {
            return Err(X64TailWorkerDependencyDefinitionError::Invalid(
                "duplicate version definition primary name",
            ));
        }
        if is_base && primary_name != provider.soname() {
            return Err(X64TailWorkerDependencyDefinitionError::Invalid(
                "base definition SONAME",
            ));
        }
        let mut evidence = X64TailWorkerDependencyDefinitionRecordEvidence {
            ordinal,
            file_offset,
            version,
            flags,
            version_index,
            auxiliary_count,
            name_hash,
            aux_offset,
            next_offset,
            auxiliaries,
            evidence_hash: SemanticHash::ZERO,
        };
        evidence.evidence_hash = definition_record_evidence_hash(&evidence);
        definitions.push(evidence);
        if next_offset != 0 {
            current_address = current_address
                .checked_add(u64::from(next_offset))
                .ok_or(X64TailWorkerDependencyDefinitionError::Overflow("vd_next"))?;
        }
    }
    if definition_count > 0 && base_count != 1 {
        return Err(X64TailWorkerDependencyDefinitionError::Invalid(
            "base definition count",
        ));
    }
    let auxiliary_count = definitions.iter().try_fold(0u16, |total, definition| {
        total
            .checked_add(u16::try_from(definition.auxiliaries.len()).map_err(|_| {
                X64TailWorkerDependencyDefinitionError::Overflow("object auxiliaries")
            })?)
            .ok_or(X64TailWorkerDependencyDefinitionError::Overflow(
                "object auxiliaries",
            ))
    })?;
    let mut evidence = X64TailWorkerDependencyDefinitionObjectEvidence {
        provider_ordinal: provider.ordinal(),
        source_object_ordinal,
        closure_provider_evidence_hash: provider.evidence_hash(),
        object_hash,
        soname: provider.soname().to_owned(),
        definition_count: u16::try_from(definitions.len())
            .map_err(|_| X64TailWorkerDependencyDefinitionError::Overflow("object definitions"))?,
        auxiliary_count,
        definitions,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = definition_object_evidence_hash(&evidence);
    Ok(evidence)
}

fn decode_layout(
    bytes: &[u8],
) -> Result<(Vec<LoadSegment>, DynamicSegment), X64TailWorkerDependencyDefinitionError> {
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
        return Err(X64TailWorkerDependencyDefinitionError::Invalid(
            "ELF identity",
        ));
    }
    let program_offset = read_u64(bytes, 32, "program-header offset")?;
    let program_count = read_u16(bytes, 56, "program-header count")?;
    if program_count == 0
        || program_count > X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_PROGRAM_HEADERS
    {
        return Err(X64TailWorkerDependencyDefinitionError::Limit {
            field: "program headers",
            limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_PROGRAM_HEADERS),
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
            .ok_or(X64TailWorkerDependencyDefinitionError::Overflow(
                "program header",
            ))?;
        let kind = read_u32(bytes, offset, "program-header type")?;
        let file_offset = read_u64(bytes, offset + 8, "segment offset")?;
        let virtual_address = read_u64(bytes, offset + 16, "segment address")?;
        let file_size = read_u64(bytes, offset + 32, "segment file size")?;
        let memory_size = read_u64(bytes, offset + 40, "segment memory size")?;
        if file_size > memory_size {
            return Err(X64TailWorkerDependencyDefinitionError::Invalid(
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
                return Err(X64TailWorkerDependencyDefinitionError::Invalid(
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
        || loads.len() > usize::from(X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_LOAD_SEGMENTS)
    {
        return Err(X64TailWorkerDependencyDefinitionError::Limit {
            field: "load segments",
            limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_LOAD_SEGMENTS),
            actual: u64::try_from(loads.len()).unwrap_or(u64::MAX),
        });
    }
    Ok((
        loads,
        dynamic.ok_or(X64TailWorkerDependencyDefinitionError::Invalid(
            "missing dynamic segment",
        ))?,
    ))
}

fn decode_dynamic_definition_tags(
    bytes: &[u8],
    dynamic: &DynamicSegment,
) -> Result<(u64, u64, Option<u64>, u16), X64TailWorkerDependencyDefinitionError> {
    if dynamic.file_size == 0 || !dynamic.file_size.is_multiple_of(DYNAMIC_ENTRY_BYTES) {
        return Err(X64TailWorkerDependencyDefinitionError::Invalid(
            "dynamic segment size",
        ));
    }
    let entry_count = dynamic.file_size / DYNAMIC_ENTRY_BYTES;
    if entry_count > u64::from(X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_DYNAMIC_ENTRIES) {
        return Err(X64TailWorkerDependencyDefinitionError::Limit {
            field: "dynamic entries",
            limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_DYNAMIC_ENTRIES),
            actual: entry_count,
        });
    }
    let mut string_address = None;
    let mut string_bytes = None;
    let mut definition_address = None;
    let mut definition_count = None;
    let mut terminated = false;
    for ordinal in 0..entry_count {
        let offset = dynamic
            .file_offset
            .checked_add(ordinal * DYNAMIC_ENTRY_BYTES)
            .ok_or(X64TailWorkerDependencyDefinitionError::Overflow(
                "dynamic entry",
            ))?;
        let tag = read_i64(bytes, offset, "dynamic tag")?;
        let value = read_u64(bytes, offset + 8, "dynamic value")?;
        if terminated {
            if tag != DT_NULL || value != 0 {
                return Err(X64TailWorkerDependencyDefinitionError::Invalid(
                    "dynamic trailing entries",
                ));
            }
            continue;
        }
        match tag {
            DT_NULL => {
                if value != 0 {
                    return Err(X64TailWorkerDependencyDefinitionError::Invalid(
                        "dynamic terminator",
                    ));
                }
                terminated = true;
            }
            DT_STRTAB => set_once(&mut string_address, value, "DT_STRTAB")?,
            DT_STRSZ => set_once(&mut string_bytes, value, "DT_STRSZ")?,
            DT_VERDEF => set_once(&mut definition_address, value, "DT_VERDEF")?,
            DT_VERDEFNUM => set_once(&mut definition_count, value, "DT_VERDEFNUM")?,
            _ => {}
        }
    }
    if !terminated {
        return Err(X64TailWorkerDependencyDefinitionError::Invalid(
            "missing dynamic terminator",
        ));
    }
    let string_address = string_address.ok_or(X64TailWorkerDependencyDefinitionError::Invalid(
        "missing DT_STRTAB",
    ))?;
    let string_bytes = string_bytes.ok_or(X64TailWorkerDependencyDefinitionError::Invalid(
        "missing DT_STRSZ",
    ))?;
    if string_bytes == 0 {
        return Err(X64TailWorkerDependencyDefinitionError::Invalid(
            "empty string table",
        ));
    }
    match (definition_address, definition_count) {
        (None, None) => Ok((string_address, string_bytes, None, 0)),
        (Some(address), Some(count)) => {
            let count = u16::try_from(count).map_err(|_| {
                X64TailWorkerDependencyDefinitionError::Limit {
                    field: "version definitions",
                    limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_DEFINITIONS),
                    actual: count,
                }
            })?;
            if address == 0
                || count == 0
                || count > X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_DEFINITIONS
            {
                return Err(X64TailWorkerDependencyDefinitionError::Limit {
                    field: "version definitions",
                    limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_DEFINITIONS),
                    actual: u64::from(count),
                });
            }
            Ok((string_address, string_bytes, Some(address), count))
        }
        _ => Err(X64TailWorkerDependencyDefinitionError::Invalid(
            "unpaired version definition tags",
        )),
    }
}

fn preflight_definition_evidence(
    object_set: &X64TailWorkerDependencyObjectSet,
    closure: &X64TailWorkerDependencyClosureEvidence,
    versions: &X64TailWorkerDependencyVersionEvidence,
    evidence: &X64TailWorkerDependencyDefinitionEvidence,
) -> Result<(), X64TailWorkerDependencyDefinitionError> {
    if evidence.schema_version != X64_TAIL_WORKER_DEPENDENCY_DEFINITION_SCHEMA_VERSION
        || evidence.policy_version != X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_VERSION
        || evidence.policy_hash != X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_ROOT
        || evidence.policy_hash != x64_tail_worker_dependency_definition_policy_hash()
        || evidence.closure_policy_hash != X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT
        || evidence.closure_evidence_hash != closure.evidence_hash()
        || evidence.version_policy_hash != X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_ROOT
        || evidence.version_evidence_hash != versions.evidence_hash()
        || evidence.object_set_evidence_hash != object_set.evidence().evidence_hash()
        || usize::from(evidence.provider_count) != closure.providers().len()
        || evidence.objects.len() != closure.providers().len()
        || evidence.total_auxiliaries > X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_TOTAL_AUX
        || x64_tail_worker_dependency_definition_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerDependencyDefinitionError::EvidenceMismatch);
    }
    let mut total_definitions = 0u16;
    let mut total_auxiliaries = 0u16;
    for (ordinal, (object, provider)) in
        evidence.objects.iter().zip(closure.providers()).enumerate()
    {
        let source_ordinal = provider.source_object_ordinals().first().copied();
        total_definitions = total_definitions
            .checked_add(object.definition_count)
            .ok_or(X64TailWorkerDependencyDefinitionError::Overflow(
                "evidence definitions",
            ))?;
        total_auxiliaries = total_auxiliaries
            .checked_add(object.auxiliary_count)
            .ok_or(X64TailWorkerDependencyDefinitionError::Overflow(
                "evidence auxiliaries",
            ))?;
        if object.provider_ordinal != u16::try_from(ordinal).unwrap_or(u16::MAX)
            || object.provider_ordinal != provider.ordinal()
            || Some(object.source_object_ordinal) != source_ordinal
            || object.closure_provider_evidence_hash != provider.evidence_hash()
            || object.object_hash != provider.object_hash()
            || object.soname != provider.soname()
            || usize::from(object.definition_count) != object.definitions.len()
            || object.definition_count > X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_DEFINITIONS
            || usize::from(object.auxiliary_count)
                != object
                    .definitions
                    .iter()
                    .map(|definition| definition.auxiliaries.len())
                    .sum::<usize>()
            || definition_object_evidence_hash(object) != object.evidence_hash
        {
            return Err(X64TailWorkerDependencyDefinitionError::EvidenceMismatch);
        }
        let mut indices = BTreeSet::new();
        let mut primary_names = BTreeSet::new();
        let mut base_count = 0u16;
        for (definition_ordinal, definition) in object.definitions.iter().enumerate() {
            let is_base = definition.flags & VER_FLG_BASE != 0;
            if definition.ordinal != u16::try_from(definition_ordinal).unwrap_or(u16::MAX)
                || definition.version != VERDEF_CURRENT
                || definition.flags & !(VER_FLG_BASE | VER_FLG_WEAK) != 0
                || definition.auxiliaries.is_empty()
                || usize::from(definition.auxiliary_count) != definition.auxiliaries.len()
                || definition.auxiliary_count
                    > X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_AUX_PER_DEFINITION
                || !indices.insert(definition.version_index)
                || definition_record_evidence_hash(definition) != definition.evidence_hash
            {
                return Err(X64TailWorkerDependencyDefinitionError::EvidenceMismatch);
            }
            if (is_base
                && (definition.version_index != VER_NDX_GLOBAL
                    || definition.auxiliary_count != 1
                    || definition.primary_name() != provider.soname()))
                || (!is_base && !(2..VER_NDX_LORESERVE).contains(&definition.version_index))
                || elf_hash(definition.primary_name().as_bytes()) != definition.name_hash
                || !primary_names.insert(definition.primary_name().to_owned())
            {
                return Err(X64TailWorkerDependencyDefinitionError::EvidenceMismatch);
            }
            if is_base {
                base_count = base_count.checked_add(1).ok_or(
                    X64TailWorkerDependencyDefinitionError::Overflow("evidence base definitions"),
                )?;
            }
            for (aux_ordinal, auxiliary) in definition.auxiliaries.iter().enumerate() {
                if auxiliary.ordinal != u16::try_from(aux_ordinal).unwrap_or(u16::MAX)
                    || definition_aux_evidence_hash(auxiliary) != auxiliary.evidence_hash
                {
                    return Err(X64TailWorkerDependencyDefinitionError::EvidenceMismatch);
                }
            }
        }
        if !object.definitions.is_empty() && base_count != 1 {
            return Err(X64TailWorkerDependencyDefinitionError::EvidenceMismatch);
        }
    }
    if total_definitions != evidence.total_definitions
        || total_auxiliaries != evidence.total_auxiliaries
    {
        return Err(X64TailWorkerDependencyDefinitionError::EvidenceMismatch);
    }
    Ok(())
}

fn map_virtual_file_record<'bytes>(
    bytes: &'bytes [u8],
    loads: &[LoadSegment],
    address: u64,
    size: u64,
    field: &'static str,
) -> Result<(&'bytes [u8], u64), X64TailWorkerDependencyDefinitionError> {
    let end = address
        .checked_add(size)
        .ok_or(X64TailWorkerDependencyDefinitionError::Overflow(field))?;
    let mut matches = loads.iter().filter(|load| {
        address >= load.virtual_address
            && load
                .virtual_address
                .checked_add(load.file_size)
                .is_some_and(|load_end| end <= load_end)
    });
    let load = matches
        .next()
        .ok_or(X64TailWorkerDependencyDefinitionError::Invalid(field))?;
    if matches.next().is_some() {
        return Err(X64TailWorkerDependencyDefinitionError::Invalid(
            "ambiguous virtual mapping",
        ));
    }
    let file_offset = load
        .file_offset
        .checked_add(address - load.virtual_address)
        .ok_or(X64TailWorkerDependencyDefinitionError::Overflow(field))?;
    Ok((slice_range(bytes, file_offset, size, field)?, file_offset))
}

fn map_virtual_file_range<'bytes>(
    bytes: &'bytes [u8],
    loads: &[LoadSegment],
    address: u64,
    size: u64,
) -> Result<&'bytes [u8], X64TailWorkerDependencyDefinitionError> {
    map_virtual_file_record(bytes, loads, address, size, "dynamic string table")
        .map(|(value, _)| value)
}

fn claim_record_range(
    occupied: &mut Vec<(u64, u64)>,
    offset: u64,
    size: u64,
) -> Result<(), X64TailWorkerDependencyDefinitionError> {
    let end = offset
        .checked_add(size)
        .ok_or(X64TailWorkerDependencyDefinitionError::Overflow(
            "version record range",
        ))?;
    if occupied
        .iter()
        .any(|(existing_start, existing_end)| offset < *existing_end && *existing_start < end)
    {
        return Err(X64TailWorkerDependencyDefinitionError::Invalid(
            "overlapping version records",
        ));
    }
    occupied.push((offset, end));
    Ok(())
}

fn validate_relative_offset(
    offset: u32,
    minimum: u64,
    field: &'static str,
) -> Result<(), X64TailWorkerDependencyDefinitionError> {
    if u64::from(offset) < minimum || !offset.is_multiple_of(4) {
        return Err(X64TailWorkerDependencyDefinitionError::Invalid(field));
    }
    Ok(())
}

fn validate_chain_next(
    offset: u32,
    is_last: bool,
    minimum: u64,
    field: &'static str,
) -> Result<(), X64TailWorkerDependencyDefinitionError> {
    if (is_last && offset != 0)
        || (!is_last && (u64::from(offset) < minimum || !offset.is_multiple_of(4)))
    {
        return Err(X64TailWorkerDependencyDefinitionError::Invalid(field));
    }
    Ok(())
}

fn decode_string_at(
    strings: &[u8],
    string_bytes: u64,
    offset: u64,
    field: &'static str,
) -> Result<String, X64TailWorkerDependencyDefinitionError> {
    if offset >= string_bytes {
        return Err(X64TailWorkerDependencyDefinitionError::Invalid(field));
    }
    let start = usize::try_from(offset)
        .map_err(|_| X64TailWorkerDependencyDefinitionError::Overflow(field))?;
    let retained = usize::from(X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_NAME_BYTES)
        .min(strings.len().saturating_sub(start));
    let value = &strings[start..start + retained];
    let end = value
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(X64TailWorkerDependencyDefinitionError::Invalid(field))?;
    let name = &value[..end];
    if name.is_empty()
        || name.iter().any(|byte| !(0x21..=0x7e).contains(byte))
        || name.contains(&b'/')
        || name.contains(&b'\\')
    {
        return Err(X64TailWorkerDependencyDefinitionError::Invalid(field));
    }
    std::str::from_utf8(name)
        .map(str::to_owned)
        .map_err(|_| X64TailWorkerDependencyDefinitionError::Invalid(field))
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
) -> Result<(), X64TailWorkerDependencyDefinitionError> {
    let end = offset
        .checked_add(size)
        .ok_or(X64TailWorkerDependencyDefinitionError::Overflow(field))?;
    if end > u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
        return Err(X64TailWorkerDependencyDefinitionError::Invalid(field));
    }
    Ok(())
}

fn slice_range<'bytes>(
    bytes: &'bytes [u8],
    offset: u64,
    size: u64,
    field: &'static str,
) -> Result<&'bytes [u8], X64TailWorkerDependencyDefinitionError> {
    require_range(bytes, offset, size, field)?;
    let start = usize::try_from(offset)
        .map_err(|_| X64TailWorkerDependencyDefinitionError::Overflow(field))?;
    let end = usize::try_from(offset + size)
        .map_err(|_| X64TailWorkerDependencyDefinitionError::Overflow(field))?;
    Ok(&bytes[start..end])
}

fn read_u16(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<u16, X64TailWorkerDependencyDefinitionError> {
    let value = slice_range(bytes, offset, 2, field)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<u32, X64TailWorkerDependencyDefinitionError> {
    let value = slice_range(bytes, offset, 4, field)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<u64, X64TailWorkerDependencyDefinitionError> {
    let value = slice_range(bytes, offset, 8, field)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn read_i64(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<i64, X64TailWorkerDependencyDefinitionError> {
    Ok(read_u64(bytes, offset, field)? as i64)
}

fn set_once(
    slot: &mut Option<u64>,
    value: u64,
    field: &'static str,
) -> Result<(), X64TailWorkerDependencyDefinitionError> {
    if slot.replace(value).is_some() {
        Err(X64TailWorkerDependencyDefinitionError::Invalid(field))
    } else {
        Ok(())
    }
}

pub fn x64_tail_worker_dependency_definition_policy_hash() -> SemanticHash {
    let mut bytes = Vec::with_capacity(768);
    bytes.extend_from_slice(POLICY_DOMAIN);
    put_version(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DEFINITION_SCHEMA_VERSION,
    );
    put_version(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_VERSION,
    );
    put_hash(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT);
    put_hash(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_ROOT);
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_PROVIDERS,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_PROGRAM_HEADERS,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_LOAD_SEGMENTS,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_DYNAMIC_ENTRIES,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_DEFINITIONS,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_AUX_PER_DEFINITION,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_TOTAL_AUX,
    );
    put_u64(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_STRING_TABLE_BYTES,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_NAME_BYTES,
    );
    put_u16(&mut bytes, ELF_HEADER_BYTES);
    put_u16(&mut bytes, PROGRAM_HEADER_BYTES);
    put_u64(&mut bytes, DYNAMIC_ENTRY_BYTES);
    put_u64(&mut bytes, VERDEF_BYTES);
    put_u64(&mut bytes, VERDAUX_BYTES);
    put_u64(&mut bytes, DT_VERDEF as u64);
    put_u64(&mut bytes, DT_VERDEFNUM as u64);
    put_u16(&mut bytes, VERDEF_CURRENT);
    put_u16(&mut bytes, VER_FLG_BASE);
    put_u16(&mut bytes, VER_FLG_WEAK);
    put_u16(&mut bytes, VER_NDX_GLOBAL);
    put_u16(&mut bytes, VER_NDX_LORESERVE);
    put_u16(
        &mut bytes,
        u16::try_from(POLICY_CAPABILITIES.len()).unwrap_or(u16::MAX),
    );
    for capability in POLICY_CAPABILITIES {
        put_string(&mut bytes, capability);
    }
    SemanticHash(sha256(&bytes))
}

fn definition_aux_evidence_hash(
    evidence: &X64TailWorkerDependencyDefinitionAuxEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(AUX_DOMAIN);
    put_u16(&mut bytes, evidence.ordinal);
    put_u64(&mut bytes, evidence.file_offset);
    put_u32(&mut bytes, evidence.name_offset);
    put_string(&mut bytes, &evidence.name);
    put_u32(&mut bytes, evidence.next_offset);
    SemanticHash(sha256(&bytes))
}

fn definition_record_evidence_hash(
    evidence: &X64TailWorkerDependencyDefinitionRecordEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(384);
    bytes.extend_from_slice(DEFINITION_DOMAIN);
    put_u16(&mut bytes, evidence.ordinal);
    put_u64(&mut bytes, evidence.file_offset);
    put_u16(&mut bytes, evidence.version);
    put_u16(&mut bytes, evidence.flags);
    put_u16(&mut bytes, evidence.version_index);
    put_u16(&mut bytes, evidence.auxiliary_count);
    put_u32(&mut bytes, evidence.name_hash);
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

fn definition_object_evidence_hash(
    evidence: &X64TailWorkerDependencyDefinitionObjectEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(384);
    bytes.extend_from_slice(OBJECT_DOMAIN);
    put_u16(&mut bytes, evidence.provider_ordinal);
    put_u16(&mut bytes, evidence.source_object_ordinal);
    put_hash(&mut bytes, evidence.closure_provider_evidence_hash);
    put_hash(&mut bytes, evidence.object_hash);
    put_string(&mut bytes, &evidence.soname);
    put_u16(&mut bytes, evidence.definition_count);
    put_u16(&mut bytes, evidence.auxiliary_count);
    for definition in &evidence.definitions {
        put_hash(&mut bytes, definition.evidence_hash);
    }
    SemanticHash(sha256(&bytes))
}

pub fn x64_tail_worker_dependency_definition_evidence_hash(
    evidence: &X64TailWorkerDependencyDefinitionEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_hash(&mut bytes, evidence.policy_hash);
    put_hash(&mut bytes, evidence.closure_policy_hash);
    put_hash(&mut bytes, evidence.closure_evidence_hash);
    put_hash(&mut bytes, evidence.version_policy_hash);
    put_hash(&mut bytes, evidence.version_evidence_hash);
    put_hash(&mut bytes, evidence.object_set_evidence_hash);
    put_u16(&mut bytes, evidence.provider_count);
    put_u16(&mut bytes, evidence.total_definitions);
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
pub fn probe_x64_tail_worker_dependency_definition_decoder_mutations(
    bytes: &[u8],
    provider_ordinal: u16,
    closure: &X64TailWorkerDependencyClosureEvidence,
) -> bool {
    let Some(provider) = closure.providers().get(usize::from(provider_ordinal)) else {
        return false;
    };
    if decode_definition_object(
        bytes,
        provider.source_object_ordinals()[0],
        provider.object_hash(),
        provider,
    )
    .is_err()
    {
        return false;
    }
    let Ok((loads, dynamic)) = decode_layout(bytes) else {
        return false;
    };
    let Ok((_string_address, _string_bytes, Some(definition_address), definition_count)) =
        decode_dynamic_definition_tags(bytes, &dynamic)
    else {
        return false;
    };
    let Ok((definition, definition_file_offset)) = map_virtual_file_record(
        bytes,
        &loads,
        definition_address,
        VERDEF_BYTES,
        "probe Verdef",
    ) else {
        return false;
    };
    let Ok(aux_offset) = read_u32(definition, 12, "probe vd_aux") else {
        return false;
    };
    let Some(aux_address) = definition_address.checked_add(u64::from(aux_offset)) else {
        return false;
    };
    let Ok((_, auxiliary_file_offset)) =
        map_virtual_file_record(bytes, &loads, aux_address, VERDAUX_BYTES, "probe Verdaux")
    else {
        return false;
    };
    let Some(definition_tag) = find_dynamic_tag_offset(bytes, &dynamic, DT_VERDEF) else {
        return false;
    };
    let Some(definition_count_tag) = find_dynamic_tag_offset(bytes, &dynamic, DT_VERDEFNUM) else {
        return false;
    };
    let aux_count = read_u16(bytes, definition_file_offset + 6, "probe vd_cnt").unwrap_or(0);
    let next_offset = read_u32(bytes, definition_file_offset + 16, "probe vd_next").unwrap_or(0);
    let second_definition_file_offset = (definition_count > 1 && next_offset != 0)
        .then(|| definition_address.checked_add(u64::from(next_offset)))
        .flatten()
        .and_then(|address| {
            map_virtual_file_record(bytes, &loads, address, VERDEF_BYTES, "probe second Verdef")
                .ok()
                .map(|(_, offset)| offset)
        });
    let semantic_base_mutation = second_definition_file_offset.is_some_and(|second_offset| {
        let second_aux_offset = read_u32(bytes, second_offset + 12, "probe second vd_aux").ok();
        let second_hash = read_u32(bytes, second_offset + 8, "probe second vd_hash").ok();
        let second_name_offset = second_aux_offset
            .and_then(|offset| second_offset.checked_add(u64::from(offset)))
            .and_then(|offset| read_u32(bytes, offset, "probe second vda_name").ok());
        match (second_hash, second_name_offset) {
            (Some(hash), Some(name_offset)) => {
                definition_decoder_mutation_rejected(bytes, provider, |value| {
                    write_u32(value, definition_file_offset + 8, hash);
                    write_u32(value, auxiliary_file_offset, name_offset);
                })
            }
            _ => false,
        }
    });
    let duplicate_index_mutation = second_definition_file_offset.is_some_and(|second_offset| {
        definition_decoder_mutation_rejected(bytes, provider, |value| {
            write_u16(value, second_offset + 4, VER_NDX_GLOBAL)
        })
    });
    [
        definition_decoder_mutation_rejected(bytes, provider, |value| {
            write_i64(value, definition_tag, 0x1234)
        }),
        definition_decoder_mutation_rejected(bytes, provider, |value| {
            write_i64(value, definition_count_tag, DT_VERDEF)
        }),
        definition_decoder_mutation_rejected(bytes, provider, |value| {
            write_u64(
                value,
                definition_count_tag + 8,
                u64::from(X64_TAIL_WORKER_DEPENDENCY_DEFINITION_MAX_DEFINITIONS) + 1,
            )
        }),
        definition_decoder_mutation_rejected(bytes, provider, |value| {
            write_u64(value, definition_count_tag + 8, 1)
        }),
        definition_decoder_mutation_rejected(bytes, provider, |value| {
            write_u16(value, definition_file_offset, VERDEF_CURRENT + 1)
        }),
        definition_decoder_mutation_rejected(bytes, provider, |value| {
            write_u16(value, definition_file_offset + 2, 4)
        }),
        definition_decoder_mutation_rejected(bytes, provider, |value| {
            write_u16(value, definition_file_offset + 2, 0)
        }),
        definition_decoder_mutation_rejected(bytes, provider, |value| {
            write_u16(value, definition_file_offset + 4, VER_NDX_LORESERVE)
        }),
        definition_decoder_mutation_rejected(bytes, provider, |value| {
            write_u16(value, definition_file_offset + 6, 0)
        }),
        definition_decoder_mutation_rejected(bytes, provider, |value| {
            let current = read_u32(value, definition_file_offset + 8, "probe hash").unwrap_or(0);
            write_u32(value, definition_file_offset + 8, current ^ 1)
        }),
        definition_decoder_mutation_rejected(bytes, provider, |value| {
            write_u32(value, definition_file_offset + 12, 0)
        }),
        definition_decoder_mutation_rejected(bytes, provider, |value| {
            write_u32(value, auxiliary_file_offset, u32::MAX)
        }),
        definition_decoder_mutation_rejected(bytes, provider, |value| {
            if aux_count > 1 {
                write_u32(value, auxiliary_file_offset + 4, 0);
            } else {
                write_u32(value, auxiliary_file_offset + 4, 8);
            }
        }),
        definition_decoder_mutation_rejected(bytes, provider, |value| {
            if definition_count > 1 {
                write_u32(value, definition_file_offset + 16, 0);
            } else {
                write_u32(value, definition_file_offset + 16, 20);
            }
        }),
        definition_decoder_mutation_rejected(bytes, provider, |value| {
            write_u32(value, definition_file_offset + 16, 20)
        }),
        semantic_base_mutation,
        duplicate_index_mutation,
    ]
    .into_iter()
    .all(|rejected| rejected)
}

#[cfg(debug_assertions)]
fn definition_decoder_mutation_rejected(
    bytes: &[u8],
    provider: &X64TailWorkerDependencyClosureProviderEvidence,
    mutate: impl FnOnce(&mut [u8]),
) -> bool {
    let mut mutation = bytes.to_vec();
    mutate(&mut mutation);
    decode_definition_object(
        &mutation,
        provider.source_object_ordinals()[0],
        provider.object_hash(),
        provider,
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
pub fn probe_x64_tail_worker_dependency_definition_mutations(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure_evidence: &X64TailWorkerDependencyClosureEvidence,
    version_evidence: &X64TailWorkerDependencyVersionEvidence,
    evidence: &X64TailWorkerDependencyDefinitionEvidence,
) -> bool {
    let mut stale_policy = evidence.clone();
    stale_policy.policy_hash.0[0] ^= 1;
    let mut stale_closure = evidence.clone();
    stale_closure.closure_evidence_hash.0[0] ^= 1;
    let mut stale_versions = evidence.clone();
    stale_versions.version_evidence_hash.0[0] ^= 1;
    let mut stale_count = evidence.clone();
    stale_count.total_auxiliaries = stale_count.total_auxiliaries.saturating_add(1);
    let mut stale_object = evidence.clone();
    stale_object.objects[0].soname.push('x');
    let mut stale_auxiliary = evidence.clone();
    let Some(auxiliary) = stale_auxiliary
        .objects
        .iter_mut()
        .flat_map(|object| object.definitions.iter_mut())
        .flat_map(|definition| definition.auxiliaries.iter_mut())
        .next()
    else {
        return false;
    };
    auxiliary.name.push('x');

    let shallow_rejected = [
        stale_policy,
        stale_closure,
        stale_versions,
        stale_count,
        stale_object,
        stale_auxiliary,
    ]
    .iter()
    .all(|mutation| {
        verify_x64_tail_worker_dependency_definition_evidence(
            artifact,
            inventory,
            declaration_expectation,
            declaration_evidence,
            manifest,
            object_set,
            dynamic_evidence,
            closure_expectation,
            closure_evidence,
            version_evidence,
            mutation,
        )
        .is_err()
    });

    let mut resealed = evidence.clone();
    let Some((object_ordinal, definition_ordinal, auxiliary_ordinal)) =
        resealed
            .objects
            .iter()
            .enumerate()
            .find_map(|(object_ordinal, object)| {
                object.definitions.iter().enumerate().find_map(
                    |(definition_ordinal, definition)| {
                        (!definition.auxiliaries.is_empty()).then_some((
                            object_ordinal,
                            definition_ordinal,
                            0usize,
                        ))
                    },
                )
            })
    else {
        return false;
    };
    let auxiliary = &mut resealed.objects[object_ordinal].definitions[definition_ordinal]
        .auxiliaries[auxiliary_ordinal];
    auxiliary.name.push('x');
    auxiliary.evidence_hash = definition_aux_evidence_hash(auxiliary);
    let definition = &mut resealed.objects[object_ordinal].definitions[definition_ordinal];
    definition.name_hash = elf_hash(definition.primary_name().as_bytes());
    definition.evidence_hash = definition_record_evidence_hash(definition);
    let object = &mut resealed.objects[object_ordinal];
    object.evidence_hash = definition_object_evidence_hash(object);
    resealed.evidence_hash = x64_tail_worker_dependency_definition_evidence_hash(&resealed);
    let resealed_rejected = verify_x64_tail_worker_dependency_definition_evidence(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
        dynamic_evidence,
        closure_expectation,
        closure_evidence,
        version_evidence,
        &resealed,
    )
    .is_err();
    shallow_rejected && resealed_rejected
}
