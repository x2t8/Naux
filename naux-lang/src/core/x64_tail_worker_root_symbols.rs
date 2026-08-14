//! ADR-0082 proof-only dynamic-symbol and GNU version-index inventory.
//!
//! This boundary independently derives a bounded dynamic-symbol extent from
//! ELF hash tables, reconstructs their complete topology, and inventories the
//! parallel GNU version vector. It never looks up, selects, binds, relocates,
//! maps, initializes, or executes a symbol.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_worker_artifact::{
    verify_x64_tail_worker_artifact, x64_tail_worker_artifact_bytes, X64TailWorkerArtifact,
    X64TailWorkerArtifactError, X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT,
};
use super::x64_tail_worker_dependency_admission::{
    X64TailWorkerDependencyAdmissionEvidence, X64TailWorkerDependencyExpectation,
};
use super::x64_tail_worker_dependency_closure::{
    X64TailWorkerDependencyClosureEvidence, X64TailWorkerDependencyClosureExpectation,
};
use super::x64_tail_worker_dependency_definitions::X64TailWorkerDependencyDefinitionEvidence;
use super::x64_tail_worker_dependency_dynamic::X64TailWorkerDependencyDynamicEvidence;
use super::x64_tail_worker_dependency_objects::{
    X64TailWorkerDependencyObjectManifest, X64TailWorkerDependencyObjectSet,
};
use super::x64_tail_worker_dependency_versions::X64TailWorkerDependencyVersionEvidence;
use super::x64_tail_worker_elf::{X64TailWorkerElfEvidence, X64_TAIL_WORKER_ELF_POLICY_ROOT};
use super::x64_tail_worker_root_compatibility::{
    verify_x64_tail_worker_root_compatibility, X64TailWorkerRootCompatibilityError,
    X64TailWorkerRootCompatibilityEvidence, X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_ROOT,
};
use super::x64_tail_worker_root_versions::{
    X64TailWorkerRootVersionEvidence, X64_TAIL_WORKER_ROOT_VERSION_POLICY_ROOT,
};
use std::fmt;

pub const X64_TAIL_WORKER_ROOT_SYMBOL_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_ROOT_SYMBOL_MAX_PROGRAM_HEADERS: u16 = 64;
pub const X64_TAIL_WORKER_ROOT_SYMBOL_MAX_LOAD_SEGMENTS: u16 = 16;
pub const X64_TAIL_WORKER_ROOT_SYMBOL_MAX_DYNAMIC_ENTRIES: u16 = 4_096;
pub const X64_TAIL_WORKER_ROOT_SYMBOL_MAX_SYMBOLS: u16 = 4_096;
pub const X64_TAIL_WORKER_ROOT_SYMBOL_MAX_HASH_BUCKETS: u16 = 4_096;
pub const X64_TAIL_WORKER_ROOT_SYMBOL_MAX_GNU_BLOOM_WORDS: u16 = 512;
pub const X64_TAIL_WORKER_ROOT_SYMBOL_MAX_STRING_TABLE_BYTES: u64 = 1024 * 1024;
pub const X64_TAIL_WORKER_ROOT_SYMBOL_MAX_NAME_BYTES: u16 = 256;
pub const X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT: SemanticHash = SemanticHash([
    109, 104, 200, 196, 85, 83, 108, 104, 52, 132, 240, 18, 163, 208, 195, 233, 31, 138, 135, 154,
    201, 129, 249, 99, 98, 199, 196, 91, 55, 234, 110, 164,
]);

const POLICY_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-symbol-policy:v1\0";
const SYMBOL_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-symbol-record:v1\0";
const OBJECT_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-symbol-object:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-symbol-evidence:v1\0";
const POLICY_CAPABILITIES: &[&str] = &[
    "immutable-verified-adr0070-root-descriptor-source-v1",
    "full-adr0081-root-compatibility-replay-v1",
    "independent-elf64-x86-64-layout-decoder-v1",
    "paired-bounded-dynsym-syment-strtab-versym-tags-v1",
    "sysv-nchain-exact-symbol-extent-v1",
    "gnu-terminal-and-complete-hash-reconstruction-v1",
    "exact-elf64-sym-and-parallel-versym-vector-v1",
    "undefined-to-root-verneed-and-compatibility-index-replay-v1",
    "domain-separated-record-object-aggregate-replay-v1",
    "proof-only-no-lookup-binding-relocation-or-execution-v1",
];

const ELF_HEADER_BYTES: u16 = 64;
const PROGRAM_HEADER_BYTES: u16 = 56;
const DYNAMIC_ENTRY_BYTES: u64 = 16;
const ELF64_SYMBOL_BYTES: u64 = 24;
const VERSYM_BYTES: u64 = 2;
const GNU_HASH_HEADER_BYTES: u64 = 16;
const SYSV_HASH_HEADER_BYTES: u64 = 8;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_W: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_VERSYM: i64 = 0x6fff_fff0;
const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const STB_GNU_UNIQUE: u8 = 10;
const STT_NOTYPE: u8 = 0;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_SECTION: u8 = 3;
const STT_FILE: u8 = 4;
const STT_COMMON: u8 = 5;
const STT_TLS: u8 = 6;
const STT_GNU_IFUNC: u8 = 10;
const SHN_UNDEF: u16 = 0;
const SHN_LORESERVE: u16 = 0xff00;
const SHN_ABS: u16 = 0xfff1;
const SHN_COMMON: u16 = 0xfff2;
const VERSYM_HIDDEN: u16 = 0x8000;
const VERSYM_INDEX_MASK: u16 = 0x7fff;
const VERSYM_LORESERVE: u16 = 0x7f00;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum X64TailWorkerRootSymbolNamespaceKind {
    Local = 0,
    Global = 1,
    Requirement = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerRootSymbolRecordEvidence {
    ordinal: u16,
    file_offset: u64,
    name_offset: u32,
    name: String,
    sysv_name_hash: u32,
    gnu_name_hash: u32,
    binding: u8,
    symbol_type: u8,
    visibility: u8,
    section_index: u16,
    value: u64,
    size: u64,
    version_word: u16,
    version_index: u16,
    version_hidden: bool,
    namespace_kind: X64TailWorkerRootSymbolNamespaceKind,
    namespace_provider_ordinal: u16,
    namespace_record_ordinal: u16,
    namespace_auxiliary_ordinal: u16,
    namespace_evidence_hash: SemanticHash,
    compatibility_binding_evidence_hash: SemanticHash,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerRootSymbolRecordEvidence {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn sysv_name_hash(&self) -> u32 {
        self.sysv_name_hash
    }

    pub const fn gnu_name_hash(&self) -> u32 {
        self.gnu_name_hash
    }

    pub const fn binding(&self) -> u8 {
        self.binding
    }

    pub const fn symbol_type(&self) -> u8 {
        self.symbol_type
    }

    pub const fn visibility(&self) -> u8 {
        self.visibility
    }

    pub const fn section_index(&self) -> u16 {
        self.section_index
    }

    pub const fn is_defined(&self) -> bool {
        self.section_index != SHN_UNDEF
    }

    pub const fn version_word(&self) -> u16 {
        self.version_word
    }

    pub const fn version_index(&self) -> u16 {
        self.version_index
    }

    pub const fn version_hidden(&self) -> bool {
        self.version_hidden
    }

    pub const fn namespace_kind(&self) -> X64TailWorkerRootSymbolNamespaceKind {
        self.namespace_kind
    }

    pub const fn namespace_provider_ordinal(&self) -> u16 {
        self.namespace_provider_ordinal
    }

    pub const fn namespace_record_ordinal(&self) -> u16 {
        self.namespace_record_ordinal
    }

    pub const fn namespace_auxiliary_ordinal(&self) -> u16 {
        self.namespace_auxiliary_ordinal
    }

    pub const fn namespace_evidence_hash(&self) -> SemanticHash {
        self.namespace_evidence_hash
    }

    pub const fn compatibility_binding_evidence_hash(&self) -> SemanticHash {
        self.compatibility_binding_evidence_hash
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerRootSymbolObjectEvidence {
    artifact_hash: SemanticHash,
    inventory_evidence_hash: SemanticHash,
    root_version_evidence_hash: SemanticHash,
    root_compatibility_evidence_hash: SemanticHash,
    symbol_table_address: u64,
    string_table_address: u64,
    string_table_bytes: u64,
    version_table_address: u64,
    sysv_hash_address: Option<u64>,
    sysv_buckets: Vec<u32>,
    sysv_chains: Vec<u32>,
    gnu_hash_address: Option<u64>,
    gnu_symbol_offset: u32,
    gnu_bloom_shift: u32,
    gnu_bloom: Vec<u64>,
    gnu_buckets: Vec<u32>,
    gnu_chains: Vec<u32>,
    symbol_count: u16,
    symbols: Vec<X64TailWorkerRootSymbolRecordEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerRootSymbolObjectEvidence {
    pub const fn artifact_hash(&self) -> SemanticHash {
        self.artifact_hash
    }

    pub const fn symbol_count(&self) -> u16 {
        self.symbol_count
    }

    pub fn symbols(&self) -> &[X64TailWorkerRootSymbolRecordEvidence] {
        &self.symbols
    }

    pub fn sysv_buckets(&self) -> &[u32] {
        &self.sysv_buckets
    }

    pub fn sysv_chains(&self) -> &[u32] {
        &self.sysv_chains
    }

    pub fn gnu_bloom(&self) -> &[u64] {
        &self.gnu_bloom
    }

    pub fn gnu_buckets(&self) -> &[u32] {
        &self.gnu_buckets
    }

    pub fn gnu_chains(&self) -> &[u32] {
        &self.gnu_chains
    }

    pub const fn gnu_symbol_offset(&self) -> u32 {
        self.gnu_symbol_offset
    }

    pub const fn gnu_bloom_shift(&self) -> u32 {
        self.gnu_bloom_shift
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerRootSymbolEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    policy_hash: SemanticHash,
    artifact_policy_hash: SemanticHash,
    artifact_hash: SemanticHash,
    inventory_policy_hash: SemanticHash,
    inventory_evidence_hash: SemanticHash,
    root_version_policy_hash: SemanticHash,
    root_version_evidence_hash: SemanticHash,
    root_compatibility_policy_hash: SemanticHash,
    root_compatibility_evidence_hash: SemanticHash,
    symbol_count: u16,
    object: X64TailWorkerRootSymbolObjectEvidence,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerRootSymbolEvidence {
    pub const fn policy_hash(&self) -> SemanticHash {
        self.policy_hash
    }

    pub const fn symbol_count(&self) -> u16 {
        self.symbol_count
    }

    pub const fn object(&self) -> &X64TailWorkerRootSymbolObjectEvidence {
        &self.object
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailWorkerRootSymbols<'evidence> {
    evidence: &'evidence X64TailWorkerRootSymbolEvidence,
}

impl<'evidence> VerifiedX64TailWorkerRootSymbols<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64TailWorkerRootSymbolEvidence {
        self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailWorkerRootSymbolError {
    Artifact(X64TailWorkerArtifactError),
    Compatibility(X64TailWorkerRootCompatibilityError),
    Invalid(&'static str),
    Limit {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    Overflow(&'static str),
    EvidenceMismatch,
}

impl fmt::Display for X64TailWorkerRootSymbolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Artifact(error) => write!(formatter, "ADR-0082 artifact failed: {error}"),
            Self::Compatibility(error) => {
                write!(formatter, "ADR-0082 compatibility failed: {error}")
            }
            Self::Invalid(field) => write!(formatter, "invalid ADR-0082 {field}"),
            Self::Limit {
                field,
                limit,
                actual,
            } => write!(formatter, "ADR-0082 {field} {actual} exceeds limit {limit}"),
            Self::Overflow(field) => write!(formatter, "ADR-0082 {field} overflow"),
            Self::EvidenceMismatch => formatter.write_str("ADR-0082 evidence mismatch"),
        }
    }
}

impl std::error::Error for X64TailWorkerRootSymbolError {}

impl From<X64TailWorkerArtifactError> for X64TailWorkerRootSymbolError {
    fn from(value: X64TailWorkerArtifactError) -> Self {
        Self::Artifact(value)
    }
}

impl From<X64TailWorkerRootCompatibilityError> for X64TailWorkerRootSymbolError {
    fn from(value: X64TailWorkerRootCompatibilityError) -> Self {
        Self::Compatibility(value)
    }
}

struct LoadSegment {
    file_offset: u64,
    virtual_address: u64,
    file_size: u64,
    flags: u32,
}

struct DynamicSegment {
    file_offset: u64,
    file_size: u64,
}

struct DynamicTables {
    string_address: u64,
    string_bytes: u64,
    symbol_address: u64,
    version_address: u64,
    sysv_hash_address: Option<u64>,
    gnu_hash_address: Option<u64>,
}

struct SysvHashTable {
    address: u64,
    buckets: Vec<u32>,
    chains: Vec<u32>,
}

struct GnuHashTable {
    address: u64,
    symbol_offset: u32,
    bloom_shift: u32,
    bloom: Vec<u64>,
    buckets: Vec<u32>,
    chains: Vec<u32>,
}

#[allow(clippy::too_many_arguments)]
pub fn emit_x64_tail_worker_root_symbol_evidence(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure_evidence: &X64TailWorkerDependencyClosureEvidence,
    dependency_version_evidence: &X64TailWorkerDependencyVersionEvidence,
    definition_evidence: &X64TailWorkerDependencyDefinitionEvidence,
    root_version_evidence: &X64TailWorkerRootVersionEvidence,
    root_compatibility_evidence: &X64TailWorkerRootCompatibilityEvidence,
) -> Result<X64TailWorkerRootSymbolEvidence, X64TailWorkerRootSymbolError> {
    if x64_tail_worker_root_symbol_policy_hash() != X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT {
        return Err(X64TailWorkerRootSymbolError::Invalid("policy root"));
    }
    verify_x64_tail_worker_root_compatibility(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
        dynamic_evidence,
        closure_expectation,
        closure_evidence,
        dependency_version_evidence,
        definition_evidence,
        root_version_evidence,
        root_compatibility_evidence,
    )?;
    let verified_artifact = verify_x64_tail_worker_artifact(artifact)?;
    let bytes = x64_tail_worker_artifact_bytes(&verified_artifact)?;
    let object = decode_symbol_object(
        &bytes,
        artifact.expectation().artifact_hash(),
        inventory,
        root_version_evidence,
        root_compatibility_evidence,
    )?;
    let symbol_count = object.symbol_count;
    let mut evidence = X64TailWorkerRootSymbolEvidence {
        schema_version: X64_TAIL_WORKER_ROOT_SYMBOL_SCHEMA_VERSION,
        policy_version: X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_VERSION,
        policy_hash: x64_tail_worker_root_symbol_policy_hash(),
        artifact_policy_hash: X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT,
        artifact_hash: artifact.expectation().artifact_hash(),
        inventory_policy_hash: X64_TAIL_WORKER_ELF_POLICY_ROOT,
        inventory_evidence_hash: inventory.evidence_hash(),
        root_version_policy_hash: X64_TAIL_WORKER_ROOT_VERSION_POLICY_ROOT,
        root_version_evidence_hash: root_version_evidence.evidence_hash(),
        root_compatibility_policy_hash: X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_ROOT,
        root_compatibility_evidence_hash: root_compatibility_evidence.evidence_hash(),
        symbol_count,
        object,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = x64_tail_worker_root_symbol_evidence_hash(&evidence);
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_x64_tail_worker_root_symbol_evidence<'evidence>(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure_evidence: &X64TailWorkerDependencyClosureEvidence,
    dependency_version_evidence: &X64TailWorkerDependencyVersionEvidence,
    definition_evidence: &X64TailWorkerDependencyDefinitionEvidence,
    root_version_evidence: &X64TailWorkerRootVersionEvidence,
    root_compatibility_evidence: &X64TailWorkerRootCompatibilityEvidence,
    evidence: &'evidence X64TailWorkerRootSymbolEvidence,
) -> Result<VerifiedX64TailWorkerRootSymbols<'evidence>, X64TailWorkerRootSymbolError> {
    preflight_symbol_evidence(
        artifact,
        inventory,
        root_version_evidence,
        root_compatibility_evidence,
        evidence,
    )?;
    let expected = emit_x64_tail_worker_root_symbol_evidence(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
        dynamic_evidence,
        closure_expectation,
        closure_evidence,
        dependency_version_evidence,
        definition_evidence,
        root_version_evidence,
        root_compatibility_evidence,
    )?;
    if &expected != evidence
        || x64_tail_worker_root_symbol_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerRootSymbolError::EvidenceMismatch);
    }
    Ok(VerifiedX64TailWorkerRootSymbols { evidence })
}

fn decode_symbol_object(
    bytes: &[u8],
    artifact_hash: SemanticHash,
    inventory: &X64TailWorkerElfEvidence,
    root_versions: &X64TailWorkerRootVersionEvidence,
    root_compatibility: &X64TailWorkerRootCompatibilityEvidence,
) -> Result<X64TailWorkerRootSymbolObjectEvidence, X64TailWorkerRootSymbolError> {
    if inventory.artifact_hash() != artifact_hash
        || root_versions.artifact_hash() != artifact_hash
        || root_compatibility.root_version_evidence_hash() != root_versions.evidence_hash()
    {
        return Err(X64TailWorkerRootSymbolError::EvidenceMismatch);
    }
    let (loads, dynamic) = decode_layout(bytes)?;
    let tables = decode_dynamic_symbol_tags(bytes, &dynamic)?;
    if tables.string_bytes > X64_TAIL_WORKER_ROOT_SYMBOL_MAX_STRING_TABLE_BYTES {
        return Err(X64TailWorkerRootSymbolError::Limit {
            field: "string table bytes",
            limit: X64_TAIL_WORKER_ROOT_SYMBOL_MAX_STRING_TABLE_BYTES,
            actual: tables.string_bytes,
        });
    }
    let strings = map_virtual_readonly_range(
        bytes,
        &loads,
        tables.string_address,
        tables.string_bytes,
        "dynamic string table",
    )?;
    let sysv = tables
        .sysv_hash_address
        .map(|address| decode_sysv_hash(bytes, &loads, address))
        .transpose()?;
    let gnu = tables
        .gnu_hash_address
        .map(|address| decode_gnu_hash(bytes, &loads, address))
        .transpose()?;
    let symbol_count = match (&sysv, &gnu) {
        (Some(sysv), Some(gnu)) if sysv.chains.len() == gnu_symbol_count(gnu)? => sysv.chains.len(),
        (Some(_), Some(_)) => {
            return Err(X64TailWorkerRootSymbolError::Invalid(
                "hash symbol count disagreement",
            ));
        }
        (Some(sysv), None) => sysv.chains.len(),
        (None, Some(gnu)) => gnu_symbol_count(gnu)?,
        (None, None) => {
            return Err(X64TailWorkerRootSymbolError::Invalid(
                "missing dynamic hash table",
            ));
        }
    };
    if symbol_count == 0 || symbol_count > usize::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_SYMBOLS) {
        return Err(X64TailWorkerRootSymbolError::Limit {
            field: "dynamic symbols",
            limit: u64::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_SYMBOLS),
            actual: u64::try_from(symbol_count).unwrap_or(u64::MAX),
        });
    }
    let symbols = decode_symbols(
        bytes,
        &loads,
        strings,
        &tables,
        symbol_count,
        root_versions,
        root_compatibility,
    )?;
    if let Some(sysv) = &sysv {
        validate_sysv_hash(sysv, &symbols)?;
    }
    if let Some(gnu) = &gnu {
        validate_gnu_hash(gnu, &symbols)?;
    }

    let mut evidence = X64TailWorkerRootSymbolObjectEvidence {
        artifact_hash,
        inventory_evidence_hash: inventory.evidence_hash(),
        root_version_evidence_hash: root_versions.evidence_hash(),
        root_compatibility_evidence_hash: root_compatibility.evidence_hash(),
        symbol_table_address: tables.symbol_address,
        string_table_address: tables.string_address,
        string_table_bytes: tables.string_bytes,
        version_table_address: tables.version_address,
        sysv_hash_address: sysv.as_ref().map(|value| value.address),
        sysv_buckets: sysv
            .as_ref()
            .map_or_else(Vec::new, |value| value.buckets.clone()),
        sysv_chains: sysv
            .as_ref()
            .map_or_else(Vec::new, |value| value.chains.clone()),
        gnu_hash_address: gnu.as_ref().map(|value| value.address),
        gnu_symbol_offset: gnu.as_ref().map_or(0, |value| value.symbol_offset),
        gnu_bloom_shift: gnu.as_ref().map_or(0, |value| value.bloom_shift),
        gnu_bloom: gnu
            .as_ref()
            .map_or_else(Vec::new, |value| value.bloom.clone()),
        gnu_buckets: gnu
            .as_ref()
            .map_or_else(Vec::new, |value| value.buckets.clone()),
        gnu_chains: gnu
            .as_ref()
            .map_or_else(Vec::new, |value| value.chains.clone()),
        symbol_count: u16::try_from(symbol_count)
            .map_err(|_| X64TailWorkerRootSymbolError::Overflow("symbol count"))?,
        symbols,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = symbol_object_evidence_hash(&evidence);
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)]
fn decode_symbols(
    bytes: &[u8],
    loads: &[LoadSegment],
    strings: &[u8],
    tables: &DynamicTables,
    symbol_count: usize,
    root_versions: &X64TailWorkerRootVersionEvidence,
    root_compatibility: &X64TailWorkerRootCompatibilityEvidence,
) -> Result<Vec<X64TailWorkerRootSymbolRecordEvidence>, X64TailWorkerRootSymbolError> {
    let mut symbols = Vec::with_capacity(symbol_count);
    for ordinal in 0..symbol_count {
        let ordinal_u64 = u64::try_from(ordinal)
            .map_err(|_| X64TailWorkerRootSymbolError::Overflow("symbol ordinal"))?;
        let symbol_address = tables
            .symbol_address
            .checked_add(ordinal_u64 * ELF64_SYMBOL_BYTES)
            .ok_or(X64TailWorkerRootSymbolError::Overflow("symbol address"))?;
        let (record, file_offset) = map_virtual_readonly_record(
            bytes,
            loads,
            symbol_address,
            ELF64_SYMBOL_BYTES,
            "dynamic symbol record",
        )?;
        let version_address = tables
            .version_address
            .checked_add(ordinal_u64 * VERSYM_BYTES)
            .ok_or(X64TailWorkerRootSymbolError::Overflow("version address"))?;
        let (version_record, _) = map_virtual_readonly_record(
            bytes,
            loads,
            version_address,
            VERSYM_BYTES,
            "version symbol record",
        )?;
        if ordinal == 0 && (record.iter().any(|byte| *byte != 0) || version_record != [0, 0]) {
            return Err(X64TailWorkerRootSymbolError::Invalid("STN_UNDEF record"));
        }
        let name_offset = read_u32(record, 0, "symbol name offset")?;
        let info = record[4];
        let other = record[5];
        let binding = info >> 4;
        let symbol_type = info & 0x0f;
        let visibility = other & 0x03;
        let section_index = read_u16(record, 6, "symbol section index")?;
        let value = read_u64(record, 8, "symbol value")?;
        let size = read_u64(record, 16, "symbol size")?;
        validate_symbol_fields(binding, symbol_type, other, section_index)?;
        let name = decode_symbol_name(strings, tables.string_bytes, name_offset)?;
        let version_word = read_u16(version_record, 0, "version word")?;
        let version_index = version_word & VERSYM_INDEX_MASK;
        let version_hidden = version_word & VERSYM_HIDDEN != 0;
        let (
            namespace_kind,
            namespace_provider_ordinal,
            namespace_record_ordinal,
            namespace_auxiliary_ordinal,
            namespace_evidence_hash,
            compatibility_binding_evidence_hash,
        ) = resolve_namespace(
            version_index,
            version_hidden,
            section_index,
            root_versions,
            root_compatibility,
        )?;
        let mut evidence = X64TailWorkerRootSymbolRecordEvidence {
            ordinal: u16::try_from(ordinal)
                .map_err(|_| X64TailWorkerRootSymbolError::Overflow("symbol ordinal"))?,
            file_offset,
            name_offset,
            sysv_name_hash: elf_hash(name.as_bytes()),
            gnu_name_hash: gnu_hash(name.as_bytes()),
            name,
            binding,
            symbol_type,
            visibility,
            section_index,
            value,
            size,
            version_word,
            version_index,
            version_hidden,
            namespace_kind,
            namespace_provider_ordinal,
            namespace_record_ordinal,
            namespace_auxiliary_ordinal,
            namespace_evidence_hash,
            compatibility_binding_evidence_hash,
            evidence_hash: SemanticHash::ZERO,
        };
        evidence.evidence_hash = symbol_record_evidence_hash(&evidence);
        symbols.push(evidence);
    }
    Ok(symbols)
}

fn resolve_namespace(
    version_index: u16,
    hidden: bool,
    section_index: u16,
    root_versions: &X64TailWorkerRootVersionEvidence,
    root_compatibility: &X64TailWorkerRootCompatibilityEvidence,
) -> Result<
    (
        X64TailWorkerRootSymbolNamespaceKind,
        u16,
        u16,
        u16,
        SemanticHash,
        SemanticHash,
    ),
    X64TailWorkerRootSymbolError,
> {
    match version_index {
        0 if !hidden => Ok((
            X64TailWorkerRootSymbolNamespaceKind::Local,
            u16::MAX,
            u16::MAX,
            u16::MAX,
            SemanticHash::ZERO,
            SemanticHash::ZERO,
        )),
        1 if !hidden => Ok((
            X64TailWorkerRootSymbolNamespaceKind::Global,
            u16::MAX,
            u16::MAX,
            u16::MAX,
            SemanticHash::ZERO,
            SemanticHash::ZERO,
        )),
        0 | 1 => Err(X64TailWorkerRootSymbolError::Invalid(
            "hidden reserved version index",
        )),
        index if index < VERSYM_LORESERVE && section_index == SHN_UNDEF => {
            let mut matches = root_versions.requirements().iter().flat_map(|requirement| {
                requirement
                    .auxiliaries()
                    .iter()
                    .filter(move |auxiliary| auxiliary.version_index() == index)
                    .map(move |auxiliary| (requirement, auxiliary))
            });
            let (requirement, auxiliary) = matches.next().ok_or(
                X64TailWorkerRootSymbolError::Invalid("undefined symbol version index"),
            )?;
            if matches.next().is_some() {
                return Err(X64TailWorkerRootSymbolError::Invalid(
                    "ambiguous undefined symbol version index",
                ));
            }
            let mut compatibility_matches =
                root_compatibility.bindings().iter().filter(|binding| {
                    binding.root_requirement_ordinal() == requirement.ordinal()
                        && binding.root_auxiliary_ordinal() == auxiliary.ordinal()
                        && binding.requirement_version_index() == auxiliary.version_index()
                        && binding.provider_ordinal() == requirement.provider_ordinal()
                        && binding.root_requirement_evidence_hash() == requirement.evidence_hash()
                        && binding.root_auxiliary_evidence_hash() == auxiliary.evidence_hash()
                });
            let compatibility =
                compatibility_matches
                    .next()
                    .ok_or(X64TailWorkerRootSymbolError::Invalid(
                        "root compatibility version index",
                    ))?;
            if compatibility_matches.next().is_some() {
                return Err(X64TailWorkerRootSymbolError::Invalid(
                    "ambiguous root compatibility version index",
                ));
            }
            Ok((
                X64TailWorkerRootSymbolNamespaceKind::Requirement,
                requirement.provider_ordinal(),
                requirement.ordinal(),
                auxiliary.ordinal(),
                auxiliary.evidence_hash(),
                compatibility.evidence_hash(),
            ))
        }
        index if index < VERSYM_LORESERVE => Err(X64TailWorkerRootSymbolError::Invalid(
            "defined root symbol version index",
        )),
        _ => Err(X64TailWorkerRootSymbolError::Invalid(
            "reserved version index",
        )),
    }
}

fn decode_sysv_hash(
    bytes: &[u8],
    loads: &[LoadSegment],
    address: u64,
) -> Result<SysvHashTable, X64TailWorkerRootSymbolError> {
    let (header, _) = map_virtual_readonly_record(
        bytes,
        loads,
        address,
        SYSV_HASH_HEADER_BYTES,
        "System V hash header",
    )?;
    let bucket_count = read_u32(header, 0, "System V bucket count")?;
    let chain_count = read_u32(header, 4, "System V chain count")?;
    validate_hash_count(bucket_count, "System V buckets")?;
    validate_symbol_count(chain_count, "System V chains")?;
    let bucket_address = address.checked_add(SYSV_HASH_HEADER_BYTES).ok_or(
        X64TailWorkerRootSymbolError::Overflow("System V bucket address"),
    )?;
    let buckets = read_u32_vector(
        bytes,
        loads,
        bucket_address,
        bucket_count,
        "System V buckets",
    )?;
    let chain_address = bucket_address
        .checked_add(u64::from(bucket_count) * 4)
        .ok_or(X64TailWorkerRootSymbolError::Overflow(
            "System V chain address",
        ))?;
    let chains = read_u32_vector(bytes, loads, chain_address, chain_count, "System V chains")?;
    Ok(SysvHashTable {
        address,
        buckets,
        chains,
    })
}

fn decode_gnu_hash(
    bytes: &[u8],
    loads: &[LoadSegment],
    address: u64,
) -> Result<GnuHashTable, X64TailWorkerRootSymbolError> {
    let (header, _) = map_virtual_readonly_record(
        bytes,
        loads,
        address,
        GNU_HASH_HEADER_BYTES,
        "GNU hash header",
    )?;
    let bucket_count = read_u32(header, 0, "GNU bucket count")?;
    let symbol_offset = read_u32(header, 4, "GNU symbol offset")?;
    let bloom_count = read_u32(header, 8, "GNU bloom count")?;
    let bloom_shift = read_u32(header, 12, "GNU bloom shift")?;
    validate_hash_count(bucket_count, "GNU buckets")?;
    validate_symbol_count(symbol_offset, "GNU symbol offset")?;
    if bloom_count == 0
        || bloom_count > u32::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_GNU_BLOOM_WORDS)
        || !bloom_count.is_power_of_two()
    {
        return Err(X64TailWorkerRootSymbolError::Limit {
            field: "GNU bloom words",
            limit: u64::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_GNU_BLOOM_WORDS),
            actual: u64::from(bloom_count),
        });
    }
    if bloom_shift >= 64 {
        return Err(X64TailWorkerRootSymbolError::Invalid("GNU bloom shift"));
    }
    let bloom_address = address
        .checked_add(GNU_HASH_HEADER_BYTES)
        .ok_or(X64TailWorkerRootSymbolError::Overflow("GNU bloom address"))?;
    let bloom = read_u64_vector(bytes, loads, bloom_address, bloom_count, "GNU bloom words")?;
    let bucket_address = bloom_address
        .checked_add(u64::from(bloom_count) * 8)
        .ok_or(X64TailWorkerRootSymbolError::Overflow("GNU bucket address"))?;
    let buckets = read_u32_vector(bytes, loads, bucket_address, bucket_count, "GNU buckets")?;
    let chain_address = bucket_address
        .checked_add(u64::from(bucket_count) * 4)
        .ok_or(X64TailWorkerRootSymbolError::Overflow("GNU chain address"))?;

    let mut maximum_terminal = symbol_offset.checked_sub(1);
    for bucket in buckets.iter().copied().filter(|bucket| *bucket != 0) {
        if bucket < symbol_offset || bucket >= u32::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_SYMBOLS) {
            return Err(X64TailWorkerRootSymbolError::Invalid(
                "GNU bucket symbol ordinal",
            ));
        }
        let mut ordinal = bucket;
        let mut steps = 0u32;
        loop {
            steps = steps
                .checked_add(1)
                .ok_or(X64TailWorkerRootSymbolError::Overflow("GNU chain steps"))?;
            if steps > u32::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_SYMBOLS) {
                return Err(X64TailWorkerRootSymbolError::Limit {
                    field: "GNU chain steps",
                    limit: u64::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_SYMBOLS),
                    actual: u64::from(steps),
                });
            }
            let chain_ordinal = ordinal
                .checked_sub(symbol_offset)
                .ok_or(X64TailWorkerRootSymbolError::Overflow("GNU chain ordinal"))?;
            let chain_entry_address = chain_address
                .checked_add(u64::from(chain_ordinal) * 4)
                .ok_or(X64TailWorkerRootSymbolError::Overflow(
                    "GNU chain entry address",
                ))?;
            let (entry, _) = map_virtual_readonly_record(
                bytes,
                loads,
                chain_entry_address,
                4,
                "GNU chain entry",
            )?;
            let value = read_u32(entry, 0, "GNU chain value")?;
            if value & 1 != 0 {
                maximum_terminal = Some(maximum_terminal.map_or(ordinal, |old| old.max(ordinal)));
                break;
            }
            ordinal = ordinal
                .checked_add(1)
                .ok_or(X64TailWorkerRootSymbolError::Overflow(
                    "GNU chain symbol ordinal",
                ))?;
            if ordinal >= u32::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_SYMBOLS) {
                return Err(X64TailWorkerRootSymbolError::Limit {
                    field: "GNU chain symbol ordinal",
                    limit: u64::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_SYMBOLS),
                    actual: u64::from(ordinal),
                });
            }
        }
    }
    let symbol_count =
        maximum_terminal.map_or(symbol_offset, |terminal| terminal.saturating_add(1));
    validate_symbol_count(symbol_count, "GNU symbol extent")?;
    let chain_count = symbol_count
        .checked_sub(symbol_offset)
        .ok_or(X64TailWorkerRootSymbolError::Overflow("GNU chain count"))?;
    let chains = read_u32_vector(bytes, loads, chain_address, chain_count, "GNU chains")?;
    Ok(GnuHashTable {
        address,
        symbol_offset,
        bloom_shift,
        bloom,
        buckets,
        chains,
    })
}

fn gnu_symbol_count(table: &GnuHashTable) -> Result<usize, X64TailWorkerRootSymbolError> {
    usize::try_from(table.symbol_offset)
        .ok()
        .and_then(|offset| offset.checked_add(table.chains.len()))
        .ok_or(X64TailWorkerRootSymbolError::Overflow("GNU symbol count"))
}

fn validate_sysv_hash(
    table: &SysvHashTable,
    symbols: &[X64TailWorkerRootSymbolRecordEvidence],
) -> Result<(), X64TailWorkerRootSymbolError> {
    if table.chains.len() != symbols.len() || table.buckets.is_empty() {
        return Err(X64TailWorkerRootSymbolError::Invalid("System V hash shape"));
    }
    let mut buckets = vec![0u32; table.buckets.len()];
    let mut chains = vec![0u32; symbols.len()];
    let mut tails = vec![0usize; table.buckets.len()];
    for (ordinal, symbol) in symbols.iter().enumerate().skip(1) {
        let bucket = usize::try_from(symbol.sysv_name_hash).unwrap_or(usize::MAX) % buckets.len();
        let ordinal_u32 = u32::try_from(ordinal)
            .map_err(|_| X64TailWorkerRootSymbolError::Overflow("System V ordinal"))?;
        if buckets[bucket] == 0 {
            buckets[bucket] = ordinal_u32;
        } else {
            chains[tails[bucket]] = ordinal_u32;
        }
        tails[bucket] = ordinal;
    }
    if table.buckets != buckets || table.chains != chains {
        return Err(X64TailWorkerRootSymbolError::Invalid(
            "System V hash reconstruction",
        ));
    }
    Ok(())
}

fn validate_gnu_hash(
    table: &GnuHashTable,
    symbols: &[X64TailWorkerRootSymbolRecordEvidence],
) -> Result<(), X64TailWorkerRootSymbolError> {
    let symbol_offset = usize::try_from(table.symbol_offset)
        .map_err(|_| X64TailWorkerRootSymbolError::Overflow("GNU symbol offset"))?;
    if symbol_offset > symbols.len()
        || symbols[symbol_offset..]
            .iter()
            .any(|symbol| symbol.binding == STB_LOCAL)
        || table.buckets.is_empty()
        || table.bloom.is_empty()
    {
        return Err(X64TailWorkerRootSymbolError::Invalid(
            "GNU unhashed/hashed partition",
        ));
    }
    let mut bloom = vec![0u64; table.bloom.len()];
    let mut buckets = vec![0u32; table.buckets.len()];
    let mut chains = Vec::with_capacity(symbols.len().saturating_sub(symbol_offset));
    let mut seen_bucket = vec![false; buckets.len()];
    let mut current_bucket = None;
    for (ordinal, symbol) in symbols.iter().enumerate().skip(symbol_offset) {
        let hash = symbol.gnu_name_hash;
        let bucket = usize::try_from(hash).unwrap_or(usize::MAX) % buckets.len();
        if current_bucket != Some(bucket) {
            if seen_bucket[bucket] {
                return Err(X64TailWorkerRootSymbolError::Invalid(
                    "noncontiguous GNU bucket",
                ));
            }
            seen_bucket[bucket] = true;
            current_bucket = Some(bucket);
            buckets[bucket] = u32::try_from(ordinal)
                .map_err(|_| X64TailWorkerRootSymbolError::Overflow("GNU bucket ordinal"))?;
        }
        let word = (usize::try_from(hash / 64).unwrap_or(usize::MAX)) % bloom.len();
        let first_bit = hash % 64;
        let second_bit = (hash >> table.bloom_shift) % 64;
        bloom[word] |= (1u64 << first_bit) | (1u64 << second_bit);
        let terminal = symbols.get(ordinal + 1).is_none_or(|next| {
            usize::try_from(next.gnu_name_hash).unwrap_or(usize::MAX) % buckets.len() != bucket
        });
        chains.push((hash & !1) | u32::from(terminal));
    }
    if table.bloom != bloom || table.buckets != buckets || table.chains != chains {
        return Err(X64TailWorkerRootSymbolError::Invalid(
            "GNU hash reconstruction",
        ));
    }
    Ok(())
}

fn validate_symbol_fields(
    binding: u8,
    symbol_type: u8,
    other: u8,
    section_index: u16,
) -> Result<(), X64TailWorkerRootSymbolError> {
    if !matches!(binding, STB_LOCAL | STB_GLOBAL | STB_WEAK | STB_GNU_UNIQUE) {
        return Err(X64TailWorkerRootSymbolError::Invalid("symbol binding"));
    }
    if !matches!(
        symbol_type,
        STT_NOTYPE
            | STT_OBJECT
            | STT_FUNC
            | STT_SECTION
            | STT_FILE
            | STT_COMMON
            | STT_TLS
            | STT_GNU_IFUNC
    ) {
        return Err(X64TailWorkerRootSymbolError::Invalid("symbol type"));
    }
    if other & !0x03 != 0 {
        return Err(X64TailWorkerRootSymbolError::Invalid("symbol visibility"));
    }
    if section_index >= SHN_LORESERVE && section_index != SHN_ABS && section_index != SHN_COMMON {
        return Err(X64TailWorkerRootSymbolError::Invalid(
            "symbol section index",
        ));
    }
    Ok(())
}

fn decode_layout(
    bytes: &[u8],
) -> Result<(Vec<LoadSegment>, DynamicSegment), X64TailWorkerRootSymbolError> {
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
        return Err(X64TailWorkerRootSymbolError::Invalid("ELF identity"));
    }
    let program_offset = read_u64(bytes, 32, "program-header offset")?;
    let program_count = read_u16(bytes, 56, "program-header count")?;
    if program_count == 0 || program_count > X64_TAIL_WORKER_ROOT_SYMBOL_MAX_PROGRAM_HEADERS {
        return Err(X64TailWorkerRootSymbolError::Limit {
            field: "program headers",
            limit: u64::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_PROGRAM_HEADERS),
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
            .ok_or(X64TailWorkerRootSymbolError::Overflow("program header"))?;
        let kind = read_u32(bytes, offset, "program-header type")?;
        let flags = read_u32(bytes, offset + 4, "program-header flags")?;
        let file_offset = read_u64(bytes, offset + 8, "segment offset")?;
        let virtual_address = read_u64(bytes, offset + 16, "segment address")?;
        let file_size = read_u64(bytes, offset + 32, "segment file size")?;
        let memory_size = read_u64(bytes, offset + 40, "segment memory size")?;
        if file_size > memory_size {
            return Err(X64TailWorkerRootSymbolError::Invalid("segment sizes"));
        }
        require_range(bytes, file_offset, file_size, "segment file range")?;
        match kind {
            PT_LOAD => loads.push(LoadSegment {
                file_offset,
                virtual_address,
                file_size,
                flags,
            }),
            PT_DYNAMIC if dynamic.is_some() => {
                return Err(X64TailWorkerRootSymbolError::Invalid(
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
    if loads.is_empty() || loads.len() > usize::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_LOAD_SEGMENTS)
    {
        return Err(X64TailWorkerRootSymbolError::Limit {
            field: "load segments",
            limit: u64::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_LOAD_SEGMENTS),
            actual: u64::try_from(loads.len()).unwrap_or(u64::MAX),
        });
    }
    Ok((
        loads,
        dynamic.ok_or(X64TailWorkerRootSymbolError::Invalid(
            "missing dynamic segment",
        ))?,
    ))
}

fn decode_dynamic_symbol_tags(
    bytes: &[u8],
    dynamic: &DynamicSegment,
) -> Result<DynamicTables, X64TailWorkerRootSymbolError> {
    if dynamic.file_size == 0 || !dynamic.file_size.is_multiple_of(DYNAMIC_ENTRY_BYTES) {
        return Err(X64TailWorkerRootSymbolError::Invalid(
            "dynamic segment size",
        ));
    }
    let entry_count = dynamic.file_size / DYNAMIC_ENTRY_BYTES;
    if entry_count > u64::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_DYNAMIC_ENTRIES) {
        return Err(X64TailWorkerRootSymbolError::Limit {
            field: "dynamic entries",
            limit: u64::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_DYNAMIC_ENTRIES),
            actual: entry_count,
        });
    }
    let mut string_address = None;
    let mut string_bytes = None;
    let mut symbol_address = None;
    let mut symbol_entry_bytes = None;
    let mut version_address = None;
    let mut sysv_hash_address = None;
    let mut gnu_hash_address = None;
    let mut terminated = false;
    for ordinal in 0..entry_count {
        let offset = dynamic
            .file_offset
            .checked_add(ordinal * DYNAMIC_ENTRY_BYTES)
            .ok_or(X64TailWorkerRootSymbolError::Overflow("dynamic entry"))?;
        let tag = read_i64(bytes, offset, "dynamic tag")?;
        let value = read_u64(bytes, offset + 8, "dynamic value")?;
        if terminated {
            if tag != DT_NULL || value != 0 {
                return Err(X64TailWorkerRootSymbolError::Invalid(
                    "dynamic trailing entries",
                ));
            }
            continue;
        }
        match tag {
            DT_NULL => {
                if value != 0 {
                    return Err(X64TailWorkerRootSymbolError::Invalid("dynamic terminator"));
                }
                terminated = true;
            }
            DT_HASH => set_once(&mut sysv_hash_address, value, "DT_HASH")?,
            DT_STRTAB => set_once(&mut string_address, value, "DT_STRTAB")?,
            DT_SYMTAB => set_once(&mut symbol_address, value, "DT_SYMTAB")?,
            DT_STRSZ => set_once(&mut string_bytes, value, "DT_STRSZ")?,
            DT_SYMENT => set_once(&mut symbol_entry_bytes, value, "DT_SYMENT")?,
            DT_GNU_HASH => set_once(&mut gnu_hash_address, value, "DT_GNU_HASH")?,
            DT_VERSYM => set_once(&mut version_address, value, "DT_VERSYM")?,
            _ => {}
        }
    }
    if !terminated {
        return Err(X64TailWorkerRootSymbolError::Invalid(
            "missing dynamic terminator",
        ));
    }
    if symbol_entry_bytes != Some(ELF64_SYMBOL_BYTES) {
        return Err(X64TailWorkerRootSymbolError::Invalid("DT_SYMENT"));
    }
    let tables = DynamicTables {
        string_address: string_address
            .ok_or(X64TailWorkerRootSymbolError::Invalid("missing DT_STRTAB"))?,
        string_bytes: string_bytes
            .ok_or(X64TailWorkerRootSymbolError::Invalid("missing DT_STRSZ"))?,
        symbol_address: symbol_address
            .ok_or(X64TailWorkerRootSymbolError::Invalid("missing DT_SYMTAB"))?,
        version_address: version_address
            .ok_or(X64TailWorkerRootSymbolError::Invalid("missing DT_VERSYM"))?,
        sysv_hash_address,
        gnu_hash_address,
    };
    if tables.string_bytes == 0
        || tables.string_address == 0
        || tables.symbol_address == 0
        || tables.version_address == 0
        || (tables.sysv_hash_address.is_none() && tables.gnu_hash_address.is_none())
    {
        return Err(X64TailWorkerRootSymbolError::Invalid(
            "dynamic symbol tag values",
        ));
    }
    Ok(tables)
}

fn preflight_symbol_evidence(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    root_versions: &X64TailWorkerRootVersionEvidence,
    root_compatibility: &X64TailWorkerRootCompatibilityEvidence,
    evidence: &X64TailWorkerRootSymbolEvidence,
) -> Result<(), X64TailWorkerRootSymbolError> {
    if evidence.schema_version != X64_TAIL_WORKER_ROOT_SYMBOL_SCHEMA_VERSION
        || evidence.policy_version != X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_VERSION
        || evidence.policy_hash != X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT
        || evidence.policy_hash != x64_tail_worker_root_symbol_policy_hash()
        || evidence.artifact_policy_hash != X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT
        || evidence.artifact_hash != artifact.expectation().artifact_hash()
        || evidence.inventory_policy_hash != X64_TAIL_WORKER_ELF_POLICY_ROOT
        || evidence.inventory_evidence_hash != inventory.evidence_hash()
        || evidence.root_version_policy_hash != X64_TAIL_WORKER_ROOT_VERSION_POLICY_ROOT
        || evidence.root_version_evidence_hash != root_versions.evidence_hash()
        || evidence.root_compatibility_policy_hash != X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_ROOT
        || evidence.root_compatibility_evidence_hash != root_compatibility.evidence_hash()
        || evidence.symbol_count != evidence.object.symbol_count
        || evidence.symbol_count > X64_TAIL_WORKER_ROOT_SYMBOL_MAX_SYMBOLS
        || x64_tail_worker_root_symbol_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerRootSymbolError::EvidenceMismatch);
    }
    let object = &evidence.object;
    if object.artifact_hash != evidence.artifact_hash
        || object.inventory_evidence_hash != inventory.evidence_hash()
        || object.root_version_evidence_hash != root_versions.evidence_hash()
        || object.root_compatibility_evidence_hash != root_compatibility.evidence_hash()
        || usize::from(object.symbol_count) != object.symbols.len()
        || object.sysv_buckets.len() > usize::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_HASH_BUCKETS)
        || object.sysv_chains.len() > usize::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_SYMBOLS)
        || object.gnu_bloom.len() > usize::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_GNU_BLOOM_WORDS)
        || object.gnu_buckets.len() > usize::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_HASH_BUCKETS)
        || object.gnu_chains.len() > usize::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_SYMBOLS)
        || symbol_object_evidence_hash(object) != object.evidence_hash
    {
        return Err(X64TailWorkerRootSymbolError::EvidenceMismatch);
    }
    for (symbol_ordinal, symbol) in object.symbols.iter().enumerate() {
        let expected_namespace = resolve_namespace(
            symbol.version_index,
            symbol.version_hidden,
            symbol.section_index,
            root_versions,
            root_compatibility,
        )?;
        if symbol.ordinal != u16::try_from(symbol_ordinal).unwrap_or(u16::MAX)
            || expected_namespace
                != (
                    symbol.namespace_kind,
                    symbol.namespace_provider_ordinal,
                    symbol.namespace_record_ordinal,
                    symbol.namespace_auxiliary_ordinal,
                    symbol.namespace_evidence_hash,
                    symbol.compatibility_binding_evidence_hash,
                )
            || symbol_record_evidence_hash(symbol) != symbol.evidence_hash
        {
            return Err(X64TailWorkerRootSymbolError::EvidenceMismatch);
        }
    }
    Ok(())
}

fn map_virtual_readonly_record<'bytes>(
    bytes: &'bytes [u8],
    loads: &[LoadSegment],
    address: u64,
    size: u64,
    field: &'static str,
) -> Result<(&'bytes [u8], u64), X64TailWorkerRootSymbolError> {
    let end = address
        .checked_add(size)
        .ok_or(X64TailWorkerRootSymbolError::Overflow(field))?;
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
        .ok_or(X64TailWorkerRootSymbolError::Invalid(field))?;
    if matches.next().is_some() {
        return Err(X64TailWorkerRootSymbolError::Invalid(
            "ambiguous virtual mapping",
        ));
    }
    let file_offset = load
        .file_offset
        .checked_add(address - load.virtual_address)
        .ok_or(X64TailWorkerRootSymbolError::Overflow(field))?;
    Ok((slice_range(bytes, file_offset, size, field)?, file_offset))
}

fn map_virtual_readonly_range<'bytes>(
    bytes: &'bytes [u8],
    loads: &[LoadSegment],
    address: u64,
    size: u64,
    field: &'static str,
) -> Result<&'bytes [u8], X64TailWorkerRootSymbolError> {
    map_virtual_readonly_record(bytes, loads, address, size, field).map(|(value, _)| value)
}

fn read_u32_vector(
    bytes: &[u8],
    loads: &[LoadSegment],
    address: u64,
    count: u32,
    field: &'static str,
) -> Result<Vec<u32>, X64TailWorkerRootSymbolError> {
    let size = u64::from(count)
        .checked_mul(4)
        .ok_or(X64TailWorkerRootSymbolError::Overflow(field))?;
    let value = map_virtual_readonly_range(bytes, loads, address, size, field)?;
    (0..count)
        .map(|ordinal| read_u32(value, u64::from(ordinal) * 4, field))
        .collect()
}

fn read_u64_vector(
    bytes: &[u8],
    loads: &[LoadSegment],
    address: u64,
    count: u32,
    field: &'static str,
) -> Result<Vec<u64>, X64TailWorkerRootSymbolError> {
    let size = u64::from(count)
        .checked_mul(8)
        .ok_or(X64TailWorkerRootSymbolError::Overflow(field))?;
    let value = map_virtual_readonly_range(bytes, loads, address, size, field)?;
    (0..count)
        .map(|ordinal| read_u64(value, u64::from(ordinal) * 8, field))
        .collect()
}

fn validate_hash_count(
    count: u32,
    field: &'static str,
) -> Result<(), X64TailWorkerRootSymbolError> {
    if count == 0 || count > u32::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_HASH_BUCKETS) {
        Err(X64TailWorkerRootSymbolError::Limit {
            field,
            limit: u64::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_HASH_BUCKETS),
            actual: u64::from(count),
        })
    } else {
        Ok(())
    }
}

fn validate_symbol_count(
    count: u32,
    field: &'static str,
) -> Result<(), X64TailWorkerRootSymbolError> {
    if count == 0 || count > u32::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_SYMBOLS) {
        Err(X64TailWorkerRootSymbolError::Limit {
            field,
            limit: u64::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_SYMBOLS),
            actual: u64::from(count),
        })
    } else {
        Ok(())
    }
}

fn decode_symbol_name(
    strings: &[u8],
    string_bytes: u64,
    offset: u32,
) -> Result<String, X64TailWorkerRootSymbolError> {
    if u64::from(offset) >= string_bytes {
        return Err(X64TailWorkerRootSymbolError::Invalid("symbol name offset"));
    }
    let start = usize::try_from(offset)
        .map_err(|_| X64TailWorkerRootSymbolError::Overflow("symbol name offset"))?;
    let retained = usize::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_NAME_BYTES)
        .min(strings.len().saturating_sub(start));
    let value = &strings[start..start + retained];
    let end =
        value
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(X64TailWorkerRootSymbolError::Invalid(
                "symbol name terminator",
            ))?;
    let name = &value[..end];
    if (offset != 0 && name.is_empty())
        || name.iter().any(|byte| !(0x21..=0x7e).contains(byte))
        || name.contains(&b'/')
        || name.contains(&b'\\')
    {
        return Err(X64TailWorkerRootSymbolError::Invalid("symbol name"));
    }
    std::str::from_utf8(name)
        .map(str::to_owned)
        .map_err(|_| X64TailWorkerRootSymbolError::Invalid("symbol name"))
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

fn gnu_hash(name: &[u8]) -> u32 {
    name.iter().fold(5381u32, |hash, byte| {
        hash.wrapping_mul(33).wrapping_add(u32::from(*byte))
    })
}

fn require_range(
    bytes: &[u8],
    offset: u64,
    size: u64,
    field: &'static str,
) -> Result<(), X64TailWorkerRootSymbolError> {
    let end = offset
        .checked_add(size)
        .ok_or(X64TailWorkerRootSymbolError::Overflow(field))?;
    if end > u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
        return Err(X64TailWorkerRootSymbolError::Invalid(field));
    }
    Ok(())
}

fn slice_range<'bytes>(
    bytes: &'bytes [u8],
    offset: u64,
    size: u64,
    field: &'static str,
) -> Result<&'bytes [u8], X64TailWorkerRootSymbolError> {
    require_range(bytes, offset, size, field)?;
    let start =
        usize::try_from(offset).map_err(|_| X64TailWorkerRootSymbolError::Overflow(field))?;
    let end = usize::try_from(offset + size)
        .map_err(|_| X64TailWorkerRootSymbolError::Overflow(field))?;
    Ok(&bytes[start..end])
}

fn read_u16(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<u16, X64TailWorkerRootSymbolError> {
    let value = slice_range(bytes, offset, 2, field)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<u32, X64TailWorkerRootSymbolError> {
    let value = slice_range(bytes, offset, 4, field)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<u64, X64TailWorkerRootSymbolError> {
    let value = slice_range(bytes, offset, 8, field)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn read_i64(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<i64, X64TailWorkerRootSymbolError> {
    Ok(read_u64(bytes, offset, field)? as i64)
}

fn set_once(
    slot: &mut Option<u64>,
    value: u64,
    field: &'static str,
) -> Result<(), X64TailWorkerRootSymbolError> {
    if slot.replace(value).is_some() {
        Err(X64TailWorkerRootSymbolError::Invalid(field))
    } else {
        Ok(())
    }
}

pub fn x64_tail_worker_root_symbol_policy_hash() -> SemanticHash {
    let mut bytes = Vec::with_capacity(1024);
    bytes.extend_from_slice(POLICY_DOMAIN);
    put_version(&mut bytes, X64_TAIL_WORKER_ROOT_SYMBOL_SCHEMA_VERSION);
    put_version(&mut bytes, X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_VERSION);
    put_hash(&mut bytes, X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT);
    put_hash(&mut bytes, X64_TAIL_WORKER_ELF_POLICY_ROOT);
    put_hash(&mut bytes, X64_TAIL_WORKER_ROOT_VERSION_POLICY_ROOT);
    put_hash(&mut bytes, X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_ROOT);
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_SYMBOL_MAX_PROGRAM_HEADERS);
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_SYMBOL_MAX_LOAD_SEGMENTS);
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_SYMBOL_MAX_DYNAMIC_ENTRIES);
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_SYMBOL_MAX_SYMBOLS);
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_SYMBOL_MAX_HASH_BUCKETS);
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_SYMBOL_MAX_GNU_BLOOM_WORDS);
    put_u64(
        &mut bytes,
        X64_TAIL_WORKER_ROOT_SYMBOL_MAX_STRING_TABLE_BYTES,
    );
    put_u16(&mut bytes, X64_TAIL_WORKER_ROOT_SYMBOL_MAX_NAME_BYTES);
    for value in [
        ELF_HEADER_BYTES,
        PROGRAM_HEADER_BYTES,
        u16::try_from(DYNAMIC_ENTRY_BYTES).unwrap_or(u16::MAX),
        u16::try_from(ELF64_SYMBOL_BYTES).unwrap_or(u16::MAX),
        u16::try_from(VERSYM_BYTES).unwrap_or(u16::MAX),
        u16::try_from(GNU_HASH_HEADER_BYTES).unwrap_or(u16::MAX),
        u16::try_from(SYSV_HASH_HEADER_BYTES).unwrap_or(u16::MAX),
        ET_DYN,
        EM_X86_64,
    ] {
        put_u16(&mut bytes, value);
    }
    for value in [PT_LOAD, PT_DYNAMIC, PF_W] {
        put_u32(&mut bytes, value);
    }
    for tag in [
        DT_HASH,
        DT_STRTAB,
        DT_SYMTAB,
        DT_STRSZ,
        DT_SYMENT,
        DT_GNU_HASH,
        DT_VERSYM,
    ] {
        put_u64(&mut bytes, tag as u64);
    }
    for value in [
        SHN_UNDEF,
        VERSYM_HIDDEN,
        VERSYM_INDEX_MASK,
        VERSYM_LORESERVE,
        SHN_LORESERVE,
        SHN_ABS,
        SHN_COMMON,
    ] {
        put_u16(&mut bytes, value);
    }
    bytes.extend_from_slice(&[
        STB_LOCAL,
        STB_GLOBAL,
        STB_WEAK,
        STB_GNU_UNIQUE,
        STT_NOTYPE,
        STT_OBJECT,
        STT_FUNC,
        STT_SECTION,
        STT_FILE,
        STT_COMMON,
        STT_TLS,
        STT_GNU_IFUNC,
        0x03,
        64,
    ]);
    put_u16(
        &mut bytes,
        u16::try_from(POLICY_CAPABILITIES.len()).unwrap_or(u16::MAX),
    );
    for capability in POLICY_CAPABILITIES {
        put_string(&mut bytes, capability);
    }
    SemanticHash(sha256(&bytes))
}

fn symbol_record_evidence_hash(evidence: &X64TailWorkerRootSymbolRecordEvidence) -> SemanticHash {
    let mut bytes = Vec::with_capacity(384);
    bytes.extend_from_slice(SYMBOL_DOMAIN);
    put_u16(&mut bytes, evidence.ordinal);
    put_u64(&mut bytes, evidence.file_offset);
    put_u32(&mut bytes, evidence.name_offset);
    put_string(&mut bytes, &evidence.name);
    put_u32(&mut bytes, evidence.sysv_name_hash);
    put_u32(&mut bytes, evidence.gnu_name_hash);
    bytes.extend_from_slice(&[evidence.binding, evidence.symbol_type, evidence.visibility]);
    put_u16(&mut bytes, evidence.section_index);
    put_u64(&mut bytes, evidence.value);
    put_u64(&mut bytes, evidence.size);
    put_u16(&mut bytes, evidence.version_word);
    put_u16(&mut bytes, evidence.version_index);
    bytes.push(u8::from(evidence.version_hidden));
    bytes.push(evidence.namespace_kind as u8);
    put_u16(&mut bytes, evidence.namespace_provider_ordinal);
    put_u16(&mut bytes, evidence.namespace_record_ordinal);
    put_u16(&mut bytes, evidence.namespace_auxiliary_ordinal);
    put_hash(&mut bytes, evidence.namespace_evidence_hash);
    put_hash(&mut bytes, evidence.compatibility_binding_evidence_hash);
    SemanticHash(sha256(&bytes))
}

fn symbol_object_evidence_hash(evidence: &X64TailWorkerRootSymbolObjectEvidence) -> SemanticHash {
    let mut bytes = Vec::with_capacity(1024 + evidence.symbols.len() * 32);
    bytes.extend_from_slice(OBJECT_DOMAIN);
    put_hash(&mut bytes, evidence.artifact_hash);
    put_hash(&mut bytes, evidence.inventory_evidence_hash);
    put_hash(&mut bytes, evidence.root_version_evidence_hash);
    put_hash(&mut bytes, evidence.root_compatibility_evidence_hash);
    put_u64(&mut bytes, evidence.symbol_table_address);
    put_u64(&mut bytes, evidence.string_table_address);
    put_u64(&mut bytes, evidence.string_table_bytes);
    put_u64(&mut bytes, evidence.version_table_address);
    put_optional_u64(&mut bytes, evidence.sysv_hash_address);
    put_u32_vector(&mut bytes, &evidence.sysv_buckets);
    put_u32_vector(&mut bytes, &evidence.sysv_chains);
    put_optional_u64(&mut bytes, evidence.gnu_hash_address);
    put_u32(&mut bytes, evidence.gnu_symbol_offset);
    put_u32(&mut bytes, evidence.gnu_bloom_shift);
    put_u64_vector(&mut bytes, &evidence.gnu_bloom);
    put_u32_vector(&mut bytes, &evidence.gnu_buckets);
    put_u32_vector(&mut bytes, &evidence.gnu_chains);
    put_u16(&mut bytes, evidence.symbol_count);
    for symbol in &evidence.symbols {
        put_hash(&mut bytes, symbol.evidence_hash);
    }
    SemanticHash(sha256(&bytes))
}

pub fn x64_tail_worker_root_symbol_evidence_hash(
    evidence: &X64TailWorkerRootSymbolEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_hash(&mut bytes, evidence.policy_hash);
    put_hash(&mut bytes, evidence.artifact_policy_hash);
    put_hash(&mut bytes, evidence.artifact_hash);
    put_hash(&mut bytes, evidence.inventory_policy_hash);
    put_hash(&mut bytes, evidence.inventory_evidence_hash);
    put_hash(&mut bytes, evidence.root_version_policy_hash);
    put_hash(&mut bytes, evidence.root_version_evidence_hash);
    put_hash(&mut bytes, evidence.root_compatibility_policy_hash);
    put_hash(&mut bytes, evidence.root_compatibility_evidence_hash);
    put_u16(&mut bytes, evidence.symbol_count);
    put_hash(&mut bytes, evidence.object.evidence_hash);
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

fn put_optional_u64(bytes: &mut Vec<u8>, value: Option<u64>) {
    bytes.push(u8::from(value.is_some()));
    put_u64(bytes, value.unwrap_or(0));
}

fn put_u32_vector(bytes: &mut Vec<u8>, values: &[u32]) {
    put_u16(bytes, u16::try_from(values.len()).unwrap_or(u16::MAX));
    for value in values {
        put_u32(bytes, *value);
    }
}

fn put_u64_vector(bytes: &mut Vec<u8>, values: &[u64]) {
    put_u16(bytes, u16::try_from(values.len()).unwrap_or(u16::MAX));
    for value in values {
        put_u64(bytes, *value);
    }
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
pub fn probe_x64_tail_worker_root_symbol_decoder_mutations(
    bytes: &[u8],
    artifact_hash: SemanticHash,
    inventory: &X64TailWorkerElfEvidence,
    root_versions: &X64TailWorkerRootVersionEvidence,
    root_compatibility: &X64TailWorkerRootCompatibilityEvidence,
) -> bool {
    let Ok(baseline) = decode_symbol_object(
        bytes,
        artifact_hash,
        inventory,
        root_versions,
        root_compatibility,
    ) else {
        return false;
    };
    let Ok((loads, dynamic)) = decode_layout(bytes) else {
        return false;
    };
    let Ok(tables) = decode_dynamic_symbol_tags(bytes, &dynamic) else {
        return false;
    };
    let Some(gnu_address) = tables.gnu_hash_address else {
        return false;
    };
    let Ok(gnu) = decode_gnu_hash(bytes, &loads, gnu_address) else {
        return false;
    };
    let Ok((_, gnu_header_offset)) = map_virtual_readonly_record(
        bytes,
        &loads,
        gnu_address,
        GNU_HASH_HEADER_BYTES,
        "probe GNU header",
    ) else {
        return false;
    };
    let bloom_address = gnu_address + GNU_HASH_HEADER_BYTES;
    let Ok((_, bloom_offset)) =
        map_virtual_readonly_record(bytes, &loads, bloom_address, 8, "probe GNU bloom")
    else {
        return false;
    };
    let bucket_address = bloom_address + u64::try_from(gnu.bloom.len()).unwrap_or(u64::MAX) * 8;
    let Some((bucket_ordinal, _)) = gnu.buckets.iter().enumerate().next() else {
        return false;
    };
    let Ok((_, bucket_offset)) = map_virtual_readonly_record(
        bytes,
        &loads,
        bucket_address + u64::try_from(bucket_ordinal).unwrap_or(u64::MAX) * 4,
        4,
        "probe GNU bucket",
    ) else {
        return false;
    };
    let chain_address = bucket_address + u64::try_from(gnu.buckets.len()).unwrap_or(u64::MAX) * 4;
    let chain_offset = if gnu.chains.is_empty() {
        None
    } else {
        let Ok((_, offset)) =
            map_virtual_readonly_record(bytes, &loads, chain_address, 4, "probe GNU chain")
        else {
            return false;
        };
        Some(offset)
    };
    let Some(symbol_ordinal) = baseline
        .symbols
        .iter()
        .find(|symbol| symbol.version_index >= 2)
        .map(|symbol| u32::from(symbol.ordinal))
    else {
        return false;
    };
    let Ok((symbol, symbol_offset)) = map_virtual_readonly_record(
        bytes,
        &loads,
        tables.symbol_address + u64::from(symbol_ordinal) * ELF64_SYMBOL_BYTES,
        ELF64_SYMBOL_BYTES,
        "probe symbol",
    ) else {
        return false;
    };
    let Ok((_, version_offset)) = map_virtual_readonly_record(
        bytes,
        &loads,
        tables.version_address + u64::from(symbol_ordinal) * VERSYM_BYTES,
        VERSYM_BYTES,
        "probe version symbol",
    ) else {
        return false;
    };
    let Some(gnu_tag_offset) = find_dynamic_tag_offset(bytes, &dynamic, DT_GNU_HASH) else {
        return false;
    };
    let Some(syment_tag_offset) = find_dynamic_tag_offset(bytes, &dynamic, DT_SYMENT) else {
        return false;
    };

    let mut rejected = vec![
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| write_i64(value, gnu_tag_offset, 0x1234),
        ),
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| write_i64(value, syment_tag_offset, DT_GNU_HASH),
        ),
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| write_u64(value, syment_tag_offset + 8, ELF64_SYMBOL_BYTES + 1),
        ),
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| write_u32(value, gnu_header_offset, 0),
        ),
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| {
                write_u32(
                    value,
                    gnu_header_offset + 4,
                    u32::from(X64_TAIL_WORKER_ROOT_SYMBOL_MAX_SYMBOLS) + 1,
                )
            },
        ),
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| write_u32(value, gnu_header_offset + 8, 0),
        ),
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| write_u32(value, gnu_header_offset + 8, 3),
        ),
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| write_u32(value, gnu_header_offset + 12, 64),
        ),
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| {
                let old = read_u64(value, bloom_offset, "probe bloom mutation").unwrap_or(0);
                write_u64(value, bloom_offset, old ^ 1)
            },
        ),
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| {
                let old = read_u32(value, bucket_offset, "probe bucket mutation").unwrap_or(0);
                write_u32(value, bucket_offset, old.saturating_add(1))
            },
        ),
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| write_u8(value, 0, value[0] ^ 1),
        ),
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| write_u32(value, symbol_offset, u32::MAX),
        ),
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| write_u8(value, symbol_offset + 4, 0xf0 | (symbol[4] & 0x0f)),
        ),
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| write_u8(value, symbol_offset + 4, (symbol[4] & 0xf0) | 0x0f),
        ),
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| write_u8(value, symbol_offset + 5, 4),
        ),
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| write_u16(value, symbol_offset + 6, u16::MAX),
        ),
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| write_u16(value, version_offset, VERSYM_HIDDEN | 1),
        ),
        symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| write_u16(value, version_offset, VERSYM_LORESERVE),
        ),
    ];
    if let Some(chain_offset) = chain_offset {
        rejected.push(symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| {
                let old = read_u32(value, chain_offset, "probe chain hash mutation").unwrap_or(0);
                write_u32(value, chain_offset, old ^ 2)
            },
        ));
        rejected.push(symbol_decoder_mutation_rejected(
            bytes,
            artifact_hash,
            inventory,
            root_versions,
            root_compatibility,
            |value| {
                let old =
                    read_u32(value, chain_offset, "probe chain terminal mutation").unwrap_or(0);
                write_u32(value, chain_offset, old ^ 1)
            },
        ));
    }
    rejected
        .into_iter()
        .all(|mutation_rejected| mutation_rejected)
}

#[cfg(debug_assertions)]
fn symbol_decoder_mutation_rejected(
    bytes: &[u8],
    artifact_hash: SemanticHash,
    inventory: &X64TailWorkerElfEvidence,
    root_versions: &X64TailWorkerRootVersionEvidence,
    root_compatibility: &X64TailWorkerRootCompatibilityEvidence,
    mutate: impl FnOnce(&mut [u8]),
) -> bool {
    let mut mutation = bytes.to_vec();
    mutate(&mut mutation);
    decode_symbol_object(
        &mutation,
        artifact_hash,
        inventory,
        root_versions,
        root_compatibility,
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
fn write_u8(bytes: &mut [u8], offset: u64, value: u8) {
    if let Ok(offset) = usize::try_from(offset) {
        if let Some(target) = bytes.get_mut(offset) {
            *target = value;
        }
    }
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
pub fn probe_x64_tail_worker_root_symbol_mutations(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    dynamic_evidence: &X64TailWorkerDependencyDynamicEvidence,
    closure_expectation: &X64TailWorkerDependencyClosureExpectation,
    closure_evidence: &X64TailWorkerDependencyClosureEvidence,
    dependency_version_evidence: &X64TailWorkerDependencyVersionEvidence,
    definition_evidence: &X64TailWorkerDependencyDefinitionEvidence,
    root_version_evidence: &X64TailWorkerRootVersionEvidence,
    root_compatibility_evidence: &X64TailWorkerRootCompatibilityEvidence,
    evidence: &X64TailWorkerRootSymbolEvidence,
) -> bool {
    if evidence.object.symbols.len() < 2 || evidence.object.gnu_bloom.is_empty() {
        return false;
    }
    let mut stale_policy = evidence.clone();
    stale_policy.policy_hash.0[0] ^= 1;
    let mut stale_versions = evidence.clone();
    stale_versions.root_version_evidence_hash.0[0] ^= 1;
    let mut stale_compatibility = evidence.clone();
    stale_compatibility.root_compatibility_evidence_hash.0[0] ^= 1;
    let mut stale_count = evidence.clone();
    stale_count.symbol_count = stale_count.symbol_count.saturating_add(1);
    let mut stale_object = evidence.clone();
    stale_object.object.artifact_hash.0[0] ^= 1;
    let mut stale_symbol = evidence.clone();
    stale_symbol.object.symbols[0].name.push('x');
    let mut stale_hash = evidence.clone();
    stale_hash.object.gnu_bloom[0] ^= 1;
    let mut reordered = evidence.clone();
    reordered.object.symbols.swap(0, 1);
    let shallow_rejected = [
        stale_policy,
        stale_versions,
        stale_compatibility,
        stale_count,
        stale_object,
        stale_symbol,
        stale_hash,
        reordered,
    ]
    .iter()
    .all(|mutation| {
        verify_x64_tail_worker_root_symbol_evidence(
            artifact,
            inventory,
            declaration_expectation,
            declaration_evidence,
            manifest,
            object_set,
            dynamic_evidence,
            closure_expectation,
            closure_evidence,
            dependency_version_evidence,
            definition_evidence,
            root_version_evidence,
            root_compatibility_evidence,
            mutation,
        )
        .is_err()
    });

    let Some(symbol_ordinal) = evidence.object.symbols.iter().position(|symbol| {
        !symbol.is_defined()
            && symbol.namespace_kind == X64TailWorkerRootSymbolNamespaceKind::Requirement
    }) else {
        return false;
    };
    let old_index = evidence.object.symbols[symbol_ordinal].version_index;
    let Some((replacement_requirement, replacement_auxiliary)) = root_version_evidence
        .requirements()
        .iter()
        .find_map(|requirement| {
            requirement
                .auxiliaries()
                .iter()
                .find(|auxiliary| auxiliary.version_index() != old_index)
                .map(|auxiliary| (requirement, auxiliary))
        })
    else {
        return false;
    };
    let Some(replacement_compatibility) =
        root_compatibility_evidence
            .bindings()
            .iter()
            .find(|binding| {
                binding.root_requirement_ordinal() == replacement_requirement.ordinal()
                    && binding.root_auxiliary_ordinal() == replacement_auxiliary.ordinal()
                    && binding.requirement_version_index() == replacement_auxiliary.version_index()
                    && binding.provider_ordinal() == replacement_requirement.provider_ordinal()
            })
    else {
        return false;
    };
    let mut resealed = evidence.clone();
    let symbol = &mut resealed.object.symbols[symbol_ordinal];
    symbol.version_index = replacement_auxiliary.version_index();
    symbol.version_word =
        replacement_auxiliary.version_index() | (u16::from(symbol.version_hidden) * VERSYM_HIDDEN);
    symbol.namespace_kind = X64TailWorkerRootSymbolNamespaceKind::Requirement;
    symbol.namespace_provider_ordinal = replacement_requirement.provider_ordinal();
    symbol.namespace_record_ordinal = replacement_requirement.ordinal();
    symbol.namespace_auxiliary_ordinal = replacement_auxiliary.ordinal();
    symbol.namespace_evidence_hash = replacement_auxiliary.evidence_hash();
    symbol.compatibility_binding_evidence_hash = replacement_compatibility.evidence_hash();
    symbol.evidence_hash = symbol_record_evidence_hash(symbol);
    resealed.object.evidence_hash = symbol_object_evidence_hash(&resealed.object);
    resealed.evidence_hash = x64_tail_worker_root_symbol_evidence_hash(&resealed);
    let resealed_rejected = verify_x64_tail_worker_root_symbol_evidence(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
        dynamic_evidence,
        closure_expectation,
        closure_evidence,
        dependency_version_evidence,
        definition_evidence,
        root_version_evidence,
        root_compatibility_evidence,
        &resealed,
    )
    .is_err();

    shallow_rejected && resealed_rejected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_symbol_policy_root_is_frozen() {
        assert_eq!(
            x64_tail_worker_root_symbol_policy_hash(),
            X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT
        );
    }

    #[test]
    fn production_source_has_no_loader_or_execution_authority() {
        let source = include_str!("x64_tail_worker_root_symbols.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        for forbidden in [
            "std::fs",
            "std::path",
            "std::process",
            "readelf",
            "object::",
            "goblin",
            "libloading",
            "x64_tail_worker_dependency_symbols",
            "x64_tail_worker_dependency_object_bytes",
            "x64_tail_enveloped_native",
            "x64_native_process",
            "x64_standalone",
            "x64_target::raw",
        ] {
            assert!(
                !production.contains(forbidden),
                "production symbol inventory contains forbidden authority {forbidden}"
            );
        }
    }
}
