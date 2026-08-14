//! ADR-0074 proof-only dynamic identity and transitive declaration inventory.
//!
//! This decoder reads only opaque ADR-0073 sealed-object bytes. It records an
//! exact `DT_SONAME`, ordered `DT_NEEDED` names, string-table identity, and
//! dynamic hardening flags for every admitted object. It never resolves a
//! name, opens a pathname, maps a shared object, or invokes the host loader.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_worker_artifact::X64TailWorkerArtifact;
use super::x64_tail_worker_dependency_admission::{
    X64TailWorkerDependencyAdmissionEvidence, X64TailWorkerDependencyExpectation,
};
use super::x64_tail_worker_dependency_objects::{
    verify_x64_tail_worker_dependency_objects, x64_tail_worker_dependency_object_bytes,
    X64TailWorkerDependencyObjectError, X64TailWorkerDependencyObjectManifest,
    X64TailWorkerDependencyObjectSet, X64_TAIL_WORKER_DEPENDENCY_OBJECT_POLICY_ROOT,
};
use super::x64_tail_worker_elf::X64TailWorkerElfEvidence;
use std::collections::BTreeSet;
use std::fmt;

pub const X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_OBJECTS: u16 = 65;
pub const X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_PROGRAM_HEADERS: u16 = 64;
pub const X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_LOAD_SEGMENTS: u16 = 16;
pub const X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_ENTRIES: u16 = 4_096;
pub const X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_NEEDED: u16 = 64;
pub const X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_STRING_TABLE_BYTES: u64 = 1024 * 1024;
pub const X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_NAME_BYTES: u64 = 256;
pub const X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_POLICY_ROOT: SemanticHash = SemanticHash([
    0x70, 0x83, 0xc3, 0xd4, 0xb4, 0xd4, 0xaf, 0xed, 0x21, 0x02, 0x34, 0x48, 0xd8, 0xa1, 0x6b, 0x06,
    0x65, 0x58, 0xa6, 0xe3, 0xf1, 0x79, 0x69, 0x83, 0x5e, 0x1a, 0x87, 0x89, 0x2a, 0x3d, 0x37, 0x1f,
]);

const POLICY_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-dynamic-policy:v1\0";
const OBJECT_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-dynamic-object:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-dependency-dynamic-evidence:v1\0";
const POLICY_CAPABILITIES: &[&str] = &[
    "opaque-adr0073-sealed-byte-source-v1",
    "independent-elf64-x86-64-program-header-replay-v1",
    "exact-one-file-backed-dynamic-table-v1",
    "exact-one-soname-matching-reviewed-declaration-v1",
    "ordered-unique-transitive-needed-inventory-v1",
    "exact-dynamic-flags-and-flags1-inventory-v1",
    "bounded-unambiguous-dynamic-string-table-v1",
    "reject-search-audit-filter-and-auxiliary-policy-v1",
    "proof-only-no-name-resolution-map-load-or-execute-v1",
];

const ELF_HEADER_BYTES: u16 = 64;
const PROGRAM_HEADER_BYTES: u16 = 56;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DYNAMIC_ENTRY_BYTES: u64 = 16;
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_STRTAB: i64 = 5;
const DT_STRSZ: i64 = 10;
const DT_SONAME: i64 = 14;
const DT_RPATH: i64 = 15;
const DT_RUNPATH: i64 = 29;
const DT_FLAGS: i64 = 30;
const DT_FLAGS_1: i64 = 0x6fff_fffb;
const DT_DEPAUDIT: i64 = 0x6fff_fefb;
const DT_AUDIT: i64 = 0x6fff_fefc;
const DT_AUXILIARY: i64 = 0x7fff_fffd;
const DT_FILTER: i64 = 0x7fff_ffff;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyDynamicName {
    ordinal: u16,
    string_offset: u64,
    name: String,
}

impl X64TailWorkerDependencyDynamicName {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub const fn string_offset(&self) -> u64 {
        self.string_offset
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyDynamicObjectEvidence {
    ordinal: u16,
    object_evidence_hash: SemanticHash,
    object_hash: SemanticHash,
    declaration: String,
    soname_offset: u64,
    soname: String,
    needed: Vec<X64TailWorkerDependencyDynamicName>,
    dynamic_flags: u64,
    dynamic_flags_1: u64,
    dynamic_entry_count: u16,
    string_table_bytes: u64,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerDependencyDynamicObjectEvidence {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub fn declaration(&self) -> &str {
        &self.declaration
    }

    pub fn soname(&self) -> &str {
        &self.soname
    }

    pub fn needed(&self) -> &[X64TailWorkerDependencyDynamicName] {
        &self.needed
    }

    pub const fn dynamic_flags(&self) -> u64 {
        self.dynamic_flags
    }

    pub const fn dynamic_flags_1(&self) -> u64 {
        self.dynamic_flags_1
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerDependencyDynamicEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    policy_hash: SemanticHash,
    object_policy_hash: SemanticHash,
    object_set_evidence_hash: SemanticHash,
    object_manifest_hash: SemanticHash,
    object_count: u16,
    total_needed: u16,
    objects: Vec<X64TailWorkerDependencyDynamicObjectEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerDependencyDynamicEvidence {
    pub const fn policy_hash(&self) -> SemanticHash {
        self.policy_hash
    }

    pub const fn object_set_evidence_hash(&self) -> SemanticHash {
        self.object_set_evidence_hash
    }

    pub const fn object_count(&self) -> u16 {
        self.object_count
    }

    pub const fn total_needed(&self) -> u16 {
        self.total_needed
    }

    pub fn objects(&self) -> &[X64TailWorkerDependencyDynamicObjectEvidence] {
        &self.objects
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailWorkerDependencyDynamic<'evidence> {
    evidence: &'evidence X64TailWorkerDependencyDynamicEvidence,
}

impl<'evidence> VerifiedX64TailWorkerDependencyDynamic<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64TailWorkerDependencyDynamicEvidence {
        self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailWorkerDependencyDynamicError {
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

impl fmt::Display for X64TailWorkerDependencyDynamicError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Objects(error) => write!(formatter, "ADR-0074 objects failed: {error}"),
            Self::Invalid(field) => write!(formatter, "invalid ADR-0074 {field}"),
            Self::Limit {
                field,
                limit,
                actual,
            } => write!(formatter, "ADR-0074 {field} {actual} exceeds limit {limit}"),
            Self::Overflow(field) => write!(formatter, "ADR-0074 {field} overflow"),
            Self::EvidenceMismatch => formatter.write_str("ADR-0074 evidence mismatch"),
        }
    }
}

impl std::error::Error for X64TailWorkerDependencyDynamicError {}

impl From<X64TailWorkerDependencyObjectError> for X64TailWorkerDependencyDynamicError {
    fn from(value: X64TailWorkerDependencyObjectError) -> Self {
        Self::Objects(value)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn emit_x64_tail_worker_dependency_dynamic_evidence(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
) -> Result<X64TailWorkerDependencyDynamicEvidence, X64TailWorkerDependencyDynamicError> {
    if x64_tail_worker_dependency_dynamic_policy_hash()
        != X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_POLICY_ROOT
    {
        return Err(X64TailWorkerDependencyDynamicError::Invalid("policy root"));
    }
    let verified = verify_x64_tail_worker_dependency_objects(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
    )?;
    if object_set.object_count() > usize::from(X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_OBJECTS) {
        return Err(X64TailWorkerDependencyDynamicError::Limit {
            field: "objects",
            limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_OBJECTS),
            actual: u64::try_from(object_set.object_count()).unwrap_or(u64::MAX),
        });
    }
    let mut objects = Vec::with_capacity(object_set.object_count());
    let mut total_needed = 0u16;
    for (ordinal, object) in object_set.evidence().objects().iter().enumerate() {
        let ordinal = u16::try_from(ordinal)
            .map_err(|_| X64TailWorkerDependencyDynamicError::Overflow("object ordinal"))?;
        let bytes = x64_tail_worker_dependency_object_bytes(&verified, ordinal)?;
        let decoded = decode_dynamic_object(
            &bytes,
            ordinal,
            object.declaration(),
            object.object_hash(),
            object.evidence_hash(),
        )?;
        total_needed = total_needed
            .checked_add(
                u16::try_from(decoded.needed.len())
                    .map_err(|_| X64TailWorkerDependencyDynamicError::Overflow("needed count"))?,
            )
            .ok_or(X64TailWorkerDependencyDynamicError::Overflow(
                "total needed",
            ))?;
        objects.push(decoded);
    }
    let mut evidence = X64TailWorkerDependencyDynamicEvidence {
        schema_version: X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_SCHEMA_VERSION,
        policy_version: X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_POLICY_VERSION,
        policy_hash: x64_tail_worker_dependency_dynamic_policy_hash(),
        object_policy_hash: X64_TAIL_WORKER_DEPENDENCY_OBJECT_POLICY_ROOT,
        object_set_evidence_hash: object_set.evidence().evidence_hash(),
        object_manifest_hash: manifest.manifest_hash(),
        object_count: u16::try_from(objects.len())
            .map_err(|_| X64TailWorkerDependencyDynamicError::Overflow("object count"))?,
        total_needed,
        objects,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = x64_tail_worker_dependency_dynamic_evidence_hash(&evidence);
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_x64_tail_worker_dependency_dynamic_evidence<'evidence>(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    evidence: &'evidence X64TailWorkerDependencyDynamicEvidence,
) -> Result<VerifiedX64TailWorkerDependencyDynamic<'evidence>, X64TailWorkerDependencyDynamicError>
{
    preflight_dynamic_evidence(manifest, object_set, evidence)?;
    let expected = emit_x64_tail_worker_dependency_dynamic_evidence(
        artifact,
        inventory,
        declaration_expectation,
        declaration_evidence,
        manifest,
        object_set,
    )?;
    if &expected != evidence
        || x64_tail_worker_dependency_dynamic_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerDependencyDynamicError::EvidenceMismatch);
    }
    Ok(VerifiedX64TailWorkerDependencyDynamic { evidence })
}

fn preflight_dynamic_evidence(
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    evidence: &X64TailWorkerDependencyDynamicEvidence,
) -> Result<(), X64TailWorkerDependencyDynamicError> {
    if evidence.schema_version != X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_SCHEMA_VERSION
        || evidence.policy_version != X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_POLICY_VERSION
        || evidence.policy_hash != X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_POLICY_ROOT
        || evidence.policy_hash != x64_tail_worker_dependency_dynamic_policy_hash()
        || evidence.object_policy_hash != X64_TAIL_WORKER_DEPENDENCY_OBJECT_POLICY_ROOT
        || evidence.object_set_evidence_hash != object_set.evidence().evidence_hash()
        || evidence.object_manifest_hash != manifest.manifest_hash()
        || usize::from(evidence.object_count) != object_set.object_count()
        || evidence.objects.len() != object_set.object_count()
        || x64_tail_worker_dependency_dynamic_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerDependencyDynamicError::EvidenceMismatch);
    }
    for (ordinal, (dynamic, object)) in evidence
        .objects
        .iter()
        .zip(object_set.evidence().objects())
        .enumerate()
    {
        if dynamic.ordinal != u16::try_from(ordinal).unwrap_or(u16::MAX)
            || dynamic.object_evidence_hash != object.evidence_hash()
            || dynamic.object_hash != object.object_hash()
            || dynamic.declaration != object.declaration()
            || dynamic.soname != declaration_basename(object.declaration())?
            || dynamic_object_evidence_hash(dynamic) != dynamic.evidence_hash
        {
            return Err(X64TailWorkerDependencyDynamicError::EvidenceMismatch);
        }
    }
    Ok(())
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

fn decode_dynamic_object(
    bytes: &[u8],
    object_ordinal: u16,
    declaration: &str,
    object_hash: SemanticHash,
    object_evidence_hash: SemanticHash,
) -> Result<X64TailWorkerDependencyDynamicObjectEvidence, X64TailWorkerDependencyDynamicError> {
    let (loads, dynamic) = decode_layout(bytes)?;
    if dynamic.file_size == 0 || !dynamic.file_size.is_multiple_of(DYNAMIC_ENTRY_BYTES) {
        return Err(X64TailWorkerDependencyDynamicError::Invalid(
            "dynamic table size",
        ));
    }
    let count = dynamic.file_size / DYNAMIC_ENTRY_BYTES;
    if count > u64::from(X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_ENTRIES) {
        return Err(X64TailWorkerDependencyDynamicError::Limit {
            field: "dynamic entries",
            limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_ENTRIES),
            actual: count,
        });
    }
    let mut needed_offsets = Vec::new();
    let mut soname_offset = None;
    let mut string_address = None;
    let mut string_bytes = None;
    let mut flags = None;
    let mut flags_1 = None;
    let mut saw_null = false;
    for ordinal in 0..count {
        let offset = dynamic
            .file_offset
            .checked_add(ordinal * DYNAMIC_ENTRY_BYTES)
            .ok_or(X64TailWorkerDependencyDynamicError::Overflow(
                "dynamic entry offset",
            ))?;
        let tag = read_i64(bytes, offset, "dynamic tag")?;
        let value = read_u64(bytes, offset + 8, "dynamic value")?;
        if saw_null && (tag != DT_NULL || value != 0) {
            return Err(X64TailWorkerDependencyDynamicError::Invalid(
                "dynamic data after NULL",
            ));
        }
        if tag == DT_NULL {
            if value != 0 {
                return Err(X64TailWorkerDependencyDynamicError::Invalid(
                    "dynamic NULL value",
                ));
            }
            saw_null = true;
        }
        match tag {
            DT_NEEDED if !saw_null => needed_offsets.push(value),
            DT_STRTAB if !saw_null => set_once(&mut string_address, value, "DT_STRTAB")?,
            DT_STRSZ if !saw_null => set_once(&mut string_bytes, value, "DT_STRSZ")?,
            DT_SONAME if !saw_null => set_once(&mut soname_offset, value, "DT_SONAME")?,
            DT_FLAGS if !saw_null => set_once(&mut flags, value, "DT_FLAGS")?,
            DT_FLAGS_1 if !saw_null => set_once(&mut flags_1, value, "DT_FLAGS_1")?,
            DT_RPATH | DT_RUNPATH | DT_DEPAUDIT | DT_AUDIT | DT_AUXILIARY | DT_FILTER
                if !saw_null =>
            {
                return Err(X64TailWorkerDependencyDynamicError::Invalid(
                    "embedded loader policy",
                ));
            }
            _ => {}
        }
    }
    if !saw_null {
        return Err(X64TailWorkerDependencyDynamicError::Invalid(
            "missing dynamic NULL",
        ));
    }
    if needed_offsets.len() > usize::from(X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_NEEDED) {
        return Err(X64TailWorkerDependencyDynamicError::Limit {
            field: "needed declarations",
            limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_NEEDED),
            actual: u64::try_from(needed_offsets.len()).unwrap_or(u64::MAX),
        });
    }
    let string_address = string_address.ok_or(X64TailWorkerDependencyDynamicError::Invalid(
        "missing DT_STRTAB",
    ))?;
    let string_bytes = string_bytes.ok_or(X64TailWorkerDependencyDynamicError::Invalid(
        "missing DT_STRSZ",
    ))?;
    if string_bytes == 0 || string_bytes > X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_STRING_TABLE_BYTES
    {
        return Err(X64TailWorkerDependencyDynamicError::Limit {
            field: "dynamic string table",
            limit: X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_STRING_TABLE_BYTES,
            actual: string_bytes,
        });
    }
    let strings = map_virtual_file_range(bytes, &loads, string_address, string_bytes)?;
    let soname_offset = soname_offset.ok_or(X64TailWorkerDependencyDynamicError::Invalid(
        "missing DT_SONAME",
    ))?;
    let soname = decode_string_at(strings, string_bytes, soname_offset, "SONAME")?;
    if soname != declaration_basename(declaration)? {
        return Err(X64TailWorkerDependencyDynamicError::Invalid(
            "SONAME declaration mismatch",
        ));
    }
    let mut names = BTreeSet::new();
    let mut needed = Vec::with_capacity(needed_offsets.len());
    for (ordinal, string_offset) in needed_offsets.into_iter().enumerate() {
        let name = decode_string_at(strings, string_bytes, string_offset, "needed name")?;
        if !names.insert(name.clone()) {
            return Err(X64TailWorkerDependencyDynamicError::Invalid(
                "duplicate needed name",
            ));
        }
        needed.push(X64TailWorkerDependencyDynamicName {
            ordinal: u16::try_from(ordinal)
                .map_err(|_| X64TailWorkerDependencyDynamicError::Overflow("needed ordinal"))?,
            string_offset,
            name,
        });
    }
    let mut evidence = X64TailWorkerDependencyDynamicObjectEvidence {
        ordinal: object_ordinal,
        object_evidence_hash,
        object_hash,
        declaration: declaration.to_owned(),
        soname_offset,
        soname,
        needed,
        dynamic_flags: flags.ok_or(X64TailWorkerDependencyDynamicError::Invalid(
            "missing DT_FLAGS",
        ))?,
        dynamic_flags_1: flags_1.ok_or(X64TailWorkerDependencyDynamicError::Invalid(
            "missing DT_FLAGS_1",
        ))?,
        dynamic_entry_count: u16::try_from(count)
            .map_err(|_| X64TailWorkerDependencyDynamicError::Overflow("dynamic count"))?,
        string_table_bytes: string_bytes,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = dynamic_object_evidence_hash(&evidence);
    Ok(evidence)
}

fn decode_layout(
    bytes: &[u8],
) -> Result<(Vec<LoadSegment>, DynamicSegment), X64TailWorkerDependencyDynamicError> {
    require_range(bytes, 0, u64::from(ELF_HEADER_BYTES), "ELF header")?;
    if &bytes[0..4] != b"\x7fELF"
        || bytes[4] != 2
        || bytes[5] != 1
        || bytes[6] != 1
        || read_u16(bytes, 16, "ELF type")? != ET_DYN
        || read_u16(bytes, 18, "ELF machine")? != EM_X86_64
        || read_u16(bytes, 52, "ELF header size")? != ELF_HEADER_BYTES
        || read_u16(bytes, 54, "program header size")? != PROGRAM_HEADER_BYTES
    {
        return Err(X64TailWorkerDependencyDynamicError::Invalid("ELF identity"));
    }
    let table_offset = read_u64(bytes, 32, "program header offset")?;
    let count = read_u16(bytes, 56, "program header count")?;
    if count == 0 || count > X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_PROGRAM_HEADERS {
        return Err(X64TailWorkerDependencyDynamicError::Limit {
            field: "program headers",
            limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_PROGRAM_HEADERS),
            actual: u64::from(count),
        });
    }
    require_range(
        bytes,
        table_offset,
        u64::from(count) * u64::from(PROGRAM_HEADER_BYTES),
        "program header table",
    )?;
    let mut loads = Vec::new();
    let mut dynamic = None;
    for ordinal in 0..count {
        let offset = table_offset
            .checked_add(u64::from(ordinal) * u64::from(PROGRAM_HEADER_BYTES))
            .ok_or(X64TailWorkerDependencyDynamicError::Overflow(
                "program header offset",
            ))?;
        let segment_type = read_u32(bytes, offset, "segment type")?;
        let file_offset = read_u64(bytes, offset + 8, "segment file offset")?;
        let virtual_address = read_u64(bytes, offset + 16, "segment virtual address")?;
        let file_size = read_u64(bytes, offset + 32, "segment file size")?;
        require_range(bytes, file_offset, file_size, "segment file range")?;
        if segment_type == PT_LOAD {
            loads.push(LoadSegment {
                file_offset,
                virtual_address,
                file_size,
            });
        } else if segment_type == PT_DYNAMIC
            && dynamic
                .replace(DynamicSegment {
                    file_offset,
                    file_size,
                })
                .is_some()
        {
            return Err(X64TailWorkerDependencyDynamicError::Invalid(
                "duplicate dynamic segment",
            ));
        }
    }
    if loads.is_empty()
        || loads.len() > usize::from(X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_LOAD_SEGMENTS)
    {
        return Err(X64TailWorkerDependencyDynamicError::Limit {
            field: "load segments",
            limit: u64::from(X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_LOAD_SEGMENTS),
            actual: u64::try_from(loads.len()).unwrap_or(u64::MAX),
        });
    }
    Ok((
        loads,
        dynamic.ok_or(X64TailWorkerDependencyDynamicError::Invalid(
            "missing dynamic segment",
        ))?,
    ))
}

fn map_virtual_file_range<'bytes>(
    bytes: &'bytes [u8],
    loads: &[LoadSegment],
    address: u64,
    size: u64,
) -> Result<&'bytes [u8], X64TailWorkerDependencyDynamicError> {
    let end = address
        .checked_add(size)
        .ok_or(X64TailWorkerDependencyDynamicError::Overflow(
            "virtual string table",
        ))?;
    let mut matches = loads.iter().filter(|load| {
        address >= load.virtual_address
            && load
                .virtual_address
                .checked_add(load.file_size)
                .is_some_and(|load_end| end <= load_end)
    });
    let load = matches
        .next()
        .ok_or(X64TailWorkerDependencyDynamicError::Invalid(
            "string table mapping",
        ))?;
    if matches.next().is_some() {
        return Err(X64TailWorkerDependencyDynamicError::Invalid(
            "ambiguous string table mapping",
        ));
    }
    let offset = load
        .file_offset
        .checked_add(address - load.virtual_address)
        .ok_or(X64TailWorkerDependencyDynamicError::Overflow(
            "string table file offset",
        ))?;
    slice_range(bytes, offset, size, "dynamic string table")
}

fn decode_string_at(
    strings: &[u8],
    string_bytes: u64,
    offset: u64,
    field: &'static str,
) -> Result<String, X64TailWorkerDependencyDynamicError> {
    if offset >= string_bytes {
        return Err(X64TailWorkerDependencyDynamicError::Invalid(field));
    }
    let start = usize::try_from(offset)
        .map_err(|_| X64TailWorkerDependencyDynamicError::Overflow(field))?;
    let retained = usize::try_from(X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_NAME_BYTES)
        .unwrap_or(usize::MAX)
        .min(strings.len().saturating_sub(start));
    let value = &strings[start..start + retained];
    let end = value
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(X64TailWorkerDependencyDynamicError::Invalid(field))?;
    let name = &value[..end];
    if name.is_empty()
        || name.iter().any(|byte| !(0x21..=0x7e).contains(byte))
        || name.contains(&b'/')
        || name.contains(&b'\\')
    {
        return Err(X64TailWorkerDependencyDynamicError::Invalid(field));
    }
    std::str::from_utf8(name)
        .map(str::to_owned)
        .map_err(|_| X64TailWorkerDependencyDynamicError::Invalid(field))
}

fn declaration_basename(declaration: &str) -> Result<&str, X64TailWorkerDependencyDynamicError> {
    declaration
        .rsplit('/')
        .next()
        .filter(|value| !value.is_empty())
        .ok_or(X64TailWorkerDependencyDynamicError::Invalid(
            "declaration basename",
        ))
}

fn set_once(
    slot: &mut Option<u64>,
    value: u64,
    field: &'static str,
) -> Result<(), X64TailWorkerDependencyDynamicError> {
    if slot.replace(value).is_some() {
        Err(X64TailWorkerDependencyDynamicError::Invalid(field))
    } else {
        Ok(())
    }
}

pub fn x64_tail_worker_dependency_dynamic_policy_hash() -> SemanticHash {
    let mut bytes = Vec::with_capacity(768);
    bytes.extend_from_slice(POLICY_DOMAIN);
    put_version(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_SCHEMA_VERSION,
    );
    put_version(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_POLICY_VERSION,
    );
    put_hash(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_OBJECT_POLICY_ROOT);
    put_u16(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_OBJECTS);
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_PROGRAM_HEADERS,
    );
    put_u16(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_LOAD_SEGMENTS,
    );
    put_u16(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_ENTRIES);
    put_u16(&mut bytes, X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_NEEDED);
    put_u64(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_STRING_TABLE_BYTES,
    );
    put_u64(
        &mut bytes,
        X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_NAME_BYTES,
    );
    put_u16(&mut bytes, ELF_HEADER_BYTES);
    put_u16(&mut bytes, PROGRAM_HEADER_BYTES);
    put_u64(&mut bytes, DYNAMIC_ENTRY_BYTES);
    put_u16(
        &mut bytes,
        u16::try_from(POLICY_CAPABILITIES.len()).unwrap_or(u16::MAX),
    );
    for capability in POLICY_CAPABILITIES {
        put_string(&mut bytes, capability);
    }
    SemanticHash(sha256(&bytes))
}

fn dynamic_object_evidence_hash(
    evidence: &X64TailWorkerDependencyDynamicObjectEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(OBJECT_DOMAIN);
    put_u16(&mut bytes, evidence.ordinal);
    put_hash(&mut bytes, evidence.object_evidence_hash);
    put_hash(&mut bytes, evidence.object_hash);
    put_string(&mut bytes, &evidence.declaration);
    put_u64(&mut bytes, evidence.soname_offset);
    put_string(&mut bytes, &evidence.soname);
    put_u16(
        &mut bytes,
        u16::try_from(evidence.needed.len()).unwrap_or(u16::MAX),
    );
    for needed in &evidence.needed {
        put_u16(&mut bytes, needed.ordinal);
        put_u64(&mut bytes, needed.string_offset);
        put_string(&mut bytes, &needed.name);
    }
    put_u64(&mut bytes, evidence.dynamic_flags);
    put_u64(&mut bytes, evidence.dynamic_flags_1);
    put_u16(&mut bytes, evidence.dynamic_entry_count);
    put_u64(&mut bytes, evidence.string_table_bytes);
    SemanticHash(sha256(&bytes))
}

pub fn x64_tail_worker_dependency_dynamic_evidence_hash(
    evidence: &X64TailWorkerDependencyDynamicEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_hash(&mut bytes, evidence.policy_hash);
    put_hash(&mut bytes, evidence.object_policy_hash);
    put_hash(&mut bytes, evidence.object_set_evidence_hash);
    put_hash(&mut bytes, evidence.object_manifest_hash);
    put_u16(&mut bytes, evidence.object_count);
    put_u16(&mut bytes, evidence.total_needed);
    for object in &evidence.objects {
        put_hash(&mut bytes, object.evidence_hash);
    }
    SemanticHash(sha256(&bytes))
}

fn require_range(
    bytes: &[u8],
    offset: u64,
    size: u64,
    field: &'static str,
) -> Result<(), X64TailWorkerDependencyDynamicError> {
    let end = offset
        .checked_add(size)
        .ok_or(X64TailWorkerDependencyDynamicError::Overflow(field))?;
    if end > u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
        return Err(X64TailWorkerDependencyDynamicError::Invalid(field));
    }
    Ok(())
}

fn slice_range<'bytes>(
    bytes: &'bytes [u8],
    offset: u64,
    size: u64,
    field: &'static str,
) -> Result<&'bytes [u8], X64TailWorkerDependencyDynamicError> {
    require_range(bytes, offset, size, field)?;
    let start = usize::try_from(offset)
        .map_err(|_| X64TailWorkerDependencyDynamicError::Overflow(field))?;
    let end = usize::try_from(offset + size)
        .map_err(|_| X64TailWorkerDependencyDynamicError::Overflow(field))?;
    Ok(&bytes[start..end])
}

fn read_u16(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<u16, X64TailWorkerDependencyDynamicError> {
    let value = slice_range(bytes, offset, 2, field)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<u32, X64TailWorkerDependencyDynamicError> {
    let value = slice_range(bytes, offset, 4, field)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<u64, X64TailWorkerDependencyDynamicError> {
    let value = slice_range(bytes, offset, 8, field)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn read_i64(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<i64, X64TailWorkerDependencyDynamicError> {
    Ok(read_u64(bytes, offset, field)? as i64)
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
pub fn probe_x64_tail_worker_dependency_dynamic_decoder_mutations(
    bytes: &[u8],
    declaration: &str,
) -> bool {
    if decode_dynamic_object(
        bytes,
        0,
        declaration,
        SemanticHash::ZERO,
        SemanticHash::ZERO,
    )
    .is_err()
    {
        return false;
    }
    let Ok((_, dynamic)) = decode_layout(bytes) else {
        return false;
    };
    let count = dynamic.file_size / DYNAMIC_ENTRY_BYTES;
    let mut soname = None;
    let mut needed = None;
    let mut string_table = None;
    let mut string_size = None;
    let mut flags = None;
    let mut null = None;
    for ordinal in 0..count {
        let Some(offset) = dynamic
            .file_offset
            .checked_add(ordinal * DYNAMIC_ENTRY_BYTES)
        else {
            return false;
        };
        let Ok(tag) = read_i64(bytes, offset, "probe tag") else {
            return false;
        };
        match tag {
            DT_SONAME => soname = Some(offset),
            DT_NEEDED if needed.is_none() => needed = Some(offset),
            DT_STRTAB => string_table = Some(offset),
            DT_STRSZ => string_size = Some(offset),
            DT_FLAGS => flags = Some(offset),
            DT_NULL if null.is_none() => null = Some(offset),
            _ => {}
        }
    }
    let (
        Some(soname),
        Some(needed),
        Some(string_table),
        Some(string_size),
        Some(flags),
        Some(null),
    ) = (soname, needed, string_table, string_size, flags, null)
    else {
        return false;
    };
    [
        dynamic_decoder_mutation_rejected(bytes, declaration, |value| {
            write_i64(value, soname, 0x1234)
        }),
        dynamic_decoder_mutation_rejected(bytes, declaration, |value| {
            write_u64(value, needed + 8, u64::MAX)
        }),
        dynamic_decoder_mutation_rejected(bytes, declaration, |value| {
            write_u64(value, string_table + 8, u64::MAX)
        }),
        dynamic_decoder_mutation_rejected(bytes, declaration, |value| {
            write_u64(
                value,
                string_size + 8,
                X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_MAX_STRING_TABLE_BYTES + 1,
            )
        }),
        dynamic_decoder_mutation_rejected(bytes, declaration, |value| {
            write_i64(value, flags, 0x1234)
        }),
        dynamic_decoder_mutation_rejected(bytes, declaration, |value| {
            write_u64(value, null + 8, 1)
        }),
        dynamic_decoder_mutation_rejected(bytes, declaration, |value| {
            write_i64(value, null, DT_RPATH)
        }),
    ]
    .into_iter()
    .all(|rejected| rejected)
}

#[cfg(debug_assertions)]
fn dynamic_decoder_mutation_rejected(
    bytes: &[u8],
    declaration: &str,
    mutate: impl FnOnce(&mut [u8]),
) -> bool {
    let mut mutation = bytes.to_vec();
    mutate(&mut mutation);
    decode_dynamic_object(
        &mutation,
        0,
        declaration,
        SemanticHash::ZERO,
        SemanticHash::ZERO,
    )
    .is_err()
}

#[cfg(debug_assertions)]
fn write_i64(bytes: &mut [u8], offset: u64, value: i64) {
    write_u64(bytes, offset, value as u64);
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
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn probe_x64_tail_worker_dependency_dynamic_mutations(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    declaration_expectation: &X64TailWorkerDependencyExpectation,
    declaration_evidence: &X64TailWorkerDependencyAdmissionEvidence,
    manifest: &X64TailWorkerDependencyObjectManifest,
    object_set: &X64TailWorkerDependencyObjectSet,
    evidence: &X64TailWorkerDependencyDynamicEvidence,
) -> bool {
    let mut stale_policy = evidence.clone();
    stale_policy.policy_hash.0[0] ^= 1;
    let mut stale_objects = evidence.clone();
    stale_objects.object_set_evidence_hash.0[0] ^= 1;
    let mut stale_count = evidence.clone();
    stale_count.total_needed = stale_count.total_needed.saturating_add(1);
    let mut stale_record = evidence.clone();
    stale_record.objects[0].soname.push('x');
    let mut resealed = evidence.clone();
    resealed.objects[0].soname.push('x');
    resealed.objects[0].evidence_hash = dynamic_object_evidence_hash(&resealed.objects[0]);
    resealed.evidence_hash = x64_tail_worker_dependency_dynamic_evidence_hash(&resealed);
    [
        stale_policy,
        stale_objects,
        stale_count,
        stale_record,
        resealed,
    ]
    .iter()
    .all(|mutation| {
        verify_x64_tail_worker_dependency_dynamic_evidence(
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
