//! ADR-0071 independent, proof-only ELF dependency inventory.
//!
//! This decoder consumes only exact ADR-0070 bytes. It does not resolve or
//! launch an interpreter or dependency, and it shares no parser with the
//! historical standalone authority.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_worker_artifact::{
    verify_x64_tail_worker_artifact, x64_tail_worker_artifact_bytes,
    x64_tail_worker_expectation_from_reviewed_bytes, X64TailWorkerArtifact,
    X64TailWorkerArtifactError, X64TailWorkerArtifactExpectation,
    X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT,
};
use std::collections::BTreeSet;
use std::fmt;

pub const X64_TAIL_WORKER_ELF_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_ELF_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_ELF_MAX_PROGRAM_HEADERS: u16 = 64;
pub const X64_TAIL_WORKER_ELF_MAX_SECTION_HEADERS: u16 = 4_096;
pub const X64_TAIL_WORKER_ELF_MAX_LOAD_SEGMENTS: u16 = 16;
pub const X64_TAIL_WORKER_ELF_MAX_DYNAMIC_ENTRIES: u16 = 4_096;
pub const X64_TAIL_WORKER_ELF_MAX_DEPENDENCIES: u16 = 64;
pub const X64_TAIL_WORKER_ELF_MAX_STRING_TABLE_BYTES: u64 = 1024 * 1024;
pub const X64_TAIL_WORKER_ELF_MAX_NAME_BYTES: u64 = 256;
pub const X64_TAIL_WORKER_ELF_POLICY_ROOT: SemanticHash = SemanticHash([
    0x1a, 0x6c, 0x96, 0xc8, 0xb4, 0x7a, 0x20, 0x01, 0xd9, 0x96, 0x94, 0x88, 0x78, 0x5c, 0x6b, 0xb2,
    0xb8, 0x46, 0xc3, 0x78, 0x28, 0x0b, 0x04, 0x98, 0xf2, 0xc1, 0x6b, 0x0f, 0x14, 0xfd, 0x3b, 0xbf,
]);

const POLICY_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-elf-policy:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-elf-evidence:v1\0";

const ELF_HEADER_BYTES: u16 = 64;
const PROGRAM_HEADER_BYTES: u16 = 56;
const SECTION_HEADER_BYTES: u16 = 64;
const DYNAMIC_ENTRY_BYTES: u64 = 16;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_STRTAB: i64 = 5;
const DT_STRSZ: i64 = 10;
const DT_RPATH: i64 = 15;
const DT_FLAGS: i64 = 30;
const DT_RUNPATH: i64 = 29;
const DT_FLAGS_1: i64 = 0x6fff_fffb;
const DT_DEPAUDIT: i64 = 0x6fff_fefb;
const DT_AUDIT: i64 = 0x6fff_fefc;
const DT_AUXILIARY: i64 = 0x7fff_fffd;
const DT_FILTER: i64 = 0x7fff_ffff;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerElfHeader {
    entry: u64,
    program_header_offset: u64,
    program_header_count: u16,
    section_header_offset: u64,
    section_header_count: u16,
}

impl X64TailWorkerElfHeader {
    pub const fn entry(&self) -> u64 {
        self.entry
    }

    pub const fn program_header_count(&self) -> u16 {
        self.program_header_count
    }

    pub const fn section_header_count(&self) -> u16 {
        self.section_header_count
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerElfSegment {
    ordinal: u16,
    segment_type: u32,
    flags: u32,
    file_offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
}

impl X64TailWorkerElfSegment {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub const fn segment_type(&self) -> u32 {
        self.segment_type
    }

    pub const fn flags(&self) -> u32 {
        self.flags
    }

    pub const fn file_offset(&self) -> u64 {
        self.file_offset
    }

    pub const fn virtual_address(&self) -> u64 {
        self.virtual_address
    }

    pub const fn file_size(&self) -> u64 {
        self.file_size
    }

    pub const fn memory_size(&self) -> u64 {
        self.memory_size
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerElfDynamicEntry {
    ordinal: u16,
    tag: i64,
    value: u64,
}

impl X64TailWorkerElfDynamicEntry {
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub const fn tag(&self) -> i64 {
        self.tag
    }

    pub const fn value(&self) -> u64 {
        self.value
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerElfDependency {
    ordinal: u16,
    string_offset: u64,
    name: String,
}

impl X64TailWorkerElfDependency {
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
pub struct X64TailWorkerElfTotals {
    program_headers: u16,
    section_headers: u16,
    load_segments: u16,
    dynamic_entries: u16,
    dependencies: u16,
    string_table_bytes: u64,
    writable_executable_loads: u16,
    executable_stacks: u16,
    embedded_search_paths: u16,
}

impl X64TailWorkerElfTotals {
    pub const fn program_headers(&self) -> u16 {
        self.program_headers
    }

    pub const fn load_segments(&self) -> u16 {
        self.load_segments
    }

    pub const fn dependencies(&self) -> u16 {
        self.dependencies
    }

    pub const fn dynamic_entries(&self) -> u16 {
        self.dynamic_entries
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerElfEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    policy_hash: SemanticHash,
    artifact_expectation_hash: SemanticHash,
    artifact_hash: SemanticHash,
    header: X64TailWorkerElfHeader,
    segments: Vec<X64TailWorkerElfSegment>,
    interpreter: String,
    dynamic_entries: Vec<X64TailWorkerElfDynamicEntry>,
    dependencies: Vec<X64TailWorkerElfDependency>,
    dynamic_flags: u64,
    dynamic_flags_1: u64,
    totals: X64TailWorkerElfTotals,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerElfEvidence {
    pub const fn policy_hash(&self) -> SemanticHash {
        self.policy_hash
    }

    pub const fn artifact_hash(&self) -> SemanticHash {
        self.artifact_hash
    }

    pub const fn header(&self) -> &X64TailWorkerElfHeader {
        &self.header
    }

    pub fn segments(&self) -> &[X64TailWorkerElfSegment] {
        &self.segments
    }

    pub fn interpreter(&self) -> &str {
        &self.interpreter
    }

    pub fn dynamic_entries(&self) -> &[X64TailWorkerElfDynamicEntry] {
        &self.dynamic_entries
    }

    pub fn dependencies(&self) -> &[X64TailWorkerElfDependency] {
        &self.dependencies
    }

    pub const fn dynamic_flags(&self) -> u64 {
        self.dynamic_flags
    }

    pub const fn dynamic_flags_1(&self) -> u64 {
        self.dynamic_flags_1
    }

    pub const fn totals(&self) -> &X64TailWorkerElfTotals {
        &self.totals
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailWorkerElf<'evidence> {
    evidence: &'evidence X64TailWorkerElfEvidence,
}

impl<'evidence> VerifiedX64TailWorkerElf<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64TailWorkerElfEvidence {
        self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailWorkerElfError {
    Artifact(X64TailWorkerArtifactError),
    ExpectationMismatch,
    Truncated(&'static str),
    Invalid(&'static str),
    Limit {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    Overflow(&'static str),
    EvidenceMismatch,
}

impl fmt::Display for X64TailWorkerElfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Artifact(error) => write!(formatter, "ADR-0071 artifact failed: {error}"),
            Self::ExpectationMismatch => formatter.write_str("ADR-0071 expectation mismatch"),
            Self::Truncated(field) => write!(formatter, "ADR-0071 truncated {field}"),
            Self::Invalid(field) => write!(formatter, "invalid ADR-0071 {field}"),
            Self::Limit {
                field,
                limit,
                actual,
            } => write!(formatter, "ADR-0071 {field} {actual} exceeds limit {limit}"),
            Self::Overflow(field) => write!(formatter, "ADR-0071 {field} overflow"),
            Self::EvidenceMismatch => formatter.write_str("ADR-0071 evidence mismatch"),
        }
    }
}

impl std::error::Error for X64TailWorkerElfError {}

impl From<X64TailWorkerArtifactError> for X64TailWorkerElfError {
    fn from(value: X64TailWorkerArtifactError) -> Self {
        Self::Artifact(value)
    }
}

pub fn emit_x64_tail_worker_elf_evidence(
    artifact: &X64TailWorkerArtifact,
) -> Result<X64TailWorkerElfEvidence, X64TailWorkerElfError> {
    let verified = verify_x64_tail_worker_artifact(artifact)?;
    let bytes = x64_tail_worker_artifact_bytes(&verified)?;
    decode_x64_tail_worker_elf(&bytes, artifact.expectation())
}

pub fn verify_x64_tail_worker_elf_evidence<'evidence>(
    artifact: &X64TailWorkerArtifact,
    evidence: &'evidence X64TailWorkerElfEvidence,
) -> Result<VerifiedX64TailWorkerElf<'evidence>, X64TailWorkerElfError> {
    let expected = emit_x64_tail_worker_elf_evidence(artifact)?;
    if &expected != evidence
        || x64_tail_worker_elf_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerElfError::EvidenceMismatch);
    }
    Ok(VerifiedX64TailWorkerElf { evidence })
}

pub fn decode_x64_tail_worker_elf(
    bytes: &[u8],
    expectation: &X64TailWorkerArtifactExpectation,
) -> Result<X64TailWorkerElfEvidence, X64TailWorkerElfError> {
    let reconstructed = x64_tail_worker_expectation_from_reviewed_bytes(bytes)?;
    if &reconstructed != expectation {
        return Err(X64TailWorkerElfError::ExpectationMismatch);
    }
    let header = decode_header(bytes)?;
    let segments = decode_segments(bytes, &header)?;
    let layout = validate_segment_layout(bytes, &header, &segments)?;
    let interpreter = decode_interpreter(bytes, layout.interpreter)?;
    let dynamic = decode_dynamic(bytes, layout.dynamic, &segments)?;
    let totals = X64TailWorkerElfTotals {
        program_headers: header.program_header_count,
        section_headers: header.section_header_count,
        load_segments: u16::try_from(layout.loads.len())
            .map_err(|_| X64TailWorkerElfError::Overflow("load count"))?,
        dynamic_entries: u16::try_from(dynamic.entries.len())
            .map_err(|_| X64TailWorkerElfError::Overflow("dynamic count"))?,
        dependencies: u16::try_from(dynamic.dependencies.len())
            .map_err(|_| X64TailWorkerElfError::Overflow("dependency count"))?,
        string_table_bytes: dynamic.string_table_bytes,
        writable_executable_loads: 0,
        executable_stacks: 0,
        embedded_search_paths: 0,
    };
    let mut evidence = X64TailWorkerElfEvidence {
        schema_version: X64_TAIL_WORKER_ELF_SCHEMA_VERSION,
        policy_version: X64_TAIL_WORKER_ELF_POLICY_VERSION,
        policy_hash: x64_tail_worker_elf_policy_hash(),
        artifact_expectation_hash: expectation.expectation_hash(),
        artifact_hash: expectation.artifact_hash(),
        header,
        segments,
        interpreter,
        dynamic_entries: dynamic.entries,
        dependencies: dynamic.dependencies,
        dynamic_flags: dynamic.flags,
        dynamic_flags_1: dynamic.flags_1,
        totals,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = x64_tail_worker_elf_evidence_hash(&evidence);
    Ok(evidence)
}

pub fn x64_tail_worker_elf_policy_hash() -> SemanticHash {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(POLICY_DOMAIN);
    put_version(&mut bytes, X64_TAIL_WORKER_ELF_SCHEMA_VERSION);
    put_version(&mut bytes, X64_TAIL_WORKER_ELF_POLICY_VERSION);
    put_u16(&mut bytes, X64_TAIL_WORKER_ELF_MAX_PROGRAM_HEADERS);
    put_u16(&mut bytes, X64_TAIL_WORKER_ELF_MAX_SECTION_HEADERS);
    put_u16(&mut bytes, X64_TAIL_WORKER_ELF_MAX_LOAD_SEGMENTS);
    put_u16(&mut bytes, X64_TAIL_WORKER_ELF_MAX_DYNAMIC_ENTRIES);
    put_u16(&mut bytes, X64_TAIL_WORKER_ELF_MAX_DEPENDENCIES);
    put_u64(&mut bytes, X64_TAIL_WORKER_ELF_MAX_STRING_TABLE_BYTES);
    put_u64(&mut bytes, X64_TAIL_WORKER_ELF_MAX_NAME_BYTES);
    put_hash(&mut bytes, X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT);
    SemanticHash(sha256(&bytes))
}

pub fn x64_tail_worker_elf_evidence_hash(evidence: &X64TailWorkerElfEvidence) -> SemanticHash {
    let mut bytes = Vec::with_capacity(4096);
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_hash(&mut bytes, evidence.policy_hash);
    put_hash(&mut bytes, evidence.artifact_expectation_hash);
    put_hash(&mut bytes, evidence.artifact_hash);
    put_u64(&mut bytes, evidence.header.entry);
    put_u64(&mut bytes, evidence.header.program_header_offset);
    put_u16(&mut bytes, evidence.header.program_header_count);
    put_u64(&mut bytes, evidence.header.section_header_offset);
    put_u16(&mut bytes, evidence.header.section_header_count);
    put_u16(
        &mut bytes,
        u16::try_from(evidence.segments.len()).unwrap_or(u16::MAX),
    );
    for segment in &evidence.segments {
        put_u16(&mut bytes, segment.ordinal);
        put_u32(&mut bytes, segment.segment_type);
        put_u32(&mut bytes, segment.flags);
        put_u64(&mut bytes, segment.file_offset);
        put_u64(&mut bytes, segment.virtual_address);
        put_u64(&mut bytes, segment.file_size);
        put_u64(&mut bytes, segment.memory_size);
        put_u64(&mut bytes, segment.alignment);
    }
    put_string(&mut bytes, &evidence.interpreter);
    put_u16(
        &mut bytes,
        u16::try_from(evidence.dynamic_entries.len()).unwrap_or(u16::MAX),
    );
    for entry in &evidence.dynamic_entries {
        put_u16(&mut bytes, entry.ordinal);
        put_u64(&mut bytes, entry.tag as u64);
        put_u64(&mut bytes, entry.value);
    }
    put_u16(
        &mut bytes,
        u16::try_from(evidence.dependencies.len()).unwrap_or(u16::MAX),
    );
    for dependency in &evidence.dependencies {
        put_u16(&mut bytes, dependency.ordinal);
        put_u64(&mut bytes, dependency.string_offset);
        put_string(&mut bytes, &dependency.name);
    }
    put_u64(&mut bytes, evidence.dynamic_flags);
    put_u64(&mut bytes, evidence.dynamic_flags_1);
    put_u16(&mut bytes, evidence.totals.program_headers);
    put_u16(&mut bytes, evidence.totals.section_headers);
    put_u16(&mut bytes, evidence.totals.load_segments);
    put_u16(&mut bytes, evidence.totals.dynamic_entries);
    put_u16(&mut bytes, evidence.totals.dependencies);
    put_u64(&mut bytes, evidence.totals.string_table_bytes);
    put_u16(&mut bytes, evidence.totals.writable_executable_loads);
    put_u16(&mut bytes, evidence.totals.executable_stacks);
    put_u16(&mut bytes, evidence.totals.embedded_search_paths);
    SemanticHash(sha256(&bytes))
}

fn decode_header(bytes: &[u8]) -> Result<X64TailWorkerElfHeader, X64TailWorkerElfError> {
    require_range(bytes, 0, u64::from(ELF_HEADER_BYTES), "ELF header")?;
    if &bytes[0..4] != b"\x7fELF" {
        return Err(X64TailWorkerElfError::Invalid("ELF magic"));
    }
    if bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 {
        return Err(X64TailWorkerElfError::Invalid("ELF class/data/version"));
    }
    if !matches!(bytes[7], 0 | 3) || bytes[8] != 0 || bytes[9..16].iter().any(|byte| *byte != 0) {
        return Err(X64TailWorkerElfError::Invalid("ELF ident padding"));
    }
    if read_u16(bytes, 16, "ELF type")? != ET_DYN
        || read_u16(bytes, 18, "ELF machine")? != EM_X86_64
        || read_u32(bytes, 20, "ELF version")? != 1
        || read_u32(bytes, 48, "ELF flags")? != 0
        || read_u16(bytes, 52, "ELF header size")? != ELF_HEADER_BYTES
        || read_u16(bytes, 54, "program header size")? != PROGRAM_HEADER_BYTES
    {
        return Err(X64TailWorkerElfError::Invalid("ELF header identity"));
    }
    let program_header_offset = read_u64(bytes, 32, "program header offset")?;
    let program_header_count = read_u16(bytes, 56, "program header count")?;
    if program_header_count == 0 || program_header_count > X64_TAIL_WORKER_ELF_MAX_PROGRAM_HEADERS {
        return Err(X64TailWorkerElfError::Limit {
            field: "program headers",
            limit: u64::from(X64_TAIL_WORKER_ELF_MAX_PROGRAM_HEADERS),
            actual: u64::from(program_header_count),
        });
    }
    require_table(
        bytes,
        program_header_offset,
        u64::from(PROGRAM_HEADER_BYTES),
        u64::from(program_header_count),
        "program header table",
    )?;

    let section_header_offset = read_u64(bytes, 40, "section header offset")?;
    let section_header_size = read_u16(bytes, 58, "section header size")?;
    let section_header_count = read_u16(bytes, 60, "section header count")?;
    let section_name_index = read_u16(bytes, 62, "section name index")?;
    if section_header_count == 0 {
        if section_header_offset != 0 || section_header_size != 0 || section_name_index != 0 {
            return Err(X64TailWorkerElfError::Invalid("empty section table"));
        }
    } else {
        if section_header_size != SECTION_HEADER_BYTES
            || section_header_count > X64_TAIL_WORKER_ELF_MAX_SECTION_HEADERS
            || section_name_index >= section_header_count
        {
            return Err(X64TailWorkerElfError::Invalid("section header table"));
        }
        require_table(
            bytes,
            section_header_offset,
            u64::from(SECTION_HEADER_BYTES),
            u64::from(section_header_count),
            "section header table",
        )?;
    }
    Ok(X64TailWorkerElfHeader {
        entry: read_u64(bytes, 24, "ELF entry")?,
        program_header_offset,
        program_header_count,
        section_header_offset,
        section_header_count,
    })
}

fn decode_segments(
    bytes: &[u8],
    header: &X64TailWorkerElfHeader,
) -> Result<Vec<X64TailWorkerElfSegment>, X64TailWorkerElfError> {
    let mut segments = Vec::with_capacity(usize::from(header.program_header_count));
    for ordinal in 0..header.program_header_count {
        let offset = header
            .program_header_offset
            .checked_add(u64::from(ordinal) * u64::from(PROGRAM_HEADER_BYTES))
            .ok_or(X64TailWorkerElfError::Overflow("program header offset"))?;
        let segment = X64TailWorkerElfSegment {
            ordinal,
            segment_type: read_u32(bytes, offset, "segment type")?,
            flags: read_u32(bytes, offset + 4, "segment flags")?,
            file_offset: read_u64(bytes, offset + 8, "segment file offset")?,
            virtual_address: read_u64(bytes, offset + 16, "segment virtual address")?,
            file_size: read_u64(bytes, offset + 32, "segment file size")?,
            memory_size: read_u64(bytes, offset + 40, "segment memory size")?,
            alignment: read_u64(bytes, offset + 48, "segment alignment")?,
        };
        validate_segment(bytes, &segment)?;
        segments.push(segment);
    }
    Ok(segments)
}

fn validate_segment(
    bytes: &[u8],
    segment: &X64TailWorkerElfSegment,
) -> Result<(), X64TailWorkerElfError> {
    if !matches!(
        segment.segment_type,
        PT_LOAD
            | PT_DYNAMIC
            | PT_INTERP
            | PT_NOTE
            | PT_PHDR
            | PT_TLS
            | PT_GNU_EH_FRAME
            | PT_GNU_STACK
            | PT_GNU_RELRO
    ) {
        return Err(X64TailWorkerElfError::Invalid("segment type"));
    }
    if segment.flags & !(PF_R | PF_W | PF_X) != 0 {
        return Err(X64TailWorkerElfError::Invalid("segment flags"));
    }
    if segment.memory_size < segment.file_size {
        return Err(X64TailWorkerElfError::Invalid("segment memory size"));
    }
    require_range(
        bytes,
        segment.file_offset,
        segment.file_size,
        "segment file range",
    )?;
    if segment.alignment != 0
        && (!segment.alignment.is_power_of_two()
            || (segment.file_offset % segment.alignment)
                != (segment.virtual_address % segment.alignment))
    {
        return Err(X64TailWorkerElfError::Invalid("segment alignment"));
    }
    Ok(())
}

struct SegmentLayout<'segments> {
    loads: Vec<&'segments X64TailWorkerElfSegment>,
    interpreter: &'segments X64TailWorkerElfSegment,
    dynamic: &'segments X64TailWorkerElfSegment,
}

fn validate_segment_layout<'segments>(
    _bytes: &[u8],
    header: &X64TailWorkerElfHeader,
    segments: &'segments [X64TailWorkerElfSegment],
) -> Result<SegmentLayout<'segments>, X64TailWorkerElfError> {
    let loads = segments
        .iter()
        .filter(|segment| segment.segment_type == PT_LOAD)
        .collect::<Vec<_>>();
    if loads.is_empty() || loads.len() > usize::from(X64_TAIL_WORKER_ELF_MAX_LOAD_SEGMENTS) {
        return Err(X64TailWorkerElfError::Limit {
            field: "load segments",
            limit: u64::from(X64_TAIL_WORKER_ELF_MAX_LOAD_SEGMENTS),
            actual: u64::try_from(loads.len()).unwrap_or(u64::MAX),
        });
    }
    let mut previous_end = None;
    for load in &loads {
        if load.flags & (PF_W | PF_X) == (PF_W | PF_X) {
            return Err(X64TailWorkerElfError::Invalid("writable executable load"));
        }
        let end = load
            .virtual_address
            .checked_add(load.memory_size)
            .ok_or(X64TailWorkerElfError::Overflow("load memory range"))?;
        if previous_end.is_some_and(|previous| load.virtual_address < previous) {
            return Err(X64TailWorkerElfError::Invalid("overlapping load segments"));
        }
        previous_end = Some(end);
    }
    let executable_entries = loads
        .iter()
        .filter(|load| {
            let end = load.virtual_address.saturating_add(load.memory_size);
            load.flags & PF_X != 0 && header.entry >= load.virtual_address && header.entry < end
        })
        .count();
    if executable_entries != 1 {
        return Err(X64TailWorkerElfError::Invalid("entry executable load"));
    }
    let interpreter = exactly_one(segments, PT_INTERP, "interpreter segment")?;
    let dynamic = exactly_one(segments, PT_DYNAMIC, "dynamic segment")?;
    let stack = exactly_one(segments, PT_GNU_STACK, "stack segment")?;
    let _relro = exactly_one(segments, PT_GNU_RELRO, "RELRO segment")?;
    if stack.flags & PF_X != 0 || stack.file_size != 0 || stack.memory_size != 0 {
        return Err(X64TailWorkerElfError::Invalid("executable stack"));
    }
    Ok(SegmentLayout {
        loads,
        interpreter,
        dynamic,
    })
}

fn exactly_one<'segments>(
    segments: &'segments [X64TailWorkerElfSegment],
    segment_type: u32,
    field: &'static str,
) -> Result<&'segments X64TailWorkerElfSegment, X64TailWorkerElfError> {
    let mut matches = segments
        .iter()
        .filter(|segment| segment.segment_type == segment_type);
    let value = matches
        .next()
        .ok_or(X64TailWorkerElfError::Invalid(field))?;
    if matches.next().is_some() {
        return Err(X64TailWorkerElfError::Invalid(field));
    }
    Ok(value)
}

fn decode_interpreter(
    bytes: &[u8],
    segment: &X64TailWorkerElfSegment,
) -> Result<String, X64TailWorkerElfError> {
    if segment.file_size < 2 || segment.file_size > X64_TAIL_WORKER_ELF_MAX_NAME_BYTES {
        return Err(X64TailWorkerElfError::Limit {
            field: "interpreter bytes",
            limit: X64_TAIL_WORKER_ELF_MAX_NAME_BYTES,
            actual: segment.file_size,
        });
    }
    let slice = slice_range(bytes, segment.file_offset, segment.file_size, "interpreter")?;
    let value = decode_exact_c_string(slice, true, "interpreter")?;
    if !value.starts_with('/') {
        return Err(X64TailWorkerElfError::Invalid("interpreter path"));
    }
    Ok(value)
}

struct DynamicInventory {
    entries: Vec<X64TailWorkerElfDynamicEntry>,
    dependencies: Vec<X64TailWorkerElfDependency>,
    flags: u64,
    flags_1: u64,
    string_table_bytes: u64,
}

fn decode_dynamic(
    bytes: &[u8],
    dynamic: &X64TailWorkerElfSegment,
    segments: &[X64TailWorkerElfSegment],
) -> Result<DynamicInventory, X64TailWorkerElfError> {
    if dynamic.file_size == 0 || !dynamic.file_size.is_multiple_of(DYNAMIC_ENTRY_BYTES) {
        return Err(X64TailWorkerElfError::Invalid("dynamic table size"));
    }
    let count = dynamic.file_size / DYNAMIC_ENTRY_BYTES;
    if count > u64::from(X64_TAIL_WORKER_ELF_MAX_DYNAMIC_ENTRIES) {
        return Err(X64TailWorkerElfError::Limit {
            field: "dynamic entries",
            limit: u64::from(X64_TAIL_WORKER_ELF_MAX_DYNAMIC_ENTRIES),
            actual: count,
        });
    }
    let mut entries = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    let mut needed_offsets = Vec::new();
    let mut string_table_address = None;
    let mut string_table_bytes = None;
    let mut flags = None;
    let mut flags_1 = None;
    let mut saw_null = false;
    for ordinal in 0..count {
        let offset = dynamic
            .file_offset
            .checked_add(ordinal * DYNAMIC_ENTRY_BYTES)
            .ok_or(X64TailWorkerElfError::Overflow("dynamic entry offset"))?;
        let tag = read_i64(bytes, offset, "dynamic tag")?;
        let value = read_u64(bytes, offset + 8, "dynamic value")?;
        if saw_null && (tag != DT_NULL || value != 0) {
            return Err(X64TailWorkerElfError::Invalid("dynamic data after NULL"));
        }
        if tag == DT_NULL && value != 0 {
            return Err(X64TailWorkerElfError::Invalid("dynamic NULL value"));
        }
        if tag == DT_NULL {
            saw_null = true;
        } else if saw_null {
            return Err(X64TailWorkerElfError::Invalid("dynamic NULL ordering"));
        }
        match tag {
            DT_NEEDED => needed_offsets.push(value),
            DT_STRTAB => set_once(&mut string_table_address, value, "DT_STRTAB")?,
            DT_STRSZ => set_once(&mut string_table_bytes, value, "DT_STRSZ")?,
            DT_FLAGS => set_once(&mut flags, value, "DT_FLAGS")?,
            DT_FLAGS_1 => set_once(&mut flags_1, value, "DT_FLAGS_1")?,
            DT_RPATH | DT_RUNPATH | DT_DEPAUDIT | DT_AUDIT | DT_AUXILIARY | DT_FILTER => {
                return Err(X64TailWorkerElfError::Invalid(
                    "embedded loader search policy",
                ));
            }
            _ => {}
        }
        entries.push(X64TailWorkerElfDynamicEntry {
            ordinal: u16::try_from(ordinal)
                .map_err(|_| X64TailWorkerElfError::Overflow("dynamic ordinal"))?,
            tag,
            value,
        });
    }
    if !saw_null {
        return Err(X64TailWorkerElfError::Invalid("missing dynamic NULL"));
    }
    if needed_offsets.is_empty()
        || needed_offsets.len() > usize::from(X64_TAIL_WORKER_ELF_MAX_DEPENDENCIES)
    {
        return Err(X64TailWorkerElfError::Limit {
            field: "dependencies",
            limit: u64::from(X64_TAIL_WORKER_ELF_MAX_DEPENDENCIES),
            actual: u64::try_from(needed_offsets.len()).unwrap_or(u64::MAX),
        });
    }
    let string_table_address =
        string_table_address.ok_or(X64TailWorkerElfError::Invalid("missing DT_STRTAB"))?;
    let string_table_bytes =
        string_table_bytes.ok_or(X64TailWorkerElfError::Invalid("missing DT_STRSZ"))?;
    if string_table_bytes == 0 || string_table_bytes > X64_TAIL_WORKER_ELF_MAX_STRING_TABLE_BYTES {
        return Err(X64TailWorkerElfError::Limit {
            field: "dynamic string table",
            limit: X64_TAIL_WORKER_ELF_MAX_STRING_TABLE_BYTES,
            actual: string_table_bytes,
        });
    }
    let string_table =
        map_virtual_file_range(bytes, segments, string_table_address, string_table_bytes)?;
    let mut names = BTreeSet::new();
    let mut dependencies = Vec::with_capacity(needed_offsets.len());
    for (ordinal, offset) in needed_offsets.into_iter().enumerate() {
        if offset >= string_table_bytes {
            return Err(X64TailWorkerElfError::Invalid("dependency string offset"));
        }
        let start = usize::try_from(offset)
            .map_err(|_| X64TailWorkerElfError::Overflow("dependency string offset"))?;
        let name = decode_bounded_c_string(
            &string_table[start..],
            X64_TAIL_WORKER_ELF_MAX_NAME_BYTES,
            false,
            "dependency name",
        )?;
        if !names.insert(name.clone()) {
            return Err(X64TailWorkerElfError::Invalid("duplicate dependency"));
        }
        dependencies.push(X64TailWorkerElfDependency {
            ordinal: u16::try_from(ordinal)
                .map_err(|_| X64TailWorkerElfError::Overflow("dependency ordinal"))?,
            string_offset: offset,
            name,
        });
    }
    Ok(DynamicInventory {
        entries,
        dependencies,
        flags: flags.unwrap_or(0),
        flags_1: flags_1.unwrap_or(0),
        string_table_bytes,
    })
}

fn set_once(
    slot: &mut Option<u64>,
    value: u64,
    field: &'static str,
) -> Result<(), X64TailWorkerElfError> {
    if slot.replace(value).is_some() {
        Err(X64TailWorkerElfError::Invalid(field))
    } else {
        Ok(())
    }
}

fn map_virtual_file_range<'bytes>(
    bytes: &'bytes [u8],
    segments: &[X64TailWorkerElfSegment],
    virtual_address: u64,
    size: u64,
) -> Result<&'bytes [u8], X64TailWorkerElfError> {
    let virtual_end = virtual_address
        .checked_add(size)
        .ok_or(X64TailWorkerElfError::Overflow("virtual string table"))?;
    let mut matches = segments.iter().filter(|segment| {
        if segment.segment_type != PT_LOAD {
            return false;
        }
        let file_virtual_end = segment
            .virtual_address
            .checked_add(segment.file_size)
            .unwrap_or(0);
        virtual_address >= segment.virtual_address && virtual_end <= file_virtual_end
    });
    let load = matches
        .next()
        .ok_or(X64TailWorkerElfError::Invalid("string table load mapping"))?;
    if matches.next().is_some() {
        return Err(X64TailWorkerElfError::Invalid(
            "ambiguous string table load mapping",
        ));
    }
    let relative = virtual_address - load.virtual_address;
    let file_offset = load
        .file_offset
        .checked_add(relative)
        .ok_or(X64TailWorkerElfError::Overflow("string table file offset"))?;
    slice_range(bytes, file_offset, size, "dynamic string table")
}

fn decode_exact_c_string(
    bytes: &[u8],
    allow_slash: bool,
    field: &'static str,
) -> Result<String, X64TailWorkerElfError> {
    if bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
        return Err(X64TailWorkerElfError::Invalid(field));
    }
    decode_name(&bytes[..bytes.len() - 1], allow_slash, field)
}

fn decode_bounded_c_string(
    bytes: &[u8],
    limit: u64,
    allow_slash: bool,
    field: &'static str,
) -> Result<String, X64TailWorkerElfError> {
    let retained = usize::try_from(limit)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    let end = bytes[..retained]
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(X64TailWorkerElfError::Invalid(field))?;
    decode_name(&bytes[..end], allow_slash, field)
}

fn decode_name(
    bytes: &[u8],
    allow_slash: bool,
    field: &'static str,
) -> Result<String, X64TailWorkerElfError> {
    if bytes.is_empty()
        || bytes.iter().any(|byte| !(0x20..=0x7e).contains(byte))
        || (!allow_slash && bytes.contains(&b'/'))
    {
        return Err(X64TailWorkerElfError::Invalid(field));
    }
    let value = std::str::from_utf8(bytes)
        .map_err(|_| X64TailWorkerElfError::Invalid(field))?
        .to_owned();
    if allow_slash && value.split('/').any(|component| component == "..") {
        return Err(X64TailWorkerElfError::Invalid(field));
    }
    Ok(value)
}

fn require_table(
    bytes: &[u8],
    offset: u64,
    width: u64,
    count: u64,
    field: &'static str,
) -> Result<(), X64TailWorkerElfError> {
    let size = width
        .checked_mul(count)
        .ok_or(X64TailWorkerElfError::Overflow(field))?;
    require_range(bytes, offset, size, field)
}

fn require_range(
    bytes: &[u8],
    offset: u64,
    size: u64,
    field: &'static str,
) -> Result<(), X64TailWorkerElfError> {
    let end = offset
        .checked_add(size)
        .ok_or(X64TailWorkerElfError::Overflow(field))?;
    if end > u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
        Err(X64TailWorkerElfError::Truncated(field))
    } else {
        Ok(())
    }
}

fn slice_range<'bytes>(
    bytes: &'bytes [u8],
    offset: u64,
    size: u64,
    field: &'static str,
) -> Result<&'bytes [u8], X64TailWorkerElfError> {
    require_range(bytes, offset, size, field)?;
    let start = usize::try_from(offset).map_err(|_| X64TailWorkerElfError::Overflow(field))?;
    let end_u64 = offset
        .checked_add(size)
        .ok_or(X64TailWorkerElfError::Overflow(field))?;
    let end = usize::try_from(end_u64).map_err(|_| X64TailWorkerElfError::Overflow(field))?;
    Ok(&bytes[start..end])
}

fn read_u16(bytes: &[u8], offset: u64, field: &'static str) -> Result<u16, X64TailWorkerElfError> {
    let slice = slice_range(bytes, offset, 2, field)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: u64, field: &'static str) -> Result<u32, X64TailWorkerElfError> {
    let slice = slice_range(bytes, offset, 4, field)?;
    Ok(u32::from_le_bytes(
        slice
            .try_into()
            .map_err(|_| X64TailWorkerElfError::Truncated(field))?,
    ))
}

fn read_u64(bytes: &[u8], offset: u64, field: &'static str) -> Result<u64, X64TailWorkerElfError> {
    let slice = slice_range(bytes, offset, 8, field)?;
    Ok(u64::from_le_bytes(
        slice
            .try_into()
            .map_err(|_| X64TailWorkerElfError::Truncated(field))?,
    ))
}

fn read_i64(bytes: &[u8], offset: u64, field: &'static str) -> Result<i64, X64TailWorkerElfError> {
    let slice = slice_range(bytes, offset, 8, field)?;
    Ok(i64::from_le_bytes(
        slice
            .try_into()
            .map_err(|_| X64TailWorkerElfError::Truncated(field))?,
    ))
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
pub fn probe_x64_tail_worker_elf_evidence_mutations(
    artifact: &X64TailWorkerArtifact,
    evidence: &X64TailWorkerElfEvidence,
) -> bool {
    let mut stale_policy = evidence.clone();
    stale_policy.policy_hash.0[0] ^= 1;

    let mut stale_segment = evidence.clone();
    stale_segment.segments[0].flags ^= 1;

    let mut stale_interpreter = evidence.clone();
    stale_interpreter.interpreter.push('x');

    let mut stale_hash = evidence.clone();
    stale_hash.evidence_hash.0[0] ^= 1;

    let mut resealed_dependency = evidence.clone();
    resealed_dependency.dependencies[0].name.push('x');
    resealed_dependency.evidence_hash = x64_tail_worker_elf_evidence_hash(&resealed_dependency);

    [
        stale_policy,
        stale_segment,
        stale_interpreter,
        stale_hash,
        resealed_dependency,
    ]
    .iter()
    .all(|mutation| verify_x64_tail_worker_elf_evidence(artifact, mutation).is_err())
}
