//! ADR-0085 proof-only root dynamic-relocation inventory.
//!
//! This boundary decodes only dynamic `Rela` records authorized by accepted
//! ADR-0071 evidence, joins symbol-bearing records to ADR-0082/0084 evidence,
//! and returns no address or write authority.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_tail_worker_artifact::{
    verify_x64_tail_worker_artifact, x64_tail_worker_artifact_bytes, X64TailWorkerArtifact,
    X64TailWorkerArtifactError, X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT,
};
use super::x64_tail_worker_elf::{
    VerifiedX64TailWorkerElf, X64TailWorkerElfEvidence, X64_TAIL_WORKER_ELF_POLICY_ROOT,
};
use super::x64_tail_worker_root_selection::{
    VerifiedX64TailWorkerRootSelection, X64TailWorkerRootSelectionDecisionKind,
    X64TailWorkerRootSelectionEvidence, X64_TAIL_WORKER_ROOT_SELECTION_POLICY_ROOT,
};
use super::x64_tail_worker_root_symbols::{
    VerifiedX64TailWorkerRootSymbols, X64TailWorkerRootSymbolEvidence,
    X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT,
};
use std::collections::BTreeSet;
use std::fmt;

pub const X64_TAIL_WORKER_ROOT_RELOCATION_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_ROOT_RELOCATION_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_WORKER_ROOT_RELOCATION_MAX_RECORDS: u32 = 32_768;
pub const X64_TAIL_WORKER_ROOT_RELOCATION_POLICY_ROOT: SemanticHash = SemanticHash([
    0x82, 0x5e, 0xdb, 0xe0, 0x3b, 0xec, 0x0d, 0xdd, 0x1d, 0x5d, 0xba, 0xa8, 0xb2, 0x6c, 0xf0, 0x52,
    0xd7, 0x2c, 0xe6, 0xa3, 0x5c, 0xbe, 0x5a, 0xa9, 0xaa, 0x06, 0xb4, 0x14, 0x0a, 0x6c, 0x37, 0x79,
]);

const POLICY_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-relocation-policy:v1\0";
const RECORD_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-relocation-record:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:x86-64:tail-worker-root-relocation-evidence:v1\0";
const POLICY_CAPABILITIES: &[&str] = &[
    "verified-adr0071-dynamic-entry-and-load-segment-source-v1",
    "verified-adr0082-root-symbol-source-v1",
    "verified-adr0084-root-selection-source-v1",
    "dynamic-tag-authorized-rela-and-jmprel-only-v1",
    "checked-elf64-rela-width-and-extents-v1",
    "exact-relative-prefix-and-symbol-bearing-type-partition-v1",
    "exact-root-symbol-and-selection-decision-join-v1",
    "bounded-target-load-segment-coverage-v1",
    "artifact-local-exact-counts-without-global-layout-lock-v1",
    "domain-separated-record-and-aggregate-replay-v1",
    "proof-only-no-address-write-mapping-or-execution-v1",
];

const ELF64_RELA_BYTES: u64 = 24;
const RELOCATION_WRITE_BYTES: u64 = 8;
const PT_LOAD: u32 = 1;
const PF_W: u32 = 2;
const DT_PLTRELSZ: i64 = 2;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;
const DT_RELACOUNT: i64 = 0x6fff_fff9;
const R_X86_64_GLOB_DAT: u32 = 6;
const R_X86_64_JUMP_SLOT: u32 = 7;
const R_X86_64_RELATIVE: u32 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum X64TailWorkerRootRelocationTableKind {
    Rela = 0,
    JumpRel = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum X64TailWorkerRootRelocationClass {
    Relative = 0,
    Selected = 1,
    RefusedIfunc = 2,
    UnsupportedRequester = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerRootRelocationRecordEvidence {
    ordinal: u32,
    table_kind: X64TailWorkerRootRelocationTableKind,
    table_ordinal: u32,
    file_offset: u64,
    target_virtual_address: u64,
    raw_info: u64,
    symbol_ordinal: u16,
    relocation_type: u32,
    addend: i64,
    target_segment_ordinal: u16,
    root_symbol_evidence_hash: SemanticHash,
    selection_decision_evidence_hash: SemanticHash,
    class: X64TailWorkerRootRelocationClass,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerRootRelocationRecordEvidence {
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub const fn table_kind(&self) -> X64TailWorkerRootRelocationTableKind {
        self.table_kind
    }

    pub const fn table_ordinal(&self) -> u32 {
        self.table_ordinal
    }

    pub const fn target_virtual_address(&self) -> u64 {
        self.target_virtual_address
    }

    pub const fn symbol_ordinal(&self) -> u16 {
        self.symbol_ordinal
    }

    pub const fn relocation_type(&self) -> u32 {
        self.relocation_type
    }

    pub const fn addend(&self) -> i64 {
        self.addend
    }

    pub const fn target_segment_ordinal(&self) -> u16 {
        self.target_segment_ordinal
    }

    pub const fn class(&self) -> X64TailWorkerRootRelocationClass {
        self.class
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TailWorkerRootRelocationEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    policy_hash: SemanticHash,
    artifact_policy_hash: SemanticHash,
    artifact_hash: SemanticHash,
    inventory_policy_hash: SemanticHash,
    inventory_evidence_hash: SemanticHash,
    root_symbol_policy_hash: SemanticHash,
    root_symbol_evidence_hash: SemanticHash,
    root_selection_policy_hash: SemanticHash,
    root_selection_evidence_hash: SemanticHash,
    rela_address: u64,
    rela_bytes: u64,
    rela_count: u32,
    relative_prefix_count: u32,
    jmprel_address: u64,
    jmprel_bytes: u64,
    jmprel_count: u32,
    relative_count: u32,
    glob_dat_count: u32,
    jump_slot_count: u32,
    selected_count: u32,
    ifunc_refused_count: u32,
    unsupported_count: u32,
    records: Vec<X64TailWorkerRootRelocationRecordEvidence>,
    evidence_hash: SemanticHash,
}

impl X64TailWorkerRootRelocationEvidence {
    pub const fn policy_hash(&self) -> SemanticHash {
        self.policy_hash
    }

    pub const fn rela_count(&self) -> u32 {
        self.rela_count
    }

    pub const fn relative_prefix_count(&self) -> u32 {
        self.relative_prefix_count
    }

    pub const fn jmprel_count(&self) -> u32 {
        self.jmprel_count
    }

    pub const fn relative_count(&self) -> u32 {
        self.relative_count
    }

    pub const fn glob_dat_count(&self) -> u32 {
        self.glob_dat_count
    }

    pub const fn jump_slot_count(&self) -> u32 {
        self.jump_slot_count
    }

    pub const fn selected_count(&self) -> u32 {
        self.selected_count
    }

    pub const fn ifunc_refused_count(&self) -> u32 {
        self.ifunc_refused_count
    }

    pub const fn unsupported_count(&self) -> u32 {
        self.unsupported_count
    }

    pub fn records(&self) -> &[X64TailWorkerRootRelocationRecordEvidence] {
        &self.records
    }

    pub const fn evidence_hash(&self) -> SemanticHash {
        self.evidence_hash
    }
}

#[derive(Debug)]
pub struct VerifiedX64TailWorkerRootRelocations<'evidence> {
    evidence: &'evidence X64TailWorkerRootRelocationEvidence,
}

impl<'evidence> VerifiedX64TailWorkerRootRelocations<'evidence> {
    pub const fn evidence(&self) -> &'evidence X64TailWorkerRootRelocationEvidence {
        self.evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailWorkerRootRelocationError {
    Artifact(X64TailWorkerArtifactError),
    Invalid(&'static str),
    Limit {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    Overflow(&'static str),
    EvidenceMismatch,
}

impl fmt::Display for X64TailWorkerRootRelocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Artifact(error) => write!(formatter, "ADR-0085 artifact failed: {error}"),
            Self::Invalid(field) => write!(formatter, "invalid ADR-0085 {field}"),
            Self::Limit {
                field,
                limit,
                actual,
            } => write!(formatter, "ADR-0085 {field} {actual} exceeds limit {limit}"),
            Self::Overflow(field) => write!(formatter, "ADR-0085 {field} overflow"),
            Self::EvidenceMismatch => formatter.write_str("ADR-0085 evidence mismatch"),
        }
    }
}

impl std::error::Error for X64TailWorkerRootRelocationError {}

impl From<X64TailWorkerArtifactError> for X64TailWorkerRootRelocationError {
    fn from(value: X64TailWorkerArtifactError) -> Self {
        Self::Artifact(value)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn emit_x64_tail_worker_root_relocation_evidence(
    artifact: &X64TailWorkerArtifact,
    inventory: &VerifiedX64TailWorkerElf<'_>,
    root_symbols: &VerifiedX64TailWorkerRootSymbols<'_>,
    root_selection: &VerifiedX64TailWorkerRootSelection<'_>,
) -> Result<X64TailWorkerRootRelocationEvidence, X64TailWorkerRootRelocationError> {
    let verified_artifact = verify_x64_tail_worker_artifact(artifact)?;
    let bytes = x64_tail_worker_artifact_bytes(&verified_artifact)?;
    let inventory = inventory.evidence();
    let root_symbols = root_symbols.evidence();
    let root_selection = root_selection.evidence();
    validate_predecessors(artifact, inventory, root_symbols, root_selection)?;

    let rela_address = required_dynamic_value(inventory, DT_RELA, "DT_RELA")?;
    let rela_bytes = required_dynamic_value(inventory, DT_RELASZ, "DT_RELASZ")?;
    let rela_entry_bytes = required_dynamic_value(inventory, DT_RELAENT, "DT_RELAENT")?;
    let relative_prefix = required_dynamic_value(inventory, DT_RELACOUNT, "DT_RELACOUNT")?;
    let jmprel_address = required_dynamic_value(inventory, DT_JMPREL, "DT_JMPREL")?;
    let jmprel_bytes = required_dynamic_value(inventory, DT_PLTRELSZ, "DT_PLTRELSZ")?;
    let pltrel_kind = required_dynamic_value(inventory, DT_PLTREL, "DT_PLTREL")?;
    if rela_entry_bytes != ELF64_RELA_BYTES || pltrel_kind != DT_RELA as u64 {
        return Err(X64TailWorkerRootRelocationError::Invalid(
            "dynamic Rela entry identity",
        ));
    }
    let rela_count = checked_record_count(rela_bytes, "Rela records")?;
    let jmprel_count = checked_record_count(jmprel_bytes, "JmpRel records")?;
    let total_count =
        rela_count
            .checked_add(jmprel_count)
            .ok_or(X64TailWorkerRootRelocationError::Overflow(
                "total record count",
            ))?;
    let relative_prefix_count = u32::try_from(relative_prefix)
        .map_err(|_| X64TailWorkerRootRelocationError::Overflow("relative prefix count"))?;
    if total_count > X64_TAIL_WORKER_ROOT_RELOCATION_MAX_RECORDS
        || relative_prefix_count > rela_count
    {
        return Err(X64TailWorkerRootRelocationError::Limit {
            field: "relocation records",
            limit: u64::from(X64_TAIL_WORKER_ROOT_RELOCATION_MAX_RECORDS),
            actual: u64::from(total_count),
        });
    }
    let rela_file_offset = virtual_file_range(inventory, rela_address, rela_bytes)?;
    let jmprel_file_offset = virtual_file_range(inventory, jmprel_address, jmprel_bytes)?;
    require_nonoverlap(rela_address, rela_bytes, jmprel_address, jmprel_bytes)?;

    let mut records = Vec::with_capacity(
        usize::try_from(total_count)
            .map_err(|_| X64TailWorkerRootRelocationError::Overflow("record allocation"))?,
    );
    let mut counts = RelocationCounts::default();
    decode_table(
        &bytes,
        inventory,
        root_symbols,
        root_selection,
        X64TailWorkerRootRelocationTableKind::Rela,
        rela_file_offset,
        rela_count,
        relative_prefix_count,
        &mut counts,
        &mut records,
    )?;
    decode_table(
        &bytes,
        inventory,
        root_symbols,
        root_selection,
        X64TailWorkerRootRelocationTableKind::JumpRel,
        jmprel_file_offset,
        jmprel_count,
        0,
        &mut counts,
        &mut records,
    )?;
    validate_partition(
        total_count,
        rela_count,
        relative_prefix_count,
        jmprel_count,
        &counts,
    )?;

    let mut evidence = X64TailWorkerRootRelocationEvidence {
        schema_version: X64_TAIL_WORKER_ROOT_RELOCATION_SCHEMA_VERSION,
        policy_version: X64_TAIL_WORKER_ROOT_RELOCATION_POLICY_VERSION,
        policy_hash: x64_tail_worker_root_relocation_policy_hash(),
        artifact_policy_hash: X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT,
        artifact_hash: artifact.expectation().artifact_hash(),
        inventory_policy_hash: X64_TAIL_WORKER_ELF_POLICY_ROOT,
        inventory_evidence_hash: inventory.evidence_hash(),
        root_symbol_policy_hash: X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT,
        root_symbol_evidence_hash: root_symbols.evidence_hash(),
        root_selection_policy_hash: X64_TAIL_WORKER_ROOT_SELECTION_POLICY_ROOT,
        root_selection_evidence_hash: root_selection.evidence_hash(),
        rela_address,
        rela_bytes,
        rela_count,
        relative_prefix_count,
        jmprel_address,
        jmprel_bytes,
        jmprel_count,
        relative_count: counts.relative,
        glob_dat_count: counts.glob_dat,
        jump_slot_count: counts.jump_slot,
        selected_count: counts.selected,
        ifunc_refused_count: counts.ifunc_refused,
        unsupported_count: counts.unsupported,
        records,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = x64_tail_worker_root_relocation_evidence_hash(&evidence);
    Ok(evidence)
}

pub fn verify_x64_tail_worker_root_relocation_evidence<'evidence>(
    artifact: &X64TailWorkerArtifact,
    inventory: &VerifiedX64TailWorkerElf<'_>,
    root_symbols: &VerifiedX64TailWorkerRootSymbols<'_>,
    root_selection: &VerifiedX64TailWorkerRootSelection<'_>,
    evidence: &'evidence X64TailWorkerRootRelocationEvidence,
) -> Result<VerifiedX64TailWorkerRootRelocations<'evidence>, X64TailWorkerRootRelocationError> {
    preflight_evidence(evidence)?;
    let expected = emit_x64_tail_worker_root_relocation_evidence(
        artifact,
        inventory,
        root_symbols,
        root_selection,
    )?;
    if &expected != evidence {
        return Err(X64TailWorkerRootRelocationError::EvidenceMismatch);
    }
    Ok(VerifiedX64TailWorkerRootRelocations { evidence })
}

pub fn x64_tail_worker_root_relocation_policy_hash() -> SemanticHash {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(POLICY_DOMAIN);
    put_version(&mut bytes, X64_TAIL_WORKER_ROOT_RELOCATION_SCHEMA_VERSION);
    put_version(&mut bytes, X64_TAIL_WORKER_ROOT_RELOCATION_POLICY_VERSION);
    put_u32(&mut bytes, X64_TAIL_WORKER_ROOT_RELOCATION_MAX_RECORDS);
    for value in [
        ELF64_RELA_BYTES,
        RELOCATION_WRITE_BYTES,
        u64::from(PT_LOAD),
        u64::from(PF_W),
        DT_PLTRELSZ as u64,
        DT_RELA as u64,
        DT_RELASZ as u64,
        DT_RELAENT as u64,
        DT_PLTREL as u64,
        DT_JMPREL as u64,
        DT_RELACOUNT as u64,
        u64::from(R_X86_64_GLOB_DAT),
        u64::from(R_X86_64_JUMP_SLOT),
        u64::from(R_X86_64_RELATIVE),
    ] {
        put_u64(&mut bytes, value);
    }
    put_hash(&mut bytes, X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT);
    put_hash(&mut bytes, X64_TAIL_WORKER_ELF_POLICY_ROOT);
    put_hash(&mut bytes, X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT);
    put_hash(&mut bytes, X64_TAIL_WORKER_ROOT_SELECTION_POLICY_ROOT);
    put_u16(
        &mut bytes,
        u16::try_from(POLICY_CAPABILITIES.len()).unwrap_or(u16::MAX),
    );
    for capability in POLICY_CAPABILITIES {
        put_string(&mut bytes, capability);
    }
    SemanticHash(sha256(&bytes))
}

pub fn x64_tail_worker_root_relocation_evidence_hash(
    evidence: &X64TailWorkerRootRelocationEvidence,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(1024 + evidence.records.len() * 32);
    bytes.extend_from_slice(EVIDENCE_DOMAIN);
    put_version(&mut bytes, evidence.schema_version);
    put_version(&mut bytes, evidence.policy_version);
    put_hash(&mut bytes, evidence.policy_hash);
    put_hash(&mut bytes, evidence.artifact_policy_hash);
    put_hash(&mut bytes, evidence.artifact_hash);
    put_hash(&mut bytes, evidence.inventory_policy_hash);
    put_hash(&mut bytes, evidence.inventory_evidence_hash);
    put_hash(&mut bytes, evidence.root_symbol_policy_hash);
    put_hash(&mut bytes, evidence.root_symbol_evidence_hash);
    put_hash(&mut bytes, evidence.root_selection_policy_hash);
    put_hash(&mut bytes, evidence.root_selection_evidence_hash);
    put_u64(&mut bytes, evidence.rela_address);
    put_u64(&mut bytes, evidence.rela_bytes);
    put_u32(&mut bytes, evidence.rela_count);
    put_u32(&mut bytes, evidence.relative_prefix_count);
    put_u64(&mut bytes, evidence.jmprel_address);
    put_u64(&mut bytes, evidence.jmprel_bytes);
    put_u32(&mut bytes, evidence.jmprel_count);
    put_u32(&mut bytes, evidence.relative_count);
    put_u32(&mut bytes, evidence.glob_dat_count);
    put_u32(&mut bytes, evidence.jump_slot_count);
    put_u32(&mut bytes, evidence.selected_count);
    put_u32(&mut bytes, evidence.ifunc_refused_count);
    put_u32(&mut bytes, evidence.unsupported_count);
    put_u32(
        &mut bytes,
        u32::try_from(evidence.records.len()).unwrap_or(u32::MAX),
    );
    for record in &evidence.records {
        put_hash(&mut bytes, record.evidence_hash);
    }
    SemanticHash(sha256(&bytes))
}

fn relocation_record_hash(record: &X64TailWorkerRootRelocationRecordEvidence) -> SemanticHash {
    let mut bytes = Vec::with_capacity(192);
    bytes.extend_from_slice(RECORD_DOMAIN);
    put_u32(&mut bytes, record.ordinal);
    put_u8(&mut bytes, record.table_kind as u8);
    put_u32(&mut bytes, record.table_ordinal);
    put_u64(&mut bytes, record.file_offset);
    put_u64(&mut bytes, record.target_virtual_address);
    put_u64(&mut bytes, record.raw_info);
    put_u16(&mut bytes, record.symbol_ordinal);
    put_u32(&mut bytes, record.relocation_type);
    put_u64(&mut bytes, record.addend as u64);
    put_u16(&mut bytes, record.target_segment_ordinal);
    put_hash(&mut bytes, record.root_symbol_evidence_hash);
    put_hash(&mut bytes, record.selection_decision_evidence_hash);
    put_u8(&mut bytes, record.class as u8);
    SemanticHash(sha256(&bytes))
}

#[derive(Default)]
struct RelocationCounts {
    relative: u32,
    glob_dat: u32,
    jump_slot: u32,
    selected: u32,
    ifunc_refused: u32,
    unsupported: u32,
}

fn validate_partition(
    total_count: u32,
    rela_count: u32,
    relative_prefix_count: u32,
    jmprel_count: u32,
    counts: &RelocationCounts,
) -> Result<(), X64TailWorkerRootRelocationError> {
    let rela_partition = counts
        .relative
        .checked_add(counts.glob_dat)
        .ok_or(X64TailWorkerRootRelocationError::Overflow("Rela partition"))?;
    let total_partition = rela_partition.checked_add(counts.jump_slot).ok_or(
        X64TailWorkerRootRelocationError::Overflow("relocation partition"),
    )?;
    let symbol_partition = counts
        .selected
        .checked_add(counts.ifunc_refused)
        .and_then(|count| count.checked_add(counts.unsupported))
        .ok_or(X64TailWorkerRootRelocationError::Overflow(
            "symbol class partition",
        ))?;
    let symbol_records = counts.glob_dat.checked_add(counts.jump_slot).ok_or(
        X64TailWorkerRootRelocationError::Overflow("symbol record partition"),
    )?;
    if counts.relative != relative_prefix_count
        || rela_partition != rela_count
        || counts.jump_slot != jmprel_count
        || total_partition != total_count
        || symbol_partition != symbol_records
    {
        return Err(X64TailWorkerRootRelocationError::Invalid(
            "artifact-local relocation partition",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn decode_table(
    bytes: &[u8],
    inventory: &X64TailWorkerElfEvidence,
    root_symbols: &X64TailWorkerRootSymbolEvidence,
    root_selection: &X64TailWorkerRootSelectionEvidence,
    table_kind: X64TailWorkerRootRelocationTableKind,
    table_file_offset: u64,
    table_count: u32,
    relative_prefix_count: u32,
    counts: &mut RelocationCounts,
    records: &mut Vec<X64TailWorkerRootRelocationRecordEvidence>,
) -> Result<(), X64TailWorkerRootRelocationError> {
    for table_ordinal in 0..table_count {
        let file_offset = table_file_offset
            .checked_add(u64::from(table_ordinal) * ELF64_RELA_BYTES)
            .ok_or(X64TailWorkerRootRelocationError::Overflow(
                "record file offset",
            ))?;
        let target_virtual_address = read_u64(bytes, file_offset, "relocation offset")?;
        let raw_info = read_u64(bytes, file_offset + 8, "relocation info")?;
        let addend = read_i64(bytes, file_offset + 16, "relocation addend")?;
        let raw_symbol_ordinal = raw_info >> 32;
        let symbol_ordinal = u16::try_from(raw_symbol_ordinal)
            .map_err(|_| X64TailWorkerRootRelocationError::Overflow("symbol ordinal"))?;
        let relocation_type = raw_info as u32;
        let target_segment_ordinal = target_segment(inventory, target_virtual_address)?;
        let ordinal = u32::try_from(records.len())
            .map_err(|_| X64TailWorkerRootRelocationError::Overflow("record ordinal"))?;
        let (class, root_symbol_evidence_hash, selection_decision_evidence_hash) = classify_record(
            root_symbols,
            root_selection,
            table_kind,
            table_ordinal,
            relative_prefix_count,
            symbol_ordinal,
            relocation_type,
            counts,
        )?;
        let mut record = X64TailWorkerRootRelocationRecordEvidence {
            ordinal,
            table_kind,
            table_ordinal,
            file_offset,
            target_virtual_address,
            raw_info,
            symbol_ordinal,
            relocation_type,
            addend,
            target_segment_ordinal,
            root_symbol_evidence_hash,
            selection_decision_evidence_hash,
            class,
            evidence_hash: SemanticHash::ZERO,
        };
        record.evidence_hash = relocation_record_hash(&record);
        records.push(record);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn classify_record(
    root_symbols: &X64TailWorkerRootSymbolEvidence,
    root_selection: &X64TailWorkerRootSelectionEvidence,
    table_kind: X64TailWorkerRootRelocationTableKind,
    table_ordinal: u32,
    relative_prefix_count: u32,
    symbol_ordinal: u16,
    relocation_type: u32,
    counts: &mut RelocationCounts,
) -> Result<
    (X64TailWorkerRootRelocationClass, SemanticHash, SemanticHash),
    X64TailWorkerRootRelocationError,
> {
    if table_kind == X64TailWorkerRootRelocationTableKind::Rela
        && table_ordinal < relative_prefix_count
    {
        if symbol_ordinal != 0 || relocation_type != R_X86_64_RELATIVE {
            return Err(X64TailWorkerRootRelocationError::Invalid(
                "relative prefix record",
            ));
        }
        counts.relative = checked_increment(counts.relative, "relative count")?;
        return Ok((
            X64TailWorkerRootRelocationClass::Relative,
            SemanticHash::ZERO,
            SemanticHash::ZERO,
        ));
    }
    match table_kind {
        X64TailWorkerRootRelocationTableKind::Rela if relocation_type == R_X86_64_GLOB_DAT => {
            counts.glob_dat = checked_increment(counts.glob_dat, "GLOB_DAT count")?;
        }
        X64TailWorkerRootRelocationTableKind::JumpRel if relocation_type == R_X86_64_JUMP_SLOT => {
            counts.jump_slot = checked_increment(counts.jump_slot, "JUMP_SLOT count")?;
        }
        _ => {
            return Err(X64TailWorkerRootRelocationError::Invalid(
                "relocation table/type partition",
            ));
        }
    }
    if symbol_ordinal == 0 {
        return Err(X64TailWorkerRootRelocationError::Invalid(
            "symbol-bearing zero ordinal",
        ));
    }
    let symbol = root_symbols
        .object()
        .symbols()
        .get(usize::from(symbol_ordinal))
        .ok_or(X64TailWorkerRootRelocationError::Invalid(
            "relocation symbol ordinal",
        ))?;
    if symbol.ordinal() != symbol_ordinal || symbol.is_defined() {
        return Err(X64TailWorkerRootRelocationError::Invalid(
            "relocation root symbol identity",
        ));
    }
    let mut decisions = root_selection.decisions().iter().filter(|decision| {
        decision.requester_symbol_ordinal() == symbol_ordinal
            && decision.requester_symbol_evidence_hash() == symbol.evidence_hash()
            && decision.name() == symbol.name()
    });
    let decision = decisions.next();
    if decisions.next().is_some() {
        return Err(X64TailWorkerRootRelocationError::Invalid(
            "duplicate selection decision",
        ));
    }
    match decision {
        Some(decision)
            if decision.decision_kind() == X64TailWorkerRootSelectionDecisionKind::Selected =>
        {
            counts.selected = checked_increment(counts.selected, "selected count")?;
            Ok((
                X64TailWorkerRootRelocationClass::Selected,
                symbol.evidence_hash(),
                decision.evidence_hash(),
            ))
        }
        Some(decision) => {
            counts.ifunc_refused = checked_increment(counts.ifunc_refused, "IFUNC refusal count")?;
            Ok((
                X64TailWorkerRootRelocationClass::RefusedIfunc,
                symbol.evidence_hash(),
                decision.evidence_hash(),
            ))
        }
        None => {
            counts.unsupported = checked_increment(counts.unsupported, "unsupported count")?;
            Ok((
                X64TailWorkerRootRelocationClass::UnsupportedRequester,
                symbol.evidence_hash(),
                SemanticHash::ZERO,
            ))
        }
    }
}

fn validate_predecessors(
    artifact: &X64TailWorkerArtifact,
    inventory: &X64TailWorkerElfEvidence,
    root_symbols: &X64TailWorkerRootSymbolEvidence,
    root_selection: &X64TailWorkerRootSelectionEvidence,
) -> Result<(), X64TailWorkerRootRelocationError> {
    let artifact_hash = artifact.expectation().artifact_hash();
    if inventory.policy_hash() != X64_TAIL_WORKER_ELF_POLICY_ROOT
        || inventory.artifact_hash() != artifact_hash
        || root_symbols.policy_hash() != X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT
        || root_symbols.object().artifact_hash() != artifact_hash
        || root_symbols.symbol_count() != 108
        || root_selection.policy_hash() != X64_TAIL_WORKER_ROOT_SELECTION_POLICY_ROOT
        || root_selection.root_symbol_evidence_hash() != root_symbols.evidence_hash()
    {
        return Err(X64TailWorkerRootRelocationError::Invalid(
            "predecessor identity",
        ));
    }
    Ok(())
}

fn preflight_evidence(
    evidence: &X64TailWorkerRootRelocationEvidence,
) -> Result<(), X64TailWorkerRootRelocationError> {
    let record_count = u32::try_from(evidence.records.len())
        .map_err(|_| X64TailWorkerRootRelocationError::Overflow("evidence record count"))?;
    let total_count = evidence
        .rela_count
        .checked_add(evidence.jmprel_count)
        .ok_or(X64TailWorkerRootRelocationError::Overflow(
            "evidence total count",
        ))?;
    let expected_rela_bytes = u64::from(evidence.rela_count)
        .checked_mul(ELF64_RELA_BYTES)
        .ok_or(X64TailWorkerRootRelocationError::Overflow(
            "evidence Rela bytes",
        ))?;
    let expected_jmprel_bytes = u64::from(evidence.jmprel_count)
        .checked_mul(ELF64_RELA_BYTES)
        .ok_or(X64TailWorkerRootRelocationError::Overflow(
            "evidence JmpRel bytes",
        ))?;
    if evidence.schema_version != X64_TAIL_WORKER_ROOT_RELOCATION_SCHEMA_VERSION
        || evidence.policy_version != X64_TAIL_WORKER_ROOT_RELOCATION_POLICY_VERSION
        || evidence.policy_hash != X64_TAIL_WORKER_ROOT_RELOCATION_POLICY_ROOT
        || evidence.artifact_policy_hash != X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT
        || evidence.inventory_policy_hash != X64_TAIL_WORKER_ELF_POLICY_ROOT
        || evidence.root_symbol_policy_hash != X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT
        || evidence.root_selection_policy_hash != X64_TAIL_WORKER_ROOT_SELECTION_POLICY_ROOT
        || total_count > X64_TAIL_WORKER_ROOT_RELOCATION_MAX_RECORDS
        || record_count != total_count
        || evidence.relative_prefix_count > evidence.rela_count
        || evidence.rela_bytes != expected_rela_bytes
        || evidence.jmprel_bytes != expected_jmprel_bytes
        || x64_tail_worker_root_relocation_evidence_hash(evidence) != evidence.evidence_hash
    {
        return Err(X64TailWorkerRootRelocationError::EvidenceMismatch);
    }
    let mut targets = BTreeSet::new();
    let mut counts = RelocationCounts::default();
    for (ordinal, record) in evidence.records.iter().enumerate() {
        let ordinal = u32::try_from(ordinal).unwrap_or(u32::MAX);
        let expected_table = if ordinal < evidence.rela_count {
            X64TailWorkerRootRelocationTableKind::Rela
        } else {
            X64TailWorkerRootRelocationTableKind::JumpRel
        };
        let expected_table_ordinal = match expected_table {
            X64TailWorkerRootRelocationTableKind::Rela => ordinal,
            X64TailWorkerRootRelocationTableKind::JumpRel => {
                ordinal.checked_sub(evidence.rela_count).unwrap_or(u32::MAX)
            }
        };
        if record.ordinal != ordinal
            || record.table_kind != expected_table
            || record.table_ordinal != expected_table_ordinal
            || record.table_ordinal
                >= match expected_table {
                    X64TailWorkerRootRelocationTableKind::Rela => evidence.rela_count,
                    X64TailWorkerRootRelocationTableKind::JumpRel => evidence.jmprel_count,
                }
            || !targets.insert(record.target_virtual_address)
            || relocation_record_hash(record) != record.evidence_hash
        {
            return Err(X64TailWorkerRootRelocationError::EvidenceMismatch);
        }
        if ordinal < evidence.relative_prefix_count {
            if record.class != X64TailWorkerRootRelocationClass::Relative
                || record.relocation_type != R_X86_64_RELATIVE
            {
                return Err(X64TailWorkerRootRelocationError::EvidenceMismatch);
            }
        } else {
            let expected_type = match expected_table {
                X64TailWorkerRootRelocationTableKind::Rela => R_X86_64_GLOB_DAT,
                X64TailWorkerRootRelocationTableKind::JumpRel => R_X86_64_JUMP_SLOT,
            };
            if record.class == X64TailWorkerRootRelocationClass::Relative
                || record.relocation_type != expected_type
            {
                return Err(X64TailWorkerRootRelocationError::EvidenceMismatch);
            }
        }
        match record.relocation_type {
            R_X86_64_RELATIVE => counts.relative += 1,
            R_X86_64_GLOB_DAT => counts.glob_dat += 1,
            R_X86_64_JUMP_SLOT => counts.jump_slot += 1,
            _ => return Err(X64TailWorkerRootRelocationError::EvidenceMismatch),
        }
        match record.class {
            X64TailWorkerRootRelocationClass::Relative => {
                if record.symbol_ordinal != 0
                    || record.relocation_type != R_X86_64_RELATIVE
                    || record.root_symbol_evidence_hash != SemanticHash::ZERO
                    || record.selection_decision_evidence_hash != SemanticHash::ZERO
                {
                    return Err(X64TailWorkerRootRelocationError::EvidenceMismatch);
                }
            }
            X64TailWorkerRootRelocationClass::UnsupportedRequester => {
                if record.symbol_ordinal == 0
                    || record.root_symbol_evidence_hash == SemanticHash::ZERO
                    || record.selection_decision_evidence_hash != SemanticHash::ZERO
                {
                    return Err(X64TailWorkerRootRelocationError::EvidenceMismatch);
                }
                counts.unsupported += 1;
            }
            X64TailWorkerRootRelocationClass::Selected => {
                if record.symbol_ordinal == 0
                    || record.root_symbol_evidence_hash == SemanticHash::ZERO
                    || record.selection_decision_evidence_hash == SemanticHash::ZERO
                {
                    return Err(X64TailWorkerRootRelocationError::EvidenceMismatch);
                }
                counts.selected += 1;
            }
            X64TailWorkerRootRelocationClass::RefusedIfunc => {
                if record.symbol_ordinal == 0
                    || record.root_symbol_evidence_hash == SemanticHash::ZERO
                    || record.selection_decision_evidence_hash == SemanticHash::ZERO
                {
                    return Err(X64TailWorkerRootRelocationError::EvidenceMismatch);
                }
                counts.ifunc_refused += 1;
            }
        }
    }
    validate_partition(
        total_count,
        evidence.rela_count,
        evidence.relative_prefix_count,
        evidence.jmprel_count,
        &counts,
    )?;
    if evidence.relative_count != counts.relative
        || evidence.glob_dat_count != counts.glob_dat
        || evidence.jump_slot_count != counts.jump_slot
        || evidence.selected_count != counts.selected
        || evidence.ifunc_refused_count != counts.ifunc_refused
        || evidence.unsupported_count != counts.unsupported
    {
        return Err(X64TailWorkerRootRelocationError::EvidenceMismatch);
    }
    Ok(())
}

fn required_dynamic_value(
    inventory: &X64TailWorkerElfEvidence,
    tag: i64,
    field: &'static str,
) -> Result<u64, X64TailWorkerRootRelocationError> {
    let mut entries = inventory
        .dynamic_entries()
        .iter()
        .filter(|entry| entry.tag() == tag);
    let value = entries
        .next()
        .ok_or(X64TailWorkerRootRelocationError::Invalid(field))?
        .value();
    if entries.next().is_some() {
        return Err(X64TailWorkerRootRelocationError::Invalid(field));
    }
    Ok(value)
}

fn checked_record_count(
    bytes: u64,
    field: &'static str,
) -> Result<u32, X64TailWorkerRootRelocationError> {
    if bytes == 0 || !bytes.is_multiple_of(ELF64_RELA_BYTES) {
        return Err(X64TailWorkerRootRelocationError::Invalid(field));
    }
    u32::try_from(bytes / ELF64_RELA_BYTES)
        .map_err(|_| X64TailWorkerRootRelocationError::Overflow(field))
}

fn virtual_file_range(
    inventory: &X64TailWorkerElfEvidence,
    address: u64,
    size: u64,
) -> Result<u64, X64TailWorkerRootRelocationError> {
    let end = address
        .checked_add(size)
        .ok_or(X64TailWorkerRootRelocationError::Overflow(
            "table virtual extent",
        ))?;
    let mut matches = inventory.segments().iter().filter(|segment| {
        if segment.segment_type() != PT_LOAD {
            return false;
        }
        let segment_end = segment
            .virtual_address()
            .checked_add(segment.file_size())
            .unwrap_or(0);
        address >= segment.virtual_address() && end <= segment_end
    });
    let segment = matches
        .next()
        .ok_or(X64TailWorkerRootRelocationError::Invalid(
            "table load coverage",
        ))?;
    if matches.next().is_some() {
        return Err(X64TailWorkerRootRelocationError::Invalid(
            "ambiguous table load coverage",
        ));
    }
    segment
        .file_offset()
        .checked_add(address - segment.virtual_address())
        .ok_or(X64TailWorkerRootRelocationError::Overflow(
            "table file offset",
        ))
}

fn target_segment(
    inventory: &X64TailWorkerElfEvidence,
    address: u64,
) -> Result<u16, X64TailWorkerRootRelocationError> {
    let end = address
        .checked_add(RELOCATION_WRITE_BYTES)
        .ok_or(X64TailWorkerRootRelocationError::Overflow("target extent"))?;
    let mut matches = inventory.segments().iter().filter(|segment| {
        if segment.segment_type() != PT_LOAD || segment.flags() & PF_W == 0 {
            return false;
        }
        let segment_end = segment
            .virtual_address()
            .checked_add(segment.memory_size())
            .unwrap_or(0);
        address >= segment.virtual_address() && end <= segment_end
    });
    let segment = matches
        .next()
        .ok_or(X64TailWorkerRootRelocationError::Invalid(
            "writable target load coverage",
        ))?;
    if matches.next().is_some() {
        return Err(X64TailWorkerRootRelocationError::Invalid(
            "ambiguous target load coverage",
        ));
    }
    Ok(segment.ordinal())
}

fn require_nonoverlap(
    left_address: u64,
    left_size: u64,
    right_address: u64,
    right_size: u64,
) -> Result<(), X64TailWorkerRootRelocationError> {
    let left_end =
        left_address
            .checked_add(left_size)
            .ok_or(X64TailWorkerRootRelocationError::Overflow(
                "left table extent",
            ))?;
    let right_end =
        right_address
            .checked_add(right_size)
            .ok_or(X64TailWorkerRootRelocationError::Overflow(
                "right table extent",
            ))?;
    if left_address < right_end && right_address < left_end {
        return Err(X64TailWorkerRootRelocationError::Invalid(
            "overlapping relocation tables",
        ));
    }
    Ok(())
}

fn checked_increment(
    value: u32,
    field: &'static str,
) -> Result<u32, X64TailWorkerRootRelocationError> {
    value
        .checked_add(1)
        .ok_or(X64TailWorkerRootRelocationError::Overflow(field))
}

fn read_u64(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<u64, X64TailWorkerRootRelocationError> {
    let start =
        usize::try_from(offset).map_err(|_| X64TailWorkerRootRelocationError::Overflow(field))?;
    let end = start
        .checked_add(8)
        .ok_or(X64TailWorkerRootRelocationError::Overflow(field))?;
    let value = bytes
        .get(start..end)
        .ok_or(X64TailWorkerRootRelocationError::Invalid(field))?;
    Ok(u64::from_le_bytes(value.try_into().map_err(|_| {
        X64TailWorkerRootRelocationError::Invalid(field)
    })?))
}

fn read_i64(
    bytes: &[u8],
    offset: u64,
    field: &'static str,
) -> Result<i64, X64TailWorkerRootRelocationError> {
    Ok(read_u64(bytes, offset, field)? as i64)
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn probe_x64_tail_worker_root_relocation_decoder_mutations(
    artifact: &X64TailWorkerArtifact,
    inventory: &VerifiedX64TailWorkerElf<'_>,
    root_symbols: &VerifiedX64TailWorkerRootSymbols<'_>,
    root_selection: &VerifiedX64TailWorkerRootSelection<'_>,
    evidence: &X64TailWorkerRootRelocationEvidence,
) -> bool {
    let Ok(verified_artifact) = verify_x64_tail_worker_artifact(artifact) else {
        return false;
    };
    let Ok(bytes) = x64_tail_worker_artifact_bytes(&verified_artifact) else {
        return false;
    };
    let inventory = inventory.evidence();
    let root_symbols = root_symbols.evidence();
    let root_selection = root_selection.evidence();
    let Ok(baseline) =
        decode_probe_records(&bytes, inventory, root_symbols, root_selection, evidence)
    else {
        return false;
    };
    if baseline != evidence.records {
        return false;
    }
    let Some(relative) = evidence.records.first() else {
        return false;
    };
    let Some(symbol_bearing) = evidence
        .records
        .iter()
        .find(|record| record.symbol_ordinal != 0)
    else {
        return false;
    };
    if evidence.records.len() < 2 {
        return false;
    }
    let last_end = evidence
        .records
        .iter()
        .filter_map(|record| record.file_offset.checked_add(ELF64_RELA_BYTES))
        .max()
        .and_then(|end| usize::try_from(end).ok());
    let Some(last_end) = last_end.filter(|end| *end <= bytes.len()) else {
        return false;
    };

    let mutations = [
        mutate_u64(&bytes, relative.file_offset + 8, R_X86_64_GLOB_DAT.into()),
        mutate_u64(
            &bytes,
            symbol_bearing.file_offset + 8,
            u64::from(symbol_bearing.relocation_type),
        ),
        mutate_u64(&bytes, relative.file_offset, 0),
        mutate_u64(
            &bytes,
            evidence.records[1].file_offset,
            relative.target_virtual_address,
        ),
        mutate_u64(
            &bytes,
            relative.file_offset + 16,
            (relative.addend as u64) ^ 1,
        ),
    ];
    let all_mutations_rejected = mutations.into_iter().all(|mutation| {
        let Some(mutated) = mutation else {
            return false;
        };
        decode_probe_records(&mutated, inventory, root_symbols, root_selection, evidence).is_err()
    });
    let truncation_rejected = last_end > 0
        && decode_probe_records(
            &bytes[..last_end - 1],
            inventory,
            root_symbols,
            root_selection,
            evidence,
        )
        .is_err();
    all_mutations_rejected && truncation_rejected
}

#[cfg(debug_assertions)]
fn decode_probe_records(
    bytes: &[u8],
    inventory: &X64TailWorkerElfEvidence,
    root_symbols: &X64TailWorkerRootSymbolEvidence,
    root_selection: &X64TailWorkerRootSelectionEvidence,
    evidence: &X64TailWorkerRootRelocationEvidence,
) -> Result<Vec<X64TailWorkerRootRelocationRecordEvidence>, X64TailWorkerRootRelocationError> {
    let rela_file_offset =
        virtual_file_range(inventory, evidence.rela_address, evidence.rela_bytes)?;
    let jmprel_file_offset =
        virtual_file_range(inventory, evidence.jmprel_address, evidence.jmprel_bytes)?;
    let total_count = evidence
        .rela_count
        .checked_add(evidence.jmprel_count)
        .ok_or(X64TailWorkerRootRelocationError::Overflow(
            "probe total count",
        ))?;
    let mut records = Vec::with_capacity(
        usize::try_from(total_count)
            .map_err(|_| X64TailWorkerRootRelocationError::Overflow("probe record allocation"))?,
    );
    let mut counts = RelocationCounts::default();
    decode_table(
        bytes,
        inventory,
        root_symbols,
        root_selection,
        X64TailWorkerRootRelocationTableKind::Rela,
        rela_file_offset,
        evidence.rela_count,
        evidence.relative_prefix_count,
        &mut counts,
        &mut records,
    )?;
    decode_table(
        bytes,
        inventory,
        root_symbols,
        root_selection,
        X64TailWorkerRootRelocationTableKind::JumpRel,
        jmprel_file_offset,
        evidence.jmprel_count,
        0,
        &mut counts,
        &mut records,
    )?;
    validate_partition(
        total_count,
        evidence.rela_count,
        evidence.relative_prefix_count,
        evidence.jmprel_count,
        &counts,
    )?;
    let mut targets = BTreeSet::new();
    if records
        .iter()
        .any(|record| !targets.insert(record.target_virtual_address))
        || records != evidence.records
    {
        return Err(X64TailWorkerRootRelocationError::EvidenceMismatch);
    }
    Ok(records)
}

#[cfg(debug_assertions)]
fn mutate_u64(bytes: &[u8], offset: u64, value: u64) -> Option<Vec<u8>> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(8)?;
    let target = bytes.get(start..end)?;
    if target == value.to_le_bytes() {
        return None;
    }
    let mut mutated = bytes.to_vec();
    mutated
        .get_mut(start..end)?
        .copy_from_slice(&value.to_le_bytes());
    Some(mutated)
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn probe_x64_tail_worker_root_relocation_mutations(
    artifact: &X64TailWorkerArtifact,
    inventory: &VerifiedX64TailWorkerElf<'_>,
    root_symbols: &VerifiedX64TailWorkerRootSymbols<'_>,
    root_selection: &VerifiedX64TailWorkerRootSelection<'_>,
    evidence: &X64TailWorkerRootRelocationEvidence,
) -> bool {
    let mut shallow = evidence.clone();
    shallow.relative_count = shallow.relative_count.saturating_sub(1);

    let mut coherent_record = evidence.clone();
    if let Some(record) = coherent_record
        .records
        .iter_mut()
        .find(|record| record.class == X64TailWorkerRootRelocationClass::Selected)
    {
        record.class = X64TailWorkerRootRelocationClass::UnsupportedRequester;
        record.selection_decision_evidence_hash = SemanticHash::ZERO;
        record.evidence_hash = relocation_record_hash(record);
    }
    coherent_record.selected_count = coherent_record.selected_count.saturating_sub(1);
    coherent_record.unsupported_count = coherent_record.unsupported_count.saturating_add(1);
    coherent_record.evidence_hash = x64_tail_worker_root_relocation_evidence_hash(&coherent_record);

    let mut coherent_addend = evidence.clone();
    if let Some(record) = coherent_addend.records.first_mut() {
        record.addend ^= 1;
        record.evidence_hash = relocation_record_hash(record);
    }
    coherent_addend.evidence_hash = x64_tail_worker_root_relocation_evidence_hash(&coherent_addend);

    let mut coherent_duplicate_target = evidence.clone();
    if coherent_duplicate_target.records.len() > 1 {
        let duplicate = coherent_duplicate_target.records[0].target_virtual_address;
        coherent_duplicate_target.records[1].target_virtual_address = duplicate;
        coherent_duplicate_target.records[1].evidence_hash =
            relocation_record_hash(&coherent_duplicate_target.records[1]);
    }
    coherent_duplicate_target.evidence_hash =
        x64_tail_worker_root_relocation_evidence_hash(&coherent_duplicate_target);

    let mut coherent_reorder = evidence.clone();
    if coherent_reorder.records.len() > 1 {
        coherent_reorder.records.swap(0, 1);
    }
    coherent_reorder.evidence_hash =
        x64_tail_worker_root_relocation_evidence_hash(&coherent_reorder);

    let all_rejected = [
        &shallow,
        &coherent_record,
        &coherent_addend,
        &coherent_duplicate_target,
        &coherent_reorder,
    ]
    .into_iter()
    .all(|mutation| {
        verify_x64_tail_worker_root_relocation_evidence(
            artifact,
            inventory,
            root_symbols,
            root_selection,
            mutation,
        )
        .is_err()
    });
    all_rejected
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    put_u16(bytes, version.0);
    put_u16(bytes, version.1);
    put_u16(bytes, version.2);
}

fn put_hash(bytes: &mut Vec<u8>, value: SemanticHash) {
    bytes.extend_from_slice(&value.0);
}

fn put_string(bytes: &mut Vec<u8>, value: &str) {
    put_u16(bytes, u16::try_from(value.len()).unwrap_or(u16::MAX));
    bytes.extend_from_slice(value.as_bytes());
}

fn put_u8(bytes: &mut Vec<u8>, value: u8) {
    bytes.push(value);
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_relocation_policy_root_is_frozen() {
        assert_eq!(
            x64_tail_worker_root_relocation_policy_hash(),
            X64_TAIL_WORKER_ROOT_RELOCATION_POLICY_ROOT
        );
    }

    #[test]
    fn production_module_has_no_forbidden_authority() {
        let source = include_str!("x64_tail_worker_root_relocations.rs");
        let imports = source
            .lines()
            .filter(|line| line.trim_start().starts_with("use "))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [
            "std::fs",
            "std::path",
            "std::process",
            "readelf",
            "dlsym",
            "libloading",
            "x64_tail_enveloped_native",
            "x64_native_process",
            "x64_standalone",
            "x64_target::raw",
            "Instant",
            "SystemTime",
        ] {
            assert!(
                !imports.contains(forbidden),
                "ADR-0085 production module imports forbidden authority {forbidden}"
            );
        }
    }
}
