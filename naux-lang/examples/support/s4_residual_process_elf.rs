//! Fresh-process completion boundary for S4-WP5E.
//!
//! WP5D owns the canonical Machine-IR-to-x86-64 encoding.  This module does
//! not widen or rewrite that lowering.  It replaces the one admitted return
//! sequence with a same-sized jump to an appended verifier.  The verifier
//! observes the still-live frame, checks the terminal loop counters and the
//! consumed owner slot, then returns the checksum and observations to a
//! deterministic ELF startup.  The startup emits one fixed-size binary record
//! through `write(2)` and exits.  Expected checksum literals remain outside
//! the image and belong to the independent replay contract.

use crate::machine::MachineType;
use crate::residual::WorkWitness;
use crate::target::{
    verify_x64_encoding, EncodedX64, EncodingKind, StackHome, X64ElfError, X64Plan, X64Terminator,
};
use std::fmt;

const ELF_BASE: u64 = 0x0040_0000;
const ELF_ENTRY_OFFSET: usize = 0x100;
const ELF_ENTRY: u64 = ELF_BASE + ELF_ENTRY_OFFSET as u64;
const ELF_HEADER_BYTES: usize = 64;
const PROGRAM_HEADER_BYTES: usize = 56;
const PROGRAM_HEADER_COUNT: usize = 2;
const PROGRAM_HEADERS_END: usize = ELF_HEADER_BYTES + PROGRAM_HEADER_BYTES * PROGRAM_HEADER_COUNT;
const TARGET_ALIGNMENT: usize = 16;
const MAX_TARGET_BYTES: usize = 1_048_576;
const MAX_ELF_BYTES: usize = 1_114_112;
const SYS_WRITE: u32 = 1;
const SYS_EXIT: u32 = 60;
const FAILURE_EXIT_CODE: u32 = 70;

pub const RESULT_MAGIC: [u8; 8] = *b"NAUX5E01";
pub const RESULT_BYTES: u32 = 48;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletionWitness {
    pub return_start: u32,
    pub verifier_offset: u32,
    pub error_offset: u32,
    pub checksum_displacement: i32,
    pub outer_displacement: i32,
    pub inner_displacement: i32,
    pub owner_displacement: i32,
    pub expected_outer: u64,
    pub expected_inner: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessTarget {
    pub bytes: Vec<u8>,
    pub witness: CompletionWitness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessElf64 {
    pub bytes: Vec<u8>,
    pub ordinal: u64,
    pub startup_bytes: u32,
    pub target_offset: u32,
    pub target_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessElf64Facts {
    pub entry: u64,
    pub image_bytes: u64,
    pub startup_bytes: u64,
    pub target_offset: u64,
    pub target_bytes: u64,
    pub result_bytes: u64,
    pub load_flags: u32,
    pub stack_flags: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessElfError {
    Parent(String),
    InvalidWitness(String),
    InvalidTarget(String),
    InvalidElf(String),
}

impl fmt::Display for ProcessElfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (label, message) = match self {
            Self::Parent(message) => ("WP5D parent", message),
            Self::InvalidWitness(message) => ("completion witness", message),
            Self::InvalidTarget(message) => ("process target", message),
            Self::InvalidElf(message) => ("process ELF64", message),
        };
        write!(formatter, "S4-WP5E {label} error: {message}")
    }
}

impl std::error::Error for ProcessElfError {}

impl From<X64ElfError> for ProcessElfError {
    fn from(error: X64ElfError) -> Self {
        Self::Parent(error.to_string())
    }
}

/// Append a completion verifier without changing the sealed WP5D target
/// envelope or embedding a checksum oracle.
pub fn append_completion_witness(
    plan: &X64Plan,
    parent: &EncodedX64,
    work: &WorkWitness,
    owner_local: u32,
) -> Result<ProcessTarget, ProcessElfError> {
    verify_x64_encoding(plan, parent)?;
    let (witness, return_home, outer_home, inner_home, owner_home) =
        witness_inputs(plan, parent, work, owner_local)?;
    let bytes = reconstruct_process_target(
        parent,
        &witness,
        return_home,
        outer_home,
        inner_home,
        owner_home,
    )?;
    let target = ProcessTarget { bytes, witness };
    verify_process_target(plan, parent, work, owner_local, &target)?;
    Ok(target)
}

/// Independently reconstruct the completion appendix from the sealed parent.
pub fn verify_process_target(
    plan: &X64Plan,
    parent: &EncodedX64,
    work: &WorkWitness,
    owner_local: u32,
    process: &ProcessTarget,
) -> Result<(), ProcessElfError> {
    verify_x64_encoding(plan, parent)?;
    let (witness, return_home, outer_home, inner_home, owner_home) =
        witness_inputs(plan, parent, work, owner_local)?;
    if process.witness != witness {
        return Err(ProcessElfError::InvalidWitness(
            "completion receipt differs from the independently derived witness".into(),
        ));
    }
    let expected = reconstruct_process_target(
        parent,
        &witness,
        return_home,
        outer_home,
        inner_home,
        owner_home,
    )?;
    if process.bytes != expected || process.bytes.len() > MAX_TARGET_BYTES {
        return Err(ProcessElfError::InvalidTarget(
            "completion target differs from exact reconstruction or exceeds its limit".into(),
        ));
    }
    Ok(())
}

/// Wrap one verified process target in a sectionless ET_EXEC image.  The
/// ordinal is provenance metadata; it never selects a kernel implementation.
pub fn build_process_elf64(
    process: &ProcessTarget,
    ordinal: u64,
) -> Result<ProcessElf64, ProcessElfError> {
    if ordinal == 0 {
        return Err(ProcessElfError::InvalidElf(
            "artifact ordinal must be non-zero".into(),
        ));
    }
    if process.bytes.is_empty() || process.bytes.len() > MAX_TARGET_BYTES {
        return Err(ProcessElfError::InvalidElf(
            "process target is empty or exceeds its limit".into(),
        ));
    }
    let startup = process_startup(ordinal, 0)?;
    let target_offset = align_up(ELF_ENTRY_OFFSET + startup.len(), TARGET_ALIGNMENT)?;
    let startup = process_startup(ordinal, target_offset)?;
    let image_bytes = target_offset
        .checked_add(process.bytes.len())
        .ok_or_else(|| ProcessElfError::InvalidElf("image length overflowed".into()))?;
    if image_bytes > MAX_ELF_BYTES {
        return Err(ProcessElfError::InvalidElf(format!(
            "image uses {image_bytes} bytes; limit is {MAX_ELF_BYTES}"
        )));
    }
    let mut bytes = Vec::with_capacity(image_bytes);
    write_elf_header(&mut bytes, image_bytes as u64);
    if bytes.len() != PROGRAM_HEADERS_END {
        return Err(ProcessElfError::InvalidElf(
            "writer did not finish at the program-header boundary".into(),
        ));
    }
    bytes.resize(ELF_ENTRY_OFFSET, 0);
    bytes.extend_from_slice(&startup);
    bytes.resize(target_offset, 0);
    bytes.extend_from_slice(&process.bytes);
    let image = ProcessElf64 {
        bytes,
        ordinal,
        startup_bytes: as_u32(startup.len(), "startup bytes")?,
        target_offset: as_u32(target_offset, "target offset")?,
        target_bytes: as_u32(process.bytes.len(), "target bytes")?,
    };
    verify_process_elf64(&image, process)?;
    Ok(image)
}

pub fn verify_process_elf64(
    image: &ProcessElf64,
    process: &ProcessTarget,
) -> Result<ProcessElf64Facts, ProcessElfError> {
    if image.ordinal == 0
        || process.bytes.is_empty()
        || process.bytes.len() > MAX_TARGET_BYTES
        || image.bytes.len() > MAX_ELF_BYTES
    {
        return Err(ProcessElfError::InvalidElf(
            "image extent or ordinal is outside the admitted envelope".into(),
        ));
    }
    let startup = process_startup(image.ordinal, image.target_offset as usize)?;
    let expected_target_offset = align_up(ELF_ENTRY_OFFSET + startup.len(), TARGET_ALIGNMENT)?;
    if image.startup_bytes as usize != startup.len()
        || image.target_offset as usize != expected_target_offset
        || image.target_bytes as usize != process.bytes.len()
        || expected_target_offset.checked_add(process.bytes.len()) != Some(image.bytes.len())
    {
        return Err(ProcessElfError::InvalidElf(
            "image layout receipt drifted".into(),
        ));
    }
    let expected = reconstruct_elf(process, image.ordinal)?;
    if image.bytes != expected {
        return Err(ProcessElfError::InvalidElf(
            "image differs from independent reconstruction".into(),
        ));
    }
    verify_header(&image.bytes)?;
    Ok(ProcessElf64Facts {
        entry: ELF_ENTRY,
        image_bytes: image.bytes.len() as u64,
        startup_bytes: startup.len() as u64,
        target_offset: expected_target_offset as u64,
        target_bytes: process.bytes.len() as u64,
        result_bytes: RESULT_BYTES as u64,
        load_flags: 5,
        stack_flags: 6,
    })
}

fn witness_inputs(
    plan: &X64Plan,
    parent: &EncodedX64,
    work: &WorkWitness,
    owner_local: u32,
) -> Result<
    (
        CompletionWitness,
        StackHome,
        StackHome,
        StackHome,
        StackHome,
    ),
    ProcessElfError,
> {
    if work.outer.bound == 0
        || work.inner.bound == 0
        || work.inner.bound != plan.list_length
        || work.traversal_count
            != work
                .outer
                .bound
                .checked_mul(work.inner.bound)
                .ok_or_else(|| {
                    ProcessElfError::InvalidWitness("traversal count overflowed".into())
                })?
    {
        return Err(ProcessElfError::InvalidWitness(
            "loop bounds do not match the sealed traversal witness".into(),
        ));
    }
    let outer_home = slot_home(plan, work.outer.counter_local, MachineType::I64, "outer")?;
    let inner_home = slot_home(plan, work.inner.counter_local, MachineType::I64, "inner")?;
    let owner_home = slot_home(plan, owner_local, MachineType::OwnedI64List, "owner")?;
    // Requiring the checksum slot here binds the residual witness to the
    // target frame.  The actual return value lives in the register home
    // produced by the canonical final LoadSlot operation.
    let _checksum_home = slot_home(plan, work.checksum_local, MachineType::I64, "checksum")?;

    let returns = plan
        .blocks
        .iter()
        .filter_map(|block| match block.terminator {
            X64Terminator::Return { value } => Some((block, value)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if returns.len() != 1 {
        return Err(ProcessElfError::InvalidWitness(format!(
            "expected one completion return, found {}",
            returns.len()
        )));
    }
    let (block, return_home) = returns[0];
    let range = parent
        .ranges
        .iter()
        .find(|range| {
            range.block == block.id
                && range.kind == EncodingKind::Terminator
                && range.ordinal == block.operations.len() as u32
        })
        .ok_or_else(|| {
            ProcessElfError::InvalidWitness("completion return range is missing".into())
        })?;
    if range.end != parent.error_offset
        || range.end.checked_sub(range.start) != Some(9)
        || return_home.ty != MachineType::I64
    {
        return Err(ProcessElfError::InvalidWitness(
            "completion return is not the final canonical checksum load".into(),
        ));
    }
    let witness = CompletionWitness {
        return_start: range.start,
        verifier_offset: as_u32(parent.bytes.len(), "verifier offset")?,
        error_offset: parent.error_offset,
        checksum_displacement: return_home.displacement,
        outer_displacement: outer_home.displacement,
        inner_displacement: inner_home.displacement,
        owner_displacement: owner_home.displacement,
        expected_outer: work.outer.bound,
        expected_inner: work.inner.bound,
    };
    Ok((witness, return_home, outer_home, inner_home, owner_home))
}

fn slot_home(
    plan: &X64Plan,
    local: u32,
    ty: MachineType,
    label: &str,
) -> Result<StackHome, ProcessElfError> {
    let home = *plan.slot_homes.get(local as usize).ok_or_else(|| {
        ProcessElfError::InvalidWitness(format!("{label} local escapes target slots"))
    })?;
    if home.index != local || home.ty != ty {
        return Err(ProcessElfError::InvalidWitness(format!(
            "{label} home has the wrong identity or type"
        )));
    }
    Ok(home)
}

fn reconstruct_process_target(
    parent: &EncodedX64,
    witness: &CompletionWitness,
    return_home: StackHome,
    outer_home: StackHome,
    inner_home: StackHome,
    owner_home: StackHome,
) -> Result<Vec<u8>, ProcessElfError> {
    let start = witness.return_start as usize;
    let end = start
        .checked_add(9)
        .ok_or_else(|| ProcessElfError::InvalidTarget("return range overflowed".into()))?;
    let expected_return = load_bytes(0x85, return_home);
    if parent.bytes.get(start..start + 7) != Some(expected_return.as_slice())
        || parent.bytes.get(start + 7..end) != Some(&[0xc9, 0xc3])
        || witness.verifier_offset as usize != parent.bytes.len()
    {
        return Err(ProcessElfError::InvalidTarget(
            "sealed parent return bytes drifted".into(),
        ));
    }

    let mut bytes = parent.bytes.clone();
    let verifier = parent.bytes.len();
    bytes[start] = 0xe9;
    patch_rel32(&mut bytes, start + 1, verifier)?;
    bytes[start + 5..end].fill(0x90);

    bytes.extend_from_slice(&load_bytes(0x85, return_home));
    bytes.extend_from_slice(&load_bytes(0x8d, outer_home));
    mov_r8_imm64(&mut bytes, witness.expected_outer);
    bytes.extend_from_slice(&[0x4c, 0x39, 0xc1]);
    emit_rel32(&mut bytes, &[0x0f, 0x85], witness.error_offset as usize)?;
    bytes.extend_from_slice(&load_bytes(0x95, inner_home));
    mov_r8_imm64(&mut bytes, witness.expected_inner);
    bytes.extend_from_slice(&[0x4c, 0x39, 0xc2]);
    emit_rel32(&mut bytes, &[0x0f, 0x85], witness.error_offset as usize)?;
    bytes.extend_from_slice(&load_bytes(0xb5, owner_home));
    bytes.extend_from_slice(&[0x48, 0x85, 0xf6]);
    emit_rel32(&mut bytes, &[0x0f, 0x85], witness.error_offset as usize)?;
    bytes.extend_from_slice(&[0xc9, 0xc3]);
    Ok(bytes)
}

fn reconstruct_elf(process: &ProcessTarget, ordinal: u64) -> Result<Vec<u8>, ProcessElfError> {
    let provisional = process_startup(ordinal, 0)?;
    let target_offset = align_up(ELF_ENTRY_OFFSET + provisional.len(), TARGET_ALIGNMENT)?;
    let startup = process_startup(ordinal, target_offset)?;
    let image_bytes = target_offset
        .checked_add(process.bytes.len())
        .ok_or_else(|| ProcessElfError::InvalidElf("reconstruction overflowed".into()))?;
    let mut bytes = Vec::with_capacity(image_bytes);
    write_elf_header(&mut bytes, image_bytes as u64);
    bytes.resize(ELF_ENTRY_OFFSET, 0);
    bytes.extend_from_slice(&startup);
    bytes.resize(target_offset, 0);
    bytes.extend_from_slice(&process.bytes);
    Ok(bytes)
}

fn process_startup(ordinal: u64, target_offset: usize) -> Result<Vec<u8>, ProcessElfError> {
    let mut bytes = vec![0xe8, 0, 0, 0, 0];
    let displacement = relative_displacement(ELF_ENTRY_OFFSET + 1, target_offset)?;
    bytes[1..5].copy_from_slice(&displacement.to_le_bytes());
    bytes.extend_from_slice(&[0x48, 0x83, 0xec, RESULT_BYTES as u8]);
    mov_r8_imm64(&mut bytes, u64::from_le_bytes(RESULT_MAGIC));
    bytes.extend_from_slice(&[0x4c, 0x89, 0x04, 0x24]);
    mov_r8_imm64(&mut bytes, ordinal);
    bytes.extend_from_slice(&[0x4c, 0x89, 0x44, 0x24, 0x08]);
    bytes.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x10]);
    bytes.extend_from_slice(&[0x48, 0x89, 0x4c, 0x24, 0x18]);
    bytes.extend_from_slice(&[0x48, 0x89, 0x54, 0x24, 0x20]);
    bytes.extend_from_slice(&[0x48, 0x89, 0x74, 0x24, 0x28]);
    bytes.push(0xb8);
    bytes.extend_from_slice(&SYS_WRITE.to_le_bytes());
    bytes.push(0xbf);
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0x48, 0x89, 0xe6]);
    bytes.push(0xba);
    bytes.extend_from_slice(&RESULT_BYTES.to_le_bytes());
    bytes.extend_from_slice(&[0x0f, 0x05]);
    bytes.extend_from_slice(&[0x48, 0x83, 0xf8, RESULT_BYTES as u8]);
    let failure_fixup = bytes.len() + 2;
    bytes.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]);
    bytes.extend_from_slice(&[0x48, 0x83, 0xc4, RESULT_BYTES as u8]);
    bytes.extend_from_slice(&[0x31, 0xff]);
    bytes.push(0xb8);
    bytes.extend_from_slice(&SYS_EXIT.to_le_bytes());
    bytes.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    let failure = bytes.len();
    bytes.push(0xbf);
    bytes.extend_from_slice(&FAILURE_EXIT_CODE.to_le_bytes());
    bytes.push(0xb8);
    bytes.extend_from_slice(&SYS_EXIT.to_le_bytes());
    bytes.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    patch_rel32(&mut bytes, failure_fixup, failure)?;
    Ok(bytes)
}

fn verify_header(bytes: &[u8]) -> Result<(), ProcessElfError> {
    if bytes.get(..4) != Some(b"\x7fELF")
        || read_u16(bytes, 16)? != 2
        || read_u16(bytes, 18)? != 62
        || read_u64(bytes, 24)? != ELF_ENTRY
        || read_u64(bytes, 32)? != ELF_HEADER_BYTES as u64
        || read_u64(bytes, 40)? != 0
        || read_u16(bytes, 56)? != PROGRAM_HEADER_COUNT as u16
    {
        return Err(ProcessElfError::InvalidElf(
            "ELF identity or header envelope drifted".into(),
        ));
    }
    let load = ELF_HEADER_BYTES;
    let stack = ELF_HEADER_BYTES + PROGRAM_HEADER_BYTES;
    if read_u32(bytes, load)? != 1
        || read_u32(bytes, load + 4)? != 5
        || read_u64(bytes, load + 32)? != bytes.len() as u64
        || read_u64(bytes, load + 40)? != bytes.len() as u64
        || read_u32(bytes, stack)? != 0x6474_e551
        || read_u32(bytes, stack + 4)? != 6
    {
        return Err(ProcessElfError::InvalidElf(
            "RX load or RW-NX stack envelope drifted".into(),
        ));
    }
    Ok(())
}

fn load_bytes(modrm: u8, home: StackHome) -> Vec<u8> {
    let mut bytes = vec![0x48, 0x8b, modrm];
    bytes.extend_from_slice(&home.displacement.to_le_bytes());
    bytes
}

fn mov_r8_imm64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&[0x49, 0xb8]);
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn emit_rel32(bytes: &mut Vec<u8>, opcode: &[u8], target: usize) -> Result<(), ProcessElfError> {
    bytes.extend_from_slice(opcode);
    let displacement = bytes.len();
    bytes.extend_from_slice(&[0; 4]);
    patch_rel32(bytes, displacement, target)
}

fn patch_rel32(
    bytes: &mut [u8],
    displacement: usize,
    target: usize,
) -> Result<(), ProcessElfError> {
    let next = displacement
        .checked_add(4)
        .ok_or_else(|| ProcessElfError::InvalidTarget("rel32 overflowed".into()))?;
    let delta = i64::try_from(target).unwrap_or(i64::MAX) - i64::try_from(next).unwrap_or(i64::MIN);
    let delta = i32::try_from(delta)
        .map_err(|_| ProcessElfError::InvalidTarget("rel32 target is out of range".into()))?;
    let destination = bytes.get_mut(displacement..next).ok_or_else(|| {
        ProcessElfError::InvalidTarget("rel32 displacement escapes the byte stream".into())
    })?;
    destination.copy_from_slice(&delta.to_le_bytes());
    Ok(())
}

fn relative_displacement(
    displacement_offset: usize,
    target: usize,
) -> Result<i32, ProcessElfError> {
    let next = displacement_offset
        .checked_add(4)
        .ok_or_else(|| ProcessElfError::InvalidElf("call offset overflowed".into()))?;
    i32::try_from(
        i64::try_from(target).unwrap_or(i64::MAX) - i64::try_from(next).unwrap_or(i64::MIN),
    )
    .map_err(|_| ProcessElfError::InvalidElf("call target exceeds rel32".into()))
}

fn write_elf_header(bytes: &mut Vec<u8>, image_bytes: u64) {
    bytes.extend_from_slice(b"\x7fELF");
    bytes.extend_from_slice(&[2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    put_u16(bytes, 2);
    put_u16(bytes, 62);
    put_u32(bytes, 1);
    put_u64(bytes, ELF_ENTRY);
    put_u64(bytes, ELF_HEADER_BYTES as u64);
    put_u64(bytes, 0);
    put_u32(bytes, 0);
    put_u16(bytes, ELF_HEADER_BYTES as u16);
    put_u16(bytes, PROGRAM_HEADER_BYTES as u16);
    put_u16(bytes, PROGRAM_HEADER_COUNT as u16);
    put_u16(bytes, 0);
    put_u16(bytes, 0);
    put_u16(bytes, 0);
    put_u32(bytes, 1);
    put_u32(bytes, 5);
    put_u64(bytes, 0);
    put_u64(bytes, ELF_BASE);
    put_u64(bytes, ELF_BASE);
    put_u64(bytes, image_bytes);
    put_u64(bytes, image_bytes);
    put_u64(bytes, 4096);
    put_u32(bytes, 0x6474_e551);
    put_u32(bytes, 6);
    for _ in 0..5 {
        put_u64(bytes, 0);
    }
    put_u64(bytes, 16);
}

fn align_up(value: usize, alignment: usize) -> Result<usize, ProcessElfError> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(ProcessElfError::InvalidElf("invalid alignment".into()));
    }
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or_else(|| ProcessElfError::InvalidElf("alignment overflowed".into()))
}

fn as_u32(value: usize, label: &str) -> Result<u32, ProcessElfError> {
    u32::try_from(value).map_err(|_| ProcessElfError::InvalidTarget(format!("{label} exceeds u32")))
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

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ProcessElfError> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| ProcessElfError::InvalidElf("u16 field is truncated".into()))?
        .try_into()
        .expect("two-byte slice");
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ProcessElfError> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| ProcessElfError::InvalidElf("u32 field is truncated".into()))?
        .try_into()
        .expect("four-byte slice");
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ProcessElfError> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| ProcessElfError::InvalidElf("u64 field is truncated".into()))?
        .try_into()
        .expect("eight-byte slice");
    Ok(u64::from_le_bytes(raw))
}
