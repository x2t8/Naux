//! In-role timing wrapper for the sealed S4-WP5E process target.
//!
//! The process target is embedded byte-for-byte.  A new linker-free startup
//! reads CLOCK_MONOTONIC_RAW immediately before calling that target, validates
//! the returned checksum after target teardown, then reads the clock again.
//! Result serialization is after the second read.  This module only builds and
//! verifies bytes; execution belongs to a later controlled-host authority.

use crate::process::ProcessTarget;
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
const STACK_BYTES: u8 = 96;
const START_SECONDS: u8 = 0;
const START_NANOSECONDS: u8 = 8;
const END_SECONDS: u8 = 16;
const END_NANOSECONDS: u8 = 24;
const RESULT_OFFSET: u8 = 32;
const CHECKSUM_OFFSET: u8 = 48;
const OUTER_OFFSET: u8 = 56;
const INNER_OFFSET: u8 = 64;
const OWNER_OFFSET: u8 = 72;
const DURATION_OFFSET: u8 = 80;
const CLOCK_MONOTONIC_RAW: u32 = 4;
const SYS_WRITE: u32 = 1;
const SYS_CLOCK_GETTIME: u32 = 228;
const SYS_EXIT: u32 = 60;
const FAILURE_EXIT_CODE: u32 = 71;
const NANOSECONDS_PER_SECOND: u32 = 1_000_000_000;
const RESULT_OWNER: u64 = 1;

pub const RESULT_MAGIC: [u8; 8] = *b"NAUX7B01";
pub const RESULT_BYTES: u32 = 56;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimingElf64 {
    pub bytes: Vec<u8>,
    pub ordinal: u64,
    pub oracle: i64,
    pub startup_bytes: u32,
    pub target_offset: u32,
    pub target_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimingElf64Facts {
    pub entry: u64,
    pub image_bytes: u64,
    pub startup_bytes: u64,
    pub target_offset: u64,
    pub target_bytes: u64,
    pub result_bytes: u64,
    pub clock_reads: u32,
    pub owner_zero_checks: u32,
    pub result_owner: u64,
    pub load_flags: u32,
    pub stack_flags: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::enum_variant_names,
    reason = "the shared Invalid prefix is part of this sealed carrier's diagnostic vocabulary"
)]
pub enum TimingElfError {
    InvalidInput(String),
    InvalidStartup(String),
    InvalidElf(String),
}

impl fmt::Display for TimingElfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (label, message) = match self {
            Self::InvalidInput(message) => ("parent target", message),
            Self::InvalidStartup(message) => ("timing startup", message),
            Self::InvalidElf(message) => ("timing ELF64", message),
        };
        write!(formatter, "S4-WP7B {label} error: {message}")
    }
}

impl std::error::Error for TimingElfError {}

/// Wrap the exact WP5E target without running it or reading a clock.
pub fn build_timing_elf64(
    process: &ProcessTarget,
    ordinal: u64,
    oracle: i64,
) -> Result<TimingElf64, TimingElfError> {
    validate_inputs(process, ordinal)?;
    let provisional = timing_startup(ordinal, oracle, 0)?;
    let target_offset = align_up(ELF_ENTRY_OFFSET + provisional.len(), TARGET_ALIGNMENT)?;
    let startup = timing_startup(ordinal, oracle, target_offset)?;
    let image_bytes = target_offset
        .checked_add(process.bytes.len())
        .ok_or_else(|| TimingElfError::InvalidElf("image length overflowed".into()))?;
    if image_bytes > MAX_ELF_BYTES {
        return Err(TimingElfError::InvalidElf(format!(
            "image uses {image_bytes} bytes; limit is {MAX_ELF_BYTES}"
        )));
    }
    let mut bytes = Vec::with_capacity(image_bytes);
    write_elf_header(&mut bytes, image_bytes as u64);
    if bytes.len() != PROGRAM_HEADERS_END {
        return Err(TimingElfError::InvalidElf(
            "writer did not finish at the program-header boundary".into(),
        ));
    }
    bytes.resize(ELF_ENTRY_OFFSET, 0);
    bytes.extend_from_slice(&startup);
    bytes.resize(target_offset, 0);
    bytes.extend_from_slice(&process.bytes);
    let image = TimingElf64 {
        bytes,
        ordinal,
        oracle,
        startup_bytes: as_u32(startup.len(), "startup bytes")?,
        target_offset: as_u32(target_offset, "target offset")?,
        target_bytes: as_u32(process.bytes.len(), "target bytes")?,
    };
    verify_timing_elf64(&image, process)?;
    Ok(image)
}

/// Independently reconstruct the complete image and prove exact embedding.
pub fn verify_timing_elf64(
    image: &TimingElf64,
    process: &ProcessTarget,
) -> Result<TimingElf64Facts, TimingElfError> {
    validate_inputs(process, image.ordinal)?;
    if image.bytes.len() > MAX_ELF_BYTES {
        return Err(TimingElfError::InvalidElf(
            "image exceeds its byte limit".into(),
        ));
    }
    let startup = timing_startup(image.ordinal, image.oracle, image.target_offset as usize)?;
    let expected_target_offset = align_up(ELF_ENTRY_OFFSET + startup.len(), TARGET_ALIGNMENT)?;
    let expected_bytes = reconstruct_elf(process, image.ordinal, image.oracle)?;
    if image.startup_bytes as usize != startup.len()
        || image.target_offset as usize != expected_target_offset
        || image.target_bytes as usize != process.bytes.len()
        || image.bytes != expected_bytes
        || image.bytes.get(expected_target_offset..) != Some(process.bytes.as_slice())
    {
        return Err(TimingElfError::InvalidElf(
            "layout, reconstruction, or exact parent embedding drifted".into(),
        ));
    }
    verify_header(&image.bytes)?;
    Ok(TimingElf64Facts {
        entry: ELF_ENTRY,
        image_bytes: image.bytes.len() as u64,
        startup_bytes: startup.len() as u64,
        target_offset: expected_target_offset as u64,
        target_bytes: process.bytes.len() as u64,
        result_bytes: RESULT_BYTES as u64,
        clock_reads: 2,
        owner_zero_checks: 1,
        result_owner: RESULT_OWNER,
        load_flags: 5,
        stack_flags: 6,
    })
}

fn validate_inputs(process: &ProcessTarget, ordinal: u64) -> Result<(), TimingElfError> {
    if ordinal == 0 {
        return Err(TimingElfError::InvalidInput(
            "artifact ordinal must be non-zero".into(),
        ));
    }
    if process.bytes.is_empty() || process.bytes.len() > MAX_TARGET_BYTES {
        return Err(TimingElfError::InvalidInput(
            "process target is empty or exceeds its limit".into(),
        ));
    }
    Ok(())
}

fn reconstruct_elf(
    process: &ProcessTarget,
    ordinal: u64,
    oracle: i64,
) -> Result<Vec<u8>, TimingElfError> {
    let provisional = timing_startup(ordinal, oracle, 0)?;
    let target_offset = align_up(ELF_ENTRY_OFFSET + provisional.len(), TARGET_ALIGNMENT)?;
    let startup = timing_startup(ordinal, oracle, target_offset)?;
    let image_bytes = target_offset
        .checked_add(process.bytes.len())
        .ok_or_else(|| TimingElfError::InvalidElf("reconstruction overflowed".into()))?;
    let mut bytes = Vec::with_capacity(image_bytes);
    write_elf_header(&mut bytes, image_bytes as u64);
    bytes.resize(ELF_ENTRY_OFFSET, 0);
    bytes.extend_from_slice(&startup);
    bytes.resize(target_offset, 0);
    bytes.extend_from_slice(&process.bytes);
    Ok(bytes)
}

fn timing_startup(
    ordinal: u64,
    oracle: i64,
    target_offset: usize,
) -> Result<Vec<u8>, TimingElfError> {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(&[0x48, 0x83, 0xec, STACK_BYTES]);
    let mut failure_fixups = Vec::new();

    emit_clock_read(&mut bytes, START_SECONDS, &mut failure_fixups);

    let call = bytes.len();
    bytes.extend_from_slice(&[0xe8, 0, 0, 0, 0]);
    let call_next = ELF_ENTRY_OFFSET
        .checked_add(call)
        .and_then(|value| value.checked_add(5))
        .ok_or_else(|| TimingElfError::InvalidStartup("call position overflowed".into()))?;
    let call_delta = i64::try_from(target_offset).unwrap_or(i64::MAX)
        - i64::try_from(call_next).unwrap_or(i64::MIN);
    let call_delta = i32::try_from(call_delta)
        .map_err(|_| TimingElfError::InvalidStartup("target exceeds call rel32".into()))?;
    bytes[call + 1..call + 5].copy_from_slice(&call_delta.to_le_bytes());

    store_rax_rsp(&mut bytes, CHECKSUM_OFFSET);
    store_rcx_rsp(&mut bytes, OUTER_OFFSET);
    store_rdx_rsp(&mut bytes, INNER_OFFSET);
    store_rsi_rsp(&mut bytes, OWNER_OFFSET);
    bytes.extend_from_slice(&[0x48, 0x85, 0xf6]);
    failure_fixups.push(emit_jcc(&mut bytes, &[0x0f, 0x85]));
    mov_r8_imm64(&mut bytes, oracle as u64);
    bytes.extend_from_slice(&[0x4c, 0x39, 0xc0]);
    failure_fixups.push(emit_jcc(&mut bytes, &[0x0f, 0x85]));

    emit_clock_read(&mut bytes, END_SECONDS, &mut failure_fixups);
    validate_nanoseconds(&mut bytes, START_NANOSECONDS, &mut failure_fixups);
    validate_nanoseconds(&mut bytes, END_NANOSECONDS, &mut failure_fixups);

    load_rax_rsp(&mut bytes, END_SECONDS);
    bytes.extend_from_slice(&[0x48, 0x2b, 0x04, 0x24]);
    failure_fixups.push(emit_jcc(&mut bytes, &[0x0f, 0x88]));
    bytes.extend_from_slice(&[0x48, 0x69, 0xc0]);
    bytes.extend_from_slice(&NANOSECONDS_PER_SECOND.to_le_bytes());
    failure_fixups.push(emit_jcc(&mut bytes, &[0x0f, 0x80]));
    load_r8_rsp(&mut bytes, END_NANOSECONDS);
    bytes.extend_from_slice(&[0x4c, 0x01, 0xc0]);
    failure_fixups.push(emit_jcc(&mut bytes, &[0x0f, 0x80]));
    load_r8_rsp(&mut bytes, START_NANOSECONDS);
    bytes.extend_from_slice(&[0x4c, 0x29, 0xc0]);
    failure_fixups.push(emit_jcc(&mut bytes, &[0x0f, 0x88]));
    bytes.extend_from_slice(&[0x48, 0x85, 0xc0]);
    failure_fixups.push(emit_jcc(&mut bytes, &[0x0f, 0x8e]));
    store_rax_rsp(&mut bytes, DURATION_OFFSET);

    mov_r8_imm64(&mut bytes, u64::from_le_bytes(RESULT_MAGIC));
    store_r8_rsp(&mut bytes, RESULT_OFFSET);
    mov_r8_imm64(&mut bytes, ordinal);
    store_r8_rsp(&mut bytes, RESULT_OFFSET + 8);
    mov_r8_imm64(&mut bytes, RESULT_OWNER);
    store_r8_rsp(&mut bytes, OWNER_OFFSET);

    bytes.push(0xb8);
    bytes.extend_from_slice(&SYS_WRITE.to_le_bytes());
    bytes.push(0xbf);
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    lea_rsi_rsp(&mut bytes, RESULT_OFFSET);
    bytes.push(0xba);
    bytes.extend_from_slice(&RESULT_BYTES.to_le_bytes());
    bytes.extend_from_slice(&[0x0f, 0x05]);
    bytes.extend_from_slice(&[0x48, 0x83, 0xf8, RESULT_BYTES as u8]);
    failure_fixups.push(emit_jcc(&mut bytes, &[0x0f, 0x85]));
    bytes.extend_from_slice(&[0x48, 0x83, 0xc4, STACK_BYTES]);
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
    for displacement in failure_fixups {
        patch_rel32(&mut bytes, displacement, failure)?;
    }
    Ok(bytes)
}

fn emit_clock_read(bytes: &mut Vec<u8>, offset: u8, failures: &mut Vec<usize>) {
    bytes.push(0xb8);
    bytes.extend_from_slice(&SYS_CLOCK_GETTIME.to_le_bytes());
    bytes.push(0xbf);
    bytes.extend_from_slice(&CLOCK_MONOTONIC_RAW.to_le_bytes());
    lea_rsi_rsp(bytes, offset);
    bytes.extend_from_slice(&[0x0f, 0x05, 0x48, 0x85, 0xc0]);
    failures.push(emit_jcc(bytes, &[0x0f, 0x85]));
}

fn validate_nanoseconds(bytes: &mut Vec<u8>, offset: u8, failures: &mut Vec<usize>) {
    load_r8_rsp(bytes, offset);
    bytes.extend_from_slice(&[0x4d, 0x85, 0xc0]);
    failures.push(emit_jcc(bytes, &[0x0f, 0x88]));
    bytes.extend_from_slice(&[0x49, 0xc7, 0xc2]);
    bytes.extend_from_slice(&NANOSECONDS_PER_SECOND.to_le_bytes());
    bytes.extend_from_slice(&[0x4d, 0x39, 0xd0]);
    failures.push(emit_jcc(bytes, &[0x0f, 0x83]));
}

fn emit_jcc(bytes: &mut Vec<u8>, opcode: &[u8]) -> usize {
    bytes.extend_from_slice(opcode);
    let displacement = bytes.len();
    bytes.extend_from_slice(&[0; 4]);
    displacement
}

fn patch_rel32(bytes: &mut [u8], displacement: usize, target: usize) -> Result<(), TimingElfError> {
    let next = displacement
        .checked_add(4)
        .ok_or_else(|| TimingElfError::InvalidStartup("rel32 overflowed".into()))?;
    let delta = i64::try_from(target).unwrap_or(i64::MAX) - i64::try_from(next).unwrap_or(i64::MIN);
    let delta = i32::try_from(delta)
        .map_err(|_| TimingElfError::InvalidStartup("rel32 target is out of range".into()))?;
    let destination = bytes.get_mut(displacement..next).ok_or_else(|| {
        TimingElfError::InvalidStartup("rel32 displacement escapes the startup".into())
    })?;
    destination.copy_from_slice(&delta.to_le_bytes());
    Ok(())
}

fn lea_rsi_rsp(bytes: &mut Vec<u8>, offset: u8) {
    bytes.extend_from_slice(&[0x48, 0x8d, 0x74, 0x24, offset]);
}

fn load_rax_rsp(bytes: &mut Vec<u8>, offset: u8) {
    bytes.extend_from_slice(&[0x48, 0x8b, 0x44, 0x24, offset]);
}

fn load_r8_rsp(bytes: &mut Vec<u8>, offset: u8) {
    bytes.extend_from_slice(&[0x4c, 0x8b, 0x44, 0x24, offset]);
}

fn store_rax_rsp(bytes: &mut Vec<u8>, offset: u8) {
    bytes.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, offset]);
}

fn store_rcx_rsp(bytes: &mut Vec<u8>, offset: u8) {
    bytes.extend_from_slice(&[0x48, 0x89, 0x4c, 0x24, offset]);
}

fn store_rdx_rsp(bytes: &mut Vec<u8>, offset: u8) {
    bytes.extend_from_slice(&[0x48, 0x89, 0x54, 0x24, offset]);
}

fn store_rsi_rsp(bytes: &mut Vec<u8>, offset: u8) {
    bytes.extend_from_slice(&[0x48, 0x89, 0x74, 0x24, offset]);
}

fn store_r8_rsp(bytes: &mut Vec<u8>, offset: u8) {
    bytes.extend_from_slice(&[0x4c, 0x89, 0x44, 0x24, offset]);
}

fn mov_r8_imm64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&[0x49, 0xb8]);
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn verify_header(bytes: &[u8]) -> Result<(), TimingElfError> {
    if bytes.get(..4) != Some(b"\x7fELF")
        || read_u16(bytes, 16)? != 2
        || read_u16(bytes, 18)? != 62
        || read_u64(bytes, 24)? != ELF_ENTRY
        || read_u64(bytes, 32)? != ELF_HEADER_BYTES as u64
        || read_u64(bytes, 40)? != 0
        || read_u16(bytes, 56)? != PROGRAM_HEADER_COUNT as u16
    {
        return Err(TimingElfError::InvalidElf(
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
        return Err(TimingElfError::InvalidElf(
            "RX load or RW-NX stack envelope drifted".into(),
        ));
    }
    Ok(())
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

fn align_up(value: usize, alignment: usize) -> Result<usize, TimingElfError> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(TimingElfError::InvalidElf("invalid alignment".into()));
    }
    value
        .checked_add(alignment - 1)
        .map(|rounded| rounded & !(alignment - 1))
        .ok_or_else(|| TimingElfError::InvalidElf("alignment overflowed".into()))
}

fn as_u32(value: usize, label: &str) -> Result<u32, TimingElfError> {
    u32::try_from(value).map_err(|_| TimingElfError::InvalidElf(format!("{label} exceeds u32")))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, TimingElfError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| TimingElfError::InvalidElf("truncated u16".into()))?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, TimingElfError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| TimingElfError::InvalidElf("truncated u32".into()))?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, TimingElfError> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| TimingElfError::InvalidElf("truncated u64".into()))?;
    Ok(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
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
