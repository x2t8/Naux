//! Quarantined ELF64 envelope for the bounded S4-WP8F gate.
//!
//! The frozen WP5D writer remains the only ELF constructor. This module
//! adapts already-verified WP8E function bytes to that writer and then parses
//! the complete image independently. It never writes an executable file,
//! starts a process, reads a clock, or measures performance.

use crate::baseline::{build_elf64, EncodedX64};
use crate::residency_encoding::ResidencyEncodedX64;
use std::fmt;

const ELF_BASE: u64 = 0x0040_0000;
const ELF_ENTRY_OFFSET: usize = 0x100;
const ELF_ENTRY: u64 = ELF_BASE + ELF_ENTRY_OFFSET as u64;
const ELF_HEADER_BYTES: usize = 64;
const PROGRAM_HEADER_BYTES: usize = 56;
const PROGRAM_HEADER_COUNT: usize = 2;
const PROGRAM_HEADERS_END: usize = ELF_HEADER_BYTES + PROGRAM_HEADER_BYTES * PROGRAM_HEADER_COUNT;
const TARGET_OFFSET: usize = 0x110;
const TARGET_ALIGNMENT: usize = 16;
const MAX_TARGET_BYTES: usize = 1_048_576;
const MAX_ELF_BYTES: usize = 1_114_112;
const STARTUP_SUFFIX: [u8; 11] = [
    0x31, 0xff, // xor edi, edi
    0xb8, 0x3c, 0, 0, 0, // mov eax, SYS_exit
    0x0f, 0x05, // syscall
    0x0f, 0x0b, // ud2
];
const ELF_REPORT_DOMAIN: &[u8] = b"NAUX:s4-register-residency-elf-report:v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidencyElf64Image {
    pub bytes: Vec<u8>,
    pub target_offset: u32,
    pub target_bytes: u32,
    pub target_hash: naux::core::SemanticHash,
    pub image_hash: naux::core::SemanticHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedResidencyElf64Facts {
    pub entry: u64,
    pub image_bytes: u64,
    pub target_offset: u64,
    pub target_bytes: u64,
    pub load_flags: u32,
    pub stack_flags: u32,
    pub target_hash: naux::core::SemanticHash,
    pub image_hash: naux::core::SemanticHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResidencyElfError {
    InvalidInput(String),
    InvalidElf(String),
}

impl fmt::Display for ResidencyElfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, message) = match self {
            Self::InvalidInput(message) => ("input", message),
            Self::InvalidElf(message) => ("ELF64", message),
        };
        write!(formatter, "S4-WP8F residency {kind} error: {message}")
    }
}

impl std::error::Error for ResidencyElfError {}

/// Wrap verified candidate function bytes in the exact frozen WP5D envelope.
pub fn build_register_residency_elf(
    candidate: &ResidencyEncodedX64,
) -> Result<ResidencyElf64Image, ResidencyElfError> {
    validate_candidate_extent(candidate)?;
    let adapted = EncodedX64 {
        bytes: candidate.bytes.clone(),
        block_offsets: Vec::new(),
        error_offset: candidate.error_offset,
        ranges: Vec::new(),
    };
    let baseline_image = build_elf64(&adapted)
        .map_err(|error| ResidencyElfError::InvalidInput(error.to_string()))?;
    let image = ResidencyElf64Image {
        target_hash: hash(&candidate.bytes),
        image_hash: hash(&baseline_image.bytes),
        bytes: baseline_image.bytes,
        target_offset: baseline_image.target_offset,
        target_bytes: baseline_image.target_bytes,
    };
    verify_register_residency_elf(&image, candidate)?;
    Ok(image)
}

/// Parse and reconstruct the complete ELF image without trusting its receipt.
pub fn verify_register_residency_elf(
    image: &ResidencyElf64Image,
    candidate: &ResidencyEncodedX64,
) -> Result<VerifiedResidencyElf64Facts, ResidencyElfError> {
    validate_candidate_extent(candidate)?;
    let bytes = &image.bytes;
    let expected_len = TARGET_OFFSET
        .checked_add(candidate.bytes.len())
        .ok_or_else(|| ResidencyElfError::InvalidElf("image length overflowed".into()))?;
    if bytes.len() != expected_len || bytes.len() > MAX_ELF_BYTES {
        return Err(ResidencyElfError::InvalidElf(
            "image extent does not equal the fixed envelope plus target".into(),
        ));
    }

    expect(bytes, 0, b"\x7fELF", "magic")?;
    expect(bytes, 4, &[2, 1, 1, 0, 0], "identity")?;
    zeroes(bytes, 9, 16, "identity padding")?;
    expect_u16(bytes, 16, 2, "type")?;
    expect_u16(bytes, 18, 62, "machine")?;
    expect_u32(bytes, 20, 1, "version")?;
    expect_u64(bytes, 24, ELF_ENTRY, "entry")?;
    expect_u64(bytes, 32, ELF_HEADER_BYTES as u64, "program-header offset")?;
    expect_u64(bytes, 40, 0, "section-header offset")?;
    expect_u32(bytes, 48, 0, "flags")?;
    expect_u16(bytes, 52, ELF_HEADER_BYTES as u16, "header size")?;
    expect_u16(
        bytes,
        54,
        PROGRAM_HEADER_BYTES as u16,
        "program-header size",
    )?;
    expect_u16(
        bytes,
        56,
        PROGRAM_HEADER_COUNT as u16,
        "program-header count",
    )?;
    expect_u16(bytes, 58, 0, "section-header size")?;
    expect_u16(bytes, 60, 0, "section-header count")?;
    expect_u16(bytes, 62, 0, "section-name index")?;

    let load = ELF_HEADER_BYTES;
    expect_u32(bytes, load, 1, "load type")?;
    expect_u32(bytes, load + 4, 5, "load flags")?;
    expect_u64(bytes, load + 8, 0, "load offset")?;
    expect_u64(bytes, load + 16, ELF_BASE, "load virtual address")?;
    expect_u64(bytes, load + 24, ELF_BASE, "load physical address")?;
    expect_u64(bytes, load + 32, bytes.len() as u64, "load file size")?;
    expect_u64(bytes, load + 40, bytes.len() as u64, "load memory size")?;
    expect_u64(bytes, load + 48, 4096, "load alignment")?;

    let stack = ELF_HEADER_BYTES + PROGRAM_HEADER_BYTES;
    expect_u32(bytes, stack, 0x6474_e551, "stack type")?;
    expect_u32(bytes, stack + 4, 6, "stack flags")?;
    for offset in [8, 16, 24, 32, 40] {
        expect_u64(bytes, stack + offset, 0, "stack zero field")?;
    }
    expect_u64(bytes, stack + 48, 16, "stack alignment")?;
    zeroes(
        bytes,
        PROGRAM_HEADERS_END,
        ELF_ENTRY_OFFSET,
        "header padding",
    )?;

    if image.target_offset as usize != TARGET_OFFSET
        || image.target_bytes as usize != candidate.bytes.len()
        || !TARGET_OFFSET.is_multiple_of(TARGET_ALIGNMENT)
    {
        return Err(ResidencyElfError::InvalidElf(
            "target layout receipt drifted".into(),
        ));
    }
    expect(bytes, ELF_ENTRY_OFFSET, &[0xe8], "startup call opcode")?;
    let call_displacement = read_i32(bytes, ELF_ENTRY_OFFSET + 1, "startup call displacement")?;
    let call_target = (ELF_ENTRY_OFFSET + 5) as i64 + i64::from(call_displacement);
    if call_target != TARGET_OFFSET as i64 {
        return Err(ResidencyElfError::InvalidElf(
            "startup call does not target the candidate".into(),
        ));
    }
    expect(
        bytes,
        ELF_ENTRY_OFFSET + 5,
        &STARTUP_SUFFIX,
        "startup suffix",
    )?;
    if ELF_ENTRY_OFFSET + 16 != TARGET_OFFSET {
        return Err(ResidencyElfError::InvalidElf(
            "fixed startup/target boundary drifted".into(),
        ));
    }
    expect(bytes, TARGET_OFFSET, &candidate.bytes, "candidate target")?;

    let target_hash = hash(&candidate.bytes);
    let image_hash = hash(bytes);
    if image.target_hash != target_hash || image.image_hash != image_hash {
        return Err(ResidencyElfError::InvalidElf(
            "target or image hash receipt drifted".into(),
        ));
    }
    let reconstructed = reconstruct(&candidate.bytes)?;
    if reconstructed != *bytes {
        return Err(ResidencyElfError::InvalidElf(
            "independent canonical reconstruction differs".into(),
        ));
    }

    Ok(VerifiedResidencyElf64Facts {
        entry: ELF_ENTRY,
        image_bytes: bytes.len() as u64,
        target_offset: TARGET_OFFSET as u64,
        target_bytes: candidate.bytes.len() as u64,
        load_flags: 5,
        stack_flags: 6,
        target_hash,
        image_hash,
    })
}

pub fn elf_report_hash(payload: &[u8]) -> naux::core::SemanticHash {
    let mut preimage = Vec::with_capacity(ELF_REPORT_DOMAIN.len() + payload.len());
    preimage.extend_from_slice(ELF_REPORT_DOMAIN);
    preimage.extend_from_slice(payload);
    hash(&preimage)
}

fn validate_candidate_extent(candidate: &ResidencyEncodedX64) -> Result<(), ResidencyElfError> {
    if candidate.bytes.is_empty()
        || candidate.bytes.len() > MAX_TARGET_BYTES
        || candidate.error_offset as usize >= candidate.bytes.len()
        || candidate.save_start >= candidate.save_end
        || candidate.save_end as usize > candidate.bytes.len()
    {
        return Err(ResidencyElfError::InvalidInput(
            "candidate receipt or byte extent is outside WP8F bounds".into(),
        ));
    }
    Ok(())
}

fn reconstruct(target: &[u8]) -> Result<Vec<u8>, ResidencyElfError> {
    let image_bytes = TARGET_OFFSET
        .checked_add(target.len())
        .ok_or_else(|| ResidencyElfError::InvalidElf("reconstruction overflowed".into()))?;
    let mut result = vec![0_u8; image_bytes];
    write_u8s(&mut result, 0, b"\x7fELF")?;
    write_u8s(&mut result, 4, &[2, 1, 1, 0, 0])?;
    write_u16(&mut result, 16, 2)?;
    write_u16(&mut result, 18, 62)?;
    write_u32(&mut result, 20, 1)?;
    write_u64(&mut result, 24, ELF_ENTRY)?;
    write_u64(&mut result, 32, ELF_HEADER_BYTES as u64)?;
    write_u16(&mut result, 52, ELF_HEADER_BYTES as u16)?;
    write_u16(&mut result, 54, PROGRAM_HEADER_BYTES as u16)?;
    write_u16(&mut result, 56, PROGRAM_HEADER_COUNT as u16)?;

    let load = ELF_HEADER_BYTES;
    write_u32(&mut result, load, 1)?;
    write_u32(&mut result, load + 4, 5)?;
    write_u64(&mut result, load + 16, ELF_BASE)?;
    write_u64(&mut result, load + 24, ELF_BASE)?;
    write_u64(&mut result, load + 32, image_bytes as u64)?;
    write_u64(&mut result, load + 40, image_bytes as u64)?;
    write_u64(&mut result, load + 48, 4096)?;

    let stack = ELF_HEADER_BYTES + PROGRAM_HEADER_BYTES;
    write_u32(&mut result, stack, 0x6474_e551)?;
    write_u32(&mut result, stack + 4, 6)?;
    write_u64(&mut result, stack + 48, 16)?;

    write_u8s(&mut result, ELF_ENTRY_OFFSET, &[0xe8])?;
    let displacement = i32::try_from(TARGET_OFFSET as i64 - (ELF_ENTRY_OFFSET + 5) as i64)
        .map_err(|_| ResidencyElfError::InvalidElf("startup displacement overflowed".into()))?;
    write_u8s(
        &mut result,
        ELF_ENTRY_OFFSET + 1,
        &displacement.to_le_bytes(),
    )?;
    write_u8s(&mut result, ELF_ENTRY_OFFSET + 5, &STARTUP_SUFFIX)?;
    write_u8s(&mut result, TARGET_OFFSET, target)?;
    Ok(result)
}

fn expect(
    bytes: &[u8],
    offset: usize,
    expected: &[u8],
    label: &str,
) -> Result<(), ResidencyElfError> {
    if bytes.get(offset..offset.saturating_add(expected.len())) != Some(expected) {
        return Err(ResidencyElfError::InvalidElf(format!("{label} drifted")));
    }
    Ok(())
}

fn zeroes(bytes: &[u8], start: usize, end: usize, label: &str) -> Result<(), ResidencyElfError> {
    let range = bytes
        .get(start..end)
        .ok_or_else(|| ResidencyElfError::InvalidElf(format!("{label} is out of bounds")))?;
    if range.iter().any(|byte| *byte != 0) {
        return Err(ResidencyElfError::InvalidElf(format!("{label} drifted")));
    }
    Ok(())
}

fn read_i32(bytes: &[u8], offset: usize, label: &str) -> Result<i32, ResidencyElfError> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| ResidencyElfError::InvalidElf(format!("{label} is truncated")))?
        .try_into()
        .map_err(|_| ResidencyElfError::InvalidElf(format!("{label} is malformed")))?;
    Ok(i32::from_le_bytes(raw))
}

macro_rules! integer_reader {
    ($name:ident, $ty:ty, $width:expr) => {
        fn $name(bytes: &[u8], offset: usize, label: &str) -> Result<$ty, ResidencyElfError> {
            let raw: [u8; $width] = bytes
                .get(offset..offset + $width)
                .ok_or_else(|| ResidencyElfError::InvalidElf(format!("{label} is truncated")))?
                .try_into()
                .map_err(|_| ResidencyElfError::InvalidElf(format!("{label} is malformed")))?;
            Ok(<$ty>::from_le_bytes(raw))
        }
    };
}

integer_reader!(read_u16, u16, 2);
integer_reader!(read_u32, u32, 4);
integer_reader!(read_u64, u64, 8);

fn expect_u16(
    bytes: &[u8],
    offset: usize,
    expected: u16,
    label: &str,
) -> Result<(), ResidencyElfError> {
    if read_u16(bytes, offset, label)? != expected {
        return Err(ResidencyElfError::InvalidElf(format!("{label} drifted")));
    }
    Ok(())
}

fn expect_u32(
    bytes: &[u8],
    offset: usize,
    expected: u32,
    label: &str,
) -> Result<(), ResidencyElfError> {
    if read_u32(bytes, offset, label)? != expected {
        return Err(ResidencyElfError::InvalidElf(format!("{label} drifted")));
    }
    Ok(())
}

fn expect_u64(
    bytes: &[u8],
    offset: usize,
    expected: u64,
    label: &str,
) -> Result<(), ResidencyElfError> {
    if read_u64(bytes, offset, label)? != expected {
        return Err(ResidencyElfError::InvalidElf(format!("{label} drifted")));
    }
    Ok(())
}

fn write_u8s(bytes: &mut [u8], offset: usize, value: &[u8]) -> Result<(), ResidencyElfError> {
    bytes
        .get_mut(offset..offset + value.len())
        .ok_or_else(|| {
            ResidencyElfError::InvalidElf("reconstruction write is out of bounds".into())
        })?
        .copy_from_slice(value);
    Ok(())
}

macro_rules! integer_writer {
    ($name:ident, $ty:ty) => {
        fn $name(bytes: &mut [u8], offset: usize, value: $ty) -> Result<(), ResidencyElfError> {
            write_u8s(bytes, offset, &value.to_le_bytes())
        }
    };
}

integer_writer!(write_u16, u16);
integer_writer!(write_u32, u32);
integer_writer!(write_u64, u64);

fn hash(bytes: &[u8]) -> naux::core::SemanticHash {
    naux::core::SemanticHash(sha256(bytes))
}

fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    let mut state = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in words[..16].iter_mut().enumerate() {
            *word = u32::from_be_bytes(chunk[index * 4..index * 4 + 4].try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let big1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(big1)
                .wrapping_add(choice)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let big0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = big0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut output = [0_u8; 32];
    for (chunk, value) in output.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    output
}
