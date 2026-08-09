//! Independently identified hand-specialized standalone baseline for Gate B.
//!
//! This module deliberately does not consume the R1-S7a target artifact.  It
//! owns a separate target emitter, verifier-owned byte oracle, identity
//! domains, and artifact type.  The only shared components are the frozen
//! R1-S8 BranchMix startup/protocol and direct-ELF grammar required by the
//! structurally matched Gate B measurement contract.

use super::encoding::sha256;
use super::schema::SemanticHash;
use super::x64_standalone_elf::{
    build_x64_standalone_elf_r1_s8, verify_x64_standalone_elf_r1_s8, X64_STANDALONE_ELF_BASE,
};
use super::x64_standalone_protocol::X64StandaloneProfile;
use super::x64_standalone_startup_raw::{
    encode_x64_standalone_startup_raw, independently_verify_x64_standalone_startup_raw_r1_s8,
};
use std::fmt;

pub const X64_GATE_B_BASELINE_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_BASELINE_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_GATE_B_BASELINE_TARGET_BYTES: u32 = 158;
pub const X64_GATE_B_BASELINE_STARTUP_BYTES: u32 = 1_032;
pub const X64_GATE_B_BASELINE_TARGET_OFFSET: u32 = 0x510;
pub const X64_GATE_B_BASELINE_IMAGE_BYTES: u32 = 0x5ae;

const TARGET_DOMAIN: &[u8] = b"NAUX:gate-b:hand-baseline:x86-64:target:v1\0";
const ARTIFACT_DOMAIN: &[u8] = b"NAUX:gate-b:hand-baseline:x86-64:artifact:v1\0";
const TARGET_ENTRY_VADDR: u64 = X64_STANDALONE_ELF_BASE + X64_GATE_B_BASELINE_TARGET_OFFSET as u64;
const TARGET_BYTES_USIZE: usize = X64_GATE_B_BASELINE_TARGET_BYTES as usize;

// Verifier-owned byte oracle.  The production emitter below is deliberately a
// second representation assembled instruction by instruction.
const TARGET_ORACLE: [u8; TARGET_BYTES_USIZE] = decode_hex::<TARGET_BYTES_USIZE>(
    concat!(
        "4883ec080fae1c244989cb4531c0660fefc04989d14d85c90f8e4c00000045",
        "31d24939f20f83370000004983c0114983f8610f8c040000004983e861f2420f",
        "100cd74983f8300f8d09000000f20f58c1e904000000f20f5cc149ffc2e9c0",
        "ffffff49ffc90f8fb4ffffff660f2ec00f8a0a00000066480f7ec0e90a000000",
        "48b8000000000000f87f49890349c74308000000000fae14244883c40831c0",
        "c3",
    )
    .as_bytes(),
);

const TARGET_RAW_SHA256: [u8; 32] = [
    0x65, 0x34, 0xd7, 0x40, 0x9f, 0xa6, 0xb5, 0x29, 0x37, 0x40, 0x44, 0xb4, 0x6e, 0x43, 0xfe, 0x6b,
    0x71, 0xec, 0xfc, 0x2e, 0xe7, 0xf5, 0x6a, 0x25, 0xd2, 0x28, 0xd8, 0x5d, 0x75, 0x94, 0xf2, 0x98,
];

const INSTRUCTION_STARTS: [usize; 36] = [
    0, 4, 8, 11, 14, 18, 21, 24, 30, 33, 36, 42, 46, 50, 56, 60, 66, 70, 76, 80, 85, 89, 92, 97,
    100, 106, 110, 116, 121, 126, 136, 139, 147, 151, 155, 157,
];

// displacement offset, next-instruction offset, exact target offset
const CONTROL_TRANSFERS: [(usize, usize, usize); 9] = [
    (26, 30, 106),
    (38, 42, 97),
    (52, 56, 60),
    (72, 76, 85),
    (81, 85, 89),
    (93, 97, 33),
    (102, 106, 30),
    (112, 116, 126),
    (122, 126, 136),
];

const fn decode_hex<const N: usize>(encoded: &[u8]) -> [u8; N] {
    assert!(encoded.len() == N * 2);
    let mut decoded = [0; N];
    let mut index = 0;
    while index < N {
        decoded[index] = (decode_hex_nibble(encoded[index * 2]) << 4)
            | decode_hex_nibble(encoded[index * 2 + 1]);
        index += 1;
    }
    decoded
}

const fn decode_hex_nibble(encoded: u8) -> u8 {
    match encoded {
        b'0'..=b'9' => encoded - b'0',
        b'a'..=b'f' => encoded - b'a' + 10,
        _ => panic!("noncanonical Gate B baseline target hex"),
    }
}

/// Raw baseline image produced by the isolated hand-target writer.
///
/// This type intentionally has no conversion into an R1-S8 generated
/// artifact or seed authority.
#[derive(Clone, PartialEq, Eq)]
pub struct X64GateBBaselineArtifact {
    image: Vec<u8>,
    target_hash: SemanticHash,
    elf_image_hash: SemanticHash,
    artifact_hash: SemanticHash,
}

impl fmt::Debug for X64GateBBaselineArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("X64GateBBaselineArtifact")
            .field("image_bytes", &self.image.len())
            .field("target_hash", &self.target_hash)
            .field("elf_image_hash", &self.elf_image_hash)
            .field("artifact_hash", &self.artifact_hash)
            .finish()
    }
}

impl X64GateBBaselineArtifact {
    pub fn image_bytes(&self) -> &[u8] {
        &self.image
    }

    pub const fn target_hash(&self) -> SemanticHash {
        self.target_hash
    }

    pub const fn elf_image_hash(&self) -> SemanticHash {
        self.elf_image_hash
    }

    pub const fn artifact_hash(&self) -> SemanticHash {
        self.artifact_hash
    }
}

/// Lifetime-bound independently verified view of a baseline image.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifiedX64GateBBaselineArtifact<'image> {
    image: &'image [u8],
    target_hash: SemanticHash,
    elf_image_hash: SemanticHash,
    artifact_hash: SemanticHash,
}

impl fmt::Debug for VerifiedX64GateBBaselineArtifact<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedX64GateBBaselineArtifact")
            .field("image_bytes", &self.image.len())
            .field("target_hash", &self.target_hash)
            .field("elf_image_hash", &self.elf_image_hash)
            .field("artifact_hash", &self.artifact_hash)
            .finish()
    }
}

impl<'image> VerifiedX64GateBBaselineArtifact<'image> {
    pub const fn image_bytes(&self) -> &'image [u8] {
        self.image
    }

    pub const fn target_hash(&self) -> SemanticHash {
        self.target_hash
    }

    pub const fn elf_image_hash(&self) -> SemanticHash {
        self.elf_image_hash
    }

    pub const fn artifact_hash(&self) -> SemanticHash {
        self.artifact_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64GateBBaselineError {
    TargetLength {
        expected: usize,
        actual: usize,
    },
    TargetByte {
        offset: usize,
        expected: u8,
        actual: u8,
    },
    TargetDigest {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    TargetControlTransfer {
        displacement_offset: usize,
        expected: usize,
        actual: i128,
    },
    TargetInstructionBoundary {
        offset: usize,
    },
    TargetInvariant {
        field: &'static str,
    },
    Startup {
        stage: &'static str,
        message: String,
    },
    Elf {
        stage: &'static str,
        message: String,
    },
    Layout {
        field: &'static str,
        expected: u64,
        actual: u64,
    },
}

impl fmt::Display for X64GateBBaselineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetLength { expected, actual } => write!(
                formatter,
                "Gate B hand target has {actual} bytes; expected {expected}"
            ),
            Self::TargetByte {
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "Gate B hand target byte {offset:#x} is {actual:#04x}; expected {expected:#04x}"
            ),
            Self::TargetDigest { expected, actual } => write!(
                formatter,
                "Gate B hand target SHA-256 {actual:02x?} differs from {expected:02x?}"
            ),
            Self::TargetControlTransfer {
                displacement_offset,
                expected,
                actual,
            } => write!(
                formatter,
                "Gate B hand target control transfer at {displacement_offset:#x} resolves to \
                 {actual:#x}; expected {expected:#x}"
            ),
            Self::TargetInstructionBoundary { offset } => write!(
                formatter,
                "Gate B hand target control transfer resolves outside an instruction boundary \
                 at {offset:#x}"
            ),
            Self::TargetInvariant { field } => {
                write!(formatter, "Gate B hand target violates {field}")
            }
            Self::Startup { stage, message } => {
                write!(
                    formatter,
                    "Gate B baseline startup {stage} failed: {message}"
                )
            }
            Self::Elf { stage, message } => {
                write!(formatter, "Gate B baseline ELF {stage} failed: {message}")
            }
            Self::Layout {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "Gate B baseline {field} is {actual}; expected {expected}"
            ),
        }
    }
}

impl std::error::Error for X64GateBBaselineError {}

/// Build the exact hand-specialized BranchMix standalone baseline.
pub fn build_x64_gate_b_baseline_artifact(
) -> Result<X64GateBBaselineArtifact, X64GateBBaselineError> {
    let target = emit_hand_specialized_target()?;
    let _ = independently_verify_hand_target(&target)?;
    let startup =
        encode_x64_standalone_startup_raw(X64StandaloneProfile::BranchMix, TARGET_ENTRY_VADDR)
            .map_err(|error| startup_error("encoding", error))?;
    let verified_startup = independently_verify_x64_standalone_startup_raw_r1_s8(
        startup.code(),
        &startup,
        X64StandaloneProfile::BranchMix,
        TARGET_ENTRY_VADDR,
    )
    .map_err(|error| startup_error("verification", error))?;
    let elf = build_x64_standalone_elf_r1_s8(verified_startup.code(), &target)
        .map_err(|error| elf_error("construction", error))?;
    let verified = verify_x64_gate_b_baseline_artifact(elf.bytes())?;
    Ok(X64GateBBaselineArtifact {
        image: verified.image_bytes().to_vec(),
        target_hash: verified.target_hash(),
        elf_image_hash: verified.elf_image_hash(),
        artifact_hash: verified.artifact_hash(),
    })
}

/// Independently verify a complete baseline image against the separate target
/// oracle and the frozen R1-S8 startup/ELF verifiers.
pub fn verify_x64_gate_b_baseline_artifact<'image>(
    image: &'image [u8],
) -> Result<VerifiedX64GateBBaselineArtifact<'image>, X64GateBBaselineError> {
    let target = independently_verify_hand_target(&TARGET_ORACLE)?;
    let startup =
        encode_x64_standalone_startup_raw(X64StandaloneProfile::BranchMix, TARGET_ENTRY_VADDR)
            .map_err(|error| startup_error("receipt reconstruction", error))?;
    let verified_startup = independently_verify_x64_standalone_startup_raw_r1_s8(
        startup.code(),
        &startup,
        X64StandaloneProfile::BranchMix,
        TARGET_ENTRY_VADDR,
    )
    .map_err(|error| startup_error("independent verification", error))?;
    let elf = verify_x64_standalone_elf_r1_s8(image, verified_startup.code(), target.bytes)
        .map_err(|error| elf_error("independent verification", error))?;
    verify_layout(
        "startup byte count",
        u64::from(X64_GATE_B_BASELINE_STARTUP_BYTES),
        elf.startup_bytes(),
    )?;
    verify_layout(
        "target offset",
        u64::from(X64_GATE_B_BASELINE_TARGET_OFFSET),
        elf.target_offset(),
    )?;
    verify_layout(
        "target byte count",
        u64::from(X64_GATE_B_BASELINE_TARGET_BYTES),
        elf.target_bytes(),
    )?;
    verify_layout(
        "image byte count",
        u64::from(X64_GATE_B_BASELINE_IMAGE_BYTES),
        image.len() as u64,
    )?;
    let artifact_hash = baseline_artifact_hash(target.hash, elf.image_hash(), image.len());
    Ok(VerifiedX64GateBBaselineArtifact {
        image: elf.bytes(),
        target_hash: target.hash,
        elf_image_hash: elf.image_hash(),
        artifact_hash,
    })
}

pub fn x64_gate_b_baseline_target_hash() -> SemanticHash {
    baseline_target_hash(&TARGET_ORACLE)
}

fn emit_hand_specialized_target() -> Result<Vec<u8>, X64GateBBaselineError> {
    let mut code = Vec::with_capacity(TARGET_BYTES_USIZE);
    code.extend_from_slice(&[0x48, 0x83, 0xec, 0x08]); // sub rsp, 8
    code.extend_from_slice(&[0x0f, 0xae, 0x1c, 0x24]); // stmxcsr [rsp]
    code.extend_from_slice(&[0x49, 0x89, 0xcb]); // mov r11, rcx
    code.extend_from_slice(&[0x45, 0x31, 0xc0]); // xor r8d, r8d
    code.extend_from_slice(&[0x66, 0x0f, 0xef, 0xc0]); // pxor xmm0, xmm0
    code.extend_from_slice(&[0x49, 0x89, 0xd1]); // mov r9, rdx
    code.extend_from_slice(&[0x4d, 0x85, 0xc9]); // test r9, r9
    code.extend_from_slice(&[0x0f, 0x8e, 0x4c, 0x00, 0x00, 0x00]); // jle done
    code.extend_from_slice(&[0x45, 0x31, 0xd2]); // xor r10d, r10d
    code.extend_from_slice(&[0x49, 0x39, 0xf2]); // cmp r10, rsi
    code.extend_from_slice(&[0x0f, 0x83, 0x37, 0x00, 0x00, 0x00]); // jae outer_done
    code.extend_from_slice(&[0x49, 0x83, 0xc0, 0x11]); // add r8, 17
    code.extend_from_slice(&[0x49, 0x83, 0xf8, 0x61]); // cmp r8, 97
    code.extend_from_slice(&[0x0f, 0x8c, 0x04, 0x00, 0x00, 0x00]); // jl state_reduced
    code.extend_from_slice(&[0x49, 0x83, 0xe8, 0x61]); // sub r8, 97
    code.extend_from_slice(&[0xf2, 0x42, 0x0f, 0x10, 0x0c, 0xd7]); // movsd xmm1,[rdi+r10*8]
    code.extend_from_slice(&[0x49, 0x83, 0xf8, 0x30]); // cmp r8, 48
    code.extend_from_slice(&[0x0f, 0x8d, 0x09, 0x00, 0x00, 0x00]); // jge subtract
    code.extend_from_slice(&[0xf2, 0x0f, 0x58, 0xc1]); // addsd xmm0, xmm1
    code.extend_from_slice(&[0xe9, 0x04, 0x00, 0x00, 0x00]); // jmp after_accumulate
    code.extend_from_slice(&[0xf2, 0x0f, 0x5c, 0xc1]); // subsd xmm0, xmm1
    code.extend_from_slice(&[0x49, 0xff, 0xc2]); // inc r10
    code.extend_from_slice(&[0xe9, 0xc0, 0xff, 0xff, 0xff]); // jmp inner_check
    code.extend_from_slice(&[0x49, 0xff, 0xc9]); // dec r9
    code.extend_from_slice(&[0x0f, 0x8f, 0xb4, 0xff, 0xff, 0xff]); // jg outer_body
    code.extend_from_slice(&[0x66, 0x0f, 0x2e, 0xc0]); // ucomisd xmm0, xmm0
    code.extend_from_slice(&[0x0f, 0x8a, 0x0a, 0x00, 0x00, 0x00]); // jp canonical_nan
    code.extend_from_slice(&[0x66, 0x48, 0x0f, 0x7e, 0xc0]); // movq rax, xmm0
    code.extend_from_slice(&[0xe9, 0x0a, 0x00, 0x00, 0x00]); // jmp store
    code.extend_from_slice(&[0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x7f]); // movabs rax, canonical NaN
    code.extend_from_slice(&[0x49, 0x89, 0x03]); // mov [r11], rax
    code.extend_from_slice(&[0x49, 0xc7, 0x43, 0x08, 0x00, 0x00, 0x00, 0x00]); // payload1 = 0
    code.extend_from_slice(&[0x0f, 0xae, 0x14, 0x24]); // ldmxcsr [rsp]
    code.extend_from_slice(&[0x48, 0x83, 0xc4, 0x08]); // add rsp, 8
    code.extend_from_slice(&[0x31, 0xc0]); // eax = ReturnF64
    code.push(0xc3); // ret
    if code.len() != TARGET_BYTES_USIZE {
        return Err(X64GateBBaselineError::TargetLength {
            expected: TARGET_BYTES_USIZE,
            actual: code.len(),
        });
    }
    Ok(code)
}

#[derive(Clone, Copy)]
struct VerifiedHandTarget<'target> {
    bytes: &'target [u8],
    hash: SemanticHash,
}

fn independently_verify_hand_target(
    target: &[u8],
) -> Result<VerifiedHandTarget<'_>, X64GateBBaselineError> {
    if target.len() != TARGET_BYTES_USIZE {
        return Err(X64GateBBaselineError::TargetLength {
            expected: TARGET_BYTES_USIZE,
            actual: target.len(),
        });
    }
    if let Some((offset, (actual, expected))) = target
        .iter()
        .copied()
        .zip(TARGET_ORACLE)
        .enumerate()
        .find(|(_, (actual, expected))| actual != expected)
    {
        return Err(X64GateBBaselineError::TargetByte {
            offset,
            expected,
            actual,
        });
    }
    let actual_digest = sha256(target);
    if actual_digest != TARGET_RAW_SHA256 {
        return Err(X64GateBBaselineError::TargetDigest {
            expected: TARGET_RAW_SHA256,
            actual: actual_digest,
        });
    }
    for &(displacement_offset, next_instruction, expected_target) in &CONTROL_TRANSFERS {
        let displacement = i32::from_le_bytes(
            target[displacement_offset..displacement_offset + 4]
                .try_into()
                .map_err(|_| X64GateBBaselineError::TargetInvariant {
                    field: "control-transfer displacement width",
                })?,
        );
        let actual_target = next_instruction as i128 + i128::from(displacement);
        if actual_target != expected_target as i128 {
            return Err(X64GateBBaselineError::TargetControlTransfer {
                displacement_offset,
                expected: expected_target,
                actual: actual_target,
            });
        }
        if INSTRUCTION_STARTS.binary_search(&expected_target).is_err() {
            return Err(X64GateBBaselineError::TargetInstructionBoundary {
                offset: expected_target,
            });
        }
    }
    if target.windows(2).any(|window| window == [0x0f, 0x05]) {
        return Err(X64GateBBaselineError::TargetInvariant {
            field: "no-syscall policy",
        });
    }
    if target[..8] != [0x48, 0x83, 0xec, 0x08, 0x0f, 0xae, 0x1c, 0x24]
        || target[136..139] != [0x49, 0x89, 0x03]
        || target[139..147] != [0x49, 0xc7, 0x43, 0x08, 0, 0, 0, 0]
        || target[147..155] != [0x0f, 0xae, 0x14, 0x24, 0x48, 0x83, 0xc4, 0x08]
        || target[155..] != [0x31, 0xc0, 0xc3]
    {
        return Err(X64GateBBaselineError::TargetInvariant {
            field: "MXCSR save/restore and canonical two-word result epilogue",
        });
    }
    Ok(VerifiedHandTarget {
        bytes: target,
        hash: baseline_target_hash(target),
    })
}

fn baseline_target_hash(target: &[u8]) -> SemanticHash {
    let mut bytes = Vec::with_capacity(TARGET_DOMAIN.len() + 18 + target.len());
    bytes.extend_from_slice(TARGET_DOMAIN);
    put_version(&mut bytes, X64_GATE_B_BASELINE_SCHEMA_VERSION);
    put_version(&mut bytes, X64_GATE_B_BASELINE_POLICY_VERSION);
    bytes.extend_from_slice(&(target.len() as u32).to_be_bytes());
    bytes.extend_from_slice(target);
    SemanticHash(sha256(&bytes))
}

fn baseline_artifact_hash(
    target_hash: SemanticHash,
    elf_image_hash: SemanticHash,
    image_bytes: usize,
) -> SemanticHash {
    let mut bytes = Vec::with_capacity(ARTIFACT_DOMAIN.len() + 82);
    bytes.extend_from_slice(ARTIFACT_DOMAIN);
    put_version(&mut bytes, X64_GATE_B_BASELINE_SCHEMA_VERSION);
    put_version(&mut bytes, X64_GATE_B_BASELINE_POLICY_VERSION);
    bytes.extend_from_slice(&target_hash.0);
    bytes.extend_from_slice(&elf_image_hash.0);
    bytes.extend_from_slice(&(image_bytes as u64).to_be_bytes());
    SemanticHash(sha256(&bytes))
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_be_bytes());
    bytes.extend_from_slice(&version.1.to_be_bytes());
    bytes.extend_from_slice(&version.2.to_be_bytes());
}

fn verify_layout(
    field: &'static str,
    expected: u64,
    actual: u64,
) -> Result<(), X64GateBBaselineError> {
    if actual == expected {
        Ok(())
    } else {
        Err(X64GateBBaselineError::Layout {
            field,
            expected,
            actual,
        })
    }
}

fn startup_error(stage: &'static str, error: impl fmt::Display) -> X64GateBBaselineError {
    X64GateBBaselineError::Startup {
        stage,
        message: error.to_string(),
    }
}

fn elf_error(stage: &'static str, error: impl fmt::Display) -> X64GateBBaselineError {
    X64GateBBaselineError::Elf {
        stage,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_target_oracle_accepts_only_the_hand_emitter() {
        let emitted = emit_hand_specialized_target().expect("hand target emission");
        let verified =
            independently_verify_hand_target(&emitted).expect("independent hand target verify");
        assert_eq!(verified.bytes, TARGET_ORACLE);
        assert_eq!(sha256(verified.bytes), TARGET_RAW_SHA256);
        assert_eq!(verified.hash, x64_gate_b_baseline_target_hash());

        for offset in 0..emitted.len() {
            let mut mutated = emitted.clone();
            mutated[offset] ^= 1;
            assert!(
                independently_verify_hand_target(&mutated).is_err(),
                "single-byte target mutation at {offset:#x} must fail closed"
            );
        }
    }

    #[test]
    fn complete_baseline_image_has_frozen_layout_and_identity() {
        let artifact = build_x64_gate_b_baseline_artifact().expect("baseline artifact");
        let verified = verify_x64_gate_b_baseline_artifact(artifact.image_bytes())
            .expect("independent baseline artifact verify");
        assert_eq!(
            artifact.image_bytes().len(),
            X64_GATE_B_BASELINE_IMAGE_BYTES as usize
        );
        assert_eq!(artifact.target_hash(), verified.target_hash());
        assert_eq!(artifact.elf_image_hash(), verified.elf_image_hash());
        assert_eq!(artifact.artifact_hash(), verified.artifact_hash());

        for relative in 0..TARGET_BYTES_USIZE {
            let mut mutated = artifact.image_bytes().to_vec();
            mutated[X64_GATE_B_BASELINE_TARGET_OFFSET as usize + relative] ^= 1;
            assert!(
                verify_x64_gate_b_baseline_artifact(&mutated).is_err(),
                "single-byte packaged-target mutation at {relative:#x} must fail closed"
            );
        }
    }
}
