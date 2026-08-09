//! Canonical direct ELF64 image grammar for the R1-S8 standalone boundary.
//!
//! This module owns only deterministic file construction and independent
//! byte-level verification. Raw ELF bytes are never semantic authority:
//! callers must retain the opaque verified view returned by
//! [`verify_x64_standalone_elf_r1_s8`].

use super::schema::SemanticHash;
use std::fmt;

pub(super) const X64_STANDALONE_ELF_IMAGE_DOMAIN: &[u8] = b"NAUX:x86-64:r1-s8:elf-image:v1\0";
pub(super) const X64_STANDALONE_ELF_BASE: u64 = 0x0040_0000;
pub(super) const X64_STANDALONE_ELF_STARTUP_OFFSET: usize = 0x100;
pub(super) const X64_STANDALONE_ELF_ENTRY: u64 = 0x0040_0100;
pub(super) const X64_STANDALONE_ELF_MAX_STARTUP_BYTES: usize = 32_768;
pub(super) const X64_STANDALONE_ELF_MAX_TARGET_BYTES: usize = 67_108_864;
pub(super) const X64_STANDALONE_ELF_MAX_OVERHEAD_BYTES: usize = 65_536;
pub(super) const X64_STANDALONE_ELF_MAX_IMAGE_BYTES: usize = 67_174_400;

const ELF_HEADER_BYTES: usize = 64;
const PROGRAM_HEADER_BYTES: usize = 56;
const PROGRAM_HEADER_COUNT: usize = 2;
const PROGRAM_HEADERS_OFFSET: usize = ELF_HEADER_BYTES;
const PROGRAM_HEADERS_END: usize =
    PROGRAM_HEADERS_OFFSET + PROGRAM_HEADER_BYTES * PROGRAM_HEADER_COUNT;
const TARGET_ALIGNMENT: usize = 16;
const LOAD_ALIGNMENT: u64 = 4_096;
const STACK_ALIGNMENT: u64 = 16;

const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LITTLE_ENDIAN: u8 = 1;
const ELF_CURRENT_VERSION_U8: u8 = 1;
const ELF_CURRENT_VERSION_U32: u32 = 1;
const ELF_OS_ABI_NONE: u8 = 0;
const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_MACHINE_X86_64: u16 = 62;
const PROGRAM_TYPE_LOAD: u32 = 1;
const PROGRAM_TYPE_GNU_STACK: u32 = 0x6474_e551;
const PROGRAM_FLAG_EXECUTE: u32 = 1;
const PROGRAM_FLAG_WRITE: u32 = 2;
const PROGRAM_FLAG_READ: u32 = 4;
const SHA256_INITIAL: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];
const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Exact fields and absence-relevant segment counts read back from a verified
/// image.  These are parser receipts, not writer declarations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneElfFacts {
    pub(super) class: u8,
    pub(super) data: u8,
    pub(super) ident_version: u8,
    pub(super) os_abi: u8,
    pub(super) abi_version: u8,
    pub(super) object_type: u16,
    pub(super) machine: u16,
    pub(super) version: u32,
    pub(super) entry: u64,
    pub(super) program_headers_offset: u64,
    pub(super) section_headers_offset: u64,
    pub(super) flags: u32,
    pub(super) elf_header_bytes: u16,
    pub(super) program_header_bytes: u16,
    pub(super) program_header_count: u16,
    pub(super) section_header_bytes: u16,
    pub(super) section_header_count: u16,
    pub(super) section_name_index: u16,
    pub(super) load_type: u32,
    pub(super) load_flags: u32,
    pub(super) load_offset: u64,
    pub(super) load_vaddr: u64,
    pub(super) load_paddr: u64,
    pub(super) load_filesz: u64,
    pub(super) load_memsz: u64,
    pub(super) load_alignment: u64,
    pub(super) stack_type: u32,
    pub(super) stack_flags: u32,
    pub(super) stack_offset: u64,
    pub(super) stack_vaddr: u64,
    pub(super) stack_paddr: u64,
    pub(super) stack_filesz: u64,
    pub(super) stack_memsz: u64,
    pub(super) stack_alignment: u64,
    pub(super) pt_load_segments: u32,
    pub(super) pt_interp_segments: u32,
    pub(super) pt_dynamic_segments: u32,
    pub(super) writable_executable_load_segments: u32,
}

/// An emitted but not independently trusted R1-S8 ELF image.
///
/// The raw bytes are available only inside the `core` module so a later
/// writer can persist them. They do not authorize execution or evidence.
#[derive(PartialEq, Eq)]
pub(super) struct X64StandaloneElfImage {
    bytes: Vec<u8>,
    startup_bytes: u64,
    target_offset: u64,
    target_bytes: u64,
    overhead_bytes: u64,
}

impl fmt::Debug for X64StandaloneElfImage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("X64StandaloneElfImage")
            .field("image_bytes", &self.bytes.len())
            .field("startup_bytes", &self.startup_bytes)
            .field("target_offset", &self.target_offset)
            .field("target_bytes", &self.target_bytes)
            .field("overhead_bytes", &self.overhead_bytes)
            .finish()
    }
}

impl X64StandaloneElfImage {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) const fn startup_bytes(&self) -> u64 {
        self.startup_bytes
    }

    pub(super) const fn target_offset(&self) -> u64 {
        self.target_offset
    }

    pub(super) const fn target_bytes(&self) -> u64 {
        self.target_bytes
    }

    pub(super) const fn overhead_bytes(&self) -> u64 {
        self.overhead_bytes
    }
}

/// Opaque independently verified view of one exact R1-S8 image.
///
/// The lifetime binds the authority to the exact raw image that was parsed,
/// reconstructed, and hashed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct VerifiedX64StandaloneElfImage<'image> {
    bytes: &'image [u8],
    image_hash: SemanticHash,
    startup_bytes: u64,
    target_offset: u64,
    target_bytes: u64,
    overhead_bytes: u64,
    facts: X64StandaloneElfFacts,
}

impl fmt::Debug for VerifiedX64StandaloneElfImage<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedX64StandaloneElfImage")
            .field("image_bytes", &self.bytes.len())
            .field("image_hash", &self.image_hash)
            .field("startup_bytes", &self.startup_bytes)
            .field("target_offset", &self.target_offset)
            .field("target_bytes", &self.target_bytes)
            .field("overhead_bytes", &self.overhead_bytes)
            .field("facts", &self.facts)
            .finish()
    }
}

impl<'image> VerifiedX64StandaloneElfImage<'image> {
    pub(super) const fn bytes(&self) -> &'image [u8] {
        self.bytes
    }

    pub(super) const fn image_hash(&self) -> SemanticHash {
        self.image_hash
    }

    pub(super) const fn startup_bytes(&self) -> u64 {
        self.startup_bytes
    }

    pub(super) const fn target_offset(&self) -> u64 {
        self.target_offset
    }

    pub(super) const fn target_bytes(&self) -> u64 {
        self.target_bytes
    }

    pub(super) const fn overhead_bytes(&self) -> u64 {
        self.overhead_bytes
    }

    pub(super) const fn facts(&self) -> X64StandaloneElfFacts {
        self.facts
    }
}

/// Typed rejection from canonical R1-S8 ELF construction or verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum X64StandaloneElfError {
    EmptyComponent {
        component: &'static str,
    },
    ComponentByteLimit {
        component: &'static str,
        limit: usize,
        actual: usize,
    },
    OverheadByteLimit {
        limit: usize,
        actual: usize,
    },
    ImageByteLimit {
        limit: usize,
        actual: usize,
    },
    ArithmeticOverflow {
        field: &'static str,
    },
    LengthConversion {
        field: &'static str,
        actual: usize,
    },
    AllocationFailed {
        bytes: usize,
    },
    InternalLayout {
        expected: usize,
        actual: usize,
    },
    ImageLength {
        expected: usize,
        actual: usize,
    },
    Truncated {
        field: &'static str,
        offset: usize,
        needed: usize,
        remaining: usize,
    },
    InvalidBytes {
        field: &'static str,
        offset: usize,
    },
    InvalidField {
        field: &'static str,
        expected: u64,
        actual: u64,
    },
    NonZeroPadding {
        field: &'static str,
        offset: usize,
        actual: u8,
    },
    RegionMismatch {
        field: &'static str,
        offset: usize,
        expected: u8,
        actual: u8,
    },
    ReconstructionMismatch {
        offset: usize,
        expected: u8,
        actual: u8,
    },
    InvalidHashState {
        field: &'static str,
    },
}

impl fmt::Display for X64StandaloneElfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyComponent { component } => {
                write!(formatter, "R1-S8 ELF {component} must not be empty")
            }
            Self::ComponentByteLimit {
                component,
                limit,
                actual,
            } => write!(
                formatter,
                "R1-S8 ELF {component} uses {actual} bytes; limit is {limit}"
            ),
            Self::OverheadByteLimit { limit, actual } => write!(
                formatter,
                "R1-S8 ELF standalone overhead is {actual} bytes; limit is {limit}"
            ),
            Self::ImageByteLimit { limit, actual } => write!(
                formatter,
                "R1-S8 ELF image uses {actual} bytes; limit is {limit}"
            ),
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "R1-S8 ELF {field} arithmetic overflow")
            }
            Self::LengthConversion { field, actual } => write!(
                formatter,
                "R1-S8 ELF {field} length {actual} cannot be encoded as u64"
            ),
            Self::AllocationFailed { bytes } => {
                write!(formatter, "R1-S8 ELF cannot allocate {bytes} image bytes")
            }
            Self::InternalLayout { expected, actual } => write!(
                formatter,
                "R1-S8 ELF writer expected offset {expected:#x}, reached {actual:#x}"
            ),
            Self::ImageLength { expected, actual } => write!(
                formatter,
                "R1-S8 ELF image length is {actual}; expected {expected}"
            ),
            Self::Truncated {
                field,
                offset,
                needed,
                remaining,
            } => write!(
                formatter,
                "R1-S8 ELF field {field} at {offset:#x} needs {needed} bytes; \
                 only {remaining} remain"
            ),
            Self::InvalidBytes { field, offset } => write!(
                formatter,
                "R1-S8 ELF field {field} has invalid bytes at {offset:#x}"
            ),
            Self::InvalidField {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "R1-S8 ELF field {field} is {actual:#x}; expected {expected:#x}"
            ),
            Self::NonZeroPadding {
                field,
                offset,
                actual,
            } => write!(
                formatter,
                "R1-S8 ELF {field} byte at {offset:#x} is {actual:#04x}; expected zero"
            ),
            Self::RegionMismatch {
                field,
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "R1-S8 ELF {field} differs at {offset:#x}: \
                 expected {expected:#04x}, found {actual:#04x}"
            ),
            Self::ReconstructionMismatch {
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "R1-S8 ELF independent reconstruction differs at {offset:#x}: \
                 expected {expected:#04x}, found {actual:#04x}"
            ),
            Self::InvalidHashState { field } => {
                write!(formatter, "R1-S8 ELF SHA-256 state is invalid at {field}")
            }
        }
    }
}

impl std::error::Error for X64StandaloneElfError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ElfLayout {
    startup_end: usize,
    target_offset: usize,
    image_bytes: usize,
    overhead_bytes: usize,
}

/// Emit one canonical direct ELF64 image.
///
/// The startup and target are copied exactly once into the image. This
/// function does not verify their semantic provenance; the later artifact
/// layer must supply only its verified startup and source-bound R1-S7a blob.
pub(super) fn build_x64_standalone_elf_r1_s8(
    startup: &[u8],
    target: &[u8],
) -> Result<X64StandaloneElfImage, X64StandaloneElfError> {
    let layout = layout_for_lengths(startup.len(), target.len())?;
    let image_len_u64 = usize_to_u64(layout.image_bytes, "image")?;

    let mut bytes = Vec::new();
    bytes.try_reserve_exact(layout.image_bytes).map_err(|_| {
        X64StandaloneElfError::AllocationFailed {
            bytes: layout.image_bytes,
        }
    })?;

    write_elf_header(&mut bytes);
    check_writer_offset(&bytes, PROGRAM_HEADERS_OFFSET)?;
    write_load_program_header(&mut bytes, image_len_u64);
    write_stack_program_header(&mut bytes);
    check_writer_offset(&bytes, PROGRAM_HEADERS_END)?;

    bytes.resize(X64_STANDALONE_ELF_STARTUP_OFFSET, 0);
    bytes.extend_from_slice(startup);
    check_writer_offset(&bytes, layout.startup_end)?;
    bytes.resize(layout.target_offset, 0);
    bytes.extend_from_slice(target);
    check_writer_offset(&bytes, layout.image_bytes)?;

    Ok(X64StandaloneElfImage {
        bytes,
        startup_bytes: usize_to_u64(startup.len(), "startup")?,
        target_offset: usize_to_u64(layout.target_offset, "target offset")?,
        target_bytes: usize_to_u64(target.len(), "target")?,
        overhead_bytes: usize_to_u64(layout.overhead_bytes, "standalone overhead")?,
    })
}

/// Independently parse and reconstruct one canonical direct ELF64 image.
///
/// Raw byte equality or a caller-provided hash is never sufficient. The
/// verifier checks every fixed field and region, independently reconstructs
/// the expected image from the admitted startup and target, and only then
/// returns an opaque view.
pub(super) fn verify_x64_standalone_elf_r1_s8<'image>(
    image: &'image [u8],
    expected_startup: &[u8],
    expected_target: &[u8],
) -> Result<VerifiedX64StandaloneElfImage<'image>, X64StandaloneElfError> {
    let layout = verification_layout_for_lengths(expected_startup.len(), expected_target.len())?;
    if image.len() != layout.image_bytes {
        return Err(X64StandaloneElfError::ImageLength {
            expected: layout.image_bytes,
            actual: image.len(),
        });
    }
    if image.len() > X64_STANDALONE_ELF_MAX_IMAGE_BYTES {
        return Err(X64StandaloneElfError::ImageByteLimit {
            limit: X64_STANDALONE_ELF_MAX_IMAGE_BYTES,
            actual: image.len(),
        });
    }

    let image_len_u64 = usize_to_u64(image.len(), "image")?;
    verify_elf_header(image)?;
    verify_load_program_header(image, image_len_u64)?;
    verify_stack_program_header(image)?;
    verify_zero_region(
        image,
        PROGRAM_HEADERS_END,
        X64_STANDALONE_ELF_STARTUP_OFFSET,
        "header-to-startup padding",
    )?;
    verify_exact_region(
        image,
        X64_STANDALONE_ELF_STARTUP_OFFSET,
        expected_startup,
        "startup",
    )?;
    verify_zero_region(
        image,
        layout.startup_end,
        layout.target_offset,
        "startup-to-target padding",
    )?;
    verify_exact_region(image, layout.target_offset, expected_target, "target")?;

    let reconstructed =
        reconstruct_x64_standalone_elf_verifier(expected_startup, expected_target, layout)?;
    if reconstructed.len() != image.len() {
        return Err(X64StandaloneElfError::ImageLength {
            expected: reconstructed.len(),
            actual: image.len(),
        });
    }
    if let Some((offset, (expected, actual))) = reconstructed
        .iter()
        .copied()
        .zip(image.iter().copied())
        .enumerate()
        .find(|(_, (expected, actual))| expected != actual)
    {
        return Err(X64StandaloneElfError::ReconstructionMismatch {
            offset,
            expected,
            actual,
        });
    }

    let image_hash = elf_image_hash(image)?;
    let facts = parse_verified_elf_facts(image)?;

    Ok(VerifiedX64StandaloneElfImage {
        bytes: image,
        image_hash,
        startup_bytes: usize_to_u64(expected_startup.len(), "startup")?,
        target_offset: usize_to_u64(layout.target_offset, "target offset")?,
        target_bytes: usize_to_u64(expected_target.len(), "target")?,
        overhead_bytes: usize_to_u64(layout.overhead_bytes, "standalone overhead")?,
        facts,
    })
}

fn layout_for_lengths(
    startup_bytes: usize,
    target_bytes: usize,
) -> Result<ElfLayout, X64StandaloneElfError> {
    if startup_bytes == 0 {
        return Err(X64StandaloneElfError::EmptyComponent {
            component: "startup",
        });
    }
    if target_bytes == 0 {
        return Err(X64StandaloneElfError::EmptyComponent {
            component: "target",
        });
    }
    check_component_limit(
        "startup",
        startup_bytes,
        X64_STANDALONE_ELF_MAX_STARTUP_BYTES,
    )?;
    check_component_limit("target", target_bytes, X64_STANDALONE_ELF_MAX_TARGET_BYTES)?;

    let startup_end = X64_STANDALONE_ELF_STARTUP_OFFSET
        .checked_add(startup_bytes)
        .ok_or(X64StandaloneElfError::ArithmeticOverflow {
            field: "startup end",
        })?;
    let target_offset = align_up(startup_end, TARGET_ALIGNMENT)?;
    let image_bytes = target_offset.checked_add(target_bytes).ok_or(
        X64StandaloneElfError::ArithmeticOverflow {
            field: "image length",
        },
    )?;
    let overhead_bytes =
        image_bytes
            .checked_sub(target_bytes)
            .ok_or(X64StandaloneElfError::ArithmeticOverflow {
                field: "standalone overhead",
            })?;

    if overhead_bytes > X64_STANDALONE_ELF_MAX_OVERHEAD_BYTES {
        return Err(X64StandaloneElfError::OverheadByteLimit {
            limit: X64_STANDALONE_ELF_MAX_OVERHEAD_BYTES,
            actual: overhead_bytes,
        });
    }
    if image_bytes > X64_STANDALONE_ELF_MAX_IMAGE_BYTES {
        return Err(X64StandaloneElfError::ImageByteLimit {
            limit: X64_STANDALONE_ELF_MAX_IMAGE_BYTES,
            actual: image_bytes,
        });
    }
    let target_plus_overhead = target_bytes
        .checked_add(X64_STANDALONE_ELF_MAX_OVERHEAD_BYTES)
        .ok_or(X64StandaloneElfError::ArithmeticOverflow {
            field: "target plus standalone overhead",
        })?;
    if image_bytes > target_plus_overhead {
        return Err(X64StandaloneElfError::OverheadByteLimit {
            limit: X64_STANDALONE_ELF_MAX_OVERHEAD_BYTES,
            actual: overhead_bytes,
        });
    }

    Ok(ElfLayout {
        startup_end,
        target_offset,
        image_bytes,
        overhead_bytes,
    })
}

/// Recompute the canonical layout without using the writer's aligner or
/// component-limit helper. This intentionally duplicates the small trust
/// calculation so writer drift cannot validate itself.
fn verification_layout_for_lengths(
    startup_bytes: usize,
    target_bytes: usize,
) -> Result<ElfLayout, X64StandaloneElfError> {
    if startup_bytes == 0 {
        return Err(X64StandaloneElfError::EmptyComponent {
            component: "startup",
        });
    }
    if target_bytes == 0 {
        return Err(X64StandaloneElfError::EmptyComponent {
            component: "target",
        });
    }
    if startup_bytes > X64_STANDALONE_ELF_MAX_STARTUP_BYTES {
        return Err(X64StandaloneElfError::ComponentByteLimit {
            component: "startup",
            limit: X64_STANDALONE_ELF_MAX_STARTUP_BYTES,
            actual: startup_bytes,
        });
    }
    if target_bytes > X64_STANDALONE_ELF_MAX_TARGET_BYTES {
        return Err(X64StandaloneElfError::ComponentByteLimit {
            component: "target",
            limit: X64_STANDALONE_ELF_MAX_TARGET_BYTES,
            actual: target_bytes,
        });
    }

    let startup_end =
        256_usize
            .checked_add(startup_bytes)
            .ok_or(X64StandaloneElfError::ArithmeticOverflow {
                field: "verified startup end",
            })?;
    let remainder = startup_end % 16;
    let padding = if remainder == 0 {
        0
    } else {
        16_usize
            .checked_sub(remainder)
            .ok_or(X64StandaloneElfError::ArithmeticOverflow {
                field: "verified target padding",
            })?
    };
    let target_offset =
        startup_end
            .checked_add(padding)
            .ok_or(X64StandaloneElfError::ArithmeticOverflow {
                field: "verified target offset",
            })?;
    let image_bytes = target_offset.checked_add(target_bytes).ok_or(
        X64StandaloneElfError::ArithmeticOverflow {
            field: "verified image length",
        },
    )?;
    let overhead_bytes =
        image_bytes
            .checked_sub(target_bytes)
            .ok_or(X64StandaloneElfError::ArithmeticOverflow {
                field: "verified standalone overhead",
            })?;

    if overhead_bytes > 65_536 {
        return Err(X64StandaloneElfError::OverheadByteLimit {
            limit: 65_536,
            actual: overhead_bytes,
        });
    }
    if image_bytes > 67_174_400 {
        return Err(X64StandaloneElfError::ImageByteLimit {
            limit: 67_174_400,
            actual: image_bytes,
        });
    }
    let relational_limit =
        target_bytes
            .checked_add(65_536)
            .ok_or(X64StandaloneElfError::ArithmeticOverflow {
                field: "verified target plus overhead",
            })?;
    if image_bytes > relational_limit {
        return Err(X64StandaloneElfError::OverheadByteLimit {
            limit: 65_536,
            actual: overhead_bytes,
        });
    }

    Ok(ElfLayout {
        startup_end,
        target_offset,
        image_bytes,
        overhead_bytes,
    })
}

fn check_component_limit(
    component: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), X64StandaloneElfError> {
    if actual > limit {
        return Err(X64StandaloneElfError::ComponentByteLimit {
            component,
            limit,
            actual,
        });
    }
    Ok(())
}

fn align_up(value: usize, alignment: usize) -> Result<usize, X64StandaloneElfError> {
    let mask = alignment
        .checked_sub(1)
        .ok_or(X64StandaloneElfError::ArithmeticOverflow {
            field: "target alignment mask",
        })?;
    value
        .checked_add(mask)
        .map(|with_mask| with_mask & !mask)
        .ok_or(X64StandaloneElfError::ArithmeticOverflow {
            field: "target alignment",
        })
}

fn write_elf_header(bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(b"\x7fELF");
    bytes.push(ELF_CLASS_64);
    bytes.push(ELF_DATA_LITTLE_ENDIAN);
    bytes.push(ELF_CURRENT_VERSION_U8);
    bytes.push(ELF_OS_ABI_NONE);
    bytes.push(0);
    bytes.extend_from_slice(&[0; 7]);
    put_u16_le(bytes, ELF_TYPE_EXECUTABLE);
    put_u16_le(bytes, ELF_MACHINE_X86_64);
    put_u32_le(bytes, ELF_CURRENT_VERSION_U32);
    put_u64_le(bytes, X64_STANDALONE_ELF_ENTRY);
    put_u64_le(bytes, PROGRAM_HEADERS_OFFSET as u64);
    put_u64_le(bytes, 0);
    put_u32_le(bytes, 0);
    put_u16_le(bytes, ELF_HEADER_BYTES as u16);
    put_u16_le(bytes, PROGRAM_HEADER_BYTES as u16);
    put_u16_le(bytes, PROGRAM_HEADER_COUNT as u16);
    put_u16_le(bytes, 0);
    put_u16_le(bytes, 0);
    put_u16_le(bytes, 0);
}

fn write_load_program_header(bytes: &mut Vec<u8>, image_bytes: u64) {
    put_u32_le(bytes, PROGRAM_TYPE_LOAD);
    put_u32_le(bytes, PROGRAM_FLAG_READ | PROGRAM_FLAG_EXECUTE);
    put_u64_le(bytes, 0);
    put_u64_le(bytes, X64_STANDALONE_ELF_BASE);
    put_u64_le(bytes, X64_STANDALONE_ELF_BASE);
    put_u64_le(bytes, image_bytes);
    put_u64_le(bytes, image_bytes);
    put_u64_le(bytes, LOAD_ALIGNMENT);
}

fn write_stack_program_header(bytes: &mut Vec<u8>) {
    put_u32_le(bytes, PROGRAM_TYPE_GNU_STACK);
    put_u32_le(bytes, PROGRAM_FLAG_READ | PROGRAM_FLAG_WRITE);
    put_u64_le(bytes, 0);
    put_u64_le(bytes, 0);
    put_u64_le(bytes, 0);
    put_u64_le(bytes, 0);
    put_u64_le(bytes, 0);
    put_u64_le(bytes, STACK_ALIGNMENT);
}

fn put_u16_le(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u32_le(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64_le(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn check_writer_offset(bytes: &[u8], expected: usize) -> Result<(), X64StandaloneElfError> {
    if bytes.len() != expected {
        return Err(X64StandaloneElfError::InternalLayout {
            expected,
            actual: bytes.len(),
        });
    }
    Ok(())
}

/// Independently reconstruct the complete expected image through fixed
/// offset writes. This deliberately does not call the sequential production
/// writer or any of its field emitters.
fn reconstruct_x64_standalone_elf_verifier(
    startup: &[u8],
    target: &[u8],
    layout: ElfLayout,
) -> Result<Vec<u8>, X64StandaloneElfError> {
    let image_bytes = usize_to_u64(layout.image_bytes, "verified image")?;
    let mut reconstructed = Vec::new();
    reconstructed
        .try_reserve_exact(layout.image_bytes)
        .map_err(|_| X64StandaloneElfError::AllocationFailed {
            bytes: layout.image_bytes,
        })?;
    reconstructed.resize(layout.image_bytes, 0);

    verifier_copy_at(&mut reconstructed, 0, b"\x7fELF", "ELF magic")?;
    verifier_copy_at(&mut reconstructed, 4, &[2, 1, 1, 0, 0], "ELF ident")?;
    verifier_put_u16(&mut reconstructed, 16, 2, "ELF type")?;
    verifier_put_u16(&mut reconstructed, 18, 62, "ELF machine")?;
    verifier_put_u32(&mut reconstructed, 20, 1, "ELF version")?;
    verifier_put_u64(&mut reconstructed, 24, 0x0040_0100, "ELF entry")?;
    verifier_put_u64(&mut reconstructed, 32, 64, "program-header offset")?;
    verifier_put_u64(&mut reconstructed, 40, 0, "section-header offset")?;
    verifier_put_u32(&mut reconstructed, 48, 0, "ELF flags")?;
    verifier_put_u16(&mut reconstructed, 52, 64, "ELF header bytes")?;
    verifier_put_u16(&mut reconstructed, 54, 56, "program-header bytes")?;
    verifier_put_u16(&mut reconstructed, 56, 2, "program-header count")?;
    verifier_put_u16(&mut reconstructed, 58, 0, "section-header bytes")?;
    verifier_put_u16(&mut reconstructed, 60, 0, "section-header count")?;
    verifier_put_u16(&mut reconstructed, 62, 0, "section-name index")?;

    verifier_put_u32(&mut reconstructed, 64, 1, "load type")?;
    verifier_put_u32(&mut reconstructed, 68, 5, "load flags")?;
    verifier_put_u64(&mut reconstructed, 72, 0, "load file offset")?;
    verifier_put_u64(&mut reconstructed, 80, 0x0040_0000, "load virtual address")?;
    verifier_put_u64(&mut reconstructed, 88, 0x0040_0000, "load physical address")?;
    verifier_put_u64(&mut reconstructed, 96, image_bytes, "load file bytes")?;
    verifier_put_u64(&mut reconstructed, 104, image_bytes, "load memory bytes")?;
    verifier_put_u64(&mut reconstructed, 112, 4_096, "load alignment")?;

    verifier_put_u32(&mut reconstructed, 120, 0x6474_e551, "stack type")?;
    verifier_put_u32(&mut reconstructed, 124, 6, "stack flags")?;
    verifier_put_u64(&mut reconstructed, 128, 0, "stack file offset")?;
    verifier_put_u64(&mut reconstructed, 136, 0, "stack virtual address")?;
    verifier_put_u64(&mut reconstructed, 144, 0, "stack physical address")?;
    verifier_put_u64(&mut reconstructed, 152, 0, "stack file bytes")?;
    verifier_put_u64(&mut reconstructed, 160, 0, "stack memory bytes")?;
    verifier_put_u64(&mut reconstructed, 168, 16, "stack alignment")?;

    verifier_copy_at(&mut reconstructed, 256, startup, "startup")?;
    verifier_copy_at(&mut reconstructed, layout.target_offset, target, "target")?;
    Ok(reconstructed)
}

fn verifier_put_u16(
    image: &mut [u8],
    offset: usize,
    value: u16,
    field: &'static str,
) -> Result<(), X64StandaloneElfError> {
    verifier_copy_at(image, offset, &value.to_le_bytes(), field)
}

fn verifier_put_u32(
    image: &mut [u8],
    offset: usize,
    value: u32,
    field: &'static str,
) -> Result<(), X64StandaloneElfError> {
    verifier_copy_at(image, offset, &value.to_le_bytes(), field)
}

fn verifier_put_u64(
    image: &mut [u8],
    offset: usize,
    value: u64,
    field: &'static str,
) -> Result<(), X64StandaloneElfError> {
    verifier_copy_at(image, offset, &value.to_le_bytes(), field)
}

fn verifier_copy_at(
    image: &mut [u8],
    offset: usize,
    source: &[u8],
    field: &'static str,
) -> Result<(), X64StandaloneElfError> {
    let image_len = image.len();
    let end = offset
        .checked_add(source.len())
        .ok_or(X64StandaloneElfError::ArithmeticOverflow { field })?;
    let destination = image
        .get_mut(offset..end)
        .ok_or(X64StandaloneElfError::InternalLayout {
            expected: end,
            actual: image_len,
        })?;
    if destination.len() != source.len() {
        return Err(X64StandaloneElfError::InternalLayout {
            expected: source.len(),
            actual: destination.len(),
        });
    }
    destination.copy_from_slice(source);
    Ok(())
}

fn verify_elf_header(image: &[u8]) -> Result<(), X64StandaloneElfError> {
    let parser = ElfParser::new(image);
    parser.exact_bytes(0, b"\x7fELF", "ELF magic")?;
    parser.expect_u8(4, "ELF class", ELF_CLASS_64)?;
    parser.expect_u8(5, "ELF data encoding", ELF_DATA_LITTLE_ENDIAN)?;
    parser.expect_u8(6, "ELF ident version", ELF_CURRENT_VERSION_U8)?;
    parser.expect_u8(7, "ELF OS ABI", ELF_OS_ABI_NONE)?;
    parser.expect_u8(8, "ELF ABI version", 0)?;
    parser.zeroes(9, 16, "ELF ident padding")?;
    parser.expect_u16_le(16, "ELF type", ELF_TYPE_EXECUTABLE)?;
    parser.expect_u16_le(18, "ELF machine", ELF_MACHINE_X86_64)?;
    parser.expect_u32_le(20, "ELF version", ELF_CURRENT_VERSION_U32)?;
    parser.expect_u64_le(24, "ELF entry", X64_STANDALONE_ELF_ENTRY)?;
    parser.expect_u64_le(
        32,
        "ELF program-header offset",
        PROGRAM_HEADERS_OFFSET as u64,
    )?;
    parser.expect_u64_le(40, "ELF section-header offset", 0)?;
    parser.expect_u32_le(48, "ELF flags", 0)?;
    parser.expect_u16_le(52, "ELF header size", ELF_HEADER_BYTES as u16)?;
    parser.expect_u16_le(
        54,
        "ELF program-header entry size",
        PROGRAM_HEADER_BYTES as u16,
    )?;
    parser.expect_u16_le(56, "ELF program-header count", PROGRAM_HEADER_COUNT as u16)?;
    parser.expect_u16_le(58, "ELF section-header entry size", 0)?;
    parser.expect_u16_le(60, "ELF section-header count", 0)?;
    parser.expect_u16_le(62, "ELF section-name index", 0)?;
    Ok(())
}

fn verify_load_program_header(image: &[u8], image_bytes: u64) -> Result<(), X64StandaloneElfError> {
    let parser = ElfParser::new(image);
    let offset = PROGRAM_HEADERS_OFFSET;
    parser.expect_u32_le(offset, "load type", PROGRAM_TYPE_LOAD)?;
    parser.expect_u32_le(
        offset + 4,
        "load flags",
        PROGRAM_FLAG_READ | PROGRAM_FLAG_EXECUTE,
    )?;
    parser.expect_u64_le(offset + 8, "load file offset", 0)?;
    parser.expect_u64_le(offset + 16, "load virtual address", X64_STANDALONE_ELF_BASE)?;
    parser.expect_u64_le(
        offset + 24,
        "load physical address",
        X64_STANDALONE_ELF_BASE,
    )?;
    parser.expect_u64_le(offset + 32, "load file bytes", image_bytes)?;
    parser.expect_u64_le(offset + 40, "load memory bytes", image_bytes)?;
    parser.expect_u64_le(offset + 48, "load alignment", LOAD_ALIGNMENT)?;
    Ok(())
}

fn verify_stack_program_header(image: &[u8]) -> Result<(), X64StandaloneElfError> {
    let parser = ElfParser::new(image);
    let offset = PROGRAM_HEADERS_OFFSET + PROGRAM_HEADER_BYTES;
    parser.expect_u32_le(offset, "stack type", PROGRAM_TYPE_GNU_STACK)?;
    parser.expect_u32_le(
        offset + 4,
        "stack flags",
        PROGRAM_FLAG_READ | PROGRAM_FLAG_WRITE,
    )?;
    parser.expect_u64_le(offset + 8, "stack file offset", 0)?;
    parser.expect_u64_le(offset + 16, "stack virtual address", 0)?;
    parser.expect_u64_le(offset + 24, "stack physical address", 0)?;
    parser.expect_u64_le(offset + 32, "stack file bytes", 0)?;
    parser.expect_u64_le(offset + 40, "stack memory bytes", 0)?;
    parser.expect_u64_le(offset + 48, "stack alignment", STACK_ALIGNMENT)?;
    Ok(())
}

fn parse_verified_elf_facts(image: &[u8]) -> Result<X64StandaloneElfFacts, X64StandaloneElfError> {
    let parser = ElfParser::new(image);
    let load = PROGRAM_HEADERS_OFFSET;
    let stack = PROGRAM_HEADERS_OFFSET + PROGRAM_HEADER_BYTES;
    let program_types = [
        parser.u32_le(load, "verified load type")?,
        parser.u32_le(stack, "verified stack type")?,
    ];
    let program_flags = [
        parser.u32_le(load + 4, "verified load flags")?,
        parser.u32_le(stack + 4, "verified stack flags")?,
    ];
    let pt_load_segments = count_program_headers(
        program_types
            .iter()
            .filter(|program_type| **program_type == PROGRAM_TYPE_LOAD)
            .count(),
        "PT_LOAD segment count",
    )?;
    let pt_interp_segments = count_program_headers(
        program_types
            .iter()
            .filter(|program_type| **program_type == 3)
            .count(),
        "PT_INTERP segment count",
    )?;
    let pt_dynamic_segments = count_program_headers(
        program_types
            .iter()
            .filter(|program_type| **program_type == 2)
            .count(),
        "PT_DYNAMIC segment count",
    )?;
    let writable_executable_load_segments = count_program_headers(
        program_types
            .iter()
            .copied()
            .zip(program_flags.iter().copied())
            .filter(|(program_type, flags)| {
                *program_type == PROGRAM_TYPE_LOAD
                    && flags & (PROGRAM_FLAG_WRITE | PROGRAM_FLAG_EXECUTE)
                        == PROGRAM_FLAG_WRITE | PROGRAM_FLAG_EXECUTE
            })
            .count(),
        "writable/executable load-segment count",
    )?;

    Ok(X64StandaloneElfFacts {
        class: parser.u8(4, "verified ELF class")?,
        data: parser.u8(5, "verified ELF data encoding")?,
        ident_version: parser.u8(6, "verified ELF ident version")?,
        os_abi: parser.u8(7, "verified ELF OS ABI")?,
        abi_version: parser.u8(8, "verified ELF ABI version")?,
        object_type: parser.u16_le(16, "verified ELF type")?,
        machine: parser.u16_le(18, "verified ELF machine")?,
        version: parser.u32_le(20, "verified ELF version")?,
        entry: parser.u64_le(24, "verified ELF entry")?,
        program_headers_offset: parser.u64_le(32, "verified program-header offset")?,
        section_headers_offset: parser.u64_le(40, "verified section-header offset")?,
        flags: parser.u32_le(48, "verified ELF flags")?,
        elf_header_bytes: parser.u16_le(52, "verified ELF header bytes")?,
        program_header_bytes: parser.u16_le(54, "verified program-header bytes")?,
        program_header_count: parser.u16_le(56, "verified program-header count")?,
        section_header_bytes: parser.u16_le(58, "verified section-header bytes")?,
        section_header_count: parser.u16_le(60, "verified section-header count")?,
        section_name_index: parser.u16_le(62, "verified section-name index")?,
        load_type: program_types[0],
        load_flags: program_flags[0],
        load_offset: parser.u64_le(load + 8, "verified load file offset")?,
        load_vaddr: parser.u64_le(load + 16, "verified load virtual address")?,
        load_paddr: parser.u64_le(load + 24, "verified load physical address")?,
        load_filesz: parser.u64_le(load + 32, "verified load file bytes")?,
        load_memsz: parser.u64_le(load + 40, "verified load memory bytes")?,
        load_alignment: parser.u64_le(load + 48, "verified load alignment")?,
        stack_type: program_types[1],
        stack_flags: program_flags[1],
        stack_offset: parser.u64_le(stack + 8, "verified stack file offset")?,
        stack_vaddr: parser.u64_le(stack + 16, "verified stack virtual address")?,
        stack_paddr: parser.u64_le(stack + 24, "verified stack physical address")?,
        stack_filesz: parser.u64_le(stack + 32, "verified stack file bytes")?,
        stack_memsz: parser.u64_le(stack + 40, "verified stack memory bytes")?,
        stack_alignment: parser.u64_le(stack + 48, "verified stack alignment")?,
        pt_load_segments,
        pt_interp_segments,
        pt_dynamic_segments,
        writable_executable_load_segments,
    })
}

fn count_program_headers(actual: usize, field: &'static str) -> Result<u32, X64StandaloneElfError> {
    u32::try_from(actual).map_err(|_| X64StandaloneElfError::LengthConversion { field, actual })
}

fn verify_zero_region(
    image: &[u8],
    start: usize,
    end: usize,
    field: &'static str,
) -> Result<(), X64StandaloneElfError> {
    let length = end
        .checked_sub(start)
        .ok_or(X64StandaloneElfError::ArithmeticOverflow { field })?;
    let region = checked_slice(image, start, length, field)?;
    if let Some((relative, actual)) = region
        .iter()
        .copied()
        .enumerate()
        .find(|(_, byte)| *byte != 0)
    {
        let offset =
            start
                .checked_add(relative)
                .ok_or(X64StandaloneElfError::ArithmeticOverflow {
                    field: "padding mismatch offset",
                })?;
        return Err(X64StandaloneElfError::NonZeroPadding {
            field,
            offset,
            actual,
        });
    }
    Ok(())
}

fn verify_exact_region(
    image: &[u8],
    start: usize,
    expected: &[u8],
    field: &'static str,
) -> Result<(), X64StandaloneElfError> {
    let actual = checked_slice(image, start, expected.len(), field)?;
    if let Some((relative, (expected_byte, actual_byte))) = expected
        .iter()
        .copied()
        .zip(actual.iter().copied())
        .enumerate()
        .find(|(_, (expected_byte, actual_byte))| expected_byte != actual_byte)
    {
        let offset =
            start
                .checked_add(relative)
                .ok_or(X64StandaloneElfError::ArithmeticOverflow {
                    field: "region mismatch offset",
                })?;
        return Err(X64StandaloneElfError::RegionMismatch {
            field,
            offset,
            expected: expected_byte,
            actual: actual_byte,
        });
    }
    Ok(())
}

fn elf_image_hash(image: &[u8]) -> Result<SemanticHash, X64StandaloneElfError> {
    let image_bytes = usize_to_u64(image.len(), "image hash")?;
    let mut hasher = BoundedSha256::new();
    hasher.update(X64_STANDALONE_ELF_IMAGE_DOMAIN)?;
    hasher.update(&image_bytes.to_be_bytes())?;
    hasher.update(image)?;
    Ok(SemanticHash(hasher.finish()?))
}

/// Allocation-free SHA-256 used by the bounded image identity.
///
/// The shared seed hash helper pads through a temporary `Vec`, which would
/// introduce an untyped allocation at the 64 MiB image boundary. This local
/// streaming form keeps a fixed 64-byte block and reports every length/state
/// failure through `X64StandaloneElfError`.
struct BoundedSha256 {
    state: [u32; 8],
    block: [u8; 64],
    block_bytes: usize,
    total_bytes: u64,
}

impl BoundedSha256 {
    const fn new() -> Self {
        Self {
            state: SHA256_INITIAL,
            block: [0; 64],
            block_bytes: 0,
            total_bytes: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) -> Result<(), X64StandaloneElfError> {
        let input_bytes = usize_to_u64(input.len(), "SHA-256 input")?;
        self.total_bytes = self.total_bytes.checked_add(input_bytes).ok_or(
            X64StandaloneElfError::ArithmeticOverflow {
                field: "SHA-256 total byte length",
            },
        )?;
        if self.block_bytes > self.block.len() {
            return Err(X64StandaloneElfError::InvalidHashState {
                field: "buffer length",
            });
        }

        if self.block_bytes != 0 {
            let available = self.block.len().checked_sub(self.block_bytes).ok_or(
                X64StandaloneElfError::InvalidHashState {
                    field: "buffer availability",
                },
            )?;
            let copied = available.min(input.len());
            let destination_end = self.block_bytes.checked_add(copied).ok_or(
                X64StandaloneElfError::ArithmeticOverflow {
                    field: "SHA-256 buffer end",
                },
            )?;
            let destination = self
                .block
                .get_mut(self.block_bytes..destination_end)
                .ok_or(X64StandaloneElfError::InvalidHashState {
                    field: "buffer destination",
                })?;
            let source = input
                .get(..copied)
                .ok_or(X64StandaloneElfError::InvalidHashState {
                    field: "buffer source",
                })?;
            copy_equal(destination, source, "buffer copy")?;
            self.block_bytes = destination_end;
            input = input
                .get(copied..)
                .ok_or(X64StandaloneElfError::InvalidHashState {
                    field: "buffer input remainder",
                })?;

            if self.block_bytes == self.block.len() {
                let block = self.block;
                self.compress(&block)?;
                self.block = [0; 64];
                self.block_bytes = 0;
            }
        }

        while input.len() >= self.block.len() {
            let raw_block = input
                .get(..64)
                .ok_or(X64StandaloneElfError::InvalidHashState {
                    field: "complete input block",
                })?;
            let block: &[u8; 64] =
                raw_block
                    .try_into()
                    .map_err(|_| X64StandaloneElfError::InvalidHashState {
                        field: "complete input block width",
                    })?;
            self.compress(block)?;
            input = input
                .get(64..)
                .ok_or(X64StandaloneElfError::InvalidHashState {
                    field: "complete input remainder",
                })?;
        }

        if !input.is_empty() {
            let destination = self.block.get_mut(..input.len()).ok_or(
                X64StandaloneElfError::InvalidHashState {
                    field: "tail destination",
                },
            )?;
            copy_equal(destination, input, "tail copy")?;
            self.block_bytes = input.len();
        }
        Ok(())
    }

    fn finish(mut self) -> Result<[u8; 32], X64StandaloneElfError> {
        if self.block_bytes >= self.block.len() {
            return Err(X64StandaloneElfError::InvalidHashState {
                field: "final buffer length",
            });
        }
        let bit_length =
            self.total_bytes
                .checked_mul(8)
                .ok_or(X64StandaloneElfError::ArithmeticOverflow {
                    field: "SHA-256 bit length",
                })?;

        let marker = self.block.get_mut(self.block_bytes).ok_or(
            X64StandaloneElfError::InvalidHashState {
                field: "padding marker",
            },
        )?;
        *marker = 0x80;
        let after_marker =
            self.block_bytes
                .checked_add(1)
                .ok_or(X64StandaloneElfError::ArithmeticOverflow {
                    field: "SHA-256 padding offset",
                })?;

        if after_marker > 56 {
            let padding = self.block.get_mut(after_marker..).ok_or(
                X64StandaloneElfError::InvalidHashState {
                    field: "first padding block",
                },
            )?;
            padding.fill(0);
            let block = self.block;
            self.compress(&block)?;
            self.block = [0; 64];
        } else {
            let padding = self.block.get_mut(after_marker..56).ok_or(
                X64StandaloneElfError::InvalidHashState {
                    field: "final padding",
                },
            )?;
            padding.fill(0);
        }

        let encoded_length = bit_length.to_be_bytes();
        let destination =
            self.block
                .get_mut(56..64)
                .ok_or(X64StandaloneElfError::InvalidHashState {
                    field: "encoded bit length",
                })?;
        copy_equal(destination, &encoded_length, "encoded bit length")?;
        let block = self.block;
        self.compress(&block)?;

        let mut output = [0; 32];
        for (destination, word) in output.chunks_exact_mut(4).zip(self.state) {
            copy_equal(destination, &word.to_be_bytes(), "digest word")?;
        }
        Ok(output)
    }

    fn compress(&mut self, block: &[u8; 64]) -> Result<(), X64StandaloneElfError> {
        let mut words = [0_u32; 64];
        for (word, encoded) in words.iter_mut().take(16).zip(block.chunks_exact(4)) {
            let encoded: [u8; 4] =
                encoded
                    .try_into()
                    .map_err(|_| X64StandaloneElfError::InvalidHashState {
                        field: "message word width",
                    })?;
            *word = u32::from_be_bytes(encoded);
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

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for (round_constant, word) in SHA256_ROUND_CONSTANTS.into_iter().zip(words) {
            let sum1 = h
                .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
                .wrapping_add((e & f) ^ ((!e) & g))
                .wrapping_add(round_constant)
                .wrapping_add(word);
            let sum0 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
                .wrapping_add((a & b) ^ (a & c) ^ (b & c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(sum1);
            d = c;
            c = b;
            b = a;
            a = sum0.wrapping_add(sum1);
        }

        let [s0, s1, s2, s3, s4, s5, s6, s7] = self.state;
        self.state = [
            s0.wrapping_add(a),
            s1.wrapping_add(b),
            s2.wrapping_add(c),
            s3.wrapping_add(d),
            s4.wrapping_add(e),
            s5.wrapping_add(f),
            s6.wrapping_add(g),
            s7.wrapping_add(h),
        ];
        Ok(())
    }
}

fn copy_equal(
    destination: &mut [u8],
    source: &[u8],
    field: &'static str,
) -> Result<(), X64StandaloneElfError> {
    if destination.len() != source.len() {
        return Err(X64StandaloneElfError::InvalidHashState { field });
    }
    destination.copy_from_slice(source);
    Ok(())
}

fn usize_to_u64(actual: usize, field: &'static str) -> Result<u64, X64StandaloneElfError> {
    u64::try_from(actual).map_err(|_| X64StandaloneElfError::LengthConversion { field, actual })
}

fn checked_slice<'image>(
    image: &'image [u8],
    offset: usize,
    length: usize,
    field: &'static str,
) -> Result<&'image [u8], X64StandaloneElfError> {
    let end = offset
        .checked_add(length)
        .ok_or(X64StandaloneElfError::ArithmeticOverflow { field })?;
    image
        .get(offset..end)
        .ok_or(X64StandaloneElfError::Truncated {
            field,
            offset,
            needed: length,
            remaining: image.len().saturating_sub(offset),
        })
}

struct ElfParser<'image> {
    image: &'image [u8],
}

impl<'image> ElfParser<'image> {
    const fn new(image: &'image [u8]) -> Self {
        Self { image }
    }

    fn exact_bytes(
        &self,
        offset: usize,
        expected: &[u8],
        field: &'static str,
    ) -> Result<(), X64StandaloneElfError> {
        let actual = checked_slice(self.image, offset, expected.len(), field)?;
        if actual != expected {
            let relative = expected
                .iter()
                .copied()
                .zip(actual.iter().copied())
                .position(|(expected, actual)| expected != actual)
                .ok_or(X64StandaloneElfError::InvalidBytes { field, offset })?;
            let absolute =
                offset
                    .checked_add(relative)
                    .ok_or(X64StandaloneElfError::ArithmeticOverflow {
                        field: "invalid byte offset",
                    })?;
            return Err(X64StandaloneElfError::InvalidBytes {
                field,
                offset: absolute,
            });
        }
        Ok(())
    }

    fn zeroes(
        &self,
        start: usize,
        end: usize,
        field: &'static str,
    ) -> Result<(), X64StandaloneElfError> {
        verify_zero_region(self.image, start, end, field)
    }

    fn u8(&self, offset: usize, field: &'static str) -> Result<u8, X64StandaloneElfError> {
        let [value] = self.fixed_bytes::<1>(offset, field)?;
        Ok(value)
    }

    fn u16_le(&self, offset: usize, field: &'static str) -> Result<u16, X64StandaloneElfError> {
        Ok(u16::from_le_bytes(self.fixed_bytes::<2>(offset, field)?))
    }

    fn u32_le(&self, offset: usize, field: &'static str) -> Result<u32, X64StandaloneElfError> {
        Ok(u32::from_le_bytes(self.fixed_bytes::<4>(offset, field)?))
    }

    fn u64_le(&self, offset: usize, field: &'static str) -> Result<u64, X64StandaloneElfError> {
        Ok(u64::from_le_bytes(self.fixed_bytes::<8>(offset, field)?))
    }

    fn expect_u8(
        &self,
        offset: usize,
        field: &'static str,
        expected: u8,
    ) -> Result<(), X64StandaloneElfError> {
        let actual = self.u8(offset, field)?;
        expect_field(field, u64::from(expected), u64::from(actual))
    }

    fn expect_u16_le(
        &self,
        offset: usize,
        field: &'static str,
        expected: u16,
    ) -> Result<(), X64StandaloneElfError> {
        let actual = self.u16_le(offset, field)?;
        expect_field(field, u64::from(expected), u64::from(actual))
    }

    fn expect_u32_le(
        &self,
        offset: usize,
        field: &'static str,
        expected: u32,
    ) -> Result<(), X64StandaloneElfError> {
        let actual = self.u32_le(offset, field)?;
        expect_field(field, u64::from(expected), u64::from(actual))
    }

    fn expect_u64_le(
        &self,
        offset: usize,
        field: &'static str,
        expected: u64,
    ) -> Result<(), X64StandaloneElfError> {
        let actual = self.u64_le(offset, field)?;
        expect_field(field, expected, actual)
    }

    fn fixed_bytes<const N: usize>(
        &self,
        offset: usize,
        field: &'static str,
    ) -> Result<[u8; N], X64StandaloneElfError> {
        let raw = checked_slice(self.image, offset, N, field)?;
        raw.try_into()
            .map_err(|_| X64StandaloneElfError::InvalidBytes { field, offset })
    }
}

fn expect_field(
    field: &'static str,
    expected: u64,
    actual: u64,
) -> Result<(), X64StandaloneElfError> {
    if actual != expected {
        return Err(X64StandaloneElfError::InvalidField {
            field,
            expected,
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::encoding::sha256;

    const STARTUP: &[u8] = &[0x48, 0x31, 0xc0, 0xc3];
    const TARGET: &[u8] = &[0x90, 0xcc, 0xc3];
    const LOCKED_ELF_HEADER: [u8; 64] = [
        // e_ident
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // e_type, e_machine, e_version
        0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, // e_entry, e_phoff, e_shoff
        0x00, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // e_flags, e_ehsize, e_phentsize, e_phnum
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x02, 0x00,
        // e_shentsize, e_shnum, e_shstrndx
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const LOCKED_LOAD_PROGRAM_HEADER: [u8; 56] = [
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x13, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const LOCKED_STACK_PROGRAM_HEADER: [u8; 56] = [
        0x51, 0xe5, 0x74, 0x64, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const LOCKED_PROFILE_LENGTH_LOAD_PROGRAM_HEADER: [u8; 56] = [
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x13, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x05, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn bounded_streaming_sha256_matches_seed_vectors_across_block_edges() {
        for length in [0, 1, 17, 55, 56, 63, 64, 65, 127, 128, 129] {
            let input = (0..length)
                .map(|index| (index as u8).wrapping_mul(37).wrapping_add(11))
                .collect::<Vec<_>>();
            let first = input.len().min(17);
            let second = input.len().min(61);
            let mut bounded = BoundedSha256::new();
            bounded
                .update(&input[..first])
                .expect("first bounded hash segment");
            bounded
                .update(&input[first..second])
                .expect("second bounded hash segment");
            bounded
                .update(&input[second..])
                .expect("final bounded hash segment");
            assert_eq!(
                bounded.finish().expect("bounded hash finalization"),
                sha256(&input),
                "SHA-256 mismatch at {length} input bytes"
            );
        }
    }

    #[test]
    fn exact_elf_headers_layout_and_hash_preimage_are_canonical() {
        let image = build_x64_standalone_elf_r1_s8(STARTUP, TARGET)
            .expect("small canonical image must build");
        let repeated = build_x64_standalone_elf_r1_s8(STARTUP, TARGET)
            .expect("repeated canonical image must build");
        assert_eq!(repeated.bytes(), image.bytes());
        assert_eq!(image.bytes().len(), 0x113);
        assert_eq!(image.startup_bytes(), STARTUP.len() as u64);
        assert_eq!(image.target_offset(), 0x110);
        assert_eq!(image.target_bytes(), TARGET.len() as u64);
        assert_eq!(image.overhead_bytes(), 0x110);
        assert_eq!(
            X64_STANDALONE_ELF_IMAGE_DOMAIN,
            b"NAUX:x86-64:r1-s8:elf-image:v1\0"
        );
        assert_eq!(&image.bytes()[..64], &LOCKED_ELF_HEADER);
        assert_eq!(&image.bytes()[64..120], &LOCKED_LOAD_PROGRAM_HEADER);
        assert_eq!(&image.bytes()[120..176], &LOCKED_STACK_PROGRAM_HEADER);
        assert_eq!(
            &image.bytes()[24..32],
            &X64_STANDALONE_ELF_ENTRY.to_le_bytes()
        );
        assert_eq!(
            &image.bytes()[96..104],
            &(image.bytes().len() as u64).to_le_bytes()
        );
        assert_eq!(
            &image.bytes()[104..112],
            &(image.bytes().len() as u64).to_le_bytes()
        );
        assert_eq!(
            &image.bytes()[120..124],
            &PROGRAM_TYPE_GNU_STACK.to_le_bytes()
        );
        assert_eq!(
            &image.bytes()[124..128],
            &(PROGRAM_FLAG_READ | PROGRAM_FLAG_WRITE).to_le_bytes()
        );
        assert!(image.bytes()[PROGRAM_HEADERS_END..0x100]
            .iter()
            .all(|byte| *byte == 0));
        assert_eq!(&image.bytes()[0x100..0x104], STARTUP);
        assert!(image.bytes()[0x104..0x110].iter().all(|byte| *byte == 0));
        assert_eq!(&image.bytes()[0x110..], TARGET);

        let mut preimage = Vec::new();
        preimage.extend_from_slice(X64_STANDALONE_ELF_IMAGE_DOMAIN);
        preimage.extend_from_slice(&(image.bytes().len() as u64).to_be_bytes());
        preimage.extend_from_slice(image.bytes());
        let expected_image_hash = SemanticHash(sha256(&preimage));
        assert_eq!(
            elf_image_hash(image.bytes()).expect("raw image hash must encode"),
            expected_image_hash
        );

        let verified = verify_x64_standalone_elf_r1_s8(image.bytes(), STARTUP, TARGET)
            .expect("freshly emitted image must independently verify");
        assert_eq!(verified.bytes(), image.bytes());
        assert_eq!(verified.image_hash(), expected_image_hash);
        assert_eq!(verified.startup_bytes(), STARTUP.len() as u64);
        assert_eq!(verified.target_offset(), 0x110);
        assert_eq!(verified.target_bytes(), TARGET.len() as u64);
        assert_eq!(verified.overhead_bytes(), 0x110);
        let facts = verified.facts();
        assert_eq!(facts.program_header_count, 2);
        assert_eq!(facts.section_header_count, 0);
        assert_eq!(facts.load_flags, PROGRAM_FLAG_READ | PROGRAM_FLAG_EXECUTE);
        assert_eq!(facts.stack_flags, PROGRAM_FLAG_READ | PROGRAM_FLAG_WRITE);
        assert_eq!(facts.pt_load_segments, 1);
        assert_eq!(facts.pt_interp_segments, 0);
        assert_eq!(facts.pt_dynamic_segments, 0);
        assert_eq!(facts.writable_executable_load_segments, 0);
    }

    #[test]
    fn branch_and_bounds_startup_lengths_lock_exact_header_and_both_program_headers() {
        let branch_startup = vec![0x90; 1_032];
        let bounds_startup = vec![0x91; 1_038];

        for (profile, startup) in [
            ("BranchMix", branch_startup.as_slice()),
            ("Bounds", bounds_startup.as_slice()),
        ] {
            let image = build_x64_standalone_elf_r1_s8(startup, TARGET)
                .expect("representative profile-length image must build");
            assert_eq!(image.bytes().len(), 0x513, "{profile} image-length drift");
            assert_eq!(
                image.target_offset(),
                0x510,
                "{profile} target-placement drift"
            );
            assert_eq!(
                &image.bytes()[..ELF_HEADER_BYTES],
                &LOCKED_ELF_HEADER,
                "{profile} ELF-header drift"
            );
            assert_eq!(
                &image.bytes()
                    [PROGRAM_HEADERS_OFFSET..PROGRAM_HEADERS_OFFSET + PROGRAM_HEADER_BYTES],
                &LOCKED_PROFILE_LENGTH_LOAD_PROGRAM_HEADER,
                "{profile} PT_LOAD drift"
            );
            assert_eq!(
                &image.bytes()[PROGRAM_HEADERS_OFFSET + PROGRAM_HEADER_BYTES..PROGRAM_HEADERS_END],
                &LOCKED_STACK_PROGRAM_HEADER,
                "{profile} PT_GNU_STACK drift"
            );

            let verified = verify_x64_standalone_elf_r1_s8(image.bytes(), startup, TARGET)
                .expect("locked representative image must independently verify");
            assert_eq!(verified.startup_bytes(), startup.len() as u64);
            assert_eq!(verified.target_offset(), 0x510);
        }
    }

    #[test]
    fn pt_interp_substitution_and_insertion_shapes_are_rejected() {
        let image = build_x64_standalone_elf_r1_s8(STARTUP, TARGET)
            .expect("small canonical image must build");

        let mut substituted = image.bytes().to_vec();
        substituted[PROGRAM_HEADERS_OFFSET + PROGRAM_HEADER_BYTES
            ..PROGRAM_HEADERS_OFFSET + PROGRAM_HEADER_BYTES + 4]
            .copy_from_slice(&3_u32.to_le_bytes());
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&substituted, STARTUP, TARGET),
            Err(X64StandaloneElfError::InvalidField {
                field: "stack type",
                expected,
                actual: 3,
            }) if expected == u64::from(PROGRAM_TYPE_GNU_STACK)
        ));

        let mut unlisted = image.bytes().to_vec();
        unlisted[PROGRAM_HEADERS_END..PROGRAM_HEADERS_END + 4]
            .copy_from_slice(&3_u32.to_le_bytes());
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&unlisted, STARTUP, TARGET),
            Err(X64StandaloneElfError::NonZeroPadding {
                field: "header-to-startup padding",
                offset: PROGRAM_HEADERS_END,
                actual: 3,
            })
        ));

        let mut inserted = image.bytes().to_vec();
        let mut interpreter_header = [0_u8; PROGRAM_HEADER_BYTES];
        interpreter_header[..4].copy_from_slice(&3_u32.to_le_bytes());
        inserted.splice(PROGRAM_HEADERS_END..PROGRAM_HEADERS_END, interpreter_header);
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&inserted, STARTUP, TARGET),
            Err(X64StandaloneElfError::ImageLength { expected, actual })
                if expected == image.bytes().len()
                    && actual == image.bytes().len() + PROGRAM_HEADER_BYTES
        ));
    }

    #[test]
    fn writable_executable_load_and_executable_stack_are_rejected() {
        let image = build_x64_standalone_elf_r1_s8(STARTUP, TARGET)
            .expect("small canonical image must build");

        let mut writable_executable_load = image.bytes().to_vec();
        writable_executable_load[PROGRAM_HEADERS_OFFSET + 4..PROGRAM_HEADERS_OFFSET + 8]
            .copy_from_slice(
                &(PROGRAM_FLAG_READ | PROGRAM_FLAG_WRITE | PROGRAM_FLAG_EXECUTE).to_le_bytes(),
            );
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&writable_executable_load, STARTUP, TARGET),
            Err(X64StandaloneElfError::InvalidField {
                field: "load flags",
                expected,
                actual,
            }) if expected == u64::from(PROGRAM_FLAG_READ | PROGRAM_FLAG_EXECUTE)
                && actual
                    == u64::from(
                        PROGRAM_FLAG_READ | PROGRAM_FLAG_WRITE | PROGRAM_FLAG_EXECUTE
                    )
        ));

        let mut executable_stack = image.bytes().to_vec();
        let stack_flags_offset = PROGRAM_HEADERS_OFFSET + PROGRAM_HEADER_BYTES + 4;
        executable_stack[stack_flags_offset..stack_flags_offset + 4].copy_from_slice(
            &(PROGRAM_FLAG_READ | PROGRAM_FLAG_WRITE | PROGRAM_FLAG_EXECUTE).to_le_bytes(),
        );
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&executable_stack, STARTUP, TARGET),
            Err(X64StandaloneElfError::InvalidField {
                field: "stack flags",
                expected,
                actual,
            }) if expected == u64::from(PROGRAM_FLAG_READ | PROGRAM_FLAG_WRITE)
                && actual
                    == u64::from(
                        PROGRAM_FLAG_READ | PROGRAM_FLAG_WRITE | PROGRAM_FLAG_EXECUTE
                    )
        ));
    }

    #[test]
    fn extra_program_header_count_and_table_are_rejected() {
        let image = build_x64_standalone_elf_r1_s8(STARTUP, TARGET)
            .expect("small canonical image must build");

        let mut extra_count = image.bytes().to_vec();
        extra_count[56..58].copy_from_slice(&3_u16.to_le_bytes());
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&extra_count, STARTUP, TARGET),
            Err(X64StandaloneElfError::InvalidField {
                field: "ELF program-header count",
                expected: 2,
                actual: 3,
            })
        ));

        let mut extra_table = image.bytes().to_vec();
        extra_table[PROGRAM_HEADERS_END..PROGRAM_HEADERS_END + PROGRAM_HEADER_BYTES]
            .copy_from_slice(&LOCKED_STACK_PROGRAM_HEADER);
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&extra_table, STARTUP, TARGET),
            Err(X64StandaloneElfError::NonZeroPadding {
                field: "header-to-startup padding",
                offset: PROGRAM_HEADERS_END,
                actual: 0x51,
            })
        ));
    }

    #[test]
    fn every_nonzero_section_header_shape_is_rejected() {
        let image = build_x64_standalone_elf_r1_s8(STARTUP, TARGET)
            .expect("small canonical image must build");

        let mut section_offset = image.bytes().to_vec();
        section_offset[40..48].copy_from_slice(&0x100_u64.to_le_bytes());
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&section_offset, STARTUP, TARGET),
            Err(X64StandaloneElfError::InvalidField {
                field: "ELF section-header offset",
                expected: 0,
                actual: 0x100,
            })
        ));

        let mut section_entry_size = image.bytes().to_vec();
        section_entry_size[58..60].copy_from_slice(&64_u16.to_le_bytes());
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&section_entry_size, STARTUP, TARGET),
            Err(X64StandaloneElfError::InvalidField {
                field: "ELF section-header entry size",
                expected: 0,
                actual: 64,
            })
        ));

        let mut section_count = image.bytes().to_vec();
        section_count[60..62].copy_from_slice(&1_u16.to_le_bytes());
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&section_count, STARTUP, TARGET),
            Err(X64StandaloneElfError::InvalidField {
                field: "ELF section-header count",
                expected: 0,
                actual: 1,
            })
        ));

        let mut section_name_index = image.bytes().to_vec();
        section_name_index[62..64].copy_from_slice(&1_u16.to_le_bytes());
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&section_name_index, STARTUP, TARGET),
            Err(X64StandaloneElfError::InvalidField {
                field: "ELF section-name index",
                expected: 0,
                actual: 1,
            })
        ));
    }

    #[test]
    fn relocation_like_trailing_data_and_duplicated_target_are_rejected() {
        let image = build_x64_standalone_elf_r1_s8(STARTUP, TARGET)
            .expect("small canonical image must build");

        let mut relocation_trailer = image.bytes().to_vec();
        let elf64_rela_shape = [
            0x10, 0x05, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // r_offset
            0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // r_info
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r_addend
        ];
        relocation_trailer.extend_from_slice(&elf64_rela_shape);
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&relocation_trailer, STARTUP, TARGET),
            Err(X64StandaloneElfError::ImageLength { expected, actual })
                if expected == image.bytes().len()
                    && actual == image.bytes().len() + elf64_rela_shape.len()
        ));

        let mut duplicated_target = image.bytes().to_vec();
        let startup_end = X64_STANDALONE_ELF_STARTUP_OFFSET + STARTUP.len();
        duplicated_target[startup_end..startup_end + TARGET.len()].copy_from_slice(TARGET);
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&duplicated_target, STARTUP, TARGET),
            Err(X64StandaloneElfError::NonZeroPadding {
                field: "startup-to-target padding",
                offset,
                actual: 0x90,
            }) if offset == startup_end
        ));
    }

    #[test]
    fn startup_and_both_padding_region_corruptions_are_rejected() {
        let image = build_x64_standalone_elf_r1_s8(STARTUP, TARGET)
            .expect("small canonical image must build");

        let mut startup = image.bytes().to_vec();
        let startup_relative = STARTUP.len() / 2;
        let startup_offset = X64_STANDALONE_ELF_STARTUP_OFFSET + startup_relative;
        startup[startup_offset] ^= 0x40;
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&startup, STARTUP, TARGET),
            Err(X64StandaloneElfError::RegionMismatch {
                field: "startup",
                offset,
                expected,
                actual,
            }) if offset == startup_offset
                && expected == STARTUP[startup_relative]
                && actual == (STARTUP[startup_relative] ^ 0x40)
        ));

        let mut header_padding = image.bytes().to_vec();
        header_padding[PROGRAM_HEADERS_END] = 0xa5;
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&header_padding, STARTUP, TARGET),
            Err(X64StandaloneElfError::NonZeroPadding {
                field: "header-to-startup padding",
                offset: PROGRAM_HEADERS_END,
                actual: 0xa5,
            })
        ));

        let mut alignment_padding = image.bytes().to_vec();
        let startup_end = X64_STANDALONE_ELF_STARTUP_OFFSET + STARTUP.len();
        alignment_padding[startup_end] = 0x5a;
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&alignment_padding, STARTUP, TARGET),
            Err(X64StandaloneElfError::NonZeroPadding {
                field: "startup-to-target padding",
                offset,
                actual: 0x5a,
            }) if offset == startup_end
        ));
    }

    #[test]
    fn target_first_middle_and_last_byte_mutations_report_exact_offsets() {
        let image = build_x64_standalone_elf_r1_s8(STARTUP, TARGET)
            .expect("small canonical image must build");
        let target_offset =
            usize::try_from(image.target_offset()).expect("small target offset must fit usize");

        for relative in [0, TARGET.len() / 2, TARGET.len() - 1] {
            let mut mutated = image.bytes().to_vec();
            mutated[target_offset + relative] ^= 0x01;
            assert!(matches!(
                verify_x64_standalone_elf_r1_s8(&mutated, STARTUP, TARGET),
                Err(X64StandaloneElfError::RegionMismatch {
                    field: "target",
                    offset,
                    expected,
                    actual,
                }) if offset == target_offset + relative
                    && expected == TARGET[relative]
                    && actual == (TARGET[relative] ^ 0x01)
            ));
        }
    }

    #[test]
    fn eof_truncation_mutation_and_trailing_bytes_are_rejected() {
        let image = build_x64_standalone_elf_r1_s8(STARTUP, TARGET)
            .expect("small canonical image must build");
        let eof = image.bytes().len() - 1;

        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&image.bytes()[..eof], STARTUP, TARGET),
            Err(X64StandaloneElfError::ImageLength { expected, actual })
                if expected == image.bytes().len() && actual == eof
        ));

        let mut mutated_eof = image.bytes().to_vec();
        mutated_eof[eof] ^= 0x80;
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&mutated_eof, STARTUP, TARGET),
            Err(X64StandaloneElfError::RegionMismatch {
                field: "target",
                offset,
                expected,
                actual,
            }) if offset == eof
                && expected == TARGET[TARGET.len() - 1]
                && actual == (TARGET[TARGET.len() - 1] ^ 0x80)
        ));

        let mut trailing = image.bytes().to_vec();
        trailing.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&trailing, STARTUP, TARGET),
            Err(X64StandaloneElfError::ImageLength { expected, actual })
                if expected == image.bytes().len() && actual == image.bytes().len() + 4
        ));
    }

    #[test]
    fn independent_parser_rejects_header_padding_startup_target_and_eof_mutations() {
        let image = build_x64_standalone_elf_r1_s8(STARTUP, TARGET)
            .expect("small canonical image must build");
        for offset in 0..image.bytes().len() {
            let mut mutated = image.bytes().to_vec();
            mutated[offset] ^= 0x01;
            assert!(
                verify_x64_standalone_elf_r1_s8(&mutated, STARTUP, TARGET).is_err(),
                "mutation at {offset:#x} must fail closed"
            );
        }

        let truncated = &image.bytes()[..image.bytes().len() - 1];
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(truncated, STARTUP, TARGET),
            Err(X64StandaloneElfError::ImageLength { .. })
        ));
        let mut trailing = image.bytes().to_vec();
        trailing.push(0);
        assert!(matches!(
            verify_x64_standalone_elf_r1_s8(&trailing, STARTUP, TARGET),
            Err(X64StandaloneElfError::ImageLength { .. })
        ));
    }

    #[test]
    fn component_boundaries_and_alignment_fail_closed_before_allocation() {
        assert!(matches!(
            layout_for_lengths(0, 1),
            Err(X64StandaloneElfError::EmptyComponent {
                component: "startup"
            })
        ));
        assert!(matches!(
            layout_for_lengths(1, 0),
            Err(X64StandaloneElfError::EmptyComponent {
                component: "target"
            })
        ));

        let maximum = layout_for_lengths(X64_STANDALONE_ELF_MAX_STARTUP_BYTES, 1)
            .expect("maximum startup must fit");
        assert_eq!(maximum.startup_end, 0x8100);
        assert_eq!(maximum.target_offset, 0x8100);
        assert!(maximum.overhead_bytes <= X64_STANDALONE_ELF_MAX_OVERHEAD_BYTES);
        let maximum_startup = vec![0x90; X64_STANDALONE_ELF_MAX_STARTUP_BYTES];
        let maximum_startup_image = build_x64_standalone_elf_r1_s8(&maximum_startup, &[0xc3])
            .expect("maximum startup must build without widening its cap");
        verify_x64_standalone_elf_r1_s8(maximum_startup_image.bytes(), &maximum_startup, &[0xc3])
            .expect("maximum startup image must verify");
        let startup_one_over = vec![0x90; X64_STANDALONE_ELF_MAX_STARTUP_BYTES + 1];
        assert!(matches!(
            build_x64_standalone_elf_r1_s8(&startup_one_over, &[0xc3]),
            Err(X64StandaloneElfError::ComponentByteLimit {
                component: "startup",
                limit: X64_STANDALONE_ELF_MAX_STARTUP_BYTES,
                ..
            })
        ));
        assert!(matches!(
            layout_for_lengths(X64_STANDALONE_ELF_MAX_STARTUP_BYTES + 1, 1),
            Err(X64StandaloneElfError::ComponentByteLimit {
                component: "startup",
                limit: X64_STANDALONE_ELF_MAX_STARTUP_BYTES,
                ..
            })
        ));

        let maximum_target = layout_for_lengths(1, X64_STANDALONE_ELF_MAX_TARGET_BYTES)
            .expect("maximum target must fit without allocating it");
        assert_eq!(maximum_target.target_offset, 0x110);
        assert!(maximum_target.image_bytes <= X64_STANDALONE_ELF_MAX_IMAGE_BYTES);
        assert!(matches!(
            layout_for_lengths(1, X64_STANDALONE_ELF_MAX_TARGET_BYTES + 1),
            Err(X64StandaloneElfError::ComponentByteLimit {
                component: "target",
                limit: X64_STANDALONE_ELF_MAX_TARGET_BYTES,
                ..
            })
        ));

        for startup_bytes in [1, 15, 16, 17, X64_STANDALONE_ELF_MAX_STARTUP_BYTES] {
            let layout = layout_for_lengths(startup_bytes, 1).expect("admitted layout must align");
            assert_eq!(layout.target_offset % TARGET_ALIGNMENT, 0);
            assert!(layout.target_offset >= layout.startup_end);
            assert!(layout.target_offset - layout.startup_end < TARGET_ALIGNMENT);
            assert_eq!(layout.image_bytes, layout.target_offset + 1);
            assert_eq!(
                layout.overhead_bytes,
                layout.image_bytes.checked_sub(1).expect("one-byte target")
            );
        }
    }

    #[test]
    fn expected_component_substitution_is_rejected() {
        let image = build_x64_standalone_elf_r1_s8(STARTUP, TARGET)
            .expect("small canonical image must build");
        let mut startup = STARTUP.to_vec();
        startup[1] ^= 1;
        assert!(verify_x64_standalone_elf_r1_s8(image.bytes(), &startup, TARGET).is_err());

        let mut target = TARGET.to_vec();
        target[1] ^= 1;
        assert!(verify_x64_standalone_elf_r1_s8(image.bytes(), STARTUP, &target).is_err());
    }
}
