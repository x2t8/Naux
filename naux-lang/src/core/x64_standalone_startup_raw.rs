//! Raw x86-64 encoding for the bounded R1-S8 standalone startup.
//!
//! This is deliberately an internal, unsealed encoding layer.  Its receipt is
//! useful to the canonical planner/writer and to an independent verifier, but
//! it is not artifact authority and does not prove that any byte was executed.
//! All instructions are emitted directly; no assembler, linker, libc symbol,
//! callback address, or caller-selected syscall enters this boundary.

use super::encoding::sha256;
use super::x64_standalone_protocol::X64StandaloneProfile;
use std::fmt;

pub(super) const X64_STANDALONE_STARTUP_VADDR: u64 = 0x0000_0000_0040_0100;
pub(super) const X64_STANDALONE_STARTUP_MAX_LABELS: usize = 128;
pub(super) const X64_STANDALONE_STARTUP_MAX_FIXUPS: usize = 128;
pub(super) const X64_STANDALONE_STARTUP_MAX_CODE_BYTES: usize = 32_768;
pub(super) const X64_STANDALONE_STARTUP_STACK_BYTES: u16 = 183;
pub(super) const X64_STANDALONE_STARTUP_MAX_STACK_BYTES: u16 = 512;
pub(super) const X64_STANDALONE_STARTUP_SYSCALL_SITE_COUNT: usize = 8;

const X64_STANDALONE_IMAGE_BASE: u64 = 0x0000_0000_0040_0000;
const X64_STANDALONE_MAX_IMAGE_BYTES: u64 = 67_174_400;
const X64_STANDALONE_CANONICAL_TARGET_ENTRY_VADDR: u64 = 0x0000_0000_0040_0510;
const STARTUP_STACK_FRAME_BYTES: u16 = 160;
const CANONICAL_MXCSR: u32 = 0x0000_1f80;
const ARRAY_ELEMENT_LIMIT: u32 = 1_048_576;
const PAYLOAD_BYTE_LIMIT: u32 = 8_388_608;
const OUTPUT_SENTINEL: u64 = 0xa5c3_d7e9_1b2f_4068;
const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;
const F64_EXPONENT_MASK: u64 = 0x7ff0_0000_0000_0000;
const F64_FRACTION_MASK: u64 = 0x000f_ffff_ffff_ffff;

const OUTPUT_FRAME_OFFSET: u8 = 40;
const TARGET_OUTPUT_OFFSET: u8 = 80;
const MXCSR_VALUE_OFFSET: u8 = 116;
const MXCSR_OBSERVED_OFFSET: u8 = 120;
const EOF_BYTE_OFFSET: u8 = 96;

const SYSCALL_READ: u32 = 0;
const SYSCALL_WRITE: u32 = 1;
const SYSCALL_MMAP: u32 = 9;
const SYSCALL_MPROTECT: u32 = 10;
const SYSCALL_MUNMAP: u32 = 11;
const SYSCALL_EXIT_GROUP: u32 = 231;
const CANONICAL_SYSCALL_NUMBERS: [u32; 6] = [
    SYSCALL_READ,
    SYSCALL_WRITE,
    SYSCALL_MMAP,
    SYSCALL_MPROTECT,
    SYSCALL_MUNMAP,
    SYSCALL_EXIT_GROUP,
];
const CANONICAL_SYSCALL_SITES: [u16; 6] = [2, 1, 1, 1, 2, 1];
const CANONICAL_SYSCALL_SEQUENCE: [u32; X64_STANDALONE_STARTUP_SYSCALL_SITE_COUNT] = [
    SYSCALL_MMAP,
    SYSCALL_MPROTECT,
    SYSCALL_MUNMAP,
    SYSCALL_MUNMAP,
    SYSCALL_EXIT_GROUP,
    SYSCALL_READ,
    SYSCALL_READ,
    SYSCALL_WRITE,
];

// Verifier-owned full-byte oracles at the frozen v1 target entry 0x400510.
//
// These constants are decoded entirely at compile time from audited literals.
// The independent verifier selects them only by the admitted profile after
// checking the fixed target entry. It never asks the production emitter to
// reconstruct expected startup bytes.
const BRANCH_MIX_STARTUP_BYTES: [u8; 1_032] = decode_hex::<1_032>(
    concat!(
        "4531e44531ff48833c24010f85cd0200004883e4f04881eca0000000c7442474",
        "801f00000fae5424740fae5c2478817c2478801f00000f85b6020000488d3424",
        "ba28000000e8f502000085c00f859602000048b84e4155584742493148390424",
        "0f857802000048b8000100000000000148394424080f85630200004c8b742410",
        "490fce4981fe000010000f874e020000488b5c2418480fcb4c8b6c2420490fcd",
        "4c89f048c1e0034c39e80f852e0200004981fd000080000f87210200004d85ed",
        "0f844900000031ff4c89eeba0300000041ba2200000049c7c0ffffffff4531c9",
        "b8090000000f05483d01f0ffff0f83090200004989c441bf010000004c89e64c",
        "89eae83802000085c00f85d9010000488d742460e86e02000083f8010f84bc01",
        "000085c00f85be01000031c94c39f10f8313000000498b04cc480fc8498904cc",
        "48ffc1e9e4ffffff4d85ed0f841b000000b80a0000004c89e74c89eeba010000",
        "000f054885c00f859001000048b868402f1be9d7c3a548894424504889442458",
        "0fae5c2478817c2478801f00000f855f0100004c89e74c89f64889da488d4c24",
        "50e86a0200000fae5c2478817c2478801f00000f853901000085c00f840e0000",
        "0083f8010f846d000000e9230100004c8b44245048837c2458000f8512010000",
        "4c89c048ba000000000000f07f4821c248b9000000000000f07f4839ca0f852c",
        "0000004c89c248b9ffffffffffff0f004821ca4885d20f841300000048b80000",
        "00000000f87f4939c00f85c30000004531c9e92100000048837c2450000f85af",
        "00000048837c2458000f85a30000004531c041b9010000004d85ff0f84190000",
        "00b80b0000004c89e74c89ee0f054885c00f858f0000004531ff48b84e415558",
        "47424f31488944242848b8000100000000000148894424304489c80fc8894424",
        "38c744243c000000004c89c0480fc8488944244048c744244800000000488d74",
        "2428ba28000000e8ee00000085c00f8514000000bd00000000e956000000bd40",
        "000000e928000000bd4a000000e91e000000bd46000000e914000000bd470000",
        "00e90a000000bd47000000e9240000004d85ff0f841b000000b80b0000004c89",
        "e74c89ee0f054885c00f8405000000bd47000000b8e700000089ef0f050f0b49",
        "89f04989d14d85c90f843600000031c031ff4c89c64c89ca0f054885c00f841b",
        "0000000f880b0000004901c04929c1e9d1ffffff4883f8fc0f84c7ffffffb801",
        "000000c331c0c331c031ffba010000000f054885c00f841c0000000f88060000",
        "00b801000000c34883f8fc0f84d6ffffffb802000000c331c0c34989f04989d1",
        "4d85c90f843c000000b801000000bf010000004c89c64c89ca0f054885c00f84",
        "1b0000000f880b0000004901c04929c1e9cbffffff4883f8fc0f84c1ffffffb8",
        "01000000c331c0c3",
    )
    .as_bytes(),
);

const BOUNDS_STARTUP_BYTES: [u8; 1_038] = decode_hex::<1_038>(
    concat!(
        "4531e44531ff48833c24010f85d30200004883e4f04881eca0000000c7442474",
        "801f00000fae5424740fae5c2478817c2478801f00000f85bc020000488d3424",
        "ba28000000e8fb02000085c00f859c02000048b84e4155584742493148390424",
        "0f857e02000048b8000100000000000248394424080f85690200004c8b742410",
        "490fce4981fe000010000f8754020000488b5c2418480fcb4c8b6c2420490fcd",
        "4c89f048c1e0034c39e80f85340200004981fd000080000f87270200004885db",
        "0f851e0200004d85ed0f844900000031ff4c89eeba0300000041ba2200000049",
        "c7c0ffffffff4531c9b8090000000f05483d01f0ffff0f83060200004989c441",
        "bf010000004c89e64c89eae83502000085c00f85d6010000488d742460e86b02",
        "000083f8010f84b901000085c00f85bb01000031c94c39f10f8313000000498b",
        "04cc480fc8498904cc48ffc1e9e4ffffff4d85ed0f841b000000b80a0000004c",
        "89e74c89eeba010000000f054885c00f858d01000048b868402f1be9d7c3a548",
        "8944245048894424580fae5c2478817c2478801f00000f855c0100004c89e74c",
        "89f6488d542450e8640200000fae5c2478817c2478801f00000f853901000085",
        "c00f840e00000083f8010f846d000000e9230100004c8b44245048837c245800",
        "0f85120100004c89c048ba000000000000f07f4821c248b9000000000000f07f",
        "4839ca0f852c0000004c89c248b9ffffffffffff0f004821ca4885d20f841300",
        "000048b8000000000000f87f4939c00f85c30000004531c9e92100000048837c",
        "2450000f85af00000048837c2458000f85a30000004531c041b9010000004d85",
        "ff0f8419000000b80b0000004c89e74c89ee0f054885c00f858f0000004531ff",
        "48b84e41555847424f31488944242848b8000100000000000248894424304489",
        "c80fc889442438c744243c000000004c89c0480fc8488944244048c744244800",
        "000000488d742428ba28000000e8ee00000085c00f8514000000bd00000000e9",
        "56000000bd40000000e928000000bd4a000000e91e000000bd46000000e91400",
        "0000bd47000000e90a000000bd47000000e9240000004d85ff0f841b000000b8",
        "0b0000004c89e74c89ee0f054885c00f8405000000bd47000000b8e700000089",
        "ef0f050f0b4989f04989d14d85c90f843600000031c031ff4c89c64c89ca0f05",
        "4885c00f841b0000000f880b0000004901c04929c1e9d1ffffff4883f8fc0f84",
        "c7ffffffb801000000c331c0c331c031ffba010000000f054885c00f841c0000",
        "000f8806000000b801000000c34883f8fc0f84d6ffffffb802000000c331c0c3",
        "4989f04989d14d85c90f843c000000b801000000bf010000004c89c64c89ca0f",
        "054885c00f841b0000000f880b0000004901c04929c1e9cbffffff4883f8fc0f",
        "84c1ffffffb801000000c331c0c3",
    )
    .as_bytes(),
);

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
        _ => panic!("noncanonical startup oracle hex"),
    }
}

// Independent digest oracles remain as a second representation of the exact
// raw startup bytes. They are not used in place of literal byte equality.
const BRANCH_MIX_STARTUP_SHA256: [u8; 32] = [
    0x7b, 0x74, 0x37, 0x4f, 0x31, 0x23, 0x0b, 0xa5, 0x64, 0x04, 0x72, 0x87, 0x8d, 0x4c, 0x09, 0xb5,
    0x50, 0xe9, 0x78, 0xe4, 0x59, 0x35, 0x6c, 0x40, 0x45, 0x66, 0x9d, 0x09, 0x40, 0xb5, 0xaa, 0x94,
];
const BOUNDS_STARTUP_SHA256: [u8; 32] = [
    0x30, 0xbc, 0xe8, 0x8f, 0x71, 0x08, 0xcc, 0x9f, 0xa6, 0x01, 0xae, 0x9f, 0x25, 0xd2, 0xaf, 0x9f,
    0x32, 0xc1, 0x85, 0x94, 0xef, 0x08, 0x12, 0xbd, 0x67, 0x4a, 0xe6, 0x35, 0xdd, 0xcd, 0x5b, 0xc6,
];

const EXIT_SUCCESS: u32 = 0;
const EXIT_INPUT: u32 = 64;
const EXIT_INVARIANT: u32 = 70;
const EXIT_MEMORY: u32 = 71;
const EXIT_IO: u32 = 74;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum X64StandaloneStartupLabel {
    MappedPayload,
    PayloadConverted,
    EofAdmitted,
    CallReady,
    ReturnResult,
    BoundsResult,
    CanonicalReturn,
    ResultValidated,
    BuildOutput,
    InputReject,
    IoReject,
    InvariantReject,
    MemoryReject,
    UnmapReject,
    CleanupExit,
    Exit,
    ReadExact,
    ReadExactLoop,
    ReadExactNegative,
    ReadExactFailure,
    ReadExactSuccess,
    ReadEof,
    ReadEofNegative,
    ReadEofTrailing,
    ReadEofFailure,
    ReadEofSuccess,
    WriteExact,
    WriteExactLoop,
    WriteExactNegative,
    WriteExactFailure,
    WriteExactSuccess,
    ConvertLoop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum X64StandaloneStartupFixupKind {
    Jump,
    ConditionalJump,
    InternalCall,
    TargetCall,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum X64StandaloneStartupFixupTarget {
    Label(X64StandaloneStartupLabel),
    TargetEntry { vaddr: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneStartupLabelReceipt {
    label: X64StandaloneStartupLabel,
    code_offset: u32,
}

impl X64StandaloneStartupLabelReceipt {
    pub(super) const fn label(self) -> X64StandaloneStartupLabel {
        self.label
    }

    pub(super) const fn code_offset(self) -> u32 {
        self.code_offset
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneStartupFixupReceipt {
    kind: X64StandaloneStartupFixupKind,
    displacement_offset: u32,
    next_instruction_offset: u32,
    target: X64StandaloneStartupFixupTarget,
    displacement: i32,
}

impl X64StandaloneStartupFixupReceipt {
    pub(super) const fn kind(self) -> X64StandaloneStartupFixupKind {
        self.kind
    }

    pub(super) const fn displacement_offset(self) -> u32 {
        self.displacement_offset
    }

    pub(super) const fn next_instruction_offset(self) -> u32 {
        self.next_instruction_offset
    }

    pub(super) const fn target(self) -> X64StandaloneStartupFixupTarget {
        self.target
    }

    pub(super) const fn displacement(self) -> i32 {
        self.displacement
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneTargetCallPatch {
    displacement_offset: u32,
    next_instruction_offset: u32,
    target_entry_vaddr: u64,
    displacement: i32,
}

impl X64StandaloneTargetCallPatch {
    pub(super) const fn displacement_offset(self) -> u32 {
        self.displacement_offset
    }

    pub(super) const fn next_instruction_offset(self) -> u32 {
        self.next_instruction_offset
    }

    pub(super) const fn target_entry_vaddr(self) -> u64 {
        self.target_entry_vaddr
    }

    pub(super) const fn displacement(self) -> i32 {
        self.displacement
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneStartupSyscallReceipt {
    number: u32,
    opcode_offset: u32,
}

impl X64StandaloneStartupSyscallReceipt {
    pub(super) const fn number(self) -> u32 {
        self.number
    }

    pub(super) const fn opcode_offset(self) -> u32 {
        self.opcode_offset
    }
}

/// Internal output of raw startup encoding.
///
/// The type intentionally has no semantic hash, seal, verification marker, or
/// public constructor.  A later layer must bind it to a verified startup plan
/// and independently regenerate it before it can enter an ELF artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneStartupTemplate {
    profile: X64StandaloneProfile,
    code: Vec<u8>,
    labels: Vec<X64StandaloneStartupLabelReceipt>,
    fixups: Vec<X64StandaloneStartupFixupReceipt>,
    syscalls: Vec<X64StandaloneStartupSyscallReceipt>,
    target_call: X64StandaloneTargetCallPatch,
    stack_frame_bytes: u16,
    worst_case_stack_reach_bytes: u16,
    syscall_numbers: [u32; 6],
    syscall_sites: [u16; 6],
    syscall_site_count: u16,
}

impl X64StandaloneStartupTemplate {
    pub(super) const fn profile(&self) -> X64StandaloneProfile {
        self.profile
    }

    pub(super) fn code(&self) -> &[u8] {
        &self.code
    }

    pub(super) fn labels(&self) -> &[X64StandaloneStartupLabelReceipt] {
        &self.labels
    }

    pub(super) fn fixups(&self) -> &[X64StandaloneStartupFixupReceipt] {
        &self.fixups
    }

    pub(super) fn syscalls(&self) -> &[X64StandaloneStartupSyscallReceipt] {
        &self.syscalls
    }

    pub(super) fn label_count(&self) -> usize {
        self.labels.len()
    }

    pub(super) fn fixup_count(&self) -> usize {
        self.fixups.len()
    }

    pub(super) const fn target_call(&self) -> X64StandaloneTargetCallPatch {
        self.target_call
    }

    pub(super) const fn stack_frame_bytes(&self) -> u16 {
        self.stack_frame_bytes
    }

    pub(super) const fn worst_case_stack_reach_bytes(&self) -> u16 {
        self.worst_case_stack_reach_bytes
    }

    pub(super) const fn syscall_numbers(&self) -> [u32; 6] {
        self.syscall_numbers
    }

    pub(super) const fn syscall_sites(&self) -> [u16; 6] {
        self.syscall_sites
    }

    pub(super) const fn syscall_site_count(&self) -> u16 {
        self.syscall_site_count
    }

    pub(super) fn internal_call_count(&self) -> usize {
        self.fixups
            .iter()
            .filter(|fixup| fixup.kind == X64StandaloneStartupFixupKind::InternalCall)
            .count()
    }

    pub(super) fn target_call_count(&self) -> usize {
        self.fixups
            .iter()
            .filter(|fixup| fixup.kind == X64StandaloneStartupFixupKind::TargetCall)
            .count()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum X64StandaloneStartupEncodeError {
    AllocationFailed {
        field: &'static str,
        requested: usize,
    },
    CodeLimit {
        limit: usize,
        actual: usize,
    },
    LabelLimit {
        limit: usize,
        actual: usize,
    },
    FixupLimit {
        limit: usize,
        actual: usize,
    },
    SyscallSiteLimit {
        limit: usize,
        actual: usize,
    },
    DuplicateLabel {
        label: X64StandaloneStartupLabel,
    },
    UndefinedLabel {
        label: X64StandaloneStartupLabel,
    },
    OffsetOverflow {
        field: &'static str,
    },
    InvalidTargetEntry {
        vaddr: u64,
    },
    Rel32OutOfRange {
        source_next_vaddr: u64,
        target_vaddr: u64,
    },
    PatchRange {
        displacement_offset: usize,
    },
    TargetCallCount {
        actual: usize,
    },
    NonCanonicalSyscall {
        number: u32,
    },
    SyscallSiteOverflow {
        number: u32,
    },
}

impl fmt::Display for X64StandaloneStartupEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllocationFailed { field, requested } => {
                write!(formatter, "cannot reserve {requested} {field} entries")
            }
            Self::CodeLimit { limit, actual } => {
                write!(formatter, "startup code uses {actual} bytes; limit is {limit}")
            }
            Self::LabelLimit { limit, actual } => {
                write!(formatter, "startup uses {actual} labels; limit is {limit}")
            }
            Self::FixupLimit { limit, actual } => {
                write!(formatter, "startup uses {actual} fixups; limit is {limit}")
            }
            Self::SyscallSiteLimit { limit, actual } => {
                write!(formatter, "startup uses {actual} syscall sites; limit is {limit}")
            }
            Self::DuplicateLabel { label } => {
                write!(formatter, "startup label {label:?} was bound twice")
            }
            Self::UndefinedLabel { label } => {
                write!(formatter, "startup label {label:?} was not bound")
            }
            Self::OffsetOverflow { field } => {
                write!(formatter, "startup {field} offset does not fit its canonical width")
            }
            Self::InvalidTargetEntry { vaddr } => {
                write!(formatter, "target entry address {vaddr:#018x} is outside the R1-S8 image")
            }
            Self::Rel32OutOfRange {
                source_next_vaddr,
                target_vaddr,
            } => write!(
                formatter,
                "startup rel32 from {source_next_vaddr:#018x} to {target_vaddr:#018x} is out of range"
            ),
            Self::PatchRange {
                displacement_offset,
            } => write!(
                formatter,
                "startup rel32 patch at byte {displacement_offset} is outside the code"
            ),
            Self::TargetCallCount { actual } => {
                write!(formatter, "startup encoded {actual} target calls; exactly one is required")
            }
            Self::NonCanonicalSyscall { number } => {
                write!(formatter, "startup attempted to encode forbidden syscall {number}")
            }
            Self::SyscallSiteOverflow { number } => {
                write!(formatter, "startup syscall {number} site count overflowed")
            }
        }
    }
}

impl std::error::Error for X64StandaloneStartupEncodeError {}

#[derive(Clone, Copy)]
struct PendingFixup {
    kind: X64StandaloneStartupFixupKind,
    displacement_offset: usize,
    next_instruction_offset: usize,
    target: X64StandaloneStartupFixupTarget,
}

struct RawEmitter {
    code: Vec<u8>,
    labels: Vec<X64StandaloneStartupLabelReceipt>,
    fixups: Vec<PendingFixup>,
    syscalls: Vec<X64StandaloneStartupSyscallReceipt>,
    syscall_sites: [u16; 6],
}

impl RawEmitter {
    fn new() -> Result<Self, X64StandaloneStartupEncodeError> {
        let mut code = Vec::new();
        code.try_reserve_exact(X64_STANDALONE_STARTUP_MAX_CODE_BYTES)
            .map_err(|_| X64StandaloneStartupEncodeError::AllocationFailed {
                field: "code bytes",
                requested: X64_STANDALONE_STARTUP_MAX_CODE_BYTES,
            })?;
        let mut labels = Vec::new();
        labels
            .try_reserve_exact(X64_STANDALONE_STARTUP_MAX_LABELS)
            .map_err(|_| X64StandaloneStartupEncodeError::AllocationFailed {
                field: "label",
                requested: X64_STANDALONE_STARTUP_MAX_LABELS,
            })?;
        let mut fixups = Vec::new();
        fixups
            .try_reserve_exact(X64_STANDALONE_STARTUP_MAX_FIXUPS)
            .map_err(|_| X64StandaloneStartupEncodeError::AllocationFailed {
                field: "fixup",
                requested: X64_STANDALONE_STARTUP_MAX_FIXUPS,
            })?;
        let mut syscalls = Vec::new();
        syscalls
            .try_reserve_exact(X64_STANDALONE_STARTUP_SYSCALL_SITE_COUNT)
            .map_err(|_| X64StandaloneStartupEncodeError::AllocationFailed {
                field: "syscall receipt",
                requested: X64_STANDALONE_STARTUP_SYSCALL_SITE_COUNT,
            })?;
        Ok(Self {
            code,
            labels,
            fixups,
            syscalls,
            syscall_sites: [0; 6],
        })
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), X64StandaloneStartupEncodeError> {
        let actual = self.code.len().checked_add(bytes.len()).ok_or(
            X64StandaloneStartupEncodeError::OffsetOverflow {
                field: "code length",
            },
        )?;
        if actual > X64_STANDALONE_STARTUP_MAX_CODE_BYTES {
            return Err(X64StandaloneStartupEncodeError::CodeLimit {
                limit: X64_STANDALONE_STARTUP_MAX_CODE_BYTES,
                actual,
            });
        }
        self.code.extend_from_slice(bytes);
        Ok(())
    }

    fn u32(&mut self, value: u32) -> Result<(), X64StandaloneStartupEncodeError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), X64StandaloneStartupEncodeError> {
        self.bytes(&value.to_le_bytes())
    }

    fn bind(
        &mut self,
        label: X64StandaloneStartupLabel,
    ) -> Result<(), X64StandaloneStartupEncodeError> {
        if self.labels.iter().any(|receipt| receipt.label == label) {
            return Err(X64StandaloneStartupEncodeError::DuplicateLabel { label });
        }
        let actual = self.labels.len().checked_add(1).ok_or(
            X64StandaloneStartupEncodeError::OffsetOverflow {
                field: "label count",
            },
        )?;
        if actual > X64_STANDALONE_STARTUP_MAX_LABELS {
            return Err(X64StandaloneStartupEncodeError::LabelLimit {
                limit: X64_STANDALONE_STARTUP_MAX_LABELS,
                actual,
            });
        }
        let code_offset = u32::try_from(self.code.len()).map_err(|_| {
            X64StandaloneStartupEncodeError::OffsetOverflow {
                field: "label code",
            }
        })?;
        self.labels
            .push(X64StandaloneStartupLabelReceipt { label, code_offset });
        Ok(())
    }

    fn rel32(
        &mut self,
        opcode: &[u8],
        kind: X64StandaloneStartupFixupKind,
        target: X64StandaloneStartupFixupTarget,
    ) -> Result<(), X64StandaloneStartupEncodeError> {
        let actual = self.fixups.len().checked_add(1).ok_or(
            X64StandaloneStartupEncodeError::OffsetOverflow {
                field: "fixup count",
            },
        )?;
        if actual > X64_STANDALONE_STARTUP_MAX_FIXUPS {
            return Err(X64StandaloneStartupEncodeError::FixupLimit {
                limit: X64_STANDALONE_STARTUP_MAX_FIXUPS,
                actual,
            });
        }
        self.bytes(opcode)?;
        let displacement_offset = self.code.len();
        self.u32(0)?;
        let next_instruction_offset = self.code.len();
        self.fixups.push(PendingFixup {
            kind,
            displacement_offset,
            next_instruction_offset,
            target,
        });
        Ok(())
    }

    fn jump(
        &mut self,
        label: X64StandaloneStartupLabel,
    ) -> Result<(), X64StandaloneStartupEncodeError> {
        self.rel32(
            &[0xe9],
            X64StandaloneStartupFixupKind::Jump,
            X64StandaloneStartupFixupTarget::Label(label),
        )
    }

    fn jcc(
        &mut self,
        condition_opcode: u8,
        label: X64StandaloneStartupLabel,
    ) -> Result<(), X64StandaloneStartupEncodeError> {
        self.rel32(
            &[0x0f, condition_opcode],
            X64StandaloneStartupFixupKind::ConditionalJump,
            X64StandaloneStartupFixupTarget::Label(label),
        )
    }

    fn call(
        &mut self,
        label: X64StandaloneStartupLabel,
    ) -> Result<(), X64StandaloneStartupEncodeError> {
        self.rel32(
            &[0xe8],
            X64StandaloneStartupFixupKind::InternalCall,
            X64StandaloneStartupFixupTarget::Label(label),
        )
    }

    fn target_call(
        &mut self,
        target_entry_vaddr: u64,
    ) -> Result<(), X64StandaloneStartupEncodeError> {
        self.rel32(
            &[0xe8],
            X64StandaloneStartupFixupKind::TargetCall,
            X64StandaloneStartupFixupTarget::TargetEntry {
                vaddr: target_entry_vaddr,
            },
        )
    }

    fn syscall(&mut self, number: u32) -> Result<(), X64StandaloneStartupEncodeError> {
        let site = match number {
            SYSCALL_READ => 0,
            SYSCALL_WRITE => 1,
            SYSCALL_MMAP => 2,
            SYSCALL_MPROTECT => 3,
            SYSCALL_MUNMAP => 4,
            SYSCALL_EXIT_GROUP => 5,
            _ => {
                return Err(X64StandaloneStartupEncodeError::NonCanonicalSyscall { number });
            }
        };
        let current = self
            .syscall_sites
            .get(site)
            .copied()
            .ok_or(X64StandaloneStartupEncodeError::NonCanonicalSyscall { number })?;
        let next = current
            .checked_add(1)
            .ok_or(X64StandaloneStartupEncodeError::SyscallSiteOverflow { number })?;
        let slot = self
            .syscall_sites
            .get_mut(site)
            .ok_or(X64StandaloneStartupEncodeError::NonCanonicalSyscall { number })?;
        *slot = next;
        let actual = self.syscalls.len().checked_add(1).ok_or(
            X64StandaloneStartupEncodeError::OffsetOverflow {
                field: "syscall receipt count",
            },
        )?;
        if actual > X64_STANDALONE_STARTUP_SYSCALL_SITE_COUNT {
            return Err(X64StandaloneStartupEncodeError::SyscallSiteLimit {
                limit: X64_STANDALONE_STARTUP_SYSCALL_SITE_COUNT,
                actual,
            });
        }
        let opcode_offset = u32::try_from(self.code.len()).map_err(|_| {
            X64StandaloneStartupEncodeError::OffsetOverflow {
                field: "syscall opcode",
            }
        })?;
        self.bytes(&[0x0f, 0x05])?;
        self.syscalls.push(X64StandaloneStartupSyscallReceipt {
            number,
            opcode_offset,
        });
        Ok(())
    }

    fn finish(
        mut self,
        profile: X64StandaloneProfile,
    ) -> Result<X64StandaloneStartupTemplate, X64StandaloneStartupEncodeError> {
        let mut receipts = Vec::new();
        receipts.try_reserve_exact(self.fixups.len()).map_err(|_| {
            X64StandaloneStartupEncodeError::AllocationFailed {
                field: "resolved fixup",
                requested: self.fixups.len(),
            }
        })?;
        let mut target_call = None;
        let mut target_call_count = 0_usize;

        for index in 0..self.fixups.len() {
            let pending = self.fixups.get(index).copied().ok_or(
                X64StandaloneStartupEncodeError::OffsetOverflow {
                    field: "fixup index",
                },
            )?;
            let next_offset_i128 =
                i128::try_from(pending.next_instruction_offset).map_err(|_| {
                    X64StandaloneStartupEncodeError::OffsetOverflow {
                        field: "fixup source",
                    }
                })?;
            let (target_i128, source_next_vaddr, target_vaddr) = match pending.target {
                X64StandaloneStartupFixupTarget::Label(label) => {
                    let target = self
                        .labels
                        .iter()
                        .find(|receipt| receipt.label == label)
                        .ok_or(X64StandaloneStartupEncodeError::UndefinedLabel { label })?;
                    (
                        i128::from(target.code_offset),
                        0,
                        u64::from(target.code_offset),
                    )
                }
                X64StandaloneStartupFixupTarget::TargetEntry { vaddr } => {
                    let source_next_vaddr = X64_STANDALONE_STARTUP_VADDR
                        .checked_add(u64::try_from(pending.next_instruction_offset).map_err(
                            |_| X64StandaloneStartupEncodeError::OffsetOverflow {
                                field: "target-call source",
                            },
                        )?)
                        .ok_or(X64StandaloneStartupEncodeError::OffsetOverflow {
                            field: "target-call virtual address",
                        })?;
                    (i128::from(vaddr), source_next_vaddr, vaddr)
                }
            };
            let source_i128 = match pending.target {
                X64StandaloneStartupFixupTarget::Label(_) => next_offset_i128,
                X64StandaloneStartupFixupTarget::TargetEntry { .. } => {
                    i128::from(source_next_vaddr)
                }
            };
            let displacement_i128 = target_i128 - source_i128;
            let displacement = i32::try_from(displacement_i128).map_err(|_| {
                X64StandaloneStartupEncodeError::Rel32OutOfRange {
                    source_next_vaddr,
                    target_vaddr,
                }
            })?;
            let patch_end = pending.displacement_offset.checked_add(4).ok_or(
                X64StandaloneStartupEncodeError::OffsetOverflow {
                    field: "fixup patch",
                },
            )?;
            let patch = self
                .code
                .get_mut(pending.displacement_offset..patch_end)
                .ok_or(X64StandaloneStartupEncodeError::PatchRange {
                    displacement_offset: pending.displacement_offset,
                })?;
            patch.copy_from_slice(&displacement.to_le_bytes());

            let receipt = X64StandaloneStartupFixupReceipt {
                kind: pending.kind,
                displacement_offset: u32::try_from(pending.displacement_offset).map_err(|_| {
                    X64StandaloneStartupEncodeError::OffsetOverflow {
                        field: "fixup displacement",
                    }
                })?,
                next_instruction_offset: u32::try_from(pending.next_instruction_offset).map_err(
                    |_| X64StandaloneStartupEncodeError::OffsetOverflow {
                        field: "fixup next instruction",
                    },
                )?,
                target: pending.target,
                displacement,
            };
            if pending.kind == X64StandaloneStartupFixupKind::TargetCall {
                target_call_count = target_call_count.checked_add(1).ok_or(
                    X64StandaloneStartupEncodeError::OffsetOverflow {
                        field: "target-call count",
                    },
                )?;
                target_call = Some(X64StandaloneTargetCallPatch {
                    displacement_offset: receipt.displacement_offset,
                    next_instruction_offset: receipt.next_instruction_offset,
                    target_entry_vaddr: target_vaddr,
                    displacement,
                });
            }
            receipts.push(receipt);
        }

        if target_call_count != 1 {
            return Err(X64StandaloneStartupEncodeError::TargetCallCount {
                actual: target_call_count,
            });
        }
        let target_call =
            target_call.ok_or(X64StandaloneStartupEncodeError::TargetCallCount { actual: 0 })?;
        let syscall_site_count = self.syscall_sites.iter().try_fold(0_u16, |total, sites| {
            total
                .checked_add(*sites)
                .ok_or(X64StandaloneStartupEncodeError::OffsetOverflow {
                    field: "syscall site count",
                })
        })?;
        Ok(X64StandaloneStartupTemplate {
            profile,
            code: self.code,
            labels: self.labels,
            fixups: receipts,
            syscalls: self.syscalls,
            target_call,
            stack_frame_bytes: STARTUP_STACK_FRAME_BYTES,
            worst_case_stack_reach_bytes: X64_STANDALONE_STARTUP_STACK_BYTES,
            syscall_numbers: CANONICAL_SYSCALL_NUMBERS,
            syscall_sites: self.syscall_sites,
            syscall_site_count,
        })
    }
}

fn header_policy_word(profile: X64StandaloneProfile) -> u64 {
    let [profile_high, profile_low] = profile.wire_tag().to_be_bytes();
    u64::from_le_bytes([0, 1, 0, 0, 0, 0, profile_high, profile_low])
}

fn output_policy_word(profile: X64StandaloneProfile) -> u64 {
    header_policy_word(profile)
}

fn validate_target_entry(target_entry_vaddr: u64) -> Result<(), X64StandaloneStartupEncodeError> {
    let image_end = X64_STANDALONE_IMAGE_BASE
        .checked_add(X64_STANDALONE_MAX_IMAGE_BYTES)
        .ok_or(X64StandaloneStartupEncodeError::OffsetOverflow {
            field: "maximum image virtual address",
        })?;
    if target_entry_vaddr <= X64_STANDALONE_STARTUP_VADDR || target_entry_vaddr >= image_end {
        return Err(X64StandaloneStartupEncodeError::InvalidTargetEntry {
            vaddr: target_entry_vaddr,
        });
    }
    Ok(())
}

/// Encode the raw syscall-only startup for one baked profile.
///
/// The address is the final, already checked target entry virtual address,
/// including the inherited target entry offset.  It is the sole absolute
/// choice admitted by this low-level layer.
pub(super) fn encode_x64_standalone_startup_raw(
    profile: X64StandaloneProfile,
    target_entry_vaddr: u64,
) -> Result<X64StandaloneStartupTemplate, X64StandaloneStartupEncodeError> {
    validate_target_entry(target_entry_vaddr)?;
    let mut emitter = RawEmitter::new()?;

    // Kernel entry admission and the startup-owned bounded stack frame.
    emitter.bytes(&[0x45, 0x31, 0xe4])?; // xor r12d, r12d (data = null)
    emitter.bytes(&[0x45, 0x31, 0xff])?; // xor r15d, r15d (mapping absent)
    emitter.bytes(&[0x48, 0x83, 0x3c, 0x24, 0x01])?; // cmp qword [rsp], 1
    emitter.jcc(0x85, X64StandaloneStartupLabel::InputReject)?; // jne
    emitter.bytes(&[0x48, 0x83, 0xe4, 0xf0])?; // and rsp, -16
    emitter.bytes(&[0x48, 0x81, 0xec])?;
    emitter.u32(u32::from(STARTUP_STACK_FRAME_BYTES))?; // sub rsp, 160

    // Establish and verify the frozen numeric state before parsing or calling.
    emitter.bytes(&[0xc7, 0x44, 0x24, MXCSR_VALUE_OFFSET])?;
    emitter.u32(CANONICAL_MXCSR)?;
    emitter.bytes(&[0x0f, 0xae, 0x54, 0x24, MXCSR_VALUE_OFFSET])?; // ldmxcsr
    emitter.bytes(&[0x0f, 0xae, 0x5c, 0x24, MXCSR_OBSERVED_OFFSET])?; // stmxcsr
    emitter.bytes(&[0x81, 0x7c, 0x24, MXCSR_OBSERVED_OFFSET])?;
    emitter.u32(CANONICAL_MXCSR)?;
    emitter.jcc(0x85, X64StandaloneStartupLabel::InvariantReject)?;

    // Exact 40-byte header read.
    emitter.bytes(&[0x48, 0x8d, 0x34, 0x24])?; // lea rsi, [rsp]
    emitter.bytes(&[0xba])?;
    emitter.u32(40)?;
    emitter.call(X64StandaloneStartupLabel::ReadExact)?;
    emitter.bytes(&[0x85, 0xc0])?;
    emitter.jcc(0x85, X64StandaloneStartupLabel::IoReject)?;

    // Magic and the exact (version, baked-profile) policy word.
    emitter.bytes(&[0x48, 0xb8])?;
    emitter.u64(u64::from_le_bytes(*b"NAUXGBI1"))?;
    emitter.bytes(&[0x48, 0x39, 0x04, 0x24])?;
    emitter.jcc(0x85, X64StandaloneStartupLabel::InputReject)?;
    emitter.bytes(&[0x48, 0xb8])?;
    emitter.u64(header_policy_word(profile))?;
    emitter.bytes(&[0x48, 0x39, 0x44, 0x24, 0x08])?;
    emitter.jcc(0x85, X64StandaloneStartupLabel::InputReject)?;

    // Decode and check the bounded shape.  The element cap makes the shift
    // exact; equality to the declared length and the byte cap remain explicit.
    emitter.bytes(&[0x4c, 0x8b, 0x74, 0x24, 0x10])?; // mov r14, [rsp+16]
    emitter.bytes(&[0x49, 0x0f, 0xce])?; // bswap r14
    emitter.bytes(&[0x49, 0x81, 0xfe])?;
    emitter.u32(ARRAY_ELEMENT_LIMIT)?;
    emitter.jcc(0x87, X64StandaloneStartupLabel::InputReject)?; // ja
    emitter.bytes(&[0x48, 0x8b, 0x5c, 0x24, 0x18])?; // repetitions
    emitter.bytes(&[0x48, 0x0f, 0xcb])?; // bswap rbx
    emitter.bytes(&[0x4c, 0x8b, 0x6c, 0x24, 0x20])?; // payload bytes
    emitter.bytes(&[0x49, 0x0f, 0xcd])?; // bswap r13
    emitter.bytes(&[0x4c, 0x89, 0xf0])?; // mov rax, r14
    emitter.bytes(&[0x48, 0xc1, 0xe0, 0x03])?; // shl rax, 3
    emitter.bytes(&[0x4c, 0x39, 0xe8])?; // cmp rax, r13
    emitter.jcc(0x85, X64StandaloneStartupLabel::InputReject)?;
    emitter.bytes(&[0x49, 0x81, 0xfd])?;
    emitter.u32(PAYLOAD_BYTE_LIMIT)?;
    emitter.jcc(0x87, X64StandaloneStartupLabel::InputReject)?;
    if profile == X64StandaloneProfile::Bounds {
        emitter.bytes(&[0x48, 0x85, 0xdb])?; // test rbx, rbx
        emitter.jcc(0x85, X64StandaloneStartupLabel::InputReject)?;
    }

    // Empty arrays use the canonical null descriptor and no memory syscall.
    emitter.bytes(&[0x4d, 0x85, 0xed])?; // test r13, r13
    emitter.jcc(0x84, X64StandaloneStartupLabel::MappedPayload)?;

    // mmap(NULL, bytes, RW, PRIVATE|ANONYMOUS, -1, 0)
    emitter.bytes(&[0x31, 0xff])?;
    emitter.bytes(&[0x4c, 0x89, 0xee])?;
    emitter.bytes(&[0xba])?;
    emitter.u32(3)?;
    emitter.bytes(&[0x41, 0xba])?;
    emitter.u32(0x22)?;
    emitter.bytes(&[0x49, 0xc7, 0xc0])?;
    emitter.u32(u32::MAX)?; // r8 = sign-extended i64 -1
    emitter.bytes(&[0x45, 0x31, 0xc9])?;
    emitter.bytes(&[0xb8])?;
    emitter.u32(SYSCALL_MMAP)?;
    emitter.syscall(SYSCALL_MMAP)?;
    emitter.bytes(&[0x48, 0x3d])?;
    emitter.u32((-4095_i32) as u32)?;
    emitter.jcc(0x83, X64StandaloneStartupLabel::MemoryReject)?; // jae
    emitter.bytes(&[0x49, 0x89, 0xc4])?; // mov r12, rax
    emitter.bytes(&[0x41, 0xbf])?;
    emitter.u32(1)?; // mapping present, even if the returned address is zero

    // Exact payload read into the sole RW mapping.
    emitter.bytes(&[0x4c, 0x89, 0xe6])?;
    emitter.bytes(&[0x4c, 0x89, 0xea])?;
    emitter.call(X64StandaloneStartupLabel::ReadExact)?;
    emitter.bytes(&[0x85, 0xc0])?;
    emitter.jcc(0x85, X64StandaloneStartupLabel::IoReject)?;

    emitter.bind(X64StandaloneStartupLabel::MappedPayload)?;

    // Exact EOF is part of the admitted frame shape.
    emitter.bytes(&[0x48, 0x8d, 0x74, 0x24, EOF_BYTE_OFFSET])?;
    emitter.call(X64StandaloneStartupLabel::ReadEof)?;
    emitter.bytes(&[0x83, 0xf8, 0x01])?;
    emitter.jcc(0x84, X64StandaloneStartupLabel::InputReject)?;
    emitter.bytes(&[0x85, 0xc0])?;
    emitter.jcc(0x85, X64StandaloneStartupLabel::IoReject)?;
    emitter.bind(X64StandaloneStartupLabel::EofAdmitted)?;

    // Convert each wire u64 in place.  No write occurs after mprotect.
    emitter.bytes(&[0x31, 0xc9])?; // xor ecx, ecx
    emitter.bind(X64StandaloneStartupLabel::ConvertLoop)?;
    emitter.bytes(&[0x4c, 0x39, 0xf1])?; // cmp rcx, r14
    emitter.jcc(0x83, X64StandaloneStartupLabel::PayloadConverted)?;
    emitter.bytes(&[0x49, 0x8b, 0x04, 0xcc])?;
    emitter.bytes(&[0x48, 0x0f, 0xc8])?;
    emitter.bytes(&[0x49, 0x89, 0x04, 0xcc])?;
    emitter.bytes(&[0x48, 0xff, 0xc1])?;
    emitter.jump(X64StandaloneStartupLabel::ConvertLoop)?;

    emitter.bind(X64StandaloneStartupLabel::PayloadConverted)?;
    emitter.bytes(&[0x4d, 0x85, 0xed])?;
    emitter.jcc(0x84, X64StandaloneStartupLabel::CallReady)?; // skip mprotect
    emitter.bytes(&[0xb8])?;
    emitter.u32(SYSCALL_MPROTECT)?;
    emitter.bytes(&[0x4c, 0x89, 0xe7])?;
    emitter.bytes(&[0x4c, 0x89, 0xee])?;
    emitter.bytes(&[0xba])?;
    emitter.u32(1)?;
    emitter.syscall(SYSCALL_MPROTECT)?;
    emitter.bytes(&[0x48, 0x85, 0xc0])?;
    emitter.jcc(0x85, X64StandaloneStartupLabel::MemoryReject)?;

    // The label is the call-ready point (not semantic result validation).
    emitter.bind(X64StandaloneStartupLabel::CallReady)?;
    emitter.bytes(&[0x48, 0xb8])?;
    emitter.u64(OUTPUT_SENTINEL)?;
    emitter.bytes(&[0x48, 0x89, 0x44, 0x24, TARGET_OUTPUT_OFFSET])?;
    emitter.bytes(&[0x48, 0x89, 0x44, 0x24, TARGET_OUTPUT_OFFSET + 8])?;
    emitter.bytes(&[0x0f, 0xae, 0x5c, 0x24, MXCSR_OBSERVED_OFFSET])?;
    emitter.bytes(&[0x81, 0x7c, 0x24, MXCSR_OBSERVED_OFFSET])?;
    emitter.u32(CANONICAL_MXCSR)?;
    emitter.jcc(0x85, X64StandaloneStartupLabel::InvariantReject)?;

    // Exact NauxLighthouseSysV1 lanes and exactly one target-entry call.
    emitter.bytes(&[0x4c, 0x89, 0xe7])?; // rdi = data
    emitter.bytes(&[0x4c, 0x89, 0xf6])?; // rsi = elements
    match profile {
        X64StandaloneProfile::BranchMix => {
            emitter.bytes(&[0x48, 0x89, 0xda])?; // rdx = repetitions
            emitter.bytes(&[0x48, 0x8d, 0x4c, 0x24, TARGET_OUTPUT_OFFSET])?; // rcx = output
        }
        X64StandaloneProfile::Bounds => {
            emitter.bytes(&[0x48, 0x8d, 0x54, 0x24, TARGET_OUTPUT_OFFSET])?; // rdx = output
        }
    }
    emitter.target_call(target_entry_vaddr)?;

    // The target must restore the frozen MXCSR.
    emitter.bytes(&[0x0f, 0xae, 0x5c, 0x24, MXCSR_OBSERVED_OFFSET])?;
    emitter.bytes(&[0x81, 0x7c, 0x24, MXCSR_OBSERVED_OFFSET])?;
    emitter.u32(CANONICAL_MXCSR)?;
    emitter.jcc(0x85, X64StandaloneStartupLabel::InvariantReject)?;

    // Validate the native tag and two-word F64/Bounds payload grammar.
    emitter.bytes(&[0x85, 0xc0])?;
    emitter.jcc(0x84, X64StandaloneStartupLabel::ReturnResult)?;
    emitter.bytes(&[0x83, 0xf8, 0x01])?;
    emitter.jcc(0x84, X64StandaloneStartupLabel::BoundsResult)?;
    emitter.jump(X64StandaloneStartupLabel::InvariantReject)?;

    emitter.bind(X64StandaloneStartupLabel::ReturnResult)?;
    emitter.bytes(&[0x4c, 0x8b, 0x44, 0x24, TARGET_OUTPUT_OFFSET])?; // r8 = bits
    emitter.bytes(&[0x48, 0x83, 0x7c, 0x24, TARGET_OUTPUT_OFFSET + 8, 0x00])?;
    emitter.jcc(0x85, X64StandaloneStartupLabel::InvariantReject)?;
    emitter.bytes(&[0x4c, 0x89, 0xc0])?;
    emitter.bytes(&[0x48, 0xba])?;
    emitter.u64(F64_EXPONENT_MASK)?;
    emitter.bytes(&[0x48, 0x21, 0xc2])?;
    emitter.bytes(&[0x48, 0xb9])?;
    emitter.u64(F64_EXPONENT_MASK)?;
    emitter.bytes(&[0x48, 0x39, 0xca])?;
    emitter.jcc(0x85, X64StandaloneStartupLabel::CanonicalReturn)?;
    emitter.bytes(&[0x4c, 0x89, 0xc2])?;
    emitter.bytes(&[0x48, 0xb9])?;
    emitter.u64(F64_FRACTION_MASK)?;
    emitter.bytes(&[0x48, 0x21, 0xca])?;
    emitter.bytes(&[0x48, 0x85, 0xd2])?;
    emitter.jcc(0x84, X64StandaloneStartupLabel::CanonicalReturn)?;
    // The inherited R1-S7a target owns semantic NaN canonicalization. The
    // startup independently validates that boundary before serializing it.
    emitter.bytes(&[0x48, 0xb8])?;
    emitter.u64(CANONICAL_NAN_BITS)?;
    emitter.bytes(&[0x49, 0x39, 0xc0])?;
    emitter.jcc(0x85, X64StandaloneStartupLabel::InvariantReject)?;
    emitter.bind(X64StandaloneStartupLabel::CanonicalReturn)?;
    emitter.bytes(&[0x45, 0x31, 0xc9])?; // outcome r9d = Return
    emitter.jump(X64StandaloneStartupLabel::ResultValidated)?;

    emitter.bind(X64StandaloneStartupLabel::BoundsResult)?;
    emitter.bytes(&[0x48, 0x83, 0x7c, 0x24, TARGET_OUTPUT_OFFSET, 0x00])?;
    emitter.jcc(0x85, X64StandaloneStartupLabel::InvariantReject)?;
    emitter.bytes(&[0x48, 0x83, 0x7c, 0x24, TARGET_OUTPUT_OFFSET + 8, 0x00])?;
    emitter.jcc(0x85, X64StandaloneStartupLabel::InvariantReject)?;
    emitter.bytes(&[0x45, 0x31, 0xc0])?; // payload r8 = 0
    emitter.bytes(&[0x41, 0xb9])?;
    emitter.u32(1)?; // outcome r9d = Bounds

    // Both outcomes converge here after validation.  Unmap before constructing
    // or publishing the canonical output frame.
    emitter.bind(X64StandaloneStartupLabel::ResultValidated)?;
    emitter.bytes(&[0x4d, 0x85, 0xff])?; // test r15, r15
    emitter.jcc(0x84, X64StandaloneStartupLabel::BuildOutput)?;
    emitter.bytes(&[0xb8])?;
    emitter.u32(SYSCALL_MUNMAP)?;
    emitter.bytes(&[0x4c, 0x89, 0xe7])?;
    emitter.bytes(&[0x4c, 0x89, 0xee])?;
    emitter.syscall(SYSCALL_MUNMAP)?;
    emitter.bytes(&[0x48, 0x85, 0xc0])?;
    emitter.jcc(0x85, X64StandaloneStartupLabel::UnmapReject)?;
    emitter.bytes(&[0x45, 0x31, 0xff])?;

    emitter.bind(X64StandaloneStartupLabel::BuildOutput)?;
    emitter.bytes(&[0x48, 0xb8])?;
    emitter.u64(u64::from_le_bytes(*b"NAUXGBO1"))?;
    emitter.bytes(&[0x48, 0x89, 0x44, 0x24, OUTPUT_FRAME_OFFSET])?;
    emitter.bytes(&[0x48, 0xb8])?;
    emitter.u64(output_policy_word(profile))?;
    emitter.bytes(&[0x48, 0x89, 0x44, 0x24, OUTPUT_FRAME_OFFSET + 8])?;
    emitter.bytes(&[0x44, 0x89, 0xc8])?; // eax = outcome
    emitter.bytes(&[0x0f, 0xc8])?; // bswap eax
    emitter.bytes(&[0x89, 0x44, 0x24, OUTPUT_FRAME_OFFSET + 16])?;
    emitter.bytes(&[0xc7, 0x44, 0x24, OUTPUT_FRAME_OFFSET + 20])?;
    emitter.u32(0)?;
    emitter.bytes(&[0x4c, 0x89, 0xc0])?;
    emitter.bytes(&[0x48, 0x0f, 0xc8])?;
    emitter.bytes(&[0x48, 0x89, 0x44, 0x24, OUTPUT_FRAME_OFFSET + 24])?;
    emitter.bytes(&[0x48, 0xc7, 0x44, 0x24, OUTPUT_FRAME_OFFSET + 32])?;
    emitter.u32(0)?;
    emitter.bytes(&[0x48, 0x8d, 0x74, 0x24, OUTPUT_FRAME_OFFSET])?;
    emitter.bytes(&[0xba])?;
    emitter.u32(40)?;
    emitter.call(X64StandaloneStartupLabel::WriteExact)?;
    emitter.bytes(&[0x85, 0xc0])?;
    emitter.jcc(0x85, X64StandaloneStartupLabel::IoReject)?;
    emitter.bytes(&[0xbd])?;
    emitter.u32(EXIT_SUCCESS)?;
    emitter.jump(X64StandaloneStartupLabel::Exit)?;

    // Typed failures first select a status, then share mapping cleanup.
    emitter.bind(X64StandaloneStartupLabel::InputReject)?;
    emitter.bytes(&[0xbd])?;
    emitter.u32(EXIT_INPUT)?;
    emitter.jump(X64StandaloneStartupLabel::CleanupExit)?;
    emitter.bind(X64StandaloneStartupLabel::IoReject)?;
    emitter.bytes(&[0xbd])?;
    emitter.u32(EXIT_IO)?;
    emitter.jump(X64StandaloneStartupLabel::CleanupExit)?;
    emitter.bind(X64StandaloneStartupLabel::InvariantReject)?;
    emitter.bytes(&[0xbd])?;
    emitter.u32(EXIT_INVARIANT)?;
    emitter.jump(X64StandaloneStartupLabel::CleanupExit)?;
    emitter.bind(X64StandaloneStartupLabel::MemoryReject)?;
    emitter.bytes(&[0xbd])?;
    emitter.u32(EXIT_MEMORY)?;
    emitter.jump(X64StandaloneStartupLabel::CleanupExit)?;
    emitter.bind(X64StandaloneStartupLabel::UnmapReject)?;
    emitter.bytes(&[0xbd])?;
    emitter.u32(EXIT_MEMORY)?;
    emitter.jump(X64StandaloneStartupLabel::Exit)?;

    emitter.bind(X64StandaloneStartupLabel::CleanupExit)?;
    emitter.bytes(&[0x4d, 0x85, 0xff])?;
    emitter.jcc(0x84, X64StandaloneStartupLabel::Exit)?;
    emitter.bytes(&[0xb8])?;
    emitter.u32(SYSCALL_MUNMAP)?;
    emitter.bytes(&[0x4c, 0x89, 0xe7])?;
    emitter.bytes(&[0x4c, 0x89, 0xee])?;
    emitter.syscall(SYSCALL_MUNMAP)?;
    emitter.bytes(&[0x48, 0x85, 0xc0])?;
    emitter.jcc(0x84, X64StandaloneStartupLabel::Exit)?;
    emitter.bytes(&[0xbd])?;
    emitter.u32(EXIT_MEMORY)?;

    emitter.bind(X64StandaloneStartupLabel::Exit)?;
    emitter.bytes(&[0xb8])?;
    emitter.u32(SYSCALL_EXIT_GROUP)?;
    emitter.bytes(&[0x89, 0xef])?; // edi = selected exit status
    emitter.syscall(SYSCALL_EXIT_GROUP)?;
    emitter.bytes(&[0x0f, 0x0b])?; // ud2

    // read_exact(rsi=buffer, rdx=length): eax=0 success, eax=1 otherwise.
    emitter.bind(X64StandaloneStartupLabel::ReadExact)?;
    emitter.bytes(&[0x49, 0x89, 0xf0])?;
    emitter.bytes(&[0x49, 0x89, 0xd1])?;
    emitter.bind(X64StandaloneStartupLabel::ReadExactLoop)?;
    emitter.bytes(&[0x4d, 0x85, 0xc9])?;
    emitter.jcc(0x84, X64StandaloneStartupLabel::ReadExactSuccess)?;
    emitter.bytes(&[0x31, 0xc0, 0x31, 0xff])?;
    emitter.bytes(&[0x4c, 0x89, 0xc6, 0x4c, 0x89, 0xca])?;
    emitter.syscall(SYSCALL_READ)?;
    emitter.bytes(&[0x48, 0x85, 0xc0])?;
    emitter.jcc(0x84, X64StandaloneStartupLabel::ReadExactFailure)?;
    emitter.jcc(0x88, X64StandaloneStartupLabel::ReadExactNegative)?; // js
    emitter.bytes(&[0x49, 0x01, 0xc0, 0x49, 0x29, 0xc1])?;
    emitter.jump(X64StandaloneStartupLabel::ReadExactLoop)?;
    emitter.bind(X64StandaloneStartupLabel::ReadExactNegative)?;
    emitter.bytes(&[0x48, 0x83, 0xf8, 0xfc])?; // cmp rax, -EINTR
    emitter.jcc(0x84, X64StandaloneStartupLabel::ReadExactLoop)?;
    emitter.bind(X64StandaloneStartupLabel::ReadExactFailure)?;
    emitter.bytes(&[0xb8])?;
    emitter.u32(1)?;
    emitter.bytes(&[0xc3])?;
    emitter.bind(X64StandaloneStartupLabel::ReadExactSuccess)?;
    emitter.bytes(&[0x31, 0xc0, 0xc3])?;

    // read_eof(rsi=scratch): 0 EOF, 1 trailing byte, 2 read error.
    emitter.bind(X64StandaloneStartupLabel::ReadEof)?;
    emitter.bytes(&[0x31, 0xc0, 0x31, 0xff])?;
    emitter.bytes(&[0xba])?;
    emitter.u32(1)?;
    emitter.syscall(SYSCALL_READ)?;
    emitter.bytes(&[0x48, 0x85, 0xc0])?;
    emitter.jcc(0x84, X64StandaloneStartupLabel::ReadEofSuccess)?;
    emitter.jcc(0x88, X64StandaloneStartupLabel::ReadEofNegative)?;
    emitter.bind(X64StandaloneStartupLabel::ReadEofTrailing)?;
    emitter.bytes(&[0xb8])?;
    emitter.u32(1)?;
    emitter.bytes(&[0xc3])?;
    emitter.bind(X64StandaloneStartupLabel::ReadEofNegative)?;
    emitter.bytes(&[0x48, 0x83, 0xf8, 0xfc])?;
    emitter.jcc(0x84, X64StandaloneStartupLabel::ReadEof)?;
    emitter.bind(X64StandaloneStartupLabel::ReadEofFailure)?;
    emitter.bytes(&[0xb8])?;
    emitter.u32(2)?;
    emitter.bytes(&[0xc3])?;
    emitter.bind(X64StandaloneStartupLabel::ReadEofSuccess)?;
    emitter.bytes(&[0x31, 0xc0, 0xc3])?;

    // write_exact(rsi=buffer, rdx=length): eax=0 success, eax=1 otherwise.
    emitter.bind(X64StandaloneStartupLabel::WriteExact)?;
    emitter.bytes(&[0x49, 0x89, 0xf0])?;
    emitter.bytes(&[0x49, 0x89, 0xd1])?;
    emitter.bind(X64StandaloneStartupLabel::WriteExactLoop)?;
    emitter.bytes(&[0x4d, 0x85, 0xc9])?;
    emitter.jcc(0x84, X64StandaloneStartupLabel::WriteExactSuccess)?;
    emitter.bytes(&[0xb8])?;
    emitter.u32(SYSCALL_WRITE)?;
    emitter.bytes(&[0xbf])?;
    emitter.u32(1)?;
    emitter.bytes(&[0x4c, 0x89, 0xc6, 0x4c, 0x89, 0xca])?;
    emitter.syscall(SYSCALL_WRITE)?;
    emitter.bytes(&[0x48, 0x85, 0xc0])?;
    emitter.jcc(0x84, X64StandaloneStartupLabel::WriteExactFailure)?;
    emitter.jcc(0x88, X64StandaloneStartupLabel::WriteExactNegative)?;
    emitter.bytes(&[0x49, 0x01, 0xc0, 0x49, 0x29, 0xc1])?;
    emitter.jump(X64StandaloneStartupLabel::WriteExactLoop)?;
    emitter.bind(X64StandaloneStartupLabel::WriteExactNegative)?;
    emitter.bytes(&[0x48, 0x83, 0xf8, 0xfc])?;
    emitter.jcc(0x84, X64StandaloneStartupLabel::WriteExactLoop)?;
    emitter.bind(X64StandaloneStartupLabel::WriteExactFailure)?;
    emitter.bytes(&[0xb8])?;
    emitter.u32(1)?;
    emitter.bytes(&[0xc3])?;
    emitter.bind(X64StandaloneStartupLabel::WriteExactSuccess)?;
    emitter.bytes(&[0x31, 0xc0, 0xc3])?;

    emitter.finish(profile)
}

/// Opaque evidence that the supplied startup bytes passed the verifier that is
/// structurally independent from `RawEmitter`.
///
/// The token borrows the exact bytes that were checked.  It deliberately does
/// not expose a constructor or the emitter receipt used during verification.
pub(super) struct IndependentlyVerifiedX64StandaloneStartupRaw<'code> {
    code: &'code [u8],
    profile: X64StandaloneProfile,
    target_entry_vaddr: u64,
    label_count: u32,
    fixup_count: u32,
    syscall_site_count: u16,
}

impl fmt::Debug for IndependentlyVerifiedX64StandaloneStartupRaw<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndependentlyVerifiedX64StandaloneStartupRaw")
            .field("code_bytes", &self.code.len())
            .field("profile", &self.profile)
            .field("target_entry_vaddr", &self.target_entry_vaddr)
            .field("label_count", &self.label_count)
            .field("fixup_count", &self.fixup_count)
            .field("syscall_site_count", &self.syscall_site_count)
            .finish()
    }
}

impl<'code> IndependentlyVerifiedX64StandaloneStartupRaw<'code> {
    pub(super) const fn code(&self) -> &'code [u8] {
        self.code
    }

    pub(super) const fn profile(&self) -> X64StandaloneProfile {
        self.profile
    }

    pub(super) const fn target_entry_vaddr(&self) -> u64 {
        self.target_entry_vaddr
    }

    pub(super) const fn label_count(&self) -> u32 {
        self.label_count
    }

    pub(super) const fn fixup_count(&self) -> u32 {
        self.fixup_count
    }

    pub(super) const fn syscall_site_count(&self) -> u16 {
        self.syscall_site_count
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum X64StandaloneStartupVerifyError {
    Profile {
        expected: X64StandaloneProfile,
        actual: X64StandaloneProfile,
    },
    TargetEntry {
        expected: u64,
        actual: u64,
    },
    Count {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    Limit {
        field: &'static str,
        limit: usize,
        actual: usize,
    },
    WidthConversion {
        field: &'static str,
        actual: usize,
    },
    StackReceipt,
    PositionOrder {
        field: &'static str,
        index: usize,
        previous: u32,
        actual: u32,
    },
    PositionRange {
        field: &'static str,
        index: usize,
        offset: u32,
        width: u32,
        code_bytes: usize,
    },
    DuplicateLabel {
        index: usize,
        label: X64StandaloneStartupLabel,
    },
    FixupShape {
        index: usize,
        displacement_offset: u32,
        next_instruction_offset: u32,
    },
    FixupOpcode {
        index: usize,
        kind: X64StandaloneStartupFixupKind,
    },
    FixupTargetKind {
        index: usize,
        kind: X64StandaloneStartupFixupKind,
    },
    FixupDisplacement {
        index: usize,
        receipt: i32,
        encoded: i32,
    },
    FixupResolution {
        index: usize,
        expected: i128,
        actual: i128,
    },
    CallCount {
        kind: X64StandaloneStartupFixupKind,
        expected: usize,
        actual: usize,
    },
    TargetCallReceipt,
    SyscallInventory,
    SyscallSequence {
        index: usize,
        expected: u32,
        actual: u32,
    },
    SyscallOpcode {
        index: usize,
        offset: u32,
    },
    SyscallEncoding {
        index: usize,
        number: u32,
    },
    UnrecordedSyscall {
        offset: u32,
    },
    CodeDigest {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    CanonicalCodeMismatch {
        offset: u32,
    },
}

impl fmt::Display for X64StandaloneStartupVerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile { expected, actual } => write!(
                formatter,
                "startup profile receipt is {actual:?}; expected {expected:?}"
            ),
            Self::TargetEntry { expected, actual } => write!(
                formatter,
                "startup target entry receipt is {actual:#018x}; expected {expected:#018x}"
            ),
            Self::Count {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "startup {field} count is {actual}; expected {expected}"
            ),
            Self::Limit {
                field,
                limit,
                actual,
            } => write!(
                formatter,
                "startup {field} count is {actual}; hard limit is {limit}"
            ),
            Self::WidthConversion { field, actual } => write!(
                formatter,
                "startup {field} value {actual} does not fit its canonical u32 width"
            ),
            Self::StackReceipt => {
                formatter.write_str("startup stack receipt is not the locked R1-S8 layout")
            }
            Self::PositionOrder {
                field,
                index,
                previous,
                actual,
            } => write!(
                formatter,
                "startup {field} position {index} ({actual}) is not strictly after {previous}"
            ),
            Self::PositionRange {
                field,
                index,
                offset,
                width,
                code_bytes,
            } => write!(
                formatter,
                "startup {field} position {index} at {offset} with width {width} is outside {code_bytes} bytes"
            ),
            Self::DuplicateLabel { index, label } => {
                write!(formatter, "startup label {label:?} is duplicated at receipt {index}")
            }
            Self::FixupShape {
                index,
                displacement_offset,
                next_instruction_offset,
            } => write!(
                formatter,
                "startup fixup {index} has displacement {displacement_offset} but next-instruction {next_instruction_offset}"
            ),
            Self::FixupOpcode { index, kind } => write!(
                formatter,
                "startup fixup {index} has bytes incompatible with {kind:?}"
            ),
            Self::FixupTargetKind { index, kind } => write!(
                formatter,
                "startup fixup {index} has a target incompatible with {kind:?}"
            ),
            Self::FixupDisplacement {
                index,
                receipt,
                encoded,
            } => write!(
                formatter,
                "startup fixup {index} encodes displacement {encoded}, receipt says {receipt}"
            ),
            Self::FixupResolution {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "startup fixup {index} resolves to {actual:#x}; expected {expected:#x}"
            ),
            Self::CallCount {
                kind,
                expected,
                actual,
            } => write!(
                formatter,
                "startup {kind:?} count is {actual}; expected {expected}"
            ),
            Self::TargetCallReceipt => {
                formatter.write_str("startup target-call summary does not match its rel32 receipt")
            }
            Self::SyscallInventory => {
                formatter.write_str("startup syscall inventory is not the locked R1-S8 inventory")
            }
            Self::SyscallSequence {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "startup syscall receipt {index} is {actual}; expected {expected}"
            ),
            Self::SyscallOpcode { index, offset } => write!(
                formatter,
                "startup syscall receipt {index} does not point at syscall opcode {offset}"
            ),
            Self::SyscallEncoding { index, number } => write!(
                formatter,
                "startup syscall receipt {index} has no canonical setup for syscall {number}"
            ),
            Self::UnrecordedSyscall { offset } => write!(
                formatter,
                "startup contains an unrecorded syscall opcode at {offset}"
            ),
            Self::CodeDigest { expected, actual } => write!(
                formatter,
                "startup raw-code SHA-256 {actual:02x?} does not match locked digest {expected:02x?}"
            ),
            Self::CanonicalCodeMismatch { offset } => write!(
                formatter,
                "startup bytes first differ from the verifier-owned canonical table at {offset}"
            ),
        }
    }
}

impl std::error::Error for X64StandaloneStartupVerifyError {}

/// Independently validate the concrete control-transfer and syscall structure
/// of one emitted startup.
///
/// This routine never calls the emitter. It consumes a bounded structural
/// receipt plus separately supplied bytes and locked profile/target facts,
/// decodes all rel32 values and syscall sites itself, and then compares every
/// supplied byte with a verifier-owned canonical table. The production
/// receipt's code buffer is not an expected-byte oracle.
pub(super) fn independently_verify_x64_standalone_startup_raw_r1_s8<'code>(
    code: &'code [u8],
    receipt: &X64StandaloneStartupTemplate,
    expected_profile: X64StandaloneProfile,
    expected_target_entry_vaddr: u64,
) -> Result<IndependentlyVerifiedX64StandaloneStartupRaw<'code>, X64StandaloneStartupVerifyError> {
    let (expected_code_bytes, expected_fixups, expected_conditionals) =
        canonical_structural_facts(expected_profile);
    if receipt.profile() != expected_profile {
        return Err(X64StandaloneStartupVerifyError::Profile {
            expected: expected_profile,
            actual: receipt.profile(),
        });
    }
    validate_verifier_target_entry(expected_target_entry_vaddr)?;
    if receipt.target_call().target_entry_vaddr() != expected_target_entry_vaddr {
        return Err(X64StandaloneStartupVerifyError::TargetEntry {
            expected: expected_target_entry_vaddr,
            actual: receipt.target_call().target_entry_vaddr(),
        });
    }
    verify_exact_count("code byte", expected_code_bytes, code.len())?;
    verify_exact_count("label", 32, receipt.labels().len())?;
    verify_exact_count("fixup", expected_fixups, receipt.fixups().len())?;
    verify_exact_count(
        "syscall site",
        X64_STANDALONE_STARTUP_SYSCALL_SITE_COUNT,
        receipt.syscalls().len(),
    )?;
    verify_limit(
        "code byte",
        X64_STANDALONE_STARTUP_MAX_CODE_BYTES,
        code.len(),
    )?;
    verify_limit(
        "label",
        X64_STANDALONE_STARTUP_MAX_LABELS,
        receipt.labels().len(),
    )?;
    verify_limit(
        "fixup",
        X64_STANDALONE_STARTUP_MAX_FIXUPS,
        receipt.fixups().len(),
    )?;
    if receipt.stack_frame_bytes() != STARTUP_STACK_FRAME_BYTES
        || receipt.worst_case_stack_reach_bytes() != X64_STANDALONE_STARTUP_STACK_BYTES
        || receipt.worst_case_stack_reach_bytes() > X64_STANDALONE_STARTUP_MAX_STACK_BYTES
    {
        return Err(X64StandaloneStartupVerifyError::StackReceipt);
    }

    verify_labels(code, receipt.labels())?;
    verify_fixups(
        code,
        receipt,
        expected_target_entry_vaddr,
        expected_conditionals,
    )?;
    verify_syscalls(code, receipt)?;

    let expected_code = canonical_startup_bytes(expected_profile);
    let mismatch = code
        .iter()
        .zip(expected_code)
        .position(|(actual, expected)| actual != expected);
    if let Some(offset) = mismatch {
        return Err(X64StandaloneStartupVerifyError::CanonicalCodeMismatch {
            offset: verifier_usize_to_u32("canonical mismatch offset", offset)?,
        });
    }

    let expected_digest = canonical_startup_digest(expected_profile);
    let actual_digest = sha256(code);
    if actual_digest != expected_digest {
        return Err(X64StandaloneStartupVerifyError::CodeDigest {
            expected: expected_digest,
            actual: actual_digest,
        });
    }

    Ok(IndependentlyVerifiedX64StandaloneStartupRaw {
        code,
        profile: expected_profile,
        target_entry_vaddr: expected_target_entry_vaddr,
        label_count: verifier_usize_to_u32("label count", receipt.labels().len())?,
        fixup_count: verifier_usize_to_u32("fixup count", receipt.fixups().len())?,
        syscall_site_count: receipt.syscall_site_count(),
    })
}

const fn canonical_structural_facts(profile: X64StandaloneProfile) -> (usize, usize, usize) {
    match profile {
        X64StandaloneProfile::BranchMix => (1_032, 58, 42),
        X64StandaloneProfile::Bounds => (1_038, 59, 43),
    }
}

const fn canonical_startup_bytes(profile: X64StandaloneProfile) -> &'static [u8] {
    match profile {
        X64StandaloneProfile::BranchMix => &BRANCH_MIX_STARTUP_BYTES,
        X64StandaloneProfile::Bounds => &BOUNDS_STARTUP_BYTES,
    }
}

const fn canonical_startup_digest(profile: X64StandaloneProfile) -> [u8; 32] {
    match profile {
        X64StandaloneProfile::BranchMix => BRANCH_MIX_STARTUP_SHA256,
        X64StandaloneProfile::Bounds => BOUNDS_STARTUP_SHA256,
    }
}

fn validate_verifier_target_entry(
    target_entry_vaddr: u64,
) -> Result<(), X64StandaloneStartupVerifyError> {
    if target_entry_vaddr != X64_STANDALONE_CANONICAL_TARGET_ENTRY_VADDR {
        return Err(X64StandaloneStartupVerifyError::TargetEntry {
            expected: X64_STANDALONE_CANONICAL_TARGET_ENTRY_VADDR,
            actual: target_entry_vaddr,
        });
    }
    Ok(())
}

fn verify_exact_count(
    field: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), X64StandaloneStartupVerifyError> {
    if actual != expected {
        return Err(X64StandaloneStartupVerifyError::Count {
            field,
            expected,
            actual,
        });
    }
    Ok(())
}

fn verifier_usize_to_u32(
    field: &'static str,
    actual: usize,
) -> Result<u32, X64StandaloneStartupVerifyError> {
    u32::try_from(actual)
        .map_err(|_| X64StandaloneStartupVerifyError::WidthConversion { field, actual })
}

fn verify_limit(
    field: &'static str,
    limit: usize,
    actual: usize,
) -> Result<(), X64StandaloneStartupVerifyError> {
    if actual > limit {
        return Err(X64StandaloneStartupVerifyError::Limit {
            field,
            limit,
            actual,
        });
    }
    Ok(())
}

fn verify_labels(
    code: &[u8],
    labels: &[X64StandaloneStartupLabelReceipt],
) -> Result<(), X64StandaloneStartupVerifyError> {
    let mut previous = None;
    for (index, receipt) in labels.iter().copied().enumerate() {
        let offset = receipt.code_offset();
        if usize::try_from(offset).map_or(true, |offset| offset >= code.len()) {
            return Err(X64StandaloneStartupVerifyError::PositionRange {
                field: "label",
                index,
                offset,
                width: 1,
                code_bytes: code.len(),
            });
        }
        if let Some(previous) = previous {
            if offset <= previous {
                return Err(X64StandaloneStartupVerifyError::PositionOrder {
                    field: "label",
                    index,
                    previous,
                    actual: offset,
                });
            }
        }
        if labels[..index]
            .iter()
            .any(|prior| prior.label() == receipt.label())
        {
            return Err(X64StandaloneStartupVerifyError::DuplicateLabel {
                index,
                label: receipt.label(),
            });
        }
        previous = Some(offset);
    }
    Ok(())
}

fn verify_fixups(
    code: &[u8],
    receipt: &X64StandaloneStartupTemplate,
    expected_target_entry_vaddr: u64,
    expected_conditionals: usize,
) -> Result<(), X64StandaloneStartupVerifyError> {
    let mut previous_displacement = None;
    let mut jumps = 0_usize;
    let mut conditionals = 0_usize;
    let mut internal_calls = 0_usize;
    let mut target_calls = 0_usize;
    let mut verified_target_call = None;

    for (index, fixup) in receipt.fixups().iter().copied().enumerate() {
        let displacement_offset = fixup.displacement_offset();
        let next_instruction_offset = fixup.next_instruction_offset();
        if let Some(previous) = previous_displacement {
            if displacement_offset <= previous {
                return Err(X64StandaloneStartupVerifyError::PositionOrder {
                    field: "fixup displacement",
                    index,
                    previous,
                    actual: displacement_offset,
                });
            }
        }
        previous_displacement = Some(displacement_offset);
        let expected_next = displacement_offset.checked_add(4);
        if expected_next != Some(next_instruction_offset) {
            return Err(X64StandaloneStartupVerifyError::FixupShape {
                index,
                displacement_offset,
                next_instruction_offset,
            });
        }
        let displacement_start = usize::try_from(displacement_offset).map_err(|_| {
            X64StandaloneStartupVerifyError::PositionRange {
                field: "fixup displacement",
                index,
                offset: displacement_offset,
                width: 4,
                code_bytes: code.len(),
            }
        })?;
        let displacement_end = displacement_start.checked_add(4).ok_or(
            X64StandaloneStartupVerifyError::PositionRange {
                field: "fixup displacement",
                index,
                offset: displacement_offset,
                width: 4,
                code_bytes: code.len(),
            },
        )?;
        let displacement_bytes = code.get(displacement_start..displacement_end).ok_or(
            X64StandaloneStartupVerifyError::PositionRange {
                field: "fixup displacement",
                index,
                offset: displacement_offset,
                width: 4,
                code_bytes: code.len(),
            },
        )?;
        let encoded = i32::from_le_bytes([
            displacement_bytes[0],
            displacement_bytes[1],
            displacement_bytes[2],
            displacement_bytes[3],
        ]);
        if encoded != fixup.displacement() {
            return Err(X64StandaloneStartupVerifyError::FixupDisplacement {
                index,
                receipt: fixup.displacement(),
                encoded,
            });
        }

        match fixup.kind() {
            X64StandaloneStartupFixupKind::Jump => {
                jumps += 1;
                verify_single_byte_opcode(code, index, displacement_start, 0xe9, fixup.kind())?;
                if !matches!(fixup.target(), X64StandaloneStartupFixupTarget::Label(_)) {
                    return Err(X64StandaloneStartupVerifyError::FixupTargetKind {
                        index,
                        kind: fixup.kind(),
                    });
                }
            }
            X64StandaloneStartupFixupKind::ConditionalJump => {
                conditionals += 1;
                let opcode_start = displacement_start.checked_sub(2).ok_or(
                    X64StandaloneStartupVerifyError::FixupOpcode {
                        index,
                        kind: fixup.kind(),
                    },
                )?;
                let opcode = code.get(opcode_start..displacement_start).ok_or(
                    X64StandaloneStartupVerifyError::FixupOpcode {
                        index,
                        kind: fixup.kind(),
                    },
                )?;
                if opcode.first() != Some(&0x0f)
                    || !matches!(opcode.get(1), Some(0x83 | 0x84 | 0x85 | 0x87 | 0x88))
                    || !matches!(fixup.target(), X64StandaloneStartupFixupTarget::Label(_))
                {
                    return Err(X64StandaloneStartupVerifyError::FixupOpcode {
                        index,
                        kind: fixup.kind(),
                    });
                }
            }
            X64StandaloneStartupFixupKind::InternalCall => {
                internal_calls += 1;
                verify_single_byte_opcode(code, index, displacement_start, 0xe8, fixup.kind())?;
                if !matches!(fixup.target(), X64StandaloneStartupFixupTarget::Label(_)) {
                    return Err(X64StandaloneStartupVerifyError::FixupTargetKind {
                        index,
                        kind: fixup.kind(),
                    });
                }
            }
            X64StandaloneStartupFixupKind::TargetCall => {
                target_calls += 1;
                verify_single_byte_opcode(code, index, displacement_start, 0xe8, fixup.kind())?;
                if fixup.target()
                    != (X64StandaloneStartupFixupTarget::TargetEntry {
                        vaddr: expected_target_entry_vaddr,
                    })
                {
                    return Err(X64StandaloneStartupVerifyError::FixupTargetKind {
                        index,
                        kind: fixup.kind(),
                    });
                }
                verified_target_call = Some(fixup);
            }
        }

        let expected_target = match fixup.target() {
            X64StandaloneStartupFixupTarget::Label(label) => {
                let label_receipt = receipt
                    .labels()
                    .iter()
                    .find(|candidate| candidate.label() == label)
                    .ok_or(X64StandaloneStartupVerifyError::FixupTargetKind {
                        index,
                        kind: fixup.kind(),
                    })?;
                i128::from(label_receipt.code_offset())
            }
            X64StandaloneStartupFixupTarget::TargetEntry { vaddr } => i128::from(vaddr),
        };
        let source_next = match fixup.target() {
            X64StandaloneStartupFixupTarget::Label(_) => i128::from(next_instruction_offset),
            X64StandaloneStartupFixupTarget::TargetEntry { .. } => {
                i128::from(X64_STANDALONE_STARTUP_VADDR) + i128::from(next_instruction_offset)
            }
        };
        let actual_target = source_next + i128::from(encoded);
        if actual_target != expected_target {
            return Err(X64StandaloneStartupVerifyError::FixupResolution {
                index,
                expected: expected_target,
                actual: actual_target,
            });
        }
    }

    for (kind, expected, actual) in [
        (X64StandaloneStartupFixupKind::Jump, 11, jumps),
        (
            X64StandaloneStartupFixupKind::ConditionalJump,
            expected_conditionals,
            conditionals,
        ),
        (
            X64StandaloneStartupFixupKind::InternalCall,
            4,
            internal_calls,
        ),
        (X64StandaloneStartupFixupKind::TargetCall, 1, target_calls),
    ] {
        if actual != expected {
            return Err(X64StandaloneStartupVerifyError::CallCount {
                kind,
                expected,
                actual,
            });
        }
    }

    let target_fixup =
        verified_target_call.ok_or(X64StandaloneStartupVerifyError::TargetCallReceipt)?;
    let target_summary = receipt.target_call();
    if target_summary.displacement_offset() != target_fixup.displacement_offset()
        || target_summary.next_instruction_offset() != target_fixup.next_instruction_offset()
        || target_summary.target_entry_vaddr() != expected_target_entry_vaddr
        || target_summary.displacement() != target_fixup.displacement()
    {
        return Err(X64StandaloneStartupVerifyError::TargetCallReceipt);
    }
    Ok(())
}

fn verify_single_byte_opcode(
    code: &[u8],
    index: usize,
    displacement_start: usize,
    expected: u8,
    kind: X64StandaloneStartupFixupKind,
) -> Result<(), X64StandaloneStartupVerifyError> {
    let opcode_offset = displacement_start
        .checked_sub(1)
        .ok_or(X64StandaloneStartupVerifyError::FixupOpcode { index, kind })?;
    if code.get(opcode_offset) != Some(&expected) {
        return Err(X64StandaloneStartupVerifyError::FixupOpcode { index, kind });
    }
    Ok(())
}

fn verify_syscalls(
    code: &[u8],
    receipt: &X64StandaloneStartupTemplate,
) -> Result<(), X64StandaloneStartupVerifyError> {
    if receipt.syscall_numbers() != CANONICAL_SYSCALL_NUMBERS
        || receipt.syscall_sites() != CANONICAL_SYSCALL_SITES
        || usize::from(receipt.syscall_site_count()) != X64_STANDALONE_STARTUP_SYSCALL_SITE_COUNT
    {
        return Err(X64StandaloneStartupVerifyError::SyscallInventory);
    }

    let mut counts = [0_u16; 6];
    let mut previous = None;
    for (index, syscall) in receipt.syscalls().iter().copied().enumerate() {
        let expected_number = CANONICAL_SYSCALL_SEQUENCE[index];
        if syscall.number() != expected_number {
            return Err(X64StandaloneStartupVerifyError::SyscallSequence {
                index,
                expected: expected_number,
                actual: syscall.number(),
            });
        }
        let offset = syscall.opcode_offset();
        if let Some(previous) = previous {
            if offset <= previous {
                return Err(X64StandaloneStartupVerifyError::PositionOrder {
                    field: "syscall opcode",
                    index,
                    previous,
                    actual: offset,
                });
            }
        }
        previous = Some(offset);
        let start = usize::try_from(offset).map_err(|_| {
            X64StandaloneStartupVerifyError::PositionRange {
                field: "syscall opcode",
                index,
                offset,
                width: 2,
                code_bytes: code.len(),
            }
        })?;
        let end = start
            .checked_add(2)
            .ok_or(X64StandaloneStartupVerifyError::PositionRange {
                field: "syscall opcode",
                index,
                offset,
                width: 2,
                code_bytes: code.len(),
            })?;
        let opcode =
            code.get(start..end)
                .ok_or(X64StandaloneStartupVerifyError::PositionRange {
                    field: "syscall opcode",
                    index,
                    offset,
                    width: 2,
                    code_bytes: code.len(),
                })?;
        if opcode != [0x0f, 0x05] {
            return Err(X64StandaloneStartupVerifyError::SyscallOpcode { index, offset });
        }
        if !has_canonical_syscall_setup(code, start, syscall.number()) {
            return Err(X64StandaloneStartupVerifyError::SyscallEncoding {
                index,
                number: syscall.number(),
            });
        }
        let slot = syscall_slot(syscall.number())
            .ok_or(X64StandaloneStartupVerifyError::SyscallInventory)?;
        counts[slot] = counts[slot]
            .checked_add(1)
            .ok_or(X64StandaloneStartupVerifyError::SyscallInventory)?;
    }
    if counts != CANONICAL_SYSCALL_SITES {
        return Err(X64StandaloneStartupVerifyError::SyscallInventory);
    }

    let mut receipt_index = 0_usize;
    for (offset, bytes) in code.windows(2).enumerate() {
        if bytes != [0x0f, 0x05] {
            continue;
        }
        let recorded = receipt.syscalls().get(receipt_index).ok_or(
            X64StandaloneStartupVerifyError::UnrecordedSyscall {
                offset: verifier_usize_to_u32("unrecorded syscall offset", offset)?,
            },
        )?;
        if usize::try_from(recorded.opcode_offset()).ok() != Some(offset) {
            return Err(X64StandaloneStartupVerifyError::UnrecordedSyscall {
                offset: verifier_usize_to_u32("unrecorded syscall offset", offset)?,
            });
        }
        receipt_index += 1;
    }
    if receipt_index != receipt.syscalls().len() {
        let missing = receipt
            .syscalls()
            .get(receipt_index)
            .ok_or(X64StandaloneStartupVerifyError::SyscallInventory)?
            .opcode_offset();
        return Err(X64StandaloneStartupVerifyError::SyscallOpcode {
            index: receipt_index,
            offset: missing,
        });
    }
    Ok(())
}

const fn syscall_slot(number: u32) -> Option<usize> {
    match number {
        SYSCALL_READ => Some(0),
        SYSCALL_WRITE => Some(1),
        SYSCALL_MMAP => Some(2),
        SYSCALL_MPROTECT => Some(3),
        SYSCALL_MUNMAP => Some(4),
        SYSCALL_EXIT_GROUP => Some(5),
        _ => None,
    }
}

fn has_canonical_syscall_setup(code: &[u8], offset: usize, number: u32) -> bool {
    const MMAP: &[u8] = &[0xb8, 9, 0, 0, 0];
    const MPROTECT: &[u8] = &[
        0xb8, 10, 0, 0, 0, 0x4c, 0x89, 0xe7, 0x4c, 0x89, 0xee, 0xba, 1, 0, 0, 0,
    ];
    const MUNMAP: &[u8] = &[0xb8, 11, 0, 0, 0, 0x4c, 0x89, 0xe7, 0x4c, 0x89, 0xee];
    const EXIT_GROUP: &[u8] = &[0xb8, 231, 0, 0, 0, 0x89, 0xef];
    const READ_EXACT: &[u8] = &[0x31, 0xc0, 0x31, 0xff, 0x4c, 0x89, 0xc6, 0x4c, 0x89, 0xca];
    const READ_EOF: &[u8] = &[0x31, 0xc0, 0x31, 0xff, 0xba, 1, 0, 0, 0];
    const WRITE_EXACT: &[u8] = &[
        0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x4c, 0x89, 0xc6, 0x4c, 0x89, 0xca,
    ];

    match number {
        SYSCALL_MMAP => immediately_preceded_by(code, offset, MMAP),
        SYSCALL_MPROTECT => immediately_preceded_by(code, offset, MPROTECT),
        SYSCALL_MUNMAP => immediately_preceded_by(code, offset, MUNMAP),
        SYSCALL_EXIT_GROUP => immediately_preceded_by(code, offset, EXIT_GROUP),
        SYSCALL_READ => {
            immediately_preceded_by(code, offset, READ_EXACT)
                || immediately_preceded_by(code, offset, READ_EOF)
        }
        SYSCALL_WRITE => immediately_preceded_by(code, offset, WRITE_EXACT),
        _ => false,
    }
}

fn immediately_preceded_by(code: &[u8], offset: usize, prefix: &[u8]) -> bool {
    offset
        .checked_sub(prefix.len())
        .and_then(|start| code.get(start..offset))
        == Some(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET_ENTRY: u64 = 0x0000_0000_0040_0510;

    #[derive(Clone, Copy)]
    struct CriticalOffsets {
        payload_converted: u32,
        call_ready: u32,
        result_validated: u32,
        build_output: u32,
        input_reject: u32,
        invariant_reject: u32,
        memory_reject: u32,
        unmap_reject: u32,
        cleanup_exit: u32,
        exit: u32,
        read_exact: u32,
        read_exact_loop: u32,
        read_exact_negative: u32,
        read_exact_failure: u32,
        read_eof: u32,
        read_eof_negative: u32,
        read_eof_failure: u32,
        write_exact: u32,
        write_exact_loop: u32,
        write_exact_negative: u32,
        write_exact_failure: u32,
        mmap_syscall: u32,
        mprotect_syscall: u32,
        success_munmap_syscall: u32,
        cleanup_munmap_syscall: u32,
        write_syscall: u32,
        mapping_store: u32,
        target_call_displacement: u32,
        unknown_tag_displacement: u32,
        return_reserved_displacement: u32,
        noncanonical_nan_displacement: u32,
        bounds_word_0_displacement: u32,
        bounds_word_1_displacement: u32,
    }

    const fn critical_offsets(profile: X64StandaloneProfile) -> CriticalOffsets {
        match profile {
            X64StandaloneProfile::BranchMix => CriticalOffsets {
                payload_converted: 328,
                call_ready: 364,
                result_validated: 600,
                build_output: 634,
                input_reject: 734,
                invariant_reject: 754,
                memory_reject: 764,
                unmap_reject: 774,
                cleanup_exit: 784,
                exit: 820,
                read_exact: 831,
                read_exact_loop: 837,
                read_exact_negative: 884,
                read_exact_failure: 894,
                read_eof: 903,
                read_eof_negative: 935,
                read_eof_failure: 945,
                write_exact: 954,
                write_exact_loop: 960,
                write_exact_negative: 1_013,
                write_exact_failure: 1_023,
                mmap_syscall: 229,
                mprotect_syscall: 353,
                success_munmap_syscall: 620,
                cleanup_munmap_syscall: 804,
                write_syscall: 985,
                mapping_store: 316,
                target_call_displacement: 418,
                unknown_tag_displacement: 459,
                return_reserved_displacement: 476,
                noncanonical_nan_displacement: 555,
                bounds_word_0_displacement: 575,
                bounds_word_1_displacement: 587,
            },
            X64StandaloneProfile::Bounds => CriticalOffsets {
                payload_converted: 337,
                call_ready: 373,
                result_validated: 606,
                build_output: 640,
                input_reject: 740,
                invariant_reject: 760,
                memory_reject: 770,
                unmap_reject: 780,
                cleanup_exit: 790,
                exit: 826,
                read_exact: 837,
                read_exact_loop: 843,
                read_exact_negative: 890,
                read_exact_failure: 900,
                read_eof: 909,
                read_eof_negative: 941,
                read_eof_failure: 951,
                write_exact: 960,
                write_exact_loop: 966,
                write_exact_negative: 1_019,
                write_exact_failure: 1_029,
                mmap_syscall: 238,
                mprotect_syscall: 362,
                success_munmap_syscall: 626,
                cleanup_munmap_syscall: 810,
                write_syscall: 991,
                mapping_store: 325,
                target_call_displacement: 424,
                unknown_tag_displacement: 465,
                return_reserved_displacement: 482,
                noncanonical_nan_displacement: 561,
                bounds_word_0_displacement: 581,
                bounds_word_1_displacement: 593,
            },
        }
    }

    fn offset(value: u32) -> usize {
        usize::try_from(value).expect("frozen startup offset fits usize")
    }

    fn assert_label(
        template: &X64StandaloneStartupTemplate,
        label: X64StandaloneStartupLabel,
        expected_offset: u32,
    ) {
        let matches: Vec<_> = template
            .labels()
            .iter()
            .filter(|receipt| receipt.label() == label)
            .collect();
        assert_eq!(matches.len(), 1, "{label:?} must have one receipt");
        assert_eq!(matches[0].code_offset(), expected_offset, "{label:?}");
    }

    fn assert_bytes_at(template: &X64StandaloneStartupTemplate, at: u32, expected: &[u8]) {
        let start = offset(at);
        let end = start
            .checked_add(expected.len())
            .expect("bounded expected slice");
        assert_eq!(template.code().get(start..end), Some(expected), "at {at}");
    }

    fn assert_conditional(
        template: &X64StandaloneStartupTemplate,
        displacement_offset: u32,
        condition_opcode: u8,
        target: X64StandaloneStartupLabel,
    ) {
        let matches: Vec<_> = template
            .fixups()
            .iter()
            .filter(|fixup| fixup.displacement_offset() == displacement_offset)
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "conditional at {displacement_offset} must be unique"
        );
        let fixup = matches[0];
        assert_eq!(fixup.kind(), X64StandaloneStartupFixupKind::ConditionalJump);
        assert_eq!(
            fixup.target(),
            X64StandaloneStartupFixupTarget::Label(target)
        );
        assert_eq!(fixup.next_instruction_offset(), displacement_offset + 4);
        let opcode_offset = displacement_offset
            .checked_sub(2)
            .expect("conditional opcode precedes rel32");
        assert_bytes_at(template, opcode_offset, &[0x0f, condition_opcode]);
    }

    fn assert_jump(
        template: &X64StandaloneStartupTemplate,
        displacement_offset: u32,
        target: X64StandaloneStartupLabel,
    ) {
        let matches: Vec<_> = template
            .fixups()
            .iter()
            .filter(|fixup| fixup.displacement_offset() == displacement_offset)
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "jump at {displacement_offset} must be unique"
        );
        let fixup = matches[0];
        assert_eq!(fixup.kind(), X64StandaloneStartupFixupKind::Jump);
        assert_eq!(
            fixup.target(),
            X64StandaloneStartupFixupTarget::Label(target)
        );
        assert_eq!(fixup.next_instruction_offset(), displacement_offset + 4);
        assert_bytes_at(
            template,
            displacement_offset
                .checked_sub(1)
                .expect("jump opcode precedes rel32"),
            &[0xe9],
        );
    }

    fn assert_syscall(
        template: &X64StandaloneStartupTemplate,
        receipt_index: usize,
        number: u32,
        opcode_offset: u32,
    ) {
        let receipt = template
            .syscalls()
            .get(receipt_index)
            .expect("frozen syscall receipt");
        assert_eq!(receipt.number(), number);
        assert_eq!(receipt.opcode_offset(), opcode_offset);
        assert_bytes_at(template, opcode_offset, &[0x0f, 0x05]);
    }

    #[test]
    fn verifier_owned_full_byte_tables_match_both_frozen_profiles() {
        for profile in [
            X64StandaloneProfile::BranchMix,
            X64StandaloneProfile::Bounds,
        ] {
            let template = encode_x64_standalone_startup_raw(profile, TARGET_ENTRY)
                .expect("startup must encode");
            let expected = canonical_startup_bytes(profile);
            assert_eq!(expected.len(), canonical_structural_facts(profile).0);
            assert_eq!(template.code(), expected);
            assert_eq!(sha256(expected), canonical_startup_digest(profile));
        }
    }

    #[test]
    fn independent_verifier_rejects_every_single_byte_mutation() {
        for profile in [
            X64StandaloneProfile::BranchMix,
            X64StandaloneProfile::Bounds,
        ] {
            let template = encode_x64_standalone_startup_raw(profile, TARGET_ENTRY)
                .expect("startup must encode");
            for offset in 0..template.code().len() {
                let mut mutated = template.code().to_vec();
                mutated[offset] ^= 1;
                assert!(
                    independently_verify_x64_standalone_startup_raw_r1_s8(
                        &mutated,
                        &template,
                        profile,
                        TARGET_ENTRY,
                    )
                    .is_err(),
                    "{profile:?} one-byte mutation at {offset} must fail closed"
                );
            }
        }
    }

    #[test]
    fn raw_startup_encoding_is_deterministic_and_baked_per_profile() {
        let first =
            encode_x64_standalone_startup_raw(X64StandaloneProfile::BranchMix, TARGET_ENTRY)
                .expect("BranchMix startup must encode");
        let second =
            encode_x64_standalone_startup_raw(X64StandaloneProfile::BranchMix, TARGET_ENTRY)
                .expect("BranchMix startup must reproduce");
        let bounds = encode_x64_standalone_startup_raw(X64StandaloneProfile::Bounds, TARGET_ENTRY)
            .expect("Bounds startup must encode");

        assert_eq!(first, second);
        assert_ne!(first.code(), bounds.code());
        assert_eq!(first.profile(), X64StandaloneProfile::BranchMix);
        assert_eq!(bounds.profile(), X64StandaloneProfile::Bounds);
    }

    #[test]
    fn independent_structural_verifier_accepts_both_locked_profiles() {
        for profile in [
            X64StandaloneProfile::BranchMix,
            X64StandaloneProfile::Bounds,
        ] {
            let template = encode_x64_standalone_startup_raw(profile, TARGET_ENTRY)
                .expect("startup must encode");
            let verified = independently_verify_x64_standalone_startup_raw_r1_s8(
                template.code(),
                &template,
                profile,
                TARGET_ENTRY,
            )
            .expect("canonical startup must verify structurally");
            assert_eq!(verified.code(), template.code());
            assert_eq!(verified.profile(), profile);
            assert_eq!(verified.target_entry_vaddr(), TARGET_ENTRY);
            assert_eq!(verified.label_count(), 32);
            assert_eq!(
                verified.fixup_count(),
                match profile {
                    X64StandaloneProfile::BranchMix => 58,
                    X64StandaloneProfile::Bounds => 59,
                }
            );
            assert_eq!(verified.syscall_site_count(), 8);
        }
    }

    #[test]
    fn independent_verifier_rejects_noncanonical_placement_before_digest() {
        let wrong_but_bounded_target = TARGET_ENTRY + 16;
        let template = encode_x64_standalone_startup_raw(
            X64StandaloneProfile::BranchMix,
            wrong_but_bounded_target,
        )
        .expect("raw emitter admits provisional bounded placement");
        assert!(matches!(
            independently_verify_x64_standalone_startup_raw_r1_s8(
                template.code(),
                &template,
                X64StandaloneProfile::BranchMix,
                wrong_but_bounded_target,
            ),
            Err(X64StandaloneStartupVerifyError::TargetEntry {
                expected: X64_STANDALONE_CANONICAL_TARGET_ENTRY_VADDR,
                actual,
            }) if actual == wrong_but_bounded_target
        ));
    }

    #[test]
    fn independent_verifier_decodes_fixups_instead_of_trusting_the_receipt() {
        let template =
            encode_x64_standalone_startup_raw(X64StandaloneProfile::BranchMix, TARGET_ENTRY)
                .expect("startup must encode");

        let mut displacement_mutation = template.code().to_vec();
        let displacement_offset =
            usize::try_from(template.fixups()[0].displacement_offset()).expect("offset fits");
        displacement_mutation[displacement_offset] ^= 1;
        assert!(matches!(
            independently_verify_x64_standalone_startup_raw_r1_s8(
                &displacement_mutation,
                &template,
                X64StandaloneProfile::BranchMix,
                TARGET_ENTRY,
            ),
            Err(X64StandaloneStartupVerifyError::FixupDisplacement { .. })
        ));

        let mut opcode_mutation = template.code().to_vec();
        let target_call = template
            .fixups()
            .iter()
            .find(|fixup| fixup.kind() == X64StandaloneStartupFixupKind::TargetCall)
            .expect("target call receipt");
        let opcode_offset = usize::try_from(target_call.displacement_offset())
            .expect("offset fits")
            .checked_sub(1)
            .expect("call opcode");
        opcode_mutation[opcode_offset] = 0xe9;
        assert!(matches!(
            independently_verify_x64_standalone_startup_raw_r1_s8(
                &opcode_mutation,
                &template,
                X64StandaloneProfile::BranchMix,
                TARGET_ENTRY,
            ),
            Err(X64StandaloneStartupVerifyError::FixupOpcode {
                kind: X64StandaloneStartupFixupKind::TargetCall,
                ..
            })
        ));

        let mut target_mutation = template.clone();
        let first = target_mutation
            .fixups
            .first_mut()
            .expect("at least one fixup");
        first.target =
            X64StandaloneStartupFixupTarget::Label(X64StandaloneStartupLabel::WriteExact);
        assert!(matches!(
            independently_verify_x64_standalone_startup_raw_r1_s8(
                target_mutation.code(),
                &target_mutation,
                X64StandaloneProfile::BranchMix,
                TARGET_ENTRY,
            ),
            Err(X64StandaloneStartupVerifyError::FixupResolution { .. })
        ));
    }

    #[test]
    fn independent_verifier_rejects_unsorted_or_out_of_range_receipt_positions() {
        let template =
            encode_x64_standalone_startup_raw(X64StandaloneProfile::Bounds, TARGET_ENTRY)
                .expect("startup must encode");

        let mut label_order = template.clone();
        label_order.labels.swap(0, 1);
        assert!(matches!(
            independently_verify_x64_standalone_startup_raw_r1_s8(
                label_order.code(),
                &label_order,
                X64StandaloneProfile::Bounds,
                TARGET_ENTRY,
            ),
            Err(X64StandaloneStartupVerifyError::PositionOrder { field: "label", .. })
        ));

        let mut fixup_order = template.clone();
        fixup_order.fixups.swap(0, 1);
        assert!(matches!(
            independently_verify_x64_standalone_startup_raw_r1_s8(
                fixup_order.code(),
                &fixup_order,
                X64StandaloneProfile::Bounds,
                TARGET_ENTRY,
            ),
            Err(X64StandaloneStartupVerifyError::PositionOrder {
                field: "fixup displacement",
                ..
            })
        ));

        let mut syscall_range = template.clone();
        syscall_range.syscalls[0].opcode_offset = u32::MAX;
        assert!(matches!(
            independently_verify_x64_standalone_startup_raw_r1_s8(
                syscall_range.code(),
                &syscall_range,
                X64StandaloneProfile::Bounds,
                TARGET_ENTRY,
            ),
            Err(X64StandaloneStartupVerifyError::PositionRange {
                field: "syscall opcode",
                ..
            })
        ));
    }

    #[test]
    fn independent_verifier_binds_exact_syscall_sites_and_all_other_bytes() {
        let template =
            encode_x64_standalone_startup_raw(X64StandaloneProfile::BranchMix, TARGET_ENTRY)
                .expect("startup must encode");

        let mut syscall_opcode = template.code().to_vec();
        let first_syscall =
            usize::try_from(template.syscalls()[0].opcode_offset()).expect("offset fits");
        syscall_opcode[first_syscall + 1] = 0x04;
        assert!(matches!(
            independently_verify_x64_standalone_startup_raw_r1_s8(
                &syscall_opcode,
                &template,
                X64StandaloneProfile::BranchMix,
                TARGET_ENTRY,
            ),
            Err(X64StandaloneStartupVerifyError::SyscallOpcode { .. })
        ));

        let mut unrecorded_syscall = template.code().to_vec();
        unrecorded_syscall[0..2].copy_from_slice(&[0x0f, 0x05]);
        assert!(matches!(
            independently_verify_x64_standalone_startup_raw_r1_s8(
                &unrecorded_syscall,
                &template,
                X64StandaloneProfile::BranchMix,
                TARGET_ENTRY,
            ),
            Err(X64StandaloneStartupVerifyError::UnrecordedSyscall { offset: 0 })
        ));

        let mut ordinary_instruction = template.code().to_vec();
        ordinary_instruction[0] ^= 1;
        assert!(matches!(
            independently_verify_x64_standalone_startup_raw_r1_s8(
                &ordinary_instruction,
                &template,
                X64StandaloneProfile::BranchMix,
                TARGET_ENTRY,
            ),
            Err(X64StandaloneStartupVerifyError::CanonicalCodeMismatch { offset: 0 })
        ));
    }

    #[test]
    fn receipt_resolves_exactly_one_target_call() {
        let template =
            encode_x64_standalone_startup_raw(X64StandaloneProfile::BranchMix, TARGET_ENTRY)
                .expect("startup must encode");
        let target_fixups: Vec<_> = template
            .fixups()
            .iter()
            .filter(|fixup| fixup.kind() == X64StandaloneStartupFixupKind::TargetCall)
            .collect();
        assert_eq!(target_fixups.len(), 1);

        let patch = template.target_call();
        let displacement_offset =
            usize::try_from(patch.displacement_offset()).expect("u32 fits usize");
        let next_offset = usize::try_from(patch.next_instruction_offset()).expect("u32 fits usize");
        assert_eq!(
            template
                .code()
                .get(displacement_offset.checked_sub(1).expect("call opcode")),
            Some(&0xe8)
        );
        assert_eq!(
            template
                .code()
                .get(displacement_offset..displacement_offset + 4),
            Some(patch.displacement().to_le_bytes().as_slice())
        );
        let resolved = i128::from(X64_STANDALONE_STARTUP_VADDR)
            + i128::try_from(next_offset).expect("offset fits")
            + i128::from(patch.displacement());
        assert_eq!(resolved, i128::from(TARGET_ENTRY));
        assert_eq!(patch.target_entry_vaddr(), TARGET_ENTRY);
    }

    #[test]
    fn raw_startup_stays_inside_all_local_hard_limits() {
        for profile in [
            X64StandaloneProfile::BranchMix,
            X64StandaloneProfile::Bounds,
        ] {
            let template = encode_x64_standalone_startup_raw(profile, TARGET_ENTRY)
                .expect("startup must encode");
            let (expected_code_bytes, expected_fixups) = match profile {
                X64StandaloneProfile::BranchMix => (1_032, 58),
                X64StandaloneProfile::Bounds => (1_038, 59),
            };
            assert_eq!(template.code().len(), expected_code_bytes);
            assert_eq!(template.label_count(), 32);
            assert_eq!(template.fixup_count(), expected_fixups);
            assert!(template.code().len() <= X64_STANDALONE_STARTUP_MAX_CODE_BYTES);
            assert!(template.labels().len() <= X64_STANDALONE_STARTUP_MAX_LABELS);
            assert!(template.fixups().len() <= X64_STANDALONE_STARTUP_MAX_FIXUPS);
            assert_eq!(template.label_count(), template.labels().len());
            assert_eq!(template.fixup_count(), template.fixups().len());
            assert_eq!(template.stack_frame_bytes(), STARTUP_STACK_FRAME_BYTES);
            assert!(
                template.worst_case_stack_reach_bytes() <= X64_STANDALONE_STARTUP_MAX_STACK_BYTES
            );
            assert_eq!(template.syscall_numbers(), [0, 1, 9, 10, 11, 231]);
            assert_eq!(template.syscall_sites(), [2, 1, 1, 1, 2, 1]);
            assert_eq!(template.syscall_site_count(), 8);
            assert_eq!(template.internal_call_count(), 4);
            assert_eq!(template.target_call_count(), 1);
            assert!(template
                .labels()
                .windows(2)
                .all(|pair| pair[0].code_offset() <= pair[1].code_offset()));
        }
    }

    #[test]
    fn target_entry_must_be_in_the_bounded_image_after_startup() {
        let at_start = encode_x64_standalone_startup_raw(
            X64StandaloneProfile::Bounds,
            X64_STANDALONE_STARTUP_VADDR,
        );
        assert!(matches!(
            at_start,
            Err(X64StandaloneStartupEncodeError::InvalidTargetEntry { .. })
        ));

        let image_end = X64_STANDALONE_IMAGE_BASE + X64_STANDALONE_MAX_IMAGE_BYTES;
        let at_end = encode_x64_standalone_startup_raw(X64StandaloneProfile::Bounds, image_end);
        assert!(matches!(
            at_end,
            Err(X64StandaloneStartupEncodeError::InvalidTargetEntry { .. })
        ));
    }

    #[test]
    fn raw_startup_validates_canonical_nan_without_rejecting_finite_sentinel_bits() {
        let template =
            encode_x64_standalone_startup_raw(X64StandaloneProfile::BranchMix, TARGET_ENTRY)
                .expect("startup must encode");
        let mut canonical_nan_check = Vec::with_capacity(19);
        canonical_nan_check.extend_from_slice(&[0x48, 0xb8]); // movabs rax, imm64
        canonical_nan_check.extend_from_slice(&CANONICAL_NAN_BITS.to_le_bytes());
        canonical_nan_check.extend_from_slice(&[0x49, 0x39, 0xc0, 0x0f, 0x85]);
        assert_eq!(
            template
                .code()
                .windows(canonical_nan_check.len())
                .filter(|window| *window == canonical_nan_check)
                .count(),
            1
        );

        let mut sentinel_rejection = Vec::with_capacity(13);
        sentinel_rejection.extend_from_slice(&[0x48, 0xb8]);
        sentinel_rejection.extend_from_slice(&OUTPUT_SENTINEL.to_le_bytes());
        sentinel_rejection.extend_from_slice(&[0x49, 0x39, 0xc0]);
        assert!(!template
            .code()
            .windows(sentinel_rejection.len())
            .any(|window| window == sentinel_rejection));
        assert!(template
            .code()
            .windows(7)
            .any(|window| window == [0x49, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff]));
    }

    #[test]
    fn argc_admission_is_exactly_one_and_extra_argv_routes_to_input_reject() {
        for profile in [
            X64StandaloneProfile::BranchMix,
            X64StandaloneProfile::Bounds,
        ] {
            let template = encode_x64_standalone_startup_raw(profile, TARGET_ENTRY)
                .expect("startup must encode");
            let positions = critical_offsets(profile);

            // xor r12d,r12d; xor r15d,r15d; cmp qword [rsp],1; jne InputReject.
            // This is structural byte evidence. A process fixture still owns
            // the claim that a real kernel entry with argv[1] is rejected.
            assert_bytes_at(
                &template,
                0,
                &[
                    0x45, 0x31, 0xe4, 0x45, 0x31, 0xff, 0x48, 0x83, 0x3c, 0x24, 0x01,
                ],
            );
            assert_conditional(&template, 13, 0x85, X64StandaloneStartupLabel::InputReject);
            assert_label(
                &template,
                X64StandaloneStartupLabel::InputReject,
                positions.input_reject,
            );
            assert_bytes_at(&template, positions.input_reject, &[0xbd, 64, 0, 0, 0]);
            assert_jump(
                &template,
                positions.input_reject + 6,
                X64StandaloneStartupLabel::CleanupExit,
            );
        }
    }

    #[test]
    fn memory_syscall_error_edges_are_exact_and_fail_closed() {
        for profile in [
            X64StandaloneProfile::BranchMix,
            X64StandaloneProfile::Bounds,
        ] {
            let template = encode_x64_standalone_startup_raw(profile, TARGET_ENTRY)
                .expect("startup must encode");
            let positions = critical_offsets(profile);

            assert_syscall(&template, 0, SYSCALL_MMAP, positions.mmap_syscall);
            assert_bytes_at(
                &template,
                positions.mmap_syscall + 2,
                &[0x48, 0x3d, 0x01, 0xf0, 0xff, 0xff],
            );
            assert_conditional(
                &template,
                positions.mmap_syscall + 10,
                0x83,
                X64StandaloneStartupLabel::MemoryReject,
            );

            assert_syscall(&template, 1, SYSCALL_MPROTECT, positions.mprotect_syscall);
            assert_bytes_at(
                &template,
                positions.mprotect_syscall + 2,
                &[0x48, 0x85, 0xc0],
            );
            assert_conditional(
                &template,
                positions.mprotect_syscall + 7,
                0x85,
                X64StandaloneStartupLabel::MemoryReject,
            );

            assert_syscall(
                &template,
                2,
                SYSCALL_MUNMAP,
                positions.success_munmap_syscall,
            );
            assert_bytes_at(
                &template,
                positions.success_munmap_syscall + 2,
                &[0x48, 0x85, 0xc0],
            );
            assert_conditional(
                &template,
                positions.success_munmap_syscall + 7,
                0x85,
                X64StandaloneStartupLabel::UnmapReject,
            );

            assert_syscall(
                &template,
                3,
                SYSCALL_MUNMAP,
                positions.cleanup_munmap_syscall,
            );
            assert_bytes_at(
                &template,
                positions.cleanup_munmap_syscall + 2,
                &[0x48, 0x85, 0xc0],
            );
            assert_conditional(
                &template,
                positions.cleanup_munmap_syscall + 7,
                0x84,
                X64StandaloneStartupLabel::Exit,
            );
            assert_bytes_at(
                &template,
                positions.cleanup_munmap_syscall + 11,
                &[0xbd, 71, 0, 0, 0],
            );

            assert_label(
                &template,
                X64StandaloneStartupLabel::MemoryReject,
                positions.memory_reject,
            );
            assert_bytes_at(&template, positions.memory_reject, &[0xbd, 71, 0, 0, 0]);
            assert_jump(
                &template,
                positions.memory_reject + 6,
                X64StandaloneStartupLabel::CleanupExit,
            );
            assert_label(
                &template,
                X64StandaloneStartupLabel::UnmapReject,
                positions.unmap_reject,
            );
            assert_bytes_at(&template, positions.unmap_reject, &[0xbd, 71, 0, 0, 0]);
            assert_jump(
                &template,
                positions.unmap_reject + 6,
                X64StandaloneStartupLabel::Exit,
            );
        }
    }

    #[test]
    fn read_only_transition_precedes_target_and_no_mapping_store_follows_it() {
        const MAPPING_STORE: &[u8] = &[0x49, 0x89, 0x04, 0xcc];
        for profile in [
            X64StandaloneProfile::BranchMix,
            X64StandaloneProfile::Bounds,
        ] {
            let template = encode_x64_standalone_startup_raw(profile, TARGET_ENTRY)
                .expect("startup must encode");
            let positions = critical_offsets(profile);

            assert_label(
                &template,
                X64StandaloneStartupLabel::PayloadConverted,
                positions.payload_converted,
            );
            let mapping_store_offsets: Vec<_> = template
                .code()
                .windows(MAPPING_STORE.len())
                .enumerate()
                .filter_map(|(at, bytes)| (bytes == MAPPING_STORE).then_some(at))
                .collect();
            assert_eq!(mapping_store_offsets, [offset(positions.mapping_store)]);
            assert!(positions.mapping_store < positions.payload_converted);

            // Empty input has no mapping and jumps directly to CallReady.
            assert_conditional(
                &template,
                positions.payload_converted + 5,
                0x84,
                X64StandaloneStartupLabel::CallReady,
            );

            // Non-empty input falls through the exact mprotect(..., PROT_READ)
            // sequence. Only a zero return reaches the immediately following
            // CallReady label.
            assert_bytes_at(
                &template,
                positions.payload_converted + 9,
                &[
                    0xb8, 10, 0, 0, 0, 0x4c, 0x89, 0xe7, 0x4c, 0x89, 0xee, 0xba, 1, 0, 0, 0,
                ],
            );
            assert_syscall(&template, 1, SYSCALL_MPROTECT, positions.mprotect_syscall);
            assert_conditional(
                &template,
                positions.mprotect_syscall + 7,
                0x85,
                X64StandaloneStartupLabel::MemoryReject,
            );
            assert_label(
                &template,
                X64StandaloneStartupLabel::CallReady,
                positions.call_ready,
            );
            assert_eq!(
                positions.call_ready,
                positions.mprotect_syscall + 11,
                "CallReady must be the mprotect-success fallthrough"
            );

            let target_call = template
                .fixups()
                .iter()
                .find(|fixup| fixup.displacement_offset() == positions.target_call_displacement)
                .expect("frozen target call");
            assert_eq!(
                target_call.kind(),
                X64StandaloneStartupFixupKind::TargetCall
            );
            assert_eq!(
                target_call.target(),
                X64StandaloneStartupFixupTarget::TargetEntry {
                    vaddr: TARGET_ENTRY
                }
            );
            assert!(positions.target_call_displacement > positions.call_ready);
            assert!(template.code()[offset(positions.payload_converted)..]
                .windows(MAPPING_STORE.len())
                .all(|bytes| bytes != MAPPING_STORE));
        }
    }

    #[test]
    fn canonical_output_is_built_and_written_only_after_required_unmap() {
        for profile in [
            X64StandaloneProfile::BranchMix,
            X64StandaloneProfile::Bounds,
        ] {
            let template = encode_x64_standalone_startup_raw(profile, TARGET_ENTRY)
                .expect("startup must encode");
            let positions = critical_offsets(profile);

            assert_label(
                &template,
                X64StandaloneStartupLabel::ResultValidated,
                positions.result_validated,
            );
            assert_bytes_at(&template, positions.result_validated, &[0x4d, 0x85, 0xff]);
            assert_conditional(
                &template,
                positions.result_validated + 5,
                0x84,
                X64StandaloneStartupLabel::BuildOutput,
            );

            // A present mapping must take this fallthrough unmap. Failure
            // cannot reach BuildOutput; success clears the presence flag and
            // falls into BuildOutput.
            assert_syscall(
                &template,
                2,
                SYSCALL_MUNMAP,
                positions.success_munmap_syscall,
            );
            assert_conditional(
                &template,
                positions.success_munmap_syscall + 7,
                0x85,
                X64StandaloneStartupLabel::UnmapReject,
            );
            assert_bytes_at(
                &template,
                positions.success_munmap_syscall + 11,
                &[0x45, 0x31, 0xff],
            );
            assert_label(
                &template,
                X64StandaloneStartupLabel::BuildOutput,
                positions.build_output,
            );
            assert_eq!(
                positions.build_output,
                positions.success_munmap_syscall + 14
            );

            let mut output_prefix = Vec::with_capacity(15);
            output_prefix.extend_from_slice(&[0x48, 0xb8]);
            output_prefix.extend_from_slice(&u64::from_le_bytes(*b"NAUXGBO1").to_le_bytes());
            output_prefix.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, OUTPUT_FRAME_OFFSET]);
            assert_bytes_at(&template, positions.build_output, &output_prefix);

            let write_call_displacement = positions.build_output + 78;
            let write_call = template
                .fixups()
                .iter()
                .find(|fixup| fixup.displacement_offset() == write_call_displacement)
                .expect("frozen WriteExact call");
            assert_eq!(
                write_call.kind(),
                X64StandaloneStartupFixupKind::InternalCall
            );
            assert_eq!(
                write_call.target(),
                X64StandaloneStartupFixupTarget::Label(X64StandaloneStartupLabel::WriteExact)
            );
            assert_label(
                &template,
                X64StandaloneStartupLabel::WriteExact,
                positions.write_exact,
            );
            assert_syscall(&template, 7, SYSCALL_WRITE, positions.write_syscall);
            assert!(positions.success_munmap_syscall < positions.build_output);
            assert!(positions.build_output < write_call_displacement);
            assert!(write_call_displacement < positions.write_syscall);
        }
    }

    #[test]
    fn syscall_helper_errors_and_native_result_grammar_are_structurally_fail_closed() {
        for profile in [
            X64StandaloneProfile::BranchMix,
            X64StandaloneProfile::Bounds,
        ] {
            let template = encode_x64_standalone_startup_raw(profile, TARGET_ENTRY)
                .expect("startup must encode");
            let positions = critical_offsets(profile);

            assert_label(
                &template,
                X64StandaloneStartupLabel::ReadExact,
                positions.read_exact,
            );
            assert_label(
                &template,
                X64StandaloneStartupLabel::ReadExactLoop,
                positions.read_exact_loop,
            );
            assert_conditional(
                &template,
                positions.read_exact_loop + 5,
                0x84,
                X64StandaloneStartupLabel::ReadExactSuccess,
            );
            assert_conditional(
                &template,
                positions.read_exact_loop + 26,
                0x84,
                X64StandaloneStartupLabel::ReadExactFailure,
            );
            assert_conditional(
                &template,
                positions.read_exact_loop + 32,
                0x88,
                X64StandaloneStartupLabel::ReadExactNegative,
            );
            assert_label(
                &template,
                X64StandaloneStartupLabel::ReadExactNegative,
                positions.read_exact_negative,
            );
            assert_bytes_at(
                &template,
                positions.read_exact_negative,
                &[0x48, 0x83, 0xf8, 0xfc],
            );
            assert_conditional(
                &template,
                positions.read_exact_negative + 6,
                0x84,
                X64StandaloneStartupLabel::ReadExactLoop,
            );
            assert_label(
                &template,
                X64StandaloneStartupLabel::ReadExactFailure,
                positions.read_exact_failure,
            );
            assert_bytes_at(
                &template,
                positions.read_exact_failure,
                &[0xb8, 1, 0, 0, 0, 0xc3],
            );

            assert_label(
                &template,
                X64StandaloneStartupLabel::ReadEof,
                positions.read_eof,
            );
            assert_conditional(
                &template,
                positions.read_eof + 16,
                0x84,
                X64StandaloneStartupLabel::ReadEofSuccess,
            );
            assert_conditional(
                &template,
                positions.read_eof + 22,
                0x88,
                X64StandaloneStartupLabel::ReadEofNegative,
            );
            assert_label(
                &template,
                X64StandaloneStartupLabel::ReadEofNegative,
                positions.read_eof_negative,
            );
            assert_bytes_at(
                &template,
                positions.read_eof_negative,
                &[0x48, 0x83, 0xf8, 0xfc],
            );
            assert_conditional(
                &template,
                positions.read_eof_negative + 6,
                0x84,
                X64StandaloneStartupLabel::ReadEof,
            );
            assert_label(
                &template,
                X64StandaloneStartupLabel::ReadEofFailure,
                positions.read_eof_failure,
            );
            assert_bytes_at(
                &template,
                positions.read_eof_failure,
                &[0xb8, 2, 0, 0, 0, 0xc3],
            );

            assert_label(
                &template,
                X64StandaloneStartupLabel::WriteExact,
                positions.write_exact,
            );
            assert_label(
                &template,
                X64StandaloneStartupLabel::WriteExactLoop,
                positions.write_exact_loop,
            );
            assert_conditional(
                &template,
                positions.write_exact_loop + 5,
                0x84,
                X64StandaloneStartupLabel::WriteExactSuccess,
            );
            assert_conditional(
                &template,
                positions.write_exact_loop + 32,
                0x84,
                X64StandaloneStartupLabel::WriteExactFailure,
            );
            assert_conditional(
                &template,
                positions.write_exact_loop + 38,
                0x88,
                X64StandaloneStartupLabel::WriteExactNegative,
            );
            assert_label(
                &template,
                X64StandaloneStartupLabel::WriteExactNegative,
                positions.write_exact_negative,
            );
            assert_conditional(
                &template,
                positions.write_exact_negative + 6,
                0x84,
                X64StandaloneStartupLabel::WriteExactLoop,
            );
            assert_label(
                &template,
                X64StandaloneStartupLabel::WriteExactFailure,
                positions.write_exact_failure,
            );
            assert_bytes_at(
                &template,
                positions.write_exact_failure,
                &[0xb8, 1, 0, 0, 0, 0xc3],
            );

            // Unknown native outcome tags, Return payload reserved-word
            // violations, noncanonical NaNs, and nonzero Bounds payload words
            // all converge on InvariantReject.
            assert_jump(
                &template,
                positions.unknown_tag_displacement,
                X64StandaloneStartupLabel::InvariantReject,
            );
            for displacement in [
                positions.return_reserved_displacement,
                positions.noncanonical_nan_displacement,
                positions.bounds_word_0_displacement,
                positions.bounds_word_1_displacement,
            ] {
                assert_conditional(
                    &template,
                    displacement,
                    0x85,
                    X64StandaloneStartupLabel::InvariantReject,
                );
            }
            assert_label(
                &template,
                X64StandaloneStartupLabel::InvariantReject,
                positions.invariant_reject,
            );
            assert_bytes_at(&template, positions.invariant_reject, &[0xbd, 70, 0, 0, 0]);
            assert_jump(
                &template,
                positions.invariant_reject + 6,
                X64StandaloneStartupLabel::CleanupExit,
            );
            assert_label(
                &template,
                X64StandaloneStartupLabel::CleanupExit,
                positions.cleanup_exit,
            );
            assert_label(&template, X64StandaloneStartupLabel::Exit, positions.exit);
        }
    }
}
