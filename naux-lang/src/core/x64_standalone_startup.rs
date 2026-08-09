//! Canonical typed startup plan for the R1-S8 standalone x86-64 image.
//!
//! This module deliberately separates planning authority from byte emission.
//! The plan is derived only from an opaque source-bound R1-S7a target and the
//! frozen R1-S8 profile. It contains no caller-selected syscall, descriptor,
//! address, helper, or fallback edge.
//!
//! The executable encoder is a separate raw layer. This module binds its exact
//! receipt and bytes to the typed plan and live opaque upstream authority
//! before either can enter an artifact composer.

use super::corevm0_gate_a::{COREVM0_GATE_A_BOUNDS_CASES, COREVM0_GATE_A_TOTAL_CASES};
use super::encoding::sha256;
use super::machine_ir::MachineType;
use super::schema::SemanticHash;
use super::x64_gate_b_candidate_standalone_authority::X64GateBPolicy15StandaloneAuthority;
use super::x64_standalone_authority::{X64StandaloneAuthorityBinding, X64StandaloneSeedAuthority};
use super::x64_standalone_protocol::{
    X64StandaloneProfile, X64_STANDALONE_CANONICAL_NAN_BITS, X64_STANDALONE_INPUT_MAGIC,
    X64_STANDALONE_MAX_ARRAY_ELEMENTS, X64_STANDALONE_MAX_INPUT_BYTES,
    X64_STANDALONE_MAX_PAYLOAD_BYTES, X64_STANDALONE_OUTPUT_BYTES, X64_STANDALONE_OUTPUT_MAGIC,
    X64_STANDALONE_PROTOCOL_VERSION,
};
use super::x64_standalone_startup_raw::{
    encode_x64_standalone_startup_raw, independently_verify_x64_standalone_startup_raw_r1_s8,
    IndependentlyVerifiedX64StandaloneStartupRaw, X64StandaloneStartupEncodeError,
    X64StandaloneStartupTemplate, X64StandaloneStartupVerifyError,
};
use super::x64_target::{X64AbiRegister, X64EntryAbi, X64TargetAbi};
use std::fmt;

pub const X64_STANDALONE_STARTUP_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_STANDALONE_STARTUP_PLANNER_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_STANDALONE_STARTUP_LOWERING_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_STANDALONE_STARTUP_ENCODER_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_STANDALONE_IO_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_STANDALONE_IO_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);

pub const X64_STANDALONE_STARTUP_MAX_OPS: u32 = 64;
pub const X64_STANDALONE_STARTUP_MAX_LABELS: u32 = 128;
pub const X64_STANDALONE_STARTUP_MAX_FIXUPS: u32 = 128;
pub const X64_STANDALONE_STARTUP_MAX_CODE_BYTES: u32 = 32_768;
pub const X64_STANDALONE_STARTUP_MAX_STACK_BYTES: u32 = 512;
pub const X64_STANDALONE_STARTUP_TARGET_CALL_FIXUPS: u32 = 1;

pub const X64_STANDALONE_ELF_BASE: u64 = 0x0040_0000;
pub const X64_STANDALONE_STARTUP_OFFSET: u64 = 0x0100;
pub const X64_STANDALONE_STARTUP_ENTRY_VADDR: u64 =
    X64_STANDALONE_ELF_BASE + X64_STANDALONE_STARTUP_OFFSET;
pub const X64_STANDALONE_MAX_ELF_IMAGE_BYTES: u64 = 67_174_400;
pub const X64_STANDALONE_TARGET_ALIGNMENT: u64 = 16;

pub const X64_STANDALONE_EXIT_SUCCESS: u8 = 0;
pub const X64_STANDALONE_EXIT_INPUT: u8 = 64;
pub const X64_STANDALONE_EXIT_INVARIANT: u8 = 70;
pub const X64_STANDALONE_EXIT_MEMORY: u8 = 71;
pub const X64_STANDALONE_EXIT_IO: u8 = 74;

const STARTUP_PLAN_DOMAIN: &[u8] = b"NAUX:x86-64:r1-s8:startup:plan:v1\0";
const STARTUP_CODE_DOMAIN: &[u8] = b"NAUX:x86-64:r1-s8:startup:code:v1\0";
const IO_CONTRACT_DOMAIN: &[u8] = b"NAUX:x86-64:r1-s8:io-contract:v1\0";

const INPUT_HEADER_BYTES: u32 = 40;
const EOF_PROBE_BYTES: u32 = 1;
const STARTUP_OUTPUT_SENTINEL: u64 = 0xa5c3_d7e9_1b2f_4068;
const STARTUP_STACK_FRAME_BYTES: u32 = 160;
const STARTUP_STACK_WORST_REACH_BYTES: u32 = 183;
const REQUIRED_ARGC: u64 = 1;
const ARRAY_WORD_BYTES: u32 = 8;
const RETURN_F64_OUTCOME_TAG: u32 = 0;
const BOUNDS_OUTCOME_TAG: u32 = 1;

const SYS_READ: u32 = 0;
const SYS_WRITE: u32 = 1;
const SYS_MMAP: u32 = 9;
const SYS_MPROTECT: u32 = 10;
const SYS_MUNMAP: u32 = 11;
const SYS_EXIT_GROUP: u32 = 231;
const STDIN_FD: u32 = 0;
const STDOUT_FD: u32 = 1;
const PROT_READ: u32 = 0x1;
const PROT_WRITE: u32 = 0x2;
const MAP_PRIVATE: u32 = 0x02;
const MAP_ANONYMOUS: u32 = 0x20;
const RAW_SYSCALL_ERROR_FLOOR: i64 = -4095;
const RAW_EINTR_RETURN: i64 = -4;

/// Complete immutable hard-limit vector used by startup planning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64StandaloneStartupLimits {
    max_ops: u32,
    max_labels: u32,
    max_fixups: u32,
    max_code_bytes: u32,
    max_stack_bytes: u32,
    target_call_fixups: u32,
}

impl X64StandaloneStartupLimits {
    pub const fn r1_s8() -> Self {
        Self {
            max_ops: X64_STANDALONE_STARTUP_MAX_OPS,
            max_labels: X64_STANDALONE_STARTUP_MAX_LABELS,
            max_fixups: X64_STANDALONE_STARTUP_MAX_FIXUPS,
            max_code_bytes: X64_STANDALONE_STARTUP_MAX_CODE_BYTES,
            max_stack_bytes: X64_STANDALONE_STARTUP_MAX_STACK_BYTES,
            target_call_fixups: X64_STANDALONE_STARTUP_TARGET_CALL_FIXUPS,
        }
    }

    pub const fn max_ops(self) -> u32 {
        self.max_ops
    }

    pub const fn max_labels(self) -> u32 {
        self.max_labels
    }

    pub const fn max_fixups(self) -> u32 {
        self.max_fixups
    }

    pub const fn max_code_bytes(self) -> u32 {
        self.max_code_bytes
    }

    pub const fn max_stack_bytes(self) -> u32 {
        self.max_stack_bytes
    }
}

/// Exact bounded usage of one typed startup plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64StandaloneStartupUsage {
    ops: u32,
    labels: u32,
    fixups: u32,
    internal_call_fixups: u32,
    target_call_fixups: u32,
    syscall_sites: u32,
    code_bytes: u32,
    stack_bytes: u32,
}

impl X64StandaloneStartupUsage {
    pub const fn ops(self) -> u32 {
        self.ops
    }

    pub const fn labels(self) -> u32 {
        self.labels
    }

    pub const fn fixups(self) -> u32 {
        self.fixups
    }

    pub const fn target_call_fixups(self) -> u32 {
        self.target_call_fixups
    }

    pub const fn internal_call_fixups(self) -> u32 {
        self.internal_call_fixups
    }

    pub const fn syscall_sites(self) -> u32 {
        self.syscall_sites
    }

    pub const fn code_bytes(self) -> u32 {
        self.code_bytes
    }

    pub const fn stack_bytes(self) -> u32 {
        self.stack_bytes
    }
}

/// Non-overlapping stack slots, expressed as offsets below the reserved
/// startup frame base. Untrusted payload length never enters this layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64StandaloneStartupStackLayout {
    frame_bytes: u32,
    input_header_offset: u32,
    input_header_bytes: u32,
    output_frame_offset: u32,
    output_frame_bytes: u32,
    target_output_offset: u32,
    target_output_bytes: u32,
    eof_probe_offset: u32,
    eof_probe_bytes: u32,
    expected_mxcsr_offset: u32,
    observed_mxcsr_offset: u32,
}

impl X64StandaloneStartupStackLayout {
    const fn r1_s8() -> Self {
        Self {
            frame_bytes: STARTUP_STACK_FRAME_BYTES,
            input_header_offset: 0,
            input_header_bytes: INPUT_HEADER_BYTES,
            output_frame_offset: 40,
            output_frame_bytes: X64_STANDALONE_OUTPUT_BYTES as u32,
            target_output_offset: 80,
            target_output_bytes: 16,
            eof_probe_offset: 96,
            eof_probe_bytes: EOF_PROBE_BYTES,
            expected_mxcsr_offset: 116,
            observed_mxcsr_offset: 120,
        }
    }

    pub const fn frame_bytes(self) -> u32 {
        self.frame_bytes
    }
}

/// Frozen raw-syscall and I/O facts. There is no public constructor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64StandaloneStartupIoContract {
    profile: X64StandaloneProfile,
    input_magic: [u8; 8],
    output_magic: [u8; 8],
    protocol_version: (u16, u16, u16),
    required_argc: u64,
    stdin_fd: u32,
    stdout_fd: u32,
    input_header_bytes: u32,
    output_frame_bytes: u32,
    eof_probe_bytes: u32,
    max_array_elements: u64,
    max_payload_bytes: u64,
    max_input_frame_bytes: u64,
    array_word_bytes: u32,
    bounds_repetitions: i64,
    return_f64_outcome_tag: u32,
    bounds_outcome_tag: u32,
    output_reserved: u32,
    canonical_nan_bits: u64,
    target_output_sentinel: u64,
    syscall_read: u32,
    syscall_write: u32,
    syscall_mmap: u32,
    syscall_mprotect: u32,
    syscall_munmap: u32,
    syscall_exit_group: u32,
    mmap_protection: u32,
    mmap_flags: u32,
    mmap_fd: i64,
    mmap_offset: u64,
    mprotect_protection: u32,
    raw_syscall_error_floor: i64,
    raw_eintr_return: i64,
    retry_eintr: bool,
    exact_eof: bool,
    no_stderr: bool,
}

impl X64StandaloneStartupIoContract {
    const fn r1_s8(profile: X64StandaloneProfile) -> Self {
        Self {
            profile,
            input_magic: X64_STANDALONE_INPUT_MAGIC,
            output_magic: X64_STANDALONE_OUTPUT_MAGIC,
            protocol_version: X64_STANDALONE_PROTOCOL_VERSION,
            required_argc: REQUIRED_ARGC,
            stdin_fd: STDIN_FD,
            stdout_fd: STDOUT_FD,
            input_header_bytes: INPUT_HEADER_BYTES,
            output_frame_bytes: X64_STANDALONE_OUTPUT_BYTES as u32,
            eof_probe_bytes: EOF_PROBE_BYTES,
            max_array_elements: X64_STANDALONE_MAX_ARRAY_ELEMENTS,
            max_payload_bytes: X64_STANDALONE_MAX_PAYLOAD_BYTES,
            max_input_frame_bytes: X64_STANDALONE_MAX_INPUT_BYTES as u64,
            array_word_bytes: ARRAY_WORD_BYTES,
            bounds_repetitions: 0,
            return_f64_outcome_tag: RETURN_F64_OUTCOME_TAG,
            bounds_outcome_tag: BOUNDS_OUTCOME_TAG,
            output_reserved: 0,
            canonical_nan_bits: X64_STANDALONE_CANONICAL_NAN_BITS,
            target_output_sentinel: STARTUP_OUTPUT_SENTINEL,
            syscall_read: SYS_READ,
            syscall_write: SYS_WRITE,
            syscall_mmap: SYS_MMAP,
            syscall_mprotect: SYS_MPROTECT,
            syscall_munmap: SYS_MUNMAP,
            syscall_exit_group: SYS_EXIT_GROUP,
            mmap_protection: PROT_READ | PROT_WRITE,
            mmap_flags: MAP_PRIVATE | MAP_ANONYMOUS,
            mmap_fd: -1,
            mmap_offset: 0,
            mprotect_protection: PROT_READ,
            raw_syscall_error_floor: RAW_SYSCALL_ERROR_FLOOR,
            raw_eintr_return: RAW_EINTR_RETURN,
            retry_eintr: true,
            exact_eof: true,
            no_stderr: true,
        }
    }
}

/// Canonical high-level startup blocks. Each operation has one fixed semantic
/// meaning under the frozen I/O and exit policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64StandaloneStartupOp {
    AdmitProcessEntry,
    ReadHeaderExact,
    ValidateHeader,
    ValidatePayloadShape,
    MapPayloadIfNonEmpty,
    ReadPayloadExact,
    ProbeInputEof,
    ByteSwapPayloadU64InPlace,
    ProtectPayloadReadOnlyIfNonEmpty,
    EstablishCanonicalMxcsr,
    PrepareTypedTargetCall,
    CallTarget,
    ObserveAndValidateCanonicalMxcsr,
    ValidateTargetResult,
    UnmapPayloadIfNonEmpty,
    BuildCanonicalOutput,
    WriteOutputExact,
    CleanupPayloadIfMapped,
    ExitGroupThenTrap { status: u8 },
}

/// Stable plan labels, independent of Rust enum representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64StandaloneStartupLabel {
    Entry,
    ReadHeader,
    ValidateHeader,
    ValidatePayload,
    MapPayload,
    ReadPayload,
    ProbeEof,
    SwapPayload,
    ProtectPayload,
    EstablishMxcsr,
    PrepareTarget,
    CallTarget,
    ValidateMxcsr,
    ValidateTarget,
    UnmapPayload,
    BuildOutput,
    WriteOutput,
    CleanupInput,
    CleanupInvariant,
    CleanupMemory,
    CleanupIo,
    ExitSuccess,
    ExitInput,
    ExitInvariant,
    ExitMemory,
    ExitIo,
}

/// Typed branch predicate used by one internal `PcRel32` fixup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64StandaloneStartupCondition {
    ArgcMismatch,
    SyscallEintr,
    IoFailureOrTruncation,
    InputRejected,
    PayloadEmpty,
    MemoryFailure,
    TrailingInput,
    InvalidTargetResult,
    WriteRetry,
    ReadIncomplete,
    PayloadWordsRemain,
    MappingAbsent,
    NumericStateMismatch,
}

/// Every non-fallthrough control edge owned by the startup encoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64StandaloneStartupFixupKind {
    ConditionalRel32 {
        condition: X64StandaloneStartupCondition,
        target: X64StandaloneStartupLabel,
    },
    TargetCallRel32 {
        target_vaddr: u64,
    },
    UnconditionalRel32 {
        target: X64StandaloneStartupLabel,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64StandaloneStartupFixup {
    source: X64StandaloneStartupLabel,
    kind: X64StandaloneStartupFixupKind,
}

impl X64StandaloneStartupFixup {
    pub const fn source(self) -> X64StandaloneStartupLabel {
        self.source
    }

    pub const fn kind(self) -> X64StandaloneStartupFixupKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct X64StandaloneStartupBlock {
    label: X64StandaloneStartupLabel,
    operation: X64StandaloneStartupOp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct X64StandaloneStartupTarget {
    target_offset: u64,
    inherited_entry_offset: u32,
    target_entry_vaddr: u64,
    target_abi: X64TargetAbi,
    entry_abi: X64EntryAbi,
    input_lanes: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct X64StandaloneStartupLoweringReceipt {
    stack_frame_bytes: u32,
    syscall_numbers: [u32; 6],
    syscall_sites: [u16; 6],
    target_call_displacement_offset: u32,
    target_call_next_instruction_offset: u32,
    target_call_displacement: i32,
}

/// Immutable typed plan accepted by the future startup byte encoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64StandaloneStartupPlan {
    schema_version: (u16, u16, u16),
    planner_policy_version: (u16, u16, u16),
    lowering_policy_version: (u16, u16, u16),
    encoder_policy_version: (u16, u16, u16),
    io_schema_version: (u16, u16, u16),
    io_policy_version: (u16, u16, u16),
    profile: X64StandaloneProfile,
    limits: X64StandaloneStartupLimits,
    usage: X64StandaloneStartupUsage,
    stack: X64StandaloneStartupStackLayout,
    io: X64StandaloneStartupIoContract,
    io_contract_hash: SemanticHash,
    authority_binding: X64StandaloneAuthorityBinding,
    target: X64StandaloneStartupTarget,
    lowering: X64StandaloneStartupLoweringReceipt,
    blocks: Vec<X64StandaloneStartupBlock>,
    fixups: Vec<X64StandaloneStartupFixup>,
    plan_hash: SemanticHash,
}

impl X64StandaloneStartupPlan {
    pub const fn profile(&self) -> X64StandaloneProfile {
        self.profile
    }

    pub const fn limits(&self) -> X64StandaloneStartupLimits {
        self.limits
    }

    pub const fn usage(&self) -> X64StandaloneStartupUsage {
        self.usage
    }

    pub const fn stack(&self) -> X64StandaloneStartupStackLayout {
        self.stack
    }

    pub const fn io(&self) -> X64StandaloneStartupIoContract {
        self.io
    }

    pub const fn io_contract_hash(&self) -> SemanticHash {
        self.io_contract_hash
    }

    pub const fn target_offset(&self) -> u64 {
        self.target.target_offset
    }

    pub const fn inherited_entry_offset(&self) -> u32 {
        self.target.inherited_entry_offset
    }

    pub const fn target_entry_vaddr(&self) -> u64 {
        self.target.target_entry_vaddr
    }

    pub fn entry_abi(&self) -> &X64EntryAbi {
        &self.target.entry_abi
    }

    pub const fn input_lanes(&self) -> u8 {
        self.target.input_lanes
    }

    pub fn operations(&self) -> impl ExactSizeIterator<Item = X64StandaloneStartupOp> + '_ {
        self.blocks.iter().map(|block| block.operation)
    }

    pub fn labels(&self) -> impl ExactSizeIterator<Item = X64StandaloneStartupLabel> + '_ {
        self.blocks.iter().map(|block| block.label)
    }

    pub fn fixups(&self) -> &[X64StandaloneStartupFixup] {
        &self.fixups
    }

    pub const fn plan_hash(&self) -> SemanticHash {
        self.plan_hash
    }
}

/// Opaque local proof that the complete typed plan is structurally canonical.
///
/// This token does not prove equality to an upstream standalone authority.
#[derive(Clone, Copy, Debug)]
pub struct LocallyVerifiedX64StandaloneStartupPlan<'plan> {
    plan: &'plan X64StandaloneStartupPlan,
}

/// Opaque proof that a locally canonical plan is also bound field-for-field
/// to the live R1-S8 seed authority.
#[derive(Clone, Copy, Debug)]
pub(super) struct AuthorityVerifiedX64StandaloneStartupPlan<'plan> {
    plan: &'plan X64StandaloneStartupPlan,
}

impl<'plan> AuthorityVerifiedX64StandaloneStartupPlan<'plan> {
    pub(super) const fn plan(self) -> &'plan X64StandaloneStartupPlan {
        self.plan
    }
}

impl<'plan> LocallyVerifiedX64StandaloneStartupPlan<'plan> {
    pub const fn plan(self) -> &'plan X64StandaloneStartupPlan {
        self.plan
    }

    pub const fn plan_hash(self) -> SemanticHash {
        self.plan.plan_hash
    }
}

/// Internal authority-bound result of the executable startup encoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct X64StandaloneStartupCode {
    profile: X64StandaloneProfile,
    target_offset: u64,
    target_entry_vaddr: u64,
    plan_hash: SemanticHash,
    code_hash: SemanticHash,
    bytes: Vec<u8>,
}

/// Authority-bound startup plan and executable bytes with placement derived
/// internally from the frozen lowering policy.
pub(super) struct X64StandaloneStartupArtifactSeed {
    plan: X64StandaloneStartupPlan,
    code: X64StandaloneStartupCode,
}

impl X64StandaloneStartupArtifactSeed {
    pub(super) const fn plan(&self) -> &X64StandaloneStartupPlan {
        &self.plan
    }

    pub(super) const fn code(&self) -> &X64StandaloneStartupCode {
        &self.code
    }
}

impl X64StandaloneStartupCode {
    pub(super) const fn profile(&self) -> X64StandaloneProfile {
        self.profile
    }

    pub(super) const fn target_offset(&self) -> u64 {
        self.target_offset
    }

    pub(super) const fn target_entry_vaddr(&self) -> u64 {
        self.target_entry_vaddr
    }

    pub(super) const fn plan_hash(&self) -> SemanticHash {
        self.plan_hash
    }

    pub(super) const fn code_hash(&self) -> SemanticHash {
        self.code_hash
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64StandaloneStartupError {
    Authority {
        message: String,
    },
    AuthorityBindingMismatch,
    RawEncoding {
        message: String,
    },
    RawVerification {
        message: String,
    },
    TargetOffset {
        actual: u64,
    },
    AddressOverflow {
        field: &'static str,
    },
    InvalidTargetAbi,
    InvalidEntryOffset {
        actual: u32,
    },
    InvalidEntryAbi {
        profile: X64StandaloneProfile,
    },
    MetricOverflow {
        field: &'static str,
    },
    Limit {
        field: &'static str,
        limit: u32,
        actual: u32,
    },
    TargetCallFixupCount {
        expected: u32,
        actual: u32,
    },
    InvalidSchema {
        field: &'static str,
        actual: (u16, u16, u16),
    },
    NonCanonicalPlan {
        field: &'static str,
    },
    PlanHashMismatch,
    EmptyStartupCode,
    CodeByteLimit {
        limit: u32,
        actual: usize,
    },
    LengthOverflow {
        field: &'static str,
        actual: usize,
    },
    AllocationFailed {
        field: &'static str,
        bytes: usize,
    },
    IdentityByteLimit {
        field: &'static str,
        limit: usize,
        actual: usize,
    },
}

impl fmt::Display for X64StandaloneStartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority { message } => {
                write!(formatter, "R1-S8 startup authority is invalid: {message}")
            }
            Self::AuthorityBindingMismatch => formatter
                .write_str("R1-S8 startup plan is not bound to the supplied live authority"),
            Self::RawEncoding { message } => {
                write!(formatter, "R1-S8 raw startup encoding failed: {message}")
            }
            Self::RawVerification { message } => {
                write!(
                    formatter,
                    "R1-S8 raw startup verification failed: {message}"
                )
            }
            Self::TargetOffset { actual } => write!(
                formatter,
                "R1-S8 target offset {actual:#x} is outside the aligned canonical image range"
            ),
            Self::AddressOverflow { field } => {
                write!(formatter, "R1-S8 startup {field} address overflow")
            }
            Self::InvalidTargetAbi => {
                formatter.write_str("R1-S8 startup target ABI is not canonical R1-S7a")
            }
            Self::InvalidEntryOffset { actual } => write!(
                formatter,
                "R1-S8 inherited target entry offset must be zero; found {actual}"
            ),
            Self::InvalidEntryAbi { profile } => write!(
                formatter,
                "R1-S8 target entry ABI does not match baked profile {profile:?}"
            ),
            Self::MetricOverflow { field } => {
                write!(formatter, "R1-S8 startup {field} metric overflow")
            }
            Self::Limit {
                field,
                limit,
                actual,
            } => write!(
                formatter,
                "R1-S8 startup {field} usage {actual} exceeds hard limit {limit}"
            ),
            Self::TargetCallFixupCount { expected, actual } => write!(
                formatter,
                "R1-S8 startup has {actual} target-call fixups; expected {expected}"
            ),
            Self::InvalidSchema { field, actual } => {
                write!(
                    formatter,
                    "R1-S8 startup {field} version {actual:?} is invalid"
                )
            }
            Self::NonCanonicalPlan { field } => {
                write!(formatter, "R1-S8 startup plan has noncanonical {field}")
            }
            Self::PlanHashMismatch => formatter.write_str("R1-S8 startup plan hash is invalid"),
            Self::EmptyStartupCode => formatter.write_str("R1-S8 startup code cannot be empty"),
            Self::CodeByteLimit { limit, actual } => write!(
                formatter,
                "R1-S8 startup code uses {actual} bytes; limit is {limit}"
            ),
            Self::LengthOverflow { field, actual } => write!(
                formatter,
                "R1-S8 startup {field} length {actual} exceeds canonical u32 encoding"
            ),
            Self::AllocationFailed { field, bytes } => write!(
                formatter,
                "R1-S8 startup cannot allocate {bytes} bytes for {field}"
            ),
            Self::IdentityByteLimit {
                field,
                limit,
                actual,
            } => write!(
                formatter,
                "R1-S8 startup {field} identity uses {actual} bytes; reserved limit is {limit}"
            ),
        }
    }
}

impl std::error::Error for X64StandaloneStartupError {}

/// Derive the local startup plan solely from opaque R1-S8 seed authority and
/// an internal provisional placement.
///
/// Only the artifact encoder may supply `target_offset`; independent artifact
/// verification must later prove that it equals the alignment of the actual
/// encoded startup length.
pub(super) fn plan_x64_standalone_startup_r1_s8(
    authority: &X64StandaloneSeedAuthority<'_>,
    target_offset: u64,
) -> Result<X64StandaloneStartupPlan, X64StandaloneStartupError> {
    let profile = authority.profile();
    let target =
        authority
            .source_bound()
            .map_err(|error| X64StandaloneStartupError::Authority {
                message: error.to_string(),
            })?;
    let program = target.program();
    plan_from_target_parts(
        profile,
        target_offset,
        program.entry_offset,
        program.abi,
        program.entry_abi.clone(),
        authority.binding(),
    )
}

/// Derive placement, regenerate the typed plan, bind it to live authority,
/// and emit the startup as one indivisible internal operation.
pub(super) fn build_x64_standalone_startup_seed_r1_s8(
    authority: &X64StandaloneSeedAuthority<'_>,
) -> Result<X64StandaloneStartupArtifactSeed, X64StandaloneStartupError> {
    let code_bytes = canonical_raw_code_bytes(authority.profile());
    let startup_end = X64_STANDALONE_STARTUP_OFFSET
        .checked_add(code_bytes)
        .ok_or(X64StandaloneStartupError::AddressOverflow {
            field: "startup end",
        })?;
    let target_offset = startup_end
        .checked_add(X64_STANDALONE_TARGET_ALIGNMENT - 1)
        .map(|value| value & !(X64_STANDALONE_TARGET_ALIGNMENT - 1))
        .ok_or(X64StandaloneStartupError::AddressOverflow {
            field: "target alignment",
        })?;
    let plan = plan_x64_standalone_startup_r1_s8(authority, target_offset)?;
    let verified = verify_x64_standalone_startup_plan_authority_r1_s8(&plan, authority)?;
    let code = encode_x64_standalone_startup_r1_s8(verified)?;
    let actual_code_bytes = u64::try_from(code.bytes().len()).map_err(|_| {
        X64StandaloneStartupError::MetricOverflow {
            field: "startup code bytes",
        }
    })?;
    if actual_code_bytes != code_bytes
        || code.target_offset() != target_offset
        || code.target_entry_vaddr() != plan.target_entry_vaddr()
    {
        return Err(X64StandaloneStartupError::NonCanonicalPlan {
            field: "derived startup placement",
        });
    }
    Ok(X64StandaloneStartupArtifactSeed { plan, code })
}

/// Derive and emit the same reviewed startup mechanics through the distinct
/// ADR-0054 authority boundary.  No raw binding, target, ABI, or placement is
/// accepted from the caller.
pub(super) fn build_x64_gate_b_policy15_standalone_startup(
    authority: &X64GateBPolicy15StandaloneAuthority<'_, '_>,
) -> Result<X64StandaloneStartupArtifactSeed, X64StandaloneStartupError> {
    authority
        .revalidate_complete()
        .map_err(|error| X64StandaloneStartupError::Authority {
            message: error.to_string(),
        })?;
    let code_bytes = canonical_raw_code_bytes(authority.profile());
    let startup_end = X64_STANDALONE_STARTUP_OFFSET
        .checked_add(code_bytes)
        .ok_or(X64StandaloneStartupError::AddressOverflow {
            field: "candidate startup end",
        })?;
    let target_offset = startup_end
        .checked_add(X64_STANDALONE_TARGET_ALIGNMENT - 1)
        .map(|value| value & !(X64_STANDALONE_TARGET_ALIGNMENT - 1))
        .ok_or(X64StandaloneStartupError::AddressOverflow {
            field: "candidate target alignment",
        })?;
    let target = authority.target();
    let plan = plan_from_target_parts(
        authority.profile(),
        target_offset,
        target.program.entry_offset,
        target.program.abi,
        target.program.entry_abi.clone(),
        authority.binding(),
    )?;
    verify_x64_standalone_startup_plan_local_r1_s8(&plan)?;
    if plan.profile != authority.profile() || plan.authority_binding != authority.binding() {
        return Err(X64StandaloneStartupError::AuthorityBindingMismatch);
    }
    let code = encode_verified_startup_plan(&plan)?;
    let actual_code_bytes = u64::try_from(code.bytes().len()).map_err(|_| {
        X64StandaloneStartupError::MetricOverflow {
            field: "candidate startup code bytes",
        }
    })?;
    if actual_code_bytes != code_bytes
        || code.target_offset() != target_offset
        || code.target_entry_vaddr() != plan.target_entry_vaddr()
    {
        return Err(X64StandaloneStartupError::NonCanonicalPlan {
            field: "candidate derived startup placement",
        });
    }
    Ok(X64StandaloneStartupArtifactSeed { plan, code })
}

fn plan_from_target_parts(
    profile: X64StandaloneProfile,
    target_offset: u64,
    inherited_entry_offset: u32,
    target_abi: X64TargetAbi,
    entry_abi: X64EntryAbi,
    authority_binding: X64StandaloneAuthorityBinding,
) -> Result<X64StandaloneStartupPlan, X64StandaloneStartupError> {
    validate_target_offset(target_offset)?;
    if target_abi != X64TargetAbi::r1_s7a() {
        return Err(X64StandaloneStartupError::InvalidTargetAbi);
    }
    if inherited_entry_offset != 0 {
        return Err(X64StandaloneStartupError::InvalidEntryOffset {
            actual: inherited_entry_offset,
        });
    }
    if entry_abi != canonical_entry_abi(profile) {
        return Err(X64StandaloneStartupError::InvalidEntryAbi { profile });
    }
    let input_lanes = u8::try_from(entry_abi.input_lanes.len()).map_err(|_| {
        X64StandaloneStartupError::MetricOverflow {
            field: "input lanes",
        }
    })?;
    let target_entry_vaddr = X64_STANDALONE_ELF_BASE
        .checked_add(target_offset)
        .and_then(|address| address.checked_add(u64::from(inherited_entry_offset)))
        .ok_or(X64StandaloneStartupError::AddressOverflow {
            field: "target entry",
        })?;
    let blocks = canonical_blocks();
    let fixups = canonical_fixups(target_entry_vaddr);
    let template = encode_x64_standalone_startup_raw(profile, target_entry_vaddr)
        .map_err(raw_encoding_error)?;
    validate_raw_template(&template, profile, target_entry_vaddr)?;
    let usage = startup_usage(&blocks, &template)?;
    let lowering = lowering_receipt(&template);
    validate_usage(usage, X64StandaloneStartupLimits::r1_s8())?;

    let io = X64StandaloneStartupIoContract::r1_s8(profile);
    let io_contract_hash = x64_standalone_io_contract_hash_for(io)?;
    let mut plan = X64StandaloneStartupPlan {
        schema_version: X64_STANDALONE_STARTUP_SCHEMA_VERSION,
        planner_policy_version: X64_STANDALONE_STARTUP_PLANNER_POLICY_VERSION,
        lowering_policy_version: X64_STANDALONE_STARTUP_LOWERING_POLICY_VERSION,
        encoder_policy_version: X64_STANDALONE_STARTUP_ENCODER_POLICY_VERSION,
        io_schema_version: X64_STANDALONE_IO_SCHEMA_VERSION,
        io_policy_version: X64_STANDALONE_IO_POLICY_VERSION,
        profile,
        limits: X64StandaloneStartupLimits::r1_s8(),
        usage,
        stack: X64StandaloneStartupStackLayout::r1_s8(),
        io,
        io_contract_hash,
        authority_binding,
        target: X64StandaloneStartupTarget {
            target_offset,
            inherited_entry_offset,
            target_entry_vaddr,
            target_abi,
            entry_abi,
            input_lanes,
        },
        lowering,
        blocks,
        fixups,
        plan_hash: SemanticHash::ZERO,
    };
    plan.plan_hash = x64_standalone_startup_plan_hash(&plan)?;
    verify_x64_standalone_startup_plan_local_r1_s8(&plan)?;
    Ok(plan)
}

/// Canonical startup-plan preimage.
pub fn x64_standalone_startup_plan_bytes(
    plan: &X64StandaloneStartupPlan,
) -> Result<Vec<u8>, X64StandaloneStartupError> {
    let mut encoder = StartupIdentityEncoder::new("startup plan")?;
    encoder.bytes(STARTUP_PLAN_DOMAIN);
    encoder.version(plan.schema_version);
    encoder.version(plan.planner_policy_version);
    encoder.version(plan.lowering_policy_version);
    encoder.version(plan.encoder_policy_version);
    encoder.version(plan.io_schema_version);
    encoder.version(plan.io_policy_version);
    encoder.u16(plan.profile.wire_tag());
    encode_limits(&mut encoder, plan.limits);
    encode_usage(&mut encoder, plan.usage);
    encode_stack(&mut encoder, plan.stack);
    encode_io(&mut encoder, plan.io);
    encoder.bytes(&plan.io_contract_hash.0);
    encode_authority_binding(&mut encoder, plan.authority_binding);
    encode_target(&mut encoder, &plan.target)?;
    encode_lowering(&mut encoder, plan.lowering);
    encoder.length("startup blocks", plan.blocks.len())?;
    for block in &plan.blocks {
        encoder.u8(label_tag(block.label));
        encode_operation(&mut encoder, block.operation);
    }
    encoder.length("startup fixups", plan.fixups.len())?;
    for fixup in &plan.fixups {
        encoder.u8(label_tag(fixup.source));
        encode_fixup(&mut encoder, fixup.kind);
    }
    encoder.finish()
}

pub fn x64_standalone_startup_plan_hash(
    plan: &X64StandaloneStartupPlan,
) -> Result<SemanticHash, X64StandaloneStartupError> {
    Ok(SemanticHash(sha256(&x64_standalone_startup_plan_bytes(
        plan,
    )?)))
}

/// Canonical, profile-bound I/O-contract preimage.
pub fn x64_standalone_io_contract_bytes(
    profile: X64StandaloneProfile,
) -> Result<Vec<u8>, X64StandaloneStartupError> {
    x64_standalone_io_contract_bytes_for(X64StandaloneStartupIoContract::r1_s8(profile))
}

/// Canonical, profile-bound I/O-contract identity.
pub fn x64_standalone_io_contract_hash(
    profile: X64StandaloneProfile,
) -> Result<SemanticHash, X64StandaloneStartupError> {
    x64_standalone_io_contract_hash_for(X64StandaloneStartupIoContract::r1_s8(profile))
}

fn x64_standalone_io_contract_bytes_for(
    io: X64StandaloneStartupIoContract,
) -> Result<Vec<u8>, X64StandaloneStartupError> {
    let mut encoder = StartupIdentityEncoder::with_capacity("I/O contract", 512)?;
    encoder.bytes(IO_CONTRACT_DOMAIN);
    encoder.version(X64_STANDALONE_IO_SCHEMA_VERSION);
    encoder.version(X64_STANDALONE_IO_POLICY_VERSION);
    encode_io(&mut encoder, io);
    encoder.finish()
}

fn x64_standalone_io_contract_hash_for(
    io: X64StandaloneStartupIoContract,
) -> Result<SemanticHash, X64StandaloneStartupError> {
    Ok(SemanticHash(sha256(&x64_standalone_io_contract_bytes_for(
        io,
    )?)))
}

/// Verify every field and rebuild the canonical typed control graph.
pub fn verify_x64_standalone_startup_plan_local_r1_s8(
    plan: &X64StandaloneStartupPlan,
) -> Result<LocallyVerifiedX64StandaloneStartupPlan<'_>, X64StandaloneStartupError> {
    for (field, actual, expected) in [
        (
            "schema",
            plan.schema_version,
            X64_STANDALONE_STARTUP_SCHEMA_VERSION,
        ),
        (
            "planner policy",
            plan.planner_policy_version,
            X64_STANDALONE_STARTUP_PLANNER_POLICY_VERSION,
        ),
        (
            "lowering policy",
            plan.lowering_policy_version,
            X64_STANDALONE_STARTUP_LOWERING_POLICY_VERSION,
        ),
        (
            "encoder policy",
            plan.encoder_policy_version,
            X64_STANDALONE_STARTUP_ENCODER_POLICY_VERSION,
        ),
        (
            "I/O schema",
            plan.io_schema_version,
            X64_STANDALONE_IO_SCHEMA_VERSION,
        ),
        (
            "I/O policy",
            plan.io_policy_version,
            X64_STANDALONE_IO_POLICY_VERSION,
        ),
    ] {
        if actual != expected {
            return Err(X64StandaloneStartupError::InvalidSchema { field, actual });
        }
    }
    if plan.limits != X64StandaloneStartupLimits::r1_s8() {
        return Err(X64StandaloneStartupError::NonCanonicalPlan {
            field: "limit vector",
        });
    }
    if plan.stack != X64StandaloneStartupStackLayout::r1_s8() {
        return Err(X64StandaloneStartupError::NonCanonicalPlan {
            field: "stack layout",
        });
    }
    if plan.io != X64StandaloneStartupIoContract::r1_s8(plan.profile) {
        return Err(X64StandaloneStartupError::NonCanonicalPlan {
            field: "I/O contract",
        });
    }
    if plan.io_contract_hash != x64_standalone_io_contract_hash_for(plan.io)? {
        return Err(X64StandaloneStartupError::NonCanonicalPlan {
            field: "I/O contract hash",
        });
    }
    validate_authority_binding(plan.profile, plan.authority_binding)?;
    validate_target_offset(plan.target.target_offset)?;
    if plan.target.inherited_entry_offset != 0 {
        return Err(X64StandaloneStartupError::InvalidEntryOffset {
            actual: plan.target.inherited_entry_offset,
        });
    }
    if plan.target.target_abi != X64TargetAbi::r1_s7a() {
        return Err(X64StandaloneStartupError::InvalidTargetAbi);
    }
    if plan.target.entry_abi != canonical_entry_abi(plan.profile) {
        return Err(X64StandaloneStartupError::InvalidEntryAbi {
            profile: plan.profile,
        });
    }
    let expected_lanes = u8::try_from(plan.target.entry_abi.input_lanes.len()).map_err(|_| {
        X64StandaloneStartupError::MetricOverflow {
            field: "input lanes",
        }
    })?;
    if plan.target.input_lanes != expected_lanes {
        return Err(X64StandaloneStartupError::NonCanonicalPlan {
            field: "input lane count",
        });
    }
    if plan.authority_binding.entry_offset != plan.target.inherited_entry_offset
        || plan.authority_binding.input_lanes != plan.target.input_lanes
    {
        return Err(X64StandaloneStartupError::NonCanonicalPlan {
            field: "authority target facts",
        });
    }
    let expected_entry = X64_STANDALONE_ELF_BASE
        .checked_add(plan.target.target_offset)
        .and_then(|address| address.checked_add(u64::from(plan.target.inherited_entry_offset)))
        .ok_or(X64StandaloneStartupError::AddressOverflow {
            field: "target entry",
        })?;
    if plan.target.target_entry_vaddr != expected_entry {
        return Err(X64StandaloneStartupError::NonCanonicalPlan {
            field: "target entry address",
        });
    }

    let expected_blocks = canonical_blocks();
    if plan.blocks != expected_blocks {
        return Err(X64StandaloneStartupError::NonCanonicalPlan {
            field: "operation/label sequence",
        });
    }
    let expected_fixups = canonical_fixups(expected_entry);
    if plan.fixups != expected_fixups {
        return Err(X64StandaloneStartupError::NonCanonicalPlan {
            field: "control fixups",
        });
    }
    let template = encode_x64_standalone_startup_raw(plan.profile, expected_entry)
        .map_err(raw_encoding_error)?;
    validate_raw_template(&template, plan.profile, expected_entry)?;
    let expected_lowering = lowering_receipt(&template);
    if plan.lowering != expected_lowering {
        return Err(X64StandaloneStartupError::NonCanonicalPlan {
            field: "concrete lowering receipt",
        });
    }
    let usage = startup_usage(&plan.blocks, &template)?;
    if plan.usage != usage {
        return Err(X64StandaloneStartupError::NonCanonicalPlan {
            field: "usage vector",
        });
    }
    validate_usage(usage, plan.limits)?;
    if x64_standalone_startup_plan_hash(plan)? != plan.plan_hash {
        return Err(X64StandaloneStartupError::PlanHashMismatch);
    }
    Ok(LocallyVerifiedX64StandaloneStartupPlan { plan })
}

/// Compose local plan verification with exact equality to a live opaque
/// R1-S8 authority. A detached binding tuple cannot construct this token.
pub(super) fn verify_x64_standalone_startup_plan_authority_r1_s8<'plan>(
    plan: &'plan X64StandaloneStartupPlan,
    authority: &X64StandaloneSeedAuthority<'_>,
) -> Result<AuthorityVerifiedX64StandaloneStartupPlan<'plan>, X64StandaloneStartupError> {
    verify_x64_standalone_startup_plan_local_r1_s8(plan)?;
    if plan.profile != authority.profile() || plan.authority_binding != authority.binding() {
        return Err(X64StandaloneStartupError::AuthorityBindingMismatch);
    }
    Ok(AuthorityVerifiedX64StandaloneStartupPlan { plan })
}

/// Compute the future startup-code identity without granting executable
/// authority to arbitrary bytes.
pub fn x64_standalone_startup_code_hash(
    plan_hash: SemanticHash,
    code: &[u8],
) -> Result<SemanticHash, X64StandaloneStartupError> {
    if code.is_empty() {
        return Err(X64StandaloneStartupError::EmptyStartupCode);
    }
    let actual = code.len();
    let actual_u32 =
        u32::try_from(actual).map_err(|_| X64StandaloneStartupError::LengthOverflow {
            field: "startup code",
            actual,
        })?;
    if actual_u32 > X64_STANDALONE_STARTUP_MAX_CODE_BYTES {
        return Err(X64StandaloneStartupError::CodeByteLimit {
            limit: X64_STANDALONE_STARTUP_MAX_CODE_BYTES,
            actual,
        });
    }
    let identity_bytes = STARTUP_CODE_DOMAIN
        .len()
        .checked_add(6 + 6 + 32 + 4)
        .and_then(|prefix| prefix.checked_add(actual))
        .ok_or(X64StandaloneStartupError::LengthOverflow {
            field: "startup code identity",
            actual,
        })?;
    let mut encoder =
        StartupIdentityEncoder::with_capacity("startup code identity", identity_bytes)?;
    encoder.bytes(STARTUP_CODE_DOMAIN);
    encoder.version(X64_STANDALONE_STARTUP_SCHEMA_VERSION);
    encoder.version(X64_STANDALONE_STARTUP_ENCODER_POLICY_VERSION);
    encoder.bytes(&plan_hash.0);
    encoder.u32(actual_u32);
    encoder.bytes(code);
    let identity = encoder.finish()?;
    Ok(SemanticHash(sha256(&identity)))
}

/// Encode the complete raw-syscall startup only from a plan that has been
/// checked against live opaque upstream authority.
pub(super) fn encode_x64_standalone_startup_r1_s8(
    verified: AuthorityVerifiedX64StandaloneStartupPlan<'_>,
) -> Result<X64StandaloneStartupCode, X64StandaloneStartupError> {
    encode_verified_startup_plan(verified.plan())
}

fn encode_verified_startup_plan(
    plan: &X64StandaloneStartupPlan,
) -> Result<X64StandaloneStartupCode, X64StandaloneStartupError> {
    let template = encode_x64_standalone_startup_raw(plan.profile, plan.target.target_entry_vaddr)
        .map_err(raw_encoding_error)?;
    validate_raw_template(&template, plan.profile, plan.target.target_entry_vaddr)?;
    if lowering_receipt(&template) != plan.lowering
        || startup_usage(&plan.blocks, &template)? != plan.usage
    {
        return Err(X64StandaloneStartupError::NonCanonicalPlan {
            field: "encoded lowering receipt",
        });
    }
    let structurally_verified = independently_verify_x64_standalone_startup_raw_r1_s8(
        template.code(),
        &template,
        plan.profile,
        plan.target.target_entry_vaddr,
    )
    .map_err(raw_verification_error)?;
    let bytes = structurally_verified.code().to_vec();
    let code_hash = x64_standalone_startup_code_hash(plan.plan_hash, &bytes)?;
    Ok(X64StandaloneStartupCode {
        profile: plan.profile,
        target_offset: plan.target.target_offset,
        target_entry_vaddr: plan.target.target_entry_vaddr,
        plan_hash: plan.plan_hash,
        code_hash,
        bytes,
    })
}

/// Independently check an externally supplied startup slice against the
/// canonical lowering receipt derived from a typed plan.
///
/// The returned opaque token borrows the supplied slice, not the regenerated
/// receipt, so an artifact verifier can retain the proof for the exact bytes
/// extracted from an ELF image.
pub(super) fn independently_verify_x64_standalone_startup_code_r1_s8<'code>(
    plan: &X64StandaloneStartupPlan,
    code: &'code [u8],
) -> Result<IndependentlyVerifiedX64StandaloneStartupRaw<'code>, X64StandaloneStartupError> {
    let receipt = encode_x64_standalone_startup_raw(plan.profile, plan.target.target_entry_vaddr)
        .map_err(raw_encoding_error)?;
    validate_raw_template(&receipt, plan.profile, plan.target.target_entry_vaddr)?;
    independently_verify_x64_standalone_startup_raw_r1_s8(
        code,
        &receipt,
        plan.profile,
        plan.target.target_entry_vaddr,
    )
    .map_err(raw_verification_error)
}

fn validate_target_offset(target_offset: u64) -> Result<(), X64StandaloneStartupError> {
    if target_offset <= X64_STANDALONE_STARTUP_OFFSET
        || !target_offset.is_multiple_of(X64_STANDALONE_TARGET_ALIGNMENT)
        || target_offset >= X64_STANDALONE_MAX_ELF_IMAGE_BYTES
    {
        return Err(X64StandaloneStartupError::TargetOffset {
            actual: target_offset,
        });
    }
    Ok(())
}

fn canonical_entry_abi(profile: X64StandaloneProfile) -> X64EntryAbi {
    let (parameter_types, input_lanes, output_register) = match profile {
        X64StandaloneProfile::BranchMix => (
            vec![MachineType::F64Array, MachineType::I64],
            vec![
                super::x64_target::X64EntryLane {
                    parameter: 0,
                    word: 0,
                    register: X64AbiRegister::Rdi,
                },
                super::x64_target::X64EntryLane {
                    parameter: 0,
                    word: 1,
                    register: X64AbiRegister::Rsi,
                },
                super::x64_target::X64EntryLane {
                    parameter: 1,
                    word: 0,
                    register: X64AbiRegister::Rdx,
                },
            ],
            X64AbiRegister::Rcx,
        ),
        X64StandaloneProfile::Bounds => (
            vec![MachineType::F64Array],
            vec![
                super::x64_target::X64EntryLane {
                    parameter: 0,
                    word: 0,
                    register: X64AbiRegister::Rdi,
                },
                super::x64_target::X64EntryLane {
                    parameter: 0,
                    word: 1,
                    register: X64AbiRegister::Rsi,
                },
            ],
            X64AbiRegister::Rdx,
        ),
    };
    X64EntryAbi {
        parameter_types,
        input_lanes,
        output_register,
        result: MachineType::F64,
        output_words: 2,
    }
}

fn canonical_blocks() -> Vec<X64StandaloneStartupBlock> {
    use X64StandaloneStartupLabel as Label;
    use X64StandaloneStartupOp as Op;
    vec![
        block(Label::Entry, Op::AdmitProcessEntry),
        block(Label::EstablishMxcsr, Op::EstablishCanonicalMxcsr),
        block(Label::ReadHeader, Op::ReadHeaderExact),
        block(Label::ValidateHeader, Op::ValidateHeader),
        block(Label::ValidatePayload, Op::ValidatePayloadShape),
        block(Label::MapPayload, Op::MapPayloadIfNonEmpty),
        block(Label::ReadPayload, Op::ReadPayloadExact),
        block(Label::ProbeEof, Op::ProbeInputEof),
        block(Label::SwapPayload, Op::ByteSwapPayloadU64InPlace),
        block(Label::ProtectPayload, Op::ProtectPayloadReadOnlyIfNonEmpty),
        block(Label::PrepareTarget, Op::PrepareTypedTargetCall),
        block(Label::CallTarget, Op::CallTarget),
        block(Label::ValidateMxcsr, Op::ObserveAndValidateCanonicalMxcsr),
        block(Label::ValidateTarget, Op::ValidateTargetResult),
        block(Label::UnmapPayload, Op::UnmapPayloadIfNonEmpty),
        block(Label::BuildOutput, Op::BuildCanonicalOutput),
        block(Label::WriteOutput, Op::WriteOutputExact),
        block(Label::CleanupInput, Op::CleanupPayloadIfMapped),
        block(Label::CleanupInvariant, Op::CleanupPayloadIfMapped),
        block(Label::CleanupMemory, Op::CleanupPayloadIfMapped),
        block(Label::CleanupIo, Op::CleanupPayloadIfMapped),
        block(
            Label::ExitSuccess,
            Op::ExitGroupThenTrap {
                status: X64_STANDALONE_EXIT_SUCCESS,
            },
        ),
        block(
            Label::ExitInput,
            Op::ExitGroupThenTrap {
                status: X64_STANDALONE_EXIT_INPUT,
            },
        ),
        block(
            Label::ExitInvariant,
            Op::ExitGroupThenTrap {
                status: X64_STANDALONE_EXIT_INVARIANT,
            },
        ),
        block(
            Label::ExitMemory,
            Op::ExitGroupThenTrap {
                status: X64_STANDALONE_EXIT_MEMORY,
            },
        ),
        block(
            Label::ExitIo,
            Op::ExitGroupThenTrap {
                status: X64_STANDALONE_EXIT_IO,
            },
        ),
    ]
}

const fn block(
    label: X64StandaloneStartupLabel,
    operation: X64StandaloneStartupOp,
) -> X64StandaloneStartupBlock {
    X64StandaloneStartupBlock { label, operation }
}

fn canonical_fixups(target_entry_vaddr: u64) -> Vec<X64StandaloneStartupFixup> {
    use X64StandaloneStartupCondition as Condition;
    use X64StandaloneStartupLabel as Label;
    vec![
        conditional(Label::Entry, Condition::ArgcMismatch, Label::ExitInput),
        conditional(
            Label::ReadHeader,
            Condition::SyscallEintr,
            Label::ReadHeader,
        ),
        conditional(
            Label::ReadHeader,
            Condition::ReadIncomplete,
            Label::ReadHeader,
        ),
        conditional(
            Label::ReadHeader,
            Condition::IoFailureOrTruncation,
            Label::ExitIo,
        ),
        conditional(
            Label::ValidateHeader,
            Condition::InputRejected,
            Label::ExitInput,
        ),
        conditional(
            Label::ValidatePayload,
            Condition::InputRejected,
            Label::ExitInput,
        ),
        conditional(
            Label::ValidatePayload,
            Condition::PayloadEmpty,
            Label::ProbeEof,
        ),
        conditional(
            Label::MapPayload,
            Condition::MemoryFailure,
            Label::ExitMemory,
        ),
        conditional(
            Label::ReadPayload,
            Condition::SyscallEintr,
            Label::ReadPayload,
        ),
        conditional(
            Label::ReadPayload,
            Condition::ReadIncomplete,
            Label::ReadPayload,
        ),
        conditional(
            Label::ReadPayload,
            Condition::IoFailureOrTruncation,
            Label::CleanupIo,
        ),
        conditional(Label::ProbeEof, Condition::SyscallEintr, Label::ProbeEof),
        conditional(
            Label::ProbeEof,
            Condition::IoFailureOrTruncation,
            Label::CleanupIo,
        ),
        conditional(
            Label::ProbeEof,
            Condition::TrailingInput,
            Label::CleanupInput,
        ),
        conditional(
            Label::SwapPayload,
            Condition::PayloadWordsRemain,
            Label::SwapPayload,
        ),
        conditional(
            Label::ProtectPayload,
            Condition::MemoryFailure,
            Label::CleanupMemory,
        ),
        X64StandaloneStartupFixup {
            source: Label::CallTarget,
            kind: X64StandaloneStartupFixupKind::TargetCallRel32 {
                target_vaddr: target_entry_vaddr,
            },
        },
        conditional(
            Label::ValidateMxcsr,
            Condition::NumericStateMismatch,
            Label::CleanupInvariant,
        ),
        conditional(
            Label::ValidateTarget,
            Condition::InvalidTargetResult,
            Label::CleanupInvariant,
        ),
        conditional(
            Label::UnmapPayload,
            Condition::MappingAbsent,
            Label::BuildOutput,
        ),
        conditional(
            Label::UnmapPayload,
            Condition::MemoryFailure,
            Label::ExitMemory,
        ),
        unconditional(Label::UnmapPayload, Label::BuildOutput),
        conditional(
            Label::WriteOutput,
            Condition::SyscallEintr,
            Label::WriteOutput,
        ),
        conditional(
            Label::WriteOutput,
            Condition::WriteRetry,
            Label::WriteOutput,
        ),
        conditional(
            Label::WriteOutput,
            Condition::IoFailureOrTruncation,
            Label::ExitIo,
        ),
        unconditional(Label::WriteOutput, Label::ExitSuccess),
        conditional(
            Label::CleanupInput,
            Condition::MappingAbsent,
            Label::ExitInput,
        ),
        conditional(
            Label::CleanupInput,
            Condition::MemoryFailure,
            Label::ExitMemory,
        ),
        unconditional(Label::CleanupInput, Label::ExitInput),
        conditional(
            Label::CleanupInvariant,
            Condition::MappingAbsent,
            Label::ExitInvariant,
        ),
        conditional(
            Label::CleanupInvariant,
            Condition::MemoryFailure,
            Label::ExitMemory,
        ),
        unconditional(Label::CleanupInvariant, Label::ExitInvariant),
        conditional(
            Label::CleanupMemory,
            Condition::MappingAbsent,
            Label::ExitMemory,
        ),
        conditional(
            Label::CleanupMemory,
            Condition::MemoryFailure,
            Label::ExitMemory,
        ),
        unconditional(Label::CleanupMemory, Label::ExitMemory),
        conditional(Label::CleanupIo, Condition::MappingAbsent, Label::ExitIo),
        conditional(
            Label::CleanupIo,
            Condition::MemoryFailure,
            Label::ExitMemory,
        ),
        unconditional(Label::CleanupIo, Label::ExitIo),
    ]
}

const fn conditional(
    source: X64StandaloneStartupLabel,
    condition: X64StandaloneStartupCondition,
    target: X64StandaloneStartupLabel,
) -> X64StandaloneStartupFixup {
    X64StandaloneStartupFixup {
        source,
        kind: X64StandaloneStartupFixupKind::ConditionalRel32 { condition, target },
    }
}

const fn unconditional(
    source: X64StandaloneStartupLabel,
    target: X64StandaloneStartupLabel,
) -> X64StandaloneStartupFixup {
    X64StandaloneStartupFixup {
        source,
        kind: X64StandaloneStartupFixupKind::UnconditionalRel32 { target },
    }
}

fn startup_usage(
    blocks: &[X64StandaloneStartupBlock],
    template: &X64StandaloneStartupTemplate,
) -> Result<X64StandaloneStartupUsage, X64StandaloneStartupError> {
    let ops = checked_metric("operations", blocks.len())?;
    let labels = checked_metric("labels", template.label_count())?;
    let fixup_count = checked_metric("fixups", template.fixup_count())?;
    let internal_call_fixups =
        checked_metric("internal-call fixups", template.internal_call_count())?;
    let target_call_fixups = checked_metric("target-call fixups", template.target_call_count())?;
    let code_bytes = checked_metric("startup code bytes", template.code().len())?;
    Ok(X64StandaloneStartupUsage {
        ops,
        labels,
        fixups: fixup_count,
        internal_call_fixups,
        target_call_fixups,
        syscall_sites: u32::from(template.syscall_site_count()),
        code_bytes,
        stack_bytes: u32::from(template.worst_case_stack_reach_bytes()),
    })
}

fn lowering_receipt(
    template: &X64StandaloneStartupTemplate,
) -> X64StandaloneStartupLoweringReceipt {
    let target_call = template.target_call();
    X64StandaloneStartupLoweringReceipt {
        stack_frame_bytes: u32::from(template.stack_frame_bytes()),
        syscall_numbers: template.syscall_numbers(),
        syscall_sites: template.syscall_sites(),
        target_call_displacement_offset: target_call.displacement_offset(),
        target_call_next_instruction_offset: target_call.next_instruction_offset(),
        target_call_displacement: target_call.displacement(),
    }
}

fn validate_raw_template(
    template: &X64StandaloneStartupTemplate,
    profile: X64StandaloneProfile,
    target_entry_vaddr: u64,
) -> Result<(), X64StandaloneStartupError> {
    let expected_code_bytes = usize::try_from(canonical_raw_code_bytes(profile)).map_err(|_| {
        X64StandaloneStartupError::MetricOverflow {
            field: "canonical startup code bytes",
        }
    })?;
    let expected_fixups = match profile {
        X64StandaloneProfile::BranchMix => 58,
        X64StandaloneProfile::Bounds => 59,
    };
    if template.profile() != profile
        || template.code().len() != expected_code_bytes
        || template.label_count() != 32
        || template.fixup_count() != expected_fixups
        || template.internal_call_count() != 4
        || template.target_call_count() != 1
        || template.stack_frame_bytes() != STARTUP_STACK_FRAME_BYTES as u16
        || template.worst_case_stack_reach_bytes() != STARTUP_STACK_WORST_REACH_BYTES as u16
        || template.syscall_numbers()
            != [
                SYS_READ,
                SYS_WRITE,
                SYS_MMAP,
                SYS_MPROTECT,
                SYS_MUNMAP,
                SYS_EXIT_GROUP,
            ]
        || template.syscall_sites() != [2, 1, 1, 1, 2, 1]
        || template.syscall_site_count() != 8
        || template.target_call().target_entry_vaddr() != target_entry_vaddr
    {
        return Err(X64StandaloneStartupError::NonCanonicalPlan {
            field: "raw startup receipt",
        });
    }
    Ok(())
}

const fn canonical_raw_code_bytes(profile: X64StandaloneProfile) -> u64 {
    match profile {
        X64StandaloneProfile::BranchMix => 1_032,
        X64StandaloneProfile::Bounds => 1_038,
    }
}

fn raw_encoding_error(error: X64StandaloneStartupEncodeError) -> X64StandaloneStartupError {
    X64StandaloneStartupError::RawEncoding {
        message: error.to_string(),
    }
}

fn raw_verification_error(error: X64StandaloneStartupVerifyError) -> X64StandaloneStartupError {
    X64StandaloneStartupError::RawVerification {
        message: error.to_string(),
    }
}

fn checked_metric(field: &'static str, actual: usize) -> Result<u32, X64StandaloneStartupError> {
    u32::try_from(actual).map_err(|_| X64StandaloneStartupError::MetricOverflow { field })
}

fn validate_usage(
    usage: X64StandaloneStartupUsage,
    limits: X64StandaloneStartupLimits,
) -> Result<(), X64StandaloneStartupError> {
    for (field, actual, limit) in [
        ("operations", usage.ops, limits.max_ops),
        ("labels", usage.labels, limits.max_labels),
        ("fixups", usage.fixups, limits.max_fixups),
        (
            "startup code bytes",
            usage.code_bytes,
            limits.max_code_bytes,
        ),
        ("stack bytes", usage.stack_bytes, limits.max_stack_bytes),
    ] {
        if actual > limit {
            return Err(X64StandaloneStartupError::Limit {
                field,
                limit,
                actual,
            });
        }
    }
    if usage.target_call_fixups != limits.target_call_fixups {
        return Err(X64StandaloneStartupError::TargetCallFixupCount {
            expected: limits.target_call_fixups,
            actual: usage.target_call_fixups,
        });
    }
    Ok(())
}

fn encode_limits(encoder: &mut StartupIdentityEncoder, limits: X64StandaloneStartupLimits) {
    encoder.u32(limits.max_ops);
    encoder.u32(limits.max_labels);
    encoder.u32(limits.max_fixups);
    encoder.u32(limits.max_code_bytes);
    encoder.u32(limits.max_stack_bytes);
    encoder.u32(limits.target_call_fixups);
}

fn encode_usage(encoder: &mut StartupIdentityEncoder, usage: X64StandaloneStartupUsage) {
    encoder.u32(usage.ops);
    encoder.u32(usage.labels);
    encoder.u32(usage.fixups);
    encoder.u32(usage.internal_call_fixups);
    encoder.u32(usage.target_call_fixups);
    encoder.u32(usage.syscall_sites);
    encoder.u32(usage.code_bytes);
    encoder.u32(usage.stack_bytes);
}

fn encode_lowering(
    encoder: &mut StartupIdentityEncoder,
    lowering: X64StandaloneStartupLoweringReceipt,
) {
    encoder.u32(lowering.stack_frame_bytes);
    for number in lowering.syscall_numbers {
        encoder.u32(number);
    }
    for sites in lowering.syscall_sites {
        encoder.u16(sites);
    }
    encoder.u32(lowering.target_call_displacement_offset);
    encoder.u32(lowering.target_call_next_instruction_offset);
    encoder.bytes(&lowering.target_call_displacement.to_be_bytes());
}

fn encode_stack(encoder: &mut StartupIdentityEncoder, stack: X64StandaloneStartupStackLayout) {
    for value in [
        stack.frame_bytes,
        stack.input_header_offset,
        stack.input_header_bytes,
        stack.output_frame_offset,
        stack.output_frame_bytes,
        stack.target_output_offset,
        stack.target_output_bytes,
        stack.eof_probe_offset,
        stack.eof_probe_bytes,
        stack.expected_mxcsr_offset,
        stack.observed_mxcsr_offset,
    ] {
        encoder.u32(value);
    }
}

fn encode_io(encoder: &mut StartupIdentityEncoder, io: X64StandaloneStartupIoContract) {
    encoder.u16(io.profile.wire_tag());
    encoder.bytes(&io.input_magic);
    encoder.bytes(&io.output_magic);
    encoder.version(io.protocol_version);
    encoder.u64(io.required_argc);
    for value in [
        io.stdin_fd,
        io.stdout_fd,
        io.input_header_bytes,
        io.output_frame_bytes,
        io.eof_probe_bytes,
    ] {
        encoder.u32(value);
    }
    encoder.u64(io.max_array_elements);
    encoder.u64(io.max_payload_bytes);
    encoder.u64(io.max_input_frame_bytes);
    encoder.u32(io.array_word_bytes);
    encoder.i64(io.bounds_repetitions);
    encoder.u32(io.return_f64_outcome_tag);
    encoder.u32(io.bounds_outcome_tag);
    encoder.u32(io.output_reserved);
    encoder.u64(io.canonical_nan_bits);
    encoder.u64(io.target_output_sentinel);
    for value in [
        io.syscall_read,
        io.syscall_write,
        io.syscall_mmap,
        io.syscall_mprotect,
        io.syscall_munmap,
        io.syscall_exit_group,
        io.mmap_protection,
        io.mmap_flags,
        io.mprotect_protection,
    ] {
        encoder.u32(value);
    }
    encoder.i64(io.mmap_fd);
    encoder.u64(io.mmap_offset);
    encoder.i64(io.raw_syscall_error_floor);
    encoder.i64(io.raw_eintr_return);
    encoder.boolean(io.retry_eintr);
    encoder.boolean(io.exact_eof);
    encoder.boolean(io.no_stderr);
    for status in [
        X64_STANDALONE_EXIT_SUCCESS,
        X64_STANDALONE_EXIT_INPUT,
        X64_STANDALONE_EXIT_INVARIANT,
        X64_STANDALONE_EXIT_MEMORY,
        X64_STANDALONE_EXIT_IO,
    ] {
        encoder.u8(status);
    }
}

fn encode_authority_binding(
    encoder: &mut StartupIdentityEncoder,
    binding: X64StandaloneAuthorityBinding,
) {
    encoder.u16(binding.profile.wire_tag());
    for hash in [
        binding.manifest_hash,
        binding.source_core_hash,
        binding.source_ssa_hash,
        binding.source_machine_ir_hash,
        binding.target_artifact_hash,
        binding.target_plan_hash,
        binding.target_code_hash,
        binding.canonical_abi_hash,
    ] {
        encoder.bytes(&hash.0);
    }
    encoder.u32(binding.entry_offset);
    encoder.u8(binding.input_lanes);
    encoder.bytes(&binding.semantic_results_hash.0);
    encoder.bytes(&binding.process_results_hash.0);
    encoder.u32(binding.canonical_case_count);
}

fn validate_authority_binding(
    profile: X64StandaloneProfile,
    binding: X64StandaloneAuthorityBinding,
) -> Result<(), X64StandaloneStartupError> {
    let expected_lanes = match profile {
        X64StandaloneProfile::BranchMix => 3,
        X64StandaloneProfile::Bounds => 2,
    };
    let expected_cases = match profile {
        X64StandaloneProfile::BranchMix => COREVM0_GATE_A_TOTAL_CASES - COREVM0_GATE_A_BOUNDS_CASES,
        X64StandaloneProfile::Bounds => COREVM0_GATE_A_BOUNDS_CASES,
    };
    if binding.profile != profile
        || binding.entry_offset != 0
        || binding.input_lanes != expected_lanes
        || binding.canonical_case_count != expected_cases
    {
        return Err(X64StandaloneStartupError::NonCanonicalPlan {
            field: "authority binding shape",
        });
    }
    if [
        binding.manifest_hash,
        binding.source_core_hash,
        binding.source_ssa_hash,
        binding.source_machine_ir_hash,
        binding.target_artifact_hash,
        binding.target_plan_hash,
        binding.target_code_hash,
        binding.canonical_abi_hash,
        binding.semantic_results_hash,
        binding.process_results_hash,
    ]
    .contains(&SemanticHash::ZERO)
    {
        return Err(X64StandaloneStartupError::NonCanonicalPlan {
            field: "authority binding hashes",
        });
    }
    Ok(())
}

fn encode_target(
    encoder: &mut StartupIdentityEncoder,
    target: &X64StandaloneStartupTarget,
) -> Result<(), X64StandaloneStartupError> {
    encoder.u64(X64_STANDALONE_ELF_BASE);
    encoder.u64(X64_STANDALONE_STARTUP_OFFSET);
    encoder.u64(X64_STANDALONE_STARTUP_ENTRY_VADDR);
    encoder.u64(target.target_offset);
    encoder.u32(target.inherited_entry_offset);
    encoder.u64(target.target_entry_vaddr);
    // Every descriptor enum has exactly one R1-S8-admitted value. Explicit
    // tags keep identity independent of Rust discriminants.
    encoder.bytes(&[0, 0, 0, 0, 0, 0]);
    encoder.u16(target.target_abi.pointer_bits);
    encoder.u32(target.target_abi.canonical_mxcsr);
    encoder.u32(target.target_abi.stack_alignment);
    encoder.length(
        "entry parameter types",
        target.entry_abi.parameter_types.len(),
    )?;
    for ty in &target.entry_abi.parameter_types {
        encoder.u8(machine_type_tag(*ty));
    }
    encoder.length("entry lanes", target.entry_abi.input_lanes.len())?;
    for lane in &target.entry_abi.input_lanes {
        encoder.u32(lane.parameter);
        encoder.u8(lane.word);
        encoder.u8(register_tag(lane.register));
    }
    encoder.u8(register_tag(target.entry_abi.output_register));
    encoder.u8(machine_type_tag(target.entry_abi.result));
    encoder.u8(target.entry_abi.output_words);
    encoder.u8(target.input_lanes);
    Ok(())
}

fn encode_operation(encoder: &mut StartupIdentityEncoder, operation: X64StandaloneStartupOp) {
    let (tag, status) = match operation {
        X64StandaloneStartupOp::AdmitProcessEntry => (0, None),
        X64StandaloneStartupOp::ReadHeaderExact => (1, None),
        X64StandaloneStartupOp::ValidateHeader => (2, None),
        X64StandaloneStartupOp::ValidatePayloadShape => (3, None),
        X64StandaloneStartupOp::MapPayloadIfNonEmpty => (4, None),
        X64StandaloneStartupOp::ReadPayloadExact => (5, None),
        X64StandaloneStartupOp::ProbeInputEof => (6, None),
        X64StandaloneStartupOp::ByteSwapPayloadU64InPlace => (7, None),
        X64StandaloneStartupOp::ProtectPayloadReadOnlyIfNonEmpty => (8, None),
        X64StandaloneStartupOp::EstablishCanonicalMxcsr => (9, None),
        X64StandaloneStartupOp::PrepareTypedTargetCall => (10, None),
        X64StandaloneStartupOp::CallTarget => (11, None),
        X64StandaloneStartupOp::ObserveAndValidateCanonicalMxcsr => (12, None),
        X64StandaloneStartupOp::ValidateTargetResult => (13, None),
        X64StandaloneStartupOp::UnmapPayloadIfNonEmpty => (14, None),
        X64StandaloneStartupOp::BuildCanonicalOutput => (15, None),
        X64StandaloneStartupOp::WriteOutputExact => (16, None),
        X64StandaloneStartupOp::CleanupPayloadIfMapped => (17, None),
        X64StandaloneStartupOp::ExitGroupThenTrap { status } => (18, Some(status)),
    };
    encoder.u8(tag);
    if let Some(status) = status {
        encoder.u8(status);
    }
}

fn encode_fixup(encoder: &mut StartupIdentityEncoder, fixup: X64StandaloneStartupFixupKind) {
    match fixup {
        X64StandaloneStartupFixupKind::ConditionalRel32 { condition, target } => {
            encoder.u8(0);
            encoder.u8(condition_tag(condition));
            encoder.u8(label_tag(target));
        }
        X64StandaloneStartupFixupKind::TargetCallRel32 { target_vaddr } => {
            encoder.u8(1);
            encoder.u64(target_vaddr);
        }
        X64StandaloneStartupFixupKind::UnconditionalRel32 { target } => {
            encoder.u8(2);
            encoder.u8(label_tag(target));
        }
    }
}

const fn label_tag(label: X64StandaloneStartupLabel) -> u8 {
    match label {
        X64StandaloneStartupLabel::Entry => 0,
        X64StandaloneStartupLabel::ReadHeader => 1,
        X64StandaloneStartupLabel::ValidateHeader => 2,
        X64StandaloneStartupLabel::ValidatePayload => 3,
        X64StandaloneStartupLabel::MapPayload => 4,
        X64StandaloneStartupLabel::ReadPayload => 5,
        X64StandaloneStartupLabel::ProbeEof => 6,
        X64StandaloneStartupLabel::SwapPayload => 7,
        X64StandaloneStartupLabel::ProtectPayload => 8,
        X64StandaloneStartupLabel::EstablishMxcsr => 9,
        X64StandaloneStartupLabel::PrepareTarget => 10,
        X64StandaloneStartupLabel::CallTarget => 11,
        X64StandaloneStartupLabel::ValidateMxcsr => 12,
        X64StandaloneStartupLabel::ValidateTarget => 13,
        X64StandaloneStartupLabel::UnmapPayload => 14,
        X64StandaloneStartupLabel::BuildOutput => 15,
        X64StandaloneStartupLabel::WriteOutput => 16,
        X64StandaloneStartupLabel::CleanupInput => 17,
        X64StandaloneStartupLabel::CleanupInvariant => 18,
        X64StandaloneStartupLabel::CleanupMemory => 19,
        X64StandaloneStartupLabel::CleanupIo => 20,
        X64StandaloneStartupLabel::ExitSuccess => 21,
        X64StandaloneStartupLabel::ExitInput => 22,
        X64StandaloneStartupLabel::ExitInvariant => 23,
        X64StandaloneStartupLabel::ExitMemory => 24,
        X64StandaloneStartupLabel::ExitIo => 25,
    }
}

const fn condition_tag(condition: X64StandaloneStartupCondition) -> u8 {
    match condition {
        X64StandaloneStartupCondition::ArgcMismatch => 0,
        X64StandaloneStartupCondition::SyscallEintr => 1,
        X64StandaloneStartupCondition::IoFailureOrTruncation => 2,
        X64StandaloneStartupCondition::InputRejected => 3,
        X64StandaloneStartupCondition::PayloadEmpty => 4,
        X64StandaloneStartupCondition::MemoryFailure => 5,
        X64StandaloneStartupCondition::TrailingInput => 6,
        X64StandaloneStartupCondition::InvalidTargetResult => 7,
        X64StandaloneStartupCondition::WriteRetry => 8,
        X64StandaloneStartupCondition::ReadIncomplete => 9,
        X64StandaloneStartupCondition::PayloadWordsRemain => 10,
        X64StandaloneStartupCondition::MappingAbsent => 11,
        X64StandaloneStartupCondition::NumericStateMismatch => 12,
    }
}

const fn register_tag(register: X64AbiRegister) -> u8 {
    match register {
        X64AbiRegister::Rdi => 0,
        X64AbiRegister::Rsi => 1,
        X64AbiRegister::Rdx => 2,
        X64AbiRegister::Rcx => 3,
        X64AbiRegister::R8 => 4,
        X64AbiRegister::R9 => 5,
    }
}

const fn machine_type_tag(ty: MachineType) -> u8 {
    match ty {
        MachineType::Unit => 0,
        MachineType::Bool => 1,
        MachineType::I64 => 2,
        MachineType::F64 => 3,
        MachineType::F64Array => 4,
    }
}

struct StartupIdentityEncoder {
    bytes: Vec<u8>,
    field: &'static str,
    limit: usize,
    overflow: Option<usize>,
}

impl StartupIdentityEncoder {
    fn new(field: &'static str) -> Result<Self, X64StandaloneStartupError> {
        Self::with_capacity(field, 4_096)
    }

    fn with_capacity(
        field: &'static str,
        reserve: usize,
    ) -> Result<Self, X64StandaloneStartupError> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(reserve).map_err(|_| {
            X64StandaloneStartupError::AllocationFailed {
                field,
                bytes: reserve,
            }
        })?;
        Ok(Self {
            bytes,
            field,
            limit: reserve,
            overflow: None,
        })
    }

    fn bytes(&mut self, value: &[u8]) {
        if self.overflow.is_some() {
            return;
        }
        let Some(actual) = self.bytes.len().checked_add(value.len()) else {
            self.overflow = Some(usize::MAX);
            return;
        };
        if actual > self.limit {
            self.overflow = Some(actual);
            return;
        }
        self.bytes.extend_from_slice(value);
    }

    fn u8(&mut self, value: u8) {
        self.bytes(&[value]);
    }

    fn boolean(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn u16(&mut self, value: u16) {
        self.bytes(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes(&value.to_be_bytes());
    }

    fn version(&mut self, version: (u16, u16, u16)) {
        self.u16(version.0);
        self.u16(version.1);
        self.u16(version.2);
    }

    fn length(
        &mut self,
        field: &'static str,
        actual: usize,
    ) -> Result<(), X64StandaloneStartupError> {
        let length = u32::try_from(actual)
            .map_err(|_| X64StandaloneStartupError::LengthOverflow { field, actual })?;
        self.u32(length);
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>, X64StandaloneStartupError> {
        if let Some(actual) = self.overflow {
            return Err(X64StandaloneStartupError::IdentityByteLimit {
                field: self.field,
                limit: self.limit,
                actual,
            });
        }
        Ok(self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TARGET_OFFSET: u64 = 0x2000;

    fn test_authority_binding(profile: X64StandaloneProfile) -> X64StandaloneAuthorityBinding {
        let base = match profile {
            X64StandaloneProfile::BranchMix => 0x10,
            X64StandaloneProfile::Bounds => 0x40,
        };
        let hash = |offset: u8| SemanticHash([base + offset; 32]);
        X64StandaloneAuthorityBinding {
            profile,
            manifest_hash: hash(0),
            source_core_hash: hash(1),
            source_ssa_hash: hash(2),
            source_machine_ir_hash: hash(3),
            target_artifact_hash: hash(4),
            target_plan_hash: hash(5),
            target_code_hash: hash(6),
            canonical_abi_hash: hash(7),
            entry_offset: 0,
            input_lanes: match profile {
                X64StandaloneProfile::BranchMix => 3,
                X64StandaloneProfile::Bounds => 2,
            },
            semantic_results_hash: hash(8),
            process_results_hash: hash(9),
            canonical_case_count: match profile {
                X64StandaloneProfile::BranchMix => 46,
                X64StandaloneProfile::Bounds => 5,
            },
        }
    }

    fn plan(profile: X64StandaloneProfile) -> X64StandaloneStartupPlan {
        plan_from_target_parts(
            profile,
            TEST_TARGET_OFFSET,
            0,
            X64TargetAbi::r1_s7a(),
            canonical_entry_abi(profile),
            test_authority_binding(profile),
        )
        .expect("canonical startup plan")
    }

    #[test]
    fn frozen_raw_lengths_derive_the_same_aligned_target_offset() {
        for profile in [
            X64StandaloneProfile::BranchMix,
            X64StandaloneProfile::Bounds,
        ] {
            let startup_end = X64_STANDALONE_STARTUP_OFFSET + canonical_raw_code_bytes(profile);
            let target_offset = (startup_end + X64_STANDALONE_TARGET_ALIGNMENT - 1)
                & !(X64_STANDALONE_TARGET_ALIGNMENT - 1);
            assert_eq!(target_offset, 0x510);
        }
    }

    #[test]
    fn both_profiles_have_complete_bounded_canonical_plans() {
        for profile in [
            X64StandaloneProfile::BranchMix,
            X64StandaloneProfile::Bounds,
        ] {
            let plan = plan(profile);
            let verified =
                verify_x64_standalone_startup_plan_local_r1_s8(&plan).expect("plan verifies");
            assert_eq!(verified.plan_hash(), plan.plan_hash());
            assert_eq!(plan.profile(), profile);
            assert_eq!(plan.target_offset(), TEST_TARGET_OFFSET);
            assert_eq!(
                plan.target_entry_vaddr(),
                X64_STANDALONE_ELF_BASE + TEST_TARGET_OFFSET
            );
            assert_eq!(plan.usage().ops(), 26);
            assert_eq!(plan.usage().labels(), 32);
            assert_eq!(
                plan.usage().fixups(),
                match profile {
                    X64StandaloneProfile::BranchMix => 58,
                    X64StandaloneProfile::Bounds => 59,
                }
            );
            assert_eq!(plan.usage().internal_call_fixups(), 4);
            assert_eq!(plan.usage().target_call_fixups(), 1);
            assert_eq!(plan.usage().syscall_sites(), 8);
            assert_eq!(
                plan.usage().code_bytes(),
                match profile {
                    X64StandaloneProfile::BranchMix => 1_032,
                    X64StandaloneProfile::Bounds => 1_038,
                }
            );
            assert_eq!(plan.usage().stack_bytes(), STARTUP_STACK_WORST_REACH_BYTES);
            assert!(plan.usage().ops() <= plan.limits().max_ops());
            assert!(plan.usage().labels() <= plan.limits().max_labels());
            assert!(plan.usage().fixups() <= plan.limits().max_fixups());
            assert!(plan.stack().frame_bytes() <= plan.limits().max_stack_bytes());
        }
    }

    #[test]
    fn profile_selects_exact_inherited_entry_abi() {
        let branch = plan(X64StandaloneProfile::BranchMix);
        assert_eq!(
            branch.entry_abi().parameter_types,
            [MachineType::F64Array, MachineType::I64]
        );
        assert_eq!(branch.input_lanes(), 3);
        assert_eq!(branch.entry_abi().output_register, X64AbiRegister::Rcx);

        let bounds = plan(X64StandaloneProfile::Bounds);
        assert_eq!(bounds.entry_abi().parameter_types, [MachineType::F64Array]);
        assert_eq!(bounds.input_lanes(), 2);
        assert_eq!(bounds.entry_abi().output_register, X64AbiRegister::Rdx);
    }

    #[test]
    fn target_facts_fail_closed() {
        let profile = X64StandaloneProfile::BranchMix;
        for offset in [
            X64_STANDALONE_STARTUP_OFFSET,
            X64_STANDALONE_STARTUP_OFFSET + 1,
            X64_STANDALONE_MAX_ELF_IMAGE_BYTES,
        ] {
            assert!(matches!(
                plan_from_target_parts(
                    profile,
                    offset,
                    0,
                    X64TargetAbi::r1_s7a(),
                    canonical_entry_abi(profile),
                    test_authority_binding(profile),
                ),
                Err(X64StandaloneStartupError::TargetOffset { actual }) if actual == offset
            ));
        }
        assert!(matches!(
            plan_from_target_parts(
                profile,
                TEST_TARGET_OFFSET,
                1,
                X64TargetAbi::r1_s7a(),
                canonical_entry_abi(profile),
                test_authority_binding(profile),
            ),
            Err(X64StandaloneStartupError::InvalidEntryOffset { actual: 1 })
        ));

        let mut wrong_abi = canonical_entry_abi(profile);
        wrong_abi.output_register = X64AbiRegister::Rdx;
        assert!(matches!(
            plan_from_target_parts(
                profile,
                TEST_TARGET_OFFSET,
                0,
                X64TargetAbi::r1_s7a(),
                wrong_abi,
                test_authority_binding(profile),
            ),
            Err(X64StandaloneStartupError::InvalidEntryAbi {
                profile: X64StandaloneProfile::BranchMix,
            })
        ));
    }

    #[test]
    fn plan_identity_is_deterministic_and_domain_separated() {
        let branch_a = plan(X64StandaloneProfile::BranchMix);
        let branch_b = plan(X64StandaloneProfile::BranchMix);
        let bounds = plan(X64StandaloneProfile::Bounds);
        assert_eq!(
            x64_standalone_startup_plan_bytes(&branch_a).expect("plan bytes"),
            x64_standalone_startup_plan_bytes(&branch_b).expect("plan bytes")
        );
        assert_eq!(branch_a.plan_hash(), branch_b.plan_hash());
        assert_ne!(branch_a.plan_hash(), bounds.plan_hash());

        let plan_bytes = x64_standalone_startup_plan_bytes(&branch_a).expect("plan bytes");
        assert!(plan_bytes.starts_with(STARTUP_PLAN_DOMAIN));
        let io_bytes =
            x64_standalone_io_contract_bytes(branch_a.profile()).expect("I/O contract bytes");
        assert!(io_bytes.starts_with(IO_CONTRACT_DOMAIN));
        assert_eq!(
            branch_a.io_contract_hash(),
            x64_standalone_io_contract_hash(branch_a.profile()).expect("I/O contract hash")
        );
        assert_ne!(
            branch_a.io_contract_hash(),
            x64_standalone_io_contract_hash(bounds.profile()).expect("Bounds I/O contract hash")
        );
        let sample_code_hash =
            x64_standalone_startup_code_hash(branch_a.plan_hash(), &[0x0f, 0x05])
                .expect("bounded sample hashes");
        assert_ne!(branch_a.plan_hash(), sample_code_hash);
    }

    #[test]
    fn mutations_are_rejected_even_when_a_hash_is_resealed() {
        let mut schema_mutation = plan(X64StandaloneProfile::Bounds);
        schema_mutation.schema_version = (2, 0, 0);
        schema_mutation.plan_hash =
            x64_standalone_startup_plan_hash(&schema_mutation).expect("mutation rehashes");
        assert!(matches!(
            verify_x64_standalone_startup_plan_local_r1_s8(&schema_mutation),
            Err(X64StandaloneStartupError::InvalidSchema {
                field: "schema",
                actual: (2, 0, 0),
            })
        ));

        let mut fixup_mutation = plan(X64StandaloneProfile::Bounds);
        fixup_mutation.fixups.pop();
        fixup_mutation.plan_hash =
            x64_standalone_startup_plan_hash(&fixup_mutation).expect("mutation rehashes");
        assert!(matches!(
            verify_x64_standalone_startup_plan_local_r1_s8(&fixup_mutation),
            Err(X64StandaloneStartupError::NonCanonicalPlan {
                field: "control fixups",
            })
        ));

        let mut hash_mutation = plan(X64StandaloneProfile::Bounds);
        hash_mutation.plan_hash.0[0] ^= 1;
        assert!(matches!(
            verify_x64_standalone_startup_plan_local_r1_s8(&hash_mutation),
            Err(X64StandaloneStartupError::PlanHashMismatch)
        ));

        let mut lowering_mutation = plan(X64StandaloneProfile::BranchMix);
        lowering_mutation.lowering.target_call_displacement ^= 1;
        lowering_mutation.plan_hash =
            x64_standalone_startup_plan_hash(&lowering_mutation).expect("mutation rehashes");
        assert!(matches!(
            verify_x64_standalone_startup_plan_local_r1_s8(&lowering_mutation),
            Err(X64StandaloneStartupError::NonCanonicalPlan {
                field: "concrete lowering receipt",
            })
        ));

        let mut authority_mutation = plan(X64StandaloneProfile::Bounds);
        authority_mutation.authority_binding.target_code_hash = SemanticHash::ZERO;
        authority_mutation.plan_hash =
            x64_standalone_startup_plan_hash(&authority_mutation).expect("mutation rehashes");
        assert!(matches!(
            verify_x64_standalone_startup_plan_local_r1_s8(&authority_mutation),
            Err(X64StandaloneStartupError::NonCanonicalPlan {
                field: "authority binding hashes",
            })
        ));

        let mut io_hash_mutation = plan(X64StandaloneProfile::Bounds);
        io_hash_mutation.io_contract_hash.0[0] ^= 1;
        io_hash_mutation.plan_hash =
            x64_standalone_startup_plan_hash(&io_hash_mutation).expect("mutation rehashes");
        assert!(matches!(
            verify_x64_standalone_startup_plan_local_r1_s8(&io_hash_mutation),
            Err(X64StandaloneStartupError::NonCanonicalPlan {
                field: "I/O contract hash",
            })
        ));
    }

    #[test]
    fn exact_usage_caps_and_target_call_count_are_enforced() {
        let limits = X64StandaloneStartupLimits::r1_s8();
        let mut usage = plan(X64StandaloneProfile::BranchMix).usage();
        usage.ops = limits.max_ops;
        usage.labels = limits.max_labels;
        usage.fixups = limits.max_fixups;
        usage.stack_bytes = limits.max_stack_bytes;
        validate_usage(usage, limits).expect("exact caps are valid");

        usage.ops = limits.max_ops + 1;
        assert!(matches!(
            validate_usage(usage, limits),
            Err(X64StandaloneStartupError::Limit {
                field: "operations",
                limit: X64_STANDALONE_STARTUP_MAX_OPS,
                actual,
            }) if actual == X64_STANDALONE_STARTUP_MAX_OPS + 1
        ));

        let mut usage = plan(X64StandaloneProfile::BranchMix).usage();
        usage.target_call_fixups = 0;
        assert!(matches!(
            validate_usage(usage, limits),
            Err(X64StandaloneStartupError::TargetCallFixupCount {
                expected: 1,
                actual: 0,
            })
        ));
    }

    #[test]
    fn startup_code_hash_enforces_nonempty_exact_cap() {
        let plan = plan(X64StandaloneProfile::Bounds);
        assert_eq!(
            x64_standalone_startup_code_hash(plan.plan_hash(), &[]),
            Err(X64StandaloneStartupError::EmptyStartupCode)
        );
        let exact = vec![0x90; X64_STANDALONE_STARTUP_MAX_CODE_BYTES as usize];
        x64_standalone_startup_code_hash(plan.plan_hash(), &exact).expect("exact code cap hashes");
        let one_over = vec![0x90; X64_STANDALONE_STARTUP_MAX_CODE_BYTES as usize + 1];
        assert!(matches!(
            x64_standalone_startup_code_hash(plan.plan_hash(), &one_over),
            Err(X64StandaloneStartupError::CodeByteLimit {
                limit: X64_STANDALONE_STARTUP_MAX_CODE_BYTES,
                actual,
            }) if actual == one_over.len()
        ));
    }

    #[test]
    fn identity_encoder_never_grows_past_its_fallible_reservation() {
        let mut encoder =
            StartupIdentityEncoder::with_capacity("test identity", 1).expect("one byte reserve");
        encoder.u8(1);
        encoder.u8(2);
        assert!(matches!(
            encoder.finish(),
            Err(X64StandaloneStartupError::IdentityByteLimit {
                field: "test identity",
                limit: 1,
                actual: 2,
            })
        ));
    }

    #[test]
    fn local_plan_verification_does_not_mint_authority_or_executable_bytes() {
        let plan = plan(X64StandaloneProfile::BranchMix);
        let verified =
            verify_x64_standalone_startup_plan_local_r1_s8(&plan).expect("plan verifies");
        assert_eq!(verified.plan(), &plan);
        assert_eq!(verified.plan_hash(), plan.plan_hash());
    }

    #[test]
    fn typed_startup_contract_orders_admission_protection_call_unmap_and_output() {
        use X64StandaloneStartupCondition as Condition;
        use X64StandaloneStartupLabel as Label;
        use X64StandaloneStartupOp as Op;

        for profile in [
            X64StandaloneProfile::BranchMix,
            X64StandaloneProfile::Bounds,
        ] {
            let plan = plan(profile);
            assert_eq!(plan.io.required_argc, 1);
            assert_eq!(plan.io.mmap_protection, PROT_READ | PROT_WRITE);
            assert_eq!(plan.io.mprotect_protection, PROT_READ);
            assert_eq!(plan.io.raw_syscall_error_floor, -4095);
            assert!(plan.io.retry_eintr);
            assert!(plan.io.exact_eof);
            assert!(plan.io.no_stderr);

            let operations: Vec<_> = plan.operations().collect();
            let operation_index = |needle| {
                operations
                    .iter()
                    .position(|operation| *operation == needle)
                    .expect("canonical operation")
            };
            assert!(operation_index(Op::AdmitProcessEntry) < operation_index(Op::ReadHeaderExact));
            assert!(
                operation_index(Op::ByteSwapPayloadU64InPlace)
                    < operation_index(Op::ProtectPayloadReadOnlyIfNonEmpty)
            );
            assert!(
                operation_index(Op::ProtectPayloadReadOnlyIfNonEmpty)
                    < operation_index(Op::CallTarget)
            );
            assert!(operation_index(Op::CallTarget) < operation_index(Op::UnmapPayloadIfNonEmpty));
            assert!(
                operation_index(Op::UnmapPayloadIfNonEmpty)
                    < operation_index(Op::BuildCanonicalOutput)
            );
            assert!(
                operation_index(Op::BuildCanonicalOutput) < operation_index(Op::WriteOutputExact)
            );

            let expected_edges = [
                conditional(Label::Entry, Condition::ArgcMismatch, Label::ExitInput),
                conditional(
                    Label::MapPayload,
                    Condition::MemoryFailure,
                    Label::ExitMemory,
                ),
                conditional(
                    Label::ProtectPayload,
                    Condition::MemoryFailure,
                    Label::CleanupMemory,
                ),
                conditional(
                    Label::ValidateTarget,
                    Condition::InvalidTargetResult,
                    Label::CleanupInvariant,
                ),
                conditional(
                    Label::UnmapPayload,
                    Condition::MappingAbsent,
                    Label::BuildOutput,
                ),
                conditional(
                    Label::UnmapPayload,
                    Condition::MemoryFailure,
                    Label::ExitMemory,
                ),
            ];
            for edge in expected_edges {
                assert!(
                    plan.fixups().contains(&edge),
                    "typed startup edge {edge:?} must be sealed"
                );
            }
        }
    }
}
