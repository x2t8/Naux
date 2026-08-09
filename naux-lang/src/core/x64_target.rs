//! Canonical x86-64 target plan and checked raw encoding for R1-S7A.
//!
//! This module does not import the bridge VM, trace JIT, NaN-boxed values,
//! executable-memory loader, host callbacks, or `egg`. It accepts only the
//! exact source-bound R1-S6 Machine IR lighthouse envelope, assigns a fixed
//! stack-home layout, emits immutable position-independent x86-64 bytes, and
//! retains every internal rel32 fixup for deterministic replay. Execution of
//! those bytes is deliberately outside R1-S7A.

use super::core_ssa::CoreSsaArtifact;
use super::encoding::{canonical_f64_bits, sha256};
use super::interpret::{CoreValue, EffectEvent, Evaluation, EvaluationBudget, EvaluationOutcome};
use super::machine_ir::{
    verify_machine_ir, verify_machine_ir_source, MachineBlockId, MachineEffect, MachineF64BinaryOp,
    MachineFunctionId, MachineI64BinaryOp, MachineI64CompareOp, MachineInstructionKind,
    MachineIntegerMode, MachineIrArtifact, MachineIrSourceError, MachineIrVerificationErrors,
    MachineOperand, MachineTerminator, MachineType, SourceBoundMachineIrArtifact,
};
use super::schema::{CoreArtifact, ErrorKind, SemanticHash};
use home_layout::{
    allocate_canonical_home_layout, CanonicalHomeArgument, CanonicalHomeFunction,
    CanonicalHomeLayoutError, CanonicalHomeLayoutLimits, CanonicalHomeLayoutPolicy,
    CanonicalHomeProgram, CanonicalHomeTail,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub(crate) mod candidate;
mod eval;
mod home_layout;
mod profile;
mod prospective_semantics;
mod raw;

pub(crate) use candidate::{
    reconstruct_frozen_x64_target_policy15_candidate_for_process,
    reconstruct_frozen_x64_target_policy15_candidate_for_standalone,
    ProcessReconstructedX64TargetPolicy15Candidate,
    StandaloneReconstructedX64TargetPolicy15Candidate,
};
pub use candidate::{
    x64_target_policy15_accepted_candidate_capsule_hash,
    x64_target_policy15_candidate_capsule_hash, VerifiedX64TargetPolicy15CandidateCapsule,
    X64TargetPolicy15CandidateCapsule, X64TargetPolicy15CandidateError,
    X64_TARGET_POLICY15_CANDIDATE_POLICY_VERSION, X64_TARGET_POLICY15_CANDIDATE_SCHEMA_VERSION,
    X64_TARGET_POLICY15_ENCODER_POLICY_VERSION,
};

pub use eval::PlanExecutionError as X64TargetPlanEvaluatorError;
pub use profile::{
    profile_source_bound_x64_target_plan, profile_x64_target_plan,
    x64_target_prospective_shared_join_realization_hash, X64TargetExecutionProfile,
    X64TargetProfileBlockCount, X64TargetProfileClassTotal, X64TargetProfileControlCounts,
    X64TargetProfileEdgeCount, X64TargetProfileError, X64TargetProfileEvent,
    X64TargetProfileInstructionCounts, X64TargetProfileSite, X64TargetProfileTemplateClass,
    X64TargetProfiledEvaluation, X64TargetProspectiveExecutionAuthority,
    X64TargetProspectiveFixupReceipt, X64TargetProspectiveLabelDisposition,
    X64TargetProspectiveLabelReceipt, X64TargetProspectiveMachineSemanticProof,
    X64TargetProspectiveRealizationAtom, X64TargetProspectiveSharedJoinPartition,
    X64TargetProspectiveSharedJoinRealization, X64TargetSharedJoinBranchArmCounts,
    X64TargetSharedJoinComposition, X64TargetSharedJoinCompositionIngress,
    X64TargetSharedJoinCompositionStep, X64TargetSharedJoinIngress, X64TargetSharedJoinKind,
    X64TargetSharedJoinOpportunity, X64TargetSharedJoinRouteEvent,
    X64_TARGET_PROFILE_POLICY_VERSION, X64_TARGET_PROFILE_SCHEMA_VERSION,
};

pub const X64_TARGET_SCHEMA_NAME: &str = "naux-x86-64-target";
pub const X64_TARGET_SCHEMA_VERSION: (u16, u16, u16) = (0, 1, 0);
pub const X64_TARGET_LOWERING_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TARGET_ENCODER_POLICY_VERSION: (u16, u16, u16) = (1, 4, 0);

pub const X64_TARGET_MAX_SOURCE_FUNCTIONS: u64 = 16_384;
pub const X64_TARGET_MAX_SOURCE_BLOCKS: u64 = 1_000_000;
pub const X64_TARGET_MAX_SOURCE_INSTRUCTIONS: u64 = 1_000_000;
pub const X64_TARGET_MAX_OPS: u64 = 8_000_000;
pub const X64_TARGET_MAX_LABELS: u64 = 1_100_000;
pub const X64_TARGET_MAX_FIXUPS: u64 = 2_000_000;
pub const X64_TARGET_MAX_CODE_BYTES: u64 = 64 * 1024 * 1024;
pub const X64_TARGET_MAX_SEMANTIC_BYTES: u64 = 128 * 1024 * 1024;
pub const X64_TARGET_MAX_FRAME_BYTES: u32 = 4_096;
pub const X64_TARGET_MAX_OUTGOING_BYTES: u32 = 4_096;
pub const X64_TARGET_MAX_ENTRY_INPUT_LANES: u32 = 5;
pub const X64_TARGET_MAX_LOWERING_WORK: u64 = 32_000_000;
pub const X64_TARGET_MAX_PLAN_EVAL_WORK: u64 = 100_000_000;
pub const X64_TARGET_MAX_PROFILE_EVAL_WORK: u64 = 2_600_000_000;
pub const X64_TARGET_MAX_CFG_DEPTH: u32 = 512;
pub const X64_TARGET_MAX_DIAGNOSTICS: usize = 256;
pub const X64_TARGET_CORRESPONDENCE_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TARGET_MAX_CORRESPONDENCE_RECORDS: u32 = 64;
pub const X64_TARGET_MAX_CORRESPONDENCE_EFFECTS_PER_ENGINE: u32 = 1;

const X64_TARGET_PLAN_DOMAIN: &[u8] = b"NAUX:x86-64:r1-s7a:plan:v1\0";
const X64_TARGET_CODE_DOMAIN: &[u8] = b"NAUX:x86-64:r1-s7a:code:v1\0";
const X64_TARGET_SEMANTIC_DOMAIN: &[u8] = b"NAUX:x86-64:r1-s7a:artifact:v1\0";
const X64_TARGET_CORRESPONDENCE_RECORD_DOMAIN: &[u8] =
    b"NAUX:x86-64:r1-s7a:correspondence:record:v1\0";
const X64_TARGET_CORRESPONDENCE_RESULTS_DOMAIN: &[u8] =
    b"NAUX:x86-64:r1-s7a:correspondence:results:v1\0";
const X64_CANONICAL_MXCSR: u32 = 0x0000_1f80;
const X64_FRAME_HEADER_BYTES: u32 = 32;
const X64_STACK_ALIGNMENT: u32 = 16;
const X64_CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TargetSchemaVersion {
    pub name: String,
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl X64TargetSchemaVersion {
    pub fn r1_s7a() -> Self {
        Self {
            name: X64_TARGET_SCHEMA_NAME.to_owned(),
            major: X64_TARGET_SCHEMA_VERSION.0,
            minor: X64_TARGET_SCHEMA_VERSION.1,
            patch: X64_TARGET_SCHEMA_VERSION.2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TargetArchitecture {
    X86_64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TargetOperatingSystem {
    Linux,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TargetEndian {
    Little,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TargetCallingConvention {
    NauxLighthouseSysV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TargetFeatureProfile {
    X86_64Sse2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TargetCodeModel {
    PositionIndependentSingleBlob,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TargetAbi {
    pub architecture: X64TargetArchitecture,
    pub operating_system: X64TargetOperatingSystem,
    pub endian: X64TargetEndian,
    pub pointer_bits: u16,
    pub calling_convention: X64TargetCallingConvention,
    pub feature_profile: X64TargetFeatureProfile,
    pub code_model: X64TargetCodeModel,
    pub canonical_mxcsr: u32,
    pub stack_alignment: u32,
}

impl X64TargetAbi {
    pub const fn r1_s7a() -> Self {
        Self {
            architecture: X64TargetArchitecture::X86_64,
            operating_system: X64TargetOperatingSystem::Linux,
            endian: X64TargetEndian::Little,
            pointer_bits: 64,
            calling_convention: X64TargetCallingConvention::NauxLighthouseSysV1,
            feature_profile: X64TargetFeatureProfile::X86_64Sse2,
            code_model: X64TargetCodeModel::PositionIndependentSingleBlob,
            canonical_mxcsr: X64_CANONICAL_MXCSR,
            stack_alignment: X64_STACK_ALIGNMENT,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TargetLimits {
    pub max_source_functions: u64,
    pub max_source_blocks: u64,
    pub max_source_instructions: u64,
    pub max_ops: u64,
    pub max_labels: u64,
    pub max_fixups: u64,
    pub max_code_bytes: u64,
    pub max_semantic_bytes: u64,
    pub max_frame_bytes: u32,
    pub max_outgoing_bytes: u32,
    pub max_entry_input_lanes: u32,
    pub max_lowering_work: u64,
    pub max_plan_eval_work: u64,
    pub max_cfg_depth: u32,
    pub max_diagnostics: u32,
}

impl X64TargetLimits {
    pub const fn r1_s7a() -> Self {
        Self {
            max_source_functions: X64_TARGET_MAX_SOURCE_FUNCTIONS,
            max_source_blocks: X64_TARGET_MAX_SOURCE_BLOCKS,
            max_source_instructions: X64_TARGET_MAX_SOURCE_INSTRUCTIONS,
            max_ops: X64_TARGET_MAX_OPS,
            max_labels: X64_TARGET_MAX_LABELS,
            max_fixups: X64_TARGET_MAX_FIXUPS,
            max_code_bytes: X64_TARGET_MAX_CODE_BYTES,
            max_semantic_bytes: X64_TARGET_MAX_SEMANTIC_BYTES,
            max_frame_bytes: X64_TARGET_MAX_FRAME_BYTES,
            max_outgoing_bytes: X64_TARGET_MAX_OUTGOING_BYTES,
            max_entry_input_lanes: X64_TARGET_MAX_ENTRY_INPUT_LANES,
            max_lowering_work: X64_TARGET_MAX_LOWERING_WORK,
            max_plan_eval_work: X64_TARGET_MAX_PLAN_EVAL_WORK,
            max_cfg_depth: X64_TARGET_MAX_CFG_DEPTH,
            max_diagnostics: X64_TARGET_MAX_DIAGNOSTICS as u32,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64AbiRegister {
    Rdi,
    Rsi,
    Rdx,
    Rcx,
    R8,
    R9,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64EntryLane {
    pub parameter: u32,
    pub word: u8,
    pub register: X64AbiRegister,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64EntryAbi {
    pub parameter_types: Vec<MachineType>,
    pub input_lanes: Vec<X64EntryLane>,
    pub output_register: X64AbiRegister,
    pub result: MachineType,
    pub output_words: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct X64FunctionId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct X64BlockId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct X64LabelId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct X64HomeSlot(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64FrameLayout {
    pub header_bytes: u32,
    pub home_base: u32,
    pub max_home_bytes: u32,
    pub outgoing_base: u32,
    pub outgoing_bytes: u32,
    pub frame_bytes: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64Home {
    pub slot: X64HomeSlot,
    pub offset: u32,
    pub width: u8,
    pub ty: MachineType,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TargetArtifact {
    pub program: X64TargetProgram,
    pub semantic_hash: SemanticHash,
}

impl X64TargetArtifact {
    pub fn seal(mut program: X64TargetProgram) -> Result<Self, X64TargetEncodeError> {
        program.plan_hash = x64_target_plan_hash(&program)?;
        program.code_hash = x64_target_code_hash(&program.code)?;
        let semantic_hash = x64_target_semantic_hash(&program)?;
        Ok(Self {
            program,
            semantic_hash,
        })
    }
}

/// Canonical finite-validation result for the R1-S7a Machine IR and target
/// plan evaluators. Every non-NaN value retains its exact IEEE-754 bits,
/// including signed zero; NaN payload identity is deliberately unobservable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TargetCorrespondenceF64 {
    ExactBits(u64),
    CanonicalNaN,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TargetCorrespondenceOutcome {
    ReturnF64(X64TargetCorrespondenceF64),
    Bounds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TargetCorrespondenceEffect {
    Bounds,
}

/// Work counters are intentionally excluded: R1-S7a correspondence binds
/// semantic outcomes and ordered effects, not engine-local telemetry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TargetCorrespondenceObservation {
    pub outcome: X64TargetCorrespondenceOutcome,
    pub effect_trace: Vec<X64TargetCorrespondenceEffect>,
}

/// One independently sealed Machine IR ↔ target-plan observation.
///
/// `source_machine_ir_hash` and `target_plan_hash` prevent observations from
/// being replayed against a different translation. `case_ordinal` and
/// `input_hash` bind the result to its exact canonical corpus position/input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TargetCorrespondenceRecord {
    pub schema_version: (u16, u16, u16),
    pub case_ordinal: u32,
    pub input_hash: SemanticHash,
    pub source_machine_ir_hash: SemanticHash,
    pub target_plan_hash: SemanticHash,
    pub machine_ir: X64TargetCorrespondenceObservation,
    pub target_plan: X64TargetCorrespondenceObservation,
    pub record_hash: SemanticHash,
}

/// Order-sensitive bounded evidence over a caller-executed finite corpus.
///
/// This is validation evidence, not a proof over an unbounded input domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TargetCorrespondenceEvidence {
    pub schema_version: (u16, u16, u16),
    pub records: Vec<X64TargetCorrespondenceRecord>,
    pub results_hash: SemanticHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TargetCorrespondenceError {
    InvalidMachineIr(MachineIrVerificationErrors),
    InvalidTarget(X64TargetVerificationErrors),
    SourceMachineIrHashMismatch {
        declared: SemanticHash,
        actual: SemanticHash,
    },
    RecordLimit {
        limit: u32,
        actual: u32,
    },
    EffectLimit {
        engine: &'static str,
        case_ordinal: u32,
        limit: u32,
        actual: u32,
    },
    InvalidSchema {
        actual: (u16, u16, u16),
    },
    NonCanonicalOrdinal {
        expected: u32,
        actual: u32,
    },
    UnsupportedOutcome {
        engine: &'static str,
        case_ordinal: u32,
    },
    UnsupportedEffect {
        engine: &'static str,
        case_ordinal: u32,
    },
    NonCanonicalObservation {
        engine: &'static str,
        case_ordinal: u32,
    },
    SemanticMismatch {
        case_ordinal: u32,
    },
    RecordHashMismatch {
        case_ordinal: u32,
    },
    ResultsHashMismatch,
    MetricOverflow,
}

impl fmt::Display for X64TargetCorrespondenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMachineIr(errors) => write!(
                formatter,
                "R1-S7a correspondence source Machine IR is invalid: {errors}"
            ),
            Self::InvalidTarget(errors) => {
                write!(formatter, "R1-S7a correspondence target is invalid: {errors}")
            }
            Self::SourceMachineIrHashMismatch { declared, actual } => write!(
                formatter,
                "R1-S7a target declares source Machine IR {declared}; supplied source is {actual}"
            ),
            Self::RecordLimit { limit, actual } => write!(
                formatter,
                "R1-S7a correspondence record count/ordinal {actual} exceeds hard cap {limit}"
            ),
            Self::EffectLimit {
                engine,
                case_ordinal,
                limit,
                actual,
            } => write!(
                formatter,
                "{engine} effect count {actual} in R1-S7a case {case_ordinal} exceeds hard cap {limit}"
            ),
            Self::InvalidSchema { actual } => write!(
                formatter,
                "R1-S7a correspondence schema {actual:?} is not canonical"
            ),
            Self::NonCanonicalOrdinal { expected, actual } => write!(
                formatter,
                "R1-S7a correspondence expected case ordinal {expected}, found {actual}"
            ),
            Self::UnsupportedOutcome {
                engine,
                case_ordinal,
            } => write!(
                formatter,
                "{engine} produced an unsupported R1-S7a outcome in case {case_ordinal}"
            ),
            Self::UnsupportedEffect {
                engine,
                case_ordinal,
            } => write!(
                formatter,
                "{engine} produced an unsupported R1-S7a effect in case {case_ordinal}"
            ),
            Self::NonCanonicalObservation {
                engine,
                case_ordinal,
            } => write!(
                formatter,
                "{engine} produced a non-canonical R1-S7a observation in case {case_ordinal}"
            ),
            Self::SemanticMismatch { case_ordinal } => write!(
                formatter,
                "Machine IR and target plan differ in R1-S7a case {case_ordinal}"
            ),
            Self::RecordHashMismatch { case_ordinal } => write!(
                formatter,
                "R1-S7a correspondence record {case_ordinal} has an invalid seal"
            ),
            Self::ResultsHashMismatch => {
                formatter.write_str("R1-S7a correspondence results hash is invalid")
            }
            Self::MetricOverflow => {
                formatter.write_str("R1-S7a correspondence checked metric overflow")
            }
        }
    }
}

impl std::error::Error for X64TargetCorrespondenceError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TargetProgram {
    pub schema: X64TargetSchemaVersion,
    pub lowering_policy_version: (u16, u16, u16),
    pub encoder_policy_version: (u16, u16, u16),
    pub abi: X64TargetAbi,
    pub limits: X64TargetLimits,
    pub source_core_hash: SemanticHash,
    pub source_ssa_hash: SemanticHash,
    pub source_machine_ir_hash: SemanticHash,
    pub entry: X64FunctionId,
    pub entry_offset: u32,
    pub entry_abi: X64EntryAbi,
    pub frame: X64FrameLayout,
    pub functions: Vec<X64Function>,
    pub labels: Vec<X64Label>,
    pub fixups: Vec<X64Fixup>,
    pub code: Vec<u8>,
    pub plan_hash: SemanticHash,
    pub code_hash: SemanticHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64Function {
    pub id: X64FunctionId,
    pub parameters: Vec<X64Parameter>,
    pub effects: Vec<MachineEffect>,
    pub result: MachineType,
    pub entry_block: X64BlockId,
    pub blocks: Vec<X64Block>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64Parameter {
    pub home: X64Home,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64Block {
    pub id: X64BlockId,
    pub label: X64LabelId,
    pub instructions: Vec<X64Instruction>,
    pub terminator: X64Terminator,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64Instruction {
    pub origin: X64SourceOrigin,
    pub result: X64Home,
    pub kind: X64InstructionKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64SourcePosition {
    Instruction(u32),
    Terminator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64SourceOrigin {
    pub function: X64FunctionId,
    pub block: X64BlockId,
    pub position: X64SourcePosition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64I64Opcode {
    Add,
    Sub,
    Mul,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64Sse2F64Opcode {
    AddSd,
    SubSd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64SetCondition {
    SignedLessThan,
    SignedGreaterOrEqual,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64InstructionKind {
    Move(X64Operand),
    I64Wrapping {
        opcode: X64I64Opcode,
        left: X64Operand,
        right: X64Operand,
    },
    Sse2F64 {
        opcode: X64Sse2F64Opcode,
        left: X64Operand,
        right: X64Operand,
    },
    I64Setcc {
        condition: X64SetCondition,
        left: X64Operand,
        right: X64Operand,
    },
    ArrayLenF64 {
        array: X64Operand,
    },
    ArrayGetF64Checked {
        array: X64Operand,
        index: X64Operand,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64Immediate {
    Unit,
    Bool(bool),
    I64(i64),
    F64Bits(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64Operand {
    Immediate {
        ty: MachineType,
        value: X64Immediate,
    },
    Home(X64Home),
}

impl X64Operand {
    pub fn ty(&self) -> MachineType {
        match self {
            Self::Immediate { ty, .. } => *ty,
            Self::Home(home) => home.ty,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64Terminator {
    Return {
        origin: X64SourceOrigin,
        value: X64Operand,
    },
    BranchRel32 {
        origin: X64SourceOrigin,
        condition: X64Operand,
        then_label: X64LabelId,
        else_label: X64LabelId,
    },
    TailJumpRel32 {
        origin: X64SourceOrigin,
        function: X64FunctionId,
        target_label: X64LabelId,
        arguments: Vec<X64Operand>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64LabelOwner {
    EntryAdapter,
    Block {
        function: X64FunctionId,
        block: X64BlockId,
    },
    ReturnEpilogue,
    BoundsEpilogue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64Label {
    pub id: X64LabelId,
    pub owner: X64LabelOwner,
    pub code_offset: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64Fixup {
    pub patch_offset: u32,
    pub target: X64LabelId,
    pub addend: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TargetEncodeError {
    LengthOverflow { field: &'static str, length: usize },
    ByteLimit { limit: u64, actual: u64 },
}

impl fmt::Display for X64TargetEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOverflow { field, length } => {
                write!(formatter, "{field} length {length} exceeds u32")
            }
            Self::ByteLimit { limit, actual } => write!(
                formatter,
                "x86-64 target semantic encoding uses {actual} bytes; limit is {limit}"
            ),
        }
    }
}

impl std::error::Error for X64TargetEncodeError {}

#[derive(Default)]
struct TargetSemanticEncoder {
    bytes: Vec<u8>,
    attempted_bytes: u64,
}

impl TargetSemanticEncoder {
    fn append(&mut self, bytes: &[u8]) {
        self.attempted_bytes = self.attempted_bytes.saturating_add(bytes.len() as u64);
        if self.attempted_bytes <= X64_TARGET_MAX_SEMANTIC_BYTES {
            self.bytes.extend_from_slice(bytes);
        }
    }

    fn tag(&mut self, value: u8) {
        self.append(&[value]);
    }

    fn u16(&mut self, value: u16) {
        self.append(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.append(&value.to_be_bytes());
    }

    fn i32(&mut self, value: i32) {
        self.append(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.append(&value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.append(&value.to_be_bytes());
    }

    fn length(&mut self, field: &'static str, length: usize) -> Result<(), X64TargetEncodeError> {
        let length = u32::try_from(length)
            .map_err(|_| X64TargetEncodeError::LengthOverflow { field, length })?;
        self.u32(length);
        Ok(())
    }

    fn string(&mut self, field: &'static str, value: &str) -> Result<(), X64TargetEncodeError> {
        self.length(field, value.len())?;
        self.append(value.as_bytes());
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>, X64TargetEncodeError> {
        if self.attempted_bytes > X64_TARGET_MAX_SEMANTIC_BYTES {
            return Err(X64TargetEncodeError::ByteLimit {
                limit: X64_TARGET_MAX_SEMANTIC_BYTES,
                actual: self.attempted_bytes,
            });
        }
        Ok(self.bytes)
    }
}

pub fn x64_target_plan_bytes(program: &X64TargetProgram) -> Result<Vec<u8>, X64TargetEncodeError> {
    let mut encoder = TargetSemanticEncoder::default();
    encoder.append(X64_TARGET_PLAN_DOMAIN);
    encode_target_plan(&mut encoder, program)?;
    encoder.finish()
}

pub fn x64_target_plan_hash(
    program: &X64TargetProgram,
) -> Result<SemanticHash, X64TargetEncodeError> {
    Ok(SemanticHash(sha256(&x64_target_plan_bytes(program)?)))
}

pub fn x64_target_code_hash(code: &[u8]) -> Result<SemanticHash, X64TargetEncodeError> {
    let mut encoder = TargetSemanticEncoder::default();
    encoder.append(X64_TARGET_CODE_DOMAIN);
    encoder.length("target.code", code.len())?;
    encoder.append(code);
    Ok(SemanticHash(sha256(&encoder.finish()?)))
}

pub fn x64_target_semantic_bytes(
    program: &X64TargetProgram,
) -> Result<Vec<u8>, X64TargetEncodeError> {
    let mut encoder = TargetSemanticEncoder::default();
    encoder.append(X64_TARGET_SEMANTIC_DOMAIN);
    let plan = x64_target_plan_bytes(program)?;
    encoder.length("target.plan", plan.len())?;
    encoder.append(&plan);
    encoder.length("target.fixups", program.fixups.len())?;
    for fixup in &program.fixups {
        encoder.u32(fixup.patch_offset);
        encoder.u32(fixup.target.0);
        encoder.i32(fixup.addend);
    }
    encoder.append(&program.plan_hash.0);
    encoder.append(&program.code_hash.0);
    encoder.length("target.code", program.code.len())?;
    encoder.append(&program.code);
    encoder.finish()
}

pub fn x64_target_semantic_hash(
    program: &X64TargetProgram,
) -> Result<SemanticHash, X64TargetEncodeError> {
    Ok(SemanticHash(sha256(&x64_target_semantic_bytes(program)?)))
}

/// Seal one already-executed finite-corpus observation.
///
/// Both source artifacts are verified before their identities are admitted.
/// The observations are normalized from evaluator values/effects rather than
/// from formatting, and the seal excludes engine-local step counts.
pub fn seal_x64_target_correspondence_record(
    case_ordinal: u32,
    input_hash: SemanticHash,
    source_machine_ir: &MachineIrArtifact,
    target: &X64TargetArtifact,
    machine_ir: &Evaluation,
    target_plan: &Evaluation,
) -> Result<X64TargetCorrespondenceRecord, X64TargetCorrespondenceError> {
    if case_ordinal >= X64_TARGET_MAX_CORRESPONDENCE_RECORDS {
        return Err(X64TargetCorrespondenceError::RecordLimit {
            limit: X64_TARGET_MAX_CORRESPONDENCE_RECORDS,
            actual: case_ordinal,
        });
    }
    verify_machine_ir(source_machine_ir).map_err(X64TargetCorrespondenceError::InvalidMachineIr)?;
    verify_x64_target_r1_s7a(target).map_err(X64TargetCorrespondenceError::InvalidTarget)?;
    if target.program.source_machine_ir_hash != source_machine_ir.semantic_hash {
        return Err(X64TargetCorrespondenceError::SourceMachineIrHashMismatch {
            declared: target.program.source_machine_ir_hash,
            actual: source_machine_ir.semantic_hash,
        });
    }

    let machine_ir = normalize_correspondence_observation("Machine IR", case_ordinal, machine_ir)?;
    let target_plan =
        normalize_correspondence_observation("x86-64 target plan", case_ordinal, target_plan)?;
    if machine_ir != target_plan {
        return Err(X64TargetCorrespondenceError::SemanticMismatch { case_ordinal });
    }

    let mut record = X64TargetCorrespondenceRecord {
        schema_version: X64_TARGET_CORRESPONDENCE_SCHEMA_VERSION,
        case_ordinal,
        input_hash,
        source_machine_ir_hash: source_machine_ir.semantic_hash,
        target_plan_hash: target.program.plan_hash,
        machine_ir,
        target_plan,
        record_hash: SemanticHash::ZERO,
    };
    record.record_hash = x64_target_correspondence_record_hash(&record)?;
    Ok(record)
}

/// Recompute an individual record seal after validating its complete semantic
/// shape. This deliberately refuses to seal mismatched engine observations.
pub fn x64_target_correspondence_record_hash(
    record: &X64TargetCorrespondenceRecord,
) -> Result<SemanticHash, X64TargetCorrespondenceError> {
    validate_correspondence_record_shape(record)?;
    let mut bytes =
        Vec::with_capacity(X64_TARGET_CORRESPONDENCE_RECORD_DOMAIN.len() + 6 + 4 + (32 * 3) + 32);
    bytes.extend_from_slice(X64_TARGET_CORRESPONDENCE_RECORD_DOMAIN);
    correspondence_put_version(&mut bytes, record.schema_version);
    correspondence_put_u32(&mut bytes, record.case_ordinal);
    bytes.extend_from_slice(&record.input_hash.0);
    bytes.extend_from_slice(&record.source_machine_ir_hash.0);
    bytes.extend_from_slice(&record.target_plan_hash.0);
    encode_correspondence_observation(&mut bytes, &record.machine_ir);
    encode_correspondence_observation(&mut bytes, &record.target_plan);
    Ok(SemanticHash(sha256(&bytes)))
}

/// Verify schema, semantic agreement, shape caps, and the nested record seal.
pub fn verify_x64_target_correspondence_record(
    record: &X64TargetCorrespondenceRecord,
) -> Result<(), X64TargetCorrespondenceError> {
    let actual = x64_target_correspondence_record_hash(record)?;
    if actual != record.record_hash {
        return Err(X64TargetCorrespondenceError::RecordHashMismatch {
            case_ordinal: record.case_ordinal,
        });
    }
    Ok(())
}

/// Canonical order-sensitive result identity over at most 64 sealed records.
///
/// Ordinals must be exactly `0..records.len()`. This both rejects ambiguous
/// corpus order and makes permutation attacks fail closed before hashing.
pub fn x64_target_correspondence_results_hash(
    records: &[X64TargetCorrespondenceRecord],
) -> Result<SemanticHash, X64TargetCorrespondenceError> {
    let record_count =
        u32::try_from(records.len()).map_err(|_| X64TargetCorrespondenceError::MetricOverflow)?;
    if record_count > X64_TARGET_MAX_CORRESPONDENCE_RECORDS {
        return Err(X64TargetCorrespondenceError::RecordLimit {
            limit: X64_TARGET_MAX_CORRESPONDENCE_RECORDS,
            actual: record_count,
        });
    }

    let mut bytes = Vec::with_capacity(
        X64_TARGET_CORRESPONDENCE_RESULTS_DOMAIN.len() + 6 + 4 + records.len().saturating_mul(32),
    );
    bytes.extend_from_slice(X64_TARGET_CORRESPONDENCE_RESULTS_DOMAIN);
    correspondence_put_version(&mut bytes, X64_TARGET_CORRESPONDENCE_SCHEMA_VERSION);
    correspondence_put_u32(&mut bytes, record_count);
    for (expected_ordinal, record) in records.iter().enumerate() {
        let expected_ordinal = u32::try_from(expected_ordinal)
            .map_err(|_| X64TargetCorrespondenceError::MetricOverflow)?;
        if record.case_ordinal != expected_ordinal {
            return Err(X64TargetCorrespondenceError::NonCanonicalOrdinal {
                expected: expected_ordinal,
                actual: record.case_ordinal,
            });
        }
        verify_x64_target_correspondence_record(record)?;
        bytes.extend_from_slice(&record.record_hash.0);
    }
    Ok(SemanticHash(sha256(&bytes)))
}

pub fn seal_x64_target_correspondence_evidence(
    records: Vec<X64TargetCorrespondenceRecord>,
) -> Result<X64TargetCorrespondenceEvidence, X64TargetCorrespondenceError> {
    let results_hash = x64_target_correspondence_results_hash(&records)?;
    Ok(X64TargetCorrespondenceEvidence {
        schema_version: X64_TARGET_CORRESPONDENCE_SCHEMA_VERSION,
        records,
        results_hash,
    })
}

/// Fail-closed admission for a claimed finite correspondence result.
pub fn verify_x64_target_correspondence_evidence(
    evidence: &X64TargetCorrespondenceEvidence,
) -> Result<(), X64TargetCorrespondenceError> {
    if evidence.schema_version != X64_TARGET_CORRESPONDENCE_SCHEMA_VERSION {
        return Err(X64TargetCorrespondenceError::InvalidSchema {
            actual: evidence.schema_version,
        });
    }
    if x64_target_correspondence_results_hash(&evidence.records)? != evidence.results_hash {
        return Err(X64TargetCorrespondenceError::ResultsHashMismatch);
    }
    Ok(())
}

fn normalize_correspondence_observation(
    engine: &'static str,
    case_ordinal: u32,
    evaluation: &Evaluation,
) -> Result<X64TargetCorrespondenceObservation, X64TargetCorrespondenceError> {
    let outcome = match &evaluation.outcome {
        EvaluationOutcome::Return(CoreValue::F64(value)) if value.is_nan() => {
            X64TargetCorrespondenceOutcome::ReturnF64(X64TargetCorrespondenceF64::CanonicalNaN)
        }
        EvaluationOutcome::Return(CoreValue::F64(value)) => {
            X64TargetCorrespondenceOutcome::ReturnF64(X64TargetCorrespondenceF64::ExactBits(
                value.to_bits(),
            ))
        }
        EvaluationOutcome::Error(ErrorKind::Bounds) => X64TargetCorrespondenceOutcome::Bounds,
        _ => {
            return Err(X64TargetCorrespondenceError::UnsupportedOutcome {
                engine,
                case_ordinal,
            });
        }
    };
    let effect_count = u32::try_from(evaluation.effect_trace.len())
        .map_err(|_| X64TargetCorrespondenceError::MetricOverflow)?;
    if effect_count > X64_TARGET_MAX_CORRESPONDENCE_EFFECTS_PER_ENGINE {
        return Err(X64TargetCorrespondenceError::EffectLimit {
            engine,
            case_ordinal,
            limit: X64_TARGET_MAX_CORRESPONDENCE_EFFECTS_PER_ENGINE,
            actual: effect_count,
        });
    }
    let effect_trace = evaluation
        .effect_trace
        .iter()
        .map(|effect| match effect {
            EffectEvent::Error(ErrorKind::Bounds) => Ok(X64TargetCorrespondenceEffect::Bounds),
            _ => Err(X64TargetCorrespondenceError::UnsupportedEffect {
                engine,
                case_ordinal,
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let observation = X64TargetCorrespondenceObservation {
        outcome,
        effect_trace,
    };
    validate_correspondence_observation(engine, case_ordinal, &observation)?;
    Ok(observation)
}

fn validate_correspondence_record_shape(
    record: &X64TargetCorrespondenceRecord,
) -> Result<(), X64TargetCorrespondenceError> {
    if record.schema_version != X64_TARGET_CORRESPONDENCE_SCHEMA_VERSION {
        return Err(X64TargetCorrespondenceError::InvalidSchema {
            actual: record.schema_version,
        });
    }
    if record.case_ordinal >= X64_TARGET_MAX_CORRESPONDENCE_RECORDS {
        return Err(X64TargetCorrespondenceError::RecordLimit {
            limit: X64_TARGET_MAX_CORRESPONDENCE_RECORDS,
            actual: record.case_ordinal,
        });
    }
    validate_correspondence_observation("Machine IR", record.case_ordinal, &record.machine_ir)?;
    validate_correspondence_observation(
        "x86-64 target plan",
        record.case_ordinal,
        &record.target_plan,
    )?;
    if record.machine_ir != record.target_plan {
        return Err(X64TargetCorrespondenceError::SemanticMismatch {
            case_ordinal: record.case_ordinal,
        });
    }
    Ok(())
}

fn validate_correspondence_observation(
    engine: &'static str,
    case_ordinal: u32,
    observation: &X64TargetCorrespondenceObservation,
) -> Result<(), X64TargetCorrespondenceError> {
    let effect_count = u32::try_from(observation.effect_trace.len())
        .map_err(|_| X64TargetCorrespondenceError::MetricOverflow)?;
    if effect_count > X64_TARGET_MAX_CORRESPONDENCE_EFFECTS_PER_ENGINE {
        return Err(X64TargetCorrespondenceError::EffectLimit {
            engine,
            case_ordinal,
            limit: X64_TARGET_MAX_CORRESPONDENCE_EFFECTS_PER_ENGINE,
            actual: effect_count,
        });
    }
    let canonical = match observation.outcome {
        X64TargetCorrespondenceOutcome::ReturnF64(X64TargetCorrespondenceF64::ExactBits(bits)) => {
            !f64::from_bits(bits).is_nan() && observation.effect_trace.is_empty()
        }
        X64TargetCorrespondenceOutcome::ReturnF64(X64TargetCorrespondenceF64::CanonicalNaN) => {
            observation.effect_trace.is_empty()
        }
        X64TargetCorrespondenceOutcome::Bounds => {
            observation.effect_trace == [X64TargetCorrespondenceEffect::Bounds]
        }
    };
    if !canonical {
        return Err(X64TargetCorrespondenceError::NonCanonicalObservation {
            engine,
            case_ordinal,
        });
    }
    Ok(())
}

fn encode_correspondence_observation(
    bytes: &mut Vec<u8>,
    observation: &X64TargetCorrespondenceObservation,
) {
    match observation.outcome {
        X64TargetCorrespondenceOutcome::ReturnF64(X64TargetCorrespondenceF64::ExactBits(bits)) => {
            bytes.push(0);
            bytes.extend_from_slice(&bits.to_be_bytes());
        }
        X64TargetCorrespondenceOutcome::ReturnF64(X64TargetCorrespondenceF64::CanonicalNaN) => {
            bytes.push(1)
        }
        X64TargetCorrespondenceOutcome::Bounds => bytes.push(2),
    }
    correspondence_put_u32(bytes, observation.effect_trace.len() as u32);
    for effect in &observation.effect_trace {
        bytes.push(match effect {
            X64TargetCorrespondenceEffect::Bounds => 0,
        });
    }
}

fn correspondence_put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_be_bytes());
    bytes.extend_from_slice(&version.1.to_be_bytes());
    bytes.extend_from_slice(&version.2.to_be_bytes());
}

fn correspondence_put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn encode_target_plan(
    encoder: &mut TargetSemanticEncoder,
    program: &X64TargetProgram,
) -> Result<(), X64TargetEncodeError> {
    encoder.string("schema.name", &program.schema.name)?;
    encoder.u16(program.schema.major);
    encoder.u16(program.schema.minor);
    encoder.u16(program.schema.patch);
    encoder.u16(program.lowering_policy_version.0);
    encoder.u16(program.lowering_policy_version.1);
    encoder.u16(program.lowering_policy_version.2);
    encoder.u16(program.encoder_policy_version.0);
    encoder.u16(program.encoder_policy_version.1);
    encoder.u16(program.encoder_policy_version.2);
    encode_abi(encoder, program.abi);
    encode_limits(encoder, program.limits);
    encoder.append(&program.source_core_hash.0);
    encoder.append(&program.source_ssa_hash.0);
    encoder.append(&program.source_machine_ir_hash.0);
    encoder.u32(program.entry.0);
    encoder.u32(program.entry_offset);
    encode_entry_abi(encoder, &program.entry_abi)?;
    encode_frame(encoder, program.frame);
    encoder.length("target.functions", program.functions.len())?;
    for function in &program.functions {
        encode_function(encoder, function)?;
    }
    encoder.length("target.labels", program.labels.len())?;
    for label in &program.labels {
        encoder.u32(label.id.0);
        match label.owner {
            X64LabelOwner::EntryAdapter => encoder.tag(0),
            X64LabelOwner::Block { function, block } => {
                encoder.tag(1);
                encoder.u32(function.0);
                encoder.u32(block.0);
            }
            X64LabelOwner::ReturnEpilogue => encoder.tag(2),
            X64LabelOwner::BoundsEpilogue => encoder.tag(3),
        }
        encoder.u32(label.code_offset);
    }
    Ok(())
}

fn encode_abi(encoder: &mut TargetSemanticEncoder, abi: X64TargetAbi) {
    encoder.tag(match abi.architecture {
        X64TargetArchitecture::X86_64 => 0,
    });
    encoder.tag(match abi.operating_system {
        X64TargetOperatingSystem::Linux => 0,
    });
    encoder.tag(match abi.endian {
        X64TargetEndian::Little => 0,
    });
    encoder.u16(abi.pointer_bits);
    encoder.tag(match abi.calling_convention {
        X64TargetCallingConvention::NauxLighthouseSysV1 => 0,
    });
    encoder.tag(match abi.feature_profile {
        X64TargetFeatureProfile::X86_64Sse2 => 0,
    });
    encoder.tag(match abi.code_model {
        X64TargetCodeModel::PositionIndependentSingleBlob => 0,
    });
    encoder.u32(abi.canonical_mxcsr);
    encoder.u32(abi.stack_alignment);
}

fn encode_limits(encoder: &mut TargetSemanticEncoder, limits: X64TargetLimits) {
    encoder.u64(limits.max_source_functions);
    encoder.u64(limits.max_source_blocks);
    encoder.u64(limits.max_source_instructions);
    encoder.u64(limits.max_ops);
    encoder.u64(limits.max_labels);
    encoder.u64(limits.max_fixups);
    encoder.u64(limits.max_code_bytes);
    encoder.u64(limits.max_semantic_bytes);
    encoder.u32(limits.max_frame_bytes);
    encoder.u32(limits.max_outgoing_bytes);
    encoder.u32(limits.max_entry_input_lanes);
    encoder.u64(limits.max_lowering_work);
    encoder.u64(limits.max_plan_eval_work);
    encoder.u32(limits.max_cfg_depth);
    encoder.u32(limits.max_diagnostics);
}

fn encode_frame(encoder: &mut TargetSemanticEncoder, frame: X64FrameLayout) {
    encoder.u32(frame.header_bytes);
    encoder.u32(frame.home_base);
    encoder.u32(frame.max_home_bytes);
    encoder.u32(frame.outgoing_base);
    encoder.u32(frame.outgoing_bytes);
    encoder.u32(frame.frame_bytes);
}

fn encode_entry_abi(
    encoder: &mut TargetSemanticEncoder,
    entry: &X64EntryAbi,
) -> Result<(), X64TargetEncodeError> {
    encoder.length("entry.parameter_types", entry.parameter_types.len())?;
    for ty in &entry.parameter_types {
        encode_type(encoder, *ty);
    }
    encoder.length("entry.input_lanes", entry.input_lanes.len())?;
    for lane in &entry.input_lanes {
        encoder.u32(lane.parameter);
        encoder.tag(lane.word);
        encode_abi_register(encoder, lane.register);
    }
    encode_abi_register(encoder, entry.output_register);
    encode_type(encoder, entry.result);
    encoder.tag(entry.output_words);
    Ok(())
}

fn encode_abi_register(encoder: &mut TargetSemanticEncoder, register: X64AbiRegister) {
    encoder.tag(match register {
        X64AbiRegister::Rdi => 0,
        X64AbiRegister::Rsi => 1,
        X64AbiRegister::Rdx => 2,
        X64AbiRegister::Rcx => 3,
        X64AbiRegister::R8 => 4,
        X64AbiRegister::R9 => 5,
    });
}

fn encode_type(encoder: &mut TargetSemanticEncoder, ty: MachineType) {
    encoder.tag(match ty {
        MachineType::Unit => 0,
        MachineType::Bool => 1,
        MachineType::I64 => 2,
        MachineType::F64 => 3,
        MachineType::F64Array => 4,
    });
}

fn encode_effect(encoder: &mut TargetSemanticEncoder, effect: MachineEffect) {
    encoder.tag(match effect {
        MachineEffect::Bounds => 0,
    });
}

fn encode_home(encoder: &mut TargetSemanticEncoder, home: X64Home) {
    encoder.u32(home.slot.0);
    encoder.u32(home.offset);
    encoder.tag(home.width);
    encode_type(encoder, home.ty);
}

fn encode_function(
    encoder: &mut TargetSemanticEncoder,
    function: &X64Function,
) -> Result<(), X64TargetEncodeError> {
    encoder.u32(function.id.0);
    encoder.length("function.parameters", function.parameters.len())?;
    for parameter in &function.parameters {
        encode_home(encoder, parameter.home);
    }
    encoder.length("function.effects", function.effects.len())?;
    for effect in &function.effects {
        encode_effect(encoder, *effect);
    }
    encode_type(encoder, function.result);
    encoder.u32(function.entry_block.0);
    encoder.length("function.blocks", function.blocks.len())?;
    for block in &function.blocks {
        encoder.u32(block.id.0);
        encoder.u32(block.label.0);
        encoder.length("block.instructions", block.instructions.len())?;
        for instruction in &block.instructions {
            encode_origin(encoder, instruction.origin);
            encode_home(encoder, instruction.result);
            encode_instruction(encoder, &instruction.kind)?;
        }
        encode_terminator(encoder, &block.terminator)?;
    }
    Ok(())
}

fn encode_origin(encoder: &mut TargetSemanticEncoder, origin: X64SourceOrigin) {
    encoder.u32(origin.function.0);
    encoder.u32(origin.block.0);
    match origin.position {
        X64SourcePosition::Instruction(index) => {
            encoder.tag(0);
            encoder.u32(index);
        }
        X64SourcePosition::Terminator => encoder.tag(1),
    }
}

fn encode_operand(encoder: &mut TargetSemanticEncoder, operand: &X64Operand) {
    match operand {
        X64Operand::Immediate { ty, value } => {
            encoder.tag(0);
            encode_type(encoder, *ty);
            match value {
                X64Immediate::Unit => encoder.tag(0),
                X64Immediate::Bool(value) => {
                    encoder.tag(1);
                    encoder.tag(u8::from(*value));
                }
                X64Immediate::I64(value) => {
                    encoder.tag(2);
                    encoder.i64(*value);
                }
                X64Immediate::F64Bits(bits) => {
                    encoder.tag(3);
                    encoder.u64(*bits);
                }
            }
        }
        X64Operand::Home(home) => {
            encoder.tag(1);
            encode_home(encoder, *home);
        }
    }
}

fn encode_instruction(
    encoder: &mut TargetSemanticEncoder,
    instruction: &X64InstructionKind,
) -> Result<(), X64TargetEncodeError> {
    match instruction {
        X64InstructionKind::Move(operand) => {
            encoder.tag(0);
            encode_operand(encoder, operand);
        }
        X64InstructionKind::I64Wrapping {
            opcode,
            left,
            right,
        } => {
            encoder.tag(1);
            encoder.tag(match opcode {
                X64I64Opcode::Add => 0,
                X64I64Opcode::Sub => 1,
                X64I64Opcode::Mul => 2,
            });
            encode_operand(encoder, left);
            encode_operand(encoder, right);
        }
        X64InstructionKind::Sse2F64 {
            opcode,
            left,
            right,
        } => {
            encoder.tag(2);
            encoder.tag(match opcode {
                X64Sse2F64Opcode::AddSd => 0,
                X64Sse2F64Opcode::SubSd => 1,
            });
            encode_operand(encoder, left);
            encode_operand(encoder, right);
        }
        X64InstructionKind::I64Setcc {
            condition,
            left,
            right,
        } => {
            encoder.tag(3);
            encoder.tag(match condition {
                X64SetCondition::SignedLessThan => 0,
                X64SetCondition::SignedGreaterOrEqual => 1,
            });
            encode_operand(encoder, left);
            encode_operand(encoder, right);
        }
        X64InstructionKind::ArrayLenF64 { array } => {
            encoder.tag(4);
            encode_operand(encoder, array);
        }
        X64InstructionKind::ArrayGetF64Checked { array, index } => {
            encoder.tag(5);
            encode_operand(encoder, array);
            encode_operand(encoder, index);
        }
    }
    Ok(())
}

fn encode_terminator(
    encoder: &mut TargetSemanticEncoder,
    terminator: &X64Terminator,
) -> Result<(), X64TargetEncodeError> {
    match terminator {
        X64Terminator::Return { origin, value } => {
            encoder.tag(0);
            encode_origin(encoder, *origin);
            encode_operand(encoder, value);
        }
        X64Terminator::BranchRel32 {
            origin,
            condition,
            then_label,
            else_label,
        } => {
            encoder.tag(1);
            encode_origin(encoder, *origin);
            encode_operand(encoder, condition);
            encoder.u32(then_label.0);
            encoder.u32(else_label.0);
        }
        X64Terminator::TailJumpRel32 {
            origin,
            function,
            target_label,
            arguments,
        } => {
            encoder.tag(2);
            encode_origin(encoder, *origin);
            encoder.u32(function.0);
            encoder.u32(target_label.0);
            encoder.length("tail.arguments", arguments.len())?;
            for argument in arguments {
                encode_operand(encoder, argument);
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TargetLowerError {
    InvalidSourceBinding(MachineIrSourceError),
    InvalidSource(MachineIrVerificationErrors),
    UnsupportedSource {
        path: String,
        message: String,
    },
    StructuralLimit {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    ArithmeticOverflow {
        field: &'static str,
    },
    Encoding(X64TargetEncodeError),
    RawEncoding(String),
    InvalidOutput(X64TargetVerificationErrors),
}

impl fmt::Display for X64TargetLowerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSourceBinding(error) => write!(formatter, "{error}"),
            Self::InvalidSource(errors) => write!(formatter, "{errors}"),
            Self::UnsupportedSource { path, message } => {
                write!(
                    formatter,
                    "unsupported R1-S7a Machine IR at {path}: {message}"
                )
            }
            Self::StructuralLimit {
                field,
                limit,
                actual,
            } => write!(
                formatter,
                "x86-64 target lowering {field} usage {actual} exceeds hard limit {limit}"
            ),
            Self::ArithmeticOverflow { field } => {
                write!(
                    formatter,
                    "x86-64 target lowering {field} accounting overflow"
                )
            }
            Self::Encoding(error) => write!(formatter, "{error}"),
            Self::RawEncoding(error) => write!(formatter, "{error}"),
            Self::InvalidOutput(errors) => {
                write!(
                    formatter,
                    "lowerer produced invalid x86-64 target: {errors}"
                )
            }
        }
    }
}

impl std::error::Error for X64TargetLowerError {}

impl From<X64TargetEncodeError> for X64TargetLowerError {
    fn from(error: X64TargetEncodeError) -> Self {
        Self::Encoding(error)
    }
}

impl From<raw::RawEncodeError> for X64TargetLowerError {
    fn from(error: raw::RawEncodeError) -> Self {
        Self::RawEncoding(error.to_string())
    }
}

/// Lower the exact R1-S6 translation of `source_core` into the canonical
/// unexecuted R1-S7a x86-64 target artifact.
///
/// This entry point intentionally accepts all three source artifacts. A
/// locally valid Machine IR carrying copied hashes cannot acquire target
/// translation authority.
pub fn lower_x64_target_r1_s7a(
    source_machine_ir: &MachineIrArtifact,
    source_ssa: &CoreSsaArtifact,
    source_core: &CoreArtifact,
) -> Result<X64TargetArtifact, X64TargetLowerError> {
    let source = verify_machine_ir_source(source_machine_ir, source_ssa, source_core)
        .map_err(X64TargetLowerError::InvalidSourceBinding)?;
    lower_x64_target_from_source(source)
}

fn lower_x64_target_from_source(
    source: SourceBoundMachineIrArtifact<'_, '_, '_>,
) -> Result<X64TargetArtifact, X64TargetLowerError> {
    let machine = source.artifact();
    verify_machine_ir(machine).map_err(X64TargetLowerError::InvalidSource)?;
    preflight_target_lowering(machine)?;

    let (home_maps, frame) = derive_machine_frame(machine)?;
    let entry_function = machine
        .program
        .functions
        .get(machine.program.entry.0 as usize)
        .ok_or_else(|| X64TargetLowerError::UnsupportedSource {
            path: "program.entry".to_owned(),
            message: "entry function is missing after R1-S6 verification".to_owned(),
        })?;
    let entry_abi = derive_entry_abi(entry_function)?;

    let mut labels = Vec::with_capacity(
        machine
            .program
            .functions
            .iter()
            .map(|function| function.blocks.len())
            .sum::<usize>()
            .saturating_add(3),
    );
    labels.push(X64Label {
        id: X64LabelId(0),
        owner: X64LabelOwner::EntryAdapter,
        code_offset: 0,
    });
    let mut block_labels = BTreeMap::new();
    for function in &machine.program.functions {
        for block in &function.blocks {
            let id = checked_label_id(labels.len())?;
            block_labels.insert((function.id, block.id), id);
            labels.push(X64Label {
                id,
                owner: X64LabelOwner::Block {
                    function: X64FunctionId(function.id.0),
                    block: X64BlockId(block.id.0),
                },
                code_offset: 0,
            });
        }
    }
    let return_label = checked_label_id(labels.len())?;
    labels.push(X64Label {
        id: return_label,
        owner: X64LabelOwner::ReturnEpilogue,
        code_offset: 0,
    });
    let bounds_label = checked_label_id(labels.len())?;
    labels.push(X64Label {
        id: bounds_label,
        owner: X64LabelOwner::BoundsEpilogue,
        code_offset: 0,
    });

    let functions = machine
        .program
        .functions
        .iter()
        .enumerate()
        .map(|(index, function)| lower_target_function(function, &home_maps[index], &block_labels))
        .collect::<Result<Vec<_>, _>>()?;

    let mut program = X64TargetProgram {
        schema: X64TargetSchemaVersion::r1_s7a(),
        lowering_policy_version: X64_TARGET_LOWERING_POLICY_VERSION,
        encoder_policy_version: X64_TARGET_ENCODER_POLICY_VERSION,
        abi: X64TargetAbi::r1_s7a(),
        limits: X64TargetLimits::r1_s7a(),
        source_core_hash: machine.program.source_core_hash,
        source_ssa_hash: machine.program.source_ssa_hash,
        source_machine_ir_hash: machine.semantic_hash,
        entry: X64FunctionId(machine.program.entry.0),
        entry_offset: 0,
        entry_abi,
        frame,
        functions,
        labels,
        fixups: Vec::new(),
        code: Vec::new(),
        plan_hash: SemanticHash::ZERO,
        code_hash: SemanticHash::ZERO,
    };
    let encoded = raw::encode(&program)?;
    program.labels = encoded.labels;
    program.fixups = encoded.fixups;
    program.code = encoded.code;
    let artifact = X64TargetArtifact::seal(program)?;
    verify_x64_target_r1_s7a(&artifact).map_err(X64TargetLowerError::InvalidOutput)?;
    Ok(artifact)
}

fn checked_label_id(length: usize) -> Result<X64LabelId, X64TargetLowerError> {
    let id = u32::try_from(length).map_err(|_| X64TargetLowerError::StructuralLimit {
        field: "labels",
        limit: X64_TARGET_MAX_LABELS,
        actual: length as u64,
    })?;
    Ok(X64LabelId(id))
}

fn preflight_target_lowering(machine: &MachineIrArtifact) -> Result<(), X64TargetLowerError> {
    let functions = machine.program.functions.len() as u64;
    if functions > X64_TARGET_MAX_SOURCE_FUNCTIONS {
        return Err(X64TargetLowerError::StructuralLimit {
            field: "source functions",
            limit: X64_TARGET_MAX_SOURCE_FUNCTIONS,
            actual: functions,
        });
    }
    let mut blocks = 0_u64;
    let mut instructions = 0_u64;
    let mut operations = 0_u64;
    let mut work = functions;
    for function in &machine.program.functions {
        blocks = blocks.checked_add(function.blocks.len() as u64).ok_or(
            X64TargetLowerError::ArithmeticOverflow {
                field: "source block count",
            },
        )?;
        work = work
            .checked_add(function.parameters.len() as u64)
            .and_then(|value| value.checked_add(function.effects.len() as u64))
            .and_then(|value| value.checked_add(function.blocks.len() as u64))
            .ok_or(X64TargetLowerError::ArithmeticOverflow {
                field: "lowering work",
            })?;
        for block in &function.blocks {
            instructions = instructions
                .checked_add(block.instructions.len() as u64)
                .ok_or(X64TargetLowerError::ArithmeticOverflow {
                    field: "source instruction count",
                })?;
            operations = operations
                .checked_add(block.instructions.len() as u64)
                .and_then(|value| value.checked_add(1))
                .ok_or(X64TargetLowerError::ArithmeticOverflow {
                    field: "target operation count",
                })?;
            work = work
                .checked_add(block.instructions.len() as u64)
                .and_then(|value| value.checked_add(1))
                .ok_or(X64TargetLowerError::ArithmeticOverflow {
                    field: "lowering work",
                })?;
            for instruction in &block.instructions {
                let operands = match &instruction.kind {
                    MachineInstructionKind::Move(_)
                    | MachineInstructionKind::ArrayLenF64 { .. } => 1,
                    MachineInstructionKind::I64Binary { .. }
                    | MachineInstructionKind::F64Binary { .. }
                    | MachineInstructionKind::I64Compare { .. }
                    | MachineInstructionKind::ArrayGetF64Checked { .. } => 2,
                    MachineInstructionKind::Call { arguments, .. } => arguments.len() as u64,
                };
                work =
                    work.checked_add(operands)
                        .ok_or(X64TargetLowerError::ArithmeticOverflow {
                            field: "lowering work",
                        })?;
            }
            let terminator_operands = match &block.terminator {
                MachineTerminator::Return(_) | MachineTerminator::Branch { .. } => 1,
                MachineTerminator::TailCall { arguments, .. } => arguments.len() as u64,
            };
            work = work.checked_add(terminator_operands).ok_or(
                X64TargetLowerError::ArithmeticOverflow {
                    field: "lowering work",
                },
            )?;
        }
    }
    for (field, actual, limit) in [
        ("source blocks", blocks, X64_TARGET_MAX_SOURCE_BLOCKS),
        (
            "source instructions",
            instructions,
            X64_TARGET_MAX_SOURCE_INSTRUCTIONS,
        ),
        ("target operations", operations, X64_TARGET_MAX_OPS),
        ("lowering work", work, X64_TARGET_MAX_LOWERING_WORK),
    ] {
        if actual > limit {
            return Err(X64TargetLowerError::StructuralLimit {
                field,
                limit,
                actual,
            });
        }
    }
    let label_count = blocks
        .checked_add(3)
        .ok_or(X64TargetLowerError::ArithmeticOverflow {
            field: "label count",
        })?;
    if label_count > X64_TARGET_MAX_LABELS {
        return Err(X64TargetLowerError::StructuralLimit {
            field: "labels",
            limit: X64_TARGET_MAX_LABELS,
            actual: label_count,
        });
    }
    Ok(())
}

const fn canonical_home_layout_limits() -> CanonicalHomeLayoutLimits {
    CanonicalHomeLayoutLimits {
        header_bytes: X64_FRAME_HEADER_BYTES,
        outgoing_alignment: 8,
        frame_alignment: X64_STACK_ALIGNMENT,
        max_frame_bytes: X64_TARGET_MAX_FRAME_BYTES,
        max_outgoing_bytes: X64_TARGET_MAX_OUTGOING_BYTES,
    }
}

fn derive_machine_frame(
    machine: &MachineIrArtifact,
) -> Result<(Vec<Vec<X64Home>>, X64FrameLayout), X64TargetLowerError> {
    let input = canonical_home_program_from_machine(machine)?;
    let layout = allocate_canonical_home_layout(
        &input,
        CanonicalHomeLayoutPolicy::DefinitionOrderV1,
        canonical_home_layout_limits(),
    )
    .map_err(map_home_layout_lower_error)?;
    Ok((layout.homes, layout.frame))
}

fn canonical_home_program_from_machine(
    machine: &MachineIrArtifact,
) -> Result<CanonicalHomeProgram, X64TargetLowerError> {
    let mut functions = Vec::with_capacity(machine.program.functions.len());
    for function in &machine.program.functions {
        let parameter_count = u32::try_from(function.parameters.len()).map_err(|_| {
            X64TargetLowerError::StructuralLimit {
                field: "function parameters",
                limit: u64::from(u32::MAX),
                actual: function.parameters.len() as u64,
            }
        })?;
        let mut value_types = Vec::new();
        for (register, ty) in function
            .parameters
            .iter()
            .map(|parameter| (parameter.register, parameter.ty))
            .chain(
                function
                    .blocks
                    .iter()
                    .flat_map(|block| &block.instructions)
                    .map(|instruction| (instruction.result, instruction.ty)),
            )
        {
            if register.0 as usize != value_types.len() {
                return Err(X64TargetLowerError::UnsupportedSource {
                    path: format!("functions[{}].registers", function.id.0),
                    message: format!(
                        "register {} is not dense at canonical position {}",
                        register.0,
                        value_types.len()
                    ),
                });
            }
            value_types.push(ty);
        }

        let mut tails = Vec::new();
        for block in &function.blocks {
            if let MachineTerminator::TailCall {
                function: callee,
                arguments,
            } = &block.terminator
            {
                let arguments = arguments
                    .iter()
                    .enumerate()
                    .map(|(argument_index, argument)| {
                        canonical_home_argument_from_machine(
                            argument,
                            &value_types,
                            &format!(
                                "functions[{}].blocks[{}].terminator.arguments[{argument_index}]",
                                function.id.0, block.id.0
                            ),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                tails.push(CanonicalHomeTail {
                    block: block.id.0,
                    callee: callee.0,
                    arguments,
                });
            }
        }

        functions.push(CanonicalHomeFunction {
            value_types,
            parameter_count,
            tails,
        });
    }
    Ok(CanonicalHomeProgram { functions })
}

fn canonical_home_argument_from_machine(
    argument: &MachineOperand,
    value_types: &[MachineType],
    path: &str,
) -> Result<CanonicalHomeArgument, X64TargetLowerError> {
    Ok(match argument {
        MachineOperand::Unit => CanonicalHomeArgument::Immediate(MachineType::Unit),
        MachineOperand::Bool(_) => CanonicalHomeArgument::Immediate(MachineType::Bool),
        MachineOperand::I64(_) => CanonicalHomeArgument::Immediate(MachineType::I64),
        MachineOperand::F64Bits(_) => CanonicalHomeArgument::Immediate(MachineType::F64),
        MachineOperand::Register(register) => {
            let ty = value_types
                .get(register.0 as usize)
                .copied()
                .ok_or_else(|| X64TargetLowerError::UnsupportedSource {
                    path: path.to_owned(),
                    message: format!("register {} has no target home", register.0),
                })?;
            CanonicalHomeArgument::Slot {
                slot: register.0,
                ty,
            }
        }
    })
}

fn map_home_layout_lower_error(error: CanonicalHomeLayoutError) -> X64TargetLowerError {
    match error {
        CanonicalHomeLayoutError::StructuralLimit {
            field,
            limit,
            actual,
        } => X64TargetLowerError::StructuralLimit {
            field,
            limit,
            actual,
        },
        CanonicalHomeLayoutError::ArithmeticOverflow { field } => {
            X64TargetLowerError::ArithmeticOverflow { field }
        }
        CanonicalHomeLayoutError::ParameterCountExceedsValues { function, .. } => {
            X64TargetLowerError::UnsupportedSource {
                path: format!("functions[{function}].parameters"),
                message: error.to_string(),
            }
        }
        CanonicalHomeLayoutError::InvalidAlignment { .. }
        | CanonicalHomeLayoutError::MisalignedHeader { .. } => {
            X64TargetLowerError::UnsupportedSource {
                path: "target.home_layout".to_owned(),
                message: error.to_string(),
            }
        }
    }
}

fn derive_entry_abi(
    entry: &super::machine_ir::MachineFunction,
) -> Result<X64EntryAbi, X64TargetLowerError> {
    const REGISTERS: [X64AbiRegister; 6] = [
        X64AbiRegister::Rdi,
        X64AbiRegister::Rsi,
        X64AbiRegister::Rdx,
        X64AbiRegister::Rcx,
        X64AbiRegister::R8,
        X64AbiRegister::R9,
    ];
    let mut input_lanes = Vec::new();
    let mut parameter_types = Vec::with_capacity(entry.parameters.len());
    for (parameter_index, parameter) in entry.parameters.iter().enumerate() {
        parameter_types.push(parameter.ty);
        let words = match parameter.ty {
            MachineType::Unit => 0,
            MachineType::F64Array => 2,
            MachineType::Bool | MachineType::I64 | MachineType::F64 => 1,
        };
        for word in 0..words {
            let register = REGISTERS.get(input_lanes.len()).copied().ok_or_else(|| {
                X64TargetLowerError::UnsupportedSource {
                    path: "program.entry.parameters".to_owned(),
                    message: format!(
                        "entry signature needs more than {} input lanes",
                        X64_TARGET_MAX_ENTRY_INPUT_LANES
                    ),
                }
            })?;
            input_lanes.push(X64EntryLane {
                parameter: parameter_index as u32,
                word: word as u8,
                register,
            });
        }
    }
    if input_lanes.len() as u32 > X64_TARGET_MAX_ENTRY_INPUT_LANES {
        return Err(X64TargetLowerError::StructuralLimit {
            field: "entry input lanes",
            limit: u64::from(X64_TARGET_MAX_ENTRY_INPUT_LANES),
            actual: input_lanes.len() as u64,
        });
    }
    let output_register = REGISTERS[input_lanes.len()];
    Ok(X64EntryAbi {
        parameter_types,
        input_lanes,
        output_register,
        result: entry.result,
        output_words: 2,
    })
}

fn lower_target_function(
    function: &super::machine_ir::MachineFunction,
    homes: &[X64Home],
    block_labels: &BTreeMap<(MachineFunctionId, MachineBlockId), X64LabelId>,
) -> Result<X64Function, X64TargetLowerError> {
    let id = X64FunctionId(function.id.0);
    let parameters = function
        .parameters
        .iter()
        .map(|parameter| {
            let home = homes
                .get(parameter.register.0 as usize)
                .copied()
                .ok_or_else(|| X64TargetLowerError::UnsupportedSource {
                    path: format!("functions[{}].parameters", function.id.0),
                    message: "parameter home is missing".to_owned(),
                })?;
            Ok(X64Parameter { home })
        })
        .collect::<Result<Vec<_>, X64TargetLowerError>>()?;
    let blocks = function
        .blocks
        .iter()
        .map(|block| {
            let block_id = X64BlockId(block.id.0);
            let label = lookup_block_label(block_labels, function.id, block.id)?;
            let instructions = block
                .instructions
                .iter()
                .enumerate()
                .map(|(index, instruction)| {
                    lower_target_instruction(id, block_id, index, instruction, homes)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let terminator =
                lower_target_terminator(id, block_id, &block.terminator, homes, block_labels)?;
            Ok(X64Block {
                id: block_id,
                label,
                instructions,
                terminator,
            })
        })
        .collect::<Result<Vec<_>, X64TargetLowerError>>()?;
    Ok(X64Function {
        id,
        parameters,
        effects: function.effects.clone(),
        result: function.result,
        entry_block: X64BlockId(function.entry_block.0),
        blocks,
    })
}

fn lookup_block_label(
    labels: &BTreeMap<(MachineFunctionId, MachineBlockId), X64LabelId>,
    function: MachineFunctionId,
    block: MachineBlockId,
) -> Result<X64LabelId, X64TargetLowerError> {
    labels
        .get(&(function, block))
        .copied()
        .ok_or_else(|| X64TargetLowerError::UnsupportedSource {
            path: format!("functions[{}].blocks[{}]", function.0, block.0),
            message: "block label is missing".to_owned(),
        })
}

fn lower_target_instruction(
    function: X64FunctionId,
    block: X64BlockId,
    index: usize,
    instruction: &super::machine_ir::MachineInstruction,
    homes: &[X64Home],
) -> Result<X64Instruction, X64TargetLowerError> {
    let path = format!(
        "functions[{}].blocks[{}].instructions[{index}]",
        function.0, block.0
    );
    let origin = X64SourceOrigin {
        function,
        block,
        position: X64SourcePosition::Instruction(index as u32),
    };
    let result = homes
        .get(instruction.result.0 as usize)
        .copied()
        .ok_or_else(|| X64TargetLowerError::UnsupportedSource {
            path: path.clone(),
            message: "result home is missing".to_owned(),
        })?;
    let operand = |value: &MachineOperand| lower_target_operand(value, homes, &path);
    let kind = match &instruction.kind {
        MachineInstructionKind::Move(value) => X64InstructionKind::Move(operand(value)?),
        MachineInstructionKind::I64Binary {
            operation,
            mode,
            left,
            right,
        } => {
            if *mode != MachineIntegerMode::Wrapping {
                return Err(X64TargetLowerError::UnsupportedSource {
                    path,
                    message: "saturating I64 operations are outside R1-S7a".to_owned(),
                });
            }
            X64InstructionKind::I64Wrapping {
                opcode: match operation {
                    MachineI64BinaryOp::Add => X64I64Opcode::Add,
                    MachineI64BinaryOp::Sub => X64I64Opcode::Sub,
                    MachineI64BinaryOp::Mul => X64I64Opcode::Mul,
                },
                left: operand(left)?,
                right: operand(right)?,
            }
        }
        MachineInstructionKind::F64Binary {
            operation,
            left,
            right,
        } => X64InstructionKind::Sse2F64 {
            opcode: match operation {
                MachineF64BinaryOp::Add => X64Sse2F64Opcode::AddSd,
                MachineF64BinaryOp::Sub => X64Sse2F64Opcode::SubSd,
            },
            left: operand(left)?,
            right: operand(right)?,
        },
        MachineInstructionKind::I64Compare {
            operation,
            left,
            right,
        } => X64InstructionKind::I64Setcc {
            condition: match operation {
                MachineI64CompareOp::LessThan => X64SetCondition::SignedLessThan,
                MachineI64CompareOp::GreaterOrEqual => X64SetCondition::SignedGreaterOrEqual,
            },
            left: operand(left)?,
            right: operand(right)?,
        },
        MachineInstructionKind::ArrayLenF64 { array } => X64InstructionKind::ArrayLenF64 {
            array: operand(array)?,
        },
        MachineInstructionKind::ArrayGetF64Checked { array, index } => {
            X64InstructionKind::ArrayGetF64Checked {
                array: operand(array)?,
                index: operand(index)?,
            }
        }
        MachineInstructionKind::Call { .. } => {
            return Err(X64TargetLowerError::UnsupportedSource {
                path,
                message: "direct Call is outside R1-S7a".to_owned(),
            });
        }
    };
    Ok(X64Instruction {
        origin,
        result,
        kind,
    })
}

fn lower_target_terminator(
    function: X64FunctionId,
    block: X64BlockId,
    terminator: &MachineTerminator,
    homes: &[X64Home],
    block_labels: &BTreeMap<(MachineFunctionId, MachineBlockId), X64LabelId>,
) -> Result<X64Terminator, X64TargetLowerError> {
    let path = format!("functions[{}].blocks[{}].terminator", function.0, block.0);
    let origin = X64SourceOrigin {
        function,
        block,
        position: X64SourcePosition::Terminator,
    };
    let operand = |value: &MachineOperand| lower_target_operand(value, homes, &path);
    Ok(match terminator {
        MachineTerminator::Return(value) => X64Terminator::Return {
            origin,
            value: operand(value)?,
        },
        MachineTerminator::Branch {
            condition,
            then_block,
            else_block,
        } => X64Terminator::BranchRel32 {
            origin,
            condition: operand(condition)?,
            then_label: lookup_block_label(
                block_labels,
                MachineFunctionId(function.0),
                *then_block,
            )?,
            else_label: lookup_block_label(
                block_labels,
                MachineFunctionId(function.0),
                *else_block,
            )?,
        },
        MachineTerminator::TailCall {
            function: target,
            arguments,
        } => {
            let target_label = lookup_block_label(block_labels, *target, MachineBlockId(0))?;
            X64Terminator::TailJumpRel32 {
                origin,
                function: X64FunctionId(target.0),
                target_label,
                arguments: arguments
                    .iter()
                    .map(operand)
                    .collect::<Result<Vec<_>, _>>()?,
            }
        }
    })
}

fn lower_target_operand(
    operand: &MachineOperand,
    homes: &[X64Home],
    path: &str,
) -> Result<X64Operand, X64TargetLowerError> {
    Ok(match operand {
        MachineOperand::Unit => X64Operand::Immediate {
            ty: MachineType::Unit,
            value: X64Immediate::Unit,
        },
        MachineOperand::Bool(value) => X64Operand::Immediate {
            ty: MachineType::Bool,
            value: X64Immediate::Bool(*value),
        },
        MachineOperand::I64(value) => X64Operand::Immediate {
            ty: MachineType::I64,
            value: X64Immediate::I64(*value),
        },
        MachineOperand::F64Bits(bits) => X64Operand::Immediate {
            ty: MachineType::F64,
            value: X64Immediate::F64Bits(*bits),
        },
        MachineOperand::Register(register) => {
            X64Operand::Home(homes.get(register.0 as usize).copied().ok_or_else(|| {
                X64TargetLowerError::UnsupportedSource {
                    path: path.to_owned(),
                    message: format!("register {} has no target home", register.0),
                }
            })?)
        }
    })
}

fn canonical_home_program_from_target(program: &X64TargetProgram) -> CanonicalHomeProgram {
    let functions = program
        .functions
        .iter()
        .map(|function| {
            debug_assert!(u32::try_from(function.parameters.len()).is_ok());
            let value_types = function
                .parameters
                .iter()
                .map(|parameter| parameter.home.ty)
                .chain(
                    function
                        .blocks
                        .iter()
                        .flat_map(|block| &block.instructions)
                        .map(|instruction| instruction.result.ty),
                )
                .collect();
            let tails = function
                .blocks
                .iter()
                .filter_map(|block| {
                    let X64Terminator::TailJumpRel32 {
                        function: callee,
                        arguments,
                        ..
                    } = &block.terminator
                    else {
                        return None;
                    };
                    Some(CanonicalHomeTail {
                        block: block.id.0,
                        callee: callee.0,
                        arguments: arguments
                            .iter()
                            .map(canonical_home_argument_from_target)
                            .collect(),
                    })
                })
                .collect();
            CanonicalHomeFunction {
                value_types,
                parameter_count: function.parameters.len() as u32,
                tails,
            }
        })
        .collect();
    CanonicalHomeProgram { functions }
}

fn canonical_home_argument_from_target(argument: &X64Operand) -> CanonicalHomeArgument {
    match argument {
        X64Operand::Immediate { ty, .. } => CanonicalHomeArgument::Immediate(*ty),
        X64Operand::Home(home) => CanonicalHomeArgument::Slot {
            slot: home.slot.0,
            ty: home.ty,
        },
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TargetVerificationCode {
    InvalidSchema,
    InvalidPolicy,
    InvalidTarget,
    InvalidLimits,
    InvalidSourceProvenance,
    StructuralLimit,
    ArithmeticOverflow,
    NonCanonicalOrder,
    DuplicateId,
    MissingEntry,
    InvalidEntryAbi,
    InvalidFrame,
    InvalidHome,
    TypeMismatch,
    InvalidOperation,
    InvalidControlFlow,
    MissingEffect,
    InvalidLabel,
    InvalidFixup,
    CodeMismatch,
    PlanHashMismatch,
    CodeHashMismatch,
    SemanticHashMismatch,
    EncodingFailure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TargetVerificationError {
    pub code: X64TargetVerificationCode,
    pub path: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X64TargetVerificationErrors(pub Vec<X64TargetVerificationError>);

impl fmt::Display for X64TargetVerificationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} canonical x86-64 target verification error(s)",
            self.0.len()
        )?;
        for error in &self.0 {
            write!(
                formatter,
                "\n- {:?} at {}: {}",
                error.code, error.path, error.message
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for X64TargetVerificationErrors {}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedX64TargetArtifact<'artifact> {
    artifact: &'artifact X64TargetArtifact,
}

impl<'artifact> VerifiedX64TargetArtifact<'artifact> {
    pub fn artifact(self) -> &'artifact X64TargetArtifact {
        self.artifact
    }

    pub fn program(self) -> &'artifact X64TargetProgram {
        &self.artifact.program
    }

    pub fn semantic_hash(self) -> SemanticHash {
        self.artifact.semantic_hash
    }

    pub fn code_hash(self) -> SemanticHash {
        self.artifact.program.code_hash
    }
}

/// Verify the local target artifact without granting translation provenance.
///
/// In addition to target-plan checks, this independently re-lays out and
/// re-encodes the complete raw code blob and every retained PcRel32 fixup.
pub fn verify_x64_target_r1_s7a(
    artifact: &X64TargetArtifact,
) -> Result<VerifiedX64TargetArtifact<'_>, X64TargetVerificationErrors> {
    let mut verifier = X64TargetVerifier::new(&artifact.program);
    verifier.verify_envelope_metadata();
    let within_limits = verifier.preflight_counts();
    if verifier.errors.is_empty() && within_limits {
        verifier.verify_identity(artifact);
        verifier.verify_program();
        verifier.verify_raw_encoding();
    }
    if verifier.errors.is_empty() {
        Ok(VerifiedX64TargetArtifact { artifact })
    } else {
        Err(X64TargetVerificationErrors(verifier.errors))
    }
}

struct X64TargetVerifier<'program> {
    program: &'program X64TargetProgram,
    errors: Vec<X64TargetVerificationError>,
}

impl<'program> X64TargetVerifier<'program> {
    fn new(program: &'program X64TargetProgram) -> Self {
        Self {
            program,
            errors: Vec::new(),
        }
    }

    fn error(
        &mut self,
        code: X64TargetVerificationCode,
        path: impl Into<String>,
        message: impl Into<String>,
    ) {
        if self.errors.len() < X64_TARGET_MAX_DIAGNOSTICS {
            self.errors.push(X64TargetVerificationError {
                code,
                path: path.into(),
                message: message.into(),
            });
        }
    }

    fn full(&self) -> bool {
        self.errors.len() >= X64_TARGET_MAX_DIAGNOSTICS
    }

    fn verify_envelope_metadata(&mut self) {
        let schema = &self.program.schema;
        if schema.name.len() > 64
            || schema.name != X64_TARGET_SCHEMA_NAME
            || (schema.major, schema.minor, schema.patch) != X64_TARGET_SCHEMA_VERSION
        {
            self.error(
                X64TargetVerificationCode::InvalidSchema,
                "program.schema",
                "schema must be exactly naux-x86-64-target 0.1.0",
            );
        }
        if self.program.lowering_policy_version != X64_TARGET_LOWERING_POLICY_VERSION {
            self.error(
                X64TargetVerificationCode::InvalidPolicy,
                "program.lowering_policy_version",
                "target lowering policy must be exactly 1.0.0",
            );
        }
        if self.program.encoder_policy_version != X64_TARGET_ENCODER_POLICY_VERSION {
            self.error(
                X64TargetVerificationCode::InvalidPolicy,
                "program.encoder_policy_version",
                format!(
                    "target encoder policy must be exactly {}.{}.{}",
                    X64_TARGET_ENCODER_POLICY_VERSION.0,
                    X64_TARGET_ENCODER_POLICY_VERSION.1,
                    X64_TARGET_ENCODER_POLICY_VERSION.2,
                ),
            );
        }
        if self.program.abi != X64TargetAbi::r1_s7a() {
            self.error(
                X64TargetVerificationCode::InvalidTarget,
                "program.abi",
                "target must be Linux x86-64 SysV, little-endian, SSE2, PIC, MXCSR 0x1f80",
            );
        }
        if self.program.limits != X64TargetLimits::r1_s7a() {
            self.error(
                X64TargetVerificationCode::InvalidLimits,
                "program.limits",
                "target hard-limit vector differs from R1-S7a",
            );
        }
        if self.program.entry_offset != 0 {
            self.error(
                X64TargetVerificationCode::InvalidEntryAbi,
                "program.entry_offset",
                "canonical entry offset must be zero",
            );
        }
        for (path, hash) in [
            ("program.source_core_hash", self.program.source_core_hash),
            ("program.source_ssa_hash", self.program.source_ssa_hash),
            (
                "program.source_machine_ir_hash",
                self.program.source_machine_ir_hash,
            ),
        ] {
            if hash == SemanticHash::ZERO {
                self.error(
                    X64TargetVerificationCode::InvalidSourceProvenance,
                    path,
                    "source identity must be non-zero",
                );
            }
        }
    }

    fn preflight_counts(&mut self) -> bool {
        let mut ok = true;
        let functions = self.program.functions.len() as u64;
        if functions == 0 {
            self.error(
                X64TargetVerificationCode::MissingEntry,
                "program.functions",
                "target program must contain at least one function",
            );
            ok = false;
        }
        ok &= self.check_limit(
            "program.functions",
            functions,
            X64_TARGET_MAX_SOURCE_FUNCTIONS,
        );
        ok &= self.check_limit(
            "program.labels",
            self.program.labels.len() as u64,
            X64_TARGET_MAX_LABELS,
        );
        ok &= self.check_limit(
            "program.fixups",
            self.program.fixups.len() as u64,
            X64_TARGET_MAX_FIXUPS,
        );
        ok &= self.check_limit(
            "program.code",
            self.program.code.len() as u64,
            X64_TARGET_MAX_CODE_BYTES,
        );
        ok &= self.check_limit(
            "program.entry_abi.parameter_types",
            self.program.entry_abi.parameter_types.len() as u64,
            X64_TARGET_MAX_SOURCE_INSTRUCTIONS,
        );
        ok &= self.check_limit(
            "program.entry_abi.input_lanes",
            self.program.entry_abi.input_lanes.len() as u64,
            u64::from(X64_TARGET_MAX_ENTRY_INPUT_LANES),
        );

        let mut blocks = 0_u64;
        let mut instructions = 0_u64;
        let mut ops = 0_u64;
        let mut work = functions;
        for function in &self.program.functions {
            let Some(next_blocks) = blocks.checked_add(function.blocks.len() as u64) else {
                self.error(
                    X64TargetVerificationCode::ArithmeticOverflow,
                    "program.functions",
                    "block count overflow",
                );
                return false;
            };
            blocks = next_blocks;
            work = match work
                .checked_add(function.parameters.len() as u64)
                .and_then(|value| value.checked_add(function.effects.len() as u64))
                .and_then(|value| value.checked_add(function.blocks.len() as u64))
            {
                Some(value) => value,
                None => {
                    self.error(
                        X64TargetVerificationCode::ArithmeticOverflow,
                        "program.functions",
                        "verification work overflow",
                    );
                    return false;
                }
            };
            for block in &function.blocks {
                let count = block.instructions.len() as u64;
                instructions = match instructions.checked_add(count) {
                    Some(value) => value,
                    None => {
                        self.error(
                            X64TargetVerificationCode::ArithmeticOverflow,
                            "program.functions",
                            "instruction count overflow",
                        );
                        return false;
                    }
                };
                ops = match ops
                    .checked_add(count)
                    .and_then(|value| value.checked_add(1))
                {
                    Some(value) => value,
                    None => {
                        self.error(
                            X64TargetVerificationCode::ArithmeticOverflow,
                            "program.functions",
                            "target operation count overflow",
                        );
                        return false;
                    }
                };
                let mut operand_count = match &block.terminator {
                    X64Terminator::Return { .. } | X64Terminator::BranchRel32 { .. } => 1,
                    X64Terminator::TailJumpRel32 { arguments, .. } => arguments.len() as u64,
                };
                for instruction in &block.instructions {
                    operand_count = match operand_count.checked_add(
                        instruction_operands(&instruction.kind)
                            .into_iter()
                            .flatten()
                            .count() as u64,
                    ) {
                        Some(value) => value,
                        None => {
                            self.error(
                                X64TargetVerificationCode::ArithmeticOverflow,
                                "program.functions",
                                "operand count overflow",
                            );
                            return false;
                        }
                    };
                }
                work = match work
                    .checked_add(count)
                    .and_then(|value| value.checked_add(1))
                    .and_then(|value| value.checked_add(operand_count))
                {
                    Some(value) => value,
                    None => {
                        self.error(
                            X64TargetVerificationCode::ArithmeticOverflow,
                            "program.functions",
                            "verification work overflow",
                        );
                        return false;
                    }
                };
                if work > X64_TARGET_MAX_LOWERING_WORK {
                    self.error(
                        X64TargetVerificationCode::StructuralLimit,
                        "program.verification_work",
                        format!("count {work} exceeds hard limit {X64_TARGET_MAX_LOWERING_WORK}"),
                    );
                    return false;
                }
            }
        }
        ok &= self.check_limit(
            "program.functions.blocks",
            blocks,
            X64_TARGET_MAX_SOURCE_BLOCKS,
        );
        ok &= self.check_limit(
            "program.functions.instructions",
            instructions,
            X64_TARGET_MAX_SOURCE_INSTRUCTIONS,
        );
        ok &= self.check_limit("program.target_ops", ops, X64_TARGET_MAX_OPS);
        ok &= self.check_limit(
            "program.verification_work",
            work,
            X64_TARGET_MAX_LOWERING_WORK,
        );
        ok
    }

    fn check_limit(&mut self, path: &str, actual: u64, limit: u64) -> bool {
        if actual > limit {
            self.error(
                X64TargetVerificationCode::StructuralLimit,
                path,
                format!("count {actual} exceeds hard limit {limit}"),
            );
            false
        } else {
            true
        }
    }

    fn verify_identity(&mut self, artifact: &X64TargetArtifact) {
        match x64_target_plan_hash(self.program) {
            Ok(actual) if actual == self.program.plan_hash => {}
            Ok(actual) => self.error(
                X64TargetVerificationCode::PlanHashMismatch,
                "program.plan_hash",
                format!(
                    "declared {}; canonical plan is {}",
                    self.program.plan_hash, actual
                ),
            ),
            Err(error) => self.error(
                X64TargetVerificationCode::EncodingFailure,
                "program.plan_hash",
                error.to_string(),
            ),
        }
        match x64_target_code_hash(&self.program.code) {
            Ok(actual) if actual == self.program.code_hash => {}
            Ok(actual) => self.error(
                X64TargetVerificationCode::CodeHashMismatch,
                "program.code_hash",
                format!(
                    "declared {}; canonical code is {}",
                    self.program.code_hash, actual
                ),
            ),
            Err(error) => self.error(
                X64TargetVerificationCode::EncodingFailure,
                "program.code_hash",
                error.to_string(),
            ),
        }
        match x64_target_semantic_hash(self.program) {
            Ok(actual) if actual == artifact.semantic_hash => {}
            Ok(actual) => self.error(
                X64TargetVerificationCode::SemanticHashMismatch,
                "artifact.semantic_hash",
                format!(
                    "declared {}; canonical artifact is {}",
                    artifact.semantic_hash, actual
                ),
            ),
            Err(error) => self.error(
                X64TargetVerificationCode::EncodingFailure,
                "artifact.semantic_hash",
                error.to_string(),
            ),
        }
    }

    fn verify_program(&mut self) {
        let Some(entry) = self.program.functions.get(self.program.entry.0 as usize) else {
            self.error(
                X64TargetVerificationCode::MissingEntry,
                "program.entry",
                "entry function does not exist",
            );
            return;
        };
        if entry.id.0 != self.program.entry.0 {
            self.error(
                X64TargetVerificationCode::MissingEntry,
                "program.entry",
                "entry identifier does not name its canonical function position",
            );
        }

        let layout_input = canonical_home_program_from_target(self.program);
        let canonical_layout = match allocate_canonical_home_layout(
            &layout_input,
            CanonicalHomeLayoutPolicy::DefinitionOrderV1,
            canonical_home_layout_limits(),
        ) {
            Ok(layout) => layout,
            Err(error) => {
                self.home_layout_error(error);
                return;
            }
        };

        for (function_index, (function, homes)) in self
            .program
            .functions
            .iter()
            .zip(&canonical_layout.homes)
            .enumerate()
        {
            if self.full() {
                return;
            }
            let path = format!("program.functions[{function_index}]");
            if function.id.0 as usize != function_index {
                self.error(
                    X64TargetVerificationCode::NonCanonicalOrder,
                    format!("{path}.id"),
                    format!(
                        "function IDs must be dense; expected {function_index}, found {}",
                        function.id.0
                    ),
                );
            }
            if function.blocks.is_empty() || function.entry_block != X64BlockId(0) {
                self.error(
                    X64TargetVerificationCode::InvalidControlFlow,
                    format!("{path}.entry_block"),
                    "each canonical target function must enter dense block 0",
                );
            }
            self.verify_declared_function_homes(function, homes, &path);
            self.verify_function(function, homes, &path);
        }
        if self.program.frame != canonical_layout.frame {
            self.error(
                X64TargetVerificationCode::InvalidFrame,
                "program.frame",
                format!(
                    "frame must equal canonical derived layout {:?}",
                    canonical_layout.frame
                ),
            );
        }
        let expected_entry = derive_target_entry_abi(entry);
        match expected_entry {
            Ok(expected) if expected == self.program.entry_abi => {}
            Ok(expected) => self.error(
                X64TargetVerificationCode::InvalidEntryAbi,
                "program.entry_abi",
                format!("entry ABI must equal canonical derived manifest {expected:?}"),
            ),
            Err(message) => self.error(
                X64TargetVerificationCode::InvalidEntryAbi,
                "program.entry_abi",
                message,
            ),
        }
        self.verify_labels();
    }

    fn home_layout_error(&mut self, error: CanonicalHomeLayoutError) {
        let (code, path) = match error {
            CanonicalHomeLayoutError::StructuralLimit { .. } => {
                (X64TargetVerificationCode::InvalidFrame, "program.frame")
            }
            CanonicalHomeLayoutError::ArithmeticOverflow { .. } => (
                X64TargetVerificationCode::ArithmeticOverflow,
                "program.frame",
            ),
            CanonicalHomeLayoutError::ParameterCountExceedsValues { .. } => {
                (X64TargetVerificationCode::InvalidHome, "program.functions")
            }
            CanonicalHomeLayoutError::InvalidAlignment { .. }
            | CanonicalHomeLayoutError::MisalignedHeader { .. } => {
                (X64TargetVerificationCode::InvalidLimits, "program.limits")
            }
        };
        self.error(code, path, error.to_string());
    }

    fn verify_declared_function_homes(
        &mut self,
        function: &X64Function,
        canonical_homes: &[X64Home],
        path: &str,
    ) {
        let declared_homes = function
            .parameters
            .iter()
            .map(|parameter| ("parameter", parameter.home))
            .chain(
                function
                    .blocks
                    .iter()
                    .flat_map(|block| &block.instructions)
                    .map(|instruction| ("instruction", instruction.result)),
            );
        for ((location, declared), canonical) in declared_homes.zip(canonical_homes) {
            if declared != *canonical {
                self.error(
                    X64TargetVerificationCode::InvalidHome,
                    format!("{path}.{location}.home"),
                    format!("home {declared:?} must equal canonical {canonical:?}"),
                );
            }
        }
    }

    fn verify_function(&mut self, function: &X64Function, homes: &[X64Home], path: &str) {
        if !matches!(function.effects.as_slice(), [] | [MachineEffect::Bounds]) {
            self.error(
                X64TargetVerificationCode::InvalidOperation,
                format!("{path}.effects"),
                "effect row must be exactly [] or [Bounds]",
            );
        }
        let label_to_block = function
            .blocks
            .iter()
            .map(|block| (block.label, block.id))
            .collect::<BTreeMap<_, _>>();
        if label_to_block.len() != function.blocks.len() {
            self.error(
                X64TargetVerificationCode::DuplicateId,
                format!("{path}.blocks"),
                "block labels must be unique within a function",
            );
        }
        for (block_index, block) in function.blocks.iter().enumerate() {
            if block.id.0 as usize != block_index {
                self.error(
                    X64TargetVerificationCode::NonCanonicalOrder,
                    format!("{path}.blocks[{block_index}].id"),
                    "block IDs must be dense in stored order",
                );
            }
            let expected_owner = X64LabelOwner::Block {
                function: function.id,
                block: block.id,
            };
            if self
                .program
                .labels
                .get(block.label.0 as usize)
                .is_none_or(|label| label.id != block.label || label.owner != expected_owner)
            {
                self.error(
                    X64TargetVerificationCode::InvalidLabel,
                    format!("{path}.blocks[{block_index}].label"),
                    "block label must name the canonical label owned by this exact function and block",
                );
            }
            for (instruction_index, instruction) in block.instructions.iter().enumerate() {
                let instruction_path =
                    format!("{path}.blocks[{block_index}].instructions[{instruction_index}]");
                let expected_origin = X64SourceOrigin {
                    function: function.id,
                    block: block.id,
                    position: X64SourcePosition::Instruction(instruction_index as u32),
                };
                if instruction.origin != expected_origin {
                    self.error(
                        X64TargetVerificationCode::NonCanonicalOrder,
                        format!("{instruction_path}.origin"),
                        "instruction origin must match canonical source position",
                    );
                }
                self.verify_instruction(instruction, homes, &function.effects, &instruction_path);
            }
            let expected_origin = X64SourceOrigin {
                function: function.id,
                block: block.id,
                position: X64SourcePosition::Terminator,
            };
            self.verify_terminator(
                function,
                &block.terminator,
                expected_origin,
                homes,
                &label_to_block,
                &format!("{path}.blocks[{block_index}].terminator"),
            );
        }
        self.verify_cfg(function, &label_to_block, path);
        self.verify_home_dominance(function, homes, &label_to_block, path);
    }

    fn verify_home_dominance(
        &mut self,
        function: &X64Function,
        homes: &[X64Home],
        label_to_block: &BTreeMap<X64LabelId, X64BlockId>,
        path: &str,
    ) {
        let mut definitions = vec![None; homes.len()];
        for parameter in &function.parameters {
            if let Some(definition) = definitions.get_mut(parameter.home.slot.0 as usize) {
                *definition = Some(None);
            }
        }
        for block in &function.blocks {
            for (index, instruction) in block.instructions.iter().enumerate() {
                if let Some(definition) = definitions.get_mut(instruction.result.slot.0 as usize) {
                    *definition = Some(Some((block.id, index)));
                }
            }
        }

        let mut parents = vec![None; function.blocks.len()];
        for block in &function.blocks {
            if let X64Terminator::BranchRel32 {
                then_label,
                else_label,
                ..
            } = block.terminator
            {
                for label in [then_label, else_label] {
                    if let Some(target) = label_to_block.get(&label) {
                        if let Some(parent) = parents.get_mut(target.0 as usize) {
                            if parent.is_none() {
                                *parent = Some(block.id);
                            }
                        }
                    }
                }
            }
        }

        for block in &function.blocks {
            for (index, instruction) in block.instructions.iter().enumerate() {
                for operand in instruction_operands(&instruction.kind)
                    .into_iter()
                    .flatten()
                {
                    self.verify_home_use(
                        operand,
                        block.id,
                        index,
                        &definitions,
                        &parents,
                        &format!("{path}.blocks[{}].instructions[{index}]", block.id.0),
                    );
                }
            }
            let use_index = block.instructions.len();
            let terminator_path = format!("{path}.blocks[{}].terminator", block.id.0);
            match &block.terminator {
                X64Terminator::Return { value, .. } => self.verify_home_use(
                    value,
                    block.id,
                    use_index,
                    &definitions,
                    &parents,
                    &terminator_path,
                ),
                X64Terminator::BranchRel32 { condition, .. } => self.verify_home_use(
                    condition,
                    block.id,
                    use_index,
                    &definitions,
                    &parents,
                    &terminator_path,
                ),
                X64Terminator::TailJumpRel32 { arguments, .. } => {
                    for argument in arguments {
                        self.verify_home_use(
                            argument,
                            block.id,
                            use_index,
                            &definitions,
                            &parents,
                            &terminator_path,
                        );
                    }
                }
            }
        }
    }

    fn verify_home_use(
        &mut self,
        operand: &X64Operand,
        use_block: X64BlockId,
        use_index: usize,
        definitions: &[Option<Option<(X64BlockId, usize)>>],
        parents: &[Option<X64BlockId>],
        path: &str,
    ) {
        let X64Operand::Home(home) = operand else {
            return;
        };
        let Some(definition) = definitions.get(home.slot.0 as usize).copied().flatten() else {
            if definitions
                .get(home.slot.0 as usize)
                .is_some_and(Option::is_none)
            {
                self.error(
                    X64TargetVerificationCode::InvalidHome,
                    path,
                    format!("home slot {} has no definition", home.slot.0),
                );
            }
            return;
        };
        let Some((definition_block, definition_index)) = definition else {
            return;
        };
        let dominates = if definition_block == use_block {
            definition_index < use_index
        } else {
            let mut cursor = parents.get(use_block.0 as usize).copied().flatten();
            let mut found = false;
            let mut remaining = parents.len();
            while let Some(block) = cursor {
                if block == definition_block {
                    found = true;
                    break;
                }
                if remaining == 0 {
                    break;
                }
                remaining -= 1;
                cursor = parents.get(block.0 as usize).copied().flatten();
            }
            found
        };
        if !dominates {
            self.error(
                X64TargetVerificationCode::InvalidHome,
                path,
                format!(
                    "home slot {} is used before its definition or across a sibling CFG branch",
                    home.slot.0
                ),
            );
        }
    }

    fn verify_operand(&mut self, operand: &X64Operand, homes: &[X64Home], path: &str) {
        match operand {
            X64Operand::Home(home) => {
                if homes.get(home.slot.0 as usize) != Some(home) {
                    self.error(
                        X64TargetVerificationCode::InvalidHome,
                        path,
                        "operand home is not the exact canonical home for this function",
                    );
                }
            }
            X64Operand::Immediate { ty, value } => {
                let canonical = match (ty, value) {
                    (MachineType::Unit, X64Immediate::Unit)
                    | (MachineType::Bool, X64Immediate::Bool(_))
                    | (MachineType::I64, X64Immediate::I64(_)) => true,
                    (MachineType::F64, X64Immediate::F64Bits(bits)) => {
                        canonical_f64_bits(f64::from_bits(*bits)) == *bits
                    }
                    _ => false,
                };
                if !canonical {
                    self.error(
                        X64TargetVerificationCode::TypeMismatch,
                        path,
                        "immediate tag, type, or F64 NaN identity is non-canonical",
                    );
                }
            }
        }
    }

    fn verify_instruction(
        &mut self,
        instruction: &X64Instruction,
        homes: &[X64Home],
        effects: &[MachineEffect],
        path: &str,
    ) {
        if homes.get(instruction.result.slot.0 as usize) != Some(&instruction.result) {
            self.error(
                X64TargetVerificationCode::InvalidHome,
                format!("{path}.result"),
                "result is not its canonical typed home",
            );
        }
        let mut check = |operand: &X64Operand, suffix: &str| {
            self.verify_operand(operand, homes, &format!("{path}.{suffix}"));
        };
        match &instruction.kind {
            X64InstructionKind::Move(value) => {
                check(value, "value");
                if value.ty() != instruction.result.ty {
                    self.error(
                        X64TargetVerificationCode::TypeMismatch,
                        path,
                        "Move result and operand types differ",
                    );
                }
            }
            X64InstructionKind::I64Wrapping { left, right, .. } => {
                check(left, "left");
                check(right, "right");
                if instruction.result.ty != MachineType::I64
                    || left.ty() != MachineType::I64
                    || right.ty() != MachineType::I64
                {
                    self.error(
                        X64TargetVerificationCode::TypeMismatch,
                        path,
                        "wrapping I64 operation requires I64 operands and result",
                    );
                }
            }
            X64InstructionKind::Sse2F64 { left, right, .. } => {
                check(left, "left");
                check(right, "right");
                if instruction.result.ty != MachineType::F64
                    || left.ty() != MachineType::F64
                    || right.ty() != MachineType::F64
                {
                    self.error(
                        X64TargetVerificationCode::TypeMismatch,
                        path,
                        "SSE2 F64 operation requires F64 operands and result",
                    );
                }
            }
            X64InstructionKind::I64Setcc { left, right, .. } => {
                check(left, "left");
                check(right, "right");
                if instruction.result.ty != MachineType::Bool
                    || left.ty() != MachineType::I64
                    || right.ty() != MachineType::I64
                {
                    self.error(
                        X64TargetVerificationCode::TypeMismatch,
                        path,
                        "signed I64 comparison requires I64 operands and Bool result",
                    );
                }
            }
            X64InstructionKind::ArrayLenF64 { array } => {
                check(array, "array");
                if instruction.result.ty != MachineType::I64 || array.ty() != MachineType::F64Array
                {
                    self.error(
                        X64TargetVerificationCode::TypeMismatch,
                        path,
                        "ArrayLenF64 requires F64Array and produces I64",
                    );
                }
            }
            X64InstructionKind::ArrayGetF64Checked { array, index } => {
                check(array, "array");
                check(index, "index");
                if instruction.result.ty != MachineType::F64
                    || array.ty() != MachineType::F64Array
                    || index.ty() != MachineType::I64
                {
                    self.error(
                        X64TargetVerificationCode::TypeMismatch,
                        path,
                        "checked F64 array read requires (F64Array, I64) and produces F64",
                    );
                }
                if effects.binary_search(&MachineEffect::Bounds).is_err() {
                    self.error(
                        X64TargetVerificationCode::MissingEffect,
                        path,
                        "checked F64 array read requires Bounds in the function effect row",
                    );
                }
            }
        }
    }

    fn verify_terminator(
        &mut self,
        function: &X64Function,
        terminator: &X64Terminator,
        expected_origin: X64SourceOrigin,
        homes: &[X64Home],
        label_to_block: &BTreeMap<X64LabelId, X64BlockId>,
        path: &str,
    ) {
        match terminator {
            X64Terminator::Return { origin, value } => {
                if *origin != expected_origin {
                    self.error(
                        X64TargetVerificationCode::NonCanonicalOrder,
                        format!("{path}.origin"),
                        "terminator origin differs from its source position",
                    );
                }
                self.verify_operand(value, homes, &format!("{path}.value"));
                if value.ty() != function.result {
                    self.error(
                        X64TargetVerificationCode::TypeMismatch,
                        path,
                        "Return operand differs from function result type",
                    );
                }
            }
            X64Terminator::BranchRel32 {
                origin,
                condition,
                then_label,
                else_label,
            } => {
                if *origin != expected_origin {
                    self.error(
                        X64TargetVerificationCode::NonCanonicalOrder,
                        format!("{path}.origin"),
                        "terminator origin differs from its source position",
                    );
                }
                self.verify_operand(condition, homes, &format!("{path}.condition"));
                if condition.ty() != MachineType::Bool
                    || then_label == else_label
                    || !label_to_block.contains_key(then_label)
                    || !label_to_block.contains_key(else_label)
                {
                    self.error(
                        X64TargetVerificationCode::InvalidControlFlow,
                        path,
                        "Branch requires Bool and two distinct labels in the same function",
                    );
                }
            }
            X64Terminator::TailJumpRel32 {
                origin,
                function: target,
                target_label,
                arguments,
            } => {
                if *origin != expected_origin {
                    self.error(
                        X64TargetVerificationCode::NonCanonicalOrder,
                        format!("{path}.origin"),
                        "terminator origin differs from its source position",
                    );
                }
                for (index, argument) in arguments.iter().enumerate() {
                    self.verify_operand(argument, homes, &format!("{path}.arguments[{index}]"));
                }
                let target_function = self.program.functions.get(target.0 as usize);
                let valid = target_function.is_some_and(|callee| {
                    callee.id == *target
                        && callee.parameters.len() == arguments.len()
                        && callee
                            .parameters
                            .iter()
                            .zip(arguments)
                            .all(|(parameter, argument)| parameter.home.ty == argument.ty())
                        && callee.result == function.result
                        && callee.effects == function.effects
                        && callee
                            .blocks
                            .get(callee.entry_block.0 as usize)
                            .is_some_and(|block| block.label == *target_label)
                });
                if !valid {
                    self.error(
                        X64TargetVerificationCode::InvalidControlFlow,
                        path,
                        "TailJump target, entry label, signature, result, or effects differ",
                    );
                }
            }
        }
    }

    fn verify_cfg(
        &mut self,
        function: &X64Function,
        label_to_block: &BTreeMap<X64LabelId, X64BlockId>,
        path: &str,
    ) {
        if function.blocks.is_empty() {
            return;
        }
        let mut incoming = vec![0_u32; function.blocks.len()];
        for block in &function.blocks {
            if let X64Terminator::BranchRel32 {
                then_label,
                else_label,
                ..
            } = block.terminator
            {
                for target in [then_label, else_label] {
                    if let Some(block) = label_to_block.get(&target) {
                        if let Some(count) = incoming.get_mut(block.0 as usize) {
                            *count = count.saturating_add(1);
                        }
                    }
                }
            }
        }
        if incoming.first().copied().unwrap_or_default() != 0 {
            self.error(
                X64TargetVerificationCode::InvalidControlFlow,
                format!("{path}.blocks[0]"),
                "entry block must have no incoming branch edge",
            );
        }
        for (index, count) in incoming.iter().enumerate().skip(1) {
            if *count != 1 {
                self.error(
                    X64TargetVerificationCode::InvalidControlFlow,
                    format!("{path}.blocks[{index}]"),
                    format!("canonical branch tree requires one incoming edge; found {count}"),
                );
            }
        }
        let mut preorder = Vec::with_capacity(function.blocks.len());
        let mut stack = vec![(X64BlockId(0), 1_u32)];
        let mut seen = BTreeSet::new();
        while let Some((block_id, depth)) = stack.pop() {
            if depth > X64_TARGET_MAX_CFG_DEPTH || !seen.insert(block_id) {
                self.error(
                    X64TargetVerificationCode::InvalidControlFlow,
                    path,
                    "CFG is cyclic or exceeds the canonical depth limit",
                );
                return;
            }
            preorder.push(block_id.0 as usize);
            if let Some(X64Block {
                terminator:
                    X64Terminator::BranchRel32 {
                        then_label,
                        else_label,
                        ..
                    },
                ..
            }) = function.blocks.get(block_id.0 as usize)
            {
                if let (Some(then_block), Some(else_block)) = (
                    label_to_block.get(then_label),
                    label_to_block.get(else_label),
                ) {
                    stack.push((*else_block, depth.saturating_add(1)));
                    stack.push((*then_block, depth.saturating_add(1)));
                }
            }
        }
        if preorder != (0..function.blocks.len()).collect::<Vec<_>>() {
            self.error(
                X64TargetVerificationCode::InvalidControlFlow,
                path,
                "stored blocks must equal then-first CFG preorder",
            );
        }
    }

    fn verify_labels(&mut self) {
        let mut expected = Vec::new();
        expected.push(X64LabelOwner::EntryAdapter);
        for function in &self.program.functions {
            for block in &function.blocks {
                expected.push(X64LabelOwner::Block {
                    function: function.id,
                    block: block.id,
                });
            }
        }
        expected.push(X64LabelOwner::ReturnEpilogue);
        expected.push(X64LabelOwner::BoundsEpilogue);
        if self.program.labels.len() != expected.len() {
            self.error(
                X64TargetVerificationCode::InvalidLabel,
                "program.labels",
                format!(
                    "expected {} canonical labels, found {}",
                    expected.len(),
                    self.program.labels.len()
                ),
            );
            return;
        }
        let mut offsets = BTreeSet::new();
        for (index, (label, owner)) in self.program.labels.iter().zip(expected).enumerate() {
            if label.id.0 as usize != index || label.owner != owner {
                self.error(
                    X64TargetVerificationCode::InvalidLabel,
                    format!("program.labels[{index}]"),
                    "label ID or owner differs from canonical order",
                );
            }
            if label.code_offset as usize >= self.program.code.len()
                || !offsets.insert(label.code_offset)
            {
                self.error(
                    X64TargetVerificationCode::InvalidLabel,
                    format!("program.labels[{index}].code_offset"),
                    "label offset must be unique and inside the code blob",
                );
            }
        }
        if self
            .program
            .labels
            .first()
            .is_none_or(|label| label.code_offset != self.program.entry_offset)
        {
            self.error(
                X64TargetVerificationCode::InvalidLabel,
                "program.labels[0]",
                "entry-adapter label must define entry offset zero",
            );
        }
    }

    fn verify_raw_encoding(&mut self) {
        match raw::encode(self.program) {
            Ok(encoded) => {
                if encoded.labels != self.program.labels {
                    self.error(
                        X64TargetVerificationCode::InvalidLabel,
                        "program.labels",
                        "independent layout produced different label definitions",
                    );
                }
                if encoded.fixups != self.program.fixups {
                    self.error(
                        X64TargetVerificationCode::InvalidFixup,
                        "program.fixups",
                        "independent encoder produced different PcRel32 fixups",
                    );
                }
                if encoded.code != self.program.code {
                    self.error(
                        X64TargetVerificationCode::CodeMismatch,
                        "program.code",
                        "independent fixed-template encoding differs byte-for-byte",
                    );
                }
            }
            Err(error) => self.error(
                X64TargetVerificationCode::EncodingFailure,
                "program.code",
                error.to_string(),
            ),
        }
    }
}

fn derive_target_entry_abi(entry: &X64Function) -> Result<X64EntryAbi, String> {
    const REGISTERS: [X64AbiRegister; 6] = [
        X64AbiRegister::Rdi,
        X64AbiRegister::Rsi,
        X64AbiRegister::Rdx,
        X64AbiRegister::Rcx,
        X64AbiRegister::R8,
        X64AbiRegister::R9,
    ];
    let mut parameter_types = Vec::with_capacity(entry.parameters.len());
    let mut input_lanes = Vec::new();
    for (parameter_index, parameter) in entry.parameters.iter().enumerate() {
        parameter_types.push(parameter.home.ty);
        let words = match parameter.home.ty {
            MachineType::Unit => 0,
            MachineType::F64Array => 2,
            MachineType::Bool | MachineType::I64 | MachineType::F64 => 1,
        };
        for word in 0..words {
            let Some(register) = REGISTERS.get(input_lanes.len()).copied() else {
                return Err(format!(
                    "entry requires more than {} input lanes",
                    X64_TARGET_MAX_ENTRY_INPUT_LANES
                ));
            };
            input_lanes.push(X64EntryLane {
                parameter: parameter_index as u32,
                word: word as u8,
                register,
            });
        }
    }
    if input_lanes.len() as u32 > X64_TARGET_MAX_ENTRY_INPUT_LANES {
        return Err("entry input-lane cap exceeded".to_owned());
    }
    Ok(X64EntryAbi {
        parameter_types,
        output_register: REGISTERS[input_lanes.len()],
        input_lanes,
        result: entry.result,
        output_words: 2,
    })
}

fn instruction_operands(instruction: &X64InstructionKind) -> [Option<&X64Operand>; 2] {
    match instruction {
        X64InstructionKind::Move(value) => [Some(value), None],
        X64InstructionKind::I64Wrapping { left, right, .. }
        | X64InstructionKind::Sse2F64 { left, right, .. }
        | X64InstructionKind::I64Setcc { left, right, .. } => [Some(left), Some(right)],
        X64InstructionKind::ArrayLenF64 { array } => [Some(array), None],
        X64InstructionKind::ArrayGetF64Checked { array, index } => [Some(array), Some(index)],
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SourceBoundX64TargetArtifact<'target, 'machine, 'ssa, 'core> {
    verified: VerifiedX64TargetArtifact<'target>,
    source: SourceBoundMachineIrArtifact<'machine, 'ssa, 'core>,
}

impl<'target, 'machine, 'ssa, 'core> SourceBoundX64TargetArtifact<'target, 'machine, 'ssa, 'core> {
    pub fn artifact(self) -> &'target X64TargetArtifact {
        self.verified.artifact()
    }

    pub fn program(self) -> &'target X64TargetProgram {
        self.verified.program()
    }

    pub fn semantic_hash(self) -> SemanticHash {
        self.verified.semantic_hash()
    }

    pub fn code_hash(self) -> SemanticHash {
        self.verified.code_hash()
    }

    pub fn source_machine_ir(self) -> &'machine MachineIrArtifact {
        self.source.artifact()
    }

    pub fn source_ssa(self) -> &'ssa CoreSsaArtifact {
        self.source.source_ssa()
    }

    pub fn source_core(self) -> &'core CoreArtifact {
        self.source.source_core()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TargetSourceError {
    InvalidMachineSource(MachineIrSourceError),
    InvalidTarget(X64TargetVerificationErrors),
    SourceCoreHashMismatch {
        declared: SemanticHash,
        actual: SemanticHash,
    },
    SourceSsaHashMismatch {
        declared: SemanticHash,
        actual: SemanticHash,
    },
    SourceMachineIrHashMismatch {
        declared: SemanticHash,
        actual: SemanticHash,
    },
    ReplayFailed(X64TargetLowerError),
    TranslationMismatch {
        supplied: SemanticHash,
        replayed: SemanticHash,
    },
}

impl fmt::Display for X64TargetSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMachineSource(error) => write!(formatter, "{error}"),
            Self::InvalidTarget(errors) => write!(formatter, "{errors}"),
            Self::SourceCoreHashMismatch { declared, actual } => write!(
                formatter,
                "x86-64 target source Core hash declares {declared}; supplied source is {actual}"
            ),
            Self::SourceSsaHashMismatch { declared, actual } => write!(
                formatter,
                "x86-64 target source SSA hash declares {declared}; supplied source is {actual}"
            ),
            Self::SourceMachineIrHashMismatch { declared, actual } => write!(
                formatter,
                "x86-64 target source Machine IR hash declares {declared}; supplied source is {actual}"
            ),
            Self::ReplayFailed(error) => write!(formatter, "{error}"),
            Self::TranslationMismatch { supplied, replayed } => write!(
                formatter,
                "x86-64 target differs from deterministic source replay: supplied {supplied}; replayed {replayed}"
            ),
        }
    }
}

impl std::error::Error for X64TargetSourceError {}

/// Compose the R1-S6 source proof with local target verification and exact
/// target re-lowering/re-encoding.
pub fn verify_x64_target_source<'target, 'machine, 'ssa, 'core>(
    target: &'target X64TargetArtifact,
    source_machine_ir: &'machine MachineIrArtifact,
    source_ssa: &'ssa CoreSsaArtifact,
    source_core: &'core CoreArtifact,
) -> Result<SourceBoundX64TargetArtifact<'target, 'machine, 'ssa, 'core>, X64TargetSourceError> {
    let source = verify_machine_ir_source(source_machine_ir, source_ssa, source_core)
        .map_err(X64TargetSourceError::InvalidMachineSource)?;
    let verified = verify_x64_target_r1_s7a(target).map_err(X64TargetSourceError::InvalidTarget)?;
    if target.program.source_core_hash != source_core.semantic_hash {
        return Err(X64TargetSourceError::SourceCoreHashMismatch {
            declared: target.program.source_core_hash,
            actual: source_core.semantic_hash,
        });
    }
    if target.program.source_ssa_hash != source_ssa.semantic_hash {
        return Err(X64TargetSourceError::SourceSsaHashMismatch {
            declared: target.program.source_ssa_hash,
            actual: source_ssa.semantic_hash,
        });
    }
    if target.program.source_machine_ir_hash != source_machine_ir.semantic_hash {
        return Err(X64TargetSourceError::SourceMachineIrHashMismatch {
            declared: target.program.source_machine_ir_hash,
            actual: source_machine_ir.semantic_hash,
        });
    }
    let replayed =
        lower_x64_target_from_source(source).map_err(X64TargetSourceError::ReplayFailed)?;
    if target != &replayed {
        return Err(X64TargetSourceError::TranslationMismatch {
            supplied: target.semantic_hash,
            replayed: replayed.semantic_hash,
        });
    }
    Ok(SourceBoundX64TargetArtifact { verified, source })
}

#[derive(Debug)]
pub enum X64TargetPlanExecutionError {
    InvalidArtifact(X64TargetVerificationErrors),
    Execution(X64TargetPlanEvaluatorError),
}

impl fmt::Display for X64TargetPlanExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArtifact(errors) => write!(formatter, "{errors}"),
            Self::Execution(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for X64TargetPlanExecutionError {}

pub fn evaluate_x64_target_plan(
    artifact: &X64TargetArtifact,
    arguments: Vec<CoreValue>,
    budget: EvaluationBudget,
) -> Result<Evaluation, X64TargetPlanExecutionError> {
    let verified =
        verify_x64_target_r1_s7a(artifact).map_err(X64TargetPlanExecutionError::InvalidArtifact)?;
    eval::evaluate_program(verified.program(), arguments, budget)
        .map_err(X64TargetPlanExecutionError::Execution)
}

pub fn evaluate_source_bound_x64_target_plan(
    bound: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
    arguments: Vec<CoreValue>,
    budget: EvaluationBudget,
) -> Result<Evaluation, X64TargetPlanExecutionError> {
    eval::evaluate_program(bound.program(), arguments, budget)
        .map_err(X64TargetPlanExecutionError::Execution)
}

#[derive(Debug)]
pub enum X64TargetTranslationExecutionError {
    InvalidTranslation(X64TargetSourceError),
    Execution(X64TargetPlanEvaluatorError),
}

impl fmt::Display for X64TargetTranslationExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTranslation(error) => write!(formatter, "{error}"),
            Self::Execution(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for X64TargetTranslationExecutionError {}

pub fn evaluate_x64_target_translation(
    artifact: &X64TargetArtifact,
    source_machine_ir: &MachineIrArtifact,
    source_ssa: &CoreSsaArtifact,
    source_core: &CoreArtifact,
    arguments: Vec<CoreValue>,
    budget: EvaluationBudget,
) -> Result<Evaluation, X64TargetTranslationExecutionError> {
    let bound = verify_x64_target_source(artifact, source_machine_ir, source_ssa, source_core)
        .map_err(X64TargetTranslationExecutionError::InvalidTranslation)?;
    eval::evaluate_program(bound.program(), arguments, budget)
        .map_err(X64TargetTranslationExecutionError::Execution)
}
