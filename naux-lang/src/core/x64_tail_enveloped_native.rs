//! Sovereign W^X execution for an already verified ADR-0067 image.
//!
//! This module owns its Linux x86-64 syscall boundary and entry dispatch. It
//! accepts neither raw bytes nor a historical native/process/standalone
//! witness. Finite correspondence evidence is layered on this runner without
//! turning in-process execution into fault containment or performance proof.

use super::interpret::{CoreValue, EffectEvent, EvaluationOutcome};
use super::machine_ir::MachineType;
use super::schema::{ErrorKind, SemanticHash};
use super::x64_tail_enveloped_image::{
    x64_tail_enveloped_image_code_hash, VerifiedX64TailEnvelopedImage, X64TailEnvelopedImageError,
    X64_TAIL_ENVELOPED_IMAGE_MAX_CODE_BYTES,
};
use super::x64_target::{
    verify_x64_target_r1_s7a, X64AbiRegister, X64EntryAbi, X64TargetAbi, X64TargetArtifact,
};
use std::fmt;

pub const X64_TAIL_ENVELOPED_NATIVE_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_ENVELOPED_NATIVE_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_ENVELOPED_NATIVE_SYSCALL_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_TAIL_ENVELOPED_NATIVE_ENTRY_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);

pub const X64_TAIL_ENVELOPED_NATIVE_MAX_MAPPING_BYTES: u64 = 128 * 1024 * 1024;
pub const X64_TAIL_ENVELOPED_NATIVE_MAX_ENTRY_LANES: u32 = 5;
pub const X64_TAIL_ENVELOPED_NATIVE_MAX_BORROWED_F64_ARRAYS: u32 = 2;
pub const X64_TAIL_ENVELOPED_NATIVE_OUTPUT_WORDS: u32 = 2;
pub const X64_TAIL_ENVELOPED_NATIVE_MAPPING_STATE_EVENTS: u32 = 4;

const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;
const OUTPUT_SENTINEL: u64 = 0x68a4_d2f9_3c71_b50e;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X64TailEnvelopedNativeLimits {
    pub code_mappings_per_invocation: u32,
    pub max_mapping_bytes: u64,
    pub max_entry_lanes: u32,
    pub max_borrowed_f64_arrays: u32,
    pub output_words: u32,
    pub mapping_state_events: u32,
}

impl X64TailEnvelopedNativeLimits {
    pub const fn adr0068() -> Self {
        Self {
            code_mappings_per_invocation: 1,
            max_mapping_bytes: X64_TAIL_ENVELOPED_NATIVE_MAX_MAPPING_BYTES,
            max_entry_lanes: X64_TAIL_ENVELOPED_NATIVE_MAX_ENTRY_LANES,
            max_borrowed_f64_arrays: X64_TAIL_ENVELOPED_NATIVE_MAX_BORROWED_F64_ARRAYS,
            output_words: X64_TAIL_ENVELOPED_NATIVE_OUTPUT_WORDS,
            mapping_state_events: X64_TAIL_ENVELOPED_NATIVE_MAPPING_STATE_EVENTS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailEnvelopedNativeMappingState {
    Unmapped,
    ReadWrite,
    ReadExecute,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64TailEnvelopedNativeHashStage {
    ReadWrite,
    ReadExecute,
}

/// Opaque evidence for one successfully torn-down in-process invocation.
#[derive(Clone, Debug, PartialEq)]
pub struct X64TailEnvelopedNativeExecution {
    schema_version: (u16, u16, u16),
    runner_policy_version: (u16, u16, u16),
    syscall_policy_version: (u16, u16, u16),
    entry_policy_version: (u16, u16, u16),
    limits: X64TailEnvelopedNativeLimits,
    target_semantic_hash: SemanticHash,
    target_plan_hash: SemanticHash,
    image_hash: SemanticHash,
    verified_code_hash: SemanticHash,
    copied_rw_code_hash: SemanticHash,
    readback_rx_code_hash: SemanticHash,
    entry_point: u32,
    input_lanes: u8,
    mapping_trace: [X64TailEnvelopedNativeMappingState; 4],
    mxcsr_before: u32,
    mxcsr_after: u32,
    outcome: EvaluationOutcome,
    effect_trace: Vec<EffectEvent>,
    fallback: bool,
}

impl X64TailEnvelopedNativeExecution {
    pub const fn schema_version(&self) -> (u16, u16, u16) {
        self.schema_version
    }

    pub const fn runner_policy_version(&self) -> (u16, u16, u16) {
        self.runner_policy_version
    }

    pub const fn syscall_policy_version(&self) -> (u16, u16, u16) {
        self.syscall_policy_version
    }

    pub const fn entry_policy_version(&self) -> (u16, u16, u16) {
        self.entry_policy_version
    }

    pub const fn limits(&self) -> X64TailEnvelopedNativeLimits {
        self.limits
    }

    pub const fn target_semantic_hash(&self) -> SemanticHash {
        self.target_semantic_hash
    }

    pub const fn target_plan_hash(&self) -> SemanticHash {
        self.target_plan_hash
    }

    pub const fn image_hash(&self) -> SemanticHash {
        self.image_hash
    }

    pub const fn verified_code_hash(&self) -> SemanticHash {
        self.verified_code_hash
    }

    pub const fn copied_rw_code_hash(&self) -> SemanticHash {
        self.copied_rw_code_hash
    }

    pub const fn readback_rx_code_hash(&self) -> SemanticHash {
        self.readback_rx_code_hash
    }

    pub const fn entry_point(&self) -> u32 {
        self.entry_point
    }

    pub const fn input_lanes(&self) -> u8 {
        self.input_lanes
    }

    pub const fn mapping_trace(&self) -> [X64TailEnvelopedNativeMappingState; 4] {
        self.mapping_trace
    }

    pub const fn mxcsr_before(&self) -> u32 {
        self.mxcsr_before
    }

    pub const fn mxcsr_after(&self) -> u32 {
        self.mxcsr_after
    }

    pub const fn outcome(&self) -> &EvaluationOutcome {
        &self.outcome
    }

    pub fn effect_trace(&self) -> &[EffectEvent] {
        &self.effect_trace
    }

    pub const fn fallback(&self) -> bool {
        self.fallback
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64TailEnvelopedNativeRunnerError {
    UnsupportedHost,
    InvalidTarget,
    ImageTargetMismatch,
    InvalidRunnerEnvelope {
        field: &'static str,
    },
    InputArity {
        expected: usize,
        actual: usize,
    },
    InputType {
        parameter: usize,
        expected: MachineType,
    },
    InputSpanOverflow {
        parameter: usize,
    },
    InputOutputOverlap {
        parameter: usize,
    },
    CodeLimit {
        limit: u64,
        actual: u64,
    },
    CodeHashEncoding(String),
    CodeHashMismatch {
        stage: X64TailEnvelopedNativeHashStage,
        expected: SemanticHash,
        actual: SemanticHash,
    },
    MappingFailed {
        operation: &'static str,
        errno: i32,
    },
    UnknownOutcomeTag {
        tag: u32,
    },
    NonCanonicalOutput {
        result: MachineType,
        word0: u64,
        word1: u64,
    },
    ForeignArrayResult {
        data: u64,
        length: u64,
    },
    MxcsrNotRestored {
        before: u32,
        after: u32,
    },
}

impl fmt::Display for X64TailEnvelopedNativeRunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost => {
                formatter.write_str("ADR-0068 native execution requires Linux x86-64")
            }
            Self::InvalidTarget => {
                formatter.write_str("ADR-0068 target does not pass R1-S7a verification")
            }
            Self::ImageTargetMismatch => {
                formatter.write_str("ADR-0068 verified image does not bind the supplied target")
            }
            Self::InvalidRunnerEnvelope { field } => {
                write!(formatter, "ADR-0068 runner envelope has invalid {field}")
            }
            Self::InputArity { expected, actual } => write!(
                formatter,
                "ADR-0068 input arity is {actual}; entry requires {expected}"
            ),
            Self::InputType {
                parameter,
                expected,
            } => write!(
                formatter,
                "ADR-0068 input {parameter} does not have required type {expected:?}"
            ),
            Self::InputSpanOverflow { parameter } => write!(
                formatter,
                "ADR-0068 F64 array input {parameter} has an overflowing host span"
            ),
            Self::InputOutputOverlap { parameter } => write!(
                formatter,
                "ADR-0068 output area overlaps F64 array input {parameter}"
            ),
            Self::CodeLimit { limit, actual } => {
                write!(
                    formatter,
                    "ADR-0068 code uses {actual} bytes; limit is {limit}"
                )
            }
            Self::CodeHashEncoding(error) => {
                write!(formatter, "ADR-0068 cannot hash mapped image: {error}")
            }
            Self::CodeHashMismatch {
                stage,
                expected,
                actual,
            } => write!(
                formatter,
                "ADR-0068 {stage:?} code hash {actual} differs from {expected}"
            ),
            Self::MappingFailed { operation, errno } => write!(
                formatter,
                "ADR-0068 {operation} syscall failed with errno {errno}"
            ),
            Self::UnknownOutcomeTag { tag } => {
                write!(
                    formatter,
                    "ADR-0068 entry returned unknown outcome tag {tag}"
                )
            }
            Self::NonCanonicalOutput {
                result,
                word0,
                word1,
            } => write!(
                formatter,
                "ADR-0068 {result:?} output is noncanonical: {word0:#018x}, {word1:#018x}"
            ),
            Self::ForeignArrayResult { data, length } => write!(
                formatter,
                "ADR-0068 array output ({data:#018x}, {length}) is not a borrowed input"
            ),
            Self::MxcsrNotRestored { before, after } => write!(
                formatter,
                "ADR-0068 entry changed caller MXCSR from {before:#010x} to {after:#010x}"
            ),
        }
    }
}

impl std::error::Error for X64TailEnvelopedNativeRunnerError {}

impl From<X64TailEnvelopedImageError> for X64TailEnvelopedNativeRunnerError {
    fn from(value: X64TailEnvelopedImageError) -> Self {
        Self::CodeHashEncoding(value.to_string())
    }
}

#[derive(Clone, Copy)]
struct ArraySpan<'value> {
    parameter: usize,
    data: u64,
    length: u64,
    end: u64,
    value: &'value CoreValue,
}

/// Execute the exact code and entry point carried by an opaque verified
/// ADR-0067 witness. This is in-process correctness authority, not containment.
pub fn execute_x64_tail_enveloped_native(
    target: &X64TargetArtifact,
    verified: &VerifiedX64TailEnvelopedImage<'_>,
    arguments: &[CoreValue],
) -> Result<X64TailEnvelopedNativeExecution, X64TailEnvelopedNativeRunnerError> {
    verify_x64_target_r1_s7a(target)
        .map_err(|_| X64TailEnvelopedNativeRunnerError::InvalidTarget)?;
    if verified.image().source_target_semantic_hash() != target.semantic_hash {
        return Err(X64TailEnvelopedNativeRunnerError::ImageTargetMismatch);
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        execute_supported(target, verified, arguments)
    }

    #[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
    {
        let _ = (target, verified, arguments);
        Err(X64TailEnvelopedNativeRunnerError::UnsupportedHost)
    }
}

/// Run one sovereign correspondence observation from the target's canonical
/// floating-point environment while restoring the embedding thread on every
/// return path. The ordinary runner intentionally observes arbitrary caller
/// MXCSR; this scoped entry exists only to make sealed correspondence evidence
/// independent of ambient sticky exception flags.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub(crate) fn execute_x64_tail_enveloped_native_canonical_mxcsr(
    target: &X64TargetArtifact,
    verified: &VerifiedX64TailEnvelopedImage<'_>,
    arguments: &[CoreValue],
) -> Result<X64TailEnvelopedNativeExecution, X64TailEnvelopedNativeRunnerError> {
    struct RestoreMxcsr(u32);

    impl Drop for RestoreMxcsr {
        fn drop(&mut self) {
            platform::write_mxcsr(self.0);
        }
    }

    let _restore = RestoreMxcsr(platform::read_mxcsr());
    platform::write_mxcsr(target.program.abi.canonical_mxcsr);
    execute_x64_tail_enveloped_native(target, verified, arguments)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
pub(crate) fn execute_x64_tail_enveloped_native_canonical_mxcsr(
    target: &X64TargetArtifact,
    verified: &VerifiedX64TailEnvelopedImage<'_>,
    arguments: &[CoreValue],
) -> Result<X64TailEnvelopedNativeExecution, X64TailEnvelopedNativeRunnerError> {
    execute_x64_tail_enveloped_native(target, verified, arguments)
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn execute_supported(
    target: &X64TargetArtifact,
    verified: &VerifiedX64TailEnvelopedImage<'_>,
    arguments: &[CoreValue],
) -> Result<X64TailEnvelopedNativeExecution, X64TailEnvelopedNativeRunnerError> {
    let program = &target.program;
    let image = verified.image();
    validate_runner_envelope(
        program.abi,
        &program.entry_abi,
        image.code(),
        image.entry_point(),
    )?;

    let (lanes, arrays) = flatten_arguments(&program.entry_abi.parameter_types, arguments)?;
    validate_entry_abi(&program.entry_abi, lanes.len())?;

    let mut output = [OUTPUT_SENTINEL; 2];
    validate_output_disjoint(&arrays, output.as_ptr() as usize as u64)?;

    let mut mapping = platform::NativeMapping::allocate(image.code().len())?;
    mapping.copy_from(image.code());
    let copied_rw_code_hash = x64_tail_enveloped_image_code_hash(mapping.bytes())?;
    if copied_rw_code_hash != image.code_hash() {
        return Err(X64TailEnvelopedNativeRunnerError::CodeHashMismatch {
            stage: X64TailEnvelopedNativeHashStage::ReadWrite,
            expected: image.code_hash(),
            actual: copied_rw_code_hash,
        });
    }

    mapping.protect_rx()?;
    let readback_rx_code_hash = x64_tail_enveloped_image_code_hash(mapping.bytes())?;
    if readback_rx_code_hash != image.code_hash() {
        return Err(X64TailEnvelopedNativeRunnerError::CodeHashMismatch {
            stage: X64TailEnvelopedNativeHashStage::ReadExecute,
            expected: image.code_hash(),
            actual: readback_rx_code_hash,
        });
    }

    let mxcsr_before = platform::read_mxcsr();
    // SAFETY: the mapping is RX and byte-identical to the verified image; the
    // verified entry point lies inside it; the ABI preflight derives the exact
    // signature; arrays remain borrowed; output owns two disjoint words.
    let tag = unsafe {
        platform::call_entry(
            mapping.entry(image.entry_point()),
            &lanes,
            output.as_mut_ptr(),
        )
    };
    let mxcsr_after = platform::read_mxcsr();
    let decoded = decode_output(tag, program.entry_abi.result, output, &arrays);
    mapping.unmap()?;

    if mxcsr_after != mxcsr_before {
        return Err(X64TailEnvelopedNativeRunnerError::MxcsrNotRestored {
            before: mxcsr_before,
            after: mxcsr_after,
        });
    }
    let (outcome, effect_trace) = decoded?;

    Ok(X64TailEnvelopedNativeExecution {
        schema_version: X64_TAIL_ENVELOPED_NATIVE_SCHEMA_VERSION,
        runner_policy_version: X64_TAIL_ENVELOPED_NATIVE_POLICY_VERSION,
        syscall_policy_version: X64_TAIL_ENVELOPED_NATIVE_SYSCALL_POLICY_VERSION,
        entry_policy_version: X64_TAIL_ENVELOPED_NATIVE_ENTRY_POLICY_VERSION,
        limits: X64TailEnvelopedNativeLimits::adr0068(),
        target_semantic_hash: target.semantic_hash,
        target_plan_hash: program.plan_hash,
        image_hash: image.image_hash(),
        verified_code_hash: image.code_hash(),
        copied_rw_code_hash,
        readback_rx_code_hash,
        entry_point: image.entry_point(),
        input_lanes: lanes.len() as u8,
        mapping_trace: [
            X64TailEnvelopedNativeMappingState::Unmapped,
            X64TailEnvelopedNativeMappingState::ReadWrite,
            X64TailEnvelopedNativeMappingState::ReadExecute,
            X64TailEnvelopedNativeMappingState::Unmapped,
        ],
        mxcsr_before,
        mxcsr_after,
        outcome,
        effect_trace,
        fallback: false,
    })
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn validate_runner_envelope(
    abi: X64TargetAbi,
    entry: &X64EntryAbi,
    code: &[u8],
    entry_point: u32,
) -> Result<(), X64TailEnvelopedNativeRunnerError> {
    if abi != X64TargetAbi::r1_s7a() {
        return Err(X64TailEnvelopedNativeRunnerError::InvalidRunnerEnvelope {
            field: "target ABI",
        });
    }
    if entry.output_words != X64_TAIL_ENVELOPED_NATIVE_OUTPUT_WORDS as u8 {
        return Err(X64TailEnvelopedNativeRunnerError::InvalidRunnerEnvelope {
            field: "output word count",
        });
    }
    if code.is_empty() {
        return Err(X64TailEnvelopedNativeRunnerError::InvalidRunnerEnvelope {
            field: "empty code image",
        });
    }
    let code_length =
        u64::try_from(code.len()).map_err(|_| X64TailEnvelopedNativeRunnerError::CodeLimit {
            limit: X64_TAIL_ENVELOPED_NATIVE_MAX_MAPPING_BYTES,
            actual: u64::MAX,
        })?;
    let limit =
        X64_TAIL_ENVELOPED_NATIVE_MAX_MAPPING_BYTES.min(X64_TAIL_ENVELOPED_IMAGE_MAX_CODE_BYTES);
    if code_length > limit {
        return Err(X64TailEnvelopedNativeRunnerError::CodeLimit {
            limit,
            actual: code_length,
        });
    }
    let entry_point = usize::try_from(entry_point).map_err(|_| {
        X64TailEnvelopedNativeRunnerError::InvalidRunnerEnvelope {
            field: "entry point",
        }
    })?;
    if entry_point >= code.len() {
        return Err(X64TailEnvelopedNativeRunnerError::InvalidRunnerEnvelope {
            field: "entry point",
        });
    }
    Ok(())
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn flatten_arguments<'value>(
    parameter_types: &[MachineType],
    arguments: &'value [CoreValue],
) -> Result<(Vec<u64>, Vec<ArraySpan<'value>>), X64TailEnvelopedNativeRunnerError> {
    if arguments.len() != parameter_types.len() {
        return Err(X64TailEnvelopedNativeRunnerError::InputArity {
            expected: parameter_types.len(),
            actual: arguments.len(),
        });
    }

    let mut lanes = Vec::with_capacity(X64_TAIL_ENVELOPED_NATIVE_MAX_ENTRY_LANES as usize);
    let mut arrays = Vec::with_capacity(X64_TAIL_ENVELOPED_NATIVE_MAX_BORROWED_F64_ARRAYS as usize);
    for (parameter, (ty, value)) in parameter_types.iter().zip(arguments).enumerate() {
        match (ty, value) {
            (MachineType::Unit, CoreValue::Unit) => {}
            (MachineType::Bool, CoreValue::Bool(value)) => lanes.push(u64::from(*value)),
            (MachineType::I64, CoreValue::I64(value)) => lanes.push(*value as u64),
            (MachineType::F64, CoreValue::F64(value)) => lanes.push(value.to_bits()),
            (MachineType::F64Array, CoreValue::ArrayF64(values)) => {
                let length = u64::try_from(values.len()).map_err(|_| {
                    X64TailEnvelopedNativeRunnerError::InputSpanOverflow { parameter }
                })?;
                if length > i64::MAX as u64 {
                    return Err(X64TailEnvelopedNativeRunnerError::InputSpanOverflow { parameter });
                }
                let data = values.as_ptr() as usize as u64;
                let bytes = length
                    .checked_mul(8)
                    .ok_or(X64TailEnvelopedNativeRunnerError::InputSpanOverflow { parameter })?;
                let end = data
                    .checked_add(bytes)
                    .ok_or(X64TailEnvelopedNativeRunnerError::InputSpanOverflow { parameter })?;
                if length > 0 && data == 0 {
                    return Err(X64TailEnvelopedNativeRunnerError::InputSpanOverflow { parameter });
                }
                lanes.push(data);
                lanes.push(length);
                arrays.push(ArraySpan {
                    parameter,
                    data,
                    length,
                    end,
                    value,
                });
            }
            _ => {
                return Err(X64TailEnvelopedNativeRunnerError::InputType {
                    parameter,
                    expected: *ty,
                });
            }
        }
    }
    if lanes.len() > X64_TAIL_ENVELOPED_NATIVE_MAX_ENTRY_LANES as usize {
        return Err(X64TailEnvelopedNativeRunnerError::InvalidRunnerEnvelope {
            field: "input lane count",
        });
    }
    if arrays.len() > X64_TAIL_ENVELOPED_NATIVE_MAX_BORROWED_F64_ARRAYS as usize {
        return Err(X64TailEnvelopedNativeRunnerError::InvalidRunnerEnvelope {
            field: "borrowed array count",
        });
    }
    Ok((lanes, arrays))
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn validate_entry_abi(
    entry: &X64EntryAbi,
    flattened_lanes: usize,
) -> Result<(), X64TailEnvelopedNativeRunnerError> {
    const REGISTERS: [X64AbiRegister; 6] = [
        X64AbiRegister::Rdi,
        X64AbiRegister::Rsi,
        X64AbiRegister::Rdx,
        X64AbiRegister::Rcx,
        X64AbiRegister::R8,
        X64AbiRegister::R9,
    ];

    let mut expected_parameter = Vec::new();
    let mut expected_word = Vec::new();
    for (parameter, ty) in entry.parameter_types.iter().enumerate() {
        let parameter = u32::try_from(parameter).map_err(|_| {
            X64TailEnvelopedNativeRunnerError::InvalidRunnerEnvelope {
                field: "parameter index",
            }
        })?;
        match ty {
            MachineType::Unit => {}
            MachineType::Bool | MachineType::I64 | MachineType::F64 => {
                expected_parameter.push(parameter);
                expected_word.push(0);
            }
            MachineType::F64Array => {
                expected_parameter.extend_from_slice(&[parameter, parameter]);
                expected_word.extend_from_slice(&[0, 1]);
            }
        }
    }
    if flattened_lanes != expected_parameter.len()
        || entry.input_lanes.len() != expected_parameter.len()
        || flattened_lanes > X64_TAIL_ENVELOPED_NATIVE_MAX_ENTRY_LANES as usize
        || entry.output_register != REGISTERS[flattened_lanes]
    {
        return Err(X64TailEnvelopedNativeRunnerError::InvalidRunnerEnvelope {
            field: "entry lane manifest",
        });
    }
    for (ordinal, lane) in entry.input_lanes.iter().enumerate() {
        if lane.parameter != expected_parameter[ordinal]
            || lane.word != expected_word[ordinal]
            || lane.register != REGISTERS[ordinal]
        {
            return Err(X64TailEnvelopedNativeRunnerError::InvalidRunnerEnvelope {
                field: "entry lane ordering",
            });
        }
    }
    Ok(())
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn validate_output_disjoint(
    arrays: &[ArraySpan<'_>],
    output_start: u64,
) -> Result<(), X64TailEnvelopedNativeRunnerError> {
    let output_end = output_start.checked_add(16).ok_or(
        X64TailEnvelopedNativeRunnerError::InvalidRunnerEnvelope {
            field: "output span",
        },
    )?;
    for array in arrays {
        if array.length > 0 && output_start < array.end && array.data < output_end {
            return Err(X64TailEnvelopedNativeRunnerError::InputOutputOverlap {
                parameter: array.parameter,
            });
        }
    }
    Ok(())
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn decode_output(
    tag: u32,
    result: MachineType,
    output: [u64; 2],
    arrays: &[ArraySpan<'_>],
) -> Result<(EvaluationOutcome, Vec<EffectEvent>), X64TailEnvelopedNativeRunnerError> {
    match tag {
        0 => {
            let value = match result {
                MachineType::Unit if output == [0, 0] => CoreValue::Unit,
                MachineType::Bool if output[0] <= 1 && output[1] == 0 => {
                    CoreValue::Bool(output[0] == 1)
                }
                MachineType::I64 if output[1] == 0 => CoreValue::I64(output[0] as i64),
                MachineType::F64
                    if output[1] == 0
                        && (!f64::from_bits(output[0]).is_nan()
                            || output[0] == CANONICAL_NAN_BITS) =>
                {
                    CoreValue::F64(f64::from_bits(output[0]))
                }
                MachineType::F64Array => {
                    let Some(array) = arrays
                        .iter()
                        .find(|array| array.data == output[0] && array.length == output[1])
                    else {
                        return Err(X64TailEnvelopedNativeRunnerError::ForeignArrayResult {
                            data: output[0],
                            length: output[1],
                        });
                    };
                    array.value.clone()
                }
                _ => {
                    return Err(X64TailEnvelopedNativeRunnerError::NonCanonicalOutput {
                        result,
                        word0: output[0],
                        word1: output[1],
                    });
                }
            };
            Ok((EvaluationOutcome::Return(value), Vec::new()))
        }
        1 if output == [0, 0] => Ok((
            EvaluationOutcome::Error(ErrorKind::Bounds),
            vec![EffectEvent::Error(ErrorKind::Bounds)],
        )),
        1 => Err(X64TailEnvelopedNativeRunnerError::NonCanonicalOutput {
            result,
            word0: output[0],
            word1: output[1],
        }),
        tag => Err(X64TailEnvelopedNativeRunnerError::UnknownOutcomeTag { tag }),
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod platform {
    use super::X64TailEnvelopedNativeRunnerError;
    use std::arch::asm;
    use std::sync::atomic::{fence, Ordering};

    const SYS_MMAP: usize = 9;
    const SYS_MPROTECT: usize = 10;
    const SYS_MUNMAP: usize = 11;
    const PROT_READ: usize = 0x1;
    const PROT_WRITE: usize = 0x2;
    const PROT_EXEC: usize = 0x4;
    const MAP_PRIVATE: usize = 0x02;
    const MAP_ANONYMOUS: usize = 0x20;

    pub(super) struct NativeMapping {
        pointer: *mut u8,
        length: usize,
        rx: bool,
    }

    impl NativeMapping {
        pub(super) fn allocate(length: usize) -> Result<Self, X64TailEnvelopedNativeRunnerError> {
            // SAFETY: raw Linux syscall ABI with scalar arguments only.
            let result = unsafe {
                syscall6(
                    SYS_MMAP,
                    0,
                    length,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    usize::MAX,
                    0,
                )
            };
            let pointer = syscall_pointer("mmap", result)?;
            if pointer.is_null() {
                return Err(X64TailEnvelopedNativeRunnerError::MappingFailed {
                    operation: "mmap",
                    errno: 0,
                });
            }
            Ok(Self {
                pointer,
                length,
                rx: false,
            })
        }

        pub(super) fn copy_from(&mut self, code: &[u8]) {
            debug_assert_eq!(code.len(), self.length);
            // SAFETY: mapping and source are non-overlapping and equally sized.
            unsafe {
                std::ptr::copy_nonoverlapping(code.as_ptr(), self.pointer, self.length);
            }
            fence(Ordering::SeqCst);
        }

        pub(super) fn protect_rx(&mut self) -> Result<(), X64TailEnvelopedNativeRunnerError> {
            // SAFETY: this live mapping was returned by mmap.
            let result = unsafe {
                syscall6(
                    SYS_MPROTECT,
                    self.pointer as usize,
                    self.length,
                    PROT_READ | PROT_EXEC,
                    0,
                    0,
                    0,
                )
            };
            syscall_unit("mprotect", result)?;
            self.rx = true;
            fence(Ordering::SeqCst);
            Ok(())
        }

        pub(super) fn bytes(&self) -> &[u8] {
            // SAFETY: the live mapping is readable in both admitted states.
            unsafe { std::slice::from_raw_parts(self.pointer, self.length) }
        }

        pub(super) fn entry(&self, offset: u32) -> *const u8 {
            debug_assert!(self.rx);
            // SAFETY: caller checked the entry is within the image.
            unsafe { self.pointer.add(offset as usize).cast_const() }
        }

        pub(super) fn unmap(&mut self) -> Result<(), X64TailEnvelopedNativeRunnerError> {
            if self.pointer.is_null() {
                return Ok(());
            }
            // SAFETY: mapping is live and still owns its exact extent.
            let result =
                unsafe { syscall6(SYS_MUNMAP, self.pointer as usize, self.length, 0, 0, 0, 0) };
            syscall_unit("munmap", result)?;
            self.pointer = std::ptr::null_mut();
            self.length = 0;
            self.rx = false;
            Ok(())
        }
    }

    impl Drop for NativeMapping {
        fn drop(&mut self) {
            if !self.pointer.is_null() {
                // SAFETY: best-effort cleanup of the still-live mapping.
                let _ =
                    unsafe { syscall6(SYS_MUNMAP, self.pointer as usize, self.length, 0, 0, 0, 0) };
            }
        }
    }

    fn syscall_pointer(
        operation: &'static str,
        result: isize,
    ) -> Result<*mut u8, X64TailEnvelopedNativeRunnerError> {
        if let Some(errno) = syscall_errno(result) {
            Err(X64TailEnvelopedNativeRunnerError::MappingFailed { operation, errno })
        } else {
            Ok(result as usize as *mut u8)
        }
    }

    fn syscall_unit(
        operation: &'static str,
        result: isize,
    ) -> Result<(), X64TailEnvelopedNativeRunnerError> {
        if let Some(errno) = syscall_errno(result) {
            Err(X64TailEnvelopedNativeRunnerError::MappingFailed { operation, errno })
        } else if result == 0 {
            Ok(())
        } else {
            Err(X64TailEnvelopedNativeRunnerError::MappingFailed {
                operation,
                errno: 0,
            })
        }
    }

    fn syscall_errno(result: isize) -> Option<i32> {
        (-4095..=-1).contains(&result).then_some((-result) as i32)
    }

    unsafe fn syscall6(
        number: usize,
        argument0: usize,
        argument1: usize,
        argument2: usize,
        argument3: usize,
        argument4: usize,
        argument5: usize,
    ) -> isize {
        let mut result = number as isize;
        // SAFETY: operands follow the Linux x86-64 syscall ABI.
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") result,
                in("rdi") argument0,
                in("rsi") argument1,
                in("rdx") argument2,
                in("r10") argument3,
                in("r8") argument4,
                in("r9") argument5,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        result
    }

    pub(super) fn read_mxcsr() -> u32 {
        let mut value = 0_u32;
        // SAFETY: stmxcsr writes exactly four bytes to this Rust local.
        unsafe {
            asm!(
                "stmxcsr [{pointer}]",
                pointer = in(reg) &mut value,
                options(nostack, preserves_flags),
            );
        }
        value
    }

    pub(super) fn write_mxcsr(value: u32) {
        // SAFETY: value is either captured from this thread or canonical ABI.
        unsafe {
            asm!(
                "ldmxcsr [{pointer}]",
                pointer = in(reg) &value,
                options(nostack, preserves_flags),
            );
        }
    }

    pub(super) unsafe fn call_entry(entry: *const u8, lanes: &[u64], output: *mut u64) -> u32 {
        type Entry0 = unsafe extern "C" fn(*mut u64) -> u32;
        type Entry1 = unsafe extern "C" fn(u64, *mut u64) -> u32;
        type Entry2 = unsafe extern "C" fn(u64, u64, *mut u64) -> u32;
        type Entry3 = unsafe extern "C" fn(u64, u64, u64, *mut u64) -> u32;
        type Entry4 = unsafe extern "C" fn(u64, u64, u64, u64, *mut u64) -> u32;
        type Entry5 = unsafe extern "C" fn(u64, u64, u64, u64, u64, *mut u64) -> u32;

        match lanes {
            [] => {
                // SAFETY: caller proved the zero-lane signature.
                let function = unsafe { std::mem::transmute::<*const u8, Entry0>(entry) };
                unsafe { function(output) }
            }
            [a0] => {
                // SAFETY: caller proved the one-lane signature.
                let function = unsafe { std::mem::transmute::<*const u8, Entry1>(entry) };
                unsafe { function(*a0, output) }
            }
            [a0, a1] => {
                // SAFETY: caller proved the two-lane signature.
                let function = unsafe { std::mem::transmute::<*const u8, Entry2>(entry) };
                unsafe { function(*a0, *a1, output) }
            }
            [a0, a1, a2] => {
                // SAFETY: caller proved the three-lane signature.
                let function = unsafe { std::mem::transmute::<*const u8, Entry3>(entry) };
                unsafe { function(*a0, *a1, *a2, output) }
            }
            [a0, a1, a2, a3] => {
                // SAFETY: caller proved the four-lane signature.
                let function = unsafe { std::mem::transmute::<*const u8, Entry4>(entry) };
                unsafe { function(*a0, *a1, *a2, *a3, output) }
            }
            [a0, a1, a2, a3, a4] => {
                // SAFETY: caller proved the five-lane signature.
                let function = unsafe { std::mem::transmute::<*const u8, Entry5>(entry) };
                unsafe { function(*a0, *a1, *a2, *a3, *a4, output) }
            }
            _ => unreachable!("ADR-0068 preflight admits at most five lanes"),
        }
    }
}

#[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
mod tests {
    use super::*;
    use crate::core::corevm0_gate_a::CoreVmGateAWorkload::{BoundsOrderedArrayGet, BranchMix};
    use crate::core::interpret::{Evaluation, EvaluationBudget};
    use crate::core::x64_native_lighthouse::X64NativeLighthousePackage;
    use crate::core::x64_tail_abi_envelope::X64TailAbiEnvelopeProgramKind;
    use crate::core::x64_tail_body_frontier_capsule::X64TailBodyCapsuleProgramKind;
    use crate::core::x64_tail_body_frontier_realization::{
        X64TailBodyAtomInstruction, X64TailBodyControlTarget,
    };
    use crate::core::x64_tail_closed_image::{X64TailClosedProgramKind, X64TailClosedTerminalKind};
    use crate::core::x64_tail_enveloped_image::X64TailEnvelopedRelocationOrigin;
    use crate::core::x64_tail_site_binding::X64TailFrontierBindingKind;
    use crate::core::x64_target::X64LabelOwner;
    use crate::core::{
        emit_x64_tail_abi_envelope_capsule, emit_x64_tail_body_frontier_capsule,
        emit_x64_tail_body_frontier_realization, emit_x64_tail_candidate_capsule,
        emit_x64_tail_closed_image, emit_x64_tail_enveloped_image,
        emit_x64_tail_physical_allocation, emit_x64_tail_site_binding_proof,
        emit_x64_tail_state_plan, emit_x64_tail_template_realization, evaluate_x64_target_plan,
        verify_x64_tail_abi_envelope_capsule, verify_x64_tail_closed_image,
        verify_x64_tail_enveloped_image, X64TailAbiEnvelopeCapsule, X64TailBodyFrontierCapsule,
        X64TailBodyFrontierRealization, X64TailCandidateCapsule, X64TailClosedImage,
        X64TailEnvelopedImage, X64TailPhysicalAllocation, X64TailSiteBindingProof,
        X64TailStatePlan, X64TailTemplateRealization, COREVM0_GATE_A_CALL_DEPTH_LIMIT,
        COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
    };

    struct Fixture {
        package: X64NativeLighthousePackage,
        logical: X64TailStatePlan,
        physical: X64TailPhysicalAllocation,
        templates: X64TailTemplateRealization,
        transition: X64TailCandidateCapsule,
        binding: X64TailSiteBindingProof,
        realization: X64TailBodyFrontierRealization,
        body: X64TailBodyFrontierCapsule,
        closed: X64TailClosedImage,
        abi: X64TailAbiEnvelopeCapsule,
        image: X64TailEnvelopedImage,
    }

    struct MxcsrRestore(u32);

    impl Drop for MxcsrRestore {
        fn drop(&mut self) {
            platform::write_mxcsr(self.0);
        }
    }

    impl Fixture {
        fn build(workload: crate::core::CoreVmGateAWorkload) -> Self {
            let package =
                X64NativeLighthousePackage::build(workload).expect("lighthouse must build");
            let logical = emit_x64_tail_state_plan(package.target()).expect("state plan must emit");
            let physical = emit_x64_tail_physical_allocation(package.target(), &logical)
                .expect("allocation must emit");
            let templates =
                emit_x64_tail_template_realization(package.target(), &logical, &physical)
                    .expect("templates must emit");
            let transition =
                emit_x64_tail_candidate_capsule(package.target(), &logical, &physical, &templates)
                    .expect("candidate capsule must emit");
            let binding = emit_x64_tail_site_binding_proof(
                package.target(),
                &logical,
                &physical,
                &templates,
                &transition,
            )
            .expect("binding proof must emit");
            let realization = emit_x64_tail_body_frontier_realization(
                package.target(),
                &logical,
                &physical,
                &templates,
                &transition,
                &binding,
            )
            .expect("body realization must emit");
            let body = emit_x64_tail_body_frontier_capsule(
                package.target(),
                &logical,
                &physical,
                &templates,
                &transition,
                &binding,
                &realization,
            )
            .expect("body capsule must emit");
            let closed = emit_x64_tail_closed_image(
                package.target(),
                &logical,
                &physical,
                &templates,
                &transition,
                &binding,
                &realization,
                &body,
            )
            .expect("closed image must emit");
            let verified_closed = verify_x64_tail_closed_image(
                &closed,
                &body,
                &realization,
                &binding,
                &transition,
                &templates,
                &physical,
                &logical,
                package.target(),
            )
            .expect("closed image must verify");
            let abi = emit_x64_tail_abi_envelope_capsule(package.target(), &verified_closed)
                .expect("ABI capsule must emit");
            let verified_abi =
                verify_x64_tail_abi_envelope_capsule(&abi, package.target(), &verified_closed)
                    .expect("ABI capsule must verify");
            let image =
                emit_x64_tail_enveloped_image(package.target(), &verified_closed, &verified_abi)
                    .expect("enveloped image must emit");
            Self {
                package,
                logical,
                physical,
                templates,
                transition,
                binding,
                realization,
                body,
                closed,
                abi,
                image,
            }
        }

        fn verified(&self) -> VerifiedX64TailEnvelopedImage<'_> {
            let verified_closed = verify_x64_tail_closed_image(
                &self.closed,
                &self.body,
                &self.realization,
                &self.binding,
                &self.transition,
                &self.templates,
                &self.physical,
                &self.logical,
                self.package.target(),
            )
            .expect("closed image must verify");
            let verified_abi = verify_x64_tail_abi_envelope_capsule(
                &self.abi,
                self.package.target(),
                &verified_closed,
            )
            .expect("ABI capsule must verify");
            let verified = verify_x64_tail_enveloped_image(
                &self.image,
                self.package.target(),
                &verified_closed,
                &verified_abi,
            )
            .expect("enveloped image must verify");
            verified
        }
    }

    fn assert_same_evaluation(expected: &Evaluation, actual: &X64TailEnvelopedNativeExecution) {
        match (&expected.outcome, actual.outcome()) {
            (
                EvaluationOutcome::Return(CoreValue::F64(expected)),
                EvaluationOutcome::Return(CoreValue::F64(actual)),
            ) if expected.is_nan() && actual.is_nan() => {}
            (
                EvaluationOutcome::Return(CoreValue::F64(expected)),
                EvaluationOutcome::Return(CoreValue::F64(actual)),
            ) => assert_eq!(actual.to_bits(), expected.to_bits()),
            (expected, actual) => assert_eq!(actual, expected),
        }
        assert_eq!(actual.effect_trace(), expected.effect_trace);
    }

    #[test]
    fn return_frontier_relocation_preserves_the_return_epilogue_label() {
        let fixture = Fixture::build(BranchMix);
        let return_label = fixture
            .package
            .target()
            .program
            .labels
            .iter()
            .find(|label| label.owner == X64LabelOwner::ReturnEpilogue)
            .expect("target must contain a return epilogue")
            .id;
        let expected_target = X64TailBodyControlTarget::Label(return_label);
        let expected_offset = fixture
            .image
            .abi_programs()
            .iter()
            .find(|program| program.kind == X64TailAbiEnvelopeProgramKind::ReturnEpilogue)
            .expect("image must contain the return epilogue")
            .start;
        let closed_terminal = fixture
            .closed
            .terminal_receipts()
            .iter()
            .find(|terminal| terminal.kind == X64TailClosedTerminalKind::ReturnEpilogue)
            .expect("closed image must contain the return terminal");
        assert_eq!(closed_terminal.label, return_label);

        let return_rows = fixture
            .binding
            .frontiers()
            .iter()
            .filter(|row| row.kind == X64TailFrontierBindingKind::Return)
            .collect::<Vec<_>>();
        assert!(
            !return_rows.is_empty(),
            "fixture must contain a return frontier"
        );

        for row in return_rows {
            let program = fixture
                .realization
                .frontiers()
                .iter()
                .find(|program| program.row_ordinal == row.ordinal)
                .expect("return frontier realization must exist");
            assert_eq!(
                program.atoms.last().map(|atom| atom.instruction),
                Some(X64TailBodyAtomInstruction::JumpRel32 {
                    target: expected_target,
                })
            );
            assert_eq!(program.fixups.len(), 1);
            assert_eq!(program.fixups[0].target, expected_target);

            let body_fixups = fixture
                .body
                .fixup_receipts()
                .iter()
                .filter(|fixup| {
                    fixup.program_kind == X64TailBodyCapsuleProgramKind::Frontier
                        && fixup.program_ordinal == row.ordinal
                })
                .collect::<Vec<_>>();
            assert_eq!(body_fixups.len(), 1);
            assert_eq!(body_fixups[0].target, expected_target);

            let closed_relocations = fixture
                .closed
                .relocation_receipts()
                .iter()
                .filter(|relocation| {
                    relocation.program_kind == X64TailClosedProgramKind::Frontier
                        && relocation.program_ordinal == row.ordinal
                })
                .collect::<Vec<_>>();
            assert_eq!(closed_relocations.len(), 1);
            assert_eq!(closed_relocations[0].target, expected_target);
            assert_eq!(closed_relocations[0].target_offset, closed_terminal.offset);

            let image_relocations = fixture
                .image
                .relocation_receipts()
                .iter()
                .filter(|relocation| {
                    matches!(
                        relocation.origin,
                        X64TailEnvelopedRelocationOrigin::ClosedImage {
                            program_kind: X64TailClosedProgramKind::Frontier,
                            program_ordinal,
                            ..
                        } if program_ordinal == row.ordinal
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(image_relocations.len(), 1);
            assert_eq!(image_relocations[0].target, expected_target);
            assert_eq!(image_relocations[0].target_offset, expected_offset);
        }
    }

    #[test]
    fn complete_branch_and_bounds_images_execute_through_sovereign_wx_path() {
        let branch = Fixture::build(BranchMix);
        let bounds = Fixture::build(BoundsOrderedArrayGet);
        let cases = [
            (
                &branch,
                vec![CoreValue::array_f64(vec![]), CoreValue::I64(0)],
            ),
            (
                &branch,
                vec![
                    CoreValue::array_f64(vec![1.0, -2.0, f64::NAN]),
                    CoreValue::I64(7),
                ],
            ),
            (&bounds, vec![CoreValue::array_f64(vec![1.0, -0.0])]),
            (&bounds, vec![CoreValue::array_f64(vec![1.0])]),
            (&bounds, vec![CoreValue::array_f64(vec![])]),
        ];
        for (fixture, arguments) in cases {
            let expected = evaluate_x64_target_plan(
                fixture.package.target(),
                arguments.clone(),
                EvaluationBudget::new(
                    COREVM0_GATE_A_RESIDUAL_STEP_LIMIT,
                    COREVM0_GATE_A_CALL_DEPTH_LIMIT,
                ),
            )
            .expect("target plan must evaluate");
            let verified = fixture.verified();
            let actual =
                execute_x64_tail_enveloped_native(fixture.package.target(), &verified, &arguments)
                    .expect("verified enveloped image must execute");
            assert_same_evaluation(&expected, &actual);
            assert_eq!(actual.image_hash(), fixture.image.image_hash());
            assert_eq!(actual.verified_code_hash(), fixture.image.code_hash());
            assert_eq!(actual.copied_rw_code_hash(), fixture.image.code_hash());
            assert_eq!(actual.readback_rx_code_hash(), fixture.image.code_hash());
            assert_eq!(actual.entry_point(), fixture.image.entry_point());
            assert_eq!(
                actual.mapping_trace(),
                [
                    X64TailEnvelopedNativeMappingState::Unmapped,
                    X64TailEnvelopedNativeMappingState::ReadWrite,
                    X64TailEnvelopedNativeMappingState::ReadExecute,
                    X64TailEnvelopedNativeMappingState::Unmapped,
                ]
            );
            assert_eq!(actual.mxcsr_before(), actual.mxcsr_after());
            assert!(!actual.fallback());
        }
    }

    #[test]
    fn sovereign_entry_preserves_a_nondefault_caller_mxcsr() {
        let fixture = Fixture::build(BranchMix);
        let original = platform::read_mxcsr();
        let _restore = MxcsrRestore(original);
        let original_rounding = (original >> 13) & 0b11;
        let alternate = (original & !(0b11 << 13)) | (((original_rounding + 1) & 0b11) << 13);
        platform::write_mxcsr(alternate);
        assert_eq!(platform::read_mxcsr(), alternate);

        let arguments = vec![CoreValue::array_f64(vec![]), CoreValue::I64(0)];
        let verified = fixture.verified();
        let actual =
            execute_x64_tail_enveloped_native(fixture.package.target(), &verified, &arguments)
                .expect("verified entry must preserve a nondefault caller MXCSR");

        assert_eq!(actual.mxcsr_before(), alternate);
        assert_eq!(actual.mxcsr_after(), alternate);
        assert_eq!(platform::read_mxcsr(), alternate);
    }
}
