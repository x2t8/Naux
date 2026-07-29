//! Verifier-gated Linux x86-64 execution for the first R1-S7b slice.
//!
//! This module deliberately does not import the bridge JIT, libc, runtime
//! callbacks, or fallback engines. It accepts only the opaque source-bound
//! R1-S7a view, creates one anonymous RW mapping through the Linux x86-64
//! syscall ABI, copies and hashes the exact canonical bytes, changes the
//! mapping to RX, invokes the fixed lighthouse ABI, and unmaps it.
//!
//! Process isolation and the canonical 51-case native evidence package remain
//! later R1-S7b subgates. An in-process native fault cannot be converted into a
//! Rust error.

use super::interpret::{CoreValue, EffectEvent, EvaluationOutcome};
use super::machine_ir::MachineType;
use super::schema::{ErrorKind, SemanticHash};
use super::x64_target::{
    x64_target_code_hash, SourceBoundX64TargetArtifact, X64AbiRegister, X64TargetAbi,
    X64TargetEncodeError, X64_TARGET_MAX_CODE_BYTES,
};
use std::fmt;

pub const X64_NATIVE_RUNNER_SCHEMA_VERSION: (u16, u16, u16) = (0, 1, 0);
pub const X64_NATIVE_RUNNER_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_NATIVE_SYSCALL_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const X64_NATIVE_ENTRY_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);

const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;
const OUTPUT_SENTINEL: u64 = 0xa5c3_d7e9_1b2f_4068;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64NativeMappingState {
    Unmapped,
    ReadWrite,
    ReadExecute,
}

#[derive(Clone, Debug, PartialEq)]
pub struct X64NativeExecution {
    pub runner_schema_version: (u16, u16, u16),
    pub runner_policy_version: (u16, u16, u16),
    pub syscall_policy_version: (u16, u16, u16),
    pub entry_policy_version: (u16, u16, u16),
    pub target_artifact_hash: SemanticHash,
    pub target_plan_hash: SemanticHash,
    pub source_machine_ir_hash: SemanticHash,
    pub verified_code_hash: SemanticHash,
    pub copied_rw_code_hash: SemanticHash,
    pub readback_rx_code_hash: SemanticHash,
    pub entry_offset: u32,
    pub input_lanes: u8,
    pub mapping_trace: [X64NativeMappingState; 4],
    pub mxcsr_before: u32,
    pub mxcsr_after: u32,
    pub outcome: EvaluationOutcome,
    pub effect_trace: Vec<EffectEvent>,
    pub fallback: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64NativeHashStage {
    ReadWrite,
    ReadExecute,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X64NativeRunnerError {
    UnsupportedHost,
    InvalidRunnerEnvelope {
        message: &'static str,
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
    CodeHashEncoding(X64TargetEncodeError),
    CodeHashMismatch {
        stage: X64NativeHashStage,
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

impl fmt::Display for X64NativeRunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost => {
                formatter.write_str("R1-S7b native execution requires Linux x86-64")
            }
            Self::InvalidRunnerEnvelope { message } => {
                write!(formatter, "invalid R1-S7b runner envelope: {message}")
            }
            Self::InputArity { expected, actual } => write!(
                formatter,
                "R1-S7b input arity is {actual}; target entry requires {expected}"
            ),
            Self::InputType {
                parameter,
                expected,
            } => write!(
                formatter,
                "R1-S7b input {parameter} does not have required type {expected:?}"
            ),
            Self::InputSpanOverflow { parameter } => write!(
                formatter,
                "R1-S7b F64 array input {parameter} has an overflowing host span"
            ),
            Self::InputOutputOverlap { parameter } => write!(
                formatter,
                "R1-S7b output area overlaps F64 array input {parameter}"
            ),
            Self::CodeLimit { limit, actual } => {
                write!(
                    formatter,
                    "R1-S7b code uses {actual} bytes; limit is {limit}"
                )
            }
            Self::CodeHashEncoding(error) => {
                write!(formatter, "R1-S7b cannot hash copied target code: {error}")
            }
            Self::CodeHashMismatch {
                stage,
                expected,
                actual,
            } => write!(
                formatter,
                "R1-S7b {stage:?} code hash {actual} differs from verified hash {expected}"
            ),
            Self::MappingFailed { operation, errno } => {
                write!(
                    formatter,
                    "R1-S7b {operation} syscall failed with errno {errno}"
                )
            }
            Self::UnknownOutcomeTag { tag } => {
                write!(formatter, "R1-S7b native entry returned unknown tag {tag}")
            }
            Self::NonCanonicalOutput {
                result,
                word0,
                word1,
            } => write!(
                formatter,
                "R1-S7b native {result:?} payload is noncanonical: {word0:#018x}, {word1:#018x}"
            ),
            Self::ForeignArrayResult { data, length } => write!(
                formatter,
                "R1-S7b native array result ({data:#018x}, {length}) is not an admitted input"
            ),
            Self::MxcsrNotRestored { before, after } => write!(
                formatter,
                "R1-S7b native entry changed caller MXCSR from {before:#010x} to {after:#010x}"
            ),
        }
    }
}

impl std::error::Error for X64NativeRunnerError {}

impl From<X64TargetEncodeError> for X64NativeRunnerError {
    fn from(error: X64TargetEncodeError) -> Self {
        Self::CodeHashEncoding(error)
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

/// Execute one already source-bound R1-S7a artifact through the fixed
/// lighthouse ABI.
///
/// This is the in-process R1-S7b-a slice. Callers that need claim-bearing
/// fault containment must use the later process-isolated evidence harness.
pub fn execute_x64_native_r1_s7b(
    target: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
    arguments: &[CoreValue],
) -> Result<X64NativeExecution, X64NativeRunnerError> {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        execute_supported(target, arguments)
    }

    #[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
    {
        let _ = (target, arguments);
        Err(X64NativeRunnerError::UnsupportedHost)
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn execute_supported(
    target: SourceBoundX64TargetArtifact<'_, '_, '_, '_>,
    arguments: &[CoreValue],
) -> Result<X64NativeExecution, X64NativeRunnerError> {
    let artifact = target.artifact();
    let program = &artifact.program;
    if program.abi != X64TargetAbi::r1_s7a() {
        return Err(X64NativeRunnerError::InvalidRunnerEnvelope {
            message: "target ABI is not the frozen R1-S7a ABI",
        });
    }
    if program.entry_offset != 0 {
        return Err(X64NativeRunnerError::InvalidRunnerEnvelope {
            message: "entry offset is not canonical zero",
        });
    }
    if program.entry_abi.output_words != 2 {
        return Err(X64NativeRunnerError::InvalidRunnerEnvelope {
            message: "output area is not exactly two words",
        });
    }
    if program.code.is_empty() {
        return Err(X64NativeRunnerError::InvalidRunnerEnvelope {
            message: "code blob is empty",
        });
    }
    let code_len =
        u64::try_from(program.code.len()).map_err(|_| X64NativeRunnerError::CodeLimit {
            limit: X64_TARGET_MAX_CODE_BYTES,
            actual: u64::MAX,
        })?;
    if code_len > X64_TARGET_MAX_CODE_BYTES {
        return Err(X64NativeRunnerError::CodeLimit {
            limit: X64_TARGET_MAX_CODE_BYTES,
            actual: code_len,
        });
    }

    let (lanes, arrays) = flatten_arguments(&program.entry_abi.parameter_types, arguments)?;
    validate_entry_registers(
        lanes.len(),
        program.entry_abi.input_lanes.len(),
        program.entry_abi.output_register,
    )?;

    let mut output = [OUTPUT_SENTINEL; 2];
    validate_output_disjoint(&arrays, output.as_ptr() as u64)?;

    let mut mapping = platform::NativeMapping::allocate(program.code.len())?;
    mapping.copy_from(&program.code);
    let copied_rw_code_hash = x64_target_code_hash(mapping.bytes())?;
    if copied_rw_code_hash != program.code_hash {
        return Err(X64NativeRunnerError::CodeHashMismatch {
            stage: X64NativeHashStage::ReadWrite,
            expected: program.code_hash,
            actual: copied_rw_code_hash,
        });
    }

    mapping.protect_rx()?;
    let readback_rx_code_hash = x64_target_code_hash(mapping.bytes())?;
    if readback_rx_code_hash != program.code_hash {
        return Err(X64NativeRunnerError::CodeHashMismatch {
            stage: X64NativeHashStage::ReadExecute,
            expected: program.code_hash,
            actual: readback_rx_code_hash,
        });
    }

    let mxcsr_before = platform::read_mxcsr();
    // SAFETY: `mapping` is RX, contains the exact source-bound and rehashed
    // R1-S7a bytes, `entry_offset` is verified zero, the selected signature is
    // derived from the exact ABI lane count, every input span remains borrowed
    // for this call, and `output` owns two writable words.
    let tag = unsafe {
        platform::call_entry(
            mapping.entry(program.entry_offset),
            &lanes,
            output.as_mut_ptr(),
        )
    };
    let mxcsr_after = platform::read_mxcsr();
    let decoded = decode_output(tag, program.entry_abi.result, output, &arrays);
    mapping.unmap()?;
    if mxcsr_after != mxcsr_before {
        return Err(X64NativeRunnerError::MxcsrNotRestored {
            before: mxcsr_before,
            after: mxcsr_after,
        });
    }

    let (outcome, effect_trace) = decoded?;

    Ok(X64NativeExecution {
        runner_schema_version: X64_NATIVE_RUNNER_SCHEMA_VERSION,
        runner_policy_version: X64_NATIVE_RUNNER_POLICY_VERSION,
        syscall_policy_version: X64_NATIVE_SYSCALL_POLICY_VERSION,
        entry_policy_version: X64_NATIVE_ENTRY_POLICY_VERSION,
        target_artifact_hash: artifact.semantic_hash,
        target_plan_hash: program.plan_hash,
        source_machine_ir_hash: program.source_machine_ir_hash,
        verified_code_hash: program.code_hash,
        copied_rw_code_hash,
        readback_rx_code_hash,
        entry_offset: program.entry_offset,
        input_lanes: lanes.len() as u8,
        mapping_trace: [
            X64NativeMappingState::Unmapped,
            X64NativeMappingState::ReadWrite,
            X64NativeMappingState::ReadExecute,
            X64NativeMappingState::Unmapped,
        ],
        mxcsr_before,
        mxcsr_after,
        outcome,
        effect_trace,
        fallback: false,
    })
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn flatten_arguments<'value>(
    parameter_types: &[MachineType],
    arguments: &'value [CoreValue],
) -> Result<(Vec<u64>, Vec<ArraySpan<'value>>), X64NativeRunnerError> {
    if arguments.len() != parameter_types.len() {
        return Err(X64NativeRunnerError::InputArity {
            expected: parameter_types.len(),
            actual: arguments.len(),
        });
    }

    let mut lanes = Vec::with_capacity(5);
    let mut arrays = Vec::with_capacity(2);
    for (parameter, (ty, value)) in parameter_types.iter().zip(arguments).enumerate() {
        match (ty, value) {
            (MachineType::Unit, CoreValue::Unit) => {}
            (MachineType::Bool, CoreValue::Bool(value)) => lanes.push(u64::from(*value)),
            (MachineType::I64, CoreValue::I64(value)) => lanes.push(*value as u64),
            (MachineType::F64, CoreValue::F64(value)) => lanes.push(value.to_bits()),
            (MachineType::F64Array, CoreValue::ArrayF64(values)) => {
                let length = u64::try_from(values.len())
                    .map_err(|_| X64NativeRunnerError::InputSpanOverflow { parameter })?;
                if length > i64::MAX as u64 {
                    return Err(X64NativeRunnerError::InputSpanOverflow { parameter });
                }
                let data = values.as_ptr() as usize as u64;
                let bytes = length
                    .checked_mul(8)
                    .ok_or(X64NativeRunnerError::InputSpanOverflow { parameter })?;
                let end = data
                    .checked_add(bytes)
                    .ok_or(X64NativeRunnerError::InputSpanOverflow { parameter })?;
                if length > 0 && data == 0 {
                    return Err(X64NativeRunnerError::InputSpanOverflow { parameter });
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
                return Err(X64NativeRunnerError::InputType {
                    parameter,
                    expected: *ty,
                });
            }
        }
    }
    if lanes.len() > 5 {
        return Err(X64NativeRunnerError::InvalidRunnerEnvelope {
            message: "flattened input exceeds five lanes",
        });
    }
    Ok((lanes, arrays))
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn validate_entry_registers(
    flattened_lanes: usize,
    declared_lanes: usize,
    output_register: X64AbiRegister,
) -> Result<(), X64NativeRunnerError> {
    const REGISTERS: [X64AbiRegister; 6] = [
        X64AbiRegister::Rdi,
        X64AbiRegister::Rsi,
        X64AbiRegister::Rdx,
        X64AbiRegister::Rcx,
        X64AbiRegister::R8,
        X64AbiRegister::R9,
    ];
    if flattened_lanes != declared_lanes
        || flattened_lanes > 5
        || output_register != REGISTERS[flattened_lanes]
    {
        return Err(X64NativeRunnerError::InvalidRunnerEnvelope {
            message: "entry lane count or output register is inconsistent",
        });
    }
    Ok(())
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn validate_output_disjoint(
    arrays: &[ArraySpan<'_>],
    output_start: u64,
) -> Result<(), X64NativeRunnerError> {
    let output_end =
        output_start
            .checked_add(16)
            .ok_or(X64NativeRunnerError::InvalidRunnerEnvelope {
                message: "output span overflows the host address space",
            })?;
    for array in arrays {
        if array.length > 0 && output_start < array.end && array.data < output_end {
            return Err(X64NativeRunnerError::InputOutputOverlap {
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
) -> Result<(EvaluationOutcome, Vec<EffectEvent>), X64NativeRunnerError> {
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
                        return Err(X64NativeRunnerError::ForeignArrayResult {
                            data: output[0],
                            length: output[1],
                        });
                    };
                    array.value.clone()
                }
                _ => {
                    return Err(X64NativeRunnerError::NonCanonicalOutput {
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
        1 => Err(X64NativeRunnerError::NonCanonicalOutput {
            result,
            word0: output[0],
            word1: output[1],
        }),
        tag => Err(X64NativeRunnerError::UnknownOutcomeTag { tag }),
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod platform {
    use super::X64NativeRunnerError;
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
        pub(super) fn allocate(length: usize) -> Result<Self, X64NativeRunnerError> {
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
                return Err(X64NativeRunnerError::MappingFailed {
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
            // SAFETY: the mapping is RW and exactly `self.length` bytes; the
            // source slice has the same length and cannot overlap it.
            unsafe {
                std::ptr::copy_nonoverlapping(code.as_ptr(), self.pointer, self.length);
            }
            fence(Ordering::SeqCst);
        }

        pub(super) fn protect_rx(&mut self) -> Result<(), X64NativeRunnerError> {
            // SAFETY: the mapping came from mmap and remains live.
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
            // SAFETY: the live mapping is readable in both RW and RX states.
            unsafe { std::slice::from_raw_parts(self.pointer, self.length) }
        }

        pub(super) fn entry(&self, offset: u32) -> *const u8 {
            debug_assert!(self.rx);
            // SAFETY: the caller verified `offset` lies in the code blob.
            unsafe { self.pointer.add(offset as usize) as *const u8 }
        }

        pub(super) fn unmap(&mut self) -> Result<(), X64NativeRunnerError> {
            if self.pointer.is_null() {
                return Ok(());
            }
            // SAFETY: the mapping came from mmap and has not been unmapped.
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
    ) -> Result<*mut u8, X64NativeRunnerError> {
        if let Some(errno) = syscall_errno(result) {
            Err(X64NativeRunnerError::MappingFailed { operation, errno })
        } else {
            Ok(result as usize as *mut u8)
        }
    }

    fn syscall_unit(operation: &'static str, result: isize) -> Result<(), X64NativeRunnerError> {
        if let Some(errno) = syscall_errno(result) {
            Err(X64NativeRunnerError::MappingFailed { operation, errno })
        } else if result == 0 {
            Ok(())
        } else {
            Err(X64NativeRunnerError::MappingFailed {
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
        // SAFETY: the operands follow the Linux x86-64 syscall ABI. `syscall`
        // always clobbers RCX and R11. Omitting `nomem` makes this a compiler
        // memory barrier for mapping/protection operations.
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
        // SAFETY: `stmxcsr` writes exactly four bytes to an aligned Rust local.
        unsafe {
            asm!(
                "stmxcsr [{pointer}]",
                pointer = in(reg) &mut value,
                options(nostack, preserves_flags),
            );
        }
        value
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
                // SAFETY: the caller proves the entry has the zero-lane ABI.
                let function = unsafe { std::mem::transmute::<*const u8, Entry0>(entry) };
                unsafe { function(output) }
            }
            [a0] => {
                // SAFETY: the caller proves the entry has the one-lane ABI.
                let function = unsafe { std::mem::transmute::<*const u8, Entry1>(entry) };
                unsafe { function(*a0, output) }
            }
            [a0, a1] => {
                // SAFETY: the caller proves the entry has the two-lane ABI.
                let function = unsafe { std::mem::transmute::<*const u8, Entry2>(entry) };
                unsafe { function(*a0, *a1, output) }
            }
            [a0, a1, a2] => {
                // SAFETY: the caller proves the entry has the three-lane ABI.
                let function = unsafe { std::mem::transmute::<*const u8, Entry3>(entry) };
                unsafe { function(*a0, *a1, *a2, output) }
            }
            [a0, a1, a2, a3] => {
                // SAFETY: the caller proves the entry has the four-lane ABI.
                let function = unsafe { std::mem::transmute::<*const u8, Entry4>(entry) };
                unsafe { function(*a0, *a1, *a2, *a3, output) }
            }
            [a0, a1, a2, a3, a4] => {
                // SAFETY: the caller proves the entry has the five-lane ABI.
                let function = unsafe { std::mem::transmute::<*const u8, Entry5>(entry) };
                unsafe { function(*a0, *a1, *a2, *a3, *a4, output) }
            }
            _ => unreachable!("R1-S7b preflight admits at most five lanes"),
        }
    }
}
