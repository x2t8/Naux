//! Owned, deterministic raw x86-64 encoding for the R1-S7A target plan.
//!
//! The encoder deliberately exposes no arbitrary instruction or byte escape.
//! Every emitted byte belongs to one fixed System V AMD64/SSE2 template, and
//! every control transfer is an internal retained `rel32` fixup.

use super::*;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RawEncoding {
    pub(super) labels: Vec<X64Label>,
    pub(super) fixups: Vec<X64Fixup>,
    pub(super) code: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RawEncodeError {
    CodeLimit {
        limit: u64,
        attempted: u64,
    },
    FixupLimit {
        limit: u64,
        attempted: u64,
    },
    LabelLimit {
        limit: u64,
        actual: u64,
    },
    ArithmeticOverflow {
        field: &'static str,
    },
    OffsetOutOfRange {
        field: &'static str,
        offset: u64,
    },
    FrameAccess {
        field: &'static str,
        offset: u32,
        width: u32,
        frame_bytes: u32,
    },
    InvalidHome {
        field: &'static str,
        home: X64Home,
    },
    InvalidOutgoingAccess {
        offset: u32,
        width: u32,
        outgoing_base: u32,
        outgoing_bytes: u32,
    },
    DuplicateLabel {
        label: X64LabelId,
    },
    DuplicateLabelOwner {
        owner: X64LabelOwner,
    },
    MissingLabelOwner {
        owner: X64LabelOwner,
    },
    UnknownLabel {
        label: X64LabelId,
    },
    LabelAlreadyMarked {
        label: X64LabelId,
    },
    LabelNotMarked {
        label: X64LabelId,
    },
    MissingFunction {
        function: X64FunctionId,
    },
    MissingBlock {
        function: X64FunctionId,
        block: X64BlockId,
    },
    EntryOffset {
        declared: u32,
    },
    EntryLaneManifest {
        expected: usize,
        actual: usize,
    },
    InvalidEntryLane {
        parameter: u32,
        word: u8,
    },
    InvalidOperand {
        context: &'static str,
        expected: MachineType,
        actual: MachineType,
    },
    InvalidArrayOperand {
        context: &'static str,
    },
    InvalidResultWidth {
        context: &'static str,
        ty: MachineType,
        expected: u8,
        actual: u8,
    },
    TailArity {
        function: X64FunctionId,
        arguments: usize,
        parameters: usize,
    },
    TailExtent {
        required: u32,
        declared: u32,
    },
    Rel32OutOfRange {
        patch_offset: u32,
        target: X64LabelId,
        displacement: i64,
    },
    FixupPatchRange {
        patch_offset: u32,
        code_bytes: usize,
    },
    FixupOrder {
        previous: u32,
        current: u32,
    },
}

impl fmt::Display for RawEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CodeLimit { limit, attempted } => {
                write!(
                    formatter,
                    "raw x86-64 code would use {attempted} bytes; limit is {limit}"
                )
            }
            Self::FixupLimit { limit, attempted } => {
                write!(
                    formatter,
                    "raw x86-64 encoding would use {attempted} fixups; limit is {limit}"
                )
            }
            Self::LabelLimit { limit, actual } => {
                write!(
                    formatter,
                    "raw x86-64 encoding has {actual} labels; limit is {limit}"
                )
            }
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "arithmetic overflow while encoding {field}")
            }
            Self::OffsetOutOfRange { field, offset } => {
                write!(formatter, "{field} offset {offset} cannot be encoded")
            }
            Self::FrameAccess {
                field,
                offset,
                width,
                frame_bytes,
            } => write!(
                formatter,
                "{field} frame access [{offset}, {offset}+{width}) exceeds frame size {frame_bytes}"
            ),
            Self::InvalidHome { field, home } => write!(
                formatter,
                "{field} uses invalid home slot {} at offset {} with width {}",
                home.slot.0, home.offset, home.width
            ),
            Self::InvalidOutgoingAccess {
                offset,
                width,
                outgoing_base,
                outgoing_bytes,
            } => write!(
                formatter,
                "outgoing access [{offset}, {offset}+{width}) is outside [{outgoing_base}, {outgoing_base}+{outgoing_bytes})"
            ),
            Self::DuplicateLabel { label } => {
                write!(formatter, "target label {} is duplicated", label.0)
            }
            Self::DuplicateLabelOwner { owner } => {
                write!(formatter, "target label owner {owner:?} is duplicated")
            }
            Self::MissingLabelOwner { owner } => {
                write!(formatter, "target label owner {owner:?} is missing")
            }
            Self::UnknownLabel { label } => {
                write!(formatter, "target label {} is unknown", label.0)
            }
            Self::LabelAlreadyMarked { label } => {
                write!(formatter, "target label {} was marked twice", label.0)
            }
            Self::LabelNotMarked { label } => {
                write!(formatter, "target label {} was not laid out", label.0)
            }
            Self::MissingFunction { function } => {
                write!(formatter, "target function {} is missing", function.0)
            }
            Self::MissingBlock { function, block } => write!(
                formatter,
                "target function {} has no block {}",
                function.0, block.0
            ),
            Self::EntryOffset { declared } => {
                write!(
                    formatter,
                    "target entry offset must be zero, found {declared}"
                )
            }
            Self::EntryLaneManifest { expected, actual } => write!(
                formatter,
                "target entry ABI requires {expected} input lanes, found {actual}"
            ),
            Self::InvalidEntryLane { parameter, word } => write!(
                formatter,
                "target entry lane references invalid parameter {parameter} word {word}"
            ),
            Self::InvalidOperand {
                context,
                expected,
                actual,
            } => write!(
                formatter,
                "{context} expected operand {expected:?}, found {actual:?}"
            ),
            Self::InvalidArrayOperand { context } => {
                write!(formatter, "{context} requires an F64Array home operand")
            }
            Self::InvalidResultWidth {
                context,
                ty,
                expected,
                actual,
            } => write!(
                formatter,
                "{context} result {ty:?} requires width {expected}, found {actual}"
            ),
            Self::TailArity {
                function,
                arguments,
                parameters,
            } => write!(
                formatter,
                "tail transfer to function {} has {arguments} arguments for {parameters} parameters",
                function.0
            ),
            Self::TailExtent { required, declared } => write!(
                formatter,
                "tail transfer requires {required} outgoing bytes; frame declares {declared}"
            ),
            Self::Rel32OutOfRange {
                patch_offset,
                target,
                displacement,
            } => write!(
                formatter,
                "rel32 at {patch_offset} targeting label {} has out-of-range displacement {displacement}",
                target.0
            ),
            Self::FixupPatchRange {
                patch_offset,
                code_bytes,
            } => write!(
                formatter,
                "rel32 patch [{patch_offset}, {patch_offset}+4) exceeds {code_bytes} code bytes"
            ),
            Self::FixupOrder { previous, current } => write!(
                formatter,
                "fixup offsets are not strictly increasing: {previous}, then {current}"
            ),
        }
    }
}

impl std::error::Error for RawEncodeError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gpr {
    Rax,
    Rcx,
    Rdx,
    Rdi,
    Rsi,
    R8,
    R9,
}

impl Gpr {
    const fn number(self) -> u8 {
        match self {
            Self::Rax => 0,
            Self::Rcx => 1,
            Self::Rdx => 2,
            Self::Rsi => 6,
            Self::Rdi => 7,
            Self::R8 => 8,
            Self::R9 => 9,
        }
    }
}

struct RawEmitter {
    code: Vec<u8>,
    labels: Vec<X64Label>,
    label_indices: BTreeMap<X64LabelId, usize>,
    marked_labels: BTreeMap<X64LabelId, u32>,
    fixups: Vec<X64Fixup>,
    code_limit: u64,
    fixup_limit: u64,
}

impl RawEmitter {
    fn new(program: &X64TargetProgram) -> Result<Self, RawEncodeError> {
        let label_limit = program.limits.max_labels.min(X64_TARGET_MAX_LABELS);
        let label_count = u64::try_from(program.labels.len()).map_err(|_| {
            RawEncodeError::ArithmeticOverflow {
                field: "label count",
            }
        })?;
        if label_count > label_limit {
            return Err(RawEncodeError::LabelLimit {
                limit: label_limit,
                actual: label_count,
            });
        }

        let mut label_indices = BTreeMap::new();
        let mut labels = program.labels.clone();
        for (index, label) in labels.iter_mut().enumerate() {
            if label_indices.insert(label.id, index).is_some() {
                return Err(RawEncodeError::DuplicateLabel { label: label.id });
            }
            label.code_offset = 0;
        }

        Ok(Self {
            code: Vec::new(),
            labels,
            label_indices,
            marked_labels: BTreeMap::new(),
            fixups: Vec::new(),
            code_limit: program.limits.max_code_bytes.min(X64_TARGET_MAX_CODE_BYTES),
            fixup_limit: program.limits.max_fixups.min(X64_TARGET_MAX_FIXUPS),
        })
    }

    fn offset(&self, field: &'static str) -> Result<u32, RawEncodeError> {
        u32::try_from(self.code.len()).map_err(|_| RawEncodeError::OffsetOutOfRange {
            field,
            offset: self.code.len() as u64,
        })
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), RawEncodeError> {
        let attempted =
            self.code
                .len()
                .checked_add(bytes.len())
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "raw code length",
                })?;
        let attempted =
            u64::try_from(attempted).map_err(|_| RawEncodeError::ArithmeticOverflow {
                field: "raw code length",
            })?;
        if attempted > self.code_limit {
            return Err(RawEncodeError::CodeLimit {
                limit: self.code_limit,
                attempted,
            });
        }
        self.code.extend_from_slice(bytes);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), RawEncodeError> {
        self.bytes(&[value])
    }

    fn u32(&mut self, value: u32) -> Result<(), RawEncodeError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), RawEncodeError> {
        self.bytes(&value.to_le_bytes())
    }

    fn mark(&mut self, label: X64LabelId) -> Result<(), RawEncodeError> {
        let index = *self
            .label_indices
            .get(&label)
            .ok_or(RawEncodeError::UnknownLabel { label })?;
        let offset = self.offset("label")?;
        if self.marked_labels.insert(label, offset).is_some() {
            return Err(RawEncodeError::LabelAlreadyMarked { label });
        }
        self.labels[index].code_offset = offset;
        Ok(())
    }

    fn rel32(&mut self, opcode: &[u8], target: X64LabelId) -> Result<(), RawEncodeError> {
        if !self.label_indices.contains_key(&target) {
            return Err(RawEncodeError::UnknownLabel { label: target });
        }
        self.bytes(opcode)?;
        let patch_offset = self.offset("rel32 patch")?;
        self.u32(0)?;
        let attempted =
            self.fixups
                .len()
                .checked_add(1)
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "fixup count",
                })?;
        let attempted =
            u64::try_from(attempted).map_err(|_| RawEncodeError::ArithmeticOverflow {
                field: "fixup count",
            })?;
        if attempted > self.fixup_limit {
            return Err(RawEncodeError::FixupLimit {
                limit: self.fixup_limit,
                attempted,
            });
        }
        self.fixups.push(X64Fixup {
            patch_offset,
            target,
            addend: 0,
        });
        Ok(())
    }

    fn finish(mut self) -> Result<RawEncoding, RawEncodeError> {
        for label in &self.labels {
            if !self.marked_labels.contains_key(&label.id) {
                return Err(RawEncodeError::LabelNotMarked { label: label.id });
            }
        }

        self.fixups.sort_by_key(|fixup| fixup.patch_offset);
        let mut previous = None;
        for fixup in &self.fixups {
            if let Some(previous) = previous {
                if fixup.patch_offset <= previous {
                    return Err(RawEncodeError::FixupOrder {
                        previous,
                        current: fixup.patch_offset,
                    });
                }
            }
            previous = Some(fixup.patch_offset);

            let patch_start = usize::try_from(fixup.patch_offset).map_err(|_| {
                RawEncodeError::FixupPatchRange {
                    patch_offset: fixup.patch_offset,
                    code_bytes: self.code.len(),
                }
            })?;
            let patch_end =
                patch_start
                    .checked_add(4)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "rel32 patch end",
                    })?;
            if patch_end > self.code.len() {
                return Err(RawEncodeError::FixupPatchRange {
                    patch_offset: fixup.patch_offset,
                    code_bytes: self.code.len(),
                });
            }
            let target_offset =
                *self
                    .marked_labels
                    .get(&fixup.target)
                    .ok_or(RawEncodeError::LabelNotMarked {
                        label: fixup.target,
                    })?;
            let next_instruction = i64::from(fixup.patch_offset).checked_add(4).ok_or(
                RawEncodeError::ArithmeticOverflow {
                    field: "rel32 next instruction",
                },
            )?;
            let displacement = i64::from(target_offset)
                .checked_add(i64::from(fixup.addend))
                .and_then(|target| target.checked_sub(next_instruction))
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "rel32 displacement",
                })?;
            let displacement =
                i32::try_from(displacement).map_err(|_| RawEncodeError::Rel32OutOfRange {
                    patch_offset: fixup.patch_offset,
                    target: fixup.target,
                    displacement,
                })?;
            self.code[patch_start..patch_end].copy_from_slice(&displacement.to_le_bytes());
        }

        Ok(RawEncoding {
            labels: self.labels,
            fixups: self.fixups,
            code: self.code,
        })
    }
}

pub(super) fn encode(program: &X64TargetProgram) -> Result<RawEncoding, RawEncodeError> {
    if program.entry_offset != 0 {
        return Err(RawEncodeError::EntryOffset {
            declared: program.entry_offset,
        });
    }
    check_frame_header(program)?;

    let entry_adapter = unique_owner_label(program, X64LabelOwner::EntryAdapter)?;
    let return_epilogue = unique_owner_label(program, X64LabelOwner::ReturnEpilogue)?;
    let bounds_epilogue = unique_owner_label(program, X64LabelOwner::BoundsEpilogue)?;
    let entry_function = function(program, program.entry)?;
    let entry_block = block(entry_function, entry_function.entry_block)?;

    let mut emitter = RawEmitter::new(program)?;
    emitter.mark(entry_adapter)?;
    emit_prologue(&mut emitter, program, entry_function, entry_block.label)?;

    for target_function in &program.functions {
        for target_block in &target_function.blocks {
            emitter.mark(target_block.label)?;
            for instruction in &target_block.instructions {
                emit_instruction(&mut emitter, program, instruction, bounds_epilogue)?;
            }
            emit_terminator(
                &mut emitter,
                program,
                &target_block.terminator,
                return_epilogue,
            )?;
        }
    }

    emitter.mark(return_epilogue)?;
    emit_return_epilogue(&mut emitter, program)?;
    emitter.mark(bounds_epilogue)?;
    emit_bounds_epilogue(&mut emitter, program)?;
    emitter.finish()
}

fn check_frame_header(program: &X64TargetProgram) -> Result<(), RawEncodeError> {
    if program.frame.header_bytes != X64_FRAME_HEADER_BYTES
        || program.frame.home_base != X64_FRAME_HEADER_BYTES
        || program.frame.frame_bytes < X64_FRAME_HEADER_BYTES
    {
        return Err(RawEncodeError::FrameAccess {
            field: "canonical header",
            offset: 0,
            width: X64_FRAME_HEADER_BYTES,
            frame_bytes: program.frame.frame_bytes,
        });
    }
    for (field, offset, width) in [
        ("saved MXCSR", 0, 4),
        ("canonical MXCSR", 4, 4),
        ("hidden output pointer", 8, 8),
        ("reserved header", 16, 16),
    ] {
        check_frame_access(program, field, offset, width)?;
    }
    Ok(())
}

fn unique_owner_label(
    program: &X64TargetProgram,
    owner: X64LabelOwner,
) -> Result<X64LabelId, RawEncodeError> {
    let mut found = None;
    for label in &program.labels {
        if label.owner == owner && found.replace(label.id).is_some() {
            return Err(RawEncodeError::DuplicateLabelOwner { owner });
        }
    }
    found.ok_or(RawEncodeError::MissingLabelOwner { owner })
}

fn function(program: &X64TargetProgram, id: X64FunctionId) -> Result<&X64Function, RawEncodeError> {
    program
        .functions
        .iter()
        .find(|function| function.id == id)
        .ok_or(RawEncodeError::MissingFunction { function: id })
}

fn block(function: &X64Function, id: X64BlockId) -> Result<&X64Block, RawEncodeError> {
    function
        .blocks
        .iter()
        .find(|block| block.id == id)
        .ok_or(RawEncodeError::MissingBlock {
            function: function.id,
            block: id,
        })
}

fn physical_width(ty: MachineType) -> u8 {
    match ty {
        MachineType::F64Array => 16,
        MachineType::Unit | MachineType::Bool | MachineType::I64 | MachineType::F64 => 8,
    }
}

fn check_frame_access(
    program: &X64TargetProgram,
    field: &'static str,
    offset: u32,
    width: u32,
) -> Result<(), RawEncodeError> {
    let end = offset
        .checked_add(width)
        .ok_or(RawEncodeError::ArithmeticOverflow { field })?;
    if end > program.frame.frame_bytes || offset > i32::MAX as u32 {
        return Err(RawEncodeError::FrameAccess {
            field,
            offset,
            width,
            frame_bytes: program.frame.frame_bytes,
        });
    }
    Ok(())
}

fn check_home(
    program: &X64TargetProgram,
    field: &'static str,
    home: X64Home,
) -> Result<(), RawEncodeError> {
    let expected = physical_width(home.ty);
    let end = home
        .offset
        .checked_add(u32::from(home.width))
        .ok_or(RawEncodeError::ArithmeticOverflow { field })?;
    if home.width != expected
        || !home.offset.is_multiple_of(8)
        || home.offset < program.frame.home_base
        || end > program.frame.outgoing_base
    {
        return Err(RawEncodeError::InvalidHome { field, home });
    }
    check_frame_access(program, field, home.offset, u32::from(home.width))
}

fn check_outgoing(
    program: &X64TargetProgram,
    offset: u32,
    width: u32,
) -> Result<(), RawEncodeError> {
    let outgoing_end = program
        .frame
        .outgoing_base
        .checked_add(program.frame.outgoing_bytes)
        .ok_or(RawEncodeError::ArithmeticOverflow {
            field: "outgoing area end",
        })?;
    let end = offset
        .checked_add(width)
        .ok_or(RawEncodeError::ArithmeticOverflow {
            field: "outgoing access end",
        })?;
    if offset < program.frame.outgoing_base || end > outgoing_end {
        return Err(RawEncodeError::InvalidOutgoingAccess {
            offset,
            width,
            outgoing_base: program.frame.outgoing_base,
            outgoing_bytes: program.frame.outgoing_bytes,
        });
    }
    check_frame_access(program, "outgoing argument", offset, width)
}

fn abi_gpr(register: X64AbiRegister) -> Gpr {
    match register {
        X64AbiRegister::Rdi => Gpr::Rdi,
        X64AbiRegister::Rsi => Gpr::Rsi,
        X64AbiRegister::Rdx => Gpr::Rdx,
        X64AbiRegister::Rcx => Gpr::Rcx,
        X64AbiRegister::R8 => Gpr::R8,
        X64AbiRegister::R9 => Gpr::R9,
    }
}

fn emit_prologue(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    entry_function: &X64Function,
    entry_label: X64LabelId,
) -> Result<(), RawEncodeError> {
    let expected_lanes =
        entry_function
            .parameters
            .iter()
            .try_fold(0usize, |total, parameter| {
                let words = match parameter.home.ty {
                    MachineType::Unit => 0,
                    MachineType::F64Array => 2,
                    MachineType::Bool | MachineType::I64 | MachineType::F64 => 1,
                };
                total
                    .checked_add(words)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "entry lane count",
                    })
            })?;
    if program.entry_abi.input_lanes.len() != expected_lanes {
        return Err(RawEncodeError::EntryLaneManifest {
            expected: expected_lanes,
            actual: program.entry_abi.input_lanes.len(),
        });
    }
    for lane in &program.entry_abi.input_lanes {
        let Some(parameter) = entry_function.parameters.get(lane.parameter as usize) else {
            return Err(RawEncodeError::InvalidEntryLane {
                parameter: lane.parameter,
                word: lane.word,
            });
        };
        let words = match parameter.home.ty {
            MachineType::Unit => 0,
            MachineType::F64Array => 2,
            MachineType::Bool | MachineType::I64 | MachineType::F64 => 1,
        };
        if usize::from(lane.word) >= words {
            return Err(RawEncodeError::InvalidEntryLane {
                parameter: lane.parameter,
                word: lane.word,
            });
        }
    }

    // push rbp; mov rbp, rsp; sub rsp, frame_bytes
    emitter.bytes(&[0x55, 0x48, 0x89, 0xe5, 0x48, 0x81, 0xec])?;
    emitter.u32(program.frame.frame_bytes)?;

    // Save the caller's numeric state, install the canonical state, and retain
    // the hidden output pointer before any ABI input register is reused.
    emit_stmxcsr_rsp_disp32(emitter, 0)?;
    emit_mov_mem32_imm32(emitter, 4, program.abi.canonical_mxcsr)?;
    emit_ldmxcsr_rsp_disp32(emitter, 4)?;
    emit_store_frame_gpr(emitter, 8, abi_gpr(program.entry_abi.output_register))?;
    emit_mov_mem64_imm32(emitter, 16, 0)?;
    emit_mov_mem64_imm32(emitter, 24, 0)?;

    for (parameter_index, parameter) in entry_function.parameters.iter().enumerate() {
        check_home(program, "entry parameter", parameter.home)?;
        if parameter.home.ty == MachineType::Unit {
            emit_mov_mem64_imm32(emitter, parameter.home.offset, 0)?;
            continue;
        }

        let expected_words = usize::from(parameter.home.width / 8);
        let mut lanes = program
            .entry_abi
            .input_lanes
            .iter()
            .filter(|lane| lane.parameter as usize == parameter_index)
            .collect::<Vec<_>>();
        lanes.sort_by_key(|lane| lane.word);
        if lanes.len() != expected_words {
            return Err(RawEncodeError::InvalidResultWidth {
                context: "entry lane manifest",
                ty: parameter.home.ty,
                expected: parameter.home.width,
                actual: u8::try_from(lanes.len().saturating_mul(8)).unwrap_or(u8::MAX),
            });
        }
        for (word, lane) in lanes.into_iter().enumerate() {
            if usize::from(lane.word) != word {
                return Err(RawEncodeError::OffsetOutOfRange {
                    field: "entry lane word",
                    offset: u64::from(lane.word),
                });
            }
            let word_offset = u32::try_from(word)
                .map_err(|_| RawEncodeError::ArithmeticOverflow {
                    field: "entry lane word",
                })?
                .checked_mul(8)
                .and_then(|offset| parameter.home.offset.checked_add(offset))
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "entry lane home offset",
                })?;
            emit_store_frame_gpr(emitter, word_offset, abi_gpr(lane.register))?;
        }
    }

    emitter.rel32(&[0xe9], entry_label)
}

fn emit_instruction(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    instruction: &X64Instruction,
    bounds_label: X64LabelId,
) -> Result<(), RawEncodeError> {
    check_home(program, "instruction result", instruction.result)?;
    match &instruction.kind {
        X64InstructionKind::Move(operand) => {
            require_operand_type("move", instruction.result.ty, operand)?;
            require_result_width("move", instruction.result)?;
            emit_move(emitter, program, operand, instruction.result)
        }
        X64InstructionKind::I64Wrapping {
            opcode,
            left,
            right,
        } => {
            require_operand_type("wrapping I64 left", MachineType::I64, left)?;
            require_operand_type("wrapping I64 right", MachineType::I64, right)?;
            require_home_type("wrapping I64 result", instruction.result, MachineType::I64)?;
            emit_load_scalar(emitter, program, left, Gpr::Rax)?;
            emit_load_scalar(emitter, program, right, Gpr::Rcx)?;
            match opcode {
                X64I64Opcode::Add => emitter.bytes(&[0x48, 0x01, 0xc8])?,
                X64I64Opcode::Sub => emitter.bytes(&[0x48, 0x29, 0xc8])?,
                X64I64Opcode::Mul => emitter.bytes(&[0x48, 0x0f, 0xaf, 0xc1])?,
            }
            emit_store_frame_gpr(emitter, instruction.result.offset, Gpr::Rax)
        }
        X64InstructionKind::Sse2F64 {
            opcode,
            left,
            right,
        } => {
            require_operand_type("SSE2 F64 left", MachineType::F64, left)?;
            require_operand_type("SSE2 F64 right", MachineType::F64, right)?;
            require_home_type("SSE2 F64 result", instruction.result, MachineType::F64)?;
            emit_load_f64_xmm0(emitter, program, left)?;
            emit_load_f64_xmm1(emitter, program, right)?;
            match opcode {
                X64Sse2F64Opcode::AddSd => emitter.bytes(&[0xf2, 0x0f, 0x58, 0xc1])?,
                X64Sse2F64Opcode::SubSd => emitter.bytes(&[0xf2, 0x0f, 0x5c, 0xc1])?,
            }
            emit_store_xmm0_frame(emitter, instruction.result.offset)
        }
        X64InstructionKind::I64Setcc {
            condition,
            left,
            right,
        } => {
            require_operand_type("signed compare left", MachineType::I64, left)?;
            require_operand_type("signed compare right", MachineType::I64, right)?;
            require_home_type(
                "signed compare result",
                instruction.result,
                MachineType::Bool,
            )?;
            emit_load_scalar(emitter, program, left, Gpr::Rax)?;
            emit_load_scalar(emitter, program, right, Gpr::Rcx)?;
            emitter.bytes(&[0x48, 0x39, 0xc8])?; // cmp rax, rcx
            match condition {
                X64SetCondition::SignedLessThan => emitter.bytes(&[0x0f, 0x9c, 0xc0])?,
                X64SetCondition::SignedGreaterOrEqual => emitter.bytes(&[0x0f, 0x9d, 0xc0])?,
            }
            emitter.bytes(&[0x48, 0x0f, 0xb6, 0xc0])?; // movzx rax, al
            emit_store_frame_gpr(emitter, instruction.result.offset, Gpr::Rax)
        }
        X64InstructionKind::ArrayLenF64 { array } => {
            require_operand_type("F64Array length", MachineType::F64Array, array)?;
            require_home_type(
                "F64Array length result",
                instruction.result,
                MachineType::I64,
            )?;
            let array = array_home("F64Array length", program, array)?;
            let length_offset =
                array
                    .offset
                    .checked_add(8)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "F64Array length offset",
                    })?;
            emit_load_frame_gpr(emitter, Gpr::Rax, length_offset)?;
            emit_store_frame_gpr(emitter, instruction.result.offset, Gpr::Rax)
        }
        X64InstructionKind::ArrayGetF64Checked { array, index } => {
            require_operand_type("checked F64Array access", MachineType::F64Array, array)?;
            require_operand_type("checked F64Array index", MachineType::I64, index)?;
            require_home_type(
                "checked F64Array result",
                instruction.result,
                MachineType::F64,
            )?;
            let array = array_home("checked F64Array access", program, array)?;
            emit_load_scalar(emitter, program, index, Gpr::Rdx)?;
            emitter.bytes(&[0x48, 0x85, 0xd2])?; // test rdx, rdx
            emitter.rel32(&[0x0f, 0x88], bounds_label)?; // js Bounds
            let length_offset =
                array
                    .offset
                    .checked_add(8)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "F64Array length offset",
                    })?;
            emit_load_frame_gpr(emitter, Gpr::Rcx, length_offset)?;
            emitter.bytes(&[0x48, 0x39, 0xca])?; // cmp rdx, rcx
            emitter.rel32(&[0x0f, 0x83], bounds_label)?; // jae Bounds
            emit_load_frame_gpr(emitter, Gpr::Rax, array.offset)?;
            // movsd xmm0, qword ptr [rax + rdx*8]
            emitter.bytes(&[0xf2, 0x0f, 0x10, 0x04, 0xd0])?;
            emit_store_xmm0_frame(emitter, instruction.result.offset)
        }
    }
}

fn emit_terminator(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    terminator: &X64Terminator,
    return_label: X64LabelId,
) -> Result<(), RawEncodeError> {
    match terminator {
        X64Terminator::Return { value, .. } => {
            emit_return_stage(emitter, program, value)?;
            emitter.rel32(&[0xe9], return_label)
        }
        X64Terminator::BranchRel32 {
            condition,
            then_label,
            else_label,
            ..
        } => {
            require_operand_type("branch condition", MachineType::Bool, condition)?;
            emit_load_scalar(emitter, program, condition, Gpr::Rax)?;
            emitter.bytes(&[0x48, 0x85, 0xc0])?; // test rax, rax
            emitter.rel32(&[0x0f, 0x85], *then_label)?; // jnz then
            emitter.rel32(&[0xe9], *else_label)
        }
        X64Terminator::TailJumpRel32 {
            function: callee,
            target_label,
            arguments,
            ..
        } => {
            emit_tail_transfer(emitter, program, *callee, arguments)?;
            emitter.rel32(&[0xe9], *target_label)
        }
    }
}

fn emit_move(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    operand: &X64Operand,
    result: X64Home,
) -> Result<(), RawEncodeError> {
    match result.ty {
        MachineType::Unit => emit_mov_mem64_imm32(emitter, result.offset, 0),
        MachineType::Bool | MachineType::I64 | MachineType::F64 => {
            emit_load_scalar(emitter, program, operand, Gpr::Rax)?;
            emit_store_frame_gpr(emitter, result.offset, Gpr::Rax)
        }
        MachineType::F64Array => {
            let source = array_home("F64Array move", program, operand)?;
            emit_load_frame_gpr(emitter, Gpr::Rax, source.offset)?;
            let source_length =
                source
                    .offset
                    .checked_add(8)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "F64Array move source length",
                    })?;
            emit_load_frame_gpr(emitter, Gpr::Rdx, source_length)?;
            emit_store_frame_gpr(emitter, result.offset, Gpr::Rax)?;
            let result_length =
                result
                    .offset
                    .checked_add(8)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "F64Array move result length",
                    })?;
            emit_store_frame_gpr(emitter, result_length, Gpr::Rdx)
        }
    }
}

fn emit_return_stage(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    value: &X64Operand,
) -> Result<(), RawEncodeError> {
    match value.ty() {
        MachineType::Unit => {
            emit_zero_gpr32(emitter, Gpr::Rax)?;
            emit_zero_gpr32(emitter, Gpr::Rdx)
        }
        MachineType::Bool | MachineType::I64 => {
            emit_load_scalar(emitter, program, value, Gpr::Rax)?;
            emit_zero_gpr32(emitter, Gpr::Rdx)
        }
        MachineType::F64 => {
            emit_load_scalar(emitter, program, value, Gpr::Rax)?;
            // movq xmm0, rax; ucomisd xmm0, xmm0; movabs rcx, canonical NaN;
            // cmovp rax, rcx. Signed zero and every non-NaN bit pattern pass
            // through unchanged.
            emitter.bytes(&[0x66, 0x48, 0x0f, 0x6e, 0xc0])?;
            emitter.bytes(&[0x66, 0x0f, 0x2e, 0xc0])?;
            emit_mov_imm64(emitter, Gpr::Rcx, X64_CANONICAL_NAN_BITS)?;
            emitter.bytes(&[0x48, 0x0f, 0x4a, 0xc1])?;
            emit_zero_gpr32(emitter, Gpr::Rdx)
        }
        MachineType::F64Array => {
            let home = array_home("F64Array return", program, value)?;
            emit_load_frame_gpr(emitter, Gpr::Rax, home.offset)?;
            let length_offset =
                home.offset
                    .checked_add(8)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "F64Array return length",
                    })?;
            emit_load_frame_gpr(emitter, Gpr::Rdx, length_offset)
        }
    }
}

fn emit_tail_transfer(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    callee_id: X64FunctionId,
    arguments: &[X64Operand],
) -> Result<(), RawEncodeError> {
    let callee = function(program, callee_id)?;
    if arguments.len() != callee.parameters.len() {
        return Err(RawEncodeError::TailArity {
            function: callee_id,
            arguments: arguments.len(),
            parameters: callee.parameters.len(),
        });
    }

    let mut cursor = 0u32;
    for (argument, parameter) in arguments.iter().zip(&callee.parameters) {
        require_operand_type("tail argument", parameter.home.ty, argument)?;
        check_home(program, "tail parameter", parameter.home)?;
        let width = u32::from(parameter.home.width);
        let stage_offset = program.frame.outgoing_base.checked_add(cursor).ok_or(
            RawEncodeError::ArithmeticOverflow {
                field: "tail stage offset",
            },
        )?;
        check_outgoing(program, stage_offset, width)?;
        emit_stage_operand(emitter, program, argument, parameter.home.ty, stage_offset)?;
        cursor = cursor
            .checked_add(width)
            .ok_or(RawEncodeError::ArithmeticOverflow {
                field: "tail stage extent",
            })?;
    }
    if cursor > program.frame.outgoing_bytes {
        return Err(RawEncodeError::TailExtent {
            required: cursor,
            declared: program.frame.outgoing_bytes,
        });
    }

    // Commit only after the complete argument vector has been staged.
    cursor = 0;
    for parameter in &callee.parameters {
        let width = u32::from(parameter.home.width);
        let words = width / 8;
        for word in 0..words {
            let word_delta = word
                .checked_mul(8)
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "tail commit word",
                })?;
            let source = program
                .frame
                .outgoing_base
                .checked_add(cursor)
                .and_then(|offset| offset.checked_add(word_delta))
                .ok_or(RawEncodeError::ArithmeticOverflow {
                    field: "tail commit source",
                })?;
            let destination = parameter.home.offset.checked_add(word_delta).ok_or(
                RawEncodeError::ArithmeticOverflow {
                    field: "tail commit destination",
                },
            )?;
            emit_load_frame_gpr(emitter, Gpr::Rax, source)?;
            emit_store_frame_gpr(emitter, destination, Gpr::Rax)?;
        }
        cursor = cursor
            .checked_add(width)
            .ok_or(RawEncodeError::ArithmeticOverflow {
                field: "tail commit extent",
            })?;
    }
    Ok(())
}

fn emit_stage_operand(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    operand: &X64Operand,
    ty: MachineType,
    destination: u32,
) -> Result<(), RawEncodeError> {
    match ty {
        MachineType::Unit => emit_mov_mem64_imm32(emitter, destination, 0),
        MachineType::Bool | MachineType::I64 | MachineType::F64 => {
            emit_load_scalar(emitter, program, operand, Gpr::Rax)?;
            emit_store_frame_gpr(emitter, destination, Gpr::Rax)
        }
        MachineType::F64Array => {
            let source = array_home("tail F64Array argument", program, operand)?;
            emit_load_frame_gpr(emitter, Gpr::Rax, source.offset)?;
            emit_store_frame_gpr(emitter, destination, Gpr::Rax)?;
            let source_length =
                source
                    .offset
                    .checked_add(8)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "tail F64Array source length",
                    })?;
            let destination_length =
                destination
                    .checked_add(8)
                    .ok_or(RawEncodeError::ArithmeticOverflow {
                        field: "tail F64Array destination length",
                    })?;
            emit_load_frame_gpr(emitter, Gpr::Rax, source_length)?;
            emit_store_frame_gpr(emitter, destination_length, Gpr::Rax)
        }
    }
}

fn emit_return_epilogue(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
) -> Result<(), RawEncodeError> {
    emit_load_frame_gpr(emitter, Gpr::Rcx, 8)?;
    emitter.bytes(&[0x48, 0x89, 0x01])?; // mov [rcx], rax
    emitter.bytes(&[0x48, 0x89, 0x91])?; // mov [rcx+disp32], rdx
    emitter.u32(8)?;
    emit_zero_gpr32(emitter, Gpr::Rax)?;
    emit_ldmxcsr_rsp_disp32(emitter, 0)?;
    emit_frame_release_and_return(emitter, program.frame.frame_bytes)
}

fn emit_bounds_epilogue(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
) -> Result<(), RawEncodeError> {
    emit_load_frame_gpr(emitter, Gpr::Rcx, 8)?;
    emit_zero_gpr32(emitter, Gpr::Rax)?;
    emitter.bytes(&[0x48, 0x89, 0x01])?; // mov [rcx], rax
    emitter.bytes(&[0x48, 0x89, 0x81])?; // mov [rcx+disp32], rax
    emitter.u32(8)?;
    emitter.bytes(&[0xb8])?; // mov eax, 1
    emitter.u32(1)?;
    emit_ldmxcsr_rsp_disp32(emitter, 0)?;
    emit_frame_release_and_return(emitter, program.frame.frame_bytes)
}

fn emit_frame_release_and_return(
    emitter: &mut RawEmitter,
    frame_bytes: u32,
) -> Result<(), RawEncodeError> {
    // add rsp, frame_bytes; pop rbp; ret
    emitter.bytes(&[0x48, 0x81, 0xc4])?;
    emitter.u32(frame_bytes)?;
    emitter.bytes(&[0x5d, 0xc3])
}

fn require_operand_type(
    context: &'static str,
    expected: MachineType,
    operand: &X64Operand,
) -> Result<(), RawEncodeError> {
    let actual = operand.ty();
    if actual != expected {
        return Err(RawEncodeError::InvalidOperand {
            context,
            expected,
            actual,
        });
    }
    Ok(())
}

fn require_result_width(context: &'static str, home: X64Home) -> Result<(), RawEncodeError> {
    let expected = physical_width(home.ty);
    if home.width != expected {
        return Err(RawEncodeError::InvalidResultWidth {
            context,
            ty: home.ty,
            expected,
            actual: home.width,
        });
    }
    Ok(())
}

fn require_home_type(
    context: &'static str,
    home: X64Home,
    expected: MachineType,
) -> Result<(), RawEncodeError> {
    if home.ty != expected {
        return Err(RawEncodeError::InvalidOperand {
            context,
            expected,
            actual: home.ty,
        });
    }
    require_result_width(context, home)
}

fn array_home(
    context: &'static str,
    program: &X64TargetProgram,
    operand: &X64Operand,
) -> Result<X64Home, RawEncodeError> {
    match operand {
        X64Operand::Home(home) if home.ty == MachineType::F64Array => {
            check_home(program, context, *home)?;
            Ok(*home)
        }
        _ => Err(RawEncodeError::InvalidArrayOperand { context }),
    }
}

fn emit_load_scalar(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    operand: &X64Operand,
    destination: Gpr,
) -> Result<(), RawEncodeError> {
    match operand {
        X64Operand::Immediate { ty, value } => {
            let bits = match (ty, value) {
                (MachineType::Unit, X64Immediate::Unit) => 0,
                (MachineType::Bool, X64Immediate::Bool(value)) => u64::from(*value),
                (MachineType::I64, X64Immediate::I64(value)) => *value as u64,
                (MachineType::F64, X64Immediate::F64Bits(bits)) => *bits,
                _ => {
                    return Err(RawEncodeError::InvalidOperand {
                        context: "scalar immediate representation",
                        expected: *ty,
                        actual: *ty,
                    });
                }
            };
            emit_mov_imm64(emitter, destination, bits)
        }
        X64Operand::Home(home) => {
            if home.ty == MachineType::F64Array {
                return Err(RawEncodeError::InvalidArrayOperand {
                    context: "scalar load",
                });
            }
            check_home(program, "scalar operand", *home)?;
            emit_load_frame_gpr(emitter, destination, home.offset)
        }
    }
}

fn emit_load_f64_xmm0(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    operand: &X64Operand,
) -> Result<(), RawEncodeError> {
    match operand {
        X64Operand::Immediate {
            ty: MachineType::F64,
            value: X64Immediate::F64Bits(bits),
        } => {
            emit_mov_imm64(emitter, Gpr::Rax, *bits)?;
            emitter.bytes(&[0x66, 0x48, 0x0f, 0x6e, 0xc0])
        }
        X64Operand::Home(home) if home.ty == MachineType::F64 => {
            check_home(program, "SSE2 F64 left operand", *home)?;
            emitter.bytes(&[0xf2, 0x0f, 0x10, 0x84, 0x24])?;
            emitter.u32(home.offset)
        }
        _ => Err(RawEncodeError::InvalidOperand {
            context: "SSE2 F64 left operand",
            expected: MachineType::F64,
            actual: operand.ty(),
        }),
    }
}

fn emit_load_f64_xmm1(
    emitter: &mut RawEmitter,
    program: &X64TargetProgram,
    operand: &X64Operand,
) -> Result<(), RawEncodeError> {
    match operand {
        X64Operand::Immediate {
            ty: MachineType::F64,
            value: X64Immediate::F64Bits(bits),
        } => {
            emit_mov_imm64(emitter, Gpr::Rcx, *bits)?;
            emitter.bytes(&[0x66, 0x48, 0x0f, 0x6e, 0xc9])
        }
        X64Operand::Home(home) if home.ty == MachineType::F64 => {
            check_home(program, "SSE2 F64 right operand", *home)?;
            emitter.bytes(&[0xf2, 0x0f, 0x10, 0x8c, 0x24])?;
            emitter.u32(home.offset)
        }
        _ => Err(RawEncodeError::InvalidOperand {
            context: "SSE2 F64 right operand",
            expected: MachineType::F64,
            actual: operand.ty(),
        }),
    }
}

fn emit_store_xmm0_frame(emitter: &mut RawEmitter, offset: u32) -> Result<(), RawEncodeError> {
    emitter.bytes(&[0xf2, 0x0f, 0x11, 0x84, 0x24])?;
    emitter.u32(offset)
}

fn emit_load_frame_gpr(
    emitter: &mut RawEmitter,
    destination: Gpr,
    offset: u32,
) -> Result<(), RawEncodeError> {
    let number = destination.number();
    let rex = 0x48 | if number >= 8 { 0x04 } else { 0 };
    let modrm = 0x84 | ((number & 7) << 3);
    emitter.bytes(&[rex, 0x8b, modrm, 0x24])?;
    emitter.u32(offset)
}

fn emit_store_frame_gpr(
    emitter: &mut RawEmitter,
    offset: u32,
    source: Gpr,
) -> Result<(), RawEncodeError> {
    let number = source.number();
    let rex = 0x48 | if number >= 8 { 0x04 } else { 0 };
    let modrm = 0x84 | ((number & 7) << 3);
    emitter.bytes(&[rex, 0x89, modrm, 0x24])?;
    emitter.u32(offset)
}

fn emit_mov_imm64(
    emitter: &mut RawEmitter,
    destination: Gpr,
    value: u64,
) -> Result<(), RawEncodeError> {
    let number = destination.number();
    let rex = 0x48 | if number >= 8 { 0x01 } else { 0 };
    emitter.bytes(&[rex, 0xb8 + (number & 7)])?;
    emitter.u64(value)
}

fn emit_zero_gpr32(emitter: &mut RawEmitter, register: Gpr) -> Result<(), RawEncodeError> {
    let number = register.number();
    let rex = if number >= 8 { Some(0x45) } else { None };
    if let Some(rex) = rex {
        emitter.u8(rex)?;
    }
    let modrm = 0xc0 | ((number & 7) << 3) | (number & 7);
    emitter.bytes(&[0x31, modrm])
}

fn emit_mov_mem32_imm32(
    emitter: &mut RawEmitter,
    offset: u32,
    value: u32,
) -> Result<(), RawEncodeError> {
    emitter.bytes(&[0xc7, 0x84, 0x24])?;
    emitter.u32(offset)?;
    emitter.u32(value)
}

fn emit_mov_mem64_imm32(
    emitter: &mut RawEmitter,
    offset: u32,
    value: u32,
) -> Result<(), RawEncodeError> {
    emitter.bytes(&[0x48, 0xc7, 0x84, 0x24])?;
    emitter.u32(offset)?;
    emitter.u32(value)
}

fn emit_stmxcsr_rsp_disp32(emitter: &mut RawEmitter, offset: u32) -> Result<(), RawEncodeError> {
    emitter.bytes(&[0x0f, 0xae, 0x9c, 0x24])?;
    emitter.u32(offset)
}

fn emit_ldmxcsr_rsp_disp32(emitter: &mut RawEmitter, offset: u32) -> Result<(), RawEncodeError> {
    emitter.bytes(&[0x0f, 0xae, 0x94, 0x24])?;
    emitter.u32(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emitter() -> RawEmitter {
        RawEmitter {
            code: Vec::new(),
            labels: Vec::new(),
            label_indices: BTreeMap::new(),
            marked_labels: BTreeMap::new(),
            fixups: Vec::new(),
            code_limit: 1024,
            fixup_limit: 16,
        }
    }

    #[test]
    fn fixed_rsp_disp32_templates_are_exact() {
        let mut emitter = emitter();
        emit_store_frame_gpr(&mut emitter, 0x1122_3344, Gpr::R8).unwrap();
        emit_load_frame_gpr(&mut emitter, Gpr::R9, 0x5566_7788).unwrap();
        assert_eq!(
            emitter.code,
            vec![
                0x4c, 0x89, 0x84, 0x24, 0x44, 0x33, 0x22, 0x11, 0x4c, 0x8b, 0x8c, 0x24, 0x88, 0x77,
                0x66, 0x55,
            ]
        );
    }

    #[test]
    fn rel32_patch_is_retained_and_little_endian() {
        let target = X64LabelId(0);
        let mut emitter = RawEmitter {
            code: Vec::new(),
            labels: vec![X64Label {
                id: target,
                owner: X64LabelOwner::ReturnEpilogue,
                code_offset: 0,
            }],
            label_indices: BTreeMap::from([(target, 0)]),
            marked_labels: BTreeMap::new(),
            fixups: Vec::new(),
            code_limit: 1024,
            fixup_limit: 16,
        };
        emitter.rel32(&[0xe9], target).unwrap();
        emitter.bytes(&[0x90, 0x90]).unwrap();
        emitter.mark(target).unwrap();
        let encoding = emitter.finish().unwrap();
        assert_eq!(encoding.code, vec![0xe9, 0x02, 0, 0, 0, 0x90, 0x90]);
        assert_eq!(
            encoding.fixups,
            vec![X64Fixup {
                patch_offset: 1,
                target,
                addend: 0,
            }]
        );
    }
}
