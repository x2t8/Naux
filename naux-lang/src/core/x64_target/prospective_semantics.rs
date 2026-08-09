//! Independent symbolic validation for proof-only shared-join shadow bytes.
//!
//! This module deliberately does not import the raw emitter or any of its
//! instruction-template helpers. It decodes a small canonical x86-64 subset
//! from the transient candidate bytes and compares the resulting typed state
//! transition with a reference transition reconstructed from the verified
//! target program and ordered shared-join routes.

use super::profile::{
    X64TargetSharedJoinComposition, X64TargetSharedJoinCompositionIngress,
    X64TargetSharedJoinCompositionStep, X64TargetSharedJoinKind, X64TargetSharedJoinRouteEvent,
};
use super::raw::{
    RawExecutionEvent, RawProspectiveExecutionAuthority, RawProspectiveShadow,
    RawProspectiveSharedJoinPartition, RawProspectiveSharedJoinRealization, RawTemplateClass,
};
use super::*;
use std::fmt;

const MAX_SEMANTIC_ROWS: u32 = 64;
const MAX_SEMANTIC_SLICE_BYTES: u64 = 1024 * 1024;
const MAX_DECODED_INSTRUCTIONS: u32 = 4_096;
const MAX_SYMBOLIC_NODES: usize = 8_192;
const MAX_FRAME_WORDS: usize = (X64_TARGET_MAX_FRAME_BYTES as usize) / 8;
const MAX_REFERENCE_ROUTE_EVENTS: u32 = 4_096;
const MAX_SEMANTIC_WORK: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ProspectiveSemanticSummary {
    pub(super) rows: u32,
    pub(super) decoded_bytes: u64,
    pub(super) decoded_instructions: u32,
    pub(super) symbolic_nodes: u32,
    pub(super) reference_route_events: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ProspectiveSemanticError {
    message: String,
}

impl ProspectiveSemanticError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ProspectiveSemanticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProspectiveSemanticError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum WordType {
    Unit,
    Bool,
    I64,
    F64,
    F64ArrayPointer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SymbolicOperation {
    I64Add,
    I64Sub,
    I64Mul,
    F64Add,
    F64Sub,
    I64LessThan,
    I64GreaterOrEqual,
}

impl SymbolicOperation {
    const fn result_type(self) -> WordType {
        match self {
            Self::I64Add | Self::I64Sub | Self::I64Mul => WordType::I64,
            Self::F64Add | Self::F64Sub => WordType::F64,
            Self::I64LessThan | Self::I64GreaterOrEqual => WordType::Bool,
        }
    }

    const fn operand_type(self) -> WordType {
        match self {
            Self::I64Add
            | Self::I64Sub
            | Self::I64Mul
            | Self::I64LessThan
            | Self::I64GreaterOrEqual => WordType::I64,
            Self::F64Add | Self::F64Sub => WordType::F64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SymbolicNode {
    Input {
        offset: u32,
        ty: WordType,
    },
    Immediate {
        bits: u64,
        ty: WordType,
    },
    Binary {
        operation: SymbolicOperation,
        left: u32,
        right: u32,
    },
}

#[derive(Default)]
struct SemanticBudget {
    work: u64,
}

impl SemanticBudget {
    fn charge(
        &mut self,
        amount: u64,
        context: &'static str,
    ) -> Result<(), ProspectiveSemanticError> {
        self.work = self
            .work
            .checked_add(amount)
            .ok_or_else(|| ProspectiveSemanticError::new("semantic decoder work overflow"))?;
        if self.work > MAX_SEMANTIC_WORK {
            return Err(ProspectiveSemanticError::new(format!(
                "semantic decoder {context} exceeds work cap {MAX_SEMANTIC_WORK}"
            )));
        }
        Ok(())
    }
}

#[derive(Default)]
struct SymbolicArena {
    nodes: Vec<SymbolicNode>,
}

impl SymbolicArena {
    fn intern(
        &mut self,
        node: SymbolicNode,
        budget: &mut SemanticBudget,
    ) -> Result<u32, ProspectiveSemanticError> {
        budget.charge(
            u64::try_from(self.nodes.len())
                .map_err(|_| ProspectiveSemanticError::new("symbolic node count overflow"))?
                .checked_add(1)
                .ok_or_else(|| ProspectiveSemanticError::new("symbolic lookup work overflow"))?,
            "symbolic interning",
        )?;
        if let Some(index) = self.nodes.iter().position(|candidate| *candidate == node) {
            return u32::try_from(index)
                .map_err(|_| ProspectiveSemanticError::new("symbolic node index overflow"));
        }
        if self.nodes.len() >= MAX_SYMBOLIC_NODES {
            return Err(ProspectiveSemanticError::new(format!(
                "symbolic node count exceeds cap {MAX_SYMBOLIC_NODES}"
            )));
        }
        self.nodes
            .try_reserve(1)
            .map_err(|_| ProspectiveSemanticError::new("symbolic node allocation failed"))?;
        let index = u32::try_from(self.nodes.len())
            .map_err(|_| ProspectiveSemanticError::new("symbolic node index overflow"))?;
        self.nodes.push(node);
        Ok(index)
    }

    fn input(
        &mut self,
        offset: u32,
        ty: WordType,
        budget: &mut SemanticBudget,
    ) -> Result<u32, ProspectiveSemanticError> {
        self.intern(SymbolicNode::Input { offset, ty }, budget)
    }

    fn immediate(
        &mut self,
        bits: u64,
        ty: WordType,
        budget: &mut SemanticBudget,
    ) -> Result<u32, ProspectiveSemanticError> {
        self.intern(SymbolicNode::Immediate { bits, ty }, budget)
    }

    fn binary(
        &mut self,
        operation: SymbolicOperation,
        left: u32,
        right: u32,
        budget: &mut SemanticBudget,
    ) -> Result<u32, ProspectiveSemanticError> {
        let expected = operation.operand_type();
        if self.node_type(left)? != expected || self.node_type(right)? != expected {
            return Err(ProspectiveSemanticError::new(format!(
                "symbolic {operation:?} operand type mismatch"
            )));
        }
        self.intern(
            SymbolicNode::Binary {
                operation,
                left,
                right,
            },
            budget,
        )
    }

    fn node_type(&self, id: u32) -> Result<WordType, ProspectiveSemanticError> {
        let node = self
            .nodes
            .get(id as usize)
            .ok_or_else(|| ProspectiveSemanticError::new("unknown symbolic node"))?;
        Ok(match node {
            SymbolicNode::Input { ty, .. } | SymbolicNode::Immediate { ty, .. } => *ty,
            SymbolicNode::Binary { operation, .. } => operation.result_type(),
        })
    }
}

#[derive(Clone)]
struct SemanticFrame {
    words: Vec<u32>,
}

impl SemanticFrame {
    fn from_program(
        program: &X64TargetProgram,
        budget: &mut SemanticBudget,
    ) -> Result<Self, ProspectiveSemanticError> {
        let mut words = Vec::new();
        for function in &program.functions {
            for parameter in &function.parameters {
                add_home_words(program, &mut words, parameter.home, budget)?;
            }
            for block in &function.blocks {
                for instruction in &block.instructions {
                    add_home_words(program, &mut words, instruction.result, budget)?;
                    for operand in instruction_operands(&instruction.kind) {
                        if let X64Operand::Home(home) = operand {
                            add_home_words(program, &mut words, *home, budget)?;
                        }
                    }
                }
                for operand in terminator_operands(&block.terminator) {
                    if let X64Operand::Home(home) = operand {
                        add_home_words(program, &mut words, *home, budget)?;
                    }
                }
            }
        }
        if words.is_empty() || words.len() > MAX_FRAME_WORDS {
            return Err(ProspectiveSemanticError::new(format!(
                "semantic frame word count {} is outside 1..={MAX_FRAME_WORDS}",
                words.len()
            )));
        }
        Ok(Self { words })
    }

    fn index(&self, offset: u32) -> Result<usize, ProspectiveSemanticError> {
        self.words.binary_search(&offset).map_err(|_| {
            ProspectiveSemanticError::new(format!(
                "semantic decoder references undeclared frame word {offset}"
            ))
        })
    }
}

fn add_home_words(
    program: &X64TargetProgram,
    words: &mut Vec<u32>,
    home: X64Home,
    budget: &mut SemanticBudget,
) -> Result<(), ProspectiveSemanticError> {
    budget.charge(1, "frame-home discovery")?;
    let expected_width = match home.ty {
        MachineType::F64Array => 16,
        MachineType::Unit | MachineType::Bool | MachineType::I64 | MachineType::F64 => 8,
    };
    if u32::from(home.width) != expected_width {
        return Err(ProspectiveSemanticError::new(format!(
            "home {} has non-canonical width {} for {:?}",
            home.offset, home.width, home.ty
        )));
    }
    let end = home
        .offset
        .checked_add(expected_width)
        .ok_or_else(|| ProspectiveSemanticError::new("home end overflow"))?;
    if home.offset < program.frame.home_base || end > program.frame.outgoing_base {
        return Err(ProspectiveSemanticError::new(format!(
            "home {}..{end} lies outside the canonical home area",
            home.offset
        )));
    }
    let word_count = if home.ty == MachineType::F64Array {
        2
    } else {
        1
    };
    for index in 0..word_count {
        let delta = u32::try_from(index)
            .map_err(|_| ProspectiveSemanticError::new("home word index overflow"))?
            .checked_mul(8)
            .ok_or_else(|| ProspectiveSemanticError::new("home word offset overflow"))?;
        let offset = home
            .offset
            .checked_add(delta)
            .ok_or_else(|| ProspectiveSemanticError::new("home word offset overflow"))?;
        match words.binary_search(&offset) {
            Ok(_) => {}
            Err(insert) => {
                if words.len() >= MAX_FRAME_WORDS {
                    return Err(ProspectiveSemanticError::new(format!(
                        "semantic frame exceeds {MAX_FRAME_WORDS} words"
                    )));
                }
                words.try_reserve(1).map_err(|_| {
                    ProspectiveSemanticError::new("semantic frame allocation failed")
                })?;
                words.insert(insert, offset);
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SymbolicValue {
    Input {
        offset: u32,
    },
    Immediate {
        bits: u64,
        declared: Option<WordType>,
    },
    Typed(u32),
}

impl SymbolicValue {
    fn resolve(
        self,
        expected: WordType,
        arena: &mut SymbolicArena,
        budget: &mut SemanticBudget,
    ) -> Result<u32, ProspectiveSemanticError> {
        match self {
            Self::Input { offset } => arena.input(offset, expected, budget),
            Self::Immediate { bits, declared } => {
                if declared.is_some_and(|declared| declared != expected) {
                    return Err(ProspectiveSemanticError::new(format!(
                        "semantic immediate declared as {declared:?}, used as {expected:?}"
                    )));
                }
                arena.immediate(bits, expected, budget)
            }
            Self::Typed(value) => {
                if arena.node_type(value)? != expected {
                    return Err(ProspectiveSemanticError::new(format!(
                        "typed symbolic value used as {expected:?}"
                    )));
                }
                Ok(value)
            }
        }
    }
}

fn instruction_operands(kind: &X64InstructionKind) -> Vec<&X64Operand> {
    match kind {
        X64InstructionKind::Move(operand) | X64InstructionKind::ArrayLenF64 { array: operand } => {
            vec![operand]
        }
        X64InstructionKind::I64Wrapping { left, right, .. }
        | X64InstructionKind::Sse2F64 { left, right, .. }
        | X64InstructionKind::I64Setcc { left, right, .. } => vec![left, right],
        X64InstructionKind::ArrayGetF64Checked { array, index } => vec![array, index],
    }
}

fn terminator_operands(terminator: &X64Terminator) -> Vec<&X64Operand> {
    match terminator {
        X64Terminator::Return { value, .. } => vec![value],
        X64Terminator::BranchRel32 { condition, .. } => vec![condition],
        X64Terminator::TailJumpRel32 { arguments, .. } => arguments.iter().collect(),
    }
}

#[derive(Clone)]
struct SymbolicState {
    frame: Vec<SymbolicValue>,
    gpr: [Option<SymbolicValue>; 16],
    xmm: [Option<SymbolicValue>; 8],
}

struct SemanticEngine<'engine> {
    program: &'engine X64TargetProgram,
    frame: &'engine SemanticFrame,
    arena: &'engine mut SymbolicArena,
    budget: &'engine mut SemanticBudget,
    summary: &'engine mut ProspectiveSemanticSummary,
}

impl SymbolicState {
    fn initial(frame: &SemanticFrame) -> Result<Self, ProspectiveSemanticError> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(frame.words.len())
            .map_err(|_| ProspectiveSemanticError::new("initial frame allocation failed"))?;
        for offset in &frame.words {
            values.push(SymbolicValue::Input { offset: *offset });
        }
        Ok(Self {
            frame: values,
            gpr: [None; 16],
            xmm: [None; 8],
        })
    }

    fn read_frame(
        &self,
        frame: &SemanticFrame,
        offset: u32,
    ) -> Result<SymbolicValue, ProspectiveSemanticError> {
        let index = frame.index(offset)?;
        self.frame
            .get(index)
            .copied()
            .ok_or_else(|| ProspectiveSemanticError::new("missing symbolic frame value"))
    }

    fn write_frame(
        &mut self,
        frame: &SemanticFrame,
        offset: u32,
        value: SymbolicValue,
    ) -> Result<(), ProspectiveSemanticError> {
        let index = frame.index(offset)?;
        self.frame[index] = value;
        Ok(())
    }

    fn read_gpr(&self, register: u8) -> Result<SymbolicValue, ProspectiveSemanticError> {
        self.gpr
            .get(register as usize)
            .copied()
            .flatten()
            .ok_or_else(|| {
                ProspectiveSemanticError::new(format!(
                    "semantic decoder reads uninitialized GPR {register}"
                ))
            })
    }

    fn write_gpr(
        &mut self,
        register: u8,
        value: SymbolicValue,
    ) -> Result<(), ProspectiveSemanticError> {
        let slot = self
            .gpr
            .get_mut(register as usize)
            .ok_or_else(|| ProspectiveSemanticError::new(format!("unsupported GPR {register}")))?;
        *slot = Some(value);
        Ok(())
    }

    fn read_xmm(&self, register: u8) -> Result<SymbolicValue, ProspectiveSemanticError> {
        self.xmm
            .get(register as usize)
            .copied()
            .flatten()
            .ok_or_else(|| {
                ProspectiveSemanticError::new(format!(
                    "semantic decoder reads uninitialized XMM{register}"
                ))
            })
    }

    fn write_xmm(
        &mut self,
        register: u8,
        value: SymbolicValue,
    ) -> Result<(), ProspectiveSemanticError> {
        let slot = self
            .xmm
            .get_mut(register as usize)
            .ok_or_else(|| ProspectiveSemanticError::new(format!("unsupported XMM{register}")))?;
        *slot = Some(value);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecodedInstruction {
    LoadGpr {
        destination: u8,
        offset: u32,
    },
    StoreGpr {
        offset: u32,
        source: u8,
    },
    ImmediateGpr {
        destination: u8,
        bits: u64,
    },
    MoveGpr {
        destination: u8,
        source: u8,
    },
    I64Binary {
        operation: SymbolicOperation,
        destination: u8,
        source: u8,
    },
    LoadXmm {
        destination: u8,
        offset: u32,
    },
    StoreXmm {
        offset: u32,
        source: u8,
    },
    MoveXmm {
        destination: u8,
        source: u8,
    },
    F64Binary {
        operation: SymbolicOperation,
        destination: u8,
        source: u8,
    },
    JumpRel32 {
        target_offset: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecodedControl {
    Fallthrough,
    Jump(u32),
}

struct ByteDecoder<'bytes> {
    bytes: &'bytes [u8],
    absolute_start: u32,
    cursor: usize,
}

impl<'bytes> ByteDecoder<'bytes> {
    fn new(bytes: &'bytes [u8], absolute_start: u32) -> Self {
        Self {
            bytes,
            absolute_start,
            cursor: 0,
        }
    }

    fn read_u8(&mut self) -> Result<u8, ProspectiveSemanticError> {
        let value = self.bytes.get(self.cursor).copied().ok_or_else(|| {
            ProspectiveSemanticError::new("truncated prospective machine instruction")
        })?;
        self.cursor += 1;
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32, ProspectiveSemanticError> {
        let end = self
            .cursor
            .checked_add(4)
            .ok_or_else(|| ProspectiveSemanticError::new("decoder cursor overflow"))?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| ProspectiveSemanticError::new("truncated prospective disp32"))?;
        self.cursor = end;
        Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
            ProspectiveSemanticError::new("invalid prospective disp32")
        })?))
    }

    fn read_u64(&mut self) -> Result<u64, ProspectiveSemanticError> {
        let end = self
            .cursor
            .checked_add(8)
            .ok_or_else(|| ProspectiveSemanticError::new("decoder cursor overflow"))?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| ProspectiveSemanticError::new("truncated prospective imm64"))?;
        self.cursor = end;
        Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| {
            ProspectiveSemanticError::new("invalid prospective imm64")
        })?))
    }

    fn decode_next(&mut self) -> Result<DecodedInstruction, ProspectiveSemanticError> {
        let opcode = self.read_u8()?;
        match opcode {
            0xe9 => {
                let displacement = self.read_u32()? as i32;
                let next = i64::from(self.absolute_start)
                    .checked_add(i64::try_from(self.cursor).map_err(|_| {
                        ProspectiveSemanticError::new("decoder cursor conversion overflow")
                    })?)
                    .ok_or_else(|| ProspectiveSemanticError::new("relative jump base overflow"))?;
                let target = next
                    .checked_add(i64::from(displacement))
                    .and_then(|target| u32::try_from(target).ok())
                    .ok_or_else(|| {
                        ProspectiveSemanticError::new("relative jump target overflow")
                    })?;
                Ok(DecodedInstruction::JumpRel32 {
                    target_offset: target,
                })
            }
            0xf2 => self.decode_sse2(),
            rex @ 0x48..=0x4f => self.decode_rex(rex),
            _ => Err(ProspectiveSemanticError::new(format!(
                "unsupported prospective opcode 0x{opcode:02x}"
            ))),
        }
    }

    fn decode_rex(&mut self, rex: u8) -> Result<DecodedInstruction, ProspectiveSemanticError> {
        if rex & 0x08 == 0 || rex & 0x02 != 0 {
            return Err(ProspectiveSemanticError::new(format!(
                "non-canonical prospective REX prefix 0x{rex:02x}"
            )));
        }
        let opcode = self.read_u8()?;
        if (0xb8..=0xbf).contains(&opcode) {
            if rex & 0x04 != 0 {
                return Err(ProspectiveSemanticError::new(
                    "movabs carries an unused REX.R bit",
                ));
            }
            let destination = (opcode - 0xb8) + if rex & 0x01 != 0 { 8 } else { 0 };
            admit_gpr(destination)?;
            let expected_rex = 0x48 | if destination >= 8 { 0x01 } else { 0 };
            if rex != expected_rex {
                return Err(ProspectiveSemanticError::new(
                    "movabs uses a non-canonical REX prefix",
                ));
            }
            return Ok(DecodedInstruction::ImmediateGpr {
                destination,
                bits: self.read_u64()?,
            });
        }

        if opcode == 0x0f {
            let secondary = self.read_u8()?;
            if secondary != 0xaf {
                return Err(ProspectiveSemanticError::new(format!(
                    "unsupported prospective REX 0f opcode 0x{secondary:02x}"
                )));
            }
            let modrm = self.read_u8()?;
            require_register_modrm(modrm)?;
            let destination = modrm_reg(rex, modrm);
            let source = modrm_rm(rex, modrm);
            admit_gpr(destination)?;
            admit_gpr(source)?;
            require_exact_rex(rex, destination, source)?;
            return Ok(DecodedInstruction::I64Binary {
                operation: SymbolicOperation::I64Mul,
                destination,
                source,
            });
        }

        let modrm = self.read_u8()?;
        match opcode {
            0x8b => {
                let destination = decode_stack_register(rex, modrm, self.read_u8()?)?;
                admit_gpr(destination)?;
                Ok(DecodedInstruction::LoadGpr {
                    destination,
                    offset: self.read_u32()?,
                })
            }
            0x89 if modrm & 0xc0 == 0x80 => {
                let source = decode_stack_register(rex, modrm, self.read_u8()?)?;
                admit_gpr(source)?;
                Ok(DecodedInstruction::StoreGpr {
                    offset: self.read_u32()?,
                    source,
                })
            }
            0x89 => {
                require_register_modrm(modrm)?;
                let source = modrm_reg(rex, modrm);
                let destination = modrm_rm(rex, modrm);
                admit_gpr(destination)?;
                admit_gpr(source)?;
                require_exact_rex(rex, source, destination)?;
                if destination == source {
                    return Err(ProspectiveSemanticError::new(
                        "redundant register move is non-canonical",
                    ));
                }
                Ok(DecodedInstruction::MoveGpr {
                    destination,
                    source,
                })
            }
            0x01 | 0x29 => {
                require_register_modrm(modrm)?;
                let source = modrm_reg(rex, modrm);
                let destination = modrm_rm(rex, modrm);
                admit_gpr(destination)?;
                admit_gpr(source)?;
                require_exact_rex(rex, source, destination)?;
                Ok(DecodedInstruction::I64Binary {
                    operation: if opcode == 0x01 {
                        SymbolicOperation::I64Add
                    } else {
                        SymbolicOperation::I64Sub
                    },
                    destination,
                    source,
                })
            }
            _ => Err(ProspectiveSemanticError::new(format!(
                "unsupported prospective REX opcode 0x{opcode:02x}"
            ))),
        }
    }

    fn decode_sse2(&mut self) -> Result<DecodedInstruction, ProspectiveSemanticError> {
        if self.read_u8()? != 0x0f {
            return Err(ProspectiveSemanticError::new(
                "prospective F2 prefix is not followed by 0f",
            ));
        }
        let opcode = self.read_u8()?;
        let modrm = self.read_u8()?;
        if modrm & 0xc0 == 0x80 {
            if !matches!(opcode, 0x10 | 0x11) || modrm & 0xc7 != 0x84 {
                return Err(ProspectiveSemanticError::new(
                    "non-canonical prospective stack-relative movsd",
                ));
            }
            let register = (modrm >> 3) & 7;
            admit_xmm(register)?;
            if self.read_u8()? != 0x24 {
                return Err(ProspectiveSemanticError::new(
                    "prospective movsd has a non-canonical SIB",
                ));
            }
            let offset = self.read_u32()?;
            return Ok(if opcode == 0x10 {
                DecodedInstruction::LoadXmm {
                    destination: register,
                    offset,
                }
            } else {
                DecodedInstruction::StoreXmm {
                    offset,
                    source: register,
                }
            });
        }
        require_register_modrm(modrm)?;
        let destination = (modrm >> 3) & 7;
        let source = modrm & 7;
        admit_xmm(destination)?;
        admit_xmm(source)?;
        match opcode {
            0x10 => {
                if destination == source {
                    return Err(ProspectiveSemanticError::new(
                        "redundant XMM move is non-canonical",
                    ));
                }
                Ok(DecodedInstruction::MoveXmm {
                    destination,
                    source,
                })
            }
            0x58 | 0x5c => Ok(DecodedInstruction::F64Binary {
                operation: if opcode == 0x58 {
                    SymbolicOperation::F64Add
                } else {
                    SymbolicOperation::F64Sub
                },
                destination,
                source,
            }),
            _ => Err(ProspectiveSemanticError::new(format!(
                "unsupported prospective SSE2 opcode 0x{opcode:02x}"
            ))),
        }
    }
}

fn admit_gpr(register: u8) -> Result<(), ProspectiveSemanticError> {
    if matches!(register, 0 | 1 | 2 | 8) {
        Ok(())
    } else {
        Err(ProspectiveSemanticError::new(format!(
            "prospective semantic subset does not admit GPR {register}"
        )))
    }
}

fn admit_xmm(register: u8) -> Result<(), ProspectiveSemanticError> {
    if register <= 2 {
        Ok(())
    } else {
        Err(ProspectiveSemanticError::new(format!(
            "prospective semantic subset does not admit XMM{register}"
        )))
    }
}

fn require_register_modrm(modrm: u8) -> Result<(), ProspectiveSemanticError> {
    if modrm & 0xc0 == 0xc0 {
        Ok(())
    } else {
        Err(ProspectiveSemanticError::new(
            "prospective instruction requires register ModRM",
        ))
    }
}

fn decode_stack_register(rex: u8, modrm: u8, sib: u8) -> Result<u8, ProspectiveSemanticError> {
    if modrm & 0xc7 != 0x84 || sib != 0x24 || rex & 0x01 != 0 {
        return Err(ProspectiveSemanticError::new(
            "non-canonical prospective RSP+disp32 addressing",
        ));
    }
    let register = modrm_reg(rex, modrm);
    let expected_rex = 0x48 | if register >= 8 { 0x04 } else { 0 };
    if rex != expected_rex {
        return Err(ProspectiveSemanticError::new(
            "stack transfer uses a non-canonical REX prefix",
        ));
    }
    Ok(register)
}

const fn modrm_reg(rex: u8, modrm: u8) -> u8 {
    ((modrm >> 3) & 7) + if rex & 0x04 != 0 { 8 } else { 0 }
}

const fn modrm_rm(rex: u8, modrm: u8) -> u8 {
    (modrm & 7) + if rex & 0x01 != 0 { 8 } else { 0 }
}

fn require_exact_rex(rex: u8, reg_field: u8, rm_field: u8) -> Result<(), ProspectiveSemanticError> {
    let expected =
        0x48 | if reg_field >= 8 { 0x04 } else { 0 } | if rm_field >= 8 { 0x01 } else { 0 };
    if rex == expected {
        Ok(())
    } else {
        Err(ProspectiveSemanticError::new(
            "register instruction uses a non-canonical REX prefix",
        ))
    }
}

fn execute_decoded_instruction(
    instruction: DecodedInstruction,
    state: &mut SymbolicState,
    frame: &SemanticFrame,
    arena: &mut SymbolicArena,
    budget: &mut SemanticBudget,
) -> Result<Option<DecodedControl>, ProspectiveSemanticError> {
    match instruction {
        DecodedInstruction::LoadGpr {
            destination,
            offset,
        } => {
            let value = state.read_frame(frame, offset)?;
            state.write_gpr(destination, value)?;
        }
        DecodedInstruction::StoreGpr { offset, source } => {
            let value = state.read_gpr(source)?;
            state.write_frame(frame, offset, value)?;
        }
        DecodedInstruction::ImmediateGpr { destination, bits } => {
            let value = SymbolicValue::Immediate {
                bits,
                declared: None,
            };
            state.write_gpr(destination, value)?;
        }
        DecodedInstruction::MoveGpr {
            destination,
            source,
        } => {
            let value = state.read_gpr(source)?;
            state.write_gpr(destination, value)?;
        }
        DecodedInstruction::I64Binary {
            operation,
            destination,
            source,
        } => {
            let left = state
                .read_gpr(destination)?
                .resolve(WordType::I64, arena, budget)?;
            let right = state
                .read_gpr(source)?
                .resolve(WordType::I64, arena, budget)?;
            let result = arena.binary(operation, left, right, budget)?;
            state.write_gpr(destination, SymbolicValue::Typed(result))?;
        }
        DecodedInstruction::LoadXmm {
            destination,
            offset,
        } => {
            let value = state
                .read_frame(frame, offset)?
                .resolve(WordType::F64, arena, budget)?;
            state.write_xmm(destination, SymbolicValue::Typed(value))?;
        }
        DecodedInstruction::StoreXmm { offset, source } => {
            let value = state
                .read_xmm(source)?
                .resolve(WordType::F64, arena, budget)?;
            state.write_frame(frame, offset, SymbolicValue::Typed(value))?;
        }
        DecodedInstruction::MoveXmm {
            destination,
            source,
        } => {
            let value = state.read_xmm(source)?;
            state.write_xmm(destination, value)?;
        }
        DecodedInstruction::F64Binary {
            operation,
            destination,
            source,
        } => {
            let left = state
                .read_xmm(destination)?
                .resolve(WordType::F64, arena, budget)?;
            let right = state
                .read_xmm(source)?
                .resolve(WordType::F64, arena, budget)?;
            let result = arena.binary(operation, left, right, budget)?;
            state.write_xmm(destination, SymbolicValue::Typed(result))?;
        }
        DecodedInstruction::JumpRel32 { target_offset } => {
            return Ok(Some(DecodedControl::Jump(target_offset)));
        }
    }
    Ok(None)
}

fn decode_atom(
    engine: &mut SemanticEngine<'_>,
    code: &[u8],
    start: u32,
    end: u32,
    state: &mut SymbolicState,
) -> Result<DecodedControl, ProspectiveSemanticError> {
    let start_index = usize::try_from(start)
        .map_err(|_| ProspectiveSemanticError::new("atom start conversion overflow"))?;
    let end_index = usize::try_from(end)
        .map_err(|_| ProspectiveSemanticError::new("atom end conversion overflow"))?;
    let bytes = code.get(start_index..end_index).ok_or_else(|| {
        ProspectiveSemanticError::new("semantic atom lies outside candidate code")
    })?;
    if bytes.is_empty() {
        return Err(ProspectiveSemanticError::new(
            "semantic decoder received an empty atom",
        ));
    }
    let length = u64::try_from(bytes.len())
        .map_err(|_| ProspectiveSemanticError::new("semantic slice length overflow"))?;
    engine.summary.decoded_bytes = engine
        .summary
        .decoded_bytes
        .checked_add(length)
        .ok_or_else(|| ProspectiveSemanticError::new("decoded byte total overflow"))?;
    if engine.summary.decoded_bytes > MAX_SEMANTIC_SLICE_BYTES {
        return Err(ProspectiveSemanticError::new(format!(
            "decoded bytes exceed cap {MAX_SEMANTIC_SLICE_BYTES}"
        )));
    }
    engine.budget.charge(length, "candidate byte decode")?;

    let mut decoder = ByteDecoder::new(bytes, start);
    let mut control = DecodedControl::Fallthrough;
    while decoder.cursor < bytes.len() {
        if control != DecodedControl::Fallthrough {
            return Err(ProspectiveSemanticError::new(
                "prospective atom retains bytes after a control transfer",
            ));
        }
        let instruction = decoder.decode_next()?;
        engine.summary.decoded_instructions = engine
            .summary
            .decoded_instructions
            .checked_add(1)
            .ok_or_else(|| ProspectiveSemanticError::new("decoded instruction overflow"))?;
        if engine.summary.decoded_instructions > MAX_DECODED_INSTRUCTIONS {
            return Err(ProspectiveSemanticError::new(format!(
                "decoded instruction count exceeds {MAX_DECODED_INSTRUCTIONS}"
            )));
        }
        engine.budget.charge(1, "decoded instruction execution")?;
        if let Some(next) = execute_decoded_instruction(
            instruction,
            state,
            engine.frame,
            engine.arena,
            engine.budget,
        )? {
            control = next;
        }
    }
    Ok(control)
}

fn execute_reference_instruction(
    instruction: &X64Instruction,
    state: &mut SymbolicState,
    frame: &SemanticFrame,
    arena: &mut SymbolicArena,
    budget: &mut SemanticBudget,
) -> Result<(), ProspectiveSemanticError> {
    budget.charge(1, "reference instruction")?;
    match &instruction.kind {
        X64InstructionKind::Move(operand) => {
            let values = reference_operand_words(operand, state, frame, arena, budget)?;
            write_home_words(instruction.result, &values, state, frame, arena, budget)
        }
        X64InstructionKind::I64Wrapping {
            opcode,
            left,
            right,
        } => {
            let left = reference_scalar_operand(left, state, frame, arena, budget)?;
            let right = reference_scalar_operand(right, state, frame, arena, budget)?;
            let operation = match opcode {
                X64I64Opcode::Add => SymbolicOperation::I64Add,
                X64I64Opcode::Sub => SymbolicOperation::I64Sub,
                X64I64Opcode::Mul => SymbolicOperation::I64Mul,
            };
            let value = arena.binary(operation, left, right, budget)?;
            write_home_words(
                instruction.result,
                &[SymbolicValue::Typed(value)],
                state,
                frame,
                arena,
                budget,
            )
        }
        X64InstructionKind::Sse2F64 {
            opcode,
            left,
            right,
        } => {
            let left = reference_scalar_operand(left, state, frame, arena, budget)?;
            let right = reference_scalar_operand(right, state, frame, arena, budget)?;
            let operation = match opcode {
                X64Sse2F64Opcode::AddSd => SymbolicOperation::F64Add,
                X64Sse2F64Opcode::SubSd => SymbolicOperation::F64Sub,
            };
            let value = arena.binary(operation, left, right, budget)?;
            write_home_words(
                instruction.result,
                &[SymbolicValue::Typed(value)],
                state,
                frame,
                arena,
                budget,
            )
        }
        X64InstructionKind::I64Setcc {
            condition,
            left,
            right,
        } => {
            let left = reference_scalar_operand(left, state, frame, arena, budget)?;
            let right = reference_scalar_operand(right, state, frame, arena, budget)?;
            let operation = match condition {
                X64SetCondition::SignedLessThan => SymbolicOperation::I64LessThan,
                X64SetCondition::SignedGreaterOrEqual => SymbolicOperation::I64GreaterOrEqual,
            };
            let value = arena.binary(operation, left, right, budget)?;
            write_home_words(
                instruction.result,
                &[SymbolicValue::Typed(value)],
                state,
                frame,
                arena,
                budget,
            )
        }
        X64InstructionKind::ArrayLenF64 { array } => {
            let values = reference_operand_words(array, state, frame, arena, budget)?;
            let length = values.get(1).copied().ok_or_else(|| {
                ProspectiveSemanticError::new("array length operand has no length word")
            })?;
            write_home_words(instruction.result, &[length], state, frame, arena, budget)
        }
        X64InstructionKind::ArrayGetF64Checked { .. } => Err(ProspectiveSemanticError::new(
            "checked array access is outside the register semantic subset",
        )),
    }
}

fn reference_operand_words(
    operand: &X64Operand,
    state: &SymbolicState,
    frame: &SemanticFrame,
    _arena: &mut SymbolicArena,
    _budget: &mut SemanticBudget,
) -> Result<Vec<SymbolicValue>, ProspectiveSemanticError> {
    let mut values = Vec::new();
    let width = if operand.ty() == MachineType::F64Array {
        2
    } else {
        1
    };
    values
        .try_reserve_exact(width)
        .map_err(|_| ProspectiveSemanticError::new("reference operand allocation failed"))?;
    match operand {
        X64Operand::Immediate { ty, value } => {
            let (word_type, bits) = match (ty, value) {
                (MachineType::Unit, X64Immediate::Unit) => (WordType::Unit, 0),
                (MachineType::Bool, X64Immediate::Bool(value)) => {
                    (WordType::Bool, u64::from(*value))
                }
                (MachineType::I64, X64Immediate::I64(value)) => (WordType::I64, *value as u64),
                (MachineType::F64, X64Immediate::F64Bits(bits)) => (WordType::F64, *bits),
                _ => {
                    return Err(ProspectiveSemanticError::new(
                        "non-canonical reference immediate",
                    ));
                }
            };
            values.push(SymbolicValue::Immediate {
                bits,
                declared: Some(word_type),
            });
        }
        X64Operand::Home(home) => {
            for offset in home_word_offsets(*home)? {
                values.push(state.read_frame(frame, offset)?);
            }
        }
    }
    Ok(values)
}

fn reference_scalar_operand(
    operand: &X64Operand,
    state: &SymbolicState,
    frame: &SemanticFrame,
    arena: &mut SymbolicArena,
    budget: &mut SemanticBudget,
) -> Result<u32, ProspectiveSemanticError> {
    let values = reference_operand_words(operand, state, frame, arena, budget)?;
    if values.len() != 1 {
        return Err(ProspectiveSemanticError::new(
            "reference scalar operand spans multiple words",
        ));
    }
    let expected = scalar_word_type(operand.ty())?;
    values[0].resolve(expected, arena, budget)
}

fn scalar_word_type(ty: MachineType) -> Result<WordType, ProspectiveSemanticError> {
    match ty {
        MachineType::Unit => Ok(WordType::Unit),
        MachineType::Bool => Ok(WordType::Bool),
        MachineType::I64 => Ok(WordType::I64),
        MachineType::F64 => Ok(WordType::F64),
        MachineType::F64Array => Err(ProspectiveSemanticError::new(
            "array value used as a scalar symbolic word",
        )),
    }
}

fn home_word_types(home: X64Home) -> Vec<WordType> {
    match home.ty {
        MachineType::F64Array => vec![WordType::F64ArrayPointer, WordType::I64],
        MachineType::Unit => vec![WordType::Unit],
        MachineType::Bool => vec![WordType::Bool],
        MachineType::I64 => vec![WordType::I64],
        MachineType::F64 => vec![WordType::F64],
    }
}

fn home_word_offsets(home: X64Home) -> Result<Vec<u32>, ProspectiveSemanticError> {
    let words = if home.ty == MachineType::F64Array {
        2
    } else {
        1
    };
    let mut offsets = Vec::new();
    offsets
        .try_reserve_exact(words)
        .map_err(|_| ProspectiveSemanticError::new("home-word allocation failed"))?;
    for word in 0..words {
        let delta = u32::try_from(word)
            .map_err(|_| ProspectiveSemanticError::new("home-word conversion overflow"))?
            .checked_mul(8)
            .ok_or_else(|| ProspectiveSemanticError::new("home-word delta overflow"))?;
        offsets.push(
            home.offset
                .checked_add(delta)
                .ok_or_else(|| ProspectiveSemanticError::new("home-word offset overflow"))?,
        );
    }
    Ok(offsets)
}

fn write_home_words(
    home: X64Home,
    values: &[SymbolicValue],
    state: &mut SymbolicState,
    frame: &SemanticFrame,
    arena: &mut SymbolicArena,
    budget: &mut SemanticBudget,
) -> Result<(), ProspectiveSemanticError> {
    let offsets = home_word_offsets(home)?;
    let types = home_word_types(home);
    if offsets.len() != values.len() || types.len() != values.len() {
        return Err(ProspectiveSemanticError::new(format!(
            "reference write to home {} has the wrong width",
            home.offset
        )));
    }
    for ((offset, expected), value) in offsets.into_iter().zip(types).zip(values.iter().copied()) {
        let value = value.resolve(expected, arena, budget)?;
        state.write_frame(frame, offset, SymbolicValue::Typed(value))?;
    }
    Ok(())
}

fn apply_reference_tail(
    program: &X64TargetProgram,
    source: X64LabelId,
    target: X64LabelId,
    state: &mut SymbolicState,
    frame: &SemanticFrame,
    arena: &mut SymbolicArena,
    budget: &mut SemanticBudget,
) -> Result<(), ProspectiveSemanticError> {
    budget.charge(1, "reference tail event")?;
    let (_, source_block) = function_and_block_for_label(program, source)?;
    let X64Terminator::TailJumpRel32 {
        function,
        target_label,
        arguments,
        ..
    } = &source_block.terminator
    else {
        return Err(ProspectiveSemanticError::new(format!(
            "reference route source {} is not a tail",
            source.0
        )));
    };
    if *target_label != target {
        return Err(ProspectiveSemanticError::new(format!(
            "reference route tail {} targets {}, expected {}",
            source.0, target_label.0, target.0
        )));
    }
    let (callee, target_block) = function_and_block_for_label(program, target)?;
    if callee.id != *function || target_block.id != callee.entry_block {
        return Err(ProspectiveSemanticError::new(format!(
            "reference route target {} is not the declared callee entry",
            target.0
        )));
    }
    if arguments.len() != callee.parameters.len() {
        return Err(ProspectiveSemanticError::new(
            "reference tail arity differs from callee parameters",
        ));
    }
    let max_assignments = arguments
        .len()
        .checked_mul(2)
        .ok_or_else(|| ProspectiveSemanticError::new("tail assignment count overflow"))?;
    let mut assignments: Vec<(u32, WordType, SymbolicValue)> = Vec::new();
    assignments
        .try_reserve_exact(max_assignments)
        .map_err(|_| ProspectiveSemanticError::new("tail assignment allocation failed"))?;
    for (argument, parameter) in arguments.iter().zip(&callee.parameters) {
        if argument.ty() != parameter.home.ty {
            return Err(ProspectiveSemanticError::new(
                "reference tail argument type differs from parameter",
            ));
        }
        let values = reference_operand_words(argument, state, frame, arena, budget)?;
        let offsets = home_word_offsets(parameter.home)?;
        let types = home_word_types(parameter.home);
        if offsets.len() != values.len() || types.len() != values.len() {
            return Err(ProspectiveSemanticError::new(
                "reference tail argument width differs from parameter",
            ));
        }
        for ((offset, expected), value) in offsets.into_iter().zip(types).zip(values) {
            if assignments
                .iter()
                .any(|(candidate, _, _)| *candidate == offset)
            {
                return Err(ProspectiveSemanticError::new(format!(
                    "reference tail repeats destination frame word {offset}"
                )));
            }
            assignments.push((offset, expected, value));
        }
    }
    for (offset, expected, value) in assignments {
        let value = value.resolve(expected, arena, budget)?;
        state.write_frame(frame, offset, SymbolicValue::Typed(value))?;
    }
    Ok(())
}

fn function_and_block_for_label(
    program: &X64TargetProgram,
    label: X64LabelId,
) -> Result<(&X64Function, &X64Block), ProspectiveSemanticError> {
    let owner = program
        .labels
        .binary_search_by_key(&label, |candidate| candidate.id)
        .ok()
        .map(|index| program.labels[index].owner)
        .ok_or_else(|| {
            ProspectiveSemanticError::new(format!("unknown semantic label {}", label.0))
        })?;
    let X64LabelOwner::Block { function, block } = owner else {
        return Err(ProspectiveSemanticError::new(format!(
            "semantic label {} does not own a block",
            label.0
        )));
    };
    let function = program
        .functions
        .binary_search_by_key(&function, |candidate| candidate.id)
        .ok()
        .map(|index| &program.functions[index])
        .ok_or_else(|| ProspectiveSemanticError::new("semantic label names a missing function"))?;
    let block = function
        .blocks
        .binary_search_by_key(&block, |candidate| candidate.id)
        .ok()
        .map(|index| &function.blocks[index])
        .ok_or_else(|| ProspectiveSemanticError::new("semantic label names a missing block"))?;
    Ok((function, block))
}

fn downstream_ingress<'composition>(
    composition: &'composition X64TargetSharedJoinComposition,
    register_step_index: usize,
    register_step: &X64TargetSharedJoinCompositionStep,
    register_ingress: &X64TargetSharedJoinCompositionIngress,
) -> Result<
    (
        &'composition X64TargetSharedJoinCompositionStep,
        &'composition X64TargetSharedJoinCompositionIngress,
    ),
    ProspectiveSemanticError,
> {
    let mut found = None;
    for step in composition.steps.iter().skip(register_step_index + 1) {
        if !step.ancestors.contains(&register_step.target) {
            continue;
        }
        for ingress in &step.ingresses {
            if ingress.root != register_ingress.root
                || ingress.authority_trigger != register_ingress.authority_trigger
            {
                continue;
            }
            let selected_position = ingress.route.iter().position(|event| {
                *event
                    == X64TargetSharedJoinRouteEvent::Instruction {
                        label: register_step.target,
                        index: 0,
                    }
            });
            let continuation_position = ingress.route.iter().position(|event| {
                *event
                    == X64TargetSharedJoinRouteEvent::Instruction {
                        label: step.target,
                        index: 0,
                    }
            });
            if selected_position
                .zip(continuation_position)
                .is_some_and(|(selected, next)| selected < next)
                && found.replace((step, ingress)).is_some()
            {
                return Err(ProspectiveSemanticError::new(format!(
                    "register target {} has ambiguous downstream semantic routes",
                    register_step.target.0
                )));
            }
        }
    }
    found.ok_or_else(|| {
        ProspectiveSemanticError::new(format!(
            "register target {} has no bounded downstream semantic route",
            register_step.target.0
        ))
    })
}

fn execute_reference_route(
    engine: &mut SemanticEngine<'_>,
    register_step: &X64TargetSharedJoinCompositionStep,
    ingress: &X64TargetSharedJoinCompositionIngress,
    downstream_step: &X64TargetSharedJoinCompositionStep,
    downstream_ingress: &X64TargetSharedJoinCompositionIngress,
    state: &mut SymbolicState,
) -> Result<X64LabelId, ProspectiveSemanticError> {
    if ingress.root != ingress.authority_trigger {
        apply_reference_tail(
            engine.program,
            ingress.root,
            ingress.authority_trigger,
            state,
            engine.frame,
            engine.arena,
            engine.budget,
        )?;
        engine.summary.reference_route_events = engine
            .summary
            .reference_route_events
            .checked_add(1)
            .ok_or_else(|| ProspectiveSemanticError::new("reference route count overflow"))?;
        if engine.summary.reference_route_events > MAX_REFERENCE_ROUTE_EVENTS {
            return Err(ProspectiveSemanticError::new(format!(
                "reference route events exceed {MAX_REFERENCE_ROUTE_EVENTS}"
            )));
        }
    }
    let (_, authority_block) =
        function_and_block_for_label(engine.program, ingress.authority_trigger)?;
    let [authority_instruction] = authority_block.instructions.as_slice() else {
        return Err(ProspectiveSemanticError::new(format!(
            "authority trigger {} is not a one-instruction block",
            ingress.authority_trigger.0
        )));
    };
    execute_reference_instruction(
        authority_instruction,
        state,
        engine.frame,
        engine.arena,
        engine.budget,
    )?;

    let mut saw_selected = false;
    let mut saw_continuation = false;
    for (index, event) in downstream_ingress.route.iter().enumerate() {
        engine.summary.reference_route_events = engine
            .summary
            .reference_route_events
            .checked_add(1)
            .ok_or_else(|| ProspectiveSemanticError::new("reference route count overflow"))?;
        if engine.summary.reference_route_events > MAX_REFERENCE_ROUTE_EVENTS {
            return Err(ProspectiveSemanticError::new(format!(
                "reference route events exceed {MAX_REFERENCE_ROUTE_EVENTS}"
            )));
        }
        engine.budget.charge(1, "reference route traversal")?;
        match *event {
            X64TargetSharedJoinRouteEvent::Tail { source, target } => {
                if saw_continuation {
                    return Err(ProspectiveSemanticError::new(
                        "reference route continues after physical continuation",
                    ));
                }
                if index == 0 && source != ingress.authority_trigger {
                    return Err(ProspectiveSemanticError::new(
                        "reference route does not begin at the authority trigger",
                    ));
                }
                apply_reference_tail(
                    engine.program,
                    source,
                    target,
                    state,
                    engine.frame,
                    engine.arena,
                    engine.budget,
                )?;
            }
            X64TargetSharedJoinRouteEvent::Instruction { label, index } => {
                if index != 0 {
                    return Err(ProspectiveSemanticError::new(
                        "reference route names a nonzero instruction index",
                    ));
                }
                if label == register_step.target && !saw_selected {
                    let (_, block) = function_and_block_for_label(engine.program, label)?;
                    let [instruction] = block.instructions.as_slice() else {
                        return Err(ProspectiveSemanticError::new(
                            "selected register target is not a one-instruction block",
                        ));
                    };
                    execute_reference_instruction(
                        instruction,
                        state,
                        engine.frame,
                        engine.arena,
                        engine.budget,
                    )?;
                    saw_selected = true;
                } else if label == downstream_step.target && saw_selected {
                    saw_continuation = true;
                    break;
                } else {
                    return Err(ProspectiveSemanticError::new(format!(
                        "reference route contains unsupported instruction {}",
                        label.0
                    )));
                }
            }
        }
    }
    if !saw_selected || !saw_continuation {
        return Err(ProspectiveSemanticError::new(format!(
            "reference route for root {} misses selected or continuation instruction",
            ingress.root.0
        )));
    }
    Ok(downstream_step.target)
}

fn validate_shadow_receipts(
    raw: &RawProspectiveSharedJoinRealization,
    shadow: &RawProspectiveShadow,
    budget: &mut SemanticBudget,
) -> Result<(), ProspectiveSemanticError> {
    if !raw.complete || raw.atoms.len() != shadow.atoms.len() || shadow.atoms.is_empty() {
        return Err(ProspectiveSemanticError::new(
            "semantic decoder received incomplete atom receipts",
        ));
    }
    let mut cursor = 0_u32;
    for (index, (receipt, atom)) in raw.atoms.iter().zip(&shadow.atoms).enumerate() {
        budget.charge(1, "semantic atom receipt replay")?;
        if atom.start != cursor
            || atom.end <= atom.start
            || receipt.semantic_event != atom.event
            || receipt.class != atom.class
            || receipt.start != atom.start
            || receipt.end != atom.end
        {
            return Err(ProspectiveSemanticError::new(format!(
                "semantic atom receipt {index} differs from candidate coverage"
            )));
        }
        let owner = shadow
            .labels
            .iter()
            .rev()
            .find(|label| label.code_offset <= atom.start)
            .map(|label| label.id)
            .ok_or_else(|| {
                ProspectiveSemanticError::new(format!(
                    "semantic atom {index} has no physical label owner"
                ))
            })?;
        if owner != receipt.physical_owner {
            return Err(ProspectiveSemanticError::new(format!(
                "semantic atom receipt {index} has the wrong physical owner"
            )));
        }
        cursor = atom.end;
    }
    if usize::try_from(cursor).ok() != Some(shadow.code.len()) {
        return Err(ProspectiveSemanticError::new(
            "semantic atom receipts do not cover candidate code",
        ));
    }
    Ok(())
}

fn unique_atom_index(
    raw: &RawProspectiveSharedJoinRealization,
    mut predicate: impl FnMut(&super::raw::RawProspectiveRealizationAtom) -> bool,
    context: &'static str,
) -> Result<usize, ProspectiveSemanticError> {
    let mut found = None;
    for (index, atom) in raw.atoms.iter().enumerate() {
        if predicate(atom) && found.replace(index).is_some() {
            return Err(ProspectiveSemanticError::new(format!(
                "semantic row repeats {context}"
            )));
        }
    }
    found.ok_or_else(|| ProspectiveSemanticError::new(format!("semantic row misses {context}")))
}

struct RegisterRow<'row> {
    raw: &'row RawProspectiveSharedJoinRealization,
    shadow: &'row RawProspectiveShadow,
    composition: &'row X64TargetSharedJoinComposition,
    step_index: usize,
    step: &'row X64TargetSharedJoinCompositionStep,
    ingress: &'row X64TargetSharedJoinCompositionIngress,
}

fn verify_register_row(
    engine: &mut SemanticEngine<'_>,
    row: RegisterRow<'_>,
    base_state: &SymbolicState,
) -> Result<(), ProspectiveSemanticError> {
    let RegisterRow {
        raw,
        shadow,
        composition,
        step_index,
        step: register_step,
        ingress,
    } = row;
    let (downstream_step, downstream_row) =
        downstream_ingress(composition, step_index, register_step, ingress)?;
    let authority_event = RawExecutionEvent::Instruction {
        label: ingress.authority_trigger,
        index: 0,
    };
    let selected_event = RawExecutionEvent::Instruction {
        label: register_step.target,
        index: 0,
    };
    let tail_event = RawExecutionEvent::Tail {
        label: register_step.target,
    };
    let continuation_event = RawExecutionEvent::Instruction {
        label: downstream_step.target,
        index: 0,
    };
    let authority_index = unique_atom_index(
        raw,
        |atom| {
            atom.physical_owner == ingress.root
                && atom.semantic_event == authority_event
                && atom.class == RawTemplateClass::RegisterInstruction
                && atom.execution_authority
                    == RawProspectiveExecutionAuthority::SemanticEvent(authority_event)
        },
        "authority register atom",
    )?;
    let shared_authority = RawProspectiveExecutionAuthority::SharedJoin {
        target: register_step.target,
        root: ingress.root,
        authority_trigger: ingress.authority_trigger,
        partition: RawProspectiveSharedJoinPartition::All,
    };
    let selected_index = unique_atom_index(
        raw,
        |atom| {
            atom.physical_owner == ingress.root
                && atom.semantic_event == selected_event
                && atom.class == RawTemplateClass::RegisterInstruction
                && atom.execution_authority == shared_authority
        },
        "selected register atom",
    )?;
    let tail_index = unique_atom_index(
        raw,
        |atom| {
            atom.physical_owner == ingress.root
                && atom.semantic_event == tail_event
                && atom.class == RawTemplateClass::TailTransfer
                && atom.execution_authority == shared_authority
        },
        "selected register tail atom",
    )?;
    let continuation_authority = RawProspectiveExecutionAuthority::SharedJoin {
        target: downstream_step.target,
        root: ingress.root,
        authority_trigger: ingress.authority_trigger,
        partition: RawProspectiveSharedJoinPartition::All,
    };
    let continuation_index = unique_atom_index(
        raw,
        |atom| {
            atom.physical_owner == ingress.root
                && atom.semantic_event == continuation_event
                && atom.execution_authority == continuation_authority
        },
        "downstream fallthrough atom",
    )?;
    if selected_index != authority_index + 1
        || tail_index != selected_index + 1
        || continuation_index != tail_index + 1
    {
        return Err(ProspectiveSemanticError::new(format!(
            "register semantic slice at root {} is not contiguous",
            ingress.root.0
        )));
    }

    let mut reference_state = base_state.clone();
    let continuation = execute_reference_route(
        engine,
        register_step,
        ingress,
        downstream_step,
        downstream_row,
        &mut reference_state,
    )?;
    if continuation != downstream_step.target {
        return Err(ProspectiveSemanticError::new(
            "reference route produced a different continuation",
        ));
    }

    let mut machine_state = base_state.clone();
    for index in [authority_index, selected_index, tail_index] {
        let atom = shadow.atoms.get(index).ok_or_else(|| {
            ProspectiveSemanticError::new("semantic slice atom index is out of range")
        })?;
        let control = decode_atom(
            engine,
            &shadow.code,
            atom.start,
            atom.end,
            &mut machine_state,
        )?;
        if control != DecodedControl::Fallthrough {
            return Err(ProspectiveSemanticError::new(format!(
                "register semantic slice at root {} does not fall through",
                ingress.root.0
            )));
        }
    }
    let tail = shadow.atoms[tail_index];
    let continuation_atom = shadow.atoms[continuation_index];
    if tail.end != continuation_atom.start {
        return Err(ProspectiveSemanticError::new(
            "register semantic tail is not adjacent to its continuation",
        ));
    }

    let (continuation_function, continuation_block) =
        function_and_block_for_label(engine.program, continuation)?;
    if continuation_block.id != continuation_function.entry_block {
        return Err(ProspectiveSemanticError::new(
            "semantic continuation is not a function entry",
        ));
    }
    for parameter in &continuation_function.parameters {
        let offsets = home_word_offsets(parameter.home)?;
        let types = home_word_types(parameter.home);
        for (offset, ty) in offsets.into_iter().zip(types) {
            let expected = reference_state.read_frame(engine.frame, offset)?.resolve(
                ty,
                engine.arena,
                engine.budget,
            )?;
            let actual = machine_state.read_frame(engine.frame, offset)?.resolve(
                ty,
                engine.arena,
                engine.budget,
            )?;
            if expected != actual {
                return Err(ProspectiveSemanticError::new(format!(
                    "register semantic mismatch at root {} continuation {} frame word {offset}: reference {:?}, machine {:?}",
                    ingress.root.0,
                    continuation.0,
                    engine.arena.nodes.get(expected as usize),
                    engine.arena.nodes.get(actual as usize)
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn verify_prospective_register_semantics(
    program: &X64TargetProgram,
    raw: &RawProspectiveSharedJoinRealization,
    shadow: &RawProspectiveShadow,
    composition: &X64TargetSharedJoinComposition,
) -> Result<ProspectiveSemanticSummary, ProspectiveSemanticError> {
    let mut budget = SemanticBudget::default();
    validate_shadow_receipts(raw, shadow, &mut budget)?;
    let frame = SemanticFrame::from_program(program, &mut budget)?;
    let mut arena = SymbolicArena::default();
    let base_state = SymbolicState::initial(&frame)?;
    let mut summary = ProspectiveSemanticSummary::default();
    {
        let mut engine = SemanticEngine {
            program,
            frame: &frame,
            arena: &mut arena,
            budget: &mut budget,
            summary: &mut summary,
        };

        for (step_index, step) in composition.steps.iter().enumerate() {
            if step.kind != X64TargetSharedJoinKind::RegisterInstruction {
                continue;
            }
            for ingress in &step.ingresses {
                engine.summary.rows =
                    engine.summary.rows.checked_add(1).ok_or_else(|| {
                        ProspectiveSemanticError::new("semantic row count overflow")
                    })?;
                if engine.summary.rows > MAX_SEMANTIC_ROWS {
                    return Err(ProspectiveSemanticError::new(format!(
                        "semantic rows exceed cap {MAX_SEMANTIC_ROWS}"
                    )));
                }
                verify_register_row(
                    &mut engine,
                    RegisterRow {
                        raw,
                        shadow,
                        composition,
                        step_index,
                        step,
                        ingress,
                    },
                    &base_state,
                )?;
            }
        }
        let symbolic_nodes = u32::try_from(engine.arena.nodes.len())
            .map_err(|_| ProspectiveSemanticError::new("symbolic node total overflow"))?;
        engine.summary.symbolic_nodes = symbolic_nodes;
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_consumes_canonical_forms_and_rejects_truncation_and_trailing_bytes() {
        let canonical = [
            0x48, 0x8b, 0x84, 0x24, 0x70, 0, 0, 0, 0x48, 0xb9, 1, 0, 0, 0, 0, 0, 0, 0, 0x48, 0x01,
            0xc8, 0x49, 0x89, 0xc0,
        ];
        let mut decoder = ByteDecoder::new(&canonical, 0);
        let mut instructions = Vec::new();
        while decoder.cursor < canonical.len() {
            instructions.push(decoder.decode_next().expect("canonical decoder form"));
        }
        assert_eq!(instructions.len(), 4);

        let mut truncated = ByteDecoder::new(&canonical[..canonical.len() - 1], 0);
        assert!(truncated.decode_next().is_ok());
        assert!(truncated.decode_next().is_ok());
        assert!(truncated.decode_next().is_ok());
        assert!(truncated.decode_next().is_err());

        let mut with_trailing = canonical.to_vec();
        with_trailing.push(0x90);
        let mut decoder = ByteDecoder::new(&with_trailing, 0);
        for _ in 0..4 {
            decoder.decode_next().expect("canonical prefix");
        }
        assert!(decoder.decode_next().is_err());
    }

    #[test]
    fn semantic_limits_and_delayed_type_checks_fail_closed() {
        let mut exhausted = SemanticBudget {
            work: MAX_SEMANTIC_WORK,
        };
        assert!(exhausted.charge(1, "one-over test").is_err());

        let mut overflowed = SemanticBudget { work: u64::MAX };
        assert!(overflowed.charge(1, "overflow test").is_err());

        let mut arena = SymbolicArena::default();
        let mut budget = SemanticBudget::default();
        let mistyped = SymbolicValue::Immediate {
            bits: 0,
            declared: Some(WordType::F64),
        };
        assert!(mistyped
            .resolve(WordType::I64, &mut arena, &mut budget)
            .is_err());
        assert!(arena.nodes.is_empty());
    }
}
