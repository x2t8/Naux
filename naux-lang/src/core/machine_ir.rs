//! Canonical target-independent Machine IR trust boundary for R1-S6.
//!
//! This module is deliberately separate from `vm::ir`, `vm::ssa`, the trace
//! JIT, and every target encoder. It consumes only verified canonical Core
//! SSA, lowers a closed P1V0 envelope deterministically, and gives the result
//! its own verifier, evaluator, provenance chain, resource limits, and
//! semantic identity. R1-S6 is not a native-code or performance claim.

use super::core_ssa::{
    verify_core_ssa, verify_core_ssa_source, CoreSsaArtifact, CoreSsaSourceError,
    CoreSsaVerificationErrors, SourceBoundCoreSsaArtifact, SsaInstructionKind, SsaOperand,
    SsaTerminator,
};
use super::encoding::{canonical_f64_bits, sha256};
use super::interpret::{CoreValue, EffectEvent, Evaluation, EvaluationBudget, EvaluationOutcome};
use super::schema::{
    CoreArtifact, Effect, EffectRow, ErrorKind, Mutability, NumericMode, Primitive, RegionId,
    SemanticHash, Type,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

pub const MACHINE_IR_SCHEMA_NAME: &str = "naux-machine-ir";
pub const MACHINE_IR_SCHEMA_VERSION: (u16, u16, u16) = (0, 1, 0);
pub const MACHINE_IR_LOWERING_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);

pub const MACHINE_IR_MAX_FUNCTIONS: u64 = 16_384;
pub const MACHINE_IR_MAX_BLOCKS: u64 = 1_000_000;
pub const MACHINE_IR_MAX_INSTRUCTIONS: u64 = 1_000_000;
pub const MACHINE_IR_MAX_REGISTERS: u64 = 1_000_000;
pub const MACHINE_IR_MAX_EDGES: u64 = 1_000_000;
pub const MACHINE_IR_MAX_OPERANDS: u64 = 4_000_000;
pub const MACHINE_IR_MAX_LOWERING_WORK: u64 = 8_000_000;
pub const MACHINE_IR_MAX_SEMANTIC_BYTES: u64 = 64 * 1024 * 1024;
pub const MACHINE_IR_MAX_LIVE_REGISTER_SLOTS: u64 = 1_000_000;
pub const MACHINE_IR_MAX_EXECUTION_STEPS: u64 = 100_000_000;
pub const MACHINE_IR_MAX_CALL_DEPTH: u32 = 256;
pub const MACHINE_IR_MAX_CFG_DEPTH: u32 = 512;
pub const MACHINE_IR_MAX_DIAGNOSTICS: usize = 256;

const MACHINE_IR_SEMANTIC_DOMAIN: &[u8] = b"NAUX:machine-ir:r1-s6:semantic:v1\0";
const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineIrSchemaVersion {
    pub name: String,
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl MachineIrSchemaVersion {
    pub fn r1_s6() -> Self {
        Self {
            name: MACHINE_IR_SCHEMA_NAME.to_owned(),
            major: MACHINE_IR_SCHEMA_VERSION.0,
            minor: MACHINE_IR_SCHEMA_VERSION.1,
            patch: MACHINE_IR_SCHEMA_VERSION.2,
        }
    }
}

/// Limits are part of the semantic envelope. A producer cannot silently
/// widen them while retaining the R1-S6 schema or policy identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MachineIrLimits {
    pub max_functions: u64,
    pub max_blocks: u64,
    pub max_instructions: u64,
    pub max_registers: u64,
    pub max_edges: u64,
    pub max_operands: u64,
    pub max_lowering_work: u64,
    pub max_semantic_bytes: u64,
    pub max_live_register_slots: u64,
    pub max_execution_steps: u64,
    pub max_call_depth: u32,
    pub max_cfg_depth: u32,
    pub max_diagnostics: u32,
}

impl MachineIrLimits {
    pub const fn r1_s6() -> Self {
        Self {
            max_functions: MACHINE_IR_MAX_FUNCTIONS,
            max_blocks: MACHINE_IR_MAX_BLOCKS,
            max_instructions: MACHINE_IR_MAX_INSTRUCTIONS,
            max_registers: MACHINE_IR_MAX_REGISTERS,
            max_edges: MACHINE_IR_MAX_EDGES,
            max_operands: MACHINE_IR_MAX_OPERANDS,
            max_lowering_work: MACHINE_IR_MAX_LOWERING_WORK,
            max_semantic_bytes: MACHINE_IR_MAX_SEMANTIC_BYTES,
            max_live_register_slots: MACHINE_IR_MAX_LIVE_REGISTER_SLOTS,
            max_execution_steps: MACHINE_IR_MAX_EXECUTION_STEPS,
            max_call_depth: MACHINE_IR_MAX_CALL_DEPTH,
            max_cfg_depth: MACHINE_IR_MAX_CFG_DEPTH,
            max_diagnostics: MACHINE_IR_MAX_DIAGNOSTICS as u32,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MachineFunctionId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MachineBlockId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtualRegister(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MachineType {
    Unit,
    Bool,
    I64,
    F64,
    /// An immutable, logically bounded F64 sequence. Physical layout and ABI
    /// are target-lowering concerns and are not encoded in R1-S6 identity.
    F64Array,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MachineEffect {
    Bounds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineIntegerMode {
    Wrapping,
    Saturating,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineI64BinaryOp {
    Add,
    Sub,
    Mul,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineF64BinaryOp {
    Add,
    Sub,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineI64CompareOp {
    LessThan,
    GreaterOrEqual,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineIrArtifact {
    pub program: MachineIrProgram,
    pub semantic_hash: SemanticHash,
}

impl MachineIrArtifact {
    pub fn seal(program: MachineIrProgram) -> Result<Self, MachineIrEncodeError> {
        let semantic_hash = machine_ir_semantic_hash(&program)?;
        Ok(Self {
            program,
            semantic_hash,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineIrProgram {
    pub schema: MachineIrSchemaVersion,
    pub lowering_policy_version: (u16, u16, u16),
    pub limits: MachineIrLimits,
    pub source_core_hash: SemanticHash,
    pub source_ssa_hash: SemanticHash,
    pub entry: MachineFunctionId,
    pub functions: Vec<MachineFunction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineFunction {
    pub id: MachineFunctionId,
    pub parameters: Vec<MachineParameter>,
    pub effects: Vec<MachineEffect>,
    pub result: MachineType,
    pub entry_block: MachineBlockId,
    pub blocks: Vec<MachineBlock>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineParameter {
    pub register: VirtualRegister,
    pub ty: MachineType,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineBlock {
    pub id: MachineBlockId,
    pub instructions: Vec<MachineInstruction>,
    pub terminator: MachineTerminator,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineInstruction {
    pub result: VirtualRegister,
    pub ty: MachineType,
    pub kind: MachineInstructionKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MachineInstructionKind {
    Move(MachineOperand),
    I64Binary {
        operation: MachineI64BinaryOp,
        mode: MachineIntegerMode,
        left: MachineOperand,
        right: MachineOperand,
    },
    F64Binary {
        operation: MachineF64BinaryOp,
        left: MachineOperand,
        right: MachineOperand,
    },
    I64Compare {
        operation: MachineI64CompareOp,
        left: MachineOperand,
        right: MachineOperand,
    },
    ArrayLenF64 {
        array: MachineOperand,
    },
    ArrayGetF64Checked {
        array: MachineOperand,
        index: MachineOperand,
    },
    Call {
        function: MachineFunctionId,
        arguments: Vec<MachineOperand>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MachineOperand {
    Unit,
    Bool(bool),
    I64(i64),
    /// Canonical IEEE-754 identity. Signed zero is retained and every NaN is
    /// normalized to `0x7ff8_0000_0000_0000`.
    F64Bits(u64),
    Register(VirtualRegister),
}

impl MachineOperand {
    pub fn f64(value: f64) -> Self {
        Self::F64Bits(canonical_f64_bits(value))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MachineTerminator {
    Return(MachineOperand),
    Branch {
        condition: MachineOperand,
        then_block: MachineBlockId,
        else_block: MachineBlockId,
    },
    TailCall {
        function: MachineFunctionId,
        arguments: Vec<MachineOperand>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MachineIrEncodeError {
    LengthOverflow { field: &'static str, length: usize },
    ByteLimit { limit: u64, actual: u64 },
}

impl fmt::Display for MachineIrEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOverflow { field, length } => {
                write!(formatter, "{field} length {length} exceeds u32")
            }
            Self::ByteLimit { limit, actual } => write!(
                formatter,
                "Machine IR semantic encoding uses {actual} bytes; limit is {limit}"
            ),
        }
    }
}

impl std::error::Error for MachineIrEncodeError {}

#[derive(Default)]
struct MachineEncoder {
    bytes: Vec<u8>,
    attempted_bytes: u64,
}

impl MachineEncoder {
    fn append(&mut self, bytes: &[u8]) {
        self.attempted_bytes = self.attempted_bytes.saturating_add(bytes.len() as u64);
        if self.attempted_bytes <= MACHINE_IR_MAX_SEMANTIC_BYTES {
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

    fn u64(&mut self, value: u64) {
        self.append(&value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.append(&value.to_be_bytes());
    }

    fn length(&mut self, field: &'static str, length: usize) -> Result<(), MachineIrEncodeError> {
        let length = u32::try_from(length)
            .map_err(|_| MachineIrEncodeError::LengthOverflow { field, length })?;
        self.u32(length);
        Ok(())
    }

    fn string(&mut self, field: &'static str, value: &str) -> Result<(), MachineIrEncodeError> {
        self.length(field, value.len())?;
        self.append(value.as_bytes());
        Ok(())
    }
}

pub fn machine_ir_semantic_bytes(
    program: &MachineIrProgram,
) -> Result<Vec<u8>, MachineIrEncodeError> {
    let mut encoder = MachineEncoder::default();
    encoder.append(MACHINE_IR_SEMANTIC_DOMAIN);
    encoder.string("schema.name", &program.schema.name)?;
    encoder.u16(program.schema.major);
    encoder.u16(program.schema.minor);
    encoder.u16(program.schema.patch);
    encoder.u16(program.lowering_policy_version.0);
    encoder.u16(program.lowering_policy_version.1);
    encoder.u16(program.lowering_policy_version.2);
    encode_limits(&mut encoder, program.limits);
    encoder.append(&program.source_core_hash.0);
    encoder.append(&program.source_ssa_hash.0);
    encoder.u32(program.entry.0);
    encoder.length("program.functions", program.functions.len())?;
    for function in &program.functions {
        encode_function(&mut encoder, function)?;
    }
    if encoder.attempted_bytes > MACHINE_IR_MAX_SEMANTIC_BYTES {
        return Err(MachineIrEncodeError::ByteLimit {
            limit: MACHINE_IR_MAX_SEMANTIC_BYTES,
            actual: encoder.attempted_bytes,
        });
    }
    Ok(encoder.bytes)
}

pub fn machine_ir_semantic_hash(
    program: &MachineIrProgram,
) -> Result<SemanticHash, MachineIrEncodeError> {
    Ok(SemanticHash(sha256(&machine_ir_semantic_bytes(program)?)))
}

fn encode_limits(encoder: &mut MachineEncoder, limits: MachineIrLimits) {
    encoder.u64(limits.max_functions);
    encoder.u64(limits.max_blocks);
    encoder.u64(limits.max_instructions);
    encoder.u64(limits.max_registers);
    encoder.u64(limits.max_edges);
    encoder.u64(limits.max_operands);
    encoder.u64(limits.max_lowering_work);
    encoder.u64(limits.max_semantic_bytes);
    encoder.u64(limits.max_live_register_slots);
    encoder.u64(limits.max_execution_steps);
    encoder.u32(limits.max_call_depth);
    encoder.u32(limits.max_cfg_depth);
    encoder.u32(limits.max_diagnostics);
}

fn encode_function(
    encoder: &mut MachineEncoder,
    function: &MachineFunction,
) -> Result<(), MachineIrEncodeError> {
    encoder.u32(function.id.0);
    encoder.length("function.parameters", function.parameters.len())?;
    for parameter in &function.parameters {
        encoder.u32(parameter.register.0);
        encode_type(encoder, parameter.ty);
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
        encoder.length("block.instructions", block.instructions.len())?;
        for instruction in &block.instructions {
            encoder.u32(instruction.result.0);
            encode_type(encoder, instruction.ty);
            encode_instruction(encoder, &instruction.kind)?;
        }
        encode_terminator(encoder, &block.terminator)?;
    }
    Ok(())
}

fn encode_type(encoder: &mut MachineEncoder, ty: MachineType) {
    encoder.tag(match ty {
        MachineType::Unit => 0,
        MachineType::Bool => 1,
        MachineType::I64 => 2,
        MachineType::F64 => 3,
        MachineType::F64Array => 4,
    });
}

fn encode_effect(encoder: &mut MachineEncoder, effect: MachineEffect) {
    encoder.tag(match effect {
        MachineEffect::Bounds => 0,
    });
}

fn encode_operand(encoder: &mut MachineEncoder, operand: &MachineOperand) {
    match operand {
        MachineOperand::Unit => encoder.tag(0),
        MachineOperand::Bool(value) => {
            encoder.tag(1);
            encoder.tag(u8::from(*value));
        }
        MachineOperand::I64(value) => {
            encoder.tag(2);
            encoder.i64(*value);
        }
        MachineOperand::F64Bits(bits) => {
            encoder.tag(3);
            encoder.u64(*bits);
        }
        MachineOperand::Register(register) => {
            encoder.tag(4);
            encoder.u32(register.0);
        }
    }
}

fn encode_instruction(
    encoder: &mut MachineEncoder,
    instruction: &MachineInstructionKind,
) -> Result<(), MachineIrEncodeError> {
    match instruction {
        MachineInstructionKind::Move(operand) => {
            encoder.tag(0);
            encode_operand(encoder, operand);
        }
        MachineInstructionKind::I64Binary {
            operation,
            mode,
            left,
            right,
        } => {
            encoder.tag(1);
            encoder.tag(match operation {
                MachineI64BinaryOp::Add => 0,
                MachineI64BinaryOp::Sub => 1,
                MachineI64BinaryOp::Mul => 2,
            });
            encoder.tag(match mode {
                MachineIntegerMode::Wrapping => 0,
                MachineIntegerMode::Saturating => 1,
            });
            encode_operand(encoder, left);
            encode_operand(encoder, right);
        }
        MachineInstructionKind::F64Binary {
            operation,
            left,
            right,
        } => {
            encoder.tag(2);
            encoder.tag(match operation {
                MachineF64BinaryOp::Add => 0,
                MachineF64BinaryOp::Sub => 1,
            });
            encode_operand(encoder, left);
            encode_operand(encoder, right);
        }
        MachineInstructionKind::I64Compare {
            operation,
            left,
            right,
        } => {
            encoder.tag(3);
            encoder.tag(match operation {
                MachineI64CompareOp::LessThan => 0,
                MachineI64CompareOp::GreaterOrEqual => 1,
            });
            encode_operand(encoder, left);
            encode_operand(encoder, right);
        }
        MachineInstructionKind::ArrayLenF64 { array } => {
            encoder.tag(4);
            encode_operand(encoder, array);
        }
        MachineInstructionKind::ArrayGetF64Checked { array, index } => {
            encoder.tag(5);
            encode_operand(encoder, array);
            encode_operand(encoder, index);
        }
        MachineInstructionKind::Call {
            function,
            arguments,
        } => {
            encoder.tag(6);
            encoder.u32(function.0);
            encode_operands(encoder, arguments)?;
        }
    }
    Ok(())
}

fn encode_terminator(
    encoder: &mut MachineEncoder,
    terminator: &MachineTerminator,
) -> Result<(), MachineIrEncodeError> {
    match terminator {
        MachineTerminator::Return(operand) => {
            encoder.tag(0);
            encode_operand(encoder, operand);
        }
        MachineTerminator::Branch {
            condition,
            then_block,
            else_block,
        } => {
            encoder.tag(1);
            encode_operand(encoder, condition);
            encoder.u32(then_block.0);
            encoder.u32(else_block.0);
        }
        MachineTerminator::TailCall {
            function,
            arguments,
        } => {
            encoder.tag(2);
            encoder.u32(function.0);
            encode_operands(encoder, arguments)?;
        }
    }
    Ok(())
}

fn encode_operands(
    encoder: &mut MachineEncoder,
    operands: &[MachineOperand],
) -> Result<(), MachineIrEncodeError> {
    encoder.length("operands", operands.len())?;
    for operand in operands {
        encode_operand(encoder, operand);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MachineIrLowerError {
    InvalidSourceBinding(CoreSsaSourceError),
    InvalidSource(CoreSsaVerificationErrors),
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
    Encoding(MachineIrEncodeError),
    InvalidOutput(MachineIrVerificationErrors),
}

impl fmt::Display for MachineIrLowerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSourceBinding(error) => write!(formatter, "{error}"),
            Self::InvalidSource(errors) => write!(formatter, "{errors}"),
            Self::UnsupportedSource { path, message } => {
                write!(formatter, "unsupported R1-S6 Core SSA at {path}: {message}")
            }
            Self::StructuralLimit {
                field,
                limit,
                actual,
            } => write!(
                formatter,
                "Machine IR lowering {field} usage {actual} exceeds hard limit {limit}"
            ),
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "Machine IR lowering {field} accounting overflow")
            }
            Self::Encoding(error) => write!(formatter, "{error}"),
            Self::InvalidOutput(errors) => {
                write!(formatter, "lowerer produced invalid Machine IR: {errors}")
            }
        }
    }
}

impl std::error::Error for MachineIrLowerError {}

impl From<MachineIrEncodeError> for MachineIrLowerError {
    fn from(error: MachineIrEncodeError) -> Self {
        Self::Encoding(error)
    }
}

/// Deterministically lower an exact source-bound R1-S5 Core SSA envelope.
///
/// No unsupported node, fallback path, target ABI, physical register, or
/// target opcode can enter this artifact.
pub fn lower_machine_ir_r1_s6(
    source_ssa: &CoreSsaArtifact,
    source_core: &CoreArtifact,
) -> Result<MachineIrArtifact, MachineIrLowerError> {
    let source = verify_core_ssa_source(source_ssa, source_core)
        .map_err(MachineIrLowerError::InvalidSourceBinding)?;
    lower_machine_ir_from_ssa_r1_s6(source.artifact())
}

/// Internal replay primitive. Public callers must enter through the
/// Core-bound wrapper above so an arbitrary `source_core_hash` cannot acquire
/// translation authority.
fn lower_machine_ir_from_ssa_r1_s6(
    source: &CoreSsaArtifact,
) -> Result<MachineIrArtifact, MachineIrLowerError> {
    verify_core_ssa(source).map_err(MachineIrLowerError::InvalidSource)?;
    preflight_lowering_work(source)?;

    let functions = source
        .program
        .functions
        .iter()
        .enumerate()
        .map(|(index, function)| lower_function(function, index))
        .collect::<Result<Vec<_>, _>>()?;
    let artifact = MachineIrArtifact::seal(MachineIrProgram {
        schema: MachineIrSchemaVersion::r1_s6(),
        lowering_policy_version: MACHINE_IR_LOWERING_POLICY_VERSION,
        limits: MachineIrLimits::r1_s6(),
        source_core_hash: source.program.source_core_hash,
        source_ssa_hash: source.semantic_hash,
        entry: MachineFunctionId(source.program.entry.0),
        functions,
    })?;
    verify_machine_ir(&artifact).map_err(MachineIrLowerError::InvalidOutput)?;
    Ok(artifact)
}

fn preflight_lowering_work(source: &CoreSsaArtifact) -> Result<(), MachineIrLowerError> {
    let mut work = source.program.functions.len() as u64;
    for function in &source.program.functions {
        work = work
            .checked_add(function.parameters.len() as u64)
            .and_then(|value| value.checked_add(function.effects.effects.len() as u64))
            .and_then(|value| value.checked_add(function.blocks.len() as u64))
            .ok_or(MachineIrLowerError::ArithmeticOverflow {
                field: "work units",
            })?;
        for block in &function.blocks {
            work = work
                .checked_add(block.instructions.len() as u64)
                .and_then(|value| {
                    value.checked_add(machine_ssa_terminator_operand_count(&block.terminator))
                })
                .ok_or(MachineIrLowerError::ArithmeticOverflow {
                    field: "work units",
                })?;
            for instruction in &block.instructions {
                work = work
                    .checked_add(machine_ssa_instruction_operand_count(&instruction.kind))
                    .ok_or(MachineIrLowerError::ArithmeticOverflow {
                        field: "work units",
                    })?;
            }
        }
    }
    if work > MACHINE_IR_MAX_LOWERING_WORK {
        return Err(MachineIrLowerError::StructuralLimit {
            field: "work units",
            limit: MACHINE_IR_MAX_LOWERING_WORK,
            actual: work,
        });
    }
    Ok(())
}

fn machine_ssa_instruction_operand_count(kind: &SsaInstructionKind) -> u64 {
    match kind {
        SsaInstructionKind::Copy(_) => 1,
        SsaInstructionKind::Primitive { arguments, .. }
        | SsaInstructionKind::Call { arguments, .. } => arguments.len() as u64,
    }
}

fn machine_ssa_terminator_operand_count(terminator: &SsaTerminator) -> u64 {
    match terminator {
        SsaTerminator::Return(_) | SsaTerminator::Branch { .. } => 1,
        SsaTerminator::TailCall { arguments, .. } => arguments.len() as u64,
    }
}

fn lower_function(
    function: &super::core_ssa::SsaFunction,
    index: usize,
) -> Result<MachineFunction, MachineIrLowerError> {
    let path = format!("program.functions[{index}]");
    let parameters = function
        .parameters
        .iter()
        .enumerate()
        .map(|(parameter_index, parameter)| {
            Ok(MachineParameter {
                register: VirtualRegister(parameter.value.0),
                ty: lower_type(
                    &parameter.ty,
                    &format!("{path}.parameters[{parameter_index}].type"),
                )?,
            })
        })
        .collect::<Result<Vec<_>, MachineIrLowerError>>()?;
    let effects = lower_effects(&function.effects, &format!("{path}.effects"))?;
    let result = lower_type(&function.result, &format!("{path}.result"))?;
    let blocks = function
        .blocks
        .iter()
        .enumerate()
        .map(|(block_index, block)| {
            let block_path = format!("{path}.blocks[{block_index}]");
            Ok(MachineBlock {
                id: MachineBlockId(block.id.0),
                instructions: block
                    .instructions
                    .iter()
                    .enumerate()
                    .map(|(instruction_index, instruction)| {
                        let instruction_path =
                            format!("{block_path}.instructions[{instruction_index}]");
                        Ok(MachineInstruction {
                            result: VirtualRegister(instruction.result.0),
                            ty: lower_type(&instruction.ty, &format!("{instruction_path}.type"))?,
                            kind: lower_instruction(
                                &instruction.kind,
                                &format!("{instruction_path}.kind"),
                            )?,
                        })
                    })
                    .collect::<Result<Vec<_>, MachineIrLowerError>>()?,
                terminator: lower_terminator(
                    &block.terminator,
                    &format!("{block_path}.terminator"),
                )?,
            })
        })
        .collect::<Result<Vec<_>, MachineIrLowerError>>()?;
    Ok(MachineFunction {
        id: MachineFunctionId(function.id.0),
        parameters,
        effects,
        result,
        entry_block: MachineBlockId(function.entry_block.0),
        blocks,
    })
}

fn lower_type(ty: &Type, path: &str) -> Result<MachineType, MachineIrLowerError> {
    match ty {
        Type::Unit => Ok(MachineType::Unit),
        Type::Bool => Ok(MachineType::Bool),
        Type::I64 => Ok(MachineType::I64),
        Type::F64 => Ok(MachineType::F64),
        Type::Array {
            region: RegionId(0),
            mutability: Mutability::Read,
            element,
        } if element.as_ref() == &Type::F64 => Ok(MachineType::F64Array),
        _ => Err(unsupported_source(
            path,
            format!("type {ty:?} is outside the closed R1-S6 envelope"),
        )),
    }
}

fn lower_effects(
    effects: &EffectRow,
    path: &str,
) -> Result<Vec<MachineEffect>, MachineIrLowerError> {
    effects
        .effects
        .iter()
        .enumerate()
        .map(|(index, effect)| match effect {
            Effect::Error(ErrorKind::Bounds) => Ok(MachineEffect::Bounds),
            _ => Err(unsupported_source(
                format!("{path}[{index}]"),
                format!("effect {effect:?} is outside the closed R1-S6 envelope"),
            )),
        })
        .collect()
}

fn lower_instruction(
    kind: &SsaInstructionKind,
    path: &str,
) -> Result<MachineInstructionKind, MachineIrLowerError> {
    match kind {
        SsaInstructionKind::Copy(operand) => {
            Ok(MachineInstructionKind::Move(lower_operand(operand)))
        }
        SsaInstructionKind::Primitive {
            operation,
            arguments,
        } => lower_primitive(operation, arguments, path),
        SsaInstructionKind::Call {
            function,
            arguments,
        } => Ok(MachineInstructionKind::Call {
            function: MachineFunctionId(function.0),
            arguments: arguments.iter().map(lower_operand).collect(),
        }),
    }
}

fn lower_primitive(
    primitive: &Primitive,
    arguments: &[SsaOperand],
    path: &str,
) -> Result<MachineInstructionKind, MachineIrLowerError> {
    let binary = |arguments: &[SsaOperand]| -> Result<(MachineOperand, MachineOperand), MachineIrLowerError> {
        let [left, right] = arguments else {
            return Err(unsupported_source(
                format!("{path}.arguments"),
                format!("binary operation has {} arguments", arguments.len()),
            ));
        };
        Ok((lower_operand(left), lower_operand(right)))
    };
    match primitive {
        Primitive::I64Add(mode) | Primitive::I64Sub(mode) | Primitive::I64Mul(mode) => {
            let (left, right) = binary(arguments)?;
            let operation = match primitive {
                Primitive::I64Add(_) => MachineI64BinaryOp::Add,
                Primitive::I64Sub(_) => MachineI64BinaryOp::Sub,
                Primitive::I64Mul(_) => MachineI64BinaryOp::Mul,
                _ => unreachable!(),
            };
            let mode = match mode {
                NumericMode::Wrapping => MachineIntegerMode::Wrapping,
                NumericMode::Saturating => MachineIntegerMode::Saturating,
                NumericMode::Checked => {
                    return Err(unsupported_source(
                        format!("{path}.operation"),
                        "Checked I64 has no R1-S6 Machine IR opcode",
                    ));
                }
            };
            Ok(MachineInstructionKind::I64Binary {
                operation,
                mode,
                left,
                right,
            })
        }
        Primitive::F64Add | Primitive::F64Sub => {
            let (left, right) = binary(arguments)?;
            Ok(MachineInstructionKind::F64Binary {
                operation: if matches!(primitive, Primitive::F64Add) {
                    MachineF64BinaryOp::Add
                } else {
                    MachineF64BinaryOp::Sub
                },
                left,
                right,
            })
        }
        Primitive::I64CmpLt | Primitive::I64CmpGe => {
            let (left, right) = binary(arguments)?;
            Ok(MachineInstructionKind::I64Compare {
                operation: if matches!(primitive, Primitive::I64CmpLt) {
                    MachineI64CompareOp::LessThan
                } else {
                    MachineI64CompareOp::GreaterOrEqual
                },
                left,
                right,
            })
        }
        Primitive::ArrayLenF64 => {
            let [array] = arguments else {
                return Err(unsupported_source(
                    format!("{path}.arguments"),
                    format!("ArrayLenF64 has {} arguments", arguments.len()),
                ));
            };
            Ok(MachineInstructionKind::ArrayLenF64 {
                array: lower_operand(array),
            })
        }
        Primitive::ArrayGetF64 => {
            let [array, index] = arguments else {
                return Err(unsupported_source(
                    format!("{path}.arguments"),
                    format!("ArrayGetF64 has {} arguments", arguments.len()),
                ));
            };
            Ok(MachineInstructionKind::ArrayGetF64Checked {
                array: lower_operand(array),
                index: lower_operand(index),
            })
        }
    }
}

fn lower_operand(operand: &SsaOperand) -> MachineOperand {
    match operand {
        SsaOperand::Unit => MachineOperand::Unit,
        SsaOperand::Bool(value) => MachineOperand::Bool(*value),
        SsaOperand::I64(value) => MachineOperand::I64(*value),
        SsaOperand::F64Bits(bits) => MachineOperand::F64Bits(*bits),
        SsaOperand::Value(value) => MachineOperand::Register(VirtualRegister(value.0)),
    }
}

fn lower_terminator(
    terminator: &SsaTerminator,
    _path: &str,
) -> Result<MachineTerminator, MachineIrLowerError> {
    Ok(match terminator {
        SsaTerminator::Return(operand) => MachineTerminator::Return(lower_operand(operand)),
        SsaTerminator::Branch {
            condition,
            then_block,
            else_block,
        } => MachineTerminator::Branch {
            condition: lower_operand(condition),
            then_block: MachineBlockId(then_block.0),
            else_block: MachineBlockId(else_block.0),
        },
        SsaTerminator::TailCall {
            function,
            arguments,
        } => MachineTerminator::TailCall {
            function: MachineFunctionId(function.0),
            arguments: arguments.iter().map(lower_operand).collect(),
        },
    })
}

fn unsupported_source(path: impl Into<String>, message: impl Into<String>) -> MachineIrLowerError {
    MachineIrLowerError::UnsupportedSource {
        path: path.into(),
        message: message.into(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineIrVerificationCode {
    InvalidSchema,
    InvalidPolicy,
    InvalidLimits,
    InvalidSourceProvenance,
    SemanticHashMismatch,
    EncodingFailure,
    NonCanonicalOrder,
    DuplicateId,
    MissingEntry,
    UnboundRegister,
    TypeMismatch,
    InvalidCall,
    InvalidControlFlow,
    MissingEffect,
    StructuralLimit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineIrVerificationError {
    pub code: MachineIrVerificationCode,
    pub path: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineIrVerificationErrors(pub Vec<MachineIrVerificationError>);

impl fmt::Display for MachineIrVerificationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} canonical Machine IR verification error(s)",
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

impl std::error::Error for MachineIrVerificationErrors {}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedMachineIrArtifact<'artifact> {
    artifact: &'artifact MachineIrArtifact,
}

impl<'artifact> VerifiedMachineIrArtifact<'artifact> {
    pub fn artifact(self) -> &'artifact MachineIrArtifact {
        self.artifact
    }

    pub fn program(self) -> &'artifact MachineIrProgram {
        &self.artifact.program
    }

    pub fn semantic_hash(self) -> SemanticHash {
        self.artifact.semantic_hash
    }

    pub fn source_ssa_hash(self) -> SemanticHash {
        self.artifact.program.source_ssa_hash
    }

    pub fn source_core_hash(self) -> SemanticHash {
        self.artifact.program.source_core_hash
    }
}

/// Structurally verify a standalone Machine IR artifact.
///
/// This proves only R1-S6-local well-formedness. Translation authority for a
/// claimed Core/SSA source pair requires `verify_machine_ir_source`.
pub fn verify_machine_ir(
    artifact: &MachineIrArtifact,
) -> Result<VerifiedMachineIrArtifact<'_>, MachineIrVerificationErrors> {
    let mut verifier = MachineIrVerifier::new(&artifact.program);
    verifier.verify_envelope_metadata();
    let metadata_valid = verifier.errors.is_empty();
    let structure_within_limits = verifier.preflight_counts();
    if metadata_valid && structure_within_limits {
        verifier.verify_semantic_identity(artifact);
        verifier.verify_program();
    }
    if verifier.errors.is_empty() {
        Ok(VerifiedMachineIrArtifact { artifact })
    } else {
        Err(MachineIrVerificationErrors(verifier.errors))
    }
}

#[derive(Clone, Debug)]
struct MachineCallSignature {
    parameters: Arc<[MachineType]>,
    effects: Arc<[MachineEffect]>,
    result: MachineType,
}

struct MachineIrVerifier<'program> {
    program: &'program MachineIrProgram,
    functions: BTreeMap<MachineFunctionId, &'program MachineFunction>,
    signatures: BTreeMap<MachineFunctionId, MachineCallSignature>,
    errors: Vec<MachineIrVerificationError>,
    total_blocks: u64,
    total_instructions: u64,
    total_registers: u64,
    total_edges: u64,
    total_operands: u64,
    total_work: u64,
}

impl<'program> MachineIrVerifier<'program> {
    fn new(program: &'program MachineIrProgram) -> Self {
        Self {
            program,
            functions: BTreeMap::new(),
            signatures: BTreeMap::new(),
            errors: Vec::new(),
            total_blocks: 0,
            total_instructions: 0,
            total_registers: 0,
            total_edges: 0,
            total_operands: 0,
            total_work: 0,
        }
    }

    fn error(
        &mut self,
        code: MachineIrVerificationCode,
        path: impl Into<String>,
        message: impl Into<String>,
    ) {
        if self.errors.len() + 1 < MACHINE_IR_MAX_DIAGNOSTICS {
            self.errors.push(MachineIrVerificationError {
                code,
                path: path.into(),
                message: message.into(),
            });
        } else if self.errors.len() < MACHINE_IR_MAX_DIAGNOSTICS {
            self.errors.push(MachineIrVerificationError {
                code: MachineIrVerificationCode::StructuralLimit,
                path: "program".to_owned(),
                message: format!("verification diagnostics capped at {MACHINE_IR_MAX_DIAGNOSTICS}"),
            });
        }
    }

    fn diagnostics_full(&self) -> bool {
        self.errors.len() >= MACHINE_IR_MAX_DIAGNOSTICS
    }

    fn verify_envelope_metadata(&mut self) {
        let schema = &self.program.schema;
        if schema.name != MACHINE_IR_SCHEMA_NAME
            || (schema.major, schema.minor, schema.patch) != MACHINE_IR_SCHEMA_VERSION
        {
            self.error(
                MachineIrVerificationCode::InvalidSchema,
                "program.schema",
                format!(
                    "expected {MACHINE_IR_SCHEMA_NAME} {}.{}.{}; found name length {} and version {}.{}.{}",
                    MACHINE_IR_SCHEMA_VERSION.0,
                    MACHINE_IR_SCHEMA_VERSION.1,
                    MACHINE_IR_SCHEMA_VERSION.2,
                    schema.name.len(),
                    schema.major,
                    schema.minor,
                    schema.patch
                ),
            );
        }
        if self.program.lowering_policy_version != MACHINE_IR_LOWERING_POLICY_VERSION {
            self.error(
                MachineIrVerificationCode::InvalidPolicy,
                "program.lowering_policy_version",
                format!(
                    "expected {:?}; found {:?}",
                    MACHINE_IR_LOWERING_POLICY_VERSION, self.program.lowering_policy_version
                ),
            );
        }
        if self.program.limits != MachineIrLimits::r1_s6() {
            self.error(
                MachineIrVerificationCode::InvalidLimits,
                "program.limits",
                "R1-S6 limits must equal the canonical hard-limit vector",
            );
        }
        if self.program.source_core_hash == SemanticHash::ZERO {
            self.error(
                MachineIrVerificationCode::InvalidSourceProvenance,
                "program.source_core_hash",
                "source Core semantic hash must not be zero",
            );
        }
        if self.program.source_ssa_hash == SemanticHash::ZERO {
            self.error(
                MachineIrVerificationCode::InvalidSourceProvenance,
                "program.source_ssa_hash",
                "source Core SSA semantic hash must not be zero",
            );
        }
    }

    fn verify_semantic_identity(&mut self, artifact: &MachineIrArtifact) {
        match machine_ir_semantic_hash(&artifact.program) {
            Ok(actual) if actual != artifact.semantic_hash => self.error(
                MachineIrVerificationCode::SemanticHashMismatch,
                "artifact.semantic_hash",
                format!("declared {}; computed {actual}", artifact.semantic_hash),
            ),
            Ok(_) => {}
            Err(error) => self.error(
                MachineIrVerificationCode::EncodingFailure,
                "program",
                error.to_string(),
            ),
        }
    }

    fn verify_program(&mut self) {
        if self.program.functions.is_empty() {
            self.error(
                MachineIrVerificationCode::MissingEntry,
                "program.functions",
                "program must contain at least one function",
            );
        }
        for (index, function) in self.program.functions.iter().enumerate() {
            if self.diagnostics_full() {
                return;
            }
            let expected = MachineFunctionId(index as u32);
            if function.id != expected {
                self.error(
                    MachineIrVerificationCode::NonCanonicalOrder,
                    format!("program.functions[{index}].id"),
                    format!(
                        "function IDs must be dense; expected {}, found {}",
                        expected.0, function.id.0
                    ),
                );
            }
            if self.functions.insert(function.id, function).is_some() {
                self.error(
                    MachineIrVerificationCode::DuplicateId,
                    format!("program.functions[{index}].id"),
                    format!("duplicate function ID {}", function.id.0),
                );
            }
            self.signatures.insert(
                function.id,
                MachineCallSignature {
                    parameters: Arc::from(
                        function
                            .parameters
                            .iter()
                            .map(|parameter| parameter.ty)
                            .collect::<Vec<_>>(),
                    ),
                    effects: Arc::from(function.effects.clone()),
                    result: function.result,
                },
            );
        }
        if !self.functions.contains_key(&self.program.entry) {
            self.error(
                MachineIrVerificationCode::MissingEntry,
                "program.entry",
                format!("entry function {} does not exist", self.program.entry.0),
            );
        }
        for (index, function) in self.program.functions.iter().enumerate() {
            if self.diagnostics_full() {
                break;
            }
            self.verify_function(function, &format!("program.functions[{index}]"));
        }
    }

    fn preflight_counts(&mut self) -> bool {
        self.total_blocks = 0;
        self.total_instructions = 0;
        self.total_registers = 0;
        self.total_edges = 0;
        self.total_operands = 0;
        self.total_work = self.program.functions.len() as u64;

        if !self.preflight_limit(
            self.program.functions.len() as u64,
            MACHINE_IR_MAX_FUNCTIONS,
            "functions",
        ) || !self.preflight_limit(self.total_work, MACHINE_IR_MAX_LOWERING_WORK, "work units")
        {
            return false;
        }

        for function in &self.program.functions {
            if function.effects.len() > 1 {
                self.error(
                    MachineIrVerificationCode::StructuralLimit,
                    "program.functions.effects",
                    format!(
                        "effect-row length {} exceeds the R1-S6 maximum 1",
                        function.effects.len()
                    ),
                );
                return false;
            }

            self.total_blocks = self
                .total_blocks
                .saturating_add(function.blocks.len() as u64);
            self.total_registers = self
                .total_registers
                .saturating_add(function.parameters.len() as u64);
            self.total_work = self
                .total_work
                .saturating_add(function.parameters.len() as u64)
                .saturating_add(function.effects.len() as u64)
                .saturating_add(function.blocks.len() as u64);

            if !self.preflight_limit(self.total_blocks, MACHINE_IR_MAX_BLOCKS, "blocks")
                || !self.preflight_limit(
                    self.total_registers,
                    MACHINE_IR_MAX_REGISTERS,
                    "registers",
                )
                || !self.preflight_limit(
                    self.total_work,
                    MACHINE_IR_MAX_LOWERING_WORK,
                    "work units",
                )
            {
                return false;
            }

            for block in &function.blocks {
                let instructions = block.instructions.len() as u64;
                self.total_instructions = self.total_instructions.saturating_add(instructions);
                self.total_registers = self.total_registers.saturating_add(instructions);
                self.total_work = self.total_work.saturating_add(instructions);

                if !self.preflight_limit(
                    self.total_instructions,
                    MACHINE_IR_MAX_INSTRUCTIONS,
                    "instructions",
                ) || !self.preflight_limit(
                    self.total_registers,
                    MACHINE_IR_MAX_REGISTERS,
                    "registers",
                ) || !self.preflight_limit(
                    self.total_work,
                    MACHINE_IR_MAX_LOWERING_WORK,
                    "work units",
                ) {
                    return false;
                }

                for instruction in &block.instructions {
                    let operands = instruction_operand_count(&instruction.kind);
                    self.total_operands = self.total_operands.saturating_add(operands);
                    self.total_work = self.total_work.saturating_add(operands);
                    if !self.preflight_limit(
                        self.total_operands,
                        MACHINE_IR_MAX_OPERANDS,
                        "operands",
                    ) || !self.preflight_limit(
                        self.total_work,
                        MACHINE_IR_MAX_LOWERING_WORK,
                        "work units",
                    ) {
                        return false;
                    }
                }

                let terminator_operands = terminator_operand_count(&block.terminator);
                self.total_operands = self.total_operands.saturating_add(terminator_operands);
                self.total_work = self.total_work.saturating_add(terminator_operands);
                if matches!(block.terminator, MachineTerminator::Branch { .. }) {
                    self.total_edges = self.total_edges.saturating_add(2);
                }

                if !self.preflight_limit(self.total_edges, MACHINE_IR_MAX_EDGES, "CFG edges")
                    || !self.preflight_limit(
                        self.total_operands,
                        MACHINE_IR_MAX_OPERANDS,
                        "operands",
                    )
                    || !self.preflight_limit(
                        self.total_work,
                        MACHINE_IR_MAX_LOWERING_WORK,
                        "work units",
                    )
                {
                    return false;
                }
            }
        }
        true
    }

    fn preflight_limit(&mut self, actual: u64, limit: u64, name: &'static str) -> bool {
        if actual <= limit {
            return true;
        }
        self.error(
            MachineIrVerificationCode::StructuralLimit,
            "program.functions",
            format!("{name} count {actual} exceeds {limit}"),
        );
        false
    }

    fn verify_function(&mut self, function: &MachineFunction, path: &str) {
        if function.effects.windows(2).any(|pair| pair[0] >= pair[1]) {
            self.error(
                MachineIrVerificationCode::NonCanonicalOrder,
                format!("{path}.effects"),
                "effect row must be strictly sorted and deduplicated",
            );
        }

        let mut environment = BTreeMap::new();
        for (index, parameter) in function.parameters.iter().enumerate() {
            if self.diagnostics_full() {
                return;
            }
            let expected = VirtualRegister(index as u32);
            if parameter.register != expected {
                self.error(
                    MachineIrVerificationCode::NonCanonicalOrder,
                    format!("{path}.parameters[{index}].register"),
                    format!(
                        "parameter registers must start at zero; expected {}, found {}",
                        expected.0, parameter.register.0
                    ),
                );
            }
            if environment
                .insert(parameter.register, parameter.ty)
                .is_some()
            {
                self.error(
                    MachineIrVerificationCode::DuplicateId,
                    format!("{path}.parameters[{index}].register"),
                    format!("duplicate register {}", parameter.register.0),
                );
            }
        }

        if function.blocks.is_empty() {
            self.error(
                MachineIrVerificationCode::InvalidControlFlow,
                format!("{path}.blocks"),
                "function must contain an entry block",
            );
            return;
        }
        if function.entry_block != MachineBlockId(0) {
            self.error(
                MachineIrVerificationCode::NonCanonicalOrder,
                format!("{path}.entry_block"),
                "canonical entry block must be block 0",
            );
        }

        let mut expected_register = function.parameters.len() as u64;
        let mut incoming = vec![0_u32; function.blocks.len()];
        for (block_index, block) in function.blocks.iter().enumerate() {
            if self.diagnostics_full() {
                return;
            }
            let block_path = format!("{path}.blocks[{block_index}]");
            if block.id != MachineBlockId(block_index as u32) {
                self.error(
                    MachineIrVerificationCode::NonCanonicalOrder,
                    format!("{block_path}.id"),
                    format!(
                        "block IDs must equal vector positions; expected {block_index}, found {}",
                        block.id.0
                    ),
                );
            }
            for (instruction_index, instruction) in block.instructions.iter().enumerate() {
                if u64::from(instruction.result.0) != expected_register {
                    self.error(
                        MachineIrVerificationCode::NonCanonicalOrder,
                        format!("{block_path}.instructions[{instruction_index}].result"),
                        format!(
                            "register IDs must be contiguous in canonical block order; expected {expected_register}, found {}",
                            instruction.result.0
                        ),
                    );
                }
                expected_register = expected_register.saturating_add(1);
            }
            if let MachineTerminator::Branch {
                then_block,
                else_block,
                ..
            } = block.terminator
            {
                if then_block == else_block {
                    self.error(
                        MachineIrVerificationCode::InvalidControlFlow,
                        format!("{block_path}.terminator"),
                        "branch targets must be distinct",
                    );
                }
                for (label, target) in [("then_block", then_block), ("else_block", else_block)] {
                    match incoming.get_mut(target.0 as usize) {
                        Some(count) => *count = count.saturating_add(1),
                        None => self.error(
                            MachineIrVerificationCode::InvalidControlFlow,
                            format!("{block_path}.terminator.{label}"),
                            format!("target block {} does not exist", target.0),
                        ),
                    }
                }
            }
        }
        if incoming.first().copied().unwrap_or_default() != 0 {
            self.error(
                MachineIrVerificationCode::InvalidControlFlow,
                format!("{path}.blocks[0]"),
                "entry block must not have incoming edges",
            );
        }
        for (index, count) in incoming.iter().enumerate().skip(1) {
            if *count != 1 {
                self.error(
                    MachineIrVerificationCode::InvalidControlFlow,
                    format!("{path}.blocks[{index}]"),
                    format!("canonical branch tree requires one incoming edge; found {count}"),
                );
            }
        }

        let mut preorder = Vec::with_capacity(function.blocks.len());
        let mut reached = BTreeSet::new();
        self.collect_preorder(
            function,
            function.entry_block,
            0,
            &mut reached,
            &mut preorder,
            path,
        );
        if reached.len() != function.blocks.len() {
            self.error(
                MachineIrVerificationCode::InvalidControlFlow,
                format!("{path}.blocks"),
                format!(
                    "{} of {} blocks are reachable",
                    reached.len(),
                    function.blocks.len()
                ),
            );
        }
        let expected_preorder: Vec<MachineBlockId> = (0..function.blocks.len())
            .map(|index| MachineBlockId(index as u32))
            .collect();
        if preorder != expected_preorder {
            self.error(
                MachineIrVerificationCode::NonCanonicalOrder,
                format!("{path}.blocks"),
                "blocks must be stored in then-first depth-first preorder",
            );
        }

        let mut typed_reached = BTreeSet::new();
        self.verify_block_tree(
            function,
            function.entry_block,
            &mut environment,
            0,
            &mut typed_reached,
            path,
        );
    }

    fn collect_preorder(
        &mut self,
        function: &MachineFunction,
        block: MachineBlockId,
        depth: u32,
        reached: &mut BTreeSet<MachineBlockId>,
        order: &mut Vec<MachineBlockId>,
        path: &str,
    ) {
        if self.diagnostics_full() {
            return;
        }
        if depth > MACHINE_IR_MAX_CFG_DEPTH {
            self.error(
                MachineIrVerificationCode::StructuralLimit,
                format!("{path}.blocks"),
                format!("CFG depth exceeds {MACHINE_IR_MAX_CFG_DEPTH}"),
            );
            return;
        }
        if !reached.insert(block) {
            self.error(
                MachineIrVerificationCode::InvalidControlFlow,
                format!("{path}.blocks[{}]", block.0),
                "cycle or multiply reached block",
            );
            return;
        }
        let Some(current) = function.blocks.get(block.0 as usize) else {
            return;
        };
        order.push(block);
        if let MachineTerminator::Branch {
            then_block,
            else_block,
            ..
        } = current.terminator
        {
            self.collect_preorder(function, then_block, depth + 1, reached, order, path);
            self.collect_preorder(function, else_block, depth + 1, reached, order, path);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_block_tree(
        &mut self,
        function: &MachineFunction,
        block_id: MachineBlockId,
        environment: &mut BTreeMap<VirtualRegister, MachineType>,
        depth: u32,
        reached: &mut BTreeSet<MachineBlockId>,
        function_path: &str,
    ) {
        if self.diagnostics_full() {
            return;
        }
        if depth > MACHINE_IR_MAX_CFG_DEPTH {
            self.error(
                MachineIrVerificationCode::StructuralLimit,
                format!("{function_path}.blocks"),
                format!("CFG depth exceeds {MACHINE_IR_MAX_CFG_DEPTH}"),
            );
            return;
        }
        if !reached.insert(block_id) {
            return;
        }
        let Some(block) = function.blocks.get(block_id.0 as usize) else {
            return;
        };
        let path = format!("{function_path}.blocks[{}]", block_id.0);
        let mut defined_here = Vec::with_capacity(block.instructions.len());
        for (index, instruction) in block.instructions.iter().enumerate() {
            if self.diagnostics_full() {
                return;
            }
            let instruction_path = format!("{path}.instructions[{index}]");
            if let Some(actual) = self.instruction_type(
                &instruction.kind,
                environment,
                &function.effects,
                &instruction_path,
            ) {
                self.expect_type(instruction.ty, actual, &format!("{instruction_path}.type"));
            }
            match environment.entry(instruction.result) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(instruction.ty);
                    defined_here.push(instruction.result);
                }
                std::collections::btree_map::Entry::Occupied(_) => self.error(
                    MachineIrVerificationCode::DuplicateId,
                    format!("{instruction_path}.result"),
                    format!(
                        "register {} is defined more than once",
                        instruction.result.0
                    ),
                ),
            }
        }

        match &block.terminator {
            MachineTerminator::Return(operand) => {
                if let Some(actual) =
                    self.operand_type(operand, environment, &format!("{path}.terminator"))
                {
                    self.expect_type(function.result, actual, &format!("{path}.terminator"));
                }
            }
            MachineTerminator::Branch {
                condition,
                then_block,
                else_block,
            } => {
                if let Some(actual) = self.operand_type(
                    condition,
                    environment,
                    &format!("{path}.terminator.condition"),
                ) {
                    self.expect_type(
                        MachineType::Bool,
                        actual,
                        &format!("{path}.terminator.condition"),
                    );
                }
                self.verify_block_tree(
                    function,
                    *then_block,
                    environment,
                    depth + 1,
                    reached,
                    function_path,
                );
                self.verify_block_tree(
                    function,
                    *else_block,
                    environment,
                    depth + 1,
                    reached,
                    function_path,
                );
            }
            MachineTerminator::TailCall {
                function: target,
                arguments,
            } => {
                if let Some(result) = self.verify_call(
                    *target,
                    arguments,
                    environment,
                    &function.effects,
                    &format!("{path}.terminator"),
                ) {
                    self.expect_type(function.result, result, &format!("{path}.terminator"));
                }
            }
        }
        for register in defined_here {
            environment.remove(&register);
        }
    }

    fn instruction_type(
        &mut self,
        kind: &MachineInstructionKind,
        environment: &BTreeMap<VirtualRegister, MachineType>,
        effects: &[MachineEffect],
        path: &str,
    ) -> Option<MachineType> {
        match kind {
            MachineInstructionKind::Move(operand) => {
                self.operand_type(operand, environment, &format!("{path}.operand"))
            }
            MachineInstructionKind::I64Binary { left, right, .. } => {
                self.verify_binary_operands(left, right, MachineType::I64, environment, path);
                Some(MachineType::I64)
            }
            MachineInstructionKind::F64Binary { left, right, .. } => {
                self.verify_binary_operands(left, right, MachineType::F64, environment, path);
                Some(MachineType::F64)
            }
            MachineInstructionKind::I64Compare { left, right, .. } => {
                self.verify_binary_operands(left, right, MachineType::I64, environment, path);
                Some(MachineType::Bool)
            }
            MachineInstructionKind::ArrayLenF64 { array } => {
                if let Some(actual) =
                    self.operand_type(array, environment, &format!("{path}.array"))
                {
                    self.expect_type(MachineType::F64Array, actual, &format!("{path}.array"));
                }
                Some(MachineType::I64)
            }
            MachineInstructionKind::ArrayGetF64Checked { array, index } => {
                self.require_effect(effects, MachineEffect::Bounds, path);
                if let Some(actual) =
                    self.operand_type(array, environment, &format!("{path}.array"))
                {
                    self.expect_type(MachineType::F64Array, actual, &format!("{path}.array"));
                }
                if let Some(actual) =
                    self.operand_type(index, environment, &format!("{path}.index"))
                {
                    self.expect_type(MachineType::I64, actual, &format!("{path}.index"));
                }
                Some(MachineType::F64)
            }
            MachineInstructionKind::Call {
                function,
                arguments,
            } => self.verify_call(*function, arguments, environment, effects, path),
        }
    }

    fn verify_binary_operands(
        &mut self,
        left: &MachineOperand,
        right: &MachineOperand,
        expected: MachineType,
        environment: &BTreeMap<VirtualRegister, MachineType>,
        path: &str,
    ) {
        for (name, operand) in [("left", left), ("right", right)] {
            if let Some(actual) = self.operand_type(operand, environment, &format!("{path}.{name}"))
            {
                self.expect_type(expected, actual, &format!("{path}.{name}"));
            }
        }
    }

    fn verify_call(
        &mut self,
        function: MachineFunctionId,
        arguments: &[MachineOperand],
        environment: &BTreeMap<VirtualRegister, MachineType>,
        caller_effects: &[MachineEffect],
        path: &str,
    ) -> Option<MachineType> {
        let Some(signature) = self.signatures.get(&function).cloned() else {
            self.error(
                MachineIrVerificationCode::InvalidCall,
                format!("{path}.function"),
                format!("function {} does not exist", function.0),
            );
            return None;
        };
        if arguments.len() != signature.parameters.len() {
            self.error(
                MachineIrVerificationCode::InvalidCall,
                format!("{path}.arguments"),
                format!(
                    "expected {} arguments; found {}",
                    signature.parameters.len(),
                    arguments.len()
                ),
            );
        }
        for (index, (argument, expected)) in arguments
            .iter()
            .zip(signature.parameters.iter())
            .enumerate()
        {
            if let Some(actual) =
                self.operand_type(argument, environment, &format!("{path}.arguments[{index}]"))
            {
                self.expect_type(*expected, actual, &format!("{path}.arguments[{index}]"));
            }
        }
        for effect in signature.effects.iter().copied() {
            self.require_effect(caller_effects, effect, &format!("{path}.function"));
        }
        Some(signature.result)
    }

    fn operand_type(
        &mut self,
        operand: &MachineOperand,
        environment: &BTreeMap<VirtualRegister, MachineType>,
        path: &str,
    ) -> Option<MachineType> {
        match operand {
            MachineOperand::Unit => Some(MachineType::Unit),
            MachineOperand::Bool(_) => Some(MachineType::Bool),
            MachineOperand::I64(_) => Some(MachineType::I64),
            MachineOperand::F64Bits(bits) => {
                if f64::from_bits(*bits).is_nan() && *bits != CANONICAL_NAN_BITS {
                    self.error(
                        MachineIrVerificationCode::NonCanonicalOrder,
                        path,
                        format!("non-canonical NaN bits 0x{bits:016x}"),
                    );
                }
                Some(MachineType::F64)
            }
            MachineOperand::Register(register) => match environment.get(register) {
                Some(ty) => Some(*ty),
                None => {
                    self.error(
                        MachineIrVerificationCode::UnboundRegister,
                        path,
                        format!("register {} does not dominate this use", register.0),
                    );
                    None
                }
            },
        }
    }

    fn expect_type(&mut self, expected: MachineType, actual: MachineType, path: &str) {
        if expected != actual {
            self.error(
                MachineIrVerificationCode::TypeMismatch,
                path,
                format!("expected {expected:?}; found {actual:?}"),
            );
        }
    }

    fn require_effect(&mut self, effects: &[MachineEffect], effect: MachineEffect, path: &str) {
        if !effects.contains(&effect) {
            self.error(
                MachineIrVerificationCode::MissingEffect,
                path,
                format!("effect row is missing {effect:?}"),
            );
        }
    }
}

fn instruction_operand_count(kind: &MachineInstructionKind) -> u64 {
    match kind {
        MachineInstructionKind::Move(_) | MachineInstructionKind::ArrayLenF64 { .. } => 1,
        MachineInstructionKind::I64Binary { .. }
        | MachineInstructionKind::F64Binary { .. }
        | MachineInstructionKind::I64Compare { .. }
        | MachineInstructionKind::ArrayGetF64Checked { .. } => 2,
        MachineInstructionKind::Call { arguments, .. } => arguments.len() as u64,
    }
}

fn terminator_operand_count(terminator: &MachineTerminator) -> u64 {
    match terminator {
        MachineTerminator::Return(_) | MachineTerminator::Branch { .. } => 1,
        MachineTerminator::TailCall { arguments, .. } => arguments.len() as u64,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SourceBoundMachineIrArtifact<'artifact, 'ssa, 'core> {
    verified: VerifiedMachineIrArtifact<'artifact>,
    source: SourceBoundCoreSsaArtifact<'ssa, 'core>,
}

impl<'artifact, 'ssa, 'core> SourceBoundMachineIrArtifact<'artifact, 'ssa, 'core> {
    pub fn artifact(self) -> &'artifact MachineIrArtifact {
        self.verified.artifact()
    }

    pub fn program(self) -> &'artifact MachineIrProgram {
        self.verified.program()
    }

    pub fn semantic_hash(self) -> SemanticHash {
        self.verified.semantic_hash()
    }

    pub fn source_ssa(self) -> &'ssa CoreSsaArtifact {
        self.source.artifact()
    }

    pub fn source_core(self) -> &'core CoreArtifact {
        self.source.source()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MachineIrSourceError {
    InvalidSourceBinding(CoreSsaSourceError),
    InvalidMachineIr(MachineIrVerificationErrors),
    TranslationFailed(MachineIrLowerError),
    SourceSsaHashMismatch {
        declared: SemanticHash,
        actual: SemanticHash,
    },
    SourceCoreHashMismatch {
        declared: SemanticHash,
        actual: SemanticHash,
    },
    TranslationMismatch {
        supplied: SemanticHash,
        replayed: SemanticHash,
    },
}

impl fmt::Display for MachineIrSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSourceBinding(error) => write!(formatter, "{error}"),
            Self::InvalidMachineIr(errors) => write!(formatter, "{errors}"),
            Self::TranslationFailed(error) => write!(formatter, "{error}"),
            Self::SourceSsaHashMismatch { declared, actual } => write!(
                formatter,
                "Machine IR source SSA hash declares {declared}; supplied SSA hash is {actual}"
            ),
            Self::SourceCoreHashMismatch { declared, actual } => write!(
                formatter,
                "Machine IR source Core hash declares {declared}; supplied Core hash is {actual}"
            ),
            Self::TranslationMismatch { supplied, replayed } => write!(
                formatter,
                "Machine IR differs from deterministic replay: supplied {supplied}; replayed {replayed}"
            ),
        }
    }
}

impl std::error::Error for MachineIrSourceError {}

/// Verify that `artifact` is exactly the deterministic R1-S6 translation of
/// the supplied Core-bound SSA, rather than merely a well-typed artifact
/// carrying copied hashes.
pub fn verify_machine_ir_source<'artifact, 'ssa, 'core>(
    artifact: &'artifact MachineIrArtifact,
    source_ssa: &'ssa CoreSsaArtifact,
    source_core: &'core CoreArtifact,
) -> Result<SourceBoundMachineIrArtifact<'artifact, 'ssa, 'core>, MachineIrSourceError> {
    let source = verify_core_ssa_source(source_ssa, source_core)
        .map_err(MachineIrSourceError::InvalidSourceBinding)?;
    let verified = verify_machine_ir(artifact).map_err(MachineIrSourceError::InvalidMachineIr)?;
    if artifact.program.source_ssa_hash != source.semantic_hash() {
        return Err(MachineIrSourceError::SourceSsaHashMismatch {
            declared: artifact.program.source_ssa_hash,
            actual: source.semantic_hash(),
        });
    }
    if artifact.program.source_core_hash != source_core.semantic_hash {
        return Err(MachineIrSourceError::SourceCoreHashMismatch {
            declared: artifact.program.source_core_hash,
            actual: source_core.semantic_hash,
        });
    }

    let replayed = lower_machine_ir_from_ssa_r1_s6(source.artifact())
        .map_err(MachineIrSourceError::TranslationFailed)?;
    let supplied_bytes = machine_ir_semantic_bytes(&artifact.program).map_err(|error| {
        MachineIrSourceError::InvalidMachineIr(MachineIrVerificationErrors(vec![
            MachineIrVerificationError {
                code: MachineIrVerificationCode::EncodingFailure,
                path: "program".to_owned(),
                message: error.to_string(),
            },
        ]))
    })?;
    let replayed_bytes = machine_ir_semantic_bytes(&replayed.program).map_err(|error| {
        MachineIrSourceError::InvalidMachineIr(MachineIrVerificationErrors(vec![
            MachineIrVerificationError {
                code: MachineIrVerificationCode::EncodingFailure,
                path: "replayed.program".to_owned(),
                message: error.to_string(),
            },
        ]))
    })?;
    if artifact.semantic_hash != replayed.semantic_hash || supplied_bytes != replayed_bytes {
        return Err(MachineIrSourceError::TranslationMismatch {
            supplied: artifact.semantic_hash,
            replayed: replayed.semantic_hash,
        });
    }
    Ok(SourceBoundMachineIrArtifact { verified, source })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MachineIrExecutionError {
    InvalidArtifact(MachineIrVerificationErrors),
    InvalidBudget {
        field: &'static str,
        limit: u64,
        requested: u64,
    },
    InvalidEntryArguments {
        expected_count: usize,
        actual_count: usize,
        expected_prefix: Vec<MachineType>,
        actual_prefix: Vec<&'static str>,
    },
    StepBudgetExceeded {
        limit: u64,
    },
    CallDepthExceeded {
        limit: u32,
    },
    LiveRegisterSlotsExceeded {
        limit: u64,
    },
    InternalInvariant(String),
}

impl fmt::Display for MachineIrExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArtifact(errors) => write!(formatter, "{errors}"),
            Self::InvalidBudget {
                field,
                limit,
                requested,
            } => write!(
                formatter,
                "Machine IR evaluation {field} budget {requested} exceeds hard limit {limit}"
            ),
            Self::InvalidEntryArguments {
                expected_count,
                actual_count,
                expected_prefix,
                actual_prefix,
            } => write!(
                formatter,
                "Machine IR entry argument mismatch: expected {expected_count} value(s) \
                 beginning {expected_prefix:?}; found {actual_count} beginning {actual_prefix:?}"
            ),
            Self::StepBudgetExceeded { limit } => {
                write!(
                    formatter,
                    "Machine IR evaluation exceeded {limit} execution work units"
                )
            }
            Self::CallDepthExceeded { limit } => {
                write!(
                    formatter,
                    "Machine IR evaluation exceeded call depth {limit}"
                )
            }
            Self::LiveRegisterSlotsExceeded { limit } => write!(
                formatter,
                "Machine IR evaluation exceeded {limit} live register slots"
            ),
            Self::InternalInvariant(message) => {
                write!(formatter, "verified Machine IR invariant failed: {message}")
            }
        }
    }
}

impl std::error::Error for MachineIrExecutionError {}

/// Verify and execute a standalone Machine IR artifact.
///
/// Standalone verification does not prove translation provenance. Lighthouse
/// evidence should use `evaluate_machine_ir_translation` or an already
/// source-bound token.
pub fn evaluate_machine_ir(
    artifact: &MachineIrArtifact,
    arguments: Vec<CoreValue>,
    budget: EvaluationBudget,
) -> Result<Evaluation, MachineIrExecutionError> {
    let verified = verify_machine_ir(artifact).map_err(MachineIrExecutionError::InvalidArtifact)?;
    MachineIrEvaluator::new(verified, budget)?.evaluate(arguments)
}

pub fn evaluate_source_bound_machine_ir(
    bound: SourceBoundMachineIrArtifact<'_, '_, '_>,
    arguments: Vec<CoreValue>,
    budget: EvaluationBudget,
) -> Result<Evaluation, MachineIrExecutionError> {
    MachineIrEvaluator::new(bound.verified, budget)?.evaluate(arguments)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MachineIrTranslationExecutionError {
    InvalidTranslation(MachineIrSourceError),
    Execution(MachineIrExecutionError),
}

impl fmt::Display for MachineIrTranslationExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTranslation(error) => write!(formatter, "{error}"),
            Self::Execution(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for MachineIrTranslationExecutionError {}

pub fn evaluate_machine_ir_translation(
    artifact: &MachineIrArtifact,
    source_ssa: &CoreSsaArtifact,
    source_core: &CoreArtifact,
    arguments: Vec<CoreValue>,
    budget: EvaluationBudget,
) -> Result<Evaluation, MachineIrTranslationExecutionError> {
    let bound = verify_machine_ir_source(artifact, source_ssa, source_core)
        .map_err(MachineIrTranslationExecutionError::InvalidTranslation)?;
    evaluate_source_bound_machine_ir(bound, arguments, budget)
        .map_err(MachineIrTranslationExecutionError::Execution)
}

struct MachineIrEvaluator<'program> {
    verified: VerifiedMachineIrArtifact<'program>,
    budget: EvaluationBudget,
    steps: u64,
    effect_trace: Vec<EffectEvent>,
    frame_slots: BTreeMap<MachineFunctionId, usize>,
}

impl<'program> MachineIrEvaluator<'program> {
    fn new(
        verified: VerifiedMachineIrArtifact<'program>,
        budget: EvaluationBudget,
    ) -> Result<Self, MachineIrExecutionError> {
        if budget.max_steps > MACHINE_IR_MAX_EXECUTION_STEPS {
            return Err(MachineIrExecutionError::InvalidBudget {
                field: "execution-work",
                limit: MACHINE_IR_MAX_EXECUTION_STEPS,
                requested: budget.max_steps,
            });
        }
        if budget.max_call_depth > MACHINE_IR_MAX_CALL_DEPTH {
            return Err(MachineIrExecutionError::InvalidBudget {
                field: "call-depth",
                limit: u64::from(MACHINE_IR_MAX_CALL_DEPTH),
                requested: u64::from(budget.max_call_depth),
            });
        }
        let frame_slots = verified
            .program()
            .functions
            .iter()
            .map(|function| {
                let slots = function
                    .blocks
                    .iter()
                    .flat_map(|block| &block.instructions)
                    .map(|instruction| instruction.result.0 as usize + 1)
                    .max()
                    .unwrap_or(function.parameters.len())
                    .max(function.parameters.len());
                (function.id, slots)
            })
            .collect();
        Ok(Self {
            verified,
            budget,
            steps: 0,
            effect_trace: Vec::new(),
            frame_slots,
        })
    }

    fn evaluate(
        mut self,
        arguments: Vec<CoreValue>,
    ) -> Result<Evaluation, MachineIrExecutionError> {
        let entry = self.verified.program().entry;
        let (parameter_count, entry_slots) = {
            let function = self.find_function(entry).ok_or_else(|| {
                Self::invariant(format!("entry function {} disappeared", entry.0))
            })?;
            (
                function.parameters.len(),
                self.frame_slot_count(entry)? as u64,
            )
        };
        self.charge(self.frame_setup_work(parameter_count, entry_slots, 3)?)?;

        let arguments_match = {
            let function = self.find_function(entry).ok_or_else(|| {
                Self::invariant(format!("entry function {} disappeared", entry.0))
            })?;
            machine_arguments_match_parameters(&arguments, &function.parameters)
        };
        if !arguments_match {
            let expected_prefix = self
                .find_function(entry)
                .ok_or_else(|| Self::invariant(format!("entry function {} disappeared", entry.0)))?
                .parameters
                .iter()
                .take(8)
                .map(|parameter| parameter.ty)
                .collect();
            return Err(MachineIrExecutionError::InvalidEntryArguments {
                expected_count: parameter_count,
                actual_count: arguments.len(),
                expected_prefix,
                actual_prefix: arguments.iter().take(8).map(machine_value_kind).collect(),
            });
        }
        let outcome = self.run(entry, arguments)?;
        Ok(Evaluation {
            outcome,
            steps: self.steps,
            effect_trace: self.effect_trace,
        })
    }

    fn run(
        &mut self,
        entry: MachineFunctionId,
        arguments: Vec<CoreValue>,
    ) -> Result<EvaluationOutcome, MachineIrExecutionError> {
        let entry_slots = self.frame_slot_count(entry)?;
        if entry_slots as u64 > MACHINE_IR_MAX_LIVE_REGISTER_SLOTS {
            return Err(MachineIrExecutionError::LiveRegisterSlotsExceeded {
                limit: MACHINE_IR_MAX_LIVE_REGISTER_SLOTS,
            });
        }
        let mut frame = self.new_frame(entry, arguments)?;
        let mut continuations: Vec<MachineContinuation> = Vec::new();
        let mut live_register_slots = entry_slots as u64;

        loop {
            let instruction_work = {
                let block = self
                    .find_function(frame.function)
                    .and_then(|function| function.blocks.get(frame.block.0 as usize))
                    .ok_or_else(|| {
                        Self::invariant(format!(
                            "missing function {} block {}",
                            frame.function.0, frame.block.0
                        ))
                    })?;
                block
                    .instructions
                    .get(frame.next_instruction)
                    .map(|instruction| self.instruction_work(&instruction.kind))
                    .transpose()?
            };

            if let Some(work) = instruction_work {
                self.charge(work)?;
                let instruction = self
                    .find_function(frame.function)
                    .and_then(|function| function.blocks.get(frame.block.0 as usize))
                    .and_then(|block| block.instructions.get(frame.next_instruction))
                    .cloned()
                    .ok_or_else(|| Self::invariant("charged instruction disappeared"))?;
                frame.next_instruction += 1;
                match instruction.kind {
                    MachineInstructionKind::Move(operand) => {
                        let value = eval_machine_operand(&operand, &frame.registers)?;
                        assign_machine_register(&mut frame.registers, instruction.result, value)?;
                    }
                    MachineInstructionKind::Call {
                        function,
                        arguments,
                    } => {
                        let arguments = eval_machine_operands(&arguments, &frame.registers)?;
                        if continuations.len() as u32 >= self.budget.max_call_depth {
                            return Err(MachineIrExecutionError::CallDepthExceeded {
                                limit: self.budget.max_call_depth,
                            });
                        }
                        let callee_slots = self.frame_slot_count(function)? as u64;
                        let projected = live_register_slots.checked_add(callee_slots).ok_or(
                            MachineIrExecutionError::LiveRegisterSlotsExceeded {
                                limit: MACHINE_IR_MAX_LIVE_REGISTER_SLOTS,
                            },
                        )?;
                        if projected > MACHINE_IR_MAX_LIVE_REGISTER_SLOTS {
                            return Err(MachineIrExecutionError::LiveRegisterSlotsExceeded {
                                limit: MACHINE_IR_MAX_LIVE_REGISTER_SLOTS,
                            });
                        }
                        continuations.push(MachineContinuation {
                            caller: frame,
                            result: instruction.result,
                        });
                        frame = self.new_frame(function, arguments)?;
                        live_register_slots = projected;
                    }
                    operation => match evaluate_machine_operation(&operation, &frame.registers)? {
                        MachineComputation::Value(value) => assign_machine_register(
                            &mut frame.registers,
                            instruction.result,
                            value,
                        )?,
                        MachineComputation::Error(error) => {
                            self.effect_trace.push(EffectEvent::Error(error.clone()));
                            return Ok(EvaluationOutcome::Error(error));
                        }
                    },
                }
                continue;
            }

            let terminator_work = {
                let block = self
                    .find_function(frame.function)
                    .and_then(|function| function.blocks.get(frame.block.0 as usize))
                    .ok_or_else(|| {
                        Self::invariant(format!(
                            "missing function {} block {}",
                            frame.function.0, frame.block.0
                        ))
                    })?;
                self.terminator_work(&block.terminator)?
            };
            self.charge(terminator_work)?;
            let terminator = self
                .find_function(frame.function)
                .and_then(|function| function.blocks.get(frame.block.0 as usize))
                .map(|block| block.terminator.clone())
                .ok_or_else(|| Self::invariant("charged terminator disappeared"))?;
            match terminator {
                MachineTerminator::Return(operand) => {
                    let value = eval_machine_operand(&operand, &frame.registers)?;
                    match continuations.pop() {
                        Some(continuation) => {
                            live_register_slots = live_register_slots
                                .checked_sub(frame.registers.len() as u64)
                                .ok_or_else(|| {
                                    Self::invariant("live register-slot accounting underflow")
                                })?;
                            frame = continuation.caller;
                            assign_machine_register(
                                &mut frame.registers,
                                continuation.result,
                                value,
                            )?;
                        }
                        None => return Ok(EvaluationOutcome::Return(value)),
                    }
                }
                MachineTerminator::Branch {
                    condition,
                    then_block,
                    else_block,
                } => {
                    let CoreValue::Bool(condition) =
                        eval_machine_operand(&condition, &frame.registers)?
                    else {
                        return Err(Self::invariant("verified branch condition is not Bool"));
                    };
                    frame.block = if condition { then_block } else { else_block };
                    frame.next_instruction = 0;
                }
                MachineTerminator::TailCall {
                    function,
                    arguments,
                } => {
                    let arguments = eval_machine_operands(&arguments, &frame.registers)?;
                    let callee_slots = self.frame_slot_count(function)? as u64;
                    let projected = live_register_slots
                        .checked_sub(frame.registers.len() as u64)
                        .and_then(|slots| slots.checked_add(callee_slots))
                        .ok_or(MachineIrExecutionError::LiveRegisterSlotsExceeded {
                            limit: MACHINE_IR_MAX_LIVE_REGISTER_SLOTS,
                        })?;
                    if projected > MACHINE_IR_MAX_LIVE_REGISTER_SLOTS {
                        return Err(MachineIrExecutionError::LiveRegisterSlotsExceeded {
                            limit: MACHINE_IR_MAX_LIVE_REGISTER_SLOTS,
                        });
                    }
                    drop(frame);
                    frame = self.new_frame(function, arguments)?;
                    live_register_slots = projected;
                }
            }
        }
    }

    fn new_frame(
        &self,
        function_id: MachineFunctionId,
        arguments: Vec<CoreValue>,
    ) -> Result<MachineExecutionFrame, MachineIrExecutionError> {
        let function = self
            .find_function(function_id)
            .ok_or_else(|| Self::invariant(format!("missing function {}", function_id.0)))?;
        if !machine_arguments_match_parameters(&arguments, &function.parameters) {
            return Err(Self::invariant(format!(
                "verified call to function {} has invalid arguments",
                function_id.0
            )));
        }
        let register_count = self.frame_slot_count(function_id)?;
        let mut registers = vec![None; register_count];
        for (parameter, argument) in function.parameters.iter().zip(arguments) {
            let slot = registers
                .get_mut(parameter.register.0 as usize)
                .ok_or_else(|| Self::invariant("parameter register is outside verified frame"))?;
            *slot = Some(argument);
        }
        Ok(MachineExecutionFrame {
            function: function_id,
            block: function.entry_block,
            next_instruction: 0,
            registers,
        })
    }

    fn frame_slot_count(
        &self,
        function: MachineFunctionId,
    ) -> Result<usize, MachineIrExecutionError> {
        self.frame_slots.get(&function).copied().ok_or_else(|| {
            Self::invariant(format!(
                "missing frame-slot metadata for function {}",
                function.0
            ))
        })
    }

    fn find_function(&self, id: MachineFunctionId) -> Option<&MachineFunction> {
        self.verified
            .program()
            .functions
            .binary_search_by_key(&id, |function| function.id)
            .ok()
            .map(|index| &self.verified.program().functions[index])
    }

    fn instruction_work(
        &self,
        instruction: &MachineInstructionKind,
    ) -> Result<u64, MachineIrExecutionError> {
        match instruction {
            MachineInstructionKind::Call {
                function,
                arguments,
            } => {
                let frame_slots = self.frame_slot_count(*function)? as u64;
                self.frame_setup_work(arguments.len(), frame_slots, 4)?
                    .checked_add(1)
                    .ok_or(MachineIrExecutionError::StepBudgetExceeded {
                        limit: self.budget.max_steps,
                    })
            }
            _ => Ok(1),
        }
    }

    fn terminator_work(
        &self,
        terminator: &MachineTerminator,
    ) -> Result<u64, MachineIrExecutionError> {
        match terminator {
            MachineTerminator::TailCall {
                function,
                arguments,
            } => {
                let frame_slots = self.frame_slot_count(*function)? as u64;
                self.frame_setup_work(arguments.len(), frame_slots, 4)?
                    .checked_add(1)
                    .ok_or(MachineIrExecutionError::StepBudgetExceeded {
                        limit: self.budget.max_steps,
                    })
            }
            _ => Ok(1),
        }
    }

    fn frame_setup_work(
        &self,
        argument_count: usize,
        frame_slots: u64,
        argument_passes: u64,
    ) -> Result<u64, MachineIrExecutionError> {
        let arguments = u64::try_from(argument_count).map_err(|_| {
            MachineIrExecutionError::StepBudgetExceeded {
                limit: self.budget.max_steps,
            }
        })?;
        arguments
            .checked_mul(argument_passes)
            .and_then(|work| work.checked_add(frame_slots))
            .ok_or(MachineIrExecutionError::StepBudgetExceeded {
                limit: self.budget.max_steps,
            })
    }

    fn charge(&mut self, work: u64) -> Result<(), MachineIrExecutionError> {
        let Some(next) = self.steps.checked_add(work) else {
            return Err(MachineIrExecutionError::StepBudgetExceeded {
                limit: self.budget.max_steps,
            });
        };
        if next > self.budget.max_steps {
            return Err(MachineIrExecutionError::StepBudgetExceeded {
                limit: self.budget.max_steps,
            });
        }
        self.steps = next;
        Ok(())
    }

    fn invariant(message: impl Into<String>) -> MachineIrExecutionError {
        MachineIrExecutionError::InternalInvariant(message.into())
    }
}

struct MachineExecutionFrame {
    function: MachineFunctionId,
    block: MachineBlockId,
    next_instruction: usize,
    registers: Vec<Option<CoreValue>>,
}

struct MachineContinuation {
    caller: MachineExecutionFrame,
    result: VirtualRegister,
}

fn assign_machine_register(
    registers: &mut [Option<CoreValue>],
    result: VirtualRegister,
    value: CoreValue,
) -> Result<(), MachineIrExecutionError> {
    let slot = registers.get_mut(result.0 as usize).ok_or_else(|| {
        MachineIrExecutionError::InternalInvariant(format!(
            "result register {} is outside verified frame",
            result.0
        ))
    })?;
    *slot = Some(value);
    Ok(())
}

enum MachineComputation {
    Value(CoreValue),
    Error(ErrorKind),
}

fn evaluate_machine_operation(
    operation: &MachineInstructionKind,
    registers: &[Option<CoreValue>],
) -> Result<MachineComputation, MachineIrExecutionError> {
    match operation {
        MachineInstructionKind::I64Binary {
            operation,
            mode,
            left,
            right,
        } => {
            let left = expect_machine_i64(eval_machine_operand(left, registers)?)?;
            let right = expect_machine_i64(eval_machine_operand(right, registers)?)?;
            let value = match (operation, mode) {
                (MachineI64BinaryOp::Add, MachineIntegerMode::Wrapping) => left.wrapping_add(right),
                (MachineI64BinaryOp::Sub, MachineIntegerMode::Wrapping) => left.wrapping_sub(right),
                (MachineI64BinaryOp::Mul, MachineIntegerMode::Wrapping) => left.wrapping_mul(right),
                (MachineI64BinaryOp::Add, MachineIntegerMode::Saturating) => {
                    left.saturating_add(right)
                }
                (MachineI64BinaryOp::Sub, MachineIntegerMode::Saturating) => {
                    left.saturating_sub(right)
                }
                (MachineI64BinaryOp::Mul, MachineIntegerMode::Saturating) => {
                    left.saturating_mul(right)
                }
            };
            Ok(MachineComputation::Value(CoreValue::I64(value)))
        }
        MachineInstructionKind::F64Binary {
            operation,
            left,
            right,
        } => {
            let left = expect_machine_f64(eval_machine_operand(left, registers)?)?;
            let right = expect_machine_f64(eval_machine_operand(right, registers)?)?;
            let value = match operation {
                MachineF64BinaryOp::Add => left + right,
                MachineF64BinaryOp::Sub => left - right,
            };
            Ok(MachineComputation::Value(CoreValue::F64(value)))
        }
        MachineInstructionKind::I64Compare {
            operation,
            left,
            right,
        } => {
            let left = expect_machine_i64(eval_machine_operand(left, registers)?)?;
            let right = expect_machine_i64(eval_machine_operand(right, registers)?)?;
            let value = match operation {
                MachineI64CompareOp::LessThan => left < right,
                MachineI64CompareOp::GreaterOrEqual => left >= right,
            };
            Ok(MachineComputation::Value(CoreValue::Bool(value)))
        }
        MachineInstructionKind::ArrayLenF64 { array } => {
            let CoreValue::ArrayF64(values) = eval_machine_operand(array, registers)? else {
                return Err(MachineIrEvaluator::invariant(
                    "ArrayLenF64 argument mismatch",
                ));
            };
            let length = i64::try_from(values.len())
                .map_err(|_| MachineIrEvaluator::invariant("array length does not fit I64"))?;
            Ok(MachineComputation::Value(CoreValue::I64(length)))
        }
        MachineInstructionKind::ArrayGetF64Checked { array, index } => {
            let CoreValue::ArrayF64(values) = eval_machine_operand(array, registers)? else {
                return Err(MachineIrEvaluator::invariant(
                    "ArrayGetF64Checked array mismatch",
                ));
            };
            let index = expect_machine_i64(eval_machine_operand(index, registers)?)?;
            let Ok(index) = usize::try_from(index) else {
                return Ok(MachineComputation::Error(ErrorKind::Bounds));
            };
            Ok(match values.get(index) {
                Some(value) => MachineComputation::Value(CoreValue::F64(*value)),
                None => MachineComputation::Error(ErrorKind::Bounds),
            })
        }
        MachineInstructionKind::Move(_) | MachineInstructionKind::Call { .. } => Err(
            MachineIrEvaluator::invariant("non-operation reached operation evaluator"),
        ),
    }
}

fn eval_machine_operands(
    operands: &[MachineOperand],
    registers: &[Option<CoreValue>],
) -> Result<Vec<CoreValue>, MachineIrExecutionError> {
    operands
        .iter()
        .map(|operand| eval_machine_operand(operand, registers))
        .collect()
}

fn eval_machine_operand(
    operand: &MachineOperand,
    registers: &[Option<CoreValue>],
) -> Result<CoreValue, MachineIrExecutionError> {
    match operand {
        MachineOperand::Unit => Ok(CoreValue::Unit),
        MachineOperand::Bool(value) => Ok(CoreValue::Bool(*value)),
        MachineOperand::I64(value) => Ok(CoreValue::I64(*value)),
        MachineOperand::F64Bits(bits) => Ok(CoreValue::F64(f64::from_bits(*bits))),
        MachineOperand::Register(register) => registers
            .get(register.0 as usize)
            .and_then(Clone::clone)
            .ok_or_else(|| {
                MachineIrEvaluator::invariant(format!(
                    "verified register {} is unavailable",
                    register.0
                ))
            }),
    }
}

fn expect_machine_i64(value: CoreValue) -> Result<i64, MachineIrExecutionError> {
    let CoreValue::I64(value) = value else {
        return Err(MachineIrEvaluator::invariant("expected I64 value"));
    };
    Ok(value)
}

fn expect_machine_f64(value: CoreValue) -> Result<f64, MachineIrExecutionError> {
    let CoreValue::F64(value) = value else {
        return Err(MachineIrEvaluator::invariant("expected F64 value"));
    };
    Ok(value)
}

fn machine_arguments_match_parameters(
    arguments: &[CoreValue],
    parameters: &[MachineParameter],
) -> bool {
    arguments.len() == parameters.len()
        && arguments
            .iter()
            .zip(parameters)
            .all(|(value, parameter)| machine_value_matches(value, parameter.ty))
}

fn machine_value_matches(value: &CoreValue, ty: MachineType) -> bool {
    matches!(
        (value, ty),
        (CoreValue::Unit, MachineType::Unit)
            | (CoreValue::Bool(_), MachineType::Bool)
            | (CoreValue::I64(_), MachineType::I64)
            | (CoreValue::F64(_), MachineType::F64)
            | (CoreValue::ArrayF64(_), MachineType::F64Array)
    )
}

fn machine_value_kind(value: &CoreValue) -> &'static str {
    match value {
        CoreValue::Unit => "Unit",
        CoreValue::Bool(_) => "Bool",
        CoreValue::I64(_) => "I64",
        CoreValue::F64(_) => "F64",
        CoreValue::Tuple(_) => "Tuple",
        CoreValue::Sum { .. } => "Sum",
        CoreValue::ArrayF64(_) => "ArrayF64",
        CoreValue::Reference(_) => "Reference",
        CoreValue::Closure(_) => "Closure",
    }
}
