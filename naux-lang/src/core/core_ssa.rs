//! Canonical typed SSA handoff for the R1-S5 Residual-Core gate.
//!
//! This is deliberately separate from `vm::ssa`: it consumes verified
//! Core-N0 artifacts, preserves Core types/effects/numeric modes, and has its
//! own deterministic semantic identity.  R1-S5 is a correctness handoff, not
//! an optimizer or native-code claim.

use super::encoding::{canonical_f64_bits, sha256};
use super::interpret::{CoreValue, EffectEvent, Evaluation, EvaluationBudget, EvaluationOutcome};
use super::schema::{
    ConstructorType, CoreArtifact, CoreProfile, Effect, EffectRow, ErrorKind, Function, FunctionId,
    LocalId, Mutability, NumericMode, Operand, OperationSignature, Primitive, RValue, RegionId,
    SemanticHash, SumType, Term, Type,
};
use super::verify::{verify, VerificationErrors};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const CORE_SSA_SCHEMA_NAME: &str = "core-ssa";
pub const CORE_SSA_SCHEMA_VERSION: (u16, u16, u16) = (0, 1, 0);
pub const CORE_SSA_LOWERING_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);

pub const CORE_SSA_MAX_FUNCTIONS: u64 = 16_384;
pub const CORE_SSA_MAX_BLOCKS: u64 = 1_000_000;
pub const CORE_SSA_MAX_INSTRUCTIONS: u64 = 1_000_000;
pub const CORE_SSA_MAX_VALUES: u64 = 1_000_000;
pub const CORE_SSA_MAX_EDGES: u64 = 1_000_000;
pub const CORE_SSA_MAX_CFG_DEPTH: u32 = 512;
pub const CORE_SSA_MAX_SEMANTIC_BYTES: u64 = 64 * 1024 * 1024;
pub const CORE_SSA_MAX_LIVE_VALUE_SLOTS: u64 = 1_000_000;
pub const CORE_SSA_MAX_DIAGNOSTICS: usize = 256;
pub const CORE_SSA_MAX_ENVIRONMENT_COPY_WORK: u64 = 4_000_000;

const CORE_SSA_SEMANTIC_DOMAIN: &[u8] = b"NAUX:core-ssa:r1-s5:semantic:v1\0";
const MAX_SAFE_CALL_DEPTH: u32 = 256;
const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreSsaSchemaVersion {
    pub name: String,
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl CoreSsaSchemaVersion {
    pub fn r1_s5() -> Self {
        Self {
            name: CORE_SSA_SCHEMA_NAME.to_owned(),
            major: CORE_SSA_SCHEMA_VERSION.0,
            minor: CORE_SSA_SCHEMA_VERSION.1,
            patch: CORE_SSA_SCHEMA_VERSION.2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SsaBlockId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SsaValueId(pub u32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreSsaArtifact {
    pub program: CoreSsaProgram,
    pub semantic_hash: SemanticHash,
}

impl CoreSsaArtifact {
    pub fn seal(program: CoreSsaProgram) -> Result<Self, CoreSsaEncodeError> {
        let semantic_hash = core_ssa_semantic_hash(&program)?;
        Ok(Self {
            program,
            semantic_hash,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreSsaProgram {
    pub schema: CoreSsaSchemaVersion,
    pub lowering_policy_version: (u16, u16, u16),
    pub source_core_hash: SemanticHash,
    pub profile: CoreProfile,
    pub entry: FunctionId,
    pub functions: Vec<SsaFunction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsaFunction {
    pub id: FunctionId,
    pub region_parameters: Vec<RegionId>,
    pub parameters: Vec<SsaParameter>,
    pub effects: EffectRow,
    pub result: Type,
    pub entry_block: SsaBlockId,
    pub blocks: Vec<SsaBlock>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsaParameter {
    pub value: SsaValueId,
    pub ty: Type,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsaBlock {
    pub id: SsaBlockId,
    pub instructions: Vec<SsaInstruction>,
    pub terminator: SsaTerminator,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsaInstruction {
    pub result: SsaValueId,
    pub ty: Type,
    pub kind: SsaInstructionKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SsaInstructionKind {
    Copy(SsaOperand),
    Primitive {
        operation: Primitive,
        arguments: Vec<SsaOperand>,
    },
    Call {
        function: FunctionId,
        arguments: Vec<SsaOperand>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SsaOperand {
    Unit,
    Bool(bool),
    I64(i64),
    /// Canonical IEEE-754 bits. All NaNs use `0x7ff8_0000_0000_0000`;
    /// signed zero is preserved.
    F64Bits(u64),
    Value(SsaValueId),
}

impl SsaOperand {
    pub fn f64(value: f64) -> Self {
        Self::F64Bits(canonical_f64_bits(value))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SsaTerminator {
    Return(SsaOperand),
    Branch {
        condition: SsaOperand,
        then_block: SsaBlockId,
        else_block: SsaBlockId,
    },
    TailCall {
        function: FunctionId,
        arguments: Vec<SsaOperand>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreSsaEncodeError {
    LengthOverflow { field: &'static str, length: usize },
    NestingLimit { field: &'static str, limit: u32 },
    ByteLimit { limit: u64, actual: u64 },
}

impl fmt::Display for CoreSsaEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOverflow { field, length } => {
                write!(formatter, "{field} length {length} exceeds u32")
            }
            Self::NestingLimit { field, limit } => {
                write!(formatter, "{field} nesting exceeds {limit}")
            }
            Self::ByteLimit { limit, actual } => {
                write!(
                    formatter,
                    "Core SSA semantic encoding uses {actual} bytes; limit is {limit}"
                )
            }
        }
    }
}

impl std::error::Error for CoreSsaEncodeError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreSsaVerificationCode {
    InvalidSchema,
    InvalidPolicy,
    InvalidSourceProvenance,
    SemanticHashMismatch,
    EncodingFailure,
    NonCanonicalOrder,
    DuplicateId,
    MissingEntry,
    UnsupportedFeature,
    InvalidType,
    UnboundValue,
    TypeMismatch,
    InvalidCall,
    InvalidControlFlow,
    MissingEffect,
    StructuralLimit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreSsaVerificationError {
    pub code: CoreSsaVerificationCode,
    pub path: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreSsaVerificationErrors(pub Vec<CoreSsaVerificationError>);

impl fmt::Display for CoreSsaVerificationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} canonical Core SSA verification error(s)",
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

impl std::error::Error for CoreSsaVerificationErrors {}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedCoreSsaArtifact<'artifact> {
    artifact: &'artifact CoreSsaArtifact,
}

impl<'artifact> VerifiedCoreSsaArtifact<'artifact> {
    pub fn artifact(self) -> &'artifact CoreSsaArtifact {
        self.artifact
    }

    pub fn program(self) -> &'artifact CoreSsaProgram {
        &self.artifact.program
    }

    pub fn semantic_hash(self) -> SemanticHash {
        self.artifact.semantic_hash
    }

    pub fn source_core_hash(self) -> SemanticHash {
        self.artifact.program.source_core_hash
    }
}

/// Opaque proof that an SSA artifact is the exact deterministic translation
/// of a particular verified Residual-Core artifact.
#[derive(Clone, Copy, Debug)]
pub struct SourceBoundCoreSsaArtifact<'artifact, 'source> {
    verified: VerifiedCoreSsaArtifact<'artifact>,
    source: &'source CoreArtifact,
}

impl<'artifact, 'source> SourceBoundCoreSsaArtifact<'artifact, 'source> {
    pub fn artifact(self) -> &'artifact CoreSsaArtifact {
        self.verified.artifact()
    }

    pub fn program(self) -> &'artifact CoreSsaProgram {
        self.verified.program()
    }

    pub fn semantic_hash(self) -> SemanticHash {
        self.verified.semantic_hash()
    }

    pub fn source(self) -> &'source CoreArtifact {
        self.source
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreSsaLowerError {
    InvalidSource(VerificationErrors),
    UnsupportedSource { path: String, message: String },
    StructuralLimit { field: &'static str, limit: u64 },
    Encoding(CoreSsaEncodeError),
    InvalidOutput(CoreSsaVerificationErrors),
}

impl fmt::Display for CoreSsaLowerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSource(errors) => write!(formatter, "{errors}"),
            Self::UnsupportedSource { path, message } => {
                write!(formatter, "unsupported R1-S5 Core at {path}: {message}")
            }
            Self::StructuralLimit { field, limit } => {
                write!(formatter, "Core SSA lowering exceeds {field} limit {limit}")
            }
            Self::Encoding(error) => write!(formatter, "{error}"),
            Self::InvalidOutput(errors) => {
                write!(
                    formatter,
                    "lowerer produced invalid canonical Core SSA: {errors}"
                )
            }
        }
    }
}

impl std::error::Error for CoreSsaLowerError {}

impl From<CoreSsaEncodeError> for CoreSsaLowerError {
    fn from(error: CoreSsaEncodeError) -> Self {
        Self::Encoding(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreSsaSourceError {
    InvalidSource(VerificationErrors),
    InvalidSsa(CoreSsaVerificationErrors),
    TranslationFailed(CoreSsaLowerError),
    SourceHashMismatch {
        declared: SemanticHash,
        actual: SemanticHash,
    },
    SourceEnvelopeMismatch {
        field: &'static str,
    },
    TranslationMismatch {
        supplied: SemanticHash,
        replayed: SemanticHash,
    },
}

impl fmt::Display for CoreSsaSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSource(errors) => write!(formatter, "{errors}"),
            Self::InvalidSsa(errors) => write!(formatter, "{errors}"),
            Self::TranslationFailed(error) => write!(formatter, "{error}"),
            Self::SourceHashMismatch { declared, actual } => write!(
                formatter,
                "Core SSA source hash declares {declared}; supplied Core hash is {actual}"
            ),
            Self::SourceEnvelopeMismatch { field } => {
                write!(formatter, "Core SSA source {field} does not match supplied Core")
            }
            Self::TranslationMismatch { supplied, replayed } => write!(
                formatter,
                "Core SSA translation differs from deterministic replay: supplied {supplied}; replayed {replayed}"
            ),
        }
    }
}

impl std::error::Error for CoreSsaSourceError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreSsaExecutionError {
    InvalidArtifact(CoreSsaVerificationErrors),
    InvalidEntryArguments {
        expected: Vec<Type>,
        actual: Vec<&'static str>,
    },
    StepBudgetExceeded {
        limit: u64,
    },
    CallDepthExceeded {
        limit: u32,
    },
    LiveValueSlotsExceeded {
        limit: u64,
    },
    InternalInvariant(String),
}

impl fmt::Display for CoreSsaExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArtifact(errors) => write!(formatter, "{errors}"),
            Self::InvalidEntryArguments { expected, actual } => write!(
                formatter,
                "Core SSA entry argument mismatch: expected {expected:?}; found {actual:?}"
            ),
            Self::StepBudgetExceeded { limit } => {
                write!(formatter, "Core SSA evaluation exceeded {limit} steps")
            }
            Self::CallDepthExceeded { limit } => {
                write!(formatter, "Core SSA evaluation exceeded call depth {limit}")
            }
            Self::LiveValueSlotsExceeded { limit } => {
                write!(
                    formatter,
                    "Core SSA evaluation exceeded {limit} cumulative live value slots"
                )
            }
            Self::InternalInvariant(message) => {
                write!(formatter, "verified Core SSA invariant failed: {message}")
            }
        }
    }
}

impl std::error::Error for CoreSsaExecutionError {}

#[derive(Default)]
struct SsaEncoder {
    bytes: Vec<u8>,
    attempted_bytes: u64,
}

impl SsaEncoder {
    fn append(&mut self, bytes: &[u8]) {
        self.attempted_bytes = self.attempted_bytes.saturating_add(bytes.len() as u64);
        if self.attempted_bytes <= CORE_SSA_MAX_SEMANTIC_BYTES {
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

    fn length(&mut self, field: &'static str, length: usize) -> Result<(), CoreSsaEncodeError> {
        let length = u32::try_from(length)
            .map_err(|_| CoreSsaEncodeError::LengthOverflow { field, length })?;
        self.u32(length);
        Ok(())
    }

    fn string(&mut self, field: &'static str, value: &str) -> Result<(), CoreSsaEncodeError> {
        self.length(field, value.len())?;
        self.append(value.as_bytes());
        Ok(())
    }
}

pub fn core_ssa_semantic_bytes(program: &CoreSsaProgram) -> Result<Vec<u8>, CoreSsaEncodeError> {
    let mut encoder = SsaEncoder::default();
    encoder.append(CORE_SSA_SEMANTIC_DOMAIN);
    encoder.string("schema.name", &program.schema.name)?;
    encoder.u16(program.schema.major);
    encoder.u16(program.schema.minor);
    encoder.u16(program.schema.patch);
    encoder.u16(program.lowering_policy_version.0);
    encoder.u16(program.lowering_policy_version.1);
    encoder.u16(program.lowering_policy_version.2);
    encoder.append(&program.source_core_hash.0);
    encode_profile(&mut encoder, program.profile);
    encoder.u32(program.entry.0);
    encoder.length("program.functions", program.functions.len())?;
    for function in &program.functions {
        encode_ssa_function(&mut encoder, function)?;
    }
    let actual = encoder.attempted_bytes;
    if actual > CORE_SSA_MAX_SEMANTIC_BYTES {
        return Err(CoreSsaEncodeError::ByteLimit {
            limit: CORE_SSA_MAX_SEMANTIC_BYTES,
            actual,
        });
    }
    Ok(encoder.bytes)
}

pub fn core_ssa_semantic_hash(
    program: &CoreSsaProgram,
) -> Result<SemanticHash, CoreSsaEncodeError> {
    Ok(SemanticHash(sha256(&core_ssa_semantic_bytes(program)?)))
}

fn encode_profile(encoder: &mut SsaEncoder, profile: CoreProfile) {
    encoder.tag(match profile {
        CoreProfile::P1V0 => 0,
        CoreProfile::P1V1 => 1,
        CoreProfile::P1V2 => 2,
        CoreProfile::P1V3 => 3,
        CoreProfile::P1V4 => 4,
        CoreProfile::P1V5 => 5,
    });
}

fn encode_ssa_function(
    encoder: &mut SsaEncoder,
    function: &SsaFunction,
) -> Result<(), CoreSsaEncodeError> {
    encoder.u32(function.id.0);
    encoder.length(
        "function.region_parameters",
        function.region_parameters.len(),
    )?;
    for region in &function.region_parameters {
        encoder.u32(region.0);
    }
    encoder.length("function.parameters", function.parameters.len())?;
    for parameter in &function.parameters {
        encoder.u32(parameter.value.0);
        encode_type(encoder, &parameter.ty, 0)?;
    }
    encode_effect_row(encoder, &function.effects, 0)?;
    encode_type(encoder, &function.result, 0)?;
    encoder.u32(function.entry_block.0);
    encoder.length("function.blocks", function.blocks.len())?;
    for block in &function.blocks {
        encoder.u32(block.id.0);
        encoder.length("block.instructions", block.instructions.len())?;
        for instruction in &block.instructions {
            encoder.u32(instruction.result.0);
            encode_type(encoder, &instruction.ty, 0)?;
            encode_instruction_kind(encoder, &instruction.kind)?;
        }
        encode_terminator(encoder, &block.terminator)?;
    }
    Ok(())
}

fn encode_instruction_kind(
    encoder: &mut SsaEncoder,
    kind: &SsaInstructionKind,
) -> Result<(), CoreSsaEncodeError> {
    match kind {
        SsaInstructionKind::Copy(operand) => {
            encoder.tag(0);
            encode_operand(encoder, operand);
        }
        SsaInstructionKind::Primitive {
            operation,
            arguments,
        } => {
            encoder.tag(1);
            encode_primitive(encoder, operation);
            encode_operands(encoder, arguments)?;
        }
        SsaInstructionKind::Call {
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

fn encode_terminator(
    encoder: &mut SsaEncoder,
    terminator: &SsaTerminator,
) -> Result<(), CoreSsaEncodeError> {
    match terminator {
        SsaTerminator::Return(operand) => {
            encoder.tag(0);
            encode_operand(encoder, operand);
        }
        SsaTerminator::Branch {
            condition,
            then_block,
            else_block,
        } => {
            encoder.tag(1);
            encode_operand(encoder, condition);
            encoder.u32(then_block.0);
            encoder.u32(else_block.0);
        }
        SsaTerminator::TailCall {
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
    encoder: &mut SsaEncoder,
    operands: &[SsaOperand],
) -> Result<(), CoreSsaEncodeError> {
    encoder.length("operands", operands.len())?;
    for operand in operands {
        encode_operand(encoder, operand);
    }
    Ok(())
}

fn encode_operand(encoder: &mut SsaEncoder, operand: &SsaOperand) {
    match operand {
        SsaOperand::Unit => encoder.tag(0),
        SsaOperand::Bool(value) => {
            encoder.tag(1);
            encoder.tag(u8::from(*value));
        }
        SsaOperand::I64(value) => {
            encoder.tag(2);
            encoder.i64(*value);
        }
        SsaOperand::F64Bits(bits) => {
            encoder.tag(3);
            encoder.u64(*bits);
        }
        SsaOperand::Value(value) => {
            encoder.tag(4);
            encoder.u32(value.0);
        }
    }
}

fn encode_type(encoder: &mut SsaEncoder, ty: &Type, depth: u32) -> Result<(), CoreSsaEncodeError> {
    if depth > CORE_SSA_MAX_CFG_DEPTH {
        return Err(CoreSsaEncodeError::NestingLimit {
            field: "type",
            limit: CORE_SSA_MAX_CFG_DEPTH,
        });
    }
    match ty {
        Type::Unit => encoder.tag(0),
        Type::Bool => encoder.tag(1),
        Type::I64 => encoder.tag(2),
        Type::F64 => encoder.tag(3),
        Type::Text => encoder.tag(4),
        Type::Bytes => encoder.tag(5),
        Type::Tuple(fields) => {
            encoder.tag(6);
            encoder.length("type.tuple.fields", fields.len())?;
            for field in fields {
                encode_type(encoder, field, depth + 1)?;
            }
        }
        Type::Sum(sum) => {
            encoder.tag(7);
            encode_sum_type(encoder, sum, depth + 1)?;
        }
        Type::Array {
            region,
            mutability,
            element,
        } => {
            encoder.tag(8);
            encoder.u32(region.0);
            encode_mutability(encoder, *mutability);
            encode_type(encoder, element, depth + 1)?;
        }
        Type::Ref {
            region,
            mutability,
            element,
        } => {
            encoder.tag(9);
            encoder.u32(region.0);
            encode_mutability(encoder, *mutability);
            encode_type(encoder, element, depth + 1)?;
        }
        Type::Function {
            parameters,
            effects,
            result,
        } => {
            encoder.tag(10);
            encoder.length("type.function.parameters", parameters.len())?;
            for parameter in parameters {
                encode_type(encoder, parameter, depth + 1)?;
            }
            encode_effect_row(encoder, effects, depth + 1)?;
            encode_type(encoder, result, depth + 1)?;
        }
        Type::Closure {
            parameters,
            effects,
            result,
        } => {
            encoder.tag(11);
            encoder.length("type.closure.parameters", parameters.len())?;
            for parameter in parameters {
                encode_type(encoder, parameter, depth + 1)?;
            }
            encode_effect_row(encoder, effects, depth + 1)?;
            encode_type(encoder, result, depth + 1)?;
        }
    }
    Ok(())
}

fn encode_mutability(encoder: &mut SsaEncoder, mutability: Mutability) {
    encoder.tag(match mutability {
        Mutability::Read => 0,
        Mutability::Unique => 1,
        Mutability::Shared => 2,
    });
}

fn encode_sum_type(
    encoder: &mut SsaEncoder,
    sum: &SumType,
    depth: u32,
) -> Result<(), CoreSsaEncodeError> {
    encoder.string("sum.name", &sum.name)?;
    encoder.length("sum.constructors", sum.constructors.len())?;
    for constructor in &sum.constructors {
        encode_constructor_type(encoder, constructor, depth + 1)?;
    }
    Ok(())
}

fn encode_constructor_type(
    encoder: &mut SsaEncoder,
    constructor: &ConstructorType,
    depth: u32,
) -> Result<(), CoreSsaEncodeError> {
    encoder.string("constructor.name", &constructor.name)?;
    encoder.length("constructor.fields", constructor.fields.len())?;
    for field in &constructor.fields {
        encode_type(encoder, field, depth + 1)?;
    }
    Ok(())
}

fn encode_effect_row(
    encoder: &mut SsaEncoder,
    row: &EffectRow,
    depth: u32,
) -> Result<(), CoreSsaEncodeError> {
    encoder.length("effect_row.effects", row.effects.len())?;
    for effect in &row.effects {
        encode_effect(encoder, effect, depth + 1)?;
    }
    Ok(())
}

fn encode_effect(
    encoder: &mut SsaEncoder,
    effect: &Effect,
    depth: u32,
) -> Result<(), CoreSsaEncodeError> {
    match effect {
        Effect::State(region) => {
            encoder.tag(0);
            encoder.u32(region.0);
        }
        Effect::Alloc(region) => {
            encoder.tag(1);
            encoder.u32(region.0);
        }
        Effect::Error(error) => {
            encoder.tag(2);
            encode_error_kind(encoder, error);
        }
        Effect::Io => encoder.tag(3),
        Effect::Ffi(hash) => {
            encoder.tag(4);
            encoder.append(hash);
        }
        Effect::UnsafeMemory(hash) => {
            encoder.tag(5);
            encoder.append(hash);
        }
        Effect::Operation(operation) => {
            encoder.tag(6);
            encode_operation_signature(encoder, operation, depth + 1)?;
        }
    }
    Ok(())
}

fn encode_operation_signature(
    encoder: &mut SsaEncoder,
    operation: &OperationSignature,
    depth: u32,
) -> Result<(), CoreSsaEncodeError> {
    encoder.u32(operation.id.0);
    encoder.length("operation.parameters", operation.parameters.len())?;
    for parameter in &operation.parameters {
        encode_type(encoder, parameter, depth + 1)?;
    }
    encode_type(encoder, &operation.result, depth + 1)
}

fn encode_error_kind(encoder: &mut SsaEncoder, error: &ErrorKind) {
    match error {
        ErrorKind::Overflow => encoder.tag(0),
        ErrorKind::Bounds => encoder.tag(1),
        ErrorKind::DivisionByZero => encoder.tag(2),
        ErrorKind::User(id) => {
            encoder.tag(3);
            encoder.u32(*id);
        }
    }
}

fn encode_numeric_mode(encoder: &mut SsaEncoder, mode: NumericMode) {
    encoder.tag(match mode {
        NumericMode::Checked => 0,
        NumericMode::Wrapping => 1,
        NumericMode::Saturating => 2,
    });
}

fn encode_primitive(encoder: &mut SsaEncoder, primitive: &Primitive) {
    match primitive {
        Primitive::I64Add(mode) => {
            encoder.tag(0);
            encode_numeric_mode(encoder, *mode);
        }
        Primitive::I64Sub(mode) => {
            encoder.tag(1);
            encode_numeric_mode(encoder, *mode);
        }
        Primitive::I64Mul(mode) => {
            encoder.tag(2);
            encode_numeric_mode(encoder, *mode);
        }
        Primitive::F64Add => encoder.tag(3),
        Primitive::F64Sub => encoder.tag(4),
        Primitive::I64CmpLt => encoder.tag(5),
        Primitive::I64CmpGe => encoder.tag(6),
        Primitive::ArrayLenF64 => encoder.tag(7),
        Primitive::ArrayGetF64 => encoder.tag(8),
    }
}

/// Lower the verified, ordinary Residual-Core slice admitted by R1-S5.
///
/// The accepted slice is intentionally fail-closed: P1V0 scalar/read-only
/// F64-array types, empty or canonical Error(Bounds) rows, Let/If/TailCall/
/// Return terms, and Use/Primitive/direct-Call rvalues.
pub fn lower_core_ssa_r1_s5(source: &CoreArtifact) -> Result<CoreSsaArtifact, CoreSsaLowerError> {
    verify(source).map_err(CoreSsaLowerError::InvalidSource)?;
    if source.program.profile != CoreProfile::P1V0 {
        return Err(unsupported_source(
            "program.profile",
            "R1-S5 admits only CoreProfile::P1V0",
        ));
    }
    if source.program.functions.len() as u64 > CORE_SSA_MAX_FUNCTIONS {
        return Err(CoreSsaLowerError::StructuralLimit {
            field: "functions",
            limit: CORE_SSA_MAX_FUNCTIONS,
        });
    }
    validate_source_call_regions(source)?;

    let mut functions = Vec::with_capacity(source.program.functions.len());
    for (index, function) in source.program.functions.iter().enumerate() {
        if function.id != FunctionId(index as u32) {
            return Err(unsupported_source(
                format!("program.functions[{index}].id"),
                format!(
                    "R1-S5 function IDs must be dense; expected {index}, found {}",
                    function.id.0
                ),
            ));
        }
        functions.push(lower_function(
            function,
            &format!("program.functions[{index}]"),
        )?);
    }

    let artifact = CoreSsaArtifact::seal(CoreSsaProgram {
        schema: CoreSsaSchemaVersion::r1_s5(),
        lowering_policy_version: CORE_SSA_LOWERING_POLICY_VERSION,
        source_core_hash: source.semantic_hash,
        profile: source.program.profile,
        entry: source.program.entry,
        functions,
    })?;
    verify_core_ssa(&artifact).map_err(CoreSsaLowerError::InvalidOutput)?;
    Ok(artifact)
}

/// R1-S5 uses implicit, identity-preserving region arguments. It therefore
/// deliberately narrows ordinary Core admission: every callee region must
/// already be authorized by the caller, even when no value operand exposes
/// that region.
fn validate_source_call_regions(source: &CoreArtifact) -> Result<(), CoreSsaLowerError> {
    for (index, function) in source.program.functions.iter().enumerate() {
        let caller_regions: BTreeSet<RegionId> =
            function.region_parameters.iter().copied().collect();
        validate_term_call_regions(
            &function.body,
            &caller_regions,
            &source.program.functions,
            &format!("program.functions[{index}].body"),
        )?;
    }
    Ok(())
}

fn validate_term_call_regions(
    term: &Term,
    caller_regions: &BTreeSet<RegionId>,
    functions: &[Function],
    path: &str,
) -> Result<(), CoreSsaLowerError> {
    match term {
        Term::Let { value, next, .. } => {
            if let RValue::Call { function, .. } = value {
                validate_call_region_authority(
                    *function,
                    caller_regions,
                    functions,
                    &format!("{path}.value.function"),
                )?;
            }
            validate_term_call_regions(next, caller_regions, functions, &format!("{path}.next"))
        }
        Term::If {
            then_term,
            else_term,
            ..
        } => {
            validate_term_call_regions(
                then_term,
                caller_regions,
                functions,
                &format!("{path}.then"),
            )?;
            validate_term_call_regions(
                else_term,
                caller_regions,
                functions,
                &format!("{path}.else"),
            )
        }
        Term::TailCall { function, .. } => validate_call_region_authority(
            *function,
            caller_regions,
            functions,
            &format!("{path}.function"),
        ),
        Term::Return(_) => Ok(()),
        // These are rejected by the admitted-slice lowerer; there is no need
        // to interpret calls hidden inside unsupported control forms.
        Term::Case { .. } | Term::Region { .. } | Term::Handle { .. } => Ok(()),
    }
}

fn validate_call_region_authority(
    target: FunctionId,
    caller_regions: &BTreeSet<RegionId>,
    functions: &[Function],
    path: &str,
) -> Result<(), CoreSsaLowerError> {
    let Some(callee) = functions
        .binary_search_by_key(&target, |function| function.id)
        .ok()
        .map(|index| &functions[index])
    else {
        return Err(unsupported_source(
            path,
            format!("callee function {} does not exist", target.0),
        ));
    };
    if let Some(region) = callee
        .region_parameters
        .iter()
        .find(|region| !caller_regions.contains(region))
    {
        Err(unsupported_source(
            path,
            format!(
                "callee region {} is not authorized by the caller under the narrower R1-S5 rule",
                region.0
            ),
        ))
    } else {
        Ok(())
    }
}

fn unsupported_source(path: impl Into<String>, message: impl Into<String>) -> CoreSsaLowerError {
    CoreSsaLowerError::UnsupportedSource {
        path: path.into(),
        message: message.into(),
    }
}

fn lower_function(function: &Function, path: &str) -> Result<SsaFunction, CoreSsaLowerError> {
    validate_source_regions(
        &function.region_parameters,
        &format!("{path}.region_parameters"),
    )?;
    for (index, parameter) in function.parameters.iter().enumerate() {
        validate_source_type(
            &parameter.ty,
            &function.region_parameters,
            &format!("{path}.parameters[{index}].type"),
        )?;
    }
    validate_source_effects(&function.effects, &format!("{path}.effects"))?;
    validate_source_type(
        &function.result,
        &function.region_parameters,
        &format!("{path}.result"),
    )?;

    if function.parameters.len() as u64 > CORE_SSA_MAX_VALUES {
        return Err(CoreSsaLowerError::StructuralLimit {
            field: "values",
            limit: CORE_SSA_MAX_VALUES,
        });
    }

    let mut environment = BTreeMap::new();
    let mut parameters = Vec::with_capacity(function.parameters.len());
    for (index, parameter) in function.parameters.iter().enumerate() {
        let value = SsaValueId(index as u32);
        environment.insert(parameter.local, value);
        parameters.push(SsaParameter {
            value,
            ty: parameter.ty.clone(),
        });
    }

    let mut lowerer = FunctionLowerer {
        blocks: Vec::new(),
        next_value: function.parameters.len() as u64,
        instructions: 0,
        environment_copy_work: 0,
        regions: function.region_parameters.clone(),
        path,
    };
    let entry_block = lowerer.allocate_block()?;
    lowerer.lower_term(
        &function.body,
        entry_block,
        environment,
        Vec::new(),
        &format!("{path}.body"),
        0,
    )?;
    let blocks = lowerer
        .blocks
        .into_iter()
        .enumerate()
        .map(|(index, block)| {
            block.ok_or_else(|| {
                unsupported_source(
                    format!("{path}.blocks[{index}]"),
                    "internal lowering hole remained",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(SsaFunction {
        id: function.id,
        region_parameters: function.region_parameters.clone(),
        parameters,
        effects: function.effects.clone(),
        result: function.result.clone(),
        entry_block,
        blocks,
    })
}

struct FunctionLowerer<'path> {
    blocks: Vec<Option<SsaBlock>>,
    next_value: u64,
    instructions: u64,
    environment_copy_work: u64,
    regions: Vec<RegionId>,
    path: &'path str,
}

impl FunctionLowerer<'_> {
    fn allocate_block(&mut self) -> Result<SsaBlockId, CoreSsaLowerError> {
        if self.blocks.len() as u64 >= CORE_SSA_MAX_BLOCKS {
            return Err(CoreSsaLowerError::StructuralLimit {
                field: "blocks",
                limit: CORE_SSA_MAX_BLOCKS,
            });
        }
        let id =
            u32::try_from(self.blocks.len()).map_err(|_| CoreSsaLowerError::StructuralLimit {
                field: "blocks",
                limit: CORE_SSA_MAX_BLOCKS,
            })?;
        self.blocks.push(None);
        Ok(SsaBlockId(id))
    }

    fn allocate_value(&mut self) -> Result<SsaValueId, CoreSsaLowerError> {
        if self.next_value >= CORE_SSA_MAX_VALUES {
            return Err(CoreSsaLowerError::StructuralLimit {
                field: "values",
                limit: CORE_SSA_MAX_VALUES,
            });
        }
        let value =
            u32::try_from(self.next_value).map_err(|_| CoreSsaLowerError::StructuralLimit {
                field: "values",
                limit: CORE_SSA_MAX_VALUES,
            })?;
        self.next_value += 1;
        Ok(SsaValueId(value))
    }

    fn push_instruction(
        &mut self,
        instructions: &mut Vec<SsaInstruction>,
        instruction: SsaInstruction,
    ) -> Result<(), CoreSsaLowerError> {
        if self.instructions >= CORE_SSA_MAX_INSTRUCTIONS {
            return Err(CoreSsaLowerError::StructuralLimit {
                field: "instructions",
                limit: CORE_SSA_MAX_INSTRUCTIONS,
            });
        }
        self.instructions += 1;
        instructions.push(instruction);
        Ok(())
    }

    fn charge_environment_copy(&mut self, values: usize) -> Result<(), CoreSsaLowerError> {
        self.environment_copy_work = self
            .environment_copy_work
            .checked_add(values as u64)
            .ok_or(CoreSsaLowerError::StructuralLimit {
                field: "environment copy work",
                limit: CORE_SSA_MAX_ENVIRONMENT_COPY_WORK,
            })?;
        if self.environment_copy_work > CORE_SSA_MAX_ENVIRONMENT_COPY_WORK {
            return Err(CoreSsaLowerError::StructuralLimit {
                field: "environment copy work",
                limit: CORE_SSA_MAX_ENVIRONMENT_COPY_WORK,
            });
        }
        Ok(())
    }

    fn finish_block(
        &mut self,
        block: SsaBlockId,
        instructions: Vec<SsaInstruction>,
        terminator: SsaTerminator,
    ) -> Result<(), CoreSsaLowerError> {
        let slot = self
            .blocks
            .get_mut(block.0 as usize)
            .ok_or_else(|| unsupported_source(self.path, "allocated block disappeared"))?;
        if slot.is_some() {
            return Err(unsupported_source(self.path, "block was finished twice"));
        }
        *slot = Some(SsaBlock {
            id: block,
            instructions,
            terminator,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn lower_term(
        &mut self,
        term: &Term,
        block: SsaBlockId,
        mut environment: BTreeMap<LocalId, SsaValueId>,
        mut instructions: Vec<SsaInstruction>,
        path: &str,
        depth: u32,
    ) -> Result<(), CoreSsaLowerError> {
        if depth > CORE_SSA_MAX_CFG_DEPTH {
            return Err(CoreSsaLowerError::StructuralLimit {
                field: "term depth",
                limit: CORE_SSA_MAX_CFG_DEPTH as u64,
            });
        }
        match term {
            Term::Let {
                binder,
                ty,
                value,
                next,
            } => {
                validate_source_type(ty, &self.regions, &format!("{path}.type"))?;
                let result = self.allocate_value()?;
                let kind = self.lower_rvalue(value, &environment, &format!("{path}.value"))?;
                self.push_instruction(
                    &mut instructions,
                    SsaInstruction {
                        result,
                        ty: ty.clone(),
                        kind,
                    },
                )?;
                environment.insert(*binder, result);
                self.lower_term(
                    next,
                    block,
                    environment,
                    instructions,
                    &format!("{path}.next"),
                    depth + 1,
                )
            }
            Term::If {
                condition,
                then_term,
                else_term,
            } => {
                let condition =
                    lower_operand(condition, &environment, &format!("{path}.condition"))?;
                let then_block = self.allocate_block()?;
                self.charge_environment_copy(environment.len())?;
                self.lower_term(
                    then_term,
                    then_block,
                    environment.clone(),
                    Vec::new(),
                    &format!("{path}.then"),
                    depth + 1,
                )?;
                let else_block = self.allocate_block()?;
                self.lower_term(
                    else_term,
                    else_block,
                    environment,
                    Vec::new(),
                    &format!("{path}.else"),
                    depth + 1,
                )?;
                self.finish_block(
                    block,
                    instructions,
                    SsaTerminator::Branch {
                        condition,
                        then_block,
                        else_block,
                    },
                )
            }
            Term::TailCall {
                function,
                arguments,
            } => {
                let arguments =
                    lower_operands(arguments, &environment, &format!("{path}.arguments"))?;
                self.finish_block(
                    block,
                    instructions,
                    SsaTerminator::TailCall {
                        function: *function,
                        arguments,
                    },
                )
            }
            Term::Return(operand) => {
                let operand = lower_operand(operand, &environment, path)?;
                self.finish_block(block, instructions, SsaTerminator::Return(operand))
            }
            Term::Case { .. } => Err(unsupported_source(
                path,
                "Case is outside the R1-S5 Residual-Core handoff",
            )),
            Term::Region { .. } => Err(unsupported_source(
                path,
                "Region terms are outside the R1-S5 Residual-Core handoff",
            )),
            Term::Handle { .. } => Err(unsupported_source(
                path,
                "Handle terms are outside the R1-S5 Residual-Core handoff",
            )),
        }
    }

    fn lower_rvalue(
        &self,
        value: &RValue,
        environment: &BTreeMap<LocalId, SsaValueId>,
        path: &str,
    ) -> Result<SsaInstructionKind, CoreSsaLowerError> {
        match value {
            RValue::Use(operand) => Ok(SsaInstructionKind::Copy(lower_operand(
                operand,
                environment,
                path,
            )?)),
            RValue::Primitive {
                operation,
                arguments,
            } => {
                if matches!(
                    operation,
                    Primitive::I64Add(NumericMode::Checked)
                        | Primitive::I64Sub(NumericMode::Checked)
                        | Primitive::I64Mul(NumericMode::Checked)
                ) {
                    return Err(unsupported_source(
                        format!("{path}.operation"),
                        "Checked I64 is outside the exact R1-S4 residual envelope",
                    ));
                }
                Ok(SsaInstructionKind::Primitive {
                    operation: operation.clone(),
                    arguments: lower_operands(
                        arguments,
                        environment,
                        &format!("{path}.arguments"),
                    )?,
                })
            }
            RValue::Call {
                function,
                arguments,
            } => Ok(SsaInstructionKind::Call {
                function: *function,
                arguments: lower_operands(arguments, environment, &format!("{path}.arguments"))?,
            }),
            RValue::Tuple(_) => Err(unsupported_source(path, "Tuple rvalue")),
            RValue::Project { .. } => Err(unsupported_source(path, "Project rvalue")),
            RValue::Construct { .. } => Err(unsupported_source(path, "Construct rvalue")),
            RValue::RefAlloc { .. } => Err(unsupported_source(path, "RefAlloc rvalue")),
            RValue::RefLoad { .. } => Err(unsupported_source(path, "RefLoad rvalue")),
            RValue::RefStore { .. } => Err(unsupported_source(path, "RefStore rvalue")),
            RValue::PackClosure { .. } => Err(unsupported_source(path, "PackClosure rvalue")),
            RValue::CallClosure { .. } => Err(unsupported_source(path, "CallClosure rvalue")),
            RValue::Perform { .. } => Err(unsupported_source(path, "Perform rvalue")),
        }
    }
}

fn lower_operands(
    operands: &[Operand],
    environment: &BTreeMap<LocalId, SsaValueId>,
    path: &str,
) -> Result<Vec<SsaOperand>, CoreSsaLowerError> {
    operands
        .iter()
        .enumerate()
        .map(|(index, operand)| lower_operand(operand, environment, &format!("{path}[{index}]")))
        .collect()
}

fn lower_operand(
    operand: &Operand,
    environment: &BTreeMap<LocalId, SsaValueId>,
    path: &str,
) -> Result<SsaOperand, CoreSsaLowerError> {
    match operand {
        Operand::Unit => Ok(SsaOperand::Unit),
        Operand::Bool(value) => Ok(SsaOperand::Bool(*value)),
        Operand::I64(value) => Ok(SsaOperand::I64(*value)),
        Operand::F64(value) => Ok(SsaOperand::f64(*value)),
        Operand::Local(local) => environment
            .get(local)
            .copied()
            .map(SsaOperand::Value)
            .ok_or_else(|| unsupported_source(path, format!("local {} is not in scope", local.0))),
    }
}

fn validate_source_regions(regions: &[RegionId], path: &str) -> Result<(), CoreSsaLowerError> {
    if regions.is_empty() || regions == [RegionId(0)] {
        Ok(())
    } else {
        Err(unsupported_source(
            path,
            "R1-S5 admits only no region parameters or exactly RegionId(0)",
        ))
    }
}

fn validate_source_type(
    ty: &Type,
    regions: &[RegionId],
    path: &str,
) -> Result<(), CoreSsaLowerError> {
    match ty {
        Type::Unit | Type::Bool | Type::I64 | Type::F64 => Ok(()),
        Type::Array {
            region,
            mutability: Mutability::Read,
            element,
        } if **element == Type::F64 && *region == RegionId(0) && regions.contains(region) => Ok(()),
        Type::Array { .. } => Err(unsupported_source(
            path,
            "R1-S5 admits only read-only Array<F64, RegionId(0)>",
        )),
        _ => Err(unsupported_source(
            path,
            format!("type {ty:?} is outside the R1-S5 slice"),
        )),
    }
}

fn validate_source_effects(row: &EffectRow, path: &str) -> Result<(), CoreSsaLowerError> {
    if row.effects.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(unsupported_source(path, "effect row is not canonical"));
    }
    if row
        .effects
        .iter()
        .all(|effect| matches!(effect, Effect::Error(ErrorKind::Bounds)))
    {
        Ok(())
    } else {
        Err(unsupported_source(
            path,
            "R1-S5 admits only an empty row or Error(Bounds)",
        ))
    }
}

pub fn verify_core_ssa(
    artifact: &CoreSsaArtifact,
) -> Result<VerifiedCoreSsaArtifact<'_>, CoreSsaVerificationErrors> {
    let mut verifier = CoreSsaVerifier::new(&artifact.program);
    verifier.verify_envelope(artifact);
    verifier.verify_program();
    if verifier.errors.is_empty() {
        Ok(VerifiedCoreSsaArtifact { artifact })
    } else {
        Err(CoreSsaVerificationErrors(verifier.errors))
    }
}

/// Verify both the SSA artifact and its binding to the supplied Core source.
pub fn verify_core_ssa_source<'artifact, 'source>(
    artifact: &'artifact CoreSsaArtifact,
    source: &'source CoreArtifact,
) -> Result<SourceBoundCoreSsaArtifact<'artifact, 'source>, CoreSsaSourceError> {
    verify(source).map_err(CoreSsaSourceError::InvalidSource)?;
    let verified = verify_core_ssa(artifact).map_err(CoreSsaSourceError::InvalidSsa)?;
    if artifact.program.source_core_hash != source.semantic_hash {
        return Err(CoreSsaSourceError::SourceHashMismatch {
            declared: artifact.program.source_core_hash,
            actual: source.semantic_hash,
        });
    }
    if artifact.program.profile != source.program.profile {
        return Err(CoreSsaSourceError::SourceEnvelopeMismatch { field: "profile" });
    }
    if artifact.program.entry != source.program.entry {
        return Err(CoreSsaSourceError::SourceEnvelopeMismatch { field: "entry" });
    }
    if artifact.program.functions.len() != source.program.functions.len() {
        return Err(CoreSsaSourceError::SourceEnvelopeMismatch {
            field: "function count",
        });
    }
    for (ssa, core) in artifact
        .program
        .functions
        .iter()
        .zip(&source.program.functions)
    {
        let core_parameters: Vec<&Type> = core.parameters.iter().map(|value| &value.ty).collect();
        let ssa_parameters: Vec<&Type> = ssa.parameters.iter().map(|value| &value.ty).collect();
        if ssa.id != core.id
            || ssa.region_parameters != core.region_parameters
            || ssa_parameters != core_parameters
            || ssa.effects != core.effects
            || ssa.result != core.result
        {
            return Err(CoreSsaSourceError::SourceEnvelopeMismatch {
                field: "function signature",
            });
        }
    }

    // Source hashes and copied signatures are provenance metadata, not a
    // translation proof. Replay the deterministic lowering and compare the
    // canonical semantic encoding so a resealed behavior mutation cannot
    // masquerade as a translation of `source`.
    let replayed = lower_core_ssa_r1_s5(source).map_err(CoreSsaSourceError::TranslationFailed)?;
    let supplied_bytes = core_ssa_semantic_bytes(&artifact.program).map_err(|error| {
        CoreSsaSourceError::InvalidSsa(CoreSsaVerificationErrors(vec![CoreSsaVerificationError {
            code: CoreSsaVerificationCode::EncodingFailure,
            path: "program".to_owned(),
            message: error.to_string(),
        }]))
    })?;
    let replayed_bytes = core_ssa_semantic_bytes(&replayed.program).map_err(|error| {
        CoreSsaSourceError::InvalidSsa(CoreSsaVerificationErrors(vec![CoreSsaVerificationError {
            code: CoreSsaVerificationCode::EncodingFailure,
            path: "replayed.program".to_owned(),
            message: error.to_string(),
        }]))
    })?;
    if artifact.semantic_hash != replayed.semantic_hash || supplied_bytes != replayed_bytes {
        return Err(CoreSsaSourceError::TranslationMismatch {
            supplied: artifact.semantic_hash,
            replayed: replayed.semantic_hash,
        });
    }
    Ok(SourceBoundCoreSsaArtifact { verified, source })
}

struct CoreSsaVerifier<'program> {
    program: &'program CoreSsaProgram,
    functions: BTreeMap<FunctionId, &'program SsaFunction>,
    errors: Vec<CoreSsaVerificationError>,
    total_blocks: u64,
    total_instructions: u64,
    total_values: u64,
    total_edges: u64,
}

impl<'program> CoreSsaVerifier<'program> {
    fn new(program: &'program CoreSsaProgram) -> Self {
        Self {
            program,
            functions: BTreeMap::new(),
            errors: Vec::new(),
            total_blocks: 0,
            total_instructions: 0,
            total_values: 0,
            total_edges: 0,
        }
    }

    fn error(
        &mut self,
        code: CoreSsaVerificationCode,
        path: impl Into<String>,
        message: impl Into<String>,
    ) {
        if self.errors.len() + 1 < CORE_SSA_MAX_DIAGNOSTICS {
            self.errors.push(CoreSsaVerificationError {
                code,
                path: path.into(),
                message: message.into(),
            });
        } else if self.errors.len() < CORE_SSA_MAX_DIAGNOSTICS {
            self.errors.push(CoreSsaVerificationError {
                code: CoreSsaVerificationCode::StructuralLimit,
                path: "program".to_owned(),
                message: format!("verification diagnostics capped at {CORE_SSA_MAX_DIAGNOSTICS}"),
            });
        }
    }

    fn diagnostics_full(&self) -> bool {
        self.errors.len() >= CORE_SSA_MAX_DIAGNOSTICS
    }

    fn verify_envelope(&mut self, artifact: &CoreSsaArtifact) {
        let schema = &artifact.program.schema;
        if schema.name != CORE_SSA_SCHEMA_NAME
            || (schema.major, schema.minor, schema.patch) != CORE_SSA_SCHEMA_VERSION
        {
            self.error(
                CoreSsaVerificationCode::InvalidSchema,
                "program.schema",
                format!(
                    "expected {CORE_SSA_SCHEMA_NAME} {}.{}.{}; found {} {}.{}.{}",
                    CORE_SSA_SCHEMA_VERSION.0,
                    CORE_SSA_SCHEMA_VERSION.1,
                    CORE_SSA_SCHEMA_VERSION.2,
                    schema.name,
                    schema.major,
                    schema.minor,
                    schema.patch
                ),
            );
        }
        if artifact.program.lowering_policy_version != CORE_SSA_LOWERING_POLICY_VERSION {
            self.error(
                CoreSsaVerificationCode::InvalidPolicy,
                "program.lowering_policy_version",
                format!(
                    "expected {:?}; found {:?}",
                    CORE_SSA_LOWERING_POLICY_VERSION, artifact.program.lowering_policy_version
                ),
            );
        }
        if artifact.program.source_core_hash == SemanticHash::ZERO {
            self.error(
                CoreSsaVerificationCode::InvalidSourceProvenance,
                "program.source_core_hash",
                "source Core semantic hash must not be zero",
            );
        }
        match core_ssa_semantic_hash(&artifact.program) {
            Ok(actual) if actual != artifact.semantic_hash => self.error(
                CoreSsaVerificationCode::SemanticHashMismatch,
                "artifact.semantic_hash",
                format!("declared {}; computed {actual}", artifact.semantic_hash),
            ),
            Ok(_) => {}
            Err(error) => self.error(
                CoreSsaVerificationCode::EncodingFailure,
                "program",
                error.to_string(),
            ),
        }
    }

    fn verify_program(&mut self) {
        if self.diagnostics_full() {
            return;
        }
        if self.program.profile != CoreProfile::P1V0 {
            self.error(
                CoreSsaVerificationCode::UnsupportedFeature,
                "program.profile",
                "R1-S5 canonical Core SSA admits only CoreProfile::P1V0",
            );
        }
        if self.program.functions.is_empty() {
            self.error(
                CoreSsaVerificationCode::MissingEntry,
                "program.functions",
                "program must contain at least one function",
            );
        }
        let within_structural_limits = self.preflight_counts();
        if !within_structural_limits {
            return;
        }
        for pair in self.program.functions.windows(2) {
            if self.diagnostics_full() {
                return;
            }
            if pair[0].id >= pair[1].id {
                self.error(
                    CoreSsaVerificationCode::NonCanonicalOrder,
                    "program.functions",
                    "function IDs must be strictly increasing",
                );
            }
        }
        for (index, function) in self.program.functions.iter().enumerate() {
            if self.diagnostics_full() {
                return;
            }
            if function.id != FunctionId(index as u32) {
                self.error(
                    CoreSsaVerificationCode::NonCanonicalOrder,
                    format!("program.functions[{index}].id"),
                    format!(
                        "function IDs must be dense; expected {index}, found {}",
                        function.id.0
                    ),
                );
            }
            if self.functions.insert(function.id, function).is_some() {
                self.error(
                    CoreSsaVerificationCode::DuplicateId,
                    format!("program.functions[{index}].id"),
                    format!("duplicate function ID {}", function.id.0),
                );
            }
        }
        if !self.functions.contains_key(&self.program.entry) {
            self.error(
                CoreSsaVerificationCode::MissingEntry,
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
        self.total_values = 0;
        self.total_edges = 0;
        for function in &self.program.functions {
            // Saturation is a fail-closed overflow marker: every hard cap is
            // below u64::MAX, so it necessarily becomes a StructuralLimit.
            self.total_blocks = self
                .total_blocks
                .saturating_add(function.blocks.len() as u64);
            self.total_values = self
                .total_values
                .saturating_add(function.parameters.len() as u64);
            for block in &function.blocks {
                let instructions = block.instructions.len() as u64;
                self.total_instructions = self.total_instructions.saturating_add(instructions);
                self.total_values = self.total_values.saturating_add(instructions);
                if matches!(block.terminator, SsaTerminator::Branch { .. }) {
                    self.total_edges = self.total_edges.saturating_add(2);
                }
            }
        }
        let limits = [
            (
                self.program.functions.len() as u64,
                CORE_SSA_MAX_FUNCTIONS,
                "functions",
            ),
            (self.total_blocks, CORE_SSA_MAX_BLOCKS, "blocks"),
            (
                self.total_instructions,
                CORE_SSA_MAX_INSTRUCTIONS,
                "instructions",
            ),
            (self.total_values, CORE_SSA_MAX_VALUES, "values"),
            (self.total_edges, CORE_SSA_MAX_EDGES, "CFG edges"),
        ];
        let mut within = true;
        for (actual, limit, name) in limits {
            if actual > limit {
                within = false;
                self.error(
                    CoreSsaVerificationCode::StructuralLimit,
                    "program.functions",
                    format!("{name} count {actual} exceeds {limit}"),
                );
            }
        }
        within
    }

    fn verify_function(&mut self, function: &SsaFunction, path: &str) {
        if self.diagnostics_full() {
            return;
        }
        self.verify_regions(
            &function.region_parameters,
            &format!("{path}.region_parameters"),
        );
        let regions: BTreeSet<RegionId> = function.region_parameters.iter().copied().collect();
        self.verify_effect_row(&function.effects, &format!("{path}.effects"));
        self.verify_type(&function.result, &regions, &format!("{path}.result"));

        let mut environment = BTreeMap::new();
        for (index, parameter) in function.parameters.iter().enumerate() {
            if self.diagnostics_full() {
                return;
            }
            let expected = SsaValueId(index as u32);
            if parameter.value != expected {
                self.error(
                    CoreSsaVerificationCode::NonCanonicalOrder,
                    format!("{path}.parameters[{index}].value"),
                    format!(
                        "parameter value IDs must start at zero; expected {}, found {}",
                        expected.0, parameter.value.0
                    ),
                );
            }
            self.verify_type(
                &parameter.ty,
                &regions,
                &format!("{path}.parameters[{index}].type"),
            );
            if environment
                .insert(parameter.value, parameter.ty.clone())
                .is_some()
            {
                self.error(
                    CoreSsaVerificationCode::DuplicateId,
                    format!("{path}.parameters[{index}].value"),
                    format!("duplicate value ID {}", parameter.value.0),
                );
            }
        }

        if function.blocks.is_empty() {
            self.error(
                CoreSsaVerificationCode::InvalidControlFlow,
                format!("{path}.blocks"),
                "function must contain an entry block",
            );
            return;
        }
        if function.entry_block != SsaBlockId(0) {
            self.error(
                CoreSsaVerificationCode::NonCanonicalOrder,
                format!("{path}.entry_block"),
                "canonical entry block must be block 0",
            );
        }

        let mut expected_value = function.parameters.len() as u64;
        let mut incoming = vec![0_u32; function.blocks.len()];
        for (block_index, block) in function.blocks.iter().enumerate() {
            if self.diagnostics_full() {
                return;
            }
            let block_path = format!("{path}.blocks[{block_index}]");
            if block.id != SsaBlockId(block_index as u32) {
                self.error(
                    CoreSsaVerificationCode::NonCanonicalOrder,
                    format!("{block_path}.id"),
                    format!(
                        "block IDs must equal canonical vector positions; expected {block_index}, found {}",
                        block.id.0
                    ),
                );
            }
            for (instruction_index, instruction) in block.instructions.iter().enumerate() {
                if self.diagnostics_full() {
                    return;
                }
                if u64::from(instruction.result.0) != expected_value {
                    self.error(
                        CoreSsaVerificationCode::NonCanonicalOrder,
                        format!(
                            "{block_path}.instructions[{instruction_index}].result"
                        ),
                        format!(
                            "value IDs must be contiguous in canonical block order; expected {expected_value}, found {}",
                            instruction.result.0
                        ),
                    );
                }
                expected_value = expected_value.saturating_add(1);
            }
            if let SsaTerminator::Branch {
                then_block,
                else_block,
                ..
            } = block.terminator
            {
                if then_block == else_block {
                    self.error(
                        CoreSsaVerificationCode::InvalidControlFlow,
                        format!("{block_path}.terminator"),
                        "branch targets must be distinct",
                    );
                }
                for (label, target) in [("then_block", then_block), ("else_block", else_block)] {
                    match incoming.get_mut(target.0 as usize) {
                        Some(count) => *count = count.saturating_add(1),
                        None => self.error(
                            CoreSsaVerificationCode::InvalidControlFlow,
                            format!("{block_path}.terminator.{label}"),
                            format!("target block {} does not exist", target.0),
                        ),
                    }
                }
            }
        }
        if incoming.first().copied().unwrap_or_default() != 0 {
            self.error(
                CoreSsaVerificationCode::InvalidControlFlow,
                format!("{path}.blocks[0]"),
                "entry block must not have incoming edges",
            );
        }
        for (index, count) in incoming.iter().enumerate().skip(1) {
            if self.diagnostics_full() {
                return;
            }
            if *count != 1 {
                self.error(
                    CoreSsaVerificationCode::InvalidControlFlow,
                    format!("{path}.blocks[{index}]"),
                    format!(
                        "canonical branch tree requires exactly one incoming edge; found {count}"
                    ),
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
                CoreSsaVerificationCode::InvalidControlFlow,
                format!("{path}.blocks"),
                format!(
                    "{} of {} blocks are reachable",
                    reached.len(),
                    function.blocks.len()
                ),
            );
        }
        let expected_preorder: Vec<SsaBlockId> = (0..function.blocks.len())
            .map(|index| SsaBlockId(index as u32))
            .collect();
        if preorder != expected_preorder {
            self.error(
                CoreSsaVerificationCode::NonCanonicalOrder,
                format!("{path}.blocks"),
                "blocks must be stored in then-first depth-first preorder",
            );
        }

        let mut typed_reached = BTreeSet::new();
        self.verify_block_tree(
            function,
            function.entry_block,
            &mut environment,
            &regions,
            0,
            &mut typed_reached,
            path,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_block_tree(
        &mut self,
        function: &SsaFunction,
        block_id: SsaBlockId,
        environment: &mut BTreeMap<SsaValueId, Type>,
        regions: &BTreeSet<RegionId>,
        depth: u32,
        reached: &mut BTreeSet<SsaBlockId>,
        function_path: &str,
    ) {
        if self.diagnostics_full() {
            return;
        }
        if depth > CORE_SSA_MAX_CFG_DEPTH {
            self.error(
                CoreSsaVerificationCode::StructuralLimit,
                format!("{function_path}.blocks"),
                format!("CFG depth exceeds {CORE_SSA_MAX_CFG_DEPTH}"),
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
            self.verify_type(
                &instruction.ty,
                regions,
                &format!("{instruction_path}.type"),
            );
            let actual = self.instruction_type(
                &instruction.kind,
                environment,
                regions,
                &function.effects,
                &instruction_path,
            );
            if let Some(actual) = actual {
                self.expect_type(
                    &instruction.ty,
                    &actual,
                    &format!("{instruction_path}.type"),
                );
            }
            match environment.entry(instruction.result) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(instruction.ty.clone());
                    defined_here.push(instruction.result);
                }
                std::collections::btree_map::Entry::Occupied(_) => {
                    self.error(
                        CoreSsaVerificationCode::DuplicateId,
                        format!("{instruction_path}.result"),
                        format!("value {} is defined more than once", instruction.result.0),
                    );
                }
            }
        }

        match &block.terminator {
            SsaTerminator::Return(operand) => {
                if let Some(actual) =
                    self.operand_type(operand, environment, &format!("{path}.terminator"))
                {
                    self.expect_type(&function.result, &actual, &format!("{path}.terminator"));
                }
            }
            SsaTerminator::Branch {
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
                        &Type::Bool,
                        &actual,
                        &format!("{path}.terminator.condition"),
                    );
                }
                self.verify_block_tree(
                    function,
                    *then_block,
                    environment,
                    regions,
                    depth + 1,
                    reached,
                    function_path,
                );
                if self.diagnostics_full() {
                    return;
                }
                self.verify_block_tree(
                    function,
                    *else_block,
                    environment,
                    regions,
                    depth + 1,
                    reached,
                    function_path,
                );
            }
            SsaTerminator::TailCall {
                function: target,
                arguments,
            } => {
                if let Some(result) = self.verify_call(
                    *target,
                    arguments,
                    environment,
                    regions,
                    &function.effects,
                    &format!("{path}.terminator"),
                ) {
                    self.expect_type(&function.result, &result, &format!("{path}.terminator"));
                }
            }
        }
        for value in defined_here {
            environment.remove(&value);
        }
    }

    fn collect_preorder(
        &mut self,
        function: &SsaFunction,
        block: SsaBlockId,
        depth: u32,
        reached: &mut BTreeSet<SsaBlockId>,
        order: &mut Vec<SsaBlockId>,
        path: &str,
    ) {
        if self.diagnostics_full() {
            return;
        }
        if depth > CORE_SSA_MAX_CFG_DEPTH {
            self.error(
                CoreSsaVerificationCode::StructuralLimit,
                format!("{path}.blocks"),
                format!("CFG depth exceeds {CORE_SSA_MAX_CFG_DEPTH}"),
            );
            return;
        }
        if !reached.insert(block) {
            self.error(
                CoreSsaVerificationCode::InvalidControlFlow,
                format!("{path}.blocks[{}]", block.0),
                "cycle or multiply reached block",
            );
            return;
        }
        let Some(current) = function.blocks.get(block.0 as usize) else {
            return;
        };
        order.push(block);
        if let SsaTerminator::Branch {
            then_block,
            else_block,
            ..
        } = current.terminator
        {
            self.collect_preorder(function, then_block, depth + 1, reached, order, path);
            if self.diagnostics_full() {
                return;
            }
            self.collect_preorder(function, else_block, depth + 1, reached, order, path);
        }
    }

    fn instruction_type(
        &mut self,
        kind: &SsaInstructionKind,
        environment: &BTreeMap<SsaValueId, Type>,
        regions: &BTreeSet<RegionId>,
        effects: &EffectRow,
        path: &str,
    ) -> Option<Type> {
        match kind {
            SsaInstructionKind::Copy(operand) => {
                self.operand_type(operand, environment, &format!("{path}.operand"))
            }
            SsaInstructionKind::Primitive {
                operation,
                arguments,
            } => self.primitive_type(operation, arguments, environment, effects, path),
            SsaInstructionKind::Call {
                function,
                arguments,
            } => self.verify_call(*function, arguments, environment, regions, effects, path),
        }
    }

    fn primitive_type(
        &mut self,
        operation: &Primitive,
        arguments: &[SsaOperand],
        environment: &BTreeMap<SsaValueId, Type>,
        effects: &EffectRow,
        path: &str,
    ) -> Option<Type> {
        let (expected, result) = match operation {
            Primitive::I64Add(mode) | Primitive::I64Sub(mode) | Primitive::I64Mul(mode) => {
                if *mode == NumericMode::Checked {
                    self.error(
                        CoreSsaVerificationCode::UnsupportedFeature,
                        format!("{path}.operation"),
                        "Checked I64 is outside the exact R1-S4 residual envelope",
                    );
                }
                (vec![Type::I64, Type::I64], Type::I64)
            }
            Primitive::F64Add | Primitive::F64Sub => (vec![Type::F64, Type::F64], Type::F64),
            Primitive::I64CmpLt | Primitive::I64CmpGe => (vec![Type::I64, Type::I64], Type::Bool),
            Primitive::ArrayLenF64 => {
                if arguments.len() != 1 {
                    self.invalid_arity(path, 1, arguments.len());
                    return None;
                }
                let actual =
                    self.operand_type(&arguments[0], environment, &format!("{path}.arguments[0]"))?;
                if !is_read_f64_array(&actual) {
                    self.error(
                        CoreSsaVerificationCode::TypeMismatch,
                        format!("{path}.arguments[0]"),
                        format!("expected read-only Array<F64>; found {actual:?}"),
                    );
                }
                return Some(Type::I64);
            }
            Primitive::ArrayGetF64 => {
                self.require_effect(
                    effects,
                    &Effect::Error(ErrorKind::Bounds),
                    &format!("{path}.operation"),
                );
                if arguments.len() != 2 {
                    self.invalid_arity(path, 2, arguments.len());
                    return None;
                }
                let array =
                    self.operand_type(&arguments[0], environment, &format!("{path}.arguments[0]"))?;
                if !is_read_f64_array(&array) {
                    self.error(
                        CoreSsaVerificationCode::TypeMismatch,
                        format!("{path}.arguments[0]"),
                        format!("expected read-only Array<F64>; found {array:?}"),
                    );
                }
                if let Some(index) =
                    self.operand_type(&arguments[1], environment, &format!("{path}.arguments[1]"))
                {
                    self.expect_type(&Type::I64, &index, &format!("{path}.arguments[1]"));
                }
                return Some(Type::F64);
            }
        };
        self.verify_arguments(
            arguments,
            &expected,
            environment,
            &format!("{path}.arguments"),
        );
        Some(result)
    }

    fn verify_call(
        &mut self,
        function: FunctionId,
        arguments: &[SsaOperand],
        environment: &BTreeMap<SsaValueId, Type>,
        caller_regions: &BTreeSet<RegionId>,
        caller_effects: &EffectRow,
        path: &str,
    ) -> Option<Type> {
        let Some(callee) = self.functions.get(&function).copied() else {
            self.error(
                CoreSsaVerificationCode::InvalidCall,
                format!("{path}.function"),
                format!("function {} does not exist", function.0),
            );
            return None;
        };
        let parameters: Vec<Type> = callee
            .parameters
            .iter()
            .map(|value| value.ty.clone())
            .collect();
        let callee_regions = callee.region_parameters.clone();
        let callee_effects = callee.effects.clone();
        let result = callee.result.clone();
        for region in callee_regions {
            if !caller_regions.contains(&region) {
                self.error(
                    CoreSsaVerificationCode::InvalidCall,
                    format!("{path}.function"),
                    format!("callee region {} is not authorized by the caller", region.0),
                );
            }
        }
        self.verify_arguments(
            arguments,
            &parameters,
            environment,
            &format!("{path}.arguments"),
        );
        for effect in &callee_effects.effects {
            self.require_effect(caller_effects, effect, &format!("{path}.function"));
        }
        Some(result)
    }

    fn verify_arguments(
        &mut self,
        arguments: &[SsaOperand],
        expected: &[Type],
        environment: &BTreeMap<SsaValueId, Type>,
        path: &str,
    ) {
        if arguments.len() != expected.len() {
            self.invalid_arity(path, expected.len(), arguments.len());
        }
        for (index, (argument, expected)) in arguments.iter().zip(expected).enumerate() {
            if self.diagnostics_full() {
                return;
            }
            if let Some(actual) =
                self.operand_type(argument, environment, &format!("{path}[{index}]"))
            {
                self.expect_type(expected, &actual, &format!("{path}[{index}]"));
            }
        }
    }

    fn invalid_arity(&mut self, path: &str, expected: usize, actual: usize) {
        self.error(
            CoreSsaVerificationCode::InvalidCall,
            path,
            format!("expected {expected} arguments; found {actual}"),
        );
    }

    fn operand_type(
        &mut self,
        operand: &SsaOperand,
        environment: &BTreeMap<SsaValueId, Type>,
        path: &str,
    ) -> Option<Type> {
        match operand {
            SsaOperand::Unit => Some(Type::Unit),
            SsaOperand::Bool(_) => Some(Type::Bool),
            SsaOperand::I64(_) => Some(Type::I64),
            SsaOperand::F64Bits(bits) => {
                if f64::from_bits(*bits).is_nan() && *bits != CANONICAL_NAN_BITS {
                    self.error(
                        CoreSsaVerificationCode::NonCanonicalOrder,
                        path,
                        format!("non-canonical NaN bits 0x{bits:016x}"),
                    );
                }
                Some(Type::F64)
            }
            SsaOperand::Value(value) => match environment.get(value) {
                Some(ty) => Some(ty.clone()),
                None => {
                    self.error(
                        CoreSsaVerificationCode::UnboundValue,
                        path,
                        format!("value {} does not dominate this use", value.0),
                    );
                    None
                }
            },
        }
    }

    fn expect_type(&mut self, expected: &Type, actual: &Type, path: &str) {
        if expected != actual {
            self.error(
                CoreSsaVerificationCode::TypeMismatch,
                path,
                format!("expected {expected:?}; found {actual:?}"),
            );
        }
    }

    fn require_effect(&mut self, row: &EffectRow, effect: &Effect, path: &str) {
        if !row.contains(effect) {
            self.error(
                CoreSsaVerificationCode::MissingEffect,
                path,
                format!("effect row is missing {effect:?}"),
            );
        }
    }

    fn verify_regions(&mut self, regions: &[RegionId], path: &str) {
        if !(regions.is_empty() || regions == [RegionId(0)]) {
            self.error(
                CoreSsaVerificationCode::UnsupportedFeature,
                path,
                "R1-S5 admits no regions or exactly RegionId(0)",
            );
        }
    }

    fn verify_effect_row(&mut self, row: &EffectRow, path: &str) {
        if row.effects.windows(2).any(|pair| pair[0] >= pair[1]) {
            self.error(
                CoreSsaVerificationCode::NonCanonicalOrder,
                path,
                "effect row must be strictly sorted and deduplicated",
            );
        }
        for (index, effect) in row.effects.iter().enumerate() {
            if self.diagnostics_full() {
                return;
            }
            if !matches!(effect, Effect::Error(ErrorKind::Bounds)) {
                self.error(
                    CoreSsaVerificationCode::UnsupportedFeature,
                    format!("{path}[{index}]"),
                    "R1-S5 admits only an empty row or Error(Bounds)",
                );
            }
        }
    }

    fn verify_type(&mut self, ty: &Type, regions: &BTreeSet<RegionId>, path: &str) {
        match ty {
            Type::Unit | Type::Bool | Type::I64 | Type::F64 => {}
            Type::Array {
                region,
                mutability: Mutability::Read,
                element,
            } if **element == Type::F64 && *region == RegionId(0) && regions.contains(region) => {}
            Type::Array { .. } => self.error(
                CoreSsaVerificationCode::InvalidType,
                path,
                "only read-only Array<F64, RegionId(0)> is admitted",
            ),
            _ => self.error(
                CoreSsaVerificationCode::UnsupportedFeature,
                path,
                format!("type {ty:?} is outside the R1-S5 slice"),
            ),
        }
    }
}

fn is_read_f64_array(ty: &Type) -> bool {
    matches!(
        ty,
        Type::Array {
            mutability: Mutability::Read,
            element,
            ..
        } if element.as_ref() == &Type::F64
    )
}

/// Structurally verify and evaluate a standalone canonical Core SSA artifact.
///
/// This establishes SSA-local safety only; it is not authority that the
/// artifact is a translation of any claimed Residual-Core source. H1/Gate
/// evidence must use `verify_core_ssa_source` and
/// `evaluate_source_bound_core_ssa`.
pub fn evaluate_core_ssa(
    artifact: &CoreSsaArtifact,
    arguments: Vec<CoreValue>,
    budget: EvaluationBudget,
) -> Result<Evaluation, CoreSsaExecutionError> {
    let verified = verify_core_ssa(artifact).map_err(CoreSsaExecutionError::InvalidArtifact)?;
    CoreSsaEvaluator::new(verified, budget).evaluate(arguments)
}

/// Evaluate an SSA artifact through an opaque deterministic source-binding
/// proof. The immutable references inside the token prevent either artifact
/// from changing after verification.
pub fn evaluate_source_bound_core_ssa(
    bound: SourceBoundCoreSsaArtifact<'_, '_>,
    arguments: Vec<CoreValue>,
    budget: EvaluationBudget,
) -> Result<Evaluation, CoreSsaExecutionError> {
    CoreSsaEvaluator::new(bound.verified, budget).evaluate(arguments)
}

/// Convenience entry point that regenerates and verifies the deterministic
/// translation before evaluation.
pub fn evaluate_core_ssa_translation(
    artifact: &CoreSsaArtifact,
    source: &CoreArtifact,
    arguments: Vec<CoreValue>,
    budget: EvaluationBudget,
) -> Result<Evaluation, CoreSsaTranslationExecutionError> {
    let bound = verify_core_ssa_source(artifact, source)
        .map_err(CoreSsaTranslationExecutionError::InvalidTranslation)?;
    evaluate_source_bound_core_ssa(bound, arguments, budget)
        .map_err(CoreSsaTranslationExecutionError::Execution)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreSsaTranslationExecutionError {
    InvalidTranslation(CoreSsaSourceError),
    Execution(CoreSsaExecutionError),
}

impl fmt::Display for CoreSsaTranslationExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTranslation(error) => write!(formatter, "{error}"),
            Self::Execution(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for CoreSsaTranslationExecutionError {}

struct CoreSsaEvaluator<'program> {
    verified: VerifiedCoreSsaArtifact<'program>,
    budget: EvaluationBudget,
    steps: u64,
    effect_trace: Vec<EffectEvent>,
    frame_slots: BTreeMap<FunctionId, usize>,
}

impl<'program> CoreSsaEvaluator<'program> {
    fn new(verified: VerifiedCoreSsaArtifact<'program>, budget: EvaluationBudget) -> Self {
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
        Self {
            verified,
            budget,
            steps: 0,
            effect_trace: Vec::new(),
            frame_slots,
        }
    }

    fn evaluate(mut self, arguments: Vec<CoreValue>) -> Result<Evaluation, CoreSsaExecutionError> {
        let entry = self.verified.program().entry;
        let function = self
            .find_function(entry)
            .ok_or_else(|| Self::invariant(format!("entry function {} disappeared", entry.0)))?;
        let expected: Vec<Type> = function
            .parameters
            .iter()
            .map(|value| value.ty.clone())
            .collect();
        if !arguments_match(&arguments, &expected) {
            return Err(CoreSsaExecutionError::InvalidEntryArguments {
                expected,
                actual: arguments.iter().map(value_kind).collect(),
            });
        }
        let outcome = self.run_machine(entry, arguments)?;
        Ok(Evaluation {
            outcome,
            steps: self.steps,
            effect_trace: self.effect_trace,
        })
    }

    fn run_machine(
        &mut self,
        entry: FunctionId,
        arguments: Vec<CoreValue>,
    ) -> Result<EvaluationOutcome, CoreSsaExecutionError> {
        let call_depth_limit = self.budget.max_call_depth.min(MAX_SAFE_CALL_DEPTH);
        let entry_slots = self.frame_slot_count(entry)?;
        if entry_slots as u64 > CORE_SSA_MAX_LIVE_VALUE_SLOTS {
            return Err(CoreSsaExecutionError::LiveValueSlotsExceeded {
                limit: CORE_SSA_MAX_LIVE_VALUE_SLOTS,
            });
        }
        let mut frame = self.new_frame(entry, arguments)?;
        let mut continuations: Vec<Continuation> = Vec::new();
        let mut live_value_slots = entry_slots as u64;

        loop {
            let block = self
                .find_function(frame.function)
                .and_then(|function| function.blocks.get(frame.block.0 as usize))
                .ok_or_else(|| {
                    Self::invariant(format!(
                        "missing function {} block {}",
                        frame.function.0, frame.block.0
                    ))
                })?;

            if let Some(instruction) = block.instructions.get(frame.next_instruction).cloned() {
                self.tick()?;
                frame.next_instruction += 1;
                match instruction.kind {
                    SsaInstructionKind::Copy(operand) => {
                        let value = eval_operand(&operand, &frame.values)?;
                        assign_value(&mut frame.values, instruction.result, value)?;
                    }
                    SsaInstructionKind::Primitive {
                        operation,
                        arguments,
                    } => {
                        let arguments = eval_operands(&arguments, &frame.values)?;
                        match eval_primitive(&operation, arguments)? {
                            PrimitiveComputation::Value(value) => {
                                assign_value(&mut frame.values, instruction.result, value)?;
                            }
                            PrimitiveComputation::Error(error) => {
                                self.effect_trace.push(EffectEvent::Error(error.clone()));
                                return Ok(EvaluationOutcome::Error(error));
                            }
                        }
                    }
                    SsaInstructionKind::Call {
                        function,
                        arguments,
                    } => {
                        let arguments = eval_operands(&arguments, &frame.values)?;
                        if continuations.len() as u32 >= call_depth_limit {
                            return Err(CoreSsaExecutionError::CallDepthExceeded {
                                limit: call_depth_limit,
                            });
                        }
                        let callee_slots = self.frame_slot_count(function)? as u64;
                        let projected = live_value_slots.checked_add(callee_slots).ok_or(
                            CoreSsaExecutionError::LiveValueSlotsExceeded {
                                limit: CORE_SSA_MAX_LIVE_VALUE_SLOTS,
                            },
                        )?;
                        if projected > CORE_SSA_MAX_LIVE_VALUE_SLOTS {
                            return Err(CoreSsaExecutionError::LiveValueSlotsExceeded {
                                limit: CORE_SSA_MAX_LIVE_VALUE_SLOTS,
                            });
                        }
                        continuations.push(Continuation {
                            caller: frame,
                            result: instruction.result,
                        });
                        frame = self.new_frame(function, arguments)?;
                        live_value_slots = projected;
                    }
                }
                continue;
            }

            let terminator = block.terminator.clone();
            self.tick()?;
            match terminator {
                SsaTerminator::Return(operand) => {
                    let value = eval_operand(&operand, &frame.values)?;
                    match continuations.pop() {
                        Some(continuation) => {
                            live_value_slots = live_value_slots
                                .checked_sub(frame.values.len() as u64)
                                .ok_or_else(|| {
                                    Self::invariant("live value-slot accounting underflow")
                                })?;
                            frame = continuation.caller;
                            assign_value(&mut frame.values, continuation.result, value)?;
                        }
                        None => return Ok(EvaluationOutcome::Return(value)),
                    }
                }
                SsaTerminator::Branch {
                    condition,
                    then_block,
                    else_block,
                } => {
                    let CoreValue::Bool(condition) = eval_operand(&condition, &frame.values)?
                    else {
                        return Err(Self::invariant("verified branch condition is not Bool"));
                    };
                    frame.block = if condition { then_block } else { else_block };
                    frame.next_instruction = 0;
                }
                SsaTerminator::TailCall {
                    function,
                    arguments,
                } => {
                    let arguments = eval_operands(&arguments, &frame.values)?;
                    let callee_slots = self.frame_slot_count(function)? as u64;
                    let projected = live_value_slots
                        .checked_sub(frame.values.len() as u64)
                        .and_then(|slots| slots.checked_add(callee_slots))
                        .ok_or(CoreSsaExecutionError::LiveValueSlotsExceeded {
                            limit: CORE_SSA_MAX_LIVE_VALUE_SLOTS,
                        })?;
                    if projected > CORE_SSA_MAX_LIVE_VALUE_SLOTS {
                        return Err(CoreSsaExecutionError::LiveValueSlotsExceeded {
                            limit: CORE_SSA_MAX_LIVE_VALUE_SLOTS,
                        });
                    }
                    // A tail call replaces the active frame and deliberately
                    // leaves the bounded continuation stack unchanged.
                    drop(frame);
                    frame = self.new_frame(function, arguments)?;
                    live_value_slots = projected;
                }
            }
        }
    }

    fn new_frame(
        &self,
        function_id: FunctionId,
        arguments: Vec<CoreValue>,
    ) -> Result<MachineFrame, CoreSsaExecutionError> {
        let function = self
            .find_function(function_id)
            .ok_or_else(|| Self::invariant(format!("missing function {}", function_id.0)))?;
        let expected: Vec<Type> = function
            .parameters
            .iter()
            .map(|value| value.ty.clone())
            .collect();
        if !arguments_match(&arguments, &expected) {
            return Err(Self::invariant(format!(
                "verified call to function {} has invalid arguments",
                function_id.0
            )));
        }
        let value_count = self.frame_slot_count(function_id)?;
        let mut values = vec![None; value_count];
        for (parameter, argument) in function.parameters.iter().zip(arguments) {
            let slot = values
                .get_mut(parameter.value.0 as usize)
                .ok_or_else(|| Self::invariant("parameter value slot is outside verified frame"))?;
            *slot = Some(argument);
        }
        Ok(MachineFrame {
            function: function_id,
            block: function.entry_block,
            next_instruction: 0,
            values,
        })
    }

    fn frame_slot_count(&self, function: FunctionId) -> Result<usize, CoreSsaExecutionError> {
        self.frame_slots.get(&function).copied().ok_or_else(|| {
            Self::invariant(format!(
                "missing frame-slot metadata for function {}",
                function.0
            ))
        })
    }

    fn find_function(&self, id: FunctionId) -> Option<&SsaFunction> {
        self.verified
            .program()
            .functions
            .binary_search_by_key(&id, |function| function.id)
            .ok()
            .map(|index| &self.verified.program().functions[index])
    }

    fn tick(&mut self) -> Result<(), CoreSsaExecutionError> {
        if self.steps >= self.budget.max_steps {
            return Err(CoreSsaExecutionError::StepBudgetExceeded {
                limit: self.budget.max_steps,
            });
        }
        self.steps += 1;
        Ok(())
    }

    fn invariant(message: impl Into<String>) -> CoreSsaExecutionError {
        CoreSsaExecutionError::InternalInvariant(message.into())
    }
}

struct MachineFrame {
    function: FunctionId,
    block: SsaBlockId,
    next_instruction: usize,
    values: Vec<Option<CoreValue>>,
}

struct Continuation {
    caller: MachineFrame,
    result: SsaValueId,
}

fn assign_value(
    values: &mut [Option<CoreValue>],
    result: SsaValueId,
    value: CoreValue,
) -> Result<(), CoreSsaExecutionError> {
    let slot = values.get_mut(result.0 as usize).ok_or_else(|| {
        CoreSsaExecutionError::InternalInvariant(format!(
            "result value {} is outside verified frame",
            result.0
        ))
    })?;
    *slot = Some(value);
    Ok(())
}

enum PrimitiveComputation {
    Value(CoreValue),
    Error(ErrorKind),
}

fn eval_operands(
    operands: &[SsaOperand],
    values: &[Option<CoreValue>],
) -> Result<Vec<CoreValue>, CoreSsaExecutionError> {
    operands
        .iter()
        .map(|operand| eval_operand(operand, values))
        .collect()
}

fn eval_operand(
    operand: &SsaOperand,
    values: &[Option<CoreValue>],
) -> Result<CoreValue, CoreSsaExecutionError> {
    match operand {
        SsaOperand::Unit => Ok(CoreValue::Unit),
        SsaOperand::Bool(value) => Ok(CoreValue::Bool(*value)),
        SsaOperand::I64(value) => Ok(CoreValue::I64(*value)),
        SsaOperand::F64Bits(bits) => Ok(CoreValue::F64(f64::from_bits(*bits))),
        SsaOperand::Value(value) => values
            .get(value.0 as usize)
            .and_then(Clone::clone)
            .ok_or_else(|| {
                CoreSsaEvaluator::invariant(format!("verified value {} is unavailable", value.0))
            }),
    }
}

fn eval_primitive(
    primitive: &Primitive,
    arguments: Vec<CoreValue>,
) -> Result<PrimitiveComputation, CoreSsaExecutionError> {
    match primitive {
        Primitive::I64Add(mode) => {
            let (left, right) = expect_i64_pair(arguments)?;
            Ok(match apply_i64(*mode, left, right, I64Operation::Add) {
                Ok(value) => PrimitiveComputation::Value(CoreValue::I64(value)),
                Err(error) => PrimitiveComputation::Error(error),
            })
        }
        Primitive::I64Sub(mode) => {
            let (left, right) = expect_i64_pair(arguments)?;
            Ok(match apply_i64(*mode, left, right, I64Operation::Sub) {
                Ok(value) => PrimitiveComputation::Value(CoreValue::I64(value)),
                Err(error) => PrimitiveComputation::Error(error),
            })
        }
        Primitive::I64Mul(mode) => {
            let (left, right) = expect_i64_pair(arguments)?;
            Ok(match apply_i64(*mode, left, right, I64Operation::Mul) {
                Ok(value) => PrimitiveComputation::Value(CoreValue::I64(value)),
                Err(error) => PrimitiveComputation::Error(error),
            })
        }
        Primitive::F64Add => {
            let (left, right) = expect_f64_pair(arguments)?;
            Ok(PrimitiveComputation::Value(CoreValue::F64(left + right)))
        }
        Primitive::F64Sub => {
            let (left, right) = expect_f64_pair(arguments)?;
            Ok(PrimitiveComputation::Value(CoreValue::F64(left - right)))
        }
        Primitive::I64CmpLt => {
            let (left, right) = expect_i64_pair(arguments)?;
            Ok(PrimitiveComputation::Value(CoreValue::Bool(left < right)))
        }
        Primitive::I64CmpGe => {
            let (left, right) = expect_i64_pair(arguments)?;
            Ok(PrimitiveComputation::Value(CoreValue::Bool(left >= right)))
        }
        Primitive::ArrayLenF64 => {
            let [CoreValue::ArrayF64(values)] = arguments.as_slice() else {
                return Err(CoreSsaEvaluator::invariant("ArrayLenF64 argument mismatch"));
            };
            let length = i64::try_from(values.len())
                .map_err(|_| CoreSsaEvaluator::invariant("array length does not fit I64"))?;
            Ok(PrimitiveComputation::Value(CoreValue::I64(length)))
        }
        Primitive::ArrayGetF64 => {
            let [CoreValue::ArrayF64(values), CoreValue::I64(index)] = arguments.as_slice() else {
                return Err(CoreSsaEvaluator::invariant("ArrayGetF64 argument mismatch"));
            };
            let Ok(index) = usize::try_from(*index) else {
                return Ok(PrimitiveComputation::Error(ErrorKind::Bounds));
            };
            Ok(match values.get(index) {
                Some(value) => PrimitiveComputation::Value(CoreValue::F64(*value)),
                None => PrimitiveComputation::Error(ErrorKind::Bounds),
            })
        }
    }
}

#[derive(Clone, Copy)]
enum I64Operation {
    Add,
    Sub,
    Mul,
}

fn apply_i64(
    mode: NumericMode,
    left: i64,
    right: i64,
    operation: I64Operation,
) -> Result<i64, ErrorKind> {
    match (mode, operation) {
        (NumericMode::Checked, I64Operation::Add) => {
            left.checked_add(right).ok_or(ErrorKind::Overflow)
        }
        (NumericMode::Checked, I64Operation::Sub) => {
            left.checked_sub(right).ok_or(ErrorKind::Overflow)
        }
        (NumericMode::Checked, I64Operation::Mul) => {
            left.checked_mul(right).ok_or(ErrorKind::Overflow)
        }
        (NumericMode::Wrapping, I64Operation::Add) => Ok(left.wrapping_add(right)),
        (NumericMode::Wrapping, I64Operation::Sub) => Ok(left.wrapping_sub(right)),
        (NumericMode::Wrapping, I64Operation::Mul) => Ok(left.wrapping_mul(right)),
        (NumericMode::Saturating, I64Operation::Add) => Ok(left.saturating_add(right)),
        (NumericMode::Saturating, I64Operation::Sub) => Ok(left.saturating_sub(right)),
        (NumericMode::Saturating, I64Operation::Mul) => Ok(left.saturating_mul(right)),
    }
}

fn expect_i64_pair(arguments: Vec<CoreValue>) -> Result<(i64, i64), CoreSsaExecutionError> {
    let [CoreValue::I64(left), CoreValue::I64(right)] = arguments.as_slice() else {
        return Err(CoreSsaEvaluator::invariant("expected two I64 arguments"));
    };
    Ok((*left, *right))
}

fn expect_f64_pair(arguments: Vec<CoreValue>) -> Result<(f64, f64), CoreSsaExecutionError> {
    let [CoreValue::F64(left), CoreValue::F64(right)] = arguments.as_slice() else {
        return Err(CoreSsaEvaluator::invariant("expected two F64 arguments"));
    };
    Ok((*left, *right))
}

fn arguments_match(arguments: &[CoreValue], expected: &[Type]) -> bool {
    arguments.len() == expected.len()
        && arguments
            .iter()
            .zip(expected)
            .all(|(value, ty)| value_matches(value, ty))
}

fn value_matches(value: &CoreValue, ty: &Type) -> bool {
    match (value, ty) {
        (CoreValue::Unit, Type::Unit)
        | (CoreValue::Bool(_), Type::Bool)
        | (CoreValue::I64(_), Type::I64)
        | (CoreValue::F64(_), Type::F64) => true,
        (CoreValue::ArrayF64(_), Type::Array { element, .. }) => element.as_ref() == &Type::F64,
        _ => false,
    }
}

fn value_kind(value: &CoreValue) -> &'static str {
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
