use super::encoding::{
    canonical_f64_bits, sha256, specialization_value_bytes, specialization_value_hash, EncodeError,
};
use super::schema::{ConstructorType, SemanticHash, SumType, Type};
use super::specialization::SpecializationValue;
use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;

const COREVM0_PROGRAM_DOMAIN: &[u8] = b"NAUX:corevm0:program:v1\0";

pub const COREVM0_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const COREVM0_MAX_INSTRUCTIONS: usize = 64;
pub const COREVM0_MAX_ARGUMENTS: usize = 8;
pub const COREVM0_MAX_LOCALS: usize = 16;
pub const COREVM0_MAX_STACK: usize = 16;

pub const COREVM0_INSTRUCTION_SUM_NAME: &str = "CoreVM0.Instruction.v1";
pub const COREVM0_PROGRAM_IMAGE_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const COREVM0_TYPE_SLOT_SUM_NAME: &str = "CoreVM0.TypeSlot.v1";
pub const COREVM0_INSTRUCTION_SLOT_SUM_NAME: &str = "CoreVM0.InstructionSlot.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CoreVmType {
    Bool,
    I64,
    F64,
    ArrayF64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CoreVmInstruction {
    ConstI64(i64),
    ConstF64(f64),
    LoadArg(u32),
    LoadLocal(u32),
    StoreLocal(u32),
    AddI64,
    SubI64,
    AddF64,
    SubF64,
    CmpLtI64,
    CmpGeI64,
    ArrayLenF64,
    ArrayGetF64,
    Jump(u32),
    JumpIfFalse(u32),
    ReturnF64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CoreVmProgram {
    pub schema_version: (u16, u16, u16),
    pub arguments: Vec<CoreVmType>,
    pub locals: Vec<CoreVmType>,
    pub max_stack: u32,
    pub instructions: Vec<CoreVmInstruction>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CoreVmCoreImage {
    pub ty: Type,
    pub value: SpecializationValue,
    pub program_hash: SemanticHash,
}

/// Opaque, canonical fixed-capacity image admitted by the Stage 3
/// definitional CoreVM0 boundary.
///
/// Unlike `CoreVmCoreImage`, this value binds the complete verified program
/// manifest as well as all 64 canonical instruction slots.
#[derive(Clone, Debug)]
pub struct CoreVmProgramImage {
    ty: Type,
    value: SpecializationValue,
    program_hash: SemanticHash,
    image_hash: SemanticHash,
}

impl PartialEq for CoreVmProgramImage {
    fn eq(&self, other: &Self) -> bool {
        if self.ty != other.ty
            || self.program_hash != other.program_hash
            || self.image_hash != other.image_hash
        {
            return false;
        }
        match (
            specialization_value_bytes(&self.value),
            specialization_value_bytes(&other.value),
        ) {
            (Ok(left), Ok(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for CoreVmProgramImage {}

impl CoreVmProgramImage {
    pub fn ty(&self) -> &Type {
        &self.ty
    }

    pub fn value(&self) -> &SpecializationValue {
        &self.value
    }

    pub fn program_hash(&self) -> SemanticHash {
        self.program_hash
    }

    pub fn image_hash(&self) -> SemanticHash {
        self.image_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreVmProgramImageVerificationError {
    InvalidProgram(CoreVmVerificationErrors),
    Encoding(EncodeError),
    ImageMismatch,
}

impl fmt::Display for CoreVmProgramImageVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProgram(errors) => write!(formatter, "{errors}"),
            Self::Encoding(error) => {
                write!(formatter, "CoreVM0 full image failed to encode: {error}")
            }
            Self::ImageMismatch => formatter
                .write_str("candidate CoreVM0 full image does not equal canonical regeneration"),
        }
    }
}

impl std::error::Error for CoreVmProgramImageVerificationError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreVmCoreImageError {
    InvalidProgram(CoreVmVerificationErrors),
    Encoding(EncodeError),
}

impl fmt::Display for CoreVmCoreImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProgram(errors) => {
                write!(formatter, "CoreVM0 image program is invalid: {errors}")
            }
            Self::Encoding(error) => write!(formatter, "CoreVM0 image failed to encode: {error}"),
        }
    }
}

impl std::error::Error for CoreVmCoreImageError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreVmVerificationCode {
    UnsupportedSchema,
    EmptyProgram,
    ProgramTooLarge,
    TooManyArguments,
    TooManyLocals,
    InvalidMaxStack,
    InvalidArgument,
    InvalidLocal,
    InvalidBranchTarget,
    StackUnderflow,
    StackTypeMismatch,
    StackJoinMismatch,
    LocalUninitialized,
    ReturnStackMismatch,
    Fallthrough,
    MissingReturn,
    UnreachableInstruction,
    MaxStackMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreVmVerificationError {
    pub code: CoreVmVerificationCode,
    pub pc: Option<u32>,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreVmVerificationErrors(pub Vec<CoreVmVerificationError>);

impl fmt::Display for CoreVmVerificationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} CoreVM0 verification error(s)", self.0.len())?;
        for error in &self.0 {
            match error.pc {
                Some(pc) => write!(
                    formatter,
                    "\n- {:?} at instruction {pc}: {}",
                    error.code, error.message
                )?,
                None => write!(formatter, "\n- {:?}: {}", error.code, error.message)?,
            }
        }
        Ok(())
    }
}

impl std::error::Error for CoreVmVerificationErrors {}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedCoreVmProgram<'program> {
    program: &'program CoreVmProgram,
}

impl<'program> VerifiedCoreVmProgram<'program> {
    pub fn program(&self) -> &'program CoreVmProgram {
        self.program
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum CoreVmValue {
    Bool(bool),
    I64(i64),
    F64(f64),
    ArrayF64(Arc<[f64]>),
}

impl CoreVmValue {
    pub fn array_f64(values: impl Into<Vec<f64>>) -> Self {
        Self::ArrayF64(Arc::from(values.into()))
    }

    pub fn ty(&self) -> CoreVmType {
        match self {
            Self::Bool(_) => CoreVmType::Bool,
            Self::I64(_) => CoreVmType::I64,
            Self::F64(_) => CoreVmType::F64,
            Self::ArrayF64(_) => CoreVmType::ArrayF64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreVmTypedError {
    Bounds,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CoreVmOutcome {
    ReturnF64(f64),
    Error(CoreVmTypedError),
}

#[derive(Clone, Debug, PartialEq)]
pub struct CoreVmEvaluation {
    pub program_hash: SemanticHash,
    pub outcome: CoreVmOutcome,
    pub steps: u64,
    pub effect_trace: Vec<CoreVmTypedError>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreVmExecutionError {
    ArgumentArity {
        expected: usize,
        actual: usize,
    },
    ArgumentType {
        index: u32,
        expected: CoreVmType,
        actual: CoreVmType,
    },
    StepBudgetExceeded {
        limit: u64,
        pc: u32,
    },
    Encoding(EncodeError),
    InternalInvariant {
        pc: u32,
        message: String,
    },
}

impl fmt::Display for CoreVmExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArgumentArity { expected, actual } => {
                write!(
                    formatter,
                    "CoreVM0 expected {expected} argument(s), found {actual}"
                )
            }
            Self::ArgumentType {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "CoreVM0 argument {index} expected {expected:?}, found {actual:?}"
            ),
            Self::StepBudgetExceeded { limit, pc } => {
                write!(
                    formatter,
                    "CoreVM0 exhausted step budget {limit} at pc {pc}"
                )
            }
            Self::Encoding(error) => write!(formatter, "CoreVM0 program encoding failed: {error}"),
            Self::InternalInvariant { pc, message } => {
                write!(
                    formatter,
                    "verified CoreVM0 invariant failed at pc {pc}: {message}"
                )
            }
        }
    }
}

impl std::error::Error for CoreVmExecutionError {}

impl From<EncodeError> for CoreVmExecutionError {
    fn from(error: EncodeError) -> Self {
        Self::Encoding(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AbstractState {
    stack: Vec<CoreVmType>,
    initialized: Vec<bool>,
}

pub fn verify_corevm0_program(
    program: &CoreVmProgram,
) -> Result<VerifiedCoreVmProgram<'_>, CoreVmVerificationErrors> {
    let mut errors = Vec::new();
    if program.schema_version != COREVM0_SCHEMA_VERSION {
        push_verification_error(
            &mut errors,
            CoreVmVerificationCode::UnsupportedSchema,
            None,
            format!(
                "expected schema {:?}, found {:?}",
                COREVM0_SCHEMA_VERSION, program.schema_version
            ),
        );
    }
    if program.instructions.is_empty() {
        push_verification_error(
            &mut errors,
            CoreVmVerificationCode::EmptyProgram,
            None,
            "program contains no instruction".to_owned(),
        );
    }
    if program.instructions.len() > COREVM0_MAX_INSTRUCTIONS {
        push_verification_error(
            &mut errors,
            CoreVmVerificationCode::ProgramTooLarge,
            None,
            format!(
                "program contains {} instructions; hard cap is {COREVM0_MAX_INSTRUCTIONS}",
                program.instructions.len()
            ),
        );
    }
    if program.arguments.len() > COREVM0_MAX_ARGUMENTS {
        push_verification_error(
            &mut errors,
            CoreVmVerificationCode::TooManyArguments,
            None,
            format!(
                "program declares {} arguments; hard cap is {COREVM0_MAX_ARGUMENTS}",
                program.arguments.len()
            ),
        );
    }
    if program.locals.len() > COREVM0_MAX_LOCALS {
        push_verification_error(
            &mut errors,
            CoreVmVerificationCode::TooManyLocals,
            None,
            format!(
                "program declares {} locals; hard cap is {COREVM0_MAX_LOCALS}",
                program.locals.len()
            ),
        );
    }
    if program.max_stack == 0 || program.max_stack as usize > COREVM0_MAX_STACK {
        push_verification_error(
            &mut errors,
            CoreVmVerificationCode::InvalidMaxStack,
            None,
            format!(
                "declared max_stack {} is outside 1..={COREVM0_MAX_STACK}",
                program.max_stack
            ),
        );
    }
    if !errors.is_empty() {
        return Err(CoreVmVerificationErrors(errors));
    }

    let instruction_count = program.instructions.len();
    let mut states = vec![None; instruction_count];
    states[0] = Some(AbstractState {
        stack: Vec::new(),
        initialized: vec![false; program.locals.len()],
    });
    let mut pending = VecDeque::from([0usize]);
    let mut maximum_stack = 0usize;
    let mut saw_return = false;

    while let Some(pc) = pending.pop_front() {
        let Some(mut state) = states[pc].clone() else {
            continue;
        };
        maximum_stack = maximum_stack.max(state.stack.len());
        let instruction = &program.instructions[pc];
        let mut successors = Vec::new();
        let mut transfer_valid = true;

        match instruction {
            CoreVmInstruction::ConstI64(_) => state.stack.push(CoreVmType::I64),
            CoreVmInstruction::ConstF64(_) => state.stack.push(CoreVmType::F64),
            CoreVmInstruction::LoadArg(index) => {
                let Some(ty) = program.arguments.get(*index as usize) else {
                    push_verification_error(
                        &mut errors,
                        CoreVmVerificationCode::InvalidArgument,
                        Some(pc as u32),
                        format!("argument index {index} is out of range"),
                    );
                    continue;
                };
                state.stack.push(*ty);
            }
            CoreVmInstruction::LoadLocal(index) => {
                let Some(ty) = program.locals.get(*index as usize) else {
                    push_verification_error(
                        &mut errors,
                        CoreVmVerificationCode::InvalidLocal,
                        Some(pc as u32),
                        format!("local index {index} is out of range"),
                    );
                    continue;
                };
                if !state.initialized[*index as usize] {
                    push_verification_error(
                        &mut errors,
                        CoreVmVerificationCode::LocalUninitialized,
                        Some(pc as u32),
                        format!("local {index} is not definitely initialized"),
                    );
                }
                state.stack.push(*ty);
            }
            CoreVmInstruction::StoreLocal(index) => {
                let Some(expected) = program.locals.get(*index as usize) else {
                    push_verification_error(
                        &mut errors,
                        CoreVmVerificationCode::InvalidLocal,
                        Some(pc as u32),
                        format!("local index {index} is out of range"),
                    );
                    continue;
                };
                transfer_valid &= pop_expected(&mut state.stack, *expected, pc, &mut errors);
                if transfer_valid {
                    state.initialized[*index as usize] = true;
                }
            }
            CoreVmInstruction::AddI64 | CoreVmInstruction::SubI64 => {
                transfer_valid &= pop_expected(&mut state.stack, CoreVmType::I64, pc, &mut errors);
                transfer_valid &= pop_expected(&mut state.stack, CoreVmType::I64, pc, &mut errors);
                if transfer_valid {
                    state.stack.push(CoreVmType::I64);
                }
            }
            CoreVmInstruction::AddF64 | CoreVmInstruction::SubF64 => {
                transfer_valid &= pop_expected(&mut state.stack, CoreVmType::F64, pc, &mut errors);
                transfer_valid &= pop_expected(&mut state.stack, CoreVmType::F64, pc, &mut errors);
                if transfer_valid {
                    state.stack.push(CoreVmType::F64);
                }
            }
            CoreVmInstruction::CmpLtI64 | CoreVmInstruction::CmpGeI64 => {
                transfer_valid &= pop_expected(&mut state.stack, CoreVmType::I64, pc, &mut errors);
                transfer_valid &= pop_expected(&mut state.stack, CoreVmType::I64, pc, &mut errors);
                if transfer_valid {
                    state.stack.push(CoreVmType::Bool);
                }
            }
            CoreVmInstruction::ArrayLenF64 => {
                transfer_valid &=
                    pop_expected(&mut state.stack, CoreVmType::ArrayF64, pc, &mut errors);
                if transfer_valid {
                    state.stack.push(CoreVmType::I64);
                }
            }
            CoreVmInstruction::ArrayGetF64 => {
                transfer_valid &= pop_expected(&mut state.stack, CoreVmType::I64, pc, &mut errors);
                transfer_valid &=
                    pop_expected(&mut state.stack, CoreVmType::ArrayF64, pc, &mut errors);
                if transfer_valid {
                    state.stack.push(CoreVmType::F64);
                }
            }
            CoreVmInstruction::Jump(target) => {
                transfer_valid &= valid_target(*target, instruction_count, pc, &mut errors);
                if transfer_valid {
                    successors.push(*target as usize);
                }
            }
            CoreVmInstruction::JumpIfFalse(target) => {
                transfer_valid &= pop_expected(&mut state.stack, CoreVmType::Bool, pc, &mut errors);
                transfer_valid &= valid_target(*target, instruction_count, pc, &mut errors);
                let fallthrough = pc + 1;
                if fallthrough == instruction_count {
                    push_verification_error(
                        &mut errors,
                        CoreVmVerificationCode::Fallthrough,
                        Some(pc as u32),
                        "conditional jump falls beyond the program".to_owned(),
                    );
                    transfer_valid = false;
                }
                if transfer_valid {
                    successors.push(*target as usize);
                    successors.push(fallthrough);
                }
            }
            CoreVmInstruction::ReturnF64 => {
                saw_return = true;
                transfer_valid &= pop_expected(&mut state.stack, CoreVmType::F64, pc, &mut errors);
                if transfer_valid && !state.stack.is_empty() {
                    push_verification_error(
                        &mut errors,
                        CoreVmVerificationCode::ReturnStackMismatch,
                        Some(pc as u32),
                        format!(
                            "ReturnF64 leaves {} value(s) below the result",
                            state.stack.len()
                        ),
                    );
                }
            }
        }

        maximum_stack = maximum_stack.max(state.stack.len());
        if !transfer_valid {
            continue;
        }
        if !matches!(
            instruction,
            CoreVmInstruction::Jump(_)
                | CoreVmInstruction::JumpIfFalse(_)
                | CoreVmInstruction::ReturnF64
        ) {
            let fallthrough = pc + 1;
            if fallthrough == instruction_count {
                push_verification_error(
                    &mut errors,
                    CoreVmVerificationCode::Fallthrough,
                    Some(pc as u32),
                    "instruction falls beyond the program".to_owned(),
                );
                continue;
            }
            successors.push(fallthrough);
        }

        for successor in successors {
            merge_state(successor, &state, &mut states, &mut pending, &mut errors);
        }
    }

    if !saw_return {
        push_verification_error(
            &mut errors,
            CoreVmVerificationCode::MissingReturn,
            None,
            "no reachable ReturnF64 instruction".to_owned(),
        );
    }
    for (pc, state) in states.iter().enumerate() {
        if state.is_none() {
            push_verification_error(
                &mut errors,
                CoreVmVerificationCode::UnreachableInstruction,
                Some(pc as u32),
                "canonical CoreVM0 programs contain no unreachable instruction".to_owned(),
            );
        }
    }
    if maximum_stack != program.max_stack as usize {
        push_verification_error(
            &mut errors,
            CoreVmVerificationCode::MaxStackMismatch,
            None,
            format!(
                "declared max_stack {}, verifier computed {maximum_stack}",
                program.max_stack
            ),
        );
    }

    if errors.is_empty() {
        Ok(VerifiedCoreVmProgram { program })
    } else {
        Err(CoreVmVerificationErrors(errors))
    }
}

pub fn evaluate_corevm0(
    verified: VerifiedCoreVmProgram<'_>,
    arguments: Vec<CoreVmValue>,
    max_steps: u64,
) -> Result<CoreVmEvaluation, CoreVmExecutionError> {
    let program = verified.program;
    if arguments.len() != program.arguments.len() {
        return Err(CoreVmExecutionError::ArgumentArity {
            expected: program.arguments.len(),
            actual: arguments.len(),
        });
    }
    for (index, (argument, expected)) in arguments.iter().zip(&program.arguments).enumerate() {
        let actual = argument.ty();
        if actual != *expected {
            return Err(CoreVmExecutionError::ArgumentType {
                index: index as u32,
                expected: *expected,
                actual,
            });
        }
    }

    let program_hash = corevm0_program_hash(program)?;
    let mut pc = 0usize;
    let mut stack = Vec::with_capacity(program.max_stack as usize);
    let mut locals = vec![None; program.locals.len()];
    let mut steps = 0u64;

    loop {
        if steps == max_steps {
            return Err(CoreVmExecutionError::StepBudgetExceeded {
                limit: max_steps,
                pc: pc as u32,
            });
        }
        steps += 1;
        let instruction = &program.instructions[pc];
        let mut advance = true;
        match instruction {
            CoreVmInstruction::ConstI64(value) => stack.push(CoreVmValue::I64(*value)),
            CoreVmInstruction::ConstF64(value) => stack.push(CoreVmValue::F64(*value)),
            CoreVmInstruction::LoadArg(index) => {
                stack.push(arguments[*index as usize].clone());
            }
            CoreVmInstruction::LoadLocal(index) => {
                let value = locals[*index as usize]
                    .clone()
                    .ok_or_else(|| invariant(pc, format!("local {index} is uninitialized")))?;
                stack.push(value);
            }
            CoreVmInstruction::StoreLocal(index) => {
                locals[*index as usize] = Some(pop_value(&mut stack, pc)?);
            }
            CoreVmInstruction::AddI64 => {
                let right = pop_i64(&mut stack, pc)?;
                let left = pop_i64(&mut stack, pc)?;
                stack.push(CoreVmValue::I64(left.wrapping_add(right)));
            }
            CoreVmInstruction::SubI64 => {
                let right = pop_i64(&mut stack, pc)?;
                let left = pop_i64(&mut stack, pc)?;
                stack.push(CoreVmValue::I64(left.wrapping_sub(right)));
            }
            CoreVmInstruction::AddF64 => {
                let right = pop_f64(&mut stack, pc)?;
                let left = pop_f64(&mut stack, pc)?;
                stack.push(CoreVmValue::F64(left + right));
            }
            CoreVmInstruction::SubF64 => {
                let right = pop_f64(&mut stack, pc)?;
                let left = pop_f64(&mut stack, pc)?;
                stack.push(CoreVmValue::F64(left - right));
            }
            CoreVmInstruction::CmpLtI64 => {
                let right = pop_i64(&mut stack, pc)?;
                let left = pop_i64(&mut stack, pc)?;
                stack.push(CoreVmValue::Bool(left < right));
            }
            CoreVmInstruction::CmpGeI64 => {
                let right = pop_i64(&mut stack, pc)?;
                let left = pop_i64(&mut stack, pc)?;
                stack.push(CoreVmValue::Bool(left >= right));
            }
            CoreVmInstruction::ArrayLenF64 => {
                let values = pop_array(&mut stack, pc)?;
                let length = i64::try_from(values.len())
                    .map_err(|_| invariant(pc, "array length does not fit I64".to_owned()))?;
                stack.push(CoreVmValue::I64(length));
            }
            CoreVmInstruction::ArrayGetF64 => {
                let index = pop_i64(&mut stack, pc)?;
                let values = pop_array(&mut stack, pc)?;
                let value = usize::try_from(index)
                    .ok()
                    .and_then(|index| values.get(index))
                    .copied();
                let Some(value) = value else {
                    return Ok(CoreVmEvaluation {
                        program_hash,
                        outcome: CoreVmOutcome::Error(CoreVmTypedError::Bounds),
                        steps,
                        effect_trace: vec![CoreVmTypedError::Bounds],
                    });
                };
                stack.push(CoreVmValue::F64(value));
            }
            CoreVmInstruction::Jump(target) => {
                pc = *target as usize;
                advance = false;
            }
            CoreVmInstruction::JumpIfFalse(target) => {
                if !pop_bool(&mut stack, pc)? {
                    pc = *target as usize;
                    advance = false;
                }
            }
            CoreVmInstruction::ReturnF64 => {
                let value = pop_f64(&mut stack, pc)?;
                return Ok(CoreVmEvaluation {
                    program_hash,
                    outcome: CoreVmOutcome::ReturnF64(value),
                    steps,
                    effect_trace: Vec::new(),
                });
            }
        }
        if advance {
            pc += 1;
        }
    }
}

pub fn corevm0_program_bytes(program: &CoreVmProgram) -> Result<Vec<u8>, EncodeError> {
    let mut bytes = COREVM0_PROGRAM_DOMAIN.to_vec();
    put_version(&mut bytes, program.schema_version);
    put_length(
        &mut bytes,
        "corevm0.program.arguments",
        program.arguments.len(),
    )?;
    for ty in &program.arguments {
        bytes.push(type_tag(*ty));
    }
    put_length(&mut bytes, "corevm0.program.locals", program.locals.len())?;
    for ty in &program.locals {
        bytes.push(type_tag(*ty));
    }
    bytes.extend_from_slice(&program.max_stack.to_be_bytes());
    put_length(
        &mut bytes,
        "corevm0.program.instructions",
        program.instructions.len(),
    )?;
    for instruction in &program.instructions {
        encode_instruction(&mut bytes, instruction);
    }
    Ok(bytes)
}

pub fn corevm0_program_hash(program: &CoreVmProgram) -> Result<SemanticHash, EncodeError> {
    Ok(SemanticHash(sha256(&corevm0_program_bytes(program)?)))
}

/// Map one verified CoreVM0 program into the ordinary P1V0 Tuple/Sum static
/// value domain used by specialization requests.
pub fn corevm0_core_image(
    program: &CoreVmProgram,
) -> Result<CoreVmCoreImage, CoreVmCoreImageError> {
    verify_corevm0_program(program).map_err(CoreVmCoreImageError::InvalidProgram)?;
    let instruction_type = corevm0_instruction_sum_type();
    let values = program
        .instructions
        .iter()
        .map(|instruction| instruction_specialization_value(instruction, &instruction_type))
        .collect();
    Ok(CoreVmCoreImage {
        ty: Type::Tuple(vec![
            Type::Sum(instruction_type.clone());
            program.instructions.len()
        ]),
        value: SpecializationValue::Tuple(values),
        program_hash: corevm0_program_hash(program).map_err(CoreVmCoreImageError::Encoding)?,
    })
}

/// Construct the canonical full Stage 3 program image from an already
/// verified CoreVM0 program.
///
/// The image has one fixed Core type for every admitted program. Live
/// manifests and instructions use `Present`-style Sum constructors; every
/// unused slot has one canonical padding constructor.
pub fn corevm0_program_image(
    verified: VerifiedCoreVmProgram<'_>,
) -> Result<CoreVmProgramImage, EncodeError> {
    let program = verified.program();
    let instruction_type = corevm0_instruction_sum_type();
    let type_slot = corevm0_type_slot_sum_type();
    let instruction_slot = corevm0_instruction_slot_sum_type();
    let ty = corevm0_program_image_type();

    let argument_types = fixed_type_slots(&program.arguments, COREVM0_MAX_ARGUMENTS, &type_slot);
    let local_types = fixed_type_slots(&program.locals, COREVM0_MAX_LOCALS, &type_slot);
    let mut instructions = Vec::with_capacity(COREVM0_MAX_INSTRUCTIONS);
    for instruction in &program.instructions {
        instructions.push(SpecializationValue::Sum {
            ty: instruction_slot.clone(),
            constructor: 1,
            fields: vec![instruction_specialization_value(
                instruction,
                &instruction_type,
            )],
        });
    }
    while instructions.len() < COREVM0_MAX_INSTRUCTIONS {
        instructions.push(SpecializationValue::Sum {
            ty: instruction_slot.clone(),
            constructor: 0,
            fields: vec![],
        });
    }

    let value = SpecializationValue::Tuple(vec![
        SpecializationValue::I64(i64::from(COREVM0_PROGRAM_IMAGE_VERSION.0)),
        SpecializationValue::I64(i64::from(COREVM0_PROGRAM_IMAGE_VERSION.1)),
        SpecializationValue::I64(i64::from(COREVM0_PROGRAM_IMAGE_VERSION.2)),
        SpecializationValue::I64(program.arguments.len() as i64),
        SpecializationValue::Tuple(argument_types),
        SpecializationValue::I64(program.locals.len() as i64),
        SpecializationValue::Tuple(local_types),
        SpecializationValue::I64(i64::from(program.max_stack)),
        SpecializationValue::I64(program.instructions.len() as i64),
        SpecializationValue::Tuple(instructions),
    ]);
    let program_hash = corevm0_program_hash(program)?;
    let image_hash = specialization_value_hash(&value)?;

    Ok(CoreVmProgramImage {
        ty,
        value,
        program_hash,
        image_hash,
    })
}

/// Re-run bytecode verification and compare a raw static candidate with the
/// exact canonical full image. Ordinary Core/R0 type checking alone is not a
/// CoreVM0 program proof.
pub fn verify_corevm0_program_image(
    program: &CoreVmProgram,
    candidate: &SpecializationValue,
) -> Result<CoreVmProgramImage, CoreVmProgramImageVerificationError> {
    let verified = verify_corevm0_program(program)
        .map_err(CoreVmProgramImageVerificationError::InvalidProgram)?;
    let image =
        corevm0_program_image(verified).map_err(CoreVmProgramImageVerificationError::Encoding)?;
    let canonical = specialization_value_bytes(image.value())
        .map_err(CoreVmProgramImageVerificationError::Encoding)?;
    let candidate = specialization_value_bytes(candidate)
        .map_err(CoreVmProgramImageVerificationError::Encoding)?;
    if canonical != candidate {
        return Err(CoreVmProgramImageVerificationError::ImageMismatch);
    }
    Ok(image)
}

pub fn corevm0_program_image_type() -> Type {
    let type_slot = Type::Sum(corevm0_type_slot_sum_type());
    let instruction_slot = Type::Sum(corevm0_instruction_slot_sum_type());
    Type::Tuple(vec![
        Type::I64,
        Type::I64,
        Type::I64,
        Type::I64,
        Type::Tuple(vec![type_slot; COREVM0_MAX_ARGUMENTS]),
        Type::I64,
        Type::Tuple(vec![
            Type::Sum(corevm0_type_slot_sum_type());
            COREVM0_MAX_LOCALS
        ]),
        Type::I64,
        Type::I64,
        Type::Tuple(vec![instruction_slot; COREVM0_MAX_INSTRUCTIONS]),
    ])
}

pub fn corevm0_instruction_sum_type() -> SumType {
    let constructor = |name: &str, fields: Vec<Type>| ConstructorType {
        name: name.to_owned(),
        fields,
    };
    SumType {
        name: COREVM0_INSTRUCTION_SUM_NAME.to_owned(),
        constructors: vec![
            constructor("ConstI64", vec![Type::I64]),
            constructor("ConstF64", vec![Type::F64]),
            constructor("LoadArg", vec![Type::I64]),
            constructor("LoadLocal", vec![Type::I64]),
            constructor("StoreLocal", vec![Type::I64]),
            constructor("AddI64", vec![]),
            constructor("SubI64", vec![]),
            constructor("AddF64", vec![]),
            constructor("SubF64", vec![]),
            constructor("CmpLtI64", vec![]),
            constructor("CmpGeI64", vec![]),
            constructor("ArrayLenF64", vec![]),
            constructor("ArrayGetF64", vec![]),
            constructor("Jump", vec![Type::I64]),
            constructor("JumpIfFalse", vec![Type::I64]),
            constructor("ReturnF64", vec![]),
        ],
    }
}

pub fn corevm0_type_slot_sum_type() -> SumType {
    let constructor = |name: &str| ConstructorType {
        name: name.to_owned(),
        fields: vec![],
    };
    SumType {
        name: COREVM0_TYPE_SLOT_SUM_NAME.to_owned(),
        constructors: vec![
            constructor("Absent"),
            constructor("Bool"),
            constructor("I64"),
            constructor("F64"),
            constructor("ArrayF64"),
        ],
    }
}

pub fn corevm0_instruction_slot_sum_type() -> SumType {
    SumType {
        name: COREVM0_INSTRUCTION_SLOT_SUM_NAME.to_owned(),
        constructors: vec![
            ConstructorType {
                name: "Padding".to_owned(),
                fields: vec![],
            },
            ConstructorType {
                name: "Present".to_owned(),
                fields: vec![Type::Sum(corevm0_instruction_sum_type())],
            },
        ],
    }
}

/// The canonical bytecode image for the P1 `branch_mix_kernel` workload.
pub fn branch_mix_kernel_program() -> CoreVmProgram {
    use CoreVmInstruction as I;

    CoreVmProgram {
        schema_version: COREVM0_SCHEMA_VERSION,
        arguments: vec![CoreVmType::ArrayF64, CoreVmType::I64],
        locals: vec![
            CoreVmType::I64, // state
            CoreVmType::F64, // sum
            CoreVmType::I64, // repetition
            CoreVmType::I64, // index
            CoreVmType::I64, // array length
        ],
        max_stack: 3,
        instructions: vec![
            I::ConstI64(0),     // 0
            I::StoreLocal(0),   // 1 state = 0
            I::ConstF64(0.0),   // 2
            I::StoreLocal(1),   // 3 sum = 0
            I::ConstI64(0),     // 4
            I::StoreLocal(2),   // 5 repetition = 0
            I::LoadLocal(2),    // 6 outer_check
            I::LoadArg(1),      // 7
            I::CmpGeI64,        // 8 repetition >= reps
            I::JumpIfFalse(11), // 9
            I::Jump(60),        // 10 done
            I::ConstI64(0),     // 11 outer_body
            I::StoreLocal(3),   // 12 index = 0
            I::LoadArg(0),      // 13
            I::ArrayLenF64,     // 14
            I::StoreLocal(4),   // 15 len = input.len
            I::LoadLocal(3),    // 16 inner_check
            I::LoadLocal(4),    // 17
            I::CmpGeI64,        // 18 index >= len
            I::JumpIfFalse(21), // 19
            I::Jump(55),        // 20 outer_increment
            I::LoadLocal(0),    // 21 inner_body
            I::ConstI64(17),    // 22
            I::AddI64,          // 23
            I::StoreLocal(0),   // 24 state += 17
            I::LoadLocal(0),    // 25
            I::ConstI64(97),    // 26
            I::CmpGeI64,        // 27
            I::JumpIfFalse(33), // 28
            I::LoadLocal(0),    // 29
            I::ConstI64(97),    // 30
            I::SubI64,          // 31
            I::StoreLocal(0),   // 32 state -= 97
            I::LoadLocal(0),    // 33 after_reduce
            I::ConstI64(48),    // 34
            I::CmpLtI64,        // 35
            I::JumpIfFalse(44), // 36
            I::LoadLocal(1),    // 37 add path
            I::LoadArg(0),      // 38
            I::LoadLocal(3),    // 39
            I::ArrayGetF64,     // 40
            I::AddF64,          // 41
            I::StoreLocal(1),   // 42
            I::Jump(50),        // 43
            I::LoadLocal(1),    // 44 subtract path
            I::LoadArg(0),      // 45
            I::LoadLocal(3),    // 46
            I::ArrayGetF64,     // 47
            I::SubF64,          // 48
            I::StoreLocal(1),   // 49
            I::LoadLocal(3),    // 50 after_sum
            I::ConstI64(1),     // 51
            I::AddI64,          // 52
            I::StoreLocal(3),   // 53 index += 1
            I::Jump(16),        // 54
            I::LoadLocal(2),    // 55 outer_increment
            I::ConstI64(1),     // 56
            I::AddI64,          // 57
            I::StoreLocal(2),   // 58 repetition += 1
            I::Jump(6),         // 59
            I::LoadLocal(1),    // 60 done
            I::ReturnF64,       // 61
        ],
    }
}

fn pop_expected(
    stack: &mut Vec<CoreVmType>,
    expected: CoreVmType,
    pc: usize,
    errors: &mut Vec<CoreVmVerificationError>,
) -> bool {
    let Some(actual) = stack.pop() else {
        push_verification_error(
            errors,
            CoreVmVerificationCode::StackUnderflow,
            Some(pc as u32),
            format!("expected {expected:?} on the stack"),
        );
        return false;
    };
    if actual != expected {
        push_verification_error(
            errors,
            CoreVmVerificationCode::StackTypeMismatch,
            Some(pc as u32),
            format!("expected {expected:?}, found {actual:?}"),
        );
        false
    } else {
        true
    }
}

fn valid_target(
    target: u32,
    instruction_count: usize,
    pc: usize,
    errors: &mut Vec<CoreVmVerificationError>,
) -> bool {
    if target as usize >= instruction_count {
        push_verification_error(
            errors,
            CoreVmVerificationCode::InvalidBranchTarget,
            Some(pc as u32),
            format!("branch target {target} is out of range"),
        );
        false
    } else {
        true
    }
}

fn merge_state(
    pc: usize,
    incoming: &AbstractState,
    states: &mut [Option<AbstractState>],
    pending: &mut VecDeque<usize>,
    errors: &mut Vec<CoreVmVerificationError>,
) {
    let Some(existing) = &mut states[pc] else {
        states[pc] = Some(incoming.clone());
        pending.push_back(pc);
        return;
    };
    if existing.stack != incoming.stack {
        push_verification_error(
            errors,
            CoreVmVerificationCode::StackJoinMismatch,
            Some(pc as u32),
            format!(
                "incoming stack {:?} disagrees with {:?}",
                incoming.stack, existing.stack
            ),
        );
        return;
    }
    let mut changed = false;
    for (known, incoming) in existing.initialized.iter_mut().zip(&incoming.initialized) {
        let merged = *known && *incoming;
        changed |= merged != *known;
        *known = merged;
    }
    if changed {
        pending.push_back(pc);
    }
}

fn push_verification_error(
    errors: &mut Vec<CoreVmVerificationError>,
    code: CoreVmVerificationCode,
    pc: Option<u32>,
    message: String,
) {
    let error = CoreVmVerificationError { code, pc, message };
    if !errors.contains(&error) {
        errors.push(error);
    }
}

fn pop_value(stack: &mut Vec<CoreVmValue>, pc: usize) -> Result<CoreVmValue, CoreVmExecutionError> {
    stack
        .pop()
        .ok_or_else(|| invariant(pc, "verified stack underflow".to_owned()))
}

fn pop_bool(stack: &mut Vec<CoreVmValue>, pc: usize) -> Result<bool, CoreVmExecutionError> {
    let CoreVmValue::Bool(value) = pop_value(stack, pc)? else {
        return Err(invariant(pc, "verified stack value is not Bool".to_owned()));
    };
    Ok(value)
}

fn pop_i64(stack: &mut Vec<CoreVmValue>, pc: usize) -> Result<i64, CoreVmExecutionError> {
    let CoreVmValue::I64(value) = pop_value(stack, pc)? else {
        return Err(invariant(pc, "verified stack value is not I64".to_owned()));
    };
    Ok(value)
}

fn pop_f64(stack: &mut Vec<CoreVmValue>, pc: usize) -> Result<f64, CoreVmExecutionError> {
    let CoreVmValue::F64(value) = pop_value(stack, pc)? else {
        return Err(invariant(pc, "verified stack value is not F64".to_owned()));
    };
    Ok(value)
}

fn pop_array(stack: &mut Vec<CoreVmValue>, pc: usize) -> Result<Arc<[f64]>, CoreVmExecutionError> {
    let CoreVmValue::ArrayF64(value) = pop_value(stack, pc)? else {
        return Err(invariant(
            pc,
            "verified stack value is not ArrayF64".to_owned(),
        ));
    };
    Ok(value)
}

fn invariant(pc: usize, message: String) -> CoreVmExecutionError {
    CoreVmExecutionError::InternalInvariant {
        pc: pc as u32,
        message,
    }
}

fn put_version(bytes: &mut Vec<u8>, version: (u16, u16, u16)) {
    bytes.extend_from_slice(&version.0.to_be_bytes());
    bytes.extend_from_slice(&version.1.to_be_bytes());
    bytes.extend_from_slice(&version.2.to_be_bytes());
}

fn put_length(bytes: &mut Vec<u8>, field: &'static str, length: usize) -> Result<(), EncodeError> {
    let length =
        u32::try_from(length).map_err(|_| EncodeError::LengthOverflow { field, length })?;
    bytes.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

fn type_tag(ty: CoreVmType) -> u8 {
    match ty {
        CoreVmType::Bool => 0,
        CoreVmType::I64 => 1,
        CoreVmType::F64 => 2,
        CoreVmType::ArrayF64 => 3,
    }
}

fn encode_instruction(bytes: &mut Vec<u8>, instruction: &CoreVmInstruction) {
    match instruction {
        CoreVmInstruction::ConstI64(value) => {
            bytes.push(0);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        CoreVmInstruction::ConstF64(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&canonical_f64_bits(*value).to_be_bytes());
        }
        CoreVmInstruction::LoadArg(index) => encode_index(bytes, 2, *index),
        CoreVmInstruction::LoadLocal(index) => encode_index(bytes, 3, *index),
        CoreVmInstruction::StoreLocal(index) => encode_index(bytes, 4, *index),
        CoreVmInstruction::AddI64 => bytes.push(5),
        CoreVmInstruction::SubI64 => bytes.push(6),
        CoreVmInstruction::AddF64 => bytes.push(7),
        CoreVmInstruction::SubF64 => bytes.push(8),
        CoreVmInstruction::CmpLtI64 => bytes.push(9),
        CoreVmInstruction::CmpGeI64 => bytes.push(10),
        CoreVmInstruction::ArrayLenF64 => bytes.push(11),
        CoreVmInstruction::ArrayGetF64 => bytes.push(12),
        CoreVmInstruction::Jump(target) => encode_index(bytes, 13, *target),
        CoreVmInstruction::JumpIfFalse(target) => encode_index(bytes, 14, *target),
        CoreVmInstruction::ReturnF64 => bytes.push(15),
    }
}

fn encode_index(bytes: &mut Vec<u8>, tag: u8, index: u32) {
    bytes.push(tag);
    bytes.extend_from_slice(&index.to_be_bytes());
}

fn instruction_specialization_value(
    instruction: &CoreVmInstruction,
    instruction_type: &SumType,
) -> SpecializationValue {
    let (constructor, fields) = match instruction {
        CoreVmInstruction::ConstI64(value) => (0, vec![SpecializationValue::I64(*value)]),
        CoreVmInstruction::ConstF64(value) => (1, vec![SpecializationValue::F64(*value)]),
        CoreVmInstruction::LoadArg(index) => (2, vec![SpecializationValue::I64(i64::from(*index))]),
        CoreVmInstruction::LoadLocal(index) => {
            (3, vec![SpecializationValue::I64(i64::from(*index))])
        }
        CoreVmInstruction::StoreLocal(index) => {
            (4, vec![SpecializationValue::I64(i64::from(*index))])
        }
        CoreVmInstruction::AddI64 => (5, vec![]),
        CoreVmInstruction::SubI64 => (6, vec![]),
        CoreVmInstruction::AddF64 => (7, vec![]),
        CoreVmInstruction::SubF64 => (8, vec![]),
        CoreVmInstruction::CmpLtI64 => (9, vec![]),
        CoreVmInstruction::CmpGeI64 => (10, vec![]),
        CoreVmInstruction::ArrayLenF64 => (11, vec![]),
        CoreVmInstruction::ArrayGetF64 => (12, vec![]),
        CoreVmInstruction::Jump(target) => (13, vec![SpecializationValue::I64(i64::from(*target))]),
        CoreVmInstruction::JumpIfFalse(target) => {
            (14, vec![SpecializationValue::I64(i64::from(*target))])
        }
        CoreVmInstruction::ReturnF64 => (15, vec![]),
    };
    SpecializationValue::Sum {
        ty: instruction_type.clone(),
        constructor,
        fields,
    }
}

fn fixed_type_slots(
    types: &[CoreVmType],
    capacity: usize,
    slot_type: &SumType,
) -> Vec<SpecializationValue> {
    let mut slots = Vec::with_capacity(capacity);
    for ty in types {
        let constructor = match ty {
            CoreVmType::Bool => 1,
            CoreVmType::I64 => 2,
            CoreVmType::F64 => 3,
            CoreVmType::ArrayF64 => 4,
        };
        slots.push(SpecializationValue::Sum {
            ty: slot_type.clone(),
            constructor,
            fields: vec![],
        });
    }
    while slots.len() < capacity {
        slots.push(SpecializationValue::Sum {
            ty: slot_type.clone(),
            constructor: 0,
            fields: vec![],
        });
    }
    slots
}
