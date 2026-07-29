use super::corevm0::{
    corevm0_instruction_slot_sum_type, corevm0_program_image, corevm0_program_image_type,
    verify_corevm0_program, CoreVmOutcome, CoreVmProgram, CoreVmType, CoreVmTypedError,
    CoreVmValue, CoreVmVerificationErrors, COREVM0_MAX_LOCALS, COREVM0_MAX_STACK,
};
use super::encoding::{interpreter_semantics_hash, EncodeError};
use super::interpret::{
    evaluate, CoreValue, EffectEvent, EvaluationBudget, EvaluationOutcome, ExecutionError,
};
use super::schema::{
    CaseArm, ConstructorType, CoreArtifact, CoreProfile, Effect, EffectRow, ErrorKind, Function,
    FunctionId, LocalId, Mutability, NumericMode, Operand, Parameter, Primitive, Program, RValue,
    RegionId, SchemaVersion, SemanticHash, SumType, Term, Type,
};
use super::specialization::SpecializationValue;
use super::verify::{verify, VerificationErrors};
use std::fmt;

pub const COREVM0_DEFINITIONAL_CONSTRUCTION_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const COREVM0_RUNTIME_VALUE_SUM_NAME: &str = "CoreVM0.RuntimeValue.v1";
pub const COREVM0_VALUE_LOOKUP_SUM_NAME: &str = "CoreVM0.ValueLookup.v1";
pub const COREVM0_BANK_UPDATE_SUM_NAME: &str = "CoreVM0.BankUpdate.v1";

const ENTRY_FUNCTION: FunctionId = FunctionId(0);
const LOOP_FUNCTION: FunctionId = FunctionId(1);
const FETCH_FUNCTION: FunctionId = FunctionId(2);
const GET_SLOT_FUNCTION: FunctionId = FunctionId(3);
const SET_SLOT_FUNCTION: FunctionId = FunctionId(4);
const GET_ARGUMENT_FUNCTION: FunctionId = FunctionId(5);
const TRAP_FUNCTION: FunctionId = FunctionId(6);
const ARRAY_REGION: RegionId = RegionId(0);

const IMAGE_INSTRUCTION_COUNT_INDEX: u32 = 8;
const IMAGE_INSTRUCTION_SLOTS_INDEX: u32 = 9;

#[derive(Clone, Debug)]
pub struct DefinitionalCoreVmArtifact {
    artifact: CoreArtifact,
    program_hash: SemanticHash,
    program_image_hash: SemanticHash,
    program_image: SpecializationValue,
    program_image_value: CoreValue,
    argument_types: Vec<CoreVmType>,
    core_interpreter_semantics_hash: SemanticHash,
    construction_version: (u16, u16, u16),
}

impl DefinitionalCoreVmArtifact {
    pub fn artifact(&self) -> &CoreArtifact {
        &self.artifact
    }

    pub fn program_hash(&self) -> SemanticHash {
        self.program_hash
    }

    pub fn program_image_hash(&self) -> SemanticHash {
        self.program_image_hash
    }

    pub fn program_image(&self) -> &SpecializationValue {
        &self.program_image
    }

    pub fn argument_types(&self) -> &[CoreVmType] {
        &self.argument_types
    }

    pub fn core_interpreter_semantics_hash(&self) -> SemanticHash {
        self.core_interpreter_semantics_hash
    }

    pub fn construction_version(&self) -> (u16, u16, u16) {
        self.construction_version
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DefinitionalCoreVmBuildError {
    InvalidProgram(CoreVmVerificationErrors),
    ImageEncoding(EncodeError),
    ArtifactEncoding(EncodeError),
    ArtifactRejected(VerificationErrors),
    ImageInvariant(String),
}

impl fmt::Display for DefinitionalCoreVmBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProgram(errors) => write!(formatter, "{errors}"),
            Self::ImageEncoding(error) => {
                write!(formatter, "CoreVM0 full image failed to encode: {error}")
            }
            Self::ArtifactEncoding(error) => {
                write!(
                    formatter,
                    "definitional CoreVM0 artifact failed to encode: {error}"
                )
            }
            Self::ArtifactRejected(errors) => {
                write!(
                    formatter,
                    "definitional CoreVM0 artifact was rejected: {errors}"
                )
            }
            Self::ImageInvariant(message) => {
                write!(
                    formatter,
                    "canonical CoreVM0 image invariant failed: {message}"
                )
            }
        }
    }
}

impl std::error::Error for DefinitionalCoreVmBuildError {}

#[derive(Clone, Debug, PartialEq)]
pub struct DefinitionalCoreVmEvaluation {
    pub program_hash: SemanticHash,
    pub outcome: CoreVmOutcome,
    pub core_steps: u64,
    pub effect_trace: Vec<CoreVmTypedError>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DefinitionalCoreVmExecutionError {
    ArgumentArity {
        expected: usize,
        actual: usize,
    },
    ArgumentType {
        index: u32,
        expected: CoreVmType,
        actual: CoreVmType,
    },
    Core(ExecutionError),
    InvalidCoreOutcome(String),
}

impl fmt::Display for DefinitionalCoreVmExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArgumentArity { expected, actual } => write!(
                formatter,
                "definitional CoreVM0 expected {expected} argument(s), found {actual}"
            ),
            Self::ArgumentType {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "definitional CoreVM0 argument {index} expected {expected:?}, found {actual:?}"
            ),
            Self::Core(error) => write!(formatter, "{error}"),
            Self::InvalidCoreOutcome(message) => {
                write!(
                    formatter,
                    "definitional CoreVM0 produced an invalid outcome: {message}"
                )
            }
        }
    }
}

impl std::error::Error for DefinitionalCoreVmExecutionError {}

/// Verify a raw CoreVM0 program, regenerate its complete canonical image, and
/// bind it to the generic Core-N0 interpreter for that exact argument shape.
pub fn build_definitional_corevm0(
    program: &CoreVmProgram,
) -> Result<DefinitionalCoreVmArtifact, DefinitionalCoreVmBuildError> {
    let verified =
        verify_corevm0_program(program).map_err(DefinitionalCoreVmBuildError::InvalidProgram)?;
    let image =
        corevm0_program_image(verified).map_err(DefinitionalCoreVmBuildError::ImageEncoding)?;
    let artifact = CoreArtifact::seal(build_program(&program.arguments))
        .map_err(DefinitionalCoreVmBuildError::ArtifactEncoding)?;
    verify(&artifact).map_err(DefinitionalCoreVmBuildError::ArtifactRejected)?;
    let program_image_value = specialization_to_core_value(image.value())?;
    let core_interpreter_semantics_hash = interpreter_semantics_hash(CoreProfile::P1V0)
        .map_err(DefinitionalCoreVmBuildError::ArtifactEncoding)?;

    Ok(DefinitionalCoreVmArtifact {
        artifact,
        program_hash: image.program_hash(),
        program_image_hash: image.image_hash(),
        program_image: image.value().clone(),
        program_image_value,
        argument_types: program.arguments.clone(),
        core_interpreter_semantics_hash,
        construction_version: COREVM0_DEFINITIONAL_CONSTRUCTION_VERSION,
    })
}

/// Execute only through the opaque verified-program binding.
///
/// `budget` counts Core-N0 terms and rvalues, not CoreVM0 opcodes.
pub fn evaluate_definitional_corevm0(
    bound: &DefinitionalCoreVmArtifact,
    arguments: Vec<CoreVmValue>,
    budget: EvaluationBudget,
) -> Result<DefinitionalCoreVmEvaluation, DefinitionalCoreVmExecutionError> {
    if arguments.len() != bound.argument_types.len() {
        return Err(DefinitionalCoreVmExecutionError::ArgumentArity {
            expected: bound.argument_types.len(),
            actual: arguments.len(),
        });
    }
    for (index, (argument, expected)) in arguments.iter().zip(&bound.argument_types).enumerate() {
        let actual = argument.ty();
        if actual != *expected {
            return Err(DefinitionalCoreVmExecutionError::ArgumentType {
                index: index as u32,
                expected: *expected,
                actual,
            });
        }
    }

    let mut core_arguments = Vec::with_capacity(arguments.len() + 1);
    core_arguments.push(bound.program_image_value.clone());
    core_arguments.extend(arguments.into_iter().map(core_value_from_vm));
    let evaluation = evaluate(&bound.artifact, core_arguments, budget)
        .map_err(DefinitionalCoreVmExecutionError::Core)?;

    let outcome = match evaluation.outcome {
        EvaluationOutcome::Return(CoreValue::F64(value)) => CoreVmOutcome::ReturnF64(value),
        EvaluationOutcome::Error(ErrorKind::Bounds) => {
            CoreVmOutcome::Error(CoreVmTypedError::Bounds)
        }
        other => {
            return Err(DefinitionalCoreVmExecutionError::InvalidCoreOutcome(
                format!("{other:?}"),
            ));
        }
    };
    let mut effect_trace = Vec::with_capacity(evaluation.effect_trace.len());
    for event in evaluation.effect_trace {
        match event {
            EffectEvent::Error(ErrorKind::Bounds) => {
                effect_trace.push(CoreVmTypedError::Bounds);
            }
            other => {
                return Err(DefinitionalCoreVmExecutionError::InvalidCoreOutcome(
                    format!("unexpected effect {other:?}"),
                ));
            }
        }
    }

    Ok(DefinitionalCoreVmEvaluation {
        program_hash: bound.program_hash,
        outcome,
        core_steps: evaluation.steps,
        effect_trace,
    })
}

fn build_program(argument_types: &[CoreVmType]) -> Program {
    let runtime_value = runtime_value_sum_type();
    let bank = Type::Tuple(vec![
        Type::Sum(runtime_value.clone());
        COREVM0_MAX_STACK.max(COREVM0_MAX_LOCALS)
    ]);
    let lookup = value_lookup_sum_type();
    let update = bank_update_sum_type();
    let instruction_slots = instruction_slots_type();
    let effects = EffectRow::canonical(vec![Effect::Error(ErrorKind::Bounds)]);

    Program {
        schema: SchemaVersion::core_n0(),
        profile: CoreProfile::P1V0,
        entry: ENTRY_FUNCTION,
        functions: vec![
            build_entry(
                argument_types,
                &runtime_value,
                &bank,
                &instruction_slots,
                &effects,
            ),
            build_loop(
                argument_types,
                &runtime_value,
                &bank,
                &lookup,
                &update,
                &instruction_slots,
                &effects,
            ),
            build_fetch(&instruction_slots),
            build_get_slot(&runtime_value, &bank, &lookup),
            build_set_slot(&runtime_value, &bank, &update),
            build_get_argument(argument_types, &runtime_value, &lookup),
            build_trap(),
        ],
    }
}

fn build_entry(
    argument_types: &[CoreVmType],
    runtime_value: &SumType,
    bank: &Type,
    instruction_slots: &Type,
    effects: &EffectRow,
) -> Function {
    let mut parameters = vec![Parameter {
        local: LocalId(0),
        ty: corevm0_program_image_type(),
    }];
    parameters.extend(
        argument_types
            .iter()
            .enumerate()
            .map(|(index, ty)| Parameter {
                local: LocalId(index as u32 + 1),
                ty: core_type(*ty),
            }),
    );
    let mut builder = TermBuilder::new(parameters.len() as u32);
    let image = parameters[0].local;
    let argument_locals: Vec<LocalId> = parameters.iter().skip(1).map(|p| p.local).collect();
    let body = builder.bind(
        Type::I64,
        RValue::Project {
            tuple: Operand::Local(image),
            index: IMAGE_INSTRUCTION_COUNT_INDEX,
        },
        |builder, instruction_count| {
            builder.bind(
                instruction_slots.clone(),
                RValue::Project {
                    tuple: Operand::Local(image),
                    index: IMAGE_INSTRUCTION_SLOTS_INDEX,
                },
                |builder, instructions| {
                    builder.bind(
                        Type::Sum(runtime_value.clone()),
                        RValue::Construct {
                            sum: runtime_value.clone(),
                            constructor: 4,
                            fields: vec![],
                        },
                        |builder, uninitialized| {
                            builder.bind(
                                bank.clone(),
                                RValue::Tuple(vec![
                                    Operand::Local(uninitialized);
                                    COREVM0_MAX_STACK
                                ]),
                                |builder, stack| {
                                    builder.bind(
                                        bank.clone(),
                                        RValue::Tuple(vec![
                                            Operand::Local(uninitialized);
                                            COREVM0_MAX_LOCALS
                                        ]),
                                        |_builder, locals| {
                                            tail_loop(
                                                instructions,
                                                instruction_count,
                                                &argument_locals,
                                                Operand::I64(0),
                                                Operand::I64(0),
                                                stack,
                                                locals,
                                            )
                                        },
                                    )
                                },
                            )
                        },
                    )
                },
            )
        },
    );

    Function {
        id: ENTRY_FUNCTION,
        region_parameters: vec![ARRAY_REGION],
        parameters,
        effects: effects.clone(),
        result: Type::F64,
        body,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_loop(
    argument_types: &[CoreVmType],
    runtime_value: &SumType,
    bank: &Type,
    lookup: &SumType,
    update: &SumType,
    instruction_slots: &Type,
    effects: &EffectRow,
) -> Function {
    let mut parameters = Vec::new();
    let mut next = 0_u32;
    let mut parameter = |ty: Type| {
        let local = LocalId(next);
        next += 1;
        parameters.push(Parameter { local, ty });
        local
    };
    let instructions = parameter(instruction_slots.clone());
    let instruction_count = parameter(Type::I64);
    let argument_locals: Vec<LocalId> = argument_types
        .iter()
        .map(|ty| parameter(core_type(*ty)))
        .collect();
    let pc = parameter(Type::I64);
    let sp = parameter(Type::I64);
    let stack = parameter(bank.clone());
    let locals = parameter(bank.clone());
    let context = LoopContext {
        instructions,
        instruction_count,
        arguments: argument_locals,
        pc,
        sp,
        stack,
        locals,
    };
    let mut builder = TermBuilder::new(next);
    let body = builder.bind(
        Type::Bool,
        primitive(
            Primitive::I64CmpLt,
            vec![Operand::Local(pc), Operand::I64(0)],
        ),
        |builder, negative_pc| {
            let valid_nonnegative = builder.bind(
                Type::Bool,
                primitive(
                    Primitive::I64CmpGe,
                    vec![Operand::Local(pc), Operand::Local(instruction_count)],
                ),
                |builder, beyond_program| {
                    let fetch = builder.bind(
                        Type::Sum(corevm0_instruction_slot_sum_type()),
                        RValue::Call {
                            function: FETCH_FUNCTION,
                            arguments: vec![Operand::Local(instructions), Operand::Local(pc)],
                        },
                        |builder, slot| {
                            dispatch_slot(
                                builder,
                                slot,
                                &context,
                                runtime_value,
                                bank,
                                lookup,
                                update,
                            )
                        },
                    );
                    Term::If {
                        condition: Operand::Local(beyond_program),
                        then_term: Box::new(trap_term()),
                        else_term: Box::new(fetch),
                    }
                },
            );
            Term::If {
                condition: Operand::Local(negative_pc),
                then_term: Box::new(trap_term()),
                else_term: Box::new(valid_nonnegative),
            }
        },
    );

    Function {
        id: LOOP_FUNCTION,
        region_parameters: vec![ARRAY_REGION],
        parameters,
        effects: effects.clone(),
        result: Type::F64,
        body,
    }
}

fn build_fetch(instruction_slots: &Type) -> Function {
    let parameters = vec![
        Parameter {
            local: LocalId(0),
            ty: instruction_slots.clone(),
        },
        Parameter {
            local: LocalId(1),
            ty: Type::I64,
        },
    ];
    let mut builder = TermBuilder::new(2);
    let body = build_fetch_tree(&mut builder, LocalId(0), LocalId(1), 0, 64);
    Function {
        id: FETCH_FUNCTION,
        region_parameters: vec![],
        parameters,
        effects: EffectRow::pure(),
        result: Type::Sum(corevm0_instruction_slot_sum_type()),
        body,
    }
}

fn build_get_slot(runtime_value: &SumType, bank: &Type, lookup: &SumType) -> Function {
    let parameters = vec![
        Parameter {
            local: LocalId(0),
            ty: bank.clone(),
        },
        Parameter {
            local: LocalId(1),
            ty: Type::I64,
        },
    ];
    let mut builder = TermBuilder::new(2);
    let body = checked_get_slot(&mut builder, LocalId(0), LocalId(1), runtime_value, lookup);
    Function {
        id: GET_SLOT_FUNCTION,
        region_parameters: vec![ARRAY_REGION],
        parameters,
        effects: EffectRow::pure(),
        result: Type::Sum(lookup.clone()),
        body,
    }
}

fn build_set_slot(runtime_value: &SumType, bank: &Type, update: &SumType) -> Function {
    let parameters = vec![
        Parameter {
            local: LocalId(0),
            ty: bank.clone(),
        },
        Parameter {
            local: LocalId(1),
            ty: Type::I64,
        },
        Parameter {
            local: LocalId(2),
            ty: Type::Sum(runtime_value.clone()),
        },
    ];
    let mut builder = TermBuilder::new(3);
    let body = checked_set_slot(
        &mut builder,
        LocalId(0),
        LocalId(1),
        LocalId(2),
        runtime_value,
        bank,
        update,
    );
    Function {
        id: SET_SLOT_FUNCTION,
        region_parameters: vec![ARRAY_REGION],
        parameters,
        effects: EffectRow::pure(),
        result: Type::Sum(update.clone()),
        body,
    }
}

fn build_get_argument(
    argument_types: &[CoreVmType],
    runtime_value: &SumType,
    lookup: &SumType,
) -> Function {
    let mut parameters: Vec<Parameter> = argument_types
        .iter()
        .enumerate()
        .map(|(index, ty)| Parameter {
            local: LocalId(index as u32),
            ty: core_type(*ty),
        })
        .collect();
    let index_local = LocalId(parameters.len() as u32);
    parameters.push(Parameter {
        local: index_local,
        ty: Type::I64,
    });
    let argument_locals: Vec<LocalId> = parameters
        .iter()
        .take(argument_types.len())
        .map(|parameter| parameter.local)
        .collect();
    let mut builder = TermBuilder::new(parameters.len() as u32);
    let body = checked_get_argument(
        &mut builder,
        index_local,
        &argument_locals,
        argument_types,
        runtime_value,
        lookup,
    );
    Function {
        id: GET_ARGUMENT_FUNCTION,
        region_parameters: vec![ARRAY_REGION],
        parameters,
        effects: EffectRow::pure(),
        result: Type::Sum(lookup.clone()),
        body,
    }
}

fn build_trap() -> Function {
    Function {
        id: TRAP_FUNCTION,
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::F64,
        body: trap_term(),
    }
}

#[derive(Clone)]
struct LoopContext {
    instructions: LocalId,
    instruction_count: LocalId,
    arguments: Vec<LocalId>,
    pc: LocalId,
    sp: LocalId,
    stack: LocalId,
    locals: LocalId,
}

struct TermBuilder {
    next_local: u32,
}

impl TermBuilder {
    fn new(next_local: u32) -> Self {
        Self { next_local }
    }

    fn fresh(&mut self) -> LocalId {
        let local = LocalId(self.next_local);
        self.next_local = self
            .next_local
            .checked_add(1)
            .expect("bounded CoreVM0 construction exhausted LocalId");
        local
    }

    fn bind<F>(&mut self, ty: Type, value: RValue, next: F) -> Term
    where
        F: FnOnce(&mut Self, LocalId) -> Term,
    {
        let binder = self.fresh();
        let next = next(self, binder);
        Term::Let {
            binder,
            ty,
            value,
            next: Box::new(next),
        }
    }
}

fn primitive(operation: Primitive, arguments: Vec<Operand>) -> RValue {
    RValue::Primitive {
        operation,
        arguments,
    }
}

fn core_type(ty: CoreVmType) -> Type {
    match ty {
        CoreVmType::Bool => Type::Bool,
        CoreVmType::I64 => Type::I64,
        CoreVmType::F64 => Type::F64,
        CoreVmType::ArrayF64 => array_type(),
    }
}

fn array_type() -> Type {
    Type::Array {
        region: ARRAY_REGION,
        mutability: Mutability::Read,
        element: Box::new(Type::F64),
    }
}

fn runtime_value_sum_type() -> SumType {
    SumType {
        name: COREVM0_RUNTIME_VALUE_SUM_NAME.to_owned(),
        constructors: vec![
            ConstructorType {
                name: "Bool".to_owned(),
                fields: vec![Type::Bool],
            },
            ConstructorType {
                name: "I64".to_owned(),
                fields: vec![Type::I64],
            },
            ConstructorType {
                name: "F64".to_owned(),
                fields: vec![Type::F64],
            },
            ConstructorType {
                name: "ArrayF64".to_owned(),
                fields: vec![array_type()],
            },
            ConstructorType {
                name: "Uninitialized".to_owned(),
                fields: vec![],
            },
        ],
    }
}

fn value_lookup_sum_type() -> SumType {
    SumType {
        name: COREVM0_VALUE_LOOKUP_SUM_NAME.to_owned(),
        constructors: vec![
            ConstructorType {
                name: "Invalid".to_owned(),
                fields: vec![],
            },
            ConstructorType {
                name: "Valid".to_owned(),
                fields: vec![Type::Sum(runtime_value_sum_type())],
            },
        ],
    }
}

fn bank_update_sum_type() -> SumType {
    SumType {
        name: COREVM0_BANK_UPDATE_SUM_NAME.to_owned(),
        constructors: vec![
            ConstructorType {
                name: "Invalid".to_owned(),
                fields: vec![],
            },
            ConstructorType {
                name: "Valid".to_owned(),
                fields: vec![Type::Tuple(vec![
                    Type::Sum(runtime_value_sum_type());
                    COREVM0_MAX_STACK.max(COREVM0_MAX_LOCALS)
                ])],
            },
        ],
    }
}

fn instruction_slots_type() -> Type {
    let Type::Tuple(fields) = corevm0_program_image_type() else {
        unreachable!("canonical CoreVM0 image type must be a Tuple");
    };
    fields[IMAGE_INSTRUCTION_SLOTS_INDEX as usize].clone()
}

fn trap_term() -> Term {
    Term::TailCall {
        function: TRAP_FUNCTION,
        arguments: vec![],
    }
}

fn tail_loop(
    instructions: LocalId,
    instruction_count: LocalId,
    arguments: &[LocalId],
    pc: Operand,
    sp: Operand,
    stack: LocalId,
    locals: LocalId,
) -> Term {
    let mut operands = vec![
        Operand::Local(instructions),
        Operand::Local(instruction_count),
    ];
    operands.extend(arguments.iter().copied().map(Operand::Local));
    operands.extend([pc, sp, Operand::Local(stack), Operand::Local(locals)]);
    Term::TailCall {
        function: LOOP_FUNCTION,
        arguments: operands,
    }
}

fn advance_pc<F>(builder: &mut TermBuilder, pc: LocalId, next: F) -> Term
where
    F: FnOnce(&mut TermBuilder, LocalId) -> Term,
{
    builder.bind(
        Type::I64,
        primitive(
            Primitive::I64Add(NumericMode::Wrapping),
            vec![Operand::Local(pc), Operand::I64(1)],
        ),
        next,
    )
}

fn build_fetch_tree(
    builder: &mut TermBuilder,
    slots: LocalId,
    index: LocalId,
    start: u32,
    end: u32,
) -> Term {
    if end - start == 1 {
        return builder.bind(
            Type::Sum(corevm0_instruction_slot_sum_type()),
            RValue::Project {
                tuple: Operand::Local(slots),
                index: start,
            },
            |_builder, slot| Term::Return(Operand::Local(slot)),
        );
    }
    let middle = start + (end - start) / 2;
    builder.bind(
        Type::Bool,
        primitive(
            Primitive::I64CmpLt,
            vec![Operand::Local(index), Operand::I64(i64::from(middle))],
        ),
        |builder, goes_left| Term::If {
            condition: Operand::Local(goes_left),
            then_term: Box::new(build_fetch_tree(builder, slots, index, start, middle)),
            else_term: Box::new(build_fetch_tree(builder, slots, index, middle, end)),
        },
    )
}

fn invalid_lookup(builder: &mut TermBuilder, lookup: &SumType) -> Term {
    builder.bind(
        Type::Sum(lookup.clone()),
        RValue::Construct {
            sum: lookup.clone(),
            constructor: 0,
            fields: vec![],
        },
        |_builder, value| Term::Return(Operand::Local(value)),
    )
}

fn valid_lookup(builder: &mut TermBuilder, lookup: &SumType, value: LocalId) -> Term {
    builder.bind(
        Type::Sum(lookup.clone()),
        RValue::Construct {
            sum: lookup.clone(),
            constructor: 1,
            fields: vec![Operand::Local(value)],
        },
        |_builder, result| Term::Return(Operand::Local(result)),
    )
}

fn checked_get_slot(
    builder: &mut TermBuilder,
    bank: LocalId,
    index: LocalId,
    runtime_value: &SumType,
    lookup: &SumType,
) -> Term {
    builder.bind(
        Type::Bool,
        primitive(
            Primitive::I64CmpLt,
            vec![Operand::Local(index), Operand::I64(0)],
        ),
        |builder, negative| {
            let nonnegative = builder.bind(
                Type::Bool,
                primitive(
                    Primitive::I64CmpGe,
                    vec![
                        Operand::Local(index),
                        Operand::I64(COREVM0_MAX_STACK as i64),
                    ],
                ),
                |builder, too_large| {
                    let selected =
                        build_get_slot_tree(builder, bank, index, 0, 16, runtime_value, lookup);
                    Term::If {
                        condition: Operand::Local(too_large),
                        then_term: Box::new(invalid_lookup(builder, lookup)),
                        else_term: Box::new(selected),
                    }
                },
            );
            Term::If {
                condition: Operand::Local(negative),
                then_term: Box::new(invalid_lookup(builder, lookup)),
                else_term: Box::new(nonnegative),
            }
        },
    )
}

fn build_get_slot_tree(
    builder: &mut TermBuilder,
    bank: LocalId,
    index: LocalId,
    start: u32,
    end: u32,
    runtime_value: &SumType,
    lookup: &SumType,
) -> Term {
    if end - start == 1 {
        return builder.bind(
            Type::Sum(runtime_value.clone()),
            RValue::Project {
                tuple: Operand::Local(bank),
                index: start,
            },
            |builder, value| valid_lookup(builder, lookup, value),
        );
    }
    let middle = start + (end - start) / 2;
    builder.bind(
        Type::Bool,
        primitive(
            Primitive::I64CmpLt,
            vec![Operand::Local(index), Operand::I64(i64::from(middle))],
        ),
        |builder, goes_left| Term::If {
            condition: Operand::Local(goes_left),
            then_term: Box::new(build_get_slot_tree(
                builder,
                bank,
                index,
                start,
                middle,
                runtime_value,
                lookup,
            )),
            else_term: Box::new(build_get_slot_tree(
                builder,
                bank,
                index,
                middle,
                end,
                runtime_value,
                lookup,
            )),
        },
    )
}

fn invalid_update(builder: &mut TermBuilder, update: &SumType) -> Term {
    builder.bind(
        Type::Sum(update.clone()),
        RValue::Construct {
            sum: update.clone(),
            constructor: 0,
            fields: vec![],
        },
        |_builder, value| Term::Return(Operand::Local(value)),
    )
}

fn checked_set_slot(
    builder: &mut TermBuilder,
    bank: LocalId,
    index: LocalId,
    value: LocalId,
    runtime_value: &SumType,
    bank_type: &Type,
    update: &SumType,
) -> Term {
    builder.bind(
        Type::Bool,
        primitive(
            Primitive::I64CmpLt,
            vec![Operand::Local(index), Operand::I64(0)],
        ),
        |builder, negative| {
            let nonnegative = builder.bind(
                Type::Bool,
                primitive(
                    Primitive::I64CmpGe,
                    vec![
                        Operand::Local(index),
                        Operand::I64(COREVM0_MAX_STACK as i64),
                    ],
                ),
                |builder, too_large| {
                    let selected = build_set_slot_tree(
                        builder,
                        bank,
                        index,
                        value,
                        0,
                        16,
                        runtime_value,
                        bank_type,
                        update,
                    );
                    Term::If {
                        condition: Operand::Local(too_large),
                        then_term: Box::new(invalid_update(builder, update)),
                        else_term: Box::new(selected),
                    }
                },
            );
            Term::If {
                condition: Operand::Local(negative),
                then_term: Box::new(invalid_update(builder, update)),
                else_term: Box::new(nonnegative),
            }
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn build_set_slot_tree(
    builder: &mut TermBuilder,
    bank: LocalId,
    index: LocalId,
    value: LocalId,
    start: u32,
    end: u32,
    runtime_value: &SumType,
    bank_type: &Type,
    update: &SumType,
) -> Term {
    if end - start == 1 {
        return rebuild_bank(
            builder,
            bank,
            value,
            start,
            0,
            Vec::with_capacity(16),
            runtime_value,
            bank_type,
            update,
        );
    }
    let middle = start + (end - start) / 2;
    builder.bind(
        Type::Bool,
        primitive(
            Primitive::I64CmpLt,
            vec![Operand::Local(index), Operand::I64(i64::from(middle))],
        ),
        |builder, goes_left| Term::If {
            condition: Operand::Local(goes_left),
            then_term: Box::new(build_set_slot_tree(
                builder,
                bank,
                index,
                value,
                start,
                middle,
                runtime_value,
                bank_type,
                update,
            )),
            else_term: Box::new(build_set_slot_tree(
                builder,
                bank,
                index,
                value,
                middle,
                end,
                runtime_value,
                bank_type,
                update,
            )),
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn rebuild_bank(
    builder: &mut TermBuilder,
    bank: LocalId,
    replacement: LocalId,
    replacement_index: u32,
    cursor: u32,
    mut fields: Vec<Operand>,
    runtime_value: &SumType,
    bank_type: &Type,
    update: &SumType,
) -> Term {
    if cursor == 16 {
        return builder.bind(
            bank_type.clone(),
            RValue::Tuple(fields),
            |builder, rebuilt| {
                builder.bind(
                    Type::Sum(update.clone()),
                    RValue::Construct {
                        sum: update.clone(),
                        constructor: 1,
                        fields: vec![Operand::Local(rebuilt)],
                    },
                    |_builder, result| Term::Return(Operand::Local(result)),
                )
            },
        );
    }
    if cursor == replacement_index {
        fields.push(Operand::Local(replacement));
        return rebuild_bank(
            builder,
            bank,
            replacement,
            replacement_index,
            cursor + 1,
            fields,
            runtime_value,
            bank_type,
            update,
        );
    }
    builder.bind(
        Type::Sum(runtime_value.clone()),
        RValue::Project {
            tuple: Operand::Local(bank),
            index: cursor,
        },
        |builder, field| {
            fields.push(Operand::Local(field));
            rebuild_bank(
                builder,
                bank,
                replacement,
                replacement_index,
                cursor + 1,
                fields,
                runtime_value,
                bank_type,
                update,
            )
        },
    )
}

fn checked_get_argument(
    builder: &mut TermBuilder,
    index: LocalId,
    arguments: &[LocalId],
    argument_types: &[CoreVmType],
    runtime_value: &SumType,
    lookup: &SumType,
) -> Term {
    if arguments.is_empty() {
        return invalid_lookup(builder, lookup);
    }
    builder.bind(
        Type::Bool,
        primitive(
            Primitive::I64CmpLt,
            vec![Operand::Local(index), Operand::I64(0)],
        ),
        |builder, negative| {
            let nonnegative = builder.bind(
                Type::Bool,
                primitive(
                    Primitive::I64CmpGe,
                    vec![Operand::Local(index), Operand::I64(arguments.len() as i64)],
                ),
                |builder, too_large| {
                    let selected = build_get_argument_tree(
                        builder,
                        index,
                        arguments,
                        argument_types,
                        0,
                        arguments.len(),
                        runtime_value,
                        lookup,
                    );
                    Term::If {
                        condition: Operand::Local(too_large),
                        then_term: Box::new(invalid_lookup(builder, lookup)),
                        else_term: Box::new(selected),
                    }
                },
            );
            Term::If {
                condition: Operand::Local(negative),
                then_term: Box::new(invalid_lookup(builder, lookup)),
                else_term: Box::new(nonnegative),
            }
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn build_get_argument_tree(
    builder: &mut TermBuilder,
    index: LocalId,
    arguments: &[LocalId],
    argument_types: &[CoreVmType],
    start: usize,
    end: usize,
    runtime_value: &SumType,
    lookup: &SumType,
) -> Term {
    if end - start == 1 {
        let constructor = match argument_types[start] {
            CoreVmType::Bool => 0,
            CoreVmType::I64 => 1,
            CoreVmType::F64 => 2,
            CoreVmType::ArrayF64 => 3,
        };
        return builder.bind(
            Type::Sum(runtime_value.clone()),
            RValue::Construct {
                sum: runtime_value.clone(),
                constructor,
                fields: vec![Operand::Local(arguments[start])],
            },
            |builder, value| valid_lookup(builder, lookup, value),
        );
    }
    let middle = start + (end - start) / 2;
    builder.bind(
        Type::Bool,
        primitive(
            Primitive::I64CmpLt,
            vec![Operand::Local(index), Operand::I64(middle as i64)],
        ),
        |builder, goes_left| Term::If {
            condition: Operand::Local(goes_left),
            then_term: Box::new(build_get_argument_tree(
                builder,
                index,
                arguments,
                argument_types,
                start,
                middle,
                runtime_value,
                lookup,
            )),
            else_term: Box::new(build_get_argument_tree(
                builder,
                index,
                arguments,
                argument_types,
                middle,
                end,
                runtime_value,
                lookup,
            )),
        },
    )
}

fn dispatch_slot(
    builder: &mut TermBuilder,
    slot: LocalId,
    context: &LoopContext,
    runtime_value: &SumType,
    bank: &Type,
    lookup: &SumType,
    update: &SumType,
) -> Term {
    let instruction = builder.fresh();
    let dispatch = dispatch_instruction(
        builder,
        instruction,
        context,
        runtime_value,
        bank,
        lookup,
        update,
    );
    Term::Case {
        scrutinee: Operand::Local(slot),
        arms: vec![
            CaseArm {
                constructor: 0,
                bindings: vec![],
                body: trap_term(),
            },
            CaseArm {
                constructor: 1,
                bindings: vec![instruction],
                body: dispatch,
            },
        ],
    }
}

fn dispatch_instruction(
    builder: &mut TermBuilder,
    instruction: LocalId,
    context: &LoopContext,
    runtime_value: &SumType,
    bank: &Type,
    lookup: &SumType,
    update: &SumType,
) -> Term {
    let instruction_type = super::corevm0::corevm0_instruction_sum_type();
    let mut arms = Vec::with_capacity(16);
    for constructor in 0_u32..16 {
        let fields: Vec<LocalId> = instruction_type.constructors[constructor as usize]
            .fields
            .iter()
            .map(|_| builder.fresh())
            .collect();
        let body = opcode_term(
            builder,
            constructor,
            &fields,
            context,
            runtime_value,
            bank,
            lookup,
            update,
        );
        arms.push(CaseArm {
            constructor,
            bindings: fields,
            body,
        });
    }
    Term::Case {
        scrutinee: Operand::Local(instruction),
        arms,
    }
}

#[allow(clippy::too_many_arguments)]
fn opcode_term(
    builder: &mut TermBuilder,
    opcode: u32,
    fields: &[LocalId],
    context: &LoopContext,
    runtime_value: &SumType,
    bank: &Type,
    lookup: &SumType,
    update: &SumType,
) -> Term {
    match opcode {
        0 => construct_runtime_and_push(
            builder,
            runtime_value,
            1,
            Operand::Local(fields[0]),
            context,
            bank,
            update,
        ),
        1 => construct_runtime_and_push(
            builder,
            runtime_value,
            2,
            Operand::Local(fields[0]),
            context,
            bank,
            update,
        ),
        2 => load_argument(builder, fields[0], context, bank, lookup, update),
        3 => load_local(builder, fields[0], context, bank, lookup, update),
        4 => store_local(builder, fields[0], context, lookup, update),
        5 => binary_i64(
            builder,
            Primitive::I64Add(NumericMode::Wrapping),
            1,
            context,
            runtime_value,
            bank,
            lookup,
            update,
        ),
        6 => binary_i64(
            builder,
            Primitive::I64Sub(NumericMode::Wrapping),
            1,
            context,
            runtime_value,
            bank,
            lookup,
            update,
        ),
        7 => binary_f64(
            builder,
            Primitive::F64Add,
            context,
            runtime_value,
            bank,
            lookup,
            update,
        ),
        8 => binary_f64(
            builder,
            Primitive::F64Sub,
            context,
            runtime_value,
            bank,
            lookup,
            update,
        ),
        9 => binary_i64(
            builder,
            Primitive::I64CmpLt,
            0,
            context,
            runtime_value,
            bank,
            lookup,
            update,
        ),
        10 => binary_i64(
            builder,
            Primitive::I64CmpGe,
            0,
            context,
            runtime_value,
            bank,
            lookup,
            update,
        ),
        11 => array_len(builder, context, runtime_value, bank, lookup, update),
        12 => array_get(builder, context, runtime_value, bank, lookup, update),
        13 => tail_loop(
            context.instructions,
            context.instruction_count,
            &context.arguments,
            Operand::Local(fields[0]),
            Operand::Local(context.sp),
            context.stack,
            context.locals,
        ),
        14 => jump_if_false(builder, fields[0], context, lookup),
        15 => return_f64(builder, context, lookup),
        _ => unreachable!("instruction schema has exactly 16 constructors"),
    }
}

fn construct_runtime_and_push(
    builder: &mut TermBuilder,
    runtime_value: &SumType,
    constructor: u32,
    field: Operand,
    context: &LoopContext,
    bank: &Type,
    update: &SumType,
) -> Term {
    builder.bind(
        Type::Sum(runtime_value.clone()),
        RValue::Construct {
            sum: runtime_value.clone(),
            constructor,
            fields: vec![field],
        },
        |builder, value| push_and_advance(builder, value, context, bank, update),
    )
}

fn push_and_advance(
    builder: &mut TermBuilder,
    value: LocalId,
    context: &LoopContext,
    bank: &Type,
    update: &SumType,
) -> Term {
    builder.bind(
        Type::Sum(update.clone()),
        RValue::Call {
            function: SET_SLOT_FUNCTION,
            arguments: vec![
                Operand::Local(context.stack),
                Operand::Local(context.sp),
                Operand::Local(value),
            ],
        },
        |builder, update_value| {
            expect_update(builder, update_value, update, bank, |builder, stack| {
                builder.bind(
                    Type::I64,
                    primitive(
                        Primitive::I64Add(NumericMode::Wrapping),
                        vec![Operand::Local(context.sp), Operand::I64(1)],
                    ),
                    |builder, next_sp| {
                        advance_pc(builder, context.pc, |_builder, next_pc| {
                            tail_loop(
                                context.instructions,
                                context.instruction_count,
                                &context.arguments,
                                Operand::Local(next_pc),
                                Operand::Local(next_sp),
                                stack,
                                context.locals,
                            )
                        })
                    },
                )
            })
        },
    )
}

fn load_argument(
    builder: &mut TermBuilder,
    index: LocalId,
    context: &LoopContext,
    bank: &Type,
    lookup: &SumType,
    update: &SumType,
) -> Term {
    let mut arguments: Vec<Operand> = context
        .arguments
        .iter()
        .copied()
        .map(Operand::Local)
        .collect();
    arguments.push(Operand::Local(index));
    builder.bind(
        Type::Sum(lookup.clone()),
        RValue::Call {
            function: GET_ARGUMENT_FUNCTION,
            arguments,
        },
        |builder, result| {
            expect_lookup(builder, result, lookup, |builder, value| {
                push_and_advance(builder, value, context, bank, update)
            })
        },
    )
}

fn load_local(
    builder: &mut TermBuilder,
    index: LocalId,
    context: &LoopContext,
    bank: &Type,
    lookup: &SumType,
    update: &SumType,
) -> Term {
    builder.bind(
        Type::Sum(lookup.clone()),
        RValue::Call {
            function: GET_SLOT_FUNCTION,
            arguments: vec![Operand::Local(context.locals), Operand::Local(index)],
        },
        |builder, result| {
            expect_lookup(builder, result, lookup, |builder, value| {
                push_and_advance(builder, value, context, bank, update)
            })
        },
    )
}

fn store_local(
    builder: &mut TermBuilder,
    index: LocalId,
    context: &LoopContext,
    lookup: &SumType,
    update: &SumType,
) -> Term {
    pop_one(builder, context, lookup, |builder, value, next_sp| {
        builder.bind(
            Type::Sum(update.clone()),
            RValue::Call {
                function: SET_SLOT_FUNCTION,
                arguments: vec![
                    Operand::Local(context.locals),
                    Operand::Local(index),
                    Operand::Local(value),
                ],
            },
            |builder, result| {
                expect_update(
                    builder,
                    result,
                    update,
                    &Type::Tuple(vec![
                        Type::Sum(runtime_value_sum_type());
                        COREVM0_MAX_LOCALS
                    ]),
                    |builder, locals| {
                        advance_pc(builder, context.pc, |_builder, next_pc| {
                            tail_loop(
                                context.instructions,
                                context.instruction_count,
                                &context.arguments,
                                Operand::Local(next_pc),
                                Operand::Local(next_sp),
                                context.stack,
                                locals,
                            )
                        })
                    },
                )
            },
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn binary_i64(
    builder: &mut TermBuilder,
    operation: Primitive,
    result_constructor: u32,
    context: &LoopContext,
    runtime_value: &SumType,
    bank: &Type,
    lookup: &SumType,
    update: &SumType,
) -> Term {
    pop_two(
        builder,
        context,
        lookup,
        |builder, left, right, result_index, next_sp| {
            expect_runtime(builder, left, runtime_value, 1, |builder, left_value| {
                expect_runtime(builder, right, runtime_value, 1, |builder, right_value| {
                    let result_type = if result_constructor == 0 {
                        Type::Bool
                    } else {
                        Type::I64
                    };
                    builder.bind(
                        result_type,
                        primitive(
                            operation,
                            vec![Operand::Local(left_value), Operand::Local(right_value)],
                        ),
                        |builder, result| {
                            builder.bind(
                                Type::Sum(runtime_value.clone()),
                                RValue::Construct {
                                    sum: runtime_value.clone(),
                                    constructor: result_constructor,
                                    fields: vec![Operand::Local(result)],
                                },
                                |builder, wrapped| {
                                    replace_top_and_advance(
                                        builder,
                                        wrapped,
                                        result_index,
                                        next_sp,
                                        context,
                                        bank,
                                        update,
                                    )
                                },
                            )
                        },
                    )
                })
            })
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn binary_f64(
    builder: &mut TermBuilder,
    operation: Primitive,
    context: &LoopContext,
    runtime_value: &SumType,
    bank: &Type,
    lookup: &SumType,
    update: &SumType,
) -> Term {
    pop_two(
        builder,
        context,
        lookup,
        |builder, left, right, result_index, next_sp| {
            expect_runtime(builder, left, runtime_value, 2, |builder, left_value| {
                expect_runtime(builder, right, runtime_value, 2, |builder, right_value| {
                    builder.bind(
                        Type::F64,
                        primitive(
                            operation,
                            vec![Operand::Local(left_value), Operand::Local(right_value)],
                        ),
                        |builder, result| {
                            builder.bind(
                                Type::Sum(runtime_value.clone()),
                                RValue::Construct {
                                    sum: runtime_value.clone(),
                                    constructor: 2,
                                    fields: vec![Operand::Local(result)],
                                },
                                |builder, wrapped| {
                                    replace_top_and_advance(
                                        builder,
                                        wrapped,
                                        result_index,
                                        next_sp,
                                        context,
                                        bank,
                                        update,
                                    )
                                },
                            )
                        },
                    )
                })
            })
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn replace_top_and_advance(
    builder: &mut TermBuilder,
    value: LocalId,
    index: LocalId,
    next_sp: LocalId,
    context: &LoopContext,
    bank: &Type,
    update: &SumType,
) -> Term {
    builder.bind(
        Type::Sum(update.clone()),
        RValue::Call {
            function: SET_SLOT_FUNCTION,
            arguments: vec![
                Operand::Local(context.stack),
                Operand::Local(index),
                Operand::Local(value),
            ],
        },
        |builder, result| {
            expect_update(builder, result, update, bank, |builder, stack| {
                advance_pc(builder, context.pc, |_builder, next_pc| {
                    tail_loop(
                        context.instructions,
                        context.instruction_count,
                        &context.arguments,
                        Operand::Local(next_pc),
                        Operand::Local(next_sp),
                        stack,
                        context.locals,
                    )
                })
            })
        },
    )
}

fn array_len(
    builder: &mut TermBuilder,
    context: &LoopContext,
    runtime_value: &SumType,
    bank: &Type,
    lookup: &SumType,
    update: &SumType,
) -> Term {
    pop_one(builder, context, lookup, |builder, value, result_sp| {
        expect_runtime(builder, value, runtime_value, 3, |builder, array| {
            builder.bind(
                Type::I64,
                primitive(Primitive::ArrayLenF64, vec![Operand::Local(array)]),
                |builder, length| {
                    builder.bind(
                        Type::Sum(runtime_value.clone()),
                        RValue::Construct {
                            sum: runtime_value.clone(),
                            constructor: 1,
                            fields: vec![Operand::Local(length)],
                        },
                        |builder, wrapped| {
                            replace_top_after_pop_and_advance(
                                builder, wrapped, result_sp, context, bank, update,
                            )
                        },
                    )
                },
            )
        })
    })
}

fn array_get(
    builder: &mut TermBuilder,
    context: &LoopContext,
    runtime_value: &SumType,
    bank: &Type,
    lookup: &SumType,
    update: &SumType,
) -> Term {
    pop_two(
        builder,
        context,
        lookup,
        |builder, array_value, index_value, result_index, next_sp| {
            expect_runtime(builder, array_value, runtime_value, 3, |builder, array| {
                expect_runtime(builder, index_value, runtime_value, 1, |builder, index| {
                    builder.bind(
                        Type::F64,
                        primitive(
                            Primitive::ArrayGetF64,
                            vec![Operand::Local(array), Operand::Local(index)],
                        ),
                        |builder, value| {
                            builder.bind(
                                Type::Sum(runtime_value.clone()),
                                RValue::Construct {
                                    sum: runtime_value.clone(),
                                    constructor: 2,
                                    fields: vec![Operand::Local(value)],
                                },
                                |builder, wrapped| {
                                    replace_top_and_advance(
                                        builder,
                                        wrapped,
                                        result_index,
                                        next_sp,
                                        context,
                                        bank,
                                        update,
                                    )
                                },
                            )
                        },
                    )
                })
            })
        },
    )
}

fn replace_top_after_pop_and_advance(
    builder: &mut TermBuilder,
    value: LocalId,
    index: LocalId,
    context: &LoopContext,
    bank: &Type,
    update: &SumType,
) -> Term {
    builder.bind(
        Type::Sum(update.clone()),
        RValue::Call {
            function: SET_SLOT_FUNCTION,
            arguments: vec![
                Operand::Local(context.stack),
                Operand::Local(index),
                Operand::Local(value),
            ],
        },
        |builder, result| {
            expect_update(builder, result, update, bank, |builder, stack| {
                advance_pc(builder, context.pc, |builder, next_pc| {
                    builder.bind(
                        Type::I64,
                        primitive(
                            Primitive::I64Add(NumericMode::Wrapping),
                            vec![Operand::Local(index), Operand::I64(1)],
                        ),
                        |_builder, next_sp| {
                            tail_loop(
                                context.instructions,
                                context.instruction_count,
                                &context.arguments,
                                Operand::Local(next_pc),
                                Operand::Local(next_sp),
                                stack,
                                context.locals,
                            )
                        },
                    )
                })
            })
        },
    )
}

fn jump_if_false(
    builder: &mut TermBuilder,
    target: LocalId,
    context: &LoopContext,
    lookup: &SumType,
) -> Term {
    pop_one(builder, context, lookup, |builder, value, next_sp| {
        expect_runtime(
            builder,
            value,
            &runtime_value_sum_type(),
            0,
            |builder, condition| {
                let then_term = advance_pc(builder, context.pc, |_builder, next_pc| {
                    tail_loop(
                        context.instructions,
                        context.instruction_count,
                        &context.arguments,
                        Operand::Local(next_pc),
                        Operand::Local(next_sp),
                        context.stack,
                        context.locals,
                    )
                });
                let else_term = tail_loop(
                    context.instructions,
                    context.instruction_count,
                    &context.arguments,
                    Operand::Local(target),
                    Operand::Local(next_sp),
                    context.stack,
                    context.locals,
                );
                Term::If {
                    condition: Operand::Local(condition),
                    then_term: Box::new(then_term),
                    else_term: Box::new(else_term),
                }
            },
        )
    })
}

fn return_f64(builder: &mut TermBuilder, context: &LoopContext, lookup: &SumType) -> Term {
    pop_one(builder, context, lookup, |builder, value, _next_sp| {
        expect_runtime(
            builder,
            value,
            &runtime_value_sum_type(),
            2,
            |_builder, result| Term::Return(Operand::Local(result)),
        )
    })
}

fn pop_one<F>(builder: &mut TermBuilder, context: &LoopContext, lookup: &SumType, next: F) -> Term
where
    F: FnOnce(&mut TermBuilder, LocalId, LocalId) -> Term,
{
    builder.bind(
        Type::I64,
        primitive(
            Primitive::I64Sub(NumericMode::Wrapping),
            vec![Operand::Local(context.sp), Operand::I64(1)],
        ),
        |builder, next_sp| {
            builder.bind(
                Type::Sum(lookup.clone()),
                RValue::Call {
                    function: GET_SLOT_FUNCTION,
                    arguments: vec![Operand::Local(context.stack), Operand::Local(next_sp)],
                },
                |builder, result| {
                    expect_lookup(builder, result, lookup, |builder, value| {
                        next(builder, value, next_sp)
                    })
                },
            )
        },
    )
}

fn pop_two<F>(builder: &mut TermBuilder, context: &LoopContext, lookup: &SumType, next: F) -> Term
where
    F: FnOnce(&mut TermBuilder, LocalId, LocalId, LocalId, LocalId) -> Term,
{
    builder.bind(
        Type::I64,
        primitive(
            Primitive::I64Sub(NumericMode::Wrapping),
            vec![Operand::Local(context.sp), Operand::I64(1)],
        ),
        |builder, right_index| {
            builder.bind(
                Type::Sum(lookup.clone()),
                RValue::Call {
                    function: GET_SLOT_FUNCTION,
                    arguments: vec![Operand::Local(context.stack), Operand::Local(right_index)],
                },
                |builder, right_lookup| {
                    expect_lookup(builder, right_lookup, lookup, |builder, right| {
                        builder.bind(
                            Type::I64,
                            primitive(
                                Primitive::I64Sub(NumericMode::Wrapping),
                                vec![Operand::Local(right_index), Operand::I64(1)],
                            ),
                            |builder, left_index| {
                                builder.bind(
                                    Type::Sum(lookup.clone()),
                                    RValue::Call {
                                        function: GET_SLOT_FUNCTION,
                                        arguments: vec![
                                            Operand::Local(context.stack),
                                            Operand::Local(left_index),
                                        ],
                                    },
                                    |builder, left_lookup| {
                                        expect_lookup(
                                            builder,
                                            left_lookup,
                                            lookup,
                                            |builder, left| {
                                                next(builder, left, right, left_index, right_index)
                                            },
                                        )
                                    },
                                )
                            },
                        )
                    })
                },
            )
        },
    )
}

fn expect_lookup<F>(
    builder: &mut TermBuilder,
    lookup_value: LocalId,
    _lookup: &SumType,
    next: F,
) -> Term
where
    F: FnOnce(&mut TermBuilder, LocalId) -> Term,
{
    let value = builder.fresh();
    let body = next(builder, value);
    Term::Case {
        scrutinee: Operand::Local(lookup_value),
        arms: vec![
            CaseArm {
                constructor: 0,
                bindings: vec![],
                body: trap_term(),
            },
            CaseArm {
                constructor: 1,
                bindings: vec![value],
                body,
            },
        ],
    }
}

fn expect_update<F>(
    builder: &mut TermBuilder,
    update_value: LocalId,
    update: &SumType,
    bank: &Type,
    next: F,
) -> Term
where
    F: FnOnce(&mut TermBuilder, LocalId) -> Term,
{
    let rebuilt = builder.fresh();
    let body = next(builder, rebuilt);
    debug_assert_eq!(
        update.constructors[1].fields.first(),
        Some(bank),
        "bank update type must carry the canonical bank"
    );
    Term::Case {
        scrutinee: Operand::Local(update_value),
        arms: vec![
            CaseArm {
                constructor: 0,
                bindings: vec![],
                body: trap_term(),
            },
            CaseArm {
                constructor: 1,
                bindings: vec![rebuilt],
                body,
            },
        ],
    }
}

fn expect_runtime<F>(
    builder: &mut TermBuilder,
    value: LocalId,
    runtime_value: &SumType,
    expected_constructor: u32,
    next: F,
) -> Term
where
    F: FnOnce(&mut TermBuilder, LocalId) -> Term,
{
    let mut next = Some(next);
    let mut arms = Vec::with_capacity(runtime_value.constructors.len());
    for (constructor, constructor_type) in runtime_value.constructors.iter().enumerate() {
        let bindings: Vec<LocalId> = constructor_type
            .fields
            .iter()
            .map(|_| builder.fresh())
            .collect();
        let body = if constructor as u32 == expected_constructor {
            let field = bindings[0];
            next.take()
                .expect("expected runtime constructor appears once")(builder, field)
        } else {
            trap_term()
        };
        arms.push(CaseArm {
            constructor: constructor as u32,
            bindings,
            body,
        });
    }
    Term::Case {
        scrutinee: Operand::Local(value),
        arms,
    }
}

fn core_value_from_vm(value: CoreVmValue) -> CoreValue {
    match value {
        CoreVmValue::Bool(value) => CoreValue::Bool(value),
        CoreVmValue::I64(value) => CoreValue::I64(value),
        CoreVmValue::F64(value) => CoreValue::F64(value),
        CoreVmValue::ArrayF64(values) => CoreValue::ArrayF64(values),
    }
}

fn specialization_to_core_value(
    value: &SpecializationValue,
) -> Result<CoreValue, DefinitionalCoreVmBuildError> {
    match value {
        SpecializationValue::Unit => Ok(CoreValue::Unit),
        SpecializationValue::Bool(value) => Ok(CoreValue::Bool(*value)),
        SpecializationValue::I64(value) => Ok(CoreValue::I64(*value)),
        SpecializationValue::F64(value) => Ok(CoreValue::F64(*value)),
        SpecializationValue::Tuple(fields) => fields
            .iter()
            .map(specialization_to_core_value)
            .collect::<Result<Vec<_>, _>>()
            .map(CoreValue::Tuple),
        SpecializationValue::Sum {
            ty,
            constructor,
            fields,
        } => Ok(CoreValue::Sum {
            ty: ty.clone(),
            constructor: *constructor,
            fields: fields
                .iter()
                .map(specialization_to_core_value)
                .collect::<Result<Vec<_>, _>>()?,
        }),
        SpecializationValue::ArrayF64(values) => Ok(CoreValue::array_f64(values.clone())),
    }
}
