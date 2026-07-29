use super::schema::{
    CoreArtifact, EffectRow, ErrorKind, FunctionId, HandlerClause, LocalId, Mutability,
    NumericMode, Operand, OperationSignature, Primitive, RValue, RegionId, SumType, Term, Type,
};
use super::verify::{verify, VerificationErrors, VerifiedArtifact};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

const MAX_SAFE_CALL_DEPTH: u32 = 256;

#[derive(Clone, Debug, PartialEq)]
pub enum CoreValue {
    Unit,
    Bool(bool),
    I64(i64),
    F64(f64),
    Tuple(Vec<CoreValue>),
    Sum {
        ty: SumType,
        constructor: u32,
        fields: Vec<CoreValue>,
    },
    ArrayF64(Arc<[f64]>),
    Reference(LogicalReference),
    Closure(CoreClosure),
}

impl CoreValue {
    pub fn array_f64(values: impl Into<Vec<f64>>) -> Self {
        Self::ArrayF64(Arc::from(values.into()))
    }
}

/// An opaque logical reference created only by the verified canonical
/// interpreter. Its identity is intentionally unavailable to Core programs
/// and its location is omitted from debug output.
#[derive(Clone, PartialEq, Eq)]
pub struct LogicalReference {
    region: RegionId,
    mutability: Mutability,
    element: Type,
    location: u64,
}

impl fmt::Debug for LogicalReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogicalReference")
            .field("region", &self.region)
            .field("mutability", &self.mutability)
            .field("element", &self.element)
            .field("location", &"<opaque>")
            .finish()
    }
}

/// A closure value with an existentially hidden ordered environment.
/// Captures are intentionally absent from debug output.
#[derive(Clone, PartialEq)]
pub struct CoreClosure {
    function: FunctionId,
    captures: Vec<CoreValue>,
    parameters: Vec<Type>,
    effects: EffectRow,
    result: Type,
}

impl fmt::Debug for CoreClosure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreClosure")
            .field("function", &self.function)
            .field("capture_count", &self.captures.len())
            .field("parameters", &self.parameters)
            .field("effects", &self.effects)
            .field("result", &self.result)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectEvent {
    Error(ErrorKind),
}

#[derive(Clone, Debug, PartialEq)]
pub enum EvaluationOutcome {
    Return(CoreValue),
    Error(ErrorKind),
    UnhandledOperation(OperationRequest),
}

#[derive(Clone, Debug, PartialEq)]
pub struct OperationRequest {
    pub operation: OperationSignature,
    pub arguments: Vec<CoreValue>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Evaluation {
    pub outcome: EvaluationOutcome,
    pub steps: u64,
    pub effect_trace: Vec<EffectEvent>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvaluationBudget {
    pub max_steps: u64,
    pub max_call_depth: u32,
}

impl EvaluationBudget {
    pub fn new(max_steps: u64, max_call_depth: u32) -> Self {
        Self {
            max_steps,
            max_call_depth,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionError {
    InvalidArtifact(VerificationErrors),
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
    InternalInvariant(String),
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArtifact(errors) => write!(formatter, "{errors}"),
            Self::InvalidEntryArguments { expected, actual } => {
                write!(
                    formatter,
                    "entry argument mismatch: expected {expected:?}; found {actual:?}"
                )
            }
            Self::StepBudgetExceeded { limit } => {
                write!(formatter, "Core-N0 evaluation exceeded {limit} steps")
            }
            Self::CallDepthExceeded { limit } => {
                write!(formatter, "Core-N0 evaluation exceeded call depth {limit}")
            }
            Self::InternalInvariant(message) => {
                write!(formatter, "verified Core-N0 invariant failed: {message}")
            }
        }
    }
}

impl std::error::Error for ExecutionError {}

/// Verify and evaluate an artifact. There is deliberately no unchecked
/// interpreter entry point.
pub fn evaluate(
    artifact: &CoreArtifact,
    arguments: Vec<CoreValue>,
    budget: EvaluationBudget,
) -> Result<Evaluation, ExecutionError> {
    let verified = verify(artifact).map_err(ExecutionError::InvalidArtifact)?;
    Evaluator::new(verified, budget).evaluate(arguments)
}

struct Evaluator<'program> {
    verified: VerifiedArtifact<'program>,
    budget: EvaluationBudget,
    steps: u64,
    effect_trace: Vec<EffectEvent>,
}

enum Control {
    Return(CoreValue),
    TailCall(FunctionId, Vec<CoreValue>),
    Error(ErrorKind),
    UnhandledOperation(OperationRequest),
}

enum Computation {
    Value(CoreValue),
    Error(ErrorKind),
    UnhandledOperation(OperationRequest),
}

#[derive(Clone)]
struct LogicalCell {
    region: RegionId,
    mutability: Mutability,
    element: Type,
    value: CoreValue,
}

#[derive(Default)]
struct LogicalStore {
    next_location: u64,
    active_regions: BTreeSet<RegionId>,
    cells: BTreeMap<u64, LogicalCell>,
}

#[derive(Clone)]
struct ActiveHandler {
    captures: BTreeMap<LocalId, CoreValue>,
    clauses: Vec<HandlerClause>,
}

impl LogicalStore {
    fn open(&mut self, region: RegionId) -> Result<(), ExecutionError> {
        if !self.active_regions.insert(region) {
            return Err(Evaluator::invariant(format!(
                "verified region {} is already active",
                region.0
            )));
        }
        Ok(())
    }

    fn close(&mut self, region: RegionId) -> Result<(), ExecutionError> {
        if !self.active_regions.remove(&region) {
            return Err(Evaluator::invariant(format!(
                "verified region {} is not active",
                region.0
            )));
        }
        self.cells.retain(|_, cell| cell.region != region);
        Ok(())
    }

    fn allocate(
        &mut self,
        region: RegionId,
        mutability: Mutability,
        element: Type,
        value: CoreValue,
    ) -> Result<LogicalReference, ExecutionError> {
        if !self.active_regions.contains(&region) {
            return Err(Evaluator::invariant(format!(
                "allocation region {} is not active",
                region.0
            )));
        }
        let location = self.next_location;
        self.next_location = self
            .next_location
            .checked_add(1)
            .ok_or_else(|| Evaluator::invariant("logical location space exhausted"))?;
        self.cells.insert(
            location,
            LogicalCell {
                region,
                mutability,
                element: element.clone(),
                value,
            },
        );
        Ok(LogicalReference {
            region,
            mutability,
            element,
            location,
        })
    }

    fn load(&self, reference: &LogicalReference) -> Result<CoreValue, ExecutionError> {
        let cell = self.cell(reference)?;
        Ok(cell.value.clone())
    }

    fn store(
        &mut self,
        reference: &LogicalReference,
        value: CoreValue,
    ) -> Result<(), ExecutionError> {
        if !self.active_regions.contains(&reference.region) {
            return Err(Evaluator::invariant(format!(
                "reference region {} is not active",
                reference.region.0
            )));
        }
        let cell = self
            .cells
            .get_mut(&reference.location)
            .ok_or_else(|| Evaluator::invariant("verified reference location is not live"))?;
        if cell.region != reference.region
            || cell.mutability != reference.mutability
            || cell.element != reference.element
        {
            return Err(Evaluator::invariant(
                "verified reference metadata does not match its logical cell",
            ));
        }
        if !matches!(cell.mutability, Mutability::Shared | Mutability::Unique) {
            return Err(Evaluator::invariant(
                "verified store reached a non-writable logical cell",
            ));
        }
        if !value_matches(&value, &cell.element) {
            return Err(Evaluator::invariant(
                "verified store value does not match its logical cell type",
            ));
        }
        cell.value = value;
        Ok(())
    }

    fn cell(&self, reference: &LogicalReference) -> Result<&LogicalCell, ExecutionError> {
        if !self.active_regions.contains(&reference.region) {
            return Err(Evaluator::invariant(format!(
                "reference region {} is not active",
                reference.region.0
            )));
        }
        let cell = self
            .cells
            .get(&reference.location)
            .ok_or_else(|| Evaluator::invariant("verified reference location is not live"))?;
        if cell.region != reference.region
            || cell.mutability != reference.mutability
            || cell.element != reference.element
        {
            return Err(Evaluator::invariant(
                "verified reference metadata does not match its logical cell",
            ));
        }
        Ok(cell)
    }
}

impl<'program> Evaluator<'program> {
    fn new(verified: VerifiedArtifact<'program>, budget: EvaluationBudget) -> Self {
        Self {
            verified,
            budget,
            steps: 0,
            effect_trace: Vec::new(),
        }
    }

    fn evaluate(mut self, arguments: Vec<CoreValue>) -> Result<Evaluation, ExecutionError> {
        let entry = self.verified.program().entry;
        let function = self
            .find_function(entry)
            .ok_or_else(|| Self::invariant(format!("entry function {} disappeared", entry.0)))?;
        let expected: Vec<Type> = function
            .parameters
            .iter()
            .map(|parameter| parameter.ty.clone())
            .collect();
        if !arguments_match(&arguments, &expected) {
            return Err(ExecutionError::InvalidEntryArguments {
                expected,
                actual: arguments.iter().map(value_kind).collect(),
            });
        }

        let outcome = self.invoke(entry, arguments, 0, &[])?;
        Ok(Evaluation {
            outcome,
            steps: self.steps,
            effect_trace: self.effect_trace,
        })
    }

    fn invoke(
        &mut self,
        mut function_id: FunctionId,
        mut arguments: Vec<CoreValue>,
        depth: u32,
        handlers: &[ActiveHandler],
    ) -> Result<EvaluationOutcome, ExecutionError> {
        let call_depth_limit = self.budget.max_call_depth.min(MAX_SAFE_CALL_DEPTH);
        if depth > call_depth_limit {
            return Err(ExecutionError::CallDepthExceeded {
                limit: call_depth_limit,
            });
        }

        loop {
            let function = self
                .find_function(function_id)
                .cloned()
                .ok_or_else(|| Self::invariant(format!("missing function {}", function_id.0)))?;
            if !arguments_match(
                &arguments,
                &function
                    .parameters
                    .iter()
                    .map(|parameter| parameter.ty.clone())
                    .collect::<Vec<_>>(),
            ) {
                return Err(Self::invariant(format!(
                    "verified call to function {} has invalid arguments",
                    function_id.0
                )));
            }
            let mut environment = BTreeMap::new();
            for (parameter, argument) in function.parameters.iter().zip(arguments) {
                environment.insert(parameter.local, argument);
            }
            let mut store = LogicalStore::default();

            match self.eval_term(
                &function.body,
                &mut environment,
                &mut store,
                depth,
                handlers,
            )? {
                Control::Return(value) => return Ok(EvaluationOutcome::Return(value)),
                Control::Error(error) => return Ok(EvaluationOutcome::Error(error)),
                Control::UnhandledOperation(operation) => {
                    return Ok(EvaluationOutcome::UnhandledOperation(operation));
                }
                Control::TailCall(next_function, next_arguments) => {
                    function_id = next_function;
                    arguments = next_arguments;
                }
            }
        }
    }

    fn invoke_borrowed(
        &mut self,
        function_id: FunctionId,
        arguments: Vec<CoreValue>,
        depth: u32,
        store: &mut LogicalStore,
        handlers: &[ActiveHandler],
    ) -> Result<EvaluationOutcome, ExecutionError> {
        let call_depth_limit = self.budget.max_call_depth.min(MAX_SAFE_CALL_DEPTH);
        if depth > call_depth_limit {
            return Err(ExecutionError::CallDepthExceeded {
                limit: call_depth_limit,
            });
        }

        let mut function_id = function_id;
        let mut arguments = arguments;
        loop {
            let function = self
                .find_function(function_id)
                .cloned()
                .ok_or_else(|| Self::invariant(format!("missing function {}", function_id.0)))?;
            if !arguments_match(
                &arguments,
                &function
                    .parameters
                    .iter()
                    .map(|parameter| parameter.ty.clone())
                    .collect::<Vec<_>>(),
            ) {
                return Err(Self::invariant(format!(
                    "verified borrowed call to function {} has invalid arguments",
                    function_id.0
                )));
            }

            let mut environment = BTreeMap::new();
            for (parameter, argument) in function.parameters.iter().zip(arguments) {
                environment.insert(parameter.local, argument);
            }
            match self.eval_term(&function.body, &mut environment, store, depth, handlers)? {
                Control::Return(value) => return Ok(EvaluationOutcome::Return(value)),
                Control::Error(error) => return Ok(EvaluationOutcome::Error(error)),
                Control::UnhandledOperation(operation) => {
                    return Ok(EvaluationOutcome::UnhandledOperation(operation));
                }
                Control::TailCall(next_function, next_arguments) => {
                    if values_contain_non_unique_reference(&next_arguments) {
                        return Err(Self::invariant(
                            "verified borrowed call attempted a non-Unique reference-containing tail transfer",
                        ));
                    }
                    function_id = next_function;
                    arguments = next_arguments;
                }
            }
        }
    }

    fn eval_term(
        &mut self,
        term: &Term,
        environment: &mut BTreeMap<LocalId, CoreValue>,
        store: &mut LogicalStore,
        depth: u32,
        handlers: &[ActiveHandler],
    ) -> Result<Control, ExecutionError> {
        self.tick()?;
        match term {
            Term::Let {
                binder,
                value,
                next,
                ..
            } => match self.eval_rvalue(value, environment, store, depth, handlers)? {
                Computation::Value(value) => {
                    environment.insert(*binder, value);
                    self.eval_term(next, environment, store, depth, handlers)
                }
                Computation::Error(error) => Ok(Control::Error(error)),
                Computation::UnhandledOperation(operation) => {
                    Ok(Control::UnhandledOperation(operation))
                }
            },
            Term::If {
                condition,
                then_term,
                else_term,
            } => match self.eval_operand(condition, environment)? {
                CoreValue::Bool(true) => {
                    self.eval_term(then_term, environment, store, depth, handlers)
                }
                CoreValue::Bool(false) => {
                    self.eval_term(else_term, environment, store, depth, handlers)
                }
                _ => Err(Self::invariant("if condition is not Bool")),
            },
            Term::Case { scrutinee, arms } => {
                let CoreValue::Sum {
                    constructor,
                    fields,
                    ..
                } = self.eval_operand(scrutinee, environment)?
                else {
                    return Err(Self::invariant("case scrutinee is not a sum"));
                };
                let arm = arms
                    .get(constructor as usize)
                    .ok_or_else(|| Self::invariant("case constructor is out of range"))?;
                let mut arm_environment = environment.clone();
                for (binding, field) in arm.bindings.iter().zip(fields) {
                    arm_environment.insert(*binding, field);
                }
                self.eval_term(&arm.body, &mut arm_environment, store, depth, handlers)
            }
            Term::TailCall {
                function,
                arguments,
            } => {
                let arguments = self.eval_operands_move(arguments, environment)?;
                Ok(Control::TailCall(*function, arguments))
            }
            Term::Return(operand) => Ok(Control::Return(
                self.eval_operand_move(operand, environment)?,
            )),
            Term::Region { region, body } => {
                store.open(*region)?;
                let result = self.eval_term(body, environment, store, depth, handlers);
                let result = match result {
                    Ok(Control::TailCall(function, arguments))
                        if values_contain_reference(&arguments) =>
                    {
                        self.invoke_in_context(function, arguments, depth + 1, store, handlers)
                            .map(control_from_outcome)
                    }
                    other => other,
                };
                store.close(*region)?;
                result
            }
            Term::Handle {
                captures,
                capture_parameters,
                clauses,
                body,
            } => {
                let capture_values = self.eval_operands(captures, environment)?;
                let captures = capture_parameters
                    .iter()
                    .zip(capture_values)
                    .map(|(parameter, value)| (parameter.local, value))
                    .collect();
                let mut body_handlers = handlers.to_vec();
                body_handlers.push(ActiveHandler {
                    captures,
                    clauses: clauses.clone(),
                });
                let control = self.eval_term(body, environment, store, depth, &body_handlers)?;
                match control {
                    Control::TailCall(function, arguments) => {
                        let outcome = self.invoke_in_context(
                            function,
                            arguments,
                            depth + 1,
                            store,
                            &body_handlers,
                        )?;
                        Ok(control_from_outcome(outcome))
                    }
                    other => Ok(other),
                }
            }
        }
    }

    fn invoke_in_context(
        &mut self,
        function: FunctionId,
        arguments: Vec<CoreValue>,
        depth: u32,
        store: &mut LogicalStore,
        handlers: &[ActiveHandler],
    ) -> Result<EvaluationOutcome, ExecutionError> {
        if values_contain_reference(&arguments) || handlers_contain_reference(handlers) {
            self.invoke_borrowed(function, arguments, depth, store, handlers)
        } else {
            self.invoke(function, arguments, depth, handlers)
        }
    }

    fn resolve_clause_control(
        &mut self,
        control: Control,
        store: &mut LogicalStore,
        depth: u32,
        handlers: &[ActiveHandler],
    ) -> Result<Computation, ExecutionError> {
        match control {
            Control::Return(value) => Ok(Computation::Value(value)),
            Control::Error(error) => Ok(Computation::Error(error)),
            Control::UnhandledOperation(operation) => {
                Ok(Computation::UnhandledOperation(operation))
            }
            Control::TailCall(function, arguments) => {
                let outcome =
                    self.invoke_in_context(function, arguments, depth + 1, store, handlers)?;
                Ok(computation_from_outcome(outcome))
            }
        }
    }

    fn eval_rvalue(
        &mut self,
        value: &RValue,
        environment: &mut BTreeMap<LocalId, CoreValue>,
        store: &mut LogicalStore,
        depth: u32,
        handlers: &[ActiveHandler],
    ) -> Result<Computation, ExecutionError> {
        self.tick()?;
        match value {
            RValue::Use(operand) => Ok(Computation::Value(
                self.eval_operand_move(operand, environment)?,
            )),
            RValue::Tuple(fields) => Ok(Computation::Value(CoreValue::Tuple(
                self.eval_operands_move(fields, environment)?,
            ))),
            RValue::Project { tuple, index } => {
                let CoreValue::Tuple(fields) = self.eval_operand(tuple, environment)? else {
                    return Err(Self::invariant("tuple projection source is not a tuple"));
                };
                Ok(Computation::Value(
                    fields.get(*index as usize).cloned().ok_or_else(|| {
                        Self::invariant("verified tuple projection is out of bounds")
                    })?,
                ))
            }
            RValue::Construct {
                sum,
                constructor,
                fields,
            } => Ok(Computation::Value(CoreValue::Sum {
                ty: sum.clone(),
                constructor: *constructor,
                fields: self.eval_operands_move(fields, environment)?,
            })),
            RValue::Primitive {
                operation,
                arguments,
            } => {
                let arguments = self.eval_operands(arguments, environment)?;
                let result = self.eval_primitive(operation, arguments)?;
                if let Err(error) = &result {
                    self.effect_trace.push(EffectEvent::Error(error.clone()));
                }
                Ok(match result {
                    Ok(value) => Computation::Value(value),
                    Err(error) => Computation::Error(error),
                })
            }
            RValue::Call {
                function,
                arguments,
            } => {
                let arguments = self.eval_operands_move(arguments, environment)?;
                let outcome = if values_contain_reference(&arguments)
                    || handlers_contain_reference(handlers)
                {
                    self.invoke_borrowed(*function, arguments, depth + 1, store, handlers)?
                } else {
                    self.invoke(*function, arguments, depth + 1, handlers)?
                };
                Ok(computation_from_outcome(outcome))
            }
            RValue::RefAlloc {
                region,
                mutability,
                value,
            } => {
                let value = self.eval_operand(value, environment)?;
                let element = scalar_type(&value).ok_or_else(|| {
                    Self::invariant("verified RefAlloc value is not a logical-store scalar")
                })?;
                let reference = store.allocate(*region, *mutability, element, value)?;
                Ok(Computation::Value(CoreValue::Reference(reference)))
            }
            RValue::RefLoad { reference } => {
                let CoreValue::Reference(reference) = self.eval_operand(reference, environment)?
                else {
                    return Err(Self::invariant(
                        "verified RefLoad operand is not a reference",
                    ));
                };
                Ok(Computation::Value(store.load(&reference)?))
            }
            RValue::RefStore { reference, value } => {
                let CoreValue::Reference(reference) = self.eval_operand(reference, environment)?
                else {
                    return Err(Self::invariant(
                        "verified RefStore operand is not a reference",
                    ));
                };
                let value = self.eval_operand(value, environment)?;
                store.store(&reference, value)?;
                Ok(Computation::Value(CoreValue::Unit))
            }
            RValue::PackClosure { function, captures } => {
                let captures = self.eval_operands(captures, environment)?;
                let code = self.find_function(*function).cloned().ok_or_else(|| {
                    Self::invariant(format!("missing closure code function {}", function.0))
                })?;
                let parameters = code
                    .parameters
                    .iter()
                    .skip(1)
                    .map(|parameter| parameter.ty.clone())
                    .collect();
                Ok(Computation::Value(CoreValue::Closure(CoreClosure {
                    function: *function,
                    captures,
                    parameters,
                    effects: code.effects,
                    result: code.result,
                })))
            }
            RValue::CallClosure { closure, arguments } => {
                let CoreValue::Closure(closure) = self.eval_operand(closure, environment)? else {
                    return Err(Self::invariant(
                        "verified CallClosure operand is not a closure",
                    ));
                };
                let explicit_arguments = self.eval_operands(arguments, environment)?;
                let mut code_arguments = Vec::with_capacity(explicit_arguments.len() + 1);
                code_arguments.push(CoreValue::Tuple(closure.captures.clone()));
                code_arguments.extend(explicit_arguments);
                let outcome = if values_contain_reference(&code_arguments)
                    || handlers_contain_reference(handlers)
                {
                    self.invoke_borrowed(
                        closure.function,
                        code_arguments,
                        depth + 1,
                        store,
                        handlers,
                    )?
                } else {
                    self.invoke(closure.function, code_arguments, depth + 1, handlers)?
                };
                Ok(computation_from_outcome(outcome))
            }
            RValue::Perform {
                operation,
                arguments,
            } => {
                let arguments = self.eval_operands(arguments, environment)?;
                let selected = handlers
                    .iter()
                    .enumerate()
                    .rev()
                    .find_map(|(index, handler)| {
                        handler
                            .clauses
                            .iter()
                            .find(|clause| clause.operation == *operation)
                            .cloned()
                            .map(|clause| (index, handler.captures.clone(), clause))
                    });
                let Some((handler_index, mut clause_environment, clause)) = selected else {
                    return Ok(Computation::UnhandledOperation(OperationRequest {
                        operation: operation.clone(),
                        arguments,
                    }));
                };
                for (parameter, argument) in clause.parameters.iter().zip(arguments) {
                    clause_environment.insert(*parameter, argument);
                }
                let control = self.eval_term(
                    &clause.body,
                    &mut clause_environment,
                    store,
                    depth,
                    &handlers[..handler_index],
                )?;
                self.resolve_clause_control(control, store, depth, &handlers[..handler_index])
            }
        }
    }

    fn eval_primitive(
        &self,
        primitive: &Primitive,
        arguments: Vec<CoreValue>,
    ) -> Result<Result<CoreValue, ErrorKind>, ExecutionError> {
        match primitive {
            Primitive::I64Add(mode) => {
                let (left, right) = expect_i64_pair(arguments)?;
                Ok(apply_i64_binary(*mode, left, right, I64Operation::Add).map(CoreValue::I64))
            }
            Primitive::I64Sub(mode) => {
                let (left, right) = expect_i64_pair(arguments)?;
                Ok(apply_i64_binary(*mode, left, right, I64Operation::Sub).map(CoreValue::I64))
            }
            Primitive::I64Mul(mode) => {
                let (left, right) = expect_i64_pair(arguments)?;
                Ok(apply_i64_binary(*mode, left, right, I64Operation::Mul).map(CoreValue::I64))
            }
            Primitive::F64Add => {
                let (left, right) = expect_f64_pair(arguments)?;
                Ok(Ok(CoreValue::F64(left + right)))
            }
            Primitive::F64Sub => {
                let (left, right) = expect_f64_pair(arguments)?;
                Ok(Ok(CoreValue::F64(left - right)))
            }
            Primitive::I64CmpLt => {
                let (left, right) = expect_i64_pair(arguments)?;
                Ok(Ok(CoreValue::Bool(left < right)))
            }
            Primitive::I64CmpGe => {
                let (left, right) = expect_i64_pair(arguments)?;
                Ok(Ok(CoreValue::Bool(left >= right)))
            }
            Primitive::ArrayLenF64 => {
                let [CoreValue::ArrayF64(values)] = arguments.as_slice() else {
                    return Err(Self::invariant("ArrayLenF64 argument mismatch"));
                };
                let length = i64::try_from(values.len())
                    .map_err(|_| Self::invariant("array length does not fit I64"))?;
                Ok(Ok(CoreValue::I64(length)))
            }
            Primitive::ArrayGetF64 => {
                let [CoreValue::ArrayF64(values), CoreValue::I64(index)] = arguments.as_slice()
                else {
                    return Err(Self::invariant("ArrayGetF64 argument mismatch"));
                };
                let Ok(index) = usize::try_from(*index) else {
                    return Ok(Err(ErrorKind::Bounds));
                };
                Ok(match values.get(index) {
                    Some(value) => Ok(CoreValue::F64(*value)),
                    None => Err(ErrorKind::Bounds),
                })
            }
        }
    }

    fn eval_operands(
        &self,
        operands: &[Operand],
        environment: &BTreeMap<LocalId, CoreValue>,
    ) -> Result<Vec<CoreValue>, ExecutionError> {
        operands
            .iter()
            .map(|operand| self.eval_operand(operand, environment))
            .collect()
    }

    fn eval_operands_move(
        &self,
        operands: &[Operand],
        environment: &mut BTreeMap<LocalId, CoreValue>,
    ) -> Result<Vec<CoreValue>, ExecutionError> {
        let mut values = Vec::with_capacity(operands.len());
        for operand in operands {
            values.push(self.eval_operand_move(operand, environment)?);
        }
        Ok(values)
    }

    fn eval_operand_move(
        &self,
        operand: &Operand,
        environment: &mut BTreeMap<LocalId, CoreValue>,
    ) -> Result<CoreValue, ExecutionError> {
        let Operand::Local(local) = operand else {
            return self.eval_operand(operand, environment);
        };
        let is_unique = matches!(
            environment.get(local),
            Some(CoreValue::Reference(reference))
                if reference.mutability == Mutability::Unique
        );
        if is_unique {
            environment.remove(local).ok_or_else(|| {
                Self::invariant(format!("verified Unique local {} is not bound", local.0))
            })
        } else {
            self.eval_operand(operand, environment)
        }
    }

    fn eval_operand(
        &self,
        operand: &Operand,
        environment: &BTreeMap<LocalId, CoreValue>,
    ) -> Result<CoreValue, ExecutionError> {
        match operand {
            Operand::Unit => Ok(CoreValue::Unit),
            Operand::Bool(value) => Ok(CoreValue::Bool(*value)),
            Operand::I64(value) => Ok(CoreValue::I64(*value)),
            Operand::F64(value) => Ok(CoreValue::F64(*value)),
            Operand::Local(local) => environment
                .get(local)
                .cloned()
                .ok_or_else(|| Self::invariant(format!("verified local {} is not bound", local.0))),
        }
    }

    fn find_function(&self, id: FunctionId) -> Option<&super::schema::Function> {
        self.verified
            .program()
            .functions
            .binary_search_by_key(&id, |function| function.id)
            .ok()
            .map(|index| &self.verified.program().functions[index])
    }

    fn tick(&mut self) -> Result<(), ExecutionError> {
        if self.steps >= self.budget.max_steps {
            return Err(ExecutionError::StepBudgetExceeded {
                limit: self.budget.max_steps,
            });
        }
        self.steps += 1;
        Ok(())
    }

    fn invariant(message: impl Into<String>) -> ExecutionError {
        ExecutionError::InternalInvariant(message.into())
    }
}

enum I64Operation {
    Add,
    Sub,
    Mul,
}

fn apply_i64_binary(
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

fn expect_i64_pair(arguments: Vec<CoreValue>) -> Result<(i64, i64), ExecutionError> {
    let [CoreValue::I64(left), CoreValue::I64(right)] = arguments.as_slice() else {
        return Err(Evaluator::invariant("expected two I64 arguments"));
    };
    Ok((*left, *right))
}

fn expect_f64_pair(arguments: Vec<CoreValue>) -> Result<(f64, f64), ExecutionError> {
    let [CoreValue::F64(left), CoreValue::F64(right)] = arguments.as_slice() else {
        return Err(Evaluator::invariant("expected two F64 arguments"));
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
        (CoreValue::Tuple(values), Type::Tuple(types)) => arguments_match(values, types),
        (
            CoreValue::Sum {
                ty: value_type,
                constructor,
                fields,
            },
            Type::Sum(expected_type),
        ) => {
            value_type == expected_type
                && expected_type
                    .constructors
                    .get(*constructor as usize)
                    .is_some_and(|constructor_type| {
                        arguments_match(fields, &constructor_type.fields)
                    })
        }
        (CoreValue::ArrayF64(_), Type::Array { element, .. }) => element.as_ref() == &Type::F64,
        (
            CoreValue::Reference(reference),
            Type::Ref {
                region,
                mutability,
                element,
            },
        ) => {
            reference.region == *region
                && reference.mutability == *mutability
                && reference.element == **element
        }
        (
            CoreValue::Closure(closure),
            Type::Closure {
                parameters,
                effects,
                result,
            },
        ) => {
            closure.parameters == *parameters
                && closure.effects == *effects
                && closure.result == **result
        }
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

fn scalar_type(value: &CoreValue) -> Option<Type> {
    match value {
        CoreValue::Bool(_) => Some(Type::Bool),
        CoreValue::I64(_) => Some(Type::I64),
        CoreValue::F64(_) => Some(Type::F64),
        CoreValue::Unit
        | CoreValue::Tuple(_)
        | CoreValue::Sum { .. }
        | CoreValue::ArrayF64(_)
        | CoreValue::Reference(_)
        | CoreValue::Closure(_) => None,
    }
}

fn computation_from_outcome(outcome: EvaluationOutcome) -> Computation {
    match outcome {
        EvaluationOutcome::Return(value) => Computation::Value(value),
        EvaluationOutcome::Error(error) => Computation::Error(error),
        EvaluationOutcome::UnhandledOperation(operation) => {
            Computation::UnhandledOperation(operation)
        }
    }
}

fn control_from_outcome(outcome: EvaluationOutcome) -> Control {
    match outcome {
        EvaluationOutcome::Return(value) => Control::Return(value),
        EvaluationOutcome::Error(error) => Control::Error(error),
        EvaluationOutcome::UnhandledOperation(operation) => Control::UnhandledOperation(operation),
    }
}

fn values_contain_reference(values: &[CoreValue]) -> bool {
    values.iter().any(value_contains_reference)
}

fn values_contain_non_unique_reference(values: &[CoreValue]) -> bool {
    values.iter().any(value_contains_non_unique_reference)
}

fn handlers_contain_reference(handlers: &[ActiveHandler]) -> bool {
    handlers
        .iter()
        .flat_map(|handler| handler.captures.values())
        .any(value_contains_reference)
}

fn value_contains_reference(value: &CoreValue) -> bool {
    match value {
        CoreValue::Reference(_) => true,
        CoreValue::Tuple(fields) => fields.iter().any(value_contains_reference),
        CoreValue::Sum { fields, .. } => fields.iter().any(value_contains_reference),
        CoreValue::Closure(closure) => closure.captures.iter().any(value_contains_reference),
        CoreValue::Unit
        | CoreValue::Bool(_)
        | CoreValue::I64(_)
        | CoreValue::F64(_)
        | CoreValue::ArrayF64(_) => false,
    }
}

fn value_contains_non_unique_reference(value: &CoreValue) -> bool {
    match value {
        CoreValue::Reference(reference) => reference.mutability != Mutability::Unique,
        CoreValue::Tuple(fields) => fields.iter().any(value_contains_non_unique_reference),
        CoreValue::Sum { fields, .. } => fields.iter().any(value_contains_non_unique_reference),
        CoreValue::Closure(closure) => closure
            .captures
            .iter()
            .any(value_contains_non_unique_reference),
        CoreValue::Unit
        | CoreValue::Bool(_)
        | CoreValue::I64(_)
        | CoreValue::F64(_)
        | CoreValue::ArrayF64(_) => false,
    }
}
