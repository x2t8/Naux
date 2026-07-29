use crate::ast::{BinaryOp, Expr, ExprKind, Param, Span, Stmt, TypeAnnotation};
use crate::core::{
    verify, CoreArtifact, CoreProfile, CoreValue, EffectRow, Function, FunctionId, LocalId,
    Operand, Parameter, Primitive, Program, RValue, SchemaVersion, Term, Type,
};
use crate::runtime::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const T2A_MAX_INPUTS: usize = 256;
pub const T2A_MAX_SOURCE_STEPS: u64 = 256;
pub const T2A_MAX_CORE_NODES: u64 = 256;
pub const T2B_MAX_FUNCTIONS: usize = 32;
pub const T2B_MAX_PARAMETERS: usize = 32;
const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceElaborationProfile {
    T2A,
    T2B,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceScalarType {
    Bool,
    I64,
    F64,
}

impl SurfaceScalarType {
    fn core_type(self) -> Type {
        match self {
            Self::Bool => Type::Bool,
            Self::I64 => Type::I64,
            Self::F64 => Type::F64,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurfaceInput {
    pub name: String,
    pub ty: SurfaceScalarType,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurfaceFunctionSignature {
    pub name: String,
    pub parameters: Vec<SurfaceScalarType>,
    pub result: SurfaceScalarType,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SurfaceScalarValue {
    Bool(bool),
    I64(i64),
    F64(f64),
}

impl SurfaceScalarValue {
    fn ty(self) -> SurfaceScalarType {
        match self {
            Self::Bool(_) => SurfaceScalarType::Bool,
            Self::I64(_) => SurfaceScalarType::I64,
            Self::F64(_) => SurfaceScalarType::F64,
        }
    }

    fn to_surface(self) -> Value {
        match self {
            Self::Bool(value) => Value::Bool(value),
            Self::I64(value) => Value::SmallInt(value),
            Self::F64(value) => Value::Float(value),
        }
    }

    fn to_core(self) -> CoreValue {
        match self {
            Self::Bool(value) => CoreValue::Bool(value),
            Self::I64(value) => CoreValue::I64(value),
            Self::F64(value) => CoreValue::F64(value),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NormalizedScalar {
    Bool(bool),
    I64(i64),
    /// IEEE-754 bits with every NaN payload collapsed to one canonical NaN.
    /// Non-NaN values, including signed zero, retain their exact bits.
    F64Bits(u64),
}

#[derive(Clone, Debug)]
pub struct BoundSurfaceInputs {
    pub surface_bindings: Vec<(String, Value)>,
    pub core_arguments: Vec<CoreValue>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputBindingError {
    Arity {
        expected: usize,
        actual: usize,
    },
    Type {
        index: usize,
        name: String,
        expected: SurfaceScalarType,
        actual: SurfaceScalarType,
    },
}

impl fmt::Display for InputBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arity { expected, actual } => {
                write!(
                    formatter,
                    "expected {expected} Surface inputs; found {actual}"
                )
            }
            Self::Type {
                index,
                name,
                expected,
                actual,
            } => write!(
                formatter,
                "Surface input {index} `{name}` expects {expected:?}; found {actual:?}"
            ),
        }
    }
}

impl std::error::Error for InputBindingError {}

pub fn bind_surface_t2a_inputs(
    report: &ElaborationReport,
    values: &[SurfaceScalarValue],
) -> Result<BoundSurfaceInputs, InputBindingError> {
    bind_surface_inputs(report, values)
}

pub fn bind_surface_inputs(
    report: &ElaborationReport,
    values: &[SurfaceScalarValue],
) -> Result<BoundSurfaceInputs, InputBindingError> {
    if report.input_order.len() != values.len() {
        return Err(InputBindingError::Arity {
            expected: report.input_order.len(),
            actual: values.len(),
        });
    }

    let mut surface_bindings = Vec::with_capacity(values.len());
    let mut core_arguments = Vec::with_capacity(values.len());
    for (index, (input, value)) in report.input_order.iter().zip(values).enumerate() {
        let actual = value.ty();
        if input.ty != actual {
            return Err(InputBindingError::Type {
                index,
                name: input.name.clone(),
                expected: input.ty,
                actual,
            });
        }
        surface_bindings.push((input.name.clone(), value.to_surface()));
        core_arguments.push(value.to_core());
    }
    Ok(BoundSurfaceInputs {
        surface_bindings,
        core_arguments,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalarObservationError {
    NonScalarSurfaceValue,
    NonScalarCoreValue,
}

impl fmt::Display for ScalarObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonScalarSurfaceValue => {
                formatter.write_str("Surface result is outside the elaboration scalar domain")
            }
            Self::NonScalarCoreValue => {
                formatter.write_str("Core result is outside the elaboration scalar domain")
            }
        }
    }
}

impl std::error::Error for ScalarObservationError {}

pub fn normalize_surface_scalar(value: &Value) -> Result<NormalizedScalar, ScalarObservationError> {
    match value {
        Value::Bool(value) => Ok(NormalizedScalar::Bool(*value)),
        Value::SmallInt(value) => Ok(NormalizedScalar::I64(*value)),
        Value::Float(value) => Ok(NormalizedScalar::F64Bits(normalize_f64_bits(*value))),
        _ => Err(ScalarObservationError::NonScalarSurfaceValue),
    }
}

pub fn normalize_core_scalar(
    value: &CoreValue,
) -> Result<NormalizedScalar, ScalarObservationError> {
    match value {
        CoreValue::Bool(value) => Ok(NormalizedScalar::Bool(*value)),
        CoreValue::I64(value) => Ok(NormalizedScalar::I64(*value)),
        CoreValue::F64(value) => Ok(NormalizedScalar::F64Bits(normalize_f64_bits(*value))),
        _ => Err(ScalarObservationError::NonScalarCoreValue),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ElaborationBudget {
    pub max_source_steps: u64,
    pub max_core_nodes: u64,
}

impl ElaborationBudget {
    pub fn new(max_source_steps: u64, max_core_nodes: u64) -> Self {
        Self {
            max_source_steps,
            max_core_nodes,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ElaborationReport {
    pub profile: SurfaceElaborationProfile,
    pub artifact: CoreArtifact,
    pub input_order: Vec<SurfaceInput>,
    pub functions: Vec<SurfaceFunctionSignature>,
    pub result_type: SurfaceScalarType,
    pub source_steps: u64,
    pub core_nodes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElaborationCode {
    InvalidRequest,
    InvalidSourceShape,
    InvalidSignature,
    DuplicateInput,
    DuplicateFunction,
    DuplicateParameter,
    InvalidCall,
    UnsupportedStatement,
    UnsupportedExpression,
    UnboundVariable,
    TypeMismatch,
    MissingResult,
    MissingReturn,
    SourceBudgetExceeded,
    CoreBudgetExceeded,
    StructuralLimit,
    ProducedInvalidCore,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElaborationError {
    pub code: ElaborationCode,
    pub path: String,
    pub span: Option<Span>,
    pub message: String,
}

impl fmt::Display for ElaborationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?} at {}: {}",
            self.code, self.path, self.message
        )
    }
}

impl std::error::Error for ElaborationError {}

/// Elaborate the conservative Surface T2A profile into a sealed and verified
/// Core-N0 artifact.
///
/// A successful report is impossible unless the independent Core verifier
/// accepts the generated artifact.
pub fn elaborate_surface_t2a(
    statements: &[Stmt],
    inputs: &[SurfaceInput],
    result: &str,
    budget: ElaborationBudget,
) -> Result<ElaborationReport, ElaborationError> {
    if result.is_empty() {
        return Err(error(
            ElaborationCode::InvalidRequest,
            "request.result",
            None,
            "result variable name cannot be empty",
        ));
    }
    if inputs.len() > T2A_MAX_INPUTS {
        return Err(error(
            ElaborationCode::StructuralLimit,
            "request.inputs",
            None,
            format!(
                "input count {} exceeds T2A hard limit {T2A_MAX_INPUTS}",
                inputs.len()
            ),
        ));
    }
    if statements.len() > T2A_MAX_SOURCE_STEPS as usize {
        return Err(error(
            ElaborationCode::StructuralLimit,
            "statements",
            None,
            format!(
                "top-level statement count {} exceeds T2A hard limit {T2A_MAX_SOURCE_STEPS}",
                statements.len()
            ),
        ));
    }
    if budget.max_source_steps > T2A_MAX_SOURCE_STEPS {
        return Err(error(
            ElaborationCode::InvalidRequest,
            "request.max_source_steps",
            None,
            format!(
                "requested source-step budget {} exceeds safety cap {T2A_MAX_SOURCE_STEPS}",
                budget.max_source_steps
            ),
        ));
    }
    if budget.max_core_nodes > T2A_MAX_CORE_NODES {
        return Err(error(
            ElaborationCode::InvalidRequest,
            "request.max_core_nodes",
            None,
            format!(
                "requested Core-node budget {} exceeds safety cap {T2A_MAX_CORE_NODES}",
                budget.max_core_nodes
            ),
        ));
    }

    let mut builder = Builder::new(budget, BTreeMap::new(), SurfaceElaborationProfile::T2A);
    let mut names = BTreeSet::new();
    let mut environment = Environment::new();
    let mut parameters = Vec::with_capacity(inputs.len());
    for (index, input) in inputs.iter().enumerate() {
        let path = format!("request.inputs[{index}]");
        if input.name.is_empty() {
            return Err(error(
                ElaborationCode::InvalidRequest,
                format!("{path}.name"),
                None,
                "input name cannot be empty",
            ));
        }
        if !names.insert(input.name.clone()) {
            return Err(error(
                ElaborationCode::DuplicateInput,
                format!("{path}.name"),
                None,
                format!("duplicate input `{}`", input.name),
            ));
        }
        let local = builder.allocate_local(&path, None)?;
        let ty = input.ty.core_type();
        parameters.push(Parameter {
            local,
            ty: ty.clone(),
        });
        environment.insert(input.name.clone(), BindingInfo { local, ty });
    }

    let pending: Vec<Pending<'_>> = statements
        .iter()
        .enumerate()
        .map(|(index, statement)| Pending {
            statement,
            path: format!("statements[{index}]"),
        })
        .collect();
    let lowered = builder.lower_sequence(
        &pending,
        environment,
        &Terminal::ResultVariable { name: result },
    )?;

    let program = Program {
        schema: SchemaVersion::core_n0(),
        profile: CoreProfile::P1V0,
        entry: FunctionId(0),
        functions: vec![Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters,
            effects: EffectRow::pure(),
            result: lowered.result_type.clone(),
            body: lowered.term,
        }],
    };
    let artifact = CoreArtifact::seal(program).map_err(|encoding_error| {
        error(
            ElaborationCode::StructuralLimit,
            "generated_core",
            None,
            encoding_error.to_string(),
        )
    })?;
    verify(&artifact).map_err(|verification_errors| {
        error(
            ElaborationCode::ProducedInvalidCore,
            "generated_core",
            None,
            verification_errors.to_string(),
        )
    })?;

    Ok(ElaborationReport {
        profile: SurfaceElaborationProfile::T2A,
        artifact,
        input_order: inputs.to_vec(),
        functions: vec![],
        result_type: scalar_type(&lowered.result_type).ok_or_else(|| {
            error(
                ElaborationCode::ProducedInvalidCore,
                "generated_core.result",
                None,
                "T2A generated a non-scalar result",
            )
        })?,
        source_steps: builder.source_steps,
        core_nodes: builder.core_nodes,
    })
}

/// Elaborate the annotated, closed, direct-function T2B profile into one
/// sealed and independently verified Core-N0 artifact.
pub fn elaborate_surface_t2b(
    statements: &[Stmt],
    inputs: &[SurfaceInput],
    result: &str,
    budget: ElaborationBudget,
) -> Result<ElaborationReport, ElaborationError> {
    validate_request_envelope(statements, inputs, result, budget, "T2B")?;

    let function_count = statements
        .iter()
        .take_while(|statement| matches!(statement, Stmt::FnDef { .. }))
        .count();
    if function_count > T2B_MAX_FUNCTIONS {
        return Err(error(
            ElaborationCode::StructuralLimit,
            "statements.functions",
            None,
            format!("function count {function_count} exceeds T2B hard limit {T2B_MAX_FUNCTIONS}"),
        ));
    }
    if let Some((index, statement)) = statements
        .iter()
        .enumerate()
        .skip(function_count)
        .find(|(_, statement)| matches!(statement, Stmt::FnDef { .. }))
    {
        return Err(error(
            ElaborationCode::InvalidSourceShape,
            format!("statements[{index}]"),
            statement_span(statement),
            "T2B function declarations must form one contiguous top-level prefix",
        ));
    }

    let mut function_names = BTreeSet::new();
    let mut declarations = Vec::with_capacity(function_count);
    let mut function_table = BTreeMap::new();
    let mut signatures = Vec::with_capacity(function_count);
    for (index, statement) in statements[..function_count].iter().enumerate() {
        let Stmt::FnDef {
            name,
            params,
            body,
            return_type,
            span,
        } = statement
        else {
            unreachable!("function prefix contains only FnDef")
        };
        let path = format!("statements[{index}]");
        if name.is_empty() {
            return Err(error(
                ElaborationCode::InvalidSignature,
                format!("{path}.name"),
                span.clone(),
                "T2B function name cannot be empty",
            ));
        }
        if !function_names.insert(name.clone()) {
            return Err(error(
                ElaborationCode::DuplicateFunction,
                format!("{path}.name"),
                span.clone(),
                format!("duplicate T2B function `{name}`"),
            ));
        }
        if params.len() > T2B_MAX_PARAMETERS {
            return Err(error(
                ElaborationCode::StructuralLimit,
                format!("{path}.parameters"),
                span.clone(),
                format!(
                    "function `{name}` has {} parameters; T2B limit is {T2B_MAX_PARAMETERS}",
                    params.len()
                ),
            ));
        }
        if body.len() > T2A_MAX_SOURCE_STEPS as usize {
            return Err(error(
                ElaborationCode::StructuralLimit,
                format!("{path}.body"),
                span.clone(),
                format!(
                    "function `{name}` body exceeds T2B hard source limit {T2A_MAX_SOURCE_STEPS}"
                ),
            ));
        }

        let parameters = parse_function_parameters(params, &path)?;
        let result_type = parse_scalar_annotation(
            return_type.as_ref(),
            &format!("{path}.return_type"),
            span.clone(),
        )?;
        let id = FunctionId(u32::try_from(index + 1).map_err(|_| {
            error(
                ElaborationCode::StructuralLimit,
                format!("{path}.id"),
                span.clone(),
                "T2B function ID space exhausted",
            )
        })?);
        let parameter_types = parameters
            .iter()
            .map(|(_, parameter_type)| *parameter_type)
            .collect::<Vec<_>>();
        let info = FunctionInfo {
            id,
            parameters: parameter_types
                .iter()
                .copied()
                .map(SurfaceScalarType::core_type)
                .collect(),
            result: result_type.core_type(),
        };
        function_table.insert(name.clone(), info);
        signatures.push(SurfaceFunctionSignature {
            name: name.clone(),
            parameters: parameter_types,
            result: result_type,
        });
        declarations.push(FunctionDeclaration {
            source_index: index,
            name,
            parameters,
            result: result_type,
            body,
            span: span.clone(),
            id,
        });
    }

    let mut builder = Builder::new(budget, function_table, SurfaceElaborationProfile::T2B);
    let mut functions = Vec::with_capacity(function_count + 1);
    for declaration in &declarations {
        builder.reset_locals();
        let function_path = format!("statements[{}]", declaration.source_index);
        builder.charge_source(&function_path, declaration.span.clone())?;
        let Some((return_statement, body_prefix)) = declaration.body.split_last() else {
            return Err(error(
                ElaborationCode::MissingReturn,
                format!("{function_path}.body"),
                declaration.span.clone(),
                format!(
                    "T2B function `{}` requires one final value return",
                    declaration.name
                ),
            ));
        };
        let Stmt::Return {
            value: Some(return_expression),
            span: return_span,
        } = return_statement
        else {
            return Err(error(
                ElaborationCode::MissingReturn,
                format!("{function_path}.body[{}]", body_prefix.len()),
                statement_span(return_statement),
                format!(
                    "T2B function `{}` must end in a value-bearing Return",
                    declaration.name
                ),
            ));
        };

        let mut environment = Environment::new();
        let mut parameters = Vec::with_capacity(declaration.parameters.len());
        for (parameter_index, (name, surface_type)) in declaration.parameters.iter().enumerate() {
            let parameter_path = format!("{function_path}.parameters[{parameter_index}]");
            let local = builder.allocate_local(&parameter_path, declaration.span.clone())?;
            let ty = surface_type.core_type();
            parameters.push(Parameter {
                local,
                ty: ty.clone(),
            });
            environment.insert(name.clone(), BindingInfo { local, ty });
        }

        let pending = body_prefix
            .iter()
            .enumerate()
            .map(|(body_index, statement)| Pending {
                statement,
                path: format!("{function_path}.body[{body_index}]"),
            })
            .collect::<Vec<_>>();
        let return_path = format!("{function_path}.body[{}]", body_prefix.len());
        let expected_result = declaration.result.core_type();
        let lowered = builder.lower_sequence(
            &pending,
            environment,
            &Terminal::FunctionReturn {
                expression: return_expression,
                path: &return_path,
                span: return_span.clone(),
                expected: &expected_result,
            },
        )?;
        functions.push(Function {
            id: declaration.id,
            region_parameters: vec![],
            parameters,
            effects: EffectRow::pure(),
            result: expected_result,
            body: lowered.term,
        });
    }

    builder.reset_locals();
    let (entry_parameters, entry_environment) =
        allocate_entry_inputs(&mut builder, inputs, "request.inputs")?;
    let entry_pending = statements[function_count..]
        .iter()
        .enumerate()
        .map(|(entry_index, statement)| Pending {
            statement,
            path: format!("statements[{}]", function_count + entry_index),
        })
        .collect::<Vec<_>>();
    let entry = builder.lower_sequence(
        &entry_pending,
        entry_environment,
        &Terminal::ResultVariable { name: result },
    )?;
    let result_type = scalar_type(&entry.result_type).ok_or_else(|| {
        error(
            ElaborationCode::ProducedInvalidCore,
            "generated_core.entry.result",
            None,
            "T2B generated a non-scalar entry result",
        )
    })?;
    functions.insert(
        0,
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: entry_parameters,
            effects: EffectRow::pure(),
            result: entry.result_type,
            body: entry.term,
        },
    );

    let program = Program {
        schema: SchemaVersion::core_n0(),
        profile: CoreProfile::P1V0,
        entry: FunctionId(0),
        functions,
    };
    let artifact = seal_and_verify(program, "T2B")?;
    Ok(ElaborationReport {
        profile: SurfaceElaborationProfile::T2B,
        artifact,
        input_order: inputs.to_vec(),
        functions: signatures,
        result_type,
        source_steps: builder.source_steps,
        core_nodes: builder.core_nodes,
    })
}

type Environment = BTreeMap<String, BindingInfo>;

#[derive(Clone)]
struct FunctionInfo {
    id: FunctionId,
    parameters: Vec<Type>,
    result: Type,
}

struct FunctionDeclaration<'source> {
    source_index: usize,
    name: &'source str,
    parameters: Vec<(String, SurfaceScalarType)>,
    result: SurfaceScalarType,
    body: &'source [Stmt],
    span: Option<Span>,
    id: FunctionId,
}

#[derive(Clone)]
struct BindingInfo {
    local: LocalId,
    ty: Type,
}

#[derive(Clone)]
struct Pending<'statement> {
    statement: &'statement Stmt,
    path: String,
}

enum Terminal<'source> {
    ResultVariable {
        name: &'source str,
    },
    FunctionReturn {
        expression: &'source Expr,
        path: &'source str,
        span: Option<Span>,
        expected: &'source Type,
    },
}

struct LoweredBody {
    term: Term,
    result_type: Type,
}

struct LoweredExpr {
    bindings: Vec<AnfBinding>,
    operand: Operand,
    ty: Type,
}

struct LoweredDirectCall {
    bindings: Vec<AnfBinding>,
    function: FunctionId,
    arguments: Vec<Operand>,
    result: Type,
}

struct AnfBinding {
    local: LocalId,
    ty: Type,
    value: RValue,
    path: String,
    span: Option<Span>,
}

struct Builder {
    budget: ElaborationBudget,
    functions: BTreeMap<String, FunctionInfo>,
    profile: SurfaceElaborationProfile,
    next_local: u32,
    source_steps: u64,
    core_nodes: u64,
}

impl Builder {
    fn new(
        budget: ElaborationBudget,
        functions: BTreeMap<String, FunctionInfo>,
        profile: SurfaceElaborationProfile,
    ) -> Self {
        Self {
            budget,
            functions,
            profile,
            next_local: 0,
            source_steps: 0,
            core_nodes: 0,
        }
    }

    fn reset_locals(&mut self) {
        self.next_local = 0;
    }

    fn profile_name(&self) -> &'static str {
        match self.profile {
            SurfaceElaborationProfile::T2A => "T2A",
            SurfaceElaborationProfile::T2B => "T2B",
        }
    }

    fn allocate_local(
        &mut self,
        path: &str,
        span: Option<Span>,
    ) -> Result<LocalId, ElaborationError> {
        let local = LocalId(self.next_local);
        self.next_local = self.next_local.checked_add(1).ok_or_else(|| {
            error(
                ElaborationCode::StructuralLimit,
                path,
                span,
                "Core local ID space exhausted",
            )
        })?;
        Ok(local)
    }

    fn charge_source(&mut self, path: &str, span: Option<Span>) -> Result<(), ElaborationError> {
        if self.source_steps >= self.budget.max_source_steps {
            return Err(error(
                ElaborationCode::SourceBudgetExceeded,
                path,
                span,
                format!(
                    "source-step budget {} exhausted",
                    self.budget.max_source_steps
                ),
            ));
        }
        self.source_steps += 1;
        Ok(())
    }

    fn charge_core(&mut self, path: &str, span: Option<Span>) -> Result<(), ElaborationError> {
        if self.core_nodes >= self.budget.max_core_nodes {
            return Err(error(
                ElaborationCode::CoreBudgetExceeded,
                path,
                span,
                format!("Core-node budget {} exhausted", self.budget.max_core_nodes),
            ));
        }
        self.core_nodes += 1;
        Ok(())
    }

    fn lower_terminal(
        &mut self,
        terminal: &Terminal<'_>,
        environment: &Environment,
    ) -> Result<LoweredBody, ElaborationError> {
        match terminal {
            Terminal::ResultVariable { name } => {
                let Some(binding) = environment.get(*name) else {
                    return Err(error(
                        ElaborationCode::MissingResult,
                        "request.result",
                        None,
                        format!("result variable `{name}` is not defined on this path"),
                    ));
                };
                self.charge_core("request.result", None)?;
                Ok(LoweredBody {
                    term: Term::Return(Operand::Local(binding.local)),
                    result_type: binding.ty.clone(),
                })
            }
            Terminal::FunctionReturn {
                expression,
                path,
                span,
                expected,
            } => {
                self.charge_source(path, span.clone())?;
                if matches!(expression.kind, ExprKind::Call { .. }) {
                    return self.lower_tail_call(expression, environment, path, expected);
                }

                let lowered = self.lower_expr(expression, environment, &format!("{path}.value"))?;
                if &lowered.ty != *expected {
                    return Err(error(
                        ElaborationCode::TypeMismatch,
                        format!("{path}.value"),
                        expression.span.clone(),
                        format!("T2B return expects {:?}; found {:?}", expected, lowered.ty),
                    ));
                }
                self.charge_core(path, span.clone())?;
                Ok(LoweredBody {
                    term: self.wrap_bindings(lowered.bindings, Term::Return(lowered.operand))?,
                    result_type: (*expected).clone(),
                })
            }
        }
    }

    fn lower_tail_call(
        &mut self,
        expression: &Expr,
        environment: &Environment,
        path: &str,
        expected: &Type,
    ) -> Result<LoweredBody, ElaborationError> {
        self.charge_source(&format!("{path}.value"), expression.span.clone())?;
        let ExprKind::Call { callee, args } = &expression.kind else {
            unreachable!("tail-call lowering requires a Call expression")
        };
        let call = self.lower_direct_call(callee, args, environment, &format!("{path}.value"))?;
        if &call.result != expected {
            return Err(error(
                ElaborationCode::TypeMismatch,
                format!("{path}.value"),
                expression.span.clone(),
                format!(
                    "T2B tail return expects {expected:?}; call returns {:?}",
                    call.result
                ),
            ));
        }
        self.charge_core(path, expression.span.clone())?;
        Ok(LoweredBody {
            term: self.wrap_bindings(
                call.bindings,
                Term::TailCall {
                    function: call.function,
                    arguments: call.arguments,
                },
            )?,
            result_type: expected.clone(),
        })
    }

    fn lower_sequence(
        &mut self,
        statements: &[Pending<'_>],
        environment: Environment,
        terminal: &Terminal<'_>,
    ) -> Result<LoweredBody, ElaborationError> {
        let Some(current) = statements.first() else {
            return self.lower_terminal(terminal, &environment);
        };

        let span = statement_span(current.statement);
        self.charge_source(&current.path, span.clone())?;
        match current.statement {
            Stmt::Assign {
                name,
                annotation,
                expr,
                ..
            } => {
                if annotation.is_some() {
                    let profile = self.profile_name();
                    return Err(error(
                        ElaborationCode::UnsupportedStatement,
                        format!("{}.annotation", current.path),
                        span,
                        format!("{profile} does not interpret assignment annotations"),
                    ));
                }
                let mut lowered_expr =
                    self.lower_expr(expr, &environment, &format!("{}.expr", current.path))?;
                if let Some(existing) = environment.get(name) {
                    if existing.ty != lowered_expr.ty {
                        return Err(error(
                            ElaborationCode::TypeMismatch,
                            current.path.clone(),
                            span,
                            format!(
                                "type-changing reassignment of `{name}`: {:?} to {:?}",
                                existing.ty, lowered_expr.ty
                            ),
                        ));
                    }
                }

                let assignment_local = self.allocate_local(&current.path, span.clone())?;
                lowered_expr.bindings.push(AnfBinding {
                    local: assignment_local,
                    ty: lowered_expr.ty.clone(),
                    value: RValue::Use(lowered_expr.operand),
                    path: current.path.clone(),
                    span: span.clone(),
                });
                let mut next_environment = environment;
                next_environment.insert(
                    name.clone(),
                    BindingInfo {
                        local: assignment_local,
                        ty: lowered_expr.ty,
                    },
                );
                let continuation =
                    self.lower_sequence(&statements[1..], next_environment, terminal)?;
                Ok(LoweredBody {
                    term: self.wrap_bindings(lowered_expr.bindings, continuation.term)?,
                    result_type: continuation.result_type,
                })
            }
            Stmt::If {
                cond,
                then_block,
                else_block,
                ..
            } => {
                let lowered_condition =
                    self.lower_expr(cond, &environment, &format!("{}.condition", current.path))?;
                if lowered_condition.ty != Type::Bool {
                    let profile = self.profile_name();
                    return Err(error(
                        ElaborationCode::TypeMismatch,
                        format!("{}.condition", current.path),
                        cond.span.clone(),
                        format!(
                            "{profile} if condition must be Bool; found {:?}",
                            lowered_condition.ty
                        ),
                    ));
                }

                let continuation_len = statements.len().saturating_sub(1);
                if then_block.len().saturating_add(continuation_len) > T2A_MAX_SOURCE_STEPS as usize
                    || else_block.len().saturating_add(continuation_len)
                        > T2A_MAX_SOURCE_STEPS as usize
                {
                    let profile = self.profile_name();
                    return Err(error(
                        ElaborationCode::StructuralLimit,
                        current.path.clone(),
                        span,
                        format!(
                            "branch plus duplicated continuation exceeds {profile} hard source limit"
                        ),
                    ));
                }

                let mut then_pending: Vec<Pending<'_>> = then_block
                    .iter()
                    .enumerate()
                    .map(|(index, statement)| Pending {
                        statement,
                        path: format!("{}.then[{index}]", current.path),
                    })
                    .collect();
                then_pending.extend_from_slice(&statements[1..]);
                let mut else_pending: Vec<Pending<'_>> = else_block
                    .iter()
                    .enumerate()
                    .map(|(index, statement)| Pending {
                        statement,
                        path: format!("{}.else[{index}]", current.path),
                    })
                    .collect();
                else_pending.extend_from_slice(&statements[1..]);

                let then_body =
                    self.lower_sequence(&then_pending, environment.clone(), terminal)?;
                let else_body = self.lower_sequence(&else_pending, environment, terminal)?;
                if then_body.result_type != else_body.result_type {
                    return Err(error(
                        ElaborationCode::TypeMismatch,
                        current.path.clone(),
                        span,
                        format!(
                            "branch result types differ: {:?} vs {:?}",
                            then_body.result_type, else_body.result_type
                        ),
                    ));
                }
                self.charge_core(&current.path, statement_span(current.statement))?;
                let branch = Term::If {
                    condition: lowered_condition.operand,
                    then_term: Box::new(then_body.term),
                    else_term: Box::new(else_body.term),
                };
                Ok(LoweredBody {
                    term: self.wrap_bindings(lowered_condition.bindings, branch)?,
                    result_type: then_body.result_type,
                })
            }
            unsupported => {
                let profile = self.profile_name();
                Err(error(
                    ElaborationCode::UnsupportedStatement,
                    current.path.clone(),
                    span,
                    format!(
                        "Surface statement {} is outside {profile}",
                        statement_name(unsupported)
                    ),
                ))
            }
        }
    }

    fn lower_expr(
        &mut self,
        expr: &Expr,
        environment: &Environment,
        path: &str,
    ) -> Result<LoweredExpr, ElaborationError> {
        self.charge_source(path, expr.span.clone())?;
        match &expr.kind {
            ExprKind::Number(value) => {
                if value.fract().abs() < f64::EPSILON {
                    Ok(LoweredExpr {
                        bindings: vec![],
                        operand: Operand::I64(*value as i64),
                        ty: Type::I64,
                    })
                } else {
                    Ok(LoweredExpr {
                        bindings: vec![],
                        operand: Operand::F64(*value),
                        ty: Type::F64,
                    })
                }
            }
            ExprKind::Bool(value) => Ok(LoweredExpr {
                bindings: vec![],
                operand: Operand::Bool(*value),
                ty: Type::Bool,
            }),
            ExprKind::Var(name) => {
                let Some(binding) = environment.get(name) else {
                    return Err(error(
                        ElaborationCode::UnboundVariable,
                        path,
                        expr.span.clone(),
                        format!("Surface variable `{name}` is not bound"),
                    ));
                };
                Ok(LoweredExpr {
                    bindings: vec![],
                    operand: Operand::Local(binding.local),
                    ty: binding.ty.clone(),
                })
            }
            ExprKind::Call { callee, args } if self.profile == SurfaceElaborationProfile::T2B => {
                let mut call = self.lower_direct_call(callee, args, environment, path)?;
                let local = self.allocate_local(path, expr.span.clone())?;
                call.bindings.push(AnfBinding {
                    local,
                    ty: call.result.clone(),
                    value: RValue::Call {
                        function: call.function,
                        arguments: call.arguments,
                    },
                    path: path.to_owned(),
                    span: expr.span.clone(),
                });
                Ok(LoweredExpr {
                    bindings: call.bindings,
                    operand: Operand::Local(local),
                    ty: call.result,
                })
            }
            ExprKind::Call { .. } => Err(error(
                ElaborationCode::UnsupportedExpression,
                path,
                expr.span.clone(),
                "Surface expression Call is outside T2A",
            )),
            ExprKind::Binary { op, left, right } if matches!(op, BinaryOp::Add | BinaryOp::Sub) => {
                let mut lowered_left =
                    self.lower_expr(left, environment, &format!("{path}.left"))?;
                let lowered_right =
                    self.lower_expr(right, environment, &format!("{path}.right"))?;
                if lowered_left.ty != Type::F64 || lowered_right.ty != Type::F64 {
                    let profile = self.profile_name();
                    return Err(error(
                        ElaborationCode::TypeMismatch,
                        path,
                        expr.span.clone(),
                        format!(
                            "{profile} {:?} requires F64/F64; found {:?}/{:?}",
                            op, lowered_left.ty, lowered_right.ty
                        ),
                    ));
                }
                let local = self.allocate_local(path, expr.span.clone())?;
                lowered_left.bindings.extend(lowered_right.bindings);
                lowered_left.bindings.push(AnfBinding {
                    local,
                    ty: Type::F64,
                    value: RValue::Primitive {
                        operation: match op {
                            BinaryOp::Add => Primitive::F64Add,
                            BinaryOp::Sub => Primitive::F64Sub,
                            _ => unreachable!("guard admits only add/sub"),
                        },
                        arguments: vec![lowered_left.operand, lowered_right.operand],
                    },
                    path: path.to_owned(),
                    span: expr.span.clone(),
                });
                Ok(LoweredExpr {
                    bindings: lowered_left.bindings,
                    operand: Operand::Local(local),
                    ty: Type::F64,
                })
            }
            ExprKind::Binary { op, .. } => {
                let profile = self.profile_name();
                Err(error(
                    ElaborationCode::UnsupportedExpression,
                    path,
                    expr.span.clone(),
                    format!("Surface binary operation {op:?} is outside {profile}"),
                ))
            }
            unsupported => {
                let profile = self.profile_name();
                Err(error(
                    ElaborationCode::UnsupportedExpression,
                    path,
                    expr.span.clone(),
                    format!(
                        "Surface expression {} is outside {profile}",
                        expression_name(unsupported)
                    ),
                ))
            }
        }
    }

    fn lower_direct_call(
        &mut self,
        callee: &Expr,
        args: &[Expr],
        environment: &Environment,
        path: &str,
    ) -> Result<LoweredDirectCall, ElaborationError> {
        let callee_path = format!("{path}.callee");
        self.charge_source(&callee_path, callee.span.clone())?;
        let ExprKind::Var(name) = &callee.kind else {
            return Err(error(
                ElaborationCode::InvalidCall,
                callee_path,
                callee.span.clone(),
                "T2B admits only a direct declared function name as callee",
            ));
        };
        let Some(function) = self.functions.get(name).cloned() else {
            return Err(error(
                ElaborationCode::InvalidCall,
                callee_path,
                callee.span.clone(),
                format!("direct function `{name}` is not declared in the T2B prefix"),
            ));
        };
        if args.len() != function.parameters.len() {
            return Err(error(
                ElaborationCode::InvalidCall,
                format!("{path}.arguments"),
                callee.span.clone(),
                format!(
                    "function `{name}` expects {} arguments; found {}",
                    function.parameters.len(),
                    args.len()
                ),
            ));
        }

        let mut bindings = Vec::new();
        let mut arguments = Vec::with_capacity(args.len());
        for (index, (argument, expected)) in args.iter().zip(&function.parameters).enumerate() {
            let argument_path = format!("{path}.arguments[{index}]");
            let lowered = self.lower_expr(argument, environment, &argument_path)?;
            if &lowered.ty != expected {
                return Err(error(
                    ElaborationCode::TypeMismatch,
                    argument_path,
                    argument.span.clone(),
                    format!(
                        "function `{name}` argument {index} expects {expected:?}; found {:?}",
                        lowered.ty
                    ),
                ));
            }
            bindings.extend(lowered.bindings);
            arguments.push(lowered.operand);
        }
        Ok(LoweredDirectCall {
            bindings,
            function: function.id,
            arguments,
            result: function.result,
        })
    }

    fn wrap_bindings(
        &mut self,
        bindings: Vec<AnfBinding>,
        mut continuation: Term,
    ) -> Result<Term, ElaborationError> {
        for binding in &bindings {
            self.charge_core(&binding.path, binding.span.clone())?;
        }
        for binding in bindings.into_iter().rev() {
            continuation = Term::Let {
                binder: binding.local,
                ty: binding.ty,
                value: binding.value,
                next: Box::new(continuation),
            };
        }
        Ok(continuation)
    }
}

fn validate_request_envelope(
    statements: &[Stmt],
    inputs: &[SurfaceInput],
    result: &str,
    budget: ElaborationBudget,
    profile: &str,
) -> Result<(), ElaborationError> {
    if result.is_empty() {
        return Err(error(
            ElaborationCode::InvalidRequest,
            "request.result",
            None,
            "result variable name cannot be empty",
        ));
    }
    if inputs.len() > T2A_MAX_INPUTS {
        return Err(error(
            ElaborationCode::StructuralLimit,
            "request.inputs",
            None,
            format!(
                "input count {} exceeds {profile} hard limit {T2A_MAX_INPUTS}",
                inputs.len()
            ),
        ));
    }
    if statements.len() > T2A_MAX_SOURCE_STEPS as usize {
        return Err(error(
            ElaborationCode::StructuralLimit,
            "statements",
            None,
            format!(
                "top-level statement count {} exceeds {profile} hard limit {T2A_MAX_SOURCE_STEPS}",
                statements.len()
            ),
        ));
    }
    if budget.max_source_steps > T2A_MAX_SOURCE_STEPS {
        return Err(error(
            ElaborationCode::InvalidRequest,
            "request.max_source_steps",
            None,
            format!(
                "requested source-step budget {} exceeds safety cap {T2A_MAX_SOURCE_STEPS}",
                budget.max_source_steps
            ),
        ));
    }
    if budget.max_core_nodes > T2A_MAX_CORE_NODES {
        return Err(error(
            ElaborationCode::InvalidRequest,
            "request.max_core_nodes",
            None,
            format!(
                "requested Core-node budget {} exceeds safety cap {T2A_MAX_CORE_NODES}",
                budget.max_core_nodes
            ),
        ));
    }
    Ok(())
}

fn parse_function_parameters(
    parameters: &[Param],
    function_path: &str,
) -> Result<Vec<(String, SurfaceScalarType)>, ElaborationError> {
    let mut names = BTreeSet::new();
    let mut parsed = Vec::with_capacity(parameters.len());
    for (index, parameter) in parameters.iter().enumerate() {
        let path = format!("{function_path}.parameters[{index}]");
        if parameter.name.is_empty() {
            return Err(error(
                ElaborationCode::InvalidSignature,
                format!("{path}.name"),
                None,
                "T2B parameter name cannot be empty",
            ));
        }
        if !names.insert(parameter.name.clone()) {
            return Err(error(
                ElaborationCode::DuplicateParameter,
                format!("{path}.name"),
                None,
                format!("duplicate parameter `{}`", parameter.name),
            ));
        }
        let ty = parse_scalar_annotation(
            parameter.annotation.as_ref(),
            &format!("{path}.annotation"),
            None,
        )?;
        parsed.push((parameter.name.clone(), ty));
    }
    Ok(parsed)
}

fn parse_scalar_annotation(
    annotation: Option<&TypeAnnotation>,
    path: &str,
    span: Option<Span>,
) -> Result<SurfaceScalarType, ElaborationError> {
    let Some(annotation) = annotation else {
        return Err(error(
            ElaborationCode::InvalidSignature,
            path,
            span,
            "T2B requires an explicit Bool, I64, or F64 annotation",
        ));
    };
    if annotation.predicate.is_some() {
        return Err(error(
            ElaborationCode::InvalidSignature,
            path,
            span,
            "T2B does not admit refinement predicates in callable signatures",
        ));
    }
    match annotation.base.as_str() {
        "Bool" => Ok(SurfaceScalarType::Bool),
        "I64" => Ok(SurfaceScalarType::I64),
        "F64" => Ok(SurfaceScalarType::F64),
        unsupported => Err(error(
            ElaborationCode::InvalidSignature,
            path,
            span,
            format!("T2B annotation `{unsupported}` is not one of Bool, I64, or F64"),
        )),
    }
}

fn allocate_entry_inputs(
    builder: &mut Builder,
    inputs: &[SurfaceInput],
    path_prefix: &str,
) -> Result<(Vec<Parameter>, Environment), ElaborationError> {
    let mut names = BTreeSet::new();
    let mut environment = Environment::new();
    let mut parameters = Vec::with_capacity(inputs.len());
    for (index, input) in inputs.iter().enumerate() {
        let path = format!("{path_prefix}[{index}]");
        if input.name.is_empty() {
            return Err(error(
                ElaborationCode::InvalidRequest,
                format!("{path}.name"),
                None,
                "input name cannot be empty",
            ));
        }
        if !names.insert(input.name.clone()) {
            return Err(error(
                ElaborationCode::DuplicateInput,
                format!("{path}.name"),
                None,
                format!("duplicate input `{}`", input.name),
            ));
        }
        let local = builder.allocate_local(&path, None)?;
        let ty = input.ty.core_type();
        parameters.push(Parameter {
            local,
            ty: ty.clone(),
        });
        environment.insert(input.name.clone(), BindingInfo { local, ty });
    }
    Ok((parameters, environment))
}

fn seal_and_verify(program: Program, profile: &str) -> Result<CoreArtifact, ElaborationError> {
    let artifact = CoreArtifact::seal(program).map_err(|encoding_error| {
        error(
            ElaborationCode::StructuralLimit,
            "generated_core",
            None,
            encoding_error.to_string(),
        )
    })?;
    verify(&artifact).map_err(|verification_errors| {
        error(
            ElaborationCode::ProducedInvalidCore,
            "generated_core",
            None,
            format!("{profile} produced invalid Core: {verification_errors}"),
        )
    })?;
    Ok(artifact)
}

fn scalar_type(ty: &Type) -> Option<SurfaceScalarType> {
    match ty {
        Type::Bool => Some(SurfaceScalarType::Bool),
        Type::I64 => Some(SurfaceScalarType::I64),
        Type::F64 => Some(SurfaceScalarType::F64),
        _ => None,
    }
}

fn normalize_f64_bits(value: f64) -> u64 {
    if value.is_nan() {
        CANONICAL_NAN_BITS
    } else {
        value.to_bits()
    }
}

fn statement_span(statement: &Stmt) -> Option<Span> {
    match statement {
        Stmt::Rite { span, .. }
        | Stmt::Unsafe { span, .. }
        | Stmt::FnDef { span, .. }
        | Stmt::Assign { span, .. }
        | Stmt::Expr { span, .. }
        | Stmt::If { span, .. }
        | Stmt::Loop { span, .. }
        | Stmt::Each { span, .. }
        | Stmt::While { span, .. }
        | Stmt::Action { span, .. }
        | Stmt::Return { span, .. }
        | Stmt::Import { span, .. } => span.clone(),
    }
}

fn statement_name(statement: &Stmt) -> &'static str {
    match statement {
        Stmt::Rite { .. } => "Rite",
        Stmt::Unsafe { .. } => "Unsafe",
        Stmt::FnDef { .. } => "FnDef",
        Stmt::Assign { .. } => "Assign",
        Stmt::Expr { .. } => "Expr",
        Stmt::If { .. } => "If",
        Stmt::Loop { .. } => "Loop",
        Stmt::Each { .. } => "Each",
        Stmt::While { .. } => "While",
        Stmt::Action { .. } => "Action",
        Stmt::Return { .. } => "Return",
        Stmt::Import { .. } => "Import",
    }
}

fn expression_name(expression: &ExprKind) -> &'static str {
    match expression {
        ExprKind::Number(_) => "Number",
        ExprKind::Bool(_) => "Bool",
        ExprKind::Text(_) => "Text",
        ExprKind::Bytes(_) => "Bytes",
        ExprKind::List(_) => "List",
        ExprKind::Map(_) => "Map",
        ExprKind::Var(_) => "Var",
        ExprKind::Call { .. } => "Call",
        ExprKind::Binary { .. } => "Binary",
        ExprKind::Unary { .. } => "Unary",
        ExprKind::Index { .. } => "Index",
        ExprKind::Fn(_) => "Fn",
        ExprKind::Field { .. } => "Field",
    }
}

fn error(
    code: ElaborationCode,
    path: impl Into<String>,
    span: Option<Span>,
    message: impl Into<String>,
) -> ElaborationError {
    ElaborationError {
        code,
        path: path.into(),
        span,
        message: message.into(),
    }
}
