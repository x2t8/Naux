use super::encoding::semantic_hash;
use super::schema::{
    CaseArm, CoreArtifact, CoreProfile, Effect, EffectRow, ErrorKind, Function, FunctionId,
    LocalId, Mutability, NumericMode, Operand, OperationId, OperationSignature, Primitive, Program,
    RValue, RegionId, SemanticHash, SumType, Term, Type, CORE_SCHEMA_NAME, CORE_SCHEMA_VERSION,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const MAX_VERIFY_NODES: u64 = 1_000_000;
const MAX_VERIFY_DEPTH: u32 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationCode {
    InvalidSchema,
    SemanticHashMismatch,
    EncodingFailure,
    NonCanonicalOrder,
    DuplicateId,
    MissingEntry,
    UnsupportedProfileFeature,
    InvalidType,
    UnboundLocal,
    TypeMismatch,
    InvalidCall,
    InvalidCase,
    MissingEffect,
    OwnershipViolation,
    StructuralLimit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationError {
    pub code: VerificationCode,
    pub path: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationErrors(pub Vec<VerificationError>);

impl fmt::Display for VerificationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} Core-N0 verification error(s)", self.0.len())?;
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

impl std::error::Error for VerificationErrors {}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedArtifact<'artifact> {
    artifact: &'artifact CoreArtifact,
}

impl<'artifact> VerifiedArtifact<'artifact> {
    pub fn program(self) -> &'artifact Program {
        &self.artifact.program
    }

    pub fn semantic_hash(self) -> SemanticHash {
        self.artifact.semantic_hash
    }
}

pub fn verify(artifact: &CoreArtifact) -> Result<VerifiedArtifact<'_>, VerificationErrors> {
    let mut verifier = Verifier::new(&artifact.program);
    verifier.verify_envelope(artifact);
    verifier.verify_program();
    if verifier.errors.is_empty() {
        Ok(VerifiedArtifact { artifact })
    } else {
        Err(VerificationErrors(verifier.errors))
    }
}

struct Verifier<'program> {
    program: &'program Program,
    functions: BTreeMap<FunctionId, &'program Function>,
    operations: BTreeMap<OperationId, OperationSignature>,
    errors: Vec<VerificationError>,
    nodes: u64,
}

#[derive(Clone, Copy)]
struct VerificationContext<'context> {
    regions: &'context BTreeSet<RegionId>,
    active_store_regions: &'context BTreeSet<RegionId>,
    active_handlers: &'context [OperationSignature],
    effects: &'context EffectRow,
}

#[derive(Clone, Default)]
struct AffineState {
    types: BTreeMap<LocalId, Type>,
    available_unique: BTreeSet<LocalId>,
}

impl<'program> Verifier<'program> {
    fn new(program: &'program Program) -> Self {
        Self {
            program,
            functions: BTreeMap::new(),
            operations: BTreeMap::new(),
            errors: Vec::new(),
            nodes: 0,
        }
    }

    fn error(
        &mut self,
        code: VerificationCode,
        path: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.errors.push(VerificationError {
            code,
            path: path.into(),
            message: message.into(),
        });
    }

    fn enter_node(&mut self, path: &str, depth: u32) -> bool {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_VERIFY_NODES {
            if self.nodes == MAX_VERIFY_NODES + 1 {
                self.error(
                    VerificationCode::StructuralLimit,
                    path,
                    format!("artifact exceeds {MAX_VERIFY_NODES} verifier nodes"),
                );
            }
            return false;
        }
        if depth > MAX_VERIFY_DEPTH {
            self.error(
                VerificationCode::StructuralLimit,
                path,
                format!("term depth exceeds {MAX_VERIFY_DEPTH}"),
            );
            return false;
        }
        true
    }

    fn verify_envelope(&mut self, artifact: &CoreArtifact) {
        let schema = &artifact.program.schema;
        if schema.name != CORE_SCHEMA_NAME
            || (schema.major, schema.minor, schema.patch) != CORE_SCHEMA_VERSION
        {
            self.error(
                VerificationCode::InvalidSchema,
                "program.schema",
                format!(
                    "expected {CORE_SCHEMA_NAME} {}.{}.{}; found {} {}.{}.{}",
                    CORE_SCHEMA_VERSION.0,
                    CORE_SCHEMA_VERSION.1,
                    CORE_SCHEMA_VERSION.2,
                    schema.name,
                    schema.major,
                    schema.minor,
                    schema.patch
                ),
            );
        }

        match semantic_hash(&artifact.program) {
            Ok(actual) if actual != artifact.semantic_hash => self.error(
                VerificationCode::SemanticHashMismatch,
                "artifact.semantic_hash",
                format!("declared {}; computed {actual}", artifact.semantic_hash),
            ),
            Ok(_) => {}
            Err(error) => self.error(
                VerificationCode::EncodingFailure,
                "program",
                error.to_string(),
            ),
        }
    }

    fn verify_program(&mut self) {
        for pair in self.program.functions.windows(2) {
            if pair[0].id >= pair[1].id {
                self.error(
                    VerificationCode::NonCanonicalOrder,
                    "program.functions",
                    format!(
                        "function IDs must be strictly increasing; found {} before {}",
                        pair[0].id.0, pair[1].id.0
                    ),
                );
            }
        }

        for (index, function) in self.program.functions.iter().enumerate() {
            if self.functions.insert(function.id, function).is_some() {
                self.error(
                    VerificationCode::DuplicateId,
                    format!("program.functions[{index}].id"),
                    format!("duplicate function ID {}", function.id.0),
                );
            }
        }

        if !self.functions.contains_key(&self.program.entry) {
            self.error(
                VerificationCode::MissingEntry,
                "program.entry",
                format!("entry function {} does not exist", self.program.entry.0),
            );
        }

        for (index, function) in self.program.functions.iter().enumerate() {
            self.verify_function(function, &format!("program.functions[{index}]"));
        }
    }

    fn verify_function(&mut self, function: &Function, path: &str) {
        for pair in function.region_parameters.windows(2) {
            if pair[0] >= pair[1] {
                self.error(
                    VerificationCode::NonCanonicalOrder,
                    format!("{path}.region_parameters"),
                    "region parameters must be strictly increasing",
                );
            }
        }

        let regions: BTreeSet<RegionId> = function.region_parameters.iter().copied().collect();
        if regions.len() != function.region_parameters.len() {
            self.error(
                VerificationCode::DuplicateId,
                format!("{path}.region_parameters"),
                "duplicate region parameter",
            );
        }

        self.verify_effect_row(&function.effects, &regions, &format!("{path}.effects"));
        self.verify_type(&function.result, &regions, &format!("{path}.result"));
        if self.supports_logical_store() && contains_ref(&function.result) {
            if !self.supports_ownership_return() {
                self.error(
                    VerificationCode::UnsupportedProfileFeature,
                    format!("{path}.result"),
                    "references cannot cross a function result boundary",
                );
            } else if function.id == self.program.entry {
                self.error(
                    VerificationCode::UnsupportedProfileFeature,
                    format!("{path}.result"),
                    "P1V5 references cannot cross the program entry result boundary",
                );
            } else if !is_direct_unique_ref(&function.result) {
                self.error(
                    VerificationCode::UnsupportedProfileFeature,
                    format!("{path}.result"),
                    "P1V5 admits only a direct Unique scalar reference result",
                );
            } else {
                let reference_parameters: Vec<_> = function
                    .parameters
                    .iter()
                    .filter(|parameter| contains_ref(&parameter.ty))
                    .collect();
                if reference_parameters.len() != 1
                    || !is_direct_unique_ref(&reference_parameters[0].ty)
                    || reference_parameters[0].ty != function.result
                {
                    self.error(
                        VerificationCode::UnsupportedProfileFeature,
                        format!("{path}.result"),
                        "P1V5 ownership return requires exactly one reference-bearing parameter whose direct Unique type equals the result",
                    );
                }
            }
        }
        if self.supports_closures() && contains_closure(&function.result) {
            self.error(
                VerificationCode::UnsupportedProfileFeature,
                format!("{path}.result"),
                "P1V2 closures cannot cross a function result boundary",
            );
        }

        let mut environment = BTreeMap::new();
        let mut seen_bindings = BTreeSet::new();
        for (index, parameter) in function.parameters.iter().enumerate() {
            let parameter_path = format!("{path}.parameters[{index}]");
            self.verify_type(&parameter.ty, &regions, &format!("{parameter_path}.type"));
            if self.program.profile == CoreProfile::P1V1 && contains_ref(&parameter.ty) {
                self.error(
                    VerificationCode::UnsupportedProfileFeature,
                    format!("{parameter_path}.type"),
                    "P1V1 references cannot cross a function parameter boundary",
                );
            }
            if self.supports_closures()
                && function.id == self.program.entry
                && contains_ref(&parameter.ty)
            {
                self.error(
                    VerificationCode::UnsupportedProfileFeature,
                    format!("{parameter_path}.type"),
                    "references cannot enter through the program entry boundary",
                );
            }
            if self.supports_closures() && contains_closure(&parameter.ty) {
                self.error(
                    VerificationCode::UnsupportedProfileFeature,
                    format!("{parameter_path}.type"),
                    "P1V2 closures cannot cross a function parameter boundary",
                );
            }
            if !seen_bindings.insert(parameter.local) {
                self.error(
                    VerificationCode::DuplicateId,
                    format!("{parameter_path}.local"),
                    format!("local {} is already defined", parameter.local.0),
                );
            }
            environment.insert(parameter.local, parameter.ty.clone());
        }

        let mut active_store_regions = BTreeSet::new();
        if self.supports_closures() && function.id != self.program.entry {
            for parameter in &function.parameters {
                collect_ref_regions(&parameter.ty, &mut active_store_regions);
            }
        }
        self.verify_term(
            &function.body,
            &environment,
            &mut seen_bindings,
            &regions,
            &active_store_regions,
            &[],
            &function.effects,
            &function.result,
            &format!("{path}.body"),
            0,
        );
        if self.supports_unique() {
            self.verify_affine_function(function, path);
        }
    }

    fn verify_effect_row(&mut self, row: &EffectRow, regions: &BTreeSet<RegionId>, path: &str) {
        for pair in row.effects.windows(2) {
            if pair[0] >= pair[1] {
                self.error(
                    VerificationCode::NonCanonicalOrder,
                    path,
                    "effect rows must be strictly sorted and duplicate-free",
                );
            }
        }
        for (index, effect) in row.effects.iter().enumerate() {
            match effect {
                Effect::Error(ErrorKind::Overflow | ErrorKind::Bounds) => {}
                Effect::State(region) | Effect::Alloc(region) => {
                    if !regions.contains(region) {
                        self.error(
                            VerificationCode::InvalidType,
                            format!("{path}[{index}]"),
                            format!("effect uses undeclared region {}", region.0),
                        );
                    } else if !self.supports_logical_store() {
                        self.error(
                            VerificationCode::UnsupportedProfileFeature,
                            format!("{path}[{index}]"),
                            "State/Alloc effects require the Core-N0 P1V1 profile",
                        );
                    }
                }
                Effect::Operation(operation) => {
                    self.verify_operation_signature(
                        operation,
                        regions,
                        &format!("{path}[{index}].operation"),
                    );
                    if !self.supports_handlers() {
                        self.error(
                            VerificationCode::UnsupportedProfileFeature,
                            format!("{path}[{index}]"),
                            "user operations require the Core-N0 P1V3 profile",
                        );
                    }
                }
                _ => self.error(
                    VerificationCode::UnsupportedProfileFeature,
                    format!("{path}[{index}]"),
                    "effect is outside the selected Core-N0 profile",
                ),
            }
        }
    }

    fn verify_type(&mut self, ty: &Type, regions: &BTreeSet<RegionId>, path: &str) {
        match ty {
            Type::Unit | Type::Bool | Type::I64 | Type::F64 => {}
            Type::Tuple(fields) => {
                for (index, field) in fields.iter().enumerate() {
                    let field_path = format!("{path}.tuple[{index}]");
                    self.verify_type(field, regions, &field_path);
                    if self.supports_unique() && contains_unique_ref(field) {
                        self.error(
                            VerificationCode::UnsupportedProfileFeature,
                            field_path,
                            "affine ownership profiles do not admit Unique references inside tuples",
                        );
                    }
                }
            }
            Type::Sum(sum) => self.verify_sum_type(sum, regions, path),
            Type::Array {
                region,
                mutability,
                element,
            } => {
                if !regions.contains(region) {
                    self.error(
                        VerificationCode::InvalidType,
                        path,
                        format!("array uses undeclared region {}", region.0),
                    );
                }
                if *mutability != Mutability::Read || element.as_ref() != &Type::F64 {
                    self.error(
                        VerificationCode::UnsupportedProfileFeature,
                        path,
                        "P1V0 admits only read-only Array<F64>",
                    );
                }
            }
            Type::Ref {
                region,
                mutability,
                element,
            } if self.supports_logical_store() => {
                if !regions.contains(region) {
                    self.error(
                        VerificationCode::InvalidType,
                        path,
                        format!("reference uses undeclared region {}", region.0),
                    );
                }
                let admitted_mutability = *mutability == Mutability::Shared
                    || (self.supports_unique() && *mutability == Mutability::Unique);
                if !admitted_mutability || !is_store_scalar(element) {
                    self.error(
                        VerificationCode::UnsupportedProfileFeature,
                        path,
                        "selected profile admits only Ref<rho, Shared|Unique, Bool|I64|F64>, with Unique starting at P1V4",
                    );
                }
            }
            Type::Closure {
                parameters,
                effects,
                result,
            } if self.supports_closures() => {
                for (index, parameter) in parameters.iter().enumerate() {
                    self.verify_type(
                        parameter,
                        regions,
                        &format!("{path}.closure.parameters[{index}]"),
                    );
                    if contains_ref(parameter) || contains_closure(parameter) {
                        self.error(
                            VerificationCode::UnsupportedProfileFeature,
                            format!("{path}.closure.parameters[{index}]"),
                            "P1V2 closure arguments cannot contain references or closures",
                        );
                    }
                }
                self.verify_effect_row(effects, regions, &format!("{path}.closure.effects"));
                self.verify_type(result, regions, &format!("{path}.closure.result"));
                if contains_ref(result) || contains_closure(result) {
                    self.error(
                        VerificationCode::UnsupportedProfileFeature,
                        format!("{path}.closure.result"),
                        "P1V2 closure results cannot contain references or closures",
                    );
                }
            }
            Type::Text
            | Type::Bytes
            | Type::Ref { .. }
            | Type::Function { .. }
            | Type::Closure { .. } => self.error(
                VerificationCode::UnsupportedProfileFeature,
                path,
                "type is represented by the schema but not admitted by the selected profile",
            ),
        }
    }

    fn verify_sum_type(&mut self, sum: &SumType, regions: &BTreeSet<RegionId>, path: &str) {
        if sum.name.is_empty() {
            self.error(
                VerificationCode::InvalidType,
                format!("{path}.sum.name"),
                "sum name cannot be empty",
            );
        }
        if sum.constructors.is_empty() {
            self.error(
                VerificationCode::InvalidType,
                format!("{path}.sum.constructors"),
                "sum must have at least one constructor",
            );
        }
        let mut names = BTreeSet::new();
        for (constructor_index, constructor) in sum.constructors.iter().enumerate() {
            let constructor_path = format!("{path}.sum.constructors[{constructor_index}]");
            if constructor.name.is_empty() {
                self.error(
                    VerificationCode::InvalidType,
                    format!("{constructor_path}.name"),
                    "constructor name cannot be empty",
                );
            } else if !names.insert(constructor.name.as_str()) {
                self.error(
                    VerificationCode::InvalidType,
                    format!("{constructor_path}.name"),
                    format!("duplicate constructor name {}", constructor.name),
                );
            }
            for (field_index, field) in constructor.fields.iter().enumerate() {
                self.verify_type(
                    field,
                    regions,
                    &format!("{constructor_path}.fields[{field_index}]"),
                );
                if self.supports_unique() && contains_unique_ref(field) {
                    self.error(
                        VerificationCode::UnsupportedProfileFeature,
                        format!("{constructor_path}.fields[{field_index}]"),
                        "affine ownership profiles do not admit Unique references inside sums",
                    );
                }
            }
        }
    }

    fn verify_operation_signature(
        &mut self,
        operation: &OperationSignature,
        regions: &BTreeSet<RegionId>,
        path: &str,
    ) {
        if let Some(existing) = self.operations.get(&operation.id).cloned() {
            if existing != *operation {
                self.error(
                    VerificationCode::InvalidType,
                    format!("{path}.id"),
                    format!("operation ID {} has conflicting signatures", operation.id.0),
                );
            }
        } else {
            self.operations.insert(operation.id, operation.clone());
        }

        for (index, parameter) in operation.parameters.iter().enumerate() {
            let parameter_path = format!("{path}.parameters[{index}]");
            self.verify_type(parameter, regions, &parameter_path);
            if contains_ref(parameter) || contains_closure(parameter) {
                self.error(
                    VerificationCode::UnsupportedProfileFeature,
                    parameter_path,
                    "P1V3 operation parameters cannot contain references or closures",
                );
            }
        }
        self.verify_type(&operation.result, regions, &format!("{path}.result"));
        if contains_ref(&operation.result) || contains_closure(&operation.result) {
            self.error(
                VerificationCode::UnsupportedProfileFeature,
                format!("{path}.result"),
                "P1V3 operation results cannot contain references or closures",
            );
        }
    }

    fn verify_affine_function(&mut self, function: &Function, path: &str) {
        let mut state = AffineState::default();
        for parameter in &function.parameters {
            state.types.insert(parameter.local, parameter.ty.clone());
            if is_direct_unique_ref(&parameter.ty) {
                state.available_unique.insert(parameter.local);
            }
        }
        self.verify_affine_term(&function.body, &mut state, &format!("{path}.body"));
    }

    fn verify_affine_term(&mut self, term: &Term, state: &mut AffineState, path: &str) {
        match term {
            Term::Let {
                binder,
                ty,
                value,
                next,
            } => {
                self.verify_affine_rvalue(value, state, &format!("{path}.value"));
                state.types.insert(*binder, ty.clone());
                if is_direct_unique_ref(ty) {
                    state.available_unique.insert(*binder);
                }
                self.verify_affine_term(next, state, &format!("{path}.next"));
            }
            Term::If {
                condition,
                then_term,
                else_term,
            } => {
                self.affine_borrow_operand(condition, state, &format!("{path}.condition"));
                let mut then_state = state.clone();
                let mut else_state = state.clone();
                self.verify_affine_term(then_term, &mut then_state, &format!("{path}.then"));
                self.verify_affine_term(else_term, &mut else_state, &format!("{path}.else"));
            }
            Term::Case { scrutinee, arms } => {
                self.affine_borrow_operand(scrutinee, state, &format!("{path}.scrutinee"));
                let sum = affine_operand_type(scrutinee, state).and_then(|ty| match ty {
                    Type::Sum(sum) => Some(sum.clone()),
                    _ => None,
                });
                for (arm_index, arm) in arms.iter().enumerate() {
                    let mut arm_state = state.clone();
                    if let Some(constructor) = sum
                        .as_ref()
                        .and_then(|sum| sum.constructors.get(arm.constructor as usize))
                    {
                        for (binding, field_type) in arm.bindings.iter().zip(&constructor.fields) {
                            arm_state.types.insert(*binding, field_type.clone());
                            if is_direct_unique_ref(field_type) {
                                arm_state.available_unique.insert(*binding);
                            }
                        }
                    }
                    self.verify_affine_term(
                        &arm.body,
                        &mut arm_state,
                        &format!("{path}.arms[{arm_index}].body"),
                    );
                }
            }
            Term::TailCall { arguments, .. } => {
                for (index, argument) in arguments.iter().enumerate() {
                    self.affine_move_operand(
                        argument,
                        state,
                        &format!("{path}.arguments[{index}]"),
                    );
                }
            }
            Term::Return(operand) => self.affine_move_operand(operand, state, path),
            Term::Region { body, .. } => {
                self.verify_affine_term(body, state, &format!("{path}.body"));
            }
            Term::Handle {
                captures,
                capture_parameters,
                clauses,
                body,
            } => {
                for (index, capture) in captures.iter().enumerate() {
                    self.affine_borrow_operand(
                        capture,
                        state,
                        &format!("{path}.captures[{index}]"),
                    );
                    if affine_operand_type(capture, state).is_some_and(contains_unique_ref) {
                        self.error(
                            VerificationCode::OwnershipViolation,
                            format!("{path}.captures[{index}]"),
                            "affine ownership profiles do not let handlers capture a Unique owner",
                        );
                    }
                }

                let mut clause_base = AffineState::default();
                for parameter in capture_parameters {
                    clause_base
                        .types
                        .insert(parameter.local, parameter.ty.clone());
                    if is_direct_unique_ref(&parameter.ty) {
                        clause_base.available_unique.insert(parameter.local);
                    }
                }
                for (clause_index, clause) in clauses.iter().enumerate() {
                    let mut clause_state = clause_base.clone();
                    for (parameter, parameter_type) in
                        clause.parameters.iter().zip(&clause.operation.parameters)
                    {
                        clause_state
                            .types
                            .insert(*parameter, parameter_type.clone());
                        if is_direct_unique_ref(parameter_type) {
                            clause_state.available_unique.insert(*parameter);
                        }
                    }
                    self.verify_affine_term(
                        &clause.body,
                        &mut clause_state,
                        &format!("{path}.clauses[{clause_index}].body"),
                    );
                }
                let mut body_state = state.clone();
                self.verify_affine_term(body, &mut body_state, &format!("{path}.body"));
            }
        }
    }

    fn verify_affine_rvalue(&mut self, value: &RValue, state: &mut AffineState, path: &str) {
        match value {
            RValue::Use(operand) => self.affine_move_operand(operand, state, path),
            RValue::Tuple(fields) => {
                for (index, field) in fields.iter().enumerate() {
                    self.affine_move_operand(field, state, &format!("{path}.fields[{index}]"));
                }
            }
            RValue::Project { tuple, .. } => {
                self.affine_borrow_operand(tuple, state, &format!("{path}.tuple"));
            }
            RValue::Construct { fields, .. } => {
                for (index, field) in fields.iter().enumerate() {
                    self.affine_move_operand(field, state, &format!("{path}.fields[{index}]"));
                }
            }
            RValue::Primitive { arguments, .. } => {
                for (index, argument) in arguments.iter().enumerate() {
                    self.affine_borrow_operand(
                        argument,
                        state,
                        &format!("{path}.arguments[{index}]"),
                    );
                }
            }
            RValue::Call { arguments, .. } => {
                for (index, argument) in arguments.iter().enumerate() {
                    self.affine_move_operand(
                        argument,
                        state,
                        &format!("{path}.arguments[{index}]"),
                    );
                }
            }
            RValue::RefAlloc { value, .. } => {
                self.affine_borrow_operand(value, state, &format!("{path}.value"));
            }
            RValue::RefLoad { reference } => {
                self.affine_borrow_operand(reference, state, &format!("{path}.reference"));
            }
            RValue::RefStore { reference, value } => {
                self.affine_borrow_operand(reference, state, &format!("{path}.reference"));
                self.affine_borrow_operand(value, state, &format!("{path}.value"));
            }
            RValue::PackClosure { captures, .. } => {
                for (index, capture) in captures.iter().enumerate() {
                    self.affine_borrow_operand(
                        capture,
                        state,
                        &format!("{path}.captures[{index}]"),
                    );
                    if affine_operand_type(capture, state).is_some_and(contains_unique_ref) {
                        self.error(
                            VerificationCode::OwnershipViolation,
                            format!("{path}.captures[{index}]"),
                            "affine ownership profiles do not let closures capture a Unique owner",
                        );
                    }
                }
            }
            RValue::CallClosure { closure, arguments } => {
                self.affine_borrow_operand(closure, state, &format!("{path}.closure"));
                for (index, argument) in arguments.iter().enumerate() {
                    self.affine_borrow_operand(
                        argument,
                        state,
                        &format!("{path}.arguments[{index}]"),
                    );
                    if affine_operand_type(argument, state).is_some_and(contains_unique_ref) {
                        self.error(
                            VerificationCode::OwnershipViolation,
                            format!("{path}.arguments[{index}]"),
                            "affine ownership profiles do not let closure calls receive a Unique owner",
                        );
                    }
                }
            }
            RValue::Perform { arguments, .. } => {
                for (index, argument) in arguments.iter().enumerate() {
                    self.affine_borrow_operand(
                        argument,
                        state,
                        &format!("{path}.arguments[{index}]"),
                    );
                    if affine_operand_type(argument, state).is_some_and(contains_unique_ref) {
                        self.error(
                            VerificationCode::OwnershipViolation,
                            format!("{path}.arguments[{index}]"),
                            "affine ownership profiles do not let operations receive a Unique owner",
                        );
                    }
                }
            }
        }
    }

    fn affine_borrow_operand(&mut self, operand: &Operand, state: &AffineState, path: &str) {
        let Operand::Local(local) = operand else {
            return;
        };
        if state.types.get(local).is_some_and(is_direct_unique_ref)
            && !state.available_unique.contains(local)
        {
            self.error(
                VerificationCode::OwnershipViolation,
                path,
                format!("Unique local {} was already moved", local.0),
            );
        }
    }

    fn affine_move_operand(&mut self, operand: &Operand, state: &mut AffineState, path: &str) {
        let Operand::Local(local) = operand else {
            return;
        };
        if state.types.get(local).is_some_and(is_direct_unique_ref)
            && !state.available_unique.remove(local)
        {
            self.error(
                VerificationCode::OwnershipViolation,
                path,
                format!("Unique local {} was already moved", local.0),
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_term(
        &mut self,
        term: &Term,
        environment: &BTreeMap<LocalId, Type>,
        seen_bindings: &mut BTreeSet<LocalId>,
        regions: &BTreeSet<RegionId>,
        active_store_regions: &BTreeSet<RegionId>,
        active_handlers: &[OperationSignature],
        effects: &EffectRow,
        result: &Type,
        path: &str,
        depth: u32,
    ) {
        if !self.enter_node(path, depth) {
            return;
        }
        match term {
            Term::Let {
                binder,
                ty,
                value,
                next,
            } => {
                self.verify_type(ty, regions, &format!("{path}.type"));
                let context = VerificationContext {
                    regions,
                    active_store_regions,
                    active_handlers,
                    effects,
                };
                let actual =
                    self.rvalue_type(value, environment, &context, &format!("{path}.value"));
                if let Some(actual) = actual {
                    self.expect_type(ty, &actual, &format!("{path}.value"));
                }

                let mut next_environment = environment.clone();
                if !seen_bindings.insert(*binder) || next_environment.contains_key(binder) {
                    self.error(
                        VerificationCode::DuplicateId,
                        format!("{path}.binder"),
                        format!("local {} is already defined", binder.0),
                    );
                } else {
                    next_environment.insert(*binder, ty.clone());
                }
                self.verify_term(
                    next,
                    &next_environment,
                    seen_bindings,
                    regions,
                    active_store_regions,
                    active_handlers,
                    effects,
                    result,
                    &format!("{path}.next"),
                    depth + 1,
                );
            }
            Term::If {
                condition,
                then_term,
                else_term,
            } => {
                if let Some(condition_type) =
                    self.operand_type(condition, environment, &format!("{path}.condition"))
                {
                    self.expect_type(&Type::Bool, &condition_type, &format!("{path}.condition"));
                }
                self.verify_term(
                    then_term,
                    environment,
                    seen_bindings,
                    regions,
                    active_store_regions,
                    active_handlers,
                    effects,
                    result,
                    &format!("{path}.then"),
                    depth + 1,
                );
                self.verify_term(
                    else_term,
                    environment,
                    seen_bindings,
                    regions,
                    active_store_regions,
                    active_handlers,
                    effects,
                    result,
                    &format!("{path}.else"),
                    depth + 1,
                );
            }
            Term::Case { scrutinee, arms } => {
                let scrutinee_type =
                    self.operand_type(scrutinee, environment, &format!("{path}.scrutinee"));
                match scrutinee_type {
                    Some(Type::Sum(sum)) => self.verify_case(
                        &sum,
                        arms,
                        environment,
                        seen_bindings,
                        regions,
                        active_store_regions,
                        active_handlers,
                        effects,
                        result,
                        path,
                        depth,
                    ),
                    Some(actual) => self.error(
                        VerificationCode::TypeMismatch,
                        format!("{path}.scrutinee"),
                        format!("case requires a sum; found {actual:?}"),
                    ),
                    None => {}
                }
            }
            Term::TailCall {
                function,
                arguments,
            } => {
                let context = VerificationContext {
                    regions,
                    active_store_regions,
                    active_handlers,
                    effects,
                };
                if let Some(actual) =
                    self.verify_call(*function, arguments, environment, &context, path)
                {
                    self.expect_type(result, &actual, path);
                }
                if self.supports_closures()
                    && arguments.iter().any(|argument| {
                        operand_contains_disallowed_tail_reference(
                            argument,
                            environment,
                            self.supports_unique(),
                        )
                    })
                {
                    self.error(
                        VerificationCode::UnsupportedProfileFeature,
                        format!("{path}.arguments"),
                        "selected profile tail calls cannot transfer this reference argument",
                    );
                }
            }
            Term::Return(operand) => {
                if let Some(actual) = self.operand_type(operand, environment, path) {
                    self.expect_type(result, &actual, path);
                }
            }
            Term::Region { region, body } => {
                if !self.supports_logical_store() {
                    self.error(
                        VerificationCode::UnsupportedProfileFeature,
                        path,
                        "lexical regions require the Core-N0 P1V1 profile",
                    );
                }
                if !regions.contains(region) {
                    self.error(
                        VerificationCode::InvalidType,
                        format!("{path}.region"),
                        format!("lexical scope uses undeclared region {}", region.0),
                    );
                }
                if active_store_regions.contains(region) {
                    self.error(
                        VerificationCode::InvalidType,
                        format!("{path}.region"),
                        format!("region {} is already active", region.0),
                    );
                }
                let mut body_regions = active_store_regions.clone();
                body_regions.insert(*region);
                self.verify_term(
                    body,
                    environment,
                    seen_bindings,
                    regions,
                    &body_regions,
                    active_handlers,
                    effects,
                    result,
                    &format!("{path}.body"),
                    depth + 1,
                );
            }
            Term::Handle {
                captures,
                capture_parameters,
                clauses,
                body,
            } => {
                self.require_handler_profile(path);
                if captures.len() != capture_parameters.len() {
                    self.error(
                        VerificationCode::InvalidCall,
                        format!("{path}.captures"),
                        format!(
                            "handler expects {} captures; found {}",
                            capture_parameters.len(),
                            captures.len()
                        ),
                    );
                }

                let mut clause_environment = BTreeMap::new();
                for (index, capture_parameter) in capture_parameters.iter().enumerate() {
                    let capture_path = format!("{path}.capture_parameters[{index}]");
                    self.verify_type(
                        &capture_parameter.ty,
                        regions,
                        &format!("{capture_path}.type"),
                    );
                    self.require_type_regions_active(
                        &capture_parameter.ty,
                        active_store_regions,
                        &format!("{capture_path}.type"),
                    );
                    if !seen_bindings.insert(capture_parameter.local)
                        || clause_environment.contains_key(&capture_parameter.local)
                    {
                        self.error(
                            VerificationCode::DuplicateId,
                            format!("{capture_path}.local"),
                            format!("local {} is already defined", capture_parameter.local.0),
                        );
                    } else {
                        clause_environment
                            .insert(capture_parameter.local, capture_parameter.ty.clone());
                    }
                    if let Some(capture) = captures.get(index) {
                        if let Some(actual) = self.operand_type(
                            capture,
                            environment,
                            &format!("{path}.captures[{index}]"),
                        ) {
                            self.expect_type(
                                &capture_parameter.ty,
                                &actual,
                                &format!("{path}.captures[{index}]"),
                            );
                            self.require_type_regions_active(
                                &actual,
                                active_store_regions,
                                &format!("{path}.captures[{index}]"),
                            );
                        }
                    }
                }
                for (index, capture) in captures.iter().enumerate().skip(capture_parameters.len()) {
                    self.operand_type(capture, environment, &format!("{path}.captures[{index}]"));
                }

                if clauses.is_empty() {
                    self.error(
                        VerificationCode::InvalidCall,
                        format!("{path}.clauses"),
                        "a handler must contain at least one clause",
                    );
                }
                for pair in clauses.windows(2) {
                    if pair[0].operation.id >= pair[1].operation.id {
                        self.error(
                            VerificationCode::NonCanonicalOrder,
                            format!("{path}.clauses"),
                            "handler clauses must have strictly increasing operation IDs",
                        );
                    }
                }

                let mut handled_operations = active_handlers.to_vec();
                let mut clause_ids = BTreeSet::new();
                for (clause_index, clause) in clauses.iter().enumerate() {
                    let clause_path = format!("{path}.clauses[{clause_index}]");
                    self.verify_operation_signature(
                        &clause.operation,
                        regions,
                        &format!("{clause_path}.operation"),
                    );
                    if !clause_ids.insert(clause.operation.id) {
                        self.error(
                            VerificationCode::DuplicateId,
                            format!("{clause_path}.operation.id"),
                            format!("duplicate handler operation ID {}", clause.operation.id.0),
                        );
                    }
                    handled_operations.push(clause.operation.clone());

                    if clause.parameters.len() != clause.operation.parameters.len() {
                        self.error(
                            VerificationCode::InvalidCall,
                            format!("{clause_path}.parameters"),
                            format!(
                                "operation expects {} clause parameters; found {}",
                                clause.operation.parameters.len(),
                                clause.parameters.len()
                            ),
                        );
                    }
                    let mut operation_environment = clause_environment.clone();
                    for (parameter_index, parameter) in clause.parameters.iter().enumerate() {
                        let parameter_path = format!("{clause_path}.parameters[{parameter_index}]");
                        if !seen_bindings.insert(*parameter)
                            || operation_environment.contains_key(parameter)
                        {
                            self.error(
                                VerificationCode::DuplicateId,
                                parameter_path,
                                format!("local {} is already defined", parameter.0),
                            );
                            continue;
                        }
                        if let Some(parameter_type) =
                            clause.operation.parameters.get(parameter_index)
                        {
                            operation_environment.insert(*parameter, parameter_type.clone());
                        }
                    }
                    self.verify_term(
                        &clause.body,
                        &operation_environment,
                        seen_bindings,
                        regions,
                        active_store_regions,
                        active_handlers,
                        effects,
                        &clause.operation.result,
                        &format!("{clause_path}.body"),
                        depth + 1,
                    );
                }

                self.verify_term(
                    body,
                    environment,
                    seen_bindings,
                    regions,
                    active_store_regions,
                    &handled_operations,
                    effects,
                    result,
                    &format!("{path}.body"),
                    depth + 1,
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_case(
        &mut self,
        sum: &SumType,
        arms: &[CaseArm],
        environment: &BTreeMap<LocalId, Type>,
        seen_bindings: &mut BTreeSet<LocalId>,
        regions: &BTreeSet<RegionId>,
        active_store_regions: &BTreeSet<RegionId>,
        active_handlers: &[OperationSignature],
        effects: &EffectRow,
        result: &Type,
        path: &str,
        depth: u32,
    ) {
        if arms.len() != sum.constructors.len() {
            self.error(
                VerificationCode::InvalidCase,
                format!("{path}.arms"),
                format!(
                    "case has {} arms but sum {} has {} constructors",
                    arms.len(),
                    sum.name,
                    sum.constructors.len()
                ),
            );
        }
        for (arm_index, arm) in arms.iter().enumerate() {
            let arm_path = format!("{path}.arms[{arm_index}]");
            if arm.constructor as usize != arm_index {
                self.error(
                    VerificationCode::NonCanonicalOrder,
                    format!("{arm_path}.constructor"),
                    "case arms must appear once in constructor-index order",
                );
            }
            let Some(constructor) = sum.constructors.get(arm.constructor as usize) else {
                self.error(
                    VerificationCode::InvalidCase,
                    format!("{arm_path}.constructor"),
                    format!("constructor {} does not exist", arm.constructor),
                );
                continue;
            };
            if arm.bindings.len() != constructor.fields.len() {
                self.error(
                    VerificationCode::InvalidCase,
                    format!("{arm_path}.bindings"),
                    format!(
                        "constructor expects {} bindings; found {}",
                        constructor.fields.len(),
                        arm.bindings.len()
                    ),
                );
            }

            let mut arm_environment = environment.clone();
            for (binding_index, binding) in arm.bindings.iter().enumerate() {
                let binding_path = format!("{arm_path}.bindings[{binding_index}]");
                if !seen_bindings.insert(*binding) || arm_environment.contains_key(binding) {
                    self.error(
                        VerificationCode::DuplicateId,
                        binding_path,
                        format!("local {} is already defined", binding.0),
                    );
                    continue;
                }
                if let Some(field_type) = constructor.fields.get(binding_index) {
                    arm_environment.insert(*binding, field_type.clone());
                }
            }
            self.verify_term(
                &arm.body,
                &arm_environment,
                seen_bindings,
                regions,
                active_store_regions,
                active_handlers,
                effects,
                result,
                &format!("{arm_path}.body"),
                depth + 1,
            );
        }
    }

    fn rvalue_type(
        &mut self,
        value: &RValue,
        environment: &BTreeMap<LocalId, Type>,
        context: &VerificationContext<'_>,
        path: &str,
    ) -> Option<Type> {
        let VerificationContext {
            regions,
            active_store_regions,
            active_handlers,
            effects,
        } = *context;
        match value {
            RValue::Use(operand) => self.operand_type(operand, environment, path),
            RValue::Tuple(fields) => {
                let mut types = Vec::with_capacity(fields.len());
                for (index, field) in fields.iter().enumerate() {
                    types.push(self.operand_type(
                        field,
                        environment,
                        &format!("{path}.fields[{index}]"),
                    )?);
                }
                Some(Type::Tuple(types))
            }
            RValue::Project { tuple, index } => {
                match self.operand_type(tuple, environment, &format!("{path}.tuple"))? {
                    Type::Tuple(fields) => match fields.get(*index as usize) {
                        Some(field) => Some(field.clone()),
                        None => {
                            self.error(
                                VerificationCode::InvalidType,
                                format!("{path}.index"),
                                format!("tuple projection index {index} is out of range"),
                            );
                            None
                        }
                    },
                    actual => {
                        self.error(
                            VerificationCode::TypeMismatch,
                            format!("{path}.tuple"),
                            format!("tuple projection requires tuple; found {actual:?}"),
                        );
                        None
                    }
                }
            }
            RValue::Construct {
                sum,
                constructor,
                fields,
            } => {
                self.verify_sum_type(sum, regions, &format!("{path}.sum"));
                let Some(constructor_type) = sum.constructors.get(*constructor as usize) else {
                    self.error(
                        VerificationCode::InvalidType,
                        format!("{path}.constructor"),
                        format!("constructor {constructor} does not exist"),
                    );
                    return None;
                };
                self.verify_arguments(
                    fields,
                    &constructor_type.fields,
                    environment,
                    &format!("{path}.fields"),
                );
                Some(Type::Sum(sum.clone()))
            }
            RValue::Primitive {
                operation,
                arguments,
            } => self.primitive_type(operation, arguments, environment, effects, path),
            RValue::Call {
                function,
                arguments,
            } => self.verify_call(*function, arguments, environment, context, path),
            RValue::RefAlloc {
                region,
                mutability,
                value,
            } => {
                self.require_store_profile(path);
                self.require_active_store_region(*region, regions, active_store_regions, path);
                self.require_effect(effects, &Effect::Alloc(*region), path);
                let admitted_mutability = *mutability == Mutability::Shared
                    || (self.supports_unique() && *mutability == Mutability::Unique);
                if !admitted_mutability {
                    self.error(
                        VerificationCode::UnsupportedProfileFeature,
                        format!("{path}.mutability"),
                        "selected profile admits Shared allocation and affine ownership profiles additionally admit Unique",
                    );
                }
                let element = self.operand_type(value, environment, &format!("{path}.value"))?;
                if !is_store_scalar(&element) {
                    self.error(
                        VerificationCode::UnsupportedProfileFeature,
                        format!("{path}.value"),
                        "P1V1 logical-store cells admit only Bool, I64, or F64",
                    );
                }
                Some(Type::Ref {
                    region: *region,
                    mutability: *mutability,
                    element: Box::new(element),
                })
            }
            RValue::RefLoad { reference } => {
                self.require_store_profile(path);
                let reference_type =
                    self.operand_type(reference, environment, &format!("{path}.reference"))?;
                match reference_type {
                    Type::Ref {
                        region,
                        mutability,
                        element,
                    } if mutability == Mutability::Shared
                        || (self.supports_unique() && mutability == Mutability::Unique) =>
                    {
                        self.require_active_store_region(
                            region,
                            regions,
                            active_store_regions,
                            path,
                        );
                        self.require_effect(effects, &Effect::State(region), path);
                        Some(*element)
                    }
                    actual => {
                        self.error(
                            VerificationCode::TypeMismatch,
                            format!("{path}.reference"),
                            format!(
                                "RefLoad requires an admitted Shared or Unique reference; found {actual:?}"
                            ),
                        );
                        None
                    }
                }
            }
            RValue::RefStore { reference, value } => {
                self.require_store_profile(path);
                let reference_type =
                    self.operand_type(reference, environment, &format!("{path}.reference"))?;
                let value_type = self.operand_type(value, environment, &format!("{path}.value"));
                match reference_type {
                    Type::Ref {
                        region,
                        mutability,
                        element,
                    } if mutability == Mutability::Shared
                        || (self.supports_unique() && mutability == Mutability::Unique) =>
                    {
                        self.require_active_store_region(
                            region,
                            regions,
                            active_store_regions,
                            path,
                        );
                        self.require_effect(effects, &Effect::State(region), path);
                        if let Some(value_type) = value_type {
                            self.expect_type(&element, &value_type, &format!("{path}.value"));
                        }
                        Some(Type::Unit)
                    }
                    actual => {
                        self.error(
                            VerificationCode::TypeMismatch,
                            format!("{path}.reference"),
                            format!(
                                "RefStore requires an admitted Shared or Unique reference; found {actual:?}"
                            ),
                        );
                        None
                    }
                }
            }
            RValue::PackClosure { function, captures } => {
                self.require_closure_profile(path);

                let mut capture_types = Vec::with_capacity(captures.len());
                for (index, capture) in captures.iter().enumerate() {
                    let capture_type = self.operand_type(
                        capture,
                        environment,
                        &format!("{path}.captures[{index}]"),
                    )?;
                    if contains_closure(&capture_type) {
                        self.error(
                            VerificationCode::UnsupportedProfileFeature,
                            format!("{path}.captures[{index}]"),
                            "P1V2 does not admit nested closure capture",
                        );
                    }
                    self.require_type_regions_active(
                        &capture_type,
                        active_store_regions,
                        &format!("{path}.captures[{index}]"),
                    );
                    capture_types.push(capture_type);
                }

                let Some(code) = self.functions.get(function).copied() else {
                    self.error(
                        VerificationCode::InvalidCall,
                        format!("{path}.function"),
                        format!("closure code function {} does not exist", function.0),
                    );
                    return None;
                };
                let code_parameters: Vec<Type> = code
                    .parameters
                    .iter()
                    .map(|parameter| parameter.ty.clone())
                    .collect();
                let code_effects = code.effects.clone();
                let code_result = code.result.clone();

                let Some(environment_type) = code_parameters.first() else {
                    self.error(
                        VerificationCode::InvalidCall,
                        format!("{path}.function"),
                        "closure code requires a hidden tuple-environment parameter",
                    );
                    return None;
                };
                let expected_environment = Type::Tuple(capture_types);
                self.expect_type(
                    &expected_environment,
                    environment_type,
                    &format!("{path}.captures"),
                );
                if contains_closure(environment_type) {
                    self.error(
                        VerificationCode::UnsupportedProfileFeature,
                        format!("{path}.captures"),
                        "P1V2 closure environments cannot contain closures",
                    );
                }

                let behavioral_parameters = code_parameters[1..].to_vec();
                for (index, parameter) in behavioral_parameters.iter().enumerate() {
                    if contains_ref(parameter) || contains_closure(parameter) {
                        self.error(
                            VerificationCode::UnsupportedProfileFeature,
                            format!("{path}.function.parameters[{}]", index + 1),
                            "P1V2 closure arguments cannot contain references or closures",
                        );
                    }
                }
                if contains_ref(&code_result) || contains_closure(&code_result) {
                    self.error(
                        VerificationCode::UnsupportedProfileFeature,
                        format!("{path}.function.result"),
                        "P1V2 closure results cannot contain references or closures",
                    );
                }

                Some(Type::Closure {
                    parameters: behavioral_parameters,
                    effects: code_effects,
                    result: Box::new(code_result),
                })
            }
            RValue::CallClosure { closure, arguments } => {
                self.require_closure_profile(path);
                let closure_type =
                    self.operand_type(closure, environment, &format!("{path}.closure"))?;
                match closure_type {
                    Type::Closure {
                        parameters,
                        effects: closure_effects,
                        result,
                    } => {
                        self.verify_arguments(
                            arguments,
                            &parameters,
                            environment,
                            &format!("{path}.arguments"),
                        );
                        for effect in &closure_effects.effects {
                            self.require_effect_or_handler(
                                effects,
                                effect,
                                active_handlers,
                                &format!("{path}.closure"),
                            );
                        }
                        Some(*result)
                    }
                    actual => {
                        self.error(
                            VerificationCode::TypeMismatch,
                            format!("{path}.closure"),
                            format!("CallClosure requires a closure; found {actual:?}"),
                        );
                        None
                    }
                }
            }
            RValue::Perform {
                operation,
                arguments,
            } => {
                self.require_handler_profile(path);
                self.verify_operation_signature(operation, regions, &format!("{path}.operation"));
                self.verify_arguments(
                    arguments,
                    &operation.parameters,
                    environment,
                    &format!("{path}.arguments"),
                );
                self.require_effect_or_handler(
                    effects,
                    &Effect::Operation(operation.clone()),
                    active_handlers,
                    path,
                );
                Some((*operation.result).clone())
            }
        }
    }

    fn primitive_type(
        &mut self,
        operation: &Primitive,
        arguments: &[Operand],
        environment: &BTreeMap<LocalId, Type>,
        effects: &EffectRow,
        path: &str,
    ) -> Option<Type> {
        let (expected, result) = match operation {
            Primitive::I64Add(mode) | Primitive::I64Sub(mode) | Primitive::I64Mul(mode) => {
                if *mode == NumericMode::Checked {
                    self.require_effect(
                        effects,
                        &Effect::Error(ErrorKind::Overflow),
                        &format!("{path}.operation"),
                    );
                }
                (vec![Type::I64, Type::I64], Type::I64)
            }
            Primitive::F64Add | Primitive::F64Sub => (vec![Type::F64, Type::F64], Type::F64),
            Primitive::I64CmpLt | Primitive::I64CmpGe => (vec![Type::I64, Type::I64], Type::Bool),
            Primitive::ArrayLenF64 => {
                if arguments.len() != 1 {
                    self.error(
                        VerificationCode::InvalidCall,
                        path,
                        format!("ArrayLenF64 expects 1 argument; found {}", arguments.len()),
                    );
                    return None;
                }
                let actual =
                    self.operand_type(&arguments[0], environment, &format!("{path}.arguments[0]"))?;
                if !is_read_f64_array(&actual) {
                    self.error(
                        VerificationCode::TypeMismatch,
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
                    self.error(
                        VerificationCode::InvalidCall,
                        path,
                        format!("ArrayGetF64 expects 2 arguments; found {}", arguments.len()),
                    );
                    return None;
                }
                let array =
                    self.operand_type(&arguments[0], environment, &format!("{path}.arguments[0]"))?;
                if !is_read_f64_array(&array) {
                    self.error(
                        VerificationCode::TypeMismatch,
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
        function_id: FunctionId,
        arguments: &[Operand],
        environment: &BTreeMap<LocalId, Type>,
        context: &VerificationContext<'_>,
        path: &str,
    ) -> Option<Type> {
        let VerificationContext {
            active_store_regions,
            active_handlers,
            effects: caller_effects,
            ..
        } = *context;
        let Some(function) = self.functions.get(&function_id).copied() else {
            self.error(
                VerificationCode::InvalidCall,
                format!("{path}.function"),
                format!("function {} does not exist", function_id.0),
            );
            return None;
        };
        let parameter_types: Vec<Type> = function
            .parameters
            .iter()
            .map(|parameter| parameter.ty.clone())
            .collect();
        let function_effects = function.effects.clone();
        let function_result = function.result.clone();
        self.verify_arguments(
            arguments,
            &parameter_types,
            environment,
            &format!("{path}.arguments"),
        );
        for (index, argument) in arguments.iter().enumerate() {
            if let Some(argument_type) = operand_type_known(argument, environment) {
                self.require_type_regions_active(
                    &argument_type,
                    active_store_regions,
                    &format!("{path}.arguments[{index}]"),
                );
            }
        }
        for effect in &function_effects.effects {
            self.require_effect_or_handler(
                caller_effects,
                effect,
                active_handlers,
                &format!("{path}.function"),
            );
        }
        Some(function_result)
    }

    fn verify_arguments(
        &mut self,
        arguments: &[Operand],
        expected: &[Type],
        environment: &BTreeMap<LocalId, Type>,
        path: &str,
    ) {
        if arguments.len() != expected.len() {
            self.error(
                VerificationCode::InvalidCall,
                path,
                format!(
                    "expected {} arguments; found {}",
                    expected.len(),
                    arguments.len()
                ),
            );
        }
        for (index, (argument, expected_type)) in arguments.iter().zip(expected.iter()).enumerate()
        {
            if let Some(actual) =
                self.operand_type(argument, environment, &format!("{path}[{index}]"))
            {
                self.expect_type(expected_type, &actual, &format!("{path}[{index}]"));
            }
        }
    }

    fn operand_type(
        &mut self,
        operand: &Operand,
        environment: &BTreeMap<LocalId, Type>,
        path: &str,
    ) -> Option<Type> {
        match operand {
            Operand::Unit => Some(Type::Unit),
            Operand::Bool(_) => Some(Type::Bool),
            Operand::I64(_) => Some(Type::I64),
            Operand::F64(_) => Some(Type::F64),
            Operand::Local(local) => match environment.get(local) {
                Some(ty) => Some(ty.clone()),
                None => {
                    self.error(
                        VerificationCode::UnboundLocal,
                        path,
                        format!("local {} is not in scope", local.0),
                    );
                    None
                }
            },
        }
    }

    fn expect_type(&mut self, expected: &Type, actual: &Type, path: &str) {
        if expected != actual {
            self.error(
                VerificationCode::TypeMismatch,
                path,
                format!("expected {expected:?}; found {actual:?}"),
            );
        }
    }

    fn require_effect(&mut self, row: &EffectRow, required: &Effect, path: &str) {
        if !row.effects.contains(required) {
            self.error(
                VerificationCode::MissingEffect,
                path,
                format!("operation requires declared effect {required:?}"),
            );
        }
    }

    fn require_effect_or_handler(
        &mut self,
        row: &EffectRow,
        required: &Effect,
        active_handlers: &[OperationSignature],
        path: &str,
    ) {
        let is_handled = match required {
            Effect::Operation(operation) => active_handlers
                .iter()
                .rev()
                .any(|handled| handled == operation),
            _ => false,
        };
        if !is_handled {
            self.require_effect(row, required, path);
        }
    }

    fn supports_logical_store(&self) -> bool {
        matches!(
            self.program.profile,
            CoreProfile::P1V1
                | CoreProfile::P1V2
                | CoreProfile::P1V3
                | CoreProfile::P1V4
                | CoreProfile::P1V5
        )
    }

    fn supports_closures(&self) -> bool {
        matches!(
            self.program.profile,
            CoreProfile::P1V2 | CoreProfile::P1V3 | CoreProfile::P1V4 | CoreProfile::P1V5
        )
    }

    fn supports_handlers(&self) -> bool {
        matches!(
            self.program.profile,
            CoreProfile::P1V3 | CoreProfile::P1V4 | CoreProfile::P1V5
        )
    }

    fn supports_unique(&self) -> bool {
        matches!(self.program.profile, CoreProfile::P1V4 | CoreProfile::P1V5)
    }

    fn supports_ownership_return(&self) -> bool {
        self.program.profile == CoreProfile::P1V5
    }

    fn require_store_profile(&mut self, path: &str) {
        if !self.supports_logical_store() {
            self.error(
                VerificationCode::UnsupportedProfileFeature,
                path,
                "logical-store operations require the Core-N0 P1V1 profile",
            );
        }
    }

    fn require_closure_profile(&mut self, path: &str) {
        if !self.supports_closures() {
            self.error(
                VerificationCode::UnsupportedProfileFeature,
                path,
                "closure operations require the Core-N0 P1V2 profile",
            );
        }
    }

    fn require_handler_profile(&mut self, path: &str) {
        if !self.supports_handlers() {
            self.error(
                VerificationCode::UnsupportedProfileFeature,
                path,
                "operation and handler constructs require the Core-N0 P1V3 profile",
            );
        }
    }

    fn require_active_store_region(
        &mut self,
        region: RegionId,
        declared_regions: &BTreeSet<RegionId>,
        active_regions: &BTreeSet<RegionId>,
        path: &str,
    ) {
        if !declared_regions.contains(&region) {
            self.error(
                VerificationCode::InvalidType,
                format!("{path}.region"),
                format!(
                    "logical-store operation uses undeclared region {}",
                    region.0
                ),
            );
        }
        if !active_regions.contains(&region) {
            self.error(
                VerificationCode::InvalidType,
                format!("{path}.region"),
                format!("logical-store operation uses inactive region {}", region.0),
            );
        }
    }

    fn require_type_regions_active(
        &mut self,
        ty: &Type,
        active_regions: &BTreeSet<RegionId>,
        path: &str,
    ) {
        let mut referenced_regions = BTreeSet::new();
        collect_ref_regions(ty, &mut referenced_regions);
        for region in referenced_regions {
            if !active_regions.contains(&region) {
                self.error(
                    VerificationCode::InvalidType,
                    path,
                    format!("reference region {} is not active at this use", region.0),
                );
            }
        }
    }
}

fn is_store_scalar(ty: &Type) -> bool {
    matches!(ty, Type::Bool | Type::I64 | Type::F64)
}

fn contains_ref(ty: &Type) -> bool {
    match ty {
        Type::Ref { .. } => true,
        Type::Tuple(fields) => fields.iter().any(contains_ref),
        Type::Sum(sum) => sum
            .constructors
            .iter()
            .flat_map(|constructor| &constructor.fields)
            .any(contains_ref),
        Type::Array { element, .. } => contains_ref(element),
        Type::Function {
            parameters, result, ..
        }
        | Type::Closure {
            parameters, result, ..
        } => parameters.iter().any(contains_ref) || contains_ref(result),
        Type::Unit | Type::Bool | Type::I64 | Type::F64 | Type::Text | Type::Bytes => false,
    }
}

fn contains_closure(ty: &Type) -> bool {
    match ty {
        Type::Closure { .. } => true,
        Type::Tuple(fields) => fields.iter().any(contains_closure),
        Type::Sum(sum) => sum
            .constructors
            .iter()
            .flat_map(|constructor| &constructor.fields)
            .any(contains_closure),
        Type::Array { element, .. } | Type::Ref { element, .. } => contains_closure(element),
        Type::Function {
            parameters, result, ..
        } => parameters.iter().any(contains_closure) || contains_closure(result),
        Type::Unit | Type::Bool | Type::I64 | Type::F64 | Type::Text | Type::Bytes => false,
    }
}

fn contains_unique_ref(ty: &Type) -> bool {
    match ty {
        Type::Ref {
            mutability: Mutability::Unique,
            ..
        } => true,
        Type::Tuple(fields) => fields.iter().any(contains_unique_ref),
        Type::Sum(sum) => sum
            .constructors
            .iter()
            .flat_map(|constructor| &constructor.fields)
            .any(contains_unique_ref),
        Type::Array { element, .. } => contains_unique_ref(element),
        Type::Function {
            parameters, result, ..
        }
        | Type::Closure {
            parameters, result, ..
        } => parameters.iter().any(contains_unique_ref) || contains_unique_ref(result),
        Type::Ref { element, .. } => contains_unique_ref(element),
        Type::Unit | Type::Bool | Type::I64 | Type::F64 | Type::Text | Type::Bytes => false,
    }
}

fn is_direct_unique_ref(ty: &Type) -> bool {
    matches!(
        ty,
        Type::Ref {
            mutability: Mutability::Unique,
            ..
        }
    )
}

fn collect_ref_regions(ty: &Type, regions: &mut BTreeSet<RegionId>) {
    match ty {
        Type::Ref {
            region, element, ..
        } => {
            regions.insert(*region);
            collect_ref_regions(element, regions);
        }
        Type::Tuple(fields) => {
            for field in fields {
                collect_ref_regions(field, regions);
            }
        }
        Type::Sum(sum) => {
            for constructor in &sum.constructors {
                for field in &constructor.fields {
                    collect_ref_regions(field, regions);
                }
            }
        }
        Type::Array { element, .. } => collect_ref_regions(element, regions),
        Type::Function {
            parameters, result, ..
        }
        | Type::Closure {
            parameters, result, ..
        } => {
            for parameter in parameters {
                collect_ref_regions(parameter, regions);
            }
            collect_ref_regions(result, regions);
        }
        Type::Unit | Type::Bool | Type::I64 | Type::F64 | Type::Text | Type::Bytes => {}
    }
}

fn operand_type_known(operand: &Operand, environment: &BTreeMap<LocalId, Type>) -> Option<Type> {
    match operand {
        Operand::Unit => Some(Type::Unit),
        Operand::Bool(_) => Some(Type::Bool),
        Operand::I64(_) => Some(Type::I64),
        Operand::F64(_) => Some(Type::F64),
        Operand::Local(local) => environment.get(local).cloned(),
    }
}

fn operand_contains_disallowed_tail_reference(
    operand: &Operand,
    environment: &BTreeMap<LocalId, Type>,
    allow_direct_unique: bool,
) -> bool {
    operand_type_known(operand, environment)
        .is_some_and(|ty| contains_ref(&ty) && !(allow_direct_unique && is_direct_unique_ref(&ty)))
}

fn affine_operand_type<'state>(
    operand: &Operand,
    state: &'state AffineState,
) -> Option<&'state Type> {
    match operand {
        Operand::Local(local) => state.types.get(local),
        Operand::Unit | Operand::Bool(_) | Operand::I64(_) | Operand::F64(_) => None,
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
