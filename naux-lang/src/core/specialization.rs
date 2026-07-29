use super::encoding::{
    binding_time_request_hash, specialization_policy_hash, specialization_request_hash, EncodeError,
};
use super::schema::{CoreArtifact, FunctionId, Mutability, SemanticHash, SumType, Type};
use super::staging::{BindingTime, BindingTimeCertificate, BindingTimeRequest, B0_POLICY_VERSION};
use super::staging_verify::{
    verify_binding_time_b0_certificate, BindingTimeCertificateErrors,
    VerifiedBindingTimeCertificate,
};
use std::fmt;

pub const R0_REQUEST_SCHEMA_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const R0_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const R0_MAX_STATIC_VALUE_NODES_HARD_CAP: u64 = 1_000_000;
pub const R0_MAX_STATIC_ARRAY_ELEMENTS_HARD_CAP: u64 = 16_777_216;
pub const R0_MAX_SPECIALIZATION_STEPS_HARD_CAP: u64 = 100_000_000;
pub const R0_MAX_RESIDUAL_NODES_HARD_CAP: u64 = 1_000_000;
pub const R0_MAX_RESIDUAL_BYTES_HARD_CAP: u64 = 1_073_741_824;

#[derive(Clone, Debug, PartialEq)]
pub enum SpecializationValue {
    Unit,
    Bool(bool),
    I64(i64),
    F64(f64),
    Tuple(Vec<SpecializationValue>),
    Sum {
        ty: SumType,
        constructor: u32,
        fields: Vec<SpecializationValue>,
    },
    ArrayF64(Vec<f64>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum SpecializationSlot {
    Static(SpecializationValue),
    Dynamic(Type),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpecializationBudget {
    pub max_static_value_nodes: u64,
    pub max_static_array_elements: u64,
    pub max_specialization_steps: u64,
    pub max_residual_nodes: u64,
    pub max_residual_bytes: u64,
}

impl SpecializationBudget {
    pub const fn new(
        max_static_value_nodes: u64,
        max_static_array_elements: u64,
        max_specialization_steps: u64,
        max_residual_nodes: u64,
        max_residual_bytes: u64,
    ) -> Self {
        Self {
            max_static_value_nodes,
            max_static_array_elements,
            max_specialization_steps,
            max_residual_nodes,
            max_residual_bytes,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SpecializationRequest {
    pub schema_version: (u16, u16, u16),
    pub source_program_hash: SemanticHash,
    pub interpreter_semantics_hash: SemanticHash,
    pub binding_time_policy_version: (u16, u16, u16),
    pub binding_time_policy_hash: SemanticHash,
    pub binding_time_request_hash: SemanticHash,
    pub binding_time_certificate_hash: SemanticHash,
    pub policy_version: (u16, u16, u16),
    pub policy_hash: SemanticHash,
    pub entry_function: FunctionId,
    pub entry_slots: Vec<SpecializationSlot>,
    pub budget: SpecializationBudget,
}

impl SpecializationRequest {
    /// Construct the canonical R0-A envelope without trusting its inputs.
    ///
    /// `validate_specialization_r0a_request` is the only admission boundary.
    pub fn p1v0(
        artifact: &CoreArtifact,
        binding_time_request: &BindingTimeRequest,
        certificate: &BindingTimeCertificate,
        entry_slots: Vec<SpecializationSlot>,
        budget: SpecializationBudget,
    ) -> Result<Self, EncodeError> {
        Ok(Self {
            schema_version: R0_REQUEST_SCHEMA_VERSION,
            source_program_hash: artifact.semantic_hash,
            interpreter_semantics_hash: binding_time_request.interpreter_semantics_hash,
            binding_time_policy_version: binding_time_request.policy_version,
            binding_time_policy_hash: binding_time_request.policy_hash,
            binding_time_request_hash: binding_time_request_hash(binding_time_request)?,
            binding_time_certificate_hash: certificate.certificate_hash,
            policy_version: R0_POLICY_VERSION,
            policy_hash: specialization_policy_hash()?,
            entry_function: artifact.program.entry,
            entry_slots,
            budget,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecializationRequestCode {
    InvalidBindingTimeCertificate,
    UnsupportedRequestSchema,
    SourceProgramHashMismatch,
    InterpreterSemanticsHashMismatch,
    BindingTimePolicyVersionMismatch,
    BindingTimePolicyHashMismatch,
    BindingTimeRequestHashMismatch,
    BindingTimeCertificateHashMismatch,
    UnsupportedPolicyVersion,
    PolicyHashMismatch,
    EntryFunctionMismatch,
    EntrySlotArity,
    StaticDynamicMismatch,
    DynamicTypeMismatch,
    StaticValueTypeMismatch,
    StaticValueBudgetExceeded,
    StaticArrayBudgetExceeded,
    ZeroBudget,
    BudgetHardCapExceeded,
    EncodingFailure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecializationRequestError {
    pub code: SpecializationRequestCode,
    pub path: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecializationRequestErrors(pub Vec<SpecializationRequestError>);

impl fmt::Display for SpecializationRequestErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} specialization R0-A request error(s)",
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

impl std::error::Error for SpecializationRequestErrors {}

#[derive(Clone, Debug)]
pub struct ValidatedSpecializationRequest<'artifact, 'certificate> {
    artifact: &'artifact CoreArtifact,
    verified_certificate: VerifiedBindingTimeCertificate<'certificate>,
    request: SpecializationRequest,
    request_hash: SemanticHash,
}

impl<'artifact, 'certificate> ValidatedSpecializationRequest<'artifact, 'certificate> {
    pub fn artifact(&self) -> &'artifact CoreArtifact {
        self.artifact
    }

    pub fn certificate(&self) -> VerifiedBindingTimeCertificate<'certificate> {
        self.verified_certificate
    }

    pub fn request(&self) -> &SpecializationRequest {
        &self.request
    }

    pub fn request_hash(&self) -> SemanticHash {
        self.request_hash
    }
}

pub fn validate_specialization_r0a_request<'artifact, 'certificate>(
    artifact: &'artifact CoreArtifact,
    binding_time_request: &BindingTimeRequest,
    certificate: &'certificate BindingTimeCertificate,
    request: &SpecializationRequest,
) -> Result<ValidatedSpecializationRequest<'artifact, 'certificate>, SpecializationRequestErrors> {
    let verified_certificate =
        verify_binding_time_b0_certificate(artifact, binding_time_request, certificate)
            .map_err(invalid_certificate_error)?;
    let program = &artifact.program;
    let entry = program
        .functions
        .iter()
        .find(|function| function.id == program.entry)
        .expect("verified B0 certificate implies a verified entry function");
    let mut errors = Vec::new();

    if request.schema_version != R0_REQUEST_SCHEMA_VERSION {
        push_error(
            &mut errors,
            SpecializationRequestCode::UnsupportedRequestSchema,
            "request.schema_version",
            &format!(
                "expected {:?}, found {:?}",
                R0_REQUEST_SCHEMA_VERSION, request.schema_version
            ),
        );
    }
    if request.source_program_hash != artifact.semantic_hash {
        push_error(
            &mut errors,
            SpecializationRequestCode::SourceProgramHashMismatch,
            "request.source_program_hash",
            "request source hash does not match the verified B0 artifact",
        );
    }
    if request.interpreter_semantics_hash != binding_time_request.interpreter_semantics_hash {
        push_error(
            &mut errors,
            SpecializationRequestCode::InterpreterSemanticsHashMismatch,
            "request.interpreter_semantics_hash",
            "request semantics hash does not match the verified B0 request",
        );
    }
    if request.binding_time_policy_version != B0_POLICY_VERSION {
        push_error(
            &mut errors,
            SpecializationRequestCode::BindingTimePolicyVersionMismatch,
            "request.binding_time_policy_version",
            "request B0 policy version is not the admitted version",
        );
    }
    if request.binding_time_policy_hash != binding_time_request.policy_hash {
        push_error(
            &mut errors,
            SpecializationRequestCode::BindingTimePolicyHashMismatch,
            "request.binding_time_policy_hash",
            "request B0 policy hash does not match the verified B0 request",
        );
    }
    match binding_time_request_hash(binding_time_request) {
        Ok(expected) if request.binding_time_request_hash != expected => push_error(
            &mut errors,
            SpecializationRequestCode::BindingTimeRequestHashMismatch,
            "request.binding_time_request_hash",
            "request does not bind the canonical B0 request hash",
        ),
        Err(error) => push_error(
            &mut errors,
            SpecializationRequestCode::EncodingFailure,
            "request.binding_time_request_hash",
            &error.to_string(),
        ),
        _ => {}
    }
    if request.binding_time_certificate_hash != certificate.certificate_hash {
        push_error(
            &mut errors,
            SpecializationRequestCode::BindingTimeCertificateHashMismatch,
            "request.binding_time_certificate_hash",
            "request does not bind the verified B0 certificate hash",
        );
    }
    if request.policy_version != R0_POLICY_VERSION {
        push_error(
            &mut errors,
            SpecializationRequestCode::UnsupportedPolicyVersion,
            "request.policy_version",
            "request R0 policy version is not admitted",
        );
    }
    match specialization_policy_hash() {
        Ok(expected) if request.policy_hash != expected => push_error(
            &mut errors,
            SpecializationRequestCode::PolicyHashMismatch,
            "request.policy_hash",
            "request R0 policy hash does not match the canonical policy",
        ),
        Err(error) => push_error(
            &mut errors,
            SpecializationRequestCode::EncodingFailure,
            "request.policy_hash",
            &error.to_string(),
        ),
        _ => {}
    }
    if request.entry_function != program.entry {
        push_error(
            &mut errors,
            SpecializationRequestCode::EntryFunctionMismatch,
            "request.entry_function",
            "request entry function does not match the verified source",
        );
    }
    if request.entry_slots.len() != entry.parameters.len() {
        push_error(
            &mut errors,
            SpecializationRequestCode::EntrySlotArity,
            "request.entry_slots",
            &format!(
                "expected {} entry slot(s), found {}",
                entry.parameters.len(),
                request.entry_slots.len()
            ),
        );
    }

    validate_budget(&mut errors, request.budget);
    let mut usage = StaticValueUsage::default();
    let manifest = &verified_certificate.certificate().entry_parameters;
    for (index, ((slot, parameter), binding_time)) in request
        .entry_slots
        .iter()
        .zip(&entry.parameters)
        .zip(manifest)
        .enumerate()
    {
        let path = format!("request.entry_slots[{index}]");
        match (binding_time, slot) {
            (BindingTime::Static, SpecializationSlot::Static(value)) => {
                inspect_static_value(
                    value,
                    &parameter.ty,
                    &format!("{path}.value"),
                    &mut usage,
                    &mut errors,
                );
            }
            (BindingTime::Dynamic, SpecializationSlot::Dynamic(ty)) => {
                if ty != &parameter.ty {
                    push_error(
                        &mut errors,
                        SpecializationRequestCode::DynamicTypeMismatch,
                        &format!("{path}.type"),
                        &format!("expected {:?}, found {ty:?}", parameter.ty),
                    );
                }
            }
            (BindingTime::Static, SpecializationSlot::Dynamic(_)) => push_error(
                &mut errors,
                SpecializationRequestCode::StaticDynamicMismatch,
                &path,
                "B0 Static parameter requires a concrete Static slot",
            ),
            (BindingTime::Dynamic, SpecializationSlot::Static(_)) => push_error(
                &mut errors,
                SpecializationRequestCode::StaticDynamicMismatch,
                &path,
                "B0 Dynamic parameter requires a value-free Dynamic slot",
            ),
        }
    }
    if usage.nodes > request.budget.max_static_value_nodes {
        push_error(
            &mut errors,
            SpecializationRequestCode::StaticValueBudgetExceeded,
            "request.entry_slots",
            &format!(
                "static values use {} node(s), limit is {}",
                usage.nodes, request.budget.max_static_value_nodes
            ),
        );
    }
    if usage.array_elements > request.budget.max_static_array_elements {
        push_error(
            &mut errors,
            SpecializationRequestCode::StaticArrayBudgetExceeded,
            "request.entry_slots",
            &format!(
                "static arrays contain {} element(s), limit is {}",
                usage.array_elements, request.budget.max_static_array_elements
            ),
        );
    }

    if !errors.is_empty() {
        return Err(SpecializationRequestErrors(errors));
    }
    let request_hash = specialization_request_hash(request).map_err(|error| {
        SpecializationRequestErrors(vec![SpecializationRequestError {
            code: SpecializationRequestCode::EncodingFailure,
            path: "request".to_owned(),
            message: error.to_string(),
        }])
    })?;
    Ok(ValidatedSpecializationRequest {
        artifact,
        verified_certificate,
        request: request.clone(),
        request_hash,
    })
}

fn invalid_certificate_error(errors: BindingTimeCertificateErrors) -> SpecializationRequestErrors {
    SpecializationRequestErrors(vec![SpecializationRequestError {
        code: SpecializationRequestCode::InvalidBindingTimeCertificate,
        path: "request.binding_time_certificate".to_owned(),
        message: errors.to_string(),
    }])
}

fn validate_budget(errors: &mut Vec<SpecializationRequestError>, budget: SpecializationBudget) {
    validate_budget_field(
        errors,
        "request.budget.max_static_value_nodes",
        budget.max_static_value_nodes,
        R0_MAX_STATIC_VALUE_NODES_HARD_CAP,
    );
    validate_budget_field(
        errors,
        "request.budget.max_static_array_elements",
        budget.max_static_array_elements,
        R0_MAX_STATIC_ARRAY_ELEMENTS_HARD_CAP,
    );
    validate_budget_field(
        errors,
        "request.budget.max_specialization_steps",
        budget.max_specialization_steps,
        R0_MAX_SPECIALIZATION_STEPS_HARD_CAP,
    );
    validate_budget_field(
        errors,
        "request.budget.max_residual_nodes",
        budget.max_residual_nodes,
        R0_MAX_RESIDUAL_NODES_HARD_CAP,
    );
    validate_budget_field(
        errors,
        "request.budget.max_residual_bytes",
        budget.max_residual_bytes,
        R0_MAX_RESIDUAL_BYTES_HARD_CAP,
    );
}

fn validate_budget_field(
    errors: &mut Vec<SpecializationRequestError>,
    path: &'static str,
    value: u64,
    hard_cap: u64,
) {
    if value == 0 {
        push_error(
            errors,
            SpecializationRequestCode::ZeroBudget,
            path,
            "budget must be non-zero",
        );
    } else if value > hard_cap {
        push_error(
            errors,
            SpecializationRequestCode::BudgetHardCapExceeded,
            path,
            &format!("budget exceeds hard cap {hard_cap}"),
        );
    }
}

#[derive(Default)]
struct StaticValueUsage {
    nodes: u64,
    array_elements: u64,
}

fn inspect_static_value(
    value: &SpecializationValue,
    expected: &Type,
    path: &str,
    usage: &mut StaticValueUsage,
    errors: &mut Vec<SpecializationRequestError>,
) {
    usage.nodes = usage.nodes.saturating_add(1);
    match (value, expected) {
        (SpecializationValue::Unit, Type::Unit)
        | (SpecializationValue::Bool(_), Type::Bool)
        | (SpecializationValue::I64(_), Type::I64)
        | (SpecializationValue::F64(_), Type::F64) => {}
        (SpecializationValue::Tuple(values), Type::Tuple(types)) => {
            if values.len() != types.len() {
                static_type_error(
                    errors,
                    path,
                    &format!(
                        "tuple has {} field(s), expected {}",
                        values.len(),
                        types.len()
                    ),
                );
            }
            for (index, (field, ty)) in values.iter().zip(types).enumerate() {
                inspect_static_value(field, ty, &format!("{path}.fields[{index}]"), usage, errors);
            }
        }
        (
            SpecializationValue::Sum {
                ty,
                constructor,
                fields,
            },
            Type::Sum(expected_sum),
        ) => {
            if ty != expected_sum {
                static_type_error(
                    errors,
                    &format!("{path}.type"),
                    "sum type identity mismatch",
                );
            }
            let Some(constructor_type) = expected_sum.constructors.get(*constructor as usize)
            else {
                static_type_error(
                    errors,
                    &format!("{path}.constructor"),
                    &format!("constructor {constructor} does not exist"),
                );
                return;
            };
            if fields.len() != constructor_type.fields.len() {
                static_type_error(
                    errors,
                    &format!("{path}.fields"),
                    &format!(
                        "constructor has {} field(s), expected {}",
                        fields.len(),
                        constructor_type.fields.len()
                    ),
                );
            }
            for (index, (field, ty)) in fields.iter().zip(&constructor_type.fields).enumerate() {
                inspect_static_value(field, ty, &format!("{path}.fields[{index}]"), usage, errors);
            }
        }
        (
            SpecializationValue::ArrayF64(values),
            Type::Array {
                mutability,
                element,
                ..
            },
        ) if *mutability == Mutability::Read && element.as_ref() == &Type::F64 => {
            let elements = u64::try_from(values.len()).unwrap_or(u64::MAX);
            usage.array_elements = usage.array_elements.saturating_add(elements);
        }
        _ => static_type_error(
            errors,
            path,
            &format!("value does not match expected type {expected:?}"),
        ),
    }
}

fn static_type_error(errors: &mut Vec<SpecializationRequestError>, path: &str, message: &str) {
    push_error(
        errors,
        SpecializationRequestCode::StaticValueTypeMismatch,
        path,
        message,
    );
}

fn push_error(
    errors: &mut Vec<SpecializationRequestError>,
    code: SpecializationRequestCode,
    path: &str,
    message: &str,
) {
    errors.push(SpecializationRequestError {
        code,
        path: path.to_owned(),
        message: message.to_owned(),
    });
}
