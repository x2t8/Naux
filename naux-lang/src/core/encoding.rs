use super::schema::{
    CaseArm, ConstructorType, CoreProfile, Effect, EffectRow, ErrorKind, Function, HandlerClause,
    Mutability, NumericMode, Operand, OperationSignature, Primitive, Program, RValue, SemanticHash,
    SumType, Term, Type, CORE_SCHEMA_NAME, CORE_SCHEMA_VERSION,
};
use super::specialization::{
    SpecializationRequest, SpecializationSlot, SpecializationValue, R0_MAX_RESIDUAL_BYTES_HARD_CAP,
    R0_MAX_RESIDUAL_NODES_HARD_CAP, R0_MAX_SPECIALIZATION_STEPS_HARD_CAP,
    R0_MAX_STATIC_ARRAY_ELEMENTS_HARD_CAP, R0_MAX_STATIC_VALUE_NODES_HARD_CAP, R0_POLICY_VERSION,
};
use super::staging::{
    BindingTime, BindingTimeCertificate, BindingTimeFunctionSummary, BindingTimeJudgment,
    BindingTimeNodeId, BindingTimeNodeKind, BindingTimePathField, BindingTimeRequest,
    StaticEvaluationEligibility, B0_MAX_CALL_EDGES_HARD_CAP, B0_MAX_FIXPOINT_ITERATIONS_HARD_CAP,
    B0_MAX_NODES_HARD_CAP, B0_POLICY_VERSION,
};
use std::fmt;

const SEMANTIC_DOMAIN: &[u8] = b"NAUX:core-n0:semantic:v1\0";
const INTERPRETER_SEMANTICS_DOMAIN: &[u8] = b"NAUX:core-n0:interpreter-semantics:v1\0";
const BINDING_TIME_POLICY_DOMAIN: &[u8] = b"NAUX:core-n0:binding-time-policy:b0:v1\0";
const BINDING_TIME_REQUEST_DOMAIN: &[u8] = b"NAUX:core-n0:binding-time-request:b0:v1\0";
const BINDING_TIME_NODE_DOMAIN: &[u8] = b"NAUX:core-n0:binding-time-node:b0:v1\0";
const BINDING_TIME_CERTIFICATE_DOMAIN: &[u8] = b"NAUX:core-n0:binding-time-certificate:b0:v1\0";
const SPECIALIZATION_VALUE_DOMAIN: &[u8] = b"NAUX:core-n0:specialization-value:r0:v1\0";
const SPECIALIZATION_POLICY_DOMAIN: &[u8] = b"NAUX:core-n0:specialization-policy:r0:v1\0";
const SPECIALIZATION_REQUEST_DOMAIN: &[u8] = b"NAUX:core-n0:specialization-request:r0:v1\0";
const INTERPRETER_SEMANTICS_VERSION: (u16, u16, u16) = (1, 0, 0);
const INTERPRETER_SEMANTIC_CAPABILITIES: &[&str] = &[
    "verified-artifact-only-v1",
    "call-by-value-left-to-right-anf-v1",
    "strict-i64-explicit-modes-v1",
    "strict-f64-binary64-v1",
    "typed-overflow-bounds-v1",
    "deterministic-step-call-budget-v1",
    "p1v0-values-calls-case-array-v1",
    "p1v1-lexical-logical-store-shared-v1",
    "p1v2-existential-closure-environment-v1",
    "p1v3-linear-lexical-handler-v1",
    "p1v4-affine-direct-unique-v1",
    "p1v5-anchored-ownership-return-v1",
];
const BINDING_TIME_POLICY_CAPABILITIES: &[&str] = &[
    "two-point-static-dynamic-lattice-v1",
    "conservative-dynamic-control-v1",
    "fixed-p1v0-input-v1",
    "effect-eligibility-separated-v1",
    "deterministic-least-fixpoint-v1",
    "stable-structural-node-path-v1",
    "fail-closed-budget-v1",
];
const SPECIALIZATION_POLICY_CAPABILITIES: &[&str] = &[
    "verified-b0-certificate-only-v1",
    "exact-static-dynamic-entry-slots-v1",
    "canonical-immutable-p1v0-values-v1",
    "effect-safe-static-execution-required-v1",
    "fail-closed-specialization-budgets-v1",
    "verified-residual-core-only-v1",
];
const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {
    LengthOverflow { field: &'static str, length: usize },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOverflow { field, length } => {
                write!(formatter, "{field} length {length} exceeds u32")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

pub fn semantic_bytes(program: &Program) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::default();
    encoder.bytes.extend_from_slice(SEMANTIC_DOMAIN);
    encoder.string("schema.name", &program.schema.name)?;
    encoder.u16(program.schema.major);
    encoder.u16(program.schema.minor);
    encoder.u16(program.schema.patch);
    encode_profile(&mut encoder, program.profile);
    encoder.u32(program.entry.0);
    encoder.sequence("program.functions", &program.functions, encode_function)?;
    Ok(encoder.bytes)
}

pub fn semantic_hash(program: &Program) -> Result<SemanticHash, EncodeError> {
    Ok(SemanticHash(sha256(&semantic_bytes(program)?)))
}

/// Encode the declared interpreter semantics for a Core profile.
///
/// This identity is independent of any particular Core program and of the
/// bridge implementation's source layout. Each later profile includes the
/// capabilities of every earlier profile.
pub fn interpreter_semantics_bytes(profile: CoreProfile) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::default();
    encoder
        .bytes
        .extend_from_slice(INTERPRETER_SEMANTICS_DOMAIN);
    encoder.string("interpreter_semantics.schema.name", CORE_SCHEMA_NAME)?;
    encoder.u16(CORE_SCHEMA_VERSION.0);
    encoder.u16(CORE_SCHEMA_VERSION.1);
    encoder.u16(CORE_SCHEMA_VERSION.2);
    encoder.u16(INTERPRETER_SEMANTICS_VERSION.0);
    encoder.u16(INTERPRETER_SEMANTICS_VERSION.1);
    encoder.u16(INTERPRETER_SEMANTICS_VERSION.2);
    encode_profile(&mut encoder, profile);

    let capability_count = interpreter_semantics_capability_count(profile);
    encoder.length("interpreter_semantics.capabilities", capability_count)?;
    for capability in &INTERPRETER_SEMANTIC_CAPABILITIES[..capability_count] {
        encoder.string("interpreter_semantics.capability", capability)?;
    }
    Ok(encoder.bytes)
}

/// Hash the canonical declared interpreter semantics for a Core profile.
pub fn interpreter_semantics_hash(profile: CoreProfile) -> Result<SemanticHash, EncodeError> {
    Ok(SemanticHash(sha256(&interpreter_semantics_bytes(profile)?)))
}

pub fn binding_time_policy_bytes() -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::default();
    encoder.bytes.extend_from_slice(BINDING_TIME_POLICY_DOMAIN);
    encoder.string("binding_time.policy.schema.name", CORE_SCHEMA_NAME)?;
    encoder.u16(CORE_SCHEMA_VERSION.0);
    encoder.u16(CORE_SCHEMA_VERSION.1);
    encoder.u16(CORE_SCHEMA_VERSION.2);
    encoder.u16(B0_POLICY_VERSION.0);
    encoder.u16(B0_POLICY_VERSION.1);
    encoder.u16(B0_POLICY_VERSION.2);
    encode_profile(&mut encoder, CoreProfile::P1V0);
    encoder
        .bytes
        .extend_from_slice(&interpreter_semantics_hash(CoreProfile::P1V0)?.0);
    encoder.u64(B0_MAX_NODES_HARD_CAP);
    encoder.u64(B0_MAX_CALL_EDGES_HARD_CAP);
    encoder.u32(B0_MAX_FIXPOINT_ITERATIONS_HARD_CAP);
    encoder.length(
        "binding_time.policy.capabilities",
        BINDING_TIME_POLICY_CAPABILITIES.len(),
    )?;
    for capability in BINDING_TIME_POLICY_CAPABILITIES {
        encoder.string("binding_time.policy.capability", capability)?;
    }
    Ok(encoder.bytes)
}

pub fn binding_time_policy_hash() -> Result<SemanticHash, EncodeError> {
    Ok(SemanticHash(sha256(&binding_time_policy_bytes()?)))
}

pub fn binding_time_request_bytes(request: &BindingTimeRequest) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::default();
    encoder.bytes.extend_from_slice(BINDING_TIME_REQUEST_DOMAIN);
    encoder.u16(request.schema_version.0);
    encoder.u16(request.schema_version.1);
    encoder.u16(request.schema_version.2);
    encoder
        .bytes
        .extend_from_slice(&request.source_program_hash.0);
    encoder
        .bytes
        .extend_from_slice(&request.interpreter_semantics_hash.0);
    encoder.u16(request.policy_version.0);
    encoder.u16(request.policy_version.1);
    encoder.u16(request.policy_version.2);
    encoder.bytes.extend_from_slice(&request.policy_hash.0);
    encoder.length(
        "binding_time.request.entry_parameters",
        request.entry_parameters.len(),
    )?;
    for binding_time in &request.entry_parameters {
        encode_binding_time(&mut encoder, *binding_time);
    }
    encoder.u64(request.budget.max_nodes);
    encoder.u64(request.budget.max_call_edges);
    encoder.u32(request.budget.max_fixpoint_iterations);
    Ok(encoder.bytes)
}

pub fn binding_time_request_hash(
    request: &BindingTimeRequest,
) -> Result<SemanticHash, EncodeError> {
    Ok(SemanticHash(sha256(&binding_time_request_bytes(request)?)))
}

pub fn binding_time_node_bytes(node: &BindingTimeNodeId) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::default();
    encoder.bytes.extend_from_slice(BINDING_TIME_NODE_DOMAIN);
    encoder.u32(node.function.0);
    encoder.length("binding_time.node.path", node.path.len())?;
    for segment in &node.path {
        encode_binding_time_path_field(&mut encoder, segment.field);
        encoder.u32(segment.index);
    }
    Ok(encoder.bytes)
}

pub fn binding_time_node_hash(node: &BindingTimeNodeId) -> Result<SemanticHash, EncodeError> {
    Ok(SemanticHash(sha256(&binding_time_node_bytes(node)?)))
}

pub fn binding_time_certificate_bytes(
    certificate: &BindingTimeCertificate,
) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::default();
    encoder
        .bytes
        .extend_from_slice(BINDING_TIME_CERTIFICATE_DOMAIN);
    encoder.u16(certificate.schema_version.0);
    encoder.u16(certificate.schema_version.1);
    encoder.u16(certificate.schema_version.2);
    encoder
        .bytes
        .extend_from_slice(&certificate.source_program_hash.0);
    encoder
        .bytes
        .extend_from_slice(&certificate.interpreter_semantics_hash.0);
    encoder.bytes.extend_from_slice(&certificate.policy_hash.0);
    encoder.bytes.extend_from_slice(&certificate.request_hash.0);
    encoder.u32(certificate.entry_function.0);
    encoder.length(
        "binding_time.certificate.entry_parameters",
        certificate.entry_parameters.len(),
    )?;
    for binding_time in &certificate.entry_parameters {
        encode_binding_time(&mut encoder, *binding_time);
    }
    encoder.sequence(
        "binding_time.certificate.judgments",
        &certificate.judgments,
        encode_binding_time_judgment,
    )?;
    encoder.sequence(
        "binding_time.certificate.function_summaries",
        &certificate.function_summaries,
        encode_binding_time_function_summary,
    )?;
    encoder.u64(certificate.declared_budget.max_nodes);
    encoder.u64(certificate.declared_budget.max_call_edges);
    encoder.u32(certificate.declared_budget.max_fixpoint_iterations);
    encoder.u64(certificate.budget_usage.nodes);
    encoder.u64(certificate.budget_usage.call_edges);
    encoder.u32(certificate.budget_usage.fixpoint_iterations);
    Ok(encoder.bytes)
}

pub fn binding_time_certificate_hash(
    certificate: &BindingTimeCertificate,
) -> Result<SemanticHash, EncodeError> {
    Ok(SemanticHash(sha256(&binding_time_certificate_bytes(
        certificate,
    )?)))
}

pub fn specialization_value_bytes(value: &SpecializationValue) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::default();
    encoder.bytes.extend_from_slice(SPECIALIZATION_VALUE_DOMAIN);
    encode_specialization_value(&mut encoder, value)?;
    Ok(encoder.bytes)
}

pub fn specialization_value_hash(value: &SpecializationValue) -> Result<SemanticHash, EncodeError> {
    Ok(SemanticHash(sha256(&specialization_value_bytes(value)?)))
}

pub fn specialization_policy_bytes() -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::default();
    encoder
        .bytes
        .extend_from_slice(SPECIALIZATION_POLICY_DOMAIN);
    encoder.string("specialization.policy.schema.name", CORE_SCHEMA_NAME)?;
    encoder.u16(CORE_SCHEMA_VERSION.0);
    encoder.u16(CORE_SCHEMA_VERSION.1);
    encoder.u16(CORE_SCHEMA_VERSION.2);
    encoder.u16(R0_POLICY_VERSION.0);
    encoder.u16(R0_POLICY_VERSION.1);
    encoder.u16(R0_POLICY_VERSION.2);
    encode_profile(&mut encoder, CoreProfile::P1V0);
    encoder
        .bytes
        .extend_from_slice(&interpreter_semantics_hash(CoreProfile::P1V0)?.0);
    encoder
        .bytes
        .extend_from_slice(&binding_time_policy_hash()?.0);
    encoder.u64(R0_MAX_STATIC_VALUE_NODES_HARD_CAP);
    encoder.u64(R0_MAX_STATIC_ARRAY_ELEMENTS_HARD_CAP);
    encoder.u64(R0_MAX_SPECIALIZATION_STEPS_HARD_CAP);
    encoder.u64(R0_MAX_RESIDUAL_NODES_HARD_CAP);
    encoder.u64(R0_MAX_RESIDUAL_BYTES_HARD_CAP);
    encoder.length(
        "specialization.policy.capabilities",
        SPECIALIZATION_POLICY_CAPABILITIES.len(),
    )?;
    for capability in SPECIALIZATION_POLICY_CAPABILITIES {
        encoder.string("specialization.policy.capability", capability)?;
    }
    Ok(encoder.bytes)
}

pub fn specialization_policy_hash() -> Result<SemanticHash, EncodeError> {
    Ok(SemanticHash(sha256(&specialization_policy_bytes()?)))
}

pub fn specialization_request_bytes(
    request: &SpecializationRequest,
) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::default();
    encoder
        .bytes
        .extend_from_slice(SPECIALIZATION_REQUEST_DOMAIN);
    encoder.u16(request.schema_version.0);
    encoder.u16(request.schema_version.1);
    encoder.u16(request.schema_version.2);
    encoder
        .bytes
        .extend_from_slice(&request.source_program_hash.0);
    encoder
        .bytes
        .extend_from_slice(&request.interpreter_semantics_hash.0);
    encoder.u16(request.binding_time_policy_version.0);
    encoder.u16(request.binding_time_policy_version.1);
    encoder.u16(request.binding_time_policy_version.2);
    encoder
        .bytes
        .extend_from_slice(&request.binding_time_policy_hash.0);
    encoder
        .bytes
        .extend_from_slice(&request.binding_time_request_hash.0);
    encoder
        .bytes
        .extend_from_slice(&request.binding_time_certificate_hash.0);
    encoder.u16(request.policy_version.0);
    encoder.u16(request.policy_version.1);
    encoder.u16(request.policy_version.2);
    encoder.bytes.extend_from_slice(&request.policy_hash.0);
    encoder.u32(request.entry_function.0);
    encoder.sequence(
        "specialization.request.entry_slots",
        &request.entry_slots,
        encode_specialization_slot,
    )?;
    encoder.u64(request.budget.max_static_value_nodes);
    encoder.u64(request.budget.max_static_array_elements);
    encoder.u64(request.budget.max_specialization_steps);
    encoder.u64(request.budget.max_residual_nodes);
    encoder.u64(request.budget.max_residual_bytes);
    Ok(encoder.bytes)
}

pub fn specialization_request_hash(
    request: &SpecializationRequest,
) -> Result<SemanticHash, EncodeError> {
    Ok(SemanticHash(sha256(&specialization_request_bytes(
        request,
    )?)))
}

fn encode_specialization_slot(
    encoder: &mut Encoder,
    slot: &SpecializationSlot,
) -> Result<(), EncodeError> {
    match slot {
        SpecializationSlot::Static(value) => {
            encoder.tag(0);
            let value = specialization_value_bytes(value)?;
            encoder.length("specialization.request.slot.static", value.len())?;
            encoder.bytes.extend_from_slice(&value);
        }
        SpecializationSlot::Dynamic(ty) => {
            encoder.tag(1);
            encode_type(encoder, ty)?;
        }
    }
    Ok(())
}

fn encode_specialization_value(
    encoder: &mut Encoder,
    value: &SpecializationValue,
) -> Result<(), EncodeError> {
    match value {
        SpecializationValue::Unit => encoder.tag(0),
        SpecializationValue::Bool(value) => {
            encoder.tag(1);
            encoder.tag(u8::from(*value));
        }
        SpecializationValue::I64(value) => {
            encoder.tag(2);
            encoder.i64(*value);
        }
        SpecializationValue::F64(value) => {
            encoder.tag(3);
            encoder.u64(canonical_f64_bits(*value));
        }
        SpecializationValue::Tuple(fields) => {
            encoder.tag(4);
            encoder.sequence(
                "specialization.value.tuple.fields",
                fields,
                encode_specialization_value,
            )?;
        }
        SpecializationValue::Sum {
            ty,
            constructor,
            fields,
        } => {
            encoder.tag(5);
            encode_sum_type(encoder, ty)?;
            encoder.u32(*constructor);
            encoder.sequence(
                "specialization.value.sum.fields",
                fields,
                encode_specialization_value,
            )?;
        }
        SpecializationValue::ArrayF64(values) => {
            encoder.tag(6);
            encoder.length("specialization.value.array_f64", values.len())?;
            for value in values {
                encoder.u64(canonical_f64_bits(*value));
            }
        }
    }
    Ok(())
}

fn encode_binding_time_judgment(
    encoder: &mut Encoder,
    judgment: &BindingTimeJudgment,
) -> Result<(), EncodeError> {
    let node = binding_time_node_bytes(&judgment.node)?;
    encoder.length("binding_time.certificate.judgment.node", node.len())?;
    encoder.bytes.extend_from_slice(&node);
    encode_binding_time_node_kind(encoder, judgment.kind);
    encode_binding_time(encoder, judgment.binding_time);
    encode_static_evaluation_eligibility(encoder, judgment.static_evaluation);
    Ok(())
}

fn encode_binding_time_function_summary(
    encoder: &mut Encoder,
    summary: &BindingTimeFunctionSummary,
) -> Result<(), EncodeError> {
    encoder.u32(summary.function.0);
    encoder.tag(u8::from(summary.reachable));
    encoder.length(
        "binding_time.certificate.summary.parameters",
        summary.parameters.len(),
    )?;
    for binding_time in &summary.parameters {
        encode_binding_time(encoder, *binding_time);
    }
    encode_binding_time(encoder, summary.control);
    encode_binding_time(encoder, summary.result);
    encode_static_evaluation_eligibility(encoder, summary.static_evaluation);
    Ok(())
}

fn encode_binding_time(encoder: &mut Encoder, binding_time: BindingTime) {
    encoder.tag(match binding_time {
        BindingTime::Static => 0,
        BindingTime::Dynamic => 1,
    });
}

fn encode_binding_time_node_kind(encoder: &mut Encoder, kind: BindingTimeNodeKind) {
    encoder.tag(match kind {
        BindingTimeNodeKind::Term => 0,
        BindingTimeNodeKind::RValue => 1,
        BindingTimeNodeKind::Operand => 2,
    });
}

fn encode_static_evaluation_eligibility(
    encoder: &mut Encoder,
    eligibility: StaticEvaluationEligibility,
) {
    encoder.tag(match eligibility {
        StaticEvaluationEligibility::EligiblePure => 0,
        StaticEvaluationEligibility::Denied => 1,
    });
}

fn encode_binding_time_path_field(encoder: &mut Encoder, field: BindingTimePathField) {
    encoder.tag(field.tag());
}

fn interpreter_semantics_capability_count(profile: CoreProfile) -> usize {
    match profile {
        CoreProfile::P1V0 => 7,
        CoreProfile::P1V1 => 8,
        CoreProfile::P1V2 => 9,
        CoreProfile::P1V3 => 10,
        CoreProfile::P1V4 => 11,
        CoreProfile::P1V5 => 12,
    }
}

#[derive(Default)]
struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn tag(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn length(&mut self, field: &'static str, length: usize) -> Result<(), EncodeError> {
        let length =
            u32::try_from(length).map_err(|_| EncodeError::LengthOverflow { field, length })?;
        self.u32(length);
        Ok(())
    }

    fn string(&mut self, field: &'static str, value: &str) -> Result<(), EncodeError> {
        self.length(field, value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn sequence<T>(
        &mut self,
        field: &'static str,
        values: &[T],
        encode: fn(&mut Self, &T) -> Result<(), EncodeError>,
    ) -> Result<(), EncodeError> {
        self.length(field, values.len())?;
        for value in values {
            encode(self, value)?;
        }
        Ok(())
    }
}

fn encode_profile(encoder: &mut Encoder, profile: CoreProfile) {
    encoder.tag(match profile {
        CoreProfile::P1V0 => 0,
        CoreProfile::P1V1 => 1,
        CoreProfile::P1V2 => 2,
        CoreProfile::P1V3 => 3,
        CoreProfile::P1V4 => 4,
        CoreProfile::P1V5 => 5,
    });
}

fn encode_function(encoder: &mut Encoder, function: &Function) -> Result<(), EncodeError> {
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
        encoder.u32(parameter.local.0);
        encode_type(encoder, &parameter.ty)?;
    }
    encode_effect_row(encoder, &function.effects)?;
    encode_type(encoder, &function.result)?;
    encode_term(encoder, &function.body)
}

fn encode_type(encoder: &mut Encoder, ty: &Type) -> Result<(), EncodeError> {
    match ty {
        Type::Unit => encoder.tag(0),
        Type::Bool => encoder.tag(1),
        Type::I64 => encoder.tag(2),
        Type::F64 => encoder.tag(3),
        Type::Text => encoder.tag(4),
        Type::Bytes => encoder.tag(5),
        Type::Tuple(fields) => {
            encoder.tag(6);
            encoder.sequence("type.tuple.fields", fields, encode_type)?;
        }
        Type::Sum(sum) => {
            encoder.tag(7);
            encode_sum_type(encoder, sum)?;
        }
        Type::Array {
            region,
            mutability,
            element,
        } => {
            encoder.tag(8);
            encoder.u32(region.0);
            encode_mutability(encoder, *mutability);
            encode_type(encoder, element)?;
        }
        Type::Ref {
            region,
            mutability,
            element,
        } => {
            encoder.tag(9);
            encoder.u32(region.0);
            encode_mutability(encoder, *mutability);
            encode_type(encoder, element)?;
        }
        Type::Function {
            parameters,
            effects,
            result,
        } => {
            encoder.tag(10);
            encoder.sequence("type.function.parameters", parameters, encode_type)?;
            encode_effect_row(encoder, effects)?;
            encode_type(encoder, result)?;
        }
        Type::Closure {
            parameters,
            effects,
            result,
        } => {
            encoder.tag(11);
            encoder.sequence("type.closure.parameters", parameters, encode_type)?;
            encode_effect_row(encoder, effects)?;
            encode_type(encoder, result)?;
        }
    }
    Ok(())
}

fn encode_mutability(encoder: &mut Encoder, mutability: Mutability) {
    encoder.tag(match mutability {
        Mutability::Read => 0,
        Mutability::Unique => 1,
        Mutability::Shared => 2,
    });
}

fn encode_sum_type(encoder: &mut Encoder, sum: &SumType) -> Result<(), EncodeError> {
    encoder.string("sum.name", &sum.name)?;
    encoder.sequence(
        "sum.constructors",
        &sum.constructors,
        encode_constructor_type,
    )
}

fn encode_constructor_type(
    encoder: &mut Encoder,
    constructor: &ConstructorType,
) -> Result<(), EncodeError> {
    encoder.string("constructor.name", &constructor.name)?;
    encoder.sequence("constructor.fields", &constructor.fields, encode_type)
}

fn encode_effect_row(encoder: &mut Encoder, row: &EffectRow) -> Result<(), EncodeError> {
    encoder.sequence("effect_row.effects", &row.effects, encode_effect)
}

fn encode_effect(encoder: &mut Encoder, effect: &Effect) -> Result<(), EncodeError> {
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
            encoder.bytes.extend_from_slice(hash);
        }
        Effect::UnsafeMemory(hash) => {
            encoder.tag(5);
            encoder.bytes.extend_from_slice(hash);
        }
        Effect::Operation(operation) => {
            encoder.tag(6);
            encode_operation_signature(encoder, operation)?;
        }
    }
    Ok(())
}

fn encode_operation_signature(
    encoder: &mut Encoder,
    operation: &OperationSignature,
) -> Result<(), EncodeError> {
    encoder.u32(operation.id.0);
    encoder.sequence("operation.parameters", &operation.parameters, encode_type)?;
    encode_type(encoder, &operation.result)
}

fn encode_error_kind(encoder: &mut Encoder, error: &ErrorKind) {
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

fn encode_numeric_mode(encoder: &mut Encoder, mode: NumericMode) {
    encoder.tag(match mode {
        NumericMode::Checked => 0,
        NumericMode::Wrapping => 1,
        NumericMode::Saturating => 2,
    });
}

fn encode_primitive(encoder: &mut Encoder, primitive: &Primitive) {
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

fn encode_operand(encoder: &mut Encoder, operand: &Operand) -> Result<(), EncodeError> {
    match operand {
        Operand::Unit => encoder.tag(0),
        Operand::Bool(value) => {
            encoder.tag(1);
            encoder.tag(u8::from(*value));
        }
        Operand::I64(value) => {
            encoder.tag(2);
            encoder.i64(*value);
        }
        Operand::F64(value) => {
            encoder.tag(3);
            encoder.u64(canonical_f64_bits(*value));
        }
        Operand::Local(local) => {
            encoder.tag(4);
            encoder.u32(local.0);
        }
    }
    Ok(())
}

pub(super) fn canonical_f64_bits(value: f64) -> u64 {
    if value.is_nan() {
        CANONICAL_NAN_BITS
    } else {
        value.to_bits()
    }
}

fn encode_rvalue(encoder: &mut Encoder, value: &RValue) -> Result<(), EncodeError> {
    match value {
        RValue::Use(operand) => {
            encoder.tag(0);
            encode_operand(encoder, operand)?;
        }
        RValue::Tuple(fields) => {
            encoder.tag(1);
            encoder.sequence("rvalue.tuple.fields", fields, encode_operand)?;
        }
        RValue::Project { tuple, index } => {
            encoder.tag(2);
            encode_operand(encoder, tuple)?;
            encoder.u32(*index);
        }
        RValue::Construct {
            sum,
            constructor,
            fields,
        } => {
            encoder.tag(3);
            encode_sum_type(encoder, sum)?;
            encoder.u32(*constructor);
            encoder.sequence("rvalue.constructor.fields", fields, encode_operand)?;
        }
        RValue::Primitive {
            operation,
            arguments,
        } => {
            encoder.tag(4);
            encode_primitive(encoder, operation);
            encoder.sequence("rvalue.primitive.arguments", arguments, encode_operand)?;
        }
        RValue::Call {
            function,
            arguments,
        } => {
            encoder.tag(5);
            encoder.u32(function.0);
            encoder.sequence("rvalue.call.arguments", arguments, encode_operand)?;
        }
        RValue::RefAlloc {
            region,
            mutability,
            value,
        } => {
            encoder.tag(6);
            encoder.u32(region.0);
            encode_mutability(encoder, *mutability);
            encode_operand(encoder, value)?;
        }
        RValue::RefLoad { reference } => {
            encoder.tag(7);
            encode_operand(encoder, reference)?;
        }
        RValue::RefStore { reference, value } => {
            encoder.tag(8);
            encode_operand(encoder, reference)?;
            encode_operand(encoder, value)?;
        }
        RValue::PackClosure { function, captures } => {
            encoder.tag(9);
            encoder.u32(function.0);
            encoder.sequence("rvalue.pack_closure.captures", captures, encode_operand)?;
        }
        RValue::CallClosure { closure, arguments } => {
            encoder.tag(10);
            encode_operand(encoder, closure)?;
            encoder.sequence("rvalue.call_closure.arguments", arguments, encode_operand)?;
        }
        RValue::Perform {
            operation,
            arguments,
        } => {
            encoder.tag(11);
            encode_operation_signature(encoder, operation)?;
            encoder.sequence("rvalue.perform.arguments", arguments, encode_operand)?;
        }
    }
    Ok(())
}

fn encode_case_arm(encoder: &mut Encoder, arm: &CaseArm) -> Result<(), EncodeError> {
    encoder.u32(arm.constructor);
    encoder.length("case_arm.bindings", arm.bindings.len())?;
    for binding in &arm.bindings {
        encoder.u32(binding.0);
    }
    encode_term(encoder, &arm.body)
}

fn encode_handler_clause(encoder: &mut Encoder, clause: &HandlerClause) -> Result<(), EncodeError> {
    encode_operation_signature(encoder, &clause.operation)?;
    encoder.length("handler_clause.parameters", clause.parameters.len())?;
    for parameter in &clause.parameters {
        encoder.u32(parameter.0);
    }
    encode_term(encoder, &clause.body)
}

fn encode_term(encoder: &mut Encoder, term: &Term) -> Result<(), EncodeError> {
    match term {
        Term::Let {
            binder,
            ty,
            value,
            next,
        } => {
            encoder.tag(0);
            encoder.u32(binder.0);
            encode_type(encoder, ty)?;
            encode_rvalue(encoder, value)?;
            encode_term(encoder, next)?;
        }
        Term::If {
            condition,
            then_term,
            else_term,
        } => {
            encoder.tag(1);
            encode_operand(encoder, condition)?;
            encode_term(encoder, then_term)?;
            encode_term(encoder, else_term)?;
        }
        Term::Case { scrutinee, arms } => {
            encoder.tag(2);
            encode_operand(encoder, scrutinee)?;
            encoder.sequence("term.case.arms", arms, encode_case_arm)?;
        }
        Term::TailCall {
            function,
            arguments,
        } => {
            encoder.tag(3);
            encoder.u32(function.0);
            encoder.sequence("term.tail_call.arguments", arguments, encode_operand)?;
        }
        Term::Return(operand) => {
            encoder.tag(4);
            encode_operand(encoder, operand)?;
        }
        Term::Region { region, body } => {
            encoder.tag(5);
            encoder.u32(region.0);
            encode_term(encoder, body)?;
        }
        Term::Handle {
            captures,
            capture_parameters,
            clauses,
            body,
        } => {
            encoder.tag(6);
            encoder.sequence("term.handle.captures", captures, encode_operand)?;
            encoder.length("term.handle.capture_parameters", capture_parameters.len())?;
            for parameter in capture_parameters {
                encoder.u32(parameter.local.0);
                encode_type(encoder, &parameter.ty)?;
            }
            encoder.sequence("term.handle.clauses", clauses, encode_handler_clause)?;
            encode_term(encoder, body)?;
        }
    }
    Ok(())
}

pub(crate) fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    let bit_length = (input.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity((input.len() + 72) & !63);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sum1 = h
                .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
                .wrapping_add((e & f) ^ ((!e) & g))
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sum0 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
                .wrapping_add((a & b) ^ (a & c) ^ (b & c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(sum1);
            d = c;
            c = b;
            b = a;
            a = sum0.wrapping_add(sum1);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut output = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::sha256;

    fn hex(bytes: [u8; 32]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn sha256_matches_standard_vectors() {
        assert_eq!(
            hex(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb924\
             27ae41e4649b934ca495991b7852b855"
                .replace(' ', "")
        );
        assert_eq!(
            hex(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223\
             b00361a396177a9cb410ff61f20015ad"
                .replace(' ', "")
        );
    }
}
