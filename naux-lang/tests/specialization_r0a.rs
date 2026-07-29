use naux::core::{
    binding_time_request_hash, certify_binding_time_b0d, specialization_policy_bytes,
    specialization_policy_hash, specialization_request_bytes, specialization_request_hash,
    specialization_value_bytes, specialization_value_hash, validate_binding_time_b0_request,
    validate_specialization_r0a_request, BindingTime, BindingTimeBudget, BindingTimeCertificate,
    BindingTimeRequest, ConstructorType, CoreArtifact, CoreProfile, EffectRow, Function,
    FunctionId, LocalId, Mutability, Operand, Parameter, Program, RegionId, SemanticHash,
    SpecializationBudget, SpecializationRequest, SpecializationRequestCode, SpecializationSlot,
    SpecializationValue, SumType, Term, Type, R0_MAX_RESIDUAL_BYTES_HARD_CAP,
    R0_MAX_RESIDUAL_NODES_HARD_CAP, R0_MAX_SPECIALIZATION_STEPS_HARD_CAP,
    R0_MAX_STATIC_ARRAY_ELEMENTS_HARD_CAP, R0_MAX_STATIC_VALUE_NODES_HARD_CAP,
};

fn seal(functions: Vec<Function>) -> CoreArtifact {
    CoreArtifact::seal(Program {
        schema: naux::core::SchemaVersion::core_n0(),
        profile: CoreProfile::P1V0,
        entry: FunctionId(0),
        functions,
    })
    .expect("test program must encode")
}

fn scalar_program() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![
            Parameter {
                local: LocalId(0),
                ty: Type::I64,
            },
            Parameter {
                local: LocalId(1),
                ty: Type::F64,
            },
        ],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Return(Operand::Local(LocalId(0))),
    }])
}

fn b0(
    artifact: &CoreArtifact,
    manifest: Vec<BindingTime>,
) -> (BindingTimeRequest, BindingTimeCertificate) {
    let request =
        BindingTimeRequest::p1v0(artifact, manifest, BindingTimeBudget::new(1_000, 100, 20))
            .expect("B0 request must encode");
    let validated =
        validate_binding_time_b0_request(artifact, &request).expect("B0 request must validate");
    let certificate = certify_binding_time_b0d(&validated).expect("B0 certificate must emit");
    (request, certificate)
}

fn budget() -> SpecializationBudget {
    SpecializationBudget::new(100, 100, 10_000, 1_000, 1_000_000)
}

fn scalar_boundary() -> (
    CoreArtifact,
    BindingTimeRequest,
    BindingTimeCertificate,
    SpecializationRequest,
) {
    let artifact = scalar_program();
    let (binding_time_request, certificate) =
        b0(&artifact, vec![BindingTime::Static, BindingTime::Dynamic]);
    let request = SpecializationRequest::p1v0(
        &artifact,
        &binding_time_request,
        &certificate,
        vec![
            SpecializationSlot::Static(SpecializationValue::I64(7)),
            SpecializationSlot::Dynamic(Type::F64),
        ],
        budget(),
    )
    .expect("R0-A request must encode");
    (artifact, binding_time_request, certificate, request)
}

fn assert_rejected(
    artifact: &CoreArtifact,
    binding_time_request: &BindingTimeRequest,
    certificate: &BindingTimeCertificate,
    request: &SpecializationRequest,
    code: SpecializationRequestCode,
) {
    let errors =
        validate_specialization_r0a_request(artifact, binding_time_request, certificate, request)
            .expect_err("forged R0-A request must fail closed");
    assert!(
        errors.0.iter().any(|error| error.code == code),
        "expected {code:?}, found {:?}",
        errors.0
    );
}

#[test]
fn specialization_value_encoding_is_domain_separated_and_numeric_exact() {
    let value = SpecializationValue::Tuple(vec![
        SpecializationValue::I64(7),
        SpecializationValue::F64(-0.0),
        SpecializationValue::ArrayF64(vec![1.5, f64::NAN]),
    ]);
    let bytes = specialization_value_bytes(&value).expect("value must encode");
    assert!(bytes.starts_with(b"NAUX:core-n0:specialization-value:r0:v1\0"));
    assert_eq!(
        specialization_value_hash(&value)
            .expect("value must hash")
            .to_hex(),
        "a06da2023df1cafbf7e214af56848587a5e2fa6f134f6527da06d1416f2282a8"
    );

    let nan_a = SpecializationValue::F64(f64::from_bits(0x7ff8_0000_0000_0001));
    let nan_b = SpecializationValue::F64(f64::from_bits(0x7fff_ffff_ffff_ffff));
    assert_eq!(
        specialization_value_bytes(&nan_a).expect("NaN must encode"),
        specialization_value_bytes(&nan_b).expect("NaN must encode")
    );
    assert_ne!(
        specialization_value_bytes(&SpecializationValue::F64(0.0)).expect("zero must encode"),
        specialization_value_bytes(&SpecializationValue::F64(-0.0))
            .expect("negative zero must encode")
    );
}

#[test]
fn canonical_policy_and_mixed_request_validate_with_locked_vectors() {
    let (artifact, binding_time_request, certificate, request) = scalar_boundary();
    let policy_bytes = specialization_policy_bytes().expect("policy must encode");
    let request_bytes = specialization_request_bytes(&request).expect("request must encode");
    assert_eq!(policy_bytes.len(), 404);
    assert_eq!(request_bytes.len(), 356);
    assert!(policy_bytes.starts_with(b"NAUX:core-n0:specialization-policy:r0:v1\0"));
    assert!(request_bytes.starts_with(b"NAUX:core-n0:specialization-request:r0:v1\0"));
    assert_eq!(
        specialization_policy_hash()
            .expect("policy must hash")
            .to_hex(),
        "f4bb6684d043f693229140f200deb1bcee04f147ef92cb88fd07421c7ae6c1c7"
    );
    assert_eq!(
        specialization_request_hash(&request)
            .expect("request must hash")
            .to_hex(),
        "d2735a25744b9087ee1efd18f2182c78d4bf831eae1bb274bb9ebeca5e640b44"
    );

    let validated = validate_specialization_r0a_request(
        &artifact,
        &binding_time_request,
        &certificate,
        &request,
    )
    .expect("canonical R0-A request must validate");
    assert_eq!(
        validated.request_hash(),
        specialization_request_hash(&request).expect("request must hash")
    );
    assert_eq!(
        validated.artifact().semantic_hash,
        artifact.semantic_hash,
        "validated boundary must retain its exact source artifact"
    );
    assert_eq!(validated.request(), &request);
    assert_eq!(
        validated.certificate().certificate().certificate_hash,
        certificate.certificate_hash
    );
}

#[test]
fn every_provenance_policy_and_entry_field_is_verified() {
    let (artifact, binding_time_request, certificate, request) = scalar_boundary();
    let mutations = [
        (
            {
                let mut value = request.clone();
                value.schema_version.0 += 1;
                value
            },
            SpecializationRequestCode::UnsupportedRequestSchema,
        ),
        (
            {
                let mut value = request.clone();
                value.source_program_hash.0[0] ^= 1;
                value
            },
            SpecializationRequestCode::SourceProgramHashMismatch,
        ),
        (
            {
                let mut value = request.clone();
                value.interpreter_semantics_hash.0[0] ^= 1;
                value
            },
            SpecializationRequestCode::InterpreterSemanticsHashMismatch,
        ),
        (
            {
                let mut value = request.clone();
                value.binding_time_policy_version.0 += 1;
                value
            },
            SpecializationRequestCode::BindingTimePolicyVersionMismatch,
        ),
        (
            {
                let mut value = request.clone();
                value.binding_time_policy_hash.0[0] ^= 1;
                value
            },
            SpecializationRequestCode::BindingTimePolicyHashMismatch,
        ),
        (
            {
                let mut value = request.clone();
                value.binding_time_request_hash.0[0] ^= 1;
                value
            },
            SpecializationRequestCode::BindingTimeRequestHashMismatch,
        ),
        (
            {
                let mut value = request.clone();
                value.binding_time_certificate_hash.0[0] ^= 1;
                value
            },
            SpecializationRequestCode::BindingTimeCertificateHashMismatch,
        ),
        (
            {
                let mut value = request.clone();
                value.policy_version.0 += 1;
                value
            },
            SpecializationRequestCode::UnsupportedPolicyVersion,
        ),
        (
            {
                let mut value = request.clone();
                value.policy_hash.0[0] ^= 1;
                value
            },
            SpecializationRequestCode::PolicyHashMismatch,
        ),
        (
            {
                let mut value = request.clone();
                value.entry_function = FunctionId(1);
                value
            },
            SpecializationRequestCode::EntryFunctionMismatch,
        ),
    ];
    for (forged, code) in mutations {
        assert_rejected(
            &artifact,
            &binding_time_request,
            &certificate,
            &forged,
            code,
        );
    }
}

#[test]
fn invalid_b0_certificate_is_rejected_before_r0_fields_are_trusted() {
    let (artifact, binding_time_request, mut certificate, request) = scalar_boundary();
    certificate.certificate_hash = SemanticHash::ZERO;
    assert_rejected(
        &artifact,
        &binding_time_request,
        &certificate,
        &request,
        SpecializationRequestCode::InvalidBindingTimeCertificate,
    );
}

#[test]
fn slot_arity_binding_time_kind_and_dynamic_type_are_exact() {
    let (artifact, binding_time_request, certificate, request) = scalar_boundary();

    let mut missing = request.clone();
    missing.entry_slots.pop();
    assert_rejected(
        &artifact,
        &binding_time_request,
        &certificate,
        &missing,
        SpecializationRequestCode::EntrySlotArity,
    );

    let mut static_as_dynamic = request.clone();
    static_as_dynamic.entry_slots[0] = SpecializationSlot::Dynamic(Type::I64);
    assert_rejected(
        &artifact,
        &binding_time_request,
        &certificate,
        &static_as_dynamic,
        SpecializationRequestCode::StaticDynamicMismatch,
    );

    let mut dynamic_as_static = request.clone();
    dynamic_as_static.entry_slots[1] = SpecializationSlot::Static(SpecializationValue::F64(1.0));
    assert_rejected(
        &artifact,
        &binding_time_request,
        &certificate,
        &dynamic_as_static,
        SpecializationRequestCode::StaticDynamicMismatch,
    );

    let mut wrong_dynamic_type = request.clone();
    wrong_dynamic_type.entry_slots[1] = SpecializationSlot::Dynamic(Type::Bool);
    assert_rejected(
        &artifact,
        &binding_time_request,
        &certificate,
        &wrong_dynamic_type,
        SpecializationRequestCode::DynamicTypeMismatch,
    );

    let mut wrong_static_type = request;
    wrong_static_type.entry_slots[0] = SpecializationSlot::Static(SpecializationValue::Bool(true));
    assert_rejected(
        &artifact,
        &binding_time_request,
        &certificate,
        &wrong_static_type,
        SpecializationRequestCode::StaticValueTypeMismatch,
    );
}

fn composite_boundary() -> (
    CoreArtifact,
    BindingTimeRequest,
    BindingTimeCertificate,
    SpecializationRequest,
) {
    let option = SumType {
        name: "OptionI64".to_owned(),
        constructors: vec![
            ConstructorType {
                name: "None".to_owned(),
                fields: vec![],
            },
            ConstructorType {
                name: "Some".to_owned(),
                fields: vec![Type::I64],
            },
        ],
    };
    let array_type = Type::Array {
        region: RegionId(0),
        mutability: Mutability::Read,
        element: Box::new(Type::F64),
    };
    let artifact = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![RegionId(0)],
        parameters: vec![
            Parameter {
                local: LocalId(0),
                ty: Type::Tuple(vec![Type::I64, Type::Bool]),
            },
            Parameter {
                local: LocalId(1),
                ty: Type::Sum(option.clone()),
            },
            Parameter {
                local: LocalId(2),
                ty: array_type,
            },
        ],
        effects: EffectRow::pure(),
        result: Type::Unit,
        body: Term::Return(Operand::Unit),
    }]);
    let (binding_time_request, certificate) = b0(
        &artifact,
        vec![
            BindingTime::Static,
            BindingTime::Static,
            BindingTime::Static,
        ],
    );
    let request = SpecializationRequest::p1v0(
        &artifact,
        &binding_time_request,
        &certificate,
        vec![
            SpecializationSlot::Static(SpecializationValue::Tuple(vec![
                SpecializationValue::I64(3),
                SpecializationValue::Bool(true),
            ])),
            SpecializationSlot::Static(SpecializationValue::Sum {
                ty: option,
                constructor: 1,
                fields: vec![SpecializationValue::I64(9)],
            }),
            SpecializationSlot::Static(SpecializationValue::ArrayF64(vec![1.0, 2.0, 3.0])),
        ],
        SpecializationBudget::new(6, 3, 100, 100, 10_000),
    )
    .expect("composite request must encode");
    (artifact, binding_time_request, certificate, request)
}

#[test]
fn tuple_sum_and_read_array_values_are_recursively_typed() {
    let (artifact, binding_time_request, certificate, request) = composite_boundary();
    validate_specialization_r0a_request(&artifact, &binding_time_request, &certificate, &request)
        .expect("exact composite values and budgets must pass");

    let mut tuple = request.clone();
    tuple.entry_slots[0] =
        SpecializationSlot::Static(SpecializationValue::Tuple(vec![SpecializationValue::I64(
            3,
        )]));
    assert_rejected(
        &artifact,
        &binding_time_request,
        &certificate,
        &tuple,
        SpecializationRequestCode::StaticValueTypeMismatch,
    );

    let mut tuple_field = request.clone();
    tuple_field.entry_slots[0] = SpecializationSlot::Static(SpecializationValue::Tuple(vec![
        SpecializationValue::Bool(true),
        SpecializationValue::Bool(true),
    ]));
    assert_rejected(
        &artifact,
        &binding_time_request,
        &certificate,
        &tuple_field,
        SpecializationRequestCode::StaticValueTypeMismatch,
    );

    let mut sum_type = request.clone();
    if let SpecializationSlot::Static(SpecializationValue::Sum { ty, .. }) =
        &mut sum_type.entry_slots[1]
    {
        ty.name.push_str("Forged");
    }
    assert_rejected(
        &artifact,
        &binding_time_request,
        &certificate,
        &sum_type,
        SpecializationRequestCode::StaticValueTypeMismatch,
    );

    let mut sum = request.clone();
    if let SpecializationSlot::Static(SpecializationValue::Sum { constructor, .. }) =
        &mut sum.entry_slots[1]
    {
        *constructor = 99;
    }
    assert_rejected(
        &artifact,
        &binding_time_request,
        &certificate,
        &sum,
        SpecializationRequestCode::StaticValueTypeMismatch,
    );

    let mut sum_field = request.clone();
    if let SpecializationSlot::Static(SpecializationValue::Sum { fields, .. }) =
        &mut sum_field.entry_slots[1]
    {
        fields[0] = SpecializationValue::Bool(false);
    }
    assert_rejected(
        &artifact,
        &binding_time_request,
        &certificate,
        &sum_field,
        SpecializationRequestCode::StaticValueTypeMismatch,
    );

    let mut array = request;
    array.entry_slots[2] = SpecializationSlot::Static(SpecializationValue::I64(3));
    assert_rejected(
        &artifact,
        &binding_time_request,
        &certificate,
        &array,
        SpecializationRequestCode::StaticValueTypeMismatch,
    );
}

#[test]
fn value_array_and_all_declared_work_budgets_are_fail_closed() {
    let (artifact, binding_time_request, certificate, request) = composite_boundary();

    let mut node_limit = request.clone();
    node_limit.budget.max_static_value_nodes = 5;
    assert_rejected(
        &artifact,
        &binding_time_request,
        &certificate,
        &node_limit,
        SpecializationRequestCode::StaticValueBudgetExceeded,
    );

    let mut array_limit = request.clone();
    array_limit.budget.max_static_array_elements = 2;
    assert_rejected(
        &artifact,
        &binding_time_request,
        &certificate,
        &array_limit,
        SpecializationRequestCode::StaticArrayBudgetExceeded,
    );

    for zeroed in [
        {
            let mut value = request.clone();
            value.budget.max_static_value_nodes = 0;
            value
        },
        {
            let mut value = request.clone();
            value.budget.max_static_array_elements = 0;
            value
        },
        {
            let mut value = request.clone();
            value.budget.max_specialization_steps = 0;
            value
        },
        {
            let mut value = request.clone();
            value.budget.max_residual_nodes = 0;
            value
        },
        {
            let mut value = request.clone();
            value.budget.max_residual_bytes = 0;
            value
        },
    ] {
        assert_rejected(
            &artifact,
            &binding_time_request,
            &certificate,
            &zeroed,
            SpecializationRequestCode::ZeroBudget,
        );
    }

    for over_cap in [
        {
            let mut value = request.clone();
            value.budget.max_static_value_nodes = R0_MAX_STATIC_VALUE_NODES_HARD_CAP + 1;
            value
        },
        {
            let mut value = request.clone();
            value.budget.max_static_array_elements = R0_MAX_STATIC_ARRAY_ELEMENTS_HARD_CAP + 1;
            value
        },
        {
            let mut value = request.clone();
            value.budget.max_specialization_steps = R0_MAX_SPECIALIZATION_STEPS_HARD_CAP + 1;
            value
        },
        {
            let mut value = request.clone();
            value.budget.max_residual_nodes = R0_MAX_RESIDUAL_NODES_HARD_CAP + 1;
            value
        },
        {
            let mut value = request;
            value.budget.max_residual_bytes = R0_MAX_RESIDUAL_BYTES_HARD_CAP + 1;
            value
        },
    ] {
        assert_rejected(
            &artifact,
            &binding_time_request,
            &certificate,
            &over_cap,
            SpecializationRequestCode::BudgetHardCapExceeded,
        );
    }
}

#[test]
fn request_identity_covers_static_facts_b0_identity_and_every_budget() {
    let (_, binding_time_request, certificate, request) = scalar_boundary();
    assert_eq!(
        request.binding_time_request_hash,
        binding_time_request_hash(&binding_time_request).expect("B0 request must hash")
    );
    assert_eq!(
        request.binding_time_certificate_hash,
        certificate.certificate_hash
    );
    let baseline = specialization_request_hash(&request).expect("request must hash");
    let mutations = [
        {
            let mut value = request.clone();
            value.entry_slots[0] = SpecializationSlot::Static(SpecializationValue::I64(8));
            value
        },
        {
            let mut value = request.clone();
            value.budget.max_static_value_nodes += 1;
            value
        },
        {
            let mut value = request.clone();
            value.budget.max_static_array_elements += 1;
            value
        },
        {
            let mut value = request.clone();
            value.budget.max_specialization_steps += 1;
            value
        },
        {
            let mut value = request.clone();
            value.budget.max_residual_nodes += 1;
            value
        },
        {
            let mut value = request.clone();
            value.budget.max_residual_bytes += 1;
            value
        },
    ];
    for mutation in mutations {
        assert_ne!(
            specialization_request_hash(&mutation).expect("mutation must hash"),
            baseline
        );
    }
}
