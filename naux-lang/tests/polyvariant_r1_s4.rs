use naux::core::{
    branch_mix_kernel_program, build_definitional_corevm0, certify_binding_time_b0d,
    corevm0_r1_s4_evidence_hash, emit_corevm0_r1_s4_evidence, evaluate,
    evaluate_definitional_corevm0, specialize_corevm0_r1_s4, specialize_polyvariant_r1_s4,
    specialize_polyvariant_r1_s4_with_control, validate_binding_time_b0_request,
    validate_specialization_r0a_request, verify, verify_corevm0_r1_s4_evidence, BindingTime,
    BindingTimeBudget, BindingTimeCertificate, BindingTimeRequest, CoreArtifact, CoreProfile,
    CoreValue, CoreVmOutcome, CoreVmProgram, CoreVmR1S4Evidence, CoreVmR1S4ReplayError, CoreVmType,
    CoreVmTypedError, CoreVmValue, Effect, EffectEvent, EffectRow, ErrorKind, EvaluationBudget,
    EvaluationOutcome, Function, FunctionId, LocalId, Mutability, Operand, Parameter,
    PolyvariantR1S4Budget, PolyvariantR1S4Control, PolyvariantR1S4Error, Primitive, Program,
    RValue, RegionId, SchemaVersion, SpecializationBudget, SpecializationRequest,
    SpecializationSlot, Term, Type, COREVM0_SCHEMA_VERSION, R1_S4_MAX_CONTROL_SPLITS_HARD_CAP,
    R1_S4_MAX_DYNAMIC_PARAMETERS_HARD_CAP, R1_S4_MAX_HELPER_UNFOLDS_HARD_CAP,
    R1_S4_MAX_PARTIAL_VALUE_NODES_HARD_CAP, R1_S4_MAX_RESIDUAL_BYTES_HARD_CAP,
    R1_S4_MAX_RESIDUAL_NODES_HARD_CAP, R1_S4_MAX_VARIANTS_HARD_CAP, R1_S4_MAX_WORK_UNITS_HARD_CAP,
};

fn array_type() -> Type {
    Type::Array {
        region: RegionId(0),
        mutability: Mutability::Read,
        element: Box::new(Type::F64),
    }
}

fn requests(
    artifact: &CoreArtifact,
    manifest: Vec<BindingTime>,
    slots: Vec<SpecializationSlot>,
) -> (
    BindingTimeRequest,
    BindingTimeCertificate,
    SpecializationRequest,
) {
    let binding = BindingTimeRequest::p1v0(
        artifact,
        manifest,
        BindingTimeBudget::new(1_000_000, 1_000_000, 10_000),
    )
    .expect("the R1-S4 B0 request must encode");
    let validated_binding = validate_binding_time_b0_request(artifact, &binding)
        .expect("the R1-S4 B0 request must validate");
    let certificate =
        certify_binding_time_b0d(&validated_binding).expect("the R1-S4 B0 certificate must emit");
    let specialization = SpecializationRequest::p1v0(
        artifact,
        &binding,
        &certificate,
        slots,
        SpecializationBudget::new(1_000_000, 1_000_000, 100_000_000, 1_000_000, 1_000_000_000),
    )
    .expect("the R1-S4 upstream request must encode");
    (binding, certificate, specialization)
}

fn generous_budget() -> PolyvariantR1S4Budget {
    PolyvariantR1S4Budget::new(
        100_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000_000,
    )
}

fn bounds_effects() -> EffectRow {
    EffectRow::canonical(vec![Effect::Error(ErrorKind::Bounds)])
}

fn seal(functions: Vec<Function>) -> CoreArtifact {
    CoreArtifact::seal(Program {
        schema: SchemaVersion::core_n0(),
        profile: CoreProfile::P1V0,
        entry: FunctionId(0),
        functions,
    })
    .expect("the R1-S4 fixture must encode")
}

fn flip_first_positive_zero(artifact: &mut CoreArtifact) -> bool {
    artifact
        .program
        .functions
        .iter_mut()
        .any(|function| flip_term_positive_zero(&mut function.body))
}

fn flip_term_positive_zero(term: &mut Term) -> bool {
    match term {
        Term::Let { value, next, .. } => {
            flip_rvalue_positive_zero(value) || flip_term_positive_zero(next)
        }
        Term::If {
            condition,
            then_term,
            else_term,
        } => {
            flip_operand_positive_zero(condition)
                || flip_term_positive_zero(then_term)
                || flip_term_positive_zero(else_term)
        }
        Term::Case { scrutinee, arms } => {
            flip_operand_positive_zero(scrutinee)
                || arms
                    .iter_mut()
                    .any(|arm| flip_term_positive_zero(&mut arm.body))
        }
        Term::TailCall { arguments, .. } => flip_operands_positive_zero(arguments),
        Term::Return(operand) => flip_operand_positive_zero(operand),
        Term::Region { body, .. } => flip_term_positive_zero(body),
        Term::Handle {
            captures,
            clauses,
            body,
            ..
        } => {
            flip_operands_positive_zero(captures)
                || clauses
                    .iter_mut()
                    .any(|clause| flip_term_positive_zero(&mut clause.body))
                || flip_term_positive_zero(body)
        }
    }
}

fn flip_rvalue_positive_zero(value: &mut RValue) -> bool {
    match value {
        RValue::Use(operand) => flip_operand_positive_zero(operand),
        RValue::Tuple(fields)
        | RValue::Construct { fields, .. }
        | RValue::Primitive {
            arguments: fields, ..
        }
        | RValue::Call {
            arguments: fields, ..
        }
        | RValue::PackClosure {
            captures: fields, ..
        }
        | RValue::Perform {
            arguments: fields, ..
        } => flip_operands_positive_zero(fields),
        RValue::Project { tuple, .. } => flip_operand_positive_zero(tuple),
        RValue::RefAlloc { value, .. } | RValue::RefLoad { reference: value } => {
            flip_operand_positive_zero(value)
        }
        RValue::RefStore { reference, value } => {
            flip_operand_positive_zero(reference) || flip_operand_positive_zero(value)
        }
        RValue::CallClosure { closure, arguments } => {
            flip_operand_positive_zero(closure) || flip_operands_positive_zero(arguments)
        }
    }
}

fn flip_operands_positive_zero(operands: &mut [Operand]) -> bool {
    operands.iter_mut().any(flip_operand_positive_zero)
}

fn flip_operand_positive_zero(operand: &mut Operand) -> bool {
    if matches!(operand, Operand::F64(value) if value.to_bits() == 0.0_f64.to_bits()) {
        *operand = Operand::F64(-0.0);
        true
    } else {
        false
    }
}

fn primitive(operation: Primitive, arguments: Vec<Operand>) -> RValue {
    RValue::Primitive {
        operation,
        arguments,
    }
}

fn budget_artifact() -> CoreArtifact {
    let get = |binder| Term::Let {
        binder,
        ty: Type::F64,
        value: primitive(
            Primitive::ArrayGetF64,
            vec![Operand::Local(LocalId(1)), Operand::Local(LocalId(3))],
        ),
        next: Box::new(Term::Return(Operand::Local(binder))),
    };
    seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![RegionId(0)],
            parameters: vec![
                Parameter {
                    local: LocalId(0),
                    ty: Type::Bool,
                },
                Parameter {
                    local: LocalId(1),
                    ty: array_type(),
                },
                Parameter {
                    local: LocalId(2),
                    ty: Type::I64,
                },
            ],
            effects: bounds_effects(),
            result: Type::F64,
            body: Term::Let {
                binder: LocalId(3),
                ty: Type::I64,
                value: RValue::Call {
                    function: FunctionId(1),
                    arguments: vec![Operand::Local(LocalId(2))],
                },
                next: Box::new(Term::If {
                    condition: Operand::Local(LocalId(0)),
                    then_term: Box::new(get(LocalId(4))),
                    else_term: Box::new(get(LocalId(5))),
                }),
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(0),
                ty: Type::I64,
            }],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Return(Operand::Local(LocalId(0))),
        },
    ])
}

fn specialize_budget_fixture(
    budget: PolyvariantR1S4Budget,
) -> Result<naux::core::PolyvariantR1S4Specialization, PolyvariantR1S4Error> {
    let artifact = budget_artifact();
    let (binding, certificate, request) = requests(
        &artifact,
        vec![
            BindingTime::Dynamic,
            BindingTime::Dynamic,
            BindingTime::Dynamic,
        ],
        vec![
            SpecializationSlot::Dynamic(Type::Bool),
            SpecializationSlot::Dynamic(array_type()),
            SpecializationSlot::Dynamic(Type::I64),
        ],
    );
    let validated =
        validate_specialization_r0a_request(&artifact, &binding, &certificate, &request)
            .expect("the budget fixture request must validate");
    specialize_polyvariant_r1_s4(&validated, budget)
}

#[test]
fn every_exact_s4_budget_passes_and_every_one_below_fails_closed() {
    let baseline =
        specialize_budget_fixture(generous_budget()).expect("the budget fixture must specialize");
    let usage = baseline.report().usage();
    let nodes = baseline.report().residual_nodes();
    let bytes = baseline.report().residual_bytes();
    assert_eq!(
        baseline.report().policy_hash().to_hex(),
        "d5320ad01a9ed44762575f7c44c0dc5d5b567f0b2b411bdece40ec864673e8ad"
    );
    assert_eq!(
        baseline.report().request_hash().to_hex(),
        "84562d7a59ce990d954dc0e429957e237f8f380fbf1efd6f919624dbb4bb9ac4"
    );
    assert_eq!(
        baseline.report().static_table_hash().to_hex(),
        "d4c22acdc02cdb4d5cd82b62b67fd42deef21c35fd8357a7aec21b7762abc4a6"
    );
    assert_eq!(
        baseline.report().summary_table_hash().to_hex(),
        "85be896774885a54795223cb40bed0388f251d20680bc5aa45ef8ec3d95a80df"
    );
    assert_eq!(
        baseline.report().variant_table_hash().to_hex(),
        "057cd1b777340c9a4258703c916643c5ab2b61f9db1df6f5ad295269c0280c6c"
    );
    assert_eq!(
        baseline.report().residual_hash().to_hex(),
        "72918bb40a2868a86a6df5a98d1518cf7141d9afb91d7b5e90fb84697bee3575"
    );
    assert_eq!(usage.work_units, 119);
    assert_eq!(usage.partial_value_nodes, 8);
    assert_eq!(usage.variants, 1);
    assert_eq!(usage.control_splits, 1);
    assert_eq!(usage.dynamic_parameters, 3);
    assert_eq!(usage.helper_unfolds, 1);
    assert_eq!(usage.static_interns, 0);
    assert_eq!(usage.summary_entries, 1);
    assert_eq!(usage.summary_hits, 0);
    assert_eq!(usage.widened_values, 0);
    assert_eq!(nodes, 14);
    assert_eq!(bytes, 157);
    let exact = PolyvariantR1S4Budget::new(
        usage.work_units,
        usage.partial_value_nodes,
        usage.variants,
        usage.control_splits,
        usage.dynamic_parameters,
        usage.helper_unfolds,
        nodes,
        bytes,
    );
    let reproduced =
        specialize_budget_fixture(exact).expect("all exact R1-S4 budgets must pass together");
    assert_eq!(reproduced.report().usage(), usage);
    assert_eq!(
        reproduced.report().residual_hash(),
        baseline.report().residual_hash()
    );

    let cases = [
        PolyvariantR1S4Budget::new(
            usage.work_units - 1,
            usage.partial_value_nodes,
            usage.variants,
            usage.control_splits,
            usage.dynamic_parameters,
            usage.helper_unfolds,
            nodes,
            bytes,
        ),
        PolyvariantR1S4Budget::new(
            usage.work_units,
            usage.partial_value_nodes - 1,
            usage.variants,
            usage.control_splits,
            usage.dynamic_parameters,
            usage.helper_unfolds,
            nodes,
            bytes,
        ),
        PolyvariantR1S4Budget::new(
            usage.work_units,
            usage.partial_value_nodes,
            usage.variants - 1,
            usage.control_splits,
            usage.dynamic_parameters,
            usage.helper_unfolds,
            nodes,
            bytes,
        ),
        PolyvariantR1S4Budget::new(
            usage.work_units,
            usage.partial_value_nodes,
            usage.variants,
            usage.control_splits - 1,
            usage.dynamic_parameters,
            usage.helper_unfolds,
            nodes,
            bytes,
        ),
        PolyvariantR1S4Budget::new(
            usage.work_units,
            usage.partial_value_nodes,
            usage.variants,
            usage.control_splits,
            usage.dynamic_parameters - 1,
            usage.helper_unfolds,
            nodes,
            bytes,
        ),
        PolyvariantR1S4Budget::new(
            usage.work_units,
            usage.partial_value_nodes,
            usage.variants,
            usage.control_splits,
            usage.dynamic_parameters,
            usage.helper_unfolds - 1,
            nodes,
            bytes,
        ),
        PolyvariantR1S4Budget::new(
            usage.work_units,
            usage.partial_value_nodes,
            usage.variants,
            usage.control_splits,
            usage.dynamic_parameters,
            usage.helper_unfolds,
            nodes - 1,
            bytes,
        ),
        PolyvariantR1S4Budget::new(
            usage.work_units,
            usage.partial_value_nodes,
            usage.variants,
            usage.control_splits,
            usage.dynamic_parameters,
            usage.helper_unfolds,
            nodes,
            bytes - 1,
        ),
    ];
    for budget in cases {
        assert!(
            specialize_budget_fixture(budget).is_err(),
            "one-below budget must fail closed"
        );
    }
}

#[test]
fn zero_and_hard_cap_checks_cover_all_eight_s4_budgets() {
    let fields = [
        ("max_work_units", R1_S4_MAX_WORK_UNITS_HARD_CAP),
        (
            "max_partial_value_nodes",
            R1_S4_MAX_PARTIAL_VALUE_NODES_HARD_CAP,
        ),
        ("max_variants", R1_S4_MAX_VARIANTS_HARD_CAP),
        ("max_control_splits", R1_S4_MAX_CONTROL_SPLITS_HARD_CAP),
        (
            "max_dynamic_parameters",
            R1_S4_MAX_DYNAMIC_PARAMETERS_HARD_CAP,
        ),
        ("max_helper_unfolds", R1_S4_MAX_HELPER_UNFOLDS_HARD_CAP),
        ("max_residual_nodes", R1_S4_MAX_RESIDUAL_NODES_HARD_CAP),
        ("max_residual_bytes", R1_S4_MAX_RESIDUAL_BYTES_HARD_CAP),
    ];
    for (index, (field, hard_cap)) in fields.into_iter().enumerate() {
        let mut limits = [1_u64, 1_u64, 1_u64, 1_u64, 1_u64, 1_u64, 1_u64, 1_u64];
        limits[index] = 0;
        assert_eq!(
            specialize_budget_fixture(PolyvariantR1S4Budget::new(
                limits[0], limits[1], limits[2], limits[3], limits[4], limits[5], limits[6],
                limits[7],
            )),
            Err(PolyvariantR1S4Error::ZeroBudget { field })
        );
        limits[index] = hard_cap + 1;
        assert!(matches!(
            specialize_budget_fixture(PolyvariantR1S4Budget::new(
                limits[0], limits[1], limits[2], limits[3], limits[4], limits[5], limits[6],
                limits[7],
            )),
            Err(PolyvariantR1S4Error::BudgetHardCapExceeded {
                field: actual,
                ..
            }) if actual == field
        ));
    }
}

#[test]
fn control_manifest_rejects_non_recursive_or_missing_parameters() {
    let artifact = budget_artifact();
    let (binding, certificate, request) = requests(
        &artifact,
        vec![
            BindingTime::Dynamic,
            BindingTime::Dynamic,
            BindingTime::Dynamic,
        ],
        vec![
            SpecializationSlot::Dynamic(Type::Bool),
            SpecializationSlot::Dynamic(array_type()),
            SpecializationSlot::Dynamic(Type::I64),
        ],
    );
    let validated =
        validate_specialization_r0a_request(&artifact, &binding, &certificate, &request)
            .expect("the control fixture request must validate");
    for control in [
        PolyvariantR1S4Control::from_pins([(FunctionId(1), 0)]),
        PolyvariantR1S4Control::from_pins([(FunctionId(99), 0)]),
    ] {
        assert!(matches!(
            specialize_polyvariant_r1_s4_with_control(&validated, generous_budget(), &control,),
            Err(PolyvariantR1S4Error::InvalidControlPin { .. })
        ));
    }
}

#[test]
fn bounds_microprogram_preserves_typed_error_and_effect_order() {
    use naux::core::CoreVmInstruction as I;

    let program = CoreVmProgram {
        schema_version: COREVM0_SCHEMA_VERSION,
        arguments: vec![CoreVmType::ArrayF64],
        locals: vec![],
        max_stack: 2,
        instructions: vec![I::LoadArg(0), I::ConstI64(0), I::ArrayGetF64, I::ReturnF64],
    };
    let bound = build_definitional_corevm0(&program).expect("the Bounds package must build");
    let (binding, certificate, request) = requests(
        bound.artifact(),
        vec![BindingTime::Static, BindingTime::Dynamic],
        vec![
            SpecializationSlot::Static(bound.program_image().clone()),
            SpecializationSlot::Dynamic(array_type()),
        ],
    );
    let validated =
        validate_specialization_r0a_request(bound.artifact(), &binding, &certificate, &request)
            .expect("the Bounds request must validate");
    let projected = specialize_corevm0_r1_s4(&bound, &validated, generous_budget())
        .expect("the Bounds package must cross R1-S4");
    assert!(projected.report().erasure().loop_variants() > 0);

    for values in [vec![], vec![3.25], vec![-0.0, f64::NAN]] {
        let source = evaluate_definitional_corevm0(
            &bound,
            vec![CoreVmValue::array_f64(values.clone())],
            EvaluationBudget::new(1_000_000, 256),
        )
        .expect("the source Bounds outcome must be typed");
        let residual = evaluate(
            projected.artifact(),
            vec![CoreValue::array_f64(values)],
            EvaluationBudget::new(1_000_000, 256),
        )
        .expect("the residual Bounds outcome must be typed");
        match source.outcome {
            CoreVmOutcome::ReturnF64(expected) => {
                let EvaluationOutcome::Return(CoreValue::F64(actual)) = residual.outcome else {
                    panic!("the Bounds residual must return F64");
                };
                if expected.is_nan() {
                    assert!(actual.is_nan());
                } else {
                    assert_eq!(actual.to_bits(), expected.to_bits());
                }
            }
            CoreVmOutcome::Error(CoreVmTypedError::Bounds) => {
                assert_eq!(
                    residual.outcome,
                    EvaluationOutcome::Error(ErrorKind::Bounds)
                );
            }
        }
        assert_eq!(
            residual.effect_trace,
            source
                .effect_trace
                .iter()
                .map(|effect| match effect {
                    CoreVmTypedError::Bounds => EffectEvent::Error(ErrorKind::Bounds),
                })
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn frozen_branch_mix_specializes_and_matches_the_definitional_source() {
    let program = branch_mix_kernel_program();
    let bound =
        build_definitional_corevm0(&program).expect("the frozen branch_mix package must build");
    let slots = vec![
        SpecializationSlot::Static(bound.program_image().clone()),
        SpecializationSlot::Dynamic(array_type()),
        SpecializationSlot::Dynamic(Type::I64),
    ];
    let (binding, certificate, request) = requests(
        bound.artifact(),
        vec![
            BindingTime::Static,
            BindingTime::Dynamic,
            BindingTime::Dynamic,
        ],
        slots,
    );
    let validated =
        validate_specialization_r0a_request(bound.artifact(), &binding, &certificate, &request)
            .expect("the frozen branch_mix request must validate");
    let projected = specialize_corevm0_r1_s4(&bound, &validated, generous_budget())
        .expect("the frozen branch_mix package must cross R1-S4");
    verify(projected.artifact()).expect("the R1-S4 residual must pass the ordinary verifier");
    assert_eq!(
        projected.report().artifact_hash().to_hex(),
        "9ef102a420024b350e46499c83de65244ad5e1f47e006922443ab8b4d4fe3abe"
    );
    assert_eq!(
        projected.report().program_hash().to_hex(),
        "9770cd0fb20fefaebba063674e02b1881173a817b73b9f910c9ba8e025a9b2d5"
    );
    assert_eq!(
        projected.report().program_image_hash().to_hex(),
        "732cc709778d757988b34b1efcf5c376b1b1443e6cebec3bb61375d1f8fa1142"
    );
    assert_eq!(
        projected.s4_report().policy_hash().to_hex(),
        "d5320ad01a9ed44762575f7c44c0dc5d5b567f0b2b411bdece40ec864673e8ad"
    );
    assert_eq!(
        projected.s4_report().request_hash().to_hex(),
        "e73aa7869e45df9a364eb3a9b985f9b2a2f32fc984aa2c8f65f0c0c4549944dd"
    );
    assert_eq!(
        projected.s4_report().control_hash().to_hex(),
        "f98faa10987f044206e09b271de2e97654d9a1b58d914c12593b8016f12bc92a"
    );
    assert_eq!(
        projected.s4_report().static_table_hash().to_hex(),
        "47241ddfe7888c870518a0e07b0738218ec8060ce77550f652909249c9410956"
    );
    assert_eq!(
        projected.s4_report().summary_table_hash().to_hex(),
        "6f99ab66dd2c84d30b903747e022b8297e479af58ef033ca8206deb881c379d0"
    );
    assert_eq!(
        projected.s4_report().variant_table_hash().to_hex(),
        "195fcb9713e6f11675bfe681ff791da9e61806ed66e596784010c8320213a476"
    );
    assert_eq!(
        projected.s4_report().residual_hash().to_hex(),
        "fd90f6b16813a851aea7b1151a2df9ad87f9a9bfb8e994a5797407700f9fb2e9"
    );
    let usage = projected.s4_report().usage();
    assert_eq!(usage.work_units, 234_073);
    assert_eq!(usage.partial_value_nodes, 8_227);
    assert_eq!(usage.variants, 121);
    assert_eq!(usage.control_splits, 9);
    assert_eq!(usage.dynamic_parameters, 1_085);
    assert_eq!(usage.helper_unfolds, 134);
    assert_eq!(usage.static_interns, 93);
    assert_eq!(usage.summary_entries, 134);
    assert_eq!(usage.summary_hits, 199);
    assert_eq!(usage.widened_values, 1_151);
    assert_eq!(projected.s4_report().residual_nodes(), 1_391);
    assert_eq!(projected.s4_report().residual_bytes(), 16_575);
    assert_eq!(
        projected
            .s4_report()
            .variants()
            .iter()
            .filter(|variant| variant.source_function() == FunctionId(0))
            .count(),
        1
    );
    assert!(projected
        .s4_report()
        .variants()
        .iter()
        .all(|variant| matches!(variant.source_function(), FunctionId(0) | FunctionId(1))));

    for (values, repetitions) in [
        (vec![], -1),
        (vec![], 0),
        (vec![1.0], 1),
        (vec![0.0, -0.0], 2),
        (vec![f64::NAN, 1.0], 1),
        (vec![f64::INFINITY, f64::NEG_INFINITY], 1),
        (vec![-1.0, 0.0, 1.0], 3),
    ] {
        let source = evaluate_definitional_corevm0(
            &bound,
            vec![
                CoreVmValue::array_f64(values.clone()),
                CoreVmValue::I64(repetitions),
            ],
            EvaluationBudget::new(10_000_000, 256),
        )
        .expect("the definitional source must complete");
        let residual = evaluate(
            projected.artifact(),
            vec![CoreValue::array_f64(values), CoreValue::I64(repetitions)],
            EvaluationBudget::new(10_000_000, 256),
        )
        .expect("the R1-S4 residual must complete");
        match source.outcome {
            CoreVmOutcome::ReturnF64(expected) => {
                let EvaluationOutcome::Return(CoreValue::F64(actual)) = residual.outcome else {
                    panic!("the R1-S4 residual must return F64");
                };
                if expected.is_nan() {
                    assert!(actual.is_nan());
                } else {
                    assert_eq!(actual.to_bits(), expected.to_bits());
                }
            }
            CoreVmOutcome::Error(CoreVmTypedError::Bounds) => {
                assert_eq!(
                    residual.outcome,
                    EvaluationOutcome::Error(ErrorKind::Bounds)
                );
            }
        }
        assert_eq!(
            residual.effect_trace,
            source
                .effect_trace
                .iter()
                .map(|effect| match effect {
                    CoreVmTypedError::Bounds => EffectEvent::Error(ErrorKind::Bounds),
                })
                .collect::<Vec<_>>()
        );
    }

    let erasure = projected.report().erasure();
    assert_eq!(erasure.residual_functions(), 121);
    assert_eq!(erasure.loop_variants(), 120);
    assert!(projected.s4_report().usage().static_interns > 0);
    assert!(projected.s4_report().usage().summary_entries > 0);
    assert!(projected.s4_report().usage().summary_hits > 0);
    assert!(projected.s4_report().usage().widened_values > 0);

    let evidence = emit_corevm0_r1_s4_evidence(&projected);
    assert_eq!(
        projected.report().binding_hash().to_hex(),
        "49e9cdf6620f0997c0ae62bedac481509bfc5229c045753a9384ec62005a2d2c"
    );
    assert_eq!(
        erasure.erasure_hash().to_hex(),
        "a100096fbfc49ccb367d9f5207f8f9fcff64205b7d64d32c98ec3621bccb4176"
    );
    assert_eq!(
        evidence.evidence_hash.to_hex(),
        "8d648c021a3c806d76790e49ae8655ee59f2e97427800827db91577c90d64896"
    );
    assert_eq!(erasure.residual_nodes_scanned(), 185);
    assert_eq!(erasure.residual_calls(), 0);
    assert_eq!(erasure.residual_tail_calls(), 127);
    assert_eq!(erasure.residual_ifs(), 9);
    let replayed = verify_corevm0_r1_s4_evidence(
        &program,
        &binding,
        &certificate,
        &request,
        generous_budget(),
        projected.artifact(),
        &evidence,
    )
    .expect("raw-input replay must regenerate the exact branch_mix residual");
    assert_eq!(replayed.artifact(), projected.artifact());

    let mut stale_signed_zero = projected.artifact().clone();
    assert!(
        flip_first_positive_zero(&mut stale_signed_zero),
        "the frozen residual must contain a positive-zero literal"
    );
    assert_eq!(
        stale_signed_zero,
        projected.artifact().clone(),
        "derived float equality is the regression precondition"
    );
    assert!(matches!(
        verify_corevm0_r1_s4_evidence(
            &program,
            &binding,
            &certificate,
            &request,
            generous_budget(),
            &stale_signed_zero,
            &evidence,
        ),
        Err(CoreVmR1S4ReplayError::ResidualMismatch)
    ));

    let mutations: Vec<fn(&mut CoreVmR1S4Evidence)> = vec![
        |value| value.schema_version.0 ^= 1,
        |value| value.replay_version.0 ^= 1,
        |value| value.binding_version.0 ^= 1,
        |value| value.construction_version.0 ^= 1,
        |value| value.s4_policy_version.0 ^= 1,
        |value| value.erasure_version.0 ^= 1,
        |value| value.core_interpreter_semantics_hash.0[0] ^= 1,
        |value| value.artifact_hash.0[0] ^= 1,
        |value| value.program_hash.0[0] ^= 1,
        |value| value.program_image_hash.0[0] ^= 1,
        |value| value.binding_time_request_hash.0[0] ^= 1,
        |value| value.binding_time_certificate_hash.0[0] ^= 1,
        |value| value.upstream_request_hash.0[0] ^= 1,
        |value| value.s4_policy_hash.0[0] ^= 1,
        |value| value.s4_request_hash.0[0] ^= 1,
        |value| value.control_hash.0[0] ^= 1,
        |value| value.static_table_hash.0[0] ^= 1,
        |value| value.summary_table_hash.0[0] ^= 1,
        |value| value.variant_table_hash.0[0] ^= 1,
        |value| value.residual_hash.0[0] ^= 1,
        |value| value.binding_hash.0[0] ^= 1,
        |value| value.erasure_hash.0[0] ^= 1,
        |value| value.budget.max_work_units ^= 1,
        |value| value.budget.max_partial_value_nodes ^= 1,
        |value| value.budget.max_variants ^= 1,
        |value| value.budget.max_control_splits ^= 1,
        |value| value.budget.max_dynamic_parameters ^= 1,
        |value| value.budget.max_helper_unfolds ^= 1,
        |value| value.budget.max_residual_nodes ^= 1,
        |value| value.budget.max_residual_bytes ^= 1,
        |value| value.usage.work_units ^= 1,
        |value| value.usage.partial_value_nodes ^= 1,
        |value| value.usage.variants ^= 1,
        |value| value.usage.control_splits ^= 1,
        |value| value.usage.dynamic_parameters ^= 1,
        |value| value.usage.helper_unfolds ^= 1,
        |value| value.usage.static_interns ^= 1,
        |value| value.usage.summary_entries ^= 1,
        |value| value.usage.summary_hits ^= 1,
        |value| value.usage.widened_values ^= 1,
        |value| value.residual_nodes ^= 1,
        |value| value.residual_bytes ^= 1,
        |value| value.residual_functions ^= 1,
        |value| value.loop_variants ^= 1,
        |value| value.residual_nodes_scanned ^= 1,
        |value| value.residual_calls ^= 1,
        |value| value.residual_tail_calls ^= 1,
        |value| value.residual_ifs ^= 1,
        |value| value.evidence_hash.0[0] ^= 1,
    ];
    for mutate in mutations {
        let mut unsealed = evidence.clone();
        mutate(&mut unsealed);
        assert!(matches!(
            verify_corevm0_r1_s4_evidence(
                &program,
                &binding,
                &certificate,
                &request,
                generous_budget(),
                projected.artifact(),
                &unsealed,
            ),
            Err(CoreVmR1S4ReplayError::InvalidEvidenceHash)
        ));
    }

    let mut resealed = evidence.clone();
    resealed.program_hash.0[0] ^= 1;
    resealed.evidence_hash = corevm0_r1_s4_evidence_hash(&resealed);
    assert!(matches!(
        verify_corevm0_r1_s4_evidence(
            &program,
            &binding,
            &certificate,
            &request,
            generous_budget(),
            projected.artifact(),
            &resealed,
        ),
        Err(CoreVmR1S4ReplayError::EvidenceMismatch)
    ));

    let mut changed_program: CoreVmProgram = program.clone();
    changed_program.instructions[0] = naux::core::CoreVmInstruction::ConstI64(1);
    assert!(matches!(
        verify_corevm0_r1_s4_evidence(
            &changed_program,
            &binding,
            &certificate,
            &request,
            generous_budget(),
            projected.artifact(),
            &evidence,
        ),
        Err(CoreVmR1S4ReplayError::EvidenceMismatch)
    ));
}
