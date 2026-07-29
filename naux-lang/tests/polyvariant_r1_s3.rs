use naux::core::{
    build_definitional_corevm0, certify_binding_time_b0d, evaluate, evaluate_definitional_corevm0,
    specialize_corevm0_r1_s3, specialize_polyvariant_r1_s3, validate_binding_time_b0_request,
    validate_specialization_r0a_request, verify, BindingTime, BindingTimeBudget,
    BindingTimeCertificate, BindingTimeRequest, CaseArm, ConstructorType, CoreArtifact,
    CoreProfile, CoreValue, CoreVmInstruction, CoreVmOutcome, CoreVmProgram, CoreVmR1S3Error,
    CoreVmType, CoreVmTypedError, CoreVmValue, Effect, EffectEvent, EffectRow, ErrorKind,
    Evaluation, EvaluationBudget, EvaluationOutcome, Function, FunctionId, LocalId, Mutability,
    NumericMode, Operand, Parameter, PolyvariantR1S3Budget, PolyvariantR1S3Error,
    PolyvariantR1S3Specialization, Primitive, Program, RValue, RegionId, SpecializationBudget,
    SpecializationRequest, SpecializationSlot, SumType, Term, Type, COREVM0_SCHEMA_VERSION,
    R1_S3_MAX_CONTROL_SPLITS_HARD_CAP, R1_S3_MAX_DYNAMIC_PARAMETERS_HARD_CAP,
    R1_S3_MAX_HELPER_UNFOLDS_HARD_CAP, R1_S3_MAX_PARTIAL_VALUE_NODES_HARD_CAP,
    R1_S3_MAX_RESIDUAL_BYTES_HARD_CAP, R1_S3_MAX_RESIDUAL_NODES_HARD_CAP,
    R1_S3_MAX_VARIANTS_HARD_CAP, R1_S3_MAX_WORK_UNITS_HARD_CAP,
};

fn array_type(region: RegionId) -> Type {
    Type::Array {
        region,
        mutability: Mutability::Read,
        element: Box::new(Type::F64),
    }
}

fn bounds_effects() -> EffectRow {
    EffectRow::canonical(vec![Effect::Error(ErrorKind::Bounds)])
}

fn seal(functions: Vec<Function>) -> CoreArtifact {
    CoreArtifact::seal(Program {
        schema: naux::core::SchemaVersion::core_n0(),
        profile: CoreProfile::P1V0,
        entry: FunctionId(0),
        functions,
    })
    .expect("the R1-S3 fixture must encode")
}

fn primitive(operation: Primitive, arguments: Vec<Operand>) -> RValue {
    RValue::Primitive {
        operation,
        arguments,
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
    .expect("the R1-S3 B0 request must encode");
    let validated_binding = validate_binding_time_b0_request(artifact, &binding)
        .expect("the R1-S3 B0 request must validate");
    let certificate =
        certify_binding_time_b0d(&validated_binding).expect("the R1-S3 B0 certificate must emit");
    let specialization = SpecializationRequest::p1v0(
        artifact,
        &binding,
        &certificate,
        slots,
        SpecializationBudget::new(1_000_000, 1_000_000, 100_000_000, 1_000_000, 1_000_000_000),
    )
    .expect("the R1-S3 upstream request must encode");
    validate_specialization_r0a_request(artifact, &binding, &certificate, &specialization)
        .expect("the R1-S3 upstream request must validate");
    (binding, certificate, specialization)
}

fn specialize(
    artifact: &CoreArtifact,
    manifest: Vec<BindingTime>,
    slots: Vec<SpecializationSlot>,
    budget: PolyvariantR1S3Budget,
) -> Result<PolyvariantR1S3Specialization, PolyvariantR1S3Error> {
    let (binding, certificate, request) = requests(artifact, manifest, slots);
    let validated = validate_specialization_r0a_request(artifact, &binding, &certificate, &request)
        .expect("the R1-S3 validated envelope must remain valid");
    specialize_polyvariant_r1_s3(&validated, budget)
}

fn generous_budget() -> PolyvariantR1S3Budget {
    PolyvariantR1S3Budget::new(
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

fn run(artifact: &CoreArtifact, arguments: Vec<CoreValue>) -> Evaluation {
    evaluate(artifact, arguments, EvaluationBudget::new(10_000_000, 256))
        .expect("the verified R1-S3 fixture must evaluate")
}

fn array_get_artifact() -> CoreArtifact {
    let region = RegionId(0);
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![region],
        parameters: vec![
            Parameter {
                local: LocalId(0),
                ty: array_type(region),
            },
            Parameter {
                local: LocalId(1),
                ty: Type::I64,
            },
        ],
        effects: bounds_effects(),
        result: Type::F64,
        body: Term::Let {
            binder: LocalId(2),
            ty: Type::F64,
            value: primitive(
                Primitive::ArrayGetF64,
                vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(1))],
            ),
            next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
        },
    }])
}

fn array_len_artifact() -> CoreArtifact {
    let region = RegionId(0);
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![region],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: array_type(region),
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(1),
            ty: Type::I64,
            value: primitive(Primitive::ArrayLenF64, vec![Operand::Local(LocalId(0))]),
            next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
        },
    }])
}

fn effectful_helper_artifact() -> CoreArtifact {
    let region = RegionId(0);
    seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![region],
            parameters: vec![
                Parameter {
                    local: LocalId(0),
                    ty: array_type(region),
                },
                Parameter {
                    local: LocalId(1),
                    ty: Type::I64,
                },
            ],
            effects: bounds_effects(),
            result: Type::F64,
            body: Term::Let {
                binder: LocalId(2),
                ty: Type::F64,
                value: RValue::Call {
                    function: FunctionId(1),
                    arguments: vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(1))],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![region],
            parameters: vec![
                Parameter {
                    local: LocalId(0),
                    ty: array_type(region),
                },
                Parameter {
                    local: LocalId(1),
                    ty: Type::I64,
                },
            ],
            effects: bounds_effects(),
            result: Type::F64,
            body: Term::Let {
                binder: LocalId(2),
                ty: Type::F64,
                value: primitive(
                    Primitive::ArrayGetF64,
                    vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(1))],
                ),
                next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
            },
        },
    ])
}

fn budget_artifact() -> CoreArtifact {
    let region = RegionId(0);
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
            region_parameters: vec![region],
            parameters: vec![
                Parameter {
                    local: LocalId(0),
                    ty: Type::Bool,
                },
                Parameter {
                    local: LocalId(1),
                    ty: array_type(region),
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

fn helper_static_control_artifact() -> CoreArtifact {
    let option = SumType {
        name: "R1S3ControlOption".to_owned(),
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
    seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![
                Parameter {
                    local: LocalId(0),
                    ty: Type::Bool,
                },
                Parameter {
                    local: LocalId(1),
                    ty: Type::I64,
                },
            ],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(2),
                ty: Type::Sum(option.clone()),
                value: RValue::Construct {
                    sum: option.clone(),
                    constructor: 1,
                    fields: vec![Operand::Local(LocalId(1))],
                },
                next: Box::new(Term::Let {
                    binder: LocalId(3),
                    ty: Type::I64,
                    value: RValue::Call {
                        function: FunctionId(1),
                        arguments: vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(2))],
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
                }),
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![
                Parameter {
                    local: LocalId(0),
                    ty: Type::Bool,
                },
                Parameter {
                    local: LocalId(1),
                    ty: Type::Sum(option.clone()),
                },
            ],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::If {
                condition: Operand::Local(LocalId(0)),
                then_term: Box::new(Term::Case {
                    scrutinee: Operand::Local(LocalId(1)),
                    arms: vec![
                        CaseArm {
                            constructor: 0,
                            bindings: vec![],
                            body: Term::Return(Operand::I64(0)),
                        },
                        CaseArm {
                            constructor: 1,
                            bindings: vec![LocalId(2)],
                            body: Term::Return(Operand::Local(LocalId(2))),
                        },
                    ],
                }),
                else_term: Box::new(Term::Return(Operand::I64(-1))),
            },
        },
    ])
}

fn recursive_components_artifact(count: usize) -> CoreArtifact {
    assert!((1..=3).contains(&count));
    let parameters = if count == 1 {
        vec![]
    } else {
        (0..count - 1)
            .map(|index| Parameter {
                local: LocalId(index as u32),
                ty: Type::Bool,
            })
            .collect()
    };
    let mut body = Term::TailCall {
        function: FunctionId(count as u32),
        arguments: vec![],
    };
    for index in (1..count).rev() {
        body = Term::If {
            condition: Operand::Local(LocalId((index - 1) as u32)),
            then_term: Box::new(Term::TailCall {
                function: FunctionId(index as u32),
                arguments: vec![],
            }),
            else_term: Box::new(body),
        };
    }
    let mut functions = vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters,
        effects: EffectRow::pure(),
        result: Type::Unit,
        body,
    }];
    for index in 1..=count {
        functions.push(Function {
            id: FunctionId(index as u32),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::Unit,
            body: Term::TailCall {
                function: FunctionId(index as u32),
                arguments: vec![],
            },
        });
    }
    seal(functions)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Shapes {
    array_len: u64,
    array_get: u64,
    calls: u64,
}

fn shapes(artifact: &CoreArtifact) -> Shapes {
    let mut shapes = Shapes::default();
    for function in &artifact.program.functions {
        count_shapes(&function.body, &mut shapes);
    }
    shapes
}

fn count_shapes(term: &Term, shapes: &mut Shapes) {
    match term {
        Term::Let { value, next, .. } => {
            match value {
                RValue::Primitive {
                    operation: Primitive::ArrayLenF64,
                    ..
                } => shapes.array_len += 1,
                RValue::Primitive {
                    operation: Primitive::ArrayGetF64,
                    ..
                } => shapes.array_get += 1,
                RValue::Call { .. } => shapes.calls += 1,
                _ => {}
            }
            count_shapes(next, shapes);
        }
        Term::If {
            then_term,
            else_term,
            ..
        } => {
            count_shapes(then_term, shapes);
            count_shapes(else_term, shapes);
        }
        Term::Case { arms, .. } => {
            for arm in arms {
                count_shapes(&arm.body, shapes);
            }
        }
        Term::Region { body, .. } => count_shapes(body, shapes),
        Term::Handle { clauses, body, .. } => {
            for clause in clauses {
                count_shapes(&clause.body, shapes);
            }
            count_shapes(body, shapes);
        }
        Term::TailCall { .. } | Term::Return(_) => {}
    }
}

#[test]
fn array_get_preserves_region_bounds_outcome_and_effect_order() {
    let source = array_get_artifact();
    let projected = specialize(
        &source,
        vec![BindingTime::Dynamic, BindingTime::Dynamic],
        vec![
            SpecializationSlot::Dynamic(array_type(RegionId(0))),
            SpecializationSlot::Dynamic(Type::I64),
        ],
        generous_budget(),
    )
    .expect("dynamic ArrayGet must specialize");
    verify(projected.artifact()).expect("the ArrayGet residual must verify");
    assert_eq!(shapes(projected.artifact()).array_get, 1);
    let entry = &projected.artifact().program.functions[0];
    assert_eq!(entry.region_parameters, vec![RegionId(0)]);
    assert_eq!(entry.effects, bounds_effects());

    for index in [-1, 0, 1] {
        let arguments = vec![CoreValue::array_f64(vec![3.5]), CoreValue::I64(index)];
        let original = run(&source, arguments.clone());
        let residual = run(projected.artifact(), arguments);
        assert_eq!(residual.outcome, original.outcome);
        assert_eq!(residual.effect_trace, original.effect_trace);
    }
}

#[test]
fn array_len_always_residualizes_and_matches_runtime_length() {
    let source = array_len_artifact();
    let projected = specialize(
        &source,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(array_type(RegionId(0)))],
        generous_budget(),
    )
    .expect("dynamic ArrayLen must specialize");
    verify(projected.artifact()).expect("the ArrayLen residual must verify");
    assert_eq!(shapes(projected.artifact()).array_len, 1);
    for values in [vec![], vec![1.0], vec![1.0, 2.0, 3.0]] {
        let arguments = vec![CoreValue::array_f64(values)];
        assert_eq!(
            run(projected.artifact(), arguments.clone()).outcome,
            run(&source, arguments).outcome
        );
    }
}

#[test]
fn effectful_helper_is_never_unfolded() {
    let source = effectful_helper_artifact();
    let projected = specialize(
        &source,
        vec![BindingTime::Dynamic, BindingTime::Dynamic],
        vec![
            SpecializationSlot::Dynamic(array_type(RegionId(0))),
            SpecializationSlot::Dynamic(Type::I64),
        ],
        generous_budget(),
    )
    .expect("the effectful helper must residualize");
    assert_eq!(projected.report().usage().helper_unfolds, 0);
    assert_eq!(shapes(projected.artifact()).calls, 1);
    assert_eq!(shapes(projected.artifact()).array_get, 1);
    for index in [-1, 0, 2] {
        let arguments = vec![CoreValue::array_f64(vec![8.0, 9.0]), CoreValue::I64(index)];
        let original = run(&source, arguments.clone());
        let residual = run(projected.artifact(), arguments);
        assert_eq!(residual.outcome, original.outcome);
        assert_eq!(residual.effect_trace, original.effect_trace);
    }
}

#[test]
fn pure_helper_unfolds_known_if_and_case_but_refuses_dynamic_control() {
    let source = helper_static_control_artifact();
    let known = specialize(
        &source,
        vec![BindingTime::Static, BindingTime::Dynamic],
        vec![
            SpecializationSlot::Static(naux::core::SpecializationValue::Bool(true)),
            SpecializationSlot::Dynamic(Type::I64),
        ],
        generous_budget(),
    )
    .expect("known helper If/Case must unfold");
    assert_eq!(shapes(known.artifact()).calls, 0);
    assert!(known.report().usage().helper_unfolds > 0);
    for value in [-9, 0, 42] {
        assert_eq!(
            run(known.artifact(), vec![CoreValue::I64(value)]).outcome,
            run(&source, vec![CoreValue::Bool(true), CoreValue::I64(value)]).outcome
        );
    }

    let dynamic = specialize(
        &source,
        vec![BindingTime::Dynamic, BindingTime::Dynamic],
        vec![
            SpecializationSlot::Dynamic(Type::Bool),
            SpecializationSlot::Dynamic(Type::I64),
        ],
        generous_budget(),
    )
    .expect("dynamic helper control must residualize");
    assert_eq!(shapes(dynamic.artifact()).calls, 1);
    for condition in [false, true] {
        let arguments = vec![CoreValue::Bool(condition), CoreValue::I64(17)];
        assert_eq!(
            run(dynamic.artifact(), arguments.clone()).outcome,
            run(&source, arguments).outcome
        );
    }
}

#[test]
fn exactly_two_recursive_components_are_admitted_and_three_fail_closed() {
    let two = recursive_components_artifact(2);
    specialize(
        &two,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::Bool)],
        generous_budget(),
    )
    .expect("two recursive components are the CoreVM0-shaped boundary");

    let three = recursive_components_artifact(3);
    assert!(matches!(
        specialize(
            &three,
            vec![BindingTime::Dynamic, BindingTime::Dynamic],
            vec![
                SpecializationSlot::Dynamic(Type::Bool),
                SpecializationSlot::Dynamic(Type::Bool),
            ],
            generous_budget(),
        ),
        Err(PolyvariantR1S3Error::MultipleRecursiveComponents { count: 3 })
    ));
}

#[test]
fn static_arrays_foreign_effects_and_nonzero_region_fail_closed() {
    let array = array_len_artifact();
    assert!(matches!(
        specialize(
            &array,
            vec![BindingTime::Static],
            vec![SpecializationSlot::Static(
                naux::core::SpecializationValue::ArrayF64(vec![1.0])
            )],
            generous_budget(),
        ),
        Err(PolyvariantR1S3Error::InvalidEntrySlot { .. })
    ));

    let overflow = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::canonical(vec![Effect::Error(ErrorKind::Overflow)]),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(0),
            ty: Type::I64,
            value: primitive(
                Primitive::I64Add(NumericMode::Checked),
                vec![Operand::I64(1), Operand::I64(2)],
            ),
            next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
        },
    }]);
    assert!(matches!(
        specialize(&overflow, vec![], vec![], generous_budget()),
        Err(PolyvariantR1S3Error::UnsupportedEffects { .. })
    ));

    let region = RegionId(1);
    let foreign_region = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![region],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: array_type(region),
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(1),
            ty: Type::I64,
            value: primitive(Primitive::ArrayLenF64, vec![Operand::Local(LocalId(0))]),
            next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
        },
    }]);
    assert!(matches!(
        specialize(
            &foreign_region,
            vec![BindingTime::Dynamic],
            vec![SpecializationSlot::Dynamic(array_type(region))],
            generous_budget(),
        ),
        Err(PolyvariantR1S3Error::UnsupportedRegionParameters { .. })
    ));
}

#[test]
fn every_exact_s3_budget_passes_and_every_one_below_fails_closed() {
    let source = budget_artifact();
    let manifest = || {
        vec![
            BindingTime::Dynamic,
            BindingTime::Dynamic,
            BindingTime::Dynamic,
        ]
    };
    let slots = || {
        vec![
            SpecializationSlot::Dynamic(Type::Bool),
            SpecializationSlot::Dynamic(array_type(RegionId(0))),
            SpecializationSlot::Dynamic(Type::I64),
        ]
    };
    let project = |budget| specialize(&source, manifest(), slots(), budget);
    let baseline = project(generous_budget()).expect("the S3 budget fixture must specialize");
    let usage = baseline.report().usage();
    let nodes = baseline.report().residual_nodes();
    let bytes = baseline.report().residual_bytes();
    assert_eq!(
        baseline.report().policy_hash().to_hex(),
        "3ec434c5443ce2daa846470b5c505566ab17c98b61f78e2552efb39239413d53"
    );
    assert_eq!(
        baseline.report().request_hash().to_hex(),
        "4462a744327e1048c1d9a3b358d7700282a9cafa6cb536a8d1a3d82ad410434d"
    );
    assert_eq!(
        baseline.report().residual_hash().to_hex(),
        "72918bb40a2868a86a6df5a98d1518cf7141d9afb91d7b5e90fb84697bee3575"
    );
    assert_eq!(usage.work_units, 109);
    assert_eq!(usage.partial_value_nodes, 8);
    assert_eq!(usage.variants, 1);
    assert_eq!(usage.control_splits, 1);
    assert_eq!(usage.dynamic_parameters, 3);
    assert_eq!(usage.helper_unfolds, 1);
    assert_eq!(nodes, 14);
    assert_eq!(bytes, 157);
    assert!(usage.work_units > 0);
    assert!(usage.partial_value_nodes > 0);
    assert!(usage.variants > 0);
    assert!(usage.control_splits > 0);
    assert!(usage.dynamic_parameters > 0);
    assert!(usage.helper_unfolds > 0);

    let exact = PolyvariantR1S3Budget::new(
        usage.work_units,
        usage.partial_value_nodes,
        usage.variants,
        usage.control_splits,
        usage.dynamic_parameters,
        usage.helper_unfolds,
        nodes,
        bytes,
    );
    let exact_result = project(exact).expect("every exact S3 budget must pass");
    assert_eq!(exact_result.report().usage(), usage);
    assert_eq!(
        exact_result.report().residual_hash(),
        baseline.report().residual_hash()
    );

    let cases = [
        (
            PolyvariantR1S3Budget::new(
                usage.work_units - 1,
                usage.partial_value_nodes,
                usage.variants,
                usage.control_splits,
                usage.dynamic_parameters,
                usage.helper_unfolds,
                nodes,
                bytes,
            ),
            "work",
        ),
        (
            PolyvariantR1S3Budget::new(
                usage.work_units,
                usage.partial_value_nodes - 1,
                usage.variants,
                usage.control_splits,
                usage.dynamic_parameters,
                usage.helper_unfolds,
                nodes,
                bytes,
            ),
            "partial",
        ),
        (
            PolyvariantR1S3Budget::new(
                usage.work_units,
                usage.partial_value_nodes,
                usage.variants - 1,
                usage.control_splits,
                usage.dynamic_parameters,
                usage.helper_unfolds,
                nodes,
                bytes,
            ),
            "variants",
        ),
        (
            PolyvariantR1S3Budget::new(
                usage.work_units,
                usage.partial_value_nodes,
                usage.variants,
                usage.control_splits - 1,
                usage.dynamic_parameters,
                usage.helper_unfolds,
                nodes,
                bytes,
            ),
            "control",
        ),
        (
            PolyvariantR1S3Budget::new(
                usage.work_units,
                usage.partial_value_nodes,
                usage.variants,
                usage.control_splits,
                usage.dynamic_parameters - 1,
                usage.helper_unfolds,
                nodes,
                bytes,
            ),
            "dynamic",
        ),
        (
            PolyvariantR1S3Budget::new(
                usage.work_units,
                usage.partial_value_nodes,
                usage.variants,
                usage.control_splits,
                usage.dynamic_parameters,
                usage.helper_unfolds - 1,
                nodes,
                bytes,
            ),
            "helper",
        ),
        (
            PolyvariantR1S3Budget::new(
                usage.work_units,
                usage.partial_value_nodes,
                usage.variants,
                usage.control_splits,
                usage.dynamic_parameters,
                usage.helper_unfolds,
                nodes - 1,
                bytes,
            ),
            "nodes",
        ),
        (
            PolyvariantR1S3Budget::new(
                usage.work_units,
                usage.partial_value_nodes,
                usage.variants,
                usage.control_splits,
                usage.dynamic_parameters,
                usage.helper_unfolds,
                nodes,
                bytes - 1,
            ),
            "bytes",
        ),
    ];
    for (budget, field) in cases {
        assert!(project(budget).is_err(), "one-below {field} must fail");
    }
}

#[test]
fn zero_and_hard_cap_overflow_reject_all_eight_s3_budget_fields() {
    let good = generous_budget();
    let fields = [
        ("max_work_units", R1_S3_MAX_WORK_UNITS_HARD_CAP),
        (
            "max_partial_value_nodes",
            R1_S3_MAX_PARTIAL_VALUE_NODES_HARD_CAP,
        ),
        ("max_variants", R1_S3_MAX_VARIANTS_HARD_CAP),
        ("max_control_splits", R1_S3_MAX_CONTROL_SPLITS_HARD_CAP),
        (
            "max_dynamic_parameters",
            R1_S3_MAX_DYNAMIC_PARAMETERS_HARD_CAP,
        ),
        ("max_helper_unfolds", R1_S3_MAX_HELPER_UNFOLDS_HARD_CAP),
        ("max_residual_nodes", R1_S3_MAX_RESIDUAL_NODES_HARD_CAP),
        ("max_residual_bytes", R1_S3_MAX_RESIDUAL_BYTES_HARD_CAP),
    ];
    for (index, (field, hard_cap)) in fields.into_iter().enumerate() {
        let mut limits = [
            good.max_work_units,
            good.max_partial_value_nodes,
            good.max_variants,
            good.max_control_splits,
            good.max_dynamic_parameters,
            good.max_helper_unfolds,
            good.max_residual_nodes,
            good.max_residual_bytes,
        ];
        limits[index] = 0;
        assert_eq!(
            specialize_polyvariant_r1_s3_unreachable(PolyvariantR1S3Budget::new(
                limits[0], limits[1], limits[2], limits[3], limits[4], limits[5], limits[6],
                limits[7],
            )),
            PolyvariantR1S3Error::ZeroBudget { field }
        );
        limits[index] = hard_cap + 1;
        assert!(matches!(
            specialize_polyvariant_r1_s3_unreachable(PolyvariantR1S3Budget::new(
                limits[0], limits[1], limits[2], limits[3], limits[4], limits[5], limits[6],
                limits[7],
            )),
            PolyvariantR1S3Error::BudgetHardCapExceeded {
                field: actual,
                ..
            } if actual == field
        ));
    }
}

fn specialize_polyvariant_r1_s3_unreachable(budget: PolyvariantR1S3Budget) -> PolyvariantR1S3Error {
    let source = array_len_artifact();
    specialize(
        &source,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(array_type(RegionId(0)))],
        budget,
    )
    .expect_err("invalid budgets must fail before specialization")
}

#[test]
fn concrete_corevm0_binding_specializes_and_rejects_another_same_shape_program() {
    let program = CoreVmProgram {
        schema_version: COREVM0_SCHEMA_VERSION,
        arguments: vec![CoreVmType::ArrayF64],
        locals: vec![],
        max_stack: 2,
        instructions: vec![
            CoreVmInstruction::LoadArg(0),
            CoreVmInstruction::ConstI64(0),
            CoreVmInstruction::ArrayGetF64,
            CoreVmInstruction::ReturnF64,
        ],
    };
    let bound = build_definitional_corevm0(&program).expect("Bounds CoreVM0 must build");
    let slots = vec![
        SpecializationSlot::Static(bound.program_image().clone()),
        SpecializationSlot::Dynamic(array_type(RegionId(0))),
    ];
    let (binding, certificate, request) = requests(
        bound.artifact(),
        vec![BindingTime::Static, BindingTime::Dynamic],
        slots,
    );
    let validated =
        validate_specialization_r0a_request(bound.artifact(), &binding, &certificate, &request)
            .expect("the concrete CoreVM0 envelope must validate");
    let projected = specialize_corevm0_r1_s3(&bound, &validated, generous_budget())
        .expect("the concrete CoreVM0 package must cross R1-S3");
    verify(projected.artifact()).expect("the CoreVM0 S3 residual must verify");
    assert_eq!(projected.report().program_hash(), bound.program_hash());
    assert_eq!(
        projected.report().program_image_hash(),
        bound.program_image_hash()
    );
    assert_eq!(
        projected.report().core_interpreter_semantics_hash(),
        bound.core_interpreter_semantics_hash()
    );
    assert_eq!(
        projected.report().program_hash().to_hex(),
        "f44da961b0335c097119a7ed12f941a1c0cbc4fea42813f989e6996fdeae2c5f"
    );
    assert_eq!(
        projected.report().program_image_hash().to_hex(),
        "a6f9bb6cecb949b2485e9c025b1fdb21d2cdffe421d58f295555e2be2afb0be4"
    );
    assert_eq!(
        projected.report().binding_hash().to_hex(),
        "2c17c52206f0a07b69f0be885ab0070a791c36b4674517cf2908e5a5422870e7"
    );
    assert_eq!(
        projected.report().residual_hash().to_hex(),
        "50504e086dcb043f7dcbc82ea38bb225f01ce23e24b20bbbb369721b48afe55c"
    );

    for values in [vec![], vec![1.0], vec![-0.0, 2.5, f64::NAN]] {
        let source = evaluate_definitional_corevm0(
            &bound,
            vec![CoreVmValue::array_f64(values.clone())],
            EvaluationBudget::new(10_000_000, 256),
        )
        .expect("the definitional CoreVM0 source must evaluate");
        let residual = run(projected.artifact(), vec![CoreValue::array_f64(values)]);
        match source.outcome {
            CoreVmOutcome::ReturnF64(expected) => {
                let EvaluationOutcome::Return(CoreValue::F64(actual)) = residual.outcome else {
                    panic!("the CoreVM0 residual must return F64");
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
        let expected_effects = source
            .effect_trace
            .iter()
            .map(|effect| match effect {
                CoreVmTypedError::Bounds => EffectEvent::Error(ErrorKind::Bounds),
            })
            .collect::<Vec<_>>();
        assert_eq!(residual.effect_trace, expected_effects);
    }

    let mut changed_program = program.clone();
    changed_program.instructions[1] = CoreVmInstruction::ConstI64(1);
    let changed =
        build_definitional_corevm0(&changed_program).expect("the same-shape mutation must build");
    assert_eq!(
        changed.artifact().semantic_hash,
        bound.artifact().semantic_hash
    );
    assert!(matches!(
        specialize_corevm0_r1_s3(&changed, &validated, generous_budget()),
        Err(CoreVmR1S3Error::ProgramImageSlotMismatch)
    ));
}
