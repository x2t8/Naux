use naux::core::{
    certify_binding_time_b0d, evaluate, evaluate_static_r0b2, generate_residual_r0c2,
    validate_binding_time_b0_request, validate_specialization_r0a_request, BindingTime,
    BindingTimeBudget, BindingTimeRequest, CaseArm, ConstructorType, CoreArtifact, CoreProfile,
    CoreValue, Effect, EffectRow, ErrorKind, EvaluationBudget, Function, FunctionId, LocalId,
    Mutability, NumericMode, Operand, Parameter, Primitive, Program, RValue, RegionId,
    ResidualCore, ResidualGenerationError, SpecializationBudget, SpecializationRequest,
    SpecializationSlot, SpecializationValue, SumType, Term, Type,
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

fn residual_boundary(
    artifact: &CoreArtifact,
    manifest: Vec<BindingTime>,
    slots: Vec<SpecializationSlot>,
    max_residual_nodes: u64,
    max_residual_bytes: u64,
) -> Result<ResidualCore, ResidualGenerationError> {
    let binding_time_request = BindingTimeRequest::p1v0(
        artifact,
        manifest,
        BindingTimeBudget::new(100_000, 100_000, 1_000),
    )
    .expect("B0 request must encode");
    let validated_binding_time = validate_binding_time_b0_request(artifact, &binding_time_request)
        .expect("B0 request must validate");
    let certificate =
        certify_binding_time_b0d(&validated_binding_time).expect("B0 certificate must emit");
    let request = SpecializationRequest::p1v0(
        artifact,
        &binding_time_request,
        &certificate,
        slots,
        SpecializationBudget::new(
            10_000,
            10_000,
            100_000,
            max_residual_nodes,
            max_residual_bytes,
        ),
    )
    .expect("R0 request must encode");
    let validated = validate_specialization_r0a_request(
        artifact,
        &binding_time_request,
        &certificate,
        &request,
    )
    .expect("R0-A request must validate");
    let evaluation = evaluate_static_r0b2(&validated).expect("R0-B2 must evaluate");
    generate_residual_r0c2(&validated, &evaluation)
}

fn assert_differential(
    original: &CoreArtifact,
    original_inputs: Vec<CoreValue>,
    residual: &CoreArtifact,
    residual_inputs: Vec<CoreValue>,
) {
    let original_run = evaluate(
        original,
        original_inputs,
        EvaluationBudget::new(100_000, 300),
    )
    .expect("original program must evaluate");
    let residual_run = evaluate(
        residual,
        residual_inputs,
        EvaluationBudget::new(100_000, 300),
    )
    .expect("residual program must evaluate");
    assert_eq!(
        original_run.outcome, residual_run.outcome,
        "original and residual behavior must agree"
    );
    assert_eq!(
        original_run.effect_trace, residual_run.effect_trace,
        "original and residual effect traces must agree"
    );
}

fn primitive(operation: Primitive, arguments: Vec<Operand>) -> RValue {
    RValue::Primitive {
        operation,
        arguments,
    }
}

fn option_i64() -> SumType {
    SumType {
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
    }
}

#[test]
fn a_static_if_folds_and_erases_the_unselected_effectful_branch() {
    let artifact = seal(vec![Function {
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
        effects: EffectRow::canonical(vec![Effect::Error(ErrorKind::Overflow)]),
        result: Type::I64,
        body: Term::If {
            condition: Operand::Local(LocalId(0)),
            then_term: Box::new(Term::Let {
                binder: LocalId(2),
                ty: Type::I64,
                value: primitive(
                    Primitive::I64Add(NumericMode::Wrapping),
                    vec![Operand::Local(LocalId(1)), Operand::I64(1)],
                ),
                next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
            }),
            else_term: Box::new(Term::Let {
                binder: LocalId(3),
                ty: Type::I64,
                value: primitive(
                    Primitive::I64Add(NumericMode::Checked),
                    vec![Operand::I64(i64::MAX), Operand::I64(1)],
                ),
                next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
            }),
        },
    }]);
    let residual = residual_boundary(
        &artifact,
        vec![BindingTime::Static, BindingTime::Dynamic],
        vec![
            SpecializationSlot::Static(SpecializationValue::Bool(true)),
            SpecializationSlot::Dynamic(Type::I64),
        ],
        1_000,
        1_000_000,
    )
    .expect("the selected static branch must residualize");

    assert_eq!(
        residual.artifact.program.functions[0].parameters,
        vec![Parameter {
            local: LocalId(1),
            ty: Type::I64,
        }]
    );
    assert_eq!(
        residual.artifact.program.functions[0].body,
        Term::Let {
            binder: LocalId(2),
            ty: Type::I64,
            value: primitive(
                Primitive::I64Add(NumericMode::Wrapping),
                vec![Operand::Local(LocalId(1)), Operand::I64(1)],
            ),
            next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
        }
    );
    for x in [-9, 0, 41] {
        assert_differential(
            &artifact,
            vec![CoreValue::Bool(true), CoreValue::I64(x)],
            &residual.artifact,
            vec![CoreValue::I64(x)],
        );
    }
}

#[test]
fn a_static_case_folds_and_materializes_the_selected_field() {
    let option = option_i64();
    let artifact = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![
            Parameter {
                local: LocalId(0),
                ty: Type::Sum(option.clone()),
            },
            Parameter {
                local: LocalId(1),
                ty: Type::I64,
            },
        ],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Case {
            scrutinee: Operand::Local(LocalId(0)),
            arms: vec![
                CaseArm {
                    constructor: 0,
                    bindings: vec![],
                    body: Term::Return(Operand::Local(LocalId(1))),
                },
                CaseArm {
                    constructor: 1,
                    bindings: vec![LocalId(2)],
                    body: Term::Let {
                        binder: LocalId(3),
                        ty: Type::I64,
                        value: primitive(
                            Primitive::I64Add(NumericMode::Wrapping),
                            vec![Operand::Local(LocalId(2)), Operand::Local(LocalId(1))],
                        ),
                        next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
                    },
                },
            ],
        },
    }]);
    let static_sum = SpecializationValue::Sum {
        ty: option.clone(),
        constructor: 1,
        fields: vec![SpecializationValue::I64(5)],
    };
    let residual = residual_boundary(
        &artifact,
        vec![BindingTime::Static, BindingTime::Dynamic],
        vec![
            SpecializationSlot::Static(static_sum),
            SpecializationSlot::Dynamic(Type::I64),
        ],
        1_000,
        1_000_000,
    )
    .expect("the selected static Case arm must residualize");

    assert_eq!(
        residual.artifact.program.functions[0].body,
        Term::Let {
            binder: LocalId(2),
            ty: Type::I64,
            value: RValue::Use(Operand::I64(5)),
            next: Box::new(Term::Let {
                binder: LocalId(3),
                ty: Type::I64,
                value: primitive(
                    Primitive::I64Add(NumericMode::Wrapping),
                    vec![Operand::Local(LocalId(2)), Operand::Local(LocalId(1))],
                ),
                next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
            }),
        }
    );
    for x in [-5, 0, 37] {
        assert_differential(
            &artifact,
            vec![
                CoreValue::Sum {
                    ty: option.clone(),
                    constructor: 1,
                    fields: vec![CoreValue::I64(5)],
                },
                CoreValue::I64(x),
            ],
            &residual.artifact,
            vec![CoreValue::I64(x)],
        );
    }
}

#[test]
fn a_live_static_tuple_is_materialized_for_a_dynamic_call() {
    let tuple = Type::Tuple(vec![Type::I64, Type::Bool]);
    let artifact = seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![
                Parameter {
                    local: LocalId(0),
                    ty: tuple.clone(),
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
                ty: Type::I64,
                value: RValue::Call {
                    function: FunctionId(1),
                    arguments: vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(1))],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![
                Parameter {
                    local: LocalId(0),
                    ty: tuple.clone(),
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
                ty: Type::I64,
                value: RValue::Project {
                    tuple: Operand::Local(LocalId(0)),
                    index: 0,
                },
                next: Box::new(Term::Let {
                    binder: LocalId(3),
                    ty: Type::I64,
                    value: primitive(
                        Primitive::I64Add(NumericMode::Wrapping),
                        vec![Operand::Local(LocalId(2)), Operand::Local(LocalId(1))],
                    ),
                    next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
                }),
            },
        },
    ]);
    let residual = residual_boundary(
        &artifact,
        vec![BindingTime::Static, BindingTime::Dynamic],
        vec![
            SpecializationSlot::Static(SpecializationValue::Tuple(vec![
                SpecializationValue::I64(7),
                SpecializationValue::Bool(true),
            ])),
            SpecializationSlot::Dynamic(Type::I64),
        ],
        1_000,
        1_000_000,
    )
    .expect("the live static Tuple must materialize");

    assert_eq!(residual.artifact.program.functions.len(), 2);
    assert!(matches!(
        residual.artifact.program.functions[0].body,
        Term::Let {
            binder: LocalId(0),
            value: RValue::Tuple(_),
            ..
        }
    ));
    for x in [-7, 0, 11] {
        assert_differential(
            &artifact,
            vec![
                CoreValue::Tuple(vec![CoreValue::I64(7), CoreValue::Bool(true)]),
                CoreValue::I64(x),
            ],
            &residual.artifact,
            vec![CoreValue::I64(x)],
        );
    }
}

#[test]
fn a_complete_nested_tuple_sum_result_is_rebuilt_children_first() {
    let option = option_i64();
    let result = Type::Tuple(vec![Type::I64, Type::Sum(option.clone())]);
    let artifact = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: result.clone(),
        body: Term::Let {
            binder: LocalId(0),
            ty: Type::Sum(option.clone()),
            value: RValue::Construct {
                sum: option.clone(),
                constructor: 1,
                fields: vec![Operand::I64(9)],
            },
            next: Box::new(Term::Let {
                binder: LocalId(1),
                ty: result,
                value: RValue::Tuple(vec![Operand::I64(3), Operand::Local(LocalId(0))]),
                next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
            }),
        },
    }]);
    let first = residual_boundary(&artifact, vec![], vec![], 1_000, 1_000_000)
        .expect("the aggregate result must materialize");
    let second = residual_boundary(&artifact, vec![], vec![], 1_000, 1_000_000)
        .expect("repeated aggregate materialization must pass");

    let expected = Term::Let {
        binder: LocalId(2),
        ty: Type::Sum(option.clone()),
        value: RValue::Construct {
            sum: option.clone(),
            constructor: 1,
            fields: vec![Operand::I64(9)],
        },
        next: Box::new(Term::Let {
            binder: LocalId(3),
            ty: Type::Tuple(vec![Type::I64, Type::Sum(option)]),
            value: RValue::Tuple(vec![Operand::I64(3), Operand::Local(LocalId(2))]),
            next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
        }),
    };
    assert_eq!(first.artifact.program.functions[0].body, expected);
    assert_eq!(first, second, "R0-C2 output must be deterministic");
    assert_differential(&artifact, vec![], &first.artifact, vec![]);
}

fn array_type() -> Type {
    Type::Array {
        region: RegionId(0),
        mutability: Mutability::Read,
        element: Box::new(Type::F64),
    }
}

#[test]
fn a_static_array_is_admitted_when_all_runtime_uses_disappear() {
    let artifact = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![RegionId(0)],
        parameters: vec![
            Parameter {
                local: LocalId(0),
                ty: array_type(),
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
            ty: Type::I64,
            value: primitive(Primitive::ArrayLenF64, vec![Operand::Local(LocalId(0))]),
            next: Box::new(Term::Let {
                binder: LocalId(3),
                ty: Type::I64,
                value: primitive(
                    Primitive::I64Add(NumericMode::Wrapping),
                    vec![Operand::Local(LocalId(2)), Operand::Local(LocalId(1))],
                ),
                next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
            }),
        },
    }]);
    let values = vec![1.0, 2.0, 3.0];
    let residual = residual_boundary(
        &artifact,
        vec![BindingTime::Static, BindingTime::Dynamic],
        vec![
            SpecializationSlot::Static(SpecializationValue::ArrayF64(values.clone())),
            SpecializationSlot::Dynamic(Type::I64),
        ],
        1_000,
        1_000_000,
    )
    .expect("the erased static array must be admitted");

    assert_eq!(
        residual.artifact.program.functions[0].parameters,
        vec![Parameter {
            local: LocalId(1),
            ty: Type::I64,
        }]
    );
    assert_eq!(
        residual.artifact.program.functions[0].body,
        Term::Let {
            binder: LocalId(2),
            ty: Type::I64,
            value: RValue::Use(Operand::I64(3)),
            next: Box::new(Term::Let {
                binder: LocalId(3),
                ty: Type::I64,
                value: primitive(
                    Primitive::I64Add(NumericMode::Wrapping),
                    vec![Operand::Local(LocalId(2)), Operand::Local(LocalId(1))],
                ),
                next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
            }),
        }
    );
    for x in [-3, 0, 100] {
        assert_differential(
            &artifact,
            vec![CoreValue::array_f64(values.clone()), CoreValue::I64(x)],
            &residual.artifact,
            vec![CoreValue::I64(x)],
        );
    }
}

#[test]
fn a_live_static_array_fails_closed_without_an_array_literal() {
    let artifact = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![RegionId(0)],
        parameters: vec![
            Parameter {
                local: LocalId(0),
                ty: array_type(),
            },
            Parameter {
                local: LocalId(1),
                ty: Type::I64,
            },
        ],
        effects: EffectRow::canonical(vec![Effect::Error(ErrorKind::Bounds)]),
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
    }]);
    let error = residual_boundary(
        &artifact,
        vec![BindingTime::Static, BindingTime::Dynamic],
        vec![
            SpecializationSlot::Static(SpecializationValue::ArrayF64(vec![1.0, 2.0])),
            SpecializationSlot::Dynamic(Type::I64),
        ],
        1_000,
        1_000_000,
    )
    .expect_err("a live static array has no honest P1V0 representation");
    assert_eq!(
        error,
        ResidualGenerationError::UnsupportedLiveStaticValue {
            local: Some(LocalId(0)),
        }
    );
}

#[test]
fn a_statically_executed_call_is_erased_and_its_callee_is_pruned() {
    let artifact = seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(0),
                ty: Type::I64,
            }],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(1),
                ty: Type::I64,
                value: RValue::Call {
                    function: FunctionId(1),
                    arguments: vec![Operand::I64(7)],
                },
                next: Box::new(Term::Let {
                    binder: LocalId(2),
                    ty: Type::I64,
                    value: primitive(
                        Primitive::I64Add(NumericMode::Wrapping),
                        vec![Operand::Local(LocalId(1)), Operand::Local(LocalId(0))],
                    ),
                    next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
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
    ]);
    let residual = residual_boundary(
        &artifact,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        1_000,
        1_000_000,
    )
    .expect("the static call must disappear");

    assert_eq!(
        residual.artifact.program.functions.len(),
        1,
        "the now-unreachable callee must be pruned"
    );
    assert!(matches!(
        residual.artifact.program.functions[0].body,
        Term::Let {
            binder: LocalId(1),
            value: RValue::Use(Operand::I64(7)),
            ..
        }
    ));
    for x in [-7, 0, 9] {
        assert_differential(
            &artifact,
            vec![CoreValue::I64(x)],
            &residual.artifact,
            vec![CoreValue::I64(x)],
        );
    }
}

#[test]
fn a_complete_result_with_skipped_effectful_work_preserves_that_work() {
    let artifact = seal(vec![Function {
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
                vec![Operand::I64(i64::MAX), Operand::I64(1)],
            ),
            next: Box::new(Term::Return(Operand::I64(42))),
        },
    }]);
    let residual = residual_boundary(&artifact, vec![], vec![], 1_000, 1_000_000)
        .expect("skipped effectful work must remain residual");

    assert_eq!(
        residual.artifact.program.functions[0].body,
        artifact.program.functions[0].body
    );
    assert_differential(&artifact, vec![], &residual.artifact, vec![]);
}

#[test]
fn fresh_local_exhaustion_fails_closed() {
    let tuple = Type::Tuple(vec![Type::I64, Type::I64]);
    let artifact = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: tuple.clone(),
        body: Term::Let {
            binder: LocalId(u32::MAX),
            ty: tuple,
            value: RValue::Tuple(vec![Operand::I64(1), Operand::I64(2)]),
            next: Box::new(Term::Return(Operand::Local(LocalId(u32::MAX)))),
        },
    }]);
    let error = residual_boundary(&artifact, vec![], vec![], 1_000, 1_000_000)
        .expect_err("aggregate collapse needs a fresh LocalId");
    assert_eq!(error, ResidualGenerationError::FreshLocalExhausted);
}

#[test]
fn r0c2_residual_budgets_still_fail_closed() {
    let artifact = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: Type::I64,
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Return(Operand::Local(LocalId(0))),
    }]);
    let nodes = residual_boundary(
        &artifact,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        1,
        1_000_000,
    )
    .expect_err("the one-node budget excludes the Return operand");
    assert!(matches!(
        nodes,
        ResidualGenerationError::ResidualNodeBudgetExceeded { limit: 1, .. }
    ));

    let bytes = residual_boundary(
        &artifact,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        1_000,
        8,
    )
    .expect_err("the byte budget must fail closed");
    assert!(matches!(
        bytes,
        ResidualGenerationError::ResidualByteBudgetExceeded { limit: 8, .. }
    ));
}
