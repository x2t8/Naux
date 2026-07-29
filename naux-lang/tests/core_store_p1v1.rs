use naux::core::{
    evaluate, semantic_bytes, verify, CoreArtifact, CoreProfile, CoreValue, Effect, EffectRow,
    ErrorKind, EvaluationBudget, EvaluationOutcome, Function, FunctionId, LocalId, Mutability,
    NumericMode, Operand, Parameter, Primitive, Program, RValue, RegionId, SchemaVersion,
    SemanticHash, Term, Type, VerificationCode,
};

const STORE_REGION: RegionId = RegionId(0);

fn budget() -> EvaluationBudget {
    EvaluationBudget::new(10_000, 64)
}

fn store_effects() -> EffectRow {
    EffectRow::canonical(vec![
        Effect::State(STORE_REGION),
        Effect::Alloc(STORE_REGION),
    ])
}

fn shared_ref(element: Type) -> Type {
    Type::Ref {
        region: STORE_REGION,
        mutability: Mutability::Shared,
        element: Box::new(element),
    }
}

fn program(profile: CoreProfile, functions: Vec<Function>) -> Program {
    Program {
        schema: SchemaVersion::core_n0(),
        profile,
        entry: FunctionId(0),
        functions,
    }
}

fn seal(program: Program) -> CoreArtifact {
    CoreArtifact::seal(program).expect("test program should encode")
}

fn alias_program(profile: CoreProfile, effects: EffectRow) -> Program {
    program(
        profile,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![STORE_REGION],
            parameters: vec![],
            effects,
            result: Type::I64,
            body: Term::Region {
                region: STORE_REGION,
                body: Box::new(Term::Let {
                    binder: LocalId(0),
                    ty: shared_ref(Type::I64),
                    value: RValue::RefAlloc {
                        region: STORE_REGION,
                        mutability: Mutability::Shared,
                        value: Operand::I64(1),
                    },
                    next: Box::new(Term::Let {
                        binder: LocalId(1),
                        ty: shared_ref(Type::I64),
                        value: RValue::Use(Operand::Local(LocalId(0))),
                        next: Box::new(Term::Let {
                            binder: LocalId(2),
                            ty: Type::Unit,
                            value: RValue::RefStore {
                                reference: Operand::Local(LocalId(1)),
                                value: Operand::I64(9),
                            },
                            next: Box::new(Term::Let {
                                binder: LocalId(3),
                                ty: Type::I64,
                                value: RValue::RefLoad {
                                    reference: Operand::Local(LocalId(0)),
                                },
                                next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
                            }),
                        }),
                    }),
                }),
            },
        }],
    )
}

#[test]
fn alias_write_is_visible_through_the_original_reference() {
    let artifact = seal(alias_program(CoreProfile::P1V1, store_effects()));
    verify(&artifact).expect("P1V1 alias program should verify");

    let evaluation = evaluate(&artifact, vec![], budget()).expect("evaluation should succeed");
    assert_eq!(
        evaluation.outcome,
        EvaluationOutcome::Return(CoreValue::I64(9))
    );
    assert_eq!(evaluation.steps, 10);
    assert!(
        evaluation.effect_trace.is_empty(),
        "store actions are ordered semantic effects, not public trace events"
    );
}

#[test]
fn fresh_allocations_do_not_alias_and_store_order_is_observable() {
    let artifact = seal(program(
        CoreProfile::P1V1,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![STORE_REGION],
            parameters: vec![],
            effects: store_effects(),
            result: Type::I64,
            body: Term::Region {
                region: STORE_REGION,
                body: Box::new(Term::Let {
                    binder: LocalId(0),
                    ty: shared_ref(Type::I64),
                    value: RValue::RefAlloc {
                        region: STORE_REGION,
                        mutability: Mutability::Shared,
                        value: Operand::I64(1),
                    },
                    next: Box::new(Term::Let {
                        binder: LocalId(1),
                        ty: shared_ref(Type::I64),
                        value: RValue::RefAlloc {
                            region: STORE_REGION,
                            mutability: Mutability::Shared,
                            value: Operand::I64(2),
                        },
                        next: Box::new(Term::Let {
                            binder: LocalId(2),
                            ty: Type::Unit,
                            value: RValue::RefStore {
                                reference: Operand::Local(LocalId(0)),
                                value: Operand::I64(9),
                            },
                            next: Box::new(Term::Let {
                                binder: LocalId(3),
                                ty: Type::I64,
                                value: RValue::RefLoad {
                                    reference: Operand::Local(LocalId(1)),
                                },
                                next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
                            }),
                        }),
                    }),
                }),
            },
        }],
    ));

    assert_eq!(
        evaluate(&artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(2))
    );
}

#[test]
fn p1v0_remains_closed_to_store_constructs() {
    let artifact = seal(alias_program(CoreProfile::P1V0, store_effects()));
    let errors = verify(&artifact).expect_err("P1V0 must not silently widen");

    assert!(errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::UnsupportedProfileFeature));
}

#[test]
fn allocation_and_state_require_exact_declared_effects() {
    let without_alloc = seal(alias_program(
        CoreProfile::P1V1,
        EffectRow::canonical(vec![Effect::State(STORE_REGION)]),
    ));
    let without_state = seal(alias_program(
        CoreProfile::P1V1,
        EffectRow::canonical(vec![Effect::Alloc(STORE_REGION)]),
    ));

    for artifact in [without_alloc, without_state] {
        let errors = verify(&artifact).expect_err("missing store effect must fail closed");
        assert!(errors
            .0
            .iter()
            .any(|error| error.code == VerificationCode::MissingEffect));
    }
}

#[test]
fn store_operations_require_an_active_declared_region() {
    let mut inactive = alias_program(CoreProfile::P1V1, store_effects());
    inactive.functions[0].body = match inactive.functions[0].body.clone() {
        Term::Region { body, .. } => *body,
        _ => unreachable!("fixture starts with a region"),
    };
    let inactive_errors =
        verify(&seal(inactive)).expect_err("operation outside Region must fail closed");
    assert!(inactive_errors
        .0
        .iter()
        .any(|error| error.message.contains("inactive region")));

    let mut undeclared = alias_program(CoreProfile::P1V1, store_effects());
    undeclared.functions[0].region_parameters.clear();
    let undeclared_errors =
        verify(&seal(undeclared)).expect_err("undeclared region must fail closed");
    assert!(undeclared_errors
        .0
        .iter()
        .any(|error| error.message.contains("undeclared region")));

    let nested = seal(program(
        CoreProfile::P1V1,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![STORE_REGION],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::Unit,
            body: Term::Region {
                region: STORE_REGION,
                body: Box::new(Term::Region {
                    region: STORE_REGION,
                    body: Box::new(Term::Return(Operand::Unit)),
                }),
            },
        }],
    ));
    let nested_errors = verify(&nested).expect_err("region re-entry must fail closed");
    assert!(nested_errors
        .0
        .iter()
        .any(|error| error.message.contains("already active")));
}

#[test]
fn load_and_store_require_reference_operands() {
    let load = seal(program(
        CoreProfile::P1V1,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![STORE_REGION],
            parameters: vec![],
            effects: EffectRow::canonical(vec![Effect::State(STORE_REGION)]),
            result: Type::I64,
            body: Term::Region {
                region: STORE_REGION,
                body: Box::new(Term::Let {
                    binder: LocalId(0),
                    ty: Type::I64,
                    value: RValue::RefLoad {
                        reference: Operand::I64(1),
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
                }),
            },
        }],
    ));
    let store = seal(program(
        CoreProfile::P1V1,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![STORE_REGION],
            parameters: vec![],
            effects: EffectRow::canonical(vec![Effect::State(STORE_REGION)]),
            result: Type::Unit,
            body: Term::Region {
                region: STORE_REGION,
                body: Box::new(Term::Let {
                    binder: LocalId(0),
                    ty: Type::Unit,
                    value: RValue::RefStore {
                        reference: Operand::I64(1),
                        value: Operand::I64(2),
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
                }),
            },
        }],
    ));

    for artifact in [load, store] {
        let errors = verify(&artifact).expect_err("non-reference operand must fail closed");
        assert!(errors
            .0
            .iter()
            .any(|error| error.code == VerificationCode::TypeMismatch));
    }
}

#[test]
fn references_cannot_cross_function_boundaries() {
    let result_escape = seal(program(
        CoreProfile::P1V1,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![STORE_REGION],
            parameters: vec![],
            effects: EffectRow::canonical(vec![Effect::Alloc(STORE_REGION)]),
            result: shared_ref(Type::I64),
            body: Term::Region {
                region: STORE_REGION,
                body: Box::new(Term::Let {
                    binder: LocalId(0),
                    ty: shared_ref(Type::I64),
                    value: RValue::RefAlloc {
                        region: STORE_REGION,
                        mutability: Mutability::Shared,
                        value: Operand::I64(1),
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
                }),
            },
        }],
    ));
    let parameter_escape = seal(program(
        CoreProfile::P1V1,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![STORE_REGION],
            parameters: vec![Parameter {
                local: LocalId(0),
                ty: Type::Tuple(vec![shared_ref(Type::Bool)]),
            }],
            effects: EffectRow::pure(),
            result: Type::Unit,
            body: Term::Return(Operand::Unit),
        }],
    ));

    for artifact in [result_escape, parameter_escape] {
        let errors = verify(&artifact).expect_err("reference escape must fail closed");
        assert!(errors
            .0
            .iter()
            .any(|error| error.message.contains("function") && error.message.contains("boundary")));
    }
}

#[test]
fn unsupported_mutability_cell_type_and_store_type_fail_closed() {
    let mut unique = alias_program(CoreProfile::P1V1, store_effects());
    if let Term::Region { body, .. } = &mut unique.functions[0].body {
        if let Term::Let { ty, value, .. } = body.as_mut() {
            *ty = Type::Ref {
                region: STORE_REGION,
                mutability: Mutability::Unique,
                element: Box::new(Type::I64),
            };
            if let RValue::RefAlloc { mutability, .. } = value {
                *mutability = Mutability::Unique;
            }
        }
    }
    let unique_errors = verify(&seal(unique)).expect_err("Unique is not admitted yet");
    assert!(unique_errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::UnsupportedProfileFeature));

    let mut non_scalar = alias_program(CoreProfile::P1V1, store_effects());
    if let Term::Region { body, .. } = &mut non_scalar.functions[0].body {
        if let Term::Let { ty, value, .. } = body.as_mut() {
            *ty = shared_ref(Type::Unit);
            if let RValue::RefAlloc { value, .. } = value {
                *value = Operand::Unit;
            }
        }
    }
    let scalar_errors = verify(&seal(non_scalar)).expect_err("Unit cell must fail closed");
    assert!(scalar_errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::UnsupportedProfileFeature));

    let mut wrong_store_type = alias_program(CoreProfile::P1V1, store_effects());
    if let Term::Region { body, .. } = &mut wrong_store_type.functions[0].body {
        if let Term::Let { next, .. } = body.as_mut() {
            if let Term::Let { next, .. } = next.as_mut() {
                if let Term::Let {
                    value: RValue::RefStore { value, .. },
                    ..
                } = next.as_mut()
                {
                    *value = Operand::Bool(true);
                }
            }
        }
    }
    let store_errors = verify(&seal(wrong_store_type)).expect_err("store type must match");
    assert!(store_errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::TypeMismatch));
}

#[test]
fn region_closes_before_tail_transfer_and_on_error_or_budget_exit() {
    let state_alloc_overflow = EffectRow::canonical(vec![
        Effect::State(STORE_REGION),
        Effect::Alloc(STORE_REGION),
        Effect::Error(ErrorKind::Overflow),
    ]);
    let error_artifact = seal(program(
        CoreProfile::P1V1,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![STORE_REGION],
            parameters: vec![],
            effects: state_alloc_overflow,
            result: Type::I64,
            body: Term::Region {
                region: STORE_REGION,
                body: Box::new(Term::Let {
                    binder: LocalId(0),
                    ty: shared_ref(Type::I64),
                    value: RValue::RefAlloc {
                        region: STORE_REGION,
                        mutability: Mutability::Shared,
                        value: Operand::I64(1),
                    },
                    next: Box::new(Term::Let {
                        binder: LocalId(1),
                        ty: Type::I64,
                        value: RValue::Primitive {
                            operation: Primitive::I64Add(NumericMode::Checked),
                            arguments: vec![Operand::I64(i64::MAX), Operand::I64(1)],
                        },
                        next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
                    }),
                }),
            },
        }],
    ));
    assert_eq!(
        evaluate(&error_artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Error(ErrorKind::Overflow)
    );

    let budget_error = evaluate(&error_artifact, vec![], EvaluationBudget::new(2, 64))
        .expect_err("store evaluation must respect the exact step budget");
    assert!(matches!(
        budget_error,
        naux::core::ExecutionError::StepBudgetExceeded { limit: 2 }
    ));

    let tail_artifact = seal(program(
        CoreProfile::P1V1,
        vec![
            Function {
                id: FunctionId(0),
                region_parameters: vec![STORE_REGION],
                parameters: vec![],
                effects: EffectRow::canonical(vec![Effect::Alloc(STORE_REGION)]),
                result: Type::I64,
                body: Term::Region {
                    region: STORE_REGION,
                    body: Box::new(Term::Let {
                        binder: LocalId(0),
                        ty: shared_ref(Type::I64),
                        value: RValue::RefAlloc {
                            region: STORE_REGION,
                            mutability: Mutability::Shared,
                            value: Operand::I64(5),
                        },
                        next: Box::new(Term::TailCall {
                            function: FunctionId(1),
                            arguments: vec![],
                        }),
                    }),
                },
            },
            Function {
                id: FunctionId(1),
                region_parameters: vec![],
                parameters: vec![],
                effects: EffectRow::pure(),
                result: Type::I64,
                body: Term::Return(Operand::I64(42)),
            },
        ],
    ));
    assert_eq!(
        evaluate(&tail_artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(42))
    );
}

#[test]
fn ordinary_calls_receive_fresh_stores_and_propagate_effects() {
    let mut callee = alias_program(CoreProfile::P1V1, store_effects())
        .functions
        .pop()
        .unwrap();
    callee.id = FunctionId(1);
    let caller = Function {
        id: FunctionId(0),
        region_parameters: vec![STORE_REGION],
        parameters: vec![],
        effects: store_effects(),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(0),
            ty: Type::I64,
            value: RValue::Call {
                function: FunctionId(1),
                arguments: vec![],
            },
            next: Box::new(Term::Let {
                binder: LocalId(1),
                ty: Type::I64,
                value: RValue::Call {
                    function: FunctionId(1),
                    arguments: vec![],
                },
                next: Box::new(Term::Let {
                    binder: LocalId(2),
                    ty: Type::I64,
                    value: RValue::Primitive {
                        operation: Primitive::I64Add(NumericMode::Wrapping),
                        arguments: vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(1))],
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
                }),
            }),
        },
    };
    let artifact = seal(program(
        CoreProfile::P1V1,
        vec![caller.clone(), callee.clone()],
    ));
    assert_eq!(
        evaluate(&artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(18))
    );

    let mut missing_caller_effect = caller;
    missing_caller_effect.effects = EffectRow::canonical(vec![Effect::Alloc(STORE_REGION)]);
    let errors = verify(&seal(program(
        CoreProfile::P1V1,
        vec![missing_caller_effect, callee],
    )))
    .expect_err("caller must cover every callee store effect");
    assert!(errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::MissingEffect));
}

#[test]
fn p1v1_hash_is_deterministic_and_covers_store_structure() {
    let first = seal(alias_program(CoreProfile::P1V1, store_effects()));
    let second = seal(alias_program(CoreProfile::P1V1, store_effects()));
    assert_eq!(first.semantic_hash, second.semantic_hash);
    assert_eq!(
        semantic_bytes(&first.program).unwrap(),
        semantic_bytes(&second.program).unwrap()
    );
    assert_eq!(
        first.semantic_hash.to_hex(),
        "ac526f04cef5428c41b002f978ff52f7eab3752bbee98d564e67f84b5edde5a6"
    );

    let mut tampered = first.clone();
    if let Term::Region { body, .. } = &mut tampered.program.functions[0].body {
        if let Term::Let {
            value: RValue::RefAlloc { value, .. },
            ..
        } = body.as_mut()
        {
            *value = Operand::I64(2);
        }
    }
    let errors = verify(&tampered).expect_err("store artifact tampering must fail closed");
    assert!(errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::SemanticHashMismatch));

    assert_ne!(first.semantic_hash, SemanticHash::ZERO);
}
