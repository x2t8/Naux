use naux::core::{
    evaluate, semantic_bytes, verify, CoreArtifact, CoreProfile, CoreValue, Effect, EffectRow,
    EvaluationBudget, EvaluationOutcome, Function, FunctionId, LocalId, Mutability, NumericMode,
    Operand, Parameter, Primitive, Program, RValue, RegionId, SchemaVersion, SemanticHash, Term,
    Type, VerificationCode,
};

const CAPTURE_REGION: RegionId = RegionId(0);

fn budget() -> EvaluationBudget {
    EvaluationBudget::new(20_000, 64)
}

fn program(profile: CoreProfile, entry: u32, functions: Vec<Function>) -> Program {
    Program {
        schema: SchemaVersion::core_n0(),
        profile,
        entry: FunctionId(entry),
        functions,
    }
}

fn seal(program: Program) -> CoreArtifact {
    CoreArtifact::seal(program).expect("test program should encode")
}

fn closure_type(parameters: Vec<Type>, effects: EffectRow, result: Type) -> Type {
    Type::Closure {
        parameters,
        effects,
        result: Box::new(result),
    }
}

fn shared_i64_ref() -> Type {
    Type::Ref {
        region: CAPTURE_REGION,
        mutability: Mutability::Shared,
        element: Box::new(Type::I64),
    }
}

fn state_effect() -> EffectRow {
    EffectRow::canonical(vec![Effect::State(CAPTURE_REGION)])
}

fn state_alloc_effects() -> EffectRow {
    EffectRow::canonical(vec![
        Effect::State(CAPTURE_REGION),
        Effect::Alloc(CAPTURE_REGION),
    ])
}

fn value_closure_functions(captures: Vec<Operand>) -> Vec<Function> {
    let behavioral_type = closure_type(vec![Type::I64], EffectRow::pure(), Type::I64);
    vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(0),
                ty: behavioral_type,
                value: RValue::PackClosure {
                    function: FunctionId(1),
                    captures,
                },
                next: Box::new(Term::Let {
                    binder: LocalId(1),
                    ty: Type::I64,
                    value: RValue::CallClosure {
                        closure: Operand::Local(LocalId(0)),
                        arguments: vec![Operand::I64(2)],
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
                }),
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![
                Parameter {
                    local: LocalId(0),
                    ty: Type::Tuple(vec![Type::I64]),
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
                    value: RValue::Primitive {
                        operation: Primitive::I64Add(NumericMode::Wrapping),
                        arguments: vec![Operand::Local(LocalId(2)), Operand::Local(LocalId(1))],
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
                }),
            },
        },
        Function {
            id: FunctionId(2),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(0),
                ty: Type::Tuple(vec![Type::I64]),
                value: RValue::Tuple(vec![Operand::I64(40)]),
                next: Box::new(Term::Let {
                    binder: LocalId(1),
                    ty: Type::I64,
                    value: RValue::Call {
                        function: FunctionId(1),
                        arguments: vec![Operand::Local(LocalId(0)), Operand::I64(2)],
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
                }),
            },
        },
    ]
}

fn recursive_reference_closure_program(caller_effects: EffectRow) -> Program {
    program(
        CoreProfile::P1V2,
        0,
        vec![
            Function {
                id: FunctionId(0),
                region_parameters: vec![CAPTURE_REGION],
                parameters: vec![],
                effects: caller_effects,
                result: Type::I64,
                body: Term::Region {
                    region: CAPTURE_REGION,
                    body: Box::new(Term::Let {
                        binder: LocalId(0),
                        ty: shared_i64_ref(),
                        value: RValue::RefAlloc {
                            region: CAPTURE_REGION,
                            mutability: Mutability::Shared,
                            value: Operand::I64(0),
                        },
                        next: Box::new(Term::Let {
                            binder: LocalId(1),
                            ty: closure_type(vec![Type::I64], state_effect(), Type::I64),
                            value: RValue::PackClosure {
                                function: FunctionId(1),
                                captures: vec![Operand::Local(LocalId(0))],
                            },
                            next: Box::new(Term::Let {
                                binder: LocalId(2),
                                ty: Type::I64,
                                value: RValue::CallClosure {
                                    closure: Operand::Local(LocalId(1)),
                                    arguments: vec![Operand::I64(3)],
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
            },
            Function {
                id: FunctionId(1),
                region_parameters: vec![CAPTURE_REGION],
                parameters: vec![
                    Parameter {
                        local: LocalId(0),
                        ty: Type::Tuple(vec![shared_i64_ref()]),
                    },
                    Parameter {
                        local: LocalId(1),
                        ty: Type::I64,
                    },
                ],
                effects: state_effect(),
                result: Type::I64,
                body: Term::Let {
                    binder: LocalId(2),
                    ty: shared_i64_ref(),
                    value: RValue::Project {
                        tuple: Operand::Local(LocalId(0)),
                        index: 0,
                    },
                    next: Box::new(Term::Let {
                        binder: LocalId(3),
                        ty: Type::Bool,
                        value: RValue::Primitive {
                            operation: Primitive::I64CmpGe,
                            arguments: vec![Operand::Local(LocalId(1)), Operand::I64(1)],
                        },
                        next: Box::new(Term::If {
                            condition: Operand::Local(LocalId(3)),
                            then_term: Box::new(Term::Let {
                                binder: LocalId(4),
                                ty: Type::I64,
                                value: RValue::RefLoad {
                                    reference: Operand::Local(LocalId(2)),
                                },
                                next: Box::new(Term::Let {
                                    binder: LocalId(5),
                                    ty: Type::I64,
                                    value: RValue::Primitive {
                                        operation: Primitive::I64Add(NumericMode::Wrapping),
                                        arguments: vec![
                                            Operand::Local(LocalId(4)),
                                            Operand::I64(1),
                                        ],
                                    },
                                    next: Box::new(Term::Let {
                                        binder: LocalId(6),
                                        ty: Type::Unit,
                                        value: RValue::RefStore {
                                            reference: Operand::Local(LocalId(2)),
                                            value: Operand::Local(LocalId(5)),
                                        },
                                        next: Box::new(Term::Let {
                                            binder: LocalId(7),
                                            ty: Type::I64,
                                            value: RValue::Primitive {
                                                operation: Primitive::I64Sub(NumericMode::Wrapping),
                                                arguments: vec![
                                                    Operand::Local(LocalId(1)),
                                                    Operand::I64(1),
                                                ],
                                            },
                                            next: Box::new(Term::Let {
                                                binder: LocalId(8),
                                                ty: Type::I64,
                                                value: RValue::Call {
                                                    function: FunctionId(1),
                                                    arguments: vec![
                                                        Operand::Local(LocalId(0)),
                                                        Operand::Local(LocalId(7)),
                                                    ],
                                                },
                                                next: Box::new(Term::Return(Operand::Local(
                                                    LocalId(8),
                                                ))),
                                            }),
                                        }),
                                    }),
                                }),
                            }),
                            else_term: Box::new(Term::Let {
                                binder: LocalId(9),
                                ty: Type::I64,
                                value: RValue::RefLoad {
                                    reference: Operand::Local(LocalId(2)),
                                },
                                next: Box::new(Term::Return(Operand::Local(LocalId(9)))),
                            }),
                        }),
                    }),
                },
            },
        ],
    )
}

#[test]
fn closure_call_matches_explicit_environment_direct_call() {
    let functions = value_closure_functions(vec![Operand::I64(40)]);
    let closure_artifact = seal(program(CoreProfile::P1V2, 0, functions.clone()));
    let direct_artifact = seal(program(CoreProfile::P1V2, 2, functions));

    verify(&closure_artifact).expect("closure artifact should verify");
    verify(&direct_artifact).expect("direct artifact should verify");
    let closure_result = evaluate(&closure_artifact, vec![], budget())
        .unwrap()
        .outcome;
    let direct_result = evaluate(&direct_artifact, vec![], budget())
        .unwrap()
        .outcome;
    assert_eq!(
        closure_result,
        EvaluationOutcome::Return(CoreValue::I64(42))
    );
    assert_eq!(closure_result, direct_result);
}

#[test]
fn empty_environment_is_an_explicit_empty_tuple() {
    let identity_type = closure_type(vec![Type::Bool], EffectRow::pure(), Type::Bool);
    let artifact = seal(program(
        CoreProfile::P1V2,
        0,
        vec![
            Function {
                id: FunctionId(0),
                region_parameters: vec![],
                parameters: vec![],
                effects: EffectRow::pure(),
                result: Type::Bool,
                body: Term::Let {
                    binder: LocalId(0),
                    ty: identity_type,
                    value: RValue::PackClosure {
                        function: FunctionId(1),
                        captures: vec![],
                    },
                    next: Box::new(Term::Let {
                        binder: LocalId(1),
                        ty: Type::Bool,
                        value: RValue::CallClosure {
                            closure: Operand::Local(LocalId(0)),
                            arguments: vec![Operand::Bool(true)],
                        },
                        next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
                    }),
                },
            },
            Function {
                id: FunctionId(1),
                region_parameters: vec![],
                parameters: vec![
                    Parameter {
                        local: LocalId(0),
                        ty: Type::Tuple(vec![]),
                    },
                    Parameter {
                        local: LocalId(1),
                        ty: Type::Bool,
                    },
                ],
                effects: EffectRow::pure(),
                result: Type::Bool,
                body: Term::Return(Operand::Local(LocalId(1))),
            },
        ],
    ));

    assert_eq!(
        evaluate(&artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::Bool(true))
    );
}

#[test]
fn capture_order_is_semantic_and_hash_visible() {
    fn ordered(captures: Vec<Operand>) -> CoreArtifact {
        seal(program(
            CoreProfile::P1V2,
            0,
            vec![
                Function {
                    id: FunctionId(0),
                    region_parameters: vec![],
                    parameters: vec![],
                    effects: EffectRow::pure(),
                    result: Type::I64,
                    body: Term::Let {
                        binder: LocalId(0),
                        ty: closure_type(vec![], EffectRow::pure(), Type::I64),
                        value: RValue::PackClosure {
                            function: FunctionId(1),
                            captures,
                        },
                        next: Box::new(Term::Let {
                            binder: LocalId(1),
                            ty: Type::I64,
                            value: RValue::CallClosure {
                                closure: Operand::Local(LocalId(0)),
                                arguments: vec![],
                            },
                            next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
                        }),
                    },
                },
                Function {
                    id: FunctionId(1),
                    region_parameters: vec![],
                    parameters: vec![Parameter {
                        local: LocalId(0),
                        ty: Type::Tuple(vec![Type::I64, Type::I64]),
                    }],
                    effects: EffectRow::pure(),
                    result: Type::I64,
                    body: Term::Let {
                        binder: LocalId(1),
                        ty: Type::I64,
                        value: RValue::Project {
                            tuple: Operand::Local(LocalId(0)),
                            index: 0,
                        },
                        next: Box::new(Term::Let {
                            binder: LocalId(2),
                            ty: Type::I64,
                            value: RValue::Project {
                                tuple: Operand::Local(LocalId(0)),
                                index: 1,
                            },
                            next: Box::new(Term::Let {
                                binder: LocalId(3),
                                ty: Type::I64,
                                value: RValue::Primitive {
                                    operation: Primitive::I64Sub(NumericMode::Wrapping),
                                    arguments: vec![
                                        Operand::Local(LocalId(1)),
                                        Operand::Local(LocalId(2)),
                                    ],
                                },
                                next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
                            }),
                        }),
                    },
                },
            ],
        ))
    }

    let forward = ordered(vec![Operand::I64(10), Operand::I64(3)]);
    let reverse = ordered(vec![Operand::I64(3), Operand::I64(10)]);
    assert_eq!(
        evaluate(&forward, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(7))
    );
    assert_eq!(
        evaluate(&reverse, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(-7))
    );
    assert_ne!(forward.semantic_hash, reverse.semantic_hash);
}

#[test]
fn captured_reference_alias_and_recursive_environment_share_the_creator_store() {
    let artifact = seal(recursive_reference_closure_program(state_alloc_effects()));
    verify(&artifact).expect("captured-reference closure should verify");

    assert_eq!(
        evaluate(&artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(3))
    );
    let depth_error = evaluate(&artifact, vec![], EvaluationBudget::new(20_000, 2))
        .expect_err("recursive environment calls must obey call depth");
    assert!(matches!(
        depth_error,
        naux::core::ExecutionError::CallDepthExceeded { limit: 2 }
    ));
    let step_error = evaluate(&artifact, vec![], EvaluationBudget::new(6, 64))
        .expect_err("closure evaluation must obey the global step budget");
    assert!(matches!(
        step_error,
        naux::core::ExecutionError::StepBudgetExceeded { limit: 6 }
    ));
}

#[test]
fn p1v0_and_p1v1_remain_closed_to_closure_constructs() {
    for profile in [CoreProfile::P1V0, CoreProfile::P1V1] {
        let artifact = seal(program(
            profile,
            0,
            value_closure_functions(vec![Operand::I64(40)]),
        ));
        let errors = verify(&artifact).expect_err("older profile must not silently widen");
        assert!(errors
            .0
            .iter()
            .any(|error| error.code == VerificationCode::UnsupportedProfileFeature));
    }
}

#[test]
fn closure_environment_and_call_types_fail_closed() {
    let mut wrong_environment = program(
        CoreProfile::P1V2,
        0,
        value_closure_functions(vec![Operand::Bool(true)]),
    );
    wrong_environment.functions[0].body = match wrong_environment.functions[0].body.clone() {
        Term::Let { next, .. } => Term::Let {
            binder: LocalId(0),
            ty: closure_type(vec![Type::I64], EffectRow::pure(), Type::I64),
            value: RValue::PackClosure {
                function: FunctionId(1),
                captures: vec![Operand::Bool(true)],
            },
            next,
        },
        _ => unreachable!("fixture starts with a closure pack"),
    };
    let environment_errors =
        verify(&seal(wrong_environment)).expect_err("environment type mismatch must fail");
    assert!(environment_errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::TypeMismatch));

    let mut wrong_argument = program(
        CoreProfile::P1V2,
        0,
        value_closure_functions(vec![Operand::I64(40)]),
    );
    if let Term::Let { next, .. } = &mut wrong_argument.functions[0].body {
        if let Term::Let {
            value: RValue::CallClosure { arguments, .. },
            ..
        } = next.as_mut()
        {
            *arguments = vec![Operand::Bool(true)];
        }
    }
    let argument_errors =
        verify(&seal(wrong_argument)).expect_err("closure argument mismatch must fail");
    assert!(argument_errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::TypeMismatch));

    let mut wrong_arity = program(
        CoreProfile::P1V2,
        0,
        value_closure_functions(vec![Operand::I64(40)]),
    );
    if let Term::Let { next, .. } = &mut wrong_arity.functions[0].body {
        if let Term::Let {
            value: RValue::CallClosure { arguments, .. },
            ..
        } = next.as_mut()
        {
            arguments.clear();
        }
    }
    let arity_errors = verify(&seal(wrong_arity)).expect_err("closure arity mismatch must fail");
    assert!(arity_errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::InvalidCall));

    let non_closure = seal(program(
        CoreProfile::P1V2,
        0,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(0),
                ty: Type::I64,
                value: RValue::CallClosure {
                    closure: Operand::I64(1),
                    arguments: vec![],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
            },
        }],
    ));
    let call_errors = verify(&non_closure).expect_err("non-closure call must fail");
    assert!(call_errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::TypeMismatch));
}

#[test]
fn missing_code_function_or_environment_parameter_fails_closed() {
    let missing = seal(program(
        CoreProfile::P1V2,
        0,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::Unit,
            body: Term::Let {
                binder: LocalId(0),
                ty: closure_type(vec![], EffectRow::pure(), Type::Unit),
                value: RValue::PackClosure {
                    function: FunctionId(99),
                    captures: vec![],
                },
                next: Box::new(Term::Return(Operand::Unit)),
            },
        }],
    ));
    let missing_errors = verify(&missing).expect_err("missing closure code must fail");
    assert!(missing_errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::InvalidCall));

    let no_environment = seal(program(
        CoreProfile::P1V2,
        0,
        vec![
            Function {
                id: FunctionId(0),
                region_parameters: vec![],
                parameters: vec![],
                effects: EffectRow::pure(),
                result: Type::Unit,
                body: Term::Let {
                    binder: LocalId(0),
                    ty: closure_type(vec![], EffectRow::pure(), Type::Unit),
                    value: RValue::PackClosure {
                        function: FunctionId(1),
                        captures: vec![],
                    },
                    next: Box::new(Term::Return(Operand::Unit)),
                },
            },
            Function {
                id: FunctionId(1),
                region_parameters: vec![],
                parameters: vec![],
                effects: EffectRow::pure(),
                result: Type::Unit,
                body: Term::Return(Operand::Unit),
            },
        ],
    ));
    let environment_errors =
        verify(&no_environment).expect_err("hidden environment parameter is mandatory");
    assert!(environment_errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::InvalidCall));
}

#[test]
fn closure_effects_must_propagate_to_the_caller() {
    let artifact = seal(recursive_reference_closure_program(EffectRow::canonical(
        vec![Effect::Alloc(CAPTURE_REGION)],
    )));
    let errors = verify(&artifact).expect_err("missing State effect must fail closed");
    assert!(errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::MissingEffect));
}

#[test]
fn closures_and_references_cannot_escape_or_enter_through_forbidden_boundaries() {
    let escaped_closure_type = closure_type(vec![], EffectRow::pure(), Type::Unit);
    let closure_escape = seal(program(
        CoreProfile::P1V2,
        0,
        vec![
            Function {
                id: FunctionId(0),
                region_parameters: vec![],
                parameters: vec![],
                effects: EffectRow::pure(),
                result: closure_type(vec![], EffectRow::pure(), Type::Unit),
                body: Term::Let {
                    binder: LocalId(0),
                    ty: closure_type(vec![], EffectRow::pure(), Type::Unit),
                    value: RValue::PackClosure {
                        function: FunctionId(1),
                        captures: vec![],
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
                },
            },
            Function {
                id: FunctionId(1),
                region_parameters: vec![],
                parameters: vec![Parameter {
                    local: LocalId(0),
                    ty: Type::Tuple(vec![]),
                }],
                effects: EffectRow::pure(),
                result: Type::Unit,
                body: Term::Return(Operand::Unit),
            },
        ],
    ));
    let nested_closure_parameter = seal(program(
        CoreProfile::P1V2,
        0,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(0),
                ty: Type::Tuple(vec![escaped_closure_type]),
            }],
            effects: EffectRow::pure(),
            result: Type::Unit,
            body: Term::Return(Operand::Unit),
        }],
    ));
    let reference_entry = seal(program(
        CoreProfile::P1V2,
        0,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![CAPTURE_REGION],
            parameters: vec![Parameter {
                local: LocalId(0),
                ty: shared_i64_ref(),
            }],
            effects: EffectRow::pure(),
            result: Type::Unit,
            body: Term::Return(Operand::Unit),
        }],
    ));
    let reference_result = seal(program(
        CoreProfile::P1V2,
        0,
        vec![
            Function {
                id: FunctionId(0),
                region_parameters: vec![],
                parameters: vec![],
                effects: EffectRow::pure(),
                result: Type::Unit,
                body: Term::Return(Operand::Unit),
            },
            Function {
                id: FunctionId(1),
                region_parameters: vec![CAPTURE_REGION],
                parameters: vec![Parameter {
                    local: LocalId(0),
                    ty: shared_i64_ref(),
                }],
                effects: EffectRow::pure(),
                result: shared_i64_ref(),
                body: Term::Return(Operand::Local(LocalId(0))),
            },
        ],
    ));

    for artifact in [
        closure_escape,
        nested_closure_parameter,
        reference_entry,
        reference_result,
    ] {
        let errors = verify(&artifact).expect_err("forbidden boundary must fail closed");
        assert!(errors
            .0
            .iter()
            .any(|error| error.code == VerificationCode::UnsupportedProfileFeature));
    }
}

#[test]
fn captured_reference_regions_must_be_active_and_declared_by_closure_code() {
    let mut inactive = recursive_reference_closure_program(state_alloc_effects());
    inactive.functions[0].body = match inactive.functions[0].body.clone() {
        Term::Region { body, .. } => *body,
        _ => unreachable!("fixture starts with a lexical region"),
    };
    let inactive_errors =
        verify(&seal(inactive)).expect_err("inactive captured reference must fail");
    assert!(inactive_errors.0.iter().any(|error| {
        error.code == VerificationCode::InvalidType
            && error.path.contains("captures[0]")
            && error.message.contains("not active")
    }));

    let mut undeclared = recursive_reference_closure_program(state_alloc_effects());
    undeclared.functions[1].region_parameters.clear();
    undeclared.functions[1].effects = EffectRow::pure();
    let undeclared_errors =
        verify(&seal(undeclared)).expect_err("closure code must declare captured regions");
    assert!(undeclared_errors.0.iter().any(|error| {
        error.code == VerificationCode::InvalidType
            && error.path.contains("functions[1].parameters[0].type")
            && error.message.contains("undeclared region")
    }));
}

#[test]
fn nested_closure_capture_and_borrowed_tail_transfer_fail_closed() {
    let nested_type = closure_type(vec![], EffectRow::pure(), Type::Unit);
    let nested = seal(program(
        CoreProfile::P1V2,
        0,
        vec![
            Function {
                id: FunctionId(0),
                region_parameters: vec![],
                parameters: vec![],
                effects: EffectRow::pure(),
                result: Type::Unit,
                body: Term::Let {
                    binder: LocalId(0),
                    ty: nested_type.clone(),
                    value: RValue::PackClosure {
                        function: FunctionId(1),
                        captures: vec![],
                    },
                    next: Box::new(Term::Let {
                        binder: LocalId(1),
                        ty: nested_type.clone(),
                        value: RValue::PackClosure {
                            function: FunctionId(2),
                            captures: vec![Operand::Local(LocalId(0))],
                        },
                        next: Box::new(Term::Return(Operand::Unit)),
                    }),
                },
            },
            Function {
                id: FunctionId(1),
                region_parameters: vec![],
                parameters: vec![Parameter {
                    local: LocalId(0),
                    ty: Type::Tuple(vec![]),
                }],
                effects: EffectRow::pure(),
                result: Type::Unit,
                body: Term::Return(Operand::Unit),
            },
            Function {
                id: FunctionId(2),
                region_parameters: vec![],
                parameters: vec![Parameter {
                    local: LocalId(0),
                    ty: Type::Tuple(vec![nested_type]),
                }],
                effects: EffectRow::pure(),
                result: Type::Unit,
                body: Term::Return(Operand::Unit),
            },
        ],
    ));
    let nested_errors = verify(&nested).expect_err("nested closure capture must fail");
    assert!(nested_errors
        .0
        .iter()
        .any(|error| error.message.contains("nested closure")));

    let borrowed_tail = seal(program(
        CoreProfile::P1V2,
        0,
        vec![
            Function {
                id: FunctionId(0),
                region_parameters: vec![CAPTURE_REGION],
                parameters: vec![],
                effects: EffectRow::canonical(vec![Effect::Alloc(CAPTURE_REGION)]),
                result: Type::Unit,
                body: Term::Region {
                    region: CAPTURE_REGION,
                    body: Box::new(Term::Let {
                        binder: LocalId(0),
                        ty: shared_i64_ref(),
                        value: RValue::RefAlloc {
                            region: CAPTURE_REGION,
                            mutability: Mutability::Shared,
                            value: Operand::I64(0),
                        },
                        next: Box::new(Term::TailCall {
                            function: FunctionId(1),
                            arguments: vec![Operand::Local(LocalId(0))],
                        }),
                    }),
                },
            },
            Function {
                id: FunctionId(1),
                region_parameters: vec![CAPTURE_REGION],
                parameters: vec![Parameter {
                    local: LocalId(0),
                    ty: shared_i64_ref(),
                }],
                effects: EffectRow::pure(),
                result: Type::Unit,
                body: Term::Return(Operand::Unit),
            },
        ],
    ));
    let tail_errors = verify(&borrowed_tail).expect_err("borrowed tail transfer must fail");
    assert!(tail_errors
        .0
        .iter()
        .any(|error| error.message.contains("tail calls")));
}

#[test]
fn p1v2_hash_is_deterministic_and_tamper_evident() {
    let first = seal(program(
        CoreProfile::P1V2,
        0,
        value_closure_functions(vec![Operand::I64(40)]),
    ));
    let second = seal(program(
        CoreProfile::P1V2,
        0,
        value_closure_functions(vec![Operand::I64(40)]),
    ));
    assert_eq!(first.semantic_hash, second.semantic_hash);
    assert_eq!(
        semantic_bytes(&first.program).unwrap(),
        semantic_bytes(&second.program).unwrap()
    );
    assert_eq!(
        first.semantic_hash.to_hex(),
        "ba1613399e67b828b1e629ace2236d492ae86b01d7a2c8ecd7304d27ae763e75"
    );

    let mut tampered = first.clone();
    if let Term::Let {
        value: RValue::PackClosure { captures, .. },
        ..
    } = &mut tampered.program.functions[0].body
    {
        captures[0] = Operand::I64(41);
    }
    let errors = verify(&tampered).expect_err("closure tampering must fail closed");
    assert!(errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::SemanticHashMismatch));
    assert_ne!(first.semantic_hash, SemanticHash::ZERO);
}
