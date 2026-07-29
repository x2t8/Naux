use naux::core::{
    evaluate, semantic_bytes, verify, CoreArtifact, CoreProfile, CoreValue, Effect, EffectRow,
    ErrorKind, EvaluationBudget, EvaluationOutcome, Function, FunctionId, LocalId, Mutability,
    NumericMode, Operand, Parameter, Primitive, Program, RValue, RegionId, SchemaVersion,
    SemanticHash, Term, Type, VerificationCode,
};

const STORE_REGION: RegionId = RegionId(0);
const INNER_REGION: RegionId = RegionId(1);

fn budget() -> EvaluationBudget {
    EvaluationBudget::new(30_000, 64)
}

fn unique_ref(region: RegionId, element: Type) -> Type {
    Type::Ref {
        region,
        mutability: Mutability::Unique,
        element: Box::new(element),
    }
}

fn unique_i64_ref() -> Type {
    unique_ref(STORE_REGION, Type::I64)
}

fn shared_i64_ref() -> Type {
    Type::Ref {
        region: STORE_REGION,
        mutability: Mutability::Shared,
        element: Box::new(Type::I64),
    }
}

fn store_effects() -> EffectRow {
    EffectRow::canonical(vec![
        Effect::State(STORE_REGION),
        Effect::Alloc(STORE_REGION),
    ])
}

fn caller_effects(callee: &EffectRow) -> EffectRow {
    let mut effects = store_effects().effects;
    effects.extend(callee.effects.iter().cloned());
    EffectRow::canonical(effects)
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

fn has_code(artifact: &CoreArtifact, code: VerificationCode) -> bool {
    verify(artifact)
        .expect_err("fixture should fail verification")
        .0
        .iter()
        .any(|error| error.code == code)
}

fn mutating_return_body(value: i64) -> Term {
    Term::Let {
        binder: LocalId(1),
        ty: Type::Unit,
        value: RValue::RefStore {
            reference: Operand::Local(LocalId(0)),
            value: Operand::I64(value),
        },
        next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
    }
}

fn round_trip_program(
    profile: CoreProfile,
    callee_body: Term,
    callee_effects: EffectRow,
    caller_move_source: LocalId,
) -> Program {
    program(
        profile,
        vec![
            Function {
                id: FunctionId(0),
                region_parameters: vec![STORE_REGION],
                parameters: vec![],
                effects: caller_effects(&callee_effects),
                result: Type::I64,
                body: Term::Region {
                    region: STORE_REGION,
                    body: Box::new(Term::Let {
                        binder: LocalId(0),
                        ty: unique_i64_ref(),
                        value: RValue::RefAlloc {
                            region: STORE_REGION,
                            mutability: Mutability::Unique,
                            value: Operand::I64(1),
                        },
                        next: Box::new(Term::Let {
                            binder: LocalId(1),
                            ty: unique_i64_ref(),
                            value: RValue::Call {
                                function: FunctionId(1),
                                arguments: vec![Operand::Local(LocalId(0))],
                            },
                            next: Box::new(Term::Let {
                                binder: LocalId(2),
                                ty: unique_i64_ref(),
                                value: RValue::Use(Operand::Local(caller_move_source)),
                                next: Box::new(Term::Let {
                                    binder: LocalId(3),
                                    ty: Type::I64,
                                    value: RValue::RefLoad {
                                        reference: Operand::Local(LocalId(2)),
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
                region_parameters: vec![STORE_REGION],
                parameters: vec![Parameter {
                    local: LocalId(0),
                    ty: unique_i64_ref(),
                }],
                effects: callee_effects,
                result: unique_i64_ref(),
                body: callee_body,
            },
        ],
    )
}

fn unused_bad_function(function: Function) -> Program {
    program(
        CoreProfile::P1V5,
        vec![
            Function {
                id: FunctionId(0),
                region_parameters: vec![],
                parameters: vec![],
                effects: EffectRow::pure(),
                result: Type::I64,
                body: Term::Return(Operand::I64(0)),
            },
            function,
        ],
    )
}

#[test]
fn direct_call_returns_one_live_owner_to_the_caller() {
    let artifact = seal(round_trip_program(
        CoreProfile::P1V5,
        mutating_return_body(41),
        EffectRow::canonical(vec![Effect::State(STORE_REGION)]),
        LocalId(1),
    ));
    verify(&artifact).expect("anchored owner return should verify");
    assert_eq!(
        evaluate(&artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(41))
    );
}

#[test]
fn caller_source_and_returned_source_each_move_exactly_once() {
    let revived_caller_source = seal(round_trip_program(
        CoreProfile::P1V5,
        mutating_return_body(2),
        EffectRow::canonical(vec![Effect::State(STORE_REGION)]),
        LocalId(0),
    ));
    assert!(has_code(
        &revived_caller_source,
        VerificationCode::OwnershipViolation
    ));

    let return_after_move = seal(round_trip_program(
        CoreProfile::P1V5,
        Term::Let {
            binder: LocalId(1),
            ty: unique_i64_ref(),
            value: RValue::Use(Operand::Local(LocalId(0))),
            next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
        },
        EffectRow::pure(),
        LocalId(1),
    ));
    assert!(has_code(
        &return_after_move,
        VerificationCode::OwnershipViolation
    ));
}

#[test]
fn callee_may_return_a_fresh_replacement_in_the_anchored_region() {
    let artifact = seal(round_trip_program(
        CoreProfile::P1V5,
        Term::Let {
            binder: LocalId(1),
            ty: unique_i64_ref(),
            value: RValue::RefAlloc {
                region: STORE_REGION,
                mutability: Mutability::Unique,
                value: Operand::I64(99),
            },
            next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
        },
        EffectRow::canonical(vec![Effect::Alloc(STORE_REGION)]),
        LocalId(1),
    ));
    assert_eq!(
        evaluate(&artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(99))
    );
}

#[test]
fn mutually_exclusive_branches_return_the_owner_independently() {
    let artifact = seal(program(
        CoreProfile::P1V5,
        vec![
            Function {
                id: FunctionId(0),
                region_parameters: vec![STORE_REGION],
                parameters: vec![],
                effects: store_effects(),
                result: Type::I64,
                body: Term::Region {
                    region: STORE_REGION,
                    body: Box::new(Term::Let {
                        binder: LocalId(0),
                        ty: unique_i64_ref(),
                        value: RValue::RefAlloc {
                            region: STORE_REGION,
                            mutability: Mutability::Unique,
                            value: Operand::I64(17),
                        },
                        next: Box::new(Term::Let {
                            binder: LocalId(1),
                            ty: unique_i64_ref(),
                            value: RValue::Call {
                                function: FunctionId(1),
                                arguments: vec![Operand::Local(LocalId(0)), Operand::Bool(false)],
                            },
                            next: Box::new(Term::Let {
                                binder: LocalId(2),
                                ty: Type::I64,
                                value: RValue::RefLoad {
                                    reference: Operand::Local(LocalId(1)),
                                },
                                next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
                            }),
                        }),
                    }),
                },
            },
            Function {
                id: FunctionId(1),
                region_parameters: vec![STORE_REGION],
                parameters: vec![
                    Parameter {
                        local: LocalId(0),
                        ty: unique_i64_ref(),
                    },
                    Parameter {
                        local: LocalId(1),
                        ty: Type::Bool,
                    },
                ],
                effects: EffectRow::pure(),
                result: unique_i64_ref(),
                body: Term::If {
                    condition: Operand::Local(LocalId(1)),
                    then_term: Box::new(Term::Return(Operand::Local(LocalId(0)))),
                    else_term: Box::new(Term::Let {
                        binder: LocalId(2),
                        ty: unique_i64_ref(),
                        value: RValue::Use(Operand::Local(LocalId(0))),
                        next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
                    }),
                },
            },
        ],
    ));
    verify(&artifact).expect("each terminal branch returns one live owner");
    assert_eq!(
        evaluate(&artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(17))
    );
}

#[test]
fn tail_call_chain_returns_the_final_owner_in_the_same_store() {
    let state = EffectRow::canonical(vec![Effect::State(STORE_REGION)]);
    let artifact = seal(program(
        CoreProfile::P1V5,
        vec![
            Function {
                id: FunctionId(0),
                region_parameters: vec![STORE_REGION],
                parameters: vec![],
                effects: store_effects(),
                result: Type::I64,
                body: Term::Region {
                    region: STORE_REGION,
                    body: Box::new(Term::Let {
                        binder: LocalId(0),
                        ty: unique_i64_ref(),
                        value: RValue::RefAlloc {
                            region: STORE_REGION,
                            mutability: Mutability::Unique,
                            value: Operand::I64(1),
                        },
                        next: Box::new(Term::Let {
                            binder: LocalId(1),
                            ty: unique_i64_ref(),
                            value: RValue::Call {
                                function: FunctionId(1),
                                arguments: vec![Operand::Local(LocalId(0))],
                            },
                            next: Box::new(Term::Let {
                                binder: LocalId(2),
                                ty: Type::I64,
                                value: RValue::RefLoad {
                                    reference: Operand::Local(LocalId(1)),
                                },
                                next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
                            }),
                        }),
                    }),
                },
            },
            Function {
                id: FunctionId(1),
                region_parameters: vec![STORE_REGION],
                parameters: vec![Parameter {
                    local: LocalId(0),
                    ty: unique_i64_ref(),
                }],
                effects: state.clone(),
                result: unique_i64_ref(),
                body: Term::TailCall {
                    function: FunctionId(2),
                    arguments: vec![Operand::Local(LocalId(0))],
                },
            },
            Function {
                id: FunctionId(2),
                region_parameters: vec![STORE_REGION],
                parameters: vec![Parameter {
                    local: LocalId(0),
                    ty: unique_i64_ref(),
                }],
                effects: state,
                result: unique_i64_ref(),
                body: mutating_return_body(55),
            },
        ],
    ));
    assert_eq!(
        evaluate(&artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(55))
    );
}

#[test]
fn ownership_result_requires_exactly_one_matching_direct_unique_anchor() {
    let bad_functions = vec![
        Function {
            id: FunctionId(1),
            region_parameters: vec![STORE_REGION],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: unique_i64_ref(),
            body: Term::Return(Operand::I64(0)),
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![STORE_REGION],
            parameters: vec![Parameter {
                local: LocalId(0),
                ty: shared_i64_ref(),
            }],
            effects: EffectRow::pure(),
            result: unique_i64_ref(),
            body: Term::Return(Operand::Local(LocalId(0))),
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![STORE_REGION],
            parameters: vec![
                Parameter {
                    local: LocalId(0),
                    ty: unique_i64_ref(),
                },
                Parameter {
                    local: LocalId(1),
                    ty: unique_i64_ref(),
                },
            ],
            effects: EffectRow::pure(),
            result: unique_i64_ref(),
            body: Term::Return(Operand::Local(LocalId(0))),
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![STORE_REGION],
            parameters: vec![Parameter {
                local: LocalId(0),
                ty: unique_ref(STORE_REGION, Type::Bool),
            }],
            effects: EffectRow::pure(),
            result: unique_i64_ref(),
            body: Term::Return(Operand::Local(LocalId(0))),
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![STORE_REGION],
            parameters: vec![Parameter {
                local: LocalId(0),
                ty: Type::Tuple(vec![shared_i64_ref()]),
            }],
            effects: EffectRow::pure(),
            result: unique_i64_ref(),
            body: Term::Return(Operand::I64(0)),
        },
    ];

    for function in bad_functions {
        assert!(has_code(
            &seal(unused_bad_function(function)),
            VerificationCode::UnsupportedProfileFeature
        ));
    }
}

#[test]
fn unanchored_closed_region_and_entry_result_escape_fail_closed() {
    let closed_region = seal(unused_bad_function(Function {
        id: FunctionId(1),
        region_parameters: vec![STORE_REGION],
        parameters: vec![],
        effects: EffectRow::canonical(vec![Effect::Alloc(STORE_REGION)]),
        result: unique_i64_ref(),
        body: Term::Region {
            region: STORE_REGION,
            body: Box::new(Term::Let {
                binder: LocalId(0),
                ty: unique_i64_ref(),
                value: RValue::RefAlloc {
                    region: STORE_REGION,
                    mutability: Mutability::Unique,
                    value: Operand::I64(1),
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
            }),
        },
    }));
    assert!(has_code(
        &closed_region,
        VerificationCode::UnsupportedProfileFeature
    ));

    let entry_result = seal(program(
        CoreProfile::P1V5,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![STORE_REGION],
            parameters: vec![],
            effects: EffectRow::canonical(vec![Effect::Alloc(STORE_REGION)]),
            result: unique_i64_ref(),
            body: Term::Region {
                region: STORE_REGION,
                body: Box::new(Term::Let {
                    binder: LocalId(0),
                    ty: unique_i64_ref(),
                    value: RValue::RefAlloc {
                        region: STORE_REGION,
                        mutability: Mutability::Unique,
                        value: Operand::I64(1),
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
                }),
            },
        }],
    ));
    assert!(has_code(
        &entry_result,
        VerificationCode::UnsupportedProfileFeature
    ));
}

#[test]
fn older_profiles_remain_closed_to_ownership_results() {
    for profile in [
        CoreProfile::P1V0,
        CoreProfile::P1V1,
        CoreProfile::P1V2,
        CoreProfile::P1V3,
        CoreProfile::P1V4,
    ] {
        let artifact = seal(round_trip_program(
            profile,
            mutating_return_body(3),
            EffectRow::canonical(vec![Effect::State(STORE_REGION)]),
            LocalId(1),
        ));
        assert!(
            has_code(&artifact, VerificationCode::UnsupportedProfileFeature),
            "{profile:?} must not silently admit ownership return"
        );
    }
}

#[test]
fn aggregate_ownership_remains_rejected_in_p1v5() {
    let aggregate = seal(unused_bad_function(Function {
        id: FunctionId(1),
        region_parameters: vec![STORE_REGION],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: unique_i64_ref(),
        }],
        effects: EffectRow::pure(),
        result: Type::Tuple(vec![unique_i64_ref()]),
        body: Term::Let {
            binder: LocalId(1),
            ty: Type::Tuple(vec![unique_i64_ref()]),
            value: RValue::Tuple(vec![Operand::Local(LocalId(0))]),
            next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
        },
    }));
    assert!(has_code(
        &aggregate,
        VerificationCode::UnsupportedProfileFeature
    ));
}

#[test]
fn typed_error_and_budget_paths_return_no_owner() {
    let error_effects = EffectRow::canonical(vec![Effect::Error(ErrorKind::Overflow)]);
    let overflow = seal(round_trip_program(
        CoreProfile::P1V5,
        Term::Let {
            binder: LocalId(1),
            ty: Type::I64,
            value: RValue::Primitive {
                operation: Primitive::I64Add(NumericMode::Checked),
                arguments: vec![Operand::I64(i64::MAX), Operand::I64(1)],
            },
            next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
        },
        error_effects,
        LocalId(1),
    ));
    assert_eq!(
        evaluate(&overflow, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Error(ErrorKind::Overflow)
    );

    let successful = seal(round_trip_program(
        CoreProfile::P1V5,
        mutating_return_body(1),
        EffectRow::canonical(vec![Effect::State(STORE_REGION)]),
        LocalId(1),
    ));
    let budget_error = evaluate(&successful, vec![], EvaluationBudget::new(3, 64))
        .expect_err("ownership-return execution must respect exact budgets");
    assert!(matches!(
        budget_error,
        naux::core::ExecutionError::StepBudgetExceeded { limit: 3 }
    ));
}

#[test]
fn p1v5_hash_is_deterministic_and_tamper_evident() {
    let first = seal(round_trip_program(
        CoreProfile::P1V5,
        mutating_return_body(41),
        EffectRow::canonical(vec![Effect::State(STORE_REGION)]),
        LocalId(1),
    ));
    let second = seal(round_trip_program(
        CoreProfile::P1V5,
        mutating_return_body(41),
        EffectRow::canonical(vec![Effect::State(STORE_REGION)]),
        LocalId(1),
    ));
    assert_eq!(first.semantic_hash, second.semantic_hash);
    assert_eq!(
        semantic_bytes(&first.program).unwrap(),
        semantic_bytes(&second.program).unwrap()
    );
    assert_eq!(
        first.semantic_hash.to_hex(),
        "09006d69756a52fd1fe1dfc36cd198d1a40122a5201fbcfe73ccd6d538a9290a"
    );

    let mut tampered = first.clone();
    let Term::Let {
        value: RValue::RefStore { value, .. },
        ..
    } = &mut tampered.program.functions[1].body
    else {
        unreachable!("fixture callee starts with a store");
    };
    *value = Operand::I64(42);
    assert!(has_code(&tampered, VerificationCode::SemanticHashMismatch));
    assert_ne!(first.semantic_hash, SemanticHash::ZERO);
}

#[test]
fn different_nested_region_cannot_satisfy_the_anchored_result_type() {
    let artifact = seal(unused_bad_function(Function {
        id: FunctionId(1),
        region_parameters: vec![STORE_REGION, INNER_REGION],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: unique_i64_ref(),
        }],
        effects: EffectRow::canonical(vec![Effect::Alloc(INNER_REGION)]),
        result: unique_i64_ref(),
        body: Term::Region {
            region: INNER_REGION,
            body: Box::new(Term::Let {
                binder: LocalId(1),
                ty: unique_ref(INNER_REGION, Type::I64),
                value: RValue::RefAlloc {
                    region: INNER_REGION,
                    mutability: Mutability::Unique,
                    value: Operand::I64(5),
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
            }),
        },
    }));
    assert!(has_code(&artifact, VerificationCode::TypeMismatch));
}
