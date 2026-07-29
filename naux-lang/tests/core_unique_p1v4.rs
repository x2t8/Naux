use naux::core::{
    evaluate, semantic_bytes, verify, ConstructorType, CoreArtifact, CoreProfile, CoreValue,
    Effect, EffectRow, ErrorKind, EvaluationBudget, EvaluationOutcome, Function, FunctionId,
    LocalId, Mutability, NumericMode, Operand, Parameter, Primitive, Program, RValue, RegionId,
    SchemaVersion, SemanticHash, SumType, Term, Type, VerificationCode,
};

const STORE_REGION: RegionId = RegionId(0);

fn budget() -> EvaluationBudget {
    EvaluationBudget::new(20_000, 64)
}

fn store_effects() -> EffectRow {
    EffectRow::canonical(vec![
        Effect::State(STORE_REGION),
        Effect::Alloc(STORE_REGION),
    ])
}

fn unique_i64_ref() -> Type {
    Type::Ref {
        region: STORE_REGION,
        mutability: Mutability::Unique,
        element: Box::new(Type::I64),
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

fn unique_borrow_program(profile: CoreProfile) -> Program {
    program(
        profile,
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
                    ty: unique_i64_ref(),
                    value: RValue::RefAlloc {
                        region: STORE_REGION,
                        mutability: Mutability::Unique,
                        value: Operand::I64(1),
                    },
                    next: Box::new(Term::Let {
                        binder: LocalId(1),
                        ty: Type::I64,
                        value: RValue::RefLoad {
                            reference: Operand::Local(LocalId(0)),
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

fn unique_mutating_callee() -> Function {
    Function {
        id: FunctionId(1),
        region_parameters: vec![STORE_REGION],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: unique_i64_ref(),
        }],
        effects: EffectRow::canonical(vec![Effect::State(STORE_REGION)]),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(1),
            ty: Type::Unit,
            value: RValue::RefStore {
                reference: Operand::Local(LocalId(0)),
                value: Operand::I64(41),
            },
            next: Box::new(Term::Let {
                binder: LocalId(2),
                ty: Type::I64,
                value: RValue::RefLoad {
                    reference: Operand::Local(LocalId(0)),
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
            }),
        },
    }
}

fn direct_transfer_program(use_source_after_call: bool) -> Program {
    let next = if use_source_after_call {
        Term::Let {
            binder: LocalId(2),
            ty: Type::I64,
            value: RValue::RefLoad {
                reference: Operand::Local(LocalId(0)),
            },
            next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
        }
    } else {
        Term::Return(Operand::Local(LocalId(1)))
    };
    program(
        CoreProfile::P1V4,
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
                            ty: Type::I64,
                            value: RValue::Call {
                                function: FunctionId(1),
                                arguments: vec![Operand::Local(LocalId(0))],
                            },
                            next: Box::new(next),
                        }),
                    }),
                },
            },
            unique_mutating_callee(),
        ],
    )
}

fn tail_transfer_program(mutability: Mutability) -> Program {
    let reference_type = Type::Ref {
        region: STORE_REGION,
        mutability,
        element: Box::new(Type::I64),
    };
    program(
        CoreProfile::P1V4,
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
                        ty: reference_type.clone(),
                        value: RValue::RefAlloc {
                            region: STORE_REGION,
                            mutability,
                            value: Operand::I64(5),
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
                region_parameters: vec![STORE_REGION],
                parameters: vec![Parameter {
                    local: LocalId(0),
                    ty: reference_type,
                }],
                effects: EffectRow::canonical(vec![Effect::State(STORE_REGION)]),
                result: Type::I64,
                body: Term::Let {
                    binder: LocalId(1),
                    ty: Type::I64,
                    value: RValue::RefLoad {
                        reference: Operand::Local(LocalId(0)),
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
                },
            },
        ],
    )
}

fn has_code(artifact: &CoreArtifact, code: VerificationCode) -> bool {
    verify(artifact)
        .expect_err("fixture should fail verification")
        .0
        .iter()
        .any(|error| error.code == code)
}

#[test]
fn unique_load_and_store_borrow_without_consuming_the_owner() {
    let artifact = seal(unique_borrow_program(CoreProfile::P1V4));
    verify(&artifact).expect("repeated Unique borrows should verify");
    assert_eq!(
        evaluate(&artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(9))
    );
}

#[test]
fn use_moves_a_unique_owner_once() {
    let valid = seal(program(
        CoreProfile::P1V4,
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
                    ty: unique_i64_ref(),
                    value: RValue::RefAlloc {
                        region: STORE_REGION,
                        mutability: Mutability::Unique,
                        value: Operand::I64(1),
                    },
                    next: Box::new(Term::Let {
                        binder: LocalId(1),
                        ty: unique_i64_ref(),
                        value: RValue::Use(Operand::Local(LocalId(0))),
                        next: Box::new(Term::Let {
                            binder: LocalId(2),
                            ty: Type::Unit,
                            value: RValue::RefStore {
                                reference: Operand::Local(LocalId(1)),
                                value: Operand::I64(7),
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
        evaluate(&valid, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(7))
    );

    let mut moved_twice = valid.program.clone();
    let Term::Region { body, .. } = &mut moved_twice.functions[0].body else {
        unreachable!("fixture starts with a region");
    };
    let Term::Let { next, .. } = body.as_mut() else {
        unreachable!("fixture starts with an allocation");
    };
    let Term::Let { next, .. } = next.as_mut() else {
        unreachable!("fixture moves into local 1");
    };
    **next = Term::Let {
        binder: LocalId(2),
        ty: Type::I64,
        value: RValue::RefLoad {
            reference: Operand::Local(LocalId(0)),
        },
        next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
    };
    assert!(has_code(
        &seal(moved_twice),
        VerificationCode::OwnershipViolation
    ));
}

#[test]
fn duplicate_direct_call_argument_cannot_alias_one_unique_owner() {
    let artifact = seal(program(
        CoreProfile::P1V4,
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
                            value: Operand::I64(0),
                        },
                        next: Box::new(Term::Let {
                            binder: LocalId(1),
                            ty: Type::I64,
                            value: RValue::Call {
                                function: FunctionId(1),
                                arguments: vec![
                                    Operand::Local(LocalId(0)),
                                    Operand::Local(LocalId(0)),
                                ],
                            },
                            next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
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
                        ty: unique_i64_ref(),
                    },
                ],
                effects: EffectRow::pure(),
                result: Type::I64,
                body: Term::Return(Operand::I64(0)),
            },
        ],
    ));
    assert!(has_code(&artifact, VerificationCode::OwnershipViolation));
}

#[test]
fn direct_call_transfers_the_unique_owner_and_invalidates_the_source() {
    let valid = seal(direct_transfer_program(false));
    assert_eq!(
        evaluate(&valid, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(41))
    );

    let invalid = seal(direct_transfer_program(true));
    assert!(has_code(&invalid, VerificationCode::OwnershipViolation));
}

#[test]
fn unique_tail_transfer_keeps_the_logical_store_live() {
    let unique = seal(tail_transfer_program(Mutability::Unique));
    assert_eq!(
        evaluate(&unique, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(5))
    );

    let shared = seal(tail_transfer_program(Mutability::Shared));
    assert!(has_code(
        &shared,
        VerificationCode::UnsupportedProfileFeature
    ));
}

#[test]
fn branches_receive_independent_affine_states() {
    let moved_branch = |owner: u32, moved: u32, loaded: u32| Term::Let {
        binder: LocalId(moved),
        ty: unique_i64_ref(),
        value: RValue::Use(Operand::Local(LocalId(owner))),
        next: Box::new(Term::Let {
            binder: LocalId(loaded),
            ty: Type::I64,
            value: RValue::RefLoad {
                reference: Operand::Local(LocalId(moved)),
            },
            next: Box::new(Term::Return(Operand::Local(LocalId(loaded)))),
        }),
    };
    let artifact = seal(program(
        CoreProfile::P1V4,
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
                    ty: unique_i64_ref(),
                    value: RValue::RefAlloc {
                        region: STORE_REGION,
                        mutability: Mutability::Unique,
                        value: Operand::I64(17),
                    },
                    next: Box::new(Term::If {
                        condition: Operand::Bool(true),
                        then_term: Box::new(moved_branch(0, 1, 2)),
                        else_term: Box::new(moved_branch(0, 3, 4)),
                    }),
                }),
            },
        }],
    ));
    verify(&artifact).expect("each terminal branch may move the owner once");
    assert_eq!(
        evaluate(&artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(17))
    );
}

#[test]
fn older_profiles_remain_closed_to_unique_ownership() {
    for profile in [
        CoreProfile::P1V0,
        CoreProfile::P1V1,
        CoreProfile::P1V2,
        CoreProfile::P1V3,
    ] {
        let artifact = seal(unique_borrow_program(profile));
        assert!(
            has_code(&artifact, VerificationCode::UnsupportedProfileFeature),
            "{profile:?} must not silently widen"
        );
    }
}

#[test]
fn unique_owners_cannot_be_hidden_inside_aggregates() {
    let sum = SumType {
        name: "UniqueBox".to_owned(),
        constructors: vec![ConstructorType {
            name: "UniqueBox".to_owned(),
            fields: vec![unique_i64_ref()],
        }],
    };
    let aggregate_program = |ty: Type, value: RValue| {
        seal(program(
            CoreProfile::P1V4,
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
                        ty: unique_i64_ref(),
                        value: RValue::RefAlloc {
                            region: STORE_REGION,
                            mutability: Mutability::Unique,
                            value: Operand::I64(1),
                        },
                        next: Box::new(Term::Let {
                            binder: LocalId(1),
                            ty,
                            value,
                            next: Box::new(Term::Return(Operand::I64(0))),
                        }),
                    }),
                },
            }],
        ))
    };

    let tuple = aggregate_program(
        Type::Tuple(vec![unique_i64_ref()]),
        RValue::Tuple(vec![Operand::Local(LocalId(0))]),
    );
    let sum_value = aggregate_program(
        Type::Sum(sum.clone()),
        RValue::Construct {
            sum,
            constructor: 0,
            fields: vec![Operand::Local(LocalId(0))],
        },
    );
    for artifact in [tuple, sum_value] {
        assert!(has_code(
            &artifact,
            VerificationCode::UnsupportedProfileFeature
        ));
    }
}

#[test]
fn closures_and_handlers_cannot_capture_a_unique_owner() {
    let closure_type = Type::Closure {
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Box::new(Type::I64),
    };
    let closure_capture = seal(program(
        CoreProfile::P1V4,
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
                            ty: closure_type,
                            value: RValue::PackClosure {
                                function: FunctionId(1),
                                captures: vec![Operand::Local(LocalId(0))],
                            },
                            next: Box::new(Term::Return(Operand::I64(0))),
                        }),
                    }),
                },
            },
            Function {
                id: FunctionId(1),
                region_parameters: vec![STORE_REGION],
                parameters: vec![Parameter {
                    local: LocalId(0),
                    ty: Type::Tuple(vec![unique_i64_ref()]),
                }],
                effects: EffectRow::pure(),
                result: Type::I64,
                body: Term::Return(Operand::I64(1)),
            },
        ],
    ));
    assert!(has_code(
        &closure_capture,
        VerificationCode::OwnershipViolation
    ));

    let handler_capture = seal(program(
        CoreProfile::P1V4,
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
                    ty: unique_i64_ref(),
                    value: RValue::RefAlloc {
                        region: STORE_REGION,
                        mutability: Mutability::Unique,
                        value: Operand::I64(1),
                    },
                    next: Box::new(Term::Handle {
                        captures: vec![Operand::Local(LocalId(0))],
                        capture_parameters: vec![Parameter {
                            local: LocalId(1),
                            ty: unique_i64_ref(),
                        }],
                        clauses: vec![],
                        body: Box::new(Term::Return(Operand::I64(0))),
                    }),
                }),
            },
        }],
    ));
    assert!(has_code(
        &handler_capture,
        VerificationCode::OwnershipViolation
    ));
}

#[test]
fn unique_owners_cannot_cross_entry_or_result_boundaries() {
    let entry_parameter = seal(program(
        CoreProfile::P1V4,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![STORE_REGION],
            parameters: vec![Parameter {
                local: LocalId(0),
                ty: unique_i64_ref(),
            }],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Return(Operand::I64(0)),
        }],
    ));
    assert!(has_code(
        &entry_parameter,
        VerificationCode::UnsupportedProfileFeature
    ));

    let result_escape = seal(program(
        CoreProfile::P1V4,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![STORE_REGION],
            parameters: vec![],
            effects: store_effects(),
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
        &result_escape,
        VerificationCode::UnsupportedProfileFeature
    ));
}

#[test]
fn unique_execution_preserves_typed_errors_and_exact_budgets() {
    let overflow = seal(program(
        CoreProfile::P1V4,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![STORE_REGION],
            parameters: vec![],
            effects: EffectRow::canonical(vec![
                Effect::Alloc(STORE_REGION),
                Effect::Error(ErrorKind::Overflow),
            ]),
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
        evaluate(&overflow, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Error(ErrorKind::Overflow)
    );

    let budget_error = evaluate(
        &seal(unique_borrow_program(CoreProfile::P1V4)),
        vec![],
        EvaluationBudget::new(2, 64),
    )
    .expect_err("Unique evaluation must respect the exact step budget");
    assert!(matches!(
        budget_error,
        naux::core::ExecutionError::StepBudgetExceeded { limit: 2 }
    ));
}

#[test]
fn p1v4_hash_is_deterministic_and_tamper_evident() {
    let first = seal(unique_borrow_program(CoreProfile::P1V4));
    let second = seal(unique_borrow_program(CoreProfile::P1V4));
    assert_eq!(first.semantic_hash, second.semantic_hash);
    assert_eq!(
        semantic_bytes(&first.program).unwrap(),
        semantic_bytes(&second.program).unwrap()
    );
    assert_eq!(
        first.semantic_hash.to_hex(),
        "f314f6e72535bf12b6b42aa962a4a34c70845a7eefa709e7242b190b95fa27a9"
    );

    let mut tampered = first.clone();
    let Term::Region { body, .. } = &mut tampered.program.functions[0].body else {
        unreachable!("fixture starts with a region");
    };
    let Term::Let {
        value: RValue::RefAlloc { value, .. },
        ..
    } = body.as_mut()
    else {
        unreachable!("fixture starts with a Unique allocation");
    };
    *value = Operand::I64(2);
    assert!(has_code(&tampered, VerificationCode::SemanticHashMismatch));
    assert_ne!(first.semantic_hash, SemanticHash::ZERO);
}
