use naux::core::{
    evaluate, semantic_bytes, verify, CoreArtifact, CoreProfile, CoreValue, Effect, EffectRow,
    ErrorKind, EvaluationBudget, EvaluationOutcome, Function, FunctionId, HandlerClause, LocalId,
    Mutability, NumericMode, Operand, OperationId, OperationSignature, Parameter, Primitive,
    Program, RValue, RegionId, SchemaVersion, SemanticHash, Term, Type, VerificationCode,
};

const STORE_REGION: RegionId = RegionId(0);

fn budget() -> EvaluationBudget {
    EvaluationBudget::new(30_000, 64)
}

fn operation(id: u32) -> OperationSignature {
    OperationSignature {
        id: OperationId(id),
        parameters: vec![Type::I64],
        result: Box::new(Type::I64),
    }
}

fn operation_effect(operation: &OperationSignature) -> EffectRow {
    EffectRow::canonical(vec![Effect::Operation(operation.clone())])
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

fn add(binder: u32, left: Operand, right: Operand, next: Term) -> Term {
    Term::Let {
        binder: LocalId(binder),
        ty: Type::I64,
        value: RValue::Primitive {
            operation: Primitive::I64Add(NumericMode::Wrapping),
            arguments: vec![left, right],
        },
        next: Box::new(next),
    }
}

fn unary_clause(operation: OperationSignature, parameter: u32, body: Term) -> HandlerClause {
    HandlerClause {
        operation,
        parameters: vec![LocalId(parameter)],
        body: Box::new(body),
    }
}

fn handled_resume_program(profile: CoreProfile) -> Program {
    let op = operation(7);
    program(
        profile,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Handle {
                captures: vec![Operand::I64(40)],
                capture_parameters: vec![Parameter {
                    local: LocalId(10),
                    ty: Type::I64,
                }],
                clauses: vec![unary_clause(
                    op.clone(),
                    11,
                    add(
                        12,
                        Operand::Local(LocalId(10)),
                        Operand::Local(LocalId(11)),
                        Term::Return(Operand::Local(LocalId(12))),
                    ),
                )],
                body: Box::new(Term::Let {
                    binder: LocalId(0),
                    ty: Type::I64,
                    value: RValue::Perform {
                        operation: op,
                        arguments: vec![Operand::I64(2)],
                    },
                    next: Box::new(add(
                        1,
                        Operand::Local(LocalId(0)),
                        Operand::I64(1),
                        Term::Return(Operand::Local(LocalId(1))),
                    )),
                }),
            },
        }],
    )
}

fn shared_i64_ref() -> Type {
    Type::Ref {
        region: STORE_REGION,
        mutability: Mutability::Shared,
        element: Box::new(Type::I64),
    }
}

fn state_alloc_effects() -> EffectRow {
    EffectRow::canonical(vec![
        Effect::State(STORE_REGION),
        Effect::Alloc(STORE_REGION),
    ])
}

fn reference_handler_program() -> Program {
    let op = operation(8);
    program(
        CoreProfile::P1V3,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![STORE_REGION],
            parameters: vec![],
            effects: state_alloc_effects(),
            result: Type::I64,
            body: Term::Region {
                region: STORE_REGION,
                body: Box::new(Term::Let {
                    binder: LocalId(0),
                    ty: shared_i64_ref(),
                    value: RValue::RefAlloc {
                        region: STORE_REGION,
                        mutability: Mutability::Shared,
                        value: Operand::I64(0),
                    },
                    next: Box::new(Term::Handle {
                        captures: vec![Operand::Local(LocalId(0))],
                        capture_parameters: vec![Parameter {
                            local: LocalId(10),
                            ty: shared_i64_ref(),
                        }],
                        clauses: vec![unary_clause(
                            op.clone(),
                            11,
                            Term::Let {
                                binder: LocalId(12),
                                ty: Type::I64,
                                value: RValue::RefLoad {
                                    reference: Operand::Local(LocalId(10)),
                                },
                                next: Box::new(add(
                                    13,
                                    Operand::Local(LocalId(12)),
                                    Operand::I64(1),
                                    Term::Let {
                                        binder: LocalId(14),
                                        ty: Type::Unit,
                                        value: RValue::RefStore {
                                            reference: Operand::Local(LocalId(10)),
                                            value: Operand::Local(LocalId(13)),
                                        },
                                        next: Box::new(Term::Return(Operand::Local(LocalId(11)))),
                                    },
                                )),
                            },
                        )],
                        body: Box::new(Term::Let {
                            binder: LocalId(1),
                            ty: Type::I64,
                            value: RValue::Perform {
                                operation: op,
                                arguments: vec![Operand::I64(9)],
                            },
                            next: Box::new(Term::Let {
                                binder: LocalId(2),
                                ty: Type::I64,
                                value: RValue::RefLoad {
                                    reference: Operand::Local(LocalId(0)),
                                },
                                next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
                            }),
                        }),
                    }),
                }),
            },
        }],
    )
}

#[test]
fn handled_value_resumes_the_structural_continuation_exactly_once() {
    let artifact = seal(handled_resume_program(CoreProfile::P1V3));
    verify(&artifact).expect("linear handler should verify");
    assert_eq!(
        evaluate(&artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(43))
    );
}

#[test]
fn declared_unhandled_operation_is_a_typed_outcome() {
    let op = operation(9);
    let artifact = seal(program(
        CoreProfile::P1V3,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: operation_effect(&op),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(0),
                ty: Type::I64,
                value: RValue::Perform {
                    operation: op.clone(),
                    arguments: vec![Operand::I64(7)],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
            },
        }],
    ));
    assert_eq!(
        evaluate(&artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::UnhandledOperation(naux::core::OperationRequest {
            operation: op,
            arguments: vec![CoreValue::I64(7)],
        })
    );
}

#[test]
fn unhandled_operation_requires_its_exact_declared_effect() {
    let op = operation(10);
    let artifact = seal(program(
        CoreProfile::P1V3,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(0),
                ty: Type::I64,
                value: RValue::Perform {
                    operation: op,
                    arguments: vec![Operand::I64(1)],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
            },
        }],
    ));
    let errors = verify(&artifact).expect_err("missing operation effect must fail");
    assert!(errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::MissingEffect));
}

#[test]
fn handler_effect_subtraction_propagates_through_direct_calls() {
    let op = operation(11);
    let artifact = seal(program(
        CoreProfile::P1V3,
        vec![
            Function {
                id: FunctionId(0),
                region_parameters: vec![],
                parameters: vec![],
                effects: EffectRow::pure(),
                result: Type::I64,
                body: Term::Handle {
                    captures: vec![],
                    capture_parameters: vec![],
                    clauses: vec![unary_clause(
                        op.clone(),
                        10,
                        add(
                            11,
                            Operand::Local(LocalId(10)),
                            Operand::I64(1),
                            Term::Return(Operand::Local(LocalId(11))),
                        ),
                    )],
                    body: Box::new(Term::Let {
                        binder: LocalId(0),
                        ty: Type::I64,
                        value: RValue::Call {
                            function: FunctionId(1),
                            arguments: vec![Operand::I64(41)],
                        },
                        next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
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
                effects: operation_effect(&op),
                result: Type::I64,
                body: Term::Let {
                    binder: LocalId(1),
                    ty: Type::I64,
                    value: RValue::Perform {
                        operation: op,
                        arguments: vec![Operand::Local(LocalId(0))],
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
                },
            },
        ],
    ));
    assert_eq!(
        evaluate(&artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(42))
    );
}

#[test]
fn handler_effect_subtraction_propagates_through_closure_calls() {
    let op = operation(12);
    let closure_type = Type::Closure {
        parameters: vec![Type::I64],
        effects: operation_effect(&op),
        result: Box::new(Type::I64),
    };
    let artifact = seal(program(
        CoreProfile::P1V3,
        vec![
            Function {
                id: FunctionId(0),
                region_parameters: vec![],
                parameters: vec![],
                effects: EffectRow::pure(),
                result: Type::I64,
                body: Term::Handle {
                    captures: vec![],
                    capture_parameters: vec![],
                    clauses: vec![unary_clause(
                        op.clone(),
                        10,
                        add(
                            11,
                            Operand::Local(LocalId(10)),
                            Operand::I64(1),
                            Term::Return(Operand::Local(LocalId(11))),
                        ),
                    )],
                    body: Box::new(Term::Let {
                        binder: LocalId(0),
                        ty: closure_type,
                        value: RValue::PackClosure {
                            function: FunctionId(1),
                            captures: vec![],
                        },
                        next: Box::new(Term::Let {
                            binder: LocalId(1),
                            ty: Type::I64,
                            value: RValue::CallClosure {
                                closure: Operand::Local(LocalId(0)),
                                arguments: vec![Operand::I64(41)],
                            },
                            next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
                        }),
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
                        ty: Type::I64,
                    },
                ],
                effects: operation_effect(&op),
                result: Type::I64,
                body: Term::Let {
                    binder: LocalId(2),
                    ty: Type::I64,
                    value: RValue::Perform {
                        operation: op,
                        arguments: vec![Operand::Local(LocalId(1))],
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
                },
            },
        ],
    ));
    assert_eq!(
        evaluate(&artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(42))
    );
}

fn nested_handler_program(forward: bool) -> Program {
    let op = operation(13);
    let inner_clause_body = if forward {
        Term::Let {
            binder: LocalId(32),
            ty: Type::I64,
            value: RValue::Perform {
                operation: op.clone(),
                arguments: vec![Operand::Local(LocalId(31))],
            },
            next: Box::new(Term::Return(Operand::Local(LocalId(32)))),
        }
    } else {
        add(
            32,
            Operand::Local(LocalId(30)),
            Operand::Local(LocalId(31)),
            Term::Return(Operand::Local(LocalId(32))),
        )
    };
    program(
        CoreProfile::P1V3,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Handle {
                captures: vec![Operand::I64(100)],
                capture_parameters: vec![Parameter {
                    local: LocalId(20),
                    ty: Type::I64,
                }],
                clauses: vec![unary_clause(
                    op.clone(),
                    21,
                    add(
                        22,
                        Operand::Local(LocalId(20)),
                        Operand::Local(LocalId(21)),
                        Term::Return(Operand::Local(LocalId(22))),
                    ),
                )],
                body: Box::new(Term::Handle {
                    captures: vec![Operand::I64(10)],
                    capture_parameters: vec![Parameter {
                        local: LocalId(30),
                        ty: Type::I64,
                    }],
                    clauses: vec![unary_clause(op.clone(), 31, inner_clause_body)],
                    body: Box::new(Term::Let {
                        binder: LocalId(0),
                        ty: Type::I64,
                        value: RValue::Perform {
                            operation: op,
                            arguments: vec![Operand::I64(1)],
                        },
                        next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
                    }),
                }),
            },
        }],
    )
}

#[test]
fn innermost_handler_wins_and_same_operation_in_clause_forwards_outward() {
    let inner = seal(nested_handler_program(false));
    let forwarded = seal(nested_handler_program(true));
    assert_eq!(
        evaluate(&inner, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(11))
    );
    assert_eq!(
        evaluate(&forwarded, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(101))
    );
}

#[test]
fn handler_capture_order_is_behavioral_and_hash_visible() {
    fn ordered(captures: Vec<Operand>) -> CoreArtifact {
        let op = operation(18);
        seal(program(
            CoreProfile::P1V3,
            vec![Function {
                id: FunctionId(0),
                region_parameters: vec![],
                parameters: vec![],
                effects: EffectRow::pure(),
                result: Type::I64,
                body: Term::Handle {
                    captures,
                    capture_parameters: vec![
                        Parameter {
                            local: LocalId(10),
                            ty: Type::I64,
                        },
                        Parameter {
                            local: LocalId(11),
                            ty: Type::I64,
                        },
                    ],
                    clauses: vec![unary_clause(
                        op.clone(),
                        12,
                        Term::Let {
                            binder: LocalId(13),
                            ty: Type::I64,
                            value: RValue::Primitive {
                                operation: Primitive::I64Sub(NumericMode::Wrapping),
                                arguments: vec![
                                    Operand::Local(LocalId(10)),
                                    Operand::Local(LocalId(11)),
                                ],
                            },
                            next: Box::new(Term::Return(Operand::Local(LocalId(13)))),
                        },
                    )],
                    body: Box::new(Term::Let {
                        binder: LocalId(0),
                        ty: Type::I64,
                        value: RValue::Perform {
                            operation: op,
                            arguments: vec![Operand::I64(0)],
                        },
                        next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
                    }),
                },
            }],
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
fn reference_capture_mutation_is_visible_after_resumption() {
    let artifact = seal(reference_handler_program());
    verify(&artifact).expect("live reference capture should verify");
    assert_eq!(
        evaluate(&artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(1))
    );
}

#[test]
fn typed_clause_error_resumes_zero_times() {
    let op = operation(14);
    let artifact = seal(program(
        CoreProfile::P1V3,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::canonical(vec![Effect::Error(ErrorKind::Overflow)]),
            result: Type::I64,
            body: Term::Handle {
                captures: vec![],
                capture_parameters: vec![],
                clauses: vec![unary_clause(
                    op.clone(),
                    10,
                    Term::Let {
                        binder: LocalId(11),
                        ty: Type::I64,
                        value: RValue::Primitive {
                            operation: Primitive::I64Add(NumericMode::Checked),
                            arguments: vec![Operand::I64(i64::MAX), Operand::I64(1)],
                        },
                        next: Box::new(Term::Return(Operand::Local(LocalId(11)))),
                    },
                )],
                body: Box::new(Term::Let {
                    binder: LocalId(0),
                    ty: Type::I64,
                    value: RValue::Perform {
                        operation: op,
                        arguments: vec![Operand::I64(0)],
                    },
                    next: Box::new(Term::Return(Operand::I64(99))),
                }),
            },
        }],
    ));
    let evaluation = evaluate(&artifact, vec![], budget()).unwrap();
    assert_eq!(
        evaluation.outcome,
        EvaluationOutcome::Error(ErrorKind::Overflow)
    );
    assert_eq!(evaluation.effect_trace.len(), 1);
}

#[test]
fn older_profiles_remain_closed_to_handler_constructs() {
    for profile in [CoreProfile::P1V0, CoreProfile::P1V1, CoreProfile::P1V2] {
        let artifact = seal(handled_resume_program(profile));
        let errors = verify(&artifact).expect_err("older profile must reject handlers");
        assert!(errors
            .0
            .iter()
            .any(|error| error.code == VerificationCode::UnsupportedProfileFeature));
    }
}

#[test]
fn operation_signatures_are_global_typed_and_reference_free() {
    let declared = operation(15);
    let conflicting = OperationSignature {
        id: declared.id,
        parameters: vec![Type::I64],
        result: Box::new(Type::Bool),
    };
    let conflict = seal(program(
        CoreProfile::P1V3,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: operation_effect(&declared),
            result: Type::Bool,
            body: Term::Let {
                binder: LocalId(0),
                ty: Type::Bool,
                value: RValue::Perform {
                    operation: conflicting,
                    arguments: vec![Operand::I64(1)],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
            },
        }],
    ));
    let conflict_errors = verify(&conflict).expect_err("signature conflict must fail");
    assert!(conflict_errors
        .0
        .iter()
        .any(|error| error.message.contains("conflicting signatures")));

    let reference_operation = OperationSignature {
        id: OperationId(16),
        parameters: vec![shared_i64_ref()],
        result: Box::new(Type::Unit),
    };
    let reference_signature = seal(program(
        CoreProfile::P1V3,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![STORE_REGION],
            parameters: vec![],
            effects: operation_effect(&reference_operation),
            result: Type::Unit,
            body: Term::Return(Operand::Unit),
        }],
    ));
    let reference_errors =
        verify(&reference_signature).expect_err("reference operation signature must fail");
    assert!(reference_errors.0.iter().any(|error| {
        error.code == VerificationCode::UnsupportedProfileFeature
            && error.message.contains("operation parameters")
    }));
}

#[test]
fn handler_shape_capture_and_perform_mismatches_fail_closed() {
    let mut wrong_capture = handled_resume_program(CoreProfile::P1V3);
    if let Term::Handle { captures, .. } = &mut wrong_capture.functions[0].body {
        captures[0] = Operand::Bool(true);
    }
    let capture_errors = verify(&seal(wrong_capture)).expect_err("capture mismatch must fail");
    assert!(capture_errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::TypeMismatch));

    let mut wrong_argument = handled_resume_program(CoreProfile::P1V3);
    if let Term::Handle { body, .. } = &mut wrong_argument.functions[0].body {
        if let Term::Let {
            value: RValue::Perform { arguments, .. },
            ..
        } = body.as_mut()
        {
            arguments[0] = Operand::Bool(true);
        }
    }
    let argument_errors =
        verify(&seal(wrong_argument)).expect_err("perform argument mismatch must fail");
    assert!(argument_errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::TypeMismatch));

    let mut empty = handled_resume_program(CoreProfile::P1V3);
    if let Term::Handle { clauses, .. } = &mut empty.functions[0].body {
        clauses.clear();
    }
    let empty_errors = verify(&seal(empty)).expect_err("empty handler must fail");
    assert!(empty_errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::InvalidCall));

    let mut noncanonical = handled_resume_program(CoreProfile::P1V3);
    if let Term::Handle { clauses, .. } = &mut noncanonical.functions[0].body {
        clauses.push(unary_clause(
            operation(6),
            20,
            Term::Return(Operand::Local(LocalId(20))),
        ));
    }
    let order_errors = verify(&seal(noncanonical)).expect_err("non-canonical clauses must fail");
    assert!(order_errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::NonCanonicalOrder));

    let mut wrong_result = handled_resume_program(CoreProfile::P1V3);
    if let Term::Handle { clauses, .. } = &mut wrong_result.functions[0].body {
        *clauses[0].body = Term::Return(Operand::Bool(true));
    }
    let result_errors = verify(&seal(wrong_result)).expect_err("clause result mismatch must fail");
    assert!(result_errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::TypeMismatch));

    let mut duplicate_parameter = handled_resume_program(CoreProfile::P1V3);
    if let Term::Handle { clauses, .. } = &mut duplicate_parameter.functions[0].body {
        let duplicate = clauses[0].parameters[0];
        clauses[0].parameters.push(duplicate);
    }
    let parameter_errors =
        verify(&seal(duplicate_parameter)).expect_err("duplicate clause parameter must fail");
    assert!(parameter_errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::DuplicateId));
}

#[test]
fn captured_reference_must_be_active_at_handler_entry() {
    let mut inactive = reference_handler_program();
    inactive.functions[0].body = match inactive.functions[0].body.clone() {
        Term::Region { body, .. } => *body,
        _ => unreachable!("fixture starts with a region"),
    };
    let errors = verify(&seal(inactive)).expect_err("inactive capture must fail");
    assert!(errors.0.iter().any(|error| {
        error.code == VerificationCode::InvalidType
            && error.path.contains("captures[0]")
            && error.message.contains("not active")
    }));
}

fn recursive_operation_program() -> Program {
    let op = operation(17);
    program(
        CoreProfile::P1V3,
        vec![
            Function {
                id: FunctionId(0),
                region_parameters: vec![],
                parameters: vec![],
                effects: EffectRow::pure(),
                result: Type::I64,
                body: Term::Handle {
                    captures: vec![],
                    capture_parameters: vec![],
                    clauses: vec![unary_clause(
                        op.clone(),
                        10,
                        Term::Return(Operand::Local(LocalId(10))),
                    )],
                    body: Box::new(Term::Let {
                        binder: LocalId(0),
                        ty: Type::I64,
                        value: RValue::Call {
                            function: FunctionId(1),
                            arguments: vec![Operand::I64(4)],
                        },
                        next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
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
                effects: operation_effect(&op),
                result: Type::I64,
                body: Term::Let {
                    binder: LocalId(1),
                    ty: Type::Bool,
                    value: RValue::Primitive {
                        operation: Primitive::I64CmpGe,
                        arguments: vec![Operand::Local(LocalId(0)), Operand::I64(1)],
                    },
                    next: Box::new(Term::If {
                        condition: Operand::Local(LocalId(1)),
                        then_term: Box::new(Term::Let {
                            binder: LocalId(2),
                            ty: Type::I64,
                            value: RValue::Primitive {
                                operation: Primitive::I64Sub(NumericMode::Wrapping),
                                arguments: vec![Operand::Local(LocalId(0)), Operand::I64(1)],
                            },
                            next: Box::new(Term::Let {
                                binder: LocalId(3),
                                ty: Type::I64,
                                value: RValue::Call {
                                    function: FunctionId(1),
                                    arguments: vec![Operand::Local(LocalId(2))],
                                },
                                next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
                            }),
                        }),
                        else_term: Box::new(Term::Let {
                            binder: LocalId(4),
                            ty: Type::I64,
                            value: RValue::Perform {
                                operation: op,
                                arguments: vec![Operand::I64(7)],
                            },
                            next: Box::new(Term::Return(Operand::Local(LocalId(4)))),
                        }),
                    }),
                },
            },
        ],
    )
}

#[test]
fn recursive_handled_operations_obey_call_depth_and_step_budgets() {
    let artifact = seal(recursive_operation_program());
    assert_eq!(
        evaluate(&artifact, vec![], budget()).unwrap().outcome,
        EvaluationOutcome::Return(CoreValue::I64(7))
    );
    let depth_error = evaluate(&artifact, vec![], EvaluationBudget::new(30_000, 2))
        .expect_err("recursive handled call must obey depth");
    assert!(matches!(
        depth_error,
        naux::core::ExecutionError::CallDepthExceeded { limit: 2 }
    ));
    let step_error = evaluate(&artifact, vec![], EvaluationBudget::new(5, 64))
        .expect_err("handler evaluation must obey step budget");
    assert!(matches!(
        step_error,
        naux::core::ExecutionError::StepBudgetExceeded { limit: 5 }
    ));
}

#[test]
fn p1v3_hash_is_deterministic_and_tamper_evident() {
    let first = seal(handled_resume_program(CoreProfile::P1V3));
    let second = seal(handled_resume_program(CoreProfile::P1V3));
    assert_eq!(first.semantic_hash, second.semantic_hash);
    assert_eq!(
        semantic_bytes(&first.program).unwrap(),
        semantic_bytes(&second.program).unwrap()
    );
    assert_eq!(
        first.semantic_hash.to_hex(),
        "20f4ae704987e1b61795085575c622111fb290dd72655899dcb770fa8a6723b4"
    );
    assert_ne!(first.semantic_hash, SemanticHash::ZERO);

    let mut tampered = first.clone();
    if let Term::Handle { captures, .. } = &mut tampered.program.functions[0].body {
        captures[0] = Operand::I64(41);
    }
    let errors = verify(&tampered).expect_err("handler tampering must fail closed");
    assert!(errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::SemanticHashMismatch));
}
