use naux::core::{
    certify_binding_time_b0d, evaluate, evaluate_static_r0b1, validate_binding_time_b0_request,
    validate_specialization_r0a_request, BindingTime, BindingTimeBudget, BindingTimeNodeId,
    BindingTimePathField, BindingTimeRequest, CaseArm, ConstructorType, CoreArtifact, CoreProfile,
    CoreValue, Effect, EffectRow, ErrorKind, EvaluationBudget, EvaluationOutcome, Function,
    FunctionId, LocalId, Mutability, NumericMode, Operand, Parameter, Primitive, Program, RValue,
    RegionId, SpecializationBudget, SpecializationRequest, SpecializationSlot, SpecializationValue,
    StaticEvaluation, StaticEvaluationError, StaticEvaluationOutcome, StaticResidual,
    StaticResidualReason, SumType, Term, Type,
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

fn evaluate_boundary(
    artifact: &CoreArtifact,
    manifest: Vec<BindingTime>,
    slots: Vec<SpecializationSlot>,
    max_steps: u64,
) -> Result<StaticEvaluation, StaticEvaluationError> {
    let binding_time_request = BindingTimeRequest::p1v0(
        artifact,
        manifest,
        BindingTimeBudget::new(10_000, 10_000, 1_000),
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
        SpecializationBudget::new(1_000, 1_000, max_steps, 1_000, 1_000_000),
    )
    .expect("R0 request must encode");
    let validated = validate_specialization_r0a_request(
        artifact,
        &binding_time_request,
        &certificate,
        &request,
    )
    .expect("R0-A request must validate");
    evaluate_static_r0b1(&validated)
}

fn wrapping_saturating_program() -> CoreArtifact {
    seal(vec![Function {
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
            value: RValue::Primitive {
                operation: Primitive::I64Add(NumericMode::Wrapping),
                arguments: vec![Operand::Local(LocalId(0)), Operand::I64(1)],
            },
            next: Box::new(Term::Let {
                binder: LocalId(2),
                ty: Type::I64,
                value: RValue::Primitive {
                    operation: Primitive::I64Sub(NumericMode::Saturating),
                    arguments: vec![Operand::Local(LocalId(1)), Operand::I64(1)],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
            }),
        },
    }])
}

fn primitive_program(operation: Primitive, arguments: Vec<Operand>, result: Type) -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: result.clone(),
        body: Term::Let {
            binder: LocalId(0),
            ty: result,
            value: RValue::Primitive {
                operation,
                arguments,
            },
            next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
        },
    }])
}

#[test]
fn static_numeric_path_is_complete_with_exact_steps_and_trace() {
    let artifact = wrapping_saturating_program();
    let first = evaluate_boundary(
        &artifact,
        vec![BindingTime::Static],
        vec![SpecializationSlot::Static(SpecializationValue::I64(
            i64::MAX,
        ))],
        100,
    )
    .expect("eligible static arithmetic must evaluate");
    let second = evaluate_boundary(
        &artifact,
        vec![BindingTime::Static],
        vec![SpecializationSlot::Static(SpecializationValue::I64(
            i64::MAX,
        ))],
        100,
    )
    .expect("repeated evaluation must pass");

    assert_eq!(
        first.outcome,
        StaticEvaluationOutcome::Complete(SpecializationValue::I64(i64::MIN))
    );
    assert_eq!(first.steps, 10);
    assert_eq!(first.executed_nodes.len() as u64, first.steps);
    let root = BindingTimeNodeId::root(FunctionId(0));
    let first_value = root.child(BindingTimePathField::LetValue, 0);
    let second_term = root.child(BindingTimePathField::LetNext, 0);
    let second_value = second_term.child(BindingTimePathField::LetValue, 0);
    let return_term = second_term.child(BindingTimePathField::LetNext, 0);
    assert_eq!(
        first.executed_nodes,
        vec![
            root,
            first_value.clone(),
            first_value.child(BindingTimePathField::PrimitiveArgument, 0),
            first_value.child(BindingTimePathField::PrimitiveArgument, 1),
            second_term,
            second_value.clone(),
            second_value.child(BindingTimePathField::PrimitiveArgument, 0),
            second_value.child(BindingTimePathField::PrimitiveArgument, 1),
            return_term.clone(),
            return_term.child(BindingTimePathField::ReturnOperand, 0),
        ]
    );
    assert_ne!(first.request_hash, naux::core::SemanticHash::ZERO);
    assert_eq!(
        first, second,
        "R0-B1 result and trace must be deterministic"
    );
    let oracle = evaluate(
        &artifact,
        vec![CoreValue::I64(i64::MAX)],
        EvaluationBudget::new(100, 10),
    )
    .expect("canonical interpreter must evaluate the same source");
    assert_eq!(
        oracle.outcome,
        EvaluationOutcome::Return(CoreValue::I64(i64::MIN))
    );
}

#[test]
fn every_admitted_numeric_primitive_family_has_static_evidence() {
    let cases = [
        (
            primitive_program(
                Primitive::I64Sub(NumericMode::Wrapping),
                vec![Operand::I64(i64::MIN), Operand::I64(1)],
                Type::I64,
            ),
            SpecializationValue::I64(i64::MAX),
        ),
        (
            primitive_program(
                Primitive::I64Mul(NumericMode::Wrapping),
                vec![Operand::I64(i64::MAX), Operand::I64(2)],
                Type::I64,
            ),
            SpecializationValue::I64(-2),
        ),
        (
            primitive_program(
                Primitive::I64Add(NumericMode::Saturating),
                vec![Operand::I64(i64::MAX), Operand::I64(1)],
                Type::I64,
            ),
            SpecializationValue::I64(i64::MAX),
        ),
        (
            primitive_program(
                Primitive::I64Mul(NumericMode::Saturating),
                vec![Operand::I64(i64::MAX), Operand::I64(2)],
                Type::I64,
            ),
            SpecializationValue::I64(i64::MAX),
        ),
        (
            primitive_program(
                Primitive::F64Sub,
                vec![Operand::F64(5.5), Operand::F64(2.0)],
                Type::F64,
            ),
            SpecializationValue::F64(3.5),
        ),
        (
            primitive_program(
                Primitive::I64CmpLt,
                vec![Operand::I64(1), Operand::I64(2)],
                Type::Bool,
            ),
            SpecializationValue::Bool(true),
        ),
    ];

    for (artifact, expected) in cases {
        let evaluation = evaluate_boundary(&artifact, vec![], vec![], 100)
            .expect("admitted pure primitive must evaluate");
        assert_eq!(
            evaluation.outcome,
            StaticEvaluationOutcome::Complete(expected)
        );
    }
}

fn array_tuple_branch_program() -> CoreArtifact {
    let array = Type::Array {
        region: RegionId(0),
        mutability: Mutability::Read,
        element: Box::new(Type::F64),
    };
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![RegionId(0)],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: array,
        }],
        effects: EffectRow::pure(),
        result: Type::F64,
        body: Term::Let {
            binder: LocalId(1),
            ty: Type::I64,
            value: RValue::Primitive {
                operation: Primitive::ArrayLenF64,
                arguments: vec![Operand::Local(LocalId(0))],
            },
            next: Box::new(Term::Let {
                binder: LocalId(2),
                ty: Type::Tuple(vec![Type::I64, Type::I64]),
                value: RValue::Tuple(vec![Operand::Local(LocalId(1)), Operand::I64(3)]),
                next: Box::new(Term::Let {
                    binder: LocalId(3),
                    ty: Type::I64,
                    value: RValue::Project {
                        tuple: Operand::Local(LocalId(2)),
                        index: 0,
                    },
                    next: Box::new(Term::Let {
                        binder: LocalId(4),
                        ty: Type::Bool,
                        value: RValue::Primitive {
                            operation: Primitive::I64CmpGe,
                            arguments: vec![Operand::Local(LocalId(3)), Operand::I64(3)],
                        },
                        next: Box::new(Term::If {
                            condition: Operand::Local(LocalId(4)),
                            then_term: Box::new(Term::Let {
                                binder: LocalId(5),
                                ty: Type::F64,
                                value: RValue::Primitive {
                                    operation: Primitive::F64Add,
                                    arguments: vec![Operand::F64(1.0), Operand::F64(0.5)],
                                },
                                next: Box::new(Term::Return(Operand::Local(LocalId(5)))),
                            }),
                            else_term: Box::new(Term::Return(Operand::F64(-1.0))),
                        }),
                    }),
                }),
            }),
        },
    }])
}

#[test]
fn array_tuple_projection_and_static_branch_use_only_the_selected_path() {
    let artifact = array_tuple_branch_program();
    let evaluation = evaluate_boundary(
        &artifact,
        vec![BindingTime::Static],
        vec![SpecializationSlot::Static(SpecializationValue::ArrayF64(
            vec![2.0, 4.0, 8.0],
        ))],
        100,
    )
    .expect("static aggregate path must evaluate");
    assert_eq!(
        evaluation.outcome,
        StaticEvaluationOutcome::Complete(SpecializationValue::F64(1.5))
    );
    let oracle = evaluate(
        &artifact,
        vec![CoreValue::array_f64(vec![2.0, 4.0, 8.0])],
        EvaluationBudget::new(100, 10),
    )
    .expect("canonical interpreter must evaluate the aggregate path");
    assert_eq!(
        oracle.outcome,
        EvaluationOutcome::Return(CoreValue::F64(1.5))
    );

    let if_node = BindingTimeNodeId::root(FunctionId(0))
        .child(BindingTimePathField::LetNext, 0)
        .child(BindingTimePathField::LetNext, 0)
        .child(BindingTimePathField::LetNext, 0)
        .child(BindingTimePathField::LetNext, 0);
    let then_node = if_node.child(BindingTimePathField::IfThen, 0);
    let else_node = if_node.child(BindingTimePathField::IfElse, 0);
    assert!(evaluation
        .executed_nodes
        .iter()
        .any(|node| node == &then_node));
    assert!(!evaluation
        .executed_nodes
        .iter()
        .any(|node| node == &else_node));
}

#[test]
fn sum_construction_and_static_case_bind_the_selected_fields() {
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
    let artifact = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(0),
            ty: Type::Sum(option.clone()),
            value: RValue::Construct {
                sum: option,
                constructor: 1,
                fields: vec![Operand::I64(9)],
            },
            next: Box::new(Term::Case {
                scrutinee: Operand::Local(LocalId(0)),
                arms: vec![
                    CaseArm {
                        constructor: 0,
                        bindings: vec![],
                        body: Term::Return(Operand::I64(0)),
                    },
                    CaseArm {
                        constructor: 1,
                        bindings: vec![LocalId(1)],
                        body: Term::Return(Operand::Local(LocalId(1))),
                    },
                ],
            }),
        },
    }]);
    let evaluation = evaluate_boundary(&artifact, vec![], vec![], 100)
        .expect("static constructor/case must evaluate");
    assert_eq!(
        evaluation.outcome,
        StaticEvaluationOutcome::Complete(SpecializationValue::I64(9))
    );
    let oracle = evaluate(&artifact, vec![], EvaluationBudget::new(100, 10))
        .expect("canonical interpreter must evaluate the sum path");
    assert_eq!(oracle.outcome, EvaluationOutcome::Return(CoreValue::I64(9)));
}

#[test]
fn dynamic_dependency_residualizes_at_the_root_without_execution() {
    let artifact = wrapping_saturating_program();
    let evaluation = evaluate_boundary(
        &artifact,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        100,
    )
    .expect("dynamic work must residualize rather than fail");
    assert_eq!(
        evaluation.outcome,
        StaticEvaluationOutcome::ResidualRequired(StaticResidual {
            node: BindingTimeNodeId::root(FunctionId(0)),
            reason: StaticResidualReason::DynamicDependency,
        })
    );
    assert_eq!(evaluation.steps, 0);
    assert!(evaluation.executed_nodes.is_empty());
}

fn checked_program() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::canonical(vec![Effect::Error(ErrorKind::Overflow)]),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(0),
            ty: Type::I64,
            value: RValue::Primitive {
                operation: Primitive::I64Add(NumericMode::Checked),
                arguments: vec![Operand::I64(i64::MAX), Operand::I64(1)],
            },
            next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
        },
    }])
}

fn array_get_program() -> CoreArtifact {
    let array = Type::Array {
        region: RegionId(0),
        mutability: Mutability::Read,
        element: Box::new(Type::F64),
    };
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![RegionId(0)],
        parameters: vec![
            Parameter {
                local: LocalId(0),
                ty: array,
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
            value: RValue::Primitive {
                operation: Primitive::ArrayGetF64,
                arguments: vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(1))],
            },
            next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
        },
    }])
}

#[test]
fn typed_error_operations_are_denied_without_being_executed() {
    let checked = evaluate_boundary(&checked_program(), vec![], vec![], 100)
        .expect("checked arithmetic must residualize");
    assert_eq!(
        checked.outcome,
        StaticEvaluationOutcome::ResidualRequired(StaticResidual {
            node: BindingTimeNodeId::root(FunctionId(0)),
            reason: StaticResidualReason::DeniedByCertificate,
        })
    );
    assert_eq!(checked.steps, 0);

    let bounds = evaluate_boundary(
        &array_get_program(),
        vec![BindingTime::Static, BindingTime::Static],
        vec![
            SpecializationSlot::Static(SpecializationValue::ArrayF64(vec![1.25])),
            SpecializationSlot::Static(SpecializationValue::I64(4)),
        ],
        100,
    )
    .expect("array indexing must residualize even with static arguments");
    assert_eq!(
        bounds.outcome,
        StaticEvaluationOutcome::ResidualRequired(StaticResidual {
            node: BindingTimeNodeId::root(FunctionId(0)),
            reason: StaticResidualReason::DeniedByCertificate,
        })
    );
    assert_eq!(bounds.steps, 0);
}

fn call_program(tail: bool) -> CoreArtifact {
    let body = if tail {
        Term::TailCall {
            function: FunctionId(1),
            arguments: vec![Operand::I64(7)],
        }
    } else {
        Term::Let {
            binder: LocalId(0),
            ty: Type::I64,
            value: RValue::Call {
                function: FunctionId(1),
                arguments: vec![Operand::I64(7)],
            },
            next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
        }
    };
    seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::I64,
            body,
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

#[test]
fn direct_and_tail_calls_are_explicit_r0b2_frontiers() {
    let direct = evaluate_boundary(&call_program(false), vec![], vec![], 100)
        .expect("direct call must defer");
    assert_eq!(
        direct.outcome,
        StaticEvaluationOutcome::ResidualRequired(StaticResidual {
            node: BindingTimeNodeId::root(FunctionId(0)).child(BindingTimePathField::LetValue, 0),
            reason: StaticResidualReason::InterproceduralDeferred,
        })
    );
    assert_eq!(direct.steps, 1);

    let tail =
        evaluate_boundary(&call_program(true), vec![], vec![], 100).expect("tail call must defer");
    assert_eq!(
        tail.outcome,
        StaticEvaluationOutcome::ResidualRequired(StaticResidual {
            node: BindingTimeNodeId::root(FunctionId(0)),
            reason: StaticResidualReason::InterproceduralDeferred,
        })
    );
    assert_eq!(tail.steps, 0);
}

#[test]
fn specialization_step_exhaustion_emits_no_partial_artifact() {
    let artifact = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Return(Operand::I64(7)),
    }]);
    let error = evaluate_boundary(&artifact, vec![], vec![], 1)
        .expect_err("second canonical node must exceed a one-step budget");
    assert_eq!(
        error,
        StaticEvaluationError::StepBudgetExceeded {
            limit: 1,
            used: 1,
            node: BindingTimeNodeId::root(FunctionId(0))
                .child(BindingTimePathField::ReturnOperand, 0),
        }
    );
}

#[test]
fn an_unused_dynamic_parameter_does_not_block_a_certified_static_result() {
    let artifact = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: Type::Bool,
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Return(Operand::I64(42)),
    }]);
    let evaluation = evaluate_boundary(
        &artifact,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::Bool)],
        100,
    )
    .expect("unused dynamic input must not contaminate a static result");
    assert_eq!(
        evaluation.outcome,
        StaticEvaluationOutcome::Complete(SpecializationValue::I64(42))
    );
    assert_eq!(evaluation.steps, 2);
}
