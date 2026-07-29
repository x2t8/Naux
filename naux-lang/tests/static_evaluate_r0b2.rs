use naux::core::{
    certify_binding_time_b0d, evaluate, evaluate_static_r0b1, evaluate_static_r0b2,
    validate_binding_time_b0_request, validate_specialization_r0a_request, BindingTime,
    BindingTimeBudget, BindingTimeNodeId, BindingTimePathField, BindingTimeRequest, CoreArtifact,
    CoreProfile, CoreValue, Effect, EffectRow, ErrorKind, EvaluationBudget, EvaluationOutcome,
    Function, FunctionId, LocalId, MixedStaticEvaluation, MixedStaticOutcome, NumericMode, Operand,
    Parameter, Primitive, Program, RValue, SkippedStaticNode, SpecializationBudget,
    SpecializationRequest, SpecializationSlot, SpecializationValue, StaticEvaluationError,
    StaticFact, StaticResidual, StaticResidualReason, Term, Type, R0B2_MAX_FRAMES,
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
) -> Result<MixedStaticEvaluation, StaticEvaluationError> {
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
    evaluate_static_r0b2(&validated)
}

fn i64_primitive(operation: Primitive, arguments: Vec<Operand>) -> RValue {
    RValue::Primitive {
        operation,
        arguments,
    }
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
            value: i64_primitive(
                Primitive::I64Add(NumericMode::Wrapping),
                vec![Operand::Local(LocalId(0)), Operand::I64(1)],
            ),
            next: Box::new(Term::Let {
                binder: LocalId(2),
                ty: Type::I64,
                value: i64_primitive(
                    Primitive::I64Sub(NumericMode::Saturating),
                    vec![Operand::Local(LocalId(1)), Operand::I64(1)],
                ),
                next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
            }),
        },
    }])
}

#[test]
fn fully_static_call_free_program_matches_r0b1_exactly() {
    let artifact = wrapping_saturating_program();
    let manifest = vec![BindingTime::Static];
    let slots = vec![SpecializationSlot::Static(SpecializationValue::I64(
        i64::MAX,
    ))];

    let binding_time_request = BindingTimeRequest::p1v0(
        &artifact,
        manifest,
        BindingTimeBudget::new(100_000, 100_000, 1_000),
    )
    .expect("B0 request must encode");
    let validated_binding_time = validate_binding_time_b0_request(&artifact, &binding_time_request)
        .expect("B0 request must validate");
    let certificate =
        certify_binding_time_b0d(&validated_binding_time).expect("B0 certificate must emit");
    let request = SpecializationRequest::p1v0(
        &artifact,
        &binding_time_request,
        &certificate,
        slots,
        SpecializationBudget::new(1_000, 1_000, 100, 1_000, 1_000_000),
    )
    .expect("R0 request must encode");
    let validated = validate_specialization_r0a_request(
        &artifact,
        &binding_time_request,
        &certificate,
        &request,
    )
    .expect("R0-A request must validate");

    let r0b1 = evaluate_static_r0b1(&validated).expect("R0-B1 must evaluate");
    let r0b2 = evaluate_static_r0b2(&validated).expect("R0-B2 must evaluate");

    assert_eq!(
        r0b2.outcome(),
        &MixedStaticOutcome::Complete(SpecializationValue::I64(i64::MIN))
    );
    assert_eq!(r0b2.steps(), r0b1.steps);
    assert_eq!(r0b2.steps(), 10);
    assert_eq!(r0b2.executed_nodes(), r0b1.executed_nodes);
    assert!(r0b2.skipped_nodes().is_empty());
    assert_eq!(r0b2.request_hash(), r0b1.request_hash);
}

/// Entry(): a = Use(5); t = (a, 2); p = t.0; return p — exercises the Use
/// and Project operand children, which must be authorized and stepped
/// exactly as in R0-B1.
fn use_project_program() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(0),
            ty: Type::I64,
            value: RValue::Use(Operand::I64(5)),
            next: Box::new(Term::Let {
                binder: LocalId(1),
                ty: Type::Tuple(vec![Type::I64, Type::I64]),
                value: RValue::Tuple(vec![Operand::Local(LocalId(0)), Operand::I64(2)]),
                next: Box::new(Term::Let {
                    binder: LocalId(2),
                    ty: Type::I64,
                    value: RValue::Project {
                        tuple: Operand::Local(LocalId(1)),
                        index: 0,
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
                }),
            }),
        },
    }])
}

#[test]
fn use_and_project_operands_match_r0b1_authority_and_steps() {
    let artifact = use_project_program();
    let binding_time_request = BindingTimeRequest::p1v0(
        &artifact,
        vec![],
        BindingTimeBudget::new(100_000, 100_000, 1_000),
    )
    .expect("B0 request must encode");
    let validated_binding_time = validate_binding_time_b0_request(&artifact, &binding_time_request)
        .expect("B0 request must validate");
    let certificate =
        certify_binding_time_b0d(&validated_binding_time).expect("B0 certificate must emit");
    let request = SpecializationRequest::p1v0(
        &artifact,
        &binding_time_request,
        &certificate,
        vec![],
        SpecializationBudget::new(1_000, 1_000, 100, 1_000, 1_000_000),
    )
    .expect("R0 request must encode");
    let validated = validate_specialization_r0a_request(
        &artifact,
        &binding_time_request,
        &certificate,
        &request,
    )
    .expect("R0-A request must validate");

    let r0b1 = evaluate_static_r0b1(&validated).expect("R0-B1 must evaluate");
    let r0b2 = evaluate_static_r0b2(&validated).expect("R0-B2 must evaluate");

    assert_eq!(
        r0b2.outcome(),
        &MixedStaticOutcome::Complete(SpecializationValue::I64(5))
    );
    assert_eq!(r0b2.steps(), r0b1.steps);
    assert_eq!(r0b2.steps(), 12);
    assert_eq!(r0b2.executed_nodes(), r0b1.executed_nodes);

    let oracle = evaluate(&artifact, vec![], EvaluationBudget::new(100, 10))
        .expect("canonical interpreter must evaluate the same source");
    assert_eq!(oracle.outcome, EvaluationOutcome::Return(CoreValue::I64(5)));
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
fn direct_call_completes_with_exact_steps_and_trace() {
    let artifact = call_program(false);
    let evaluation =
        evaluate_boundary(&artifact, vec![], vec![], 100).expect("direct call must evaluate");
    assert_eq!(
        evaluation.outcome(),
        &MixedStaticOutcome::Complete(SpecializationValue::I64(7))
    );
    let root0 = BindingTimeNodeId::root(FunctionId(0));
    let root1 = BindingTimeNodeId::root(FunctionId(1));
    let call_node = root0.child(BindingTimePathField::LetValue, 0);
    let return_term = root0.child(BindingTimePathField::LetNext, 0);
    assert_eq!(
        evaluation.executed_nodes(),
        vec![
            root0.clone(),
            call_node.clone(),
            call_node.child(BindingTimePathField::CallArgument, 0),
            root1.clone(),
            root1.child(BindingTimePathField::ReturnOperand, 0),
            return_term.clone(),
            return_term.child(BindingTimePathField::ReturnOperand, 0),
        ]
    );
    assert_eq!(evaluation.steps(), 7);
    assert!(evaluation.skipped_nodes().is_empty());

    let oracle = evaluate(&artifact, vec![], EvaluationBudget::new(100, 10))
        .expect("canonical interpreter must evaluate the same source");
    assert_eq!(oracle.outcome, EvaluationOutcome::Return(CoreValue::I64(7)));
}

#[test]
fn tail_call_completes_with_exact_steps_and_trace() {
    let artifact = call_program(true);
    let evaluation =
        evaluate_boundary(&artifact, vec![], vec![], 100).expect("tail call must evaluate");
    assert_eq!(
        evaluation.outcome(),
        &MixedStaticOutcome::Complete(SpecializationValue::I64(7))
    );
    let root0 = BindingTimeNodeId::root(FunctionId(0));
    let root1 = BindingTimeNodeId::root(FunctionId(1));
    assert_eq!(
        evaluation.executed_nodes(),
        vec![
            root0.clone(),
            root0.child(BindingTimePathField::TailCallArgument, 0),
            root1.clone(),
            root1.child(BindingTimePathField::ReturnOperand, 0),
        ]
    );
    assert_eq!(evaluation.steps(), 4);

    let oracle = evaluate(&artifact, vec![], EvaluationBudget::new(100, 10))
        .expect("canonical interpreter must evaluate the same source");
    assert_eq!(oracle.outcome, EvaluationOutcome::Return(CoreValue::I64(7)));
}

/// f1(n, acc) = if n < 1 { acc } else { f1(n - 1, acc * n) } as a proper tail
/// call; the entry tail-calls f1(n, 1).
fn tail_factorial_program(n: i64) -> CoreArtifact {
    seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::TailCall {
                function: FunctionId(1),
                arguments: vec![Operand::I64(n), Operand::I64(1)],
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![
                Parameter {
                    local: LocalId(0),
                    ty: Type::I64,
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
                ty: Type::Bool,
                value: i64_primitive(
                    Primitive::I64CmpLt,
                    vec![Operand::Local(LocalId(0)), Operand::I64(1)],
                ),
                next: Box::new(Term::If {
                    condition: Operand::Local(LocalId(2)),
                    then_term: Box::new(Term::Return(Operand::Local(LocalId(1)))),
                    else_term: Box::new(Term::Let {
                        binder: LocalId(3),
                        ty: Type::I64,
                        value: i64_primitive(
                            Primitive::I64Sub(NumericMode::Wrapping),
                            vec![Operand::Local(LocalId(0)), Operand::I64(1)],
                        ),
                        next: Box::new(Term::Let {
                            binder: LocalId(4),
                            ty: Type::I64,
                            value: i64_primitive(
                                Primitive::I64Mul(NumericMode::Wrapping),
                                vec![Operand::Local(LocalId(1)), Operand::Local(LocalId(0))],
                            ),
                            next: Box::new(Term::TailCall {
                                function: FunctionId(1),
                                arguments: vec![
                                    Operand::Local(LocalId(3)),
                                    Operand::Local(LocalId(4)),
                                ],
                            }),
                        }),
                    }),
                }),
            },
        },
    ])
}

#[test]
fn terminating_tail_recursion_completes_and_matches_the_interpreter() {
    let artifact = tail_factorial_program(5);
    let evaluation = evaluate_boundary(&artifact, vec![], vec![], 10_000)
        .expect("terminating tail recursion must evaluate");
    assert_eq!(
        evaluation.outcome(),
        &MixedStaticOutcome::Complete(SpecializationValue::I64(120))
    );
    assert!(evaluation.skipped_nodes().is_empty());

    let oracle = evaluate(&artifact, vec![], EvaluationBudget::new(10_000, 10))
        .expect("canonical interpreter must evaluate the same source");
    assert_eq!(
        oracle.outcome,
        EvaluationOutcome::Return(CoreValue::I64(120))
    );
}

/// f1(n) = if n < 1 { 0 } else { f1(n - 1) + n } through a non-tail direct
/// call; the entry binds f1(n) and returns it.
fn non_tail_sum_program(n: i64) -> CoreArtifact {
    seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(0),
                ty: Type::I64,
                value: RValue::Call {
                    function: FunctionId(1),
                    arguments: vec![Operand::I64(n)],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
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
            body: Term::Let {
                binder: LocalId(1),
                ty: Type::Bool,
                value: i64_primitive(
                    Primitive::I64CmpLt,
                    vec![Operand::Local(LocalId(0)), Operand::I64(1)],
                ),
                next: Box::new(Term::If {
                    condition: Operand::Local(LocalId(1)),
                    then_term: Box::new(Term::Return(Operand::I64(0))),
                    else_term: Box::new(Term::Let {
                        binder: LocalId(2),
                        ty: Type::I64,
                        value: i64_primitive(
                            Primitive::I64Sub(NumericMode::Wrapping),
                            vec![Operand::Local(LocalId(0)), Operand::I64(1)],
                        ),
                        next: Box::new(Term::Let {
                            binder: LocalId(3),
                            ty: Type::I64,
                            value: RValue::Call {
                                function: FunctionId(1),
                                arguments: vec![Operand::Local(LocalId(2))],
                            },
                            next: Box::new(Term::Let {
                                binder: LocalId(4),
                                ty: Type::I64,
                                value: i64_primitive(
                                    Primitive::I64Add(NumericMode::Wrapping),
                                    vec![Operand::Local(LocalId(3)), Operand::Local(LocalId(0))],
                                ),
                                next: Box::new(Term::Return(Operand::Local(LocalId(4)))),
                            }),
                        }),
                    }),
                }),
            },
        },
    ])
}

#[test]
fn terminating_non_tail_recursion_completes_and_matches_the_interpreter() {
    let artifact = non_tail_sum_program(5);
    let evaluation = evaluate_boundary(&artifact, vec![], vec![], 10_000)
        .expect("terminating non-tail recursion must evaluate");
    assert_eq!(
        evaluation.outcome(),
        &MixedStaticOutcome::Complete(SpecializationValue::I64(15))
    );

    let oracle = evaluate(&artifact, vec![], EvaluationBudget::new(10_000, 20))
        .expect("canonical interpreter must evaluate the same source");
    assert_eq!(
        oracle.outcome,
        EvaluationOutcome::Return(CoreValue::I64(15))
    );
}

#[test]
fn deep_non_tail_recursion_fails_closed_at_the_frame_cap() {
    let artifact = non_tail_sum_program(300);
    let error = evaluate_boundary(&artifact, vec![], vec![], 1_000_000)
        .expect_err("recursion deeper than the frame cap must fail closed");
    assert!(
        matches!(
            error,
            StaticEvaluationError::FrameBudgetExceeded {
                limit: R0B2_MAX_FRAMES,
                ..
            }
        ),
        "unexpected error: {error:?}"
    );
}

/// f1(n) = f1(n) — a statically eligible tail loop that never terminates.
fn unbounded_tail_loop_program() -> CoreArtifact {
    seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::TailCall {
                function: FunctionId(1),
                arguments: vec![Operand::I64(0)],
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
            body: Term::TailCall {
                function: FunctionId(1),
                arguments: vec![Operand::Local(LocalId(0))],
            },
        },
    ])
}

#[test]
fn unbounded_tail_recursion_exhausts_the_step_budget_and_fails_closed() {
    let error = evaluate_boundary(&unbounded_tail_loop_program(), vec![], vec![], 1_000)
        .expect_err("an unbounded static loop must exhaust the step budget");
    assert!(
        matches!(
            error,
            StaticEvaluationError::StepBudgetExceeded { limit: 1_000, .. }
        ),
        "unexpected error: {error:?}"
    );
}

/// Entry(x dynamic): a = 1 + 2; b = x * 2; c = a + 5; return b.
fn mixed_spine_program() -> CoreArtifact {
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
            value: i64_primitive(
                Primitive::I64Add(NumericMode::Wrapping),
                vec![Operand::I64(1), Operand::I64(2)],
            ),
            next: Box::new(Term::Let {
                binder: LocalId(2),
                ty: Type::I64,
                value: i64_primitive(
                    Primitive::I64Mul(NumericMode::Wrapping),
                    vec![Operand::Local(LocalId(0)), Operand::I64(2)],
                ),
                next: Box::new(Term::Let {
                    binder: LocalId(3),
                    ty: Type::I64,
                    value: i64_primitive(
                        Primitive::I64Add(NumericMode::Wrapping),
                        vec![Operand::Local(LocalId(1)), Operand::I64(5)],
                    ),
                    next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
                }),
            }),
        },
    }])
}

#[test]
fn a_mixed_frontier_collects_static_facts_past_skipped_dynamic_values() {
    let artifact = mixed_spine_program();
    let first = evaluate_boundary(
        &artifact,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        100,
    )
    .expect("a mixed spine must evaluate to a frontier");
    let second = evaluate_boundary(
        &artifact,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        100,
    )
    .expect("repeated evaluation must pass");

    let root = BindingTimeNodeId::root(FunctionId(0));
    let first_value = root.child(BindingTimePathField::LetValue, 0);
    let second_term = root.child(BindingTimePathField::LetNext, 0);
    let second_value = second_term.child(BindingTimePathField::LetValue, 0);
    let third_term = second_term.child(BindingTimePathField::LetNext, 0);
    let third_value = third_term.child(BindingTimePathField::LetValue, 0);
    let return_term = third_term.child(BindingTimePathField::LetNext, 0);

    assert_eq!(
        first.outcome(),
        &MixedStaticOutcome::MixedFrontier {
            halt: StaticResidual {
                node: return_term.child(BindingTimePathField::ReturnOperand, 0),
                reason: StaticResidualReason::DynamicDependency,
            },
            static_facts: vec![
                StaticFact {
                    local: LocalId(1),
                    value: SpecializationValue::I64(3),
                },
                StaticFact {
                    local: LocalId(3),
                    value: SpecializationValue::I64(8),
                },
            ],
        }
    );
    assert_eq!(
        first.skipped_nodes(),
        vec![SkippedStaticNode {
            node: second_value,
            reason: StaticResidualReason::DynamicDependency,
        }]
    );
    assert_eq!(
        first.executed_nodes(),
        vec![
            first_value.clone(),
            first_value.child(BindingTimePathField::PrimitiveArgument, 0),
            first_value.child(BindingTimePathField::PrimitiveArgument, 1),
            third_value.clone(),
            third_value.child(BindingTimePathField::PrimitiveArgument, 0),
            third_value.child(BindingTimePathField::PrimitiveArgument, 1),
        ]
    );
    assert_eq!(first.steps(), 6);
    assert_eq!(first, second, "the mixed frontier must be deterministic");
}

/// Entry(): a = checked 1 + 2 (denied); b = a + 1 (poisoned); return b.
fn denied_poison_program() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::canonical(vec![Effect::Error(ErrorKind::Overflow)]),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(0),
            ty: Type::I64,
            value: i64_primitive(
                Primitive::I64Add(NumericMode::Checked),
                vec![Operand::I64(1), Operand::I64(2)],
            ),
            next: Box::new(Term::Let {
                binder: LocalId(1),
                ty: Type::I64,
                value: i64_primitive(
                    Primitive::I64Add(NumericMode::Wrapping),
                    vec![Operand::Local(LocalId(0)), Operand::I64(1)],
                ),
                next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
            }),
        },
    }])
}

#[test]
fn a_skipped_denied_value_poisons_dependents_without_execution() {
    let artifact = denied_poison_program();
    let evaluation =
        evaluate_boundary(&artifact, vec![], vec![], 100).expect("denied work must skip, not fail");

    let root = BindingTimeNodeId::root(FunctionId(0));
    let denied_value = root.child(BindingTimePathField::LetValue, 0);
    let second_term = root.child(BindingTimePathField::LetNext, 0);
    let poisoned_value = second_term.child(BindingTimePathField::LetValue, 0);
    let return_term = second_term.child(BindingTimePathField::LetNext, 0);

    assert_eq!(
        evaluation.skipped_nodes(),
        vec![
            SkippedStaticNode {
                node: denied_value,
                reason: StaticResidualReason::DeniedByCertificate,
            },
            SkippedStaticNode {
                node: poisoned_value,
                reason: StaticResidualReason::UnavailableStaticValue,
            },
        ]
    );
    assert_eq!(
        evaluation.outcome(),
        &MixedStaticOutcome::MixedFrontier {
            halt: StaticResidual {
                node: return_term.child(BindingTimePathField::ReturnOperand, 0),
                reason: StaticResidualReason::UnavailableStaticValue,
            },
            static_facts: vec![],
        }
    );
    assert_eq!(evaluation.executed_nodes(), vec![second_term, return_term]);
    assert_eq!(evaluation.steps(), 2);
}

/// Entry(x dynamic): a = f1(x); return a — the call joins f1's parameter to
/// Dynamic, so the call node itself is dynamic and must be skipped, never
/// entered.
fn dynamic_call_program() -> CoreArtifact {
    seal(vec![
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
                    arguments: vec![Operand::Local(LocalId(0))],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
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

#[test]
fn a_dynamic_call_is_skipped_and_its_callee_is_never_entered() {
    let artifact = dynamic_call_program();
    let evaluation = evaluate_boundary(
        &artifact,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        100,
    )
    .expect("a dynamic call must skip, not fail");

    let root0 = BindingTimeNodeId::root(FunctionId(0));
    let call_node = root0.child(BindingTimePathField::LetValue, 0);
    let return_term = root0.child(BindingTimePathField::LetNext, 0);
    assert_eq!(
        evaluation.skipped_nodes(),
        vec![SkippedStaticNode {
            node: call_node,
            reason: StaticResidualReason::DynamicDependency,
        }]
    );
    assert_eq!(
        evaluation.outcome(),
        &MixedStaticOutcome::MixedFrontier {
            halt: StaticResidual {
                node: return_term.child(BindingTimePathField::ReturnOperand, 0),
                reason: StaticResidualReason::DynamicDependency,
            },
            static_facts: vec![],
        }
    );
    assert_eq!(evaluation.steps(), 0);
    assert!(evaluation.executed_nodes().is_empty());
}

#[test]
fn an_unused_dynamic_parameter_still_completes_statically() {
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
        evaluation.outcome(),
        &MixedStaticOutcome::Complete(SpecializationValue::I64(42))
    );
    assert_eq!(evaluation.steps(), 2);
}

/// The locked interprocedural mixed vector:
/// entry(x dynamic): a = f1(3, 1); b = a + x; c = a + 1; return b
/// with f1 the tail-recursive factorial. Expected: a = 6, c = 7, b skipped,
/// halt at the dynamic return operand.
fn locked_vector_program() -> CoreArtifact {
    let factorial = tail_factorial_program(3);
    let f1 = factorial.program.functions[1].clone();
    seal(vec![
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
                    arguments: vec![Operand::I64(3), Operand::I64(1)],
                },
                next: Box::new(Term::Let {
                    binder: LocalId(2),
                    ty: Type::I64,
                    value: i64_primitive(
                        Primitive::I64Add(NumericMode::Wrapping),
                        vec![Operand::Local(LocalId(1)), Operand::Local(LocalId(0))],
                    ),
                    next: Box::new(Term::Let {
                        binder: LocalId(3),
                        ty: Type::I64,
                        value: i64_primitive(
                            Primitive::I64Add(NumericMode::Wrapping),
                            vec![Operand::Local(LocalId(1)), Operand::I64(1)],
                        ),
                        next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
                    }),
                }),
            },
        },
        f1,
    ])
}

#[test]
fn the_locked_interprocedural_mixed_vector_is_stable() {
    let artifact = locked_vector_program();
    let first = evaluate_boundary(
        &artifact,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        10_000,
    )
    .expect("the locked vector must evaluate");
    let second = evaluate_boundary(
        &artifact,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        10_000,
    )
    .expect("repeated evaluation must pass");

    let root0 = BindingTimeNodeId::root(FunctionId(0));
    let call_node = root0.child(BindingTimePathField::LetValue, 0);
    let second_term = root0.child(BindingTimePathField::LetNext, 0);
    let skipped_value = second_term.child(BindingTimePathField::LetValue, 0);
    let third_term = second_term.child(BindingTimePathField::LetNext, 0);
    let return_term = third_term.child(BindingTimePathField::LetNext, 0);

    assert_eq!(
        first.outcome(),
        &MixedStaticOutcome::MixedFrontier {
            halt: StaticResidual {
                node: return_term.child(BindingTimePathField::ReturnOperand, 0),
                reason: StaticResidualReason::DynamicDependency,
            },
            static_facts: vec![
                StaticFact {
                    local: LocalId(1),
                    value: SpecializationValue::I64(6),
                },
                StaticFact {
                    local: LocalId(3),
                    value: SpecializationValue::I64(7),
                },
            ],
        }
    );
    assert_eq!(
        first.skipped_nodes(),
        vec![SkippedStaticNode {
            node: skipped_value,
            reason: StaticResidualReason::DynamicDependency,
        }]
    );
    assert_eq!(first.steps(), 65);
    assert_eq!(first.executed_nodes().len() as u64, first.steps());
    assert_eq!(
        first.executed_nodes().first(),
        Some(&call_node),
        "execution must begin at the eligible call"
    );
    assert_eq!(first, second, "the locked vector must be deterministic");
}
