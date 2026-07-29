use naux::core::{
    certify_binding_time_b0d, evaluate, evaluate_static_r0b2, generate_residual_r0c,
    validate_binding_time_b0_request, validate_specialization_r0a_request, BindingTime,
    BindingTimeBudget, BindingTimeRequest, CoreArtifact, CoreProfile, CoreValue, Effect, EffectRow,
    ErrorKind, EvaluationBudget, EvaluationOutcome, Function, FunctionId, LocalId, NumericMode,
    Operand, Parameter, Primitive, Program, RValue, ResidualCore, ResidualGenerationError,
    SpecializationBudget, SpecializationRequest, SpecializationSlot, SpecializationValue, Term,
    Type,
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

/// Drive the full B0 -> R0-A -> R0-B2 -> R0-C1 chain for one artifact.
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
        SpecializationBudget::new(1_000, 1_000, 10_000, max_residual_nodes, max_residual_bytes),
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
    generate_residual_r0c(&validated, &evaluation)
}

fn i64_primitive(operation: Primitive, arguments: Vec<Operand>) -> RValue {
    RValue::Primitive {
        operation,
        arguments,
    }
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
}

#[test]
fn a_mixed_frontier_residual_substitutes_facts_and_matches_original_behavior() {
    let artifact = mixed_spine_program();
    let first = residual_boundary(
        &artifact,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        1_000,
        1_000_000,
    )
    .expect("the mixed spine must residualize");
    let second = residual_boundary(
        &artifact,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        1_000,
        1_000_000,
    )
    .expect("repeated generation must pass");

    let entry = &first.artifact.program.functions[0];
    assert_eq!(
        entry.parameters,
        vec![Parameter {
            local: LocalId(0),
            ty: Type::I64,
        }]
    );
    assert_eq!(
        entry.body,
        Term::Let {
            binder: LocalId(1),
            ty: Type::I64,
            value: RValue::Use(Operand::I64(3)),
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
                    value: RValue::Use(Operand::I64(8)),
                    next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
                }),
            }),
        }
    );
    assert_eq!(first.source_hash, artifact.semantic_hash);
    assert_ne!(first.artifact.semantic_hash, artifact.semantic_hash);
    assert_eq!(first, second, "residual generation must be deterministic");

    for x in [-3_i64, 0, 5, 9_999] {
        assert_differential(
            &artifact,
            vec![CoreValue::I64(x)],
            &first.artifact,
            vec![CoreValue::I64(x)],
        );
    }
}

/// Entry(s static, x dynamic): r = s + x; return r.
fn static_parameter_program() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
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
            ty: Type::I64,
            value: i64_primitive(
                Primitive::I64Add(NumericMode::Wrapping),
                vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(1))],
            ),
            next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
        },
    }])
}

#[test]
fn a_static_parameter_is_bound_in_a_prologue_and_the_signature_narrows() {
    let artifact = static_parameter_program();
    let residual = residual_boundary(
        &artifact,
        vec![BindingTime::Static, BindingTime::Dynamic],
        vec![
            SpecializationSlot::Static(SpecializationValue::I64(5)),
            SpecializationSlot::Dynamic(Type::I64),
        ],
        1_000,
        1_000_000,
    )
    .expect("the static parameter must residualize");

    let entry = &residual.artifact.program.functions[0];
    assert_eq!(
        entry.parameters,
        vec![Parameter {
            local: LocalId(1),
            ty: Type::I64,
        }],
        "the residual entry must take only the dynamic parameter"
    );
    assert_eq!(
        entry.body,
        Term::Let {
            binder: LocalId(0),
            ty: Type::I64,
            value: RValue::Use(Operand::I64(5)),
            next: Box::new(Term::Let {
                binder: LocalId(2),
                ty: Type::I64,
                value: i64_primitive(
                    Primitive::I64Add(NumericMode::Wrapping),
                    vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(1))],
                ),
                next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
            }),
        }
    );

    for x in [-11_i64, 0, 37] {
        assert_differential(
            &artifact,
            vec![CoreValue::I64(5), CoreValue::I64(x)],
            &residual.artifact,
            vec![CoreValue::I64(x)],
        );
    }
}

/// Entry(y static): a = y + 1 wrapping; b = a - 1 saturating; return b.
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
fn a_complete_evaluation_without_skips_collapses_to_its_constant() {
    let artifact = wrapping_saturating_program();
    let residual = residual_boundary(
        &artifact,
        vec![BindingTime::Static],
        vec![SpecializationSlot::Static(SpecializationValue::I64(
            i64::MAX,
        ))],
        1_000,
        1_000_000,
    )
    .expect("the fully static program must residualize");

    let entry = &residual.artifact.program.functions[0];
    assert!(entry.parameters.is_empty());
    assert_eq!(entry.body, Term::Return(Operand::I64(i64::MIN)));

    let original_run = evaluate(
        &artifact,
        vec![CoreValue::I64(i64::MAX)],
        EvaluationBudget::new(100, 10),
    )
    .expect("original must evaluate");
    let residual_run = evaluate(&residual.artifact, vec![], EvaluationBudget::new(100, 10))
        .expect("residual must evaluate");
    assert_eq!(original_run.outcome, residual_run.outcome);
}

/// Entry(): a = checked MAX + 1 (denied, skipped); return 7 — the skipped
/// overflow effect must survive residualization.
fn denied_effect_program() -> CoreArtifact {
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
                vec![Operand::I64(i64::MAX), Operand::I64(1)],
            ),
            next: Box::new(Term::Return(Operand::I64(7))),
        },
    }])
}

#[test]
fn a_complete_evaluation_with_skips_preserves_the_skipped_effect() {
    let artifact = denied_effect_program();
    let residual = residual_boundary(&artifact, vec![], vec![], 1_000, 1_000_000)
        .expect("skipped denied work must residualize");

    let entry = &residual.artifact.program.functions[0];
    assert_eq!(
        entry.body, artifact.program.functions[0].body,
        "the skipped denied computation must be preserved verbatim"
    );

    let original_run = evaluate(&artifact, vec![], EvaluationBudget::new(100, 10))
        .expect("original must evaluate");
    let residual_run = evaluate(&residual.artifact, vec![], EvaluationBudget::new(100, 10))
        .expect("residual must evaluate");
    assert_eq!(
        original_run.outcome,
        EvaluationOutcome::Error(ErrorKind::Overflow),
        "the original observes the overflow effect"
    );
    assert_eq!(original_run.outcome, residual_run.outcome);
}

/// The R0-B2 locked vector program: entry(x): a = f1(3, 1); b = a + x;
/// c = a + 1; return b, with f1 the tail-recursive factorial.
fn locked_vector_program() -> CoreArtifact {
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
fn the_locked_vector_residual_folds_the_call_and_keeps_the_callee() {
    let artifact = locked_vector_program();
    let residual = residual_boundary(
        &artifact,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        1_000,
        1_000_000,
    )
    .expect("the locked vector must residualize");

    let entry = &residual.artifact.program.functions[0];
    assert_eq!(
        entry.body,
        Term::Let {
            binder: LocalId(1),
            ty: Type::I64,
            value: RValue::Use(Operand::I64(6)),
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
                    value: RValue::Use(Operand::I64(7)),
                    next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
                }),
            }),
        },
        "the statically executed call must fold to its constant"
    );
    assert_eq!(
        residual.artifact.program.functions[1], artifact.program.functions[1],
        "the callee is preserved unchanged"
    );

    for x in [-6_i64, 0, 100] {
        assert_differential(
            &artifact,
            vec![CoreValue::I64(x)],
            &residual.artifact,
            vec![CoreValue::I64(x)],
        );
    }
}

#[test]
fn a_forged_evaluation_record_fails_closed() {
    let mixed = mixed_spine_program();
    let other = wrapping_saturating_program();

    let build = |artifact: &CoreArtifact, manifest: Vec<BindingTime>| {
        let binding_time_request = BindingTimeRequest::p1v0(
            artifact,
            manifest,
            BindingTimeBudget::new(100_000, 100_000, 1_000),
        )
        .expect("B0 request must encode");
        let certificate = certify_binding_time_b0d(
            &validate_binding_time_b0_request(artifact, &binding_time_request)
                .expect("B0 request must validate"),
        )
        .expect("B0 certificate must emit");
        (binding_time_request, certificate)
    };

    let (mixed_b0, mixed_certificate) = build(&mixed, vec![BindingTime::Dynamic]);
    let mixed_request = SpecializationRequest::p1v0(
        &mixed,
        &mixed_b0,
        &mixed_certificate,
        vec![SpecializationSlot::Dynamic(Type::I64)],
        SpecializationBudget::new(1_000, 1_000, 10_000, 1_000, 1_000_000),
    )
    .expect("R0 request must encode");
    let mixed_validated =
        validate_specialization_r0a_request(&mixed, &mixed_b0, &mixed_certificate, &mixed_request)
            .expect("R0-A request must validate");

    let (other_b0, other_certificate) = build(&other, vec![BindingTime::Static]);
    let other_request = SpecializationRequest::p1v0(
        &other,
        &other_b0,
        &other_certificate,
        vec![SpecializationSlot::Static(SpecializationValue::I64(1))],
        SpecializationBudget::new(1_000, 1_000, 10_000, 1_000, 1_000_000),
    )
    .expect("R0 request must encode");
    let other_validated =
        validate_specialization_r0a_request(&other, &other_b0, &other_certificate, &other_request)
            .expect("R0-A request must validate");
    let other_evaluation =
        evaluate_static_r0b2(&other_validated).expect("the other program must evaluate");

    let error = generate_residual_r0c(&mixed_validated, &other_evaluation)
        .expect_err("a record from another request must be rejected");
    assert!(
        matches!(error, ResidualGenerationError::RecordMismatch { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn an_aggregate_static_slot_fails_closed() {
    let array = Type::Array {
        region: naux::core::RegionId(0),
        mutability: naux::core::Mutability::Read,
        element: Box::new(Type::F64),
    };
    let artifact = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![naux::core::RegionId(0)],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: array,
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(1),
            ty: Type::I64,
            value: i64_primitive(Primitive::ArrayLenF64, vec![Operand::Local(LocalId(0))]),
            next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
        },
    }]);
    let error = residual_boundary(
        &artifact,
        vec![BindingTime::Static],
        vec![SpecializationSlot::Static(SpecializationValue::ArrayF64(
            vec![1.0, 2.0],
        ))],
        1_000,
        1_000_000,
    )
    .expect_err("an aggregate static slot must be refused in R0-C1");
    assert_eq!(
        error,
        ResidualGenerationError::UnsupportedStaticSlot {
            parameter: LocalId(0),
        }
    );
}

#[test]
fn residual_budgets_fail_closed() {
    let artifact = mixed_spine_program();
    let nodes = residual_boundary(
        &artifact,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        1,
        1_000_000,
    )
    .expect_err("a one-node residual budget must be exceeded");
    assert!(
        matches!(
            nodes,
            ResidualGenerationError::ResidualNodeBudgetExceeded { limit: 1, .. }
        ),
        "unexpected error: {nodes:?}"
    );

    let bytes = residual_boundary(
        &artifact,
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
        1_000,
        8,
    )
    .expect_err("an eight-byte residual budget must be exceeded");
    assert!(
        matches!(
            bytes,
            ResidualGenerationError::ResidualByteBudgetExceeded { limit: 8, .. }
        ),
        "unexpected error: {bytes:?}"
    );
}
