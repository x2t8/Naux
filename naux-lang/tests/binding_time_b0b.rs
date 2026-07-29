use naux::core::{
    analyze_binding_time_b0b, binding_time_node_bytes, binding_time_node_hash,
    validate_binding_time_b0_request, BindingTime, BindingTimeAnalysis, BindingTimeAnalysisCode,
    BindingTimeBudget, BindingTimeNodeId, BindingTimePathField, BindingTimeRequest, CaseArm,
    ConstructorType, CoreArtifact, CoreProfile, Effect, EffectRow, ErrorKind, Function, FunctionId,
    LocalId, NumericMode, Operand, Parameter, Primitive, Program, RValue,
    StaticEvaluationEligibility, SumType, Term, Type,
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

fn budget(max_nodes: u64) -> BindingTimeBudget {
    BindingTimeBudget::new(max_nodes, 64, 16)
}

fn analyze(
    artifact: &CoreArtifact,
    manifest: Vec<BindingTime>,
    max_nodes: u64,
) -> Result<BindingTimeAnalysis, naux::core::BindingTimeAnalysisError> {
    let request = BindingTimeRequest::p1v0(artifact, manifest, budget(max_nodes))
        .expect("request must encode");
    let validated =
        validate_binding_time_b0_request(artifact, &request).expect("request must validate");
    analyze_binding_time_b0b(&validated)
}

fn wrapping_add_program() -> CoreArtifact {
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
            next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
        },
    }])
}

fn judgment<'analysis>(
    analysis: &'analysis BindingTimeAnalysis,
    node: &BindingTimeNodeId,
) -> &'analysis naux::core::BindingTimeJudgment {
    analysis
        .judgments
        .iter()
        .find(|judgment| judgment.node == *node)
        .expect("node judgment must exist")
}

#[test]
fn node_identity_tags_encoding_and_hash_are_locked() {
    let fields = [
        BindingTimePathField::LetValue,
        BindingTimePathField::LetNext,
        BindingTimePathField::IfCondition,
        BindingTimePathField::IfThen,
        BindingTimePathField::IfElse,
        BindingTimePathField::CaseScrutinee,
        BindingTimePathField::CaseArm,
        BindingTimePathField::ReturnOperand,
        BindingTimePathField::UseOperand,
        BindingTimePathField::TupleElement,
        BindingTimePathField::ProjectTuple,
        BindingTimePathField::ConstructField,
        BindingTimePathField::PrimitiveArgument,
        BindingTimePathField::CallArgument,
        BindingTimePathField::TailCallArgument,
    ];
    for (tag, field) in fields.into_iter().enumerate() {
        assert_eq!(field.tag(), tag as u8);
    }

    let node = BindingTimeNodeId::root(FunctionId(3))
        .child(BindingTimePathField::LetValue, 0)
        .child(BindingTimePathField::PrimitiveArgument, 1);
    let mut expected = b"NAUX:core-n0:binding-time-node:b0:v1\0".to_vec();
    expected.extend_from_slice(&3u32.to_be_bytes());
    expected.extend_from_slice(&2u32.to_be_bytes());
    expected.push(0);
    expected.extend_from_slice(&0u32.to_be_bytes());
    expected.push(12);
    expected.extend_from_slice(&1u32.to_be_bytes());

    assert_eq!(
        binding_time_node_bytes(&node).expect("node must encode"),
        expected
    );
    assert_eq!(
        binding_time_node_hash(&node)
            .expect("node must hash")
            .to_hex(),
        "dd595008d078ed4efbcf91aabb73ac9bccb16bea1cdeda63a4385996f95501fa"
    );
}

#[test]
fn static_intraprocedural_dataflow_is_eligible_and_canonically_ordered() {
    let artifact = wrapping_add_program();
    let analysis = analyze(&artifact, vec![BindingTime::Static], 64).expect("analysis must pass");

    assert_eq!(analysis.result_binding_time, BindingTime::Static);
    assert_eq!(
        analysis.static_evaluation,
        StaticEvaluationEligibility::EligiblePure
    );
    assert_eq!(analysis.budget_usage.nodes, 6);
    assert_eq!(analysis.budget_usage.call_edges, 0);
    assert_eq!(analysis.budget_usage.fixpoint_iterations, 0);
    assert!(analysis
        .judgments
        .windows(2)
        .all(|pair| pair[0].node < pair[1].node));

    let primitive = BindingTimeNodeId::root(FunctionId(0)).child(BindingTimePathField::LetValue, 0);
    assert_eq!(
        judgment(&analysis, &primitive).static_evaluation,
        StaticEvaluationEligibility::EligiblePure
    );
}

#[test]
fn dynamic_parameter_contaminates_its_data_dependents() {
    let artifact = wrapping_add_program();
    let analysis = analyze(&artifact, vec![BindingTime::Dynamic], 64).expect("analysis must pass");

    assert_eq!(analysis.result_binding_time, BindingTime::Dynamic);
    assert_eq!(
        analysis.static_evaluation,
        StaticEvaluationEligibility::Denied
    );
    let literal = BindingTimeNodeId::root(FunctionId(0))
        .child(BindingTimePathField::LetValue, 0)
        .child(BindingTimePathField::PrimitiveArgument, 1);
    assert_eq!(
        judgment(&analysis, &literal).binding_time,
        BindingTime::Static
    );
}

fn branch_program() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: Type::Bool,
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::If {
            condition: Operand::Local(LocalId(0)),
            then_term: Box::new(Term::Return(Operand::I64(7))),
            else_term: Box::new(Term::Return(Operand::I64(9))),
        },
    }])
}

#[test]
fn dynamic_control_contaminates_both_branch_results() {
    let artifact = branch_program();
    let dynamic = analyze(&artifact, vec![BindingTime::Dynamic], 64).expect("analysis must pass");
    assert_eq!(dynamic.result_binding_time, BindingTime::Dynamic);

    let then_literal = BindingTimeNodeId::root(FunctionId(0))
        .child(BindingTimePathField::IfThen, 0)
        .child(BindingTimePathField::ReturnOperand, 0);
    let else_literal = BindingTimeNodeId::root(FunctionId(0))
        .child(BindingTimePathField::IfElse, 0)
        .child(BindingTimePathField::ReturnOperand, 0);
    assert_eq!(
        judgment(&dynamic, &then_literal).binding_time,
        BindingTime::Dynamic
    );
    assert_eq!(
        judgment(&dynamic, &else_literal).binding_time,
        BindingTime::Dynamic
    );

    let static_analysis =
        analyze(&artifact, vec![BindingTime::Static], 64).expect("analysis must pass");
    assert_eq!(static_analysis.result_binding_time, BindingTime::Static);
    assert_eq!(
        static_analysis.static_evaluation,
        StaticEvaluationEligibility::EligiblePure
    );
}

#[test]
fn tuple_projection_constructor_and_case_follow_whole_value_dependencies() {
    let pair = Type::Tuple(vec![Type::I64, Type::I64]);
    let tuple_artifact = seal(vec![Function {
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
            ty: pair,
            value: RValue::Tuple(vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(1))]),
            next: Box::new(Term::Let {
                binder: LocalId(3),
                ty: Type::I64,
                value: RValue::Project {
                    tuple: Operand::Local(LocalId(2)),
                    index: 1,
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
            }),
        },
    }]);
    let tuple_analysis = analyze(
        &tuple_artifact,
        vec![BindingTime::Static, BindingTime::Dynamic],
        64,
    )
    .expect("tuple analysis must pass");
    assert_eq!(tuple_analysis.result_binding_time, BindingTime::Dynamic);

    let option_i64 = SumType {
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
    let case_artifact = seal(vec![Function {
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
            ty: Type::Sum(option_i64.clone()),
            value: RValue::Construct {
                sum: option_i64,
                constructor: 1,
                fields: vec![Operand::Local(LocalId(0))],
            },
            next: Box::new(Term::Case {
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
        },
    }]);
    let static_case =
        analyze(&case_artifact, vec![BindingTime::Static], 64).expect("static case must pass");
    let dynamic_case =
        analyze(&case_artifact, vec![BindingTime::Dynamic], 64).expect("dynamic case must pass");
    assert_eq!(static_case.result_binding_time, BindingTime::Static);
    assert_eq!(dynamic_case.result_binding_time, BindingTime::Dynamic);
}

#[test]
fn checked_primitive_is_static_but_not_default_static_evaluable() {
    let artifact = seal(vec![Function {
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
                arguments: vec![Operand::I64(1), Operand::I64(2)],
            },
            next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
        },
    }]);
    let analysis = analyze(&artifact, vec![], 64).expect("analysis must pass");

    assert_eq!(analysis.result_binding_time, BindingTime::Static);
    assert_eq!(
        analysis.static_evaluation,
        StaticEvaluationEligibility::Denied
    );
    let primitive = BindingTimeNodeId::root(FunctionId(0)).child(BindingTimePathField::LetValue, 0);
    assert_eq!(
        judgment(&analysis, &primitive).static_evaluation,
        StaticEvaluationEligibility::Denied
    );
}

#[test]
fn direct_and_tail_calls_fail_closed_until_b0c() {
    let direct = seal(vec![
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
                    arguments: vec![],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Return(Operand::I64(1)),
        },
    ]);
    let error = analyze(&direct, vec![], 64).expect_err("direct call must fail in B0-B");
    assert_eq!(
        error.code,
        BindingTimeAnalysisCode::UnsupportedInterprocedural
    );

    let tail = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::Unit,
        body: Term::TailCall {
            function: FunctionId(0),
            arguments: vec![],
        },
    }]);
    let error = analyze(&tail, vec![], 64).expect_err("tail call must fail in B0-B");
    assert_eq!(
        error.code,
        BindingTimeAnalysisCode::UnsupportedInterprocedural
    );
}

#[test]
fn node_budget_is_exact_and_exhaustion_returns_no_analysis() {
    let artifact = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Return(Operand::I64(1)),
    }]);

    let exact = analyze(&artifact, vec![], 2).expect("two-node budget must pass");
    assert_eq!(exact.budget_usage.nodes, 2);
    let error = analyze(&artifact, vec![], 1).expect_err("one-node budget must fail");
    assert_eq!(error.code, BindingTimeAnalysisCode::NodeBudgetExceeded);
}

#[test]
fn repeated_analysis_is_deterministic() {
    let artifact = wrapping_add_program();
    let first = analyze(&artifact, vec![BindingTime::Static], 64).expect("analysis must pass");
    let second = analyze(&artifact, vec![BindingTime::Static], 128).expect("analysis must pass");

    assert_eq!(first.judgments, second.judgments);
    assert_eq!(first.result_binding_time, second.result_binding_time);
    assert_eq!(first.static_evaluation, second.static_evaluation);
    assert_eq!(first.budget_usage, second.budget_usage);
    assert_ne!(first.request_hash, second.request_hash);
}
