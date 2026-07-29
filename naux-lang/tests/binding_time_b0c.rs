use naux::core::{
    analyze_binding_time_b0c, validate_binding_time_b0_request, BindingTime, BindingTimeAnalysis,
    BindingTimeAnalysisCode, BindingTimeBudget, BindingTimeNodeId, BindingTimePathField,
    BindingTimeRequest, CoreArtifact, CoreProfile, Effect, EffectRow, ErrorKind, Function,
    FunctionId, LocalId, NumericMode, Operand, Parameter, Primitive, Program, RValue,
    StaticEvaluationEligibility, Term, Type,
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

fn analyze(
    artifact: &CoreArtifact,
    manifest: Vec<BindingTime>,
    budget: BindingTimeBudget,
) -> Result<BindingTimeAnalysis, naux::core::BindingTimeAnalysisError> {
    let request =
        BindingTimeRequest::p1v0(artifact, manifest, budget).expect("request must encode");
    let validated =
        validate_binding_time_b0_request(artifact, &request).expect("request must validate");
    analyze_binding_time_b0c(&validated)
}

fn generous_budget() -> BindingTimeBudget {
    BindingTimeBudget::new(10_000, 10_000, 1_000)
}

fn identity_call_program(tail: bool) -> CoreArtifact {
    let call = if tail {
        Term::TailCall {
            function: FunctionId(1),
            arguments: vec![Operand::Local(LocalId(0))],
        }
    } else {
        Term::Let {
            binder: LocalId(1),
            ty: Type::I64,
            value: RValue::Call {
                function: FunctionId(1),
                arguments: vec![Operand::Local(LocalId(0))],
            },
            next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
        }
    };
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
            body: call,
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
fn direct_call_reaches_a_deterministic_least_fixed_point() {
    let artifact = identity_call_program(false);
    let static_analysis = analyze(&artifact, vec![BindingTime::Static], generous_budget())
        .expect("static direct call must analyze");
    assert_eq!(static_analysis.result_binding_time, BindingTime::Static);
    assert_eq!(
        static_analysis.static_evaluation,
        StaticEvaluationEligibility::EligiblePure
    );
    assert_eq!(static_analysis.budget_usage.fixpoint_iterations, 2);
    assert_eq!(static_analysis.budget_usage.call_edges, 2);

    let dynamic_analysis = analyze(&artifact, vec![BindingTime::Dynamic], generous_budget())
        .expect("dynamic direct call must analyze");
    assert_eq!(dynamic_analysis.result_binding_time, BindingTime::Dynamic);
    assert_eq!(
        dynamic_analysis.static_evaluation,
        StaticEvaluationEligibility::Denied
    );
    assert_eq!(dynamic_analysis.budget_usage.fixpoint_iterations, 4);
    assert!(dynamic_analysis
        .function_summaries
        .windows(2)
        .all(|pair| pair[0].function < pair[1].function));
    assert_eq!(
        dynamic_analysis.function_summaries[1].parameters,
        vec![BindingTime::Dynamic]
    );

    let argument = BindingTimeNodeId::root(FunctionId(0))
        .child(BindingTimePathField::LetValue, 0)
        .child(BindingTimePathField::CallArgument, 0);
    assert!(dynamic_analysis
        .judgments
        .iter()
        .any(|judgment| judgment.node == argument));
}

#[test]
fn tail_call_uses_the_same_summary_and_reserved_argument_path() {
    let artifact = identity_call_program(true);
    let analysis = analyze(&artifact, vec![BindingTime::Dynamic], generous_budget())
        .expect("tail call must analyze");

    assert_eq!(analysis.result_binding_time, BindingTime::Dynamic);
    assert_eq!(analysis.function_summaries[1].result, BindingTime::Dynamic);
    let argument =
        BindingTimeNodeId::root(FunctionId(0)).child(BindingTimePathField::TailCallArgument, 0);
    assert!(analysis
        .judgments
        .iter()
        .any(|judgment| judgment.node == argument));
}

#[test]
fn dynamic_call_control_reaches_a_zero_argument_constant_callee() {
    let artifact = seal(vec![
        Function {
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
                then_term: Box::new(Term::TailCall {
                    function: FunctionId(1),
                    arguments: vec![],
                }),
                else_term: Box::new(Term::TailCall {
                    function: FunctionId(1),
                    arguments: vec![],
                }),
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Return(Operand::I64(7)),
        },
    ]);

    let analysis = analyze(&artifact, vec![BindingTime::Dynamic], generous_budget())
        .expect("dynamic-control program must analyze");
    let callee = &analysis.function_summaries[1];
    assert_eq!(callee.control, BindingTime::Dynamic);
    assert_eq!(callee.result, BindingTime::Dynamic);
    assert_eq!(
        callee.static_evaluation,
        StaticEvaluationEligibility::Denied
    );
}

#[test]
fn callee_static_evaluation_denial_propagates_to_the_caller() {
    let checked_effect = Effect::Error(ErrorKind::Overflow);
    let artifact = seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::canonical(vec![checked_effect.clone()]),
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
            effects: EffectRow::canonical(vec![checked_effect]),
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
        },
    ]);

    let analysis = analyze(&artifact, vec![], generous_budget())
        .expect("checked callee must classify without executing");
    assert_eq!(analysis.result_binding_time, BindingTime::Static);
    assert_eq!(
        analysis.static_evaluation,
        StaticEvaluationEligibility::Denied
    );
    assert_eq!(
        analysis.function_summaries[1].static_evaluation,
        StaticEvaluationEligibility::Denied
    );
}

#[test]
fn recursive_summary_converges_without_host_recursion() {
    let artifact = seal(vec![Function {
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
            then_term: Box::new(Term::Return(Operand::I64(1))),
            else_term: Box::new(Term::TailCall {
                function: FunctionId(0),
                arguments: vec![Operand::Local(LocalId(0))],
            }),
        },
    }]);

    let static_analysis = analyze(&artifact, vec![BindingTime::Static], generous_budget())
        .expect("static recursive summary must converge");
    assert_eq!(static_analysis.budget_usage.fixpoint_iterations, 1);
    assert_eq!(static_analysis.result_binding_time, BindingTime::Static);

    let dynamic_analysis = analyze(&artifact, vec![BindingTime::Dynamic], generous_budget())
        .expect("dynamic recursive summary must converge");
    assert_eq!(dynamic_analysis.budget_usage.fixpoint_iterations, 2);
    assert_eq!(dynamic_analysis.result_binding_time, BindingTime::Dynamic);
    assert_eq!(
        dynamic_analysis.function_summaries[0].control,
        BindingTime::Dynamic
    );
}

#[test]
fn context_merging_is_conservative_and_explicit() {
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
                    value: RValue::Call {
                        function: FunctionId(1),
                        arguments: vec![Operand::Local(LocalId(0))],
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
                ty: Type::I64,
            }],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Return(Operand::Local(LocalId(0))),
        },
    ]);

    let analysis = analyze(&artifact, vec![BindingTime::Dynamic], generous_budget())
        .expect("merged call contexts must converge");
    assert_eq!(
        analysis.function_summaries[1].parameters,
        vec![BindingTime::Dynamic]
    );
    assert_eq!(analysis.result_binding_time, BindingTime::Dynamic);
}

#[test]
fn all_three_cumulative_budgets_are_exact_and_fail_closed() {
    let artifact = identity_call_program(false);
    let manifest = vec![BindingTime::Dynamic];
    let baseline = analyze(&artifact, manifest.clone(), generous_budget())
        .expect("baseline analysis must converge");
    let exact = BindingTimeBudget::new(
        baseline.budget_usage.nodes,
        baseline.budget_usage.call_edges,
        baseline.budget_usage.fixpoint_iterations,
    );
    let exact_analysis =
        analyze(&artifact, manifest.clone(), exact).expect("exact budgets must pass");
    assert_eq!(exact_analysis.budget_usage, baseline.budget_usage);

    let node_error = analyze(
        &artifact,
        manifest.clone(),
        BindingTimeBudget::new(
            exact.max_nodes - 1,
            exact.max_call_edges,
            exact.max_fixpoint_iterations,
        ),
    )
    .expect_err("one fewer node must fail");
    assert_eq!(node_error.code, BindingTimeAnalysisCode::NodeBudgetExceeded);

    let call_error = analyze(
        &artifact,
        manifest.clone(),
        BindingTimeBudget::new(
            exact.max_nodes,
            exact.max_call_edges - 1,
            exact.max_fixpoint_iterations,
        ),
    )
    .expect_err("one fewer call edge must fail");
    assert_eq!(
        call_error.code,
        BindingTimeAnalysisCode::CallEdgeBudgetExceeded
    );

    let iteration_error = analyze(
        &artifact,
        manifest,
        BindingTimeBudget::new(
            exact.max_nodes,
            exact.max_call_edges,
            exact.max_fixpoint_iterations - 1,
        ),
    )
    .expect_err("one fewer fixed-point round must fail");
    assert_eq!(
        iteration_error.code,
        BindingTimeAnalysisCode::FixpointBudgetExceeded
    );
}

#[test]
fn sufficient_budget_changes_only_request_identity_not_analysis_evidence() {
    let artifact = identity_call_program(false);
    let first = analyze(
        &artifact,
        vec![BindingTime::Dynamic],
        BindingTimeBudget::new(100, 20, 10),
    )
    .expect("first analysis must pass");
    let second = analyze(
        &artifact,
        vec![BindingTime::Dynamic],
        BindingTimeBudget::new(200, 40, 20),
    )
    .expect("second analysis must pass");

    assert_ne!(first.request_hash, second.request_hash);
    assert_eq!(first.function_summaries, second.function_summaries);
    assert_eq!(first.judgments, second.judgments);
    assert_eq!(first.result_binding_time, second.result_binding_time);
    assert_eq!(first.static_evaluation, second.static_evaluation);
    assert_eq!(first.budget_usage, second.budget_usage);
}
