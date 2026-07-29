use naux::core::{
    branch_mix_kernel_program, build_definitional_corevm0, certify_binding_time_b0d,
    corevm0_gate_a_manifest, evaluate, evaluate_core_ssa, evaluate_core_ssa_translation,
    evaluate_source_bound_core_ssa, lower_core_ssa_r1_s5, specialize_corevm0_r1_s4,
    validate_binding_time_b0_request, validate_specialization_r0a_request, verify, verify_core_ssa,
    verify_core_ssa_source, BindingTime, BindingTimeBudget, BindingTimeCertificate,
    BindingTimeRequest, CoreArtifact, CoreProfile, CoreSsaArtifact, CoreSsaExecutionError,
    CoreSsaSourceError, CoreSsaVerificationCode, CoreValue, CoreVmGateAWorkload, Effect, EffectRow,
    ErrorKind, EvaluationBudget, EvaluationOutcome, Function, FunctionId, LocalId, Mutability,
    NumericMode, Operand, Parameter, PolyvariantR1S4Budget, Primitive, Program, RValue, RegionId,
    SchemaVersion, SpecializationBudget, SpecializationRequest, SpecializationSlot, SsaBlockId,
    SsaInstructionKind, SsaOperand, SsaParameter, SsaTerminator, SsaValueId, Term, Type,
    CORE_SSA_MAX_DIAGNOSTICS,
};

fn array_type() -> Type {
    Type::Array {
        region: RegionId(0),
        mutability: Mutability::Read,
        element: Box::new(Type::F64),
    }
}

fn bounds_effects() -> EffectRow {
    EffectRow::canonical(vec![Effect::Error(ErrorKind::Bounds)])
}

fn seal(functions: Vec<Function>) -> CoreArtifact {
    CoreArtifact::seal(Program {
        schema: SchemaVersion::core_n0(),
        profile: CoreProfile::P1V0,
        entry: FunctionId(0),
        functions,
    })
    .expect("fixture must encode")
}

fn primitive(operation: Primitive, arguments: Vec<Operand>) -> RValue {
    RValue::Primitive {
        operation,
        arguments,
    }
}

fn requests(
    artifact: &CoreArtifact,
    manifest: Vec<BindingTime>,
    slots: Vec<SpecializationSlot>,
) -> (
    BindingTimeRequest,
    BindingTimeCertificate,
    SpecializationRequest,
) {
    let binding = BindingTimeRequest::p1v0(
        artifact,
        manifest,
        BindingTimeBudget::new(1_000_000, 1_000_000, 10_000),
    )
    .expect("binding request must encode");
    let validated = validate_binding_time_b0_request(artifact, &binding)
        .expect("binding request must validate");
    let certificate = certify_binding_time_b0d(&validated).expect("binding certificate must emit");
    let specialization = SpecializationRequest::p1v0(
        artifact,
        &binding,
        &certificate,
        slots,
        SpecializationBudget::new(1_000_000, 1_000_000, 100_000_000, 1_000_000, 1_000_000_000),
    )
    .expect("specialization request must encode");
    (binding, certificate, specialization)
}

fn s4_budget() -> PolyvariantR1S4Budget {
    PolyvariantR1S4Budget::new(
        100_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000_000,
    )
}

fn frozen_s4_residual() -> CoreArtifact {
    let program = branch_mix_kernel_program();
    let bound = build_definitional_corevm0(&program).expect("frozen branch_mix package must build");
    let (binding, certificate, request) = requests(
        bound.artifact(),
        vec![
            BindingTime::Static,
            BindingTime::Dynamic,
            BindingTime::Dynamic,
        ],
        vec![
            SpecializationSlot::Static(bound.program_image().clone()),
            SpecializationSlot::Dynamic(array_type()),
            SpecializationSlot::Dynamic(Type::I64),
        ],
    );
    let validated =
        validate_specialization_r0a_request(bound.artifact(), &binding, &certificate, &request)
            .expect("frozen branch_mix request must validate");
    specialize_corevm0_r1_s4(&bound, &validated, s4_budget())
        .expect("frozen branch_mix must cross R1-S4")
        .artifact()
        .clone()
}

fn assert_outcome_same(expected: &EvaluationOutcome, actual: &EvaluationOutcome) {
    match (expected, actual) {
        (
            EvaluationOutcome::Return(CoreValue::F64(expected)),
            EvaluationOutcome::Return(CoreValue::F64(actual)),
        ) if expected.is_nan() && actual.is_nan() => {}
        (
            EvaluationOutcome::Return(CoreValue::F64(expected)),
            EvaluationOutcome::Return(CoreValue::F64(actual)),
        ) => assert_eq!(actual.to_bits(), expected.to_bits()),
        _ => assert_eq!(actual, expected),
    }
}

fn assert_ssa_verification_code(artifact: &CoreSsaArtifact, expected: CoreSsaVerificationCode) {
    let errors = verify_core_ssa(artifact).expect_err("mutated SSA must fail verification");
    assert!(
        errors.0.iter().any(|error| error.code == expected),
        "expected {expected:?}, found {errors:?}"
    );
}

fn pure_i64_source() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Return(Operand::I64(7)),
    }])
}

fn direct_call_source() -> CoreArtifact {
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
            body: Term::Return(Operand::I64(7)),
        },
    ])
}

#[test]
fn frozen_s4_lowering_is_deterministic_and_semantically_equivalent() {
    let residual = frozen_s4_residual();
    assert_eq!(
        residual.semantic_hash.to_hex(),
        "fd90f6b16813a851aea7b1151a2df9ad87f9a9bfb8e994a5797407700f9fb2e9"
    );

    let first = lower_core_ssa_r1_s5(&residual).expect("frozen S4 must lower");
    assert_eq!(
        first.semantic_hash.to_hex(),
        "f31be2b773f263db5257fabc0e86a5572d5585b15c3b71b0d73ad6198b62630d"
    );
    let second = lower_core_ssa_r1_s5(&residual).expect("replay must lower");
    assert_eq!(first, second);
    verify_core_ssa_source(&first, &residual)
        .expect("translation replay must accept exact canonical SSA");
    assert_eq!(first.program.functions.len(), 121);

    let mut branches = 0;
    let mut tail_calls = 0;
    let mut direct_calls = 0;
    let mut blocks = 0;
    let mut instructions = 0;
    for function in &first.program.functions {
        for block in &function.blocks {
            blocks += 1;
            instructions += block.instructions.len();
            if matches!(block.terminator, SsaTerminator::Branch { .. }) {
                branches += 1;
            }
            if matches!(block.terminator, SsaTerminator::TailCall { .. }) {
                tail_calls += 1;
            }
            direct_calls += block
                .instructions
                .iter()
                .filter(|instruction| matches!(instruction.kind, SsaInstructionKind::Call { .. }))
                .count();
        }
    }
    assert_eq!(branches, 9);
    assert_eq!(tail_calls, 127);
    assert_eq!(direct_calls, 0);
    assert_eq!(
        (
            blocks,
            instructions,
            naux::core::core_ssa_semantic_bytes(&first.program)
                .expect("SSA must encode")
                .len(),
        ),
        (139, 23, 18_750)
    );

    let manifest = corevm0_gate_a_manifest().expect("Gate A manifest must generate");
    let branch_cases = manifest
        .cases
        .iter()
        .filter(|case| case.workload == CoreVmGateAWorkload::BranchMix)
        .collect::<Vec<_>>();
    assert_eq!(branch_cases.len(), 46);
    for case in branch_cases {
        let values = case
            .input
            .array_f64_bits
            .iter()
            .copied()
            .map(f64::from_bits)
            .collect::<Vec<_>>();
        let repetitions = case.input.repetitions;
        let source = evaluate(
            &residual,
            vec![
                CoreValue::array_f64(values.clone()),
                CoreValue::I64(repetitions),
            ],
            EvaluationBudget::new(10_000_000, 256),
        )
        .expect("Residual-Core evaluation must complete");
        let ssa = evaluate_core_ssa_translation(
            &first,
            &residual,
            vec![CoreValue::array_f64(values), CoreValue::I64(repetitions)],
            EvaluationBudget::new(10_000_000, 256),
        )
        .expect("Core SSA evaluation must complete");
        assert_outcome_same(&source.outcome, &ssa.outcome);
        assert_eq!(ssa.effect_trace, source.effect_trace);
    }
}

#[test]
fn translation_replay_rejects_a_resealed_behavior_mutation() {
    let source = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::F64,
        body: Term::Return(Operand::F64(0.0)),
    }]);
    let lowered = lower_core_ssa_r1_s5(&source).expect("zero fixture must lower");
    let mut program = lowered.program.clone();
    program.functions[0].blocks[0].terminator =
        SsaTerminator::Return(SsaOperand::F64Bits((-0.0_f64).to_bits()));
    let forged = CoreSsaArtifact::seal(program).expect("mutated SSA must reseal");

    verify_core_ssa(&forged).expect("the resealed SSA is independently well typed");
    assert!(matches!(
        verify_core_ssa_source(&forged, &source),
        Err(CoreSsaSourceError::TranslationMismatch { .. })
    ));
}

#[test]
fn verifier_diagnostics_are_bounded_under_many_mutations() {
    let source = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::F64,
        body: Term::Return(Operand::F64(0.0)),
    }]);
    let lowered = lower_core_ssa_r1_s5(&source).expect("fixture must lower");
    let mut program = lowered.program;
    program.functions[0].parameters = (0..400)
        .map(|_| SsaParameter {
            value: SsaValueId(0),
            ty: Type::Text,
        })
        .collect();
    let malformed = CoreSsaArtifact::seal(program).expect("malformed fixture must encode");
    let errors = verify_core_ssa(&malformed).expect_err("mutations must fail");
    assert_eq!(errors.0.len(), CORE_SSA_MAX_DIAGNOSTICS);
    let sentinel = errors.0.last().expect("diagnostic sentinel must exist");
    assert_eq!(sentinel.code, CoreSsaVerificationCode::StructuralLimit);
    assert!(sentinel.message.contains("diagnostics capped"));
}

#[test]
fn verifier_rejects_noncanonical_nan_and_unauthorized_callee_region() {
    let source = seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![RegionId(0)],
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
            region_parameters: vec![RegionId(0)],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Return(Operand::I64(7)),
        },
    ]);
    let lowered = lower_core_ssa_r1_s5(&source).expect("direct-call fixture must lower");
    assert_eq!(
        evaluate_core_ssa(&lowered, vec![], EvaluationBudget::new(100, 1))
            .expect("direct call must evaluate")
            .outcome,
        EvaluationOutcome::Return(CoreValue::I64(7))
    );

    let mut narrower_source_program = source.program.clone();
    narrower_source_program.functions[0]
        .region_parameters
        .clear();
    let narrower_source =
        CoreArtifact::seal(narrower_source_program).expect("source mutation must encode");
    verify(&narrower_source).expect("ordinary Core admits the unused callee region");
    assert!(matches!(
        lower_core_ssa_r1_s5(&narrower_source),
        Err(naux::core::CoreSsaLowerError::UnsupportedSource { .. })
    ));

    let mut unauthorized = lowered.program.clone();
    unauthorized.functions[0].region_parameters.clear();
    let unauthorized = CoreSsaArtifact::seal(unauthorized).expect("region mutation must encode");
    let errors =
        verify_core_ssa(&unauthorized).expect_err("callee region authority must be checked");
    assert!(errors.0.iter().any(|error| {
        error.code == CoreSsaVerificationCode::InvalidCall
            && error.message.contains("not authorized")
    }));

    let mut sparse = lowered.program.clone();
    sparse.functions[1].id = FunctionId(2);
    let SsaInstructionKind::Call { function, .. } =
        &mut sparse.functions[0].blocks[0].instructions[0].kind
    else {
        panic!("fixture must contain one direct call");
    };
    *function = FunctionId(2);
    let sparse = CoreSsaArtifact::seal(sparse).expect("sparse IDs must encode");
    let errors = verify_core_ssa(&sparse).expect_err("function IDs must be dense");
    assert!(errors
        .0
        .iter()
        .any(|error| error.code == CoreSsaVerificationCode::NonCanonicalOrder));

    let nan_source = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::F64,
        body: Term::Return(Operand::F64(f64::NAN)),
    }]);
    let lowered = lower_core_ssa_r1_s5(&nan_source).expect("NaN fixture must lower");
    let SsaTerminator::Return(SsaOperand::F64Bits(bits)) =
        lowered.program.functions[0].blocks[0].terminator
    else {
        panic!("NaN fixture must return an SSA F64 constant");
    };
    assert_eq!(bits, 0x7ff8_0000_0000_0000);
    let mut noncanonical = lowered.program.clone();
    noncanonical.functions[0].blocks[0].terminator =
        SsaTerminator::Return(SsaOperand::F64Bits(0x7ff8_0000_0000_0001));
    let noncanonical = CoreSsaArtifact::seal(noncanonical).expect("raw NaN bits must encode");
    let errors = verify_core_ssa(&noncanonical).expect_err("noncanonical NaN must fail closed");
    assert!(errors
        .0
        .iter()
        .any(|error| error.code == CoreSsaVerificationCode::NonCanonicalOrder));
}

#[test]
fn tail_calls_are_constant_stack_and_preserve_wrapping_mode() {
    let source = seal(vec![Function {
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
            ty: Type::Bool,
            value: primitive(
                Primitive::I64CmpGe,
                vec![Operand::Local(LocalId(0)), Operand::I64(1)],
            ),
            next: Box::new(Term::If {
                condition: Operand::Local(LocalId(1)),
                then_term: Box::new(Term::Let {
                    binder: LocalId(2),
                    ty: Type::I64,
                    value: primitive(
                        Primitive::I64Sub(NumericMode::Wrapping),
                        vec![Operand::Local(LocalId(0)), Operand::I64(1)],
                    ),
                    next: Box::new(Term::TailCall {
                        function: FunctionId(0),
                        arguments: vec![Operand::Local(LocalId(2))],
                    }),
                }),
                else_term: Box::new(Term::Return(Operand::Local(LocalId(0)))),
            }),
        },
    }]);
    let lowered = lower_core_ssa_r1_s5(&source).expect("tail-call fixture must lower");
    let result = evaluate_core_ssa(
        &lowered,
        vec![CoreValue::I64(20_000)],
        EvaluationBudget::new(100_000, 0),
    )
    .expect("tail calls must not consume call depth");
    assert_eq!(result.outcome, EvaluationOutcome::Return(CoreValue::I64(0)));
}

#[test]
fn deep_direct_calls_stop_at_the_explicit_continuation_cap() {
    let function_count = 600_u32;
    let mut functions = Vec::with_capacity(function_count as usize);
    for id in 0..function_count {
        let body = if id + 1 == function_count {
            Term::Return(Operand::I64(11))
        } else {
            Term::Let {
                binder: LocalId(0),
                ty: Type::I64,
                value: RValue::Call {
                    function: FunctionId(id + 1),
                    arguments: vec![],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
            }
        };
        functions.push(Function {
            id: FunctionId(id),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::I64,
            body,
        });
    }
    let source = seal(functions);
    let lowered = lower_core_ssa_r1_s5(&source).expect("deep call fixture must lower");
    assert!(matches!(
        evaluate_core_ssa(&lowered, vec![], EvaluationBudget::new(10_000, 256),),
        Err(CoreSsaExecutionError::CallDepthExceeded { limit: 256 })
    ));
}

#[test]
fn array_bounds_produces_exactly_one_ordered_typed_effect() {
    let source = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![RegionId(0)],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: array_type(),
        }],
        effects: bounds_effects(),
        result: Type::F64,
        body: Term::Let {
            binder: LocalId(1),
            ty: Type::F64,
            value: primitive(
                Primitive::ArrayGetF64,
                vec![Operand::Local(LocalId(0)), Operand::I64(0)],
            ),
            next: Box::new(Term::Let {
                binder: LocalId(2),
                ty: Type::F64,
                value: primitive(
                    Primitive::ArrayGetF64,
                    vec![Operand::Local(LocalId(0)), Operand::I64(1)],
                ),
                next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
            }),
        },
    }]);
    let lowered = lower_core_ssa_r1_s5(&source).expect("Bounds fixture must lower");
    let bound =
        verify_core_ssa_source(&lowered, &source).expect("Bounds SSA must bind to its source");
    let manifest = corevm0_gate_a_manifest().expect("Gate A manifest must generate");
    let bounds_cases = manifest
        .cases
        .iter()
        .filter(|case| case.workload == CoreVmGateAWorkload::BoundsOrderedArrayGet)
        .collect::<Vec<_>>();
    assert_eq!(bounds_cases.len(), 5);

    for case in bounds_cases {
        let values = case
            .input
            .array_f64_bits
            .iter()
            .copied()
            .map(f64::from_bits)
            .collect::<Vec<_>>();
        let core = evaluate(
            &source,
            vec![CoreValue::array_f64(values.clone())],
            EvaluationBudget::new(100, 0),
        )
        .expect("Core Bounds fixture must evaluate");
        let ssa = evaluate_source_bound_core_ssa(
            bound,
            vec![CoreValue::array_f64(values)],
            EvaluationBudget::new(100, 0),
        )
        .expect("source-bound SSA Bounds fixture must evaluate");
        assert_outcome_same(&core.outcome, &ssa.outcome);
        assert_eq!(ssa.effect_trace, core.effect_trace);
    }
}

#[test]
fn verifier_rejects_envelope_source_and_seal_mutations() {
    let source = pure_i64_source();
    let lowered = lower_core_ssa_r1_s5(&source).expect("pure fixture must lower");

    let mut unsealed = lowered.clone();
    unsealed.semantic_hash.0[0] ^= 1;
    assert_ssa_verification_code(&unsealed, CoreSsaVerificationCode::SemanticHashMismatch);

    let mut schema = lowered.program.clone();
    schema.schema.patch ^= 1;
    let schema = CoreSsaArtifact::seal(schema).expect("schema mutation must encode");
    assert_ssa_verification_code(&schema, CoreSsaVerificationCode::InvalidSchema);

    let mut policy = lowered.program.clone();
    policy.lowering_policy_version.2 ^= 1;
    let policy = CoreSsaArtifact::seal(policy).expect("policy mutation must encode");
    assert_ssa_verification_code(&policy, CoreSsaVerificationCode::InvalidPolicy);

    let mut wrong_source = lowered.program.clone();
    wrong_source.source_core_hash.0[0] ^= 1;
    let wrong_source =
        CoreSsaArtifact::seal(wrong_source).expect("source provenance mutation must encode");
    verify_core_ssa(&wrong_source).expect("forged source metadata remains structurally valid");
    assert!(matches!(
        verify_core_ssa_source(&wrong_source, &source),
        Err(CoreSsaSourceError::SourceHashMismatch { .. })
    ));
}

#[test]
fn verifier_rejects_bad_cfg_sibling_use_and_result_type() {
    let source = seal(vec![Function {
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
            then_term: Box::new(Term::Let {
                binder: LocalId(1),
                ty: Type::I64,
                value: RValue::Use(Operand::I64(1)),
                next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
            }),
            else_term: Box::new(Term::Return(Operand::I64(2))),
        },
    }]);
    let lowered = lower_core_ssa_r1_s5(&source).expect("branch fixture must lower");

    let mut bad_target = lowered.program.clone();
    let SsaTerminator::Branch { then_block, .. } =
        &mut bad_target.functions[0].blocks[0].terminator
    else {
        panic!("branch fixture must contain a branch");
    };
    *then_block = SsaBlockId(99);
    let bad_target = CoreSsaArtifact::seal(bad_target).expect("bad target must encode");
    assert_ssa_verification_code(&bad_target, CoreSsaVerificationCode::InvalidControlFlow);

    let mut sibling_use = lowered.program.clone();
    sibling_use.functions[0].blocks[2].terminator =
        SsaTerminator::Return(SsaOperand::Value(SsaValueId(1)));
    let sibling_use = CoreSsaArtifact::seal(sibling_use).expect("sibling use must encode");
    assert_ssa_verification_code(&sibling_use, CoreSsaVerificationCode::UnboundValue);

    let mut wrong_type = lowered.program.clone();
    wrong_type.functions[0].blocks[1].instructions[0].ty = Type::Bool;
    let wrong_type = CoreSsaArtifact::seal(wrong_type).expect("type mutation must encode");
    assert_ssa_verification_code(&wrong_type, CoreSsaVerificationCode::TypeMismatch);
}

#[test]
fn verifier_rejects_primitive_call_effect_and_numeric_mutations() {
    let arithmetic_source = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(0),
            ty: Type::I64,
            value: primitive(
                Primitive::I64Add(NumericMode::Wrapping),
                vec![Operand::I64(1), Operand::I64(2)],
            ),
            next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
        },
    }]);
    let arithmetic =
        lower_core_ssa_r1_s5(&arithmetic_source).expect("arithmetic fixture must lower");

    let mut primitive_arity = arithmetic.program.clone();
    let SsaInstructionKind::Primitive { arguments, .. } =
        &mut primitive_arity.functions[0].blocks[0].instructions[0].kind
    else {
        panic!("arithmetic fixture must contain a primitive");
    };
    arguments.pop();
    let primitive_arity =
        CoreSsaArtifact::seal(primitive_arity).expect("primitive arity mutation must encode");
    assert_ssa_verification_code(&primitive_arity, CoreSsaVerificationCode::InvalidCall);

    let mut checked = arithmetic.program.clone();
    let SsaInstructionKind::Primitive { operation, .. } =
        &mut checked.functions[0].blocks[0].instructions[0].kind
    else {
        panic!("arithmetic fixture must contain a primitive");
    };
    *operation = Primitive::I64Add(NumericMode::Checked);
    let checked = CoreSsaArtifact::seal(checked).expect("numeric-mode mutation must encode");
    assert_ssa_verification_code(&checked, CoreSsaVerificationCode::UnsupportedFeature);

    let call_source = direct_call_source();
    let call = lower_core_ssa_r1_s5(&call_source).expect("call fixture must lower");
    let mut call_arity = call.program.clone();
    let SsaInstructionKind::Call { arguments, .. } =
        &mut call_arity.functions[0].blocks[0].instructions[0].kind
    else {
        panic!("call fixture must contain a direct call");
    };
    arguments.push(SsaOperand::I64(0));
    let call_arity = CoreSsaArtifact::seal(call_arity).expect("call arity mutation must encode");
    assert_ssa_verification_code(&call_arity, CoreSsaVerificationCode::InvalidCall);

    let bounds_source = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![RegionId(0)],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: array_type(),
        }],
        effects: bounds_effects(),
        result: Type::F64,
        body: Term::Let {
            binder: LocalId(1),
            ty: Type::F64,
            value: primitive(
                Primitive::ArrayGetF64,
                vec![Operand::Local(LocalId(0)), Operand::I64(0)],
            ),
            next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
        },
    }]);
    let bounds = lower_core_ssa_r1_s5(&bounds_source).expect("Bounds fixture must lower");
    let mut missing_effect = bounds.program;
    missing_effect.functions[0].effects = EffectRow::pure();
    let missing_effect =
        CoreSsaArtifact::seal(missing_effect).expect("missing-effect mutation must encode");
    assert_ssa_verification_code(&missing_effect, CoreSsaVerificationCode::MissingEffect);
}

#[test]
fn execution_step_and_direct_call_depth_boundaries_are_exact() {
    let pure = lower_core_ssa_r1_s5(&pure_i64_source()).expect("pure fixture must lower");
    assert!(matches!(
        evaluate_core_ssa(&pure, vec![], EvaluationBudget::new(0, 0)),
        Err(CoreSsaExecutionError::StepBudgetExceeded { limit: 0 })
    ));
    let one_step = evaluate_core_ssa(&pure, vec![], EvaluationBudget::new(1, 0))
        .expect("one terminator must fit exactly one step");
    assert_eq!(one_step.steps, 1);
    assert_eq!(
        one_step.outcome,
        EvaluationOutcome::Return(CoreValue::I64(7))
    );

    let call = lower_core_ssa_r1_s5(&direct_call_source()).expect("call fixture must lower");
    assert!(matches!(
        evaluate_core_ssa(&call, vec![], EvaluationBudget::new(10, 0)),
        Err(CoreSsaExecutionError::CallDepthExceeded { limit: 0 })
    ));
    let depth_one = evaluate_core_ssa(&call, vec![], EvaluationBudget::new(3, 1))
        .expect("one direct call must fit exactly depth one");
    assert_eq!(depth_one.steps, 3);
    assert_eq!(
        depth_one.outcome,
        EvaluationOutcome::Return(CoreValue::I64(7))
    );
}
