use naux::core::{
    branch_mix_kernel_program, build_definitional_corevm0, certify_binding_time_b0d,
    corevm0_gate_a_manifest, evaluate, evaluate_core_ssa_translation, evaluate_machine_ir,
    evaluate_machine_ir_translation, lower_core_ssa_r1_s5, lower_machine_ir_r1_s6,
    machine_ir_semantic_bytes, specialize_corevm0_r1_s4, validate_binding_time_b0_request,
    validate_specialization_r0a_request, verify_machine_ir, verify_machine_ir_source, BindingTime,
    BindingTimeBudget, BindingTimeCertificate, BindingTimeRequest, CoreArtifact, CoreProfile,
    CoreSsaArtifact, CoreValue, CoreVmGateAWorkload, CoreVmInstruction, CoreVmProgram, CoreVmType,
    Effect, EffectEvent, EffectRow, ErrorKind, EvaluationBudget, EvaluationOutcome, Function,
    FunctionId, LocalId, MachineBlockId, MachineEffect, MachineFunctionId, MachineInstructionKind,
    MachineIrArtifact, MachineIrExecutionError, MachineIrLowerError, MachineIrSourceError,
    MachineIrVerificationCode, MachineOperand, MachineParameter, MachineTerminator, MachineType,
    Mutability, NumericMode, Operand, Parameter, PolyvariantR1S4Budget, Primitive, Program, RValue,
    RegionId, SchemaVersion, SemanticHash, SpecializationBudget, SpecializationRequest,
    SpecializationSlot, Term, Type, VirtualRegister, COREVM0_SCHEMA_VERSION,
    MACHINE_IR_MAX_CALL_DEPTH, MACHINE_IR_MAX_DIAGNOSTICS, MACHINE_IR_MAX_EXECUTION_STEPS,
    MACHINE_IR_MAX_FUNCTIONS,
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

fn lower_to_machine(source: &CoreArtifact) -> (CoreSsaArtifact, MachineIrArtifact) {
    let ssa = lower_core_ssa_r1_s5(source).expect("fixture must cross R1-S5");
    let machine =
        lower_machine_ir_r1_s6(&ssa, source).expect("fixture must cross source-bound R1-S6");
    (ssa, machine)
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

fn assert_machine_verification_code(
    artifact: &MachineIrArtifact,
    expected: MachineIrVerificationCode,
) {
    let errors = verify_machine_ir(artifact).expect_err("mutated Machine IR must fail");
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

fn branch_source() -> CoreArtifact {
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
            then_term: Box::new(Term::Return(Operand::I64(1))),
            else_term: Box::new(Term::Return(Operand::I64(2))),
        },
    }])
}

fn arithmetic_source() -> CoreArtifact {
    seal(vec![Function {
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
    }])
}

fn saturating_source() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(0),
            ty: Type::I64,
            value: primitive(
                Primitive::I64Add(NumericMode::Saturating),
                vec![Operand::I64(i64::MAX), Operand::I64(1)],
            ),
            next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
        },
    }])
}

fn ordered_bounds_source() -> CoreArtifact {
    seal(vec![Function {
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
    }])
}

fn tail_recursive_source() -> CoreArtifact {
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
    }])
}

fn deep_direct_call_source(function_count: u32) -> CoreArtifact {
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
    seal(functions)
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
    let certificate = certify_binding_time_b0d(&validated).expect("certificate must emit");
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

fn specialize_corevm0_program(program: &CoreVmProgram, dynamic_types: Vec<Type>) -> CoreArtifact {
    let bound = build_definitional_corevm0(program).expect("CoreVM0 package must build");
    let mut manifest = vec![BindingTime::Static];
    manifest.extend(std::iter::repeat_n(
        BindingTime::Dynamic,
        dynamic_types.len(),
    ));
    let mut slots = vec![SpecializationSlot::Static(bound.program_image().clone())];
    slots.extend(dynamic_types.into_iter().map(SpecializationSlot::Dynamic));
    let (binding, certificate, request) = requests(bound.artifact(), manifest, slots);
    let validated =
        validate_specialization_r0a_request(bound.artifact(), &binding, &certificate, &request)
            .expect("CoreVM0 request must validate");
    specialize_corevm0_r1_s4(&bound, &validated, s4_budget())
        .expect("CoreVM0 package must cross R1-S4")
        .artifact()
        .clone()
}

fn bounds_corevm0_program() -> CoreVmProgram {
    CoreVmProgram {
        schema_version: COREVM0_SCHEMA_VERSION,
        arguments: vec![CoreVmType::ArrayF64],
        locals: vec![CoreVmType::F64],
        max_stack: 2,
        instructions: vec![
            CoreVmInstruction::LoadArg(0),
            CoreVmInstruction::ConstI64(0),
            CoreVmInstruction::ArrayGetF64,
            CoreVmInstruction::StoreLocal(0),
            CoreVmInstruction::LoadArg(0),
            CoreVmInstruction::ConstI64(1),
            CoreVmInstruction::ArrayGetF64,
            CoreVmInstruction::ReturnF64,
        ],
    }
}

#[test]
fn minimal_lowering_is_deterministic_source_bound_and_executable() {
    let source = pure_i64_source();
    let ssa = lower_core_ssa_r1_s5(&source).expect("minimal source must cross R1-S5");
    let first = lower_machine_ir_r1_s6(&ssa, &source).expect("minimal SSA must cross R1-S6");
    let second = lower_machine_ir_r1_s6(&ssa, &source).expect("deterministic replay must lower");

    assert_eq!(first, second);
    assert_eq!(
        machine_ir_semantic_bytes(&first.program).expect("Machine IR must encode"),
        machine_ir_semantic_bytes(&second.program).expect("replay must encode")
    );
    verify_machine_ir(&first).expect("minimal Machine IR must verify");
    verify_machine_ir_source(&first, &ssa, &source)
        .expect("Machine IR must bind to exact Core and SSA");
    assert_eq!(first.program.source_core_hash, source.semantic_hash);
    assert_eq!(first.program.source_ssa_hash, ssa.semantic_hash);
    assert_eq!(first.program.functions.len(), 1);
    assert_eq!(first.program.functions[0].blocks.len(), 1);

    let evaluation =
        evaluate_machine_ir_translation(&first, &ssa, &source, vec![], EvaluationBudget::new(1, 0))
            .expect("minimal Machine IR must execute in exactly one step");
    assert_eq!(evaluation.steps, 1);
    assert_eq!(
        evaluation.outcome,
        EvaluationOutcome::Return(CoreValue::I64(7))
    );
    assert!(evaluation.effect_trace.is_empty());
}

#[test]
fn source_binding_rejects_resealed_behavior_and_provenance_mutations() {
    let source = pure_i64_source();
    let (ssa, machine) = lower_to_machine(&source);

    let mut forged_ssa_program = ssa.program.clone();
    forged_ssa_program.source_core_hash.0[0] ^= 1;
    let forged_ssa =
        CoreSsaArtifact::seal(forged_ssa_program).expect("forged SSA provenance must reseal");
    assert!(matches!(
        lower_machine_ir_r1_s6(&forged_ssa, &source),
        Err(MachineIrLowerError::InvalidSourceBinding(_))
    ));
    assert!(matches!(
        verify_machine_ir_source(&machine, &forged_ssa, &source),
        Err(MachineIrSourceError::InvalidSourceBinding(_))
    ));

    let mut behavior = machine.program.clone();
    behavior.functions[0].blocks[0].terminator = MachineTerminator::Return(MachineOperand::I64(8));
    let behavior = MachineIrArtifact::seal(behavior).expect("behavior mutation must reseal");
    verify_machine_ir(&behavior).expect("mutated behavior remains locally well typed");
    assert!(matches!(
        verify_machine_ir_source(&behavior, &ssa, &source),
        Err(MachineIrSourceError::TranslationMismatch { .. })
    ));

    let mut provenance = machine.program.clone();
    provenance.source_ssa_hash.0[0] ^= 1;
    let provenance = MachineIrArtifact::seal(provenance).expect("provenance mutation must reseal");
    assert!(matches!(
        verify_machine_ir_source(&provenance, &ssa, &source),
        Err(MachineIrSourceError::SourceSsaHashMismatch { .. })
    ));

    let mut core_provenance = machine.program;
    core_provenance.source_core_hash.0[0] ^= 1;
    let core_provenance =
        MachineIrArtifact::seal(core_provenance).expect("Core provenance mutation must reseal");
    assert!(matches!(
        verify_machine_ir_source(&core_provenance, &ssa, &source),
        Err(MachineIrSourceError::SourceCoreHashMismatch { .. })
    ));
}

#[test]
fn verifier_rejects_id_order_type_effect_control_flow_nan_and_limit_mutations() {
    let (_, call) = lower_to_machine(&direct_call_source());
    let mut sparse = call.program.clone();
    sparse.functions[1].id = MachineFunctionId(2);
    let MachineInstructionKind::Call { function, .. } =
        &mut sparse.functions[0].blocks[0].instructions[0].kind
    else {
        panic!("direct-call fixture must contain one call");
    };
    *function = MachineFunctionId(2);
    let sparse = MachineIrArtifact::seal(sparse).expect("sparse IDs must encode");
    assert_machine_verification_code(&sparse, MachineIrVerificationCode::NonCanonicalOrder);

    let mut wrong_arity = call.program.clone();
    let MachineInstructionKind::Call { arguments, .. } =
        &mut wrong_arity.functions[0].blocks[0].instructions[0].kind
    else {
        panic!("direct-call fixture must contain one call");
    };
    arguments.push(MachineOperand::I64(0));
    let wrong_arity = MachineIrArtifact::seal(wrong_arity).expect("wrong arity must encode");
    assert_machine_verification_code(&wrong_arity, MachineIrVerificationCode::InvalidCall);

    let (_, branch) = lower_to_machine(&branch_source());
    let mut block_order = branch.program.clone();
    block_order.functions[0].blocks.swap(0, 1);
    let block_order = MachineIrArtifact::seal(block_order).expect("block reorder must encode");
    assert_machine_verification_code(&block_order, MachineIrVerificationCode::NonCanonicalOrder);

    let mut bad_target = branch.program.clone();
    let MachineTerminator::Branch { then_block, .. } =
        &mut bad_target.functions[0].blocks[0].terminator
    else {
        panic!("branch fixture must contain a branch");
    };
    *then_block = MachineBlockId(99);
    let bad_target = MachineIrArtifact::seal(bad_target).expect("bad target must encode");
    assert_machine_verification_code(&bad_target, MachineIrVerificationCode::InvalidControlFlow);

    let mut same_target = branch.program.clone();
    let MachineTerminator::Branch {
        then_block,
        else_block,
        ..
    } = &mut same_target.functions[0].blocks[0].terminator
    else {
        panic!("branch fixture must contain a branch");
    };
    *else_block = *then_block;
    let same_target = MachineIrArtifact::seal(same_target).expect("same target must encode");
    assert_machine_verification_code(&same_target, MachineIrVerificationCode::InvalidControlFlow);

    let mut non_bool_branch = branch.program.clone();
    let MachineTerminator::Branch { condition, .. } =
        &mut non_bool_branch.functions[0].blocks[0].terminator
    else {
        panic!("branch fixture must contain a branch");
    };
    *condition = MachineOperand::I64(0);
    let non_bool_branch =
        MachineIrArtifact::seal(non_bool_branch).expect("non-Bool branch must encode");
    assert_machine_verification_code(&non_bool_branch, MachineIrVerificationCode::TypeMismatch);

    let (_, arithmetic) = lower_to_machine(&arithmetic_source());
    let mut wrong_type = arithmetic.program.clone();
    wrong_type.functions[0].blocks[0].instructions[0].ty = MachineType::Bool;
    let wrong_type = MachineIrArtifact::seal(wrong_type).expect("type mutation must encode");
    assert_machine_verification_code(&wrong_type, MachineIrVerificationCode::TypeMismatch);

    let mut unbound = arithmetic.program.clone();
    let MachineInstructionKind::I64Binary { left, .. } =
        &mut unbound.functions[0].blocks[0].instructions[0].kind
    else {
        panic!("arithmetic fixture must contain one I64 binary instruction");
    };
    *left = MachineOperand::Register(VirtualRegister(999));
    let unbound = MachineIrArtifact::seal(unbound).expect("unbound register must encode");
    assert_machine_verification_code(&unbound, MachineIrVerificationCode::UnboundRegister);

    let (_, bounds) = lower_to_machine(&ordered_bounds_source());
    let mut missing_effect = bounds.program.clone();
    missing_effect.functions[0].effects.clear();
    let missing_effect =
        MachineIrArtifact::seal(missing_effect).expect("effect mutation must encode");
    assert_machine_verification_code(&missing_effect, MachineIrVerificationCode::MissingEffect);

    let nan_source = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::F64,
        body: Term::Return(Operand::F64(f64::NAN)),
    }]);
    let (_, nan) = lower_to_machine(&nan_source);
    let mut noncanonical_nan = nan.program.clone();
    noncanonical_nan.functions[0].blocks[0].terminator =
        MachineTerminator::Return(MachineOperand::F64Bits(0x7ff8_0000_0000_0001));
    let noncanonical_nan =
        MachineIrArtifact::seal(noncanonical_nan).expect("raw NaN payload must encode");
    assert_machine_verification_code(
        &noncanonical_nan,
        MachineIrVerificationCode::NonCanonicalOrder,
    );

    let mut changed_limits = arithmetic.program.clone();
    changed_limits.limits.max_operands -= 1;
    let changed_limits =
        MachineIrArtifact::seal(changed_limits).expect("changed limits must encode");
    assert_machine_verification_code(&changed_limits, MachineIrVerificationCode::InvalidLimits);

    let mut missing_entry = arithmetic.program.clone();
    missing_entry.entry = MachineFunctionId(99);
    let missing_entry =
        MachineIrArtifact::seal(missing_entry).expect("invalid entry must still encode");
    assert_machine_verification_code(&missing_entry, MachineIrVerificationCode::MissingEntry);

    let mut wrong_return = arithmetic.program.clone();
    wrong_return.functions[0].blocks[0].terminator =
        MachineTerminator::Return(MachineOperand::Bool(false));
    let wrong_return = MachineIrArtifact::seal(wrong_return).expect("wrong return must encode");
    assert_machine_verification_code(&wrong_return, MachineIrVerificationCode::TypeMismatch);

    let mut bad_hash = arithmetic;
    bad_hash.semantic_hash.0[0] ^= 1;
    assert_machine_verification_code(&bad_hash, MachineIrVerificationCode::SemanticHashMismatch);
}

#[test]
fn verifier_enforces_structural_limits_and_bounded_diagnostics() {
    let (_, machine) = lower_to_machine(&pure_i64_source());
    let template = machine.program.functions[0].clone();
    let mut oversized = machine.program;
    oversized.functions = (0..=MACHINE_IR_MAX_FUNCTIONS)
        .map(|_| template.clone())
        .collect();
    let oversized = MachineIrArtifact {
        program: oversized,
        semantic_hash: SemanticHash::ZERO,
    };
    let errors = verify_machine_ir(&oversized).expect_err("function cap must fail closed");
    assert!(
        errors
            .0
            .iter()
            .any(|error| error.code == MachineIrVerificationCode::StructuralLimit),
        "structural limit must be reported: {errors:?}"
    );
    assert!(
        errors
            .0
            .iter()
            .all(|error| error.code != MachineIrVerificationCode::SemanticHashMismatch),
        "shape preflight must reject before semantic encoding: {errors:?}"
    );

    let (_, machine) = lower_to_machine(&pure_i64_source());
    let mut oversized_effect_row = machine.program;
    oversized_effect_row.functions[0].effects = vec![MachineEffect::Bounds; 100_000];
    let oversized_effect_row = MachineIrArtifact {
        program: oversized_effect_row,
        semantic_hash: SemanticHash::ZERO,
    };
    let errors =
        verify_machine_ir(&oversized_effect_row).expect_err("oversized effect row must preflight");
    assert_eq!(errors.0.len(), 1);
    assert_eq!(errors.0[0].code, MachineIrVerificationCode::StructuralLimit);
    assert!(
        errors
            .0
            .iter()
            .all(|error| error.code != MachineIrVerificationCode::SemanticHashMismatch),
        "effect-row preflight must reject before semantic encoding: {errors:?}"
    );

    let (_, machine) = lower_to_machine(&pure_i64_source());
    let mut hostile_schema = machine;
    hostile_schema.program.schema.name = "attacker-controlled-schema".repeat(10_000);
    let errors =
        verify_machine_ir(&hostile_schema).expect_err("hostile schema metadata must be rejected");
    assert_eq!(errors.0.len(), 1);
    assert_eq!(errors.0[0].code, MachineIrVerificationCode::InvalidSchema);
    assert!(errors.0[0].message.len() < 256);
    assert!(!errors.0[0].message.contains("attacker-controlled-schema"));

    let (_, machine) = lower_to_machine(&pure_i64_source());
    let mut malformed = machine.program;
    malformed.functions[0].parameters = (0..400)
        .map(|_| MachineParameter {
            register: VirtualRegister(0),
            ty: MachineType::I64,
        })
        .collect();
    let malformed = MachineIrArtifact::seal(malformed).expect("malformed fixture must encode");
    let errors = verify_machine_ir(&malformed).expect_err("mutations must fail");
    assert_eq!(errors.0.len(), MACHINE_IR_MAX_DIAGNOSTICS);
    let sentinel = errors.0.last().expect("diagnostic sentinel must exist");
    assert_eq!(sentinel.code, MachineIrVerificationCode::StructuralLimit);
    assert!(sentinel.message.contains("diagnostics capped"));
}

#[test]
fn tail_calls_are_constant_stack_and_direct_calls_obey_the_depth_cap() {
    let (_, tail) = lower_to_machine(&tail_recursive_source());
    let result = evaluate_machine_ir(
        &tail,
        vec![CoreValue::I64(20_000)],
        EvaluationBudget::new(1_000_000, 0),
    )
    .expect("tail calls must replace the active frame");
    assert_eq!(result.outcome, EvaluationOutcome::Return(CoreValue::I64(0)));

    let (_, direct) = lower_to_machine(&deep_direct_call_source(300));
    assert!(matches!(
        evaluate_machine_ir(&direct, vec![], EvaluationBudget::new(10_000, 256),),
        Err(MachineIrExecutionError::CallDepthExceeded { limit: 256 })
    ));
}

#[test]
fn ordered_array_bounds_preserves_outcome_bits_and_exact_effect_trace() {
    let source = ordered_bounds_source();
    let (ssa, machine) = lower_to_machine(&source);

    for values in [
        vec![],
        vec![3.25],
        vec![3.25, -0.0],
        vec![3.25, f64::NAN],
        vec![f64::INFINITY, f64::NEG_INFINITY],
    ] {
        let core = evaluate(
            &source,
            vec![CoreValue::array_f64(values.clone())],
            EvaluationBudget::new(100, 0),
        )
        .expect("Core bounds fixture must evaluate");
        let machine = evaluate_machine_ir_translation(
            &machine,
            &ssa,
            &source,
            vec![CoreValue::array_f64(values.clone())],
            EvaluationBudget::new(100, 0),
        )
        .expect("Machine IR bounds fixture must evaluate");
        assert_outcome_same(&core.outcome, &machine.outcome);
        assert_eq!(machine.effect_trace, core.effect_trace);

        if values.len() < 2 {
            assert_eq!(machine.outcome, EvaluationOutcome::Error(ErrorKind::Bounds));
            assert_eq!(
                machine.effect_trace,
                vec![EffectEvent::Error(ErrorKind::Bounds)]
            );
        }
    }
}

#[test]
fn execution_work_budget_boundary_is_exact() {
    let (_, machine) = lower_to_machine(&pure_i64_source());
    assert!(matches!(
        evaluate_machine_ir(&machine, vec![], EvaluationBudget::new(0, 0)),
        Err(MachineIrExecutionError::StepBudgetExceeded { limit: 0 })
    ));
    let one_step = evaluate_machine_ir(&machine, vec![], EvaluationBudget::new(1, 0))
        .expect("one return terminator must consume exactly one step");
    assert_eq!(one_step.steps, 1);
    assert_eq!(
        one_step.outcome,
        EvaluationOutcome::Return(CoreValue::I64(7))
    );

    assert!(matches!(
        evaluate_machine_ir(
            &machine,
            vec![],
            EvaluationBudget::new(MACHINE_IR_MAX_EXECUTION_STEPS + 1, 0),
        ),
        Err(MachineIrExecutionError::InvalidBudget {
            field: "execution-work",
            limit: MACHINE_IR_MAX_EXECUTION_STEPS,
            ..
        })
    ));
    assert!(matches!(
        evaluate_machine_ir(
            &machine,
            vec![],
            EvaluationBudget::new(1, MACHINE_IR_MAX_CALL_DEPTH + 1),
        ),
        Err(MachineIrExecutionError::InvalidBudget {
            field: "call-depth",
            limit,
            ..
        }) if limit == u64::from(MACHINE_IR_MAX_CALL_DEPTH)
    ));

    let (_, direct) = lower_to_machine(&direct_call_source());
    assert!(matches!(
        evaluate_machine_ir(&direct, vec![], EvaluationBudget::new(3, 1)),
        Err(MachineIrExecutionError::StepBudgetExceeded { limit: 3 })
    ));
    let four_units = evaluate_machine_ir(&direct, vec![], EvaluationBudget::new(4, 1))
        .expect("entry frame, call, callee return, and caller return require four work units");
    assert_eq!(four_units.steps, 4);

    let (_, saturating) = lower_to_machine(&saturating_source());
    let saturated = evaluate_machine_ir(&saturating, vec![], EvaluationBudget::new(3, 0))
        .expect("saturating I64 fixture must execute");
    assert_eq!(
        saturated.outcome,
        EvaluationOutcome::Return(CoreValue::I64(i64::MAX))
    );
}

#[test]
fn frozen_s4_to_ssa_to_machine_ir_shape_and_all_51_gate_a_cases_are_equivalent() {
    let branch_residual =
        specialize_corevm0_program(&branch_mix_kernel_program(), vec![array_type(), Type::I64]);
    let branch_ssa =
        lower_core_ssa_r1_s5(&branch_residual).expect("branch-mix residual must cross R1-S5");
    let branch_machine = lower_machine_ir_r1_s6(&branch_ssa, &branch_residual)
        .expect("branch-mix SSA must cross R1-S6");
    let branch_machine_replay = lower_machine_ir_r1_s6(&branch_ssa, &branch_residual)
        .expect("branch-mix replay must cross R1-S6");
    assert_eq!(branch_machine_replay, branch_machine);
    verify_machine_ir_source(&branch_machine, &branch_ssa, &branch_residual)
        .expect("branch-mix Machine IR must bind to its Core and SSA source");

    let bounds_residual = specialize_corevm0_program(&bounds_corevm0_program(), vec![array_type()]);
    let bounds_ssa =
        lower_core_ssa_r1_s5(&bounds_residual).expect("Bounds residual must cross R1-S5");
    let bounds_machine =
        lower_machine_ir_r1_s6(&bounds_ssa, &bounds_residual).expect("Bounds SSA must cross R1-S6");
    let bounds_machine_replay = lower_machine_ir_r1_s6(&bounds_ssa, &bounds_residual)
        .expect("Bounds replay must cross R1-S6");
    assert_eq!(bounds_machine_replay, bounds_machine);
    verify_machine_ir_source(&bounds_machine, &bounds_ssa, &bounds_residual)
        .expect("Bounds Machine IR must bind to its Core and SSA source");

    assert_eq!(
        branch_machine.semantic_hash.to_hex(),
        "1b1e303af18630fb6249b8427f25ce9ce17b05718679f097fcf5afffd0782b0f"
    );
    assert_eq!(
        machine_ir_semantic_bytes(&branch_machine.program)
            .expect("branch-mix Machine IR must encode")
            .len(),
        16_916
    );
    assert_eq!(
        bounds_machine.semantic_hash.to_hex(),
        "758468a489dcd5ba2c55477a9d916530dd8c571e8dc4402194d73f3bdc6785e0"
    );
    assert_eq!(
        machine_ir_semantic_bytes(&bounds_machine.program)
            .expect("Bounds Machine IR must encode")
            .len(),
        872
    );

    let function_count = branch_machine.program.functions.len();
    let block_count = branch_machine
        .program
        .functions
        .iter()
        .map(|function| function.blocks.len())
        .sum::<usize>();
    let instruction_count = branch_machine
        .program
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .map(|block| block.instructions.len())
        .sum::<usize>();
    let branch_count = branch_machine
        .program
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .filter(|block| matches!(block.terminator, MachineTerminator::Branch { .. }))
        .count();
    let tail_call_count = branch_machine
        .program
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .filter(|block| matches!(block.terminator, MachineTerminator::TailCall { .. }))
        .count();
    let direct_call_count = branch_machine
        .program
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
        .filter(|instruction| matches!(instruction.kind, MachineInstructionKind::Call { .. }))
        .count();
    assert_eq!(
        (
            function_count,
            block_count,
            instruction_count,
            branch_count,
            tail_call_count,
            direct_call_count,
        ),
        (121, 139, 23, 9, 127, 0)
    );

    let manifest = corevm0_gate_a_manifest().expect("Gate A manifest must regenerate");
    assert_eq!(manifest.cases.len(), 51);
    let mut branch_cases = 0;
    let mut bounds_cases = 0;
    for case in manifest.cases {
        let values = case
            .input
            .array_f64_bits
            .iter()
            .copied()
            .map(f64::from_bits)
            .collect::<Vec<_>>();
        let (residual, ssa, machine, arguments) = match case.workload {
            CoreVmGateAWorkload::BranchMix => {
                branch_cases += 1;
                (
                    &branch_residual,
                    &branch_ssa,
                    &branch_machine,
                    vec![
                        CoreValue::array_f64(values),
                        CoreValue::I64(case.input.repetitions),
                    ],
                )
            }
            CoreVmGateAWorkload::BoundsOrderedArrayGet => {
                bounds_cases += 1;
                (
                    &bounds_residual,
                    &bounds_ssa,
                    &bounds_machine,
                    vec![CoreValue::array_f64(values)],
                )
            }
        };
        let residual_evaluation = evaluate(
            residual,
            arguments.clone(),
            EvaluationBudget::new(10_000_000, 256),
        )
        .expect("Residual Core must complete for every Gate A case");
        let ssa_evaluation = evaluate_core_ssa_translation(
            ssa,
            residual,
            arguments.clone(),
            EvaluationBudget::new(10_000_000, 256),
        )
        .expect("Core SSA must complete for every Gate A case");
        let machine_evaluation = evaluate_machine_ir_translation(
            machine,
            ssa,
            residual,
            arguments,
            EvaluationBudget::new(10_000_000, 256),
        )
        .expect("Machine IR must complete for every Gate A case");
        assert_outcome_same(&residual_evaluation.outcome, &ssa_evaluation.outcome);
        assert_eq!(
            ssa_evaluation.effect_trace,
            residual_evaluation.effect_trace
        );
        assert_outcome_same(&ssa_evaluation.outcome, &machine_evaluation.outcome);
        assert_eq!(machine_evaluation.effect_trace, ssa_evaluation.effect_trace);
    }
    assert_eq!(branch_cases, 46);
    assert_eq!(bounds_cases, 5);
}
