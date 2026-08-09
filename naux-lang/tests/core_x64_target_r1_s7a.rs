use naux::core::{
    branch_mix_kernel_program, build_definitional_corevm0, certify_binding_time_b0d,
    corevm0_gate_a_manifest, evaluate, evaluate_machine_ir_translation, evaluate_x64_target_plan,
    evaluate_x64_target_translation, lower_core_ssa_r1_s5, lower_machine_ir_r1_s6,
    lower_x64_target_r1_s7a, seal_x64_target_correspondence_evidence,
    seal_x64_target_correspondence_record, specialize_corevm0_r1_s4,
    validate_binding_time_b0_request, validate_specialization_r0a_request,
    verify_x64_target_correspondence_evidence, verify_x64_target_r1_s7a, verify_x64_target_source,
    x64_target_plan_bytes, x64_target_semantic_bytes, BindingTime, BindingTimeBudget,
    BindingTimeCertificate, BindingTimeRequest, CoreArtifact, CoreProfile, CoreSsaArtifact,
    CoreValue, CoreVmGateAWorkload, CoreVmInstruction, CoreVmProgram, CoreVmType, Effect,
    EffectEvent, EffectRow, ErrorKind, EvaluationBudget, EvaluationOutcome, Function, FunctionId,
    LocalId, MachineIrArtifact, Mutability, NumericMode, Operand, Parameter, PolyvariantR1S4Budget,
    Primitive, Program, RValue, RegionId, SchemaVersion, SpecializationBudget,
    SpecializationRequest, SpecializationSlot, Term, Type, X64I64Opcode, X64Immediate,
    X64InstructionKind, X64Operand, X64SetCondition, X64Sse2F64Opcode, X64TargetArtifact,
    X64TargetLowerError, X64TargetPlanEvaluatorError, X64TargetPlanExecutionError,
    X64TargetSourceError, X64TargetVerificationCode, X64Terminator, COREVM0_SCHEMA_VERSION,
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

fn lower_to_target(
    source: &CoreArtifact,
) -> (CoreSsaArtifact, MachineIrArtifact, X64TargetArtifact) {
    let (ssa, machine) = lower_to_machine(source);
    let target = lower_x64_target_r1_s7a(&machine, &ssa, source)
        .expect("fixture must cross source-bound R1-S7a");
    (ssa, machine, target)
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

fn assert_target_verification_code(
    artifact: &X64TargetArtifact,
    expected: X64TargetVerificationCode,
) {
    let errors = verify_x64_target_r1_s7a(artifact).expect_err("mutated target artifact must fail");
    assert!(
        errors.0.iter().any(|error| error.code == expected),
        "expected {expected:?}, found {errors:?}"
    );
}

fn target_operation_shape(target: &X64TargetArtifact) -> [usize; 13] {
    let mut shape = [0; 13];
    for function in &target.program.functions {
        for block in &function.blocks {
            for instruction in &block.instructions {
                let index = match &instruction.kind {
                    X64InstructionKind::Move(_) => 0,
                    X64InstructionKind::I64Wrapping {
                        opcode: X64I64Opcode::Add,
                        ..
                    } => 1,
                    X64InstructionKind::I64Wrapping {
                        opcode: X64I64Opcode::Sub,
                        ..
                    } => 2,
                    X64InstructionKind::I64Wrapping {
                        opcode: X64I64Opcode::Mul,
                        ..
                    } => 3,
                    X64InstructionKind::Sse2F64 {
                        opcode: X64Sse2F64Opcode::AddSd,
                        ..
                    } => 4,
                    X64InstructionKind::Sse2F64 {
                        opcode: X64Sse2F64Opcode::SubSd,
                        ..
                    } => 5,
                    X64InstructionKind::I64Setcc {
                        condition: X64SetCondition::SignedLessThan,
                        ..
                    } => 6,
                    X64InstructionKind::I64Setcc {
                        condition: X64SetCondition::SignedGreaterOrEqual,
                        ..
                    } => 7,
                    X64InstructionKind::ArrayLenF64 { .. } => 8,
                    X64InstructionKind::ArrayGetF64Checked { .. } => 9,
                };
                shape[index] += 1;
            }
            let index = match &block.terminator {
                X64Terminator::Return { .. } => 10,
                X64Terminator::BranchRel32 { .. } => 11,
                X64Terminator::TailJumpRel32 { .. } => 12,
            };
            shape[index] += 1;
        }
    }
    shape
}

fn return_i64_source(value: i64) -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Return(Operand::I64(value)),
    }])
}

fn move_i64_source() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(0),
            ty: Type::I64,
            value: RValue::Use(Operand::I64(17)),
            next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
        },
    }])
}

fn return_unit_source() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::Unit,
        body: Term::Return(Operand::Unit),
    }])
}

fn return_bool_source() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::Bool,
        body: Term::Return(Operand::Bool(true)),
    }])
}

fn return_f64_source() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result: Type::F64,
        body: Term::Return(Operand::F64(-0.0)),
    }])
}

fn return_array_source() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![RegionId(0)],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: array_type(),
        }],
        effects: EffectRow::pure(),
        result: array_type(),
        body: Term::Return(Operand::Local(LocalId(0))),
    }])
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
            then_term: Box::new(Term::Return(Operand::I64(11))),
            else_term: Box::new(Term::Return(Operand::I64(29))),
        },
    }])
}

fn branch_local_source() -> CoreArtifact {
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
            then_term: Box::new(Term::Let {
                binder: LocalId(1),
                ty: Type::I64,
                value: RValue::Use(Operand::I64(11)),
                next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
            }),
            else_term: Box::new(Term::Return(Operand::I64(29))),
        },
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

fn excess_entry_lanes_source() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: (0..6)
            .map(|index| Parameter {
                local: LocalId(index),
                ty: Type::I64,
            })
            .collect(),
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Return(Operand::Local(LocalId(0))),
    }])
}

fn five_entry_lanes_source() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: (0..5)
            .map(|index| Parameter {
                local: LocalId(index),
                ty: Type::I64,
            })
            .collect(),
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Return(Operand::Local(LocalId(4))),
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

fn wrapping_mul_source() -> CoreArtifact {
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
                Primitive::I64Mul(NumericMode::Wrapping),
                vec![Operand::I64(i64::MAX), Operand::I64(2)],
            ),
            next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
        },
    }])
}

fn dynamic_f64_add_source() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![
            Parameter {
                local: LocalId(0),
                ty: Type::F64,
            },
            Parameter {
                local: LocalId(1),
                ty: Type::F64,
            },
        ],
        effects: EffectRow::pure(),
        result: Type::F64,
        body: Term::Let {
            binder: LocalId(2),
            ty: Type::F64,
            value: primitive(
                Primitive::F64Add,
                vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(1))],
            ),
            next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
        },
    }])
}

fn indexed_bounds_source() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![RegionId(0)],
        parameters: vec![
            Parameter {
                local: LocalId(0),
                ty: array_type(),
            },
            Parameter {
                local: LocalId(1),
                ty: Type::I64,
            },
        ],
        effects: bounds_effects(),
        result: Type::F64,
        body: Term::Let {
            binder: LocalId(2),
            ty: Type::F64,
            value: primitive(
                Primitive::ArrayGetF64,
                vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(1))],
            ),
            next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
        },
    }])
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
fn lowering_is_byte_deterministic_and_exactly_source_bound() {
    let source = branch_source();
    let (ssa, machine) = lower_to_machine(&source);
    let first =
        lower_x64_target_r1_s7a(&machine, &ssa, &source).expect("branch fixture must cross R1-S7a");
    let second =
        lower_x64_target_r1_s7a(&machine, &ssa, &source).expect("deterministic replay must lower");

    assert_eq!(first, second);
    assert_eq!(
        x64_target_plan_bytes(&first.program).expect("target plan must encode"),
        x64_target_plan_bytes(&second.program).expect("target replay must encode")
    );
    assert_eq!(
        x64_target_semantic_bytes(&first.program).expect("target artifact must encode"),
        x64_target_semantic_bytes(&second.program).expect("target replay must encode")
    );
    assert_eq!(first.program.code, second.program.code);
    assert!(!first.program.code.is_empty());
    assert!(!first.program.labels.is_empty());
    assert!(!first.program.fixups.is_empty());
    assert_eq!(first.program.entry_offset, 0);
    assert_eq!(first.program.labels[0].code_offset, 0);
    assert_eq!(
        first.program.code[0], 0x55,
        "entry must begin with push rbp"
    );
    assert_eq!(first.program.source_core_hash, source.semantic_hash);
    assert_eq!(first.program.source_ssa_hash, ssa.semantic_hash);
    assert_eq!(first.program.source_machine_ir_hash, machine.semantic_hash);

    verify_x64_target_r1_s7a(&first).expect("canonical target must verify locally");
    verify_x64_target_source(&first, &machine, &ssa, &source)
        .expect("canonical target must replay from its exact source chain");

    println!(
        "R1-S7a branch fixture: semantic_hash={} plan_hash={} code_hash={} plan_bytes={} semantic_bytes={} code_bytes={} labels={} fixups={}",
        first.semantic_hash.to_hex(),
        first.program.plan_hash.to_hex(),
        first.program.code_hash.to_hex(),
        x64_target_plan_bytes(&first.program)
            .expect("target plan must encode")
            .len(),
        x64_target_semantic_bytes(&first.program)
            .expect("target artifact must encode")
            .len(),
        first.program.code.len(),
        first.program.labels.len(),
        first.program.fixups.len(),
    );
}

#[test]
fn verifier_rejects_code_plan_fixup_abi_and_frame_mutations() {
    let (_, _, target) = lower_to_target(&branch_source());

    let mut code = target.clone();
    code.program.code[0] ^= 1;
    assert_target_verification_code(&code, X64TargetVerificationCode::CodeHashMismatch);
    assert_target_verification_code(&code, X64TargetVerificationCode::CodeMismatch);

    let mut plan = target.clone();
    let X64Terminator::Return { value, .. } = &mut plan.program.functions[0].blocks[1].terminator
    else {
        panic!("then block must end in Return");
    };
    *value = X64Operand::Immediate {
        ty: naux::core::MachineType::I64,
        value: X64Immediate::I64(12),
    };
    assert_target_verification_code(&plan, X64TargetVerificationCode::PlanHashMismatch);

    let mut fixup = target.clone();
    fixup.program.fixups[0].addend ^= 1;
    assert_target_verification_code(&fixup, X64TargetVerificationCode::InvalidFixup);

    let mut abi = target.clone();
    abi.program.abi.pointer_bits = 32;
    assert_target_verification_code(&abi, X64TargetVerificationCode::InvalidTarget);

    let mut frame = target;
    frame.program.frame.frame_bytes += 16;
    assert_target_verification_code(&frame, X64TargetVerificationCode::InvalidFrame);

    let (_, _, mut owner_swap) = lower_to_target(&branch_source());
    let then_label = owner_swap.program.functions[0].blocks[1].label;
    let else_label = owner_swap.program.functions[0].blocks[2].label;
    owner_swap.program.functions[0].blocks[1].label = else_label;
    owner_swap.program.functions[0].blocks[2].label = then_label;
    let X64Terminator::BranchRel32 {
        then_label,
        else_label,
        ..
    } = &mut owner_swap.program.functions[0].blocks[0].terminator
    else {
        panic!("entry block must branch");
    };
    std::mem::swap(then_label, else_label);
    assert_target_verification_code(&owner_swap, X64TargetVerificationCode::InvalidLabel);

    let (_, _, mut self_use) = lower_to_target(&wrapping_mul_source());
    let result = self_use.program.functions[0].blocks[0].instructions[0].result;
    self_use.program.functions[0].blocks[0].instructions[0].kind =
        X64InstructionKind::Move(X64Operand::Home(result));
    assert_target_verification_code(&self_use, X64TargetVerificationCode::InvalidHome);

    let (_, _, mut sibling_use) = lower_to_target(&branch_local_source());
    let sibling_home = sibling_use.program.functions[0].blocks[1].instructions[0].result;
    let X64Terminator::Return { value, .. } =
        &mut sibling_use.program.functions[0].blocks[2].terminator
    else {
        panic!("else branch must end in Return");
    };
    *value = X64Operand::Home(sibling_home);
    assert_target_verification_code(&sibling_use, X64TargetVerificationCode::InvalidHome);
}

#[test]
fn locally_valid_resealed_behavior_forgery_is_rejected_by_source_replay() {
    let source = return_i64_source(7);
    let (ssa, machine, expected) = lower_to_target(&source);

    let other_source = return_i64_source(8);
    let (_, _, other) = lower_to_target(&other_source);
    let mut forged_program = other.program;
    forged_program.source_core_hash = expected.program.source_core_hash;
    forged_program.source_ssa_hash = expected.program.source_ssa_hash;
    forged_program.source_machine_ir_hash = expected.program.source_machine_ir_hash;
    let forged = X64TargetArtifact::seal(forged_program)
        .expect("forged target must deterministically reseal");

    verify_x64_target_r1_s7a(&forged)
        .expect("behavior-forged artifact is intentionally locally self-consistent");
    assert!(matches!(
        verify_x64_target_source(&forged, &machine, &ssa, &source),
        Err(X64TargetSourceError::TranslationMismatch { .. })
    ));
}

#[test]
fn unsupported_direct_calls_and_saturating_i64_fail_closed_but_wrapping_mul_lowers() {
    for (name, source, expected_message) in [
        ("direct-call", direct_call_source(), "direct Call"),
        (
            "saturating-I64",
            saturating_source(),
            "saturating I64 operations",
        ),
    ] {
        let (ssa, machine) = lower_to_machine(&source);
        let error = lower_x64_target_r1_s7a(&machine, &ssa, &source)
            .expect_err("unsupported source must fail closed");
        assert!(
            matches!(
                error,
                X64TargetLowerError::UnsupportedSource { ref message, .. }
                    if message.contains(expected_message)
            ),
            "{name} produced unexpected error: {error:?}"
        );
    }

    let source = excess_entry_lanes_source();
    let (ssa, machine) = lower_to_machine(&source);
    assert!(matches!(
        lower_x64_target_r1_s7a(&machine, &ssa, &source),
        Err(X64TargetLowerError::StructuralLimit {
            field: "entry input lanes",
            limit: 5,
            actual: 6,
        })
    ));

    let source = wrapping_mul_source();
    let (ssa, machine, target) = lower_to_target(&source);
    assert_eq!(
        (
            target.program.code_hash.to_hex(),
            target.program.code.len(),
            target_operation_shape(&target),
        ),
        (
            "1b70eaf43c30fbe8a20a68a9bfb6449b736fc5e1e602a9a758af685bd3e685aa".to_owned(),
            201,
            [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        ),
    );
    let result = evaluate_x64_target_translation(
        &target,
        &machine,
        &ssa,
        &source,
        vec![],
        EvaluationBudget::new(100, 0),
    )
    .expect("wrapping Mul must execute through the target plan");
    assert_eq!(
        result.outcome,
        EvaluationOutcome::Return(CoreValue::I64(-2))
    );
}

#[test]
fn branch_and_checked_bounds_match_machine_ir_with_exact_effect_order() {
    let branch = branch_source();
    let (branch_ssa, branch_machine, branch_target) = lower_to_target(&branch);
    for value in [false, true] {
        let arguments = vec![CoreValue::Bool(value)];
        let machine = evaluate_machine_ir_translation(
            &branch_machine,
            &branch_ssa,
            &branch,
            arguments.clone(),
            EvaluationBudget::new(100, 0),
        )
        .expect("branch Machine IR must execute");
        let target = evaluate_x64_target_translation(
            &branch_target,
            &branch_machine,
            &branch_ssa,
            &branch,
            arguments,
            EvaluationBudget::new(100, 0),
        )
        .expect("branch target plan must execute");
        assert_outcome_same(&machine.outcome, &target.outcome);
        assert_eq!(target.effect_trace, machine.effect_trace);
    }

    let bounds = indexed_bounds_source();
    let (bounds_ssa, bounds_machine, bounds_target) = lower_to_target(&bounds);
    let values = vec![3.25, -0.0];
    for index in [-1, 0, 1, 2] {
        let arguments = vec![CoreValue::array_f64(values.clone()), CoreValue::I64(index)];
        let machine = evaluate_machine_ir_translation(
            &bounds_machine,
            &bounds_ssa,
            &bounds,
            arguments.clone(),
            EvaluationBudget::new(100, 0),
        )
        .expect("Bounds Machine IR must execute");
        let target = evaluate_x64_target_translation(
            &bounds_target,
            &bounds_machine,
            &bounds_ssa,
            &bounds,
            arguments,
            EvaluationBudget::new(100, 0),
        )
        .expect("Bounds target plan must execute");
        assert_outcome_same(&machine.outcome, &target.outcome);
        assert_eq!(target.effect_trace, machine.effect_trace);
        if index < 0 || index >= values.len() as i64 {
            assert_eq!(target.outcome, EvaluationOutcome::Error(ErrorKind::Bounds));
            assert_eq!(
                target.effect_trace,
                vec![EffectEvent::Error(ErrorKind::Bounds)]
            );
        }
    }
}

#[test]
fn target_plan_evaluator_has_an_exact_work_boundary() {
    let (_, _, target) = lower_to_target(&wrapping_mul_source());
    assert!(matches!(
        evaluate_x64_target_plan(&target, vec![], EvaluationBudget::new(2, 0)),
        Err(X64TargetPlanExecutionError::Execution(
            X64TargetPlanEvaluatorError::StepBudgetExceeded { limit: 2 }
        ))
    ));
    let exact = evaluate_x64_target_plan(&target, vec![], EvaluationBudget::new(3, 0))
        .expect("entry transfer, Mul, and Return consume exactly three work units");
    assert_eq!(exact.outcome, EvaluationOutcome::Return(CoreValue::I64(-2)));
    assert_eq!(exact.steps, 3);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn target_plan_evaluator_installs_and_restores_canonical_mxcsr() {
    struct RestoreMxcsr(u32);

    impl Drop for RestoreMxcsr {
        fn drop(&mut self) {
            // SAFETY: the value was captured with STMXCSR on this thread and
            // the pointer remains valid for the duration of the instruction.
            unsafe {
                core::arch::asm!(
                    "ldmxcsr [{address}]",
                    address = in(reg) &self.0,
                    options(nostack, preserves_flags, readonly)
                );
            }
        }
    }

    fn read_mxcsr() -> u32 {
        let mut value = 0_u32;
        // SAFETY: `value` is writable initialized u32 storage and STMXCSR is
        // a baseline x86-64 instruction.
        unsafe {
            core::arch::asm!(
                "stmxcsr [{address}]",
                address = in(reg) &mut value,
                options(nostack, preserves_flags)
            );
        }
        value
    }

    fn write_mxcsr(value: &u32) {
        // SAFETY: `value` is readable initialized u32 storage and LDMXCSR is
        // a baseline x86-64 instruction.
        unsafe {
            core::arch::asm!(
                "ldmxcsr [{address}]",
                address = in(reg) value,
                options(nostack, preserves_flags, readonly)
            );
        }
    }

    let original = read_mxcsr();
    let _restore = RestoreMxcsr(original);
    let caller_upward = 0x0000_5f80_u32;
    write_mxcsr(&caller_upward);
    assert_eq!(read_mxcsr(), caller_upward);

    let (_, _, target) = lower_to_target(&dynamic_f64_add_source());
    let result = evaluate_x64_target_plan(
        &target,
        vec![
            CoreValue::F64(1.0),
            CoreValue::F64(1.110_223_024_625_156_5e-16),
        ],
        EvaluationBudget::new(7, 0),
    )
    .expect("target-plan evaluator must run under canonical MXCSR");
    assert_eq!(
        result.outcome,
        EvaluationOutcome::Return(CoreValue::F64(1.0))
    );
    assert_eq!(
        read_mxcsr(),
        caller_upward,
        "target-plan evaluation must restore the caller's complete MXCSR"
    );
}

#[test]
fn remaining_encoder_template_families_have_locked_code_vectors() {
    for (name, source, code_hash, code_bytes, shape) in [
        (
            "move-i64",
            move_i64_source(),
            "53f8c7289faf0ecb7e7e818e738d2c2a74e2c9c82adde639b5faeb5595444863",
            187,
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        ),
        (
            "return-unit",
            return_unit_source(),
            "2aa8ba6bf48b75b97ea257d03643387663b23bc9d244eff09e9d64cfdebaf985",
            163,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        ),
        (
            "return-bool",
            return_bool_source(),
            "0b10d2d6adc4de685d206b1c2d82fb8f9de30fbea764997b95f3cc913545d676",
            171,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        ),
        (
            "return-f64",
            return_f64_source(),
            "605693d4d2b094852617d949b703269c521f3f085be1373db53d80e144d8dc8b",
            194,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        ),
        (
            "return-array",
            return_array_source(),
            "1212648da3420bd2c58fa7050e1bd40f51fc8ebee1e3e578ce91b1764ee23805",
            191,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        ),
        (
            "five-entry-lanes",
            five_entry_lanes_source(),
            "8357f066b5554b0360ca5026cd140efbd03cdcf9516f158dfecae22d50a5e3d4",
            209,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        ),
    ] {
        let (_, _, target) = lower_to_target(&source);
        assert_eq!(
            (
                target.program.code_hash.to_hex(),
                target.program.code.len(),
                target_operation_shape(&target),
            ),
            (code_hash.to_owned(), code_bytes, shape),
            "{name} encoder template vector changed",
        );
    }
}

#[test]
fn all_51_frozen_gate_a_cases_cross_machine_ir_and_target_plan() {
    let branch_residual =
        specialize_corevm0_program(&branch_mix_kernel_program(), vec![array_type(), Type::I64]);
    let (branch_ssa, branch_machine) = lower_to_machine(&branch_residual);
    let branch_target = lower_x64_target_r1_s7a(&branch_machine, &branch_ssa, &branch_residual)
        .expect("branch-mix Machine IR must cross R1-S7a");
    verify_x64_target_source(
        &branch_target,
        &branch_machine,
        &branch_ssa,
        &branch_residual,
    )
    .expect("branch-mix target must replay from the exact source chain");

    let bounds_residual = specialize_corevm0_program(&bounds_corevm0_program(), vec![array_type()]);
    let (bounds_ssa, bounds_machine) = lower_to_machine(&bounds_residual);
    let bounds_target = lower_x64_target_r1_s7a(&bounds_machine, &bounds_ssa, &bounds_residual)
        .expect("Bounds Machine IR must cross R1-S7a");
    verify_x64_target_source(
        &bounds_target,
        &bounds_machine,
        &bounds_ssa,
        &bounds_residual,
    )
    .expect("Bounds target must replay from the exact source chain");

    assert_eq!(
        (
            branch_residual.semantic_hash.to_hex(),
            branch_ssa.semantic_hash.to_hex(),
            branch_machine.semantic_hash.to_hex(),
        ),
        (
            "fd90f6b16813a851aea7b1151a2df9ad87f9a9bfb8e994a5797407700f9fb2e9".to_owned(),
            "f31be2b773f263db5257fabc0e86a5572d5585b15c3b71b0d73ad6198b62630d".to_owned(),
            "1b1e303af18630fb6249b8427f25ce9ce17b05718679f097fcf5afffd0782b0f".to_owned(),
        ),
    );
    assert_eq!(
        (
            bounds_residual.semantic_hash.to_hex(),
            bounds_ssa.semantic_hash.to_hex(),
            bounds_machine.semantic_hash.to_hex(),
        ),
        (
            "4102a323b6e0165457abd636f2252c3299b7ac88848b1f155cbb38983a8294a5".to_owned(),
            "009e1eacbec8d2c5fc0363b753de6defc96073cbb413f87dc4db046ccc10f2c6".to_owned(),
            "758468a489dcd5ba2c55477a9d916530dd8c571e8dc4402194d73f3bdc6785e0".to_owned(),
        ),
    );
    assert_eq!(
        (
            branch_target.program.functions.len(),
            branch_target
                .program
                .functions
                .iter()
                .map(|function| function.blocks.len())
                .sum::<usize>(),
            bounds_target.program.functions.len(),
            bounds_target
                .program
                .functions
                .iter()
                .map(|function| function.blocks.len())
                .sum::<usize>(),
        ),
        (121, 139, 9, 9),
    );

    assert_eq!(
        (
            branch_target.semantic_hash.to_hex(),
            branch_target.program.plan_hash.to_hex(),
            branch_target.program.code_hash.to_hex(),
            x64_target_plan_bytes(&branch_target.program)
                .expect("branch target plan must encode")
                .len(),
            x64_target_semantic_bytes(&branch_target.program)
                .expect("branch target artifact must encode")
                .len(),
            branch_target.program.code.len(),
            branch_target.program.labels.len(),
            branch_target.program.fixups.len(),
            branch_target.program.frame,
            target_operation_shape(&branch_target),
        ),
        (
            "a642bcc02f2ea3566b0d5f275780e5cbbefe007b46a0eaa5578f3f680f838e95".to_owned(),
            "86bb51383c27517fa98ec8d58f3d2d77970b61a468ef31d66defa3352190c6bd".to_owned(),
            "ef32051c5c7af81365eee82664636f0a82bef5b1de3a8e3dcc07c2c207d7ce54".to_owned(),
            34_742,
            38_558,
            3_097,
            142,
            51,
            naux::core::X64FrameLayout {
                header_bytes: 32,
                home_base: 32,
                max_home_bytes: 104,
                outgoing_base: 136,
                outgoing_bytes: 96,
                frame_bytes: 240,
            },
            [0, 5, 2, 0, 1, 1, 2, 7, 3, 2, 3, 9, 127],
        ),
    );
    assert_eq!(
        (
            bounds_target.semantic_hash.to_hex(),
            bounds_target.program.plan_hash.to_hex(),
            bounds_target.program.code_hash.to_hex(),
            x64_target_plan_bytes(&bounds_target.program)
                .expect("Bounds target plan must encode")
                .len(),
            x64_target_semantic_bytes(&bounds_target.program)
                .expect("Bounds target artifact must encode")
                .len(),
            bounds_target.program.code.len(),
            bounds_target.program.labels.len(),
            bounds_target.program.fixups.len(),
            bounds_target.program.frame,
            target_operation_shape(&bounds_target),
        ),
        (
            "06e8a4cd6d1a7df57229180248c9f0040c9aa7781e1f38dea60e3f6a8f1c6251".to_owned(),
            "ca769f57312c92eff2d3ae9339b890b5e595685cbcde8f012c0fcffc568aaf97".to_owned(),
            "c80220666bc16c99bd2c2a0570e418cc47462e0cdf8c7483530a8c7c149fee19".to_owned(),
            1_653,
            2_356,
            488,
            12,
            9,
            naux::core::X64FrameLayout {
                header_bytes: 32,
                home_base: 32,
                max_home_bytes: 56,
                outgoing_base: 88,
                outgoing_bytes: 48,
                frame_bytes: 144,
            },
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 8],
        ),
    );

    println!(
        "R1-S7a lighthouse: branch core={} ssa={} machine={} semantic={} plan={} code={} plan_bytes={} semantic_bytes={} code_bytes={} labels={} fixups={} frame={:?} shape={:?}; bounds core={} ssa={} machine={} semantic={} plan={} code={} plan_bytes={} semantic_bytes={} code_bytes={} labels={} fixups={} frame={:?} shape={:?}",
        branch_residual.semantic_hash.to_hex(),
        branch_ssa.semantic_hash.to_hex(),
        branch_machine.semantic_hash.to_hex(),
        branch_target.semantic_hash.to_hex(),
        branch_target.program.plan_hash.to_hex(),
        branch_target.program.code_hash.to_hex(),
        x64_target_plan_bytes(&branch_target.program)
            .expect("branch target plan must encode")
            .len(),
        x64_target_semantic_bytes(&branch_target.program)
            .expect("branch target artifact must encode")
            .len(),
        branch_target.program.code.len(),
        branch_target.program.labels.len(),
        branch_target.program.fixups.len(),
        branch_target.program.frame,
        target_operation_shape(&branch_target),
        bounds_residual.semantic_hash.to_hex(),
        bounds_ssa.semantic_hash.to_hex(),
        bounds_machine.semantic_hash.to_hex(),
        bounds_target.semantic_hash.to_hex(),
        bounds_target.program.plan_hash.to_hex(),
        bounds_target.program.code_hash.to_hex(),
        x64_target_plan_bytes(&bounds_target.program)
            .expect("Bounds target plan must encode")
            .len(),
        x64_target_semantic_bytes(&bounds_target.program)
            .expect("Bounds target artifact must encode")
            .len(),
        bounds_target.program.code.len(),
        bounds_target.program.labels.len(),
        bounds_target.program.fixups.len(),
        bounds_target.program.frame,
        target_operation_shape(&bounds_target),
    );

    let manifest = corevm0_gate_a_manifest().expect("Gate A manifest must regenerate");
    assert_eq!(manifest.cases.len(), 51);
    let mut branch_cases = 0;
    let mut bounds_cases = 0;
    let mut correspondence_records = Vec::with_capacity(manifest.cases.len());
    for case in manifest.cases {
        let values = case
            .input
            .array_f64_bits
            .iter()
            .copied()
            .map(f64::from_bits)
            .collect::<Vec<_>>();
        let (residual, ssa, machine, target, arguments) = match case.workload {
            CoreVmGateAWorkload::BranchMix => {
                branch_cases += 1;
                (
                    &branch_residual,
                    &branch_ssa,
                    &branch_machine,
                    &branch_target,
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
                    &bounds_target,
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
        let machine_evaluation = evaluate_machine_ir_translation(
            machine,
            ssa,
            residual,
            arguments.clone(),
            EvaluationBudget::new(10_000_000, 256),
        )
        .expect("Machine IR must complete for every Gate A case");
        let target_evaluation = evaluate_x64_target_translation(
            target,
            machine,
            ssa,
            residual,
            arguments,
            EvaluationBudget::new(10_000_000, 256),
        )
        .expect("target plan must complete for every Gate A case");
        assert_outcome_same(&residual_evaluation.outcome, &machine_evaluation.outcome);
        assert_eq!(
            machine_evaluation.effect_trace,
            residual_evaluation.effect_trace
        );
        assert_outcome_same(&machine_evaluation.outcome, &target_evaluation.outcome);
        assert_eq!(
            target_evaluation.effect_trace,
            machine_evaluation.effect_trace
        );
        correspondence_records.push(
            seal_x64_target_correspondence_record(
                case.ordinal,
                case.input_hash,
                machine,
                target,
                &machine_evaluation,
                &target_evaluation,
            )
            .expect("every Gate A case must produce canonical R1-S7a correspondence evidence"),
        );
    }
    assert_eq!(branch_cases, 46);
    assert_eq!(bounds_cases, 5);

    let evidence = seal_x64_target_correspondence_evidence(correspondence_records)
        .expect("the ordered 51-case correspondence corpus must seal");
    verify_x64_target_correspondence_evidence(&evidence)
        .expect("the sealed 51-case correspondence evidence must verify");
    assert_eq!(evidence.records.len(), 51);
    assert_eq!(
        evidence.results_hash.to_hex(),
        "fe9cbcaf67798b502e8405eecb0228b7453d39427e97e4d404c7cd1356c8c49d"
    );

    let mut reordered = evidence.clone();
    reordered.records.swap(0, 1);
    assert!(
        verify_x64_target_correspondence_evidence(&reordered).is_err(),
        "record ordering must be part of fail-closed results admission"
    );
}
