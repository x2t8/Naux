#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    branch_mix_kernel_program, build_definitional_corevm0, certify_binding_time_b0d,
    corevm0_gate_a_manifest, evaluate_machine_ir_translation, execute_x64_native_r1_s7b,
    lower_core_ssa_r1_s5, lower_machine_ir_r1_s6, lower_x64_target_r1_s7a,
    specialize_corevm0_r1_s4, validate_binding_time_b0_request,
    validate_specialization_r0a_request, verify_x64_target_source, BindingTime, BindingTimeBudget,
    BindingTimeCertificate, BindingTimeRequest, CoreArtifact, CoreProfile, CoreValue,
    CoreVmGateAWorkload, CoreVmInstruction, CoreVmProgram, CoreVmType, Effect, EffectEvent,
    EffectRow, ErrorKind, EvaluationBudget, EvaluationOutcome, Function, FunctionId, LocalId,
    MachineType, Mutability, Operand, Parameter, PolyvariantR1S4Budget, Primitive, Program, RValue,
    RegionId, SchemaVersion, SpecializationBudget, SpecializationRequest, SpecializationSlot, Term,
    Type, X64NativeExecution, X64NativeMappingState, X64NativeRunnerError, COREVM0_SCHEMA_VERSION,
};

fn seal(functions: Vec<Function>) -> CoreArtifact {
    CoreArtifact::seal(Program {
        schema: SchemaVersion::core_n0(),
        profile: CoreProfile::P1V0,
        entry: FunctionId(0),
        functions,
    })
    .expect("native runner fixture must seal")
}

fn array_type() -> Type {
    Type::Array {
        region: RegionId(0),
        mutability: Mutability::Read,
        element: Box::new(Type::F64),
    }
}

fn run_native(
    source: &CoreArtifact,
    arguments: &[CoreValue],
) -> Result<X64NativeExecution, X64NativeRunnerError> {
    let ssa = lower_core_ssa_r1_s5(source).expect("fixture must cross R1-S5");
    let machine = lower_machine_ir_r1_s6(&ssa, source).expect("fixture must cross R1-S6");
    let target =
        lower_x64_target_r1_s7a(&machine, &ssa, source).expect("fixture must cross R1-S7a");
    let source_bound = verify_x64_target_source(&target, &machine, &ssa, source)
        .expect("fixture target must replay from its exact source chain");
    execute_x64_native_r1_s7b(source_bound, arguments)
}

fn return_source(result: Type, value: Operand) -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result,
        body: Term::Return(value),
    }])
}

fn one_i64_parameter_source() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: Type::I64,
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
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

fn bounds_source() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![RegionId(0)],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: array_type(),
        }],
        effects: EffectRow::canonical(vec![Effect::Error(ErrorKind::Bounds)]),
        result: Type::F64,
        body: Term::Let {
            binder: LocalId(1),
            ty: Type::F64,
            value: RValue::Primitive {
                operation: Primitive::ArrayGetF64,
                arguments: vec![Operand::Local(LocalId(0)), Operand::I64(0)],
            },
            next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
        },
    }])
}

fn array_return_source() -> CoreArtifact {
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

fn five_lane_source() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: (0..5)
            .map(|local| Parameter {
                local: LocalId(local),
                ty: Type::I64,
            })
            .collect(),
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::Return(Operand::Local(LocalId(4))),
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

fn assert_common_execution(execution: &X64NativeExecution, lanes: u8) {
    assert_eq!(execution.input_lanes, lanes);
    assert_eq!(
        execution.mapping_trace,
        [
            X64NativeMappingState::Unmapped,
            X64NativeMappingState::ReadWrite,
            X64NativeMappingState::ReadExecute,
            X64NativeMappingState::Unmapped,
        ]
    );
    assert_eq!(execution.verified_code_hash, execution.copied_rw_code_hash);
    assert_eq!(
        execution.verified_code_hash,
        execution.readback_rx_code_hash
    );
    assert_eq!(execution.mxcsr_after, execution.mxcsr_before);
    assert!(!execution.fallback);
}

#[test]
fn unit_bool_i64_and_f64_returns_execute_through_wx_mapping() {
    let unit = run_native(&return_source(Type::Unit, Operand::Unit), &[])
        .expect("Unit bytes must execute");
    assert_eq!(unit.outcome, EvaluationOutcome::Return(CoreValue::Unit));
    assert_common_execution(&unit, 0);

    let boolean = run_native(&return_source(Type::Bool, Operand::Bool(true)), &[])
        .expect("Bool bytes must execute");
    assert_eq!(
        boolean.outcome,
        EvaluationOutcome::Return(CoreValue::Bool(true))
    );
    assert_common_execution(&boolean, 0);

    let integer = run_native(&return_source(Type::I64, Operand::I64(-17)), &[])
        .expect("I64 bytes must execute");
    assert_eq!(
        integer.outcome,
        EvaluationOutcome::Return(CoreValue::I64(-17))
    );
    assert_common_execution(&integer, 0);

    let float = run_native(&return_source(Type::F64, Operand::F64(-0.0)), &[])
        .expect("F64 bytes must execute");
    let EvaluationOutcome::Return(CoreValue::F64(value)) = float.outcome else {
        panic!("native F64 return has wrong shape");
    };
    assert_eq!(value.to_bits(), (-0.0_f64).to_bits());
    assert_common_execution(&float, 0);
}

#[test]
fn five_input_lanes_place_the_hidden_output_in_r9() {
    let execution = run_native(
        &five_lane_source(),
        &[
            CoreValue::I64(1),
            CoreValue::I64(2),
            CoreValue::I64(3),
            CoreValue::I64(4),
            CoreValue::I64(0x5566_7788),
        ],
    )
    .expect("five-lane native ABI must execute");
    assert_eq!(
        execution.outcome,
        EvaluationOutcome::Return(CoreValue::I64(0x5566_7788))
    );
    assert_common_execution(&execution, 5);
}

#[test]
fn native_branch_executes_both_directions_without_fallback() {
    let source = branch_source();
    let then_result =
        run_native(&source, &[CoreValue::Bool(true)]).expect("then branch must execute");
    let else_result =
        run_native(&source, &[CoreValue::Bool(false)]).expect("else branch must execute");
    assert_eq!(
        then_result.outcome,
        EvaluationOutcome::Return(CoreValue::I64(11))
    );
    assert_eq!(
        else_result.outcome,
        EvaluationOutcome::Return(CoreValue::I64(29))
    );
    assert_common_execution(&then_result, 1);
    assert_common_execution(&else_result, 1);
}

#[test]
fn checked_array_access_preserves_return_and_ordered_bounds() {
    let source = bounds_source();
    let returned = run_native(&source, &[CoreValue::array_f64(vec![-0.0])])
        .expect("in-bounds native load must execute");
    let EvaluationOutcome::Return(CoreValue::F64(value)) = returned.outcome else {
        panic!("in-bounds native load has wrong result");
    };
    assert_eq!(value.to_bits(), (-0.0_f64).to_bits());
    assert!(returned.effect_trace.is_empty());
    assert_common_execution(&returned, 2);

    let bounds = run_native(&source, &[CoreValue::array_f64(Vec::new())])
        .expect("native Bounds epilogue must return semantically");
    assert_eq!(bounds.outcome, EvaluationOutcome::Error(ErrorKind::Bounds));
    assert_eq!(
        bounds.effect_trace,
        vec![EffectEvent::Error(ErrorKind::Bounds)]
    );
    assert_common_execution(&bounds, 2);
}

#[test]
fn returned_array_must_be_the_exact_admitted_borrow() {
    let input = CoreValue::array_f64(vec![1.0, -0.0, f64::INFINITY]);
    let execution = run_native(&array_return_source(), std::slice::from_ref(&input))
        .expect("borrowed array descriptor must round-trip");
    assert_eq!(execution.outcome, EvaluationOutcome::Return(input.clone()));
    assert_common_execution(&execution, 2);
}

#[test]
fn arity_and_type_mismatches_fail_before_native_entry() {
    let source = one_i64_parameter_source();
    assert!(matches!(
        run_native(&source, &[]),
        Err(X64NativeRunnerError::InputArity {
            expected: 1,
            actual: 0
        })
    ));
    assert!(matches!(
        run_native(&source, &[CoreValue::Bool(true)]),
        Err(X64NativeRunnerError::InputType {
            parameter: 0,
            expected: MachineType::I64
        })
    ));
}

#[test]
fn runner_source_has_no_bridge_jit_or_libc_loader_dependency() {
    let source = include_str!("../src/core/x64_native.rs");
    for forbidden in [
        "crate::vm",
        "super::super::vm",
        "vm::jit",
        "libc::",
        "extern \"C\" {",
    ] {
        assert!(
            !source.contains(forbidden),
            "R1-S7b runner source must not contain {forbidden:?}"
        );
    }
}

#[test]
fn native_entry_restores_an_altered_caller_mxcsr() {
    struct RestoreMxcsr(u32);

    impl Drop for RestoreMxcsr {
        fn drop(&mut self) {
            // SAFETY: the value came from `stmxcsr`; only its rounding bits
            // were changed before this guard was created.
            unsafe {
                std::arch::asm!(
                    "ldmxcsr [{pointer}]",
                    pointer = in(reg) &self.0,
                    options(nostack, preserves_flags),
                );
            }
        }
    }

    let mut original = 0_u32;
    // SAFETY: `stmxcsr` writes exactly four bytes to an aligned Rust local.
    unsafe {
        std::arch::asm!(
            "stmxcsr [{pointer}]",
            pointer = in(reg) &mut original,
            options(nostack, preserves_flags),
        );
    }
    let _restore = RestoreMxcsr(original);
    let altered = (original & !0x6000) | 0x4000;
    // SAFETY: `altered` preserves every caller bit except the valid rounding
    // control field.
    unsafe {
        std::arch::asm!(
            "ldmxcsr [{pointer}]",
            pointer = in(reg) &altered,
            options(nostack, preserves_flags),
        );
    }

    let execution = run_native(&return_source(Type::Unit, Operand::Unit), &[])
        .expect("native entry must restore altered caller MXCSR");
    assert_eq!(execution.mxcsr_before, altered);
    assert_eq!(execution.mxcsr_after, altered);
}

#[test]
fn all_51_frozen_cases_match_machine_ir_in_process_without_fallback() {
    let branch_residual =
        specialize_corevm0_program(&branch_mix_kernel_program(), vec![array_type(), Type::I64]);
    let branch_ssa =
        lower_core_ssa_r1_s5(&branch_residual).expect("branch residual must cross R1-S5");
    let branch_machine =
        lower_machine_ir_r1_s6(&branch_ssa, &branch_residual).expect("branch SSA must cross R1-S6");
    let branch_target = lower_x64_target_r1_s7a(&branch_machine, &branch_ssa, &branch_residual)
        .expect("branch Machine IR must cross R1-S7a");
    let branch_bound = verify_x64_target_source(
        &branch_target,
        &branch_machine,
        &branch_ssa,
        &branch_residual,
    )
    .expect("branch target must replay");

    let bounds_residual = specialize_corevm0_program(&bounds_corevm0_program(), vec![array_type()]);
    let bounds_ssa =
        lower_core_ssa_r1_s5(&bounds_residual).expect("Bounds residual must cross R1-S5");
    let bounds_machine =
        lower_machine_ir_r1_s6(&bounds_ssa, &bounds_residual).expect("Bounds SSA must cross R1-S6");
    let bounds_target = lower_x64_target_r1_s7a(&bounds_machine, &bounds_ssa, &bounds_residual)
        .expect("Bounds Machine IR must cross R1-S7a");
    let bounds_bound = verify_x64_target_source(
        &bounds_target,
        &bounds_machine,
        &bounds_ssa,
        &bounds_residual,
    )
    .expect("Bounds target must replay");

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
        let (residual, ssa, machine, target, arguments) = match case.workload {
            CoreVmGateAWorkload::BranchMix => {
                branch_cases += 1;
                (
                    &branch_residual,
                    &branch_ssa,
                    &branch_machine,
                    branch_bound,
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
                    bounds_bound,
                    vec![CoreValue::array_f64(values)],
                )
            }
        };
        let machine_evaluation = evaluate_machine_ir_translation(
            machine,
            ssa,
            residual,
            arguments.clone(),
            EvaluationBudget::new(10_000_000, 256),
        )
        .expect("Machine IR must complete for every Gate A case");
        let native = execute_x64_native_r1_s7b(target, &arguments)
            .expect("native bytes must complete for every in-process Gate A case");
        assert_outcome_same(&machine_evaluation.outcome, &native.outcome);
        assert_eq!(machine_evaluation.effect_trace, native.effect_trace);
        assert!(!native.fallback);
    }
    assert_eq!(branch_cases, 46);
    assert_eq!(bounds_cases, 5);
}
