use naux::core::{
    branch_mix_kernel_program, build_definitional_corevm0, certify_binding_time_b0d,
    evaluate_corevm0, evaluate_definitional_corevm0, validate_binding_time_b0_request,
    validate_specialization_r0a_request, verify, verify_corevm0_program, BindingTime,
    BindingTimeBudget, BindingTimeRequest, CoreVmInstruction as I, CoreVmOutcome, CoreVmProgram,
    CoreVmType, CoreVmTypedError, CoreVmValue, DefinitionalCoreVmBuildError,
    DefinitionalCoreVmExecutionError, EvaluationBudget, FunctionId, RValue, SemanticHash,
    SpecializationBudget, SpecializationRequest, SpecializationSlot, Term,
    COREVM0_DEFINITIONAL_CONSTRUCTION_VERSION, COREVM0_SCHEMA_VERSION,
    R0_MAX_STATIC_VALUE_NODES_HARD_CAP,
};
use std::collections::BTreeSet;

fn core_budget() -> EvaluationBudget {
    EvaluationBudget::new(10_000_000, 64)
}

#[test]
fn branch_mix_definitional_artifact_verifies_and_matches_seed_smoke() {
    let program = branch_mix_kernel_program();
    let bound = build_definitional_corevm0(&program)
        .expect("verified branch_mix must construct a definitional artifact");
    verify(bound.artifact()).expect("ordinary Core verifier must admit the artifact");
    assert_eq!(
        bound.artifact().semantic_hash.to_hex(),
        "9ef102a420024b350e46499c83de65244ad5e1f47e006922443ab8b4d4fe3abe"
    );
    assert_eq!(
        bound.core_interpreter_semantics_hash().to_hex(),
        "d9911cf60e5afa54e271cdff274cde41b522a4a0c9855ccd6efbcd4e981909cc"
    );
    assert_eq!(
        bound.construction_version(),
        COREVM0_DEFINITIONAL_CONSTRUCTION_VERSION
    );

    let arguments = vec![
        CoreVmValue::array_f64(vec![1.0, -2.0, 3.5]),
        CoreVmValue::I64(2),
    ];
    let seed = evaluate_corevm0(
        verify_corevm0_program(&program).expect("program must verify"),
        arguments.clone(),
        100_000,
    )
    .expect("seed execution must complete");
    let core = evaluate_definitional_corevm0(&bound, arguments, core_budget())
        .expect("definitional execution must complete");

    assert_same_outcome(&core.outcome, &seed.outcome);
    assert_eq!(core.effect_trace, seed.effect_trace);
    assert_eq!(core.program_hash, seed.program_hash);
}

#[test]
fn branch_mix_seed_core_parity_covers_numeric_and_control_edges() {
    let program = branch_mix_kernel_program();
    let verified = verify_corevm0_program(&program).expect("program must verify");
    let bound = build_definitional_corevm0(&program).expect("artifact must build");
    let cases = vec![
        (vec![], -1),
        (vec![], 0),
        (vec![], 3),
        (vec![1.0], 0),
        (vec![1.0], 1),
        (vec![0.0, -0.0], 2),
        (vec![f64::NAN, 1.0], 1),
        (vec![f64::INFINITY, f64::NEG_INFINITY], 1),
        (vec![-1.0, 0.0, 1.0], 3),
    ];

    for (values, repetitions) in cases {
        let arguments = vec![
            CoreVmValue::array_f64(values),
            CoreVmValue::I64(repetitions),
        ];
        let seed = evaluate_corevm0(verified, arguments.clone(), 1_000_000)
            .expect("seed edge case must complete");
        let core = evaluate_definitional_corevm0(&bound, arguments, core_budget())
            .expect("Core edge case must complete");
        assert_same_outcome(&core.outcome, &seed.outcome);
        assert_eq!(core.effect_trace, seed.effect_trace);
    }
}

#[test]
fn bounded_generated_seed_core_parity_is_deterministic() {
    let program = branch_mix_kernel_program();
    let verified = verify_corevm0_program(&program).expect("program must verify");
    let bound = build_definitional_corevm0(&program).expect("artifact must build");
    let mut state = 0x8a5c_d789_635d_2dff_u64;

    for _ in 0..16 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let length = (state as usize) % 4;
        let repetitions = ((state >> 8) % 4) as i64 - 1;
        let mut values = Vec::with_capacity(length);
        for _ in 0..length {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            values.push(((state >> 17) as i64 % 257) as f64 / 16.0);
        }
        let arguments = vec![
            CoreVmValue::array_f64(values),
            CoreVmValue::I64(repetitions),
        ];
        let seed = evaluate_corevm0(verified, arguments.clone(), 1_000_000)
            .expect("seed generated case must complete");
        let first = evaluate_definitional_corevm0(&bound, arguments.clone(), core_budget())
            .expect("first Core run must complete");
        let second = evaluate_definitional_corevm0(&bound, arguments, core_budget())
            .expect("second Core run must complete");
        assert_eq!(first, second);
        assert_same_outcome(&first.outcome, &seed.outcome);
        assert_eq!(first.effect_trace, seed.effect_trace);
    }
}

#[test]
fn branch_mix_seed_core_parity_is_exhaustive_on_the_locked_micro_domain() {
    let program = branch_mix_kernel_program();
    let verified = verify_corevm0_program(&program).expect("program must verify");
    let bound = build_definitional_corevm0(&program).expect("artifact must build");
    let vectors = vec![vec![], vec![-1.0], vec![-0.0], vec![0.0], vec![1.0]];

    for values in vectors {
        for repetitions in -1_i64..=2 {
            let arguments = vec![
                CoreVmValue::array_f64(values.clone()),
                CoreVmValue::I64(repetitions),
            ];
            let seed = evaluate_corevm0(verified, arguments.clone(), 100_000)
                .expect("seed micro-domain case must complete");
            let core = evaluate_definitional_corevm0(&bound, arguments, core_budget())
                .expect("Core micro-domain case must complete");
            assert_same_outcome(&core.outcome, &seed.outcome);
            assert_eq!(core.effect_trace, seed.effect_trace);
        }
    }
}

#[test]
fn bounds_outcome_and_effect_trace_match_exactly() {
    let program = CoreVmProgram {
        schema_version: COREVM0_SCHEMA_VERSION,
        arguments: vec![CoreVmType::ArrayF64],
        locals: vec![],
        max_stack: 2,
        instructions: vec![I::LoadArg(0), I::ConstI64(0), I::ArrayGetF64, I::ReturnF64],
    };
    let verified = verify_corevm0_program(&program).expect("bounds program must verify");
    let bound = build_definitional_corevm0(&program).expect("artifact must build");

    for values in [vec![3.25], vec![]] {
        let arguments = vec![CoreVmValue::array_f64(values)];
        let seed = evaluate_corevm0(verified, arguments.clone(), 10)
            .expect("Bounds is a typed seed outcome");
        let core = evaluate_definitional_corevm0(&bound, arguments, core_budget())
            .expect("Bounds is a typed Core outcome");
        assert_same_outcome(&core.outcome, &seed.outcome);
        assert_eq!(core.effect_trace, seed.effect_trace);
    }
    let bounds =
        evaluate_definitional_corevm0(&bound, vec![CoreVmValue::array_f64(vec![])], core_budget())
            .expect("Bounds must remain a typed outcome");
    assert_eq!(
        bounds.outcome,
        CoreVmOutcome::Error(CoreVmTypedError::Bounds)
    );
    assert_eq!(bounds.effect_trace, vec![CoreVmTypedError::Bounds]);
}

#[test]
fn wrapping_i64_and_branch_direction_match_the_seed() {
    let program = CoreVmProgram {
        schema_version: COREVM0_SCHEMA_VERSION,
        arguments: vec![],
        locals: vec![],
        max_stack: 2,
        instructions: vec![
            I::ConstI64(i64::MAX),
            I::ConstI64(1),
            I::AddI64,
            I::ConstI64(0),
            I::CmpLtI64,
            I::JumpIfFalse(8),
            I::ConstF64(1.0),
            I::ReturnF64,
            I::ConstF64(0.0),
            I::ReturnF64,
        ],
    };
    let verified = verify_corevm0_program(&program).expect("wrapping program must verify");
    let bound = build_definitional_corevm0(&program).expect("artifact must build");
    let seed = evaluate_corevm0(verified, vec![], 20).expect("seed must complete");
    let core =
        evaluate_definitional_corevm0(&bound, vec![], core_budget()).expect("Core must complete");
    assert_eq!(seed.outcome, CoreVmOutcome::ReturnF64(1.0));
    assert_same_outcome(&core.outcome, &seed.outcome);
}

#[test]
fn fixed_capacity_fetch_reaches_instruction_slot_63() {
    let mut instructions = Vec::new();
    for value in 0..31 {
        instructions.push(I::ConstF64(value as f64));
        instructions.push(I::StoreLocal(0));
    }
    instructions.push(I::LoadLocal(0));
    instructions.push(I::ReturnF64);
    assert_eq!(instructions.len(), 64);
    let program = CoreVmProgram {
        schema_version: COREVM0_SCHEMA_VERSION,
        arguments: vec![],
        locals: vec![CoreVmType::F64],
        max_stack: 1,
        instructions,
    };
    let verified = verify_corevm0_program(&program).expect("capacity program must verify");
    let bound = build_definitional_corevm0(&program).expect("capacity artifact must build");
    let seed = evaluate_corevm0(verified, vec![], 100).expect("seed must reach slot 63");
    let core = evaluate_definitional_corevm0(&bound, vec![], core_budget())
        .expect("Core must reach slot 63");
    assert_eq!(seed.outcome, CoreVmOutcome::ReturnF64(30.0));
    assert_same_outcome(&core.outcome, &seed.outcome);
}

#[test]
fn fixed_capacity_state_reaches_stack_and_local_slot_15() {
    let mut instructions = Vec::new();
    for value in 0..16 {
        instructions.push(I::ConstF64(value as f64));
    }
    for local in (0..16).rev() {
        instructions.push(I::StoreLocal(local));
    }
    instructions.push(I::LoadLocal(15));
    instructions.push(I::ReturnF64);
    let program = CoreVmProgram {
        schema_version: COREVM0_SCHEMA_VERSION,
        arguments: vec![],
        locals: vec![CoreVmType::F64; 16],
        max_stack: 16,
        instructions,
    };
    let verified = verify_corevm0_program(&program).expect("capacity state program must verify");
    let bound = build_definitional_corevm0(&program).expect("capacity state artifact must build");
    let seed = evaluate_corevm0(verified, vec![], 100).expect("seed state path must complete");
    let core = evaluate_definitional_corevm0(&bound, vec![], core_budget())
        .expect("Core state path must complete");
    assert_eq!(seed.outcome, CoreVmOutcome::ReturnF64(15.0));
    assert_same_outcome(&core.outcome, &seed.outcome);
}

#[test]
fn fixed_capacity_argument_selector_reaches_slot_7() {
    let program = CoreVmProgram {
        schema_version: COREVM0_SCHEMA_VERSION,
        arguments: vec![CoreVmType::F64; 8],
        locals: vec![],
        max_stack: 1,
        instructions: vec![I::LoadArg(7), I::ReturnF64],
    };
    let verified = verify_corevm0_program(&program).expect("argument program must verify");
    let bound = build_definitional_corevm0(&program).expect("argument artifact must build");
    let arguments: Vec<CoreVmValue> = (0..8).map(|value| CoreVmValue::F64(value as f64)).collect();
    let seed = evaluate_corevm0(verified, arguments.clone(), 10).expect("seed must complete");
    let core = evaluate_definitional_corevm0(&bound, arguments, core_budget())
        .expect("Core must complete");
    assert_eq!(seed.outcome, CoreVmOutcome::ReturnF64(7.0));
    assert_same_outcome(&core.outcome, &seed.outcome);
}

#[test]
fn artifact_is_generic_over_instruction_contents_for_one_argument_shape() {
    let baseline = branch_mix_kernel_program();
    let mut changed = baseline.clone();
    changed.instructions[22] = I::ConstI64(18);
    let baseline = build_definitional_corevm0(&baseline).expect("baseline must build");
    let changed = build_definitional_corevm0(&changed).expect("valid mutation must build");

    assert_eq!(
        baseline.artifact().semantic_hash,
        changed.artifact().semantic_hash,
        "instruction contents must not construct the interpreter body"
    );
    assert_ne!(baseline.program_hash(), changed.program_hash());
    assert_ne!(baseline.program_image_hash(), changed.program_image_hash());
    assert_ne!(baseline.program_image(), changed.program_image());
}

#[test]
fn artifact_structurally_contains_all_fetch_slots_and_opcode_arms() {
    let bound =
        build_definitional_corevm0(&branch_mix_kernel_program()).expect("artifact must build");
    let fetch = bound
        .artifact()
        .program
        .functions
        .iter()
        .find(|function| function.id == FunctionId(2))
        .expect("generic fetch helper must exist");
    let mut projections = BTreeSet::new();
    let mut dispatch_cases = 0;
    inspect_term(&fetch.body, &mut projections, &mut dispatch_cases);
    assert_eq!(projections, (0_u32..64).collect());

    let loop_function = bound
        .artifact()
        .program
        .functions
        .iter()
        .find(|function| function.id == FunctionId(1))
        .expect("generic loop must exist");
    projections.clear();
    inspect_term(&loop_function.body, &mut projections, &mut dispatch_cases);
    assert_eq!(dispatch_cases, 1, "exactly one 16-opcode Case is required");
}

#[test]
fn invalid_program_arguments_and_core_budget_fail_closed() {
    let mut invalid = branch_mix_kernel_program();
    invalid.instructions[10] = I::Jump(999);
    assert!(matches!(
        build_definitional_corevm0(&invalid),
        Err(DefinitionalCoreVmBuildError::InvalidProgram(_))
    ));

    let program = branch_mix_kernel_program();
    let bound = build_definitional_corevm0(&program).expect("artifact must build");
    assert!(matches!(
        evaluate_definitional_corevm0(&bound, vec![], core_budget()),
        Err(DefinitionalCoreVmExecutionError::ArgumentArity {
            expected: 2,
            actual: 0
        })
    ));
    assert!(matches!(
        evaluate_definitional_corevm0(
            &bound,
            vec![CoreVmValue::I64(0), CoreVmValue::I64(1)],
            core_budget()
        ),
        Err(DefinitionalCoreVmExecutionError::ArgumentType {
            index: 0,
            expected: CoreVmType::ArrayF64,
            actual: CoreVmType::I64
        })
    ));
    assert!(matches!(
        evaluate_definitional_corevm0(
            &bound,
            vec![CoreVmValue::array_f64(vec![1.0]), CoreVmValue::I64(1)],
            EvaluationBudget::new(1, 64)
        ),
        Err(DefinitionalCoreVmExecutionError::Core(_))
    ));

    let mut forged_artifact = bound.artifact().clone();
    forged_artifact.semantic_hash = SemanticHash::ZERO;
    assert!(verify(&forged_artifact).is_err());
}

#[test]
fn full_program_image_passes_the_existing_b0_and_r0a_boundaries() {
    let program = branch_mix_kernel_program();
    let bound = build_definitional_corevm0(&program).expect("artifact must build");
    let request = BindingTimeRequest::p1v0(
        bound.artifact(),
        vec![
            BindingTime::Static,
            BindingTime::Dynamic,
            BindingTime::Dynamic,
        ],
        BindingTimeBudget::new(1_000_000, 1_000_000, 10_000),
    )
    .expect("B0 request must encode");
    let validated = validate_binding_time_b0_request(bound.artifact(), &request)
        .expect("B0 must admit the typed entry boundary");
    let certificate = certify_binding_time_b0d(&validated).expect("B0-D must certify");
    let entry = bound
        .artifact()
        .program
        .functions
        .iter()
        .find(|function| function.id == bound.artifact().program.entry)
        .expect("verified artifact has an entry");
    let specialization = SpecializationRequest::p1v0(
        bound.artifact(),
        &request,
        &certificate,
        vec![
            SpecializationSlot::Static(bound.program_image().clone()),
            SpecializationSlot::Dynamic(entry.parameters[1].ty.clone()),
            SpecializationSlot::Dynamic(entry.parameters[2].ty.clone()),
        ],
        SpecializationBudget::new(
            R0_MAX_STATIC_VALUE_NODES_HARD_CAP,
            1,
            1_000_000,
            1_000_000,
            100_000_000,
        ),
    )
    .expect("R0-A request must encode");
    validate_specialization_r0a_request(bound.artifact(), &request, &certificate, &specialization)
        .expect("full ProgramImage must pass ordinary R0-A admission");
}

fn assert_same_outcome(actual: &CoreVmOutcome, expected: &CoreVmOutcome) {
    match (actual, expected) {
        (CoreVmOutcome::ReturnF64(actual), CoreVmOutcome::ReturnF64(expected)) => {
            if expected.is_nan() {
                assert!(actual.is_nan());
            } else {
                assert_eq!(actual.to_bits(), expected.to_bits());
            }
        }
        (actual, expected) => assert_eq!(actual, expected),
    }
}

fn inspect_term(term: &Term, projections: &mut BTreeSet<u32>, dispatch_cases: &mut usize) {
    match term {
        Term::Let { value, next, .. } => {
            if let RValue::Project { index, .. } = value {
                projections.insert(*index);
            }
            inspect_term(next, projections, dispatch_cases);
        }
        Term::If {
            then_term,
            else_term,
            ..
        } => {
            inspect_term(then_term, projections, dispatch_cases);
            inspect_term(else_term, projections, dispatch_cases);
        }
        Term::Case { arms, .. } => {
            if arms.len() == 16
                && arms
                    .iter()
                    .enumerate()
                    .all(|(index, arm)| arm.constructor as usize == index)
            {
                *dispatch_cases += 1;
            }
            for arm in arms {
                inspect_term(&arm.body, projections, dispatch_cases);
            }
        }
        Term::Region { body, .. } => inspect_term(body, projections, dispatch_cases),
        Term::Handle { clauses, body, .. } => {
            for clause in clauses {
                inspect_term(&clause.body, projections, dispatch_cases);
            }
            inspect_term(body, projections, dispatch_cases);
        }
        Term::TailCall { .. } | Term::Return(_) => {}
    }
}
