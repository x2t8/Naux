use naux::core::{
    branch_mix_kernel_program, certify_binding_time_b0d, corevm0_core_image, corevm0_program_bytes,
    corevm0_program_hash, evaluate_corevm0, specialization_value_hash,
    validate_binding_time_b0_request, validate_specialization_r0a_request, verify_corevm0_program,
    BindingTime, BindingTimeBudget, BindingTimeRequest, CoreArtifact, CoreProfile,
    CoreVmCoreImageError, CoreVmExecutionError, CoreVmInstruction as I, CoreVmOutcome,
    CoreVmProgram, CoreVmType, CoreVmTypedError, CoreVmValue, CoreVmVerificationCode, EffectRow,
    Function, FunctionId, LocalId, Mutability, Operand, Parameter, Program, RegionId,
    SpecializationBudget, SpecializationRequest, SpecializationSlot, Term, Type,
    COREVM0_SCHEMA_VERSION, R0_MAX_STATIC_VALUE_NODES_HARD_CAP,
};

fn evaluate(
    program: &CoreVmProgram,
    arguments: Vec<CoreVmValue>,
    max_steps: u64,
) -> Result<naux::core::CoreVmEvaluation, CoreVmExecutionError> {
    let verified = verify_corevm0_program(program).expect("test program must verify");
    evaluate_corevm0(verified, arguments, max_steps)
}

fn assert_same_f64(actual: f64, expected: f64) {
    if expected.is_nan() {
        assert!(actual.is_nan(), "expected NaN, found {actual:?}");
    } else {
        assert_eq!(
            actual.to_bits(),
            expected.to_bits(),
            "strict F64 bits differ"
        );
    }
}

fn branch_mix_oracle(values: &[f64], reps: i64) -> f64 {
    let mut state = 0_i64;
    let mut sum = 0.0_f64;
    let mut repetition = 0_i64;
    while repetition < reps {
        for value in values {
            state = state.wrapping_add(17);
            if state >= 97 {
                state = state.wrapping_sub(97);
            }
            if state < 48 {
                sum += value;
            } else {
                sum -= value;
            }
        }
        repetition = repetition.wrapping_add(1);
    }
    sum
}

#[test]
fn branch_mix_image_verifies_hashes_deterministically_and_covers_every_opcode() {
    let first = branch_mix_kernel_program();
    let second = branch_mix_kernel_program();
    verify_corevm0_program(&first).expect("canonical branch_mix bytecode must verify");
    assert_eq!(first, second);
    assert_eq!(
        corevm0_program_bytes(&first).expect("program must encode"),
        corevm0_program_bytes(&second).expect("program must encode")
    );
    assert_eq!(
        corevm0_program_hash(&first)
            .expect("program must hash")
            .to_hex(),
        "9770cd0fb20fefaebba063674e02b1881173a817b73b9f910c9ba8e025a9b2d5"
    );

    let mut seen = [false; 16];
    for instruction in &first.instructions {
        let tag = match instruction {
            I::ConstI64(_) => 0,
            I::ConstF64(_) => 1,
            I::LoadArg(_) => 2,
            I::LoadLocal(_) => 3,
            I::StoreLocal(_) => 4,
            I::AddI64 => 5,
            I::SubI64 => 6,
            I::AddF64 => 7,
            I::SubF64 => 8,
            I::CmpLtI64 => 9,
            I::CmpGeI64 => 10,
            I::ArrayLenF64 => 11,
            I::ArrayGetF64 => 12,
            I::Jump(_) => 13,
            I::JumpIfFalse(_) => 14,
            I::ReturnF64 => 15,
        };
        seen[tag] = true;
    }
    assert!(
        seen.into_iter().all(|present| present),
        "the lighthouse image must exercise every required opcode"
    );
}

#[test]
fn branch_mix_program_is_an_exact_ordinary_core_static_value() {
    let program = branch_mix_kernel_program();
    let image = corevm0_core_image(&program).expect("verified bytecode must map into Core");
    let Type::Tuple(instruction_types) = &image.ty else {
        panic!("CoreVM0 image type must be a fixed Tuple");
    };
    let naux::core::SpecializationValue::Tuple(instructions) = &image.value else {
        panic!("CoreVM0 image value must be a fixed Tuple");
    };
    assert_eq!(instruction_types.len(), program.instructions.len());
    assert_eq!(instructions.len(), program.instructions.len());
    assert_eq!(
        specialization_value_hash(&image.value)
            .expect("Core image must hash")
            .to_hex(),
        "9ced2bbdcc19b5225f7e15a5d30525ffd8424794e8ccc5b40c2402a3f11856c9"
    );

    let array = Type::Array {
        region: RegionId(0),
        mutability: Mutability::Read,
        element: Box::new(Type::F64),
    };
    let artifact = CoreArtifact::seal(Program {
        schema: naux::core::SchemaVersion::core_n0(),
        profile: CoreProfile::P1V0,
        entry: FunctionId(0),
        functions: vec![Function {
            id: FunctionId(0),
            region_parameters: vec![RegionId(0)],
            parameters: vec![
                Parameter {
                    local: LocalId(0),
                    ty: image.ty.clone(),
                },
                Parameter {
                    local: LocalId(1),
                    ty: array.clone(),
                },
                Parameter {
                    local: LocalId(2),
                    ty: Type::I64,
                },
            ],
            effects: EffectRow::pure(),
            result: Type::F64,
            body: Term::Return(Operand::F64(0.0)),
        }],
    })
    .expect("Core image boundary must encode");
    let binding_time_request = BindingTimeRequest::p1v0(
        &artifact,
        vec![
            BindingTime::Static,
            BindingTime::Dynamic,
            BindingTime::Dynamic,
        ],
        BindingTimeBudget::new(100_000, 100_000, 1_000),
    )
    .expect("B0 request must encode");
    let certificate = certify_binding_time_b0d(
        &validate_binding_time_b0_request(&artifact, &binding_time_request)
            .expect("B0 request must validate"),
    )
    .expect("B0 certificate must emit");
    let request = SpecializationRequest::p1v0(
        &artifact,
        &binding_time_request,
        &certificate,
        vec![
            SpecializationSlot::Static(image.value),
            SpecializationSlot::Dynamic(array),
            SpecializationSlot::Dynamic(Type::I64),
        ],
        SpecializationBudget::new(
            R0_MAX_STATIC_VALUE_NODES_HARD_CAP,
            1,
            10_000,
            10_000,
            10_000_000,
        ),
    )
    .expect("R0 request must encode");
    validate_specialization_r0a_request(&artifact, &binding_time_request, &certificate, &request)
        .expect("the bytecode Tuple/Sum must pass the ordinary R0-A boundary");

    let mut invalid = program;
    invalid.instructions[10] = I::Jump(999);
    assert!(matches!(
        corevm0_core_image(&invalid),
        Err(CoreVmCoreImageError::InvalidProgram(_))
    ));
}

#[test]
fn branch_mix_matches_the_direct_oracle_across_edge_cases() {
    let program = branch_mix_kernel_program();
    let cases = vec![
        (vec![], 0),
        (vec![], 7),
        (vec![1.0], 0),
        (vec![1.0], -3),
        (vec![1.0], 1),
        (vec![1.0, -2.0, 3.5], 9),
        (vec![0.0, -0.0, 1.0, -1.0, 2.0], 17),
        (vec![f64::INFINITY, 1.0, f64::NEG_INFINITY], 2),
        (vec![f64::NAN, 1.0], 3),
        ((0..31).map(|index| index as f64 * 0.25 - 2.0).collect(), 11),
    ];

    for (values, reps) in cases {
        let expected = branch_mix_oracle(&values, reps);
        let evaluation = evaluate(
            &program,
            vec![
                CoreVmValue::array_f64(values.clone()),
                CoreVmValue::I64(reps),
            ],
            1_000_000,
        )
        .expect("branch_mix execution must stay in budget");
        let CoreVmOutcome::ReturnF64(actual) = evaluation.outcome else {
            panic!("branch_mix unexpectedly returned an error");
        };
        assert_same_f64(actual, expected);
        assert!(evaluation.effect_trace.is_empty());
    }
}

#[test]
fn branch_mix_matches_a_bounded_exhaustive_small_domain() {
    let program = branch_mix_kernel_program();
    let alphabet = [-1.0_f64, -0.0, 0.0, 1.0];
    let mut vectors = vec![vec![]];
    for length in 1..=3 {
        let count = alphabet.len().pow(length as u32);
        for encoded in 0..count {
            let mut cursor = encoded;
            let mut values = Vec::with_capacity(length);
            for _ in 0..length {
                values.push(alphabet[cursor % alphabet.len()]);
                cursor /= alphabet.len();
            }
            vectors.push(values);
        }
    }

    for values in vectors {
        for reps in -1_i64..=5 {
            let expected = branch_mix_oracle(&values, reps);
            let evaluation = evaluate(
                &program,
                vec![
                    CoreVmValue::array_f64(values.clone()),
                    CoreVmValue::I64(reps),
                ],
                100_000,
            )
            .expect("bounded exhaustive vector must execute");
            let CoreVmOutcome::ReturnF64(actual) = evaluation.outcome else {
                panic!("verified branch_mix vector returned a typed error");
            };
            assert_same_f64(actual, expected);
        }
    }
}

#[test]
fn branch_mix_matches_a_deterministic_generated_corpus() {
    let program = branch_mix_kernel_program();
    let mut state = 0x8a5c_d789_635d_2dff_u64;
    for _ in 0..256 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let length = (state as usize) % 18;
        let reps = ((state >> 8) % 13) as i64 - 2;
        let mut values = Vec::with_capacity(length);
        for _ in 0..length {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let signed = (state >> 11) as i64;
            values.push((signed % 20_001) as f64 / 64.0);
        }
        let expected = branch_mix_oracle(&values, reps);
        let first = evaluate(
            &program,
            vec![
                CoreVmValue::array_f64(values.clone()),
                CoreVmValue::I64(reps),
            ],
            1_000_000,
        )
        .expect("generated corpus must execute");
        let second = evaluate(
            &program,
            vec![CoreVmValue::array_f64(values), CoreVmValue::I64(reps)],
            1_000_000,
        )
        .expect("repeated generated vector must execute");
        assert_eq!(first, second, "CoreVM0 execution must be deterministic");
        let CoreVmOutcome::ReturnF64(actual) = first.outcome else {
            panic!("generated branch_mix vector returned a typed error");
        };
        assert_same_f64(actual, expected);
    }
}

#[test]
fn array_get_preserves_typed_bounds_behavior() {
    let program = CoreVmProgram {
        schema_version: COREVM0_SCHEMA_VERSION,
        arguments: vec![CoreVmType::ArrayF64],
        locals: vec![],
        max_stack: 2,
        instructions: vec![I::LoadArg(0), I::ConstI64(0), I::ArrayGetF64, I::ReturnF64],
    };
    let success = evaluate(&program, vec![CoreVmValue::array_f64(vec![3.25])], 10)
        .expect("in-bounds execution must pass");
    assert_eq!(success.outcome, CoreVmOutcome::ReturnF64(3.25));
    assert!(success.effect_trace.is_empty());

    let bounds = evaluate(&program, vec![CoreVmValue::array_f64(vec![])], 10)
        .expect("bounds failure is a typed VM outcome");
    assert_eq!(
        bounds.outcome,
        CoreVmOutcome::Error(CoreVmTypedError::Bounds)
    );
    assert_eq!(bounds.effect_trace, vec![CoreVmTypedError::Bounds]);
    assert_eq!(bounds.steps, 3);
}

#[test]
fn execution_arguments_and_step_budget_fail_closed() {
    let program = branch_mix_kernel_program();
    let verified = verify_corevm0_program(&program).expect("program must verify");

    assert!(matches!(
        evaluate_corevm0(verified, vec![], 100),
        Err(CoreVmExecutionError::ArgumentArity {
            expected: 2,
            actual: 0,
        })
    ));
    assert!(matches!(
        evaluate_corevm0(
            verified,
            vec![CoreVmValue::I64(0), CoreVmValue::I64(1)],
            100,
        ),
        Err(CoreVmExecutionError::ArgumentType {
            index: 0,
            expected: CoreVmType::ArrayF64,
            actual: CoreVmType::I64,
        })
    ));
    assert!(matches!(
        evaluate_corevm0(
            verified,
            vec![CoreVmValue::array_f64(vec![1.0]), CoreVmValue::I64(1)],
            1,
        ),
        Err(CoreVmExecutionError::StepBudgetExceeded { limit: 1, pc: 1 })
    ));
}

#[test]
fn program_hash_covers_instruction_order_immediates_layout_and_numeric_bits() {
    let baseline = branch_mix_kernel_program();
    let baseline_hash = corevm0_program_hash(&baseline).expect("baseline must hash");
    let mut mutations = Vec::new();

    let mut value = baseline.clone();
    value.instructions.swap(0, 2);
    mutations.push(value);
    let mut value = baseline.clone();
    value.instructions[22] = I::ConstI64(18);
    mutations.push(value);
    let mut value = baseline.clone();
    value.locals.swap(0, 1);
    mutations.push(value);
    let mut value = baseline.clone();
    value.max_stack += 1;
    mutations.push(value);
    let mut value = baseline;
    value.instructions[2] = I::ConstF64(-0.0);
    mutations.push(value);

    for mutation in mutations {
        assert_ne!(
            corevm0_program_hash(&mutation).expect("mutation must hash"),
            baseline_hash
        );
    }
}

#[test]
fn verifier_rejects_control_stack_local_and_reachability_mutations() {
    let baseline = branch_mix_kernel_program();

    let mut bad_target = baseline.clone();
    bad_target.instructions[10] = I::Jump(999);
    assert_code(&bad_target, CoreVmVerificationCode::InvalidBranchTarget);

    let mut bad_stack = baseline.clone();
    bad_stack.instructions[23] = I::AddF64;
    assert_code(&bad_stack, CoreVmVerificationCode::StackTypeMismatch);

    let mut uninitialized = baseline.clone();
    uninitialized.instructions[0] = I::LoadLocal(4);
    assert_code(&uninitialized, CoreVmVerificationCode::LocalUninitialized);

    let mut unreachable = baseline.clone();
    unreachable.instructions[0] = I::Jump(2);
    assert_code(&unreachable, CoreVmVerificationCode::UnreachableInstruction);

    let mut bad_max = baseline;
    bad_max.max_stack = 4;
    assert_code(&bad_max, CoreVmVerificationCode::MaxStackMismatch);
}

#[test]
fn verifier_rejects_incompatible_stack_shapes_at_cfg_joins() {
    let program = CoreVmProgram {
        schema_version: COREVM0_SCHEMA_VERSION,
        arguments: vec![],
        locals: vec![],
        max_stack: 1,
        instructions: vec![
            I::ConstI64(0),
            I::ConstI64(1),
            I::CmpLtI64,
            I::JumpIfFalse(6),
            I::ConstI64(1),
            I::Jump(7),
            I::ConstF64(1.0),
            I::ReturnF64,
        ],
    };
    assert_code(&program, CoreVmVerificationCode::StackJoinMismatch);
}

fn assert_code(program: &CoreVmProgram, expected: CoreVmVerificationCode) {
    let errors = verify_corevm0_program(program).expect_err("program mutation must fail closed");
    assert!(
        errors.0.iter().any(|error| error.code == expected),
        "expected {expected:?}, found {errors:?}"
    );
}
