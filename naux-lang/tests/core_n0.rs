use naux::core::{
    evaluate, semantic_bytes, verify, CaseArm, ConstructorType, CoreArtifact, CoreProfile,
    CoreValue, Effect, EffectEvent, EffectRow, ErrorKind, EvaluationBudget, EvaluationOutcome,
    Function, FunctionId, LocalId, Mutability, NumericMode, Operand, Parameter, Primitive, Program,
    RValue, RegionId, SchemaVersion, SemanticHash, SumType, Term, Type, VerificationCode,
};

fn program(entry: u32, functions: Vec<Function>) -> Program {
    Program {
        schema: SchemaVersion::core_n0(),
        profile: CoreProfile::P1V0,
        entry: FunctionId(entry),
        functions,
    }
}

fn seal(program: Program) -> CoreArtifact {
    CoreArtifact::seal(program).expect("test program should encode")
}

fn budget() -> EvaluationBudget {
    EvaluationBudget::new(10_000, 64)
}

fn return_f64(value: f64) -> Program {
    program(
        0,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::F64,
            body: Term::Return(Operand::F64(value)),
        }],
    )
}

#[test]
fn verified_checked_arithmetic_evaluates() {
    let artifact = seal(program(
        0,
        vec![Function {
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
            effects: EffectRow::canonical(vec![Effect::Error(ErrorKind::Overflow)]),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(2),
                ty: Type::I64,
                value: RValue::Primitive {
                    operation: Primitive::I64Add(NumericMode::Checked),
                    arguments: vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(1))],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
            },
        }],
    ));

    let verified = verify(&artifact).expect("artifact should verify");
    assert_eq!(verified.semantic_hash(), artifact.semantic_hash);
    let evaluation = evaluate(
        &artifact,
        vec![CoreValue::I64(19), CoreValue::I64(23)],
        budget(),
    )
    .expect("evaluation should succeed");
    assert_eq!(
        evaluation.outcome,
        EvaluationOutcome::Return(CoreValue::I64(42))
    );
    assert!(evaluation.effect_trace.is_empty());
}

#[test]
fn verifier_rejects_hash_tampering_and_unbound_locals() {
    let mut artifact = seal(program(
        0,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Return(Operand::Local(LocalId(99))),
        }],
    ));
    artifact.semantic_hash = SemanticHash::ZERO;

    let errors = verify(&artifact).expect_err("forged artifact must fail closed");
    assert!(errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::SemanticHashMismatch));
    assert!(errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::UnboundLocal));
}

#[test]
fn checked_operations_require_a_declared_error_effect() {
    let artifact = seal(program(
        0,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(0),
                ty: Type::I64,
                value: RValue::Primitive {
                    operation: Primitive::I64Mul(NumericMode::Checked),
                    arguments: vec![Operand::I64(7), Operand::I64(6)],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
            },
        }],
    ));

    let errors = verify(&artifact).expect_err("missing effect must be rejected");
    assert!(errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::MissingEffect));
}

#[test]
fn semantic_hash_is_deterministic_and_normalizes_unobservable_nan_payloads() {
    assert_eq!(
        seal(return_f64(42.0)).semantic_hash.to_hex(),
        "4d7afe3c5d1127e7b8ce1441c21edb8322d99480ff7efbb5051e6a73d3930bcf"
    );
    let first_nan = seal(return_f64(f64::from_bits(0x7ff8_0000_0000_0001)));
    let second_nan = seal(return_f64(f64::from_bits(0xfff0_0000_0000_0042)));
    assert_eq!(first_nan.semantic_hash, second_nan.semantic_hash);
    assert_eq!(
        semantic_bytes(&first_nan.program).unwrap(),
        semantic_bytes(&second_nan.program).unwrap()
    );

    let positive_zero = seal(return_f64(0.0));
    let negative_zero = seal(return_f64(-0.0));
    assert_ne!(positive_zero.semantic_hash, negative_zero.semantic_hash);
}

#[test]
fn case_is_exhaustive_typed_and_executable() {
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
    let artifact = seal(program(
        0,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(0),
                ty: Type::Sum(option_i64.clone()),
            }],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Case {
                scrutinee: Operand::Local(LocalId(0)),
                arms: vec![
                    CaseArm {
                        constructor: 0,
                        bindings: vec![],
                        body: Term::Return(Operand::I64(0)),
                    },
                    CaseArm {
                        constructor: 1,
                        bindings: vec![LocalId(1)],
                        body: Term::Return(Operand::Local(LocalId(1))),
                    },
                ],
            },
        }],
    ));

    let evaluation = evaluate(
        &artifact,
        vec![CoreValue::Sum {
            ty: option_i64,
            constructor: 1,
            fields: vec![CoreValue::I64(37)],
        }],
        budget(),
    )
    .unwrap();
    assert_eq!(
        evaluation.outcome,
        EvaluationOutcome::Return(CoreValue::I64(37))
    );
}

#[test]
fn tail_calls_run_under_a_deterministic_step_budget() {
    let artifact = seal(program(
        0,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![],
            effects: EffectRow::pure(),
            result: Type::Unit,
            body: Term::TailCall {
                function: FunctionId(0),
                arguments: vec![],
            },
        }],
    ));

    let error = evaluate(&artifact, vec![], EvaluationBudget::new(8, 0))
        .expect_err("unbounded tail recursion must stop at the declared budget");
    assert!(matches!(
        error,
        naux::core::ExecutionError::StepBudgetExceeded { limit: 8 }
    ));
}

#[test]
fn array_bounds_is_a_typed_observable_error() {
    let array_type = Type::Array {
        region: RegionId(0),
        mutability: Mutability::Read,
        element: Box::new(Type::F64),
    };
    let artifact = seal(program(
        0,
        vec![Function {
            id: FunctionId(0),
            region_parameters: vec![RegionId(0)],
            parameters: vec![
                Parameter {
                    local: LocalId(0),
                    ty: array_type,
                },
                Parameter {
                    local: LocalId(1),
                    ty: Type::I64,
                },
            ],
            effects: EffectRow::canonical(vec![Effect::Error(ErrorKind::Bounds)]),
            result: Type::F64,
            body: Term::Let {
                binder: LocalId(2),
                ty: Type::F64,
                value: RValue::Primitive {
                    operation: Primitive::ArrayGetF64,
                    arguments: vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(1))],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(2)))),
            },
        }],
    ));

    let evaluation = evaluate(
        &artifact,
        vec![CoreValue::array_f64(vec![1.25]), CoreValue::I64(4)],
        budget(),
    )
    .unwrap();
    assert_eq!(
        evaluation.outcome,
        EvaluationOutcome::Error(ErrorKind::Bounds)
    );
    assert_eq!(
        evaluation.effect_trace,
        vec![EffectEvent::Error(ErrorKind::Bounds)]
    );
}

#[test]
fn function_order_and_profile_boundary_fail_closed() {
    let function = |id, result| Function {
        id: FunctionId(id),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::pure(),
        result,
        body: Term::Return(Operand::Unit),
    };
    let artifact = seal(program(
        1,
        vec![function(1, Type::Unit), function(0, Type::Text)],
    ));

    let errors = verify(&artifact).expect_err("non-canonical/unsupported Core must fail");
    assert!(errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::NonCanonicalOrder));
    assert!(errors
        .0
        .iter()
        .any(|error| error.code == VerificationCode::UnsupportedProfileFeature));
}

#[test]
fn overflow_is_not_host_undefined_behavior() {
    let artifact = seal(program(
        0,
        vec![Function {
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
                    arguments: vec![Operand::I64(i64::MAX), Operand::I64(1)],
                },
                next: Box::new(Term::Return(Operand::Local(LocalId(0)))),
            },
        }],
    ));

    let evaluation = evaluate(&artifact, vec![], budget()).unwrap();
    assert_eq!(
        evaluation.outcome,
        EvaluationOutcome::Error(ErrorKind::Overflow)
    );
}

#[test]
fn direct_calls_preserve_types_effects_and_errors() {
    let overflow = EffectRow::canonical(vec![Effect::Error(ErrorKind::Overflow)]);
    let artifact = seal(program(
        0,
        vec![
            Function {
                id: FunctionId(0),
                region_parameters: vec![],
                parameters: vec![Parameter {
                    local: LocalId(0),
                    ty: Type::I64,
                }],
                effects: overflow.clone(),
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
                effects: overflow,
                result: Type::I64,
                body: Term::Let {
                    binder: LocalId(1),
                    ty: Type::I64,
                    value: RValue::Primitive {
                        operation: Primitive::I64Add(NumericMode::Checked),
                        arguments: vec![Operand::Local(LocalId(0)), Operand::Local(LocalId(0))],
                    },
                    next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
                },
            },
        ],
    ));

    assert_eq!(
        evaluate(&artifact, vec![CoreValue::I64(21)], budget())
            .unwrap()
            .outcome,
        EvaluationOutcome::Return(CoreValue::I64(42))
    );
    let overflowed = evaluate(&artifact, vec![CoreValue::I64(i64::MAX)], budget()).unwrap();
    assert_eq!(
        overflowed.outcome,
        EvaluationOutcome::Error(ErrorKind::Overflow)
    );
    assert_eq!(
        overflowed.effect_trace,
        vec![EffectEvent::Error(ErrorKind::Overflow)]
    );
}

#[test]
fn core_n0_source_has_no_bridge_or_egg_import() {
    let forbidden = [
        "egg::",
        "crate::ast",
        "crate::runtime",
        "crate::vm",
        "crate::effects",
    ];
    let core_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core");
    let mut pending = vec![core_dir];
    let mut checked_files = 0;

    while let Some(directory) = pending.pop() {
        for entry in
            std::fs::read_dir(&directory).expect("Core source directory should be readable")
        {
            let path = entry.expect("Core source entry should be readable").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                checked_files += 1;
                let source = std::fs::read_to_string(&path).expect("Core source should be UTF-8");
                for pattern in forbidden {
                    assert!(
                        !source.contains(pattern),
                        "Core-N0 semantic nucleus file {} must not import bridge path {pattern}",
                        path.display()
                    );
                }
            }
        }
    }

    assert!(
        checked_files > 0,
        "Core source boundary test scanned no files"
    );
}
