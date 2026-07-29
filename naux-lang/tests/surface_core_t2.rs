use naux::ast::{Expr, ExprKind, Stmt};
use naux::core::{evaluate, CoreValue, EvaluationBudget, EvaluationOutcome, Type};
use naux::elaboration::{
    bind_surface_t2a_inputs, elaborate_surface_t2a, normalize_core_scalar,
    normalize_surface_scalar, ElaborationBudget, ElaborationCode, InputBindingError,
    NormalizedScalar, ScalarObservationError, SurfaceInput, SurfaceScalarType, SurfaceScalarValue,
    T2A_MAX_CORE_NODES, T2A_MAX_INPUTS, T2A_MAX_SOURCE_STEPS,
};
use naux::runtime::{eval_script_with_bindings, Value};
use naux::{lexer, parser};

fn parse(source: &str) -> Vec<Stmt> {
    let tokens = lexer::lex(source).expect("T2 test source should lex");
    parser::parse_script(&tokens).expect("T2 test source should parse")
}

fn input(name: &str, ty: SurfaceScalarType) -> SurfaceInput {
    SurfaceInput {
        name: name.to_owned(),
        ty,
    }
}

fn generous_budget() -> ElaborationBudget {
    ElaborationBudget::new(T2A_MAX_SOURCE_STEPS, T2A_MAX_CORE_NODES)
}

fn assert_parity(
    statements: &[Stmt],
    report: &naux::elaboration::ElaborationReport,
    result_name: &str,
    values: &[SurfaceScalarValue],
) -> NormalizedScalar {
    let bound = bind_surface_t2a_inputs(report, values).expect("typed inputs should bind");
    let (surface_env, _events, surface_errors) =
        eval_script_with_bindings(statements, &bound.surface_bindings);
    assert!(
        surface_errors.is_empty(),
        "Surface oracle failed: {surface_errors:?}"
    );
    let surface_result = surface_env
        .get(result_name)
        .expect("Surface result should exist");
    let surface_normalized =
        normalize_surface_scalar(&surface_result).expect("Surface result should be scalar");

    let core_evaluation = evaluate(
        &report.artifact,
        bound.core_arguments,
        EvaluationBudget::new(10_000, 64),
    )
    .expect("verified Core should evaluate");
    let EvaluationOutcome::Return(core_result) = core_evaluation.outcome else {
        panic!("pure T2A Core returned an error")
    };
    let core_normalized =
        normalize_core_scalar(&core_result).expect("Core result should be scalar");
    assert_eq!(surface_normalized, core_normalized);
    surface_normalized
}

#[test]
fn dynamic_branch_and_duplicated_continuation_match_surface() {
    let statements = parse(
        r#"
        $base = $x + $offset
        ~ if $flag
            $result = $base + $delta
        ~ else
            $result = $base - $delta
        ~ end
        $result = $result + $tail
        "#,
    );
    let inputs = vec![
        input("x", SurfaceScalarType::F64),
        input("offset", SurfaceScalarType::F64),
        input("flag", SurfaceScalarType::Bool),
        input("delta", SurfaceScalarType::F64),
        input("tail", SurfaceScalarType::F64),
    ];
    let report = elaborate_surface_t2a(&statements, &inputs, "result", generous_budget())
        .expect("admitted Surface should elaborate");

    assert_eq!(report.result_type, SurfaceScalarType::F64);
    assert_eq!(report.artifact.program.functions.len(), 1);
    let function = &report.artifact.program.functions[0];
    assert_eq!(function.id.0, 0);
    assert!(function.effects.effects.is_empty());
    assert!(function.region_parameters.is_empty());
    assert_eq!(
        function
            .parameters
            .iter()
            .map(|parameter| parameter.local.0)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );

    assert_eq!(
        assert_parity(
            &statements,
            &report,
            "result",
            &[
                SurfaceScalarValue::F64(10.0),
                SurfaceScalarValue::F64(0.25),
                SurfaceScalarValue::Bool(true),
                SurfaceScalarValue::F64(3.5),
                SurfaceScalarValue::F64(0.125),
            ],
        ),
        NormalizedScalar::F64Bits(13.875f64.to_bits())
    );
    assert_eq!(
        assert_parity(
            &statements,
            &report,
            "result",
            &[
                SurfaceScalarValue::F64(10.0),
                SurfaceScalarValue::F64(0.25),
                SurfaceScalarValue::Bool(false),
                SurfaceScalarValue::F64(3.5),
                SurfaceScalarValue::F64(0.125),
            ],
        ),
        NormalizedScalar::F64Bits(6.875f64.to_bits())
    );
}

#[test]
fn f64_edge_results_use_canonical_bit_parity() {
    let identity = parse("$result = $x\n");
    let identity_report = elaborate_surface_t2a(
        &identity,
        &[input("x", SurfaceScalarType::F64)],
        "result",
        generous_budget(),
    )
    .unwrap();
    for value in [
        -0.0,
        f64::MIN_POSITIVE / 2.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::from_bits(0x7ff8_0000_0000_0042),
    ] {
        let normalized = assert_parity(
            &identity,
            &identity_report,
            "result",
            &[SurfaceScalarValue::F64(value)],
        );
        if value.is_nan() {
            assert_eq!(normalized, NormalizedScalar::F64Bits(0x7ff8_0000_0000_0000));
        } else {
            assert_eq!(normalized, NormalizedScalar::F64Bits(value.to_bits()));
        }
    }

    let add = parse("$result = $x + $y\n");
    let add_report = elaborate_surface_t2a(
        &add,
        &[
            input("x", SurfaceScalarType::F64),
            input("y", SurfaceScalarType::F64),
        ],
        "result",
        generous_budget(),
    )
    .unwrap();
    assert_eq!(
        assert_parity(
            &add,
            &add_report,
            "result",
            &[
                SurfaceScalarValue::F64(f64::MAX),
                SurfaceScalarValue::F64(f64::MAX),
            ],
        ),
        NormalizedScalar::F64Bits(f64::INFINITY.to_bits())
    );

    let subtract = parse("$result = $x - $y\n");
    let subtract_report = elaborate_surface_t2a(
        &subtract,
        &[
            input("x", SurfaceScalarType::F64),
            input("y", SurfaceScalarType::F64),
        ],
        "result",
        generous_budget(),
    )
    .unwrap();
    assert_eq!(
        assert_parity(
            &subtract,
            &subtract_report,
            "result",
            &[
                SurfaceScalarValue::F64(f64::INFINITY),
                SurfaceScalarValue::F64(f64::INFINITY),
            ],
        ),
        NormalizedScalar::F64Bits(0x7ff8_0000_0000_0000)
    );
}

#[test]
fn numeric_literal_classification_matches_bridge_boundary() {
    let cases = [
        (-0.0, SurfaceScalarType::I64, NormalizedScalar::I64(0)),
        (
            f64::EPSILON / 2.0,
            SurfaceScalarType::I64,
            NormalizedScalar::I64(0),
        ),
        (
            f64::EPSILON,
            SurfaceScalarType::F64,
            NormalizedScalar::F64Bits(f64::EPSILON.to_bits()),
        ),
        (
            1.0e20,
            SurfaceScalarType::I64,
            NormalizedScalar::I64(i64::MAX),
        ),
        (
            -1.0e20,
            SurfaceScalarType::I64,
            NormalizedScalar::I64(i64::MIN),
        ),
        (
            f64::INFINITY,
            SurfaceScalarType::F64,
            NormalizedScalar::F64Bits(f64::INFINITY.to_bits()),
        ),
    ];

    for (value, expected_type, expected_value) in cases {
        let statements = vec![Stmt::Assign {
            name: "result".to_owned(),
            annotation: None,
            expr: Expr::new(ExprKind::Number(value), None),
            span: None,
        }];
        let report = elaborate_surface_t2a(&statements, &[], "result", generous_budget()).unwrap();
        assert_eq!(report.result_type, expected_type);
        assert_eq!(
            assert_parity(&statements, &report, "result", &[]),
            expected_value
        );
    }

    let nan_statements = vec![Stmt::Assign {
        name: "result".to_owned(),
        annotation: None,
        expr: Expr::new(
            ExprKind::Number(f64::from_bits(0x7ff8_0000_0000_0001)),
            None,
        ),
        span: None,
    }];
    let nan_report =
        elaborate_surface_t2a(&nan_statements, &[], "result", generous_budget()).unwrap();
    assert_eq!(nan_report.result_type, SurfaceScalarType::F64);
    assert_eq!(
        assert_parity(&nan_statements, &nan_report, "result", &[]),
        NormalizedScalar::F64Bits(0x7ff8_0000_0000_0000)
    );
}

#[test]
fn i64_and_bool_passthrough_are_exact() {
    let i64_program = parse("$result = $x\n");
    let i64_report = elaborate_surface_t2a(
        &i64_program,
        &[input("x", SurfaceScalarType::I64)],
        "result",
        generous_budget(),
    )
    .unwrap();
    assert_eq!(
        assert_parity(
            &i64_program,
            &i64_report,
            "result",
            &[SurfaceScalarValue::I64(i64::MIN)],
        ),
        NormalizedScalar::I64(i64::MIN)
    );

    let bool_program = parse("$result = $flag\n");
    let bool_report = elaborate_surface_t2a(
        &bool_program,
        &[input("flag", SurfaceScalarType::Bool)],
        "result",
        generous_budget(),
    )
    .unwrap();
    assert_eq!(
        assert_parity(
            &bool_program,
            &bool_report,
            "result",
            &[SurfaceScalarValue::Bool(true)],
        ),
        NormalizedScalar::Bool(true)
    );
}

#[test]
fn elaboration_is_deterministic_across_sufficient_budgets_and_alpha_names() {
    let first = parse("$tmp = $left + $right\n$result = $tmp\n");
    let first_inputs = vec![
        input("left", SurfaceScalarType::F64),
        input("right", SurfaceScalarType::F64),
    ];
    let baseline = elaborate_surface_t2a(&first, &first_inputs, "result", generous_budget())
        .expect("baseline should elaborate");
    let exact = elaborate_surface_t2a(
        &first,
        &first_inputs,
        "result",
        ElaborationBudget::new(baseline.source_steps, baseline.core_nodes),
    )
    .expect("exact measured budgets should pass");
    assert_eq!(
        baseline.artifact.semantic_hash,
        exact.artifact.semantic_hash
    );

    let renamed = parse("$work = $a + $b\n$out = $work\n");
    let renamed_report = elaborate_surface_t2a(
        &renamed,
        &[
            input("a", SurfaceScalarType::F64),
            input("b", SurfaceScalarType::F64),
        ],
        "out",
        generous_budget(),
    )
    .unwrap();
    assert_eq!(
        baseline.artifact.semantic_hash,
        renamed_report.artifact.semantic_hash
    );
}

#[test]
fn input_binding_is_exact_and_has_no_numeric_coercion() {
    let statements = parse("$result = $x\n");
    let report = elaborate_surface_t2a(
        &statements,
        &[input("x", SurfaceScalarType::F64)],
        "result",
        generous_budget(),
    )
    .unwrap();

    assert!(matches!(
        bind_surface_t2a_inputs(&report, &[]),
        Err(InputBindingError::Arity {
            expected: 1,
            actual: 0
        })
    ));
    assert!(matches!(
        bind_surface_t2a_inputs(&report, &[SurfaceScalarValue::I64(1)]),
        Err(InputBindingError::Type {
            expected: SurfaceScalarType::F64,
            actual: SurfaceScalarType::I64,
            ..
        })
    ));
    let bound = bind_surface_t2a_inputs(&report, &[SurfaceScalarValue::F64(1.0)]).unwrap();
    assert!(matches!(bound.surface_bindings[0].1, Value::Float(1.0)));
    assert!(matches!(bound.core_arguments[0], CoreValue::F64(1.0)));
    assert_eq!(
        normalize_surface_scalar(&Value::Null),
        Err(ScalarObservationError::NonScalarSurfaceValue)
    );
    assert_eq!(
        normalize_core_scalar(&CoreValue::Unit),
        Err(ScalarObservationError::NonScalarCoreValue)
    );
}

#[test]
fn unsupported_and_unsound_surface_constructs_fail_closed() {
    let cases = [
        ("$result = 1 + 2\n", ElaborationCode::TypeMismatch),
        ("$result = 1.5 + 2\n", ElaborationCode::TypeMismatch),
        ("$result = -1.5\n", ElaborationCode::UnsupportedExpression),
        (
            "$result = \"text\"\n",
            ElaborationCode::UnsupportedExpression,
        ),
        (
            "$result = missing()\n",
            ElaborationCode::UnsupportedExpression,
        ),
        ("$result = $missing\n", ElaborationCode::UnboundVariable),
    ];
    for (source, expected) in cases {
        let statements = parse(source);
        let error = elaborate_surface_t2a(&statements, &[], "result", generous_budget())
            .expect_err("unsupported Surface must not return Core");
        assert_eq!(error.code, expected, "source: {source}");
    }

    let dead_branch = parse(
        r#"
        ~ if true
            $result = 1.5
        ~ else
            $result = "not admitted"
        ~ end
        "#,
    );
    assert_eq!(
        elaborate_surface_t2a(&dead_branch, &[], "result", generous_budget())
            .expect_err("dead branches are still validated")
            .code,
        ElaborationCode::UnsupportedExpression
    );

    let numeric_condition = parse(
        r#"
        ~ if $x
            $result = true
        ~ else
            $result = false
        ~ end
        "#,
    );
    assert_eq!(
        elaborate_surface_t2a(
            &numeric_condition,
            &[input("x", SurfaceScalarType::I64)],
            "result",
            generous_budget(),
        )
        .expect_err("truthy numeric conditions are outside typed T2A")
        .code,
        ElaborationCode::TypeMismatch
    );
}

#[test]
fn request_shape_results_and_reassignment_are_checked() {
    let passthrough = parse("$result = $x\n");
    assert_eq!(
        elaborate_surface_t2a(&passthrough, &[], "", generous_budget())
            .expect_err("empty result should fail")
            .code,
        ElaborationCode::InvalidRequest
    );
    assert_eq!(
        elaborate_surface_t2a(
            &passthrough,
            &[
                input("x", SurfaceScalarType::F64),
                input("x", SurfaceScalarType::F64),
            ],
            "result",
            generous_budget(),
        )
        .expect_err("duplicate input should fail")
        .code,
        ElaborationCode::DuplicateInput
    );
    assert_eq!(
        elaborate_surface_t2a(&[], &[], "result", generous_budget())
            .expect_err("missing result should fail")
            .code,
        ElaborationCode::MissingResult
    );

    let type_change = parse("$result = 1\n$result = true\n");
    assert_eq!(
        elaborate_surface_t2a(&type_change, &[], "result", generous_budget())
            .expect_err("type-changing reassignment should fail")
            .code,
        ElaborationCode::TypeMismatch
    );

    let branch_mismatch = parse(
        r#"
        ~ if $flag
            $result = 1.5
        ~ else
            $result = true
        ~ end
        "#,
    );
    assert_eq!(
        elaborate_surface_t2a(
            &branch_mismatch,
            &[input("flag", SurfaceScalarType::Bool)],
            "result",
            generous_budget(),
        )
        .expect_err("path-dependent result type should fail")
        .code,
        ElaborationCode::TypeMismatch
    );

    let result_missing_from_else = parse(
        r#"
        ~ if $flag
            $result = 1.5
        ~ else
            $other = 1.5
        ~ end
        "#,
    );
    assert_eq!(
        elaborate_surface_t2a(
            &result_missing_from_else,
            &[input("flag", SurfaceScalarType::Bool)],
            "result",
            generous_budget(),
        )
        .expect_err("the result must exist on both branch paths")
        .code,
        ElaborationCode::MissingResult
    );
}

#[test]
fn declared_and_hard_budgets_fail_before_returning_an_artifact() {
    let statements = parse("$tmp = $x + $y\n$result = $tmp\n");
    let inputs = vec![
        input("x", SurfaceScalarType::F64),
        input("y", SurfaceScalarType::F64),
    ];
    let measured = elaborate_surface_t2a(&statements, &inputs, "result", generous_budget())
        .expect("measurement elaboration should pass");
    assert!(measured.source_steps > 0);
    assert!(measured.core_nodes > 0);

    assert_eq!(
        elaborate_surface_t2a(
            &statements,
            &inputs,
            "result",
            ElaborationBudget::new(measured.source_steps - 1, measured.core_nodes),
        )
        .expect_err("source budget minus one should fail")
        .code,
        ElaborationCode::SourceBudgetExceeded
    );
    assert_eq!(
        elaborate_surface_t2a(
            &statements,
            &inputs,
            "result",
            ElaborationBudget::new(measured.source_steps, measured.core_nodes - 1),
        )
        .expect_err("Core budget minus one should fail")
        .code,
        ElaborationCode::CoreBudgetExceeded
    );
    assert_eq!(
        elaborate_surface_t2a(
            &statements,
            &inputs,
            "result",
            ElaborationBudget::new(T2A_MAX_SOURCE_STEPS + 1, T2A_MAX_CORE_NODES),
        )
        .expect_err("budget over safety cap should fail")
        .code,
        ElaborationCode::InvalidRequest
    );

    assert_eq!(
        elaborate_surface_t2a(
            &statements,
            &inputs,
            "result",
            ElaborationBudget::new(0, T2A_MAX_CORE_NODES),
        )
        .expect_err("zero source budget should fail before visiting the first statement")
        .code,
        ElaborationCode::SourceBudgetExceeded
    );
    let return_input = parse("$result = $x\n");
    assert_eq!(
        elaborate_surface_t2a(
            &return_input,
            &[input("x", SurfaceScalarType::F64)],
            "result",
            ElaborationBudget::new(T2A_MAX_SOURCE_STEPS, 0),
        )
        .expect_err("zero Core budget should fail before returning an artifact")
        .code,
        ElaborationCode::CoreBudgetExceeded
    );

    let too_many_inputs: Vec<SurfaceInput> = (0..=T2A_MAX_INPUTS)
        .map(|index| input(&format!("v{index}"), SurfaceScalarType::Bool))
        .collect();
    assert_eq!(
        elaborate_surface_t2a(&[], &too_many_inputs, "v0", generous_budget())
            .expect_err("oversized manifest should fail")
            .code,
        ElaborationCode::StructuralLimit
    );
}

#[test]
fn semantic_hash_has_a_stability_vector() {
    let statements = parse("$result = $x + $y\n");
    let report = elaborate_surface_t2a(
        &statements,
        &[
            input("x", SurfaceScalarType::F64),
            input("y", SurfaceScalarType::F64),
        ],
        "result",
        generous_budget(),
    )
    .unwrap();
    assert_eq!(report.source_steps, 4);
    assert_eq!(report.core_nodes, 3);
    assert_eq!(
        report.artifact.semantic_hash.to_hex(),
        "52ee627ea5c1685d00d88b6bcbc0947a4c44ff539ad6685349135f67b4d0b468"
    );
    assert_eq!(report.artifact.program.functions[0].result, Type::F64);
}
