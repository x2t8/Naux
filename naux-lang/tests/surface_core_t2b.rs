use naux::ast::{Expr, ExprKind, Param, Stmt, TypeAnnotation};
use naux::core::{evaluate, EvaluationBudget, EvaluationOutcome, FunctionId, RValue, Term};
use naux::elaboration::{
    bind_surface_inputs, elaborate_surface_t2b, normalize_core_scalar, normalize_surface_scalar,
    ElaborationBudget, ElaborationCode, NormalizedScalar, SurfaceElaborationProfile, SurfaceInput,
    SurfaceScalarType, SurfaceScalarValue, T2A_MAX_CORE_NODES, T2A_MAX_SOURCE_STEPS,
    T2B_MAX_FUNCTIONS, T2B_MAX_PARAMETERS,
};
use naux::runtime::eval_script_with_bindings;
use naux::{lexer, parser};

fn parse(source: &str) -> Vec<Stmt> {
    let tokens = lexer::lex(source).expect("T2B source should lex");
    parser::parse_script(&tokens).expect("T2B source should parse")
}

fn input(name: &str, ty: SurfaceScalarType) -> SurfaceInput {
    SurfaceInput {
        name: name.to_owned(),
        ty,
    }
}

fn budget() -> ElaborationBudget {
    ElaborationBudget::new(T2A_MAX_SOURCE_STEPS, T2A_MAX_CORE_NODES)
}

fn assert_parity(
    statements: &[Stmt],
    report: &naux::elaboration::ElaborationReport,
    result_name: &str,
    values: &[SurfaceScalarValue],
) -> NormalizedScalar {
    let bound = bind_surface_inputs(report, values).expect("typed inputs should bind");
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

    let evaluation = evaluate(
        &report.artifact,
        bound.core_arguments,
        EvaluationBudget::new(10_000, 64),
    )
    .expect("verified T2B Core should evaluate");
    let EvaluationOutcome::Return(core_result) = evaluation.outcome else {
        panic!("pure T2B program returned an error")
    };
    let core_normalized =
        normalize_core_scalar(&core_result).expect("Core result should be scalar");
    assert_eq!(surface_normalized, core_normalized);
    surface_normalized
}

fn call_counts(term: &Term) -> (usize, usize) {
    match term {
        Term::Let { value, next, .. } => {
            let (calls, tails) = call_counts(next);
            (
                calls + usize::from(matches!(value, RValue::Call { .. })),
                tails,
            )
        }
        Term::If {
            then_term,
            else_term,
            ..
        } => {
            let then_counts = call_counts(then_term);
            let else_counts = call_counts(else_term);
            (then_counts.0 + else_counts.0, then_counts.1 + else_counts.1)
        }
        Term::Case { arms, .. } => arms
            .iter()
            .map(|arm| call_counts(&arm.body))
            .fold((0, 0), |left, right| (left.0 + right.0, left.1 + right.1)),
        Term::TailCall { .. } => (0, 1),
        Term::Return(_) => (0, 0),
        Term::Region { body, .. } => call_counts(body),
        Term::Handle { clauses, body, .. } => clauses
            .iter()
            .map(|clause| call_counts(&clause.body))
            .chain(std::iter::once(call_counts(body)))
            .fold((0, 0), |left, right| (left.0 + right.0, left.1 + right.1)),
    }
}

#[test]
fn annotated_direct_calls_branches_and_tail_calls_match_surface() {
    let statements = parse(
        r#"
        ~ fn add($left: F64, $right: F64) -> F64
            ^ $left + $right
        ~ end

        ~ fn adjust($x: F64, $flag: Bool, $delta: F64) -> F64
            ~ if $flag
                $work = add($x, $delta)
            ~ else
                $work = $x - $delta
            ~ end
            ^ add($work, 0.5)
        ~ end

        $result = adjust($x, $flag, $delta)
        "#,
    );
    let inputs = vec![
        input("x", SurfaceScalarType::F64),
        input("flag", SurfaceScalarType::Bool),
        input("delta", SurfaceScalarType::F64),
    ];
    let report = elaborate_surface_t2b(&statements, &inputs, "result", budget())
        .expect("annotated direct functions should elaborate");

    assert_eq!(report.profile, SurfaceElaborationProfile::T2B);
    assert_eq!(
        report
            .artifact
            .program
            .functions
            .iter()
            .map(|function| function.id.0)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(
        report
            .functions
            .iter()
            .map(|signature| signature.name.as_str())
            .collect::<Vec<_>>(),
        vec!["add", "adjust"]
    );
    for function in &report.artifact.program.functions {
        assert!(function.effects.effects.is_empty());
        assert!(function.region_parameters.is_empty());
        assert_eq!(
            function
                .parameters
                .iter()
                .map(|parameter| parameter.local.0)
                .collect::<Vec<_>>(),
            (0..u32::try_from(function.parameters.len()).unwrap()).collect::<Vec<_>>()
        );
    }
    let adjust = &report.artifact.program.functions[2];
    let (ordinary_calls, tail_calls) = call_counts(&adjust.body);
    assert!(ordinary_calls >= 1);
    assert_eq!(tail_calls, 2);

    assert_eq!(
        assert_parity(
            &statements,
            &report,
            "result",
            &[
                SurfaceScalarValue::F64(10.0),
                SurfaceScalarValue::Bool(true),
                SurfaceScalarValue::F64(2.0),
            ],
        ),
        NormalizedScalar::F64Bits(12.5f64.to_bits())
    );
    assert_eq!(
        assert_parity(
            &statements,
            &report,
            "result",
            &[
                SurfaceScalarValue::F64(10.0),
                SurfaceScalarValue::Bool(false),
                SurfaceScalarValue::F64(2.0),
            ],
        ),
        NormalizedScalar::F64Bits(8.5f64.to_bits())
    );
}

#[test]
fn forward_and_nested_calls_preserve_left_to_right_anf_order() {
    let statements = parse(
        r#"
        ~ fn outer($x: F64, $y: F64) -> F64
            ^ combine(add($x, 0.25), add($y, 0.5))
        ~ end

        ~ fn add($x: F64, $y: F64) -> F64
            ^ $x + $y
        ~ end

        ~ fn combine($x: F64, $y: F64) -> F64
            ^ $x - $y
        ~ end

        $result = outer($left, $right)
        "#,
    );
    let inputs = vec![
        input("left", SurfaceScalarType::F64),
        input("right", SurfaceScalarType::F64),
    ];
    let report = elaborate_surface_t2b(&statements, &inputs, "result", budget()).unwrap();
    let outer = &report.artifact.program.functions[1];
    assert_eq!(call_counts(&outer.body), (2, 1));
    assert_eq!(
        assert_parity(
            &statements,
            &report,
            "result",
            &[SurfaceScalarValue::F64(8.0), SurfaceScalarValue::F64(3.0),],
        ),
        NormalizedScalar::F64Bits(4.75f64.to_bits())
    );
}

#[test]
fn finite_recursive_and_mutually_recursive_graphs_match_surface() {
    let direct = parse(
        r#"
        ~ fn once($again: Bool, $x: F64) -> F64
            ~ if $again
                $result = once(false, $x)
            ~ else
                $result = $x + 0.25
            ~ end
            ^ $result
        ~ end
        $result = once($again, $x)
        "#,
    );
    let inputs = vec![
        input("again", SurfaceScalarType::Bool),
        input("x", SurfaceScalarType::F64),
    ];
    let report = elaborate_surface_t2b(&direct, &inputs, "result", budget()).unwrap();
    assert_eq!(
        assert_parity(
            &direct,
            &report,
            "result",
            &[SurfaceScalarValue::Bool(true), SurfaceScalarValue::F64(2.0),],
        ),
        NormalizedScalar::F64Bits(2.25f64.to_bits())
    );

    let mutual = parse(
        r#"
        ~ fn first($again: Bool, $x: F64) -> F64
            ~ if $again
                $result = second(false, $x)
            ~ else
                $result = $x
            ~ end
            ^ $result
        ~ end
        ~ fn second($again: Bool, $x: F64) -> F64
            ~ if $again
                $result = first(false, $x)
            ~ else
                $result = $x + 1.5
            ~ end
            ^ $result
        ~ end
        $result = first(true, $x)
        "#,
    );
    let mutual_report = elaborate_surface_t2b(
        &mutual,
        &[input("x", SurfaceScalarType::F64)],
        "result",
        budget(),
    )
    .unwrap();
    assert_eq!(
        assert_parity(
            &mutual,
            &mutual_report,
            "result",
            &[SurfaceScalarValue::F64(4.0)],
        ),
        NormalizedScalar::F64Bits(5.5f64.to_bits())
    );
}

#[test]
fn scalar_i64_and_bool_signatures_are_exact_passthroughs() {
    let statements = parse(
        r#"
        ~ fn keep_i64($x: I64) -> I64
            ^ $x
        ~ end
        ~ fn keep_bool($x: Bool) -> Bool
            ^ $x
        ~ end
        $number = keep_i64($n)
        $result = keep_bool($flag)
        "#,
    );
    let inputs = vec![
        input("n", SurfaceScalarType::I64),
        input("flag", SurfaceScalarType::Bool),
    ];
    let report = elaborate_surface_t2b(&statements, &inputs, "result", budget()).unwrap();
    assert_eq!(
        assert_parity(
            &statements,
            &report,
            "result",
            &[
                SurfaceScalarValue::I64(i64::MIN),
                SurfaceScalarValue::Bool(true),
            ],
        ),
        NormalizedScalar::Bool(true)
    );
}

#[test]
fn signatures_fail_closed_without_inference_or_coercion() {
    let cases = [
        (
            r#"
            ~ fn bad($x) -> F64
                ^ $x
            ~ end
            $result = bad($x)
            "#,
            ElaborationCode::InvalidSignature,
        ),
        (
            r#"
            ~ fn bad($x: F64)
                ^ $x
            ~ end
            $result = bad($x)
            "#,
            ElaborationCode::InvalidSignature,
        ),
        (
            r#"
            ~ fn bad($x: Num) -> Num
                ^ $x
            ~ end
            $result = bad($x)
            "#,
            ElaborationCode::InvalidSignature,
        ),
        (
            r#"
            ~ fn bad($x: Any) -> F64
                ^ $x
            ~ end
            $result = bad($x)
            "#,
            ElaborationCode::InvalidSignature,
        ),
        (
            r#"
            ~ fn bad($x: F64, $x: F64) -> F64
                ^ $x
            ~ end
            $result = bad($x, $x)
            "#,
            ElaborationCode::DuplicateParameter,
        ),
    ];
    for (source, expected) in cases {
        let error = elaborate_surface_t2b(
            &parse(source),
            &[input("x", SurfaceScalarType::F64)],
            "result",
            budget(),
        )
        .expect_err("invalid signature must not produce Core");
        assert_eq!(error.code, expected, "source: {source}");
    }
}

#[test]
fn calls_and_returns_require_exact_declared_types() {
    let cases = [
        (
            r#"
            ~ fn one($x: F64) -> F64
                ^ $x
            ~ end
            $result = one()
            "#,
            ElaborationCode::InvalidCall,
        ),
        (
            r#"
            ~ fn one($x: F64) -> F64
                ^ $x
            ~ end
            $result = one(1)
            "#,
            ElaborationCode::TypeMismatch,
        ),
        (
            r#"
            ~ fn wrong($x: F64) -> Bool
                ^ $x
            ~ end
            $result = wrong($x)
            "#,
            ElaborationCode::TypeMismatch,
        ),
        (
            r#"
            ~ fn bad($x: I64) -> I64
                ^ $x + 1
            ~ end
            $result = bad($x)
            "#,
            ElaborationCode::TypeMismatch,
        ),
        (
            r#"
            ~ fn bad($x: F64) -> F64
                ^ len($x)
            ~ end
            $result = bad($x)
            "#,
            ElaborationCode::InvalidCall,
        ),
    ];
    for (source, expected) in cases {
        let error = elaborate_surface_t2b(
            &parse(source),
            &[
                input("x", SurfaceScalarType::F64),
                input("n", SurfaceScalarType::I64),
            ],
            "result",
            budget(),
        )
        .expect_err("invalid call or return must fail closed");
        assert_eq!(error.code, expected, "source: {source}");
    }
}

#[test]
fn functions_are_closed_and_return_shape_is_conservative() {
    let capture = parse(
        r#"
        ~ fn capture($x: F64) -> F64
            ^ $x + $global
        ~ end
        $global = 1.5
        $result = capture($x)
        "#,
    );
    assert_eq!(
        elaborate_surface_t2b(
            &capture,
            &[input("x", SurfaceScalarType::F64)],
            "result",
            budget(),
        )
        .expect_err("implicit capture must not become a Core closure")
        .code,
        ElaborationCode::UnboundVariable
    );

    let cases = [
        (
            r#"
            ~ fn missing($x: F64) -> F64
                $work = $x
            ~ end
            $result = missing($x)
            "#,
            ElaborationCode::MissingReturn,
        ),
        (
            r#"
            ~ fn empty($x: F64) -> F64
                ^
            ~ end
            $result = empty($x)
            "#,
            ElaborationCode::MissingReturn,
        ),
        (
            r#"
            ~ fn early($x: F64) -> F64
                ^ $x
                ^ $x
            ~ end
            $result = early($x)
            "#,
            ElaborationCode::UnsupportedStatement,
        ),
        (
            r#"
            ~ fn nested($flag: Bool, $x: F64) -> F64
                ~ if $flag
                    ^ $x
                ~ else
                    $work = $x
                ~ end
                ^ $work
            ~ end
            $result = nested($flag, $x)
            "#,
            ElaborationCode::UnsupportedStatement,
        ),
    ];
    for (source, expected) in cases {
        let error = elaborate_surface_t2b(
            &parse(source),
            &[
                input("flag", SurfaceScalarType::Bool),
                input("x", SurfaceScalarType::F64),
            ],
            "result",
            budget(),
        )
        .expect_err("unsupported return shape must fail");
        assert_eq!(error.code, expected, "source: {source}");
    }
}

#[test]
fn function_declarations_must_be_a_unique_top_level_prefix() {
    let misplaced = parse(
        r#"
        $x = 1.5
        ~ fn later($x: F64) -> F64
            ^ $x
        ~ end
        $result = later($x)
        "#,
    );
    assert_eq!(
        elaborate_surface_t2b(&misplaced, &[], "result", budget())
            .expect_err("declaration after entry code must fail")
            .code,
        ElaborationCode::InvalidSourceShape
    );

    let duplicate = parse(
        r#"
        ~ fn same($x: F64) -> F64
            ^ $x
        ~ end
        ~ fn same($x: F64) -> F64
            ^ $x
        ~ end
        $result = same($x)
        "#,
    );
    assert_eq!(
        elaborate_surface_t2b(
            &duplicate,
            &[input("x", SurfaceScalarType::F64)],
            "result",
            budget(),
        )
        .expect_err("duplicate function must fail")
        .code,
        ElaborationCode::DuplicateFunction
    );
}

#[test]
fn tail_recursion_is_stopped_by_the_core_step_budget() {
    let statements = parse(
        r#"
        ~ fn forever($x: F64) -> F64
            ^ forever($x)
        ~ end
        $result = forever($x)
        "#,
    );
    let report = elaborate_surface_t2b(
        &statements,
        &[input("x", SurfaceScalarType::F64)],
        "result",
        budget(),
    )
    .unwrap();
    assert_eq!(
        call_counts(&report.artifact.program.functions[1].body),
        (0, 1)
    );
    let bound = bind_surface_inputs(&report, &[SurfaceScalarValue::F64(1.0)]).unwrap();
    let error = evaluate(
        &report.artifact,
        bound.core_arguments,
        EvaluationBudget::new(16, 1),
    )
    .expect_err("infinite proper tail recursion must exhaust the step budget");
    assert!(matches!(
        error,
        naux::core::ExecutionError::StepBudgetExceeded { limit: 16 }
    ));
}

#[test]
fn elaboration_is_alpha_stable_and_budget_exact() {
    let first = parse(
        r#"
        ~ fn add($x: F64, $y: F64) -> F64
            ^ $x + $y
        ~ end
        $result = add($left, $right)
        "#,
    );
    let inputs = vec![
        input("left", SurfaceScalarType::F64),
        input("right", SurfaceScalarType::F64),
    ];
    let baseline = elaborate_surface_t2b(&first, &inputs, "result", budget()).unwrap();
    let exact = elaborate_surface_t2b(
        &first,
        &inputs,
        "result",
        ElaborationBudget::new(baseline.source_steps, baseline.core_nodes),
    )
    .unwrap();
    assert_eq!(
        baseline.artifact.semantic_hash,
        exact.artifact.semantic_hash
    );

    let renamed = parse(
        r#"
        ~ fn sum($a: F64, $b: F64) -> F64
            ^ $a + $b
        ~ end
        $out = sum($p, $q)
        "#,
    );
    let renamed_report = elaborate_surface_t2b(
        &renamed,
        &[
            input("p", SurfaceScalarType::F64),
            input("q", SurfaceScalarType::F64),
        ],
        "out",
        budget(),
    )
    .unwrap();
    assert_eq!(
        baseline.artifact.semantic_hash,
        renamed_report.artifact.semantic_hash
    );

    assert_eq!(
        elaborate_surface_t2b(
            &first,
            &inputs,
            "result",
            ElaborationBudget::new(baseline.source_steps - 1, baseline.core_nodes),
        )
        .expect_err("source budget minus one must fail")
        .code,
        ElaborationCode::SourceBudgetExceeded
    );
    assert_eq!(
        elaborate_surface_t2b(
            &first,
            &inputs,
            "result",
            ElaborationBudget::new(baseline.source_steps, baseline.core_nodes - 1),
        )
        .expect_err("Core budget minus one must fail")
        .code,
        ElaborationCode::CoreBudgetExceeded
    );
}

#[test]
fn function_and_parameter_hard_caps_fail_before_lowering() {
    let annotation = || TypeAnnotation {
        base: "F64".to_owned(),
        predicate: None,
    };
    let function = |index: usize, params: Vec<Param>| Stmt::FnDef {
        name: format!("f{index}"),
        params,
        body: vec![Stmt::Return {
            value: Some(Expr::new(ExprKind::Number(0.5), None)),
            span: None,
        }],
        return_type: Some(annotation()),
        span: None,
    };

    let too_many_functions = (0..=T2B_MAX_FUNCTIONS)
        .map(|index| function(index, vec![]))
        .collect::<Vec<_>>();
    assert_eq!(
        elaborate_surface_t2b(&too_many_functions, &[], "result", budget())
            .expect_err("function cap must fail")
            .code,
        ElaborationCode::StructuralLimit
    );

    let too_many_parameters = (0..=T2B_MAX_PARAMETERS)
        .map(|index| Param {
            name: format!("p{index}"),
            annotation: Some(annotation()),
        })
        .collect();
    assert_eq!(
        elaborate_surface_t2b(&[function(0, too_many_parameters)], &[], "result", budget(),)
            .expect_err("parameter cap must fail")
            .code,
        ElaborationCode::StructuralLimit
    );
}

#[test]
fn semantic_hash_has_a_t2b_stability_vector() {
    let statements = parse(
        r#"
        ~ fn identity($x: F64) -> F64
            ^ $x
        ~ end
        $result = identity($input)
        "#,
    );
    let report = elaborate_surface_t2b(
        &statements,
        &[input("input", SurfaceScalarType::F64)],
        "result",
        budget(),
    )
    .unwrap();

    assert_eq!(report.source_steps, 7);
    assert_eq!(report.core_nodes, 4);
    assert_eq!(
        report.artifact.semantic_hash.to_hex(),
        "63b41e503505c86ce409c0c61ea57dfb1d2afe91d672e0061992fd4b8c2b5209"
    );
    assert_eq!(report.artifact.program.entry, FunctionId(0));
}
