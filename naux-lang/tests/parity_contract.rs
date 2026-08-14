use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use naux::ast::Stmt;
use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::runtime::env::Env;
use naux::runtime::error::{format_runtime_error_with_file, RuntimeError};
use naux::runtime::events::RuntimeEvent;
use naux::runtime::value::Value;
use naux::runtime::{eval_script, eval_script_with_base_dir};
#[cfg(all(target_arch = "x86_64", not(windows)))]
use naux::vm::compiler::compile_script;
use naux::vm::run::{run_jit, run_vm};
#[cfg(all(target_arch = "x86_64", not(windows)))]
use naux::vm::typed::TypedRunner;

fn parse(src: &str) -> Vec<Stmt> {
    let tokens = lex(src).expect("lex");
    Parser::from_tokens(&tokens).expect("parse")
}

fn run_interpreter(src: &str) -> (Env, Vec<RuntimeEvent>, Vec<RuntimeError>) {
    let ast = parse(src);
    eval_script(&ast)
}

fn run_interpreter_with_base(
    src: &str,
    base_dir: &Path,
) -> (Env, Vec<RuntimeEvent>, Vec<RuntimeError>) {
    let ast = parse(src);
    eval_script_with_base_dir(&ast, Some(base_dir))
}

fn run_vm_result(src: &str) -> Result<(Vec<RuntimeEvent>, Value), String> {
    let ast = parse(src);
    run_vm(&ast, src, "<parity>")
}

fn run_jit_result(src: &str) -> Result<(Vec<RuntimeEvent>, Value, bool), String> {
    let ast = parse(src);
    run_jit(&ast, src, "<parity>")
}

fn assert_interpreter_error_contains(src: &str, needle: &str) {
    let (_env, _events, errors) = run_interpreter(src);
    assert!(
        errors.iter().any(|err| err.message.contains(needle)),
        "expected interpreter error containing `{needle}`, got {errors:?}"
    );
}

fn assert_vm_error_contains(src: &str, needle: &str) {
    let err = run_vm_result(src).expect_err("VM should reject this program");
    assert!(
        err.contains(needle),
        "expected VM error containing `{needle}`, got {err}"
    );
}

fn assert_jit_error_contains(src: &str, needle: &str) {
    let err = run_jit_result(src).expect_err("JIT entrypoint should reject this program");
    assert!(
        err.contains(needle),
        "expected JIT error containing `{needle}`, got {err}"
    );
}

fn assert_interpreter_vm_error_first_line(src: &str, expected: &str) {
    let (_env, _events, errors) = run_interpreter(src);
    assert_eq!(
        errors.len(),
        1,
        "expected one interpreter error: {errors:?}"
    );
    let rendered = format_runtime_error_with_file(src, &errors[0], "<parity>");
    let interp_first = rendered.lines().next().unwrap_or("");

    let vm_err = run_vm_result(src).expect_err("VM should reject this program");
    let vm_first = vm_err.lines().next().unwrap_or("");

    assert_eq!(interp_first, expected);
    assert_eq!(vm_first, expected);
}

fn say_events(events: &[RuntimeEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match event {
            RuntimeEvent::Say(text) => Some(text.clone()),
            _ => None,
        })
        .collect()
}

fn assert_interpreter_vm_out(src: &str, expected: Value) {
    let (env, _events, errors) = run_interpreter(src);
    assert!(errors.is_empty(), "runtime errors: {errors:?}");
    assert_eq!(env.get("out"), Some(expected.clone()));

    let (_vm_events, vm_value) = run_vm_result(src).expect("vm run");
    assert_eq!(vm_value, expected);
}

#[test]
fn num_001_division_by_zero_is_runtime_error() {
    for src in ["$out = 1 / 0\n^ $out\n", "$out = 0 / 0\n^ $out\n"] {
        assert_interpreter_error_contains(src, "Division by zero");
        assert_vm_error_contains(src, "Division by zero");
    }
}

#[test]
fn num_002_modulo_by_zero_is_runtime_error() {
    for src in ["$out = 1 % 0\n^ $out\n", "$out = 0 % 0\n^ $out\n"] {
        assert_interpreter_error_contains(src, "Modulo by zero");
        assert_vm_error_contains(src, "Modulo by zero");
    }
}

#[test]
fn num_003_nan_comparison_is_never_equal() {
    let nan = Value::Float(f64::NAN);

    assert_ne!(nan, nan);
    assert_ne!(Value::Float(f64::NAN), Value::SmallInt(0));
    assert!(Value::Float(f64::NAN) != Value::Float(f64::NAN));
}

#[test]
fn num_004_mixed_numeric_equality_is_stable() {
    assert_interpreter_vm_out(
        r#"
$out = len("x") == (2 / 2)
^ $out
"#,
        Value::Bool(true),
    );
    assert_interpreter_vm_out(
        r#"
$out = len("xx") != (3 / 2)
^ $out
"#,
        Value::Bool(true),
    );
}

#[test]
fn bool_001_logical_not_uses_the_same_truthiness_in_interpreter_and_vm() {
    for (source, expected) in [
        ("$out = !0\n^ $out\n", true),
        ("$out = !1\n^ $out\n", false),
        ("$out = !\"\"\n^ $out\n", true),
        ("$out = ![1]\n^ $out\n", false),
    ] {
        assert_interpreter_vm_out(source, Value::Bool(expected));
    }
}

#[test]
fn bool_002_and_short_circuits_the_unselected_rhs_in_both_backends() {
    assert_interpreter_vm_out("$out = false && (1 / 0)\n^ $out\n", Value::Bool(false));
    assert_interpreter_vm_out("$out = 7 && 2\n^ $out\n", Value::Bool(true));
}

#[test]
fn bool_003_or_short_circuits_the_unselected_rhs_in_both_backends() {
    assert_interpreter_vm_out("$out = true || (1 / 0)\n^ $out\n", Value::Bool(true));
    assert_interpreter_vm_out("$out = 0 || 2\n^ $out\n", Value::Bool(true));
}

#[test]
fn bool_004_short_circuit_result_remains_valid_at_an_outer_branch_join() {
    assert_interpreter_vm_out(
        r#"
$out = 0
~ if 1 == 1 && 2 == 2
    $out = 7
~ end
^ $out
"#,
        Value::SmallInt(7),
    );
}

#[test]
fn ctrl_001_loop_count_rejects_negative_and_fractional_values_in_both_backends() {
    for source in ["~ loop -1\n~ end\n^ 0\n", "~ loop 3 / 2\n~ end\n^ 0\n"] {
        assert_interpreter_vm_error_first_line(
            source,
            "Runtime error: Loop count must be a non-negative integer.",
        );
        assert_jit_error_contains(source, "Loop count must be a non-negative integer.");
    }
}

#[test]
fn imp_001_relative_import_resolves_from_importing_file() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("naux_parity_import_{stamp}"));
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).expect("create temp import dir");
    fs::write(src_dir.join("dep.nx"), "$from_dep = 42\n").expect("write dep");

    let main_src = r#"
import "./dep.nx"
$out = $from_dep
"#;

    let (env, _events, errors) = run_interpreter_with_base(main_src, &src_dir);
    assert!(errors.is_empty(), "runtime errors: {errors:?}");
    assert_eq!(env.get("out"), Some(Value::Float(42.0)));
}

#[test]
fn col_001_list_equality_is_structural_and_order_sensitive() {
    assert_interpreter_vm_out(
        r#"
$out = [1, 2, [3, 4]] == [1, 2, [3, 4]]
^ $out
"#,
        Value::Bool(true),
    );
    assert_interpreter_vm_out(
        r#"
$out = [1, 2, 3] == [3, 2, 1]
^ $out
"#,
        Value::Bool(false),
    );
}

#[test]
fn col_002_map_equality_is_structural_key_aware_and_order_independent() {
    assert_interpreter_vm_out(
        r#"
$out = {a: 1, b: [2, 3]} == {b: [2, 3], a: 1}
^ $out
"#,
        Value::Bool(true),
    );
    assert_interpreter_vm_out(
        r#"
$out = {a: 1, b: [2, 3]} == {a: 1, b: [3, 2]}
^ $out
"#,
        Value::Bool(false),
    );
}

#[test]
fn eff_001_events_keep_source_evaluation_order() {
    let src = r#"
~ rite
    !say "a"
    !say "b"
~ end
^ 0
"#;

    let (_env, interp_events, interp_errors) = run_interpreter(src);
    assert!(
        interp_errors.is_empty(),
        "runtime errors: {interp_errors:?}"
    );
    assert_eq!(say_events(&interp_events), vec!["a", "b"]);

    let (vm_events, value) = run_vm_result(src).expect("vm run");
    assert_eq!(value, Value::SmallInt(0));
    assert_eq!(say_events(&vm_events), vec!["a", "b"]);
}

#[cfg(all(target_arch = "x86_64", not(windows)))]
#[test]
fn jit_001_unrolled_list_loops_preserve_scalar_tail() {
    let cases = [
        r#"
~ rite
    $n = 1000
    $reps = 2
    $arr = list_range($n)
    $r = 0
    $total = 0
    ~ while $r < $reps
        $i = 0
        $sum = 0
        ~ while $i < len($arr)
            $sum = $sum + 0
            $sum = $sum + 0
            $sum = $sum + __index($arr, $i)
            $i = $i + 1
        ~ end
        $total = $total + $sum
        $r = $r + 1
    ~ end
    ^ $total
~ end
"#,
        r#"
~ rite
    $n = 1000
    $reps = 2
    $arr = list_range($n)
    $r = 0
    $total = 0
    ~ while $r < $reps
        $i = 0
        $sum = 0
        ~ while $i < len($arr)
            $v = __index($arr, $i)
            $sum = $sum + $v
            $__ = __setindex($arr, $i, $v + 1)
            $i = $i + 1
        ~ end
        $total = $total + $sum
        $r = $r + 1
    ~ end
    ^ $total
~ end
"#,
        r#"
~ rite
    $n = 1000
    $reps = 2
    $arr = list_range($n)
    $r = 0
    $total = 0
    ~ while $r < $reps
        $i = 0
        $sum = 0
        ~ while $i < len($arr)
            $v = __index($arr, $i)
            $sum = $sum + $v * $v
            $i = $i + 1
        ~ end
        $total = $total + $sum
        $r = $r + 1
    ~ end
    ^ $total
~ end
"#,
    ];

    for src in cases {
        let (_vm_events, vm_value) = run_vm_result(src).expect("VM run");
        let (_jit_events, jit_value, used_jit) = run_jit_result(src).expect("JIT run");
        assert!(used_jit, "expected typed trace JIT path");
        assert_eq!(jit_value, vm_value);
    }
}

#[cfg(all(target_arch = "x86_64", not(windows)))]
#[test]
fn jit_002_mutation_tail_is_version_safe_across_mod4_and_runner_reuse() {
    for n in 51..=58 {
        let src = format!(
            r#"
~ rite
    $n = {n}
    $reps = 3
    $arr = list_range($n)
    $view = $arr
    $r = 0
    $total = 0
    ~ while $r < $reps
        $i = 0
        $sum = 0
        ~ while $i < len($view)
            $v = __index($view, $i)
            $sum = $sum + $v
            $__ = __setindex($view, $i, $v + 1)
            $i = $i + 1
        ~ end
        $total = $total + $sum
        $r = $r + 1
    ~ end
    $head = __index($arr, 0)
    ^ $total + $head
~ end
"#
        );
        let ast = parse(&src);
        let prog = compile_script(&ast);
        let (_vm_events, expected) = run_vm_result(&src).expect("VM run");
        let mut runner = TypedRunner::new(&prog);
        let mut previous_hits = 0;

        for run_idx in 0..4 {
            let (actual, _events) = runner.run(&prog).expect("typed JIT run");
            assert_eq!(actual, expected, "n={n}, runner reuse iteration={run_idx}");

            let summary = runner.trace_summary();
            assert_eq!(summary.total_deopts, 0, "n={n}");
            assert_eq!(summary.total_runtime_deopts, 0, "n={n}");
            assert_eq!(summary.guard_fail_total, 0, "n={n}");
            let hit_delta = summary.total_hits.saturating_sub(previous_hits);
            assert_eq!(
                hit_delta, 3,
                "each of the three inner loops must enter the trace exactly once for n={n}"
            );
            previous_hits = summary.total_hits;
        }

        let summary = runner.trace_summary();
        assert_eq!(
            summary.trace_count, 1,
            "trace cache should remain stable for n={n}"
        );
        assert!(
            summary.total_hits > 0,
            "expected hot trace execution for n={n}"
        );
    }
}

#[cfg(all(target_arch = "x86_64", not(windows)))]
#[test]
fn jit_003_read_only_tail_handoff_avoids_trace_bounce() {
    let src = r#"
~ rite
    $n = 56
    $reps = 3
    $arr = list_range($n)
    $r = 0
    $total = 0
    ~ while $r < $reps
        $i = 0
        $sum = 0
        ~ while $i < len($arr)
            $sum = $sum + 0
            $sum = $sum + 0
            $sum = $sum + __index($arr, $i)
            $i = $i + 1
        ~ end
        $total = $total + $sum
        $r = $r + 1
    ~ end
    ^ $total
~ end
"#;
    let ast = parse(src);
    let prog = compile_script(&ast);
    let (_vm_events, expected) = run_vm_result(src).expect("VM run");
    let mut runner = TypedRunner::new(&prog);

    for run_idx in 0..4 {
        let previous_hits = runner.trace_summary().total_hits;
        let (actual, _events) = runner.run(&prog).expect("typed JIT run");
        assert_eq!(actual, expected, "runner reuse iteration={run_idx}");
        let summary = runner.trace_summary();
        assert_eq!(summary.total_hits.saturating_sub(previous_hits), 3);
        assert_eq!(summary.total_deopts, 0);
        assert_eq!(summary.guard_fail_total, 0);
    }
}

#[cfg(all(target_arch = "x86_64", not(windows)))]
#[test]
fn jit_004_uniform_numeric_map_branch_reaches_cmp_fusion() {
    let src = r#"
~ rite
    $n = 256
    $reps = 3
    $m = {k0: 96}
    $k = "k0"
    $sum = 0
    $last = 0
    $r = 0
    ~ while $r < $reps
        $v = 0
        $i = 0
        ~ while $i < $n
            $v = __index($m, $k)
            ~ if $v > 64
                $sum = $sum + 1
            ~ end
            $v = __index($m, $k)
            ~ if $v > 80
                $sum = $sum + 1
            ~ end
            $i = $i + 1
        ~ end
        $last = $last + $v
        $r = $r + 1
    ~ end
    ^ $sum + $last
~ end
"#;
    let ast = parse(src);
    let prog = compile_script(&ast);
    let (_vm_events, expected) = run_vm_result(src).expect("VM run");
    let mut runner = TypedRunner::new(&prog);
    let (actual, _events) = runner.run(&prog).expect("typed JIT run");
    assert_eq!(actual, expected);

    let summary = runner.trace_summary();
    assert_eq!(summary.trace_count, 1);
    assert!(summary.total_hits > 0);
    assert_eq!(summary.total_deopts, 0);
    assert_eq!(summary.total_runtime_deopts, 0);
    assert_eq!(summary.guard_fail_total, 0);
    let cmp_fusion = summary
        .fusion_hits_by_rule
        .iter()
        .find(|profile| profile.rule == "map_stable_cmp_branch")
        .expect("map comparison branch should reach the stable fusion tier");
    assert!(cmp_fusion.static_hits > 0);
    assert!(cmp_fusion.runtime_hits > 0);
}

#[cfg(all(target_arch = "x86_64", not(windows)))]
#[test]
fn jit_005_distinct_list_does_not_inherit_another_lists_bounds_guard() {
    let src = r#"
~ rite
    $long = list_range(100)
    $short = list_range(60)
    $i = 0
    $sum = 0
    ~ while $i < len($long)
        $sum = $sum + __index($short, $i)
        $i = $i + 1
    ~ end
    ^ $sum
~ end
"#;
    let (_vm_events, expected) = run_vm_result(src).expect("reference VM run");
    let (_jit_events, actual, used_jit) = run_jit_result(src).expect("typed JIT run");
    assert_eq!(actual, expected);
    assert_eq!(actual, Value::Null);
    assert!(
        !used_jit,
        "a bound proven for one list must not admit unchecked indexing into another list"
    );
}

#[cfg(all(target_arch = "x86_64", not(windows)))]
#[test]
fn jit_006_internal_branch_executes_natively_without_side_exit_bounce() {
    let src = r#"
~ rite
    $n = 90
    $pivot = 80
    $reps = 3
    $arr = list_range($n)
    $view = $arr
    $digest = 0
    $r = 0
    ~ while $r < $reps
        $i = 0
        ~ while $i < len($view)
            $v = __index($view, $i)
            ~ if $i < $pivot
                $digest = $digest + $v
            ~ end
            $digest = $digest + $v
            $__ = __setindex($arr, $i, $v + 1)
            $i = $i + 1
        ~ end
        $r = $r + 1
    ~ end
    ^ $digest + __index($view, 0) + __index($arr, $n - 1)
~ end
"#;
    let ast = parse(src);
    let prog = compile_script(&ast);
    let (_vm_events, expected) = run_vm_result(src).expect("reference VM run");
    let mut runner = TypedRunner::new(&prog);
    let mut previous_hits = 0;

    for run_idx in 0..4 {
        let (actual, _events) = runner.run(&prog).expect("typed JIT run");
        assert_eq!(actual, expected, "runner reuse iteration={run_idx}");

        let summary = runner.trace_summary();
        assert_eq!(
            summary.trace_count, 1,
            "native branch must not split traces"
        );
        assert_eq!(
            summary.total_internal_side_exits, 0,
            "forward internal branches must stay in machine code"
        );
        assert_eq!(
            summary.total_hits.saturating_sub(previous_hits),
            3,
            "the trace should be entered once per loop invocation"
        );
        assert!(
            summary.total_static_branches >= 3,
            "trace must retain the internal branch plus loop guards"
        );
        assert_eq!(summary.total_deopts, 0);
        assert_eq!(summary.total_runtime_deopts, 0);
        assert_eq!(summary.guard_fail_total, 0);
        previous_hits = summary.total_hits;
    }
}

#[cfg(all(target_arch = "x86_64", not(windows)))]
#[test]
fn jit_007_forward_if_else_branch_stays_in_one_native_trace() {
    let src = r#"
~ rite
    $n = 257
    $reps = 3
    $arr = list_range($n)
    $total = 0
    $r = 0
    ~ while $r < $reps
        $i = 0
        $sum = 0
        $state = 0
        ~ while $i < len($arr)
            $v = __index($arr, $i)
            $state = $state + 17
            ~ if $state >= 97
                $state = $state - 97
            ~ end
            ~ if $state < 48
                $sum = $sum + $v
            ~ else
                $sum = $sum - $v
            ~ end
            $i = $i + 1
        ~ end
        $total = $total + $sum
        $r = $r + 1
    ~ end
    ^ $total
~ end
"#;
    let ast = parse(src);
    let prog = compile_script(&ast);
    let (_vm_events, expected) = run_vm_result(src).expect("reference VM run");
    let mut runner = TypedRunner::new(&prog);

    for run_idx in 0..4 {
        let (actual, _events) = runner.run(&prog).expect("typed JIT run");
        assert_eq!(actual, expected, "runner reuse iteration={run_idx}");
    }

    let summary = runner.trace_summary();
    assert_eq!(summary.trace_count, 1);
    assert!(summary.total_hits > 0);
    assert_eq!(summary.total_internal_side_exits, 0);
    assert_eq!(summary.total_deopts, 0);
    assert_eq!(summary.total_runtime_deopts, 0);
    assert_eq!(summary.guard_fail_total, 0);
    assert!(
        summary.total_static_branches >= 5,
        "trace should contain loop guards and both forward branch sites"
    );
}

#[test]
fn call_001_arguments_evaluate_in_source_order() {
    let src = r#"
~ fn tap($x)
    !say $x
    ^ $x
~ end

~ fn join($a, $b)
    ^ $a + $b
~ end

$out = join(tap("a"), tap("b"))
^ $out
"#;

    let (env, interp_events, interp_errors) = run_interpreter(src);
    assert!(
        interp_errors.is_empty(),
        "runtime errors: {interp_errors:?}"
    );
    assert_eq!(env.get("out"), Some(Value::make_text("ab")));
    assert_eq!(say_events(&interp_events), vec!["a", "b"]);

    let (vm_events, vm_value) = run_vm_result(src).expect("vm run");
    assert_eq!(vm_value, Value::make_text("ab"));
    assert_eq!(say_events(&vm_events), vec!["a", "b"]);
}

#[test]
fn err_001_fatal_error_halts_current_evaluation_path() {
    let src = r#"
~ rite
    !say "before"
    $bad = 1 / 0
    !say "after"
~ end
^ 0
"#;

    let (_env, interp_events, interp_errors) = run_interpreter(src);
    assert!(
        interp_errors
            .iter()
            .any(|err| err.message.contains("Division by zero")),
        "expected interpreter division error, got {interp_errors:?}"
    );
    assert_eq!(say_events(&interp_events), vec!["before"]);

    assert_vm_error_contains(src, "Division by zero");
}

#[test]
fn err_002_error_shape_keeps_backend_stable_kind_and_message() {
    let src = "$out = 1 / 0\n^ $out\n";
    let (_env, _events, errors) = run_interpreter(src);
    assert_eq!(
        errors.len(),
        1,
        "expected one interpreter error: {errors:?}"
    );
    assert_eq!(errors[0].message, "Division by zero");

    let rendered = format_runtime_error_with_file(src, &errors[0], "<parity>");
    let interp_first = rendered.lines().next().unwrap_or("");

    let vm_err = run_vm_result(src).expect_err("VM should reject division by zero");
    let vm_first = vm_err.lines().next().unwrap_or("");

    assert_eq!(interp_first, "Runtime error: Division by zero");
    assert_eq!(vm_first, interp_first);
    assert!(rendered.contains(" --> <parity>:"));
    assert!(vm_err.contains(" --> <parity>:"));
}

#[test]
#[allow(clippy::mutable_key_type)] // The contract intentionally exercises Value's Ord implementation.
fn col_003_ordering_fallback_is_deterministic_and_distinguishes_structural_values() {
    let list_a = Value::make_list(vec![Value::SmallInt(1)]);
    let list_b = Value::make_list(vec![Value::SmallInt(2)]);

    let mut map_a = HashMap::new();
    map_a.insert("k".to_string(), Value::SmallInt(1));
    let mut map_b = HashMap::new();
    map_b.insert("k".to_string(), Value::SmallInt(2));

    let mut set = BTreeSet::new();
    set.insert(list_a.clone());
    set.insert(list_b.clone());
    set.insert(Value::make_map(map_a.clone()));
    set.insert(Value::make_map(map_b.clone()));
    assert_eq!(
        set.len(),
        4,
        "ordering fallback must not collapse unequal values"
    );

    let values = vec![
        Value::make_text("b"),
        Value::Bool(false),
        Value::make_text("a"),
        list_b,
        list_a,
        Value::make_map(map_b),
        Value::make_map(map_a),
        Value::Null,
    ];
    let mut first = values.clone();
    let mut second = values;
    first.sort();
    second.sort();
    assert_eq!(first, second);
}

#[test]
fn col_004_mutation_through_alias_is_observable() {
    assert_interpreter_vm_out(
        r#"
$a = [1]
$b = $a
$__ = __setindex($b, 0, 9)
$out = $a[0]
^ $out
"#,
        Value::SmallInt(9),
    );
}

#[test]
fn mem_001_collection_assignment_preserves_backing_identity() {
    assert_interpreter_vm_out(
        r#"
$list = [1]
$list_alias = $list
$__ = __setindex($list_alias, 0, 9)
$map = {x: 2}
$map_alias = $map
$__ = __setindex($map_alias, "x", 11)
$out = __index($list, 0) + __index($map, "x")
^ $out
"#,
        Value::SmallInt(20),
    );
}

#[test]
fn mem_002_safe_index_contract_is_null_on_read_and_error_on_write() {
    for src in [
        "$out = __index([1], 1)\n^ $out\n",
        "$out = __index([1], -1)\n^ $out\n",
        "$values = [1]\n$out = $values[-1]\n^ $out\n",
        "$out = __index({x: 1}, \"missing\")\n^ $out\n",
    ] {
        let (env, _events, errors) = run_interpreter(src);
        assert!(errors.is_empty(), "runtime errors: {errors:?}");
        assert_eq!(env.get("out"), Some(Value::Null));

        let (_events, vm_value) = run_vm_result(src).expect("VM safe read");
        assert_eq!(vm_value, Value::Null);
        let (_events, jit_value, _used_jit) = run_jit_result(src).expect("JIT safe read");
        assert_eq!(jit_value, Value::Null);
    }

    for src in [
        "$out = __index([10, 20], 3 / 2)\n^ $out\n",
        "$values = [10, 20]\n$out = $values[3 / 2]\n^ $out\n",
    ] {
        assert_interpreter_vm_error_first_line(src, "Runtime error: index must be an integer");
        assert_jit_error_contains(src, "index must be an integer");
    }

    for src in [
        "$list = [1]\n$__ = __setindex($list, 1, 9)\n^ 0\n",
        "$list = [1]\n$__ = __setindex($list, -1, 9)\n^ 0\n",
    ] {
        let expected = if src.contains("-1") {
            "index cannot be negative"
        } else {
            "index out of range"
        };
        assert_interpreter_error_contains(src, expected);
        assert_vm_error_contains(src, expected);
        assert_jit_error_contains(src, expected);
    }
}

#[cfg(all(target_arch = "x86_64", not(windows)))]
#[test]
fn mem_003_unsafe_valid_access_preserves_vm_jit_result() {
    let src = r#"
~ rite
    $arr = list_range(64)
    $sum = 0
    ~ unsafe
        $i = 0
        ~ while $i < len($arr)
            $sum = $sum + __index($arr, $i)
            $i = $i + 1
        ~ end
    ~ end
    ^ $sum
~ end
"#;
    let (_vm_events, expected) = run_vm_result(src).expect("VM unsafe run");
    let (_jit_events, actual, used_jit) = run_jit_result(src).expect("JIT unsafe run");
    assert!(used_jit, "valid unsafe loop should reach the typed JIT");
    assert_eq!(actual, expected);
}

#[test]
fn call_003_builtin_failures_propagate_with_stable_shape() {
    assert_interpreter_vm_error_first_line(
        "$out = __index([1], 0, 99)\n^ $out\n",
        "Runtime error: __index(list/map, key)",
    );
    assert_interpreter_vm_error_first_line(
        "$out = __index(1, 0)\n^ $out\n",
        "Runtime error: invalid __index operands",
    );
}

#[test]
fn imp_002_absolute_filesystem_import_resolves_deterministically() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("naux_parity_absolute_import_{stamp}"));
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).expect("create temp import dir");
    let dep_path = src_dir.join("absolute_dep.nx");
    fs::write(&dep_path, "$absolute_dep = 11\n").expect("write dep");

    let module_ref = dep_path.to_string_lossy().replace('\\', "/");
    let main_src = format!(
        r#"
import "{}"
$out = $absolute_dep
"#,
        module_ref
    );

    let (env, _events, errors) = run_interpreter(&main_src);
    assert!(errors.is_empty(), "runtime errors: {errors:?}");
    assert_eq!(env.get("out"), Some(Value::Float(11.0)));
}

#[test]
fn mod_001_duplicate_imports_are_deduped_by_interpreter_module_cache() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("naux_parity_duplicate_import_{stamp}"));
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).expect("create temp import dir");
    fs::write(
        src_dir.join("dep.nx"),
        r#"
!say "dep loaded"
$from_dep = 7
"#,
    )
    .expect("write dep");

    let main_src = r#"
import "./dep.nx"
import "./dep.nx"
$out = $from_dep
"#;

    let (env, events, errors) = run_interpreter_with_base(main_src, &src_dir);
    assert!(errors.is_empty(), "runtime errors: {errors:?}");
    assert_eq!(env.get("out"), Some(Value::Float(7.0)));
    assert_eq!(say_events(&events), vec!["dep loaded"]);
}
