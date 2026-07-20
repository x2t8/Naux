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
use naux::vm::run::run_vm;

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
    assert!(vm_err.contains("  at <parity>:"));
}

#[test]
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
