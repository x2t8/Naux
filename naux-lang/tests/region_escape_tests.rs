use naux::ast::Stmt;
use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::region::{infer_regions, RegionAllocationKind};
use naux::runtime::eval_script;
use naux::runtime::value::Value;
use naux::vm::run::{run_jit, run_vm};
#[cfg(feature = "experimental-regions")]
use naux::vm::run::{run_jit_with_region_plan, run_vm_with_region_plan};

fn parse(source: &str) -> Vec<Stmt> {
    let tokens = lex(source).expect("lex");
    Parser::from_tokens(&tokens).expect("parse")
}

#[test]
fn returned_collection_is_promoted_without_backend_semantic_drift() {
    let source = r#"
~ fn build()
    $result = [1, 2, 3]
    ^ $result
~ end

$out = build()
^ len($out)
"#;
    let ast = parse(source);
    let report = infer_regions(&ast);

    let returned = report
        .heap_allocations
        .iter()
        .find(|allocation| allocation.var == "result")
        .expect("returned list allocation");
    assert_eq!(returned.kind, RegionAllocationKind::List);
    assert!(returned.escape_to.is_some());
    assert_eq!(report.bulk_free_eligible, 0);
    assert_eq!(report.promotions.len(), 1);
    assert!(report.violations.is_empty());

    let (_env, _events, errors) = eval_script(&ast);
    assert!(errors.is_empty(), "interpreter errors: {errors:?}");

    let (_vm_events, vm_value) = run_vm(&ast, source, "<region-escape>").expect("VM execution");
    let (_jit_events, jit_value, _used_jit) =
        run_jit(&ast, source, "<region-escape>").expect("JIT/fallback execution");
    assert_eq!(vm_value, Value::SmallInt(3));
    assert_eq!(jit_value, vm_value);
}

#[test]
fn unescaped_function_scratch_is_proven_bulk_free_eligible() {
    let source = r#"
~ fn work()
    $scratch = {items: [1, 2, 3]}
    ^ len($scratch)
~ end

^ work()
"#;
    let report = infer_regions(&parse(source));

    let scratch = report
        .heap_allocations
        .iter()
        .find(|allocation| allocation.var == "scratch")
        .expect("scratch map allocation");
    assert_eq!(scratch.kind, RegionAllocationKind::Map);
    assert!(scratch.escape_to.is_none());
    assert_eq!(report.bulk_free_eligible, 1);
    assert!(report.promotions.is_empty());
    assert!(report.violations.is_empty());
}

#[test]
fn loop_assignment_is_conservatively_promoted_to_visible_parent_scope() {
    let source = r#"
~ loop 1
    $out = [4, 5, 6, 7]
~ end

^ len($out)
"#;
    let ast = parse(source);
    let report = infer_regions(&ast);
    let allocation = report
        .heap_allocations
        .iter()
        .find(|allocation| allocation.var == "out")
        .expect("loop list allocation");

    assert!(allocation.escape_to.is_some());
    assert_eq!(report.bulk_free_eligible, 0);
    assert_eq!(report.promotions.len(), 1);
    assert!(report.promotions[0].reason.contains("loop iteration"));

    let (_vm_events, vm_value) = run_vm(&ast, source, "<region-loop>").expect("VM execution");
    let (_jit_events, jit_value, _used_jit) =
        run_jit(&ast, source, "<region-loop>").expect("JIT/fallback execution");
    assert_eq!(vm_value, Value::SmallInt(4));
    assert_eq!(jit_value, vm_value);
}

#[test]
fn loop_value_returned_from_function_promotes_through_both_lifetimes() {
    let source = r#"
~ fn build()
    ~ loop 1
        $result = [8, 9]
    ~ end
    ^ $result
~ end

^ len(build())
"#;
    let ast = parse(source);
    let report = infer_regions(&ast);
    let allocation = report
        .heap_allocations
        .iter()
        .find(|allocation| allocation.var == "result")
        .expect("nested result allocation");
    let final_target = allocation.escape_to.expect("caller escape target");
    let target_summary = &report.region_map[&format!("ρ{final_target}")];

    assert_eq!(target_summary.depth, 0);
    assert_eq!(report.promotions.len(), 2);
    assert_eq!(report.bulk_free_eligible, 0);

    let (_vm_events, vm_value) = run_vm(&ast, source, "<region-transitive>").expect("VM execution");
    let (_jit_events, jit_value, _used_jit) =
        run_jit(&ast, source, "<region-transitive>").expect("JIT/fallback execution");
    assert_eq!(vm_value, Value::SmallInt(2));
    assert_eq!(jit_value, vm_value);
}

#[cfg(feature = "experimental-regions")]
#[test]
fn region_shadow_telemetry_preserves_vm_jit_values_and_counts_bulk_free_plan() {
    let source = r#"
~ fn work()
    $scratch = [1, 2, 3, 4]
    ^ len($scratch)
~ end
^ work()
"#;
    let ast = parse(source);
    let (_vm_events, ordinary_vm) = run_vm(&ast, source, "<region-shadow>").expect("ordinary VM");
    let (_region_events, region_vm, vm_telemetry) =
        run_vm_with_region_plan(&ast, source, "<region-shadow>").expect("region shadow VM");
    let (_jit_events, region_jit, _used_jit, jit_telemetry) =
        run_jit_with_region_plan(&ast, source, "<region-shadow>").expect("region shadow JIT");

    assert_eq!(ordinary_vm, Value::SmallInt(4));
    assert_eq!(region_vm, ordinary_vm);
    assert_eq!(region_jit, ordinary_vm);
    assert_eq!(vm_telemetry, jit_telemetry);
    assert!(vm_telemetry.certificate_verified);
    assert_eq!(vm_telemetry.region_local_allocations, 1);
    assert_eq!(vm_telemetry.rc_fallback_allocations, 0);
    assert_eq!(vm_telemetry.bulk_free_points, 1);
    assert_eq!(vm_telemetry.bulk_free_allocations, 1);
}

#[cfg(feature = "experimental-regions")]
#[test]
fn region_shadow_telemetry_keeps_escaping_value_on_rc_fallback() {
    let source = r#"
~ fn build()
    $result = [8, 9]
    ^ $result
~ end
^ len(build())
"#;
    let ast = parse(source);
    let (_events, value, telemetry) =
        run_vm_with_region_plan(&ast, source, "<region-shadow-escape>").expect("region shadow VM");

    assert_eq!(value, Value::SmallInt(2));
    assert_eq!(telemetry.region_local_allocations, 0);
    assert_eq!(telemetry.rc_fallback_allocations, 1);
    assert_eq!(telemetry.bulk_free_points, 0);
    assert_eq!(
        telemetry.rc_fallback_by_reason.get("escapes-proven-region"),
        Some(&1)
    );
}
