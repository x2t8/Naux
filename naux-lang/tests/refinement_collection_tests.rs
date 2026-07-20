//! Refinement collection safety tests.
//!
//! These focus on Phase 1 collection facts before the optimizer consumes them.

use naux::ast::Stmt;
use naux::lexer::lex;
use naux::parser::parser::Parser;

fn parse(source: &str) -> Vec<Stmt> {
    let tokens = lex(source).expect("lex failed");
    Parser::from_tokens(&tokens).expect("parse failed")
}

#[test]
fn list_literal_length_discharges_in_bounds_index() {
    let source = r#"
        $xs = [10, 20, 30]
        $i = 2
        $out = $xs[$i]
    "#;

    let stmts = parse(source);
    let report = naux::refinement::check_refinements(&stmts).expect("refinement check failed");

    assert_eq!(
        report.constraints_failed, 0,
        "in-bounds list index should discharge all generated constraints: {:?}",
        report.warnings
    );
    assert!(
        report.constraints_generated >= 2,
        "expected lower and upper index-bound constraints"
    );
}

#[test]
fn list_literal_length_flags_out_of_bounds_index() {
    let source = r#"
        $xs = [10, 20, 30]
        $i = 3
        $out = $xs[$i]
    "#;

    let stmts = parse(source);
    let report = naux::refinement::check_refinements(&stmts).expect("refinement check failed");

    assert_eq!(
        report.constraints_failed, 1,
        "out-of-bounds list index should fail the upper-bound proof"
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("array index must be less than collection length")),
        "expected upper-bound warning, got {:?}",
        report.warnings
    );
}

#[test]
fn list_literal_length_discharges_in_bounds_setindex() {
    let source = r#"
        $xs = [10, 20, 30]
        $i = 2
        $xs[$i] = 99
    "#;

    let stmts = parse(source);
    let report = naux::refinement::check_refinements(&stmts).expect("refinement check failed");

    assert_eq!(
        report.constraints_failed, 0,
        "in-bounds list write should discharge all generated constraints: {:?}",
        report.warnings
    );
    assert!(
        report.constraints_generated >= 2,
        "expected lower and upper write-bound constraints"
    );
}

#[test]
fn list_literal_length_flags_out_of_bounds_setindex() {
    let source = r#"
        $xs = [10, 20, 30]
        $i = 3
        $xs[$i] = 99
    "#;

    let stmts = parse(source);
    let report = naux::refinement::check_refinements(&stmts).expect("refinement check failed");

    assert_eq!(
        report.constraints_failed, 1,
        "out-of-bounds list write should fail the upper-bound proof"
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("array index must be less than collection length")),
        "expected upper-bound warning, got {:?}",
        report.warnings
    );
}

#[test]
fn map_text_index_does_not_emit_numeric_array_bound_constraints() {
    let source = r#"
        $m = {answer: 42}
        $out = $m["answer"]
    "#;

    let stmts = parse(source);
    let report = naux::refinement::check_refinements(&stmts).expect("refinement check failed");

    assert_eq!(report.constraints_generated, 0);
    assert_eq!(report.constraints_failed, 0);
}
