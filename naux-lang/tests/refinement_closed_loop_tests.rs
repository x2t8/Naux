//! Integration tests: Refinement Types → ProofSlot → E-graph → Materialization
//!
//! These tests verify the complete closed-loop pipeline:
//! 1. Refinement type checker proves properties about variables
//! 2. ProofSlots carry those proofs into the IR
//! 3. E-graph equality saturation uses proofs to fire rewrite rules
//! 4. Materialization replaces expensive ops with cheaper equivalents

use naux::ast::Stmt;
use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::runtime::eval_script;
use naux::runtime::value::Value;
use naux::vm::compiler::compile_ir_with_report;
use naux::vm::ir::IRInstr;
use naux::vm::run::{run_jit, run_vm};
use std::sync::{Mutex, OnceLock};

fn parse(source: &str) -> Vec<Stmt> {
    let tokens = lex(source).expect("lex failed");
    Parser::from_tokens(&tokens).expect("parse failed")
}

fn with_egraph_for_small_blocks<T>(f: impl FnOnce() -> T) -> T {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("env lock poisoned");
    let _guard = guard;

    unsafe {
        std::env::set_var("NAUX_EGRAPH_MIN_BLOCK_LEN", "0");
    }
    let out = f();
    unsafe {
        std::env::remove_var("NAUX_EGRAPH_MIN_BLOCK_LEN");
    }
    out
}

/// Helper: parse source, compile with refinement, return the optimized IR main block.
fn compile_and_get_main(source: &str) -> Vec<IRInstr> {
    with_egraph_for_small_blocks(|| {
        let stmts = parse(source);
        let (ir, _report) = compile_ir_with_report(&stmts);
        ir.main.iter().map(|n| n.instr.clone()).collect()
    })
}

fn assert_proof_aware_backend_value_parity(source: &str, interp_var: &str, expected: Value) {
    with_egraph_for_small_blocks(|| {
        let stmts = parse(source);
        let (env, _interp_events, interp_errors) = eval_script(&stmts);
        assert!(
            interp_errors.is_empty(),
            "interpreter errors: {:?}",
            interp_errors
        );
        let interp_value = env
            .get(interp_var)
            .unwrap_or_else(|| panic!("interpreter did not bind `{}`", interp_var));
        assert_eq!(interp_value, expected);

        let (_vm_events, vm_value) = run_vm(&stmts, source, "<proof-parity>").expect("vm run");
        assert_eq!(vm_value, interp_value);

        let (_jit_events, jit_value, _used_jit) =
            run_jit(&stmts, source, "<proof-parity>").expect("jit/fallback run");
        assert_eq!(jit_value, interp_value);
    });
}

fn assert_proof_aware_interpreter_vm_error_parity(source: &str, needle: &str) {
    with_egraph_for_small_blocks(|| {
        let stmts = parse(source);
        let (_env, _interp_events, interp_errors) = eval_script(&stmts);
        assert!(
            interp_errors.iter().any(|err| err.message.contains(needle)),
            "expected interpreter error containing `{}`, got {:?}",
            needle,
            interp_errors
        );

        let vm_err = run_vm(&stmts, source, "<proof-parity>").expect_err("vm should fail");
        assert!(
            vm_err.contains(needle),
            "expected VM error containing `{}`, got {}",
            needle,
            vm_err
        );
    });
}

/// Test 1: Simple case — `$x = 10; $y = $x / $x`
///
/// The refinement checker proves x == 10 (nonzero).
/// The e-graph should fire `div-self-nonzero` rewrite.
/// Materialization should replace `Div` with `ConstNum(1.0)`.
#[test]
fn test_refinement_proves_nonzero_div_self_egraph_win() {
    let source = r#"
        $x = 10
        $y = $x / $x
        ^ $y
    "#;
    let instrs = compile_and_get_main(source);

    // The division should be optimized away — no Div instruction remaining.
    let has_div = instrs.iter().any(|i| matches!(i, IRInstr::Div));
    assert!(
        !has_div,
        "Expected x/x to be optimized out via refinement proof, but Div is still present.\n\
         Compiled instructions: {:?}",
        instrs
    );

    // Should have ConstNum(1.0) as the result of the optimization.
    let has_one = instrs
        .iter()
        .any(|i| matches!(i, IRInstr::ConstNum(v) if (*v - 1.0).abs() < f64::EPSILON));
    assert!(
        has_one,
        "Expected ConstNum(1.0) from div-self-nonzero optimization.\n\
         Compiled instructions: {:?}",
        instrs
    );
}

/// Test 2: Branch case — `$x = 10; ~ if $x > 0 ...`
///
/// Even with branching, the refinement checker should prove x is nonzero
/// and the division inside the then-branch should be optimized.
#[test]
fn test_refinement_if_branch_positive_nonzero_div_self() {
    let source = r#"
        $x = 10
        ~ if $x > 0
            $safe = $x / $x
        ~ end
        ^ $safe
    "#;
    let instrs = compile_and_get_main(source);

    // The division should be optimized out.
    let has_div = instrs.iter().any(|i| matches!(i, IRInstr::Div));
    assert!(
        !has_div,
        "Expected path-sensitive division to be optimized out.\n\
         Compiled instructions: {:?}",
        instrs
    );
}

/// Test 3: Verify that refinement proof_slots are populated correctly.
#[test]
fn test_refinement_report_has_proof_slots() {
    let source = r#"
        $x = 10
        $y = $x / $x
    "#;
    let stmts = parse(source);
    let report = naux::refinement::check_refinements(&stmts).expect("refinement check failed");

    // The proof_slots should contain "x" with nonzero proof.
    assert!(
        report.proof_slots.contains_key("x"),
        "Expected proof_slots to contain 'x', got: {:?}",
        report.proof_slots
    );

    let x_slot = &report.proof_slots["x"];
    assert!(
        x_slot.numeric.as_ref().map_or(false, |n| n.nonzero),
        "Expected x to have nonzero proof, got: {:?}",
        x_slot
    );
}

#[test]
fn test_refinement_proof_does_not_survive_mutation() {
    let source = r#"
        $x = 10
        $ok = 1 / $x
        $x = 0
        $bad = $x / $x
        ^ $bad
    "#;
    let instrs = compile_and_get_main(source);

    assert!(
        instrs.iter().any(|i| matches!(i, IRInstr::Div)),
        "Expected Div to remain after $x is reassigned; stale nonzero proof must not unlock div-self.\n\
         Compiled instructions: {:?}",
        instrs
    );
}

#[test]
fn proof_aware_rewrite_preserves_interpreter_vm_jit_value() {
    let source = r#"
        $x = 10
        $y = $x / $x
        ^ $y
    "#;
    assert_proof_aware_backend_value_parity(source, "y", Value::SmallInt(1));
}

#[test]
fn proof_aware_branch_rewrite_preserves_interpreter_vm_jit_value() {
    let source = r#"
        $x = 10
        ~ if $x > 0
            $safe = $x / $x
        ~ end
        ^ $safe
    "#;
    assert_proof_aware_backend_value_parity(source, "safe", Value::SmallInt(1));
}

#[test]
fn stale_proof_mutation_keeps_error_parity() {
    let source = r#"
        $x = 10
        $ok = 1 / $x
        $x = 0
        $bad = $x / $x
        ^ $bad
    "#;
    assert_proof_aware_interpreter_vm_error_parity(source, "Division by zero");
}

#[test]
fn path_condition_nonzero_unlocks_div_self_without_literal_assignment() {
    let source = r#"
        $x = len("hello")
        $safe = 0
        ~ if $x != 0
            $safe = $x / $x
        ~ end
        ^ $safe
    "#;
    let instrs = compile_and_get_main(source);

    assert!(
        !instrs.iter().any(|i| matches!(i, IRInstr::Div)),
        "Expected branch-local nonzero proof to optimize x/x without a literal assignment.\n\
         Compiled instructions: {:?}",
        instrs
    );

    assert_proof_aware_backend_value_parity(source, "safe", Value::SmallInt(1));
}
