use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::runtime::value::Value;
use naux::vm::bytecode::Instr;
use naux::vm::compiler::compile_script;
use naux::vm::run::run_vm;
use std::sync::{Mutex, OnceLock};

fn compile_main(src: &str) -> Vec<Instr> {
    let tokens = lex(src).expect("lex");
    let ast = Parser::from_tokens(&tokens).expect("parse");
    let prog = compile_script(&ast);
    prog.main
}

fn compile_main_with_egraph_min(src: &str, min_block_len: usize) -> Vec<Instr> {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("env lock poisoned");
    let _guard = guard;
    unsafe {
        std::env::set_var("NAUX_EGRAPH_MIN_BLOCK_LEN", min_block_len.to_string());
    }
    let code = compile_main(src);
    unsafe {
        std::env::remove_var("NAUX_EGRAPH_MIN_BLOCK_LEN");
    }
    code
}

#[test]
fn egraph_pipeline_rewrites_mul_by_two_into_shl() {
    let code = compile_main_with_egraph_min(
        r#"
        $a = 3
        $out = $a * 2
    "#,
        0,
    );

    let shl_idx = code
        .iter()
        .position(|ins| matches!(ins, Instr::Shl))
        .expect("expected Shl in compiled bytecode");
    assert!(
        !code.iter().any(|ins| matches!(ins, Instr::Mul)),
        "expected Mul to be canonicalized into Shl"
    );
    assert!(
        shl_idx > 0,
        "expected shift amount literal before Shl instruction"
    );
    assert!(
        matches!(code[shl_idx - 1], Instr::ConstNum(v) if (v - 1.0).abs() < f64::EPSILON),
        "expected mul-by-two canonicalization to shift by 1"
    );
}

#[test]
fn egraph_pipeline_rewrites_xor_idempotent_to_zero_literal() {
    let src = r#"
        $a = 7
        $out = $a ^ $a
        ^ $out
    "#;
    let code = compile_main_with_egraph_min(src, 0);
    assert!(
        !code.iter().any(|ins| matches!(ins, Instr::Xor)),
        "expected xor-idempotent to fold into literal zero path"
    );
    assert!(
        code.iter()
            .any(|ins| matches!(ins, Instr::ConstNum(v) if v.abs() < f64::EPSILON)),
        "expected zero literal in compiled bytecode"
    );

    let tokens = lex(src).expect("lex");
    let ast = Parser::from_tokens(&tokens).expect("parse");
    let (_events, value) = run_vm(&ast, src, "<test>").expect("vm run");
    assert_eq!(value, Value::SmallInt(0));
}

#[test]
fn egraph_pipeline_rewrites_add_zero_identity_on_both_sides() {
    let rhs_identity = compile_main_with_egraph_min(
        r#"
        $a = 7
        $out = $a + 0
    "#,
        0,
    );
    assert!(
        !rhs_identity.iter().any(|ins| matches!(ins, Instr::Add)),
        "expected add-with-zero on rhs to fold into identity path"
    );
    assert!(
        rhs_identity.iter().any(|ins| matches!(ins, Instr::Pop)),
        "expected stack compensation pop when materializing identity rewrite"
    );

    let lhs_src = r#"
        $a = 7
        $out = 0 + $a
        ^ $out
    "#;
    let lhs_identity = compile_main_with_egraph_min(lhs_src, 0);
    assert!(
        !lhs_identity.iter().any(|ins| matches!(ins, Instr::Add)),
        "expected add-with-zero on lhs to fold into identity path"
    );
    let tokens = lex(lhs_src).expect("lex");
    let ast = Parser::from_tokens(&tokens).expect("parse");
    let (_events, value) = run_vm(&ast, lhs_src, "<test>").expect("vm run");
    assert_eq!(value, Value::SmallInt(7));
}

#[test]
fn egraph_pipeline_rewrites_mul_zero_rhs_to_zero_literal() {
    let src = r#"
        $a = 7
        $out = $a * 0
        ^ $out
    "#;
    let code = compile_main_with_egraph_min(src, 0);
    assert!(
        !code.iter().any(|ins| matches!(ins, Instr::Mul)),
        "expected mul-by-zero on rhs to fold into zero literal path"
    );
    assert!(
        code.iter()
            .any(|ins| matches!(ins, Instr::ConstNum(v) if v.abs() < f64::EPSILON)),
        "expected zero literal after mul-by-zero rewrite"
    );
    let tokens = lex(src).expect("lex");
    let ast = Parser::from_tokens(&tokens).expect("parse");
    let (_events, value) = run_vm(&ast, src, "<test>").expect("vm run");
    assert_eq!(value, Value::SmallInt(0));
}

#[test]
fn egraph_pipeline_rewrites_mul_one_left_to_identity() {
    let src = r#"
        $a = 42
        $out = 1 * $a
        ^ $out
    "#;
    let code = compile_main_with_egraph_min(src, 0);
    assert!(
        !code.iter().any(|ins| matches!(ins, Instr::Mul)),
        "expected mul-by-one on lhs to fold into identity path"
    );
    let tokens = lex(src).expect("lex");
    let ast = Parser::from_tokens(&tokens).expect("parse");
    let (_events, value) = run_vm(&ast, src, "<test>").expect("vm run");
    assert_eq!(value, Value::SmallInt(42));
}

#[test]
fn egraph_pipeline_skips_small_blocks_when_threshold_is_high() {
    let code = compile_main_with_egraph_min(
        r#"
        $a = 3
        $out = $a * 2
    "#,
        1024,
    );

    assert!(
        code.iter().any(|ins| matches!(ins, Instr::Mul)),
        "expected Mul to remain when the E-graph threshold disables saturation"
    );
    assert!(
        !code.iter().any(|ins| matches!(ins, Instr::Shl)),
        "did not expect Shl when the E-graph threshold disables saturation"
    );
}
