use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::runtime::eval_script;
use naux::runtime::value::Value;
use naux::vm::run::run_vm;

fn vm_value(src: &str) -> Value {
    let tokens = lex(src).unwrap();
    let ast = Parser::from_tokens(&tokens).unwrap();
    let (_events, val) = run_vm(&ast).expect("vm run");
    val
}

fn interp_value(src: &str, var: &str) -> Value {
    let tokens = lex(src).unwrap();
    let ast = Parser::from_tokens(&tokens).unwrap();
    let (env, _events, errs) = eval_script(&ast);
    assert!(errs.is_empty());
    env.get(var).unwrap_or(Value::Null)
}

#[test]
fn parity_simple_arith() {
    let src = r#"
    $x = 1 + 2 * 3
    ^ $x
    "#;
    let interp = interp_value(src, "x");
    let vmv = vm_value(src);
    assert_eq!(interp, vmv);
}

#[test]
fn parity_if_else() {
    let src = r#"
    $x = 0
    ~ if 2 > 1
        $x = 42
    ~ else
        $x = 99
    ~ end
    ^ $x
    "#;
    let interp = interp_value(src, "x");
    let vmv = vm_value(src);
    assert_eq!(interp, vmv);
}

#[test]
fn parity_loop_sum() {
    let src = r#"
    $s = 0
    ~ loop 5
        $s = $s + 2
    ~ end
    ^ $s
    "#;
    let interp = interp_value(src, "s");
    let vmv = vm_value(src);
    assert_eq!(interp, vmv);
}

#[test]
fn parity_fn_call() {
    let src = r#"
    ~ fn add($a, $b)
        ^ $a + $b
    ~ end
    $x = add(3, 4)
    ^ $x
    "#;
    let interp = interp_value(src, "x");
    let vmv = vm_value(src);
    assert_eq!(interp, vmv);
}
