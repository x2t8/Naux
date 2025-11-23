use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::runtime::eval_script;
use naux::runtime::value::Value;
use naux::vm::run::run_vm;

#[test]
fn vm_matches_interpreter_on_sum() {
    let src = r#"
    $s = 0
    $i = 0
    ~ loop 5
        $s = $s + $i
        $i = $i + 1
    ~ end
    ^ $s
    "#;
    let tokens = lex(src).unwrap();
    let ast = Parser::from_tokens(&tokens).unwrap();
    let (env, _events, errs) = eval_script(&ast);
    assert!(errs.is_empty());
    let interp = env.get("s").unwrap_or(Value::Null);
    let (vm_events, vm_val) = run_vm(&ast).expect("vm run");
    // Ensure no unexpected runtime events were emitted in this pure snippet.
    assert!(vm_events.is_empty());
    assert_eq!(interp, vm_val);
}
