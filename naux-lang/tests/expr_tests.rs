use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::runtime::eval_script;
use naux::runtime::value::Value;

fn run(src: &str) -> Value {
    let tokens = lex(src).unwrap();
    let ast = Parser::from_tokens(&tokens).unwrap();
    let (env, _events, errs) = eval_script(&ast);
    assert!(errs.is_empty(), "runtime errors: {:?}", errs);
    env.get("out").unwrap_or(Value::Null)
}

#[test]
fn arithmetic_precedence() {
    let src = r#"
    $out = 1 + 2 * 3
"#;
    assert_eq!(run(src), Value::Number(7.0));
}

#[test]
fn boolean_not() {
    let src = r#"
    $out = !false
"#;
    assert_eq!(run(src), Value::Bool(true));
}

#[test]
fn unary_negation() {
    let src = r#"
    $out = -5 + 2
"#;
    assert_eq!(run(src), Value::Number(-3.0));
}

#[test]
fn builtin_len_string() {
    let src = r#"
    $out = len("naux")
"#;
    assert_eq!(run(src), Value::Number(4.0));
}
