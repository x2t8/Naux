use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::runtime::eval_script;
use naux::runtime::value::Value;

fn run(src: &str, var: &str) -> Value {
    let tokens = lex(src).unwrap();
    let ast = Parser::from_tokens(&tokens).unwrap();
    let (env, _events, errs) = eval_script(&ast);
    assert!(errs.is_empty(), "runtime errors: {:?}", errs);
    env.get(var).unwrap_or(Value::Null)
}

#[test]
fn simple_function_return() {
    let src = r#"
~ fn add($a, $b)
    ^ $a + $b
~ end

    $res = add(2, 3)
"#;
    assert_eq!(run(src, "res"), Value::Number(5.0));
}

#[test]
fn nested_call_and_shadow() {
    let src = r#"
~ fn inc($x)
    $x = $x + 1
    ^ $x
~ end

~ fn twice($y)
    $y = inc($y)
    ^ inc($y)
~ end

    $x = 10
    $out = twice($x)
"#;
    // twice(10) -> inc(10)=11 -> inc(11)=12
    assert_eq!(run(src, "out"), Value::Number(12.0));
}
