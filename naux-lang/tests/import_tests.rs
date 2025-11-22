use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::runtime::eval_script;
use naux::runtime::value::Value;
use std::fs;
use std::path::PathBuf;

#[test]
fn import_and_call_function() {
    // Write a temporary module file
    let mut module_path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    module_path.push("mod_add.nx");
    fs::write(
        &module_path,
        r#"
~ fn add($a, $b)
    ^ $a + $b
~ end
"#,
    )
    .expect("write module");

    let src = format!(
        r#"
import "{}"
$res = add(2, 5)
"#,
        module_path.display()
    );

    let tokens = lex(&src).unwrap();
    let ast = Parser::from_tokens(&tokens).unwrap();
    let (env, _events, errs) = eval_script(&ast);
    assert!(errs.is_empty(), "runtime errors: {:?}", errs);
    assert_eq!(env.get("res"), Some(Value::Number(7.0)));
}
