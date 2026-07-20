use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::runtime::eval_script;
use naux::runtime::value::Value;

fn run_and_get(src: &str, var: &str) -> Value {
    let tokens = lex(src).unwrap();
    let ast = Parser::from_tokens(&tokens).unwrap();
    let (env, _events, errs) = eval_script(&ast);
    assert!(errs.is_empty(), "runtime errors: {:?}", errs);
    env.get(var).unwrap_or(Value::Null)
}

#[test]
fn sparse_table_min_max() {
    let src = r#"
    $arr = [3, 1, -4, 7, 0]
    $tbl_min = sparse_table_new($arr, "min")
    $tbl_max = sparse_table_new($arr, "max")
    $q1 = sparse_table_query($tbl_min, 1, 3) # min in [1,3] => -4
    $q2 = sparse_table_query($tbl_max, 0, 4) # max in [0,4] => 7
"#;
    let q1 = run_and_get(src, "q1").as_f64().unwrap();
    let q2 = run_and_get(src, "q2").as_f64().unwrap();
    assert!((q1 + 4.0).abs() < f64::EPSILON);
    assert!((q2 - 7.0).abs() < f64::EPSILON);
}
