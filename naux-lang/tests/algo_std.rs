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
fn math_pow_mod_and_sieve() {
    let src = r#"
    $pm = pow_mod(2, 10, 1000)
    $pr = sieve(10)
    "#;
    assert_eq!(run(src, "pm"), Value::Number(24.0));
    assert_eq!(
        run(src, "pr"),
        Value::List(vec![
            Value::Number(2.0),
            Value::Number(3.0),
            Value::Number(5.0),
            Value::Number(7.0)
        ])
    );
}

#[test]
fn dsu_union_find() {
    let src = r#"
    $ds = dsu_new(4)
    $ds = dsu_union($ds, 0, 1)
    $res = dsu_find($ds, 1)
    $root = $res[0]
    "#;
    assert_eq!(run(src, "root"), Value::Number(0.0));
}

#[test]
fn segtree_sum() {
    let src = r#"
    $st = segtree_new([1,2,3,4])
    $sum = segtree_query($st, 0, 4)
    $st = segtree_update($st, 2, 10)
    $sum2 = segtree_query($st, 0, 4)
    "#;
    assert_eq!(run(src, "sum"), Value::Number(10.0));
    assert_eq!(run(src, "sum2"), Value::Number(17.0));
}

#[test]
fn lis_and_knapsack() {
    let src = r#"
    $lis = lis_length([10,9,2,5,3,7,101,18])
    $val = knapsack_01([2,3,4,5], [3,4,5,6], 5)
    "#;
    assert_eq!(run(src, "lis"), Value::Number(4.0));
    assert_eq!(run(src, "val"), Value::Number(7.0));
}

#[test]
fn lower_upper_bound() {
    let src = r#"
    $a = [1,2,4,4,5]
    $lb = lower_bound($a, 4)
    $ub = upper_bound($a, 4)
    "#;
    assert_eq!(run(src, "lb"), Value::Number(2.0));
    assert_eq!(run(src, "ub"), Value::Number(4.0));
}
