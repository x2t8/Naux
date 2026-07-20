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
    assert_eq!(run(src, "pm"), Value::Float(24.0));
    match run(src, "pr") {
        Value::RcObj(rc) => {
            if let naux::runtime::value::NauxObj::List(v) = rc.as_ref() {
                assert_eq!(
                    v.borrow().as_slice(),
                    &[
                        Value::Float(2.0),
                        Value::Float(3.0),
                        Value::Float(5.0),
                        Value::Float(7.0)
                    ]
                );
            } else {
                panic!("expected list");
            }
        }
        other => panic!("unexpected primes: {:?}", other),
    }
}

#[test]
fn dsu_union_find() {
    let src = r#"
    $ds = dsu_new(4)
    $ds = dsu_union($ds, 0, 1)
    $res = dsu_find($ds, 1)
    $root = $res[0]
    "#;
    assert_eq!(run(src, "root"), Value::Float(0.0));
}

#[test]
fn segtree_sum() {
    let src = r#"
    $st = segtree_new([1,2,3,4])
    $sum = segtree_query($st, 0, 4)
    $st = segtree_update($st, 2, 10)
    $sum2 = segtree_query($st, 0, 4)
    "#;
    assert_eq!(run(src, "sum"), Value::Float(10.0));
    assert_eq!(run(src, "sum2"), Value::Float(17.0));
}

#[test]
fn segtree_lazy_range_add_sum() {
    let src = r#"
    $st = segtree_lazy_new([1,2,3,4])
    $q0 = segtree_lazy_query($st, 0, 4)
    $st = segtree_lazy_add($st, 1, 4, 10)
    $q1 = segtree_lazy_query($st, 0, 4)
    $q2 = segtree_lazy_query($st, 1, 3)
    $st = segtree_lazy_add($st, 0, 2, -1)
    $q3 = segtree_lazy_query($st, 0, 2)
    "#;
    assert_eq!(run(src, "q0"), Value::Float(10.0));
    assert_eq!(run(src, "q1"), Value::Float(40.0));
    assert_eq!(run(src, "q2"), Value::Float(25.0));
    assert_eq!(run(src, "q3"), Value::Float(11.0));
}

#[test]
fn segtree_dynamic_point_add_sum() {
    let src = r#"
    $st = segtree_dynamic_new(0, 1000000000)
    $st = segtree_dynamic_add($st, 5, 3)
    $st = segtree_dynamic_add($st, 10000000, 7)
    $q1 = segtree_dynamic_query($st, 0, 6)
    $q2 = segtree_dynamic_query($st, 0, 1000000000)
    $q3 = segtree_dynamic_query($st, 6, 10000000)
    $q4 = segtree_dynamic_query($st, 10000000, 10000001)
    "#;
    assert_eq!(run(src, "q1"), Value::Float(3.0));
    assert_eq!(run(src, "q2"), Value::Float(10.0));
    assert_eq!(run(src, "q3"), Value::Float(0.0));
    assert_eq!(run(src, "q4"), Value::Float(7.0));
}

#[test]
fn lis_and_knapsack() {
    let src = r#"
    $lis = lis_length([10,9,2,5,3,7,101,18])
    $val = knapsack_01([2,3,4,5], [3,4,5,6], 5)
    "#;
    assert_eq!(run(src, "lis"), Value::Float(4.0));
    assert_eq!(run(src, "val"), Value::Float(7.0));
}

#[test]
fn lower_upper_bound() {
    let src = r#"
    $a = [1,2,4,4,5]
    $lb = lower_bound($a, 4)
    $ub = upper_bound($a, 4)
    "#;
    assert_eq!(run(src, "lb"), Value::Float(2.0));
    assert_eq!(run(src, "ub"), Value::Float(4.0));
}

#[test]
fn sliding_window_primitives() {
    let src = r#"
    $a = [1,3,-1,-3,5,3,6,7]
    $mx = window_max($a, 3)
    $mn = window_min($a, 3)
    $sm = window_sum_fixed($a, 3)
    "#;
    assert_eq!(
        run(src, "mx"),
        Value::make_list(vec![
            Value::Float(3.0),
            Value::Float(3.0),
            Value::Float(5.0),
            Value::Float(5.0),
            Value::Float(6.0),
            Value::Float(7.0),
        ])
    );
    assert_eq!(
        run(src, "mn"),
        Value::make_list(vec![
            Value::Float(-1.0),
            Value::Float(-3.0),
            Value::Float(-3.0),
            Value::Float(-3.0),
            Value::Float(3.0),
            Value::Float(3.0),
        ])
    );
    assert_eq!(
        run(src, "sm"),
        Value::make_list(vec![
            Value::Float(3.0),
            Value::Float(-1.0),
            Value::Float(1.0),
            Value::Float(5.0),
            Value::Float(14.0),
            Value::Float(16.0),
        ])
    );
}
