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
fn set_add_contains() {
    let src = r#"
    $s = set_new()
    $s = set_add($s, 3)
    $out = set_contains($s, 3)
"#;
    assert_eq!(run(src, "out"), Value::Bool(true));
}

#[test]
fn queue_push_pop() {
    let src = r#"
    $q = queue_new()
    $q = queue_push($q, 1)
    $q = queue_push($q, 2)
    $res = queue_pop($q)
"#;
    // queue_pop returns [head, new_queue]
    match run(src, "res") {
        Value::List(items) => {
            assert_eq!(items.get(0), Some(&Value::Number(1.0)));
            // second element should be the remaining queue [2]
            match items.get(1) {
                Some(Value::List(rest)) => assert_eq!(rest, &vec![Value::Number(2.0)]),
                other => panic!("unexpected tail queue: {:?}", other),
            }
        }
        other => panic!("unexpected queue_pop result: {:?}", other),
    }
}

#[test]
fn priority_queue_push_pop() {
    let src = r#"
    $pq = pq_new()
    $pq = pq_push($pq, 5)
    $pq = pq_push($pq, 1)
    $pq = pq_push($pq, 3)
    $res = pq_pop_min($pq)
"#;
    match run(src, "res") {
        Value::List(items) => {
            assert_eq!(items.get(0), Some(&Value::Number(1.0))); // min element
            // remainder should be a priority queue with 3,5
            match items.get(1) {
                Some(Value::PriorityQueue(v)) => {
                    // order inside pq storage is implementation-defined; check set equality
                    let mut got = v.clone();
                    got.sort_by(|a, b| a.partial_cmp(b).unwrap());
                    assert_eq!(got, vec![Value::Number(3.0), Value::Number(5.0)]);
                }
                other => panic!("expected priority queue, got {:?}", other),
            }
        }
        other => panic!("unexpected pq_pop_min result: {:?}", other),
    }
}
