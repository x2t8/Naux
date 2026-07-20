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

#[allow(dead_code)]
fn as_list(v: &Value) -> Option<Vec<Value>> {
    match v {
        Value::RcObj(rc) => {
            if let naux::runtime::value::NauxObj::List(list) = rc.as_ref() {
                Some(list.borrow().clone())
            } else {
                None
            }
        }
        _ => None,
    }
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
        Value::RcObj(rc) => {
            if let naux::runtime::value::NauxObj::List(items) = rc.as_ref() {
                let items = items.borrow();
                assert_eq!(items.first(), Some(&Value::Float(1.0)));
                match items.get(1) {
                    Some(Value::RcObj(rest_rc)) => {
                        if let naux::runtime::value::NauxObj::List(rest) = rest_rc.as_ref() {
                            assert_eq!(rest.borrow().as_slice(), &[Value::Float(2.0)]);
                        } else {
                            panic!("unexpected tail queue");
                        }
                    }
                    other => panic!("unexpected tail queue: {:?}", other),
                }
            } else {
                panic!("unexpected queue_pop result");
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
        Value::RcObj(rc) => {
            if let naux::runtime::value::NauxObj::List(items) = rc.as_ref() {
                let items = items.borrow();
                assert_eq!(items.first(), Some(&Value::Float(1.0))); // min element
                match items.get(1) {
                    Some(Value::RcObj(pq_rc)) => {
                        if let naux::runtime::value::NauxObj::PriorityQueue(v) = pq_rc.as_ref() {
                            let mut got = v.borrow().clone();
                            got.sort_by(|a, b| a.as_f64().partial_cmp(&b.as_f64()).unwrap());
                            assert_eq!(got, vec![Value::Float(3.0), Value::Float(5.0)]);
                        } else {
                            panic!("expected priority queue");
                        }
                    }
                    other => panic!("expected priority queue, got {:?}", other),
                }
            } else {
                panic!("unexpected pq_pop_min result");
            }
        }
        other => panic!("unexpected pq_pop_min result: {:?}", other),
    }
}
