use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::runtime::eval_script;
use naux::runtime::value::{NauxObj, Value};

fn run_and_get(src: &str, var: &str) -> Value {
    let tokens = lex(src).unwrap();
    let ast = Parser::from_tokens(&tokens).unwrap();
    let (env, _events, errs) = eval_script(&ast);
    assert!(errs.is_empty(), "runtime errors: {:?}", errs);
    env.get(var).unwrap_or(Value::Null)
}

#[test]
fn bfs_small_graph() {
    let src = r#"
    $g = graph_new()
    $_ = graph_add_edge($g, "A", "B", 1)
    $_ = graph_add_edge($g, "A", "C", 1)
    $_ = graph_add_edge($g, "B", "D", 1)
    $order = graph_bfs($g, "A")
"#;
    match run_and_get(src, "order") {
        Value::RcObj(rc) => {
            if let NauxObj::List(v) = rc.as_ref() {
                assert_eq!(
                    v.borrow().as_slice(),
                    &[
                        Value::make_text("A"),
                        Value::make_text("B"),
                        Value::make_text("C"),
                        Value::make_text("D")
                    ]
                );
            } else {
                panic!("expected list");
            }
        }
        other => panic!("unexpected bfs result: {:?}", other),
    }
}

#[test]
fn dijkstra_path() {
    let src = r#"
    $g = graph_new(true)
    $_ = graph_add_edge($g, "S", "A", 1)
    $_ = graph_add_edge($g, "A", "B", 2)
    $_ = graph_add_edge($g, "S", "C", 4)
    $_ = graph_add_edge($g, "B", "T", 1)
    $_ = graph_add_edge($g, "C", "T", 10)
    $path = graph_dijkstra($g, "S", "T")
"#;
    let expected: std::collections::HashMap<String, Value> = [
        (
            "path".into(),
            Value::make_list(vec![
                Value::make_text("S"),
                Value::make_text("A"),
                Value::make_text("B"),
                Value::make_text("T"),
            ]),
        ),
        ("distance".into(), Value::Float(4.0)),
    ]
    .into_iter()
    .collect();
    assert_eq!(run_and_get(src, "path"), Value::make_map(expected));
}

#[test]
fn astar_path_matches_dijkstra() {
    let src = r#"
    $g = graph_new(true)
    $_ = graph_add_edge($g, "S", "A", 1)
    $_ = graph_add_edge($g, "A", "B", 2)
    $_ = graph_add_edge($g, "S", "C", 4)
    $_ = graph_add_edge($g, "B", "T", 1)
    $_ = graph_add_edge($g, "C", "T", 10)
    $path = graph_astar($g, "S", "T")
"#;
    let res = run_and_get(src, "path");
    match res {
        Value::RcObj(rc) => {
            if let NauxObj::Map(map) = rc.as_ref() {
                let m = map.borrow();
                let dist = m.get("distance").and_then(|v| v.as_f64()).unwrap();
                assert!((dist - 4.0).abs() < f64::EPSILON);
                let path_list = m.get("path").cloned().unwrap();
                if let Value::RcObj(prc) = path_list {
                    if let NauxObj::List(v) = prc.as_ref() {
                        assert_eq!(
                            v.borrow().as_slice(),
                            &[
                                Value::make_text("S"),
                                Value::make_text("A"),
                                Value::make_text("B"),
                                Value::make_text("T")
                            ]
                        );
                    } else {
                        panic!("expected list");
                    }
                } else {
                    panic!("expected path list");
                }
            } else {
                panic!("expected map");
            }
        }
        other => panic!("unexpected astar result: {:?}", other),
    }
}

#[test]
fn bridges_and_articulation_points() {
    let src = r#"
    $g = graph_new(false)
    $_ = graph_add_edge($g, "A", "B", 1)
    $_ = graph_add_edge($g, "B", "C", 1)
    $_ = graph_add_edge($g, "C", "D", 1)
    $_ = graph_add_edge($g, "D", "B", 1)
    $_ = graph_add_edge($g, "C", "E", 1)
    $_ = graph_add_edge($g, "E", "F", 1)
    $bridges = graph_bridges($g)
    $arts = graph_articulation_points($g)
"#;
    let bridges = run_and_get(src, "bridges");
    if let Value::RcObj(rc) = bridges {
        if let NauxObj::List(list) = rc.as_ref() {
            let mut pairs: Vec<(String, String)> = Vec::new();
            for v in list.borrow().iter() {
                if let Value::RcObj(mrc) = v {
                    if let NauxObj::Map(m) = mrc.as_ref() {
                        let mb = m.borrow();
                        let u = mb.get("u").unwrap().as_text().unwrap();
                        let v = mb.get("v").unwrap().as_text().unwrap();
                        pairs.push((u, v));
                    }
                }
            }
            pairs.sort();
            assert_eq!(
                pairs,
                vec![
                    ("A".into(), "B".into()),
                    ("C".into(), "E".into()),
                    ("E".into(), "F".into())
                ]
            );
        } else {
            panic!("bridges should be list");
        }
    } else {
        panic!("bridges not list");
    }

    let arts = run_and_get(src, "arts");
    if let Value::RcObj(rc) = arts {
        if let NauxObj::List(list) = rc.as_ref() {
            let mut nodes: Vec<String> = list.borrow().iter().filter_map(|v| v.as_text()).collect();
            nodes.sort();
            assert_eq!(
                nodes,
                vec!["B".to_string(), "C".to_string(), "E".to_string()]
            );
        } else {
            panic!("arts should be list");
        }
    } else {
        panic!("arts not list");
    }
}
