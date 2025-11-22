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
fn bfs_small_graph() {
    let src = r#"
    $g = graph_new()
    $_ = graph_add_edge($g, "A", "B", 1)
    $_ = graph_add_edge($g, "A", "C", 1)
    $_ = graph_add_edge($g, "B", "D", 1)
    $order = graph_bfs($g, "A")
"#;
    assert_eq!(
        run_and_get(src, "order"),
        Value::List(vec![
            Value::Text("A".into()),
            Value::Text("B".into()),
            Value::Text("C".into()),
            Value::Text("D".into()),
        ])
    );
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
    assert_eq!(
        run_and_get(src, "path"),
        Value::List(vec![
            Value::Text("S".into()),
            Value::Text("A".into()),
            Value::Text("B".into()),
            Value::Text("T".into()),
        ])
    );
}
