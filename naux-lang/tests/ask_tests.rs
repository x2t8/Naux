use naux::ask::query_ask;
use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::runtime::eval_script;
use naux::runtime::events::RuntimeEvent;

#[test]
fn ask_stub_is_deterministic() {
    assert_eq!(query_ask("ping"), "ask reply: ping");
}

#[test]
fn ask_action_emits_prompt_then_answer() {
    let src = r#"
~ rite
    !ask "status"
~ end
"#;
    let tokens = lex(src).expect("lex should succeed");
    let ast = Parser::from_tokens(&tokens).expect("parse should succeed");
    let (_env, events, errs) = eval_script(&ast);
    assert!(errs.is_empty(), "runtime errors: {:?}", errs);

    let asks: Vec<(String, String)> = events
        .iter()
        .filter_map(|e| {
            if let RuntimeEvent::Ask { prompt, answer } = e {
                Some((prompt.clone(), answer.clone()))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(asks.len(), 2, "ask events: {:?}", asks);
    assert_eq!(asks[0], ("status".to_string(), "".to_string()));
    assert_eq!(
        asks[1],
        ("status".to_string(), "ask reply: status".to_string())
    );
}
