use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::runtime::eval_script;
use naux::runtime::events::RuntimeEvent;

fn eval_src(src: &str) -> (Vec<RuntimeEvent>, Vec<naux::runtime::error::RuntimeError>) {
    let tokens = lex(src).expect("lex should succeed");
    let ast = Parser::from_tokens(&tokens).expect("parse should succeed");
    let (_env, events, errs) = eval_script(&ast);
    (events, errs)
}

#[test]
fn loop_updates_value_and_emits_say() {
    let src = r#"
~ rite
    $sum = 0
    ~ loop 4
        $sum = $sum + 1
    ~ end
    !say $sum
~ end
"#;
    let (events, errs) = eval_src(src);
    assert!(errs.is_empty(), "runtime errors: {:?}", errs);
    assert!(events
        .iter()
        .any(|e| matches!(e, RuntimeEvent::Say(text) if text == "4")));
}

#[test]
fn each_requires_list_reports_runtime_error() {
    let src = r#"
~ rite
    ~ each item in 123
        !say $item
    ~ end
~ end
"#;
    let (_events, errs) = eval_src(src);
    assert!(
        errs.iter()
            .any(|e| e.message.contains("Each expects a list")),
        "expected each/list runtime error, got: {:?}",
        errs
    );
}
