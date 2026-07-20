use naux::ast::Stmt;
use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::runtime::events::RuntimeEvent;
use naux::typecheck;
use naux::vm::run::{run_jit, run_vm};

fn parse(source: &str) -> Vec<Stmt> {
    let tokens = lex(source).expect("lex failed");
    Parser::from_tokens(&tokens).expect("parse failed")
}

fn say_text(events: &[RuntimeEvent]) -> Option<&str> {
    events.iter().find_map(|event| match event {
        RuntimeEvent::Say(text) => Some(text.as_str()),
        _ => None,
    })
}

#[test]
fn string_number_concat_typechecks_and_matches_vm_jit() {
    let source = r#"
~ rite
    $ans = 42
    !say "Result = " + $ans
~ end
"#;
    let ast = parse(source);
    typecheck::check_program(&ast).expect("typecheck");

    let (vm_events, vm_value) = run_vm(&ast, source, "<p0>").expect("vm run");
    let (jit_events, jit_value, _used_jit) = run_jit(&ast, source, "<p0>").expect("jit run");

    assert_eq!(say_text(&vm_events), Some("Result = 42"));
    assert_eq!(say_text(&jit_events), Some("Result = 42"));
    assert_eq!(vm_value, jit_value);
}

#[test]
fn to_text_uses_user_facing_collection_format() {
    let source = r#"
~ rite
    $items = [1, "A"]
    !say to_text($items)
~ end
"#;
    let ast = parse(source);
    typecheck::check_program(&ast).expect("typecheck");

    let (events, _value) = run_vm(&ast, source, "<p0>").expect("vm run");
    let text = say_text(&events).expect("say event");

    assert_eq!(text, "List [1, A]");
    assert!(!text.contains("RcObj"));
    assert!(!text.contains("RefCell"));
}

#[test]
fn unicode_identifiers_survive_lex_parse_typecheck() {
    let source = r#"
~ rite
    $kết_quả = 7
    !say "Kết quả = " + $kết_quả
~ end
"#;
    let ast = parse(source);
    typecheck::check_program(&ast).expect("typecheck");

    let (events, _value) = run_vm(&ast, source, "<p0>").expect("vm run");
    assert_eq!(say_text(&events), Some("Kết quả = 7"));
}
