use naux::lexer::lex;
use naux::parser::parser::Parser;
use naux::renderer::html::render_html;
use naux::runtime::eval_script;
use naux::runtime::events::RuntimeEvent;

fn eval_src(src: &str) -> (Vec<RuntimeEvent>, Vec<naux::runtime::error::RuntimeError>) {
    let tokens = lex(src).expect("lex should succeed");
    let ast = Parser::from_tokens(&tokens).expect("parse should succeed");
    let (_env, events, errs) = eval_script(&ast);
    (events, errs)
}

#[test]
fn runtime_keeps_unicode_string_literal() {
    let src = r#"
~ rite
    !say "Xin chào 🌍"
~ end
"#;
    let (events, errs) = eval_src(src);
    assert!(errs.is_empty(), "runtime errors: {:?}", errs);
    assert!(events
        .iter()
        .any(|e| matches!(e, RuntimeEvent::Say(text) if text == "Xin chào 🌍")));
}

#[test]
fn html_renderer_preserves_unicode_and_escapes_symbols() {
    let events = vec![RuntimeEvent::Text(
        "Tiếng Việt 🌟 <tag> & dữ liệu".to_string(),
    )];
    let out = render_html(&events, &[]);

    assert!(out.contains("Tiếng Việt 🌟"), "{}", out);
    assert!(out.contains("&lt;tag&gt; &amp; dữ liệu"), "{}", out);
}
