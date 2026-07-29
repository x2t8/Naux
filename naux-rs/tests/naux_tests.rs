use naux_rs::ask::query_ask;
use naux_rs::parser::{format_parse_error, parse};
use naux_rs::renderer;
use naux_rs::runtime::{run_program, Context, RuntimeEvent, Value};

fn collect_final_events(ctx: &Context) -> Vec<RuntimeEvent> {
    let mut final_events = Vec::new();
    for ev in &ctx.events {
        final_events.push(ev.clone());
        if let RuntimeEvent::AskRequest(prompt) = ev {
            let ans = query_ask(prompt);
            final_events.push(RuntimeEvent::AskResponse(ans));
        }
    }
    final_events
}

#[test]
fn unicode_strings_preserved() {
    let src = r#"
$name = "Cốt truyện"
!say "Xin chào " + $name
"#;
    let program = parse(src).expect("parse");
    let mut ctx = Context::new();
    run_program(&program, Some("Main"), &mut ctx);
    let events = collect_final_events(&ctx);
    let rendered = renderer::render_html(&events);
    assert!(rendered.contains("Xin chào Cốt truyện"));
}

#[test]
fn parser_error_snippet() {
    let src = "~ rite\n    !say \"ok\"\n    $ = 3\n~ end\n";
    let err = parse(src).expect_err("should fail");
    let msg = format_parse_error(src, &err);
    assert!(msg.contains("line 3"));
    assert!(msg.contains("^"));
}

#[test]
fn ask_request_response_added() {
    let src = "!ask \"Hello?\"\n";
    let program = parse(src).unwrap();
    let mut ctx = Context::new();
    run_program(&program, Some("Main"), &mut ctx);
    let events = collect_final_events(&ctx);
    assert!(matches!(
        events.first(),
        Some(RuntimeEvent::AskRequest(_))
    ));
    assert!(
        matches!(events.get(1), Some(RuntimeEvent::AskResponse(resp)) if resp.contains("Hello?"))
    );
}

#[test]
fn renderer_cli_contains_ask_response() {
    let events = vec![
        RuntimeEvent::AskRequest("What?".into()),
        RuntimeEvent::AskResponse("(ask reply) What?".into()),
    ];
    // Just ensure it doesn't panic and contains markers.
    renderer::render_cli(&events);
}

#[test]
fn runtime_reports_unknown_action() {
    let src = "!unknown\n";
    assert!(parse(src).is_err());
}

#[test]
fn sort_and_search_work() {
    let src = "$sorted = [1,2,3,4,5]\n$idx = lower_bound($sorted, 4)\n";
    let program = parse(src).unwrap();
    let mut ctx = Context::new();
    run_program(&program, Some("Main"), &mut ctx);
    assert_eq!(
        ctx.get_var("sorted"),
        Some(Value::List(vec![
            Value::Number(1.0),
            Value::Number(2.0),
            Value::Number(3.0),
            Value::Number(4.0),
            Value::Number(5.0),
        ]))
    );
    assert_eq!(ctx.get_var("idx"), Some(Value::Number(3.0)));
}

#[test]
fn gcd_and_pow_mod() {
    let src = "$g = gcd(48, 18)\n$f = pow_mod(2, 10, 1000)\n";
    let program = parse(src).unwrap();
    let mut ctx = Context::new();
    run_program(&program, Some("Main"), &mut ctx);
    assert_eq!(ctx.get_var("g"), Some(Value::Number(6.0)));
    assert_eq!(ctx.get_var("f"), Some(Value::Number(24.0)));
}
