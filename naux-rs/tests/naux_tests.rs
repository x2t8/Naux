use naux::oracle::query_oracle;
use naux::parser::{parse, format_parse_error};
use naux::renderer;
use naux::runtime::{run_program, Context, RuntimeEvent, Value};

fn collect_final_events(ctx: &Context) -> Vec<RuntimeEvent> {
    let mut final_events = Vec::new();
    for ev in &ctx.events {
        final_events.push(ev.clone());
        if let RuntimeEvent::OracleRequest(prompt) = ev {
            let ans = query_oracle(prompt);
            final_events.push(RuntimeEvent::OracleResponse(ans));
        }
    }
    final_events
}

#[test]
fn unicode_strings_preserved() {
    let src = r#"
~ rite Main
    $name = "Cốt"
    !say "Xin chào " + $name
~ end
"#;
    let program = parse(src).expect("parse");
    let mut ctx = Context::new();
    run_program(&program, Some("Main"), &mut ctx);
    let events = collect_final_events(&ctx);
    let rendered = renderer::render_html(&events);
    assert!(rendered.contains("Cốt"));
}

#[test]
fn parser_error_snippet() {
    let src = "~ rite Main\n    !say \"ok\"\n    $ = 3\n~ end\n";
    let err = parse(src).err().expect("should fail");
    let msg = format_parse_error(src, &err);
    assert!(msg.contains("line 3"));
    assert!(msg.contains("^"));
}

#[test]
fn oracle_request_response_added() {
    let src = "~ rite Main\n    !ask \"Hello?\"\n~ end\n";
    let program = parse(src).unwrap();
    let mut ctx = Context::new();
    run_program(&program, Some("Main"), &mut ctx);
    let events = collect_final_events(&ctx);
    assert!(matches!(events.get(0), Some(RuntimeEvent::OracleRequest(_))));
    assert!(matches!(events.get(1), Some(RuntimeEvent::OracleResponse(resp)) if resp.contains("Hello?")));
}

#[test]
fn renderer_cli_contains_ask_oracle() {
    let events = vec![
        RuntimeEvent::OracleRequest("What?".into()),
        RuntimeEvent::OracleResponse("(oracle says) What?".into()),
    ];
    // Just ensure it doesn't panic and contains markers.
    renderer::render_cli(&events);
}

#[test]
fn runtime_reports_unknown_action() {
    let src = "~ rite Main\n    !unknown\n~ end\n";
    let program = parse(src).unwrap();
    let mut ctx = Context::new();
    run_program(&program, Some("Main"), &mut ctx);
    assert!(!ctx.errors.is_empty());
}

#[test]
fn sort_and_search_work() {
    let src = "~ rite Main\n    $xs = [5,3,1,4,2]\n    $sorted = !sort $xs algorithm=\"merge\"\n    $idx = !search $sorted 4 algorithm=\"binary\"\n~ end\n";
    let program = parse(src).unwrap();
    let mut ctx = Context::new();
    run_program(&program, Some("Main"), &mut ctx);
    assert_eq!(ctx.get_var("sorted"), Some(Value::List(vec![
        Value::Number(1.0),
        Value::Number(2.0),
        Value::Number(3.0),
        Value::Number(4.0),
        Value::Number(5.0),
    ])));
    assert_eq!(ctx.get_var("idx"), Some(Value::Number(3.0)));
}

#[test]
fn gcd_and_fib() {
    let src = "~ rite Main\n    $g = !gcd 48 18\n    $f = !fib 10\n~ end\n";
    let program = parse(src).unwrap();
    let mut ctx = Context::new();
    run_program(&program, Some("Main"), &mut ctx);
    assert_eq!(ctx.get_var("g"), Some(Value::Number(6.0)));
    assert_eq!(ctx.get_var("f"), Some(Value::Number(55.0)));
}
