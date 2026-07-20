use naux::ast::Span;
use naux::renderer::cli::render_cli_to_string;
use naux::renderer::html::render_html;
use naux::runtime::error::{Frame, RuntimeError};
use naux::runtime::events::RuntimeEvent;

#[test]
fn cli_renderer_wraps_ui_events_in_frame() {
    let events = vec![
        RuntimeEvent::Ui {
            kind: "panel".to_string(),
            props: Vec::new(),
        },
        RuntimeEvent::Text("hello".to_string()),
        RuntimeEvent::Button("ok".to_string()),
        RuntimeEvent::Say("done".to_string()),
    ];

    let out = render_cli_to_string(&events);
    assert!(out.contains("┌──────────────────────────┐"), "{}", out);
    assert!(out.contains("│ UI: panel"), "{}", out);
    assert!(out.contains("│   TEXT: hello"), "{}", out);
    assert!(out.contains("│   [ ok ]"), "{}", out);
    assert!(out.contains("└──────────────────────────┘"), "{}", out);
    assert!(out.contains("> done"), "{}", out);
}

#[test]
fn html_renderer_escapes_html_sensitive_text() {
    let events = vec![
        RuntimeEvent::Say("<ok>&\"'".to_string()),
        RuntimeEvent::Text("A <tag> & B".to_string()),
    ];

    let out = render_html(&events, &[]);
    assert!(out.contains("&lt;ok&gt;&amp;&quot;&#39;"), "{}", out);
    assert!(out.contains("A &lt;tag&gt; &amp; B"), "{}", out);
}

#[test]
fn html_renderer_renders_runtime_trace_frames() {
    let err = RuntimeError::with_trace(
        "boom",
        Some(Span { line: 1, column: 2 }),
        vec![
            Frame {
                name: "inner".to_string(),
                span: Some(Span {
                    line: 7,
                    column: 11,
                }),
            },
            Frame {
                name: "outer".to_string(),
                span: None,
            },
        ],
    );

    let out = render_html(&[], &[err]);
    assert!(out.contains("RuntimeError"), "{}", out);
    assert!(out.contains("inner (line 7, col 11)"), "{}", out);
    assert!(out.contains("<li>outer</li>"), "{}", out);
}
