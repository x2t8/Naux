use naux::ast::{ActionKind, Stmt};
use naux::runtime::eval_script;
use naux::runtime::events::RuntimeEvent;

#[test]
fn action_variants_emit_events() {
    let stmts = vec![
        Stmt::Action { action: ActionKind::Ui { kind: "card".into(), props: vec![] }, span: None },
        Stmt::Action { action: ActionKind::Text { value: dummy_text("hello") }, span: None },
        Stmt::Action { action: ActionKind::Button { value: dummy_text("ok") }, span: None },
        Stmt::Action { action: ActionKind::Log { value: dummy_text("log") }, span: None },
    ];

    let (_env, events, errs) = eval_script(&stmts);
    assert!(errs.is_empty());
    assert!(events.iter().any(|e| matches!(e, RuntimeEvent::Ui { kind, .. } if kind == "card")));
    assert!(events.iter().any(|e| matches!(e, RuntimeEvent::Text(t) if t == "hello")));
    assert!(events.iter().any(|e| matches!(e, RuntimeEvent::Button(b) if b == "ok")));
    assert!(events.iter().any(|e| matches!(e, RuntimeEvent::Log(l) if l == "log")));
}

fn dummy_text(s: &str) -> naux::ast::Expr {
    naux::ast::Expr::new(naux::ast::ExprKind::Text(s.to_string()), None)
}
