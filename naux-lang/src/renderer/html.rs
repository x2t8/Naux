use crate::runtime::events::RuntimeEvent;
use crate::runtime::error::RuntimeError;

pub fn render_html(events: &[RuntimeEvent], errors: &[RuntimeError]) -> String {
    let mut out = String::new();
    out.push_str("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>NAUX</title><style>body{background:#0a0a0f;color:#f8f8ff;font-family:'Inter',system-ui,sans-serif;padding:24px;} .say{color:#9efcff;} .ask{color:#ffd166;font-weight:600;} .oracle{color:#8ef1b8;font-weight:700;} .log{color:#888;} .error{color:#ff5c8a;font-weight:700;} pre{background:#111122;padding:8px;border-radius:8px;}</style></head><body>\n");
    for e in errors {
        let msg = format!("Runtime error: {}", e.message);
        out.push_str(&format!("<div class=\"error\">{}</div>\n", html_escape(&msg)));
    }
    for ev in events {
        match ev {
            RuntimeEvent::Say(msg) => out.push_str(&format!("<p class=\"say\">{}</p>\n", html_escape(msg))),
            RuntimeEvent::Ask { prompt, answer } => {
                out.push_str(&format!("<p class=\"ask\">? {}</p>\n", html_escape(prompt)));
                out.push_str(&format!("<p class=\"oracle\">= {}</p>\n", html_escape(answer)));
            }
            RuntimeEvent::Fetch { target } => out.push_str(&format!("<p class=\"log\">fetch: {}</p>\n", html_escape(target))),
            RuntimeEvent::Ui { kind, .. } => out.push_str(&format!("<p class=\"log\">ui: {}</p>\n", html_escape(kind))),
            RuntimeEvent::Text(txt) => out.push_str(&format!("<p>{}</p>\n", html_escape(txt))),
            RuntimeEvent::Button(lbl) => out.push_str(&format!("<button>{}</button>\n", html_escape(lbl))),
            RuntimeEvent::Log(msg) => out.push_str(&format!("<p class=\"log\">log: {}</p>\n", html_escape(msg))),
        }
    }
    out.push_str("</body></html>");
    out
}

fn html_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '"' => "&quot;".into(),
            '\'' => "&#39;".into(),
            _ => c.to_string(),
        })
        .collect()
}
