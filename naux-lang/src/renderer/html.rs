use crate::parser::error::ParseError;
use crate::runtime::error::RuntimeError;
use crate::runtime::events::RuntimeEvent;

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

pub fn render_parser_error(src: &str, err: &ParseError, path: &str) -> String {
    render_error_page("ParserError", &err.message, src, Some(err.span.clone()), path)
}

pub fn render_runtime_error(src: &str, err: &RuntimeError, path: &str) -> String {
    render_error_page("RuntimeError", &err.message, src, err.span.clone(), path)
}

pub fn render_lex_error(src: &str, err: &crate::token::LexError, path: &str) -> String {
    render_error_page("LexError", &err.message, src, Some(err.span.clone()), path)
}

pub fn render_error_page(kind: &str, msg: &str, src: &str, span: Option<crate::ast::Span>, path: &str) -> String {
    let (line, col, snippet) = if let Some(sp) = span {
        let (line, col) = byte_to_line_col(src, sp);
        let snip = src.lines().nth(line.saturating_sub(1)).unwrap_or("").to_string();
        (line, col, snip)
    } else {
        (0, 0, String::new())
    };

    format!(r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>NAUX — {kind}</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
pre {{ background:#222; padding:10px; }}
.error {{ color:#ff5c8a; font-weight:700; }}
</style>
</head>
<body>
<h1>{kind}</h1>
<p class="error"><strong>{msg}</strong></p>
<p>{path}:{line}:{col}</p>
<pre>{snippet}</pre>
</body>
</html>
"#)
}

fn byte_to_line_col(_src: &str, span: crate::ast::Span) -> (usize, usize) {
    (span.line, span.column)
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
