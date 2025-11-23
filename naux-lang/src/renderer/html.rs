use crate::parser::error::ParseError;
use crate::renderer::css::BASE_STYLE;
use crate::runtime::error::{Frame, RuntimeError};
use crate::runtime::events::RuntimeEvent;

pub fn render_html(events: &[RuntimeEvent], errors: &[RuntimeError]) -> String {
    let mut out = String::new();
    out.push_str("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>NAUX</title><style>");
    out.push_str(BASE_STYLE);
    out.push_str("</style></head><body><section class=\"log\">\n");

    for e in errors {
        let msg = format!("Runtime error: {}", e.message);
        let trace = render_trace(e);
        out.push_str(&format!(
            "<div class=\"card\"><h3>RuntimeError</h3><div class=\"error\">{}</div>{}</div>\n",
            html_escape(&msg),
            trace
        ));
    }

    let mut open_card = false;
    for ev in events {
        match ev {
            RuntimeEvent::Say(msg) => {
                ensure_card(&mut out, &mut open_card, "SAY");
                out.push_str(&format!("<p class=\"say\">{}</p>\n", html_escape(msg)));
            }
            RuntimeEvent::Ask { prompt, answer } => {
                ensure_card(&mut out, &mut open_card, "ORACLE");
                out.push_str(&format!("<p class=\"ask\">? {}</p>\n", html_escape(prompt)));
                out.push_str(&format!("<p class=\"oracle\">= {}</p>\n", html_escape(answer)));
            }
            RuntimeEvent::Fetch { target } => {
                ensure_card(&mut out, &mut open_card, "FETCH");
                out.push_str(&format!("<p class=\"fetch\">~ fetch {}</p>\n", html_escape(target)));
            }
            RuntimeEvent::Ui { kind, .. } => {
                ensure_card(&mut out, &mut open_card, "UI");
                out.push_str(&format!("<p class=\"ui\">ui: {}</p>\n", html_escape(kind)));
            }
            RuntimeEvent::Text(txt) => {
                ensure_card(&mut out, &mut open_card, "TEXT");
                out.push_str(&format!("<p class=\"text\">{}</p>\n", html_escape(txt)));
            }
            RuntimeEvent::Button(lbl) => {
                ensure_card(&mut out, &mut open_card, "BUTTON");
                out.push_str(&format!("<button class=\"button\">{}</button>\n", html_escape(lbl)));
            }
            RuntimeEvent::Log(msg) => {
                ensure_card(&mut out, &mut open_card, "LOG");
                out.push_str(&format!("<p class=\"log\">{}</p>\n", html_escape(msg)));
            }
        }
    }
    if open_card {
        out.push_str("</div>\n");
    }
    out.push_str("</section></body></html>");
    out
}

fn ensure_card(out: &mut String, open_card: &mut bool, title: &str) {
    if !*open_card {
        out.push_str(&format!("<div class=\"card\"><h3>{}</h3>\n", html_escape(title)));
        *open_card = true;
    }
}

fn render_trace(err: &RuntimeError) -> String {
    if err.trace.is_empty() {
        return String::new();
    }
    let mut items = String::new();
    for frame in err.trace.iter().rev() {
        items.push_str(&render_frame(frame));
    }
    format!("<ul class=\"log\">{}</ul>", items)
}

fn render_frame(frame: &Frame) -> String {
    if let Some(sp) = &frame.span {
        format!("<li>{} (line {}, col {})</li>", html_escape(&frame.name), sp.line, sp.column)
    } else {
        format!("<li>{}</li>", html_escape(&frame.name))
    }
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
        let line = sp.line;
        let col = sp.column;
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
<style>{css}</style>
</head>
<body>
<section class="log">
  <div class="card">
    <h3>{kind}</h3>
    <div class="error">{msg}</div>
    <div class="log">{path}:{line}:{col}</div>
    <pre class="snippet">{snippet}</pre>
  </div>
</section>
</body>
</html>
"#,
    css = BASE_STYLE,
    kind = html_escape(kind),
    msg = html_escape(msg),
    path = html_escape(path),
    line = line,
    col = col,
    snippet = html_escape(&snippet))
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
