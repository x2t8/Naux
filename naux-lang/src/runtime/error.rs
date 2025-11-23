use crate::ast::Span;

#[derive(Debug, Clone)]
pub struct Frame {
    pub name: String,
    pub span: Option<Span>,
}

#[derive(Debug, Clone)]
pub struct RuntimeError {
    pub message: String,
    pub span: Option<Span>,
    pub trace: Vec<Frame>,
}

impl RuntimeError {
    pub fn new(message: impl Into<String>, span: Option<Span>) -> Self {
        Self {
            message: message.into(),
            span,
            trace: Vec::new(),
        }
    }

    pub fn with_trace(message: impl Into<String>, span: Option<Span>, trace: Vec<Frame>) -> Self {
        Self {
            message: message.into(),
            span,
            trace,
        }
    }
}

pub fn format_runtime_error(src: &str, err: &RuntimeError) -> String {
    let trace_rendered = format_trace(src, err, None);
    if let Some(span) = &err.span {
        let line_idx = span.line.saturating_sub(1);
        let line_text = src.lines().nth(line_idx).unwrap_or("");
        let caret = format!("{}^", " ".repeat(span.column.saturating_sub(1)));
        format!(
            "Runtime error: {}\n --> line {}, col {}\n {}\n {}{}",
            err.message, span.line, span.column, line_text, caret, trace_rendered
        )
    } else {
        format!("Runtime error: {}{}", err.message, trace_rendered)
    }
}

pub fn format_runtime_error_with_file(src: &str, err: &RuntimeError, filename: &str) -> String {
    let trace_rendered = format_trace(src, err, Some(filename));
    if let Some(span) = &err.span {
        let line_idx = span.line.saturating_sub(1);
        let line_text = src.lines().nth(line_idx).unwrap_or("");
        let caret = format!("{}^", " ".repeat(span.column.saturating_sub(1)));
        format!(
            "Runtime error: {}\n --> {}:{}:{}\n {}\n {}{}",
            err.message, filename, span.line, span.column, line_text, caret, trace_rendered
        )
    } else {
        format!("Runtime error: {}{}", err.message, trace_rendered)
    }
}

pub fn format_runtime_error_html(src: &str, err: &RuntimeError, filename: &str) -> String {
    let trace_rendered = html_trace(src, err, Some(filename));
    if let Some(span) = &err.span {
        let line_idx = span.line.saturating_sub(1);
        let line_text = src.lines().nth(line_idx).unwrap_or("");
        let caret = "&nbsp;".repeat(span.column.saturating_sub(1)) + "^";
        format!(
            "<div class=\"error\"><strong>Runtime error:</strong> {}<br/>{}:{}:{}<pre>{}</pre><pre>{}</pre>{}</div>",
            html_escape(&err.message),
            html_escape(filename),
            span.line,
            span.column,
            html_escape(line_text),
            caret,
            trace_rendered
        )
    } else {
        let trace = html_trace(src, err, Some(filename));
        format!("<div class=\"error\">Runtime error: {}{}</div>", html_escape(&err.message), trace)
    }
}

fn format_trace(src: &str, err: &RuntimeError, file: Option<&str>) -> String {
    if err.trace.is_empty() {
        return String::new();
    }
    let mut lines = String::new();
    for frame in err.trace.iter().rev() {
        if let Some(sp) = &frame.span {
            let fname = file.unwrap_or("<unknown>");
            lines.push_str(&format!("\n  at {} ({}:{}:{})", frame.name, fname, sp.line, sp.column));
            // optional snippet caret for last frame? keep concise
            let line_idx = sp.line.saturating_sub(1);
            if let Some(line_text) = src.lines().nth(line_idx) {
                lines.push_str(&format!("\n    {}\n    {}^", line_text, " ".repeat(sp.column.saturating_sub(1))));
            }
        } else {
            lines.push_str(&format!("\n  at {}", frame.name));
        }
    }
    lines
}

fn html_trace(src: &str, err: &RuntimeError, file: Option<&str>) -> String {
    if err.trace.is_empty() {
        return String::new();
    }
    let mut items = String::new();
    for frame in err.trace.iter().rev() {
        if let Some(sp) = &frame.span {
            let fname = file.unwrap_or("<unknown>");
            let mut snippet = String::new();
            if let Some(line_text) = src.lines().nth(sp.line.saturating_sub(1)) {
                snippet = format!("<pre>{}</pre><pre>{}</pre>", html_escape(line_text), "&nbsp;".repeat(sp.column.saturating_sub(1)) + "^");
            }
            items.push_str(&format!("<li>{} ({}:{}:{}){}</li>", html_escape(&frame.name), html_escape(fname), sp.line, sp.column, snippet));
        } else {
            items.push_str(&format!("<li>{}</li>", html_escape(&frame.name)));
        }
    }
    format!("<ul class=\"log\">{}</ul>", items)
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
