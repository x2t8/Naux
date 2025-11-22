use crate::ast::Span;

#[derive(Debug, Clone)]
pub struct RuntimeError {
    pub message: String,
    pub span: Option<Span>,
}

impl RuntimeError {
    pub fn new(message: impl Into<String>, span: Option<Span>) -> Self {
        Self {
            message: message.into(),
            span,
        }
    }
}

pub fn format_runtime_error(src: &str, err: &RuntimeError) -> String {
    if let Some(span) = &err.span {
        let line_idx = span.line.saturating_sub(1);
        let line_text = src.lines().nth(line_idx).unwrap_or("");
        let caret = format!("{}^", " ".repeat(span.column.saturating_sub(1)));
        format!(
            "Runtime error: {}\n --> line {}, col {}\n {}\n {}",
            err.message, span.line, span.column, line_text, caret
        )
    } else {
        format!("Runtime error: {}", err.message)
    }
}

pub fn format_runtime_error_with_file(src: &str, err: &RuntimeError, filename: &str) -> String {
    if let Some(span) = &err.span {
        let line_idx = span.line.saturating_sub(1);
        let line_text = src.lines().nth(line_idx).unwrap_or("");
        let caret = format!("{}^", " ".repeat(span.column.saturating_sub(1)));
        format!(
            "Runtime error: {}\n --> {}:{}:{}\n {}\n {}",
            err.message, filename, span.line, span.column, line_text, caret
        )
    } else {
        format!("Runtime error: {}", err.message)
    }
}

pub fn format_runtime_error_html(src: &str, err: &RuntimeError, filename: &str) -> String {
    if let Some(span) = &err.span {
        let line_idx = span.line.saturating_sub(1);
        let line_text = src.lines().nth(line_idx).unwrap_or("");
        let caret = "&nbsp;".repeat(span.column.saturating_sub(1)) + "^";
        format!(
            "<div class=\"error\"><strong>Runtime error:</strong> {}<br/>{}:{}:{}<pre>{}</pre><pre>{}</pre></div>",
            html_escape(&err.message),
            html_escape(filename),
            span.line,
            span.column,
            html_escape(line_text),
            caret
        )
    } else {
        format!("<div class=\"error\">Runtime error: {}</div>", html_escape(&err.message))
    }
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
