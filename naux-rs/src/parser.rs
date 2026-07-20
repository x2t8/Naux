use naux::ast::Stmt;

#[derive(Debug, Clone)]
pub struct ParseError {
    pub line: usize,
    pub column: usize,
    pub message: String,
}

pub type Program = Vec<Stmt>;

fn normalize_legacy_source(src: &str) -> String {
    let mut out = String::new();
    for line in src.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("~ rite ") {
            let indent = line.len().saturating_sub(trimmed.len());
            out.push_str(&" ".repeat(indent));
            out.push_str("~ rite");
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

pub fn parse(src: &str) -> Result<Program, ParseError> {
    let normalized = normalize_legacy_source(src);
    let tokens = naux::lexer::lex(&normalized).map_err(|e| ParseError {
        line: e.span.line,
        column: e.span.column,
        message: e.message,
    })?;
    naux::parser::Parser::from_tokens(&tokens).map_err(|e| ParseError {
        line: e.span.line,
        column: e.span.column,
        message: e.message,
    })
}

pub fn format_parse_error(src: &str, err: &ParseError) -> String {
    let line_text = src.lines().nth(err.line.saturating_sub(1)).unwrap_or("");
    let caret = format!("{}^", " ".repeat(err.column.saturating_sub(1)));
    format!(
        "Parse error: {}\nline {}:{}\n{}\n{}",
        err.message, err.line, err.column, line_text, caret
    )
}
