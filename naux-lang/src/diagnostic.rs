use crate::ast::Span;

pub const S1_DIAGNOSTIC_MAX_MESSAGE_CHARS: usize = 512;
pub const S1_DIAGNOSTIC_MAX_FILENAME_CHARS: usize = 512;
pub const S1_DIAGNOSTIC_MAX_SNIPPET_CHARS: usize = 160;

const S1_DIAGNOSTIC_LEFT_CONTEXT_CHARS: usize = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticStage {
    Lex,
    Parse,
    Type,
    Runtime,
}

impl DiagnosticStage {
    const fn label(self) -> &'static str {
        match self {
            Self::Lex => "Lex",
            Self::Parse => "Parse",
            Self::Type => "Type",
            Self::Runtime => "Runtime",
        }
    }
}

/// Render the stable S1 text diagnostic shared by normal `run` and `check`
/// paths. All source-derived fields are bounded and control characters are
/// escaped before the value reaches a terminal.
pub fn format_source_diagnostic(
    stage: DiagnosticStage,
    message: &str,
    source: &str,
    filename: &str,
    span: Option<&Span>,
) -> String {
    let message = escape_terminal_bounded(message, S1_DIAGNOSTIC_MAX_MESSAGE_CHARS);
    let mut rendered = format!("{} error: {}", stage.label(), message);

    let Some(span) = span else {
        return rendered;
    };

    let line_number = span.line.max(1);
    let column = span.column.max(1);
    let filename = escape_terminal_bounded(filename, S1_DIAGNOSTIC_MAX_FILENAME_CHARS);
    let line = source_line(source, line_number);
    let (snippet, caret_offset) = render_source_window(line, column);
    let gutter_width = line_number.to_string().len();

    rendered.push_str(&format!(
        "\n --> {filename}:{line_number}:{column}\n{empty:>gutter_width$} |\n{line_number:>gutter_width$} | {snippet}\n{empty:>gutter_width$} | {padding}^",
        empty = "",
        padding = " ".repeat(caret_offset),
    ));
    rendered
}

pub(crate) fn escape_terminal_bounded(input: &str, max_chars: usize) -> String {
    let mut output = String::new();
    let mut chars = input.chars();
    for ch in chars.by_ref().take(max_chars) {
        push_terminal_safe(&mut output, ch);
    }
    if chars.next().is_some() {
        output.push_str("...");
    }
    output
}

fn source_line(source: &str, line_number: usize) -> &str {
    let line = source
        .split('\n')
        .nth(line_number.saturating_sub(1))
        .unwrap_or("");
    line.strip_suffix('\r').unwrap_or(line)
}

fn render_source_window(line: &str, column: usize) -> (String, usize) {
    let chars = line.chars().collect::<Vec<_>>();
    let focus = column.saturating_sub(1).min(chars.len());
    let mut start = focus.saturating_sub(S1_DIAGNOSTIC_LEFT_CONTEXT_CHARS);
    let mut end = (start + S1_DIAGNOSTIC_MAX_SNIPPET_CHARS).min(chars.len());
    if end == chars.len() {
        start = end.saturating_sub(S1_DIAGNOSTIC_MAX_SNIPPET_CHARS);
    }
    end = (start + S1_DIAGNOSTIC_MAX_SNIPPET_CHARS).min(chars.len());

    let mut snippet = String::new();
    if start > 0 {
        snippet.push_str("...");
    }
    for ch in &chars[start..end] {
        push_terminal_safe(&mut snippet, *ch);
    }
    if end < chars.len() {
        snippet.push_str("...");
    }

    let mut caret_offset = usize::from(start > 0) * 3;
    for ch in &chars[start..focus] {
        let before = snippet_width(*ch);
        caret_offset = caret_offset.saturating_add(before);
    }
    (snippet, caret_offset)
}

fn snippet_width(ch: char) -> usize {
    let mut rendered = String::new();
    push_terminal_safe(&mut rendered, ch);
    rendered.chars().count()
}

fn push_terminal_safe(output: &mut String, ch: char) {
    if is_terminal_unsafe(ch) {
        output.extend(ch.escape_unicode());
    } else {
        output.push(ch);
    }
}

fn is_terminal_unsafe(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{00ad}'
                | '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_diagnostic_has_one_exact_location_shape() {
        let source = "~ rite\n    @\n~ end\n";
        let rendered = format_source_diagnostic(
            DiagnosticStage::Lex,
            "Unexpected character '@'",
            source,
            "sample.nx",
            Some(&Span { line: 2, column: 5 }),
        );
        assert_eq!(
            rendered,
            "Lex error: Unexpected character '@'\n --> sample.nx:2:5\n  |\n2 |     @\n  |     ^"
        );
    }

    #[test]
    fn source_diagnostic_escapes_terminal_controls() {
        let source = "safe\t\u{1b}[31m\n";
        let rendered = format_source_diagnostic(
            DiagnosticStage::Runtime,
            "bad\nmessage\u{1b}",
            source,
            "bad\nname.nx",
            Some(&Span { line: 1, column: 6 }),
        );
        assert!(!rendered.contains('\u{1b}'));
        assert!(rendered.contains("bad\\u{a}message\\u{1b}"));
        assert!(rendered.contains("bad\\u{a}name.nx:1:6"));
        assert!(rendered.contains("safe\\u{9}\\u{1b}[31m"));
    }

    #[test]
    fn source_diagnostic_keeps_caret_inside_a_bounded_long_line_window() {
        let source = format!("{}TARGET{}", "a".repeat(500), "b".repeat(500));
        let rendered = format_source_diagnostic(
            DiagnosticStage::Type,
            "bad value",
            &source,
            "long.nx",
            Some(&Span {
                line: 1,
                column: 501,
            }),
        );
        let snippet = rendered.lines().nth(3).expect("snippet line");
        assert!(snippet.starts_with("1 | ..."));
        assert!(snippet.ends_with("..."));
        assert!(snippet.contains("TARGET"));
        assert!(snippet.chars().count() <= S1_DIAGNOSTIC_MAX_SNIPPET_CHARS + 10);
        assert!(rendered.lines().nth(4).expect("caret line").ends_with('^'));
    }

    #[test]
    fn source_diagnostic_bounds_untrusted_message_and_filename() {
        let rendered = format_source_diagnostic(
            DiagnosticStage::Parse,
            &"m".repeat(S1_DIAGNOSTIC_MAX_MESSAGE_CHARS + 1),
            "x",
            &"f".repeat(S1_DIAGNOSTIC_MAX_FILENAME_CHARS + 1),
            Some(&Span { line: 1, column: 1 }),
        );
        let first = rendered.lines().next().expect("message line");
        let location = rendered.lines().nth(1).expect("location line");
        assert!(first.ends_with("..."));
        assert!(location.contains("...:1:1"));
    }
}
