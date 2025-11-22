use crate::ast::Span;
use crate::parser::error::ParseError;
use crate::token::LexError;
use crate::runtime::error::RuntimeError;
use crate::runtime::events::RuntimeEvent;

pub fn render_cli(events: &[RuntimeEvent]) {
    for ev in events {
        match ev {
            RuntimeEvent::Say(msg) => println!("{}", msg),
            RuntimeEvent::Ask { prompt, answer } => {
                println!("? ASK: {}", prompt);
                println!("= ORACLE: {}", answer);
            }
            RuntimeEvent::Fetch { target } => println!("~ fetch: {}", target),
            RuntimeEvent::Ui { kind, .. } => println!("~ ui: {}", kind),
            RuntimeEvent::Text(text) => println!("text: {}", text),
            RuntimeEvent::Button(label) => println!("[{}]", label),
            RuntimeEvent::Log(msg) => eprintln!("log: {}", msg),
        }
    }
}

pub fn print_lex_error(src: &str, err: &LexError, path: &str) {
    eprintln!("❌ LexError: {} at {}:{}:{}", err.message, path, err.span.line, err.span.column);
    print_snippet(src, err.span.clone());
}

pub fn print_parser_error(src: &str, err: &ParseError, path: &str) {
    eprintln!("❌ ParserError: {}", err.message);
    eprintln!(" --> {}:{}:{}", path, err.span.line, err.span.column);
    print_snippet(src, err.span.clone());
}

pub fn print_runtime_error(src: &str, err: &RuntimeError, path: &str) {
    eprintln!("❌ RuntimeError: {}", err.message);
    if let Some(span) = &err.span {
        eprintln!(" --> {}:{}:{}", path, span.line, span.column);
        print_snippet(src, span.clone());
    }
}

fn print_snippet(src: &str, span: Span) {
    let line_idx = span.line.saturating_sub(1);
    if let Some(line_str) = src.lines().nth(line_idx) {
        eprintln!("{} | {}", span.line, line_str);
        eprintln!("{}   {}^", " ".repeat(span.line.to_string().len()), " ".repeat(span.column.saturating_sub(1)));
    }
}
