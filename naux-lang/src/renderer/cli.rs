use crate::ast::Span;
use crate::parser::error::ParseError;
use crate::runtime::error::{Frame, RuntimeError};
use crate::runtime::events::RuntimeEvent;
use crate::token::LexError;
use std::fmt::Write;

/// Render runtime events in an ASCII-friendly, ritual-ish style.
pub fn render_cli(events: &[RuntimeEvent]) {
    let mut ui_active = false;
    for ev in events {
        match ev {
            RuntimeEvent::Say(msg) => println!("> {}", msg),
            RuntimeEvent::Ask { prompt, answer } => {
                println!("? ASK: {}", prompt);
                println!("= ORACLE: {}", answer);
            }
            RuntimeEvent::Fetch { target } => println!("~ fetch: {}", target),
            RuntimeEvent::Ui { kind, .. } => {
                if ui_active {
                    println!("└──────────────────────────┘");
                }
                println!("┌──────────────────────────┐");
                println!("│ UI: {:<22} │", kind);
                ui_active = true;
            }
            RuntimeEvent::Text(text) => {
                if !ui_active {
                    println!("┌──────────────────────────┐");
                    ui_active = true;
                }
                println!("│   TEXT: {}", text);
            }
            RuntimeEvent::Button(label) => {
                if !ui_active {
                    println!("┌──────────────────────────┐");
                    ui_active = true;
                }
                println!("│   [ {} ]", label);
            }
            RuntimeEvent::Log(msg) => eprintln!("log: {}", msg),
        }
    }
    if ui_active {
        println!("└──────────────────────────┘");
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
    if !err.trace.is_empty() {
        for frame in err.trace.iter().rev() {
            render_frame(src, path, frame);
        }
    }
}

fn render_frame(src: &str, path: &str, frame: &Frame) {
    if let Some(sp) = &frame.span {
        eprintln!("  at {} ({}:{}:{})", frame.name, path, sp.line, sp.column);
        print_snippet(src, sp.clone());
    } else {
        eprintln!("  at {}", frame.name);
    }
}

fn print_snippet(src: &str, span: Span) {
    let line_idx = span.line.saturating_sub(1);
    if let Some(line_str) = src.lines().nth(line_idx) {
        let gutter = span.line.to_string();
        eprintln!("{} | {}", gutter, line_str);
        eprintln!("{}   {}^", " ".repeat(gutter.len()), " ".repeat(span.column.saturating_sub(1)));
    }
}

pub fn render_cli_to_string(events: &[RuntimeEvent]) -> String {
    let mut out = String::new();
    let mut ui_active = false;
    for ev in events {
        match ev {
            RuntimeEvent::Say(msg) => {
                writeln!(&mut out, "> {}", msg).ok();
            }
            RuntimeEvent::Ask { prompt, answer } => {
                writeln!(&mut out, "? ASK: {}", prompt).ok();
                writeln!(&mut out, "= ORACLE: {}", answer).ok();
            }
            RuntimeEvent::Fetch { target } => {
                writeln!(&mut out, "~ fetch: {}", target).ok();
            }
            RuntimeEvent::Ui { kind, .. } => {
                if ui_active {
                    writeln!(&mut out, "└──────────────────────────┘").ok();
                }
                writeln!(&mut out, "┌──────────────────────────┐").ok();
                writeln!(&mut out, "│ UI: {:<22} │", kind).ok();
                ui_active = true;
            }
            RuntimeEvent::Text(text) => {
                if !ui_active {
                    writeln!(&mut out, "┌──────────────────────────┐").ok();
                    ui_active = true;
                }
                writeln!(&mut out, "│   TEXT: {}", text).ok();
            }
            RuntimeEvent::Button(label) => {
                if !ui_active {
                    writeln!(&mut out, "┌──────────────────────────┐").ok();
                    ui_active = true;
                }
                writeln!(&mut out, "│   [ {} ]", label).ok();
            }
            RuntimeEvent::Log(msg) => {
                writeln!(&mut out, "log: {}", msg).ok();
            }
        }
    }
    if ui_active {
        writeln!(&mut out, "└──────────────────────────┘").ok();
    }
    out
}
