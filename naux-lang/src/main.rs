use clap::Parser;

use std::fs;

use naux::lexer::lex;
use naux::parser::parser::Parser as AstParser;
use naux::parser::error::format_parse_error;
use naux::runtime::{eval_script, RuntimeEvent};
use naux::runtime::error::{format_runtime_error, format_runtime_error_html};
use naux::renderer::{render_cli, render_html};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input .nx file
    #[arg(short, long)]
    file: Option<String>,

    /// Output mode: json|cli|html
    #[arg(short, long, default_value = "json")]
    mode: String,
}

fn main() {
    let args = Args::parse();
    let path = match args.file {
        Some(p) => p,
        None => {
            eprintln!("No input file provided. Use --file <path>");
            std::process::exit(1);
        }
    };

    let src = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to read file {}: {}", path, e);
            std::process::exit(1);
        }
    };

    let tokens = match lex(&src) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Lex error at line {}, col {}: {}", e.span.line, e.span.column, e.message);
            std::process::exit(1);
        }
    };

    let mut parser = AstParser::new(tokens);
    let stmts = match parser.parse_script() {
        Ok(ast) => ast,
        Err(e) => {
            eprintln!("{}", format_parse_error(&src, &e));
            std::process::exit(1);
        }
    };

    let (_env, events, runtime_errors) = eval_script(&stmts);

    match args.mode.as_str() {
        "cli" => {
            if !runtime_errors.is_empty() {
                for err in &runtime_errors {
                    eprintln!("{}", format_runtime_error(&src, err));
                }
            }
            render_cli(&events);
        }
        "html" => {
            let html = render_html(&events, &runtime_errors);
            println!("{}", html);
        }
        "json" | _ => {
            if !runtime_errors.is_empty() {
                for err in &runtime_errors {
                    eprintln!("{}", format_runtime_error(&src, err));
                }
            }
            // crude JSON-ish: just Debug print
            println!("{:?}", events);
        }
    }
}
