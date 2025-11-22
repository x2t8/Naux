use std::env;
use std::path::Path;

use naux::parser::{parse_file, format_parse_error};
use naux::renderer;
use naux::oracle::query_oracle;
use naux::runtime::RuntimeEvent;
use naux::runtime::{run_program, Context};

fn main() {
    let mut path: Option<String> = None;
    let mut mode = "json".to_string();

    for arg in env::args().skip(1) {
        if let Some(rest) = arg.strip_prefix("--mode=") {
            mode = rest.to_string();
        } else if path.is_none() {
            path = Some(arg);
        }
    }

    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("Usage: cargo run -- <file.nx> [--mode=json|cli|html]");
            std::process::exit(1);
        }
    };

    if !Path::new(&path).exists() {
        eprintln!("File not found: {}", path);
        std::process::exit(1);
    }
    let program = match parse_file(Path::new(&path)) {
        Ok(p) => p,
        Err(e) => {
            let src = std::fs::read_to_string(&path).unwrap_or_default();
            eprintln!("{}", format_parse_error(&src, &e));
            std::process::exit(1);
        }
    };

    let mut ctx = Context::new();
    run_program(&program, Some("Main"), &mut ctx);

    if !ctx.errors.is_empty() {
        for err in &ctx.errors {
            eprintln!("Runtime error: {}", err.message());
        }
    }

    let mut final_events: Vec<RuntimeEvent> = Vec::new();
    for ev in &ctx.events {
        final_events.push(ev.clone());
        if let RuntimeEvent::OracleRequest(prompt) = ev {
            let ans = query_oracle(prompt);
            final_events.push(RuntimeEvent::OracleResponse(ans));
        }
    }

    match mode.as_str() {
        "cli" => renderer::render_cli(&final_events),
        "html" => {
            let html = renderer::render_html(&final_events);
            println!("{}", html);
        }
        "json" | _ => {
            let json = serde_json::to_string_pretty(&final_events).unwrap();
            println!("{}", json);
        }
    }
}
