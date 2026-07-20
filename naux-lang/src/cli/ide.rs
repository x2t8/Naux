use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::cli::util;
use crate::cli::DefaultEngine;
use crate::lexer;
use crate::parser;
use crate::parser::error::format_parse_error;
use crate::renderer::render_cli;
use crate::typecheck;

pub fn handle_ide(path: Option<PathBuf>) -> Result<(), String> {
    let mut current_path = path.unwrap_or_else(|| PathBuf::from("main.nx"));
    let mut buffer = load_file_lines(&current_path)?;
    print_banner(&current_path, buffer.len());
    print_help();

    loop {
        print!("ide> ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            break;
        }
        let line = input.trim_end();
        if line.is_empty() {
            continue;
        }
        if !line.starts_with(':') {
            println!("(hint) commands start with ':' - try :help or :append");
            continue;
        }
        let mut parts = line.split_whitespace();
        let cmd = parts.next().unwrap_or("");
        match cmd {
            ":help" => print_help(),
            ":show" => show_buffer(&buffer),
            ":check" => {
                if let Err(err) = check_buffer(&buffer, &current_path) {
                    println!("{}", err);
                }
            }
            ":append" => {
                let added = read_block(":end")?;
                buffer.extend(added);
                println!("(added {} lines)", buffer.len());
            }
            ":insert" => {
                let idx = parse_index(parts.next());
                match idx {
                    Some(pos) => {
                        let added = read_block(":end")?;
                        let insert_at = pos.saturating_sub(1).min(buffer.len());
                        buffer.splice(insert_at..insert_at, added);
                        println!("(inserted, total {} lines)", buffer.len());
                    }
                    None => println!("Usage: :insert <line>"),
                }
            }
            ":replace" => {
                let idx = parse_index(parts.next());
                match idx {
                    Some(pos) => {
                        if pos == 0 || pos > buffer.len() {
                            println!("Line out of range");
                            continue;
                        }
                        print!("new> ");
                        io::stdout().flush().map_err(|e| e.to_string())?;
                        let mut newline = String::new();
                        if io::stdin().read_line(&mut newline).is_err() {
                            continue;
                        }
                        buffer[pos - 1] = newline.trim_end().to_string();
                        println!("(replaced line {})", pos);
                    }
                    None => println!("Usage: :replace <line>"),
                }
            }
            ":delete" => {
                let idx = parse_index(parts.next());
                match idx {
                    Some(pos) => {
                        if pos == 0 || pos > buffer.len() {
                            println!("Line out of range");
                            continue;
                        }
                        buffer.remove(pos - 1);
                        println!("(deleted line {})", pos);
                    }
                    None => println!("Usage: :delete <line>"),
                }
            }
            ":open" => {
                if let Some(p) = parts.next() {
                    current_path = PathBuf::from(p);
                    buffer = load_file_lines(&current_path)?;
                    print_banner(&current_path, buffer.len());
                } else {
                    println!("Usage: :open <path>");
                }
            }
            ":save" => {
                save_file(&current_path, &buffer)?;
                println!("(saved {})", current_path.display());
            }
            ":run" => {
                let engine = parse_engine(parts.next());
                run_buffer(engine, &buffer, &current_path)?;
            }
            ":quit" | ":q" | ":exit" => break,
            _ => println!("Unknown command. Type :help"),
        }
    }
    Ok(())
}

fn print_banner(path: &Path, lines: usize) {
    println!("NAUX IDE (TUI) - terminal editor/checker/runner");
    println!("File: {}  Lines: {}", path.display(), lines);
}

fn print_help() {
    println!("Commands:");
    println!("  :show                 show buffer with line numbers");
    println!("  :check                lex/parse/typecheck buffer");
    println!("  :append               append lines (finish with :end)");
    println!("  :insert <line>        insert lines before line (finish with :end)");
    println!("  :replace <line>       replace a single line");
    println!("  :delete <line>        delete a line");
    println!("  :open <path>          open another file");
    println!("  :save                 save current file");
    println!("  :run [vm|interp]      run buffer (default vm)");
    println!("  :quit                 exit IDE");
}

fn show_buffer(buffer: &[String]) {
    if buffer.is_empty() {
        println!("(empty)");
        return;
    }
    for (i, line) in buffer.iter().enumerate() {
        println!("{:>4} | {}", i + 1, line);
    }
}

fn read_block(end_marker: &str) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    loop {
        print!("> ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line).is_err() {
            break;
        }
        let trimmed = line.trim_end();
        if trimmed == end_marker {
            break;
        }
        lines.push(trimmed.to_string());
    }
    Ok(lines)
}

fn parse_index(token: Option<&str>) -> Option<usize> {
    token.and_then(|t| t.parse::<usize>().ok())
}

fn load_file_lines(path: &Path) -> Result<Vec<String>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Could not read {}: {}", path.display(), e))?;
    Ok(content.lines().map(|l| l.to_string()).collect())
}

fn save_file(path: &Path, buffer: &[String]) -> Result<(), String> {
    let mut content = buffer.join("\n");
    content.push('\n');
    std::fs::write(path, content)
        .map_err(|e| format!("Could not write {}: {}", path.display(), e))
}

fn parse_engine(token: Option<&str>) -> DefaultEngine {
    match token.unwrap_or("vm").to_ascii_lowercase().as_str() {
        "interp" => DefaultEngine::Interp,
        "vm" => DefaultEngine::Vm,
        _ => DefaultEngine::Vm,
    }
}

fn run_buffer(engine: DefaultEngine, buffer: &[String], path: &Path) -> Result<(), String> {
    let src = buffer.join("\n");
    let tokens = lexer::lex(&src).map_err(|e| format!("Lex error: {}", e.message))?;
    let ast = parser::Parser::from_tokens(&tokens)
        .map_err(|err| format_parse_error(&src, &err, &path.to_string_lossy()))?;
    if let Err(e) = typecheck::check_program(&ast) {
        let loc = e
            .span
            .map(|s| format!(" (line {}, col {})", s.line, s.column))
            .unwrap_or_default();
        return Err(format!("Type error{}: {}", loc, e.message));
    }
    let (events, value) = util::execute_ast(engine, &ast, &src, path, false)?;
    println!("(run {})", engine_name(engine));
    if events.is_empty() {
        if let Some(val) = value {
            println!("> {}", val);
        } else {
            println!("(run) OK");
        }
    } else {
        render_cli(&events);
        if let Some(val) = value {
            println!("> {}", val);
        }
    }
    Ok(())
}

fn engine_name(engine: DefaultEngine) -> &'static str {
    match engine {
        DefaultEngine::Interp => "interp",
        DefaultEngine::Vm => "vm",
        DefaultEngine::Jit => "jit",
    }
}

fn check_buffer(buffer: &[String], path: &Path) -> Result<(), String> {
    let src = buffer.join("\n");
    let tokens = lexer::lex(&src).map_err(|e| format!("Lex error: {}", e.message))?;
    let ast = parser::Parser::from_tokens(&tokens)
        .map_err(|err| format_parse_error(&src, &err, &path.to_string_lossy()))?;
    if let Err(e) = typecheck::check_program(&ast) {
        let loc = e
            .span
            .map(|s| format!(" (line {}, col {})", s.line, s.column))
            .unwrap_or_default();
        return Err(format!("Type error{}: {}", loc, e.message));
    }
    println!("(check) OK");
    Ok(())
}
