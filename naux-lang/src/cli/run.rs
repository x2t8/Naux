use std::fs;

use crate::lexer;
use crate::parser;
use crate::renderer::{self, html as html_renderer, cli as cli_renderer};
use crate::runtime;

/// Render mode selected by CLI flags
#[derive(Debug, Clone)]
pub enum RenderMode {
    Cli,
    Html,
}

#[derive(Debug, Clone)]
pub enum EngineMode {
    Interp,
    Vm,
}

/// Entry point called by main
pub fn run(path: &str, mode: RenderMode, engine: EngineMode) -> Result<(), i32> {
    // ---- 1. Read file ----
    let src = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Cannot read file `{}`: {}", path, e);
            return Err(1);
        }
    };

    // ---- 2. Lexical analysis ----
    let tokens = match lexer::lex(&src) {
        Ok(t) => t,
        Err(err) => {
            match mode {
                RenderMode::Cli => {
                    renderer::cli::print_lex_error(&src, &err, path);
                }
                RenderMode::Html => {
                    let page = renderer::html::render_lex_error(&src, &err, path);
                    println!("{}", page);
                }
            }
            return Err(1);
        }
    };

    // ---- 3. Parse AST ----
    let ast = match parser::parser::Parser::from_tokens(&tokens) {
        Ok(ast) => ast,
        Err(err) => {
            match mode {
                RenderMode::Cli => {
                    renderer::cli::print_parser_error(&src, &err, path);
                }
                RenderMode::Html => {
                    let html_page = renderer::html::render_parser_error(&src, &err, path);
                    println!("{}", html_page);
                }
            }
            return Err(1);
        }
    };

    match engine {
        EngineMode::Interp => {
            // ---- 4. Runtime execution ----
            let (_env, events, runtime_errors) = runtime::eval_script(&ast);
            if let Some(err) = runtime_errors.first() {
                match mode {
                    RenderMode::Cli => renderer::cli::print_runtime_error(&src, err, path),
                    RenderMode::Html => {
                        let html_page = renderer::html::render_runtime_error(&src, err, path);
                        println!("{}", html_page);
                    }
                }
                return Err(1);
            }

            // ---- 5. Render output ----
            match mode {
                RenderMode::Cli => {
                    cli_renderer::render_cli(&events);
                }
                RenderMode::Html => {
                    let page = html_renderer::render_html(&events, &[]);
                    println!("{}", page);
                }
            }
        }
        EngineMode::Vm => {
            match crate::vm::run::run_vm(&ast) {
                Ok(val) => match mode {
                    RenderMode::Cli => println!("(vm result) {:?}", val),
                    RenderMode::Html => println!("<pre>{:?}</pre>", val),
                },
                Err(e) => {
                    eprintln!("❌ VM error: {}", e);
                    return Err(1);
                }
            }
        }
    }

    Ok(())
}
