pub mod ask;
pub mod ast;
pub mod cli;
pub mod core;
pub mod effects;
pub mod elaboration;
pub mod lexer;
pub mod logic;
pub mod parser;
pub mod refinement;
pub mod region;
pub mod renderer;
pub mod runtime;
pub mod stdlib;
pub mod token;
pub mod typecheck;
pub mod vm;

#[cfg(test)]
mod integration_tests;

pub fn run_cli() {
    let cli = match cli::parse_cli() {
        Ok(cli) => cli,
        Err(err) => {
            eprintln!("error: {}", err);
            std::process::exit(1);
        }
    };
    if cli.show_version {
        println!("naux {}", cli::NAUX_VERSION);
        return;
    }
    if let Err(err) = cli::run(cli) {
        eprintln!("error: {}", err);
        std::process::exit(1);
    }
}
