use clap::Parser;
mod ast;
mod cli;
mod lexer;
mod parser;
mod renderer;
mod runtime;
mod stdlib;
mod token;
mod vm;
use executor::Executor;
use cli::Cli;

fn main() {
    let cli = Cli::parse();
    if let Err(err) = cli::run(cli) {
        eprintln!("❌ {}", err);
        std::process::exit(1);
    }
}
