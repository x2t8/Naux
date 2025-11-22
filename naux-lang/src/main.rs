mod cli;
mod lexer;
mod parser;
mod runtime;
mod renderer;
mod oracle;
mod ast;
mod token;
mod stdlib;
mod vm;

use clap::{Parser as ClapParser, Subcommand, ValueEnum};
use colored::*;

// ===== Banner đỏ theo yêu cầu =====
const NAUX_BANNER: &str = r#"
 _   _    ___  _   _  __   __
███╗   ██╗  █████╗  ██╗   ██╗██╗  ██╗
████╗  ██║ ██╔══██╗ ██║   ██║╚██╗██╔╝
██╔██╗ ██║ ███████║ ██║   ██║ ╚███╔╝ 
██║╚██╗██║ ██╔══██║ ██║   ██║ ██╔██╗ 
██║ ╚████║ ██║  ██║ ╚██████╔╝██║╚██╗ 
╚═╝  ╚═══╝ ╚═╝  ╚═╝  ╚═════╝ ╚═╝ ╚═╝ 
"#;

fn print_banner() {
    println!("{}", NAUX_BANNER.truecolor(255, 0, 0).bold());
}

const NAUX_VERSION: &str = "0.2.0-dev";

/// NAUX CLI top-level
#[derive(ClapParser, Debug)]
#[command(
    name = "naux",
    about = "NAUX — Nexus Ascendant Unbound eXecutor",
    disable_version_flag = true,
)]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: Commands,

    /// Print version and exit
    #[arg(long)]
    pub version: bool,
}

/// Subcommands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a ritual (.nx file)
    Run {
        file: String,
        #[arg(long, default_value = "cli")]
        mode: RenderMode,
        /// Execution engine (interp/vm)
        #[arg(long, default_value = "interp")]
        engine: EngineMode,
    },

    /// Build ritual package (future compiler/VM)
    Build {
        file: String,
    },

    /// Format a ritual script
    Fmt {
        file: String,
    },

    /// Initialize a NAUX project scaffold
    Init {
        path: String,
    },
}

/// Renderer mode
#[derive(ValueEnum, Debug, Clone)]
pub enum RenderMode {
    Cli,
    Html,
}

#[derive(ValueEnum, Debug, Clone)]
pub enum EngineMode {
    Interp,
    Vm,
}
fn main() {
    let args = CliArgs::parse();

    // Handle version flag
    if args.version {
        println!("NAUX {}", NAUX_VERSION);
        return;
    }

    // Show banner
    print_banner();

    match args.command {
        // ---- RUN ----
        Commands::Run { file, mode, engine } => {
            let mode = match mode {
                RenderMode::Cli => cli::run::RenderMode::Cli,
                RenderMode::Html => cli::run::RenderMode::Html,
            };
            let engine = match engine {
                EngineMode::Interp => cli::run::EngineMode::Interp,
                EngineMode::Vm => cli::run::EngineMode::Vm,
            };

            std::process::exit(match cli::run::run(&file, mode, engine) {
                Ok(_) => 0,
                Err(code) => code,
            });
        }

        // ---- BUILD ----
        Commands::Build { file } => {
            println!("{}", "⚒️  Building ritual…".yellow().bold());
            cli::build::build(&file);
        }

        // ---- FORMAT ----
        Commands::Fmt { file } => {
            println!("{}", "✨ Formatting ritual…".cyan().bold());
            cli::format::format(&file);
        }

        Commands::Init { path } => {
            println!("{}", "⚙️  Initializing project…".bright_blue());
            cli::init::init_project(&path);
        }
    }
}
