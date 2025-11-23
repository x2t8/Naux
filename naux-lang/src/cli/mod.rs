use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

pub mod build;
pub mod dev;
pub mod fmt;
pub mod format;
pub mod init;
pub mod new;
pub mod run;
pub mod test;
pub mod util;

const NAUX_VERSION: &str = "0.2.0-dev";

#[derive(Parser, Debug)]
#[command(
    name = "naux",
    version = NAUX_VERSION,
    about = "NAUX — Nexus Ascendant Unbound eXecutor",
    propagate_version = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultEngine {
    Vm,
    Interp,
    Jit,
    Llvm,
}

#[derive(ValueEnum, Debug, Clone)]
pub enum DefaultMode {
    Cli,
    Html,
    Json,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    New { name: String },
    Run {
        path: Option<PathBuf>,
        #[arg(long, default_value = "cli")]
        mode: DefaultMode,
        #[arg(long, default_value = "vm")]
        engine: DefaultEngine,
    },
    Build,
    Fmt {
        path: Option<PathBuf>,
        #[arg(long)]
        check: bool,
    },
    Test {
        #[arg(value_name = "PATTERN")]
        pattern: Option<String>,
    },
    Dev {
        #[command(subcommand)]
        cmd: DevCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum DevCommand {
    Run {
        path: PathBuf,
        #[arg(long, value_parser = ["interp", "vm", "jit"], default_value = "vm")]
        engine: String,
        #[arg(long, value_parser = ["cli", "html", "json"], default_value = "cli")]
        mode: String,
    },
    Disasm { path: PathBuf },
    Ir { path: PathBuf },
    Bench {
        path: PathBuf,
        #[arg(long, value_parser = ["interp", "vm", "jit"], default_value = "jit")]
        engine: String,
        #[arg(long, default_value_t = 100)]
        iters: u32,
    },
}

pub fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::New { name } => new::handle_new(name),
        Command::Run { path, mode, engine } => run::handle_run(path, mode, engine),
        Command::Build => build::handle_build(),
        Command::Fmt { path, check } => fmt::handle_fmt(path, check),
        Command::Test { pattern } => test::handle_test(pattern),
        Command::Dev { cmd } => dev::handle_dev(cmd),
    }
}
