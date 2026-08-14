use std::path::PathBuf;

use crate::runtime::budget::ExecutionLimits;

pub mod build;
pub mod bundle;
pub mod check;
pub mod clean;
pub mod debug;
pub mod dev;
pub mod doctor;
pub mod fmt;
pub mod format;
pub mod help;
pub mod ide;
pub mod init;
pub mod installation;
pub mod lsp;
pub mod new;
pub mod publish;
pub mod run;
pub mod test;
pub mod upgrade;
pub mod util;
pub mod verify;
pub mod welcome;

pub const NAUX_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
pub struct Cli {
    pub command: Command,
    pub show_version: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultEngine {
    Vm,
    Interp,
    Jit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultMode {
    Plain,
    Cli,
    Html,
    Json,
}

#[derive(Debug)]
pub enum Command {
    New {
        name: String,
    },
    Init {
        path: String,
    },
    Debug {
        path: Option<PathBuf>,
    },
    Run {
        path: Option<PathBuf>,
        mode: DefaultMode,
        engine: DefaultEngine,
        time: bool,
        limits: ExecutionLimits,
    },
    Ide {
        path: Option<PathBuf>,
    },
    Check {
        path: Option<PathBuf>,
    },
    Build,
    Bundle {
        cmd: BundleCommand,
    },
    Installation {
        cmd: InstallationCommand,
    },
    Fmt {
        path: Option<PathBuf>,
        check: bool,
        indent_width: Option<usize>,
    },
    Test {
        pattern: Option<String>,
    },
    Verify,
    Dev {
        cmd: DevCommand,
    },
    Doctor {
        json: bool,
        out: Option<PathBuf>,
    },
    Clean,
    Upgrade,
    Welcome {
        language: Option<String>,
        list_languages: bool,
        validate_locales: bool,
    },
    Lsp,
    Publish,
    Help,
}

#[derive(Debug)]
pub enum BundleCommand {
    Verify { path: PathBuf },
    Install { path: PathBuf, prefix: PathBuf },
}

#[derive(Debug)]
pub enum InstallationCommand {
    Install {
        bundle: PathBuf,
        prefix: PathBuf,
        state_directory: PathBuf,
        language: String,
    },
    Uninstall {
        receipt: PathBuf,
        dry_run: bool,
    },
    VerifyWindowsIcon {
        executable: PathBuf,
        icon: PathBuf,
    },
}

#[derive(Debug)]
pub enum DevCommand {
    Run {
        path: PathBuf,
        engine: String,
        mode: String,
        time: bool,
    },
    Disasm {
        path: PathBuf,
    },
    Ir {
        path: PathBuf,
    },
    SsaStats {
        path: PathBuf,
        iters: u32,
    },
    Bench {
        path: PathBuf,
        engine: String,
        iters: u32,
    },
    BenchRt {
        path: PathBuf,
        engine: String,
        iters: u32,
        warmup_ms: u64,
        json: bool,
        trace_only: bool,
    },
    Bytecode {
        path: PathBuf,
        out: Option<PathBuf>,
    },
    Cfg {
        path: PathBuf,
        out: Option<PathBuf>,
    },
    Refine {
        path: PathBuf,
        strict: bool,
    },
    Region {
        path: PathBuf,
    },
    Effects {
        path: PathBuf,
    },
}

pub fn parse_cli() -> Result<Cli, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    parse_args(args)
}

fn parse_args(mut args: Vec<String>) -> Result<Cli, String> {
    let show_version = args.len() == 1 && matches!(args[0].as_str(), "-V" | "--version");
    if show_version {
        return Ok(Cli {
            command: Command::Help,
            show_version: true,
        });
    }
    if args
        .iter()
        .any(|argument| matches!(argument.as_str(), "-V" | "--version"))
    {
        return Err("`--version` and `-V` must be used without another command".into());
    }
    if args.iter().any(|a| a == "-h" || a == "--help") {
        return Ok(Cli {
            command: Command::Help,
            show_version,
        });
    }
    if args.is_empty() {
        return Ok(Cli {
            command: Command::Help,
            show_version,
        });
    }
    let raw_cmd = args.remove(0);
    let cmd = match raw_cmd.as_str() {
        "n" => "new",
        "i" => "init",
        other => other,
    };
    let command = match cmd {
        "new" => parse_new(args)?,
        "init" => parse_init(args)?,
        "debug" => parse_debug(args)?,
        "run" => parse_run(args)?,
        "ide" => Command::Ide {
            path: args.first().map(PathBuf::from),
        },
        "check" => Command::Check {
            path: args.first().map(PathBuf::from),
        },
        "build" => Command::Build,
        "bundle" => parse_bundle(args)?,
        "installation" => parse_installation(args)?,
        "fmt" => parse_fmt(args)?,
        "test" => Command::Test {
            pattern: args.first().cloned(),
        },
        "verify" => {
            if !args.is_empty() {
                return Err("`naux verify` does not accept arguments; use naux.toml".into());
            }
            Command::Verify
        }
        "dev" => parse_dev(args)?,
        "doctor" => parse_doctor(args)?,
        "clean" => Command::Clean,
        "upgrade" => Command::Upgrade,
        "welcome" | "about" => parse_welcome(args)?,
        "lsp" => Command::Lsp,
        "publish" => Command::Publish,
        "help" => Command::Help,
        other => {
            return Err(format!(
                "Unknown command `{}`. Run `naux help` for usage.",
                other
            ))
        }
    };
    Ok(Cli {
        command,
        show_version,
    })
}

fn parse_bundle(mut args: Vec<String>) -> Result<Command, String> {
    if args.is_empty() {
        return Err("Missing bundle action; expected `verify` or `install`".into());
    }
    let action = args.remove(0);
    match action.as_str() {
        "verify" => {
            if args.len() != 1 {
                return Err("Usage: naux bundle verify <bundle-directory>".into());
            }
            Ok(Command::Bundle {
                cmd: BundleCommand::Verify {
                    path: PathBuf::from(&args[0]),
                },
            })
        }
        "install" => {
            let mut path = None;
            let mut prefix = None;
            let mut index = 0;
            while index < args.len() {
                let argument = &args[index];
                if let Some(value) = flag_value(argument, "prefix") {
                    if prefix.replace(PathBuf::from(value)).is_some() {
                        return Err("`--prefix` may be specified only once".into());
                    }
                } else if argument == "--prefix" {
                    index += 1;
                    let value = args
                        .get(index)
                        .ok_or_else(|| "--prefix requires a path".to_string())?;
                    if prefix.replace(PathBuf::from(value)).is_some() {
                        return Err("`--prefix` may be specified only once".into());
                    }
                } else if argument.starts_with('-') {
                    return Err(format!("Unknown bundle install flag `{argument}`"));
                } else if path.replace(PathBuf::from(argument)).is_some() {
                    return Err("Too many bundle install paths".into());
                }
                index += 1;
            }
            Ok(Command::Bundle {
                cmd: BundleCommand::Install {
                    path: path.ok_or_else(|| {
                        "Usage: naux bundle install <bundle-directory> --prefix <new-prefix>"
                            .to_string()
                    })?,
                    prefix: prefix.ok_or_else(|| {
                        "Usage: naux bundle install <bundle-directory> --prefix <new-prefix>"
                            .to_string()
                    })?,
                },
            })
        }
        other => Err(format!(
            "Unknown bundle action `{other}`; expected `verify` or `install`"
        )),
    }
}

fn parse_installation(mut args: Vec<String>) -> Result<Command, String> {
    if args.is_empty() {
        return Err("Missing installation action; expected `install` or `uninstall`".into());
    }
    let action = args.remove(0);
    let cmd = match action.as_str() {
        "install" => {
            let mut bundle = None;
            let mut prefix = None;
            let mut state_directory = None;
            let mut language = None;
            let mut index = 0;
            while index < args.len() {
                let argument = &args[index];
                if let Some(value) = flag_value(argument, "prefix") {
                    set_once(&mut prefix, PathBuf::from(value), "prefix")?;
                } else if let Some(value) = flag_value(argument, "state-directory") {
                    set_once(
                        &mut state_directory,
                        PathBuf::from(value),
                        "state-directory",
                    )?;
                } else if let Some(value) = flag_value(argument, "language") {
                    set_once(&mut language, value, "language")?;
                } else if matches!(
                    argument.as_str(),
                    "--prefix" | "--state-directory" | "--language"
                ) {
                    index += 1;
                    let value = args
                        .get(index)
                        .ok_or_else(|| format!("{argument} requires a value"))?;
                    match argument.as_str() {
                        "--prefix" => set_once(&mut prefix, PathBuf::from(value), "prefix")?,
                        "--state-directory" => set_once(
                            &mut state_directory,
                            PathBuf::from(value),
                            "state-directory",
                        )?,
                        "--language" => set_once(&mut language, value.clone(), "language")?,
                        _ => unreachable!(),
                    }
                } else if argument.starts_with('-') {
                    return Err(format!("Unknown installation install flag `{argument}`"));
                } else {
                    set_once(&mut bundle, PathBuf::from(argument), "bundle path")?;
                }
                index += 1;
            }
            InstallationCommand::Install {
                bundle: bundle.ok_or_else(installation_install_usage)?,
                prefix: prefix.ok_or_else(installation_install_usage)?,
                state_directory: state_directory.ok_or_else(installation_install_usage)?,
                language: language.ok_or_else(installation_install_usage)?,
            }
        }
        "uninstall" => {
            let mut receipt = None;
            let mut dry_run = false;
            let mut index = 0;
            while index < args.len() {
                let argument = &args[index];
                if let Some(value) = flag_value(argument, "receipt") {
                    set_once(&mut receipt, PathBuf::from(value), "receipt")?;
                } else if argument == "--receipt" {
                    index += 1;
                    let value = args
                        .get(index)
                        .ok_or_else(|| "--receipt requires a path".to_string())?;
                    set_once(&mut receipt, PathBuf::from(value), "receipt")?;
                } else if argument == "--dry-run" {
                    if dry_run {
                        return Err("`--dry-run` may be specified only once".into());
                    }
                    dry_run = true;
                } else {
                    return Err(format!(
                        "Unknown installation uninstall argument `{argument}`"
                    ));
                }
                index += 1;
            }
            InstallationCommand::Uninstall {
                receipt: receipt.ok_or_else(|| {
                    "Usage: naux installation uninstall --receipt <receipt.tsv> [--dry-run]"
                        .to_string()
                })?,
                dry_run,
            }
        }
        "verify-windows-icon" => {
            if args.len() != 2 {
                return Err(
                    "Usage: naux installation verify-windows-icon <naux.exe> <canonical.ico>"
                        .into(),
                );
            }
            InstallationCommand::VerifyWindowsIcon {
                executable: PathBuf::from(&args[0]),
                icon: PathBuf::from(&args[1]),
            }
        }
        other => {
            return Err(format!(
                "Unknown installation action `{other}`; expected `install`, `uninstall`, or `verify-windows-icon`"
            ))
        }
    };
    Ok(Command::Installation { cmd })
}

fn set_once<T>(slot: &mut Option<T>, value: T, label: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("`--{label}` may be specified only once"));
    }
    Ok(())
}

fn installation_install_usage() -> String {
    "Usage: naux installation install <bundle> --prefix <new-prefix> --state-directory <existing-directory> --language <locale>".into()
}

fn parse_new(args: Vec<String>) -> Result<Command, String> {
    let name = args
        .first()
        .cloned()
        .ok_or_else(|| "Missing project name for `naux new`".to_string())?;
    Ok(Command::New { name })
}

fn parse_init(args: Vec<String>) -> Result<Command, String> {
    let path = args.first().cloned().unwrap_or_else(|| ".".into());
    Ok(Command::Init { path })
}

fn parse_run(args: Vec<String>) -> Result<Command, String> {
    let mut path: Option<PathBuf> = None;
    let mut mode = DefaultMode::Plain;
    let mut engine = DefaultEngine::Vm;
    let mut time = false;
    let defaults = ExecutionLimits::default();
    let mut max_work = defaults.max_work;
    let mut max_call_depth = defaults.max_call_depth;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(v) = flag_value(arg, "mode") {
            mode = parse_mode(&v)?;
        } else if arg == "--mode" {
            i += 1;
            let v = args
                .get(i)
                .ok_or_else(|| "--mode requires a value".to_string())?;
            mode = parse_mode(v)?;
        } else if let Some(v) = flag_value(arg, "engine") {
            engine = parse_engine(&v)?;
        } else if arg == "--engine" {
            i += 1;
            let v = args
                .get(i)
                .ok_or_else(|| "--engine requires a value".to_string())?;
            engine = parse_engine(v)?;
        } else if arg == "--time" {
            time = true;
        } else if let Some(v) = flag_value(arg, "max-work") {
            max_work = parse_u64("max-work", &v)?;
        } else if arg == "--max-work" {
            i += 1;
            let v = args
                .get(i)
                .ok_or_else(|| "--max-work requires a value".to_string())?;
            max_work = parse_u64("max-work", v)?;
        } else if let Some(v) = flag_value(arg, "max-call-depth") {
            max_call_depth = parse_usize("max-call-depth", &v)?;
        } else if arg == "--max-call-depth" {
            i += 1;
            let v = args
                .get(i)
                .ok_or_else(|| "--max-call-depth requires a value".to_string())?;
            max_call_depth = parse_usize("max-call-depth", v)?;
        } else if arg.starts_with('-') {
            return Err(format!("Unknown flag `{}`", arg));
        } else if path.is_none() {
            path = Some(PathBuf::from(arg));
        } else {
            return Err("Too many positional arguments for `naux run`".into());
        }
        i += 1;
    }
    Ok(Command::Run {
        path,
        mode,
        engine,
        time,
        limits: ExecutionLimits::new(max_work, max_call_depth)?,
    })
}

fn parse_debug(args: Vec<String>) -> Result<Command, String> {
    if args.len() > 1 {
        return Err("Too many positional arguments for `naux debug`".into());
    }
    let path = args.first().map(PathBuf::from);
    Ok(Command::Debug { path })
}

fn parse_fmt(args: Vec<String>) -> Result<Command, String> {
    let mut path: Option<PathBuf> = None;
    let mut check = false;
    let mut indent_width: Option<usize> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--check" {
            check = true;
        } else if let Some(v) = flag_value(arg, "indent-width") {
            indent_width = Some(parse_usize("indent-width", &v)?);
        } else if arg == "--indent-width" || arg == "--indent" {
            i += 1;
            let v = args
                .get(i)
                .ok_or_else(|| "--indent-width requires a value".to_string())?;
            indent_width = Some(parse_usize("indent-width", v)?);
        } else if arg.starts_with('-') {
            return Err(format!("Unknown flag `{}`", arg));
        } else if path.is_none() {
            path = Some(PathBuf::from(arg));
        } else {
            return Err("Too many positional arguments for `naux fmt`".into());
        }
        i += 1;
    }
    Ok(Command::Fmt {
        path,
        check,
        indent_width,
    })
}

fn parse_dev(args: Vec<String>) -> Result<Command, String> {
    if args.is_empty() {
        return Err("Missing dev subcommand".into());
    }
    let mut rest = args;
    let sub = rest.remove(0);
    let cmd = match sub.as_str() {
        "run" => parse_dev_run(rest)?,
        "disasm" => parse_dev_simple(rest, DevCommandKind::Disasm)?,
        "ir" => parse_dev_simple(rest, DevCommandKind::Ir)?,
        "cfg" | "emit-cfg" => parse_dev_cfg(rest)?,
        "ssa-stats" | "ssa" => parse_dev_ssa_stats(rest)?,
        "bench" => parse_dev_bench(rest)?,
        "benchrt" | "bench-rt" => parse_dev_bench_rt(rest)?,
        "bytecode" => parse_dev_bytecode(rest)?,
        "refine" => parse_dev_refine(rest)?,
        "region" => parse_dev_region(rest)?,
        "effects" | "fx" => parse_dev_effects(rest)?,
        other => return Err(format!("Unknown dev subcommand `{}`", other)),
    };
    Ok(Command::Dev { cmd })
}

enum DevCommandKind {
    Disasm,
    Ir,
}

fn parse_dev_simple(args: Vec<String>, kind: DevCommandKind) -> Result<DevCommand, String> {
    let path = args
        .first()
        .ok_or_else(|| "Missing path for dev command".to_string())?;
    let path = PathBuf::from(path);
    if args.len() > 1 {
        return Err("Too many arguments for dev command".into());
    }
    Ok(match kind {
        DevCommandKind::Disasm => DevCommand::Disasm { path },
        DevCommandKind::Ir => DevCommand::Ir { path },
    })
}

fn parse_dev_cfg(args: Vec<String>) -> Result<DevCommand, String> {
    let mut path: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(v) = flag_value(arg, "out") {
            out = Some(PathBuf::from(v));
        } else if arg == "--out" {
            i += 1;
            let v = args
                .get(i)
                .ok_or_else(|| "--out requires a value".to_string())?;
            out = Some(PathBuf::from(v));
        } else if arg.starts_with('-') {
            return Err(format!("Unknown flag `{}`", arg));
        } else if path.is_none() {
            path = Some(PathBuf::from(arg));
        } else {
            return Err("Too many positional arguments for `naux dev cfg`".into());
        }
        i += 1;
    }
    let path = path.ok_or_else(|| "Missing path for dev cfg".to_string())?;
    Ok(DevCommand::Cfg { path, out })
}

fn parse_dev_run(args: Vec<String>) -> Result<DevCommand, String> {
    let mut path: Option<PathBuf> = None;
    let mut engine = "vm".to_string();
    let mut mode = "cli".to_string();
    let mut time = false;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(v) = flag_value(arg, "engine") {
            engine = v;
        } else if arg == "--engine" {
            i += 1;
            engine = args
                .get(i)
                .ok_or_else(|| "--engine requires a value".to_string())?
                .to_string();
        } else if let Some(v) = flag_value(arg, "mode") {
            mode = v;
        } else if arg == "--mode" {
            i += 1;
            mode = args
                .get(i)
                .ok_or_else(|| "--mode requires a value".to_string())?
                .to_string();
        } else if arg == "--time" {
            time = true;
        } else if arg.starts_with('-') {
            return Err(format!("Unknown flag `{}`", arg));
        } else if path.is_none() {
            path = Some(PathBuf::from(arg));
        } else {
            return Err("Too many positional arguments for `naux dev run`".into());
        }
        i += 1;
    }
    let path = path.ok_or_else(|| "Missing path for `naux dev run`".to_string())?;
    Ok(DevCommand::Run {
        path,
        engine,
        mode,
        time,
    })
}

fn parse_dev_bench(args: Vec<String>) -> Result<DevCommand, String> {
    let mut path: Option<PathBuf> = None;
    let mut engine = "jit".to_string();
    let mut iters: u32 = 100;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(v) = flag_value(arg, "engine") {
            engine = v;
        } else if arg == "--engine" {
            i += 1;
            engine = args
                .get(i)
                .ok_or_else(|| "--engine requires a value".to_string())?
                .to_string();
        } else if let Some(v) = flag_value(arg, "iters") {
            iters = parse_u32("iters", &v)?;
        } else if arg == "--iters" {
            i += 1;
            let v = args
                .get(i)
                .ok_or_else(|| "--iters requires a value".to_string())?;
            iters = parse_u32("iters", v)?;
        } else if arg.starts_with('-') {
            return Err(format!("Unknown flag `{}`", arg));
        } else if path.is_none() {
            path = Some(PathBuf::from(arg));
        } else {
            return Err("Too many positional arguments for `naux dev bench`".into());
        }
        i += 1;
    }
    let path = path.ok_or_else(|| "Missing path for `naux dev bench`".to_string())?;
    Ok(DevCommand::Bench {
        path,
        engine,
        iters,
    })
}

fn parse_dev_ssa_stats(args: Vec<String>) -> Result<DevCommand, String> {
    let mut path: Option<PathBuf> = None;
    let mut iters: u32 = 100;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(v) = flag_value(arg, "iters") {
            iters = parse_u32("iters", &v)?;
        } else if arg == "--iters" {
            i += 1;
            let v = args
                .get(i)
                .ok_or_else(|| "--iters requires a value".to_string())?;
            iters = parse_u32("iters", v)?;
        } else if arg.starts_with('-') {
            return Err(format!("Unknown flag `{}`", arg));
        } else if path.is_none() {
            path = Some(PathBuf::from(arg));
        } else {
            return Err("Too many positional arguments for `naux dev ssa-stats`".into());
        }
        i += 1;
    }
    let path = path.ok_or_else(|| "Missing path for `naux dev ssa-stats`".to_string())?;
    Ok(DevCommand::SsaStats { path, iters })
}

fn parse_dev_bench_rt(args: Vec<String>) -> Result<DevCommand, String> {
    let mut path: Option<PathBuf> = None;
    let mut engine = "jit".to_string();
    let mut iters: u32 = 100;
    let mut warmup_ms: u64 = 100;
    let mut json = false;
    let mut trace_only = false;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(v) = flag_value(arg, "engine") {
            engine = v;
        } else if arg == "--engine" {
            i += 1;
            engine = args
                .get(i)
                .ok_or_else(|| "--engine requires a value".to_string())?
                .to_string();
        } else if let Some(v) = flag_value(arg, "iters") {
            iters = parse_u32("iters", &v)?;
        } else if arg == "--iters" {
            i += 1;
            let v = args
                .get(i)
                .ok_or_else(|| "--iters requires a value".to_string())?;
            iters = parse_u32("iters", v)?;
        } else if let Some(v) = flag_value(arg, "warmup-ms") {
            warmup_ms = v
                .parse::<u64>()
                .map_err(|_| "Invalid warmup-ms value".to_string())?;
        } else if arg == "--warmup-ms" {
            i += 1;
            let v = args
                .get(i)
                .ok_or_else(|| "--warmup-ms requires a value".to_string())?;
            warmup_ms = v
                .parse::<u64>()
                .map_err(|_| "Invalid warmup-ms value".to_string())?;
        } else if arg == "--json" {
            json = true;
        } else if arg == "--trace-only" {
            trace_only = true;
        } else if arg.starts_with('-') {
            return Err(format!("Unknown flag `{}`", arg));
        } else if path.is_none() {
            path = Some(PathBuf::from(arg));
        } else {
            return Err("Too many positional arguments for `naux dev benchrt`".into());
        }
        i += 1;
    }
    let path = path.ok_or_else(|| "Missing path for `naux dev benchrt`".to_string())?;
    Ok(DevCommand::BenchRt {
        path,
        engine,
        iters,
        warmup_ms,
        json,
        trace_only,
    })
}

fn parse_dev_bytecode(args: Vec<String>) -> Result<DevCommand, String> {
    let mut path: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-o" || arg == "--out" {
            i += 1;
            let v = args
                .get(i)
                .ok_or_else(|| "--out requires a value".to_string())?;
            out = Some(PathBuf::from(v));
        } else if let Some(v) = flag_value(arg, "out") {
            out = Some(PathBuf::from(v));
        } else if arg.starts_with('-') {
            return Err(format!("Unknown flag `{}`", arg));
        } else if path.is_none() {
            path = Some(PathBuf::from(arg));
        } else {
            return Err("Too many positional arguments for `naux dev bytecode`".into());
        }
        i += 1;
    }
    let path = path.ok_or_else(|| "Missing path for `naux dev bytecode`".to_string())?;
    Ok(DevCommand::Bytecode { path, out })
}

fn parse_dev_refine(args: Vec<String>) -> Result<DevCommand, String> {
    let mut path: Option<PathBuf> = None;
    let mut strict = false;
    for arg in &args {
        if arg == "--strict" {
            strict = true;
        } else if arg.starts_with('-') {
            return Err(format!("Unknown flag `{}`", arg));
        } else if path.is_none() {
            path = Some(PathBuf::from(arg));
        } else {
            return Err("Too many positional arguments for `naux dev refine`".into());
        }
    }
    let path = path.ok_or_else(|| "Missing path for `naux dev refine`".to_string())?;
    Ok(DevCommand::Refine { path, strict })
}

fn parse_dev_region(args: Vec<String>) -> Result<DevCommand, String> {
    let mut path: Option<PathBuf> = None;
    for arg in &args {
        if arg.starts_with('-') {
            return Err(format!("Unknown flag `{}`", arg));
        } else if path.is_none() {
            path = Some(PathBuf::from(arg));
        } else {
            return Err("Too many positional arguments for `naux dev region`".into());
        }
    }
    let path = path.ok_or_else(|| "Missing path for `naux dev region`".to_string())?;
    Ok(DevCommand::Region { path })
}

fn parse_dev_effects(args: Vec<String>) -> Result<DevCommand, String> {
    let mut path: Option<PathBuf> = None;
    for arg in &args {
        if arg.starts_with('-') {
            return Err(format!("Unknown flag `{}`", arg));
        } else if path.is_none() {
            path = Some(PathBuf::from(arg));
        } else {
            return Err("Too many positional arguments for `naux dev effects`".into());
        }
    }
    let path = path.ok_or_else(|| "Missing path for `naux dev effects`".to_string())?;
    Ok(DevCommand::Effects { path })
}

fn parse_doctor(args: Vec<String>) -> Result<Command, String> {
    let mut json = false;
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--json" {
            json = true;
        } else if arg == "-o" || arg == "--out" {
            i += 1;
            let v = args
                .get(i)
                .ok_or_else(|| "--out requires a value".to_string())?;
            out = Some(PathBuf::from(v));
        } else if let Some(v) = flag_value(arg, "out") {
            out = Some(PathBuf::from(v));
        } else if arg.starts_with('-') {
            return Err(format!("Unknown flag `{}`", arg));
        } else {
            return Err("`naux doctor` does not take positional arguments".into());
        }
        i += 1;
    }
    Ok(Command::Doctor { json, out })
}

fn parse_welcome(args: Vec<String>) -> Result<Command, String> {
    let mut language = None;
    let mut list_languages = false;
    let mut validate_locales = false;
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if let Some(value) = flag_value(argument, "language") {
            if language.replace(value).is_some() {
                return Err("`--language` may be specified only once".into());
            }
        } else if argument == "--language" {
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| "--language requires a locale".to_string())?;
            if language.replace(value.clone()).is_some() {
                return Err("`--language` may be specified only once".into());
            }
        } else if argument == "--list-languages" {
            list_languages = true;
        } else if argument == "--validate-locales" {
            validate_locales = true;
        } else {
            return Err(format!("Unknown welcome argument `{argument}`"));
        }
        index += 1;
    }
    if language.is_some() && (list_languages || validate_locales)
        || list_languages && validate_locales
    {
        return Err(
            "`--language`, `--list-languages`, and `--validate-locales` are exclusive".into(),
        );
    }
    Ok(Command::Welcome {
        language,
        list_languages,
        validate_locales,
    })
}

fn parse_engine(value: &str) -> Result<DefaultEngine, String> {
    match value.to_ascii_lowercase().as_str() {
        "vm" => Ok(DefaultEngine::Vm),
        "interp" => Ok(DefaultEngine::Interp),
        "jit" => Ok(DefaultEngine::Jit),
        other => Err(format!("Unknown engine `{}`", other)),
    }
}

fn parse_mode(value: &str) -> Result<DefaultMode, String> {
    match value.to_ascii_lowercase().as_str() {
        "plain" => Ok(DefaultMode::Plain),
        "cli" => Ok(DefaultMode::Cli),
        "html" => Ok(DefaultMode::Html),
        "json" => Ok(DefaultMode::Json),
        other => Err(format!("Unknown mode `{}`", other)),
    }
}

fn flag_value(arg: &str, key: &str) -> Option<String> {
    let prefix = format!("--{}=", key);
    if arg.starts_with(&prefix) {
        Some(arg[prefix.len()..].to_string())
    } else {
        None
    }
}

fn parse_usize(label: &str, value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("Invalid {} value `{}`", label, value))
}

fn parse_u64(label: &str, value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("Invalid {} value `{}`", label, value))
}

fn parse_u32(label: &str, value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("Invalid {} value `{}`", label, value))
}

pub fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::New { name } => new::handle_new(name),
        Command::Init { path } => init::init_project(&path),
        Command::Debug { path } => debug::handle_debug(path),
        Command::Run {
            path,
            mode,
            engine,
            time,
            limits,
        } => run::handle_run(path, mode, engine, time, limits),
        Command::Ide { path } => ide::handle_ide(path),
        Command::Check { path } => check::handle_check(path),
        Command::Build => build::handle_build(),
        Command::Bundle { cmd } => bundle::handle_bundle(cmd),
        Command::Installation { cmd } => installation::handle_installation(cmd),
        Command::Fmt {
            path,
            check,
            indent_width,
        } => fmt::handle_fmt(path, check, indent_width),
        Command::Test { pattern } => test::handle_test(pattern),
        Command::Verify => verify::handle_verify(),
        Command::Dev { cmd } => dev::handle_dev(cmd),
        Command::Doctor { json, out } => doctor::handle_doctor(json, out),
        Command::Clean => clean::handle_clean(),
        Command::Upgrade => upgrade::handle_upgrade(),
        Command::Welcome {
            language,
            list_languages,
            validate_locales,
        } => welcome::handle_welcome(language, list_languages, validate_locales),
        Command::Lsp => lsp::handle_lsp(),
        Command::Publish => publish::handle_publish(),
        Command::Help => help::handle_help(),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_args, BundleCommand, Cli, Command, InstallationCommand, NAUX_VERSION};
    use std::path::{Path, PathBuf};

    #[test]
    fn parse_doctor_defaults() {
        let Cli { command, .. } = parse_args(vec!["doctor".into()]).expect("doctor command");
        match command {
            Command::Doctor { json, out } => {
                assert!(!json);
                assert_eq!(out, None);
            }
            other => panic!("unexpected command: {:?}", other),
        }
    }

    #[test]
    fn parse_doctor_json_and_out() {
        let Cli { command, .. } = parse_args(vec![
            "doctor".into(),
            "--json".into(),
            "--out".into(),
            "reports/naux-doctor.json".into(),
        ])
        .expect("doctor command with flags");
        match command {
            Command::Doctor { json, out } => {
                assert!(json);
                assert_eq!(out, Some(PathBuf::from("reports/naux-doctor.json")));
            }
            other => panic!("unexpected command: {:?}", other),
        }
    }

    #[test]
    fn parse_verify_is_config_driven_and_argument_free() {
        let Cli { command, .. } = parse_args(vec!["verify".into()]).expect("verify command");
        assert!(matches!(command, Command::Verify));

        let error = parse_args(vec!["verify".into(), "bench.nx".into()])
            .expect_err("verify arguments must be rejected");
        assert!(error.contains("does not accept arguments"));
    }

    #[test]
    fn parse_bundle_verify_and_install_are_explicit() {
        let Cli { command, .. } =
            parse_args(vec!["bundle".into(), "verify".into(), "naux-learn".into()])
                .expect("bundle verify command");
        assert!(matches!(
            command,
            Command::Bundle {
                cmd: BundleCommand::Verify { path }
            } if path.as_path() == Path::new("naux-learn")
        ));

        let Cli { command, .. } = parse_args(vec![
            "bundle".into(),
            "install".into(),
            "naux-learn".into(),
            "--prefix=/tmp/naux".into(),
        ])
        .expect("bundle install command");
        assert!(matches!(
            command,
            Command::Bundle {
                cmd: BundleCommand::Install { path, prefix }
            } if path.as_path() == Path::new("naux-learn")
                && prefix.as_path() == Path::new("/tmp/naux")
        ));

        assert!(parse_args(vec!["bundle".into(), "install".into()]).is_err());
        assert!(parse_args(vec![
            "bundle".into(),
            "verify".into(),
            "one".into(),
            "two".into(),
        ])
        .is_err());
    }

    #[test]
    fn version_is_package_owned_and_argument_exclusive() {
        assert_eq!(NAUX_VERSION, env!("CARGO_PKG_VERSION"));
        for flag in ["--version", "-V"] {
            let parsed = parse_args(vec![flag.into()]).expect("standalone version flag");
            assert!(parsed.show_version);
            assert!(matches!(parsed.command, Command::Help));
        }
        assert!(
            parse_args(vec!["run".into(), "program.nx".into(), "--version".into()])
                .unwrap_err()
                .contains("without another command")
        );
    }

    #[test]
    fn parse_welcome_language_and_catalog_actions_are_exclusive() {
        let Cli { command, .. } =
            parse_args(vec!["welcome".into(), "--language".into(), "vi-VN".into()]).unwrap();
        assert!(matches!(
            command,
            Command::Welcome {
                language: Some(language),
                list_languages: false,
                validate_locales: false,
            } if language == "vi-VN"
        ));
        assert!(parse_args(vec![
            "about".into(),
            "--list-languages".into(),
            "--validate-locales".into(),
        ])
        .is_err());
    }

    #[test]
    fn parse_installation_requires_explicit_ownership_inputs() {
        let Cli { command, .. } = parse_args(vec![
            "installation".into(),
            "install".into(),
            "bundle".into(),
            "--prefix=/tmp/naux".into(),
            "--state-directory".into(),
            "/tmp/state".into(),
            "--language=de".into(),
        ])
        .unwrap();
        assert!(matches!(
            command,
            Command::Installation {
                cmd: InstallationCommand::Install {
                    bundle,
                    prefix,
                    state_directory,
                    language,
                }
            } if bundle == std::path::Path::new("bundle")
                && prefix == std::path::Path::new("/tmp/naux")
                && state_directory == std::path::Path::new("/tmp/state")
                && language == "de"
        ));

        let Cli { command, .. } = parse_args(vec![
            "installation".into(),
            "uninstall".into(),
            "--receipt=receipt.tsv".into(),
            "--dry-run".into(),
        ])
        .unwrap();
        assert!(matches!(
            command,
            Command::Installation {
                cmd: InstallationCommand::Uninstall { receipt, dry_run: true }
            } if receipt == std::path::Path::new("receipt.tsv")
        ));
        assert!(parse_args(vec!["installation".into(), "install".into()]).is_err());
    }
}
