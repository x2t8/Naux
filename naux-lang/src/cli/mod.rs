use std::path::PathBuf;

pub mod build;
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
pub mod lsp;
pub mod new;
pub mod publish;
pub mod run;
pub mod test;
pub mod upgrade;
pub mod util;
pub mod verify;

pub const NAUX_VERSION: &str = "0.2.0-dev";

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
    },
    Ide {
        path: Option<PathBuf>,
    },
    Check {
        path: Option<PathBuf>,
    },
    Build,
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
    Lsp,
    Publish,
    Help,
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
    let show_version = args.iter().any(|a| a == "-V" || a == "--version");
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
    let mut mode = DefaultMode::Cli;
    let mut engine = DefaultEngine::Vm;
    let mut time = false;
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
        } => run::handle_run(path, mode, engine, time),
        Command::Ide { path } => ide::handle_ide(path),
        Command::Check { path } => check::handle_check(path),
        Command::Build => build::handle_build(),
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
        Command::Lsp => lsp::handle_lsp(),
        Command::Publish => publish::handle_publish(),
        Command::Help => help::handle_help(),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_args, Cli, Command};
    use std::path::PathBuf;

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
}
