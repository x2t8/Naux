use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Instant;

use crate::cli::run;
use crate::cli::{DefaultEngine, DefaultMode, DevCommand};
use crate::cli::util;
use crate::vm::{bytecode, compiler, ir};

pub fn handle_dev(cmd: DevCommand) -> Result<(), String> {
    match cmd {
        DevCommand::Run { path, engine, mode } => run_core(&path, &engine, &mode),
        DevCommand::Disasm { path } => disasm_core(&path),
        DevCommand::Ir { path } => ir_core(&path),
        DevCommand::Bench { path, engine, iters } => bench_core(&path, &engine, iters),
    }
}

pub fn run_core(path: &PathBuf, engine: &str, mode: &str) -> Result<(), String> {
    let engine = parse_engine(engine)?;
    let mode = parse_mode(mode)?;
    run::handle_run(Some(path.clone()), mode, engine)
}

pub fn disasm_core(path: &PathBuf) -> Result<(), String> {
    let (_, ast) = util::load_ast(path)?;
    let program = compiler::compile_script(&ast);
    println!("Main:");
    println!("{}", bytecode::disasm_block(&program.main));
    if !program.functions.is_empty() {
        println!("Functions:");
        let mut names = BTreeSet::new();
        for name in program.functions.keys() {
            names.insert(name.clone());
        }
        for name in names {
            if let Some(func) = program.functions.get(&name) {
                println!("fn {}:", name);
                println!("{}", bytecode::disasm_block(&func.code));
            }
        }
    }
    Ok(())
}

pub fn ir_core(path: &PathBuf) -> Result<(), String> {
    let (_, ast) = util::load_ast(path)?;
    let ir_prog = compiler::compile_ir(&ast);
    println!("{}", ir::pretty_print_ir(&ir_prog));
    Ok(())
}

pub fn bench_core(path: &PathBuf, engine: &str, iters: u32) -> Result<(), String> {
    let engine = parse_engine(engine)?;
    let (src, ast) = util::load_ast(path)?;
    let start = Instant::now();
    if iters == 0 {
        return Err("iters phải lớn hơn 0".into());
    }
    for _ in 0..iters {
        util::execute_ast(engine, &ast, &src, path)?;
    }
    let elapsed = start.elapsed();
    let avg_ns = elapsed.as_nanos() / iters as u128;
    println!(
        "Bench {} (engine={}) – {} ns/op",
        path.display(),
        format_engine(engine),
        avg_ns
    );
    Ok(())
}

fn parse_engine(engine: &str) -> Result<DefaultEngine, String> {
    match engine.to_ascii_lowercase().as_str() {
        "vm" => Ok(DefaultEngine::Vm),
        "jit" => Ok(DefaultEngine::Jit),
        "interp" => Ok(DefaultEngine::Interp),
        "llvm" => Ok(DefaultEngine::Llvm),
        other => Err(format!("Unknown engine `{}`", other)),
    }
}

fn parse_mode(mode: &str) -> Result<DefaultMode, String> {
    match mode.to_ascii_lowercase().as_str() {
        "cli" => Ok(DefaultMode::Cli),
        "html" => Ok(DefaultMode::Html),
        "json" => Ok(DefaultMode::Json),
        other => Err(format!("Unknown mode `{}`", other)),
    }
}

fn format_engine(engine: DefaultEngine) -> &'static str {
    match engine {
        DefaultEngine::Interp => "interp",
        DefaultEngine::Vm => "vm",
        DefaultEngine::Jit => "jit",
        DefaultEngine::Llvm => "llvm",
    }
}
