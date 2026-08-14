mod bench;
pub mod cfg;
mod effects;
mod ir;
mod refine;
mod region;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::cli::run;
use crate::cli::util;
use crate::cli::{DefaultEngine, DefaultMode, DevCommand};
use crate::vm::{bytecode, compiler, ssa};
use crate::{typecheck, vm::nxb};

pub fn handle_dev(cmd: DevCommand) -> Result<(), String> {
    match cmd {
        DevCommand::Run {
            path,
            engine,
            mode,
            time,
        } => run_core(&path, &engine, &mode, time),
        DevCommand::Disasm { path } => disasm_core(&path),
        DevCommand::Ir { path } => ir::ir_core(&path),
        DevCommand::Cfg { path, out } => cfg::cfg_core(&path, out.as_ref()),
        DevCommand::SsaStats { path, iters } => ssa_stats_core(&path, iters),
        DevCommand::Bench {
            path,
            engine,
            iters,
        } => bench::bench_core(&path, &engine, iters),
        DevCommand::BenchRt {
            path,
            engine,
            iters,
            warmup_ms,
            json,
            trace_only,
        } => bench_runtime_core(&path, &engine, iters, warmup_ms, json, trace_only),
        DevCommand::Bytecode { path, out } => emit_bytecode(&path, out.as_ref()),
        DevCommand::Refine { path, strict } => refine::refine_core(&path, strict),
        DevCommand::Region { path } => region::region_core(&path),
        DevCommand::Effects { path } => effects::effects_core(&path),
    }
}

pub fn run_core(path: &Path, engine: &str, mode: &str, time: bool) -> Result<(), String> {
    let engine = parse_engine(engine)?;
    let mode = parse_mode(mode)?;
    run::handle_run(
        Some(path.to_path_buf()),
        mode,
        engine,
        time,
        crate::runtime::budget::ExecutionLimits::default(),
    )
}

pub(crate) fn bench_runtime_core(
    path: &Path,
    engine: &str,
    iters: u32,
    warmup_ms: u64,
    json: bool,
    trace_only: bool,
) -> Result<(), String> {
    bench::bench_runtime_core(path, engine, iters, warmup_ms, json, trace_only)
}

pub fn disasm_core(path: &Path) -> Result<(), String> {
    let (_, ast) = util::load_ast(path)?;
    let program = compiler::compile_script(&ast);
    print_ir_block("main", &program.main);
    if !program.functions.is_empty() {
        let mut names = BTreeSet::new();
        for name in program.functions.keys() {
            names.insert(name.clone());
        }
        for name in names {
            if let Some(func) = program.functions.get(&name) {
                print_ir_block(&name, &func.code);
            }
        }
    }
    Ok(())
}

pub fn ssa_stats_core(path: &Path, iters: u32) -> Result<(), String> {
    if iters == 0 {
        return Err("iters phải lớn hơn 0".into());
    }
    let (_, ast) = util::load_ast(path)?;
    let (ir_prog, report) = compiler::compile_ir_with_report(&ast);

    let start = Instant::now();
    let mut last_stats = ssa::LowerScratchStats::default();
    let mut last_program = None;
    for _ in 0..iters {
        let (ssa_prog, stats) = ssa::lower_program_with_stats(&ir_prog);
        last_stats = stats;
        last_program = Some(ssa_prog);
    }
    let elapsed = start.elapsed();
    let avg_ns = elapsed.as_nanos() / iters as u128;

    let Some(ssa_prog) = last_program else {
        return Err("ssa lowering did not produce a program".into());
    };
    let safe_start = Instant::now();
    let mut last_pass_log = Vec::new();
    let mut last_optimized_program = None;
    for _ in 0..iters {
        let (mut ssa_prog, _) = ssa::lower_program_with_stats(&ir_prog);
        let mut pass_manager = ssa::PassManager::with_default_pipeline();
        last_pass_log = pass_manager.run_program(&mut ssa_prog);
        last_optimized_program = Some(ssa_prog);
    }
    let safe_elapsed = safe_start.elapsed();
    let safe_avg_ns = safe_elapsed.as_nanos() / iters as u128;

    let Some(optimized_ssa) = last_optimized_program else {
        return Err("ssa safe pipeline did not produce a program".into());
    };
    let before_metrics = collect_ssa_metrics(&ssa_prog);
    let before_verify = ssa::verify_program_ssa(&ssa_prog);
    let after_verify = ssa::verify_program_ssa(&optimized_ssa);
    let after_metrics = collect_ssa_metrics(&optimized_ssa);
    let status_counts = ssa_prog
        .iter_functions()
        .fold((0usize, 0usize), |mut acc, func| {
            match func.status {
                ssa::BuildStatus::Lowered => acc.0 += 1,
                ssa::BuildStatus::Unsupported(_) => acc.1 += 1,
            }
            acc
        });
    let inst_util = percent(last_stats.insts, last_stats.inst_reserved);
    let var_op_stage_util = percent(last_stats.var_ops_staged, last_stats.var_op_reserved);

    println!("~ NAUX SSA LOWER ~");
    println!("path: {}", path.display());
    println!("iters: {}", iters);
    println!("avg: {} ns/op", avg_ns);
    println!("lower-avg: {} ns/op", avg_ns);
    println!("safe-pipeline-avg: {} ns/op", safe_avg_ns);
    println!(
        "optimizer-main-stop: {}",
        report.main_feedback_stop.as_str()
    );
    println!(
        "functions: {} (lowered={}, unsupported={})",
        last_stats.functions, status_counts.0, status_counts.1
    );
    println!("blocks: {}", last_stats.blocks);
    println!(
        "insts: {} / reserved {} ({:.1}%)",
        last_stats.insts, last_stats.inst_reserved, inst_util
    );
    println!(
        "var_ops-staged: {} / reserved {} ({:.1}%)",
        last_stats.var_ops_staged, last_stats.var_op_reserved, var_op_stage_util
    );
    println!("var_ops-live: {}", last_stats.var_ops);
    println!("stack reserve: {}", last_stats.stack_reserved);
    println!("locals reserve: {}", last_stats.locals_reserved);
    println!(
        "ssa-verify-before: {}",
        format_ssa_verify_result(&before_verify)
    );
    println!(
        "safe-passes: mem2reg,sccp,const-fold,dce (changed={})",
        last_pass_log.len()
    );
    if !last_pass_log.is_empty() {
        println!("safe-pass-log: {}", last_pass_log.join(","));
    }
    println!(
        "ssa-verify-after: {}",
        format_ssa_verify_result(&after_verify)
    );
    println!(
        "ssa-before: functions={} lowered={} unsupported={} blocks={} insts={} aliases={} consts={} binops={} calls={} effects={}",
        before_metrics.functions,
        before_metrics.lowered,
        before_metrics.unsupported,
        before_metrics.blocks,
        before_metrics.insts,
        before_metrics.aliases,
        before_metrics.consts,
        before_metrics.binops,
        before_metrics.calls,
        before_metrics.effects
    );
    println!(
        "ssa-after: functions={} lowered={} unsupported={} blocks={} insts={} aliases={} consts={} binops={} calls={} effects={}",
        after_metrics.functions,
        after_metrics.lowered,
        after_metrics.unsupported,
        after_metrics.blocks,
        after_metrics.insts,
        after_metrics.aliases,
        after_metrics.consts,
        after_metrics.binops,
        after_metrics.calls,
        after_metrics.effects
    );
    println!(
        "ssa-delta: insts={} aliases={} consts={} binops={} calls={} effects={}",
        signed_delta(after_metrics.insts, before_metrics.insts),
        signed_delta(after_metrics.aliases, before_metrics.aliases),
        signed_delta(after_metrics.consts, before_metrics.consts),
        signed_delta(after_metrics.binops, before_metrics.binops),
        signed_delta(after_metrics.calls, before_metrics.calls),
        signed_delta(after_metrics.effects, before_metrics.effects)
    );

    Ok(())
}

#[derive(Default)]
struct SsaMetrics {
    functions: usize,
    lowered: usize,
    unsupported: usize,
    blocks: usize,
    insts: usize,
    aliases: usize,
    consts: usize,
    binops: usize,
    calls: usize,
    effects: usize,
}

fn collect_ssa_metrics(program: &ssa::Program) -> SsaMetrics {
    let mut metrics = SsaMetrics::default();
    for function in program.iter_functions() {
        metrics.functions = metrics.functions.saturating_add(1);
        match function.status {
            ssa::BuildStatus::Lowered => {
                metrics.lowered = metrics.lowered.saturating_add(1);
            }
            ssa::BuildStatus::Unsupported(_) => {
                metrics.unsupported = metrics.unsupported.saturating_add(1);
            }
        }
        metrics.blocks = metrics.blocks.saturating_add(function.blocks.len());
        for block in &function.blocks {
            metrics.insts = metrics.insts.saturating_add(block.insts.len());
            for inst in &block.insts {
                match &inst.kind {
                    ssa::InstKind::Alias(_) => {
                        metrics.aliases = metrics.aliases.saturating_add(1);
                    }
                    ssa::InstKind::Const(_) => {
                        metrics.consts = metrics.consts.saturating_add(1);
                    }
                    ssa::InstKind::BinOp { .. } => {
                        metrics.binops = metrics.binops.saturating_add(1);
                    }
                    ssa::InstKind::CallBuiltin { .. } | ssa::InstKind::CallFn { .. } => {
                        metrics.calls = metrics.calls.saturating_add(1);
                    }
                    ssa::InstKind::Emit { .. } => {
                        metrics.effects = metrics.effects.saturating_add(1);
                    }
                    _ => {}
                }
            }
        }
    }
    metrics
}

fn format_ssa_verify_result(result: &Result<(), Vec<String>>) -> String {
    match result {
        Ok(()) => "OK".into(),
        Err(errors) => {
            let head = errors
                .first()
                .cloned()
                .unwrap_or_else(|| "unknown verifier error".into());
            format!("FAILED ({})", head)
        }
    }
}

fn signed_delta(after: usize, before: usize) -> isize {
    after as isize - before as isize
}

fn percent(used: usize, reserved: usize) -> f64 {
    if reserved == 0 {
        0.0
    } else {
        (used as f64 * 100.0) / reserved as f64
    }
}

pub fn emit_bytecode(path: &Path, out: Option<&PathBuf>) -> Result<(), String> {
    let (_src, ast) = util::load_ast(path)?;
    typecheck::check_program(&ast).map_err(|e| {
        let loc = e
            .span
            .map(|s| format!(" ({}:{})", s.line, s.column))
            .unwrap_or_default();
        format!("Type error{}: {}", loc, e.message)
    })?;
    let program = compiler::compile_script(&ast);
    let bytes = nxb::encode_program(&program)?;
    let target = out.cloned().unwrap_or_else(|| path.with_extension("nxb"));
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
    }
    std::fs::write(&target, &bytes)
        .map_err(|e| format!("Failed to write {}: {}", target.display(), e))?;
    println!(
        "[BYTECODE] {} -> {} ({} bytes)",
        path.display(),
        target.display(),
        bytes.len()
    );
    // quick decode sanity check
    let decoded = nxb::decode_program(&bytes)?;
    if decoded.main.len() != program.main.len() {
        return Err("Roundtrip bytecode length mismatch".into());
    }
    println!("[BYTECODE] roundtrip OK");
    Ok(())
}

fn parse_engine(engine: &str) -> Result<DefaultEngine, String> {
    match engine.to_ascii_lowercase().as_str() {
        "vm" => Ok(DefaultEngine::Vm),
        "jit" => Ok(DefaultEngine::Jit),
        "interp" => Ok(DefaultEngine::Interp),
        other => Err(format!("Unknown engine `{}`", other)),
    }
}

fn parse_mode(mode: &str) -> Result<DefaultMode, String> {
    match mode.to_ascii_lowercase().as_str() {
        "plain" => Ok(DefaultMode::Plain),
        "cli" => Ok(DefaultMode::Cli),
        "html" => Ok(DefaultMode::Html),
        "json" => Ok(DefaultMode::Json),
        other => Err(format!("Unknown mode `{}`", other)),
    }
}

fn print_ir_block(name: &str, code: &[bytecode::Instr]) {
    println!("~ NAUX IR (function {}) ~", name);
    for (i, instr) in code.iter().enumerate() {
        println!("{:04} {}", i, bytecode::fmt_instr_bc(instr));
    }
    println!();
}
