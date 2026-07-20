pub mod cfg;

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::cli::run;
use crate::cli::util;
use crate::cli::{DefaultEngine, DefaultMode, DevCommand};
use crate::effects;
use crate::refinement;
use crate::region;
use crate::runtime;
use crate::runtime::env::Env;
use crate::runtime::error::format_runtime_error_with_file;
use crate::vm;
use crate::vm::{bytecode, compiler, ir, ssa};
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
        DevCommand::Ir { path } => ir_core(&path),
        DevCommand::Cfg { path, out } => cfg::cfg_core(&path, out.as_ref()),
        DevCommand::SsaStats { path, iters } => ssa_stats_core(&path, iters),
        DevCommand::Bench {
            path,
            engine,
            iters,
        } => bench_core(&path, &engine, iters),
        DevCommand::BenchRt {
            path,
            engine,
            iters,
            warmup_ms,
            json,
            trace_only,
        } => bench_runtime_core(&path, &engine, iters, warmup_ms, json, trace_only),
        DevCommand::Bytecode { path, out } => emit_bytecode(&path, out.as_ref()),
        DevCommand::Refine { path, strict } => refine_core(&path, strict),
        DevCommand::Region { path } => region_core(&path),
        DevCommand::Effects { path } => effects_core(&path),
    }
}

pub fn run_core(path: &Path, engine: &str, mode: &str, time: bool) -> Result<(), String> {
    let engine = parse_engine(engine)?;
    let mode = parse_mode(mode)?;
    run::handle_run(Some(path.to_path_buf()), mode, engine, time)
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

pub fn ir_core(path: &Path) -> Result<(), String> {
    let (_, ast) = util::load_ast(path)?;
    let (ir_prog, report) = compiler::compile_ir_with_report(&ast);
    println!("{}", ir::pretty_print_ir(&ir_prog));
    println!("--- Optimizer Feedback ---");
    println!("main: {}", report.main_feedback_stop.as_str());
    println!(
        "[materialization] identity_lhs={} identity_rhs={} const_zero={} const_one={} mul_to_shl={} block={}->{}",
        report.main_materialization.identity_from_lhs,
        report.main_materialization.identity_from_rhs,
        report.main_materialization.const_zero_result,
        report.main_materialization.const_one_result,
        report.main_materialization.mul_to_shl,
        report.main_materialization.block_len_before,
        report.main_materialization.block_len_after,
    );
    for round in &report.main_feedback_rounds {
        println!(
            "[feedback round {}] proof_grew={} evidence_growth={} block_delta={} shape_delta={} proof_delta={} block={}->{} materialization=({},{},{},{},{})",
            round.round,
            round.proof_grew,
            round.evidence_growth,
            round.block_delta,
            round.shape_delta,
            round.proof_delta,
            round.block_len_before,
            round.block_len_after,
            round.materialization.identity_from_lhs,
            round.materialization.identity_from_rhs,
            round.materialization.const_zero_result,
            round.materialization.const_one_result,
            round.materialization.mul_to_shl,
        );
        if !round.obligations.is_empty() {
            let mut discharged = 0_usize;
            let mut blocked = 0_usize;
            let mut deferred = 0_usize;
            let mut stop_reasons = BTreeSet::new();
            for batch in &round.obligations {
                stop_reasons.insert(format!("{:?}", batch.saturation_stop_reason));
                for obligation in &batch.obligations {
                    match obligation.status {
                        crate::vm::egraph::ObligationStatus::Discharged => {
                            discharged = discharged.saturating_add(1)
                        }
                        crate::vm::egraph::ObligationStatus::Blocked => {
                            blocked = blocked.saturating_add(1)
                        }
                        crate::vm::egraph::ObligationStatus::Deferred => {
                            deferred = deferred.saturating_add(1)
                        }
                    }
                }
            }
            println!(
                "[obligations round {}] batches={} discharged={} blocked={} deferred={} stop_reasons={}",
                round.round,
                round.obligations.len(),
                discharged,
                blocked,
                deferred,
                stop_reasons.into_iter().collect::<Vec<_>>().join(","),
            );
        }
    }
    if !report.function_feedback_stops.is_empty() {
        let mut names = report
            .function_feedback_stops
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        names.sort();
        for name in names {
            if let Some(stop) = report.function_feedback_stops.get(&name) {
                println!("fn {}: {}", name, stop.as_str());
            }
        }
    }

    let mut ssa_prog = ssa::lower_program(&ir_prog);
    let mut pm = ssa::PassManager::with_default_pipeline();
    let applied = pm.run_program(&mut ssa_prog);

    println!("--- SSA (phase-1 preview) ---");
    println!("{}", ssa::pretty_print_program(&ssa_prog));
    if !applied.is_empty() {
        println!("SSA passes: {}", applied.join(", "));
    }
    match ssa::verify_program_ssa(&ssa_prog) {
        Ok(()) => println!("SSA verify: OK"),
        Err(errors) => {
            println!("SSA verify: FAILED");
            for err in errors.iter().take(10) {
                println!("  - {}", err);
            }
            if errors.len() > 10 {
                println!("  - ... {} more", errors.len() - 10);
            }
        }
    }
    Ok(())
}

pub fn refine_core(path: &Path, strict: bool) -> Result<(), String> {
    let (_, ast) = util::load_ast(path)?;

    // Phase 1: Standard typecheck.
    typecheck::check_program(&ast).map_err(|e| {
        let loc = e
            .span
            .map(|s| format!(" ({}:{})", s.line, s.column))
            .unwrap_or_default();
        format!("Type error{}: {}", loc, e.message)
    })?;

    // Phase 2: Refinement type checking.
    println!("~ NAUX REFINEMENT ANALYSIS ~");
    println!("path: {}", path.display());
    println!("mode: {}", if strict { "strict" } else { "advisory" });
    println!();

    let config = refinement::SolverConfig {
        strict_mode: strict,
        ..Default::default()
    };

    let mut env = refinement::RefinementEnv::new();
    let mut cset = refinement::ConstraintSet::new();
    let mut gen_errors = Vec::new();

    for stmt in &ast {
        if let Err(e) = refinement::generate_stmt_constraints_pub(stmt, &mut env, &mut cset) {
            gen_errors.push(e);
        }
    }

    if !gen_errors.is_empty() {
        println!(
            "[ERRORS] {} constraint generation errors:",
            gen_errors.len()
        );
        for e in &gen_errors {
            if let Some(ref span) = e.span {
                println!("  ✗ {}:{}: {}", span.line, span.column, e.message);
            } else {
                println!("  ✗ {}", e.message);
            }
        }
        return Err(format!(
            "{} refinement generation error(s)",
            gen_errors.len()
        ));
    }

    println!("[CONSTRAINTS] {} total", cset.len());
    for (i, c) in cset.iter().enumerate() {
        println!("  C{}: {}", i, c.describe());
    }
    println!();

    let solver = refinement::Solver::new(config);
    let result = solver.solve(&cset);

    println!("[SOLVER]");
    println!("  discharged: {}", result.discharged);
    println!("  failed:     {}", result.failed);
    println!();

    if !result.proof_slots.is_empty() {
        println!(
            "[PROOF EVIDENCE] → ProofSlot bridge ({} vars)",
            result.proof_slots.len()
        );
        for (name, slot) in &result.proof_slots {
            if let Some(ref numeric) = slot.numeric {
                let mut facts = Vec::new();
                if let Some(exact) = numeric.exact {
                    facts.push(format!("exact={}", exact));
                }
                if let Some((lo, hi)) = numeric.range {
                    facts.push(format!("range=[{}, {}]", lo, hi));
                }
                if numeric.nonzero {
                    facts.push("nonzero".into());
                }
                let score = numeric.evidence_score();
                println!(
                    "  ${}: {} (evidence_score={})",
                    name,
                    facts.join(", "),
                    score
                );
            }
        }
        println!();
    }

    if !result.warnings.is_empty() {
        println!("[WARNINGS] {}", result.warnings.len());
        for w in &result.warnings {
            println!("  ⚠ {}", w);
        }
        println!();
    }

    if !result.errors.is_empty() {
        println!("[ERRORS] {}", result.errors.len());
        for e in &result.errors {
            println!("  ✗ {}", e);
        }
        return Err(format!("{} refinement error(s)", result.errors.len()));
    }

    let (ir_prog, opt_report) = compiler::compile_ir_with_report(&ast);
    print_sefo_feedback(&opt_report);
    if strict {
        compiler::validate_optimization_proof_contract(&ir_prog, &opt_report)
            .map_err(|err| format!("Strict proof contract failed: {}", err))?;
        println!("[STRICT PROOF CONTRACT] OK");
        println!();
    }

    println!(
        "[RESULT] OK — {} constraints discharged, {} proof slots generated",
        result.discharged,
        result.proof_slots.len()
    );
    Ok(())
}

fn print_sefo_feedback(report: &compiler::OptimizationReport) {
    println!("[SEFO FEEDBACK]");
    println!("  main_stop: {}", report.main_feedback_stop.as_str());
    println!(
        "  materialized: identity_lhs={} identity_rhs={} const_zero={} div_self_to_one={} mul_to_shl={} block={}->{}",
        report.main_materialization.identity_from_lhs,
        report.main_materialization.identity_from_rhs,
        report.main_materialization.const_zero_result,
        report.main_materialization.const_one_result,
        report.main_materialization.mul_to_shl,
        report.main_materialization.block_len_before,
        report.main_materialization.block_len_after,
    );

    if report.main_feedback_rounds.is_empty() {
        println!("  rounds: 0");
    } else {
        for round in &report.main_feedback_rounds {
            println!(
                "  round {}: proof_grew={} evidence_growth={} block_delta={} shape_delta={} proof_delta={} block={}->{}",
                round.round,
                round.proof_grew,
                round.evidence_growth,
                round.block_delta,
                round.shape_delta,
                round.proof_delta,
                round.block_len_before,
                round.block_len_after,
            );
            println!(
                "    materialized: identity_lhs={} identity_rhs={} const_zero={} div_self_to_one={} mul_to_shl={}",
                round.materialization.identity_from_lhs,
                round.materialization.identity_from_rhs,
                round.materialization.const_zero_result,
                round.materialization.const_one_result,
                round.materialization.mul_to_shl,
            );
            print_obligation_diagnostics(round);
        }
    }

    if !report.function_feedback_stops.is_empty() {
        let mut names = report
            .function_feedback_stops
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        names.sort();
        for name in names {
            if let Some(stop) = report.function_feedback_stops.get(&name) {
                println!("  fn {}: {}", name, stop.as_str());
            }
        }
    }
    println!();
}

fn print_obligation_diagnostics(round: &compiler::FeedbackRoundStats) {
    const MAX_DETAILS_PER_BATCH: usize = 12;

    for batch in &round.obligations {
        let mut discharged = 0_usize;
        let mut blocked = 0_usize;
        let mut deferred = 0_usize;
        for obligation in &batch.obligations {
            match obligation.status {
                vm::egraph::ObligationStatus::Discharged => {
                    discharged = discharged.saturating_add(1)
                }
                vm::egraph::ObligationStatus::Blocked => blocked = blocked.saturating_add(1),
                vm::egraph::ObligationStatus::Deferred => deferred = deferred.saturating_add(1),
            }
        }

        println!(
            "    obligations stage={} stop={:?} discharged={} blocked={} deferred={}",
            batch.stage, batch.saturation_stop_reason, discharged, blocked, deferred,
        );

        for (idx, obligation) in batch.obligations.iter().enumerate() {
            if idx >= MAX_DETAILS_PER_BATCH {
                println!(
                    "      ... {} more obligations",
                    batch.obligations.len() - MAX_DETAILS_PER_BATCH
                );
                break;
            }
            let eclass = obligation
                .eclass
                .map(|id| format!(" eclass={}", id))
                .unwrap_or_default();
            println!(
                "      {:?}: {} requires {:?}{}",
                obligation.status, obligation.rewrite_name, obligation.requirement, eclass,
            );
        }
    }
}

pub fn region_core(path: &Path) -> Result<(), String> {
    let (_, ast) = util::load_ast(path)?;

    // Phase 1: Standard typecheck.
    typecheck::check_program(&ast).map_err(|e| {
        let loc = e
            .span
            .map(|s| format!(" ({}:{})", s.line, s.column))
            .unwrap_or_default();
        format!("Type error{}: {}", loc, e.message)
    })?;

    // Phase 2: Region inference.
    println!("~ NAUX REGION ANALYSIS ~");
    println!("path: {}", path.display());
    println!();

    let report = region::infer_regions(&ast);

    println!("[REGIONS] {} created", report.regions_created);
    println!("[ALLOCATIONS] {} tracked", report.allocations_tracked);
    println!();

    // Print region tree.
    let mut sorted_regions: Vec<_> = report.region_map.values().collect();
    sorted_regions.sort_by_key(|r| r.id);
    for region in &sorted_regions {
        let parent_str = region
            .parent
            .map(|p| format!(" ← ρ{}", p))
            .unwrap_or_default();
        let allocs = if region.allocations.is_empty() {
            "(empty)".to_string()
        } else {
            region
                .allocations
                .iter()
                .map(|a| format!("${}", a))
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!(
            "  ρ{} [{}]{}: {}",
            region.id,
            region.kind.as_str(),
            parent_str,
            allocs
        );
    }
    println!();

    if !report.promotions.is_empty() {
        println!("[PROMOTIONS] {} escaping values:", report.promotions.len());
        for p in &report.promotions {
            println!(
                "  ${}: ρ{} → ρ{} ({})",
                p.var, p.from_region, p.to_region, p.reason
            );
        }
        println!();
    }

    if !report.violations.is_empty() {
        println!(
            "[VIOLATIONS] {} region constraint errors:",
            report.violations.len()
        );
        for v in &report.violations {
            println!("  ✗ {}", v);
        }
        return Err(format!("{} region violation(s)", report.violations.len()));
    }

    println!(
        "[RESULT] OK — {} regions, {} allocations, {} promotions",
        report.regions_created,
        report.allocations_tracked,
        report.promotions.len()
    );
    Ok(())
}

pub fn effects_core(path: &Path) -> Result<(), String> {
    let (_, ast) = util::load_ast(path)?;

    println!("~ NAUX EFFECT ANALYSIS ~");
    println!("path: {}", path.display());
    println!();

    let result = effects::handle_effects(&ast);

    println!("[SIGNATURE] {}", result.signature);
    println!();

    if result.unhandled.is_empty() {
        println!("[EFFECTS] Pure — no side effects detected");
    } else {
        println!("[EFFECTS] {} operations:", result.unhandled.len());
        for (i, effect) in result.unhandled.iter().enumerate() {
            let args_str = effect
                .args
                .iter()
                .map(|a| format!("{}", a))
                .collect::<Vec<_>>()
                .join(", ");
            println!("  E{}: !{}({}) [{}]", i, effect.op, args_str, effect.name);
        }
    }
    println!();

    // Show builtin effect registry.
    let registry = effects::types::EffectRegistry::with_builtins();
    println!("[REGISTRY] {} built-in effects:", registry.effects.len());
    let mut names: Vec<_> = registry.effects.keys().collect();
    names.sort();
    for name in &names {
        let decl = registry.lookup(name).unwrap();
        let ops: Vec<_> = decl
            .operations
            .iter()
            .map(|o| {
                format!(
                    "!{}({}) → {}",
                    o.name,
                    o.params
                        .iter()
                        .map(|p| format!("{}: {}", p.name, p.ty))
                        .collect::<Vec<_>>()
                        .join(", "),
                    o.return_type
                )
            })
            .collect();
        println!("  effect {} {{ {} }}", name, ops.join(", "));
    }
    println!();

    println!(
        "[RESULT] signature={}, {} effect operations",
        result.signature,
        result.unhandled.len()
    );
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

pub fn bench_core(path: &Path, engine: &str, iters: u32) -> Result<(), String> {
    let engine = parse_engine(engine)?;
    let (src, ast) = util::load_ast(path)?;
    if iters == 0 {
        return Err("iters phải lớn hơn 0".into());
    }
    let program = compiler::compile_script(&ast);
    let hotspots = summarize_hotspots(&program, 5);
    let start = Instant::now();
    for _ in 0..iters {
        let _ = util::execute_ast(engine, &ast, &src, path, false)?;
    }
    let elapsed = start.elapsed();
    let avg_ns = elapsed.as_nanos() / iters as u128;
    let ops_sec = if avg_ns > 0 {
        1_000_000_000 / avg_ns
    } else {
        0
    };

    println!("~ NAUX BENCH ~");
    println!(
        "[BENCH] {} ns/op ({} ops/sec) over {} runs (engine={})",
        avg_ns,
        ops_sec,
        iters,
        format_engine(engine)
    );
    if !hotspots.is_empty() {
        println!("Hotinstructions:");
        for (instr, count) in hotspots {
            println!("  {:<5}x {}", count, instr);
        }
    }
    Ok(())
}

pub fn bench_runtime_core(
    path: &Path,
    engine: &str,
    iters: u32,
    warmup_ms: u64,
    json: bool,
    trace_only: bool,
) -> Result<(), String> {
    let engine = parse_engine(engine)?;
    let (src, ast) = util::load_ast(path)?;
    typecheck::check_program(&ast).map_err(|e| {
        let loc = e
            .span
            .map(|s| format!(" ({}:{})", s.line, s.column))
            .unwrap_or_default();
        format!("Type error{}: {}", loc, e.message)
    })?;
    let program = compiler::compile_script(&ast);

    let mut env = Env::new();
    crate::stdlib::register_all(&mut env);
    let builtins = env.builtins();

    if iters == 0 {
        return Err("iters phải lớn hơn 0".into());
    }

    let mut jit_runner =
        if engine == DefaultEngine::Jit && vm::typed::is_supported_program(&program) {
            Some(vm::typed::TypedRunner::new(&program))
        } else {
            None
        };
    let mut used_fallback = false;

    let warmup_target = Duration::from_millis(warmup_ms);
    let warmup_start = Instant::now();
    let mut warmup_iters = 0u32;
    while warmup_start.elapsed() < warmup_target {
        let _ = run_once(
            engine,
            &program,
            &ast,
            &src,
            path,
            &builtins,
            &mut jit_runner,
            &mut used_fallback,
        )?;
        warmup_iters += 1;
    }

    if trace_only {
        if engine != DefaultEngine::Jit {
            return Err("trace-only benchmark chỉ hỗ trợ --engine=jit".into());
        }
        let Some(runner) = jit_runner.as_mut() else {
            return Err("trace-only benchmark requires typed JIT-supported program".into());
        };
        if used_fallback {
            return Err("trace-only benchmark requires JIT path without fallback".into());
        }

        let prep = runner
            .prepare_trace_only(&program)
            .map_err(|e| e.to_string())?;
        for _ in 0..8 {
            let _ = runner.run_trace_only().map_err(|e| e.to_string())?;
        }
        runner.reset_runtime_path_totals();

        let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
        let mut element_samples: Vec<u64> = Vec::with_capacity(iters as usize);
        let mut total_avx_dot_elements: u64 = 0;
        let mut total_interp_index_elements: u64 = 0;
        for _ in 0..iters {
            let trace_timing = runner.run_trace_only().map_err(|e| e.to_string())?;
            samples.push(trace_timing.trace_ns);
            let total_elems = trace_timing
                .avx_dot_elements
                .saturating_add(trace_timing.interp_index_elements);
            element_samples.push(total_elems);
            total_avx_dot_elements =
                total_avx_dot_elements.saturating_add(trace_timing.avx_dot_elements);
            total_interp_index_elements =
                total_interp_index_elements.saturating_add(trace_timing.interp_index_elements);
        }

        let trace_summary = runner.trace_summary();
        runner.cleanup();

        samples.sort_unstable();
        element_samples.sort_unstable();
        let median = percentile(&samples, 50.0);
        let p95 = percentile(&samples, 95.0);
        let median_elements = percentile_u64(&element_samples, 50.0);
        let median_ns_per_elem = if median_elements > 0 {
            (median as f64) / (median_elements as f64)
        } else {
            0.0
        };
        let median_ops = if median > 0 {
            1_000_000_000u128 / median
        } else {
            0
        };
        let total_index_elements =
            total_avx_dot_elements.saturating_add(total_interp_index_elements);
        let avx_element_share = if total_index_elements > 0 {
            (total_avx_dot_elements as f64) / (total_index_elements as f64)
        } else {
            0.0
        };

        if json {
            println!(
                "{{\"engine\":\"{}\",\"mode\":\"trace-only\",\"iters\":{},\"warmup_ms\":{},\"warmup_iters\":{},\"median_ns\":{},\"p95_ns\":{},\"median_ops\":{},\"median_elements\":{},\"median_ns_per_elem\":{:.9},\"avx_dot_elements_total\":{},\"interp_index_elements_total\":{},\"avx_element_share\":{:.4},\"trace_count\":{},\"trace_loop_header\":{},\"trace_hits\":{},\"super_count\":{},\"total_hits\":{},\"total_deopts\":{},\"fallback\":{}}}",
                format_engine(engine),
                iters,
                warmup_ms,
                warmup_iters,
                median,
                p95,
                median_ops,
                median_elements,
                median_ns_per_elem,
                total_avx_dot_elements,
                total_interp_index_elements,
                avx_element_share,
                prep.trace_count,
                prep.loop_header,
                prep.hits,
                trace_summary.super_count,
                trace_summary.total_hits,
                trace_summary.total_deopts,
                used_fallback
            );
        } else {
            println!("~ NAUX BENCH (trace-only) ~");
            println!(
                "[BENCH] median={} ns/op ({} ops/sec), p95={} ns/op over {} runs (warmup {} ms, {} iters) engine={}",
                median,
                median_ops,
                p95,
                iters,
                warmup_ms,
                warmup_iters,
                format_engine(engine)
            );
            println!(
                "[TRACE-ONLY] loop_header={} trace_count={} hits={}",
                prep.loop_header, prep.trace_count, prep.hits
            );
            println!(
                "[PATH] elements(avx/interp/total)={}/{}/{} avx_share={:.2}% interp_share={:.2}%",
                total_avx_dot_elements,
                total_interp_index_elements,
                total_index_elements,
                avx_element_share * 100.0,
                (1.0 - avx_element_share) * 100.0
            );
            println!(
                "[TRACE-ONLY SLOPE] median_ns_per_elem={:.9} (median_elements={})",
                median_ns_per_elem, median_elements
            );
        }
        return Ok(());
    }

    let mut preheat_iters = 0u32;
    let mut dropped_transition_samples = 0u32;
    let mut sample_attempts = 0u32;
    if engine == DefaultEngine::Jit && jit_runner.is_some() && !used_fallback {
        const PREHEAT_MIN_ITERS: u32 = 2;
        const PREHEAT_MAX_ITERS: u32 = 12;
        const PREHEAT_STABLE_STREAK_TARGET: u32 = 2;
        const PREHEAT_MIN_TRACE_COUNT: usize = 1;

        let mut stable_streak = 0u32;
        let mut marker = jit_runner
            .as_ref()
            .map(trace_phase_marker)
            .unwrap_or_default();
        while preheat_iters < PREHEAT_MAX_ITERS {
            let _ = run_once(
                engine,
                &program,
                &ast,
                &src,
                path,
                &builtins,
                &mut jit_runner,
                &mut used_fallback,
            )?;
            preheat_iters = preheat_iters.saturating_add(1);
            if used_fallback {
                break;
            }
            let current = jit_runner
                .as_ref()
                .map(trace_phase_marker)
                .unwrap_or_default();
            if current == marker {
                stable_streak = stable_streak.saturating_add(1);
            } else {
                stable_streak = 0;
                marker = current;
            }
            if preheat_iters >= PREHEAT_MIN_ITERS
                && stable_streak >= PREHEAT_STABLE_STREAK_TARGET
                && current.trace_count >= PREHEAT_MIN_TRACE_COUNT
            {
                break;
            }
        }
    }

    if let Some(runner) = jit_runner.as_mut() {
        runner.reset_runtime_path_totals();
    }

    let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
    let mut setup_samples: Vec<u128> = Vec::with_capacity(iters as usize);
    let mut compute_samples: Vec<u128> = Vec::with_capacity(iters as usize);
    let mut total_list_range_calls: u64 = 0;
    let mut total_avx_dot_elements: u64 = 0;
    let mut total_interp_index_elements: u64 = 0;
    const MAX_TRANSITION_DROPS: u32 = 12;
    const TRANSITION_COOLDOWN_SAMPLES: u32 = 2;
    const MAX_EXTRA_ATTEMPTS: u32 = 40;
    let mut post_transition_cooldown = 0u32;
    let mut last_marker = jit_runner.as_ref().map(trace_phase_marker);
    while (samples.len() as u32) < iters {
        if sample_attempts >= iters.saturating_add(MAX_EXTRA_ATTEMPTS) {
            return Err(format!(
                "runtime benchmark could not collect stable samples (collected={}, requested={}, attempts={}, dropped={})",
                samples.len(),
                iters,
                sample_attempts,
                dropped_transition_samples
            ));
        }
        sample_attempts = sample_attempts.saturating_add(1);
        let pre_marker = if engine == DefaultEngine::Jit && !used_fallback {
            jit_runner.as_ref().map(trace_phase_marker)
        } else {
            None
        };
        let t0 = Instant::now();
        let split = run_once(
            engine,
            &program,
            &ast,
            &src,
            path,
            &builtins,
            &mut jit_runner,
            &mut used_fallback,
        )?;
        let dt = t0.elapsed();
        let post_marker = if engine == DefaultEngine::Jit && !used_fallback {
            jit_runner.as_ref().map(trace_phase_marker)
        } else {
            None
        };
        if pre_marker.is_some()
            && post_marker.is_some()
            && pre_marker != post_marker
            && dropped_transition_samples < MAX_TRANSITION_DROPS
        {
            dropped_transition_samples = dropped_transition_samples.saturating_add(1);
            post_transition_cooldown = TRANSITION_COOLDOWN_SAMPLES;
            last_marker = post_marker;
            continue;
        }
        if post_transition_cooldown > 0
            && post_marker.is_some()
            && dropped_transition_samples < MAX_TRANSITION_DROPS
        {
            if post_marker != last_marker {
                post_transition_cooldown = TRANSITION_COOLDOWN_SAMPLES;
            } else {
                post_transition_cooldown = post_transition_cooldown.saturating_sub(1);
            }
            last_marker = post_marker;
            dropped_transition_samples = dropped_transition_samples.saturating_add(1);
            continue;
        }
        samples.push(dt.as_nanos());
        if split.has_split {
            setup_samples.push(split.setup_ns);
            compute_samples.push(split.compute_ns);
            total_list_range_calls = total_list_range_calls.saturating_add(split.list_range_calls);
            total_avx_dot_elements = total_avx_dot_elements.saturating_add(split.avx_dot_elements);
            total_interp_index_elements =
                total_interp_index_elements.saturating_add(split.interp_index_elements);
        }
    }

    if let Some(runner) = jit_runner.as_mut() {
        runner.cleanup();
    }

    let trace_summary = jit_runner.as_ref().map(|runner| runner.trace_summary());

    samples.sort_unstable();
    let median = percentile(&samples, 50.0);
    let p95 = percentile(&samples, 95.0);
    let (split_available, setup_median, setup_p95, compute_median, compute_p95) =
        if !setup_samples.is_empty() && setup_samples.len() == compute_samples.len() {
            setup_samples.sort_unstable();
            compute_samples.sort_unstable();
            (
                true,
                percentile(&setup_samples, 50.0),
                percentile(&setup_samples, 95.0),
                percentile(&compute_samples, 50.0),
                percentile(&compute_samples, 95.0),
            )
        } else {
            (false, 0, 0, 0, 0)
        };
    let median_ops = if median > 0 {
        1_000_000_000u128 / median
    } else {
        0
    };
    let total_index_elements = total_avx_dot_elements.saturating_add(total_interp_index_elements);
    let avx_element_share = if total_index_elements > 0 {
        (total_avx_dot_elements as f64) / (total_index_elements as f64)
    } else {
        0.0
    };

    if json {
        let site_profiles_json = trace_summary
            .as_ref()
            .map(|s| {
                let mut out = String::from("[");
                for (i, p) in s.site_profiles.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    let total = p.taken_accum.saturating_add(p.not_taken_accum);
                    let taken_ratio = if total > 0 {
                        (p.taken_accum as f64) / (total as f64)
                    } else {
                        0.0
                    };
                    out.push_str(&format!(
                        "{{\"loop_header\":{},\"site_idx\":{},\"counter_idx\":{},\"kind\":{},\"patchable\":{},\"inverted\":{},\"stability_score\":{},\"revert_streak\":{},\"cooldown_epochs\":{},\"stable_epochs\":{},\"taken_accum\":{},\"not_taken_accum\":{},\"taken_ratio\":{:.4}}}",
                        p.loop_header,
                        p.site_idx,
                        p.counter_idx,
                        p.kind,
                        p.patchable,
                        p.inverted,
                        p.stability_score,
                        p.revert_streak,
                        p.cooldown_epochs,
                        p.stable_epochs,
                        p.taken_accum,
                        p.not_taken_accum,
                        taken_ratio
                    ));
                }
                out.push(']');
                out
            })
            .unwrap_or_else(|| "[]".to_string());
        let fusion_hits_json = trace_summary
            .as_ref()
            .map(|s| {
                let mut out = String::from("[");
                for (i, p) in s.fusion_hits_by_rule.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&format!(
                        "{{\"rule\":\"{}\",\"static_hits\":{},\"runtime_hits\":{}}}",
                        p.rule, p.static_hits, p.runtime_hits
                    ));
                }
                out.push(']');
                out
            })
            .unwrap_or_else(|| "[]".to_string());
        let deopt_reasons_json = trace_summary
            .as_ref()
            .map(|s| {
                let mut out = String::from("[");
                for (i, p) in s.deopt_reasons.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&format!(
                        "{{\"reason\":\"{}\",\"count\":{}}}",
                        p.reason, p.count
                    ));
                }
                out.push(']');
                out
            })
            .unwrap_or_else(|| "[]".to_string());
        let guard_fails_json = trace_summary
            .as_ref()
            .map(|s| {
                let mut out = String::from("[");
                for (i, p) in s.guard_fails_by_guard.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&format!(
                        "{{\"guard_id\":{},\"reason\":\"{}\",\"count\":{}}}",
                        p.guard_id, p.reason, p.count
                    ));
                }
                out.push(']');
                out
            })
            .unwrap_or_else(|| "[]".to_string());
        let by_trace_json = trace_summary
            .as_ref()
            .map(|s| {
                let mut out = String::from("[");
                for (i, p) in s.by_trace.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&format!(
                        "{{\"trace_id\":{},\"loop_header\":{},\"first_seen_ts_ms\":{},\"last_seen_ts_ms\":{},\"trace_lifetime_ms\":{},\"hits\":{},\"deopts\":{},\"guard_checks\":{},\"guard_fails\":{},\"runtime_deopts\":{},\"is_hot\":{}}}",
                        p.trace_id,
                        p.loop_header,
                        p.first_seen_ts_ms,
                        p.last_seen_ts_ms,
                        p.trace_lifetime_ms,
                        p.hits,
                        p.deopts,
                        p.guard_checks,
                        p.guard_fails,
                        p.runtime_deopts,
                        p.is_hot
                    ));
                }
                out.push(']');
                out
            })
            .unwrap_or_else(|| "[]".to_string());
        let (
            trace_count,
            super_count,
            min_ops,
            max_ops,
            avg_ops,
            min_code_bytes,
            max_code_bytes,
            avg_code_bytes,
            min_hot_code_bytes,
            max_hot_code_bytes,
            avg_hot_code_bytes,
            max_live,
            max_bc_len,
            total_hits,
            total_deopts,
            total_static_calls,
            total_static_branches,
            total_runtime_calls,
            total_runtime_branch_taken,
            total_runtime_branch_not_taken,
            total_runtime_branches,
            total_runtime_trace_iters,
            total_runtime_deopts,
            total_runtime_temp_list_elided,
            total_runtime_temp_map_elided,
            total_runtime_temp_list_materialized,
            total_runtime_temp_map_materialized,
            total_patch_sites,
            max_patch_sites,
            total_patch_attempts,
            total_patch_commits,
            total_patch_reverts,
            total_adaptive_epochs,
            max_adaptive_stable_epochs,
            max_revert_streak,
            max_deopt,
            max_hot,
        ) = trace_summary
            .as_ref()
            .map(|s| {
                (
                    s.trace_count,
                    s.super_count,
                    s.min_ops,
                    s.max_ops,
                    s.avg_ops,
                    s.min_code_bytes,
                    s.max_code_bytes,
                    s.avg_code_bytes,
                    s.min_hot_code_bytes,
                    s.max_hot_code_bytes,
                    s.avg_hot_code_bytes,
                    s.max_live,
                    s.max_bc_len,
                    s.total_hits,
                    s.total_deopts,
                    s.total_static_calls,
                    s.total_static_branches,
                    s.total_runtime_calls,
                    s.total_runtime_branch_taken,
                    s.total_runtime_branch_not_taken,
                    s.total_runtime_branches,
                    s.total_runtime_trace_iters,
                    s.total_runtime_deopts,
                    s.total_runtime_temp_list_elided,
                    s.total_runtime_temp_map_elided,
                    s.total_runtime_temp_list_materialized,
                    s.total_runtime_temp_map_materialized,
                    s.total_patch_sites,
                    s.max_patch_sites,
                    s.total_patch_attempts,
                    s.total_patch_commits,
                    s.total_patch_reverts,
                    s.total_adaptive_epochs,
                    s.max_adaptive_stable_epochs,
                    s.max_revert_streak,
                    s.max_deopt,
                    s.max_hot,
                )
            })
            .unwrap_or((
                0, 0, 0, 0, 0.0, 0, 0, 0.0, 0, 0, 0.0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ));
        let (hot_trace_id, guard_checks_total, guard_fail_total, build_fingerprint_json) =
            trace_summary
                .as_ref()
                .map(|s| {
                    (
                        s.hot_trace_id,
                        s.guard_checks_total,
                        s.guard_fail_total,
                        format!(
                            "{{\"git_sha\":\"{}\",\"rustc_version\":\"{}\",\"opt_level\":\"{}\"}}",
                            s.build_fingerprint.git_sha,
                            s.build_fingerprint.rustc_version,
                            s.build_fingerprint.opt_level
                        ),
                    )
                })
                .unwrap_or((
                    0,
                    0,
                    0,
                    "{\"git_sha\":\"unknown\",\"rustc_version\":\"unknown\",\"opt_level\":\"unknown\"}"
                        .to_string(),
                ));
        let branch_taken_ratio = if total_runtime_branches > 0 {
            (total_runtime_branch_taken as f64) / (total_runtime_branches as f64)
        } else {
            0.0
        };
        println!(
            "{{\"engine\":\"{}\",\"iters\":{},\"warmup_ms\":{},\"warmup_iters\":{},\"preheat_iters\":{},\"dropped_transition_samples\":{},\"sample_attempts\":{},\"median_ns\":{},\"p95_ns\":{},\"median_ops\":{},\"fallback\":{},\"split_available\":{},\"setup_median_ns\":{},\"setup_p95_ns\":{},\"compute_median_ns\":{},\"compute_p95_ns\":{},\"list_range_calls_total\":{},\"avx_dot_elements_total\":{},\"interp_index_elements_total\":{},\"avx_element_share\":{:.4},\"trace_count\":{},\"super_count\":{},\"min_ops\":{},\"max_ops\":{},\"avg_ops\":{:.2},\"min_code_bytes\":{},\"max_code_bytes\":{},\"avg_code_bytes\":{:.2},\"min_hot_code_bytes\":{},\"max_hot_code_bytes\":{},\"avg_hot_code_bytes\":{:.2},\"max_live\":{},\"max_bc_len\":{},\"total_hits\":{},\"total_deopts\":{},\"total_static_calls\":{},\"total_static_branches\":{},\"total_runtime_calls\":{},\"total_runtime_branch_taken\":{},\"total_runtime_branch_not_taken\":{},\"total_runtime_branches\":{},\"branch_taken_ratio\":{:.4},\"total_runtime_trace_iters\":{},\"total_runtime_deopts\":{},\"total_runtime_temp_list_elided\":{},\"total_runtime_temp_map_elided\":{},\"total_runtime_temp_list_materialized\":{},\"total_runtime_temp_map_materialized\":{},\"total_patch_sites\":{},\"max_patch_sites\":{},\"total_patch_attempts\":{},\"total_patch_commits\":{},\"total_patch_reverts\":{},\"total_adaptive_epochs\":{},\"max_adaptive_stable_epochs\":{},\"max_revert_streak\":{},\"max_deopt\":{},\"max_hot\":{},\"hot_trace_id\":{},\"guard_checks_total\":{},\"guard_fail_total\":{},\"build_fingerprint\":{},\"fusion_hits_by_rule\":{},\"site_profiles\":{},\"deopt_reasons\":{},\"guard_fails_by_guard\":{},\"by_trace\":{}}}",
            format_engine(engine),
            iters,
            warmup_ms,
            warmup_iters,
            preheat_iters,
            dropped_transition_samples,
            sample_attempts,
            median,
            p95,
            median_ops,
            used_fallback,
            split_available,
            setup_median,
            setup_p95,
            compute_median,
            compute_p95,
            total_list_range_calls,
            total_avx_dot_elements,
            total_interp_index_elements,
            avx_element_share,
            trace_count,
            super_count,
            min_ops,
            max_ops,
            avg_ops,
            min_code_bytes,
            max_code_bytes,
            avg_code_bytes,
            min_hot_code_bytes,
            max_hot_code_bytes,
            avg_hot_code_bytes,
            max_live,
            max_bc_len,
            total_hits,
            total_deopts,
            total_static_calls,
            total_static_branches,
            total_runtime_calls,
            total_runtime_branch_taken,
            total_runtime_branch_not_taken,
            total_runtime_branches,
            branch_taken_ratio,
            total_runtime_trace_iters,
            total_runtime_deopts,
            total_runtime_temp_list_elided,
            total_runtime_temp_map_elided,
            total_runtime_temp_list_materialized,
            total_runtime_temp_map_materialized,
            total_patch_sites,
            max_patch_sites,
            total_patch_attempts,
            total_patch_commits,
            total_patch_reverts,
            total_adaptive_epochs,
            max_adaptive_stable_epochs,
            max_revert_streak,
            max_deopt,
            max_hot,
            hot_trace_id,
            guard_checks_total,
            guard_fail_total,
            build_fingerprint_json,
            fusion_hits_json,
            site_profiles_json,
            deopt_reasons_json,
            guard_fails_json,
            by_trace_json
        );
    } else {
        println!("~ NAUX BENCH (runtime-only) ~");
        println!(
            "[BENCH] median={} ns/op ({} ops/sec), p95={} ns/op over {} runs (warmup {} ms, {} iters) engine={}",
            median,
            median_ops,
            p95,
            iters,
            warmup_ms,
            warmup_iters,
            format_engine(engine)
        );
        if preheat_iters > 0 || dropped_transition_samples > 0 || sample_attempts > iters {
            println!(
                "[BENCH STABILIZE] preheat_iters={} dropped_transition_samples={} sample_attempts={}",
                preheat_iters, dropped_transition_samples, sample_attempts
            );
        }
        if split_available {
            let setup_ratio = if median > 0 {
                (setup_median as f64) * 100.0 / (median as f64)
            } else {
                0.0
            };
            println!(
                "[BENCH SPLIT] setup(list_range+alloc) median={} ns/op p95={} ns/op | compute median={} ns/op p95={} ns/op | setup_ratio={:.2}% list_range_calls_total={}",
                setup_median,
                setup_p95,
                compute_median,
                compute_p95,
                setup_ratio,
                total_list_range_calls
            );
            if total_index_elements > 0 {
                let interp_share = 1.0 - avx_element_share;
                println!(
                    "[PATH] elements(avx/interp/total)={}/{}/{} avx_share={:.2}% interp_share={:.2}%",
                    total_avx_dot_elements,
                    total_interp_index_elements,
                    total_index_elements,
                    avx_element_share * 100.0,
                    interp_share * 100.0
                );
            }
        }
        if let Some(summary) = trace_summary {
            if summary.trace_count == 0 {
                println!(
                    "[TRACE] none (hot threshold not reached or trace build failed, max_hot={})",
                    summary.max_hot
                );
            } else {
                let deopt_rate = if summary.total_hits > 0 {
                    (summary.total_deopts as f64) / (summary.total_hits as f64)
                } else {
                    0.0
                };
                let branch_taken_ratio = if summary.total_runtime_branches > 0 {
                    (summary.total_runtime_branch_taken as f64)
                        / (summary.total_runtime_branches as f64)
                } else {
                    0.0
                };
                println!(
                    "[TRACE] count={} super={} ops(min/avg/max)={}/{:.1}/{} code(min/avg/max)={}/{:.1}/{} hot_code(min/avg/max)={}/{:.1}/{} live_max={} bc_max={} hits={} deopt={} (rate {:.2}%) calls(static/runtime)={}/{} branches(static/runtime/taken/not)={}/{}/{}/{} ratio={:.2}% trace_iters={} runtime_deopts={} temps(elided_list/elided_map/materialized_list/materialized_map)={}/{}/{}/{} patch_sites(total/max)={}/{} patcher(attempt/commit/revert/epochs/max_stable/max_revert_streak)={}/{}/{}/{}/{}/{} max_deopt={} max_hot={}",
                    summary.trace_count,
                    summary.super_count,
                    summary.min_ops,
                    summary.avg_ops,
                    summary.max_ops,
                    summary.min_code_bytes,
                    summary.avg_code_bytes,
                    summary.max_code_bytes,
                    summary.min_hot_code_bytes,
                    summary.avg_hot_code_bytes,
                    summary.max_hot_code_bytes,
                    summary.max_live,
                    summary.max_bc_len,
                    summary.total_hits,
                    summary.total_deopts,
                    deopt_rate * 100.0,
                    summary.total_static_calls,
                    summary.total_runtime_calls,
                    summary.total_static_branches,
                    summary.total_runtime_branches,
                    summary.total_runtime_branch_taken,
                    summary.total_runtime_branch_not_taken,
                    branch_taken_ratio * 100.0,
                    summary.total_runtime_trace_iters,
                    summary.total_runtime_deopts,
                    summary.total_runtime_temp_list_elided,
                    summary.total_runtime_temp_map_elided,
                    summary.total_runtime_temp_list_materialized,
                    summary.total_runtime_temp_map_materialized,
                    summary.total_patch_sites,
                    summary.max_patch_sites,
                    summary.total_patch_attempts,
                    summary.total_patch_commits,
                    summary.total_patch_reverts,
                    summary.total_adaptive_epochs,
                    summary.max_adaptive_stable_epochs,
                    summary.max_revert_streak,
                    summary.max_deopt,
                    summary.max_hot
                );
                if !summary.fusion_hits_by_rule.is_empty() {
                    let mut fusion_line = String::new();
                    for (i, f) in summary.fusion_hits_by_rule.iter().enumerate() {
                        if i > 0 {
                            fusion_line.push_str(" | ");
                        }
                        fusion_line.push_str(&format!(
                            "{}:static={} runtime={}",
                            f.rule, f.static_hits, f.runtime_hits
                        ));
                    }
                    println!("[FUSION] {}", fusion_line);
                }
                if summary.guard_checks_total > 0 {
                    let fail_rate = (summary.guard_fail_total as f64) * 100.0
                        / (summary.guard_checks_total as f64);
                    println!(
                        "[GUARD] checks={} fails={} fail_rate={:.4}%",
                        summary.guard_checks_total, summary.guard_fail_total, fail_rate
                    );
                }
                if !summary.deopt_reasons.is_empty() {
                    let mut line = String::new();
                    for (i, d) in summary.deopt_reasons.iter().take(3).enumerate() {
                        if i > 0 {
                            line.push_str(" | ");
                        }
                        line.push_str(&format!("{}={}", d.reason, d.count));
                    }
                    println!("[DEOPT] top_reasons {}", line);
                }
            }
        }
        if used_fallback {
            println!("[WARN] JIT fallback -> VM occurred.");
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
struct RunSplit {
    has_split: bool,
    setup_ns: u128,
    compute_ns: u128,
    list_range_calls: u64,
    avx_dot_elements: u64,
    interp_index_elements: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct TracePhaseMarker {
    trace_count: usize,
    super_count: usize,
    total_patch_commits: u64,
    total_patch_reverts: u64,
}

fn trace_phase_marker(runner: &vm::typed::TypedRunner) -> TracePhaseMarker {
    let summary = runner.trace_summary();
    TracePhaseMarker {
        trace_count: summary.trace_count,
        super_count: summary.super_count,
        total_patch_commits: summary.total_patch_commits,
        total_patch_reverts: summary.total_patch_reverts,
    }
}

#[allow(clippy::too_many_arguments)]
fn run_once(
    engine: DefaultEngine,
    program: &bytecode::Program,
    ast: &[crate::ast::Stmt],
    src: &str,
    path: &Path,
    builtins: &HashMap<String, crate::runtime::env::BuiltinFn>,
    jit_runner: &mut Option<vm::typed::TypedRunner>,
    used_fallback: &mut bool,
) -> Result<RunSplit, String> {
    match engine {
        DefaultEngine::Vm => {
            let _ = vm::interpreter::run_program(program, builtins, src, &path.to_string_lossy())
                .map_err(|e| e.to_string())?;
            Ok(RunSplit::default())
        }
        DefaultEngine::Jit => {
            if let Some(runner) = jit_runner.as_mut() {
                let _ = runner.run(program).map_err(|e| e.to_string())?;
                let timing = runner.last_run_timing();
                runner.cleanup();
                Ok(RunSplit {
                    has_split: true,
                    setup_ns: timing.setup_ns,
                    compute_ns: timing.compute_ns,
                    list_range_calls: timing.list_range_calls,
                    avx_dot_elements: timing.avx_dot_elements,
                    interp_index_elements: timing.interp_index_elements,
                })
            } else {
                *used_fallback = true;
                let _ =
                    vm::interpreter::run_program(program, builtins, src, &path.to_string_lossy())
                        .map_err(|e| e.to_string())?;
                Ok(RunSplit::default())
            }
        }
        DefaultEngine::Interp => {
            let (_env, _events, errors) = runtime::eval_script(ast);
            if let Some(err) = errors.first() {
                return Err(format_runtime_error_with_file(
                    src,
                    err,
                    &path.to_string_lossy(),
                ));
            }
            Ok(RunSplit::default())
        }
    }
}

fn percentile(samples: &[u128], pct: f64) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    let rank = ((pct / 100.0) * (samples.len() as f64 - 1.0)).ceil() as usize;
    samples[rank.min(samples.len() - 1)]
}

fn percentile_u64(samples: &[u64], pct: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let rank = ((pct / 100.0) * (samples.len() as f64 - 1.0)).ceil() as usize;
    samples[rank.min(samples.len() - 1)]
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
    }
}

fn print_ir_block(name: &str, code: &[bytecode::Instr]) {
    println!("~ NAUX IR (function {}) ~", name);
    for (i, instr) in code.iter().enumerate() {
        println!("{:04} {}", i, bytecode::fmt_instr_bc(instr));
    }
    println!();
}

fn summarize_hotspots(program: &bytecode::Program, limit: usize) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for instr in program
        .main
        .iter()
        .chain(program.functions.values().flat_map(|f| f.code.iter()))
    {
        *counts.entry(bytecode::fmt_instr_bc(instr)).or_default() += 1;
    }
    let mut items: Vec<_> = counts.into_iter().collect();
    items.sort_by(|a, b| b.1.cmp(&a.1));
    items.truncate(limit);
    items
}

fn percent(used: usize, reserved: usize) -> f64 {
    if reserved == 0 {
        0.0
    } else {
        (used as f64 * 100.0) / reserved as f64
    }
}
