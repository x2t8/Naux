use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::cli::util;
use crate::cli::DefaultEngine;
use crate::runtime::env::Env;
use crate::runtime::error::format_runtime_error_with_file;
use crate::vm;
use crate::vm::{bytecode, compiler};
use crate::{runtime, typecheck};

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
    let ops_sec = 1_000_000_000u128.checked_div(avg_ns).unwrap_or(0);

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
        let median_ops = 1_000_000_000u128.checked_div(median).unwrap_or(0);
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

    let cv_pct = coefficient_of_variation_pct(&samples);
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
    let median_ops = 1_000_000_000u128.checked_div(median).unwrap_or(0);
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
                        "{{\"trace_id\":{},\"loop_header\":{},\"first_seen_ts_ms\":{},\"last_seen_ts_ms\":{},\"trace_lifetime_ms\":{},\"hits\":{},\"deopts\":{},\"internal_side_exits\":{},\"guard_checks\":{},\"guard_fails\":{},\"runtime_deopts\":{},\"is_hot\":{}}}",
                        p.trace_id,
                        p.loop_header,
                        p.first_seen_ts_ms,
                        p.last_seen_ts_ms,
                        p.trace_lifetime_ms,
                        p.hits,
                        p.deopts,
                        p.internal_side_exits,
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
        let total_internal_side_exits = trace_summary
            .as_ref()
            .map(|summary| summary.total_internal_side_exits)
            .unwrap_or(0);
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
            "{{\"engine\":\"{}\",\"iters\":{},\"warmup_ms\":{},\"warmup_iters\":{},\"preheat_iters\":{},\"dropped_transition_samples\":{},\"sample_attempts\":{},\"median_ns\":{},\"p95_ns\":{},\"cv_pct\":{:.4},\"median_ops\":{},\"fallback\":{},\"split_available\":{},\"setup_median_ns\":{},\"setup_p95_ns\":{},\"compute_median_ns\":{},\"compute_p95_ns\":{},\"list_range_calls_total\":{},\"avx_dot_elements_total\":{},\"interp_index_elements_total\":{},\"avx_element_share\":{:.4},\"trace_count\":{},\"super_count\":{},\"min_ops\":{},\"max_ops\":{},\"avg_ops\":{:.2},\"min_code_bytes\":{},\"max_code_bytes\":{},\"avg_code_bytes\":{:.2},\"min_hot_code_bytes\":{},\"max_hot_code_bytes\":{},\"avg_hot_code_bytes\":{:.2},\"max_live\":{},\"max_bc_len\":{},\"total_hits\":{},\"total_deopts\":{},\"total_internal_side_exits\":{},\"total_static_calls\":{},\"total_static_branches\":{},\"total_runtime_calls\":{},\"total_runtime_branch_taken\":{},\"total_runtime_branch_not_taken\":{},\"total_runtime_branches\":{},\"branch_taken_ratio\":{:.4},\"total_runtime_trace_iters\":{},\"total_runtime_deopts\":{},\"total_runtime_temp_list_elided\":{},\"total_runtime_temp_map_elided\":{},\"total_runtime_temp_list_materialized\":{},\"total_runtime_temp_map_materialized\":{},\"total_patch_sites\":{},\"max_patch_sites\":{},\"total_patch_attempts\":{},\"total_patch_commits\":{},\"total_patch_reverts\":{},\"total_adaptive_epochs\":{},\"max_adaptive_stable_epochs\":{},\"max_revert_streak\":{},\"max_deopt\":{},\"max_hot\":{},\"hot_trace_id\":{},\"guard_checks_total\":{},\"guard_fail_total\":{},\"build_fingerprint\":{},\"fusion_hits_by_rule\":{},\"site_profiles\":{},\"deopt_reasons\":{},\"guard_fails_by_guard\":{},\"by_trace\":{}}}",
            format_engine(engine),
            iters,
            warmup_ms,
            warmup_iters,
            preheat_iters,
            dropped_transition_samples,
            sample_attempts,
            median,
            p95,
            cv_pct,
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
            total_internal_side_exits,
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
            "[BENCH] median={} ns/op ({} ops/sec), p95={} ns/op, cv_pct={:.4} over {} runs (warmup {} ms, {} iters) engine={}",
            median,
            median_ops,
            p95,
            cv_pct,
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
                    "[TRACE] count={} super={} ops(min/avg/max)={}/{:.1}/{} code(min/avg/max)={}/{:.1}/{} hot_code(min/avg/max)={}/{:.1}/{} live_max={} bc_max={} hits={} deopt={} (rate {:.2}%) internal_side_exits={} calls(static/runtime)={}/{} branches(static/runtime/taken/not)={}/{}/{}/{} ratio={:.2}% trace_iters={} runtime_deopts={} temps(elided_list/elided_map/materialized_list/materialized_map)={}/{}/{}/{} patch_sites(total/max)={}/{} patcher(attempt/commit/revert/epochs/max_stable/max_revert_streak)={}/{}/{}/{}/{}/{} max_deopt={} max_hot={}",
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
                    summary.total_internal_side_exits,
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

fn coefficient_of_variation_pct(samples: &[u128]) -> f64 {
    if samples.len() < 2 {
        return 0.0;
    }
    let mean = samples.iter().map(|sample| *sample as f64).sum::<f64>() / samples.len() as f64;
    if mean == 0.0 {
        return 0.0;
    }
    let variance = samples
        .iter()
        .map(|sample| {
            let delta = *sample as f64 - mean;
            delta * delta
        })
        .sum::<f64>()
        / samples.len() as f64;
    variance.sqrt() * 100.0 / mean
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

fn format_engine(engine: DefaultEngine) -> &'static str {
    match engine {
        DefaultEngine::Interp => "interp",
        DefaultEngine::Vm => "vm",
        DefaultEngine::Jit => "jit",
    }
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
    items.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    items.truncate(limit);
    items
}

#[cfg(test)]
mod tests {
    use super::coefficient_of_variation_pct;

    #[test]
    fn coefficient_of_variation_reports_stable_and_noisy_samples() {
        assert_eq!(coefficient_of_variation_pct(&[]), 0.0);
        assert_eq!(coefficient_of_variation_pct(&[100]), 0.0);
        assert_eq!(coefficient_of_variation_pct(&[100, 100, 100]), 0.0);

        let noisy = coefficient_of_variation_pct(&[100, 200]);
        assert!((noisy - 33.333_333).abs() < 0.000_1, "{noisy}");
    }
}
