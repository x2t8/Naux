use std::path::Path;

use crate::cli::util;
use crate::refinement;
use crate::typecheck;
use crate::vm;
use crate::vm::compiler;

pub fn refine_core(path: &Path, strict: bool) -> Result<(), String> {
    let (_, ast) = util::load_ast(path)?;

    typecheck::check_program(&ast).map_err(|e| {
        let loc = e
            .span
            .map(|s| format!(" ({}:{})", s.line, s.column))
            .unwrap_or_default();
        format!("Type error{}: {}", loc, e.message)
    })?;

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
