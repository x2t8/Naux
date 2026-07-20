use std::collections::BTreeSet;
use std::path::Path;

use crate::cli::util;
use crate::vm::{compiler, ir, ssa};

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
