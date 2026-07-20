use std::path::Path;

use crate::cli::util;
use crate::refinement;
use crate::typecheck;

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
        println!("[ERRORS] {} constraint generation errors:", gen_errors.len());
        for e in &gen_errors {
            if let Some(ref span) = e.span {
                println!("  ✗ {}:{}: {}", span.line, span.column, e.message);
            } else {
                println!("  ✗ {}", e.message);
            }
        }
        return Err(format!("{} refinement generation error(s)", gen_errors.len()));
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
        println!("[PROOF EVIDENCE] → ProofSlot bridge ({} vars)", result.proof_slots.len());
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
                println!("  ${}: {} (evidence_score={})", name, facts.join(", "), score);
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

    println!("[RESULT] OK — {} constraints discharged, {} proof slots generated", result.discharged, result.proof_slots.len());
    Ok(())
}
