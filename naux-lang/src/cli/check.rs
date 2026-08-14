use crate::cli::util;
use crate::diagnostic::{format_source_diagnostic, DiagnosticStage};
use crate::refinement;
use crate::region;
use crate::typecheck;
use std::path::PathBuf;

pub fn handle_check(path: Option<PathBuf>) -> Result<(), String> {
    let file_path = path.ok_or("File path is required for check command.")?;
    let (source, ast) = util::load_ast(&file_path)?;
    typecheck::check_program(&ast).map_err(|error| {
        format_source_diagnostic(
            DiagnosticStage::Type,
            &error.message,
            &source,
            &file_path.to_string_lossy(),
            error.span.as_ref(),
        )
    })?;

    println!("Checking file: {:?}", file_path);
    println!("Refinement checking...");
    match refinement::check_refinements(&ast) {
        Ok(report) => {
            println!(
                "  constraints: {} generated, {} discharged, {} unresolved",
                report.constraints_generated,
                report.constraints_discharged,
                report.constraints_failed,
            );
            if !report.proof_slots.is_empty() {
                println!(
                    "  proof evidence generated for {} variables:",
                    report.proof_slots.len()
                );
                for (name, slot) in &report.proof_slots {
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
                        println!("    ${}: {}", name, facts.join(", "));
                    }
                }
            }
            for warning in &report.warnings {
                println!("  ⚠ {}", warning);
            }
        }
        Err(errors) => {
            for error in &errors {
                if let Some(ref span) = error.span {
                    eprintln!(
                        "  ✗ refinement error at {}:{}: {}",
                        span.line, span.column, error.message
                    );
                } else {
                    eprintln!("  ✗ {}", error);
                }
            }
            return Err(format!("{} refinement error(s) found", errors.len()));
        }
    }

    println!("Region inference...");
    let region_report = region::infer_regions(&ast);
    println!(
        "  {} regions, {} allocations, {} promotions",
        region_report.regions_created,
        region_report.allocations_tracked,
        region_report.promotions.len(),
    );
    if !region_report.violations.is_empty() {
        for v in &region_report.violations {
            eprintln!("  ✗ {}", v);
        }
        return Err(format!(
            "{} region violation(s) found",
            region_report.violations.len()
        ));
    }

    println!("Check OK.");
    Ok(())
}
