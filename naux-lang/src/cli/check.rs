use crate::lexer;
use crate::parser;
use crate::parser::error::format_parse_error;
use crate::refinement;
use crate::region;
use crate::typecheck;
use std::fs;
use std::path::PathBuf;

pub fn handle_check(path: Option<PathBuf>) -> Result<(), String> {
    let file_path = path.ok_or("File path is required for check command.")?;
    println!("Checking file: {:?}", file_path);

    let source = fs::read_to_string(&file_path)
        .map_err(|e| format!("Could not read file {:?}: {}", file_path, e))?;

    println!("Lexing...");
    let tokens = lexer::lex(&source).map_err(|e| format!("Lex error: {}", e.message))?;

    println!("Parsing...");
    let ast = parser::Parser::from_tokens(&tokens)
        .map_err(|err| format_parse_error(&source, &err, &file_path.to_string_lossy()))?;

    println!("Typechecking...");
    typecheck::check_program(&ast).map_err(|e| {
        if let Some(span) = e.span {
            format!("Type error at {}:{}: {}", span.line, span.column, e.message)
        } else {
            format!("Type error: {}", e.message)
        }
    })?;

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
