use std::path::Path;

use crate::cli::util;
use crate::region;
use crate::typecheck;

pub fn region_core(path: &Path) -> Result<(), String> {
    let (_, ast) = util::load_ast(path)?;

    typecheck::check_program(&ast).map_err(|e| {
        let loc = e
            .span
            .map(|s| format!(" ({}:{})", s.line, s.column))
            .unwrap_or_default();
        format!("Type error{}: {}", loc, e.message)
    })?;

    println!("~ NAUX REGION ANALYSIS ~");
    println!("path: {}", path.display());
    println!();

    let report = region::infer_regions(&ast);

    println!("[REGIONS] {} created", report.regions_created);
    println!("[ALLOCATIONS] {} tracked", report.allocations_tracked);
    println!();

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
        println!("[VIOLATIONS] {} region constraint errors:", report.violations.len());
        for v in &report.violations {
            println!("  ✗ {}", v);
        }
        return Err(format!("{} region violation(s)", report.violations.len()));
    }

    println!("[RESULT] OK — {} regions, {} allocations, {} promotions", report.regions_created, report.allocations_tracked, report.promotions.len());
    Ok(())
}
