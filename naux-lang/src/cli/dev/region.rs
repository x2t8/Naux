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
    println!(
        "[HEAP PLAN] {} recognized, {} bulk-free eligible",
        report.heap_allocations.len(),
        report.bulk_free_eligible
    );
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

    if !report.heap_allocations.is_empty() {
        println!("[ESCAPE PLAN]");
        for allocation in &report.heap_allocations {
            let decision = allocation.escape_to.map_or_else(
                || "local".to_string(),
                |target| format!("escape → ρ{target}"),
            );
            let captures = if allocation.captures.is_empty() {
                String::new()
            } else {
                format!(
                    ", captures [{}]",
                    allocation
                        .captures
                        .iter()
                        .map(|capture| format!("${}@ρ{}", capture.var, capture.source_region))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            println!(
                "  ${}: {} in ρ{} ({}{captures})",
                allocation.var,
                allocation.kind.as_str(),
                allocation.region,
                decision
            );
        }
        println!();
    }

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

    #[cfg(feature = "experimental-regions")]
    {
        use crate::region::RegionStorageClass;

        let lowering = region::lower_region_report(&report);
        region::verify_region_lowering_plan(&report, &lowering)
            .map_err(|error| format!("Region lowering verification failed: {error}"))?;
        println!(
            "[LOWERING PLAN] schema {}, {} region-local, {} Rc fallback",
            lowering.schema_version, lowering.region_local_count, lowering.rc_fallback_count
        );
        for allocation in &lowering.allocations {
            let decision = match allocation.storage {
                RegionStorageClass::RegionLocal { free_at } => {
                    format!("region-local, free at R{free_at}")
                }
                RegionStorageClass::RcFallback { reason } => {
                    format!("Rc fallback ({})", reason.as_str())
                }
            };
            println!(
                "  ${}: {} from R{} -> {}",
                allocation.var,
                allocation.kind.as_str(),
                allocation.source_region,
                decision
            );
        }
        if !lowering.free_points.is_empty() {
            println!("[BULK FREE SCHEDULE]");
            for point in &lowering.free_points {
                println!(
                    "  exit R{} [{}]: allocations {:?}",
                    point.region,
                    point.kind.as_str(),
                    point.allocation_indices
                );
            }
        }
        println!("[LOWERING CERTIFICATE] OK");
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
        "[RESULT] OK — {} regions, {} allocations, {} promotions, {} bulk-free eligible",
        report.regions_created,
        report.allocations_tracked,
        report.promotions.len(),
        report.bulk_free_eligible
    );
    Ok(())
}
