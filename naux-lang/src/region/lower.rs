//! Feature-gated lowering metadata for the proven region subset.
//!
//! This module does not allocate or free runtime objects. It turns escape
//! evidence into deterministic storage decisions and region-exit free points
//! that a future allocator can consume without reinterpreting the proof.

use std::collections::HashMap;

use crate::region::analyze::{RegionAllocationKind, RegionReport, RegionSummary};
use crate::region::types::{RegionId, RegionKind};

/// Stable, report-local region identity. Unlike inference IDs, ordinals start
/// at zero for every plan and are reproducible across compiler invocations.
pub type RegionOrdinal = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionFallbackReason {
    GlobalLifetime,
    Escapes,
    Closure,
}

impl RegionFallbackReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GlobalLifetime => "global-lifetime",
            Self::Escapes => "escapes-proven-region",
            Self::Closure => "closure-runtime-unsupported",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionStorageClass {
    /// Candidate for allocation in the identified region and one bulk free at
    /// the corresponding exit point.
    RegionLocal { free_at: RegionOrdinal },
    /// Keep the existing reference-counted runtime representation.
    RcFallback { reason: RegionFallbackReason },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionLoweringAllocation {
    pub var: String,
    pub kind: RegionAllocationKind,
    pub source_region: RegionOrdinal,
    pub escape_target: Option<RegionOrdinal>,
    pub storage: RegionStorageClass,
    pub captures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionFreePoint {
    pub region: RegionOrdinal,
    pub kind: RegionKind,
    pub allocation_indices: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionLoweringPlan {
    pub schema_version: u32,
    pub allocations: Vec<RegionLoweringAllocation>,
    pub free_points: Vec<RegionFreePoint>,
    pub region_local_count: usize,
    pub rc_fallback_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionLoweringError {
    pub message: String,
}

impl std::fmt::Display for RegionLoweringError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for RegionLoweringError {}

/// Lower a completed escape report into deterministic allocation metadata.
///
/// The only admissible `RegionLocal` decision is a non-global, non-closure
/// allocation with no escape target. Every other recognized allocation keeps
/// the current `Rc` representation.
pub fn lower_region_report(report: &RegionReport) -> RegionLoweringPlan {
    let (ordinals, summaries) = normalized_regions(report);
    let mut allocations = Vec::with_capacity(report.heap_allocations.len());
    let mut free_point_allocations: HashMap<RegionOrdinal, Vec<usize>> = HashMap::new();

    for allocation in &report.heap_allocations {
        let source_region = ordinals[&allocation.region];
        let source_kind = summaries[&source_region].kind;
        let escape_target = allocation
            .escape_to
            .and_then(|target| ordinals.get(&target).copied());
        let storage = if allocation.kind == RegionAllocationKind::Closure {
            RegionStorageClass::RcFallback {
                reason: RegionFallbackReason::Closure,
            }
        } else if source_kind == RegionKind::Global {
            RegionStorageClass::RcFallback {
                reason: RegionFallbackReason::GlobalLifetime,
            }
        } else if escape_target.is_some() {
            RegionStorageClass::RcFallback {
                reason: RegionFallbackReason::Escapes,
            }
        } else {
            RegionStorageClass::RegionLocal {
                free_at: source_region,
            }
        };
        let allocation_index = allocations.len();
        if let RegionStorageClass::RegionLocal { free_at } = storage {
            free_point_allocations
                .entry(free_at)
                .or_default()
                .push(allocation_index);
        }
        allocations.push(RegionLoweringAllocation {
            var: allocation.var.clone(),
            kind: allocation.kind,
            source_region,
            escape_target,
            storage,
            captures: allocation
                .captures
                .iter()
                .map(|capture| capture.var.clone())
                .collect(),
        });
    }

    let mut free_points: Vec<_> = free_point_allocations
        .into_iter()
        .map(|(region, allocation_indices)| RegionFreePoint {
            region,
            kind: summaries[&region].kind,
            allocation_indices,
        })
        .collect();
    // Inner regions must be freed before their parents. The depth/ordinal
    // order is deterministic even when two sibling regions share a depth.
    free_points.sort_by_key(|point| {
        (
            std::cmp::Reverse(summaries[&point.region].depth),
            std::cmp::Reverse(point.region),
        )
    });

    let region_local_count = allocations
        .iter()
        .filter(|allocation| matches!(allocation.storage, RegionStorageClass::RegionLocal { .. }))
        .count();
    RegionLoweringPlan {
        schema_version: 1,
        rc_fallback_count: allocations.len() - region_local_count,
        allocations,
        free_points,
        region_local_count,
    }
}

/// Recompute the canonical lowering and reject any metadata drift or
/// post-lowering mutation before a runtime is allowed to consume it.
pub fn verify_region_lowering_plan(
    report: &RegionReport,
    plan: &RegionLoweringPlan,
) -> Result<(), RegionLoweringError> {
    if plan.schema_version != 1 {
        return Err(RegionLoweringError {
            message: format!("unsupported region lowering schema {}", plan.schema_version),
        });
    }
    if plan.region_local_count != report.bulk_free_eligible {
        return Err(RegionLoweringError {
            message: format!(
                "region-local count {} does not match escape proof {}",
                plan.region_local_count, report.bulk_free_eligible
            ),
        });
    }
    let canonical = lower_region_report(report);
    if *plan != canonical {
        return Err(RegionLoweringError {
            message: "region lowering metadata does not match the canonical escape proof"
                .to_string(),
        });
    }
    Ok(())
}

fn normalized_regions(
    report: &RegionReport,
) -> (
    HashMap<RegionId, RegionOrdinal>,
    HashMap<RegionOrdinal, RegionSummary>,
) {
    let mut regions: Vec<_> = report.region_map.values().cloned().collect();
    regions.sort_by_key(|region| region.id);
    let ordinals: HashMap<_, _> = regions
        .iter()
        .enumerate()
        .map(|(ordinal, region)| (region.id, ordinal as RegionOrdinal))
        .collect();
    let summaries = regions
        .into_iter()
        .map(|region| (ordinals[&region.id], region))
        .collect();
    (ordinals, summaries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Expr, ExprKind, FnExpr, Stmt};
    use crate::region::infer_regions;

    fn num(value: f64) -> Expr {
        Expr::new(ExprKind::Number(value), None)
    }

    fn var(name: &str) -> Expr {
        Expr::new(ExprKind::Var(name.to_string()), None)
    }

    fn function(body: Vec<Stmt>) -> Vec<Stmt> {
        vec![Stmt::FnDef {
            name: "work".into(),
            params: vec![],
            body,
            return_type: None,
            span: None,
        }]
    }

    #[test]
    fn local_proven_allocation_gets_one_bulk_free_point() {
        let report = infer_regions(&function(vec![Stmt::Assign {
            name: "scratch".into(),
            annotation: None,
            expr: Expr::new(ExprKind::List(vec![num(1.0)]), None),
            span: None,
        }]));
        let plan = lower_region_report(&report);

        assert_eq!(plan.region_local_count, 1);
        assert_eq!(plan.rc_fallback_count, 0);
        assert_eq!(plan.free_points.len(), 1);
        assert_eq!(plan.free_points[0].allocation_indices, vec![0]);
        assert!(matches!(
            plan.allocations[0].storage,
            RegionStorageClass::RegionLocal { .. }
        ));
    }

    #[test]
    fn escaped_allocation_remains_rc_fallback() {
        let report = infer_regions(&function(vec![
            Stmt::Assign {
                name: "result".into(),
                annotation: None,
                expr: Expr::new(ExprKind::Map(vec![("n".into(), num(1.0))]), None),
                span: None,
            },
            Stmt::Return {
                value: Some(var("result")),
                span: None,
            },
        ]));
        let plan = lower_region_report(&report);

        assert_eq!(plan.region_local_count, 0);
        assert_eq!(plan.rc_fallback_count, 1);
        assert!(matches!(
            plan.allocations[0].storage,
            RegionStorageClass::RcFallback {
                reason: RegionFallbackReason::Escapes
            }
        ));
    }

    #[test]
    fn local_capture_does_not_demote_unescaped_payload() {
        let report = infer_regions(&function(vec![
            Stmt::Assign {
                name: "payload".into(),
                annotation: None,
                expr: Expr::new(ExprKind::Bytes(vec![1, 2, 3]), None),
                span: None,
            },
            Stmt::Assign {
                name: "callback".into(),
                annotation: None,
                expr: Expr::new(
                    ExprKind::Fn(Box::new(FnExpr {
                        params: vec![],
                        body: vec![Stmt::Return {
                            value: Some(var("payload")),
                            span: None,
                        }],
                        span: None,
                    })),
                    None,
                ),
                span: None,
            },
        ]));
        let plan = lower_region_report(&report);
        let payload = plan
            .allocations
            .iter()
            .find(|allocation| allocation.var == "payload")
            .expect("payload lowering");
        let callback = plan
            .allocations
            .iter()
            .find(|allocation| allocation.var == "callback")
            .expect("closure lowering");

        assert!(matches!(
            payload.storage,
            RegionStorageClass::RegionLocal { .. }
        ));
        assert_eq!(callback.captures, vec!["payload"]);
        assert!(matches!(
            callback.storage,
            RegionStorageClass::RcFallback {
                reason: RegionFallbackReason::Closure
            }
        ));
    }

    #[test]
    fn normalized_plan_is_reproducible_across_fresh_inference_ids() {
        let stmts = function(vec![Stmt::Assign {
            name: "scratch".into(),
            annotation: None,
            expr: Expr::new(ExprKind::List(vec![num(1.0)]), None),
            span: None,
        }]);
        let first = lower_region_report(&infer_regions(&stmts));
        let second = lower_region_report(&infer_regions(&stmts));

        assert_eq!(first, second);
    }

    #[test]
    fn verifier_rejects_storage_or_schedule_tampering() {
        let report = infer_regions(&function(vec![Stmt::Assign {
            name: "scratch".into(),
            annotation: None,
            expr: Expr::new(ExprKind::List(vec![num(1.0)]), None),
            span: None,
        }]));
        let plan = lower_region_report(&report);
        verify_region_lowering_plan(&report, &plan).expect("canonical plan");

        let mut storage_tamper = plan.clone();
        storage_tamper.allocations[0].storage = RegionStorageClass::RcFallback {
            reason: RegionFallbackReason::Escapes,
        };
        assert!(verify_region_lowering_plan(&report, &storage_tamper).is_err());

        let mut schedule_tamper = plan;
        schedule_tamper.free_points[0].allocation_indices.push(0);
        assert!(verify_region_lowering_plan(&report, &schedule_tamper).is_err());
    }
}
