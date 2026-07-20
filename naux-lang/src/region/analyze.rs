//! Region inference analysis pass.
//!
//! Walks the AST and infers which region each allocation belongs to.
//! Detects **escaping values** — values that outlive their region — and
//! promotes them to a parent region.

use std::collections::HashMap;

use crate::ast::{Expr, ExprKind, Stmt};
use crate::region::types::*;

/// Result from region inference.
#[derive(Debug, Clone, Default)]
pub struct RegionReport {
    /// Total regions created.
    pub regions_created: usize,
    /// Total allocations tracked.
    pub allocations_tracked: usize,
    /// Variables that escaped their initial region (promoted).
    pub promotions: Vec<RegionPromotion>,
    /// Constraints that couldn't be resolved.
    pub violations: Vec<RegionConstraint>,
    /// Detailed region map for diagnostics.
    pub region_map: HashMap<String, RegionSummary>,
}

/// A promotion: value was moved to a longer-lived region.
#[derive(Debug, Clone)]
pub struct RegionPromotion {
    pub var: String,
    pub from_region: RegionId,
    pub to_region: RegionId,
    pub reason: String,
}

/// Summary of a region for diagnostics.
#[derive(Debug, Clone)]
pub struct RegionSummary {
    pub id: RegionId,
    pub kind: RegionKind,
    pub depth: u32,
    pub allocations: Vec<String>,
    pub parent: Option<RegionId>,
}

/// Infer regions for a program.
pub fn infer_regions(stmts: &[Stmt]) -> RegionReport {
    let mut env = RegionEnv::new();
    let mut constraints: Vec<RegionConstraint> = Vec::new();
    let mut promotions: Vec<RegionPromotion> = Vec::new();

    for stmt in stmts {
        analyze_stmt(stmt, &mut env, &mut constraints, &mut promotions);
    }

    // Build region summaries.
    let mut region_map = HashMap::new();
    for (i, region) in env.all_regions().iter().enumerate() {
        let summary = RegionSummary {
            id: region.id,
            kind: region.kind,
            depth: i as u32,
            allocations: region.allocations.clone(),
            parent: region.parent,
        };
        region_map.insert(format!("ρ{}", region.id), summary);
    }

    // Check constraints for violations.
    let mut violations = Vec::new();
    for c in &constraints {
        if !region_outlives(&env, c.source_region, c.required_region) {
            violations.push(c.clone());
        }
    }

    RegionReport {
        regions_created: env.all_regions().len(),
        allocations_tracked: env.all_regions()
            .iter()
            .map(|r| r.allocations.len())
            .sum(),
        promotions,
        violations,
        region_map,
    }
}

/// Check whether region `a` outlives region `b` (i.e., `a` is freed after `b`).
/// In a LIFO stack, a region outlives another if it was pushed first (lower index).
fn region_outlives(env: &RegionEnv, a: RegionId, b: RegionId) -> bool {
    if a == b {
        return true;
    }
    // Global region outlives everything.
    let all = env.all_regions();
    let a_idx = all.iter().position(|r| r.id == a);
    let b_idx = all.iter().position(|r| r.id == b);
    match (a_idx, b_idx) {
        (Some(ai), Some(bi)) => ai <= bi, // Earlier = longer-lived.
        _ => false,
    }
}

// ── AST analysis ────────────────────────────────────────────────────

fn analyze_stmt(
    stmt: &Stmt,
    env: &mut RegionEnv,
    constraints: &mut Vec<RegionConstraint>,
    promotions: &mut Vec<RegionPromotion>,
) {
    match stmt {
        Stmt::Assign { name, expr, .. } => {
            analyze_expr(expr, env, constraints);
            env.allocate(name);

            // Check: if RHS references a variable from a deeper region,
            // the result escapes. For now, track simple cases.
            if let Some(rhs_var) = extract_var_ref(expr) {
                if let (Some(lhs_region), Some(rhs_region)) =
                    (env.lookup_region(name), env.lookup_region(&rhs_var))
                {
                    if !region_outlives(env, rhs_region, lhs_region) {
                        // RHS value may not live long enough!
                        constraints.push(RegionConstraint {
                            var: rhs_var.clone(),
                            source_region: rhs_region,
                            required_region: lhs_region,
                            reason: format!(
                                "${} references ${} from shorter-lived region",
                                name, rhs_var
                            ),
                        });
                    }
                }
            }
        }
        Stmt::FnDef { name: _, params, body, .. } => {
            let _fn_region = env.push_region(RegionKind::Function);
            for p in params {
                env.allocate(&p.name);
            }
            for s in body {
                analyze_stmt(s, env, constraints, promotions);
            }
            env.pop_region();
        }
        Stmt::If { cond, then_block, else_block, .. } => {
            analyze_expr(cond, env, constraints);

            env.push_region(RegionKind::Block);
            for s in then_block {
                analyze_stmt(s, env, constraints, promotions);
            }
            env.pop_region();

            env.push_region(RegionKind::Block);
            for s in else_block {
                analyze_stmt(s, env, constraints, promotions);
            }
            env.pop_region();
        }
        Stmt::Loop { count, body, .. } => {
            analyze_expr(count, env, constraints);
            env.push_region(RegionKind::LoopIter);
            for s in body {
                analyze_stmt(s, env, constraints, promotions);
            }
            env.pop_region();
        }
        Stmt::While { cond: _, body, .. } => {
            env.push_region(RegionKind::LoopIter);
            for s in body {
                analyze_stmt(s, env, constraints, promotions);
            }
            env.pop_region();
        }
        Stmt::Each { var, iter, body, .. } => {
            analyze_expr(iter, env, constraints);
            env.push_region(RegionKind::LoopIter);
            env.allocate(var);
            for s in body {
                analyze_stmt(s, env, constraints, promotions);
            }
            env.pop_region();
        }
        Stmt::Rite { body, .. } => {
            env.push_region(RegionKind::Block);
            for s in body {
                analyze_stmt(s, env, constraints, promotions);
            }
            env.pop_region();
        }
        Stmt::Unsafe { body, .. } => {
            env.push_region(RegionKind::Block);
            for s in body {
                analyze_stmt(s, env, constraints, promotions);
            }
            env.pop_region();
        }
        Stmt::Return { value, .. } => {
            if let Some(expr) = value {
                analyze_expr(expr, env, constraints);
                // Return value escapes function region → promote to caller.
                if let Some(var_name) = extract_var_ref(expr) {
                    if let Some(var_region) = env.lookup_region(&var_name) {
                        let current = env.current_region_id();
                        if var_region == current {
                            // Returning a local — needs promotion.
                            promotions.push(RegionPromotion {
                                var: var_name,
                                from_region: var_region,
                                to_region: 0, // Will be resolved to caller's region.
                                reason: "return escapes function scope".into(),
                            });
                        }
                    }
                }
            }
        }
        Stmt::Expr { expr, .. } => {
            analyze_expr(expr, env, constraints);
        }
        Stmt::Action { .. } | Stmt::Import { .. } => {}
    }
}

fn analyze_expr(
    expr: &Expr,
    env: &mut RegionEnv,
    constraints: &mut Vec<RegionConstraint>,
) {
    match &expr.kind {
        ExprKind::List(items) => {
            for item in items {
                analyze_expr(item, env, constraints);
            }
        }
        ExprKind::Map(entries) => {
            for (_, v) in entries {
                analyze_expr(v, env, constraints);
            }
        }
        ExprKind::Binary { left, right, .. } => {
            analyze_expr(left, env, constraints);
            analyze_expr(right, env, constraints);
        }
        ExprKind::Unary { expr: inner, .. } => {
            analyze_expr(inner, env, constraints);
        }
        ExprKind::Call { callee, args } => {
            analyze_expr(callee, env, constraints);
            for arg in args {
                analyze_expr(arg, env, constraints);
            }
        }
        ExprKind::Index { target, index } => {
            analyze_expr(target, env, constraints);
            analyze_expr(index, env, constraints);
        }
        ExprKind::Field { target, .. } => {
            analyze_expr(target, env, constraints);
        }
        ExprKind::Fn(fn_expr) => {
            // Closure captures — variables referenced from outer scope
            // create region constraints.
            env.push_region(RegionKind::Function);
            for p in &fn_expr.params {
                env.allocate(&p.name);
            }
            for s in &fn_expr.body {
                analyze_stmt(s, env, constraints, &mut Vec::new());
            }
            env.pop_region();
        }
        // Leaf expressions — no allocations.
        ExprKind::Number(_)
        | ExprKind::Bool(_)
        | ExprKind::Text(_)
        | ExprKind::Bytes(_)
        | ExprKind::Var(_) => {}
    }
}

/// Extract a simple variable reference from an expression.
fn extract_var_ref(expr: &Expr) -> Option<String> {
    match &expr.kind {
        ExprKind::Var(name) => Some(name.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::*;

    fn num(n: f64) -> Expr {
        Expr::new(ExprKind::Number(n), None)
    }

    fn var(name: &str) -> Expr {
        Expr::new(ExprKind::Var(name.to_string()), None)
    }

    #[test]
    fn test_simple_assignment() {
        let stmts = vec![
            Stmt::Assign {
                name: "x".into(),
                annotation: None,
                expr: num(42.0),
                span: None,
            },
            Stmt::Assign {
                name: "y".into(),
                annotation: None,
                expr: num(10.0),
                span: None,
            },
        ];
        let report = infer_regions(&stmts);
        assert_eq!(report.regions_created, 1); // Only global.
        assert_eq!(report.allocations_tracked, 2);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn test_function_region() {
        let stmts = vec![Stmt::FnDef {
            name: "foo".into(),
            params: vec!["a".into()],
            body: vec![Stmt::Assign {
                name: "local".into(),
                annotation: None,
                expr: num(1.0),
                span: None,
            }],
            return_type: None,
            span: None,
        }];
        let report = infer_regions(&stmts);
        assert_eq!(report.regions_created, 2); // Global + function.
        assert!(report.violations.is_empty());
    }

    #[test]
    fn test_if_block_regions() {
        let stmts = vec![Stmt::If {
            cond: var("x"),
            then_block: vec![Stmt::Assign {
                name: "a".into(),
                annotation: None,
                expr: num(1.0),
                span: None,
            }],
            else_block: vec![Stmt::Assign {
                name: "b".into(),
                annotation: None,
                expr: num(2.0),
                span: None,
            }],
            span: None,
        }];
        let report = infer_regions(&stmts);
        assert_eq!(report.regions_created, 3); // Global + 2 blocks.
    }

    #[test]
    fn test_loop_region() {
        let stmts = vec![Stmt::Loop {
            count: num(10.0),
            body: vec![Stmt::Assign {
                name: "i".into(),
                annotation: None,
                expr: num(0.0),
                span: None,
            }],
            span: None,
        }];
        let report = infer_regions(&stmts);
        assert_eq!(report.regions_created, 2); // Global + loop-iter.
    }

    #[test]
    fn test_nested_scopes() {
        let stmts = vec![
            Stmt::Assign {
                name: "outer".into(),
                annotation: None,
                expr: num(1.0),
                span: None,
            },
            Stmt::FnDef {
                name: "f".into(),
                params: vec![],
                body: vec![
                    Stmt::Assign {
                        name: "mid".into(),
                        annotation: None,
                        expr: num(2.0),
                        span: None,
                    },
                    Stmt::Loop {
                        count: num(5.0),
                        body: vec![Stmt::Assign {
                            name: "inner".into(),
                            annotation: None,
                            expr: num(3.0),
                            span: None,
                        }],
                        span: None,
                    },
                ],
                return_type: None,
                span: None,
            },
        ];
        let report = infer_regions(&stmts);
        // Global + function + loop-iter = 3.
        assert_eq!(report.regions_created, 3);
    }
}
