//! Integration tests: full pipeline (refinement + region + effects).
//!
//! These tests exercise the 3 analysis passes together on realistic AST inputs.

#[cfg(test)]
mod tests {
    use crate::ast::*;
    use crate::effects;
    use crate::refinement;
    use crate::region;

    // ── Helpers ─────────────────────────────────────────────────────────

    fn num(n: f64) -> Expr {
        Expr::new(ExprKind::Number(n), None)
    }

    fn var(name: &str) -> Expr {
        Expr::new(ExprKind::Var(name.to_string()), None)
    }

    fn text(s: &str) -> Expr {
        Expr::new(ExprKind::Text(s.to_string()), None)
    }

    fn assign(name: &str, expr: Expr) -> Stmt {
        Stmt::Assign {
            name: name.into(),
            annotation: None,
            expr,
            span: None,
        }
    }

    fn say(expr: Expr) -> Stmt {
        Stmt::Action {
            action: ActionKind::Say { value: expr },
            span: None,
        }
    }

    fn binop(op: BinaryOp, left: Expr, right: Expr) -> Expr {
        Expr::new(
            ExprKind::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            },
            None,
        )
    }

    // ── Refinement stability ────────────────────────────────────────────

    #[test]
    fn refinement_empty_program() {
        let stmts: Vec<Stmt> = vec![];
        let mut env = refinement::RefinementEnv::new();
        let mut cset = refinement::ConstraintSet::new();
        for s in &stmts {
            let _ = refinement::generate_stmt_constraints_pub(s, &mut env, &mut cset);
        }
        assert_eq!(cset.len(), 0);
    }

    #[test]
    fn refinement_simple_assign_no_constraints() {
        let stmts = vec![assign("x", num(42.0))];
        let mut env = refinement::RefinementEnv::new();
        let mut cset = refinement::ConstraintSet::new();
        for s in &stmts {
            let _ = refinement::generate_stmt_constraints_pub(s, &mut env, &mut cset);
        }
        // Simple assign generates no subtype constraints.
        assert_eq!(cset.len(), 0);
    }

    #[test]
    fn refinement_division_generates_constraint() {
        let stmts = vec![assign("r", binop(BinaryOp::Div, num(100.0), num(5.0)))];
        let mut env = refinement::RefinementEnv::new();
        let mut cset = refinement::ConstraintSet::new();
        for s in &stmts {
            let _ = refinement::generate_stmt_constraints_pub(s, &mut env, &mut cset);
        }
        // Division should generate a nonzero constraint for divisor.
        assert!(!cset.is_empty(), "division should produce constraint");
    }

    #[test]
    fn refinement_division_by_literal_nonzero_discharged() {
        let stmts = vec![assign("r", binop(BinaryOp::Div, num(100.0), num(5.0)))];
        let mut env = refinement::RefinementEnv::new();
        let mut cset = refinement::ConstraintSet::new();
        for s in &stmts {
            let _ = refinement::generate_stmt_constraints_pub(s, &mut env, &mut cset);
        }
        let solver = refinement::Solver::new(refinement::SolverConfig::default());
        let result = solver.solve(&cset);
        assert_eq!(result.failed, 0, "div by 5 should be proven safe");
    }

    #[test]
    fn refinement_nested_if_no_panic() {
        let stmts = vec![Stmt::If {
            cond: var("x"),
            then_block: vec![
                assign("a", num(1.0)),
                Stmt::If {
                    cond: var("a"),
                    then_block: vec![assign("b", num(2.0))],
                    else_block: vec![assign("b", num(3.0))],
                    span: None,
                },
            ],
            else_block: vec![assign("c", num(4.0))],
            span: None,
        }];
        let mut env = refinement::RefinementEnv::new();
        let mut cset = refinement::ConstraintSet::new();
        for s in &stmts {
            let _ = refinement::generate_stmt_constraints_pub(s, &mut env, &mut cset);
        }
        // Should not panic on nested control flow.
    }

    // ── Region stability ────────────────────────────────────────────────

    #[test]
    fn region_empty_program() {
        let report = region::infer_regions(&[]);
        assert_eq!(report.regions_created, 1); // Global always exists.
        assert_eq!(report.allocations_tracked, 0);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn region_deeply_nested() {
        let stmts = vec![Stmt::FnDef {
            name: "outer".into(),
            params: vec![],
            body: vec![
                assign("a", num(1.0)),
                Stmt::Loop {
                    count: num(10.0),
                    body: vec![
                        assign("b", num(2.0)),
                        Stmt::If {
                            cond: var("b"),
                            then_block: vec![assign("c", num(3.0))],
                            else_block: vec![assign("d", num(4.0))],
                            span: None,
                        },
                    ],
                    span: None,
                },
            ],
            return_type: None,
            span: None,
        }];
        let report = region::infer_regions(&stmts);
        // Global + function + loop-iter + 2 blocks = 5.
        assert_eq!(report.regions_created, 5);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn region_many_variables() {
        let mut stmts = Vec::new();
        for i in 0..50 {
            stmts.push(assign(&format!("v{}", i), num(i as f64)));
        }
        let report = region::infer_regions(&stmts);
        assert_eq!(report.allocations_tracked, 50);
        assert!(report.violations.is_empty());
    }

    // ── Effects stability ───────────────────────────────────────────────

    #[test]
    fn effects_empty_program() {
        let result = effects::handle_effects(&[]);
        assert!(result.signature.is_pure());
        assert!(result.unhandled.is_empty());
    }

    #[test]
    fn effects_pure_computation() {
        let stmts = vec![
            assign("x", num(1.0)),
            assign("y", num(2.0)),
            assign("z", binop(BinaryOp::Add, var("x"), var("y"))),
        ];
        let result = effects::handle_effects(&stmts);
        assert!(result.signature.is_pure());
    }

    #[test]
    fn effects_multiple_io() {
        let stmts = vec![
            say(text("line 1")),
            say(text("line 2")),
            say(text("line 3")),
        ];
        let result = effects::handle_effects(&stmts);
        assert_eq!(result.unhandled.len(), 3);
        assert!(result.signature.effects.contains(&"IO".to_string()));
    }

    #[test]
    fn effects_in_nested_scopes() {
        let stmts = vec![Stmt::FnDef {
            name: "f".into(),
            params: vec![],
            body: vec![Stmt::Loop {
                count: num(5.0),
                body: vec![say(text("tick"))],
                span: None,
            }],
            return_type: None,
            span: None,
        }];
        let result = effects::handle_effects(&stmts);
        assert_eq!(result.unhandled.len(), 1);
        assert!(result.signature.effects.contains(&"IO".to_string()));
    }

    // ── Full pipeline ───────────────────────────────────────────────────

    #[test]
    fn full_pipeline_simple_program() {
        let stmts = vec![
            assign("x", num(10.0)),
            assign("y", binop(BinaryOp::Div, num(100.0), num(10.0))),
            say(text("result")),
        ];

        // Refinement.
        let mut env = refinement::RefinementEnv::new();
        let mut cset = refinement::ConstraintSet::new();
        for s in &stmts {
            let _ = refinement::generate_stmt_constraints_pub(s, &mut env, &mut cset);
        }
        let solver = refinement::Solver::new(refinement::SolverConfig::default());
        let refine_result = solver.solve(&cset);
        assert_eq!(refine_result.failed, 0);

        // Region.
        let region_report = region::infer_regions(&stmts);
        assert!(region_report.violations.is_empty());

        // Effects.
        let fx_result = effects::handle_effects(&stmts);
        assert!(fx_result.signature.effects.contains(&"IO".to_string()));
        assert_eq!(fx_result.unhandled.len(), 1); // 1 say.
    }

    #[test]
    fn full_pipeline_complex_program() {
        let stmts = vec![
            assign("base", num(10.0)),
            assign("limit", num(100.0)),
            assign("ratio", binop(BinaryOp::Div, var("limit"), var("base"))),
            Stmt::If {
                cond: var("base"),
                then_block: vec![
                    assign("safe", binop(BinaryOp::Div, var("limit"), var("base"))),
                    say(text("safe division")),
                ],
                else_block: vec![say(text("base is zero"))],
                span: None,
            },
            Stmt::FnDef {
                name: "compute".into(),
                params: vec!["n".into()],
                body: vec![
                    assign("result", binop(BinaryOp::Mul, var("n"), num(2.0))),
                    Stmt::Return {
                        value: Some(var("result")),
                        span: None,
                    },
                ],
                return_type: None,
                span: None,
            },
            Stmt::Loop {
                count: num(5.0),
                body: vec![
                    assign("tmp", binop(BinaryOp::Add, var("base"), num(1.0))),
                    say(var("tmp")),
                ],
                span: None,
            },
        ];

        // All 3 passes should complete without panic.
        let mut env = refinement::RefinementEnv::new();
        let mut cset = refinement::ConstraintSet::new();
        for s in &stmts {
            let _ = refinement::generate_stmt_constraints_pub(s, &mut env, &mut cset);
        }
        let solver = refinement::Solver::new(refinement::SolverConfig::default());
        let _refine = solver.solve(&cset);

        let region_report = region::infer_regions(&stmts);
        // Global + if-then + if-else + function + loop = 5.
        assert_eq!(region_report.regions_created, 5);
        assert!(region_report.violations.is_empty());

        let fx = effects::handle_effects(&stmts);
        assert_eq!(fx.unhandled.len(), 3); // 3 say actions.
    }
}
