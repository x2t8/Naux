//! # Refinement Type System for Naux
//!
//! Refinement analysis experiments for numeric and collection safety.
//!
//! Instead of simple `Num`, variables carry **predicates** that the compiler
//! proves at compile time. This eliminates runtime checks for:
//! - Array bounds
//! - Division by zero
//! - Integer overflow
//! - Null dereference
//!
//! The solver uses a Horn-clause–style constraint system with abstract
//! interpretation, feeding results back into [`ProofSlot`] for use by
//! the e-graph optimizer and JIT.

pub mod constraint;
pub mod predicate;
pub mod solver;

pub use constraint::{Constraint, ConstraintSet};
pub use predicate::{Predicate, RefinementVar};
pub use solver::{Solution, Solver, SolverConfig, SolverResult};

use std::collections::HashMap;

use crate::ast::{BinaryOp, Expr, ExprKind, Span, Stmt, UnaryOp};
use crate::typecheck::Type;
use crate::vm::ir::{NumericProof, ProofSlot};

/// A refined type: base type + logical predicate that constrains the value.
///
/// Example: `{ v: Num | v > 0 && v < 100 }` is
/// `Refined { base: Num, pred: And(Gt(Var("v"), Lit(0)), Lt(Var("v"), Lit(100))) }`
#[derive(Debug, Clone, PartialEq)]
pub struct Refined {
    pub base: Type,
    pub pred: Predicate,
    pub span: Option<Span>,
}

impl Refined {
    pub fn trivial(base: Type) -> Self {
        Self {
            base,
            pred: Predicate::True,
            span: None,
        }
    }

    pub fn num_positive() -> Self {
        Self {
            base: Type::Num,
            pred: Predicate::Gt(
                Box::new(Predicate::Var(RefinementVar::Value)),
                Box::new(Predicate::Lit(0)),
            ),
            span: None,
        }
    }

    pub fn num_nonzero() -> Self {
        Self {
            base: Type::Num,
            pred: Predicate::Ne(
                Box::new(Predicate::Var(RefinementVar::Value)),
                Box::new(Predicate::Lit(0)),
            ),
            span: None,
        }
    }

    pub fn num_in_range(lo: i64, hi: i64) -> Self {
        Self {
            base: Type::Num,
            pred: Predicate::And(
                Box::new(Predicate::Ge(
                    Box::new(Predicate::Var(RefinementVar::Value)),
                    Box::new(Predicate::Lit(lo)),
                )),
                Box::new(Predicate::Le(
                    Box::new(Predicate::Var(RefinementVar::Value)),
                    Box::new(Predicate::Lit(hi)),
                )),
            ),
            span: None,
        }
    }

    /// Does this refinement logically imply another?
    /// Conservative: returns true only when provably implied.
    pub fn implies(&self, other: &Refined) -> bool {
        if self.base != other.base && other.base != Type::Any {
            return false;
        }
        if other.pred == Predicate::True {
            return true;
        }
        if self.pred == other.pred {
            return true;
        }
        // Delegate to solver for deeper checks.
        false
    }

    /// Convert this refinement into a `ProofSlot` for the IR/e-graph pipeline.
    pub fn to_proof_slot(&self) -> ProofSlot {
        let mut slot = ProofSlot::default();

        if self.base == Type::Num {
            let mut proof = NumericProof::default();
            self.pred.extract_numeric_facts(&mut proof);
            if proof != NumericProof::default() {
                slot.numeric = Some(proof);
            }
        }

        slot
    }
}

/// Environment mapping variable names to their refined types.
#[derive(Debug, Clone, Default)]
pub struct RefinementEnv {
    scopes: Vec<HashMap<String, Refined>>,
    /// Accumulated constraints from control flow (if-then paths, loop bounds).
    pub path_constraints: Vec<Predicate>,
}

impl RefinementEnv {
    pub fn new() -> Self {
        Self {
            scopes: vec![HashMap::new()],
            path_constraints: Vec::new(),
        }
    }

    pub fn push_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }

    pub fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    pub fn bind(&mut self, name: &str, refined: Refined) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name.to_string(), refined);
        }
    }

    pub fn lookup(&self, name: &str) -> Option<&Refined> {
        for scope in self.scopes.iter().rev() {
            if let Some(r) = scope.get(name) {
                return Some(r);
            }
        }
        None
    }

    /// Push a path constraint (e.g., inside an `if` branch we know the condition is true).
    pub fn push_path_constraint(&mut self, pred: Predicate) {
        self.path_constraints.push(pred);
    }

    pub fn pop_path_constraint(&mut self) {
        self.path_constraints.pop();
    }
}

/// Top-level refinement checking for a program.
pub fn check_refinements(stmts: &[Stmt]) -> Result<RefinementReport, Vec<RefinementError>> {
    let mut env = RefinementEnv::new();
    let mut cset = ConstraintSet::new();
    let mut errors = Vec::new();

    for stmt in stmts {
        if let Err(e) = generate_stmt_constraints(stmt, &mut env, &mut cset) {
            errors.push(e);
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    // Solve collected constraints.
    let solver = Solver::new(SolverConfig::default());
    let result = solver.solve(&cset);

    Ok(RefinementReport {
        constraints_generated: cset.len(),
        constraints_discharged: result.discharged,
        constraints_failed: result.failed,
        proof_slots: result.proof_slots,
        warnings: result.warnings,
    })
}

/// Report from refinement checking.
#[derive(Debug, Clone, Default)]
pub struct RefinementReport {
    pub constraints_generated: usize,
    pub constraints_discharged: usize,
    pub constraints_failed: usize,
    pub proof_slots: HashMap<String, ProofSlot>,
    pub warnings: Vec<String>,
}

/// Error from refinement checking.
#[derive(Debug, Clone)]
pub struct RefinementError {
    pub message: String,
    pub span: Option<Span>,
}

impl std::fmt::Display for RefinementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "refinement error: {}", self.message)
    }
}

// Constraint generation from AST.

/// Public entry point for constraint generation (used by `dev refine`).
pub fn generate_stmt_constraints_pub(
    stmt: &Stmt,
    env: &mut RefinementEnv,
    cset: &mut ConstraintSet,
) -> Result<(), RefinementError> {
    generate_stmt_constraints(stmt, env, cset)
}

fn generate_stmt_constraints(
    stmt: &Stmt,
    env: &mut RefinementEnv,
    cset: &mut ConstraintSet,
) -> Result<(), RefinementError> {
    match stmt {
        Stmt::Assign { name, expr, .. } => {
            let mut refined = synthesize_expr(expr, env, cset)?;
            attach_assignment_facts(name, expr, &mut refined);
            env.bind(name, refined);
            Ok(())
        }
        Stmt::Rite { body, span: _ } => {
            env.push_scope();
            for s in body {
                generate_stmt_constraints(s, env, cset)?;
            }
            env.pop_scope();
            Ok(())
        }
        Stmt::If {
            cond,
            then_block,
            else_block,
            span: _,
        } => {
            let _cond_refined = synthesize_expr(cond, env, cset)?;
            // Extract predicate from condition for path-sensitive refinement.
            let cond_pred = expr_to_predicate(cond);

            // Then branch: condition is true.
            env.push_scope();
            if let Some(pred) = &cond_pred {
                env.push_path_constraint(pred.clone());
                refine_env_from_condition(cond, env, true);
            }
            for s in then_block {
                generate_stmt_constraints(s, env, cset)?;
            }
            if cond_pred.is_some() {
                env.pop_path_constraint();
            }
            env.pop_scope();

            // Else branch: condition is false.
            env.push_scope();
            if let Some(pred) = &cond_pred {
                env.push_path_constraint(Predicate::Not(Box::new(pred.clone())));
                refine_env_from_condition(cond, env, false);
            }
            for s in else_block {
                generate_stmt_constraints(s, env, cset)?;
            }
            if cond_pred.is_some() {
                env.pop_path_constraint();
            }
            env.pop_scope();

            Ok(())
        }
        Stmt::FnDef { params, body, .. } => {
            env.push_scope();
            for p in params {
                env.bind(&p.name, Refined::trivial(Type::Any));
            }
            for s in body {
                generate_stmt_constraints(s, env, cset)?;
            }
            env.pop_scope();
            Ok(())
        }
        Stmt::Loop {
            count, body, span, ..
        } => {
            let count_refined = synthesize_expr(count, env, cset)?;
            // Loop count must be non-negative.
            cset.add(Constraint::Subtype {
                sub: count_refined,
                sup: Refined {
                    base: Type::Num,
                    pred: Predicate::Ge(
                        Box::new(Predicate::Var(RefinementVar::Value)),
                        Box::new(Predicate::Lit(0)),
                    ),
                    span: span.clone(),
                },
                context: "loop count must be non-negative".into(),
            });
            env.push_scope();
            for s in body {
                generate_stmt_constraints(s, env, cset)?;
            }
            env.pop_scope();
            Ok(())
        }
        Stmt::Expr { expr, .. } => {
            let _ = synthesize_expr(expr, env, cset)?;
            Ok(())
        }
        Stmt::Action { .. } => Ok(()),
        Stmt::Return { value, .. } => {
            if let Some(expr) = value {
                let _ = synthesize_expr(expr, env, cset)?;
            }
            Ok(())
        }
        Stmt::Each {
            var, iter, body, ..
        } => {
            let iter_refined = synthesize_expr(iter, env, cset)?;
            env.push_scope();
            // Iteration variable is element type.
            let elem_ty = match &iter_refined.base {
                Type::List(inner) => (**inner).clone(),
                _ => Type::Any,
            };
            env.bind(var, Refined::trivial(elem_ty));
            for s in body {
                generate_stmt_constraints(s, env, cset)?;
            }
            env.pop_scope();
            Ok(())
        }
        Stmt::While { cond: _, body, .. } => {
            env.push_scope();
            for s in body {
                generate_stmt_constraints(s, env, cset)?;
            }
            env.pop_scope();
            Ok(())
        }
        Stmt::Unsafe { body, .. } => {
            env.push_scope();
            for s in body {
                generate_stmt_constraints(s, env, cset)?;
            }
            env.pop_scope();
            Ok(())
        }
        Stmt::Import { .. } => Ok(()),
    }
}

/// Synthesize a refined type for an expression.
fn synthesize_expr(
    expr: &Expr,
    env: &mut RefinementEnv,
    cset: &mut ConstraintSet,
) -> Result<Refined, RefinementError> {
    match &expr.kind {
        ExprKind::Number(n) => {
            let exact = if n.fract().abs() < f64::EPSILON {
                *n as i64
            } else {
                return Ok(Refined::trivial(Type::Num));
            };
            Ok(Refined {
                base: Type::Num,
                pred: Predicate::Eq(
                    Box::new(Predicate::Var(RefinementVar::Value)),
                    Box::new(Predicate::Lit(exact)),
                ),
                span: expr.span.clone(),
            })
        }
        ExprKind::Bool(_) => Ok(Refined::trivial(Type::Bool)),
        ExprKind::Text(_) => Ok(Refined::trivial(Type::Text)),
        ExprKind::Bytes(_) => Ok(Refined::trivial(Type::Bytes)),
        ExprKind::List(items) => {
            for item in items {
                let _ = synthesize_expr(item, env, cset)?;
            }
            Ok(Refined::trivial(Type::List(Box::new(Type::Any))))
        }
        ExprKind::Map(entries) => {
            for (_, v) in entries {
                let _ = synthesize_expr(v, env, cset)?;
            }
            Ok(Refined::trivial(Type::Map(Box::new(Type::Any))))
        }
        ExprKind::Var(name) => {
            if let Some(r) = env.lookup(name) {
                // Substitute Value → Named(name) so the solver can extract
                // the variable name when generating proof slots.
                let named_pred = r.pred.substitute_value_with_named(name);
                Ok(Refined {
                    base: r.base.clone(),
                    pred: named_pred,
                    span: r.span.clone(),
                })
            } else {
                Ok(Refined::trivial(Type::Any))
            }
        }
        ExprKind::Binary { op, left, right } => {
            let l = synthesize_expr(left, env, cset)?;
            let r = synthesize_expr(right, env, cset)?;
            synthesize_binary(op.clone(), &l, &r, expr.span.clone(), cset)
        }
        ExprKind::Unary { op, expr: inner } => {
            let _inner_r = synthesize_expr(inner, env, cset)?;
            match op {
                UnaryOp::Neg => Ok(Refined::trivial(Type::Num)),
                UnaryOp::Not => Ok(Refined::trivial(Type::Bool)),
            }
        }
        ExprKind::Call { callee, args } => {
            if let ExprKind::Var(name) = &callee.kind {
                match name.as_str() {
                    "__index" if args.len() == 2 => {
                        let target_r = synthesize_expr(&args[0], env, cset)?;
                        let index_r = synthesize_expr(&args[1], env, cset)?;
                        add_index_bound_constraints(&args[0], &target_r, index_r, cset);
                        return Ok(index_result_refinement(&target_r));
                    }
                    "__setindex" if args.len() == 3 => {
                        let target_r = synthesize_expr(&args[0], env, cset)?;
                        let index_r = synthesize_expr(&args[1], env, cset)?;
                        let _value_r = synthesize_expr(&args[2], env, cset)?;
                        add_index_bound_constraints(&args[0], &target_r, index_r, cset);
                        return Ok(target_r);
                    }
                    _ => {}
                }
            }
            for arg in args {
                let _ = synthesize_expr(arg, env, cset)?;
            }
            Ok(Refined::trivial(Type::Any))
        }
        ExprKind::Index { target, index } => {
            let target_r = synthesize_expr(target, env, cset)?;
            let index_r = synthesize_expr(index, env, cset)?;
            add_index_bound_constraints(target, &target_r, index_r, cset);

            let elem_ty = match &target_r.base {
                Type::List(inner) => (**inner).clone(),
                _ => Type::Any,
            };
            Ok(Refined::trivial(elem_ty))
        }
        ExprKind::Field { target, field: _ } => {
            let _ = synthesize_expr(target, env, cset)?;
            Ok(Refined::trivial(Type::Any))
        }
        ExprKind::Fn(_) => Ok(Refined::trivial(Type::Any)),
    }
}

fn add_index_bound_constraints(
    target: &Expr,
    target_r: &Refined,
    index_r: Refined,
    cset: &mut ConstraintSet,
) {
    if !should_check_numeric_index_bounds(&target_r.base, &index_r.base) {
        return;
    }

    cset.add(Constraint::Subtype {
        sub: index_r.clone(),
        sup: Refined {
            base: Type::Num,
            pred: Predicate::Ge(
                Box::new(Predicate::Var(RefinementVar::Value)),
                Box::new(Predicate::Lit(0)),
            ),
            span: None,
        },
        context: "array index must be non-negative".into(),
    });

    if let Some(len) = collection_len_exact(target, target_r) {
        cset.add(Constraint::Subtype {
            sub: index_r,
            sup: Refined {
                base: Type::Num,
                pred: Predicate::Lt(
                    Box::new(Predicate::Var(RefinementVar::Value)),
                    Box::new(Predicate::Lit(len)),
                ),
                span: None,
            },
            context: "array index must be less than collection length".into(),
        });
    }
}

fn index_result_refinement(target: &Refined) -> Refined {
    let elem_ty = match &target.base {
        Type::List(inner) => (**inner).clone(),
        Type::Bytes => Type::Num,
        Type::Map(inner) => (**inner).clone(),
        _ => Type::Any,
    };
    Refined::trivial(elem_ty)
}

fn attach_assignment_facts(name: &str, expr: &Expr, refined: &mut Refined) {
    let len = match &expr.kind {
        ExprKind::List(items) => Some(items.len() as i64),
        ExprKind::Bytes(bytes) => Some(bytes.len() as i64),
        _ => None,
    };

    if let Some(len) = len {
        refined.pred = and_predicates(
            refined.pred.clone(),
            Predicate::Eq(
                Box::new(Predicate::Var(RefinementVar::LenOf(name.to_string()))),
                Box::new(Predicate::Lit(len)),
            ),
        );
    }
}

fn and_predicates(lhs: Predicate, rhs: Predicate) -> Predicate {
    match (lhs, rhs) {
        (Predicate::True, p) | (p, Predicate::True) => p,
        (a, b) => Predicate::And(Box::new(a), Box::new(b)),
    }
}

fn should_check_numeric_index_bounds(target_base: &Type, index_base: &Type) -> bool {
    matches!(target_base, Type::List(_) | Type::Bytes | Type::Any)
        && matches!(index_base, Type::Num | Type::Any)
}

fn collection_len_exact(target: &Expr, refined: &Refined) -> Option<i64> {
    match &target.kind {
        ExprKind::List(items) => Some(items.len() as i64),
        ExprKind::Bytes(bytes) => Some(bytes.len() as i64),
        ExprKind::Var(name) => predicate_len_exact(&refined.pred, name),
        _ => None,
    }
}

fn predicate_len_exact(pred: &Predicate, name: &str) -> Option<i64> {
    match pred {
        Predicate::Eq(lhs, rhs) => match (lhs.as_ref(), rhs.as_ref()) {
            (Predicate::Var(RefinementVar::LenOf(n)), value)
            | (value, Predicate::Var(RefinementVar::LenOf(n)))
                if n == name =>
            {
                value.eval_i64()
            }
            _ => None,
        },
        Predicate::And(a, b) => {
            predicate_len_exact(a, name).or_else(|| predicate_len_exact(b, name))
        }
        _ => None,
    }
}

/// Synthesize a refined type for a binary operation.
fn synthesize_binary(
    op: BinaryOp,
    lhs: &Refined,
    rhs: &Refined,
    span: Option<Span>,
    cset: &mut ConstraintSet,
) -> Result<Refined, RefinementError> {
    match op {
        BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Mod => {
            // Propagate range info for simple cases.
            let pred = match op {
                BinaryOp::Add => propagate_add(&lhs.pred, &rhs.pred),
                BinaryOp::Mul => propagate_mul(&lhs.pred, &rhs.pred),
                _ => None,
            };
            Ok(Refined {
                base: Type::Num,
                pred: pred.unwrap_or(Predicate::True),
                span,
            })
        }
        BinaryOp::Div => {
            // CRITICAL: divisor must be non-zero. This is the key refinement check.
            cset.add(Constraint::Subtype {
                sub: rhs.clone(),
                sup: Refined::num_nonzero(),
                context: "divisor must be non-zero".into(),
            });
            Ok(Refined::trivial(Type::Num))
        }
        BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Gt | BinaryOp::Ge | BinaryOp::Lt | BinaryOp::Le => {
            Ok(Refined::trivial(Type::Bool))
        }
        BinaryOp::And | BinaryOp::Or => Ok(Refined::trivial(Type::Bool)),
        BinaryOp::Xor | BinaryOp::Shl => Ok(Refined::trivial(Type::Num)),
    }
}

/// Propagate addition: if both sides have known ranges, compute the result range.
fn propagate_add(lhs: &Predicate, rhs: &Predicate) -> Option<Predicate> {
    let (l_lo, l_hi) = lhs.extract_range()?;
    let (r_lo, r_hi) = rhs.extract_range()?;
    let lo = l_lo.checked_add(r_lo)?;
    let hi = l_hi.checked_add(r_hi)?;
    Some(Predicate::And(
        Box::new(Predicate::Ge(
            Box::new(Predicate::Var(RefinementVar::Value)),
            Box::new(Predicate::Lit(lo)),
        )),
        Box::new(Predicate::Le(
            Box::new(Predicate::Var(RefinementVar::Value)),
            Box::new(Predicate::Lit(hi)),
        )),
    ))
}

/// Propagate multiplication: if both sides have known non-negative ranges.
fn propagate_mul(lhs: &Predicate, rhs: &Predicate) -> Option<Predicate> {
    let (l_lo, l_hi) = lhs.extract_range()?;
    let (r_lo, r_hi) = rhs.extract_range()?;
    if l_lo < 0 || r_lo < 0 {
        return None; // Conservative: don't handle negative ranges yet.
    }
    let lo = l_lo.checked_mul(r_lo)?;
    let hi = l_hi.checked_mul(r_hi)?;
    Some(Predicate::And(
        Box::new(Predicate::Ge(
            Box::new(Predicate::Var(RefinementVar::Value)),
            Box::new(Predicate::Lit(lo)),
        )),
        Box::new(Predicate::Le(
            Box::new(Predicate::Var(RefinementVar::Value)),
            Box::new(Predicate::Lit(hi)),
        )),
    ))
}

/// Convert an AST expression into a predicate (for path-sensitive refinement).
fn expr_to_predicate(expr: &Expr) -> Option<Predicate> {
    match &expr.kind {
        ExprKind::Binary { op, left, right } => {
            let lp = expr_to_pred_term(left)?;
            let rp = expr_to_pred_term(right)?;
            match op {
                BinaryOp::Gt => Some(Predicate::Gt(Box::new(lp), Box::new(rp))),
                BinaryOp::Ge => Some(Predicate::Ge(Box::new(lp), Box::new(rp))),
                BinaryOp::Lt => Some(Predicate::Lt(Box::new(lp), Box::new(rp))),
                BinaryOp::Le => Some(Predicate::Le(Box::new(lp), Box::new(rp))),
                BinaryOp::Eq => Some(Predicate::Eq(Box::new(lp), Box::new(rp))),
                BinaryOp::Ne => Some(Predicate::Ne(Box::new(lp), Box::new(rp))),
                _ => None,
            }
        }
        _ => None,
    }
}

fn expr_to_pred_term(expr: &Expr) -> Option<Predicate> {
    match &expr.kind {
        ExprKind::Number(n) if n.fract().abs() < f64::EPSILON => Some(Predicate::Lit(*n as i64)),
        ExprKind::Var(name) => Some(Predicate::Var(RefinementVar::Named(name.clone()))),
        _ => None,
    }
}

/// Refine environment based on a condition being true or false.
/// Example: if a branch tests a numeric variable, the branch can refine that variable.
fn refine_env_from_condition(cond: &Expr, env: &mut RefinementEnv, branch_true: bool) {
    if let ExprKind::Binary { op, left, right } = &cond.kind {
        // Pattern: `$var > lit` or `$var != lit`
        if let (ExprKind::Var(name), ExprKind::Number(n)) = (&left.kind, &right.kind) {
            if n.fract().abs() < f64::EPSILON {
                let val = *n as i64;
                let pred = match (op, branch_true) {
                    (BinaryOp::Gt, true) => Some(Predicate::Gt(
                        Box::new(Predicate::Var(RefinementVar::Value)),
                        Box::new(Predicate::Lit(val)),
                    )),
                    (BinaryOp::Gt, false) => Some(Predicate::Le(
                        Box::new(Predicate::Var(RefinementVar::Value)),
                        Box::new(Predicate::Lit(val)),
                    )),
                    (BinaryOp::Ne, true) => Some(Predicate::Ne(
                        Box::new(Predicate::Var(RefinementVar::Value)),
                        Box::new(Predicate::Lit(val)),
                    )),
                    (BinaryOp::Eq, true) => Some(Predicate::Eq(
                        Box::new(Predicate::Var(RefinementVar::Value)),
                        Box::new(Predicate::Lit(val)),
                    )),
                    (BinaryOp::Ge, true) => Some(Predicate::Ge(
                        Box::new(Predicate::Var(RefinementVar::Value)),
                        Box::new(Predicate::Lit(val)),
                    )),
                    (BinaryOp::Lt, true) => Some(Predicate::Lt(
                        Box::new(Predicate::Var(RefinementVar::Value)),
                        Box::new(Predicate::Lit(val)),
                    )),
                    _ => None,
                };
                if let Some(p) = pred {
                    let base = env
                        .lookup(name)
                        .map(|r| r.base.clone())
                        .unwrap_or(Type::Num);
                    env.bind(
                        name,
                        Refined {
                            base,
                            pred: p,
                            span: None,
                        },
                    );
                }
            }
        }
    }
}
