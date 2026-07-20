//! Refinement constraint solver.
//!
//! Uses abstract interpretation over integer intervals to discharge
//! refinement constraints. This is a simplified "poor man's SMT" that
//! handles the most common patterns without requiring Z3.
//!
//! Strategy:
//! 1. For each `Subtype { sub, sup }` constraint, check whether
//!    `sub.pred ⇒ sup.pred` holds via interval arithmetic.
//! 2. Constant predicates are evaluated directly.
//! 3. Range-based predicates use interval meet/join.
//! 4. Undischargeable constraints become warnings (soft) or errors (hard).

use std::collections::HashMap;

use crate::refinement::constraint::{Constraint, ConstraintSet};
use crate::refinement::predicate::{Predicate, RefinementVar};
use crate::refinement::Refined;
use crate::vm::ir::{NumericProof, ProofSlot};

/// Solver configuration.
#[derive(Debug, Clone)]
pub struct SolverConfig {
    /// Maximum iterations for fixed-point computation.
    pub max_iterations: usize,
    /// Whether undischarged constraints are hard errors or soft warnings.
    pub strict_mode: bool,
}

impl Default for SolverConfig {
    fn default() -> Self {
        Self {
            max_iterations: 100,
            strict_mode: false,
        }
    }
}

/// Result from constraint solving.
#[derive(Debug, Clone, Default)]
pub struct SolverResult {
    pub discharged: usize,
    pub failed: usize,
    pub proof_slots: HashMap<String, ProofSlot>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

/// The refinement constraint solver.
pub struct Solver {
    config: SolverConfig,
}

/// An abstract domain for integer intervals: `[lo, hi]` or ⊤ (unknown).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum Interval {
    Top,
    Range(i64, i64),
    Bottom,
}

#[allow(dead_code)]
impl Interval {
    fn from_predicate(pred: &Predicate) -> Self {
        if let Some((lo, hi)) = pred.extract_range() {
            Self::Range(lo, hi)
        } else if let Some(v) = pred.eval_i64() {
            Self::Range(v, v)
        } else {
            Self::Top
        }
    }

    fn contains(self, value: i64) -> bool {
        match self {
            Self::Top => true,
            Self::Range(lo, hi) => value >= lo && value <= hi,
            Self::Bottom => false,
        }
    }

    fn excludes_zero(self) -> bool {
        match self {
            Self::Range(lo, hi) => lo > 0 || hi < 0,
            _ => false,
        }
    }

    /// Check whether `self ⊆ other` (self is subinterval of other).
    fn subset_of(self, other: Self) -> bool {
        match (self, other) {
            (_, Self::Top) => true,
            (Self::Bottom, _) => true,
            (Self::Top, Self::Range(..)) => false,
            (Self::Range(a_lo, a_hi), Self::Range(b_lo, b_hi)) => a_lo >= b_lo && a_hi <= b_hi,
            (Self::Range(..), Self::Bottom) => false,
            (Self::Top, Self::Bottom) => false,
        }
    }

    fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Top, r) | (r, Self::Top) => r,
            (Self::Range(a_lo, a_hi), Self::Range(b_lo, b_hi)) => {
                let lo = a_lo.max(b_lo);
                let hi = a_hi.min(b_hi);
                if lo > hi {
                    Self::Bottom
                } else {
                    Self::Range(lo, hi)
                }
            }
        }
    }
}

/// A solution represents the resolved abstract state.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct Solution {
    intervals: HashMap<String, Interval>,
    pub proof_slots: HashMap<String, ProofSlot>,
}

impl Solver {
    pub fn new(config: SolverConfig) -> Self {
        Self { config }
    }

    /// Solve a constraint set and return the result.
    pub fn solve(&self, cset: &ConstraintSet) -> SolverResult {
        let mut result = SolverResult::default();

        for constraint in cset.iter() {
            match self.discharge(constraint) {
                DischargeResult::Discharged(proof_info) => {
                    result.discharged += 1;
                    if let Some((name, slot)) = proof_info {
                        result.proof_slots.insert(name, slot);
                    }
                }
                DischargeResult::Undischarged(reason) => {
                    result.failed += 1;
                    if self.config.strict_mode {
                        result.errors.push(reason);
                    } else {
                        result.warnings.push(reason);
                    }
                }
            }
        }

        result
    }

    fn discharge(&self, constraint: &Constraint) -> DischargeResult {
        match constraint {
            Constraint::Subtype { sub, sup, context } => {
                self.discharge_subtype(sub, sup, context)
            }
            Constraint::WellFormed { refined, context } => {
                self.discharge_well_formed(refined, context)
            }
            Constraint::Guarded { guard, body } => {
                // If guard is trivially true, discharge body.
                // If guard is trivially false, constraint is vacuously true.
                match guard.eval_const() {
                    Some(false) => DischargeResult::Discharged(None),
                    Some(true) => self.discharge(body),
                    None => {
                        // Conservatively try to discharge the body.
                        self.discharge(body)
                    }
                }
            }
        }
    }

    fn discharge_subtype(
        &self,
        sub: &Refined,
        sup: &Refined,
        context: &str,
    ) -> DischargeResult {
        // Normalize Named → Value for interval/implication checks.
        let norm_sub_pred = sub.pred.substitute_named_with_value();
        let norm_sup_pred = sup.pred.substitute_named_with_value();

        // If super-type predicate is trivially true, always discharged.
        if norm_sup_pred.is_trivial() {
            return DischargeResult::Discharged(None);
        }

        // If sub-type predicate equals super-type predicate, discharged.
        if norm_sub_pred == norm_sup_pred {
            return DischargeResult::Discharged(None);
        }

        // Strategy 1: Constant evaluation.
        if let Some(true) = check_implication_const(&norm_sub_pred, &norm_sup_pred) {
            // Use original (Named) predicate for proof info extraction.
            return DischargeResult::Discharged(self.generate_proof_info(sub, sup));
        }

        // Strategy 2: Interval-based subtyping.
        let sub_interval = Interval::from_predicate(&norm_sub_pred);
        let sup_interval = Interval::from_predicate(&norm_sup_pred);

        if sup_interval != Interval::Top && sub_interval.subset_of(sup_interval) {
            // Generate proof evidence for the ProofSlot pipeline.
            let proof_info = self.generate_proof_info(sub, sup);
            return DischargeResult::Discharged(proof_info);
        }

        // Strategy 3: Nonzero check (for division safety).
        if norm_sup_pred.implies_nonzero() && norm_sub_pred.implies_nonzero() {
            let proof_info = self.generate_proof_info(sub, sup);
            return DischargeResult::Discharged(proof_info);
        }

        // Strategy 4: Check if sub has exact value that satisfies sup.
        if let Some((lo, hi)) = norm_sub_pred.extract_range() {
            if lo == hi {
                // Exact value — check if it satisfies all sup constraints.
                let mut proof = NumericProof::default();
                norm_sup_pred.extract_numeric_facts(&mut proof);
                if proof.nonzero && lo != 0 {
                    return DischargeResult::Discharged(self.generate_proof_info(sub, sup));
                }
                if let Some((sup_lo, sup_hi)) = norm_sup_pred.extract_range() {
                    if lo >= sup_lo && lo <= sup_hi {
                        return DischargeResult::Discharged(self.generate_proof_info(sub, sup));
                    }
                }
            }
        }

        // Undischarged — we can't prove the subtyping.
        DischargeResult::Undischarged(format!(
            "{}: cannot prove {{ {} }} <: {{ {} }}",
            context,
            sub.pred.display(),
            sup.pred.display(),
        ))
    }

    fn discharge_well_formed(
        &self,
        refined: &Refined,
        context: &str,
    ) -> DischargeResult {
        // Check that the predicate is satisfiable (not ⊥).
        if refined.pred.is_bottom() {
            return DischargeResult::Undischarged(format!(
                "{}: unsatisfiable predicate {}",
                context,
                refined.pred.display(),
            ));
        }
        if let Some(false) = refined.pred.eval_const() {
            return DischargeResult::Undischarged(format!(
                "{}: predicate evaluates to false: {}",
                context,
                refined.pred.display(),
            ));
        }
        DischargeResult::Discharged(None)
    }

    fn generate_proof_info(
        &self,
        sub: &Refined,
        _sup: &Refined,
    ) -> Option<(String, ProofSlot)> {
        // Extract the variable name from the original (Named) predicate.
        let name = extract_var_name(&sub.pred)?;
        // Normalize back to Value for numeric extraction (extract_numeric_facts
        // expects RefinementVar::Value).
        let normalized = Refined {
            base: sub.base.clone(),
            pred: sub.pred.substitute_named_with_value(),
            span: sub.span.clone(),
        };
        let slot = normalized.to_proof_slot();
        if slot.numeric.is_some() {
            Some((name, slot))
        } else {
            None
        }
    }
}

enum DischargeResult {
    Discharged(Option<(String, ProofSlot)>),
    Undischarged(String),
}

/// Check if `lhs ⇒ rhs` holds by constant evaluation.
fn check_implication_const(lhs: &Predicate, rhs: &Predicate) -> Option<bool> {
    // If rhs is trivially true, implication holds.
    if rhs.is_trivial() {
        return Some(true);
    }
    // If lhs is trivially false, implication holds vacuously.
    if lhs.is_bottom() || lhs.eval_const() == Some(false) {
        return Some(true);
    }

    // Special case: lhs says `v == exact`, check if rhs is satisfied at that exact value.
    if let Predicate::Eq(lhs_var, lhs_val) = lhs {
        if matches!(lhs_var.as_ref(), Predicate::Var(RefinementVar::Value)) {
            if let Some(exact) = lhs_val.eval_i64() {
                // Substitute the exact value into rhs and evaluate.
                let substituted = substitute_value(rhs, exact);
                return substituted.eval_const();
            }
        }
    }

    None
}

/// Substitute `RefinementVar::Value` with a concrete integer in a predicate.
fn substitute_value(pred: &Predicate, value: i64) -> Predicate {
    match pred {
        Predicate::Var(RefinementVar::Value) => Predicate::Lit(value),
        Predicate::Var(_) | Predicate::Lit(_) | Predicate::True | Predicate::False => {
            pred.clone()
        }
        Predicate::Eq(a, b) => Predicate::Eq(
            Box::new(substitute_value(a, value)),
            Box::new(substitute_value(b, value)),
        ),
        Predicate::Ne(a, b) => Predicate::Ne(
            Box::new(substitute_value(a, value)),
            Box::new(substitute_value(b, value)),
        ),
        Predicate::Gt(a, b) => Predicate::Gt(
            Box::new(substitute_value(a, value)),
            Box::new(substitute_value(b, value)),
        ),
        Predicate::Ge(a, b) => Predicate::Ge(
            Box::new(substitute_value(a, value)),
            Box::new(substitute_value(b, value)),
        ),
        Predicate::Lt(a, b) => Predicate::Lt(
            Box::new(substitute_value(a, value)),
            Box::new(substitute_value(b, value)),
        ),
        Predicate::Le(a, b) => Predicate::Le(
            Box::new(substitute_value(a, value)),
            Box::new(substitute_value(b, value)),
        ),
        Predicate::And(a, b) => Predicate::And(
            Box::new(substitute_value(a, value)),
            Box::new(substitute_value(b, value)),
        ),
        Predicate::Or(a, b) => Predicate::Or(
            Box::new(substitute_value(a, value)),
            Box::new(substitute_value(b, value)),
        ),
        Predicate::Not(a) => Predicate::Not(Box::new(substitute_value(a, value))),
        Predicate::Implies(a, b) => Predicate::Implies(
            Box::new(substitute_value(a, value)),
            Box::new(substitute_value(b, value)),
        ),
        Predicate::Add(a, b) => Predicate::Add(
            Box::new(substitute_value(a, value)),
            Box::new(substitute_value(b, value)),
        ),
        Predicate::Sub(a, b) => Predicate::Sub(
            Box::new(substitute_value(a, value)),
            Box::new(substitute_value(b, value)),
        ),
        Predicate::Mul(a, b) => Predicate::Mul(
            Box::new(substitute_value(a, value)),
            Box::new(substitute_value(b, value)),
        ),
        Predicate::Mod(a, b) => Predicate::Mod(
            Box::new(substitute_value(a, value)),
            Box::new(substitute_value(b, value)),
        ),
    }
}

/// Extract a variable name from a predicate (for tagging proof results).
fn extract_var_name(pred: &Predicate) -> Option<String> {
    match pred {
        Predicate::Var(RefinementVar::Named(n)) => Some(n.clone()),
        Predicate::Eq(a, _)
        | Predicate::Ne(a, _)
        | Predicate::Gt(a, _)
        | Predicate::Ge(a, _)
        | Predicate::Lt(a, _)
        | Predicate::Le(a, _) => extract_var_name(a),
        Predicate::And(a, _) => extract_var_name(a),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refinement::constraint::ConstraintSet;
    use crate::typecheck::Type;

    fn v() -> Box<Predicate> {
        Box::new(Predicate::Var(RefinementVar::Value))
    }

    fn lit(n: i64) -> Box<Predicate> {
        Box::new(Predicate::Lit(n))
    }

    #[test]
    fn test_div_by_constant_nonzero() {
        let mut cset = ConstraintSet::new();
        // $x / 5: the divisor is the constant 5, which is nonzero.
        let divisor = Refined {
            base: Type::Num,
            pred: Predicate::Eq(v(), lit(5)),
            span: None,
        };
        cset.add(Constraint::Subtype {
            sub: divisor,
            sup: Refined::num_nonzero(),
            context: "div by constant".into(),
        });

        let solver = Solver::new(SolverConfig::default());
        let result = solver.solve(&cset);
        assert_eq!(result.discharged, 1);
        assert_eq!(result.failed, 0);
    }

    #[test]
    fn test_div_by_zero_fails() {
        let mut cset = ConstraintSet::new();
        // $x / 0: the divisor is the constant 0.
        let divisor = Refined {
            base: Type::Num,
            pred: Predicate::Eq(v(), lit(0)),
            span: None,
        };
        cset.add(Constraint::Subtype {
            sub: divisor,
            sup: Refined::num_nonzero(),
            context: "div by zero".into(),
        });

        let solver = Solver::new(SolverConfig::default());
        let result = solver.solve(&cset);
        assert_eq!(result.discharged, 0);
        assert_eq!(result.failed, 1);
    }

    #[test]
    fn test_range_subtype() {
        let mut cset = ConstraintSet::new();
        // { v | 1 <= v <= 50 } <: { v | 0 <= v <= 100 }
        let sub = Refined::num_in_range(1, 50);
        let sup = Refined::num_in_range(0, 100);
        cset.add(Constraint::Subtype {
            sub,
            sup,
            context: "range subtype".into(),
        });

        let solver = Solver::new(SolverConfig::default());
        let result = solver.solve(&cset);
        assert_eq!(result.discharged, 1);
        assert_eq!(result.failed, 0);
    }

    #[test]
    fn test_range_not_subtype() {
        let mut cset = ConstraintSet::new();
        // { v | 0 <= v <= 200 } <: { v | 0 <= v <= 100 } — should fail
        let sub = Refined::num_in_range(0, 200);
        let sup = Refined::num_in_range(0, 100);
        cset.add(Constraint::Subtype {
            sub,
            sup,
            context: "range not subtype".into(),
        });

        let solver = Solver::new(SolverConfig::default());
        let result = solver.solve(&cset);
        assert_eq!(result.discharged, 0);
        assert_eq!(result.failed, 1);
    }

    #[test]
    fn test_positive_implies_nonzero() {
        let mut cset = ConstraintSet::new();
        let sub = Refined::num_positive();
        let sup = Refined::num_nonzero();
        cset.add(Constraint::Subtype {
            sub,
            sup,
            context: "positive implies nonzero".into(),
        });

        let solver = Solver::new(SolverConfig::default());
        let result = solver.solve(&cset);
        assert_eq!(result.discharged, 1);
        assert_eq!(result.failed, 0);
    }

    #[test]
    fn test_loop_count_constraint() {
        let mut cset = ConstraintSet::new();
        // Loop count = 10, should satisfy >= 0.
        let count = Refined {
            base: Type::Num,
            pred: Predicate::Eq(v(), lit(10)),
            span: None,
        };
        let requirement = Refined {
            base: Type::Num,
            pred: Predicate::Ge(v(), lit(0)),
            span: None,
        };
        cset.add(Constraint::Subtype {
            sub: count,
            sup: requirement,
            context: "loop count non-negative".into(),
        });

        let solver = Solver::new(SolverConfig::default());
        let result = solver.solve(&cset);
        assert_eq!(result.discharged, 1);
        assert_eq!(result.failed, 0);
    }

    #[test]
    fn test_negative_loop_count_fails() {
        let mut cset = ConstraintSet::new();
        // Loop count = -1, should fail >= 0.
        let count = Refined {
            base: Type::Num,
            pred: Predicate::Eq(v(), lit(-1)),
            span: None,
        };
        let requirement = Refined {
            base: Type::Num,
            pred: Predicate::Ge(v(), lit(0)),
            span: None,
        };
        cset.add(Constraint::Subtype {
            sub: count,
            sup: requirement,
            context: "loop count non-negative".into(),
        });

        let solver = Solver::new(SolverConfig::default());
        let result = solver.solve(&cset);
        assert_eq!(result.discharged, 0);
        assert_eq!(result.failed, 1);
    }
}
