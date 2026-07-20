//! Predicate language for refinement types.
//!
//! Predicates are the logical formulas attached to refined types.
//! They describe properties of values that the solver must verify.

use crate::vm::ir::NumericProof;

/// A variable in a predicate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RefinementVar {
    /// The "self" value of the refined type (the `v` in `{ v: T | P(v) }`).
    Value,
    /// A named program variable.
    Named(String),
    /// Length of a collection variable.
    LenOf(String),
}

impl std::fmt::Display for RefinementVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value => write!(f, "ν"),
            Self::Named(n) => write!(f, "${}", n),
            Self::LenOf(n) => write!(f, "len(${})", n),
        }
    }
}

/// A predicate in the refinement type system.
///
/// This is a small expression language for logical formulas.
/// It supports arithmetic comparisons, boolean connectives, and simple
/// arithmetic over variables and literals.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Predicate {
    /// Always true (trivial refinement).
    True,
    /// Always false (unreachable / bottom).
    False,
    /// A variable reference.
    Var(RefinementVar),
    /// An integer literal.
    Lit(i64),

    // ── Comparisons ──
    Eq(Box<Predicate>, Box<Predicate>),
    Ne(Box<Predicate>, Box<Predicate>),
    Gt(Box<Predicate>, Box<Predicate>),
    Ge(Box<Predicate>, Box<Predicate>),
    Lt(Box<Predicate>, Box<Predicate>),
    Le(Box<Predicate>, Box<Predicate>),

    // ── Boolean connectives ──
    And(Box<Predicate>, Box<Predicate>),
    Or(Box<Predicate>, Box<Predicate>),
    Not(Box<Predicate>),
    Implies(Box<Predicate>, Box<Predicate>),

    // ── Arithmetic (for expressing computed refinements) ──
    Add(Box<Predicate>, Box<Predicate>),
    Sub(Box<Predicate>, Box<Predicate>),
    Mul(Box<Predicate>, Box<Predicate>),
    Mod(Box<Predicate>, Box<Predicate>),
}

impl Predicate {
    /// Check whether this predicate is trivially true.
    pub fn is_trivial(&self) -> bool {
        matches!(self, Self::True)
    }

    /// Check whether this predicate is trivially false.
    pub fn is_bottom(&self) -> bool {
        matches!(self, Self::False)
    }

    /// Try to evaluate the predicate as a constant boolean.
    pub fn eval_const(&self) -> Option<bool> {
        match self {
            Self::True => Some(true),
            Self::False => Some(false),
            Self::Eq(a, b) => match (a.eval_i64(), b.eval_i64()) {
                (Some(x), Some(y)) => Some(x == y),
                _ => None,
            },
            Self::Ne(a, b) => match (a.eval_i64(), b.eval_i64()) {
                (Some(x), Some(y)) => Some(x != y),
                _ => None,
            },
            Self::Gt(a, b) => match (a.eval_i64(), b.eval_i64()) {
                (Some(x), Some(y)) => Some(x > y),
                _ => None,
            },
            Self::Ge(a, b) => match (a.eval_i64(), b.eval_i64()) {
                (Some(x), Some(y)) => Some(x >= y),
                _ => None,
            },
            Self::Lt(a, b) => match (a.eval_i64(), b.eval_i64()) {
                (Some(x), Some(y)) => Some(x < y),
                _ => None,
            },
            Self::Le(a, b) => match (a.eval_i64(), b.eval_i64()) {
                (Some(x), Some(y)) => Some(x <= y),
                _ => None,
            },
            Self::And(a, b) => match (a.eval_const(), b.eval_const()) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), Some(true)) => Some(true),
                _ => None,
            },
            Self::Or(a, b) => match (a.eval_const(), b.eval_const()) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (Some(false), Some(false)) => Some(false),
                _ => None,
            },
            Self::Not(a) => a.eval_const().map(|v| !v),
            Self::Implies(a, b) => match (a.eval_const(), b.eval_const()) {
                (Some(false), _) => Some(true),
                (_, Some(true)) => Some(true),
                (Some(true), Some(false)) => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    /// Try to evaluate as a constant integer.
    pub fn eval_i64(&self) -> Option<i64> {
        match self {
            Self::Lit(n) => Some(*n),
            Self::Add(a, b) => Some(a.eval_i64()?.checked_add(b.eval_i64()?)?),
            Self::Sub(a, b) => Some(a.eval_i64()?.checked_sub(b.eval_i64()?)?),
            Self::Mul(a, b) => Some(a.eval_i64()?.checked_mul(b.eval_i64()?)?),
            _ => None,
        }
    }

    /// Extract a value range `[lo, hi]` from this predicate if it has the form
    /// `v >= lo && v <= hi` or `v == exact`.
    pub fn extract_range(&self) -> Option<(i64, i64)> {
        match self {
            Self::Eq(lhs, rhs) => {
                if matches!(lhs.as_ref(), Self::Var(RefinementVar::Value)) {
                    rhs.eval_i64().map(|v| (v, v))
                } else {
                    None
                }
            }
            Self::And(a, b) => {
                let lo = extract_lower_bound(a);
                let hi = extract_upper_bound(b);
                match (lo, hi) {
                    (Some(l), Some(h)) if l <= h => Some((l, h)),
                    _ => {
                        // Try the other way around.
                        let lo = extract_lower_bound(b);
                        let hi = extract_upper_bound(a);
                        match (lo, hi) {
                            (Some(l), Some(h)) if l <= h => Some((l, h)),
                            _ => None,
                        }
                    }
                }
            }
            Self::Ge(lhs, rhs) => {
                if matches!(lhs.as_ref(), Self::Var(RefinementVar::Value)) {
                    rhs.eval_i64().map(|lo| (lo, i64::MAX))
                } else {
                    None
                }
            }
            Self::Gt(lhs, rhs) => {
                if matches!(lhs.as_ref(), Self::Var(RefinementVar::Value)) {
                    rhs.eval_i64()
                        .and_then(|lo| lo.checked_add(1))
                        .map(|lo| (lo, i64::MAX))
                } else {
                    None
                }
            }
            Self::Le(lhs, rhs) => {
                if matches!(lhs.as_ref(), Self::Var(RefinementVar::Value)) {
                    rhs.eval_i64().map(|hi| (i64::MIN, hi))
                } else {
                    None
                }
            }
            Self::Lt(lhs, rhs) => {
                if matches!(lhs.as_ref(), Self::Var(RefinementVar::Value)) {
                    rhs.eval_i64()
                        .and_then(|hi| hi.checked_sub(1))
                        .map(|hi| (i64::MIN, hi))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Check whether this predicate implies nonzero.
    pub fn implies_nonzero(&self) -> bool {
        match self {
            Self::Ne(lhs, rhs) => {
                matches!(lhs.as_ref(), Self::Var(RefinementVar::Value)) && rhs.eval_i64() == Some(0)
            }
            Self::Gt(lhs, rhs) => {
                matches!(lhs.as_ref(), Self::Var(RefinementVar::Value))
                    && rhs.eval_i64().map_or(false, |v| v >= 0)
            }
            Self::Ge(lhs, rhs) => {
                matches!(lhs.as_ref(), Self::Var(RefinementVar::Value))
                    && rhs.eval_i64().map_or(false, |v| v > 0)
            }
            Self::Lt(lhs, rhs) => {
                matches!(lhs.as_ref(), Self::Var(RefinementVar::Value))
                    && rhs.eval_i64().map_or(false, |v| v <= 0)
            }
            Self::Le(lhs, rhs) => {
                matches!(lhs.as_ref(), Self::Var(RefinementVar::Value))
                    && rhs.eval_i64().map_or(false, |v| v < 0)
            }
            Self::Eq(lhs, rhs) => {
                matches!(lhs.as_ref(), Self::Var(RefinementVar::Value))
                    && rhs.eval_i64().map_or(false, |v| v != 0)
            }
            Self::And(a, b) => a.implies_nonzero() || b.implies_nonzero(),
            _ => false,
        }
    }

    /// Extract numeric proof facts from this predicate into a [`NumericProof`].
    /// This bridges refinements into the existing ProofSlot system.
    pub fn extract_numeric_facts(&self, proof: &mut NumericProof) {
        match self {
            Self::Eq(lhs, rhs) if matches!(lhs.as_ref(), Self::Var(RefinementVar::Value)) => {
                if let Some(v) = rhs.eval_i64() {
                    proof.exact = Some(v);
                    proof.nonzero = v != 0;
                    if v >= 0 {
                        proof.range = Some((v as u64, v as u64));
                    }
                }
            }
            Self::And(a, b) => {
                // Try to extract a combined range from the whole And first.
                if let Some((lo, hi)) = self.extract_range() {
                    if lo >= 0 && hi >= 0 && hi < i64::MAX {
                        proof.range = Some((lo as u64, hi as u64));
                        if lo > 0 {
                            proof.nonzero = true;
                        }
                    }
                }
                // Also check children for nonzero / exact facts.
                if a.implies_nonzero() || b.implies_nonzero() {
                    proof.nonzero = true;
                }
                // Check for exact value in children.
                if let Self::Eq(lhs, rhs) = a.as_ref() {
                    if matches!(lhs.as_ref(), Self::Var(RefinementVar::Value)) {
                        if let Some(v) = rhs.eval_i64() {
                            proof.exact = Some(v);
                            proof.nonzero |= v != 0;
                        }
                    }
                }
                if let Self::Eq(lhs, rhs) = b.as_ref() {
                    if matches!(lhs.as_ref(), Self::Var(RefinementVar::Value)) {
                        if let Some(v) = rhs.eval_i64() {
                            proof.exact = Some(v);
                            proof.nonzero |= v != 0;
                        }
                    }
                }
            }
            _ => {
                if self.implies_nonzero() {
                    proof.nonzero = true;
                }
                if let Some((lo, hi)) = self.extract_range() {
                    if lo >= 0 && hi >= 0 && hi < i64::MAX {
                        proof.range = Some((lo as u64, hi as u64));
                        if lo > 0 {
                            proof.nonzero = true;
                        }
                    }
                }
            }
        }
    }

    /// Pretty-print for diagnostics.
    pub fn display(&self) -> String {
        match self {
            Self::True => "true".into(),
            Self::False => "false".into(),
            Self::Var(v) => v.to_string(),
            Self::Lit(n) => n.to_string(),
            Self::Eq(a, b) => format!("({} == {})", a.display(), b.display()),
            Self::Ne(a, b) => format!("({} != {})", a.display(), b.display()),
            Self::Gt(a, b) => format!("({} > {})", a.display(), b.display()),
            Self::Ge(a, b) => format!("({} >= {})", a.display(), b.display()),
            Self::Lt(a, b) => format!("({} < {})", a.display(), b.display()),
            Self::Le(a, b) => format!("({} <= {})", a.display(), b.display()),
            Self::And(a, b) => format!("({} ∧ {})", a.display(), b.display()),
            Self::Or(a, b) => format!("({} ∨ {})", a.display(), b.display()),
            Self::Not(a) => format!("¬{}", a.display()),
            Self::Implies(a, b) => format!("({} ⇒ {})", a.display(), b.display()),
            Self::Add(a, b) => format!("({} + {})", a.display(), b.display()),
            Self::Sub(a, b) => format!("({} - {})", a.display(), b.display()),
            Self::Mul(a, b) => format!("({} × {})", a.display(), b.display()),
            Self::Mod(a, b) => format!("({} mod {})", a.display(), b.display()),
        }
    }

    /// Replace every `RefinementVar::Value` with `RefinementVar::Named(name)`.
    ///
    /// Used when a variable is looked up from the environment so that
    /// the solver can later extract the variable name for proof tagging.
    pub fn substitute_value_with_named(&self, name: &str) -> Self {
        match self {
            Self::Var(RefinementVar::Value) => Self::Var(RefinementVar::Named(name.to_string())),
            Self::Var(_) | Self::Lit(_) | Self::True | Self::False => self.clone(),
            Self::Eq(a, b) => Self::Eq(
                Box::new(a.substitute_value_with_named(name)),
                Box::new(b.substitute_value_with_named(name)),
            ),
            Self::Ne(a, b) => Self::Ne(
                Box::new(a.substitute_value_with_named(name)),
                Box::new(b.substitute_value_with_named(name)),
            ),
            Self::Gt(a, b) => Self::Gt(
                Box::new(a.substitute_value_with_named(name)),
                Box::new(b.substitute_value_with_named(name)),
            ),
            Self::Ge(a, b) => Self::Ge(
                Box::new(a.substitute_value_with_named(name)),
                Box::new(b.substitute_value_with_named(name)),
            ),
            Self::Lt(a, b) => Self::Lt(
                Box::new(a.substitute_value_with_named(name)),
                Box::new(b.substitute_value_with_named(name)),
            ),
            Self::Le(a, b) => Self::Le(
                Box::new(a.substitute_value_with_named(name)),
                Box::new(b.substitute_value_with_named(name)),
            ),
            Self::And(a, b) => Self::And(
                Box::new(a.substitute_value_with_named(name)),
                Box::new(b.substitute_value_with_named(name)),
            ),
            Self::Or(a, b) => Self::Or(
                Box::new(a.substitute_value_with_named(name)),
                Box::new(b.substitute_value_with_named(name)),
            ),
            Self::Not(a) => Self::Not(Box::new(a.substitute_value_with_named(name))),
            Self::Implies(a, b) => Self::Implies(
                Box::new(a.substitute_value_with_named(name)),
                Box::new(b.substitute_value_with_named(name)),
            ),
            Self::Add(a, b) => Self::Add(
                Box::new(a.substitute_value_with_named(name)),
                Box::new(b.substitute_value_with_named(name)),
            ),
            Self::Sub(a, b) => Self::Sub(
                Box::new(a.substitute_value_with_named(name)),
                Box::new(b.substitute_value_with_named(name)),
            ),
            Self::Mul(a, b) => Self::Mul(
                Box::new(a.substitute_value_with_named(name)),
                Box::new(b.substitute_value_with_named(name)),
            ),
            Self::Mod(a, b) => Self::Mod(
                Box::new(a.substitute_value_with_named(name)),
                Box::new(b.substitute_value_with_named(name)),
            ),
        }
    }

    /// Replace every `RefinementVar::Named(_)` with `RefinementVar::Value`.
    ///
    /// Used before interval arithmetic in the solver, which expects
    /// the bound variable to be `Value`.
    pub fn substitute_named_with_value(&self) -> Self {
        match self {
            Self::Var(RefinementVar::Named(_)) => Self::Var(RefinementVar::Value),
            Self::Var(_) | Self::Lit(_) | Self::True | Self::False => self.clone(),
            Self::Eq(a, b) => Self::Eq(
                Box::new(a.substitute_named_with_value()),
                Box::new(b.substitute_named_with_value()),
            ),
            Self::Ne(a, b) => Self::Ne(
                Box::new(a.substitute_named_with_value()),
                Box::new(b.substitute_named_with_value()),
            ),
            Self::Gt(a, b) => Self::Gt(
                Box::new(a.substitute_named_with_value()),
                Box::new(b.substitute_named_with_value()),
            ),
            Self::Ge(a, b) => Self::Ge(
                Box::new(a.substitute_named_with_value()),
                Box::new(b.substitute_named_with_value()),
            ),
            Self::Lt(a, b) => Self::Lt(
                Box::new(a.substitute_named_with_value()),
                Box::new(b.substitute_named_with_value()),
            ),
            Self::Le(a, b) => Self::Le(
                Box::new(a.substitute_named_with_value()),
                Box::new(b.substitute_named_with_value()),
            ),
            Self::And(a, b) => Self::And(
                Box::new(a.substitute_named_with_value()),
                Box::new(b.substitute_named_with_value()),
            ),
            Self::Or(a, b) => Self::Or(
                Box::new(a.substitute_named_with_value()),
                Box::new(b.substitute_named_with_value()),
            ),
            Self::Not(a) => Self::Not(Box::new(a.substitute_named_with_value())),
            Self::Implies(a, b) => Self::Implies(
                Box::new(a.substitute_named_with_value()),
                Box::new(b.substitute_named_with_value()),
            ),
            Self::Add(a, b) => Self::Add(
                Box::new(a.substitute_named_with_value()),
                Box::new(b.substitute_named_with_value()),
            ),
            Self::Sub(a, b) => Self::Sub(
                Box::new(a.substitute_named_with_value()),
                Box::new(b.substitute_named_with_value()),
            ),
            Self::Mul(a, b) => Self::Mul(
                Box::new(a.substitute_named_with_value()),
                Box::new(b.substitute_named_with_value()),
            ),
            Self::Mod(a, b) => Self::Mod(
                Box::new(a.substitute_named_with_value()),
                Box::new(b.substitute_named_with_value()),
            ),
        }
    }
}

/// Extract a lower bound from `v >= lit` or `v > lit`.
fn extract_lower_bound(pred: &Predicate) -> Option<i64> {
    match pred {
        Predicate::Ge(lhs, rhs) if matches!(lhs.as_ref(), Predicate::Var(RefinementVar::Value)) => {
            rhs.eval_i64()
        }
        Predicate::Gt(lhs, rhs) if matches!(lhs.as_ref(), Predicate::Var(RefinementVar::Value)) => {
            rhs.eval_i64().and_then(|v| v.checked_add(1))
        }
        _ => None,
    }
}

/// Extract an upper bound from `v <= lit` or `v < lit`.
fn extract_upper_bound(pred: &Predicate) -> Option<i64> {
    match pred {
        Predicate::Le(lhs, rhs) if matches!(lhs.as_ref(), Predicate::Var(RefinementVar::Value)) => {
            rhs.eval_i64()
        }
        Predicate::Lt(lhs, rhs) if matches!(lhs.as_ref(), Predicate::Var(RefinementVar::Value)) => {
            rhs.eval_i64().and_then(|v| v.checked_sub(1))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v() -> Box<Predicate> {
        Box::new(Predicate::Var(RefinementVar::Value))
    }

    fn lit(n: i64) -> Box<Predicate> {
        Box::new(Predicate::Lit(n))
    }

    #[test]
    fn test_exact_eq() {
        let pred = Predicate::Eq(v(), lit(42));
        assert_eq!(pred.extract_range(), Some((42, 42)));
        assert!(pred.implies_nonzero());
    }

    #[test]
    fn test_eq_zero_not_nonzero() {
        let pred = Predicate::Eq(v(), lit(0));
        assert!(!pred.implies_nonzero());
    }

    #[test]
    fn test_range_and() {
        let pred = Predicate::And(
            Box::new(Predicate::Ge(v(), lit(1))),
            Box::new(Predicate::Le(v(), lit(100))),
        );
        assert_eq!(pred.extract_range(), Some((1, 100)));
        assert!(pred.implies_nonzero());
    }

    #[test]
    fn test_gt_zero_implies_nonzero() {
        let pred = Predicate::Gt(v(), lit(0));
        assert!(pred.implies_nonzero());
    }

    #[test]
    fn test_ne_zero_implies_nonzero() {
        let pred = Predicate::Ne(v(), lit(0));
        assert!(pred.implies_nonzero());
    }

    #[test]
    fn test_numeric_facts_extraction() {
        let pred = Predicate::And(
            Box::new(Predicate::Ge(v(), lit(5))),
            Box::new(Predicate::Le(v(), lit(50))),
        );
        let mut proof = NumericProof::default();
        pred.extract_numeric_facts(&mut proof);
        assert_eq!(proof.range, Some((5, 50)));
        assert!(proof.nonzero);
    }

    #[test]
    fn test_const_eval() {
        let pred = Predicate::Gt(lit(5), lit(3));
        assert_eq!(pred.eval_const(), Some(true));

        let pred2 = Predicate::And(
            Box::new(Predicate::Gt(lit(5), lit(3))),
            Box::new(Predicate::Lt(lit(2), lit(10))),
        );
        assert_eq!(pred2.eval_const(), Some(true));
    }

    #[test]
    fn test_display() {
        let pred = Predicate::And(
            Box::new(Predicate::Ge(v(), lit(0))),
            Box::new(Predicate::Lt(v(), lit(100))),
        );
        assert_eq!(pred.display(), "((ν >= 0) ∧ (ν < 100))");
    }
}
