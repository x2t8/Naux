//! Constraint types for refinement type checking.
//!
//! During type synthesis, the checker emits constraints. The solver then
//! attempts to discharge them. Undischarged constraints become type errors.

use crate::ast::Span;
use crate::refinement::{Refined, predicate::Predicate};

/// A single refinement constraint.
#[derive(Debug, Clone)]
pub enum Constraint {
    /// Subtyping: `sub <: sup` — the predicate on `sub` must imply `sup`'s.
    ///
    /// Example: for `$x / $y`, we emit `Subtype { sub: typeof($y), sup: { v | v ≠ 0 } }`.
    Subtype {
        sub: Refined,
        sup: Refined,
        context: String,
    },
    /// Well-formedness: a predicate must be satisfiable.
    WellFormed {
        refined: Refined,
        context: String,
    },
    /// Implication under path constraints: `path_condition ⇒ predicate`.
    Guarded {
        guard: Predicate,
        body: Box<Constraint>,
    },
}

impl Constraint {
    /// Human-readable description of this constraint.
    pub fn describe(&self) -> String {
        match self {
            Self::Subtype { sub, sup, context } => {
                format!(
                    "{}: {{ {} | {} }} <: {{ {} | {} }}",
                    context,
                    format!("{:?}", sub.base),
                    sub.pred.display(),
                    format!("{:?}", sup.base),
                    sup.pred.display(),
                )
            }
            Self::WellFormed { refined, context } => {
                format!(
                    "{}: WF {{ {} | {} }}",
                    context,
                    format!("{:?}", refined.base),
                    refined.pred.display(),
                )
            }
            Self::Guarded { guard, body } => {
                format!("{} ⇒ ({})", guard.display(), body.describe())
            }
        }
    }

    /// Get the span associated with the relevant refined type, if any.
    pub fn span(&self) -> Option<&Span> {
        match self {
            Self::Subtype { sup, .. } => sup.span.as_ref(),
            Self::WellFormed { refined, .. } => refined.span.as_ref(),
            Self::Guarded { body, .. } => body.span(),
        }
    }
}

/// A collection of constraints to be solved.
#[derive(Debug, Clone, Default)]
pub struct ConstraintSet {
    constraints: Vec<Constraint>,
}

impl ConstraintSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, c: Constraint) {
        self.constraints.push(c);
    }

    pub fn len(&self) -> usize {
        self.constraints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Constraint> {
        self.constraints.iter()
    }
}
