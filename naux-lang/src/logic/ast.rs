//! Core logical term AST for the proof kernel (mini-Coq style).
//! Uses de Bruijn indices for binders to keep substitution simple.

use std::collections::VecDeque;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sort {
    Prop,
    Type0,
}

/// Logical terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    Sort(Sort),
    Var(usize), // de Bruijn index
    Nat,
    NatLit(u64),
    Bool,
    BoolLit(bool),
    Lambda {
        ty: Box<Term>,
        body: Box<Term>,
    },
    Pi {
        ty: Box<Term>,
        body: Box<Term>,
    },
    App {
        fun: Box<Term>,
        arg: Box<Term>,
    },
    Let {
        val: Box<Term>,
        body: Box<Term>,
    },
    Eq {
        ty: Box<Term>,
        lhs: Box<Term>,
        rhs: Box<Term>,
    },
    Refl {
        ty: Box<Term>,
        term: Box<Term>,
    },
    And(Box<Term>, Box<Term>),
    Pair(Box<Term>, Box<Term>),
    Fst(Box<Term>),
    Snd(Box<Term>),
}

impl Term {
    pub fn arrow(a: Term, b: Term) -> Term {
        Term::Pi {
            ty: Box::new(a),
            body: Box::new(b),
        }
    }
}

// --- Type Checker ---

pub type Context = VecDeque<Term>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeError {
    UnboundVariable(usize),
    SortHasNoType(Sort),
    Mismatch { expected: Term, found: Term },
    UnsupportedTerm(&'static str),
}

impl std::fmt::Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeError::UnboundVariable(idx) => write!(f, "Variable not in context: {}", idx),
            TypeError::SortHasNoType(sort) => write!(f, "Sort {:?} has no type", sort),
            TypeError::Mismatch { expected, found } => {
                write!(f, "Type mismatch: expected {:?}, got {:?}", expected, found)
            }
            TypeError::UnsupportedTerm(term) => {
                write!(f, "Type inference for term '{}' is not implemented", term)
            }
        }
    }
}

impl std::error::Error for TypeError {}

/// Infers the type of a term within a given context.
pub fn infer_type(ctx: &Context, term: &Term) -> Result<Term, TypeError> {
    match term {
        Term::Sort(Sort::Prop) => Ok(Term::Sort(Sort::Type0)),
        Term::Sort(s) => Err(TypeError::SortHasNoType(s.clone())),
        Term::Var(idx) => ctx
            .get(*idx)
            .cloned()
            .ok_or(TypeError::UnboundVariable(*idx)),
        Term::Nat => Ok(Term::Sort(Sort::Type0)),
        Term::NatLit(_) => Ok(Term::Nat),
        Term::Bool => Ok(Term::Sort(Sort::Type0)),
        Term::BoolLit(_) => Ok(Term::Bool),
        Term::Pi { ty, body } => {
            let _ = infer_type(ctx, ty)?; // Check that the type is a valid sort
            let mut new_ctx = ctx.clone();
            new_ctx.push_front(*ty.clone());
            let body_ty = infer_type(&new_ctx, body)?;
            // The type of a Pi-type is a Sort
            if let Term::Sort(s) = body_ty {
                Ok(Term::Sort(s))
            } else {
                Err(TypeError::Mismatch {
                    expected: Term::Sort(Sort::Type0), // Or some other sort
                    found: body_ty,
                })
            }
        }
        Term::App { fun, arg } => {
            let fun_ty = infer_type(ctx, fun)?;
            if let Term::Pi { ty, body } = fun_ty {
                check_type(ctx, arg, &ty)?;
                // TODO: Substitution for dependent types
                Ok(*body)
            } else {
                Err(TypeError::Mismatch {
                    expected: Term::Pi {
                        ty: Box::new(Term::Var(0)), // Placeholder
                        body: Box::new(Term::Var(0)),
                    },
                    found: fun_ty,
                })
            }
        }
        Term::Let { val, body } => {
            let val_ty = infer_type(ctx, val)?;
            let mut new_ctx = ctx.clone();
            new_ctx.push_front(val_ty);
            infer_type(&new_ctx, body)
        }
        Term::Lambda { ty, body } => {
            // Check that the type of the argument is a valid sort
            let _ = infer_type(ctx, ty)?;
            let mut new_ctx = ctx.clone();
            new_ctx.push_front(*ty.clone());
            let body_ty = infer_type(&new_ctx, body)?;
            Ok(Term::Pi {
                ty: ty.clone(),
                body: Box::new(body_ty),
            })
        }
        _ => Err(TypeError::UnsupportedTerm(unsupported_term_name(term))),
    }
}

fn unsupported_term_name(term: &Term) -> &'static str {
    match term {
        Term::Eq { .. } => "Eq",
        Term::Refl { .. } => "Refl",
        Term::And(_, _) => "And",
        Term::Pair(_, _) => "Pair",
        Term::Fst(_) => "Fst",
        Term::Snd(_) => "Snd",
        _ => "Unknown",
    }
}

/// Checks if a term has the expected type within a given context.
pub fn check_type(ctx: &Context, term: &Term, expected_type: &Term) -> Result<(), TypeError> {
    match (term, expected_type) {
        (
            Term::Lambda { ty: lam_ty, body },
            Term::Pi {
                ty: pi_ty,
                body: pi_body,
            },
        ) => {
            if **lam_ty != **pi_ty {
                return Err(TypeError::Mismatch {
                    expected: *pi_ty.clone(),
                    found: *lam_ty.clone(),
                });
            }
            let mut new_ctx = ctx.clone();
            new_ctx.push_front(*pi_ty.clone());
            check_type(&new_ctx, body, pi_body)
        }
        _ => {
            let found_type = infer_type(ctx, term)?;
            if found_type == *expected_type {
                Ok(())
            } else {
                Err(TypeError::Mismatch {
                    expected: expected_type.clone(),
                    found: found_type,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infer_type_reports_unsupported_eq_term() {
        let ctx = Context::new();
        let term = Term::Eq {
            ty: Box::new(Term::Nat),
            lhs: Box::new(Term::NatLit(1)),
            rhs: Box::new(Term::NatLit(1)),
        };
        let err = infer_type(&ctx, &term).expect_err("Eq should not panic or infer yet");
        assert_eq!(err, TypeError::UnsupportedTerm("Eq"));
    }

    #[test]
    fn infer_type_reports_unsupported_pair_term() {
        let ctx = Context::new();
        let term = Term::Pair(Box::new(Term::NatLit(1)), Box::new(Term::NatLit(2)));
        let err = infer_type(&ctx, &term).expect_err("Pair should not panic or infer yet");
        assert_eq!(err, TypeError::UnsupportedTerm("Pair"));
    }
}
