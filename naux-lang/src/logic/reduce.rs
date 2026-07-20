use crate::logic::ast::Term;

/// Shift de Bruijn indices in `t` by `d`, starting at cutoff `c`.
fn shift(d: isize, c: usize, t: &Term) -> Term {
    match t {
        Term::Sort(_) => t.clone(),
        Term::Var(k) => {
            if *k >= c {
                Term::Var(((*k as isize) + d) as usize)
            } else {
                Term::Var(*k)
            }
        }
        Term::Nat => Term::Nat,
        Term::NatLit(n) => Term::NatLit(*n),
        Term::Bool => Term::Bool,
        Term::BoolLit(b) => Term::BoolLit(*b),
        Term::Lambda { ty, body } => Term::Lambda {
            ty: Box::new(shift(d, c, ty)),
            body: Box::new(shift(d, c + 1, body)),
        },
        Term::Pi { ty, body } => Term::Pi {
            ty: Box::new(shift(d, c, ty)),
            body: Box::new(shift(d, c + 1, body)),
        },
        Term::App { fun, arg } => Term::App {
            fun: Box::new(shift(d, c, fun)),
            arg: Box::new(shift(d, c, arg)),
        },
        Term::Let { val, body } => Term::Let {
            val: Box::new(shift(d, c, val)),
            body: Box::new(shift(d, c + 1, body)),
        },
        Term::Eq { ty, lhs, rhs } => Term::Eq {
            ty: Box::new(shift(d, c, ty)),
            lhs: Box::new(shift(d, c, lhs)),
            rhs: Box::new(shift(d, c, rhs)),
        },
        Term::Refl { ty, term } => Term::Refl {
            ty: Box::new(shift(d, c, ty)),
            term: Box::new(shift(d, c, term)),
        },
        Term::And(a, b) => Term::And(Box::new(shift(d, c, a)), Box::new(shift(d, c, b))),
        Term::Pair(a, b) => Term::Pair(Box::new(shift(d, c, a)), Box::new(shift(d, c, b))),
        Term::Fst(p) => Term::Fst(Box::new(shift(d, c, p))),
        Term::Snd(p) => Term::Snd(Box::new(shift(d, c, p))),
    }
}

/// Substitute term `s` for variable `j` in term `t`.
fn subst(j: usize, s: &Term, t: &Term) -> Term {
    match t {
        Term::Sort(_) => t.clone(),
        Term::Var(k) => {
            if *k == j {
                shift(j as isize, 0, s)
            } else if *k > j {
                Term::Var(k - 1)
            } else {
                Term::Var(*k)
            }
        }
        Term::Nat => Term::Nat,
        Term::NatLit(n) => Term::NatLit(*n),
        Term::Bool => Term::Bool,
        Term::BoolLit(b) => Term::BoolLit(*b),
        Term::Lambda { ty, body } => Term::Lambda {
            ty: Box::new(subst(j, s, ty)),
            body: Box::new(subst(j + 1, s, body)),
        },
        Term::Pi { ty, body } => Term::Pi {
            ty: Box::new(subst(j, s, ty)),
            body: Box::new(subst(j + 1, s, body)),
        },
        Term::App { fun, arg } => Term::App {
            fun: Box::new(subst(j, s, fun)),
            arg: Box::new(subst(j, s, arg)),
        },
        Term::Let { val, body } => Term::Let {
            val: Box::new(subst(j, s, val)),
            body: Box::new(subst(j + 1, s, body)),
        },
        Term::Eq { ty, lhs, rhs } => Term::Eq {
            ty: Box::new(subst(j, s, ty)),
            lhs: Box::new(subst(j, s, lhs)),
            rhs: Box::new(subst(j, s, rhs)),
        },
        Term::Refl { ty, term } => Term::Refl {
            ty: Box::new(subst(j, s, ty)),
            term: Box::new(subst(j, s, term)),
        },
        Term::And(a, b) => Term::And(Box::new(subst(j, s, a)), Box::new(subst(j, s, b))),
        Term::Pair(a, b) => Term::Pair(Box::new(subst(j, s, a)), Box::new(subst(j, s, b))),
        Term::Fst(p) => Term::Fst(Box::new(subst(j, s, p))),
        Term::Snd(p) => Term::Snd(Box::new(subst(j, s, p))),
    }
}

pub fn subst_top(s: &Term, t: &Term) -> Term {
    subst(0, &shift(1, 0, s), t)
}

pub fn reduce_whnf(t: &Term) -> Term {
    match t {
        Term::App { fun, arg } => {
            let f = reduce_whnf(fun);
            match f {
                Term::Lambda { body, .. } => reduce_whnf(&subst_top(arg, &body)),
                _ => Term::App {
                    fun: Box::new(f),
                    arg: Box::new(reduce_whnf(arg)),
                },
            }
        }
        Term::Let { val, body } => reduce_whnf(&subst_top(val, body)),
        Term::Fst(p) => {
            let p_whnf = reduce_whnf(p);
            if let Term::Pair(a, _) = p_whnf {
                reduce_whnf(&a)
            } else {
                Term::Fst(Box::new(p_whnf))
            }
        }
        Term::Snd(p) => {
            let p_whnf = reduce_whnf(p);
            if let Term::Pair(_, b) = p_whnf {
                reduce_whnf(&b)
            } else {
                Term::Snd(Box::new(p_whnf))
            }
        }
        _ => t.clone(),
    }
}

/// Check convertibility up to weak-head reduction.
pub fn convertible(a: &Term, b: &Term) -> bool {
    let wa = reduce_whnf(a);
    let wb = reduce_whnf(b);
    wa == wb
}
