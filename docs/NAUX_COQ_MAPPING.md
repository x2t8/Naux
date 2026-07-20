## NAUX ↔ Coq mapping (L0 core)

- NAUX `Int` / `Nat` ↔ `tyNat` (Coq `TyNat` in `Syntax.v`).
- NAUX `Bool` ↔ `tyBool` (`TyBool`).
- Function ↔ `TAbs`/`TApp` (`TyArrow`).
- `let` ↔ `TLet`.
- `if` ↔ `TIf`.
- Literals ↔ `TNat n`, `TBool b`.
- Subset modeled: L0 = lambda + let + if + nat/bool (mini core).

Commitment: Rust/NAUX semantics for this subset should align with `naux-meta-coq` definitions (`NauxCore.*`). Further constructs (pair/list/effects) to be added later. Proof artifacts live in `naux-meta-coq/`, not required for end users. 
