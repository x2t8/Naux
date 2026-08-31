(**
  NauxCore.Syntax (de Bruijn indices)
  - ty   : simple types
  - term : lambda + let + if + nat/bool literals
  - value: closed values
*)

From Stdlib Require Import List Arith Bool.
Import ListNotations.

Inductive ty : Type :=
| TyNat
| TyBool
| TyArrow (A B : ty).

Inductive term : Type :=
| TVar (x : nat)
| TAbs (A : ty) (body : term)
| TApp (t1 t2 : term)
| TLet (t1 t2 : term)
| TNat (n : nat)
| TBool (b : bool)
| TIf (c t e : term).

Inductive value : term -> Prop :=
| VAbs : forall A body, value (TAbs A body)
| VNat : forall n, value (TNat n)
| VBool : forall b, value (TBool b).

Definition ttrue := TBool true.
Definition tfalse := TBool false.

(* End of Syntax.v *)
