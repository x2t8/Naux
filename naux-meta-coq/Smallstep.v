(**
  NauxCore.Smallstep (de Bruijn indices)
  - shift/subst
  - small-step semantics
*)

From Stdlib Require Import List Arith Bool.
Import ListNotations.

From NauxCore Require Import Syntax.

Fixpoint shift (d c : nat) (t : term) : term :=
  match t with
  | TVar k => if Nat.leb c k then TVar (k + d) else TVar k
  | TAbs A body => TAbs A (shift d (S c) body)
  | TApp t1 t2 => TApp (shift d c t1) (shift d c t2)
  | TLet t1 t2 => TLet (shift d c t1) (shift d (S c) t2)
  | TNat n => TNat n
  | TBool b => TBool b
  | TIf c1 t1 t2 => TIf (shift d c c1) (shift d c t1) (shift d c t2)
  end.

Fixpoint subst (j : nat) (s t : term) : term :=
  match t with
  | TVar k =>
      match Nat.compare k j with
      | Eq => s
      | Gt => TVar (k - 1)
      | Lt => TVar k
      end
  | TAbs A body => TAbs A (subst (S j) (shift 1 0 s) body)
  | TApp t1 t2 => TApp (subst j s t1) (subst j s t2)
  | TLet t1 t2 => TLet (subst j s t1) (subst (S j) (shift 1 0 s) t2)
  | TNat n => TNat n
  | TBool b => TBool b
  | TIf c1 t1 t2 => TIf (subst j s c1) (subst j s t1) (subst j s t2)
  end.

Inductive step : term -> term -> Prop :=
| ST_AppAbs : forall A body v2,
    value v2 ->
    step (TApp (TAbs A body) v2) (subst 0 v2 body)
| ST_App1 : forall t1 t1' t2,
    step t1 t1' ->
    step (TApp t1 t2) (TApp t1' t2)
| ST_App2 : forall v1 t2 t2',
    value v1 ->
    step t2 t2' ->
    step (TApp v1 t2) (TApp v1 t2')
| ST_LetValue : forall v1 t2,
    value v1 ->
    step (TLet v1 t2) (subst 0 v1 t2)
| ST_Let : forall t1 t1' t2,
    step t1 t1' ->
    step (TLet t1 t2) (TLet t1' t2)
| ST_IfTrue : forall t e,
    step (TIf (TBool true) t e) t
| ST_IfFalse : forall t e,
    step (TIf (TBool false) t e) e
| ST_If : forall c c' t e,
    step c c' ->
    step (TIf c t e) (TIf c' t e).

Inductive multi_step : term -> term -> Prop :=
| ms_refl : forall t, multi_step t t
| ms_step : forall t t' t'',
    step t t' ->
    multi_step t' t'' ->
    multi_step t t''.

(* End of Smallstep.v *)
