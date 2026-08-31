(**
  NauxCore.Typing (de Bruijn indices)
*)

From Stdlib Require Import List Arith.
Import ListNotations.

From NauxCore Require Import Syntax.

Definition context := list ty.

Definition ctx_lookup (x : nat) (Gamma : context) : option ty :=
  nth_error Gamma x.

Inductive has_type : context -> term -> ty -> Prop :=
| T_Var : forall Gamma x T,
    ctx_lookup x Gamma = Some T ->
    has_type Gamma (TVar x) T
| T_Abs : forall Gamma A body B,
    has_type (A :: Gamma) body B ->
    has_type Gamma (TAbs A body) (TyArrow A B)
| T_App : forall Gamma t1 t2 A B,
    has_type Gamma t1 (TyArrow A B) ->
    has_type Gamma t2 A ->
    has_type Gamma (TApp t1 t2) B
| T_Let : forall Gamma t1 t2 A B,
    has_type Gamma t1 A ->
    has_type (A :: Gamma) t2 B ->
    has_type Gamma (TLet t1 t2) B
| T_If : forall Gamma c t e T,
    has_type Gamma c TyBool ->
    has_type Gamma t T ->
    has_type Gamma e T ->
    has_type Gamma (TIf c t e) T
| T_Nat : forall Gamma n,
    has_type Gamma (TNat n) TyNat
| T_Bool : forall Gamma b,
    has_type Gamma (TBool b) TyBool.

(* End of Typing.v *)
