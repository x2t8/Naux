(**
  NauxCore.RegisterResidency

  A small, separately checked model of one local compiler rewrite: keeping a
  selected stack-resident scalar in a register while a straight-line region
  performs scalar updates on it.

  This file does not model x86-64, register allocation, aliasing, calls, traps,
  or the full NAUX language.  Those obligations remain outside this theorem.
*)

From Stdlib Require Import List ZArith Lia.
Import ListNotations.
Open Scope Z_scope.

Definition cell_map := nat -> Z.

Definition map_update (m : cell_map) (key : nat) (value : Z) : cell_map :=
  fun query => if Nat.eqb query key then value else m query.

Lemma map_update_eq : forall m key value,
  map_update m key value key = value.
Proof.
  intros. unfold map_update. now rewrite Nat.eqb_refl.
Qed.

Lemma map_update_neq : forall m key value query,
  query <> key ->
  map_update m key value query = m query.
Proof.
  intros m key value query Hneq.
  unfold map_update.
  apply Nat.eqb_neq in Hneq. now rewrite Hneq.
Qed.

Record machine_state : Type := {
  stack_cells : cell_map;
  register_cells : cell_map
}.

Definition with_stack (st : machine_state) (stack : cell_map) : machine_state :=
  {| stack_cells := stack; register_cells := register_cells st |}.

Definition with_registers (st : machine_state) (registers : cell_map)
  : machine_state :=
  {| stack_cells := stack_cells st; register_cells := registers |}.

(**
  The candidate register contains the authoritative value of [home_slot].
  Every non-home stack cell and every non-resident register is unchanged.
  The candidate home slot may be stale until the value is materialized.
*)
Definition resident_equiv
    (home_slot resident_register : nat)
    (baseline candidate : machine_state) : Prop :=
  register_cells candidate resident_register = stack_cells baseline home_slot /\
  (forall slot,
      slot <> home_slot ->
      stack_cells candidate slot = stack_cells baseline slot) /\
  (forall reg,
      reg <> resident_register ->
      register_cells candidate reg = register_cells baseline reg).

Inductive scalar_update : Type :=
| SetConst (value : Z)
| AddConst (value : Z)
| SubConst (value : Z)
| MulConst (value : Z).

Definition apply_scalar (op : scalar_update) (value : Z) : Z :=
  match op with
  | SetConst next => next
  | AddConst delta => value + delta
  | SubConst delta => value - delta
  | MulConst factor => value * factor
  end.

Definition baseline_step
    (home_slot : nat) (op : scalar_update) (st : machine_state)
    : machine_state :=
  with_stack st
    (map_update (stack_cells st) home_slot
      (apply_scalar op (stack_cells st home_slot))).

Definition resident_step
    (resident_register : nat) (op : scalar_update) (st : machine_state)
    : machine_state :=
  with_registers st
    (map_update (register_cells st) resident_register
      (apply_scalar op (register_cells st resident_register))).

Theorem resident_step_preserves_equiv :
  forall home_slot resident_register baseline candidate op,
    resident_equiv home_slot resident_register baseline candidate ->
    resident_equiv home_slot resident_register
      (baseline_step home_slot op baseline)
      (resident_step resident_register op candidate).
Proof.
  intros home_slot resident_register baseline candidate op
    [Hhome [Hstack Hregister]].
  split.
  - simpl. repeat rewrite map_update_eq. now rewrite Hhome.
  - split.
    + intros slot Hslot. simpl.
      rewrite map_update_neq by exact Hslot.
      apply Hstack. exact Hslot.
    + intros reg Hreg. simpl.
      rewrite map_update_neq by exact Hreg.
      apply Hregister. exact Hreg.
Qed.

Fixpoint baseline_run
    (home_slot : nat) (program : list scalar_update) (st : machine_state)
    : machine_state :=
  match program with
  | [] => st
  | op :: rest => baseline_run home_slot rest (baseline_step home_slot op st)
  end.

Fixpoint resident_run
    (resident_register : nat) (program : list scalar_update)
    (st : machine_state) : machine_state :=
  match program with
  | [] => st
  | op :: rest =>
      resident_run resident_register rest
        (resident_step resident_register op st)
  end.

Theorem resident_run_preserves_equiv :
  forall program home_slot resident_register baseline candidate,
    resident_equiv home_slot resident_register baseline candidate ->
    resident_equiv home_slot resident_register
      (baseline_run home_slot program baseline)
      (resident_run resident_register program candidate).
Proof.
  induction program as [|op rest IH]; intros; simpl.
  - exact H.
  - apply IH. now apply resident_step_preserves_equiv.
Qed.

Definition spill_home
    (home_slot resident_register : nat) (candidate : machine_state)
    : machine_state :=
  with_stack candidate
    (map_update (stack_cells candidate) home_slot
      (register_cells candidate resident_register)).

Theorem spill_restores_stack :
  forall home_slot resident_register baseline candidate,
    resident_equiv home_slot resident_register baseline candidate ->
    forall slot,
      stack_cells (spill_home home_slot resident_register candidate) slot =
      stack_cells baseline slot.
Proof.
  intros home_slot resident_register baseline candidate
    [Hhome [Hstack Hregister]] slot.
  destruct (Nat.eq_dec slot home_slot) as [Heq | Hneq].
  - subst. simpl. rewrite map_update_eq. exact Hhome.
  - simpl. rewrite map_update_neq by exact Hneq.
    apply Hstack. exact Hneq.
Qed.

Theorem resident_program_spill_correct :
  forall program home_slot resident_register baseline candidate,
    resident_equiv home_slot resident_register baseline candidate ->
    forall slot,
      stack_cells
        (spill_home home_slot resident_register
          (resident_run resident_register program candidate)) slot =
      stack_cells (baseline_run home_slot program baseline) slot.
Proof.
  intros program home_slot resident_register baseline candidate Hequiv slot.
  apply spill_restores_stack.
  now apply resident_run_preserves_equiv.
Qed.

Theorem resident_program_result_correct :
  forall program home_slot resident_register baseline candidate,
    resident_equiv home_slot resident_register baseline candidate ->
    register_cells (resident_run resident_register program candidate)
      resident_register =
    stack_cells (baseline_run home_slot program baseline) home_slot.
Proof.
  intros.
  pose proof
    (resident_run_preserves_equiv program home_slot resident_register
      baseline candidate H) as Hrun.
  exact (proj1 Hrun).
Qed.

(** A concrete loop-shaped update trace, checked by computation. *)
Example four_iterations_preserve_result :
  forall home_slot resident_register baseline candidate,
    resident_equiv home_slot resident_register baseline candidate ->
    register_cells
      (resident_run resident_register
        [AddConst 3; AddConst 3; AddConst 3; AddConst 3] candidate)
      resident_register =
    stack_cells
      (baseline_run home_slot
        [AddConst 3; AddConst 3; AddConst 3; AddConst 3] baseline)
      home_slot.
Proof.
  intros. now apply resident_program_result_correct.
Qed.
