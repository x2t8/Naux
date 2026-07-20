(** NAUX meta model in Coq — Sample data/algorithms lemmas. *)

From Coq Require Import List Arith Bool Lia.
Import ListNotations.

(** Simple nat add. *)
Fixpoint add (a b : nat) : nat :=
  match a with
  | 0 => b
  | S a' => S (add a' b)
  end.

Lemma add_zero_left : forall n, add 0 n = n.
Proof. reflexivity. Qed.

Lemma add_zero_right : forall n, add n 0 = n.
Proof.
  induction n; simpl; auto.
Qed.

Lemma add_comm : forall a b, add a b = add b a.
Proof.
  induction a; intros; simpl.
  - rewrite add_zero_right; reflexivity.
  - rewrite IHa. induction b; simpl; auto.
Qed.

(** List lemmas using stdlib List.rev. *)
Lemma rev_rev : forall A (xs : list A), List.rev (List.rev xs) = xs.
Proof. apply List.rev_involutive. Qed.

Lemma length_append : forall A (xs ys : list A),
  length (xs ++ ys) = length xs + length ys.
Proof. apply length_app. Qed.

Lemma succ_not_eq : forall n, S n <> n.
Proof.
  intros n H. lia.
Qed.

(* End of DataAlgo.v *)
