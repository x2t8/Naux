(**
  NauxCore.I64Arithmetic

  Executable signed 64-bit arithmetic shared by the bounded S4 residency
  models.  Values are represented by [Z], normalized into the signed i64
  interval after each arithmetic operation, and paired with the same signed
  overflow predicate used by Rust's [overflowing_add/sub/mul].
*)

From Stdlib Require Import Bool ZArith Lia.
Open Scope Z_scope.

Definition i64_bits : Z := 64.
Definition i64_modulus : Z := 2 ^ i64_bits.
Definition i64_half_modulus : Z := 2 ^ 63.
Definition i64_min : Z := -i64_half_modulus.
Definition i64_max : Z := i64_half_modulus - 1.

Definition i64_wrap (value : Z) : Z :=
  ((value - i64_min) mod i64_modulus) + i64_min.

Definition i64_in_rangeb (value : Z) : bool :=
  (i64_min <=? value) && (value <=? i64_max).

Definition i64_in_range (value : Z) : Prop :=
  i64_min <= value <= i64_max.

Theorem i64_in_rangeb_reflect : forall value,
  i64_in_rangeb value = true <-> i64_in_range value.
Proof.
  intro value. unfold i64_in_rangeb, i64_in_range.
  rewrite Bool.andb_true_iff, !Z.leb_le. tauto.
Qed.

Definition i64_overflowb (raw_result : Z) : bool :=
  negb (i64_in_rangeb raw_result).

Definition i64_add_raw (left right : Z) : Z :=
  i64_wrap left + i64_wrap right.

Definition i64_sub_raw (left right : Z) : Z :=
  i64_wrap left - i64_wrap right.

Definition i64_mul_raw (left right : Z) : Z :=
  i64_wrap left * i64_wrap right.

Definition i64_wrapping_add (left right : Z) : Z :=
  i64_wrap (i64_add_raw left right).

Definition i64_wrapping_sub (left right : Z) : Z :=
  i64_wrap (i64_sub_raw left right).

Definition i64_wrapping_mul (left right : Z) : Z :=
  i64_wrap (i64_mul_raw left right).

Definition overflow_increment (overflowed : bool) : nat :=
  if overflowed then 1%nat else 0%nat.

Theorem i64_wrap_in_range : forall value,
  i64_in_range (i64_wrap value).
Proof.
  intro value.
  assert (Hmodulus : i64_modulus = 18446744073709551616).
  { unfold i64_modulus, i64_bits. reflexivity. }
  assert (Hminimum : i64_min = -9223372036854775808).
  { unfold i64_min, i64_half_modulus. reflexivity. }
  assert (Hmaximum : i64_max = 9223372036854775807).
  { unfold i64_max, i64_half_modulus. reflexivity. }
  pose proof (Z.mod_pos_bound (value - i64_min) i64_modulus) as Hbound.
  specialize (Hbound ltac:(rewrite Hmodulus; lia)).
  unfold i64_in_range, i64_wrap.
  rewrite Hmodulus, Hminimum in Hbound.
  rewrite Hmodulus, Hminimum, Hmaximum.
  lia.
Qed.

Theorem i64_overflowb_reflect : forall raw_result,
  i64_overflowb raw_result = true <->
  raw_result < i64_min \/ i64_max < raw_result.
Proof.
  intro raw_result.
  unfold i64_overflowb, i64_in_rangeb.
  destruct (i64_min <=? raw_result) eqn:Hminimum;
    destruct (raw_result <=? i64_max) eqn:Hmaximum;
    simpl; rewrite ?Z.leb_le in Hminimum, Hmaximum;
    rewrite ?Z.leb_gt in Hminimum, Hmaximum; lia.
Qed.

Corollary i64_wrapping_add_in_range : forall left right,
  i64_in_range (i64_wrapping_add left right).
Proof. intros left right. apply i64_wrap_in_range. Qed.

Corollary i64_wrapping_sub_in_range : forall left right,
  i64_in_range (i64_wrapping_sub left right).
Proof. intros left right. apply i64_wrap_in_range. Qed.

Corollary i64_wrapping_mul_in_range : forall left right,
  i64_in_range (i64_wrapping_mul left right).
Proof. intros left right. apply i64_wrap_in_range. Qed.

Example i64_max_plus_one_wraps_to_min :
  i64_wrapping_add i64_max 1 = i64_min.
Proof. vm_compute. reflexivity. Qed.

Example i64_max_plus_one_reports_overflow :
  i64_overflowb (i64_add_raw i64_max 1) = true.
Proof. vm_compute. reflexivity. Qed.

Example i64_small_add_does_not_report_overflow :
  i64_overflowb (i64_add_raw 40 2) = false.
Proof. vm_compute. reflexivity. Qed.

Example i64_min_minus_one_wraps_to_max :
  i64_wrapping_sub i64_min 1 = i64_max.
Proof. vm_compute. reflexivity. Qed.

Example i64_min_minus_one_reports_overflow :
  i64_overflowb (i64_sub_raw i64_min 1) = true.
Proof. vm_compute. reflexivity. Qed.

Example i64_max_times_two_wraps_to_minus_two :
  i64_wrapping_mul i64_max 2 = -2.
Proof. vm_compute. reflexivity. Qed.

Example i64_max_times_two_reports_overflow :
  i64_overflowb (i64_mul_raw i64_max 2) = true.
Proof. vm_compute. reflexivity. Qed.
