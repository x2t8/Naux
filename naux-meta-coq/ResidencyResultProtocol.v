(**
  NauxCore.ResidencyResultProtocol

  A byte-level decoder for the fixed 48-byte result record emitted by the
  WP8G fresh-process register-residency artifacts.  The record contains an
  eight-byte magic followed by five little-endian 64-bit fields: artifact
  ordinal, signed checksum, terminal outer count, terminal inner count, and
  live allocation owner.

  This model establishes serialization structure only.  It does not model
  Linux write semantics, x86-64 execution, or prove that an execution emits
  a particular record.
*)

From Stdlib Require Import List Bool Arith ZArith.
From NauxCore Require Import ELF64ResidencyEnvelope.
Import ListNotations.

Definition residency_result_magic : list nat :=
  [78; 65; 85; 88; 53; 69; 48; 49].

Definition residency_result_bytes : nat := 48%nat.

Record residency_result_record : Type := {
  residency_result_ordinal : Z;
  residency_result_checksum : Z;
  residency_result_outer : Z;
  residency_result_inner : Z;
  residency_result_owner : Z
}.

Open Scope Z_scope.

(** Decode exactly eight little-endian bytes as an unsigned 64-bit integer.
    Callers first establish the exact record extent, so the fallback is never
    used for an accepted record. *)
Definition residency_result_decode_u64 (bytes : list nat) : Z :=
  match bytes with
  | [b0; b1; b2; b3; b4; b5; b6; b7] =>
      Z.of_nat b0 +
      256 * Z.of_nat b1 +
      65536 * Z.of_nat b2 +
      16777216 * Z.of_nat b3 +
      4294967296 * Z.of_nat b4 +
      1099511627776 * Z.of_nat b5 +
      281474976710656 * Z.of_nat b6 +
      72057594037927936 * Z.of_nat b7
  | _ => 0
  end.

Definition residency_result_decode_i64 (bytes : list nat) : Z :=
  let unsigned := residency_result_decode_u64 bytes in
  if unsigned <? 9223372036854775808
  then unsigned
  else unsigned - 18446744073709551616.

Definition residency_result_payload (bytes : list nat)
    : residency_result_record :=
  {| residency_result_ordinal :=
       residency_result_decode_u64 (firstn 8 (skipn 8 bytes));
     residency_result_checksum :=
       residency_result_decode_i64 (firstn 8 (skipn 16 bytes));
     residency_result_outer :=
       residency_result_decode_u64 (firstn 8 (skipn 24 bytes));
     residency_result_inner :=
       residency_result_decode_u64 (firstn 8 (skipn 32 bytes));
     residency_result_owner :=
       residency_result_decode_u64 (firstn 8 (skipn 40 bytes)) |}.

Definition residency_result_decode (bytes : list nat)
    : option residency_result_record :=
  if forallb elf64_residency_byte_validb bytes &&
     (Nat.eqb (length bytes) residency_result_bytes &&
      elf64_residency_list_eqb (firstn 8 bytes) residency_result_magic)
  then Some (residency_result_payload bytes)
  else None.

Definition residency_result_record_well_formed (bytes : list nat) : Prop :=
  Forall (fun byte => (byte < 256)%nat) bytes /\
  length bytes = residency_result_bytes /\
  firstn 8 bytes = residency_result_magic.

Lemma residency_result_magic_length :
  length residency_result_magic = 8%nat.
Proof. reflexivity. Qed.

Theorem residency_result_decode_sound :
  forall bytes result,
    residency_result_decode bytes = Some result ->
    residency_result_record_well_formed bytes /\
    result = residency_result_payload bytes.
Proof.
  intros bytes result Hdecode.
  unfold residency_result_decode in Hdecode.
  destruct
    (forallb elf64_residency_byte_validb bytes &&
     (Nat.eqb (length bytes) residency_result_bytes &&
      elf64_residency_list_eqb (firstn 8 bytes) residency_result_magic))
    eqn:Hcheck; try discriminate.
  inversion Hdecode. subst result.
  apply Bool.andb_true_iff in Hcheck.
  destruct Hcheck as [Hbytes Hshape].
  apply Bool.andb_true_iff in Hshape.
  destruct Hshape as [Hlength Hmagic].
  split.
  - repeat split.
    + now apply elf64_residency_bytes_check_sound.
    + apply Nat.eqb_eq in Hlength. exact Hlength.
    + now apply elf64_residency_list_eqb_sound.
  - reflexivity.
Qed.
