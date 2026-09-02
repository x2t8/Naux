(**
  NauxCore.ELF64ResidencyEnvelope

  A closed byte-level constructor for the linker-free ELF64 envelope used by
  the bounded S4 register-residency candidate.  A certificate is accepted
  only when the complete reported image is byte-for-byte equal to this
  constructor around the already checked WP8E target.

  This establishes ELF structure and payload containment.  It does not model
  the Linux loader, system calls, x86-64 execution, or native correctness.
*)

From Stdlib Require Import List Bool Arith Lia.
Import ListNotations.

Definition elf64_residency_byte_validb (byte : nat) : bool :=
  Nat.ltb byte 256.

(** WP8F deliberately admits only images smaller than 64 KiB.  Encoding the
    two live extent bytes directly avoids normalizing divisions by enormous
    powers of two while retaining the exact ELF64 little-endian field. *)
Definition elf64_residency_small_le64 (value : nat) : list nat :=
  [value mod 256;
   (value / 256) mod 256;
   0; 0; 0; 0; 0; 0].

Definition elf64_residency_header : list nat :=
  [127; 69; 76; 70; 2; 1; 1; 0; 0; 0; 0; 0; 0; 0; 0; 0;
   2; 0; 62; 0; 1; 0; 0; 0; 0; 1; 64; 0; 0; 0; 0; 0;
   64; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0;
   0; 0; 0; 0; 64; 0; 56; 0; 2; 0; 0; 0; 0; 0; 0; 0].

Definition elf64_residency_load_header (image_bytes : nat) : list nat :=
  [1; 0; 0; 0; 5; 0; 0; 0;
   0; 0; 0; 0; 0; 0; 0; 0;
   0; 0; 64; 0; 0; 0; 0; 0;
   0; 0; 64; 0; 0; 0; 0; 0] ++
  elf64_residency_small_le64 image_bytes ++
  elf64_residency_small_le64 image_bytes ++
  [0; 16; 0; 0; 0; 0; 0; 0].

Definition elf64_residency_stack_header : list nat :=
  [81; 229; 116; 100; 6; 0; 0; 0;
   0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0;
   0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0;
   0; 0; 0; 0; 0; 0; 0; 0; 16; 0; 0; 0; 0; 0; 0; 0].

Definition elf64_residency_startup : list nat :=
  [232; 11; 0; 0; 0;
   49; 255; 184; 60; 0; 0; 0; 15; 5; 15; 11].

Definition elf64_residency_prefix (image_bytes : nat) : list nat :=
  elf64_residency_header ++
  elf64_residency_load_header image_bytes ++
  elf64_residency_stack_header ++
  repeat 0 80 ++
  elf64_residency_startup.

Definition elf64_residency_envelope (target : list nat) : list nat :=
  elf64_residency_prefix (272 + length target) ++ target.

Fixpoint elf64_residency_list_eqb
    (left right : list nat) : bool :=
  match left, right with
  | [], [] => true
  | left_byte :: left_rest, right_byte :: right_rest =>
      Nat.eqb left_byte right_byte &&
      elf64_residency_list_eqb left_rest right_rest
  | _, _ => false
  end.

Definition elf64_residency_image_check
    (target image : list nat) : bool :=
  forallb elf64_residency_byte_validb image &&
  (Nat.ltb (272 + length target) 65536 &&
   elf64_residency_list_eqb image (elf64_residency_envelope target)).

Definition elf64_residency_image_well_formed
    (target image : list nat) : Prop :=
  Forall (fun byte => byte < 256) image /\
  272 + length target < 65536 /\
  image = elf64_residency_envelope target.

Lemma elf64_residency_list_eqb_sound :
  forall left right,
    elf64_residency_list_eqb left right = true ->
    left = right.
Proof.
  induction left as [|left_byte left_rest IH];
    destruct right as [|right_byte right_rest]; simpl; intros Hcheck;
    try discriminate; try reflexivity.
  apply Bool.andb_true_iff in Hcheck.
  destruct Hcheck as [Hbyte Hrest].
  apply Nat.eqb_eq in Hbyte. subst right_byte.
  f_equal. now apply IH.
Qed.

Lemma elf64_residency_bytes_check_sound :
  forall image,
    forallb elf64_residency_byte_validb image = true ->
    Forall (fun byte => byte < 256) image.
Proof.
  intros image Hbytes.
  rewrite forallb_forall in Hbytes.
  apply Forall_forall. intros byte Hin.
  apply Nat.ltb_lt. now apply Hbytes.
Qed.

Theorem elf64_residency_image_check_sound :
  forall target image,
    elf64_residency_image_check target image = true ->
    elf64_residency_image_well_formed target image.
Proof.
  intros target image Hcheck.
  unfold elf64_residency_image_check in Hcheck.
  apply Bool.andb_true_iff in Hcheck.
  destruct Hcheck as [Hbytes Hstructure].
  apply Bool.andb_true_iff in Hstructure.
  destruct Hstructure as [Hextent Henvelope]. split.
  - now apply elf64_residency_bytes_check_sound.
  - split.
    + now apply Nat.ltb_lt.
    + now apply elf64_residency_list_eqb_sound.
Qed.

Lemma elf64_residency_prefix_length :
  forall image_bytes,
    length (elf64_residency_prefix image_bytes) = 272.
Proof.
  intros image_bytes.
  unfold elf64_residency_prefix, elf64_residency_header,
    elf64_residency_load_header,
    elf64_residency_stack_header, elf64_residency_startup,
    elf64_residency_small_le64.
  repeat rewrite length_app.
  repeat rewrite repeat_length.
  simpl. lia.
Qed.

Lemma elf64_residency_skipn_length_app :
  forall (left right : list nat),
    skipn (length left) (left ++ right) = right.
Proof.
  induction left as [|head tail IH]; intros right; simpl; auto.
Qed.

Theorem elf64_residency_envelope_extent :
  forall target,
    length (elf64_residency_envelope target) = 272 + length target.
Proof.
  intros target. unfold elf64_residency_envelope.
  rewrite length_app, elf64_residency_prefix_length. reflexivity.
Qed.

Theorem elf64_residency_envelope_contains_target :
  forall target,
    skipn 272 (elf64_residency_envelope target) = target.
Proof.
  intros target. unfold elf64_residency_envelope.
  set (prefix := elf64_residency_prefix (272 + length target)).
  change (skipn 272 (prefix ++ target) = target).
  assert (Hprefix : length prefix = 272).
  { subst prefix. apply elf64_residency_prefix_length. }
  rewrite <- Hprefix.
  apply elf64_residency_skipn_length_app.
Qed.

Theorem elf64_residency_image_from_prefix :
  forall target prefix,
    Forall (fun byte => byte < 256) prefix ->
    Forall (fun byte => byte < 256) target ->
    272 + length target < 65536 ->
    prefix = elf64_residency_prefix (272 + length target) ->
    elf64_residency_image_well_formed target (prefix ++ target).
Proof.
  intros target prefix Hprefix_bytes Htarget_bytes Hextent Hprefix. split.
  - apply Forall_app. now split.
  - split.
    + exact Hextent.
    + unfold elf64_residency_envelope. now rewrite Hprefix.
Qed.

Theorem elf64_residency_well_formed_contains_target :
  forall target image,
    elf64_residency_image_well_formed target image ->
    skipn 272 image = target.
Proof.
  intros target image [_ [_ Henvelope]]. subst image.
  apply elf64_residency_envelope_contains_target.
Qed.
