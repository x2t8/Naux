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

Definition elf64_residency_le16 (value : nat) : list nat :=
  [value mod 256;
   (value / 256) mod 256].

Definition elf64_residency_le32 (value : nat) : list nat :=
  [value mod 256;
   (value / 256) mod 256;
   (value / 65536) mod 256;
   (value / 16777216) mod 256].

Definition elf64_residency_le64 (value : nat) : list nat :=
  [value mod 256;
   (value / 256) mod 256;
   (value / 65536) mod 256;
   (value / 16777216) mod 256;
   (value / 4294967296) mod 256;
   (value / 1099511627776) mod 256;
   (value / 281474976710656) mod 256;
   (value / 72057594037927936) mod 256].

Definition elf64_residency_ident : list nat :=
  [127; 69; 76; 70; 2; 1; 1] ++ repeat 0 9.

Definition elf64_residency_header : list nat :=
  elf64_residency_ident ++
  elf64_residency_le16 2 ++
  elf64_residency_le16 62 ++
  elf64_residency_le32 1 ++
  elf64_residency_le64 4194560 ++
  elf64_residency_le64 64 ++
  elf64_residency_le64 0 ++
  elf64_residency_le32 0 ++
  elf64_residency_le16 64 ++
  elf64_residency_le16 56 ++
  elf64_residency_le16 2 ++
  elf64_residency_le16 0 ++
  elf64_residency_le16 0 ++
  elf64_residency_le16 0.

Definition elf64_residency_load_header (image_bytes : nat) : list nat :=
  elf64_residency_le32 1 ++
  elf64_residency_le32 5 ++
  elf64_residency_le64 0 ++
  elf64_residency_le64 4194304 ++
  elf64_residency_le64 4194304 ++
  elf64_residency_le64 image_bytes ++
  elf64_residency_le64 image_bytes ++
  elf64_residency_le64 4096.

Definition elf64_residency_stack_header : list nat :=
  elf64_residency_le32 1685382481 ++
  elf64_residency_le32 6 ++
  elf64_residency_le64 0 ++
  elf64_residency_le64 0 ++
  elf64_residency_le64 0 ++
  elf64_residency_le64 0 ++
  elf64_residency_le64 0 ++
  elf64_residency_le64 16.

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
  elf64_residency_list_eqb image (elf64_residency_envelope target).

Definition elf64_residency_image_well_formed
    (target image : list nat) : Prop :=
  Forall (fun byte => byte < 256) image /\
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

Theorem elf64_residency_image_check_sound :
  forall target image,
    elf64_residency_image_check target image = true ->
    elf64_residency_image_well_formed target image.
Proof.
  intros target image Hcheck.
  unfold elf64_residency_image_check in Hcheck.
  apply Bool.andb_true_iff in Hcheck.
  destruct Hcheck as [Hbytes Henvelope]. split.
  - rewrite forallb_forall in Hbytes.
    apply Forall_forall. intros byte Hin.
    apply Nat.ltb_lt. now apply Hbytes.
  - now apply elf64_residency_list_eqb_sound.
Qed.

Lemma elf64_residency_prefix_length :
  forall image_bytes,
    length (elf64_residency_prefix image_bytes) = 272.
Proof.
  intros image_bytes.
  unfold elf64_residency_prefix, elf64_residency_header,
    elf64_residency_ident, elf64_residency_load_header,
    elf64_residency_stack_header, elf64_residency_startup,
    elf64_residency_le16, elf64_residency_le32,
    elf64_residency_le64.
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
  replace 272 with (length prefix).
  - apply elf64_residency_skipn_length_app.
  - subst prefix. symmetry. apply elf64_residency_prefix_length.
Qed.

Theorem elf64_residency_well_formed_contains_target :
  forall target image,
    elf64_residency_image_well_formed target image ->
    skipn 272 image = target.
Proof.
  intros target image [_ Henvelope]. subst image.
  apply elf64_residency_envelope_contains_target.
Qed.
