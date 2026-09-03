(**
  NauxCore.ELF64ResidencyProcessEnvelope

  A closed byte-level constructor for the sectionless ELF64 envelope used by
  the WP8G fresh-process register-residency candidate.  It extends the WP8F
  header model with the exact 117-byte result-record startup, the fixed
  sixteen-byte target alignment, and the already checked WP8G process target.

  This establishes image structure and payload containment.  It does not
  model the Linux loader, syscall semantics, x86-64 execution, clocks, or
  performance.
*)

From Stdlib Require Import List Bool Arith Lia.
From NauxCore Require Import ELF64ResidencyEnvelope.
Import ListNotations.

Definition elf64_residency_process_target_offset : nat := 384%nat.

(** The call displacement is 384 - 261 = 123.  The eight bytes following
    [49; 184] encode the non-zero artifact ordinal. *)
Definition elf64_residency_process_startup (ordinal : nat) : list nat :=
  [232; 123; 0; 0; 0;
   72; 131; 236; 48;
   73; 184; 78; 65; 85; 88; 53; 69; 48; 49;
   76; 137; 4; 36;
   73; 184] ++
  elf64_residency_small_le64 ordinal ++
  [76; 137; 68; 36; 8;
   72; 137; 68; 36; 16;
   72; 137; 76; 36; 24;
   72; 137; 84; 36; 32;
   72; 137; 116; 36; 40;
   184; 1; 0; 0; 0;
   191; 1; 0; 0; 0;
   72; 137; 230;
   186; 48; 0; 0; 0;
   15; 5;
   72; 131; 248; 48;
   15; 133; 15; 0; 0; 0;
   72; 131; 196; 48;
   49; 255;
   184; 60; 0; 0; 0;
   15; 5; 15; 11;
   191; 70; 0; 0; 0;
   184; 60; 0; 0; 0;
   15; 5; 15; 11].

Definition elf64_residency_process_image_bytes
    (process : list nat) : nat :=
  elf64_residency_process_target_offset + length process.

Definition elf64_residency_process_prefix
    (process : list nat) (ordinal : nat) : list nat :=
  elf64_residency_header ++
  elf64_residency_load_header
    (elf64_residency_process_image_bytes process) ++
  elf64_residency_stack_header ++
  repeat 0 80 ++
  elf64_residency_process_startup ordinal ++
  repeat 0 11.

Definition elf64_residency_process_envelope
    (process : list nat) (ordinal : nat) : list nat :=
  elf64_residency_process_prefix process ordinal ++ process.

Definition elf64_residency_process_extent_fitsb
    (process : list nat) : bool :=
  Nat.ltb (elf64_residency_process_image_bytes process) (256 * 256).

Definition elf64_residency_process_ordinal_validb
    (ordinal : nat) : bool :=
  Nat.ltb 0 ordinal && Nat.ltb ordinal (256 * 256).

Definition elf64_residency_process_image_check
    (process : list nat) (ordinal : nat) (image : list nat) : bool :=
  forallb elf64_residency_byte_validb image &&
  (elf64_residency_process_extent_fitsb process &&
   (elf64_residency_process_ordinal_validb ordinal &&
    elf64_residency_list_eqb image
      (elf64_residency_process_envelope process ordinal))).

Definition elf64_residency_process_image_well_formed
    (process : list nat) (ordinal : nat) (image : list nat) : Prop :=
  Forall (fun byte => (byte < 256)%nat) image /\
  elf64_residency_process_extent_fitsb process = true /\
  elf64_residency_process_ordinal_validb ordinal = true /\
  image = elf64_residency_process_envelope process ordinal.

Lemma elf64_residency_process_startup_length :
  forall ordinal,
    length (elf64_residency_process_startup ordinal) = 117%nat.
Proof.
  intros ordinal.
  unfold elf64_residency_process_startup,
    elf64_residency_small_le64.
  repeat rewrite length_app. simpl. lia.
Qed.

Lemma elf64_residency_process_prefix_length :
  forall process ordinal,
    length (elf64_residency_process_prefix process ordinal) = 384%nat.
Proof.
  intros process ordinal.
  unfold elf64_residency_process_prefix,
    elf64_residency_header, elf64_residency_load_header,
    elf64_residency_stack_header, elf64_residency_small_le64.
  repeat rewrite length_app.
  repeat rewrite repeat_length.
  rewrite elf64_residency_process_startup_length.
  simpl. lia.
Qed.

Theorem elf64_residency_process_envelope_extent :
  forall process ordinal,
    length (elf64_residency_process_envelope process ordinal) =
      (384 + length process)%nat.
Proof.
  intros process ordinal.
  unfold elf64_residency_process_envelope.
  rewrite length_app, elf64_residency_process_prefix_length.
  reflexivity.
Qed.

Theorem elf64_residency_process_envelope_contains_target :
  forall process ordinal,
    skipn 384 (elf64_residency_process_envelope process ordinal) = process.
Proof.
  intros process ordinal.
  unfold elf64_residency_process_envelope.
  set (prefix := elf64_residency_process_prefix process ordinal).
  change (skipn 384 (prefix ++ process) = process).
  assert (Hprefix : length prefix = 384%nat).
  { subst prefix. apply elf64_residency_process_prefix_length. }
  rewrite <- Hprefix.
  apply elf64_residency_skipn_length_app.
Qed.

Theorem elf64_residency_process_image_check_sound :
  forall process ordinal image,
    elf64_residency_process_image_check process ordinal image = true ->
    elf64_residency_process_image_well_formed process ordinal image.
Proof.
  intros process ordinal image Hcheck.
  unfold elf64_residency_process_image_check in Hcheck.
  repeat rewrite Bool.andb_true_iff in Hcheck.
  destruct Hcheck as [Hbytes [Hextent [Hordinal Henvelope]]].
  repeat split.
  - now apply elf64_residency_bytes_check_sound.
  - exact Hextent.
  - exact Hordinal.
  - now apply elf64_residency_list_eqb_sound.
Qed.

Theorem elf64_residency_process_image_from_prefix :
  forall process ordinal prefix,
    Forall (fun byte => (byte < 256)%nat) prefix ->
    Forall (fun byte => (byte < 256)%nat) process ->
    elf64_residency_process_extent_fitsb process = true ->
    elf64_residency_process_ordinal_validb ordinal = true ->
    prefix = elf64_residency_process_prefix process ordinal ->
    elf64_residency_process_image_well_formed
      process ordinal (prefix ++ process).
Proof.
  intros process ordinal prefix Hprefix_bytes Hprocess_bytes
    Hextent Hordinal Hprefix.
  repeat split.
  - apply Forall_app. now split.
  - exact Hextent.
  - exact Hordinal.
  - unfold elf64_residency_process_envelope. now rewrite Hprefix.
Qed.

Theorem elf64_residency_process_well_formed_contains_target :
  forall process ordinal image,
    elf64_residency_process_image_well_formed process ordinal image ->
    skipn 384 image = process.
Proof.
  intros process ordinal image [_ [_ [_ Henvelope]]].
  subst image.
  apply elf64_residency_process_envelope_contains_target.
Qed.
