(**
  NauxCore.ResidencyProcessTarget

  A closed structural model of the WP8G process-target rewrite.  The final
  sixteen-byte restore/return range of an admitted WP8E target is replaced by
  one relative jump plus padding, and an eighty-byte completion verifier is
  appended.  The model checks the original return, jump destination, verifier
  fields, terminal-state expectations, and all three error edges.

  This is byte-structure evidence.  It does not model general x86 execution,
  Linux loading, syscalls, clocks, or performance.
*)

From Stdlib Require Import List Bool Arith Lia ZArith.
From NauxCore Require Import X86ResidencyEncoding.
Import ListNotations.
Open Scope Z_scope.

Definition residency_process_bytes_at
    (target : list nat) (start width : nat) : list nat :=
  firstn width (skipn start target).

Definition residency_process_return_decode
    (bytes : list nat) : option (Z * Z) :=
  match bytes with
  | [76%nat; 139%nat; 165%nat; p0; p1; p2; p3;
     72%nat; 139%nat; 133%nat; c0; c1; c2; c3;
     201%nat; 195%nat] =>
      match x86_decode_disp32 p0 p1 p2 p3,
            x86_decode_disp32 c0 c1 c2 c3 with
      | Some promoted, Some checksum => Some (promoted, checksum)
      | _, _ => None
      end
  | _ => None
  end.

Definition residency_process_jump_decode
    (bytes : list nat) : option Z :=
  match bytes with
  | [233%nat; b0; b1; b2; b3;
     144%nat; 144%nat; 144%nat; 144%nat; 144%nat; 144%nat;
     144%nat; 144%nat; 144%nat; 144%nat; 144%nat] =>
      x86_decode_disp32 b0 b1 b2 b3
  | _ => None
  end.

Record residency_completion_verifier : Type := {
  residency_completion_checksum_displacement : Z;
  residency_completion_outer_displacement : Z;
  residency_completion_expected_outer : nat;
  residency_completion_outer_error_delta : Z;
  residency_completion_expected_inner : nat;
  residency_completion_inner_error_delta : Z;
  residency_completion_owner_displacement : Z;
  residency_completion_owner_error_delta : Z;
  residency_completion_promoted_displacement : Z
}.

Definition residency_process_verifier_decode
    (bytes : list nat) : option residency_completion_verifier :=
  match bytes with
  | [72%nat; 139%nat; 133%nat; c0; c1; c2; c3;
     72%nat; 139%nat; 141%nat; o0; o1; o2; o3;
     73%nat; 184%nat; eo0; eo1; 0%nat; 0%nat; 0%nat; 0%nat; 0%nat; 0%nat;
     76%nat; 57%nat; 193%nat; 15%nat; 133%nat; bo0; bo1; bo2; bo3;
     76%nat; 137%nat; 226%nat;
     73%nat; 184%nat; ei0; ei1; 0%nat; 0%nat; 0%nat; 0%nat; 0%nat; 0%nat;
     76%nat; 57%nat; 194%nat; 15%nat; 133%nat; bi0; bi1; bi2; bi3;
     72%nat; 139%nat; 181%nat; w0; w1; w2; w3;
     72%nat; 133%nat; 246%nat; 15%nat; 133%nat; bw0; bw1; bw2; bw3;
     76%nat; 139%nat; 165%nat; p0; p1; p2; p3;
     201%nat; 195%nat] =>
      match x86_decode_disp32 c0 c1 c2 c3,
            x86_decode_disp32 o0 o1 o2 o3,
            x86_decode_disp32 bo0 bo1 bo2 bo3,
            x86_decode_disp32 bi0 bi1 bi2 bi3,
            x86_decode_disp32 w0 w1 w2 w3,
            x86_decode_disp32 bw0 bw1 bw2 bw3,
            x86_decode_disp32 p0 p1 p2 p3 with
      | Some checksum, Some outer, Some outer_error,
        Some inner_error, Some owner, Some owner_error, Some promoted =>
          Some
            {| residency_completion_checksum_displacement := checksum;
               residency_completion_outer_displacement := outer;
               residency_completion_expected_outer := eo0 + 256 * eo1;
               residency_completion_outer_error_delta := outer_error;
               residency_completion_expected_inner := ei0 + 256 * ei1;
               residency_completion_inner_error_delta := inner_error;
               residency_completion_owner_displacement := owner;
               residency_completion_owner_error_delta := owner_error;
               residency_completion_promoted_displacement := promoted |}
      | _, _, _, _, _, _, _ => None
      end
  | _ => None
  end.

Record residency_process_receipt : Type := {
  residency_process_return_start : nat;
  residency_process_verifier_offset : nat;
  residency_process_error_offset : nat;
  residency_process_promoted_displacement : Z;
  residency_process_checksum_displacement : Z;
  residency_process_outer_displacement : Z;
  residency_process_inner_displacement : Z;
  residency_process_owner_displacement : Z;
  residency_process_expected_outer : nat;
  residency_process_expected_inner : nat
}.

Definition residency_process_patch_candidate
    (candidate patch : list nat) (return_start : nat) : list nat :=
  firstn return_start candidate ++ patch ++
  skipn (return_start + 16) candidate.

Definition residency_process_target
    (candidate patch verifier : list nat) (return_start : nat) : list nat :=
  residency_process_patch_candidate candidate patch return_start ++ verifier.

Definition residency_completion_matches_receipt
    (receipt : residency_process_receipt)
    (completion : residency_completion_verifier) : Prop :=
  residency_completion_checksum_displacement completion =
      residency_process_checksum_displacement receipt /\
  residency_completion_outer_displacement completion =
      residency_process_outer_displacement receipt /\
  residency_completion_expected_outer completion =
      residency_process_expected_outer receipt /\
  residency_completion_expected_inner completion =
      residency_process_expected_inner receipt /\
  residency_completion_owner_displacement completion =
      residency_process_owner_displacement receipt /\
  residency_completion_promoted_displacement completion =
      residency_process_promoted_displacement receipt.

Definition residency_completion_targets_error
    (receipt : residency_process_receipt)
    (completion : residency_completion_verifier) : Prop :=
  Z.of_nat (residency_process_error_offset receipt) =
    Z.of_nat (residency_process_verifier_offset receipt + 33) +
      residency_completion_outer_error_delta completion /\
  Z.of_nat (residency_process_error_offset receipt) =
    Z.of_nat (residency_process_verifier_offset receipt + 55) +
      residency_completion_inner_error_delta completion /\
  Z.of_nat (residency_process_error_offset receipt) =
    Z.of_nat (residency_process_verifier_offset receipt + 71) +
      residency_completion_owner_error_delta completion.

Record residency_process_target_well_formed
    (candidate patch verifier process : list nat)
    (receipt : residency_process_receipt)
    (completion : residency_completion_verifier) : Prop := {
  residency_process_return_inside :
    (residency_process_return_start receipt + 16 <= length candidate)%nat;
  residency_process_verifier_follows_candidate :
    residency_process_verifier_offset receipt = length candidate;
  residency_process_candidate_return_decodes :
    residency_process_return_decode
      (residency_process_bytes_at candidate
        (residency_process_return_start receipt) 16) =
      Some (residency_process_promoted_displacement receipt,
        residency_process_checksum_displacement receipt);
  residency_process_patch_extent : length patch = 16%nat;
  residency_process_patch_jumps_to_verifier :
    residency_process_jump_decode patch =
      Some
        (Z.of_nat (residency_process_verifier_offset receipt) -
         Z.of_nat (residency_process_return_start receipt + 5));
  residency_process_verifier_extent : length verifier = 80%nat;
  residency_process_verifier_decodes :
    residency_process_verifier_decode verifier = Some completion;
  residency_process_verifier_matches :
    residency_completion_matches_receipt receipt completion;
  residency_process_verifier_error_edges :
    residency_completion_targets_error receipt completion;
  residency_process_patch_bytes :
    Forall (fun byte => (byte < 256)%nat) patch;
  residency_process_verifier_bytes :
    Forall (fun byte => (byte < 256)%nat) verifier;
  residency_process_exact_reconstruction :
    process = residency_process_target candidate patch verifier
      (residency_process_return_start receipt)
}.

Lemma residency_process_forall_firstn :
  forall (property : nat -> Prop) count bytes,
    Forall property bytes -> Forall property (firstn count bytes).
Proof.
  intros property count bytes Hbytes. revert count.
  induction Hbytes as [|byte rest Hbyte Hrest IH]; intros count.
  - destruct count; constructor.
  - destruct count as [|count]; simpl.
    + constructor.
    + constructor; [exact Hbyte | apply IH].
Qed.

Lemma residency_process_forall_skipn :
  forall (property : nat -> Prop) count bytes,
    Forall property bytes -> Forall property (skipn count bytes).
Proof.
  intros property count bytes Hbytes. revert count.
  induction Hbytes as [|byte rest Hbyte Hrest IH]; intros count.
  - destruct count; constructor.
  - destruct count as [|count]; simpl.
    + constructor; assumption.
    + apply IH.
Qed.

Lemma residency_process_patch_candidate_extent :
  forall candidate patch return_start,
    (return_start + 16 <= length candidate)%nat ->
    length patch = 16%nat ->
    length (residency_process_patch_candidate candidate patch return_start) =
      length candidate.
Proof.
  intros candidate patch return_start Hinside Hpatch.
  unfold residency_process_patch_candidate.
  repeat rewrite length_app.
  rewrite firstn_length, skipn_length, Hpatch.
  rewrite Nat.min_l by lia. lia.
Qed.

Theorem residency_process_target_extent :
  forall candidate patch verifier process receipt completion,
    residency_process_target_well_formed
      candidate patch verifier process receipt completion ->
    length process = length candidate + 80%nat.
Proof.
  intros candidate patch verifier process receipt completion Hvalid.
  destruct Hvalid as
    [Hinside Hoffset Hreturn Hpatch Hjump Hverifier Hdecode
     Hmatches Hedges Hpatch_bytes Hverifier_bytes Hprocess].
  subst process. unfold residency_process_target. rewrite length_app.
  rewrite (residency_process_patch_candidate_extent
    candidate patch (residency_process_return_start receipt)); auto.
Qed.

Lemma residency_process_skipn_length_app :
  forall (left right : list nat),
    skipn (length left) (left ++ right) = right.
Proof.
  induction left as [|head tail IH]; intros right; simpl; auto.
Qed.

Theorem residency_process_target_contains_verifier :
  forall candidate patch verifier process receipt completion,
    residency_process_target_well_formed
      candidate patch verifier process receipt completion ->
    skipn (length candidate) process = verifier.
Proof.
  intros candidate patch verifier process receipt completion Hvalid.
  destruct Hvalid as
    [Hinside Hoffset Hreturn Hpatch Hjump Hverifier Hdecode
     Hmatches Hedges Hpatch_bytes Hverifier_bytes Hprocess].
  subst process. unfold residency_process_target.
  pose proof (residency_process_patch_candidate_extent
    candidate patch (residency_process_return_start receipt)
    Hinside Hpatch) as Hextent.
  rewrite <- Hextent. apply residency_process_skipn_length_app.
Qed.

Theorem residency_process_target_bytes_are_bounded :
  forall candidate patch verifier process receipt completion,
    Forall (fun byte => (byte < 256)%nat) candidate ->
    residency_process_target_well_formed
      candidate patch verifier process receipt completion ->
    Forall (fun byte => (byte < 256)%nat) process.
Proof.
  intros candidate patch verifier process receipt completion
    Hcandidate Hvalid.
  destruct Hvalid as
    [Hinside Hoffset Hreturn Hpatch Hjump Hverifier Hdecode
     Hmatches Hedges Hpatch_bytes Hverifier_bytes Hprocess].
  subst process. unfold residency_process_target,
    residency_process_patch_candidate.
  apply Forall_app. split.
  - apply Forall_app. split.
    + now apply residency_process_forall_firstn.
    + apply Forall_app. split; auto.
      now apply residency_process_forall_skipn.
  - exact Hverifier_bytes.
Qed.
