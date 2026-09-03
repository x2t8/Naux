(**
  NauxCore.ResidencyCandidateRole

  The formal boundary for the S4-WP8H untimed register-residency candidate
  role.  An admitted assignment must retain the baseline, keep timing
  forbidden, carry a non-zero artifact ordinal, decode the expected WP8G
  result record, and contain the exact proved process inside its ELF image.

  This model makes role isolation explicit.  It does not grant measurement
  authority and does not establish a performance claim.
*)

From Stdlib Require Import List Arith ZArith.
From NauxCore Require Import ResidencyResultProtocol.

Inductive residency_execution_role : Type :=
| ResidencyBaselineRole
| ResidencyRegisterCandidateRole.

Inductive residency_timing_authority : Type :=
| ResidencyTimingForbidden
| ResidencyTimingPermitted.

Record residency_role_assignment : Type := {
  residency_assignment_role : residency_execution_role;
  residency_assignment_timing : residency_timing_authority;
  residency_assignment_baseline_retained : bool;
  residency_assignment_ordinal : nat;
  residency_assignment_process : list nat;
  residency_assignment_elf : list nat;
  residency_assignment_result_bytes : list nat;
  residency_assignment_expected_result : residency_result_record
}.

Definition residency_candidate_role_admitted
    (assignment : residency_role_assignment) : Prop :=
  residency_assignment_role assignment = ResidencyRegisterCandidateRole /\
  residency_assignment_timing assignment = ResidencyTimingForbidden /\
  residency_assignment_baseline_retained assignment = true /\
  (0 < residency_assignment_ordinal assignment)%nat /\
  residency_result_ordinal
      (residency_assignment_expected_result assignment) =
    Z.of_nat (residency_assignment_ordinal assignment) /\
  residency_result_decode (residency_assignment_result_bytes assignment) =
    Some (residency_assignment_expected_result assignment) /\
  skipn 384 (residency_assignment_elf assignment) =
    residency_assignment_process assignment.

Theorem residency_candidate_role_is_not_baseline :
  forall assignment,
    residency_candidate_role_admitted assignment ->
    residency_assignment_role assignment <> ResidencyBaselineRole.
Proof.
  intros assignment Hadmitted Hbaseline.
  destruct Hadmitted as [Hcandidate _].
  rewrite Hbaseline in Hcandidate.
  discriminate.
Qed.

Theorem residency_candidate_role_has_no_timing_authority :
  forall assignment,
    residency_candidate_role_admitted assignment ->
    residency_assignment_timing assignment = ResidencyTimingForbidden.
Proof.
  intros assignment [_ [Htiming _]].
  exact Htiming.
Qed.

Theorem residency_candidate_role_retains_baseline :
  forall assignment,
    residency_candidate_role_admitted assignment ->
    residency_assignment_baseline_retained assignment = true.
Proof.
  intros assignment [_ [_ [Hbaseline _]]].
  exact Hbaseline.
Qed.

Theorem residency_candidate_role_result_is_well_formed :
  forall assignment,
    residency_candidate_role_admitted assignment ->
    residency_result_record_well_formed
      (residency_assignment_result_bytes assignment).
Proof.
  intros assignment
    [_ [_ [_ [_ [_ [Hdecode _]]]]]].
  destruct (residency_result_decode_sound
    (residency_assignment_result_bytes assignment)
    (residency_assignment_expected_result assignment)
    Hdecode) as [Hshape _].
  exact Hshape.
Qed.

