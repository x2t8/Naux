(**
  NauxCore.ResidencyPublicBundle

  The formal boundary for the static S4-WP8R public-bundle authority.  The
  static object retains the admitted WP8Q public-protocol receipt and WP8N
  paired-evidence replay, but contains no archive and no public-reachability
  observation.  Local packaging or offline intake cannot manufacture a public
  bundle, claim request, release approval, admission action, or performance
  claim.
*)

From Stdlib Require Import List.
From NauxCore Require Import ResidencyControlledHost
  ResidencyMeasurementRunner ResidencyPairedEvidenceReplay
  ResidencyClaimAdmission ResidencyPublicProtocolAcceptance.
Import ListNotations.

Inductive residency_public_bundle_mode : Type :=
| ResidencyPublicBundleStaticValidation
| ResidencyPublicBundleLocalPackaging
| ResidencyPublicBundleReadOnlyIntake.

Inductive residency_public_bundle_archive : Type :=
| ResidencyPublicBundleArchiveMissing
| ResidencyPublicBundleArchiveVerified
    (archive_root bundle_root session_root host_root evidence_root : list nat).

Inductive residency_public_bundle_reachability : Type :=
| ResidencyPublicBundleReachabilityNotObserved
| ResidencyPublicBundleReachabilityConfirmed.

Record residency_public_bundle_authority : Type := {
  residency_public_bundle_protocol_parent : residency_public_protocol_receipt;
  residency_public_bundle_evidence_parent : residency_paired_evidence_replay;
  residency_public_bundle_tracked_commit : list nat;
  residency_public_bundle_mode_value : residency_public_bundle_mode;
  residency_public_bundle_archive_value : residency_public_bundle_archive;
  residency_public_bundle_reachability_value :
    residency_public_bundle_reachability;
  residency_public_bundle_unresolved_blockers : list residency_claim_blocker;
  residency_public_bundle_package_action : residency_runner_action_authority;
  residency_public_bundle_intake_action : residency_runner_action_authority;
  residency_public_bundle_network : residency_runner_action_authority;
  residency_public_bundle_clock : residency_runner_action_authority;
  residency_public_bundle_build : residency_runner_action_authority;
  residency_public_bundle_execution : residency_runner_action_authority;
  residency_public_bundle_publication : residency_runner_action_authority;
  residency_public_bundle_admission : residency_runner_action_authority;
  residency_public_bundle_claim_authority :
    residency_performance_claim_authority
}.

Record residency_public_bundle_static_admitted
    (authority : residency_public_bundle_authority) : Prop := {
  residency_public_bundle_protocol_parent_admitted :
    residency_public_protocol_receipt_admitted
      (residency_public_bundle_protocol_parent authority);
  residency_public_bundle_evidence_parent_admitted :
    residency_paired_evidence_static_admitted
      (residency_public_bundle_evidence_parent authority);
  residency_public_bundle_commit_exact :
    residency_public_bundle_tracked_commit authority =
      residency_public_protocol_commit
        (residency_public_bundle_protocol_parent authority);
  residency_public_bundle_static_mode :
    residency_public_bundle_mode_value authority =
      ResidencyPublicBundleStaticValidation;
  residency_public_bundle_static_no_archive :
    residency_public_bundle_archive_value authority =
      ResidencyPublicBundleArchiveMissing;
  residency_public_bundle_static_reachability_unobserved :
    residency_public_bundle_reachability_value authority =
      ResidencyPublicBundleReachabilityNotObserved;
  residency_public_bundle_static_blockers_exact :
    residency_public_bundle_unresolved_blockers authority =
      residency_public_protocol_remaining_blockers;
  residency_public_bundle_static_package_forbidden :
    residency_public_bundle_package_action authority =
      ResidencyRunnerActionForbidden;
  residency_public_bundle_static_intake_forbidden :
    residency_public_bundle_intake_action authority =
      ResidencyRunnerActionForbidden;
  residency_public_bundle_static_network_forbidden :
    residency_public_bundle_network authority = ResidencyRunnerActionForbidden;
  residency_public_bundle_static_clock_forbidden :
    residency_public_bundle_clock authority = ResidencyRunnerActionForbidden;
  residency_public_bundle_static_build_forbidden :
    residency_public_bundle_build authority = ResidencyRunnerActionForbidden;
  residency_public_bundle_static_execution_forbidden :
    residency_public_bundle_execution authority =
      ResidencyRunnerActionForbidden;
  residency_public_bundle_static_publication_forbidden :
    residency_public_bundle_publication authority =
      ResidencyRunnerActionForbidden;
  residency_public_bundle_static_admission_forbidden :
    residency_public_bundle_admission authority =
      ResidencyRunnerActionForbidden;
  residency_public_bundle_static_claim_forbidden :
    residency_public_bundle_claim_authority authority =
      ResidencyPerformanceClaimForbidden
}.

Definition residency_public_bundle_claim_ready
    (authority : residency_public_bundle_authority) : Prop :=
  residency_public_bundle_archive_value authority <>
    ResidencyPublicBundleArchiveMissing /\
  residency_public_bundle_reachability_value authority =
    ResidencyPublicBundleReachabilityConfirmed /\
  residency_public_bundle_unresolved_blockers authority = [] /\
  residency_public_bundle_admission authority = ResidencyRunnerActionPermitted /\
  residency_public_bundle_claim_authority authority =
    ResidencyPerformanceClaimPermitted.

Theorem residency_static_public_bundle_has_no_archive_or_reachability :
  forall authority,
    residency_public_bundle_static_admitted authority ->
    residency_public_bundle_archive_value authority =
      ResidencyPublicBundleArchiveMissing /\
    residency_public_bundle_reachability_value authority =
      ResidencyPublicBundleReachabilityNotObserved.
Proof.
  intros authority Hadmitted.
  split.
  - exact (residency_public_bundle_static_no_archive authority Hadmitted).
  - exact (residency_public_bundle_static_reachability_unobserved
      authority Hadmitted).
Qed.

Theorem residency_static_public_bundle_retains_three_blockers :
  forall authority,
    residency_public_bundle_static_admitted authority ->
    length (residency_public_bundle_unresolved_blockers authority) = 3%nat.
Proof.
  intros authority Hadmitted.
  rewrite (residency_public_bundle_static_blockers_exact authority Hadmitted).
  reflexivity.
Qed.

Theorem residency_static_public_bundle_retains_eligible_bundle_blocker :
  forall authority,
    residency_public_bundle_static_admitted authority ->
    In ResidencyClaimBlockerEligibleBundle
      (residency_public_bundle_unresolved_blockers authority).
Proof.
  intros authority Hadmitted.
  rewrite (residency_public_bundle_static_blockers_exact authority Hadmitted).
  simpl; auto.
Qed.

Theorem residency_static_public_bundle_has_no_claim_path :
  forall authority,
    residency_public_bundle_static_admitted authority ->
    ~ residency_public_bundle_claim_ready authority.
Proof.
  intros authority Hadmitted [_ [_ [Hempty _]]].
  rewrite (residency_public_bundle_static_blockers_exact authority Hadmitted)
    in Hempty.
  discriminate.
Qed.

Theorem residency_static_public_bundle_has_no_package_or_intake_authority :
  forall authority,
    residency_public_bundle_static_admitted authority ->
    residency_public_bundle_package_action authority =
      ResidencyRunnerActionForbidden /\
    residency_public_bundle_intake_action authority =
      ResidencyRunnerActionForbidden.
Proof.
  intros authority Hadmitted.
  split.
  - exact (residency_public_bundle_static_package_forbidden
      authority Hadmitted).
  - exact (residency_public_bundle_static_intake_forbidden
      authority Hadmitted).
Qed.

Theorem residency_static_public_bundle_has_no_external_or_claim_authority :
  forall authority,
    residency_public_bundle_static_admitted authority ->
    residency_public_bundle_network authority = ResidencyRunnerActionForbidden /\
    residency_public_bundle_clock authority = ResidencyRunnerActionForbidden /\
    residency_public_bundle_build authority = ResidencyRunnerActionForbidden /\
    residency_public_bundle_execution authority =
      ResidencyRunnerActionForbidden /\
    residency_public_bundle_publication authority =
      ResidencyRunnerActionForbidden /\
    residency_public_bundle_admission authority =
      ResidencyRunnerActionForbidden /\
    residency_public_bundle_claim_authority authority =
      ResidencyPerformanceClaimForbidden.
Proof.
  intros authority Hadmitted.
  repeat split.
  - exact (residency_public_bundle_static_network_forbidden authority Hadmitted).
  - exact (residency_public_bundle_static_clock_forbidden authority Hadmitted).
  - exact (residency_public_bundle_static_build_forbidden authority Hadmitted).
  - exact (residency_public_bundle_static_execution_forbidden authority Hadmitted).
  - exact (residency_public_bundle_static_publication_forbidden authority Hadmitted).
  - exact (residency_public_bundle_static_admission_forbidden authority Hadmitted).
  - exact (residency_public_bundle_static_claim_forbidden authority Hadmitted).
Qed.
