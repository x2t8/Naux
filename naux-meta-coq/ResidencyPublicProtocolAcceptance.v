(**
  NauxCore.ResidencyPublicProtocolAcceptance

  The formal boundary for the S4-WP8Q public-protocol receipt.  A receipt may
  close only the first WP8P blocker by retaining one exact source commit and
  three successful public workflow identities.  It cannot manufacture a
  measurement bundle, claim request, distinct approval, admission action, or
  performance claim.
*)

From Stdlib Require Import List.
From NauxCore Require Import ResidencyControlledHost
  ResidencyMeasurementRunner ResidencyClaimAdmission.
Import ListNotations.

Inductive residency_public_protocol_mode : Type :=
| ResidencyPublicProtocolStaticReviewed
| ResidencyPublicProtocolDynamicAcquisition.

Definition residency_public_protocol_remaining_blockers :
    list residency_claim_blocker :=
  [ ResidencyClaimBlockerEligibleBundle;
    ResidencyClaimBlockerExactRequest;
    ResidencyClaimBlockerDistinctApproval ].

Record residency_public_protocol_receipt : Type := {
  residency_public_protocol_parent : residency_claim_protocol;
  residency_public_protocol_commit : list nat;
  residency_public_protocol_ci_run : list nat;
  residency_public_protocol_formal_model_run : list nat;
  residency_public_protocol_formal_bridge_run : list nat;
  residency_public_protocol_ci_commit : list nat;
  residency_public_protocol_formal_model_commit : list nat;
  residency_public_protocol_formal_bridge_commit : list nat;
  residency_public_protocol_ci_success : bool;
  residency_public_protocol_formal_model_success : bool;
  residency_public_protocol_formal_bridge_success : bool;
  residency_public_protocol_public_records : bool;
  residency_public_protocol_mode_value : residency_public_protocol_mode;
  residency_public_protocol_unresolved_blockers :
    list residency_claim_blocker;
  residency_public_protocol_request : residency_claim_request;
  residency_public_protocol_approval : residency_claim_approval;
  residency_public_protocol_network : residency_runner_action_authority;
  residency_public_protocol_clock : residency_runner_action_authority;
  residency_public_protocol_build : residency_runner_action_authority;
  residency_public_protocol_execution : residency_runner_action_authority;
  residency_public_protocol_admission : residency_runner_action_authority;
  residency_public_protocol_claim_authority :
    residency_performance_claim_authority
}.

Record residency_public_protocol_receipt_admitted
    (receipt : residency_public_protocol_receipt) : Prop := {
  residency_public_protocol_parent_admitted :
    residency_claim_protocol_static_admitted
      (residency_public_protocol_parent receipt);
  residency_public_protocol_commit_is_sha1 :
    length (residency_public_protocol_commit receipt) = 20%nat;
  residency_public_protocol_ci_run_nonempty :
    residency_public_protocol_ci_run receipt <> [];
  residency_public_protocol_formal_model_run_nonempty :
    residency_public_protocol_formal_model_run receipt <> [];
  residency_public_protocol_formal_bridge_run_nonempty :
    residency_public_protocol_formal_bridge_run receipt <> [];
  residency_public_protocol_ci_commit_exact :
    residency_public_protocol_ci_commit receipt =
      residency_public_protocol_commit receipt;
  residency_public_protocol_formal_model_commit_exact :
    residency_public_protocol_formal_model_commit receipt =
      residency_public_protocol_commit receipt;
  residency_public_protocol_formal_bridge_commit_exact :
    residency_public_protocol_formal_bridge_commit receipt =
      residency_public_protocol_commit receipt;
  residency_public_protocol_ci_success_exact :
    residency_public_protocol_ci_success receipt = true;
  residency_public_protocol_formal_model_success_exact :
    residency_public_protocol_formal_model_success receipt = true;
  residency_public_protocol_formal_bridge_success_exact :
    residency_public_protocol_formal_bridge_success receipt = true;
  residency_public_protocol_records_are_public :
    residency_public_protocol_public_records receipt = true;
  residency_public_protocol_static_review :
    residency_public_protocol_mode_value receipt =
      ResidencyPublicProtocolStaticReviewed;
  residency_public_protocol_blockers_exact :
    residency_public_protocol_unresolved_blockers receipt =
      residency_public_protocol_remaining_blockers;
  residency_public_protocol_no_request :
    residency_public_protocol_request receipt = ResidencyClaimRequestMissing;
  residency_public_protocol_no_approval :
    residency_public_protocol_approval receipt = ResidencyClaimApprovalMissing;
  residency_public_protocol_network_forbidden :
    residency_public_protocol_network receipt = ResidencyRunnerActionForbidden;
  residency_public_protocol_clock_forbidden :
    residency_public_protocol_clock receipt = ResidencyRunnerActionForbidden;
  residency_public_protocol_build_forbidden :
    residency_public_protocol_build receipt = ResidencyRunnerActionForbidden;
  residency_public_protocol_execution_forbidden :
    residency_public_protocol_execution receipt = ResidencyRunnerActionForbidden;
  residency_public_protocol_admission_forbidden :
    residency_public_protocol_admission receipt = ResidencyRunnerActionForbidden;
  residency_public_protocol_claim_forbidden :
    residency_public_protocol_claim_authority receipt =
      ResidencyPerformanceClaimForbidden
}.

Definition residency_public_protocol_gate_closed
    (receipt : residency_public_protocol_receipt) : Prop :=
  length (residency_public_protocol_commit receipt) = 20%nat /\
  residency_public_protocol_ci_run receipt <> [] /\
  residency_public_protocol_formal_model_run receipt <> [] /\
  residency_public_protocol_formal_bridge_run receipt <> [] /\
  residency_public_protocol_ci_commit receipt =
    residency_public_protocol_commit receipt /\
  residency_public_protocol_formal_model_commit receipt =
    residency_public_protocol_commit receipt /\
  residency_public_protocol_formal_bridge_commit receipt =
    residency_public_protocol_commit receipt /\
  residency_public_protocol_ci_success receipt = true /\
  residency_public_protocol_formal_model_success receipt = true /\
  residency_public_protocol_formal_bridge_success receipt = true /\
  residency_public_protocol_public_records receipt = true.

Definition residency_public_protocol_claim_ready
    (receipt : residency_public_protocol_receipt) : Prop :=
  residency_public_protocol_unresolved_blockers receipt = [] /\
  residency_public_protocol_request receipt <> ResidencyClaimRequestMissing /\
  residency_public_protocol_approval receipt <> ResidencyClaimApprovalMissing /\
  residency_public_protocol_admission receipt = ResidencyRunnerActionPermitted /\
  residency_public_protocol_claim_authority receipt =
    ResidencyPerformanceClaimPermitted.

Theorem residency_public_protocol_admission_closes_public_gate :
  forall receipt,
    residency_public_protocol_receipt_admitted receipt ->
    residency_public_protocol_gate_closed receipt.
Proof.
  intros receipt Hadmitted.
  repeat split.
  - exact (residency_public_protocol_commit_is_sha1 receipt Hadmitted).
  - exact (residency_public_protocol_ci_run_nonempty receipt Hadmitted).
  - exact (residency_public_protocol_formal_model_run_nonempty receipt Hadmitted).
  - exact (residency_public_protocol_formal_bridge_run_nonempty receipt Hadmitted).
  - exact (residency_public_protocol_ci_commit_exact receipt Hadmitted).
  - exact (residency_public_protocol_formal_model_commit_exact receipt Hadmitted).
  - exact (residency_public_protocol_formal_bridge_commit_exact receipt Hadmitted).
  - exact (residency_public_protocol_ci_success_exact receipt Hadmitted).
  - exact (residency_public_protocol_formal_model_success_exact receipt Hadmitted).
  - exact (residency_public_protocol_formal_bridge_success_exact receipt Hadmitted).
  - exact (residency_public_protocol_records_are_public receipt Hadmitted).
Qed.

Theorem residency_public_protocol_admission_retains_three_blockers :
  forall receipt,
    residency_public_protocol_receipt_admitted receipt ->
    length (residency_public_protocol_unresolved_blockers receipt) = 3%nat.
Proof.
  intros receipt Hadmitted.
  rewrite (residency_public_protocol_blockers_exact receipt Hadmitted).
  reflexivity.
Qed.

Theorem residency_public_protocol_admission_removes_only_public_blocker :
  forall receipt,
    residency_public_protocol_receipt_admitted receipt ->
    ~ In ResidencyClaimBlockerPublicProtocol
        (residency_public_protocol_unresolved_blockers receipt) /\
    In ResidencyClaimBlockerEligibleBundle
      (residency_public_protocol_unresolved_blockers receipt) /\
    In ResidencyClaimBlockerExactRequest
      (residency_public_protocol_unresolved_blockers receipt) /\
    In ResidencyClaimBlockerDistinctApproval
      (residency_public_protocol_unresolved_blockers receipt).
Proof.
  intros receipt Hadmitted.
  rewrite (residency_public_protocol_blockers_exact receipt Hadmitted).
  simpl; intuition discriminate.
Qed.

Theorem residency_public_protocol_admission_has_no_claim_path :
  forall receipt,
    residency_public_protocol_receipt_admitted receipt ->
    ~ residency_public_protocol_claim_ready receipt.
Proof.
  intros receipt Hadmitted [Hempty _].
  rewrite (residency_public_protocol_blockers_exact receipt Hadmitted) in Hempty.
  discriminate.
Qed.

Theorem residency_public_protocol_admission_preserves_no_request_or_approval :
  forall receipt,
    residency_public_protocol_receipt_admitted receipt ->
    residency_public_protocol_request receipt = ResidencyClaimRequestMissing /\
    residency_public_protocol_approval receipt = ResidencyClaimApprovalMissing.
Proof.
  intros receipt Hadmitted.
  split.
  - exact (residency_public_protocol_no_request receipt Hadmitted).
  - exact (residency_public_protocol_no_approval receipt Hadmitted).
Qed.

Theorem residency_public_protocol_admission_preserves_no_claim_authority :
  forall receipt,
    residency_public_protocol_receipt_admitted receipt ->
    residency_public_protocol_admission receipt = ResidencyRunnerActionForbidden /\
    residency_public_protocol_claim_authority receipt =
      ResidencyPerformanceClaimForbidden.
Proof.
  intros receipt Hadmitted.
  split.
  - exact (residency_public_protocol_admission_forbidden receipt Hadmitted).
  - exact (residency_public_protocol_claim_forbidden receipt Hadmitted).
Qed.
