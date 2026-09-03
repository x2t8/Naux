(**
  NauxCore.ResidencyClaimAdmission

  The formal boundary for the blocked S4-WP8P register-residency claim
  protocol.  This version admits only the protocol shape: it retains the
  static WP8O threshold evaluator, all eight gates and all four unresolved
  blockers, but has no public bundle, claim request, distinct approval, or
  admission authority.

  Only a future statement scoped to the exact host, commit, bundle,
  threshold candidate, and four sealed kernels is even potentially
  admissible.  Language-wide speedups, compiler leadership, and extrapolation
  to unmeasured workloads or platforms are unconditionally outside the
  protocol.
*)

From Stdlib Require Import List.
From NauxCore Require Import ResidencyControlledHost
  ResidencyMeasurementRunner ResidencyPairedThreshold.
Import ListNotations.

Inductive residency_claim_protocol_mode : Type :=
| ResidencyClaimProtocolStaticBlocked
| ResidencyClaimProtocolExternalAdmission.

Inductive residency_claim_class : Type :=
| ResidencyClaimExactFourKernelObservation
| ResidencyClaimLanguageWideSpeedup
| ResidencyClaimCompilerLeadership
| ResidencyClaimUnmeasuredExtrapolation.

Definition residency_claim_classes : list residency_claim_class :=
  [ ResidencyClaimExactFourKernelObservation;
    ResidencyClaimLanguageWideSpeedup;
    ResidencyClaimCompilerLeadership;
    ResidencyClaimUnmeasuredExtrapolation ].

Definition residency_claim_class_potentially_admissible
    (class : residency_claim_class) : Prop :=
  match class with
  | ResidencyClaimExactFourKernelObservation => True
  | ResidencyClaimLanguageWideSpeedup => False
  | ResidencyClaimCompilerLeadership => False
  | ResidencyClaimUnmeasuredExtrapolation => False
  end.

Inductive residency_claim_gate : Type :=
| ResidencyClaimGatePublicProtocol
| ResidencyClaimGateEligibleBundle
| ResidencyClaimGatePairedEvidence
| ResidencyClaimGatePairedThreshold
| ResidencyClaimGateExactText
| ResidencyClaimGatePublicArtifacts
| ResidencyClaimGateDistinctApproval
| ResidencyClaimGateNonSelfAdmission.

Definition residency_claim_required_gates : list residency_claim_gate :=
  [ ResidencyClaimGatePublicProtocol;
    ResidencyClaimGateEligibleBundle;
    ResidencyClaimGatePairedEvidence;
    ResidencyClaimGatePairedThreshold;
    ResidencyClaimGateExactText;
    ResidencyClaimGatePublicArtifacts;
    ResidencyClaimGateDistinctApproval;
    ResidencyClaimGateNonSelfAdmission ].

Inductive residency_claim_blocker : Type :=
| ResidencyClaimBlockerPublicProtocol
| ResidencyClaimBlockerEligibleBundle
| ResidencyClaimBlockerExactRequest
| ResidencyClaimBlockerDistinctApproval.

Definition residency_claim_required_blockers : list residency_claim_blocker :=
  [ ResidencyClaimBlockerPublicProtocol;
    ResidencyClaimBlockerEligibleBundle;
    ResidencyClaimBlockerExactRequest;
    ResidencyClaimBlockerDistinctApproval ].

Inductive residency_claim_request : Type :=
| ResidencyClaimRequestMissing
| ResidencyClaimRequestRetained
    (host_root commit_root bundle_root candidate_root text_root : list nat)
    (kernel_count : nat).

Inductive residency_claim_approval : Type :=
| ResidencyClaimApprovalMissing
| ResidencyClaimApprovalRetained
    (requester_root approver_root : list nat)
    (distinct_owner explicit_approval : bool).

Record residency_claim_protocol : Type := {
  residency_claim_parent : residency_paired_threshold_evaluator;
  residency_claim_gates : list residency_claim_gate;
  residency_claim_classes_value : list residency_claim_class;
  residency_claim_unresolved_blockers : list residency_claim_blocker;
  residency_claim_mode_value : residency_claim_protocol_mode;
  residency_claim_request_value : residency_claim_request;
  residency_claim_approval_value : residency_claim_approval;
  residency_claim_explicit_entrypoint : bool;
  residency_claim_host : residency_runner_action_authority;
  residency_claim_network : residency_runner_action_authority;
  residency_claim_clock : residency_runner_action_authority;
  residency_claim_build : residency_runner_action_authority;
  residency_claim_execution : residency_runner_action_authority;
  residency_claim_admission : residency_runner_action_authority;
  residency_claim_authority : residency_performance_claim_authority
}.

Record residency_claim_protocol_static_admitted
    (protocol : residency_claim_protocol) : Prop := {
  residency_claim_static_parent_admitted :
    residency_paired_threshold_static_admitted
      (residency_claim_parent protocol);
  residency_claim_static_gates_exact :
    residency_claim_gates protocol = residency_claim_required_gates;
  residency_claim_static_classes_exact :
    residency_claim_classes_value protocol = residency_claim_classes;
  residency_claim_static_blockers_exact :
    residency_claim_unresolved_blockers protocol =
      residency_claim_required_blockers;
  residency_claim_static_mode :
    residency_claim_mode_value protocol = ResidencyClaimProtocolStaticBlocked;
  residency_claim_static_no_request :
    residency_claim_request_value protocol = ResidencyClaimRequestMissing;
  residency_claim_static_no_approval :
    residency_claim_approval_value protocol = ResidencyClaimApprovalMissing;
  residency_claim_static_explicit_entrypoint :
    residency_claim_explicit_entrypoint protocol = false;
  residency_claim_static_host_forbidden :
    residency_claim_host protocol = ResidencyRunnerActionForbidden;
  residency_claim_static_network_forbidden :
    residency_claim_network protocol = ResidencyRunnerActionForbidden;
  residency_claim_static_clock_forbidden :
    residency_claim_clock protocol = ResidencyRunnerActionForbidden;
  residency_claim_static_build_forbidden :
    residency_claim_build protocol = ResidencyRunnerActionForbidden;
  residency_claim_static_execution_forbidden :
    residency_claim_execution protocol = ResidencyRunnerActionForbidden;
  residency_claim_static_admission_forbidden :
    residency_claim_admission protocol = ResidencyRunnerActionForbidden;
  residency_claim_static_authority_forbidden :
    residency_claim_authority protocol = ResidencyPerformanceClaimForbidden
}.

Definition residency_claim_protocol_blockers_resolved
    (protocol : residency_claim_protocol) : Prop :=
  residency_claim_unresolved_blockers protocol = [] /\
  residency_claim_mode_value protocol = ResidencyClaimProtocolExternalAdmission /\
  exists request approval,
    residency_claim_request_value protocol = request /\
    request <> ResidencyClaimRequestMissing /\
    residency_claim_approval_value protocol = approval /\
    approval <> ResidencyClaimApprovalMissing.

Theorem residency_static_claim_protocol_has_four_blockers :
  forall protocol,
    residency_claim_protocol_static_admitted protocol ->
    length (residency_claim_unresolved_blockers protocol) = 4%nat.
Proof.
  intros protocol Hadmitted.
  rewrite (residency_claim_static_blockers_exact protocol Hadmitted).
  reflexivity.
Qed.

Theorem residency_static_claim_protocol_is_not_resolved :
  forall protocol,
    residency_claim_protocol_static_admitted protocol ->
    ~ residency_claim_protocol_blockers_resolved protocol.
Proof.
  intros protocol Hadmitted [Hempty _].
  rewrite (residency_claim_static_blockers_exact protocol Hadmitted) in Hempty.
  discriminate.
Qed.

Theorem residency_static_claim_protocol_has_no_request_or_approval :
  forall protocol,
    residency_claim_protocol_static_admitted protocol ->
    residency_claim_request_value protocol = ResidencyClaimRequestMissing /\
    residency_claim_approval_value protocol = ResidencyClaimApprovalMissing.
Proof.
  intros protocol Hadmitted.
  split.
  - exact (residency_claim_static_no_request protocol Hadmitted).
  - exact (residency_claim_static_no_approval protocol Hadmitted).
Qed.

Theorem residency_static_claim_protocol_has_no_admission_authority :
  forall protocol,
    residency_claim_protocol_static_admitted protocol ->
    residency_claim_admission protocol = ResidencyRunnerActionForbidden /\
    residency_claim_authority protocol = ResidencyPerformanceClaimForbidden.
Proof.
  intros protocol Hadmitted.
  split.
  - exact (residency_claim_static_admission_forbidden protocol Hadmitted).
  - exact (residency_claim_static_authority_forbidden protocol Hadmitted).
Qed.

Theorem residency_language_wide_claim_is_forbidden :
  ~ residency_claim_class_potentially_admissible
      ResidencyClaimLanguageWideSpeedup.
Proof. simpl; intros contradiction; exact contradiction. Qed.

Theorem residency_compiler_leadership_claim_is_forbidden :
  ~ residency_claim_class_potentially_admissible
      ResidencyClaimCompilerLeadership.
Proof. simpl; intros contradiction; exact contradiction. Qed.

Theorem residency_unmeasured_extrapolation_claim_is_forbidden :
  ~ residency_claim_class_potentially_admissible
      ResidencyClaimUnmeasuredExtrapolation.
Proof. simpl; intros contradiction; exact contradiction. Qed.
