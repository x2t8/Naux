(**
  NauxCore.ResidencyPairedRunner

  The formal boundary for the static S4-WP8M same-session paired runner.  It
  retains the admitted WP8K candidate runner beside an authenticated baseline
  role, fixes an odd-AB/even-BA schedule for 120 pairs and 240 invocations,
  and requires one shared toolchain/session policy.  Its static state has no
  retained host and grants no clock, build, execution, publication, or
  performance-claim authority.

  This layer proves the protocol shape only.  It does not model a baseline
  carrier, execute either role, read a clock, establish host eligibility, or
  conclude that one role is faster than the other.
*)

From Stdlib Require Import List Arith.
From NauxCore Require Import ResidencyControlledHost ResidencyMeasurementRunner.
Import ListNotations.

Inductive residency_paired_runner_mode : Type :=
| ResidencyPairedRunnerStaticValidation
| ResidencyPairedRunnerExplicitAcquisition.

Inductive residency_paired_role : Type :=
| ResidencyPairedBaselineRole
| ResidencyPairedCandidateRole.

Inductive residency_pair_order : Type :=
| ResidencyPairAB
| ResidencyPairBA.

Inductive residency_paired_schedule : Type :=
| ResidencyPairedScheduleOddABEvenBA.

Inductive residency_paired_gate : Type :=
| ResidencyPairedGateStaticIsolation
| ResidencyPairedGateRetainedAttestation
| ResidencyPairedGateLiveReattestation
| ResidencyPairedGateCheckout
| ResidencyPairedGateToolchains
| ResidencyPairedGateArtifacts
| ResidencyPairedGateWarmup
| ResidencyPairedGateSchedule
| ResidencyPairedGateSamples
| ResidencyPairedGateParity
| ResidencyPairedGateAtomicPublication.

Definition residency_paired_required_gates : list residency_paired_gate :=
  [ ResidencyPairedGateStaticIsolation;
    ResidencyPairedGateRetainedAttestation;
    ResidencyPairedGateLiveReattestation;
    ResidencyPairedGateCheckout;
    ResidencyPairedGateToolchains;
    ResidencyPairedGateArtifacts;
    ResidencyPairedGateWarmup;
    ResidencyPairedGateSchedule;
    ResidencyPairedGateSamples;
    ResidencyPairedGateParity;
    ResidencyPairedGateAtomicPublication ].

Definition residency_paired_order_for (pair : nat) : residency_pair_order :=
  if Nat.odd pair then ResidencyPairAB else ResidencyPairBA.

Record residency_paired_measurement_runner : Type := {
  residency_paired_candidate_runner : residency_measurement_runner;
  residency_paired_roles : list residency_paired_role;
  residency_paired_baseline_retained : bool;
  residency_paired_gates : list residency_paired_gate;
  residency_paired_mode_value : residency_paired_runner_mode;
  residency_paired_host_attestation_value : residency_runner_host_attestation;
  residency_paired_explicit_entrypoint : bool;
  residency_paired_same_session : bool;
  residency_paired_same_toolchains : bool;
  residency_paired_schedule_value : residency_paired_schedule;
  residency_paired_pairs_required : nat;
  residency_paired_invocations_required : nat;
  residency_paired_build : residency_runner_action_authority;
  residency_paired_clock : residency_runner_action_authority;
  residency_paired_execution : residency_runner_action_authority;
  residency_paired_publication : residency_runner_action_authority;
  residency_paired_claim : residency_performance_claim_authority
}.

Record residency_paired_runner_static_admitted
    (runner : residency_paired_measurement_runner) : Prop := {
  residency_paired_static_candidate_admitted :
    residency_measurement_runner_static_admitted
      (residency_paired_candidate_runner runner);
  residency_paired_static_roles_exact :
    residency_paired_roles runner =
      [ResidencyPairedBaselineRole; ResidencyPairedCandidateRole];
  residency_paired_static_baseline_retained :
    residency_paired_baseline_retained runner = true;
  residency_paired_static_gates_exact :
    residency_paired_gates runner = residency_paired_required_gates;
  residency_paired_static_mode :
    residency_paired_mode_value runner =
      ResidencyPairedRunnerStaticValidation;
  residency_paired_static_no_host :
    residency_paired_host_attestation_value runner =
      ResidencyRunnerHostAttestationMissing;
  residency_paired_static_explicit_entrypoint :
    residency_paired_explicit_entrypoint runner = true;
  residency_paired_static_same_session :
    residency_paired_same_session runner = true;
  residency_paired_static_same_toolchains :
    residency_paired_same_toolchains runner = true;
  residency_paired_static_schedule_exact :
    residency_paired_schedule_value runner =
      ResidencyPairedScheduleOddABEvenBA;
  residency_paired_static_pairs_exact :
    residency_paired_pairs_required runner = 120%nat;
  residency_paired_static_invocations_exact :
    residency_paired_invocations_required runner = 240%nat;
  residency_paired_static_build_forbidden :
    residency_paired_build runner = ResidencyRunnerActionForbidden;
  residency_paired_static_clock_forbidden :
    residency_paired_clock runner = ResidencyRunnerActionForbidden;
  residency_paired_static_execution_forbidden :
    residency_paired_execution runner = ResidencyRunnerActionForbidden;
  residency_paired_static_publication_forbidden :
    residency_paired_publication runner = ResidencyRunnerActionForbidden;
  residency_paired_static_claim_forbidden :
    residency_paired_claim runner = ResidencyPerformanceClaimForbidden
}.

Record residency_paired_runner_acquisition_ready
    (runner : residency_paired_measurement_runner) : Prop := {
  residency_paired_ready_candidate_admitted :
    residency_measurement_runner_static_admitted
      (residency_paired_candidate_runner runner);
  residency_paired_ready_roles_exact :
    residency_paired_roles runner =
      [ResidencyPairedBaselineRole; ResidencyPairedCandidateRole];
  residency_paired_ready_baseline_retained :
    residency_paired_baseline_retained runner = true;
  residency_paired_ready_gates_exact :
    residency_paired_gates runner = residency_paired_required_gates;
  residency_paired_ready_mode :
    residency_paired_mode_value runner =
      ResidencyPairedRunnerExplicitAcquisition;
  residency_paired_ready_host :
    residency_runner_host_attestation_eligible
      (residency_paired_host_attestation_value runner);
  residency_paired_ready_explicit_entrypoint :
    residency_paired_explicit_entrypoint runner = true;
  residency_paired_ready_same_session :
    residency_paired_same_session runner = true;
  residency_paired_ready_same_toolchains :
    residency_paired_same_toolchains runner = true;
  residency_paired_ready_schedule_exact :
    residency_paired_schedule_value runner =
      ResidencyPairedScheduleOddABEvenBA;
  residency_paired_ready_pairs_exact :
    residency_paired_pairs_required runner = 120%nat;
  residency_paired_ready_invocations_exact :
    residency_paired_invocations_required runner = 240%nat;
  residency_paired_ready_build_permitted :
    residency_paired_build runner = ResidencyRunnerActionPermitted;
  residency_paired_ready_clock_permitted :
    residency_paired_clock runner = ResidencyRunnerActionPermitted;
  residency_paired_ready_execution_permitted :
    residency_paired_execution runner = ResidencyRunnerActionPermitted;
  residency_paired_ready_publication_permitted :
    residency_paired_publication runner = ResidencyRunnerActionPermitted;
  residency_paired_ready_claim_forbidden :
    residency_paired_claim runner = ResidencyPerformanceClaimForbidden
}.

Theorem residency_paired_schedule_starts_ab_then_ba :
  residency_paired_order_for 1 = ResidencyPairAB /\
  residency_paired_order_for 2 = ResidencyPairBA.
Proof.
  split; reflexivity.
Qed.

Theorem residency_static_paired_runner_has_exact_roles :
  forall runner,
    residency_paired_runner_static_admitted runner ->
    residency_paired_roles runner =
      [ResidencyPairedBaselineRole; ResidencyPairedCandidateRole].
Proof.
  intros runner Hadmitted.
  exact (residency_paired_static_roles_exact runner Hadmitted).
Qed.

Theorem residency_static_paired_runner_invocations_are_two_per_pair :
  forall runner,
    residency_paired_runner_static_admitted runner ->
    (2 * residency_paired_pairs_required runner)%nat =
      residency_paired_invocations_required runner.
Proof.
  intros runner Hadmitted.
  rewrite (residency_paired_static_pairs_exact runner Hadmitted).
  rewrite (residency_paired_static_invocations_exact runner Hadmitted).
  reflexivity.
Qed.

Theorem residency_static_paired_runner_has_no_host :
  forall runner,
    residency_paired_runner_static_admitted runner ->
    residency_paired_host_attestation_value runner =
      ResidencyRunnerHostAttestationMissing.
Proof.
  intros runner Hadmitted.
  exact (residency_paired_static_no_host runner Hadmitted).
Qed.

Theorem residency_static_paired_runner_has_no_execution_authority :
  forall runner,
    residency_paired_runner_static_admitted runner ->
    residency_paired_execution runner = ResidencyRunnerActionForbidden.
Proof.
  intros runner Hadmitted.
  exact (residency_paired_static_execution_forbidden runner Hadmitted).
Qed.

Theorem residency_static_paired_runner_has_no_performance_claim :
  forall runner,
    residency_paired_runner_static_admitted runner ->
    residency_paired_claim runner = ResidencyPerformanceClaimForbidden.
Proof.
  intros runner Hadmitted.
  exact (residency_paired_static_claim_forbidden runner Hadmitted).
Qed.

Theorem residency_static_paired_runner_is_not_acquisition_ready :
  forall runner,
    residency_paired_runner_static_admitted runner ->
    ~ residency_paired_runner_acquisition_ready runner.
Proof.
  intros runner Hstatic Hready.
  pose proof (residency_paired_static_mode runner Hstatic) as Hstatic_mode.
  pose proof (residency_paired_ready_mode runner Hready) as Hready_mode.
  rewrite Hstatic_mode in Hready_mode.
  discriminate.
Qed.

Theorem residency_ready_paired_runner_cannot_self_admit_claim :
  forall runner,
    residency_paired_runner_acquisition_ready runner ->
    residency_paired_claim runner = ResidencyPerformanceClaimForbidden.
Proof.
  intros runner Hready.
  exact (residency_paired_ready_claim_forbidden runner Hready).
Qed.
