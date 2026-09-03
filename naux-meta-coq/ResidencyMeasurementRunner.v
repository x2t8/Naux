(**
  NauxCore.ResidencyMeasurementRunner

  The formal boundary for the static S4-WP8K candidate measurement runner.
  The admitted object contains exactly four already-admitted WP8J carriers and
  the complete ten-gate acquisition policy, but its default state has no
  retained host attestation and grants no clock, build, execution, publication,
  or performance-claim authority.

  This layer proves properties of the static runner admission only.  It does
  not model a live host, execute a carrier, interpret a clock, or establish any
  measurement result.
*)

From Stdlib Require Import List.
From NauxCore Require Import ResidencyControlledHost ResidencyTimingCarrier.
Import ListNotations.

Inductive residency_runner_mode : Type :=
| ResidencyRunnerStaticValidation
| ResidencyRunnerExplicitAcquisition.

Inductive residency_runner_action_authority : Type :=
| ResidencyRunnerActionForbidden
| ResidencyRunnerActionPermitted.

Inductive residency_runner_host_attestation : Type :=
| ResidencyRunnerHostAttestationMissing
| ResidencyRunnerHostAttestationRetained
    (fingerprint : list nat) (eligible : bool).

Inductive residency_runner_gate : Type :=
| ResidencyRunnerGateStaticIsolation
| ResidencyRunnerGateRetainedAttestation
| ResidencyRunnerGateLiveReattestation
| ResidencyRunnerGateCheckout
| ResidencyRunnerGateToolchains
| ResidencyRunnerGateArtifacts
| ResidencyRunnerGateWarmup
| ResidencyRunnerGateSamples
| ResidencyRunnerGateParity
| ResidencyRunnerGateAtomicPublication.

Definition residency_runner_required_gates : list residency_runner_gate :=
  [ ResidencyRunnerGateStaticIsolation;
    ResidencyRunnerGateRetainedAttestation;
    ResidencyRunnerGateLiveReattestation;
    ResidencyRunnerGateCheckout;
    ResidencyRunnerGateToolchains;
    ResidencyRunnerGateArtifacts;
    ResidencyRunnerGateWarmup;
    ResidencyRunnerGateSamples;
    ResidencyRunnerGateParity;
    ResidencyRunnerGateAtomicPublication ].

Definition residency_runner_host_attestation_eligible
    (attestation : residency_runner_host_attestation) : Prop :=
  exists fingerprint,
    attestation = ResidencyRunnerHostAttestationRetained fingerprint true /\
    residency_host_fingerprint_well_formed fingerprint.

Record residency_measurement_runner : Type := {
  residency_runner_carriers : list residency_timing_carrier;
  residency_runner_gates : list residency_runner_gate;
  residency_runner_mode_value : residency_runner_mode;
  residency_runner_host_attestation_value : residency_runner_host_attestation;
  residency_runner_explicit_entrypoint : bool;
  residency_runner_samples_required : nat;
  residency_runner_clock : residency_runner_action_authority;
  residency_runner_build : residency_runner_action_authority;
  residency_runner_execution : residency_runner_action_authority;
  residency_runner_publication : residency_runner_action_authority;
  residency_runner_claim : residency_performance_claim_authority
}.

Definition residency_measurement_runner_static_admitted
    (runner : residency_measurement_runner) : Prop :=
  length (residency_runner_carriers runner) = 4%nat /\
  Forall residency_timing_carrier_admitted
    (residency_runner_carriers runner) /\
  residency_runner_gates runner = residency_runner_required_gates /\
  residency_runner_mode_value runner = ResidencyRunnerStaticValidation /\
  residency_runner_host_attestation_value runner =
    ResidencyRunnerHostAttestationMissing /\
  residency_runner_explicit_entrypoint runner = true /\
  residency_runner_samples_required runner = 120%nat /\
  residency_runner_clock runner = ResidencyRunnerActionForbidden /\
  residency_runner_build runner = ResidencyRunnerActionForbidden /\
  residency_runner_execution runner = ResidencyRunnerActionForbidden /\
  residency_runner_publication runner = ResidencyRunnerActionForbidden /\
  residency_runner_claim runner = ResidencyPerformanceClaimForbidden.

Definition residency_measurement_runner_acquisition_ready
    (runner : residency_measurement_runner) : Prop :=
  length (residency_runner_carriers runner) = 4%nat /\
  Forall residency_timing_carrier_admitted
    (residency_runner_carriers runner) /\
  residency_runner_gates runner = residency_runner_required_gates /\
  residency_runner_mode_value runner = ResidencyRunnerExplicitAcquisition /\
  residency_runner_host_attestation_eligible
    (residency_runner_host_attestation_value runner) /\
  residency_runner_clock runner = ResidencyRunnerActionPermitted /\
  residency_runner_build runner = ResidencyRunnerActionPermitted /\
  residency_runner_execution runner = ResidencyRunnerActionPermitted /\
  residency_runner_publication runner = ResidencyRunnerActionPermitted /\
  residency_runner_claim runner = ResidencyPerformanceClaimForbidden.

Theorem residency_static_runner_has_exactly_four_carriers :
  forall runner,
    residency_measurement_runner_static_admitted runner ->
    length (residency_runner_carriers runner) = 4%nat.
Proof.
  intros runner [Hcarriers _].
  exact Hcarriers.
Qed.

Theorem residency_static_runner_has_complete_gate_policy :
  forall runner,
    residency_measurement_runner_static_admitted runner ->
    residency_runner_gates runner = residency_runner_required_gates.
Proof.
  intros runner [_ [_ [Hgates _]]].
  exact Hgates.
Qed.

Theorem residency_static_runner_has_no_retained_host :
  forall runner,
    residency_measurement_runner_static_admitted runner ->
    residency_runner_host_attestation_value runner =
      ResidencyRunnerHostAttestationMissing.
Proof.
  intros runner [_ [_ [_ [_ [Hhost _]]]]].
  exact Hhost.
Qed.

Theorem residency_static_runner_has_no_execution_authority :
  forall runner,
    residency_measurement_runner_static_admitted runner ->
    residency_runner_execution runner = ResidencyRunnerActionForbidden.
Proof.
  intros runner
    [_ [_ [_ [_ [_ [_ [_ [_ [_ [Hexecution _]]]]]]]]]].
  exact Hexecution.
Qed.

Theorem residency_static_runner_has_no_publication_authority :
  forall runner,
    residency_measurement_runner_static_admitted runner ->
    residency_runner_publication runner = ResidencyRunnerActionForbidden.
Proof.
  intros runner
    [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [Hpublication _]]]]]]]]]]].
  exact Hpublication.
Qed.

Theorem residency_static_runner_has_no_performance_claim :
  forall runner,
    residency_measurement_runner_static_admitted runner ->
    residency_runner_claim runner = ResidencyPerformanceClaimForbidden.
Proof.
  intros runner
    [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ Hclaim]]]]]]]]]]].
  exact Hclaim.
Qed.

Theorem residency_static_runner_is_not_acquisition_ready :
  forall runner,
    residency_measurement_runner_static_admitted runner ->
    ~ residency_measurement_runner_acquisition_ready runner.
Proof.
  intros runner Hstatic Hready.
  destruct Hstatic as [_ [_ [_ [Hstatic_mode _]]]].
  destruct Hready as [_ [_ [_ [Hacquire_mode _]]]].
  rewrite Hstatic_mode in Hacquire_mode.
  discriminate.
Qed.

Theorem residency_static_runner_carriers_remain_non_runnable :
  forall runner,
    residency_measurement_runner_static_admitted runner ->
    Forall (fun carrier => ~ residency_timing_carrier_runnable carrier)
      (residency_runner_carriers runner).
Proof.
  intros runner [_ [Hcarriers _]].
  induction Hcarriers as [|carrier remaining Hadmitted Hremaining IH].
  - constructor.
  - constructor.
    + exact (residency_timing_carrier_is_not_runnable carrier Hadmitted).
    + exact IH.
Qed.
