(**
  NauxCore.ResidencyEvidenceReplay

  The formal boundary for the static S4-WP8L candidate-evidence replay.
  The admitted object binds the already-admitted WP8K runner to the complete
  ten-gate, read-only replay policy, but contains no raw bundle and grants no
  replay, live-host, clock, build, execution, mutation, or performance-claim
  authority.

  This layer proves properties of the static replay admission only.  It does
  not inspect a bundle, validate elapsed-time observations, calculate a
  benchmark result, or compare the candidate with a baseline.
*)

From Stdlib Require Import List.
From NauxCore Require Import ResidencyControlledHost ResidencyMeasurementRunner.
Import ListNotations.

Inductive residency_evidence_replay_mode : Type :=
| ResidencyEvidenceReplayStaticValidation
| ResidencyEvidenceReplayExplicitReadOnly.

Inductive residency_evidence_bundle : Type :=
| ResidencyEvidenceBundleMissing
| ResidencyEvidenceBundleRetained
    (root : list nat)
    (payload_files kernels samples : nat)
    (eligible_host_attestation : bool).

Inductive residency_evidence_gate : Type :=
| ResidencyEvidenceGateStaticIsolation
| ResidencyEvidenceGateBundleRoot
| ResidencyEvidenceGateHostAttestation
| ResidencyEvidenceGateSessionRoot
| ResidencyEvidenceGateArtifactIdentity
| ResidencyEvidenceGateToolchainIdentity
| ResidencyEvidenceGateResultParity
| ResidencyEvidenceGateReproduction
| ResidencyEvidenceGateStatistics
| ResidencyEvidenceGateClaimBoundary.

Definition residency_evidence_required_gates : list residency_evidence_gate :=
  [ ResidencyEvidenceGateStaticIsolation;
    ResidencyEvidenceGateBundleRoot;
    ResidencyEvidenceGateHostAttestation;
    ResidencyEvidenceGateSessionRoot;
    ResidencyEvidenceGateArtifactIdentity;
    ResidencyEvidenceGateToolchainIdentity;
    ResidencyEvidenceGateResultParity;
    ResidencyEvidenceGateReproduction;
    ResidencyEvidenceGateStatistics;
    ResidencyEvidenceGateClaimBoundary ].

Definition residency_evidence_digest_well_formed
    (digest : list nat) : Prop :=
  length digest = 32%nat /\
  Forall (fun byte => (byte < 256)%nat) digest.

Definition residency_evidence_bundle_eligible
    (bundle : residency_evidence_bundle) : Prop :=
  exists root,
    bundle = ResidencyEvidenceBundleRetained root 8 4 120 true /\
    residency_evidence_digest_well_formed root.

Record residency_evidence_replay : Type := {
  residency_evidence_runner : residency_measurement_runner;
  residency_evidence_gates : list residency_evidence_gate;
  residency_evidence_mode_value : residency_evidence_replay_mode;
  residency_evidence_bundle_value : residency_evidence_bundle;
  residency_evidence_explicit_entrypoint : bool;
  residency_evidence_payload_files_required : nat;
  residency_evidence_kernels_required : nat;
  residency_evidence_samples_per_kernel : nat;
  residency_evidence_samples_required : nat;
  residency_evidence_replay_action : residency_runner_action_authority;
  residency_evidence_live_host : residency_runner_action_authority;
  residency_evidence_clock : residency_runner_action_authority;
  residency_evidence_build : residency_runner_action_authority;
  residency_evidence_execution : residency_runner_action_authority;
  residency_evidence_mutation : residency_runner_action_authority;
  residency_evidence_claim : residency_performance_claim_authority
}.

Definition residency_evidence_replay_static_admitted
    (replay : residency_evidence_replay) : Prop :=
  residency_measurement_runner_static_admitted
    (residency_evidence_runner replay) /\
  residency_evidence_gates replay = residency_evidence_required_gates /\
  residency_evidence_mode_value replay =
    ResidencyEvidenceReplayStaticValidation /\
  residency_evidence_bundle_value replay = ResidencyEvidenceBundleMissing /\
  residency_evidence_explicit_entrypoint replay = true /\
  residency_evidence_payload_files_required replay = 8%nat /\
  residency_evidence_kernels_required replay = 4%nat /\
  residency_evidence_samples_per_kernel replay = 30%nat /\
  residency_evidence_samples_required replay = 120%nat /\
  residency_evidence_replay_action replay = ResidencyRunnerActionForbidden /\
  residency_evidence_live_host replay = ResidencyRunnerActionForbidden /\
  residency_evidence_clock replay = ResidencyRunnerActionForbidden /\
  residency_evidence_build replay = ResidencyRunnerActionForbidden /\
  residency_evidence_execution replay = ResidencyRunnerActionForbidden /\
  residency_evidence_mutation replay = ResidencyRunnerActionForbidden /\
  residency_evidence_claim replay = ResidencyPerformanceClaimForbidden.

Definition residency_evidence_replay_ready
    (replay : residency_evidence_replay) : Prop :=
  residency_measurement_runner_static_admitted
    (residency_evidence_runner replay) /\
  residency_evidence_gates replay = residency_evidence_required_gates /\
  residency_evidence_mode_value replay =
    ResidencyEvidenceReplayExplicitReadOnly /\
  residency_evidence_bundle_eligible
    (residency_evidence_bundle_value replay) /\
  residency_evidence_explicit_entrypoint replay = true /\
  residency_evidence_payload_files_required replay = 8%nat /\
  residency_evidence_kernels_required replay = 4%nat /\
  residency_evidence_samples_per_kernel replay = 30%nat /\
  residency_evidence_samples_required replay = 120%nat /\
  residency_evidence_replay_action replay = ResidencyRunnerActionPermitted /\
  residency_evidence_live_host replay = ResidencyRunnerActionForbidden /\
  residency_evidence_clock replay = ResidencyRunnerActionForbidden /\
  residency_evidence_build replay = ResidencyRunnerActionForbidden /\
  residency_evidence_execution replay = ResidencyRunnerActionForbidden /\
  residency_evidence_mutation replay = ResidencyRunnerActionForbidden /\
  residency_evidence_claim replay = ResidencyPerformanceClaimForbidden.

Theorem residency_static_evidence_replay_has_complete_gate_policy :
  forall replay,
    residency_evidence_replay_static_admitted replay ->
    residency_evidence_gates replay = residency_evidence_required_gates.
Proof.
  intros replay [_ [Hgates _]].
  exact Hgates.
Qed.

Theorem residency_static_evidence_replay_has_no_bundle :
  forall replay,
    residency_evidence_replay_static_admitted replay ->
    residency_evidence_bundle_value replay = ResidencyEvidenceBundleMissing.
Proof.
  intros replay [_ [_ [_ [Hbundle _]]]].
  exact Hbundle.
Qed.

Theorem residency_static_evidence_replay_has_exact_sample_policy :
  forall replay,
    residency_evidence_replay_static_admitted replay ->
    residency_evidence_kernels_required replay = 4%nat /\
    residency_evidence_samples_per_kernel replay = 30%nat /\
    residency_evidence_samples_required replay = 120%nat.
Proof.
  intros replay
    [_ [_ [_ [_ [_ [_ [Hkernels [Hper_kernel [Hsamples _]]]]]]]]].
  repeat split; assumption.
Qed.

Theorem residency_static_evidence_replay_has_no_replay_authority :
  forall replay,
    residency_evidence_replay_static_admitted replay ->
    residency_evidence_replay_action replay = ResidencyRunnerActionForbidden.
Proof.
  intros replay
    [_ [_ [_ [_ [_ [_ [_ [_ [_ [Hreplay _]]]]]]]]]].
  exact Hreplay.
Qed.

Theorem residency_static_evidence_replay_has_no_execution_authority :
  forall replay,
    residency_evidence_replay_static_admitted replay ->
    residency_evidence_execution replay = ResidencyRunnerActionForbidden.
Proof.
  intros replay
    [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [Hexecution _]]]]]]]]]]]]]].
  exact Hexecution.
Qed.

Theorem residency_static_evidence_replay_has_no_mutation_authority :
  forall replay,
    residency_evidence_replay_static_admitted replay ->
    residency_evidence_mutation replay = ResidencyRunnerActionForbidden.
Proof.
  intros replay
    [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [Hmutation _]]]]]]]]]]]]]]].
  exact Hmutation.
Qed.

Theorem residency_static_evidence_replay_has_no_performance_claim :
  forall replay,
    residency_evidence_replay_static_admitted replay ->
    residency_evidence_claim replay = ResidencyPerformanceClaimForbidden.
Proof.
  intros replay
    [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ Hclaim]]]]]]]]]]]]]]].
  exact Hclaim.
Qed.

Theorem residency_static_evidence_replay_is_not_ready :
  forall replay,
    residency_evidence_replay_static_admitted replay ->
    ~ residency_evidence_replay_ready replay.
Proof.
  intros replay Hstatic Hready.
  destruct Hstatic as [_ [_ [Hstatic_mode _]]].
  destruct Hready as [_ [_ [Hready_mode _]]].
  rewrite Hstatic_mode in Hready_mode.
  discriminate.
Qed.

Theorem residency_ready_evidence_replay_is_read_only :
  forall replay,
    residency_evidence_replay_ready replay ->
    residency_evidence_live_host replay = ResidencyRunnerActionForbidden /\
    residency_evidence_clock replay = ResidencyRunnerActionForbidden /\
    residency_evidence_build replay = ResidencyRunnerActionForbidden /\
    residency_evidence_execution replay = ResidencyRunnerActionForbidden /\
    residency_evidence_mutation replay = ResidencyRunnerActionForbidden.
Proof.
  intros replay Hready.
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as
    [Hhost [Hclock [Hbuild [Hexecution [Hmutation _]]]]].
  repeat split; assumption.
Qed.

Theorem residency_ready_evidence_replay_cannot_self_admit_claim :
  forall replay,
    residency_evidence_replay_ready replay ->
    residency_evidence_claim replay = ResidencyPerformanceClaimForbidden.
Proof.
  intros replay Hready.
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hready].
  destruct Hready as [_ Hclaim].
  exact Hclaim.
Qed.
