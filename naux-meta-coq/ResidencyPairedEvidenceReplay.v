(**
  NauxCore.ResidencyPairedEvidenceReplay

  The formal boundary for the static S4-WP8N same-session paired-evidence
  replay.  It retains the admitted WP8M paired runner and fixes the complete
  eleven-gate, read-only replay policy for twelve payload files, four kernels,
  120 sample pairs, and 240 sample invocations.

  The static object contains no bundle.  An explicit replay-ready object may
  inspect one eligible retained bundle, but it cannot observe a live host,
  read a clock, build or execute code, mutate or publish evidence, or grant a
  performance claim.  Descriptive kernel summaries remain evidence facts,
  not claim authority.
*)

From Stdlib Require Import List ZArith.
From NauxCore Require Import ResidencyControlledHost ResidencyPairedRunner.
Import ListNotations.

Inductive residency_paired_evidence_mode : Type :=
| ResidencyPairedEvidenceStaticValidation
| ResidencyPairedEvidenceExplicitReadOnly.

Inductive residency_paired_evidence_bundle : Type :=
| ResidencyPairedEvidenceBundleMissing
| ResidencyPairedEvidenceBundleRetained
    (bundle_root session_root host_attestation_root : list nat)
    (payload_files kernels sample_pairs sample_invocations : nat)
    (eligible_host schedule_exact artifacts_exact toolchains_exact : bool)
    (result_parity_exact reproduction_exact : bool).

Inductive residency_paired_evidence_gate : Type :=
| ResidencyPairedEvidenceGateStaticIsolation
| ResidencyPairedEvidenceGateBundleRoot
| ResidencyPairedEvidenceGateHostAttestation
| ResidencyPairedEvidenceGateSessionRoot
| ResidencyPairedEvidenceGateArtifactIdentity
| ResidencyPairedEvidenceGateToolchainIdentity
| ResidencyPairedEvidenceGateSchedule
| ResidencyPairedEvidenceGateResultParity
| ResidencyPairedEvidenceGateStatistics
| ResidencyPairedEvidenceGateReproduction
| ResidencyPairedEvidenceGateClaimBoundary.

Definition residency_paired_evidence_required_gates :
    list residency_paired_evidence_gate :=
  [ ResidencyPairedEvidenceGateStaticIsolation;
    ResidencyPairedEvidenceGateBundleRoot;
    ResidencyPairedEvidenceGateHostAttestation;
    ResidencyPairedEvidenceGateSessionRoot;
    ResidencyPairedEvidenceGateArtifactIdentity;
    ResidencyPairedEvidenceGateToolchainIdentity;
    ResidencyPairedEvidenceGateSchedule;
    ResidencyPairedEvidenceGateResultParity;
    ResidencyPairedEvidenceGateStatistics;
    ResidencyPairedEvidenceGateReproduction;
    ResidencyPairedEvidenceGateClaimBoundary ].

Definition residency_paired_evidence_digest_well_formed
    (digest : list nat) : Prop :=
  length digest = 32%nat /\
  Forall (fun byte => (byte < 256)%nat) digest.

Definition residency_paired_evidence_bundle_eligible
    (bundle : residency_paired_evidence_bundle) : Prop :=
  exists bundle_root session_root host_root,
    bundle = ResidencyPairedEvidenceBundleRetained
      bundle_root session_root host_root 12 4 120 240
      true true true true true true /\
    residency_paired_evidence_digest_well_formed bundle_root /\
    residency_paired_evidence_digest_well_formed session_root /\
    residency_paired_evidence_digest_well_formed host_root.

Record residency_paired_kernel_summary : Type := {
  residency_paired_summary_kernel : nat;
  residency_paired_summary_sample_pairs : nat;
  residency_paired_summary_baseline_total_ns : nat;
  residency_paired_summary_candidate_total_ns : nat;
  residency_paired_summary_delta_total_ns : Z;
  residency_paired_summary_baseline_median_num : nat;
  residency_paired_summary_baseline_median_den : nat;
  residency_paired_summary_candidate_median_num : nat;
  residency_paired_summary_candidate_median_den : nat;
  residency_paired_summary_delta_median_num : Z;
  residency_paired_summary_delta_median_den : nat;
  residency_paired_summary_candidate_wins : nat;
  residency_paired_summary_ties : nat;
  residency_paired_summary_candidate_losses : nat;
  residency_paired_summary_ratio_num : nat;
  residency_paired_summary_ratio_den : nat
}.

Definition residency_paired_kernel_summary_well_formed
    (summary : residency_paired_kernel_summary) : Prop :=
  residency_paired_summary_sample_pairs summary = 30%nat /\
  (residency_paired_summary_candidate_wins summary +
   residency_paired_summary_ties summary +
   residency_paired_summary_candidate_losses summary = 30)%nat /\
  (0 < residency_paired_summary_baseline_median_den summary)%nat /\
  (0 < residency_paired_summary_candidate_median_den summary)%nat /\
  (0 < residency_paired_summary_delta_median_den summary)%nat /\
  (0 < residency_paired_summary_ratio_den summary)%nat.

Record residency_paired_evidence_replay : Type := {
  residency_paired_evidence_runner : residency_paired_measurement_runner;
  residency_paired_evidence_gates : list residency_paired_evidence_gate;
  residency_paired_evidence_mode_value : residency_paired_evidence_mode;
  residency_paired_evidence_bundle_value : residency_paired_evidence_bundle;
  residency_paired_evidence_explicit_entrypoint : bool;
  residency_paired_evidence_payload_files_required : nat;
  residency_paired_evidence_kernels_required : nat;
  residency_paired_evidence_pairs_per_kernel : nat;
  residency_paired_evidence_pairs_required : nat;
  residency_paired_evidence_invocations_required : nat;
  residency_paired_evidence_replay_action : residency_runner_action_authority;
  residency_paired_evidence_live_host : residency_runner_action_authority;
  residency_paired_evidence_clock : residency_runner_action_authority;
  residency_paired_evidence_build : residency_runner_action_authority;
  residency_paired_evidence_execution : residency_runner_action_authority;
  residency_paired_evidence_mutation : residency_runner_action_authority;
  residency_paired_evidence_publication : residency_runner_action_authority;
  residency_paired_evidence_claim : residency_performance_claim_authority
}.

Record residency_paired_evidence_static_admitted
    (replay : residency_paired_evidence_replay) : Prop := {
  residency_paired_evidence_static_runner_admitted :
    residency_paired_runner_static_admitted
      (residency_paired_evidence_runner replay);
  residency_paired_evidence_static_gates_exact :
    residency_paired_evidence_gates replay =
      residency_paired_evidence_required_gates;
  residency_paired_evidence_static_mode :
    residency_paired_evidence_mode_value replay =
      ResidencyPairedEvidenceStaticValidation;
  residency_paired_evidence_static_no_bundle :
    residency_paired_evidence_bundle_value replay =
      ResidencyPairedEvidenceBundleMissing;
  residency_paired_evidence_static_explicit_entrypoint :
    residency_paired_evidence_explicit_entrypoint replay = true;
  residency_paired_evidence_static_payload_files_exact :
    residency_paired_evidence_payload_files_required replay = 12%nat;
  residency_paired_evidence_static_kernels_exact :
    residency_paired_evidence_kernels_required replay = 4%nat;
  residency_paired_evidence_static_pairs_per_kernel_exact :
    residency_paired_evidence_pairs_per_kernel replay = 30%nat;
  residency_paired_evidence_static_pairs_exact :
    residency_paired_evidence_pairs_required replay = 120%nat;
  residency_paired_evidence_static_invocations_exact :
    residency_paired_evidence_invocations_required replay = 240%nat;
  residency_paired_evidence_static_replay_forbidden :
    residency_paired_evidence_replay_action replay =
      ResidencyRunnerActionForbidden;
  residency_paired_evidence_static_live_host_forbidden :
    residency_paired_evidence_live_host replay = ResidencyRunnerActionForbidden;
  residency_paired_evidence_static_clock_forbidden :
    residency_paired_evidence_clock replay = ResidencyRunnerActionForbidden;
  residency_paired_evidence_static_build_forbidden :
    residency_paired_evidence_build replay = ResidencyRunnerActionForbidden;
  residency_paired_evidence_static_execution_forbidden :
    residency_paired_evidence_execution replay = ResidencyRunnerActionForbidden;
  residency_paired_evidence_static_mutation_forbidden :
    residency_paired_evidence_mutation replay = ResidencyRunnerActionForbidden;
  residency_paired_evidence_static_publication_forbidden :
    residency_paired_evidence_publication replay =
      ResidencyRunnerActionForbidden;
  residency_paired_evidence_static_claim_forbidden :
    residency_paired_evidence_claim replay =
      ResidencyPerformanceClaimForbidden
}.

Record residency_paired_evidence_replay_ready
    (replay : residency_paired_evidence_replay) : Prop := {
  residency_paired_evidence_ready_runner_admitted :
    residency_paired_runner_static_admitted
      (residency_paired_evidence_runner replay);
  residency_paired_evidence_ready_gates_exact :
    residency_paired_evidence_gates replay =
      residency_paired_evidence_required_gates;
  residency_paired_evidence_ready_mode :
    residency_paired_evidence_mode_value replay =
      ResidencyPairedEvidenceExplicitReadOnly;
  residency_paired_evidence_ready_bundle :
    residency_paired_evidence_bundle_eligible
      (residency_paired_evidence_bundle_value replay);
  residency_paired_evidence_ready_explicit_entrypoint :
    residency_paired_evidence_explicit_entrypoint replay = true;
  residency_paired_evidence_ready_payload_files_exact :
    residency_paired_evidence_payload_files_required replay = 12%nat;
  residency_paired_evidence_ready_kernels_exact :
    residency_paired_evidence_kernels_required replay = 4%nat;
  residency_paired_evidence_ready_pairs_per_kernel_exact :
    residency_paired_evidence_pairs_per_kernel replay = 30%nat;
  residency_paired_evidence_ready_pairs_exact :
    residency_paired_evidence_pairs_required replay = 120%nat;
  residency_paired_evidence_ready_invocations_exact :
    residency_paired_evidence_invocations_required replay = 240%nat;
  residency_paired_evidence_ready_replay_permitted :
    residency_paired_evidence_replay_action replay =
      ResidencyRunnerActionPermitted;
  residency_paired_evidence_ready_live_host_forbidden :
    residency_paired_evidence_live_host replay = ResidencyRunnerActionForbidden;
  residency_paired_evidence_ready_clock_forbidden :
    residency_paired_evidence_clock replay = ResidencyRunnerActionForbidden;
  residency_paired_evidence_ready_build_forbidden :
    residency_paired_evidence_build replay = ResidencyRunnerActionForbidden;
  residency_paired_evidence_ready_execution_forbidden :
    residency_paired_evidence_execution replay = ResidencyRunnerActionForbidden;
  residency_paired_evidence_ready_mutation_forbidden :
    residency_paired_evidence_mutation replay = ResidencyRunnerActionForbidden;
  residency_paired_evidence_ready_publication_forbidden :
    residency_paired_evidence_publication replay =
      ResidencyRunnerActionForbidden;
  residency_paired_evidence_ready_claim_forbidden :
    residency_paired_evidence_claim replay =
      ResidencyPerformanceClaimForbidden
}.

Definition residency_paired_evidence_output_valid
    (replay : residency_paired_evidence_replay)
    (summaries : list residency_paired_kernel_summary) : Prop :=
  residency_paired_evidence_replay_ready replay /\
  length summaries = 4%nat /\
  Forall residency_paired_kernel_summary_well_formed summaries.

Theorem residency_static_paired_evidence_has_no_bundle :
  forall replay,
    residency_paired_evidence_static_admitted replay ->
    residency_paired_evidence_bundle_value replay =
      ResidencyPairedEvidenceBundleMissing.
Proof.
  intros replay Hadmitted.
  exact (residency_paired_evidence_static_no_bundle replay Hadmitted).
Qed.

Theorem residency_static_paired_evidence_has_exact_cardinality :
  forall replay,
    residency_paired_evidence_static_admitted replay ->
    (residency_paired_evidence_kernels_required replay *
       residency_paired_evidence_pairs_per_kernel replay =
       residency_paired_evidence_pairs_required replay)%nat /\
    (2 * residency_paired_evidence_pairs_required replay =
       residency_paired_evidence_invocations_required replay)%nat.
Proof.
  intros replay Hadmitted.
  rewrite (residency_paired_evidence_static_kernels_exact replay Hadmitted).
  rewrite (residency_paired_evidence_static_pairs_per_kernel_exact
    replay Hadmitted).
  rewrite (residency_paired_evidence_static_pairs_exact replay Hadmitted).
  rewrite (residency_paired_evidence_static_invocations_exact
    replay Hadmitted).
  split; reflexivity.
Qed.

Theorem residency_static_paired_evidence_has_no_replay_authority :
  forall replay,
    residency_paired_evidence_static_admitted replay ->
    residency_paired_evidence_replay_action replay =
      ResidencyRunnerActionForbidden.
Proof.
  intros replay Hadmitted.
  exact (residency_paired_evidence_static_replay_forbidden replay Hadmitted).
Qed.

Theorem residency_static_paired_evidence_is_not_ready :
  forall replay,
    residency_paired_evidence_static_admitted replay ->
    ~ residency_paired_evidence_replay_ready replay.
Proof.
  intros replay Hstatic Hready.
  pose proof (residency_paired_evidence_static_mode replay Hstatic)
    as Hstatic_mode.
  pose proof (residency_paired_evidence_ready_mode replay Hready)
    as Hready_mode.
  rewrite Hstatic_mode in Hready_mode.
  discriminate.
Qed.

Theorem residency_ready_paired_evidence_is_read_only :
  forall replay,
    residency_paired_evidence_replay_ready replay ->
    residency_paired_evidence_live_host replay =
      ResidencyRunnerActionForbidden /\
    residency_paired_evidence_clock replay = ResidencyRunnerActionForbidden /\
    residency_paired_evidence_build replay = ResidencyRunnerActionForbidden /\
    residency_paired_evidence_execution replay =
      ResidencyRunnerActionForbidden /\
    residency_paired_evidence_mutation replay =
      ResidencyRunnerActionForbidden /\
    residency_paired_evidence_publication replay =
      ResidencyRunnerActionForbidden.
Proof.
  intros replay Hready.
  repeat split.
  - exact (residency_paired_evidence_ready_live_host_forbidden replay Hready).
  - exact (residency_paired_evidence_ready_clock_forbidden replay Hready).
  - exact (residency_paired_evidence_ready_build_forbidden replay Hready).
  - exact (residency_paired_evidence_ready_execution_forbidden replay Hready).
  - exact (residency_paired_evidence_ready_mutation_forbidden replay Hready).
  - exact (residency_paired_evidence_ready_publication_forbidden replay Hready).
Qed.

Theorem residency_valid_paired_evidence_has_four_complete_summaries :
  forall replay summaries,
    residency_paired_evidence_output_valid replay summaries ->
    length summaries = 4%nat /\
    Forall residency_paired_kernel_summary_well_formed summaries.
Proof.
  intros replay summaries [_ [Hlength Hsummaries]].
  split; assumption.
Qed.

Theorem residency_valid_paired_evidence_cannot_self_admit_claim :
  forall replay summaries,
    residency_paired_evidence_output_valid replay summaries ->
    residency_paired_evidence_claim replay =
      ResidencyPerformanceClaimForbidden.
Proof.
  intros replay summaries [Hready _].
  exact (residency_paired_evidence_ready_claim_forbidden replay Hready).
Qed.
