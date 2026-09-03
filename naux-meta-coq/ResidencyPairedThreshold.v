(**
  NauxCore.ResidencyPairedThreshold

  The formal boundary for the S4-WP8O paired-threshold decision law.  The
  static object retains the admitted WP8N replay policy but contains no
  bundle, no kernel decisions, and no evaluation authority.  An explicit
  read-only evaluator may accept exactly four kernel decisions only after an
  eligible WP8N replay.

  Every kernel must retain at least 24 non-tied observations from 30 pairs,
  have a strictly negative candidate-minus-baseline median, pass the exact
  one-sided binomial sign tail at 1/100, and reach a baseline-total over
  candidate-total ratio of at least 21/20.  A passing family remains a
  threshold candidate and never grants performance-claim authority.
*)

From Stdlib Require Import List Arith ZArith Lia.
From NauxCore Require Import ResidencyControlledHost
  ResidencyMeasurementRunner ResidencyPairedEvidenceReplay.
Import ListNotations.

Inductive residency_paired_threshold_mode : Type :=
| ResidencyPairedThresholdStaticValidation
| ResidencyPairedThresholdExplicitReadOnly.

Inductive residency_paired_threshold_gate : Type :=
| ResidencyPairedThresholdGateParent
| ResidencyPairedThresholdGateBundle
| ResidencyPairedThresholdGateCoverage
| ResidencyPairedThresholdGateDirection
| ResidencyPairedThresholdGateSignTail
| ResidencyPairedThresholdGateMagnitude
| ResidencyPairedThresholdGateFamily
| ResidencyPairedThresholdGateClaimBoundary.

Definition residency_paired_threshold_required_gates :
    list residency_paired_threshold_gate :=
  [ ResidencyPairedThresholdGateParent;
    ResidencyPairedThresholdGateBundle;
    ResidencyPairedThresholdGateCoverage;
    ResidencyPairedThresholdGateDirection;
    ResidencyPairedThresholdGateSignTail;
    ResidencyPairedThresholdGateMagnitude;
    ResidencyPairedThresholdGateFamily;
    ResidencyPairedThresholdGateClaimBoundary ].

Fixpoint residency_threshold_pow2 (exponent : nat) : nat :=
  match exponent with
  | O => 1
  | S remaining => 2 * residency_threshold_pow2 remaining
  end.

Fixpoint residency_threshold_choose (population selected : nat) : nat :=
  match population, selected with
  | _, O => 1
  | O, S _ => 0
  | S population', S selected' =>
      residency_threshold_choose population' selected' +
      residency_threshold_choose population' (S selected')
  end.

Fixpoint residency_threshold_choose_tail
    (population selected terms : nat) : nat :=
  match terms with
  | O => 0
  | S remaining =>
      residency_threshold_choose population selected +
      residency_threshold_choose_tail population (S selected) remaining
  end.

Definition residency_threshold_sign_tail_numerator
    (wins losses : nat) : nat :=
  residency_threshold_choose_tail (wins + losses) wins (S losses).

Definition residency_threshold_sign_tail_denominator
    (wins losses : nat) : nat :=
  residency_threshold_pow2 (wins + losses).

Record residency_paired_threshold_kernel : Type := {
  residency_threshold_kernel_ordinal : nat;
  residency_threshold_sample_pairs : nat;
  residency_threshold_effective_pairs : nat;
  residency_threshold_wins : nat;
  residency_threshold_ties : nat;
  residency_threshold_losses : nat;
  residency_threshold_sign_tail_num : nat;
  residency_threshold_sign_tail_den : nat;
  residency_threshold_total_ratio_num : nat;
  residency_threshold_total_ratio_den : nat;
  residency_threshold_delta_median_num : Z;
  residency_threshold_delta_median_den : nat
}.

Definition residency_paired_threshold_kernel_passes
    (decision : residency_paired_threshold_kernel) : Prop :=
  residency_threshold_sample_pairs decision = 30%nat /\
  (residency_threshold_wins decision + residency_threshold_ties decision +
     residency_threshold_losses decision = 30)%nat /\
  residency_threshold_effective_pairs decision =
    (residency_threshold_wins decision + residency_threshold_losses decision)%nat /\
  (24 <= residency_threshold_effective_pairs decision)%nat /\
  (residency_threshold_delta_median_num decision < 0)%Z /\
  (0 < residency_threshold_delta_median_den decision)%nat /\
  (0 < residency_threshold_sign_tail_den decision)%nat /\
  (residency_threshold_sign_tail_num decision *
     residency_threshold_sign_tail_denominator
       (residency_threshold_wins decision)
       (residency_threshold_losses decision) =
   residency_threshold_sign_tail_numerator
       (residency_threshold_wins decision)
       (residency_threshold_losses decision) *
     residency_threshold_sign_tail_den decision)%nat /\
  Nat.gcd (residency_threshold_sign_tail_num decision)
    (residency_threshold_sign_tail_den decision) = 1%nat /\
  (100 * residency_threshold_sign_tail_num decision <=
     residency_threshold_sign_tail_den decision)%nat /\
  (0 < residency_threshold_total_ratio_num decision)%nat /\
  (0 < residency_threshold_total_ratio_den decision)%nat /\
  Nat.gcd (residency_threshold_total_ratio_num decision)
    (residency_threshold_total_ratio_den decision) = 1%nat /\
  (21 * residency_threshold_total_ratio_den decision <=
     20 * residency_threshold_total_ratio_num decision)%nat.

Definition residency_paired_threshold_family_passes
    (decisions : list residency_paired_threshold_kernel) : Prop :=
  length decisions = 4%nat /\
  Forall residency_paired_threshold_kernel_passes decisions.

Inductive residency_paired_threshold_candidate : Type :=
| ResidencyPairedThresholdCandidateMissing
| ResidencyPairedThresholdCandidateRetained
    (decisions : list residency_paired_threshold_kernel).

Definition residency_paired_threshold_candidate_passes
    (candidate : residency_paired_threshold_candidate) : Prop :=
  exists decisions,
    candidate = ResidencyPairedThresholdCandidateRetained decisions /\
    residency_paired_threshold_family_passes decisions.

Record residency_paired_threshold_evaluator : Type := {
  residency_threshold_parent : residency_paired_evidence_replay;
  residency_threshold_gates : list residency_paired_threshold_gate;
  residency_threshold_mode_value : residency_paired_threshold_mode;
  residency_threshold_candidate_value : residency_paired_threshold_candidate;
  residency_threshold_explicit_entrypoint : bool;
  residency_threshold_sample_pairs_required : nat;
  residency_threshold_effective_pairs_required : nat;
  residency_threshold_sign_alpha_num : nat;
  residency_threshold_sign_alpha_den : nat;
  residency_threshold_speedup_num : nat;
  residency_threshold_speedup_den : nat;
  residency_threshold_kernels_required : nat;
  residency_threshold_evaluation : residency_runner_action_authority;
  residency_threshold_live_host : residency_runner_action_authority;
  residency_threshold_clock : residency_runner_action_authority;
  residency_threshold_build : residency_runner_action_authority;
  residency_threshold_execution : residency_runner_action_authority;
  residency_threshold_mutation : residency_runner_action_authority;
  residency_threshold_publication : residency_runner_action_authority;
  residency_threshold_claim : residency_performance_claim_authority
}.

Record residency_paired_threshold_static_admitted
    (evaluator : residency_paired_threshold_evaluator) : Prop := {
  residency_threshold_static_parent_admitted :
    residency_paired_evidence_static_admitted
      (residency_threshold_parent evaluator);
  residency_threshold_static_gates_exact :
    residency_threshold_gates evaluator =
      residency_paired_threshold_required_gates;
  residency_threshold_static_mode :
    residency_threshold_mode_value evaluator =
      ResidencyPairedThresholdStaticValidation;
  residency_threshold_static_no_candidate :
    residency_threshold_candidate_value evaluator =
      ResidencyPairedThresholdCandidateMissing;
  residency_threshold_static_explicit_entrypoint :
    residency_threshold_explicit_entrypoint evaluator = true;
  residency_threshold_static_sample_pairs_exact :
    residency_threshold_sample_pairs_required evaluator = 30%nat;
  residency_threshold_static_effective_pairs_exact :
    residency_threshold_effective_pairs_required evaluator = 24%nat;
  residency_threshold_static_sign_alpha_num_exact :
    residency_threshold_sign_alpha_num evaluator = 1%nat;
  residency_threshold_static_sign_alpha_den_exact :
    residency_threshold_sign_alpha_den evaluator = 100%nat;
  residency_threshold_static_speedup_num_exact :
    residency_threshold_speedup_num evaluator = 21%nat;
  residency_threshold_static_speedup_den_exact :
    residency_threshold_speedup_den evaluator = 20%nat;
  residency_threshold_static_kernels_exact :
    residency_threshold_kernels_required evaluator = 4%nat;
  residency_threshold_static_evaluation_forbidden :
    residency_threshold_evaluation evaluator = ResidencyRunnerActionForbidden;
  residency_threshold_static_live_host_forbidden :
    residency_threshold_live_host evaluator = ResidencyRunnerActionForbidden;
  residency_threshold_static_clock_forbidden :
    residency_threshold_clock evaluator = ResidencyRunnerActionForbidden;
  residency_threshold_static_build_forbidden :
    residency_threshold_build evaluator = ResidencyRunnerActionForbidden;
  residency_threshold_static_execution_forbidden :
    residency_threshold_execution evaluator = ResidencyRunnerActionForbidden;
  residency_threshold_static_mutation_forbidden :
    residency_threshold_mutation evaluator = ResidencyRunnerActionForbidden;
  residency_threshold_static_publication_forbidden :
    residency_threshold_publication evaluator = ResidencyRunnerActionForbidden;
  residency_threshold_static_claim_forbidden :
    residency_threshold_claim evaluator = ResidencyPerformanceClaimForbidden
}.

Record residency_paired_threshold_evaluation_ready
    (evaluator : residency_paired_threshold_evaluator) : Prop := {
  residency_threshold_ready_parent :
    residency_paired_evidence_replay_ready
      (residency_threshold_parent evaluator);
  residency_threshold_ready_gates_exact :
    residency_threshold_gates evaluator =
      residency_paired_threshold_required_gates;
  residency_threshold_ready_mode :
    residency_threshold_mode_value evaluator =
      ResidencyPairedThresholdExplicitReadOnly;
  residency_threshold_ready_candidate :
    residency_paired_threshold_candidate_passes
      (residency_threshold_candidate_value evaluator);
  residency_threshold_ready_explicit_entrypoint :
    residency_threshold_explicit_entrypoint evaluator = true;
  residency_threshold_ready_sample_pairs_exact :
    residency_threshold_sample_pairs_required evaluator = 30%nat;
  residency_threshold_ready_effective_pairs_exact :
    residency_threshold_effective_pairs_required evaluator = 24%nat;
  residency_threshold_ready_sign_alpha_num_exact :
    residency_threshold_sign_alpha_num evaluator = 1%nat;
  residency_threshold_ready_sign_alpha_den_exact :
    residency_threshold_sign_alpha_den evaluator = 100%nat;
  residency_threshold_ready_speedup_num_exact :
    residency_threshold_speedup_num evaluator = 21%nat;
  residency_threshold_ready_speedup_den_exact :
    residency_threshold_speedup_den evaluator = 20%nat;
  residency_threshold_ready_kernels_exact :
    residency_threshold_kernels_required evaluator = 4%nat;
  residency_threshold_ready_evaluation_permitted :
    residency_threshold_evaluation evaluator = ResidencyRunnerActionPermitted;
  residency_threshold_ready_live_host_forbidden :
    residency_threshold_live_host evaluator = ResidencyRunnerActionForbidden;
  residency_threshold_ready_clock_forbidden :
    residency_threshold_clock evaluator = ResidencyRunnerActionForbidden;
  residency_threshold_ready_build_forbidden :
    residency_threshold_build evaluator = ResidencyRunnerActionForbidden;
  residency_threshold_ready_execution_forbidden :
    residency_threshold_execution evaluator = ResidencyRunnerActionForbidden;
  residency_threshold_ready_mutation_forbidden :
    residency_threshold_mutation evaluator = ResidencyRunnerActionForbidden;
  residency_threshold_ready_publication_forbidden :
    residency_threshold_publication evaluator = ResidencyRunnerActionForbidden;
  residency_threshold_ready_claim_forbidden :
    residency_threshold_claim evaluator = ResidencyPerformanceClaimForbidden
}.

Theorem residency_static_paired_threshold_has_exact_law :
  forall evaluator,
    residency_paired_threshold_static_admitted evaluator ->
    (residency_threshold_effective_pairs_required evaluator <=
       residency_threshold_sample_pairs_required evaluator)%nat /\
    residency_threshold_sign_alpha_num evaluator = 1%nat /\
    residency_threshold_sign_alpha_den evaluator = 100%nat /\
    residency_threshold_speedup_num evaluator = 21%nat /\
    residency_threshold_speedup_den evaluator = 20%nat /\
    residency_threshold_kernels_required evaluator = 4%nat.
Proof.
  intros evaluator Hadmitted.
  rewrite (residency_threshold_static_effective_pairs_exact evaluator Hadmitted).
  rewrite (residency_threshold_static_sample_pairs_exact evaluator Hadmitted).
  rewrite (residency_threshold_static_sign_alpha_num_exact evaluator Hadmitted).
  rewrite (residency_threshold_static_sign_alpha_den_exact evaluator Hadmitted).
  rewrite (residency_threshold_static_speedup_num_exact evaluator Hadmitted).
  rewrite (residency_threshold_static_speedup_den_exact evaluator Hadmitted).
  rewrite (residency_threshold_static_kernels_exact evaluator Hadmitted).
  lia.
Qed.

Theorem residency_static_paired_threshold_has_no_candidate :
  forall evaluator,
    residency_paired_threshold_static_admitted evaluator ->
    residency_threshold_candidate_value evaluator =
      ResidencyPairedThresholdCandidateMissing.
Proof.
  intros evaluator Hadmitted.
  exact (residency_threshold_static_no_candidate evaluator Hadmitted).
Qed.

Theorem residency_static_paired_threshold_has_no_evaluation_authority :
  forall evaluator,
    residency_paired_threshold_static_admitted evaluator ->
    residency_threshold_evaluation evaluator = ResidencyRunnerActionForbidden.
Proof.
  intros evaluator Hadmitted.
  exact (residency_threshold_static_evaluation_forbidden evaluator Hadmitted).
Qed.

Theorem residency_static_paired_threshold_is_not_ready :
  forall evaluator,
    residency_paired_threshold_static_admitted evaluator ->
    ~ residency_paired_threshold_evaluation_ready evaluator.
Proof.
  intros evaluator Hstatic Hready.
  pose proof (residency_threshold_static_mode evaluator Hstatic) as Hstatic_mode.
  pose proof (residency_threshold_ready_mode evaluator Hready) as Hready_mode.
  rewrite Hstatic_mode in Hready_mode.
  discriminate.
Qed.

Theorem residency_ready_paired_threshold_is_read_only :
  forall evaluator,
    residency_paired_threshold_evaluation_ready evaluator ->
    residency_threshold_live_host evaluator = ResidencyRunnerActionForbidden /\
    residency_threshold_clock evaluator = ResidencyRunnerActionForbidden /\
    residency_threshold_build evaluator = ResidencyRunnerActionForbidden /\
    residency_threshold_execution evaluator = ResidencyRunnerActionForbidden /\
    residency_threshold_mutation evaluator = ResidencyRunnerActionForbidden /\
    residency_threshold_publication evaluator = ResidencyRunnerActionForbidden.
Proof.
  intros evaluator Hready.
  repeat split.
  - exact (residency_threshold_ready_live_host_forbidden evaluator Hready).
  - exact (residency_threshold_ready_clock_forbidden evaluator Hready).
  - exact (residency_threshold_ready_build_forbidden evaluator Hready).
  - exact (residency_threshold_ready_execution_forbidden evaluator Hready).
  - exact (residency_threshold_ready_mutation_forbidden evaluator Hready).
  - exact (residency_threshold_ready_publication_forbidden evaluator Hready).
Qed.

Theorem residency_passing_threshold_requires_all_four_kernels :
  forall decisions,
    residency_paired_threshold_family_passes decisions ->
    length decisions = 4%nat /\
    Forall residency_paired_threshold_kernel_passes decisions.
Proof.
  intros decisions Hpasses.
  exact Hpasses.
Qed.

Theorem residency_passing_threshold_cannot_self_admit_claim :
  forall evaluator,
    residency_paired_threshold_evaluation_ready evaluator ->
    residency_threshold_claim evaluator = ResidencyPerformanceClaimForbidden.
Proof.
  intros evaluator Hready.
  exact (residency_threshold_ready_claim_forbidden evaluator Hready).
Qed.
