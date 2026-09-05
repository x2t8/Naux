(**
  WP8S: a finite, exact-observation certificate, not a compiler-wide theorem.

  Binary integers let the kernel recompute the 120 measured pairs without
  expanding nanoseconds or binomial denominators into unary naturals.  The
  decision constants are the sealed WP8O policy: 30 pairs, >=24 non-ties,
  negative paired median, one-sided sign tail <=1/100, total ratio >=21/20.

  The Python boundary authenticates archives, replay reports and the recorded
  approval. Rocq checks the supplied finite numbers and exact claim scope;
  it does not prove SHA-256, physical timing, network availability, publisher
  identity, or that approval is a cryptographic signature.
*)
From Stdlib Require Import List String Ascii Bool ZArith.
Import ListNotations.
Open Scope Z_scope.

Record residency_exact_sample : Type := {
  exact_pair_number : nat;
  exact_baseline_first : bool;
  exact_baseline_ns : Z;
  exact_candidate_ns : Z
}.

Record residency_exact_kernel : Type := {
  exact_kernel_number : nat;
  exact_samples : list residency_exact_sample
}.

Fixpoint exact_insert (value : Z) (values : list Z) : list Z :=
  match values with
  | [] => [value]
  | head :: tail =>
      if value <=? head then value :: values
      else head :: exact_insert value tail
  end.

Fixpoint exact_sort (values : list Z) : list Z :=
  match values with
  | [] => []
  | head :: tail => exact_insert head (exact_sort tail)
  end.

(** Pascal's triangle in binary integers; no floating-point tail estimate. *)
Fixpoint exact_binomial_row (population : nat) : list Z :=
  match population with
  | O => [1]
  | S previous =>
      let row := exact_binomial_row previous in
      map (fun pair => fst pair + snd pair)
        (combine (0 :: row) (row ++ [0]))
  end.

Definition exact_sum (values : list Z) : Z := fold_right Z.add 0 values.
Definition exact_wins (samples : list residency_exact_sample) : nat :=
  List.length (filter (fun p => exact_candidate_ns p <? exact_baseline_ns p) samples).
Definition exact_losses (samples : list residency_exact_sample) : nat :=
  List.length (filter (fun p => exact_baseline_ns p <? exact_candidate_ns p) samples).
Definition exact_ties (samples : list residency_exact_sample) : nat :=
  List.length (filter (fun p => exact_baseline_ns p =? exact_candidate_ns p) samples).
Definition exact_effective (samples : list residency_exact_sample) : nat :=
  (exact_wins samples + exact_losses samples)%nat.
Definition exact_tail_num (samples : list residency_exact_sample) : Z :=
  exact_sum (skipn (exact_wins samples)
    (exact_binomial_row (exact_effective samples))).
Definition exact_tail_den (samples : list residency_exact_sample) : Z :=
  2 ^ Z.of_nat (exact_effective samples).
Definition exact_baseline_total (samples : list residency_exact_sample) : Z :=
  exact_sum (map exact_baseline_ns samples).
Definition exact_candidate_total (samples : list residency_exact_sample) : Z :=
  exact_sum (map exact_candidate_ns samples).

(** Exactly 30 observations: twice the median is the sum of indices 14/15. *)
Definition exact_twice_median (samples : list residency_exact_sample) : Z :=
  let deltas := exact_sort
    (map (fun p => exact_candidate_ns p - exact_baseline_ns p) samples) in
  nth 14 deltas 0 + nth 15 deltas 0.

Definition exact_sample_valid (number : nat) (p : residency_exact_sample) : bool :=
  Nat.eqb (exact_pair_number p) number &&
  Bool.eqb (exact_baseline_first p) (Nat.odd number) &&
  (0 <? exact_baseline_ns p) && (0 <? exact_candidate_ns p).

Definition exact_kernel_passes (kernel : residency_exact_kernel) : bool :=
  let samples := exact_samples kernel in
  Nat.eqb (List.length samples) 30 &&
  forallb (fun pair => exact_sample_valid (fst pair) (snd pair))
    (combine (seq 1 30) samples) &&
  Nat.leb 24 (exact_effective samples) &&
  (exact_twice_median samples <? 0) &&
  (100 * exact_tail_num samples <=? exact_tail_den samples) &&
  (21 * exact_candidate_total samples <=? 20 * exact_baseline_total samples).

Definition exact_family_passes (kernels : list residency_exact_kernel) : bool :=
  Nat.eqb (List.length kernels) 4 &&
  forallb (fun pair =>
    Nat.eqb (exact_kernel_number (snd pair)) (fst pair) &&
    exact_kernel_passes (snd pair)) (combine (seq 1 4) kernels).

(** Compare all WP8O reported statistics against independently computed data. *)
Record residency_exact_metrics : Type := {
  exact_report_wins : nat;
  exact_report_ties : nat;
  exact_report_losses : nat;
  exact_report_sign_num : Z;
  exact_report_sign_den : Z;
  exact_report_ratio_num : Z;
  exact_report_ratio_den : Z;
  exact_report_median_num : Z;
  exact_report_median_den : Z
}.

Definition exact_reduced_fraction (num den : Z) : bool :=
  (0 <? den) && (Z.gcd num den =? 1).

Definition exact_metrics_match (kernel : residency_exact_kernel)
    (metrics : residency_exact_metrics) : bool :=
  let samples := exact_samples kernel in
  Nat.eqb (exact_wins samples) (exact_report_wins metrics) &&
  Nat.eqb (exact_ties samples) (exact_report_ties metrics) &&
  Nat.eqb (exact_losses samples) (exact_report_losses metrics) &&
  exact_reduced_fraction (exact_report_sign_num metrics) (exact_report_sign_den metrics) &&
  exact_reduced_fraction (exact_report_ratio_num metrics) (exact_report_ratio_den metrics) &&
  exact_reduced_fraction (exact_report_median_num metrics) (exact_report_median_den metrics) &&
  (exact_report_sign_num metrics * exact_tail_den samples =?
    exact_tail_num samples * exact_report_sign_den metrics) &&
  (exact_report_ratio_num metrics * exact_candidate_total samples =?
    exact_baseline_total samples * exact_report_ratio_den metrics) &&
  (2 * exact_report_median_num metrics =?
    exact_twice_median samples * exact_report_median_den metrics).

Inductive residency_exact_scope : Type :=
| ExactObservedFourKernels
| WholeLanguagePerformance
| CrossImplementationComparison.

Inductive residency_exact_approval : Type :=
| ExactApprovalAbsent
| ExactApprovalRecordedSnapshot.

Inductive residency_exact_replay : Type :=
| ExactReplayAbsent
| ExactReplayAuthenticatedSnapshot.

Open Scope string_scope.
Definition wp8s_reference_bindings : list (string * string) :=
  [("authority", "319b9325cdba206037908ec3663d09f945ce3358fa91f9a25ed2e5ff791ad481");
   ("report-root", "fc74bb0dbf246bb23e127079c95a777e9de1b640db910debe08378a2633ae830");
   ("source-commit", "56b6447a13ac648c8e35e64daa34ddabb7e0b51c");
   ("host-attestation", "85eae3c1b490e94f8c5ca06f224965e79bd66a54ab3828343499a282eb8ead9c");
   ("bundle-root", "81fbe0034fb2561d8b86f31552d170ccb4f7273545fcc1596e46ccb7f1c02bb9");
   ("session-root", "77c5447ef1db3bf95a517926383f3ff17eebd53dfa832cef98348a9d337ecc04");
   ("evidence-root", "16f5c8eec57f4a1c36a2f1a02d04f81684bfd9f1b859d836995525323f0e12c5");
   ("threshold-root", "9bb2df954d9e8f03bc5119906fcdc3e7a5ccc6aaa0601809ff762489f102d79f");
   ("public-intake-root", "a77a45ddf18b4611a569acb65bb1347370ef021f354b46ff0bfbed671b67d2fc");
   ("archive-sha256", "c94dd7bb8743f2a740227e57b75a51e56b0ff309492f2277628a297de0cfee69");
   ("receipt-sha256", "6441d7effac7f21a692ff28ee0504473c90f7cd77a2d8d599888e69c33d45d81");
   ("release-body-sha256", "d4127d9b3870765e04dc8ea22ea66d6344d4c24b05e26162db30e68430cf59f6");
   ("claim-sha256", "4c2067dc2734669e4ac9f98d453c5c54180d3cfb59760cffd38236ac1bf19505")].

Definition wp8s_reference_claim : string :=
  "On the controlled x86-64 Linux host identified by attestation 85eae3c1b490e94f8c5ca06f224965e79bd66a54ab3828343499a282eb8ead9c, for NAUX commit 56b6447a13ac648c8e35e64daa34ddabb7e0b51c, the register-residency candidate identified by bundle root 81fbe0034fb2561d8b86f31552d170ccb4f7273545fcc1596e46ccb7f1c02bb9 and threshold root 9bb2df954d9e8f03bc5119906fcdc3e7a5ccc6aaa0601809ff762489f102d79f passed the sealed WP8O paired-threshold policy on all four measured kernels, using 30 same-session AB/BA pairs per kernel. This observation applies only to the named host, commit, artifacts, protocol, and workloads; it is not a language-wide speed claim or a comparison with C, C++, or other implementations."
  ++ String (ascii_of_nat 10) EmptyString.
Close Scope string_scope.

Record residency_exact_observation : Type := {
  exact_bindings : list (string * string);
  exact_claim_text : string;
  exact_scope : residency_exact_scope;
  exact_approval : residency_exact_approval;
  exact_replay : residency_exact_replay;
  exact_kernels : list residency_exact_kernel
}.

Definition residency_exact_admitted (observation : residency_exact_observation) : Prop :=
  exact_bindings observation = wp8s_reference_bindings /\
  exact_claim_text observation = wp8s_reference_claim /\
  exact_scope observation = ExactObservedFourKernels /\
  exact_approval observation = ExactApprovalRecordedSnapshot /\
  exact_replay observation = ExactReplayAuthenticatedSnapshot /\
  exact_family_passes (exact_kernels observation) = true.

Theorem exact_claim_cannot_broaden : forall observation,
  residency_exact_admitted observation ->
  exact_scope observation <> WholeLanguagePerformance /\
  exact_scope observation <> CrossImplementationComparison.
Proof.
  intros observation [_ [_ [Hscope _]]].
  rewrite Hscope; split; discriminate.
Qed.

Theorem exact_claim_cannot_reword : forall observation,
  residency_exact_admitted observation ->
  exact_claim_text observation = wp8s_reference_claim.
Proof. intros observation [_ [Htext _]]; exact Htext. Qed.

Theorem exact_claim_requires_approval_and_replay : forall observation,
  residency_exact_admitted observation ->
  exact_approval observation <> ExactApprovalAbsent /\
  exact_replay observation <> ExactReplayAbsent.
Proof.
  intros observation [_ [_ [_ [Happroval [Hreplay _]]]]].
  rewrite Happroval, Hreplay; split; discriminate.
Qed.
