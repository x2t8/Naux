(**
  General soundness of the executable WP8S sample checker.

  These theorems quantify over arbitrary sample lists, not just the four
  admitted measurement fixtures. The declarative specification uses Forall2
  to exclude silent zip/combine truncation. Sorting preserves the complete
  multiset of paired deltas and orders it monotonically before median lookup.

  This is a theorem about the finite checker, not authentication of external
  timing data, a correctness proof of the Python validators, or a new claim.
*)
From Stdlib Require Import List Bool Arith ZArith Lia Sorting.Permutation Sorting.Sorted.
From NauxCore Require Import ResidencyExactClaim.
Import ListNotations.
Open Scope Z_scope.

Lemma exact_insert_permutation : forall value values,
  Permutation (value :: values) (exact_insert value values).
Proof.
  intros value values; induction values as [|head tail IH]; simpl.
  - reflexivity.
  - destruct (value <=? head).
    + reflexivity.
    + eapply Permutation_trans.
      * apply perm_swap.
      * apply perm_skip; exact IH.
Qed.

Theorem exact_sort_permutation : forall values,
  Permutation values (exact_sort values).
Proof.
  induction values as [|head tail IH]; simpl.
  - reflexivity.
  - eapply Permutation_trans.
    + apply perm_skip; exact IH.
    + apply exact_insert_permutation.
Qed.

Lemma exact_insert_forall : forall (P : Z -> Prop) value values,
  P value -> Forall P values -> Forall P (exact_insert value values).
Proof.
  intros P value values Hvalue Hvalues.
  induction Hvalues as [|head tail Hhead Htail IH]; simpl.
  - constructor; [exact Hvalue | constructor].
  - destruct (value <=? head).
    + constructor; [exact Hvalue | constructor; assumption].
    + constructor; assumption.
Qed.

Lemma exact_insert_sorted : forall value values,
  StronglySorted Z.le values -> StronglySorted Z.le (exact_insert value values).
Proof.
  intros value values Hsorted.
  induction Hsorted as [|head tail Htail IH Hall]; simpl.
  - constructor; constructor.
  - destruct (value <=? head) eqn:Hcompare.
    + apply Z.leb_le in Hcompare.
      constructor.
      * constructor; assumption.
      * constructor; [exact Hcompare |].
        eapply Forall_impl; [|exact Hall].
        intros element Hle; lia.
    + apply Z.leb_gt in Hcompare.
      constructor; [exact IH |].
      apply exact_insert_forall; [lia | exact Hall].
Qed.

Theorem exact_sort_sorted : forall values,
  StronglySorted Z.le (exact_sort values).
Proof.
  induction values as [|head tail IH]; simpl.
  - constructor.
  - apply exact_insert_sorted; exact IH.
Qed.

Theorem exact_sort_length : forall values,
  List.length (exact_sort values) = List.length values.
Proof.
  intro values; symmetry.
  apply Permutation_length, exact_sort_permutation.
Qed.

Lemma exact_forallb_combine_spec : forall (A B : Type)
    (test : A -> B -> bool) (left : list A) (right : list B),
  List.length left = List.length right ->
  (forallb (fun pair => test (fst pair) (snd pair)) (combine left right) = true <->
   Forall2 (fun a b => test a b = true) left right).
Proof.
  intros A B test left; induction left as [|a tail IH]; intros right Hlength.
  - destruct right; [simpl; split; constructor | discriminate].
  - destruct right as [|b rest]; [discriminate |].
    simpl in Hlength; injection Hlength as Hlength.
    simpl; rewrite andb_true_iff, Forall2_cons_iff, (IH rest Hlength).
    reflexivity.
Qed.

Lemma exact_Forall2_iff : forall (A B : Type) (P Q : A -> B -> Prop),
  (forall a b, P a b <-> Q a b) ->
  forall left right, Forall2 P left right <-> Forall2 Q left right.
Proof.
  intros A B P Q Hequiv left right; split; intro H;
    induction H; constructor; try assumption.
  - apply Hequiv; assumption.
  - apply Hequiv; assumption.
Qed.

Definition exact_sample_spec (number : nat) (sample : residency_exact_sample) : Prop :=
  exact_pair_number sample = number /\
  exact_baseline_first sample = Nat.odd number /\
  0 < exact_baseline_ns sample /\ 0 < exact_candidate_ns sample.

Lemma exact_sample_valid_spec : forall number sample,
  exact_sample_valid number sample = true <-> exact_sample_spec number sample.
Proof.
  intros number sample; unfold exact_sample_valid, exact_sample_spec.
  rewrite !andb_true_iff, Nat.eqb_eq, Bool.eqb_true_iff, !Z.ltb_lt.
  tauto.
Qed.

Definition exact_kernel_spec (kernel : residency_exact_kernel) : Prop :=
  let samples := exact_samples kernel in
  Forall2 exact_sample_spec (seq 1 30) samples /\
  (24 <= exact_effective samples)%nat /\
  exact_twice_median samples < 0 /\
  100 * exact_tail_num samples <= exact_tail_den samples /\
  21 * exact_candidate_total samples <= 20 * exact_baseline_total samples.

Theorem exact_kernel_passes_spec : forall kernel,
  exact_kernel_passes kernel = true <-> exact_kernel_spec kernel.
Proof.
  intro kernel; unfold exact_kernel_passes, exact_kernel_spec.
  rewrite !andb_true_iff, Nat.eqb_eq, Nat.leb_le, Z.ltb_lt, !Z.leb_le.
  assert (Hschedule : List.length (exact_samples kernel) = 30%nat ->
    (forallb (fun pair => exact_sample_valid (fst pair) (snd pair))
       (combine (seq 1 30) (exact_samples kernel)) = true <->
     Forall2 exact_sample_spec (seq 1 30) (exact_samples kernel))).
  { intro Hlength.
    rewrite exact_forallb_combine_spec by (rewrite length_seq; lia).
    apply exact_Forall2_iff; apply exact_sample_valid_spec. }
  split.
  - intros [[[[[Hlength Hvalid] Heffective] Hmedian] Hsign] Hratio].
    repeat split; try assumption.
    apply (Hschedule Hlength); exact Hvalid.
  - intros [Hvalid [Heffective [Hmedian [Hsign Hratio]]]].
    assert (Hlength : List.length (exact_samples kernel) = 30%nat).
    { apply Forall2_length in Hvalid; rewrite length_seq in Hvalid; lia. }
    repeat split; try assumption.
    apply (Hschedule Hlength); exact Hvalid.
Qed.

Definition exact_family_spec (kernels : list residency_exact_kernel) : Prop :=
  Forall2 (fun number kernel =>
    exact_kernel_number kernel = number /\ exact_kernel_spec kernel)
    (seq 1 4) kernels.

Theorem exact_family_passes_spec : forall kernels,
  exact_family_passes kernels = true <-> exact_family_spec kernels.
Proof.
  intro kernels; unfold exact_family_passes, exact_family_spec.
  rewrite andb_true_iff, Nat.eqb_eq.
  assert (Hfamily : List.length kernels = 4%nat ->
    (forallb (fun pair => Nat.eqb (exact_kernel_number (snd pair)) (fst pair) &&
        exact_kernel_passes (snd pair)) (combine (seq 1 4) kernels) = true <->
     Forall2 (fun number kernel => exact_kernel_number kernel = number /\
       exact_kernel_spec kernel) (seq 1 4) kernels)).
  { intro Hlength.
    rewrite (exact_forallb_combine_spec nat residency_exact_kernel
      (fun number kernel => Nat.eqb (exact_kernel_number kernel) number &&
        exact_kernel_passes kernel)) by (rewrite length_seq; lia).
    apply exact_Forall2_iff; intros number kernel.
    rewrite andb_true_iff, Nat.eqb_eq, exact_kernel_passes_spec; reflexivity. }
  split.
  - intros [Hlength Hvalid]; apply (Hfamily Hlength); exact Hvalid.
  - intro Hvalid.
    assert (Hlength : List.length kernels = 4%nat).
    { apply Forall2_length in Hvalid; rewrite length_seq in Hvalid; lia. }
    split; [exact Hlength | apply (Hfamily Hlength); exact Hvalid].
Qed.

Theorem exact_median_preserves_all_samples : forall samples,
  List.length samples = 30%nat ->
  exists ordered,
    Permutation (map (fun p => exact_candidate_ns p - exact_baseline_ns p) samples) ordered /\
    StronglySorted Z.le ordered /\ List.length ordered = 30%nat /\
    nth_error ordered 14 = Some (nth 14 ordered 0) /\
    nth_error ordered 15 = Some (nth 15 ordered 0) /\
    exact_twice_median samples = nth 14 ordered 0 + nth 15 ordered 0.
Proof.
  intros samples Hlength.
  exists (exact_sort (map (fun p => exact_candidate_ns p - exact_baseline_ns p) samples)).
  assert (Hsorted_length : List.length
      (exact_sort (map (fun p => exact_candidate_ns p - exact_baseline_ns p) samples)) = 30%nat).
  { rewrite exact_sort_length, length_map; exact Hlength. }
  repeat split.
  - apply exact_sort_permutation.
  - apply exact_sort_sorted.
  - exact Hsorted_length.
  - apply nth_error_nth'; rewrite Hsorted_length; lia.
  - apply nth_error_nth'; rewrite Hsorted_length; lia.
Qed.

Theorem exact_kernel_has_30_pairs : forall kernel,
  exact_kernel_passes kernel = true -> List.length (exact_samples kernel) = 30%nat.
Proof.
  intros kernel Hpass; apply exact_kernel_passes_spec in Hpass.
  destruct Hpass as [Hschedule _].
  apply Forall2_length in Hschedule; rewrite length_seq in Hschedule; lia.
Qed.

Lemma exact_family_numbers : forall numbers kernels,
  Forall2 (fun number kernel => exact_kernel_number kernel = number /\
    exact_kernel_spec kernel) numbers kernels ->
  map exact_kernel_number kernels = numbers.
Proof.
  intros numbers kernels Hfamily; induction Hfamily; simpl.
  - reflexivity.
  - destruct H as [Hnumber _]; rewrite Hnumber, IHHfamily; reflexivity.
Qed.

Theorem exact_family_has_distinct_kernels : forall kernels,
  exact_family_passes kernels = true ->
  map exact_kernel_number kernels = [1%nat; 2%nat; 3%nat; 4%nat] /\
  NoDup (map exact_kernel_number kernels).
Proof.
  intros kernels Hpass; apply exact_family_passes_spec in Hpass.
  apply exact_family_numbers in Hpass; rewrite Hpass.
  split; [reflexivity |].
  apply seq_NoDup.
Qed.

Lemma exact_family_sample_count : forall numbers kernels,
  Forall2 (fun number kernel => exact_kernel_number kernel = number /\
    exact_kernel_spec kernel) numbers kernels ->
  List.length (concat (map exact_samples kernels)) = (30 * List.length numbers)%nat.
Proof.
  intros numbers kernels Hfamily; induction Hfamily; simpl.
  - reflexivity.
  - destruct H as [_ Hspec].
    apply exact_kernel_passes_spec in Hspec.
    apply exact_kernel_has_30_pairs in Hspec.
    rewrite length_app, Hspec, IHHfamily; lia.
Qed.

Theorem exact_family_has_120_pairs : forall kernels,
  exact_family_passes kernels = true ->
  List.length (concat (map exact_samples kernels)) = 120%nat.
Proof.
  intros kernels Hpass; apply exact_family_passes_spec in Hpass.
  apply exact_family_sample_count in Hpass; exact Hpass.
Qed.

Theorem exact_direction_counts_partition : forall samples,
  (exact_wins samples + exact_ties samples + exact_losses samples)%nat =
  List.length samples.
Proof.
  unfold exact_wins, exact_ties, exact_losses.
  induction samples as [|sample rest IH]; simpl; [reflexivity |].
  destruct (Z.ltb_spec0 (exact_candidate_ns sample) (exact_baseline_ns sample));
    destruct (Z.eqb_spec (exact_baseline_ns sample) (exact_candidate_ns sample));
    destruct (Z.ltb_spec0 (exact_baseline_ns sample) (exact_candidate_ns sample));
    simpl; lia.
Qed.

Corollary exact_effective_excludes_only_ties : forall samples,
  (exact_effective samples + exact_ties samples)%nat = List.length samples.
Proof.
  intro samples; unfold exact_effective.
  pose proof (exact_direction_counts_partition samples); lia.
Qed.

Corollary exact_admitted_observation_has_full_coverage : forall observation,
  residency_exact_admitted observation ->
  map exact_kernel_number (exact_kernels observation) = [1%nat; 2%nat; 3%nat; 4%nat] /\
  List.length (concat (map exact_samples (exact_kernels observation))) = 120%nat.
Proof.
  intros observation [_ [_ [_ [_ [_ Hpass]]]]].
  split.
  - exact (proj1 (exact_family_has_distinct_kernels _ Hpass)).
  - apply exact_family_has_120_pairs; exact Hpass.
Qed.

Corollary exact_admitted_observation_satisfies_spec : forall observation,
  residency_exact_admitted observation -> exact_family_spec (exact_kernels observation).
Proof.
  intros observation [_ [_ [_ [_ [_ Hpass]]]]].
  apply exact_family_passes_spec; exact Hpass.
Qed.
