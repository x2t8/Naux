(**
  NauxCore.ResidencyControlledHost

  The formal boundary for the S4-WP8I controlled-host protocol.  A static
  binding connects an already checked WP8H candidate to the host protocol,
  but records no host observation, grants no timing authority, and carries no
  performance claim.  An eligible observation must instead carry a bounded
  32-byte host fingerprint and an explicit eligibility bit.

  This model deliberately separates protocol admission from measurement
  readiness.  The WP8I static report can establish the former and cannot
  establish the latter.
*)

From Stdlib Require Import List.
From NauxCore Require Import ResidencyCandidateRole.

Inductive residency_host_observation : Type :=
| ResidencyHostNotObserved
| ResidencyHostObserved (fingerprint : list nat) (eligible : bool).

Inductive residency_performance_claim_authority : Type :=
| ResidencyPerformanceClaimForbidden
| ResidencyPerformanceClaimPermitted.

Record residency_controlled_host_binding : Type := {
  residency_host_candidate : residency_role_assignment;
  residency_host_protocol_linked : bool;
  residency_host_observation_state : residency_host_observation;
  residency_host_timing : residency_timing_authority;
  residency_host_performance_claim : residency_performance_claim_authority
}.

Definition residency_host_fingerprint_well_formed
    (fingerprint : list nat) : Prop :=
  length fingerprint = 32%nat /\
  Forall (fun byte => (byte < 256)%nat) fingerprint.

Definition residency_host_observation_eligible
    (observation : residency_host_observation) : Prop :=
  exists fingerprint,
    observation = ResidencyHostObserved fingerprint true /\
    residency_host_fingerprint_well_formed fingerprint.

Definition residency_static_host_boundary_admitted
    (binding : residency_controlled_host_binding) : Prop :=
  residency_candidate_role_admitted
      (residency_host_candidate binding) /\
  residency_host_protocol_linked binding = true /\
  residency_host_observation_state binding = ResidencyHostNotObserved /\
  residency_host_timing binding = ResidencyTimingForbidden /\
  residency_host_performance_claim binding =
    ResidencyPerformanceClaimForbidden.

Definition residency_candidate_measurement_ready
    (binding : residency_controlled_host_binding) : Prop :=
  residency_candidate_role_admitted
      (residency_host_candidate binding) /\
  residency_host_protocol_linked binding = true /\
  residency_host_observation_eligible
      (residency_host_observation_state binding) /\
  residency_host_timing binding = ResidencyTimingPermitted /\
  residency_host_performance_claim binding =
    ResidencyPerformanceClaimPermitted.

Theorem residency_static_host_boundary_has_no_observation :
  forall binding,
    residency_static_host_boundary_admitted binding ->
    residency_host_observation_state binding = ResidencyHostNotObserved.
Proof.
  intros binding [_ [_ [Hobservation _]]].
  exact Hobservation.
Qed.

Theorem residency_static_host_boundary_is_not_eligible :
  forall binding,
    residency_static_host_boundary_admitted binding ->
    ~ residency_host_observation_eligible
        (residency_host_observation_state binding).
Proof.
  intros binding Hstatic Heligible.
  destruct Hstatic as [_ [_ [Hobservation _]]].
  destruct Heligible as [fingerprint [Hobserved _]].
  rewrite Hobservation in Hobserved.
  discriminate.
Qed.

Theorem residency_static_host_boundary_has_no_timing_authority :
  forall binding,
    residency_static_host_boundary_admitted binding ->
    residency_host_timing binding = ResidencyTimingForbidden.
Proof.
  intros binding [_ [_ [_ [Htiming _]]]].
  exact Htiming.
Qed.

Theorem residency_static_host_boundary_has_no_performance_claim :
  forall binding,
    residency_static_host_boundary_admitted binding ->
    residency_host_performance_claim binding =
      ResidencyPerformanceClaimForbidden.
Proof.
  intros binding [_ [_ [_ [_ Hclaim]]]].
  exact Hclaim.
Qed.

Theorem residency_static_host_boundary_is_not_measurement_ready :
  forall binding,
    residency_static_host_boundary_admitted binding ->
    ~ residency_candidate_measurement_ready binding.
Proof.
  intros binding Hstatic Hready.
  destruct Hstatic as [_ [_ [_ [Hforbidden _]]]].
  destruct Hready as [_ [_ [_ [Hpermitted _]]]].
  rewrite Hforbidden in Hpermitted.
  discriminate.
Qed.

Theorem residency_static_host_boundary_retains_candidate_isolation :
  forall binding,
    residency_static_host_boundary_admitted binding ->
    residency_assignment_role (residency_host_candidate binding) <>
      ResidencyBaselineRole.
Proof.
  intros binding [Hcandidate _].
  exact (residency_candidate_role_is_not_baseline
    (residency_host_candidate binding) Hcandidate).
Qed.
