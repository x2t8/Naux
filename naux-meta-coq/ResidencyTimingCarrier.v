(**
  NauxCore.ResidencyTimingCarrier

  The formal boundary for the S4-WP8J candidate timing carrier.  The carrier
  preserves the exact WP8G process target behind a finite prefix, exposes two
  checked CLOCK_MONOTONIC_RAW syscall markers and the role-four result-owner
  marker, but remains structurally non-executable and grants no performance
  claim.

  This layer checks bytes and placement only.  It does not model Linux syscall
  semantics, elapsed time, host eligibility, or benchmark acquisition.
*)

From Stdlib Require Import List Arith.
From NauxCore Require Import ResidencyCandidateRole ResidencyControlledHost.
Import ListNotations.

Inductive residency_carrier_clock_source : Type :=
| ResidencyClockMonotonicRaw.

Inductive residency_carrier_clock_placement : Type :=
| ResidencyClockBeforeTargetAfterValidation.

Inductive residency_carrier_execution_authority : Type :=
| ResidencyCarrierExecutionForbidden
| ResidencyCarrierExecutionPermitted.

Definition residency_nat_list_eqb (left right : list nat) : bool :=
  if list_eq_dec Nat.eq_dec left right then true else false.

Definition residency_sublist_atb
    (offset : nat) (marker bytes : list nat) : bool :=
  residency_nat_list_eqb
    (firstn (length marker) (skipn offset bytes)) marker.

Fixpoint residency_sublist_count
    (marker bytes : list nat) : nat :=
  match bytes with
  | [] => 0%nat
  | _ :: remaining =>
      (if list_eq_dec Nat.eq_dec
            (firstn (length marker) bytes) marker
       then 1%nat
       else 0%nat) + residency_sublist_count marker remaining
  end.

Definition residency_monotonic_raw_clock_prefix : list nat :=
  [184; 228; 0; 0; 0; 191; 4; 0; 0; 0; 72; 141; 116; 36].

Definition residency_monotonic_raw_clock_marker
    (timespec_offset : nat) : list nat :=
  residency_monotonic_raw_clock_prefix ++ [timespec_offset; 15; 5].

Definition residency_role_four_owner_marker : list nat :=
  [73; 184; 4; 0; 0; 0; 0; 0; 0; 0; 76; 137; 68; 36; 72].

Record residency_timing_carrier : Type := {
  residency_carrier_host_binding : residency_controlled_host_binding;
  residency_carrier_target : list nat;
  residency_carrier_prefix : list nat;
  residency_carrier_image : list nat;
  residency_carrier_target_offset : nat;
  residency_carrier_start_clock_offset : nat;
  residency_carrier_end_clock_offset : nat;
  residency_carrier_owner_offset : nat;
  residency_carrier_role_owner : nat;
  residency_carrier_clock_source_value : residency_carrier_clock_source;
  residency_carrier_clock_reads : nat;
  residency_carrier_clock_placement_value : residency_carrier_clock_placement;
  residency_carrier_execution : residency_carrier_execution_authority;
  residency_carrier_claim : residency_performance_claim_authority
}.

Definition residency_timing_prefix_well_formed
    (carrier : residency_timing_carrier) : Prop :=
  residency_sublist_atb
      (residency_carrier_start_clock_offset carrier)
      (residency_monotonic_raw_clock_marker 0)
      (residency_carrier_prefix carrier) = true /\
  residency_sublist_atb
      (residency_carrier_end_clock_offset carrier)
      (residency_monotonic_raw_clock_marker 16)
      (residency_carrier_prefix carrier) = true /\
  residency_sublist_atb
      (residency_carrier_owner_offset carrier)
      residency_role_four_owner_marker
      (residency_carrier_prefix carrier) = true /\
  residency_sublist_count residency_monotonic_raw_clock_prefix
      (residency_carrier_prefix carrier) = 2%nat /\
  (residency_carrier_start_clock_offset carrier <
     residency_carrier_end_clock_offset carrier)%nat /\
  (residency_carrier_end_clock_offset carrier <
     residency_carrier_owner_offset carrier)%nat /\
  (residency_carrier_owner_offset carrier <
     residency_carrier_target_offset carrier)%nat.

Definition residency_timing_carrier_admitted
    (carrier : residency_timing_carrier) : Prop :=
  residency_static_host_boundary_admitted
      (residency_carrier_host_binding carrier) /\
  residency_carrier_target carrier =
    residency_assignment_process
      (residency_host_candidate
        (residency_carrier_host_binding carrier)) /\
  residency_carrier_image carrier =
    residency_carrier_prefix carrier ++ residency_carrier_target carrier /\
  length (residency_carrier_prefix carrier) =
    residency_carrier_target_offset carrier /\
  Forall (fun byte => (byte < 256)%nat)
    (residency_carrier_prefix carrier) /\
  Forall (fun byte => (byte < 256)%nat)
    (residency_carrier_image carrier) /\
  residency_timing_prefix_well_formed carrier /\
  residency_carrier_role_owner carrier = 4%nat /\
  residency_carrier_clock_source_value carrier =
    ResidencyClockMonotonicRaw /\
  residency_carrier_clock_reads carrier = 2%nat /\
  residency_carrier_clock_placement_value carrier =
    ResidencyClockBeforeTargetAfterValidation /\
  residency_carrier_execution carrier = ResidencyCarrierExecutionForbidden /\
  residency_carrier_claim carrier = ResidencyPerformanceClaimForbidden.

Definition residency_timing_carrier_runnable
    (carrier : residency_timing_carrier) : Prop :=
  residency_carrier_execution carrier = ResidencyCarrierExecutionPermitted /\
  residency_candidate_measurement_ready
    (residency_carrier_host_binding carrier).

Lemma residency_skipn_length_app :
  forall (left right : list nat),
    skipn (length left) (left ++ right) = right.
Proof.
  induction left as [|head remaining IH]; intros right.
  - reflexivity.
  - simpl. exact (IH right).
Qed.

Theorem residency_timing_carrier_preserves_candidate_target :
  forall carrier,
    residency_timing_carrier_admitted carrier ->
    residency_carrier_target carrier =
      residency_assignment_process
        (residency_host_candidate
          (residency_carrier_host_binding carrier)).
Proof.
  intros carrier [_ [Htarget _]].
  exact Htarget.
Qed.

Theorem residency_timing_carrier_contains_exact_target :
  forall carrier,
    residency_timing_carrier_admitted carrier ->
    skipn (residency_carrier_target_offset carrier)
      (residency_carrier_image carrier) =
        residency_carrier_target carrier.
Proof.
  intros carrier
    [_ [_ [Himage [Hextent _]]]].
  rewrite Himage.
  rewrite <- Hextent.
  apply residency_skipn_length_app.
Qed.

Theorem residency_timing_carrier_has_two_raw_clock_markers :
  forall carrier,
    residency_timing_carrier_admitted carrier ->
    residency_sublist_count residency_monotonic_raw_clock_prefix
      (residency_carrier_prefix carrier) = 2%nat.
Proof.
  intros carrier
    [_ [_ [_ [_ [_ [_ [Hprefix _]]]]]]].
  destruct Hprefix as [_ [_ [_ [Hcount _]]]].
  exact Hcount.
Qed.

Theorem residency_timing_carrier_execution_is_forbidden :
  forall carrier,
    residency_timing_carrier_admitted carrier ->
    residency_carrier_execution carrier = ResidencyCarrierExecutionForbidden.
Proof.
  intros carrier
    [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [Hexecution _]]]]]]]]]]]].
  exact Hexecution.
Qed.

Theorem residency_timing_carrier_has_no_performance_claim :
  forall carrier,
    residency_timing_carrier_admitted carrier ->
    residency_carrier_claim carrier = ResidencyPerformanceClaimForbidden.
Proof.
  intros carrier
    [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ Hclaim]]]]]]]]]]]].
  exact Hclaim.
Qed.

Theorem residency_timing_carrier_is_not_runnable :
  forall carrier,
    residency_timing_carrier_admitted carrier ->
    ~ residency_timing_carrier_runnable carrier.
Proof.
  intros carrier Hadmitted Hrunnable.
  destruct Hrunnable as [Hpermitted _].
  rewrite (residency_timing_carrier_execution_is_forbidden
    carrier Hadmitted) in Hpermitted.
  discriminate.
Qed.
