(**
  NauxCore.HeapMachineIRResidency

  A bounded heap/list extension of [ScalarMachineIRResidency].  This model
  retains the successful data semantics of the WP8C owned-list operations:
  range allocation, static length validation, checked load, checked store,
  and release of a live handle.  Heap liveness and bounds failures are
  represented by [None].  The source slot invalidation performed by release
  is part of the ownership/undefined-cell boundary below, not represented as
  an ordinary numeric write.

  The model intentionally uses mathematical integers and naturals.  Host
  allocation failure, u32 handle exhaustion, i64 overflow events, step
  counters, and undefined register/slot ownership after a consuming move are
  not claimed here.  Branch selection and native x86-64 semantics also remain
  outside this theorem.
*)

From Stdlib Require Import List Bool Arith Lia ZArith.
From NauxCore Require Import RegisterResidency DefiniteInitialization
  ProjectedCFGResidency ScalarMachineIRResidency.
Import ListNotations.
Open Scope Z_scope.

Definition owned_heap := nat -> option (list Z).

Definition heap_update
    (heap : owned_heap) (handle : nat) (value : option (list Z))
    : owned_heap :=
  fun query => if Nat.eqb query handle then value else heap query.

Lemma heap_update_eq : forall heap handle value,
  heap_update heap handle value handle = value.
Proof.
  intros. unfold heap_update. now rewrite Nat.eqb_refl.
Qed.

Lemma heap_update_neq : forall heap handle value query,
  query <> handle ->
  heap_update heap handle value query = heap query.
Proof.
  intros heap handle value query Hneq.
  unfold heap_update. apply Nat.eqb_neq in Hneq. now rewrite Hneq.
Qed.

Record heap_machine_state : Type := {
  heap_scalar_state : machine_state;
  heap_objects : owned_heap;
  heap_next_handle : nat;
  heap_allocation_count : nat;
  heap_release_count : nat
}.

Definition with_heap_scalar
    (st : heap_machine_state) (scalar : machine_state)
    : heap_machine_state :=
  {| heap_scalar_state := scalar;
     heap_objects := heap_objects st;
     heap_next_handle := heap_next_handle st;
     heap_allocation_count := heap_allocation_count st;
     heap_release_count := heap_release_count st |}.

Definition heap_projected_phase_equiv
    (home_slot resident_register : nat) (initialized : bool)
    (baseline candidate : heap_machine_state) : Prop :=
  projected_phase_equiv home_slot resident_register initialized
    (heap_scalar_state baseline) (heap_scalar_state candidate) /\
  heap_objects candidate = heap_objects baseline /\
  heap_next_handle candidate = heap_next_handle baseline /\
  heap_allocation_count candidate = heap_allocation_count baseline /\
  heap_release_count candidate = heap_release_count baseline.

Definition heap_full_state_equiv
    (baseline candidate : heap_machine_state) : Prop :=
  full_state_equiv
    (heap_scalar_state baseline) (heap_scalar_state candidate) /\
  heap_objects candidate = heap_objects baseline /\
  heap_next_handle candidate = heap_next_handle baseline /\
  heap_allocation_count candidate = heap_allocation_count baseline /\
  heap_release_count candidate = heap_release_count baseline.

Definition heap_hide_reserved_register
    (resident_register : nat) (replacement : Z)
    (st : heap_machine_state) : heap_machine_state :=
  with_heap_scalar st
    (hide_reserved_register resident_register replacement
      (heap_scalar_state st)).

Lemma heap_hide_reserved_register_preserves_phase :
  forall home_slot resident_register replacement st,
    heap_projected_phase_equiv home_slot resident_register false st
      (heap_hide_reserved_register resident_register replacement st).
Proof.
  intros. unfold heap_projected_phase_equiv, heap_hide_reserved_register,
    with_heap_scalar. simpl.
  repeat split; try reflexivity.
  apply hide_reserved_register_preserves_observable.
Qed.

Definition heap_finalize
    (home_slot resident_register : nat) (saved_value : Z)
    (initialized : bool) (candidate : heap_machine_state)
    : heap_machine_state :=
  with_heap_scalar candidate
    (projected_finalize home_slot resident_register saved_value initialized
      (heap_scalar_state candidate)).

Theorem heap_finalize_closes_phase :
  forall home_slot resident_register initialized baseline candidate
      saved_value,
    heap_projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    saved_value =
      register_cells (heap_scalar_state baseline) resident_register ->
    heap_full_state_equiv baseline
      (heap_finalize home_slot resident_register saved_value initialized
        candidate).
Proof.
  intros home_slot resident_register initialized baseline candidate
    saved_value [Hphase [Hheap [Hnext [Halloc Hrelease]]]] Hsaved.
  unfold heap_full_state_equiv, heap_finalize, with_heap_scalar. simpl.
  split.
  - now apply projected_finalize_closes_phase.
  - repeat split; assumption.
Qed.

Definition decode_nonnegative (value : Z) : option nat :=
  if value <? 0 then None else Some (Z.to_nat value).

Fixpoint replace_nth (index : nat) (value : Z) (values : list Z)
    : option (list Z) :=
  match index, values with
  | O, _ :: rest => Some (value :: rest)
  | S next, current :: rest =>
      match replace_nth next value rest with
      | Some updated => Some (current :: updated)
      | None => None
      end
  | _, [] => None
  end.

Definition range_values (length : nat) : list Z :=
  map Z.of_nat (seq 0 length).

Inductive heap_machine_instruction : Type :=
| HeapRangeAllocateInit (destination length : nat)
| HeapListLengthStatic (destination slot expected_length : nat)
| HeapListLoadChecked (destination list_register index_register : nat)
| HeapListStoreChecked
    (destination list_register index_register value_register : nat)
| HeapReleaseOwnedList (slot : nat).

Definition heap_machine_instruction_admissible
    (home_slot resident_register : nat)
    (instruction : heap_machine_instruction) : Prop :=
  match instruction with
  | HeapRangeAllocateInit destination _ =>
      destination <> resident_register
  | HeapListLengthStatic destination slot _ =>
      destination <> resident_register /\ slot <> home_slot
  | HeapListLoadChecked destination list_register index_register =>
      destination <> resident_register /\
      list_register <> resident_register /\
      index_register <> resident_register
  | HeapListStoreChecked destination list_register index_register
      value_register =>
      destination <> resident_register /\
      list_register <> resident_register /\
      index_register <> resident_register /\
      value_register <> resident_register
  | HeapReleaseOwnedList slot => slot <> home_slot
  end.

Definition heap_machine_instruction_admissibleb
    (home_slot resident_register : nat)
    (instruction : heap_machine_instruction) : bool :=
  match instruction with
  | HeapRangeAllocateInit destination _ =>
      nat_negb destination resident_register
  | HeapListLengthStatic destination slot _ =>
      nat_negb destination resident_register && nat_negb slot home_slot
  | HeapListLoadChecked destination list_register index_register =>
      nat_negb destination resident_register &&
      nat_negb list_register resident_register &&
      nat_negb index_register resident_register
  | HeapListStoreChecked destination list_register index_register
      value_register =>
      nat_negb destination resident_register &&
      nat_negb list_register resident_register &&
      nat_negb index_register resident_register &&
      nat_negb value_register resident_register
  | HeapReleaseOwnedList slot => nat_negb slot home_slot
  end.

Theorem heap_machine_instruction_admissibleb_reflect :
  forall home_slot resident_register instruction,
    heap_machine_instruction_admissibleb home_slot resident_register
      instruction = true <->
    heap_machine_instruction_admissible home_slot resident_register
      instruction.
Proof.
  intros home_slot resident_register instruction.
  destruct instruction as
    [destination length | destination slot expected |
     destination list_register index_register |
     destination list_register index_register value_register | slot];
    simpl; repeat rewrite Bool.andb_true_iff;
    repeat rewrite nat_negb_reflect; tauto.
Qed.

Definition heap_machine_step
    (instruction : heap_machine_instruction) (st : heap_machine_state)
    : option heap_machine_state :=
  let scalar := heap_scalar_state st in
  match instruction with
  | HeapRangeAllocateInit destination length =>
      let handle := heap_next_handle st in
      Some
        {| heap_scalar_state :=
             scalar_machine_step
               (ScalarConst destination (Z.of_nat handle)) scalar;
           heap_objects :=
             heap_update (heap_objects st) handle
               (Some (range_values length));
           heap_next_handle := S handle;
           heap_allocation_count := S (heap_allocation_count st);
           heap_release_count := heap_release_count st |}
  | HeapListLengthStatic destination slot expected_length =>
      match decode_nonnegative (stack_cells scalar slot) with
      | Some handle =>
          match heap_objects st handle with
          | Some values =>
              if Nat.eqb (length values) expected_length then
                Some (with_heap_scalar st
                  (scalar_machine_step
                    (ScalarConst destination (Z.of_nat expected_length))
                    scalar))
              else None
          | None => None
          end
      | None => None
      end
  | HeapListLoadChecked destination list_register index_register =>
      match decode_nonnegative (register_cells scalar list_register),
            decode_nonnegative (register_cells scalar index_register) with
      | Some handle, Some index =>
          match heap_objects st handle with
          | Some values =>
              match nth_error values index with
              | Some value =>
                  Some (with_heap_scalar st
                    (scalar_machine_step
                      (ScalarConst destination value) scalar))
              | None => None
              end
          | None => None
          end
      | _, _ => None
      end
  | HeapListStoreChecked destination list_register index_register
      value_register =>
      match decode_nonnegative (register_cells scalar list_register),
            decode_nonnegative (register_cells scalar index_register) with
      | Some handle, Some index =>
          match heap_objects st handle with
          | Some values =>
              match replace_nth index
                (register_cells scalar value_register) values with
              | Some updated =>
                  Some
                    {| heap_scalar_state :=
                         scalar_machine_step
                           (ScalarConst destination 0) scalar;
                       heap_objects :=
                         heap_update (heap_objects st) handle (Some updated);
                       heap_next_handle := heap_next_handle st;
                       heap_allocation_count := heap_allocation_count st;
                       heap_release_count := heap_release_count st |}
              | None => None
              end
          | None => None
          end
      | _, _ => None
      end
  | HeapReleaseOwnedList slot =>
      match decode_nonnegative (stack_cells scalar slot) with
      | Some handle =>
          match heap_objects st handle with
          | Some _ =>
              Some
                {| heap_scalar_state := scalar;
                   heap_objects := heap_update (heap_objects st) handle None;
                   heap_next_handle := heap_next_handle st;
                   heap_allocation_count := heap_allocation_count st;
                   heap_release_count := S (heap_release_count st) |}
          | None => None
          end
      | None => None
      end
  end.

Lemma heap_phase_stack_agree :
  forall home_slot resident_register initialized baseline candidate slot,
    slot <> home_slot ->
    heap_projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    stack_cells (heap_scalar_state candidate) slot =
      stack_cells (heap_scalar_state baseline) slot.
Proof.
  intros home_slot resident_register initialized baseline candidate slot
    Hslot [Hphase _].
  destruct initialized; simpl in Hphase.
  - exact (proj1 (proj2 Hphase) slot Hslot).
  - exact (proj1 Hphase slot).
Qed.

Lemma heap_phase_register_agree :
  forall home_slot resident_register initialized baseline candidate reg,
    reg <> resident_register ->
    heap_projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    register_cells (heap_scalar_state candidate) reg =
      register_cells (heap_scalar_state baseline) reg.
Proof.
  intros home_slot resident_register initialized baseline candidate reg
    Hreg [Hphase _].
  destruct initialized; simpl in Hphase.
  - exact (proj2 (proj2 Hphase) reg Hreg).
  - exact (proj2 Hphase reg Hreg).
Qed.

Lemma scalar_const_preserves_projected_phase :
  forall home_slot resident_register initialized destination value
      baseline candidate,
    destination <> resident_register ->
    projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    projected_phase_equiv home_slot resident_register initialized
      (scalar_machine_step (ScalarConst destination value) baseline)
      (scalar_machine_step (ScalarConst destination value) candidate).
Proof.
  intros home_slot resident_register initialized destination value
    baseline candidate Hdestination Hphase.
  destruct initialized.
  - change (resident_equiv home_slot resident_register baseline candidate)
      in Hphase.
    change (resident_equiv home_slot resident_register
      (scalar_machine_step (ScalarConst destination value) baseline)
      (scalar_machine_step (ScalarConst destination value) candidate)).
    eapply scalar_machine_step_preserves_resident; eassumption.
  - change (observable_equiv resident_register baseline candidate) in Hphase.
    change (observable_equiv resident_register
      (scalar_machine_step (ScalarConst destination value) baseline)
      (scalar_machine_step (ScalarConst destination value) candidate)).
    eapply scalar_machine_step_preserves_observable
      with (home_slot := home_slot); eassumption.
Qed.

Theorem heap_machine_step_preserves_phase :
  forall home_slot resident_register initialized instruction baseline
      candidate baseline_out,
    heap_machine_instruction_admissible home_slot resident_register
      instruction ->
    heap_projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    heap_machine_step instruction baseline = Some baseline_out ->
    exists candidate_out,
      heap_machine_step instruction candidate = Some candidate_out /\
      heap_projected_phase_equiv home_slot resident_register initialized
        baseline_out candidate_out.
Proof.
  intros home_slot resident_register initialized instruction baseline
    candidate baseline_out Hadmissible Hequiv Hbaseline.
  destruct Hequiv as [Hphase [Hheap [Hnext [Halloc Hrelease]]]].
  destruct instruction as
    [destination length |
     destination slot expected_length |
     destination list_register index_register |
     destination list_register index_register value_register |
     slot]; simpl in Hadmissible.
  - simpl in Hbaseline. inversion Hbaseline; subst baseline_out.
    simpl. rewrite Hnext, Hheap, Halloc, Hrelease.
    eexists. split; [reflexivity|].
    unfold heap_projected_phase_equiv. simpl.
    repeat split; try reflexivity.
    now apply scalar_const_preserves_projected_phase.
  - destruct Hadmissible as [Hdestination Hslot].
    pose proof (heap_phase_stack_agree home_slot resident_register initialized
      baseline candidate slot Hslot
      (conj Hphase (conj Hheap (conj Hnext (conj Halloc Hrelease)))))
      as Hslot_value.
    simpl in Hbaseline |- *.
    rewrite Hslot_value, Hheap.
    destruct (decode_nonnegative
      (stack_cells (heap_scalar_state baseline) slot)) as [handle|]
      eqn:Hhandle; try discriminate.
    destruct (heap_objects baseline handle) as [values|] eqn:Hvalues;
      try discriminate.
    destruct (Nat.eqb (Datatypes.length values) expected_length)
      eqn:Hlength; try discriminate.
    inversion Hbaseline; subst baseline_out.
    eexists. split; [reflexivity|].
    unfold heap_projected_phase_equiv, with_heap_scalar. simpl.
    repeat split; try assumption.
    now apply scalar_const_preserves_projected_phase.
  - destruct Hadmissible as [Hdestination [Hlist Hindex]].
    pose proof (heap_phase_register_agree home_slot resident_register
      initialized baseline candidate list_register Hlist
      (conj Hphase (conj Hheap (conj Hnext (conj Halloc Hrelease)))))
      as Hlist_value.
    pose proof (heap_phase_register_agree home_slot resident_register
      initialized baseline candidate index_register Hindex
      (conj Hphase (conj Hheap (conj Hnext (conj Halloc Hrelease)))))
      as Hindex_value.
    simpl in Hbaseline |- *.
    rewrite Hlist_value, Hindex_value, Hheap.
    destruct (decode_nonnegative
      (register_cells (heap_scalar_state baseline) list_register))
      as [handle|] eqn:Hhandle; try discriminate.
    destruct (decode_nonnegative
      (register_cells (heap_scalar_state baseline) index_register))
      as [index|] eqn:Hindex_decode; try discriminate.
    destruct (heap_objects baseline handle) as [values|] eqn:Hvalues;
      try discriminate.
    destruct (nth_error values index) as [value|] eqn:Hvalue;
      try discriminate.
    inversion Hbaseline; subst baseline_out.
    eexists. split; [reflexivity|].
    unfold heap_projected_phase_equiv, with_heap_scalar. simpl.
    repeat split; try assumption.
    now apply scalar_const_preserves_projected_phase.
  - destruct Hadmissible as [Hdestination [Hlist [Hindex Hvalue]]].
    pose proof (heap_phase_register_agree home_slot resident_register
      initialized baseline candidate list_register Hlist
      (conj Hphase (conj Hheap (conj Hnext (conj Halloc Hrelease)))))
      as Hlist_value.
    pose proof (heap_phase_register_agree home_slot resident_register
      initialized baseline candidate index_register Hindex
      (conj Hphase (conj Hheap (conj Hnext (conj Halloc Hrelease)))))
      as Hindex_value.
    pose proof (heap_phase_register_agree home_slot resident_register
      initialized baseline candidate value_register Hvalue
      (conj Hphase (conj Hheap (conj Hnext (conj Halloc Hrelease)))))
      as Hstored_value.
    simpl in Hbaseline |- *.
    rewrite Hlist_value, Hindex_value, Hstored_value, Hheap.
    destruct (decode_nonnegative
      (register_cells (heap_scalar_state baseline) list_register))
      as [handle|] eqn:Hhandle; try discriminate.
    destruct (decode_nonnegative
      (register_cells (heap_scalar_state baseline) index_register))
      as [index|] eqn:Hindex_decode; try discriminate.
    destruct (heap_objects baseline handle) as [values|] eqn:Hvalues;
      try discriminate.
    destruct (replace_nth index
      (register_cells (heap_scalar_state baseline) value_register) values)
      as [updated|] eqn:Hupdated; try discriminate.
    inversion Hbaseline; subst baseline_out.
    eexists. split; [reflexivity|].
    unfold heap_projected_phase_equiv. simpl.
    repeat split; try assumption; try reflexivity.
    now apply scalar_const_preserves_projected_phase.
  - pose proof (heap_phase_stack_agree home_slot resident_register initialized
      baseline candidate slot Hadmissible
      (conj Hphase (conj Hheap (conj Hnext (conj Halloc Hrelease)))))
      as Hslot_value.
    simpl in Hbaseline |- *.
    rewrite Hslot_value, Hheap.
    destruct (decode_nonnegative
      (stack_cells (heap_scalar_state baseline) slot)) as [handle|]
      eqn:Hhandle; try discriminate.
    destruct (heap_objects baseline handle) as [values|] eqn:Hvalues;
      try discriminate.
    inversion Hbaseline; subst baseline_out.
    eexists. split; [reflexivity|].
    unfold heap_projected_phase_equiv. simpl.
    repeat split; try assumption; try reflexivity.
    now rewrite Hrelease.
Qed.

(** The complete bounded trace interleaves the already-proved scalar/
    residency projection with heap instructions. *)
Inductive heap_residency_instruction : Type :=
| HeapScalarInstruction (instruction : scalar_residency_instruction)
| HeapPassThrough (instruction : heap_machine_instruction).

Definition heap_residency_projection
    (instruction : heap_residency_instruction)
    : list resident_instruction :=
  match instruction with
  | HeapScalarInstruction scalar => scalar_residency_projection scalar
  | HeapPassThrough _ => []
  end.

Fixpoint heap_residency_program_projection
    (program : list heap_residency_instruction)
    : list resident_instruction :=
  match program with
  | [] => []
  | instruction :: rest =>
      heap_residency_projection instruction ++
      heap_residency_program_projection rest
  end.

Definition heap_residency_instruction_admissible
    (home_slot resident_register : nat)
    (instruction : heap_residency_instruction) : Prop :=
  match instruction with
  | HeapScalarInstruction scalar =>
      scalar_residency_instruction_admissible
        home_slot resident_register scalar
  | HeapPassThrough heap =>
      heap_machine_instruction_admissible
        home_slot resident_register heap
  end.

Definition heap_residency_instruction_admissibleb
    (home_slot resident_register : nat)
    (instruction : heap_residency_instruction) : bool :=
  match instruction with
  | HeapScalarInstruction scalar =>
      scalar_residency_instruction_admissibleb
        home_slot resident_register scalar
  | HeapPassThrough heap =>
      heap_machine_instruction_admissibleb
        home_slot resident_register heap
  end.

Definition heap_residency_program_admissibleb
    (home_slot resident_register : nat)
    (program : list heap_residency_instruction) : bool :=
  forallb
    (heap_residency_instruction_admissibleb
      home_slot resident_register) program.

Theorem heap_residency_program_admissibleb_reflect :
  forall home_slot resident_register program,
    heap_residency_program_admissibleb
      home_slot resident_register program = true <->
    Forall
      (heap_residency_instruction_admissible
        home_slot resident_register) program.
Proof.
  intros home_slot resident_register program.
  unfold heap_residency_program_admissibleb.
  rewrite forallb_forall, Forall_forall.
  split; intros H instruction Hin; specialize (H instruction Hin).
  - destruct instruction as [scalar | heap]; simpl in *.
    + destruct scalar as [resident | scalar]; simpl in *.
      * now apply (proj1
          (instruction_admissibleb_reflect resident_register resident)).
      * now apply (proj1 (scalar_instruction_admissibleb_reflect
          home_slot resident_register scalar)).
    + now apply (proj1 (heap_machine_instruction_admissibleb_reflect
        home_slot resident_register heap)).
  - destruct instruction as [scalar | heap]; simpl in *.
    + destruct scalar as [resident | scalar]; simpl in *.
      * now apply (proj2
          (instruction_admissibleb_reflect resident_register resident)).
      * now apply (proj2 (scalar_instruction_admissibleb_reflect
          home_slot resident_register scalar)).
    + now apply (proj2 (heap_machine_instruction_admissibleb_reflect
        home_slot resident_register heap)).
Qed.

Definition heap_residency_baseline_step
    (home_slot : nat) (instruction : heap_residency_instruction)
    (st : heap_machine_state) : option heap_machine_state :=
  match instruction with
  | HeapScalarInstruction scalar =>
      Some (with_heap_scalar st
        (scalar_residency_baseline_step home_slot scalar
          (heap_scalar_state st)))
  | HeapPassThrough heap => heap_machine_step heap st
  end.

Definition heap_residency_candidate_step
    (resident_register : nat) (initialized : bool)
    (instruction : heap_residency_instruction)
    (candidate : heap_machine_state)
    : option (bool * heap_machine_state) :=
  match instruction with
  | HeapScalarInstruction scalar =>
      match scalar_residency_candidate_step
        resident_register initialized scalar
        (heap_scalar_state candidate) with
      | Some (next, stepped) =>
          Some (next, with_heap_scalar candidate stepped)
      | None => None
      end
  | HeapPassThrough heap =>
      match heap_machine_step heap candidate with
      | Some stepped => Some (initialized, stepped)
      | None => None
      end
  end.

Fixpoint heap_residency_baseline_execute
    (home_slot : nat) (program : list heap_residency_instruction)
    (st : heap_machine_state) : option heap_machine_state :=
  match program with
  | [] => Some st
  | instruction :: rest =>
      match heap_residency_baseline_step home_slot instruction st with
      | Some stepped =>
          heap_residency_baseline_execute home_slot rest stepped
      | None => None
      end
  end.

Fixpoint heap_residency_candidate_execute
    (resident_register : nat) (initialized : bool)
    (program : list heap_residency_instruction)
    (candidate : heap_machine_state)
    : option (bool * heap_machine_state) :=
  match program with
  | [] => Some (initialized, candidate)
  | instruction :: rest =>
      match heap_residency_candidate_step resident_register initialized
        instruction candidate with
      | Some (next, stepped) =>
          heap_residency_candidate_execute resident_register next rest stepped
      | None => None
      end
  end.

Theorem heap_residency_instruction_preserves_phase :
  forall home_slot resident_register initialized next instruction baseline
      candidate baseline_out,
    heap_residency_instruction_admissible
      home_slot resident_register instruction ->
    initialization_block initialized
      (heap_residency_projection instruction) = Some next ->
    heap_projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    heap_residency_baseline_step home_slot instruction baseline =
      Some baseline_out ->
    exists candidate_out,
      heap_residency_candidate_step resident_register initialized
        instruction candidate = Some (next, candidate_out) /\
      heap_projected_phase_equiv home_slot resident_register next
        baseline_out candidate_out.
Proof.
  intros home_slot resident_register initialized next instruction baseline
    candidate baseline_out Hadmissible Hinitialization Hphase Hbaseline.
  destruct instruction as [scalar | heap].
  - simpl in Hbaseline. inversion Hbaseline; subst baseline_out.
    destruct Hphase as [Hscalar [Hheap [Hnext [Halloc Hrelease]]]].
    destruct (scalar_residency_candidate_step resident_register initialized
      scalar (heap_scalar_state candidate)) as [[candidate_next stepped]|]
      eqn:Hcandidate.
    2: {
      destruct scalar as [resident | ordinary]; simpl in Hcandidate.
      - unfold projected_candidate_step in Hcandidate.
        destruct (initialization_step initialized resident)
          as [resident_next|] eqn:Hresident; try discriminate.
        simpl in Hinitialization. rewrite Hresident in Hinitialization.
        discriminate.
      - discriminate.
    }
    assert (Hcandidate_next : candidate_next = next).
    {
      destruct scalar as [resident | ordinary]; simpl in *.
      - unfold projected_candidate_step in Hcandidate.
        destruct (initialization_step initialized resident)
          as [resident_next|] eqn:Hresident; try discriminate.
        inversion Hcandidate; inversion Hinitialization; congruence.
      - inversion Hcandidate; inversion Hinitialization; congruence.
    }
    subst candidate_next.
    exists (with_heap_scalar candidate stepped). split.
    + simpl. now rewrite Hcandidate.
    + unfold heap_projected_phase_equiv, with_heap_scalar. simpl.
      split.
      * pose proof (scalar_residency_instruction_preserves_phase
          home_slot resident_register initialized next
          (heap_scalar_state baseline) (heap_scalar_state candidate)
          scalar Hadmissible Hinitialization Hscalar) as Hpreserved.
        now rewrite Hcandidate in Hpreserved.
      * repeat split; assumption.
  - simpl in Hinitialization. inversion Hinitialization; subst next.
    simpl in Hbaseline.
    destruct (heap_machine_step_preserves_phase home_slot resident_register
      initialized heap baseline candidate baseline_out Hadmissible Hphase
      Hbaseline) as [candidate_out [Hcandidate Hout]].
    exists candidate_out. split; [simpl; now rewrite Hcandidate|exact Hout].
Qed.

Theorem heap_residency_candidate_execute_preserves_phase :
  forall program home_slot resident_register initialized baseline candidate
      baseline_out path_out,
    Forall
      (heap_residency_instruction_admissible
        home_slot resident_register) program ->
    heap_projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    initialization_block initialized
      (heap_residency_program_projection program) = Some path_out ->
    heap_residency_baseline_execute home_slot program baseline =
      Some baseline_out ->
    exists candidate_out,
      heap_residency_candidate_execute resident_register initialized
        program candidate = Some (path_out, candidate_out) /\
      heap_projected_phase_equiv home_slot resident_register path_out
        baseline_out candidate_out.
Proof.
  induction program as [|instruction rest IH];
    intros home_slot resident_register initialized baseline candidate
      baseline_out path_out Hadmissible Hphase Hinitialization Hbaseline;
    simpl in *.
  - inversion Hinitialization; inversion Hbaseline; subst.
    exists candidate. now split.
  - inversion Hadmissible as [|? ? Hinstruction Hrest]; subst.
    destruct (initialization_block initialized
      (heap_residency_projection instruction))
      as [next|] eqn:Hnext.
    2: {
      rewrite initialization_block_app, Hnext in Hinitialization.
      discriminate.
    }
    rewrite initialization_block_app, Hnext in Hinitialization.
    destruct (heap_residency_baseline_step home_slot instruction baseline)
      as [stepped_baseline|] eqn:Hbaseline_step; try discriminate.
    destruct (heap_residency_instruction_preserves_phase
      home_slot resident_register initialized next instruction baseline
      candidate stepped_baseline Hinstruction Hnext Hphase Hbaseline_step)
      as [stepped_candidate [Hcandidate_step Hstepped]].
    destruct (IH home_slot resident_register next stepped_baseline
      stepped_candidate baseline_out path_out Hrest Hstepped
      Hinitialization Hbaseline)
      as [candidate_out [Hcandidate Hout]].
    exists candidate_out. split; [|exact Hout].
    now rewrite Hcandidate_step.
Qed.

Lemma heap_machine_step_preserves_reserved_register :
  forall home_slot resident_register instruction initial final,
    heap_machine_instruction_admissible home_slot resident_register
      instruction ->
    heap_machine_step instruction initial = Some final ->
    register_cells (heap_scalar_state final) resident_register =
      register_cells (heap_scalar_state initial) resident_register.
Proof.
  intros home_slot resident_register instruction initial final
    Hadmissible Hstep.
  destruct instruction as
    [destination length |
     destination slot expected_length |
     destination list_register index_register |
     destination list_register index_register value_register | slot];
    simpl in Hadmissible, Hstep.
  - inversion Hstep; subst. simpl.
    rewrite map_update_neq by congruence. reflexivity.
  - destruct Hadmissible as [Hdestination Hslot].
    destruct (decode_nonnegative
      (stack_cells (heap_scalar_state initial) slot)) as [handle|];
      try discriminate.
    destruct (heap_objects initial handle) as [values|]; try discriminate.
    destruct (Nat.eqb (Datatypes.length values) expected_length);
      try discriminate.
    inversion Hstep; subst. simpl.
    rewrite map_update_neq by congruence. reflexivity.
  - destruct Hadmissible as [Hdestination [Hlist Hindex]].
    destruct (decode_nonnegative
      (register_cells (heap_scalar_state initial) list_register));
      try discriminate.
    destruct (decode_nonnegative
      (register_cells (heap_scalar_state initial) index_register));
      try discriminate.
    destruct (heap_objects initial n) as [values|]; try discriminate.
    destruct (nth_error values n0); try discriminate.
    inversion Hstep; subst. simpl.
    rewrite map_update_neq by congruence. reflexivity.
  - destruct Hadmissible as [Hdestination [Hlist [Hindex Hvalue]]].
    destruct (decode_nonnegative
      (register_cells (heap_scalar_state initial) list_register));
      try discriminate.
    destruct (decode_nonnegative
      (register_cells (heap_scalar_state initial) index_register));
      try discriminate.
    destruct (heap_objects initial n) as [values|]; try discriminate.
    destruct (replace_nth n0
      (register_cells (heap_scalar_state initial) value_register) values);
      try discriminate.
    inversion Hstep; subst. simpl.
    rewrite map_update_neq by congruence. reflexivity.
  - destruct (decode_nonnegative
      (stack_cells (heap_scalar_state initial) slot)); try discriminate.
    destruct (heap_objects initial n); try discriminate.
    inversion Hstep; reflexivity.
Qed.

Lemma heap_residency_baseline_step_preserves_reserved_register :
  forall home_slot resident_register instruction initial final,
    heap_residency_instruction_admissible
      home_slot resident_register instruction ->
    heap_residency_baseline_step home_slot instruction initial = Some final ->
    register_cells (heap_scalar_state final) resident_register =
      register_cells (heap_scalar_state initial) resident_register.
Proof.
  intros home_slot resident_register instruction initial final
    Hadmissible Hstep.
  destruct instruction as [scalar | heap].
  - simpl in Hstep. inversion Hstep; subst. simpl.
    destruct scalar as [resident | scalar]; simpl in Hadmissible |- *.
    + now apply baseline_instruction_preserves_reserved_register
        with (home_slot := home_slot) (instruction := resident).
    + now apply scalar_machine_step_preserves_reserved_register
        with (home_slot := home_slot) (instruction := scalar).
  - now apply heap_machine_step_preserves_reserved_register
      with (home_slot := home_slot) (instruction := heap).
Qed.

Lemma heap_residency_baseline_execute_preserves_reserved_register :
  forall program home_slot resident_register initial final,
    Forall
      (heap_residency_instruction_admissible
        home_slot resident_register) program ->
    heap_residency_baseline_execute home_slot program initial = Some final ->
    register_cells (heap_scalar_state final) resident_register =
      register_cells (heap_scalar_state initial) resident_register.
Proof.
  induction program as [|instruction rest IH];
    intros home_slot resident_register initial final Hadmissible Hexecute;
    simpl in Hexecute.
  - inversion Hexecute. reflexivity.
  - inversion Hadmissible as [|? ? Hinstruction Hrest]; subst.
    destruct (heap_residency_baseline_step home_slot instruction initial)
      as [stepped|] eqn:Hstep; try discriminate.
    rewrite (IH home_slot resident_register stepped final Hrest Hexecute).
    now apply heap_residency_baseline_step_preserves_reserved_register
      with (home_slot := home_slot) (instruction := instruction).
Qed.

Theorem heap_residency_program_checked_abi_correct :
  forall program home_slot resident_register initial replacement
      baseline_out path_out,
    heap_residency_program_admissibleb
      home_slot resident_register program = true ->
    initialization_block false
      (heap_residency_program_projection program) = Some path_out ->
    heap_residency_baseline_execute home_slot program initial =
      Some baseline_out ->
    exists candidate_out,
      heap_residency_candidate_execute resident_register false program
        (heap_hide_reserved_register resident_register replacement initial) =
        Some (path_out, candidate_out) /\
      heap_full_state_equiv baseline_out
        (heap_finalize home_slot resident_register
          (register_cells (heap_scalar_state initial) resident_register)
          path_out candidate_out).
Proof.
  intros program home_slot resident_register initial replacement
    baseline_out path_out Hcheck Hinitialization Hbaseline.
  pose proof (proj1 (heap_residency_program_admissibleb_reflect
    home_slot resident_register program) Hcheck) as Hadmissible.
  destruct (heap_residency_candidate_execute_preserves_phase
    program home_slot resident_register false initial
    (heap_hide_reserved_register resident_register replacement initial)
    baseline_out path_out Hadmissible
    (heap_hide_reserved_register_preserves_phase
      home_slot resident_register replacement initial)
    Hinitialization Hbaseline)
    as [candidate_out [Hcandidate Hphase]].
  exists candidate_out. split; [exact Hcandidate|].
  apply heap_finalize_closes_phase; [exact Hphase|].
  symmetry. now apply
    heap_residency_baseline_execute_preserves_reserved_register
      with (program := program) (home_slot := home_slot).
Qed.

Record heap_residency_graph : Type := {
  heap_residency_entry : nat;
  heap_residency_blocks : list (list heap_residency_instruction);
  heap_residency_successors : list (list nat)
}.

Definition heap_residency_graph_projection
    (graph : heap_residency_graph) : initialization_graph :=
  {| initialization_entry := heap_residency_entry graph;
     initialization_blocks :=
       map heap_residency_program_projection
         (heap_residency_blocks graph);
     initialization_successors := heap_residency_successors graph |}.

Fixpoint heap_residency_path_program
    (graph : heap_residency_graph) (path : list nat)
    : option (list heap_residency_instruction) :=
  match path with
  | [] => Some []
  | block_id :: rest =>
      match nth_error (heap_residency_blocks graph) block_id,
            heap_residency_path_program graph rest with
      | Some block, Some tail => Some (block ++ tail)
      | _, _ => None
      end
  end.

Definition heap_residency_graph_admissibleb
    (home_slot resident_register : nat) (graph : heap_residency_graph)
    : bool :=
  forallb
    (heap_residency_program_admissibleb home_slot resident_register)
    (heap_residency_blocks graph).

Lemma heap_residency_program_projection_app :
  forall prefix suffix,
    heap_residency_program_projection (prefix ++ suffix) =
    heap_residency_program_projection prefix ++
      heap_residency_program_projection suffix.
Proof.
  induction prefix as [|instruction rest IH]; intros suffix; simpl.
  - reflexivity.
  - rewrite IH. now rewrite app_assoc.
Qed.

Lemma heap_residency_program_admissibleb_app :
  forall home_slot resident_register prefix suffix,
    heap_residency_program_admissibleb home_slot resident_register
      (prefix ++ suffix) =
    (heap_residency_program_admissibleb
       home_slot resident_register prefix &&
     heap_residency_program_admissibleb
       home_slot resident_register suffix)%bool.
Proof.
  intros. unfold heap_residency_program_admissibleb.
  now rewrite forallb_app.
Qed.

Theorem heap_residency_path_program_projects :
  forall graph path program,
    heap_residency_path_program graph path = Some program ->
    projected_path_program (heap_residency_graph_projection graph) path =
      Some (heap_residency_program_projection program).
Proof.
  intros graph path.
  induction path as [|block_id rest IH]; intros program Hprogram; simpl in *.
  - inversion Hprogram. reflexivity.
  - destruct (nth_error (heap_residency_blocks graph) block_id)
      as [block|] eqn:Hblock; try discriminate.
    destruct (heap_residency_path_program graph rest)
      as [tail|] eqn:Htail; try discriminate.
    inversion Hprogram; subst program.
    simpl. rewrite nth_error_map, Hblock. simpl.
    rewrite (IH tail eq_refl), heap_residency_program_projection_app.
    reflexivity.
Qed.

Theorem initialization_path_has_heap_residency_program :
  forall graph block_id path,
    initialization_path_from (heap_residency_graph_projection graph)
      block_id path ->
    exists program,
      heap_residency_path_program graph path = Some program.
Proof.
  intros graph block_id path Hpath.
  induction Hpath as
    [block_id projected_block Hblock |
     block_id projected_block successors next tail Hblock Hsuccessors
       Hnext Htail IH].
  - simpl in Hblock.
    destruct (nth_error_map_some_inv
      _ _ heap_residency_program_projection
      (heap_residency_blocks graph) block_id projected_block Hblock)
      as [block [Hmixed Hprojection]].
    exists block. simpl. rewrite Hmixed. simpl. now rewrite app_nil_r.
  - simpl in Hblock.
    destruct (nth_error_map_some_inv
      _ _ heap_residency_program_projection
      (heap_residency_blocks graph) block_id projected_block Hblock)
      as [block [Hmixed Hprojection]].
    destruct IH as [tail_program Htail_program].
    exists (block ++ tail_program). simpl.
    now rewrite Hmixed, Htail_program.
Qed.

Theorem heap_residency_path_program_is_admissible :
  forall graph path program home_slot resident_register,
    heap_residency_graph_admissibleb
      home_slot resident_register graph = true ->
    heap_residency_path_program graph path = Some program ->
    heap_residency_program_admissibleb
      home_slot resident_register program = true.
Proof.
  intros graph path.
  induction path as [|block_id rest IH];
    intros program home_slot resident_register Hgraph Hprogram; simpl in *.
  - inversion Hprogram. reflexivity.
  - destruct (nth_error (heap_residency_blocks graph) block_id)
      as [block|] eqn:Hblock; try discriminate.
    destruct (heap_residency_path_program graph rest)
      as [tail|] eqn:Htail; try discriminate.
    inversion Hprogram; subst program.
    rewrite heap_residency_program_admissibleb_app, Bool.andb_true_iff.
    split.
    + unfold heap_residency_graph_admissibleb in Hgraph.
      rewrite forallb_forall in Hgraph.
      apply Hgraph. now apply nth_error_In in Hblock.
    + exact (IH tail home_slot resident_register Hgraph eq_refl).
Qed.

(** Every finite structural path admitted by the sealed initialization graph
    preserves the exact successful heap/list projection.  The success premise
    exposes the partial checks (live handle, static length, and bounds) rather
    than silently assuming them away. *)
Theorem admitted_cfg_all_heap_residency_paths_abi_correct :
  forall proposed accepted graph path home_slot resident_register
      initial replacement baseline_out,
    admit_cfg_initialization_certificate proposed = Some accepted ->
    heap_residency_graph_projection graph = initialization_cfg accepted ->
    heap_residency_graph_admissibleb
      home_slot resident_register graph = true ->
    initialization_path_from (initialization_cfg accepted)
      (initialization_entry (initialization_cfg accepted)) path ->
    (exists program,
      heap_residency_path_program graph path = Some program /\
      heap_residency_baseline_execute home_slot program initial =
        Some baseline_out) ->
    exists program path_out candidate_out,
      heap_residency_path_program graph path = Some program /\
      initialization_path_execute
        (initialization_cfg accepted) path false = Some path_out /\
      heap_residency_baseline_execute home_slot program initial =
        Some baseline_out /\
      heap_residency_candidate_execute resident_register false program
        (heap_hide_reserved_register
          resident_register replacement initial) =
        Some (path_out, candidate_out) /\
      heap_full_state_equiv baseline_out
        (heap_finalize home_slot resident_register
          (register_cells (heap_scalar_state initial) resident_register)
          path_out candidate_out).
Proof.
  intros proposed accepted graph path home_slot resident_register
    initial replacement baseline_out Hadmitted Hprojection Hadmissible
    Hpath [program [Hprogram Hbaseline]].
  destruct (admitted_cfg_initialization_certificate_paths_safe
    proposed accepted path Hadmitted Hpath) as [path_out Hpath_out].
  assert (Hprojected :
    projected_path_program (initialization_cfg accepted) path =
      Some (heap_residency_program_projection program)).
  {
    rewrite <- Hprojection.
    now apply heap_residency_path_program_projects.
  }
  assert (Hinitialization :
    initialization_block false
      (heap_residency_program_projection program) = Some path_out).
  { eapply projected_path_program_reflects_initialization; eassumption. }
  assert (Hprogram_admissible :
    heap_residency_program_admissibleb
      home_slot resident_register program = true).
  { eapply heap_residency_path_program_is_admissible; eassumption. }
  destruct (heap_residency_program_checked_abi_correct
    program home_slot resident_register initial replacement baseline_out
    path_out Hprogram_admissible Hinitialization Hbaseline)
    as [candidate_out [Hcandidate Hequiv]].
  exists program, path_out, candidate_out.
  split; [exact Hprogram|].
  split; [exact Hpath_out|].
  split; [exact Hbaseline|].
  now split.
Qed.
