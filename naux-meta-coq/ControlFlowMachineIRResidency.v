(**
  NauxCore.ControlFlowMachineIRResidency

  Exact goto/branch/return observations for the bounded WP8C residency
  graphs.  Earlier layers prove state preservation for every admitted
  structural path; this layer retains each terminator operand and proves that
  a successful baseline block and its transformed block select the same next
  block or return the same value.

  Machine types are checked by the closed report bridge.  Boolean registers
  are represented as [0] or [1] in the scalar state; any other value fails
  closed in both executions.
*)

From Stdlib Require Import List Bool Arith Lia ZArith.
From NauxCore Require Import RegisterResidency DefiniteInitialization
  ProjectedCFGResidency ScalarMachineIRResidency HeapMachineIRResidency
  OwnershipMachineIRResidency.
Import ListNotations.
Open Scope Z_scope.

Inductive ownership_control_terminator : Type :=
| OwnershipControlGoto (target : nat)
| OwnershipControlBranch
    (condition if_true if_false : nat)
| OwnershipControlReturn (result : nat).

Definition ownership_control_successors
    (terminator : ownership_control_terminator) : list nat :=
  match terminator with
  | OwnershipControlGoto target => [target]
  | OwnershipControlBranch _ if_true if_false => [if_true; if_false]
  | OwnershipControlReturn _ => []
  end.

Definition ownership_control_terminator_admissible
    (resident_register : nat)
    (terminator : ownership_control_terminator) : Prop :=
  match terminator with
  | OwnershipControlGoto _ => True
  | OwnershipControlBranch condition _ _ =>
      condition <> resident_register
  | OwnershipControlReturn result => result <> resident_register
  end.

Definition ownership_control_terminator_admissibleb
    (resident_register : nat)
    (terminator : ownership_control_terminator) : bool :=
  match terminator with
  | OwnershipControlGoto _ => true
  | OwnershipControlBranch condition _ _ =>
      nat_negb condition resident_register
  | OwnershipControlReturn result => nat_negb result resident_register
  end.

Theorem ownership_control_terminator_admissibleb_reflect :
  forall resident_register terminator,
    ownership_control_terminator_admissibleb
      resident_register terminator = true <->
    ownership_control_terminator_admissible
      resident_register terminator.
Proof.
  intros resident_register terminator.
  destruct terminator; simpl; try tauto; apply nat_negb_reflect.
Qed.

Inductive ownership_control_outcome : Type :=
| OwnershipControlNext (target : nat)
| OwnershipControlReturned (value : Z).

Definition ownership_control_observe
    (terminator : ownership_control_terminator)
    (st : ownership_machine_state)
    : option ownership_control_outcome :=
  let scalar := heap_scalar_state (ownership_heap_state st) in
  match terminator with
  | OwnershipControlGoto target => Some (OwnershipControlNext target)
  | OwnershipControlBranch condition if_true if_false =>
      if ownership_register_defined st condition then
        let value := register_cells scalar condition in
        if Z.eqb value 1
        then Some (OwnershipControlNext if_true)
        else if Z.eqb value 0
             then Some (OwnershipControlNext if_false)
             else None
      else None
  | OwnershipControlReturn result =>
      if ownership_register_defined st result
      then Some (OwnershipControlReturned (register_cells scalar result))
      else None
  end.

Theorem ownership_control_observation_agrees :
  forall home_slot resident_register initialized terminator baseline
      candidate,
    ownership_control_terminator_admissible
      resident_register terminator ->
    ownership_projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    ownership_control_observe terminator candidate =
      ownership_control_observe terminator baseline.
Proof.
  intros home_slot resident_register initialized terminator baseline
    candidate Hadmissible
    [Hheap [Hslots [Hregisters Hoverflow]]].
  destruct terminator as [target | condition if_true if_false | result];
    simpl in *; try reflexivity.
  - rewrite Hregisters.
    destruct (ownership_register_defined baseline condition);
      simpl; try reflexivity.
    rewrite (heap_phase_register_agree home_slot resident_register
      initialized (ownership_heap_state baseline)
      (ownership_heap_state candidate) condition Hadmissible Hheap).
    reflexivity.
  - rewrite Hregisters.
    destruct (ownership_register_defined baseline result);
      simpl; try reflexivity.
    rewrite (heap_phase_register_agree home_slot resident_register
      initialized (ownership_heap_state baseline)
      (ownership_heap_state candidate) result Hadmissible Hheap).
    reflexivity.
Qed.

Record ownership_control_block : Type := {
  ownership_control_instructions : list ownership_machine_instruction;
  ownership_control_block_terminator : ownership_control_terminator
}.

Definition ownership_control_block_admissibleb
    (home_slot resident_register : nat)
    (block : ownership_control_block) : bool :=
  ownership_machine_program_admissibleb home_slot resident_register
    (ownership_control_instructions block) &&
  ownership_control_terminator_admissibleb resident_register
    (ownership_control_block_terminator block).

Lemma ownership_control_block_admissibleb_elim :
  forall home_slot resident_register block,
    ownership_control_block_admissibleb
      home_slot resident_register block = true ->
    Forall
      (ownership_machine_instruction_admissible
        home_slot resident_register)
      (ownership_control_instructions block) /\
    ownership_control_terminator_admissible resident_register
      (ownership_control_block_terminator block).
Proof.
  intros home_slot resident_register [program terminator] Hcheck.
  unfold ownership_control_block_admissibleb in Hcheck. simpl in Hcheck.
  rewrite Bool.andb_true_iff in Hcheck.
  destruct Hcheck as [Hprogram Hterminator].
  split.
  - now apply (proj1 (ownership_machine_program_admissibleb_reflect
      home_slot resident_register program)).
  - now apply (proj1 (ownership_control_terminator_admissibleb_reflect
      resident_register terminator)).
Qed.

Definition ownership_control_baseline_block
    (home_slot : nat) (block : ownership_control_block)
    (st : ownership_machine_state)
    : option (ownership_machine_state * ownership_control_outcome) :=
  match ownership_baseline_execute home_slot
          (ownership_control_instructions block) st with
  | Some stepped =>
      match ownership_control_observe
              (ownership_control_block_terminator block) stepped with
      | Some outcome => Some (stepped, outcome)
      | None => None
      end
  | None => None
  end.

Definition ownership_control_candidate_block
    (home_slot resident_register : nat) (initialized : bool)
    (block : ownership_control_block) (candidate : ownership_machine_state)
    : option
        (bool * (ownership_machine_state * ownership_control_outcome)) :=
  match ownership_candidate_execute home_slot resident_register initialized
          (ownership_control_instructions block) candidate with
  | Some (next, stepped) =>
      match ownership_control_observe
              (ownership_control_block_terminator block) stepped with
      | Some outcome => Some (next, (stepped, outcome))
      | None => None
      end
  | None => None
  end.

Theorem ownership_control_block_preserves_selection :
  forall home_slot resident_register initialized next block baseline
      candidate baseline_out outcome,
    ownership_control_block_admissibleb
      home_slot resident_register block = true ->
    initialization_block initialized
      (ownership_residency_program_projection
        (ownership_control_instructions block)) = Some next ->
    ownership_projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    ownership_control_baseline_block home_slot block baseline =
      Some (baseline_out, outcome) ->
    exists candidate_out,
      ownership_control_candidate_block home_slot resident_register
        initialized block candidate =
        Some (next, (candidate_out, outcome)) /\
      ownership_projected_phase_equiv home_slot resident_register next
        baseline_out candidate_out.
Proof.
  intros home_slot resident_register initialized next
    [program terminator] baseline candidate baseline_out outcome
    Hcheck Hinitialization Hphase Hbaseline.
  destruct (ownership_control_block_admissibleb_elim
    home_slot resident_register
    {| ownership_control_instructions := program;
       ownership_control_block_terminator := terminator |} Hcheck)
    as [Hprogram Hterminator].
  unfold ownership_control_baseline_block in Hbaseline. simpl in Hbaseline.
  destruct (ownership_baseline_execute home_slot program baseline)
    as [stepped_baseline|] eqn:Hbaseline_program; try discriminate.
  destruct (ownership_control_observe terminator stepped_baseline)
    as [baseline_outcome|] eqn:Hbaseline_terminator; try discriminate.
  inversion Hbaseline; subst stepped_baseline baseline_outcome.
  destruct (ownership_candidate_execute_preserves_phase
    program home_slot resident_register initialized baseline candidate
    baseline_out next Hprogram Hphase Hinitialization Hbaseline_program)
    as [candidate_out [Hcandidate_program Hout]].
  exists candidate_out. split; [|exact Hout].
  unfold ownership_control_candidate_block. simpl.
  rewrite Hcandidate_program.
  rewrite (ownership_control_observation_agrees home_slot resident_register
    next terminator baseline_out candidate_out Hterminator Hout).
  now rewrite Hbaseline_terminator.
Qed.

Record ownership_control_graph : Type := {
  ownership_control_entry : nat;
  ownership_control_blocks : list ownership_control_block
}.

Definition ownership_control_graph_projection
    (graph : ownership_control_graph) : ownership_residency_graph :=
  {| ownership_residency_entry := ownership_control_entry graph;
     ownership_residency_blocks :=
       map ownership_control_instructions (ownership_control_blocks graph);
     ownership_residency_successors :=
       map (fun block => ownership_control_successors
         (ownership_control_block_terminator block))
         (ownership_control_blocks graph) |}.

Definition ownership_control_graph_admissibleb
    (home_slot resident_register : nat)
    (graph : ownership_control_graph) : bool :=
  forallb
    (ownership_control_block_admissibleb home_slot resident_register)
    (ownership_control_blocks graph).

Lemma ownership_control_graph_block_is_admissible :
  forall graph block_id block home_slot resident_register,
    ownership_control_graph_admissibleb
      home_slot resident_register graph = true ->
    nth_error (ownership_control_blocks graph) block_id = Some block ->
    ownership_control_block_admissibleb
      home_slot resident_register block = true.
Proof.
  intros graph block_id block home_slot resident_register Hgraph Hblock.
  unfold ownership_control_graph_admissibleb in Hgraph.
  rewrite forallb_forall in Hgraph.
  apply Hgraph. now apply nth_error_In in Hblock.
Qed.

Theorem ownership_control_graph_block_preserves_selection :
  forall graph block_id block home_slot resident_register initialized next
      baseline candidate baseline_out outcome,
    ownership_control_graph_admissibleb
      home_slot resident_register graph = true ->
    nth_error (ownership_control_blocks graph) block_id = Some block ->
    initialization_block initialized
      (ownership_residency_program_projection
        (ownership_control_instructions block)) = Some next ->
    ownership_projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    ownership_control_baseline_block home_slot block baseline =
      Some (baseline_out, outcome) ->
    exists candidate_out,
      ownership_control_candidate_block home_slot resident_register
        initialized block candidate =
        Some (next, (candidate_out, outcome)) /\
      ownership_projected_phase_equiv home_slot resident_register next
        baseline_out candidate_out.
Proof.
  intros graph block_id block home_slot resident_register initialized next
    baseline candidate baseline_out outcome Hgraph Hblock.
  apply ownership_control_block_preserves_selection.
  now apply ownership_control_graph_block_is_admissible
    with (graph := graph) (block_id := block_id).
Qed.

Example control_branch_rejects_non_boolean_value :
  let scalar :=
    {| stack_cells := fun _ => 0;
       register_cells := fun _ => 2 |} in
  let heap :=
    {| heap_scalar_state := scalar;
       heap_objects := fun _ => None;
       heap_next_handle := 0%nat;
       heap_allocation_count := 0%nat;
       heap_release_count := 0%nat |} in
  let st :=
    {| ownership_heap_state := heap;
       ownership_slot_defined := fun _ => true;
       ownership_register_defined := fun _ => true;
       ownership_overflow_count := 0%nat |} in
  ownership_control_observe
    (OwnershipControlBranch 1%nat 2%nat 3%nat) st = None.
Proof. reflexivity. Qed.
