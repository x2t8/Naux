(**
  NauxCore.OwnershipMachineIRResidency

  Defined-cell and consuming-move semantics for the bounded WP8C Machine IR.
  This layer retains the keep/consume bit erased by the scalar data model,
  rejects reads from undefined virtual registers or stack slots, clears a
  consumed source register, and clears the owner slot after release.

  The data projection is exactly [HeapMachineIRResidency].  Types are checked
  by the closed report bridge but are not represented in this Rocq state.
  Fixed-width overflow, host allocation failure, branch selection, and native
  x86-64 execution remain outside the theorem.
*)

From Stdlib Require Import List Bool Arith Lia ZArith.
From NauxCore Require Import RegisterResidency DefiniteInitialization
  ProjectedCFGResidency ScalarMachineIRResidency HeapMachineIRResidency.
Import ListNotations.

Definition defined_map := nat -> bool.

Definition defined_update
    (cells : defined_map) (cell : nat) (value : bool) : defined_map :=
  fun query => if Nat.eqb query cell then value else cells query.

Lemma defined_update_eq : forall cells cell value,
  defined_update cells cell value cell = value.
Proof.
  intros. unfold defined_update. now rewrite Nat.eqb_refl.
Qed.

Lemma defined_update_neq : forall cells cell value query,
  query <> cell ->
  defined_update cells cell value query = cells query.
Proof.
  intros cells cell value query Hneq.
  unfold defined_update. apply Nat.eqb_neq in Hneq. now rewrite Hneq.
Qed.

Record ownership_machine_state : Type := {
  ownership_heap_state : heap_machine_state;
  ownership_slot_defined : defined_map;
  ownership_register_defined : defined_map
}.

(** Store instructions carry the report's ownership bit explicitly.  Plain
    instructions are admitted only when they are not an erased store. *)
Inductive ownership_machine_instruction : Type :=
| OwnershipPlain (instruction : heap_residency_instruction)
| OwnershipStoreSlot (slot source : nat) (keep : bool)
| OwnershipStoreHome (source : nat) (keep : bool).

Definition ownership_machine_projection
    (instruction : ownership_machine_instruction)
    : heap_residency_instruction :=
  match instruction with
  | OwnershipPlain plain => plain
  | OwnershipStoreSlot slot source _ =>
      HeapScalarInstruction
        (ScalarPassThrough (ScalarStoreSlot slot source))
  | OwnershipStoreHome source _ =>
      HeapScalarInstruction (ResidencyAccess (StoreHome source))
  end.

Definition ownership_residency_projection
    (instruction : ownership_machine_instruction)
    : list resident_instruction :=
  heap_residency_projection (ownership_machine_projection instruction).

Fixpoint ownership_program_projection
    (program : list ownership_machine_instruction)
    : list heap_residency_instruction :=
  match program with
  | [] => []
  | instruction :: rest =>
      ownership_machine_projection instruction ::
      ownership_program_projection rest
  end.

Fixpoint ownership_residency_program_projection
    (program : list ownership_machine_instruction)
    : list resident_instruction :=
  match program with
  | [] => []
  | instruction :: rest =>
      ownership_residency_projection instruction ++
      ownership_residency_program_projection rest
  end.

Definition ownership_plain_well_formed
    (instruction : heap_residency_instruction) : Prop :=
  match instruction with
  | HeapScalarInstruction (ResidencyAccess (StoreHome _)) => False
  | HeapScalarInstruction
      (ScalarPassThrough (ScalarStoreSlot _ _)) => False
  | _ => True
  end.

Definition ownership_plain_well_formedb
    (instruction : heap_residency_instruction) : bool :=
  match instruction with
  | HeapScalarInstruction (ResidencyAccess (StoreHome _)) => false
  | HeapScalarInstruction
      (ScalarPassThrough (ScalarStoreSlot _ _)) => false
  | _ => true
  end.

Lemma ownership_plain_well_formedb_reflect :
  forall instruction,
    ownership_plain_well_formedb instruction = true <->
    ownership_plain_well_formed instruction.
Proof.
  intros [[resident | scalar] | heap].
  - destruct resident; simpl; intuition discriminate.
  - destruct scalar; simpl; intuition discriminate.
  - destruct heap; simpl; intuition discriminate.
Qed.

Lemma ownership_heap_instruction_admissibleb_reflect :
  forall home_slot resident_register instruction,
    heap_residency_instruction_admissibleb
      home_slot resident_register instruction = true <->
    heap_residency_instruction_admissible
      home_slot resident_register instruction.
Proof.
  intros home_slot resident_register [scalar | heap]; simpl.
  - destruct scalar as [resident | ordinary]; simpl.
    + apply instruction_admissibleb_reflect.
    + apply scalar_instruction_admissibleb_reflect.
  - apply heap_machine_instruction_admissibleb_reflect.
Qed.

Definition ownership_machine_instruction_admissible
    (home_slot resident_register : nat)
    (instruction : ownership_machine_instruction) : Prop :=
  match instruction with
  | OwnershipPlain plain =>
      ownership_plain_well_formed plain /\
      heap_residency_instruction_admissible
        home_slot resident_register plain
  | OwnershipStoreSlot slot source _ =>
      slot <> home_slot /\ source <> resident_register
  | OwnershipStoreHome source _ => source <> resident_register
  end.

Definition ownership_machine_instruction_admissibleb
    (home_slot resident_register : nat)
    (instruction : ownership_machine_instruction) : bool :=
  match instruction with
  | OwnershipPlain plain =>
      ownership_plain_well_formedb plain &&
      heap_residency_instruction_admissibleb
        home_slot resident_register plain
  | OwnershipStoreSlot slot source _ =>
      nat_negb slot home_slot && nat_negb source resident_register
  | OwnershipStoreHome source _ => nat_negb source resident_register
  end.

Theorem ownership_machine_instruction_admissibleb_reflect :
  forall home_slot resident_register instruction,
    ownership_machine_instruction_admissibleb
      home_slot resident_register instruction = true <->
    ownership_machine_instruction_admissible
      home_slot resident_register instruction.
Proof.
  intros home_slot resident_register instruction.
  destruct instruction as [plain | slot source keep | source keep]; simpl.
  - rewrite Bool.andb_true_iff, ownership_plain_well_formedb_reflect,
      ownership_heap_instruction_admissibleb_reflect. tauto.
  - repeat rewrite Bool.andb_true_iff.
    repeat rewrite nat_negb_reflect. tauto.
  - apply nat_negb_reflect.
Qed.

Definition ownership_machine_program_admissibleb
    (home_slot resident_register : nat)
    (program : list ownership_machine_instruction) : bool :=
  forallb
    (ownership_machine_instruction_admissibleb
      home_slot resident_register) program.

Theorem ownership_machine_program_admissibleb_reflect :
  forall home_slot resident_register program,
    ownership_machine_program_admissibleb
      home_slot resident_register program = true <->
    Forall
      (ownership_machine_instruction_admissible
        home_slot resident_register) program.
Proof.
  intros home_slot resident_register program.
  unfold ownership_machine_program_admissibleb.
  rewrite forallb_forall, Forall_forall.
  split; intros H instruction Hin; specialize (H instruction Hin).
  - now apply (proj1 (ownership_machine_instruction_admissibleb_reflect
      home_slot resident_register instruction)).
  - now apply (proj2 (ownership_machine_instruction_admissibleb_reflect
      home_slot resident_register instruction)).
Qed.

Definition consume_if_requested
    (registers : defined_map) (source : nat) (keep : bool)
    : defined_map :=
  if keep then registers else defined_update registers source false.

Definition ownership_plain_definedness_step
    (home_slot : nat) (instruction : heap_residency_instruction)
    (slots registers : defined_map)
    : option (defined_map * defined_map) :=
  match instruction with
  | HeapScalarInstruction (ResidencyAccess resident) =>
      match resident with
      | UpdateHome _ =>
          if slots home_slot then Some (slots, registers) else None
      | LoadHome destination =>
          if slots home_slot
          then Some (slots, defined_update registers destination true)
          else None
      | StoreHome _ => None
      end
  | HeapScalarInstruction (ScalarPassThrough scalar) =>
      match scalar with
      | ScalarConst destination _ =>
          Some (slots, defined_update registers destination true)
      | ScalarLoadSlot destination slot =>
          if slots slot
          then Some (slots, defined_update registers destination true)
          else None
      | ScalarStoreSlot _ _ => None
      | ScalarAddSlotConst slot _ =>
          if slots slot then Some (slots, registers) else None
      | ScalarBinary destination _ left_register right_register
      | ScalarCompare destination _ left_register right_register =>
          if registers left_register && registers right_register
          then Some (slots, defined_update registers destination true)
          else None
      end
  | HeapPassThrough heap =>
      match heap with
      | HeapRangeAllocateInit destination _ =>
          Some (slots, defined_update registers destination true)
      | HeapListLengthStatic destination slot _ =>
          if slots slot
          then Some (slots, defined_update registers destination true)
          else None
      | HeapListLoadChecked destination list_register index_register =>
          if registers list_register && registers index_register
          then Some (slots, defined_update registers destination true)
          else None
      | HeapListStoreChecked destination list_register index_register
          value_register =>
          if registers list_register && registers index_register &&
               registers value_register
          then Some (slots, defined_update registers destination true)
          else None
      | HeapReleaseOwnedList slot =>
          if slots slot
          then Some (defined_update slots slot false, registers)
          else None
      end
  end.

Definition ownership_definedness_step
    (home_slot : nat) (instruction : ownership_machine_instruction)
    (slots registers : defined_map)
    : option (defined_map * defined_map) :=
  match instruction with
  | OwnershipPlain plain =>
      ownership_plain_definedness_step home_slot plain slots registers
  | OwnershipStoreSlot slot source keep =>
      if registers source
      then Some
        (defined_update slots slot true,
         consume_if_requested registers source keep)
      else None
  | OwnershipStoreHome source keep =>
      if registers source
      then Some
        (defined_update slots home_slot true,
         consume_if_requested registers source keep)
      else None
  end.

Definition ownership_projected_phase_equiv
    (home_slot resident_register : nat) (initialized : bool)
    (baseline candidate : ownership_machine_state) : Prop :=
  heap_projected_phase_equiv home_slot resident_register initialized
    (ownership_heap_state baseline) (ownership_heap_state candidate) /\
  ownership_slot_defined candidate = ownership_slot_defined baseline /\
  ownership_register_defined candidate =
    ownership_register_defined baseline.

Definition ownership_full_state_equiv
    (baseline candidate : ownership_machine_state) : Prop :=
  heap_full_state_equiv
    (ownership_heap_state baseline) (ownership_heap_state candidate) /\
  ownership_slot_defined candidate = ownership_slot_defined baseline /\
  ownership_register_defined candidate =
    ownership_register_defined baseline.

Definition ownership_hide_reserved_register
    (resident_register : nat) (replacement : Z)
    (st : ownership_machine_state) : ownership_machine_state :=
  {| ownership_heap_state :=
       heap_hide_reserved_register resident_register replacement
         (ownership_heap_state st);
     ownership_slot_defined := ownership_slot_defined st;
     ownership_register_defined := ownership_register_defined st |}.

Lemma ownership_hide_reserved_register_preserves_phase :
  forall home_slot resident_register replacement st,
    ownership_projected_phase_equiv home_slot resident_register false st
      (ownership_hide_reserved_register resident_register replacement st).
Proof.
  intros. unfold ownership_projected_phase_equiv,
    ownership_hide_reserved_register. simpl.
  split.
  - apply heap_hide_reserved_register_preserves_phase.
  - now split.
Qed.

Definition ownership_finalize
    (home_slot resident_register : nat) (saved_value : Z)
    (initialized : bool) (candidate : ownership_machine_state)
    : ownership_machine_state :=
  {| ownership_heap_state :=
       heap_finalize home_slot resident_register saved_value initialized
         (ownership_heap_state candidate);
     ownership_slot_defined := ownership_slot_defined candidate;
     ownership_register_defined := ownership_register_defined candidate |}.

Theorem ownership_finalize_closes_phase :
  forall home_slot resident_register initialized baseline candidate
      saved_value,
    ownership_projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    saved_value = register_cells
      (heap_scalar_state (ownership_heap_state baseline))
      resident_register ->
    ownership_full_state_equiv baseline
      (ownership_finalize home_slot resident_register saved_value initialized
        candidate).
Proof.
  intros home_slot resident_register initialized baseline candidate
    saved_value [Hphase [Hslots Hregisters]] Hsaved.
  unfold ownership_full_state_equiv, ownership_finalize. simpl.
  split.
  - now apply heap_finalize_closes_phase.
  - now split.
Qed.

Definition ownership_baseline_step
    (home_slot : nat) (instruction : ownership_machine_instruction)
    (st : ownership_machine_state) : option ownership_machine_state :=
  match ownership_definedness_step home_slot instruction
          (ownership_slot_defined st) (ownership_register_defined st),
        heap_residency_baseline_step home_slot
          (ownership_machine_projection instruction)
          (ownership_heap_state st) with
  | Some (slots, registers), Some heap =>
      Some
        {| ownership_heap_state := heap;
           ownership_slot_defined := slots;
           ownership_register_defined := registers |}
  | _, _ => None
  end.

Definition ownership_candidate_step
    (home_slot resident_register : nat) (initialized : bool)
    (instruction : ownership_machine_instruction)
    (candidate : ownership_machine_state)
    : option (bool * ownership_machine_state) :=
  match ownership_definedness_step home_slot instruction
          (ownership_slot_defined candidate)
          (ownership_register_defined candidate),
        heap_residency_candidate_step resident_register initialized
          (ownership_machine_projection instruction)
          (ownership_heap_state candidate) with
  | Some (slots, registers), Some (next, heap) =>
      Some (next,
        {| ownership_heap_state := heap;
           ownership_slot_defined := slots;
           ownership_register_defined := registers |})
  | _, _ => None
  end.

Lemma ownership_admissible_projects :
  forall home_slot resident_register instruction,
    ownership_machine_instruction_admissible
      home_slot resident_register instruction ->
    heap_residency_instruction_admissible home_slot resident_register
      (ownership_machine_projection instruction).
Proof.
  intros home_slot resident_register instruction Hadmissible.
  destruct instruction as [plain | slot source keep | source keep]; simpl in *.
  - tauto.
  - exact Hadmissible.
  - exact Hadmissible.
Qed.

Theorem ownership_instruction_preserves_phase :
  forall home_slot resident_register initialized next instruction baseline
      candidate baseline_out,
    ownership_machine_instruction_admissible
      home_slot resident_register instruction ->
    initialization_block initialized
      (ownership_residency_projection instruction) = Some next ->
    ownership_projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    ownership_baseline_step home_slot instruction baseline =
      Some baseline_out ->
    exists candidate_out,
      ownership_candidate_step home_slot resident_register initialized
        instruction candidate = Some (next, candidate_out) /\
      ownership_projected_phase_equiv home_slot resident_register next
        baseline_out candidate_out.
Proof.
  intros home_slot resident_register initialized next instruction baseline
    candidate baseline_out Hadmissible Hinitialization
    [Hheap [Hslots Hregisters]] Hbaseline.
  unfold ownership_baseline_step in Hbaseline.
  destruct (ownership_definedness_step home_slot instruction
    (ownership_slot_defined baseline)
    (ownership_register_defined baseline))
    as [[slots_out registers_out]|] eqn:Hdefined; try discriminate.
  destruct (heap_residency_baseline_step home_slot
    (ownership_machine_projection instruction)
    (ownership_heap_state baseline)) as [heap_out|] eqn:Hbaseline_heap;
    try discriminate.
  inversion Hbaseline; subst baseline_out.
  assert (Hcandidate_defined :
    ownership_definedness_step home_slot instruction
      (ownership_slot_defined candidate)
      (ownership_register_defined candidate) =
    Some (slots_out, registers_out)).
  { now rewrite Hslots, Hregisters. }
  destruct (heap_residency_instruction_preserves_phase
    home_slot resident_register initialized next
    (ownership_machine_projection instruction)
    (ownership_heap_state baseline) (ownership_heap_state candidate)
    heap_out (ownership_admissible_projects _ _ _ Hadmissible)
    Hinitialization Hheap Hbaseline_heap)
    as [candidate_heap [Hcandidate_heap Hheap_out]].
  exists
    {| ownership_heap_state := candidate_heap;
       ownership_slot_defined := slots_out;
       ownership_register_defined := registers_out |}.
  split.
  - unfold ownership_candidate_step.
    now rewrite Hcandidate_defined, Hcandidate_heap.
  - unfold ownership_projected_phase_equiv. simpl.
    split; [exact Hheap_out|]. now split.
Qed.

Fixpoint ownership_baseline_execute
    (home_slot : nat) (program : list ownership_machine_instruction)
    (st : ownership_machine_state) : option ownership_machine_state :=
  match program with
  | [] => Some st
  | instruction :: rest =>
      match ownership_baseline_step home_slot instruction st with
      | Some stepped => ownership_baseline_execute home_slot rest stepped
      | None => None
      end
  end.

Fixpoint ownership_candidate_execute
    (home_slot resident_register : nat) (initialized : bool)
    (program : list ownership_machine_instruction)
    (candidate : ownership_machine_state)
    : option (bool * ownership_machine_state) :=
  match program with
  | [] => Some (initialized, candidate)
  | instruction :: rest =>
      match ownership_candidate_step home_slot resident_register initialized
        instruction candidate with
      | Some (next, stepped) =>
          ownership_candidate_execute home_slot resident_register next
            rest stepped
      | None => None
      end
  end.

Theorem ownership_candidate_execute_preserves_phase :
  forall program home_slot resident_register initialized baseline candidate
      baseline_out path_out,
    Forall
      (ownership_machine_instruction_admissible
        home_slot resident_register) program ->
    ownership_projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    initialization_block initialized
      (ownership_residency_program_projection program) = Some path_out ->
    ownership_baseline_execute home_slot program baseline =
      Some baseline_out ->
    exists candidate_out,
      ownership_candidate_execute home_slot resident_register initialized
        program candidate = Some (path_out, candidate_out) /\
      ownership_projected_phase_equiv home_slot resident_register path_out
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
      (ownership_residency_projection instruction))
      as [next|] eqn:Hnext.
    2: {
      rewrite initialization_block_app, Hnext in Hinitialization.
      discriminate.
    }
    rewrite initialization_block_app, Hnext in Hinitialization.
    destruct (ownership_baseline_step home_slot instruction baseline)
      as [stepped_baseline|] eqn:Hbaseline_step; try discriminate.
    destruct (ownership_instruction_preserves_phase
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

Lemma ownership_baseline_step_preserves_reserved_register :
  forall home_slot resident_register instruction initial final,
    ownership_machine_instruction_admissible
      home_slot resident_register instruction ->
    ownership_baseline_step home_slot instruction initial = Some final ->
    register_cells
      (heap_scalar_state (ownership_heap_state final)) resident_register =
    register_cells
      (heap_scalar_state (ownership_heap_state initial)) resident_register.
Proof.
  intros home_slot resident_register instruction initial final
    Hadmissible Hstep.
  unfold ownership_baseline_step in Hstep.
  destruct (ownership_definedness_step home_slot instruction
    (ownership_slot_defined initial)
    (ownership_register_defined initial))
    as [[slots registers]|]; try discriminate.
  destruct (heap_residency_baseline_step home_slot
    (ownership_machine_projection instruction)
    (ownership_heap_state initial)) as [heap|] eqn:Hheap; try discriminate.
  inversion Hstep; subst final. simpl.
  now apply heap_residency_baseline_step_preserves_reserved_register
    with (home_slot := home_slot)
      (instruction := ownership_machine_projection instruction);
    [apply ownership_admissible_projects|].
Qed.

Lemma ownership_baseline_execute_preserves_reserved_register :
  forall program home_slot resident_register initial final,
    Forall
      (ownership_machine_instruction_admissible
        home_slot resident_register) program ->
    ownership_baseline_execute home_slot program initial = Some final ->
    register_cells
      (heap_scalar_state (ownership_heap_state final)) resident_register =
    register_cells
      (heap_scalar_state (ownership_heap_state initial)) resident_register.
Proof.
  induction program as [|instruction rest IH];
    intros home_slot resident_register initial final Hadmissible Hexecute;
    simpl in Hexecute.
  - inversion Hexecute. reflexivity.
  - inversion Hadmissible as [|? ? Hinstruction Hrest]; subst.
    destruct (ownership_baseline_step home_slot instruction initial)
      as [stepped|] eqn:Hstep; try discriminate.
    rewrite (IH home_slot resident_register stepped final Hrest Hexecute).
    now apply ownership_baseline_step_preserves_reserved_register
      with (home_slot := home_slot) (instruction := instruction).
Qed.

Theorem ownership_program_checked_abi_correct :
  forall program home_slot resident_register initial replacement
      baseline_out path_out,
    ownership_machine_program_admissibleb
      home_slot resident_register program = true ->
    initialization_block false
      (ownership_residency_program_projection program) = Some path_out ->
    ownership_baseline_execute home_slot program initial =
      Some baseline_out ->
    exists candidate_out,
      ownership_candidate_execute home_slot resident_register false program
        (ownership_hide_reserved_register
          resident_register replacement initial) =
        Some (path_out, candidate_out) /\
      ownership_full_state_equiv baseline_out
        (ownership_finalize home_slot resident_register
          (register_cells
            (heap_scalar_state (ownership_heap_state initial))
            resident_register)
          path_out candidate_out).
Proof.
  intros program home_slot resident_register initial replacement
    baseline_out path_out Hcheck Hinitialization Hbaseline.
  pose proof (proj1 (ownership_machine_program_admissibleb_reflect
    home_slot resident_register program) Hcheck) as Hadmissible.
  destruct (ownership_candidate_execute_preserves_phase
    program home_slot resident_register false initial
    (ownership_hide_reserved_register
      resident_register replacement initial)
    baseline_out path_out Hadmissible
    (ownership_hide_reserved_register_preserves_phase
      home_slot resident_register replacement initial)
    Hinitialization Hbaseline)
    as [candidate_out [Hcandidate Hphase]].
  exists candidate_out. split; [exact Hcandidate|].
  apply ownership_finalize_closes_phase; [exact Hphase|].
  symmetry. now apply
    ownership_baseline_execute_preserves_reserved_register
      with (program := program) (home_slot := home_slot).
Qed.

Lemma ownership_residency_program_projection_is_heap_projection :
  forall program,
    ownership_residency_program_projection program =
    heap_residency_program_projection
      (ownership_program_projection program).
Proof.
  induction program as [|instruction rest IH]; simpl.
  - reflexivity.
  - now rewrite IH.
Qed.

(** Executable witnesses for the ownership effects that were previously an
    explicit non-claim. *)
Example ownership_consume_clears_source :
  forall slots registers slot source,
    registers source = true ->
    exists slots_out registers_out,
      ownership_definedness_step 0%nat
        (OwnershipStoreSlot slot source false) slots registers =
          Some (slots_out, registers_out) /\
      slots_out slot = true /\ registers_out source = false.
Proof.
  intros slots registers slot source Hsource.
  unfold ownership_definedness_step. rewrite Hsource.
  exists (defined_update slots slot true),
    (defined_update registers source false).
  repeat split; apply defined_update_eq.
Qed.

Example ownership_keep_retains_source :
  forall slots registers slot source,
    registers source = true ->
    exists slots_out registers_out,
      ownership_definedness_step 0%nat
        (OwnershipStoreSlot slot source true) slots registers =
          Some (slots_out, registers_out) /\
      slots_out slot = true /\ registers_out source = true.
Proof.
  intros slots registers slot source Hsource.
  unfold ownership_definedness_step. rewrite Hsource.
  exists (defined_update slots slot true), registers.
  repeat split; try assumption. apply defined_update_eq.
Qed.

Example ownership_release_clears_slot :
  forall slots registers slot,
    slots slot = true ->
    exists slots_out registers_out,
      ownership_definedness_step 0%nat
        (OwnershipPlain
          (HeapPassThrough (HeapReleaseOwnedList slot)))
        slots registers = Some (slots_out, registers_out) /\
      slots_out slot = false.
Proof.
  intros slots registers slot Hslot.
  unfold ownership_definedness_step,
    ownership_plain_definedness_step. rewrite Hslot.
  exists (defined_update slots slot false), registers.
  split; [reflexivity|apply defined_update_eq].
Qed.

Record ownership_residency_graph : Type := {
  ownership_residency_entry : nat;
  ownership_residency_blocks :
    list (list ownership_machine_instruction);
  ownership_residency_successors : list (list nat)
}.

Definition ownership_residency_graph_projection
    (graph : ownership_residency_graph) : heap_residency_graph :=
  {| heap_residency_entry := ownership_residency_entry graph;
     heap_residency_blocks :=
       map ownership_program_projection
         (ownership_residency_blocks graph);
     heap_residency_successors := ownership_residency_successors graph |}.

Definition ownership_initialization_graph_projection
    (graph : ownership_residency_graph) : initialization_graph :=
  heap_residency_graph_projection
    (ownership_residency_graph_projection graph).

Fixpoint ownership_residency_path_program
    (graph : ownership_residency_graph) (path : list nat)
    : option (list ownership_machine_instruction) :=
  match path with
  | [] => Some []
  | block_id :: rest =>
      match nth_error (ownership_residency_blocks graph) block_id,
            ownership_residency_path_program graph rest with
      | Some block, Some tail => Some (block ++ tail)
      | _, _ => None
      end
  end.

Definition ownership_residency_graph_admissibleb
    (home_slot resident_register : nat)
    (graph : ownership_residency_graph) : bool :=
  forallb
    (ownership_machine_program_admissibleb
      home_slot resident_register)
    (ownership_residency_blocks graph).

Lemma ownership_program_projection_app :
  forall prefix suffix,
    ownership_program_projection (prefix ++ suffix) =
    ownership_program_projection prefix ++
      ownership_program_projection suffix.
Proof.
  induction prefix as [|instruction rest IH]; intros suffix; simpl.
  - reflexivity.
  - now rewrite IH.
Qed.

Lemma ownership_residency_program_projection_app :
  forall prefix suffix,
    ownership_residency_program_projection (prefix ++ suffix) =
    ownership_residency_program_projection prefix ++
      ownership_residency_program_projection suffix.
Proof.
  induction prefix as [|instruction rest IH]; intros suffix; simpl.
  - reflexivity.
  - rewrite IH. now rewrite app_assoc.
Qed.

Lemma ownership_machine_program_admissibleb_app :
  forall home_slot resident_register prefix suffix,
    ownership_machine_program_admissibleb home_slot resident_register
      (prefix ++ suffix) =
    (ownership_machine_program_admissibleb
       home_slot resident_register prefix &&
     ownership_machine_program_admissibleb
       home_slot resident_register suffix)%bool.
Proof.
  intros. unfold ownership_machine_program_admissibleb.
  now rewrite forallb_app.
Qed.

Theorem ownership_residency_path_program_projects :
  forall graph path program,
    ownership_residency_path_program graph path = Some program ->
    heap_residency_path_program
      (ownership_residency_graph_projection graph) path =
      Some (ownership_program_projection program).
Proof.
  intros graph path.
  induction path as [|block_id rest IH]; intros program Hprogram; simpl in *.
  - inversion Hprogram. reflexivity.
  - destruct (nth_error (ownership_residency_blocks graph) block_id)
      as [block|] eqn:Hblock; try discriminate.
    destruct (ownership_residency_path_program graph rest)
      as [tail|] eqn:Htail; try discriminate.
    inversion Hprogram; subst program.
    simpl. rewrite nth_error_map, Hblock. simpl.
    rewrite (IH tail eq_refl), ownership_program_projection_app.
    reflexivity.
Qed.

Lemma heap_path_has_ownership_residency_program :
  forall graph path heap_program,
    heap_residency_path_program
      (ownership_residency_graph_projection graph) path =
      Some heap_program ->
    exists program,
      ownership_residency_path_program graph path = Some program.
Proof.
  intros graph path.
  induction path as [|block_id rest IH]; intros heap_program Hprogram;
    simpl in *.
  - exists []. reflexivity.
  - destruct (nth_error (ownership_residency_blocks graph) block_id)
      as [block|] eqn:Hblock.
    2: { rewrite nth_error_map, Hblock in Hprogram. discriminate. }
    rewrite nth_error_map, Hblock in Hprogram. simpl in Hprogram.
    destruct (heap_residency_path_program
      (ownership_residency_graph_projection graph) rest)
      as [heap_tail|] eqn:Htail; try discriminate.
    destruct (IH heap_tail eq_refl) as [tail Hownership_tail].
    exists (block ++ tail). simpl.
    now rewrite Hownership_tail.
Qed.

Theorem initialization_path_has_ownership_residency_program :
  forall graph block_id path,
    initialization_path_from
      (ownership_initialization_graph_projection graph) block_id path ->
    exists program,
      ownership_residency_path_program graph path = Some program.
Proof.
  intros graph block_id path Hpath.
  assert (Hheap_path :
    initialization_path_from
      (heap_residency_graph_projection
        (ownership_residency_graph_projection graph)) block_id path).
  { exact Hpath. }
  destruct (initialization_path_has_heap_residency_program
    (ownership_residency_graph_projection graph) block_id path Hheap_path)
    as [heap_program Hheap_program].
  now apply heap_path_has_ownership_residency_program
    with (heap_program := heap_program).
Qed.

Theorem ownership_residency_path_program_is_admissible :
  forall graph path program home_slot resident_register,
    ownership_residency_graph_admissibleb
      home_slot resident_register graph = true ->
    ownership_residency_path_program graph path = Some program ->
    ownership_machine_program_admissibleb
      home_slot resident_register program = true.
Proof.
  intros graph path.
  induction path as [|block_id rest IH];
    intros program home_slot resident_register Hgraph Hprogram; simpl in *.
  - inversion Hprogram. reflexivity.
  - destruct (nth_error (ownership_residency_blocks graph) block_id)
      as [block|] eqn:Hblock; try discriminate.
    destruct (ownership_residency_path_program graph rest)
      as [tail|] eqn:Htail; try discriminate.
    inversion Hprogram; subst program.
    rewrite ownership_machine_program_admissibleb_app,
      Bool.andb_true_iff.
    split.
    + unfold ownership_residency_graph_admissibleb in Hgraph.
      rewrite forallb_forall in Hgraph.
      apply Hgraph. now apply nth_error_In in Hblock.
    + exact (IH tail home_slot resident_register Hgraph eq_refl).
Qed.

Theorem ownership_residency_path_program_reflects_initialization :
  forall graph path program initialized path_out,
    ownership_residency_path_program graph path = Some program ->
    initialization_path_execute
      (ownership_initialization_graph_projection graph)
      path initialized = Some path_out ->
    initialization_block initialized
      (ownership_residency_program_projection program) = Some path_out.
Proof.
  intros graph path program initialized path_out Hprogram Hexecute.
  assert (Hheap_program :
    heap_residency_path_program
      (ownership_residency_graph_projection graph) path =
      Some (ownership_program_projection program)).
  { now apply ownership_residency_path_program_projects. }
  pose proof (heap_residency_path_program_projects
    (ownership_residency_graph_projection graph) path
    (ownership_program_projection program) Hheap_program) as Hprojected.
  apply projected_path_program_reflects_initialization with
    (graph := ownership_initialization_graph_projection graph)
      (path := path).
  - rewrite ownership_residency_program_projection_is_heap_projection.
    exact Hprojected.
  - exact Hexecute.
Qed.

(** Every finite structural path accepted by the sealed initialization
    certificate preserves both the successful data/heap semantics and the
    exact defined/undefined ownership state emitted from the report. *)
Theorem admitted_cfg_all_ownership_residency_paths_abi_correct :
  forall proposed accepted graph path home_slot resident_register
      initial replacement baseline_out,
    admit_cfg_initialization_certificate proposed = Some accepted ->
    ownership_initialization_graph_projection graph =
      initialization_cfg accepted ->
    ownership_residency_graph_admissibleb
      home_slot resident_register graph = true ->
    initialization_path_from (initialization_cfg accepted)
      (initialization_entry (initialization_cfg accepted)) path ->
    (exists program,
      ownership_residency_path_program graph path = Some program /\
      ownership_baseline_execute home_slot program initial =
        Some baseline_out) ->
    exists program path_out candidate_out,
      ownership_residency_path_program graph path = Some program /\
      initialization_path_execute
        (initialization_cfg accepted) path false = Some path_out /\
      ownership_baseline_execute home_slot program initial =
        Some baseline_out /\
      ownership_candidate_execute home_slot resident_register false program
        (ownership_hide_reserved_register
          resident_register replacement initial) =
        Some (path_out, candidate_out) /\
      ownership_full_state_equiv baseline_out
        (ownership_finalize home_slot resident_register
          (register_cells
            (heap_scalar_state (ownership_heap_state initial))
            resident_register)
          path_out candidate_out).
Proof.
  intros proposed accepted graph path home_slot resident_register
    initial replacement baseline_out Hadmitted Hprojection Hadmissible
    Hpath [program [Hprogram Hbaseline]].
  destruct (admitted_cfg_initialization_certificate_paths_safe
    proposed accepted path Hadmitted Hpath) as [path_out Hpath_out].
  assert (Hinitialization :
    initialization_block false
      (ownership_residency_program_projection program) = Some path_out).
  {
    apply ownership_residency_path_program_reflects_initialization
      with (graph := graph) (path := path).
    - exact Hprogram.
    - now rewrite Hprojection.
  }
  assert (Hprogram_admissible :
    ownership_machine_program_admissibleb
      home_slot resident_register program = true).
  { eapply ownership_residency_path_program_is_admissible; eassumption. }
  destruct (ownership_program_checked_abi_correct
    program home_slot resident_register initial replacement baseline_out
    path_out Hprogram_admissible Hinitialization Hbaseline)
    as [candidate_out [Hcandidate Hequiv]].
  exists program, path_out, candidate_out.
  split; [exact Hprogram|].
  split; [exact Hpath_out|].
  split; [exact Hbaseline|].
  now split.
Qed.
