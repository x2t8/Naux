(**
  NauxCore.ProjectedCFGResidency

  Semantic preservation for the bounded physical-access projection accepted
  by [DefiniteInitialization].  The candidate may hide the reserved register
  before the first store.  That first store establishes residency; subsequent
  accesses preserve it; final spill and callee-saved restoration recover the
  complete baseline state.

  This file deliberately models only [resident_instruction] traces.  It does
  not assign semantics to pass-through Machine IR instructions, parse a WP8C
  report, or prove whole-compiler correctness.
*)

From Stdlib Require Import List Bool Arith Lia ZArith.
From NauxCore Require Import RegisterResidency DefiniteInitialization.
Import ListNotations.

(** Reserve the candidate register without changing any observable location.
    The replacement value is intentionally arbitrary. *)
Definition hide_reserved_register
    (reserved_register : nat) (replacement : Z) (st : machine_state)
    : machine_state :=
  with_registers st
    (map_update (register_cells st) reserved_register replacement).

Theorem hide_reserved_register_preserves_observable :
  forall reserved_register replacement st,
    observable_equiv reserved_register st
      (hide_reserved_register reserved_register replacement st).
Proof.
  intros reserved_register replacement st.
  split.
  - reflexivity.
  - intros reg Hreg. simpl.
    now rewrite map_update_neq by exact Hreg.
Qed.

(** Before initialization, the reserved register is hidden.  Afterwards it
    contains the authoritative home value. *)
Definition projected_phase_equiv
    (home_slot resident_register : nat) (initialized : bool)
    (baseline candidate : machine_state) : Prop :=
  if initialized
  then resident_equiv home_slot resident_register baseline candidate
  else observable_equiv resident_register baseline candidate.

Definition projected_candidate_step
    (resident_register : nat) (initialized : bool)
    (instruction : resident_instruction) (candidate : machine_state)
    : option (bool * machine_state) :=
  match initialization_step initialized instruction with
  | Some next =>
      Some (next,
        resident_instruction_step resident_register instruction candidate)
  | None => None
  end.

Fixpoint projected_candidate_execute
    (resident_register : nat) (initialized : bool)
    (program : list resident_instruction) (candidate : machine_state)
    : option (bool * machine_state) :=
  match program with
  | [] => Some (initialized, candidate)
  | instruction :: rest =>
      match projected_candidate_step
        resident_register initialized instruction candidate with
      | Some (next, stepped) =>
          projected_candidate_execute resident_register next rest stepped
      | None => None
      end
  end.

Theorem projected_instruction_preserves_phase :
  forall home_slot resident_register initialized next baseline candidate
      instruction,
    instruction_admissible resident_register instruction ->
    initialization_step initialized instruction = Some next ->
    projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    projected_phase_equiv home_slot resident_register next
      (baseline_instruction_step home_slot instruction baseline)
      (resident_instruction_step resident_register instruction candidate).
Proof.
  intros home_slot resident_register initialized next baseline candidate
    instruction Hadmissible Hstep Hequiv.
  destruct initialized.
  - assert (Hnext : next = true).
    { destruct instruction; simpl in Hstep; now inversion Hstep. }
    subst next. unfold projected_phase_equiv in *. simpl in *.
    now apply resident_instruction_preserves_equiv.
  - destruct instruction as [op | destination | source];
      simpl in Hstep; try discriminate.
    inversion Hstep; subst.
    unfold projected_phase_equiv in *. simpl in *.
    now apply store_home_from_observable_state_establishes_equiv.
Qed.

Theorem projected_candidate_execute_preserves_phase :
  forall program home_slot resident_register initialized
      baseline candidate path_out,
    Forall (instruction_admissible resident_register) program ->
    projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    initialization_block initialized program = Some path_out ->
    exists candidate_out,
      projected_candidate_execute resident_register initialized
        program candidate = Some (path_out, candidate_out) /\
      projected_phase_equiv home_slot resident_register path_out
        (baseline_execute home_slot program baseline) candidate_out.
Proof.
  induction program as [|instruction rest IH];
    intros home_slot resident_register initialized baseline candidate
      path_out Hadmissible Hequiv Hinitialization; simpl in *.
  - inversion Hinitialization; subst.
    exists candidate. split; reflexivity || exact Hequiv.
  - inversion Hadmissible as [|? ? Hinstruction Hrest]; subst.
    destruct (initialization_step initialized instruction)
      as [next|] eqn:Hstep; try discriminate.
    assert (Hphase :
      projected_phase_equiv home_slot resident_register next
        (baseline_instruction_step home_slot instruction baseline)
        (resident_instruction_step resident_register instruction candidate)).
    { eapply projected_instruction_preserves_phase; eassumption. }
    destruct (IH home_slot resident_register next
      (baseline_instruction_step home_slot instruction baseline)
      (resident_instruction_step resident_register instruction candidate)
      path_out Hrest Hphase Hinitialization)
      as [candidate_out [Hexecute Hout]].
    exists candidate_out. split; [|exact Hout].
    unfold projected_candidate_step. now rewrite Hstep.
Qed.

Definition projected_finalize
    (home_slot resident_register : nat) (saved_value : Z)
    (initialized : bool) (candidate : machine_state) : machine_state :=
  restore_reserved_register resident_register saved_value
    (if initialized
     then spill_home home_slot resident_register candidate
     else candidate).

Theorem projected_finalize_closes_phase :
  forall home_slot resident_register initialized baseline candidate
      saved_value,
    projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    saved_value = register_cells baseline resident_register ->
    full_state_equiv baseline
      (projected_finalize home_slot resident_register saved_value
        initialized candidate).
Proof.
  intros home_slot resident_register initialized baseline candidate
    saved_value Hphase Hsaved.
  destruct initialized; simpl in Hphase |- *.
  - apply restore_reserved_register_closes_equiv; [|exact Hsaved].
    now apply spill_restores_observable_state.
  - now apply restore_reserved_register_closes_equiv.
Qed.

(** End-to-end semantics for any admitted straight-line physical-access
    projection.  Initialization may happen in a later block, or not at all
    when the trace never reads the home. *)
Theorem projected_program_checked_abi_correct :
  forall program home_slot resident_register initial replacement path_out,
    program_admissibleb resident_register program = true ->
    initialization_block false program = Some path_out ->
    exists candidate_out,
      projected_candidate_execute resident_register false program
        (hide_reserved_register resident_register replacement initial) =
        Some (path_out, candidate_out) /\
      full_state_equiv
        (baseline_execute home_slot program initial)
        (projected_finalize home_slot resident_register
          (register_cells initial resident_register) path_out candidate_out).
Proof.
  intros program home_slot resident_register initial replacement path_out
    Hcheck Hinitialization.
  pose proof (proj1
    (program_admissibleb_reflect resident_register program) Hcheck)
    as Hadmissible.
  destruct (projected_candidate_execute_preserves_phase
    program home_slot resident_register false initial
    (hide_reserved_register resident_register replacement initial)
    path_out Hadmissible
    (hide_reserved_register_preserves_observable
      resident_register replacement initial)
    Hinitialization) as [candidate_out [Hexecute Hphase]].
  exists candidate_out. split; [exact Hexecute|].
  apply projected_finalize_closes_phase; [exact Hphase|].
  symmetry.
  now apply baseline_execute_preserves_reserved_register.
Qed.

(** Flatten precisely the physical-access blocks selected by one CFG path.
    Failure means that the path names a block outside the bounded graph. *)
Fixpoint projected_path_program
    (graph : initialization_graph) (path : list nat)
    : option (list resident_instruction) :=
  match path with
  | [] => Some []
  | block_id :: rest =>
      match nth_error (initialization_blocks graph) block_id,
            projected_path_program graph rest with
      | Some block, Some tail => Some (block ++ tail)
      | _, _ => None
      end
  end.

Definition initialization_graph_programs_admissibleb
    (resident_register : nat) (graph : initialization_graph) : bool :=
  forallb (program_admissibleb resident_register)
    (initialization_blocks graph).

Lemma program_admissibleb_app :
  forall resident_register prefix suffix,
    program_admissibleb resident_register (prefix ++ suffix) =
    (program_admissibleb resident_register prefix &&
      program_admissibleb resident_register suffix)%bool.
Proof.
  intros resident_register prefix suffix.
  unfold program_admissibleb. now rewrite forallb_app.
Qed.

Theorem projected_path_program_is_admissible :
  forall graph path program resident_register,
    initialization_graph_programs_admissibleb resident_register graph = true ->
    projected_path_program graph path = Some program ->
    program_admissibleb resident_register program = true.
Proof.
  induction path as [|block_id rest IH];
    intros program resident_register Hgraph Hprogram; simpl in *.
  - inversion Hprogram; reflexivity.
  - destruct (nth_error (initialization_blocks graph) block_id)
      as [block|] eqn:Hblock; try discriminate.
    destruct (projected_path_program graph rest)
      as [tail|] eqn:Htail; try discriminate.
    inversion Hprogram; subst program.
    rewrite program_admissibleb_app, Bool.andb_true_iff.
    split.
    + unfold initialization_graph_programs_admissibleb in Hgraph.
      rewrite forallb_forall in Hgraph.
      apply Hgraph. now apply nth_error_In in Hblock.
    + apply (IH tail resident_register Hgraph). reflexivity.
Qed.

Lemma initialization_block_app :
  forall prefix suffix initialized,
    initialization_block initialized (prefix ++ suffix) =
    match initialization_block initialized prefix with
    | Some middle => initialization_block middle suffix
    | None => None
    end.
Proof.
  induction prefix as [|instruction rest IH];
    intros suffix initialized; simpl.
  - reflexivity.
  - destruct (initialization_step initialized instruction)
      as [next|] eqn:Hstep; simpl; [apply IH|reflexivity].
Qed.

Theorem projected_path_program_reflects_initialization :
  forall graph path program initialized path_out,
    projected_path_program graph path = Some program ->
    initialization_path_execute graph path initialized = Some path_out ->
    initialization_block initialized program = Some path_out.
Proof.
  induction path as [|block_id rest IH];
    intros program initialized path_out Hprogram Hexecute; simpl in *.
  - inversion Hprogram; subst. exact Hexecute.
  - destruct (nth_error (initialization_blocks graph) block_id)
      as [block|] eqn:Hblock; try discriminate.
    destruct (projected_path_program graph rest)
      as [tail|] eqn:Htail; try discriminate.
    inversion Hprogram; subst program.
    destruct (initialization_block initialized block)
      as [middle|] eqn:Hmiddle; try discriminate.
    rewrite initialization_block_app, Hmiddle.
    apply (IH tail middle path_out).
    + reflexivity.
    + exact Hexecute.
Qed.

Theorem initialization_path_has_projected_program :
  forall graph block_id path,
    initialization_path_from graph block_id path ->
    exists program,
      projected_path_program graph path = Some program.
Proof.
  intros graph block_id path Hpath.
  induction Hpath as
    [block_id block Hblock |
     block_id block successors next tail Hblock Hsuccessors
       Hnext Htail IH].
  - exists block. simpl. rewrite Hblock. simpl.
    now rewrite app_nil_r.
  - destruct IH as [tail_program Htail_program].
    exists (block ++ tail_program). simpl.
    now rewrite Hblock, Htail_program.
Qed.

(** The admitted must-initialization certificate and the semantic theorem now
    meet at the same path.  Admissibility of register operands remains an
    explicit, executable premise because it is a different safety property
    from definite initialization. *)
Theorem admitted_cfg_projected_path_abi_correct :
  forall proposed accepted path program home_slot resident_register
      initial replacement,
    admit_cfg_initialization_certificate proposed = Some accepted ->
    initialization_path_from (initialization_cfg accepted)
      (initialization_entry (initialization_cfg accepted)) path ->
    projected_path_program (initialization_cfg accepted) path = Some program ->
    program_admissibleb resident_register program = true ->
    exists path_out candidate_out,
      initialization_path_execute
        (initialization_cfg accepted) path false = Some path_out /\
      projected_candidate_execute resident_register false program
        (hide_reserved_register resident_register replacement initial) =
        Some (path_out, candidate_out) /\
      full_state_equiv
        (baseline_execute home_slot program initial)
        (projected_finalize home_slot resident_register
          (register_cells initial resident_register) path_out candidate_out).
Proof.
  intros proposed accepted path program home_slot resident_register
    initial replacement Hadmitted Hpath Hprogram Hadmissible.
  destruct (admitted_cfg_initialization_certificate_paths_safe
    proposed accepted path Hadmitted Hpath) as [path_out Hpath_out].
  assert (Hblock : initialization_block false program = Some path_out).
  { eapply projected_path_program_reflects_initialization; eassumption. }
  destruct (projected_program_checked_abi_correct
    program home_slot resident_register initial replacement path_out
    Hadmissible Hblock) as [candidate_out [Hexecute Hequiv]].
  exists path_out, candidate_out. split; [exact Hpath_out|].
  split; [exact Hexecute|exact Hequiv].
Qed.

(** When every projected block passes the operand checker, an admitted graph
    gives the full-state result for every finite path without any remaining
    path-specific premise. *)
Theorem admitted_cfg_all_projected_paths_abi_correct :
  forall proposed accepted path home_slot resident_register initial replacement,
    admit_cfg_initialization_certificate proposed = Some accepted ->
    initialization_graph_programs_admissibleb resident_register
      (initialization_cfg accepted) = true ->
    initialization_path_from (initialization_cfg accepted)
      (initialization_entry (initialization_cfg accepted)) path ->
    exists program path_out candidate_out,
      projected_path_program (initialization_cfg accepted) path = Some program /\
      initialization_path_execute
        (initialization_cfg accepted) path false = Some path_out /\
      projected_candidate_execute resident_register false program
        (hide_reserved_register resident_register replacement initial) =
        Some (path_out, candidate_out) /\
      full_state_equiv
        (baseline_execute home_slot program initial)
        (projected_finalize home_slot resident_register
          (register_cells initial resident_register) path_out candidate_out).
Proof.
  intros proposed accepted path home_slot resident_register initial replacement
    Hadmitted Hgraph Hpath.
  destruct (initialization_path_has_projected_program
    (initialization_cfg accepted)
    (initialization_entry (initialization_cfg accepted)) path Hpath)
    as [program Hprogram].
  assert (Hadmissible :
    program_admissibleb resident_register program = true).
  { eapply projected_path_program_is_admissible; eassumption. }
  destruct (admitted_cfg_projected_path_abi_correct
    proposed accepted path program home_slot resident_register
    initial replacement Hadmitted Hpath Hprogram Hadmissible)
    as [path_out [candidate_out [Hpath_out [Hexecute Hequiv]]]].
  exists program, path_out, candidate_out.
  split; [exact Hprogram|].
  split; [exact Hpath_out|].
  split; [exact Hexecute|exact Hequiv].
Qed.

(** A concrete branch of the accepted diamond crosses the same executable
    admission boundary and receives a no-axiom full-state theorem. *)
Example safe_diamond_left_branch_abi_correct :
  forall home_slot initial replacement,
    exists path_out candidate_out,
      projected_candidate_execute 12%nat false [StoreHome 1; LoadHome 2]
        (hide_reserved_register 12%nat replacement initial) =
        Some (path_out, candidate_out) /\
      full_state_equiv
        (baseline_execute home_slot [StoreHome 1; LoadHome 2] initial)
        (projected_finalize home_slot 12%nat
          (register_cells initial 12%nat) path_out candidate_out).
Proof.
  intros home_slot initial replacement.
  pose proof (admitted_cfg_projected_path_abi_correct
    safe_diamond_certificate safe_diamond_certificate
    [0%nat; 1%nat; 3%nat] [StoreHome 1; LoadHome 2]
    home_slot 12%nat initial replacement
    safe_diamond_is_admitted) as Hcorrect.
  assert (Hpath : initialization_path_from safe_diamond_graph 0%nat
    [0%nat; 1%nat; 3%nat]).
  { eapply InitializationPathStep with (next := 1%nat); simpl; try reflexivity.
    - now left.
    - eapply InitializationPathStep with (next := 3%nat); simpl; try reflexivity.
      + now left.
      + apply InitializationPathHere with (program := [LoadHome 2]).
        reflexivity. }
  specialize (Hcorrect Hpath eq_refl eq_refl).
  destruct Hcorrect as [path_out [candidate_out
    [Hpath_out [Hexecute Hequiv]]]].
  exists path_out, candidate_out. now split.
Qed.
