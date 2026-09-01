(**
  NauxCore.ScalarMachineIRResidency

  A scalar Machine-IR projection around the register-residency rewrite.  In
  contrast to [ProjectedCFGResidency], this model retains ordinary integer
  register and stack instructions that pass through the transform unchanged.

  Lists, heap effects, ownership, overflow-event accounting, and branch
  selection are deliberately outside this projection. Fixed-width wrapping
  values are retained. The report bridge may
  omit those instructions, but it must preserve every admitted scalar operand
  and constant exactly.
*)

From Stdlib Require Import List Bool Arith Lia ZArith.
From NauxCore Require Import I64Arithmetic RegisterResidency DefiniteInitialization
  ProjectedCFGResidency.
Import ListNotations.
Open Scope Z_scope.

Inductive scalar_binary : Type :=
| ScalarAdd
| ScalarSub
| ScalarMul.

Definition apply_scalar_binary
    (operation : scalar_binary) (left right : Z) : Z :=
  match operation with
  | ScalarAdd => i64_wrapping_add left right
  | ScalarSub => i64_wrapping_sub left right
  | ScalarMul => i64_wrapping_mul left right
  end.

Definition scalar_binary_overflowb
    (operation : scalar_binary) (left right : Z) : bool :=
  match operation with
  | ScalarAdd => i64_overflowb (i64_add_raw left right)
  | ScalarSub => i64_overflowb (i64_sub_raw left right)
  | ScalarMul => i64_overflowb (i64_mul_raw left right)
  end.

Inductive scalar_compare : Type :=
| ScalarEq
| ScalarNe
| ScalarGt
| ScalarGe
| ScalarLt
| ScalarLe.

Definition bool_as_z (value : bool) : Z :=
  if value then 1 else 0.

Definition apply_scalar_compare
    (operation : scalar_compare) (left right : Z) : Z :=
  let left := i64_wrap left in
  let right := i64_wrap right in
  bool_as_z
    (match operation with
     | ScalarEq => Z.eqb left right
     | ScalarNe => negb (Z.eqb left right)
     | ScalarGt => Z.gtb left right
     | ScalarGe => Z.geb left right
     | ScalarLt => Z.ltb left right
     | ScalarLe => Z.leb left right
     end).

Inductive scalar_machine_instruction : Type :=
| ScalarConst (destination : nat) (value : Z)
| ScalarLoadSlot (destination slot : nat)
| ScalarStoreSlot (slot source : nat)
| ScalarAddSlotConst (slot : nat) (value : Z)
| ScalarBinary (destination : nat) (operation : scalar_binary)
    (left right : nat)
| ScalarCompare (destination : nat) (operation : scalar_compare)
    (left right : nat).

Definition scalar_machine_step
    (instruction : scalar_machine_instruction) (st : machine_state)
    : machine_state :=
  match instruction with
  | ScalarConst destination value =>
      with_registers st
        (map_update (register_cells st) destination (i64_wrap value))
  | ScalarLoadSlot destination slot =>
      with_registers st
        (map_update (register_cells st) destination (stack_cells st slot))
  | ScalarStoreSlot slot source =>
      with_stack st
        (map_update (stack_cells st) slot (register_cells st source))
  | ScalarAddSlotConst slot value =>
      with_stack st
        (map_update (stack_cells st) slot
          (i64_wrapping_add (stack_cells st slot) value))
  | ScalarBinary destination operation left_register right_register =>
      with_registers st
        (map_update (register_cells st) destination
          (apply_scalar_binary operation
            (register_cells st left_register)
            (register_cells st right_register)))
  | ScalarCompare destination operation left_register right_register =>
      with_registers st
        (map_update (register_cells st) destination
          (apply_scalar_compare operation
            (register_cells st left_register)
            (register_cells st right_register)))
  end.

(** Frame conditions required while the physical home is authoritative. *)
Definition scalar_instruction_admissible
    (home_slot resident_register : nat)
    (instruction : scalar_machine_instruction) : Prop :=
  match instruction with
  | ScalarConst destination _ => destination <> resident_register
  | ScalarLoadSlot destination slot =>
      destination <> resident_register /\ slot <> home_slot
  | ScalarStoreSlot slot source =>
      slot <> home_slot /\ source <> resident_register
  | ScalarAddSlotConst slot _ => slot <> home_slot
  | ScalarBinary destination _ left_register right_register
  | ScalarCompare destination _ left_register right_register =>
      destination <> resident_register /\
      left_register <> resident_register /\
      right_register <> resident_register
  end.

Definition nat_negb (left right : nat) : bool :=
  negb (Nat.eqb left right).

Definition scalar_instruction_admissibleb
    (home_slot resident_register : nat)
    (instruction : scalar_machine_instruction) : bool :=
  match instruction with
  | ScalarConst destination _ => nat_negb destination resident_register
  | ScalarLoadSlot destination slot =>
      nat_negb destination resident_register && nat_negb slot home_slot
  | ScalarStoreSlot slot source =>
      nat_negb slot home_slot && nat_negb source resident_register
  | ScalarAddSlotConst slot _ => nat_negb slot home_slot
  | ScalarBinary destination _ left_register right_register
  | ScalarCompare destination _ left_register right_register =>
      nat_negb destination resident_register &&
      nat_negb left_register resident_register &&
      nat_negb right_register resident_register
  end.

Lemma nat_negb_reflect :
  forall left right,
    nat_negb left right = true <-> left <> right.
Proof.
  intros left right. unfold nat_negb.
  rewrite Bool.negb_true_iff. apply Nat.eqb_neq.
Qed.

Theorem scalar_instruction_admissibleb_reflect :
  forall home_slot resident_register instruction,
    scalar_instruction_admissibleb home_slot resident_register instruction =
      true <->
    scalar_instruction_admissible home_slot resident_register instruction.
Proof.
  intros home_slot resident_register instruction.
  destruct instruction as
    [destination value | destination slot | slot source | slot value |
     destination operation left right |
     destination operation left right]; simpl;
    repeat rewrite Bool.andb_true_iff;
    repeat rewrite nat_negb_reflect; tauto.
Qed.

Lemma scalar_machine_step_preserves_reserved_register :
  forall home_slot resident_register instruction st,
    scalar_instruction_admissible home_slot resident_register instruction ->
    register_cells (scalar_machine_step instruction st) resident_register =
      register_cells st resident_register.
Proof.
  intros home_slot resident_register instruction st Hadmissible.
  destruct instruction as
    [destination value | destination slot | slot source | slot value |
     destination operation left right_register |
     destination operation left right_register]; simpl in *.
  - rewrite map_update_neq by congruence. reflexivity.
  - destruct Hadmissible as [Hdestination Hslot].
    rewrite map_update_neq by congruence. reflexivity.
  - reflexivity.
  - reflexivity.
  - destruct Hadmissible as [Hdestination [Hleft Hright]].
    rewrite map_update_neq by congruence. reflexivity.
  - destruct Hadmissible as [Hdestination [Hleft Hright]].
    rewrite map_update_neq by congruence. reflexivity.
Qed.

Theorem scalar_machine_step_preserves_observable :
  forall home_slot resident_register instruction baseline candidate,
    scalar_instruction_admissible home_slot resident_register instruction ->
    observable_equiv resident_register baseline candidate ->
    observable_equiv resident_register
      (scalar_machine_step instruction baseline)
      (scalar_machine_step instruction candidate).
Proof.
  intros home_slot resident_register instruction baseline candidate
    Hadmissible [Hstack Hregister].
  unfold observable_equiv.
  destruct instruction as
    [destination value | destination slot | slot source | slot value |
     destination operation left right |
     destination operation left right];
    unfold scalar_machine_step, with_registers, with_stack in *; simpl in *.
  - split; [exact Hstack|].
    intros reg Hreg.
    destruct (Nat.eq_dec reg destination) as [-> | Hneq].
    + repeat rewrite map_update_eq. reflexivity.
    + repeat rewrite map_update_neq by exact Hneq.
      now apply Hregister.
  - split; [exact Hstack|].
    intros reg Hreg.
    destruct (Nat.eq_dec reg destination) as [-> | Hneq].
    + repeat rewrite map_update_eq. now rewrite Hstack.
    + repeat rewrite map_update_neq by exact Hneq.
      now apply Hregister.
  - split.
    + intro query.
      destruct (Nat.eq_dec query slot) as [-> | Hneq].
      * repeat rewrite map_update_eq. now rewrite Hregister by tauto.
      * repeat rewrite map_update_neq by exact Hneq. now apply Hstack.
    + intros reg Hreg. now apply Hregister.
  - split.
    + intro query.
      destruct (Nat.eq_dec query slot) as [-> | Hneq].
      * repeat rewrite map_update_eq. now rewrite Hstack.
      * repeat rewrite map_update_neq by exact Hneq. now apply Hstack.
    + intros reg Hreg. now apply Hregister.
  - split; [exact Hstack|].
    intros reg Hreg.
    destruct (Nat.eq_dec reg destination) as [-> | Hneq].
    + repeat rewrite map_update_eq.
      rewrite Hregister by tauto. now rewrite Hregister by tauto.
    + repeat rewrite map_update_neq by exact Hneq.
      now apply Hregister.
  - split; [exact Hstack|].
    intros reg Hreg.
    destruct (Nat.eq_dec reg destination) as [-> | Hneq].
    + repeat rewrite map_update_eq.
      rewrite Hregister by tauto. now rewrite Hregister by tauto.
    + repeat rewrite map_update_neq by exact Hneq.
      now apply Hregister.
Qed.

Theorem scalar_machine_step_preserves_resident :
  forall home_slot resident_register instruction baseline candidate,
    scalar_instruction_admissible home_slot resident_register instruction ->
    resident_equiv home_slot resident_register baseline candidate ->
    resident_equiv home_slot resident_register
      (scalar_machine_step instruction baseline)
      (scalar_machine_step instruction candidate).
Proof.
  intros home_slot resident_register instruction baseline candidate
    Hadmissible [Hhome [Hstack Hregister]].
  unfold resident_equiv.
  destruct instruction as
    [destination value | destination slot | slot source | slot value |
     destination operation left right |
     destination operation left right];
    unfold scalar_machine_step, with_registers, with_stack in *; simpl in *.
  - split.
    + rewrite map_update_neq by congruence. exact Hhome.
    + split; [exact Hstack|].
      intros reg Hreg.
      destruct (Nat.eq_dec reg destination) as [-> | Hneq].
      * repeat rewrite map_update_eq. reflexivity.
      * repeat rewrite map_update_neq by exact Hneq. now apply Hregister.
  - destruct Hadmissible as [Hdestination Hslot].
    split.
    + rewrite map_update_neq by congruence. exact Hhome.
    + split; [exact Hstack|].
      intros reg Hreg.
      destruct (Nat.eq_dec reg destination) as [-> | Hneq].
      * repeat rewrite map_update_eq. now rewrite Hstack by exact Hslot.
      * repeat rewrite map_update_neq by exact Hneq. now apply Hregister.
  - destruct Hadmissible as [Hslot Hsource].
    split.
    + rewrite map_update_neq by congruence. exact Hhome.
    + split.
      * intros query Hquery.
        destruct (Nat.eq_dec query slot) as [-> | Hneq].
        -- repeat rewrite map_update_eq. now rewrite Hregister by exact Hsource.
        -- repeat rewrite map_update_neq by exact Hneq. now apply Hstack.
      * intros reg Hreg. now apply Hregister.
  - split.
    + rewrite map_update_neq by congruence. exact Hhome.
    + split.
      * intros query Hquery.
        destruct (Nat.eq_dec query slot) as [-> | Hneq].
        -- repeat rewrite map_update_eq. now rewrite Hstack by exact Hadmissible.
        -- repeat rewrite map_update_neq by exact Hneq. now apply Hstack.
      * intros reg Hreg. now apply Hregister.
  - destruct Hadmissible as [Hdestination [Hleft Hright]].
    split.
    + rewrite map_update_neq by congruence. exact Hhome.
    + split; [exact Hstack|].
      intros reg Hreg.
      destruct (Nat.eq_dec reg destination) as [-> | Hneq].
      * repeat rewrite map_update_eq.
        rewrite Hregister by exact Hleft. now rewrite Hregister by exact Hright.
      * repeat rewrite map_update_neq by exact Hneq. now apply Hregister.
  - destruct Hadmissible as [Hdestination [Hleft Hright]].
    split.
    + rewrite map_update_neq by congruence. exact Hhome.
    + split; [exact Hstack|].
      intros reg Hreg.
      destruct (Nat.eq_dec reg destination) as [-> | Hneq].
      * repeat rewrite map_update_eq.
        rewrite Hregister by exact Hleft. now rewrite Hregister by exact Hright.
      * repeat rewrite map_update_neq by exact Hneq. now apply Hregister.
Qed.

(** A report trace interleaves transformed physical accesses with retained
    scalar Machine-IR instructions. *)
Inductive scalar_residency_instruction : Type :=
| ResidencyAccess (instruction : resident_instruction)
| ScalarPassThrough (instruction : scalar_machine_instruction).

Definition scalar_residency_projection
    (instruction : scalar_residency_instruction)
    : list resident_instruction :=
  match instruction with
  | ResidencyAccess resident => [resident]
  | ScalarPassThrough _ => []
  end.

Fixpoint scalar_residency_program_projection
    (program : list scalar_residency_instruction)
    : list resident_instruction :=
  match program with
  | [] => []
  | instruction :: rest =>
      scalar_residency_projection instruction ++
      scalar_residency_program_projection rest
  end.

Definition scalar_residency_instruction_admissible
    (home_slot resident_register : nat)
    (instruction : scalar_residency_instruction) : Prop :=
  match instruction with
  | ResidencyAccess resident =>
      instruction_admissible resident_register resident
  | ScalarPassThrough scalar =>
      scalar_instruction_admissible home_slot resident_register scalar
  end.

Definition scalar_residency_instruction_admissibleb
    (home_slot resident_register : nat)
    (instruction : scalar_residency_instruction) : bool :=
  match instruction with
  | ResidencyAccess resident =>
      instruction_admissibleb resident_register resident
  | ScalarPassThrough scalar =>
      scalar_instruction_admissibleb home_slot resident_register scalar
  end.

Definition scalar_residency_program_admissibleb
    (home_slot resident_register : nat)
    (program : list scalar_residency_instruction) : bool :=
  forallb
    (scalar_residency_instruction_admissibleb home_slot resident_register)
    program.

Theorem scalar_residency_program_admissibleb_reflect :
  forall home_slot resident_register program,
    scalar_residency_program_admissibleb home_slot resident_register program =
      true <->
    Forall
      (scalar_residency_instruction_admissible home_slot resident_register)
      program.
Proof.
  intros home_slot resident_register program.
  unfold scalar_residency_program_admissibleb.
  rewrite forallb_forall, Forall_forall.
  split; intros H instruction Hin; specialize (H instruction Hin).
  - destruct instruction as [resident | scalar]; simpl in *.
    + now apply (proj1
        (instruction_admissibleb_reflect resident_register resident)).
    + now apply (proj1
        (scalar_instruction_admissibleb_reflect
          home_slot resident_register scalar)).
  - destruct instruction as [resident | scalar]; simpl in *.
    + now apply (proj2
        (instruction_admissibleb_reflect resident_register resident)).
    + now apply (proj2
        (scalar_instruction_admissibleb_reflect
          home_slot resident_register scalar)).
Qed.

Definition scalar_residency_baseline_step
    (home_slot : nat) (instruction : scalar_residency_instruction)
    (st : machine_state) : machine_state :=
  match instruction with
  | ResidencyAccess resident =>
      baseline_instruction_step home_slot resident st
  | ScalarPassThrough scalar => scalar_machine_step scalar st
  end.

Definition scalar_residency_candidate_step
    (resident_register : nat) (initialized : bool)
    (instruction : scalar_residency_instruction) (candidate : machine_state)
    : option (bool * machine_state) :=
  match instruction with
  | ResidencyAccess resident =>
      projected_candidate_step resident_register initialized resident candidate
  | ScalarPassThrough scalar =>
      Some (initialized, scalar_machine_step scalar candidate)
  end.

Fixpoint scalar_residency_baseline_execute
    (home_slot : nat) (program : list scalar_residency_instruction)
    (st : machine_state) : machine_state :=
  match program with
  | [] => st
  | instruction :: rest =>
      scalar_residency_baseline_execute home_slot rest
        (scalar_residency_baseline_step home_slot instruction st)
  end.

Fixpoint scalar_residency_candidate_execute
    (resident_register : nat) (initialized : bool)
    (program : list scalar_residency_instruction) (candidate : machine_state)
    : option (bool * machine_state) :=
  match program with
  | [] => Some (initialized, candidate)
  | instruction :: rest =>
      match scalar_residency_candidate_step
        resident_register initialized instruction candidate with
      | Some (next, stepped) =>
          scalar_residency_candidate_execute resident_register next rest stepped
      | None => None
      end
  end.

Theorem scalar_residency_instruction_preserves_phase :
  forall home_slot resident_register initialized next baseline candidate
      instruction,
    scalar_residency_instruction_admissible
      home_slot resident_register instruction ->
    initialization_block initialized
      (scalar_residency_projection instruction) = Some next ->
    projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    projected_phase_equiv home_slot resident_register next
      (scalar_residency_baseline_step home_slot instruction baseline)
      match scalar_residency_candidate_step
        resident_register initialized instruction candidate with
      | Some (_, stepped) => stepped
      | None => candidate
      end.
Proof.
  intros home_slot resident_register initialized next baseline candidate
    instruction Hadmissible Hinitialization Hphase.
  destruct instruction as [resident | scalar]; simpl in *.
  - destruct (initialization_step initialized resident)
      as [resident_next|] eqn:Hstep; try discriminate.
    inversion Hinitialization; subst resident_next.
    unfold projected_candidate_step. rewrite Hstep. simpl.
    change
      (projected_phase_equiv home_slot resident_register next
        (baseline_instruction_step home_slot resident baseline)
        (resident_instruction_step resident_register resident candidate)).
    eapply projected_instruction_preserves_phase; eassumption.
  - inversion Hinitialization; subst next. simpl.
    destruct initialized; simpl in Hphase |- *.
    + now apply scalar_machine_step_preserves_resident.
    + now apply scalar_machine_step_preserves_observable
        with (home_slot := home_slot).
Qed.

Theorem scalar_residency_candidate_execute_preserves_phase :
  forall program home_slot resident_register initialized baseline candidate
      path_out,
    Forall
      (scalar_residency_instruction_admissible home_slot resident_register)
      program ->
    projected_phase_equiv home_slot resident_register initialized
      baseline candidate ->
    initialization_block initialized
      (scalar_residency_program_projection program) = Some path_out ->
    exists candidate_out,
      scalar_residency_candidate_execute resident_register initialized
        program candidate = Some (path_out, candidate_out) /\
      projected_phase_equiv home_slot resident_register path_out
        (scalar_residency_baseline_execute home_slot program baseline)
        candidate_out.
Proof.
  induction program as [|instruction rest IH];
    intros home_slot resident_register initialized baseline candidate
      path_out Hadmissible Hphase Hinitialization; simpl in *.
  - inversion Hinitialization; subst.
    exists candidate. now split.
  - inversion Hadmissible as [|? ? Hinstruction Hrest]; subst.
    destruct (initialization_block initialized
      (scalar_residency_projection instruction))
      as [next|] eqn:Hnext.
    2: {
      rewrite initialization_block_app, Hnext in Hinitialization.
      discriminate.
    }
    rewrite initialization_block_app, Hnext in Hinitialization.
    destruct (scalar_residency_candidate_step
      resident_register initialized instruction candidate)
      as [[candidate_next stepped]|] eqn:Hcandidate.
    2: {
      destruct instruction as [resident | scalar].
      - simpl in Hcandidate.
        unfold projected_candidate_step in Hcandidate.
        destruct (initialization_step initialized resident)
          as [resident_next|] eqn:Hresident.
        + discriminate.
        + simpl in Hnext. rewrite Hresident in Hnext. discriminate.
      - simpl in Hcandidate. discriminate.
    }
    assert (Hcandidate_next : candidate_next = next).
    {
      destruct instruction as [resident | scalar]; simpl in *.
      - unfold projected_candidate_step in Hcandidate.
        destruct (initialization_step initialized resident)
          as [resident_next|] eqn:Hresident; try discriminate.
        inversion Hcandidate; inversion Hnext; congruence.
      - inversion Hcandidate. inversion Hnext. congruence.
    }
    subst candidate_next.
    assert (Hstepped :
      projected_phase_equiv home_slot resident_register next
        (scalar_residency_baseline_step home_slot instruction baseline)
        stepped).
    {
      pose proof (scalar_residency_instruction_preserves_phase
        home_slot resident_register initialized next baseline candidate
        instruction Hinstruction Hnext Hphase) as Hpreserved.
      rewrite Hcandidate in Hpreserved. exact Hpreserved.
    }
    destruct (IH home_slot resident_register next
      (scalar_residency_baseline_step home_slot instruction baseline)
      stepped path_out Hrest Hstepped Hinitialization)
      as [candidate_out [Hexecute Hout]].
    exists candidate_out. split; [|exact Hout].
    exact Hexecute.
Qed.

Lemma scalar_residency_baseline_execute_preserves_reserved_register :
  forall program home_slot resident_register initial,
    Forall
      (scalar_residency_instruction_admissible home_slot resident_register)
      program ->
    register_cells
      (scalar_residency_baseline_execute home_slot program initial)
      resident_register = register_cells initial resident_register.
Proof.
  induction program as [|instruction rest IH];
    intros home_slot resident_register initial Hadmissible; simpl.
  - reflexivity.
  - inversion Hadmissible as [|? ? Hinstruction Hrest]; subst.
    rewrite (IH home_slot resident_register
      (scalar_residency_baseline_step home_slot instruction initial) Hrest).
    destruct instruction as [resident | scalar]; simpl in *.
    + now apply baseline_instruction_preserves_reserved_register.
    + now apply scalar_machine_step_preserves_reserved_register
        with (home_slot := home_slot).
Qed.

Theorem scalar_residency_program_checked_abi_correct :
  forall program home_slot resident_register initial replacement path_out,
    scalar_residency_program_admissibleb
      home_slot resident_register program = true ->
    initialization_block false
      (scalar_residency_program_projection program) = Some path_out ->
    exists candidate_out,
      scalar_residency_candidate_execute resident_register false program
        (hide_reserved_register resident_register replacement initial) =
        Some (path_out, candidate_out) /\
      full_state_equiv
        (scalar_residency_baseline_execute home_slot program initial)
        (projected_finalize home_slot resident_register
          (register_cells initial resident_register) path_out candidate_out).
Proof.
  intros program home_slot resident_register initial replacement path_out
    Hcheck Hinitialization.
  pose proof (proj1
    (scalar_residency_program_admissibleb_reflect
      home_slot resident_register program) Hcheck) as Hadmissible.
  destruct (scalar_residency_candidate_execute_preserves_phase
    program home_slot resident_register false initial
    (hide_reserved_register resident_register replacement initial)
    path_out Hadmissible
    (hide_reserved_register_preserves_observable
      resident_register replacement initial)
    Hinitialization) as [candidate_out [Hexecute Hphase]].
  exists candidate_out. split; [exact Hexecute|].
  apply projected_finalize_closes_phase; [exact Hphase|].
  symmetry. now apply
    scalar_residency_baseline_execute_preserves_reserved_register.
Qed.

(** A mixed graph retains scalar blocks while its projection is exactly the
    physical-access graph consumed by the initialization checker. *)
Record scalar_residency_graph : Type := {
  scalar_residency_entry : nat;
  scalar_residency_blocks : list (list scalar_residency_instruction);
  scalar_residency_successors : list (list nat)
}.

Definition scalar_residency_graph_projection
    (graph : scalar_residency_graph) : initialization_graph :=
  {| initialization_entry := scalar_residency_entry graph;
     initialization_blocks :=
       map scalar_residency_program_projection
         (scalar_residency_blocks graph);
     initialization_successors := scalar_residency_successors graph |}.

Fixpoint scalar_residency_path_program
    (graph : scalar_residency_graph) (path : list nat)
    : option (list scalar_residency_instruction) :=
  match path with
  | [] => Some []
  | block_id :: rest =>
      match nth_error (scalar_residency_blocks graph) block_id,
            scalar_residency_path_program graph rest with
      | Some block, Some tail => Some (block ++ tail)
      | _, _ => None
      end
  end.

Definition scalar_residency_graph_admissibleb
    (home_slot resident_register : nat) (graph : scalar_residency_graph)
    : bool :=
  forallb
    (scalar_residency_program_admissibleb home_slot resident_register)
    (scalar_residency_blocks graph).

Lemma scalar_residency_program_projection_app :
  forall prefix suffix,
    scalar_residency_program_projection (prefix ++ suffix) =
    scalar_residency_program_projection prefix ++
      scalar_residency_program_projection suffix.
Proof.
  induction prefix as [|instruction rest IH]; intros suffix; simpl.
  - reflexivity.
  - rewrite IH. now rewrite app_assoc.
Qed.

Lemma scalar_residency_program_admissibleb_app :
  forall home_slot resident_register prefix suffix,
    scalar_residency_program_admissibleb home_slot resident_register
      (prefix ++ suffix) =
    (scalar_residency_program_admissibleb home_slot resident_register prefix &&
     scalar_residency_program_admissibleb home_slot resident_register suffix)%bool.
Proof.
  intros home_slot resident_register prefix suffix.
  unfold scalar_residency_program_admissibleb. now rewrite forallb_app.
Qed.

Lemma nth_error_map_some_inv :
  forall (A B : Type) (transform : A -> B) values index value,
    nth_error (map transform values) index = Some value ->
    exists source,
      nth_error values index = Some source /\ transform source = value.
Proof.
  intros A B transform values.
  induction values as [|source rest IH]; intros index value Hvalue.
  - destruct index; discriminate.
  - destruct index as [|index]; simpl in *.
    + inversion Hvalue; subst. exists source. now split.
    + destruct (IH index value Hvalue) as [found [Hfound Hequal]].
      exists found. now split.
Qed.

Theorem scalar_residency_path_program_projects :
  forall graph path program,
    scalar_residency_path_program graph path = Some program ->
    projected_path_program (scalar_residency_graph_projection graph) path =
      Some (scalar_residency_program_projection program).
Proof.
  intros graph path.
  induction path as [|block_id rest IH]; intros program Hprogram; simpl in *.
  - inversion Hprogram. reflexivity.
  - destruct (nth_error (scalar_residency_blocks graph) block_id)
      as [block|] eqn:Hblock; try discriminate.
    destruct (scalar_residency_path_program graph rest)
      as [tail|] eqn:Htail; try discriminate.
    inversion Hprogram; subst program.
    simpl. rewrite nth_error_map, Hblock. simpl.
    rewrite (IH tail eq_refl), scalar_residency_program_projection_app.
    reflexivity.
Qed.

Theorem initialization_path_has_scalar_residency_program :
  forall graph block_id path,
    initialization_path_from (scalar_residency_graph_projection graph)
      block_id path ->
    exists program,
      scalar_residency_path_program graph path = Some program.
Proof.
  intros graph block_id path Hpath.
  induction Hpath as
    [block_id projected_block Hblock |
     block_id projected_block successors next tail Hblock Hsuccessors
       Hnext Htail IH].
  - simpl in Hblock.
    destruct (nth_error_map_some_inv
      _ _ scalar_residency_program_projection
      (scalar_residency_blocks graph) block_id projected_block Hblock)
      as [block [Hmixed Hprojection]].
    exists block. simpl. rewrite Hmixed. simpl. now rewrite app_nil_r.
  - simpl in Hblock.
    destruct (nth_error_map_some_inv
      _ _ scalar_residency_program_projection
      (scalar_residency_blocks graph) block_id projected_block Hblock)
      as [block [Hmixed Hprojection]].
    destruct IH as [tail_program Htail_program].
    exists (block ++ tail_program). simpl.
    now rewrite Hmixed, Htail_program.
Qed.

Theorem scalar_residency_path_program_is_admissible :
  forall graph path program home_slot resident_register,
    scalar_residency_graph_admissibleb
      home_slot resident_register graph = true ->
    scalar_residency_path_program graph path = Some program ->
    scalar_residency_program_admissibleb
      home_slot resident_register program = true.
Proof.
  intros graph path.
  induction path as [|block_id rest IH];
    intros program home_slot resident_register Hgraph Hprogram; simpl in *.
  - inversion Hprogram. reflexivity.
  - destruct (nth_error (scalar_residency_blocks graph) block_id)
      as [block|] eqn:Hblock; try discriminate.
    destruct (scalar_residency_path_program graph rest)
      as [tail|] eqn:Htail; try discriminate.
    inversion Hprogram; subst program.
    rewrite scalar_residency_program_admissibleb_app, Bool.andb_true_iff.
    split.
    + unfold scalar_residency_graph_admissibleb in Hgraph.
      rewrite forallb_forall in Hgraph.
      apply Hgraph. now apply nth_error_In in Hblock.
    + exact (IH tail home_slot resident_register Hgraph eq_refl).
Qed.

(** Every finite structural path admitted by the sealed initialization graph
    now preserves the scalar Machine-IR projection as well as the transformed
    physical accesses.  Branch selection and omitted heap/list operations are
    not claimed by this theorem. *)
Theorem admitted_cfg_all_scalar_residency_paths_abi_correct :
  forall proposed accepted graph path home_slot resident_register
      initial replacement,
    admit_cfg_initialization_certificate proposed = Some accepted ->
    scalar_residency_graph_projection graph =
      initialization_cfg accepted ->
    scalar_residency_graph_admissibleb
      home_slot resident_register graph = true ->
    initialization_path_from (initialization_cfg accepted)
      (initialization_entry (initialization_cfg accepted)) path ->
    exists program path_out candidate_out,
      scalar_residency_path_program graph path = Some program /\
      initialization_path_execute
        (initialization_cfg accepted) path false = Some path_out /\
      scalar_residency_candidate_execute resident_register false program
        (hide_reserved_register resident_register replacement initial) =
        Some (path_out, candidate_out) /\
      full_state_equiv
        (scalar_residency_baseline_execute home_slot program initial)
        (projected_finalize home_slot resident_register
          (register_cells initial resident_register) path_out candidate_out).
Proof.
  intros proposed accepted graph path home_slot resident_register
    initial replacement Hadmitted Hprojection Hadmissible Hpath.
  destruct (admitted_cfg_initialization_certificate_paths_safe
    proposed accepted path Hadmitted Hpath) as [path_out Hpath_out].
  assert (Hmixed_path :
    initialization_path_from (scalar_residency_graph_projection graph)
      (initialization_entry (scalar_residency_graph_projection graph)) path).
  { now rewrite Hprojection. }
  destruct (initialization_path_has_scalar_residency_program
    graph _ path Hmixed_path) as [program Hprogram].
  assert (Hprojected :
    projected_path_program (initialization_cfg accepted) path =
      Some (scalar_residency_program_projection program)).
  {
    rewrite <- Hprojection.
    now apply scalar_residency_path_program_projects.
  }
  assert (Hinitialization :
    initialization_block false
      (scalar_residency_program_projection program) = Some path_out).
  { eapply projected_path_program_reflects_initialization; eassumption. }
  assert (Hprogram_admissible :
    scalar_residency_program_admissibleb
      home_slot resident_register program = true).
  { eapply scalar_residency_path_program_is_admissible; eassumption. }
  destruct (scalar_residency_program_checked_abi_correct
    program home_slot resident_register initial replacement path_out
    Hprogram_admissible Hinitialization)
    as [candidate_out [Hexecute Hequiv]].
  exists program, path_out, candidate_out.
  split; [exact Hprogram|].
  split; [exact Hpath_out|].
  now split.
Qed.
