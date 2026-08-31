(**
  NauxCore.DefiniteInitialization

  A separately checked model of the must-initialization boundary used by the
  S4 register-residency verifier.  Block identifiers are canonical positions
  in finite lists.  A certificate marks the reachable blocks and supplies a
  conservative incoming fact for each one.  The executable checker rejects a
  graph when any reachable path can read the physical home before a store has
  initialized it.

  This is a bounded CFG model.  It does not parse or authenticate the frozen
  Rust plan report; that bridge remains a separate obligation.
*)

From Stdlib Require Import List Bool Arith Lia.
From NauxCore Require Import RegisterResidency.
Import ListNotations.

(** A store establishes the physical home.  Loads and arithmetic updates read
    it, so they are legal only after initialization. *)
Definition initialization_step
    (initialized : bool) (instruction : resident_instruction) : option bool :=
  match instruction with
  | StoreHome _ => Some true
  | LoadHome _ | UpdateHome _ =>
      if initialized then Some true else None
  end.

Fixpoint initialization_block
    (initialized : bool) (program : list resident_instruction) : option bool :=
  match program with
  | [] => Some initialized
  | instruction :: rest =>
      match initialization_step initialized instruction with
      | Some next => initialization_block next rest
      | None => None
      end
  end.

(** [initialization_dominates actual guaranteed] says the actual execution has
    at least the initialization guarantee recorded in the certificate. *)
Definition initialization_dominates (actual guaranteed : bool) : Prop :=
  guaranteed = true -> actual = true.

Lemma initialization_dominates_refl :
  forall initialized,
    initialization_dominates initialized initialized.
Proof.
  intros initialized Hinitialized. exact Hinitialized.
Qed.

Lemma initialization_dominates_trans :
  forall left middle right,
    initialization_dominates left middle ->
    initialization_dominates middle right ->
    initialization_dominates left right.
Proof.
  intros left middle right Hleft Hmiddle Hright.
  apply Hleft. now apply Hmiddle.
Qed.

Theorem initialization_block_monotone :
  forall program guaranteed actual guaranteed_out,
    initialization_dominates actual guaranteed ->
    initialization_block guaranteed program = Some guaranteed_out ->
    exists actual_out,
      initialization_block actual program = Some actual_out /\
      initialization_dominates actual_out guaranteed_out.
Proof.
  induction program as [|instruction rest IH];
    intros guaranteed actual guaranteed_out Hdominates Hchecked; simpl in *.
  - inversion Hchecked; subst.
    exists actual. split; [reflexivity|exact Hdominates].
  - destruct instruction as [op | destination | source]; simpl in *.
    + destruct guaranteed eqn:Hguaranteed; try discriminate.
      assert (Hactual : actual = true).
      { apply Hdominates. reflexivity. }
      subst actual. now apply (IH true true guaranteed_out).
    + destruct guaranteed eqn:Hguaranteed; try discriminate.
      assert (Hactual : actual = true).
      { apply Hdominates. reflexivity. }
      subst actual. now apply (IH true true guaranteed_out).
    + now apply (IH true true guaranteed_out).
Qed.

Record initialization_graph : Type := {
  initialization_entry : nat;
  initialization_blocks : list (list resident_instruction);
  initialization_successors : list (list nat)
}.

Record cfg_initialization_certificate : Type := {
  initialization_cfg : initialization_graph;
  initialization_reachable : list bool;
  initialization_incoming : list bool
}.

Definition implicationb (required provided : bool) : bool :=
  negb required || provided.

Definition initialization_edge_checkb
    (certificate : cfg_initialization_certificate)
    (block_out : bool) (successor : nat) : bool :=
  match nth_error (initialization_reachable certificate) successor,
        nth_error (initialization_incoming certificate) successor with
  | Some true, Some successor_in => implicationb successor_in block_out
  | _, _ => false
  end.

Definition initialization_block_checkb
    (certificate : cfg_initialization_certificate) (block_id : nat) : bool :=
  let graph := initialization_cfg certificate in
  match nth_error (initialization_reachable certificate) block_id with
  | Some false => true
  | Some true =>
      match nth_error (initialization_incoming certificate) block_id,
            nth_error (initialization_blocks graph) block_id,
            nth_error (initialization_successors graph) block_id with
      | Some incoming, Some program, Some successors =>
          match initialization_block incoming program with
          | Some block_out =>
              forallb
                (initialization_edge_checkb certificate block_out)
                successors
          | None => false
          end
      | _, _, _ => false
      end
  | None => false
  end.

Definition initialization_shape_checkb
    (certificate : cfg_initialization_certificate) : bool :=
  let graph := initialization_cfg certificate in
  let count := length (initialization_blocks graph) in
  Nat.eqb (length (initialization_successors graph)) count &&
  Nat.eqb (length (initialization_reachable certificate)) count &&
  Nat.eqb (length (initialization_incoming certificate)) count.

Definition initialization_entry_checkb
    (certificate : cfg_initialization_certificate) : bool :=
  let entry := initialization_entry (initialization_cfg certificate) in
  match nth_error (initialization_reachable certificate) entry,
        nth_error (initialization_incoming certificate) entry with
  | Some true, Some false => true
  | _, _ => false
  end.

Definition cfg_initialization_certificate_admissibleb
    (certificate : cfg_initialization_certificate) : bool :=
  let count := length
    (initialization_blocks (initialization_cfg certificate)) in
  initialization_shape_checkb certificate &&
  initialization_entry_checkb certificate &&
  forallb (initialization_block_checkb certificate) (seq 0 count).

Definition initialization_edge_valid
    (certificate : cfg_initialization_certificate)
    (block_out : bool) (successor : nat) : Prop :=
  exists successor_in,
    nth_error (initialization_reachable certificate) successor = Some true /\
    nth_error (initialization_incoming certificate) successor =
      Some successor_in /\
    initialization_dominates block_out successor_in.

Definition initialization_block_valid
    (certificate : cfg_initialization_certificate) (block_id : nat) : Prop :=
  nth_error (initialization_reachable certificate) block_id = Some true ->
  exists incoming program successors block_out,
    nth_error (initialization_incoming certificate) block_id = Some incoming /\
    nth_error
      (initialization_blocks (initialization_cfg certificate)) block_id =
      Some program /\
    nth_error
      (initialization_successors (initialization_cfg certificate)) block_id =
      Some successors /\
    initialization_block incoming program = Some block_out /\
    Forall (initialization_edge_valid certificate block_out) successors.

Definition cfg_initialization_certificate_valid
    (certificate : cfg_initialization_certificate) : Prop :=
  let graph := initialization_cfg certificate in
  let entry := initialization_entry graph in
  let count := length (initialization_blocks graph) in
  length (initialization_successors graph) = count /\
  length (initialization_reachable certificate) = count /\
  length (initialization_incoming certificate) = count /\
  nth_error (initialization_reachable certificate) entry = Some true /\
  nth_error (initialization_incoming certificate) entry = Some false /\
  forall block_id,
    block_id < count -> initialization_block_valid certificate block_id.

Lemma implicationb_sound :
  forall required provided,
    implicationb required provided = true ->
    initialization_dominates provided required.
Proof.
  intros required provided Hcheck Hrequired.
  unfold implicationb in Hcheck.
  subst required. simpl in Hcheck. exact Hcheck.
Qed.

Lemma initialization_edge_checkb_sound :
  forall certificate block_out successor,
    initialization_edge_checkb certificate block_out successor = true ->
    initialization_edge_valid certificate block_out successor.
Proof.
  intros certificate block_out successor Hcheck.
  unfold initialization_edge_checkb in Hcheck.
  destruct (nth_error (initialization_reachable certificate) successor)
    as [reachable|] eqn:Hreachable; try discriminate.
  destruct reachable; try discriminate.
  destruct (nth_error (initialization_incoming certificate) successor)
    as [successor_in|] eqn:Hincoming; try discriminate.
  exists successor_in. repeat split; try assumption.
  now apply implicationb_sound.
Qed.

Lemma initialization_block_checkb_sound :
  forall certificate block_id,
    initialization_block_checkb certificate block_id = true ->
    initialization_block_valid certificate block_id.
Proof.
  intros certificate block_id Hcheck Hreachable.
  unfold initialization_block_checkb in Hcheck.
  rewrite Hreachable in Hcheck.
  destruct (nth_error (initialization_incoming certificate) block_id)
    as [incoming|] eqn:Hincoming; try discriminate.
  destruct (nth_error
    (initialization_blocks (initialization_cfg certificate)) block_id)
    as [program|] eqn:Hprogram; try discriminate.
  destruct (nth_error
    (initialization_successors (initialization_cfg certificate)) block_id)
    as [successors|] eqn:Hsuccessors; try discriminate.
  destruct (initialization_block incoming program)
    as [block_out|] eqn:Hblock; try discriminate.
  exists incoming, program, successors, block_out.
  repeat split; try assumption.
  rewrite Forall_forall. intros successor Hmember.
  apply initialization_edge_checkb_sound.
  rewrite forallb_forall in Hcheck.
  now apply Hcheck.
Qed.

Theorem cfg_initialization_certificate_admissibleb_sound :
  forall certificate,
    cfg_initialization_certificate_admissibleb certificate = true ->
    cfg_initialization_certificate_valid certificate.
Proof.
  intros certificate Hcheck.
  unfold cfg_initialization_certificate_admissibleb in Hcheck.
  apply andb_true_iff in Hcheck as [Hprefix Hblocks].
  apply andb_true_iff in Hprefix as [Hshape Hentry].
  unfold initialization_shape_checkb in Hshape.
  apply andb_true_iff in Hshape as [Hshape Hincoming].
  apply andb_true_iff in Hshape as [Hsuccessors Hreachable].
  apply Nat.eqb_eq in Hsuccessors.
  apply Nat.eqb_eq in Hreachable.
  apply Nat.eqb_eq in Hincoming.
  unfold initialization_entry_checkb in Hentry.
  destruct (nth_error (initialization_reachable certificate)
    (initialization_entry (initialization_cfg certificate)))
    as [entry_reachable|] eqn:Hentry_reachable; try discriminate.
  destruct entry_reachable; try discriminate.
  destruct (nth_error (initialization_incoming certificate)
    (initialization_entry (initialization_cfg certificate)))
    as [entry_incoming|] eqn:Hentry_incoming; try discriminate.
  destruct entry_incoming; try discriminate.
  repeat split; try assumption.
  intros block_id Hbound.
  apply initialization_block_checkb_sound.
  rewrite forallb_forall in Hblocks.
  apply Hblocks. apply in_seq. lia.
Qed.

Inductive initialization_path_from
    (graph : initialization_graph) : nat -> list nat -> Prop :=
| InitializationPathHere : forall block_id program,
    nth_error (initialization_blocks graph) block_id = Some program ->
    initialization_path_from graph block_id [block_id]
| InitializationPathStep : forall block_id program successors next tail,
    nth_error (initialization_blocks graph) block_id = Some program ->
    nth_error (initialization_successors graph) block_id = Some successors ->
    In next successors ->
    initialization_path_from graph next tail ->
    initialization_path_from graph block_id (block_id :: tail).

Fixpoint initialization_path_execute
    (graph : initialization_graph) (path : list nat) (initialized : bool)
    : option bool :=
  match path with
  | [] => Some initialized
  | block_id :: rest =>
      match nth_error (initialization_blocks graph) block_id with
      | Some program =>
          match initialization_block initialized program with
          | Some block_out =>
              initialization_path_execute graph rest block_out
          | None => None
          end
      | None => None
      end
  end.

Lemma cfg_initialization_certificate_path_safe_from :
  forall certificate block_id path actual incoming,
    cfg_initialization_certificate_valid certificate ->
    initialization_path_from (initialization_cfg certificate) block_id path ->
    nth_error (initialization_reachable certificate) block_id = Some true ->
    nth_error (initialization_incoming certificate) block_id = Some incoming ->
    initialization_dominates actual incoming ->
    exists path_out,
      initialization_path_execute
        (initialization_cfg certificate) path actual = Some path_out.
Proof.
  intros certificate block_id path actual incoming Hvalid Hpath.
  revert actual incoming.
  induction Hpath as
    [block_id program Hprogram |
     block_id program successors next tail Hprogram Hsuccessors
       Hnext Htail IH];
    intros actual incoming Hreachable Hincoming Hdominates.
  - destruct Hvalid as
      [Hsuccessors_length [Hreachable_length [Hincoming_length
       [Hentry_reachable [Hentry_incoming Hblocks]]]]].
    assert (Hbound : block_id <
      length (initialization_blocks (initialization_cfg certificate))).
    { apply nth_error_Some. rewrite Hprogram. discriminate. }
    specialize (Hblocks block_id Hbound Hreachable).
    destruct Hblocks as
      [certified_in [certified_program [certified_successors [block_out
       [Hcertified_in [Hcertified_program [Hcertified_successors
        [Hblock Hedges]]]]]]]].
    rewrite Hincoming in Hcertified_in. inversion Hcertified_in; subst.
    rewrite Hprogram in Hcertified_program.
    inversion Hcertified_program; subst.
    destruct (initialization_block_monotone
      certified_program certified_in actual block_out
      Hdominates Hblock) as [actual_out [Hactual Hout]].
    exists actual_out. simpl. now rewrite Hprogram, Hactual.
  - destruct Hvalid as
      [Hsuccessors_length [Hreachable_length [Hincoming_length
       [Hentry_reachable [Hentry_incoming Hblocks]]]]].
    assert (Hbound : block_id <
      length (initialization_blocks (initialization_cfg certificate))).
    { apply nth_error_Some. rewrite Hprogram. discriminate. }
    specialize (Hblocks block_id Hbound Hreachable).
    destruct Hblocks as
      [certified_in [certified_program [certified_successors [block_out
       [Hcertified_in [Hcertified_program [Hcertified_successors
        [Hblock Hedges]]]]]]]].
    rewrite Hincoming in Hcertified_in. inversion Hcertified_in; subst.
    rewrite Hprogram in Hcertified_program.
    inversion Hcertified_program; subst.
    rewrite Hsuccessors in Hcertified_successors.
    inversion Hcertified_successors; subst.
    destruct (initialization_block_monotone
      certified_program certified_in actual block_out
      Hdominates Hblock) as [actual_out [Hactual Hout]].
    rewrite Forall_forall in Hedges.
    specialize (Hedges next Hnext).
    destruct Hedges as
      [next_in [Hnext_reachable [Hnext_incoming Hnext_dominates]]].
    destruct (IH actual_out next_in Hnext_reachable Hnext_incoming)
      as [path_out Hpath_out].
    { now apply (initialization_dominates_trans
        actual_out block_out next_in). }
    exists path_out. simpl. now rewrite Hprogram, Hactual.
Qed.

Theorem cfg_initialization_certificate_paths_safe :
  forall certificate path,
    cfg_initialization_certificate_admissibleb certificate = true ->
    initialization_path_from (initialization_cfg certificate)
      (initialization_entry (initialization_cfg certificate)) path ->
    exists path_out,
      initialization_path_execute
        (initialization_cfg certificate) path false = Some path_out.
Proof.
  intros certificate path Hcheck Hpath.
  pose proof
    (cfg_initialization_certificate_admissibleb_sound certificate Hcheck)
    as Hvalid.
  destruct Hvalid as
    [Hsuccessors_length [Hreachable_length [Hincoming_length
     [Hentry_reachable [Hentry_incoming Hblocks]]]]].
  eapply cfg_initialization_certificate_path_safe_from.
  - repeat split; eassumption.
  - exact Hpath.
  - exact Hentry_reachable.
  - exact Hentry_incoming.
  - apply initialization_dominates_refl.
Qed.

(** Only a certificate accepted by the executable checker may cross this
    admission boundary. *)
Definition admit_cfg_initialization_certificate
    (certificate : cfg_initialization_certificate)
    : option cfg_initialization_certificate :=
  if cfg_initialization_certificate_admissibleb certificate
  then Some certificate
  else None.

Theorem admit_cfg_initialization_certificate_sound :
  forall proposed accepted,
    admit_cfg_initialization_certificate proposed = Some accepted ->
    accepted = proposed /\
    cfg_initialization_certificate_admissibleb accepted = true.
Proof.
  intros proposed accepted Hadmitted.
  unfold admit_cfg_initialization_certificate in Hadmitted.
  destruct (cfg_initialization_certificate_admissibleb proposed)
    eqn:Hcheck; inversion Hadmitted; subst.
  now split.
Qed.

Theorem admitted_cfg_initialization_certificate_paths_safe :
  forall proposed accepted path,
    admit_cfg_initialization_certificate proposed = Some accepted ->
    initialization_path_from (initialization_cfg accepted)
      (initialization_entry (initialization_cfg accepted)) path ->
    exists path_out,
      initialization_path_execute
        (initialization_cfg accepted) path false = Some path_out.
Proof.
  intros proposed accepted path Hadmitted Hpath.
  apply cfg_initialization_certificate_paths_safe.
  - now apply (proj2
      (admit_cfg_initialization_certificate_sound
        proposed accepted Hadmitted)).
  - exact Hpath.
Qed.

(** A diamond is accepted only when both arms establish the physical home
    before the join reads it. *)
Definition safe_diamond_graph : initialization_graph :=
  {| initialization_entry := 0;
     initialization_blocks :=
       [[]; [StoreHome 1]; [StoreHome 1]; [LoadHome 2]];
     initialization_successors := [[1; 2]; [3]; [3]; []] |}.

Definition safe_diamond_certificate : cfg_initialization_certificate :=
  {| initialization_cfg := safe_diamond_graph;
     initialization_reachable := [true; true; true; true];
     initialization_incoming := [false; false; false; true] |}.

Example safe_diamond_is_admitted :
  admit_cfg_initialization_certificate safe_diamond_certificate =
    Some safe_diamond_certificate.
Proof. reflexivity. Qed.

Definition unsafe_diamond_graph : initialization_graph :=
  {| initialization_entry := 0;
     initialization_blocks :=
       [[]; [StoreHome 1]; []; [LoadHome 2]];
     initialization_successors := [[1; 2]; [3]; [3]; []] |}.

Definition unsafe_diamond_certificate : cfg_initialization_certificate :=
  {| initialization_cfg := unsafe_diamond_graph;
     initialization_reachable := [true; true; true; true];
     initialization_incoming := [false; false; false; false] |}.

Example unsafe_diamond_is_rejected :
  admit_cfg_initialization_certificate unsafe_diamond_certificate = None.
Proof. reflexivity. Qed.
