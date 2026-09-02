(**
  NauxCore.X86ResidencyEncoding

  A closed decoder for the two seven-byte x86-64 templates used by the
  bounded S4 register-residency candidate.  This layer connects the exact
  transformed sites in an ownership control graph to byte ranges in a
  candidate target and checks the callee-save save/restore envelope.

  It deliberately does not model arbitrary x86-64 instructions, rel32
  relocation, ELF loading, host failures, or native execution.  Those remain
  separate authority boundaries.
*)

From Stdlib Require Import List Bool Arith ZArith.
From NauxCore Require Import RegisterResidency ScalarMachineIRResidency
  HeapMachineIRResidency OwnershipMachineIRResidency
  ControlFlowMachineIRResidency.
Import ListNotations.
Open Scope Z_scope.

Inductive x86_residency_template : Type :=
| X86StoreR12ToHome (displacement : Z)
| X86LoadR12FromHome (displacement : Z).

Definition x86_byte_validb (byte : nat) : bool := Nat.ltb byte 256.

Definition x86_decode_disp32
    (byte0 byte1 byte2 byte3 : nat) : option Z :=
  if forallb x86_byte_validb [byte0; byte1; byte2; byte3] then
    let raw :=
      Z.of_nat byte0 +
      256 * Z.of_nat byte1 +
      65536 * Z.of_nat byte2 +
      16777216 * Z.of_nat byte3 in
    Some (if raw <? 2147483648 then raw else raw - 4294967296)
  else None.

Definition x86_residency_decode
    (bytes : list nat) : option x86_residency_template :=
  match bytes with
  | [76%nat; 137%nat; 165%nat; byte0; byte1; byte2; byte3] =>
      match x86_decode_disp32 byte0 byte1 byte2 byte3 with
      | Some displacement => Some (X86StoreR12ToHome displacement)
      | None => None
      end
  | [76%nat; 139%nat; 165%nat; byte0; byte1; byte2; byte3] =>
      match x86_decode_disp32 byte0 byte1 byte2 byte3 with
      | Some displacement => Some (X86LoadR12FromHome displacement)
      | None => None
      end
  | _ => None
  end.

Definition x86_residency_bytes_at
    (target : list nat) (start : nat) : list nat :=
  firstn 7%nat (skipn start target).

Definition x86_residency_decode_at
    (target : list nat) (start : nat) : option x86_residency_template :=
  x86_residency_decode (x86_residency_bytes_at target start).

Example x86_store_r12_negative_48_decodes :
  x86_residency_decode
    [76%nat; 137%nat; 165%nat; 208%nat; 255%nat; 255%nat; 255%nat] =
    Some (X86StoreR12ToHome (-48)).
Proof. reflexivity. Qed.

Example x86_load_r12_negative_56_decodes :
  x86_residency_decode
    [76%nat; 139%nat; 165%nat; 200%nat; 255%nat; 255%nat; 255%nat] =
    Some (X86LoadR12FromHome (-56)).
Proof. reflexivity. Qed.

Inductive x86_residency_semantic_site : Type :=
| X86SemanticLoadPhysical (result : nat)
| X86SemanticStorePhysical (source : nat) (keep : bool).

Record x86_residency_location : Type := {
  x86_residency_block : nat;
  x86_residency_ordinal : nat;
  x86_residency_semantics : x86_residency_semantic_site
}.

Definition x86_residency_semantics_of_instruction
    (instruction : ownership_machine_instruction)
    : option x86_residency_semantic_site :=
  match instruction with
  | OwnershipPlain
      (HeapScalarInstruction (ResidencyAccess (LoadHome result))) =>
      Some (X86SemanticLoadPhysical result)
  | OwnershipStoreHome source keep =>
      Some (X86SemanticStorePhysical source keep)
  | _ => None
  end.

Fixpoint x86_residency_program_sites
    (block ordinal : nat) (program : list ownership_machine_instruction)
    : list x86_residency_location :=
  match program with
  | [] => []
  | instruction :: rest =>
      let tail := x86_residency_program_sites block (S ordinal) rest in
      match x86_residency_semantics_of_instruction instruction with
      | Some semantics =>
          {| x86_residency_block := block;
             x86_residency_ordinal := ordinal;
             x86_residency_semantics := semantics |} :: tail
      | None => tail
      end
  end.

Fixpoint x86_residency_blocks_sites
    (block : nat) (blocks : list ownership_control_block)
    : list x86_residency_location :=
  match blocks with
  | [] => []
  | first :: rest =>
      x86_residency_program_sites block 0%nat
        (ownership_control_instructions first) ++
      x86_residency_blocks_sites (S block) rest
  end.

Definition x86_residency_graph_sites
    (graph : ownership_control_graph) : list x86_residency_location :=
  x86_residency_blocks_sites 0%nat (ownership_control_blocks graph).

Fixpoint x86_residency_return_count
    (blocks : list ownership_control_block) : nat :=
  match blocks with
  | [] => 0%nat
  | block :: rest =>
      match ownership_control_block_terminator block with
      | OwnershipControlReturn _ =>
          S (x86_residency_return_count rest)
      | _ => x86_residency_return_count rest
      end
  end.

Record x86_residency_encoded_site : Type := {
  x86_residency_encoded_location : x86_residency_location;
  x86_residency_encoded_start : nat
}.

Definition x86_residency_site_check
    (target : list nat) (site : x86_residency_encoded_site) : bool :=
  match x86_residency_semantics (x86_residency_encoded_location site),
        x86_residency_decode_at target (x86_residency_encoded_start site) with
  | X86SemanticLoadPhysical _, Some (X86StoreR12ToHome _) => true
  | X86SemanticStorePhysical _ _, Some (X86LoadR12FromHome _) => true
  | _, _ => false
  end.

Definition x86_residency_site_well_encoded
    (target : list nat) (site : x86_residency_encoded_site) : Prop :=
  match x86_residency_semantics (x86_residency_encoded_location site),
        x86_residency_decode_at target (x86_residency_encoded_start site) with
  | X86SemanticLoadPhysical _, Some (X86StoreR12ToHome _) => True
  | X86SemanticStorePhysical _ _, Some (X86LoadR12FromHome _) => True
  | _, _ => False
  end.

Theorem x86_residency_site_check_reflect :
  forall target site,
    x86_residency_site_check target site = true <->
    x86_residency_site_well_encoded target site.
Proof.
  intros target [location start].
  destruct location as [block ordinal semantics].
  destruct semantics.
  - unfold x86_residency_site_check,
      x86_residency_site_well_encoded. simpl.
    destruct (x86_residency_decode_at target start)
      as [[displacement|displacement]|]; simpl; try tauto.
    all: split; [discriminate | contradiction].
  - unfold x86_residency_site_check,
      x86_residency_site_well_encoded. simpl.
    destruct (x86_residency_decode_at target start)
      as [[displacement|displacement]|]; simpl; try tauto.
    all: split; [discriminate | contradiction].
Qed.

Record x86_residency_abi : Type := {
  x86_residency_shadow_displacement : Z;
  x86_residency_save_start : nat;
  x86_residency_restore_starts : list nat
}.

Definition x86_residency_restore_check
    (target : list nat) (shadow : Z) (start : nat) : bool :=
  match x86_residency_decode_at target start with
  | Some (X86LoadR12FromHome displacement) => Z.eqb displacement shadow
  | _ => false
  end.

Definition x86_residency_abi_check
    (target : list nat) (abi : x86_residency_abi) : bool :=
  match x86_residency_decode_at target (x86_residency_save_start abi) with
  | Some (X86StoreR12ToHome displacement) =>
      Z.eqb displacement (x86_residency_shadow_displacement abi) &&
      match x86_residency_restore_starts abi with
      | [] => false
      | restores =>
          forallb
            (x86_residency_restore_check target
              (x86_residency_shadow_displacement abi))
            restores
      end
  | _ => false
  end.

Definition x86_residency_abi_well_encoded
    (target : list nat) (abi : x86_residency_abi) : Prop :=
  x86_residency_decode_at target (x86_residency_save_start abi) =
    Some (X86StoreR12ToHome
      (x86_residency_shadow_displacement abi)) /\
  x86_residency_restore_starts abi <> [] /\
  Forall
    (fun start =>
      x86_residency_decode_at target start =
        Some (X86LoadR12FromHome
          (x86_residency_shadow_displacement abi)))
    (x86_residency_restore_starts abi).

Lemma x86_residency_restore_check_sound :
  forall target shadow start,
    x86_residency_restore_check target shadow start = true ->
    x86_residency_decode_at target start =
      Some (X86LoadR12FromHome shadow).
Proof.
  intros target shadow start Hcheck.
  unfold x86_residency_restore_check in Hcheck.
  destruct (x86_residency_decode_at target start)
    as [template|] eqn:Hdecode; try discriminate.
  destruct template; try discriminate.
  apply Z.eqb_eq in Hcheck. subst. reflexivity.
Qed.

Theorem x86_residency_abi_check_sound :
  forall target abi,
    x86_residency_abi_check target abi = true ->
    x86_residency_abi_well_encoded target abi.
Proof.
  intros target [shadow save restores] Hcheck.
  unfold x86_residency_abi_check in Hcheck. simpl in Hcheck.
  destruct (x86_residency_decode_at target save)
    as [template|] eqn:Hsave; try discriminate.
  destruct template as [displacement|displacement]; try discriminate.
  apply Bool.andb_true_iff in Hcheck.
  destruct Hcheck as [Hdisplacement Hrestores].
  apply Z.eqb_eq in Hdisplacement. subst displacement.
  split; [exact Hsave|].
  destruct restores as [|first rest]; try discriminate.
  split; [discriminate|].
  change (forallb (x86_residency_restore_check target shadow)
    (first :: rest) = true) in Hrestores.
  rewrite forallb_forall in Hrestores.
  apply Forall_forall. intros start Hin.
  now apply x86_residency_restore_check_sound, Hrestores.
Qed.

Record x86_residency_native_certificate : Type := {
  x86_residency_target_bytes : list nat;
  x86_residency_encoded_sites : list x86_residency_encoded_site;
  x86_residency_abi_evidence : x86_residency_abi
}.

Definition x86_residency_native_certificate_check
    (certificate : x86_residency_native_certificate) : bool :=
  forallb
    (x86_residency_site_check (x86_residency_target_bytes certificate))
    (x86_residency_encoded_sites certificate) &&
  x86_residency_abi_check
    (x86_residency_target_bytes certificate)
    (x86_residency_abi_evidence certificate).

Definition x86_residency_native_certificate_well_encoded
    (certificate : x86_residency_native_certificate) : Prop :=
  Forall
    (x86_residency_site_well_encoded
      (x86_residency_target_bytes certificate))
    (x86_residency_encoded_sites certificate) /\
  x86_residency_abi_well_encoded
    (x86_residency_target_bytes certificate)
    (x86_residency_abi_evidence certificate).

Theorem x86_residency_native_certificate_check_sound :
  forall certificate,
    x86_residency_native_certificate_check certificate = true ->
    x86_residency_native_certificate_well_encoded certificate.
Proof.
  intros [target sites abi] Hcheck.
  unfold x86_residency_native_certificate_check in Hcheck. simpl in Hcheck.
  apply Bool.andb_true_iff in Hcheck.
  destruct Hcheck as [Hsites Habi]. split.
  - rewrite forallb_forall in Hsites.
    apply Forall_forall. intros site Hin.
    apply (proj1 (x86_residency_site_check_reflect target site)).
    now apply Hsites.
  - now apply x86_residency_abi_check_sound.
Qed.

Definition x86_residency_certificate_covers_graph
    (graph : ownership_control_graph)
    (certificate : x86_residency_native_certificate) : Prop :=
  map x86_residency_encoded_location
      (x86_residency_encoded_sites certificate) =
    x86_residency_graph_sites graph /\
  length
      (x86_residency_restore_starts
        (x86_residency_abi_evidence certificate)) =
    x86_residency_return_count (ownership_control_blocks graph) /\
  x86_residency_native_certificate_well_encoded certificate.

Theorem x86_residency_checked_certificate_covers_graph :
  forall graph certificate,
    x86_residency_native_certificate_check certificate = true ->
    map x86_residency_encoded_location
        (x86_residency_encoded_sites certificate) =
      x86_residency_graph_sites graph ->
    length
        (x86_residency_restore_starts
          (x86_residency_abi_evidence certificate)) =
      x86_residency_return_count (ownership_control_blocks graph) ->
    x86_residency_certificate_covers_graph graph certificate.
Proof.
  intros graph certificate Hcheck Hsites Hreturns.
  split; [exact Hsites|]. split; [exact Hreturns|].
  now apply x86_residency_native_certificate_check_sound.
Qed.
