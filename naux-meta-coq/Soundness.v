From Coq Require Import List Arith Bool Lia.
Import ListNotations.

From NauxCore Require Import Syntax Typing Smallstep.

Lemma weakening_one : forall Gamma t T A,
  has_type Gamma t T ->
  has_type (A :: Gamma) (shift 1 0 t) T.
Proof.
  intros Gamma t T A HT.
  induction HT; simpl; eauto using has_type.
  - (* Var *)
    constructor. unfold ctx_lookup in *.
    replace (x + 1) with (S x) by lia.
    simpl. exact H.
  - (* Abs *)
    constructor. apply IHHT.
Qed.

Lemma substitution_zero : forall Gamma t T U s,
  has_type (U :: Gamma) t T ->
  has_type Gamma s U ->
  has_type Gamma (subst 0 s t) T.
Proof.
  intros Gamma t T U s Ht Hs.
  generalize dependent Gamma.
  induction Ht; intros Gamma0; simpl; eauto using has_type.
  - (* Var *)
    destruct x; simpl in H.
    + inversion H; subst. exact Hs.
    + constructor. exact H.
  - (* Abs *)
    constructor.
    apply IHHt.
    apply weakening_one. exact Hs.
  - (* Let *)
    econstructor; eauto.
  - (* If *)
    econstructor; eauto.
Qed.

Theorem preservation : forall t t' T,
  has_type [] t T ->
  step t t' ->
  has_type [] t' T.
Proof.
  intros t t' T HT HS.
  generalize dependent T.
  induction HS; intros T HT; inversion HT; subst; eauto using has_type.
  - (* AppAbs *)
    inversion H2; subst.
    eapply substitution_zero; eauto.
  - (* LetValue *)
    inversion H3; subst.
    eapply substitution_zero; eauto.
Qed.



Lemma canonical_arrow : forall v A B,
  value v ->
  has_type [] v (TyArrow A B) ->
  exists body, v = TAbs A body.
Proof.
  intros v A B Hv Ht.
  inversion Hv; subst; inversion Ht; eauto.
Qed.

Lemma canonical_bool : forall v,
  value v ->
  has_type [] v TyBool ->
  exists b, v = TBool b.
Proof.
  intros v Hv Ht.
  inversion Hv; subst; inversion Ht; eauto.
Qed.



Theorem progress : forall t T,
  has_type [] t T ->
  value t \/ exists t', step t t'.
Proof.
  intros t T HT.
  remember [] as Gamma.
  induction HT; subst; eauto.
  - (* Var *) inversion H.
  - (* App *)
    destruct IHHT1 as [V1 | [t1' S1]]; auto.
    destruct IHHT2 as [V2 | [t2' S2]]; auto.
    + destruct (canonical_arrow _ _ _ V1 H2) as [body Heq]; subst.
      right. exists (subst 0 t2 body). constructor; auto.
    + right. exists (TApp t1 t2'). constructor; auto.
    + right. exists (TApp t1' t2). constructor; auto.
  - (* Let *)
    destruct IHHT1 as [V1 | [t1' S1]]; auto.
    + right. exists (subst 0 t1 t2). constructor; auto.
    + right. exists (TLet t1' t2). constructor; auto.
  - (* If *)
    destruct IHHT1 as [Vc | [c' Sc]]; auto.
    + destruct (canonical_bool _ Vc H1) as [b Hb]; subst.
      right. destruct b; [exists t2 | exists t3]; constructor.
    + right. exists (TIf c' t2 t3). constructor; auto.
Qed.

(* End of Soundness.v *)
