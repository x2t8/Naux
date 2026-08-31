From Stdlib Require Import List Arith Bool Lia.
Import ListNotations.

From NauxCore Require Import Syntax Typing Smallstep.

Lemma lookup_shift_under_binder : forall Gamma Gamma' cutoff A,
  (forall x U,
    ctx_lookup x Gamma = Some U ->
    ctx_lookup (if Nat.leb cutoff x then x + 1 else x) Gamma' = Some U) ->
  forall x U,
    ctx_lookup x (A :: Gamma) = Some U ->
    ctx_lookup (if Nat.leb (S cutoff) x then x + 1 else x) (A :: Gamma') =
      Some U.
Proof.
  intros Gamma Gamma' cutoff A Hlookup [|x] U Hx.
  - simpl in Hx. inversion Hx; subst. reflexivity.
  - simpl in Hx |- *.
    destruct (Nat.leb cutoff x) eqn:Hcutoff; simpl.
    + replace (S x + 1) with (S (x + 1)) by lia.
      simpl. specialize (Hlookup x U Hx). now rewrite Hcutoff in Hlookup.
    + specialize (Hlookup x U Hx). now rewrite Hcutoff in Hlookup.
Qed.

Lemma typing_shift : forall Gamma t T,
  has_type Gamma t T ->
  forall Gamma' cutoff,
    (forall x U,
      ctx_lookup x Gamma = Some U ->
      ctx_lookup (if Nat.leb cutoff x then x + 1 else x) Gamma' = Some U) ->
    has_type Gamma' (shift 1 cutoff t) T.
Proof.
  intros Gamma t T HT.
  induction HT; intros Gamma' cutoff Hlookup; simpl.
  - destruct (Nat.leb cutoff x) eqn:Hcutoff; constructor;
      specialize (Hlookup x T H); now rewrite Hcutoff in Hlookup.
  - constructor. apply IHHT.
    now apply lookup_shift_under_binder.
  - econstructor.
    + apply IHHT1. exact Hlookup.
    + apply IHHT2. exact Hlookup.
  - econstructor.
    + apply IHHT1. exact Hlookup.
    + apply IHHT2. now apply lookup_shift_under_binder.
  - econstructor.
    + apply IHHT1. exact Hlookup.
    + apply IHHT2. exact Hlookup.
    + apply IHHT3. exact Hlookup.
  - constructor.
  - constructor.
Qed.

Lemma weakening_one : forall Gamma t T A,
  has_type Gamma t T ->
  has_type (A :: Gamma) (shift 1 0 t) T.
Proof.
  intros Gamma t T A HT.
  eapply typing_shift; eauto.
  intros x U Hx.
  assert (Nat.leb 0 x = true) as Hzero by (destruct x; reflexivity).
  rewrite Hzero.
  replace (x + 1) with (S x) by lia.
  simpl. exact Hx.
Qed.

Lemma typing_substitution : forall Gamma t T,
  has_type Gamma t T ->
  forall Gamma' index replacement U,
    has_type Gamma' replacement U ->
    ctx_lookup index Gamma = Some U ->
    (forall x V,
      x < index ->
      ctx_lookup x Gamma = Some V ->
      ctx_lookup x Gamma' = Some V) ->
    (forall x V,
      index < x ->
      ctx_lookup x Gamma = Some V ->
      ctx_lookup (x - 1) Gamma' = Some V) ->
    has_type Gamma' (subst index replacement t) T.
Proof.
  intros Gamma t T HT.
  induction HT; intros Gamma' index replacement U
    Hreplacement Hslot Hbefore Hafter; simpl.
  - destruct (Nat.compare x index) eqn:Hcompare.
    + apply Nat.compare_eq_iff in Hcompare. subst x.
      rewrite H in Hslot. inversion Hslot; subst. exact Hreplacement.
    + constructor. apply Hbefore.
      * now apply Nat.compare_lt_iff in Hcompare.
      * exact H.
    + constructor. apply Hafter.
      * now apply Nat.compare_gt_iff in Hcompare.
      * exact H.
  - constructor. eapply IHHT.
    + eapply weakening_one. exact Hreplacement.
    + simpl. exact Hslot.
    + intros [|x] V Hlt Hx.
      * simpl in Hx. inversion Hx; subst. reflexivity.
      * simpl in Hx |- *. apply Hbefore; [lia | exact Hx].
    + intros [|x] V Hgt Hx.
      * lia.
      * destruct x as [|x].
        -- lia.
        -- change (ctx_lookup (S x) Gamma = Some V) in Hx.
           change (ctx_lookup x Gamma' = Some V).
           specialize (Hafter (S x) V ltac:(lia) Hx).
           replace (S x - 1) with x in Hafter by lia. exact Hafter.
  - econstructor.
    + eapply IHHT1; eauto.
    + eapply IHHT2; eauto.
  - econstructor.
    + eapply IHHT1; eauto.
    + eapply IHHT2.
      * eapply weakening_one. exact Hreplacement.
      * simpl. exact Hslot.
      * intros [|x] V Hlt Hx.
        -- simpl in Hx. inversion Hx; subst. reflexivity.
        -- simpl in Hx |- *. apply Hbefore; [lia | exact Hx].
      * intros [|x] V Hgt Hx.
        -- lia.
        -- destruct x as [|x].
           ++ lia.
           ++ change (ctx_lookup (S x) Gamma = Some V) in Hx.
              change (ctx_lookup x Gamma' = Some V).
              specialize (Hafter (S x) V ltac:(lia) Hx).
              replace (S x - 1) with x in Hafter by lia. exact Hafter.
  - econstructor.
    + eapply IHHT1; eauto.
    + eapply IHHT2; eauto.
    + eapply IHHT3; eauto.
  - constructor.
  - constructor.
Qed.

Lemma substitution_zero : forall Gamma t T U s,
  has_type (U :: Gamma) t T ->
  has_type Gamma s U ->
  has_type Gamma (subst 0 s t) T.
Proof.
  intros Gamma t T U s Ht Hs.
  eapply typing_substitution with (U := U).
  - exact Ht.
  - exact Hs.
  - reflexivity.
  - intros. lia.
  - intros [|x] V Hgt Hx.
    + lia.
    + simpl in Hx |- *. replace (x - 0) with x by lia. exact Hx.
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
    match goal with
    | Habs : has_type [] (TAbs _ _) _ |- _ => inversion Habs; subst
    end.
    eapply substitution_zero; eauto.
  - (* LetValue *)
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
  induction HT; subst.
  - (* Var *) destruct x; inversion H.
  - (* Abs *) left. constructor.
  - (* App *)
    specialize (IHHT1 eq_refl).
    specialize (IHHT2 eq_refl).
    destruct IHHT1 as [V1 | [t1' S1]].
    destruct IHHT2 as [V2 | [t2' S2]].
    + match goal with
      | Hfun : has_type [] t1 (TyArrow _ _) |- _ =>
          destruct (canonical_arrow _ _ _ V1 Hfun) as [body Heq]
      end.
      subst.
      right. exists (subst 0 t2 body). constructor; auto.
    + right. exists (TApp t1 t2'). constructor; auto.
    + right. exists (TApp t1' t2). constructor; auto.
  - (* Let *)
    specialize (IHHT1 eq_refl).
    destruct IHHT1 as [V1 | [t1' S1]].
    + right. exists (subst 0 t1 t2). constructor; auto.
    + right. exists (TLet t1' t2). constructor; auto.
  - (* If *)
    specialize (IHHT1 eq_refl).
    destruct IHHT1 as [Vc | [c' Sc]].
    + match goal with
      | Hcondition : has_type [] c TyBool |- _ =>
          destruct (canonical_bool _ Vc Hcondition) as [b Hb]
      end.
      subst c.
      destruct b; right; eexists; constructor.
    + right. eexists. constructor. exact Sc.
  - (* Nat *) left. constructor.
  - (* Bool *) left. constructor.
Qed.

(* End of Soundness.v *)
