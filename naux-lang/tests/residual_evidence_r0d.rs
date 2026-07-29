use naux::core::{
    certify_binding_time_b0d, emit_residual_evidence_r0d, evaluate, evaluate_static_r0b2,
    generate_residual_r0c2, mixed_static_evaluation_hash, residual_evidence_bytes,
    residual_evidence_hash, semantic_bytes, validate_binding_time_b0_request,
    validate_specialization_r0a_request, verify_residual_evidence_r0d, BindingTime,
    BindingTimeBudget, BindingTimeCertificate, BindingTimeRequest, CoreArtifact, CoreProfile,
    CoreValue, Effect, EffectRow, ErrorKind, EvaluationBudget, Function, FunctionId, LocalId,
    NumericMode, Operand, Parameter, Primitive, Program, RValue, ResidualCore, ResidualEvidence,
    ResidualEvidenceBuildError, ResidualEvidenceCode, SemanticHash, SpecializationBudget,
    SpecializationRequest, SpecializationSlot, Term, Type,
};

struct Boundary {
    source: CoreArtifact,
    binding_time_request: BindingTimeRequest,
    binding_time_certificate: BindingTimeCertificate,
    specialization_request: SpecializationRequest,
}

fn seal(functions: Vec<Function>) -> CoreArtifact {
    CoreArtifact::seal(Program {
        schema: naux::core::SchemaVersion::core_n0(),
        profile: CoreProfile::P1V0,
        entry: FunctionId(0),
        functions,
    })
    .expect("test program must encode")
}

fn primitive(operation: Primitive, arguments: Vec<Operand>) -> RValue {
    RValue::Primitive {
        operation,
        arguments,
    }
}

/// entry(x dynamic):
///   a = f1(7)                 // static call
///   p = a >= 5               // static true
///   if p { a + x } else { checked MAX + 1 }
fn source_program() -> CoreArtifact {
    seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(0),
                ty: Type::I64,
            }],
            effects: EffectRow::canonical(vec![Effect::Error(ErrorKind::Overflow)]),
            result: Type::I64,
            body: Term::Let {
                binder: LocalId(1),
                ty: Type::I64,
                value: RValue::Call {
                    function: FunctionId(1),
                    arguments: vec![Operand::I64(7)],
                },
                next: Box::new(Term::Let {
                    binder: LocalId(2),
                    ty: Type::Bool,
                    value: primitive(
                        Primitive::I64CmpGe,
                        vec![Operand::Local(LocalId(1)), Operand::I64(5)],
                    ),
                    next: Box::new(Term::If {
                        condition: Operand::Local(LocalId(2)),
                        then_term: Box::new(Term::Let {
                            binder: LocalId(3),
                            ty: Type::I64,
                            value: primitive(
                                Primitive::I64Add(NumericMode::Wrapping),
                                vec![Operand::Local(LocalId(1)), Operand::Local(LocalId(0))],
                            ),
                            next: Box::new(Term::Return(Operand::Local(LocalId(3)))),
                        }),
                        else_term: Box::new(Term::Let {
                            binder: LocalId(4),
                            ty: Type::I64,
                            value: primitive(
                                Primitive::I64Add(NumericMode::Checked),
                                vec![Operand::I64(i64::MAX), Operand::I64(1)],
                            ),
                            next: Box::new(Term::Return(Operand::Local(LocalId(4)))),
                        }),
                    }),
                }),
            },
        },
        Function {
            id: FunctionId(1),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(0),
                ty: Type::I64,
            }],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Return(Operand::Local(LocalId(0))),
        },
    ])
}

fn boundary_for(
    source: CoreArtifact,
    manifest: Vec<BindingTime>,
    slots: Vec<SpecializationSlot>,
) -> Boundary {
    let binding_time_request = BindingTimeRequest::p1v0(
        &source,
        manifest,
        BindingTimeBudget::new(100_000, 100_000, 1_000),
    )
    .expect("B0 request must encode");
    let validated_binding_time = validate_binding_time_b0_request(&source, &binding_time_request)
        .expect("B0 request must validate");
    let binding_time_certificate =
        certify_binding_time_b0d(&validated_binding_time).expect("B0 evidence must emit");
    let specialization_request = SpecializationRequest::p1v0(
        &source,
        &binding_time_request,
        &binding_time_certificate,
        slots,
        SpecializationBudget::new(1_000, 1_000, 10_000, 1_000, 1_000_000),
    )
    .expect("R0 request must encode");
    Boundary {
        source,
        binding_time_request,
        binding_time_certificate,
        specialization_request,
    }
}

fn boundary() -> Boundary {
    boundary_for(
        source_program(),
        vec![BindingTime::Dynamic],
        vec![SpecializationSlot::Dynamic(Type::I64)],
    )
}

fn products(
    boundary: &Boundary,
) -> (
    naux::core::MixedStaticEvaluation,
    ResidualCore,
    ResidualEvidence,
) {
    let validated = validate_specialization_r0a_request(
        &boundary.source,
        &boundary.binding_time_request,
        &boundary.binding_time_certificate,
        &boundary.specialization_request,
    )
    .expect("R0 request must validate");
    let evaluation = evaluate_static_r0b2(&validated).expect("R0-B2 must evaluate");
    let residual = generate_residual_r0c2(&validated, &evaluation).expect("R0-C2 must residualize");
    let evidence = emit_residual_evidence_r0d(&validated, &evaluation, &residual)
        .expect("R0-D evidence must emit");
    (evaluation, residual, evidence)
}

fn verify<'evidence>(
    boundary: &Boundary,
    residual: &CoreArtifact,
    evidence: &'evidence ResidualEvidence,
) -> Result<naux::core::VerifiedResidualEvidence<'evidence>, naux::core::ResidualEvidenceErrors> {
    verify_residual_evidence_r0d(
        &boundary.source,
        &boundary.binding_time_request,
        &boundary.binding_time_certificate,
        &boundary.specialization_request,
        residual,
        evidence,
    )
}

fn reseal(evidence: &mut ResidualEvidence) {
    evidence.evidence_hash =
        residual_evidence_hash(evidence).expect("mutated evidence must still encode");
}

#[test]
fn canonical_evidence_is_deterministic_sealed_and_regeneratively_verified() {
    let boundary = boundary();
    let (first_evaluation, first_residual, first_evidence) = products(&boundary);
    let (second_evaluation, second_residual, second_evidence) = products(&boundary);

    let verified = verify(&boundary, &first_residual.artifact, &first_evidence)
        .expect("canonical R0-D evidence must verify");
    assert_eq!(verified.evidence(), &first_evidence);
    assert_eq!(first_evaluation, second_evaluation);
    assert_eq!(first_residual, second_residual);
    assert_eq!(first_evidence, second_evidence);
    assert_eq!(
        first_evidence.evaluation_hash,
        mixed_static_evaluation_hash(&first_evaluation).expect("evaluation must hash")
    );
    assert_eq!(
        first_evidence.evidence_hash,
        residual_evidence_hash(&first_evidence).expect("evidence must hash")
    );
    assert_eq!(
        first_evidence.evaluation_hash.to_hex(),
        "35fe28eebf550682e4abb45d7bc7baa1c2a8f80e18239442465da777c3f85295"
    );
    assert_eq!(
        first_evidence.evidence_hash.to_hex(),
        "98121ecc99f317a046a35a8b313d608d26ff6a909934a22d36b77434f4e0c683"
    );

    assert_eq!(
        first_residual.artifact.program.functions.len(),
        1,
        "regenerated R0-C2 output must contain no dead helper"
    );
    for x in [-7, 0, 99] {
        let original = evaluate(
            &boundary.source,
            vec![CoreValue::I64(x)],
            EvaluationBudget::new(1_000, 100),
        )
        .expect("source must evaluate");
        let residual = evaluate(
            &first_residual.artifact,
            vec![CoreValue::I64(x)],
            EvaluationBudget::new(1_000, 100),
        )
        .expect("residual must evaluate");
        assert_eq!(original.outcome, residual.outcome);
        assert_eq!(original.effect_trace, residual.effect_trace);
    }
}

#[test]
fn declared_hash_is_excluded_from_the_canonical_payload() {
    let boundary = boundary();
    let (_, _, evidence) = products(&boundary);
    let baseline = residual_evidence_bytes(&evidence).expect("evidence must encode");
    let mut mutated = evidence;
    mutated.evidence_hash = SemanticHash([0xa5; 32]);
    assert_eq!(
        residual_evidence_bytes(&mutated).expect("mutated declaration must encode"),
        baseline
    );
    assert_ne!(
        mutated.evidence_hash,
        residual_evidence_hash(&mutated).expect("payload hash must recompute")
    );
}

#[test]
fn every_evidence_binding_rejects_mutation_even_after_resealing() {
    let boundary = boundary();
    let (_, residual, evidence) = products(&boundary);
    let mut mutations = Vec::new();

    let mut value = evidence.clone();
    value.schema_version.2 += 1;
    mutations.push(value);
    let mut value = evidence.clone();
    value.replay_policy_version.2 += 1;
    mutations.push(value);
    let mut value = evidence.clone();
    value.source_program_hash = SemanticHash([1; 32]);
    mutations.push(value);
    let mut value = evidence.clone();
    value.interpreter_semantics_hash = SemanticHash([2; 32]);
    mutations.push(value);
    let mut value = evidence.clone();
    value.binding_time_request_hash = SemanticHash([3; 32]);
    mutations.push(value);
    let mut value = evidence.clone();
    value.binding_time_certificate_hash = SemanticHash([4; 32]);
    mutations.push(value);
    let mut value = evidence.clone();
    value.specialization_request_hash = SemanticHash([5; 32]);
    mutations.push(value);
    let mut value = evidence.clone();
    value.evaluation_hash = SemanticHash([6; 32]);
    mutations.push(value);
    let mut value = evidence.clone();
    value.evaluation_steps += 1;
    mutations.push(value);
    let mut value = evidence.clone();
    value.residual_program_hash = SemanticHash([7; 32]);
    mutations.push(value);
    let mut value = evidence.clone();
    value.residual_nodes += 1;
    mutations.push(value);
    let mut value = evidence.clone();
    value.residual_bytes += 1;
    mutations.push(value);

    for (index, mut mutation) in mutations.into_iter().enumerate() {
        reseal(&mut mutation);
        assert!(
            verify(&boundary, &residual.artifact, &mutation).is_err(),
            "resealed evidence mutation {index} must fail"
        );
    }

    let mut hash_only = evidence;
    hash_only.evidence_hash = SemanticHash([0xff; 32]);
    let errors = verify(&boundary, &residual.artifact, &hash_only)
        .expect_err("declared evidence-hash mutation must fail");
    assert!(errors
        .0
        .iter()
        .any(|error| error.code == ResidualEvidenceCode::EvidenceHashMismatch));
}

#[test]
fn a_resealed_but_forged_residual_fails_exact_regeneration() {
    let boundary = boundary();
    let (_, residual, evidence) = products(&boundary);
    let mut program = residual.artifact.program.clone();
    let Term::Let { value, .. } = &mut program.functions[0].body else {
        panic!("locked residual must begin with a materialized fact");
    };
    *value = RValue::Use(Operand::I64(8));
    let forged = CoreArtifact::seal(program).expect("forged program must still encode");

    let mut forged_evidence = evidence;
    forged_evidence.residual_program_hash = forged.semantic_hash;
    forged_evidence.residual_nodes = residual.residual_nodes;
    forged_evidence.residual_bytes = semantic_bytes(&forged.program)
        .expect("forged residual must encode")
        .len() as u64;
    reseal(&mut forged_evidence);

    let errors = verify(&boundary, &forged, &forged_evidence)
        .expect_err("a public caller cannot authorize a forged residual by resealing");
    assert!(errors
        .0
        .iter()
        .any(|error| error.code == ResidualEvidenceCode::ResidualStructureMismatch));
}

#[test]
fn the_emitter_rejects_forged_residual_wrappers() {
    let boundary = boundary();
    let (evaluation, residual, _) = products(&boundary);
    let validated = validate_specialization_r0a_request(
        &boundary.source,
        &boundary.binding_time_request,
        &boundary.binding_time_certificate,
        &boundary.specialization_request,
    )
    .expect("R0 request must validate");

    let mut bad_provenance = residual.clone();
    bad_provenance.source_hash = SemanticHash::ZERO;
    assert!(matches!(
        emit_residual_evidence_r0d(&validated, &evaluation, &bad_provenance),
        Err(ResidualEvidenceBuildError::ResidualProvenanceMismatch)
    ));

    let mut bad_metrics = residual;
    bad_metrics.residual_nodes += 1;
    assert!(matches!(
        emit_residual_evidence_r0d(&validated, &evaluation, &bad_metrics),
        Err(ResidualEvidenceBuildError::ResidualMetricMismatch)
    ));
}

#[test]
fn complete_outcomes_with_skipped_work_are_encoded_and_verified() {
    let source = seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![],
        effects: EffectRow::canonical(vec![Effect::Error(ErrorKind::Overflow)]),
        result: Type::I64,
        body: Term::Let {
            binder: LocalId(0),
            ty: Type::I64,
            value: primitive(
                Primitive::I64Add(NumericMode::Checked),
                vec![Operand::I64(i64::MAX), Operand::I64(1)],
            ),
            next: Box::new(Term::Return(Operand::I64(42))),
        },
    }]);
    let boundary = boundary_for(source, vec![], vec![]);
    let (evaluation, residual, evidence) = products(&boundary);

    assert!(!evaluation.skipped_nodes().is_empty());
    assert!(matches!(
        evaluation.outcome(),
        naux::core::MixedStaticOutcome::Complete(naux::core::SpecializationValue::I64(42))
    ));
    verify(&boundary, &residual.artifact, &evidence)
        .expect("complete-with-skips R0-D evidence must verify");
    assert_eq!(
        residual.artifact.program.functions[0].body, boundary.source.program.functions[0].body,
        "the independently admitted residual must retain skipped effects"
    );
}

#[test]
fn raw_request_or_certificate_mutation_cannot_reuse_evidence() {
    let boundary = boundary();
    let (_, residual, evidence) = products(&boundary);

    let mut request = boundary.specialization_request.clone();
    request.budget.max_residual_nodes += 1;
    let request_errors = verify_residual_evidence_r0d(
        &boundary.source,
        &boundary.binding_time_request,
        &boundary.binding_time_certificate,
        &request,
        &residual.artifact,
        &evidence,
    )
    .expect_err("a mutated specialization request must not reuse evidence");
    assert!(request_errors
        .0
        .iter()
        .any(|error| { error.code == ResidualEvidenceCode::SpecializationRequestHashMismatch }));

    let mut certificate = boundary.binding_time_certificate.clone();
    certificate.certificate_hash = SemanticHash::ZERO;
    let certificate_errors = verify_residual_evidence_r0d(
        &boundary.source,
        &boundary.binding_time_request,
        &certificate,
        &boundary.specialization_request,
        &residual.artifact,
        &evidence,
    )
    .expect_err("a mutated B0 certificate must fail before residual replay");
    assert!(certificate_errors
        .0
        .iter()
        .any(|error| error.code == ResidualEvidenceCode::InvalidRequest));
}
