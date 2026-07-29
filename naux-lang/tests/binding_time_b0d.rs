use naux::core::{
    binding_time_certificate_bytes, binding_time_certificate_hash, certify_binding_time_b0d,
    validate_binding_time_b0_request, verify_binding_time_b0_certificate, BindingTime,
    BindingTimeAnalysisCode, BindingTimeBudget, BindingTimeCertificate,
    BindingTimeCertificateBuildError, BindingTimeCertificateCode, BindingTimeRequest, CoreArtifact,
    CoreProfile, EffectRow, Function, FunctionId, LocalId, Operand, Parameter, Program, RValue,
    SemanticHash, StaticEvaluationEligibility, Term, Type,
};

fn seal(functions: Vec<Function>) -> CoreArtifact {
    CoreArtifact::seal(Program {
        schema: naux::core::SchemaVersion::core_n0(),
        profile: CoreProfile::P1V0,
        entry: FunctionId(0),
        functions,
    })
    .expect("test program must encode")
}

fn identity_call_program(tail: bool) -> CoreArtifact {
    let body = if tail {
        Term::TailCall {
            function: FunctionId(1),
            arguments: vec![Operand::Local(LocalId(0))],
        }
    } else {
        Term::Let {
            binder: LocalId(1),
            ty: Type::I64,
            value: RValue::Call {
                function: FunctionId(1),
                arguments: vec![Operand::Local(LocalId(0))],
            },
            next: Box::new(Term::Return(Operand::Local(LocalId(1)))),
        }
    };
    seal(vec![
        Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![Parameter {
                local: LocalId(0),
                ty: Type::I64,
            }],
            effects: EffectRow::pure(),
            result: Type::I64,
            body,
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

fn recursive_program() -> CoreArtifact {
    seal(vec![Function {
        id: FunctionId(0),
        region_parameters: vec![],
        parameters: vec![Parameter {
            local: LocalId(0),
            ty: Type::Bool,
        }],
        effects: EffectRow::pure(),
        result: Type::I64,
        body: Term::If {
            condition: Operand::Local(LocalId(0)),
            then_term: Box::new(Term::Return(Operand::I64(1))),
            else_term: Box::new(Term::TailCall {
                function: FunctionId(0),
                arguments: vec![Operand::Local(LocalId(0))],
            }),
        },
    }])
}

fn emit(
    artifact: &CoreArtifact,
    manifest: Vec<BindingTime>,
    budget: BindingTimeBudget,
) -> (BindingTimeRequest, BindingTimeCertificate) {
    let request =
        BindingTimeRequest::p1v0(artifact, manifest, budget).expect("request must encode");
    let validated =
        validate_binding_time_b0_request(artifact, &request).expect("request must validate");
    let certificate = certify_binding_time_b0d(&validated).expect("certificate must emit");
    (request, certificate)
}

fn standard_budget() -> BindingTimeBudget {
    BindingTimeBudget::new(1_000, 100, 20)
}

fn resealed(
    certificate: &BindingTimeCertificate,
    mutation: impl FnOnce(&mut BindingTimeCertificate),
) -> BindingTimeCertificate {
    let mut forged = certificate.clone();
    mutation(&mut forged);
    forged.certificate_hash =
        binding_time_certificate_hash(&forged).expect("mutated certificate must encode");
    forged
}

fn assert_rejected_with(
    artifact: &CoreArtifact,
    request: &BindingTimeRequest,
    certificate: &BindingTimeCertificate,
    code: BindingTimeCertificateCode,
) {
    let errors = verify_binding_time_b0_certificate(artifact, request, certificate)
        .expect_err("forged certificate must fail closed");
    assert!(
        errors.0.iter().any(|error| error.code == code),
        "expected {code:?}, found {:?}",
        errors.0
    );
}

#[test]
fn canonical_certificate_is_sealed_verified_and_vector_locked() {
    let artifact = identity_call_program(false);
    let (request, certificate) = emit(&artifact, vec![BindingTime::Dynamic], standard_budget());
    let bytes = binding_time_certificate_bytes(&certificate).expect("certificate must encode");

    assert!(bytes.starts_with(b"NAUX:core-n0:binding-time-certificate:b0:v1\0"));
    assert_eq!(bytes.len(), 660);
    assert_eq!(
        certificate.certificate_hash,
        binding_time_certificate_hash(&certificate).expect("certificate must hash")
    );
    assert_eq!(
        certificate.certificate_hash.to_hex(),
        "9e778974108bec97945e6b64294fc6b4a0cba174ef7970b51cceb92f3cf1c857"
    );
    let verified = verify_binding_time_b0_certificate(&artifact, &request, &certificate)
        .expect("canonical certificate must verify");
    assert_eq!(verified.certificate(), &certificate);
}

#[test]
fn declared_hash_is_excluded_from_payload_but_verified() {
    let artifact = identity_call_program(false);
    let (request, certificate) = emit(&artifact, vec![BindingTime::Dynamic], standard_budget());
    let original_bytes =
        binding_time_certificate_bytes(&certificate).expect("certificate must encode");
    let mut forged = certificate.clone();
    forged.certificate_hash.0[0] ^= 1;

    assert_eq!(
        binding_time_certificate_bytes(&forged).expect("forged certificate must encode"),
        original_bytes
    );
    assert_rejected_with(
        &artifact,
        &request,
        &forged,
        BindingTimeCertificateCode::CertificateHashMismatch,
    );
}

#[test]
fn every_provenance_and_request_binding_mutation_fails_closed() {
    let artifact = identity_call_program(false);
    let (request, certificate) = emit(&artifact, vec![BindingTime::Dynamic], standard_budget());

    let cases = [
        (
            resealed(&certificate, |value| value.schema_version.0 += 1),
            BindingTimeCertificateCode::UnsupportedCertificateSchema,
        ),
        (
            resealed(&certificate, |value| value.source_program_hash.0[0] ^= 1),
            BindingTimeCertificateCode::SourceProgramHashMismatch,
        ),
        (
            resealed(&certificate, |value| {
                value.interpreter_semantics_hash.0[0] ^= 1;
            }),
            BindingTimeCertificateCode::InterpreterSemanticsHashMismatch,
        ),
        (
            resealed(&certificate, |value| value.policy_hash.0[0] ^= 1),
            BindingTimeCertificateCode::PolicyHashMismatch,
        ),
        (
            resealed(&certificate, |value| value.request_hash.0[0] ^= 1),
            BindingTimeCertificateCode::RequestHashMismatch,
        ),
        (
            resealed(&certificate, |value| value.entry_function = FunctionId(1)),
            BindingTimeCertificateCode::EntryFunctionMismatch,
        ),
        (
            resealed(&certificate, |value| {
                value.entry_parameters[0] = BindingTime::Static;
            }),
            BindingTimeCertificateCode::EntryManifestMismatch,
        ),
        (
            resealed(&certificate, |value| {
                value.declared_budget.max_nodes += 1;
            }),
            BindingTimeCertificateCode::DeclaredBudgetMismatch,
        ),
    ];

    for (forged, code) in cases {
        assert_rejected_with(&artifact, &request, &forged, code);
    }
}

#[test]
fn missing_duplicate_and_reordered_evidence_fails_closed() {
    let artifact = identity_call_program(false);
    let (request, certificate) = emit(&artifact, vec![BindingTime::Dynamic], standard_budget());

    let missing_summary = resealed(&certificate, |value| {
        value.function_summaries.pop();
    });
    assert_rejected_with(
        &artifact,
        &request,
        &missing_summary,
        BindingTimeCertificateCode::FunctionSummarySetMismatch,
    );

    let reordered_summaries = resealed(&certificate, |value| {
        value.function_summaries.swap(0, 1);
    });
    assert_rejected_with(
        &artifact,
        &request,
        &reordered_summaries,
        BindingTimeCertificateCode::NonCanonicalSummaryOrder,
    );

    let duplicate_judgment = resealed(&certificate, |value| {
        value.judgments.insert(1, value.judgments[0].clone());
    });
    assert_rejected_with(
        &artifact,
        &request,
        &duplicate_judgment,
        BindingTimeCertificateCode::NonCanonicalJudgmentOrder,
    );

    let missing_judgment = resealed(&certificate, |value| {
        value.judgments.pop();
    });
    assert_rejected_with(
        &artifact,
        &request,
        &missing_judgment,
        BindingTimeCertificateCode::JudgmentsMismatch,
    );

    let reordered_judgments = resealed(&certificate, |value| {
        value.judgments.swap(0, 1);
    });
    assert_rejected_with(
        &artifact,
        &request,
        &reordered_judgments,
        BindingTimeCertificateCode::NonCanonicalJudgmentOrder,
    );
}

#[test]
fn semantic_summary_judgment_and_budget_mutations_fail_independent_replay() {
    let artifact = identity_call_program(false);
    let (request, certificate) = emit(&artifact, vec![BindingTime::Dynamic], standard_budget());

    let summary = resealed(&certificate, |value| {
        value.function_summaries[1].result = BindingTime::Static;
    });
    assert_rejected_with(
        &artifact,
        &request,
        &summary,
        BindingTimeCertificateCode::FunctionSummariesMismatch,
    );

    let judgment = resealed(&certificate, |value| {
        value.judgments[0].binding_time = match value.judgments[0].binding_time {
            BindingTime::Static => BindingTime::Dynamic,
            BindingTime::Dynamic => BindingTime::Static,
        };
    });
    assert_rejected_with(
        &artifact,
        &request,
        &judgment,
        BindingTimeCertificateCode::JudgmentsMismatch,
    );

    let node_identity = resealed(&certificate, |value| {
        let segment = value
            .judgments
            .last_mut()
            .and_then(|judgment| judgment.node.path.last_mut())
            .expect("last vector judgment has a structural path");
        segment.index += 1;
    });
    assert_rejected_with(
        &artifact,
        &request,
        &node_identity,
        BindingTimeCertificateCode::JudgmentsMismatch,
    );

    let eligibility = resealed(&certificate, |value| {
        let judgment = value
            .judgments
            .last_mut()
            .expect("certificate has judgments");
        judgment.static_evaluation = match judgment.static_evaluation {
            StaticEvaluationEligibility::EligiblePure => StaticEvaluationEligibility::Denied,
            StaticEvaluationEligibility::Denied => StaticEvaluationEligibility::EligiblePure,
        };
    });
    assert_rejected_with(
        &artifact,
        &request,
        &eligibility,
        BindingTimeCertificateCode::JudgmentsMismatch,
    );

    let usage = resealed(&certificate, |value| {
        value.budget_usage.nodes += 1;
    });
    assert_rejected_with(
        &artifact,
        &request,
        &usage,
        BindingTimeCertificateCode::BudgetUsageMismatch,
    );
}

#[test]
fn independent_replay_matches_analyzer_across_call_and_recursive_corpus() {
    let corpus = [
        (identity_call_program(false), Type::I64),
        (identity_call_program(true), Type::I64),
        (recursive_program(), Type::Bool),
    ];
    for (artifact, parameter_type) in corpus {
        for binding_time in [BindingTime::Static, BindingTime::Dynamic] {
            let manifest = match parameter_type {
                Type::I64 | Type::Bool => vec![binding_time],
                _ => unreachable!("bounded corpus uses one scalar parameter"),
            };
            let (request, certificate) = emit(&artifact, manifest, standard_budget());
            verify_binding_time_b0_certificate(&artifact, &request, &certificate)
                .expect("independent replay must agree with analyzer");
        }
    }
}

#[test]
fn invalid_source_or_request_never_reaches_certificate_evidence() {
    let artifact = identity_call_program(false);
    let (request, certificate) = emit(&artifact, vec![BindingTime::Dynamic], standard_budget());

    let mut forged_request = request.clone();
    forged_request.source_program_hash = SemanticHash::ZERO;
    assert_rejected_with(
        &artifact,
        &forged_request,
        &certificate,
        BindingTimeCertificateCode::InvalidRequest,
    );

    let mut forged_artifact = artifact.clone();
    forged_artifact.semantic_hash = SemanticHash::ZERO;
    assert_rejected_with(
        &forged_artifact,
        &request,
        &certificate,
        BindingTimeCertificateCode::InvalidRequest,
    );
}

#[test]
fn emitter_returns_no_certificate_when_analysis_budget_is_exhausted() {
    let artifact = identity_call_program(false);
    let request = BindingTimeRequest::p1v0(
        &artifact,
        vec![BindingTime::Dynamic],
        BindingTimeBudget::new(1, 100, 20),
    )
    .expect("request must encode");
    let validated =
        validate_binding_time_b0_request(&artifact, &request).expect("request must validate");
    let error = certify_binding_time_b0d(&validated).expect_err("exhaustion must fail closed");

    match error {
        BindingTimeCertificateBuildError::Analysis(error) => {
            assert_eq!(error.code, BindingTimeAnalysisCode::NodeBudgetExceeded);
        }
        BindingTimeCertificateBuildError::Encoding(error) => {
            panic!("unexpected encoding failure: {error}");
        }
    }
}
