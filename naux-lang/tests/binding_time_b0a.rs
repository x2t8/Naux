use naux::core::{
    binding_time_policy_bytes, binding_time_policy_hash, binding_time_request_bytes,
    binding_time_request_hash, validate_binding_time_b0_request, BindingTime, BindingTimeBudget,
    BindingTimeRequest, BindingTimeRequestCode, CoreArtifact, CoreProfile, EffectRow, Function,
    FunctionId, LocalId, Parameter, Program, SemanticHash, Term, Type, B0_MAX_CALL_EDGES_HARD_CAP,
    B0_MAX_FIXPOINT_ITERATIONS_HARD_CAP, B0_MAX_NODES_HARD_CAP,
};

const TIMES: [BindingTime; 2] = [BindingTime::Static, BindingTime::Dynamic];

fn artifact(profile: CoreProfile) -> CoreArtifact {
    CoreArtifact::seal(Program {
        schema: naux::core::SchemaVersion::core_n0(),
        profile,
        entry: FunctionId(0),
        functions: vec![Function {
            id: FunctionId(0),
            region_parameters: vec![],
            parameters: vec![
                Parameter {
                    local: LocalId(0),
                    ty: Type::I64,
                },
                Parameter {
                    local: LocalId(1),
                    ty: Type::I64,
                },
            ],
            effects: EffectRow::pure(),
            result: Type::I64,
            body: Term::Return(naux::core::Operand::Local(LocalId(0))),
        }],
    })
    .expect("test program must encode")
}

fn budget() -> BindingTimeBudget {
    BindingTimeBudget::new(1_024, 512, 32)
}

fn request(artifact: &CoreArtifact) -> BindingTimeRequest {
    BindingTimeRequest::p1v0(
        artifact,
        vec![BindingTime::Static, BindingTime::Dynamic],
        budget(),
    )
    .expect("B0 request must encode")
}

fn has_code(errors: &naux::core::BindingTimeRequestErrors, code: BindingTimeRequestCode) -> bool {
    errors.0.iter().any(|error| error.code == code)
}

#[test]
fn two_point_lattice_obeys_order_and_join_laws() {
    assert!(BindingTime::Static.is_at_most(BindingTime::Static));
    assert!(BindingTime::Static.is_at_most(BindingTime::Dynamic));
    assert!(!BindingTime::Dynamic.is_at_most(BindingTime::Static));
    assert!(BindingTime::Dynamic.is_at_most(BindingTime::Dynamic));

    for left in TIMES {
        for right in TIMES {
            assert_eq!(left.join(right), right.join(left));
            assert_eq!(left.join(left), left);
            for third in TIMES {
                assert_eq!(left.join(right).join(third), left.join(right.join(third)));
            }
        }
    }

    for lower_left in TIMES {
        for upper_left in TIMES {
            for lower_right in TIMES {
                for upper_right in TIMES {
                    if lower_left.is_at_most(upper_left) && lower_right.is_at_most(upper_right) {
                        assert!(lower_left
                            .join(lower_right)
                            .is_at_most(upper_left.join(upper_right)));
                    }
                }
            }
        }
    }
}

#[test]
fn canonical_p1v0_request_validates_and_recomputes_its_hash() {
    let artifact = artifact(CoreProfile::P1V0);
    let request = request(&artifact);
    let validated =
        validate_binding_time_b0_request(&artifact, &request).expect("request must validate");

    assert_eq!(validated.artifact().semantic_hash(), artifact.semantic_hash);
    assert_eq!(validated.request(), &request);
    assert_eq!(
        validated.request_hash(),
        binding_time_request_hash(&request).expect("request must hash")
    );
}

#[test]
fn policy_and_request_encodings_are_domain_separated_and_deterministic() {
    const POLICY_DOMAIN: &[u8] = b"NAUX:core-n0:binding-time-policy:b0:v1\0";
    const REQUEST_DOMAIN: &[u8] = b"NAUX:core-n0:binding-time-request:b0:v1\0";

    let artifact = artifact(CoreProfile::P1V0);
    let request = request(&artifact);
    let first_policy = binding_time_policy_bytes().expect("policy must encode");
    let second_policy = binding_time_policy_bytes().expect("policy must re-encode");
    let first_request = binding_time_request_bytes(&request).expect("request must encode");
    let second_request = binding_time_request_bytes(&request).expect("request must re-encode");

    assert_eq!(first_policy, second_policy);
    assert_eq!(first_request, second_request);
    assert!(first_policy.starts_with(POLICY_DOMAIN));
    assert!(first_request.starts_with(REQUEST_DOMAIN));
    assert_ne!(first_policy, first_request);
}

#[test]
fn policy_and_request_hashes_match_locked_vectors() {
    let artifact = artifact(CoreProfile::P1V0);
    let request = request(&artifact);

    assert_eq!(
        artifact.semantic_hash.to_hex(),
        "681ba7a62f778e3a20aa059b4fc2b2dfc4f17877f6b61a686ecd50618b3b87c2"
    );
    assert_eq!(
        binding_time_policy_hash()
            .expect("policy must hash")
            .to_hex(),
        "ee19444d56fe1de89eab9a0054c556b47e7ad115ec12255511d31a4526261a51"
    );
    assert_eq!(
        binding_time_request_hash(&request)
            .expect("request must hash")
            .to_hex(),
        "e338943aedab84880f56cbd627af68cf18a43cf101e17bf08006b2c0add1bfd3"
    );
}

#[test]
fn request_hash_covers_manifest_and_every_budget() {
    let artifact = artifact(CoreProfile::P1V0);
    let original = request(&artifact);
    let original_hash = binding_time_request_hash(&original).expect("request must hash");

    let mut variants = Vec::new();
    let mut manifest = original.clone();
    manifest.entry_parameters.swap(0, 1);
    variants.push(manifest);
    let mut nodes = original.clone();
    nodes.budget.max_nodes += 1;
    variants.push(nodes);
    let mut edges = original.clone();
    edges.budget.max_call_edges += 1;
    variants.push(edges);
    let mut iterations = original.clone();
    iterations.budget.max_fixpoint_iterations += 1;
    variants.push(iterations);

    for variant in variants {
        assert_ne!(
            binding_time_request_hash(&variant).expect("variant must hash"),
            original_hash
        );
    }
}

#[test]
fn source_profile_and_artifact_tampering_fail_closed() {
    let p1v1 = artifact(CoreProfile::P1V1);
    let errors = validate_binding_time_b0_request(&p1v1, &request(&p1v1))
        .expect_err("P1V1 must remain outside B0");
    assert!(has_code(
        &errors,
        BindingTimeRequestCode::UnsupportedProfile
    ));

    let mut tampered = artifact(CoreProfile::P1V0);
    tampered.semantic_hash = SemanticHash::ZERO;
    let errors = validate_binding_time_b0_request(&tampered, &request(&tampered))
        .expect_err("tampered artifact must fail");
    assert!(has_code(&errors, BindingTimeRequestCode::InvalidArtifact));
}

#[test]
fn forged_schema_provenance_and_policy_fields_fail_closed() {
    let artifact = artifact(CoreProfile::P1V0);
    let canonical = request(&artifact);
    let cases = [
        {
            let mut request = canonical.clone();
            request.schema_version = (2, 0, 0);
            (request, BindingTimeRequestCode::UnsupportedRequestSchema)
        },
        {
            let mut request = canonical.clone();
            request.source_program_hash = SemanticHash::ZERO;
            (request, BindingTimeRequestCode::SourceProgramHashMismatch)
        },
        {
            let mut request = canonical.clone();
            request.interpreter_semantics_hash = SemanticHash::ZERO;
            (
                request,
                BindingTimeRequestCode::InterpreterSemanticsHashMismatch,
            )
        },
        {
            let mut request = canonical.clone();
            request.policy_version = (2, 0, 0);
            (request, BindingTimeRequestCode::UnsupportedPolicyVersion)
        },
        {
            let mut request = canonical.clone();
            request.policy_hash = SemanticHash::ZERO;
            (request, BindingTimeRequestCode::PolicyHashMismatch)
        },
    ];

    for (request, expected) in cases {
        let errors = validate_binding_time_b0_request(&artifact, &request)
            .expect_err("forged request must fail");
        assert!(has_code(&errors, expected), "{errors}");
    }
}

#[test]
fn manifest_and_budget_boundaries_are_exact_and_fail_closed() {
    let artifact = artifact(CoreProfile::P1V0);
    let canonical = request(&artifact);

    let mut wrong_arity = canonical.clone();
    wrong_arity.entry_parameters.pop();
    let errors = validate_binding_time_b0_request(&artifact, &wrong_arity)
        .expect_err("wrong manifest arity must fail");
    assert!(has_code(
        &errors,
        BindingTimeRequestCode::EntryManifestArity
    ));

    let zero_cases = [
        BindingTimeBudget::new(0, 1, 1),
        BindingTimeBudget::new(1, 0, 1),
        BindingTimeBudget::new(1, 1, 0),
    ];
    for budget in zero_cases {
        let mut request = canonical.clone();
        request.budget = budget;
        let errors = validate_binding_time_b0_request(&artifact, &request)
            .expect_err("zero budget must fail");
        assert!(has_code(&errors, BindingTimeRequestCode::ZeroBudget));
    }

    let over_cap_cases = [
        BindingTimeBudget::new(B0_MAX_NODES_HARD_CAP + 1, 1, 1),
        BindingTimeBudget::new(1, B0_MAX_CALL_EDGES_HARD_CAP + 1, 1),
        BindingTimeBudget::new(1, 1, B0_MAX_FIXPOINT_ITERATIONS_HARD_CAP + 1),
    ];
    for budget in over_cap_cases {
        let mut request = canonical.clone();
        request.budget = budget;
        let errors = validate_binding_time_b0_request(&artifact, &request)
            .expect_err("over-cap budget must fail");
        assert!(has_code(
            &errors,
            BindingTimeRequestCode::BudgetHardCapExceeded
        ));
    }

    let mut exact_caps = canonical;
    exact_caps.budget = BindingTimeBudget::new(
        B0_MAX_NODES_HARD_CAP,
        B0_MAX_CALL_EDGES_HARD_CAP,
        B0_MAX_FIXPOINT_ITERATIONS_HARD_CAP,
    );
    validate_binding_time_b0_request(&artifact, &exact_caps)
        .expect("exact hard caps must remain valid");
}
