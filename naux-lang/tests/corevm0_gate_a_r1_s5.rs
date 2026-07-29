use naux::core::{
    branch_mix_kernel_program, build_definitional_corevm0, certify_binding_time_b0d,
    corevm0_gate_a_case_input_hash, corevm0_gate_a_evidence_hash, corevm0_gate_a_manifest,
    corevm0_gate_a_manifest_hash, corevm0_gate_a_record_hash, corevm0_gate_a_results_hash,
    corevm0_gate_a_telemetry_hash, emit_corevm0_gate_a_r1_s5, specialize_corevm0_r1_s4,
    validate_binding_time_b0_request, validate_specialization_r0a_request,
    verify_corevm0_gate_a_r1_s5, BindingTime, BindingTimeBudget, BindingTimeCertificate,
    BindingTimeRequest, CoreVmGateAAssurance, CoreVmGateACaseClass, CoreVmGateAEffect,
    CoreVmGateAEvidence, CoreVmGateAF64, CoreVmGateAOutcome, CoreVmGateAReplayError,
    CoreVmGateAUsage, CoreVmGateAWorkload, CoreVmProgram, CoreVmR1S4Evidence,
    CoreVmR1S4Specialization, Mutability, PolyvariantR1S4Budget, RegionId, SpecializationBudget,
    SpecializationRequest, SpecializationSlot, Type, COREVM0_GATE_A_BOUNDS_CASES,
    COREVM0_GATE_A_EDGE_CASES, COREVM0_GATE_A_EXHAUSTIVE_CASES, COREVM0_GATE_A_GENERATED_CASES,
    COREVM0_GATE_A_TOTAL_CASES,
};
use std::sync::OnceLock;

struct Fixture {
    program: CoreVmProgram,
    binding: BindingTimeRequest,
    certificate: BindingTimeCertificate,
    request: SpecializationRequest,
    budget: PolyvariantR1S4Budget,
    specialization: CoreVmR1S4Specialization,
    s4_evidence: CoreVmR1S4Evidence,
    gate_a_evidence: CoreVmGateAEvidence,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let program = branch_mix_kernel_program();
        let bound =
            build_definitional_corevm0(&program).expect("the frozen lighthouse must construct");
        let binding = BindingTimeRequest::p1v0(
            bound.artifact(),
            vec![
                BindingTime::Static,
                BindingTime::Dynamic,
                BindingTime::Dynamic,
            ],
            BindingTimeBudget::new(1_000_000, 1_000_000, 10_000),
        )
        .expect("the Gate A B0 request must encode");
        let validated_binding = validate_binding_time_b0_request(bound.artifact(), &binding)
            .expect("the Gate A B0 request must validate");
        let certificate = certify_binding_time_b0d(&validated_binding)
            .expect("the Gate A B0 certificate must emit");
        let request = SpecializationRequest::p1v0(
            bound.artifact(),
            &binding,
            &certificate,
            vec![
                SpecializationSlot::Static(bound.program_image().clone()),
                SpecializationSlot::Dynamic(array_type()),
                SpecializationSlot::Dynamic(Type::I64),
            ],
            SpecializationBudget::new(1_000_000, 1_000_000, 100_000_000, 1_000_000, 1_000_000_000),
        )
        .expect("the Gate A R0 request must encode");
        let validated =
            validate_specialization_r0a_request(bound.artifact(), &binding, &certificate, &request)
                .expect("the Gate A R0 request must validate");
        let budget = generous_s4_budget();
        let specialization = specialize_corevm0_r1_s4(&bound, &validated, budget)
            .expect("the frozen lighthouse must specialize through R1-S4");
        let s4_evidence = naux::core::emit_corevm0_r1_s4_evidence(&specialization);
        let gate_a_evidence = emit_corevm0_gate_a_r1_s5(&program, &specialization, &s4_evidence)
            .expect("the finite Gate A corpus must agree across all three engines");
        Fixture {
            program,
            binding,
            certificate,
            request,
            budget,
            specialization,
            s4_evidence,
            gate_a_evidence,
        }
    })
}

#[test]
fn corpus_manifest_is_internal_bounded_and_locked() {
    let first = corevm0_gate_a_manifest().expect("the fixed corpus must generate");
    let second = corevm0_gate_a_manifest().expect("the fixed corpus must regenerate");
    assert_eq!(first, second);
    assert_eq!(first.edge_cases, COREVM0_GATE_A_EDGE_CASES);
    assert_eq!(first.exhaustive_cases, COREVM0_GATE_A_EXHAUSTIVE_CASES);
    assert_eq!(first.generated_cases, COREVM0_GATE_A_GENERATED_CASES);
    assert_eq!(first.bounds_cases, COREVM0_GATE_A_BOUNDS_CASES);
    assert_eq!(first.total_cases, COREVM0_GATE_A_TOTAL_CASES);
    assert_eq!(first.cases.len(), COREVM0_GATE_A_TOTAL_CASES as usize);
    let raw_bits = first
        .cases
        .iter()
        .flat_map(|case| case.input.array_f64_bits.iter().copied())
        .collect::<Vec<_>>();
    for required in [
        f64::MAX.to_bits(),
        (-f64::MAX).to_bits(),
        f64::MIN_POSITIVE.to_bits(),
        (-f64::MIN_POSITIVE).to_bits(),
        1,
        (1_u64 << 63) | 1,
        0x7ff8_0000_0000_0001,
        0xfff8_0000_0000_0002,
    ] {
        assert!(
            raw_bits.contains(&required),
            "the finite edge corpus must preserve raw input bits {required:#018x}"
        );
    }
    assert_eq!(
        corevm0_gate_a_manifest_hash(&first).expect("manifest must hash"),
        first.manifest_hash
    );
    assert_eq!(
        first.manifest_hash.to_hex(),
        "0c4e4e796d60d571c874fd37b87e0418e1240f469a03672a6a4af4a4047b4e8f"
    );
}

#[test]
fn finite_three_way_evidence_preserves_bits_nan_bounds_and_trace() {
    let fixture = fixture();
    let evidence = &fixture.gate_a_evidence;
    assert_eq!(
        evidence.assurance,
        CoreVmGateAAssurance::FiniteBoundedValidation
    );
    assert_eq!(evidence.records.len(), COREVM0_GATE_A_TOTAL_CASES as usize);
    for record in &evidence.records {
        assert_eq!(record.seed.outcome, record.definitional_core.outcome);
        assert_eq!(record.seed.outcome, record.residual_core.outcome);
        assert_eq!(
            record.seed.effect_trace,
            record.definitional_core.effect_trace
        );
        assert_eq!(record.seed.effect_trace, record.residual_core.effect_trace);
        assert_eq!(
            corevm0_gate_a_record_hash(record).expect("record must hash"),
            record.record_hash
        );
    }
    let mut telemetry_only = evidence.records.clone();
    telemetry_only[0].seed.steps ^= 1;
    assert_eq!(
        corevm0_gate_a_record_hash(&telemetry_only[0]).expect("semantic record must hash"),
        evidence.records[0].record_hash,
        "engine work usage must not enter the semantic result hash"
    );
    assert_ne!(
        corevm0_gate_a_telemetry_hash(&telemetry_only, evidence.execution_budget, evidence.usage,)
            .expect("mutated telemetry must hash"),
        evidence.telemetry_hash,
        "ordered work usage must enter the separate telemetry hash"
    );

    let bounds_cases = evidence
        .corpus
        .cases
        .iter()
        .filter(|case| case.class == CoreVmGateACaseClass::BoundsEffect)
        .collect::<Vec<_>>();
    assert_eq!(bounds_cases.len(), COREVM0_GATE_A_BOUNDS_CASES as usize);

    let empty = bounds_cases
        .iter()
        .find(|case| case.input.array_f64_bits.is_empty())
        .expect("the Bounds corpus must contain an empty array");
    let empty_record = &evidence.records[empty.ordinal as usize];
    assert_eq!(empty_record.seed.outcome, CoreVmGateAOutcome::Bounds);
    assert_eq!(
        empty_record.seed.effect_trace,
        vec![CoreVmGateAEffect::Bounds]
    );

    let second_read_failure = bounds_cases
        .iter()
        .find(|case| case.input.array_f64_bits == vec![3.25_f64.to_bits()])
        .expect("the Bounds corpus must contain a second-read failure");
    let second_read_record = &evidence.records[second_read_failure.ordinal as usize];
    assert_eq!(second_read_record.seed.outcome, CoreVmGateAOutcome::Bounds);
    assert_eq!(
        second_read_record.seed.effect_trace,
        vec![CoreVmGateAEffect::Bounds]
    );
    assert!(
        second_read_record.seed.steps > empty_record.seed.steps,
        "the later failure must prove the first ordered read completed"
    );

    let signed_zero = bounds_cases
        .iter()
        .find(|case| case.input.array_f64_bits == vec![3.25_f64.to_bits(), (-0.0_f64).to_bits()])
        .expect("the Bounds corpus must contain negative zero");
    assert_eq!(
        evidence.records[signed_zero.ordinal as usize].seed.outcome,
        CoreVmGateAOutcome::ReturnF64(CoreVmGateAF64::ExactBits((-0.0_f64).to_bits()))
    );

    let nan = bounds_cases
        .iter()
        .find(|case| {
            case.input.array_f64_bits.len() == 2
                && f64::from_bits(case.input.array_f64_bits[1]).is_nan()
        })
        .expect("the Bounds corpus must contain NaN");
    assert_eq!(
        evidence.records[nan.ordinal as usize].seed.outcome,
        CoreVmGateAOutcome::ReturnF64(CoreVmGateAF64::CanonicalNaN)
    );

    assert_eq!(
        evidence.evidence_hash.to_hex(),
        "5c2d81b3cd20ef72e41437b1426156642404a1c736faf7cace70ffe1e82c5f01"
    );
    assert_eq!(
        evidence.results_hash.to_hex(),
        "bc755f8a99b6cbffaa7fee7d1e7cbc81de7787249a2dc5ba83458798a2366249"
    );
    assert_eq!(
        corevm0_gate_a_telemetry_hash(
            &evidence.records,
            evidence.execution_budget,
            evidence.usage,
        )
        .expect("telemetry must hash"),
        evidence.telemetry_hash
    );
    assert_eq!(
        evidence.telemetry_hash.to_hex(),
        "f5d709e2713fac7f2268ad6da4855010dc7978a61529adfd74cf7b34b9ef1a29"
    );
    assert_eq!(evidence.usage.seed_steps, 4_665);
    assert_eq!(evidence.usage.definitional_core_steps, 509_714);
    assert_eq!(evidence.usage.residual_core_steps, 7_274);
}

#[test]
fn raw_replay_and_mutations_are_fail_closed() {
    let fixture = fixture();
    let verified = verify_corevm0_gate_a_r1_s5(
        &fixture.program,
        &fixture.binding,
        &fixture.certificate,
        &fixture.request,
        fixture.budget,
        fixture.specialization.artifact(),
        &fixture.s4_evidence,
        &fixture.gate_a_evidence,
    )
    .expect("raw replay must regenerate the exact finite Gate A evidence");
    assert_eq!(verified.evidence(), &fixture.gate_a_evidence);
    assert_eq!(verified.residual(), fixture.specialization.artifact());

    let mut mutated_s4_evidence = fixture.s4_evidence.clone();
    mutated_s4_evidence.evidence_hash.0[0] ^= 1;
    assert!(matches!(
        verify_corevm0_gate_a_r1_s5(
            &fixture.program,
            &fixture.binding,
            &fixture.certificate,
            &fixture.request,
            fixture.budget,
            fixture.specialization.artifact(),
            &mutated_s4_evidence,
            &fixture.gate_a_evidence,
        ),
        Err(CoreVmGateAReplayError::S4(_))
    ));

    let mut mutated_s4_budget = fixture.budget;
    mutated_s4_budget.max_work_units += 1;
    assert!(matches!(
        verify_corevm0_gate_a_r1_s5(
            &fixture.program,
            &fixture.binding,
            &fixture.certificate,
            &fixture.request,
            mutated_s4_budget,
            fixture.specialization.artifact(),
            &fixture.s4_evidence,
            &fixture.gate_a_evidence,
        ),
        Err(CoreVmGateAReplayError::S4(_))
    ));

    macro_rules! reject_unsealed {
        ($mutation:expr) => {{
            let mut claim = fixture.gate_a_evidence.clone();
            ($mutation)(&mut claim);
            assert!(matches!(
                replay(fixture, &claim),
                Err(CoreVmGateAReplayError::InvalidEvidenceHash)
            ));
        }};
    }

    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.schema_version.2 ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.replay_version.2 ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.numeric_contract_version.2 ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.numeric_contract_hash.0[0] ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.s4_evidence_hash.0[0] ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.source_program_hash.0[0] ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.source_program_image_hash.0[0] ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.definitional_artifact_hash.0[0] ^= 1);
    reject_unsealed!(
        |claim: &mut CoreVmGateAEvidence| claim.core_interpreter_semantics_hash.0[0] ^= 1
    );
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.residual_hash.0[0] ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.s4_binding_hash.0[0] ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.s4_erasure_hash.0[0] ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.bounds_program_hash.0[0] ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim
        .bounds_definitional_artifact_hash
        .0[0] ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.bounds_residual_hash.0[0] ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.bounds_s4_evidence_hash.0[0] ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.corpus.generator_seed ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.records[0].seed.steps ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.results_hash.0[0] ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.execution_budget.max_cases ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.usage.seed_steps ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.telemetry_hash.0[0] ^= 1);
    reject_unsealed!(|claim: &mut CoreVmGateAEvidence| claim.evidence_hash.0[0] ^= 1);

    let mut unsealed = fixture.gate_a_evidence.clone();
    unsealed.usage.seed_steps ^= 1;
    assert!(matches!(
        verify_corevm0_gate_a_r1_s5(
            &fixture.program,
            &fixture.binding,
            &fixture.certificate,
            &fixture.request,
            fixture.budget,
            fixture.specialization.artifact(),
            &fixture.s4_evidence,
            &unsealed,
        ),
        Err(CoreVmGateAReplayError::InvalidEvidenceHash)
    ));

    // A caller may recompute every exposed corpus seal. Canonical manifest
    // regeneration must still reject a raw-input bit substitution.
    let mut resealed_manifest = fixture.gate_a_evidence.clone();
    let corpus_case = resealed_manifest
        .corpus
        .cases
        .iter_mut()
        .find(|case| {
            case.workload == CoreVmGateAWorkload::BranchMix && !case.input.array_f64_bits.is_empty()
        })
        .expect("the corpus contains a non-empty branch_mix case");
    let ordinal = corpus_case.ordinal as usize;
    corpus_case.input.array_f64_bits[0] ^= 1;
    corpus_case.input_hash =
        corevm0_gate_a_case_input_hash(corpus_case).expect("mutated input can be resealed");
    resealed_manifest.records[ordinal].input_hash = corpus_case.input_hash;
    resealed_manifest.records[ordinal].record_hash =
        corevm0_gate_a_record_hash(&resealed_manifest.records[ordinal])
            .expect("mutated record can be resealed");
    resealed_manifest.corpus.manifest_hash =
        corevm0_gate_a_manifest_hash(&resealed_manifest.corpus)
            .expect("mutated manifest can be resealed");
    resealed_manifest.results_hash = corevm0_gate_a_results_hash(&resealed_manifest.records)
        .expect("mutated results can be resealed");
    resealed_manifest.telemetry_hash = corevm0_gate_a_telemetry_hash(
        &resealed_manifest.records,
        resealed_manifest.execution_budget,
        resealed_manifest.usage,
    )
    .expect("mutated telemetry can be resealed");
    resealed_manifest.evidence_hash =
        corevm0_gate_a_evidence_hash(&resealed_manifest).expect("mutated evidence can be resealed");
    assert!(matches!(
        replay(fixture, &resealed_manifest),
        Err(CoreVmGateAReplayError::EvidenceMismatch)
    ));

    let mut omitted = fixture.gate_a_evidence.clone();
    omitted.corpus.cases.remove(0);
    omitted.records.remove(0);
    assert_resealed_manifest_rejected(fixture, omitted);

    let mut duplicated = fixture.gate_a_evidence.clone();
    duplicated
        .corpus
        .cases
        .insert(1, duplicated.corpus.cases[0].clone());
    duplicated.records.insert(1, duplicated.records[0].clone());
    assert_resealed_manifest_rejected(fixture, duplicated);

    let mut reordered = fixture.gate_a_evidence.clone();
    reordered.corpus.cases.swap(0, 1);
    reordered.records.swap(0, 1);
    assert_resealed_manifest_rejected(fixture, reordered);

    let mut reclassified = fixture.gate_a_evidence.clone();
    reclassified.corpus.cases[0].class = CoreVmGateACaseClass::DeterministicGenerated;
    assert_resealed_manifest_rejected(fixture, reclassified);

    let mut signed_zero = fixture.gate_a_evidence.clone();
    let signed_zero_bits = (-0.0_f64).to_bits();
    let signed_zero_input = signed_zero
        .corpus
        .cases
        .iter_mut()
        .flat_map(|case| &mut case.input.array_f64_bits)
        .find(|bits| **bits == signed_zero_bits)
        .expect("the canonical manifest must contain negative zero");
    *signed_zero_input = 0.0_f64.to_bits();
    assert_resealed_manifest_rejected(fixture, signed_zero);

    let mut nan_payload = fixture.gate_a_evidence.clone();
    let nan_input = nan_payload
        .corpus
        .cases
        .iter_mut()
        .flat_map(|case| &mut case.input.array_f64_bits)
        .find(|bits| f64::from_bits(**bits).is_nan())
        .expect("the canonical manifest must contain a NaN payload");
    *nan_input ^= 1;
    assert_resealed_manifest_rejected(fixture, nan_payload);

    // This attacker leaves the canonical manifest untouched, mutates one
    // backend's result and telemetry, then recomputes record, results,
    // telemetry, usage, and top seals. It passes every nested-seal check and
    // can be rejected only by complete semantic evidence regeneration.
    let mut fully_resealed = fixture.gate_a_evidence.clone();
    fully_resealed.records[0].seed.outcome = CoreVmGateAOutcome::Bounds;
    fully_resealed.records[0].seed.steps ^= 1;
    fully_resealed.records[0].record_hash = corevm0_gate_a_record_hash(&fully_resealed.records[0])
        .expect("backend mutation can be resealed");
    fully_resealed.results_hash = corevm0_gate_a_results_hash(&fully_resealed.records)
        .expect("mutated semantic results can be resealed");
    fully_resealed.usage = usage_from_records(&fully_resealed);
    fully_resealed.telemetry_hash = corevm0_gate_a_telemetry_hash(
        &fully_resealed.records,
        fully_resealed.execution_budget,
        fully_resealed.usage,
    )
    .expect("mutated telemetry can be fully resealed");
    fully_resealed.evidence_hash =
        corevm0_gate_a_evidence_hash(&fully_resealed).expect("top evidence can be fully resealed");
    assert!(matches!(
        replay(fixture, &fully_resealed),
        Err(CoreVmGateAReplayError::EvidenceMismatch)
    ));

    let mut oversized = fixture.gate_a_evidence.clone();
    oversized.records[0]
        .seed
        .effect_trace
        .extend([CoreVmGateAEffect::Bounds, CoreVmGateAEffect::Bounds]);
    assert!(matches!(
        replay(fixture, &oversized),
        Err(CoreVmGateAReplayError::InvalidClaimShape(_))
    ));
}

fn replay(fixture: &Fixture, evidence: &CoreVmGateAEvidence) -> Result<(), CoreVmGateAReplayError> {
    verify_corevm0_gate_a_r1_s5(
        &fixture.program,
        &fixture.binding,
        &fixture.certificate,
        &fixture.request,
        fixture.budget,
        fixture.specialization.artifact(),
        &fixture.s4_evidence,
        evidence,
    )
    .map(|_| ())
}

fn usage_from_records(evidence: &CoreVmGateAEvidence) -> CoreVmGateAUsage {
    CoreVmGateAUsage {
        seed_steps: evidence
            .records
            .iter()
            .map(|record| record.seed.steps)
            .sum(),
        definitional_core_steps: evidence
            .records
            .iter()
            .map(|record| record.definitional_core.steps)
            .sum(),
        residual_core_steps: evidence
            .records
            .iter()
            .map(|record| record.residual_core.steps)
            .sum(),
    }
}

fn assert_resealed_manifest_rejected(fixture: &Fixture, mut evidence: CoreVmGateAEvidence) {
    reseal_claim(&mut evidence);
    assert!(matches!(
        replay(fixture, &evidence),
        Err(CoreVmGateAReplayError::EvidenceMismatch)
    ));
}

fn reseal_claim(evidence: &mut CoreVmGateAEvidence) {
    assert_eq!(evidence.corpus.cases.len(), evidence.records.len());
    evidence.corpus.edge_cases = 0;
    evidence.corpus.exhaustive_cases = 0;
    evidence.corpus.generated_cases = 0;
    evidence.corpus.bounds_cases = 0;
    evidence.corpus.total_array_elements = 0;

    for (ordinal, (case, record)) in evidence
        .corpus
        .cases
        .iter_mut()
        .zip(&mut evidence.records)
        .enumerate()
    {
        case.ordinal = u32::try_from(ordinal).expect("test corpus ordinal must fit u32");
        case.input_hash = corevm0_gate_a_case_input_hash(case).expect("mutated input must reseal");
        record.case_ordinal = case.ordinal;
        record.input_hash = case.input_hash;
        record.record_hash =
            corevm0_gate_a_record_hash(record).expect("mutated record must reseal");
        evidence.corpus.total_array_elements +=
            u64::try_from(case.input.array_f64_bits.len()).expect("test input length must fit u64");
        match case.class {
            CoreVmGateACaseClass::Edge => evidence.corpus.edge_cases += 1,
            CoreVmGateACaseClass::BoundedExhaustive => evidence.corpus.exhaustive_cases += 1,
            CoreVmGateACaseClass::DeterministicGenerated => {
                evidence.corpus.generated_cases += 1;
            }
            CoreVmGateACaseClass::BoundsEffect => evidence.corpus.bounds_cases += 1,
        }
    }
    evidence.corpus.total_cases =
        u32::try_from(evidence.corpus.cases.len()).expect("test corpus length must fit u32");
    evidence.corpus.manifest_hash =
        corevm0_gate_a_manifest_hash(&evidence.corpus).expect("mutated manifest must reseal");
    evidence.results_hash =
        corevm0_gate_a_results_hash(&evidence.records).expect("mutated results must reseal");
    evidence.usage = usage_from_records(evidence);
    evidence.telemetry_hash =
        corevm0_gate_a_telemetry_hash(&evidence.records, evidence.execution_budget, evidence.usage)
            .expect("mutated telemetry must reseal");
    evidence.evidence_hash =
        corevm0_gate_a_evidence_hash(evidence).expect("mutated top evidence must reseal");
}

fn array_type() -> Type {
    Type::Array {
        region: RegionId(0),
        mutability: Mutability::Read,
        element: Box::new(Type::F64),
    }
}

fn generous_s4_budget() -> PolyvariantR1S4Budget {
    PolyvariantR1S4Budget::new(
        100_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000,
        1_000_000_000,
    )
}
