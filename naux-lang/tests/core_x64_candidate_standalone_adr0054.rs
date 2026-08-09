#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    authorize_x64_gate_b_policy15_standalone, build_x64_gate_b_policy15_standalone_artifact,
    emit_x64_gate_b_policy15_candidate_capsule, emit_x64_gate_b_policy15_candidate_correctness,
    emit_x64_gate_b_policy15_candidate_process_evidence,
    emit_x64_gate_b_policy15_standalone_process_evidence,
    verify_x64_gate_b_policy15_candidate_correctness,
    verify_x64_gate_b_policy15_candidate_process_evidence,
    verify_x64_gate_b_policy15_standalone_artifact,
    verify_x64_gate_b_policy15_standalone_process_evidence, X64StandaloneProfile,
    X64_GATE_B_POLICY15_STANDALONE_ARTIFACT_SCHEMA_VERSION,
    X64_GATE_B_POLICY15_STANDALONE_AUTHORITY_SCHEMA_VERSION,
    X64_GATE_B_POLICY15_STANDALONE_PROCESS_CASES,
    X64_GATE_B_POLICY15_STANDALONE_PROCESS_SCHEMA_VERSION, X64_TARGET_ENCODER_POLICY_VERSION,
};
use std::path::Path;

fn worker() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_naux-policy15-candidate-worker"))
}

#[test]
fn adr0054_boundary_versions_are_closed_without_changing_global_selection() {
    assert_eq!(
        X64_GATE_B_POLICY15_STANDALONE_AUTHORITY_SCHEMA_VERSION,
        (1, 0, 0)
    );
    assert_eq!(
        X64_GATE_B_POLICY15_STANDALONE_ARTIFACT_SCHEMA_VERSION,
        (1, 0, 0)
    );
    assert_eq!(
        X64_GATE_B_POLICY15_STANDALONE_PROCESS_SCHEMA_VERSION,
        (1, 0, 0)
    );
    assert_eq!(X64_GATE_B_POLICY15_STANDALONE_PROCESS_CASES, 51);
    assert_eq!(X64_TARGET_ENCODER_POLICY_VERSION, (1, 4, 0));
}

#[test]
#[ignore = "regenerates ADR-0051/0052, launches all ADR-0053 workers, then builds and directly executes both ADR-0054 ELF images; run explicitly in release mode"]
fn full_candidate_standalone_chain_replays_and_rejects_image_mutations() {
    let candidate = emit_x64_gate_b_policy15_candidate_capsule().expect("ADR-0051 capsule");
    let correctness =
        emit_x64_gate_b_policy15_candidate_correctness(&candidate).expect("ADR-0052 correctness");
    let verified_correctness =
        verify_x64_gate_b_policy15_candidate_correctness(&candidate, &correctness)
            .expect("ADR-0052 replay");
    let process =
        emit_x64_gate_b_policy15_candidate_process_evidence(worker(), verified_correctness)
            .expect("ADR-0053 fresh-child evidence");
    let verified_process =
        verify_x64_gate_b_policy15_candidate_process_evidence(verified_correctness, &process)
            .expect("ADR-0053 replay");

    let branch = authorize_x64_gate_b_policy15_standalone(
        verified_correctness,
        verified_process,
        X64StandaloneProfile::BranchMix,
    )
    .expect("BranchMix candidate standalone authority");
    let bounds = authorize_x64_gate_b_policy15_standalone(
        verified_correctness,
        verified_process,
        X64StandaloneProfile::Bounds,
    )
    .expect("Bounds fallback standalone authority");
    let branch_image =
        build_x64_gate_b_policy15_standalone_artifact(&branch).expect("BranchMix candidate ELF");
    let bounds_image =
        build_x64_gate_b_policy15_standalone_artifact(&bounds).expect("Bounds fallback ELF");
    let verified_branch =
        verify_x64_gate_b_policy15_standalone_artifact(&branch, branch_image.image_bytes())
            .expect("BranchMix candidate ELF replay");
    let verified_bounds =
        verify_x64_gate_b_policy15_standalone_artifact(&bounds, bounds_image.image_bytes())
            .expect("Bounds fallback ELF replay");

    for (authority, image) in [
        (&branch, branch_image.image_bytes()),
        (&bounds, bounds_image.image_bytes()),
    ] {
        for offset in [
            0,
            64,
            176,
            1_024.min(image.len() - 1),
            image.len() / 2,
            image.len() - 1,
        ] {
            let mut mutated = image.to_vec();
            mutated[offset] ^= 1;
            assert!(
                verify_x64_gate_b_policy15_standalone_artifact(authority, &mutated).is_err(),
                "single-byte image mutation at {offset} must fail"
            );
        }
        let mut trailing = image.to_vec();
        trailing.push(0);
        assert!(verify_x64_gate_b_policy15_standalone_artifact(authority, &trailing).is_err());
        assert!(verify_x64_gate_b_policy15_standalone_artifact(
            authority,
            &image[..image.len() - 1]
        )
        .is_err());
    }

    let direct = emit_x64_gate_b_policy15_standalone_process_evidence(
        &branch,
        &verified_branch,
        &bounds,
        &verified_bounds,
    )
    .expect("all 51 direct candidate/fallback processes must pass");
    let verified_direct = verify_x64_gate_b_policy15_standalone_process_evidence(
        &branch,
        &verified_branch,
        &bounds,
        &verified_bounds,
        &direct,
    )
    .expect("ADR-0054 direct-process aggregate must replay");
    assert_eq!(verified_direct.evidence(), &direct);
    assert_eq!(direct.records().len(), 51);
    assert_eq!(direct.candidate_execution_cases(), 46);
    assert_eq!(direct.fallback_cases(), 5);
    println!(
        "ADR-0054 branch-artifact={} bounds-artifact={} direct-results={}",
        verified_branch.artifact_hash().to_hex(),
        verified_bounds.artifact_hash().to_hex(),
        direct.results_hash().to_hex(),
    );
}
