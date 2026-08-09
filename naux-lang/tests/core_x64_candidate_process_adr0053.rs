#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

#[cfg(debug_assertions)]
use naux::core::probe_x64_gate_b_policy15_candidate_worker_debug;
use naux::core::{
    corevm0_gate_a_manifest, emit_x64_gate_b_policy15_candidate_capsule,
    emit_x64_gate_b_policy15_candidate_correctness,
    emit_x64_gate_b_policy15_candidate_process_evidence,
    execute_x64_gate_b_policy15_candidate_worker_case,
    verify_x64_gate_b_policy15_candidate_correctness,
    verify_x64_gate_b_policy15_candidate_process_evidence, CoreVmGateAWorkload,
    X64GateBPolicy15CandidateSelection,
};
use std::path::Path;

fn worker() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_naux-policy15-candidate-worker"))
}

#[test]
fn dedicated_worker_reconstructs_both_exact_selection_routes() {
    let manifest = corevm0_gate_a_manifest().expect("canonical Gate A manifest");
    for workload in [
        CoreVmGateAWorkload::BranchMix,
        CoreVmGateAWorkload::BoundsOrderedArrayGet,
    ] {
        let case = manifest
            .cases
            .iter()
            .find(|case| case.workload == workload)
            .expect("each frozen workload has at least one case");
        let ipc = execute_x64_gate_b_policy15_candidate_worker_case(worker(), case.ordinal)
            .expect("fresh child must reconstruct and bind the exact record");
        assert_eq!(ipc.case_ordinal(), case.ordinal);
        assert_eq!(ipc.workload(), workload);
        assert_eq!(ipc.input_hash(), case.input_hash);
        assert_eq!(
            ipc.selection(),
            match workload {
                CoreVmGateAWorkload::BranchMix => {
                    X64GateBPolicy15CandidateSelection::Policy15Candidate
                }
                CoreVmGateAWorkload::BoundsOrderedArrayGet => {
                    X64GateBPolicy15CandidateSelection::Policy14Fallback
                }
            }
        );
    }
}

#[cfg(debug_assertions)]
#[test]
fn candidate_worker_failure_matrix_is_contained_and_fail_closed() {
    let modes = [
        "abort",
        "abnormal",
        "timeout",
        "descendant-pipe",
        "missing",
        "malformed",
        "oversized",
        "diagnostics-one-over",
        "diagnostics-limit",
        "diagnostic-bytes-limit",
        "diagnostic-bytes-one-over",
        "trailing",
        "truncated",
        "double-frame",
        "valid-abnormal",
        "valid-abort",
        "wrong-case",
    ];
    for mode in modes {
        let timeout_millis = if matches!(mode, "timeout" | "descendant-pipe") {
            25
        } else {
            10_000
        };
        assert!(
            probe_x64_gate_b_policy15_candidate_worker_debug(worker(), 0, mode, timeout_millis,)
                .is_err(),
            "debug probe {mode} must fail closed"
        );
    }
    assert!(probe_x64_gate_b_policy15_candidate_worker_debug(worker(), 0, "unknown", 10).is_err());
}

#[test]
#[ignore = "regenerates the complete 2.526-billion-work candidate admission before launching and verifying all 51 fresh children; run explicitly in release mode"]
fn full_candidate_process_evidence_replays_from_verified_adr0052() {
    let candidate = emit_x64_gate_b_policy15_candidate_capsule().expect("ADR-0051 capsule");
    let correctness = emit_x64_gate_b_policy15_candidate_correctness(&candidate)
        .expect("ADR-0052 correctness evidence");
    let verified_correctness =
        verify_x64_gate_b_policy15_candidate_correctness(&candidate, &correctness)
            .expect("ADR-0052 must independently replay");
    let process =
        emit_x64_gate_b_policy15_candidate_process_evidence(worker(), verified_correctness)
            .expect("all 51 candidate/fallback children must pass");
    let verified_process =
        verify_x64_gate_b_policy15_candidate_process_evidence(verified_correctness, &process)
            .expect("candidate process aggregate must independently verify");
    assert_eq!(verified_process.evidence(), &process);
    assert_eq!(process.receipts().len(), 51);
    assert_eq!(process.candidate_execution_cases(), 46);
    assert_eq!(process.fallback_cases(), 5);
    println!(
        "ADR-0053 candidate-process results={}",
        process.results_hash().to_hex()
    );
}
