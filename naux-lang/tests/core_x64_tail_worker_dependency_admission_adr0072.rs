#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    admit_x64_tail_worker_artifact, admit_x64_tail_worker_dependency_declarations,
    emit_x64_tail_worker_elf_evidence, probe_x64_tail_worker_dependency_admission_mutations,
    verify_x64_tail_worker_dependency_admission, x64_tail_worker_dependency_admission_policy_hash,
    x64_tail_worker_expectation_from_reviewed_bytes, SemanticHash,
    X64TailWorkerDependencyExpectation, X64_TAIL_WORKER_DEPENDENCY_ADMISSION_POLICY_ROOT,
    X64_TAIL_WORKER_DEPENDENCY_REQUIRED_FLAGS, X64_TAIL_WORKER_DEPENDENCY_REQUIRED_FLAGS_1,
    X64_TAIL_WORKER_ELF_POLICY_ROOT,
};
use std::fs;
use std::path::Path;

fn worker() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_naux-tail-enveloped-worker"))
}

fn reviewed_dependency_expectation() -> X64TailWorkerDependencyExpectation {
    X64TailWorkerDependencyExpectation::new(
        "/lib64/ld-linux-x86-64.so.2".to_owned(),
        vec![
            "libgcc_s.so.1".to_owned(),
            "libc.so.6".to_owned(),
            "ld-linux-x86-64.so.2".to_owned(),
        ],
        X64_TAIL_WORKER_DEPENDENCY_REQUIRED_FLAGS,
        X64_TAIL_WORKER_DEPENDENCY_REQUIRED_FLAGS_1,
    )
    .expect("the deployment manifest is a valid externally reviewed expectation")
}

fn hash_hex(hash: SemanticHash) -> String {
    hash.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn adr0072_admits_only_the_reviewed_dependency_declarations() {
    let admission_source = include_str!("../src/core/x64_tail_worker_dependency_admission.rs");
    let imports = admission_source
        .lines()
        .filter(|line| line.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "x64_tail_enveloped_native",
        "x64_native_process",
        "x64_standalone",
        "x64_target::raw",
        "measurement",
        "std::process",
        "std::fs",
    ] {
        assert!(
            !imports.contains(forbidden),
            "admission imports forbidden authority {forbidden}"
        );
    }

    let bytes = fs::read(worker()).expect("read reviewed worker");
    let artifact_expectation = x64_tail_worker_expectation_from_reviewed_bytes(&bytes).unwrap();
    let artifact =
        admit_x64_tail_worker_artifact(worker(), artifact_expectation).expect("seal worker");
    let inventory = emit_x64_tail_worker_elf_evidence(&artifact).expect("replay ADR-0071");
    let expectation = reviewed_dependency_expectation();

    let evidence =
        admit_x64_tail_worker_dependency_declarations(&artifact, &inventory, &expectation)
            .expect("exact reviewed dependency declarations must admit");
    let verified =
        verify_x64_tail_worker_dependency_admission(&artifact, &inventory, &expectation, &evidence)
            .expect("admission evidence must independently replay");
    assert_eq!(verified.evidence(), &evidence);
    assert_eq!(
        evidence.policy_hash(),
        x64_tail_worker_dependency_admission_policy_hash()
    );
    assert_eq!(
        evidence.policy_hash(),
        X64_TAIL_WORKER_DEPENDENCY_ADMISSION_POLICY_ROOT
    );
    assert_eq!(inventory.policy_hash(), X64_TAIL_WORKER_ELF_POLICY_ROOT);
    assert_eq!(evidence.artifact_hash(), inventory.artifact_hash());
    assert_eq!(
        evidence.inventory_evidence_hash(),
        inventory.evidence_hash()
    );
    assert_eq!(evidence.expectation_hash(), expectation.expectation_hash());
    assert_eq!(
        usize::from(evidence.dependency_count()),
        expectation.dependencies().len()
    );
    assert!(probe_x64_tail_worker_dependency_admission_mutations(
        &artifact,
        &inventory,
        &expectation,
        &evidence,
    ));

    assert_eq!(
        hash_hex(expectation.expectation_hash()),
        "b9b550ccffdfd72a6b2e67da466590235aadf4f177bdc8951653d67080495875"
    );

    let wrong_interpreter = X64TailWorkerDependencyExpectation::new(
        "/reviewed/other-loader".to_owned(),
        expectation.dependencies().to_vec(),
        expectation.dynamic_flags(),
        expectation.dynamic_flags_1(),
    )
    .unwrap();
    assert!(admit_x64_tail_worker_dependency_declarations(
        &artifact,
        &inventory,
        &wrong_interpreter
    )
    .is_err());

    let mut reordered_names = expectation.dependencies().to_vec();
    reordered_names.swap(0, 1);
    let reordered = X64TailWorkerDependencyExpectation::new(
        expectation.interpreter().to_owned(),
        reordered_names,
        expectation.dynamic_flags(),
        expectation.dynamic_flags_1(),
    )
    .unwrap();
    assert!(
        admit_x64_tail_worker_dependency_declarations(&artifact, &inventory, &reordered).is_err()
    );

    let missing = X64TailWorkerDependencyExpectation::new(
        expectation.interpreter().to_owned(),
        expectation.dependencies()[..2].to_vec(),
        expectation.dynamic_flags(),
        expectation.dynamic_flags_1(),
    )
    .unwrap();
    assert!(
        admit_x64_tail_worker_dependency_declarations(&artifact, &inventory, &missing).is_err()
    );
}

#[test]
fn adr0072_expectation_is_canonical_bounded_and_hardening_exact() {
    let exact = reviewed_dependency_expectation();
    assert_eq!(exact, reviewed_dependency_expectation());

    for interpreter in [
        "relative-loader",
        "/",
        "/lib64/../loader",
        "/lib64//loader",
        "/lib64/./loader",
        "/lib64/loader/",
    ] {
        assert!(X64TailWorkerDependencyExpectation::new(
            interpreter.to_owned(),
            exact.dependencies().to_vec(),
            exact.dynamic_flags(),
            exact.dynamic_flags_1(),
        )
        .is_err());
    }

    for dependencies in [
        Vec::<String>::new(),
        vec!["libc.so.6".to_owned(), "libc.so.6".to_owned()],
        vec!["/lib/libc.so.6".to_owned()],
        vec!["../libc.so.6".to_owned()],
        vec!["libc so.6".to_owned()],
    ] {
        assert!(X64TailWorkerDependencyExpectation::new(
            exact.interpreter().to_owned(),
            dependencies,
            exact.dynamic_flags(),
            exact.dynamic_flags_1(),
        )
        .is_err());
    }

    assert!(X64TailWorkerDependencyExpectation::new(
        exact.interpreter().to_owned(),
        exact.dependencies().to_vec(),
        0,
        exact.dynamic_flags_1(),
    )
    .is_err());
    assert!(X64TailWorkerDependencyExpectation::new(
        exact.interpreter().to_owned(),
        exact.dependencies().to_vec(),
        exact.dynamic_flags(),
        0,
    )
    .is_err());

    let mut reordered_names = exact.dependencies().to_vec();
    reordered_names.swap(0, 1);
    let reordered = X64TailWorkerDependencyExpectation::new(
        exact.interpreter().to_owned(),
        reordered_names,
        exact.dynamic_flags(),
        exact.dynamic_flags_1(),
    )
    .unwrap();
    assert_ne!(exact.expectation_hash(), reordered.expectation_hash());
}
