#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::thesis_surface_native_process::{
    emit_surface_native_t1_process_evidence, surface_native_t1_process_report_hash,
    verify_surface_native_t1_process_evidence,
};
#[cfg(debug_assertions)]
use naux::thesis_surface_native_process::{
    probe_surface_native_t1_process_resealed_carrier_mutation,
    probe_surface_native_t1_process_resealed_receipt_mutation,
    probe_surface_native_t1_worker_debug,
};
use std::path::PathBuf;
use std::process::Command;

fn worker() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_naux-surface-native-t1-worker"))
}

#[test]
fn fixed_surface_carrier_crosses_twelve_fresh_children_deterministically() {
    let worker = worker();
    let first =
        emit_surface_native_t1_process_evidence(&worker).expect("fixed process carrier must emit");
    let second =
        emit_surface_native_t1_process_evidence(&worker).expect("second process carrier must emit");
    assert_eq!(first, second);
    verify_surface_native_t1_process_evidence(&first, &worker)
        .expect("regenerative fresh-child replay must accept");

    assert_eq!(first.receipts().len(), 12);
    assert_eq!(
        first.carrier().source_hash.to_hex(),
        "e421ce08fd53c0fe9c0d0be75d202110e96699f89918ed8f8217fdc5416e3652"
    );
    assert_eq!(
        first.carrier().results_hash.to_hex(),
        "661914e708e3a7b903e82eb9e4681e3f5646dff3baa8113efeb2c6ed50e02791"
    );
    assert_eq!(
        first.results_hash().to_hex(),
        "bd835a82c5b1d9cf8f3cd8bbed6517b40132b6d7bf7eab781435882fa661b6e7"
    );
    assert_eq!(
        first.evidence_hash().to_hex(),
        "6677a52ec741ee3cda867191a2cc5bc8f161414dbf05038c30ecc3363c8b9978"
    );
    assert_eq!(
        surface_native_t1_process_report_hash(&first).to_hex(),
        "eef6f4dc99b75fb3504310a014dc77b85e719cb06aac6f81c3f013447a494ca0"
    );
}

#[test]
fn dedicated_process_binary_emits_only_regenerated_evidence() {
    let output = Command::new(env!("CARGO_BIN_EXE_naux-surface-native-t1-process"))
        .arg(worker())
        .output()
        .expect("dedicated process carrier must start");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("process report must be UTF-8");
    assert!(stdout.starts_with("NAUX-SURFACE-NATIVE-T1-PROCESS\n"));
    assert!(stdout.lines().any(|line| line == "frame-bytes\t715"));
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.starts_with("case\t"))
            .count(),
        12
    );
    assert!(stdout.ends_with("verification\tregenerated-fresh-children\n"));

    let rejected = Command::new(env!("CARGO_BIN_EXE_naux-surface-native-t1-process"))
        .arg(worker())
        .arg("untrusted-override")
        .output()
        .expect("refusal carrier must start");
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
    assert_eq!(
        String::from_utf8(rejected.stderr).expect("usage must be UTF-8"),
        "usage: naux-surface-native-t1-process WORKER-PATH\n"
    );
}

#[test]
#[cfg(debug_assertions)]
fn abnormal_process_and_frame_matrix_fails_closed() {
    let worker = worker();
    for mode in [
        "abort",
        "abnormal",
        "timeout",
        "descendant-pipe",
        "missing",
        "malformed",
        "oversized",
        "diagnostics-limit",
        "diagnostics-one-over",
        "diagnostic-bytes-limit",
        "diagnostic-bytes-one-over",
        "record-limit",
        "trailing",
        "truncated",
        "double-frame",
        "valid-abnormal",
        "valid-abort",
        "wrong-case",
        "resealed-observation",
        "resealed-identity",
        "resealed-mapping",
    ] {
        assert!(
            probe_surface_native_t1_worker_debug(&worker, 0, mode).is_err(),
            "debug probe `{mode}` must fail closed"
        );
    }
}

#[test]
#[cfg(debug_assertions)]
fn coherent_process_and_nested_carrier_reseals_are_rejected() {
    let worker = worker();
    let evidence =
        emit_surface_native_t1_process_evidence(&worker).expect("fixed process carrier must emit");
    for mutated in [
        probe_surface_native_t1_process_resealed_receipt_mutation(&evidence),
        probe_surface_native_t1_process_resealed_carrier_mutation(&evidence),
    ] {
        assert!(verify_surface_native_t1_process_evidence(&mutated, &worker).is_err());
    }
}

#[test]
fn worker_accepts_only_one_canonical_in_range_ordinal() {
    let worker = worker();
    for arguments in [
        Vec::<&str>::new(),
        vec!["0", "1"],
        vec!["00"],
        vec!["-1"],
        vec!["12"],
        vec!["4294967296"],
    ] {
        let status = Command::new(&worker)
            .args(arguments)
            .status()
            .expect("worker must launch");
        assert!(!status.success());
    }
}
