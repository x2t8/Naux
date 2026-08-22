#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::elaboration::NormalizedScalar;
#[cfg(debug_assertions)]
use naux::thesis_surface_native::probe_surface_native_t1_resealed_observation_mutation;
use naux::thesis_surface_native::{
    canonical_surface_native_t1_cases, emit_surface_native_t1, render_surface_native_t1_report,
    surface_native_t1_report_hash, verify_surface_native_t1, SurfaceNativeT1Error,
    SURFACE_NATIVE_T1_CASES,
};
use std::process::Command;

#[test]
fn fixed_surface_program_reaches_verified_native_without_fallback() {
    let cases = canonical_surface_native_t1_cases();
    assert_eq!(cases.len(), SURFACE_NATIVE_T1_CASES);
    assert_eq!(
        cases.iter().map(|case| case.ordinal).collect::<Vec<_>>(),
        (0..SURFACE_NATIVE_T1_CASES as u32).collect::<Vec<_>>()
    );

    let evidence = emit_surface_native_t1().expect("fixed T1 carrier must execute");
    let locked_roots = [
        (
            evidence.source_hash,
            "e421ce08fd53c0fe9c0d0be75d202110e96699f89918ed8f8217fdc5416e3652",
        ),
        (
            evidence.request_hash,
            "6738f1f7f820ba57a311de4b6e85a4c497f06bd1de91fd46a651c092710e62d4",
        ),
        (
            evidence.corpus_hash,
            "150029f8e9c0ae58c7b70fbaa7881fadecd315608f7e36d91d5158678dd73a46",
        ),
        (
            evidence.core_hash,
            "d31b07ed7f9ed0bf038bad8cb368f1f53b48ce6adab7d56e18601f68da8c8ac1",
        ),
        (
            evidence.ssa_hash,
            "fbbfc3f60ffe6e936b81f2a535d8d43c5bf4318793d9b51803041745f79eb825",
        ),
        (
            evidence.machine_ir_hash,
            "93d9c76e64a6f068fde1fb6574888300204b870083d31e1bebdbbbaade56e57e",
        ),
        (
            evidence.target_hash,
            "573ca6f8d1f5190dbbd6d2fe15abff4ba4ab1fa58c24ca5e10fddc6bf51178ee",
        ),
        (
            evidence.target_plan_hash,
            "b50221274d30505f758a50d546892b2e3cb81b44c60482766cd72cea8e0a3e56",
        ),
        (
            evidence.target_code_hash,
            "bea1358d78cda633a106589cd7cc54e25be7209632785be052a62b58c14d46cd",
        ),
        (
            evidence.results_hash,
            "661914e708e3a7b903e82eb9e4681e3f5646dff3baa8113efeb2c6ed50e02791",
        ),
        (
            evidence.evidence_hash,
            "157c8947fd432951ec5cdefca3879992726d4e0b9ade98937ec4f8f66c11efc2",
        ),
    ];
    for (actual, expected) in locked_roots {
        assert_eq!(actual.to_hex(), expected);
    }
    assert_eq!(evidence.records.len(), SURFACE_NATIVE_T1_CASES);
    assert!(evidence.records.iter().all(|record| {
        record.surface == record.core
            && record.surface == record.ssa
            && record.surface == record.machine_ir
            && record.surface == record.target_plan
            && record.surface == record.native
    }));
    assert_eq!(
        evidence.records[6].native,
        NormalizedScalar::F64Bits(f64::INFINITY.to_bits())
    );
    assert_eq!(
        evidence.records[9].native,
        NormalizedScalar::F64Bits(0x7ff8_0000_0000_0000)
    );
    assert_eq!(
        evidence.records[10].native,
        NormalizedScalar::F64Bits(0x7ff8_0000_0000_0000)
    );
    verify_surface_native_t1(&evidence).expect("exact evidence must replay");

    let replay = emit_surface_native_t1().expect("replay must execute");
    assert_eq!(evidence, replay);

    let report = render_surface_native_t1_report(&evidence);
    assert_eq!(
        report
            .lines()
            .filter(|line| line.starts_with("case\t"))
            .count(),
        12
    );
    assert!(report.ends_with("records\t12\n"));
    assert_eq!(
        surface_native_t1_report_hash(&evidence).to_hex(),
        "5a770f0a8034656652bf8b978f54207761cc1231711e656f5037e0a6b096815e"
    );
    assert_eq!(
        surface_native_t1_report_hash(&evidence),
        surface_native_t1_report_hash(&replay)
    );
}

#[test]
fn dedicated_carrier_binary_emits_only_verified_deterministic_evidence() {
    let output = Command::new(env!("CARGO_BIN_EXE_naux-surface-native-t1"))
        .output()
        .expect("dedicated T1 binary must start");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("T1 report must be UTF-8");
    assert!(stdout.starts_with("NAUX-SURFACE-NATIVE-T1\n"));
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.starts_with("case\t"))
            .count(),
        12
    );
    assert!(stdout.ends_with("verification\tregenerated\n"));

    let rejected = Command::new(env!("CARGO_BIN_EXE_naux-surface-native-t1"))
        .arg("untrusted-override")
        .output()
        .expect("T1 refusal carrier must start");
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
    assert_eq!(
        String::from_utf8(rejected.stderr).expect("usage must be UTF-8"),
        "usage: naux-surface-native-t1\n"
    );
}

#[test]
#[cfg(debug_assertions)]
fn evidence_mutations_fail_closed_even_when_resealed_fields_are_changed() {
    let evidence = emit_surface_native_t1().expect("fixed T1 carrier must execute");

    let mut source_mutation = evidence.clone();
    source_mutation.source_hash.0[0] ^= 1;
    assert_eq!(
        verify_surface_native_t1(&source_mutation),
        Err(SurfaceNativeT1Error::EvidenceMismatch)
    );

    let mut schema_mutation = evidence.clone();
    schema_mutation.schema_version.1 = schema_mutation.schema_version.1.wrapping_add(1);
    assert_eq!(
        verify_surface_native_t1(&schema_mutation),
        Err(SurfaceNativeT1Error::EvidenceMismatch)
    );

    let observation_mutation = probe_surface_native_t1_resealed_observation_mutation(&evidence);
    assert_eq!(
        verify_surface_native_t1(&observation_mutation),
        Err(SurfaceNativeT1Error::EvidenceMismatch)
    );

    let mut order_mutation = evidence.clone();
    order_mutation.records.swap(0, 1);
    assert_eq!(
        verify_surface_native_t1(&order_mutation),
        Err(SurfaceNativeT1Error::EvidenceMismatch)
    );

    let mut cardinality_mutation = evidence.clone();
    cardinality_mutation.records.pop();
    assert_eq!(
        verify_surface_native_t1(&cardinality_mutation),
        Err(SurfaceNativeT1Error::EvidenceMismatch)
    );
}
