#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    decode_x64_tail_enveloped_ipc, emit_x64_tail_enveloped_process_evidence,
    encode_x64_tail_enveloped_ipc, probe_x64_tail_enveloped_worker,
    verify_x64_tail_enveloped_process_evidence, X64TailEnvelopedProcessError,
    X64_TAIL_ENVELOPED_CORRESPONDENCE_ACCEPTED_ROOT, X64_TAIL_ENVELOPED_PROCESS_CHILDREN,
    X64_TAIL_ENVELOPED_PROCESS_EVIDENCE_ROOT,
};
use std::path::Path;
use std::time::{Duration, Instant};

fn worker() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_naux-tail-enveloped-worker"))
}

#[test]
fn adr0069_contains_the_exact_sovereign_corpus_in_one_child() {
    let parent_source = include_str!("../src/core/x64_tail_enveloped_process.rs");
    let imports = parent_source
        .lines()
        .filter(|line| line.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "x64_tail_enveloped_native",
        "emit_x64_tail_enveloped_correspondence",
        "x64_native_process",
        "x64_standalone",
        "x64_target::raw",
        "measurement",
    ] {
        assert!(
            !imports.contains(forbidden),
            "parent authority imports forbidden module {forbidden}"
        );
    }

    let evidence = emit_x64_tail_enveloped_process_evidence(worker())
        .expect("one sovereign child must emit accepted evidence");
    let verified = verify_x64_tail_enveloped_process_evidence(&evidence)
        .expect("process evidence must replay without parent native execution");
    assert_eq!(verified.evidence(), &evidence);
    assert_eq!(
        evidence.receipt().children(),
        X64_TAIL_ENVELOPED_PROCESS_CHILDREN
    );
    assert_eq!(
        evidence.correspondence().evidence_hash(),
        X64_TAIL_ENVELOPED_CORRESPONDENCE_ACCEPTED_ROOT
    );
    assert_eq!(evidence.correspondence().records().len(), 51);
    assert_eq!(
        evidence.evidence_hash(),
        X64_TAIL_ENVELOPED_PROCESS_EVIDENCE_ROOT
    );
    assert_eq!(
        evidence.receipt().ipc_frame_hash().to_hex(),
        "0bb2cbe0ebc7e425e538a6c6317815050c274bf7584386c1678407d9fc618044"
    );

    let frame = encode_x64_tail_enveloped_ipc(evidence.correspondence())
        .expect("accepted observation must encode");
    assert_eq!(
        decode_x64_tail_enveloped_ipc(&frame).expect("canonical frame must decode"),
        *evidence.correspondence()
    );
    for index in 0..frame.len() {
        let mut mutated = frame.clone();
        mutated[index] ^= 1;
        assert!(
            decode_x64_tail_enveloped_ipc(&mutated).is_err(),
            "single-byte mutation {index} must fail"
        );
    }
    let mut truncated = frame.clone();
    truncated.pop();
    assert!(decode_x64_tail_enveloped_ipc(&truncated).is_err());
    let mut trailing = frame;
    trailing.push(0);
    assert!(decode_x64_tail_enveloped_ipc(&trailing).is_err());
}

#[test]
fn adr0069_worker_failures_are_bounded_and_fail_closed() {
    assert!(matches!(
        probe_x64_tail_enveloped_worker(worker(), "missing", Duration::from_secs(2)),
        Err(X64TailEnvelopedProcessError::MissingFrame)
    ));
    assert!(matches!(
        probe_x64_tail_enveloped_worker(worker(), "malformed", Duration::from_secs(2)),
        Err(X64TailEnvelopedProcessError::Ipc(_))
    ));
    assert!(matches!(
        probe_x64_tail_enveloped_worker(worker(), "oversized", Duration::from_secs(2)),
        Err(X64TailEnvelopedProcessError::FrameByteLimit { .. })
    ));
    assert!(matches!(
        probe_x64_tail_enveloped_worker(worker(), "diagnostic", Duration::from_secs(2)),
        Err(X64TailEnvelopedProcessError::UnexpectedDiagnostics { .. })
    ));
    assert!(matches!(
        probe_x64_tail_enveloped_worker(worker(), "abnormal", Duration::from_secs(2)),
        Err(X64TailEnvelopedProcessError::AbnormalExit { .. })
    ));
    assert!(matches!(
        probe_x64_tail_enveloped_worker(worker(), "abort", Duration::from_secs(2)),
        Err(X64TailEnvelopedProcessError::NativeFault)
    ));

    let started = Instant::now();
    assert!(matches!(
        probe_x64_tail_enveloped_worker(worker(), "timeout", Duration::from_millis(50)),
        Err(X64TailEnvelopedProcessError::Timeout { .. })
    ));
    assert!(started.elapsed() < Duration::from_secs(2));

    let started = Instant::now();
    assert!(matches!(
        probe_x64_tail_enveloped_worker(worker(), "descendant-pipe", Duration::from_secs(2),),
        Err(X64TailEnvelopedProcessError::MissingFrame)
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
}
