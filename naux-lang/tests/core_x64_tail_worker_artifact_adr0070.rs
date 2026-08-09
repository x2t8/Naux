#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    admit_x64_tail_worker_artifact, emit_x64_tail_worker_launch_evidence,
    probe_x64_tail_worker_launch_evidence_mutations, verify_x64_tail_worker_artifact,
    verify_x64_tail_worker_launch_evidence, x64_tail_worker_artifact_policy_hash,
    x64_tail_worker_expectation_from_reviewed_bytes, SemanticHash, X64TailWorkerArtifactError,
    X64TailWorkerArtifactExpectation, X64_TAIL_ENVELOPED_PROCESS_EVIDENCE_ROOT,
    X64_TAIL_WORKER_ARTIFACT_MAX_BYTES, X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT,
    X64_TAIL_WORKER_ARTIFACT_REQUIRED_SEALS,
};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn worker() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_naux-tail-enveloped-worker"))
}

fn temporary_directory(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nonce = NEXT.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "naux-adr0070-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&directory).expect("unique ADR-0070 temporary directory");
    directory
}

fn write_file(path: &Path, bytes: &[u8], mode: u32) {
    let mut file = File::create(path).expect("create fixture");
    file.write_all(bytes).expect("write fixture");
    file.set_permissions(fs::Permissions::from_mode(mode))
        .expect("set fixture mode");
}

#[test]
fn adr0070_launches_only_the_reviewed_sealed_worker_descriptor() {
    let artifact_source = include_str!("../src/core/x64_tail_worker_artifact.rs");
    let imports = artifact_source
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
            "artifact authority imports forbidden module {forbidden}"
        );
    }

    let reviewed_bytes = fs::read(worker()).expect("read the reviewed Cargo worker artifact");
    let expectation = x64_tail_worker_expectation_from_reviewed_bytes(&reviewed_bytes)
        .expect("reviewed worker must fit the ADR-0070 bound");
    let artifact = admit_x64_tail_worker_artifact(worker(), expectation.clone())
        .expect("exact reviewed worker must become an immutable capsule");
    let verified_artifact =
        verify_x64_tail_worker_artifact(&artifact).expect("sealed capsule must replay");
    assert_eq!(verified_artifact.artifact().expectation(), &expectation);
    assert_eq!(
        verified_artifact.artifact().seals(),
        X64_TAIL_WORKER_ARTIFACT_REQUIRED_SEALS
    );

    let evidence = emit_x64_tail_worker_launch_evidence(&artifact)
        .expect("exact-FD execveat must pass the accepted ADR-0069 owner");
    let verified = verify_x64_tail_worker_launch_evidence(&evidence)
        .expect("launch evidence must replay independently");
    assert_eq!(verified.evidence(), &evidence);
    assert_eq!(evidence.expectation(), &expectation);
    assert_eq!(
        evidence.receipt().policy_hash(),
        X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT
    );
    assert_eq!(
        x64_tail_worker_artifact_policy_hash(),
        X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT
    );
    assert_eq!(
        X64_TAIL_WORKER_ARTIFACT_POLICY_ROOT.to_hex(),
        "967282494499035aa13fe3daaf05d61825fb7ab9027052c6dec51f3420a5317d"
    );
    assert_eq!(
        evidence.receipt().process_root(),
        X64_TAIL_ENVELOPED_PROCESS_EVIDENCE_ROOT
    );
    assert_eq!(
        evidence.process().evidence_hash(),
        X64_TAIL_ENVELOPED_PROCESS_EVIDENCE_ROOT
    );
    assert!(probe_x64_tail_worker_launch_evidence_mutations(&evidence));
}

#[test]
fn adr0070_admission_and_path_replacement_fail_closed() {
    let directory = temporary_directory("admission");
    let source = directory.join("worker");
    let reviewed = b"reviewed-worker-fixture";
    write_file(&source, reviewed, 0o755);
    let expectation = x64_tail_worker_expectation_from_reviewed_bytes(reviewed).unwrap();

    let artifact = admit_x64_tail_worker_artifact(&source, expectation.clone())
        .expect("reviewed fixture must seal");
    write_file(&source, b"path-now-names-different-bytes", 0o755);
    verify_x64_tail_worker_artifact(&artifact)
        .expect("source replacement cannot alter the sealed descriptor");
    fs::remove_file(&source).expect("remove replaced source");
    verify_x64_tail_worker_artifact(&artifact)
        .expect("source deletion cannot alter the sealed descriptor");

    let original = directory.join("original");
    let link = directory.join("link");
    write_file(&original, reviewed, 0o755);
    symlink(&original, &link).expect("create final symlink fixture");
    assert!(matches!(
        admit_x64_tail_worker_artifact(&link, expectation.clone()),
        Err(X64TailWorkerArtifactError::SourceSymlink)
    ));

    let mut wrong_hash = expectation.artifact_hash();
    wrong_hash.0[0] ^= 1;
    let wrong_hash_expectation =
        X64TailWorkerArtifactExpectation::new(expectation.byte_len(), wrong_hash).unwrap();
    assert!(matches!(
        admit_x64_tail_worker_artifact(&original, wrong_hash_expectation),
        Err(X64TailWorkerArtifactError::ArtifactHashMismatch)
    ));

    let wrong_length = X64TailWorkerArtifactExpectation::new(
        expectation.byte_len() + 1,
        expectation.artifact_hash(),
    )
    .unwrap();
    assert!(matches!(
        admit_x64_tail_worker_artifact(&original, wrong_length),
        Err(X64TailWorkerArtifactError::LengthMismatch { .. })
    ));

    let set_id = directory.join("set-id");
    write_file(&set_id, reviewed, 0o4755);
    assert!(matches!(
        admit_x64_tail_worker_artifact(&set_id, expectation.clone()),
        Err(X64TailWorkerArtifactError::SourceSetId)
    ));
    assert!(matches!(
        admit_x64_tail_worker_artifact(&directory, expectation),
        Err(X64TailWorkerArtifactError::SourceNotRegular)
    ));
    assert!(matches!(
        x64_tail_worker_expectation_from_reviewed_bytes(&[]),
        Err(X64TailWorkerArtifactError::ByteLimit { actual: 0 })
    ));
    assert!(matches!(
        X64TailWorkerArtifactExpectation::new(
            X64_TAIL_WORKER_ARTIFACT_MAX_BYTES + 1,
            SemanticHash::ZERO,
        ),
        Err(X64TailWorkerArtifactError::ByteLimit { .. })
    ));

    let non_executable = directory.join("non-executable");
    write_file(&non_executable, b"not-elf", 0o644);
    let non_executable_expectation =
        x64_tail_worker_expectation_from_reviewed_bytes(b"not-elf").unwrap();
    let non_executable_artifact =
        admit_x64_tail_worker_artifact(&non_executable, non_executable_expectation).unwrap();
    assert!(matches!(
        emit_x64_tail_worker_launch_evidence(&non_executable_artifact),
        Err(X64TailWorkerArtifactError::Process(_))
    ));

    fs::remove_dir_all(directory).expect("remove ADR-0070 temporary fixtures");
}
