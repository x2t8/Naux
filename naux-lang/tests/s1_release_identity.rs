use std::fs;
use std::path::Path;
use std::process::Command;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn repository_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("naux-lang must have the workspace root as parent")
}

fn read(relative: &str) -> String {
    fs::read_to_string(repository_root().join(relative))
        .unwrap_or_else(|error| panic!("cannot read {relative}: {error}"))
}

#[test]
fn executable_bundle_seed_and_notes_share_one_release_identity() {
    for flag in ["--version", "-V"] {
        let output = Command::new(env!("CARGO_BIN_EXE_naux"))
            .arg(flag)
            .output()
            .expect("run naux version command");
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("naux {VERSION}\n")
        );
        assert!(output.stderr.is_empty());
    }

    let seed = read("distribution/s1-learn/BUILD-SEED.tsv");
    assert!(seed
        .lines()
        .any(|line| line == format!("package\tnaux@{VERSION}")));
    let notes = read("archive/releases/0.1.1/RELEASE_NOTES.linux.md");
    assert!(notes.starts_with(&format!("# NAUX Learn {VERSION}\n")));
    assert!(notes.contains("Status: experimental release"));
    assert!(notes.contains("It is not dependency closure"));

    let bundle_readme = read("distribution/s1-learn/README.md");
    let limitations = read("distribution/s1-learn/LIMITATIONS.md");
    let hello = read("distribution/s1-learn/hello.nx");
    for source in [bundle_readme, limitations, hello] {
        assert!(source.contains(VERSION));
        assert!(!source.contains("0.2.0-dev"));
    }
}

#[test]
fn release_scripts_bind_archive_version_and_verify_before_publish() {
    let producer = read("scripts/package_s1_release.sh");
    assert!(producer.contains("version=${package#naux@}"));
    assert!(producer.contains("verify_s1_release.sh"));
    assert!(producer.contains("render_s1_bootstrap.sh"));
    assert!(producer.contains("nauxup.sh"));
    assert!(producer.contains("gzip --no-name --best"));
    assert!(producer.contains("--mtime=@0"));

    let verifier = read("scripts/verify_s1_release.sh");
    assert!(verifier.contains("release binary version does not match archive identity"));
    assert!(verifier.contains("bundle verify"));
    assert!(verifier.contains("cmp -- \"$expected\" \"$actual\""));

    let renderer = read("scripts/render_s1_bootstrap.sh");
    assert!(renderer.contains("tag=\"v$version-learn\""));
    assert!(renderer.contains("archive_bytes=$(wc -c"));
    assert!(renderer.contains("bootstrap checksum file is noncanonical"));

    let bootstrap = read("distribution/s1-learn/bootstrap/nauxup.sh.in");
    assert!(bootstrap.contains("--proto '=https'"));
    assert!(bootstrap.contains("NAUX_ARCHIVE_SHA256='@@ARCHIVE_SHA256@@'"));
    assert!(bootstrap.contains("bundle verify"));
    assert!(bootstrap.contains("--same-permissions"));
    assert!(!bootstrap.contains("releases/latest"));
}

#[test]
fn windows_release_identity_is_target_exact_and_fail_closed() {
    let seed = read("distribution/s1-learn/windows/BUILD-SEED.tsv");
    assert!(seed
        .lines()
        .any(|line| line == format!("package\tnaux@{VERSION}")));
    assert!(seed.contains("rust-target\tx86_64-pc-windows-gnu"));
    assert!(seed.contains("linker-timestamp-policy\t--no-insert-timestamp"));
    assert!(seed.contains("archive-producer-flags\t-X -9"));
    assert!(seed.contains(
        "archive-producer-archive-sha256\td776e0d9da98b3d2fbec48dce7f1c59e58ff29037c5eab389115bc456cddd7c3"
    ));
    assert!(seed.contains(
        "archive-producer-executable-sha256\tca346f988e814e492a59078f66776ff2382c1360d79519fc42aab2b92ff4c4fa"
    ));
    assert!(seed.contains(
        "brand-source-sha256\t8818d089bc3a11394082080d7291fe9bafecaf698db66f17af40cc1900db1408"
    ));
    assert!(seed.contains(
        "windows-icon-source-sha256\t506815be3785def4411675ffca7bbe89d18500f23e4dcea17a33a96e67cdde00"
    ));

    let dependencies = read("distribution/s1-learn/windows/HOST-DEPENDENCIES.tsv");
    assert!(dependencies.contains("target\twindows-x86_64-gnu"));
    assert!(dependencies.contains("object-format\tPE32+"));
    assert!(!dependencies.contains("libgcc_s_seh-1.dll"));

    let producer = read("scripts/package_s1_learn_windows.sh");
    assert!(producer.contains("--no-insert-timestamp"));
    assert!(producer.contains("SOURCE_DATE_EPOCH=0"));
    assert!(producer.contains("NAUX_WINDOWS_WINDRES"));
    assert!(producer.contains("installation verify-windows-icon"));
    assert!(producer.contains("Windows PE boundary differs"));

    let archive_producer = read("scripts/package_s1_release_windows.sh");
    assert!(archive_producer.contains("-q -X -9"));
    assert!(archive_producer.contains("verify_s1_release_windows.sh"));
    assert!(archive_producer.contains("render_s1_bootstrap.sh"));
    assert!(archive_producer.contains("nauxup.ps1"));

    let bootstrap = read("distribution/s1-learn/bootstrap/nauxup.ps1.in");
    assert!(bootstrap.contains("Get-FileHash"));
    assert!(bootstrap.contains("bundle verify"));
    assert!(bootstrap.contains("NAUX_LEARN_INSTALL_LANGUAGE"));
    assert!(!bootstrap.contains("releases/latest"));

    let verifier = read("scripts/verify_s1_release_windows.sh");
    assert!(verifier.contains("pe_timestamp"));
    assert!(verifier.contains("dll_characteristics"));
    assert!(verifier.contains("actual_needed"));
    assert!(verifier.contains("installation verify-windows-icon"));
    assert!(verifier.contains("canonical deterministic ZIP encoding"));

    let runtime = read("scripts/test_s1_windows_runtime.ps1");
    assert!(runtime.contains("bundle verify"));
    assert!(runtime.contains("NAUX-Learn-Setup.exe"));
    assert!(runtime.contains("--yes --language vi-VN"));
    assert!(runtime.contains("installation uninstall"));
    assert!(runtime.contains("--dry-run"));
    assert!(runtime.contains("installed logo identity mismatch"));
    assert!(runtime.contains("SequenceEqual"));
    assert!(runtime.contains("S1 Windows pinned-bootstrap install: PASS"));
}
