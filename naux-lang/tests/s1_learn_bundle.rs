#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use naux::install_lifecycle::{
    execute_uninstall, install_with_receipt, plan_uninstall, read_installation_receipt,
};
use naux::learn_bundle::{install_learn_bundle, verify_learn_bundle};

const FILES: &[(&str, u32)] = &[
    ("BUILD-SEED.tsv", 0o644),
    ("HOST-DEPENDENCIES.tsv", 0o644),
    ("LICENSE", 0o644),
    ("README.md", 0o644),
    ("naux-learn-setup", 0o755),
    ("assets/langnaux-learn.png", 0o644),
    ("bin/naux", 0o755),
    ("docs/LIMITATIONS.md", 0o644),
    ("docs/RELEASE_DISCLOSURE.md", 0o644),
    ("docs/s1_learn_batch_io.md", 0o644),
    ("docs/s1_learn_diagnostics.md", 0o644),
    ("docs/s1_learn_execution_envelope.md", 0o644),
    ("docs/s1_learn_quick_reference_v0_1.md", 0o644),
    ("examples/hello.nx", 0o644),
    ("examples/hello.out", 0o644),
    ("locales/SUPPORTED_LOCALES.tsv", 0o644),
    ("locales/de.tsv", 0o644),
    ("locales/en-US.tsv", 0o644),
    ("locales/es.tsv", 0o644),
    ("locales/fr.tsv", 0o644),
    ("locales/ja-JP.tsv", 0o644),
    ("locales/ko-KR.tsv", 0o644),
    ("locales/pt-BR.tsv", 0o644),
    ("locales/vi-VN.tsv", 0o644),
    ("locales/zh-CN.tsv", 0o644),
];

const WINDOWS_FILES: &[(&str, u32)] = &[
    ("BUILD-SEED.tsv", 0o644),
    ("HOST-DEPENDENCIES.tsv", 0o644),
    ("LICENSE", 0o644),
    ("README.md", 0o644),
    ("NAUX-Learn-Setup.exe", 0o755),
    ("assets/langnaux-learn.ico", 0o644),
    ("assets/langnaux-learn.png", 0o644),
    ("bin/naux.exe", 0o755),
    ("docs/LIMITATIONS.md", 0o644),
    ("docs/RELEASE_DISCLOSURE.md", 0o644),
    ("docs/s1_learn_batch_io.md", 0o644),
    ("docs/s1_learn_diagnostics.md", 0o644),
    ("docs/s1_learn_execution_envelope.md", 0o644),
    ("docs/s1_learn_quick_reference_v0_1.md", 0o644),
    ("examples/hello.nx", 0o644),
    ("examples/hello.out", 0o644),
    ("locales/SUPPORTED_LOCALES.tsv", 0o644),
    ("locales/de.tsv", 0o644),
    ("locales/en-US.tsv", 0o644),
    ("locales/es.tsv", 0o644),
    ("locales/fr.tsv", 0o644),
    ("locales/ja-JP.tsv", 0o644),
    ("locales/ko-KR.tsv", 0o644),
    ("locales/pt-BR.tsv", 0o644),
    ("locales/vi-VN.tsv", 0o644),
    ("locales/zh-CN.tsv", 0o644),
];

const SEAL_DOMAIN: &[u8] = b"NAUX:s1-learn-bundle:manifest:v1\0";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(label: &str) -> Self {
        let ordinal = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "naux-s1-bundle-{label}-{}-{ordinal}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create unique temp root");
        Self { root }
    }

    fn bundle(&self) -> PathBuf {
        self.root.join("bundle")
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn make_bundle(label: &str) -> TempTree {
    make_target_bundle(label, "linux-x86_64-gnu", FILES)
}

fn make_target_bundle(label: &str, target: &str, files: &[(&str, u32)]) -> TempTree {
    let temp = TempTree::new(label);
    let root = temp.bundle();
    fs::create_dir(&root).unwrap();
    for directory in ["assets", "bin", "docs", "examples", "locales"] {
        fs::create_dir(root.join(directory)).unwrap();
    }
    for (relative, mode) in files {
        let path = root.join(relative);
        if relative.starts_with("bin/naux") {
            fs::copy("/bin/true", &path).unwrap();
        } else if relative.starts_with("locales/") {
            fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join(relative), &path).unwrap();
        } else {
            fs::write(&path, format!("fixture:{relative}\n")).unwrap();
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(*mode)).unwrap();
    }
    write_target_manifest(&root, target, &canonical_rows_for(&root, files));
    temp
}

fn canonical_rows(root: &Path) -> Vec<String> {
    canonical_rows_for(root, FILES)
}

fn canonical_rows_for(root: &Path, files: &[(&str, u32)]) -> Vec<String> {
    files
        .iter()
        .map(|(relative, mode)| {
            let path = root.join(relative);
            let size = fs::metadata(&path).unwrap().len();
            let digest = sha256_file(&path);
            format!("file\t{mode:04o}\t{size}\t{digest}\t{relative}")
        })
        .collect()
}

fn write_manifest(root: &Path, rows: &[String]) {
    write_target_manifest(root, "linux-x86_64-gnu", rows);
}

fn write_target_manifest(root: &Path, target: &str, rows: &[String]) {
    let mut body = format!(
        "NAUX-S1-LEARN-BUNDLE\t1\nbundle\t{}\ntarget\t{target}\n",
        env!("CARGO_PKG_VERSION")
    );
    for row in rows {
        body.push_str(row);
        body.push('\n');
    }
    let mut preimage = SEAL_DOMAIN.to_vec();
    preimage.extend_from_slice(body.as_bytes());
    let seal = sha256_bytes(&preimage);
    fs::write(root.join("MANIFEST.tsv"), format!("{body}seal\t{seal}\n")).unwrap();
    fs::set_permissions(root.join("MANIFEST.tsv"), fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn verifies_windows_transport_but_refuses_cross_target_installation() {
    let temp = make_target_bundle("windows-transport", "windows-x86_64-gnu", WINDOWS_FILES);
    let bundle = temp.bundle();
    let verified = verify_learn_bundle(&bundle).unwrap();
    assert_eq!(verified.target(), "windows-x86_64-gnu");
    assert_eq!(verified.file_count(), 27);

    let error = install_learn_bundle(&bundle, &temp.root.join("installed"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("cannot be installed on host `linux-x86_64-gnu`"));
}

fn sha256_file(path: &Path) -> String {
    let output = Command::new("sha256sum")
        .arg("--")
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

#[test]
fn verifies_and_installs_exact_inventory_into_a_new_prefix() {
    let temp = make_bundle("install");
    let bundle = temp.bundle();
    let verified = verify_learn_bundle(&bundle).unwrap();
    assert_eq!(verified.file_count(), 26);
    assert_eq!(verified.manifest_seal_hex().len(), 64);

    let prefix = temp.root.join("installed");
    let installed = install_learn_bundle(&bundle, &prefix).unwrap();
    assert_eq!(installed.prefix(), prefix);
    assert_eq!(installed.manifest_seal_hex(), verified.manifest_seal_hex());
    assert_eq!(
        verify_learn_bundle(&prefix).unwrap().manifest_seal_hex(),
        verified.manifest_seal_hex()
    );
    assert!(install_learn_bundle(&bundle, &prefix)
        .unwrap_err()
        .to_string()
        .contains("already exists"));
}

#[test]
fn rejects_missing_extra_and_substituted_members() {
    let missing = make_bundle("missing");
    fs::remove_file(missing.bundle().join("LICENSE")).unwrap();
    assert!(verify_learn_bundle(&missing.bundle()).is_err());

    let extra = make_bundle("extra");
    fs::write(extra.bundle().join("UNSEALED"), b"extra").unwrap();
    assert!(verify_learn_bundle(&extra.bundle()).is_err());

    let substituted = make_bundle("substituted");
    let readme = substituted.bundle().join("README.md");
    let mut bytes = fs::read(&readme).unwrap();
    bytes[0] ^= 1;
    fs::write(readme, bytes).unwrap();
    let error = verify_learn_bundle(&substituted.bundle()).unwrap_err();
    assert!(error.to_string().contains("SHA-256 mismatch"));

    let translated = make_bundle("resealed-translated-catalog");
    let catalog = translated.bundle().join("locales/fr.tsv");
    let mut text = fs::read_to_string(&catalog).unwrap();
    text = text.replace("Installer NAUX Learn", "Installer autre chose");
    fs::write(&catalog, text).unwrap();
    write_manifest(&translated.bundle(), &canonical_rows(&translated.bundle()));
    assert!(verify_learn_bundle(&translated.bundle())
        .unwrap_err()
        .to_string()
        .contains("differs from the executable catalog"));
}

#[test]
fn rejects_resealed_duplicate_and_traversing_manifest_rows() {
    let duplicate = make_bundle("duplicate");
    let mut rows = canonical_rows(&duplicate.bundle());
    rows.insert(1, rows[0].clone());
    write_manifest(&duplicate.bundle(), &rows);
    assert!(verify_learn_bundle(&duplicate.bundle())
        .unwrap_err()
        .to_string()
        .contains("duplicates"));

    let traversal = make_bundle("traversal");
    let mut rows = canonical_rows(&traversal.bundle());
    rows[0] = rows[0].replace("BUILD-SEED.tsv", "../BUILD-SEED.tsv");
    write_manifest(&traversal.bundle(), &rows);
    assert!(verify_learn_bundle(&traversal.bundle())
        .unwrap_err()
        .to_string()
        .contains("unsafe path"));
}

#[test]
fn rejects_symlink_oversize_and_mode_drift() {
    let symlinked = make_bundle("symlink");
    let output = symlinked.bundle().join("examples/hello.out");
    fs::remove_file(&output).unwrap();
    symlink("hello.nx", &output).unwrap();
    assert!(verify_learn_bundle(&symlinked.bundle())
        .unwrap_err()
        .to_string()
        .contains("symlink"));

    let oversized = make_bundle("oversized");
    fs::write(
        oversized.bundle().join("BUILD-SEED.tsv"),
        vec![b'x'; 16 * 1024 + 1],
    )
    .unwrap();
    write_manifest(&oversized.bundle(), &canonical_rows(&oversized.bundle()));
    assert!(verify_learn_bundle(&oversized.bundle())
        .unwrap_err()
        .to_string()
        .contains("byte cap"));

    let mode = make_bundle("mode");
    fs::set_permissions(
        mode.bundle().join("README.md"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(verify_learn_bundle(&mode.bundle())
        .unwrap_err()
        .to_string()
        .contains("mode is 0600"));
}

#[test]
fn lifecycle_receipt_binds_locale_prefix_and_exact_owned_paths() {
    let temp = make_bundle("lifecycle-plan");
    let state = temp.root.join("state");
    fs::create_dir(&state).unwrap();
    let prefix = temp.root.join("installed lifecycle");
    let receipt = install_with_receipt(&temp.bundle(), &prefix, &state, "vi-VN").unwrap();

    assert_eq!(receipt.locale(), "vi-VN");
    assert_eq!(receipt.prefix(), prefix);
    assert_eq!(receipt.file_count(), 26);
    assert_eq!(receipt.installation_id().len(), 64);
    assert_eq!(
        read_installation_receipt(receipt.receipt_path()).unwrap(),
        receipt
    );

    let plan = plan_uninstall(receipt.receipt_path()).unwrap();
    assert_eq!(plan.files().len(), 26);
    assert_eq!(plan.directories().len(), 6);
    assert!(plan.files().iter().all(|path| path.starts_with(&prefix)));
    assert!(
        prefix.exists(),
        "dry-run planning must not mutate the install"
    );
    assert!(receipt.receipt_path().exists());
}

#[test]
fn lifecycle_refuses_changed_payload_and_corrupted_or_linked_receipt() {
    let changed = make_bundle("lifecycle-changed");
    let state = changed.root.join("state");
    fs::create_dir(&state).unwrap();
    let receipt = install_with_receipt(
        &changed.bundle(),
        &changed.root.join("installed"),
        &state,
        "en-US",
    )
    .unwrap();
    fs::write(receipt.prefix().join("examples/hello.out"), b"changed\n").unwrap();
    assert!(plan_uninstall(receipt.receipt_path())
        .unwrap_err()
        .to_string()
        .contains("not intact"));

    let corrupted = make_bundle("lifecycle-corrupt-receipt");
    let state = corrupted.root.join("state");
    fs::create_dir(&state).unwrap();
    let receipt = install_with_receipt(
        &corrupted.bundle(),
        &corrupted.root.join("installed"),
        &state,
        "fr",
    )
    .unwrap();
    let mut bytes = fs::read(receipt.receipt_path()).unwrap();
    bytes[0] ^= 1;
    fs::write(receipt.receipt_path(), bytes).unwrap();
    assert!(read_installation_receipt(receipt.receipt_path())
        .unwrap_err()
        .to_string()
        .contains("seal mismatch"));

    let linked = make_bundle("lifecycle-linked-receipt");
    let state = linked.root.join("state");
    fs::create_dir(&state).unwrap();
    let receipt = install_with_receipt(
        &linked.bundle(),
        &linked.root.join("installed"),
        &state,
        "de",
    )
    .unwrap();
    let target = state.join("receipt-copy");
    fs::rename(receipt.receipt_path(), &target).unwrap();
    symlink(&target, receipt.receipt_path()).unwrap();
    assert!(read_installation_receipt(receipt.receipt_path())
        .unwrap_err()
        .to_string()
        .contains("regular non-symlink"));
}

#[test]
fn lifecycle_uninstall_removes_only_verified_install_and_its_receipt() {
    let temp = make_bundle("lifecycle-uninstall");
    let state = temp.root.join("state");
    fs::create_dir(&state).unwrap();
    let user_project = temp.root.join("my-homework.nx");
    fs::write(&user_project, b"~ rite\n    !say 42\n").unwrap();
    let prefix = temp.root.join("installed");
    let receipt = install_with_receipt(&temp.bundle(), &prefix, &state, "es").unwrap();
    let receipt_path = receipt.receipt_path().to_path_buf();

    let removed = execute_uninstall(&receipt_path).unwrap();
    assert_eq!(
        removed.receipt().installation_id(),
        receipt.installation_id()
    );
    assert!(!prefix.exists());
    assert!(!receipt_path.exists());
    assert!(state.is_dir());
    assert!(user_project.is_file());
}

#[test]
fn lifecycle_receipt_collision_rolls_back_new_exact_payload() {
    let temp = make_bundle("lifecycle-collision");
    let state = temp.root.join("state");
    fs::create_dir(&state).unwrap();
    let prefix = temp.root.join("installed");
    let first = install_with_receipt(&temp.bundle(), &prefix, &state, "pt-BR").unwrap();
    fs::remove_dir_all(&prefix).unwrap();

    let error = install_with_receipt(&temp.bundle(), &prefix, &state, "pt-BR")
        .unwrap_err()
        .to_string();
    assert!(error.contains("already exists"));
    assert!(
        !prefix.exists(),
        "failed ledger publication must roll back payload"
    );
    assert!(first.receipt_path().is_file());
}
