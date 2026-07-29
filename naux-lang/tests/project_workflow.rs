use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct TempProject {
    path: PathBuf,
}

impl TempProject {
    fn fresh() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        Self {
            path: std::env::temp_dir().join(format!(
                "naux_verify_{}_{}",
                std::process::id(),
                stamp
            )),
        }
    }
}

impl Drop for TempProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_naux(current_dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_naux"))
        .current_dir(current_dir)
        .args(args)
        .output()
        .expect("failed to run naux CLI")
}

#[test]
fn new_project_verify_runs_check_test_build_and_benchmark() {
    let project = TempProject::fresh();
    let project_arg = project.path.to_str().expect("temp path must be UTF-8");
    let created = run_naux(Path::new(env!("CARGO_MANIFEST_DIR")), &["new", project_arg]);
    assert!(
        created.status.success(),
        "new failed:\n{}",
        String::from_utf8_lossy(&created.stderr)
    );

    for relative in [
        "main.nx",
        "bench.nx",
        "tests/smoke_test.nx",
        "naux.toml",
        ".gitignore",
        "README.md",
    ] {
        assert!(
            project.path.join(relative).is_file(),
            "scaffold missing {relative}"
        );
    }
    assert!(
        !project.path.join("build").exists(),
        "build output should be created by verify, not committed in the scaffold"
    );

    let verified = run_naux(&project.path, &["verify"]);
    assert!(
        verified.status.success(),
        "verify failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&verified.stdout),
        String::from_utf8_lossy(&verified.stderr),
    );
    let stdout = String::from_utf8(verified.stdout).expect("verify output must be UTF-8");
    assert!(stdout.contains("[VERIFY 1/4] Check main.nx"));
    assert!(stdout.contains("[VERIFY 2/4] Test project"));
    assert!(stdout.contains("Summary: 1 passed, 0 failed"));
    assert!(stdout.contains("[VERIFY 3/4] Build project"));
    assert!(stdout.contains("[VERIFY 4/4] Benchmark bench.nx"));
    assert!(stdout.contains("[VERIFY] PASS"));
    assert!(project.path.join("build/main.txt").is_file());

    fs::write(
        project.path.join("tests/smoke_test.nx"),
        "~ rite\n    !log \"[FAIL] forced regression\"\n~ end\n",
    )
    .expect("write failing project test");
    let rejected = run_naux(&project.path, &["verify"]);
    assert!(
        !rejected.status.success(),
        "verify must fail when a project test emits [FAIL]"
    );
    let rejected_stdout =
        String::from_utf8(rejected.stdout).expect("failed verify output must be UTF-8");
    assert!(rejected_stdout.contains("[FAIL] tests/smoke_test.nx"));
    assert!(rejected_stdout.contains("Summary: 0 passed, 1 failed"));
    assert!(
        !rejected_stdout.contains("[VERIFY 3/4]"),
        "verify must stop before build after a failed test"
    );
}

#[test]
fn init_uses_the_same_verifiable_scaffold_and_rejects_nonempty_targets() {
    let project = TempProject::fresh();
    fs::create_dir_all(&project.path).expect("create empty init target");
    let project_arg = project.path.to_str().expect("temp path must be UTF-8");
    let initialized = run_naux(
        Path::new(env!("CARGO_MANIFEST_DIR")),
        &["init", project_arg],
    );
    assert!(
        initialized.status.success(),
        "init failed:\n{}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    let verified = run_naux(&project.path, &["verify"]);
    assert!(
        verified.status.success(),
        "initialized project verify failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&verified.stdout),
        String::from_utf8_lossy(&verified.stderr),
    );

    let repeated = run_naux(
        Path::new(env!("CARGO_MANIFEST_DIR")),
        &["init", project_arg],
    );
    assert!(
        !repeated.status.success(),
        "init must reject an existing non-empty project"
    );
    assert!(String::from_utf8_lossy(&repeated.stderr).contains("không rỗng"));
}
