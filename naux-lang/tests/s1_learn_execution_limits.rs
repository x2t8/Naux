use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(5);

struct SourceFile {
    path: PathBuf,
}

impl SourceFile {
    fn new(source: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let ordinal = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "naux-s1-execution-limits-{}-{ordinal}.nx",
            std::process::id()
        ));
        fs::write(&path, source).expect("write temporary NAUX source");
        Self { path }
    }
}

impl Drop for SourceFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn run_naux(source: &Path, extra_args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_naux"))
        .arg("run")
        .arg(source)
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bounded naux run");
    child
        .stdin
        .take()
        .expect("piped standard input")
        .write_all(b"")
        .expect("close empty input tape");

    let deadline = Instant::now() + PROCESS_TIMEOUT;
    loop {
        if child.try_wait().expect("poll bounded naux run").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().expect("collect killed process");
            panic!(
                "bounded execution exceeded its external carrier deadline\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(2));
    }
    child.wait_with_output().expect("collect bounded naux run")
}

fn assert_success(output: &Output, stdout: &str) {
    assert!(
        output.status.success(),
        "execution failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, stdout.as_bytes());
    assert!(output.stderr.is_empty());
}

fn assert_same_fail_closed(outputs: &[Output], message: &str) {
    let expected = &outputs[0].stderr;
    assert!(!expected.is_empty());
    for output in outputs {
        assert!(!output.status.success());
        assert!(output.stdout.is_empty(), "failure leaked partial stdout");
        assert_eq!(&output.stderr, expected, "backend diagnostic drifted");
    }
    assert!(
        String::from_utf8_lossy(expected).contains(message),
        "diagnostic did not contain `{message}`: {}",
        String::from_utf8_lossy(expected)
    );
}

#[test]
fn exact_work_boundary_succeeds_and_one_over_is_backend_independent() {
    let source = SourceFile::new("~ rite\n    $value = 7\n    !say $value\n~ end\n");
    for engine in ["vm", "interp", "jit"] {
        let output = run_naux(&source.path, &["--engine", engine, "--max-work", "2"]);
        assert_success(&output, "7\n");
    }

    let outputs = ["vm", "interp", "jit"]
        .map(|engine| run_naux(&source.path, &["--engine", engine, "--max-work", "1"]));
    assert_same_fail_closed(
        &outputs,
        "S1 work limit of 1 semantic checkpoints exceeded.",
    );
}

#[test]
fn infinite_loop_is_bounded_and_cannot_leak_buffered_output() {
    let source = SourceFile::new(
        "~ rite\n    !say \"must-not-leak\"\n    $i = 0\n    ~ while true\n        $i = $i + 1\n    ~ end\n~ end\n",
    );
    let outputs = ["vm", "interp", "jit"]
        .map(|engine| run_naux(&source.path, &["--engine", engine, "--max-work", "10"]));
    assert_same_fail_closed(
        &outputs,
        "S1 work limit of 10 semantic checkpoints exceeded.",
    );
}

#[test]
fn fixed_loop_iterations_consume_source_semantic_work_in_both_backends() {
    let source = SourceFile::new(
        "~ rite\n    $sum = 0\n    ~ loop 2\n        $sum = $sum + 1\n    ~ end\n    !say $sum\n~ end\n",
    );
    for engine in ["vm", "interp", "jit"] {
        let output = run_naux(&source.path, &["--engine", engine, "--max-work", "7"]);
        assert_success(&output, "2\n");
    }
    let outputs = ["vm", "interp", "jit"]
        .map(|engine| run_naux(&source.path, &["--engine", engine, "--max-work", "6"]));
    assert_same_fail_closed(
        &outputs,
        "S1 work limit of 6 semantic checkpoints exceeded.",
    );
}

#[test]
fn exact_call_depth_succeeds_and_one_over_fails_before_frame_creation() {
    let source = SourceFile::new(
        "~ fn descend($n)\n    ~ if $n == 0\n        ^ $n\n    ~ else\n        ^ descend($n - 1)\n    ~ end\n~ end\n\n~ rite\n    !say descend(2)\n~ end\n",
    );
    for engine in ["vm", "interp", "jit"] {
        let output = run_naux(
            &source.path,
            &[
                "--engine",
                engine,
                "--max-work",
                "100",
                "--max-call-depth",
                "3",
            ],
        );
        assert_success(&output, "0\n");
    }

    let over = SourceFile::new(
        "~ fn descend($n)\n    ~ if $n == 0\n        ^ $n\n    ~ else\n        ^ descend($n - 1)\n    ~ end\n~ end\n\n~ rite\n    !say descend(3)\n~ end\n",
    );
    let outputs = ["vm", "interp", "jit"].map(|engine| {
        run_naux(
            &over.path,
            &[
                "--engine",
                engine,
                "--max-work",
                "100",
                "--max-call-depth",
                "3",
            ],
        )
    });
    assert_same_fail_closed(&outputs, "S1 function-call depth limit of 3 exceeded.");
}

#[test]
fn cli_limit_overrides_are_positive_and_hard_bounded() {
    let source = SourceFile::new("~ rite\n    !say 1\n~ end\n");
    for (args, message) in [
        (
            vec!["--max-work", "0"],
            "--max-work must be between 1 and 10000000",
        ),
        (
            vec!["--max-work", "10000001"],
            "--max-work must be between 1 and 10000000",
        ),
        (
            vec!["--max-call-depth", "0"],
            "--max-call-depth must be between 1 and 512",
        ),
        (
            vec!["--max-call-depth", "513"],
            "--max-call-depth must be between 1 and 512",
        ),
    ] {
        let output = run_naux(&source.path, &args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains(message));
    }
}
