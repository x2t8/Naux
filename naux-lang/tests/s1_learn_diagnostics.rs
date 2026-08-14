use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

struct SourceFile {
    path: PathBuf,
}

impl SourceFile {
    fn new(source: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let ordinal = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "naux-s1-diagnostic-{}-{ordinal}.nx",
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

fn invoke_naux(command: &str, source: &Path, extra_args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_naux"))
        .arg(command)
        .arg(source)
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn NAUX command");
    child
        .stdin
        .take()
        .expect("piped standard input")
        .write_all(input)
        .expect("write NAUX input");
    child.wait_with_output().expect("collect NAUX output")
}

fn expected_diagnostic(
    stage: &str,
    message: &str,
    source: &Path,
    line: usize,
    column: usize,
    snippet: &str,
) -> String {
    let gutter_width = line.to_string().len();
    format!(
        "error: {stage} error: {message}\n --> {}:{line}:{column}\n{empty:>gutter_width$} |\n{line:>gutter_width$} | {snippet}\n{empty:>gutter_width$} | {padding}^\n",
        source.display(),
        empty = "",
        padding = " ".repeat(column.saturating_sub(1)),
    )
}

fn assert_exact_failure(output: &Output, expected_stderr: &str) {
    assert!(!output.status.success(), "command unexpectedly succeeded");
    assert_eq!(output.stdout, b"", "failure must not leak partial stdout");
    assert_eq!(
        String::from_utf8(output.stderr.clone()).expect("diagnostic must be UTF-8"),
        expected_stderr
    );
}

fn assert_run_and_check_match(source: &SourceFile, expected: &str) {
    let run = invoke_naux("run", &source.path, &[], b"");
    let check = invoke_naux("check", &source.path, &[], b"");
    assert_exact_failure(&run, expected);
    assert_exact_failure(&check, expected);
}

#[test]
fn lex_failure_is_exact_and_identical_for_run_and_check() {
    let source = SourceFile::new("~ rite\n    @\n~ end\n");
    let expected = expected_diagnostic(
        "Lex",
        "Unexpected character '@'",
        &source.path,
        2,
        5,
        "    @",
    );
    assert_run_and_check_match(&source, &expected);
}

#[test]
fn parse_failure_is_exact_and_identical_for_run_and_check() {
    let source = SourceFile::new("~ rite\n    $value =\n~ end\n");
    let expected = expected_diagnostic(
        "Parse",
        "Expected expression",
        &source.path,
        2,
        13,
        "    $value =",
    );
    assert_run_and_check_match(&source, &expected);
}

#[test]
fn type_failure_is_exact_and_identical_for_run_and_check() {
    let source = SourceFile::new("~ rite\n    $value = read_int(1)\n~ end\n");
    let expected = expected_diagnostic(
        "Type",
        "`read_int` expects 0 args, got 1",
        &source.path,
        2,
        14,
        "    $value = read_int(1)",
    );
    assert_run_and_check_match(&source, &expected);
}

#[test]
fn runtime_failure_is_exact_and_backend_independent() {
    let source = SourceFile::new("~ rite\n    $value = read_int()\n    !say $value\n~ end\n");
    let expected = expected_diagnostic(
        "Runtime",
        "`read_int` expected an i64 token, found `nope`",
        &source.path,
        2,
        22,
        "    $value = read_int()",
    );
    for engine in ["vm", "interp"] {
        let output = invoke_naux("run", &source.path, &["--engine", engine], b"nope\n");
        assert_exact_failure(&output, &expected);
    }
}
