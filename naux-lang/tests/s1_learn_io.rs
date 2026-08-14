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
        let path =
            std::env::temp_dir().join(format!("naux-s1-io-{}-{ordinal}.nx", std::process::id()));
        fs::write(&path, source).expect("write temporary NAUX source");
        Self { path }
    }
}

impl Drop for SourceFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn run_naux(source: &Path, extra_args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_naux"))
        .arg("run")
        .arg(source)
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn naux run");
    child
        .stdin
        .take()
        .expect("piped standard input")
        .write_all(input)
        .expect("write NAUX input tape");
    child.wait_with_output().expect("collect naux run output")
}

fn assert_success(output: &Output, expected_stdout: &str) {
    assert!(
        output.status.success(),
        "naux run failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, expected_stdout.as_bytes());
    assert!(
        output.stderr.is_empty(),
        "ordinary S1 execution must not emit an engine banner: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn default_run_has_exact_batch_io_parity_between_vm_and_interpreter() {
    let source = SourceFile::new(include_str!("../examples/learn_sum.nx"));
    let input = b"4\n10 -3 5 30\n";
    let vm = run_naux(&source.path, &[], input);
    let interpreter = run_naux(&source.path, &["--engine", "interp"], input);

    assert_success(&vm, "42\n");
    assert_success(&interpreter, "42\n");
    assert_eq!(vm.stdout, interpreter.stdout);
}

#[test]
fn token_and_line_reads_share_one_unicode_and_crlf_aware_tape() {
    let source = SourceFile::new(
        "~ rite\n    $word = read_token()\n    $tail = read_line()\n    !say $word + \"::\" + $tail\n    !say read_line()\n~ end\n",
    );
    let output = run_naux(&source.path, &[], "hẹllo world\r\nlast".as_bytes());
    assert_success(&output, "hẹllo:: world\nlast\n");
}

#[test]
fn malformed_integer_input_fails_at_the_call_site_without_partial_stdout() {
    let source = SourceFile::new("~ rite\n    $value = read_int()\n    !say $value\n~ end\n");
    for engine in ["vm", "interp"] {
        let output = run_naux(&source.path, &["--engine", engine], b"not-an-int\n");
        assert!(
            !output.status.success(),
            "{engine} accepted malformed input"
        );
        assert!(output.stdout.is_empty());
        let diagnostic = String::from_utf8(output.stderr).expect("diagnostic must be UTF-8");
        assert!(diagnostic.contains("`read_int` expected an i64 token"));
        assert!(diagnostic.contains(":2:"), "{diagnostic}");
        assert!(diagnostic.contains("$value = read_int()"), "{diagnostic}");
    }
}

#[test]
fn typed_input_builtin_arity_is_rejected_before_execution() {
    let source = SourceFile::new("~ rite\n    $value = read_int(1)\n~ end\n");
    let output = run_naux(&source.path, &[], b"");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let diagnostic = String::from_utf8(output.stderr).expect("diagnostic must be UTF-8");
    assert!(diagnostic.contains("`read_int` expects 0 args, got 1"));
    assert!(diagnostic.contains(":2:14"));
    assert!(diagnostic.contains("$value = read_int(1)"));
    assert!(diagnostic.ends_with("              ^\n"));
}

#[test]
fn requested_jit_exposes_input_as_an_ordinary_vm_fallback() {
    let source = include_str!("../examples/learn_sum.nx");
    let tokens = naux::lexer::lex(source).expect("S1 example must lex");
    let ast = naux::parser::Parser::from_tokens(&tokens).expect("S1 example must parse");
    let (events, _value, used_jit) =
        naux::vm::run::run_jit_with_input(&ast, source, "examples/learn_sum.nx", "4\n10 -3 5 30\n")
            .expect("ordinary VM fallback must execute the input program");

    assert!(!used_jit, "S1 input operations have no JIT authority");
    let say_lines = events
        .iter()
        .filter_map(|event| match event {
            naux::runtime::events::RuntimeEvent::Say(line) => Some(line.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(say_lines, vec!["42"]);
}
