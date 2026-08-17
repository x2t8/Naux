use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use naux::learn::admit_learn_case_result;

const REFERENCE_MAX_BYTES: usize = 64 * 1024;
const EXAMPLE_MAX_BYTES: usize = 16 * 1024;
const EXAMPLE_TIMEOUT: Duration = Duration::from_secs(5);
const EXAMPLES: [&str; 3] = ["01-control", "02-collections", "03-recursion"];

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("naux-lang has a repository parent")
        .to_path_buf()
}

fn reference_path() -> PathBuf {
    repository_root().join("docs/s1_learn_quick_reference_v0_1.md")
}

fn example_path(id: &str, extension: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("learn/reference-v0.1/examples")
        .join(format!("{id}.{extension}"))
}

fn read_bounded(path: &Path, cap: usize) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert!(
        bytes.len() <= cap,
        "{} exceeds its {}-byte cap",
        path.display(),
        cap
    );
    let text = String::from_utf8(bytes)
        .unwrap_or_else(|_| panic!("{} must be valid UTF-8", path.display()));
    assert!(!text.contains('\0'), "{} contains NUL", path.display());
    assert!(
        !text.contains('\r') && text.ends_with('\n'),
        "{} must use canonical LF and end in LF",
        path.display()
    );
    text
}

fn run_example(source: &Path, input: &[u8], engine: Option<&str>, id: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_naux"));
    command.arg("run").arg(source);
    if let Some(engine) = engine {
        command.arg("--engine").arg(engine);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("reference example `{id}` could not spawn: {error}"));
    {
        let mut stdin = child
            .stdin
            .take()
            .unwrap_or_else(|| panic!("reference example `{id}` has no piped stdin"));
        stdin
            .write_all(input)
            .unwrap_or_else(|error| panic!("reference example `{id}` input failed: {error}"));
    }

    let deadline = Instant::now() + EXAMPLE_TIMEOUT;
    loop {
        if child
            .try_wait()
            .unwrap_or_else(|error| panic!("reference example `{id}` poll failed: {error}"))
            .is_some()
        {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait_with_output();
            panic!("reference example `{id}` exceeded the five-second cap");
        }
        thread::sleep(Duration::from_millis(2));
    }
    child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("reference example `{id}` output failed: {error}"))
}

#[test]
fn reference_is_versioned_bounded_and_fixture_synchronized() {
    let reference = read_bounded(&reference_path(), REFERENCE_MAX_BYTES);
    for required in [
        "# NAUX Learn quick reference v0.1",
        "## Run and check",
        "## Operators",
        "## Control flow",
        "## Lists and maps",
        "## Standard input and output",
        "## Diagnostics",
        "## Explicit exclusions",
    ] {
        assert!(reference.contains(required), "missing `{required}`");
    }

    for id in EXAMPLES {
        let source = read_bounded(&example_path(id, "nx"), EXAMPLE_MAX_BYTES);
        let input = read_bounded(&example_path(id, "in"), EXAMPLE_MAX_BYTES);
        let expected = read_bounded(&example_path(id, "out"), EXAMPLE_MAX_BYTES);
        assert!(
            reference.contains(&format!("```naux\n{source}```")),
            "reference source fence drifted for `{id}`"
        );
        assert!(
            reference.contains(&format!("```stdin\n{input}```")),
            "reference input fence drifted for `{id}`"
        );
        assert!(
            reference.contains(&format!("```stdout\n{expected}```")),
            "reference output fence drifted for `{id}`"
        );
    }
}

#[test]
fn all_reference_examples_match_vm_and_interpreter_cli() {
    for id in EXAMPLES {
        let source_path = example_path(id, "nx");
        let input = read_bounded(&example_path(id, "in"), EXAMPLE_MAX_BYTES);
        let expected = read_bounded(&example_path(id, "out"), EXAMPLE_MAX_BYTES);
        for engine in [None, Some("interp")] {
            let output = run_example(&source_path, input.as_bytes(), engine, id);
            admit_learn_case_result(
                id,
                output.status.success(),
                &output.stdout,
                &output.stderr,
                &expected,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "{error}\nengine={engine:?}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            });
        }
    }
}
