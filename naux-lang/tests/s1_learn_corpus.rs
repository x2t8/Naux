use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use naux::learn::{
    admit_learn_case_result, load_learn_corpus_v1, LearnImplementation, LearnTopic,
    S1_LEARN_CORPUS_CASE_COUNT, S1_LEARN_CORPUS_MIN_SOURCE_ALGORITHMS, S1_LEARN_CORPUS_VERSION,
};

const CASE_TIMEOUT: Duration = Duration::from_secs(5);

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("learn/corpus-v1/manifest.tsv")
}

fn run_case(source: &std::path::Path, input: &[u8], id: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_naux"))
        .arg("run")
        .arg(source)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("learn case `{id}` could not spawn `naux run`: {error}"));
    {
        let mut stdin = child
            .stdin
            .take()
            .unwrap_or_else(|| panic!("learn case `{id}` has no piped stdin"));
        stdin
            .write_all(input)
            .unwrap_or_else(|error| panic!("learn case `{id}` input write failed: {error}"));
    }

    let deadline = Instant::now() + CASE_TIMEOUT;
    loop {
        if child
            .try_wait()
            .unwrap_or_else(|error| panic!("learn case `{id}` status poll failed: {error}"))
            .is_some()
        {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait_with_output();
            panic!(
                "learn case `{id}` exceeded the {} ms execution cap",
                CASE_TIMEOUT.as_millis()
            );
        }
        thread::sleep(Duration::from_millis(2));
    }
    child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("learn case `{id}` output collection failed: {error}"))
}

#[test]
fn corpus_v1_manifest_is_exact_bounded_and_algorithmic() {
    let corpus = load_learn_corpus_v1(&manifest_path()).expect("admit canonical S1 corpus v1");
    assert_eq!(corpus.version, S1_LEARN_CORPUS_VERSION);
    assert_eq!(corpus.cases.len(), S1_LEARN_CORPUS_CASE_COUNT);

    let source_algorithms = corpus
        .cases
        .iter()
        .filter(|case| case.entry.implementation == LearnImplementation::SourceAlgorithm)
        .count();
    assert!(source_algorithms >= S1_LEARN_CORPUS_MIN_SOURCE_ALGORITHMS);
    for required in [
        LearnTopic::Search,
        LearnTopic::Sorting,
        LearnTopic::Graph,
        LearnTopic::Greedy,
        LearnTopic::DynamicProgramming,
    ] {
        assert!(
            corpus.cases.iter().any(|case| case.entry.topic == required),
            "missing required learn topic {required:?}"
        );
    }
}

#[test]
fn all_thirty_cases_execute_through_the_normal_cli() {
    let corpus = load_learn_corpus_v1(&manifest_path()).expect("admit canonical S1 corpus v1");
    for case in &corpus.cases {
        let output = run_case(&case.source_path, case.input.as_bytes(), &case.entry.id);
        if let Err(error) = admit_learn_case_result(
            &case.entry.id,
            output.status.success(),
            &output.stdout,
            &output.stderr,
            &case.expected_output,
        ) {
            panic!(
                "{error}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
