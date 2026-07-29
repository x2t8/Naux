use std::path::PathBuf;
use std::process::{Command, Output};

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
}

fn run_dev(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_naux"))
        .arg("dev")
        .args(args)
        .output()
        .expect("failed to run naux dev command")
}

fn assert_success(output: Output, command: &str) -> String {
    assert!(
        output.status.success(),
        "{command} failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).expect("dev command output must be UTF-8")
}

#[test]
fn split_analysis_modules_remain_wired_to_dev_cli() {
    let hello = example("hello.nx");
    let hello = hello.to_str().expect("example path must be UTF-8");

    let ir = assert_success(run_dev(&["ir", hello]), "dev ir");
    assert!(ir.contains("--- Optimizer Feedback ---"));
    assert!(ir.contains("SSA verify: OK"));

    let refine = assert_success(
        run_dev(&["refine", hello, "--strict"]),
        "dev refine --strict",
    );
    assert!(refine.contains("[SEFO FEEDBACK]"));
    assert!(refine.contains("[STRICT PROOF CONTRACT] OK"));

    let region = assert_success(run_dev(&["region", hello]), "dev region");
    assert!(region.contains("~ NAUX REGION ANALYSIS ~"));
    assert!(region.contains("[RESULT] OK"));
    #[cfg(feature = "experimental-regions")]
    assert!(region.contains("[LOWERING PLAN] schema 1"));

    let effects = assert_success(run_dev(&["effects", hello]), "dev effects");
    assert!(effects.contains("~ NAUX EFFECT ANALYSIS ~"));
    assert!(effects.contains("[RESULT] signature="));
}

#[test]
fn split_bench_module_preserves_side_exit_json_schema() {
    let workload = example("bench_internal_branch_handoff.nx");
    let workload = workload.to_str().expect("example path must be UTF-8");
    let output = Command::new(env!("CARGO_BIN_EXE_naux"))
        .env("NAUX_TRACE_PROFILE", "1")
        .args([
            "dev",
            "benchrt",
            workload,
            "--engine=jit",
            "--iters=1",
            "--warmup-ms=0",
            "--json",
        ])
        .output()
        .expect("failed to run split bench module");
    let json = assert_success(output, "dev benchrt --json");

    assert!(json.starts_with('{') && json.trim_end().ends_with('}'));
    assert!(json.contains("\"cv_pct\":"));
    assert!(json.contains("\"trace_count\":1"));
    assert!(json.contains("\"total_internal_side_exits\":"));
    assert!(json.contains("\"total_deopts\":0"));
    assert!(json.contains("\"total_runtime_deopts\":0"));
    assert!(json.contains("\"internal_side_exits\":"));
    assert!(json.contains("\"by_trace\":[{"));
}
