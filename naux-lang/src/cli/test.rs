use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::DefaultEngine;
use naux::lexer;
use naux::parser;
use naux::runtime;
use naux::runtime::events::RuntimeEvent;
use naux::runtime::error::format_runtime_error_with_file;
use naux::vm;

pub struct TestResult {
    pub path: PathBuf,
    pub passed: bool,
    pub message: Option<String>,
}

pub struct TestSummary {
    pub results: Vec<TestResult>,
}

impl TestSummary {
    pub fn new() -> Self {
        Self { results: Vec::new() }
    }

    pub fn add(&mut self, result: TestResult) {
        self.results.push(result);
    }

    pub fn passed(&self) -> usize {
        self.results.iter().filter(|r| r.passed).count()
    }

    pub fn failed(&self) -> usize {
        self.results.iter().filter(|r| !r.passed).count()
    }
}

pub fn handle_test(pattern: Option<String>) -> Result<(), String> {
    let mut paths = vec![PathBuf::from("tests")];
    if let Some(pat) = pattern {
        paths = vec![PathBuf::from(pat)];
    }
    let summary = run_tests(&paths, DefaultEngine::Vm);
    for result in &summary.results {
        if result.passed {
            println!("[PASS] {}", result.path.display());
        } else {
            println!("[FAIL] {}", result.path.display());
            if let Some(msg) = &result.message {
                println!("  {}", msg.replace('\n', "\n  "));
            }
        }
    }
    println!("Summary: {} passed, {} failed", summary.passed(), summary.failed());
    if summary.failed() > 0 {
        Err("Some tests failed".into())
    } else {
        Ok(())
    }
}

fn discover_tests(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut collected = Vec::new();
    for path in paths {
        if path.is_dir() {
            collect_dir(path, &mut collected);
        } else if path.is_file() && matches_test_file(path) {
            collected.push(path.clone());
        }
    }
    collected.sort();
    collected
}

fn collect_dir(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                collect_dir(&path, out);
            } else if matches_test_file(&path) {
                out.push(path);
            }
        }
    }
}

fn matches_test_file(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
        if ext != "nx" {
            return false;
        }
    } else {
        return false;
    }
    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
        name.ends_with("_test.nx") || name.ends_with(".test.nx")
    } else {
        false
    }
}

fn run_tests(paths: &[PathBuf], engine: DefaultEngine) -> TestSummary {
    let mut summary = TestSummary::new();
    for path in discover_tests(paths) {
        summary.add(run_test_file(&path, engine));
    }
    summary
}

fn run_test_file(path: &Path, engine: DefaultEngine) -> TestResult {
    let mut passed = true;
    let mut message = None;

    let src = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            passed = false;
            message = Some(format!("Failed to read: {}", e));
            return TestResult { path: path.to_path_buf(), passed, message };
        }
    };

    let tokens = match lexer::lex(&src) {
        Ok(t) => t,
        Err(err) => {
            passed = false;
            message = Some(format!("Lex error: {}", err.message));
            return TestResult { path: path.to_path_buf(), passed, message };
        }
    };

    let ast = match parser::parser::Parser::from_tokens(&tokens) {
        Ok(ast) => ast,
        Err(err) => {
            passed = false;
            message = Some(format!("Parse error: {}", err.message));
            return TestResult { path: path.to_path_buf(), passed, message };
        }
    };

    let mut events = Vec::new();
    let mut runtime_fail: Option<String> = None;

    match engine {
        DefaultEngine::Interp => {
            let (_env, ev, errs) = runtime::eval_script(&ast);
            events = ev;
            if let Some(err) = errs.first() {
                runtime_fail = Some(format_runtime_error_with_file(&src, err, &path.to_string_lossy()));
            }
        }
        DefaultEngine::Vm | DefaultEngine::Jit => {
            let res = if engine == DefaultEngine::Vm {
                vm::run::run_vm(&ast, &src, &path.to_string_lossy())
            } else {
                vm::run::run_jit(&ast, &src, &path.to_string_lossy())
            };
            match res {
                Ok((ev, _)) => events = ev,
                Err(err) => {
                    runtime_fail = Some(err);
                }
            }
        }
        DefaultEngine::Llvm => {
            runtime_fail = Some("LLVM engine not supported in tests".into());
        }
    }

    let mut fail_log = None;
    for event in events.iter() {
        if let RuntimeEvent::Log(msg) = event {
            if msg.contains("[FAIL]") || msg.contains("__NAUX_TEST_FAIL__") {
                passed = false;
                fail_log = Some(msg.clone());
            }
        }
    }
    if runtime_fail.is_some() {
        passed = false;
        if message.is_none() {
            message = runtime_fail.clone();
        }
    } else if !passed {
        message = message.or_else(|| fail_log);
    }

    TestResult { path: path.to_path_buf(), passed, message }
}
