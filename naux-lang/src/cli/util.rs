use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::ast::Stmt;
use crate::cli::DefaultEngine;
use crate::diagnostic::{format_source_diagnostic, DiagnosticStage};
use crate::lexer;
use crate::parser;
use crate::parser::error::format_parse_error;
use crate::runtime;
use crate::runtime::budget::ExecutionLimits;
use crate::runtime::error::format_runtime_error_with_file;
use crate::vm::run::{run_jit_with_input_and_limits, run_vm_with_input_and_limits};

pub fn load_ast(path: &Path) -> Result<(String, Vec<Stmt>), String> {
    let src = fs::read_to_string(path)
        .map_err(|e| format!("Không đọc được {}: {}", path.display(), e))?;
    let tokens = lexer::lex(&src).map_err(|error| {
        format_source_diagnostic(
            DiagnosticStage::Lex,
            &error.message,
            &src,
            &path.to_string_lossy(),
            Some(&error.span),
        )
    })?;
    let stmts = parser::Parser::from_tokens(&tokens)
        .map_err(|err| format_parse_error(&src, &err, &path.to_string_lossy()))?;
    Ok((src, stmts))
}

pub fn execute_ast(
    engine: DefaultEngine,
    ast: &[Stmt],
    src: &str,
    path: &Path,
    print_engine: bool,
) -> Result<
    (
        Vec<runtime::events::RuntimeEvent>,
        Option<crate::runtime::value::Value>,
    ),
    String,
> {
    execute_ast_with_input(
        engine,
        ast,
        src,
        path,
        "",
        print_engine,
        ExecutionLimits::default(),
    )
}

pub fn execute_ast_with_input(
    engine: DefaultEngine,
    ast: &[Stmt],
    src: &str,
    path: &Path,
    input: &str,
    print_engine: bool,
    limits: ExecutionLimits,
) -> Result<
    (
        Vec<runtime::events::RuntimeEvent>,
        Option<crate::runtime::value::Value>,
    ),
    String,
> {
    match engine {
        DefaultEngine::Interp => {
            if print_engine {
                eprintln!("[engine] interp");
            }
            let (_env, events, errors) = runtime::eval_script_with_base_dir_input_and_limits(
                ast,
                path.parent(),
                input,
                limits,
            );
            if let Some(err) = errors.first() {
                Err(format_runtime_error_with_file(
                    src,
                    err,
                    &path.to_string_lossy(),
                ))
            } else {
                Ok((events, None))
            }
        }
        DefaultEngine::Vm => {
            if print_engine {
                eprintln!("[engine] vm");
            }
            let (events, val) =
                run_vm_with_input_and_limits(ast, src, &path.to_string_lossy(), input, limits)?;
            Ok((events, Some(val)))
        }
        DefaultEngine::Jit => {
            let (events, val, used_jit) =
                run_jit_with_input_and_limits(ast, src, &path.to_string_lossy(), input, limits)?;
            if print_engine {
                if used_jit {
                    eprintln!("[engine] jit");
                } else {
                    eprintln!("[engine] vm (fallback)");
                }
            }
            Ok((events, Some(val)))
        }
    }
}

pub fn collect_nx_files_in_project() -> Vec<PathBuf> {
    let mut files = BTreeSet::new();
    let defaults = ["src", "tests", "examples"];
    for entry in defaults {
        let candidate = PathBuf::from(entry);
        if candidate.exists() {
            gather_path(&candidate, &mut files);
        }
    }
    files.into_iter().collect()
}

pub fn collect_nx_files_for_doctor() -> Result<Vec<PathBuf>, String> {
    let cwd = env::current_dir().map_err(|e| format!("Không lấy được thư mục hiện tại: {}", e))?;
    let mut files = BTreeSet::new();
    for candidate in doctor_scan_roots(&cwd) {
        if candidate.exists() {
            gather_path(&candidate, &mut files);
        }
    }
    Ok(files.into_iter().collect())
}

fn doctor_scan_roots(cwd: &Path) -> Vec<PathBuf> {
    if is_workspace_root(cwd) {
        return vec![
            cwd.join("examples"),
            cwd.join("tests"),
            cwd.join("naux-lang/examples"),
            cwd.join("naux-lang/tests"),
            cwd.join("naux-lang/src"),
        ];
    }

    if is_naux_crate_dir(cwd) {
        let mut roots = vec![cwd.join("src"), cwd.join("tests"), cwd.join("examples")];
        if let Some(parent) = cwd.parent().filter(|p| is_workspace_root(p)) {
            roots.push(parent.join("examples"));
            roots.push(parent.join("tests"));
        }
        return roots;
    }

    vec![cwd.join("src"), cwd.join("tests"), cwd.join("examples")]
}

fn is_workspace_root(path: &Path) -> bool {
    path.join("naux-lang").is_dir() && path.join("benchmarks").is_dir()
}

fn is_naux_crate_dir(path: &Path) -> bool {
    path.join("src").is_dir()
        && path.join("examples").is_dir()
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name == "naux-lang")
            .unwrap_or(false)
}

fn gather_path(path: &Path, out: &mut BTreeSet<PathBuf>) {
    if path.is_file() {
        if is_nx(path) {
            out.insert(path.to_path_buf());
        }
    } else if path.is_dir() {
        collect_dir(path, out);
    }
}

fn collect_dir(dir: &Path, out: &mut BTreeSet<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                collect_dir(&path, out);
            } else if is_nx(&path) {
                out.insert(path);
            }
        }
    }
}

fn is_nx(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("nx"))
        .unwrap_or(false)
}
