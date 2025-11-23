use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::format;
use crate::cli::util;

pub fn handle_fmt(path: Option<PathBuf>, check: bool) -> Result<(), String> {
    let files = collect_targets(path)?;
    if files.is_empty() {
        return Err("Không tìm thấy file .nx để format".into());
    }
    let mut needs_format = Vec::new();
    for file in files {
        match format_file(&file, check) {
            Ok(changed) => {
                if changed && check {
                    needs_format.push(file);
                }
            }
            Err(err) => return Err(err),
        }
    }
    if check && !needs_format.is_empty() {
        Err(format!(
            "Formatter muốn thay đổi {} file",
            needs_format.len()
        ))
    } else {
        Ok(())
    }
}

fn collect_targets(path: Option<PathBuf>) -> Result<Vec<PathBuf>, String> {
    let mut files = BTreeSet::new();
    if let Some(root) = path {
        gather_path(&root, &mut files)?;
    } else {
        let defaults = ["main.nx", "src", "tests"];
        for entry in defaults {
            let candidate = PathBuf::from(entry);
            if candidate.exists() {
                gather_path(&candidate, &mut files)?;
            }
        }
    }
    Ok(files.into_iter().collect())
}

fn gather_path(path: &Path, out: &mut BTreeSet<PathBuf>) -> Result<(), String> {
    if path.is_file() {
        if is_nx(path) {
            out.insert(path.to_path_buf());
            Ok(())
        } else {
            Err(format!("{} không phải file .nx", path.display()))
        }
    } else if path.is_dir() {
        collect_dir(path, out);
        Ok(())
    } else {
        Err(format!("Không tìm thấy {}", path.display()))
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

fn format_file(path: &Path, check: bool) -> Result<bool, String> {
    let (src, ast) = util::load_ast(path)?;
    let formatted = format::format_stmts(&ast);
    if formatted == src {
        return Ok(false);
    }
    if check {
        println!("{} cần format lại", path.display());
        return Ok(true);
    }
    fs::write(path, formatted)
        .map_err(|e| format!("Không ghi được {}: {}", path.display(), e))?;
    println!("Formatted {}", path.display());
    Ok(true)
}
