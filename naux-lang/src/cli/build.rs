use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::{util, DefaultEngine};
use crate::renderer::{cli::render_cli_to_string, render_html};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildMode {
    Cli,
    Html,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildEngine {
    Vm,
    Jit,
}

struct BuildOptions {
    entry: String,
    mode: BuildMode,
    engine: BuildEngine,
    output_dir: String,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            entry: "main.nx".into(),
            mode: BuildMode::Cli,
            engine: BuildEngine::Vm,
            output_dir: "build".into(),
        }
    }
}

pub fn handle_build() -> Result<(), String> {
    let config = load_build_config()?;
    let entry_path = PathBuf::from(&config.entry);
    if !entry_path.exists() {
        return Err(format!("Không tìm thấy entry `{}`", entry_path.display()));
    }
    println!("[BUILD] Parsing {}", entry_path.display());
    let (src, ast) = util::load_ast(&entry_path)?;
    let engine = match config.engine {
        BuildEngine::Vm => DefaultEngine::Vm,
        BuildEngine::Jit => DefaultEngine::Jit,
    };
    println!("[BUILD] Generating bytecode...");
    println!("[BUILD] Running engine: {}", describe_engine(engine));
    let (events, _value) = util::execute_ast(engine, &ast, &src, &entry_path, false)?;
    let rendered = match config.mode {
        BuildMode::Cli => render_cli_to_string(&events),
        BuildMode::Html => render_html(&events, &[]),
    };
    let output_dir = PathBuf::from(&config.output_dir);
    fs::create_dir_all(&output_dir)
        .map_err(|e| format!("Không tạo được thư mục build {:?}: {}", output_dir, e))?;
    let stem = entry_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("main");
    let extension = match config.mode {
        BuildMode::Cli => "txt",
        BuildMode::Html => "html",
    };
    let output_file = output_dir.join(format!("{}.{}", stem, extension));
    fs::write(&output_file, rendered)
        .map_err(|e| format!("Không ghi được {}: {}", output_file.display(), e))?;
    println!("[SUCCESS] Output → {}", output_file.display());
    Ok(())
}

fn load_build_config() -> Result<BuildOptions, String> {
    let path = Path::new("naux.toml");
    if !path.exists() {
        return Ok(BuildOptions::default());
    }
    let content =
        fs::read_to_string(path).map_err(|e| format!("Không đọc được naux.toml: {}", e))?;
    parse_build_section(&content)
}

fn parse_build_section(src: &str) -> Result<BuildOptions, String> {
    let mut opts = BuildOptions::default();
    let mut section = String::new();
    for (idx, raw_line) in src.lines().enumerate() {
        let line_no = idx + 1;
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            continue;
        }
        if section != "build" {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("naux.toml:{}: invalid key=value", line_no))?;
        let key = key.trim();
        let value = parse_string_value(value.trim())?;
        match key {
            "entry" => opts.entry = value,
            "mode" => opts.mode = parse_build_mode(&value, line_no)?,
            "engine" => opts.engine = parse_build_engine(&value, line_no)?,
            "output" => opts.output_dir = value,
            _ => {
                // Ignore unknown keys in build section.
            }
        }
    }
    Ok(opts)
}

fn strip_comment(line: &str) -> &str {
    if let Some((before, _)) = line.split_once('#') {
        before
    } else {
        line
    }
}

fn parse_string_value(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    let quoted = ((trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
        && trimmed.len() >= 2;
    if quoted {
        Ok(trimmed[1..trimmed.len() - 1].to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn parse_build_mode(value: &str, line: usize) -> Result<BuildMode, String> {
    match value.to_ascii_lowercase().as_str() {
        "cli" => Ok(BuildMode::Cli),
        "html" => Ok(BuildMode::Html),
        other => Err(format!(
            "naux.toml:{}: unknown build.mode `{}`",
            line, other
        )),
    }
}

fn parse_build_engine(value: &str, line: usize) -> Result<BuildEngine, String> {
    match value.to_ascii_lowercase().as_str() {
        "vm" => Ok(BuildEngine::Vm),
        "jit" => Ok(BuildEngine::Jit),
        other => Err(format!(
            "naux.toml:{}: unknown build.engine `{}`",
            line, other
        )),
    }
}

fn describe_engine(engine: DefaultEngine) -> &'static str {
    match engine {
        DefaultEngine::Vm => "vm",
        DefaultEngine::Interp => "interp",
        DefaultEngine::Jit => "jit",
    }
}
