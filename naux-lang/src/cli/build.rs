use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::cli::{util, DefaultEngine};
use crate::renderer::{cli::render_cli_to_string, render_html};

#[derive(Debug, Deserialize)]
struct BuildToml {
    build: Option<BuildSection>,
}

#[derive(Debug, Deserialize)]
struct BuildSection {
    entry: Option<String>,
    mode: Option<BuildMode>,
    engine: Option<BuildEngine>,
    output: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum BuildMode {
    Cli,
    Html,
}

impl Default for BuildMode {
    fn default() -> Self {
        BuildMode::Cli
    }
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum BuildEngine {
    Vm,
    Jit,
}

impl Default for BuildEngine {
    fn default() -> Self {
        BuildEngine::Vm
    }
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

impl BuildOptions {
    fn from_section(section: Option<BuildSection>) -> Self {
        let mut opts = BuildOptions::default();
        if let Some(section) = section {
            if let Some(entry) = section.entry {
                opts.entry = entry;
            }
            if let Some(mode) = section.mode {
                opts.mode = mode;
            }
            if let Some(engine) = section.engine {
                opts.engine = engine;
            }
            if let Some(output) = section.output {
                opts.output_dir = output;
            }
        }
        opts
    }
}

pub fn handle_build() -> Result<(), String> {
    let config = load_build_config()?;
    let entry_path = PathBuf::from(&config.entry);
    if !entry_path.exists() {
        return Err(format!("Không tìm thấy entry `{}`", entry_path.display()));
    }
    let (src, ast) = util::load_ast(&entry_path)?;
    let engine = match config.engine {
        BuildEngine::Vm => DefaultEngine::Vm,
        BuildEngine::Jit => DefaultEngine::Jit,
    };
    let events = util::execute_ast(engine, &ast, &src, &entry_path)?;
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
    println!("Build thành công: {}", output_file.display());
    Ok(())
}

fn load_build_config() -> Result<BuildOptions, String> {
    let path = Path::new("naux.toml");
    if !path.exists() {
        return Ok(BuildOptions::default());
    }
    let content = fs::read_to_string(path).map_err(|e| format!("Không đọc được naux.toml: {}", e))?;
    let parsed: BuildToml = toml::from_str(&content).map_err(|e| format!("Không parse naux.toml: {}", e))?;
    Ok(BuildOptions::from_section(parsed.build))
}
