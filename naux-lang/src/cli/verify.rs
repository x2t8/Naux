use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::{build, check, dev, test};

#[derive(Debug)]
struct VerifyOptions {
    benchmark: PathBuf,
    engine: String,
    iters: u32,
    warmup_ms: u64,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            benchmark: PathBuf::from("bench.nx"),
            engine: "vm".into(),
            iters: 10,
            warmup_ms: 0,
        }
    }
}

pub fn handle_verify() -> Result<(), String> {
    let options = load_verify_config()?;
    let entry = build::project_entry_path()?;
    if !entry.is_file() {
        return Err(format!(
            "Project entry `{}` does not exist",
            entry.display()
        ));
    }
    if !options.benchmark.is_file() {
        return Err(format!(
            "Verify benchmark `{}` does not exist; configure [verify].benchmark",
            options.benchmark.display()
        ));
    }

    println!("[VERIFY 1/4] Check {}", entry.display());
    check::handle_check(Some(entry))?;

    println!("[VERIFY 2/4] Test project");
    test::handle_test(None)?;

    println!("[VERIFY 3/4] Build project");
    build::handle_build()?;

    println!(
        "[VERIFY 4/4] Benchmark {} (engine={}, iters={}, warmup_ms={})",
        options.benchmark.display(),
        options.engine,
        options.iters,
        options.warmup_ms,
    );
    dev::bench_runtime_core(
        &options.benchmark,
        &options.engine,
        options.iters,
        options.warmup_ms,
        false,
        false,
    )?;

    println!("[VERIFY] PASS — check, test, build, and benchmark completed");
    Ok(())
}

fn load_verify_config() -> Result<VerifyOptions, String> {
    let path = Path::new("naux.toml");
    if !path.exists() {
        return Ok(VerifyOptions::default());
    }
    let content =
        fs::read_to_string(path).map_err(|err| format!("Could not read naux.toml: {err}"))?;
    parse_verify_section(&content)
}

fn parse_verify_section(src: &str) -> Result<VerifyOptions, String> {
    let mut options = VerifyOptions::default();
    let mut section = "";

    for (index, raw_line) in src.lines().enumerate() {
        let line_no = index + 1;
        let line = raw_line
            .split_once('#')
            .map_or(raw_line, |(head, _)| head)
            .trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim();
            continue;
        }
        if section != "verify" {
            continue;
        }

        let (key, raw_value) = line
            .split_once('=')
            .ok_or_else(|| format!("naux.toml:{line_no}: invalid key=value"))?;
        let key = key.trim();
        let value = string_value(raw_value.trim());
        match key {
            "benchmark" => options.benchmark = PathBuf::from(value),
            "engine" => {
                let engine = value.to_ascii_lowercase();
                if !matches!(engine.as_str(), "vm" | "interp" | "jit") {
                    return Err(format!(
                        "naux.toml:{line_no}: unknown verify.engine `{engine}`"
                    ));
                }
                options.engine = engine;
            }
            "iters" => {
                options.iters = value
                    .parse()
                    .map_err(|_| format!("naux.toml:{line_no}: invalid verify.iters `{value}`"))?;
                if options.iters == 0 {
                    return Err(format!(
                        "naux.toml:{line_no}: verify.iters must be greater than zero"
                    ));
                }
            }
            "warmup_ms" => {
                options.warmup_ms = value.parse().map_err(|_| {
                    format!("naux.toml:{line_no}: invalid verify.warmup_ms `{value}`")
                })?;
            }
            _ => {}
        }
    }

    Ok(options)
}

fn string_value(raw: &str) -> String {
    let quoted = raw.len() >= 2
        && ((raw.starts_with('"') && raw.ends_with('"'))
            || (raw.starts_with('\'') && raw.ends_with('\'')));
    if quoted {
        raw[1..raw.len() - 1].to_string()
    } else {
        raw.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::parse_verify_section;
    use std::path::Path;

    #[test]
    fn parses_verify_workflow_config() {
        let options = parse_verify_section(
            r#"
[verify]
benchmark = "perf/smoke.nx"
engine = "jit"
iters = 7
warmup_ms = 25
"#,
        )
        .expect("verify config");

        assert_eq!(options.benchmark, Path::new("perf/smoke.nx"));
        assert_eq!(options.engine, "jit");
        assert_eq!(options.iters, 7);
        assert_eq!(options.warmup_ms, 25);
    }

    #[test]
    fn rejects_zero_iterations() {
        let error = parse_verify_section("[verify]\niters = 0\n").expect_err("zero must fail");
        assert!(error.contains("greater than zero"));
    }
}
