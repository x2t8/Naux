use crate::cli::util;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

impl CheckStatus {
    fn as_str(self) -> &'static str {
        match self {
            CheckStatus::Ok => "ok",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "fail",
        }
    }

    fn label(self) -> &'static str {
        match self {
            CheckStatus::Ok => "[OK]",
            CheckStatus::Warn => "[WARN]",
            CheckStatus::Fail => "[FAIL]",
        }
    }
}

#[derive(Debug, Clone)]
struct DoctorCheck {
    name: String,
    status: CheckStatus,
    message: String,
    details: Vec<String>,
}

#[derive(Debug, Clone)]
struct DoctorReport {
    project_root: PathBuf,
    cpu_core: usize,
    checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    fn has_failures(&self) -> bool {
        self.checks
            .iter()
            .any(|check| check.status == CheckStatus::Fail)
    }

    fn count_by(&self, status: CheckStatus) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == status)
            .count()
    }

    fn print_human(&self) {
        println!("Naux Doctor");
        println!("-----------");
        println!("Project root: {}", self.project_root.display());
        println!("CPU core for perf checks: {}", self.cpu_core);
        println!();

        for check in &self.checks {
            println!("{} {}: {}", check.status.label(), check.name, check.message);
            for detail in &check.details {
                println!("  - {}", detail);
            }
        }

        println!();
        println!(
            "Summary: {} ok, {} warn, {} fail",
            self.count_by(CheckStatus::Ok),
            self.count_by(CheckStatus::Warn),
            self.count_by(CheckStatus::Fail)
        );
    }

    fn to_json(&self) -> String {
        let checks = self
            .checks
            .iter()
            .map(DoctorCheck::to_json)
            .collect::<Vec<_>>()
            .join(",\n");
        format!(
            "{{\n  \"ok\": {},\n  \"project_root\": \"{}\",\n  \"cpu_core\": {},\n  \"summary\": {{\n    \"ok\": {},\n    \"warn\": {},\n    \"fail\": {}\n  }},\n  \"checks\": [\n{}\n  ]\n}}",
            if self.has_failures() { "false" } else { "true" },
            json_escape(&self.project_root.display().to_string()),
            self.cpu_core,
            self.count_by(CheckStatus::Ok),
            self.count_by(CheckStatus::Warn),
            self.count_by(CheckStatus::Fail),
            indent_json_items(&checks, 4)
        )
    }
}

impl DoctorCheck {
    fn to_json(&self) -> String {
        let details = self
            .details
            .iter()
            .map(|detail| format!("\"{}\"", json_escape(detail)))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{{\"name\":\"{}\",\"status\":\"{}\",\"message\":\"{}\",\"details\":[{}]}}",
            json_escape(&self.name),
            self.status.as_str(),
            json_escape(&self.message),
            details
        )
    }
}

pub fn handle_doctor(json: bool, out: Option<PathBuf>) -> Result<(), String> {
    let report = collect_report()?;
    let json_report = report.to_json();

    if let Some(path) = out {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Không tạo được thư mục {}: {}", parent.display(), e))?;
            }
        }
        fs::write(&path, &json_report)
            .map_err(|e| format!("Không ghi được report {}: {}", path.display(), e))?;
        if !json {
            println!("[OK] Wrote doctor report to {}", path.display());
            println!();
        }
    }

    if json {
        println!("{}", json_report);
    } else {
        report.print_human();
    }

    if report.has_failures() {
        Err(format!(
            "doctor found {} failing checks",
            report.count_by(CheckStatus::Fail)
        ))
    } else {
        Ok(())
    }
}

fn collect_report() -> Result<DoctorReport, String> {
    let cwd = env::current_dir().map_err(|e| format!("Không lấy được thư mục hiện tại: {}", e))?;
    let project_root = resolve_project_root(&cwd);
    let cpu_core = env::var("CPU_CORE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);

    let checks = vec![
        command_check("rustc", &["--version"], false),
        command_check("cargo", &["--version"], false),
        command_check("taskset", &["--version"], true),
        command_check("coqc", &["--version"], true),
        file_exists_check(
            "perf_baseline_tsv",
            &project_root.join("benchmarks/perf_baseline.tsv"),
            false,
        ),
        file_exists_check(
            "perf_baseline_fingerprint",
            &project_root.join("benchmarks/perf_baseline_fingerprint.json"),
            false,
        ),
        governor_check(cpu_core),
        turbo_check(),
        nx_parse_check()?,
    ];

    Ok(DoctorReport {
        project_root,
        cpu_core,
        checks,
    })
}

fn resolve_project_root(cwd: &Path) -> PathBuf {
    if cwd.join("benchmarks").is_dir() && cwd.join("naux-lang").is_dir() {
        return cwd.to_path_buf();
    }

    if cwd
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == "naux-lang")
        .unwrap_or(false)
    {
        if let Some(parent) = cwd.parent() {
            if parent.join("benchmarks").is_dir() && parent.join("naux-lang").is_dir() {
                return parent.to_path_buf();
            }
        }
    }

    cwd.to_path_buf()
}

fn command_check(name: &str, args: &[&str], warn_only: bool) -> DoctorCheck {
    match Command::new(name).args(args).output() {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let message = if !stdout.is_empty() {
                summarize_command_output(&stdout)
            } else if !stderr.is_empty() {
                summarize_command_output(&stderr)
            } else {
                format!("{} is available", name)
            };
            DoctorCheck {
                name: name.to_string(),
                status: CheckStatus::Ok,
                message,
                details: Vec::new(),
            }
        }
        Ok(output) => DoctorCheck {
            name: name.to_string(),
            status: if warn_only {
                CheckStatus::Warn
            } else {
                CheckStatus::Fail
            },
            message: format!("{} exited with status {}", name, output.status),
            details: stderr_or_stdout_details(&output),
        },
        Err(err) => DoctorCheck {
            name: name.to_string(),
            status: if warn_only {
                CheckStatus::Warn
            } else {
                CheckStatus::Fail
            },
            message: format!("{} is unavailable", name),
            details: vec![err.to_string()],
        },
    }
}

fn file_exists_check(name: &str, path: &Path, warn_only: bool) -> DoctorCheck {
    if path.is_file() {
        DoctorCheck {
            name: name.to_string(),
            status: CheckStatus::Ok,
            message: format!("found {}", path.display()),
            details: Vec::new(),
        }
    } else {
        DoctorCheck {
            name: name.to_string(),
            status: if warn_only {
                CheckStatus::Warn
            } else {
                CheckStatus::Fail
            },
            message: format!("missing {}", path.display()),
            details: vec![
                "Run the perf baseline capture/update flow before trusting perf gates.".into(),
            ],
        }
    }
}

fn governor_check(cpu_core: usize) -> DoctorCheck {
    let expected = env::var("PERF_EXPECT_GOVERNOR").unwrap_or_else(|_| "performance".into());
    let path = format!(
        "/sys/devices/system/cpu/cpu{}/cpufreq/scaling_governor",
        cpu_core
    );
    match read_trimmed(&path) {
        Some(actual) if actual == expected => DoctorCheck {
            name: "cpu_governor".into(),
            status: CheckStatus::Ok,
            message: format!(
                "cpu{} governor={} (expected {})",
                cpu_core, actual, expected
            ),
            details: Vec::new(),
        },
        Some(actual) => DoctorCheck {
            name: "cpu_governor".into(),
            status: CheckStatus::Warn,
            message: format!(
                "cpu{} governor={} (expected {})",
                cpu_core, actual, expected
            ),
            details: vec!["Perf gates can get noisy when the governor drifts.".into()],
        },
        None => DoctorCheck {
            name: "cpu_governor".into(),
            status: CheckStatus::Warn,
            message: format!("cpu{} governor is unavailable", cpu_core),
            details: vec![format!("Tried {}", path)],
        },
    }
}

fn turbo_check() -> DoctorCheck {
    let expected_no_turbo = env::var("PERF_EXPECT_INTEL_NO_TURBO").unwrap_or_else(|_| "1".into());
    let intel_path = "/sys/devices/system/cpu/intel_pstate/no_turbo";
    let amd_path = "/sys/devices/system/cpu/cpufreq/boost";

    if let Some(actual) = read_trimmed(intel_path) {
        return if actual == expected_no_turbo {
            DoctorCheck {
                name: "cpu_turbo".into(),
                status: CheckStatus::Ok,
                message: format!("intel no_turbo={} (expected {})", actual, expected_no_turbo),
                details: Vec::new(),
            }
        } else {
            DoctorCheck {
                name: "cpu_turbo".into(),
                status: CheckStatus::Warn,
                message: format!("intel no_turbo={} (expected {})", actual, expected_no_turbo),
                details: vec!["Perf gates can drift when turbo policy changes.".into()],
            }
        };
    }

    if let Some(actual) = read_trimmed(amd_path) {
        let expected = if expected_no_turbo == "1" { "0" } else { "1" };
        return if actual == expected {
            DoctorCheck {
                name: "cpu_turbo".into(),
                status: CheckStatus::Ok,
                message: format!("cpufreq boost={} (expected {})", actual, expected),
                details: Vec::new(),
            }
        } else {
            DoctorCheck {
                name: "cpu_turbo".into(),
                status: CheckStatus::Warn,
                message: format!("cpufreq boost={} (expected {})", actual, expected),
                details: vec!["Perf gates can drift when boost policy changes.".into()],
            }
        };
    }

    DoctorCheck {
        name: "cpu_turbo".into(),
        status: CheckStatus::Warn,
        message: "turbo control sysfs is unavailable".into(),
        details: vec![intel_path.into(), amd_path.into()],
    }
}

fn nx_parse_check() -> Result<DoctorCheck, String> {
    let paths = util::collect_nx_files_for_doctor()?;
    if paths.is_empty() {
        return Ok(DoctorCheck {
            name: "nx_parse".into(),
            status: CheckStatus::Warn,
            message: "no .nx files found in standard project roots".into(),
            details: vec!["Expected roots: examples/, tests/, or naux-lang/examples/".into()],
        });
    }

    let mut warn_details = Vec::new();
    let mut fail_details = Vec::new();
    for path in &paths {
        let (src, ast) = match util::load_ast(path) {
            Ok(result) => result,
            Err(err) => {
                fail_details.push(format!("{}: {}", path.display(), err));
                continue;
            }
        };
        if ast.is_empty() && !src.trim().is_empty() {
            warn_details.push(format!(
                "{}: file is not empty but AST is empty",
                path.display()
            ));
        }
    }

    let status = if !fail_details.is_empty() {
        CheckStatus::Fail
    } else if !warn_details.is_empty() {
        CheckStatus::Warn
    } else {
        CheckStatus::Ok
    };

    let message = match status {
        CheckStatus::Ok => format!("parsed {} .nx files cleanly", paths.len()),
        CheckStatus::Warn => format!(
            "parsed {} .nx files with {} warnings",
            paths.len(),
            warn_details.len()
        ),
        CheckStatus::Fail => format!(
            "parsed {} .nx files with {} failures and {} warnings",
            paths.len(),
            fail_details.len(),
            warn_details.len()
        ),
    };

    let mut details = fail_details;
    details.extend(warn_details);

    Ok(DoctorCheck {
        name: "nx_parse".into(),
        status,
        message,
        details,
    })
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn stderr_or_stdout_details(output: &std::process::Output) -> Vec<String> {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        return vec![stderr];
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stdout.is_empty() {
        return vec![stdout];
    }
    Vec::new()
}

fn summarize_command_output(output: &str) -> String {
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("command succeeded")
        .to_string()
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

fn indent_json_items(block: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    block
        .lines()
        .map(|line| format!("{}{}", pad, line))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{indent_json_items, json_escape, resolve_project_root, summarize_command_output};
    use std::path::Path;

    #[test]
    fn json_escape_handles_quotes_and_newlines() {
        assert_eq!(json_escape("a\"b\nc"), "a\\\"b\\nc");
    }

    #[test]
    fn indent_json_items_prefixes_each_line() {
        assert_eq!(indent_json_items("{\n}", 2), "  {\n  }");
    }

    #[test]
    fn resolve_project_root_keeps_repo_root() {
        let root = Path::new("/tmp/workspace");
        assert_eq!(resolve_project_root(root), root);
    }

    #[test]
    fn summarize_command_output_uses_first_non_empty_line() {
        assert_eq!(
            summarize_command_output("\nUsage: taskset\nmore"),
            "Usage: taskset"
        );
    }
}
