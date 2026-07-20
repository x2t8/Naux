use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

#[derive(Debug, Clone)]
struct Scenario {
    name: &'static str,
    template: PathBuf,
    mode: &'static str, // runtime|trace
    n_values: &'static [i64],
    iters: i64,
    warmup_ms: i64,
    require_r2: f64,
    max_a_reg_pct: f64,
    max_b_reg_pct: f64,
    element_formula: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaselineEntry {
    a_ns_per_elem: f64,
    b_ns: f64,
    r2: f64,
}

#[derive(Debug, Clone, Parser)]
#[command(name = "slope_gate")]
#[command(about = "Run slope gates for Naux perf invariants")]
struct Args {
    #[arg(long)]
    root: PathBuf,
    #[arg(long = "naux-bin")]
    naux_bin: PathBuf,
    #[arg(long = "cpu-core", default_value_t = 0)]
    cpu_core: i64,
    #[arg(long, default_value = "jit")]
    engine: String,
    #[arg(long = "default-iters", default_value_t = 25)]
    default_iters: i64,
    #[arg(long = "default-warmup-ms", default_value_t = 100)]
    default_warmup_ms: i64,
    #[arg(long = "dot-runtime-iters", default_value_t = 0)]
    dot_runtime_iters: i64,
    #[arg(long = "dot-runtime-warmup-ms", default_value_t = 0)]
    dot_runtime_warmup_ms: i64,
    #[arg(long = "dot-trace-iters", default_value_t = 0)]
    dot_trace_iters: i64,
    #[arg(long = "dot-trace-warmup-ms", default_value_t = 0)]
    dot_trace_warmup_ms: i64,
    #[arg(long = "map-runtime-iters", default_value_t = 0)]
    map_runtime_iters: i64,
    #[arg(long = "map-runtime-warmup-ms", default_value_t = 0)]
    map_runtime_warmup_ms: i64,
    #[arg(long = "map-guard-entry-iters", default_value_t = 0)]
    map_guard_entry_iters: i64,
    #[arg(long = "map-guard-entry-warmup-ms", default_value_t = 0)]
    map_guard_entry_warmup_ms: i64,
    #[arg(long = "map-get-mul-acc-iters", default_value_t = 0)]
    map_get_mul_acc_iters: i64,
    #[arg(long = "map-get-mul-acc-warmup-ms", default_value_t = 0)]
    map_get_mul_acc_warmup_ms: i64,
    #[arg(long = "map-get-cmp-branch-iters", default_value_t = 0)]
    map_get_cmp_branch_iters: i64,
    #[arg(long = "map-get-cmp-branch-warmup-ms", default_value_t = 0)]
    map_get_cmp_branch_warmup_ms: i64,
    #[arg(
        long = "slope-baseline",
        default_value = "benchmarks/perf_slope_baseline.tsv"
    )]
    slope_baseline: PathBuf,
    #[arg(long = "min-r2", default_value_t = 0.995)]
    min_r2: f64,
    #[arg(long = "max-a-regression-pct", default_value_t = 5.0)]
    max_a_regression_pct: f64,
    #[arg(long = "max-b-regression-pct", default_value_t = 10.0)]
    max_b_regression_pct: f64,
    #[arg(long = "instability-r2-margin", default_value_t = 0.01)]
    instability_r2_margin: f64,
    #[arg(long = "instability-a-overage-pct", default_value_t = 3.0)]
    instability_a_overage_pct: f64,
    #[arg(long = "instability-b-overage-pct", default_value_t = 5.0)]
    instability_b_overage_pct: f64,
    #[arg(long = "min-baseline-b-ns-for-gate", default_value_t = 100_000.0)]
    min_baseline_b_ns_for_gate: f64,
    #[arg(long = "trace-min-measurement-ns", default_value_t = 50_000.0)]
    trace_min_measurement_ns: f64,
    #[arg(long = "runtime-measure-runs", default_value_t = 5)]
    runtime_measure_runs: usize,
    #[arg(long = "runtime-trim-pct", default_value_t = 0.2)]
    runtime_trim_pct: f64,
    #[arg(long = "require-baseline", default_value_t = false)]
    require_baseline: bool,
    #[arg(
        long = "fusion-expectations",
        default_value = "scripts/fusion_expectations.json"
    )]
    fusion_expectations: PathBuf,
    #[arg(long = "require-fusion-expectation-scenarios", default_value = "")]
    require_fusion_expectation_scenarios: String,
    #[arg(long = "disable-fusion-rule-gate", default_value_t = false)]
    disable_fusion_rule_gate: bool,
    #[arg(long = "nonblocking-scenarios", default_value = "")]
    nonblocking_scenarios: String,
    #[arg(long = "input-report")]
    input_report: Option<PathBuf>,
    #[arg(long = "baseline-fingerprint-file", default_value = "")]
    baseline_fingerprint_file: String,
    #[arg(long = "baseline-fingerprint-status", default_value = "")]
    baseline_fingerprint_status: String,
    #[arg(long = "baseline-fingerprint-notes", default_value = "")]
    baseline_fingerprint_notes: String,
    #[arg(long = "cpu-model", default_value = "")]
    cpu_model: String,
    #[arg(long = "out-json", default_value = "target/perf/slope_report.json")]
    out_json: PathBuf,
    #[arg(long = "out-md", default_value = "target/perf/slope_report.md")]
    out_md: PathBuf,
}

#[derive(Debug, Clone)]
struct FusionExpectation {
    required: Vec<String>,
    optional: Vec<String>,
    forbidden: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MeasurementRun {
    a_ns_per_elem: f64,
    b_ns: f64,
    r2: f64,
    max_point_time_ns: f64,
}

type FusionHits = BTreeMap<String, Map<String, Value>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AggregatedFit {
    a_ns_per_elem: f64,
    b_ns: f64,
    r2: f64,
}

fn parse_csv_items(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn pick_override(value: i64, fallback: i64) -> i64 {
    if value > 0 {
        value
    } else {
        fallback
    }
}

fn unique_rules(rules: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for r in rules {
        if seen.insert(r.clone()) {
            out.push(r);
        }
    }
    out
}

fn normalize_rules(raw: Option<&Value>, ctx: &str) -> Result<Vec<String>, String> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let arr = raw
        .as_array()
        .ok_or_else(|| format!("{ctx} must be a list of strings"))?;
    let mut out = Vec::new();
    for (idx, item) in arr.iter().enumerate() {
        let s = item
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("{ctx}[{idx}] must be a non-empty string"))?;
        out.push(s.to_string());
    }
    Ok(unique_rules(out))
}

fn parse_expectation_entry(scenario: &str, raw: &Value) -> Result<FusionExpectation, String> {
    if raw.is_array() {
        return Ok(FusionExpectation {
            required: normalize_rules(Some(raw), &format!("{scenario}.required"))?,
            optional: Vec::new(),
            forbidden: Vec::new(),
        });
    }
    let obj = raw.as_object().ok_or_else(|| {
        format!(
            "fusion expectation for scenario '{scenario}' must be either a list or an object with required/optional/forbidden"
        )
    })?;
    for key in obj.keys() {
        if key != "required" && key != "optional" && key != "forbidden" {
            return Err(format!(
                "fusion expectation for scenario '{scenario}' has unknown keys: {key}"
            ));
        }
    }
    Ok(FusionExpectation {
        required: normalize_rules(obj.get("required"), &format!("{scenario}.required"))?,
        optional: normalize_rules(obj.get("optional"), &format!("{scenario}.optional"))?,
        forbidden: normalize_rules(obj.get("forbidden"), &format!("{scenario}.forbidden"))?,
    })
}

fn load_fusion_expectations(path: &Path) -> Result<BTreeMap<String, FusionExpectation>, String> {
    if !path.exists() {
        return Err(format!(
            "fusion expectation config not found: {}",
            path.display()
        ));
    }
    let raw_txt = fs::read_to_string(path).map_err(|e| {
        format!(
            "failed to read fusion expectation config {}: {e}",
            path.display()
        )
    })?;
    let raw: Value = serde_json::from_str(&raw_txt)
        .map_err(|e| format!("invalid fusion expectation JSON at {}: {e}", path.display()))?;
    let obj = raw.as_object().ok_or_else(|| {
        format!(
            "fusion expectation config must be a JSON object: {}",
            path.display()
        )
    })?;
    let mut out = BTreeMap::new();
    for (scenario, entry) in obj {
        let s = scenario.trim();
        if s.is_empty() {
            return Err("fusion expectation keys must be non-empty scenario names".to_string());
        }
        out.insert(s.to_string(), parse_expectation_entry(s, entry)?);
    }
    Ok(out)
}

fn replace_first_int_assignment(src: &str, var: &str, value: i64) -> Result<String, String> {
    let pat = Regex::new(&format!(
        r"(?m)^(\s*\${}\s*=\s*)(\d+)(\s*)$",
        regex::escape(var)
    ))
    .map_err(|e| format!("invalid regex for ${var}: {e}"))?;
    if let Some(m) = pat.captures(src) {
        let whole = m
            .get(0)
            .ok_or_else(|| format!("cannot find assignment for ${var}"))?;
        let p1 = m.get(1).map(|x| x.as_str()).unwrap_or("");
        let p3 = m.get(3).map(|x| x.as_str()).unwrap_or("");
        let mut out = String::new();
        out.push_str(&src[..whole.start()]);
        out.push_str(p1);
        out.push_str(&value.to_string());
        out.push_str(p3);
        out.push_str(&src[whole.end()..]);
        Ok(out)
    } else {
        Err(format!("cannot find assignment for ${var}"))
    }
}

fn parse_first_int_assignment(src: &str, var: &str) -> Result<i64, String> {
    let pat = Regex::new(&format!(
        r"(?m)^\s*\${}\s*=\s*(\d+)\s*$",
        regex::escape(var)
    ))
    .map_err(|e| format!("invalid regex for ${var}: {e}"))?;
    let caps = pat
        .captures(src)
        .ok_or_else(|| format!("cannot parse assignment for ${var}"))?;
    let val = caps
        .get(1)
        .ok_or_else(|| format!("cannot parse assignment for ${var}"))?
        .as_str()
        .parse::<i64>()
        .map_err(|e| format!("cannot parse assignment for ${var}: {e}"))?;
    Ok(val)
}

fn run_cmd(cmd: &[String], cwd: &Path) -> Result<String, String> {
    let out = Command::new(&cmd[0])
        .args(&cmd[1..])
        .current_dir(cwd)
        .output()
        .map_err(|e| format!("command exec error: {}: {e}", cmd.join(" ")))?;
    if !out.status.success() {
        return Err(format!(
            "command failed rc={}: {}\nstdout:\n{}\nstderr:\n{}",
            out.status.code().unwrap_or(-1),
            cmd.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        return Err(format!("empty output: {}", cmd.join(" ")));
    }
    Ok(s)
}

#[allow(clippy::too_many_arguments)]
fn bench_json(
    root: &Path,
    naux_bin: &Path,
    pin_cmd: &Option<Vec<String>>,
    engine: &str,
    nx_path: &Path,
    mode: &str,
    iters: i64,
    warmup_ms: i64,
) -> Result<Value, String> {
    let mut cmd: Vec<String> = Vec::new();
    if let Some(pin) = pin_cmd {
        cmd.extend(pin.clone());
    }
    cmd.extend([
        naux_bin.display().to_string(),
        "dev".to_string(),
        "benchrt".to_string(),
        nx_path.display().to_string(),
        format!("--engine={engine}"),
        format!("--iters={iters}"),
        format!("--warmup-ms={warmup_ms}"),
        "--json".to_string(),
    ]);
    if mode == "trace" {
        let idx = cmd.len() - 1;
        cmd.insert(idx, "--trace-only".to_string());
    }
    let out = run_cmd(&cmd, root)?;
    serde_json::from_str(&out).map_err(|e| {
        format!(
            "invalid JSON from benchrt for {}: {e}\n{out}",
            nx_path.display()
        )
    })
}

fn linear_fit(xs: &[f64], ys: &[f64]) -> Result<(f64, f64, f64), String> {
    let n = xs.len();
    if n < 2 || ys.len() != n {
        return Err("need at least 2 points".to_string());
    }
    let mx = xs.iter().sum::<f64>() / n as f64;
    let my = ys.iter().sum::<f64>() / n as f64;
    let sxx = xs.iter().map(|x| (x - mx) * (x - mx)).sum::<f64>();
    if sxx == 0.0 {
        return Err("degenerate x values".to_string());
    }
    let sxy = xs
        .iter()
        .zip(ys.iter())
        .map(|(x, y)| (x - mx) * (y - my))
        .sum::<f64>();
    let a = sxy / sxx;
    let b = my - a * mx;
    let yhat: Vec<f64> = xs.iter().map(|x| a * x + b).collect();
    let ss_res = ys
        .iter()
        .zip(yhat.iter())
        .map(|(y, yh)| (y - yh) * (y - yh))
        .sum::<f64>();
    let ss_tot = ys.iter().map(|y| (y - my) * (y - my)).sum::<f64>();
    let r2 = if ss_tot == 0.0 {
        1.0
    } else {
        1.0 - (ss_res / ss_tot)
    };
    Ok((a, b, r2))
}

fn parse_baseline(path: &Path) -> Result<BTreeMap<String, BaselineEntry>, String> {
    let mut out = BTreeMap::new();
    if !path.exists() {
        return Ok(out);
    }
    let txt = fs::read_to_string(path)
        .map_err(|e| format!("failed to read baseline {}: {e}", path.display()))?;
    for line in txt.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let a = parts[1]
            .parse::<f64>()
            .map_err(|e| format!("invalid baseline a for {}: {e}", parts[0]))?;
        let b = parts[2]
            .parse::<f64>()
            .map_err(|e| format!("invalid baseline b for {}: {e}", parts[0]))?;
        let r2 = parts[3]
            .parse::<f64>()
            .map_err(|e| format!("invalid baseline r2 for {}: {e}", parts[0]))?;
        out.insert(
            parts[0].to_string(),
            BaselineEntry {
                a_ns_per_elem: a,
                b_ns: b,
                r2,
            },
        );
    }
    Ok(out)
}

fn rel_regression_pct(new: f64, base: f64) -> f64 {
    if base == 0.0 {
        if new == 0.0 {
            0.0
        } else {
            10_000.0
        }
    } else {
        ((new - base) / base.abs()) * 100.0
    }
}

fn max_point_time_ns(points: &[Value]) -> f64 {
    points
        .iter()
        .filter_map(|p| p.get("time_ns").and_then(|v| v.as_f64()))
        .fold(0.0, f64::max)
}

fn short_trace_measurement_retryable(
    mode: &str,
    points: &[Value],
    trace_min_measurement_ns: f64,
) -> bool {
    mode == "trace" && max_point_time_ns(points) < trace_min_measurement_ns
}

fn trimmed_median(values: &[f64], trim_pct: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let trim = ((ordered.len() as f64) * trim_pct).floor() as usize;
    if trim > 0 && ordered.len().saturating_sub(trim * 2) >= 1 {
        ordered = ordered[trim..ordered.len() - trim].to_vec();
    }
    let len = ordered.len();
    if len % 2 == 1 {
        ordered[len / 2]
    } else {
        (ordered[(len / 2) - 1] + ordered[len / 2]) / 2.0
    }
}

fn representative_run_index(runs: &[MeasurementRun], agg_a: f64, agg_b: f64, agg_r2: f64) -> usize {
    runs.iter()
        .enumerate()
        .min_by(|(_, lhs), (_, rhs)| {
            let lhs_a_scale = agg_a.abs().max(1e-9);
            let rhs_a_scale = agg_a.abs().max(1e-9);
            let lhs_b_scale = agg_b.abs().max(1.0);
            let rhs_b_scale = agg_b.abs().max(1.0);
            let lhs_score = (
                ((lhs.a_ns_per_elem - agg_a).abs() / lhs_a_scale),
                ((lhs.b_ns - agg_b).abs() / lhs_b_scale),
                (lhs.r2 - agg_r2).abs(),
            );
            let rhs_score = (
                ((rhs.a_ns_per_elem - agg_a).abs() / rhs_a_scale),
                ((rhs.b_ns - agg_b).abs() / rhs_b_scale),
                (rhs.r2 - agg_r2).abs(),
            );
            lhs_score
                .0
                .partial_cmp(&rhs_score.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    lhs_score
                        .1
                        .partial_cmp(&rhs_score.1)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| {
                    lhs_score
                        .2
                        .partial_cmp(&rhs_score.2)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        })
        .map(|(idx, _)| idx)
        .unwrap_or(0)
}

fn eval_elements_formula(expr: &str, n: i64, reps: i64) -> Result<f64, String> {
    let rendered = expr
        .replace("reps", &reps.to_string())
        .replace("n", &n.to_string());
    let safe_re = Regex::new(r"^[0-9+\-*/().\s]+$").map_err(|e| format!("regex error: {e}"))?;
    if !safe_re.is_match(&rendered) {
        return Err(format!("unsafe element formula: {expr}"));
    }
    let v = meval::eval_str(&rendered)
        .map_err(|e| format!("failed to eval element formula '{expr}': {e}"))?;
    if v <= 0.0 {
        return Err(format!("element formula must be > 0, got {v} for {expr}"));
    }
    Ok(v)
}

fn merge_fusion_hit_maps(
    into: &mut BTreeMap<String, Map<String, Value>>,
    from: &BTreeMap<String, Map<String, Value>>,
) {
    for (rule, stats) in from {
        let static_hits = stats
            .get("static_hits")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let runtime_hits = stats
            .get("runtime_hits")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let entry = into.entry(rule.clone()).or_insert_with(|| {
            let mut m = Map::new();
            m.insert("static_hits".to_string(), Value::from(0u64));
            m.insert("runtime_hits".to_string(), Value::from(0u64));
            m
        });
        let prev_s = entry
            .get("static_hits")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let prev_r = entry
            .get("runtime_hits")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        entry.insert(
            "static_hits".to_string(),
            Value::from(prev_s.saturating_add(static_hits)),
        );
        entry.insert(
            "runtime_hits".to_string(),
            Value::from(prev_r.saturating_add(runtime_hits)),
        );
    }
}

fn measure_scenario_run(
    root: &Path,
    naux_bin: &Path,
    pin_cmd: &Option<Vec<String>>,
    args: &Args,
    sc: &Scenario,
    src: &str,
    reps: i64,
) -> Result<(Vec<Value>, FusionHits), String> {
    let td = tempdir().map_err(|e| format!("tempdir failed: {e}"))?;
    let mut points = Vec::<Value>::new();
    let mut fusion_hits: FusionHits = BTreeMap::new();
    for n in sc.n_values {
        let nx_src = replace_first_int_assignment(src, "n", *n)?;
        let nx_path = td.path().join(format!("{}_{}.nx", sc.name, n));
        fs::write(&nx_path, nx_src)
            .map_err(|e| format!("failed write temp nx {}: {e}", nx_path.display()))?;
        let j = bench_json(
            root,
            naux_bin,
            pin_cmd,
            &args.engine,
            &nx_path,
            sc.mode,
            sc.iters,
            sc.warmup_ms,
        )?;
        merge_fusion_hits(&mut fusion_hits, &j);
        let t_ns = if sc.mode == "trace" {
            j.get("median_ns").and_then(|v| v.as_f64()).unwrap_or(0.0)
        } else {
            j.get("compute_median_ns")
                .or_else(|| j.get("median_ns"))
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0)
        };
        let elems = if let Some(expr) = sc.element_formula {
            eval_elements_formula(expr, *n, reps)?
        } else if sc.mode == "trace" {
            let from_json = j
                .get("median_elements")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            if from_json > 0.0 {
                from_json
            } else {
                (*n as f64) * (reps as f64)
            }
        } else {
            let avx = j
                .get("avx_dot_elements_total")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let interp = j
                .get("interp_index_elements_total")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let it = j
                .get("iters")
                .and_then(|v| v.as_f64())
                .unwrap_or(1.0)
                .max(1.0);
            (avx + interp) / it
        };
        points.push(json!({
            "n": n,
            "time_ns": t_ns,
            "elements": elems,
            "ns_per_elem": if elems > 0.0 { Some(t_ns / elems) } else { None::<f64> },
        }));
    }
    Ok((points, fusion_hits))
}

fn merge_fusion_hits(into: &mut BTreeMap<String, Map<String, Value>>, payload: &Value) {
    if let Some(arr) = payload
        .get("fusion_hits_by_rule")
        .and_then(|v| v.as_array())
    {
        for raw in arr {
            let rule = raw
                .get("rule")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if rule.is_empty() {
                continue;
            }
            let static_hits = raw.get("static_hits").and_then(|v| v.as_u64()).unwrap_or(0);
            let runtime_hits = raw
                .get("runtime_hits")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let entry = into.entry(rule).or_insert_with(|| {
                let mut m = Map::new();
                m.insert("static_hits".to_string(), Value::from(0u64));
                m.insert("runtime_hits".to_string(), Value::from(0u64));
                m
            });
            let prev_s = entry
                .get("static_hits")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let prev_r = entry
                .get("runtime_hits")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            entry.insert(
                "static_hits".to_string(),
                Value::from(prev_s.saturating_add(static_hits)),
            );
            entry.insert(
                "runtime_hits".to_string(),
                Value::from(prev_r.saturating_add(runtime_hits)),
            );
        }
    }
}

fn main() {
    let args = Args::parse();
    let rc = if let Err(e) = run(args) {
        eprintln!("[slope-gate-rs] {e}");
        1
    } else {
        0
    };
    std::process::exit(rc);
}

fn run(args: Args) -> Result<(), String> {
    let root = args
        .root
        .canonicalize()
        .map_err(|e| format!("invalid --root: {e}"))?;
    let naux_bin = if args.naux_bin.is_absolute() {
        args.naux_bin.clone()
    } else {
        root.join(&args.naux_bin)
    }
    .canonicalize()
    .map_err(|e| format!("invalid --naux-bin: {e}"))?;

    let baseline_path = root.join(&args.slope_baseline);
    let fusion_expectations_path = root.join(&args.fusion_expectations);
    let out_json = root.join(&args.out_json);
    let out_md = root.join(&args.out_md);
    if let Some(parent) = out_json.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("failed create out-json dir: {e}"))?;
    }
    if let Some(parent) = out_md.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("failed create out-md dir: {e}"))?;
    }

    let input_report_path = if let Some(p) = &args.input_report {
        let p = if p.is_absolute() {
            p.clone()
        } else {
            root.join(p)
        };
        let cp = p
            .canonicalize()
            .map_err(|e| format!("invalid --input-report {}: {e}", p.display()))?;
        Some(cp)
    } else {
        None
    };
    let mut input_report_scenarios: BTreeMap<String, Value> = BTreeMap::new();
    if let Some(p) = &input_report_path {
        let txt = fs::read_to_string(p)
            .map_err(|e| format!("failed to read input report {}: {e}", p.display()))?;
        let raw: Value = serde_json::from_str(&txt)
            .map_err(|e| format!("invalid input report JSON {}: {e}", p.display()))?;
        if let Some(arr) = raw.get("scenarios").and_then(|v| v.as_array()) {
            for sc in arr {
                let Some(name) = sc.get("name").and_then(|v| v.as_str()).map(str::trim) else {
                    continue;
                };
                if name.is_empty() {
                    continue;
                }
                input_report_scenarios.insert(name.to_string(), sc.clone());
            }
        }
    }

    let pin_cmd = if Command::new("taskset").arg("--help").output().is_ok() {
        Some(vec![
            "taskset".to_string(),
            "-c".to_string(),
            args.cpu_core.to_string(),
        ])
    } else {
        None
    };

    let scenarios = vec![
        Scenario {
            name: "dot_runtime_only",
            template: root.join("naux-lang/examples/bench_dot_product.nx"),
            mode: "runtime",
            n_values: &[4096, 8192, 16384, 32768, 65536],
            iters: pick_override(args.dot_runtime_iters, args.default_iters.max(15)),
            warmup_ms: pick_override(args.dot_runtime_warmup_ms, args.default_warmup_ms),
            require_r2: args.min_r2,
            max_a_reg_pct: args.max_a_regression_pct,
            max_b_reg_pct: args.max_b_regression_pct,
            element_formula: Some("n*reps"),
        },
        Scenario {
            name: "dot_trace_only",
            template: root.join("naux-lang/examples/bench_dot_product.nx"),
            mode: "trace",
            n_values: &[1024, 2048, 4096, 8192, 16384, 32768, 65536],
            iters: pick_override(args.dot_trace_iters, args.default_iters.max(25)),
            warmup_ms: pick_override(args.dot_trace_warmup_ms, args.default_warmup_ms),
            require_r2: args.min_r2,
            max_a_reg_pct: args.max_a_regression_pct,
            max_b_reg_pct: args.max_b_regression_pct,
            element_formula: None,
        },
        Scenario {
            name: "map_heavy_read",
            template: root.join("naux-lang/examples/bench_map_get_wide_const.nx"),
            mode: "runtime",
            n_values: &[1000, 4000, 16000, 64000, 256000],
            iters: pick_override(args.map_runtime_iters, (args.default_iters / 2).max(12)),
            warmup_ms: pick_override(args.map_runtime_warmup_ms, args.default_warmup_ms),
            require_r2: args.min_r2,
            max_a_reg_pct: args.max_a_regression_pct,
            max_b_reg_pct: args.max_b_regression_pct,
            element_formula: Some("n*reps*2"),
        },
        Scenario {
            name: "map_guard_entry_heavy",
            template: root.join("naux-lang/examples/bench_map_guard_entry_wide.nx"),
            mode: "runtime",
            n_values: &[16, 64, 256, 1024, 2048],
            iters: pick_override(args.map_guard_entry_iters, (args.default_iters / 2).max(12)),
            warmup_ms: pick_override(args.map_guard_entry_warmup_ms, args.default_warmup_ms),
            require_r2: args.min_r2,
            max_a_reg_pct: args.max_a_regression_pct,
            max_b_reg_pct: args.max_b_regression_pct,
            element_formula: Some("n*reps*2"),
        },
        Scenario {
            name: "map_get_mul_acc",
            template: root.join("naux-lang/examples/bench_map_get_mul_acc.nx"),
            mode: "runtime",
            n_values: &[1000, 4000, 16000, 64000, 256000],
            iters: pick_override(args.map_get_mul_acc_iters, (args.default_iters / 2).max(12)),
            warmup_ms: pick_override(args.map_get_mul_acc_warmup_ms, args.default_warmup_ms),
            require_r2: args.min_r2,
            max_a_reg_pct: args.max_a_regression_pct,
            max_b_reg_pct: args.max_b_regression_pct,
            element_formula: Some("n*reps*2"),
        },
        Scenario {
            name: "map_get_cmp_branch",
            template: root.join("naux-lang/examples/bench_map_get_cmp_branch.nx"),
            mode: "runtime",
            n_values: &[1000, 4000, 16000, 64000, 256000],
            iters: pick_override(
                args.map_get_cmp_branch_iters,
                (args.default_iters / 2).max(12),
            ),
            warmup_ms: pick_override(args.map_get_cmp_branch_warmup_ms, args.default_warmup_ms),
            require_r2: args.min_r2,
            max_a_reg_pct: args.max_a_regression_pct,
            max_b_reg_pct: args.max_b_regression_pct,
            element_formula: Some("n*reps*2"),
        },
    ];

    let baseline = parse_baseline(&baseline_path)?;
    let nonblocking_scenarios: BTreeSet<String> = parse_csv_items(&args.nonblocking_scenarios)
        .into_iter()
        .collect();
    let required_expectation_scenarios =
        parse_csv_items(&args.require_fusion_expectation_scenarios);
    let mut fusion_expectations = BTreeMap::new();
    let mut fusion_expectation_error: Option<String> = None;

    if !args.disable_fusion_rule_gate {
        match load_fusion_expectations(&fusion_expectations_path) {
            Ok(cfg) => {
                let missing: Vec<String> = required_expectation_scenarios
                    .iter()
                    .filter(|s| !cfg.contains_key((*s).as_str()))
                    .cloned()
                    .collect();
                if !missing.is_empty() {
                    fusion_expectation_error = Some(format!(
                        "missing required fusion expectation scenarios: {}",
                        missing.join(",")
                    ));
                }
                fusion_expectations = cfg;
            }
            Err(e) => fusion_expectation_error = Some(e),
        }
    }

    let mut failed = false;
    let mut hard_failure_any = false;
    let mut retryable_failure_any = false;
    if fusion_expectation_error.is_some() {
        failed = true;
        hard_failure_any = true;
    }

    let mut report = json!({
        "meta": {
            "cpu_core": args.cpu_core,
            "engine": args.engine,
            "baseline": baseline_path.display().to_string(),
            "fusion_expectations": fusion_expectations_path.display().to_string(),
            "require_fusion_expectation_scenarios": required_expectation_scenarios,
            "nonblocking_scenarios": nonblocking_scenarios.iter().cloned().collect::<Vec<String>>(),
            "min_r2": args.min_r2,
            "max_a_regression_pct": args.max_a_regression_pct,
            "max_b_regression_pct": args.max_b_regression_pct,
            "instability_r2_margin": args.instability_r2_margin,
            "instability_a_overage_pct": args.instability_a_overage_pct,
            "instability_b_overage_pct": args.instability_b_overage_pct,
            "min_baseline_b_ns_for_gate": args.min_baseline_b_ns_for_gate,
            "trace_min_measurement_ns": args.trace_min_measurement_ns,
            "runtime_measure_runs": args.runtime_measure_runs,
            "runtime_trim_pct": args.runtime_trim_pct,
            "require_baseline": args.require_baseline,
            "fusion_rule_gate_enabled": !args.disable_fusion_rule_gate,
            "fusion_expectation_error": fusion_expectation_error,
            "input_report": input_report_path.as_ref().map(|p| p.display().to_string()),
            "baseline_fingerprint_file": args.baseline_fingerprint_file,
            "baseline_fingerprint_status": args.baseline_fingerprint_status,
            "baseline_fingerprint_notes": args.baseline_fingerprint_notes,
            "cpu_model": args.cpu_model,
        },
        "scenarios": []
    });

    let mut md_lines = vec![
        "# Slope Gate Report".to_string(),
        "".to_string(),
        format!("- baseline: `{}`", baseline_path.display()),
        format!("- fusion_expectations: `{}`", fusion_expectations_path.display()),
        format!("- cpu_core: `{}`", args.cpu_core),
        format!("- cpu_model: `{}`", if args.cpu_model.is_empty() { "unknown".to_string() } else { args.cpu_model.clone() }),
        format!("- engine: `{}`", args.engine),
        format!("- baseline_fingerprint_file: `{}`", if args.baseline_fingerprint_file.is_empty() { "n/a".to_string() } else { args.baseline_fingerprint_file.clone() }),
        format!("- baseline_fingerprint_status: `{}`", if args.baseline_fingerprint_status.is_empty() { "n/a".to_string() } else { args.baseline_fingerprint_status.clone() }),
        format!("- baseline_fingerprint_notes: `{}`", if args.baseline_fingerprint_notes.is_empty() { "none".to_string() } else { args.baseline_fingerprint_notes.clone() }),
        format!("- trace_min_measurement_ns: `{:.0}`", args.trace_min_measurement_ns),
        format!("- runtime_measure_runs: `{}`", args.runtime_measure_runs),
        format!("- runtime_trim_pct: `{:.2}`", args.runtime_trim_pct),
        "".to_string(),
        "| scenario | a (ns/elem) | b (ns) | R² | baseline a | baseline b | baseline R² | a regress % | b regress % | fusion required | fusion optional | fusion forbidden | fusion required hits | retry hint | gate |".to_string(),
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---|---|---|---|".to_string(),
    ];
    if let Some(err) = &fusion_expectation_error {
        md_lines.push("".to_string());
        md_lines.push(format!("- fusion_expectation_error: `{}`", err));
        md_lines.push("".to_string());
    }

    for sc in scenarios {
        if input_report_scenarios.is_empty() && !sc.template.exists() {
            failed = true;
            hard_failure_any = true;
            let msg = format!("missing template: {}", sc.template.display());
            report["scenarios"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name": sc.name, "error": msg}));
            md_lines.push(format!(
                "| {} | - | - | - | - | - | - | - | - | - | - | - | - | HARD | FAIL ({}) |",
                sc.name, msg
            ));
            continue;
        }

        let mut points = Vec::<Value>::new();
        let mut fusion_hits: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
        let mut measurement_runs = Vec::<MeasurementRun>::new();
        let mut runtime_robust_applied = false;
        let mut runtime_good_runs = 0usize;
        let mut runtime_insufficient_good_runs = false;
        let mut runtime_consistent_a_regression = false;
        let mut runtime_consistent_b_regression = false;
        let mut aggregated_fit: Option<AggregatedFit> = None;
        let mut src_text = String::new();
        let mut reps = 1_i64;
        if !input_report_scenarios.is_empty() {
            let Some(src_sc) = input_report_scenarios.get(sc.name) else {
                failed = true;
                hard_failure_any = true;
                let msg = format!("missing scenario '{}' in input report", sc.name);
                report["scenarios"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"name": sc.name, "error": msg}));
                md_lines.push(format!(
                    "| {} | - | - | - | - | - | - | - | - | - | - | - | - | HARD | FAIL ({}) |",
                    sc.name, msg
                ));
                continue;
            };
            let Some(src_points) = src_sc.get("points").and_then(|v| v.as_array()) else {
                failed = true;
                hard_failure_any = true;
                let msg = format!("invalid points for scenario '{}' in input report", sc.name);
                report["scenarios"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"name": sc.name, "error": msg}));
                md_lines.push(format!(
                    "| {} | - | - | - | - | - | - | - | - | - | - | - | - | HARD | FAIL ({}) |",
                    sc.name, msg
                ));
                continue;
            };
            for p in src_points {
                let n = p.get("n").and_then(|v| v.as_f64()).unwrap_or(0.0) as i64;
                let t_ns = p.get("time_ns").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let elems = p.get("elements").and_then(|v| v.as_f64()).unwrap_or(0.0);
                points.push(json!({
                    "n": n,
                    "time_ns": t_ns,
                    "elements": elems,
                    "ns_per_elem": if elems > 0.0 { Some(t_ns / elems) } else { None::<f64> },
                }));
            }
            match src_sc.get("fusion_hits_by_rule") {
                Some(Value::Object(map)) => {
                    for (rule, stat_v) in map {
                        let Some(stat_obj) = stat_v.as_object() else {
                            continue;
                        };
                        let static_hits = stat_obj
                            .get("static_hits")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let runtime_hits = stat_obj
                            .get("runtime_hits")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let mut m = Map::new();
                        m.insert("static_hits".to_string(), Value::from(static_hits));
                        m.insert("runtime_hits".to_string(), Value::from(runtime_hits));
                        fusion_hits.insert(rule.clone(), m);
                    }
                }
                Some(Value::Array(arr)) => {
                    let payload = json!({ "fusion_hits_by_rule": arr });
                    merge_fusion_hits(&mut fusion_hits, &payload);
                }
                _ => {}
            }
            if let Some(arr) = src_sc.get("measurement_runs").and_then(|v| v.as_array()) {
                for run in arr {
                    if let Ok(parsed) = serde_json::from_value::<MeasurementRun>(run.clone()) {
                        measurement_runs.push(parsed);
                    }
                }
            }
            if let Some(raw_fit) = src_sc.get("aggregated_fit") {
                if let Ok(parsed) = serde_json::from_value::<AggregatedFit>(raw_fit.clone()) {
                    aggregated_fit = Some(parsed);
                }
            }
            runtime_robust_applied = src_sc
                .get("runtime_robust_applied")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            runtime_good_runs = src_sc
                .get("runtime_good_runs")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            runtime_insufficient_good_runs = src_sc
                .get("runtime_insufficient_good_runs")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            runtime_consistent_a_regression = src_sc
                .get("runtime_consistent_a_regression")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            runtime_consistent_b_regression = src_sc
                .get("runtime_consistent_b_regression")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
        } else {
            src_text = fs::read_to_string(&sc.template)
                .map_err(|e| format!("failed reading template {}: {e}", sc.template.display()))?;
            reps = parse_first_int_assignment(&src_text, "reps").unwrap_or(1);
            let (initial_points, initial_hits) =
                measure_scenario_run(&root, &naux_bin, &pin_cmd, &args, &sc, &src_text, reps)?;
            points = initial_points;
            fusion_hits = initial_hits;
        }

        if points.len() < 2 {
            failed = true;
            hard_failure_any = true;
            let msg = format!("need at least 2 points for scenario '{}'", sc.name);
            report["scenarios"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name": sc.name, "error": msg}));
            md_lines.push(format!(
                "| {} | - | - | - | - | - | - | - | - | - | - | - | - | HARD | FAIL ({}) |",
                sc.name, msg
            ));
            continue;
        }

        let xs: Vec<f64> = points
            .iter()
            .filter_map(|p| p.get("elements").and_then(|v| v.as_f64()))
            .collect();
        let ys: Vec<f64> = points
            .iter()
            .filter_map(|p| p.get("time_ns").and_then(|v| v.as_f64()))
            .collect();
        let mut max_point_ns = max_point_time_ns(&points);
        let short_trace_retryable =
            short_trace_measurement_retryable(sc.mode, &points, args.trace_min_measurement_ns);
        let base = baseline.get(sc.name);
        let (mut a, mut b, mut r2) = if let Some(fit) = &aggregated_fit {
            (fit.a_ns_per_elem, fit.b_ns, fit.r2)
        } else {
            linear_fit(&xs, &ys)?
        };
        if measurement_runs.is_empty() {
            measurement_runs.push(MeasurementRun {
                a_ns_per_elem: a,
                b_ns: b,
                r2,
                max_point_time_ns: max_point_ns,
            });
        }
        if aggregated_fit.is_none() && sc.mode == "runtime" && args.runtime_measure_runs > 1 {
            let mut potential_measurement_fail = false;
            if let Some(base) = base {
                let a_reg_probe = rel_regression_pct(a, base.a_ns_per_elem);
                let b_reg_probe = rel_regression_pct(b, base.b_ns);
                let b_regressed = base.b_ns.abs() >= args.min_baseline_b_ns_for_gate
                    && b_reg_probe > sc.max_b_reg_pct;
                if r2 < sc.require_r2 || a_reg_probe > sc.max_a_reg_pct || b_regressed {
                    potential_measurement_fail = true;
                } else if base.r2 > 0.0 {
                    let r2_drop_limit = sc.require_r2.min(base.r2 - 0.01);
                    if (r2_drop_limit - (r2 + 0.0001)) > 0.0 {
                        potential_measurement_fail = true;
                    }
                }
            } else if args.require_baseline {
                potential_measurement_fail = true;
            }

            if potential_measurement_fail {
                runtime_robust_applied = true;
                let mut all_run_points = vec![points.clone()];
                for _ in 1..args.runtime_measure_runs {
                    let (extra_points, extra_hits) = measure_scenario_run(
                        &root, &naux_bin, &pin_cmd, &args, &sc, &src_text, reps,
                    )?;
                    let xs_extra: Vec<f64> = extra_points
                        .iter()
                        .filter_map(|p| p.get("elements").and_then(|v| v.as_f64()))
                        .collect();
                    let ys_extra: Vec<f64> = extra_points
                        .iter()
                        .filter_map(|p| p.get("time_ns").and_then(|v| v.as_f64()))
                        .collect();
                    let (a_extra, b_extra, r2_extra) = linear_fit(&xs_extra, &ys_extra)?;
                    measurement_runs.push(MeasurementRun {
                        a_ns_per_elem: a_extra,
                        b_ns: b_extra,
                        r2: r2_extra,
                        max_point_time_ns: max_point_time_ns(&extra_points),
                    });
                    merge_fusion_hit_maps(&mut fusion_hits, &extra_hits);
                    all_run_points.push(extra_points);
                }

                let good_indices: Vec<usize> = measurement_runs
                    .iter()
                    .enumerate()
                    .filter_map(|(idx, run)| (run.r2 >= sc.require_r2).then_some(idx))
                    .collect();
                runtime_good_runs = good_indices.len();
                let selected_indices: Vec<usize> = if runtime_good_runs >= 2 {
                    good_indices.clone()
                } else {
                    runtime_insufficient_good_runs = true;
                    (0..measurement_runs.len()).collect()
                };
                let selected_runs: Vec<MeasurementRun> = selected_indices
                    .iter()
                    .map(|idx| measurement_runs[*idx].clone())
                    .collect();
                let a_vals: Vec<f64> = selected_runs.iter().map(|run| run.a_ns_per_elem).collect();
                let b_vals: Vec<f64> = selected_runs.iter().map(|run| run.b_ns).collect();
                let r2_vals: Vec<f64> = selected_runs.iter().map(|run| run.r2).collect();
                a = trimmed_median(&a_vals, args.runtime_trim_pct);
                b = trimmed_median(&b_vals, args.runtime_trim_pct);
                r2 = trimmed_median(&r2_vals, args.runtime_trim_pct);
                let rep_idx = representative_run_index(&selected_runs, a, b, r2);
                if let Some(original_idx) = selected_indices.get(rep_idx) {
                    points = all_run_points[*original_idx].clone();
                    max_point_ns = max_point_time_ns(&points);
                }
                aggregated_fit = Some(AggregatedFit {
                    a_ns_per_elem: a,
                    b_ns: b,
                    r2,
                });
                if let Some(base) = base {
                    if good_indices.len() >= 2 {
                        runtime_consistent_a_regression = good_indices.iter().all(|idx| {
                            rel_regression_pct(
                                measurement_runs[*idx].a_ns_per_elem,
                                base.a_ns_per_elem,
                            ) > sc.max_a_reg_pct
                        });
                        if base.b_ns.abs() >= args.min_baseline_b_ns_for_gate {
                            runtime_consistent_b_regression = good_indices.iter().all(|idx| {
                                rel_regression_pct(measurement_runs[*idx].b_ns, base.b_ns)
                                    > sc.max_b_reg_pct
                            });
                        }
                    }
                }
            }
        }
        let mut a_reg: Option<f64> = None;
        let mut b_reg: Option<f64> = None;
        let mut hard_reasons = Vec::<String>::new();
        let mut retryable_reasons = Vec::<String>::new();

        let mut add_failure = |reason: String, retryable: bool| {
            if retryable {
                retryable_reasons.push(reason);
            } else {
                hard_reasons.push(reason);
            }
        };
        let runtime_r2_retryable = runtime_robust_applied && runtime_insufficient_good_runs;

        if r2 < sc.require_r2 {
            let r2_over = sc.require_r2 - r2;
            add_failure(
                format!("R2<{}", sc.require_r2),
                short_trace_retryable
                    || runtime_r2_retryable
                    || r2_over <= args.instability_r2_margin,
            );
        }

        if let Some(base) = base {
            a_reg = Some(rel_regression_pct(a, base.a_ns_per_elem));
            b_reg = Some(rel_regression_pct(b, base.b_ns));
            if let Some(ar) = a_reg {
                if ar > sc.max_a_reg_pct {
                    add_failure(
                        format!("a regress {:.2}% > {:.2}%", ar, sc.max_a_reg_pct),
                        short_trace_retryable
                            || (runtime_robust_applied && !runtime_consistent_a_regression)
                            || (ar - sc.max_a_reg_pct) <= args.instability_a_overage_pct,
                    );
                }
            }
            if base.b_ns.abs() >= args.min_baseline_b_ns_for_gate {
                if let Some(br) = b_reg {
                    if br > sc.max_b_reg_pct {
                        add_failure(
                            format!("b regress {:.2}% > {:.2}%", br, sc.max_b_reg_pct),
                            short_trace_retryable
                                || (runtime_robust_applied && !runtime_consistent_b_regression)
                                || (br - sc.max_b_reg_pct) <= args.instability_b_overage_pct,
                        );
                    }
                }
            }
            if base.r2 > 0.0 {
                let r2_drop_limit = sc.require_r2.min(base.r2 - 0.01);
                let r2_drop_over = r2_drop_limit - (r2 + 0.0001);
                if r2_drop_over > 0.0 {
                    add_failure(
                        format!("R2 drop {:.4} vs baseline {:.4}", r2, base.r2),
                        short_trace_retryable
                            || runtime_r2_retryable
                            || r2_drop_over <= args.instability_r2_margin,
                    );
                }
            }
        } else if args.require_baseline {
            add_failure("missing baseline".to_string(), false);
        }

        let expectation = if args.disable_fusion_rule_gate {
            FusionExpectation {
                required: Vec::new(),
                optional: Vec::new(),
                forbidden: Vec::new(),
            }
        } else {
            fusion_expectations
                .get(sc.name)
                .cloned()
                .unwrap_or(FusionExpectation {
                    required: Vec::new(),
                    optional: Vec::new(),
                    forbidden: Vec::new(),
                })
        };

        if !args.disable_fusion_rule_gate {
            let missing: Vec<String> = expectation
                .required
                .iter()
                .filter(|rule| {
                    fusion_hits
                        .get((*rule).as_str())
                        .and_then(|m| m.get("runtime_hits"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                        == 0
                })
                .cloned()
                .collect();
            if !missing.is_empty() {
                add_failure(
                    format!("missing fusion runtime hits: {}", missing.join(",")),
                    false,
                );
            }
            let forbidden_hit: Vec<String> = expectation
                .forbidden
                .iter()
                .filter(|rule| {
                    fusion_hits
                        .get((*rule).as_str())
                        .and_then(|m| m.get("runtime_hits"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                        > 0
                })
                .cloned()
                .collect();
            if !forbidden_hit.is_empty() {
                add_failure(
                    format!("forbidden fusion rules hit: {}", forbidden_hit.join(",")),
                    false,
                );
            }
        }

        let mut all_reasons = hard_reasons.clone();
        all_reasons.extend(retryable_reasons.clone());
        let is_nonblocking = nonblocking_scenarios.contains(sc.name);
        let scenario_failed = !all_reasons.is_empty();
        let scenario_retryable = scenario_failed && hard_reasons.is_empty();
        let mut gate = if scenario_failed {
            format!("FAIL ({})", all_reasons.join("; "))
        } else {
            "PASS".to_string()
        };
        if scenario_failed && is_nonblocking {
            gate = format!("OBSERVE ({})", all_reasons.join("; "));
        }

        if scenario_failed && !is_nonblocking {
            failed = true;
            if scenario_retryable {
                retryable_failure_any = true;
            } else {
                hard_failure_any = true;
            }
        }
        let retry_hint = if scenario_failed && is_nonblocking {
            "OBSERVE"
        } else if scenario_retryable {
            "RETRYABLE"
        } else if scenario_failed {
            "HARD"
        } else {
            "-"
        };

        let fusion_hits_json: Map<String, Value> = fusion_hits
            .iter()
            .map(|(k, v)| (k.clone(), Value::Object(v.clone())))
            .collect();

        report["scenarios"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "name": sc.name,
                "mode": sc.mode,
                "points": points,
                "a_ns_per_elem": a,
                "b_ns": b,
                "r2": r2,
                "max_point_time_ns": max_point_ns,
                "short_trace_measurement_retryable": short_trace_retryable,
                "runtime_robust_applied": runtime_robust_applied,
                "runtime_good_runs": runtime_good_runs,
                "runtime_insufficient_good_runs": runtime_insufficient_good_runs,
                "runtime_consistent_a_regression": runtime_consistent_a_regression,
                "runtime_consistent_b_regression": runtime_consistent_b_regression,
                "measurement_runs": measurement_runs,
                "aggregated_fit": aggregated_fit,
                "baseline": base.map(|x| json!({"a_ns_per_elem": x.a_ns_per_elem, "b_ns": x.b_ns, "r2": x.r2})),
                "a_regression_pct": a_reg,
                "b_regression_pct": b_reg,
                "fusion_required_rules": expectation.required,
                "fusion_optional_rules": expectation.optional,
                "fusion_forbidden_rules": expectation.forbidden,
                "fusion_hits_by_rule": fusion_hits_json,
                "retryable_failure_reasons": retryable_reasons,
                "hard_failure_reasons": hard_reasons,
                "retry_recommended": scenario_retryable && !is_nonblocking,
                "nonblocking": is_nonblocking,
                "gate": gate,
            }));

        let ba = base
            .map(|x| format!("{:.6}", x.a_ns_per_elem))
            .unwrap_or_else(|| "-".to_string());
        let bb = base
            .map(|x| format!("{:.3}", x.b_ns))
            .unwrap_or_else(|| "-".to_string());
        let br = base
            .map(|x| format!("{:.4}", x.r2))
            .unwrap_or_else(|| "-".to_string());

        let fusion_required_md = if expectation.required.is_empty() {
            "-".to_string()
        } else {
            expectation.required.join(",")
        };
        let fusion_optional_md = if expectation.optional.is_empty() {
            "-".to_string()
        } else {
            expectation.optional.join(",")
        };
        let fusion_forbidden_md = if expectation.forbidden.is_empty() {
            "-".to_string()
        } else {
            expectation.forbidden.join(",")
        };
        let fusion_required_runtime_md = if expectation.required.is_empty() {
            "-".to_string()
        } else {
            expectation
                .required
                .iter()
                .map(|rule| {
                    let hits = fusion_hits
                        .get(rule)
                        .and_then(|m| m.get("runtime_hits"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    format!("{}:{}", rule, hits)
                })
                .collect::<Vec<_>>()
                .join(",")
        };

        md_lines.push(format!(
            "| {} | {:.6} | {:.3} | {:.4} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            sc.name,
            a,
            b,
            r2,
            ba,
            bb,
            br,
            a_reg
                .map(|v| format!("{:.2}", v))
                .unwrap_or_else(|| "-".to_string()),
            b_reg
                .map(|v| format!("{:.2}", v))
                .unwrap_or_else(|| "-".to_string()),
            fusion_required_md,
            fusion_optional_md,
            fusion_forbidden_md,
            fusion_required_runtime_md,
            retry_hint,
            gate,
        ));
    }

    let retry_recommended = failed && retryable_failure_any && !hard_failure_any;
    let retry_class = if !failed {
        "pass"
    } else if retry_recommended {
        "retryable"
    } else {
        "hard"
    };
    report["retry_recommended"] = Value::Bool(retry_recommended);
    report["retry_class"] = Value::String(retry_class.to_string());

    md_lines.push("".to_string());
    md_lines.push(format!("- retry_class: `{}`", retry_class));
    md_lines.push(format!(
        "- retry_recommended: `{}`",
        if retry_recommended { "true" } else { "false" }
    ));

    let report_txt =
        serde_json::to_string_pretty(&report).map_err(|e| format!("json serialize failed: {e}"))?;
    fs::write(&out_json, report_txt).map_err(|e| format!("write out-json failed: {e}"))?;
    fs::write(&out_md, format!("{}\n", md_lines.join("\n")))
        .map_err(|e| format!("write out-md failed: {e}"))?;

    if failed {
        if retry_recommended {
            println!("[slope-gate] FAILED (instability-retry-recommended)");
        } else {
            println!("[slope-gate] FAILED");
        }
        let md = fs::read_to_string(&out_md).unwrap_or_default();
        println!("{md}");
        std::process::exit(if retry_recommended { 2 } else { 1 });
    }

    println!("[slope-gate] PASS");
    let md = fs::read_to_string(&out_md).unwrap_or_default();
    println!("{md}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(time_ns: f64) -> Value {
        json!({
            "n": 1,
            "time_ns": time_ns,
            "elements": 1.0,
            "ns_per_elem": time_ns,
        })
    }

    #[test]
    fn short_trace_measurement_is_retryable() {
        let points = vec![point(138.0), point(883.0), point(6596.0)];
        assert!(short_trace_measurement_retryable(
            "trace", &points, 50_000.0
        ));
    }

    #[test]
    fn runtime_measurement_does_not_trigger_short_trace_retryable() {
        let points = vec![point(138.0), point(883.0), point(6596.0)];
        assert!(!short_trace_measurement_retryable(
            "runtime", &points, 50_000.0
        ));
    }

    #[test]
    fn long_trace_measurement_stays_hard_gated() {
        let points = vec![point(60_000.0), point(90_000.0)];
        assert!(!short_trace_measurement_retryable(
            "trace", &points, 50_000.0
        ));
    }
}
