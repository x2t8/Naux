#!/usr/bin/env python3
import argparse
import json
import re
import shutil
import statistics
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class Scenario:
    name: str
    template: Path
    mode: str  # runtime|trace
    n_values: List[int]
    iters: int
    warmup_ms: int
    require_r2: float
    max_a_reg_pct: float
    max_b_reg_pct: float
    element_formula: Optional[str] = None  # map formulas use this


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run slope gates for Naux perf invariants")
    p.add_argument("--root", required=True)
    p.add_argument("--naux-bin", required=True)
    p.add_argument("--cpu-core", type=int, default=0)
    p.add_argument("--engine", default="jit")
    p.add_argument("--default-iters", type=int, default=25)
    p.add_argument("--default-warmup-ms", type=int, default=100)
    p.add_argument("--dot-runtime-iters", type=int, default=0)
    p.add_argument("--dot-runtime-warmup-ms", type=int, default=0)
    p.add_argument("--dot-trace-iters", type=int, default=0)
    p.add_argument("--dot-trace-warmup-ms", type=int, default=0)
    p.add_argument("--map-runtime-iters", type=int, default=0)
    p.add_argument("--map-runtime-warmup-ms", type=int, default=0)
    p.add_argument("--map-guard-entry-iters", type=int, default=0)
    p.add_argument("--map-guard-entry-warmup-ms", type=int, default=0)
    p.add_argument("--map-get-mul-acc-iters", type=int, default=0)
    p.add_argument("--map-get-mul-acc-warmup-ms", type=int, default=0)
    p.add_argument("--map-get-cmp-branch-iters", type=int, default=0)
    p.add_argument("--map-get-cmp-branch-warmup-ms", type=int, default=0)
    p.add_argument("--slope-baseline", default="benchmarks/perf_slope_baseline.tsv")
    p.add_argument("--min-r2", type=float, default=0.995)
    p.add_argument("--max-a-regression-pct", type=float, default=5.0)
    p.add_argument("--max-b-regression-pct", type=float, default=10.0)
    p.add_argument(
        "--instability-r2-margin",
        type=float,
        default=0.01,
        help="Treat R² failure as retryable when threshold miss is within this margin",
    )
    p.add_argument(
        "--instability-a-overage-pct",
        type=float,
        default=3.0,
        help="Treat a-regression failure as retryable when overage is within this percent",
    )
    p.add_argument(
        "--instability-b-overage-pct",
        type=float,
        default=5.0,
        help="Treat b-regression failure as retryable when overage is within this percent",
    )
    p.add_argument(
        "--min-baseline-b-ns-for-gate",
        type=float,
        default=100_000.0,
        help="Only enforce intercept regression gate when |baseline b| >= this threshold",
    )
    p.add_argument(
        "--trace-min-measurement-ns",
        type=float,
        default=50_000.0,
        help="Treat trace-mode slope failures as retryable when all measured points stay below this time",
    )
    p.add_argument(
        "--runtime-measure-runs",
        type=int,
        default=5,
        help="When a runtime slope scenario looks unstable or regressed, remeasure up to this many independent runs",
    )
    p.add_argument(
        "--runtime-trim-pct",
        type=float,
        default=0.2,
        help="Trim percentage used when aggregating runtime slope reruns",
    )
    p.add_argument("--require-baseline", action="store_true")
    p.add_argument(
        "--fusion-expectations",
        default="scripts/fusion_expectations.json",
        help="JSON file mapping scenario -> required/optional/forbidden fusion rules",
    )
    p.add_argument(
        "--require-fusion-expectation-scenarios",
        default="",
        help="Comma-separated scenario names that must exist in fusion expectation config when fusion gate is enabled",
    )
    p.add_argument(
        "--disable-fusion-rule-gate",
        action="store_true",
        help="Skip fusion rule hit assertions for map scenarios",
    )
    p.add_argument(
        "--nonblocking-scenarios",
        default="",
        help="Comma-separated scenarios to evaluate in observe mode (failures do not fail overall gate)",
    )
    p.add_argument(
        "--input-report",
        default="",
        help="Optional slope report JSON to replay (skip benchmark execution and reuse scenario points/fusion hits)",
    )
    p.add_argument("--baseline-fingerprint-file", default="")
    p.add_argument("--baseline-fingerprint-status", default="")
    p.add_argument("--baseline-fingerprint-notes", default="")
    p.add_argument("--cpu-model", default="")
    p.add_argument("--out-json", default="target/perf/slope_report.json")
    p.add_argument("--out-md", default="target/perf/slope_report.md")
    return p.parse_args()


def pick_override(value: int, fallback: int) -> int:
    return value if value > 0 else fallback


def replace_first_int_assignment(src: str, var: str, value: int) -> str:
    pat = re.compile(rf"^(\s*\${re.escape(var)}\s*=\s*)(\d+)(\s*)$", re.MULTILINE)
    m = pat.search(src)
    if not m:
        raise RuntimeError(f"cannot find assignment for ${var}")
    return src[: m.start()] + f"{m.group(1)}{value}{m.group(3)}" + src[m.end() :]


def parse_first_int_assignment(src: str, var: str) -> int:
    pat = re.compile(rf"^\s*\${re.escape(var)}\s*=\s*(\d+)\s*$", re.MULTILINE)
    m = pat.search(src)
    if not m:
        raise RuntimeError(f"cannot parse assignment for ${var}")
    return int(m.group(1))


def run_cmd(cmd: List[str], cwd: Path) -> str:
    p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(
            f"command failed rc={p.returncode}: {' '.join(cmd)}\nstdout:\n{p.stdout}\nstderr:\n{p.stderr}"
        )
    out = p.stdout.strip()
    if not out:
        raise RuntimeError(f"empty output: {' '.join(cmd)}")
    return out


def bench_json(
    root: Path,
    naux_bin: Path,
    pin_cmd: Optional[List[str]],
    engine: str,
    nx_path: Path,
    mode: str,
    iters: int,
    warmup_ms: int,
) -> Dict:
    cmd: List[str] = []
    if pin_cmd:
        cmd.extend(pin_cmd)
    cmd.extend(
        [
            str(naux_bin),
            "dev",
            "benchrt",
            str(nx_path),
            f"--engine={engine}",
            f"--iters={iters}",
            f"--warmup-ms={warmup_ms}",
            "--json",
        ]
    )
    if mode == "trace":
        cmd.insert(-1, "--trace-only")
    out = run_cmd(cmd, root)
    try:
        return json.loads(out)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"invalid JSON from benchrt for {nx_path}: {e}\n{out}")


def linear_fit(xs: List[float], ys: List[float]) -> Tuple[float, float, float]:
    n = len(xs)
    if n < 2:
        raise RuntimeError("need at least 2 points")
    mx = sum(xs) / n
    my = sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        raise RuntimeError("degenerate x values")
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    a = sxy / sxx
    b = my - a * mx
    yhat = [a * x + b for x in xs]
    ss_res = sum((y - yh) ** 2 for y, yh in zip(ys, yhat))
    ss_tot = sum((y - my) ** 2 for y in ys)
    r2 = 1.0 if ss_tot == 0 else 1.0 - (ss_res / ss_tot)
    return a, b, r2


def parse_baseline(path: Path) -> Dict[str, Tuple[float, float, float]]:
    out: Dict[str, Tuple[float, float, float]] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        out[parts[0]] = (float(parts[1]), float(parts[2]), float(parts[3]))
    return out


def rel_regression_pct(new: float, base: float) -> float:
    if base == 0:
        return 0.0 if new == 0 else 10_000.0
    return ((new - base) / abs(base)) * 100.0


def max_point_time_ns(points: List[Dict]) -> float:
    return max((float(p.get("time_ns", 0.0) or 0.0) for p in points), default=0.0)


def short_trace_measurement_retryable(mode: str, points: List[Dict], trace_min_measurement_ns: float) -> bool:
    return mode == "trace" and max_point_time_ns(points) < trace_min_measurement_ns


def trimmed_median(samples: List[float], trim_pct: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(float(x) for x in samples)
    trim = int(len(ordered) * trim_pct)
    if trim > 0 and (len(ordered) - (2 * trim)) >= 1:
        ordered = ordered[trim: len(ordered) - trim]
    return float(statistics.median(ordered))


def representative_run_index(
    runs: List[Dict[str, object]], agg_a: float, agg_b: float, agg_r2: float
) -> int:
    def score(run: Dict[str, object]) -> Tuple[float, float, float]:
        a = float(run["a_ns_per_elem"])
        b = float(run["b_ns"])
        r2 = float(run["r2"])
        a_scale = max(abs(agg_a), 1e-9)
        b_scale = max(abs(agg_b), 1.0)
        return (
            abs(a - agg_a) / a_scale,
            abs(b - agg_b) / b_scale,
            abs(r2 - agg_r2),
        )

    return min(range(len(runs)), key=lambda idx: score(runs[idx]))


def eval_elements_formula(expr: str, n: int, reps: int) -> float:
    rendered = expr.replace("reps", str(reps)).replace("n", str(n))
    if not re.fullmatch(r"[0-9+\-*/().\s]+", rendered):
        raise RuntimeError(f"unsafe element formula: {expr}")
    try:
        value = eval(rendered, {"__builtins__": {}}, {})
    except Exception as e:
        raise RuntimeError(f"failed to eval element formula '{expr}': {e}") from e
    value_f = float(value)
    if value_f <= 0:
        raise RuntimeError(f"element formula must be > 0, got {value_f} for {expr}")
    return value_f


def merge_fusion_hits(into: Dict[str, Dict[str, int]], payload: Dict) -> None:
    for raw in payload.get("fusion_hits_by_rule", []):
        rule = str(raw.get("rule", "")).strip()
        if not rule:
            continue
        static_hits = int(raw.get("static_hits", 0) or 0)
        runtime_hits = int(raw.get("runtime_hits", 0) or 0)
        cur = into.setdefault(rule, {"static_hits": 0, "runtime_hits": 0})
        cur["static_hits"] += static_hits
        cur["runtime_hits"] += runtime_hits


def parse_csv_items(raw: str) -> List[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def unique_rules(rules: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for rule in rules:
        if rule in seen:
            continue
        seen.add(rule)
        out.append(rule)
    return out


def normalize_rules(raw: object, context: str) -> List[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise RuntimeError(f"{context} must be a list of strings")
    rules: List[str] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, str) or not item.strip():
            raise RuntimeError(f"{context}[{idx}] must be a non-empty string")
        rules.append(item.strip())
    return unique_rules(rules)


def parse_expectation_entry(scenario: str, raw: object) -> Dict[str, List[str]]:
    if isinstance(raw, list):
        return {
            "required": normalize_rules(raw, f"{scenario}.required"),
            "optional": [],
            "forbidden": [],
        }
    if not isinstance(raw, dict):
        raise RuntimeError(
            f"fusion expectation for scenario '{scenario}' must be either a list or an object with required/optional/forbidden"
        )
    unknown = set(raw.keys()) - {"required", "optional", "forbidden"}
    if unknown:
        raise RuntimeError(f"fusion expectation for scenario '{scenario}' has unknown keys: {', '.join(sorted(unknown))}")
    return {
        "required": normalize_rules(raw.get("required"), f"{scenario}.required"),
        "optional": normalize_rules(raw.get("optional"), f"{scenario}.optional"),
        "forbidden": normalize_rules(raw.get("forbidden"), f"{scenario}.forbidden"),
    }


def load_fusion_expectations(path: Path) -> Dict[str, Dict[str, List[str]]]:
    if not path.exists():
        raise RuntimeError(f"fusion expectation config not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"invalid fusion expectation JSON at {path}: {e}") from e
    if not isinstance(raw, dict):
        raise RuntimeError(f"fusion expectation config must be a JSON object: {path}")
    out: Dict[str, Dict[str, List[str]]] = {}
    for scenario, entry in raw.items():
        if not isinstance(scenario, str) or not scenario.strip():
            raise RuntimeError("fusion expectation keys must be non-empty scenario names")
        out[scenario.strip()] = parse_expectation_entry(scenario.strip(), entry)
    return out


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    naux_bin = Path(args.naux_bin).resolve()
    baseline_path = (root / args.slope_baseline).resolve()
    fusion_expectations_path = (root / args.fusion_expectations).resolve()
    out_json = (root / args.out_json).resolve()
    out_md = (root / args.out_md).resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    pin_cmd: Optional[List[str]] = None
    if shutil.which("taskset"):
        pin_cmd = ["taskset", "-c", str(args.cpu_core)]
    input_report_path: Optional[Path] = None
    input_report_scenarios: Dict[str, Dict] = {}
    if args.input_report:
        input_report_path = (root / args.input_report).resolve()
        if not input_report_path.exists():
            raise RuntimeError(f"input report not found: {input_report_path}")
        raw = json.loads(input_report_path.read_text(encoding="utf-8"))
        for sc in raw.get("scenarios", []):
            if not isinstance(sc, dict):
                continue
            name = str(sc.get("name", "")).strip()
            if not name:
                continue
            input_report_scenarios[name] = sc

    scenarios = [
        Scenario(
            name="dot_runtime_only",
            template=root / "naux-lang/examples/bench_dot_product.nx",
            mode="runtime",
            n_values=[4096, 8192, 16384, 32768, 65536],
            iters=pick_override(args.dot_runtime_iters, max(15, args.default_iters)),
            warmup_ms=pick_override(args.dot_runtime_warmup_ms, args.default_warmup_ms),
            require_r2=args.min_r2,
            max_a_reg_pct=args.max_a_regression_pct,
            max_b_reg_pct=args.max_b_regression_pct,
            element_formula="n*reps",
        ),
        Scenario(
            name="dot_trace_only",
            template=root / "naux-lang/examples/bench_dot_product.nx",
            mode="trace",
            n_values=[1024, 2048, 4096, 8192, 16384, 32768, 65536],
            iters=pick_override(args.dot_trace_iters, max(25, args.default_iters)),
            warmup_ms=pick_override(args.dot_trace_warmup_ms, args.default_warmup_ms),
            require_r2=args.min_r2,
            max_a_reg_pct=args.max_a_regression_pct,
            max_b_reg_pct=args.max_b_regression_pct,
        ),
        Scenario(
            name="map_heavy_read",
            template=root / "naux-lang/examples/bench_map_get_wide_const.nx",
            mode="runtime",
            n_values=[1000, 4000, 16000, 64000, 256000],
            iters=pick_override(args.map_runtime_iters, max(12, args.default_iters // 2)),
            warmup_ms=pick_override(args.map_runtime_warmup_ms, args.default_warmup_ms),
            require_r2=args.min_r2,
            max_a_reg_pct=args.max_a_regression_pct,
            max_b_reg_pct=args.max_b_regression_pct,
            element_formula="n*reps*2",
        ),
        Scenario(
            name="map_guard_entry_heavy",
            template=root / "naux-lang/examples/bench_map_guard_entry_wide.nx",
            mode="runtime",
            n_values=[16, 64, 256, 1024, 2048],
            iters=pick_override(args.map_guard_entry_iters, max(12, args.default_iters // 2)),
            warmup_ms=pick_override(args.map_guard_entry_warmup_ms, args.default_warmup_ms),
            require_r2=args.min_r2,
            max_a_reg_pct=args.max_a_regression_pct,
            max_b_reg_pct=args.max_b_regression_pct,
            element_formula="n*reps*2",
        ),
        Scenario(
            name="map_get_mul_acc",
            template=root / "naux-lang/examples/bench_map_get_mul_acc.nx",
            mode="runtime",
            n_values=[1000, 4000, 16000, 64000, 256000],
            iters=pick_override(args.map_get_mul_acc_iters, max(12, args.default_iters // 2)),
            warmup_ms=pick_override(args.map_get_mul_acc_warmup_ms, args.default_warmup_ms),
            require_r2=args.min_r2,
            max_a_reg_pct=args.max_a_regression_pct,
            max_b_reg_pct=args.max_b_regression_pct,
            element_formula="n*reps*2",
        ),
        Scenario(
            name="map_get_cmp_branch",
            template=root / "naux-lang/examples/bench_map_get_cmp_branch.nx",
            mode="runtime",
            n_values=[1000, 4000, 16000, 64000, 256000],
            iters=pick_override(args.map_get_cmp_branch_iters, max(12, args.default_iters // 2)),
            warmup_ms=pick_override(args.map_get_cmp_branch_warmup_ms, args.default_warmup_ms),
            require_r2=args.min_r2,
            max_a_reg_pct=args.max_a_regression_pct,
            max_b_reg_pct=args.max_b_regression_pct,
            element_formula="n*reps*2",
        ),
    ]

    baseline = parse_baseline(baseline_path)
    nonblocking_scenarios = set(parse_csv_items(args.nonblocking_scenarios))
    required_expectation_scenarios = parse_csv_items(args.require_fusion_expectation_scenarios)
    fusion_expectations: Dict[str, Dict[str, List[str]]] = {}
    fusion_expectation_error: Optional[str] = None
    if not args.disable_fusion_rule_gate:
        try:
            fusion_expectations = load_fusion_expectations(fusion_expectations_path)
            missing_expected = [
                scenario for scenario in required_expectation_scenarios if scenario not in fusion_expectations
            ]
            if missing_expected:
                fusion_expectation_error = (
                    "missing required fusion expectation scenarios: " + ",".join(sorted(missing_expected))
                )
        except RuntimeError as e:
            fusion_expectation_error = str(e)

    failed = False
    hard_failure_any = False
    retryable_failure_any = False
    if fusion_expectation_error is not None:
        failed = True
        hard_failure_any = True
    report = {
        "meta": {
            "cpu_core": args.cpu_core,
            "engine": args.engine,
            "baseline": str(baseline_path),
            "fusion_expectations": str(fusion_expectations_path),
            "require_fusion_expectation_scenarios": required_expectation_scenarios,
            "nonblocking_scenarios": sorted(nonblocking_scenarios),
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
            "fusion_rule_gate_enabled": not args.disable_fusion_rule_gate,
            "fusion_expectation_error": fusion_expectation_error,
            "input_report": (str(input_report_path) if input_report_path else None),
            "baseline_fingerprint_file": args.baseline_fingerprint_file,
            "baseline_fingerprint_status": args.baseline_fingerprint_status,
            "baseline_fingerprint_notes": args.baseline_fingerprint_notes,
            "cpu_model": args.cpu_model,
        },
        "scenarios": [],
    }

    md_lines = [
        "# Slope Gate Report",
        "",
        f"- baseline: `{baseline_path}`",
        f"- fusion_expectations: `{fusion_expectations_path}`",
        f"- cpu_core: `{args.cpu_core}`",
        f"- cpu_model: `{args.cpu_model or 'unknown'}`",
        f"- engine: `{args.engine}`",
        f"- baseline_fingerprint_file: `{args.baseline_fingerprint_file or 'n/a'}`",
        f"- baseline_fingerprint_status: `{args.baseline_fingerprint_status or 'n/a'}`",
        f"- baseline_fingerprint_notes: `{args.baseline_fingerprint_notes or 'none'}`",
        f"- trace_min_measurement_ns: `{args.trace_min_measurement_ns:.0f}`",
        f"- runtime_measure_runs: `{args.runtime_measure_runs}`",
        f"- runtime_trim_pct: `{args.runtime_trim_pct:.2f}`",
        "",
        "| scenario | a (ns/elem) | b (ns) | R² | baseline a | baseline b | baseline R² | a regress % | b regress % | fusion required | fusion optional | fusion forbidden | fusion required hits | retry hint | gate |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---|---|---|---|",
    ]
    if fusion_expectation_error is not None:
        md_lines.extend(["", f"- fusion_expectation_error: `{fusion_expectation_error}`", ""])

    def measure_scenario_run(sc: Scenario, src: str, reps: int) -> Tuple[List[Dict], Dict[str, Dict[str, int]]]:
        points: List[Dict] = []
        fusion_hits: Dict[str, Dict[str, int]] = {}
        with tempfile.TemporaryDirectory(prefix=f"naux-slope-{sc.name}-") as td:
            tdp = Path(td)
            for n in sc.n_values:
                nx_src = replace_first_int_assignment(src, "n", n)
                nx_path = tdp / f"{sc.name}_{n}.nx"
                nx_path.write_text(nx_src, encoding="utf-8")
                j = bench_json(root, naux_bin, pin_cmd, args.engine, nx_path, sc.mode, sc.iters, sc.warmup_ms)
                merge_fusion_hits(fusion_hits, j)

                if sc.mode == "trace":
                    t_ns = float(j["median_ns"])
                    if sc.element_formula:
                        elems = eval_elements_formula(sc.element_formula, n, reps)
                    else:
                        elems = float(j.get("median_elements", 0))
                        if elems <= 0:
                            elems = float(n * reps)
                else:
                    t_ns = float(j.get("compute_median_ns", j["median_ns"]))
                    if sc.element_formula:
                        elems = eval_elements_formula(sc.element_formula, n, reps)
                    else:
                        avx = float(j.get("avx_dot_elements_total", 0))
                        interp = float(j.get("interp_index_elements_total", 0))
                        it = float(j.get("iters", 1))
                        elems = (avx + interp) / max(1.0, it)

                points.append(
                    {
                        "n": n,
                        "time_ns": t_ns,
                        "elements": elems,
                        "ns_per_elem": (t_ns / elems) if elems > 0 else None,
                    }
                )
        return points, fusion_hits

    for sc in scenarios:
        if not input_report_scenarios and not sc.template.exists():
            failed = True
            hard_failure_any = True
            msg = f"missing template: {sc.template}"
            report["scenarios"].append({"name": sc.name, "error": msg})
            md_lines.append(
                f"| {sc.name} | - | - | - | - | - | - | - | - | - | - | - | - | HARD | FAIL ({msg}) |"
            )
            continue

        points: List[Dict] = []
        fusion_hits: Dict[str, Dict[str, int]] = {}
        measurement_runs: List[Dict[str, object]] = []
        runtime_robust_applied = False
        runtime_good_runs = 0
        runtime_insufficient_good_runs = False
        runtime_consistent_a_regression = False
        runtime_consistent_b_regression = False
        aggregated_fit: Optional[Dict[str, float]] = None
        if input_report_scenarios:
            src_sc = input_report_scenarios.get(sc.name)
            if src_sc is None:
                failed = True
                hard_failure_any = True
                msg = f"missing scenario '{sc.name}' in input report"
                report["scenarios"].append({"name": sc.name, "error": msg})
                md_lines.append(
                    f"| {sc.name} | - | - | - | - | - | - | - | - | - | - | - | - | HARD | FAIL ({msg}) |"
                )
                continue
            src_points = src_sc.get("points", [])
            if not isinstance(src_points, list) or len(src_points) < 2:
                failed = True
                hard_failure_any = True
                msg = f"invalid points for scenario '{sc.name}' in input report"
                report["scenarios"].append({"name": sc.name, "error": msg})
                md_lines.append(
                    f"| {sc.name} | - | - | - | - | - | - | - | - | - | - | - | - | HARD | FAIL ({msg}) |"
                )
                continue
            for p in src_points:
                if not isinstance(p, dict):
                    continue
                n = int(float(p.get("n", 0) or 0))
                t_ns = float(p.get("time_ns", 0.0) or 0.0)
                elems = float(p.get("elements", 0.0) or 0.0)
                points.append(
                    {
                        "n": n,
                        "time_ns": t_ns,
                        "elements": elems,
                        "ns_per_elem": (t_ns / elems) if elems > 0 else None,
                    }
                )
            src_fh = src_sc.get("fusion_hits_by_rule", {})
            if isinstance(src_fh, dict):
                for rule, stat in src_fh.items():
                    if not isinstance(rule, str):
                        continue
                    if not isinstance(stat, dict):
                        continue
                    fusion_hits[rule] = {
                        "static_hits": int(stat.get("static_hits", 0) or 0),
                        "runtime_hits": int(stat.get("runtime_hits", 0) or 0),
                    }
            elif isinstance(src_fh, list):
                merge_fusion_hits(fusion_hits, {"fusion_hits_by_rule": src_fh})
            measurement_runs_raw = src_sc.get("measurement_runs", [])
            if isinstance(measurement_runs_raw, list):
                for run in measurement_runs_raw:
                    if isinstance(run, dict):
                        measurement_runs.append(dict(run))
            aggregated_fit_raw = src_sc.get("aggregated_fit")
            if isinstance(aggregated_fit_raw, dict):
                aggregated_fit = {
                    "a_ns_per_elem": float(aggregated_fit_raw.get("a_ns_per_elem", 0.0) or 0.0),
                    "b_ns": float(aggregated_fit_raw.get("b_ns", 0.0) or 0.0),
                    "r2": float(aggregated_fit_raw.get("r2", 0.0) or 0.0),
                }
            runtime_robust_applied = bool(src_sc.get("runtime_robust_applied", False))
            runtime_good_runs = int(src_sc.get("runtime_good_runs", 0) or 0)
            runtime_insufficient_good_runs = bool(src_sc.get("runtime_insufficient_good_runs", False))
            runtime_consistent_a_regression = bool(src_sc.get("runtime_consistent_a_regression", False))
            runtime_consistent_b_regression = bool(src_sc.get("runtime_consistent_b_regression", False))
        else:
            src = sc.template.read_text(encoding="utf-8")
            try:
                reps = parse_first_int_assignment(src, "reps")
            except RuntimeError:
                reps = 1
            points, fusion_hits = measure_scenario_run(sc, src, reps)

        if len(points) < 2:
            failed = True
            hard_failure_any = True
            msg = f"need at least 2 points for scenario '{sc.name}'"
            report["scenarios"].append({"name": sc.name, "error": msg})
            md_lines.append(
                f"| {sc.name} | - | - | - | - | - | - | - | - | - | - | - | - | HARD | FAIL ({msg}) |"
            )
            continue

        xs = [p["elements"] for p in points]
        ys = [p["time_ns"] for p in points]
        max_point_ns = max_point_time_ns(points)
        short_trace_retryable = short_trace_measurement_retryable(
            sc.mode, points, args.trace_min_measurement_ns
        )
        base = baseline.get(sc.name)
        if aggregated_fit is not None:
            a = float(aggregated_fit["a_ns_per_elem"])
            b = float(aggregated_fit["b_ns"])
            r2 = float(aggregated_fit["r2"])
        else:
            a, b, r2 = linear_fit(xs, ys)
            if not measurement_runs:
                measurement_runs.append(
                    {
                        "a_ns_per_elem": a,
                        "b_ns": b,
                        "r2": r2,
                        "max_point_time_ns": max_point_ns,
                    }
                )
            potential_measurement_fail = False
            if base is None:
                potential_measurement_fail = args.require_baseline
            else:
                ba, bb, br2 = base
                a_reg_probe = rel_regression_pct(a, ba)
                b_reg_probe = rel_regression_pct(b, bb)
                if r2 < sc.require_r2 or a_reg_probe > sc.max_a_reg_pct:
                    potential_measurement_fail = True
                elif abs(bb) >= args.min_baseline_b_ns_for_gate and b_reg_probe > sc.max_b_reg_pct:
                    potential_measurement_fail = True
                elif br2 > 0 and (min(sc.require_r2, br2 - 0.01) - (r2 + 0.0001)) > 0:
                    potential_measurement_fail = True

            if (
                sc.mode == "runtime"
                and args.runtime_measure_runs > 1
                and potential_measurement_fail
            ):
                runtime_robust_applied = True
                all_run_points = [points]
                for _ in range(args.runtime_measure_runs - 1):
                    extra_points, extra_hits = measure_scenario_run(sc, src, reps)
                    all_run_points.append(extra_points)
                    merge_fusion_hits(
                        fusion_hits,
                        {
                            "fusion_hits_by_rule": [
                                {
                                    "rule": rule,
                                    "static_hits": stats.get("static_hits", 0),
                                    "runtime_hits": stats.get("runtime_hits", 0),
                                }
                                for rule, stats in extra_hits.items()
                            ]
                        },
                    )
                    xs_extra = [p["elements"] for p in extra_points]
                    ys_extra = [p["time_ns"] for p in extra_points]
                    a_extra, b_extra, r2_extra = linear_fit(xs_extra, ys_extra)
                    measurement_runs.append(
                        {
                            "a_ns_per_elem": a_extra,
                            "b_ns": b_extra,
                            "r2": r2_extra,
                            "max_point_time_ns": max_point_time_ns(extra_points),
                        }
                    )

                good_runs = [run for run in measurement_runs if float(run["r2"]) >= sc.require_r2]
                runtime_good_runs = len(good_runs)
                selected_runs = good_runs if len(good_runs) >= 2 else measurement_runs
                runtime_insufficient_good_runs = len(good_runs) < 2

                a = trimmed_median([float(run["a_ns_per_elem"]) for run in selected_runs], args.runtime_trim_pct)
                b = trimmed_median([float(run["b_ns"]) for run in selected_runs], args.runtime_trim_pct)
                r2 = trimmed_median([float(run["r2"]) for run in selected_runs], args.runtime_trim_pct)
                rep_idx = representative_run_index(selected_runs, a, b, r2)
                rep_run = selected_runs[rep_idx]
                if rep_run in measurement_runs:
                    rep_points = all_run_points[measurement_runs.index(rep_run)]
                    points = rep_points
                    max_point_ns = max_point_time_ns(points)

                aggregated_fit = {
                    "a_ns_per_elem": a,
                    "b_ns": b,
                    "r2": r2,
                }

                if base is not None and len(good_runs) >= 2:
                    ba, bb, _ = base
                    runtime_consistent_a_regression = all(
                        rel_regression_pct(float(run["a_ns_per_elem"]), ba) > sc.max_a_reg_pct
                        for run in good_runs
                    )
                    if abs(bb) >= args.min_baseline_b_ns_for_gate:
                        runtime_consistent_b_regression = all(
                            rel_regression_pct(float(run["b_ns"]), bb) > sc.max_b_reg_pct
                            for run in good_runs
                        )
        a_reg = None
        b_reg = None
        hard_reasons: List[str] = []
        retryable_reasons: List[str] = []

        def add_failure(reason: str, retryable: bool) -> None:
            if retryable:
                retryable_reasons.append(reason)
            else:
                hard_reasons.append(reason)

        runtime_r2_retryable = runtime_robust_applied and runtime_insufficient_good_runs

        if r2 < sc.require_r2:
            r2_over = sc.require_r2 - r2
            add_failure(
                f"R2<{sc.require_r2}",
                short_trace_retryable or runtime_r2_retryable or r2_over <= args.instability_r2_margin,
            )

        if base is None:
            if args.require_baseline:
                add_failure("missing baseline", False)
        else:
            ba, bb, br2 = base
            a_reg = rel_regression_pct(a, ba)
            b_reg = rel_regression_pct(b, bb)
            if a_reg > sc.max_a_reg_pct:
                add_failure(
                    f"a regress {a_reg:.2f}% > {sc.max_a_reg_pct:.2f}%",
                    short_trace_retryable
                    or (runtime_robust_applied and not runtime_consistent_a_regression)
                    or (a_reg - sc.max_a_reg_pct) <= args.instability_a_overage_pct,
                )
            if abs(bb) >= args.min_baseline_b_ns_for_gate and b_reg > sc.max_b_reg_pct:
                add_failure(
                    f"b regress {b_reg:.2f}% > {sc.max_b_reg_pct:.2f}%",
                    short_trace_retryable
                    or (runtime_robust_applied and not runtime_consistent_b_regression)
                    or (b_reg - sc.max_b_reg_pct) <= args.instability_b_overage_pct,
                )
            if br2 > 0:
                r2_drop_limit = min(sc.require_r2, br2 - 0.01)
                r2_drop_over = r2_drop_limit - (r2 + 0.0001)
                if r2_drop_over > 0:
                    add_failure(
                        f"R2 drop {r2:.4f} vs baseline {br2:.4f}",
                        short_trace_retryable or runtime_r2_retryable or r2_drop_over <= args.instability_r2_margin,
                    )

        required_fusion_rules: List[str] = []
        optional_fusion_rules: List[str] = []
        forbidden_fusion_rules: List[str] = []
        if not args.disable_fusion_rule_gate:
            expectation = fusion_expectations.get(
                sc.name, {"required": [], "optional": [], "forbidden": []}
            )
            required_fusion_rules = expectation["required"]
            optional_fusion_rules = expectation["optional"]
            forbidden_fusion_rules = expectation["forbidden"]

            missing = [rule for rule in required_fusion_rules if fusion_hits.get(rule, {}).get("runtime_hits", 0) <= 0]
            if missing:
                add_failure(f"missing fusion runtime hits: {','.join(missing)}", False)
            forbidden_hit = [rule for rule in forbidden_fusion_rules if fusion_hits.get(rule, {}).get("runtime_hits", 0) > 0]
            if forbidden_hit:
                add_failure(f"forbidden fusion rules hit: {','.join(forbidden_hit)}", False)

        is_nonblocking = sc.name in nonblocking_scenarios
        all_reasons = hard_reasons + retryable_reasons
        scenario_failed = bool(all_reasons)
        scenario_retryable = scenario_failed and not hard_reasons
        gate = "PASS" if not scenario_failed else f"FAIL ({'; '.join(all_reasons)})"
        if scenario_failed and is_nonblocking:
            gate = f"OBSERVE ({'; '.join(all_reasons)})"
        if scenario_failed and not is_nonblocking:
            failed = True
            if scenario_retryable:
                retryable_failure_any = True
            else:
                hard_failure_any = True
        retry_hint = "OBSERVE" if (scenario_failed and is_nonblocking) else (
            "RETRYABLE" if scenario_retryable else ("HARD" if scenario_failed else "-")
        )

        fusion_required_md = ",".join(required_fusion_rules) if required_fusion_rules else "-"
        fusion_optional_md = ",".join(optional_fusion_rules) if optional_fusion_rules else "-"
        fusion_forbidden_md = ",".join(forbidden_fusion_rules) if forbidden_fusion_rules else "-"
        if required_fusion_rules:
            fusion_required_runtime_md = ",".join(
                f"{rule}:{fusion_hits.get(rule, {}).get('runtime_hits', 0)}"
                for rule in required_fusion_rules
            )
        else:
            fusion_required_runtime_md = "-"

        report["scenarios"].append(
            {
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
                "baseline": None if base is None else {"a_ns_per_elem": base[0], "b_ns": base[1], "r2": base[2]},
                "a_regression_pct": a_reg,
                "b_regression_pct": b_reg,
                "fusion_required_rules": required_fusion_rules,
                "fusion_optional_rules": optional_fusion_rules,
                "fusion_forbidden_rules": forbidden_fusion_rules,
                "fusion_hits_by_rule": fusion_hits,
                "retryable_failure_reasons": retryable_reasons,
                "hard_failure_reasons": hard_reasons,
                "retry_recommended": (scenario_retryable and not is_nonblocking),
                "nonblocking": is_nonblocking,
                "gate": gate,
            }
        )

        ba = "-"
        bb = "-"
        br = "-"
        if base is not None:
            ba = f"{base[0]:.6f}"
            bb = f"{base[1]:.3f}"
            br = f"{base[2]:.4f}"
        md_lines.append(
            "| {name} | {a:.6f} | {b:.3f} | {r2:.4f} | {ba} | {bb} | {br} | {areg} | {breg} | {fusion_required} | {fusion_optional} | {fusion_forbidden} | {fusion_required_runtime} | {retry_hint} | {gate} |".format(
                name=sc.name,
                a=a,
                b=b,
                r2=r2,
                ba=ba,
                bb=bb,
                br=br,
                areg="-" if a_reg is None else f"{a_reg:.2f}",
                breg="-" if b_reg is None else f"{b_reg:.2f}",
                fusion_required=fusion_required_md,
                fusion_optional=fusion_optional_md,
                fusion_forbidden=fusion_forbidden_md,
                fusion_required_runtime=fusion_required_runtime_md,
                retry_hint=retry_hint,
                gate=gate,
            )
        )

    retry_recommended = failed and retryable_failure_any and not hard_failure_any
    retry_class = "pass"
    if failed:
        retry_class = "retryable" if retry_recommended else "hard"
    report["retry_recommended"] = retry_recommended
    report["retry_class"] = retry_class

    md_lines.extend(
        [
            "",
            f"- retry_class: `{retry_class}`",
            f"- retry_recommended: `{str(retry_recommended).lower()}`",
        ]
    )

    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    out_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    if failed:
        if retry_recommended:
            print("[slope-gate] FAILED (instability-retry-recommended)")
        else:
            print("[slope-gate] FAILED")
        print(out_md.read_text(encoding="utf-8"))
        return 2 if retry_recommended else 1

    print("[slope-gate] PASS")
    print(out_md.read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
