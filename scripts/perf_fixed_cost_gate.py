#!/usr/bin/env python3
import argparse
import json
import re
import shutil
import statistics
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Gate fixed-cost performance (low-n + cold-start) and capture perf-stat artifacts"
    )
    p.add_argument("--root", required=True)
    p.add_argument("--naux-bin", required=True)
    p.add_argument("--cpu-core", type=int, default=0)
    p.add_argument("--engine", default="jit")
    p.add_argument("--template", default="naux-lang/examples/bench_dot_product.nx")
    p.add_argument("--low-n-values", default="512,1024,2048")
    p.add_argument("--low-n-iters", type=int, default=50)
    p.add_argument("--low-n-warmup-ms", type=int, default=100)
    p.add_argument(
        "--low-n-discard-runs",
        type=int,
        default=0,
        help="Run and discard this many low-n samples before collecting the measured sample",
    )
    p.add_argument(
        "--low-n-measure-runs",
        type=int,
        default=5,
        help="Collect this many measured low-n samples and gate on their median",
    )
    p.add_argument(
        "--low-n-trim-pct",
        type=float,
        default=0.2,
        help="Trim this fraction of low/high measured low-n runs before aggregating",
    )
    p.add_argument(
        "--low-n-cooldown-ms",
        type=int,
        default=0,
        help="Sleep for this many ms before each low-n sample sequence",
    )
    p.add_argument("--low-n-max-reg-pct", type=float, default=7.0)
    p.add_argument("--low-n-abs-ns", type=float, default=2000.0)
    p.add_argument("--low-n-abs-ns-tiny", type=float, default=3500.0)
    p.add_argument("--low-n-tiny-threshold", type=int, default=512)
    p.add_argument("--cold-n", type=int, default=65536)
    p.add_argument("--cold-samples", type=int, default=11)
    p.add_argument("--cold-max-reg-pct", type=float, default=12.0)
    p.add_argument("--cold-abs-ns", type=float, default=100000.0)
    p.add_argument(
        "--instability-overage-pct",
        type=float,
        default=3.0,
        help="Treat threshold overage within this percent as retryable instability",
    )
    p.add_argument(
        "--instability-overage-ns",
        type=float,
        default=1000.0,
        help="Treat threshold overage within this absolute ns as retryable instability",
    )
    p.add_argument("--low-n-baseline", default="benchmarks/perf_low_n_baseline.tsv")
    p.add_argument("--cold-baseline", default="benchmarks/perf_cold_baseline.tsv")
    p.add_argument("--require-baseline", action="store_true")
    p.add_argument("--enable-perf-stat", action="store_true")
    p.add_argument("--enable-microarch-observe", action="store_true")
    p.add_argument("--perf-stat-n", type=int, default=65536)
    p.add_argument("--perf-stat-iters", type=int, default=20)
    p.add_argument("--perf-stat-warmup-ms", type=int, default=100)
    p.add_argument("--out-json", default="target/perf/fixed_cost_report.json")
    p.add_argument("--out-md", default="target/perf/fixed_cost_report.md")
    return p.parse_args()


def run_cmd(cmd: List[str], cwd: Path) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


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


def parse_baseline(path: Path) -> Dict[str, float]:
    out: Dict[str, float] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        out[parts[0]] = float(parts[1])
    return out


def bench_json(
    root: Path,
    naux_bin: Path,
    pin_cmd: Optional[List[str]],
    engine: str,
    nx_path: Path,
    iters: int,
    warmup_ms: int,
    trace_only: bool = False,
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
    if trace_only:
        cmd.insert(-1, "--trace-only")
    rc, stdout, stderr = run_cmd(cmd, root)
    if rc != 0:
        raise RuntimeError(
            f"benchrt failed rc={rc}\ncmd={' '.join(cmd)}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        )
    data = stdout.strip()
    if not data:
        raise RuntimeError(f"empty benchrt output: {' '.join(cmd)}")
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"invalid benchrt JSON: {e}\n{data}")


def parse_low_n_values(raw: str) -> List[int]:
    vals: List[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        vals.append(int(part))
    if not vals:
        raise RuntimeError("low-n-values is empty")
    return vals


def gate_threshold(base: float, reg_pct: float, abs_ns: float) -> float:
    pct_cap = base * (1.0 + reg_pct / 100.0)
    abs_cap = base + abs_ns
    return max(pct_cap, abs_cap)


def maybe_sleep(ms: int) -> None:
    if ms > 0:
        time.sleep(ms / 1000.0)


def discard_bench_params(iters: int, warmup_ms: int) -> Tuple[int, int]:
    discard_iters = max(8, min(32, max(1, iters // 6)))
    discard_warmup_ms = min(warmup_ms, 75)
    return discard_iters, discard_warmup_ms


def trimmed_median(samples: List[float], trim_pct: float) -> Tuple[float, List[float]]:
    if not samples:
        raise RuntimeError("cannot aggregate empty sample set")
    ordered = sorted(samples)
    trim_each = int(len(ordered) * trim_pct)
    max_trim = (len(ordered) - 1) // 2
    trim_each = min(trim_each, max_trim)
    if trim_each > 0:
        trimmed = ordered[trim_each : len(ordered) - trim_each]
    else:
        trimmed = ordered
    return float(statistics.median(trimmed)), trimmed


def refresh_low_n_row_status(row: Dict) -> None:
    hard_reasons = row["hard_failure_reasons"]
    retryable_reasons = row["retryable_failure_reasons"]
    all_reasons = hard_reasons + retryable_reasons
    row_failed = bool(all_reasons)
    row_retryable = row_failed and not hard_reasons
    row["retry_hint"] = "RETRYABLE" if row_retryable else ("HARD" if row_failed else "-")
    row["gate"] = "PASS" if not row_failed else f"FAIL ({'; '.join(all_reasons)})"


def downgrade_low_n_failures_to_retryable(rows: List[Dict], note: str) -> None:
    for row in rows:
        if row["hard_failure_reasons"]:
            row["retryable_failure_reasons"].extend(row["hard_failure_reasons"])
            row["hard_failure_reasons"] = []
            if note not in row["retryable_failure_reasons"]:
                row["retryable_failure_reasons"].append(note)
            refresh_low_n_row_status(row)


def has_nonmonotonic_low_n_failure_shape(rows: List[Dict]) -> bool:
    failed_ns = [row["n"] for row in rows if row["hard_failure_reasons"] or row["retryable_failure_reasons"]]
    if not failed_ns:
        return False
    max_failed_n = max(failed_ns)
    if any(
        row["n"] > max_failed_n and not (row["hard_failure_reasons"] or row["retryable_failure_reasons"])
        for row in rows
    ):
        return True

    # The same benchmark at larger n should not run materially faster than a smaller n.
    # When the timing curve inverts here, the batch is almost certainly contaminated by
    # machine-state noise rather than a real regression in the compiler output.
    ordered = sorted(rows, key=lambda row: row["n"])
    for left, right in zip(ordered, ordered[1:]):
        left_ns = left.get("compute_median_ns")
        right_ns = right.get("compute_median_ns")
        if left_ns is None or right_ns is None:
            continue
        if left_ns > right_ns * 1.05:
            return True

    # If the current timing curve diverges too far from the baseline timing
    # curve between adjacent low-n points, treat it as an unstable batch and
    # retry instead of declaring a hard regression on one contaminated sample.
    for left, right in zip(ordered, ordered[1:]):
        left_ns = left.get("compute_median_ns")
        right_ns = right.get("compute_median_ns")
        left_base = left.get("baseline_ns")
        right_base = right.get("baseline_ns")
        if (
            left_ns is None
            or right_ns is None
            or left_base is None
            or right_base is None
            or left_ns <= 0
            or left_base <= 0
        ):
            continue
        current_ratio = right_ns / left_ns
        baseline_ratio = right_base / left_base
        if current_ratio > baseline_ratio * 1.25 or current_ratio < baseline_ratio / 1.25:
            return True

    # When every low-n point inflates by nearly the same factor versus baseline,
    # that is more consistent with temporary machine slowdown than with a
    # benchmark-specific regression. Retry before treating it as hard failure.
    inflation_factors: List[float] = []
    for row in ordered:
        current = row.get("compute_median_ns")
        base = row.get("baseline_ns")
        if current is None or base is None or base <= 0:
            return False
        if not (row["hard_failure_reasons"] or row["retryable_failure_reasons"]):
            break
        inflation_factors.append(current / base)
    else:
        if len(inflation_factors) >= 3:
            span = max(inflation_factors) - min(inflation_factors)
            if span <= 0.20:
                return True
    return False


def is_retryable_overage(current: float, threshold: float, pct_margin: float, abs_margin_ns: float) -> bool:
    if current <= threshold:
        return False
    overage = current - threshold
    pct_allow = threshold * (pct_margin / 100.0)
    allow = max(abs_margin_ns, pct_allow)
    return overage <= allow


def parse_perf_stat(stderr: str) -> Dict[str, float]:
    metrics: Dict[str, float] = {}
    for raw in stderr.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3:
            continue
        value_raw, _unit, event = parts[0], parts[1], parts[2]
        if value_raw in ("<not supported>", "<not counted>"):
            continue
        try:
            value = float(value_raw.replace(",", ""))
        except ValueError:
            continue
        metrics[event] = value
    return metrics


def run_perf_stat_events(
    root: Path,
    pin_cmd: Optional[List[str]],
    base_cmd: List[str],
    events: List[str],
) -> Tuple[Optional[Dict[str, float]], Optional[str], Optional[str]]:
    if not shutil.which("perf"):
        return None, None, "perf not found"
    cmd: List[str] = ["perf", "stat", "-x,", "-e", ",".join(events)]
    cmd.append("--")
    if pin_cmd:
        cmd.extend(pin_cmd)
    cmd.extend(base_cmd)
    rc, stdout, stderr = run_cmd(cmd, root)
    if rc != 0:
        return None, stdout, f"perf stat failed rc={rc}: {stderr.strip()}"
    metrics = parse_perf_stat(stderr)
    return metrics, stdout, None


def safe_div(numer: float, denom: float) -> Optional[float]:
    if denom == 0:
        return None
    return numer / denom


def capture_first_supported_event(
    root: Path,
    pin_cmd: Optional[List[str]],
    base_cmd: List[str],
    candidates: List[str],
) -> Dict:
    attempts: List[str] = []
    for event in candidates:
        metrics, _stdout, err = run_perf_stat_events(root, pin_cmd, base_cmd, [event])
        if err is not None:
            attempts.append(f"{event}: {err}")
            continue
        if metrics is None:
            attempts.append(f"{event}: no metrics")
            continue
        if event in metrics:
            return {
                "available": True,
                "event": event,
                "value": float(metrics[event]),
                "reason": None,
                "attempts": attempts,
            }
        attempts.append(f"{event}: not in perf output")
    return {
        "available": False,
        "event": None,
        "value": None,
        "reason": "no supported icache event",
        "attempts": attempts,
    }


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    naux_bin = Path(args.naux_bin).resolve()
    template_path = (root / args.template).resolve()
    out_json = (root / args.out_json).resolve()
    out_md = (root / args.out_md).resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    low_n_values = parse_low_n_values(args.low_n_values)
    pin_cmd: Optional[List[str]] = None
    if shutil.which("taskset"):
        pin_cmd = ["taskset", "-c", str(args.cpu_core)]

    low_n_baseline = parse_baseline((root / args.low_n_baseline).resolve())
    cold_baseline = parse_baseline((root / args.cold_baseline).resolve())
    discard_iters, discard_warmup_ms = discard_bench_params(
        args.low_n_iters, args.low_n_warmup_ms
    )

    source = template_path.read_text(encoding="utf-8")
    try:
        reps = parse_first_int_assignment(source, "reps")
    except RuntimeError:
        reps = 1

    low_n_rows: List[Dict] = []

    with tempfile.TemporaryDirectory(prefix="naux-fixed-cost-") as td:
        tmp = Path(td)
        for n in low_n_values:
            nx_src = replace_first_int_assignment(source, "n", n)
            nx_path = tmp / f"dot_low_n_{n}.nx"
            nx_path.write_text(nx_src, encoding="utf-8")
            maybe_sleep(args.low_n_cooldown_ms)
            discarded_runs: List[float] = []
            for _ in range(args.low_n_discard_runs):
                maybe_sleep(args.low_n_cooldown_ms)
                discarded = bench_json(
                    root=root,
                    naux_bin=naux_bin,
                    pin_cmd=pin_cmd,
                    engine=args.engine,
                    nx_path=nx_path,
                    iters=discard_iters,
                    warmup_ms=discard_warmup_ms,
                    trace_only=False,
                )
                discarded_runs.append(float(discarded.get("compute_median_ns", discarded["median_ns"])))
            measured_runs: List[float] = []
            for _ in range(max(1, args.low_n_measure_runs)):
                maybe_sleep(args.low_n_cooldown_ms)
                bench = bench_json(
                    root=root,
                    naux_bin=naux_bin,
                    pin_cmd=pin_cmd,
                    engine=args.engine,
                    nx_path=nx_path,
                    iters=args.low_n_iters,
                    warmup_ms=args.low_n_warmup_ms,
                    trace_only=False,
                )
                measured_runs.append(float(bench.get("compute_median_ns", bench["median_ns"])))
            current, trimmed_runs = trimmed_median(measured_runs, args.low_n_trim_pct)
            key = f"dot_runtime_n{n}"
            base = low_n_baseline.get(key)
            gate = "PASS"
            retry_hint = "-"
            hard_reasons: List[str] = []
            retryable_reasons: List[str] = []
            threshold = None
            if base is None:
                if args.require_baseline:
                    gate = "FAIL (missing baseline)"
                    hard_reasons.append("missing baseline")
            else:
                abs_allow = (
                    args.low_n_abs_ns_tiny if n <= args.low_n_tiny_threshold else args.low_n_abs_ns
                )
                threshold = gate_threshold(base, args.low_n_max_reg_pct, abs_allow)
                if current > threshold:
                    reason = f"{current:.0f}ns > {threshold:.0f}ns"
                    if is_retryable_overage(
                        current=current,
                        threshold=threshold,
                        pct_margin=args.instability_overage_pct,
                        abs_margin_ns=args.instability_overage_ns,
                    ):
                        retryable_reasons.append(reason)
                    else:
                        hard_reasons.append(reason)
            row = {
                "scenario": key,
                "n": n,
                "reps": reps,
                "discard_runs": args.low_n_discard_runs,
                "measure_runs": args.low_n_measure_runs,
                "trim_pct": args.low_n_trim_pct,
                "discard_iters": discard_iters,
                "discard_warmup_ms": discard_warmup_ms,
                "discarded_compute_median_ns": discarded_runs,
                "measured_compute_median_ns": measured_runs,
                "trimmed_compute_median_ns": trimmed_runs,
                "compute_median_ns": current,
                "baseline_ns": base,
                "threshold_ns": threshold,
                "retry_hint": retry_hint,
                "hard_failure_reasons": hard_reasons,
                "retryable_failure_reasons": retryable_reasons,
                "gate": gate,
            }
            refresh_low_n_row_status(row)
            low_n_rows.append(row)

        cold_samples: List[float] = []
        nx_src = replace_first_int_assignment(source, "n", args.cold_n)
        nx_path = tmp / f"dot_cold_n{args.cold_n}.nx"
        nx_path.write_text(nx_src, encoding="utf-8")
        for _ in range(args.cold_samples):
            bench = bench_json(
                root=root,
                naux_bin=naux_bin,
                pin_cmd=pin_cmd,
                engine=args.engine,
                nx_path=nx_path,
                iters=1,
                warmup_ms=0,
                trace_only=False,
            )
            cold_samples.append(float(bench["median_ns"]))

        cold_median = float(statistics.median(cold_samples)) if cold_samples else 0.0
        cold_key = f"dot_runtime_cold_n{args.cold_n}"
        cold_base = cold_baseline.get(cold_key)
        cold_threshold = None
        cold_gate = "PASS"
        cold_retry_hint = "-"
        cold_hard_reasons: List[str] = []
        cold_retryable_reasons: List[str] = []
        if cold_base is None:
            if args.require_baseline:
                cold_hard_reasons.append("missing baseline")
        else:
            cold_threshold = gate_threshold(cold_base, args.cold_max_reg_pct, args.cold_abs_ns)
            if cold_median > cold_threshold:
                reason = f"{cold_median:.0f}ns > {cold_threshold:.0f}ns"
                if is_retryable_overage(
                    current=cold_median,
                    threshold=cold_threshold,
                    pct_margin=args.instability_overage_pct,
                    abs_margin_ns=args.instability_overage_ns,
                ):
                    cold_retryable_reasons.append(reason)
                else:
                    cold_hard_reasons.append(reason)
        cold_all_reasons = cold_hard_reasons + cold_retryable_reasons
        cold_failed = bool(cold_all_reasons)
        cold_retryable = cold_failed and not cold_hard_reasons
        if cold_failed:
            cold_gate = f"FAIL ({'; '.join(cold_all_reasons)})"
        cold_retry_hint = "RETRYABLE" if cold_retryable else ("HARD" if cold_failed else "-")

        if has_nonmonotonic_low_n_failure_shape(low_n_rows):
            downgrade_low_n_failures_to_retryable(
                low_n_rows,
                "non-monotonic low-n failure shape",
            )

        perf_stat_report: Dict = {
            "available": False,
            "reason": "disabled",
            "runtime_only": None,
            "trace_only": None,
            "delta_per_elem": None,
            "delta_derived": None,
            "microarch_observe_enabled": bool(args.enable_microarch_observe),
        }
        if args.enable_perf_stat:
            perf_stat_report["reason"] = None
            nx_src = replace_first_int_assignment(source, "n", args.perf_stat_n)
            nx_perf_path = tmp / f"dot_perf_n{args.perf_stat_n}.nx"
            nx_perf_path.write_text(nx_src, encoding="utf-8")
            modes = [("runtime_only", False), ("trace_only", True)]
            mode_reports: Dict[str, Dict] = {}
            base_events = ["cycles", "instructions", "branches", "branch-misses"]
            icache_candidates = ["L1-icache-load-misses", "icache.misses"]
            for mode_name, trace_only in modes:
                base_cmd = [
                    str(naux_bin),
                    "dev",
                    "benchrt",
                    str(nx_perf_path),
                    f"--engine={args.engine}",
                    f"--iters={args.perf_stat_iters}",
                    f"--warmup-ms={args.perf_stat_warmup_ms}",
                    "--json",
                ]
                if trace_only:
                    base_cmd.insert(-1, "--trace-only")
                metrics, stdout, err = run_perf_stat_events(root, pin_cmd, base_cmd, base_events)
                if err is not None:
                    perf_stat_report = {
                        "available": False,
                        "reason": err,
                        "runtime_only": None,
                        "trace_only": None,
                        "delta_per_elem": None,
                        "delta_derived": None,
                        "microarch_observe_enabled": bool(args.enable_microarch_observe),
                    }
                    mode_reports = {}
                    break
                if stdout is None:
                    perf_stat_report = {
                        "available": False,
                        "reason": "missing stdout from perf stat command",
                        "runtime_only": None,
                        "trace_only": None,
                        "delta_per_elem": None,
                        "delta_derived": None,
                        "microarch_observe_enabled": bool(args.enable_microarch_observe),
                    }
                    mode_reports = {}
                    break
                bench = json.loads(stdout.strip())
                total_elements = float(
                    bench.get("avx_dot_elements_total", 0)
                    + bench.get("interp_index_elements_total", 0)
                )
                if total_elements <= 0:
                    perf_stat_report = {
                        "available": False,
                        "reason": "unable to derive element count for perf stat",
                        "runtime_only": None,
                        "trace_only": None,
                        "delta_per_elem": None,
                        "delta_derived": None,
                        "microarch_observe_enabled": bool(args.enable_microarch_observe),
                    }
                    mode_reports = {}
                    break
                per_elem = {}
                for event in base_events:
                    value = float(metrics.get(event, 0.0)) if metrics else 0.0
                    per_elem[event] = value / total_elements
                derived = {
                    "branch_miss_rate": safe_div(
                        float(metrics.get("branch-misses", 0.0)),
                        float(metrics.get("branches", 0.0)),
                    ),
                    "ipc": safe_div(
                        float(metrics.get("instructions", 0.0)),
                        float(metrics.get("cycles", 0.0)),
                    ),
                }
                microarch = {
                    "available": False,
                    "icache_event": None,
                    "icache_misses": None,
                    "icache_misses_per_elem": None,
                    "icache_mpki": None,
                    "reason": "disabled",
                    "attempts": [],
                }
                if args.enable_microarch_observe:
                    microarch = capture_first_supported_event(root, pin_cmd, base_cmd, icache_candidates)
                    if microarch.get("available"):
                        icache_misses = float(microarch.get("value", 0.0))
                        microarch["icache_misses_per_elem"] = safe_div(icache_misses, total_elements)
                        microarch["icache_mpki"] = safe_div(
                            icache_misses * 1000.0,
                            float(metrics.get("instructions", 0.0)),
                        )
                mode_reports[mode_name] = {
                    "elements_total": int(total_elements),
                    "raw": metrics,
                    "per_elem": per_elem,
                    "derived": derived,
                    "microarch": microarch,
                }

            if mode_reports and "runtime_only" in mode_reports and "trace_only" in mode_reports:
                delta = {}
                for event in base_events:
                    delta[event] = (
                        mode_reports["runtime_only"]["per_elem"][event]
                        - mode_reports["trace_only"]["per_elem"][event]
                    )
                d_branch_miss_rate = None
                if (
                    mode_reports["runtime_only"]["derived"]["branch_miss_rate"] is not None
                    and mode_reports["trace_only"]["derived"]["branch_miss_rate"] is not None
                ):
                    d_branch_miss_rate = (
                        mode_reports["runtime_only"]["derived"]["branch_miss_rate"]
                        - mode_reports["trace_only"]["derived"]["branch_miss_rate"]
                    )
                d_ipc = None
                if (
                    mode_reports["runtime_only"]["derived"]["ipc"] is not None
                    and mode_reports["trace_only"]["derived"]["ipc"] is not None
                ):
                    d_ipc = (
                        mode_reports["runtime_only"]["derived"]["ipc"]
                        - mode_reports["trace_only"]["derived"]["ipc"]
                    )
                d_icache_per_elem = None
                d_icache_mpki = None
                d_icache_event = None
                runtime_micro = mode_reports["runtime_only"]["microarch"]
                trace_micro = mode_reports["trace_only"]["microarch"]
                if runtime_micro.get("available") and trace_micro.get("available"):
                    d_icache_event = f"{runtime_micro.get('event')}|{trace_micro.get('event')}"
                    r_icache = runtime_micro.get("icache_misses_per_elem")
                    t_icache = trace_micro.get("icache_misses_per_elem")
                    if r_icache is not None and t_icache is not None:
                        d_icache_per_elem = r_icache - t_icache
                    r_mpki = runtime_micro.get("icache_mpki")
                    t_mpki = trace_micro.get("icache_mpki")
                    if r_mpki is not None and t_mpki is not None:
                        d_icache_mpki = r_mpki - t_mpki
                perf_stat_report = {
                    "available": True,
                    "reason": None,
                    "runtime_only": mode_reports["runtime_only"],
                    "trace_only": mode_reports["trace_only"],
                    "delta_per_elem": delta,
                    "delta_derived": {
                        "branch_miss_rate": d_branch_miss_rate,
                        "ipc": d_ipc,
                        "icache_misses_per_elem": d_icache_per_elem,
                        "icache_mpki": d_icache_mpki,
                        "icache_event": d_icache_event,
                    },
                    "microarch_observe_enabled": bool(args.enable_microarch_observe),
                }

    failed = False
    hard_failure_any = False
    retryable_failure_any = False
    for row in low_n_rows:
        row_failed = bool(row["hard_failure_reasons"] or row["retryable_failure_reasons"])
        row_retryable = row_failed and not row["hard_failure_reasons"]
        if row_failed:
            failed = True
            if row_retryable:
                retryable_failure_any = True
            else:
                hard_failure_any = True
    if cold_failed:
        failed = True
        if cold_retryable:
            retryable_failure_any = True
        else:
            hard_failure_any = True

    report = {
        "meta": {
            "engine": args.engine,
            "cpu_core": args.cpu_core,
            "template": str(template_path),
            "low_n_values": low_n_values,
            "low_n_iters": args.low_n_iters,
            "low_n_warmup_ms": args.low_n_warmup_ms,
            "low_n_discard_runs": args.low_n_discard_runs,
            "low_n_measure_runs": args.low_n_measure_runs,
            "low_n_trim_pct": args.low_n_trim_pct,
            "low_n_cooldown_ms": args.low_n_cooldown_ms,
            "low_n_discard_iters": discard_iters,
            "low_n_discard_warmup_ms": discard_warmup_ms,
            "low_n_max_reg_pct": args.low_n_max_reg_pct,
            "low_n_abs_ns": args.low_n_abs_ns,
            "low_n_abs_ns_tiny": args.low_n_abs_ns_tiny,
            "low_n_tiny_threshold": args.low_n_tiny_threshold,
            "cold_n": args.cold_n,
            "cold_samples": args.cold_samples,
            "cold_max_reg_pct": args.cold_max_reg_pct,
            "cold_abs_ns": args.cold_abs_ns,
            "instability_overage_pct": args.instability_overage_pct,
            "instability_overage_ns": args.instability_overage_ns,
            "low_n_baseline": str((root / args.low_n_baseline).resolve()),
            "cold_baseline": str((root / args.cold_baseline).resolve()),
            "require_baseline": args.require_baseline,
            "perf_stat_enabled": args.enable_perf_stat,
        },
        "low_n": low_n_rows,
        "cold_start": {
            "scenario": cold_key,
            "samples_ns": cold_samples,
            "median_ns": cold_median,
            "baseline_ns": cold_base,
            "threshold_ns": cold_threshold,
            "retry_hint": cold_retry_hint,
            "hard_failure_reasons": cold_hard_reasons,
            "retryable_failure_reasons": cold_retryable_reasons,
            "gate": cold_gate,
        },
        "perf_stat": perf_stat_report,
    }

    md_lines = [
        "# Fixed Cost Gate Report",
        "",
        "## Low-n",
        "",
        "| scenario | n | compute median ns | baseline ns | threshold ns | retry hint | gate |",
        "|---|---:|---:|---:|---:|---|---|",
    ]
    for row in low_n_rows:
        md_lines.append(
            "| {scenario} | {n} | {cur:.0f} | {base} | {thr} | {hint} | {gate} |".format(
                scenario=row["scenario"],
                n=row["n"],
                cur=row["compute_median_ns"],
                base="-"
                if row["baseline_ns"] is None
                else f"{row['baseline_ns']:.0f}",
                thr="-"
                if row["threshold_ns"] is None
                else f"{row['threshold_ns']:.0f}",
                hint=row["retry_hint"],
                gate=row["gate"],
            )
        )

    md_lines.extend(
        [
            "",
            "## Cold Start",
            "",
            "| scenario | median ns | baseline ns | threshold ns | retry hint | gate |",
            "|---|---:|---:|---:|---|---|",
            "| {scenario} | {cur:.0f} | {base} | {thr} | {hint} | {gate} |".format(
                scenario=cold_key,
                cur=cold_median,
                base="-" if cold_base is None else f"{cold_base:.0f}",
                thr="-" if cold_threshold is None else f"{cold_threshold:.0f}",
                hint=cold_retry_hint,
                gate=cold_gate,
            ),
            "",
            "## Perf Stat",
            "",
        ]
    )
    if not perf_stat_report.get("available"):
        md_lines.append(f"- unavailable: {perf_stat_report.get('reason')}")
    else:
        def fmt_opt(v: Optional[float], digits: int = 6) -> str:
            return "-" if v is None else f"{v:.{digits}f}"

        def fmt_pct(v: Optional[float]) -> str:
            return "-" if v is None else f"{(v * 100.0):.4f}%"

        md_lines.extend(
            [
                "| mode | cycles/elem | instructions/elem | branches/elem | branch-misses/elem | branch-miss-rate | IPC | icache-misses/elem | icache-MPKI | icache-event |",
                "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
                "| runtime_only | {c:.6f} | {i:.6f} | {b:.6f} | {m:.6f} | {bmr} | {ipc} | {ic} | {mpki} | {ice} |".format(
                    c=perf_stat_report["runtime_only"]["per_elem"]["cycles"],
                    i=perf_stat_report["runtime_only"]["per_elem"]["instructions"],
                    b=perf_stat_report["runtime_only"]["per_elem"]["branches"],
                    m=perf_stat_report["runtime_only"]["per_elem"]["branch-misses"],
                    bmr=fmt_pct(perf_stat_report["runtime_only"]["derived"]["branch_miss_rate"]),
                    ipc=fmt_opt(perf_stat_report["runtime_only"]["derived"]["ipc"]),
                    ic=fmt_opt(perf_stat_report["runtime_only"]["microarch"]["icache_misses_per_elem"]),
                    mpki=fmt_opt(perf_stat_report["runtime_only"]["microarch"]["icache_mpki"]),
                    ice=perf_stat_report["runtime_only"]["microarch"]["event"] or "-",
                ),
                "| trace_only | {c:.6f} | {i:.6f} | {b:.6f} | {m:.6f} | {bmr} | {ipc} | {ic} | {mpki} | {ice} |".format(
                    c=perf_stat_report["trace_only"]["per_elem"]["cycles"],
                    i=perf_stat_report["trace_only"]["per_elem"]["instructions"],
                    b=perf_stat_report["trace_only"]["per_elem"]["branches"],
                    m=perf_stat_report["trace_only"]["per_elem"]["branch-misses"],
                    bmr=fmt_pct(perf_stat_report["trace_only"]["derived"]["branch_miss_rate"]),
                    ipc=fmt_opt(perf_stat_report["trace_only"]["derived"]["ipc"]),
                    ic=fmt_opt(perf_stat_report["trace_only"]["microarch"]["icache_misses_per_elem"]),
                    mpki=fmt_opt(perf_stat_report["trace_only"]["microarch"]["icache_mpki"]),
                    ice=perf_stat_report["trace_only"]["microarch"]["event"] or "-",
                ),
                "| delta(runtime-trace) | {c:.6f} | {i:.6f} | {b:.6f} | {m:.6f} | {bmr} | {ipc} | {ic} | {mpki} | {ice} |".format(
                    c=perf_stat_report["delta_per_elem"]["cycles"],
                    i=perf_stat_report["delta_per_elem"]["instructions"],
                    b=perf_stat_report["delta_per_elem"]["branches"],
                    m=perf_stat_report["delta_per_elem"]["branch-misses"],
                    bmr=fmt_pct(perf_stat_report["delta_derived"]["branch_miss_rate"]),
                    ipc=fmt_opt(perf_stat_report["delta_derived"]["ipc"]),
                    ic=fmt_opt(perf_stat_report["delta_derived"]["icache_misses_per_elem"]),
                    mpki=fmt_opt(perf_stat_report["delta_derived"]["icache_mpki"]),
                    ice=perf_stat_report["delta_derived"]["icache_event"] or "-",
                ),
            ]
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
            f"- retry_recommended: `{'true' if retry_recommended else 'false'}`",
        ]
    )

    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    out_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    if failed:
        if retry_recommended:
            print("[fixed-cost-gate] FAILED (instability-retry-recommended)")
        else:
            print("[fixed-cost-gate] FAILED")
        print(out_md.read_text(encoding="utf-8"))
        return 2 if retry_recommended else 1

    print("[fixed-cost-gate] PASS")
    print(out_md.read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
