#!/usr/bin/env python3
"""Render PERF_STATUS.md from latest perf governance artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from perf_status import (
    RETRY_CLASS_HARD,
    RETRY_CLASS_PASS,
    RETRY_CLASS_RETRYABLE,
    STABILITY_STATUS_PASS,
    normalize_retry_class,
    normalize_stability_status,
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Update PERF_STATUS.md from perf artifacts")
    p.add_argument("--trend-json", default="target/perf/trend_report.json")
    p.add_argument("--stability-json", default="target/perf/stability_window_report.json")
    p.add_argument("--slope-json", default="target/perf/slope_report.json")
    p.add_argument("--fixed-cost-json", default="target/perf/fixed_cost_report.json")
    p.add_argument("--deopt-warn-json", default="target/perf/deopt_warn_report.json")
    p.add_argument("--out", default="PERF_STATUS.md")
    return p.parse_args()


def load_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def scenario_map(slope: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for sc in slope.get("scenarios", []):
        name = sc.get("name")
        if isinstance(name, str) and name:
            out[name] = sc
    return out


def gate_pass(gate: str) -> bool:
    return gate.startswith("PASS")


def fmt_float(v: Optional[float], digits: int = 4) -> str:
    if v is None:
        return "-"
    return f"{v:.{digits}f}"


def summarize_latest_metrics(
    trend: Optional[Dict[str, Any]],
    slope: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    metrics: Dict[str, Any] = {
        "latest_run_id": "-",
        "latest_run_retry_class": "-",
        "dot_a": None,
        "map_a": None,
        "map_guard_a": None,
        "fusion_add_hits": 0,
        "fusion_mul_hits": 0,
        "fusion_cmp_hits": 0,
    }

    if trend:
        runs = trend.get("runs", [])
        if isinstance(runs, list) and runs:
            latest = runs[0]
            metrics["latest_run_id"] = str(latest.get("run_id", "-"))
            metrics["latest_run_retry_class"] = normalize_retry_class(latest.get("retry_class", "-"))
            metrics["dot_a"] = latest.get("dot_runtime_a_ns_per_elem")
            metrics["map_a"] = latest.get("map_heavy_a_ns_per_elem")
            metrics["map_guard_a"] = latest.get("map_guard_entry_a_ns_per_elem")
            f = latest.get("fusion_runtime_hits", {})
            if isinstance(f, dict):
                metrics["fusion_add_hits"] = int(f.get("map_stable_add_local", 0) or 0)
                metrics["fusion_mul_hits"] = int(f.get("map_stable_mul_acc", 0) or 0)
                metrics["fusion_cmp_hits"] = int(f.get("map_stable_cmp_branch", 0) or 0)

    # prefer immediate slope report for current run values
    if slope:
        sc = scenario_map(slope)
        if "dot_runtime_only" in sc:
            metrics["dot_a"] = sc["dot_runtime_only"].get("a_ns_per_elem")
        if "map_heavy_read" in sc:
            metrics["map_a"] = sc["map_heavy_read"].get("a_ns_per_elem")
        if "map_guard_entry_heavy" in sc:
            metrics["map_guard_a"] = sc["map_guard_entry_heavy"].get("a_ns_per_elem")

    return metrics


def estimate_progress(
    slope: Optional[Dict[str, Any]],
    trend: Optional[Dict[str, Any]],
    stability: Optional[Dict[str, Any]],
    fixed_cost: Optional[Dict[str, Any]],
    deopt_warn: Optional[Dict[str, Any]],
) -> Tuple[int, int, int]:
    # Estimated scores, bounded and driven by artifact states.
    perf_core = 90
    production_ready = 68
    goal_progress = 65

    if not slope:
        perf_core = 84
    else:
        sc = scenario_map(slope)
        fail_count = 0
        for row in sc.values():
            gate = str(row.get("gate", ""))
            if not gate_pass(gate):
                fail_count += 1
        if fail_count > 0:
            perf_core = max(84, perf_core - fail_count * 2)

    if trend:
        run_count = int((trend.get("meta") or {}).get("run_count", 0) or 0)
        if run_count >= 7:
            production_ready += 2
            goal_progress += 1
        counts = trend.get("retry_class_counts", {})
        if isinstance(counts, dict):
            hard = int(counts.get(RETRY_CLASS_HARD, 0) or 0)
            retryable = int(counts.get(RETRY_CLASS_RETRYABLE, 0) or 0)
            if hard == 0:
                production_ready += 1
            if retryable <= 1:
                production_ready += 1
    else:
        production_ready -= 2

    if stability:
        gate = str(stability.get("gate", ""))
        status = normalize_stability_status(stability.get("status", ""))
        if gate == "PASS":
            production_ready += 2
        if status == STABILITY_STATUS_PASS:
            production_ready += 1
            goal_progress += 1
    else:
        production_ready -= 1

    if fixed_cost:
        low = fixed_cost.get("low_n", [])
        cold = fixed_cost.get("cold_start", {})
        low_ok = True
        if isinstance(low, list):
            for row in low:
                g = str((row or {}).get("gate", ""))
                if not gate_pass(g):
                    low_ok = False
                    break
        cold_ok = gate_pass(str((cold or {}).get("gate", "")))
        if low_ok and cold_ok:
            production_ready += 1
            goal_progress += 1

    if deopt_warn:
        gate = str(deopt_warn.get("gate", ""))
        if gate == "PASS":
            production_ready += 1

    perf_core = max(80, min(92, perf_core))
    production_ready = max(60, min(78, production_ready))
    goal_progress = max(55, min(72, goal_progress))
    return perf_core, production_ready, goal_progress


def slope_failures(slope: Optional[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    if not slope:
        return ["missing slope_report.json"]
    for sc in slope.get("scenarios", []):
        name = str(sc.get("name", "unknown"))
        gate = str(sc.get("gate", ""))
        if not gate_pass(gate):
            out.append(f"{name}: {gate}")
    return out


def main() -> int:
    args = parse_args()
    trend_path = Path(args.trend_json).resolve()
    stability_path = Path(args.stability_json).resolve()
    slope_path = Path(args.slope_json).resolve()
    fixed_path = Path(args.fixed_cost_json).resolve()
    deopt_warn_path = Path(args.deopt_warn_json).resolve()
    out_path = Path(args.out).resolve()

    trend = load_json(trend_path)
    stability = load_json(stability_path)
    slope = load_json(slope_path)
    fixed_cost = load_json(fixed_path)
    deopt_warn = load_json(deopt_warn_path)

    perf_core, production_ready, goal_progress = estimate_progress(
        slope=slope,
        trend=trend,
        stability=stability,
        fixed_cost=fixed_cost,
        deopt_warn=deopt_warn,
    )
    metrics = summarize_latest_metrics(trend=trend, slope=slope)
    failures = slope_failures(slope)

    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    trend_run_count = int(((trend or {}).get("meta") or {}).get("run_count", 0) or 0)
    retry_counts = (trend or {}).get("retry_class_counts", {})
    retry_pass = int((retry_counts or {}).get(RETRY_CLASS_PASS, 0) or 0)
    retry_retryable = int((retry_counts or {}).get(RETRY_CLASS_RETRYABLE, 0) or 0)
    retry_hard = int((retry_counts or {}).get(RETRY_CLASS_HARD, 0) or 0)

    stability_gate = str((stability or {}).get("gate", "MISSING"))
    stability_status = normalize_stability_status((stability or {}).get("status", "missing"), default="missing")
    stability_retryable_pct = (stability or {}).get("retryable_pct")
    rule_stats = (stability or {}).get("rule_stats", [])

    lines: List[str] = []
    lines.append("# Naux Perf Status")
    lines.append("")
    lines.append(f"- updated_utc: `{now}`")
    lines.append("")
    lines.append("## Overall Progress (Estimated)")
    lines.append("")
    lines.append(f"- performance_core: `{perf_core}%`")
    lines.append(f"- production_readiness: `{production_ready}%`")
    lines.append(f"- beat_c_cpp_goal_progress: `{goal_progress}%`")
    lines.append("")
    lines.append("## Governance Snapshot")
    lines.append("")
    lines.append(f"- latest_run_id: `{metrics['latest_run_id']}`")
    lines.append(f"- latest_retry_class: `{metrics['latest_run_retry_class']}`")
    lines.append(f"- trend_run_count: `{trend_run_count}`")
    lines.append(
        f"- retry_class_counts: `pass={retry_pass}, retryable={retry_retryable}, hard={retry_hard}`"
    )
    lines.append(f"- stability_gate: `{stability_gate}`")
    lines.append(f"- stability_status: `{stability_status}`")
    lines.append(
        f"- stability_retryable_pct: `{fmt_float(stability_retryable_pct, 2)}%`"
        if stability_retryable_pct is not None
        else "- stability_retryable_pct: `-`"
    )
    lines.append("")
    lines.append("## Latest Perf Signals")
    lines.append("")
    lines.append(f"- dot_runtime_only_slope_a: `{fmt_float(metrics['dot_a'], 6)} ns/elem`")
    lines.append(f"- map_heavy_read_slope_a: `{fmt_float(metrics['map_a'], 6)} ns/elem`")
    lines.append(f"- map_guard_entry_heavy_slope_a: `{fmt_float(metrics['map_guard_a'], 6)} ns/elem`")
    lines.append(
        "- fusion_runtime_hits: "
        f"`add={metrics['fusion_add_hits']}, mul_acc={metrics['fusion_mul_hits']}, cmp_branch={metrics['fusion_cmp_hits']}`"
    )
    lines.append("")
    lines.append("## Stability Rule Window")
    lines.append("")
    if isinstance(rule_stats, list) and rule_stats:
        lines.append("| rule | hit_runs | run_count | hit_pct | pass |")
        lines.append("|---|---:|---:|---:|---|")
        for row in rule_stats:
            rule = str((row or {}).get("rule", "-"))
            hit_runs = int((row or {}).get("hit_runs", 0) or 0)
            run_count = int((row or {}).get("run_count", 0) or 0)
            hit_pct = (row or {}).get("hit_pct")
            ok = bool((row or {}).get("pass", False))
            lines.append(
                f"| {rule} | {hit_runs} | {run_count} | {fmt_float(hit_pct, 2)}% | {'PASS' if ok else 'FAIL'} |"
            )
    else:
        lines.append("- rule_stats: `unavailable`")
    lines.append("")
    lines.append("## Active Blockers")
    lines.append("")
    if failures:
        for f in failures:
            lines.append(f"- {f}")
    else:
        lines.append("- None from slope gate (all scenarios PASS).")
    if stability and stability_gate != "PASS":
        lines.append(f"- Stability window gate is `{stability_gate}` (`{stability_status}`).")
    if not trend:
        lines.append("- Missing trend_report.json (run trend aggregation).")
    if not fixed_cost:
        lines.append("- Missing fixed_cost_report.json for this run.")
    if not deopt_warn:
        lines.append("- Missing deopt_warn_report.json (observe-only path may be disabled).")
    lines.append("")
    lines.append("## Next 7-Day Focus")
    lines.append("")
    lines.append("- Keep `retry_class=hard` at `0` across the moving window.")
    lines.append("- Promote Rust slope gate on a controlled branch and compare drift vs Python shadow.")
    lines.append("- Publish refreshed C/C++/Rust/Go/Zig baseline artifacts for claim credibility.")
    lines.append("- Expand branchy + allocation workloads under the same perf contract.")
    lines.append("")
    lines.append("## Artifact Inputs")
    lines.append("")
    lines.append(f"- trend_json: `{trend_path}`")
    lines.append(f"- stability_json: `{stability_path}`")
    lines.append(f"- slope_json: `{slope_path}`")
    lines.append(f"- fixed_cost_json: `{fixed_path}`")
    lines.append(f"- deopt_warn_json: `{deopt_warn_path}`")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[perf-status] wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
