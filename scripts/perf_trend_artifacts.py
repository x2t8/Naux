#!/usr/bin/env python3
"""Aggregate perf gate artifacts into a compact multi-run trend report.

This script scans an artifact root for slope gate reports and optionally reads
fixed-cost reports from the same run directory. It then emits:
  - trend_report.json (machine readable)
  - trend_report.md   (human scan friendly)
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from perf_status import (
    RETRY_CLASS_HARD,
    RETRY_CLASS_PASS,
    RETRY_CLASS_RETRYABLE,
    normalize_retry_class,
)


KEY_FUSION_RULES = [
    "map_const_slot_stable",
    "map_stable_add_local",
    "map_stable_mul_acc",
    "map_stable_cmp_branch",
]


@dataclass
class ScenarioSummary:
    a_ns_per_elem: Optional[float]
    r2: Optional[float]
    gate: str


@dataclass
class RunSummary:
    run_id: str
    slope_path: Path
    fixed_cost_path: Optional[Path]
    mtime_utc: str
    retry_class: str
    retry_recommended: bool
    dot_runtime: ScenarioSummary
    dot_trace: ScenarioSummary
    map_heavy: ScenarioSummary
    map_guard_entry: ScenarioSummary
    fusion_runtime_hits: Dict[str, int]
    fixed_cost_status: str
    fixed_cost_error: Optional[str]
    low_n_failed: Optional[int]
    low_n_total: Optional[int]
    cold_gate: Optional[str]
    perf_stat_available: Optional[bool]
    slope_primary_impl: Optional[str]
    slope_shadow_impl: Optional[str]
    shadow_compare_status: str
    perf_report_path: Optional[Path]
    promotion_context: Dict[str, object]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build trend report from perf artifacts")
    p.add_argument(
        "--artifacts-root",
        default="target/perf/history",
        help="Root directory containing per-run artifacts (recursive scan)",
    )
    p.add_argument(
        "--slope-filenames",
        default="slope_report.json,perf_slope_report.json",
        help="Comma-separated slope report filenames to scan recursively",
    )
    p.add_argument(
        "--fixed-cost-filenames",
        default="fixed_cost_report.json,perf_fixed_cost_report.json",
        help="Comma-separated fixed-cost report filenames colocated with slope report",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=7,
        help="Number of most recent runs to include",
    )
    p.add_argument(
        "--out-json",
        default="target/perf/trend_report.json",
        help="Output JSON report path",
    )
    p.add_argument(
        "--out-md",
        default="target/perf/trend_report.md",
        help="Output markdown report path",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when no slope artifacts are found",
    )
    return p.parse_args()


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _fmt_ts_utc(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _find_slope_reports(root: Path, slope_filename: str) -> List[Path]:
    if not root.exists():
        return []
    files = [p for p in root.rglob(slope_filename) if p.is_file()]
    # Also allow direct path to slope file as artifacts root.
    if root.is_file() and root.name == slope_filename:
        files.append(root)
    # De-dup and sort by mtime desc.
    uniq = sorted(set(files), key=lambda p: p.stat().st_mtime, reverse=True)
    return uniq


def _parse_csv(value: str) -> List[str]:
    out = [item.strip() for item in value.split(",") if item.strip()]
    return out


def _find_slope_reports_multi(root: Path, slope_filenames: List[str]) -> List[Path]:
    all_files: List[Path] = []
    for name in slope_filenames:
        all_files.extend(_find_slope_reports(root, name))
    return sorted(set(all_files), key=lambda p: p.stat().st_mtime, reverse=True)


def _scenario_index(slope: dict) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    for sc in slope.get("scenarios", []):
        name = sc.get("name")
        if isinstance(name, str) and name:
            out[name] = sc
    return out


def _scenario_summary(scenario: Optional[dict]) -> ScenarioSummary:
    if scenario is None:
        return ScenarioSummary(None, None, "MISSING")
    return ScenarioSummary(
        a_ns_per_elem=scenario.get("a_ns_per_elem"),
        r2=scenario.get("r2"),
        gate=str(scenario.get("gate", "UNKNOWN")),
    )


def _parse_fusion_hits(slope: dict) -> Dict[str, int]:
    totals: Dict[str, int] = {}
    for sc in slope.get("scenarios", []):
        by_rule = sc.get("fusion_hits_by_rule", {})
        if isinstance(by_rule, dict):
            for rule, payload in by_rule.items():
                if not isinstance(payload, dict):
                    continue
                runtime_hits = int(payload.get("runtime_hits", 0) or 0)
                totals[rule] = totals.get(rule, 0) + runtime_hits
        elif isinstance(by_rule, list):
            # Backward-compat for list shape.
            for row in by_rule:
                if not isinstance(row, dict):
                    continue
                rule = row.get("rule")
                if not isinstance(rule, str) or not rule:
                    continue
                runtime_hits = int(row.get("runtime_hits", 0) or 0)
                totals[rule] = totals.get(rule, 0) + runtime_hits
    return totals


def _parse_fixed_cost(path: Optional[Path]) -> Tuple[str, Optional[str], Optional[int], Optional[int], Optional[str], Optional[bool]]:
    if path is None or not path.exists():
        return "missing", None, None, None, None, None
    try:
        data = _load_json(path)
    except Exception as e:  # pragma: no cover - defensive
        return "parse_error", str(e), None, None, None, None
    low = data.get("low_n", [])
    low_total = len(low) if isinstance(low, list) else None
    low_failed = None
    if isinstance(low, list):
        low_failed = 0
        for row in low:
            gate = str((row or {}).get("gate", ""))
            if not gate.startswith("PASS"):
                low_failed += 1
    cold_gate = None
    cold = data.get("cold_start")
    if isinstance(cold, dict):
        cold_gate = str(cold.get("gate", ""))
    perf_avail = None
    perf_stat = data.get("perf_stat")
    if isinstance(perf_stat, dict):
        perf_avail = bool(perf_stat.get("available", False))
    return "present", None, low_failed, low_total, cold_gate, perf_avail


def _find_fixed_cost_peer(slope_path: Path, fixed_cost_filenames: List[str]) -> Optional[Path]:
    for name in fixed_cost_filenames:
        p = slope_path.parent / name
        if p.exists():
            return p
    return None


def _parse_shadow_compare(slope_path: Path) -> Tuple[Optional[str], Optional[str], str]:
    canonical = slope_path.parent / "slope_report_shadow_compare.json"
    if canonical.exists():
        try:
            payload = _load_json(canonical)
            primary = payload.get("primary", {})
            shadow = payload.get("shadow", {})
            status = str(payload.get("status", "error")).lower()
            if status not in {"match", "mismatch"}:
                status = "error"
            return (
                primary.get("implementation") if isinstance(primary, dict) else None,
                shadow.get("implementation") if isinstance(shadow, dict) else None,
                status,
            )
        except Exception:
            return None, None, "error"

    legacy = (
        ("slope_report_rs_shadow_compare.txt", "python", "rust"),
        ("slope_report_py_shadow_compare.txt", "rust", "python"),
    )
    for filename, primary_impl, shadow_impl in legacy:
        path = slope_path.parent / filename
        if not path.exists():
            continue
        try:
            first_line = path.read_text(encoding="utf-8").splitlines()[0].strip()
        except (OSError, IndexError, UnicodeError):
            return primary_impl, shadow_impl, "error"
        if first_line == "[slope-shadow] match":
            return primary_impl, shadow_impl, "match"
        if first_line == "[slope-shadow] MISMATCH":
            return primary_impl, shadow_impl, "mismatch"
        return primary_impl, shadow_impl, "error"

    return None, None, "missing"


def _parse_promotion_context(slope_path: Path) -> Tuple[Optional[Path], Dict[str, object]]:
    perf_path = slope_path.parent / "perf_report.json"
    if not perf_path.exists():
        return None, {}
    try:
        payload = _load_json(perf_path)
        meta = payload.get("meta", {})
    except Exception:
        return perf_path, {"parse_error": True}
    if not isinstance(meta, dict):
        return perf_path, {"parse_error": True}
    keys = (
        "perf_env_enforce",
        "perf_require_taskset",
        "perf_env_status",
        "perf_env_governor_actual",
        "perf_env_turbo_source",
        "perf_env_turbo_actual",
        "perf_env_cpu_model",
        "git_sha",
        "git_branch",
        "git_dirty",
        "ci_run_id",
        "ci_run_attempt",
        "controlled_branch",
        "slope_gate_primary_requested",
        "slope_gate_primary_actual",
        "slope_gate_primary_fallback_used",
        "baseline_fingerprint_status",
    )
    return perf_path, {key: meta.get(key) for key in keys}


def _build_run_summary(slope_path: Path, fixed_cost_filenames: List[str]) -> RunSummary:
    slope = _load_json(slope_path)
    sc = _scenario_index(slope)

    any_fail = any(str((s or {}).get("gate", "")).startswith("FAIL") for s in slope.get("scenarios", []))
    retry_class = normalize_retry_class(slope.get("retry_class", ""), any_fail=any_fail)
    retry_recommended = bool(slope.get("retry_recommended", False))

    fixed_path = _find_fixed_cost_peer(slope_path, fixed_cost_filenames)
    fixed_cost_status, fixed_cost_error, low_failed, low_total, cold_gate, perf_avail = _parse_fixed_cost(
        fixed_path
    )

    fusion_runtime_hits = _parse_fusion_hits(slope)
    for rule in KEY_FUSION_RULES:
        fusion_runtime_hits.setdefault(rule, 0)

    run_id = slope_path.parent.name
    mtime_utc = _fmt_ts_utc(slope_path.stat().st_mtime)
    primary_impl, shadow_impl, shadow_status = _parse_shadow_compare(slope_path)
    perf_report_path, promotion_context = _parse_promotion_context(slope_path)

    return RunSummary(
        run_id=run_id,
        slope_path=slope_path,
        fixed_cost_path=fixed_path,
        mtime_utc=mtime_utc,
        retry_class=retry_class,
        retry_recommended=retry_recommended,
        dot_runtime=_scenario_summary(sc.get("dot_runtime_only")),
        dot_trace=_scenario_summary(sc.get("dot_trace_only")),
        map_heavy=_scenario_summary(sc.get("map_heavy_read")),
        map_guard_entry=_scenario_summary(sc.get("map_guard_entry_heavy")),
        fusion_runtime_hits=fusion_runtime_hits,
        fixed_cost_status=fixed_cost_status,
        fixed_cost_error=fixed_cost_error,
        low_n_failed=low_failed,
        low_n_total=low_total,
        cold_gate=cold_gate,
        perf_stat_available=perf_avail,
        slope_primary_impl=primary_impl,
        slope_shadow_impl=shadow_impl,
        shadow_compare_status=shadow_status,
        perf_report_path=perf_report_path,
        promotion_context=promotion_context,
    )


def _fmt_float(v: Optional[float], digits: int = 4) -> str:
    if v is None:
        return "-"
    return f"{v:.{digits}f}"


def _pass_fail_tag(gate: Optional[str]) -> str:
    if gate is None:
        return "-"
    return "PASS" if gate.startswith("PASS") else "FAIL"


def _to_json_report(root: Path, runs: List[RunSummary]) -> dict:
    class_counts = {"pass": 0, "retryable": 0, "hard": 0}
    shadow_counts = {"match": 0, "mismatch": 0, "missing": 0, "error": 0}
    for r in runs:
        class_counts[r.retry_class] = class_counts.get(r.retry_class, 0) + 1
        shadow_counts[r.shadow_compare_status] = shadow_counts.get(r.shadow_compare_status, 0) + 1
    return {
        "meta": {
            "artifacts_root": str(root),
            "run_count": len(runs),
        },
        "retry_class_counts": class_counts,
        "shadow_compare_counts": shadow_counts,
        "runs": [
            {
                "run_id": r.run_id,
                "mtime_utc": r.mtime_utc,
                "retry_class": r.retry_class,
                "retry_recommended": r.retry_recommended,
                "slope_report": str(r.slope_path),
                "fixed_cost_report": None if r.fixed_cost_path is None else str(r.fixed_cost_path),
                "dot_runtime_a_ns_per_elem": r.dot_runtime.a_ns_per_elem,
                "dot_runtime_r2": r.dot_runtime.r2,
                "dot_runtime_gate": r.dot_runtime.gate,
                "dot_trace_a_ns_per_elem": r.dot_trace.a_ns_per_elem,
                "dot_trace_r2": r.dot_trace.r2,
                "dot_trace_gate": r.dot_trace.gate,
                "map_heavy_a_ns_per_elem": r.map_heavy.a_ns_per_elem,
                "map_heavy_r2": r.map_heavy.r2,
                "map_heavy_gate": r.map_heavy.gate,
                "map_guard_entry_a_ns_per_elem": r.map_guard_entry.a_ns_per_elem,
                "map_guard_entry_r2": r.map_guard_entry.r2,
                "map_guard_entry_gate": r.map_guard_entry.gate,
                "fusion_runtime_hits": r.fusion_runtime_hits,
                "fixed_cost_status": r.fixed_cost_status,
                "fixed_cost_error": r.fixed_cost_error,
                "low_n_failed": r.low_n_failed,
                "low_n_total": r.low_n_total,
                "cold_gate": r.cold_gate,
                "perf_stat_available": r.perf_stat_available,
                "slope_primary_impl": r.slope_primary_impl,
                "slope_shadow_impl": r.slope_shadow_impl,
                "shadow_compare_status": r.shadow_compare_status,
                "perf_report": (
                    None if r.perf_report_path is None else str(r.perf_report_path)
                ),
                "promotion_context": r.promotion_context,
            }
            for r in runs
        ],
    }


def _to_markdown_report(root: Path, runs: List[RunSummary]) -> str:
    lines: List[str] = []
    lines.append("# Perf Trend (Last Runs)")
    lines.append("")
    lines.append(f"- artifacts_root: `{root}`")
    lines.append(f"- run_count: `{len(runs)}`")
    shadow_match_count = sum(1 for run in runs if run.shadow_compare_status == "match")
    lines.append(f"- shadow_match: `{shadow_match_count}/{len(runs)}`")
    lines.append("")
    lines.append(
        "| run_id | mtime_utc | retry_class | slope impl | shadow | dot_a | dot_r2 | map_a | guard_map_a | "
        "fuse_add | fuse_mul_acc | fuse_cmp_branch | fixed_cost | low_n | cold | perf_stat |"
    )
    lines.append("|---|---|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|---|---|")
    for r in runs:
        low_n = "-"
        if r.low_n_total is not None and r.low_n_failed is not None:
            low_n = f"{r.low_n_total - r.low_n_failed}/{r.low_n_total} pass"
        cold = _pass_fail_tag(r.cold_gate)
        perf_stat = "-" if r.perf_stat_available is None else ("yes" if r.perf_stat_available else "no")
        fixed_cost = r.fixed_cost_status
        if r.fixed_cost_error:
            fixed_cost = f"{fixed_cost} ({r.fixed_cost_error})"
        lines.append(
            "| {run_id} | {mtime} | {retry} | {impl} | {shadow} | {dot_a} | {dot_r2} | {map_a} | {guard_a} | {f_add} | {f_mul} | {f_cmp} | {fixed_cost} | {low_n} | {cold} | {perf} |".format(
                run_id=r.run_id,
                mtime=r.mtime_utc,
                retry=r.retry_class,
                impl=r.slope_primary_impl or "-",
                shadow=r.shadow_compare_status,
                dot_a=_fmt_float(r.dot_runtime.a_ns_per_elem, 6),
                dot_r2=_fmt_float(r.dot_runtime.r2, 4),
                map_a=_fmt_float(r.map_heavy.a_ns_per_elem, 6),
                guard_a=_fmt_float(r.map_guard_entry.a_ns_per_elem, 6),
                f_add=r.fusion_runtime_hits.get("map_stable_add_local", 0),
                f_mul=r.fusion_runtime_hits.get("map_stable_mul_acc", 0),
                f_cmp=r.fusion_runtime_hits.get("map_stable_cmp_branch", 0),
                fixed_cost=fixed_cost,
                low_n=low_n,
                cold=cold,
                perf=perf_stat,
            )
        )

    if len(runs) >= 2:
        latest = runs[0]
        prev = runs[1]
        lines.append("")
        lines.append("## Delta (latest vs previous)")
        lines.append("")
        if latest.dot_runtime.a_ns_per_elem is not None and prev.dot_runtime.a_ns_per_elem is not None:
            dot_delta = latest.dot_runtime.a_ns_per_elem - prev.dot_runtime.a_ns_per_elem
            lines.append(f"- dot_runtime_only a delta: `{dot_delta:+.6f} ns/elem`")
        if latest.map_heavy.a_ns_per_elem is not None and prev.map_heavy.a_ns_per_elem is not None:
            map_delta = latest.map_heavy.a_ns_per_elem - prev.map_heavy.a_ns_per_elem
            lines.append(f"- map_heavy_read a delta: `{map_delta:+.6f} ns/elem`")
        for rule in ("map_stable_add_local", "map_stable_mul_acc", "map_stable_cmp_branch"):
            dv = latest.fusion_runtime_hits.get(rule, 0) - prev.fusion_runtime_hits.get(rule, 0)
            lines.append(f"- fusion runtime hits delta `{rule}`: `{dv:+d}`")

    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    root = Path(args.artifacts_root).resolve()
    out_json = Path(args.out_json).resolve()
    out_md = Path(args.out_md).resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)

    slope_filenames = _parse_csv(args.slope_filenames)
    fixed_cost_filenames = _parse_csv(args.fixed_cost_filenames)
    slope_reports = _find_slope_reports_multi(root, slope_filenames)
    if not slope_reports:
        msg = f"[trend] no slope artifacts found under: {root}"
        if args.strict:
            print(msg)
            return 1
        report = {
            "meta": {"artifacts_root": str(root), "run_count": 0},
            "retry_class_counts": {
                RETRY_CLASS_PASS: 0,
                RETRY_CLASS_RETRYABLE: 0,
                RETRY_CLASS_HARD: 0,
            },
            "shadow_compare_counts": {
                "match": 0,
                "mismatch": 0,
                "missing": 0,
                "error": 0,
            },
            "runs": [],
        }
        out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        out_md.write_text("# Perf Trend (Last Runs)\n\n- run_count: `0`\n", encoding="utf-8")
        print(msg)
        return 0

    selected = slope_reports[: max(1, args.limit)]
    runs = [_build_run_summary(path, fixed_cost_filenames) for path in selected]

    json_report = _to_json_report(root, runs)
    md_report = _to_markdown_report(root, runs)
    out_json.write_text(json.dumps(json_report, indent=2), encoding="utf-8")
    out_md.write_text(md_report + "\n", encoding="utf-8")

    print(f"[trend] wrote {out_json}")
    print(f"[trend] wrote {out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
