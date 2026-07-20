#!/usr/bin/env python3
"""Warn/enforce policy checks from deopt telemetry artifacts.

Default behavior is warn-only (exit 0). Use --enforce to fail on policy issues.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Dict, List, Tuple


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Evaluate deopt telemetry policy checks")
    p.add_argument("--deopt-report", default="target/perf/deopt_report.json")
    p.add_argument("--max-summary-deopt-rate-pct", type=float, default=1.0)
    p.add_argument("--max-summary-guard-fail-rate-pct", type=float, default=0.5)
    p.add_argument("--max-total-clones", type=int, default=256)
    p.add_argument("--max-scenario-clones", type=int, default=8)
    p.add_argument("--max-unknown-deopt-reasons", type=int, default=0)
    p.add_argument("--max-unknown-guard-reasons", type=int, default=0)
    p.add_argument("--min-total-hits-for-rate-checks", type=int, default=1000)
    p.add_argument("--enforce", action="store_true")
    p.add_argument("--out-json", default="target/perf/deopt_warn_report.json")
    p.add_argument("--out-md", default="target/perf/deopt_warn_report.md")
    return p.parse_args()


def safe_float(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def safe_int(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def push_check(
    checks: List[Dict],
    name: str,
    observed: object,
    threshold: object,
    comparator: str,
    ok: bool,
    detail: str,
) -> None:
    checks.append(
        {
            "name": name,
            "observed": observed,
            "threshold": threshold,
            "comparator": comparator,
            "ok": bool(ok),
            "detail": detail,
        }
    )


def status_from_checks(checks: List[Dict]) -> Tuple[str, int]:
    failed = sum(1 for c in checks if not c.get("ok", False))
    if failed == 0:
        return "pass", 0
    return "warn", failed


def render_markdown(payload: Dict) -> str:
    checks = payload.get("checks", [])
    summary = payload.get("summary", {})
    thresholds = payload.get("thresholds", {})

    lines: List[str] = []
    lines.append("# Deopt Warn Gate Report")
    lines.append("")
    lines.append(f"- generated_at_utc: `{payload.get('generated_at_utc', '')}`")
    lines.append(f"- gate: `{payload.get('gate', '')}`")
    lines.append(f"- status: `{payload.get('status', '')}`")
    lines.append(f"- enforce: `{payload.get('enforce', False)}`")
    lines.append(f"- warnings: `{payload.get('warnings', 0)}`")
    lines.append(f"- deopt_report: `{payload.get('deopt_report', '')}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- total_hits: `{summary.get('total_hits', 0)}`")
    lines.append(f"- total_deopts: `{summary.get('total_deopts', 0)}`")
    lines.append(f"- deopt_rate_pct: `{safe_float(summary.get('deopt_rate_pct', 0.0)):.4f}`")
    lines.append(f"- guard_checks_total: `{summary.get('guard_checks_total', 0)}`")
    lines.append(f"- guard_fail_total: `{summary.get('guard_fail_total', 0)}`")
    lines.append(f"- guard_fail_rate_pct: `{safe_float(summary.get('guard_fail_rate_pct', 0.0)):.4f}`")
    lines.append(f"- total_clones: `{summary.get('total_clones', 0)}`")
    lines.append("")
    lines.append("## Thresholds")
    lines.append("")
    lines.append(f"- max_summary_deopt_rate_pct: `{thresholds.get('max_summary_deopt_rate_pct', 0)}`")
    lines.append(
        f"- max_summary_guard_fail_rate_pct: `{thresholds.get('max_summary_guard_fail_rate_pct', 0)}`"
    )
    lines.append(f"- max_total_clones: `{thresholds.get('max_total_clones', 0)}`")
    lines.append(f"- max_scenario_clones: `{thresholds.get('max_scenario_clones', 0)}`")
    lines.append(f"- max_unknown_deopt_reasons: `{thresholds.get('max_unknown_deopt_reasons', 0)}`")
    lines.append(f"- max_unknown_guard_reasons: `{thresholds.get('max_unknown_guard_reasons', 0)}`")
    lines.append(
        f"- min_total_hits_for_rate_checks: `{thresholds.get('min_total_hits_for_rate_checks', 0)}`"
    )
    lines.append("")
    lines.append("## Checks")
    lines.append("")
    lines.append("| check | observed | threshold | cmp | gate | detail |")
    lines.append("|---|---:|---:|---|---|---|")
    if checks:
        for c in checks:
            gate = "PASS" if c.get("ok", False) else "WARN"
            lines.append(
                "| {name} | {observed} | {threshold} | {cmp} | {gate} | {detail} |".format(
                    name=c.get("name", ""),
                    observed=c.get("observed", ""),
                    threshold=c.get("threshold", ""),
                    cmp=c.get("comparator", ""),
                    gate=gate,
                    detail=c.get("detail", ""),
                )
            )
    else:
        lines.append("| - | - | - | - | PASS | no checks |")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    report_path = Path(args.deopt_report).resolve()
    out_json = Path(args.out_json).resolve()
    out_md = Path(args.out_md).resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)

    checks: List[Dict] = []
    generated_at = dt.datetime.now(tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    summary: Dict = {
        "total_hits": 0,
        "total_deopts": 0,
        "deopt_rate_pct": 0.0,
        "guard_checks_total": 0,
        "guard_fail_total": 0,
        "guard_fail_rate_pct": 0.0,
        "total_clones": 0,
    }

    unknown_deopt_count = 0
    unknown_guard_count = 0
    max_scenario_clone_observed = 0

    if not report_path.exists():
        push_check(
            checks,
            "deopt_report_present",
            0,
            1,
            "==",
            False,
            f"missing deopt report: {report_path}",
        )
    else:
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception as exc:
            push_check(
                checks,
                "deopt_report_parse",
                "error",
                "ok",
                "==",
                False,
                f"invalid JSON: {exc}",
            )
            payload = {}

        loaded_summary = payload.get("summary", {})
        if isinstance(loaded_summary, dict):
            summary.update(loaded_summary)

        total_hits = safe_int(summary.get("total_hits", 0))
        total_clones = safe_int(summary.get("total_clones", 0))
        deopt_rate_pct = safe_float(summary.get("deopt_rate_pct", 0.0))
        guard_fail_rate_pct = safe_float(summary.get("guard_fail_rate_pct", 0.0))

        push_check(
            checks,
            "total_clones",
            total_clones,
            args.max_total_clones,
            "<=",
            total_clones <= args.max_total_clones,
            "aggregate clone cap",
        )

        scenarios = payload.get("scenarios", [])
        if isinstance(scenarios, list):
            for row in scenarios:
                if not isinstance(row, dict):
                    continue
                c = safe_int(row.get("clone_count", 0))
                if c > max_scenario_clone_observed:
                    max_scenario_clone_observed = c
        push_check(
            checks,
            "max_scenario_clones",
            max_scenario_clone_observed,
            args.max_scenario_clones,
            "<=",
            max_scenario_clone_observed <= args.max_scenario_clones,
            "largest clone count among scenarios",
        )

        top_deopt = payload.get("top_deopt_reasons", [])
        if isinstance(top_deopt, list):
            for row in top_deopt:
                if not isinstance(row, dict):
                    continue
                if str(row.get("reason", "")).strip() == "unknown_reason":
                    unknown_deopt_count += safe_int(row.get("count", 0))

        top_guard = payload.get("top_guard_failures", [])
        if isinstance(top_guard, list):
            for row in top_guard:
                if not isinstance(row, dict):
                    continue
                if str(row.get("reason", "")).strip() == "unknown_reason":
                    unknown_guard_count += safe_int(row.get("count", 0))

        push_check(
            checks,
            "unknown_deopt_reasons",
            unknown_deopt_count,
            args.max_unknown_deopt_reasons,
            "<=",
            unknown_deopt_count <= args.max_unknown_deopt_reasons,
            "unknown_reason count in top_deopt_reasons",
        )
        push_check(
            checks,
            "unknown_guard_reasons",
            unknown_guard_count,
            args.max_unknown_guard_reasons,
            "<=",
            unknown_guard_count <= args.max_unknown_guard_reasons,
            "unknown_reason count in top_guard_failures",
        )

        if total_hits < args.min_total_hits_for_rate_checks:
            push_check(
                checks,
                "summary_deopt_rate_pct",
                f"{deopt_rate_pct:.4f}",
                f"{args.max_summary_deopt_rate_pct:.4f}",
                "<=",
                True,
                f"skipped: total_hits={total_hits} < min_total_hits_for_rate_checks={args.min_total_hits_for_rate_checks}",
            )
            push_check(
                checks,
                "summary_guard_fail_rate_pct",
                f"{guard_fail_rate_pct:.4f}",
                f"{args.max_summary_guard_fail_rate_pct:.4f}",
                "<=",
                True,
                f"skipped: total_hits={total_hits} < min_total_hits_for_rate_checks={args.min_total_hits_for_rate_checks}",
            )
        else:
            push_check(
                checks,
                "summary_deopt_rate_pct",
                f"{deopt_rate_pct:.4f}",
                f"{args.max_summary_deopt_rate_pct:.4f}",
                "<=",
                deopt_rate_pct <= args.max_summary_deopt_rate_pct,
                "summary deopt rate cap",
            )
            push_check(
                checks,
                "summary_guard_fail_rate_pct",
                f"{guard_fail_rate_pct:.4f}",
                f"{args.max_summary_guard_fail_rate_pct:.4f}",
                "<=",
                guard_fail_rate_pct <= args.max_summary_guard_fail_rate_pct,
                "summary guard-fail rate cap",
            )

    status, warnings = status_from_checks(checks)
    gate = "PASS" if warnings == 0 else ("FAIL" if args.enforce else "WARN")
    rc = 1 if (warnings > 0 and args.enforce) else 0

    output = {
        "generated_at_utc": generated_at,
        "deopt_report": str(report_path),
        "enforce": bool(args.enforce),
        "gate": gate,
        "status": status,
        "warnings": warnings,
        "thresholds": {
            "max_summary_deopt_rate_pct": float(args.max_summary_deopt_rate_pct),
            "max_summary_guard_fail_rate_pct": float(args.max_summary_guard_fail_rate_pct),
            "max_total_clones": int(args.max_total_clones),
            "max_scenario_clones": int(args.max_scenario_clones),
            "max_unknown_deopt_reasons": int(args.max_unknown_deopt_reasons),
            "max_unknown_guard_reasons": int(args.max_unknown_guard_reasons),
            "min_total_hits_for_rate_checks": int(args.min_total_hits_for_rate_checks),
        },
        "summary": summary,
        "checks": checks,
    }

    out_json.write_text(json.dumps(output, indent=2), encoding="utf-8")
    out_md.write_text(render_markdown(output) + "\n", encoding="utf-8")
    print(f"[deopt-warn] {gate} ({status}, warnings={warnings})")
    print(f"[deopt-warn] wrote {out_json}")
    print(f"[deopt-warn] wrote {out_md}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
