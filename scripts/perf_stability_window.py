#!/usr/bin/env python3
"""Evaluate stability readiness from trend artifacts.

This gate is intentionally policy-only:
- input: trend_report.json
- output: stability_window_report.{json,md}
- it does not influence trend generation or slope/fixed-cost measurement
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

from perf_status import (
    RETRY_CLASS_HARD,
    RETRY_CLASS_PASS,
    RETRY_CLASS_RETRYABLE,
    STABILITY_STATUS_FAIL,
    STABILITY_STATUS_MISSING_TREND,
    STABILITY_STATUS_PASS,
    STABILITY_STATUS_WARMING_UP,
    normalize_retry_class,
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Evaluate stability window from trend report")
    p.add_argument("--trend-json", default="target/perf/trend_report.json", help="Path to trend_report.json")
    p.add_argument("--window", type=int, default=7, help="How many most-recent runs to evaluate")
    p.add_argument("--min-runs", type=int, default=7, help="Minimum runs required for strict evaluation")
    p.add_argument("--max-retryable-pct", type=float, default=5.0, help="Max retryable percentage allowed")
    p.add_argument("--max-hard-count", type=int, default=0, help="Max hard failures allowed in window")
    p.add_argument("--required-rules", default="", help="Comma-separated fusion rules expected to hit")
    p.add_argument("--min-rule-hit-pct", type=float, default=90.0, help="Min hit ratio for each required rule")
    p.add_argument(
        "--require-shadow-match",
        action="store_true",
        help="Require every run to include a successful primary/shadow slope comparison",
    )
    p.add_argument(
        "--min-shadow-match-pct",
        type=float,
        default=100.0,
        help="Minimum shadow-match percentage across the evaluated window",
    )
    p.add_argument(
        "--fail-on-insufficient-runs",
        action="store_true",
        help="Fail when run count in window is less than --min-runs",
    )
    p.add_argument("--out-json", default="target/perf/stability_window_report.json", help="Output JSON report path")
    p.add_argument("--out-md", default="target/perf/stability_window_report.md", help="Output markdown report path")
    return p.parse_args()


def parse_csv(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def write_outputs(path_json: Path, path_md: Path, payload: Dict, md: str) -> None:
    path_json.parent.mkdir(parents=True, exist_ok=True)
    path_md.parent.mkdir(parents=True, exist_ok=True)
    path_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    path_md.write_text(md + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()

    trend_path = Path(args.trend_json).resolve()
    out_json = Path(args.out_json).resolve()
    out_md = Path(args.out_md).resolve()

    if not trend_path.exists():
        payload = {
            "status": STABILITY_STATUS_MISSING_TREND,
            "gate": "FAIL",
            "reason": f"trend report not found: {trend_path}",
        }
        md = "\n".join(
            [
                "# Stability Window Report",
                "",
                f"- gate: `FAIL`",
                f"- status: `{STABILITY_STATUS_MISSING_TREND}`",
                f"- reason: `{payload['reason']}`",
            ]
        )
        write_outputs(out_json, out_md, payload, md)
        print(f"[stability] FAIL: {payload['reason']}")
        return 1

    trend = json.loads(trend_path.read_text(encoding="utf-8"))
    runs = trend.get("runs", [])
    if not isinstance(runs, list):
        runs = []
    window_runs = runs[: max(0, int(args.window))]
    run_count = len(window_runs)

    retryable_count = 0
    hard_count = 0
    pass_count = 0
    shadow_match_count = 0
    shadow_mismatch_count = 0
    shadow_missing_count = 0
    shadow_error_count = 0
    for run in window_runs:
        cls = normalize_retry_class((run or {}).get("retry_class", ""))
        if cls == RETRY_CLASS_RETRYABLE:
            retryable_count += 1
        elif cls == RETRY_CLASS_HARD:
            hard_count += 1
        else:
            pass_count += 1
        shadow_status = str((run or {}).get("shadow_compare_status", "missing")).lower()
        if shadow_status == "match":
            shadow_match_count += 1
        elif shadow_status == "mismatch":
            shadow_mismatch_count += 1
        elif shadow_status == "error":
            shadow_error_count += 1
        else:
            shadow_missing_count += 1

    retryable_pct = (100.0 * retryable_count / run_count) if run_count > 0 else 0.0
    shadow_match_pct = (100.0 * shadow_match_count / run_count) if run_count > 0 else 0.0
    shadow_coverage_count = shadow_match_count + shadow_mismatch_count
    shadow_coverage_pct = (100.0 * shadow_coverage_count / run_count) if run_count > 0 else 0.0

    required_rules = parse_csv(args.required_rules)
    rule_stats = []
    for rule in required_rules:
        hit_runs = 0
        for run in window_runs:
            by_rule = (run or {}).get("fusion_runtime_hits", {})
            runtime_hits = 0
            if isinstance(by_rule, dict):
                runtime_hits = int(by_rule.get(rule, 0) or 0)
            if runtime_hits > 0:
                hit_runs += 1
        hit_pct = (100.0 * hit_runs / run_count) if run_count > 0 else 0.0
        rule_stats.append(
            {
                "rule": rule,
                "hit_runs": hit_runs,
                "run_count": run_count,
                "hit_pct": hit_pct,
                "pass": (hit_pct >= args.min_rule_hit_pct) if run_count > 0 else False,
            }
        )

    insufficient_runs = run_count < args.min_runs

    checks = []
    checks.append(
        {
            "name": "run_count",
            "gate": "PASS" if (not insufficient_runs or not args.fail_on_insufficient_runs) else "FAIL",
            "detail": f"{run_count}/{args.min_runs}",
        }
    )
    checks.append(
        {
            "name": "retryable_pct",
            "gate": "PASS" if retryable_pct <= args.max_retryable_pct else "FAIL",
            "detail": f"{retryable_pct:.2f}% <= {args.max_retryable_pct:.2f}%",
        }
    )
    checks.append(
        {
            "name": "hard_count",
            "gate": "PASS" if hard_count <= args.max_hard_count else "FAIL",
            "detail": f"{hard_count} <= {args.max_hard_count}",
        }
    )
    if args.require_shadow_match:
        shadow_ok = (
            run_count > 0
            and shadow_coverage_count == run_count
            and shadow_error_count == 0
            and shadow_match_pct >= args.min_shadow_match_pct
        )
        checks.append(
            {
                "name": "shadow_match_pct",
                "gate": "PASS" if shadow_ok else "FAIL",
                "detail": (
                    f"{shadow_match_pct:.2f}% >= {args.min_shadow_match_pct:.2f}%"
                    f"; coverage={shadow_coverage_count}/{run_count}"
                ),
            }
        )
    for rs in rule_stats:
        checks.append(
            {
                "name": f"rule_hit_pct:{rs['rule']}",
                "gate": "PASS" if rs["pass"] else "FAIL",
                "detail": f"{rs['hit_pct']:.2f}% >= {args.min_rule_hit_pct:.2f}%",
            }
        )

    hard_fail = any(c["gate"] == "FAIL" for c in checks if c["name"] != "run_count")
    insufficient_fail = insufficient_runs and args.fail_on_insufficient_runs

    if hard_fail or insufficient_fail:
        status = STABILITY_STATUS_FAIL
        gate = "FAIL"
        rc = 1
    elif insufficient_runs:
        status = STABILITY_STATUS_WARMING_UP
        gate = "PASS"
        rc = 0
    else:
        status = STABILITY_STATUS_PASS
        gate = "PASS"
        rc = 0

    payload = {
        "status": status,
        "gate": gate,
        "trend_json": str(trend_path),
        "window": int(args.window),
        "min_runs": int(args.min_runs),
        "run_count": run_count,
        "retry_class_counts": {
            RETRY_CLASS_PASS: pass_count,
            RETRY_CLASS_RETRYABLE: retryable_count,
            RETRY_CLASS_HARD: hard_count,
        },
        "retryable_pct": retryable_pct,
        "shadow_compare_counts": {
            "match": shadow_match_count,
            "mismatch": shadow_mismatch_count,
            "missing": shadow_missing_count,
            "error": shadow_error_count,
        },
        "shadow_match_pct": shadow_match_pct,
        "shadow_coverage_pct": shadow_coverage_pct,
        "thresholds": {
            "max_retryable_pct": float(args.max_retryable_pct),
            "max_hard_count": int(args.max_hard_count),
            "min_rule_hit_pct": float(args.min_rule_hit_pct),
            "require_shadow_match": bool(args.require_shadow_match),
            "min_shadow_match_pct": float(args.min_shadow_match_pct),
            "fail_on_insufficient_runs": bool(args.fail_on_insufficient_runs),
        },
        "required_rules": required_rules,
        "rule_stats": rule_stats,
        "checks": checks,
    }

    lines: List[str] = []
    lines.append("# Stability Window Report")
    lines.append("")
    lines.append(f"- gate: `{gate}`")
    lines.append(f"- status: `{status}`")
    lines.append(f"- trend_json: `{trend_path}`")
    lines.append(f"- run_count: `{run_count}` (min `{args.min_runs}`)")
    lines.append(f"- retryable_pct: `{retryable_pct:.2f}%` (max `{args.max_retryable_pct:.2f}%`)")
    lines.append(f"- hard_count: `{hard_count}` (max `{args.max_hard_count}`)")
    lines.append(
        f"- shadow_match_pct: `{shadow_match_pct:.2f}%` "
        f"(coverage `{shadow_coverage_count}/{run_count}`, required `{args.require_shadow_match}`)"
    )
    if required_rules:
        lines.append(f"- required_rules: `{','.join(required_rules)}` (min hit `{args.min_rule_hit_pct:.2f}%`)")
    else:
        lines.append("- required_rules: `-`")
    lines.append("")
    lines.append("| check | gate | detail |")
    lines.append("|---|---|---|")
    for c in checks:
        lines.append(f"| {c['name']} | {c['gate']} | {c['detail']} |")

    if rule_stats:
        lines.append("")
        lines.append("| rule | hit_runs | run_count | hit_pct | gate |")
        lines.append("|---|---:|---:|---:|---|")
        for rs in rule_stats:
            lines.append(
                f"| {rs['rule']} | {rs['hit_runs']} | {rs['run_count']} | {rs['hit_pct']:.2f}% | {'PASS' if rs['pass'] else 'FAIL'} |"
            )

    write_outputs(out_json, out_md, payload, "\n".join(lines))
    print(f"[stability] {gate} ({status})")
    print(f"[stability] wrote {out_json}")
    print(f"[stability] wrote {out_md}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
