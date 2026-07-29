#!/usr/bin/env python3
"""Fail-closed M1 readiness aggregation.

M1 is ready only when one evidence set proves all three roadmap exits:
- a stable, hard-failure-free multi-run window;
- Rust slope policy running as the actual primary in a controlled CI run;
- a verified, claim-eligible cross-language bundle from the same Git SHA.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

import perf_claim_bundle


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Evaluate Naux M1 readiness")
    parser.add_argument(
        "--trend-json",
        type=Path,
        default=repo_root / "target/perf/trend_report.json",
    )
    parser.add_argument(
        "--stability-json",
        type=Path,
        default=repo_root / "target/perf/stability_window_report.json",
    )
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--min-runs", type=int, default=10)
    parser.add_argument(
        "--out-json",
        type=Path,
        default=repo_root / "target/perf/m1_readiness.json",
    )
    parser.add_argument(
        "--out-md",
        type=Path,
        default=repo_root / "target/perf/m1_readiness.md",
    )
    return parser.parse_args(argv)


def read_json(path: Path, label: str) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"{label} is missing: {path}") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is invalid: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} root must be a JSON object")
    return payload


def _is_enabled(value: object) -> bool:
    return value is True or value == 1 or value == "1"


def _full_git_sha(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 40:
        return False
    return all(char in "0123456789abcdef" for char in value.lower())


def _controlled_rust_primary(run: dict) -> tuple[bool, str]:
    context = run.get("promotion_context")
    if not isinstance(context, dict):
        return False, "promotion_context is missing"
    checks = [
        (run.get("slope_primary_impl") == "rust", "shadow artifact primary is not Rust"),
        (run.get("slope_shadow_impl") == "python", "shadow implementation is not Python"),
        (run.get("shadow_compare_status") == "match", "Rust/Python shadow decision did not match"),
        (
            context.get("slope_gate_primary_requested") == "rust",
            "Rust primary was not requested",
        ),
        (
            context.get("slope_gate_primary_actual") == "rust",
            "Rust was not the actual primary",
        ),
        (
            context.get("slope_gate_primary_fallback_used") is False,
            "primary fallback was used",
        ),
        (_is_enabled(context.get("perf_env_enforce")), "environment enforcement was disabled"),
        (_is_enabled(context.get("perf_require_taskset")), "CPU pinning was not required"),
        (context.get("perf_env_status") == "pass", "performance environment did not pass"),
        (
            context.get("perf_env_governor_actual") == "performance",
            "CPU governor was not performance",
        ),
        (
            (
                context.get("perf_env_turbo_source") == "intel_pstate/no_turbo"
                and str(context.get("perf_env_turbo_actual")) == "1"
            )
            or (
                context.get("perf_env_turbo_source") == "cpufreq/boost"
                and str(context.get("perf_env_turbo_actual")) == "0"
            ),
            "CPU turbo/boost was not disabled",
        ),
        (
            context.get("perf_env_cpu_model")
            not in (None, "", "unknown", "unavailable"),
            "CPU model is missing",
        ),
        (
            context.get("baseline_fingerprint_status") == "pass",
            "baseline fingerprint did not pass",
        ),
        (_full_git_sha(context.get("git_sha")), "controlled run Git SHA is invalid"),
        (context.get("git_dirty") is False, "controlled run worktree was dirty"),
        (
            isinstance(context.get("git_branch"), str)
            and bool(context.get("git_branch")),
            "controlled branch identity is missing",
        ),
        (
            isinstance(context.get("ci_run_id"), str)
            and bool(context.get("ci_run_id")),
            "controlled CI run identity is missing",
        ),
        (
            _is_enabled(context.get("controlled_branch")),
            "run was not admitted as a dedicated controlled branch",
        ),
    ]
    failures = [detail for passed, detail in checks if not passed]
    return not failures, "; ".join(failures) if failures else "controlled Rust primary proven"


def evaluate_readiness(
    trend: dict,
    stability: dict,
    verified_bundle: dict | None,
    *,
    bundle_error: str | None = None,
    input_errors: list[str] | None = None,
    min_runs: int = 10,
) -> dict:
    if min_runs <= 0:
        raise ValueError("min_runs must be positive")
    runs = trend.get("runs")
    if not isinstance(runs, list):
        runs = []
    window = [run for run in runs[:min_runs] if isinstance(run, dict)]
    latest = window[0] if window else {}
    retry_classes = [str(run.get("retry_class", "")) for run in window]
    shadow_statuses = [str(run.get("shadow_compare_status", "")) for run in window]
    rust_primary_ok, rust_primary_detail = _controlled_rust_primary(latest)

    stability_counts = stability.get("retry_class_counts")
    if not isinstance(stability_counts, dict):
        stability_counts = {}
    stability_hard = stability_counts.get("hard")
    stability_run_count = stability.get("run_count")

    bundle_sha = None
    bundle_git_sha = None
    if verified_bundle is not None:
        bundle_sha = verified_bundle.get("sha256")
        report = verified_bundle.get("report")
        if isinstance(report, dict):
            environment = report.get("environment")
            if isinstance(environment, dict):
                bundle_git_sha = environment.get("git_sha")
    promotion_context = latest.get("promotion_context")
    promotion_git_sha = (
        promotion_context.get("git_sha")
        if isinstance(promotion_context, dict)
        else None
    )

    input_errors = [] if input_errors is None else input_errors
    checks: List[Dict[str, object]] = [
        {
            "name": "input_reports",
            "pass": not input_errors,
            "detail": "present and valid" if not input_errors else "; ".join(input_errors),
        },
        {
            "name": "trend_run_count",
            "pass": len(window) == min_runs,
            "detail": f"{len(window)}/{min_runs}",
        },
        {
            "name": "stable_retry_classes",
            "pass": len(window) == min_runs
            and all(retry_class == "pass" for retry_class in retry_classes),
            "detail": f"classes={retry_classes}",
        },
        {
            "name": "shadow_match_window",
            "pass": len(window) == min_runs
            and all(status == "match" for status in shadow_statuses),
            "detail": f"statuses={shadow_statuses}",
        },
        {
            "name": "stability_gate",
            "pass": (
                stability.get("gate") == "PASS"
                and stability.get("status") == "pass"
                and isinstance(stability_run_count, int)
                and stability_run_count >= min_runs
                and stability_hard == 0
                and stability.get("shadow_match_pct") == 100.0
                and stability.get("shadow_coverage_pct") == 100.0
            ),
            "detail": (
                f"gate={stability.get('gate')}, status={stability.get('status')}, "
                f"runs={stability_run_count}, hard={stability_hard}, "
                f"shadow={stability.get('shadow_match_pct')}%, "
                f"coverage={stability.get('shadow_coverage_pct')}%"
            ),
        },
        {
            "name": "controlled_rust_primary",
            "pass": rust_primary_ok,
            "detail": rust_primary_detail,
        },
        {
            "name": "claim_bundle_verified",
            "pass": verified_bundle is not None and bundle_error is None,
            "detail": (
                f"sha256={bundle_sha}"
                if verified_bundle is not None
                else (bundle_error or "bundle verification did not run")
            ),
        },
        {
            "name": "single_commit_evidence",
            "pass": (
                _full_git_sha(promotion_git_sha)
                and promotion_git_sha == bundle_git_sha
            ),
            "detail": (
                f"promotion_sha={promotion_git_sha}, bundle_sha={bundle_git_sha}"
            ),
        },
    ]
    blockers = [
        f"{check['name']}: {check['detail']}"
        for check in checks
        if check["pass"] is not True
    ]
    return {
        "schema_version": 1,
        "gate": "PASS" if not blockers else "FAIL",
        "status": "ready" if not blockers else "blocked",
        "criteria": {
            "minimum_stable_runs": min_runs,
            "maximum_hard_failures": 0,
            "required_shadow_match_pct": 100.0,
            "required_primary": "rust",
            "required_shadow": "python",
            "require_controlled_environment": True,
            "require_same_git_sha": True,
            "require_verified_cross_language_bundle": True,
        },
        "checks": checks,
        "blockers": blockers,
        "evidence": {
            "trend_runs_considered": len(window),
            "promotion_git_sha": promotion_git_sha,
            "bundle_git_sha": bundle_git_sha,
            "bundle_sha256": bundle_sha,
        },
    }


def render_markdown(payload: dict) -> str:
    lines = [
        "# Naux M1 Readiness",
        "",
        f"- gate: `{payload['gate']}`",
        f"- status: `{payload['status']}`",
        "",
        "| check | gate | detail |",
        "|---|---|---|",
    ]
    for check in payload["checks"]:
        detail = str(check["detail"]).replace("|", "\\|")
        lines.append(
            f"| {check['name']} | {'PASS' if check['pass'] else 'FAIL'} | {detail} |"
        )
    if payload["blockers"]:
        lines.extend(["", "## Blockers", ""])
        lines.extend(f"- {blocker}" for blocker in payload["blockers"])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    input_errors = []
    try:
        trend = read_json(args.trend_json.resolve(), "trend report")
    except ValueError as exc:
        trend = {}
        input_errors.append(str(exc))
    try:
        stability = read_json(args.stability_json.resolve(), "stability report")
    except ValueError as exc:
        stability = {}
        input_errors.append(str(exc))

    verified_bundle = None
    bundle_error = None
    try:
        verified_bundle = perf_claim_bundle.verify_bundle(args.bundle)
    except perf_claim_bundle.BundleError as exc:
        bundle_error = str(exc)

    payload = evaluate_readiness(
        trend,
        stability,
        verified_bundle,
        bundle_error=bundle_error,
        input_errors=input_errors,
        min_runs=args.min_runs,
    )
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.out_md.write_text(render_markdown(payload), encoding="utf-8")
    print(f"[m1-readiness] {payload['gate']} ({payload['status']})")
    print(f"[m1-readiness] wrote {args.out_json}")
    print(f"[m1-readiness] wrote {args.out_md}")
    return 0 if payload["gate"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
