#!/usr/bin/env python3
"""Render deopt/guard telemetry artifacts from benchrt profile JSON files."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build deopt telemetry artifacts")
    p.add_argument(
        "--profiles-root",
        default="target/perf",
        help="Directory containing benchrt profile JSON artifacts",
    )
    p.add_argument(
        "--profile-glob",
        default="*.naux.profile.json,*_check.json",
        help="Comma-separated glob patterns scanned under profiles root",
    )
    p.add_argument(
        "--slope-report",
        default="",
        help="Optional slope_report.json path for context",
    )
    p.add_argument(
        "--fixed-cost-report",
        default="",
        help="Optional fixed_cost_report.json path for context",
    )
    p.add_argument(
        "--out-json",
        default="target/perf/deopt_report.json",
        help="Output JSON report path",
    )
    p.add_argument(
        "--out-md",
        default="target/perf/deopt_report.md",
        help="Output markdown report path",
    )
    return p.parse_args()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def is_benchrt_profile(payload: dict) -> bool:
    return isinstance(payload, dict) and "trace_count" in payload and "total_deopts" in payload


def parse_globs(raw: str) -> List[str]:
    return [g.strip() for g in raw.split(",") if g.strip()]


def discover_profile_files(root: Path, globs: Iterable[str]) -> List[Path]:
    files: List[Path] = []
    if not root.exists():
        return files
    for pattern in globs:
        files.extend(path for path in root.glob(pattern) if path.is_file())
    return sorted(set(files))


def scenario_name(path: Path) -> str:
    name = path.name
    if name.endswith(".naux.profile.json"):
        return name[: -len(".naux.profile.json")]
    if name.endswith(".json"):
        return name[: -len(".json")]
    return name


def share_pct(count: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return (count * 100.0) / total


def parse_optional_json(path_str: str) -> dict:
    if not path_str:
        return {}
    path = Path(path_str)
    if not path.exists():
        return {}
    try:
        payload = load_json(path)
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def main() -> int:
    args = parse_args()
    root = Path(args.profiles_root).resolve()
    out_json = Path(args.out_json).resolve()
    out_md = Path(args.out_md).resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)

    files = discover_profile_files(root, parse_globs(args.profile_glob))

    scenario_rows: List[dict] = []
    trace_rows: List[dict] = []
    deopt_counts: Dict[str, int] = {}
    guard_fail_counts: Dict[Tuple[int, str], int] = {}
    fingerprints: Dict[str, int] = {}

    total_hits = 0
    total_deopts = 0
    total_guard_checks = 0
    total_guard_fails = 0
    total_clones = 0

    for path in files:
        try:
            payload = load_json(path)
        except Exception:
            continue
        if not is_benchrt_profile(payload):
            continue

        name = scenario_name(path)
        trace_count = int(payload.get("trace_count", 0) or 0)
        hot_trace_id = int(payload.get("hot_trace_id", 0) or 0)
        hits = int(payload.get("total_hits", 0) or 0)
        deopts = int(payload.get("total_deopts", 0) or 0)
        guard_checks = int(payload.get("guard_checks_total", 0) or 0)
        guard_fails = int(payload.get("guard_fail_total", 0) or 0)
        avg_hot_code = float(payload.get("avg_hot_code_bytes", 0.0) or 0.0)
        max_hot_code = int(payload.get("max_hot_code_bytes", 0) or 0)
        by_trace = payload.get("by_trace", [])
        if not isinstance(by_trace, list):
            by_trace = []
        deopt_reasons = payload.get("deopt_reasons", [])
        if not isinstance(deopt_reasons, list):
            deopt_reasons = []
        guard_fails_by_guard = payload.get("guard_fails_by_guard", [])
        if not isinstance(guard_fails_by_guard, list):
            guard_fails_by_guard = []
        fusion_hits = payload.get("fusion_hits_by_rule", [])
        if not isinstance(fusion_hits, list):
            fusion_hits = []
        scenario_fusion_runtime_hits: Dict[str, int] = {}

        fp = payload.get("build_fingerprint", {})
        if isinstance(fp, dict):
            key = (
                f"{fp.get('git_sha', 'unknown')}|"
                f"{fp.get('rustc_version', 'unknown')}|"
                f"{fp.get('opt_level', 'unknown')}"
            )
            fingerprints[key] = fingerprints.get(key, 0) + 1

        loop_to_trace_ids: Dict[int, set] = {}
        for row in by_trace:
            if not isinstance(row, dict):
                continue
            trace_id = int(row.get("trace_id", 0) or 0)
            loop_header = int(row.get("loop_header", 0) or 0)
            row_hits = int(row.get("hits", 0) or 0)
            row_deopts = int(row.get("deopts", 0) or 0)
            row_guard_checks = int(row.get("guard_checks", 0) or 0)
            row_guard_fails = int(row.get("guard_fails", 0) or 0)
            runtime_deopts = int(row.get("runtime_deopts", 0) or 0)
            first_seen = int(row.get("first_seen_ts_ms", 0) or 0)
            last_seen = int(row.get("last_seen_ts_ms", first_seen) or first_seen)
            lifetime = int(row.get("trace_lifetime_ms", 0) or 0)
            is_hot = bool(row.get("is_hot", False))

            loop_to_trace_ids.setdefault(loop_header, set()).add(trace_id)
            trace_rows.append(
                {
                    "scenario": name,
                    "trace_id": trace_id,
                    "loop_header": loop_header,
                    "is_hot": is_hot,
                    "hits": row_hits,
                    "deopts": row_deopts,
                    "deopt_rate_pct": share_pct(row_deopts, row_hits),
                    "guard_checks": row_guard_checks,
                    "guard_fails": row_guard_fails,
                    "guard_fail_rate_pct": share_pct(row_guard_fails, row_guard_checks),
                    "runtime_deopts": runtime_deopts,
                    "first_seen_ts_ms": first_seen,
                    "last_seen_ts_ms": last_seen,
                    "trace_lifetime_ms": lifetime,
                }
            )

        scenario_clone_count = 0
        for ids in loop_to_trace_ids.values():
            scenario_clone_count += max(0, len(ids) - 1)

        for row in deopt_reasons:
            if not isinstance(row, dict):
                continue
            reason = str(row.get("reason", "")).strip()
            count = int(row.get("count", 0) or 0)
            if not reason:
                reason = "unknown_reason"
            deopt_counts[reason] = deopt_counts.get(reason, 0) + max(0, count)

        for row in guard_fails_by_guard:
            if not isinstance(row, dict):
                continue
            guard_id = int(row.get("guard_id", 0) or 0)
            reason = str(row.get("reason", "")).strip() or "unknown_reason"
            count = int(row.get("count", 0) or 0)
            key = (guard_id, reason)
            guard_fail_counts[key] = guard_fail_counts.get(key, 0) + max(0, count)

        for row in fusion_hits:
            if not isinstance(row, dict):
                continue
            rule = str(row.get("rule", "")).strip()
            if not rule:
                continue
            scenario_fusion_runtime_hits[rule] = scenario_fusion_runtime_hits.get(rule, 0) + int(
                row.get("runtime_hits", 0) or 0
            )

        scenario_rows.append(
            {
                "scenario": name,
                "profile_path": str(path),
                "trace_count": trace_count,
                "hot_trace_id": hot_trace_id,
                "total_hits": hits,
                "total_deopts": deopts,
                "deopt_rate_pct": share_pct(deopts, hits),
                "guard_checks_total": guard_checks,
                "guard_fail_total": guard_fails,
                "guard_fail_rate_pct": share_pct(guard_fails, guard_checks),
                "clone_count": scenario_clone_count,
                "avg_hot_code_bytes": avg_hot_code,
                "max_hot_code_bytes": max_hot_code,
                "fusion_runtime_hits": {
                    str(k): int(v)
                    for k, v in sorted(scenario_fusion_runtime_hits.items())
                },
            }
        )

        total_hits += hits
        total_deopts += deopts
        total_guard_checks += guard_checks
        total_guard_fails += guard_fails
        total_clones += scenario_clone_count

    scenario_rows.sort(
        key=lambda r: (
            -int(r["total_deopts"]),
            -float(r["deopt_rate_pct"]),
            str(r["scenario"]),
        )
    )
    trace_rows.sort(
        key=lambda r: (
            -int(r["deopts"]),
            -float(r["deopt_rate_pct"]),
            -int(r["hits"]),
            str(r["scenario"]),
            int(r["loop_header"]),
        )
    )

    top_deopt_reasons = [
        {
            "reason": reason,
            "count": count,
            "share_pct": share_pct(count, max(1, total_deopts)),
        }
        for reason, count in sorted(deopt_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    top_guard_fails = [
        {
            "guard_id": gid,
            "reason": reason,
            "count": count,
            "share_pct": share_pct(count, max(1, total_guard_fails)),
        }
        for (gid, reason), count in sorted(
            guard_fail_counts.items(), key=lambda kv: (-kv[1], kv[0][0], kv[0][1])
        )
    ]

    slope_report = parse_optional_json(args.slope_report)
    fixed_cost_report = parse_optional_json(args.fixed_cost_report)

    generated_at = dt.datetime.now(tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report = {
        "meta": {
            "generated_at_utc": generated_at,
            "profiles_root": str(root),
            "profile_glob": parse_globs(args.profile_glob),
            "profiles_discovered": len(files),
            "profiles_processed": len(scenario_rows),
            "build_fingerprints": [
                {"fingerprint": key, "count": count}
                for key, count in sorted(fingerprints.items(), key=lambda kv: (-kv[1], kv[0]))
            ],
        },
        "summary": {
            "total_hits": total_hits,
            "total_deopts": total_deopts,
            "deopt_rate_pct": share_pct(total_deopts, total_hits),
            "guard_checks_total": total_guard_checks,
            "guard_fail_total": total_guard_fails,
            "guard_fail_rate_pct": share_pct(total_guard_fails, total_guard_checks),
            "total_clones": total_clones,
            "top_deopt_reasons_count": len(top_deopt_reasons),
            "top_guard_failures_count": len(top_guard_fails),
        },
        "top_deopt_reasons": top_deopt_reasons,
        "top_guard_failures": top_guard_fails,
        "scenarios": scenario_rows,
        "traces": trace_rows,
        "context": {
            "slope_report_present": bool(slope_report),
            "fixed_cost_report_present": bool(fixed_cost_report),
            "slope_retry_class": str(slope_report.get("retry_class", "")) if slope_report else "",
            "fixed_cost_perf_stat_available": (
                bool((fixed_cost_report.get("perf_stat") or {}).get("available", False))
                if fixed_cost_report
                else False
            ),
        },
    }

    md_lines = [
        "# Deopt Report",
        "",
        f"- generated_at_utc: `{generated_at}`",
        f"- profiles_discovered: `{len(files)}`",
        f"- profiles_processed: `{len(scenario_rows)}`",
        f"- total_hits: `{total_hits}`",
        f"- total_deopts: `{total_deopts}`",
        f"- deopt_rate_pct: `{report['summary']['deopt_rate_pct']:.4f}`",
        f"- guard_checks_total: `{total_guard_checks}`",
        f"- guard_fail_total: `{total_guard_fails}`",
        f"- guard_fail_rate_pct: `{report['summary']['guard_fail_rate_pct']:.4f}`",
        f"- total_clones: `{total_clones}`",
        "",
        "## Top Deopt Reasons",
        "",
        "| reason | count | share % |",
        "|---|---:|---:|",
    ]
    if top_deopt_reasons:
        for row in top_deopt_reasons[:10]:
            md_lines.append(
                f"| {row['reason']} | {row['count']} | {row['share_pct']:.2f} |"
            )
    else:
        md_lines.append("| - | 0 | 0.00 |")

    md_lines.extend(
        [
            "",
            "## Top Guard Failures",
            "",
            "| guard_id | reason | count | share % |",
            "|---:|---|---:|---:|",
        ]
    )
    if top_guard_fails:
        for row in top_guard_fails[:10]:
            md_lines.append(
                f"| {row['guard_id']} | {row['reason']} | {row['count']} | {row['share_pct']:.2f} |"
            )
    else:
        md_lines.append("| 0 | - | 0 | 0.00 |")

    md_lines.extend(
        [
            "",
            "## Scenario Breakdown",
            "",
            "| scenario | traces | hits | deopts | deopt % | guard checks | guard fails | guard fail % | clones | hot trace | avg hot bytes |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    if scenario_rows:
        for row in scenario_rows:
            md_lines.append(
                "| {scenario} | {trace_count} | {total_hits} | {total_deopts} | {deopt_rate_pct:.2f} | "
                "{guard_checks_total} | {guard_fail_total} | {guard_fail_rate_pct:.2f} | {clone_count} | "
                "{hot_trace_id} | {avg_hot_code_bytes:.2f} |".format(**row)
            )
    else:
        md_lines.append("| - | 0 | 0 | 0 | 0.00 | 0 | 0 | 0.00 | 0 | 0 | 0.00 |")

    md_lines.extend(
        [
            "",
            "## Trace Breakdown",
            "",
            "| scenario | trace_id | loop_header | hot | hits | deopts | deopt % | guard checks | guard fails | guard fail % | runtime deopts | lifetime ms |",
            "|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    if trace_rows:
        for row in trace_rows[:50]:
            md_lines.append(
                "| {scenario} | {trace_id} | {loop_header} | {is_hot} | {hits} | {deopts} | {deopt_rate_pct:.2f} | "
                "{guard_checks} | {guard_fails} | {guard_fail_rate_pct:.2f} | {runtime_deopts} | {trace_lifetime_ms} |".format(
                    **row
                )
            )
    else:
        md_lines.append("| - | 0 | 0 | false | 0 | 0 | 0.00 | 0 | 0 | 0.00 | 0 | 0 |")

    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    out_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(f"[deopt-artifacts] wrote {out_json}")
    print(f"[deopt-artifacts] wrote {out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
