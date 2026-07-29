#!/usr/bin/env python3
"""Compare two slope-gate reports and emit promotion evidence.

The primary and shadow implementations must make the same policy decision for
every scenario and for the run-level retry class. The comparison intentionally
does not compare floating-point measurements: the shadow gate replays the
primary report, so this artifact answers whether Python and Rust interpret the
same evidence identically.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Tuple


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare primary and shadow slope-gate reports")
    parser.add_argument("--primary-json", required=True, help="Primary slope_report.json")
    parser.add_argument("--shadow-json", required=True, help="Shadow slope report")
    parser.add_argument("--primary-impl", required=True, choices=("python", "rust"))
    parser.add_argument("--shadow-impl", required=True, choices=("python", "rust"))
    parser.add_argument("--out-json", required=True, help="Structured comparison artifact")
    parser.add_argument("--out-text", required=True, help="Human-readable comparison artifact")
    return parser.parse_args()


def scenario_gates(report: dict) -> Dict[str, object]:
    gates: Dict[str, object] = {}
    for scenario in report.get("scenarios", []):
        if not isinstance(scenario, dict):
            continue
        name = scenario.get("name")
        if isinstance(name, str) and name:
            gates[name] = scenario.get("gate")
    return gates


def compare_reports(
    primary: dict,
    shadow: dict,
    *,
    primary_impl: str,
    shadow_impl: str,
    primary_path: Path,
    shadow_path: Path,
) -> dict:
    primary_retry = primary.get("retry_class")
    shadow_retry = shadow.get("retry_class")
    primary_gates = scenario_gates(primary)
    shadow_gates = scenario_gates(shadow)

    mismatches: List[str] = []
    for name in sorted(set(primary_gates) | set(shadow_gates)):
        primary_gate = primary_gates.get(name)
        shadow_gate = shadow_gates.get(name)
        if primary_gate != shadow_gate:
            mismatches.append(
                f"scenario gate mismatch: {name}: "
                f"primary={primary_gate!r} shadow={shadow_gate!r}"
            )

    if primary_retry != shadow_retry:
        mismatches.append(
            f"retry_class mismatch: primary={primary_retry!r} shadow={shadow_retry!r}"
        )

    status = "match" if not mismatches else "mismatch"
    return {
        "schema_version": 1,
        "status": status,
        "gate": "PASS" if status == "match" else "FAIL",
        "primary": {
            "implementation": primary_impl,
            "report": str(primary_path),
            "retry_class": primary_retry,
            "scenario_gates": primary_gates,
        },
        "shadow": {
            "implementation": shadow_impl,
            "report": str(shadow_path),
            "retry_class": shadow_retry,
            "scenario_gates": shadow_gates,
        },
        "mismatches": mismatches,
    }


def render_text(payload: dict) -> str:
    status = str(payload["status"])
    primary = payload["primary"]
    shadow = payload["shadow"]
    lines = [
        f"[slope-shadow] {status.upper() if status != 'match' else 'match'}",
        (
            f"primary={primary['implementation']} "
            f"shadow={shadow['implementation']}"
        ),
        f"retry_class={primary['retry_class']}",
    ]
    if payload["mismatches"]:
        lines.extend(str(item) for item in payload["mismatches"])
    else:
        for name, gate in sorted(primary["scenario_gates"].items()):
            lines.append(f"{name}: {gate}")
    return "\n".join(lines) + "\n"


def load_reports(primary_path: Path, shadow_path: Path) -> Tuple[dict, dict]:
    primary = json.loads(primary_path.read_text(encoding="utf-8"))
    shadow = json.loads(shadow_path.read_text(encoding="utf-8"))
    if not isinstance(primary, dict) or not isinstance(shadow, dict):
        raise ValueError("slope reports must be JSON objects")
    return primary, shadow


def main() -> int:
    args = parse_args()
    primary_path = Path(args.primary_json).resolve()
    shadow_path = Path(args.shadow_json).resolve()
    out_json = Path(args.out_json).resolve()
    out_text = Path(args.out_text).resolve()

    primary, shadow = load_reports(primary_path, shadow_path)
    payload = compare_reports(
        primary,
        shadow,
        primary_impl=args.primary_impl,
        shadow_impl=args.shadow_impl,
        primary_path=primary_path,
        shadow_path=shadow_path,
    )

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_text.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    out_text.write_text(render_text(payload), encoding="utf-8")

    print(f"[slope-shadow] {payload['status']}")
    print(f"[slope-shadow] wrote {out_json}")
    print(f"[slope-shadow] wrote {out_text}")
    return 0 if payload["status"] == "match" else 1


if __name__ == "__main__":
    raise SystemExit(main())
