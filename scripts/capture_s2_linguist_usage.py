#!/usr/bin/env python3
"""Capture reproducible GitHub searches without treating false positives as adoption."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path


QUERIES = (
    ("raw-extension", "extension:nx -user:x2t8"),
    ("canonical-entry", '"~ rite" extension:nx -user:x2t8'),
    ("standard-output", '"!say" extension:nx -user:x2t8'),
    ("standard-input", '"read_int()" extension:nx -user:x2t8'),
)


def search(query: str) -> dict[str, object]:
    completed = subprocess.run(
        [
            "gh",
            "api",
            "-X",
            "GET",
            "search/code",
            "-f",
            f"q={query}",
            "-f",
            "per_page=100",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "GitHub code search failed")
    payload = json.loads(completed.stdout)
    candidates = [
        {
            "repository": item["repository"]["full_name"],
            "path": item["path"],
            "url": item["html_url"],
        }
        for item in payload.get("items", [])
    ]
    return {
        "query": query,
        "total_count": payload["total_count"],
        "incomplete_results": payload["incomplete_results"],
        "returned_candidates": candidates,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("target/linguist-candidate/USAGE-REPORT.json"),
    )
    args = parser.parse_args(argv)

    try:
        results = {name: search(query) for name, query in QUERIES}
    except (OSError, RuntimeError, json.JSONDecodeError, KeyError) as error:
        print(f"S2 Linguist usage capture: FAIL: {error}", file=sys.stderr)
        return 1

    report = {
        "schema": "naux-s2-linguist-usage-v1",
        "captured_at_utc": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "source": "GitHub REST code search via authenticated gh CLI",
        "excluded_owner": "x2t8",
        "queries": results,
        "assessment": {
            "qualifying_independent_naux_files": None,
            "status": "not-established",
            "reason": (
                "The .nx extension is shared by unrelated projects. Search totals and "
                "signature candidates require human review and are not Linguist eligibility evidence."
            ),
            "upstream_pr": "must-remain-unopened-until-policy-is-satisfied",
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"S2 Linguist usage report: {args.output}")
    for name, result in results.items():
        print(f"  {name}: {result['total_count']} raw match(es)")
    print("Qualifying independent NAUX usage: NOT ESTABLISHED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
