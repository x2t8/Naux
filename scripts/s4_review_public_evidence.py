#!/usr/bin/env python3
"""Replay a downloaded S4 archive through WP8R/WP8N/WP8O without admitting a claim.

This unsealed convenience CLI emits the original WP8R intake and WP8O candidate
reports, concatenated unchanged. It does not download or execute the artifacts.
Exit codes: 0 = threshold pass (not claim admission), 1 = invalid evidence or
identity mismatch, 2 = threshold failure or command-line usage error.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import s4_register_residency_paired_threshold as wp8o
import s4_register_residency_public_bundle as wp8r


def _root_hash(value: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise argparse.ArgumentTypeError("expected 64 lowercase hexadecimal characters")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--expected-bundle-root", type=_root_hash)
    parser.add_argument("--expected-threshold-root", type=_root_hash)
    arguments = parser.parse_args(argv)

    try:
        public_admission = wp8r.validate(arguments.root)
        threshold_admission = wp8o.validate(arguments.root)
        intake = wp8r.intake_archive(
            arguments.archive, arguments.receipt, public_admission
        )
        if (
            arguments.expected_bundle_root is not None
            and intake.replay.manifest.root != arguments.expected_bundle_root
        ):
            raise ValueError("bundle root does not match --expected-bundle-root")

        # Reuse the verified in-memory replay, as WP8O.evaluate_bundle does.
        # Keep the sealed validators and their report formats untouched.
        _decisions, candidate_report, candidate_root, passed = wp8o._candidate_report(
            threshold_admission, intake.replay
        )
        if (
            arguments.expected_threshold_root is not None
            and candidate_root != arguments.expected_threshold_root
        ):
            raise ValueError("threshold root does not match --expected-threshold-root")

        # Buffer until every check succeeds: an invalid identity emits no report.
        sys.stdout.buffer.write(intake.report + candidate_report)
        return 0 if passed else 2
    except (
        wp8r.PublicBundleError,
        wp8r.wp8q.PublicProtocolError,
        wp8r.wp8q.wp8p.ClaimAdmissionError,
        wp8o.PairedThresholdError,
        wp8r.wp8n.PairedEvidenceError,
        wp8r.wp8n.wp8m.PairedRunnerError,
        wp8r.wp8n.wp8m.wp8k.CandidateRunnerError,
        wp8r.wp8n.wp8m.wp7c.RunnerError,
        OSError,
        ValueError,
    ) as error:
        print(f"S4 public evidence review failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
