from __future__ import annotations

import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import perf_m1_readiness as readiness  # noqa: E402


GIT_SHA = "a" * 40


def valid_run() -> dict:
    return {
        "retry_class": "pass",
        "slope_primary_impl": "rust",
        "slope_shadow_impl": "python",
        "shadow_compare_status": "match",
        "promotion_context": {
            "perf_env_enforce": 1,
            "perf_require_taskset": 1,
            "perf_env_status": "pass",
            "perf_env_governor_actual": "performance",
            "perf_env_turbo_source": "intel_pstate/no_turbo",
            "perf_env_turbo_actual": "1",
            "perf_env_cpu_model": "fixture CPU",
            "baseline_fingerprint_status": "pass",
            "git_sha": GIT_SHA,
            "git_branch": "north-star/rust-slope-primary",
            "git_dirty": False,
            "ci_run_id": "1234",
            "ci_run_attempt": "1",
            "controlled_branch": 1,
            "slope_gate_primary_requested": "rust",
            "slope_gate_primary_actual": "rust",
            "slope_gate_primary_fallback_used": False,
        },
    }


def valid_stability(run_count: int = 10) -> dict:
    return {
        "gate": "PASS",
        "status": "pass",
        "run_count": run_count,
        "retry_class_counts": {"pass": run_count, "retryable": 0, "hard": 0},
        "shadow_match_pct": 100.0,
        "shadow_coverage_pct": 100.0,
    }


def valid_bundle(git_sha: str = GIT_SHA) -> dict:
    return {
        "sha256": "b" * 64,
        "manifest": {"schema_version": 1},
        "report": {"environment": {"git_sha": git_sha}},
    }


class M1ReadinessTests(unittest.TestCase):
    def test_complete_single_commit_evidence_is_ready(self) -> None:
        payload = readiness.evaluate_readiness(
            {"runs": [valid_run() for _ in range(10)]},
            valid_stability(),
            valid_bundle(),
        )

        self.assertEqual(payload["gate"], "PASS")
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(payload["blockers"], [])

    def test_fewer_than_ten_runs_is_blocked(self) -> None:
        payload = readiness.evaluate_readiness(
            {"runs": [valid_run() for _ in range(9)]},
            valid_stability(9),
            valid_bundle(),
        )

        self.assertEqual(payload["gate"], "FAIL")
        self.assertTrue(
            any("trend_run_count" in blocker for blocker in payload["blockers"])
        )

    def test_hard_or_missing_shadow_run_is_blocked(self) -> None:
        runs = [valid_run() for _ in range(10)]
        runs[4]["retry_class"] = "hard"
        runs[7]["shadow_compare_status"] = "missing"
        payload = readiness.evaluate_readiness(
            {"runs": runs},
            valid_stability(),
            valid_bundle(),
        )

        self.assertEqual(payload["gate"], "FAIL")
        self.assertTrue(
            any("stable_retry_classes" in blocker for blocker in payload["blockers"])
        )
        self.assertTrue(
            any("shadow_match_window" in blocker for blocker in payload["blockers"])
        )

    def test_fallback_or_uncontrolled_latest_run_is_blocked(self) -> None:
        runs = [valid_run() for _ in range(10)]
        runs[0]["promotion_context"]["slope_gate_primary_actual"] = "python"
        runs[0]["promotion_context"]["slope_gate_primary_fallback_used"] = True
        runs[0]["promotion_context"]["perf_env_governor_actual"] = "powersave"
        payload = readiness.evaluate_readiness(
            {"runs": runs},
            valid_stability(),
            valid_bundle(),
        )

        self.assertEqual(payload["gate"], "FAIL")
        self.assertTrue(
            any("controlled_rust_primary" in blocker for blocker in payload["blockers"])
        )

    def test_bundle_must_match_promotion_commit(self) -> None:
        payload = readiness.evaluate_readiness(
            {"runs": [valid_run() for _ in range(10)]},
            valid_stability(),
            valid_bundle("c" * 40),
        )

        self.assertEqual(payload["gate"], "FAIL")
        self.assertTrue(
            any("single_commit_evidence" in blocker for blocker in payload["blockers"])
        )


if __name__ == "__main__":
    unittest.main()
