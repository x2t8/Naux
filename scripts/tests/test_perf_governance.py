from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import perf_slope_shadow_compare as shadow_compare  # noqa: E402
import perf_trend_artifacts as trend_artifacts  # noqa: E402


def slope_report(retry_class: str = "pass", gate: str = "PASS") -> dict:
    return {
        "retry_class": retry_class,
        "scenarios": [
            {"name": "dot_runtime_only", "gate": gate, "a_ns_per_elem": 1.0, "r2": 1.0}
        ],
    }


class ShadowCompareTests(unittest.TestCase):
    def test_match_emits_promotion_evidence(self) -> None:
        payload = shadow_compare.compare_reports(
            slope_report(),
            slope_report(),
            primary_impl="python",
            shadow_impl="rust",
            primary_path=Path("primary.json"),
            shadow_path=Path("shadow.json"),
        )

        self.assertEqual(payload["status"], "match")
        self.assertEqual(payload["gate"], "PASS")
        self.assertEqual(payload["mismatches"], [])
        self.assertIn("[slope-shadow] match", shadow_compare.render_text(payload))

    def test_policy_difference_is_a_mismatch(self) -> None:
        payload = shadow_compare.compare_reports(
            slope_report(retry_class="pass", gate="PASS"),
            slope_report(retry_class="hard", gate="FAIL_HARD"),
            primary_impl="rust",
            shadow_impl="python",
            primary_path=Path("primary.json"),
            shadow_path=Path("shadow.json"),
        )

        self.assertEqual(payload["status"], "mismatch")
        self.assertEqual(payload["gate"], "FAIL")
        self.assertEqual(len(payload["mismatches"]), 2)


class TrendArtifactTests(unittest.TestCase):
    def test_structured_shadow_evidence_is_included_in_trend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run-1"
            run_dir.mkdir()
            slope_path = run_dir / "slope_report.json"
            slope_path.write_text(json.dumps(slope_report()), encoding="utf-8")
            (run_dir / "slope_report_shadow_compare.json").write_text(
                json.dumps(
                    {
                        "status": "match",
                        "primary": {"implementation": "rust"},
                        "shadow": {"implementation": "python"},
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "perf_report.json").write_text(
                json.dumps(
                    {
                        "meta": {
                            "perf_env_enforce": 1,
                            "perf_require_taskset": 1,
                            "perf_env_status": "pass",
                            "slope_gate_primary_requested": "rust",
                            "slope_gate_primary_actual": "rust",
                            "slope_gate_primary_fallback_used": False,
                            "git_sha": "a" * 40,
                            "git_dirty": False,
                            "controlled_branch": 1,
                        }
                    }
                ),
                encoding="utf-8",
            )

            summary = trend_artifacts._build_run_summary(slope_path, [])
            report = trend_artifacts._to_json_report(Path(tmp), [summary])

            self.assertEqual(summary.slope_primary_impl, "rust")
            self.assertEqual(summary.slope_shadow_impl, "python")
            self.assertEqual(summary.shadow_compare_status, "match")
            self.assertEqual(report["shadow_compare_counts"]["match"], 1)
            self.assertEqual(
                summary.promotion_context["slope_gate_primary_actual"], "rust"
            )
            self.assertFalse(summary.promotion_context["git_dirty"])

    def test_legacy_shadow_text_remains_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            slope_path = run_dir / "slope_report.json"
            slope_path.write_text(json.dumps(slope_report()), encoding="utf-8")
            (run_dir / "slope_report_rs_shadow_compare.txt").write_text(
                "[slope-shadow] match\n",
                encoding="utf-8",
            )

            summary = trend_artifacts._build_run_summary(slope_path, [])

            self.assertEqual(summary.slope_primary_impl, "python")
            self.assertEqual(summary.slope_shadow_impl, "rust")
            self.assertEqual(summary.shadow_compare_status, "match")


class DeoptArtifactTests(unittest.TestCase):
    def test_internal_side_exits_remain_separate_from_deopt_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            profiles = tmp_path / "profiles"
            profiles.mkdir()
            (profiles / "branch.naux.profile.json").write_text(
                json.dumps(
                    {
                        "trace_count": 1,
                        "hot_trace_id": 7,
                        "total_hits": 9,
                        "total_deopts": 2,
                        "total_internal_side_exits": 7,
                        "guard_checks_total": 9,
                        "guard_fail_total": 0,
                        "deopt_reasons": [{"reason": "runtime_site_3", "count": 2}],
                        "by_trace": [
                            {
                                "trace_id": 7,
                                "loop_header": 3,
                                "hits": 9,
                                "deopts": 2,
                                "internal_side_exits": 7,
                                "guard_checks": 9,
                                "guard_fails": 0,
                                "runtime_deopts": 0,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out_json = tmp_path / "deopt.json"
            out_md = tmp_path / "deopt.md"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS_DIR / "perf_deopt_artifacts.py"),
                    "--profiles-root",
                    str(profiles),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["total_deopts"], 2)
            self.assertEqual(payload["summary"]["total_internal_side_exits"], 7)
            self.assertEqual(payload["scenarios"][0]["total_internal_side_exits"], 7)
            self.assertEqual(payload["traces"][0]["internal_side_exits"], 7)
            self.assertEqual(payload["top_deopt_reasons"][0]["share_pct"], 100.0)
            self.assertIn("total_internal_side_exits: `7`", out_md.read_text(encoding="utf-8"))


class FusionPolicyTests(unittest.TestCase):
    def test_proven_mul_acc_rule_cannot_silently_return_to_optional(self) -> None:
        policy = json.loads(
            (SCRIPTS_DIR / "fusion_expectations.json").read_text(encoding="utf-8")
        )
        expectation = policy["map_get_mul_acc"]

        self.assertIn("map_stable_mul_acc", expectation["required"])
        self.assertNotIn("map_stable_mul_acc", expectation["optional"])


class StabilityGateTests(unittest.TestCase):
    def run_stability(self, statuses: list[str]) -> tuple[subprocess.CompletedProcess[str], dict]:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            trend_path = tmp_path / "trend.json"
            out_json = tmp_path / "stability.json"
            out_md = tmp_path / "stability.md"
            trend_path.write_text(
                json.dumps(
                    {
                        "runs": [
                            {
                                "retry_class": "pass",
                                "fusion_runtime_hits": {},
                                "shadow_compare_status": status,
                            }
                            for status in statuses
                        ]
                    }
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS_DIR / "perf_stability_window.py"),
                    "--trend-json",
                    str(trend_path),
                    "--window",
                    str(len(statuses)),
                    "--min-runs",
                    str(len(statuses)),
                    "--fail-on-insufficient-runs",
                    "--require-shadow-match",
                    "--min-shadow-match-pct",
                    "100",
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            return result, payload

    def test_missing_shadow_evidence_blocks_promotion(self) -> None:
        result, payload = self.run_stability(["match", "missing"])

        self.assertEqual(result.returncode, 1)
        self.assertEqual(payload["gate"], "FAIL")
        self.assertEqual(payload["shadow_match_pct"], 50.0)
        self.assertEqual(payload["shadow_coverage_pct"], 50.0)

    def test_complete_shadow_match_window_passes(self) -> None:
        result, payload = self.run_stability(["match", "match"])

        self.assertEqual(result.returncode, 0)
        self.assertEqual(payload["gate"], "PASS")
        self.assertEqual(payload["shadow_match_pct"], 100.0)
        self.assertEqual(payload["shadow_coverage_pct"], 100.0)


if __name__ == "__main__":
    unittest.main()
