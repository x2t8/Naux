from __future__ import annotations

import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residency_paired_runner_coq_certificate.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "s4_residency_paired_runner_coq_certificate_test", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == bridge.wp8m.wp8k.lt1.APACHE_HASH
)


class S4ResidencyPairedRunnerCoqCertificateTests(unittest.TestCase):
    @unittest.skipUnless(
        CURRENT_APACHE_SURFACE,
        "WP8M certificate test requires the current Apache-2.0 surface",
    )
    def test_exact_static_paired_report_is_authenticated(self) -> None:
        admission = bridge.wp8m.validate(ROOT)
        evidence = bridge.parse_authenticated_paired_runner_report(
            admission.static_report, admission
        )
        self.assertEqual(evidence.report_root, admission.report_root)
        self.assertEqual(
            (evidence.pairs_required, evidence.invocations_required), (120, 240)
        )

    @unittest.skipUnless(
        CURRENT_APACHE_SURFACE,
        "WP8M certificate test requires the current Apache-2.0 surface",
    )
    def test_resealed_execution_mode_drift_is_rejected(self) -> None:
        admission = bridge.wp8m.validate(ROOT)
        body = admission.static_report.rsplit(b"report-root\t", 1)[0].replace(
            b"mode\tstatic-no-host-no-clock-no-build-no-execution\n",
            b"mode\texplicit-controlled-paired-acquisition\n",
            1,
        )
        mutated = body + (
            "report-root\t"
            + hashlib.sha256(bridge.wp8m.REPORT_DOMAIN + body).hexdigest()
            + "\n"
        ).encode()
        with self.assertRaisesRegex(
            bridge.PairedRunnerCertificateError, "metadata drifted"
        ):
            bridge.parse_authenticated_paired_runner_report(mutated, admission)

    @unittest.skipUnless(
        CURRENT_APACHE_SURFACE,
        "WP8M certificate test requires the current Apache-2.0 surface",
    )
    def test_resealed_invocation_count_drift_is_rejected(self) -> None:
        admission = bridge.wp8m.validate(ROOT)
        body = admission.static_report.rsplit(b"report-root\t", 1)[0].replace(
            b"sample-invocations-required\t240\n",
            b"sample-invocations-required\t239\n",
            1,
        )
        mutated = body + (
            "report-root\t"
            + hashlib.sha256(bridge.wp8m.REPORT_DOMAIN + body).hexdigest()
            + "\n"
        ).encode()
        with self.assertRaisesRegex(
            bridge.PairedRunnerCertificateError, "metadata drifted"
        ):
            bridge.parse_authenticated_paired_runner_report(mutated, admission)

    def test_emitter_exposes_only_the_closed_wp8m_boundary(self) -> None:
        output = bridge.emit_rocq(
            bridge.PairedRunnerReport("a" * 64, 120, 240), "b" * 64
        )
        self.assertIn("GeneratedWP8KRunner", output)
        self.assertIn("ResidencyPairedRunner", output)
        self.assertIn("ResidencyPairedScheduleOddABEvenBA", output)
        self.assertIn("wp8m_static_paired_runner_is_admitted", output)
        self.assertIn("has_two_invocations_per_pair", output)
        self.assertIn("is_not_ready", output)
        self.assertIn("has_no_execution_authority", output)
        self.assertIn("has_no_performance_claim", output)
        self.assertNotIn("ResidencyRunnerActionPermitted", output)
        self.assertNotIn("ResidencyPerformanceClaimPermitted", output)


if __name__ == "__main__":
    unittest.main()
