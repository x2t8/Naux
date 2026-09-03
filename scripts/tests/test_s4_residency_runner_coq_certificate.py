from __future__ import annotations

import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residency_runner_coq_certificate.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "s4_residency_runner_coq_certificate_test", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)


class S4ResidencyRunnerCoqCertificateTests(unittest.TestCase):
    def test_exact_static_runner_report_is_authenticated(self) -> None:
        admission = bridge.wp8k.validate(ROOT)
        evidence = bridge.parse_authenticated_runner_report(
            admission.static_report, admission
        )
        self.assertEqual(evidence.report_root, admission.report_root)
        self.assertEqual(evidence.samples_required, 120)

    def test_resealed_execution_mode_drift_is_rejected(self) -> None:
        admission = bridge.wp8k.validate(ROOT)
        body = admission.static_report.rsplit(b"report-root\t", 1)[0].replace(
            b"mode\tstatic-no-host-no-clock-no-build-no-execution\n",
            b"mode\texplicit-controlled-candidate-acquisition\n",
            1,
        )
        mutated = body + (
            "report-root\t"
            + hashlib.sha256(bridge.wp8k.REPORT_DOMAIN + body).hexdigest()
            + "\n"
        ).encode()
        with self.assertRaisesRegex(
            bridge.RunnerCertificateError, "metadata drifted"
        ):
            bridge.parse_authenticated_runner_report(mutated, admission)

    def test_resealed_claim_drift_is_rejected(self) -> None:
        admission = bridge.wp8k.validate(ROOT)
        body = admission.static_report.rsplit(b"report-root\t", 1)[0].replace(
            b"claim-status\tnot-admitted\n",
            b"claim-status\tadmitted\n",
            1,
        )
        mutated = body + (
            "report-root\t"
            + hashlib.sha256(bridge.wp8k.REPORT_DOMAIN + body).hexdigest()
            + "\n"
        ).encode()
        with self.assertRaisesRegex(
            bridge.RunnerCertificateError, "metadata drifted"
        ):
            bridge.parse_authenticated_runner_report(mutated, admission)

    def test_emitter_exposes_only_the_closed_wp8k_boundary(self) -> None:
        output = bridge.emit_rocq(
            bridge.RunnerReportEvidence("a" * 64, 120), "b" * 64
        )
        for ordinal in ("01", "02", "03", "04"):
            self.assertIn(f"GeneratedWP8JTimingKernel{ordinal}", output)
            self.assertIn(f"wp8j_kernel_{ordinal}_carrier", output)
        self.assertIn("ResidencyMeasurementRunner", output)
        self.assertIn("wp8k_static_runner_is_admitted", output)
        self.assertIn("is_not_acquisition_ready", output)
        self.assertIn("has_no_execution_authority", output)
        self.assertIn("has_no_publication_authority", output)
        self.assertIn("has_no_performance_claim", output)
        self.assertNotIn("ResidencyRunnerActionPermitted", output)
        self.assertNotIn("ResidencyPerformanceClaimPermitted", output)


if __name__ == "__main__":
    unittest.main()
