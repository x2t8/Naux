from __future__ import annotations

import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residency_claim_admission_coq_certificate.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "s4_residency_claim_admission_coq_certificate_test", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == bridge.wp8p.wp8o.wp8n.wp8m.wp8k.lt1.APACHE_HASH
)


class S4ResidencyClaimAdmissionCoqCertificateTests(unittest.TestCase):
    @unittest.skipUnless(
        CURRENT_APACHE_SURFACE,
        "WP8P certificate test requires the current Apache-2.0 surface",
    )
    def test_exact_static_report_is_authenticated(self) -> None:
        admission = bridge.wp8p.validate(ROOT)
        report = bridge.parse_authenticated_claim_admission_report(
            admission.report, admission
        )
        self.assertEqual(report.report_root, admission.report_root)
        self.assertEqual(report.blocker_count, 4)

    @unittest.skipUnless(
        CURRENT_APACHE_SURFACE,
        "WP8P certificate test requires the current Apache-2.0 surface",
    )
    def test_resealed_status_or_blocker_drift_is_rejected(self) -> None:
        admission = bridge.wp8p.validate(ROOT)
        for old, new in (
            (b"admission-status\tblocked\n", b"admission-status\tadmitted\n"),
            (b"claim-status\tnot-admitted\n", b"claim-status\tadmitted\n"),
            (b"blockers\t4\n", b"blockers\t0\n"),
        ):
            with self.subTest(old=old):
                body = admission.report.rsplit(b"report-root\t", 1)[0]
                body = body.replace(old, new, 1)
                mutated = body + (
                    "report-root\t"
                    + hashlib.sha256(bridge.wp8p.REPORT_DOMAIN + body).hexdigest()
                    + "\n"
                ).encode()
                with self.assertRaisesRegex(
                    bridge.ClaimAdmissionCertificateError, "metadata drifted"
                ):
                    bridge.parse_authenticated_claim_admission_report(
                        mutated, admission
                    )

    def test_emitter_exposes_only_the_blocked_wp8p_boundary(self) -> None:
        output = bridge.emit_rocq(
            bridge.ClaimAdmissionReport("a" * 64, 4), "b" * 64
        )
        self.assertIn("GeneratedWP8OThreshold", output)
        self.assertIn("ResidencyClaimAdmission", output)
        self.assertIn("residency_claim_required_blockers", output)
        self.assertIn("has_four_blockers", output)
        self.assertIn("is_not_resolved", output)
        self.assertIn("has_no_request_or_approval", output)
        self.assertIn("has_no_admission_authority", output)
        self.assertNotIn("ResidencyClaimRequestRetained", output)
        self.assertNotIn("ResidencyClaimApprovalRetained", output)
        self.assertNotIn("ResidencyRunnerActionPermitted", output)
        self.assertNotIn("ResidencyPerformanceClaimPermitted", output)


if __name__ == "__main__":
    unittest.main()
