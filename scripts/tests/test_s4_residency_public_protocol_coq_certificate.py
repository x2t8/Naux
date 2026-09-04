from __future__ import annotations

import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residency_public_protocol_coq_certificate.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8q_coq_certificate_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
certificate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = certificate
SPEC.loader.exec_module(certificate)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == certificate.wp8q.wp8p.wp8o.wp8n.wp8m.wp8k.lt1.APACHE_HASH
)


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8Q certificate tests require the current Apache-2.0 surface",
)
class ResidencyPublicProtocolCoqCertificateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.admission = certificate.wp8q.validate(ROOT)

    def test_exact_report_parses_and_emits_closed_receipt(self) -> None:
        report = certificate.parse_authenticated_public_protocol_report(
            self.admission.report, self.admission
        )
        source = certificate.emit_rocq(report, self.admission.authority.seal)
        self.assertEqual(report.tracked_commit, certificate.wp8q.TRACKED_COMMIT)
        self.assertEqual(report.blocker_count, 3)
        self.assertIn("wp8q_public_protocol_gate_is_closed", source)
        self.assertIn("wp8q_public_protocol_retains_three_blockers", source)
        self.assertIn("wp8q_public_protocol_removes_only_public_blocker", source)
        self.assertIn("wp8q_public_protocol_has_no_claim_path", source)
        self.assertIn("residency_public_protocol_ci_commit", source)
        self.assertIn("residency_public_protocol_formal_model_commit", source)
        self.assertIn("residency_public_protocol_formal_bridge_commit", source)
        self.assertIn("residency_public_protocol_ci_success := true", source)
        self.assertIn("residency_public_protocol_formal_model_success := true", source)
        self.assertIn("residency_public_protocol_formal_bridge_success := true", source)
        self.assertIn("Definition wp8q_ci_run_identity : list nat", source)
        self.assertIn("Definition wp8q_formal_model_run_identity : list nat", source)
        self.assertIn("Definition wp8q_formal_bridge_run_identity : list nat", source)
        self.assertNotIn(f"{report.ci_run}%nat", source)
        self.assertEqual(source.count("Proof. discriminate. Qed.\n"), 3)
        self.assertIn("residency_public_protocol_parent_admitted :=", source)
        self.assertIn("residency_public_protocol_claim_forbidden := eq_refl", source)
        self.assertNotIn("ResidencyClaimRequestRetained", source)
        self.assertNotIn("ResidencyClaimApprovalRetained", source)
        self.assertNotIn("ResidencyRunnerActionPermitted", source)
        self.assertNotIn("ResidencyPerformanceClaimPermitted", source)

    def test_changed_run_fails_even_with_recomputed_report_root(self) -> None:
        raw = self.admission.report
        body = raw[: raw.rfind(b"report-root\t")]
        body = body.replace(b"ci-run\t33785721821", b"ci-run\t33785721822", 1)
        root = hashlib.sha256(certificate.wp8q.REPORT_DOMAIN + body).hexdigest()
        mutated = body + f"report-root\t{root}\n".encode()
        with self.assertRaises(certificate.PublicProtocolCertificateError):
            certificate.parse_authenticated_public_protocol_report(
                mutated, self.admission
            )

    def test_changed_blocker_count_fails_with_recomputed_root(self) -> None:
        raw = self.admission.report
        body = raw[: raw.rfind(b"report-root\t")]
        body = body.replace(b"blockers\t3\n", b"blockers\t0\n", 1)
        root = hashlib.sha256(certificate.wp8q.REPORT_DOMAIN + body).hexdigest()
        mutated = body + f"report-root\t{root}\n".encode()
        with self.assertRaises(certificate.PublicProtocolCertificateError):
            certificate.parse_authenticated_public_protocol_report(
                mutated, self.admission
            )


if __name__ == "__main__":
    unittest.main()
