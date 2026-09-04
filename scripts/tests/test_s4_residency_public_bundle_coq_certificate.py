from __future__ import annotations

import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residency_public_bundle_coq_certificate.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8r_coq_certificate_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
certificate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = certificate
SPEC.loader.exec_module(certificate)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == certificate.wp8r.wp8n.wp8m.wp8k.lt1.APACHE_HASH
)


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8R certificate tests require the current Apache-2.0 surface",
)
class ResidencyPublicBundleCoqCertificateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.admission = certificate.wp8r.validate(ROOT)

    def test_exact_report_emits_static_no_claim_authority(self) -> None:
        report = certificate.parse_authenticated_public_bundle_report(
            self.admission.report, self.admission
        )
        source = certificate.emit_rocq(report, self.admission.authority.seal)
        self.assertEqual(report.tracked_commit, certificate.wp8r.wp8q.TRACKED_COMMIT)
        self.assertEqual(report.blocker_count, 3)
        self.assertIn("wp8r_static_public_bundle_authority_is_admitted", source)
        self.assertIn("wp8r_static_public_bundle_has_no_archive_or_reachability", source)
        self.assertIn("wp8r_static_public_bundle_retains_eligible_blocker", source)
        self.assertIn("wp8r_static_public_bundle_has_no_claim_path", source)
        self.assertIn("wp8r_static_public_bundle_has_no_package_or_intake", source)
        self.assertIn("ResidencyPublicBundleArchiveMissing", source)
        self.assertIn("ResidencyPublicBundleReachabilityNotObserved", source)
        self.assertIn("GeneratedWP8NPairedEvidence", source)
        self.assertIn("GeneratedWP8QPublicProtocol", source)
        self.assertNotIn("ResidencyPublicBundleReachabilityConfirmed", source)
        self.assertNotIn("ResidencyRunnerActionPermitted", source)
        self.assertNotIn("ResidencyPerformanceClaimPermitted", source)

    def test_archive_presence_fails_even_with_recomputed_report_root(self) -> None:
        raw = self.admission.report
        body = raw[: raw.rfind(b"report-root\t")]
        body = body.replace(b"archive-status\tabsent", b"archive-status\tverified", 1)
        root = hashlib.sha256(certificate.wp8r.REPORT_DOMAIN + body).hexdigest()
        mutated = body + f"report-root\t{root}\n".encode()
        with self.assertRaises(certificate.PublicBundleCertificateError):
            certificate.parse_authenticated_public_bundle_report(mutated, self.admission)

    def test_changed_blocker_count_fails_with_recomputed_root(self) -> None:
        raw = self.admission.report
        body = raw[: raw.rfind(b"report-root\t")]
        body = body.replace(b"blockers\t3\n", b"blockers\t0\n", 1)
        root = hashlib.sha256(certificate.wp8r.REPORT_DOMAIN + body).hexdigest()
        mutated = body + f"report-root\t{root}\n".encode()
        with self.assertRaises(certificate.PublicBundleCertificateError):
            certificate.parse_authenticated_public_bundle_report(mutated, self.admission)


if __name__ == "__main__":
    unittest.main()
