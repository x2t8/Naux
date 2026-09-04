from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_public_protocol.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8q_public_protocol_refusal_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
receipt = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = receipt
SPEC.loader.exec_module(receipt)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == receipt.wp8p.wp8o.wp8n.wp8m.wp8k.lt1.APACHE_HASH
)


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8Q refusal tests require the current Apache-2.0 surface",
)
class RegisterResidencyPublicProtocolRefusalTests(unittest.TestCase):
    def test_no_network_or_claim_api_exists(self) -> None:
        for name in (
            "query_ci",
            "fetch_run",
            "admit_claim",
            "approve_claim",
            "publish_claim",
        ):
            self.assertFalse(hasattr(receipt, name))

    def test_cli_rejects_external_and_claim_inputs(self) -> None:
        for option in ("url", "run-id", "token", "request", "approve", "admit"):
            with self.subTest(option=option), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    receipt.main(["--" + option, "value"])

    def test_exactly_one_parent_blocker_is_closed(self) -> None:
        admission = receipt.validate(ROOT)
        parent_text = admission.parent.report.decode()
        report_text = admission.report.decode()
        self.assertIn("blockers\t4\n", parent_text)
        self.assertIn("blockers\t3\n", report_text)
        self.assertEqual(
            receipt.CLOSURES,
            (
                (
                    "01",
                    "tracked-public-protocol-acceptance-unavailable",
                    "closed",
                    "exact-tracked-commit-three-green-public-runs",
                ),
            ),
        )

    def test_receipt_cannot_admit_a_claim(self) -> None:
        admission = receipt.validate(ROOT)
        self.assertIn(b"admission-status\tblocked\n", admission.report)
        self.assertIn(b"claim-status\tnot-admitted\n", admission.report)
        self.assertEqual(len(receipt.BLOCKERS), 3)


if __name__ == "__main__":
    unittest.main()
