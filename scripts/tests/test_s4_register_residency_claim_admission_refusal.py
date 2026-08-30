from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_claim_admission.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8p_claim_refusal_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
claim = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = claim
SPEC.loader.exec_module(claim)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == claim.wp8o.wp8n.wp8m.wp8k.lt1.APACHE_HASH
)


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8P refusal tests require the current Apache-2.0 surface",
)
class RegisterResidencyClaimAdmissionRefusalTests(unittest.TestCase):
    def test_no_claim_admission_api_exists(self) -> None:
        for name in (
            "admit_claim",
            "approve_claim",
            "publish_claim",
            "evaluate_request",
        ):
            self.assertFalse(hasattr(claim, name))

    def test_cli_rejects_every_future_input_surface(self) -> None:
        for option in ("bundle", "candidate", "request", "approve", "admit"):
            with self.subTest(option=option), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    claim.main(["--" + option, "value"])

    def test_only_exact_bounded_class_can_ever_be_permitted(self) -> None:
        permitted = [row for row in claim.CLASSES if row[2] != "forbidden"]
        self.assertEqual(
            permitted,
            [
                (
                    "01",
                    "exact-four-kernel-register-residency-threshold-observation",
                    "permitted-only-after-all-gates",
                )
            ],
        )

    def test_protocol_has_no_current_unlock_path(self) -> None:
        admission = claim.validate(ROOT)
        self.assertIn(b"admission-status\tblocked\n", admission.report)
        self.assertIn(b"claim-status\tnot-admitted\n", admission.report)
        self.assertEqual(len(claim.BLOCKERS), 4)


if __name__ == "__main__":
    unittest.main()
