#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_claim_admission.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_claim_admission_refusal", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
admission = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = admission
SPEC.loader.exec_module(admission)


class S4ClaimAdmissionRefusalTests(unittest.TestCase):
    def test_no_input_or_admission_surface_exists(self) -> None:
        source = SCRIPT.read_text()
        self.assertNotIn("def evaluate_claim", source)
        self.assertNotIn("def admit_claim", source)
        self.assertEqual(tuple(vars(admission).get(name) for name in ("ClaimRequest", "ClaimResult")), (None, None))

    def test_workflow_cannot_supply_evidence_or_external_approval(self) -> None:
        workflow = (ROOT / ".github/workflows/s4-claim-admission.yml").read_text()
        self.assertIn("Static claim admission authority", workflow)
        self.assertNotIn("workflow_dispatch", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("id-token: write", workflow)

    def test_contract_keeps_every_current_blocker(self) -> None:
        contract = (ROOT / "distribution/s4-performance/WP7E-CLAIM.tsv").read_text()
        for _ordinal, blocker in admission.CONTRACT_BLOCKERS:
            self.assertIn(f"\t{blocker}\n", contract)
        self.assertIn("class\t02\tlanguage-wide-performance-leadership\tforbidden\n", contract)


if __name__ == "__main__":
    unittest.main()
