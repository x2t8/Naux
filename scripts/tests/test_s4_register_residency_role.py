from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_role.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8h_role_replay_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
role = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = role
SPEC.loader.exec_module(role)


class ResidencyRoleReplayTests(unittest.TestCase):
    @staticmethod
    def _binary() -> Path | None:
        configured = os.environ.get("NAUX_S4_WP8H_BINARY")
        candidates = (
            Path(configured) if configured else None,
            ROOT / "target/debug/examples/naux_s4_register_residency_process",
            ROOT / "target/release/examples/naux_s4_register_residency_process",
        )
        for candidate in candidates:
            if candidate is not None and candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
        return None

    def test_two_pass_replay_admits_isolated_candidate_role(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP8G emitter is unavailable")
        report, results = role.replay(role.validate(ROOT), binary)
        text = report.decode()
        self.assertEqual(len(results), 8)
        self.assertIn(
            "role-status\tuntimed-register-residency-candidate-admitted\n", text
        )
        self.assertIn("process-report-root\t" + role.WP8G_REPLAY_ROOT + "\n", text)
        self.assertIn("role-isolation\tdoes-not-replace-wp5f\n", text)
        self.assertIn("timing-status\tforbidden\n", text)

    def test_replay_report_is_deterministic(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP8G emitter is unavailable")
        admission = role.validate(ROOT)
        first, _ = role.replay(admission, binary)
        second, _ = role.replay(admission, binary)
        self.assertEqual(first, second)

    def test_wrong_parent_report_root_fails_closed(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP8G emitter is unavailable")
        admission = role.validate(ROOT)
        original = role.wp8g.replay

        def mutated(parent: object, path: Path) -> tuple[bytes, object, tuple[object, ...]]:
            report, candidate, results = original(parent, path)
            return report.replace(role.WP8G_REPLAY_ROOT.encode(), b"0" * 64), candidate, results

        with mock.patch.object(role.wp8g, "replay", side_effect=mutated):
            with self.assertRaisesRegex(role.CandidateRoleError, "replay root"):
                role.replay(admission, binary)

    def test_artifact_identity_substitution_fails_closed(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP8G emitter is unavailable")
        admission = role.validate(ROOT)
        changed = replace(admission.contract.artifacts[0], elf_hash="0" * 64)
        mutated = replace(
            admission,
            contract=replace(
                admission.contract,
                artifacts=(changed,) + admission.contract.artifacts[1:],
            ),
        )
        with self.assertRaisesRegex(role.CandidateRoleError, "artifact set"):
            role.replay(mutated, binary)

    def test_missing_or_reordered_process_result_fails_closed(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP8G emitter is unavailable")
        admission = role.validate(ROOT)
        report, candidate, results = role.wp8g.replay(admission.process, binary)
        for mutation in (results[:-1], (results[1], results[0]) + results[2:]):
            with mock.patch.object(
                role.wp8g,
                "replay",
                return_value=(report, candidate, mutation),
            ):
                with self.assertRaises(role.CandidateRoleError):
                    role.replay(admission, binary)


if __name__ == "__main__":
    unittest.main()
