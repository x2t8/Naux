#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residual_role_admission.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_residual_role_admission_replay", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
role = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = role
SPEC.loader.exec_module(role)


class S4ResidualRoleAdmissionReplayTests(unittest.TestCase):
    @staticmethod
    def _binary() -> Path | None:
        configured = os.environ.get("NAUX_S4_RESIDUAL_PROCESS_BINARY")
        shared = Path(
            "/run/media/txuandev/New Volume/David Xuân Tools/Kali/"
            ".naux-codex-target"
        )
        candidates = (
            Path(configured) if configured else None,
            ROOT / "target/debug/examples/naux_s4_residual_process",
            ROOT / "target/release/examples/naux_s4_residual_process",
            shared / "debug/examples/naux_s4_residual_process",
            shared / "release/examples/naux_s4_residual_process",
        )
        for candidate in candidates:
            if candidate is not None and candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
        return None

    def test_two_pass_replay_admits_exact_role_without_timing(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP5E emitter is unavailable")
        admission = role.validate(ROOT)
        report, results = role.replay(admission, binary)
        text = report.decode()
        self.assertEqual(len(results), 8)
        self.assertIn("role-status\tuntimed-naux-residual-admitted\n", text)
        self.assertIn("process-report-root\t" + role.WP5E_REPLAY_ROOT + "\n", text)
        self.assertIn("timing-status\tforbidden\n", text)
        self.assertNotIn("runtime-ns", text)

    def test_replay_report_is_deterministic(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP5E emitter is unavailable")
        admission = role.validate(ROOT)
        first, _ = role.replay(admission, binary)
        second, _ = role.replay(admission, binary)
        self.assertEqual(first, second)

    def test_wrong_parent_report_root_fails_closed(self) -> None:
        admission = role.validate(ROOT)
        original = role.wp5e.replay

        def mutated(parent: object, binary: Path) -> tuple[bytes, object, tuple[object, ...]]:
            report, candidate, results = original(parent, binary)
            return report.replace(role.WP5E_REPLAY_ROOT.encode(), b"0" * 64), candidate, results

        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP5E emitter is unavailable")
        with mock.patch.object(role.wp5e, "replay", side_effect=mutated):
            with self.assertRaisesRegex(role.RoleAdmissionError, "replay root"):
                role.replay(admission, binary)

    def test_artifact_identity_substitution_fails_closed(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP5E emitter is unavailable")
        admission = role.validate(ROOT)
        changed = replace(admission.contract.artifacts[0], elf_hash="0" * 64)
        contract = replace(
            admission.contract,
            artifacts=(changed,) + admission.contract.artifacts[1:],
        )
        mutated = replace(admission, contract=contract)
        with self.assertRaisesRegex(role.RoleAdmissionError, "artifact set"):
            role.replay(mutated, binary)

    def test_missing_process_result_fails_closed(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP5E emitter is unavailable")
        admission = role.validate(ROOT)
        report, candidate, results = role.wp5e.replay(admission.parent, binary)
        with mock.patch.object(
            role.wp5e,
            "replay",
            return_value=(report, candidate, results[:-1]),
        ):
            with self.assertRaisesRegex(role.RoleAdmissionError, "artifact set"):
                role.replay(admission, binary)


if __name__ == "__main__":
    unittest.main()
