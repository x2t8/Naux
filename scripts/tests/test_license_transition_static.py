#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/license_transition.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("license_transition", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
transition = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = transition
SPEC.loader.exec_module(transition)


class LicenseTransitionStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest() != transition.APACHE_HASH:
            raise unittest.SkipTest("LT1 tests run only against the current Apache surface")

    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode())

    def test_repository_admission_is_deterministic_and_nonclaiming(self) -> None:
        first = transition.validate(ROOT)
        second = transition.validate(ROOT)
        self.assertEqual(first, second)
        self.assertIn(b"inventory-status\texact\n", first.report)
        self.assertIn(b"legal-delta-status\texact\n", first.report)
        self.assertIn(b"claim-status\tnot-admitted\n", first.report)
        self.assertIn(b"historical-authority-status\tpending-explicit-replay\n", first.report)

    def test_contract_mutation_fails_even_after_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-lt1-contract-") as directory:
            target = Path(directory) / "LT1-CONTRACT.tsv"
            shutil.copy2(ROOT / "distribution/license-transition/LT1-CONTRACT.tsv", target)
            target.write_text(target.read_text().replace("claim-boundary\tnot-admitted", "claim-boundary\tadmitted", 1))
            self._reseal(target, transition.CONTRACT_DOMAIN)
            with self.assertRaises(transition.TransitionError):
                transition.parse_contract(target)

    def test_bound_file_mutation_and_symlink_fail(self) -> None:
        contract = transition.parse_contract(ROOT / "distribution/license-transition/LT1-CONTRACT.tsv")
        authority = transition.parse_authority(ROOT / "distribution/license-transition/LT1-AUTHORITY.tsv", contract.seal)
        with tempfile.TemporaryDirectory(prefix="naux-lt1-authority-") as directory:
            copied = []
            for record in authority.files:
                target = Path(directory) / record.path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / record.path, target)
                copied.append(target)
            copied[0].write_bytes(copied[0].read_bytes() + b"drift\n")
            with self.assertRaises(transition.TransitionError):
                transition._verify_authority_files(Path(directory), authority)
            shutil.copy2(ROOT / authority.files[0].path, copied[0])
            original = copied[0].with_suffix(".copy")
            copied[0].rename(original)
            copied[0].symlink_to(original.name)
            with self.assertRaises(transition.TransitionError):
                transition._verify_authority_files(Path(directory), authority)

    def test_non_license_delta_fails_despite_valid_file_shape(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-lt1-delta-") as directory:
            root = Path(directory)
            for *_fields, relative in transition.TRANSITIONS:
                current = root / relative
                snapshot = root / "distribution/license-transition/pre-apache" / relative
                current.parent.mkdir(parents=True, exist_ok=True)
                snapshot.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, current)
                shutil.copy2(ROOT / "distribution/license-transition/pre-apache" / relative, snapshot)
            readme = root / "README.md"
            readme.write_bytes(readme.read_bytes().replace(b"NAUX", b"NAXU", 1))
            with self.assertRaises(transition.TransitionError):
                transition._verify_legal_deltas(root)

    def test_transition_snapshots_are_regular_mode_0644(self) -> None:
        for *_fields, relative in transition.TRANSITIONS:
            path = ROOT / "distribution/license-transition/pre-apache" / relative
            info = path.lstat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertFalse(path.is_symlink())
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o644)


if __name__ == "__main__":
    unittest.main()
