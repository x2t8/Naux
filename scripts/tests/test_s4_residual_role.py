#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residual_role.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_residual_role", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
wp5 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = wp5
SPEC.loader.exec_module(wp5)


class S4ResidualRoleTests(unittest.TestCase):
    def test_repository_contract_is_static_and_blocked(self) -> None:
        admission = wp5.validate(ROOT)
        self.assertEqual(admission.contract.blockers, wp5.CONTRACT_BLOCKERS)
        text = admission.report.decode()
        self.assertIn("contract-status\tcontract-only\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)
        self.assertIn("timing-status\tforbidden\n", text)
        self.assertEqual(text.count("blocker\t"), 3)
        self.assertTrue(text.endswith(f"report-root\t{admission.report_root}\n"))

    def test_trace_substitution_is_rejected_even_when_resealed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = self._copy_contract(Path(temp))
            path = root / "distribution/s4-performance/WP5-RESIDUAL-ROLE.tsv"
            text = path.read_text().replace(
                "meta\trequired-role\tnaux-residual\n",
                "meta\trequired-role\tnaux-trace-carrier-observation\n",
            )
            self._reseal(path, wp5.CONTRACT_DOMAIN, text)
            with self.assertRaises(wp5.ResidualRoleError):
                wp5.parse_contract(path)

    def test_static_checksum_fold_is_rejected_even_when_resealed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = self._copy_contract(Path(temp))
            path = root / "distribution/s4-performance/WP5-RESIDUAL-ROLE.tsv"
            text = path.read_text().replace(
                "meta\tdynamic-work\tpreserved\n",
                "meta\tdynamic-work\tprecomputed\n",
            )
            self._reseal(path, wp5.CONTRACT_DOMAIN, text)
            with self.assertRaises(wp5.ResidualRoleError):
                wp5.parse_contract(path)

    def test_missing_handwritten_template_prohibition_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = self._copy_contract(Path(temp))
            path = root / "distribution/s4-performance/WP5-RESIDUAL-ROLE.tsv"
            lines = path.read_text().splitlines()
            lines.remove("forbid\t07\tper-kernel-native-template")
            self._reseal(path, wp5.CONTRACT_DOMAIN, "\n".join(lines) + "\n")
            with self.assertRaises(wp5.ResidualRoleError):
                wp5.parse_contract(path)

    def test_parent_authority_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = self._copy_contract(Path(temp))
            path = root / "distribution/s4-performance/WP5-AUTHORITY.tsv"
            text = path.read_text().replace(wp5.WP4_AUTHORITY_SEAL, "0" * 64, 1)
            self._reseal(path, wp5.AUTHORITY_DOMAIN, text)
            contract = wp5.parse_contract(
                root / "distribution/s4-performance/WP5-RESIDUAL-ROLE.tsv"
            )
            with self.assertRaises(wp5.ResidualRoleError):
                wp5.parse_authority(path, contract.seal)

    def test_bound_file_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = self._copy_contract(Path(temp))
            path = root / "distribution/s4-performance/WP5-NONCLAIMS.md"
            path.write_text(path.read_text() + "drift\n")
            contract = wp5.parse_contract(
                root / "distribution/s4-performance/WP5-RESIDUAL-ROLE.tsv"
            )
            authority = wp5.parse_authority(
                root / "distribution/s4-performance/WP5-AUTHORITY.tsv", contract.seal
            )
            with self.assertRaises(wp5.ResidualRoleError):
                wp5._verify_files(root, authority)

    def test_bound_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = self._copy_contract(Path(temp))
            contract = wp5.parse_contract(
                root / "distribution/s4-performance/WP5-RESIDUAL-ROLE.tsv"
            )
            authority = wp5.parse_authority(
                root / "distribution/s4-performance/WP5-AUTHORITY.tsv", contract.seal
            )
            path = root / "distribution/s4-performance/WP5-README.md"
            target = root / "readme-copy.md"
            shutil.copy2(path, target)
            path.unlink()
            path.symlink_to(target)
            with self.assertRaises(wp5.ResidualRoleError):
                wp5._verify_files(root, authority)

    def test_contract_workflow_cannot_build_execute_or_measure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workflow = root / ".github/workflows/s4-residual-role.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                "python3 scripts/s4_residual_role.py\n"
                "python3 -m unittest scripts.tests.test_s4_residual_role\n"
                "cargo run -p naux --example forged_residual\n"
            )
            distribution = root / "distribution/s4-performance"
            distribution.mkdir(parents=True)
            for name in (
                "WP5-AUTHORITY.tsv",
                "WP5-NONCLAIMS.md",
                "WP5-README.md",
                "WP5-RESIDUAL-ROLE.tsv",
            ):
                (distribution / name).write_text("placeholder\n")
            with self.assertRaises(wp5.ResidualRoleError):
                wp5._verify_contract_only(root)

    @staticmethod
    def _reseal(path: Path, domain: bytes, text: str) -> None:
        lines = text.splitlines()
        body = "".join(f"{line}\n" for line in lines[:-1]).encode()
        lines[-1] = f"seal\t{hashlib.sha256(domain + body).hexdigest()}"
        path.write_text("\n".join(lines) + "\n")

    @staticmethod
    def _copy_contract(temp: Path) -> Path:
        for relative in (
            "distribution/s4-performance/WP5-RESIDUAL-ROLE.tsv",
            "distribution/s4-performance/WP5-AUTHORITY.tsv",
            "distribution/s4-performance/WP5-NONCLAIMS.md",
            "distribution/s4-performance/WP5-README.md",
        ):
            destination = temp / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        return temp


if __name__ == "__main__":
    unittest.main()
