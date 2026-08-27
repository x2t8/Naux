#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residual_role_admission.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_residual_role_admission_static", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
role = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = role
SPEC.loader.exec_module(role)


class S4ResidualRoleAdmissionStaticTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        seal = hashlib.sha256(domain + body).hexdigest()
        path.write_bytes(body + f"seal\t{seal}\n".encode())

    def test_repository_static_admission_is_deterministic_and_pending(self) -> None:
        first = role.validate(ROOT)
        second = role.validate(ROOT)
        self.assertEqual(first, second)
        text = first.static_report.decode()
        self.assertIn("role-status\tpending-process-replay\n", text)
        self.assertIn("claim-status\tuntimed-role-only\n", text)
        self.assertIn("timing-status\tforbidden\n", text)
        self.assertNotIn("role-status\tuntimed-naux-residual-admitted\n", text)

    def test_contract_binds_exact_wp5e_artifacts(self) -> None:
        contract = role.parse_contract(
            ROOT / "distribution/s4-performance/WP5F-ROLE.tsv"
        )
        parent = role.wp5e.validate(ROOT)
        self.assertEqual(len(contract.artifacts), 4)
        self.assertEqual(
            tuple(record.elf_hash for record in contract.artifacts),
            tuple(record.elf_hash for record in parent.contract.records),
        )
        self.assertEqual(
            tuple(record.target_hash for record in contract.artifacts),
            tuple(record.process_target_hash for record in parent.contract.records),
        )

    def test_contract_metadata_mutation_fails_after_coherent_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp5f-contract-") as directory:
            path = Path(directory) / "WP5F-ROLE.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP5F-ROLE.tsv", path)
            path.write_text(
                path.read_text().replace("timing-status\tforbidden", "timing-status\tready", 1)
            )
            self._reseal(path, role.CONTRACT_DOMAIN)
            with self.assertRaises(role.RoleAdmissionError):
                role.parse_contract(path)

    def test_artifact_substitution_fails_after_coherent_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp5f-artifact-") as directory:
            path = Path(directory) / "WP5F-ROLE.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP5F-ROLE.tsv", path)
            text = path.read_text()
            text = text.replace(
                "8d65246a0cbdbb5789c72bf5088978f4447dff73fcb7816f753c10ed9041eff8",
                "0" * 64,
                1,
            )
            path.write_text(text)
            self._reseal(path, role.CONTRACT_DOMAIN)
            contract = role.parse_contract(path)
            parent = role.wp5e.validate(ROOT)
            original = role.wp5e.wp5d.wp5c.wp5b.wp5a.wp5.validate(ROOT)
            with self.assertRaisesRegex(role.RoleAdmissionError, "artifacts differ"):
                role._verify_contract_composition(contract, parent, original.contract)

    def test_authority_chain_mismatch_fails_closed(self) -> None:
        expected = [seal for _, _, seal in role.CONTRACT_AUTHORITIES]
        expected[0] = "0" * 64
        with mock.patch.object(role, "_terminal_seal", side_effect=expected):
            with self.assertRaisesRegex(role.RoleAdmissionError, "identity chain"):
                role._verify_chain(ROOT)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = role.parse_contract(
            ROOT / "distribution/s4-performance/WP5F-ROLE.tsv"
        )
        authority = role.parse_authority(
            ROOT / "distribution/s4-performance/WP5F-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp5f-files-") as directory:
            root = Path(directory)
            for relative in role.EXPECTED_FILES:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = root / "distribution/s4-performance/WP5F-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(role.RoleAdmissionError):
                role._verify_files(root, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP5F-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(role.RoleAdmissionError):
                role._verify_files(root, authority)


if __name__ == "__main__":
    unittest.main()
