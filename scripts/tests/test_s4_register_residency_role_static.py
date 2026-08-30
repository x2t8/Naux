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
SCRIPT = ROOT / "scripts/s4_register_residency_role.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8h_role_static_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
role = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = role
SPEC.loader.exec_module(role)


class ResidencyRoleStaticTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        seal = hashlib.sha256(role.CONTRACT_DOMAIN + body).hexdigest()
        path.write_bytes(body + f"seal\t{seal}\n".encode())

    def test_repository_static_admission_is_deterministic_and_pending(self) -> None:
        first = role.validate(ROOT)
        second = role.validate(ROOT)
        self.assertEqual(first, second)
        text = first.static_report.decode()
        self.assertIn("role-status\tpending-process-replay\n", text)
        self.assertIn("role-isolation\tdoes-not-replace-wp5f\n", text)
        self.assertIn("timing-status\tforbidden\n", text)
        self.assertNotIn("role-status\tuntimed-register-residency-candidate-admitted\n", text)

    def test_contract_binds_wp8g_artifacts_and_wp5f_workload(self) -> None:
        contract = role.parse_contract(
            ROOT / "distribution/s4-performance/WP8H-CANDIDATE-ROLE.tsv"
        )
        process = role.wp8g.validate(ROOT)
        role._verify_composition(ROOT, contract, process)
        baseline = role.wp5f.parse_contract(
            ROOT / "distribution/s4-performance/WP5F-ROLE.tsv"
        )
        self.assertEqual(
            tuple((item.name, item.oracle, item.work_hash) for item in contract.artifacts),
            tuple((item.name, item.oracle, item.work_hash) for item in baseline.artifacts),
        )

    def test_contract_policy_mutation_fails_after_coherent_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8h-contract-") as directory:
            path = Path(directory) / "WP8H-CANDIDATE-ROLE.tsv"
            shutil.copy2(
                ROOT / "distribution/s4-performance/WP8H-CANDIDATE-ROLE.tsv", path
            )
            path.write_text(
                path.read_text().replace(
                    "timing-status\tforbidden", "timing-status\tready", 1
                )
            )
            self._reseal(path)
            with self.assertRaises(role.CandidateRoleError):
                role.parse_contract(path)

    def test_artifact_substitution_fails_composition(self) -> None:
        contract = role.parse_contract(
            ROOT / "distribution/s4-performance/WP8H-CANDIDATE-ROLE.tsv"
        )
        changed = role.ArtifactRecord(
            contract.artifacts[0].ordinal,
            contract.artifacts[0].name,
            contract.artifacts[0].oracle,
            contract.artifacts[0].work_hash,
            "0" * 64,
            contract.artifacts[0].elf_hash,
        )
        mutated = role.Contract((changed,) + contract.artifacts[1:], contract.seal)
        with self.assertRaisesRegex(role.CandidateRoleError, "WP8G process contract"):
            role._verify_composition(ROOT, mutated, role.wp8g.validate(ROOT))

    def test_license_transition_or_baseline_authority_drift_fails_closed(self) -> None:
        contract = role.parse_contract(
            ROOT / "distribution/s4-performance/WP8H-CANDIDATE-ROLE.tsv"
        )
        process = role.wp8g.validate(ROOT)
        transition = role.lt1.validate(ROOT)
        wrong_transition = role.lt1.Admission(
            transition.contract,
            role.lt1.Authority(transition.authority.files, "0" * 64),
            transition.report,
            transition.report_root,
        )
        with mock.patch.object(role.lt1, "validate", return_value=wrong_transition):
            with self.assertRaisesRegex(role.CandidateRoleError, "Apache transition"):
                role._verify_composition(ROOT, contract, process)
        baseline = role.wp5f.parse_authority
        with mock.patch.object(role.wp5f, "parse_authority", wraps=baseline) as parser:
            parser.side_effect = lambda path, seal: role.wp5f.Authority((), "0" * 64)
            with self.assertRaisesRegex(role.CandidateRoleError, "historical baseline"):
                role._verify_composition(ROOT, contract, process)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = role.parse_contract(
            ROOT / "distribution/s4-performance/WP8H-CANDIDATE-ROLE.tsv"
        )
        authority = role.parse_authority(
            ROOT / "distribution/s4-performance/WP8H-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp8h-files-") as directory:
            root = Path(directory)
            for relative in role.EXPECTED_FILES:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = root / "distribution/s4-performance/WP8H-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(role.CandidateRoleError):
                role._verify_files(root, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP8H-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(role.CandidateRoleError):
                role._verify_files(root, authority)


if __name__ == "__main__":
    unittest.main()
