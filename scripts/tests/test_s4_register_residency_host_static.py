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
SCRIPT = ROOT / "scripts/s4_register_residency_host.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8i_host_static_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
host = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = host
SPEC.loader.exec_module(host)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest() == host.lt1.APACHE_HASH
)


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8I static admission requires the current Apache-2.0 surface",
)
class RegisterResidencyHostStaticTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(
            body + f"seal\t{hashlib.sha256(host.CONTRACT_DOMAIN + body).hexdigest()}\n".encode()
        )

    def test_static_admission_is_deterministic_and_observes_no_host(self) -> None:
        first = host.validate(ROOT)
        second = host.validate(ROOT)
        self.assertEqual(first, second)
        text = first.static_report.decode()
        self.assertIn("protocol-status\tcandidate-controlled-host-protocol-admitted\n", text)
        self.assertIn("host-status\tnot-observed\n", text)
        self.assertIn("role\tnaux-register-residency-candidate\n", text)
        self.assertIn("baseline-role\tnaux-residual\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)
        self.assertIn("timing-status\tforbidden\n", text)

    def test_composition_binds_exact_candidate_and_historical_host(self) -> None:
        candidate, host_contract, host_authority = host._verify_composition(ROOT)
        self.assertEqual(candidate.contract.seal, host.WP8H_CONTRACT_SEAL)
        self.assertEqual(candidate.authority.seal, host.WP8H_AUTHORITY_SEAL)
        self.assertEqual(host_contract.seal, host.WP6_CONTRACT_SEAL)
        self.assertEqual(host_authority.seal, host.WP6_AUTHORITY_SEAL)

    def test_contract_policy_mutation_fails_after_coherent_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8i-contract-") as directory:
            path = Path(directory) / "WP8I-HOST.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP8I-HOST.tsv", path)
            path.write_text(
                path.read_text().replace("timing-status\tforbidden", "timing-status\tready", 1)
            )
            self._reseal(path)
            with self.assertRaises(host.CandidateHostError):
                host.parse_contract(path)

    def test_candidate_or_host_parent_substitution_fails_closed(self) -> None:
        candidate = host.wp8h.validate(ROOT)
        wrong_candidate = host.wp8h.Admission(
            candidate.contract,
            host.wp8h.Authority(candidate.authority.files, "0" * 64),
            candidate.process,
            candidate.static_report,
            candidate.static_root,
        )
        with mock.patch.object(host.wp8h, "validate", return_value=wrong_candidate):
            with self.assertRaisesRegex(host.CandidateHostError, "WP8H candidate"):
                host._verify_composition(ROOT)

        parser = host.wp6.parse_authority
        with mock.patch.object(host.wp6, "parse_authority", wraps=parser) as authority_parser:
            authority_parser.side_effect = lambda path, seal: host.wp6.Authority((), "0" * 64)
            with self.assertRaisesRegex(host.CandidateHostError, "WP6 host"):
                host._verify_composition(ROOT)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = host.parse_contract(ROOT / "distribution/s4-performance/WP8I-HOST.tsv")
        authority = host.parse_authority(
            ROOT / "distribution/s4-performance/WP8I-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp8i-files-") as directory:
            root = Path(directory)
            for relative in host.EXPECTED_FILES:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = root / "distribution/s4-performance/WP8I-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(host.CandidateHostError):
                host._verify_files(root, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP8I-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(host.CandidateHostError):
                host._verify_files(root, authority)

    def test_source_boundary_forbids_measurement(self) -> None:
        host._verify_source_boundary(ROOT)
        source = SCRIPT.read_text()
        forbidden_calls = (
            "." + "perf_counter(",
            "." + "monotonic_ns(",
            "." + "time_ns(",
            "." + "clock_gettime(",
        )
        self.assertFalse(any(token in source for token in forbidden_calls))


if __name__ == "__main__":
    unittest.main()
