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
SCRIPT = ROOT / "scripts/s4_register_residency_paired_runner.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8m_paired_runner_static_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == runner.wp8k.lt1.APACHE_HASH
)


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8M static tests require the current Apache-2.0 surface",
)
class RegisterResidencyPairedRunnerStaticTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode())

    def test_static_admission_is_deterministic_and_executes_nothing(self) -> None:
        with (
            mock.patch.object(runner.wp8k, "parse_retained_host", side_effect=AssertionError("host")),
            mock.patch.object(runner, "build_pair", side_effect=AssertionError("build")),
            mock.patch.object(runner, "collect_paired_invocations", side_effect=AssertionError("clock")),
            mock.patch.object(runner, "publish_bundle", side_effect=AssertionError("publish")),
        ):
            first = runner.validate(ROOT)
            second = runner.validate(ROOT)
        self.assertEqual(first, second)
        text = first.static_report.decode()
        self.assertIn("runner-status\tsame-session-paired-runner-structurally-admitted\n", text)
        self.assertIn("mode\tstatic-no-host-no-clock-no-build-no-execution\n", text)
        self.assertIn("sample-pairs-required\t120\n", text)
        self.assertIn("sample-invocations-required\t240\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)

    def test_contract_mutation_fails_after_coherent_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8m-contract-") as directory_name:
            path = Path(directory_name) / "WP8M-PAIRED-RUNNER.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP8M-PAIRED-RUNNER.tsv", path)
            path.write_text(path.read_text().replace("odd-ab-even-ba", "odd-ba-even-ab", 1))
            self._reseal(path, runner.CONTRACT_DOMAIN)
            with self.assertRaises(runner.PairedRunnerError):
                runner.parse_contract(path)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = runner.parse_contract(
            ROOT / "distribution/s4-performance/WP8M-PAIRED-RUNNER.tsv"
        )
        authority = runner.parse_authority(
            ROOT / "distribution/s4-performance/WP8M-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp8m-files-") as directory_name:
            copied = Path(directory_name)
            for relative in runner.EXPECTED_FILES:
                destination = copied / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = copied / "distribution/s4-performance/WP8M-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(runner.PairedRunnerError):
                runner._verify_files(copied, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP8M-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(runner.PairedRunnerError):
                runner._verify_files(copied, authority)

    def test_hosted_workflow_cannot_acquire_or_observe(self) -> None:
        workflow = (
            ROOT / ".github/workflows/s4-register-residency-paired-runner.yml"
        ).read_text()
        self.assertNotIn("--acquire", workflow)
        self.assertNotIn("--observe", workflow)
        self.assertNotIn("taskset", workflow)


if __name__ == "__main__":
    unittest.main()
