#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import io
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_measurement_runner.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_measurement_runner_static", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


class S4MeasurementRunnerStaticTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(
            body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode()
        )

    def test_static_admission_is_deterministic_and_claim_free(self) -> None:
        first = runner.validate(ROOT)
        second = runner.validate(ROOT)
        self.assertEqual(first, second)
        text = first.report.decode()
        self.assertIn("runner-status\tmeasurement-runner-structurally-admitted\n", text)
        self.assertIn("mode\tstatic-no-host-no-clock-no-execution\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)
        self.assertIn("samples-required\t360\n", text)

    def test_default_validation_cannot_reach_runner_acquisition_capabilities(self) -> None:
        with (
            mock.patch.object(runner, "_raw_ns", side_effect=AssertionError("clock")),
            mock.patch.object(runner, "verify_live_host", side_effect=AssertionError("host")),
            mock.patch.object(runner, "build_roles", side_effect=AssertionError("build")),
            mock.patch.object(runner, "collect_invocations", side_effect=AssertionError("execute")),
        ):
            runner.validate(ROOT)

    def test_contract_mutation_fails_after_coherent_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp7c-contract-") as directory:
            path = Path(directory) / "WP7C-RUNNER.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP7C-RUNNER.tsv", path)
            path.write_text(
                path.read_text().replace("exact360-no-retry", "exact359-no-retry", 1)
            )
            self._reseal(path, runner.CONTRACT_DOMAIN)
            with self.assertRaises(runner.RunnerError):
                runner.parse_contract(path)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = runner.parse_contract(
            ROOT / "distribution/s4-performance/WP7C-RUNNER.tsv"
        )
        authority = runner.parse_authority(
            ROOT / "distribution/s4-performance/WP7C-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp7c-files-") as directory:
            copied = Path(directory)
            for relative in runner.EXPECTED_FILES:
                destination = copied / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = copied / "distribution/s4-performance/WP7C-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(runner.RunnerError):
                runner._verify_files(copied, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP7C-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(runner.RunnerError):
                runner._verify_files(copied, authority)

    def test_host_and_output_arguments_are_explicit_acquisition_only(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                runner.main(["--root", str(ROOT), "--host-attestation", "host.tsv"])
            with self.assertRaises(SystemExit):
                runner.main(["--root", str(ROOT), "--acquire"])

    def test_hosted_workflow_remains_static_only(self) -> None:
        workflow = (ROOT / ".github/workflows/s4-measurement-runner.yml").read_text()
        self.assertNotIn("--acquire", workflow)
        self.assertIn("test_s4_measurement_runner_static", workflow)
        self.assertIn("test_s4_measurement_runner_replay", workflow)


if __name__ == "__main__":
    unittest.main()
