from __future__ import annotations

import hashlib
import importlib.util
import io
import struct
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_measurement_runner.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8k_runner_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest() == runner.lt1.APACHE_HASH
)
FACT_VALUES = {
    "kernel-system": "Linux",
    "kernel-release": "6.12.1",
    "machine": "x86_64",
    "cpu-vendor": "GenuineIntel",
    "cpu-family": "6",
    "cpu-model": "154",
    "cpu-stepping": "3",
    "microcode": "0x123",
    "logical-cpu": "2",
    "affinity-mask": "2",
    "governor": "performance",
    "turbo-control": "intel-pstate-no-turbo",
    "turbo-value": "1",
    "monotonic-implementation": "clock_gettime(CLOCK_MONOTONIC)",
    "git-commit": "0123456789abcdef0123456789abcdef01234567",
}


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8K runner tests require the current Apache-2.0 surface",
)
class RegisterResidencyMeasurementRunnerTests(unittest.TestCase):
    @staticmethod
    def _eligible_host_report() -> bytes:
        facts = tuple(
            (name, FACT_VALUES[name]) for _ordinal, name in runner.wp8i.wp6.CONTRACT_FACTS
        )
        fact_body = b"".join(f"fact\t{name}\t{value}\n".encode() for name, value in facts)
        fingerprint = hashlib.sha256(
            runner.wp8i.wp6.FINGERPRINT_DOMAIN + fact_body
        ).hexdigest()
        rows = [
            runner.wp8i.REPORT_MAGIC,
            f"contract\t{runner.WP8I_CONTRACT_SEAL}",
            f"authority\t{runner.WP8I_AUTHORITY_SEAL}",
            f"candidate-role-authority\t{runner.wp8i.WP8H_AUTHORITY_SEAL}",
            f"host-protocol-authority\t{runner.wp8i.WP6_AUTHORITY_SEAL}",
            "protocol-status\tcandidate-controlled-host-protocol-admitted",
            "host-status\teligible-ephemeral-observation",
            f"role\t{runner.ROLE_NAME}",
            "baseline-role\tnaux-residual",
            "claim-status\tnot-admitted",
            "timing-status\tforbidden",
            "mode\thost-observation",
            f"fingerprint\t{fingerprint}",
        ]
        rows.extend(f"fact\t{name}\t{value}" for name, value in facts)
        rows.append("refusals\t0")
        body = b"".join(f"{row}\n".encode() for row in rows)
        return body + f"report-root\t{hashlib.sha256(runner.wp8i.REPORT_DOMAIN + body).hexdigest()}\n".encode()

    def test_eligible_wp8i_report_parses_exactly(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8k-host-") as directory_name:
            path = Path(directory_name) / "host.tsv"
            path.write_bytes(self._eligible_host_report())
            retained = runner.parse_retained_host(path, mock.sentinel.admission)
        self.assertEqual(retained.commit, FACT_VALUES["git-commit"])
        self.assertEqual(dict(retained.facts)["logical-cpu"], "2")

    def test_ineligible_or_mutated_host_report_fails_closed(self) -> None:
        raw = self._eligible_host_report()
        mutations = (
            raw.replace(b"eligible-ephemeral-observation", b"ineligible-observation", 1),
            raw.replace(b"refusals\t0", b"refusals\t1\nrefusal\t01\tunsupported-platform", 1),
            raw.replace(b"cpu-model\t154", b"cpu-model\t155", 1),
        )
        for mutation in mutations:
            with self.subTest(prefix=mutation[:32]):
                with tempfile.TemporaryDirectory(prefix="naux-wp8k-host-") as directory_name:
                    path = Path(directory_name) / "host.tsv"
                    path.write_bytes(mutation)
                    with self.assertRaises(runner.CandidateRunnerError):
                        runner.parse_retained_host(path, mock.sentinel.admission)

    def test_truncated_host_report_fails_with_runner_error(self) -> None:
        raw = self._eligible_host_report()
        lines = raw.splitlines(keepends=True)
        for extent in (2, 8, 13, 15):
            with self.subTest(extent=extent):
                body = b"".join(lines[:extent])
                truncated = body + (
                    f"report-root\t{hashlib.sha256(runner.wp8i.REPORT_DOMAIN + body).hexdigest()}\n"
                ).encode()
                with tempfile.TemporaryDirectory(prefix="naux-wp8k-host-") as directory_name:
                    path = Path(directory_name) / "host.tsv"
                    path.write_bytes(truncated)
                    with self.assertRaises(runner.CandidateRunnerError):
                        runner.parse_retained_host(path, mock.sentinel.admission)

    def test_candidate_result_requires_owner_four_and_exact_parity(self) -> None:
        raw = runner.RESULT_MAGIC + struct.pack(
            "<QqQQQQ", 1, 6_710_476_800, runner.REPS, runner.N, 4, 1234
        )
        result = runner.decode_candidate_record(raw, "01")
        self.assertEqual(result.owner, 4)
        self.assertEqual(result.duration_ns, 1234)
        drift = runner.RESULT_MAGIC + struct.pack(
            "<QqQQQQ", 1, 6_710_476_800, runner.REPS, runner.N, 1, 1234
        )
        with self.assertRaisesRegex(runner.CandidateRunnerError, "owner drifted"):
            runner.decode_candidate_record(drift, "01")

    def test_build_identity_detects_post_measurement_artifact_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8k-artifact-") as directory_name:
            directory = Path(directory_name)
            artifacts = []
            for ordinal, _name, _oracle in runner.KERNELS:
                path = directory / ordinal
                path.write_bytes(f"candidate-{ordinal}".encode())
                path.chmod(0o700)
                artifacts.append(
                    runner.wp7c._artifact(runner.ROLE_ORDINAL, ordinal, path)
                )
            artifact_tuple = tuple(artifacts)
            version = b"cargo test identity"
            tool = runner.wp7c.ToolIdentity(
                "cargo",
                "/test/cargo",
                "1" * 64,
                hashlib.sha256(version).hexdigest(),
                version.hex(),
            )
            toolchains = (tool,)
            build = runner.wp7c.RoleBuild(
                runner.ROLE_ORDINAL,
                runner.ROLE_NAME,
                "candidate-isolated",
                runner.wp7c.aggregate_binary_identity(artifact_tuple),
                runner.wp7c.aggregate_toolchain_identity(toolchains),
                1,
                1,
                artifact_tuple,
                toolchains,
            )
            with mock.patch.object(runner.wp7c, "_tool_identity", return_value=tool):
                runner.verify_build_identity(build)
                artifact_tuple[0].path.write_bytes(b"drifted")
                with self.assertRaisesRegex(
                    runner.CandidateRunnerError, "artifact identity drifted"
                ):
                    runner.verify_build_identity(build)

    def test_collection_retains_warmups_and_exact_120_samples(self) -> None:
        artifacts = tuple(
            runner.wp7c.Artifact(runner.ROLE_ORDINAL, ordinal, Path(f"/{ordinal}"), "0" * 64, 1)
            for ordinal, _name, _oracle in runner.KERNELS
        )
        build = runner.wp7c.RoleBuild(
            runner.ROLE_ORDINAL, runner.ROLE_NAME, "candidate-isolated",
            "1" * 64, "2" * 64, 1, 1, artifacts, (),
        )

        def execute(artifact: object) -> tuple[object, int, int]:
            oracle = next(value for ordinal, _name, value in runner.KERNELS if ordinal == artifact.kernel)
            result = runner.wp7c.CarrierResult(
                int(artifact.kernel), oracle, runner.REPS, runner.N, 4, 60_000_000
            )
            return result, 60_001_000, 4096

        with mock.patch.object(runner, "execute_candidate", side_effect=execute) as mocked:
            data = runner.collect_invocations(build)
        self.assertEqual(len(data.warmups), 8)
        self.assertEqual(len(data.samples), 120)
        self.assertEqual(mocked.call_count, 128)
        self.assertEqual(tuple(item.kernel for item in data.samples[::30]), ("01", "02", "03", "04"))

    @staticmethod
    def _publication_fixture(directory: Path) -> tuple[object, object, object, object]:
        artifacts = []
        for ordinal, name, _oracle in runner.KERNELS:
            path = directory / f"{ordinal}-{name}"
            path.write_bytes(f"artifact-{ordinal}".encode())
            path.chmod(0o700)
            artifacts.append(
                runner.wp7c._artifact(runner.ROLE_ORDINAL, ordinal, path)
            )
        artifact_tuple = tuple(artifacts)
        version = b"cargo publication identity"
        tool = runner.wp7c.ToolIdentity(
            "cargo",
            "/test/cargo",
            "2" * 64,
            hashlib.sha256(version).hexdigest(),
            version.hex(),
        )
        toolchains = (tool,)
        build = runner.wp7c.RoleBuild(
            runner.ROLE_ORDINAL,
            runner.ROLE_NAME,
            "candidate-isolated",
            runner.wp7c.aggregate_binary_identity(artifact_tuple),
            runner.wp7c.aggregate_toolchain_identity(toolchains),
            1,
            1,
            artifact_tuple,
            toolchains,
        )
        data = runner.wp7c.AcquisitionData((build,), (), ())
        admission = types.SimpleNamespace(
            authority=types.SimpleNamespace(seal="a" * 64)
        )
        retained = runner.RetainedHost(
            b"host-attestation\n",
            "b" * 64,
            "c" * 64,
            (("git-commit", "0123456789abcdef0123456789abcdef01234567"),),
        )
        return data, admission, retained, tool

    def test_atomic_publication_emits_exact_bundle_inventory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8k-publish-") as directory_name:
            directory = Path(directory_name)
            data, admission, retained, tool = self._publication_fixture(directory)
            host = directory / "retained-host.tsv"
            host.write_bytes(retained.raw)
            output = directory / "published"
            with mock.patch.object(runner.wp7c, "_tool_identity", return_value=tool):
                root = runner.publish_bundle(
                    ROOT,
                    output,
                    admission,
                    retained,
                    data,
                    b"raw-session\n",
                    "d" * 64,
                    host,
                )
            self.assertTrue(output.is_dir())
            manifest = (output / "MANIFEST.tsv").read_bytes()
            self.assertIn(b"meta\tfile-count\t8\n", manifest)
            self.assertIn(b"file\tRAW-SESSION.tsv\t12\t", manifest)
            self.assertTrue(manifest.endswith(f"bundle-root\t{root}\n".encode()))
            self.assertEqual(
                sorted(path.name for path in (output / "artifacts").iterdir()),
                ["01-sum-dense", "02-branch-mix", "03-dot-product", "04-list-update"],
            )

    def test_failed_atomic_publication_leaves_no_bundle_or_stage(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8k-rollback-") as directory_name:
            directory = Path(directory_name)
            data, admission, retained, tool = self._publication_fixture(directory)
            host = directory / "retained-host.tsv"
            host.write_bytes(retained.raw)
            output = directory / "published"
            with (
                mock.patch.object(runner.wp7c, "_tool_identity", return_value=tool),
                mock.patch.object(
                    runner.wp7c,
                    "_rename_noreplace",
                    side_effect=runner.wp7c.RunnerError("injected publication failure"),
                ),
            ):
                with self.assertRaisesRegex(
                    runner.wp7c.RunnerError, "injected publication failure"
                ):
                    runner.publish_bundle(
                        ROOT,
                        output,
                        admission,
                        retained,
                        data,
                        b"raw-session\n",
                        "d" * 64,
                        host,
                    )
            self.assertFalse(output.exists())
            self.assertFalse(any(path.name.startswith(".published.stage-") for path in directory.iterdir()))

    def test_acquisition_arguments_are_explicit_only(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                runner.main(["--root", str(ROOT), "--acquire"])
            with self.assertRaises(SystemExit):
                runner.main(["--root", str(ROOT), "--output", "/tmp/result"])
            with self.assertRaises(SystemExit):
                runner.main(["--root", str(ROOT), "--cargo", "other-cargo"])


if __name__ == "__main__":
    unittest.main()
