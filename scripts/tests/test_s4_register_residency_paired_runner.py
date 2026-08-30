from __future__ import annotations

import hashlib
import importlib.util
import io
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_paired_runner.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8m_paired_runner_test", SCRIPT)
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
    "WP8M runner tests require the current Apache-2.0 surface",
)
class RegisterResidencyPairedRunnerTests(unittest.TestCase):
    @staticmethod
    def _build_fixture(directory: Path) -> tuple[tuple[object, object], object]:
        version = b"cargo paired identity"
        tools = (
            runner.wp7c.ToolIdentity(
                "cargo", "/test/cargo", "1" * 64,
                hashlib.sha256(version).hexdigest(), version.hex(),
            ),
            runner.wp7c.ToolIdentity(
                "rustc", "/test/rustc", "2" * 64,
                hashlib.sha256(version + b" rustc").hexdigest(),
                (version + b" rustc").hex(),
            ),
        )
        builds = []
        for role, name, status, _owner in runner.ROLES:
            artifacts = []
            for kernel, kernel_name, _oracle in runner.KERNELS:
                path = directory / f"{role}-{kernel}-{kernel_name}"
                path.write_bytes(f"artifact-{role}-{kernel}".encode())
                path.chmod(0o700)
                artifacts.append(runner.wp7c._artifact(role, kernel, path))
            artifact_tuple = tuple(artifacts)
            builds.append(runner.wp7c.RoleBuild(
                role,
                name,
                status,
                runner.wp7c.aggregate_binary_identity(artifact_tuple),
                runner.wp7c.aggregate_toolchain_identity(tools),
                1,
                1,
                artifact_tuple,
                tools,
            ))
        return (builds[0], builds[1]), tools

    @staticmethod
    def _execute(artifact: object) -> tuple[object, int, int]:
        oracle = next(
            value for kernel, _name, value in runner.KERNELS
            if kernel == artifact.kernel
        )
        owner = 1 if artifact.role == runner.BASELINE_ROLE else 4
        result = runner.wp7c.CarrierResult(
            int(artifact.kernel), oracle, runner.wp8k.REPS,
            runner.wp8k.N, owner, 60_000_000,
        )
        return result, 60_001_000, 4096

    def test_collection_uses_exact_ab_ba_pairs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8m-pairs-") as directory_name:
            builds, _tools = self._build_fixture(Path(directory_name))
            with mock.patch.object(runner, "_execute", side_effect=self._execute) as execute:
                data = runner.collect_paired_invocations(builds)
        self.assertEqual(len(data.warmups), 8)
        self.assertEqual(len(data.samples), 120)
        self.assertEqual(execute.call_count, 256)
        first, second = data.samples[:2]
        self.assertEqual((first.order, first.first.role, first.second.role), ("AB", "01", "04"))
        self.assertEqual((second.order, second.first.role, second.second.role), ("BA", "04", "01"))
        self.assertEqual(tuple(pair.kernel for pair in data.samples[::30]), ("01", "02", "03", "04"))

    def test_schedule_mutation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8m-mutate-") as directory_name:
            builds, _tools = self._build_fixture(Path(directory_name))
            with mock.patch.object(runner, "_execute", side_effect=self._execute):
                data = runner.collect_paired_invocations(builds)
        first = data.samples[0]
        mutated = runner.PairRecord(first.kernel, first.ordinal, "BA", first.first, first.second)
        invalid = runner.PairedAcquisition(data.builds, data.warmups, (mutated, *data.samples[1:]))
        with self.assertRaisesRegex(runner.PairedRunnerError, "schedule drifted"):
            runner._validate_acquisition(invalid)

    def test_unknown_role_and_superfluous_warmup_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8m-invalid-") as directory_name:
            builds, _tools = self._build_fixture(Path(directory_name))
            with mock.patch.object(runner, "_execute", side_effect=self._execute):
                data = runner.collect_paired_invocations(builds)
                extra = runner._pair(builds, "01", 3)
        first = data.samples[0]
        unknown = runner.wp7c.Invocation(
            "99", first.first.kernel, first.first.ordinal,
            first.first.duration_ns, first.first.checksum,
            first.first.path_status, first.first.envelope_ns, first.first.rss_bytes,
        )
        bad_role = runner.PairRecord(
            first.kernel, first.ordinal, first.order, unknown, first.second
        )
        with self.assertRaises(runner.PairedRunnerError):
            runner._validate_pair(bad_role, "01", 1)
        too_many = runner.PairedAcquisition(
            data.builds,
            (*data.warmups[:2], extra, *data.warmups[2:]),
            data.samples,
        )
        with self.assertRaisesRegex(runner.PairedRunnerError, "continued"):
            runner._validate_acquisition(too_many)

    def test_raw_session_retains_pair_order_and_both_builds(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8m-session-") as directory_name:
            builds, _tools = self._build_fixture(Path(directory_name))
            with mock.patch.object(runner, "_execute", side_effect=self._execute):
                data = runner.collect_paired_invocations(builds)
        admission = types.SimpleNamespace(authority=types.SimpleNamespace(seal="a" * 64))
        retained = runner.wp8k.RetainedHost(
            b"host\n", "b" * 64, "c" * 64,
            (("git-commit", "0123456789abcdef0123456789abcdef01234567"),),
        )
        session, root = runner.build_raw_session(admission, retained, data)
        self.assertIn(b"sample-pairs\t120\n", session)
        self.assertIn(b"sample-pair\t01\t01\tAB\n", session)
        self.assertIn(b"sample-pair\t01\t02\tBA\n", session)
        self.assertEqual(session.count(b"sample-run\t"), 240)
        self.assertTrue(session.endswith(f"session-root\t{root}\n".encode()))

    def test_atomic_publication_contains_both_artifact_sets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8m-publish-") as directory_name:
            directory = Path(directory_name)
            builds, tools = self._build_fixture(directory)
            with mock.patch.object(runner, "_execute", side_effect=self._execute):
                data = runner.collect_paired_invocations(builds)
            admission = types.SimpleNamespace(authority=types.SimpleNamespace(seal="a" * 64))
            retained = runner.wp8k.RetainedHost(
                b"host\n", "b" * 64, "c" * 64,
                (("git-commit", "0123456789abcdef0123456789abcdef01234567"),),
            )
            host = directory / "host.tsv"
            host.write_bytes(retained.raw)
            output = directory / "published"
            identities = {tool.name: tool for tool in tools}
            with mock.patch.object(
                runner.wp7c, "_tool_identity",
                side_effect=lambda name, _path: identities[name],
            ):
                bundle_root = runner.publish_bundle(
                    ROOT, output, admission, retained, data,
                    b"paired-session\n", "d" * 64, host,
                )
            manifest = (output / "MANIFEST.tsv").read_bytes()
            self.assertIn(b"meta\tfile-count\t12\n", manifest)
            self.assertIn(b"file\tartifacts/baseline/01-sum-dense\t", manifest)
            self.assertIn(b"file\tartifacts/candidate/04-list-update\t", manifest)
            self.assertTrue(manifest.endswith(f"bundle-root\t{bundle_root}\n".encode()))

    def test_failed_publication_rolls_back_stage_and_bundle(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8m-rollback-") as directory_name:
            directory = Path(directory_name)
            builds, tools = self._build_fixture(directory)
            with mock.patch.object(runner, "_execute", side_effect=self._execute):
                data = runner.collect_paired_invocations(builds)
            admission = types.SimpleNamespace(authority=types.SimpleNamespace(seal="a" * 64))
            retained = runner.wp8k.RetainedHost(
                b"host\n", "b" * 64, "c" * 64,
                (("git-commit", "0123456789abcdef0123456789abcdef01234567"),),
            )
            host = directory / "host.tsv"
            host.write_bytes(retained.raw)
            output = directory / "published"
            identities = {tool.name: tool for tool in tools}
            with (
                mock.patch.object(
                    runner.wp7c, "_tool_identity",
                    side_effect=lambda name, _path: identities[name],
                ),
                mock.patch.object(
                    runner.wp7c, "_rename_noreplace",
                    side_effect=runner.wp7c.RunnerError("injected failure"),
                ),
            ):
                with self.assertRaisesRegex(runner.wp7c.RunnerError, "injected failure"):
                    runner.publish_bundle(
                        ROOT, output, admission, retained, data,
                        b"paired-session\n", "d" * 64, host,
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
