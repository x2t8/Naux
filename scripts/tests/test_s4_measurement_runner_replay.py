#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_measurement_runner.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_measurement_runner_replay", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


class S4MeasurementRunnerReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.admission = runner.validate(ROOT)
        cls.evidence = runner.wp7a.validate(ROOT)
        cls.host_admission = runner.wp7a.wp6.validate(ROOT)

    def retained(self, directory: Path) -> runner.RetainedHost:
        values = {
            "kernel-system": "Linux",
            "kernel-release": "6.12.1-naux",
            "machine": "x86_64",
            "cpu-vendor": "GenuineIntel",
            "cpu-family": "6",
            "cpu-model": "154",
            "cpu-stepping": "4",
            "microcode": "0xffffffff",
            "logical-cpu": "2",
            "affinity-mask": "2",
            "governor": "performance",
            "turbo-control": "intel-pstate-no-turbo",
            "turbo-value": "1",
            "monotonic-implementation": "clock_gettime-CLOCK_MONOTONIC",
            "git-commit": "4" * 40,
        }
        facts = tuple((name, values[name]) for _ordinal, name in runner.wp7a.wp6.CONTRACT_FACTS)
        body = b"".join(f"fact\t{name}\t{value}\n".encode() for name, value in facts)
        observation = runner.wp7a.wp6.HostObservation(
            facts,
            (),
            hashlib.sha256(runner.wp7a.wp6.FINGERPRINT_DOMAIN + body).hexdigest(),
        )
        raw = runner.wp7a.wp6.observation_report(self.host_admission, observation)
        path = directory / "host.tsv"
        path.write_bytes(raw)
        return runner.parse_retained_host(path, self.admission)

    def acquisition_data(self, directory: Path) -> runner.AcquisitionData:
        directory.mkdir(parents=True)
        builds: list[runner.RoleBuild] = []
        warmups: list[runner.Invocation] = []
        samples: list[runner.Invocation] = []
        for role, name, status in runner.wp7a.ROLES:
            artifacts: list[runner.Artifact] = []
            role_directory = directory / role
            role_directory.mkdir()
            for kernel, _kernel_name, oracle in runner.wp7a.KERNELS:
                path = role_directory / kernel
                path.write_bytes(f"synthetic-{role}-{kernel}".encode())
                path.chmod(0o700)
                raw = path.read_bytes()
                artifacts.append(
                    runner.Artifact(role, kernel, path, hashlib.sha256(raw).hexdigest(), len(raw))
                )
                warmups.append(
                    runner.Invocation(role, kernel, 1, 100_000_000, oracle, status, 100_001_000, 4096)
                )
                for ordinal in range(1, 31):
                    duration = 1_000_000 + int(role) * 10_000 + int(kernel) * 100 + ordinal % 3
                    samples.append(
                        runner.Invocation(role, kernel, ordinal, duration, oracle, status, duration + 1000, 4096)
                    )
            artifact_tuple = tuple(artifacts)
            version = f"synthetic-tool-{role}\n".encode()
            tool_names = ("cargo", "rustc") if role == "01" else ("cc",)
            toolchains = tuple(
                runner.ToolIdentity(
                    tool_name,
                    f"/synthetic/tool/{role}/{tool_name}",
                    hashlib.sha256(f"executable-{role}-{tool_name}".encode()).hexdigest(),
                    hashlib.sha256(version + tool_name.encode()).hexdigest(),
                    (version + tool_name.encode()).hex(),
                )
                for tool_name in tool_names
            )
            builds.append(
                runner.RoleBuild(
                    role,
                    name,
                    status,
                    runner.aggregate_binary_identity(artifact_tuple),
                    runner.aggregate_toolchain_identity(toolchains),
                    1000 + int(role),
                    500 if role == "01" else 0,
                    artifact_tuple,
                    toolchains,
                )
            )
        return runner.AcquisitionData(tuple(builds), tuple(warmups), tuple(samples))

    def test_retained_eligible_report_and_live_exact_match_replay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp7c-host-") as directory_name:
            retained = self.retained(Path(directory_name))
            observation = runner.wp7a.wp6.HostObservation(retained.facts, (), retained.fingerprint)
            with mock.patch.object(runner.wp7a.wp6, "observe", return_value=observation):
                runner.verify_live_host(ROOT, retained)
            changed = runner.wp7a.wp6.HostObservation(retained.facts, (), "9" * 64)
            with (
                mock.patch.object(runner.wp7a.wp6, "observe", return_value=changed),
                self.assertRaises(runner.RunnerError),
            ):
                runner.verify_live_host(ROOT, retained)

    def test_retained_report_mutation_and_symlink_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp7c-host-mutation-") as directory_name:
            directory = Path(directory_name)
            retained = self.retained(directory)
            path = directory / "host.tsv"
            path.write_bytes(retained.raw.replace(b"performance", b"powersave", 1))
            with self.assertRaises(runner.RunnerError):
                runner.parse_retained_host(path, self.admission)
            path.unlink()
            real = directory / "real.tsv"
            real.write_bytes(retained.raw)
            path.symlink_to(real.name)
            with self.assertRaises(runner.RunnerError):
                runner.parse_retained_host(path, self.admission)

    def test_fixed_le56_record_requires_every_identity_field(self) -> None:
        raw = runner.RESULT_MAGIC + struct.pack(
            "<QqQQQQ", 1, 6_710_476_800, runner.REPS, runner.N, 1, 1234
        )
        result = runner.decode_carrier_record(raw, "01", "01")
        self.assertEqual(result.duration_ns, 1234)
        for mutation in (
            raw[:-1],
            raw[:40] + struct.pack("<Q", 2) + raw[48:],
            runner.RESULT_MAGIC + struct.pack("<QqQQQQ", 1, 0, runner.REPS, runner.N, 1, 1234),
        ):
            with self.assertRaises(runner.RunnerError):
                runner.decode_carrier_record(mutation, "01", "01")

    def test_complete_acquisition_replays_evidence_and_retains_all_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp7c-evidence-") as directory_name:
            directory = Path(directory_name)
            retained = self.retained(directory)
            data = self.acquisition_data(directory / "artifacts")
            candidate, session = runner.build_evidence_candidate(
                self.evidence, self.admission, retained, data
            )
            self.assertEqual(candidate.count(b"sample\t"), 360)
            self.assertEqual(candidate.count(b"warmup\t"), 12)
            self.assertEqual(session.count(b"sample-run\t"), 360)
            self.assertEqual(session.count(b"warmup-run\t"), 12)
            self.assertIn(b"claim-status\tnot-admitted\n", candidate)

    def test_missing_sample_short_warmup_and_bad_envelope_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp7c-refusal-") as directory_name:
            directory = Path(directory_name)
            retained = self.retained(directory)
            data = self.acquisition_data(directory / "artifacts")
            mutations = (
                runner.AcquisitionData(data.builds, data.warmups, data.samples[:-1]),
                runner.AcquisitionData(
                    data.builds,
                    (runner.Invocation("01", "01", 1, 99_999_999, 6_710_476_800, "native-clean", 100_000_999, 4096),) + data.warmups[1:],
                    data.samples,
                ),
                runner.AcquisitionData(
                    data.builds,
                    data.warmups,
                    (runner.Invocation("01", "01", 1, data.samples[0].duration_ns, 6_710_476_800, "native-clean", data.samples[0].duration_ns, 4096),) + data.samples[1:],
                ),
            )
            for mutation in mutations:
                with self.subTest(samples=len(mutation.samples)), self.assertRaises(runner.RunnerError):
                    runner.build_evidence_candidate(
                        self.evidence, self.admission, retained, mutation
                    )

    def test_bundle_is_complete_atomic_and_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp7c-bundle-") as directory_name:
            directory = Path(directory_name)
            retained = self.retained(directory)
            data = self.acquisition_data(directory / "artifacts")
            evidence, session = runner.build_evidence_candidate(
                self.evidence, self.admission, retained, data
            )
            output = directory / "published"
            bundle_root = runner.publish_bundle(
                ROOT, output, self.admission, retained, data, evidence, session,
                directory / "host.tsv",
            )
            manifest = (output / "MANIFEST.tsv").read_text()
            self.assertIn(f"bundle-root\t{bundle_root}\n", manifest)
            toolchains = (output / "TOOLCHAINS.tsv").read_text()
            self.assertIn("tool\t01\t01\tcargo\t", toolchains)
            self.assertIn("tool\t01\t02\trustc\t", toolchains)
            self.assertEqual(toolchains.count("\ntool\t"), 4)
            self.assertEqual(len(tuple((output / "artifacts").glob("*/*"))), 12)
            with self.assertRaises(runner.RunnerError):
                runner.publish_bundle(
                    ROOT, output, self.admission, retained, data, evidence, session,
                    directory / "host.tsv",
                )


if __name__ == "__main__":
    unittest.main()
