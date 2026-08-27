#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_threshold_evaluator.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_threshold_evaluator_replay", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
evaluator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evaluator
SPEC.loader.exec_module(evaluator)
runner = evaluator.wp7c


class S4ThresholdEvaluatorReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.admission = evaluator.validate(ROOT)
        cls.evidence_admission = runner.wp7a.validate(ROOT)
        cls.host_admission = runner.wp7a.wp6.validate(ROOT)

    def _retained(self, directory: Path) -> tuple[runner.RetainedHost, Path]:
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
        return runner.parse_retained_host(path, self.admission.runner), path

    def _data(self, directory: Path, profile: str = "pass") -> runner.AcquisitionData:
        directory.mkdir(parents=True)
        bases = {"01": 1_000_000, "02": 1_500_000, "03": 1_000_000}
        if profile == "threshold-fail":
            bases["02"] = 1_100_000
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
                for ordinal in range(1, runner.SAMPLE_COUNT + 1):
                    duration = bases[role] + int(kernel) * 100 + ordinal % 3
                    if profile == "variance-fail" and role == "01" and kernel == "01":
                        duration = 500_000 if ordinal <= 15 else 1_500_000
                    samples.append(
                        runner.Invocation(
                            role, kernel, ordinal, duration, oracle, status, duration + 1000, 4096
                        )
                    )
            artifact_tuple = tuple(artifacts)
            tool_names = ("cargo", "rustc") if role == "01" else ("cc",)
            toolchains: list[runner.ToolIdentity] = []
            for tool_name in tool_names:
                version = f"synthetic-{role}-{tool_name}\n".encode()
                toolchains.append(
                    runner.ToolIdentity(
                        tool_name,
                        f"/synthetic/tool/{role}/{tool_name}",
                        hashlib.sha256(f"executable-{role}-{tool_name}".encode()).hexdigest(),
                        hashlib.sha256(version).hexdigest(),
                        version.hex(),
                    )
                )
            toolchain_tuple = tuple(toolchains)
            builds.append(
                runner.RoleBuild(
                    role,
                    name,
                    status,
                    runner.aggregate_binary_identity(artifact_tuple),
                    runner.aggregate_toolchain_identity(toolchain_tuple),
                    1000 + int(role),
                    500 if role == "01" else 0,
                    artifact_tuple,
                    toolchain_tuple,
                )
            )
        return runner.AcquisitionData(tuple(builds), tuple(warmups), tuple(samples))

    def _bundle(self, directory: Path, profile: str = "pass") -> Path:
        retained, host_path = self._retained(directory)
        data = self._data(directory / "source-artifacts", profile)
        evidence, session = runner.build_evidence_candidate(
            self.evidence_admission, self.admission.runner, retained, data
        )
        bundle = directory / "bundle"
        runner.publish_bundle(
            ROOT,
            bundle,
            self.admission.runner,
            retained,
            data,
            evidence,
            session,
            host_path,
        )
        return bundle

    @staticmethod
    def _reseal_manifest(bundle: Path, relative: str) -> None:
        target = bundle / relative
        raw = target.read_bytes()
        lines = (bundle / "MANIFEST.tsv").read_text().splitlines()
        wanted = f"file\t{relative}\t"
        replacements = 0
        for index, line in enumerate(lines[:-1]):
            if line.startswith(wanted):
                lines[index] = f"file\t{relative}\t{len(raw)}\t{hashlib.sha256(raw).hexdigest()}"
                replacements += 1
        if replacements != 1:
            raise AssertionError("manifest target not unique")
        body = b"".join(f"{line}\n".encode() for line in lines[:-1])
        root = hashlib.sha256(evaluator.BUNDLE_DOMAIN + body).hexdigest()
        (bundle / "MANIFEST.tsv").write_bytes(body + f"bundle-root\t{root}\n".encode())

    @staticmethod
    def _reseal_document(path: Path, domain: bytes, label: str) -> None:
        lines = path.read_text().splitlines()
        body = b"".join(f"{line}\n".encode() for line in lines[:-1])
        path.write_bytes(body + f"{label}\t{hashlib.sha256(domain + body).hexdigest()}\n".encode())

    def test_same_kernel_threshold_intersection_passes_but_never_admits_claim(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp7d-pass-") as directory_name:
            replay = evaluator.replay_bundle(
                self._bundle(Path(directory_name)), self.admission
            )
            text = replay.report.decode()
            self.assertIn("variance-gate\tpass\n", text)
            self.assertIn("intersection-kernels\t4\n", text)
            self.assertIn("threshold-candidate\tpass\n", text)
            self.assertIn("claim-status\tnot-admitted\n", text)
            self.assertIn("claim-authority\trequired-not-admitted\n", text)

    def test_threshold_or_variance_failure_cannot_form_a_candidate(self) -> None:
        for profile in ("threshold-fail", "variance-fail"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory(
                prefix=f"naux-wp7d-{profile}-"
            ) as directory_name:
                replay = evaluator.replay_bundle(
                    self._bundle(Path(directory_name), profile), self.admission
                )
                self.assertIn(b"threshold-candidate\tfail\n", replay.report)
                if profile == "variance-fail":
                    self.assertIn(b"variance-gate\tfail\n", replay.report)

    def test_artifact_mutation_fails_even_after_manifest_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp7d-artifact-") as directory_name:
            bundle = self._bundle(Path(directory_name))
            relative = "artifacts/01-naux-residual/01-sum-dense"
            target = bundle / relative
            target.write_bytes(target.read_bytes() + b"mutation")
            target.chmod(0o700)
            self._reseal_manifest(bundle, relative)
            with self.assertRaises(evaluator.ThresholdError):
                evaluator.replay_bundle(bundle, self.admission)

    def test_session_mutation_fails_after_session_and_manifest_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp7d-session-") as directory_name:
            bundle = self._bundle(Path(directory_name))
            path = bundle / "SESSION.tsv"
            text = path.read_text().replace(
                "sample-run\t01\t01\t01\t1000101\t1001101",
                "sample-run\t01\t01\t01\t1000102\t1001101",
                1,
            )
            self.assertNotEqual(text, path.read_text())
            path.write_text(text)
            self._reseal_document(path, evaluator.SESSION_DOMAIN, "session-root")
            self._reseal_manifest(bundle, "SESSION.tsv")
            with self.assertRaises(evaluator.ThresholdError):
                evaluator.replay_bundle(bundle, self.admission)

    def test_toolchain_mutation_fails_after_receipt_and_manifest_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp7d-toolchain-") as directory_name:
            bundle = self._bundle(Path(directory_name))
            path = bundle / "TOOLCHAINS.tsv"
            lines = path.read_text().splitlines()
            fields = lines[4].split("\t")
            changed = bytes.fromhex(fields[7]) + b"changed"
            fields[6] = hashlib.sha256(changed).hexdigest()
            fields[7] = changed.hex()
            lines[4] = "\t".join(fields)
            path.write_text("\n".join(lines) + "\n")
            self._reseal_document(
                path, evaluator.TOOLCHAIN_RECEIPT_DOMAIN, "toolchain-root"
            )
            self._reseal_manifest(bundle, "TOOLCHAINS.tsv")
            with self.assertRaises(evaluator.ThresholdError):
                evaluator.replay_bundle(bundle, self.admission)

    def test_missing_extra_and_symlink_bundle_entries_fail_closed(self) -> None:
        mutations = ("missing", "extra", "symlink")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(
                prefix=f"naux-wp7d-{mutation}-"
            ) as directory_name:
                bundle = self._bundle(Path(directory_name))
                if mutation == "missing":
                    (bundle / "REPRODUCE.tsv").unlink()
                elif mutation == "extra":
                    (bundle / "EXTRA.tsv").write_text("extra\n")
                else:
                    (bundle / "EXTRA.tsv").symlink_to("REPRODUCE.tsv")
                with self.assertRaises(evaluator.ThresholdError):
                    evaluator.replay_bundle(bundle, self.admission)

    def test_bundle_path_symlink_is_rejected_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp7d-bundle-link-") as directory_name:
            directory = Path(directory_name)
            bundle = self._bundle(directory)
            link = directory / "bundle-link"
            link.symlink_to(bundle.name, target_is_directory=True)
            with self.assertRaises(evaluator.ThresholdError):
                evaluator.replay_bundle(link, self.admission)


if __name__ == "__main__":
    unittest.main()
