from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
import tempfile
import types
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_evidence.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8l_evidence_replay_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == evidence.wp8k.lt1.APACHE_HASH
)
COMMIT = "0123456789abcdef0123456789abcdef01234567"
FACT_VALUES = {
    "kernel-system": "Linux",
    "kernel-release": "7.1.5-test",
    "machine": "x86_64",
    "cpu-vendor": "GenuineIntel",
    "cpu-family": "6",
    "cpu-model": "141",
    "cpu-stepping": "1",
    "microcode": "0x58",
    "logical-cpu": "0",
    "affinity-mask": "0",
    "governor": "performance",
    "turbo-control": "intel-pstate-no-turbo",
    "turbo-value": "1",
    "monotonic-implementation": "clock_gettime(CLOCK_MONOTONIC)",
    "git-commit": COMMIT,
}


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8L replay tests require the current Apache-2.0 surface",
)
class RegisterResidencyEvidenceReplayTests(unittest.TestCase):
    @staticmethod
    def _write(path: Path, raw: bytes, mode: int = 0o600) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(mode)

    @staticmethod
    def _host_report() -> tuple[bytes, str]:
        facts = tuple(
            (name, FACT_VALUES[name])
            for _ordinal, name in evidence.wp8k.wp8i.wp6.CONTRACT_FACTS
        )
        fact_body = b"".join(
            f"fact\t{name}\t{value}\n".encode() for name, value in facts
        )
        fingerprint = hashlib.sha256(
            evidence.wp8k.wp8i.wp6.FINGERPRINT_DOMAIN + fact_body
        ).hexdigest()
        rows = [
            evidence.wp8k.wp8i.REPORT_MAGIC,
            f"contract\t{evidence.wp8k.WP8I_CONTRACT_SEAL}",
            f"authority\t{evidence.wp8k.WP8I_AUTHORITY_SEAL}",
            "candidate-role-authority\t"
            f"{evidence.wp8k.wp8i.WP8H_AUTHORITY_SEAL}",
            f"host-protocol-authority\t{evidence.wp8k.wp8i.WP6_AUTHORITY_SEAL}",
            "protocol-status\tcandidate-controlled-host-protocol-admitted",
            "host-status\teligible-ephemeral-observation",
            f"role\t{evidence.wp8k.ROLE_NAME}",
            "baseline-role\tnaux-residual",
            "claim-status\tnot-admitted",
            "timing-status\tforbidden",
            "mode\thost-observation",
            f"fingerprint\t{fingerprint}",
        ]
        rows.extend(f"fact\t{name}\t{value}" for name, value in facts)
        rows.append("refusals\t0")
        body = b"".join(f"{row}\n".encode() for row in rows)
        root = hashlib.sha256(evidence.wp8k.wp8i.REPORT_DOMAIN + body).hexdigest()
        return body + f"report-root\t{root}\n".encode(), root

    @classmethod
    def _manifest(cls, bundle: Path, host_root: str, session_root: str) -> str:
        files = []
        for relative in evidence.EXPECTED_BUNDLE_FILES:
            raw = (bundle / relative).read_bytes()
            files.append((relative, len(raw), hashlib.sha256(raw).hexdigest()))
        rows = [
            evidence.wp8k.BUNDLE_MAGIC,
            f"meta\trunner-authority\t{evidence.WP8K_AUTHORITY_SEAL}",
            f"meta\thost-attestation\t{host_root}",
            f"meta\tsession-root\t{session_root}",
            f"meta\tsource-commit\t{COMMIT}",
            "meta\tclaim-status\tnot-admitted",
            f"meta\tfile-count\t{len(files)}",
        ]
        rows.extend(
            f"file\t{relative}\t{size}\t{digest}"
            for relative, size, digest in files
        )
        body = b"".join(f"{row}\n".encode() for row in rows)
        root = hashlib.sha256(evidence.BUNDLE_DOMAIN + body).hexdigest()
        cls._write(bundle / "MANIFEST.tsv", body + f"bundle-root\t{root}\n".encode())
        return root

    @classmethod
    def _bundle(cls, parent: Path) -> tuple[Path, object]:
        bundle = parent / "bundle"
        bundle.mkdir(mode=0o700)
        (bundle / "artifacts").mkdir(mode=0o755)
        records = []
        artifact_rows = []
        code_size = 0
        for ordinal, name, oracle in evidence.wp8k.KERNELS:
            raw = f"exact-candidate-{ordinal}".encode()
            digest = hashlib.sha256(raw).hexdigest()
            cls._write(bundle / f"artifacts/{ordinal}-{name}", raw, 0o700)
            records.append(
                types.SimpleNamespace(
                    ordinal=int(ordinal),
                    name=name,
                    oracle=oracle,
                    elf_bytes=len(raw),
                    elf_hash=digest,
                )
            )
            artifact_rows.append(f"artifact\t{ordinal}\t{digest}\t{len(raw)}\n")
            code_size += len(raw)
        binary_hash = hashlib.sha256(
            evidence.BINARY_DOMAIN + "".join(artifact_rows).encode()
        ).hexdigest()

        tools = []
        aggregate_rows = []
        for ordinal, name in (("01", "cargo"), ("02", "rustc")):
            version = f"{name} test version".encode()
            executable_hash = hashlib.sha256(f"/{name}".encode()).hexdigest()
            version_hash = hashlib.sha256(version).hexdigest()
            tools.append(
                f"tool\t{ordinal}\t{name}\t/test/{name}\t{executable_hash}\t"
                f"{version_hash}\t{version.hex()}"
            )
            aggregate_rows.append(
                f"tool\t{name}\t{executable_hash}\t{version_hash}\n"
            )
        toolchain_hash = hashlib.sha256(
            evidence.TOOLCHAIN_DOMAIN + "".join(aggregate_rows).encode()
        ).hexdigest()
        tool_rows = [
            evidence.wp8k.TOOLCHAIN_MAGIC,
            f"meta\trunner-authority\t{evidence.WP8K_AUTHORITY_SEAL}",
            f"meta\tsource-commit\t{COMMIT}",
            "meta\tclaim-status\tnot-admitted",
            *tools,
        ]
        tool_body = b"".join(f"{row}\n".encode() for row in tool_rows)
        tool_root = hashlib.sha256(
            evidence.TOOLCHAIN_RECEIPT_DOMAIN + tool_body
        ).hexdigest()
        cls._write(
            bundle / "TOOLCHAINS.tsv",
            tool_body + f"toolchain-root\t{tool_root}\n".encode(),
        )

        host_raw, host_root = cls._host_report()
        cls._write(bundle / "HOST-ATTESTATION.tsv", host_raw)
        session_rows = [
            evidence.wp8k.SESSION_MAGIC,
            f"meta\trunner-authority\t{evidence.WP8K_AUTHORITY_SEAL}",
            f"meta\thost-attestation\t{host_root}",
            f"meta\tsource-commit\t{COMMIT}",
            f"meta\tcarrier-authority\t{evidence.WP8J_AUTHORITY_SEAL}",
            f"meta\trole\t{evidence.wp8k.ROLE_NAME}",
            "meta\tclaim-status\tnot-admitted",
            f"build\t{binary_hash}\t{toolchain_hash}\t1\t1\t{code_size}",
            "warmups\t8",
        ]
        for ordinal, _name, oracle in evidence.wp8k.KERNELS:
            for warmup in range(1, 3):
                session_rows.append(
                    f"warmup\t{ordinal}\t{warmup}\t60000000\t{oracle}\t"
                    "60001000\t4096"
                )
        session_rows.append("samples\t120")
        for ordinal, _name, oracle in evidence.wp8k.KERNELS:
            for sample in range(1, 31):
                duration = 1_000_000 + int(ordinal) * 1_000 + sample
                session_rows.append(
                    f"sample\t{ordinal}\t{sample}\t{duration}\t{oracle}\t"
                    f"{duration + 1000}\t4096"
                )
        session_body = b"".join(f"{row}\n".encode() for row in session_rows)
        session_root = hashlib.sha256(
            evidence.SESSION_DOMAIN + session_body
        ).hexdigest()
        cls._write(
            bundle / "RAW-SESSION.tsv",
            session_body + f"session-root\t{session_root}\n".encode(),
        )
        reproduction = (
            "NAUX-S4-REGISTER-RESIDENCY-REPRODUCTION\t1\n"
            f"source-commit\t{COMMIT}\n"
            f"runner-authority\t{evidence.WP8K_AUTHORITY_SEAL}\n"
            f"host-attestation-root\t{host_root}\n"
            "/tmp/original-host-attestation.tsv\n"
            "policy\tnew-eligible-attestation-and-new-output-required-for-each-run\n"
        ).replace(
            "/tmp/original-host-attestation.tsv\n",
            "original-host-attestation\t/tmp/original-host-attestation.tsv\n",
        )
        cls._write(bundle / "REPRODUCE.tsv", reproduction.encode())
        cls._manifest(bundle, host_root, session_root)
        admission = types.SimpleNamespace(
            contract=types.SimpleNamespace(seal="e" * 64),
            authority=types.SimpleNamespace(seal="f" * 64),
            runner=types.SimpleNamespace(
                carrier=types.SimpleNamespace(
                    contract=types.SimpleNamespace(records=tuple(records))
                )
            ),
        )
        return bundle, admission

    @staticmethod
    def _reseal_session(bundle: Path) -> str:
        path = bundle / "RAW-SESSION.tsv"
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        root = hashlib.sha256(evidence.SESSION_DOMAIN + body).hexdigest()
        RegisterResidencyEvidenceReplayTests._write(
            path, body + f"session-root\t{root}\n".encode()
        )
        return root

    def test_complete_bundle_replays_to_exact_statistics(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8l-replay-") as directory_name:
            bundle, admission = self._bundle(Path(directory_name))
            replay = evidence.replay_bundle(bundle, admission)
        self.assertEqual(len(replay.session.statistics), 4)
        first = replay.session.statistics[0]
        self.assertEqual((first.warmup_count, first.warmup_ns), (2, 120_000_000))
        self.assertEqual((first.sample_count, first.minimum_ns, first.maximum_ns), (30, 1_001_001, 1_001_030))
        self.assertEqual((first.median_num, first.median_den), (2_002_031, 2))
        self.assertIn(b"samples\t120\nclaim-status\tnot-admitted\n", replay.evidence)

    def test_coherently_resealed_wrong_checksum_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8l-checksum-") as directory_name:
            bundle, admission = self._bundle(Path(directory_name))
            path = bundle / "RAW-SESSION.tsv"
            raw = path.read_bytes().replace(b"\t6710476800\t1002001\t", b"\t6710476801\t1002001\t", 1)
            self._write(path, raw)
            session_root = self._reseal_session(bundle)
            host_raw = (bundle / "HOST-ATTESTATION.tsv").read_bytes()
            host_root = host_raw.split(b"report-root\t")[-1].strip().decode()
            self._manifest(bundle, host_root, session_root)
            with self.assertRaisesRegex(evidence.CandidateEvidenceError, "checksum"):
                evidence.replay_bundle(bundle, admission)

    def test_coherently_resealed_artifact_drift_fails_wp8j_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8l-artifact-") as directory_name:
            bundle, admission = self._bundle(Path(directory_name))
            path = bundle / "artifacts/01-sum-dense"
            self._write(path, b"different-candidate", 0o700)
            session_raw = (bundle / "RAW-SESSION.tsv").read_bytes()
            session_root = session_raw.split(b"session-root\t")[-1].strip().decode()
            host_raw = (bundle / "HOST-ATTESTATION.tsv").read_bytes()
            host_root = host_raw.split(b"report-root\t")[-1].strip().decode()
            self._manifest(bundle, host_root, session_root)
            with self.assertRaisesRegex(evidence.CandidateEvidenceError, "differs from WP8J"):
                evidence.replay_bundle(bundle, admission)

    def test_extra_file_and_symlink_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8l-inventory-") as directory_name:
            bundle, admission = self._bundle(Path(directory_name))
            self._write(bundle / "extra", b"extra")
            with self.assertRaisesRegex(evidence.CandidateEvidenceError, "inventory"):
                evidence.replay_bundle(bundle, admission)
            (bundle / "extra").unlink()
            target = bundle.parent / "RAW-SESSION.copy"
            os.rename(bundle / "RAW-SESSION.tsv", target)
            (bundle / "RAW-SESSION.tsv").symlink_to(target)
            with self.assertRaisesRegex(
                evidence.CandidateEvidenceError, "bounded regular file"
            ):
                evidence.replay_bundle(bundle, admission)

    def test_manifest_drift_during_replay_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8l-race-") as directory_name:
            bundle, admission = self._bundle(Path(directory_name))
            original = evidence.parse_manifest
            calls = 0

            def drifting_manifest(path: Path) -> object:
                nonlocal calls
                calls += 1
                manifest = original(path)
                return replace(manifest, root="0" * 64) if calls == 2 else manifest

            with mock.patch.object(
                evidence, "parse_manifest", side_effect=drifting_manifest
            ):
                with self.assertRaisesRegex(
                    evidence.CandidateEvidenceError, "changed during replay"
                ):
                    evidence.replay_bundle(bundle, admission)


if __name__ == "__main__":
    unittest.main()
