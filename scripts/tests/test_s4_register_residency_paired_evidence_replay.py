from __future__ import annotations

import hashlib
import importlib.util
import sys
import tempfile
import types
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_paired_evidence.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8n_paired_evidence_replay_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == evidence.wp8m.wp8k.lt1.APACHE_HASH
)
COMMIT = "0123456789abcdef0123456789abcdef01234567"
HOST_ROOT = "a" * 64


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8N replay tests require the current Apache-2.0 surface",
)
class RegisterResidencyPairedEvidenceReplayTests(unittest.TestCase):
    @staticmethod
    def _write(path: Path, raw: bytes, mode: int = 0o600) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(mode)

    @classmethod
    def _manifest(cls, bundle: Path, session_root: str) -> str:
        files = []
        for relative in evidence.EXPECTED_BUNDLE_FILES:
            raw = (bundle / relative).read_bytes()
            files.append((relative, len(raw), hashlib.sha256(raw).hexdigest()))
        rows = [
            evidence.wp8m.BUNDLE_MAGIC,
            f"meta\trunner-authority\t{evidence.WP8M_AUTHORITY_SEAL}",
            f"meta\thost-attestation\t{HOST_ROOT}",
            f"meta\tsession-root\t{session_root}",
            f"meta\tsource-commit\t{COMMIT}",
            "meta\tschedule\tkernel-major-odd-ab-even-ba",
            "meta\tclaim-status\tnot-admitted",
            f"meta\tfile-count\t{len(files)}",
        ]
        rows.extend(f"file\t{relative}\t{size}\t{digest}" for relative, size, digest in files)
        body = b"".join(f"{row}\n".encode() for row in rows)
        root = hashlib.sha256(evidence.BUNDLE_DOMAIN + body).hexdigest()
        cls._write(bundle / "MANIFEST.tsv", body + f"bundle-root\t{root}\n".encode())
        return root

    @staticmethod
    def _binary_hash(role: str, records: list[object]) -> str:
        rows = "".join(
            f"artifact\t{record.ordinal:02}\t{record.elf_hash}\t{record.elf_bytes}\n"
            for record in records
        )
        return hashlib.sha256(evidence.BINARY_DOMAIN + rows.encode()).hexdigest()

    @classmethod
    def _bundle(cls, parent: Path) -> tuple[Path, object, object]:
        bundle = parent / "bundle"
        bundle.mkdir(mode=0o700)
        baseline_records = []
        candidate_records = []
        hashes = {}
        sizes = {}
        for role, directory, records in (
            (evidence.wp8m.BASELINE_ROLE, "baseline", baseline_records),
            (evidence.wp8m.CANDIDATE_ROLE, "candidate", candidate_records),
        ):
            total = 0
            for ordinal, name, oracle in evidence.wp8m.KERNELS:
                raw = f"exact-{directory}-{ordinal}".encode()
                digest = hashlib.sha256(raw).hexdigest()
                cls._write(bundle / f"artifacts/{directory}/{ordinal}-{name}", raw, 0o700)
                records.append(types.SimpleNamespace(
                    ordinal=int(ordinal), name=name, oracle=oracle,
                    elf_bytes=len(raw), elf_hash=digest,
                ))
                total += len(raw)
            hashes[role] = cls._binary_hash(role, records)
            sizes[role] = total

        tool_rows = [
            evidence.wp8m.TOOLCHAIN_MAGIC,
            f"meta\trunner-authority\t{evidence.WP8M_AUTHORITY_SEAL}",
            f"meta\tsource-commit\t{COMMIT}",
            "meta\tclaim-status\tnot-admitted",
        ]
        aggregate = []
        for role in (evidence.wp8m.BASELINE_ROLE, evidence.wp8m.CANDIDATE_ROLE):
            for ordinal, name in (("01", "cargo"), ("02", "rustc")):
                version = f"{name} paired test".encode()
                executable_hash = hashlib.sha256(f"/{name}".encode()).hexdigest()
                version_hash = hashlib.sha256(version).hexdigest()
                tool_rows.append(
                    f"tool\t{role}\t{ordinal}\t{name}\t/test/{name}\t{executable_hash}\t"
                    f"{version_hash}\t{version.hex()}"
                )
                if role == evidence.wp8m.BASELINE_ROLE:
                    aggregate.append(f"tool\t{name}\t{executable_hash}\t{version_hash}\n")
        toolchain_hash = hashlib.sha256(
            evidence.TOOLCHAIN_DOMAIN + "".join(aggregate).encode()
        ).hexdigest()
        tool_body = b"".join(f"{row}\n".encode() for row in tool_rows)
        tool_root = hashlib.sha256(
            evidence.TOOLCHAIN_RECEIPT_DOMAIN + tool_body
        ).hexdigest()
        cls._write(bundle / "TOOLCHAINS.tsv", tool_body + f"toolchain-root\t{tool_root}\n".encode())

        cls._write(bundle / "HOST-ATTESTATION.tsv", b"synthetic-eligible-host\n")
        cls._write(
            bundle / "REPRODUCE.tsv",
            (
                "NAUX-S4-REGISTER-RESIDENCY-PAIRED-REPRODUCTION\t1\n"
                f"source-commit\t{COMMIT}\n"
                f"runner-authority\t{evidence.WP8M_AUTHORITY_SEAL}\n"
                f"host-attestation-root\t{HOST_ROOT}\n"
                "/placeholder\n"
                "policy\tnew-eligible-attestation-and-new-output-required-for-each-run\n"
            ).replace("/placeholder\n", "original-host-attestation\t/test/host.tsv\n").encode(),
        )

        session_rows = [
            evidence.wp8m.SESSION_MAGIC,
            f"meta\trunner-authority\t{evidence.WP8M_AUTHORITY_SEAL}",
            f"meta\thost-attestation\t{HOST_ROOT}",
            f"meta\tsource-commit\t{COMMIT}",
            f"meta\tbaseline-carrier-authority\t{evidence.WP7B_AUTHORITY_SEAL}",
            f"meta\tcandidate-carrier-authority\t{evidence.WP8J_AUTHORITY_SEAL}",
            "meta\tschedule\tkernel-major-odd-ab-even-ba",
            "meta\tclaim-status\tnot-admitted",
            f"build\t01\tnaux-residual\t{hashes['01']}\t{toolchain_hash}\t10\t20\t{sizes['01']}",
            f"build\t04\t{evidence.wp8m.wp8k.ROLE_NAME}\t{hashes['04']}\t{toolchain_hash}\t11\t21\t{sizes['04']}",
            "warmup-pairs\t8",
        ]
        statuses = {role: status for role, _name, status, _owner in evidence.wp8m.ROLES}
        for kernel, _name, oracle in evidence.wp8m.KERNELS:
            for pair in (1, 2):
                order = "AB" if pair % 2 else "BA"
                rendered = f"{pair:06}"
                session_rows.append(f"warmup-pair\t{kernel}\t{rendered}\t{order}")
                roles = ("01", "04") if order == "AB" else ("04", "01")
                for position, role in enumerate(roles, 1):
                    duration = 60_000_000 if role == "01" else 55_000_000
                    session_rows.append(
                        f"warmup-run\t{kernel}\t{rendered}\t{position}\t{role}\t{duration}\t"
                        f"{oracle}\t{duration + 1000}\t4096\t{statuses[role]}"
                    )
        session_rows.append("sample-pairs\t120")
        for kernel_index, (kernel, _name, oracle) in enumerate(evidence.wp8m.KERNELS):
            for pair in range(1, 31):
                order = "AB" if pair % 2 else "BA"
                rendered = f"{pair:02}"
                session_rows.append(f"sample-pair\t{kernel}\t{rendered}\t{order}")
                roles = ("01", "04") if order == "AB" else ("04", "01")
                baseline = 1_000 + kernel_index * 100 + pair
                candidate = baseline - 100
                for position, role in enumerate(roles, 1):
                    duration = baseline if role == "01" else candidate
                    session_rows.append(
                        f"sample-run\t{kernel}\t{rendered}\t{position}\t{role}\t{duration}\t"
                        f"{oracle}\t{duration + 100}\t4096\t{statuses[role]}"
                    )
        session_body = b"".join(f"{row}\n".encode() for row in session_rows)
        session_root = hashlib.sha256(evidence.SESSION_DOMAIN + session_body).hexdigest()
        cls._write(
            bundle / "RAW-PAIRED-SESSION.tsv",
            session_body + f"session-root\t{session_root}\n".encode(),
        )
        cls._manifest(bundle, session_root)
        admission = types.SimpleNamespace(
            contract=types.SimpleNamespace(seal="b" * 64),
            authority=types.SimpleNamespace(seal="c" * 64),
            runner=types.SimpleNamespace(
                candidate=types.SimpleNamespace(
                    carrier=types.SimpleNamespace(
                        contract=types.SimpleNamespace(records=tuple(candidate_records)),
                        wrapper=types.SimpleNamespace(
                            contract=types.SimpleNamespace(records=tuple(baseline_records))
                        ),
                    )
                )
            ),
        )
        retained = types.SimpleNamespace(report_root=HOST_ROOT, commit=COMMIT)
        return bundle, admission, retained

    @classmethod
    def _reseal_session_and_manifest(cls, bundle: Path) -> None:
        path = bundle / "RAW-PAIRED-SESSION.tsv"
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        root = hashlib.sha256(evidence.SESSION_DOMAIN + body).hexdigest()
        cls._write(path, body + f"session-root\t{root}\n".encode())
        cls._manifest(bundle, root)

    @classmethod
    def _reseal_toolchains_and_manifest(cls, bundle: Path) -> None:
        path = bundle / "TOOLCHAINS.tsv"
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        root = hashlib.sha256(evidence.TOOLCHAIN_RECEIPT_DOMAIN + body).hexdigest()
        cls._write(path, body + f"toolchain-root\t{root}\n".encode())
        manifest = evidence.parse_manifest(bundle)
        cls._manifest(bundle, manifest.session_root)

    def test_exact_bundle_replays_and_derives_paired_statistics(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8n-bundle-") as directory_name:
            bundle, admission, retained = self._bundle(Path(directory_name))
            with mock.patch.object(
                evidence.wp8m.wp8k, "parse_retained_host", return_value=retained
            ):
                replay = evidence.replay_bundle(bundle, admission)
        first = replay.session.comparisons[0]
        self.assertEqual(first.sample_pairs, 30)
        self.assertEqual((first.candidate_wins, first.ties, first.candidate_losses), (30, 0, 0))
        self.assertEqual((first.delta_total_ns, first.delta_median_num, first.delta_median_den), (-3000, -100, 1))
        self.assertIn(b"sample-invocations\t240\n", replay.evidence)
        self.assertIn(b"claim-status\tnot-admitted\n", replay.evidence)

    def test_coherently_resealed_schedule_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8n-schedule-") as directory_name:
            bundle, admission, retained = self._bundle(Path(directory_name))
            session = bundle / "RAW-PAIRED-SESSION.tsv"
            session.write_bytes(
                session.read_bytes().replace(b"sample-pair\t01\t01\tAB", b"sample-pair\t01\t01\tBA", 1)
            )
            self._reseal_session_and_manifest(bundle)
            with mock.patch.object(
                evidence.wp8m.wp8k, "parse_retained_host", return_value=retained
            ):
                with self.assertRaisesRegex(evidence.PairedEvidenceError, "schedule drifted"):
                    evidence.replay_bundle(bundle, admission)

    def test_coherently_resealed_artifact_drift_fails_parent_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8n-artifact-") as directory_name:
            bundle, admission, retained = self._bundle(Path(directory_name))
            target = bundle / "artifacts/candidate/01-sum-dense"
            target.write_bytes(b"different-candidate")
            target.chmod(0o700)
            manifest = evidence.parse_manifest(bundle)
            self._manifest(bundle, manifest.session_root)
            with mock.patch.object(
                evidence.wp8m.wp8k, "parse_retained_host", return_value=retained
            ):
                with self.assertRaisesRegex(evidence.PairedEvidenceError, "differs from its carrier"):
                    evidence.replay_bundle(bundle, admission)

    def test_coherently_resealed_cross_role_toolchain_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8n-tools-") as directory_name:
            bundle, admission, retained = self._bundle(Path(directory_name))
            receipt = bundle / "TOOLCHAINS.tsv"
            lines = receipt.read_text().splitlines()
            for index, line in enumerate(lines):
                if line.startswith("tool\t04\t02\trustc\t"):
                    fields = line.split("\t")
                    fields[4] = "/test/different-rustc"
                    lines[index] = "\t".join(fields)
                    break
            receipt.write_text("\n".join(lines) + "\n")
            self._reseal_toolchains_and_manifest(bundle)
            with mock.patch.object(
                evidence.wp8m.wp8k, "parse_retained_host", return_value=retained
            ):
                with self.assertRaisesRegex(evidence.PairedEvidenceError, "toolchain receipts differ"):
                    evidence.replay_bundle(bundle, admission)

    def test_extra_file_and_artifact_symlink_fail_inventory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8n-inventory-") as directory_name:
            bundle, admission, _retained = self._bundle(Path(directory_name))
            (bundle / "extra").write_text("no\n")
            with self.assertRaises(evidence.PairedEvidenceError):
                evidence.replay_bundle(bundle, admission)
        with tempfile.TemporaryDirectory(prefix="naux-wp8n-symlink-") as directory_name:
            bundle, admission, _retained = self._bundle(Path(directory_name))
            target = bundle / "artifacts/baseline/01-sum-dense"
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(evidence.PairedEvidenceError):
                evidence.replay_bundle(bundle, admission)

    def test_manifest_change_during_replay_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8n-race-") as directory_name:
            bundle, admission, retained = self._bundle(Path(directory_name))
            manifest = evidence.parse_manifest(bundle)
            changed = replace(manifest, root="d" * 64)
            with (
                mock.patch.object(evidence, "parse_manifest", side_effect=(manifest, changed)),
                mock.patch.object(
                    evidence.wp8m.wp8k, "parse_retained_host", return_value=retained
                ),
            ):
                with self.assertRaisesRegex(evidence.PairedEvidenceError, "changed during replay"):
                    evidence.replay_bundle(bundle, admission)

    def test_fraction_and_even_signed_median_are_exact(self) -> None:
        self.assertEqual(evidence._fraction(30, 24), (5, 4))
        self.assertEqual(evidence._median([-3, -2, -1, 4]), (-3, 2))


if __name__ == "__main__":
    unittest.main()
