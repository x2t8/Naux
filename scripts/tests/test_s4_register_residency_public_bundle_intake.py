from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import sys
import tarfile
import tempfile
import types
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts.tests import test_s4_register_residency_paired_evidence_replay as wp8n_fixture


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_public_bundle.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8r_public_bundle_intake_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
public_bundle = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = public_bundle
SPEC.loader.exec_module(public_bundle)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == public_bundle.wp8n.wp8m.wp8k.lt1.APACHE_HASH
)
HASHES = {
    "bundle": "1" * 64,
    "session": "2" * 64,
    "host": "3" * 64,
    "evidence": "4" * 64,
}


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8R intake tests require the current Apache-2.0 surface",
)
class RegisterResidencyPublicBundleIntakeTests(unittest.TestCase):
    @staticmethod
    def _replay(**overrides: str) -> object:
        values = {**HASHES, **overrides}
        manifest = types.SimpleNamespace(
            root=values["bundle"],
            session_root=values["session"],
            host_attestation=values["host"],
            source_commit=public_bundle.wp8q.TRACKED_COMMIT,
        )
        return types.SimpleNamespace(
            manifest=manifest,
            evidence_root=values["evidence"],
        )

    @staticmethod
    def _source_bundle(parent: Path) -> Path:
        bundle = parent / "source-bundle"
        for relative in ("", "artifacts", "artifacts/baseline", "artifacts/candidate"):
            target = bundle if not relative else bundle / relative
            target.mkdir(mode=0o700)
        for relative in public_bundle.ARCHIVE_FILES:
            path = bundle / relative
            path.write_bytes(f"fixture:{relative}\n".encode())
            path.chmod(0o700 if relative.startswith("artifacts/") else 0o600)
        return bundle

    @staticmethod
    def _write_pair(parent: Path, archive: bytes, replay: object) -> tuple[Path, Path]:
        asset_name = public_bundle._asset_name(public_bundle.wp8q.TRACKED_COMMIT)
        archive_path = parent / asset_name
        receipt_path = parent / f"{asset_name}.receipt.tsv"
        archive_path.write_bytes(archive)
        archive_path.chmod(0o600)
        receipt_path.write_bytes(
            public_bundle._receipt_bytes("s4-wp8r-test", asset_name, archive, replay)
        )
        receipt_path.chmod(0o600)
        return archive_path, receipt_path

    @staticmethod
    def _reseal_receipt(path: Path) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(
            body
            + (
                "receipt-root\t"
                f"{hashlib.sha256(public_bundle.RECEIPT_DOMAIN + body).hexdigest()}\n"
            ).encode()
        )

    @staticmethod
    def _mutated_archive(raw: bytes, *, symlink: bool = False, extra: bool = False) -> bytes:
        source = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
        members = source.getmembers()
        payloads = {
            member.name: source.extractfile(member).read()
            for member in members
            if member.isfile()
        }
        output = io.BytesIO()
        with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for member in members:
                    clone = tarfile.TarInfo(member.name)
                    clone.type = member.type
                    clone.size = member.size
                    clone.mode = member.mode
                    clone.mtime = member.mtime
                    clone.uid = member.uid
                    clone.gid = member.gid
                    if symlink and member.isfile() and member.name.endswith("MANIFEST.tsv"):
                        clone.type = tarfile.SYMTYPE
                        clone.linkname = "HOST-ATTESTATION.tsv"
                        clone.size = 0
                        archive.addfile(clone)
                    elif member.isdir():
                        archive.addfile(clone)
                    else:
                        archive.addfile(clone, io.BytesIO(payloads[member.name]))
                if extra:
                    injected = tarfile.TarInfo("../escape")
                    injected.size = 1
                    injected.mode = 0o600
                    injected.mtime = 0
                    archive.addfile(injected, io.BytesIO(b"x"))
        source.close()
        return output.getvalue()

    def test_package_is_deterministic_and_intake_replays_wp8n(self) -> None:
        admission = public_bundle.validate(ROOT)
        replay = self._replay()
        with tempfile.TemporaryDirectory(prefix="naux-wp8r-package-") as name:
            parent = Path(name)
            bundle = self._source_bundle(parent)
            first = parent / "first"
            second = parent / "second"
            with mock.patch.object(public_bundle.wp8n, "replay_bundle", return_value=replay):
                first_report, _ = public_bundle.package_bundle(
                    ROOT, bundle, "s4-wp8r-test", first, admission
                )
                second_report, _ = public_bundle.package_bundle(
                    ROOT, bundle, "s4-wp8r-test", second, admission
                )
                asset_name = public_bundle._asset_name(public_bundle.wp8q.TRACKED_COMMIT)
                intake = public_bundle.intake_archive(
                    first / asset_name,
                    first / f"{asset_name}.receipt.tsv",
                    admission,
                )
            self.assertEqual(
                (first / asset_name).read_bytes(), (second / asset_name).read_bytes()
            )
            self.assertEqual(
                (first / f"{asset_name}.receipt.tsv").read_bytes(),
                (second / f"{asset_name}.receipt.tsv").read_bytes(),
            )
            self.assertIn(b"archive-integrity\tverified\n", first_report)
            self.assertIn(b"public-reachability\tnot-observed\n", first_report)
            self.assertIn(b"claim-status\tnot-admitted\n", intake.report)

    def test_archive_round_trip_uses_real_wp8n_replay(self) -> None:
        admission = public_bundle.validate(ROOT)
        with tempfile.TemporaryDirectory(prefix="naux-wp8r-round-trip-") as name:
            parent = Path(name)
            fixture = wp8n_fixture.RegisterResidencyPairedEvidenceReplayTests
            bundle, evidence_admission, retained = fixture._bundle(parent)
            admission = replace(admission, evidence=evidence_admission)
            output = parent / "release-candidate"
            with (
                mock.patch.object(
                    public_bundle.wp8q,
                    "TRACKED_COMMIT",
                    wp8n_fixture.COMMIT,
                ),
                mock.patch.object(
                    public_bundle.wp8n.wp8m.wp8k,
                    "parse_retained_host",
                    return_value=retained,
                ),
            ):
                package_report, _ = public_bundle.package_bundle(
                    ROOT, bundle, "s4-wp8r-integration", output, admission
                )
                asset_name = public_bundle._asset_name(wp8n_fixture.COMMIT)
                intake = public_bundle.intake_archive(
                    output / asset_name,
                    output / f"{asset_name}.receipt.tsv",
                    admission,
                )
            self.assertEqual(intake.replay.manifest.root, intake.receipt.bundle_root)
            self.assertEqual(intake.replay.evidence_root, intake.receipt.evidence_root)
            self.assertIn(b"archive-integrity\tverified\n", package_report)

    def test_archive_hash_tampering_fails_before_replay(self) -> None:
        admission = public_bundle.validate(ROOT)
        replay = self._replay()
        with tempfile.TemporaryDirectory(prefix="naux-wp8r-hash-") as name:
            parent = Path(name)
            bundle = self._source_bundle(parent)
            _root_name, raw = public_bundle._archive_bytes(bundle, replay)
            archive_path, receipt_path = self._write_pair(parent, raw, replay)
            archive_path.write_bytes(raw + b"tamper")
            with (
                mock.patch.object(
                    public_bundle.wp8n,
                    "replay_bundle",
                    side_effect=AssertionError("replay after hash failure"),
                ),
                self.assertRaisesRegex(public_bundle.PublicBundleError, "SHA-256"),
            ):
                public_bundle.intake_archive(archive_path, receipt_path, admission)

    def test_symlink_and_extra_path_archives_fail_closed(self) -> None:
        admission = public_bundle.validate(ROOT)
        replay = self._replay()
        with tempfile.TemporaryDirectory(prefix="naux-wp8r-envelope-") as name:
            parent = Path(name)
            bundle = self._source_bundle(parent)
            _root_name, original = public_bundle._archive_bytes(bundle, replay)
            for label, raw in (
                ("symlink", self._mutated_archive(original, symlink=True)),
                ("extra", self._mutated_archive(original, extra=True)),
            ):
                case = parent / label
                case.mkdir()
                archive_path, receipt_path = self._write_pair(case, raw, replay)
                with self.subTest(label=label), self.assertRaises(public_bundle.PublicBundleError):
                    public_bundle.intake_archive(archive_path, receipt_path, admission)

    def test_coherently_resealed_noncanonical_locator_fails(self) -> None:
        replay = self._replay()
        with tempfile.TemporaryDirectory(prefix="naux-wp8r-locator-") as name:
            parent = Path(name)
            bundle = self._source_bundle(parent)
            _root_name, raw = public_bundle._archive_bytes(bundle, replay)
            _archive_path, receipt_path = self._write_pair(parent, raw, replay)
            receipt_path.write_text(
                receipt_path.read_text().replace(
                    "https://github.com/x2t8/Naux/releases/download/",
                    "https://example.invalid/",
                    1,
                )
            )
            self._reseal_receipt(receipt_path)
            with self.assertRaisesRegex(public_bundle.PublicBundleError, "canonical"):
                public_bundle.parse_receipt(receipt_path)

    def test_replayed_identity_mismatch_fails_closed(self) -> None:
        admission = public_bundle.validate(ROOT)
        replay = self._replay()
        drifted = self._replay(evidence="5" * 64)
        with tempfile.TemporaryDirectory(prefix="naux-wp8r-identity-") as name:
            parent = Path(name)
            bundle = self._source_bundle(parent)
            _root_name, raw = public_bundle._archive_bytes(bundle, replay)
            archive_path, receipt_path = self._write_pair(parent, raw, replay)
            with (
                mock.patch.object(public_bundle.wp8n, "replay_bundle", return_value=drifted),
                self.assertRaisesRegex(public_bundle.PublicBundleError, "differs"),
            ):
                public_bundle.intake_archive(archive_path, receipt_path, admission)


if __name__ == "__main__":
    unittest.main()
