from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_public_bundle.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8r_public_bundle_static_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
public_bundle = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = public_bundle
SPEC.loader.exec_module(public_bundle)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == public_bundle.wp8n.wp8m.wp8k.lt1.APACHE_HASH
)


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8R static tests require the current Apache-2.0 surface",
)
class RegisterResidencyPublicBundleStaticTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode())

    def test_static_report_is_deterministic_and_touches_no_bundle(self) -> None:
        with (
            mock.patch.object(
                public_bundle,
                "intake_archive",
                side_effect=AssertionError("archive intake"),
            ),
            mock.patch.object(
                public_bundle,
                "package_bundle",
                side_effect=AssertionError("bundle packaging"),
            ),
        ):
            first = public_bundle.validate(ROOT)
            second = public_bundle.validate(ROOT)
        self.assertEqual(first, second)
        text = first.report.decode()
        self.assertIn("archive-status\tabsent\n", text)
        self.assertIn("public-reachability\tnot-observed\n", text)
        self.assertIn("admission-status\tblocked\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)
        self.assertIn("blockers\t3\n", text)

    def test_coherently_resealed_contract_mutation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8r-contract-") as name:
            path = Path(name) / "WP8R-PUBLIC-BUNDLE.tsv"
            shutil.copy2(
                ROOT / "distribution/s4-performance/WP8R-PUBLIC-BUNDLE.tsv", path
            )
            path.write_text(
                path.read_text().replace(
                    "canonical-github-release-url-shape-no-reachability-claim",
                    "accept-any-url",
                    1,
                )
            )
            self._reseal(path, public_bundle.CONTRACT_DOMAIN)
            with self.assertRaises(public_bundle.PublicBundleError):
                public_bundle.parse_contract(path)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = public_bundle.parse_contract(
            ROOT / "distribution/s4-performance/WP8R-PUBLIC-BUNDLE.tsv"
        )
        authority = public_bundle.parse_authority(
            ROOT / "distribution/s4-performance/WP8R-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp8r-files-") as name:
            copied = Path(name)
            for relative in public_bundle.EXPECTED_FILES:
                destination = copied / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = copied / "distribution/s4-performance/WP8R-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(public_bundle.PublicBundleError):
                public_bundle._verify_files(copied, authority)
            shutil.copy2(
                ROOT / "distribution/s4-performance/WP8R-NONCLAIMS.md", target
            )
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(public_bundle.PublicBundleError):
                public_bundle._verify_files(copied, authority)

    def test_hosted_workflow_is_static_only(self) -> None:
        workflow = (
            ROOT / ".github/workflows/s4-register-residency-public-bundle.yml"
        ).read_text()
        for token in ("--archive", "--receipt", "--package-bundle", "curl "):
            self.assertNotIn(token, workflow)

    def test_cli_requires_complete_and_exclusive_explicit_modes(self) -> None:
        cases = (
            ["--archive", "bundle.tar.gz"],
            ["--receipt", "receipt.tsv"],
            ["--package-bundle", "bundle"],
            [
                "--package-bundle",
                "bundle",
                "--release-tag",
                "tag",
                "--output",
                "out",
                "--archive",
                "archive",
                "--receipt",
                "receipt",
            ],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    public_bundle.main(arguments)

    def test_no_network_or_claim_admission_api_exists(self) -> None:
        for name in (
            "fetch_archive",
            "query_release",
            "admit_claim",
            "approve_claim",
            "publish_claim",
        ):
            self.assertFalse(hasattr(public_bundle, name))


if __name__ == "__main__":
    unittest.main()
