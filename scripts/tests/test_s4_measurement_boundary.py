#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_measurement_boundary.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_measurement_boundary", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
wp4 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = wp4
SPEC.loader.exec_module(wp4)


class S4MeasurementBoundaryTests(unittest.TestCase):
    def test_repository_boundary_is_static_and_blocked(self) -> None:
        admission = wp4.validate(ROOT)
        self.assertEqual(admission.boundary.blockers, wp4.BOUNDARY_BLOCKERS)
        text = admission.report.decode()
        self.assertIn("claim-status\tnot-admitted\n", text)
        self.assertIn("timing-status\tforbidden\n", text)
        self.assertEqual(text.count("blocker\t"), 3)
        self.assertTrue(text.endswith(f"report-root\t{admission.report_root}\n"))

    def test_role_substitution_is_rejected_even_when_resealed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = self._copy_boundary(Path(temp))
            path = root / "distribution/s4-performance/WP4-BOUNDARY.tsv"
            text = path.read_text()
            text = text.replace(
                "meta\trequired-naux-role\tnaux-residual\n",
                "meta\trequired-naux-role\tnaux-trace-carrier-observation\n",
            )
            self._reseal(path, wp4.BOUNDARY_DOMAIN, text)
            with self.assertRaises(wp4.BoundaryError):
                wp4.parse_boundary(path)

    def test_sample_drop_policy_is_rejected_even_when_resealed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = self._copy_boundary(Path(temp))
            path = root / "distribution/s4-performance/WP4-BOUNDARY.tsv"
            text = path.read_text().replace(
                "meta\tsample-policy\tretain-all-in-collection-order\n",
                "meta\tsample-policy\tdrop-outliers\n",
            )
            self._reseal(path, wp4.BOUNDARY_DOMAIN, text)
            with self.assertRaises(wp4.BoundaryError):
                wp4.parse_boundary(path)

    def test_missing_claim_blocker_is_rejected_even_when_resealed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = self._copy_boundary(Path(temp))
            path = root / "distribution/s4-performance/WP4-BOUNDARY.tsv"
            lines = path.read_text().splitlines()
            lines.remove("blocker\t01\tnaux-residual-unavailable")
            text = "\n".join(lines) + "\n"
            self._reseal(path, wp4.BOUNDARY_DOMAIN, text)
            with self.assertRaises(wp4.BoundaryError):
                wp4.parse_boundary(path)

    def test_authority_parent_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = self._copy_boundary(Path(temp))
            path = root / "distribution/s4-performance/WP4-AUTHORITY.tsv"
            text = path.read_text().replace(wp4.WP3_AUTHORITY_SEAL, "0" * 64, 1)
            self._reseal(path, wp4.AUTHORITY_DOMAIN, text)
            boundary = wp4.parse_boundary(
                root / "distribution/s4-performance/WP4-BOUNDARY.tsv"
            )
            with self.assertRaises(wp4.BoundaryError):
                wp4.parse_authority(path, boundary.seal)

    def test_bound_file_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = self._copy_boundary(Path(temp))
            path = root / "distribution/s4-performance/WP4-NONCLAIMS.md"
            path.write_text(path.read_text() + "drift\n")
            boundary = wp4.parse_boundary(
                root / "distribution/s4-performance/WP4-BOUNDARY.tsv"
            )
            authority = wp4.parse_authority(
                root / "distribution/s4-performance/WP4-AUTHORITY.tsv", boundary.seal
            )
            with self.assertRaises(wp4.BoundaryError):
                wp4._verify_files(root, authority)

    def test_bound_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = self._copy_boundary(Path(temp))
            boundary = wp4.parse_boundary(
                root / "distribution/s4-performance/WP4-BOUNDARY.tsv"
            )
            authority = wp4.parse_authority(
                root / "distribution/s4-performance/WP4-AUTHORITY.tsv", boundary.seal
            )
            path = root / "distribution/s4-performance/WP4-NONCLAIMS.md"
            target = root / "nonclaims-copy.md"
            shutil.copy2(path, target)
            path.unlink()
            path.symlink_to(target)
            with self.assertRaises(wp4.BoundaryError):
                wp4._verify_files(root, authority)

    def test_workflow_cannot_collect_a_clock_sample(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workflow = root / ".github/workflows/s4-measurement-boundary.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                "python3 scripts/s4_measurement_boundary.py\n"
                "python3 -m unittest scripts.tests.test_s4_measurement_boundary\n"
                "perf stat true\n"
            )
            distribution = root / "distribution/s4-performance"
            distribution.mkdir(parents=True)
            for name in (
                "WP4-AUTHORITY.tsv",
                "WP4-BOUNDARY.tsv",
                "WP4-NONCLAIMS.md",
                "WP4-README.md",
            ):
                (distribution / name).write_text("placeholder\n")
            with self.assertRaises(wp4.BoundaryError):
                wp4._verify_clock_free_boundary(root)

    @staticmethod
    def _reseal(path: Path, domain: bytes, text: str) -> None:
        lines = text.splitlines()
        body = "".join(f"{line}\n" for line in lines[:-1]).encode()
        lines[-1] = f"seal\t{hashlib.sha256(domain + body).hexdigest()}"
        path.write_text("\n".join(lines) + "\n")

    @staticmethod
    def _copy_boundary(temp: Path) -> Path:
        for relative in (
            "distribution/s4-performance/WP4-BOUNDARY.tsv",
            "distribution/s4-performance/WP4-AUTHORITY.tsv",
            "distribution/s4-performance/WP4-NONCLAIMS.md",
            "distribution/s4-performance/WP4-README.md",
        ):
            destination = temp / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        return temp


if __name__ == "__main__":
    unittest.main()
