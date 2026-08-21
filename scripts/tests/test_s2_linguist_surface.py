from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts/s2_linguist_surface.py"
SPEC = importlib.util.spec_from_file_location("s2_linguist_surface", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
SURFACE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SURFACE
SPEC.loader.exec_module(SURFACE)


class S2LinguistSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock_path = REPO_ROOT / "distribution/s2-preview/LINGUIST-SURFACE.tsv"
        self.surface_root = REPO_ROOT / "vscode/naux-lang"

    def test_canonical_lock_admits_the_monorepo_mirror(self) -> None:
        lock = SURFACE.parse_lock(self.lock_path)
        SURFACE.verify_files(self.surface_root, lock)
        SURFACE.verify_identity(self.surface_root, lock)
        self.assertEqual(lock.metadata["tag"], "v0.1.2")
        self.assertEqual(len(lock.files), 14)

    def test_content_mutation_fails_closed(self) -> None:
        lock = SURFACE.parse_lock(self.lock_path)
        with tempfile.TemporaryDirectory(prefix="naux-s2-linguist-test-") as temp:
            root = Path(temp) / "surface"
            shutil.copytree(self.surface_root, root)
            package = root / "package.json"
            package.write_bytes(package.read_bytes() + b"\n")
            with self.assertRaisesRegex(SURFACE.SurfaceError, "content drift"):
                SURFACE.verify_files(root, lock)

    def test_extra_member_fails_closed(self) -> None:
        lock = SURFACE.parse_lock(self.lock_path)
        with tempfile.TemporaryDirectory(prefix="naux-s2-linguist-test-") as temp:
            root = Path(temp) / "surface"
            shutil.copytree(self.surface_root, root)
            (root / "UNOWNED").write_text("not admitted\n", encoding="utf-8")
            with self.assertRaisesRegex(SURFACE.SurfaceError, "inventory drift"):
                SURFACE.verify_files(root, lock)

    def test_locally_resealed_metadata_drift_is_rejected(self) -> None:
        raw = self.lock_path.read_text(encoding="utf-8")
        lines = raw.splitlines()
        lines[2] = "tag\tv9.9.9"
        body = "".join(f"{line}\n" for line in lines[:-1]).encode("utf-8")
        lines[-1] = f"seal\t{SURFACE._sha256(SURFACE.DOMAIN + body)}"
        with tempfile.TemporaryDirectory(prefix="naux-s2-linguist-test-") as temp:
            mutated = Path(temp) / "LINGUIST-SURFACE.tsv"
            mutated.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(SURFACE.SurfaceError, "metadata differs"):
                SURFACE.parse_lock(mutated)


if __name__ == "__main__":
    unittest.main()
