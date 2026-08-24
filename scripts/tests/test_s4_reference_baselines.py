from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
MODULE_PATH = SCRIPTS / "s4_reference_baselines.py"
SPEC = importlib.util.spec_from_file_location("s4_reference_baselines", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
reference = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reference
SPEC.loader.exec_module(reference)
wp1 = reference.wp1


class ReferenceBaselineTests(unittest.TestCase):
    def _copy_repo(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory(prefix="naux-s4-wp2-test-")
        root = Path(temporary.name)
        paths = set(wp1.EXPECTED_FILES) | set(reference.EXPECTED_FILES)
        paths.update(
            {
                "distribution/s4-performance/AUTHORITY.tsv",
                "distribution/s4-performance/CORPUS.tsv",
                "distribution/s4-performance/PROTOCOL.tsv",
                "distribution/s4-performance/WP2-AUTHORITY.tsv",
            }
        )
        for relative in sorted(paths):
            source = REPO_ROOT / relative
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination, follow_symlinks=False)
        return temporary, root

    @staticmethod
    def _reseal(path: Path, domain: bytes) -> str:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        seal = hashlib.sha256(domain + body).hexdigest()
        path.write_bytes(body + f"seal\t{seal}\n".encode())
        return seal

    @staticmethod
    def _mutate_field(path: Path, row_index: int, field_index: int) -> None:
        lines = path.read_text(encoding="utf-8").splitlines()
        fields = lines[row_index].split("\t")
        fields[field_index] += "x"
        lines[row_index] = "\t".join(fields)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

    def _rebuild_authority(self, root: Path) -> None:
        authority_path = root / "distribution/s4-performance/WP2-AUTHORITY.tsv"
        lines = authority_path.read_text(encoding="utf-8").splitlines()
        baseline_path = root / "distribution/s4-performance/BASELINES.tsv"
        baseline_seal = baseline_path.read_text(encoding="utf-8").splitlines()[-1].split("\t")[1]
        component = lines.index(
            next(line for line in lines if line.startswith("component\tbaselines\t"))
        )
        component_fields = lines[component].split("\t")
        component_fields[3] = baseline_seal
        lines[component] = "\t".join(component_fields)
        for index, line in enumerate(lines):
            if not line.startswith("file\t"):
                continue
            fields = line.split("\t")
            path = root / fields[4]
            info = path.lstat()
            raw = path.read_bytes()
            fields[1] = f"{stat.S_IFREG | stat.S_IMODE(info.st_mode):o}"
            fields[2] = str(len(raw))
            fields[3] = hashlib.sha256(raw).hexdigest()
            lines[index] = "\t".join(fields)
        authority_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        self._reseal(authority_path, reference.AUTHORITY_DOMAIN)

    def test_repository_static_admission_is_deterministic(self) -> None:
        first = reference.validate(REPO_ROOT)
        second = reference.validate(REPO_ROOT)
        self.assertEqual(first, second)
        self.assertEqual(first.report, second.report)
        self.assertIn(b"claim-status\tnot-admitted\n", first.report)
        self.assertIn(b"mode\tstatic\n", first.report)

    def test_real_c_parity_is_exact_and_deterministic(self) -> None:
        if shutil.which("cc") is None:
            self.skipTest("cc is unavailable")
        admission = reference.validate(REPO_ROOT)
        first = reference.replay_parity(REPO_ROOT, admission, "cc")
        second = reference.replay_parity(REPO_ROOT, admission, "cc")
        self.assertEqual(first, second)
        report, _root = first
        self.assertIn(b"mode\tuntimed-parity\n", report)
        self.assertIn(b"parity-runs\t8\n", report)
        self.assertIn(b"negative-runs\t36\n", report)

    def test_every_baseline_field_mutation_is_rejected(self) -> None:
        source_lines = (
            REPO_ROOT / "distribution/s4-performance/BASELINES.tsv"
        ).read_text(encoding="utf-8").splitlines()
        for row_index in range(1, len(source_lines) - 1):
            field_count = len(source_lines[row_index].split("\t"))
            for field_index in range(1, field_count):
                with self.subTest(row=row_index, field=field_index):
                    temporary, root = self._copy_repo()
                    self.addCleanup(temporary.cleanup)
                    path = root / "distribution/s4-performance/BASELINES.tsv"
                    self._mutate_field(path, row_index, field_index)
                    self._reseal(path, reference.BASELINES_DOMAIN)
                    self._rebuild_authority(root)
                    with self.assertRaises((reference.ReferenceError, wp1.AuthorityError)):
                        reference.validate(root)

    def test_every_authority_field_mutation_is_rejected(self) -> None:
        source_lines = (
            REPO_ROOT / "distribution/s4-performance/WP2-AUTHORITY.tsv"
        ).read_text(encoding="utf-8").splitlines()
        for row_index in range(1, len(source_lines) - 1):
            field_count = len(source_lines[row_index].split("\t"))
            for field_index in range(1, field_count):
                with self.subTest(row=row_index, field=field_index):
                    temporary, root = self._copy_repo()
                    self.addCleanup(temporary.cleanup)
                    path = root / "distribution/s4-performance/WP2-AUTHORITY.tsv"
                    self._mutate_field(path, row_index, field_index)
                    self._reseal(path, reference.AUTHORITY_DOMAIN)
                    with self.assertRaises((reference.ReferenceError, wp1.AuthorityError)):
                        reference.validate(root)

    def test_every_bound_file_byte_is_enforced(self) -> None:
        for relative in reference.EXPECTED_FILES:
            with self.subTest(path=relative):
                temporary, root = self._copy_repo()
                self.addCleanup(temporary.cleanup)
                path = root / relative
                path.write_bytes(path.read_bytes() + b"mutation\n")
                with self.assertRaises(reference.ReferenceError):
                    reference.validate(root)

    def test_missing_bound_file_is_rejected(self) -> None:
        temporary, root = self._copy_repo()
        self.addCleanup(temporary.cleanup)
        (root / reference.EXPECTED_FILES[2]).unlink()
        with self.assertRaises(reference.ReferenceError):
            reference.validate(root)

    def test_symlinked_bound_file_is_rejected(self) -> None:
        temporary, root = self._copy_repo()
        self.addCleanup(temporary.cleanup)
        path = root / reference.EXPECTED_FILES[2]
        replacement = path.with_suffix(".replacement")
        path.rename(replacement)
        path.symlink_to(replacement.name)
        with self.assertRaises(reference.ReferenceError):
            reference.validate(root)

    def test_mode_drift_is_rejected(self) -> None:
        temporary, root = self._copy_repo()
        self.addCleanup(temporary.cleanup)
        path = root / reference.EXPECTED_FILES[2]
        path.chmod(0o755)
        with self.assertRaises(reference.ReferenceError):
            reference.validate(root)

    def test_direct_oracle_substitution_is_rejected_even_when_resealed(self) -> None:
        for kernel in reference.EXPECTED_KERNELS:
            with self.subTest(kernel=kernel[1]):
                temporary, root = self._copy_repo()
                self.addCleanup(temporary.cleanup)
                path = root / kernel[3]
                path.write_text(
                    path.read_text(encoding="utf-8") + f"/* {kernel[2]} */\n",
                    encoding="utf-8",
                    newline="\n",
                )
                self._rebuild_authority(root)
                with self.assertRaises(reference.ReferenceError):
                    reference.validate(root)

    def test_required_kernel_structure_is_rejected_when_resealed(self) -> None:
        for kernel in reference.EXPECTED_KERNELS:
            with self.subTest(kernel=kernel[1]):
                temporary, root = self._copy_repo()
                self.addCleanup(temporary.cleanup)
                path = root / kernel[3]
                text = path.read_text(encoding="utf-8")
                text = text.replace("naux_s4_allocate(n)", "malloc(n * sizeof(double))", 1)
                path.write_text(text, encoding="utf-8", newline="\n")
                self._rebuild_authority(root)
                with self.assertRaises(reference.ReferenceError):
                    reference.validate(root)

    def test_output_drift_fails_real_parity_after_reseal(self) -> None:
        if shutil.which("cc") is None:
            self.skipTest("cc is unavailable")
        temporary, root = self._copy_repo()
        self.addCleanup(temporary.cleanup)
        header = root / "benchmarks/s4/c/baseline.h"
        text = header.read_text(encoding="utf-8").replace("\\t%.0f\\n", "\\t%.1f\\n")
        header.write_text(text, encoding="utf-8", newline="\n")
        self._rebuild_authority(root)
        admission = reference.validate(root)
        with self.assertRaises(reference.ReferenceError):
            reference.replay_parity(root, admission, "cc")

    def test_compiler_failure_is_rejected(self) -> None:
        admission = reference.validate(REPO_ROOT)
        failed = subprocess.CompletedProcess([], 1, b"", b"failed")
        with mock.patch.object(reference, "_compiler_path", return_value=Path("/bin/false")), mock.patch.object(
            reference, "_run", return_value=failed
        ):
            with self.assertRaises(reference.ReferenceError):
                reference.replay_parity(REPO_ROOT, admission, "cc")

    def test_process_invocation_is_an_argv_without_shell(self) -> None:
        completed = subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch.object(subprocess, "run", return_value=completed) as run:
            result = reference._run(["/bin/true", "literal;not-shell"], timeout=1)
        self.assertEqual(result.returncode, 0)
        args, kwargs = run.call_args
        self.assertIsInstance(args[0], list)
        self.assertNotIn("shell", kwargs)

    def test_noncanonical_manifests_are_rejected(self) -> None:
        mutations = {
            "missing-lf": lambda raw: raw.rstrip(b"\n"),
            "crlf": lambda raw: raw.replace(b"\n", b"\r\n"),
            "nul": lambda raw: raw.replace(b"claim-status", b"claim\x00-status", 1),
            "blank": lambda raw: raw.replace(b"meta\t", b"\nmeta\t", 1),
            "trailing": lambda raw: raw + b"trailing\trow\n",
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                temporary, root = self._copy_repo()
                self.addCleanup(temporary.cleanup)
                path = root / "distribution/s4-performance/BASELINES.tsv"
                path.write_bytes(mutate(path.read_bytes()))
                with self.assertRaises(reference.ReferenceError):
                    reference.parse_baselines(path)

    def test_manifest_size_caps_are_enforced(self) -> None:
        temporary, root = self._copy_repo()
        self.addCleanup(temporary.cleanup)
        path = root / "distribution/s4-performance/BASELINES.tsv"
        path.write_bytes(path.read_bytes() + b"x" * 1_000_001)
        with self.assertRaises(reference.ReferenceError):
            reference.parse_baselines(path)

    def test_parent_authority_is_composed_not_duplicated(self) -> None:
        temporary, root = self._copy_repo()
        self.addCleanup(temporary.cleanup)
        parent = root / "distribution/s4-performance/AUTHORITY.tsv"
        parent.write_bytes(parent.read_bytes().replace(b"claim-status", b"claim-statuX", 1))
        with self.assertRaises((reference.ReferenceError, wp1.AuthorityError)):
            reference.validate(root)


if __name__ == "__main__":
    unittest.main()
