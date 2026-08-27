#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residual_elf64.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_residual_elf64", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
elf64 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = elf64
SPEC.loader.exec_module(elf64)


class S4ResidualElf64Tests(unittest.TestCase):
    @staticmethod
    def _binary() -> Path | None:
        configured = os.environ.get("NAUX_S4_RESIDUAL_ELF64_BINARY")
        candidates = (
            Path(configured) if configured else None,
            ROOT / "target/release/examples/naux_s4_residual_elf64",
            ROOT / "target/debug/examples/naux_s4_residual_elf64",
            Path("/tmp/naux-codex-target/release/examples/naux_s4_residual_elf64"),
            Path("/tmp/naux-codex-target/debug/examples/naux_s4_residual_elf64"),
        )
        for candidate in candidates:
            if candidate is not None and candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
        return None

    def _stdout(self) -> bytes:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed residual ELF64 emitter is unavailable")
        elf64._validate_emitter_binary(binary)
        completed = elf64._run(binary)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        return completed.stdout

    @staticmethod
    def _reseal(path: Path, domain: bytes) -> str:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        seal = hashlib.sha256(domain + body).hexdigest()
        path.write_bytes(body + f"seal\t{seal}\n".encode())
        return seal

    def test_repository_static_admission_is_deterministic(self) -> None:
        first = elf64.validate(ROOT)
        second = elf64.validate(ROOT)
        self.assertEqual(first, second)
        text = first.report.decode()
        self.assertIn("status\tx86-64-elf64-structurally-admitted\n", text)
        self.assertIn("execution-status\tforbidden\n", text)
        self.assertIn("timing-status\tforbidden\n", text)
        self.assertEqual(text.count("blocker\t"), 2)

    def test_exact_candidate_replays_twice(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed residual ELF64 emitter is unavailable")
        admission = elf64.validate(ROOT)
        report, candidate = elf64.replay(admission, binary)
        self.assertIn(b"mode\tuntimed-elf64-replay\n", report)
        self.assertIn(b"replays\t2\n", report)
        self.assertEqual(len(candidate.kernels), 4)

    def test_target_plan_encoding_and_elf_mutations_are_rejected(self) -> None:
        original = self._stdout()
        contract = elf64.parse_contract(ROOT / "distribution/s4-performance/WP5D-ELF64.tsv")
        mutations = (
            original.replace(b"const-i64\tr0:i64@-64\t16384", b"const-i64\tr0:i64@-64\t16385", 1),
            original.replace(b"encoding\t01\t0\t0\toperation\t11", b"encoding\t01\t0\t0\toperation\t12", 1),
            original.replace(b"correspondence\t01\t0\t0\t0\toperation", b"correspondence\t01\t0\t0\t1\toperation", 1),
            original.replace(b"target-hex\t01\t55", b"target-hex\t01\t54", 1),
            original.replace(b"elf-hex\t01\t7f", b"elf-hex\t01\t7e", 1),
            original.replace(b"branch\tr7:bool@-120\tb2\tb6", b"branch\tr7:bool@-120\tb3\tb6", 1),
        )
        for mutation in mutations:
            with self.subTest(prefix=mutation[:32]):
                with self.assertRaises(elf64.Elf64Error):
                    elf64.parse_candidate(mutation, contract)

    def test_candidate_rejects_timing_and_noncanonical_text(self) -> None:
        original = self._stdout()
        contract = elf64.parse_contract(ROOT / "distribution/s4-performance/WP5D-ELF64.tsv")
        mutations = (
            original.replace(b"verification\t", b"runtime-ns\t1\nverification\t", 1),
            original.rstrip(b"\n"),
            original.replace(b"\n", b"\r\n"),
            original + b"trailing\trow\n",
        )
        for mutation in mutations:
            with self.assertRaises(elf64.Elf64Error):
                elf64.parse_candidate(mutation, contract)

    def test_contract_mutation_fails_even_after_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp5d-contract-") as directory:
            path = Path(directory) / "WP5D-ELF64.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP5D-ELF64.tsv", path)
            path.write_text(path.read_text().replace("execution-status\tforbidden", "execution-status\tready", 1))
            self._reseal(path, elf64.CONTRACT_DOMAIN)
            with self.assertRaises(elf64.Elf64Error):
                elf64.parse_contract(path)

    def test_bound_file_drift_and_symlink_are_rejected(self) -> None:
        contract = elf64.parse_contract(ROOT / "distribution/s4-performance/WP5D-ELF64.tsv")
        authority = elf64.parse_authority(
            ROOT / "distribution/s4-performance/WP5D-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp5d-files-") as directory:
            root = Path(directory)
            for relative in elf64.EXPECTED_FILES:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = root / "distribution/s4-performance/WP5D-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(elf64.Elf64Error):
                elf64._verify_files(root, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP5D-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(elf64.Elf64Error):
                elf64._verify_files(root, authority)

    def test_generic_lowering_rejects_kernel_dispatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp5d-source-") as directory:
            root = Path(directory)
            support = root / "naux-lang/examples/support/s4_residual_x64_elf.rs"
            support.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / "naux-lang/examples/support/s4_residual_x64_elf.rs", support)
            example = root / "naux-lang/examples/naux_s4_residual_elf64.rs"
            shutil.copy2(ROOT / "naux-lang/examples/naux_s4_residual_elf64.rs", example)
            support.write_text(support.read_text() + "\n// sum-dense special case\n")
            with self.assertRaises(elf64.Elf64Error):
                elf64._verify_source_boundary(root)

    def test_generated_image_is_rejected_before_subprocess_execution(self) -> None:
        raw = self._stdout()
        contract = elf64.parse_contract(ROOT / "distribution/s4-performance/WP5D-ELF64.tsv")
        candidate = elf64.parse_candidate(raw, contract)
        admission = elf64.validate(ROOT)
        original = candidate.kernels[0].elf
        executable_stack_mutation = bytearray(original)
        executable_stack_mutation[124:128] = (7).to_bytes(4, "little")
        for ordinal, payload in enumerate((original, bytes(executable_stack_mutation))):
            with self.subTest(ordinal=ordinal):
                with tempfile.TemporaryDirectory(prefix="naux-wp5d-noexec-") as directory:
                    image = Path(directory) / "naux_s4_residual_elf64"
                    image.write_bytes(payload)
                    image.chmod(0o755)
                    with mock.patch.object(
                        elf64, "_run", side_effect=AssertionError("subprocess must not start")
                    ):
                        with self.assertRaisesRegex(
                            elf64.Elf64Error,
                            "refusing to execute a generated WP5D ELF64 image",
                        ):
                            elf64.replay(admission, image)

    def test_emitter_symlink_is_rejected_before_resolution(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed residual ELF64 emitter is unavailable")
        with tempfile.TemporaryDirectory(prefix="naux-wp5d-symlink-") as directory:
            link = Path(directory) / "naux_s4_residual_elf64"
            link.symlink_to(binary.resolve())
            with self.assertRaisesRegex(elf64.Elf64Error, "regular executable"):
                elf64._validate_emitter_binary(link)


if __name__ == "__main__":
    unittest.main()
