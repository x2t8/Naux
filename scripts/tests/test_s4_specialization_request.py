#!/usr/bin/env python3

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


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_specialization_request.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_specialization_request", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
request = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = request
SPEC.loader.exec_module(request)
wp1 = request.wp5.wp4.wp3.wp2.wp1


class S4SpecializationRequestTests(unittest.TestCase):
    @staticmethod
    def _binary() -> Path | None:
        configured = os.environ.get("NAUX_S4_REQUEST_BINARY")
        candidates = (
            Path(configured) if configured else None,
            ROOT / "target/release/examples/naux_s4_specialization_request",
            Path("/tmp/naux-codex-target/release/examples/naux_s4_specialization_request"),
        )
        for candidate in candidates:
            if candidate is not None and candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate.resolve()
        return None

    def _stdout(self) -> bytes:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed specialization-request binary is unavailable")
        completed = request._run(binary)
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

    def _copy_slice(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory(prefix="naux-s4-wp5a-test-")
        root = Path(temporary.name)
        paths = set(request.EXPECTED_FILES)
        paths.add("distribution/s4-performance/WP5A-AUTHORITY.tsv")
        paths.update(record.naux_source for record in wp1.validate(ROOT).corpus.kernels)
        for relative in sorted(paths):
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination, follow_symlinks=False)
        return temporary, root

    def _rebuild_authority(self, root: Path) -> None:
        path = root / "distribution/s4-performance/WP5A-AUTHORITY.tsv"
        lines = path.read_text().splitlines()
        for index, line in enumerate(lines):
            if not line.startswith("file\t"):
                continue
            fields = line.split("\t")
            target = root / fields[4]
            info = target.lstat()
            raw = target.read_bytes()
            fields[1] = f"{stat.S_IFREG | stat.S_IMODE(info.st_mode):o}"
            fields[2] = str(len(raw))
            fields[3] = hashlib.sha256(raw).hexdigest()
            lines[index] = "\t".join(fields)
        path.write_text("\n".join(lines) + "\n")
        self._reseal(path, request.AUTHORITY_DOMAIN)

    def test_repository_static_admission_is_deterministic(self) -> None:
        first = request.validate(ROOT)
        second = request.validate(ROOT)
        self.assertEqual(first, second)
        text = first.report.decode()
        self.assertIn("request-status\tadmitted\n", text)
        self.assertIn("residual-status\tunavailable\n", text)
        self.assertIn("timing-status\tforbidden\n", text)
        self.assertEqual(text.count("blocker\t"), 3)

    def test_real_request_replay_is_exact_and_deterministic(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed specialization-request binary is unavailable")
        admission = request.validate(ROOT)
        first = request.replay(ROOT, admission, binary)
        second = request.replay(ROOT, admission, binary)
        self.assertEqual(first, second)
        self.assertIn(b"mode\tuntimed-request-replay\n", first[0])
        self.assertIn(b"replays\t2\n", first[0])

    def test_candidate_record_mutations_are_rejected(self) -> None:
        original = self._stdout()
        contract = request.validate(ROOT).contract
        for field in range(1, 11):
            with self.subTest(field=field):
                lines = original.decode().splitlines()
                fields = lines[8].split("\t")
                fields[field] = "1" if fields[field] != "1" else "2"
                lines[8] = "\t".join(fields)
                with self.assertRaises(request.RequestError):
                    request.parse_candidate(("\n".join(lines) + "\n").encode(), ROOT, contract)

    def test_candidate_rejects_timing_and_noncanonical_text(self) -> None:
        original = self._stdout()
        contract = request.validate(ROOT).contract
        mutations = (
            original.replace(b"verification\t", b"runtime-ns\t1\nverification\t", 1),
            original.rstrip(b"\n"),
            original.replace(b"\n", b"\r\n"),
            original + b"trailing\trow\n",
        )
        for mutation in mutations:
            with self.subTest(size=len(mutation)):
                with self.assertRaises(request.RequestError):
                    request.parse_candidate(mutation, ROOT, contract)

    def test_contract_metadata_mutation_fails_after_reseal(self) -> None:
        temporary, root = self._copy_slice()
        self.addCleanup(temporary.cleanup)
        path = root / "distribution/s4-performance/WP5A-REQUEST.tsv"
        path.write_text(path.read_text().replace("residual-status\tunavailable", "residual-status\tready", 1))
        self._reseal(path, request.CONTRACT_DOMAIN)
        with self.assertRaises(request.RequestError):
            request.parse_contract(path, root, wp1.validate(ROOT).corpus)

    def test_work_obligation_mutation_fails_after_reseal(self) -> None:
        temporary, root = self._copy_slice()
        self.addCleanup(temporary.cleanup)
        path = root / "distribution/s4-performance/WP5A-REQUEST.tsv"
        path.write_text(path.read_text().replace("reps-times-full-n-source-semantics", "oracle-lookup", 1))
        self._reseal(path, request.CONTRACT_DOMAIN)
        with self.assertRaises(request.RequestError):
            request.parse_contract(path, root, wp1.validate(ROOT).corpus)

    def test_source_identity_mutation_fails_after_reseal(self) -> None:
        temporary, root = self._copy_slice()
        self.addCleanup(temporary.cleanup)
        path = root / "distribution/s4-performance/WP5A-REQUEST.tsv"
        path.write_text(path.read_text().replace("7517f1ec", "0517f1ec", 1))
        self._reseal(path, request.CONTRACT_DOMAIN)
        with self.assertRaises(request.RequestError):
            request.parse_contract(path, root, wp1.validate(ROOT).corpus)

    def test_bound_file_drift_and_symlink_are_rejected(self) -> None:
        temporary, root = self._copy_slice()
        self.addCleanup(temporary.cleanup)
        contract = request.parse_contract(
            root / "distribution/s4-performance/WP5A-REQUEST.tsv",
            root,
            wp1.validate(ROOT).corpus,
        )
        authority = request.parse_authority(
            root / "distribution/s4-performance/WP5A-AUTHORITY.tsv", contract.seal
        )
        path = root / "distribution/s4-performance/WP5A-NONCLAIMS.md"
        path.write_bytes(path.read_bytes() + b"drift\n")
        with self.assertRaises(request.RequestError):
            request._verify_files(root, authority)
        shutil.copy2(ROOT / "distribution/s4-performance/WP5A-NONCLAIMS.md", path)
        replacement = path.with_suffix(".copy")
        path.rename(replacement)
        path.symlink_to(replacement.name)
        with self.assertRaises(request.RequestError):
            request._verify_files(root, authority)

    def test_direct_oracle_and_clock_tokens_are_rejected_after_reseal(self) -> None:
        for mutation in ("// 6710476800\n", "// Instant::now()\n"):
            with self.subTest(mutation=mutation.strip()):
                temporary, root = self._copy_slice()
                self.addCleanup(temporary.cleanup)
                path = root / "naux-lang/examples/naux_s4_specialization_request.rs"
                path.write_text(path.read_text() + mutation)
                self._rebuild_authority(root)
                with self.assertRaises(request.RequestError):
                    request._verify_source_boundary(root, wp1.validate(ROOT).corpus)

    def test_process_invocation_is_fixed_argv_without_shell(self) -> None:
        completed = subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch.object(subprocess, "run", return_value=completed) as run:
            result = request._run(Path("/bin/true"))
        self.assertEqual(result.returncode, 0)
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["/bin/true"])
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["input"], b"")


if __name__ == "__main__":
    unittest.main()
