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
MODULE_PATH = SCRIPTS / "s4_native_carrier.py"
SPEC = importlib.util.spec_from_file_location("s4_native_carrier", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
carrier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = carrier
SPEC.loader.exec_module(carrier)
wp2 = carrier.wp2
wp1 = wp2.wp1


class NativeCarrierTests(unittest.TestCase):
    def _copy_repo(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory(prefix="naux-s4-wp3-test-")
        root = Path(temporary.name)
        paths = set(wp1.EXPECTED_FILES) | set(wp2.EXPECTED_FILES) | set(carrier.EXPECTED_FILES)
        paths.update(
            {
                "distribution/s4-performance/AUTHORITY.tsv",
                "distribution/s4-performance/BASELINES.tsv",
                "distribution/s4-performance/CORPUS.tsv",
                "distribution/s4-performance/PROTOCOL.tsv",
                "distribution/s4-performance/WP2-AUTHORITY.tsv",
                "distribution/s4-performance/WP3-AUTHORITY.tsv",
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

    def _rebuild_authority(self, root: Path) -> None:
        path = root / "distribution/s4-performance/WP3-AUTHORITY.tsv"
        lines = path.read_text(encoding="utf-8").splitlines()
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
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        self._reseal(path, carrier.AUTHORITY_DOMAIN)

    @staticmethod
    def _binary() -> Path | None:
        configured = os.environ.get("NAUX_S4_CARRIER_BINARY")
        candidates = [
            Path(configured) if configured else None,
            REPO_ROOT / "target/release/examples/naux_s4_native_carrier",
            Path("/tmp/naux-codex-target/release/examples/naux_s4_native_carrier"),
        ]
        for candidate in candidates:
            if candidate is not None and candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate.resolve()
        return None

    def _candidate_stdout(self) -> bytes:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed S4 carrier binary is unavailable")
        completed = carrier._run(binary)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        return completed.stdout

    def test_repository_static_admission_is_deterministic(self) -> None:
        first = carrier.validate(REPO_ROOT)
        second = carrier.validate(REPO_ROOT)
        self.assertEqual(first, second)
        self.assertEqual(first.report, second.report)
        self.assertIn(b"claim-status\tnot-admitted\n", first.report)
        self.assertIn(b"timing-status\tforbidden\n", first.report)

    def test_real_carrier_replay_is_exact_and_deterministic(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed S4 carrier binary is unavailable")
        admission = carrier.validate(REPO_ROOT)
        first = carrier.replay(REPO_ROOT, admission, binary)
        second = carrier.replay(REPO_ROOT, admission, binary)
        self.assertEqual(first, second)
        self.assertIn(b"mode\tuntimed-native-replay\n", first[0])
        self.assertIn(b"replays\t2\n", first[0])

    def test_candidate_field_mutations_are_rejected(self) -> None:
        original = self._candidate_stdout()
        corpus = wp1.validate(REPO_ROOT).corpus
        for field_index in (3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16):
            with self.subTest(field=field_index):
                lines = original.decode().splitlines()
                fields = lines[5].split("\t")
                fields[field_index] = "1" if fields[field_index] != "1" else "2"
                lines[5] = "\t".join(fields)
                mutated = ("\n".join(lines) + "\n").encode()
                with self.assertRaises(carrier.CarrierError):
                    carrier.parse_candidate(mutated, REPO_ROOT, corpus)

    def test_candidate_rejects_timing_field_and_noncanonical_text(self) -> None:
        original = self._candidate_stdout()
        corpus = wp1.validate(REPO_ROOT).corpus
        mutations = (
            original.replace(b"verification\t", b"runtime-ns\t1\nverification\t", 1),
            original.rstrip(b"\n"),
            original.replace(b"\n", b"\r\n"),
            original + b"trailing\trow\n",
        )
        for mutated in mutations:
            with self.subTest(size=len(mutated)):
                with self.assertRaises(carrier.CarrierError):
                    carrier.parse_candidate(mutated, REPO_ROOT, corpus)

    def test_authority_metadata_mutation_fails_after_reseal(self) -> None:
        temporary, root = self._copy_repo()
        self.addCleanup(temporary.cleanup)
        path = root / "distribution/s4-performance/WP3-AUTHORITY.tsv"
        text = path.read_text(encoding="utf-8").replace(
            "meta\ttiming-status\tforbidden", "meta\ttiming-status\toptional", 1
        )
        path.write_text(text, encoding="utf-8", newline="\n")
        self._reseal(path, carrier.AUTHORITY_DOMAIN)
        with self.assertRaises(carrier.CarrierError):
            carrier.validate(root)

    def test_bound_file_mutation_is_rejected(self) -> None:
        temporary, root = self._copy_repo()
        self.addCleanup(temporary.cleanup)
        path = root / "naux-lang/src/s4_native_carrier.rs"
        path.write_bytes(path.read_bytes() + b"// mutation\n")
        with self.assertRaises(carrier.CarrierError):
            carrier.validate(root)

    def test_direct_oracle_substitution_is_rejected_after_reseal(self) -> None:
        temporary, root = self._copy_repo()
        self.addCleanup(temporary.cleanup)
        path = root / "naux-lang/src/s4_native_carrier.rs"
        path.write_bytes(path.read_bytes() + b"// 6710476800\n")
        self._rebuild_authority(root)
        with self.assertRaises(carrier.CarrierError):
            carrier.validate(root)

    def test_clock_sampling_token_is_rejected_after_reseal(self) -> None:
        temporary, root = self._copy_repo()
        self.addCleanup(temporary.cleanup)
        path = root / "naux-lang/src/s4_native_carrier.rs"
        path.write_bytes(path.read_bytes() + b"// Instant::now()\n")
        self._rebuild_authority(root)
        with self.assertRaises(carrier.CarrierError):
            carrier.validate(root)

    def test_symlinked_bound_file_is_rejected(self) -> None:
        temporary, root = self._copy_repo()
        self.addCleanup(temporary.cleanup)
        path = root / carrier.EXPECTED_FILES[6]
        replacement = path.with_suffix(".replacement")
        path.rename(replacement)
        path.symlink_to(replacement.name)
        with self.assertRaises(carrier.CarrierError):
            carrier.validate(root)

    def test_process_invocation_is_fixed_argv_without_shell(self) -> None:
        completed = subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch.object(subprocess, "run", return_value=completed) as run:
            result = carrier._run(Path("/bin/true"))
        self.assertEqual(result.returncode, 0)
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["/bin/true"])
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["input"], b"")

    def test_failed_process_is_rejected(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed S4 carrier binary is unavailable")
        admission = carrier.validate(REPO_ROOT)
        failed = subprocess.CompletedProcess([], 1, b"", b"failed")
        with mock.patch.object(carrier, "_run", return_value=failed):
            with self.assertRaises(carrier.CarrierError):
                carrier.replay(REPO_ROOT, admission, binary)


if __name__ == "__main__":
    unittest.main()
