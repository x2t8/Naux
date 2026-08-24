from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts/s4_benchmark_authority.py"
SPEC = importlib.util.spec_from_file_location("s4_benchmark_authority", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
AUTH = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUTH
SPEC.loader.exec_module(AUTH)


class S4BenchmarkAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = REPO_ROOT / "distribution/s4-performance"
        self.corpus_path = self.directory / "CORPUS.tsv"
        self.protocol_path = self.directory / "PROTOCOL.tsv"
        self.authority_path = self.directory / "AUTHORITY.tsv"

    def _mutate_and_reseal(self, source: Path, domain: bytes, mutate) -> Path:
        lines = source.read_text(encoding="utf-8").splitlines()
        mutate(lines)
        body = "".join(f"{line}\n" for line in lines[:-1]).encode()
        lines[-1] = f"seal\t{AUTH._sha256(domain + body)}"
        directory = Path(tempfile.mkdtemp(prefix="naux-s4-manifest-"))
        self.addCleanup(shutil.rmtree, directory)
        target = directory / source.name
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return target

    def _copy_bound_tree(self) -> Path:
        corpus = AUTH.parse_corpus(self.corpus_path)
        protocol = AUTH.parse_protocol(self.protocol_path)
        authority = AUTH.parse_authority(self.authority_path, corpus.seal, protocol.seal)
        directory = Path(tempfile.mkdtemp(prefix="naux-s4-tree-"))
        self.addCleanup(shutil.rmtree, directory)
        for record in authority.files:
            source = REPO_ROOT / record.path
            target = directory / record.path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        target = directory / "distribution/s4-performance/AUTHORITY.tsv"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.authority_path, target)
        return directory

    def _assert_manifest_shape_rejected(self, source: Path, parser, domain: bytes) -> None:
        original = source.read_bytes()
        variants = {
            "missing-final-lf": original[:-1],
            "crlf": original.replace(b"\n", b"\r\n"),
            "nul": original.replace(b"\n", b"\x00\n", 1),
            "blank-row": original.replace(b"\n", b"\n\n", 1),
            "bad-seal": original[:-65] + b"0" * 64 + b"\n",
        }
        for name, raw in variants.items():
            with self.subTest(name=name):
                directory = Path(tempfile.mkdtemp(prefix="naux-s4-shape-"))
                self.addCleanup(shutil.rmtree, directory)
                path = directory / source.name
                path.write_bytes(raw)
                with self.assertRaises(AUTH.AuthorityError):
                    parser(path)
        lines = original.decode().splitlines()
        for name, mutate in (
            ("missing-row", lambda rows: rows.pop(1)),
            ("duplicate-row", lambda rows: rows.insert(2, rows[1])),
            ("reordered-row", lambda rows: rows.__setitem__(slice(1, 3), reversed(rows[1:3]))),
            ("trailing-row", lambda rows: rows.insert(-1, "unknown\tdata")),
        ):
            with self.subTest(name=name):
                path = self._mutate_and_reseal(source, domain, mutate)
                with self.assertRaises(AUTH.AuthorityError):
                    parser(path)

    def test_canonical_authority_admits_without_running_toolchains(self) -> None:
        admission = AUTH.validate(REPO_ROOT)
        self.assertEqual(admission.authority.metadata, AUTH.AUTHORITY_METADATA)
        self.assertEqual(admission.protocol.metadata[1], ("claim-status", "not-admitted"))
        self.assertEqual(len(admission.corpus.kernels), 4)
        self.assertEqual(len(admission.authority.files), 22)

    def test_authority_report_is_byte_deterministic(self) -> None:
        first = AUTH.validate(REPO_ROOT)
        second = AUTH.validate(REPO_ROOT)
        self.assertEqual(first.report, second.report)
        self.assertEqual(first.report_root, second.report_root)
        self.assertTrue(first.report.startswith(AUTH.REPORT_MAGIC.encode() + b"\n"))
        self.assertTrue(first.report.endswith(f"report-root\t{first.report_root}\n".encode()))

    def test_all_oracles_are_independently_recomputed_and_binary64_exact(self) -> None:
        corpus = AUTH.parse_corpus(self.corpus_path)
        expected = {
            "sum-dense": 6_710_476_800,
            "branch-mix": -69_189_632,
            "dot-product": 73_294_064_435_200,
            "list-update": 6_730_547_200,
        }
        self.assertEqual({kernel.name: kernel.expected for kernel in corpus.kernels}, expected)
        for kernel in corpus.kernels:
            with self.subTest(kernel=kernel.name):
                self.assertEqual(AUTH._oracle(kernel.name, kernel.n, kernel.reps), kernel.expected)
                self.assertLess(abs(kernel.expected), AUTH.MAX_EXACT_BINARY64_INTEGER)

    def test_every_corpus_metadata_field_is_authoritative(self) -> None:
        lines = self.corpus_path.read_text(encoding="utf-8").splitlines()
        metadata_rows = [index for index, line in enumerate(lines) if line.startswith("meta\t")]
        for row_index in metadata_rows:
            for field_index in range(3):
                with self.subTest(row=row_index, field=field_index):
                    def mutate(rows, row_index=row_index, field_index=field_index):
                        fields = rows[row_index].split("\t")
                        fields[field_index] += "-mutated"
                        rows[row_index] = "\t".join(fields)
                    path = self._mutate_and_reseal(self.corpus_path, AUTH.CORPUS_DOMAIN, mutate)
                    with self.assertRaises(AUTH.AuthorityError):
                        AUTH.parse_corpus(path)

    def test_every_kernel_field_is_authoritative(self) -> None:
        lines = self.corpus_path.read_text(encoding="utf-8").splitlines()
        kernel_rows = [index for index, line in enumerate(lines) if line.startswith("kernel\t")]
        for row_index in kernel_rows:
            for field_index in range(11):
                with self.subTest(row=row_index, field=field_index):
                    def mutate(rows, row_index=row_index, field_index=field_index):
                        fields = rows[row_index].split("\t")
                        fields[field_index] += "-mutated"
                        rows[row_index] = "\t".join(fields)
                    path = self._mutate_and_reseal(self.corpus_path, AUTH.CORPUS_DOMAIN, mutate)
                    with self.assertRaises(AUTH.AuthorityError):
                        AUTH.parse_corpus(path)

    def test_stale_or_coherently_resealed_oracle_is_rejected(self) -> None:
        def mutate(rows):
            fields = rows[4].split("\t")
            fields[7] = str(int(fields[7]) + 1)
            rows[4] = "\t".join(fields)
        path = self._mutate_and_reseal(self.corpus_path, AUTH.CORPUS_DOMAIN, mutate)
        with self.assertRaisesRegex(AUTH.AuthorityError, "oracle mismatch"):
            AUTH.parse_corpus(path)

    def test_corpus_structure_and_canonical_text_fail_closed(self) -> None:
        self._assert_manifest_shape_rejected(self.corpus_path, AUTH.parse_corpus, AUTH.CORPUS_DOMAIN)

    def test_every_oversized_manifest_is_rejected(self) -> None:
        corpus = AUTH.parse_corpus(self.corpus_path)
        protocol = AUTH.parse_protocol(self.protocol_path)
        cases = (
            ("CORPUS.tsv", AUTH.parse_corpus),
            ("PROTOCOL.tsv", AUTH.parse_protocol),
            ("AUTHORITY.tsv", lambda path: AUTH.parse_authority(path, corpus.seal, protocol.seal)),
        )
        for name, parser in cases:
            with self.subTest(name=name):
                directory = Path(tempfile.mkdtemp(prefix="naux-s4-oversized-"))
                self.addCleanup(shutil.rmtree, directory)
                path = directory / name
                path.write_bytes(b"x" * 1_000_001 + b"\n")
                with self.assertRaisesRegex(AUTH.AuthorityError, "size limit"):
                    parser(path)

    def test_every_protocol_metadata_field_is_authoritative(self) -> None:
        lines = self.protocol_path.read_text(encoding="utf-8").splitlines()
        metadata_rows = [index for index, line in enumerate(lines) if line.startswith("meta\t")]
        for row_index in metadata_rows:
            for field_index in range(3):
                with self.subTest(row=row_index, field=field_index):
                    def mutate(rows, row_index=row_index, field_index=field_index):
                        fields = rows[row_index].split("\t")
                        fields[field_index] += "-mutated"
                        rows[row_index] = "\t".join(fields)
                    path = self._mutate_and_reseal(self.protocol_path, AUTH.PROTOCOL_DOMAIN, mutate)
                    with self.assertRaises(AUTH.AuthorityError):
                        AUTH.parse_protocol(path)

    def test_every_role_field_is_authoritative(self) -> None:
        lines = self.protocol_path.read_text(encoding="utf-8").splitlines()
        role_rows = [index for index, line in enumerate(lines) if line.startswith("role\t")]
        for row_index in role_rows:
            for field_index in range(6):
                with self.subTest(row=row_index, field=field_index):
                    def mutate(rows, row_index=row_index, field_index=field_index):
                        fields = rows[row_index].split("\t")
                        fields[field_index] += "-mutated"
                        rows[row_index] = "\t".join(fields)
                    path = self._mutate_and_reseal(self.protocol_path, AUTH.PROTOCOL_DOMAIN, mutate)
                    with self.assertRaises(AUTH.AuthorityError):
                        AUTH.parse_protocol(path)

    def test_every_metric_field_is_authoritative(self) -> None:
        lines = self.protocol_path.read_text(encoding="utf-8").splitlines()
        metric_rows = [index for index, line in enumerate(lines) if line.startswith("metric\t")]
        for row_index in metric_rows:
            for field_index in range(7):
                with self.subTest(row=row_index, field=field_index):
                    def mutate(rows, row_index=row_index, field_index=field_index):
                        fields = rows[row_index].split("\t")
                        fields[field_index] += "-mutated"
                        rows[row_index] = "\t".join(fields)
                    path = self._mutate_and_reseal(self.protocol_path, AUTH.PROTOCOL_DOMAIN, mutate)
                    with self.assertRaises(AUTH.AuthorityError):
                        AUTH.parse_protocol(path)

    def test_protocol_structure_and_canonical_text_fail_closed(self) -> None:
        self._assert_manifest_shape_rejected(self.protocol_path, AUTH.parse_protocol, AUTH.PROTOCOL_DOMAIN)

    def test_command_shaped_manifest_data_is_rejected(self) -> None:
        cases = (
            (self.corpus_path, AUTH.CORPUS_DOMAIN, AUTH.parse_corpus, "kernel", 2),
            (self.protocol_path, AUTH.PROTOCOL_DOMAIN, AUTH.parse_protocol, "role", 2),
            (self.protocol_path, AUTH.PROTOCOL_DOMAIN, AUTH.parse_protocol, "metric", 2),
        )
        for source, domain, parser, prefix, field_index in cases:
            with self.subTest(prefix=prefix):
                def mutate(rows, prefix=prefix, field_index=field_index):
                    index = next(i for i, row in enumerate(rows) if row.startswith(prefix + "\t"))
                    fields = rows[index].split("\t")
                    fields[field_index] = "value;touch-pwned"
                    rows[index] = "\t".join(fields)
                path = self._mutate_and_reseal(source, domain, mutate)
                with self.assertRaises(AUTH.AuthorityError):
                    parser(path)

    def test_every_authority_metadata_field_is_authoritative(self) -> None:
        lines = self.authority_path.read_text(encoding="utf-8").splitlines()
        metadata_rows = [index for index, line in enumerate(lines) if line.startswith("meta\t")]
        corpus = AUTH.parse_corpus(self.corpus_path)
        protocol = AUTH.parse_protocol(self.protocol_path)
        for row_index in metadata_rows:
            for field_index in range(3):
                with self.subTest(row=row_index, field=field_index):
                    def mutate(rows, row_index=row_index, field_index=field_index):
                        fields = rows[row_index].split("\t")
                        fields[field_index] += "-mutated"
                        rows[row_index] = "\t".join(fields)
                    path = self._mutate_and_reseal(self.authority_path, AUTH.AUTHORITY_DOMAIN, mutate)
                    with self.assertRaises(AUTH.AuthorityError):
                        AUTH.parse_authority(path, corpus.seal, protocol.seal)

    def test_every_component_field_is_authoritative(self) -> None:
        lines = self.authority_path.read_text(encoding="utf-8").splitlines()
        component_rows = [index for index, line in enumerate(lines) if line.startswith("component\t")]
        corpus = AUTH.parse_corpus(self.corpus_path)
        protocol = AUTH.parse_protocol(self.protocol_path)
        for row_index in component_rows:
            for field_index in range(4):
                with self.subTest(row=row_index, field=field_index):
                    def mutate(rows, row_index=row_index, field_index=field_index):
                        fields = rows[row_index].split("\t")
                        fields[field_index] += "-mutated"
                        rows[row_index] = "\t".join(fields)
                    path = self._mutate_and_reseal(self.authority_path, AUTH.AUTHORITY_DOMAIN, mutate)
                    with self.assertRaises(AUTH.AuthorityError):
                        AUTH.parse_authority(path, corpus.seal, protocol.seal)

    def test_authority_structure_and_canonical_text_fail_closed(self) -> None:
        corpus = AUTH.parse_corpus(self.corpus_path)
        protocol = AUTH.parse_protocol(self.protocol_path)
        parser = lambda path: AUTH.parse_authority(path, corpus.seal, protocol.seal)
        self._assert_manifest_shape_rejected(self.authority_path, parser, AUTH.AUTHORITY_DOMAIN)

    def test_every_file_record_field_is_checked(self) -> None:
        lines = self.authority_path.read_text(encoding="utf-8").splitlines()
        file_rows = [index for index, line in enumerate(lines) if line.startswith("file\t")]
        corpus = AUTH.parse_corpus(self.corpus_path)
        protocol = AUTH.parse_protocol(self.protocol_path)
        for row_index in file_rows:
            for field_index in range(5):
                with self.subTest(row=row_index, field=field_index):
                    def mutate(rows, row_index=row_index, field_index=field_index):
                        fields = rows[row_index].split("\t")
                        if field_index == 1:
                            fields[field_index] = "100755" if fields[field_index] == "100644" else "100644"
                        elif field_index == 2:
                            fields[field_index] = str(int(fields[field_index]) + 1)
                        elif field_index == 3:
                            fields[field_index] = "0" * 64
                        else:
                            fields[field_index] += "-mutated"
                        rows[row_index] = "\t".join(fields)
                    path = self._mutate_and_reseal(self.authority_path, AUTH.AUTHORITY_DOMAIN, mutate)
                    with self.assertRaises(AUTH.AuthorityError):
                        authority = AUTH.parse_authority(path, corpus.seal, protocol.seal)
                        AUTH._verify_files(REPO_ROOT, authority)

    def test_every_bound_file_byte_drift_is_rejected(self) -> None:
        root = self._copy_bound_tree()
        authority = AUTH.validate(root).authority
        for record in authority.files:
            with self.subTest(path=record.path):
                path = root / record.path
                original = path.read_bytes()
                path.write_bytes(original + b"x")
                try:
                    with self.assertRaises(AUTH.AuthorityError):
                        AUTH.validate(root)
                finally:
                    path.write_bytes(original)
                    os.chmod(path, stat.S_IMODE(record.mode))

    def test_bound_mode_drift_and_symlink_are_rejected(self) -> None:
        root = self._copy_bound_tree()
        admission = AUTH.validate(root)
        record = admission.authority.files[0]
        path = root / record.path
        original_mode = stat.S_IMODE(path.stat().st_mode)
        os.chmod(path, 0o755 if original_mode == 0o644 else 0o644)
        with self.assertRaisesRegex(AUTH.AuthorityError, "mode mismatch"):
            AUTH.validate(root)
        os.chmod(path, original_mode)
        path.unlink()
        path.symlink_to(root / admission.authority.files[1].path)
        with self.assertRaisesRegex(AUTH.AuthorityError, "not a regular file"):
            AUTH.validate(root)

    def test_naux_source_dimensions_must_match_corpus(self) -> None:
        corpus = AUTH.parse_corpus(self.corpus_path)
        for kernel in corpus.kernels:
            with self.subTest(kernel=kernel.name):
                AUTH._verify_source_dimensions(REPO_ROOT, kernel)
        changed = AUTH.Kernel(
            corpus.kernels[0].ordinal,
            corpus.kernels[0].name,
            corpus.kernels[0].category,
            corpus.kernels[0].specialization,
            corpus.kernels[0].n + 1,
            corpus.kernels[0].reps,
            corpus.kernels[0].expected,
            corpus.kernels[0].naux_source,
            corpus.kernels[0].c_source,
            corpus.kernels[0].rust_source,
        )
        with self.assertRaisesRegex(AUTH.AuthorityError, "dimensions disagree"):
            AUTH._verify_source_dimensions(REPO_ROOT, changed)

    def test_validation_source_adds_one_output_without_changing_return(self) -> None:
        corpus = AUTH.parse_corpus(self.corpus_path)
        for kernel in corpus.kernels:
            with self.subTest(kernel=kernel.name):
                original = (REPO_ROOT / kernel.naux_source).read_text(encoding="utf-8")
                validation = AUTH._validation_source(REPO_ROOT, kernel)
                self.assertEqual(validation.count("    !say $"), 1)
                self.assertEqual(validation.count("    ^ $"), 1)
                self.assertEqual(validation.replace("    !say " + validation.split("    !say ", 1)[1].splitlines()[0] + "\n", "", 1), original)

    def test_semantic_replay_uses_fixed_argv_and_never_a_shell(self) -> None:
        admission = AUTH.validate(REPO_ROOT)
        directory = Path(tempfile.mkdtemp(prefix="naux-s4-binary-"))
        self.addCleanup(shutil.rmtree, directory)
        binary = directory / "naux"
        binary.write_bytes(b"reviewed test stub\n")
        binary.chmod(0o755)
        expected_outputs = iter(f"{kernel.expected}\n".encode() for kernel in admission.corpus.kernels)
        calls: list[tuple[list[str], dict]] = []

        def fake_run(argv, **kwargs):
            calls.append((argv, kwargs))
            generated = Path(argv[2]).read_text(encoding="utf-8")
            self.assertEqual(generated.count("    !say $"), 1)
            return AUTH.subprocess.CompletedProcess(argv, 0, next(expected_outputs), b"")

        with mock.patch.object(AUTH.subprocess, "run", side_effect=fake_run):
            report, report_root = AUTH.replay_semantics(REPO_ROOT, admission, binary)
        self.assertEqual(len(calls), 4)
        self.assertIn(b"mode\tsemantic-replay\n", report)
        self.assertTrue(report.endswith(f"report-root\t{report_root}\n".encode()))
        for argv, kwargs in calls:
            self.assertEqual(argv[0], str(binary.resolve()))
            self.assertEqual(argv[1], "run")
            self.assertEqual(argv[3:], ["--engine", "vm", "--max-work", "10000000"])
            self.assertNotIn("shell", kwargs)
            self.assertEqual(kwargs["input"], b"")
            self.assertTrue(kwargs["capture_output"])
            self.assertFalse(kwargs["check"])
            self.assertEqual(kwargs["timeout"], 60)

    def test_semantic_replay_rejects_output_or_process_drift(self) -> None:
        admission = AUTH.validate(REPO_ROOT)
        directory = Path(tempfile.mkdtemp(prefix="naux-s4-binary-"))
        self.addCleanup(shutil.rmtree, directory)
        binary = directory / "naux"
        binary.write_bytes(b"reviewed test stub\n")
        binary.chmod(0o755)
        cases = (
            AUTH.subprocess.CompletedProcess([], 0, b"wrong\n", b""),
            AUTH.subprocess.CompletedProcess([], 0, f"{admission.corpus.kernels[0].expected}\n".encode(), b"diagnostic\n"),
            AUTH.subprocess.CompletedProcess([], 9, b"", b""),
        )
        for completed in cases:
            with self.subTest(returncode=completed.returncode, stderr=completed.stderr):
                with mock.patch.object(AUTH.subprocess, "run", return_value=completed):
                    with self.assertRaises(AUTH.AuthorityError):
                        AUTH.replay_semantics(REPO_ROOT, admission, binary)

    def test_semantic_replay_rejects_symlink_or_nonexecutable_binary(self) -> None:
        admission = AUTH.validate(REPO_ROOT)
        directory = Path(tempfile.mkdtemp(prefix="naux-s4-binary-"))
        self.addCleanup(shutil.rmtree, directory)
        target = directory / "target"
        target.write_bytes(b"stub\n")
        target.chmod(0o755)
        symlink = directory / "naux-link"
        symlink.symlink_to(target)
        with self.assertRaisesRegex(AUTH.AuthorityError, "non-symlink"):
            AUTH.replay_semantics(REPO_ROOT, admission, symlink)
        target.chmod(0o644)
        with self.assertRaisesRegex(AUTH.AuthorityError, "not executable"):
            AUTH.replay_semantics(REPO_ROOT, admission, target)

    def test_manifests_are_data_only(self) -> None:
        forbidden = (b"$(", b"`", b";", b"&&", b"||")
        for path in (self.corpus_path, self.protocol_path, self.authority_path):
            raw = path.read_bytes()
            with self.subTest(path=path.name):
                for token in forbidden:
                    self.assertNotIn(token, raw)


if __name__ == "__main__":
    unittest.main()
