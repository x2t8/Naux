from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts/s3_thesis_audit.py"
SPEC = importlib.util.spec_from_file_location("s3_thesis_audit", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


class S3TrustedThesisAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit_path = REPO_ROOT / "distribution/s3-thesis/AUDIT.tsv"
        self.tcb_path = REPO_ROOT / "distribution/s3-thesis/TCB.tsv"
        self.experiments_path = REPO_ROOT / "distribution/s3-thesis/EXPERIMENTS.tsv"

    def _mutate_and_reseal(
        self,
        source: Path,
        magic: str,
        domain: bytes,
        mutate,
    ) -> Path:
        lines = source.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[0], magic)
        mutate(lines)
        body = "".join(f"{line}\n" for line in lines[:-1]).encode()
        lines[-1] = f"seal\t{AUDIT._sha256(domain + body)}"
        directory = Path(tempfile.mkdtemp(prefix="naux-s3-mutated-"))
        self.addCleanup(shutil.rmtree, directory)
        output = directory / source.name
        output.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return output

    def _copy_bound_tree(self) -> Path:
        directory = Path(tempfile.mkdtemp(prefix="naux-s3-tree-"))
        self.addCleanup(shutil.rmtree, directory)
        bundle = AUDIT.parse_audit(self.audit_path)
        for record in bundle.files:
            source = REPO_ROOT / record.path
            target = directory / record.path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        audit_target = directory / "distribution/s3-thesis/AUDIT.tsv"
        audit_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.audit_path, audit_target)
        return directory

    def test_canonical_bundle_admits_without_building_rust(self) -> None:
        bundle = AUDIT.verify_bundle(REPO_ROOT, self.audit_path)
        self.assertEqual(len(bundle.files), 15)
        self.assertEqual(dict(bundle.roots)["process-results"], AUDIT.EXPECTED_ROOTS[-3][1])
        report = AUDIT.render_audit_report(bundle, replayed=False)
        self.assertIn("mode\tstatic-only\n", report)
        self.assertIn("performance-leadership\tnot-claimed\n", report)

    def test_missing_final_lf_is_rejected(self) -> None:
        raw = self.audit_path.read_bytes()
        with tempfile.TemporaryDirectory(prefix="naux-s3-no-lf-") as temp:
            path = Path(temp) / "AUDIT.tsv"
            path.write_bytes(raw.rstrip(b"\n"))
            with self.assertRaisesRegex(AUDIT.AuditError, "end with one LF"):
                AUDIT.parse_audit(path)

    def test_crlf_is_rejected(self) -> None:
        raw = self.audit_path.read_bytes().replace(b"\n", b"\r\n")
        with tempfile.TemporaryDirectory(prefix="naux-s3-crlf-") as temp:
            path = Path(temp) / "AUDIT.tsv"
            path.write_bytes(raw)
            with self.assertRaisesRegex(AUDIT.AuditError, "canonical LF"):
                AUDIT.parse_audit(path)

    def test_magic_mutation_is_rejected_even_when_resealed(self) -> None:
        cases = (
            (
                self.audit_path,
                AUDIT.AUDIT_MAGIC,
                AUDIT.AUDIT_DOMAIN,
                AUDIT.parse_audit,
            ),
            (self.tcb_path, AUDIT.TCB_MAGIC, AUDIT.TCB_DOMAIN, AUDIT.parse_tcb),
            (
                self.experiments_path,
                AUDIT.EXPERIMENT_MAGIC,
                AUDIT.EXPERIMENT_DOMAIN,
                AUDIT.parse_experiments,
            ),
        )
        for source, magic, domain, parser in cases:
            with self.subTest(manifest=source.name):
                path = self._mutate_and_reseal(
                    source,
                    magic,
                    domain,
                    lambda lines: lines.__setitem__(0, lines[0] + "-MUTATED"),
                )
                with self.assertRaisesRegex(AUDIT.AuditError, "unsupported schema"):
                    parser(path)

    def test_final_seal_is_verified_for_every_manifest(self) -> None:
        cases = (
            (self.audit_path, AUDIT.parse_audit),
            (self.tcb_path, AUDIT.parse_tcb),
            (self.experiments_path, AUDIT.parse_experiments),
        )
        for source, parser in cases:
            with self.subTest(manifest=source.name):
                lines = source.read_text(encoding="utf-8").splitlines()
                fields = lines[-1].split("\t")
                fields[1] = ("0" if fields[1][0] != "0" else "1") + fields[1][1:]
                lines[-1] = "\t".join(fields)
                with tempfile.TemporaryDirectory(prefix="naux-s3-seal-") as temp:
                    path = Path(temp) / source.name
                    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    with self.assertRaisesRegex(AUDIT.AuditError, "seal mismatch"):
                        parser(path)

    def test_stale_semantic_root_is_rejected_even_when_resealed(self) -> None:
        def mutate(lines: list[str]) -> None:
            index = next(i for i, line in enumerate(lines) if line.startswith("root\tcore\t"))
            lines[index] = "root\tcore\t" + ("0" * 64)

        path = self._mutate_and_reseal(
            self.audit_path, AUDIT.AUDIT_MAGIC, AUDIT.AUDIT_DOMAIN, mutate
        )
        with self.assertRaisesRegex(AUDIT.AuditError, "semantic root drift"):
            AUDIT.parse_audit(path)

    def test_every_audit_metadata_value_is_immutable_after_reseal(self) -> None:
        for offset, (key, _) in enumerate(AUDIT.AUDIT_METADATA, start=1):
            with self.subTest(key=key):
                def mutate(lines: list[str], row: int = offset) -> None:
                    fields = lines[row].split("\t")
                    fields[1] = "mutated"
                    lines[row] = "\t".join(fields)

                path = self._mutate_and_reseal(
                    self.audit_path, AUDIT.AUDIT_MAGIC, AUDIT.AUDIT_DOMAIN, mutate
                )
                with self.assertRaisesRegex(AUDIT.AuditError, "metadata drift"):
                    AUDIT.parse_audit(path)

    def test_every_semantic_root_is_immutable_after_reseal(self) -> None:
        start = 1 + len(AUDIT.AUDIT_METADATA)
        for offset, (name, digest) in enumerate(AUDIT.EXPECTED_ROOTS, start=start):
            with self.subTest(root=name):
                replacement = ("0" if digest[0] != "0" else "1") + digest[1:]

                def mutate(lines: list[str], row: int = offset, value: str = replacement) -> None:
                    fields = lines[row].split("\t")
                    fields[2] = value
                    lines[row] = "\t".join(fields)

                path = self._mutate_and_reseal(
                    self.audit_path, AUDIT.AUDIT_MAGIC, AUDIT.AUDIT_DOMAIN, mutate
                )
                with self.assertRaisesRegex(AUDIT.AuditError, "semantic root drift"):
                    AUDIT.parse_audit(path)

    def test_metadata_order_is_rejected_even_when_resealed(self) -> None:
        def mutate(lines: list[str]) -> None:
            lines[1], lines[2] = lines[2], lines[1]

        path = self._mutate_and_reseal(
            self.audit_path, AUDIT.AUDIT_MAGIC, AUDIT.AUDIT_DOMAIN, mutate
        )
        with self.assertRaisesRegex(AUDIT.AuditError, "metadata drift"):
            AUDIT.parse_audit(path)

    def test_file_count_drift_is_rejected_even_when_resealed(self) -> None:
        def mutate(lines: list[str]) -> None:
            index = next(i for i, line in enumerate(lines) if line.startswith("files\t"))
            lines[index] = "files\t14"

        path = self._mutate_and_reseal(
            self.audit_path, AUDIT.AUDIT_MAGIC, AUDIT.AUDIT_DOMAIN, mutate
        )
        with self.assertRaisesRegex(AUDIT.AuditError, "file count drift"):
            AUDIT.parse_audit(path)

    def test_noncanonical_file_count_is_rejected_even_when_resealed(self) -> None:
        def mutate(lines: list[str]) -> None:
            index = next(i for i, line in enumerate(lines) if line.startswith("files\t"))
            lines[index] = "files\t015"

        path = self._mutate_and_reseal(
            self.audit_path, AUDIT.AUDIT_MAGIC, AUDIT.AUDIT_DOMAIN, mutate
        )
        with self.assertRaisesRegex(AUDIT.AuditError, "file count drift"):
            AUDIT.parse_audit(path)

    def test_noncanonical_file_mode_is_rejected_even_when_resealed(self) -> None:
        def mutate(lines: list[str]) -> None:
            index = next(i for i, line in enumerate(lines) if line.startswith("file\t"))
            fields = lines[index].split("\t")
            fields[1] = "00644"
            lines[index] = "\t".join(fields)

        path = self._mutate_and_reseal(
            self.audit_path, AUDIT.AUDIT_MAGIC, AUDIT.AUDIT_DOMAIN, mutate
        )
        with self.assertRaisesRegex(AUDIT.AuditError, "mode or size"):
            AUDIT.parse_audit(path)

    def test_invalid_file_hash_is_rejected_even_when_resealed(self) -> None:
        def mutate(lines: list[str]) -> None:
            index = next(i for i, line in enumerate(lines) if line.startswith("file\t"))
            fields = lines[index].split("\t")
            fields[3] = "g" * 64
            lines[index] = "\t".join(fields)

        path = self._mutate_and_reseal(
            self.audit_path, AUDIT.AUDIT_MAGIC, AUDIT.AUDIT_DOMAIN, mutate
        )
        with self.assertRaisesRegex(AUDIT.AuditError, "invalid SHA-256"):
            AUDIT.parse_audit(path)

    def test_trailing_record_is_rejected_even_when_resealed(self) -> None:
        def mutate(lines: list[str]) -> None:
            lines.insert(-1, "unexpected\tdata")

        path = self._mutate_and_reseal(
            self.audit_path, AUDIT.AUDIT_MAGIC, AUDIT.AUDIT_DOMAIN, mutate
        )
        with self.assertRaisesRegex(AUDIT.AuditError, "unexpected audit trailing record"):
            AUDIT.parse_audit(path)

    def test_path_traversal_is_rejected_even_when_resealed(self) -> None:
        def mutate(lines: list[str]) -> None:
            index = next(i for i, line in enumerate(lines) if line.startswith("file\t"))
            fields = lines[index].split("\t")
            fields[4] = "../escape"
            lines[index] = "\t".join(fields)

        path = self._mutate_and_reseal(
            self.audit_path, AUDIT.AUDIT_MAGIC, AUDIT.AUDIT_DOMAIN, mutate
        )
        with self.assertRaisesRegex(AUDIT.AuditError, "not canonical and relative"):
            AUDIT.parse_audit(path)

    def test_duplicate_inventory_member_is_rejected(self) -> None:
        def mutate(lines: list[str]) -> None:
            indices = [i for i, line in enumerate(lines) if line.startswith("file\t")]
            fields = lines[indices[1]].split("\t")
            fields[4] = lines[indices[0]].split("\t")[4]
            lines[indices[1]] = "\t".join(fields)

        path = self._mutate_and_reseal(
            self.audit_path, AUDIT.AUDIT_MAGIC, AUDIT.AUDIT_DOMAIN, mutate
        )
        with self.assertRaisesRegex(AUDIT.AuditError, "inventory identity"):
            AUDIT.parse_audit(path)

    def test_bound_file_content_drift_is_rejected(self) -> None:
        root = self._copy_bound_tree()
        target = root / "distribution/s3-thesis/LIMITATIONS.md"
        target.write_bytes(target.read_bytes() + b"drift\n")
        with self.assertRaisesRegex(AUDIT.AuditError, "content drift"):
            AUDIT.verify_bundle(root, root / "distribution/s3-thesis/AUDIT.tsv")

    def test_every_bound_file_content_is_verified(self) -> None:
        root = self._copy_bound_tree()
        bundle = AUDIT.parse_audit(root / "distribution/s3-thesis/AUDIT.tsv")
        for record in bundle.files:
            with self.subTest(path=record.path):
                target = root / record.path
                original = target.read_bytes()
                target.write_bytes(original + b"mutation")
                try:
                    with self.assertRaises(AUDIT.AuditError):
                        AUDIT.verify_bundle(
                            root, root / "distribution/s3-thesis/AUDIT.tsv"
                        )
                finally:
                    target.write_bytes(original)

    def test_every_audit_file_record_field_is_checked_after_reseal(self) -> None:
        bundle = AUDIT.parse_audit(self.audit_path)
        for record in bundle.files:
            for field in ("mode", "size", "sha256", "path"):
                with self.subTest(path=record.path, field=field):
                    def mutate(
                        lines: list[str],
                        member: str = record.path,
                        field_name: str = field,
                    ) -> None:
                        index = next(
                            i
                            for i, line in enumerate(lines)
                            if line.startswith("file\t") and line.endswith("\t" + member)
                        )
                        fields = lines[index].split("\t")
                        if field_name == "mode":
                            fields[1] = "0755"
                        elif field_name == "size":
                            fields[2] = str(int(fields[2]) + 1)
                        elif field_name == "sha256":
                            fields[3] = ("0" if fields[3][0] != "0" else "1") + fields[3][1:]
                        else:
                            fields[4] = "mutated/" + fields[4]
                        lines[index] = "\t".join(fields)

                    path = self._mutate_and_reseal(
                        self.audit_path, AUDIT.AUDIT_MAGIC, AUDIT.AUDIT_DOMAIN, mutate
                    )
                    with self.assertRaises(AUDIT.AuditError):
                        AUDIT.verify_bundle(REPO_ROOT, path)

    def test_bound_file_symlink_is_rejected(self) -> None:
        root = self._copy_bound_tree()
        target = root / "distribution/s3-thesis/LIMITATIONS.md"
        target.unlink()
        target.symlink_to("TCB.tsv")
        with self.assertRaisesRegex(AUDIT.AuditError, "not a regular file"):
            AUDIT.verify_bundle(root, root / "distribution/s3-thesis/AUDIT.tsv")

    def test_tcb_class_mutation_is_rejected_even_when_resealed(self) -> None:
        def first_entry(lines: list[str]) -> None:
            index = next(i for i, line in enumerate(lines) if line.startswith("entry\t01\t"))
            lines[index] = lines[index].replace("\tbuild-seed\t", "\toptional-tool\t")

        path = self._mutate_and_reseal(
            self.tcb_path, AUDIT.TCB_MAGIC, AUDIT.TCB_DOMAIN, first_entry
        )
        with self.assertRaisesRegex(AUDIT.AuditError, "identity, order, or status drift"):
            AUDIT.parse_tcb(path)

    def test_every_tcb_header_value_is_immutable_after_reseal(self) -> None:
        for row in range(1, 6):
            with self.subTest(row=row):
                def mutate(lines: list[str], index: int = row) -> None:
                    fields = lines[index].split("\t")
                    fields[1] = "mutated"
                    lines[index] = "\t".join(fields)

                path = self._mutate_and_reseal(
                    self.tcb_path, AUDIT.TCB_MAGIC, AUDIT.TCB_DOMAIN, mutate
                )
                with self.assertRaisesRegex(AUDIT.AuditError, "header or count drift"):
                    AUDIT.parse_tcb(path)

    def test_every_tcb_entry_field_is_immutable_after_reseal(self) -> None:
        replacements = {
            1: "99",
            2: "mutated-class",
            3: "mutated-component",
            4: "mutated-version",
            5: "mutated-status",
            6: "mutated description",
        }
        for row_offset, key in enumerate(AUDIT.EXPECTED_TCB_KEYS, start=6):
            for field_index, replacement in replacements.items():
                with self.subTest(entry=key[0], field=field_index):
                    def mutate(
                        lines: list[str],
                        row: int = row_offset,
                        column: int = field_index,
                        value: str = replacement,
                    ) -> None:
                        fields = lines[row].split("\t")
                        fields[column] = value
                        lines[row] = "\t".join(fields)

                    path = self._mutate_and_reseal(
                        self.tcb_path, AUDIT.TCB_MAGIC, AUDIT.TCB_DOMAIN, mutate
                    )
                    with self.assertRaises(AUDIT.AuditError):
                        AUDIT.parse_tcb(path)

    def test_command_shaped_experiment_id_is_rejected_after_reseal(self) -> None:
        def mutate(lines: list[str]) -> None:
            index = next(i for i, line in enumerate(lines) if line.startswith("step\t04\t"))
            fields = lines[index].split("\t")
            fields[3] = "$(touch-pwned)"
            lines[index] = "\t".join(fields)

        path = self._mutate_and_reseal(
            self.experiments_path,
            AUDIT.EXPERIMENT_MAGIC,
            AUDIT.EXPERIMENT_DOMAIN,
            mutate,
        )
        with self.assertRaisesRegex(AUDIT.AuditError, "data-only"):
            AUDIT.parse_experiments(path)

    def test_unknown_experiment_step_is_rejected_after_reseal(self) -> None:
        def mutate(lines: list[str]) -> None:
            index = next(i for i, line in enumerate(lines) if line.startswith("step\t04\t"))
            fields = lines[index].split("\t")
            fields[3] = "unknown-step"
            lines[index] = "\t".join(fields)

        path = self._mutate_and_reseal(
            self.experiments_path,
            AUDIT.EXPERIMENT_MAGIC,
            AUDIT.EXPERIMENT_DOMAIN,
            mutate,
        )
        with self.assertRaisesRegex(AUDIT.AuditError, "identity, order, kind, or status drift"):
            AUDIT.parse_experiments(path)

    def test_every_experiment_header_value_is_immutable_after_reseal(self) -> None:
        for row in range(1, 5):
            with self.subTest(row=row):
                def mutate(lines: list[str], index: int = row) -> None:
                    fields = lines[index].split("\t")
                    fields[1] = "mutated"
                    lines[index] = "\t".join(fields)

                path = self._mutate_and_reseal(
                    self.experiments_path,
                    AUDIT.EXPERIMENT_MAGIC,
                    AUDIT.EXPERIMENT_DOMAIN,
                    mutate,
                )
                with self.assertRaisesRegex(AUDIT.AuditError, "header or count drift"):
                    AUDIT.parse_experiments(path)

    def test_every_experiment_field_is_immutable_after_reseal(self) -> None:
        replacements = {
            1: "99",
            2: "mutated-kind",
            3: "mutated-step",
            4: "mutated-status",
            5: "mutated description",
        }
        for row_offset, key in enumerate(AUDIT.EXPECTED_EXPERIMENT_KEYS, start=5):
            for field_index, replacement in replacements.items():
                with self.subTest(step=key[0], field=field_index):
                    def mutate(
                        lines: list[str],
                        row: int = row_offset,
                        column: int = field_index,
                        value: str = replacement,
                    ) -> None:
                        fields = lines[row].split("\t")
                        fields[column] = value
                        lines[row] = "\t".join(fields)

                    path = self._mutate_and_reseal(
                        self.experiments_path,
                        AUDIT.EXPERIMENT_MAGIC,
                        AUDIT.EXPERIMENT_DOMAIN,
                        mutate,
                    )
                    with self.assertRaises(AUDIT.AuditError):
                        AUDIT.parse_experiments(path)

    def test_reordered_and_duplicate_rows_fail_for_each_manifest_class(self) -> None:
        cases = (
            (self.audit_path, AUDIT.AUDIT_MAGIC, AUDIT.AUDIT_DOMAIN, 1),
            (self.tcb_path, AUDIT.TCB_MAGIC, AUDIT.TCB_DOMAIN, 6),
            (
                self.experiments_path,
                AUDIT.EXPERIMENT_MAGIC,
                AUDIT.EXPERIMENT_DOMAIN,
                5,
            ),
        )
        parsers = (AUDIT.parse_audit, AUDIT.parse_tcb, AUDIT.parse_experiments)
        for (source, magic, domain, first), parser in zip(cases, parsers, strict=True):
            for operation in ("reorder", "duplicate"):
                with self.subTest(manifest=source.name, operation=operation):
                    def mutate(
                        lines: list[str], index: int = first, action: str = operation
                    ) -> None:
                        if action == "reorder":
                            lines[index], lines[index + 1] = lines[index + 1], lines[index]
                        else:
                            lines[index + 1] = lines[index]

                    path = self._mutate_and_reseal(source, magic, domain, mutate)
                    with self.assertRaises(AUDIT.AuditError):
                        parser(path)

    def test_missing_and_trailing_rows_fail_for_each_manifest_class(self) -> None:
        cases = (
            (self.audit_path, AUDIT.AUDIT_MAGIC, AUDIT.AUDIT_DOMAIN, 1),
            (self.tcb_path, AUDIT.TCB_MAGIC, AUDIT.TCB_DOMAIN, 6),
            (
                self.experiments_path,
                AUDIT.EXPERIMENT_MAGIC,
                AUDIT.EXPERIMENT_DOMAIN,
                5,
            ),
        )
        parsers = (AUDIT.parse_audit, AUDIT.parse_tcb, AUDIT.parse_experiments)
        for (source, magic, domain, first), parser in zip(cases, parsers, strict=True):
            for operation in ("missing", "trailing"):
                with self.subTest(manifest=source.name, operation=operation):
                    def mutate(
                        lines: list[str], index: int = first, action: str = operation
                    ) -> None:
                        if action == "missing":
                            del lines[index]
                        else:
                            lines.insert(-1, "unknown\trecord")

                    path = self._mutate_and_reseal(source, magic, domain, mutate)
                    with self.assertRaises(AUDIT.AuditError):
                        parser(path)

    def test_oversized_manifest_is_rejected_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-s3-oversized-") as temp:
            path = Path(temp) / "AUDIT.tsv"
            path.write_bytes(b"x" * 1_000_001 + b"\n")
            with self.assertRaisesRegex(AUDIT.AuditError, "size limit"):
                AUDIT.parse_audit(path)

    def test_component_seal_substitution_is_rejected(self) -> None:
        for key in ("tcb-seal", "experiments-seal"):
            with self.subTest(component=key):
                def mutate(lines: list[str], seal_key: str = key) -> None:
                    index = next(i for i, line in enumerate(lines) if line.startswith(seal_key + "\t"))
                    lines[index] = seal_key + "\t" + ("0" * 64)

                path = self._mutate_and_reseal(
                    self.audit_path, AUDIT.AUDIT_MAGIC, AUDIT.AUDIT_DOMAIN, mutate
                )
                with self.assertRaisesRegex(AUDIT.AuditError, "component seal"):
                    AUDIT.verify_bundle(REPO_ROOT, path)

    def test_fixed_argv_runner_does_not_invoke_a_shell(self) -> None:
        marker = Path(tempfile.mkdtemp(prefix="naux-s3-shell-")) / "owned"
        self.addCleanup(shutil.rmtree, marker.parent)
        payload = f";touch {marker}"
        output = AUDIT._run(
            [sys.executable, "-c", "import sys; print(sys.argv[1])", payload],
            "argv probe",
            4096,
        )
        self.assertEqual(output.decode().strip(), payload)
        self.assertFalse(marker.exists())

    def test_worker_frame_size_mutation_is_rejected(self) -> None:
        bundle = AUDIT.parse_audit(self.audit_path)
        dummy_carrier = AUDIT.CarrierReport(tuple(), "0" * 64)
        dummy_process = AUDIT.ProcessReport(tuple(), "0" * 64)
        with self.assertRaisesRegex(AUDIT.AuditError, "714 bytes instead of 715"):
            AUDIT.verify_worker_frame(b"\0" * 714, 0, dict(bundle.roots), dummy_carrier, dummy_process)

    def test_real_reports_replay_when_reviewed_binaries_exist(self) -> None:
        binaries = (
            REPO_ROOT / "target/debug/naux-surface-native-t1",
            REPO_ROOT / "target/debug/naux-surface-native-t1-worker",
            REPO_ROOT / "target/debug/naux-surface-native-t1-process",
        )
        if not all(path.is_file() for path in binaries):
            self.skipTest("reviewed debug binaries have not been built")
        bundle = AUDIT.verify_bundle(REPO_ROOT, self.audit_path)
        carrier, process = AUDIT.replay(bundle, *binaries)
        self.assertEqual(len(carrier.cases), 12)
        self.assertEqual(len(process.cases), 12)

    def test_real_carrier_report_value_mutation_fails_closed_when_available(self) -> None:
        binary = REPO_ROOT / "target/debug/naux-surface-native-t1"
        if not binary.is_file():
            self.skipTest("reviewed debug binary has not been built")
        raw = subprocess.run([binary], check=True, stdout=subprocess.PIPE).stdout
        lines = raw.decode().splitlines()
        index = next(i for i, line in enumerate(lines) if line.startswith("case\t0\t"))
        fields = lines[index].split("\t")
        fields[9] = "f64:0x0000000000000000"
        lines[index] = "\t".join(fields)
        mutated = ("\n".join(lines) + "\n").encode()
        with self.assertRaisesRegex(AUDIT.AuditError, "record hash mismatch"):
            AUDIT.parse_carrier_report(mutated, dict(AUDIT.EXPECTED_ROOTS))

    def test_real_report_shape_and_receipt_mutations_fail_closed_when_available(self) -> None:
        t1 = REPO_ROOT / "target/debug/naux-surface-native-t1"
        worker = REPO_ROOT / "target/debug/naux-surface-native-t1-worker"
        process = REPO_ROOT / "target/debug/naux-surface-native-t1-process"
        if not all(path.is_file() for path in (t1, worker, process)):
            self.skipTest("reviewed debug binaries have not been built")
        roots = dict(AUDIT.EXPECTED_ROOTS)
        carrier_raw = subprocess.run([t1], check=True, stdout=subprocess.PIPE).stdout
        carrier = AUDIT.parse_carrier_report(carrier_raw, roots)
        carrier_lines = carrier_raw.decode().splitlines()
        carrier_columns = next(
            i for i, line in enumerate(carrier_lines) if line.startswith("columns\t")
        )
        carrier_lines[carrier_columns] += "\textra"
        with self.assertRaisesRegex(AUDIT.AuditError, "columns drift"):
            AUDIT.parse_carrier_report(("\n".join(carrier_lines) + "\n").encode(), roots)

        process_raw = subprocess.run(
            [process, worker], check=True, stdout=subprocess.PIPE
        ).stdout
        process_lines = process_raw.decode().splitlines()
        process_columns = next(
            i for i, line in enumerate(process_lines) if line.startswith("columns\t")
        )
        original_columns = process_lines[process_columns]
        process_lines[process_columns] += "\textra"
        with self.assertRaisesRegex(AUDIT.AuditError, "columns drift"):
            AUDIT.parse_process_report(
                ("\n".join(process_lines) + "\n").encode(), roots, carrier
            )
        process_lines[process_columns] = original_columns
        case_index = next(
            i for i, line in enumerate(process_lines) if line.startswith("case\t0\t")
        )
        fields = process_lines[case_index].split("\t")
        fields[5] = "0" * 64
        process_lines[case_index] = "\t".join(fields)
        with self.assertRaisesRegex(AUDIT.AuditError, "receipt reconstruction mismatch"):
            AUDIT.parse_process_report(
                ("\n".join(process_lines) + "\n").encode(), roots, carrier
            )

    def test_resealed_worker_mapping_mutation_fails_closed_when_available(self) -> None:
        t1 = REPO_ROOT / "target/debug/naux-surface-native-t1"
        worker = REPO_ROOT / "target/debug/naux-surface-native-t1-worker"
        process = REPO_ROOT / "target/debug/naux-surface-native-t1-process"
        if not all(path.is_file() for path in (t1, worker, process)):
            self.skipTest("reviewed debug binaries have not been built")
        roots = dict(AUDIT.EXPECTED_ROOTS)
        carrier_raw = subprocess.run([t1], check=True, stdout=subprocess.PIPE).stdout
        carrier = AUDIT.parse_carrier_report(carrier_raw, roots)
        process_raw = subprocess.run(
            [process, worker], check=True, stdout=subprocess.PIPE
        ).stdout
        process_report = AUDIT.parse_process_report(process_raw, roots, carrier)
        frame = bytearray(
            subprocess.run([worker, "0"], check=True, stdout=subprocess.PIPE).stdout
        )
        mapping_start = (
            len(AUDIT.IPC_DOMAIN) + 18 + 4 + (9 * 32) + 32 + (6 * 9) + 32 + (6 * 32)
        )
        self.assertEqual(frame[mapping_start:mapping_start + 4], bytes((0, 1, 2, 0)))
        frame[mapping_start] = 2
        frame[-32:] = bytes.fromhex(AUDIT._sha256(bytes(frame[:-32])))
        with self.assertRaisesRegex(AUDIT.AuditError, "mapping trace drift"):
            AUDIT.verify_worker_frame(
                bytes(frame), 0, roots, carrier, process_report
            )


if __name__ == "__main__":
    unittest.main()
