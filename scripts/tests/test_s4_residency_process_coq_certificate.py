#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residency_process_coq_certificate.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "s4_residency_process_coq_certificate_test", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)


class S4ResidencyProcessCoqCertificateTests(unittest.TestCase):
    def fixture(self):
        candidate = bytearray(40)
        candidate[11:18] = bytes.fromhex("4c89a5d0ffffff")
        candidate[24:40] = bytes.fromhex(
            "4c8ba5d0ffffff488b85e0ffffffc9c3"
        )
        record = bridge.wp8g.ContractRecord(
            ordinal=1,
            name="test",
            oracle=7,
            work_hash="a" * 64,
            candidate_hash=hashlib.sha256(candidate).hexdigest(),
            process_hash="b" * 64,
            elf_hash="c" * 64,
            candidate_bytes=40,
            process_bytes=120,
            error_offset=40,
            return_start=24,
            verifier_offset=40,
            checksum_displacement=-32,
            outer_displacement=-48,
            inner_displacement=-48,
            owner_displacement=-24,
            expected_outer=50,
            expected_inner=16_384,
            elf_bytes=504,
            startup_bytes=117,
            target_offset=384,
        )
        process = bridge.wp8g._reconstruct_process(bytes(candidate), record)
        elf = bridge.canonical_process_elf_prefix(process, record.ordinal) + process
        kernel = bridge.wp8g.Kernel(record, bytes(candidate), process, elf)
        report = bridge.wp8g.Candidate((kernel,), b"fixture\n")
        native = bridge.x86_bridge.NativeKernel(
            ordinal="01",
            name="test",
            target=tuple(candidate),
            target_bytes=len(candidate),
            error_offset=40,
            save_start=11,
            shadow_displacement=-48,
            sites=(),
            restore_starts=(24,),
        )
        return report, native

    def test_join_extracts_exact_patch_verifier_and_error_edges(self) -> None:
        candidate, native = self.fixture()
        kernel = bridge.join_authenticated_candidate(candidate, [native])[0]
        self.assertEqual(kernel.patch[:1], (0xE9,))
        self.assertEqual(kernel.patch[5:], (0x90,) * 11)
        self.assertEqual(len(kernel.verifier), 80)
        self.assertEqual(len(kernel.elf_prefix), 384)
        self.assertEqual(kernel.elf_bytes, 504)
        self.assertEqual(40 + 33 + kernel.outer_error_delta, 40)
        self.assertEqual(40 + 55 + kernel.inner_error_delta, 40)
        self.assertEqual(40 + 71 + kernel.owner_error_delta, 40)

    def test_join_rejects_a_candidate_not_equal_to_wp8e(self) -> None:
        candidate, native = self.fixture()
        drifted = bridge.x86_bridge.NativeKernel(
            ordinal=native.ordinal,
            name=native.name,
            target=tuple([*native.target[:-1], native.target[-1] ^ 1]),
            target_bytes=native.target_bytes,
            error_offset=native.error_offset,
            save_start=native.save_start,
            shadow_displacement=native.shadow_displacement,
            sites=native.sites,
            restore_starts=native.restore_starts,
        )
        with self.assertRaisesRegex(
            bridge.ProcessCertificateError, "not the admitted WP8E target"
        ):
            bridge.join_authenticated_candidate(candidate, [drifted])

    def test_emitter_reuses_wp8e_and_exposes_closed_wp8g_proofs(self) -> None:
        candidate, native = self.fixture()
        kernel = bridge.join_authenticated_candidate(candidate, [native])[0]
        output = bridge.emit_rocq(
            [kernel], "a" * 64, "b" * 64, "c" * 64, "d" * 64
        )
        self.assertIn("GeneratedWP8EX86Certificates", output)
        self.assertIn("wp8e_kernel_01_target", output)
        self.assertNotIn("Definition wp8g_kernel_01_candidate", output)
        self.assertIn("process_is_well_formed", output)
        self.assertIn("contains_verifier", output)
        self.assertIn("process_bytes_are_bounded", output)
        self.assertIn("reported_elf_prefix_is_canonical", output)
        self.assertIn("elf_image_is_well_formed", output)
        self.assertIn("elf_contains_process", output)
        self.assertIn("ELF64ResidencyProcessEnvelope", output)
        self.assertIn("x86 execution, Linux loading", output)

    def test_join_rejects_noncanonical_process_elf_prefix(self) -> None:
        candidate, native = self.fixture()
        kernel = candidate.kernels[0]
        drifted_elf = bytearray(kernel.elf)
        drifted_elf[200] ^= 1
        drifted = bridge.wp8g.Candidate(
            (
                bridge.wp8g.Kernel(
                    kernel.record,
                    kernel.candidate,
                    kernel.process,
                    bytes(drifted_elf),
                ),
            ),
            candidate.raw,
        )
        with self.assertRaisesRegex(
            bridge.ProcessCertificateError, "process ELF prefix drifted"
        ):
            bridge.join_authenticated_candidate(drifted, [native])

    def test_kernel_filter_is_fail_closed(self) -> None:
        candidate, native = self.fixture()
        kernels = bridge.join_authenticated_candidate(candidate, [native])
        self.assertEqual(bridge._filter_kernels(kernels, ["01"]), kernels)
        with self.assertRaisesRegex(
            bridge.ProcessCertificateError, "unknown --kernel ordinal"
        ):
            bridge._filter_kernels(kernels, ["02"])
        with self.assertRaisesRegex(
            bridge.ProcessCertificateError, "duplicate --kernel ordinal"
        ):
            bridge._filter_kernels(kernels, ["01", "01"])


if __name__ == "__main__":
    unittest.main()
