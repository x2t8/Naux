#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residency_elf_coq_certificate.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "s4_residency_elf_coq_certificate_test", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)


class S4ResidencyElfCoqCertificateTests(unittest.TestCase):
    def native_kernel(self, target: bytes = b"\x90\xc3"):
        return bridge.x86_bridge.NativeKernel(
            ordinal="01",
            name="test",
            target=tuple(target),
            target_bytes=len(target),
            error_offset=0,
            save_start=0,
            shadow_displacement=-48,
            sites=(),
            restore_starts=(),
        )

    def report(self, image: bytes, target_bytes: int = 2) -> bytes:
        rows = [bridge.wp8f.ELF_MAGIC]
        rows.extend(
            f"meta\t{key}\t{value}" for key, value in bridge.wp8f.EXPECTED_METADATA
        )
        rows.extend(
            [
                bridge.wp8f.EXPECTED_COLUMNS,
                "\t".join(
                    (
                        "kernel",
                        "01",
                        "test",
                        "a" * 64,
                        "b" * 64,
                        "c" * 64,
                        "d" * 64,
                        str(target_bytes),
                        str(len(image)),
                        "272",
                        "4194560",
                        "5",
                        "6",
                    )
                ),
                f"elf-hex\t01\t{image.hex()}",
                "verification\tindependent-elf-parser-accepted",
                "verification\tno-file-no-execution-no-measurement",
                "report-root\troot",
            ]
        )
        return ("\n".join(rows) + "\n").encode()

    def test_canonical_envelope_has_exact_layout_and_target(self) -> None:
        target = bytes.fromhex("90c3")
        image = bridge.canonical_elf64_envelope(target)
        self.assertEqual(len(image), 274)
        self.assertEqual(image[:7], b"\x7fELF\x02\x01\x01")
        self.assertEqual(image[256:272], bytes.fromhex("e80b00000031ffb83c0000000f050f0b"))
        self.assertEqual(image[272:], target)

    def test_report_joins_complete_image_to_native_target(self) -> None:
        native = self.native_kernel()
        image = bridge.canonical_elf64_envelope(bytes(native.target))
        kernels = bridge.parse_joined_elf_report(
            self.report(image), [native], "root"
        )
        self.assertEqual(kernels[0].image, tuple(image))
        self.assertEqual(kernels[0].target_offset, 272)

    def test_header_mutation_fails_closed(self) -> None:
        native = self.native_kernel()
        image = bytearray(bridge.canonical_elf64_envelope(bytes(native.target)))
        image[0] ^= 1
        with self.assertRaises(bridge.ElfCertificateError):
            bridge.parse_joined_elf_report(
                self.report(bytes(image)), [native], "root"
            )

    def test_target_mutation_fails_closed(self) -> None:
        native = self.native_kernel()
        image = bytearray(bridge.canonical_elf64_envelope(bytes(native.target)))
        image[-1] ^= 1
        with self.assertRaisesRegex(
            bridge.ElfCertificateError, "does not contain the WP8E target"
        ):
            bridge.parse_joined_elf_report(
                self.report(bytes(image)), [native], "root"
            )

    def test_receipt_extent_mutation_fails_closed(self) -> None:
        native = self.native_kernel()
        image = bridge.canonical_elf64_envelope(bytes(native.target))
        with self.assertRaises(bridge.ElfCertificateError):
            bridge.parse_joined_elf_report(
                self.report(image, target_bytes=3), [native], "root"
            )

    def test_emitter_binds_image_to_generated_wp8e_target(self) -> None:
        image = bridge.canonical_elf64_envelope(b"\x90\xc3")
        kernel = bridge.ElfKernel(
            ordinal="01",
            name="test",
            image=tuple(image),
            image_bytes=len(image),
            target_bytes=2,
            target_offset=272,
            entry=4_194_560,
            load_flags=5,
            stack_flags=6,
        )
        output = bridge.emit_rocq([kernel], "a" * 64, "b" * 64, "c" * 64)
        self.assertIn("GeneratedWP8EX86Certificates", output)
        self.assertIn("wp8e_kernel_01_target", output)
        self.assertIn("image_is_canonical_envelope", output)
        self.assertIn("contains_wp8e_target", output)


if __name__ == "__main__":
    unittest.main()
