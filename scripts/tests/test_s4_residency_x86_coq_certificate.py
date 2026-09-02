#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residency_x86_coq_certificate.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "s4_residency_x86_coq_certificate_test", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)


class S4ResidencyX86CoqCertificateTests(unittest.TestCase):
    def test_semantic_load_site_is_retained(self) -> None:
        action = (
            "OwnershipPlain (HeapScalarInstruction "
            "(ResidencyAccess (LoadHome 20%nat)))"
        )
        self.assertEqual(
            bridge._semantic_site(action),
            "X86SemanticLoadPhysical 20%nat",
        )

    def test_semantic_store_site_retains_source_and_ownership(self) -> None:
        self.assertEqual(
            bridge._semantic_site("OwnershipStoreHome 25%nat false"),
            "X86SemanticStorePhysical 25%nat false",
        )
        self.assertEqual(
            bridge._semantic_site("OwnershipStoreHome 9%nat true"),
            "X86SemanticStorePhysical 9%nat true",
        )

    def test_plain_instruction_is_not_a_native_residency_site(self) -> None:
        self.assertIsNone(
            bridge._semantic_site(
                "OwnershipPlain (HeapScalarInstruction "
                "(ScalarPassThrough (ScalarConst 1%nat 0%Z)))"
            )
        )

    def test_store_template_decodes_signed_disp32(self) -> None:
        self.assertEqual(
            bridge._decode_template(bytes.fromhex("4c89a5d0ffffff")),
            ("store-r12", -48),
        )

    def test_load_template_decodes_signed_disp32(self) -> None:
        self.assertEqual(
            bridge._decode_template(bytes.fromhex("4c8ba5c8ffffff")),
            ("load-r12", -56),
        )

    def test_noncanonical_template_fails_closed(self) -> None:
        for raw in (
            bytes.fromhex("4d89a5d0ffffff"),
            bytes.fromhex("4c89a5d0ffff"),
            bytes.fromhex("4c01a5d0ffffff"),
        ):
            with self.subTest(raw=raw.hex()):
                with self.assertRaises(bridge.X86CertificateError):
                    bridge._decode_template(raw)

    def test_emitter_binds_full_target_sites_and_graph(self) -> None:
        kernel = bridge.NativeKernel(
            ordinal="01",
            name="test",
            target=tuple(bytes.fromhex("4c89a5d0ffffff4c8ba5d0ffffff")),
            target_bytes=14,
            error_offset=14,
            save_start=0,
            shadow_displacement=-48,
            sites=(
                bridge.NativeSite(
                    2, 1, 7, "X86SemanticStorePhysical 9%nat false"
                ),
            ),
            restore_starts=(7,),
        )
        output = bridge.emit_rocq([kernel], "a" * 64, "b" * 64)
        self.assertIn("Definition wp8e_kernel_01_target : list nat", output)
        self.assertIn("X86SemanticStorePhysical 9%nat false", output)
        self.assertIn("wp8c_kernel_01_control_graph", output)
        self.assertIn("target_bytes_are_bounded", output)
        self.assertIn("function_bytes_cover_residency_graph", output)


if __name__ == "__main__":
    unittest.main()
