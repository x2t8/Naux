#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residency_coq_certificate.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "s4_residency_coq_certificate_test", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)


class S4ResidencyCoqCertificateTests(unittest.TestCase):
    def test_physical_actions_preserve_exact_virtual_operands(self) -> None:
        self.assertEqual(
            bridge._physical_action(
                [
                    "instruction",
                    "01",
                    "2",
                    "1",
                    "store-physical",
                    "r12",
                    "r8:i64",
                    "consume",
                ]
            ),
            "StoreHome 9%nat",
        )
        self.assertEqual(
            bridge._physical_action(
                [
                    "instruction",
                    "01",
                    "3",
                    "0",
                    "load-physical",
                    "r12:i64",
                    "r12",
                ]
            ),
            "LoadHome 13%nat",
        )
        self.assertEqual(
            bridge._physical_action(
                [
                    "instruction",
                    "01",
                    "4",
                    "0",
                    "add-physical-const",
                    "r12",
                    "-7",
                ]
            ),
            "UpdateHome (AddConst (-7%Z))",
        )

    def test_physical_and_virtual_r12_namespaces_do_not_alias(self) -> None:
        self.assertEqual(bridge._virtual_i64_register("r12:i64", "register"), 13)
        self.assertEqual(bridge._coq_nat(0), "0%nat")
        self.assertNotEqual(
            bridge._virtual_i64_register("r12:i64", "register"), 0
        )

    def test_signed_i64_parser_is_canonical_and_bounded(self) -> None:
        self.assertEqual(bridge._signed_i64("0", "integer"), 0)
        self.assertEqual(bridge._signed_i64(str(-(1 << 63)), "integer"), -(1 << 63))
        self.assertEqual(
            bridge._signed_i64(str((1 << 63) - 1), "integer"), (1 << 63) - 1
        )
        for raw in (
            "-0",
            "+1",
            "01",
            str(1 << 63),
            str(-(1 << 63) - 1),
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(bridge.CertificateError):
                    bridge._signed_i64(raw, "integer")

    def test_malformed_or_non_i64_virtual_registers_fail_closed(self) -> None:
        for raw in ("r1:bool", "r01:i64", "r1", "r-1:i64", "x1:i64"):
            with self.subTest(raw=raw):
                with self.assertRaises(bridge.CertificateError):
                    bridge._virtual_i64_register(raw, "register")

    def test_store_ownership_mode_is_checked(self) -> None:
        with self.assertRaises(bridge.CertificateError):
            bridge._physical_action(
                [
                    "instruction",
                    "01",
                    "2",
                    "1",
                    "store-physical",
                    "r12",
                    "r8:i64",
                    "borrow",
                ]
            )

    def test_scalar_actions_preserve_exact_operands_and_constants(self) -> None:
        cases = (
            (
                ["instruction", "01", "0", "0", "const-i64", "r3:i64", "-7"],
                "ScalarConst 4%nat (-7%Z)",
            ),
            (
                ["instruction", "01", "0", "0", "load-slot", "r3:i64", "s5"],
                "ScalarLoadSlot 4%nat 5%nat",
            ),
            (
                [
                    "instruction",
                    "01",
                    "0",
                    "0",
                    "store-slot",
                    "s5",
                    "r3:i64",
                    "keep",
                ],
                "ScalarStoreSlot 5%nat 4%nat",
            ),
            (
                ["instruction", "01", "0", "0", "add-slot-const", "s5", "17"],
                "ScalarAddSlotConst 5%nat (17%Z)",
            ),
            (
                [
                    "instruction",
                    "01",
                    "0",
                    "0",
                    "i64-mul",
                    "r3:i64",
                    "r1:i64",
                    "r2:i64",
                ],
                "ScalarBinary 4%nat ScalarMul 2%nat 3%nat",
            ),
            (
                [
                    "instruction",
                    "01",
                    "0",
                    "0",
                    "i64-ge",
                    "r3:bool",
                    "r1:i64",
                    "r2:i64",
                ],
                "ScalarCompare 4%nat ScalarGe 2%nat 3%nat",
            ),
        )
        for row, expected in cases:
            with self.subTest(opcode=row[4]):
                self.assertEqual(bridge._scalar_action(row), expected)

    def test_heap_operations_are_explicitly_outside_scalar_projection(self) -> None:
        self.assertIsNone(
            bridge._scalar_action(
                [
                    "instruction",
                    "01",
                    "0",
                    "0",
                    "list-load-checked",
                    "r3:i64",
                    "r1:owned-list-i64",
                    "r2:i64",
                ]
            )
        )
        with self.assertRaises(bridge.CertificateError):
            bridge._scalar_action(
                [
                    "instruction",
                    "01",
                    "0",
                    "0",
                    "i64-div",
                    "r3:i64",
                    "r1:i64",
                    "r2:i64",
                ]
            )

    def test_kernel_home_slot_and_scalar_graph_are_emitted(self) -> None:
        report = "\n".join(
            (
                "NAUX-S4-REGISTER-RESIDENCY-PLAN\t1",
                "kernel\t01\ttest\ta\tb\t8\ts5\ti64\tr12\t3\t2\t1",
                "block\t01\t0\t1",
                "instruction\t01\t0\t0\tconst-i64\tr3:i64\t-7",
                "terminator\t01\t0\treturn\tr3:i64",
            )
        )
        kernels = bridge.parse_verified_report(report.encode("utf-8"))
        self.assertEqual(kernels[0].home_slot, 5)
        output = bridge.emit_rocq(kernels, "0" * 64)
        self.assertIn("Definition wp8c_kernel_01_scalar_graph", output)
        self.assertIn("ScalarPassThrough (ScalarConst 4%nat (-7%Z))", output)
        self.assertIn("scalar_residency_baseline_execute 5%nat", output)


if __name__ == "__main__":
    unittest.main()
