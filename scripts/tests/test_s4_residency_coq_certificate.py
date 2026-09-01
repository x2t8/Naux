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


if __name__ == "__main__":
    unittest.main()
