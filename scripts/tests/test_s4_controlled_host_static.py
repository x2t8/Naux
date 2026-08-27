#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_controlled_host.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_controlled_host_static", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
host = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = host
SPEC.loader.exec_module(host)


class S4ControlledHostStaticTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(
            body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode()
        )

    def test_static_protocol_is_deterministic_and_admits_no_host(self) -> None:
        first = host.validate(ROOT)
        second = host.validate(ROOT)
        self.assertEqual(first, second)
        text = first.static_report.decode()
        self.assertIn("protocol-status\tcontrolled-host-protocol-admitted\n", text)
        self.assertIn("host-status\tnot-observed\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)
        self.assertIn("timing-status\tforbidden\n", text)

    def test_contract_mutation_fails_after_coherent_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp6-contract-") as directory:
            path = Path(directory) / "WP6-HOST.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP6-HOST.tsv", path)
            path.write_text(
                path.read_text().replace("selected-cpu-performance", "selected-cpu-powersave", 1)
            )
            self._reseal(path, host.CONTRACT_DOMAIN)
            with self.assertRaises(host.HostControlError):
                host.parse_contract(path)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = host.parse_contract(
            ROOT / "distribution/s4-performance/WP6-HOST.tsv"
        )
        authority = host.parse_authority(
            ROOT / "distribution/s4-performance/WP6-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp6-files-") as directory:
            root = Path(directory)
            for relative in host.EXPECTED_FILES:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = root / "distribution/s4-performance/WP6-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(host.HostControlError):
                host._verify_files(root, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP6-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(host.HostControlError):
                host._verify_files(root, authority)

    def test_source_contains_no_clock_sample_call(self) -> None:
        source = SCRIPT.read_text()
        forbidden = (
            "." + "monotonic(",
            "." + "perf_counter(",
            "." + "time_ns(",
            "." + "clock_gettime(",
        )
        self.assertFalse(any(token in source for token in forbidden))

    def test_cpu_list_parser_is_exact(self) -> None:
        self.assertEqual(host._parse_cpu_set("0-2,5,8-9"), {0, 1, 2, 5, 8, 9})
        for malformed in ("", "2-1", "1,,2", "x", "1-99999"):
            with self.subTest(value=malformed):
                with self.assertRaises(host.HostControlError):
                    host._parse_cpu_set(malformed)


if __name__ == "__main__":
    unittest.main()
