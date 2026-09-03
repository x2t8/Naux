from __future__ import annotations

import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residency_timing_coq_certificate.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "s4_residency_timing_coq_certificate_test", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)


class S4ResidencyTimingCoqCertificateTests(unittest.TestCase):
    @staticmethod
    def fixture():
        target = b"exact-wp8g-process"
        prefix = b"".join(
            (
                b"\x90" * 3,
                bridge.START_CLOCK_MARKER,
                b"\x90" * 5,
                bridge.END_CLOCK_MARKER,
                b"\x90" * 7,
                bridge.ROLE_FOUR_OWNER_MARKER,
                b"\x90" * 11,
            )
        )
        image = prefix + target
        timing_record = SimpleNamespace(
            ordinal=1,
            name="test",
            target_bytes=len(target),
            target_hash=hashlib.sha256(target).hexdigest(),
            elf_bytes=len(image),
            elf_hash=hashlib.sha256(image).hexdigest(),
            target_offset=len(prefix),
        )
        process_record = SimpleNamespace(ordinal=1, name="test")
        timing_candidate = bridge.wp8j.Candidate(
            (bridge.wp8j.Kernel(timing_record, target, image),), b"timing\n"
        )
        process_candidate = bridge.wp8g.Candidate(
            (SimpleNamespace(record=process_record, process=target),), b"process\n"
        )
        return timing_candidate, process_candidate

    def test_join_binds_exact_process_and_extracts_marker_offsets(self) -> None:
        timing, process = self.fixture()
        kernel = bridge.join_authenticated_carrier(timing, process)[0]
        self.assertEqual(kernel.ordinal, "01")
        self.assertEqual(kernel.start_clock_offset, 3)
        self.assertLess(kernel.start_clock_offset, kernel.end_clock_offset)
        self.assertLess(kernel.end_clock_offset, kernel.owner_offset)
        self.assertLess(kernel.owner_offset, kernel.target_offset)
        self.assertEqual(kernel.elf_bytes, len(kernel.prefix) + len(b"exact-wp8g-process"))

    def test_join_rejects_target_drift_and_extra_clock_marker(self) -> None:
        timing, process = self.fixture()
        drifted_process = bridge.wp8g.Candidate(
            (
                SimpleNamespace(
                    record=process.kernels[0].record,
                    process=b"different-wp8g-process",
                ),
            ),
            b"process\n",
        )
        with self.assertRaisesRegex(
            bridge.TimingCertificateError, "not the exact WP8G process"
        ):
            bridge.join_authenticated_carrier(timing, drifted_process)

        kernel = timing.kernels[0]
        prefix = kernel.elf[: kernel.record.target_offset] + bridge.START_CLOCK_MARKER
        image = prefix + kernel.target
        record = SimpleNamespace(
            **{
                **vars(kernel.record),
                "elf_bytes": len(image),
                "elf_hash": hashlib.sha256(image).hexdigest(),
                "target_offset": len(prefix),
            }
        )
        malformed = bridge.wp8j.Candidate(
            (bridge.wp8j.Kernel(record, kernel.target, image),), b"timing\n"
        )
        with self.assertRaisesRegex(
            bridge.TimingCertificateError, "clock or role-owner placement drifted"
        ):
            bridge.join_authenticated_carrier(malformed, process)

    def test_exact_replay_report_is_authenticated_fail_closed(self) -> None:
        admission = bridge.wp8j.validate(ROOT)
        candidate = bridge.wp8j.Candidate((), b"fixture\n")
        report, root = bridge.wp8j._report(
            admission.contract, admission.authority, candidate
        )
        evidence = bridge.parse_authenticated_timing_report(
            report, admission, candidate
        )
        self.assertEqual(evidence.report_root, root)

        body = report.rsplit(b"report-root\t", 1)[0].replace(
            b"execution-status\tforbidden\n",
            b"execution-status\tpermitted\n",
            1,
        )
        mutated = body + (
            "report-root\t"
            + hashlib.sha256(bridge.wp8j.REPORT_DOMAIN + body).hexdigest()
            + "\n"
        ).encode()
        with self.assertRaisesRegex(
            bridge.TimingCertificateError, "metadata drifted"
        ):
            bridge.parse_authenticated_timing_report(mutated, admission, candidate)

    def test_emitter_exposes_only_the_closed_wp8j_boundary(self) -> None:
        timing, process = self.fixture()
        kernel = bridge.join_authenticated_carrier(timing, process)[0]
        output = bridge.emit_rocq(
            [kernel], "a" * 64, "b" * 64, "c" * 64, "d" * 64
        )
        self.assertIn("ResidencyTimingCarrier", output)
        self.assertIn("GeneratedWP8GProcessKernel01", output)
        self.assertIn("wp8g_kernel_01_process", output)
        self.assertIn("timing_image_extent", output)
        self.assertIn("clock_marker_count_check", output)
        self.assertIn("carrier_is_admitted", output)
        self.assertIn("contains_exact_process", output)
        self.assertIn("is_not_runnable", output)
        self.assertIn("has_no_performance_claim", output)
        self.assertNotIn("ResidencyCarrierExecutionPermitted", output)
        self.assertNotIn("ResidencyPerformanceClaimPermitted", output)


if __name__ == "__main__":
    unittest.main()
