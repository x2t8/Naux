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
        self.assertEqual(len(kernel.result_record), 48)
        self.assertEqual(kernel.result_record[:8], tuple(b"NAUX5E01"))
        self.assertEqual(kernel.oracle, 7)
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
            [kernel],
            "a" * 64,
            "b" * 64,
            "c" * 64,
            "d" * 64,
            "e" * 64,
            "f" * 64,
            "g" * 64,
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
        self.assertIn("ResidencyResultProtocol", output)
        self.assertIn("expected_result_protocol_decodes", output)
        self.assertIn("expected_result_protocol_is_well_formed", output)
        self.assertIn("WP8G replay report root: " + "e" * 64, output)
        self.assertIn("WP8H role replay report root: " + "f" * 64, output)
        self.assertIn("WP8I static host report root: " + "g" * 64, output)
        self.assertIn("ResidencyCandidateRole", output)
        self.assertIn("ResidencyControlledHost", output)
        self.assertIn("candidate_role_is_admitted", output)
        self.assertIn("candidate_role_is_isolated", output)
        self.assertIn("candidate_role_is_untimed", output)
        self.assertIn("candidate_role_retains_baseline", output)
        self.assertIn("static_host_boundary_is_admitted", output)
        self.assertIn("static_host_has_no_observation", output)
        self.assertIn("static_host_is_not_measurement_ready", output)
        self.assertIn("static_host_has_no_performance_claim", output)
        self.assertIn("x86 execution, Linux loading", output)

    def test_host_report_is_bound_to_exact_static_wp8i_boundary(self) -> None:
        admission = bridge.wp8i.validate(ROOT)
        evidence = bridge.parse_authenticated_host_report(
            admission.static_report, admission
        )
        self.assertEqual(evidence.report_root, admission.static_root)

    def test_host_report_rejects_resealed_observation_drift(self) -> None:
        admission = bridge.wp8i.validate(ROOT)
        lines = admission.static_report.splitlines(keepends=True)
        body = b"".join(lines[:-1]).replace(
            b"host-status\tnot-observed\n",
            b"host-status\teligible-ephemeral-observation\n",
            1,
        )
        resealed = body + (
            "report-root\t"
            + hashlib.sha256(bridge.wp8i.REPORT_DOMAIN + body).hexdigest()
            + "\n"
        ).encode()
        with self.assertRaisesRegex(
            bridge.ProcessCertificateError, "metadata drifted"
        ):
            bridge.parse_authenticated_host_report(resealed, admission)

    def test_replay_report_is_exactly_bound_to_two_passes(self) -> None:
        candidate, _ = self.fixture()
        record = candidate.kernels[0].record
        contract = bridge.wp8g.Contract((record,), "a" * 64)
        authority = bridge.wp8g.Authority((), "b" * 64)
        admission = bridge.wp8g.Admission(contract, authority, b"", "c" * 64)
        results = tuple(
            bridge.wp8g.ProcessResult(
                pass_number,
                record.ordinal,
                record.name,
                record.oracle,
                record.expected_outer,
                record.expected_inner,
                0,
            )
            for pass_number in (1, 2)
        )
        raw = bridge.wp8g._report(contract, authority, candidate, results)
        evidence = bridge.parse_authenticated_replay_report(
            raw, admission, candidate
        )
        self.assertEqual(evidence.results, results)
        self.assertEqual(len(evidence.report_root), 64)

    def test_replay_report_rejects_coherently_resealed_value_drift(self) -> None:
        candidate, _ = self.fixture()
        record = candidate.kernels[0].record
        contract = bridge.wp8g.Contract((record,), "a" * 64)
        authority = bridge.wp8g.Authority((), "b" * 64)
        admission = bridge.wp8g.Admission(contract, authority, b"", "c" * 64)
        drifted = tuple(
            bridge.wp8g.ProcessResult(
                pass_number,
                record.ordinal,
                record.name,
                record.oracle + 1,
                record.expected_outer,
                record.expected_inner,
                0,
            )
            for pass_number in (1, 2)
        )
        raw = bridge.wp8g._report(contract, authority, candidate, drifted)
        with self.assertRaisesRegex(
            bridge.ProcessCertificateError, "identity or value drifted"
        ):
            bridge.parse_authenticated_replay_report(raw, admission, candidate)

    def test_role_report_is_bound_to_exact_wp8g_replay(self) -> None:
        candidate, _ = self.fixture()
        record = candidate.kernels[0].record
        contract = bridge.wp8g.Contract((record,), "a" * 64)
        authority = bridge.wp8g.Authority((), "b" * 64)
        process_admission = bridge.wp8g.Admission(
            contract, authority, b"", "c" * 64
        )
        results = tuple(
            bridge.wp8g.ProcessResult(
                pass_number,
                record.ordinal,
                record.name,
                record.oracle,
                record.expected_outer,
                record.expected_inner,
                0,
            )
            for pass_number in (1, 2)
        )
        process_raw = bridge.wp8g._report(
            contract, authority, candidate, results
        )
        process_evidence = bridge.parse_authenticated_replay_report(
            process_raw, process_admission, candidate
        )
        role_admission = bridge.wp8h.validate(ROOT)
        role_raw = bridge.wp8h._report(
            role_admission.contract,
            role_admission.authority,
            results,
            process_raw,
        )
        evidence = bridge.parse_authenticated_role_report(
            role_raw, role_admission, process_raw, process_evidence
        )
        self.assertEqual(len(evidence.report_root), 64)

    def test_role_report_rejects_coherently_resealed_role_drift(self) -> None:
        candidate, _ = self.fixture()
        record = candidate.kernels[0].record
        contract = bridge.wp8g.Contract((record,), "a" * 64)
        authority = bridge.wp8g.Authority((), "b" * 64)
        process_admission = bridge.wp8g.Admission(
            contract, authority, b"", "c" * 64
        )
        results = tuple(
            bridge.wp8g.ProcessResult(
                pass_number,
                record.ordinal,
                record.name,
                record.oracle,
                record.expected_outer,
                record.expected_inner,
                0,
            )
            for pass_number in (1, 2)
        )
        process_raw = bridge.wp8g._report(
            contract, authority, candidate, results
        )
        process_evidence = bridge.parse_authenticated_replay_report(
            process_raw, process_admission, candidate
        )
        role_admission = bridge.wp8h.validate(ROOT)
        role_raw = bridge.wp8h._report(
            role_admission.contract,
            role_admission.authority,
            results,
            process_raw,
        )
        lines = role_raw.splitlines(keepends=True)
        body = b"".join(lines[:-1]).replace(
            b"timing-status\tforbidden\n",
            b"timing-status\tpermitted\n",
            1,
        )
        resealed = body + (
            "report-root\t"
            + hashlib.sha256(bridge.wp8h.REPORT_DOMAIN + body).hexdigest()
            + "\n"
        ).encode()
        with self.assertRaisesRegex(
            bridge.ProcessCertificateError, "metadata drifted"
        ):
            bridge.parse_authenticated_role_report(
                resealed, role_admission, process_raw, process_evidence
            )

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
