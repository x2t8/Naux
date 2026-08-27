#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_measurement_evidence.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_measurement_evidence_replay", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)

CARRIER = "1" * 64
HOST = "2" * 64
RUNNER = "3" * 64
COMMIT = "4" * 40


def candidate_bytes(
    admission: object,
    *,
    variable: bool = False,
    mutate_sample: bool = False,
    reorder: bool = False,
) -> bytes:
    rows = [
        evidence.EVIDENCE_MAGIC,
        f"meta\tcontract\t{admission.contract.seal}",
        f"meta\tevidence-law-authority\t{admission.authority.seal}",
        f"meta\tcarrier-authority\t{CARRIER}",
        f"meta\thost-attestation\t{HOST}",
        f"meta\trunner-authority\t{RUNNER}",
        f"meta\tsource-commit\t{COMMIT}",
        "meta\tclock-source\tclock-monotonic-raw",
        "meta\truntime-region\tallocation-initialization-kernel-checksum-validation-teardown",
        "meta\tsample-policy\tordered-complete-no-drop-no-retry",
        "meta\tsample-count\t30",
        "meta\tclaim-status\tnot-admitted",
    ]
    for ordinal, name, status in evidence.ROLES:
        rows.append(f"role\t{ordinal}\t{name}\t{ordinal * 32}\t{ordinal[1] * 64}\t{status}")
    rows.extend(
        (
            "cost\t01\t1000\t500\t200\t4096\t1024",
            "cost\t02\t1100\t0\t210\t4096\t2048",
            "cost\t03\t1200\t0\t220\t4096\t2048",
        )
    )
    for role, _name, status in evidence.ROLES:
        for kernel, _kernel_name, oracle in evidence.KERNELS:
            rows.append(f"warmup\t{role}\t{kernel}\t100000000\t{oracle}\t{status}")
    groups: dict[tuple[str, str], tuple[int, ...]] = {}
    for role, _name, status in evidence.ROLES:
        for kernel, _kernel_name, oracle in evidence.KERNELS:
            base = 1_000_000 + int(role) * 10_000 + int(kernel) * 100
            durations = tuple(
                base + (index * 500_000 if variable else index % 3)
                for index in range(1, 31)
            )
            groups[(role, kernel)] = durations
            for index, duration in enumerate(durations, 1):
                checksum = oracle + 1 if mutate_sample and role == "01" and kernel == "01" and index == 1 else oracle
                rows.append(f"sample\t{role}\t{kernel}\t{index:02}\t{duration}\t{checksum}\t{status}")
    if reorder:
        first = next(index for index, row in enumerate(rows) if row.startswith("sample\t"))
        rows[first], rows[first + 1] = rows[first + 1], rows[first]
    for role, _name, _status in evidence.ROLES:
        for kernel, _kernel_name, _oracle in evidence.KERNELS:
            stat = evidence.derive_statistic(role, kernel, groups[(role, kernel)])
            rows.append(
                f"stat\t{role}\t{kernel}\t{stat.median_num}\t{stat.median_den}\t{stat.p95}"
                f"\t{stat.cv2_num}\t{stat.cv2_den}\t{'pass' if stat.stable else 'fail'}"
            )
    body = b"".join(f"{row}\n".encode() for row in rows)
    return body + f"evidence-root\t{hashlib.sha256(evidence.EVIDENCE_DOMAIN + body).hexdigest()}\n".encode()


class S4MeasurementEvidenceReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.admission = evidence.validate(ROOT)

    def replay(self, raw: bytes) -> object:
        return evidence.replay_candidate(
            raw,
            self.admission,
            carrier_authority=CARRIER,
            host_attestation=HOST,
            runner_authority=RUNNER,
        )

    def test_exact_ordered_candidate_replays_without_admitting_a_claim(self) -> None:
        raw = candidate_bytes(self.admission)
        candidate = self.replay(raw)
        self.assertTrue(candidate.variance_gate)
        self.assertEqual(len(candidate.statistics), 12)
        self.assertEqual(candidate.evidence_root, raw.decode().rsplit("\t", 1)[1].strip())

    def test_high_variance_is_retained_and_fails_variance_gate(self) -> None:
        candidate = self.replay(candidate_bytes(self.admission, variable=True))
        self.assertFalse(candidate.variance_gate)
        self.assertTrue(any(not statistic.stable for statistic in candidate.statistics))

    def test_checksum_mutation_is_rejected_even_when_resealed(self) -> None:
        with self.assertRaises(evidence.EvidenceError):
            self.replay(candidate_bytes(self.admission, mutate_sample=True))

    def test_sample_reordering_is_rejected_even_when_resealed(self) -> None:
        with self.assertRaises(evidence.EvidenceError):
            self.replay(candidate_bytes(self.admission, reorder=True))

    def test_derived_statistic_mutation_is_rejected_even_when_resealed(self) -> None:
        raw = candidate_bytes(self.admission)
        lines = raw.decode().splitlines()
        index = next(i for i, row in enumerate(lines) if row.startswith("stat\t"))
        fields = lines[index].split("\t")
        fields[5] = str(int(fields[5]) + 1)
        lines[index] = "\t".join(fields)
        body = "".join(f"{line}\n" for line in lines[:-1]).encode()
        lines[-1] = f"evidence-root\t{hashlib.sha256(evidence.EVIDENCE_DOMAIN + body).hexdigest()}"
        with self.assertRaises(evidence.EvidenceError):
            self.replay(("\n".join(lines) + "\n").encode())

    def test_authority_substitution_is_rejected(self) -> None:
        with self.assertRaises(evidence.EvidenceError):
            evidence.replay_candidate(
                candidate_bytes(self.admission),
                self.admission,
                carrier_authority="9" * 64,
                host_attestation=HOST,
                runner_authority=RUNNER,
            )


if __name__ == "__main__":
    unittest.main()
