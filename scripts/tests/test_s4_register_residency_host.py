from __future__ import annotations

import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_host.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8i_host_observation_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
host = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = host
SPEC.loader.exec_module(host)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest() == host.lt1.APACHE_HASH
)
FACT_VALUES = {
    "kernel-system": "Linux",
    "kernel-release": "6.12.1",
    "machine": "x86_64",
    "cpu-vendor": "GenuineIntel",
    "cpu-family": "6",
    "cpu-model": "154",
    "cpu-stepping": "3",
    "microcode": "0x123",
    "logical-cpu": "2",
    "affinity-mask": "2",
    "governor": "performance",
    "turbo-control": "intel-pstate-no-turbo",
    "turbo-value": "1",
    "monotonic-implementation": "clock_gettime(CLOCK_MONOTONIC)",
    "git-commit": "0123456789abcdef0123456789abcdef01234567",
}


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8I observation tests require the current Apache-2.0 surface",
)
class RegisterResidencyHostObservationTests(unittest.TestCase):
    @staticmethod
    def _observation(
        refusals: tuple[str, ...] = (),
        facts: tuple[tuple[str, str], ...] | None = None,
        fingerprint: str | None = None,
    ) -> object:
        selected = facts or tuple(
            (name, FACT_VALUES[name]) for _ordinal, name in host.wp6.CONTRACT_FACTS
        )
        fact_body = b"".join(f"fact\t{name}\t{value}\n".encode() for name, value in selected)
        actual_fingerprint = fingerprint or hashlib.sha256(
            host.wp6.FINGERPRINT_DOMAIN + fact_body
        ).hexdigest()
        return host.wp6.HostObservation(selected, refusals, actual_fingerprint)

    def test_eligible_observation_is_ephemeral_and_not_a_claim(self) -> None:
        admission = host.validate(ROOT)
        report = host.observation_report(admission, self._observation()).decode()
        self.assertIn("host-status\teligible-ephemeral-observation\n", report)
        self.assertIn("role\tnaux-register-residency-candidate\n", report)
        self.assertIn("claim-status\tnot-admitted\n", report)
        self.assertIn("timing-status\tforbidden\n", report)
        self.assertIn("refusals\t0\n", report)

    def test_ineligible_observation_retains_exact_refusal_order(self) -> None:
        admission = host.validate(ROOT)
        refusals = (
            "multi-cpu-or-offline-affinity",
            "missing-or-enabled-turbo-control",
        )
        report = host.observation_report(admission, self._observation(refusals)).decode()
        self.assertIn("host-status\tineligible-observation\n", report)
        self.assertIn("refusal\t04\tmulti-cpu-or-offline-affinity\n", report)
        self.assertIn("refusal\t06\tmissing-or-enabled-turbo-control\n", report)

    def test_fact_schema_or_fingerprint_mutation_fails_closed(self) -> None:
        observation = self._observation()
        with self.assertRaisesRegex(host.CandidateHostError, "fact schema"):
            host._verify_observation(
                self._observation(facts=observation.facts[:-1])
            )
        with self.assertRaisesRegex(host.CandidateHostError, "fingerprint"):
            host._verify_observation(self._observation(fingerprint="0" * 64))

    def test_unknown_duplicate_or_reordered_refusal_fails_closed(self) -> None:
        for refusals in (
            ("unknown-refusal",),
            ("commit-mismatch", "commit-mismatch"),
            ("commit-mismatch", "unsupported-platform"),
        ):
            with self.subTest(refusals=refusals):
                with self.assertRaisesRegex(host.CandidateHostError, "refusal schema"):
                    host._verify_observation(self._observation(refusals))

    def test_observation_report_is_deterministic(self) -> None:
        admission = host.validate(ROOT)
        observation = self._observation()
        self.assertEqual(
            host.observation_report(admission, observation),
            host.observation_report(admission, observation),
        )


if __name__ == "__main__":
    unittest.main()
