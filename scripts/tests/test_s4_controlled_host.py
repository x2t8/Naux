#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_controlled_host.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_controlled_host_observe", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
host = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = host
SPEC.loader.exec_module(host)
COMMIT = "0123456789abcdef0123456789abcdef01234567"
CPU_FACTS = {
    "vendor_id": "GenuineIntel",
    "cpu family": "6",
    "model": "154",
    "stepping": "3",
    "microcode": "0x123",
}


class S4ControlledHostObservationTests(unittest.TestCase):
    def _observe(
        self,
        *,
        affinity: set[int] = {2},
        online: str = "0-7",
        governor: str = "performance",
        turbo: tuple[str, str, bool] = ("intel-pstate-no-turbo", "1", True),
        commit: tuple[str, bool] = (COMMIT, True),
        expected_commit: str | None = COMMIT,
        clock_monotonic: bool = True,
    ) -> object:
        uname = SimpleNamespace(sysname="Linux", release="6.12.1", machine="x86_64")

        def read_small(path: Path) -> str | None:
            if path == Path("/sys/devices/system/cpu/online"):
                return online
            if path.name == "scaling_governor":
                return governor
            return None

        clock = SimpleNamespace(
            monotonic=clock_monotonic,
            implementation="clock_gettime(CLOCK_MONOTONIC)",
        )
        with (
            mock.patch.object(host.os, "uname", return_value=uname),
            mock.patch.object(host.os, "sched_getaffinity", return_value=affinity),
            mock.patch.object(host, "_read_small", side_effect=read_small),
            mock.patch.object(host, "_cpu_facts", return_value=CPU_FACTS),
            mock.patch.object(host, "_turbo_fact", return_value=turbo),
            mock.patch.object(host, "_git_facts", return_value=commit),
            mock.patch.object(host.time, "get_clock_info", return_value=clock),
        ):
            return host.observe(ROOT, expected_commit)

    def test_exact_controlled_facts_are_eligible_but_not_a_claim(self) -> None:
        observation = self._observe()
        self.assertTrue(observation.eligible)
        self.assertEqual(observation.refusals, ())
        admission = host.validate(ROOT)
        report = host.observation_report(admission, observation).decode()
        self.assertIn("host-status\teligible-ephemeral-observation\n", report)
        self.assertIn("claim-status\tnot-admitted\n", report)
        self.assertIn("timing-status\tforbidden\n", report)

    def test_multi_cpu_affinity_is_refused(self) -> None:
        observation = self._observe(affinity={2, 3})
        self.assertIn("multi-cpu-or-offline-affinity", observation.refusals)

    def test_governor_and_turbo_fail_closed(self) -> None:
        observation = self._observe(
            governor="powersave",
            turbo=("intel-pstate-no-turbo", "0", False),
        )
        self.assertIn("missing-or-nonperformance-governor", observation.refusals)
        self.assertIn("missing-or-enabled-turbo-control", observation.refusals)

    def test_dirty_or_wrong_commit_is_refused(self) -> None:
        observation = self._observe(commit=(COMMIT, False), expected_commit="f" * 40)
        self.assertIn("dirty-or-unborn-repository", observation.refusals)
        self.assertIn("commit-mismatch", observation.refusals)

    def test_nonmonotonic_capability_is_refused_without_sampling(self) -> None:
        observation = self._observe(clock_monotonic=False)
        self.assertIn("nonmonotonic-or-unavailable-clock", observation.refusals)

    def test_observation_report_is_deterministic(self) -> None:
        admission = host.validate(ROOT)
        observation = self._observe()
        self.assertEqual(
            host.observation_report(admission, observation),
            host.observation_report(admission, observation),
        )


if __name__ == "__main__":
    unittest.main()
