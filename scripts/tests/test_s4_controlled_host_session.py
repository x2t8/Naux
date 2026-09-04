# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts/s4_controlled_host_session.py"
SPEC = importlib.util.spec_from_file_location("s4_controlled_host_session", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
session = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = session
SPEC.loader.exec_module(session)


BOOT_ID = "01234567-89ab-cdef-0123-456789abcdef"


class ControlledHostFixture:
    def __init__(self, base: Path, governor: str = "powersave", turbo: str = "0") -> None:
        self.root = base / "sysfs"
        self.boot_id = base / "boot_id"
        self.receipt = base / "session.tsv"
        controls = self.root / "cpu2/cpufreq"
        controls.mkdir(parents=True)
        (controls / "scaling_governor").write_text(governor, encoding="ascii")
        (controls / "scaling_available_governors").write_text(
            "powersave performance", encoding="ascii"
        )
        turbo_dir = self.root / "intel_pstate"
        turbo_dir.mkdir()
        (turbo_dir / "no_turbo").write_text(turbo, encoding="ascii")
        self.boot_id.write_text(BOOT_ID + "\n", encoding="ascii")

    @property
    def governor(self) -> Path:
        return self.root / "cpu2/cpufreq/scaling_governor"

    @property
    def turbo(self) -> Path:
        return self.root / "intel_pstate/no_turbo"


class ControlledHostSessionTests(unittest.TestCase):
    def test_status_reports_both_control_states(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = ControlledHostFixture(Path(raw))
            snapshot = session.observe(
                2, sysfs_root=fixture.root, boot_id_path=fixture.boot_id
            )
            self.assertFalse(session.is_controlled(snapshot))
            report = session.status_report(snapshot).decode("ascii")
            self.assertIn("governor\tpowersave\n", report)
            self.assertIn("turbo-kind\tintel-pstate-no-turbo\n", report)
            self.assertIn("turbo-value\t0\n", report)
            self.assertTrue(report.endswith("controlled\tno\n"))

    def test_prepare_and_restore_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = ControlledHostFixture(Path(raw))
            snapshot = session.prepare(
                2,
                fixture.receipt,
                sysfs_root=fixture.root,
                boot_id_path=fixture.boot_id,
                require_root=False,
            )
            self.assertEqual(snapshot.governor_before, "powersave")
            self.assertEqual(fixture.governor.read_text(encoding="ascii"), "performance")
            self.assertEqual(fixture.turbo.read_text(encoding="ascii"), "1")
            self.assertEqual(stat.S_IMODE(fixture.receipt.stat().st_mode), 0o600)
            self.assertIn("receipt-root\t", fixture.receipt.read_text(encoding="ascii"))

            restored = session.restore(
                fixture.receipt,
                sysfs_root=fixture.root,
                boot_id_path=fixture.boot_id,
                require_root=False,
            )
            self.assertEqual(restored, snapshot)
            self.assertEqual(fixture.governor.read_text(encoding="ascii"), "powersave")
            self.assertEqual(fixture.turbo.read_text(encoding="ascii"), "0")

    def test_cpufreq_boost_fallback_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = ControlledHostFixture(Path(raw))
            fixture.turbo.unlink()
            fixture.turbo.parent.rmdir()
            boost = fixture.root / "cpufreq/boost"
            boost.parent.mkdir()
            boost.write_text("1", encoding="ascii")

            snapshot = session.prepare(
                2,
                fixture.receipt,
                sysfs_root=fixture.root,
                boot_id_path=fixture.boot_id,
                require_root=False,
            )
            self.assertEqual(snapshot.turbo, session.CPUFREQ_BOOST)
            self.assertEqual(boost.read_text(encoding="ascii"), "0")
            session.restore(
                fixture.receipt,
                sysfs_root=fixture.root,
                boot_id_path=fixture.boot_id,
                require_root=False,
            )
            self.assertEqual(boost.read_text(encoding="ascii"), "1")

    def test_prepare_refuses_non_root_before_observation_or_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = ControlledHostFixture(Path(raw))
            with mock.patch.object(session.os, "geteuid", return_value=1000):
                with self.assertRaisesRegex(session.HostSessionError, "requires root"):
                    session.prepare(
                        2,
                        fixture.receipt,
                        sysfs_root=fixture.root,
                        boot_id_path=fixture.boot_id,
                    )
            self.assertFalse(fixture.receipt.exists())
            self.assertEqual(fixture.governor.read_text(encoding="ascii"), "powersave")
            self.assertEqual(fixture.turbo.read_text(encoding="ascii"), "0")

    def test_existing_receipt_refuses_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = ControlledHostFixture(Path(raw))
            fixture.receipt.write_text("owned\n", encoding="ascii")
            with self.assertRaisesRegex(session.HostSessionError, "already exists"):
                session.prepare(
                    2,
                    fixture.receipt,
                    sysfs_root=fixture.root,
                    boot_id_path=fixture.boot_id,
                    require_root=False,
                )
            self.assertEqual(fixture.governor.read_text(encoding="ascii"), "powersave")
            self.assertEqual(fixture.turbo.read_text(encoding="ascii"), "0")

    def test_failed_prepare_rolls_back_after_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = ControlledHostFixture(Path(raw))
            real_write = session._write_control

            def fail_turbo(root: Path, path: Path, value: str, label: str) -> None:
                if path == session.INTEL_TURBO.relative_path and value == "1":
                    raise session.HostSessionError("injected turbo refusal")
                real_write(root, path, value, label)

            with mock.patch.object(session, "_write_control", side_effect=fail_turbo):
                with self.assertRaisesRegex(
                    session.HostSessionError, "restore receipt retained"
                ):
                    session.prepare(
                        2,
                        fixture.receipt,
                        sysfs_root=fixture.root,
                        boot_id_path=fixture.boot_id,
                        require_root=False,
                    )
            self.assertTrue(fixture.receipt.is_file())
            self.assertEqual(fixture.governor.read_text(encoding="ascii"), "powersave")
            self.assertEqual(fixture.turbo.read_text(encoding="ascii"), "0")

    def test_failed_post_write_observation_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = ControlledHostFixture(Path(raw))
            snapshot = session.observe(
                2, sysfs_root=fixture.root, boot_id_path=fixture.boot_id
            )
            with mock.patch.object(
                session,
                "observe",
                side_effect=[snapshot, session.HostSessionError("injected observation")],
            ):
                with self.assertRaisesRegex(
                    session.HostSessionError, "injected observation"
                ):
                    session.prepare(
                        2,
                        fixture.receipt,
                        sysfs_root=fixture.root,
                        boot_id_path=fixture.boot_id,
                        require_root=False,
                    )
            self.assertTrue(fixture.receipt.is_file())
            self.assertEqual(fixture.governor.read_text(encoding="ascii"), "powersave")
            self.assertEqual(fixture.turbo.read_text(encoding="ascii"), "0")

    def test_tampered_receipt_cannot_restore(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = ControlledHostFixture(Path(raw))
            session.prepare(
                2,
                fixture.receipt,
                sysfs_root=fixture.root,
                boot_id_path=fixture.boot_id,
                require_root=False,
            )
            payload = fixture.receipt.read_text(encoding="ascii")
            fixture.receipt.write_text(
                payload.replace("governor-before\tpowersave", "governor-before\tondemand"),
                encoding="ascii",
            )
            fixture.receipt.chmod(0o600)
            with self.assertRaisesRegex(session.HostSessionError, "root mismatch"):
                session.restore(
                    fixture.receipt,
                    sysfs_root=fixture.root,
                    boot_id_path=fixture.boot_id,
                    require_root=False,
                )
            self.assertEqual(fixture.governor.read_text(encoding="ascii"), "performance")
            self.assertEqual(fixture.turbo.read_text(encoding="ascii"), "1")

    def test_receipt_cannot_cross_boot_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = ControlledHostFixture(Path(raw))
            session.prepare(
                2,
                fixture.receipt,
                sysfs_root=fixture.root,
                boot_id_path=fixture.boot_id,
                require_root=False,
            )
            fixture.boot_id.write_text(
                "fedcba98-7654-3210-fedc-ba9876543210\n", encoding="ascii"
            )
            with self.assertRaisesRegex(session.HostSessionError, "different boot"):
                session.restore(
                    fixture.receipt,
                    sysfs_root=fixture.root,
                    boot_id_path=fixture.boot_id,
                    require_root=False,
                )

    def test_symlinked_control_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = ControlledHostFixture(Path(raw))
            target = Path(raw) / "outside-governor"
            target.write_text("powersave", encoding="ascii")
            fixture.governor.unlink()
            fixture.governor.symlink_to(target)
            with self.assertRaisesRegex(session.HostSessionError, "direct regular"):
                session.observe(2, sysfs_root=fixture.root, boot_id_path=fixture.boot_id)

    def test_symlinked_receipt_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = ControlledHostFixture(Path(raw))
            snapshot = session.observe(
                2, sysfs_root=fixture.root, boot_id_path=fixture.boot_id
            )
            target = Path(raw) / "actual-receipt.tsv"
            target.write_bytes(session._receipt_bytes(snapshot))
            target.chmod(0o600)
            fixture.receipt.symlink_to(target)
            with self.assertRaisesRegex(session.HostSessionError, "direct regular"):
                session.restore(
                    fixture.receipt,
                    sysfs_root=fixture.root,
                    boot_id_path=fixture.boot_id,
                    require_root=False,
                )

    def test_helper_never_spawns_privilege_or_benchmark_commands(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("import subprocess", source)
        self.assertNotIn("os.system(", source)
        self.assertNotIn("os.popen(", source)
        self.assertIn("os.geteuid()", source)
        self.assertIn("os.O_EXCL", source)
        self.assertIn('getattr(os, "O_NOFOLLOW", 0)', source)

    def test_group_readable_receipt_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = ControlledHostFixture(Path(raw))
            session.prepare(
                2,
                fixture.receipt,
                sysfs_root=fixture.root,
                boot_id_path=fixture.boot_id,
                require_root=False,
            )
            fixture.receipt.chmod(0o640)
            with self.assertRaisesRegex(session.HostSessionError, "group or others"):
                session.restore(
                    fixture.receipt,
                    sysfs_root=fixture.root,
                    boot_id_path=fixture.boot_id,
                    require_root=False,
                )


if __name__ == "__main__":
    unittest.main()
