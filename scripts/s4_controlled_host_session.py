#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare and restore the two mutable CPU controls required by S4.

The default mode is read-only.  ``--prepare`` and ``--restore`` are explicit,
root-only operations.  This helper never invokes sudo, reads a password, runs a
benchmark, or produces performance evidence.  A sealed pre-mutation receipt is
required so the original host state can be restored after the measurement.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shlex
import stat
import sys
from dataclasses import dataclass
from pathlib import Path


STATUS_MAGIC = "NAUX-S4-CONTROLLED-HOST-SESSION-STATUS\t1"
RECEIPT_MAGIC = "NAUX-S4-CONTROLLED-HOST-SESSION\t1"
RECEIPT_DOMAIN = b"NAUX:s4-controlled-host-session:v1\0"
SYSFS_CPU_ROOT = Path("/sys/devices/system/cpu")
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
MAX_CONTROL_BYTES = 128
MAX_RECEIPT_BYTES = 4096
MAX_CPU = 4095
SAFE_VALUE_RE = re.compile(r"[A-Za-z0-9_.:+-]+")
BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


class HostSessionError(RuntimeError):
    """A fail-closed controlled-host session error."""


@dataclass(frozen=True)
class TurboControl:
    kind: str
    relative_path: Path
    disabled_value: str


@dataclass(frozen=True)
class HostSnapshot:
    cpu: int
    boot_id: str
    governor_path: Path
    governor_before: str
    turbo: TurboControl
    turbo_before: str


INTEL_TURBO = TurboControl(
    kind="intel-pstate-no-turbo",
    relative_path=Path("intel_pstate/no_turbo"),
    disabled_value="1",
)
CPUFREQ_BOOST = TurboControl(
    kind="cpufreq-boost",
    relative_path=Path("cpufreq/boost"),
    disabled_value="0",
)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _validate_cpu(cpu: int) -> int:
    if cpu < 0 or cpu > MAX_CPU:
        raise HostSessionError(f"CPU index must be between 0 and {MAX_CPU}")
    return cpu


def _validate_value(value: str, label: str) -> str:
    if not SAFE_VALUE_RE.fullmatch(value):
        raise HostSessionError(f"{label} contains an unsafe or empty value")
    return value


def _open_control(root: Path, relative_path: Path, flags: int, label: str) -> int:
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise HostSessionError(f"{label} path escaped the CPU control root")
    path = root / relative_path
    try:
        before = path.lstat()
    except OSError as error:
        raise HostSessionError(f"cannot inspect {label} at {path}: {error}") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise HostSessionError(f"{label} is not a direct regular control file: {path}")
    open_flags = flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, open_flags)
    except OSError as error:
        raise HostSessionError(f"cannot open {label} at {path}: {error}") from error
    try:
        after = os.fstat(descriptor)
    except OSError as error:
        os.close(descriptor)
        raise HostSessionError(f"cannot inspect open {label} at {path}: {error}") from error
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        os.close(descriptor)
        raise HostSessionError(f"{label} changed while it was opened: {path}")
    return descriptor


def _read_control_line(root: Path, relative_path: Path, label: str) -> str:
    descriptor = _open_control(root, relative_path, os.O_RDONLY, label)
    try:
        payload = _read_bounded_descriptor(descriptor, MAX_CONTROL_BYTES, label)
    finally:
        os.close(descriptor)
    try:
        decoded = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise HostSessionError(f"{label} is not ASCII") from error
    value = decoded.strip()
    if decoded not in (value, f"{value}\n"):
        raise HostSessionError(f"{label} is not canonical single-line text")
    if not value:
        raise HostSessionError(f"{label} is empty")
    return value


def _read_bounded_descriptor(descriptor: int, limit: int, label: str) -> bytes:
    payload = bytearray()
    while len(payload) <= limit:
        try:
            chunk = os.read(descriptor, min(4096, limit + 1 - len(payload)))
        except OSError as error:
            raise HostSessionError(f"cannot read {label}: {error}") from error
        if not chunk:
            break
        payload.extend(chunk)
    if len(payload) > limit:
        raise HostSessionError(f"{label} exceeds {limit} bytes")
    return bytes(payload)


def _read_control(root: Path, relative_path: Path, label: str) -> str:
    return _validate_value(_read_control_line(root, relative_path, label), label)


def _write_control(root: Path, relative_path: Path, value: str, label: str) -> None:
    value = _validate_value(value, label)
    descriptor = _open_control(root, relative_path, os.O_WRONLY | os.O_TRUNC, label)
    payload = value.encode("ascii")
    try:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise HostSessionError(f"short write while changing {label}")
            written += count
    except OSError as error:
        raise HostSessionError(f"cannot change {label}: {error}") from error
    finally:
        os.close(descriptor)
    observed = _read_control(root, relative_path, label)
    if observed != value:
        raise HostSessionError(
            f"{label} verification failed: expected {value}, observed {observed}"
        )


def _read_boot_id(path: Path) -> str:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise HostSessionError(f"cannot read boot identity at {path}: {error}") from error
    if len(payload) > MAX_CONTROL_BYTES:
        raise HostSessionError("boot identity is oversized")
    try:
        decoded = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise HostSessionError("boot identity is not ASCII") from error
    value = decoded.strip()
    if decoded not in (value, f"{value}\n") or not BOOT_ID_RE.fullmatch(value):
        raise HostSessionError("boot identity is not a canonical lowercase UUID")
    return value


def _governor_path(cpu: int) -> Path:
    return Path(f"cpu{_validate_cpu(cpu)}/cpufreq/scaling_governor")


def _require_performance_governor(root: Path, cpu: int) -> None:
    available = Path(f"cpu{cpu}/cpufreq/scaling_available_governors")
    if not (root / available).exists():
        return
    value = _read_control_line(root, available, "available governor list")
    governors = value.split(" ")
    if any(not item or not SAFE_VALUE_RE.fullmatch(item) for item in governors):
        raise HostSessionError("available governor list is not canonical")
    if "performance" not in governors:
        raise HostSessionError(f"CPU {cpu} does not expose the performance governor")


def _resolve_turbo(root: Path) -> TurboControl:
    for control in (INTEL_TURBO, CPUFREQ_BOOST):
        if (root / control.relative_path).exists():
            value = _read_control(root, control.relative_path, "turbo control")
            if value not in ("0", "1"):
                raise HostSessionError(
                    f"{control.kind} must contain 0 or 1, observed {value}"
                )
            return control
    raise HostSessionError("no supported Intel no_turbo or cpufreq boost control exists")


def observe(
    cpu: int,
    *,
    sysfs_root: Path = SYSFS_CPU_ROOT,
    boot_id_path: Path = BOOT_ID_PATH,
) -> HostSnapshot:
    cpu = _validate_cpu(cpu)
    governor_path = _governor_path(cpu)
    governor = _read_control(sysfs_root, governor_path, f"CPU {cpu} governor")
    turbo = _resolve_turbo(sysfs_root)
    turbo_value = _read_control(sysfs_root, turbo.relative_path, "turbo control")
    return HostSnapshot(
        cpu=cpu,
        boot_id=_read_boot_id(boot_id_path),
        governor_path=governor_path,
        governor_before=governor,
        turbo=turbo,
        turbo_before=turbo_value,
    )


def is_controlled(snapshot: HostSnapshot) -> bool:
    return (
        snapshot.governor_before == "performance"
        and snapshot.turbo_before == snapshot.turbo.disabled_value
    )


def status_report(snapshot: HostSnapshot) -> bytes:
    rows = (
        STATUS_MAGIC,
        f"cpu\t{snapshot.cpu}",
        f"boot-id\t{snapshot.boot_id}",
        f"governor-path\t{snapshot.governor_path.as_posix()}",
        f"governor\t{snapshot.governor_before}",
        f"turbo-kind\t{snapshot.turbo.kind}",
        f"turbo-path\t{snapshot.turbo.relative_path.as_posix()}",
        f"turbo-value\t{snapshot.turbo_before}",
        f"controlled\t{'yes' if is_controlled(snapshot) else 'no'}",
    )
    return ("\n".join(rows) + "\n").encode()


def _receipt_bytes(snapshot: HostSnapshot) -> bytes:
    rows = (
        RECEIPT_MAGIC,
        f"cpu\t{snapshot.cpu}",
        f"boot-id\t{snapshot.boot_id}",
        f"governor-path\t{snapshot.governor_path.as_posix()}",
        f"governor-before\t{snapshot.governor_before}",
        "governor-controlled\tperformance",
        f"turbo-kind\t{snapshot.turbo.kind}",
        f"turbo-path\t{snapshot.turbo.relative_path.as_posix()}",
        f"turbo-before\t{snapshot.turbo_before}",
        f"turbo-controlled\t{snapshot.turbo.disabled_value}",
    )
    body = ("\n".join(rows) + "\n").encode()
    return body + f"receipt-root\t{_sha256(RECEIPT_DOMAIN + body)}\n".encode()


def _validate_receipt_target(path: Path) -> None:
    if not path.is_absolute():
        raise HostSessionError("receipt path must be absolute")
    if any(ord(character) < 32 or ord(character) == 127 for character in str(path)):
        raise HostSessionError("receipt path contains a control character")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise HostSessionError(f"receipt parent is unavailable: {error}") from error
    if parent != path.parent or not parent.is_dir():
        raise HostSessionError("receipt parent must be a direct existing directory")
    if path.exists() or path.is_symlink():
        raise HostSessionError(f"receipt already exists; refusing to overwrite: {path}")


def _write_receipt(path: Path, payload: bytes) -> None:
    _validate_receipt_target(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise HostSessionError(f"cannot create receipt {path}: {error}") from error
    try:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise HostSessionError("short write while creating session receipt")
            written += count
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise HostSessionError("session receipt is not a regular file after creation")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise HostSessionError("session receipt permissions drifted from 0600")
    except BaseException:
        os.close(descriptor)
        try:
            path.unlink()
        except OSError:
            pass
        raise
    os.close(descriptor)


def _parse_receipt(path: Path) -> HostSnapshot:
    if not path.is_absolute():
        raise HostSessionError("receipt path must be absolute")
    if any(ord(character) < 32 or ord(character) == 127 for character in str(path)):
        raise HostSessionError("receipt path contains a control character")
    try:
        before = path.lstat()
    except OSError as error:
        raise HostSessionError(f"cannot inspect receipt {path}: {error}") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise HostSessionError("session receipt must be a direct regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise HostSessionError(f"cannot open receipt {path}: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise HostSessionError("session receipt changed while it was opened")
        if not stat.S_ISREG(opened.st_mode):
            raise HostSessionError("session receipt must be a direct regular file")
        if hasattr(os, "geteuid") and opened.st_uid != os.geteuid():
            raise HostSessionError("session receipt is not owned by the current user")
        if stat.S_IMODE(opened.st_mode) & 0o077:
            raise HostSessionError(
                "session receipt must not be readable by group or others"
            )
        if opened.st_size <= 0 or opened.st_size > MAX_RECEIPT_BYTES:
            raise HostSessionError("session receipt has invalid extent")
        payload = _read_bounded_descriptor(
            descriptor, MAX_RECEIPT_BYTES, "session receipt"
        )
        after = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(opened, field) != getattr(after, field) for field in stable_fields):
            raise HostSessionError("session receipt changed while it was read")
        if len(payload) != opened.st_size:
            raise HostSessionError("session receipt extent changed while it was read")
    finally:
        os.close(descriptor)
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise HostSessionError("session receipt is not ASCII") from error
    if not text.endswith("\n") or "\r" in text or "\n\n" in text:
        raise HostSessionError("session receipt is not canonical LF text")
    lines = text.splitlines()
    if len(lines) != 11 or lines[0] != RECEIPT_MAGIC:
        raise HostSessionError("session receipt has an unexpected schema")
    expected_keys = (
        "cpu",
        "boot-id",
        "governor-path",
        "governor-before",
        "governor-controlled",
        "turbo-kind",
        "turbo-path",
        "turbo-before",
        "turbo-controlled",
    )
    fields: dict[str, str] = {}
    for line, key in zip(lines[1:10], expected_keys, strict=True):
        parts = line.split("\t")
        if len(parts) != 2 or parts[0] != key:
            raise HostSessionError(f"session receipt expected field {key}")
        fields[key] = parts[1]
    root_parts = lines[10].split("\t")
    if len(root_parts) != 2 or root_parts[0] != "receipt-root":
        raise HostSessionError("session receipt root is missing")
    body = ("\n".join(lines[:10]) + "\n").encode()
    if root_parts[1] != _sha256(RECEIPT_DOMAIN + body):
        raise HostSessionError("session receipt root mismatch")
    try:
        cpu = int(fields["cpu"], 10)
    except ValueError as error:
        raise HostSessionError("session receipt CPU is invalid") from error
    cpu = _validate_cpu(cpu)
    governor_path = _governor_path(cpu)
    if fields["governor-path"] != governor_path.as_posix():
        raise HostSessionError("session receipt governor path drifted")
    governor_before = _validate_value(fields["governor-before"], "saved governor")
    if fields["governor-controlled"] != "performance":
        raise HostSessionError("session receipt controlled governor drifted")
    turbo_by_kind = {control.kind: control for control in (INTEL_TURBO, CPUFREQ_BOOST)}
    turbo = turbo_by_kind.get(fields["turbo-kind"])
    if turbo is None:
        raise HostSessionError("session receipt turbo kind is unsupported")
    if fields["turbo-path"] != turbo.relative_path.as_posix():
        raise HostSessionError("session receipt turbo path drifted")
    turbo_before = fields["turbo-before"]
    if turbo_before not in ("0", "1"):
        raise HostSessionError("session receipt saved turbo value is invalid")
    if fields["turbo-controlled"] != turbo.disabled_value:
        raise HostSessionError("session receipt controlled turbo value drifted")
    boot_id = fields["boot-id"]
    if not BOOT_ID_RE.fullmatch(boot_id):
        raise HostSessionError("session receipt boot identity is invalid")
    return HostSnapshot(
        cpu=cpu,
        boot_id=boot_id,
        governor_path=governor_path,
        governor_before=governor_before,
        turbo=turbo,
        turbo_before=turbo_before,
    )


def _require_root(require_root: bool) -> None:
    if require_root and (not hasattr(os, "geteuid") or os.geteuid() != 0):
        raise HostSessionError(
            "host mutation requires root; rerun explicitly with sudo "
            "(the helper never reads or stores a password)"
        )


def _restore_snapshot(sysfs_root: Path, snapshot: HostSnapshot) -> list[str]:
    failures: list[str] = []
    for path, value, label in (
        (snapshot.turbo.relative_path, snapshot.turbo_before, "turbo control"),
        (snapshot.governor_path, snapshot.governor_before, f"CPU {snapshot.cpu} governor"),
    ):
        try:
            _write_control(sysfs_root, path, value, label)
        except HostSessionError as error:
            failures.append(str(error))
    return failures


def prepare(
    cpu: int,
    receipt: Path,
    *,
    sysfs_root: Path = SYSFS_CPU_ROOT,
    boot_id_path: Path = BOOT_ID_PATH,
    require_root: bool = True,
) -> HostSnapshot:
    _require_root(require_root)
    snapshot = observe(cpu, sysfs_root=sysfs_root, boot_id_path=boot_id_path)
    _require_performance_governor(sysfs_root, snapshot.cpu)
    _write_receipt(receipt, _receipt_bytes(snapshot))
    try:
        _write_control(
            sysfs_root,
            snapshot.governor_path,
            "performance",
            f"CPU {snapshot.cpu} governor",
        )
        _write_control(
            sysfs_root,
            snapshot.turbo.relative_path,
            snapshot.turbo.disabled_value,
            "turbo control",
        )
        controlled = observe(
            snapshot.cpu, sysfs_root=sysfs_root, boot_id_path=boot_id_path
        )
        if not is_controlled(controlled):
            raise HostSessionError("host controls did not remain stable")
    except HostSessionError as error:
        rollback_failures = _restore_snapshot(sysfs_root, snapshot)
        suffix = f"; restore receipt retained at {receipt}"
        if rollback_failures:
            suffix += "; rollback also failed: " + "; ".join(rollback_failures)
        raise HostSessionError(f"host preparation failed: {error}{suffix}") from error
    return snapshot


def restore(
    receipt: Path,
    *,
    sysfs_root: Path = SYSFS_CPU_ROOT,
    boot_id_path: Path = BOOT_ID_PATH,
    require_root: bool = True,
) -> HostSnapshot:
    _require_root(require_root)
    snapshot = _parse_receipt(receipt)
    if _read_boot_id(boot_id_path) != snapshot.boot_id:
        raise HostSessionError("receipt belongs to a different boot session")
    current_turbo = _resolve_turbo(sysfs_root)
    if current_turbo != snapshot.turbo:
        raise HostSessionError("live turbo control differs from the session receipt")
    failures = _restore_snapshot(sysfs_root, snapshot)
    if failures:
        raise HostSessionError("host restoration failed: " + "; ".join(failures))
    restored = observe(
        snapshot.cpu, sysfs_root=sysfs_root, boot_id_path=boot_id_path
    )
    if (
        restored.governor_before != snapshot.governor_before
        or restored.turbo_before != snapshot.turbo_before
    ):
        raise HostSessionError("restored host state does not match the session receipt")
    return snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--status", action="store_true", help="inspect controls (default)")
    modes.add_argument("--prepare", action="store_true", help="apply controlled values")
    modes.add_argument("--restore", action="store_true", help="restore a sealed session")
    parser.add_argument("--cpu", type=int, help="logical CPU for status or prepare")
    parser.add_argument("--receipt", type=Path, help="absolute receipt path")
    arguments = parser.parse_args()
    try:
        if arguments.restore:
            if arguments.cpu is not None:
                parser.error("--cpu cannot be used with --restore; the receipt binds it")
            if arguments.receipt is None:
                parser.error("--restore requires --receipt")
            snapshot = restore(arguments.receipt)
            sys.stdout.write(
                f"restored\tcpu{snapshot.cpu}\t{snapshot.governor_before}\t"
                f"{snapshot.turbo.kind}:{snapshot.turbo_before}\n"
            )
            return 0
        cpu = 2 if arguments.cpu is None else arguments.cpu
        if arguments.prepare:
            if arguments.receipt is None:
                parser.error("--prepare requires --receipt")
            snapshot = prepare(cpu, arguments.receipt)
            sys.stdout.write(
                f"prepared\tcpu{snapshot.cpu}\tperformance\t"
                f"{snapshot.turbo.kind}:{snapshot.turbo.disabled_value}\n"
                "restore-with\t"
                f"{shlex.quote(sys.executable)} {shlex.quote(str(Path(__file__).resolve()))} "
                f"--restore --receipt {shlex.quote(str(arguments.receipt))}\n"
            )
            return 0
        if arguments.receipt is not None:
            parser.error("--receipt requires --prepare or --restore")
        sys.stdout.buffer.write(status_report(observe(cpu)))
        return 0
    except (HostSessionError, OSError, ValueError) as error:
        print(f"S4 controlled-host session failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
