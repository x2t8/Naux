#!/usr/bin/env python3
"""Validate and observe the clock-free S4 controlled-host preflight."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import s4_residual_role_admission as wp5f


CONTRACT_MAGIC = "NAUX-S4-CONTROLLED-HOST-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-CONTROLLED-HOST-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-CONTROLLED-HOST-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-controlled-host:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-controlled-host:authority:v1\0"
FINGERPRINT_DOMAIN = b"NAUX:s4-controlled-host:fingerprint:v1\0"
REPORT_DOMAIN = b"NAUX:s4-controlled-host:report:v1\0"
WP4_AUTHORITY_SEAL = "bda4409f32e1afe162b68401529d127cf4a77077df000826823d2660ee4ade26"
WP5F_AUTHORITY_SEAL = "1d85ad923f5db2eb520cee9d3582bbc97f63b711c67d5d4b44d5859fb0fa92bd"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")

CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-measurement-boundary", WP4_AUTHORITY_SEAL),
    ("parent-role-admission", WP5F_AUTHORITY_SEAL),
    ("protocol-status", "controlled-host-protocol-admitted"),
    ("host-status", "runtime-attestation-required"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("attestation", "canonical-stdout-only"),
    ("fingerprint", "sha256-canonical-host-facts"),
    ("clock-policy", "capability-inspection-only-no-sample"),
)
CONTRACT_REQUIREMENTS = (
    ("01", "platform", "exact", "linux-x86_64"),
    ("02", "source-state", "exact", "clean-detached-or-branch-head"),
    ("03", "commit", "exact", "caller-supplied-lower-hex40"),
    ("04", "affinity", "exact", "single-online-logical-cpu"),
    ("05", "governor", "exact", "selected-cpu-performance"),
    ("06", "turbo", "exact", "disabled-by-supported-kernel-control"),
    ("07", "clock", "exact", "monotonic-clock-gettime-capability"),
    ("08", "identity", "exact", "stable-cpu-kernel-host-fingerprint"),
)
CONTRACT_FACTS = (
    ("01", "kernel-system"),
    ("02", "kernel-release"),
    ("03", "machine"),
    ("04", "cpu-vendor"),
    ("05", "cpu-family"),
    ("06", "cpu-model"),
    ("07", "cpu-stepping"),
    ("08", "microcode"),
    ("09", "logical-cpu"),
    ("10", "affinity-mask"),
    ("11", "governor"),
    ("12", "turbo-control"),
    ("13", "turbo-value"),
    ("14", "monotonic-implementation"),
    ("15", "git-commit"),
)
CONTRACT_REFUSALS = (
    ("01", "unsupported-platform"),
    ("02", "dirty-or-unborn-repository"),
    ("03", "commit-mismatch"),
    ("04", "multi-cpu-or-offline-affinity"),
    ("05", "missing-or-nonperformance-governor"),
    ("06", "missing-or-enabled-turbo-control"),
    ("07", "nonmonotonic-or-unavailable-clock"),
    ("08", "missing-cpu-fingerprint-fact"),
)
CONTRACT_CLOSURES = (("01", "naux-residual-unavailable", "wp5f-local-role-authority"),)
CONTRACT_BLOCKERS = (
    ("01", "controlled-host-attestation-unavailable"),
    ("02", "measurement-runner-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP6"),
    ("authority-id", "s4-controlled-host-protocol-v1"),
    ("protocol-status", "controlled-host-protocol-admitted"),
    ("host-status", "runtime-attestation-required"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-controlled-host.yml",
    "distribution/s4-performance/WP6-HOST.tsv",
    "distribution/s4-performance/WP6-NONCLAIMS.md",
    "distribution/s4-performance/WP6-README.md",
    "scripts/s4_controlled_host.py",
    "scripts/tests/test_s4_controlled_host.py",
    "scripts/tests/test_s4_controlled_host_static.py",
)
CPU_FACT_KEYS = ("vendor_id", "cpu family", "model", "stepping", "microcode")
TURBO_CONTROLS = (
    ("intel-pstate-no-turbo", Path("/sys/devices/system/cpu/intel_pstate/no_turbo"), "1"),
    ("cpufreq-boost", Path("/sys/devices/system/cpu/cpufreq/boost"), "0"),
)


class HostControlError(RuntimeError):
    """A fail-closed S4-WP6 host-control error."""


@dataclass(frozen=True)
class Contract:
    seal: str


@dataclass(frozen=True)
class FileRecord:
    mode: int
    size: int
    sha256: str
    path: str


@dataclass(frozen=True)
class Authority:
    files: tuple[FileRecord, ...]
    seal: str


@dataclass(frozen=True)
class Admission:
    contract: Contract
    authority: Authority
    static_report: bytes
    static_root: str


@dataclass(frozen=True)
class HostObservation:
    facts: tuple[tuple[str, str], ...]
    refusals: tuple[str, ...]
    fingerprint: str

    @property
    def eligible(self) -> bool:
        return not self.refusals


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(raw: bytes, label: str, maximum: int = 131_072) -> list[str]:
    if not raw or len(raw) > maximum or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise HostControlError(f"{label} has invalid extent or encoding")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HostControlError(f"{label} is not UTF-8") from error
    lines = text.splitlines()
    if any(not line for line in lines):
        raise HostControlError(f"{label} contains a blank row")
    return lines


def _sealed_lines(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise HostControlError(f"{path.name} is not a regular file")
    raw = path.read_bytes()
    lines = _canonical(raw, path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise HostControlError(f"{path.name} shape or magic drifted")
    fields = lines[-1].split("\t")
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise HostControlError(f"{path.name} seal row is malformed")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if _sha256(domain + body) != fields[1]:
        raise HostControlError(f"{path.name} seal verification failed")
    return lines, fields[1]


def parse_contract(path: Path) -> Contract:
    lines, seal = _sealed_lines(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    index = 1

    def rows(tag: str, width: int) -> list[tuple[str, ...]]:
        nonlocal index
        result: list[tuple[str, ...]] = []
        while index < len(lines) - 1 and lines[index].startswith(f"{tag}\t"):
            fields = lines[index].split("\t")
            if len(fields) != width:
                raise HostControlError(f"WP6 {tag} row is malformed")
            result.append(tuple(fields[1:]))
            index += 1
        return result

    if tuple(rows("meta", 3)) != CONTRACT_METADATA:
        raise HostControlError("WP6 contract metadata drifted")
    if tuple(rows("requirement", 5)) != CONTRACT_REQUIREMENTS:
        raise HostControlError("WP6 requirement set drifted")
    if tuple(rows("fact", 3)) != CONTRACT_FACTS:
        raise HostControlError("WP6 fact set drifted")
    if tuple(rows("refusal", 3)) != CONTRACT_REFUSALS:
        raise HostControlError("WP6 refusal set drifted")
    if tuple(rows("closure", 4)) != CONTRACT_CLOSURES:
        raise HostControlError("WP6 closure set drifted")
    if tuple(rows("blocker", 3)) != CONTRACT_BLOCKERS or index != len(lines) - 1:
        raise HostControlError("WP6 blocker set or extent drifted")
    return Contract(seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    lines, seal = _sealed_lines(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    index = 1
    metadata: list[tuple[str, str]] = []
    while index < len(lines) - 1 and lines[index].startswith("meta\t"):
        fields = lines[index].split("\t")
        if len(fields) != 3:
            raise HostControlError("WP6 authority metadata is malformed")
        metadata.append((fields[1], fields[2]))
        index += 1
    if tuple(metadata) != AUTHORITY_METADATA:
        raise HostControlError("WP6 authority metadata drifted")
    expected_links = (
        f"component\thost-contract\tdistribution/s4-performance/WP6-HOST.tsv\t{contract_seal}",
        f"parent\tmeasurement-boundary-authority\tdistribution/s4-performance/WP4-AUTHORITY.tsv\t{WP4_AUTHORITY_SEAL}",
        f"parent\tresidual-role-admission-authority\tdistribution/s4-performance/WP5F-AUTHORITY.tsv\t{WP5F_AUTHORITY_SEAL}",
    )
    if tuple(lines[index : index + 3]) != expected_links:
        raise HostControlError("WP6 component or parent binding drifted")
    index += 3
    files: list[FileRecord] = []
    while index < len(lines) - 1:
        fields = lines[index].split("\t")
        if (
            len(fields) != 6
            or fields[0] != "file"
            or not MODE_RE.fullmatch(fields[1])
            or not UINT_RE.fullmatch(fields[2])
            or not HASH_RE.fullmatch(fields[3])
            or not PATH_RE.fullmatch(fields[4])
            or fields[5] != "host-protocol"
        ):
            raise HostControlError("WP6 authority file row is malformed")
        files.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
        index += 1
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise HostControlError("WP6 authority file inventory drifted")
    return Authority(tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise HostControlError(f"WP6 bound file is not regular: {record.path}")
        raw = path.read_bytes()
        mode = stat.S_IFREG | stat.S_IMODE(metadata.st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise HostControlError(f"WP6 bound file drifted: {record.path}")


def _verify_source_boundary(root: Path) -> None:
    workflow = (root / ".github/workflows/s4-controlled-host.yml").read_text()
    for token in ("scripts/s4_controlled_host.py", "test_s4_controlled_host"):
        if token not in workflow:
            raise HostControlError("WP6 workflow omits a static gate")
    source = (root / "scripts/s4_controlled_host.py").read_text()
    forbidden_calls = (
        "." + "monotonic(",
        "." + "perf_counter(",
        "." + "time_ns(",
        "." + "clock_gettime(",
    )
    if any(token in source for token in forbidden_calls):
        raise HostControlError("WP6 source collects a clock sample")
    expected = {"WP6-AUTHORITY.tsv", "WP6-HOST.tsv", "WP6-NONCLAIMS.md", "WP6-README.md"}
    actual = {
        path.name
        for path in (root / "distribution/s4-performance").glob("WP6-*")
        if path.is_file()
    }
    if actual != expected:
        raise HostControlError("unexpected WP6 distribution artifact")


def _static_report(contract: Contract, authority: Authority) -> bytes:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"parent-role-admission\t{WP5F_AUTHORITY_SEAL}",
        "protocol-status\tcontrolled-host-protocol-admitted",
        "host-status\tnot-observed",
        "claim-status\tnot-admitted",
        "timing-status\tforbidden",
        "mode\tstatic-authority",
        "requirements\t8",
        "blockers\t2",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    return body + f"report-root\t{_sha256(REPORT_DOMAIN + body)}\n".encode()


def validate(root: Path) -> Admission:
    root = root.resolve()
    role = wp5f.validate(root)
    if role.authority.seal != WP5F_AUTHORITY_SEAL:
        raise HostControlError("WP5F parent authority drifted")
    boundary = wp5f.wp5e.wp5d.wp5c.wp5b.wp5a.wp5.wp4.validate(root)
    if boundary.authority.seal != WP4_AUTHORITY_SEAL:
        raise HostControlError("WP4 parent authority drifted")
    contract = parse_contract(root / "distribution/s4-performance/WP6-HOST.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/WP6-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    _verify_source_boundary(root)
    report = _static_report(contract, authority)
    report_root = report.decode().split("report-root\t", 1)[1].strip()
    return Admission(contract, authority, report, report_root)


def _safe_fact(value: str, label: str) -> str:
    value = value.strip()
    if not value or len(value.encode()) > 256 or "\t" in value or "\n" in value or "\r" in value:
        raise HostControlError(f"invalid host fact: {label}")
    return value


def _read_small(path: Path) -> str | None:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4096:
            return None
        return path.read_text().strip()
    except OSError:
        return None


def _parse_cpu_set(text: str) -> set[int]:
    cpus: set[int] = set()
    for part in text.strip().split(","):
        if not part:
            raise HostControlError("empty CPU-list component")
        bounds = part.split("-", 1)
        if any(not UINT_RE.fullmatch(value) for value in bounds):
            raise HostControlError("malformed CPU-list component")
        start = int(bounds[0])
        end = int(bounds[-1])
        if end < start or end - start > 4096:
            raise HostControlError("invalid CPU-list range")
        cpus.update(range(start, end + 1))
    return cpus


def _cpu_facts(cpu: int) -> dict[str, str]:
    raw = Path("/proc/cpuinfo").read_text()
    blocks = [block for block in raw.split("\n\n") if block.strip()]
    for block in blocks:
        facts: dict[str, str] = {}
        for line in block.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            facts[key.strip()] = value.strip()
        if facts.get("processor") == str(cpu):
            return facts
    return {}


def _git_facts(root: Path) -> tuple[str, bool]:
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "LANG": "C"}
    commit = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    if commit.returncode != 0 or status.returncode != 0:
        return "unavailable", False
    value = commit.stdout.decode("ascii", errors="strict").strip()
    if not COMMIT_RE.fullmatch(value):
        return "unavailable", False
    return value, not status.stdout


def _turbo_fact() -> tuple[str, str, bool]:
    for name, path, disabled in TURBO_CONTROLS:
        value = _read_small(path)
        if value is not None:
            return name, value, value == disabled
    return "unavailable", "unavailable", False


def observe(root: Path, expected_commit: str | None) -> HostObservation:
    refusals: set[str] = set()
    uname = os.uname()
    if uname.sysname != "Linux" or uname.machine != "x86_64":
        refusals.add("unsupported-platform")

    affinity = set(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else set()
    cpu = next(iter(affinity)) if len(affinity) == 1 else -1
    online_raw = _read_small(Path("/sys/devices/system/cpu/online"))
    try:
        online = _parse_cpu_set(online_raw) if online_raw is not None else set()
    except HostControlError:
        online = set()
    if cpu < 0 or cpu not in online:
        refusals.add("multi-cpu-or-offline-affinity")

    cpuinfo = _cpu_facts(cpu) if cpu >= 0 else {}
    if any(not cpuinfo.get(key) for key in CPU_FACT_KEYS):
        refusals.add("missing-cpu-fingerprint-fact")

    governor = (
        _read_small(Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor"))
        if cpu >= 0
        else None
    )
    if governor != "performance":
        refusals.add("missing-or-nonperformance-governor")

    turbo_control, turbo_value, turbo_disabled = _turbo_fact()
    if not turbo_disabled:
        refusals.add("missing-or-enabled-turbo-control")

    clock = time.get_clock_info("monotonic")
    if not clock.monotonic or "CLOCK_MONOTONIC" not in clock.implementation:
        refusals.add("nonmonotonic-or-unavailable-clock")

    commit, clean = _git_facts(root)
    if not clean:
        refusals.add("dirty-or-unborn-repository")
    if expected_commit is None or not COMMIT_RE.fullmatch(expected_commit) or commit != expected_commit:
        refusals.add("commit-mismatch")

    facts = (
        ("kernel-system", _safe_fact(uname.sysname, "kernel-system")),
        ("kernel-release", _safe_fact(uname.release, "kernel-release")),
        ("machine", _safe_fact(uname.machine, "machine")),
        ("cpu-vendor", _safe_fact(cpuinfo.get("vendor_id", "unavailable"), "cpu-vendor")),
        ("cpu-family", _safe_fact(cpuinfo.get("cpu family", "unavailable"), "cpu-family")),
        ("cpu-model", _safe_fact(cpuinfo.get("model", "unavailable"), "cpu-model")),
        ("cpu-stepping", _safe_fact(cpuinfo.get("stepping", "unavailable"), "cpu-stepping")),
        ("microcode", _safe_fact(cpuinfo.get("microcode", "unavailable"), "microcode")),
        ("logical-cpu", str(cpu) if cpu >= 0 else "unavailable"),
        ("affinity-mask", ",".join(str(value) for value in sorted(affinity)) or "unavailable"),
        ("governor", _safe_fact(governor or "unavailable", "governor")),
        ("turbo-control", turbo_control),
        ("turbo-value", _safe_fact(turbo_value, "turbo-value")),
        ("monotonic-implementation", _safe_fact(clock.implementation, "clock")),
        ("git-commit", commit),
    )
    fact_body = b"".join(f"fact\t{key}\t{value}\n".encode() for key, value in facts)
    fingerprint = _sha256(FINGERPRINT_DOMAIN + fact_body)
    ordered_refusals = tuple(name for _, name in CONTRACT_REFUSALS if name in refusals)
    return HostObservation(facts, ordered_refusals, fingerprint)


def observation_report(admission: Admission, observation: HostObservation) -> bytes:
    rows = [
        REPORT_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        "protocol-status\tcontrolled-host-protocol-admitted",
        f"host-status\t{'eligible-ephemeral-observation' if observation.eligible else 'ineligible-observation'}",
        "claim-status\tnot-admitted",
        "timing-status\tforbidden",
        "mode\thost-observation",
        f"fingerprint\t{observation.fingerprint}",
    ]
    rows.extend(f"fact\t{key}\t{value}" for key, value in observation.facts)
    rows.append(f"refusals\t{len(observation.refusals)}")
    refusal_ordinals = {name: ordinal for ordinal, name in CONTRACT_REFUSALS}
    rows.extend(
        f"refusal\t{refusal_ordinals[name]}\t{name}"
        for name in observation.refusals
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    return body + f"report-root\t{_sha256(REPORT_DOMAIN + body)}\n".encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--observe", action="store_true")
    parser.add_argument("--expected-commit")
    parser.add_argument("--require-eligible", action="store_true")
    arguments = parser.parse_args()
    if arguments.require_eligible and not arguments.observe:
        parser.error("--require-eligible requires --observe")
    try:
        admission = validate(arguments.root)
        if not arguments.observe:
            sys.stdout.buffer.write(admission.static_report)
            return 0
        observation = observe(arguments.root.resolve(), arguments.expected_commit)
        sys.stdout.buffer.write(observation_report(admission, observation))
        return 0 if observation.eligible or not arguments.require_eligible else 2
    except (
        HostControlError,
        wp5f.RoleAdmissionError,
        wp5f.wp5e.ProcessReplayError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        print(f"S4-WP6 validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
