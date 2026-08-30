#!/usr/bin/env python3
"""Admit and replay the non-executing S4-WP8J candidate timing carrier."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import license_transition as lt1
import s4_register_residency_role as wp8h
import s4_residual_timing as wp7b


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-TIMING-CARRIER-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-TIMING-CARRIER-AUTHORITY\t1"
CANDIDATE_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-TIMING-CARRIER\t1"
REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-TIMING-CARRIER-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency-timing-carrier:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency-timing-carrier:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-register-residency-timing-carrier:report:v1\0"
CONTRACT_SEAL = "d3c2b8f1489f30aeec4c31edbac4b4db725cc30d7415f91cd589e28ec5f40ec4"
LT1_AUTHORITY_SEAL = "225cda9b967bd6c0bf93330721bfed1d41841fce11cc7e2677b4885678e5d5be"
WP8H_AUTHORITY_SEAL = "9a128600ba9ce4f2d6d503a393d41c54d413b75717e5687f9118b0e169bac3f1"
WP7B_AUTHORITY_SEAL = "dbde9cb35d1687b47f7e3c96081bc2d62e750013656ba7ba57933f0f186661ed"
CANDIDATE_REPORT_SHA256 = "9c5090cee4db9a9f2d84ed9eadf78d838e5dbaa6fe593fc65b42a1bd8f37e885"
CANDIDATE_REPORT_BYTES = 23_747
CANDIDATE_REPORT_LINES = 23
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
INT_RE = re.compile(r"0|-?[1-9][0-9]*\Z")
MAX_TEXT_BYTES = 2_000_000
MAX_EMITTER_BYTES = 256 * 1024 * 1024
BASELINE_OWNER = 1
CANDIDATE_OWNER = 4
OWNER_OFFSET = 72

METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-license-transition-authority", LT1_AUTHORITY_SEAL),
    ("parent-candidate-role-authority", WP8H_AUTHORITY_SEAL),
    ("parent-timing-wrapper-authority", WP7B_AUTHORITY_SEAL),
    ("status", "candidate-timing-carrier-structurally-admitted"),
    ("execution-status", "forbidden"),
    ("claim-status", "not-admitted"),
    ("role", "naux-register-residency-candidate"),
    ("role-owner", str(CANDIDATE_OWNER)),
    ("clock-source", "clock-monotonic-raw"),
    ("clock-reads", "2"),
    ("clock-placement", "before-exact-target-after-target-and-checksum-validation"),
    ("target-preservation", "byte-exact-wp8g-process-target"),
    ("wrapper-preservation", "exact-wp7b-wrapper-except-post-clock-role-owner"),
    ("result-protocol", "fixed-le56-v1"),
    ("allowed-syscalls", "mmap-munmap-clock-gettime-write-exit"),
    ("linker", "none"),
    ("libc", "none"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("candidate-report-sha256", CANDIDATE_REPORT_SHA256),
    ("candidate-report-bytes", str(CANDIDATE_REPORT_BYTES)),
    ("candidate-report-lines", str(CANDIDATE_REPORT_LINES)),
    ("kernel-count", "4"),
)
RECORDS = (
    (1, "sum-dense", 6_710_476_800, "5594c78b156929f021990ba06ebc045d17316f2c45b432a1009f210f6b985cac", 1052, "d8a2ff6b4e4e91d8c98c634fecaaa53f9bb5955ae8dc9d75825382bfd872aba5", 1660, 345, 608, "e1ec7d57cd8e1db4f050c04f35529307a52f7db0bc52ffb4fe8493480135b969"),
    (2, "branch-mix", -69_189_632, "1f188884b4bb04d85dc00608cf436c6b07d8a665d17f63d7d8ab8192749ba195", 1247, "897defb6998bc6c95c5e60b48fce2415edbf54e9e8c939bf7728e7f0db4ea870", 1855, 345, 608, "07928d332d46ab19b2ac418abea9cca079f1ab210d0ad15da27260fe721681d2"),
    (3, "dot-product", 73_294_064_435_200, "62291dc2f6662fdcb8f0a0e0d6f04a8a6f31ce498e6572a5908602b1ed7f2f7f", 1009, "0171b94556cb4ab82805171c84f09975b678ce91b4321d69dc851ce704800964", 1617, 345, 608, "d4c9e8adda3905ecdadc7e0a87064678feefb3c79fdec4279f608a533a559164"),
    (4, "list-update", 6_730_547_200, "a7937fa3e64d75cf6a96165d0e63baa4a0dc66b365647af8a87b3ea07079dc55", 1123, "8114b4c85fe5b3062645aaf625342715f5d170f6f0acda6834ae66c22707306a", 1731, 345, 608, "c82e887d9e109a476146b7945154b19ebe09b86cfa1e7081c52dc835a4293611"),
)
GATES = (
    ("01", "license-transition", "required", "exact-current-apache-authority"),
    ("02", "candidate-role", "required", "exact-wp8h-isolated-role"),
    ("03", "timing-wrapper", "required", "exact-wp7b-clock-and-result-envelope"),
    ("04", "target-preservation", "required", "byte-exact-four-wp8g-process-targets"),
    ("05", "role-specialization", "required", "exactly-one-owner-literal-one-to-four"),
    ("06", "independent-reconstruction", "required", "complete-elf-and-order-replay"),
    ("07", "static-isolation", "required", "no-clock-no-generated-image-execution"),
)
CLOSURES = (("01", "candidate-in-role-timing-carrier-unavailable", "closed", "wp8j-exact-wrapper-specialization"),)
BLOCKERS = (
    ("01", "eligible-candidate-host-attestation-unavailable"),
    ("02", "candidate-measurement-runner-unavailable"),
    ("03", "candidate-raw-measurement-evidence-unavailable"),
)
CANDIDATE_METADATA = (
    ("status", "register-residency-timing-carrier-candidate"),
    ("execution-status", "forbidden"),
    ("clock-source", "clock-monotonic-raw"),
    ("clock-placement", "before-target-after-checksum-validation"),
    ("result-protocol", "fixed-le56-v1"),
    ("result-owner-policy", "target-rsi-zero-before-stop-record-role-four-after-stop"),
    ("allowed-syscalls", "mmap-munmap-clock-gettime-write-exit"),
    ("target", "x86_64-unknown-linux-gnu"),
)
CANDIDATE_COLUMNS = (
    "columns\tordinal\tkernel\twork-hash\toracle\tprocess-target-bytes\t"
    "timing-elf-bytes\tstartup-bytes\ttarget-offset"
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP8J"),
    ("authority-id", "s4-register-residency-timing-carrier-v1"),
    ("status", "candidate-timing-carrier-structurally-admitted"),
    ("execution-status", "forbidden"),
    ("claim-status", "not-admitted"),
    ("file-count", "9"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-timing.yml",
    "distribution/s4-performance/WP8J-CARRIER.tsv",
    "distribution/s4-performance/WP8J-NONCLAIMS.md",
    "distribution/s4-performance/WP8J-README.md",
    "naux-lang/examples/naux_s4_register_residency_timing.rs",
    "naux-lang/examples/support/s4_register_residency_timing_elf.rs",
    "scripts/s4_register_residency_timing.py",
    "scripts/tests/test_s4_register_residency_timing.py",
    "scripts/tests/test_s4_register_residency_timing_static.py",
)


class CandidateTimingError(RuntimeError):
    """A fail-closed WP8J composition or replay error."""


@dataclass(frozen=True)
class ContractRecord:
    ordinal: int
    name: str
    oracle: int
    work_hash: str
    target_bytes: int
    target_hash: str
    elf_bytes: int
    startup_bytes: int
    target_offset: int
    elf_hash: str


@dataclass(frozen=True)
class Contract:
    records: tuple[ContractRecord, ...]
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
class Kernel:
    record: ContractRecord
    target: bytes
    elf: bytes


@dataclass(frozen=True)
class Candidate:
    kernels: tuple[Kernel, ...]
    raw: bytes


@dataclass(frozen=True)
class Admission:
    contract: Contract
    authority: Authority
    role: wp8h.Admission
    wrapper: wp7b.Admission
    static_report: bytes
    static_root: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_regular(path: Path, label: str, maximum: int = MAX_TEXT_BYTES) -> bytes:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise CandidateTimingError(f"{label} is not a bounded regular file")
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        raw = handle.read(maximum + 1)
        after = os.fstat(handle.fileno())
    rebound = path.lstat()
    if (
        (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        or (opened.st_dev, opened.st_ino, opened.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or len(raw) != after.st_size
        or stat.S_ISLNK(rebound.st_mode)
        or (rebound.st_dev, rebound.st_ino) != (after.st_dev, after.st_ino)
    ):
        raise CandidateTimingError(f"{label} changed while read")
    return raw


def _canonical(raw: bytes, label: str, maximum: int = MAX_TEXT_BYTES) -> list[str]:
    if not raw or len(raw) > maximum or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise CandidateTimingError(f"{label} has invalid canonical extent")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise CandidateTimingError(f"{label} is not UTF-8") from error
    if any(not line or line != line.strip() for line in lines):
        raise CandidateTimingError(f"{label} contains blank or padded rows")
    return lines


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    raw = _read_regular(path, path.name)
    lines = _canonical(raw, path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise CandidateTimingError(f"{path.name} shape drifted")
    fields = lines[-1].split("\t")
    body = raw[: -(len(lines[-1]) + 1)]
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]) or _sha256(domain + body) != fields[1]:
        raise CandidateTimingError(f"{path.name} seal drifted")
    return lines[1:-1], fields[1]


def parse_contract(path: Path) -> Contract:
    rows, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if seal != CONTRACT_SEAL:
        raise CandidateTimingError("WP8J contract identity drifted")
    expected = [f"meta\t{key}\t{value}" for key, value in METADATA]
    expected.extend(f"kernel\t{ordinal:02}\t{name}\t{oracle}\t{work}\t{target_bytes}\t{target_hash}\t{elf_bytes}\t{startup}\t{offset}\t{elf_hash}" for ordinal, name, oracle, work, target_bytes, target_hash, elf_bytes, startup, offset, elf_hash in RECORDS)
    expected.extend(f"gate\t{ordinal}\t{name}\t{status}\t{detail}" for ordinal, name, status, detail in GATES)
    expected.extend(f"closure\t{ordinal}\t{name}\t{status}\t{detail}" for ordinal, name, status, detail in CLOSURES)
    expected.extend(f"blocker\t{ordinal}\t{name}" for ordinal, name in BLOCKERS)
    if rows != expected:
        raise CandidateTimingError("WP8J contract rows drifted")
    return Contract(tuple(ContractRecord(*record) for record in RECORDS), seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    rows, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    prefix = [f"meta\t{key}\t{value}" for key, value in AUTHORITY_METADATA]
    prefix.extend((
        f"component\tcandidate-timing-contract\tdistribution/s4-performance/WP8J-CARRIER.tsv\t{contract_seal}",
        f"parent\tlicense-transition-authority\tdistribution/license-transition/LT1-AUTHORITY.tsv\t{LT1_AUTHORITY_SEAL}",
        f"parent\tcandidate-role-authority\tdistribution/s4-performance/WP8H-AUTHORITY.tsv\t{WP8H_AUTHORITY_SEAL}",
        f"parent\ttiming-wrapper-authority\tdistribution/s4-performance/WP7B-AUTHORITY.tsv\t{WP7B_AUTHORITY_SEAL}",
    ))
    if rows[: len(prefix)] != prefix:
        raise CandidateTimingError("WP8J authority metadata or parent binding drifted")
    records = []
    for row in rows[len(prefix):]:
        fields = row.split("\t")
        if (
            len(fields) != 6
            or fields[0] != "file"
            or not MODE_RE.fullmatch(fields[1])
            or not UINT_RE.fullmatch(fields[2])
            or not HASH_RE.fullmatch(fields[3])
            or fields[4] not in EXPECTED_FILES
            or fields[5] != "candidate-timing-carrier"
        ):
            raise CandidateTimingError("WP8J authority file row is malformed")
        records.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in records) != EXPECTED_FILES:
        raise CandidateTimingError("WP8J authority inventory drifted")
    return Authority(tuple(records), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        raw = _read_regular(path, record.path)
        mode = stat.S_IFREG | stat.S_IMODE(path.lstat().st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise CandidateTimingError(f"bound WP8J file drifted: {record.path}")


def _historical_wrapper(root: Path) -> wp7b.Admission:
    contract = wp7b.parse_contract(root / "distribution/s4-performance/WP7B-CARRIER.tsv")
    authority = wp7b.parse_authority(
        root / "distribution/s4-performance/WP7B-AUTHORITY.tsv", contract.seal
    )
    if authority.seal != WP7B_AUTHORITY_SEAL:
        raise CandidateTimingError("WP7B timing-wrapper authority drifted")
    transitioned = {relative for *_fields, relative in lt1.TRANSITIONS}
    snapshot = root / "distribution/license-transition/pre-apache"
    for record in authority.files:
        path = snapshot / record.path if record.path in transitioned else root / record.path
        raw = _read_regular(path, f"WP7B historical {record.path}")
        mode = stat.S_IFREG | stat.S_IMODE(path.lstat().st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise CandidateTimingError(f"WP7B historical authority drifted: {record.path}")
    report = wp7b._report(contract, authority, None)
    report_root = report.decode().split("report-root\t", 1)[1].strip()
    return wp7b.Admission(contract, authority, report, report_root)


def _owner_store(owner: int) -> bytes:
    return b"\x49\xb8" + struct.pack("<Q", owner) + b"\x4c\x89\x44\x24" + bytes((OWNER_OFFSET,))


def _specialize_owner(elf: bytes, target_offset: int) -> bytes:
    result = bytearray(elf)
    startup = result[wp7b.ELF_ENTRY_OFFSET:target_offset]
    pattern = _owner_store(BASELINE_OWNER)
    positions = [index for index in range(len(startup)) if startup.startswith(pattern, index)]
    if len(positions) != 1:
        raise CandidateTimingError("WP7B wrapper does not contain one exact baseline owner literal")
    position = wp7b.ELF_ENTRY_OFFSET + positions[0]
    replacement = _owner_store(CANDIDATE_OWNER)
    result[position:position + len(replacement)] = replacement
    return bytes(result)


def _verify_composition(root: Path, contract: Contract, role: wp8h.Admission, wrapper: wp7b.Admission) -> None:
    if role.authority.seal != WP8H_AUTHORITY_SEAL or wrapper.authority.seal != WP7B_AUTHORITY_SEAL:
        raise CandidateTimingError("WP8J parent authority drifted")
    transition = lt1.validate(root)
    if transition.authority.seal != LT1_AUTHORITY_SEAL:
        raise CandidateTimingError("Apache transition authority drifted")
    parent = role.contract.artifacts
    if len(parent) != len(contract.records):
        raise CandidateTimingError("WP8H artifact count drifted")
    for record, artifact in zip(contract.records, parent, strict=True):
        if (
            (record.ordinal, record.name, record.oracle, record.work_hash, record.target_hash)
            != (artifact.ordinal, artifact.name, artifact.oracle, artifact.work_hash, artifact.target_hash)
        ):
            raise CandidateTimingError("WP8J target identity differs from WP8H")
    support = (root / "naux-lang/examples/support/s4_register_residency_timing_elf.rs").read_text().lower()
    if "clock_gettime" in support or "std::time" in support or "command::new" in support:
        raise CandidateTimingError("WP8J specialization crossed its no-clock/no-execution boundary")


def _report(contract: Contract, authority: Authority, candidate: Candidate | None) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"candidate-report-sha256\t{CANDIDATE_REPORT_SHA256 if candidate else 'pending-replay'}",
        f"mode\t{'independent-byte-replay-no-execution' if candidate else 'static-no-host-no-clock-no-execution'}",
        "status\tcandidate-timing-carrier-structurally-admitted",
        "execution-status\tforbidden",
        "claim-status\tnot-admitted",
        "role-owner\t4",
        "clock-reads\t2",
        "artifacts\t4",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve(strict=True)
    contract = parse_contract(root / "distribution/s4-performance/WP8J-CARRIER.tsv")
    authority = parse_authority(root / "distribution/s4-performance/WP8J-AUTHORITY.tsv", contract.seal)
    _verify_files(root, authority)
    role = wp8h.validate(root)
    wrapper = _historical_wrapper(root)
    _verify_composition(root, contract, role, wrapper)
    report, report_root = _report(contract, authority, None)
    return Admission(contract, authority, role, wrapper, report, report_root)


def _verify_kernel(kernel: Kernel) -> None:
    record = kernel.record
    if (
        len(kernel.target) != record.target_bytes
        or _sha256(kernel.target) != record.target_hash
        or len(kernel.elf) != record.elf_bytes
        or _sha256(kernel.elf) != record.elf_hash
        or kernel.elf[record.target_offset:] != kernel.target
    ):
        raise CandidateTimingError(f"{record.name} target or timing ELF identity drifted")
    baseline = wp7b._reconstruct_elf(record, kernel.target)
    expected = _specialize_owner(baseline, record.target_offset)
    if kernel.elf != expected:
        raise CandidateTimingError(f"{record.name} independent timing ELF reconstruction differs")
    if kernel.elf.count(_owner_store(CANDIDATE_OWNER)) != 1 or kernel.elf.count(_owner_store(BASELINE_OWNER)) != 0:
        raise CandidateTimingError(f"{record.name} role owner specialization drifted")
    try:
        wp7b._verify_order(record, kernel.elf)
    except wp7b.TimingReplayError as error:
        raise CandidateTimingError(str(error)) from error


def parse_candidate(raw: bytes, contract: Contract) -> Candidate:
    if len(raw) != CANDIDATE_REPORT_BYTES or _sha256(raw) != CANDIDATE_REPORT_SHA256:
        raise CandidateTimingError("WP8J candidate report identity drifted")
    lines = _canonical(raw, "WP8J candidate", CANDIDATE_REPORT_BYTES)
    if len(lines) != CANDIDATE_REPORT_LINES or lines[0] != CANDIDATE_MAGIC:
        raise CandidateTimingError("WP8J candidate extent or magic drifted")
    index = 1
    metadata = []
    while index < len(lines) and lines[index].startswith("meta\t"):
        fields = lines[index].split("\t")
        if len(fields) != 3:
            raise CandidateTimingError("WP8J candidate metadata is malformed")
        metadata.append((fields[1], fields[2]))
        index += 1
    if tuple(metadata) != CANDIDATE_METADATA or lines[index] != CANDIDATE_COLUMNS:
        raise CandidateTimingError("WP8J candidate metadata or columns drifted")
    index += 1
    kernels = []
    for record in contract.records:
        fields = lines[index].split("\t")
        expected = (
            "kernel", f"{record.ordinal:02}", record.name, record.work_hash,
            str(record.oracle), str(record.target_bytes), str(record.elf_bytes),
            str(record.startup_bytes), str(record.target_offset),
        )
        if tuple(fields) != expected:
            raise CandidateTimingError(f"{record.name} candidate receipt drifted")
        target_fields = lines[index + 1].split("\t")
        elf_fields = lines[index + 2].split("\t")
        if target_fields[:2] != ["target-hex", f"{record.ordinal:02}"] or elf_fields[:2] != ["elf-hex", f"{record.ordinal:02}"]:
            raise CandidateTimingError(f"{record.name} candidate payload identity drifted")
        try:
            target = bytes.fromhex(target_fields[2])
            elf = bytes.fromhex(elf_fields[2])
        except (IndexError, ValueError) as error:
            raise CandidateTimingError(f"{record.name} candidate payload is not canonical hex") from error
        if target.hex() != target_fields[2] or elf.hex() != elf_fields[2]:
            raise CandidateTimingError(f"{record.name} candidate payload is not lowercase exact hex")
        kernel = Kernel(record, target, elf)
        _verify_kernel(kernel)
        kernels.append(kernel)
        index += 3
    if lines[index:] != ["verification\tregenerated-no-execution"]:
        raise CandidateTimingError("WP8J candidate has trailing or missing rows")
    return Candidate(tuple(kernels), raw)


def _looks_like_generated_image(path: Path) -> bool:
    with path.open("rb") as stream:
        header = stream.read(20)
    return len(header) == 20 and header[:7] == b"\x7fELF\x02\x01\x01" and struct.unpack_from("<HH", header, 16) == (2, 62)


def _validate_emitter_binary(binary: Path) -> None:
    metadata = binary.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_EMITTER_BYTES or not os.access(binary, os.X_OK):
        raise CandidateTimingError("reviewed WP8J emitter is not a bounded regular executable")
    if binary.name != "naux_s4_register_residency_timing":
        raise CandidateTimingError("reviewed WP8J emitter has a noncanonical filename")
    if _looks_like_generated_image(binary):
        raise CandidateTimingError("refusing to execute a generated timing image as the WP8J emitter")


def _run_emitter(binary: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [os.fspath(binary)], input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "LANG": "C"},
        check=False, timeout=30,
    )


def replay(admission: Admission, binary: Path) -> tuple[bytes, Candidate]:
    _validate_emitter_binary(binary)
    reviewed = binary.resolve(strict=True)
    first = _run_emitter(reviewed)
    second = _run_emitter(reviewed)
    if any(completed.returncode != 0 or completed.stderr for completed in (first, second)):
        raise CandidateTimingError("WP8J emitter did not exit cleanly and silently")
    if first.stdout != second.stdout:
        raise CandidateTimingError("WP8J emitter is nondeterministic")
    candidate = parse_candidate(first.stdout, admission.contract)
    report, _root = _report(admission.contract, admission.authority, candidate)
    return report, candidate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--binary", type=Path)
    arguments = parser.parse_args(argv)
    try:
        admission = validate(arguments.root)
        if arguments.binary is None:
            sys.stdout.buffer.write(admission.static_report)
        else:
            report, _candidate = replay(admission, arguments.binary)
            sys.stdout.buffer.write(report)
        return 0
    except (
        CandidateTimingError,
        lt1.TransitionError,
        wp8h.CandidateRoleError,
        wp7b.TimingReplayError,
        OSError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"S4-WP8J validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
