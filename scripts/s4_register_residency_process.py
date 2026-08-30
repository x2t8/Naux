#!/usr/bin/env python3
"""Admit and execute the untimed S4-WP8G residency process boundary."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_elf_authority as wp8f


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PROCESS-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PROCESS-AUTHORITY\t1"
CANDIDATE_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PROCESS\t1"
REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PROCESS-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency-process:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency-process:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-register-residency-process:report:v1\0"
CONTRACT_SEAL = "050107eff2a80a6dc6a4af0f9d2c64eedae8732dafa038e430bfab9303cc03bb"
WP8F_CONTRACT_SEAL = "c653e98c392903f3c8007b3703480030c60aeffd48c1b10fb138a4c34f0fe69c"
WP8F_AUTHORITY_SEAL = "fcb1cda5837ecfcda7ab36b60dbdc107bf93aff4eb27882d436233a78145ce4f"
WP8F_REPORT_ROOT = "50fe50575497b2a93e0f7fd48f5e81eddd339cb486c8b974c98d7cc0c5891398"
CANDIDATE_REPORT_SHA256 = "34cc3b7f1b0d7bd0810e0fb9db472a46071d62b3eed8409893a023bc89295ef2"
CANDIDATE_REPORT_BYTES = 30_401
CANDIDATE_REPORT_LINES = 27
RESULT_MAGIC = b"NAUX5E01"
RESULT_STRUCT = struct.Struct("<8sQqQQQ")
RESULT_BYTES = RESULT_STRUCT.size
MAX_FILE_BYTES = 1_000_000
MAX_EMITTER_BYTES = 256 * 1024 * 1024
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
INT_RE = re.compile(r"0|-?[1-9][0-9]*\Z")
HEX_RE = re.compile(r"(?:[0-9a-f]{2})+\Z")

EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-process.yml",
    "distribution/s4-performance/WP8G-NONCLAIMS.md",
    "distribution/s4-performance/WP8G-PROCESS.tsv",
    "distribution/s4-performance/WP8G-README.md",
    "naux-lang/examples/naux_s4_register_residency_process.rs",
    "naux-lang/examples/support/s4_register_residency_process.rs",
    "scripts/s4_register_residency_process.py",
    "scripts/tests/test_s4_register_residency_process.py",
)
EXPECTED_ROWS = (
    ("01", "sum-dense", 6_710_476_800, "5594c78b156929f021990ba06ebc045d17316f2c45b432a1009f210f6b985cac", "84578fc8a90dcfeb655e984dee5677c4a1164e866378825fd276a95ecf28e7ef", "d8a2ff6b4e4e91d8c98c634fecaaa53f9bb5955ae8dc9d75825382bfd872aba5", "c13f847f443403baf6d3152122b2f8f9bd52dd60b8c740247be5e703530700f8", 972, 1052, 958, 942, 972, -288, -32, -48, -24, 50, 16384, 1436, 117, 384),
    ("02", "branch-mix", -69_189_632, "1f188884b4bb04d85dc00608cf436c6b07d8a665d17f63d7d8ab8192749ba195", "362c5dc7b3857358d2826b0a2f2dcbe376920514d948844a08c2b4433343ed42", "897defb6998bc6c95c5e60b48fce2415edbf54e9e8c939bf7728e7f0db4ea870", "cf31d1407677213a85ba3dbb395a06895e8c5c63dce46a42ac13fe916769f0a7", 1167, 1247, 1153, 1137, 1167, -344, -32, -56, -24, 50, 16384, 1631, 117, 384),
    ("03", "dot-product", 73_294_064_435_200, "62291dc2f6662fdcb8f0a0e0d6f04a8a6f31ce498e6572a5908602b1ed7f2f7f", "87ab3713c01593e5746e331ddf363fd500699d74c40d3b5db19ff72c2bc2b41a", "0171b94556cb4ab82805171c84f09975b678ce91b4321d69dc851ce704800964", "b33c2f464595c9c07e6482288917874e22e271296f428d535ddcda15ba8d6846", 929, 1009, 915, 899, 929, -288, -32, -48, -24, 50, 16384, 1393, 117, 384),
    ("04", "list-update", 6_730_547_200, "a7937fa3e64d75cf6a96165d0e63baa4a0dc66b365647af8a87b3ea07079dc55", "a0b5e4316250342f7c9739d4adf021036b3badcdef7f62a0aec7c4b2c79b6c17", "8114b4c85fe5b3062645aaf625342715f5d170f6f0acda6834ae66c22707306a", "18cd00a4b3f4b43c300b6643e248574c8f956ad52971915997d0482ba2c351cd", 1043, 1123, 1029, 1013, 1043, -328, -32, -48, -24, 50, 16384, 1507, 117, 384),
)
META_ROWS = (
    "meta\tstatus\tfresh-process-artifact-candidate",
    "meta\texecution-owner\twp8g-only",
    "meta\ttiming-status\tforbidden",
    "meta\tresult-protocol\tfixed-le48-v1",
    "meta\tallowed-syscalls\tmmap-munmap-write-exit",
    "meta\tlinker\tnone",
    "meta\tlibc\tnone",
    "meta\ttarget\tx86_64-unknown-linux-gnu",
)
COLUMNS = (
    "columns\tordinal\tkernel\twork-hash\tcandidate-target-bytes\tprocess-target-bytes"
    "\terror-offset\treturn-start\tverifier-offset\tchecksum-displacement"
    "\touter-displacement\tinner-displacement\towner-displacement\texpected-outer"
    "\texpected-inner\telf-bytes\tstartup-bytes\ttarget-offset"
)


class ProcessReplayError(RuntimeError):
    """A fail-closed WP8G admission or replay error."""


@dataclass(frozen=True)
class ContractRecord:
    ordinal: int
    name: str
    oracle: int
    work_hash: str
    candidate_hash: str
    process_hash: str
    elf_hash: str
    candidate_bytes: int
    process_bytes: int
    error_offset: int
    return_start: int
    verifier_offset: int
    checksum_displacement: int
    outer_displacement: int
    inner_displacement: int
    owner_displacement: int
    expected_outer: int
    expected_inner: int
    elf_bytes: int
    startup_bytes: int
    target_offset: int


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
    candidate: bytes
    process: bytes
    elf: bytes


@dataclass(frozen=True)
class Candidate:
    kernels: tuple[Kernel, ...]
    raw: bytes


@dataclass(frozen=True)
class ProcessResult:
    pass_number: int
    ordinal: int
    name: str
    checksum: int
    outer: int
    inner: int
    owner: int


@dataclass(frozen=True)
class Admission:
    contract: Contract
    authority: Authority
    static_report: bytes
    report_root: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(raw: bytes, label: str, limit: int) -> list[str]:
    if not raw or len(raw) > limit or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise ProcessReplayError(f"{label} has invalid canonical extent")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ProcessReplayError(f"{label} is not UTF-8") from error
    if any(not line or line != line.strip() for line in lines):
        raise ProcessReplayError(f"{label} contains blank or padded rows")
    return lines


def _read_regular(path: Path, label: str, limit: int = MAX_FILE_BYTES) -> bytes:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ProcessReplayError(f"{label} is not a bounded regular file")
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        raw = handle.read(limit + 1)
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
        raise ProcessReplayError(f"{label} changed while read")
    return raw


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    raw = _read_regular(path, path.name)
    lines = _canonical(raw, path.name, MAX_FILE_BYTES)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise ProcessReplayError(f"{path.name} shape drifted")
    body = raw[: -(len(lines[-1]) + 1)]
    fields = lines[-1].split("\t")
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]) or _sha256(domain + body) != fields[1]:
        raise ProcessReplayError(f"{path.name} seal drifted")
    return lines[1:-1], fields[1]


def parse_contract(path: Path) -> Contract:
    lines, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if seal != CONTRACT_SEAL:
        raise ProcessReplayError("WP8G contract identity drifted")
    metadata = dict(line.split("\t")[1:] for line in lines if line.startswith("meta\t"))
    required = {
        "parent-wp8f-contract": WP8F_CONTRACT_SEAL,
        "parent-wp8f-authority": WP8F_AUTHORITY_SEAL,
        "parent-wp8f-report-root": WP8F_REPORT_ROOT,
        "status": "fresh-process-checksum-work-parity-admitted",
        "claim-status": "untimed-parity-only",
        "timing-status": "forbidden",
        "candidate-report-sha256": CANDIDATE_REPORT_SHA256,
        "candidate-report-bytes": str(CANDIDATE_REPORT_BYTES),
        "candidate-report-lines": str(CANDIDATE_REPORT_LINES),
        "kernel-count": "4",
        "replay-count": "2",
    }
    if any(metadata.get(key) != value for key, value in required.items()):
        raise ProcessReplayError("WP8G contract metadata drifted")
    rows = [line.split("\t") for line in lines if line.startswith("kernel\t")]
    expected = [["kernel", *(str(value) for value in row)] for row in EXPECTED_ROWS]
    if rows != expected:
        raise ProcessReplayError("WP8G contract kernel identities drifted")
    records = tuple(
        ContractRecord(
            ordinal=int(row[0]),
            name=row[1],
            oracle=int(row[2]),
            work_hash=row[3],
            candidate_hash=row[4],
            process_hash=row[5],
            elf_hash=row[6],
            candidate_bytes=int(row[7]),
            process_bytes=int(row[8]),
            error_offset=int(row[9]),
            return_start=int(row[10]),
            verifier_offset=int(row[11]),
            checksum_displacement=int(row[12]),
            outer_displacement=int(row[13]),
            inner_displacement=int(row[14]),
            owner_displacement=int(row[15]),
            expected_outer=int(row[16]),
            expected_inner=int(row[17]),
            elf_bytes=int(row[18]),
            startup_bytes=int(row[19]),
            target_offset=int(row[20]),
        )
        for row in EXPECTED_ROWS
    )
    return Contract(records, seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    lines, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    expected_metadata = (
        "meta\tscope\tS4",
        "meta\twork-package\tS4-WP8G",
        "meta\tauthority-id\ts4-one-hot-loop-index-r12-process-v1",
        "meta\tstatus\tfresh-process-checksum-work-parity-admitted",
        "meta\tclaim-status\tuntimed-parity-only",
        "meta\ttiming-status\tforbidden",
        "meta\tkernel-count\t4",
        f"meta\tfile-count\t{len(EXPECTED_FILES)}",
    )
    if tuple(line for line in lines if line.startswith("meta\t")) != expected_metadata:
        raise ProcessReplayError("WP8G authority metadata drifted")
    links = tuple(line for line in lines if line.startswith(("component\t", "parent\t")))
    if links != (
        f"component\tprocess-contract\tdistribution/s4-performance/WP8G-PROCESS.tsv\t{contract_seal}",
        f"parent\twp8f-contract\tdistribution/s4-performance/WP8F-ELF64-CONTRACT.tsv\t{WP8F_CONTRACT_SEAL}",
        f"parent\twp8f-authority\tdistribution/s4-performance/WP8F-AUTHORITY.tsv\t{WP8F_AUTHORITY_SEAL}",
    ):
        raise ProcessReplayError("WP8G authority parent binding drifted")
    records = []
    for line in lines:
        if not line.startswith("file\t"):
            continue
        fields = line.split("\t")
        if (
            len(fields) != 6
            or not MODE_RE.fullmatch(fields[1])
            or not UINT_RE.fullmatch(fields[2])
            or not HASH_RE.fullmatch(fields[3])
            or fields[4] not in EXPECTED_FILES
            or fields[5] != "register-residency-process"
        ):
            raise ProcessReplayError("WP8G authority file row is malformed")
        records.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in records) != EXPECTED_FILES:
        raise ProcessReplayError("WP8G authority inventory drifted")
    return Authority(tuple(records), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        raw = _read_regular(path, record.path)
        if (
            stat.S_IMODE(path.lstat().st_mode) != record.mode & 0o777
            or len(raw) != record.size
            or _sha256(raw) != record.sha256
        ):
            raise ProcessReplayError(f"bound WP8G file drifted: {record.path}")


def _verify_source_boundary(root: Path) -> None:
    sources = "\n".join(
        _read_regular(root / path, path).decode().lower()
        for path in (
            "naux-lang/examples/naux_s4_register_residency_process.rs",
            "naux-lang/examples/support/s4_register_residency_process.rs",
        )
    )
    forbidden = (
        "instant::now",
        "systemtime::now",
        ".elapsed()",
        "duration_since(",
        "runtime_ns",
        "compile_ns",
        "command::new",
        "std::process::command",
        "throughput",
        "latency",
        "median",
    )
    if any(token in sources for token in forbidden):
        raise ProcessReplayError("WP8G emitter crossed its no-clock/no-measurement boundary")


def _rel32(target: int, displacement: int) -> bytes:
    delta = target - (displacement + 4)
    if not -(1 << 31) <= delta < (1 << 31):
        raise ProcessReplayError("WP8G rel32 escapes its bound")
    return struct.pack("<i", delta)


def _reconstruct_process(candidate: bytes, record: ContractRecord) -> bytes:
    if record.verifier_offset != len(candidate) or record.process_bytes != len(candidate) + 80:
        raise ProcessReplayError("WP8G verifier extent equation drifted")
    start = record.return_start
    end = start + 16
    promoted = candidate[14:18]
    if (
        candidate[11:14] != b"\x4c\x89\xa5"
        or candidate[start : start + 3] != b"\x4c\x8b\xa5"
        or candidate[start + 3 : start + 7] != promoted
        or candidate[start + 7 : start + 10] != b"\x48\x8b\x85"
        or candidate[start + 10 : start + 14] != struct.pack("<i", record.checksum_displacement)
        or candidate[start + 14 : end] != b"\xc9\xc3"
        or end != record.error_offset
        or promoted != struct.pack("<i", record.inner_displacement)
    ):
        raise ProcessReplayError("WP8G candidate save/restore return boundary drifted")
    result = bytearray(candidate)
    result[start:end] = b"\xe9" + _rel32(len(candidate), start + 1) + b"\x90" * 11
    appendix = bytearray()
    appendix += b"\x48\x8b\x85" + struct.pack("<i", record.checksum_displacement)
    appendix += b"\x48\x8b\x8d" + struct.pack("<i", record.outer_displacement)
    appendix += b"\x49\xb8" + struct.pack("<Q", record.expected_outer)
    appendix += b"\x4c\x39\xc1\x0f\x85"
    appendix += _rel32(record.error_offset, len(candidate) + len(appendix))
    appendix += b"\x4c\x89\xe2"
    appendix += b"\x49\xb8" + struct.pack("<Q", record.expected_inner)
    appendix += b"\x4c\x39\xc2\x0f\x85"
    appendix += _rel32(record.error_offset, len(candidate) + len(appendix))
    appendix += b"\x48\x8b\xb5" + struct.pack("<i", record.owner_displacement)
    appendix += b"\x48\x85\xf6\x0f\x85"
    appendix += _rel32(record.error_offset, len(candidate) + len(appendix))
    appendix += b"\x4c\x8b\xa5" + promoted + b"\xc9\xc3"
    result.extend(appendix)
    return bytes(result)


def _verify_elf(elf: bytes, process: bytes, record: ContractRecord) -> None:
    if (
        len(elf) != record.elf_bytes
        or record.target_offset + len(process) != len(elf)
        or elf[record.target_offset :] != process
        or _sha256(elf) != record.elf_hash
        or elf[:7] != b"\x7fELF\x02\x01\x01"
        or struct.unpack_from("<HH", elf, 16) != (2, 62)
        or struct.unpack_from("<Q", elf, 24)[0] != 0x0040_0100
        or struct.unpack_from("<Q", elf, 40)[0] != 0
        or struct.unpack_from("<II", elf, 64) != (1, 5)
        or struct.unpack_from("<II", elf, 120) != (0x6474_E551, 6)
        or elf[256] != 0xE8
        or 261 + struct.unpack_from("<i", elf, 257)[0] != record.target_offset
        or record.startup_bytes != 117
    ):
        raise ProcessReplayError("WP8G ELF structure or target binding drifted")


def parse_candidate(raw: bytes, contract: Contract) -> Candidate:
    if (
        len(raw) != CANDIDATE_REPORT_BYTES
        or _sha256(raw) != CANDIDATE_REPORT_SHA256
    ):
        raise ProcessReplayError("WP8G candidate report identity drifted")
    lines = _canonical(raw, "WP8G candidate", CANDIDATE_REPORT_BYTES)
    if len(lines) != CANDIDATE_REPORT_LINES or lines[0] != CANDIDATE_MAGIC:
        raise ProcessReplayError("WP8G candidate extent or magic drifted")
    if tuple(lines[1:9]) != META_ROWS or lines[9] != COLUMNS:
        raise ProcessReplayError("WP8G candidate metadata or columns drifted")
    index = 10
    kernels = []
    for record in contract.records:
        fields = lines[index].split("\t")
        index += 1
        expected = [
            "kernel",
            f"{record.ordinal:02}",
            record.name,
            record.work_hash,
            str(record.candidate_bytes),
            str(record.process_bytes),
            str(record.error_offset),
            str(record.return_start),
            str(record.verifier_offset),
            str(record.checksum_displacement),
            str(record.outer_displacement),
            str(record.inner_displacement),
            str(record.owner_displacement),
            str(record.expected_outer),
            str(record.expected_inner),
            str(record.elf_bytes),
            str(record.startup_bytes),
            str(record.target_offset),
        ]
        if fields != expected:
            raise ProcessReplayError("WP8G candidate kernel row drifted")
        payloads = []
        for label in ("candidate-target-hex", "target-hex", "elf-hex"):
            row = lines[index].split("\t")
            index += 1
            if len(row) != 3 or row[:2] != [label, f"{record.ordinal:02}"] or not HEX_RE.fullmatch(row[2]):
                raise ProcessReplayError(f"WP8G {label} row is malformed")
            payloads.append(bytes.fromhex(row[2]))
        candidate, process, elf = payloads
        if (
            len(candidate) != record.candidate_bytes
            or _sha256(candidate) != record.candidate_hash
            or len(process) != record.process_bytes
            or _sha256(process) != record.process_hash
            or process != _reconstruct_process(candidate, record)
        ):
            raise ProcessReplayError("WP8G target identity or reconstruction drifted")
        _verify_elf(elf, process, record)
        if struct.pack("<q", record.oracle) in process:
            raise ProcessReplayError("WP8G process target embeds its checksum oracle")
        kernels.append(Kernel(record, candidate, process, elf))
    if lines[index:] != ["verification\tregenerated"]:
        raise ProcessReplayError("WP8G candidate has trailing or missing rows")
    return Candidate(tuple(kernels), raw)


def _report(
    contract: Contract,
    authority: Authority,
    candidate: Candidate | None,
    results: tuple[ProcessResult, ...] = (),
) -> bytes:
    rows = [
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"candidate-report-sha256\t{CANDIDATE_REPORT_SHA256 if candidate else 'pending-replay'}",
        f"mode\t{'untimed-fresh-process-replay' if candidate else 'static-admission'}",
        f"replays\t{2 if candidate else 0}",
        "status\tfresh-process-checksum-work-parity-admitted",
        "claim-status\tuntimed-parity-only",
        "timing-status\tforbidden",
    ]
    for result in results:
        rows.append(
            f"result\t{result.pass_number}\t{result.ordinal:02}\t{result.name}\t"
            f"{result.checksum}\t{result.outer}\t{result.inner}\t{result.owner}"
        )
    body = b"".join(f"{row}\n".encode() for row in rows)
    return body + f"report-root\t{_sha256(REPORT_DOMAIN + body)}\n".encode()


def validate(root: Path) -> Admission:
    root = root.resolve(strict=True)
    contract = parse_contract(root / "distribution/s4-performance/WP8G-PROCESS.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/WP8G-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    _verify_source_boundary(root)
    wp8f.parse_contract(root / "distribution/s4-performance/WP8F-ELF64-CONTRACT.tsv")
    parent = wp8f.parse_authority(root / "distribution/s4-performance/WP8F-AUTHORITY.tsv")
    wp8f._verify_files(root, parent)
    if parent.seal != WP8F_AUTHORITY_SEAL:
        raise ProcessReplayError("WP8F parent authority drifted")
    report = _report(contract, authority, None)
    report_root = report.decode().split("report-root\t", 1)[1].strip()
    return Admission(contract, authority, report, report_root)


def _looks_like_generated_image(path: Path) -> bool:
    with path.open("rb") as stream:
        header = stream.read(20)
    return len(header) == 20 and header[:7] == b"\x7fELF\x02\x01\x01" and struct.unpack_from("<HH", header, 16) == (2, 62)


def _validate_emitter_binary(binary: Path) -> None:
    metadata = binary.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > MAX_EMITTER_BYTES
        or not os.access(binary, os.X_OK)
    ):
        raise ProcessReplayError("reviewed WP8G emitter is not a bounded regular executable")
    if binary.name != "naux_s4_register_residency_process":
        raise ProcessReplayError("reviewed WP8G emitter has a noncanonical filename")
    if _looks_like_generated_image(binary):
        raise ProcessReplayError("refusing to use a generated process image as the WP8G emitter")


def _run_emitter(binary: Path) -> subprocess.CompletedProcess[bytes]:
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "LANG": "C"}
    return subprocess.run(
        [os.fspath(binary)],
        input=b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
        timeout=30,
    )


def _write_exact_image(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o700)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ProcessReplayError("artifact write made no progress")
            view = view[written:]
        os.fchmod(descriptor, 0o700)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or _sha256(_read_regular(path, "materialized artifact")) != _sha256(payload)
    ):
        raise ProcessReplayError("materialized artifact identity drifted")


def _run_process_image(path: Path, expected_hash: str) -> subprocess.CompletedProcess[bytes]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ProcessReplayError("WP8G process image is not an owned regular file")
    raw = _read_regular(path, "WP8G process image")
    if _sha256(raw) != expected_hash or not _looks_like_generated_image(path):
        raise ProcessReplayError("WP8G process image failed exact pre-execution admission")
    return subprocess.run(
        [os.fspath(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=os.fspath(path.parent),
        env={"LC_ALL": "C", "LANG": "C"},
        check=False,
        timeout=30,
    )


def _parse_result(
    completed: subprocess.CompletedProcess[bytes],
    record: ContractRecord,
    pass_number: int,
) -> ProcessResult:
    if completed.returncode != 0 or completed.stderr or len(completed.stdout) != RESULT_BYTES:
        raise ProcessReplayError(f"{record.name} fresh process did not complete exactly")
    magic, ordinal, checksum, outer, inner, owner = RESULT_STRUCT.unpack(completed.stdout)
    if (
        magic != RESULT_MAGIC
        or ordinal != record.ordinal
        or checksum != record.oracle
        or outer != record.expected_outer
        or inner != record.expected_inner
        or owner != 0
    ):
        raise ProcessReplayError(f"{record.name} checksum or terminal work state differs")
    return ProcessResult(pass_number, record.ordinal, record.name, checksum, outer, inner, owner)


def replay(
    admission: Admission, binary: Path
) -> tuple[bytes, Candidate, tuple[ProcessResult, ...]]:
    _validate_emitter_binary(binary)
    reviewed_binary = binary.resolve(strict=True)
    first = _run_emitter(reviewed_binary)
    second = _run_emitter(reviewed_binary)
    for completed in (first, second):
        if completed.returncode != 0 or completed.stderr:
            raise ProcessReplayError("WP8G emitter did not exit cleanly and silently")
    if first.stdout != second.stdout:
        raise ProcessReplayError("WP8G emitter is nondeterministic")
    candidate = parse_candidate(first.stdout, admission.contract)
    results = []
    with tempfile.TemporaryDirectory(prefix="naux-wp8g-process-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        for pass_number in (1, 2):
            for kernel in candidate.kernels:
                path = root / f"pass-{pass_number}-artifact-{kernel.record.ordinal:02}"
                _write_exact_image(path, kernel.elf)
                completed = _run_process_image(path, kernel.record.elf_hash)
                results.append(_parse_result(completed, kernel.record, pass_number))
    result_tuple = tuple(results)
    return _report(admission.contract, admission.authority, candidate, result_tuple), candidate, result_tuple


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--binary", type=Path)
    arguments = parser.parse_args()
    try:
        admission = validate(arguments.root)
        if arguments.binary is None:
            sys.stdout.buffer.write(admission.static_report)
        else:
            report, _, _ = replay(admission, arguments.binary)
            sys.stdout.buffer.write(report)
    except (
        ProcessReplayError,
        wp8f.ElfAuthorityError,
        OSError,
        subprocess.TimeoutExpired,
        ValueError,
    ) as error:
        print(f"S4-WP8G validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
