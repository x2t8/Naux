#!/usr/bin/env python3
"""Validate the S4-WP8E candidate function-byte authority."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_encoding_contract as wp8d


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-CANDIDATE-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-CANDIDATE-AUTHORITY\t1"
CANDIDATE_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-ENCODING\t1"
REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-CANDIDATE-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency-candidate-contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency-candidate-authority:v1\0"
CANDIDATE_DOMAIN = b"NAUX:s4-register-residency-encoding-report:v1\0"
REPORT_DOMAIN = b"NAUX:s4-register-residency-candidate-authority-report:v1\0"
CONTRACT_SEAL = "179c724165ee4fdb8965f0f196294310723dbd70d0127dbba0afe039c14d529c"
WP8D_CONTRACT_SEAL = "ebe81a4dce396afa1b510b470c331bf63aa7d8d3acb898079c0c6f68c07c43a6"
WP8D_AUTHORITY_SEAL = "38418de42556a3c8962a880c7a4a5be4d7504d93a47259841f2ab612da255e36"
CANDIDATE_ROOT = "605153686e716e2d9ea3c20b44c41d9c0e4b85a3369b4e091c467a8b8db68fd5"
CANDIDATE_SHA256 = "d88e8f5860e001e5f643858b1b4be034168ab64497e80345a7aaef2eb23ad4fa"
CANDIDATE_BYTES = 20_241
CANDIDATE_LINES = 234
MAX_FILE_BYTES = 1_000_000
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")

EXPECTED_METADATA = (
    ("status", "candidate-function-bytes-only"),
    ("elf-status", "absent"),
    ("native-execution-status", "forbidden"),
    ("measurement-status", "forbidden"),
    ("claim-status", "not-admitted"),
)
EXPECTED_KERNELS = (
    ("01", "sum-dense", "97d8699e9449d53f4f3c9386839099be194b7db985709122092dfac3eacb8f2d", "98e3ac1191dbb078730f024f12a8f4b310f542bfed72830b32cfce127b705e27", 993, 972, 958, 5, 1, "84578fc8a90dcfeb655e984dee5677c4a1164e866378825fd276a95ecf28e7ef"),
    ("02", "branch-mix", "8095c962d36b2a6876770412feac0df8fdd5f4e3627481f97f6b78f9bc489888", "68ef1e141aac58454b2b1dde0bcf8d2ea100c4faa1ee43323ce121b6471a86ad", 1188, 1167, 1153, 5, 1, "362c5dc7b3857358d2826b0a2f2dcbe376920514d948844a08c2b4433343ed42"),
    ("03", "dot-product", "b2fa698b60cb29e50d14e7f56650d1f09657562e3160e99bc7930e60f7c9e857", "c3a3bb75473b90689646c413552de32005ea27594d0565b72cc1984c731b7a3b", 950, 929, 915, 5, 1, "87ab3713c01593e5746e331ddf363fd500699d74c40d3b5db19ff72c2bc2b41a"),
    ("04", "list-update", "c6ac1a97cad0ec0529e7f5f49bb91d316fa63a2b9abb2c7452a0040fe4150199", "de4e36706adc23c47bae3c95d0b45719867684423897b59b462e0cd937c6f982", 1071, 1043, 1029, 6, 1, "a0b5e4316250342f7c9739d4adf021036b3badcdef7f62a0aec7c4b2c79b6c17"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-candidate.yml",
    "distribution/s4-performance/WP8E-CANDIDATE-ENCODING.tsv",
    "distribution/s4-performance/WP8E-NONCLAIMS.md",
    "distribution/s4-performance/WP8E-README.md",
    "naux-lang/examples/naux_s4_register_residency_encoding.rs",
    "naux-lang/examples/support/s4_register_residency_encoding.rs",
    "scripts/s4_register_residency_candidate_authority.py",
    "scripts/tests/test_s4_register_residency_candidate_authority.py",
)


class CandidateAuthorityError(RuntimeError):
    """A fail-closed WP8E authority error."""


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
class CandidateReport:
    root: str
    sha256: str
    kernels: tuple[tuple[str, ...], ...]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_regular(path: Path, label: str) -> bytes:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise CandidateAuthorityError(f"{label} is not regular")
    if before.st_size > MAX_FILE_BYTES:
        raise CandidateAuthorityError(f"{label} exceeds the bounded input limit")
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise CandidateAuthorityError(f"{label} changed before open")
        raw = handle.read(MAX_FILE_BYTES + 1)
        after = os.fstat(handle.fileno())
    rebound = path.lstat()
    if (
        (opened.st_dev, opened.st_ino, opened.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or len(raw) != after.st_size
        or stat.S_ISLNK(rebound.st_mode)
        or not stat.S_ISREG(rebound.st_mode)
        or (after.st_dev, after.st_ino) != (rebound.st_dev, rebound.st_ino)
    ):
        raise CandidateAuthorityError(f"{label} changed while read")
    return raw


def _canonical(raw: bytes, label: str) -> list[str]:
    if not raw or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise CandidateAuthorityError(f"{label} has invalid extent or encoding")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise CandidateAuthorityError(f"{label} is not UTF-8") from error
    if any(not line or line != line.strip() for line in lines):
        raise CandidateAuthorityError(f"{label} contains blank or padded rows")
    return lines


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    raw = _read_regular(path, path.name)
    lines = _canonical(raw, path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise CandidateAuthorityError(f"{path.name} shape drifted")
    fields = lines[-1].split("\t")
    body = raw[: -(len(lines[-1]) + 1)]
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise CandidateAuthorityError(f"{path.name} seal is malformed")
    if _sha256(domain + body) != fields[1]:
        raise CandidateAuthorityError(f"{path.name} seal mismatch")
    return lines[1:-1], fields[1]


def parse_contract(path: Path) -> tuple[tuple[str, ...], ...]:
    lines, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if seal != CONTRACT_SEAL:
        raise CandidateAuthorityError("WP8E accepted contract identity drifted")
    kernels = tuple(tuple(line.split("\t")[1:]) for line in lines if line.startswith("kernel\t"))
    expected = tuple(tuple(str(value) for value in row) for row in EXPECTED_KERNELS)
    if kernels != expected:
        raise CandidateAuthorityError("WP8E contract kernel identities drifted")
    metadata = dict(line.split("\t")[1:] for line in lines if line.startswith("meta\t"))
    required = {
        "parent-wp8d-contract": WP8D_CONTRACT_SEAL,
        "parent-wp8d-authority": WP8D_AUTHORITY_SEAL,
        "status": "candidate-function-bytes-structurally-admitted",
        "artifact-status": "function-bytes-only",
        "elf-status": "absent",
        "native-execution-status": "forbidden",
        "measurement-status": "forbidden",
        "claim-status": "not-admitted",
        "report-root": CANDIDATE_ROOT,
        "report-sha256": CANDIDATE_SHA256,
        "report-bytes": str(CANDIDATE_BYTES),
        "report-lines": str(CANDIDATE_LINES),
    }
    if any(metadata.get(key) != value for key, value in required.items()):
        raise CandidateAuthorityError("WP8E contract metadata drifted")
    return kernels


def parse_authority(path: Path) -> Authority:
    lines, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    metadata = [line for line in lines if line.startswith("meta\t")]
    expected_metadata = (
        "meta\tscope\tS4",
        "meta\twork-package\tS4-WP8E",
        "meta\tauthority-id\ts4-one-hot-loop-index-r12-candidate-bytes-v1",
        "meta\tstatus\tcandidate-function-bytes-structurally-admitted",
        "meta\telf-status\tabsent",
        "meta\tnative-execution-status\tforbidden",
        "meta\tmeasurement-status\tforbidden",
        "meta\tclaim-status\tnot-admitted",
        f"meta\tfile-count\t{len(EXPECTED_FILES)}",
    )
    if tuple(metadata) != expected_metadata:
        raise CandidateAuthorityError("WP8E authority metadata drifted")
    links = [line for line in lines if line.startswith(("component\t", "parent\t"))]
    if tuple(links) != (
        f"component\tcandidate-contract\tdistribution/s4-performance/WP8E-CANDIDATE-ENCODING.tsv\t{CONTRACT_SEAL}",
        f"parent\twp8d-contract\tdistribution/s4-performance/WP8D-ENCODING-CONTRACT.tsv\t{WP8D_CONTRACT_SEAL}",
        f"parent\twp8d-authority\tdistribution/s4-performance/WP8D-AUTHORITY.tsv\t{WP8D_AUTHORITY_SEAL}",
    ):
        raise CandidateAuthorityError("WP8E authority parent binding drifted")
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
            or fields[5] != "register-residency-candidate-bytes"
        ):
            raise CandidateAuthorityError("WP8E authority file row is malformed")
        records.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in records) != EXPECTED_FILES:
        raise CandidateAuthorityError("WP8E authority inventory drifted")
    return Authority(tuple(records), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        raw = _read_regular(path, record.path)
        mode = stat.S_IMODE(path.lstat().st_mode)
        if mode != record.mode & 0o777 or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise CandidateAuthorityError(f"bound WP8E file drifted: {record.path}")


def _verify_quarantine(root: Path, authority: Authority) -> None:
    validator = _read_regular(
        root / "scripts/s4_register_residency_candidate_authority.py",
        "WP8E validator source",
    ).decode()
    rust_sources = "\n".join(
        _read_regular(root / path, path).decode()
        for path in (
            "naux-lang/examples/naux_s4_register_residency_encoding.rs",
            "naux-lang/examples/support/s4_register_residency_encoding.rs",
        )
    )
    forbidden_validator = (
        "sub" + "process",
        "time." + "time(",
        "perf_" + "counter(",
        "sock" + "et",
        "requ" + "ests",
        "url" + "lib",
        "cty" + "pes",
    )
    forbidden_rust = (
        "build_" + "elf64",
        "std::process::" + "Command",
        "Instant::" + "now",
        "SystemTime::" + "now",
        "lib" + "c::",
    )
    if any(token in validator for token in forbidden_validator) or any(
        token in rust_sources for token in forbidden_rust
    ):
        raise CandidateAuthorityError("WP8E source crossed its no-execution/no-clock boundary")
    if any(
        record.path.endswith((".bin", ".elf", ".o", ".so", ".exe"))
        for record in authority.files
    ):
        raise CandidateAuthorityError("WP8E authority binds an executable artifact")


def parse_candidate_report(raw: bytes) -> CandidateReport:
    if len(raw) != CANDIDATE_BYTES or _sha256(raw) != CANDIDATE_SHA256:
        raise CandidateAuthorityError("candidate report document identity drifted")
    lines = _canonical(raw, "candidate report")
    if len(lines) != CANDIDATE_LINES or lines[0] != CANDIDATE_MAGIC:
        raise CandidateAuthorityError("candidate report extent or magic drifted")
    root_fields = lines[-1].split("\t")
    body = raw[: -(len(lines[-1]) + 1)]
    if (
        root_fields != ["report-root", CANDIDATE_ROOT]
        or _sha256(CANDIDATE_DOMAIN + body) != CANDIDATE_ROOT
    ):
        raise CandidateAuthorityError("candidate report root drifted")
    metadata = tuple(tuple(line.split("\t")[1:]) for line in lines[1:6])
    if metadata != EXPECTED_METADATA:
        raise CandidateAuthorityError("candidate report metadata drifted")

    index = 6
    kernels = []
    for expected in EXPECTED_KERNELS:
        fields = lines[index].split("\t")
        index += 1
        report_kernel = tuple(fields[1:])
        expected_report = tuple(str(value) for value in expected[:-1])
        if fields[0] != "kernel" or report_kernel != expected_report:
            raise CandidateAuthorityError("candidate kernel row drifted")
        abi = lines[index].split("\t")
        index += 1
        if abi != ["abi", expected[0], "save-r12", "11", "18", "restore-every-return"]:
            raise CandidateAuthorityError("candidate ABI row drifted")
        ranges = []
        while index < len(lines) and lines[index].startswith(f"range\t{expected[0]}\t"):
            fields = lines[index].split("\t")
            index += 1
            if len(fields) != 9 or not all(UINT_RE.fullmatch(value) for value in fields[2:4] + fields[5:]):
                raise CandidateAuthorityError("candidate range row is malformed")
            ranges.append(fields)
        if not ranges or int(ranges[0][5]) != 18:
            raise CandidateAuthorityError("candidate range partition lacks canonical start")
        for left, right in zip(ranges, ranges[1:]):
            if left[6] != right[5]:
                raise CandidateAuthorityError("candidate ranges are not contiguous")
        if int(ranges[-1][6]) != expected[6]:
            raise CandidateAuthorityError("candidate ranges do not end at the error suffix")
        transformed = sum(row[4] in {"load-physical", "store-physical"} for row in ranges)
        returns = sum(row[4] == "return-with-restore" for row in ranges)
        if transformed != expected[7] or returns != expected[8]:
            raise CandidateAuthorityError("candidate transformed-site extent drifted")
        for row in ranges:
            width = int(row[6]) - int(row[5])
            baseline_width = int(row[8]) - int(row[7])
            kind = row[4]
            if (
                kind in {"load-physical", "store-physical"} and width != 7
                or kind.startswith("passthrough-") and width != baseline_width
                or kind == "return-with-restore" and width != baseline_width + 7
            ):
                raise CandidateAuthorityError("candidate range width equation drifted")
        target = lines[index].split("\t")
        index += 1
        if len(target) != 3 or target[:2] != ["target-hex", expected[0]]:
            raise CandidateAuthorityError("candidate target row drifted")
        try:
            target_bytes = bytes.fromhex(target[2])
        except ValueError as error:
            raise CandidateAuthorityError("candidate target hex is malformed") from error
        if len(target_bytes) != expected[5] or _sha256(target_bytes) != expected[9]:
            raise CandidateAuthorityError("candidate target byte identity drifted")
        if (
            target_bytes[:7] != bytes.fromhex("554889e54881ec")
            or target_bytes[11:14] != bytes.fromhex("4c89a5")
            or target_bytes[-14:] != bytes.fromhex("bf46000000b83c0000000f050f0b")
        ):
            raise CandidateAuthorityError("candidate prologue, save, or error suffix drifted")
        kernels.append(report_kernel)
    if lines[index : index + 2] != [
        "verification\tindependent-byte-parser-accepted",
        "verification\tno-elf-no-execution-no-measurement",
    ] or index + 2 != len(lines) - 1:
        raise CandidateAuthorityError("candidate verification surface drifted")
    return CandidateReport(CANDIDATE_ROOT, CANDIDATE_SHA256, tuple(kernels))


def validate(root: Path, report_path: Path) -> tuple[Authority, CandidateReport, bytes, str]:
    root = root.resolve(strict=True)
    parse_contract(root / "distribution/s4-performance/WP8E-CANDIDATE-ENCODING.tsv")
    authority = parse_authority(root / "distribution/s4-performance/WP8E-AUTHORITY.tsv")
    _verify_files(root, authority)
    _verify_quarantine(root, authority)
    parent = wp8d.validate(root)
    if parent.contract.seal != WP8D_CONTRACT_SEAL or parent.authority.seal != WP8D_AUTHORITY_SEAL:
        raise CandidateAuthorityError("WP8D parent authority drifted")
    report = parse_candidate_report(_read_regular(report_path, "candidate report"))
    rows = (
        REPORT_MAGIC,
        f"contract\t{CONTRACT_SEAL}",
        f"authority\t{authority.seal}",
        f"candidate-report-root\t{report.root}",
        f"candidate-report-sha256\t{report.sha256}",
        "status\tcandidate-function-bytes-structurally-admitted",
        "elf-status\tabsent",
        "native-execution-status\tforbidden",
        "measurement-status\tforbidden",
        "claim-status\tnot-admitted",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    report_root = _sha256(REPORT_DOMAIN + body)
    return authority, report, body + f"report-root\t{report_root}\n".encode(), report_root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        _, _, report, _ = validate(arguments.root, arguments.report)
        sys.stdout.buffer.write(report)
    except (CandidateAuthorityError, wp8d.EncodingContractError, OSError, ValueError) as error:
        print(f"WP8E validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
