#!/usr/bin/env python3
"""Validate the quarantined S4-WP8F register-residency ELF64 authority."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_candidate_authority as wp8e


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-ELF64-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-ELF64-AUTHORITY\t1"
ELF_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-ELF64\t1"
REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-ELF64-AUTHORITY-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency-elf-contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency-elf-authority:v1\0"
ELF_REPORT_DOMAIN = b"NAUX:s4-register-residency-elf-report:v1\0"
REPORT_DOMAIN = b"NAUX:s4-register-residency-elf-authority-report:v1\0"
CONTRACT_SEAL = "c653e98c392903f3c8007b3703480030c60aeffd48c1b10fb138a4c34f0fe69c"
WP8E_CONTRACT_SEAL = "179c724165ee4fdb8965f0f196294310723dbd70d0127dbba0afe039c14d529c"
WP8E_AUTHORITY_SEAL = "9a6ee8f48c65bf7daf797c2e8189981ceeac17609a8521fe7b30966ef65a5ea3"
WP8E_REPORT_ROOT = "605153686e716e2d9ea3c20b44c41d9c0e4b85a3369b4e091c467a8b8db68fd5"
ELF_REPORT_ROOT = "50fe50575497b2a93e0f7fd48f5e81eddd339cb486c8b974c98d7cc0c5891398"
ELF_REPORT_SHA256 = "5535f57f6e27457a1ff4591173a0a241af5ad12cafe2ce90e0ff15537107350a"
ELF_REPORT_BYTES = 12_270
ELF_REPORT_LINES = 21
MAX_FILE_BYTES = 1_000_000
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
HEX_RE = re.compile(r"(?:[0-9a-f]{2})+\Z")

EXPECTED_METADATA = (
    ("status", "candidate-elf-structurally-admitted"),
    ("artifact-status", "report-hex-only"),
    ("native-execution-status", "forbidden"),
    ("measurement-status", "forbidden"),
    ("claim-status", "not-admitted"),
    ("linker", "none"),
    ("libc", "none"),
    ("target", "x86_64-unknown-linux-gnu"),
)
EXPECTED_COLUMNS = (
    "columns\tordinal\tkernel\tmachine-hash\tplan-hash\ttarget-hash\telf-hash"
    "\ttarget-bytes\telf-bytes\ttarget-offset\tentry\tload-flags\tstack-flags"
)
EXPECTED_KERNELS = (
    ("01", "sum-dense", "97d8699e9449d53f4f3c9386839099be194b7db985709122092dfac3eacb8f2d", "98e3ac1191dbb078730f024f12a8f4b310f542bfed72830b32cfce127b705e27", "84578fc8a90dcfeb655e984dee5677c4a1164e866378825fd276a95ecf28e7ef", "e07bbe5ea0fd2494061393a107f6fd818758fb84cc640c90d9bb0ffe18763008", 972, 1244, 272, 4194560, 5, 6),
    ("02", "branch-mix", "8095c962d36b2a6876770412feac0df8fdd5f4e3627481f97f6b78f9bc489888", "68ef1e141aac58454b2b1dde0bcf8d2ea100c4faa1ee43323ce121b6471a86ad", "362c5dc7b3857358d2826b0a2f2dcbe376920514d948844a08c2b4433343ed42", "e4ea9e017940bd87d1f9dd5059149bd659add95b0a6d4b5d112f64345e1b35d3", 1167, 1439, 272, 4194560, 5, 6),
    ("03", "dot-product", "b2fa698b60cb29e50d14e7f56650d1f09657562e3160e99bc7930e60f7c9e857", "c3a3bb75473b90689646c413552de32005ea27594d0565b72cc1984c731b7a3b", "87ab3713c01593e5746e331ddf363fd500699d74c40d3b5db19ff72c2bc2b41a", "d7ea5990d1069328f2c139d8139ef3fcbbe6eaf7ab1d5d27b0a12fcd359e26f9", 929, 1201, 272, 4194560, 5, 6),
    ("04", "list-update", "c6ac1a97cad0ec0529e7f5f49bb91d316fa63a2b9abb2c7452a0040fe4150199", "de4e36706adc23c47bae3c95d0b45719867684423897b59b462e0cd937c6f982", "a0b5e4316250342f7c9739d4adf021036b3badcdef7f62a0aec7c4b2c79b6c17", "cd4d2e4d7d5b9965fd2c0ef32f081926382ed1917feb1485960819a198eac26c", 1043, 1315, 272, 4194560, 5, 6),
)
EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-elf.yml",
    "distribution/s4-performance/WP8F-ELF64-CONTRACT.tsv",
    "distribution/s4-performance/WP8F-NONCLAIMS.md",
    "distribution/s4-performance/WP8F-README.md",
    "naux-lang/examples/naux_s4_register_residency_elf.rs",
    "naux-lang/examples/support/s4_register_residency_elf.rs",
    "scripts/s4_register_residency_elf_authority.py",
    "scripts/tests/test_s4_register_residency_elf_authority.py",
)


class ElfAuthorityError(RuntimeError):
    """A fail-closed WP8F authority error."""


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
class ElfReport:
    root: str
    sha256: str
    kernels: tuple[tuple[str, ...], ...]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_regular(path: Path, label: str) -> bytes:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ElfAuthorityError(f"{label} is not regular")
    if before.st_size > MAX_FILE_BYTES:
        raise ElfAuthorityError(f"{label} exceeds the bounded input limit")
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ElfAuthorityError(f"{label} changed before open")
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
        raise ElfAuthorityError(f"{label} changed while read")
    return raw


def _canonical(raw: bytes, label: str) -> list[str]:
    if not raw or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise ElfAuthorityError(f"{label} has invalid extent or encoding")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ElfAuthorityError(f"{label} is not UTF-8") from error
    if any(not line or line != line.strip() for line in lines):
        raise ElfAuthorityError(f"{label} contains blank or padded rows")
    return lines


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    raw = _read_regular(path, path.name)
    lines = _canonical(raw, path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise ElfAuthorityError(f"{path.name} shape drifted")
    fields = lines[-1].split("\t")
    body = raw[: -(len(lines[-1]) + 1)]
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise ElfAuthorityError(f"{path.name} seal is malformed")
    if _sha256(domain + body) != fields[1]:
        raise ElfAuthorityError(f"{path.name} seal mismatch")
    return lines[1:-1], fields[1]


def parse_contract(path: Path) -> tuple[tuple[str, ...], ...]:
    lines, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if seal != CONTRACT_SEAL:
        raise ElfAuthorityError("WP8F accepted contract identity drifted")
    kernels = tuple(tuple(line.split("\t")[1:]) for line in lines if line.startswith("kernel\t"))
    expected = tuple(tuple(str(value) for value in row) for row in EXPECTED_KERNELS)
    if kernels != expected:
        raise ElfAuthorityError("WP8F contract kernel identities drifted")
    metadata = dict(line.split("\t")[1:] for line in lines if line.startswith("meta\t"))
    required = {
        "parent-wp8e-contract": WP8E_CONTRACT_SEAL,
        "parent-wp8e-authority": WP8E_AUTHORITY_SEAL,
        "parent-wp8e-report-root": WP8E_REPORT_ROOT,
        "status": "candidate-elf-structurally-admitted",
        "artifact-status": "report-hex-only",
        "native-execution-status": "forbidden",
        "measurement-status": "forbidden",
        "claim-status": "not-admitted",
        "entry": "4194560",
        "target-offset": "272",
        "load-flags": "5",
        "stack-flags": "6",
        "report-root": ELF_REPORT_ROOT,
        "report-sha256": ELF_REPORT_SHA256,
        "report-bytes": str(ELF_REPORT_BYTES),
        "report-lines": str(ELF_REPORT_LINES),
    }
    if any(metadata.get(key) != value for key, value in required.items()):
        raise ElfAuthorityError("WP8F contract metadata drifted")
    return kernels


def parse_authority(path: Path) -> Authority:
    lines, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    expected_metadata = (
        "meta\tscope\tS4",
        "meta\twork-package\tS4-WP8F",
        "meta\tauthority-id\ts4-one-hot-loop-index-r12-elf64-v1",
        "meta\tstatus\tcandidate-elf-structurally-admitted",
        "meta\tartifact-status\treport-hex-only",
        "meta\tnative-execution-status\tforbidden",
        "meta\tmeasurement-status\tforbidden",
        "meta\tclaim-status\tnot-admitted",
        f"meta\tfile-count\t{len(EXPECTED_FILES)}",
    )
    metadata = tuple(line for line in lines if line.startswith("meta\t"))
    if metadata != expected_metadata:
        raise ElfAuthorityError("WP8F authority metadata drifted")
    links = tuple(line for line in lines if line.startswith(("component\t", "parent\t")))
    if links != (
        f"component\telf-contract\tdistribution/s4-performance/WP8F-ELF64-CONTRACT.tsv\t{CONTRACT_SEAL}",
        f"parent\twp8e-contract\tdistribution/s4-performance/WP8E-CANDIDATE-ENCODING.tsv\t{WP8E_CONTRACT_SEAL}",
        f"parent\twp8e-authority\tdistribution/s4-performance/WP8E-AUTHORITY.tsv\t{WP8E_AUTHORITY_SEAL}",
    ):
        raise ElfAuthorityError("WP8F authority parent binding drifted")
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
            or fields[5] != "register-residency-elf64"
        ):
            raise ElfAuthorityError("WP8F authority file row is malformed")
        records.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in records) != EXPECTED_FILES:
        raise ElfAuthorityError("WP8F authority inventory drifted")
    return Authority(tuple(records), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        raw = _read_regular(path, record.path)
        mode = stat.S_IMODE(path.lstat().st_mode)
        if mode != record.mode & 0o777 or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise ElfAuthorityError(f"bound WP8F file drifted: {record.path}")


def _verify_quarantine(root: Path) -> None:
    validator = _read_regular(
        root / "scripts/s4_register_residency_elf_authority.py", "WP8F validator source"
    ).decode()
    rust_sources = "\n".join(
        _read_regular(root / path, path).decode()
        for path in (
            "naux-lang/examples/naux_s4_register_residency_elf.rs",
            "naux-lang/examples/support/s4_register_residency_elf.rs",
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
        "std::fs" + "::",
        "std::process::" + "Command",
        "Instant::" + "now",
        "SystemTime::" + "now",
        "lib" + "c::",
    )
    if any(token in validator for token in forbidden_validator) or any(
        token in rust_sources for token in forbidden_rust
    ):
        raise ElfAuthorityError("WP8F source crossed its no-file/no-execution/no-clock boundary")


def _u16(raw: bytes, offset: int) -> int:
    return int.from_bytes(raw[offset : offset + 2], "little")


def _u32(raw: bytes, offset: int) -> int:
    return int.from_bytes(raw[offset : offset + 4], "little")


def _u64(raw: bytes, offset: int) -> int:
    return int.from_bytes(raw[offset : offset + 8], "little")


def _verify_elf(raw: bytes, expected: tuple[object, ...]) -> None:
    target_bytes = int(expected[6])
    elf_bytes = int(expected[7])
    if len(raw) != elf_bytes or elf_bytes != 272 + target_bytes:
        raise ElfAuthorityError("ELF extent equation drifted")
    if (
        raw[:16] != b"\x7fELF\x02\x01\x01\x00\x00" + b"\0" * 7
        or _u16(raw, 16) != 2
        or _u16(raw, 18) != 62
        or _u32(raw, 20) != 1
        or _u64(raw, 24) != 4_194_560
        or _u64(raw, 32) != 64
        or _u64(raw, 40) != 0
        or _u32(raw, 48) != 0
        or (_u16(raw, 52), _u16(raw, 54), _u16(raw, 56)) != (64, 56, 2)
        or raw[58:64] != b"\0" * 6
    ):
        raise ElfAuthorityError("ELF header drifted")
    if (
        (_u32(raw, 64), _u32(raw, 68)) != (1, 5)
        or _u64(raw, 72) != 0
        or _u64(raw, 80) != 0x0040_0000
        or _u64(raw, 88) != 0x0040_0000
        or (_u64(raw, 96), _u64(raw, 104), _u64(raw, 112)) != (elf_bytes, elf_bytes, 4096)
    ):
        raise ElfAuthorityError("ELF load segment drifted")
    if (
        (_u32(raw, 120), _u32(raw, 124)) != (0x6474_E551, 6)
        or raw[128:168] != b"\0" * 40
        or _u64(raw, 168) != 16
        or raw[176:256] != b"\0" * 80
    ):
        raise ElfAuthorityError("ELF stack segment or header padding drifted")
    displacement = int.from_bytes(raw[257:261], "little", signed=True)
    if (
        raw[256] != 0xE8
        or 261 + displacement != 272
        or raw[261:272] != bytes.fromhex("31ffb83c0000000f050f0b")
    ):
        raise ElfAuthorityError("ELF startup drifted")
    target = raw[272:]
    if _sha256(target) != expected[4] or _sha256(raw) != expected[5]:
        raise ElfAuthorityError("ELF target or image hash drifted")


def parse_elf_report(raw: bytes) -> ElfReport:
    if len(raw) != ELF_REPORT_BYTES or _sha256(raw) != ELF_REPORT_SHA256:
        raise ElfAuthorityError("ELF report document identity drifted")
    lines = _canonical(raw, "ELF report")
    if len(lines) != ELF_REPORT_LINES or lines[0] != ELF_MAGIC:
        raise ElfAuthorityError("ELF report extent or magic drifted")
    body = raw[: -(len(lines[-1]) + 1)]
    if lines[-1] != f"report-root\t{ELF_REPORT_ROOT}" or _sha256(ELF_REPORT_DOMAIN + body) != ELF_REPORT_ROOT:
        raise ElfAuthorityError("ELF report root drifted")
    metadata = tuple(tuple(line.split("\t")[1:]) for line in lines[1:9])
    if metadata != EXPECTED_METADATA or lines[9] != EXPECTED_COLUMNS:
        raise ElfAuthorityError("ELF report metadata or columns drifted")
    index = 10
    kernels = []
    for expected in EXPECTED_KERNELS:
        fields = lines[index].split("\t")
        index += 1
        expected_fields = ["kernel", *(str(value) for value in expected)]
        if fields != expected_fields:
            raise ElfAuthorityError("ELF kernel row drifted")
        elf_fields = lines[index].split("\t")
        index += 1
        if (
            len(elf_fields) != 3
            or elf_fields[:2] != ["elf-hex", str(expected[0])]
            or not HEX_RE.fullmatch(elf_fields[2])
        ):
            raise ElfAuthorityError("ELF hex row is malformed")
        image = bytes.fromhex(elf_fields[2])
        _verify_elf(image, expected)
        kernels.append(tuple(fields[1:]))
    if lines[index : index + 2] != [
        "verification\tindependent-elf-parser-accepted",
        "verification\tno-file-no-execution-no-measurement",
    ] or index + 2 != len(lines) - 1:
        raise ElfAuthorityError("ELF report verification surface drifted")
    return ElfReport(ELF_REPORT_ROOT, ELF_REPORT_SHA256, tuple(kernels))


def validate(root: Path, report_path: Path) -> tuple[Authority, ElfReport, bytes, str]:
    root = root.resolve(strict=True)
    parse_contract(root / "distribution/s4-performance/WP8F-ELF64-CONTRACT.tsv")
    authority = parse_authority(root / "distribution/s4-performance/WP8F-AUTHORITY.tsv")
    _verify_files(root, authority)
    _verify_quarantine(root)
    wp8e.parse_contract(root / "distribution/s4-performance/WP8E-CANDIDATE-ENCODING.tsv")
    parent = wp8e.parse_authority(root / "distribution/s4-performance/WP8E-AUTHORITY.tsv")
    wp8e._verify_files(root, parent)
    wp8e._verify_quarantine(root, parent)
    if parent.seal != WP8E_AUTHORITY_SEAL:
        raise ElfAuthorityError("WP8E parent authority drifted")
    report = parse_elf_report(_read_regular(report_path, "ELF report"))
    rows = (
        REPORT_MAGIC,
        f"contract\t{CONTRACT_SEAL}",
        f"authority\t{authority.seal}",
        f"elf-report-root\t{report.root}",
        f"elf-report-sha256\t{report.sha256}",
        "status\tcandidate-elf-structurally-admitted",
        "artifact-status\treport-hex-only",
        "native-execution-status\tforbidden",
        "measurement-status\tforbidden",
        "claim-status\tnot-admitted",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root_hash = _sha256(REPORT_DOMAIN + body)
    return authority, report, body + f"report-root\t{root_hash}\n".encode(), root_hash


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        _, _, report, _ = validate(arguments.root, arguments.report)
        sys.stdout.buffer.write(report)
    except (ElfAuthorityError, wp8e.CandidateAuthorityError, OSError, ValueError) as error:
        print(f"WP8F validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
