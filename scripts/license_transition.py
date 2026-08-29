#!/usr/bin/env python3
"""Validate and replay the authority-preserving Apache-2.0 transition."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import s2_linguist_surface as s2
import s3_thesis_audit as s3
import s4_benchmark_authority as wp1
import s4_native_carrier as wp3
import s4_residual_elf64 as wp5d


CONTRACT_MAGIC = "NAUX-LICENSE-TRANSITION-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-LICENSE-TRANSITION-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-LICENSE-TRANSITION-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:license-transition:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:license-transition:authority:v1\0"
REPORT_DOMAIN = b"NAUX:license-transition:report:v1\0"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_TEXT_BYTES = 2_000_000
APACHE_HASH = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
PRE_COMMIT = "7d270a54c0af7530585fde7be4d9f3f67c15e142"
S2_SEAL = "031d82feef5f7f9c0ddab11d58059d3ca99384e49aa6f62b43bc8626ed0ee7c9"
S3_SEAL = "6fe6a1a75f003d491edf3dad6a36d4c8b115de94d4489f7bf9d2d12b3906ffe0"
WP1_SEAL = "b23533c4e96ec9e3b66482e96b79fdeb5985c823ce012d827e69eb1c14a4b659"
WP3_SEAL = "7a853a68da91a4d41f3fe6f7b9e9e21dd254a4d4ac36b248007e506bd046c9ab"

METADATA = (
    ("policy-version", "1.0.0"),
    ("pre-transition-commit", PRE_COMMIT),
    ("previous-license", "MIT"),
    ("current-license", "Apache-2.0"),
    ("apache-license-sha256", APACHE_HASH),
    ("transition-count", "21"),
    ("historical-s2-surface-seal", S2_SEAL),
    ("historical-s3-audit-seal", S3_SEAL),
    ("historical-s4-wp1-seal", WP1_SEAL),
    ("historical-s4-wp3-seal", WP3_SEAL),
)
GATES = (
    ("01", "exact-before-after-inventory", "required"),
    ("02", "canonical-apache-license", "required"),
    ("03", "legal-only-delta-replay", "required"),
    ("04", "historical-authority-snapshot", "required"),
    ("05", "current-target-identity", "required"),
    ("06", "claim-boundary", "not-admitted"),
)
TRANSITIONS = (
    ("01", "canonical-license-replacement", 1709, "38e567a0a3a4f4e62d3b41fab3621549c89e5f75c89a1bfebef83a8efff83c76", 11358, APACHE_HASH, "LICENSE"),
    ("02", "public-license-wording", 12139, "854371d4be8273765bba984bba77d7c00a879890925cce7854894ff8cdb50f0d", 12163, "66ed4e169a8bcbf6efcc721f07fada8da4d7d57e8c84411e944e1545b938a858", "README.md"),
    ("03", "spdx-license-metadata", 1062, "5e57d2f6c272250b04ea2bf69f9c783e9904537039fa62106ec0c578c3366285", 1069, "1579ebc71a1175fb25fc17d69b3f05c10e6b7cb629bcf209f9210f8f3bb56709", "naux-lang/Cargo.toml"),
    ("04", "canonical-license-replacement", 1709, "38e567a0a3a4f4e62d3b41fab3621549c89e5f75c89a1bfebef83a8efff83c76", 11358, APACHE_HASH, "naux-lang/LICENSE"),
    ("05", "generated-license-source", 3203, "3ef211811f7c6e61a41409ce558b225988ad00009c6594559c4590e66a49f1be", 2164, "43eec6e4c8a05b1757f8013b6eaaaa4a0da605fd251b67ed81c863284ce66645", "naux-lang/src/cli/new.rs"),
    ("06", "license-changelog", 826, "508f6410ecafda63fc89a8e743038c0b67ab717fb56e683a5a78642bc8ca6196", 895, "38d13c791a8f5ae210f5b6beb0b5b11a1858ab3751d6fa93edf6f008dcc5a4ef", "vscode/naux-lang/CHANGELOG.md"),
    ("07", "canonical-license-replacement", 1068, "2631cd0336d5597b274ad15c3c857596d39523e13b9209721d45274e701e7709", 11358, APACHE_HASH, "vscode/naux-lang/LICENSE"),
    ("08", "public-license-wording", 3534, "6434346e68da22c1fa19115922cfdffd3d3d9e631aec32689110c3ade373a798", 3563, "78679c85e71677a3bad36df23687d72f432d095a7e8aff9a282662b921598fa4", "vscode/naux-lang/README.md"),
    ("09", "spdx-license-metadata", 348, "46cea18a6c0415c7a10e0d2ae56d0a1a486eaeb55703affd0bec992c91ddf04d", 355, "432e7ee6a72642c170ac2fe942722011134b170b28c2f3b3a4749f32d812b9e0", "vscode/naux-lang/linguist-language.json"),
    ("10", "spdx-license-metadata", 1350, "4dfc29e799a9e1c8701ad8be1e3b36228b3f76c6f76398eda8605a23e046a717", 1357, "ba62738c2571c39a77d3c575efb5c006390d544e12cb889430177acdf412909d", "vscode/naux-lang/package.json"),
    ("11", "license-validation", 10042, "4bb02b2796df942f81b2e37c7368df683508a039470781b3e9e7f1ab48e040dc", 10340, "77eac3340f686a4a2c71aa9a2e844da935a6e96003c6f372ebb6d7cf5f0e51c4", "vscode/naux-lang/scripts/validate.mjs"),
    ("12", "authority-routing", 16959, "ff780cd579d7ae8bc89e74e43f87cc754885fa0cdc9dc670b646be7416e99173", 17281, "1f9834b64241381f16ab990bd969caa7556327d374b4e71b512d8b9b0093fbd1", ".github/workflows/ci.yml"),
    ("13", "authority-routing", 533, "a6273ceecf2677aebc7d1bba65e69db8e8832c55331967881deab9b5e3333c06", 769, "3eec7c0ca28cb8800a3c49a6fb28f01cfeda6ec41a06b97336c2679267a06338", ".github/workflows/s4-measurement-boundary.yml"),
    ("14", "authority-routing", 1152, "3e89422cbe22ec0bb22810e044e4070c29471de6697958e2da4d1253ab0baf64", 1495, "962133d795cc44e19a8fe0cbe463267a76e9f0abf6b6e96a8f488fb31a8ae5af", ".github/workflows/s4-native-carrier.yml"),
    ("15", "authority-routing", 1346, "132f6d6529f67cc8f0512e651791c47cb712fddab4b64b10c9d2edd90e23fa09", 1606, "c63bb410ca39b2d695583e7391ce4a534ee95aa31a20dc9b47af40d5b2124ecc", ".github/workflows/s4-performance-gap-forensics.yml"),
    ("16", "authority-routing", 719, "4ca435e5ab9f3c216d87f50979921589e31130dbea42cac77c9c82ecfebf0dff", 1004, "264c09dd123c39c3bc680f20142cb3988ee4b646160fafde83fde79eb4fc61fa", ".github/workflows/s4-reference-baselines.yml"),
    ("17", "authority-routing", 1361, "36e84c889e98cc1e7674e775f22bcd6628501d62753070da63dddf23b14e1e0a", 1704, "a47f36a06db85c7191fd00e040330d96bb6db8caf8ef3b3a6af8248332609cd9", ".github/workflows/s4-residual-elf64.yml"),
    ("18", "authority-routing", 1384, "9fdfe5590c2b05a82c194e1aa7f2ca1a0b7b62dbaa870dacba5ba313be432744", 1727, "3e5ab62796fc5db2a097228cb3c2d59b8ba576c2b8fa8054b5ffb923c2b78f3f", ".github/workflows/s4-residual-machine-ir.yml"),
    ("19", "authority-routing", 535, "c5d467d8c1b415bc79dd5ecd28b4c241f7be7dfec9cba0318b870c9ed30a2080", 771, "4c2edfab4a915fdb9e9d1bdebf36e24a260561fde297b90f52bc48a46ad17ce5", ".github/workflows/s4-residual-role.yml"),
    ("20", "authority-routing", 1360, "0cfaf318168b6e96e138f3d77d2f5b01150e678f9d0ac777650b87228f9a0ca4", 1703, "90707fb82e3a9e7c9e2e8faafbe4bbd8cc333af735199e4246d695bdbec3fbe6", ".github/workflows/s4-specialization-request.yml"),
    ("21", "authority-routing", 1387, "e7a7ff61d50f29c32b02a3fb1a56606e024d699e9a3041dcd45516e536cffdee", 1730, "de9347cb53a80e59175b281b1e372dc08c41bef561cf7df459832dc2789f9544", ".github/workflows/s4-structural-residual.yml"),
)

AUTHORITY_METADATA = (
    ("scope", "license-transition"),
    ("work-package", "LT1"),
    ("authority-id", "apache-2-transition-v1"),
    ("status", "transition-protocol-admitted"),
    ("claim-status", "not-admitted"),
    ("file-count", "28"),
)
EXPECTED_FILES = (
    ".github/workflows/license-transition.yml",
    "distribution/license-transition/LT1-CONTRACT.tsv",
    "distribution/license-transition/NONCLAIMS.md",
    "distribution/license-transition/README.md",
    "distribution/license-transition/pre-apache/LICENSE",
    "distribution/license-transition/pre-apache/README.md",
    "distribution/license-transition/pre-apache/naux-lang/Cargo.toml",
    "distribution/license-transition/pre-apache/naux-lang/LICENSE",
    "distribution/license-transition/pre-apache/naux-lang/src/cli/new.rs",
    "distribution/license-transition/pre-apache/vscode/naux-lang/CHANGELOG.md",
    "distribution/license-transition/pre-apache/vscode/naux-lang/LICENSE",
    "distribution/license-transition/pre-apache/vscode/naux-lang/README.md",
    "distribution/license-transition/pre-apache/vscode/naux-lang/linguist-language.json",
    "distribution/license-transition/pre-apache/vscode/naux-lang/package.json",
    "distribution/license-transition/pre-apache/vscode/naux-lang/scripts/validate.mjs",
    "distribution/license-transition/pre-apache/.github/workflows/ci.yml",
    "distribution/license-transition/pre-apache/.github/workflows/s4-measurement-boundary.yml",
    "distribution/license-transition/pre-apache/.github/workflows/s4-native-carrier.yml",
    "distribution/license-transition/pre-apache/.github/workflows/s4-performance-gap-forensics.yml",
    "distribution/license-transition/pre-apache/.github/workflows/s4-reference-baselines.yml",
    "distribution/license-transition/pre-apache/.github/workflows/s4-residual-elf64.yml",
    "distribution/license-transition/pre-apache/.github/workflows/s4-residual-machine-ir.yml",
    "distribution/license-transition/pre-apache/.github/workflows/s4-residual-role.yml",
    "distribution/license-transition/pre-apache/.github/workflows/s4-specialization-request.yml",
    "distribution/license-transition/pre-apache/.github/workflows/s4-structural-residual.yml",
    "scripts/license_transition.py",
    "scripts/tests/test_license_transition_replay.py",
    "scripts/tests/test_license_transition_static.py",
)


class TransitionError(RuntimeError):
    """A fail-closed license-transition validation error."""


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
    report: bytes
    report_root: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(raw: bytes, label: str) -> list[str]:
    if not raw or len(raw) > MAX_TEXT_BYTES or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise TransitionError(f"{label} has invalid extent or encoding")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TransitionError(f"{label} is not UTF-8") from error
    lines = text.splitlines()
    if any(not line or line != line.strip() for line in lines):
        raise TransitionError(f"{label} contains blank or padded rows")
    return lines


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    try:
        info = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise TransitionError(f"cannot read {path}") from error
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise TransitionError(f"{path.name} is not a regular file")
    lines = _canonical(raw, path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise TransitionError(f"{path.name} magic or shape drifted")
    fields = lines[-1].split("\t")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]) or _sha256(domain + body) != fields[1]:
        raise TransitionError(f"{path.name} seal mismatch")
    return lines[1:-1], fields[1]


def parse_contract(path: Path) -> Contract:
    rows, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    expected = [f"meta\t{k}\t{v}" for k, v in METADATA]
    expected.extend(
        f"transition\t{o}\t{kind}\t{before_size}\t{before_hash}\t{after_size}\t{after_hash}\t{relative}"
        for o, kind, before_size, before_hash, after_size, after_hash, relative in TRANSITIONS
    )
    expected.extend(f"gate\t{o}\t{name}\t{value}" for o, name, value in GATES)
    if rows != expected:
        raise TransitionError("LT1 contract metadata, transitions, or gates drifted")
    return Contract(seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    rows, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    prefix = [f"meta\t{k}\t{v}" for k, v in AUTHORITY_METADATA]
    prefix.append(f"component\ttransition-contract\tdistribution/license-transition/LT1-CONTRACT.tsv\t{contract_seal}")
    if rows[: len(prefix)] != prefix:
        raise TransitionError("LT1 authority metadata or component binding drifted")
    records: list[FileRecord] = []
    for expected, row in zip(EXPECTED_FILES, rows[len(prefix) :]):
        fields = row.split("\t")
        if len(fields) != 5 or fields[0] != "file" or fields[4] != expected:
            raise TransitionError("LT1 authority file inventory drifted")
        try:
            mode, size = int(fields[1], 8), int(fields[2])
        except ValueError as error:
            raise TransitionError("LT1 authority mode or size is invalid") from error
        if mode != 0o100644 or size < 0 or not HASH_RE.fullmatch(fields[3]):
            raise TransitionError("LT1 authority file record is outside policy")
        records.append(FileRecord(mode, size, fields[3], fields[4]))
    if len(records) != len(EXPECTED_FILES) or len(prefix) + len(records) != len(rows):
        raise TransitionError("LT1 authority extent drifted")
    return Authority(tuple(records), seal)


def _regular_bytes(path: Path, expected_mode: int = 0o644) -> bytes:
    try:
        info = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise TransitionError(f"cannot read {path}") from error
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != expected_mode:
        raise TransitionError(f"file type or mode drifted: {path}")
    return raw


def _verify_authority_files(root: Path, authority: Authority) -> None:
    if tuple(record.path for record in authority.files) != EXPECTED_FILES:
        raise TransitionError("LT1 authority does not bind the exact file set")
    for record in authority.files:
        raw = _regular_bytes(root / record.path)
        mode = stat.S_IFREG | 0o644
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise TransitionError(f"LT1 authority member drifted: {record.path}")


def _verify_inventory(root: Path) -> None:
    snapshot_root = root / "distribution/license-transition/pre-apache"
    for _ordinal, _kind, before_size, before_hash, after_size, after_hash, relative in TRANSITIONS:
        before = _regular_bytes(snapshot_root / relative)
        after = _regular_bytes(root / relative)
        if len(before) != before_size or _sha256(before) != before_hash:
            raise TransitionError(f"pre-Apache snapshot drifted: {relative}")
        if len(after) != after_size or _sha256(after) != after_hash:
            raise TransitionError(f"current Apache surface drifted: {relative}")


def _replace_once(raw: bytes, before: bytes, after: bytes, label: str) -> bytes:
    if raw.count(before) != 1:
        raise TransitionError(f"{label} legal delta anchor is not unique")
    return raw.replace(before, after, 1)


def _verify_legal_deltas(root: Path) -> None:
    snapshots = root / "distribution/license-transition/pre-apache"
    apache = _regular_bytes(root / "LICENSE")
    if _sha256(apache) != APACHE_HASH:
        raise TransitionError("root LICENSE is not the canonical Apache-2.0 text")
    for relative in ("naux-lang/LICENSE", "vscode/naux-lang/LICENSE"):
        if _regular_bytes(root / relative) != apache:
            raise TransitionError(f"Apache license copy diverged: {relative}")

    def before(relative: str) -> bytes:
        return _regular_bytes(snapshots / relative)

    def current(relative: str) -> bytes:
        return _regular_bytes(root / relative)

    generated = before("README.md")
    generated = _replace_once(generated, b"license-MIT-green", b"license-Apache--2.0-green", "root README badge")
    generated = _replace_once(generated, b"canonical MIT-licensed NAUX grammar", b"canonical Apache-2.0 NAUX grammar", "root README grammar")
    generated = _replace_once(
        generated,
        b"NAUX is licensed under the MIT License and provided without warranty.\n",
        b"NAUX is licensed under the [Apache License 2.0](LICENSE) and provided without\nwarranty.\n",
        "root README license",
    )
    if generated != current("README.md"):
        raise TransitionError("root README contains a non-legal transition delta")

    generated = _replace_once(before("naux-lang/Cargo.toml"), b'license = "MIT"', b'license = "Apache-2.0"', "Cargo license")
    if generated != current("naux-lang/Cargo.toml"):
        raise TransitionError("Cargo manifest contains a non-license transition delta")

    old_new = before("naux-lang/src/cli/new.rs")
    start = old_new.find(b'const LICENSE: &str = r#"MIT License')
    end = old_new.find(b'"#;\n', start)
    if start < 0 or end < 0:
        raise TransitionError("generated-license source anchor drifted")
    generated = old_new[:start] + b'const LICENSE: &str = include_str!("../../LICENSE");\n' + old_new[end + 4 :]
    if generated != current("naux-lang/src/cli/new.rs"):
        raise TransitionError("new-project scaffold contains a non-license transition delta")

    generated = before("vscode/naux-lang/CHANGELOG.md")
    generated = _replace_once(generated, b"# Changelog\n\n", b"# Changelog\n\n## Unreleased\n\n- Re-license the current language-support package under Apache-2.0.\n\n", "grammar changelog")
    generated = _replace_once(generated, b"- Publish the canonical MIT-licensed TextMate grammar and Linguist candidate\n  identity.\n", b"- Publish the canonical TextMate grammar and Linguist candidate identity.\n", "grammar history wording")
    if generated != current("vscode/naux-lang/CHANGELOG.md"):
        raise TransitionError("grammar changelog contains a non-license transition delta")

    generated = before("vscode/naux-lang/README.md")
    for old, new in (
        (b"self-contained, MIT-licensed", b"self-contained, Apache-2.0-licensed"),
        (b"| Grammar license | MIT |", b"| Grammar license | Apache-2.0 |"),
        (b"standalone MIT grant", b"standalone Apache License 2.0 grant"),
    ):
        generated = _replace_once(generated, old, new, "grammar README")
    if generated != current("vscode/naux-lang/README.md"):
        raise TransitionError("grammar README contains a non-license transition delta")

    for relative in ("vscode/naux-lang/package.json", "vscode/naux-lang/linguist-language.json"):
        old_object = json.loads(before(relative))
        new_object = json.loads(current(relative))
        if new_object.get("license") != "Apache-2.0":
            raise TransitionError(f"Apache SPDX identity missing: {relative}")
        new_object["license"] = "MIT"
        if new_object != old_object:
            raise TransitionError(f"JSON contains a non-license transition delta: {relative}")

    generated = before("vscode/naux-lang/scripts/validate.mjs")
    generated = _replace_once(generated, b'const snippets = readJson(join(packageRoot, "snippets/naux.json"));\n', b'const snippets = readJson(join(packageRoot, "snippets/naux.json"));\nconst license = readFileSync(join(packageRoot, "LICENSE"), "utf8");\n', "validator license read")
    generated = _replace_once(generated, b'  license: "MIT",', b'  license: "Apache-2.0",', "validator SPDX")
    anchor = b'assert.equal(packageJson.license, identity.license);\n'
    assertion = anchor + b'assert.ok(\n  license.includes("Apache License") &&\n    license.includes("Version 2.0, January 2004") &&\n    license.includes("END OF TERMS AND CONDITIONS"),\n  "LICENSE must contain the canonical Apache License 2.0 text"\n);\n'
    generated = _replace_once(generated, anchor, assertion, "validator Apache assertion")
    if generated != current("vscode/naux-lang/scripts/validate.mjs"):
        raise TransitionError("grammar validator contains a non-license transition delta")

    for *_fields, relative in TRANSITIONS:
        if not relative.startswith(".github/workflows/"):
            continue
        old_lines = before(relative).decode().splitlines()
        new_lines = current(relative).decode().splitlines()
        additions = []
        removals = []
        for line in difflib.ndiff(old_lines, new_lines):
            if line.startswith("+ "):
                additions.append(line[2:])
            elif line.startswith("- "):
                removals.append(line[2:])
        if not any("--materialize-historical /tmp/naux-pre-apache" in line for line in additions):
            raise TransitionError(f"workflow does not materialize the historical authority: {relative}")
        if any(
            "/tmp/naux-pre-apache" not in line
            and "Materialize the sealed pre-Apache authority view" not in line
            and "${{ github.workspace }}" not in line
            for line in additions
        ):
            raise TransitionError(f"workflow contains a non-routing addition: {relative}")
        if any(
            "python3 scripts/" not in line
            and "python3 -m unittest" not in line
            and "target/" not in line
            for line in removals
        ):
            raise TransitionError(f"workflow contains a non-routing removal: {relative}")


def _report(contract: Contract, authority: Authority, historical: bool, target_identity: bool) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract-seal\t{contract.seal}",
        f"authority-seal\t{authority.seal}",
        "transition-count\t21",
        "current-license\tApache-2.0",
        "inventory-status\texact",
        "legal-delta-status\texact",
        f"historical-authority-status\t{'replayed' if historical else 'pending-explicit-replay'}",
        f"current-target-identity\t{'identical' if target_identity else 'pending-explicit-replay'}",
        "claim-status\tnot-admitted",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    report_root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{report_root}\n".encode(), report_root


def validate(root: Path) -> Admission:
    contract = parse_contract(root / "distribution/license-transition/LT1-CONTRACT.tsv")
    authority = parse_authority(root / "distribution/license-transition/LT1-AUTHORITY.tsv", contract.seal)
    _verify_authority_files(root, authority)
    _verify_inventory(root)
    _verify_legal_deltas(root)
    report, report_root = _report(contract, authority, False, False)
    return Admission(contract, authority, report, report_root)


def materialize_historical(root: Path, destination: Path) -> Path:
    if destination.exists():
        raise TransitionError("historical destination already exists")
    if destination == root or root in destination.parents:
        raise TransitionError("historical destination must be outside the repository")
    try:
        listed = subprocess.run(
            ["git", "-C", os.fspath(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        if listed.returncode != 0 or listed.stderr or not listed.stdout.endswith(b"\0"):
            raise TransitionError("cannot enumerate the bounded repository view")
        names = listed.stdout[:-1].split(b"\0")
        if not names or len(names) != len(set(names)):
            raise TransitionError("bounded repository inventory is empty or duplicated")
        destination.mkdir(mode=0o700)
        for encoded in names:
            try:
                relative = encoded.decode("utf-8")
            except UnicodeDecodeError as error:
                raise TransitionError("repository path is not UTF-8") from error
            candidate = Path(relative)
            if candidate.is_absolute() or ".." in candidate.parts or relative != candidate.as_posix():
                raise TransitionError("repository path is not canonical and relative")
            source = root / candidate
            info = source.lstat()
            if source.is_symlink() or not stat.S_ISREG(info.st_mode):
                raise TransitionError(f"bounded repository member is not regular: {relative}")
            target = destination / candidate
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        snapshots = root / "distribution/license-transition/pre-apache"
        for *_fields, relative in TRANSITIONS:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(snapshots / relative, target)
    except OSError as error:
        raise TransitionError("cannot materialize historical snapshot") from error
    return destination


def replay_historical(view: Path) -> None:
    lock = s2.parse_lock(view / "distribution/s2-preview/LINGUIST-SURFACE.tsv")
    if lock.seal != S2_SEAL:
        raise TransitionError("historical S2 seal drifted")
    s2.verify_files(view / "vscode/naux-lang", lock)
    s2.verify_identity(view / "vscode/naux-lang", lock)
    if s3.verify_bundle(view, view / "distribution/s3-thesis/AUDIT.tsv").seal != S3_SEAL:
        raise TransitionError("historical S3 seal drifted")
    if wp1.validate(view).authority.seal != WP1_SEAL:
        raise TransitionError("historical WP1 seal drifted")
    if wp3.validate(view).authority.seal != WP3_SEAL:
        raise TransitionError("historical WP3 seal drifted")


def _candidate_bytes(admission: wp5d.Admission, binary: Path) -> bytes:
    _report_bytes, candidate = wp5d.replay(admission, binary)
    return candidate.raw


def replay(root: Path, admission: Admission, historical_root: Path, current_binary: Path, historical_binary: Path) -> tuple[bytes, str]:
    replay_historical(historical_root)
    historical_admission = wp5d.validate(historical_root)
    current = _candidate_bytes(historical_admission, current_binary)
    historical = _candidate_bytes(historical_admission, historical_binary)
    if current != historical:
        raise TransitionError("Apache transition changed WP5D target output")
    report, report_root = _report(admission.contract, admission.authority, True, True)
    return report, report_root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--materialize-historical", type=Path)
    parser.add_argument("--historical-root", type=Path)
    parser.add_argument("--current-binary", type=Path)
    parser.add_argument("--historical-binary", type=Path)
    arguments = parser.parse_args(argv)
    try:
        root = arguments.root.resolve()
        admission = validate(root)
        if arguments.materialize_historical is not None:
            materialize_historical(root, arguments.materialize_historical.resolve())
            print(arguments.materialize_historical.resolve())
            return 0
        replay_args = (arguments.historical_root, arguments.current_binary, arguments.historical_binary)
        if any(value is not None for value in replay_args):
            if not all(value is not None for value in replay_args):
                raise TransitionError("historical replay requires all three replay arguments")
            report, _ = replay(root, admission, arguments.historical_root.resolve(), arguments.current_binary.resolve(), arguments.historical_binary.resolve())
            sys.stdout.buffer.write(report)
        else:
            sys.stdout.buffer.write(admission.report)
    except (TransitionError, s2.SurfaceError, s3.AuditError, wp1.AuthorityError, wp3.CarrierError, wp5d.Elf64Error, OSError, subprocess.TimeoutExpired) as error:
        print(f"LT1 validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
