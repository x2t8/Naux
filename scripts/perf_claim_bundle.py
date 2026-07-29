#!/usr/bin/env python3
"""Build a deterministic, fail-closed Naux performance evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Iterable


REQUIRED_IMPLEMENTATIONS = {"naux", "c", "cpp", "go", "rust", "zig"}
REQUIRED_BENCHMARKS = {"sum_dense", "list_update", "dot_product", "branch_mix"}
DEFAULT_SOURCE_PATHS = (
    ".github/workflows/ci.yml",
    "Cargo.lock",
    "Cargo.toml",
    "PERF_CONTRACT.md",
    "docs/benchmarks.md",
    "scripts/bench_cross_language.sh",
    "scripts/perf_claim_bundle.py",
    "naux-lang/Cargo.toml",
    "naux-lang/examples/bench_sum_dense.nx",
    "naux-lang/examples/bench_list_update.nx",
    "naux-lang/examples/bench_dot_product.nx",
    "naux-lang/examples/bench_branch_mix.nx",
    "benchmarks/c/bench_sum_dense.c",
    "benchmarks/c/bench_list_update.c",
    "benchmarks/c/bench_dot_product.c",
    "benchmarks/c/bench_branch_mix.c",
    "benchmarks/cpp/bench_baselines.cpp",
    "benchmarks/go/bench_sum_dense.go",
    "benchmarks/go/bench_list_update.go",
    "benchmarks/go/bench_dot_product.go",
    "benchmarks/go/bench_branch_mix.go",
    "benchmarks/rust/Cargo.toml",
    "benchmarks/rust/src/bin/bench_sum_dense.rs",
    "benchmarks/rust/src/bin/bench_list_update.rs",
    "benchmarks/rust/src/bin/bench_dot_product.rs",
    "benchmarks/rust/src/bin/bench_branch_mix.rs",
    "benchmarks/zig/bench_baselines.zig",
)


class BundleError(RuntimeError):
    """The evidence is not safe to package for publication."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BundleError(f"missing report: {path}") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BundleError(f"invalid report {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise BundleError("report root must be a JSON object")
    return payload


def _required_mapping(parent: dict, key: str) -> dict:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise BundleError(f"report field `{key}` must be an object")
    return value


def _positive_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise BundleError(f"report field `{field}` must be a positive integer")
    return value


def _non_negative_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise BundleError(f"report field `{field}` must be a non-negative number")
    return float(value)


def _positive_integer_string(value: object, field: str) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError) as exc:
        raise BundleError(f"environment field `{field}` must be a positive integer") from exc
    if parsed <= 0:
        raise BundleError(f"environment field `{field}` must be a positive integer")
    return parsed


def validate_report(payload: dict) -> None:
    if payload.get("schema_version") != 2:
        raise BundleError("cross-language report schema_version must be 2")
    if payload.get("status") != "pass":
        raise BundleError("cross-language report status must be `pass`")
    generated_at = payload.get("generated_at_utc")
    if not isinstance(generated_at, str) or not generated_at.endswith("Z"):
        raise BundleError("report must contain a UTC generation timestamp")

    claim = _required_mapping(payload, "claim")
    if claim.get("eligible") is not True:
        raise BundleError("claim.eligible must be true")
    blockers = claim.get("blockers")
    if blockers != []:
        raise BundleError("claim.blockers must be an empty list")
    thresholds = _required_mapping(claim, "thresholds")
    minimum_samples = _positive_int(
        thresholds.get("minimum_samples_per_implementation"),
        "claim.thresholds.minimum_samples_per_implementation",
    )
    minimum_warmup = _non_negative_number(
        thresholds.get("minimum_warmup_ms"),
        "claim.thresholds.minimum_warmup_ms",
    )
    maximum_cv = _non_negative_number(
        thresholds.get("maximum_cv_pct"),
        "claim.thresholds.maximum_cv_pct",
    )
    kind = claim.get("kind")
    if kind not in {"baseline-observation", "competitive"}:
        raise BundleError("claim.kind must be `baseline-observation` or `competitive`")
    if kind == "competitive" and not (
        thresholds.get("require_naux_beat_c") is True
        or thresholds.get("require_naux_beat_cpp") is True
    ):
        raise BundleError("competitive claim must enable at least one comparison threshold")

    workload = _required_mapping(payload, "workload")
    if workload.get("engine") != "jit":
        raise BundleError("claim bundle requires the Naux JIT engine")
    iters = _positive_int(workload.get("iters"), "workload.iters")
    sample_count = _positive_int(
        workload.get("sample_count_per_implementation"),
        "workload.sample_count_per_implementation",
    )
    warmup_ms = _non_negative_number(workload.get("warmup_ms"), "workload.warmup_ms")
    if iters != sample_count:
        raise BundleError("workload sample count must equal iters")
    if sample_count < minimum_samples:
        raise BundleError(
            f"sample count {sample_count} is below claim minimum {minimum_samples}"
        )
    if warmup_ms < minimum_warmup:
        raise BundleError(f"warmup {warmup_ms}ms is below claim minimum {minimum_warmup}ms")
    statistics = workload.get("statistics")
    if not isinstance(statistics, list) or not {
        "median_ns",
        "p95_ns",
        "cv_pct",
    }.issubset(statistics):
        raise BundleError("workload statistics must include median_ns, p95_ns, and cv_pct")
    if workload.get("cv_definition") != (
        "population standard deviation / arithmetic mean * 100"
    ):
        raise BundleError("workload CV definition is missing or unsupported")
    if not isinstance(workload.get("outlier_policy"), str):
        raise BundleError("workload outlier policy is missing")
    timed_region = workload.get("timed_region")
    if not isinstance(timed_region, str) or "allocation" not in timed_region:
        raise BundleError("workload timed region must explicitly include input allocation")
    definitions = workload.get("definitions")
    if not isinstance(definitions, dict) or set(definitions) != REQUIRED_BENCHMARKS:
        raise BundleError("workload definitions must cover every benchmark")
    if not all(isinstance(description, str) and description for description in definitions.values()):
        raise BundleError("workload definitions must be non-empty")

    environment = _required_mapping(payload, "environment")
    for field in (
        "platform",
        "machine",
        "cpu_model",
        "physical_core_count",
        "logical_core_count",
        "memory_bytes",
        "target_triple",
        "git_sha",
    ):
        value = environment.get(field)
        if value in (None, "", "unknown", "unavailable"):
            raise BundleError(f"environment fingerprint field `{field}` is missing")
    for field in ("physical_core_count", "logical_core_count", "memory_bytes"):
        _positive_integer_string(environment.get(field), field)
    git_sha = str(environment["git_sha"])
    if len(git_sha) != 40 or any(char not in "0123456789abcdef" for char in git_sha.lower()):
        raise BundleError("environment git_sha must be a full hexadecimal commit ID")
    if environment.get("git_dirty") is not False:
        raise BundleError("report must come from a clean worktree")
    if environment.get("pin_status") != "pinned":
        raise BundleError("report must come from a pinned CPU run")
    if environment.get("governor") != "performance":
        raise BundleError("report must use the performance CPU governor")
    if environment.get("intel_no_turbo") != "1":
        raise BundleError("report must record Intel turbo disabled")

    toolchains = _required_mapping(payload, "toolchains")
    for toolchain in ("rustc", "cc", "cpp", "go", "zig"):
        if toolchains.get(toolchain) in (None, "", "missing", "unknown"):
            raise BundleError(f"toolchain `{toolchain}` is missing")
    coverage = _required_mapping(payload, "coverage")
    for implementation in REQUIRED_IMPLEMENTATIONS:
        if coverage.get(implementation) != "measured":
            raise BundleError(f"implementation `{implementation}` was not measured")
    build_flags = _required_mapping(payload, "build_flags")
    build_profiles = _required_mapping(payload, "build_profiles")
    for implementation in REQUIRED_IMPLEMENTATIONS:
        if not isinstance(build_flags.get(implementation), str):
            raise BundleError(f"build flags missing for `{implementation}`")
        if not isinstance(build_profiles.get(implementation), str):
            raise BundleError(f"build profile missing for `{implementation}`")

    reproduction = _required_mapping(payload, "reproduction")
    command = reproduction.get("command")
    if not isinstance(command, str) or "bench_cross_language.sh" not in command:
        raise BundleError("reproduction command is missing or invalid")

    evidence_sha256 = payload.get("evidence_sha256")
    if not isinstance(evidence_sha256, dict):
        raise BundleError("report evidence_sha256 must be an object")
    expected_evidence_names = required_hashed_evidence_names()
    if set(evidence_sha256) != expected_evidence_names:
        missing = sorted(expected_evidence_names - set(evidence_sha256))
        extra = sorted(set(evidence_sha256) - expected_evidence_names)
        raise BundleError(f"evidence hash coverage mismatch; missing={missing}, extra={extra}")
    for name, digest in evidence_sha256.items():
        if not isinstance(digest, str) or len(digest) != 64 or any(
            char not in "0123456789abcdef" for char in digest.lower()
        ):
            raise BundleError(f"invalid SHA-256 for evidence `{name}`")

    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise BundleError("report rows must be a list")
    expected_pairs = {
        (benchmark, implementation)
        for benchmark in REQUIRED_BENCHMARKS
        for implementation in REQUIRED_IMPLEMENTATIONS
    }
    actual_pairs: set[tuple[str, str]] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise BundleError(f"row {index} must be an object")
        pair = (row.get("benchmark"), row.get("implementation"))
        if pair in actual_pairs:
            raise BundleError(f"duplicate benchmark row: {pair}")
        actual_pairs.add(pair)
        if row.get("checksum_match") is not True:
            raise BundleError(f"checksum parity failed for {pair}")
        if row.get("claim_stable") is not True:
            raise BundleError(f"unstable samples cannot be claimed for {pair}")
        cv_pct = _non_negative_number(row.get("cv_pct"), f"rows[{index}].cv_pct")
        if cv_pct > maximum_cv:
            raise BundleError(f"CV {cv_pct}% exceeds {maximum_cv}% for {pair}")
        _positive_int(row.get("median_ns"), f"rows[{index}].median_ns")
        _positive_int(row.get("p95_ns"), f"rows[{index}].p95_ns")
    if actual_pairs != expected_pairs:
        missing = sorted(expected_pairs - actual_pairs)
        extra = sorted(actual_pairs - expected_pairs)
        raise BundleError(f"row coverage mismatch; missing={missing}, extra={extra}")

    naux_execution = _required_mapping(payload, "naux_execution")
    if set(naux_execution) != REQUIRED_BENCHMARKS:
        raise BundleError("naux_execution must cover every benchmark")
    for benchmark, execution in naux_execution.items():
        if not isinstance(execution, dict):
            raise BundleError(f"naux_execution.{benchmark} must be an object")
        if execution.get("requested_engine") != "jit":
            raise BundleError(f"{benchmark} did not request the JIT engine")
        if execution.get("fallback") is not False:
            raise BundleError(f"{benchmark} used a fallback backend")
        _positive_int(
            execution.get("trace_count"),
            f"naux_execution.{benchmark}.trace_count",
        )
        _non_negative_number(
            execution.get("deopts"),
            f"naux_execution.{benchmark}.deopts",
        )
        _non_negative_number(
            execution.get("internal_side_exits"),
            f"naux_execution.{benchmark}.internal_side_exits",
        )
        _non_negative_number(
            execution.get("static_branches"),
            f"naux_execution.{benchmark}.static_branches",
        )
    branch_execution = naux_execution["branch_mix"]
    if branch_execution["internal_side_exits"] != 0:
        raise BundleError("branch_mix must stay in native internal control flow")
    if branch_execution["static_branches"] < 3:
        raise BundleError("branch_mix native branch coverage is missing")


def verify_repo_state(repo_root: Path, payload: dict) -> None:
    try:
        current_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise BundleError(f"cannot verify repository state: {exc}") from exc

    report_sha = payload["environment"]["git_sha"]
    if current_sha != report_sha:
        raise BundleError(f"report git SHA {report_sha} does not match checkout {current_sha}")
    if status.strip():
        raise BundleError("current checkout is dirty; source/report binding is unproven")


def required_evidence_paths(report_path: Path, zig_measured: bool = True) -> list[Path]:
    root = report_path.parent
    paths = [
        report_path,
        root / "cross_language.md",
        root / "cross_language.tsv",
    ]
    implementations = ["naux", "c", "cpp", "go", "rust"]
    if zig_measured:
        implementations.append("zig")
    for benchmark in sorted(REQUIRED_BENCHMARKS):
        paths.append(root / f"{benchmark}.naux.validation.log")
        paths.extend(root / f"{benchmark}.{implementation}.log" for implementation in implementations)
    return paths


def required_hashed_evidence_names() -> set[str]:
    names = {"cross_language.tsv"}
    for benchmark in REQUIRED_BENCHMARKS:
        names.add(f"{benchmark}.naux.validation.log")
        names.update(
            f"{benchmark}.{implementation}.log"
            for implementation in REQUIRED_IMPLEMENTATIONS
        )
    return names


def verify_evidence_hashes(report_path: Path, payload: dict) -> None:
    expected = payload["evidence_sha256"]
    for path in required_evidence_paths(report_path):
        if path.name not in expected:
            continue
        data = _read_required(path, "hashed evidence artifact")
        actual = sha256_bytes(data)
        if actual != expected[path.name]:
            raise BundleError(
                f"evidence hash mismatch for {path.name}: expected {expected[path.name]}, got {actual}"
            )


def _read_required(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError as exc:
        raise BundleError(f"missing {label}: {path}") from exc
    except OSError as exc:
        raise BundleError(f"cannot read {label} {path}: {exc}") from exc


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.size = size
    info.mtime = 0
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def _reproduction_text(payload: dict) -> bytes:
    command = payload["reproduction"]["command"]
    git_sha = payload["environment"]["git_sha"]
    return (
        "# Naux Performance Evidence Reproduction\n\n"
        f"1. Check out Git SHA `{git_sha}` on the recorded hardware class.\n"
        "2. Apply the CPU governor, turbo, and pinning policy recorded in "
        "`evidence/cross_language.json`.\n"
        "3. Run:\n\n"
        "```bash\n"
        f"{command}\n"
        "```\n\n"
        "The command must finish with `claim_eligible=true` before replacing "
        "this bundle.\n"
    ).encode("utf-8")


def build_bundle(
    report_path: Path,
    out_path: Path,
    repo_root: Path,
    *,
    source_paths: Iterable[str] = DEFAULT_SOURCE_PATHS,
    enforce_repo_state: bool = True,
) -> tuple[Path, Path, dict]:
    report_path = report_path.resolve()
    repo_root = repo_root.resolve()
    payload = read_json(report_path)
    validate_report(payload)
    verify_evidence_hashes(report_path, payload)
    if enforce_repo_state:
        verify_repo_state(repo_root, payload)

    entries: dict[str, bytes] = {}
    for evidence_path in required_evidence_paths(report_path):
        entries[f"evidence/{evidence_path.name}"] = _read_required(
            evidence_path, "evidence artifact"
        )
    for relative in source_paths:
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise BundleError(f"unsafe source path: {relative}")
        entries[f"source/{relative_path.as_posix()}"] = _read_required(
            repo_root / relative_path, "source artifact"
        )
    entries["REPRODUCE.md"] = _reproduction_text(payload)

    manifest_entries = [
        {
            "path": name,
            "sha256": sha256_bytes(data),
            "size_bytes": len(data),
        }
        for name, data in sorted(entries.items())
    ]
    manifest = {
        "schema_version": 1,
        "bundle_kind": "naux-performance-evidence",
        "generated_at_utc": payload["generated_at_utc"],
        "git_sha": payload["environment"]["git_sha"],
        "claim_kind": payload["claim"]["kind"],
        "report_sha256": sha256_bytes(entries["evidence/cross_language.json"]),
        "reproduction_command": payload["reproduction"]["command"],
        "entries": manifest_entries,
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=out_path.parent, prefix=f".{out_path.name}.", suffix=".tmp", delete=False
    ) as temporary:
        temporary_path = Path(temporary.name)
    try:
        with tarfile.open(temporary_path, "w", format=tarfile.PAX_FORMAT) as archive:
            archive.addfile(
                _tar_info("bundle_manifest.json", len(manifest_bytes)),
                io.BytesIO(manifest_bytes),
            )
            for name, data in sorted(entries.items()):
                archive.addfile(_tar_info(name, len(data)), io.BytesIO(data))
        os.replace(temporary_path, out_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()

    bundle_hash = sha256_bytes(out_path.read_bytes())
    checksum_path = out_path.with_suffix(out_path.suffix + ".sha256")
    checksum_path.write_text(f"{bundle_hash}  {out_path.name}\n", encoding="utf-8")
    return out_path, checksum_path, manifest


def verify_bundle(
    bundle_path: Path,
    checksum_path: Path | None = None,
) -> dict:
    bundle_path = bundle_path.resolve()
    checksum_path = (
        bundle_path.with_suffix(bundle_path.suffix + ".sha256")
        if checksum_path is None
        else checksum_path.resolve()
    )
    bundle_data = _read_required(bundle_path, "claim bundle")
    checksum_data = _read_required(checksum_path, "claim bundle checksum")
    try:
        checksum_line = checksum_data.decode("utf-8").strip()
    except UnicodeError as exc:
        raise BundleError("claim bundle checksum is not UTF-8") from exc
    checksum_parts = checksum_line.split()
    if len(checksum_parts) != 2 or checksum_parts[1] != bundle_path.name:
        raise BundleError("claim bundle checksum sidecar has an invalid shape")
    expected_bundle_hash = checksum_parts[0]
    if len(expected_bundle_hash) != 64 or any(
        char not in "0123456789abcdef" for char in expected_bundle_hash.lower()
    ):
        raise BundleError("claim bundle checksum sidecar has an invalid SHA-256")
    actual_bundle_hash = sha256_bytes(bundle_data)
    if actual_bundle_hash != expected_bundle_hash:
        raise BundleError(
            "claim bundle checksum mismatch: "
            f"expected {expected_bundle_hash}, got {actual_bundle_hash}"
        )

    try:
        with tarfile.open(bundle_path, "r") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if len(names) != len(set(names)):
                raise BundleError("claim bundle contains duplicate archive paths")
            for member in members:
                path = Path(member.name)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or not member.isfile()
                    or member.mtime != 0
                    or member.mode != 0o644
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname
                    or member.gname
                ):
                    raise BundleError(
                        f"claim bundle member metadata is unsafe or non-deterministic: {member.name}"
                    )
            if "bundle_manifest.json" not in names:
                raise BundleError("claim bundle manifest is missing")
            manifest_file = archive.extractfile("bundle_manifest.json")
            if manifest_file is None:
                raise BundleError("claim bundle manifest is unreadable")
            try:
                manifest = json.loads(manifest_file.read().decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise BundleError("claim bundle manifest is invalid") from exc
            if not isinstance(manifest, dict):
                raise BundleError("claim bundle manifest root must be an object")
            entries = manifest.get("entries")
            if not isinstance(entries, list):
                raise BundleError("claim bundle manifest entries must be a list")

            manifest_names: set[str] = set()
            for index, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    raise BundleError(f"claim bundle manifest entry {index} is invalid")
                name = entry.get("path")
                digest = entry.get("sha256")
                size = entry.get("size_bytes")
                if not isinstance(name, str) or not name or name in manifest_names:
                    raise BundleError(
                        f"claim bundle manifest entry {index} has an invalid path"
                    )
                manifest_names.add(name)
                member_file = archive.extractfile(name)
                if member_file is None:
                    raise BundleError(f"claim bundle entry is missing: {name}")
                data = member_file.read()
                if size != len(data):
                    raise BundleError(f"claim bundle entry size mismatch: {name}")
                if digest != sha256_bytes(data):
                    raise BundleError(f"claim bundle entry hash mismatch: {name}")

            archive_entries = set(names) - {"bundle_manifest.json"}
            if manifest_names != archive_entries:
                missing = sorted(manifest_names - archive_entries)
                extra = sorted(archive_entries - manifest_names)
                raise BundleError(
                    "claim bundle manifest coverage mismatch; "
                    f"missing={missing}, extra={extra}"
                )
            report_file = archive.extractfile("evidence/cross_language.json")
            if report_file is None:
                raise BundleError("claim bundle cross-language report is missing")
            report_data = report_file.read()
    except (OSError, tarfile.TarError) as exc:
        raise BundleError(f"cannot read claim bundle: {exc}") from exc

    if manifest.get("schema_version") != 1:
        raise BundleError("claim bundle manifest schema_version must be 1")
    if manifest.get("bundle_kind") != "naux-performance-evidence":
        raise BundleError("claim bundle kind is invalid")
    if manifest.get("report_sha256") != sha256_bytes(report_data):
        raise BundleError("claim bundle report hash does not match the manifest")
    try:
        report = json.loads(report_data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BundleError("claim bundle cross-language report is invalid") from exc
    if not isinstance(report, dict):
        raise BundleError("claim bundle cross-language report root must be an object")
    validate_report(report)
    if manifest.get("git_sha") != report["environment"]["git_sha"]:
        raise BundleError("claim bundle Git SHA does not match its report")
    if manifest.get("claim_kind") != report["claim"]["kind"]:
        raise BundleError("claim bundle claim kind does not match its report")
    if manifest.get("generated_at_utc") != report["generated_at_utc"]:
        raise BundleError("claim bundle timestamp does not match its report")
    if manifest.get("reproduction_command") != report["reproduction"]["command"]:
        raise BundleError("claim bundle reproduction command does not match its report")
    return {
        "bundle_path": str(bundle_path),
        "checksum_path": str(checksum_path),
        "sha256": actual_bundle_hash,
        "manifest": manifest,
        "report": report,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Package claim-eligible cross-language evidence."
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=repo_root / "target/perf/cross_language/cross_language.json",
    )
    parser.add_argument("--repo-root", type=Path, default=repo_root)
    parser.add_argument("--out", type=Path)
    parser.add_argument(
        "--verify",
        type=Path,
        help="Verify an existing bundle and its .sha256 sidecar instead of packaging",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.verify is not None:
            verified = verify_bundle(args.verify)
            print(f"[claim-bundle] verified {verified['bundle_path']}")
            print(f"[claim-bundle] sha256={verified['sha256']}")
            print(
                "[claim-bundle] git_sha="
                f"{verified['report']['environment']['git_sha']}"
            )
            return 0
        payload = read_json(args.report)
        git_sha = str(payload.get("environment", {}).get("git_sha", "unknown"))
        out_path = args.out
        if out_path is None:
            out_path = (
                args.repo_root
                / "target/perf/claims"
                / f"naux-performance-evidence-{git_sha[:12]}.tar"
            )
        bundle_path, checksum_path, manifest = build_bundle(
            args.report, out_path, args.repo_root
        )
    except BundleError as exc:
        print(f"[claim-bundle] REFUSED: {exc}", file=sys.stderr)
        return 1

    print(f"[claim-bundle] wrote {bundle_path}")
    print(f"[claim-bundle] wrote {checksum_path}")
    print(f"[claim-bundle] entries={len(manifest['entries'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
