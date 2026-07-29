from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import perf_claim_bundle as claim_bundle  # noqa: E402


def valid_report() -> dict:
    rows = []
    for benchmark in sorted(claim_bundle.REQUIRED_BENCHMARKS):
        for implementation in sorted(claim_bundle.REQUIRED_IMPLEMENTATIONS):
            rows.append(
                {
                    "benchmark": benchmark,
                    "implementation": implementation,
                    "median_ns": 100,
                    "p95_ns": 120,
                    "cv_pct": 1.25,
                    "checksum": 42.0,
                    "checksum_match": True,
                    "baseline_over_naux": 1.0,
                    "claim_stable": True,
                }
            )
    return {
        "schema_version": 2,
        "generated_at_utc": "2026-07-23T00:00:00Z",
        "status": "pass",
        "claim": {
            "eligible": True,
            "blockers": [],
            "kind": "baseline-observation",
            "thresholds": {
                "minimum_samples_per_implementation": 30,
                "minimum_warmup_ms": 100,
                "maximum_cv_pct": 5.0,
                "require_naux_beat_c": False,
                "require_naux_beat_cpp": False,
            },
        },
        "workload": {
            "engine": "jit",
            "n": 100_000,
            "iters": 50,
            "warmup_ms": 100,
            "reps": 50,
            "sample_count_per_implementation": 50,
            "statistics": ["median_ns", "p95_ns", "cv_pct"],
            "cv_definition": (
                "population standard deviation / arithmetic mean * 100"
            ),
            "outlier_policy": (
                "no statistical outlier trimming; Naux transition samples are logged"
            ),
            "timed_region": "input allocation plus initialization plus kernel execution",
            "definitions": {
                benchmark: f"{benchmark} definition"
                for benchmark in claim_bundle.REQUIRED_BENCHMARKS
            },
        },
        "environment": {
            "platform": "test-os",
            "machine": "x86_64",
            "cpu_model": "test-cpu",
            "physical_core_count": "4",
            "logical_core_count": "8",
            "memory_bytes": "17179869184",
            "cpu_core": 0,
            "pin_status": "pinned",
            "governor": "performance",
            "intel_no_turbo": "1",
            "target_triple": "x86_64-unknown-linux-gnu",
            "target_features": ["avx2"],
            "git_sha": "a" * 40,
            "git_dirty": False,
        },
        "toolchains": {
            "rustc": "rustc test",
            "cc": "cc test",
            "cpp": "c++ test",
            "go": "go test",
            "zig": "0.16.0",
        },
        "coverage": {
            implementation: "measured"
            for implementation in claim_bundle.REQUIRED_IMPLEMENTATIONS
        },
        "build_flags": {
            implementation: "-O"
            for implementation in claim_bundle.REQUIRED_IMPLEMENTATIONS
        },
        "build_profiles": {
            implementation: "release"
            for implementation in claim_bundle.REQUIRED_IMPLEMENTATIONS
        },
        "reproduction": {
            "command": "CPU_CORE=0 ENFORCE_CLAIM_ENV=1 ./scripts/bench_cross_language.sh",
            "working_directory": ".",
        },
        "evidence_sha256": {
            name: "0" * 64 for name in claim_bundle.required_hashed_evidence_names()
        },
        "rows": rows,
        "naux_execution": {
            benchmark: {
                "requested_engine": "jit",
                "fallback": False,
                "trace_count": 1,
                "deopts": 0,
                "internal_side_exits": 0,
                "static_branches": 4 if benchmark == "branch_mix" else 2,
            }
            for benchmark in claim_bundle.REQUIRED_BENCHMARKS
        },
    }


def write_evidence(report_dir: Path, payload: dict) -> Path:
    report_dir.mkdir(parents=True)
    report_path = report_dir / "cross_language.json"
    (report_dir / "cross_language.md").write_text("# report\n", encoding="utf-8")
    (report_dir / "cross_language.tsv").write_text("fixture\n", encoding="utf-8")
    for path in claim_bundle.required_evidence_paths(report_path):
        if path != report_path and not path.exists():
            path.write_text(f"{path.name}\n", encoding="utf-8")
    payload["evidence_sha256"] = {
        name: hashlib.sha256((report_dir / name).read_bytes()).hexdigest()
        for name in claim_bundle.required_hashed_evidence_names()
    }
    report_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return report_path


class ClaimBundleValidationTests(unittest.TestCase):
    def test_ineligible_report_is_refused(self) -> None:
        payload = valid_report()
        payload["claim"]["eligible"] = False
        payload["claim"]["blockers"] = ["dirty worktree"]

        with self.assertRaisesRegex(claim_bundle.BundleError, "eligible"):
            claim_bundle.validate_report(payload)

    def test_checksum_or_row_tampering_is_refused(self) -> None:
        payload = valid_report()
        payload["rows"][0]["checksum_match"] = False
        with self.assertRaisesRegex(claim_bundle.BundleError, "checksum parity"):
            claim_bundle.validate_report(payload)

    def test_jit_fallback_or_missing_native_branch_is_refused(self) -> None:
        payload = valid_report()
        payload["naux_execution"]["sum_dense"]["fallback"] = True
        with self.assertRaisesRegex(claim_bundle.BundleError, "fallback"):
            claim_bundle.validate_report(payload)

        payload = valid_report()
        payload["naux_execution"]["branch_mix"]["static_branches"] = 2
        with self.assertRaisesRegex(claim_bundle.BundleError, "branch coverage"):
            claim_bundle.validate_report(payload)

        payload = valid_report()
        payload["rows"].pop()
        with self.assertRaisesRegex(claim_bundle.BundleError, "row coverage mismatch"):
            claim_bundle.validate_report(payload)

    def test_insufficient_samples_and_unstable_cv_are_refused(self) -> None:
        payload = valid_report()
        payload["workload"]["iters"] = 20
        payload["workload"]["sample_count_per_implementation"] = 20
        with self.assertRaisesRegex(claim_bundle.BundleError, "below claim minimum"):
            claim_bundle.validate_report(payload)

        payload = valid_report()
        payload["rows"][0]["cv_pct"] = 5.1
        payload["rows"][0]["claim_stable"] = False
        with self.assertRaisesRegex(claim_bundle.BundleError, "unstable samples"):
            claim_bundle.validate_report(payload)


class ClaimBundleBuildTests(unittest.TestCase):
    def test_bundle_is_deterministic_and_hash_manifest_covers_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture-source.txt"
            source.write_text("source\n", encoding="utf-8")
            report = write_evidence(root / "evidence", valid_report())
            first = root / "first.tar"
            second = root / "second.tar"

            _, _, first_manifest = claim_bundle.build_bundle(
                report,
                first,
                root,
                source_paths=["fixture-source.txt"],
                enforce_repo_state=False,
            )
            claim_bundle.build_bundle(
                report,
                second,
                root,
                source_paths=["fixture-source.txt"],
                enforce_repo_state=False,
            )

            self.assertEqual(
                hashlib.sha256(first.read_bytes()).hexdigest(),
                hashlib.sha256(second.read_bytes()).hexdigest(),
            )
            with tarfile.open(first, "r") as archive:
                names = archive.getnames()
                self.assertIn("bundle_manifest.json", names)
                self.assertIn("source/fixture-source.txt", names)
                self.assertIn("evidence/cross_language.json", names)
                manifest = json.load(archive.extractfile("bundle_manifest.json"))
                for entry in manifest["entries"]:
                    data = archive.extractfile(entry["path"]).read()
                    self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])
                    self.assertEqual(len(data), entry["size_bytes"])
            self.assertEqual(first_manifest["schema_version"], 1)
            verified = claim_bundle.verify_bundle(first)
            self.assertEqual(
                verified["sha256"],
                hashlib.sha256(first.read_bytes()).hexdigest(),
            )
            self.assertEqual(verified["manifest"], first_manifest)

    def test_bundle_checksum_tampering_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture-source.txt"
            source.write_text("source\n", encoding="utf-8")
            report = write_evidence(root / "evidence", valid_report())
            bundle = root / "evidence.tar"
            _, checksum, _ = claim_bundle.build_bundle(
                report,
                bundle,
                root,
                source_paths=["fixture-source.txt"],
                enforce_repo_state=False,
            )
            checksum.write_text(f"{'f' * 64}  {bundle.name}\n", encoding="utf-8")

            with self.assertRaisesRegex(claim_bundle.BundleError, "checksum mismatch"):
                claim_bundle.verify_bundle(bundle)

    def test_missing_evidence_file_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture-source.txt"
            source.write_text("source\n", encoding="utf-8")
            report = write_evidence(root / "evidence", valid_report())
            (report.parent / "dot_product.zig.log").unlink()

            with self.assertRaisesRegex(claim_bundle.BundleError, "missing .*evidence"):
                claim_bundle.build_bundle(
                    report,
                    root / "out.tar",
                    root,
                    source_paths=["fixture-source.txt"],
                    enforce_repo_state=False,
                )

    def test_tampered_evidence_log_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture-source.txt"
            source.write_text("source\n", encoding="utf-8")
            report = write_evidence(root / "evidence", valid_report())
            (report.parent / "dot_product.zig.log").write_text(
                "tampered\n", encoding="utf-8"
            )

            with self.assertRaisesRegex(claim_bundle.BundleError, "hash mismatch"):
                claim_bundle.build_bundle(
                    report,
                    root / "out.tar",
                    root,
                    source_paths=["fixture-source.txt"],
                    enforce_repo_state=False,
                )


class ClaimBundleRepoBindingTests(unittest.TestCase):
    def test_repo_sha_and_clean_state_are_both_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.txt"
            source.write_text("source\n", encoding="utf-8")
            commands = [
                ["git", "init", "-q"],
                ["git", "config", "user.name", "Naux Test"],
                ["git", "config", "user.email", "naux-test@example.invalid"],
                ["git", "add", "source.txt"],
                ["git", "commit", "-q", "-m", "fixture"],
            ]
            for command in commands:
                subprocess.run(command, cwd=root, check=True)
            sha = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            payload = valid_report()
            payload["environment"]["git_sha"] = sha
            claim_bundle.verify_repo_state(root, payload)

            payload["environment"]["git_sha"] = "b" * 40
            with self.assertRaisesRegex(claim_bundle.BundleError, "does not match"):
                claim_bundle.verify_repo_state(root, payload)

            payload["environment"]["git_sha"] = sha
            source.write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(claim_bundle.BundleError, "checkout is dirty"):
                claim_bundle.verify_repo_state(root, payload)


if __name__ == "__main__":
    unittest.main()
