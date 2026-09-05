from __future__ import annotations

import contextlib
import io
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import s4_residency_exact_claim_coq_certificate as certificate

PUBLIC_DIR = os.environ.get("NAUX_WP8S_PUBLIC_DIR")
ROCQ = os.environ.get("NAUX_ROCQ") or shutil.which("rocq")


class ExactClaimEncodingTests(unittest.TestCase):
    def test_string_encoder_keeps_code_as_data(self) -> None:
        self.assertEqual(certificate.rocq_string(b""), "EmptyString")
        self.assertEqual(certificate.rocq_string(b'a"b'), '("a""b")%string')
        self.assertEqual(
            certificate.rocq_string(b"line\n\x00\xff"),
            '("line" ++ String (ascii_of_nat 10) EmptyString ++ '
            'String (ascii_of_nat 0) EmptyString ++ '
            'String (ascii_of_nat 255) EmptyString)%string',
        )

    def test_missing_artifacts_emit_no_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "Proof.v"
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                certificate.main([
                    "--archive", str(Path(directory) / "missing.tar.gz"),
                    "--receipt", str(Path(directory) / "missing.tsv"),
                    "--admission-report", str(Path(directory) / "report.tsv"),
                    "--output", str(output),
                ])
            self.assertFalse(output.exists())


@unittest.skipUnless(PUBLIC_DIR, "set NAUX_WP8S_PUBLIC_DIR to the two pinned public assets")
class ExactClaimPublicCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace = tempfile.TemporaryDirectory(prefix="naux-wp8s-certificate-tests-")
        cls.addClassCleanup(cls.workspace.cleanup)
        cls.directory = Path(cls.workspace.name)
        base = Path(PUBLIC_DIR)
        cls.archive = base / certificate.wp8s.EXPECTED.archive_name
        cls.receipt = base / certificate.wp8s.EXPECTED.receipt_name
        cls.static = certificate.wp8s.validate(ROOT)
        cls.exact = certificate.wp8s.admit(cls.archive, cls.receipt, cls.static)
        cls.report = cls.directory / "admission.tsv"
        cls.report.write_bytes(cls.exact.report)
        cls.data = certificate.authenticate(ROOT, cls.report, cls.archive, cls.receipt)
        cls.source = certificate.emit_rocq(cls.data)

    def test_public_replay_emits_120_samples_deterministically(self) -> None:
        self.assertEqual([len(samples) for samples in self.data.samples], [30] * 4)
        self.assertEqual(self.data.claim, self.static.claim)
        self.assertEqual(self.source, certificate.emit_rocq(
            certificate.authenticate(ROOT, self.report, self.archive, self.receipt)
        ))
        self.assertEqual(self.source.count("exact_baseline_ns :="), 120)
        self.assertEqual(self.source.count("_metrics_match :"), 4)
        self.assertNotRegex(self.source, r"\b(?:Axiom|Admitted|admit|Parameter|native_compute)\b")

    def test_static_refusal_cannot_become_a_certificate(self) -> None:
        with self.assertRaises(certificate.ExactClaimCertificateError):
            certificate.authenticate_report(self.static.static_report, self.exact)

    def test_resealed_report_mutations_are_refused(self) -> None:
        body = self.exact.report[:self.exact.report.rfind(b"report-root\t")]
        for old, new in (
            (b"passing-kernels\t4", b"passing-kernels\t3"),
            (b"pairs-per-kernel\t30", b"pairs-per-kernel\t29"),
            (b"explicit-owner-approved", b"automatic-approval"),
            (b"not-a-cryptographic-signature", b"cryptographic-signature"),
            (b"exact-host-commit-artifacts-protocol-and-four-kernels-only", b"whole-language"),
            (certificate.wp8s.EXPECTED.claim_sha256.encode(), b"0" * 64),
            (certificate.wp8s.EXPECTED.source_commit.encode(), b"0" * 40),
        ):
            with self.subTest(old=old):
                changed = body.replace(old, new, 1)
                self.assertNotEqual(changed, body)
                root = certificate.wp8s._sha256(certificate.wp8s.ADMISSION_REPORT_DOMAIN + changed)
                with self.assertRaises(certificate.ExactClaimCertificateError):
                    certificate.authenticate_report(changed + f"report-root\t{root}\n".encode(), self.exact)

    def test_noncanonical_report_mutations_are_refused(self) -> None:
        for raw in (
            self.exact.report[:-1], self.exact.report + b"extra\trow\n",
            self.exact.report.replace(b"\n", b"\r\n"), b"\xff",
        ):
            with self.subTest(raw=raw[:30]), self.assertRaises(certificate.ExactClaimCertificateError):
                certificate.authenticate_report(raw, self.exact)

    def test_changed_archive_is_refused_before_emission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / self.archive.name
            archive.write_bytes(self.archive.read_bytes() + b"changed")
            with self.assertRaises(certificate.wp8s.ExactClaimError):
                certificate.authenticate(ROOT, self.report, archive, self.receipt)

    def test_changed_raw_session_is_refused(self) -> None:
        payloads = certificate.wp8s.wp8r._archive_inventory(self.archive.read_bytes(), self.exact.intake.receipt)
        raw = payloads["RAW-PAIRED-SESSION.tsv"]
        with self.assertRaises(certificate.ExactClaimCertificateError):
            certificate.extract_samples(raw.replace(b"sample-pairs\t120", b"sample-pairs\t119"), self.exact)

    def test_cli_preserves_existing_output(self) -> None:
        output = self.directory / "Existing.v"
        output.write_text("user-owned proof\n")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            certificate.main([
                "--archive", str(self.archive), "--receipt", str(self.receipt),
                "--admission-report", str(self.report), "--output", str(output),
            ])
        self.assertEqual(output.read_text(), "user-owned proof\n")

    @unittest.skipUnless(ROCQ, "Rocq is required for kernel-level mutation tests")
    def test_kernel_acceptance_and_mutation_refusals(self) -> None:
        model = self.directory / "ResidencyExactClaim.v"
        shutil.copyfile(ROOT / "naux-meta-coq/ResidencyExactClaim.v", model)

        def compile_source(path: Path) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [ROCQ, "c", "-Q", str(self.directory), "NauxCore", str(path)],
                capture_output=True, text=True, timeout=60,
            )

        compiled_model = compile_source(model)
        self.assertEqual(compiled_model.returncode, 0, compiled_model.stdout + compiled_model.stderr)
        proof = self.directory / "GeneratedWP8SExactClaim.v"
        proof.write_text(self.source)
        good = compile_source(proof)
        self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
        checked = subprocess.run(
            [ROCQ, "check", "-silent", "-o", "-Q", str(self.directory), "NauxCore",
             "NauxCore.GeneratedWP8SExactClaim"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        self.assertIn("* Axioms: <none>", checked.stdout + checked.stderr)

        first = self.data.samples[0][0]
        mutations = (
            (f"exact_candidate_ns := {first.candidate_ns}", "exact_candidate_ns := 999999999999"),
            ("exact_pair_number := 1%nat", "exact_pair_number := 2%nat"),
            ("exact_baseline_first := true", "exact_baseline_first := false"),
            ("exact_kernel_number := 1%nat", "exact_kernel_number := 2%nat"),
            ("exact_report_wins := 30%nat", "exact_report_wins := 29%nat"),
            ("exact_report_sign_num := 1;", "exact_report_sign_num := 0;"),
            (certificate.wp8s.EXPECTED.host_attestation, "0" * 64),
            ("This observation applies only", "This universal guarantee applies"),
            ("exact_scope := ExactObservedFourKernels", "exact_scope := WholeLanguagePerformance"),
            ("exact_approval := ExactApprovalRecordedSnapshot", "exact_approval := ExactApprovalAbsent"),
            ("exact_replay := ExactReplayAuthenticatedSnapshot", "exact_replay := ExactReplayAbsent"),
        )
        for index, (old, new) in enumerate(mutations):
            with self.subTest(mutation=old):
                changed = self.source.replace(old, new, 1)
                self.assertNotEqual(changed, self.source)
                path = self.directory / f"Mutated{index}.v"
                path.write_text(changed)
                rejected = compile_source(path)
                self.assertNotEqual(rejected.returncode, 0, "Rocq accepted the mutation")
                self.assertIn("Unable to unify", rejected.stdout + rejected.stderr)

        # Gate boundary fixtures, separate from the authenticated observation.
        boundaries = self.directory / "ThresholdBoundaries.v"
        boundaries.write_text('''From Stdlib Require Import List ZArith.
From NauxCore Require Import ResidencyExactClaim.
Import ListNotations.
Open Scope Z_scope.
Definition uniform (baseline candidate : Z) : residency_exact_kernel :=
  {| exact_kernel_number := 1; exact_samples := map (fun n =>
     {| exact_pair_number := n; exact_baseline_first := Nat.odd n;
        exact_baseline_ns := baseline; exact_candidate_ns := candidate |}) (seq 1 30) |}.
Example inclusive_ratio : exact_kernel_passes (uniform 105 100) = true.
Proof. vm_compute. reflexivity. Qed.
Example insufficient_ratio : exact_kernel_passes (uniform 104 100) = false.
Proof. vm_compute. reflexivity. Qed.
Example ties_are_not_wins : exact_kernel_passes (uniform 100 100) = false.
Proof. vm_compute. reflexivity. Qed.
Example losses_fail : exact_kernel_passes (uniform 100 105) = false.
Proof. vm_compute. reflexivity. Qed.
Example zero_is_invalid : exact_kernel_passes (uniform 100 0) = false.
Proof. vm_compute. reflexivity. Qed.
Example negative_is_invalid : exact_kernel_passes (uniform 100 (-1)) = false.
Proof. vm_compute. reflexivity. Qed.
Definition tied (wins : nat) : residency_exact_kernel :=
  {| exact_kernel_number := 1; exact_samples := map (fun n =>
     {| exact_pair_number := n; exact_baseline_first := Nat.odd n;
        exact_baseline_ns := 100;
        exact_candidate_ns := if Nat.leb n wins then 80 else 100 |}) (seq 1 30) |}.
Example effective_24 : exact_kernel_passes (tied 24) = true.
Proof. vm_compute. reflexivity. Qed.
Example effective_23 : exact_kernel_passes (tied 23) = false.
Proof. vm_compute. reflexivity. Qed.
Example tail_29_wins : exact_sum (skipn 29 (exact_binomial_row 30)) = 31.
Proof. vm_compute. reflexivity. Qed.
Example tail_28_wins : exact_sum (skipn 28 (exact_binomial_row 30)) = 466.
Proof. vm_compute. reflexivity. Qed.
''')
        edges = compile_source(boundaries)
        self.assertEqual(edges.returncode, 0, edges.stdout + edges.stderr)

        # Differential fixtures: compare this binary-integer model against the
        # sealed WP8N median/ratio and WP8O decision code, including every win
        # count and deterministic mixed durations. These are tests, not new
        # measurement evidence or approved claims.
        rng = random.Random(0x8A51)
        cases = [[(100, 50 if n < wins else 110) for n in range(30)]
                 for wins in range(31)]
        for _ in range(20):
            cases.append([(base := rng.randint(100, 10000),
                           base + rng.randint(-base // 3, base // 10))
                          for _ in range(30)])
        differential = [
            "From Stdlib Require Import List ZArith.",
            "From NauxCore Require Import ResidencyExactClaim.",
            "Import ListNotations. Open Scope Z_scope.",
        ]
        for index, pairs in enumerate(cases):
            baseline = sum(a for a, _ in pairs)
            candidate = sum(b for _, b in pairs)
            ratio = certificate.wp8s.wp8r.wp8n._fraction(baseline, candidate)
            median = certificate.wp8s.wp8r.wp8n._median([b - a for a, b in pairs])
            comparison = replace(
                self.exact.intake.replay.session.comparisons[0],
                baseline_total_ns=baseline, candidate_total_ns=candidate,
                candidate_wins=sum(b < a for a, b in pairs),
                ties=sum(a == b for a, b in pairs),
                candidate_losses=sum(b > a for a, b in pairs),
                total_ratio_num=ratio[0], total_ratio_den=ratio[1],
                delta_median_num=median[0], delta_median_den=median[1],
            )
            expected = certificate.wp8s.wp8o.decide_kernel(comparison).kernel_pass
            rendered = "; ".join(f"({a}, {b})" for a, b in pairs)
            differential.extend([
                f"Definition case_{index} : residency_exact_kernel :=",
                "  {| exact_kernel_number := 1; exact_samples := map (fun p =>",
                "    {| exact_pair_number := fst p; exact_baseline_first := Nat.odd (fst p);",
                "       exact_baseline_ns := fst (snd p); exact_candidate_ns := snd (snd p) |})",
                f"    (combine (seq 1 30) [{rendered}]) |}}.",
                f"Example agreement_{index} : exact_kernel_passes case_{index} = {str(expected).lower()}.",
                "Proof. vm_compute. reflexivity. Qed.",
            ])
        differential_path = self.directory / "DifferentialPolicy.v"
        differential_path.write_text("\n".join(differential) + "\n")
        agreement = compile_source(differential_path)
        self.assertEqual(agreement.returncode, 0, agreement.stdout + agreement.stderr)


if __name__ == "__main__":
    unittest.main()
