# NAUX Learn 0.1.0 Windows release candidate

Status: cross-build, archive, and Wine smoke accepted; real-Windows gate pending\
Date: 2026-08-13\
Target: `windows-x86_64-gnu` / Rust `x86_64-pc-windows-gnu`

## 1. Claim boundary

This contract extends the completed NAUX Learn language profile to one
Windows x86-64 release candidate without changing learner semantics. It does
not weaken or replace the accepted Linux artifact. It adds a deterministic
PE32+ executable, Windows-specific host disclosure, canonical ZIP carrier,
independent Linux-side structural admission, Wine execution smoke, and a
PowerShell real-host acceptance carrier.

The candidate is not yet a supported Windows release. Promotion requires
`scripts/test_s1_windows_runtime.ps1` to pass on an admitted real 64-bit
Windows 10 22H2 or Windows 11 host. Wine evidence cannot grant that claim.

## 2. Build seed and executable identity

`distribution/s1-learn/windows/BUILD-SEED.tsv` pins Rust/Cargo 1.96.0, the
workspace lock hash, `egg` 0.10.0, Rust target `x86_64-pc-windows-gnu`, and the
exact signed Arch MinGW-w64 GCC, binutils, CRT, headers, and winpthreads package
identities and archive hashes. The producer accepts only the recorded GCC and
objdump releases.

The cross build clears ambient Cargo/Rust overrides, disables incremental
compilation, sets `SOURCE_DATE_EPOCH=0`, and passes linker policy
`--no-insert-timestamp`. It also compiles the canonical multi-size icon with
the pinned MinGW `windres` and links it as a native PE resource. The accepted
candidate executable is 11,678,395 bytes, has a zero PE timestamp, and has
SHA-256
`729798f0b1a8be7878fd96f178c72bbc97b9780e64f02984ff59c311658ae9cf`.
Two builds with distinct Cargo target directories are byte-identical.

The same producer emits the native console `NAUX-Learn-Setup.exe` with the
identical PE timestamp, import, mitigation, and icon boundary. It is
11,704,554 bytes with SHA-256
`74a1b02193f222225e032bacc4acefe83c894ebcb7d3c570a8bc071c2d818ba6`.

## 3. Host boundary

The executable is a stripped PE32+ x86-64 console application with ASLR,
high-entropy VA, and NX compatibility. It imports only the exact system DLL
contracts in `HOST-DEPENDENCIES.tsv`; no MinGW runtime DLL is bundled or
required. Its native icon group contains 16-, 32-, 48-, and 256-pixel images,
so Explorer and shortcuts can use the NAUX Learn identity without an external
icon lookup. The admitted future host boundary is 64-bit Windows 10 22H2 and
Windows 11. Windows 7/8/8.1, 32-bit Windows, ARM64, Wine, ReactOS, and other
targets have no compatibility claim.

## 4. Bundle and deterministic ZIP

The Windows directory bundle uses the existing sealed manifest grammar with
target `windows-x86_64-gnu` and replaces only `bin/naux` with `bin/naux.exe`.
The other learner contracts and first-program files remain semantically
identical. Cross-target verification is allowed, while installation fails
closed unless the bundle target equals the executing NAUX host target.

The bundle also includes `NAUX-Learn-Setup.exe` at its root. Opening that
carrier selects a language before installation, renders the full localized
experimental disclosure, asks for consent, installs through the shared sealed
receipt engine, and renders the same disclosure after success. It is a native
console carrier, not yet a graphical wizard.

The release directory contains exactly:

```text
naux-learn-0.1.0-windows-x86_64-gnu.zip
naux-learn-0.1.0-windows-x86_64-gnu.zip.sha256
RELEASE_NOTES.md
```

Info-ZIP 3.0 runs with `-X -9` over an exact ordered 33-entry list after every
member timestamp is normalized to the ZIP epoch. The accepted ZIP is
8,352,967 bytes with SHA-256
`1927f480765ce1b0889d86e7f22a304c5b70e6ff4c72da659160c67ca738b4bb`.
Its expanded 27-file bundle total is 23,831,912 bytes and its internal
manifest seal is
`19464f11ee1cb3dc30013d05c476290c7c599716b0ae639fbd6f25a9f155cf71`.
The installed `assets/langnaux-learn.png` is a separately sealed 500-by-500
RGBA source asset with SHA-256
`8818d089bc3a11394082080d7291fe9bafecaf698db66f17af40cc1900db1408`.
The derived ICO has SHA-256
`506815be3785def4411675ffca7bbe89d18500f23e4dcea17a33a96e67cdde00`;
the verifier reconstructs that exact ICO from the executable's bounded
`RT_GROUP_ICON` and `RT_ICON` tree. This semantic identity remains stable when
unrelated PE layout RVAs change.

## 5. Verification and mutation boundary

`scripts/verify_s1_release_windows.sh` checks the canonical names and checksum
grammar, exact entry order, regular-file/directory types, transport modes,
entry and byte caps, extracted bundle receipt, PE format/subsystem/timestamp,
required high-entropy-ASLR/dynamic-base/NX DLL characteristics, exact imported
DLL set, exact reconstructed ICO identity, and byte-identical ZIP
reconstruction. The bounded PE reader admits only the canonical numeric icon
resource shape and does not execute or rewrite the inspected image.

`scripts/test_s1_release_windows.sh` rebuilds in two independent Cargo target
directories and rejects checksum corruption, an extra coherently checksummed
ZIP member, and a coherently resealed executable whose PE timestamp was
changed. It also rejects a one-byte-mutated canonical ICO. Resource identity
is checked on every build and independent archive verification.
`scripts/test_s1_windows_runtime.ps1` independently
verifies the checksum on Windows, extracts, checks the sealed PNG identity,
checks version, verifies the nine catalogs, stages receipt-backed installation
with Cargo/Rust absent from `PATH`, dry-runs exact uninstall, rechecks the
installed PNG, executes the first program, and compares its bytes.

## 6. Current evidence and exclusions

The two independent cross builds and ZIPs are byte-identical. Linux-side
archive, manifest, PE, semantic icon, import, and canonical-reconstruction
gates pass. Wine 11.14 passes `naux.exe --version`, bundle verification, all
nine catalogs, direct native Setup installation in German, receipt-backed
installation in `pt-BR`, byte-exact first-program execution, uninstall dry-run,
and required refusal of in-process self-removal.
Default and all-feature focused S1 groups each pass 30 tests plus two native
Setup tests; the all-feature
library regression passes 454 tests with six deliberately ignored. This is
useful portability evidence, not proof of a real Windows host.

There is no GUI setup wizard, Start Menu/desktop shortcut creation,
Authenticode signature, SmartScreen reputation, MSIX/winget package, publisher
authentication, detached Windows uninstall helper, SBOM, provenance
attestation, stable ABI,
production/security suitability, native-performance claim, seed independence,
self-generation, or compiler-generation claim. No commit, tag, push, hosted
release, or external publication is part of this contract.
