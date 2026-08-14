# NAUX Learn 0.1.1 Windows release candidate

Status: cross-build and archive accepted; Wine and real-Windows gates pending\
Date: 2026-08-14\
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
candidate executable is 11,671,446 bytes, has a zero PE timestamp, and has
SHA-256
`6b76b26c6fc98a6170e373b5b25abe66cd2cc7e72f41f9cb94cdbf73ed2eda93`.
Two builds with distinct Cargo target directories are byte-identical.

The same producer emits the native console `NAUX-Learn-Setup.exe` with the
identical PE timestamp, import, mitigation, and icon boundary. It is
11,697,593 bytes with SHA-256
`2a77fc58d583acb7ecb7b34c58b37c6c12b7e555c38a73bcc62f799e1768c3dd`.

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
naux-learn-0.1.1-windows-x86_64-gnu.zip
naux-learn-0.1.1-windows-x86_64-gnu.zip.sha256
RELEASE_NOTES.md
nauxup.ps1
```

Info-ZIP 3.0 runs with `-X -9` over an exact ordered 33-entry list after every
member timestamp is normalized to the ZIP epoch. The accepted ZIP is
8,353,234 bytes with SHA-256
`2346987f900babc5f021b6ffa77def35de085524354fc80b5eebf518ec9d5dda`.
Its expanded 27-file bundle total is 23,818,002 bytes and its internal
manifest seal is
`120998ed3b3518f20b4dd520f2457aa57893ef07e364c1f8524351f6b16ab76c`.
The 4,592-byte pinned `nauxup.ps1` has SHA-256
`91b8ce0cccbb91af130f88c797d71041631185328993af46047565dd976dbfb2`.
It pins the exact tag, ZIP basename, compressed byte length, and SHA-256,
checks those values before extraction, invokes the sealed bundle verifier and
version gate, then opens the same native localized Setup carrier. It owns only
its private temporary tree and does not mutate user PATH or create an untracked
launcher.
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
`scripts/test_s1_windows_runtime.ps1` independently parses and replays the
pinned bootstrap against local accepted assets, verifies the checksum on
Windows, extracts, checks the sealed PNG identity, checks version, verifies the
nine catalogs, stages receipt-backed installation with Cargo/Rust absent from
`PATH`, dry-runs exact uninstall, rechecks the installed PNG, executes the first
program, and compares its bytes.

## 6. Current evidence and exclusions

The two independent 0.1.1 cross builds and ZIPs are byte-identical. Linux-side
archive, manifest, PE, semantic icon, import, and canonical-reconstruction
gates pass. The predecessor 0.1.0 executable passed Wine 11.14 smoke, but its
binary identity differs and that evidence cannot promote 0.1.1. Wine and
declared real-Windows replays remain pending for this candidate.

There is no GUI setup wizard, Start Menu/desktop shortcut creation,
Authenticode signature, SmartScreen reputation, MSIX/winget package, publisher
authentication, detached Windows uninstall helper, SBOM, provenance
attestation, stable ABI,
production/security suitability, native-performance claim, seed independence,
self-generation, or compiler-generation claim. No commit, tag, push, hosted
release, or external publication is part of this contract.
