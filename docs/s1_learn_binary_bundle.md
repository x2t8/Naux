# NAUX Learn supported-host binary bundle v0.1

Status: accepted\
Date: 2026-08-14\
Scope: S1-WP6 / Linux x86-64 GNU learner distribution

## 1. Purpose and claim boundary

WP6 gives a learner one prebuilt `naux` executable, the admitted learner
reference, exact limitations, and a deterministic first program. Installing
or using the bundle does not invoke Rust, Cargo, LLVM, a C compiler, an
assembler, or a linker.

This is a distribution boundary, not dependency closure. The binary is still
built by the pinned Rust/Cargo seed, incorporates `egg`, and is dynamically
linked to declared GNU/Linux system components. WP6 grants no production,
security, native-performance, cross-platform, static-linking, signature,
seed-independence, self-generation, or compiler-generation claim.

## 2. Supported host and seed

The only admitted target string is `linux-x86_64-gnu`. The packaged executable
is an ELF64 little-endian x86-64 PIE with interpreter
`/lib64/ld-linux-x86-64.so.2`. The exact admitted dynamic inventory is:

```text
ld-linux-x86-64.so.2
libc.so.6
libgcc_s.so.1
libm.so.6
```

The current artifact requires interfaces through `GLIBC_2.39` and
`GCC_4.2.0`; `HOST-DEPENDENCIES.tsv` exposes those requirements inside the
bundle. The `GNU/Linux 4.4.0` ELF tag is recorded but is not a universal
distribution-compatibility promise. Packaging rejects drift in interpreter,
machine, PIE type, dependency names, or maximum declared interface versions.

`BUILD-SEED.tsv` pins Rust 1.96.0 commit
`ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96`, Cargo 1.96.0 commit
`30a34c682`, target `x86_64-unknown-linux-gnu`, package `naux@0.1.1`,
`egg@0.10.0`, and the complete workspace `Cargo.lock` SHA-256. The producer
runs `cargo build --locked --release -p naux --bin naux` only after the active
seed agrees byte-for-byte with that record. The producer clears ambient Rust
wrapper, encoded-flag, target-flag, and release-profile overrides, disables
incremental compilation, and fixes the workspace target directory. This is a
bounded producer discipline, not a hermetic build-environment claim.

## 3. Canonical directory inventory

The artifact is a directory, not an archive. No extraction algorithm or
archive traversal surface is part of WP6. Its exact regular-file inventory is:

| Mode | Member | Per-file cap |
|---:|---|---:|
| `0644` | `BUILD-SEED.tsv` | 16 KiB |
| `0644` | `HOST-DEPENDENCIES.tsv` | 16 KiB |
| `0644` | `LICENSE` | 64 KiB |
| `0644` | `README.md` | 256 KiB |
| `0755` | `naux-learn-setup` | 16 MiB |
| `0644` | `assets/langnaux-learn.png` | 512 KiB |
| `0755` | `bin/naux` | 16 MiB |
| `0644` | `docs/LIMITATIONS.md` | 256 KiB |
| `0644` | `docs/RELEASE_DISCLOSURE.md` | 256 KiB |
| `0644` | `docs/s1_learn_batch_io.md` | 256 KiB |
| `0644` | `docs/s1_learn_diagnostics.md` | 256 KiB |
| `0644` | `docs/s1_learn_execution_envelope.md` | 256 KiB |
| `0644` | `docs/s1_learn_quick_reference_v0_1.md` | 1 MiB |
| `0644` | `examples/hello.nx` | 64 KiB |
| `0644` | `examples/hello.out` | 64 KiB |
| `0644` | `locales/SUPPORTED_LOCALES.tsv` | 16 KiB |
| `0644` | `locales/{de,en-US,es,fr,ja-JP,ko-KR,pt-BR,vi-VN,zh-CN}.tsv` | 64 KiB each |
| `0644` | `MANIFEST.tsv` | 16 KiB |

The only directories are `assets`, `bin`, `docs`, `examples`, and `locales`.
The inventory has a 40-entry hard ceiling, paths have a 160-byte ceiling, and
total admitted bytes have a 32 MiB ceiling. Only UTF-8 normal relative path
components separated by `/` are admitted. Absolute paths, `.`, `..`,
backslashes, NUL, non-UTF-8 components, symlinks, devices, sockets, FIFOs,
missing members, and extra members fail closed.

## 4. Manifest grammar and seal

`MANIFEST.tsv` is canonical UTF-8 with LF endings and a terminal LF:

```text
NAUX-S1-LEARN-BUNDLE<TAB>1
bundle<TAB>0.1.1
target<TAB>linux-x86_64-gnu
file<TAB>MODE<TAB>SIZE<TAB>SHA256<TAB>PATH
...
seal<TAB>SHA256
```

File rows occur exactly once in the table order above. Modes are four octal
digits, sizes are minimal unsigned decimal, and digests are 64 lowercase hex
digits. The seal is:

```text
SHA256("NAUX:s1-learn-bundle:manifest:v1\0" || every preceding manifest byte)
```

The seal detects manifest corruption and binds every file path, mode, size,
and digest. It is deliberately not a publisher signature: a coherently
repacked directory can create a different internally valid seal. Publisher
identity and signed release checksums are excluded from WP6.

## 5. Independent admission and installation

The producer is `scripts/package_s1_learn.sh`; the consumer is the Rust module
`learn_bundle`, exposed as:

```text
naux bundle verify <bundle-directory>
naux bundle install <bundle-directory> --prefix <new-prefix>
naux installation install <bundle-directory> --prefix <new-prefix> \
  --state-directory <existing-state-directory> --language <locale>
naux installation uninstall --receipt <receipt.tsv> [--dry-run]
```

The verifier independently parses and seals the manifest, walks the complete
filesystem inventory, enforces type/path/mode/size limits, reads every member
under its own cap, and checks every SHA-256. It does not execute the artifact.

Installation accepts only a new prefix. It first admits the source, copies the
canonical files into a new sibling staging directory, restores canonical
modes, independently admits the staged copy, compares its receipt to the
source receipt, then renames the staging directory into place. Any failure
removes only that uniquely named staging directory. Existing prefixes are
never overwritten or deleted.

The lifecycle command adds a separate sealed receipt that binds the absolute
prefix, locale, target, bundle seal, file count, and byte count. The state
directory must already exist and must not be a symlink. Dry-run and actual
uninstall first re-admit the receipt and exact installed bundle, then enumerate
or remove only manifest-owned paths. It never scans for guessed NAUX files or
owns learner projects outside the prefix.

## 6. First-program gate without a toolchain

The end-to-end carrier is:

```text
scripts/test_s1_learn_bundle.sh
```

It packages into a fresh temporary directory, puts executable `cargo` and
`rustc` poison sentinels at the only `PATH`, verifies and installs using the
prebuilt binary, runs installed `examples/hello.nx`, byte-compares stdout with
`examples/hello.out`, proves reinstall refusal, dry-runs receipt-based removal,
and performs exact uninstall. Thus the normal lifecycle cannot silently depend
on Cargo or Rust being available.

## 7. Mutation and regression boundary

`naux-lang/tests/s1_learn_bundle.rs` independently creates a canonical fixture
using the host `sha256sum` oracle and locks admission/installation behavior. It
rejects missing, extra, same-length substituted, duplicate, traversing,
symlinked, oversized, mode-drifted, and existing-prefix cases. Lifecycle tests
also reject changed payloads, corrupt or linked receipts, receipt collisions,
and coherently resealed packaged catalogs that differ from the executable.
Library units reject noncanonical line endings and a corrupted seal before
accepting manifest contents.

The full S1 regression gate retains deterministic batch I/O, stable
diagnostics, all 30 corpus exercises, the executed quick reference, and the
bounded semantic execution envelope.

## 8. Explicit exclusions

WP6 does not provide tar/zip packaging, reproducible byte identity across
arbitrary build roots, a hermetic origin image, static linking, musl support,
another OS or architecture, a release signature, publisher authentication,
auto-update, repair, rollback, registry publication, sandboxing,
security-critical suitability, production support, native learner execution,
or performance evidence against C/C++/Rust. No broader language or release
claim is implied by this bundle.

## 9. Acceptance evidence

The release-sealed producer generated the same 26-file artifact in distinct
output directories. The accepted resealed artifact contains 5,357,110 bytes
including its manifest and has manifest seal
`99e4ab2ee05d00615d00b3d6b8f7f87067289b8c11c4ba1957d57a9620390bb1`.
Its executable is 4,082,552 bytes with SHA-256
`dd12495211efcdb890cdf821476bf6386a19c738d2e7588d042f35ca881147da`
and reports exactly `naux 0.1.1`. The canonical 500-by-500 RGBA project logo
is installed at `assets/langnaux-learn.png`, is sealed as an ordinary bundle
member, and has SHA-256
`8818d089bc3a11394082080d7291fe9bafecaf698db66f17af40cc1900db1408`. The
bundle-local Markdown link audit has no broken target.

The native console Setup carrier is 1,112,856 bytes with SHA-256
`b13a03710035b8af098581f5a5f966df7969979be8951aeaf428e4efd7ad6af1`.
It presents the nine-language selector, localized disclosure and consent before
installation, then repeats the disclosure and prints the sealed receipt after
success.

The no-toolchain carrier passes with `cargo` and `rustc` poison sentinels as
the complete `PATH`; verify, receipt-backed staged install, installed
first-program output, dry-run, exact uninstall, and existing-prefix refusal all
pass. The focused default and all-feature S1 groups each pass 30 tests plus two
native Setup tests,
including nine bundle/lifecycle mutation tests and three release-identity
tests.

The 0.1.1 focused bundle/lifecycle group passes nine mutation and ownership
tests, and the release-identity group passes three tests. Strict shell syntax,
release reproducibility, mutation, no-toolchain bootstrap, and bundle-document
gates pass. The CI-equivalent all-feature workspace regression also completes
with the main library at 453 passed, zero failed, six deliberately ignored,
and one controlled fixture filtered out; every subsequently executed
integration and documentation test passes.
