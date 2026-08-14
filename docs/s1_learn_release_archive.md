# NAUX Learn 0.1.0 release archive

Status: accepted\
Date: 2026-08-13\
Scope: post-S1 release sealing; no language-surface expansion

## 1. Purpose

The accepted S1 directory bundle is the semantic distribution artifact. This
contract adds the deterministic single-file carrier needed to download that
directory as a release asset. It also locks the public version identity and a
separate checksum file.

Release sealing does not add language features or reopen Scope 1 semantics. It
does not perform a commit, tag, push, hosted release, or external publication.

## 2. Exact public artifacts

The producer emits one new directory containing exactly:

```text
naux-learn-0.1.0-linux-x86_64-gnu.tar.gz
naux-learn-0.1.0-linux-x86_64-gnu.tar.gz.sha256
RELEASE_NOTES.md
```

`Cargo.toml` package version `0.1.0` is the sole compiled version source. The
CLI, internal bundle grammar, seed identity, archive name, checksum name, and
release notes must all agree. Both `naux --version` and `naux -V` emit exactly
`naux 0.1.0` plus LF and no stderr. Version flags are argument-exclusive.

## 3. Deterministic archive producer

`scripts/package_s1_release.sh` first invokes the accepted directory-bundle
producer. It then uses GNU tar with sorted names, POSIX ustar headers, epoch
mtime, numeric owner/group zero, and the canonical root directory name. GNU
gzip runs with `--no-name --best`, suppressing original filename and timestamp
metadata. The output file mode is `0644`.

The archive contains the exact accepted bundle root and its 31 total directory
and regular-file entries. There are no archive links, devices, FIFOs, sockets,
PAX extensions, absolute paths, traversal components, or extra members.

This proves byte reproducibility only for the declared pinned source/seed and
reviewed producer environment. GNU tar, gzip, coreutils, ELF inspection tools,
and the host kernel remain producer dependencies; this is not a hermetic origin
image or universal reproducible-build claim.

## 4. Outer checksum

The adjacent checksum file contains exactly one canonical line:

```text
<64 lowercase SHA-256 hex><two spaces><archive basename><LF>
```

The checksum detects archive corruption but is not a signature and does not
authenticate the publisher. A hosted release must disclose this explicitly.

## 5. Independent verifier

`scripts/verify_s1_release.sh` operates before extraction:

1. validate the canonical archive/checksum names and 20 MiB compressed cap;
2. validate and replay the exact checksum line;
3. list the compressed archive and byte-compare all 32 ordered member paths;
4. reject member types other than regular files/directories;
5. enforce 40-entry and 32 MiB expanded-byte caps;
6. extract into a fresh temporary directory without restoring ownership;
7. require the extracted binary version to match the archive identity;
8. invoke the independent internal bundle verifier over the extracted root.
9. reconstruct the canonical tar/gzip stream from the admitted extraction and
   byte-compare it with the supplied archive, rejecting header drift, ignored
   trailers, concatenated streams, or another noncanonical encoding.

The temporary extraction tree is removed on success or failure. The verifier
does not install into a user prefix.

## 6. Release acceptance carrier

`scripts/test_s1_release.sh` produces two releases in distinct temporary
directories and byte-compares their archives, checksum files, and release
notes. It rejects a corrupted checksum and a coherently rechecksummed archive
containing an extra member. It then extracts the canonical archive, places
executable `cargo` and `rustc` poison sentinels first on `PATH`, installs with
a sealed lifecycle receipt, runs the installed first program, dry-runs exact
removal, uninstalls, and byte-compares output.

`naux-lang/tests/s1_release_identity.rs` independently locks the executable,
seed, bundle sources, release notes, archive producer, and verifier identity.

## 7. Explicit exclusions

This carrier is not a publisher signature, transparency-log entry, SBOM,
provenance attestation, package-manager package, auto-updater, installer UI,
cross-platform archive, static binary, production release, compatibility SLA,
security SLA, native-performance claim, dependency closure, self-generation,
or compiler-generation claim.

## 8. Acceptance evidence

Two fresh release builds produced byte-identical archives, checksum files, and
release notes. The accepted local candidate is
`naux-learn-0.1.0-linux-x86_64-gnu.tar.gz`: 2,192,220 compressed bytes,
32 exact archive entries, and SHA-256
`87850e4348b101d7316db68ae4349959ec18cfb9e6649515a4f38285d90777b4`.
Its admitted internal 26-file bundle contains 5,357,382 bytes and seals as
`e3b7c154a04077f3bded4d70eb35a10d55a3618868bf9dbbde1ac8467ae009ff`.

The release carrier passes byte reproducibility, exact three-file output
inventory, corrupted-checksum rejection, coherently rechecksummed extra-member
rejection, canonical-stream reconstruction, no-toolchain installation, and
byte-exact first-program execution, dry-run, and exact uninstall. The focused
default and all-feature S1 groups each pass 30 tests plus two native Setup
tests.

The current all-feature library regression has 454 passing tests, zero
failures, and six intentionally ignored tests. Strict workspace
all-target/all-feature Clippy, formatting, shell syntax, reproducibility,
mutation, and local-link gates pass.

Acceptance is local evidence only. No commit, tag, push, hosted release, or
external publication was performed.
