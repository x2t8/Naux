# NAUX Learn 0.1.1 release archive

Status: accepted\
Date: 2026-08-14\
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
naux-learn-0.1.1-linux-x86_64-gnu.tar.gz
naux-learn-0.1.1-linux-x86_64-gnu.tar.gz.sha256
RELEASE_NOTES.md
nauxup.sh
```

`Cargo.toml` package version `0.1.1` is the sole compiled version source. The
CLI, internal bundle grammar, seed identity, archive name, checksum name, and
release notes must all agree. Both `naux --version` and `naux -V` emit exactly
`naux 0.1.1` plus LF and no stderr. Version flags are argument-exclusive.

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

### Pinned bootstrap carrier

`scripts/render_s1_bootstrap.sh` renders `nauxup.sh` only after the archive and
canonical checksum exist. The generated script embeds the exact release tag,
archive basename, compressed byte length, and SHA-256. It admits Linux x86-64,
downloads only from that tag, checks the checksum grammar, size, and digest,
extracts into a private temporary tree, invokes the inner `bundle verify`,
checks the executable version, and only then hands control to localized Setup.
The temporary tree is removed on every exit.

The bootstrap does not edit shell profiles or create an external launcher:
persistent ownership remains entirely inside Setup's sealed receipt. The
bootstrap and digest travel through the same GitHub release channel, so this
is corruption and substitution detection, not publisher authentication.

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
directories and byte-compares their archives, checksum files, release notes,
and rendered `nauxup.sh`. It rejects a corrupted checksum, a coherently
rechecksummed archive containing an extra member, and a mutated bootstrap
download. It then places executable `cargo` and `rustc` poison sentinels first
on `PATH`, replays the pinned bootstrap through a local transport double,
installs with a sealed lifecycle receipt, runs the installed first program,
dry-runs exact removal, uninstalls, and byte-compares output.

`naux-lang/tests/s1_release_identity.rs` independently locks the executable,
seed, bundle sources, release notes, archive producer, and verifier identity.

## 7. Explicit exclusions

This carrier is not a publisher signature, transparency-log entry, SBOM,
provenance attestation, package-manager package, auto-updater, graphical installer UI,
cross-platform archive, static binary, production release, compatibility SLA,
security SLA, native-performance claim, dependency closure, self-generation,
or compiler-generation claim.

## 8. Acceptance evidence

Two fresh release builds produced byte-identical archives, checksum files, and
release notes. The accepted local candidate is
`naux-learn-0.1.1-linux-x86_64-gnu.tar.gz`: 2,191,819 compressed bytes,
32 exact archive entries, and SHA-256
`6fc528dfd518f260aea1c95cda87063f53abe1b466d5cf35c5572f279bdade42`.
Its admitted internal 26-file bundle contains 5,357,110 bytes and seals as
`99e4ab2ee05d00615d00b3d6b8f7f87067289b8c11c4ba1957d57a9620390bb1`.
The 3,748-byte `nauxup.sh` has SHA-256
`d97021e63af93c3bd45498316ca264dd6bf1b04d7478eab89b49ed20300e692d`.

The release carrier passes byte reproducibility, exact four-file output
inventory, corrupted-checksum rejection, coherently rechecksummed extra-member
rejection, bootstrap download mutation rejection, canonical-stream
reconstruction, no-toolchain bootstrap installation, and byte-exact
first-program execution, dry-run, and exact uninstall.

Acceptance is local evidence only and does not itself constitute a tag, hosted
release, or external publication.
