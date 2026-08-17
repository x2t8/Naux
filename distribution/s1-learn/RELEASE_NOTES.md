# NAUX Learn 0.1.4

Status: experimental pre-release

This pre-release replaces the withdrawn learner payload design with a minimal
Linux installation containing only NAUX, Setup, the lifecycle manager, and
the metadata required to verify their origin and host boundary.

Install on Linux x86-64 GNU:

```sh
curl -fsSL https://github.com/x2t8/Naux/releases/download/v0.1.4-learn/nauxup.sh | sh
```

Included changes:

- the public `nauxup.sh` transport mode is canonical `0644`, matching GitHub
  Release downloads and the documented explicit `sh nauxup.sh` entry path;
- every public asset is bound to a canonical `PROVENANCE.tsv` record carrying
  the annotated tag, source commit/tree, pinned seed, release notes, inner
  bundle seal, byte length, and SHA-256 identity;
- the independent preview verifier rejects source, asset, inventory, link,
  permission, and provenance-seal drift before admission;
- public security, compatibility, support, and issue-routing policies define
  where reports belong and which claims remain outside this preview;
- keyboard input works on demand in an interactive terminal;
- redirected stdin retains deterministic VM/interpreter parity;
- `naux run program.nx` operates on user-owned source outside the toolchain;
- the quickstart states explicitly that `^ value` returns internally while
  only `!say value` writes deterministic program output;
- Setup no longer installs examples, documentation, logos, or grammar files;
- `nauxup doctor` and receipt-backed uninstall cover the exact seven-file
  installation inventory;
- the tarball, SHA-256 file, and pinned bootstrap are byte-reproducible on the
  admitted producer.

The installed executables do not require Rust or Cargo at runtime. SHA-256 and
the provenance seal provide deterministic integrity, not publisher
authentication. This unsigned experimental pre-release is not dependency
closure, seed independence, production readiness, sandboxing, stable
compatibility, or a native-performance claim.
