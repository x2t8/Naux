# NAUX Learn 0.1.2

Status: development candidate — not a public release

This candidate replaces the withdrawn learner payload design with a minimal
Linux installation containing only NAUX, Setup, the lifecycle manager, and
the metadata required to verify their origin and host boundary.

Changes under validation:

- keyboard input works on demand in an interactive terminal;
- redirected stdin retains deterministic VM/interpreter parity;
- `naux run program.nx` operates on user-owned source outside the toolchain;
- Setup no longer installs examples, documentation, logos, or grammar files;
- `nauxup doctor` and receipt-backed uninstall cover the exact seven-file
  installation inventory;
- the tarball, SHA-256 file, and pinned bootstrap are byte-reproducible on the
  admitted producer.

The installed executables do not require Rust or Cargo at runtime. This is not
dependency closure, seed independence, production readiness, sandboxing, or a
native-performance claim.
