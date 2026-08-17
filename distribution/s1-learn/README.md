# NAUX Learn Linux bundle definition

> [!WARNING]
> NAUX Learn 0.1.3 is an unsigned experimental pre-release. It is not intended
> for production, security-critical, or safety-critical use.

This is the experimental Linux x86-64 GNU bundle for guided programming and
algorithm study. It contains prebuilt NAUX, Setup, and lifecycle-manager
executables; using the bundle does not require Rust, Cargo, LLVM, a C compiler,
an assembler, or a linker.

It is not a production, security, sovereignty, or native-performance release.
Run `naux welcome` for the embedded localized experimental-release disclosure.
The installer catalogs are compiled into the executables; this does not
localize program output or diagnostics.

## Host boundary

The supported WP6 host is Linux x86-64 with the GNU dynamic loader at
`/lib64/ld-linux-x86-64.so.2`, the dynamic libraries and symbol interfaces
listed in `HOST-DEPENDENCIES.tsv`, and ordinary UTF-8 terminal/file I/O.
This bundle is dynamically linked; it is not a portable static executable.

## Install the experimental pre-release

The pinned Linux bootstrap downloads and verifies the canonical archive before
running Setup:

```bash
curl -fsSL https://github.com/x2t8/Naux/releases/download/v0.1.3-learn/nauxup.sh | sh
```

To inspect the bootstrap before executing it, download `nauxup.sh` from the
[v0.1.3-learn release](https://github.com/x2t8/Naux/releases/tag/v0.1.3-learn),
review it, then run `sh nauxup.sh`.

From an extracted archive, verification and Setup remain explicit:

From the bundle directory:

```bash
./bin/naux bundle verify .
./naux-learn-setup
```

The default versioned toolchain is
`$XDG_DATA_HOME/naux/toolchains/learn/0.1.3` (or
`~/.local/share/naux/toolchains/learn/0.1.3`). Stable `naux` and `nauxup`
launchers are placed in `~/.local/bin`; sealed ownership receipts live below
`$XDG_STATE_HOME/naux/receipts` (or `~/.local/state/naux/receipts`). Missing
directories are created on a clean machine. Existing prefixes or launchers
are never overwritten.

Setup does not edit shell startup files. If `~/.local/bin` is not already on
`PATH`, it prints the one `export PATH=...` line needed for the current shell.
The user may place that same line in their chosen shell profile for future
terminals; Setup never edits such files implicitly.

Write your own source file outside the installation prefix, then run it:

```bash
naux run solution.nx < input.txt
```

Inspect or remove the installation without machine-wide scanning:

```bash
nauxup status
nauxup doctor
nauxup uninstall --dry-run
nauxup uninstall
```

`nauxup` 0.1.3 deliberately has no network update command. Repair, signed
channels, and rollback remain future lifecycle work.

The installed executable does not invoke Rust or Cargo. `BUILD-SEED.tsv`
records the temporary Rust/Cargo/egg origin debt used to build this artifact;
it is disclosure, not an installed runtime dependency.

## Inventory

`MANIFEST.tsv` seals the only accepted files by path, mode, byte length, and
SHA-256. The Linux payload owns exactly six files plus the manifest:

```text
BUILD-SEED.tsv
HOST-DEPENDENCIES.tsv
LICENSE
naux-learn-setup
bin/naux
bin/nauxup
MANIFEST.tsv
```

It intentionally installs no examples, documentation, images, grammar
fixtures, or editable user projects. A separate activation receipt binds both
stable launchers, their exact targets, the immutable bundle receipt, and the
directories Setup created. Verification rejects a missing, substituted,
duplicated, traversing, oversized, hash-mismatched, symlinked, or extra member.
