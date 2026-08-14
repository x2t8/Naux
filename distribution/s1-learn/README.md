# NAUX Learn 0.1.1 bundle

![NAUX Learn](../../assets/langnaux-learn.png)

This is the experimental Linux x86-64 GNU bundle for guided programming and
algorithm study. It contains a prebuilt NAUX executable; using the bundle does
not require Rust, Cargo, LLVM, a C compiler, an assembler, or a linker.

It is not a production, security, sovereignty, or native-performance release.
Read `docs/LIMITATIONS.md` before use. The learner language surface is in
`docs/s1_learn_quick_reference_v0_1.md`.

Run `./bin/naux welcome` for the localized experimental-release disclosure,
or read `docs/RELEASE_DISCLOSURE.md`. Nine bounded installer languages are
sealed under `locales/`; this does not localize program output or diagnostics.

## Host boundary

The supported WP6 host is Linux x86-64 with the GNU dynamic loader at
`/lib64/ld-linux-x86-64.so.2`, the dynamic libraries and symbol interfaces
listed in `HOST-DEPENDENCIES.tsv`, and ordinary UTF-8 terminal/file I/O.
This bundle is dynamically linked; it is not a portable static executable.

## Verify and install

One-command installation:

```bash
curl -fsSL https://github.com/x2t8/Naux/releases/download/v0.1.1-learn/nauxup.sh | sh
```

Setup detects a supported locale from the environment, prints a concise plan,
and asks for one confirmation. For unattended installation:

```bash
curl -fsSL https://github.com/x2t8/Naux/releases/download/v0.1.1-learn/nauxup.sh \
  | sh -s -- --yes
```

The bootstrap pins the archive version, byte length, and SHA-256, checks the
matching row in `SHA256SUMS`, verifies the sealed inner bundle, and only then
runs Setup. It uses a private temporary directory and removes it on exit.

Manual installation from an extracted bundle:

From the bundle directory:

```bash
./bin/naux bundle verify .
./naux-learn-setup
```

The default versioned toolchain is
`$XDG_DATA_HOME/naux/toolchains/learn/0.1.1` (or
`~/.local/share/naux/toolchains/learn/0.1.1`). Stable `naux` and `nauxup`
launchers are placed in `~/.local/bin`; sealed ownership receipts live below
`$XDG_STATE_HOME/naux/receipts` (or `~/.local/state/naux/receipts`). Missing
directories are created on a clean machine. Existing prefixes or launchers
are never overwritten.

Setup does not edit shell startup files. If `~/.local/bin` is not already on
`PATH`, it prints the one `export PATH=...` line needed for the current shell.
The user may place that same line in their chosen shell profile for future
terminals; Setup never edits such files implicitly.

Run the bundled first program and compare its exact output:

```bash
naux run "$HOME/.local/share/naux/toolchains/learn/0.1.1/examples/hello.nx"
```

Expected stdout is stored in `examples/hello.out`. For your own file:

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

`nauxup` 0.1.1 deliberately has no network update command. Repair, signed
channels, and rollback remain future lifecycle work.

The installed executable does not invoke Rust or Cargo. `BUILD-SEED.tsv`
records the temporary Rust/Cargo/egg origin debt used to build this artifact;
it is disclosure, not an installed runtime dependency.

## Inventory

`MANIFEST.tsv` seals the only accepted files by path, mode, byte length, and
SHA-256. A separate activation receipt binds both stable launchers, their
exact targets, the immutable bundle receipt, and directories Setup created.
Verification rejects a missing, substituted, duplicated, traversing,
oversized, hash-mismatched, symlinked, or extra member.
