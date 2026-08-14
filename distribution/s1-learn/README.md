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

From the bundle directory:

```bash
./bin/naux bundle verify .
./naux-learn-setup
```

Setup asks for one of nine languages before installation, shows the localized
experimental disclosure, asks for consent, and repeats the disclosure after
success. The default user-local prefix is
$XDG_DATA_HOME/naux-learn/0.1.1 (or ~/.local/share/naux-learn/0.1.1).
The destination must be a new path. Installation verifies the source, copies
to a sibling staging directory, verifies that copy again, and only then
renames it into place. Existing prefixes are never overwritten.

The install report prints a sealed receipt path. Use it to preview exact
removal with `naux installation uninstall --receipt <receipt.tsv> --dry-run`,
then omit `--dry-run` to uninstall. Removal re-verifies both receipt and bundle
and never scans for guessed NAUX files.

Run the bundled first program and compare its exact output:

```bash
"$HOME/.local/share/naux-learn/0.1.1/bin/naux" run \
  "$HOME/.local/share/naux-learn/0.1.1/examples/hello.nx"
```

Expected stdout is stored in `examples/hello.out`. For your own file:

```bash
"$HOME/.local/share/naux-learn/0.1.1/bin/naux" run solution.nx < input.txt
```

The installed executable does not invoke Rust or Cargo. `BUILD-SEED.tsv`
records the temporary Rust/Cargo/egg origin debt used to build this artifact;
it is disclosure, not an installed runtime dependency.

## Inventory

`MANIFEST.tsv` seals the only accepted files by path, mode, byte length, and
SHA-256. Verification rejects a missing, substituted, duplicated, traversing,
oversized, hash-mismatched, symlinked, or extra member.
