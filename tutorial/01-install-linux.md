# Install NAUX Learn on Linux

[Tutorial index](README.md) · [First program](03-first-program.md) ·
[Troubleshooting](06-troubleshooting.md)

This installs **NAUX Learn 0.1.0** on the supported experimental Linux host.
Normal installation and learner execution do not require Rust, Cargo, LLVM,
or a C/C++ compiler.

## 1. Check the host

```sh
uname -s
uname -m
```

The expected results are `Linux` and `x86_64`/`amd64`. The release requires the
GNU dynamic-loader boundary and ordinary system tools including `curl`, `tar`,
and `sha256sum`. ARM64, 32-bit x86, musl-only systems, macOS, and BSD are not
admitted by this bundle.

## 2. Install

```sh
curl -fsSL https://github.com/x2t8/Naux/releases/download/v0.1.0-learn/nauxup.sh | sh
```

Setup will:

1. download the exact version-pinned archive and checksum;
2. verify its byte length and SHA-256;
3. verify the bundle's inner sealed manifest;
4. ask for one of nine languages;
5. display the experimental-release disclosure;
6. ask for confirmation and install to a new prefix;
7. print the installation prefix, ownership receipt, and first command.

Keep the printed receipt path. It is the authority for exact uninstall.

## 3. Locate NAUX

The default prefix is `$XDG_DATA_HOME/naux-learn/0.1.0`, or
`~/.local/share/naux-learn/0.1.0` when `XDG_DATA_HOME` is unset.

```sh
NAUX_HOME="${XDG_DATA_HOME:-$HOME/.local/share}/naux-learn/0.1.0"
NAUX="$NAUX_HOME/bin/naux"
```

## 4. Verify and run the bundled program

```sh
"$NAUX" --version
"$NAUX" run "$NAUX_HOME/examples/hello.nx"
```

Expected version:

```text
naux 0.1.0
```

## 5. Optional short command for this terminal

The installer does not modify `PATH` or shell profiles because an untracked
profile edit would escape receipt-backed uninstall. This function exists only
until the current terminal closes:

```sh
naux() { "$NAUX_HOME/bin/naux" "$@"; }
naux --version
```

Continue with [your first NAUX program](03-first-program.md).

## Inspect before running

If you do not want to pipe a network response into a shell, download
`nauxup.sh`, the archive, and its adjacent `.sha256` file from the
[release page](https://github.com/x2t8/Naux/releases/tag/v0.1.0-learn). Inspect
the script, verify the published identities, and follow the README inside the
archive.
