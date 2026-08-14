# Install NAUX Learn on Linux

[Tutorial index](README.md) · [First program](03-first-program.md) ·
[Troubleshooting](06-troubleshooting.md)

This installs **NAUX Learn 0.1.1** on the supported experimental Linux host.
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
curl -fsSL https://github.com/x2t8/Naux/releases/download/v0.1.1-learn/nauxup.sh | sh
```

Setup will:

1. download the exact version-pinned archive and `SHA256SUMS`;
2. verify its byte length and SHA-256;
3. verify the bundle's inner sealed manifest;
4. select one of nine supported languages from the environment;
5. display a concise experimental-release plan;
6. ask for one confirmation and install to a new prefix;
7. publish stable `naux` and `nauxup` launchers with sealed ownership.

For unattended installation:

```sh
curl -fsSL https://github.com/x2t8/Naux/releases/download/v0.1.1-learn/nauxup.sh \
  | sh -s -- --yes
```

## 3. Locate NAUX

The default prefix is `$XDG_DATA_HOME/naux/toolchains/learn/0.1.1`, or
`~/.local/share/naux/toolchains/learn/0.1.1` when `XDG_DATA_HOME` is unset.

```sh
NAUX_HOME="${XDG_DATA_HOME:-$HOME/.local/share}/naux/toolchains/learn/0.1.1"
```

## 4. Verify and run the bundled program

```sh
naux --version
naux run "$NAUX_HOME/examples/hello.nx"
```

Expected version:

```text
naux 0.1.1
```

## 5. If `naux` is not yet on `PATH`

Setup creates `~/.local/bin/naux` and `~/.local/bin/nauxup`, but does not edit
shell profiles. Enable that standard command directory in the current shell:

```sh
export PATH="$HOME/.local/bin:$PATH"
naux --version
```

Continue with [your first NAUX program](03-first-program.md).

## Inspect before running

If you do not want to pipe a network response into a shell, download
`nauxup.sh`, the archive, and `SHA256SUMS` from the
[release page](https://github.com/x2t8/Naux/releases/tag/v0.1.1-learn). Inspect
the script, verify the published identities, and follow the README inside the
archive.
