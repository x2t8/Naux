# Install NAUX Learn

This guide installs the current public prerelease, **NAUX Learn 0.1.0**. It is
an experimental learning profile for programming and algorithm exercises, not
a production or security-critical tool.

- [Linux](#linux-x86-64-gnu)
- [Windows](#windows-x86-64-candidate)
- [Uninstall](#uninstall)
- [Troubleshooting](#troubleshooting)
- [Learn the language](LEARN.md)

The prebuilt bundles do not require Rust, Cargo, LLVM, or a C/C++ compiler.
The installer supports English, Tiếng Việt, 简体中文, 日本語, 한국어, Español,
Português do Brasil, Français, and Deutsch.

## Linux x86-64 GNU

### 1. Check the host

```sh
uname -s
uname -m
```

This release expects `Linux` and `x86_64`/`amd64`, with the GNU dynamic loader.
It also needs ordinary system tools including `curl`, `tar`, and `sha256sum`.

### 2. Install

Run this in a terminal:

```sh
curl -fsSL https://github.com/x2t8/Naux/releases/download/v0.1.0-learn/nauxup.sh | sh
```

Setup asks for a language, displays the experimental-release disclosure, and
asks for confirmation. It then prints the exact installation prefix and
receipt. Keep the receipt path; it is the authority used for exact uninstall.

The default installation is:

```text
~/.local/share/naux-learn/0.1.0
```

If `XDG_DATA_HOME` is set, the prefix is instead
`$XDG_DATA_HOME/naux-learn/0.1.0`.

### 3. Verify and run the bundled example

```sh
NAUX_HOME="${XDG_DATA_HOME:-$HOME/.local/share}/naux-learn/0.1.0"
NAUX="$NAUX_HOME/bin/naux"

"$NAUX" --version
"$NAUX" run "$NAUX_HOME/examples/hello.nx"
```

Expected version:

```text
naux 0.1.0
```

The installer deliberately does not edit shell profiles or `PATH`, because
files outside the sealed installation would escape receipt-backed uninstall.
For the current terminal only, this optional function provides the short
`naux` spelling:

```sh
naux() { "$NAUX_HOME/bin/naux" "$@"; }
naux --version
```

## Windows x86-64 candidate

> [!CAUTION]
> The Windows artifact is an unsigned experimental candidate. Its archive and
> executable structure have passed cross-build and Wine gates, but the required
> Windows 10/11 real-host gate is still pending.

### 1. Check the host

Open 64-bit PowerShell on Windows 10 22H2 or Windows 11:

```powershell
$env:PROCESSOR_ARCHITECTURE
```

The expected architecture is `AMD64`.

### 2. Install

```powershell
irm https://github.com/x2t8/Naux/releases/download/v0.1.0-learn/nauxup.ps1 | iex
```

Setup asks for a language and confirmation. The default installation is:

```text
%LOCALAPPDATA%\Programs\NAUX\Learn\0.1.0
```

### 3. Verify and run the bundled example

```powershell
$NauxHome = Join-Path $env:LOCALAPPDATA 'Programs\NAUX\Learn\0.1.0'
$Naux = Join-Path $NauxHome 'bin\naux.exe'

& $Naux --version
& $Naux run (Join-Path $NauxHome 'examples\hello.nx')
```

For the current PowerShell session only, this optional function provides the
short `naux` spelling:

```powershell
function naux { & $Naux @args }
naux --version
```

## Uninstall

### Linux

Setup prints a receipt path after installation. Preview the exact removal
first, then execute it:

```sh
"$NAUX" installation uninstall --receipt "/exact/path/from/setup.tsv" --dry-run
"$NAUX" installation uninstall --receipt "/exact/path/from/setup.tsv"
```

If the terminal output was lost, receipts are confined to the dedicated state
directory. Listing this directory does not scan the machine:

```sh
ls "${XDG_STATE_HOME:-$HOME/.local/state}/naux-learn"
```

Choose the receipt whose contents name the 0.1.0 prefix, then run the two
commands above. Uninstall re-verifies the receipt and installed bundle before
removing exactly the owned files.

### Windows

The candidate can verify a receipt and preview its exact uninstall plan:

```powershell
$ReceiptDirectory = Join-Path $env:LOCALAPPDATA 'NAUX\state'
Get-ChildItem -LiteralPath $ReceiptDirectory -Filter '*.tsv'
& $Naux installation uninstall --receipt 'C:\exact\receipt-from-setup.tsv' --dry-run
```

Actual in-process Windows removal is intentionally refused in 0.1.0 because a
running executable must not delete itself. A detached native remover is still
required before Windows becomes a supported release. Do not mistake the
dry-run for a completed uninstall.

## Manual download and verification

Users who do not want to pipe a network response into a shell can download the
archive and adjacent `.sha256` file from the
[release page](https://github.com/x2t8/Naux/releases/tag/v0.1.0-learn), inspect
the bootstrap, and follow the bundle README. The bootstrap itself is pinned to
the exact tag, archive name, byte count, and SHA-256; it also verifies the
bundle's inner sealed manifest before Setup starts.

## Troubleshooting

### `naux: command not found`

NAUX Learn 0.1.0 does not modify `PATH`. Use the `$NAUX`/`$Naux` command shown
above or the session-local function.

### `bootstrap output already exists` or installation prefix already exists

Setup never overwrites an installation. Verify and uninstall the existing
prefix, or choose an explicitly new prefix with the manual Setup interface.

### Linux reports an unsupported host

This bundle does not support ARM64, 32-bit x86, musl-only distributions,
macOS, BSD, or other host boundaries.

### Windows blocks the command

Confirm that the terminal is 64-bit PowerShell, GitHub is reachable over
HTTPS, and organization policy permits PowerShell scripts. Do not disable
machine security policy merely to install this experimental candidate.

### Report a defect

Include the operating system, CPU architecture, exact command, complete error
message, and `naux --version` output in a
[GitHub issue](https://github.com/x2t8/Naux/issues).
