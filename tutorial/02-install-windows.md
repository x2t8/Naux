# Install NAUX Learn on Windows

[Tutorial index](README.md) · [First program](03-first-program.md) ·
[Troubleshooting](06-troubleshooting.md)

> [!CAUTION]
> NAUX Learn 0.1.0 for Windows is an unsigned experimental candidate. Its
> deterministic archive, PE boundary, imports, icon, installation lifecycle,
> and Wine smoke have been checked, but its required Windows 10/11 real-host
> release gate is still pending.

Normal candidate installation and learner execution do not require Rust,
Cargo, LLVM, MinGW, or a C/C++ compiler.

## 1. Check the host

Open 64-bit PowerShell on Windows 10 22H2 or Windows 11:

```powershell
$env:PROCESSOR_ARCHITECTURE
```

The expected architecture is `AMD64`.

## 2. Install

```powershell
irm https://github.com/x2t8/Naux/releases/download/v0.1.0-learn/nauxup.ps1 | iex
```

The bootstrap downloads only the exact 0.1.0 Windows archive and checksum,
checks its byte length and SHA-256, verifies the inner sealed manifest, and
then opens Setup. Setup asks for a language, displays the experimental-release
boundary, and asks for confirmation.

Keep the printed receipt path. It is required to verify ownership and preview
uninstall.

## 3. Locate NAUX

The default installation is:

```text
%LOCALAPPDATA%\Programs\NAUX\Learn\0.1.0
```

In PowerShell:

```powershell
$NauxHome = Join-Path $env:LOCALAPPDATA 'Programs\NAUX\Learn\0.1.0'
$Naux = Join-Path $NauxHome 'bin\naux.exe'
```

## 4. Verify and run the bundled program

```powershell
& $Naux --version
& $Naux run (Join-Path $NauxHome 'examples\hello.nx')
```

Expected version:

```text
naux 0.1.0
```

## 5. Optional short command for this PowerShell session

```powershell
function naux { & $Naux @args }
naux --version
```

This function disappears when the PowerShell session closes and creates no
untracked profile file.

Continue with [your first NAUX program](03-first-program.md).

## Inspect before running

Download `nauxup.ps1`, the ZIP, and its adjacent `.sha256` file from the
[release page](https://github.com/x2t8/Naux/releases/tag/v0.1.0-learn) if you
prefer to inspect the script before execution. The Windows candidate remains
unsigned; a checksum is integrity evidence, not publisher authentication.
