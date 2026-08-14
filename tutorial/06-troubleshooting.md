# NAUX Learn Troubleshooting

[Tutorial index](README.md) · [Linux install](01-install-linux.md) ·
[Windows install](02-install-windows.md)

## `naux: command not found`

NAUX Learn 0.1.1 creates launchers in `~/.local/bin` but deliberately does not
modify shell profiles.

Linux:

```sh
export PATH="$HOME/.local/bin:$PATH"
naux --version
```

Windows PowerShell:

```powershell
$Naux = Join-Path $env:LOCALAPPDATA 'Programs\NAUX\Learn\0.1.0\bin\naux.exe'
& $Naux --version
```

## The installation prefix already exists

Setup is fail-closed and never overwrites an existing prefix. Verify and
uninstall the existing installation, or use the manual Setup interface with a
new explicit prefix.

## Linux reports an unsupported host

The public Linux bundle admits only Linux x86-64 with the declared GNU dynamic
loader and system-library boundary. It does not support ARM64, 32-bit x86,
musl-only systems, macOS, BSD, or other targets.

## A Linux dependency is missing

The bootstrap requires `curl`, `tar`, and `sha256sum`. Install the missing
system utility with the operating system's trusted package manager, then retry.
Do not replace checksum verification with an unverified download.

## PowerShell blocks the Windows command

Confirm that the terminal is 64-bit PowerShell, GitHub is reachable over
HTTPS, and organization policy permits PowerShell scripts. Do not disable
machine security policy merely to install an unsigned experimental candidate.

## A program reaches a work or call-depth limit

First check for an accidental infinite loop or recursion. For a deliberately
larger exercise, use bounded positive overrides:

```text
naux run solution.nx --max-work 100000 --max-call-depth 64
```

Hard ceilings still apply. These limits are semantic execution controls, not
a security sandbox.

## A program fails to parse or type-check

Run `naux check solution.nx` and read the source-positioned diagnostic. The
learner grammar uses `$name` for variables, `~ rite` for the entry block,
`~ end` to close structured blocks, and boolean conditions. See the
[quick reference](../docs/s1_learn_quick_reference_v0_1.md).

## Report a reproducible defect

Open a [GitHub issue](https://github.com/x2t8/Naux/issues) with:

- operating system and CPU architecture;
- `naux --version` output;
- the exact command;
- the smallest `.nx` source and input that reproduce the problem;
- complete stdout, stderr, and exit status;
- whether the VM and `--engine interp` agree.
