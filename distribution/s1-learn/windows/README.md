# NAUX Learn 0.1.4 Windows bundle

![NAUX Learn](../../../assets/langnaux-learn.png)

> [!WARNING]
> This Windows candidate is not publicly distributed. The bundle definition
> remains reproducible packaging infrastructure while the Linux candidate is
> the active usability target.

This is the experimental Windows x86-64 GNU bundle for guided programming and
algorithm study. It contains a prebuilt `naux.exe`; using it does not require
Rust, Cargo, LLVM, MinGW, a C compiler, an assembler, or a linker.

It is not a production, security, sovereignty, or native-performance release.
Read `docs/LIMITATIONS.md` before use. The learner language surface is in
`docs/s1_learn_quick_reference_v0_1.md`.

Run `.\bin\naux.exe welcome` for the localized experimental-release
disclosure, or read `docs/RELEASE_DISCLOSURE.md`. Nine bounded installer
languages are sealed under `locales/`; this does not localize program output
or diagnostics.

## Host boundary

The intended real-host acceptance boundary is 64-bit Windows 10 22H2 or
Windows 11 with the system DLL contracts listed in `HOST-DEPENDENCIES.tsv`.
The executable is a PE32+ console application with the NAUX Learn multi-size
icon embedded as a native Windows resource, so Explorer and shortcuts can use
the project logo. No non-system MinGW DLL is shipped or required. This
candidate is not a supported Windows release until the checked real-host
carrier passes on that boundary.

## Verify, install, and run

From PowerShell in the extracted bundle directory:

```powershell
.\bin\naux.exe bundle verify .
.\NAUX-Learn-Setup.exe
```

Setup asks for one of nine languages before installation, shows the localized
experimental disclosure, asks for consent, and repeats the disclosure after
success. The default prefix is
%LOCALAPPDATA%\Programs\NAUX\Learn\0.1.4.

Expected stdout is stored in `examples/hello.out`. For your own program:

```powershell
Get-Content -Raw input.txt |
  & "$env:LOCALAPPDATA\Programs\NAUX\Learn\0.1.4\bin\naux.exe" run solution.nx
```

The installed executable does not invoke Rust or Cargo. `BUILD-SEED.tsv`
records the Rust/Cargo/egg and MinGW origin debt used to cross-build this
artifact; it is disclosure, not an installed runtime dependency.

The install report prints a sealed ownership receipt. The current executable
can verify and dry-run the exact uninstall plan. Actual Windows removal awaits
the detached native Setup helper because a running PE must not delete itself.

## Inventory

`MANIFEST.tsv` seals the exact files by path, transport mode, byte length, and
SHA-256. Verification rejects missing, substituted, duplicated, traversing,
oversized, hash-mismatched, linked, or extra members.
