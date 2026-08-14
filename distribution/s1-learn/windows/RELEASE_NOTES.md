# NAUX Learn 0.1.1 for Windows

Status: experimental Windows release candidate\
Publication: withdrawn; retained only as a historical build record\
Target: Windows x86-64 GNU (`windows-x86_64-gnu`)\
Scope: guided programming and algorithm study

This archive contains a prebuilt `naux.exe`, the NAUX Learn 0.1 learner
reference, deterministic first program, exact build-seed disclosure, host DLL
inventory, a sealed project-logo asset, and a sealed directory manifest. The
same identity is embedded into `naux.exe` as a native 16/32/48/256-pixel icon
resource for Windows Explorer and shortcuts. It also contains nine sealed
installer/disclosure locales and an exact installation-ownership receipt
foundation.

## Publication status

This candidate is withdrawn and has no public installer URL. The material
below is retained only to reproduce and verify locally built historical
artifacts.

## Manual install

In PowerShell, verify the adjacent archive checksum before extraction:

```powershell
$expected = (Get-Content .\naux-learn-0.1.1-windows-x86_64-gnu.zip.sha256).Split()[0]
$actual = (Get-FileHash .\naux-learn-0.1.1-windows-x86_64-gnu.zip -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $expected) { throw "NAUX archive checksum mismatch" }
Expand-Archive .\naux-learn-0.1.1-windows-x86_64-gnu.zip -DestinationPath .
cd .\naux-learn-0.1.1-windows-x86_64-gnu
.\bin\naux.exe bundle verify .
.\NAUX-Learn-Setup.exe
```

This candidate is unsigned and experimental. It is not suitable for
production, safety-critical, or security-critical use. It makes no native-
performance, C/C++ leadership, stable ABI, long-term compatibility,
sovereignty, self-generation, or compiler-generation claim. A checked replay
on real Windows 10/11 hardware remains required before this becomes a
supported Windows release.

Installation is currently performed by the checked native
NAUX-Learn-Setup.exe console carrier. It selects language before install,
shows the localized disclosure, asks for consent, and repeats the disclosure
after success. Exact uninstall planning is available from the sealed receipt;
actual Windows removal remains delegated to the pending detached Setup helper
because a running `naux.exe` must not remove itself. This candidate does not
yet include a GUI setup wizard, shortcut creator, MSIX package, or
Authenticode signature.
