# Uninstall NAUX Learn

[Tutorial index](README.md) · [Troubleshooting](06-troubleshooting.md)

NAUX installation ownership is recorded in a sealed receipt. Uninstall uses
that receipt and the exact installed bundle; it does not scan the whole
machine or guess which files belong to NAUX.

## Linux

Preview exact removal first:

```sh
nauxup uninstall --dry-run
```

Review the listed files and directories, then execute exact removal:

```sh
nauxup uninstall
```

`nauxup` re-verifies the activation receipt, immutable bundle receipt, every
bundle member, and both launcher targets before mutation. Run `nauxup doctor`
for the same admission checks without removal.

If the original Setup output was lost, receipts are confined to the dedicated
state directory. Listing this directory is not a machine-wide scan:

```sh
ls "${XDG_STATE_HOME:-$HOME/.local/state}/naux/receipts"
```

The current activation receipt is named `learn-0.1.3.tsv`; users normally do
not need to pass it manually.

## Windows candidate

The candidate can verify a receipt and preview the exact plan:

```powershell
$ReceiptDirectory = Join-Path $env:LOCALAPPDATA 'NAUX\state'
Get-ChildItem -LiteralPath $ReceiptDirectory -Filter '*.tsv'
& $Naux installation uninstall --receipt 'C:\exact\receipt-from-setup.tsv' --dry-run
```

> [!WARNING]
> NAUX Learn 0.1.0 does not yet execute Windows removal. The running PE refuses
> to delete itself; a detached native remover is required before Windows can
> become supported. A successful dry-run is not a completed uninstall.

The candidate documentation does not recommend an unverifiable recursive
delete as if it were the official lifecycle.
