# Uninstall NAUX Learn

[Tutorial index](README.md) · [Troubleshooting](06-troubleshooting.md)

NAUX installation ownership is recorded in a sealed receipt. Uninstall uses
that receipt and the exact installed bundle; it does not scan the whole
machine or guess which files belong to NAUX.

## Linux

Setup prints a receipt path after installation. Preview the removal first:

```sh
"$NAUX" installation uninstall --receipt "/exact/path/from/setup.tsv" --dry-run
```

Review the listed files and directories, then execute exact removal:

```sh
"$NAUX" installation uninstall --receipt "/exact/path/from/setup.tsv"
```

Uninstall re-verifies the receipt and installed bundle before mutation.

If the original Setup output was lost, receipts are confined to the dedicated
state directory. Listing this directory is not a machine-wide scan:

```sh
ls "${XDG_STATE_HOME:-$HOME/.local/state}/naux-learn"
```

Choose the receipt whose contents name the installed 0.1.0 prefix. Do not use
a receipt from a different installation.

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
