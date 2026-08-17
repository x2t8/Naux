# Linux binary installation

[Tutorial index](README.md) · [Build from source](../README.md#build-from-source)

NAUX Learn 0.1.2 is an unsigned experimental pre-release for Linux x86-64 GNU.
It is dynamically linked and admits only the host boundary documented in the
[bundle contract](../docs/s1_learn_binary_bundle.md).

## Install

The bootstrap is pinned to version `0.1.2`, verifies the archive SHA-256, asks
for language and consent, and then runs native Setup:

```sh
curl -fsSL https://github.com/x2t8/Naux/releases/download/v0.1.2-learn/nauxup.sh | sh
```

Open a new terminal if `~/.local/bin` was already configured by your desktop,
or follow the exact `export PATH=...` line printed by Setup. Then verify:

```sh
naux --version
nauxup doctor
```

Expected version output is `naux 0.1.2`.

For an inspect-before-execute workflow, download `nauxup.sh`, the `.tar.gz`,
and `SHA256SUMS` from the
[GitHub pre-release](https://github.com/x2t8/Naux/releases/tag/v0.1.2-learn).
Review the bootstrap, verify the archive with `sha256sum -c SHA256SUMS`, then
run `sh nauxup.sh`.

Continue with the [five-minute quickstart](00-quickstart.md). Removal is
receipt-backed and documented in the [uninstall guide](05-uninstall.md).
