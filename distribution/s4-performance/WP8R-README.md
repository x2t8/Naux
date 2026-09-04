# S4-WP8R — Public paired-bundle archive

WP8R turns one already-valid WP8M directory into a deterministic `.tar.gz`
plus a sealed receipt, then verifies downloaded copies by replaying WP8N.

Static validation performs no bundle access, packaging, network access, clock
read, or execution:

```bash
python3 scripts/s4_register_residency_public_bundle.py
```

After an eligible WP8M run for the tracked WP8Q commit, package it outside the
checkout with explicit `--package-bundle`, `--release-tag`, and `--output`.
Verify a downloaded archive with explicit `--archive` and `--receipt`.

The receipt pins the archive, bundle, session, host, source commit, and WP8N
evidence roots. Its GitHub URL is only a canonical locator declaration; WP8R
does not access the network or claim that the asset is publicly reachable.
