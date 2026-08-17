# NAUX Research Preview trust surface v0.1

Status: active work package
Date: 2026-08-17
Scope: S2-WP1 / public policy and artifact provenance

## Purpose

S2-WP1 makes an experimental binary inspectable without widening NAUX Learn's
language, host, safety, performance, or sovereignty claims. It separates four
questions that a public preview must answer:

1. What exact artifact was distributed?
2. Which tagged source commit and tree produced it?
3. Which seed metadata and release disclosure were in force?
4. Where should correctness, compatibility, support, and security reports go?

This package adds evidence and policy. It does not change language semantics,
declare the implementation secure, or authenticate the publisher.

## Canonical provenance record

`PROVENANCE.tsv` is UTF-8/LF text with exactly fourteen ordered rows:

```text
NAUX-S2-RELEASE-PROVENANCE<TAB>1
product<TAB>naux-learn
version<TAB>MAJOR.MINOR.PATCH
tag<TAB>vMAJOR.MINOR.PATCH-learn
target<TAB>linux-x86_64-gnu
source-commit<TAB>40-lower-hex
source-tree<TAB>40-lower-hex
build-seed-sha256<TAB>64-lower-hex
release-notes-sha256<TAB>64-lower-hex
bundle-manifest-seal<TAB>64-lower-hex
asset<TAB>archive<TAB>BYTES<TAB>SHA256<TAB>NAME
asset<TAB>checksum<TAB>BYTES<TAB>SHA256<TAB>SHA256SUMS
asset<TAB>bootstrap<TAB>BYTES<TAB>SHA256<TAB>nauxup.sh
seal<TAB>64-lower-hex
```

The final seal is SHA-256 over the domain bytes
`NAUX:s2-release-provenance:v1\0` followed by the exact first thirteen rows,
including their line feeds. It provides deterministic integrity and domain
separation, not a digital signature.

## Producer and verifier separation

`scripts/render_s2_preview_provenance.sh` consumes an already verified S1
release, explicit source commit/tree identities, and the independently visible
inner bundle seal. It writes one new file and then invokes the independent
consumer.

`scripts/verify_s2_preview_provenance.sh` reconstructs and checks:

- exact four-file release inventory and regular-file types;
- version, tag, target, commit, tree, seed, and release-note bindings;
- byte length and SHA-256 of every public asset;
- the canonical `SHA256SUMS` and deterministic S1 archive contract;
- the inner bundle manifest seal extracted from the archive;
- the domain-separated provenance seal.

The verifier accepts expected source commit and tree as independent inputs. It
does not trust the values merely because they appear in the provenance record.

`scripts/package_s2_preview.sh` is the publication boundary. It refuses a
dirty worktree, requires the exact annotated release tag at `HEAD`, derives the
commit and tree independently, builds the S1 carrier, emits provenance, and
replays the complete verifier before publication.

## Mutation and policy gates

`scripts/test_s2_preview_provenance.sh` requires two independent release builds
to produce byte-identical provenance. It rejects a wrong expected source
commit or tree, mutation of each public asset, a mutated provenance seal, a
false inner manifest seal, and an extra asset. Linked assets and noncanonical
transport modes are rejected as well. It also requires the public security,
compatibility, and support policy files. The same gate reconstructs the bundle
metrics and requires the public version, install URL, manifest seal, archive
size, and archive hash to agree with the emitted artifact.

## Explicit non-claims

This record is not signing, key management, SLSA conformance, a hermetic build,
reproducibility across arbitrary roots, vulnerability-free evidence, production
support, stable compatibility, dependency closure, or Nauxogenesis. Rust,
Cargo, `egg`, GNU archive tools, and the declared dynamic host remain visible
debt or producer/host dependencies.

S2-WP1 is complete only after a clean tagged preview is emitted through this
new boundary, independently downloaded, and replayed on the supported host.
