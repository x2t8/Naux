# NAUX Research Preview exit audit

Status: closure candidate; fresh public CI pending

Audit date: 2026-08-21

Release under audit: NAUX Learn 0.1.4 / `linux-x86_64-gnu`

Scope authority: Scope 2 in `NAUX_SCOPE_LADDER.md`

## Decision

Scope 2 is not yet recorded as complete. Its released artifact gates and local
technical gates pass, but the closure commit must first pass one fresh public
CI run containing the corrected provenance-mutation carrier and the new
tracked-link and Linguist-surface gates.

GitHub Linguist recognition is not a Scope 2 exit gate. The grammar is ready
for inspection, but an upstream PR must remain unopened until independent
real-world NAUX usage satisfies Linguist's policy.

## Exit-gate matrix

| Scope 2 exit gate | Result | Evidence |
|---|---|---|
| Clean supported machine installs and runs the preview | Pass | The public `v0.1.4-learn` assets completed a clean-HOME, no-Rust/Cargo install, run, doctor, and uninstall replay on `linux-x86_64-gnu`. |
| Format, lint, tests, governance, and artifact-link audits pass | Local pass; public replay pending | `cargo fmt --all -- --check`, strict all-target/all-feature Clippy, focused release identity, terminal I/O, provenance mutation, grammar validation, Python governance/link tests, and the tracked-link audit pass locally. Public runs `32469453512` and `32472185638` exposed the two additional carrier defects described below; neither run is borrowed as closure evidence. |
| Exact binaries and evidence bundles are reproducible | Pass | `v0.1.4-learn` binds source commit `393df085205f2d82c687a3a5fa677ff0854361c0`, source tree `680d83872f4107dbf05c4f9361190d75b4fa0cb2`, archive SHA-256 `13682a9825b37cd12bc010efbfd7d9dc1b9c7b711583615b52b078e397dc8f1b`, and provenance seal `56b9962a4d332baea18eb808a5a6b141b41d138c5bf37f6d33e39a992f5f1a6d`. Independently downloaded assets match the local producer. |
| Limitations and seed dependencies are visible before install | Pass | The release disclosure, limitations, `BUILD-SEED.tsv`, `HOST-DEPENDENCIES.tsv`, README, support, compatibility, and security policies disclose the Rust/Cargo seed, `egg`, dynamic host, experimental status, and non-claims. |
| Examples use real source-to-runtime paths | Pass | The installed first program and learner corpus execute through ordinary `naux run`; the release identity tests reject an example or launcher that bypasses the packaged runtime path. |

## S2-WP2 technical surface

The canonical grammar is `x2t8/naux-grammar` tag `v0.1.2`, annotated tag
object `36e5eae4ddfe6db35d5a268cf36032cc4fcd12e1`, commit
`124d72cc8ae4fdaef6413ef94e6cf895fb294a55`, and tree
`34f0f17115a5367c6ca20f445de3bd3fef835143`. The sealed 14-file mirror is
recorded in `distribution/s2-preview/LINGUIST-SURFACE.tsv` under seal
`031d82feef5f7f9c0ddab11d58059d3ca99384e49aa6f62b43bc8626ed0ee7c9`.

`scripts/s2_linguist_surface.py` rejects inventory, mode, length, content,
identity, dependency, tag, commit, and tree drift. With a canonical checkout,
it additionally replays the annotated tag and compares all 14 files byte for
byte. The existing dependency-free grammar validator independently checks
`.nx`, `source.naux`, `#FF304D`, snippets, language configuration, and all 71
public compiler builtins.

The 2026-08-21 GitHub capture found 3,800 raw files named `*.nx`, but that
extension is shared by unrelated projects. Excluding owner `x2t8`, the
canonical `"~ rite"` signature returned zero matches, `"read_int()"` returned
zero, and `"!say"` returned one unrelated Discord example. Therefore no
qualifying independent NAUX usage count is claimed and no Linguist PR is
authorized.

## CI defects found by the audit

The previous provenance test changed the first seal character to `0`. On a
runner whose valid seal already began with `0`, the file stayed byte-identical
and the test incorrectly reported that the verifier accepted a mutation. The
carrier now reads the existing first character and deterministically flips it
between `0` and `1`, guaranteeing that the negative case is a real mutation.

This was a test defect, not an accepted invalid artifact. The corrected
carrier passes locally and still rejects source/tree mismatch, every public
asset mutation, seal mutation, extra members, links, and mode drift.

The first public closure run then rebuilt the release on an ambient GitHub
runner and required its archive bytes to equal the artifact produced on the
controlled release host. That assertion contradicted the bundle contract,
which does not claim a hermetic origin image or arbitrary-build-root byte
identity. The current producer/consumer mutation carrier remains offline and
deterministic, while exact published evidence is now replayed separately: CI
downloads the four immutable `v0.1.4-learn` assets, byte-compares the published
provenance with the tracked sealed lock, runs the independent verifier, and
checks the documentation against the downloaded archive.

The following documentation commit changed three files inside the exact
14-file grammar mirror after it had been sealed against canonical grammar tag
`v0.1.2`. The next public run correctly failed on that content drift. The
monorepo mirror is restored byte-for-byte to the canonical tag; project-site
links remain on the root public surface and do not mutate the frozen grammar
package.

## Closure condition

The owner may record Scope 2 complete only after the current closure repairs
are committed and one fresh public CI run passes every job. A red, cancelled,
or older run cannot be borrowed as closure evidence. Scope 3 remains queued
until that event; the external Linguist adoption gate remains separate and may
stay open indefinitely without reopening a completed Research Preview.
