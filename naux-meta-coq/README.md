# NAUX Rocq model

This directory contains the separately checked formal model for NAUX semantic
claims. The tracked authority is deliberately small:

- `*.v` — proof source;
- `_CoqProject` — module/build configuration;
- `Makefile` — reproducible local entry point.

Compiled Coq products (`*.vo`, `*.glob`, auxiliary caches, and related files)
are generated locally and must not be committed.

`RegisterResidency.v` proves a bounded compiler theorem: starting from one
ordinary machine state, a selected stack slot may become resident through an
entry load or an initializing first store, be updated by an admitted
instruction trace or a bounded repetition of one admitted loop body, and be
spilled back. A residency certificate records which entry strategy establishes
the physical home. A reflected Boolean checker rejects complete certificates
that clobber or self-source the reserved register, or claim the first-store
strategy without an initializing store. After spilling the home slot and
restoring the saved callee-owned register, every stack and register cell agrees
with the baseline execution. This semantic-equivalence theorem deliberately
does not claim an x86-64, allocator, aliasing, call, trap, arbitrary-CFG,
plan-parser, or whole-language proof.

`DefiniteInitialization.v` models the control-flow must analysis used before a
first-store residency transform is admitted. Its executable checker validates
canonical finite block graphs, reachability closure, and conservative incoming
facts. The soundness theorem covers every finite path from the entry block and
rules out a load or update before the physical home is initialized on that
path.

```bash
make -C naux-meta-coq
rocq check -silent -o -Q naux-meta-coq NauxCore \
  NauxCore.NauxCore NauxCore.Soundness NauxCore.RegisterResidency \
  NauxCore.DefiniteInitialization
make -C naux-meta-coq clean
```

The checked baseline is Rocq 9.1. CI rebuilds every proof, replays the generated
objects in the kernel, and requires the reported axiom set to remain empty.
