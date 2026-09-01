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

`ProjectedCFGResidency.v` joins that admitted path property to the bounded
physical-access semantics. Before the first store, the candidate may hide only
the reserved register. The first store establishes the resident invariant;
later accesses preserve it; final spill and callee-saved restoration recover
the complete baseline stack and register state. The theorem consumes the same
CFG paths checked by `DefiniteInitialization.v`. Its boundary is intentionally
the projected `resident_instruction` trace: pass-through Machine IR semantics,
report parsing, and whole-compiler correctness remain separate obligations.

The formal-residency bridge rebuilds the reviewed WP8C emitter, authenticates
its complete 276-line report through the sealed authority, translates the four
physical-access CFGs into untrusted Rocq certificates, and admits them again
with the checked initialization and operand boundaries. For every finite path
through each generated graph, Rocq then derives full-state equivalence for the
physical-access projection after spill and ABI restoration. The generated
certificate preserves each transformed virtual-register operand and i64
constant. Its register encoding keeps namespaces disjoint: Rocq register `0`
denotes physical `r12`, while virtual `rN` maps to `S N`. The proof source is
ephemeral and is not a new sealed project artifact; omitted pass-through
instructions are still outside this semantic claim.

```bash
make -C naux-meta-coq
rocq check -silent -o -Q naux-meta-coq NauxCore \
  NauxCore.NauxCore NauxCore.Soundness NauxCore.RegisterResidency \
  NauxCore.DefiniteInitialization NauxCore.ProjectedCFGResidency
make -C naux-meta-coq clean
```

The checked baseline is Rocq 9.1. CI rebuilds every proof, replays the generated
objects in the kernel, and requires the reported axiom set to remain empty.
