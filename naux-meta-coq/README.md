# NAUX Coq model

This directory contains the separately checked formal model for NAUX semantic
claims. The tracked authority is deliberately small:

- `*.v` — proof source;
- `_CoqProject` — module/build configuration;
- `Makefile` — reproducible local entry point.

Compiled Coq products (`*.vo`, `*.glob`, auxiliary caches, and related files)
are generated locally and must not be committed.

`RegisterResidency.v` proves a bounded compiler theorem: scalar updates and
admissible physical-home loads/stores for one selected stack slot can execute
against a resident register, preserving the selected value and all
non-selected state; a final spill restores every baseline stack slot. It
deliberately does not claim an x86-64, allocator, aliasing, call, trap,
control-flow-selection, or whole-language proof.

```bash
make -C naux-meta-coq
coqchk -silent -o -Q naux-meta-coq NauxCore \
  NauxCore.NauxCore NauxCore.Soundness NauxCore.RegisterResidency
make -C naux-meta-coq clean
```

The checked baseline is Rocq 9.1. CI rebuilds every proof, replays the generated
objects in the kernel, and requires the reported axiom set to remain empty.
