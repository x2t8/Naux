# Scope 3 trusted-thesis candidate: limits

This directory is a machine-checkable audit bundle for one bounded experiment.
It does not turn the experiment into a general claim about the NAUX language.

## What is bound

- One fixed twelve-case Surface program corpus.
- Agreement among Surface, Core, SSA, Machine IR, the x86-64 target plan, and
  observed native results.
- One fresh Linux x86-64 worker process per case, with an exact 715-byte frame.
- The observed `Unmapped -> ReadWrite -> ReadExecute -> Unmapped` mapping trace.
- Canonical roots, source files, seed debt, experiments, negative tests, and
  deterministic evaluator output.

## What is not claimed

- Correctness for arbitrary NAUX programs, targets, effects, or compiler passes.
- A security sandbox, hostile-code containment, or executable attestation.
- Reproducible binary bytes or a complete inventory of each build host.
- Standalone execution without the current Rust/Cargo seed.
- Removal of Rust, rustc's LLVM backend, or `egg` dependency debt.
- Performance leadership over C, C++, Rust, or any other implementation.
- Futamura P2, Futamura P3, self-origin, or Nauxogenesis.

The worker path is explicitly supplied by the evaluator and is therefore a
reviewed trust input. The evaluator executes only fixed argument vectors; no
command stored in a manifest is evaluated by a shell.
