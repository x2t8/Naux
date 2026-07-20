# Naux Core Thesis

Naux is not trying to win by having the most features. It is trying to win by making optimizer decisions depend on semantic evidence instead of heuristics alone.

## Core Claim

The central bet of Naux is:

- the IR carries proof-style metadata
- optimizer passes consume that metadata directly
- high-value rewrites only fire when the attached evidence says their preconditions hold

This is the spine that connects the VM, bytecode format, SSA work, typed trace JIT, and formalization effort.

## What Naux Is Actually Building

Naux is a self-owned compiler/runtime stack with:

- a custom bytecode format
- a bytecode VM
- a typed trace JIT on `x86_64`
- optimizer work built on SSA and e-graph infrastructure
- formalization work that can feed invariants back into optimization

The goal is not "magic performance". The goal is a pipeline where optimization decisions are easier to justify, test, and eventually prove.

## Why This Matters

Most optimizers rely on a mix of syntax, local analysis, and cost heuristics. Naux is pushing toward a different center of gravity:

- semantic evidence lives in the IR
- rewrites are guarded by that evidence
- the JIT and optimizer consume the same spine instead of inventing separate stories

That makes the project narrower than a general "new language" pitch, but more defensible as a compiler research and engineering direction.

## Practical Focus

Naux should be judged by a small number of concrete outcomes:

- proof-aware optimization is visible in the compiler pipeline
- dead code and redundant checks are removed for reasons that can be inspected
- the JIT, SSA, and perf harness agree on what changed
- benchmarks stay reproducible on real runner hardware

## What This Thesis Is Not

- It is not a promise to beat C everywhere.
- It is not a claim that formal verification is complete.
- It is not a claim that every planned subsystem is finished.

It is a statement of what makes Naux distinct right now: proof-guided optimization in a self-owned JIT/compiler stack.
