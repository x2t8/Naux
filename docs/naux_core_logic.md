# Naux Core Logic

This document names and defines the technical spine that Naux is building around.

## Working Name

**Semantic Evidence Feedback Optimization (SEFO)**

SEFO is the current best name for the central Naux technique:

- semantic evidence is carried in the IR
- optimization passes strengthen that evidence
- equality saturation and later lowering/JIT stages consume that evidence as a legality gate
- the optimizer runs as a bounded feedback loop instead of a one-way pipeline

This is the part of Naux that should stay coherent even as the rest of the project grows.

## One-Sentence Definition

Naux is building a compiler/JIT architecture where semantic evidence is first-class optimizer state, not just commentary atẹ tached to nodes or ad hoc side conditions on rewrites.

## What Counts As Semantic Evidence

In the current codebase, semantic evidence includes:

- `ProofSlot` facts attached to IR nodes
- `ProofEnv` snapshots collected across a block or feedback round
- proof-style facts strengthened by SSA passes such as SCCP
- legality facts such as:
  - constant values
  - nonzero/range constraints
  - aliasing facts
  - unsafe-context facts

The important point is not whether every fact is formally proved yet. The important point is that the optimizer treats these facts as state that can be carried, merged, strengthened, and consumed.

## Core Invariants

SEFO only stays meaningful if these invariants remain true:

1. Evidence Is Carried

Semantic evidence must survive long enough to matter.

- IR nodes carry `ProofSlot`
- lowering must not silently discard useful facts
- optimizer feedback can export upgraded evidence back into later stages

2. Evidence Is Strengthened Conservatively

Passes may add stronger facts, but only when the pass has actually established them.

- SCCP can upgrade a value to a proven constant
- alias facts can be tightened
- evidence growth should be monotonic within a round unless a transform rebuilds the graph and re-derives facts

3. Evidence Gates Legality, Not Just Cost

High-value rewrites must depend on whether the semantic precondition is satisfied, not only on heuristic preference.

- a rewrite is legal because the evidence allows it
- cost still matters, but cost is not the whole story

4. Feedback Is Bounded

The optimizer must not become an unbounded self-rewrite machine.

- feedback loops stop on fixed point
- or stop on diminishing returns
- or stop on an explicit iteration cap

5. Perf Must Stay Observable

If SEFO changes behavior, Naux must be able to explain it.

- canary benchmarks must stay visible
- optimizer stop reasons must be inspectable
- materialization and code-shape effects must be measurable

## Architecture Shape

SEFO touches multiple layers of Naux at once.

### Layer 2: Semantic Groundwork

- facts begin as proof-style metadata
- refined predicates and aliasing facts enter the pipeline here

### Layer 3: IR + E-Graph

- evidence is attached to IR nodes
- e-graph rewrites are selected or gated based on evidence
- materialization turns extracted equivalences back into IR shape

### Layer 4: SSA Optimizer

- SCCP, constant folding, and DCE do not just rewrite code
- they also create stronger evidence
- SSA can then feed evidence back into the IR/e-graph loop

### Layer 5: Lowering + JIT

- lowering should preserve the useful evidence that later stages can consume
- typed/JIT specialization should eventually rely on the same semantic spine, not invent a separate one

## What SEFO Looks Like In The Current Code

Today, SEFO already has concrete implementation hooks:

- `naux-lang/src/vm/ir.rs`
  - `ProofSlot`
  - `ProofEnv`
- `naux-lang/src/vm/ssa.rs`
  - proof-aware constant folding
  - SCCP
  - proof export back into the pipeline
- `naux-lang/src/vm/egraph.rs`
  - proof-aware legality requirements for rewrites
- `naux-lang/src/vm/compiler.rs`
  - bounded e-graph feedback loop
  - diminishing-returns stop condition
  - optimizer stop reasons

This means SEFO is implemented in constrained pieces with real verification and measurement requirements.

## What SEFO Is Not

SEFO is not:

- "beat C everywhere"
- "formal verification is finished"
- "every optimization is fully proved"
- "the optimizer can do arbitrary rewrites if the cost model likes it"

SEFO is also not about making Naux complicated for its own sake.

The goal is not obscurity.
The goal is a compiler whose optimization logic is difficult to copy because it is semantically coherent from end to end.

## Why This Is The Right Kind Of Difficulty

There are many ways to make a project look hard.

SEFO is the right kind of hard because it forces the whole compiler to agree on the same story:

- where facts come from
- when they become strong enough to matter
- which rewrites are legal
- when the optimizer should stop
- how performance consequences are measured

That kind of difficulty creates a moat. It does not just create confusion.

## Near-Term Consequences

If Naux is serious about SEFO, the next engineering priorities should follow from it:

1. Stabilize e-graph materialization on the canary benchmarks.
2. Add better materialization instrumentation so the compiler can explain shape changes.
3. Tighten legality from coarse/block-level evidence toward node/eclass-aware evidence.
4. Strengthen evidence representation so it depends less on stringly predicates.
5. Make typed/JIT specialization consume more of the same evidence spine.

## Decision Rule

When a new idea appears, Naux should ask:

> Does this make semantic evidence easier to carry, strengthen, consume, or explain?

If the answer is no, it is probably not core to Naux.

If the answer is yes, it is probably worth serious attention.
