# Naux Parity Ledger

This file tracks parity claims that should stay explicit and test-backed.

## Active parity targets

### VM vs JIT runtime parity
- Goal: identical observable events and compatible final values for covered programs.
- Evidence:
  - runtime and smoke tests under `tests/`
  - focused VM/JIT examples in `naux-lang/examples/`
  - `./scripts/sanity_matrix.sh`
- Current note:
  - treat any divergence as a correctness bug before treating it as a perf issue

### IR vs bytecode lowering parity
- Goal: lowering preserves the intended control/data flow shape for covered instruction families.
- Evidence:
  - `naux-lang/src/vm/compiler.rs` tests
  - bytecode inspection via `naux dev bytecode`
- Current note:
  - proof/cost metadata threading is now part of this parity surface

### E-graph rewrite parity
- Goal: proof-gated rewrites only fire when their legality evidence exists.
- Evidence:
  - `cargo test -p naux vm::egraph -- --nocapture`
  - compiler integration tests for materialization paths
- Current note:
  - SCCP proof feedback now increases the legality evidence pool; parity checks should cover that bridge

### SSA optimizer parity
- Goal: fold / SCCP / DCE preserve semantics while changing only optimized shape.
- Evidence:
  - `cargo test -p naux vm::ssa -- --nocapture`
  - targeted compiler tests for lowered output
- Current note:
  - branch pruning and proof upgrades should be treated as parity-sensitive, not just perf-sensitive

## How to use this file

- Add a short note when a new parity surface becomes important.
- Prefer linking to a concrete test or run artifact.
- If a parity claim is not backed by a test yet, mark it as provisional.
