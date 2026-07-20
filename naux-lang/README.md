# naux-lang
Main crate for the active Naux implementation.

> [!CAUTION]
> **Experimental Research Software:** Naux is shared under the MIT License for learning, review, and experimentation. It is not recommended for production use. Use, modify, or distribute it entirely at your own risk; the author provides no warranty, support promise, safety guarantee, or liability for any consequences.

This crate contains the language frontend, runtime, bytecode VM, typed trace JIT, and the current SSA/optimizer work.

## What This Crate Does Today
- Frontend: lexer, parser, and typecheck are active.
- Runtime: evaluator + event flow + CLI/HTML rendering modes.
- VM: bytecode compiler + interpreter.
- JIT: typed trace JIT path on `x86_64`.
- SSA: CFG with explicit terminators, dominator tree, dominance frontier, phi placement, rename, verifier, and early optimizer passes.
- Advanced Systems: Refinement Types, Region Inference, and Algebraic Effects.

## What Is Still Rough
- JIT behavior outside the benchmarked/tested paths.
- Optimizer work is in progress, not feature-complete.
- Some docs/spec files are historical and kept only for context.

## Build and Run
```bash
cargo run -- run examples/graph_bfs.nx
```

Commands you will probably use:

```bash
cargo run -- dev ir examples/bench_sum_dense.nx
cargo run -- dev disasm examples/bench_sum_dense.nx
cargo run -- dev bench examples/bench_sum_dense.nx --engine vm --iters 100
```

## Quality Gate (before commit)
```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## CLI Commands (Core)
```bash
naux run <file.nx>
naux fmt [--check]
naux test
naux dev ir <file.nx>
naux dev disasm <file.nx>
naux dev bench <file.nx> --engine vm --iters 100
```

## Algorithm Coverage (stdlib)
- Collections: set/queue/priority_queue/stack/dsu/segment_tree.
- Graph: `graph_new`, `graph_add_edge`, `graph_bfs`, `graph_dijkstra`.
- Math/Algo: `gcd`, `lcm`, `pow_mod`, `sieve`, `lis_length`, `knapsack_01`, bounds helpers.

## Current Compiler Priority
1. `mem2reg`
2. CFG-aware dead code elimination
3. constant propagation
4. benchmark regression hardening
5. LICM/GVN (after core passes are stable)

## Important Paths
- Source: `src/`
- Tests: `tests/`
- Examples: `examples/`
- Specs/docs: `docs/`, `SPEC.md`

## Read Next
- Workspace doc index: `../docs/README.md`
- Active IR spec: `docs/IR_SPEC.md`
- Pipeline overview: `../docs/compiler_pipeline.md`
