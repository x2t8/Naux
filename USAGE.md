# Naux Usage

This file is the shortest path to doing useful work in this repo without
guessing.

## Quick start

From repo root:

```bash
cargo run -p naux -- run naux-lang/examples/graph_bfs.nx
```

Inspect compiler output:

```bash
cargo run -p naux -- dev ir naux-lang/examples/bench_sum_dense.nx
cargo run -p naux -- dev disasm naux-lang/examples/bench_sum_dense.nx
```

## Health check

Run this before perf work or before debugging an odd local failure:

```bash
cargo run -p naux -- doctor
```

Machine-readable report:

```bash
cargo run -p naux -- doctor --json --out target/naux-doctor.json
```

`naux doctor` currently checks:
- `rustc`, `cargo`, `taskset`, and optional `coqc`
- perf baseline files in `benchmarks/`
- CPU governor / turbo policy signals
- parse health for the standard `.nx` program roots

## Build and test

For a project created with `naux new`, run the complete project workflow:

```bash
naux verify
```

This stops on the first failure and executes:

1. semantic check of `[build].entry`;
2. project tests under `tests/`;
3. project build;
4. the configured runtime benchmark.

The generated `naux.toml` contains:

```toml
[verify]
benchmark = "bench.nx"
engine = "vm"
iters = 5
warmup_ms = 0
```

Repo-root quality gate:

```bash
cargo fmt --manifest-path naux-lang/Cargo.toml --all -- --check
cargo clippy --manifest-path naux-lang/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path naux-lang/Cargo.toml --all-features
```

SSA-focused loop:

```bash
cargo test -p naux vm::ssa -- --nocapture
```

Sanity corpus parity:

```bash
./scripts/sanity_matrix.sh
```

Compiler / e-graph loop:

```bash
cargo test -p naux vm::compiler -- --nocapture
cargo test -p naux vm::egraph -- --nocapture
```

## Runtime and perf

Single benchmark smoke:

```bash
cargo run -p naux --release -- dev benchrt naux-lang/examples/bench_sum_dense.nx --engine=jit --iters=100 --warmup-ms=100
```

Full perf contract:

```bash
bash ./scripts/perf_contract_ci.sh
```

Before trusting perf results, prefer:
- pinned CPU via `taskset`
- governor set to `performance`
- a declared and repeatable turbo policy
- baseline fingerprint present in `benchmarks/perf_baseline_fingerprint.json`

See `docs/benchmarks.md` and `PERF_CONTRACT.md` for the stricter contract.
