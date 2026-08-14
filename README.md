<div align="center">
  <img src="assets/langnaux-learn.png" alt="NAUX Learn" width="220" />

# Naux

  <p><strong>An experimental programming language, compiler, runtime, and native-code laboratory.</strong></p>

  <p>
    <img alt="Rust 2021" src="https://img.shields.io/badge/Rust-2021-b7410e?logo=rust&logoColor=white" />
    <img alt="Status" src="https://img.shields.io/badge/status-experimental-orange" />
    <img alt="CLI" src="https://img.shields.io/badge/CLI-naux-1f6feb" />
    <img alt="License" src="https://img.shields.io/badge/license-MIT-green" />
  </p>

  <p>
    <a href="INSTALL.md"><strong>Install NAUX Learn</strong></a>
    ·
    <a href="LEARN.md"><strong>Write your first program</strong></a>
    ·
    <a href="https://github.com/x2t8/Naux/releases/tag/v0.1.0-learn"><strong>Current prerelease</strong></a>
  </p>
</div>

Naux is a hands-on language implementation covering the path from `.nx`
source code to interpretation, bytecode execution, optimization, and
experimental native execution. The repository includes the compiler/runtime
source, integration tests, examples, developer tools, and a reproducible
cross-language benchmark harness.

> [!WARNING]
> Naux is active experimental research software. It may contain incomplete
> features, undocumented behavior, and unsafe compiler/runtime experiments.
> Do not use it for production or safety-critical systems.

## Highlights

| Area | Available implementation |
|---|---|
| Language frontend | Span-aware lexer, parser, formatter, diagnostics, and type checking |
| Execution | Reference interpreter and bytecode virtual machine |
| Compiler IR | Stack IR, SSA construction, CFG/dominator analysis, and verification |
| Optimization | Proof-gated rewrites, e-graph experiments, refinement analysis, and specialization infrastructure |
| Native paths | Typed trace JIT plus verifier-gated x86-64 encoding/execution experiments |
| Language systems | Regions, effects, ownership experiments, closures, and collection semantics |
| Developer UX | CLI, project scaffolding, health checks, verification workflow, and terminal IDE |
| Evidence | Integration/parity tests and C/C++/Go/Rust/Zig benchmark baselines |

The table describes code that exists in this repository. It is not a
production-readiness or performance claim.

## Quick start

### Current public prerelease: NAUX Learn 0.1.0

The public experimental release bundle supports Linux x86-64 GNU and does
not require Rust or Cargo for installation or normal learner execution. The
version-pinned one-command installer downloads the exact sealed archive,
checks its byte length and SHA-256, verifies its inner manifest, then opens the
localized Setup flow:

```bash
curl -fsSL https://github.com/x2t8/Naux/releases/download/v0.1.0-learn/nauxup.sh | sh
```

Windows PowerShell has an unsigned experimental candidate:

```powershell
irm https://github.com/x2t8/Naux/releases/download/v0.1.0-learn/nauxup.ps1 | iex
```

Start with the step-by-step [installation and uninstall guide](INSTALL.md),
then [write the first NAUX program](LEARN.md). The Windows artifact remains a
candidate until its declared real-Windows gate passes. The `main` branch is
preparing 0.1.1; commands above deliberately point to the latest artifact that
is actually public. The bundles are dynamically linked, Rust-seeded
experimental artifacts. A checksum is integrity evidence, not a publisher
signature.

### Build from source

Requirements:

- a recent stable Rust toolchain;
- Cargo;
- Linux, macOS, or Windows for the portable frontend/VM paths;
- Linux x86-64 for Linux-specific native experiments.

From the repository root:

```bash
cargo run -p naux -- run naux-lang/examples/hello.nx
cargo run -p naux -- run naux-lang/examples/graph_bfs.nx
printf '4 10 -3 5 30\n' | cargo run -p naux -- run naux-lang/examples/learn_sum.nx
cargo run -p naux -- doctor
```

Run the test suite:

```bash
cargo test --workspace
```

On Windows with the GNU Rust toolchain:

```powershell
$env:CARGO_TARGET_DIR = 'D:\cargo-target-langnaux'
cargo +stable-x86_64-pc-windows-gnu run -p naux -- run naux-lang/examples/hello.nx
```

## Language example

```text
$n = 10
$i = 0
$sum = 0

~ loop $n
    $sum = $sum + ($i * 3 + 1)
    $sum = $sum - ($i % 7)
    $i = $i + 1
~ end

^ $sum
```

Run a program with a selected engine:

```bash
cargo run -p naux -- run path/to/program.nx --engine vm
```

The current surface language uses:

- `$name` for variables;
- `~ ... ~ end` for structured blocks;
- `^ expression` for returns;
- `!action` for runtime actions.

See the [language specification](docs/language_spec.md) for the admitted
surface behavior.

## Current execution pipeline

```mermaid
flowchart LR
    SRC[.nx source] --> LEX[Lexer]
    LEX --> PARSE[Parser]
    PARSE --> AST[AST]
    AST --> TC[Type checker]
    TC --> INTERP[Interpreter]
    TC --> BC[Bytecode compiler]
    BC --> OPT[IR and SSA passes]
    OPT --> VM[Bytecode VM]
    OPT --> JIT[Typed trace JIT]
    OPT --> NATIVE[x86-64 experiments]
    INTERP --> EVENTS[Runtime events]
    VM --> EVENTS
    JIT --> EVENTS
    EVENTS --> CLI[CLI / TUI / HTML renderers]
```

Unsupported optimized/native forms are expected to reject or fall back
according to their declared boundary; silent semantic divergence is treated
as a bug.

## CLI

Common commands:

```text
naux run <file.nx> [--engine vm|interp|jit] [--mode plain|cli|html|json]
naux check <file.nx>
naux fmt <path-or-dir>
naux test
naux verify
naux doctor [--json --out <file>]
naux ide [file.nx]
```

`naux run` uses plain `!say` output by default and accepts bounded UTF-8 batch
input through `read_int()`, `read_token()`, and `read_line()`. See the
[NAUX Learn batch-I/O contract](docs/s1_learn_batch_io.md) for exact EOF,
cursor, size, and fallback semantics. Use `--mode cli` for the ritual event
renderer. Common lexer, parser, type, and runtime failures use the bounded
[NAUX Learn source-diagnostic contract](docs/s1_learn_diagnostics.md) across
normal `run` and `check` paths.

The versioned [NAUX Learn exercise corpus](docs/s1_learn_corpus.md) contains 30
deterministic cases spanning introductory programming, search, sorting, graph,
greedy, and dynamic programming. Its acceptance carrier executes every
solution through the normal `naux run` command.
The [NAUX Learn quick reference v0.1](docs/s1_learn_quick_reference_v0_1.md)
defines the smaller learner-facing compatibility profile and carries executed
VM/interpreter examples. Normal learner execution is fail-closed under the
[bounded execution envelope](docs/s1_learn_execution_envelope.md), whose work
units are source-semantic checkpoints rather than backend instructions.
The [supported-host bundle contract](docs/s1_learn_binary_bundle.md) defines a
sealed Linux x86-64 GNU directory artifact whose prebuilt binary can verify,
install, and run the first learner program without Rust or Cargo. This remains
a dynamically linked, Rust-seeded experimental boundary, not sovereignty or a
production release.

Compiler and runtime inspection:

```text
naux dev ir <file.nx>
naux dev disasm <file.nx>
naux dev bench <file.nx> --engine vm --iters 100
naux dev benchrt <file.nx> --engine jit --iters 100
naux dev refine <file.nx>
naux dev region <file.nx>
naux dev effects <file.nx>
```

Open the terminal IDE:

```bash
cargo run -p naux -- ide naux-lang/examples/hello.nx
```

Inside the IDE:

```text
:show
:check
:run vm
:run interp
:quit
```

## Benchmarks

The benchmark harness compares equivalent workloads across Naux, C, C++, Go,
Rust, and Zig. Generated binaries, raw samples, and machine-local reports are
excluded from Git.

```bash
CPU_CORE=0 N=100000 REPS=50 ITERS=50 WARMUP_MS=100 \
    ./scripts/bench_cross_language.sh
```

Results are written under `target/perf/`. A local observation is not a public
performance claim unless its environment, checksums, samples, toolchains, and
repository identity satisfy the published benchmark contract.

See [benchmark methodology](docs/benchmarks.md).

## Development

Recommended checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Useful focused commands:

```bash
cargo test -p naux vm::ssa -- --nocapture
cargo test -p naux vm::compiler -- --nocapture
cargo run -p naux -- dev ir naux-lang/examples/bench_sum_dense.nx
cargo run -p naux -- dev disasm naux-lang/examples/bench_sum_dense.nx
```

## Repository layout

```text
.
|-- naux-lang/          Compiler, runtime, VM, CLI, tests, and examples
|-- benchmarks/         Cross-language benchmark sources
|-- scripts/            Benchmark, validation, and reporting tools
|-- tools/perf-gates/   Rust performance-gate utilities
|-- naux-meta-coq/      Separate formal-model workspace
|-- vscode/             VS Code language support
|-- docs/               Public language and benchmark documentation
|-- assets/             Public project assets
```

Important implementation paths:

```text
naux-lang/src/lexer.rs       Tokenization
naux-lang/src/parser/        Parsing
naux-lang/src/typecheck.rs   Type checking
naux-lang/src/runtime/       Interpreter and runtime values
naux-lang/src/vm/            Bytecode, SSA, optimizer, and JIT
naux-lang/src/core/          Typed semantic and native-code experiments
naux-lang/src/cli/           CLI and developer tools
naux-lang/tests/             Integration and parity evidence
```

## Public documentation

- [Install, verify, locate, and uninstall NAUX Learn](INSTALL.md)
- [Write the first program and practice algorithms](LEARN.md)
- [Usage and local workflow](USAGE.md)
- [Language behavior](docs/language_spec.md)
- [Memory model](MEMORY_MODEL.md)
- [Backend parity contract](PARITY_CONTRACT.md)
- [Benchmark methodology](docs/benchmarks.md)
- [Performance-claim contract](PERF_CONTRACT.md)
- [Standard algorithm surface](docs/stdlib_algo.md)
- [NAUX Learn exercise corpus](docs/s1_learn_corpus.md)
- [NAUX Learn quick reference v0.1](docs/s1_learn_quick_reference_v0_1.md)
- [NAUX Learn bounded execution envelope](docs/s1_learn_execution_envelope.md)
- [NAUX Learn supported-host bundle](docs/s1_learn_binary_bundle.md)
- [NAUX Learn deterministic release archive](docs/s1_learn_release_archive.md)
- [NAUX Learn Windows release candidate](docs/s1_learn_windows_release.md)
- [Upcoming NAUX Learn 0.1.1 release notes](RELEASE_NOTES.md)
- [Compiler IR specification](naux-lang/docs/IR_SPEC.md)

Internal planning and unpublished research strategy are intentionally not part
of the public repository surface.

## License

Naux is licensed under the MIT License and provided without warranty.
