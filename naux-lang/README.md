# naux-lang

`naux-lang` is the main implementation crate for Naux.

It contains:

- lexer, parser, formatter, diagnostics, and type checking;
- interpreter/runtime values and event rendering;
- bytecode compiler and virtual machine;
- CFG, SSA, verifier, and optimization infrastructure;
- typed trace-JIT and x86-64 experiments;
- CLI, terminal IDE, project tools, examples, and integration tests.

Build and test:

```bash
cargo build -p naux
cargo test -p naux
```

Run an example:

```bash
cargo run -p naux -- run naux-lang/examples/hello.nx
```

Inspect compiler output:

```bash
cargo run -p naux -- dev ir naux-lang/examples/bench_sum_dense.nx
cargo run -p naux -- dev disasm naux-lang/examples/bench_sum_dense.nx
```

This crate is experimental research software and is provided without warranty.
