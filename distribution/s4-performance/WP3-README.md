# S4-WP3 NAUX native corpus carrier

S4-WP3 admits one untimed NAUX execution carrier for the four frozen S4
kernels. The carrier uses the ordinary NAUX lexer, parser, type checker,
bytecode compiler, and typed trace-native runtime. It does not substitute a
host implementation of any kernel.

Static authority admission:

```bash
python3 scripts/s4_native_carrier.py
```

Untimed carrier replay after building the reviewed binary:

```bash
cargo build --release --locked -p naux --example naux_s4_native_carrier
python3 scripts/s4_native_carrier.py \
  --binary target/release/examples/naux_s4_native_carrier
```

The replay is accepted only when every kernel returns its independently
recomputed oracle, executes a native trace on each frozen repetition, and has
zero fallback, deopt, internal side exit, guard failure, and
interpreter-indexed elements.

No clock is sampled by the admitted carrier API. This work package establishes
semantic and native-path eligibility only. See `WP3-NONCLAIMS.md`.
