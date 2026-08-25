# S4-WP5A specialization-request authority

S4-WP5A admits the clock-free request that a future whole-program residual
generator must consume. One reviewed executable sends all four frozen NAUX
sources through the ordinary lexer, parser, type checker, and bytecode compiler,
then binds each source and compiled program identity to `n=16384`, `reps=50`,
the corpus oracle, and five work-preservation obligations.

Static authority admission:

```bash
python3 scripts/s4_specialization_request.py
```

Untimed regenerative replay:

```bash
cargo build --release --locked -p naux \
  --example naux_s4_specialization_request
python3 scripts/s4_specialization_request.py \
  --binary target/release/examples/naux_s4_specialization_request
```

This package admits a specialization request only. It does not claim that a
residual generator, residual IR, native artifact, or measured result exists.
See `WP5A-NONCLAIMS.md`.
