# S4-WP8J — Register-residency timing carrier

WP8J wraps each exact WP8G register-residency process target with the already
admitted WP7B `CLOCK_MONOTONIC_RAW` timing envelope. The process target remains
byte-for-byte identical. One post-clock literal changes the serialized role
owner from baseline role `1` to isolated candidate role `4`.

Static validation performs no build, clock read, generated-image execution, or
host observation:

```bash
python3 scripts/s4_register_residency_timing.py
```

The reviewed Rust emitter can be built and replayed explicitly:

```bash
cargo build --locked --offline -p naux \
  --example naux_s4_register_residency_timing
python3 scripts/s4_register_residency_timing.py \
  --binary target/debug/examples/naux_s4_register_residency_timing
```

Replay executes only the reviewed Rust byte emitter. It reconstructs all four
timing ELF images independently but never executes those images. Controlled
acquisition remains a later authority and still requires an eligible retained
WP8I host observation.
