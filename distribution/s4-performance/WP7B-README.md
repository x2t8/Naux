# S4-WP7B — NAUX residual timing carrier

WP7B derives a new linker-free timing carrier around each exact WP5E process
target. The target bytes remain unchanged. A generic startup reads
`CLOCK_MONOTONIC_RAW`, calls the target, saves its returned checksum and work
facts, validates the checksum, reads the clock again, computes a checked
positive nanosecond delta, and only then serializes a fixed 56-byte record.

Static authority validation:

```bash
python3 scripts/s4_residual_timing.py
```

Structural replay requires the reviewed emitter binary:

```bash
cargo build -p naux --example naux_s4_residual_timing
python3 scripts/s4_residual_timing.py \
  --binary target/debug/examples/naux_s4_residual_timing
```

Neither command executes a generated timing image. WP7B admits only the NAUX
carrier structure; equal-boundary C carriers, retained host attestation, the
runner, raw samples, and claim evaluation remain open.
