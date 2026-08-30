# S4-WP8L — Candidate evidence replay

WP8L independently replays a complete WP8K raw bundle. It verifies the sealed
manifest and exact inventory, eligible WP8I host report, four WP8J timing
images, portable toolchain receipts, every warmup, and exactly 30 samples for
each of the four kernels.

Default validation does not inspect a bundle, host, clock, toolchain, or
generated image:

```bash
python3 scripts/s4_register_residency_evidence.py
```

Explicit replay is read-only:

```bash
python3 scripts/s4_register_residency_evidence.py \
  --bundle /path/to/new-candidate-session
```

The replay report reduces retained durations with exact integer arithmetic and
binds the result to the bundle, session, host, source commit, artifact, and
toolchain roots. It does not compare against a baseline and cannot admit a
performance claim.
