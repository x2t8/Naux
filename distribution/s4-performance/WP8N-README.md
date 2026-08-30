# S4-WP8N — Paired evidence replay

WP8N independently replays a complete WP8M bundle without executing any ELF,
reading a clock, observing the host, or changing the bundle. It verifies the
eligible retained host report, exact manifest and session roots, all eight
carrier images, shared toolchain identity, AB/BA order, frozen checksums, and
all 240 sample invocations.

Static validation is isolated from external evidence:

```bash
python3 scripts/s4_register_residency_paired_evidence.py
```

Read-only replay is explicit:

```bash
python3 scripts/s4_register_residency_paired_evidence.py \
  --bundle /path/to/wp8m-paired-bundle
```

For each kernel, the replay derives exact totals, role medians, paired-delta
median, candidate wins/ties/losses, and the reduced baseline-total to
candidate-total ratio. These are evidence facts only; WP8N does not admit a
performance claim.
