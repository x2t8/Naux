# S4-WP7A — Measurement evidence law

WP7A freezes the evidence shape and exact arithmetic for future Scope 4
measurement. It does not build an instrumented carrier, retain a host
attestation, execute a timed workload, or admit a performance claim.

Static validation is clock-free:

```bash
python3 scripts/s4_measurement_evidence.py
```

The future evidence candidate must contain three exact role identities, three
separate cost records, twelve per-role/per-kernel warmup records, 360 raw
runtime samples in collection order, and twelve derived statistic records.
The independent replay recomputes median, nearest-rank p95, and squared
coefficient of variation using exact integer and rational arithmetic.

Even a structurally valid candidate remains `claim-status=not-admitted` at
this layer. Instrumented-carrier authority, a retained controlled-host
attestation, measurement-runner authority, raw evidence, and the later
threshold decision are separate gates.
