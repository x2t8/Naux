# Scope 4 Performance Alpha authority

This directory contains the sealed pre-measurement law for S4-WP1:

- `CORPUS.tsv` freezes four kernels, one exact dataset, source roles, and
  independently recomputed semantic oracles;
- `PROTOCOL.tsv` freezes generic/specialized roles, timed-region boundaries,
  required cost dimensions, statistics, and thresholds;
- `AUTHORITY.tsv` binds the two component seals and the exact reviewed file
  inventory;
- `NONCLAIMS.md` prevents this authority from being presented as a benchmark
  result.

Validate it without compiling or timing code:

```bash
python3 scripts/s4_benchmark_authority.py
```

The deterministic report must say `claim-status\tnot-admitted`. Existing
timing reports remain observations until a later work package supplies the
complete raw evidence required by this authority.
