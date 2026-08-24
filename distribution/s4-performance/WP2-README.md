# S4-WP2 reference baselines

S4-WP2 separates semantic parity from measurement. Each kernel under
`benchmarks/s4/c/` is one C17 translation unit compiled into two roles:

- `c-generic` receives strict positive decimal `n` and `reps` at runtime;
- `c-specialized` receives the frozen dataset through compiler definitions and
  accepts no dataset arguments.

Both roles execute the same allocation, initialization, kernel, checksum,
teardown, and canonical-output source body. The checker uses fixed argument
vectors and never evaluates manifest text in a shell.

Static admission:

```bash
python3 scripts/s4_reference_baselines.py
```

Untimed compile and parity replay:

```bash
python3 scripts/s4_reference_baselines.py --cc cc
```

Neither command emits or admits benchmark timings. See `WP2-NONCLAIMS.md`.
