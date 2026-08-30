# S4-WP8O — Paired threshold candidate

WP8O freezes the decision law before an eligible WP8M bundle exists. Its
default mode validates only sealed repository structure and cannot inspect a
host, read a clock, build, or execute a workload.

```bash
python3 scripts/s4_register_residency_paired_threshold.py
```

An explicit read-only evaluation accepts one complete WP8M bundle:

```bash
python3 scripts/s4_register_residency_paired_threshold.py \
  --bundle /absolute/path/naux-s4-register-residency-paired
```

For each kernel the candidate must retain at least 24 non-tied pairs, have a
strictly negative median of candidate-minus-baseline deltas, pass an exact
one-sided sign tail at `1/100`, and reach a baseline-total/candidate-total
speedup ratio of at least `21/20`. Ties remain disclosed and reduce effective
sign-test coverage. All four kernels must pass every gate; favorable kernels
cannot hide a failure elsewhere.

All arithmetic is integer or reduced rational arithmetic. Even a passing
result remains `claim-status=not-admitted`: WP8O creates a threshold candidate,
not a public performance claim. Synthetic bundles used by tests are not
measurements.
