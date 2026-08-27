# S4-WP7D — Bundle and threshold evaluator

WP7D independently replays a complete WP7C bundle and evaluates the frozen
Scope 4 thresholds with exact integer/rational arithmetic. Its default mode is
static and cannot inspect a host, read a clock, build, or execute a workload.

```bash
python3 scripts/s4_threshold_evaluator.py
```

An explicit read-only evaluation accepts one already published bundle:

```bash
python3 scripts/s4_threshold_evaluator.py --bundle /absolute/path/naux-s4-evidence
```

The evaluator requires exact manifest inventory, host report, WP7A evidence,
session-to-evidence correspondence, twelve artifact aggregates, four readable
toolchain receipts, and all twelve variance gates. It then applies both frozen
thresholds to each kernel. A positive threshold candidate requires at least
one same kernel to pass both gates; two unrelated favorable kernels cannot be
combined.

Even a passing evaluation reports `claim-status=not-admitted`. WP7D produces a
candidate for later tracked/public claim authority, never a self-authorized
performance claim. Synthetic test bundles are not measurements.
