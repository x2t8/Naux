# S4-WP7B — C timing carriers

This complementary WP7B authority derives equal-boundary `c-generic` and
`c-specialized` timing carriers from the exact accepted WP2 sources. It does
not edit, replace, or weaken the WP2 authority.

The transformation is deliberately mechanical. It adds a direct
`CLOCK_MONOTONIC_RAW` syscall before allocation, validates the exact checksum,
performs teardown, reads the same clock again, and only then serializes a
fixed-width result record. Argument parsing and output remain outside runtime.

Static replay is workload-free:

```bash
python3 scripts/s4_c_timing_carriers.py
```

Compiler audit builds all eight role/kernel combinations and inspects emitted
assembly and ELF files without running them:

```bash
python3 scripts/s4_c_timing_carriers.py --cc cc
```

The accepted NAUX carrier remains a separate sibling authority. Together they
provide the three instrumented roles required by WP7A, but no host, runner,
sample, statistic, speedup, or performance claim is admitted here.
