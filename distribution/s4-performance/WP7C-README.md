# S4-WP7C — Controlled acquisition runner

WP7C is the only Scope 4 path allowed to turn exact WP7B carriers into a WP7A
evidence candidate. Its default mode is static and cannot inspect a host, read
a clock, build a carrier, or execute a workload.

```bash
python3 scripts/s4_measurement_runner.py
```

Acquisition is available only through an explicit command with an exact
eligible retained WP6 report, a matching live re-attestation, a clean attested
commit, resolved toolchains, and a new output path outside the checkout:

```bash
python3 scripts/s4_measurement_runner.py \
  --acquire \
  --host-attestation /absolute/path/WP6-HOST-OBSERVATION.tsv \
  --output /absolute/new/path/naux-s4-evidence
```

The runner builds through fixed argv without a shell, retains every warmup and
all 360 ordered samples, independently replays the WP7A candidate, includes
the twelve exact artifacts, and publishes the complete bundle with an atomic
no-replace rename. The bundle retains readable executable/version digests and
the exact hex-encoded version output behind every role toolchain aggregate;
the aggregate is not an opaque hash. Hosted CI runs only static and synthetic
refusal/replay tests and never supplies `--acquire`.

WP7C structural admission is not a benchmark result. A synthetic test bundle
is not evidence. No raw Scope 4 evidence exists until an eligible controlled
session successfully publishes a complete independently replayed bundle.
