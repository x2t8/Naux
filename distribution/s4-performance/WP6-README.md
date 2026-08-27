# S4-WP6 — Controlled-host preflight

WP6 freezes a fail-closed, clock-free preflight for a future Scope 4
measurement host. It binds the WP4 boundary and the WP5F role authority, then
checks the host facts required by ADR-0092 without running a benchmark or
collecting a clock sample.

Static protocol validation:

```bash
python3 scripts/s4_controlled_host.py
```

Ephemeral host observation for an exact commit:

```bash
taskset -c 2 python3 scripts/s4_controlled_host.py \
  --observe --expected-commit "$(git rev-parse HEAD)"
```

Add `--require-eligible` only on a machine intentionally prepared for claim
measurement. That mode exits nonzero unless every host requirement passes.
The observation is emitted to stdout and is not automatically accepted or
stored as project evidence.

WP6 never changes affinity, governor, turbo, repository state, or system
configuration. It only reads them.
