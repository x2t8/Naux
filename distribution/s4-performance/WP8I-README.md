# S4-WP8I — Register-residency controlled-host admission

WP8I binds the exact WP8H candidate role to the existing WP6 controlled-host
protocol. The bridge validates the current Apache-2.0 surface, the sealed WP8H
role, and the historical WP6 authority without changing the retained WP5F
baseline.

Static validation performs no host observation or clock access:

```bash
python3 scripts/s4_register_residency_host.py
```

An optional, clock-free host observation reuses the exact WP6 fact,
fingerprint, and refusal schema:

```bash
taskset -c 2 python3 scripts/s4_register_residency_host.py \
  --observe --expected-commit "$(git rev-parse HEAD)"
```

`--require-eligible` is intended only for an intentionally prepared controlled
host. WP8I never changes affinity, governor, turbo state, repository state, or
system configuration, and it never retains the observation automatically.
