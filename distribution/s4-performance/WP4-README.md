# S4-WP4 controlled measurement boundary

S4-WP4 freezes the boundary that a future Scope 4 measurement runner must
cross. It composes the accepted benchmark, C reference, and NAUX native-carrier
authorities, but it does not collect a clock sample.

The currently available NAUX role is named
`naux-trace-carrier-observation`. It is not silently promoted to the frozen
`naux-residual` comparison role. Claim admission remains blocked until that
whole-program residual role, a controlled host, and the measurement runner all
exist and pass the boundary.

Validate the static boundary with:

```bash
python3 scripts/s4_measurement_boundary.py
```

The deterministic report must retain all three blockers and say
`claim-status\tnot-admitted`. See `WP4-NONCLAIMS.md`.
