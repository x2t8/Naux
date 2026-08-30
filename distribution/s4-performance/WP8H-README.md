# S4-WP8H untimed register-residency candidate role

WP8H composes the frozen WP5F baseline role with the exact WP8G process
artifacts. It admits those four artifacts only to the separate
`naux-register-residency-candidate` role.

The existing `naux-residual` baseline remains authoritative and unchanged.
WP8H neither selects the candidate globally nor permits measurement. Its
dynamic gate repeats all four WP8G images in two fresh-process passes and
requires the exact checksum, outer counter, promoted inner counter, and
consumed owner state before emitting an admitted role report.

```bash
cargo build --locked -p naux --example naux_s4_register_residency_process
python3 scripts/s4_register_residency_role.py
python3 scripts/s4_register_residency_role.py \
  --binary target/debug/examples/naux_s4_register_residency_process
```

A later work package must independently define the controlled-host and
measurement boundary. WP8H reads no clock and produces no performance claim.
