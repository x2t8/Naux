# S4-WP5 whole-program residual role

S4-WP5 freezes what must exist before NAUX may occupy the required
`naux-residual` comparison role. This first slice is a contract, not a residual
implementation.

The contract requires one ordinary NAUX source-to-residual-to-ELF pipeline for
all four frozen kernels. It explicitly rejects renaming the WP3 trace carrier,
folding the static workload to its checksum, copying a reference loop, or
adding per-kernel native templates.

Validate the clock-free role contract with:

```bash
python3 scripts/s4_residual_role.py
```

The report must retain all three implementation blockers and say
`claim-status\tnot-admitted`. No clock is collected by this package.
