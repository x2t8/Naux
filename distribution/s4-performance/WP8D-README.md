# S4-WP8D bounded encoding contract

WP8D specifies how the exact WP8C physical-home operations may be encoded
without producing a candidate target. The contract reuses the promoted stack
slot as an ABI-only shadow for the caller's `r12`, so the WP5D frame immediate
and home layout remain unchanged.

The four admitted symbolic templates have fixed seven-byte widths: save `r12`
to the promoted shadow after frame allocation, copy `r12` to a result home,
copy a value home to `r12`, and restore the caller's `r12` before every return.
All unselected operations retain the frozen WP5D lowering. CFG edges and
terminators retain the WP8C shape; relative fixups may only be recomputed from
that shape. The nonreturning error suffix never restores or rejoins the caller.

For each kernel, the contract checks:

```text
candidate target bytes
  = frozen WP5D target bytes
  - selected WP5D access bytes
  + symbolic physical-home bytes
  + ABI save bytes
  + ABI restore bytes per return
```

This gives exact pre-implementation budgets of 972, 1,167, 929, and 1,043
bytes, decreasing the four frozen targets by 21, 21, 21, and 28 bytes. These
are structural width equations, not emitted artifacts or performance results.

Validate the static authority with:

```bash
python3 scripts/s4_register_residency_encoding_contract.py
```
