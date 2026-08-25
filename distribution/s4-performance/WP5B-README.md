# S4-WP5B structural residual

WP5B introduces one closed residual IR lowering for all four admitted S4
programs. The lowering starts after the ordinary NAUX frontend, specializes the
static dataset, remaps control flow, inserts explicit list teardown, and rejects
every bytecode instruction outside its reviewed subset.

The emitted instruction stream is replayed independently by Python. That
replay checks canonical hashes, stack depth at every control-flow merge, two
nested counted loops, list allocation and initialization, all list accesses,
the `n * reps` traversal obligation, checksum return, and teardown ordering.

Validate the static authority:

```bash
python3 scripts/s4_structural_residual.py
```

Replay a reviewed emitter without collecting clocks:

```bash
python3 scripts/s4_structural_residual.py \
  --binary target/release/examples/naux_s4_structural_residual
```

This slice does not yet lower the residual IR to machine IR or ELF and does not
admit a performance claim.
