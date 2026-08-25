# S4-WP5C residual Machine IR

WP5C lowers every admitted WP5B residual through one target-independent path.
The stack program becomes closed typed slots, single-assignment virtual
registers, basic blocks, explicit branch/goto/return terminators, checked list
operations, and explicit owned-list release.

Every residual instruction has exactly one source-map record. An independent
Python replay reconstructs the Machine IR and correspondence identities,
replays stack-to-register operands, validates CFG reachability and loop
backedges, and checks allocation, traversal list effects, checksum return, and
teardown without collecting a clock.

Validate the static authority:

```bash
python3 scripts/s4_residual_machine_ir.py
```

Replay a reviewed emitter without collecting clocks:

```bash
python3 scripts/s4_residual_machine_ir.py \
  --binary target/release/examples/naux_s4_residual_machine_ir
```

This slice emits no target plan, x86-64 bytes, ELF file, or performance result.
