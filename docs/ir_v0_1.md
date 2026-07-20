# HolyVM IR v0.1 (Legacy Note)

Status: legacy reference.

This document used to describe an early stack-IR snapshot.
Current canonical IR description lives in:

- `naux-lang/docs/IR_SPEC.md`

## Why this file still exists
- Historical context for older commits/design decisions.
- Useful when reading old benchmark notes or past branch discussions.

## Current direction (summary)
- Stack IR still exists for VM/JIT execution path.
- Compiler optimization work now centers on SSA pipeline:
  - CFG with explicit terminators
  - dominator tree
  - dominance frontier
  - phi insertion + rename
  - SSA verifier

If this file conflicts with `naux-lang/docs/IR_SPEC.md`, treat this file as outdated.
