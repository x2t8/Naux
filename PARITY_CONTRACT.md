# NAUX Parity Contract

Status: normative for the current Surface NAUX and bridge backends

> This document defines observable parity for the current admitted language.
> If an implementation disagrees with this contract, the implementation is
> wrong unless a higher architectural authority explicitly changes the rule.

---

## 1. Purpose

The parity contract exists to prevent "faster but different" implementations.
Optimization is only valid when it preserves the contract exactly.

This document is the blocker for:
- SSA rewrites
- e-graph extraction
- trace JIT specialization
- partial evaluation
- future region/effects work

---

## 2. Source of truth

### 2.1 Contract hierarchy
1. `MEMORY_MODEL.md` for current memory behavior
2. **This parity contract**
3. Surface language specification
4. Reference implementation behavior
5. Backend implementation behavior

### 2.2 Important rule
The interpreter is **not** the final source of truth if it contains a bug.
The interpreter is the reference implementation only insofar as it matches the
public contracts. Any semantic revision must update this file and its mapped
tests together.

### 2.3 Open decisions
The following semantics are intentionally not re-decided here if they are still under active language-design review:
- none at this time

If a future design change is needed, it must be added here explicitly and the affected rule IDs must be updated.

---

## 3. Normative rules

Each rule has:
- `ID`
- `Statement`
- `Expected`
- `Backend impact`
- `Test mapping`

### NUM-001: Division By Zero
**Statement:** Division by zero is a runtime error.

**Expected:** `1 / 0` and `0 / 0` must not produce `inf`, `NaN`, or a backend-specific value.

**Backend impact:** interpreter, VM, JIT, const folding, SSA, and e-graph must preserve this.

**Test mapping:** `parity_numeric_div_zero`

### NUM-002: Modulo By Zero
**Statement:** Modulo by zero is a runtime error.

**Expected:** `1 % 0` and `0 % 0` must fail as runtime errors and must not return a value.

**Backend impact:** interpreter, VM, JIT, constant folding, SSA, and e-graph must preserve this.

**Test mapping:** `parity_numeric_mod_zero`

### NUM-003: Floating NaN Comparison
**Statement:** NaN values do not compare equal to any value, including themselves, unless the language spec explicitly says otherwise.

**Expected:** `NaN == NaN` must not be treated as `true` by default. `NaN != NaN` must reflect the chosen language rule consistently across backends.

**Backend impact:** comparisons, constant folding, SSA, and e-graph rewrites must not invent a different NaN rule.

**Test mapping:** `parity_nan_compare`

### NUM-004: Mixed Numeric Equality
**Statement:** Mixed numeric comparison rules are stable and backend-independent.

**Expected:** If `1 == 1.0` is allowed by the language, every backend must agree; if it is not allowed, every backend must reject it in the same way.

**Backend impact:** interpreter, VM, JIT, and optimizer passes must preserve the exact coercion rule.

**Test mapping:** `parity_numeric_mixed_eq`

### IMP-001: Relative Import Resolution
**Statement:** Relative imports resolve relative to the importing file, not process cwd.

**Expected:** `import "./x.nx"` from `dir/main.nx` loads `dir/x.nx`.

**Backend impact:** interpreter/VM execution paths must use the same module resolver.

**Test mapping:** `parity_relative_import`

### IMP-002: Absolute Import Resolution
**Statement:** Absolute or root-anchored imports resolve according to the same explicit module root in every backend.

**Expected:** The same import string must always resolve to the same module when the project root is unchanged.

**Backend impact:** interpreter, VM, CLI entrypoints, and JIT bootstrap paths must share the resolver.

**Test mapping:** `parity_absolute_import`

### COL-001: List Equality
**Statement:** List equality is structural and order-sensitive.

**Expected:** Lists are equal only if they contain equal elements in the same order.

**Backend impact:** interpreter, VM, JIT, and optimizer must not change structural list equality.

**Test mapping:** `parity_list_eq`

### COL-002: Map Equality
**Statement:** Map equality is structural and key-aware.

**Expected:** Maps compare equal when they contain the same key/value pairs under the same equality rules for keys and values.

**Backend impact:** map hashing, comparison, and optimizer rewrites must preserve this behavior.

**Test mapping:** `parity_map_eq`

### COL-003: Ordering Fallback
**Statement:** Ordering fallback for mixed or non-total comparable values is deterministic and backend-independent.

**Expected:** If the language defines a fallback order, every backend must produce the same order; if the language forbids ordering, every backend must error the same way.

**Backend impact:** sort, compare, ordered collections, and optimizer rewrites must preserve the rule.

**Test mapping:** `parity_order_fallback`

### COL-004: Aliasing Visibility
**Statement:** Mutations through aliases are observable according to the language aliasing model.

**Expected:** If two references alias the same collection/object, a mutation via one reference must be visible via the other reference when the language allows mutation.

**Backend impact:** runtime representation, region inference, and optimizer must not erase observable aliasing.

**Test mapping:** `col_004_mutation_through_alias_is_observable`,
`mem_001_collection_assignment_preserves_backing_identity`

### MEM-001: Safe Collection Access
**Statement:** Collection access is safe by default under `MEMORY_MODEL.md`.

**Expected:** Missing/out-of-range reads return `Null`; invalid list/bytes
writes fail deterministically; a proof may remove a check only for the exact
backing object covered by that proof.

**Backend impact:** interpreter, VM, JIT, alias analysis, bounds-guard reuse,
and deopt reconstruction must preserve this behavior.

**Test mapping:** `mem_002_safe_index_contract_is_null_on_read_and_error_on_write`,
`jit_005_distinct_list_does_not_inherit_another_lists_bounds_guard`

### MEM-002: Valid Unsafe Parity
**Statement:** `unsafe` removes selected guarantees, not semantics for programs
that satisfy every unsafe precondition.

**Expected:** A valid unsafe program produces the same value, events, and
mutations across VM and JIT.

**Backend impact:** unsafe flags must survive lowering; unchecked JIT paths may
not alter valid-program results.

**Test mapping:** `mem_003_unsafe_valid_access_preserves_vm_jit_result`

### CALL-001: Argument Evaluation Order
**Statement:** Function arguments are evaluated in source order unless the language spec explicitly says otherwise.

**Expected:** Side effects inside arguments happen in the defined order.

**Backend impact:** interpreter, VM, JIT, and optimizer must not reorder argument evaluation.

**Test mapping:** `parity_arg_eval_order`

### CALL-002: Closure Capture Behavior
**Statement:** Closures capture variables according to the language's capture model.

**Expected:** Captured values must remain stable under the same semantics across backends.

**Backend impact:** closure conversion, SSA lowering, and JIT specialization must preserve capture behavior.

**Test mapping:** `parity_closure_capture`

### CALL-003: Builtin Failure Propagation
**Statement:** Builtin failures propagate through the same error path as user-code failures unless explicitly distinguished.

**Expected:** Builtin errors must not vanish, reorder, or change shape between backends.

**Backend impact:** runtime, VM, JIT, and effect/error handling paths must preserve builtin failure semantics.

**Test mapping:** `parity_builtin_failure`

### EFF-001: Event Ordering
**Statement:** Runtime events are emitted in source evaluation order.

**Expected:** `!say "a"; !say "b"` always emits `a` then `b`.

**Backend impact:** JIT/optimizer may not reorder effectful operations.

**Test mapping:** `parity_effect_order`

### EFF-002: Unhandled Effects
**Statement:** Unhandled effects are runtime errors with deterministic shape.

**Expected:** The same missing handler situation must fail the same way across backends.

**Backend impact:** effect dispatch, handler lookup, and JIT boundaries must preserve the error shape.

**Test mapping:** `parity_unhandled_effect`

### EFF-003: Handler Resume Order
**Statement:** Resuming an effect handler follows the same documented order across backends.

**Expected:** If a handler resumes multiple times or nests resumptions, the order of observable events must remain stable.

**Backend impact:** handler codegen, CPS transforms, and trace specialization must not alter resume ordering.

**Test mapping:** `parity_resume_order`

### ERR-001: Error Halt Policy
**Statement:** A fatal runtime error halts the current evaluation path immediately unless the language explicitly defines recovery.

**Expected:** A backend may not continue executing code after an uncaught fatal runtime error.

**Backend impact:** interpreter, VM, JIT, and optimizer must agree on where execution stops.

**Test mapping:** `parity_error_halt`

### ERR-002: Error Shape Stability
**Statement:** Equivalent runtime failures must produce equivalent error kinds and formatting.

**Expected:** Message shape, span formatting, and classification must remain stable across backends.

**Backend impact:** error constructors, runtime formatting, and JIT deopt reporting must preserve shape.

**Test mapping:** `parity_error_shape`

### MOD-001: Duplicate Import Behavior
**Statement:** Duplicate imports follow one stable policy.

**Expected:** If duplicate imports are cached, deduplicated, or rejected, every backend must do the same.

**Backend impact:** module resolver, interpreter, VM bootstrap, and future JIT loading must preserve policy.

**Test mapping:** `parity_duplicate_import`

---

## 4. Backend parity requirements

Every backend must preserve the same observable behavior for:
- final value
- error kind/message
- trace event order
- side-effect order
- exit status

### Backends in scope
- interpreter
- VM
- JIT
- SSA optimizer output
- any future residual program produced by partial evaluation

---

## 5. Observable artifacts

Parity is not considered proven unless we can observe it.
Required artifacts:
- golden output snapshots
- error snapshots
- runtime event logs
- trace summaries
- benchmark outputs for stable cases

These artifacts must be reproducible from a command.

---

## 6. Required test matrix

### 6.1 Core matrix
For each sample program:
- interpreter vs VM
- interpreter vs JIT
- VM vs JIT
- optimizer disabled vs optimizer enabled

### 6.2 Program classes
The matrix should include:
- arithmetic-heavy
- branch-heavy
- collection-heavy
- effect-heavy
- function/closure-heavy
- error-heavy
- import/module-heavy

### 6.3 Failure policy
If any backend disagrees with the contract:
- stop optimization work on that path
- file a parity bug
- add regression test before proceeding

---

## 7. Canonical edge cases

These are the edge cases that must be nailed down before aggressive optimization.

### 7.1 Numeric edge cases
- `0 / 0`
- `1 / 0`
- `0 % 0`
- `-0.0` handling if applicable
- float NaN comparison policy
- integer/float equality edge cases

### 7.2 Collection edge cases
- empty list vs empty map
- self-referential structures if supported
- mutation after aliasing
- ordering fallback on mixed types

### 7.3 Runtime edge cases
- nested function capture
- builtin failure propagation
- handler stack ordering
- unhandled effect crash path

---

## 8. Compatibility rule for optimizer work

An optimization may only land if it satisfies:
- contract preserved
- backend parity maintained
- no new observable error shape unless explicitly specified
- no reordered effects unless specified

If proof evidence is missing, the optimizer must keep the guard.

---

## 9. Contract discipline

### Every change must answer
- Does it change an observable behavior?
- If yes, is the parity contract updated?
- Are all backends still in agreement?
- Are golden tests updated?

### If the answer is unknown
Do not ship the optimization.

---

## 10. Practical definition of "wrong"

A backend is wrong if it:
- produces a different final result
- formats an error differently without spec reason
- reorders side effects
- changes truthiness or equality semantics
- changes import resolution
- changes function closure behavior
- changes effect handler ordering

---

## 11. Merge gate

Before any optimizer/JIT/e-graph work is merged:
- parity contract must be written
- at least one representative parity test must exist
- failures must be reproducible
- the reference implementation and backend must agree

---

## 12. Summary

The parity contract is the wall between "fast" and "fast but broken".
It is the precondition for SSA work, e-graph rewrites, JIT specialization, and future partial evaluation.
