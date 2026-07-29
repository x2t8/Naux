# NAUX Memory Model

Status: normative for current Surface NAUX 0.2 bridge semantics
Scope: interpreter, bytecode VM, typed trace JIT, and optimizer-visible behavior

This document defines which memory behaviors a Naux program may observe. It is
the source of truth for aliasing, collection mutation, safe access, and the
`unsafe` boundary. Internal representations may change only if they preserve
this contract.

## 1. Contract hierarchy

For memory behavior, the order of authority is:

1. this memory model;
2. `PARITY_CONTRACT.md`;
3. the Surface language specification;
4. the reference interpreter;
5. VM/JIT implementation details.

If an implementation disagrees with this document, the implementation is
wrong for programs that satisfy the documented safety preconditions. The
implementation cannot silently weaken this contract.

## 2. Value categories

### MEM-001: Scalar value semantics

`SmallInt`, `Float`, `Bool`, and `Null` have value semantics. Assigning one of
these values copies the value. A later assignment to one variable does not
change another variable.

Text values are immutable at the language level. An implementation may share
their backing storage because no program can observe in-place text mutation.

### MEM-002: Object identity

Mutable collections and runtime objects have identity. This includes:

- bytes;
- lists;
- maps;
- graphs;
- sets;
- priority queues;
- function closures and their captured environment.

Assigning such a value to another variable preserves the same backing identity;
it does not deep-copy the object.

```naux
$a = [1]
$b = $a
$__ = __setindex($b, 0, 9)
$out = __index($a, 0)
```

Cloning performed inside the runtime is not a language-level copy operation
unless an explicit future API says so.

### MEM-003: Observable mutation

Mutation through any alias is visible through every live alias to the same
object. An optimizer must not replace a shared object with independent copies,
cache a mutable element across an unproven mutation, or reuse a bounds/shape
proof from a distinct backing object.

List and bytes mutation updates an existing index. Map mutation inserts or
replaces the value for the specified text key. Mutation returns the same
logical collection identity.

Structural equality remains separate from identity: two distinct collections
may compare equal when their contents compare equal.

## 3. Safe access

### MEM-004: Safe-by-default boundary

Code is safe by default. Outside `~ unsafe ... ~ end`, a backend must retain
the checks required by this section unless it has proof that the checks cannot
fail.

For list and bytes reads:

- an in-range non-negative integer index returns the element;
- a missing or out-of-range index returns `Null`;
- an operand of the wrong kind is a runtime error.

For map reads:

- an existing text key returns its value;
- a missing text key returns `Null`;
- a non-text key or non-map target is a runtime error.

For list and bytes writes:

- an in-range non-negative integer index updates the element;
- a negative index is a runtime error;
- an out-of-range index is a runtime error;
- an invalid bytes value is a runtime error.

For map writes, a text key inserts or replaces the associated value. Invalid
target/key combinations are runtime errors.

Safe code must not produce memory corruption, use-after-free, or unchecked raw
pointer access. A failed speculative JIT guard must resume or deopt to a
semantically equivalent safe path.

### MEM-005: Proof-backed check removal

A compiler may remove a safe check only when its proof is valid for the exact
object identity and program point being optimized. At minimum:

- a list bounds proof is tied to the exact backing list;
- a shape/version proof is invalidated by relevant mutation;
- alias analysis must conservatively keep checks when identity is unknown;
- deoptimization must reconstruct the state expected by the target bytecode.

Profile observations are not proofs by themselves. They may select a guarded
specialization, but they may not justify unguarded safe behavior.

## 4. Explicit `unsafe`

### MEM-006: Syntax and scope

The explicit boundary is:

```naux
~ unsafe
    $value = __index($items, $proven_index)
~ end
```

Unsafe state is lexical and nested unsafe blocks remain unsafe. The compiler
records unsafe context per bytecode instruction so the boundary survives
lowering and NXB encoding.

### MEM-007: Programmer obligations

Inside an unsafe block, the programmer is responsible for all of the following:

- every list/bytes index used by an unchecked path is in range;
- index values have the required numeric/integer form;
- the target has the expected runtime kind and element representation;
- object lifetime covers the entire unchecked operation;
- aliases do not perform an unaccounted mutation that invalidates a cached
  pointer, length, capacity, shape, or slot;
- syscall arguments and platform contracts are valid.

The typed JIT may use raw pointer arithmetic and omit bounds checks when the
unsafe flag is present. Violating an unsafe precondition is outside the
language guarantees: execution may trap, fail, return an unspecified value, or
cause memory unsafety. Unsafe is never a license for an optimizer to change the
result of a program that satisfies all preconditions.

`!syscall` is only syntactically legal inside an unsafe block. This restriction
does not make a syscall intrinsically safe.

### MEM-008: Valid unsafe parity

For an unsafe program that satisfies every precondition, interpreter, VM, and
JIT must preserve the same observable value, events, and mutations. Backends
may differ only for programs that violate an unsafe obligation.

## 5. Lifetime and reclamation

### MEM-009: Current reclamation model

The current general runtime uses shared reference-counted objects. Storage is
reclaimed when its last strong reference is released, except for reference
cycles. The current runtime has no tracing cycle collector; a reachable cycle
can therefore remain allocated.

This is an implementation limitation, not permission for a program to observe
an object after its lifetime ends. Naux does not yet claim a general zero-GC
region runtime.

Experimental ownership and region analyses do not change Surface bridge
reclamation unless their result is materialized by an execution backend.

The JIT may use internal arenas, handles, or temporary-allocation elision for
hot paths. Those mechanisms are not exposed as language addresses and must
preserve MEM-002 through MEM-005. An escaping object must be materialized
before it becomes observable outside the optimized region.

### MEM-010: No stable address contract

Naux source code has no stable-address guarantee for managed values. Moving,
compacting, stack-promoting, region-allocating, or scalar-replacing an object
is allowed only when object identity and all observable aliasing remain
equivalent.

Raw addresses used by the JIT or FFI are implementation details. They may not
be persisted by safe code.

## 6. Concurrency

### MEM-011: Current single-threaded semantics

The current language/runtime executes a program on one thread. Managed objects
are not promised to be thread-safe or shareable across concurrent runtime
instances. Therefore the current safe language has no data-race semantics to
define.

A future concurrency model must specify ownership, synchronization, atomicity,
and cross-thread aliasing before managed values can be shared. It must not
silently inherit host-language behavior.

## 7. Optimizer and backend obligations

Every backend and optimization pass must:

- preserve scalar value semantics and object identity;
- keep mutation visible through aliases;
- retain safe checks or attach proof-valid guards;
- distinguish expected control-flow side exits from speculative deopts;
- keep lifetime totals and deopt evidence observable;
- materialize escaping optimized allocations;
- treat unknown aliasing conservatively;
- preserve valid-unsafe parity.

No LLVM or external runtime contract is assumed by this model.

## 8. Regression evidence

The normative test mappings are:

| Rule | Test evidence |
|---|---|
| MEM-001 / MEM-002 / MEM-003 | `mem_001_collection_assignment_preserves_backing_identity`, `col_004_mutation_through_alias_is_observable` |
| MEM-004 | `mem_002_safe_index_contract_is_null_on_read_and_error_on_write` |
| MEM-005 | `jit_005_distinct_list_does_not_inherit_another_lists_bounds_guard`, exact-alias guard unit tests, deterministic alias/mutation fuzz |
| MEM-006 / MEM-007 | parser syscall-boundary tests and typed unsafe-plan unit tests |
| MEM-008 | `mem_003_unsafe_valid_access_preserves_vm_jit_result` |
| Region escape experiment | `region_escape_tests`, region parent-chain and promotion unit tests |
| JIT mutation/deopt safety | `jit_002`, `jit_003`, `jit_006`, `jit_alias_fuzz` |

Changes to any rule require an explicit update to this document and a parity
regression before optimizer work continues.
