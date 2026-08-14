# NAUX Learn bounded execution envelope v0.1

Status: accepted\
Date: 2026-08-13\
Scope: S1-WP5 / normal `naux run`

## 1. Purpose

NAUX Learn must stop ordinary accidental nontermination and excessive
recursion deterministically without defining work in terms of one backend's
instruction set. This contract bounds semantic execution shared by the normal
Surface interpreter and instrumented VM.

## 2. Limits

Normal `naux run` uses these defaults:

| Limit | Default | Hard CLI ceiling |
|---|---:|---:|
| semantic work | 1,000,000 units | 10,000,000 units |
| active user-function depth | 128 calls | 512 calls |

Overrides are explicit and positive:

```text
naux run solution.nx --max-work 100000 --max-call-depth 64
```

Both `--flag value` and `--flag=value` forms are accepted. Zero, malformed,
or over-ceiling values fail before source execution.

## 3. Backend-independent work unit

One semantic work unit is consumed before each of these admitted operations:

1. an executable source statement;
2. entry into one `~ loop`, `~ while`, or `~ each` body iteration;
3. entry into one user-defined function call.

`~ rite`, function declarations, and the `~ unsafe` wrapper are structural and
do not independently consume a unit; executable statements nested inside them
do. Builtin implementation steps and optimized VM instruction counts are not
work units. Consequently an optimizer may change bytecode shape without
changing the learner budget.

A work limit of `N` admits exactly the first `N` checkpoints. Attempting
checkpoint `N + 1` fails at that source position.

## 4. Function-call depth

Depth counts active user-defined function calls. The top-level `~ rite` frame
and builtin calls do not count. A limit of `N` admits depth `N`; the attempted
call that would create depth `N + 1` fails before its frame is created.

## 5. Failure contract

Both limits fail with the existing bounded source diagnostic:

```text
Runtime error: S1 work limit of N semantic checkpoints exceeded.
Runtime error: S1 function-call depth limit of N exceeded.
```

The VM, interpreter, and a requested JIT agree on the diagnostic. JIT/native
execution has no WP5 authority, so a bounded JIT request deterministically uses
the instrumented VM. Normal CLI rendering buffers events until successful
completion; a limit failure therefore emits no partial stdout.

## 6. Exclusions

WP5 does not claim a wall-clock deadline, an operating-system memory cap,
allocation accounting, bytecode-instruction metering, native/JIT metering,
adversarial sandboxing, process isolation, asynchronous interruption, or a
general termination proof. The external five-second deadlines in acceptance
carriers are test-harness guards, not language semantics.

The hard CLI ceilings protect this learner profile from silently disabling its
envelope. They are not security boundaries and do not make NAUX suitable for
untrusted hostile programs.

## 7. Acceptance carrier

`naux-lang/tests/s1_learn_execution_limits.rs` locks:

- success exactly at a work boundary and failure one checkpoint over it;
- bounded termination of an infinite loop;
- suppression of stdout buffered before a later limit failure;
- success exactly at a function-depth boundary and failure before the next
  frame;
- byte-identical VM/interpreter/JIT-fallback diagnostics; and
- rejection of zero and over-ceiling CLI overrides.

The existing 30-case corpus remains the ordinary-program regression boundary.

## 8. Acceptance evidence

Five CLI carriers pass under default and all-feature builds. They cover the
exact and one-over work boundary, fixed-loop accounting, bounded infinite-loop
termination, buffered-output suppression, exact and one-over call depth,
backend diagnostic identity, JIT fallback, and CLI ceiling rejection. The full
all-feature workspace exits successfully with 442 library tests passed, zero
failed, and six intentionally ignored. Strict all-target/all-feature Clippy,
formatting, diff, and the 160-file documentation audit pass with zero broken
local links.
