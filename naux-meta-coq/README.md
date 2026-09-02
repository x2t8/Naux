# NAUX Rocq model

This directory contains the separately checked formal model for NAUX semantic
claims. The tracked authority is deliberately small:

- `*.v` — proof source;
- `_CoqProject` — module/build configuration;
- `Makefile` — reproducible local entry point.

Compiled Coq products (`*.vo`, `*.glob`, auxiliary caches, and related files)
are generated locally and must not be committed.

`I64Arithmetic.v` defines the signed 64-bit interval, normalization modulo
`2^64`, wrapping add/subtract/multiply, and the executable signed-overflow
predicate used by the S4 replay. Kernel-checked examples cover both the
addition/subtraction/multiplication wrap boundaries and a non-overflowing
addition; range lemmas show every wrapping result remains a signed i64.

`RegisterResidency.v` proves a bounded compiler theorem: starting from one
ordinary machine state, a selected stack slot may become resident through an
entry load or an initializing first store, be updated by an admitted
instruction trace or a bounded repetition of one admitted loop body, and be
spilled back. A residency certificate records which entry strategy establishes
the physical home. A reflected Boolean checker rejects complete certificates
that clobber or self-source the reserved register, or claim the first-store
strategy without an initializing store. After spilling the home slot and
restoring the saved callee-owned register, every stack and register cell agrees
with the baseline execution. This semantic-equivalence theorem deliberately
does not claim an x86-64, allocator, aliasing, call, trap, arbitrary-CFG,
plan-parser, or whole-language proof.

`DefiniteInitialization.v` models the control-flow must analysis used before a
first-store residency transform is admitted. Its executable checker validates
canonical finite block graphs, reachability closure, and conservative incoming
facts. The soundness theorem covers every finite path from the entry block and
rules out a load or update before the physical home is initialized on that
path.

`ProjectedCFGResidency.v` joins that admitted path property to the bounded
physical-access semantics. Before the first store, the candidate may hide only
the reserved register. The first store establishes the resident invariant;
later accesses preserve it; final spill and callee-saved restoration recover
the complete baseline stack and register state. The theorem consumes the same
CFG paths checked by `DefiniteInitialization.v`. Its boundary is intentionally
the projected `resident_instruction` trace: pass-through Machine IR semantics,
report parsing, and whole-compiler correctness remain separate obligations.

`ScalarMachineIRResidency.v` retains the exact scalar pass-through projection
around those physical accesses: integer constants, stack loads/stores,
stack-constant updates, add/subtract/multiply, and integer comparisons. A
reflected frame checker excludes the selected home slot and physical register
where required. The mixed-trace theorem covers every finite structural CFG
path admitted by the same initialization certificate, including the
pre-initialization phase and final ABI restoration. Scalar results use the
shared signed-i64 wrapping semantics. Heap/list effects, ownership,
overflow-event accounting, and branch selection remain outside this layer
rather than being modeled as no-ops.

`HeapMachineIRResidency.v` extends that trace with the owned-list operations
present in the sealed WP8C programs. It models range initialization, live
handles, static-length validation, checked loads, checked stores, release,
allocation/release counts, and failure through a partial semantics. For every
successful baseline path, the transformed path succeeds with the same heap,
liveness state, counters, scalar observations, and restored ABI state. The
theorem does not model consuming moves or a released source slot as undefined
cells, host allocation or handle exhaustion, overflow-event accounting,
control-flow selection, or native x86-64 execution.

`OwnershipMachineIRResidency.v` adds an exact defined-cell projection around
that heap semantics. Store instructions retain the report's `keep`/`consume`
bit, consuming stores invalidate their virtual-register source, releases
invalidate the owner slot, and every retained operand must be defined before
it is read. The reflected frame checker prevents an erased store from being
smuggled through the plain-instruction constructor. For every successful
admitted CFG path, final stack/register definedness agrees exactly alongside
the heap, scalar, initialization, and ABI observations proved by the lower
layers. It also increments an explicit event counter from the signed-i64
overflow predicate and proves the transformed trace observes the same event at
each arithmetic instruction. Machine types are validated by the closed report
bridge but are not a Rocq state component; host failures, bounded counter
exhaustion, branch selection, and native x86-64 execution remain outside this
theorem.

`ControlFlowMachineIRResidency.v` retains the exact `goto`, `branch`, and
`return` terminators that the earlier structural graph stored only as
successor lists. Branch conditions and return values must be defined virtual
registers outside physical `r12`; boolean observations accept only `0` or `1`
and otherwise fail closed. For every successful admitted block, the kernel
proof shows the baseline and register-resident execution select the same next
block or return the same i64 value while preserving the ownership phase
relation. Its fuel-bounded runners then construct the dynamic path from those
observations and prove every successful baseline execution is matched by a
candidate execution with the same return value, final initialization phase,
and state relation. A final theorem restores the saved physical register and
closes this relation to full state/heap/ownership/overflow equivalence at
return. Fuel exhaustion and malformed/undefined observations fail closed;
unbounded termination is not claimed.

The formal-residency bridge rebuilds the reviewed WP8C emitter, authenticates
its complete 276-line report through the sealed authority, translates the four
physical-access CFGs into untrusted Rocq certificates, and admits them again
with the checked initialization and operand boundaries. For every finite path
through each generated graph, Rocq derives full-state equivalence for the
physical-access and retained scalar projections after spill and ABI
restoration. For every successfully executed bounded heap path, it additionally
derives equality of heap contents, live handles, and allocation/release counts.
The generated certificate preserves every admitted virtual-register operand,
stack slot, length, and i64 constant. Its register encoding
keeps namespaces disjoint: Rocq register `0` denotes physical `r12`, while
virtual `rN` maps to `S N`. The generated ownership graph additionally retains
every `keep`/`consume` bit and proves exact defined/undefined and overflow-event
count agreement for successful paths. The generated control graph retains each
condition/result register and true/false/goto target, and instantiates the
per-block and bounded whole-CFG selection/ABI theorems for all four WP8C
programs. The proof source is ephemeral and is not a new sealed project
artifact; unbounded termination, host/counter failures, and native semantics
remain explicit non-claims.

```bash
make -C naux-meta-coq
rocq check -silent -o -Q naux-meta-coq NauxCore \
  NauxCore.NauxCore NauxCore.Soundness NauxCore.I64Arithmetic \
  NauxCore.RegisterResidency \
  NauxCore.DefiniteInitialization NauxCore.ProjectedCFGResidency \
  NauxCore.ScalarMachineIRResidency NauxCore.HeapMachineIRResidency \
  NauxCore.OwnershipMachineIRResidency \
  NauxCore.ControlFlowMachineIRResidency
make -C naux-meta-coq clean
```

The checked baseline is Rocq 9.1. CI rebuilds every proof, replays the generated
objects in the kernel, and requires the reported axiom set to remain empty.
