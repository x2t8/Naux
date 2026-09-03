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
and state relation. An inductive terminating-execution semantics removes the
arbitrary fuel number from the main partial-correctness statement: every
terminating baseline derivation has a matching transformed derivation. A final
theorem restores the saved physical register and closes this relation to full
state/heap/ownership/overflow equivalence at return. Fuel exhaustion and
malformed/undefined observations fail closed; total termination is not claimed.

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
per-block, bounded whole-CFG, and fuel-independent terminating-execution ABI
theorems for all four WP8C programs. The proof source is ephemeral and is not a
new sealed project artifact; total termination, host/counter failures, and
native semantics remain explicit non-claims.

`X86ResidencyEncoding.v` closes the next structural boundary without claiming
a full x86 proof. It defines a seven-byte decoder for `mov [rbp+disp32], r12`
and `mov r12, [rbp+disp32]`, extracts every physical residency site directly
from the proved ownership control graph, and checks exact offsets into the
complete WP8E candidate function bytes. The generated certificate must cover
every WP8C residency site exactly once, decode each load/store in the required
direction, save caller `r12` to the WP8D shadow displacement, and restore it at
every return. Passthrough instructions, relative fixups, general x86 semantics,
ELF loading, and native execution remain outside this theorem.

`ELF64ResidencyEnvelope.v` closes the quarantined WP8F packaging boundary at
the byte level. It independently constructs the fixed little-endian ELF64
header, `R-X` load segment, non-executable `R-W` GNU stack declaration,
padding, and startup call, with the image-size fields derived from the target
extent. The model rejects images of 64 KiB or more; this makes the two live
little-endian extent bytes explicit and keeps kernel reduction bounded while
covering every admitted WP8F artifact. The generator admits every WP8F-owned
prefix byte and reuses the corresponding complete, proved WP8E target as the
payload instead of duplicating it. Each generated theorem equates that complete
image with the canonical envelope, then derives that dropping the first 272
bytes recovers the target exactly. Linux loader,
system-call, x86 execution, timing, and native-correctness claims remain out of
scope.

The CI bridge emits one WP8F module per kernel. Each module is compiled and
replayed in a fresh Rocq process so proof memory remains bounded without
weakening or omitting any kernel certificate.

`ResidencyProcessTarget.v` establishes the WP8G boundary at the exact byte
rewrite that makes the candidate executable under the fresh-process parity
protocol. It decodes the displaced WP8E restore/return range, checks the
same-width jump and its destination, decodes all fields in the appended
80-byte completion verifier, and checks that its three failure branches target
the admitted error exit. Generic theorems retain the candidate extent, recover
the appended verifier exactly, and preserve byte bounds. Native instruction
semantics and Linux execution remain outside this structural layer.

`ELF64ResidencyProcessEnvelope.v` closes the remaining WP8G packaging gap.
It constructs the sectionless executable header, exact 117-byte result-record
startup, sixteen-byte-aligned target placement at offset 384, and the complete
process payload. The artifact ordinal is checked as a non-zero bounded value
and encoded into the startup record. Generic theorems derive the full image
extent and recover the process target exactly after the prefix. As at WP8F,
Linux loading, syscall semantics, native execution, timing, and performance
remain outside the byte-structure theorem.

`ResidencyResultProtocol.v` models the fixed 48-byte WP8G success record. It
checks the `NAUX5E01` magic, exact extent, and byte bounds before decoding the
artifact ordinal, signed checksum, terminal loop counters, and allocation
owner as little-endian 64-bit fields. Generated certificates instantiate the
exact expected record for every admitted kernel and ask Rocq to decode it.
This closes the serialization schema; the Linux `write` syscall and the claim
that native execution produced those bytes remain governed by the separate
fresh-process replay gate rather than the formal model.

`ResidencyCandidateRole.v` closes the WP8H role boundary around those checked
objects. An admitted assignment must use the isolated register-residency
candidate role, keep timing authority forbidden, retain the authoritative
baseline role, carry a non-zero ordinal whose value agrees with the decoded
result, and contain the exact proved WP8G process at the canonical ELF target
offset. The model proves that such an assignment cannot be the baseline role
and derives result-record well-formedness. It deliberately grants neither
measurement authority nor a performance claim.

`ResidencyControlledHost.v` closes the static WP8I boundary. It distinguishes
an unobserved host from an eligible observation carrying a bounded 32-byte
fingerprint, and separates protocol linkage from measurement readiness. The
checked static binding reuses the WP8H candidate, records that no host was
observed, keeps timing forbidden, and carries no performance-claim authority.
The model proves that this state is neither host-eligible nor measurement
ready; a future positive observation must cross a separate evidence gate.

`scripts/s4_residency_process_coq_certificate.py` is the untrusted bridge for
the sealed WP8G candidate, WP8H role report, and WP8I static host report. It
authenticates the WP8C through WP8I parents, requires each process candidate
to equal its admitted WP8E target,
and emits only the 16-byte patch, 80-byte verifier, exact 384-byte ELF prefix,
fixed 48-byte expected result, and closed receipt. The bridge independently
reconstructs the prefix and result serialization before emission. It also
requires the authenticated two-pass fresh-process replay report, derived WP8H
role report, and exact clock-free WP8I static report. It refuses to emit if any
observed kernel identity, result field, role, timing boundary,
baseline-retention fact, host status, or report root differs from the sealed
contracts. CI generates one module per kernel, compiles each with Rocq 9.1,
and asks the kernel to replay every process, full-image, result-schema, role,
and static-host-boundary theorem with an empty axiom set.

```bash
make -C naux-meta-coq
rocq check -silent -o -Q naux-meta-coq NauxCore \
  NauxCore.NauxCore NauxCore.Soundness NauxCore.I64Arithmetic \
  NauxCore.RegisterResidency \
  NauxCore.DefiniteInitialization NauxCore.ProjectedCFGResidency \
  NauxCore.ScalarMachineIRResidency NauxCore.HeapMachineIRResidency \
  NauxCore.OwnershipMachineIRResidency \
  NauxCore.ControlFlowMachineIRResidency \
  NauxCore.X86ResidencyEncoding \
  NauxCore.ELF64ResidencyEnvelope NauxCore.ResidencyProcessTarget \
  NauxCore.ELF64ResidencyProcessEnvelope \
  NauxCore.ResidencyResultProtocol NauxCore.ResidencyCandidateRole \
  NauxCore.ResidencyControlledHost
make -C naux-meta-coq clean
```

The checked baseline is Rocq 9.1. CI rebuilds every proof, replays the generated
objects in the kernel, and requires the reported axiom set to remain empty.
