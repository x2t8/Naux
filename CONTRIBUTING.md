# Contributing to NAUX

NAUX is an experimental language, compiler, runtime, and native-code research
system. Its development is evidence-gated: an implementation and the claims
made about it have separate acceptance requirements.

Contributions are welcome when they create demonstrated value and preserve
NAUX's architectural and evidence requirements. This guide makes those
requirements explicit so contributors can identify useful work before investing
in an implementation. It is an entry point, acceptance model, and routing
document; it does not replace the governing contracts.

Participation also follows the [Code of Conduct](CODE_OF_CONDUCT.md). Technical
acceptance and respectful conduct are separate requirements: rigorous review
does not justify personal attacks, and respectful participation does not by
itself establish a reason to merge.

## Philosophy

**Every accepted change must justify its existence.**

A working implementation, passing tests, an interesting technique, or a new
feature is not sufficient on its own. Review follows a concrete chain:

```text
existing problem or capability gap
  → precise change introduced by the commit
  → evidence demonstrating that change
  → value sufficient to justify its architectural and maintenance cost
```

These are four distinct acceptance questions:

| Dimension | Question |
|---|---|
| Code correctness | Does the implementation behave correctly within its declared boundary? |
| Architectural correctness | Does it preserve the affected contracts, ownership, and trust boundaries? |
| Evidence sufficiency | Can a reviewer check the stated result using evidence appropriate to the risk and claim? |
| Contribution value | Does it solve a real problem or create a needed capability worth maintaining? |

All four matter. Correct code can still lack sufficient value. A useful feature
can still violate a contract. A favorable benchmark can still lack authority
for a performance claim. Contributor effort is not a reason to merge: time
already spent cannot substitute for correctness, value, architectural fit, or
appropriate evidence.

## Architecture and Reading Route

Start with [README.md](README.md) for the public surface and
[PROJECT_MAP.md](PROJECT_MAP.md) as the primary architecture and subsystem map.
Do not treat every implementation in the repository as one interchangeable
compiler path.

| Area | Boundary to understand |
|---|---|
| Current Rust bridge | The user-facing CLI, AST interpreter, bytecode VM, VM optimizer, and typed trace JIT. Its declared VM fallback and deoptimization behavior belongs to this path. |
| Canonical checked/native path | Bounded Surface elaboration into Typed Core, binding-time analysis and specialization, Residual Core, source-bound Core SSA and Machine IR, checked x86-64 encoding, and separately admitted native/ELF/process execution. |
| Evidence system | Parity, mutation, replay, artifact identity, benchmark protocols, release provenance, and claim admission. A producer's output is not automatically an accepted result. |
| Formal model | The separate [Rocq/Coq model](naux-meta-coq/README.md), with explicitly scoped theorems and certificate bridges. It is supporting evidence, not the ordinary Rust build or execution path. |

In particular, bridge `vm::ssa` is not canonical Core SSA, and a successful
trace-JIT run does not establish canonical native-path evidence. Rust/Cargo and
`egg` remain disclosed seed/bridge dependencies, not proof of completed
toolchain sovereignty.

Read the applicable documents before proposing a change:

- [PARITY_CONTRACT.md](PARITY_CONTRACT.md): observable behavior and cross-engine
  equivalence.
- [MEMORY_MODEL.md](MEMORY_MODEL.md): values, aliasing, identity, mutation,
  lifetime, and optimization freedom.
- [PERF_CONTRACT.md](PERF_CONTRACT.md): measurement and performance-claim gates.
- [COMPATIBILITY.md](COMPATIBILITY.md): versioned profiles and release promises.
- [RELEASE_PROVENANCE.md](RELEASE_PROVENANCE.md): release identity and replay.
- [SECURITY.md](SECURITY.md): private security reporting. Do not put vulnerability
  details in a public issue or PR.
- [SUPPORT.md](SUPPORT.md): support boundaries and bug-report requirements.

Follow the authority order in `PROJECT_MAP.md`, including relevant accepted
ADRs and the active roadmap/scope boundary. Some planning and ADR materials
referenced there are internal and absent from public checkouts. For affected
work, ask maintainers to provide the relevant approved decision and acceptance
boundary in the design discussion before implementation. Contributors are not
expected to infer inaccessible requirements. Check acceptance and supersession
status: a proposal or superseded snapshot does not override current authority.

## Before Opening an Issue

Issues are for substantiated problems and capability gaps, not an idea box.
Before opening one:

1. Search the repository, including implementations, tests, documentation, and
   evidence scripts; searching only the README is insufficient.
2. Search existing open and closed issues and PRs, including prior rejections.
3. Read `PROJECT_MAP.md` and the contract governing the affected subsystem.
4. Locate the closest existing mechanism and determine what it already handles.
5. Identify the remaining gap, why the current implementation does not resolve
   it, and why the proposed work belongs in the current architecture.

Include the relevant paths, symbols, tests, or prior discussions. If a boundary
is unclear, state what you inspected and what remains uncertain instead of
asserting that a capability does not exist.

## Issue Requirements

For a capability or design proposal, establish:

- the concrete problem, workload, or user-visible limitation;
- what existing mechanisms support, and the exact condition they cannot handle;
- why another subsystem does not already solve it;
- the intended capability delta and how it would be demonstrated;
- architectural fit, affected contracts, alternatives, and explicit exclusions.

“Add feature X” is insufficient. A useful starting point is:

> Existing mechanism A handles B and C, but does not support D under condition E
> because F.

Support that statement with repository references and a reproducer or bounded
example, not just an assertion. An issue establishes a problem and acceptance
target; the eventual PR must demonstrate the actual delta.

For a bug, use the existing bug-report form and [support policy](SUPPORT.md).
A reproducible contradiction of the declared behavior is useful evidence; the
reporter does not need to supply a patch, design a replacement subsystem, or
prove the whole compiler incorrect. Small typo or broken-link fixes can go
directly to a focused PR without a separate design issue.

## Evidence Expectations

Evidence must support the specific claim, not merely show that a command exited
successfully. Depending on the change, it may include regression or parity
tests, before/after behavior, independent replay, mutation tests, deterministic
artifacts, verifier results, benchmarks, profiler data, reproducible
measurements, or formal proofs. These are options with different purposes,
not a checklist every contribution must complete.

Classify risk by impact, not filename or patch size:

| Risk | Typical contributions | Expected starting evidence |
|---|---|---|
| Low | Non-normative docs, examples, grammar/editor support, packaging presentation, typos, small tooling | Source accuracy, relevant rendering/link/package checks, and focused example or tool tests where behavior changes. |
| Medium | Lexer, parser, diagnostics, standard library, CLI, runtime changes within existing contracts | Focused positive and negative regression tests, before/after behavior, and parity checks for affected execution paths. |
| High | Semantic rules, VM optimizer, SSA, e-graph, typed JIT, specialization, deopt, Typed Core, Machine IR, x86/native backend, formal model, evidence infrastructure, claim admission | A reviewed design boundary and the subsystem's required parity, verifier, replay, mutation, identity, resource-limit, and proof/model checks as applicable. |

These examples are not exemptions. Packaging that changes installer ownership
or release trust, a parser change that changes semantics, or documentation that
changes a normative contract is not low-risk. Escalate to the highest affected
boundary. High-risk changes can require several review rounds.

Not every contribution requires a formal proof. State what each item of
evidence establishes and what it does not. For a regression fix, show that the
test exposes the prior defect and passes with the correction. Record commands,
revision, results, relevant configuration, and any skipped or unavailable
checks; unavailable evidence is not a pass. Label synthetic fixtures as such:
they can test a measurement checker but are not measured performance.

## Design Before Implementation

Open a design issue and agree on the boundary before substantial implementation
of a major change. This applies to semantics, optimizer or JIT design, the
memory model, the native backend, proof/evidence systems, and new performance
claims. Small contract-preserving fixes can use the issue or PR to explain
their existing boundary without a separate architectural proposal.

The design should identify the demonstrated gap, affected subsystem and
invariants, simpler alternatives, dependency and maintenance costs, admitted
and unsupported cases, resource budgets, validation plan, and migration needs.
Work outside the current scope needs an explicit scope decision, not incidental
introduction through a PR.

The purpose is to avoid hundreds of implementation lines for a design the
project cannot accept. Agreement to investigate a design is not a promise to
merge its implementation. Where an architectural decision changes, use a new
explicitly superseding ADR; do not silently rewrite accepted history.

## Pull Requests

Keep one coherent change per PR, identify the affected subsystem and risk,
and avoid unrelated refactoring. Link the substantiated issue or, for a small
fix, put its problem statement directly in the PR.

Every PR description must answer:

1. **What is wrong or missing now?** Identify the existing mechanism and gap.
2. **What exactly changes?** Explain the delta introduced by these commits.
3. **What becomes possible afterward?** State the concrete benefit; removing a
   defect or unnecessary complexity also counts.
4. **What evidence demonstrates that?** Give reproducible checks and results,
   not only “tests pass.”
5. **Which contracts or invariants are affected?** Include callers, downstream
   consumers, compatibility, and evidence identities where relevant.
6. **What was deliberately not changed?** State exclusions and remaining limits.

Include corresponding tests and documentation where behavior or a public
boundary changes. For a typo, an exact correction and link/rendering check can
answer these questions briefly; no research report is required.

Preserve the repository's [Apache-2.0 license](LICENSE) and applicable notices.
Keep build caches, compiled proof products, private planning files, and
unreviewed local benchmark output out of the PR. Publish benchmark and release
evidence through the applicable reviewed protocol.

## Semantic Changes

Read [PARITY_CONTRACT.md](PARITY_CONTRACT.md) and
[MEMORY_MODEL.md](MEMORY_MODEL.md) first. **Faster but different is wrong.**

A semantic change may affect the interpreter, VM, JIT, SSA, e-graph, constant
folding, memory behavior, native backend, and formal model. Identify all
applicable paths and update their contracts and evidence together. Compare the
declared observations, including values, errors, effect/output order, aliasing,
and exit behavior—not only one final number.

Silent backend divergence is unacceptable. Unsupported optimized/native
behavior must reject, residualize, or take an explicitly declared generic
fallback according to that boundary. A canonical native profile that forbids
fallback cannot borrow the bridge VM's fallback as evidence of success.
Unproven optimization assumptions must retain the required guards or refusal.

Neither current interpreter behavior nor agreement among backends overrides a
normative contract; they can share a bug. Explicit semantic revisions require
reviewed contract and compatibility changes, not silently changing the expected
test output. Preserve logical identity, alias-visible mutation, and effects
without equating logical regions with a particular physical allocator.

## Performance Changes

Read [PERF_CONTRACT.md](PERF_CONTRACT.md) before proposing or measuring a
performance change. “This is faster” is not an acceptable result description.
Provide:

- the exact workload, dataset, oracle, and timed region;
- the baseline and candidate roles, source commits, build flags, and artifact
  identities;
- the environment, including hardware, OS, toolchain, and required host controls;
- the measurement method, warmup policy, sample count/order, raw samples,
  statistics, variance, and applicable predeclared thresholds;
- correctness/parity results and native/fallback/deopt status where applicable;
- the precise claim scope and the protocol used to admit it.

Use the existing protocol for that experiment; do not mix bridge comparisons,
canonical native carriers, and S4 paired observations as interchangeable data.
[PROJECT_MAP.md](PROJECT_MAP.md) routes to the current carriers and replay
tools; the [S4 authority](distribution/s4-performance/README.md) separates
measurement law from results. Account for compile/specialization time, startup,
runtime, memory, and code size as required by the applicable contract.

Preserve failed and high-variance results. Do not remove inconvenient samples,
retry a frozen experiment into success, change baselines, or relax thresholds
to manufacture a win. A structural reduction in stack accesses or emitted
bytes is not by itself a measured runtime speedup. A win on one workload does
not authorize a language-wide comparison or a claim about unmeasured hosts.

A correctness or infrastructure improvement may be accepted without a
performance claim. A passing threshold candidate still needs the applicable
provenance, replay, claim-scope, and distinct approval gates.

## High-Risk Compiler Changes

Preserve the canonical backend pattern described in `PROJECT_MAP.md`:

```text
typed/source-bound input
  → bounded deterministic lowering
  → canonical encoding and identity
  → structural verification
  → independent replay/evaluation
  → fail-closed admission
```

Explain each changed input boundary and downstream consumer. Carry types,
effects, source identities, canonical order, and hard limits through the
affected stages. Demonstrate malformed, unsupported, over-budget, and forged
input rejection as required by the subsystem. Positive execution alone does
not establish verifier soundness or source correspondence.

### Proof and Evidence Boundaries

Do not weaken a verifier, bypass independent replay, remove refusal cases, or
lower an evidence standard to get a PR accepted. If the evidence is insufficient,
narrow the claim—not the evidence standard.

A matching hash establishes identity, not semantic correctness. Recomputing a
seal over changed content does not preserve an accepted authority. Mutations
that remain internally consistent after resealing must still be checked against
the original source or predecessor boundary where the protocol requires it.
Historical artifacts and measurements remain historical; use reviewed,
versioned transitions rather than silently replacing their identities. The
[license-transition record](distribution/license-transition/README.md) is an
example of preserving exact historical evidence across a legitimate change.

For formal work, name the model, theorem, assumptions, admitted domain, and
implementation/certificate bridge. Use the [formal model's validation
instructions](naux-meta-coq/README.md), including its kernel and axiom checks.
Formal evidence supports claims within declared boundaries; a finite corpus,
bounded theorem, or checked certificate does not make the whole NAUX compiler
“formally verified.” Do not present Python-only checks or skipped kernel tests
as proof-assistant verification.

Release changes must follow [RELEASE_PROVENANCE.md](RELEASE_PROVENANCE.md).
This guide does not create an alternative release or evidence policy.

## Architectural Cost

**Complexity is acceptable when necessary; unjustified complexity is not.**

Every feature creates maintenance, testing, documentation, compatibility, and
review cost. Feature count, code volume, contributor count, and benchmark wins
are not project goals. Coherence, correctness, reproducibility, explainability,
and evidence-backed evolution are.

### Duplicate or Already-Existing Functionality

Prefer extending an appropriate existing mechanism over building a parallel
subsystem. Explain why reuse or a smaller change is insufficient. However,
independent verifiers and replay implementations can be deliberate architectural
separation: similar code is not automatically duplication to remove. Sharing
producer logic with its checker can destroy the independence being tested.

## Review Process

Maintainers examine the problem, design, implementation, evidence, and value;
core changes commonly need multiple rounds. Review may request more evidence,
narrower scope, additional tests, replay, benchmark corrections, design
revision, contract updates, proof/model updates, or architectural justification.

Respond with the changed reasoning and evidence, and identify which commits
address each concern. Recheck affected downstream consumers after revisions.
An initial design discussion, green CI, or an earlier review pass does not
waive the remaining acceptance questions.

### Reasons a Contribution May Be Rejected

- The capability already exists, another subsystem solves the problem, or the
  proposal reimplements it without sufficient new value.
- The claimed gap is unsubstantiated or rests on a missed implementation.
- The change conflicts with contracts, architecture, or the agreed scope.
- Evidence is insufficient, irreproducible, or narrower than the claim.
- Maintenance or dependency cost exceeds the demonstrated benefit.
- The PR mixes unrelated changes and cannot be reviewed as a coherent delta.

Rejection does not necessarily mean the code is poor. It can mean:
“This change does not create enough new value for NAUX.” The relevant gap,
contract, evidence, or cost should be made explicit in review so contributors
can decide whether a revision is worthwhile.

## Validation

Use the commands documented in [PROJECT_MAP.md](PROJECT_MAP.md) and the
affected subsystem, starting with focused checks. Validation must be
proportional to change risk.

For Rust changes, use the formatter and the applicable tests. One documented
focused example for bridge SSA work is:

```bash
cargo fmt --all -- --check
cargo test -p naux vm::ssa -- --nocapture
```

Choose the actual test filter or integration target for your subsystem; the
example above is not validation of an unrelated native or runtime change.
Check that the intended tests actually ran. Broader Rust validation includes:

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

For grammar/editor-package changes:

```bash
npm --prefix vscode/naux-lang test
```

The [README's editor-support section](README.md#editor-support) identifies the
canonical grammar repository and this repository's mirror; route grammar
changes accordingly. Native, specialization, formal, and evidence changes also
need the dedicated checks routed by `PROJECT_MAP.md`, the corresponding
subsystem README, and [CI workflows](.github/workflows/). Workspace tests alone
do not replace replay, mutation, or kernel checks. Use the feature sets and
host prerequisites required by those gates; report skips and infrastructure
failures accurately.

A non-normative documentation typo normally needs an accuracy, diff, and
link/rendering check—not the entire Rust suite, a benchmark, or a formal proof.
Use `python3 scripts/check_markdown_links.py` for repository-local link targets
and check changed heading anchors and rendering separately. Run examples when
their executable content changes. Evidence-bound files need their
identity/transition checks even when the edit looks cosmetic.

## Where to Start

If the architecture is unfamiliar, start with a confirmed documentation gap,
a focused example correction, editor support, or a small tooling defect. Read
the relevant route, identify the existing behavior, and propose a small,
demonstrable improvement. Core contributions require studying their contracts
and trust boundaries; they are not promised to be easy.

The purpose of this document is not to maximize contributions. It is to
maximize useful contributions and minimize wasted work.
