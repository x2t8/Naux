# Next comparison: register-residency NAUX and C

Status: **draft plan, not measurement authority**. The executable planner is
`scripts/s4_comparison_plan.py`. It checks existing carrier authorities and
prints the proposed inputs and schedule; it does not compile or run benchmarks.

```bash
python3 scripts/s4_comparison_plan.py
python3 scripts/s4_comparison_plan.py --schedule
```

The Apache checkout stays unchanged. Historical pre-Apache authorities are
checked through the existing LT1 materializer in an automatically cleaned
temporary directory. The only subprocess is read-only `git ls-files` inventory.

## Why a new comparison is needed

WP8S establishes one register-residency-versus-stack-home observation. It does
not include C. WP7C/WP7D's older C comparison uses the old NAUX artifact and a
different session; its variance and performance gates failed. Multiplying
ratios from those two experiments would not measure the current C gap.

| Scope 4 requirement | Existing component | Work still needed |
| --- | --- | --- |
| Within 10% of specialized C | WP2 C sources, WP7B C timing, WP7D threshold | Fresh r12/C session and role-aware replay |
| At least 1.25x over generic native C | WP2 generic C, same WP7D intersection rule | Both thresholds must pass on the same kernel |
| Independently replayable evidence | WP7C and WP8M bundle patterns | New complete three-role bundle; old bundles cannot be merged |
| Separate runtime and other costs | WP1 metric inventory and timing envelopes | Compilation, specialization, startup, memory and code-size evidence |
| Release performance regression gate | Existing tests protect carrier identity | An admitted performance reference and an enforced release gate |

This plan selects C, not C++ or Rust. Their results cannot be inferred from C.
The plan is a next runtime-comparison slice, not the complete Scope 4 exit gate.

## Proposed roles and immutable inputs

All four existing kernels retain `n=16384`, `reps=50`, checksum oracles,
numeric contracts, and the allocation/initialization/kernel/checksum/teardown
runtime region. No closed-form replacement, relaxed checks, fast-math, or LTO
is introduced. The planner emits exact WP8J expected ELF hashes, WP7B C source
hashes, and the original WP2 C compilation flags. C executable hashes do not
exist until a new build is verified and must not be replaced by source hashes.

| Result-record owner | Implementation | Parameters |
| --- | --- | --- |
| 4 | WP8J register-residency candidate | Static |
| 2 | WP7B C generic | Runtime argv `16384 50` |
| 3 | WP7B C specialized | Static, original WP2 flags |

These are **wire owners**, not WP1's role-list ordinals. In particular, owner
4 here means the WP8J candidate, not WP1's optional `rust-generic` entry. The
candidate must not be relabelled as old `naux-residual` owner 1 to pass WP7A or
WP7D. The eventual bundle needs its own format and explicit role mapping.

## Proposed schedule

For each kernel, repeat these six orders five times:

```text
4 2 3    3 2 4    2 3 4    4 3 2    3 4 2    2 4 3
```

There are 30 rounds per kernel, one invocation per role per round: 360 measured
invocations across four kernels. Each role occupies each position ten times
per kernel; every pair of roles occurs in each relative order fifteen times.
This balances the listed within-round positions/orders; it does not guarantee
absence of host noise or thermal effects.

Warmups are separate and all retained. Before recording the 30 measured rounds
of a kernel, all three roles must each accumulate at least 100 ms of warmup.
The acquisition protocol must still define and validate the bounded warmup
schedule and failure handling. There is no sample dropping, retry-until-pass,
or reuse of samples from another session.

Preserve the existing WP7D decision rules: all twelve statistics must satisfy
the 5% CV gate; at least one **same kernel** must satisfy both
`candidate median / specialized C median <= 11/10` and
`generic C median / candidate median >= 5/4`. A schedule is not a result.

## Implementation boundary

The planner has no acquisition, compiler, bundle, or host-attestation input.
Exit zero means the draft can be constructed from its checked parents, not
permission to measure or evidence that a threshold passed. Its report always
states `draft-plan-only`, `execution-status forbidden`, zero observed samples,
and `claim-status not-admitted`.

Next: review/freeze the three-role collection and evidence format, implement
the collector and independent replay with synthetic failure tests, then obtain
fresh suite-specific host eligibility and explicit live-acquisition approval.
Do not change WP8S's approved text, old measurements, or sealed parent files.
