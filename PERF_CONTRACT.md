# NAUX Performance Contract

Status: normative for any performance claim

> This document defines how Naux is allowed to claim performance.
> If a change cannot satisfy this contract, it may still be correct, but it may not be marketed or merged as a performance win.

---

## 1. Purpose

The goal of this contract is to stop vague performance claims.
A performance claim is only valid when it is:
- reproducible
- comparable
- workload-specific
- hardware-specific
- statistically stated
- tied to a command

This contract applies to:
- interpreter changes
- VM changes
- JIT changes
- SSA / optimizer changes
- runtime changes
- codegen changes
- allocation / memory model changes
- benchmark tooling changes

For a generated-code claim, the comparison set includes:

1. a fair generic C or Rust engine;
2. a hand-specialized C or Rust implementation;
3. the NAUX-generated residual implementation.

The artifact must record the exact engine and code provenance used by every
reported row.

---

## 2. Performance claim rules

A change may be described as a performance improvement only if all of the following are true:

1. The workload is named.
2. The command is written down.
3. The baseline engine is named.
4. The comparison engine is named.
5. The hardware fingerprint is recorded.
6. The warmup policy is recorded.
7. The number of iterations is recorded.
8. The statistic used for the claim is recorded.
9. The threshold for success is recorded.
10. The measurement is reproducible from a clean checkout.

If any of these are missing, the claim is invalid.

---

## 3. Required benchmark metadata

Every benchmark result that is used for a claim must include:

- `workload_name`
- `workload_description`
- `source_file` or `command_source`
- `engine`
- `baseline_engine`
- `comparison_engine`
- `hardware`
- `cpu_model`
- `core_count`
- `memory_size`
- `os`
- `rustc_version`
- `build_profile`
- `warmup_policy`
- `iterations`
- `sample_count`
- `metric`
- `threshold`
- `timestamp`
- `git_sha`
- `dirty_tree` flag

---

## 4. Hardware fingerprint

Performance claims must include a hardware fingerprint.
At minimum, record:
- CPU model
- number of physical cores
- number of logical cores
- total RAM
- OS name and version
- compiler version
- target triple
- relevant SIMD capabilities if the workload uses them

If the machine changes, the claim is no longer directly comparable.

---

## 5. Workload categories

Naux performance claims should be tied to one or more of the following workload categories.

### 5.1 Throughput workloads
Examples:
- arithmetic kernels
- collection-heavy transforms
- small DSL programs
- loop-heavy data processing

### 5.2 Latency workloads
Examples:
- short script startup
- hot function call latency
- effect handler overhead
- JIT warm-start latency

### 5.3 Allocation workloads
Examples:
- object-heavy workloads
- list/map churn
- trace allocation pressure
- region/arena behavior

The default contract runs `bench_map_temp_alloc.nx` as a required allocation
regression guard. It requires at least one runtime-elided temporary map and zero
materialized temporary maps unless a change explicitly introduces and documents a
different budget.

### 5.4 Control-flow workloads
Examples:
- branch-heavy code
- recursion
- nested loops
- effect boundary transitions

### 5.5 Compiler-internal workloads
Examples:
- IR lowering
- SSA lowering
- e-graph saturation/extraction
- pass pipeline execution

A claim must always specify which category it belongs to.

---

## 6. Allowed metrics

The following metrics are allowed for official claims:

- `ns/op`
- `ops/sec`
- `p50 latency`
- `p95 latency`
- `p99 latency`
- `throughput`
- `allocation count`
- `bytes allocated`
- `peak live bytes`
- `deopt rate`
- `guard fail rate`
- `code size`
- `compile time`
- `optimizer time`
- `trace build time`

If a metric is transformed, the transformation must be named.
Examples:
- median over samples
- p95 over samples
- geometric mean over runs
- normalized to baseline

---

## 7. Statistical rules

### 7.1 Minimum discipline
A runtime or latency claim must show:
- at least one baseline
- at least one comparison
- at least **30 measured samples** per engine

### 7.2 Preferred statistics
- median for stable latency claims
- p95 for tail latency claims
- mean only if variance is low and explicitly stated
- min/max only as supporting data, not the main claim

### 7.3 Variance rule
If coefficient of variation (CV) is greater than 5%, the result is an observation, not a performance win.
A noisy benchmark cannot be used to assert a win unless the result is repeated enough to be credible.

### 7.4 Outlier rule
Outliers must be reported or explicitly filtered with a stated policy.
No hidden sample dropping.
If outlier handling is used, the policy must be named in the benchmark output.

---

## 8. Warmup and sampling policy

### 8.1 Warmup
Any runtime benchmark involving VM/JIT must state:
- warmup duration or warmup iteration count
- whether warmup is time-based or iteration-based
- whether preheat samples are excluded from reporting

### 8.2 Sampling
Each benchmark must state:
- how many runs were collected
- whether samples were dropped
- whether the benchmark stabilizes before sampling
- whether the first N samples are ignored

### 8.3 Stability
If the engine has a transition phase, the benchmark must either:
- explicitly exclude it, or
- report it as part of the measurement

No silent transition filtering.

---

## 9. Comparison rules

### 9.1 Baseline selection
The baseline must be meaningful.
Examples:
- interpreter vs VM
- VM vs JIT
- optimizer disabled vs enabled
- old pass pipeline vs new pass pipeline

### 9.2 Fair comparison
A comparison is only fair if:
- same workload
- same input
- same hardware
- same build profile
- same output semantics
- same warmup policy

### 9.3 Engine parity
Performance claims are invalid if the compared engines do not produce the same semantics.
Correctness contract comes first.

---

## 10. Threshold policy

A claim should include a threshold.
Examples:
- at least 10% faster median latency
- at least 1.2x throughput
- at least 15% fewer allocations
- at least 20% smaller code size

If there is no threshold, the result is an observation, not a claim.

---

## 11. Failure policy

A benchmark run fails the performance contract if any of the following are true:
- the command cannot be reproduced
- the workload is not named
- the hardware fingerprint is missing
- the baseline is missing
- the statistic is missing
- semantics differ between compared engines
- the benchmark is too noisy to interpret
- the claim uses cherry-picked samples without disclosure

When failure happens:
- do not merge a performance claim
- do not update docs to imply a win
- fix the benchmark harness first

---

## 12. Benchmark command requirement

Every official claim must include a command that a second person can run.

Example shape:
- `cargo run -p naux -- dev bench ...`
- `cargo run -p naux -- dev benchrt ...`
- explicit input file
- explicit engine
- explicit iteration count
- explicit warmup policy

A performance claim without a command is invalid.

### 12.1 Claim evidence bundle

Cross-language evidence may be published only through
`scripts/perf_claim_bundle.py`. The packager is fail-closed and requires:

- `claim.eligible=true` with no blockers;
- all 24 Naux/C/C++/Go/Rust/Zig workload rows;
- checksum parity and CV within the declared threshold for every row;
- a measured Naux trace for every workload, with no JIT-to-VM fallback;
- native forward-branch coverage for `branch_mix`, with no internal side exit;
- at least 30 samples per implementation and at least 100ms warmup;
- full hardware/toolchain fingerprint and a clean, matching Git SHA;
- the report, raw command logs, benchmark sources and reproduction command.

The deterministic tar manifest records SHA-256 and byte size for every bundled
entry. A standalone SHA-256 sidecar authenticates the tar itself. Hand-built or
partially copied result folders are observations, not publishable claim
artifacts.

The same tool verifies an artifact after upload/download:

```bash
python3 scripts/perf_claim_bundle.py \
  --verify target/perf/claims/naux-performance-evidence-<sha>.tar
```

Verification rechecks the tar sidecar, deterministic member metadata, exact
manifest coverage, every entry hash/size, the embedded schema-v2 report, and
the report/manifest Git SHA and reproduction contract.

### 12.2 Controlled-run readiness evidence

A claim is not established by independently green screenshots. The
fail-closed `scripts/perf_m1_readiness.py` aggregator requires one coherent
evidence set:

- at least 10 most-recent trend runs, all `retry_class=pass`;
- 100% structured Python/Rust shadow match and coverage;
- the latest run using Rust as the actual primary, without fallback;
- enforced CPU pinning, `performance` governor, disabled turbo/boost, a clean
  controlled CI identity, and a passing baseline fingerprint;
- a verified cross-language claim bundle from the same full Git SHA.

The Rust-primary workflow-dispatch path is refused on the default branch and
first requires eight clean shadow runs on a dedicated controlled branch.
Eight runs prove two consecutive seven-run windows before the primary switch
is permitted. A blocked readiness report is expected while those external CI
artifacts are still accumulating.

---

## 13. Engine-specific guidance

### 13.1 Interpreter
Use the interpreter as the semantic reference and as a baseline for small scripts.

### 13.2 VM
Use VM as the stable execution baseline for most runtime comparisons.

### 13.3 JIT
Use JIT only when:
- warmup is accounted for
- hot path is actually reached
- deopt behavior is recorded

### 13.4 Optimizer
Optimizer comparisons must separate:
- compile-time cost
- runtime benefit
- code size impact

A slower compiler may still be acceptable if runtime wins are strong, but the tradeoff must be explicit.

---

## 14. Claim formatting template

Every performance claim should be written in a form like:

- Workload: `<name>`
- Command: `<exact command>`
- Baseline: `<engine>`
- Comparison: `<engine>`
- Hardware: `<fingerprint>`
- Warmup: `<policy>`
- Iterations: `<count>`
- Metric: `<statistic>`
- Result: `<measured value>`
- Threshold: `<pass/fail rule>`
- Notes: `<variance, caveats, parity status>`

---

## 15. What counts as a valid win

A win is valid only if:
- the performance improvement is real under the stated metric
- the result is reproducible
- parity is preserved
- the benchmark is not misleading
- the workload is representative of the improvement being claimed

A narrow win on a toy benchmark may still be useful, but it must be labeled as narrow.

---

## 16. What does not count

The following do not count as official performance wins:
- a single fast run with no repeated samples
- improvements on a workload that is not representative
- wins that break semantics
- wins that only appear with hidden flags
- wins that rely on benchmark-specific hacks
- wins that are not reproducible on the same machine

---

## 17. Merge gate

If a change alters runtime, code generation, optimization, allocation, or startup behavior, it must satisfy:
- parity contract
- benchmark contract
- reproducible command
- clear metric
- clear threshold

If it does not, the change may still merge for correctness or infrastructure reasons, but it must not be described as a performance improvement.

---

## 18. Summary

This contract exists to keep Naux honest.

Naux is allowed to be ambitious.
It is not allowed to be vague.

A performance claim is only real when it is reproducible, comparable, and backed by the same semantics.
