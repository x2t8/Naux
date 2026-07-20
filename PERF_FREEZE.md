# Performance Freeze Playbook

This document defines the operating mode for performance governance:

`Freeze -> Observe -> Stabilize -> Evolve`

The goal is to prevent false regressions and prevent optimization churn while CI/cloud is unstable.

## 1) Freeze

### Rules
- Do not change perf thresholds, gate math, or baseline files.
- Do not add/remove benchmark scenarios.
- Do not promote fusion rules (`optional -> required`) during freeze.
- Only allow:
  - measurement infrastructure fixes,
  - runner environment fixes,
  - report/telemetry visibility improvements.

### Entry checklist
- `scripts/perf_contract_ci.sh` is green locally on the reference machine at least once.
- Python/Rust slope shadow compare is enabled.
- Runner preflight is enabled (`PERF_ENV_ENFORCE=1`) for CI perf job.

## 2) Observe (minimum 7 runs, target 10)

Collect runs without changing contracts.

### Required artifacts per run
- `target/perf/slope_report.json`
- `target/perf/fixed_cost_report.json`
- `target/perf/stability_window_report.json`
- `target/perf/trend_report.json`
- `target/perf/slope_report_*_shadow_compare.txt`

### Required KPIs
- `hard = 0`
- `shadow_match = 100%`
- `retryable <= 5%`
- `baseline_fingerprint_status = pass`

If any KPI fails, remain in Observe and fix environment first.

## 3) Stabilize

### Promotion criteria
- Two consecutive windows meet all KPIs.
- No `retry_class=hard` in stability window.
- No shadow mismatch in the same window.

### Allowed actions in Stabilize
- Re-capture baseline fingerprint on the same reference machine if needed.
- Re-run soak for confirmation.
- Document root cause and fix for any transient failures.

## 4) Evolve

Only enter Evolve after Stabilize criteria are met.

### Allowed actions
- Add one performance change per PR (single-variable change).
- New fusion rules start as `optional`.
- Promote to `required` only after stable evidence window.
- Rebaseline only with explicit note + artifact references.

## Daily Checklist (Operator)

1. Verify machine state:
   - governor `performance`
   - turbo setting matches policy
   - core pinning available
2. Verify fingerprint against baseline.
3. Run contract once.
4. Review KPIs in reports.
5. If fail, classify `environment` vs `code` before any threshold/baseline change.

## Commands

Capture reference fingerprint:

```bash
CPU_CORE=2 ./scripts/perf_capture_fingerprint.sh benchmarks/perf_baseline_fingerprint.json
```

Run contract with strict environment + fingerprint enforcement:

```bash
CPU_CORE=2 \
PERF_ENV_ENFORCE=1 \
PERF_REQUIRE_TASKSET=1 \
PERF_EXPECT_GOVERNOR=performance \
PERF_EXPECT_INTEL_NO_TURBO=1 \
PERF_BASELINE_FINGERPRINT_REQUIRE=1 \
PERF_BASELINE_FINGERPRINT_ENFORCE=1 \
./scripts/perf_contract_ci.sh
```

## Non-negotiable policy

- Never soften threshold to pass noise.
- Never rebaseline without evidence window.
- Never compare slope gates from different samples.
- Keep shadow replay compare enabled until explicitly retired.
