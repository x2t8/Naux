# M1 Execution Checklist (Now -> End of Q2)

Status date: 2026-02-22  
Scope: close M1 from `ROADMAP.md` with enforceable evidence.

## Exit Criteria
- Rust slope gate promoted from shadow to primary on controlled branch.
- Trend window has >=10 stable runs, with no hard failures.
- Cross-language baseline artifacts (C/C++/Rust/Go/Zig) are published and reproducible.

## CI / Governance
| Item | Owner | Status | Exit Evidence |
|---|---|---|---|
| Keep `slope` + `fixed-cost` + `cold-start` gates green | Runtime Tooling | In Progress | `target/perf/slope_report.json`, `target/perf/fixed_cost_report.json` |
| Keep `retry_class=hard` at 0 in stability window | Runtime Tooling | In Progress | `target/perf/stability_window_report.json` |
| Promote Rust slope gate to primary (`SLOPE_GATE_PRIMARY=rust`) on branch | Runtime Tooling | In Progress | branch CI logs + `target/perf/slope_report_py_shadow_compare.txt` |
| Keep Python/Rust shadow compare mismatch at 0 | Runtime Tooling | In Progress | `target/perf/slope_report_*_shadow_compare.txt` |
| Keep trend pipeline pass-only (no snapshot on failed gate) | Runtime Tooling | Done | `scripts/perf_contract_ci.sh` behavior + history dirs |

## Runtime / JIT
| Item | Owner | Status | Exit Evidence |
|---|---|---|---|
| Maintain map fusion wins (`add_local`, `mul_acc`, `cmp_branch`) | VM/JIT | In Progress | fusion hits in `slope_report.json` |
| Keep branchy trace path stable (`cmp_branch` runtime hits) | VM/JIT | In Progress | `map_get_cmp_branch` scenario in slope report |
| Keep deopt telemetry pipeline healthy (observe/warn) | VM/JIT | In Progress | `deopt_report.json`, `deopt_warn_report.json` |
| No fixed-cost regression while expanding fusion | VM/JIT | In Progress | `fixed_cost_report.json` gates |

## Compiler / Correctness
| Item | Owner | Status | Exit Evidence |
|---|---|---|---|
| Keep clippy gate strict (`-D warnings`) | Compiler | Done | contract CI step output |
| Increase guard/deopt differential coverage | Compiler + Runtime | In Progress | runtime/oracle test additions |
| Fuzz map/list alias + mutation paths | Compiler + Runtime | Planned | new fuzz reports in CI artifacts |

## Baselines / Claims
| Item | Owner | Status | Exit Evidence |
|---|---|---|---|
| Rebuild C/C++ baseline with pinned methodology | Perf | In Progress | baseline scripts + artifacts |
| Rebuild Rust/Go/Zig baseline with pinned methodology | Perf | In Progress | `target/perf/go_rust_baseline*` and Zig artifacts |
| Publish one reproducible benchmark bundle for claims | Perf + Docs | Planned | artifact pack + docs link |

## Weekly Rhythm
- Monday: review trend/stability drift and blocker list.
- Mid-week: one optimization increment only (avoid mixed-cause regressions).
- Friday: full contract run, publish artifacts, update `ROADMAP_STATUS.md`.
