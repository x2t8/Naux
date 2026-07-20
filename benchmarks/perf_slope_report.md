# Slope Gate Report

- baseline: `/run/media/txuandev/New Volume/David Xuân Tools/Kali/LangNaux/benchmarks/perf_slope_baseline.tsv`
- cpu_core: `0`
- engine: `jit`

| scenario | a (ns/elem) | b (ns) | R² | baseline a | baseline b | baseline R² | a regress % | b regress % | gate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| dot_runtime_only | 0.059023 | 29735.875 | 0.9779 | 0.063523 | 12559.583 | 0.9999 | -7.08 | 136.76 | FAIL (R2 drop 0.9779 vs baseline 0.9999) |
| dot_trace_only | 0.062505 | 21.195 | 0.9997 | 0.061423 | 21.557 | 1.0000 | 1.76 | -1.68 | PASS |
| map_heavy_read | 3.164233 | 36456.167 | 1.0000 | 4.565634 | 62564.833 | 1.0000 | -30.69 | -41.73 | PASS |
| map_guard_entry_heavy | 3.244219 | 79018388.355 | 0.9990 | 4.765233 | 104518394.456 | 0.9980 | -31.92 | -24.40 | PASS |
