#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_MANIFEST="$ROOT_DIR/naux-lang/Cargo.toml"
ITERS="${ITERS:-20}"

CORPUS=(
  "naux-lang/examples/hello.nx"
  "naux-lang/examples/jit_numeric.nx"
  "naux-lang/examples/bench_list_temp_alloc.nx"
  "naux-lang/examples/bench_map_get_bimorphic_phase_big.nx"
  "naux-lang/examples/graph_dijkstra.nx"
)

printf '%-46s | %10s | %6s | %7s | %9s | %8s | %s\n' \
  "file" "avg_ns/op" "blocks" "inst %" "varop %" "stop" "status"
printf '%s\n' \
  "----------------------------------------------+------------+--------+---------+-----------+----------+--------"

for rel in "${CORPUS[@]}"; do
  path="$ROOT_DIR/$rel"
  if [[ ! -f "$path" ]]; then
    printf '%-46s | %10s | %6s | %7s | %9s | %8s | %s\n' \
      "$rel" "-" "-" "-" "-" "-" "missing"
    continue
  fi

  output="$(cargo run --manifest-path "$CARGO_MANIFEST" -- dev ssa-stats "$path" --iters "$ITERS" 2>/dev/null)"
  avg="$(printf '%s\n' "$output" | sed -n 's/^avg: \([0-9][0-9]*\) ns\/op$/\1/p')"
  blocks="$(printf '%s\n' "$output" | sed -n 's/^blocks: \([0-9][0-9]*\)$/\1/p')"
  inst_pct="$(printf '%s\n' "$output" | sed -n 's/^insts: .* (\([0-9.][0-9.]*%\))$/\1/p')"
  varop_pct="$(printf '%s\n' "$output" | sed -n 's/^var_ops-staged: .* (\([0-9.][0-9.]*%\))$/\1/p')"
  stop="$(printf '%s\n' "$output" | sed -n 's/^optimizer-main-stop: \(.*\)$/\1/p')"
  status="$(printf '%s\n' "$output" | sed -n 's/^functions: .*unsupported=\([0-9][0-9]*\)).*$/\1/p')"

  if [[ -n "$status" && "$status" != "0" ]]; then
    status="unsupported=$status"
  else
    status="ok"
  fi

  printf '%-46s | %10s | %6s | %7s | %9s | %8s | %s\n' \
    "$rel" "${avg:--}" "${blocks:--}" "${inst_pct:--}" "${varop_pct:--}" "${stop:--}" "$status"
done
