#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/target/perf/go_rust_baseline}"
CPU_CORE="${CPU_CORE:-0}"
ITERS="${ITERS:-10}"
WARMUP_MS="${WARMUP_MS:-100}"
REPS="${REPS:-50}"
N="${N:-100000}"
ENGINE="${ENGINE:-jit}"

REQUIRE_NAUX_BEAT_GO="${REQUIRE_NAUX_BEAT_GO:-0}"
REQUIRE_NAUX_BEAT_RUST="${REQUIRE_NAUX_BEAT_RUST:-0}"

NAUX_RUSTFLAGS="${NAUX_RUSTFLAGS:--C target-cpu=native}"
RUST_BASELINE_RUSTFLAGS="${RUST_BASELINE_RUSTFLAGS:--C target-cpu=native}"
GO_BUILD_FLAGS="${GO_BUILD_FLAGS:--trimpath}"
C_FLAGS="${C_FLAGS:--O3 -march=native}"

BENCH_NAMES=("sum_dense" "list_update" "dot_product")
NAUX_FILES=(
    "naux-lang/examples/bench_sum_dense.nx"
    "naux-lang/examples/bench_list_update.nx"
    "naux-lang/examples/bench_dot_product.nx"
)
C_SRCS=(
    "benchmarks/c/bench_sum_dense.c"
    "benchmarks/c/bench_list_update.c"
    "benchmarks/c/bench_dot_product.c"
)
C_BINS=(
    "benchmarks/c/bench_sum_dense"
    "benchmarks/c/bench_list_update"
    "benchmarks/c/bench_dot_product"
)
GO_SRCS=(
    "benchmarks/go/bench_sum_dense.go"
    "benchmarks/go/bench_list_update.go"
    "benchmarks/go/bench_dot_product.go"
)
GO_BINS=(
    "benchmarks/go/bin/bench_sum_dense"
    "benchmarks/go/bin/bench_list_update"
    "benchmarks/go/bin/bench_dot_product"
)
RUST_BINS=(
    "bench_sum_dense"
    "bench_list_update"
    "bench_dot_product"
)

mkdir -p "$OUT_DIR"
mkdir -p "$ROOT_DIR/benchmarks/go/bin"

for cmd in cargo cc go python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[bench] missing required command: $cmd" >&2
        exit 1
    fi
done

run_pinned() {
    if command -v taskset >/dev/null 2>&1; then
        taskset -c "$CPU_CORE" "$@"
    else
        "$@"
    fi
}

parse_metric() {
    local key="$1"
    local data="$2"
    echo "$data" | sed -n "s/.*$key=\\([0-9][0-9]*\\).*/\\1/p" | head -n1
}

speedup() {
    local baseline_ns="$1"
    local naux_ns="$2"
    awk -v b="$baseline_ns" -v n="$naux_ns" 'BEGIN { if (n == 0) print "0.000"; else printf "%.3f", b / n }'
}

echo "[bench] methodology: pinned CPU (if taskset), same n/iters/warmup/reps, median+p95"
echo "[bench] params: n=$N iters=$ITERS warmup_ms=$WARMUP_MS reps=$REPS engine=$ENGINE"
echo "[bench] naux build flags: RUSTFLAGS=\"$NAUX_RUSTFLAGS\" cargo build -p naux --release"
echo "[bench] rust baseline flags: RUSTFLAGS=\"$RUST_BASELINE_RUSTFLAGS\" cargo build --manifest-path benchmarks/rust/Cargo.toml --release"
echo "[bench] go baseline flags: go build $GO_BUILD_FLAGS"

echo
echo "[bench] build naux release"
(cd "$ROOT_DIR" && RUSTFLAGS="$NAUX_RUSTFLAGS" cargo build -p naux --release >/dev/null)

echo "[bench] build C baselines"
for i in "${!C_SRCS[@]}"; do
    src="$ROOT_DIR/${C_SRCS[$i]}"
    out="$ROOT_DIR/${C_BINS[$i]}"
    cc $C_FLAGS -o "$out" "$src"
done

echo "[bench] build Go baselines"
for i in "${!GO_SRCS[@]}"; do
    src="$ROOT_DIR/${GO_SRCS[$i]}"
    out="$ROOT_DIR/${GO_BINS[$i]}"
    go build $GO_BUILD_FLAGS -o "$out" "$src"
done

echo "[bench] build Rust baselines"
(cd "$ROOT_DIR" && RUSTFLAGS="$RUST_BASELINE_RUSTFLAGS" cargo build --manifest-path benchmarks/rust/Cargo.toml --release >/dev/null)

TSV="$OUT_DIR/go_rust_baseline.tsv"
MD="$OUT_DIR/go_rust_baseline.md"
JSON="$OUT_DIR/go_rust_baseline.json"
: > "$TSV"

FAILED=0
for i in "${!BENCH_NAMES[@]}"; do
    name="${BENCH_NAMES[$i]}"
    naux_file="$ROOT_DIR/${NAUX_FILES[$i]}"
    c_bin="$ROOT_DIR/${C_BINS[$i]}"
    go_bin="$ROOT_DIR/${GO_BINS[$i]}"
    rust_bin="$ROOT_DIR/benchmarks/rust/target/release/${RUST_BINS[$i]}"

    naux_out="$(run_pinned "$ROOT_DIR/target/release/naux" dev benchrt "$naux_file" --engine="$ENGINE" --iters="$ITERS" --warmup-ms="$WARMUP_MS")"
    c_out="$(run_pinned "$c_bin" "$N" "$ITERS" "$WARMUP_MS" "$REPS")"
    go_out="$(run_pinned "$go_bin" "$N" "$ITERS" "$WARMUP_MS" "$REPS")"
    rust_out="$(run_pinned "$rust_bin" "$N" "$ITERS" "$WARMUP_MS" "$REPS")"

    echo "$naux_out" > "$OUT_DIR/${name}.naux.log"
    echo "$c_out" > "$OUT_DIR/${name}.c.log"
    echo "$go_out" > "$OUT_DIR/${name}.go.log"
    echo "$rust_out" > "$OUT_DIR/${name}.rust.log"

    naux_median="$(parse_metric "median" "$naux_out")"
    naux_p95="$(parse_metric "p95" "$naux_out")"
    c_median="$(parse_metric "median" "$c_out")"
    c_p95="$(parse_metric "p95" "$c_out")"
    go_median="$(parse_metric "median" "$go_out")"
    go_p95="$(parse_metric "p95" "$go_out")"
    rust_median="$(parse_metric "median" "$rust_out")"
    rust_p95="$(parse_metric "p95" "$rust_out")"

    if [[ -z "$naux_median" || -z "$c_median" || -z "$go_median" || -z "$rust_median" ]]; then
        echo "[bench] failed to parse benchmark output for $name" >&2
        FAILED=1
        continue
    fi

    c_over_naux="$(speedup "$c_median" "$naux_median")"
    go_over_naux="$(speedup "$go_median" "$naux_median")"
    rust_over_naux="$(speedup "$rust_median" "$naux_median")"

    if [[ "$REQUIRE_NAUX_BEAT_GO" == "1" && "$go_median" -le "$naux_median" ]]; then
        echo "[bench] FAIL: Naux does not beat Go on $name (naux=$naux_median, go=$go_median)" >&2
        FAILED=1
    fi
    if [[ "$REQUIRE_NAUX_BEAT_RUST" == "1" && "$rust_median" -le "$naux_median" ]]; then
        echo "[bench] FAIL: Naux does not beat Rust on $name (naux=$naux_median, rust=$rust_median)" >&2
        FAILED=1
    fi

    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
        "$name" \
        "$naux_median" "$naux_p95" \
        "$c_median" "$c_p95" \
        "$go_median" "$go_p95" \
        "$rust_median" "$rust_p95" \
        "$c_over_naux" "$go_over_naux" "$rust_over_naux" >> "$TSV"
done

python3 - "$TSV" "$JSON" "$ENGINE" "$ITERS" "$WARMUP_MS" "$REPS" "$N" "$NAUX_RUSTFLAGS" "$RUST_BASELINE_RUSTFLAGS" "$GO_BUILD_FLAGS" "$C_FLAGS" << 'PY'
import csv
import json
import math
import sys
from pathlib import Path

tsv = Path(sys.argv[1])
out_json = Path(sys.argv[2])
engine = sys.argv[3]
iters = int(sys.argv[4])
warmup_ms = int(sys.argv[5])
reps = int(sys.argv[6])
n = int(sys.argv[7])
naux_flags = sys.argv[8]
rust_flags = sys.argv[9]
go_flags = sys.argv[10]
c_flags = sys.argv[11]

rows = []
with tsv.open("r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) != 12:
            continue
        rows.append(
            {
                "benchmark": parts[0],
                "naux_median_ns": int(parts[1]),
                "naux_p95_ns": int(parts[2]),
                "c_median_ns": int(parts[3]),
                "c_p95_ns": int(parts[4]),
                "go_median_ns": int(parts[5]),
                "go_p95_ns": int(parts[6]),
                "rust_median_ns": int(parts[7]),
                "rust_p95_ns": int(parts[8]),
                "c_over_naux": float(parts[9]),
                "go_over_naux": float(parts[10]),
                "rust_over_naux": float(parts[11]),
            }
        )

def geomean(values):
    vals = [v for v in values if v > 0.0]
    if not vals:
        return 0.0
    return math.exp(sum(math.log(v) for v in vals) / len(vals))

summary = {
    "geomean_c_over_naux": geomean([r["c_over_naux"] for r in rows]),
    "geomean_go_over_naux": geomean([r["go_over_naux"] for r in rows]),
    "geomean_rust_over_naux": geomean([r["rust_over_naux"] for r in rows]),
}

payload = {
    "meta": {
        "methodology": "same n/iters/warmup/reps, pinned CPU when taskset exists, median+p95",
        "engine": engine,
        "n": n,
        "iters": iters,
        "warmup_ms": warmup_ms,
        "reps": reps,
        "build_flags": {
            "naux_rustflags": naux_flags,
            "rust_baseline_rustflags": rust_flags,
            "go_build_flags": go_flags,
            "c_flags": c_flags,
        },
    },
    "rows": rows,
    "summary": summary,
}

out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
print(f"[bench] wrote {out_json}")
PY

{
    echo "# Go/Rust Baseline Report"
    echo
    echo "- methodology: same n/iters/warmup/reps, pinned CPU when taskset exists, median+p95"
    echo "- engine: $ENGINE"
    echo "- n: $N"
    echo "- iters: $ITERS"
    echo "- warmup_ms: $WARMUP_MS"
    echo "- reps: $REPS"
    echo "- naux build flags: RUSTFLAGS=\"$NAUX_RUSTFLAGS\" cargo build -p naux --release"
    echo "- rust baseline flags: RUSTFLAGS=\"$RUST_BASELINE_RUSTFLAGS\" cargo build --manifest-path benchmarks/rust/Cargo.toml --release"
    echo "- go baseline flags: go build $GO_BUILD_FLAGS"
    echo "- c baseline flags: cc $C_FLAGS"
    echo
    echo "| benchmark | naux median ns/op | naux p95 | c median | go median | rust median | C/Naux | Go/Naux | Rust/Naux |"
    echo "|---|---:|---:|---:|---:|---:|---:|---:|---:|"
    while IFS=$'\t' read -r name naux_median naux_p95 c_median c_p95 go_median go_p95 rust_median rust_p95 c_over_naux go_over_naux rust_over_naux; do
        [[ -z "$name" ]] && continue
        echo "| $name | $naux_median | $naux_p95 | $c_median | $go_median | $rust_median | $c_over_naux | $go_over_naux | $rust_over_naux |"
    done < "$TSV"
} > "$MD"

echo "[bench] wrote $MD"
echo "[bench] wrote $TSV"

if [[ "$FAILED" -ne 0 ]]; then
    echo "[bench] FAILED" >&2
    exit 1
fi
echo "[bench] PASS"
