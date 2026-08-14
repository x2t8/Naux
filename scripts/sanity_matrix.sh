#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/naux-lang/Cargo.toml"
BIN=(cargo run --manifest-path "$MANIFEST_PATH" -- run)

CORPUS=(
  "naux-lang/examples/hello.nx"
  "naux-lang/examples/smoke/runtime_loop.nx"
  "naux-lang/examples/graph_bfs.nx"
  "naux-lang/examples/jit_numeric.nx"
)

if [[ $# -gt 0 ]]; then
  CORPUS=("$@")
fi

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

echo "[sanity] corpus size: ${#CORPUS[@]}"

for rel in "${CORPUS[@]}"; do
  path="$ROOT_DIR/$rel"
  if [[ ! -f "$path" ]]; then
    echo "[sanity] FAIL missing file: $rel" >&2
    exit 1
  fi

  echo "[sanity] checking $rel"
  vm_out="$tmpdir/vm.json"
  jit_out="$tmpdir/jit.json"
  vm_err="$tmpdir/vm.err"
  jit_err="$tmpdir/jit.err"

  if ! "${BIN[@]}" "$path" --engine=vm --mode=json >"$vm_out" 2>"$vm_err"; then
    echo "[sanity] FAIL VM execution: $rel" >&2
    cat "$vm_err" >&2
    exit 1
  fi
  if ! "${BIN[@]}" "$path" --engine=jit --mode=json >"$jit_out" 2>"$jit_err"; then
    echo "[sanity] FAIL JIT execution: $rel" >&2
    cat "$jit_err" >&2
    exit 1
  fi

  if ! diff -u "$vm_out" "$jit_out" >"$tmpdir/diff.out"; then
    echo "[sanity] FAIL parity mismatch: $rel" >&2
    echo "--- vm stderr ---" >&2
    cat "$vm_err" >&2
    echo "--- jit stderr ---" >&2
    cat "$jit_err" >&2
    echo "--- diff ---" >&2
    cat "$tmpdir/diff.out" >&2
    exit 1
  fi

  jit_engine="$(grep -n '^\[engine\]' "$jit_err" || true)"
  if [[ -n "$jit_engine" ]]; then
    echo "  jit-path: ${jit_engine#*:}"
  fi
done

echo "[sanity] PASS"
