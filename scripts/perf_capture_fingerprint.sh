#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_PATH="${1:-$ROOT_DIR/benchmarks/perf_baseline_fingerprint.json}"
CPU_CORE="${CPU_CORE:-0}"

read_sysfs_trimmed() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        return 1
    fi
    tr -d '[:space:]' < "$path"
}

read_cpu_model() {
    if [[ -r /proc/cpuinfo ]]; then
        awk -F: '/model name/ { gsub(/^[[:space:]]+/, "", $2); print $2; exit }' /proc/cpuinfo
        return 0
    fi
    if command -v lscpu >/dev/null 2>&1; then
        lscpu | awk -F: '/Model name/ { gsub(/^[[:space:]]+/, "", $2); print $2; exit }'
        return 0
    fi
    return 1
}

json_escape() {
    local raw="${1:-}"
    printf '%s' "$raw" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read())[1:-1])'
}

gov_path="/sys/devices/system/cpu/cpu${CPU_CORE}/cpufreq/scaling_governor"
gov_val="unavailable"
if v="$(read_sysfs_trimmed "$gov_path" 2>/dev/null)"; then
    gov_val="$v"
fi

turbo_source="unavailable"
turbo_value="unavailable"
if v="$(read_sysfs_trimmed /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null)"; then
    turbo_source="intel_pstate/no_turbo"
    turbo_value="$v"
elif v="$(read_sysfs_trimmed /sys/devices/system/cpu/cpufreq/boost 2>/dev/null)"; then
    turbo_source="cpufreq/boost"
    turbo_value="$v"
fi

cpu_model="unavailable"
if v="$(read_cpu_model 2>/dev/null)"; then
    cpu_model="$v"
fi

mkdir -p "$(dirname "$OUT_PATH")"
cat > "$OUT_PATH" <<EOF
{
  "cpu_model": "$(json_escape "$cpu_model")",
  "cpu_core": "$CPU_CORE",
  "governor": "$(json_escape "$gov_val")",
  "turbo_source": "$(json_escape "$turbo_source")",
  "turbo_value": "$(json_escape "$turbo_value")"
}
EOF

echo "wrote baseline fingerprint: $OUT_PATH"
echo "cpu_model=$cpu_model"
echo "cpu_core=$CPU_CORE"
echo "governor=$gov_val"
echo "turbo_source=$turbo_source"
echo "turbo_value=$turbo_value"
