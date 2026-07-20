# Fixed Cost Gate Report

## Low-n

| scenario | n | compute median ns | baseline ns | threshold ns | gate |
|---|---:|---:|---:|---:|---|
| dot_runtime_n512 | 512 | 14486 | 14489 | 17989 | PASS |
| dot_runtime_n1024 | 1024 | 16858 | 15760 | 17760 | PASS |
| dot_runtime_n2048 | 2048 | 19062 | 18984 | 20984 | PASS |

## Cold Start

| scenario | median ns | baseline ns | threshold ns | gate |
|---|---:|---:|---:|---|
| dot_runtime_cold_n65536 | 1490322 | 1640000 | 1836800 | PASS |

## Perf Stat

- unavailable: perf not found
