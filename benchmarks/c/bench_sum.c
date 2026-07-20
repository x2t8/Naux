#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static inline uint64_t now_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static uint64_t percentile(uint64_t *samples, size_t n, double pct) {
    if (n == 0) return 0;
    double rank = (pct / 100.0) * (double)(n - 1);
    size_t idx = (size_t)(rank + 0.999999); // ceil
    if (idx >= n) idx = n - 1;
    return samples[idx];
}

static double run_once(uint64_t n) {
    double sum = 0.0;
    for (uint64_t i = 0; i < n; i++) {
        sum += (double)(i * 3 + 1);
    }
    return sum;
}

int main(int argc, char **argv) {
    uint64_t n = 100000;
    uint64_t iters = 200;
    uint64_t warmup_ms = 100;
    if (argc > 1) n = (uint64_t)strtoull(argv[1], NULL, 10);
    if (argc > 2) iters = (uint64_t)strtoull(argv[2], NULL, 10);
    if (argc > 3) warmup_ms = (uint64_t)strtoull(argv[3], NULL, 10);

    uint64_t warmup_start = now_ns();
    uint64_t warmup_iters = 0;
    while ((now_ns() - warmup_start) < warmup_ms * 1000000ULL) {
        (void)run_once(n);
        warmup_iters++;
    }

    uint64_t *samples = (uint64_t *)calloc(iters, sizeof(uint64_t));
    if (!samples) return 1;
    for (uint64_t i = 0; i < iters; i++) {
        uint64_t t0 = now_ns();
        (void)run_once(n);
        uint64_t t1 = now_ns();
        samples[i] = t1 - t0;
    }

    qsort(samples, iters, sizeof(uint64_t), cmp_u64);
    uint64_t med = percentile(samples, iters, 50.0);
    uint64_t p95 = percentile(samples, iters, 95.0);
    uint64_t ops = med ? (1000000000ULL / med) : 0;
    printf("[C BENCH] median=%lu ns/op (%lu ops/sec), p95=%lu ns/op | iters=%lu warmup=%lums\n",
           (unsigned long)med,
           (unsigned long)ops,
           (unsigned long)p95,
           (unsigned long)iters,
           (unsigned long)warmup_ms);

    free(samples);
    return 0;
}
