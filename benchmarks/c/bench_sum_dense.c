#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)atoll(argv[1]) : 100000;
    size_t iters = argc > 2 ? (size_t)atoll(argv[2]) : 200;
    size_t warmup_ms = argc > 3 ? (size_t)atoll(argv[3]) : 100;
    size_t reps = argc > 4 ? (size_t)atoll(argv[4]) : 50;

    double *arr = (double *)malloc(sizeof(double) * n);
    if (!arr) {
        return 1;
    }

    uint64_t warmup_end = now_ns() + warmup_ms * 1000000ull;
    while (now_ns() < warmup_end) {
        volatile double s = 0;
        for (size_t i = 0; i < n; i++) {
            arr[i] = (double)i;
        }
        for (size_t r = 0; r < reps; r++) {
            for (size_t i = 0; i < n; i++) {
                s += 0.0;
                s += 0.0;
                s += arr[i];
            }
        }
    }

    uint64_t *samples = (uint64_t *)malloc(sizeof(uint64_t) * iters);
    if (!samples) {
        free(arr);
        return 1;
    }

    for (size_t it = 0; it < iters; it++) {
        uint64_t start = now_ns();
        volatile double s = 0;
        for (size_t i = 0; i < n; i++) {
            arr[i] = (double)i;
        }
        for (size_t r = 0; r < reps; r++) {
            for (size_t i = 0; i < n; i++) {
                s += 0.0;
                s += 0.0;
                s += arr[i];
            }
        }
        uint64_t end = now_ns();
        samples[it] = end - start;
    }

    for (size_t i = 0; i < iters; i++) {
        for (size_t j = i + 1; j < iters; j++) {
            if (samples[j] < samples[i]) {
                uint64_t t = samples[i];
                samples[i] = samples[j];
                samples[j] = t;
            }
        }
    }

    uint64_t median = samples[iters / 2];
    uint64_t p95 = samples[(size_t)((iters * 95) / 100)];
    double ops = median > 0 ? (1e9 / (double)median) : 0.0;

    printf("[C BENCH] median=%lu ns/op (%.0f ops/sec), p95=%lu ns/op | iters=%zu warmup=%zums reps=%zu\n",
           (unsigned long)median, ops, (unsigned long)p95, iters, warmup_ms, reps);

    free(samples);
    free(arr);
    return 0;
}
