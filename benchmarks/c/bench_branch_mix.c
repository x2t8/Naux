#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static volatile double g_sink = 0.0;

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static double cv_pct(const uint64_t *samples, size_t count) {
    if (count < 2) return 0.0;
    long double mean = 0.0;
    for (size_t i = 0; i < count; i++) mean += samples[i];
    mean /= (long double)count;
    if (mean == 0.0) return 0.0;
    long double variance = 0.0;
    for (size_t i = 0; i < count; i++) {
        long double delta = (long double)samples[i] - mean;
        variance += delta * delta;
    }
    variance /= (long double)count;
    return sqrt((double)variance) * 100.0 / (double)mean;
}

static double run_kernel(double *arr, size_t n, size_t reps) {
    double sum = 0.0;
    int64_t state = 0;
    for (size_t r = 0; r < reps; r++) {
        for (size_t i = 0; i < n; i++) {
            const double value = arr[i];
            state += 17;
            if (state >= 97) {
                state -= 97;
            }
            if (state < 48) {
                sum += value;
            } else {
                sum -= value;
            }
        }
    }
    return sum;
}

static double run_once(size_t n, size_t reps) {
    double *arr = (double *)malloc(sizeof(double) * n);
    if (!arr) {
        return NAN;
    }
    for (size_t i = 0; i < n; i++) {
        arr[i] = (double)i;
    }
    const double result = run_kernel(arr, n, reps);
    g_sink = result;
    free(arr);
    return result;
}

int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)atoll(argv[1]) : 100000;
    size_t iters = argc > 2 ? (size_t)atoll(argv[2]) : 200;
    size_t warmup_ms = argc > 3 ? (size_t)atoll(argv[3]) : 100;
    size_t reps = argc > 4 ? (size_t)atoll(argv[4]) : 50;

    uint64_t warmup_end = now_ns() + warmup_ms * 1000000ull;
    while (now_ns() < warmup_end) {
        if (isnan(run_once(n, reps))) return 1;
    }

    uint64_t *samples = (uint64_t *)malloc(sizeof(uint64_t) * iters);
    if (!samples) return 1;

    double checksum = 0.0;
    for (size_t it = 0; it < iters; it++) {
        uint64_t start = now_ns();
        checksum = run_once(n, reps);
        uint64_t end = now_ns();
        if (isnan(checksum)) {
            free(samples);
            return 1;
        }
        samples[it] = end - start;
    }

    double sample_cv_pct = cv_pct(samples, iters);
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

    printf("[C BENCH] branch_mix median=%lu ns/op (%.0f ops/sec), p95=%lu ns/op cv_pct=%.4f | iters=%zu warmup=%zums reps=%zu checksum=%.17g\n",
           (unsigned long)median, ops, (unsigned long)p95, sample_cv_pct, iters, warmup_ms, reps, checksum);

    free(samples);
    return 0;
}
