#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <immintrin.h>
#include <time.h>
#include <vector>

#ifndef NAUX_DOT_VARIANT
#define NAUX_DOT_VARIANT 1
#endif

static volatile double g_sink = 0.0;

static inline uint64_t now_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull +
           static_cast<uint64_t>(ts.tv_nsec);
}

static inline uint64_t lcg_next(uint64_t &state) {
    state = state * 6364136223846793005ull + 1ull;
    return state;
}

static void fill_input(double *arr, size_t n, uint64_t seed) {
    // Keep seed=0 aligned with Naux list_range benchmark input.
    if (seed == 0) {
        for (size_t i = 0; i < n; i++) {
            arr[i] = static_cast<double>(i);
        }
        return;
    }

    uint64_t state = seed;
    constexpr double inv = 1.0 / 4294967296.0; // 2^32
    for (size_t i = 0; i < n; i++) {
        uint64_t x = lcg_next(state);
        arr[i] = static_cast<double>(x & 0xFFFFFFFFull) * inv;
    }
}

#if NAUX_DOT_VARIANT == 1
static inline const char *variant_name() { return "v1_naive"; }

static double dot_kernel(const double *arr, size_t n, size_t reps) {
    double total = 0.0;
    for (size_t r = 0; r < reps; r++) {
        double sum = 0.0;
        for (size_t i = 0; i < n; i++) {
            double v = arr[i];
            sum += v * v;
        }
        total += sum;
    }
    return total;
}
#elif NAUX_DOT_VARIANT == 2
static inline const char *variant_name() { return "v2_vec_friendly"; }

static double dot_kernel(const double *__restrict__ arr, size_t n, size_t reps) {
    double total = 0.0;
    for (size_t r = 0; r < reps; r++) {
        double sum = 0.0;
#pragma GCC ivdep
        for (size_t i = 0; i < n; i++) {
            double v = arr[i];
            sum += v * v;
        }
        total += sum;
    }
    return total;
}
#elif NAUX_DOT_VARIANT == 3
static inline const char *variant_name() { return "v3_avx2_intrinsics"; }

static double dot_kernel(const double *arr, size_t n, size_t reps) {
    double total = 0.0;
    for (size_t r = 0; r < reps; r++) {
        __m256d vacc = _mm256_setzero_pd();
        size_t i = 0;
        for (; i + 4 <= n; i += 4) {
            __m256d v = _mm256_loadu_pd(arr + i);
            vacc = _mm256_fmadd_pd(v, v, vacc);
        }

        __m128d lo = _mm256_castpd256_pd128(vacc);
        __m128d hi = _mm256_extractf128_pd(vacc, 1);
        __m128d pair = _mm_add_pd(lo, hi);
        __m128d hsum = _mm_hadd_pd(pair, pair);
        double sum = _mm_cvtsd_f64(hsum);

        for (; i < n; i++) {
            double v = arr[i];
            sum += v * v;
        }
        total += sum;
    }
    return total;
}
#else
#error "Unsupported NAUX_DOT_VARIANT (expected 1, 2, or 3)"
#endif

int main(int argc, char **argv) {
    size_t n = argc > 1 ? static_cast<size_t>(std::strtoull(argv[1], nullptr, 10)) : 100000;
    size_t iters = argc > 2 ? static_cast<size_t>(std::strtoull(argv[2], nullptr, 10)) : 200;
    size_t warmup_ms = argc > 3 ? static_cast<size_t>(std::strtoull(argv[3], nullptr, 10)) : 100;
    size_t reps = argc > 4 ? static_cast<size_t>(std::strtoull(argv[4], nullptr, 10)) : 50;
    uint64_t seed = argc > 5 ? std::strtoull(argv[5], nullptr, 10) : 0ull;
    if (iters == 0) {
        iters = 1;
    }

    void *raw = nullptr;
    if (posix_memalign(&raw, 64, sizeof(double) * n) != 0 || raw == nullptr) {
        return 1;
    }
    double *arr = static_cast<double *>(raw);

    std::vector<uint64_t> samples(iters);

    uint64_t warmup_end = now_ns() + warmup_ms * 1000000ull;
    while (now_ns() < warmup_end) {
        fill_input(arr, n, seed);
        g_sink += dot_kernel(arr, n, reps);
    }

    for (size_t it = 0; it < iters; it++) {
        fill_input(arr, n, seed);
        uint64_t start = now_ns();
        g_sink += dot_kernel(arr, n, reps);
        uint64_t end = now_ns();
        samples[it] = end - start;
    }

    std::sort(samples.begin(), samples.end());
    uint64_t median = samples[iters / 2];
    uint64_t p95 = samples[(iters * 95) / 100];
    double ops = median > 0 ? (1e9 / static_cast<double>(median)) : 0.0;

    std::printf(
        "[CPP BENCH] dot_product variant=%s median=%" PRIu64
        " ns/op (%.0f ops/sec), p95=%" PRIu64
        " ns/op | n=%zu iters=%zu warmup=%zums reps=%zu seed=%" PRIu64 "\n",
        variant_name(),
        median,
        ops,
        p95,
        n,
        iters,
        warmup_ms,
        reps,
        seed);

    std::free(raw);
    return 0;
}
