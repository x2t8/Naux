#include <algorithm>
#include <cinttypes>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <time.h>
#include <vector>

static volatile double g_sink = 0.0;

enum class Scenario {
    SumDense,
    ListUpdate,
    DotProduct,
    BranchMix,
};

static uint64_t now_ns() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull +
           static_cast<uint64_t>(ts.tv_nsec);
}

static size_t parse_size(const char *value, size_t fallback) {
    if (value == nullptr) {
        return fallback;
    }
    const auto parsed = static_cast<size_t>(std::strtoull(value, nullptr, 10));
    return parsed == 0 ? fallback : parsed;
}

static bool parse_scenario(const char *name, Scenario &scenario) {
    if (std::strcmp(name, "sum_dense") == 0) {
        scenario = Scenario::SumDense;
        return true;
    }
    if (std::strcmp(name, "list_update") == 0) {
        scenario = Scenario::ListUpdate;
        return true;
    }
    if (std::strcmp(name, "dot_product") == 0) {
        scenario = Scenario::DotProduct;
        return true;
    }
    if (std::strcmp(name, "branch_mix") == 0) {
        scenario = Scenario::BranchMix;
        return true;
    }
    return false;
}

static void fill_input(double *arr, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        arr[i] = static_cast<double>(i);
    }
}

static double run_kernel(Scenario scenario, double *arr, size_t n, size_t reps) {
    double total = 0.0;
    switch (scenario) {
    case Scenario::SumDense:
        for (size_t r = 0; r < reps; ++r) {
            double sum = 0.0;
            for (size_t i = 0; i < n; ++i) {
                sum += 0.0;
                sum += 0.0;
                sum += arr[i];
            }
            total += sum;
        }
        break;
    case Scenario::ListUpdate:
        for (size_t r = 0; r < reps; ++r) {
            double sum = 0.0;
            for (size_t i = 0; i < n; ++i) {
                const double value = arr[i];
                sum += value;
                arr[i] = value + 1.0;
            }
            total += sum;
        }
        break;
    case Scenario::DotProduct:
        for (size_t r = 0; r < reps; ++r) {
            double sum = 0.0;
            for (size_t i = 0; i < n; ++i) {
                const double value = arr[i];
                sum += value * value;
            }
            total += sum;
        }
        break;
    case Scenario::BranchMix: {
        double sum = 0.0;
        int64_t state = 0;
        for (size_t r = 0; r < reps; ++r) {
            for (size_t i = 0; i < n; ++i) {
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
    }
    return total;
}

static double cv_pct(const std::vector<uint64_t> &samples) {
    if (samples.size() < 2) {
        return 0.0;
    }
    long double mean = 0.0;
    for (const uint64_t sample : samples) {
        mean += static_cast<long double>(sample);
    }
    mean /= static_cast<long double>(samples.size());
    if (mean == 0.0) {
        return 0.0;
    }
    long double variance = 0.0;
    for (const uint64_t sample : samples) {
        const long double delta = static_cast<long double>(sample) - mean;
        variance += delta * delta;
    }
    variance /= static_cast<long double>(samples.size());
    return std::sqrt(static_cast<double>(variance)) * 100.0 /
           static_cast<double>(mean);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <sum_dense|list_update|dot_product|branch_mix> [n] [iters] [warmup_ms] [reps]\n", argv[0]);
        return 2;
    }

    Scenario scenario = Scenario::SumDense;
    if (!parse_scenario(argv[1], scenario)) {
        std::fprintf(stderr, "unknown scenario: %s\n", argv[1]);
        return 2;
    }

    const size_t n = parse_size(argc > 2 ? argv[2] : nullptr, 100000);
    const size_t iters = parse_size(argc > 3 ? argv[3] : nullptr, 200);
    const size_t warmup_ms = parse_size(argc > 4 ? argv[4] : nullptr, 100);
    const size_t reps = parse_size(argc > 5 ? argv[5] : nullptr, 50);

    std::vector<uint64_t> samples(iters);

    const uint64_t warmup_end = now_ns() + warmup_ms * 1000000ull;
    while (now_ns() < warmup_end) {
        std::vector<double> arr(n);
        fill_input(arr.data(), n);
        g_sink = run_kernel(scenario, arr.data(), n, reps);
    }

    double checksum = 0.0;
    for (size_t iteration = 0; iteration < iters; ++iteration) {
        const uint64_t start = now_ns();
        {
            std::vector<double> arr(n);
            fill_input(arr.data(), n);
            checksum = run_kernel(scenario, arr.data(), n, reps);
            g_sink = checksum;
        }
        samples[iteration] = now_ns() - start;
    }

    const double sample_cv_pct = cv_pct(samples);
    std::sort(samples.begin(), samples.end());
    const uint64_t median = samples[iters / 2];
    const uint64_t p95 = samples[(iters * 95) / 100];
    const double ops = median == 0 ? 0.0 : 1e9 / static_cast<double>(median);

    std::printf(
        "[CPP BENCH] %s median=%" PRIu64
        " ns/op (%.0f ops/sec), p95=%" PRIu64
        " ns/op cv_pct=%.4f | iters=%zu warmup=%zums reps=%zu checksum=%.17g\n",
        argv[1],
        median,
        ops,
        p95,
        sample_cv_pct,
        iters,
        warmup_ms,
        reps,
        checksum);
    return 0;
}
