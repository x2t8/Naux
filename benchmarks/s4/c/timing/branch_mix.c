#define NAUX_S4_KERNEL_NAME "branch-mix"
#define NAUX_S4_KERNEL_ORDINAL 2
#define NAUX_S4_ORACLE (-INT64_C(69189632))
#include "../baseline.h"
#include "../timing_carrier.h"

int main(int argc, char **argv) {
    size_t n = 0;
    size_t reps = 0;
    (void)&naux_s4_emit;
    if (!naux_s4_dataset(argc, argv, &n, &reps)) {
        return NAUX_S4_EXIT_USAGE;
    }

    struct naux_s4_timestamp start = {0, 0};
    if (!naux_s4_clock_read(&start)) {
        fputs("error\tclock-start-failed\n", stderr);
        return NAUX_S4_EXIT_RUNTIME;
    }

    double *values = naux_s4_allocate(n);
    if (values == NULL) {
        fputs("error\tallocation-failed\n", stderr);
        return NAUX_S4_EXIT_RUNTIME;
    }

    for (size_t i = 0; i < n; i++) {
        values[i] = (double)i;
    }

    double total = 0.0;
    int64_t state = 0;
    for (size_t repeat = 0; repeat < reps; repeat++) {
        for (size_t i = 0; i < n; i++) {
            state += 17;
            if (state >= 97) {
                state -= 97;
            }
            if (state < 48) {
                total += values[i];
            } else {
                total -= values[i];
            }
        }
    }

    naux_s4_sink = total;
    int64_t checksum = 0;
    if (!naux_s4_exact_checksum(total, &checksum) || checksum != NAUX_S4_ORACLE) {
        free(values);
        fputs("error\tchecksum-mismatch\n", stderr);
        return NAUX_S4_EXIT_RUNTIME;
    }
    free(values);

    struct naux_s4_timestamp end = {0, 0};
    if (!naux_s4_clock_read(&end)) {
        fputs("error\tclock-end-failed\n", stderr);
        return NAUX_S4_EXIT_RUNTIME;
    }
    uint64_t duration = 0;
    if (!naux_s4_duration_ns(&start, &end, &duration) ||
        !naux_s4_write_timing_record(n, reps, checksum, duration)) {
        return NAUX_S4_EXIT_RUNTIME;
    }
    return 0;
}
