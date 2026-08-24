#define NAUX_S4_KERNEL_NAME "branch-mix"
#include "baseline.h"

int main(int argc, char **argv) {
    size_t n = 0;
    size_t reps = 0;
    if (!naux_s4_dataset(argc, argv, &n, &reps)) {
        return NAUX_S4_EXIT_USAGE;
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
    free(values);
    return naux_s4_emit(n, reps, total) ? 0 : NAUX_S4_EXIT_RUNTIME;
}
