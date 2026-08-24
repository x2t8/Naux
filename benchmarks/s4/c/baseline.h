#ifndef NAUX_S4_BASELINE_H
#define NAUX_S4_BASELINE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef NAUX_S4_KERNEL_NAME
#error "NAUX_S4_KERNEL_NAME must be defined before baseline.h"
#endif

#if defined(NAUX_S4_SPECIALIZED)
#if !defined(NAUX_S4_N) || !defined(NAUX_S4_REPS)
#error "the specialized role requires NAUX_S4_N and NAUX_S4_REPS"
#endif
#define NAUX_S4_ROLE_NAME "c-specialized"
#else
#if defined(NAUX_S4_N) || defined(NAUX_S4_REPS)
#error "the generic role must not receive static dataset definitions"
#endif
#define NAUX_S4_ROLE_NAME "c-generic"
#endif

enum {
    NAUX_S4_EXIT_USAGE = 64,
    NAUX_S4_EXIT_RUNTIME = 70,
};

static volatile double naux_s4_sink = 0.0;

#if !defined(NAUX_S4_SPECIALIZED)
static int naux_s4_parse_positive_size(const char *text, size_t *value) {
    if (text == NULL || value == NULL || text[0] < '1' || text[0] > '9') {
        return 0;
    }

    size_t parsed = 0;
    for (const unsigned char *cursor = (const unsigned char *)text; *cursor != 0; cursor++) {
        if (*cursor < (unsigned char)'0' || *cursor > (unsigned char)'9') {
            return 0;
        }
        const size_t digit = (size_t)(*cursor - (unsigned char)'0');
        if (parsed > (SIZE_MAX - digit) / 10) {
            return 0;
        }
        parsed = parsed * 10 + digit;
    }

    if (parsed == 0) {
        return 0;
    }
    *value = parsed;
    return 1;
}
#endif

static int naux_s4_dataset(int argc, char **argv, size_t *n, size_t *reps) {
#if defined(NAUX_S4_SPECIALIZED)
    (void)argv;
    if (argc != 1) {
        fputs("error\tspecialized-role-accepts-no-dataset-arguments\n", stderr);
        return 0;
    }
    *n = (size_t)NAUX_S4_N;
    *reps = (size_t)NAUX_S4_REPS;
    if (*n == 0 || *reps == 0) {
        fputs("error\tinvalid-static-dataset\n", stderr);
        return 0;
    }
#else
    if (argc != 3 || !naux_s4_parse_positive_size(argv[1], n) ||
        !naux_s4_parse_positive_size(argv[2], reps)) {
        fputs("error\texpected-positive-decimal-n-and-reps\n", stderr);
        return 0;
    }
#endif
    return 1;
}

static double *naux_s4_allocate(size_t n) {
    if (n > SIZE_MAX / sizeof(double)) {
        return NULL;
    }
    return (double *)malloc(n * sizeof(double));
}

static int naux_s4_emit(size_t n, size_t reps, double checksum) {
    naux_s4_sink = checksum;
    if (printf("NAUX-S4-BASELINE\t1\t%s\t%s\t%zu\t%zu\t%.0f\n",
               NAUX_S4_KERNEL_NAME, NAUX_S4_ROLE_NAME, n, reps, checksum) < 0) {
        return 0;
    }
    return fflush(stdout) == 0;
}

#endif
