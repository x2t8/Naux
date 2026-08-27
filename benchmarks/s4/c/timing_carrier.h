#ifndef NAUX_S4_TIMING_CARRIER_H
#define NAUX_S4_TIMING_CARRIER_H

#include <limits.h>
#include <stdint.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error "the S4 C timing carrier requires Linux x86-64"
#endif

#ifndef NAUX_S4_KERNEL_ORDINAL
#error "NAUX_S4_KERNEL_ORDINAL must be defined before timing_carrier.h"
#endif

#ifndef NAUX_S4_ORACLE
#error "NAUX_S4_ORACLE must be defined before timing_carrier.h"
#endif

enum {
    NAUX_S4_CLOCK_MONOTONIC_RAW = 4,
    NAUX_S4_SYS_CLOCK_GETTIME = 228,
    NAUX_S4_TIMING_RECORD_BYTES = 56,
};

struct naux_s4_timestamp {
    int64_t seconds;
    int64_t nanoseconds;
};

static inline int naux_s4_clock_read(struct naux_s4_timestamp *timestamp) {
    long result = 0;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"((long)NAUX_S4_SYS_CLOCK_GETTIME),
                       "D"((long)NAUX_S4_CLOCK_MONOTONIC_RAW), "S"(timestamp)
                     : "rcx", "r11", "memory");
    return result == 0;
}

static inline int naux_s4_exact_checksum(double value, int64_t *result) {
    if (result == NULL || value < -9223372036854775808.0 ||
        value >= 9223372036854775808.0) {
        return 0;
    }
    const int64_t converted = (int64_t)value;
    if ((double)converted != value) {
        return 0;
    }
    *result = converted;
    return 1;
}

static inline int naux_s4_duration_ns(const struct naux_s4_timestamp *start,
                                      const struct naux_s4_timestamp *end,
                                      uint64_t *duration) {
    if (start == NULL || end == NULL || duration == NULL ||
        start->seconds < 0 || end->seconds < 0 || start->nanoseconds < 0 ||
        start->nanoseconds >= 1000000000 || end->nanoseconds < 0 ||
        end->nanoseconds >= 1000000000) {
        return 0;
    }

    int64_t seconds = end->seconds - start->seconds;
    int64_t nanoseconds = end->nanoseconds - start->nanoseconds;
    if (seconds < 0) {
        return 0;
    }
    if (nanoseconds < 0) {
        if (seconds == 0) {
            return 0;
        }
        seconds -= 1;
        nanoseconds += 1000000000;
    }
    if ((uint64_t)seconds > (UINT64_MAX - (uint64_t)nanoseconds) / UINT64_C(1000000000)) {
        return 0;
    }
    const uint64_t elapsed = (uint64_t)seconds * UINT64_C(1000000000) +
                             (uint64_t)nanoseconds;
    if (elapsed == 0) {
        return 0;
    }
    *duration = elapsed;
    return 1;
}

static inline void naux_s4_put_u64_le(unsigned char *output, uint64_t value) {
    for (unsigned int index = 0; index < 8; index++) {
        output[index] = (unsigned char)(value >> (index * 8));
    }
}

static inline int naux_s4_write_timing_record(size_t n, size_t reps,
                                              int64_t checksum,
                                              uint64_t duration) {
    static const unsigned char magic[8] = {'N', 'A', 'U', 'X', '7', 'B', '0', '1'};
    unsigned char record[NAUX_S4_TIMING_RECORD_BYTES] = {0};
    for (unsigned int index = 0; index < 8; index++) {
        record[index] = magic[index];
    }
    naux_s4_put_u64_le(record + 8, (uint64_t)NAUX_S4_KERNEL_ORDINAL);
    naux_s4_put_u64_le(record + 16, (uint64_t)checksum);
    naux_s4_put_u64_le(record + 24, (uint64_t)reps);
    naux_s4_put_u64_le(record + 32, (uint64_t)n);
#if defined(NAUX_S4_SPECIALIZED)
    naux_s4_put_u64_le(record + 40, UINT64_C(3));
#else
    naux_s4_put_u64_le(record + 40, UINT64_C(2));
#endif
    naux_s4_put_u64_le(record + 48, duration);
    return write(STDOUT_FILENO, record, sizeof(record)) == (ssize_t)sizeof(record);
}

#endif
