/* bt.h - minimal check macros for stream B's C host tests (prints a summary line; exit code = failures). */
#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int bt_checks, bt_failed;

#define CHECK(cond)                                                                                          \
    do {                                                                                                     \
        bt_checks++;                                                                                         \
        if (!(cond)) {                                                                                       \
            bt_failed++;                                                                                     \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond);                         \
        }                                                                                                    \
    } while (0)

#define CHECK_EQ(a, b)                                                                                       \
    do {                                                                                                     \
        long long a_ = (long long)(a), b_ = (long long)(b);                                                  \
        bt_checks++;                                                                                         \
        if (a_ != b_) {                                                                                      \
            bt_failed++;                                                                                     \
            fprintf(stderr, "%s:%d: CHECK_EQ(%s, %s) failed: %lld != %lld\n", __FILE__, __LINE__, #a, #b, a_, \
                    b_);                                                                                     \
        }                                                                                                    \
    } while (0)

#define CHECK_STR(a, b)                                                                                      \
    do {                                                                                                     \
        const char *a_ = (a), *b_ = (b);                                                                     \
        bt_checks++;                                                                                         \
        if (!a_ || !b_ || strcmp(a_, b_) != 0) {                                                             \
            bt_failed++;                                                                                     \
            fprintf(stderr, "%s:%d: CHECK_STR(%s, %s) failed:\n  got  '%s'\n  want '%s'\n", __FILE__, __LINE__, \
                    #a, #b, a_ ? a_ : "(null)", b_ ? b_ : "(null)");                                         \
        }                                                                                                    \
    } while (0)

#define BT_DONE()                                                                                            \
    (printf("checks=%d failed=%d\n", bt_checks, bt_failed), bt_failed ? 1 : 0)
