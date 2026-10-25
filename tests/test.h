/* test.h - absurdly tiny test harness (no dependencies). */
#ifndef SOURCEKNOCK_TEST_H
#define SOURCEKNOCK_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int t_pass = 0;
static int t_fail = 0;

#define CHECK(cond)                                                            \
    do                                                                         \
    {                                                                          \
        if (cond)                                                              \
        {                                                                      \
            t_pass++;                                                          \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            t_fail++;                                                          \
            fprintf(stderr, "  FAIL %s:%d: CHECK(%s)\n", __FILE__, __LINE__,   \
                    #cond);                                                    \
        }                                                                      \
    } while (0)

#define CHECK_EQ_INT(a, b)                                                     \
    do                                                                         \
    {                                                                          \
        long _a = (long)(a), _b = (long)(b);                                   \
        if (_a == _b)                                                          \
        {                                                                      \
            t_pass++;                                                          \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            t_fail++;                                                          \
            fprintf(stderr, "  FAIL %s:%d: %s (%ld) == %s (%ld)\n", __FILE__,  \
                    __LINE__, #a, _a, #b, _b);                                 \
        }                                                                      \
    } while (0)

#define CHECK_EQ_STR(a, b)                                                     \
    do                                                                         \
    {                                                                          \
        const char *_a = (a), *_b = (b);                                       \
        if (_a && _b && strcmp(_a, _b) == 0)                                   \
        {                                                                      \
            t_pass++;                                                          \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            t_fail++;                                                          \
            fprintf(stderr, "  FAIL %s:%d: %s (\"%s\") == %s (\"%s\")\n",      \
                    __FILE__, __LINE__, #a, _a, #b, _b);                       \
        }                                                                      \
    } while (0)

#define TEST_RUN(fn)                                                           \
    do                                                                         \
    {                                                                          \
        printf("[run] %s\n", #fn);                                             \
        fn();                                                                  \
    } while (0)

#define TEST_SUMMARY()                                                         \
    do                                                                         \
    {                                                                          \
        printf("\n%d passed, %d failed\n", t_pass, t_fail);                    \
        return t_fail ? 1 : 0;                                                 \
    } while (0)

#endif /* SOURCEKNOCK_TEST_H */
