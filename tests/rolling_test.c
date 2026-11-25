/* rolling_test.c - time-step windows and one use per step. */
#include <arpa/inet.h>
#include <string.h>

#include "rolling.h"
#include "test.h"

static const unsigned char KEY[] = "rolling-test-key-0123456789";
#define KEYLEN (sizeof(KEY) - 1)

static int fired;
static void on_ok(int family, const void *ip, void *arg)
{
    (void)family;
    (void)ip;
    (void)arg;
    fired++;
}

static struct in_addr ip4(const char *s)
{
    struct in_addr a;
    inet_pton(AF_INET, s, &a);
    return a;
}

/* Send step `seq_step`'s knock from `ip` while the server is at `now`. */
static kn_result_t knock(rolling_t *r, long now, long seq_step, const char *ip,
                         int *replay)
{
    uint16_t p[TOTP_SEQ_LEN];
    totp_sequence(KEY, KEYLEN, TOTP_LABEL_KNOCK, seq_step, p);
    struct in_addr a = ip4(ip);
    kn_result_t res = KNOCK_IGNORE;
    for (int i = 0; i < TOTP_SEQ_LEN; i++)
        res = rolling_feed(r, now, AF_INET, &a, p[i], 1.0 + 0.05 * i, replay);
    return res;
}

static void test_opens_once_per_step(void)
{
    rolling_t r;
    int replay;
    fired = 0;
    CHECK_EQ_INT(
        rolling_init(&r, KEY, KEYLEN, TOTP_LABEL_KNOCK, 5, 100, on_ok, NULL),
        0);
    CHECK_EQ_INT(knock(&r, 100, 100, "10.0.0.1", &replay), KNOCK_TRIGGER);
    CHECK_EQ_INT(fired, 1);
    CHECK_EQ_INT(replay, 0);
    /* the same knock again, from the same or another address: refused */
    CHECK_EQ_INT(knock(&r, 100, 100, "10.0.0.1", &replay), KNOCK_IGNORE);
    CHECK_EQ_INT(replay, 1);
    CHECK_EQ_INT(knock(&r, 100, 100, "10.0.0.2", &replay), KNOCK_IGNORE);
    CHECK_EQ_INT(replay, 1);
    CHECK_EQ_INT(fired, 1);
    /* the next step's knock is new */
    CHECK_EQ_INT(knock(&r, 101, 101, "10.0.0.1", &replay), KNOCK_TRIGGER);
    CHECK_EQ_INT(fired, 2);
    rolling_free(&r);
}

/* A client clock up to one step behind or ahead still works; two steps off
 * doesn't. */
static void test_clock_skew(void)
{
    rolling_t r;
    int replay;
    fired = 0;
    rolling_init(&r, KEY, KEYLEN, TOTP_LABEL_KNOCK, 5, 500, on_ok, NULL);
    CHECK_EQ_INT(knock(&r, 500, 499, "10.0.0.1", &replay), KNOCK_TRIGGER);
    CHECK_EQ_INT(knock(&r, 500, 501, "10.0.0.1", &replay), KNOCK_TRIGGER);
    CHECK(knock(&r, 500, 502, "10.0.0.1", &replay) != KNOCK_TRIGGER);
    CHECK(knock(&r, 500, 498, "10.0.0.1", &replay) != KNOCK_TRIGGER);
    CHECK_EQ_INT(fired, 2);
    rolling_free(&r);
}

/* A used step stays refused while it is in the window, and stops matching
 * at all once it has rolled out. */
static void test_used_survives_rolling(void)
{
    rolling_t r;
    int replay;
    fired = 0;
    rolling_init(&r, KEY, KEYLEN, TOTP_LABEL_KNOCK, 5, 700, on_ok, NULL);
    CHECK_EQ_INT(knock(&r, 700, 700, "10.0.0.1", &replay), KNOCK_TRIGGER);
    CHECK_EQ_INT(knock(&r, 701, 700, "10.0.0.9", &replay), KNOCK_IGNORE);
    CHECK_EQ_INT(replay, 1);
    CHECK(knock(&r, 702, 700, "10.0.0.9", &replay) != KNOCK_TRIGGER);
    CHECK_EQ_INT(replay, 0); /* no longer matches at all */
    CHECK_EQ_INT(fired, 1);
    /* a clock jump starts over cleanly */
    CHECK_EQ_INT(knock(&r, 9000, 9000, "10.0.0.1", &replay), KNOCK_TRIGGER);
    rolling_free(&r);
}

/* A knock that straddles a step boundary completes. */
static void test_knock_across_boundary(void)
{
    rolling_t r;
    int replay;
    fired = 0;
    rolling_init(&r, KEY, KEYLEN, TOTP_LABEL_KNOCK, 5, 800, on_ok, NULL);
    uint16_t p[TOTP_SEQ_LEN];
    totp_sequence(KEY, KEYLEN, TOTP_LABEL_KNOCK, 800, p);
    struct in_addr a = ip4("10.0.0.1");
    CHECK_EQ_INT(rolling_feed(&r, 800, AF_INET, &a, p[0], 1.0, &replay),
                 KNOCK_PROGRESS);
    CHECK_EQ_INT(rolling_feed(&r, 800, AF_INET, &a, p[1], 1.1, &replay),
                 KNOCK_PROGRESS);
    CHECK_EQ_INT(rolling_feed(&r, 801, AF_INET, &a, p[2], 1.2, &replay),
                 KNOCK_PROGRESS);
    CHECK_EQ_INT(rolling_feed(&r, 801, AF_INET, &a, p[3], 1.3, &replay),
                 KNOCK_TRIGGER);
    CHECK_EQ_INT(fired, 1);
    rolling_free(&r);
}

/* Revoke and knock sequences are independent; wrong keys never open. */
static void test_labels_and_keys(void)
{
    rolling_t r;
    int replay;
    fired = 0;
    rolling_init(&r, KEY, KEYLEN, TOTP_LABEL_REVOKE, 5, 900, on_ok, NULL);
    CHECK(knock(&r, 900, 900, "10.0.0.1", &replay) != KNOCK_TRIGGER);
    rolling_free(&r);
    rolling_init(&r, (const unsigned char *)"another-key-0123456789", 22,
                 TOTP_LABEL_KNOCK, 5, 900, on_ok, NULL);
    CHECK(knock(&r, 900, 900, "10.0.0.1", &replay) != KNOCK_TRIGGER);
    CHECK_EQ_INT(fired, 0);
    rolling_free(&r);
}

/* A reload carries used steps over, so it can't reopen a used step. */
static void test_carry_used(void)
{
    rolling_t a, b;
    int replay;
    fired = 0;
    rolling_init(&a, KEY, KEYLEN, TOTP_LABEL_KNOCK, 5, 1000, on_ok, NULL);
    CHECK_EQ_INT(knock(&a, 1000, 1000, "10.0.0.1", &replay), KNOCK_TRIGGER);
    rolling_init(&b, KEY, KEYLEN, TOTP_LABEL_KNOCK, 5, 1000, on_ok, NULL);
    rolling_carry_used(&b, &a);
    CHECK_EQ_INT(knock(&b, 1000, 1000, "10.0.0.1", &replay), KNOCK_IGNORE);
    CHECK_EQ_INT(replay, 1);
    CHECK_EQ_INT(knock(&b, 1000, 1001, "10.0.0.1", &replay), KNOCK_TRIGGER);
    rolling_free(&a);
    rolling_free(&b);
}

int main(void)
{
    printf("== rolling (time-based knock) tests ==\n");
    TEST_RUN(test_opens_once_per_step);
    TEST_RUN(test_clock_skew);
    TEST_RUN(test_used_survives_rolling);
    TEST_RUN(test_knock_across_boundary);
    TEST_RUN(test_labels_and_keys);
    TEST_RUN(test_carry_used);
    TEST_SUMMARY();
}
