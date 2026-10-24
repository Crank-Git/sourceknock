/* state_test.c - unit tests for the pure state machine. */
#include "test.h"
#include "state.h"

static struct in_addr ip(unsigned a, unsigned b, unsigned c, unsigned d)
{
    struct in_addr x;
    x.s_addr = (a << 24) | (b << 16) | (c << 8) | d;
    return x;
}

static int triggered = 0;
static struct in_addr triggered_ip;

static void on_complete(kn_ctx_t *ctx, int family, const void *ip, void *arg)
{
    (void)ctx; (void)family; (void)arg;
    triggered++;
    triggered_ip = *(const struct in_addr *)ip;
}

static void test_success_sequence(void)
{
    uint16_t ports[] = {7000, 8000, 9000};
    knock_sequence_t seq = { ports, 3 };
    kn_ctx_t *ctx = kn_create(&seq, 10.0);
    kn_set_complete(ctx, on_complete, NULL);
    triggered = 0;

    struct in_addr a = ip(10, 0, 0, 1);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 0.0), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 8000, 1.0), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 9000, 2.0), KNOCK_TRIGGER);
    CHECK_EQ_INT(triggered, 1);
    CHECK_EQ_INT(triggered_ip.s_addr, a.s_addr);

    /* after trigger it resets; a fresh knock must start over */
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 8000, 3.0), KNOCK_IGNORE);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 3.1), KNOCK_PROGRESS);

    /* different client is independent */
    struct in_addr b = ip(10, 0, 0, 2);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &b, 7000, 3.2), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &b, 8000, 3.3), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &b, 9000, 3.4), KNOCK_TRIGGER);
    CHECK_EQ_INT(triggered, 2);

    kn_free(ctx);
}

static void test_wrong_port_resets(void)
{
    uint16_t ports[] = {7000, 8000, 9000};
    knock_sequence_t seq = { ports, 3 };
    kn_ctx_t *ctx = kn_create(&seq, 10.0);
    kn_set_complete(ctx, on_complete, NULL);
    triggered = 0;

    struct in_addr a = ip(10, 0, 0, 1);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 0.0), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 9999, 1.0), KNOCK_RESET);   /* wrong */
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 1.1), KNOCK_PROGRESS); /* restart */
    CHECK_EQ_INT(triggered, 0);

    kn_free(ctx);
}

static void test_window_timeout(void)
{
    uint16_t ports[] = {7000, 8000};
    knock_sequence_t seq = { ports, 2 };
    kn_ctx_t *ctx = kn_create(&seq, 5.0);
    kn_set_complete(ctx, on_complete, NULL);
    triggered = 0;

    struct in_addr a = ip(10, 0, 0, 1);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 0.0), KNOCK_PROGRESS);
    /* too late -> reset, then this packet is ignored (not a seq[0]) */
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 8000, 6.0), KNOCK_IGNORE);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 6.1), KNOCK_PROGRESS);

    kn_free(ctx);
}

static void test_ignores_first_wrong(void)
{
    uint16_t ports[] = {7000, 8000};
    knock_sequence_t seq = { ports, 2 };
    kn_ctx_t *ctx = kn_create(&seq, 10.0);
    struct in_addr a = ip(10, 0, 0, 1);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 1234, 0.0), KNOCK_IGNORE);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 0.1), KNOCK_PROGRESS);
    kn_free(ctx);
}

static void test_find(void)
{
    uint16_t ports[] = {7000, 8000};
    knock_sequence_t seq = { ports, 2 };
    kn_ctx_t *ctx = kn_create(&seq, 10.0);
    struct in_addr a = ip(10, 0, 0, 1);
    CHECK(kn_find(ctx, AF_INET, &a) == NULL);
    kn_feed(ctx, AF_INET, &a, 7000, 0.0);
    kn_client_t *c = kn_find(ctx, AF_INET, &a);
    CHECK(c != NULL);
    CHECK_EQ_INT(c->index, 1);
    kn_free(ctx);
}

static void test_ipv6_keyed(void)
{
    uint16_t ports[] = {7000, 8000};
    knock_sequence_t seq = { ports, 2 };
    kn_ctx_t *ctx = kn_create(&seq, 10.0);
    struct in6_addr a6;
    memset(&a6, 0, sizeof(a6));
    a6.s6_addr[0] = 0xfe; a6.s6_addr[1] = 0x80;
    a6.s6_addr[15] = 1;
    CHECK_EQ_INT(kn_feed(ctx, AF_INET6, &a6, 7000, 0.0), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET6, &a6, 8000, 1.0), KNOCK_TRIGGER);
    kn_free(ctx);
}

int main(void)
{
    printf("== state machine tests ==\n");
    TEST_RUN(test_success_sequence);
    TEST_RUN(test_wrong_port_resets);
    TEST_RUN(test_window_timeout);
    TEST_RUN(test_ignores_first_wrong);
    TEST_RUN(test_find);
    TEST_RUN(test_ipv6_keyed);
    TEST_SUMMARY();
}
