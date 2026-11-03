/* state_test.c - unit tests for the pure state machine. */
#include "state.h"
#include "test.h"

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
    (void)ctx;
    (void)family;
    (void)arg;
    triggered++;
    triggered_ip = *(const struct in_addr *)ip;
}

static void test_success_sequence(void)
{
    uint16_t ports[] = {7000, 8000, 9000};
    knock_sequence_t seq = {ports, 3};
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
    knock_sequence_t seq = {ports, 3};
    kn_ctx_t *ctx = kn_create(&seq, 10.0);
    kn_set_complete(ctx, on_complete, NULL);
    triggered = 0;

    struct in_addr a = ip(10, 0, 0, 1);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 0.0), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 9999, 1.0), KNOCK_RESET); /* wrong */
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 1.1),
                 KNOCK_PROGRESS); /* restart */
    CHECK_EQ_INT(triggered, 0);

    kn_free(ctx);
}

static void test_window_timeout(void)
{
    uint16_t ports[] = {7000, 8000};
    knock_sequence_t seq = {ports, 2};
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
    knock_sequence_t seq = {ports, 2};
    kn_ctx_t *ctx = kn_create(&seq, 10.0);
    struct in_addr a = ip(10, 0, 0, 1);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 1234, 0.0), KNOCK_IGNORE);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 0.1), KNOCK_PROGRESS);
    kn_free(ctx);
}

static void test_find(void)
{
    uint16_t ports[] = {7000, 8000};
    knock_sequence_t seq = {ports, 2};
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
    knock_sequence_t seq = {ports, 2};
    kn_ctx_t *ctx = kn_create(&seq, 10.0);
    struct in6_addr a6;
    memset(&a6, 0, sizeof(a6));
    a6.s6_addr[0] = 0xfe;
    a6.s6_addr[1] = 0x80;
    a6.s6_addr[15] = 1;
    CHECK_EQ_INT(kn_feed(ctx, AF_INET6, &a6, 7000, 0.0), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET6, &a6, 8000, 1.0), KNOCK_TRIGGER);
    kn_free(ctx);
}

/* ---- issue #35: bounded, noise-proof client state ---- */

static int n_trig = 0;
static void count_trigger(kn_ctx_t *ctx, int family, const void *ip, void *arg)
{
    (void)ctx;
    (void)family;
    (void)ip;
    (void)arg;
    n_trig++;
}

/* Packets that aren't seq[0] from unknown clients must create no state. This
 * used to leave one permanent entry per source IP. */
static void test_noise_creates_no_state(void)
{
    uint16_t ports[] = {7000, 8000, 9000};
    knock_sequence_t seq = {ports, 3};
    kn_ctx_t *ctx = kn_create(&seq, 5.0);
    for (uint32_t i = 0; i < 100000; i++)
    {
        struct in_addr a;
        a.s_addr = 0x0a000000u + i;
        CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, (uint16_t)(443 + i % 7), 0.0),
                     KNOCK_IGNORE);
    }
    CHECK_EQ_INT(kn_count(ctx), 0);

    struct in6_addr a6;
    memset(&a6, 0, sizeof(a6));
    for (uint32_t i = 0; i < 20000; i++)
    {
        memcpy(&a6.s6_addr[12], &i, sizeof(i));
        kn_feed(ctx, AF_INET6, &a6, 8000, 0.0); /* seq[1], not seq[0] */
    }
    CHECK_EQ_INT(kn_count(ctx), 0);
    kn_free(ctx);
}

/* Completed and reset clients are removed, not kept as idle entries. */
static void test_entries_removed_on_trigger_and_reset(void)
{
    uint16_t ports[] = {7000, 8000, 9000};
    knock_sequence_t seq = {ports, 3};
    kn_ctx_t *ctx = kn_create(&seq, 5.0);
    struct in_addr a = ip(10, 0, 0, 1), b = ip(10, 0, 0, 2);

    kn_feed(ctx, AF_INET, &a, 7000, 0.0);
    kn_feed(ctx, AF_INET, &b, 7000, 0.0);
    CHECK_EQ_INT(kn_count(ctx), 2);
    kn_feed(ctx, AF_INET, &a, 8000, 0.1);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 9000, 0.2), KNOCK_TRIGGER);
    CHECK_EQ_INT(kn_count(ctx), 1);
    CHECK(kn_find(ctx, AF_INET, &a) == NULL);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &b, 1234, 0.3), KNOCK_RESET);
    CHECK_EQ_INT(kn_count(ctx), 0);
    kn_free(ctx);
}

/* Timed-out entries are evicted, both lazily (when the client shows up again)
 * and when someone else starts a knock. */
static void test_timeout_eviction(void)
{
    uint16_t ports[] = {7000, 8000, 9000};
    knock_sequence_t seq = {ports, 3};
    kn_ctx_t *ctx = kn_create(&seq, 5.0);
    for (uint32_t i = 0; i < 100; i++)
    {
        struct in_addr a;
        a.s_addr = 0x0a000000u + i;
        kn_feed(ctx, AF_INET, &a, 7000, (double)i * 0.01);
    }
    CHECK_EQ_INT(kn_count(ctx), 100);

    /* t=10: all 100 have expired; a new knock sweeps them. */
    struct in_addr n = ip(10, 9, 9, 9);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &n, 7000, 10.0), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_count(ctx), 1);

    /* lazy: the expired client's next packet sees no progress */
    struct in_addr a0;
    a0.s_addr = 0x0a000000u;
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a0, 8000, 10.1), KNOCK_IGNORE);
    kn_free(ctx);
}

/* At the bound, a new knock evicts the OLDEST in-progress one; the table
 * never grows past max_clients. */
static void test_bound_evicts_oldest(void)
{
    uint16_t ports[] = {7000, 8000, 9000};
    knock_sequence_t seq = {ports, 3};
    kn_ctx_t *ctx = kn_create_bounded(&seq, 60.0, 4);
    kn_set_complete(ctx, count_trigger, NULL);
    n_trig = 0;
    struct in_addr c[6];
    for (int i = 0; i < 6; i++)
    {
        c[i] = ip(10, 0, 1, (unsigned)i + 1);
        CHECK_EQ_INT(kn_feed(ctx, AF_INET, &c[i], 7000, (double)i),
                     KNOCK_PROGRESS);
        CHECK(kn_count(ctx) <= 4);
    }
    CHECK_EQ_INT(kn_count(ctx), 4);
    CHECK(kn_find(ctx, AF_INET, &c[0]) == NULL); /* evicted */
    CHECK(kn_find(ctx, AF_INET, &c[1]) == NULL); /* evicted */
    for (int i = 2; i < 6; i++)
        CHECK(kn_find(ctx, AF_INET, &c[i]) != NULL);

    /* evicted clients have to start over; survivors still complete */
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &c[0], 8000, 7.0), KNOCK_IGNORE);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &c[5], 8000, 7.0), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &c[5], 9000, 7.1), KNOCK_TRIGGER);
    CHECK_EQ_INT(n_trig, 1);

    /* a freed slot is reused without evicting anyone */
    CHECK_EQ_INT(kn_count(ctx), 3);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &c[0], 7000, 8.0), KNOCK_PROGRESS);
    for (int i = 2; i < 5; i++)
        CHECK(kn_find(ctx, AF_INET, &c[i]) != NULL);
    kn_free(ctx);
}

/* Spoofed seq[0] floods keep the table at its bound, and a real knock that
 * completes faster than the flood can fill the table still triggers. */
static void test_flood_stays_bounded(void)
{
    uint16_t ports[] = {7000, 8000, 9000};
    knock_sequence_t seq = {ports, 3};
    kn_ctx_t *ctx = kn_create_bounded(&seq, 5.0, 1024);
    kn_set_complete(ctx, count_trigger, NULL);
    n_trig = 0;
    struct in_addr me = ip(192, 168, 1, 10);
    double t = 0.0;
    for (uint32_t i = 0; i < 200000; i++)
    {
        struct in_addr a;
        a.s_addr = 0x0b000000u + i;
        kn_feed(ctx, AF_INET, &a, 7000, t);
        if (i == 100000)
            kn_feed(ctx, AF_INET, &me, 7000, t);
        if (i == 100500)
            kn_feed(ctx, AF_INET, &me, 8000, t);
        if (i == 101000)
            CHECK_EQ_INT(kn_feed(ctx, AF_INET, &me, 9000, t), KNOCK_TRIGGER);
        t += 0.00001;
        if (kn_count(ctx) > 1024)
        {
            CHECK(0);
            break;
        }
    }
    CHECK_EQ_INT(kn_count(ctx), 1024);
    CHECK_EQ_INT(n_trig, 1);
    kn_free(ctx);
}

/* With the table full, hash chains stay short (lookups don't degrade to a
 * scan of every tracked client). */
static void test_hash_chains_short(void)
{
    uint16_t ports[] = {7000, 8000};
    knock_sequence_t seq = {ports, 2};
    kn_ctx_t *ctx = kn_create(&seq, 60.0);
    for (uint32_t i = 0; i < KN_DEFAULT_MAX_CLIENTS; i++)
    {
        struct in_addr a;
        a.s_addr = 0x0c000000u + i;
        kn_feed(ctx, AF_INET, &a, 7000, 0.0);
    }
    CHECK_EQ_INT(kn_count(ctx), KN_DEFAULT_MAX_CLIENTS);
    size_t longest = 0;
    for (size_t b = 0; b < ctx->n_buckets; b++)
    {
        size_t len = 0;
        for (int i = ctx->buckets[b]; i >= 0; i = ctx->slots[i].hnext)
            len++;
        if (len > longest)
            longest = len;
    }
    CHECK(longest <= 12);
    kn_free(ctx);
}

/* Removing entries from the middle of hash chains and the age list keeps
 * every other entry reachable. */
static void test_interleaved_removal(void)
{
    uint16_t ports[] = {7000, 8000};
    knock_sequence_t seq = {ports, 2};
    kn_ctx_t *ctx = kn_create_bounded(&seq, 60.0, 64);
    kn_set_complete(ctx, count_trigger, NULL);
    n_trig = 0;
    struct in_addr a[64];
    for (int i = 0; i < 64; i++)
    {
        a[i] = ip(10, 1, 0, (unsigned)i);
        kn_feed(ctx, AF_INET, &a[i], 7000, 0.0);
    }
    for (int i = 0; i < 64; i += 2)
        CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a[i], 1, 1.0), KNOCK_RESET);
    CHECK_EQ_INT(kn_count(ctx), 32);
    for (int i = 1; i < 64; i += 2)
        CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a[i], 8000, 2.0), KNOCK_TRIGGER);
    CHECK_EQ_INT(n_trig, 32);
    CHECK_EQ_INT(kn_count(ctx), 0);
    /* the freed table is fully reusable */
    for (int i = 0; i < 64; i++)
        CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a[i], 7000, 3.0), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_count(ctx), 64);
    kn_free(ctx);
}

/* A one-port sequence triggers on that port. The old code went to KNOCKING
 * and then read seq.ports[1], past the end of the sequence. */
static void test_single_port_sequence(void)
{
    uint16_t ports[] = {7000};
    knock_sequence_t seq = {ports, 1};
    kn_ctx_t *ctx = kn_create(&seq, 5.0);
    kn_set_complete(ctx, count_trigger, NULL);
    n_trig = 0;
    struct in_addr a = ip(10, 0, 0, 1);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 1234, 0.0), KNOCK_IGNORE);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 0.1), KNOCK_TRIGGER);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 0.2), KNOCK_TRIGGER);
    CHECK_EQ_INT(n_trig, 2);
    CHECK_EQ_INT(kn_count(ctx), 0);
    kn_free(ctx);
}

/* Differential test: random traffic from a small client pool, compared step
 * by step against a naive unbounded reference model of the same rules. */
typedef struct
{
    size_t index; /* 0 = idle */
    double start;
} ref_client_t;

static kn_result_t ref_feed(ref_client_t *c, const uint16_t *seq, size_t len,
                            double window, uint16_t sport, double now)
{
    if (c->index && now - c->start > window)
        c->index = 0;
    if (!c->index)
    {
        if (sport != seq[0])
            return KNOCK_IGNORE;
        if (len == 1)
            return KNOCK_TRIGGER;
        c->index = 1;
        c->start = now;
        return KNOCK_PROGRESS;
    }
    if (sport != seq[c->index])
    {
        for (size_t k = 0; k < c->index; k++)
            if (sport == seq[k])
                return KNOCK_IGNORE;
        c->index = 0;
        return KNOCK_RESET;
    }
    if (++c->index >= len)
    {
        c->index = 0;
        return KNOCK_TRIGGER;
    }
    return KNOCK_PROGRESS;
}

static void test_differential_vs_reference(void)
{
    uint16_t ports[] = {7000, 8000, 9000, 7000};
    knock_sequence_t seq = {ports, 4};
    enum
    {
        POOL = 40
    };
    kn_ctx_t *ctx = kn_create_bounded(&seq, 2.0, POOL);
    ref_client_t ref[POOL];
    memset(ref, 0, sizeof(ref));
    uint16_t choices[] = {7000, 8000, 9000, 1234, 22};
    uint32_t rng = 12345;
    double now = 0.0;
    int mismatches = 0;
    for (int step = 0; step < 200000; step++)
    {
        rng = rng * 1103515245u + 12345u;
        int who = (int)((rng >> 8) % POOL);
        uint16_t sport = choices[(rng >> 20) % 5];
        now += (double)((rng >> 4) % 100) / 1000.0;
        struct in_addr a = ip(172, 16, 0, (unsigned)who);
        kn_result_t got = kn_feed(ctx, AF_INET, &a, sport, now);
        kn_result_t want = ref_feed(&ref[who], ports, 4, 2.0, sport, now);
        if (got != want)
            mismatches++;
    }
    CHECK_EQ_INT(mismatches, 0);
    kn_free(ctx);
}

/* ---- issue #36: a retransmitted knock doesn't reset progress ---- */
static void test_retransmit_ignored(void)
{
    uint16_t ports[] = {7000, 8000, 9000};
    knock_sequence_t seq = {ports, 3};
    kn_ctx_t *ctx = kn_create(&seq, 10.0);
    kn_set_complete(ctx, count_trigger, NULL);
    n_trig = 0;
    struct in_addr a = ip(10, 0, 0, 1);

    /* TCP connect() knock: each SYN is resent ~1s later */
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 0.0), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 1.0), KNOCK_IGNORE);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 8000, 1.2), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 8000, 2.2), KNOCK_IGNORE);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 8000, 2.3), KNOCK_IGNORE);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 9000, 2.4), KNOCK_TRIGGER);
    CHECK_EQ_INT(n_trig, 1);

    /* retransmits of OLDER steps land after later ones (kernels resend
     * SYNs every ~1s): also ignored */
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 5.0), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 6.0), KNOCK_IGNORE);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 8000, 6.3), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 7.0), KNOCK_IGNORE);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 8000, 7.3), KNOCK_IGNORE);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 9000, 7.6), KNOCK_TRIGGER);
    CHECK_EQ_INT(n_trig, 2);

    /* any port that is not a step already matched still resets */
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 10.0), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 9000, 10.1), KNOCK_RESET);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 7000, 11.0), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(ctx, AF_INET, &a, 1234, 11.1), KNOCK_RESET);
    CHECK_EQ_INT(n_trig, 2);

    /* a sequence that reuses a port still advances: the expected port is
     * matched before the retransmit check */
    uint16_t p3[] = {7000, 7000, 8000};
    knock_sequence_t s3 = {p3, 3};
    kn_ctx_t *c3 = kn_create(&s3, 10.0);
    CHECK_EQ_INT(kn_feed(c3, AF_INET, &a, 7000, 0.0), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(c3, AF_INET, &a, 7000, 0.1), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(c3, AF_INET, &a, 7000, 0.2), KNOCK_IGNORE);
    CHECK_EQ_INT(kn_feed(c3, AF_INET, &a, 8000, 0.3), KNOCK_TRIGGER);
    kn_free(c3);

    /* a non-adjacent repeat in the sequence itself still works */
    uint16_t p2[] = {7000, 8000, 7000};
    knock_sequence_t s2 = {p2, 3};
    kn_ctx_t *c2 = kn_create(&s2, 10.0);
    CHECK_EQ_INT(kn_feed(c2, AF_INET, &a, 7000, 0.0), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(c2, AF_INET, &a, 8000, 0.1), KNOCK_PROGRESS);
    CHECK_EQ_INT(kn_feed(c2, AF_INET, &a, 7000, 0.2), KNOCK_TRIGGER);
    kn_free(c2);
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
    TEST_RUN(test_noise_creates_no_state);
    TEST_RUN(test_entries_removed_on_trigger_and_reset);
    TEST_RUN(test_timeout_eviction);
    TEST_RUN(test_bound_evicts_oldest);
    TEST_RUN(test_flood_stays_bounded);
    TEST_RUN(test_hash_chains_short);
    TEST_RUN(test_interleaved_removal);
    TEST_RUN(test_single_port_sequence);
    TEST_RUN(test_differential_vs_reference);
    TEST_RUN(test_retransmit_ignored);
    TEST_SUMMARY();
}
