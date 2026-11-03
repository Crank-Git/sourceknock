/* state.c - knock-sequence state machine implementation. */
#include "state.h"
#include "packet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* FNV-1a over the seed, family and address bytes. */
static uint32_t client_hash(const kn_ctx_t *ctx, int family, const void *ip)
{
    uint32_t h = 2166136261u ^ ctx->seed;
    h = (h ^ (uint32_t)family) * 16777619u;
    const unsigned char *p = ip;
    for (size_t i = 0; i < pkt_addr_len(family); i++)
        h = (h ^ p[i]) * 16777619u;
    return h;
}

static size_t bucket_of(const kn_ctx_t *ctx, int family, const void *ip)
{
    return client_hash(ctx, family, ip) & (ctx->n_buckets - 1);
}

static int find_slot(const kn_ctx_t *ctx, int family, const void *ip)
{
    for (int i = ctx->buckets[bucket_of(ctx, family, ip)]; i >= 0;
         i = ctx->slots[i].hnext)
    {
        const kn_client_t *c = &ctx->slots[i];
        if (c->family == family &&
            memcmp(&c->addr, ip, pkt_addr_len(family)) == 0)
            return i;
    }
    return -1;
}

/* Unlink slot `i` from its hash chain and the age list, and free it. */
static void remove_slot(kn_ctx_t *ctx, int i)
{
    kn_client_t *c = &ctx->slots[i];

    int *pp = &ctx->buckets[bucket_of(ctx, c->family, &c->addr)];
    while (*pp != i)
        pp = &ctx->slots[*pp].hnext;
    *pp = c->hnext;

    if (c->older >= 0)
        ctx->slots[c->older].newer = c->newer;
    else
        ctx->oldest = c->newer;
    if (c->newer >= 0)
        ctx->slots[c->newer].older = c->older;
    else
        ctx->newest = c->older;

    memset(c, 0, sizeof(*c));
    c->hnext = ctx->free_head;
    ctx->free_head = i;
    ctx->n_clients--;
}

static int expired(const kn_ctx_t *ctx, const kn_client_t *c, double now)
{
    return (now - c->start_time) > ctx->window;
}

/* Start tracking a client that just sent seq[0]. Never fails: expired entries
 * are swept first, and if the table is still full the oldest in-progress knock
 * is evicted. Entries are appended in time order, so the oldest is the head of
 * the age list. */
static int add_slot(kn_ctx_t *ctx, int family, const void *ip, double now)
{
    while (ctx->oldest >= 0 && expired(ctx, &ctx->slots[ctx->oldest], now))
        remove_slot(ctx, ctx->oldest);
    if (ctx->free_head < 0)
        remove_slot(ctx, ctx->oldest);

    int i = ctx->free_head;
    kn_client_t *c = &ctx->slots[i];
    ctx->free_head = c->hnext;

    memset(c, 0, sizeof(*c));
    c->family = family;
    memcpy(&c->addr, ip, pkt_addr_len(family));
    c->start_time = now;

    size_t b = bucket_of(ctx, family, ip);
    c->hnext = ctx->buckets[b];
    ctx->buckets[b] = i;

    c->older = ctx->newest;
    c->newer = -1;
    if (ctx->newest >= 0)
        ctx->slots[ctx->newest].newer = i;
    else
        ctx->oldest = i;
    ctx->newest = i;

    ctx->n_clients++;
    return i;
}

/* Best-effort per-context seed; falls back to time/address if /dev/urandom is
 * unavailable. */
static uint32_t make_seed(const void *salt)
{
    uint32_t seed = 0;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f)
    {
        if (fread(&seed, sizeof(seed), 1, f) != 1)
            seed = 0;
        fclose(f);
    }
    if (seed == 0)
        seed = (uint32_t)time(NULL) ^ (uint32_t)(uintptr_t)salt;
    return seed;
}

kn_ctx_t *kn_create_bounded(const knock_sequence_t *seq, double window,
                            size_t max_clients)
{
    if (!seq || !seq->ports || seq->len == 0)
    {
        fprintf(stderr, "sourceknock: sequence must be non-empty\n");
        return NULL;
    }
    if (max_clients == 0 || max_clients > (1u << 24))
    {
        fprintf(stderr, "sourceknock: max_clients out of range\n");
        return NULL;
    }

    kn_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    size_t nb = 1;
    while (nb < 2 * max_clients)
        nb <<= 1;

    ctx->seq.ports = malloc(seq->len * sizeof(uint16_t));
    ctx->slots = calloc(max_clients, sizeof(*ctx->slots));
    ctx->buckets = malloc(nb * sizeof(*ctx->buckets));
    if (!ctx->seq.ports || !ctx->slots || !ctx->buckets)
    {
        kn_free(ctx);
        return NULL;
    }
    memcpy(ctx->seq.ports, seq->ports, seq->len * sizeof(uint16_t));
    ctx->seq.len = seq->len;
    ctx->window = window;

    ctx->max_clients = max_clients;
    ctx->n_buckets = nb;
    for (size_t i = 0; i < nb; i++)
        ctx->buckets[i] = -1;
    for (size_t i = 0; i < max_clients; i++)
        ctx->slots[i].hnext = (i + 1 < max_clients) ? (int)(i + 1) : -1;
    ctx->free_head = 0;
    ctx->oldest = ctx->newest = -1;
    ctx->seed = make_seed(ctx);
    return ctx;
}

kn_ctx_t *kn_create(const knock_sequence_t *seq, double window)
{
    return kn_create_bounded(seq, window, KN_DEFAULT_MAX_CLIENTS);
}

void kn_free(kn_ctx_t *ctx)
{
    if (!ctx)
        return;
    free(ctx->seq.ports);
    free(ctx->slots);
    free(ctx->buckets);
    free(ctx);
}

void kn_set_complete(kn_ctx_t *ctx, kn_complete_fn fn, void *arg)
{
    ctx->on_complete = fn;
    ctx->complete_arg = arg;
}

kn_client_t *kn_find(kn_ctx_t *ctx, int family, const void *ip)
{
    int i = find_slot(ctx, family, ip);
    return i >= 0 ? &ctx->slots[i] : NULL;
}

size_t kn_count(const kn_ctx_t *ctx) { return ctx->n_clients; }

kn_result_t kn_feed(kn_ctx_t *ctx, int family, const void *ip, uint16_t sport,
                    double now)
{
    int i = find_slot(ctx, family, ip);

    /* Timed out? The whole sequence must finish within the window. */
    if (i >= 0 && expired(ctx, &ctx->slots[i], now))
    {
        remove_slot(ctx, i);
        i = -1;
    }

    if (i < 0)
    {
        /* Not mid-knock: only the first knock port creates any state, so
         * ordinary traffic and spoofed noise cost nothing. */
        if (sport != ctx->seq.ports[0])
            return KNOCK_IGNORE;
        if (ctx->seq.len == 1)
        {
            if (ctx->on_complete)
                ctx->on_complete(ctx, family, ip, ctx->complete_arg);
            return KNOCK_TRIGGER;
        }
        i = add_slot(ctx, family, ip, now);
        ctx->slots[i].index = 1;
        ctx->slots[i].state = KNOCK_KNOCKING;
        return KNOCK_PROGRESS;
    }

    kn_client_t *c = &ctx->slots[i];

    if (sport != ctx->seq.ports[c->index])
    {
        /* A repeat of a step already matched is a retransmission (a TCP
         * client's kernel resends each SYN every second or so, and those land
         * after later steps), not a wrong knock: ignore it. The expected
         * port is checked first, so sequences that reuse a port still
         * advance. */
        for (size_t k = 0; k < c->index; k++)
            if (sport == ctx->seq.ports[k])
                return KNOCK_IGNORE;

        /* Any other port: strict ordering, start over. */
        remove_slot(ctx, i);
        return KNOCK_RESET;
    }

    c->index++;
    if (c->index >= ctx->seq.len)
    {
        c->state = KNOCK_COMPLETE;
        if (ctx->on_complete)
            ctx->on_complete(ctx, family, ip, ctx->complete_arg);
        /* Done: drop the entry so the next knock starts fresh. */
        remove_slot(ctx, i);
        return KNOCK_TRIGGER;
    }

    return KNOCK_PROGRESS;
}
