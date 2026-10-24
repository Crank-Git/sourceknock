/* state.c - knock-sequence state machine implementation. */
#include "state.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static kn_client_t *find_client(kn_ctx_t *ctx, const struct in_addr *ip)
{
    for (size_t i = 0; i < ctx->n_clients; i++) {
        if (memcmp(&ctx->clients[i].ip, ip, sizeof(struct in_addr)) == 0)
            return &ctx->clients[i];
    }
    return NULL;
}

/* Grow the client table if needed. Returns 0 on success. */
static int ensure_client(kn_ctx_t *ctx, const struct in_addr *ip,
                         kn_client_t **out)
{
    /* Reuse existing? */
    kn_client_t *c = find_client(ctx, ip);
    if (c) {
        *out = c;
        return 0;
    }

    if (ctx->n_clients == ctx->cap_clients) {
        size_t newcap = ctx->cap_clients ? ctx->cap_clients * 2 : 16;
        kn_client_t *nc = realloc(ctx->clients, newcap * sizeof(*nc));
        if (!nc)
            return -1;
        ctx->clients = nc;
        ctx->cap_clients = newcap;
    }
    c = &ctx->clients[ctx->n_clients++];
    memset(c, 0, sizeof(*c));
    c->ip = *ip;
    c->state = KNOCK_IDLE;
    *out = c;
    return 0;
}

kn_ctx_t *kn_create(const knock_sequence_t *seq, double window)
{
    if (!seq || !seq->ports || seq->len == 0) {
        fprintf(stderr, "sourceknock: sequence must be non-empty\n");
        return NULL;
    }

    kn_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->seq.ports = malloc(seq->len * sizeof(uint16_t));
    if (!ctx->seq.ports) {
        free(ctx);
        return NULL;
    }
    memcpy(ctx->seq.ports, seq->ports, seq->len * sizeof(uint16_t));
    ctx->seq.len = seq->len;
    ctx->window = window;
    return ctx;
}

void kn_free(kn_ctx_t *ctx)
{
    if (!ctx)
        return;
    free(ctx->seq.ports);
    free(ctx->clients);
    free(ctx);
}

void kn_set_complete(kn_ctx_t *ctx, kn_complete_fn fn, void *arg)
{
    ctx->on_complete = fn;
    ctx->complete_arg = arg;
}

kn_client_t *kn_find(kn_ctx_t *ctx, const struct in_addr *ip)
{
    kn_client_t *c = find_client(ctx, ip);
    if (c && c->state != KNOCK_IDLE)
        return c;
    return NULL;
}

/* Reset a single client's progress. */
static void client_reset(kn_client_t *c)
{
    c->index = 0;
    c->state = KNOCK_IDLE;
    c->start_time = 0.0;
}

kn_result_t kn_feed(kn_ctx_t *ctx, const struct in_addr *ip,
                    uint16_t sport, double now)
{
    kn_client_t *c;
    if (ensure_client(ctx, ip, &c) != 0)
        return -1;

    /* Timed out? If progress started but the window elapsed, wipe it. */
    if (c->state != KNOCK_IDLE && (now - c->start_time) > ctx->window) {
        client_reset(c);
    }

    if (c->state == KNOCK_IDLE) {
        /* Waiting for the first knock to match seq[0]. */
        if (sport == ctx->seq.ports[0]) {
            c->index = 1;
            c->state = KNOCK_KNOCKING;
            c->start_time = now;
            return KNOCK_PROGRESS;
        }
        return KNOCK_IGNORE;
    }

    /* Currently knocking: strict ordering, no tolerance. */
    if (sport != ctx->seq.ports[c->index]) {
        client_reset(c);
        return KNOCK_RESET;
    }

    c->index++;
    if (c->index >= ctx->seq.len) {
        c->state = KNOCK_COMPLETE;
        if (ctx->on_complete)
            ctx->on_complete(ctx, ip, ctx->complete_arg);
        /* Reset so the next knock starts fresh. */
        client_reset(c);
        return KNOCK_TRIGGER;
    }

    return KNOCK_PROGRESS;
}
