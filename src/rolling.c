// sourceknock - Developed by acidvegas in C (https://github.com/acidvegas)
// src/rolling.c

/* rolling.c - per-step knock state machines with one use per step. */
#include "rolling.h"

#include <string.h>

/* kn_feed() completion hook: note which slot completed; rolling_feed()
 * decides whether it counts. */
static void slot_done(kn_ctx_t *ctx, int family, const void *ip, void *arg)
{
    (void)family;
    (void)ip;
    rolling_t *r = arg;
    for (int i = 0; i < ROLLING_SLOTS; i++)
        if (r->ctx[i] == ctx)
            r->fired = i;
}

static kn_ctx_t *make_slot(rolling_t *r, long step)
{
    uint16_t ports[TOTP_SEQ_LEN];
    totp_sequence(r->key, r->keylen, r->label, step, ports);
    knock_sequence_t seq = {.ports = ports, .len = TOTP_SEQ_LEN};
    kn_ctx_t *ctx = kn_create(&seq, r->window);
    if (ctx)
        kn_set_complete(ctx, slot_done, r);
    return ctx;
}

int rolling_init(rolling_t *r, const unsigned char *key, size_t keylen,
                 const char *label, double window, long step, rolling_fn fn,
                 void *arg)
{
    memset(r, 0, sizeof(*r));
    memcpy(r->key, key, keylen);
    r->keylen = keylen;
    r->label = label;
    r->window = window;
    r->base = step;
    r->fired = -1;
    r->on_complete = fn;
    r->arg = arg;
    for (int i = 0; i < ROLLING_SLOTS; i++)
    {
        r->ctx[i] = make_slot(r, step - 1 + i);
        if (!r->ctx[i])
        {
            rolling_free(r);
            return -1;
        }
    }
    return 0;
}

/* Move the window to `step`. A one-step advance keeps the overlapping slots
 * (and any knock in progress in them); a bigger jump (clock change) starts
 * over. A slot that can't be created (out of memory) stays empty. */
static void roll_to(rolling_t *r, long step)
{
    if (step == r->base)
        return;
    if (step == r->base + 1)
    {
        kn_free(r->ctx[0]);
        r->ctx[0] = r->ctx[1];
        r->ctx[1] = r->ctx[2];
        r->used[0] = r->used[1];
        r->used[1] = r->used[2];
        r->used[2] = 0;
        r->ctx[2] = make_slot(r, step + 1);
    }
    else
    {
        for (int i = 0; i < ROLLING_SLOTS; i++)
        {
            kn_free(r->ctx[i]);
            r->ctx[i] = make_slot(r, step - 1 + i);
            r->used[i] = 0;
        }
    }
    r->base = step;
}

kn_result_t rolling_feed(rolling_t *r, long step, int family, const void *ip,
                         uint16_t sport, double ts, int *replay)
{
    *replay = 0;
    roll_to(r, step);

    kn_result_t out = KNOCK_IGNORE;
    for (int i = 0; i < ROLLING_SLOTS; i++)
    {
        if (!r->ctx[i])
            continue;
        r->fired = -1;
        kn_result_t res = kn_feed(r->ctx[i], family, ip, sport, ts);
        if (r->fired == i)
        {
            if (r->used[i])
            {
                *replay = 1;
                continue;
            }
            r->used[i] = 1;
            if (r->on_complete)
                r->on_complete(family, ip, r->arg);
            out = KNOCK_TRIGGER;
        }
        else if (res == KNOCK_PROGRESS && out != KNOCK_TRIGGER)
            out = KNOCK_PROGRESS;
        else if (res == KNOCK_RESET && out == KNOCK_IGNORE)
            out = KNOCK_RESET;
    }
    if (out == KNOCK_TRIGGER)
        *replay = 0;
    return out;
}

void rolling_carry_used(rolling_t *to, const rolling_t *from)
{
    for (int i = 0; i < ROLLING_SLOTS; i++)
    {
        long s = from->base - 1 + i;
        long j = s - (to->base - 1);
        if (from->used[i] && j >= 0 && j < ROLLING_SLOTS)
            to->used[j] = 1;
    }
}

void rolling_free(rolling_t *r)
{
    for (int i = 0; i < ROLLING_SLOTS; i++)
    {
        kn_free(r->ctx[i]);
        r->ctx[i] = NULL;
    }
}
