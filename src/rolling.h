// sourceknock - Developed by acidvegas in C (https://github.com/acidvegas)
// src/rolling.h

/*
 * rolling.h - match time-based (totp.h) knocks, each step's knock once.
 *
 * Runs one knock state machine for each of the previous, current and next
 * time steps (accepting about +-30s of clock difference between client and
 * server) and rolls them forward as time passes. A step's sequence opens the
 * port once: a repeat of it (a replayed knock) is refused, from any address,
 * until that step has expired. Pure: the caller passes the current step.
 */
#ifndef SOURCEKNOCK_ROLLING_H
#define SOURCEKNOCK_ROLLING_H

#include "state.h"
#include "totp.h"

#define ROLLING_SLOTS 3 /* steps base-1, base, base+1 */

/* Called when a step's knock completes for the first time. */
typedef void (*rolling_fn)(int family, const void *ip, void *arg);

typedef struct
{
    unsigned char key[TOTP_KEY_MAX];
    size_t keylen;
    const char *label; /* TOTP_LABEL_* */
    double window;
    long base; /* step of ctx[1] */
    kn_ctx_t *ctx[ROLLING_SLOTS];
    int used[ROLLING_SLOTS];
    int fired; /* slot completed by the packet being fed, or -1 */
    rolling_fn on_complete;
    void *arg;
} rolling_t;

/* Set up for time step `step`. Returns 0, or -1 (out of memory). */
int rolling_init(rolling_t *r, const unsigned char *key, size_t keylen,
                 const char *label, double window, long step, rolling_fn fn,
                 void *arg);

/* Feed one packet's source port at time step `step`. Returns KNOCK_TRIGGER
 * when a not yet used step's knock completed (on_complete was called),
 * KNOCK_PROGRESS / KNOCK_RESET as kn_feed() does, else KNOCK_IGNORE. Sets
 * *replay to 1 when the knock completed but its step was already used. */
kn_result_t rolling_feed(rolling_t *r, long step, int family, const void *ip,
                         uint16_t sport, double ts, int *replay);

/* Carry `from`'s used steps over to `to` (both rolled to the same step), so a
 * config reload doesn't reopen a step that was already used. */
void rolling_carry_used(rolling_t *to, const rolling_t *from);

void rolling_free(rolling_t *r);

#endif /* SOURCEKNOCK_ROLLING_H */
