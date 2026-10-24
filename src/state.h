/*
 * sourceknock - port-knocking via SOURCE ports.
 *
 * state.h - the pure knock-sequence state machine.
 *
 * This file contains NO socket / OS networking code. It is pure logic so it
 * can be unit-tested on any platform (including macOS). The capture and reward
 * layers (Linux) simply feed packets in and react to triggers.
 */
#ifndef SOURCEKNOCK_STATE_H
#define SOURCEKNOCK_STATE_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

/* Ordered list of source ports that make up the secret knock. */
typedef struct {
    uint16_t *ports;   /* len entries */
    size_t    len;
} knock_sequence_t;

typedef enum {
    KNOCK_IDLE = 0,    /* no progress on this client */
    KNOCK_KNOCKING,    /* partway through the sequence */
    KNOCK_COMPLETE     /* sequence finished (trigger fired) */
} knock_state_t;

/* What happened when a packet was fed into the machine. */
typedef enum {
    KNOCK_IGNORE = 0,  /* packet did not advance or complete the knock */
    KNOCK_PROGRESS,    /* advanced one step */
    KNOCK_TRIGGER,     /* completed the sequence -> open the port */
    KNOCK_RESET        /* wrong port / timed out -> progress wiped */
} kn_result_t;

typedef struct kn_ctx kn_ctx_t;
/* Per-client progress. `family` (AF_INET/AF_INET6) selects which member of
 * `addr` is valid; clients are keyed by (family, address). */
typedef struct {
    int  family;
    union { struct in_addr v4; struct in6_addr v6; } addr;
    size_t index;
    knock_state_t state;
    double start_time;
} kn_client_t;

/* Called when a client completes the sequence. `ip` points at a struct in_addr
 * (family==AF_INET) or struct in6_addr (family==AF_INET6). */
typedef void (*kn_complete_fn)(kn_ctx_t *ctx, int family, const void *ip,
                               void *arg);

struct kn_ctx {
    knock_sequence_t seq;          /* the secret sequence */
    double           window;       /* seconds: whole sequence must finish in this */

    kn_client_t    *clients;       /* per-client progress, keyed by IP */
    size_t          n_clients;
    size_t          cap_clients;

    kn_complete_fn  on_complete;   /* optional reward hook */
    void           *complete_arg;
};

/* kn_client_t is fully defined above. */

/* ---- lifecycle ---- */
kn_ctx_t *kn_create(const knock_sequence_t *seq, double window);
void      kn_free(kn_ctx_t *ctx);

/* Install / replace the reward callback. */
void kn_set_complete(kn_ctx_t *ctx, kn_complete_fn fn, void *arg);

/* ---- the core loop, unit-testable ---- */
/* Feed one observed packet. `now` is the timestamp (epoch seconds). `ip` is a
 * struct in_addr (family==AF_INET) or struct in6_addr (family==AF_INET6). */
kn_result_t kn_feed(kn_ctx_t *ctx, int family, const void *ip,
                    uint16_t sport, double now);

/* Look up a client's progress (NULL if none / idle). */
kn_client_t *kn_find(kn_ctx_t *ctx, int family, const void *ip);

#endif /* SOURCEKNOCK_STATE_H */
