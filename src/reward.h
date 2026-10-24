/*
 * reward.h - open the hidden service port for a knocked client.
 *
 * Implemented with nftables (netfilter userspace CLI, not a separate daemon).
 * We manage a self-contained table that drops the service port by default and
 * temporarily accepts it for IPs in an "allowed" set.
 *
 *   table inet sourceknock {
 *     set allowed { type in_addr; flags timeout size 256; }
 *     chain service {
 *       type filter hook input priority 0; policy accept (other ports untouched)
 *       ip saddr @allowed-set <proto> dport <port> accept
 *       <proto> dport <port> drop (port closed by default for everyone else)
 *     }
 *   }
 */
#ifndef SOURCEKNOCK_REWARD_H
#define SOURCEKNOCK_REWARD_H

#include <stdint.h>
#include <netinet/in.h>
#include "packet.h"

typedef struct {
    char        table[64];
    char        chain[64];
    char        set[64];
    uint16_t    port;
    proto_t     proto;
    double      fallback_ttl;   /* safety max open time (close_on_connect) */
    int         initialized;
} reward_t;

/* Create table/set/chain if missing. Idempotent. Returns 0 on success. */
int reward_init(reward_t *r, uint16_t port, proto_t proto,
                double fallback_ttl);

/* Open the port for `ip`. For fixed_ttl modes the caller passes a timeout;
 * pass <=0 for "no timeout" (close_on_connect). Returns 0 on success. */
int reward_open(reward_t *r, const struct in_addr *ip, double timeout);

/* Close the port for `ip` (remove from allowed set). Returns 0 on success. */
int reward_close(reward_t *r, const struct in_addr *ip);

/* Remove every element from the allowed set (used on shutdown/reinit). */
int reward_flush(reward_t *r);

#endif /* SOURCEKNOCK_REWARD_H */
