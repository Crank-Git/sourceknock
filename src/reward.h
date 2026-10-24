/*
 * reward.h - open the hidden service port for a knocked client.
 *
 * Implemented with nftables (netfilter userspace CLI, not a separate daemon).
 * We manage a self-contained table that drops the service port by default and
 * temporarily accepts it for IPs in an "allowed" set.
 *
 *   table inet sourceknock {
 *     set allowed_v4 { type ipv4_addr; flags timeout size 256; }
 *     set allowed_v6 { type ipv6_addr; flags timeout size 256; }
 *     chain service {
 *       type filter hook input priority 0; policy accept (other ports untouched)
 *       ip saddr @allowed_v4 <proto> dport <port> accept
 *       ip6 saddr @allowed_v6 <proto> dport <port> accept
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
    char        set_v4[64];   /* allowed IPv4 set */
    char        set_v6[64];   /* allowed IPv6 set */
    uint16_t    port;
    proto_t     proto;
    double      fallback_ttl;   /* safety max open time (close_on_connect) */
    int         initialized;
} reward_t;

/* Create table/set/chain if missing. Idempotent. Returns 0 on success.
 * `table` is the full nft table name (e.g. "inet sourceknock_ssh"); callers
 * must give each trigger a distinct name so multiple triggers don't clobber
 * each other's rules. */
int reward_init(reward_t *r, const char *table, uint16_t port, proto_t proto,
                double fallback_ttl);

/* Open the port for `ip`. `family` is AF_INET or AF_INET6 and `ip` points at
 * the matching address struct. For fixed_ttl modes the caller passes a
 * timeout; pass <=0 for "no timeout" (close_on_connect). Returns 0. */
int reward_open(reward_t *r, int family, const void *ip, double timeout);

/* Close the port for `ip` (remove from the family's allowed set). Returns 0. */
int reward_close(reward_t *r, int family, const void *ip);

/* Remove every element from both allowed sets (used on shutdown/reinit). */
int reward_flush(reward_t *r);

#endif /* SOURCEKNOCK_REWARD_H */
