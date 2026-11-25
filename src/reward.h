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
 *       type filter hook input priority 0; policy accept (other ports
 * untouched) ct state established,related accept (open sessions survive the
 * port closing) # one accept (per family) + one drop rule per service port: ip
 * saddr @allowed_v4 <proto> dport <port1> accept ip6 saddr @allowed_v6 <proto>
 * dport <port1> accept iifname "<iface>" <proto> dport <port1> drop (port
 * closed by default for everyone else on the trigger's interface)
 *       ... (repeat for port2, port3, ...) *
 *     }
 *   }
 */
#ifndef SOURCEKNOCK_REWARD_H
#define SOURCEKNOCK_REWARD_H

#include "packet.h"
#include <netinet/in.h>
#include <stdint.h>

typedef struct
{
    char table[64];
    char chain[64];
    char set_v4[64];       /* allowed IPv4 set */
    char set_v6[64];       /* allowed IPv6 set */
    const uint16_t *ports; /* n_ports service ports to open (borrowed) */
    size_t n_ports;
    proto_t proto;
    double fallback_ttl; /* safety max open time (close_on_connect) */
    int initialized;
} reward_t;

/* Write the nft script that programs one trigger's table into `buf`: the
 * table, both sets, the chain and every rule, one command per line. Returns 0,
 * or -1 when `len` is too small (the script is never truncated silently).
 * `reward_init` feeds this script to `nft -f -`, so nft applies it as one
 * transaction. It is public so tests can check the exact text. */
int reward_script(char *buf, size_t len, const char *table, const char *iface,
                  const uint16_t *ports, size_t n_ports, proto_t proto,
                  long max_allowed);

/* Create table/set/chain if missing. Idempotent. Returns 0 on success. nft
 * applies the table in one transaction; if it fails, nothing is programmed,
 * the table is removed again and the call returns -1.
 * `table` is the full nft table name (e.g. "inet sourceknock_ssh"); callers
 * must give each trigger a distinct name so multiple triggers don't clobber
 * each other's rules. The drop rules match only packets arriving on `iface`.
 * Each allowed set holds at most `max_allowed` addresses (re-running it with a
 * new size resizes the sets and keeps their elements). */
int reward_init(reward_t *r, const char *table, const char *iface,
                const uint16_t *ports, size_t n_ports, proto_t proto,
                double fallback_ttl, long max_allowed);

/* Open the port for `ip`. `family` is AF_INET or AF_INET6 and `ip` points at
 * the matching address struct. `timeout` is the kernel-enforced lifetime of the
 * element (duration for fixed_ttl, fallback_ttl for close_on_connect); pass <=0
 * for "no timeout" (permanent). Re-opening an open IP restarts its timeout.
 * Returns 0 on success. */
int reward_open(reward_t *r, int family, const void *ip, double timeout);

/* Close the port for `ip` (remove from the family's allowed set). Returns 0. */
int reward_close(reward_t *r, int family, const void *ip);

/* Remove every element from both allowed sets (used on shutdown/reinit). */
int reward_flush(reward_t *r);

/* Delete the whole table, restoring the host to its pre-daemon state. Used when
 * startup fails after some triggers were already programmed, so the daemon
 * never exits leaving a service port closed with nothing to open it. */
int reward_destroy(reward_t *r);

/* Delete every "inet sourceknock_*" table not named in `keep` (full names, as
 * in reward_t.table). A trigger that was renamed or removed from the config
 * leaves its table behind, still dropping its ports with nothing left to open
 * them. Assumes one daemon per host. Returns 0, or -1 if anything failed. */
int reward_prune_stale(const char *const *keep, size_t n_keep);

#endif /* SOURCEKNOCK_REWARD_H */
