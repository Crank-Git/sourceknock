/*
 * close.h - per-packet trigger decisions (pure, cross-platform).
 *
 * Decides whether a captured packet counts toward a trigger's knock, and
 * whether it should close an armed close_on_connect trigger. No I/O, so it can
 * be unit-tested on any OS.
 */
#ifndef SOURCEKNOCK_CLOSE_H
#define SOURCEKNOCK_CLOSE_H

#include "config.h"
#include "packet.h"
#include "state.h"
#include <stddef.h>
#include <stdint.h>

/* Does a captured frame count toward this trigger's knock (primary and admin
 * sequences)? Never for a TCP segment with ACK set and SYN clear: it belongs
 * to a flow that is already open, and a TCP knock is a SYN. Otherwise always,
 * unless the trigger sets knock_port, in which case only frames sent to that
 * destination port do. */
int knock_counts(const trigger_t *tr, const pkt_info_t *pkt);

/* Is `port` one of the trigger's service ports? */
int port_in_list(const trigger_t *tr, uint16_t port);

/* Decide whether a captured packet should close an armed close_on_connect
 * trigger.
 *
 * Closes only when: the trigger is armed (client in the allowed set), the
 * packet targets one of the service ports, the mode is close_on_connect, and
 * the packet is NOT the arming knock itself. The arming knock must never
 * close the port the instant it opens — for UDP there is no handshake, so the
 * first *subsequent* packet to the service port is what ends access. For TCP
 * only a SYN (a new connection) closes, never a segment of an open session. */
int should_close(const trigger_t *tr, int armed, const pkt_info_t *pkt,
                 kn_result_t r);

#endif /* SOURCEKNOCK_CLOSE_H */
