/*
 * capture.h - AF_PACKET raw-socket capture (Linux only).
 *
 * Delivers parsed packets to a callback. Everything platform-specific lives
 * here so the state machine stays testable on any OS.
 */
#ifndef SOURCEKNOCK_CAPTURE_H
#define SOURCEKNOCK_CAPTURE_H

#include "packet.h"

/* Called for every parsed TCP/UDP packet. `ts` is packet arrival time. */
typedef void (*kn_packet_fn)(const pkt_info_t *pkt, double ts, void *arg);

typedef struct {
    char        interface[64];
    kn_packet_fn on_packet;
    void       *arg;
    int         fd;              /* AF_PACKET fd, -1 on error */
} capture_t;

/* Open a raw AF_PACKET socket on `interface`. Returns 0 on success.
 * Requires CAP_NET_RAW (root). */
int capture_open(capture_t *cap, const char *iface,
                 kn_packet_fn fn, void *arg);

/* Read and dispatch packets until capture_stop() is called (blocks). */
int capture_run(capture_t *cap);

/* Close the socket. */
void capture_close(capture_t *cap);

#endif /* SOURCEKNOCK_CAPTURE_H */
