/*
 * capture.h - AF_PACKET raw-socket capture (Linux only).
 *
 * Delivers parsed packets to a callback. Everything platform-specific lives
 * here so the state machine stays testable on any OS.
 */
#ifndef SOURCEKNOCK_CAPTURE_H
#define SOURCEKNOCK_CAPTURE_H

#include "packet.h"
#include <signal.h>

/* Called for every parsed TCP/UDP packet. `iface` is the interface it arrived
 * on; `ts` is packet arrival time. */
typedef void (*kn_packet_fn)(const pkt_info_t *pkt, const char *iface,
                             double ts, void *arg);

typedef struct
{
    char interface[64];
    kn_packet_fn on_packet;
    void *arg;
    int fd;              /* AF_PACKET fd, -1 on error */
    unsigned int hatype; /* interface link type (PKT_ARPHRD_*) */
    double last_try;     /* monotonic time of the last open attempt, 0 = none */
} capture_t;

/* Open a raw AF_PACKET socket on `interface`. Returns 0 on success, 1 if the
 * interface doesn't exist yet (capture_run() keeps retrying it), -1 on error,
 * e.g. a link type pkt_parse() can't read knocks from. Requires CAP_NET_RAW
 * (root). */
int capture_open(capture_t *cap, const char *iface, kn_packet_fn fn, void *arg);

/* Read and dispatch packets from the `n` captures until *stop or *wake
 * becomes non-zero (checked at least once a second), then return 0. Wired to
 * the daemon's signal handlers (SIGTERM stops, SIGHUP reloads). Returns -1 on
 * a poll error. */
int capture_run(capture_t *caps, size_t n, volatile sig_atomic_t *stop,
                volatile sig_atomic_t *wake);

/* Close the socket. */
void capture_close(capture_t *cap);

#endif /* SOURCEKNOCK_CAPTURE_H */
