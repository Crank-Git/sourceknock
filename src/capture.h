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

/* Called for every parsed TCP/UDP packet. `ts` is packet arrival time. */
typedef void (*kn_packet_fn)(const pkt_info_t *pkt, double ts, void *arg);

typedef struct
{
    char interface[64];
    kn_packet_fn on_packet;
    void *arg;
    int fd;              /* AF_PACKET fd, -1 on error */
    unsigned int hatype; /* interface link type (PKT_ARPHRD_*) */
    /* If non-NULL, capture_run checks *stop before every read (reads time out
     * after 1s) and returns 0 (clean) once it is non-zero. Wired to the
     * daemon's signal handler so SIGINT/SIGTERM shut the daemon down. */
    volatile sig_atomic_t *stop;
} capture_t;

/* Open a raw AF_PACKET socket on `interface`. Returns 0 on success. Fails if
 * the interface's link type is one pkt_parse() can't read knocks from.
 * Requires CAP_NET_RAW (root). */
int capture_open(capture_t *cap, const char *iface, kn_packet_fn fn, void *arg);

/* Read and dispatch packets until *cap->stop becomes non-zero (blocks). */
int capture_run(capture_t *cap);

/* Close the socket. */
void capture_close(capture_t *cap);

#endif /* SOURCEKNOCK_CAPTURE_H */
