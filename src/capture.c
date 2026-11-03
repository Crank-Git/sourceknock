/* capture.c - AF_PACKET raw socket capture (Linux). */
/* Must precede every include, or it does not apply to the system headers the
 * local header pulls in. */
#define _POSIX_C_SOURCE 200809L
#include "capture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>

#define AF_PACKET_LINUX                                                        \
    26 /* defined in linux headers; guard for portability                      \
        */

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif

static double now_ts(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int capture_open(capture_t *cap, const char *iface, kn_packet_fn fn, void *arg)
{
    if (!cap || !iface || !fn)
    {
        fprintf(stderr, "capture: null argument\n");
        return -1;
    }
    memset(cap, 0, sizeof(*cap));
    strncpy(cap->interface, iface, sizeof(cap->interface) - 1);
    cap->on_packet = fn;
    cap->arg = arg;
    cap->fd = -1;

    /* Raw socket: see every frame on the wire regardless of dest MAC. */
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0)
    {
        fprintf(stderr, "capture: socket(): %s (need root / CAP_NET_RAW)\n",
                strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
    {
        fprintf(stderr, "capture: cannot find interface '%s': %s\n", iface,
                strerror(errno));
        close(fd);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifr.ifr_ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
    {
        fprintf(stderr, "capture: bind(): %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    /* Wake up at least once a second even on a silent interface, so a stop
     * request that lands between packets is never stuck behind a blocking
     * recvfrom(). */
    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        fprintf(stderr, "capture: SO_RCVTIMEO: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    cap->fd = fd;
    fprintf(stderr, "capture: listening on '%s' (ifindex %d)\n", iface,
            ifr.ifr_ifindex);
    return 0;
}

int capture_run(capture_t *cap)
{
    unsigned char buf[2048];

    while (!(cap->stop && *cap->stop))
    {
        struct sockaddr_ll sll;
        socklen_t sll_len = sizeof(sll);
        ssize_t n = recvfrom(cap->fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&sll, &sll_len);
        if (n < 0)
        {
            /* EINTR: a signal (the loop condition checks for a stop
             * request). EAGAIN: the 1s receive timeout on a quiet
             * interface. */
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            fprintf(stderr, "capture: recvfrom(): %s\n", strerror(errno));
            return -1;
        }

        /* Only frames this host RECEIVES can be a knock. AF_PACKET also
         * hands us every frame the host sends (PACKET_OUTGOING), which would
         * let the server's own traffic drive knock state, and on loopback is
         * the second copy of every frame. */
        if (sll.sll_pkttype == PACKET_OUTGOING)
            continue;

        double now = now_ts();
        pkt_info_t info;
        /* sll_hatype is the ARPHRD_ link-layer type; loopback frames carry
         * a 2-byte protocol prefix, Ethernet does not. */
        unsigned int link = sll.sll_hatype ? sll.sll_hatype : ARPHRD_ETHER;
        if (pkt_parse(buf, (size_t)n, link, &info))
        {
            cap->on_packet(&info, now, cap->arg);
        }
    }
    return 0;
}

void capture_close(capture_t *cap)
{
    if (cap && cap->fd >= 0)
    {
        close(cap->fd);
        cap->fd = -1;
    }
}
