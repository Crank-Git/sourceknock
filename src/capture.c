/* capture.c - AF_PACKET raw socket capture (Linux). */
#include "capture.h"

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>

#define AF_PACKET_LINUX 26   /* defined in linux headers; guard for portability */

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif

static double now_ts(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int capture_open(capture_t *cap, const char *iface,
                 kn_packet_fn fn, void *arg)
{
    if (!cap || !iface || !fn) {
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
    if (fd < 0) {
        fprintf(stderr, "capture: socket(): %s (need root / CAP_NET_RAW)\n",
                strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "capture: cannot find interface '%s': %s\n",
                iface, strerror(errno));
        close(fd);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifr.ifr_ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "capture: bind(): %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    cap->fd = fd;
    fprintf(stderr, "capture: listening on '%s' (ifindex %d)\n",
            iface, ifr.ifr_ifindex);
    return 0;
}

int capture_run(capture_t *cap)
{
    unsigned char buf[2048];

    /* Loopback (and some other) interfaces deliver each frame twice via
     * AF_PACKET. Drop near-duplicate frames seen within the window by
     * fingerprinting frame contents into a small ring buffer. */
    #define DEDUP_SIZE 2048
    #define DEDUP_WINDOW 0.5   /* seconds */
    uint32_t dph[DEDUP_SIZE];
    double   dts[DEDUP_SIZE];
    int      dslot = 0;
    for (int i = 0; i < DEDUP_SIZE; i++) dts[i] = -1e9;

    while (1) {
        struct sockaddr_ll sll;
        socklen_t sll_len = sizeof(sll);
        ssize_t n = recvfrom(cap->fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&sll, &sll_len);
        if (n < 0) {
            if (errno == EINTR) {
                if (cap->stop && *cap->stop)
                    return 0;   /* clean shutdown requested */
                continue;
            }
            fprintf(stderr, "capture: recvfrom(): %s\n", strerror(errno));
            return -1;
        }

        /* Fingerprint the frame (FNV-1a over up to 128 bytes + length). */
        uint32_t h = 2166136261u;
        size_t hn = (size_t)n < 128 ? (size_t)n : 128;
        for (size_t i = 0; i < hn; i++) { h ^= buf[i]; h *= 16777619u; }
        h ^= (uint32_t)n; h *= 16777619u;

        double now = now_ts();
        int dup = 0;
        for (int i = 0; i < DEDUP_SIZE; i++) {
            if (dts[i] > now - DEDUP_WINDOW && dph[i] == h) { dup = 1; break; }
        }
        if (dup)
            continue;   /* second copy of a frame we already processed */
        dph[dslot] = h;
        dts[dslot] = now;
        dslot = (dslot + 1) % DEDUP_SIZE;

        pkt_info_t info;
        /* sll_hatype is the ARPHRD_ link-layer type; loopback frames carry
         * a 2-byte protocol prefix, Ethernet does not. */
        unsigned int link = sll.sll_hatype ? sll.sll_hatype : ARPHRD_ETHER;
        if (pkt_parse(buf, (size_t)n, link, &info)) {
            cap->on_packet(&info, now, cap->arg);
        }
    }
    return 0;
}

void capture_close(capture_t *cap)
{
    if (cap && cap->fd >= 0) {
        close(cap->fd);
        cap->fd = -1;
    }
}
