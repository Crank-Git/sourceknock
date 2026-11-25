/* capture.c - AF_PACKET raw socket capture (Linux). */
/* Must precede every include, or it does not apply to the system headers the
 * local header pulls in. */
#define _POSIX_C_SOURCE 200809L
#include "capture.h"
#include "retry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif

static double now_ts(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Open a raw socket bound to `iface` and report its link type. Returns the
 * fd, or -1 (with a reason on stderr unless `reopen`). With `reopen` (getting
 * back an interface that was lost) it also fails while the link is down: a
 * socket bound to a down link only reports ENETDOWN again. */
static int open_socket(const char *iface, unsigned int *hatype_out, int reopen)
{
    int verbose = !reopen;
    /* Raw socket: see every frame on the wire regardless of dest MAC. */
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0)
    {
        if (verbose)
            fprintf(stderr, "capture: socket(): %s (need root / CAP_NET_RAW)\n",
                    strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
    {
        if (verbose)
            fprintf(stderr, "capture: cannot find interface '%s': %s\n", iface,
                    strerror(errno));
        close(fd);
        return -1;
    }

    /* ifr_ifindex and ifr_hwaddr share a union: keep the index before the
     * next ioctl overwrites it. */
    int ifindex = ifr.ifr_ifindex;

    if (reopen &&
        (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0 || !(ifr.ifr_flags & IFF_UP)))
    {
        close(fd);
        return -1;
    }

    /* Link type decides where the IP header starts in each frame. Refuse
     * anything we can't parse rather than run and silently never match. */
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
    {
        if (verbose)
            fprintf(stderr, "capture: cannot get link type of '%s': %s\n",
                    iface, strerror(errno));
        close(fd);
        return -1;
    }
    unsigned int hatype = ifr.ifr_hwaddr.sa_family;
    if (pkt_link_kind(hatype) == PKT_LINK_UNSUPPORTED)
    {
        if (verbose)
            fprintf(stderr,
                    "capture: interface '%s' has link type %u (%s), which "
                    "sourceknock can't read knocks from\n",
                    iface, hatype, pkt_link_name(hatype));
        close(fd);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
    {
        if (verbose)
            fprintf(stderr, "capture: bind(): %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    if (verbose)
        fprintf(stderr, "capture: listening on '%s' (ifindex %d, link %s)\n",
                iface, ifindex, pkt_link_name(hatype));
    *hatype_out = hatype;
    return fd;
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
    /* A missing interface (e.g. a VPN not up yet) must not stop the daemon:
     * refusing to start would leave a previous run's tables closing the ports
     * on every other interface too. capture_run() picks it up once it exists;
     * its own ports stay closed meanwhile. */
    if (if_nametoindex(iface) == 0)
    {
        fprintf(stderr,
                "capture: interface '%s' does not exist (yet); retrying every "
                "second\n",
                iface);
        cap->last_try = now_ts();
        return 1;
    }
    cap->fd = open_socket(iface, &cap->hatype, 0);
    return cap->fd < 0 ? -1 : 0;
}

int capture_run(capture_t *caps, size_t n, volatile sig_atomic_t *stop,
                volatile sig_atomic_t *wake)
{
    unsigned char buf[2048];
    struct pollfd *pfd = calloc(n, sizeof(*pfd));
    if (!pfd)
    {
        fprintf(stderr, "capture: out of memory\n");
        return -1;
    }
    for (size_t i = 0; i < n; i++)
    {
        pfd[i].fd = caps[i].fd;
        pfd[i].events = POLLIN;
    }

    int rc = 0;
    while (!*stop && !*wake && rc == 0)
    {
        /* Wake up at least once a second even on silent interfaces, so a stop
         * request that lands between packets is never stuck in poll(). */
        if (poll(pfd, n, 1000) < 0)
        {
            if (errno == EINTR)
                continue; /* a signal: the loop condition checks for stop */
            fprintf(stderr, "capture: poll(): %s\n", strerror(errno));
            rc = -1;
            break;
        }
        for (size_t i = 0; i < n; i++)
        {
            /* An interface that went down or away: try to reopen it (it may
             * be back, possibly with a new ifindex). Its table keeps the
             * port closed meanwhile; the other interfaces keep working. */
            if (caps[i].fd < 0)
            {
                /* poll() wakes on every packet of the other interfaces, so
                 * throttle here: a reopen is a few syscalls and must not run
                 * once per packet. */
                double now = now_ts();
                if (!capture_retry_due(caps[i].last_try, now))
                    continue;
                caps[i].last_try = now;
                caps[i].fd = open_socket(caps[i].interface, &caps[i].hatype, 1);
                if (caps[i].fd >= 0)
                    fprintf(stderr, "capture: '%s' is up, listening\n",
                            caps[i].interface);
                pfd[i].fd = caps[i].fd;
                continue;
            }
            if (!pfd[i].revents)
                continue;
            struct sockaddr_ll sll;
            socklen_t sll_len = sizeof(sll);
            ssize_t len = recvfrom(caps[i].fd, buf, sizeof(buf), MSG_DONTWAIT,
                                   (struct sockaddr *)&sll, &sll_len);
            if (len < 0)
            {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                    continue;
                /* e.g. ENETDOWN: the link went down or the device was
                 * deleted. Drop the socket and reopen it later; exiting would
                 * stop knocks on every interface. */
                fprintf(stderr,
                        "capture: lost '%s' (%s); retrying every second\n",
                        caps[i].interface, strerror(errno));
                close(caps[i].fd);
                caps[i].fd = -1;
                caps[i].last_try = now_ts();
                pfd[i].fd = -1; /* poll() ignores negative fds */
                continue;
            }

            /* Only frames this host RECEIVES can be a knock. AF_PACKET also
             * hands us every frame the host sends (PACKET_OUTGOING), which
             * would let the server's own traffic drive knock state, and on
             * loopback is the second copy of every frame. */
            if (sll.sll_pkttype == PACKET_OUTGOING)
                continue;

            double now = now_ts();
            pkt_info_t info;
            if (pkt_parse(buf, (size_t)len, caps[i].hatype, &info))
                caps[i].on_packet(&info, caps[i].interface, now, caps[i].arg);
        }
    }
    free(pfd);
    return rc;
}

void capture_close(capture_t *cap)
{
    if (cap && cap->fd >= 0)
    {
        close(cap->fd);
        cap->fd = -1;
    }
}
