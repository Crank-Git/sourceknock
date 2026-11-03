/*
 * sourceknock-knock - send a source-port knock.
 *
 *   sourceknock-knock [-p PORT] [-d MS] [-s ADDR] [-4|-6] HOST SEQUENCE
 *
 * Sends one UDP datagram per port in SEQUENCE (e.g. 7000,8000,9000), in
 * order, each bound to that port as its SOURCE port, to HOST:PORT. The
 * sourceknock daemon reads the knock from the source ports; the destination
 * port only matters if the trigger sets `knock_port` (pass it with -p).
 *
 * Portable POSIX (Linux, macOS, BSD); no dependencies.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_SEQ 64

static void usage(FILE *f)
{
    fprintf(f,
            "usage: sourceknock-knock [-p PORT] [-d MS] [-s ADDR] [-4|-6] "
            "HOST SEQUENCE\n"
            "\n"
            "Send one UDP datagram per port in SEQUENCE (comma-separated, in\n"
            "order), each from that SOURCE port, to HOST.\n"
            "\n"
            "  -p PORT  destination port (default 9; use the trigger's\n"
            "           knock_port if it sets one)\n"
            "  -d MS    delay between knocks in milliseconds (default 50)\n"
            "  -s ADDR  local address to send from (default: any)\n"
            "  -4, -6   force IPv4 / IPv6\n"
            "  -h       show this help\n");
}

/* Parse "a,b,c" into ports. Returns the count, or -1 (message printed). */
static int parse_seq(const char *arg, unsigned short *out)
{
    int n = 0;
    const char *p = arg;
    while (*p)
    {
        char *end;
        errno = 0;
        long v = strtol(p, &end, 10);
        if (end == p || errno || v < 1 || v > 65535 ||
            (*end != ',' && *end != '\0'))
        {
            fprintf(stderr, "sourceknock-knock: invalid port in sequence: %s\n",
                    p);
            return -1;
        }
        if (n == MAX_SEQ)
        {
            fprintf(stderr, "sourceknock-knock: sequence longer than %d\n",
                    MAX_SEQ);
            return -1;
        }
        out[n++] = (unsigned short)v;
        p = (*end == ',') ? end + 1 : end;
    }
    if (n == 0)
        fprintf(stderr, "sourceknock-knock: empty sequence\n");
    return n ? n : -1;
}

static int parse_port(const char *s, const char *what)
{
    char *end;
    long v = strtol(s, &end, 10);
    if (*s == '\0' || *end || v < 1 || v > 65535)
    {
        fprintf(stderr, "sourceknock-knock: invalid %s: %s\n", what, s);
        return -1;
    }
    return (int)v;
}

static void set_port(struct sockaddr_storage *ss, unsigned short port)
{
    if (ss->ss_family == AF_INET6)
        ((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
    else
        ((struct sockaddr_in *)ss)->sin_port = htons(port);
}

static socklen_t ss_len(const struct sockaddr_storage *ss)
{
    return ss->ss_family == AF_INET6 ? sizeof(struct sockaddr_in6)
                                     : sizeof(struct sockaddr_in);
}

/* Resolve `host` (numeric or name) for `family` into `out`. */
static int resolve(const char *host, int family, int passive,
                   struct sockaddr_storage *out)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = passive ? AI_PASSIVE : 0;
    int rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0)
    {
        fprintf(stderr, "sourceknock-knock: %s: %s\n", host ? host : "(any)",
                gai_strerror(rc));
        return -1;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    return 0;
}

int main(int argc, char **argv)
{
    int dport = 9, delay_ms = 50, family = AF_UNSPEC;
    const char *src = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "p:d:s:46h")) != -1)
    {
        switch (opt)
        {
        case 'p':
            if ((dport = parse_port(optarg, "port")) < 0)
                return 2;
            break;
        case 'd':
        {
            char *end;
            long v = strtol(optarg, &end, 10);
            if (*optarg == '\0' || *end || v < 0 || v > 60000)
            {
                fprintf(stderr, "sourceknock-knock: invalid delay: %s\n",
                        optarg);
                return 2;
            }
            delay_ms = (int)v;
            break;
        }
        case 's':
            src = optarg;
            break;
        case '4':
            family = AF_INET;
            break;
        case '6':
            family = AF_INET6;
            break;
        case 'h':
            usage(stdout);
            return 0;
        default:
            usage(stderr);
            return 2;
        }
    }
    if (argc - optind != 2)
    {
        usage(stderr);
        return 2;
    }
    const char *host = argv[optind];
    unsigned short seq[MAX_SEQ];
    int n = parse_seq(argv[optind + 1], seq);
    if (n < 0)
        return 2;

    struct sockaddr_storage dst, local;
    if (resolve(host, family, 0, &dst) != 0)
        return 1;
    if (src)
    {
        if (resolve(src, dst.ss_family, 1, &local) != 0)
            return 1;
    }
    else
    {
        memset(&local, 0, sizeof(local));
        local.ss_family = dst.ss_family;
    }
    set_port(&dst, (unsigned short)dport);

    for (int i = 0; i < n; i++)
    {
        int fd = socket(dst.ss_family, SOCK_DGRAM, 0);
        if (fd < 0)
        {
            perror("sourceknock-knock: socket");
            return 1;
        }
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        set_port(&local, seq[i]);
        if (bind(fd, (struct sockaddr *)&local, ss_len(&local)) < 0)
        {
            int e = errno;
            fprintf(
                stderr,
                "sourceknock-knock: cannot send from source port %u: %s%s\n",
                seq[i], strerror(e),
                e == EACCES ? " (ports below 1024 need root)"
                : e == EADDRINUSE
                    ? " (another socket is using that source port)"
                    : "");
            close(fd);
            return 1;
        }
        if (sendto(fd, "k", 1, 0, (struct sockaddr *)&dst, ss_len(&dst)) < 0)
        {
            perror("sourceknock-knock: sendto");
            close(fd);
            return 1;
        }
        close(fd);
        if (i + 1 < n && delay_ms > 0)
        {
            struct timespec ts = {delay_ms / 1000,
                                  (long)(delay_ms % 1000) * 1000000L};
            nanosleep(&ts, NULL);
        }
    }
    return 0;
}
