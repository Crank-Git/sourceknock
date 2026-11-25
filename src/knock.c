/*
 * sourceknock-knock - send a source-port knock.
 *
 *   sourceknock-knock [-p PORT] [-d MS] [-s ADDR] [-4|-6] HOST SEQUENCE
 *   sourceknock-knock -K KEYFILE [-r] [options] HOST
 *
 * Sends one UDP datagram per port in SEQUENCE (e.g. 7000,8000,9000), in
 * order, each bound to that port as its SOURCE port, to HOST:PORT. The
 * sourceknock daemon reads the knock from the source ports; the destination
 * port only matters if the trigger sets `knock_port` (pass it with -p).
 *
 * With -K the sequence is derived from the trigger's secret_file and the
 * current time (totp.h), like a 2FA code; -r sends the revoke knock instead.
 *
 * Portable POSIX (Linux, macOS, BSD); no dependencies.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "totp.h"

#define MAX_SEQ 64

static void usage(FILE *f)
{
    fprintf(f,
            "usage: sourceknock-knock [-p PORT] [-d MS] [-s ADDR] [-4|-6] "
            "HOST SEQUENCE\n"
            "       sourceknock-knock -K KEYFILE [-r] [options] HOST\n"
            "\n"
            "Send one UDP datagram per port in SEQUENCE (comma-separated, in\n"
            "order), each from that SOURCE port, to HOST.\n"
            "\n"
            "  -K FILE  derive the sequence from this secret and the current\n"
            "           time (for a trigger with secret_file); no SEQUENCE\n"
            "  -r       with -K: send the revoke knock (removes your address)\n"
            "  -p PORT  destination port (default 9; use the trigger's\n"
            "           knock_port if it sets one)\n"
            "  -d MS    delay between knocks in milliseconds (default 50)\n"
            "  -s ADDR  local address to send from (default: any)\n"
            "  -4, -6   force IPv4 / IPv6\n"
            "  -h       show this help\n");
}

/*
 * Step record for -K. The daemon accepts each step once, so the client
 * remembers the last step it sent for a (key file, host, label) and moves
 * to the next step when the current one is used. The record is a decimal
 * step in `<state dir>/<hex SHA-256 of realpath "\n" host [ "\n" label ]>`.
 */
static int state_path(const char *keyfile, const char *host, const char *label,
                      char *out, size_t cap)
{
    const char *base = getenv("XDG_STATE_HOME"), *home = getenv("HOME");
    char dir[PATH_MAX], real[PATH_MAX], in[2 * PATH_MAX + 64];
    if (base && *base)
        snprintf(dir, sizeof(dir), "%s/sourceknock", base);
    else if (home && *home)
        snprintf(dir, sizeof(dir), "%s/.local/state/sourceknock", home);
    else
        return -1;
    if (!realpath(keyfile, real))
        snprintf(real, sizeof(real), "%s", keyfile);
    /* The revoke record is separate so a revoke never uses up a knock step. */
    int len = snprintf(in, sizeof(in), "%s\n%s%s%s", real, host,
                       strcmp(label, TOTP_LABEL_KNOCK) ? "\n" : "",
                       strcmp(label, TOTP_LABEL_KNOCK) ? label : "");
    if (len < 0 || (size_t)len >= sizeof(in))
        return -1;
    unsigned char h[32];
    totp_sha256(in, (size_t)len, h);
    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex + 2 * i, 3, "%02x", h[i]);
    len = snprintf(out, cap, "%s/%s", dir, hex);
    return (len < 0 || (size_t)len >= cap) ? -1 : 0;
}

/* mkdir -p with mode 0700. */
static int make_dirs(const char *path)
{
    char buf[PATH_MAX];
    snprintf(buf, sizeof(buf), "%s", path);
    for (char *p = buf + 1; *p; p++)
    {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0700) < 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    return (mkdir(buf, 0700) < 0 && errno != EEXIST) ? -1 : 0;
}

/* Read the last step sent into *last (-1 when none). Returns -1 on error. */
static int state_read(const char *path, long *last)
{
    *last = -1;
    FILE *f = fopen(path, "r");
    if (!f)
        return errno == ENOENT ? 0 : -1;
    char buf[32];
    char *end;
    int ok = fgets(buf, sizeof(buf), f) != NULL;
    fclose(f);
    if (!ok)
        return -1;
    long v = strtol(buf, &end, 10);
    if (end == buf || v < 0)
        return -1;
    *last = v;
    return 0;
}

static int state_write(const char *path, long step)
{
    char dir[PATH_MAX];
    if (strlen(path) >= sizeof(dir))
        return -1;
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash)
    {
        *slash = '\0';
        if (make_dirs(dir) < 0)
            return -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;
    char buf[32];
    int len = snprintf(buf, sizeof(buf), "%ld\n", step);
    int ok = write(fd, buf, (size_t)len) == len;
    if (close(fd) < 0)
        ok = 0;
    return ok ? 0 : -1;
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
    const char *src = NULL, *keyfile = NULL;
    int revoke = 0;
    int opt;
    while ((opt = getopt(argc, argv, "p:d:s:K:r46h")) != -1)
    {
        switch (opt)
        {
        case 'K':
            keyfile = optarg;
            break;
        case 'r':
            revoke = 1;
            break;
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
    if (argc - optind != (keyfile ? 1 : 2) || (revoke && !keyfile))
    {
        usage(stderr);
        return 2;
    }
    const char *host = argv[optind];
    unsigned short seq[MAX_SEQ];
    int n;
    char spath[PATH_MAX + 80];
    int have_state = 0, warned = 0;
    long sent_step = 0;
    if (keyfile)
    {
        unsigned char key[TOTP_KEY_MAX];
        size_t keylen;
        char err[320];
        if (totp_load_key(keyfile, key, &keylen, err, sizeof(err)) != 0)
        {
            fprintf(stderr, "sourceknock-knock: %s\n", err);
            return 1;
        }
        if (totp_key_mode_warning(keyfile, err, sizeof(err)))
            fprintf(stderr, "sourceknock-knock: warning: %s\n", err);
        const char *label = revoke ? TOTP_LABEL_REVOKE : TOTP_LABEL_KNOCK;
        long now = (long)time(NULL), cur = totp_step(now), last = -1;
        have_state =
            state_path(keyfile, host, label, spath, sizeof(spath)) == 0;
        if (!have_state || state_read(spath, &last) != 0)
        {
            fprintf(stderr,
                    "sourceknock-knock: warning: cannot read the step record; "
                    "knocking with the current step\n");
            warned = 1;
            last = -1;
        }
        if (last > cur)
        {
            fprintf(stderr,
                    "sourceknock-knock: the steps for this time are used; "
                    "wait %ld s and knock again\n",
                    last * TOTP_STEP - now);
            return 1;
        }
        sent_step = last == cur ? cur + 1 : cur;
        uint16_t ports[TOTP_SEQ_LEN];
        totp_sequence(key, keylen, label, sent_step, ports);
        memset(key, 0, sizeof(key));
        for (n = 0; n < TOTP_SEQ_LEN; n++)
            seq[n] = ports[n];
    }
    else if ((n = parse_seq(argv[optind + 1], seq)) < 0)
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
    if (have_state && state_write(spath, sent_step) != 0 && !warned)
        fprintf(stderr,
                "sourceknock-knock: warning: cannot write the step record "
                "%s: %s\n",
                spath, strerror(errno));
    return 0;
}
