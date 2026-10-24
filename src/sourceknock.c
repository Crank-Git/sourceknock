/*
 * sourceknock - a port-knocking daemon that knocks via SOURCE ports.
 *
 * The client sends packets whose SOURCE ports spell out a secret sequence.
 * Once the sequence is seen (in order, within the window) from a given IP,
 * the daemon temporarily opens the hidden service port for that IP via nftables.
 *
 * Usage: sourceknock <config-file>
 */
#define _POSIX_C_SOURCE 200809L
#include "config.h"
#include "state.h"
#include "capture.h"
#include "reward.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

static double mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void sk_log(const char *fmt, ...)
{
    char ts[32];
    time_t t = (time_t)mono();
    struct tm *tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    fprintf(stderr, "[%s] ", ts);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

static void ipstr(int family, const void *ip, char *out, size_t n)
{
    int af = family == AF_INET6 ? AF_INET6 : AF_INET;
    inet_ntop(af, ip, out, n);
}

/* ---- per-trigger state ---- */
typedef struct {
    int family;
    union { struct in_addr v4; struct in6_addr v6; } addr;
    double deadline;
} armed_entry_t;

typedef struct {
    const trigger_t *tr;          /* back-reference to config */
    reward_t   reward;
    kn_ctx_t  *ctx;         /* primary: completes -> open the port */
    kn_ctx_t  *admin_ctx;   /* optional: completes -> revoke (remove IP) */
    armed_entry_t armed[64];
    int         n_armed;
} trigger_state_t;

typedef struct {
    trigger_state_t *ts;          /* one entry per trigger */
    size_t          n_triggers;
} daemon_t;

/* Build an nft-safe table name for a trigger: "inet sourceknock_<service>",
 * with the service sanitized to [a-z0-9_]. */
static void build_table_name(char *out, size_t outlen, const char *service)
{
    size_t i = 0;
    int n = snprintf(out, outlen, "inet sourceknock_");
    if (n < 0) { out[0] = '\0'; return; }
    i = (size_t)n;
    while (*service && i + 1 < outlen) {
        char c = *service;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_') {
            out[i++] = c;
        } else {
            out[i++] = '_';
        }
        service++;
    }
    out[i] = '\0';
}

static int find_armed(trigger_state_t *ts, int family, const void *ip)
{
    for (int i = 0; i < ts->n_armed; i++)
        if (ts->armed[i].family == family &&
            memcmp(&ts->armed[i].addr, ip, pkt_addr_len(family)) == 0)
            return i;
    return -1;
}

static void arm_ip(trigger_state_t *ts, int family, const void *ip,
                   double deadline)
{
    if (ts->n_armed >= 64) return;
    ts->armed[ts->n_armed].family = family;
    memcpy(&ts->armed[ts->n_armed].addr, ip, pkt_addr_len(family));
    ts->armed[ts->n_armed].deadline = deadline;
    ts->n_armed++;
}

static void drop_armed(trigger_state_t *ts, int idx)
{
    for (; idx < ts->n_armed - 1; idx++)
        ts->armed[idx] = ts->armed[idx + 1];
    ts->n_armed--;
}

/* Format a trigger's service ports as "22" or "80,443,8000". Bounds-checked;
 * truncates (leaving a valid NUL-terminated string) if it would overflow. */
static void fmt_ports(const trigger_t *tr, char *out, size_t n)
{
    size_t off = 0;
    for (size_t i = 0; i < tr->n_ports && off < n - 1; i++) {
        int w = snprintf(out + off, n - off, "%s%d", i ? "," : "",
                         tr->ports[i]);
        if (w < 0) break;
        off += (size_t)w;
    }
    out[off] = '\0';
}

/* Is `port` one of the trigger's service ports? */
static int port_in_list(const trigger_t *tr, uint16_t port)
{
    for (size_t i = 0; i < tr->n_ports; i++)
        if (tr->ports[i] == port) return 1;
    return 0;
}

/* Remove armed entries whose deadline has passed (safety net). */
static void cleanup_armed(trigger_state_t *ts, double now)
{
    int i = 0;
    while (i < ts->n_armed) {
        if (ts->armed[i].deadline <= now) {
            char s[48];
            ipstr(ts->armed[i].family, &ts->armed[i].addr, s, sizeof(s));
            sk_log("fallback_ttl reached: closing port for %s (no connect)", s);
            reward_close(&ts->reward, ts->armed[i].family, &ts->armed[i].addr);
            drop_armed(ts, i);
        } else {
            i++;
        }
    }
}

/* Called by the state machine when a sequence completes. */
static void on_complete(kn_ctx_t *ctx, int family, const void *ip, void *arg)
{
    (void)ctx;
    trigger_state_t *ts = arg;
    const trigger_t *tr = ts->tr;
    char s[48];
    ipstr(family, ip, s, sizeof(s));

    double timeout = (tr->mode == MODE_FIXED_TTL) ? tr->duration : 0.0;
    const char *proto = (tr->protocol == PROTO_UDP) ? "udp" : "tcp";

    if (reward_open(&ts->reward, family, ip, timeout) == 0) {
        char ports[128];
        fmt_ports(tr, ports, sizeof(ports));
        if (tr->mode == MODE_FIXED_TTL)
            sk_log("[%s] knock OK from %s: opened %s/%s for %.0fs",
                   tr->service, s, ports, proto, tr->duration);
        else if (tr->mode == MODE_PERMANENT)
            sk_log("[%s] knock OK from %s: opened %s/%s (permanent)",
                   tr->service, s, ports, proto);
        else
            sk_log("[%s] knock OK from %s: opened %s/%s (closes on connect, "
                   "%.0fs max)", tr->service, s, ports, proto,
                   tr->fallback_ttl);
        if (tr->mode == MODE_CLOSE_ON_CONNECT)
            arm_ip(ts, family, ip, mono() + tr->fallback_ttl);
    } else {
        sk_log("[%s] knock OK from %s but reward_open FAILED", tr->service, s);
    }
}

/* Called by the admin state machine when the revoke sequence completes.
 * Removes `ip` from the allowed set so the port closes again. */
static void on_revoke(kn_ctx_t *ctx, int family, const void *ip, void *arg)
{
    (void)ctx;
    trigger_state_t *ts = arg;
    const trigger_t *tr = ts->tr;
    char s[48];
    ipstr(family, ip, s, sizeof(s));
    char ports[128];
    fmt_ports(tr, ports, sizeof(ports));

    if (reward_close(&ts->reward, family, ip) == 0) {
        sk_log("[%s] admin revoke from %s: removed %s/%s",
               tr->service, s, ports, tr->protocol == PROTO_UDP ? "udp" : "tcp");
    } else {
        sk_log("[%s] admin revoke from %s: %s not currently allowed",
               tr->service, s, ports);
    }
}

/* Called for every captured packet: run it against every trigger. */
static void on_packet(const pkt_info_t *pkt, double ts, void *arg)
{
    daemon_t *d = arg;
    char s[48];
    ipstr(pkt->family, &pkt->addr, s, sizeof(s));

    for (size_t i = 0; i < d->n_triggers; i++) {
        trigger_state_t *t = &d->ts[i];
        kn_result_t r = kn_feed(t->ctx, pkt->family, &pkt->addr,
                                pkt->sport, ts);
        if (r == KNOCK_RESET)
            sk_log("[%s] incomplete/wrong knock from %s: progress reset",
                   t->tr->service, s);

        /* Optional admin/revoke sequence runs on its own state machine so it
         * never interferes with the primary knock. */
        if (t->admin_ctx)
            kn_feed(t->admin_ctx, pkt->family, &pkt->addr, pkt->sport, ts);

        /* close_on_connect: a packet to the service dest port after arming
         * is the actual connection -> close the port. */
        if (t->tr->mode == MODE_CLOSE_ON_CONNECT &&
            port_in_list(t->tr, pkt->dport)) {
            int idx = find_armed(t, pkt->family, &pkt->addr);
            if (idx >= 0) {
                reward_close(&t->reward, pkt->family, &pkt->addr);
                drop_armed(t, idx);
                char ports[128];
                fmt_ports(t->tr, ports, sizeof(ports));
                sk_log("[%s] connect from %s to %d: closing %s",
                       t->tr->service, s, pkt->dport, ports);
            }
        }
        cleanup_armed(t, ts);
    }
}

int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : "/etc/sourceknock.conf";

    char err[256];
    if (config_parse_file(path, err, sizeof(err)) != 0) {
        fprintf(stderr, "config error: %s\n", err);
        return 1;
    }

    if (g_cfg.n_triggers == 0) {
        fprintf(stderr, "config '%s': no valid [trigger] with sequence\n", path);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    sk_log("sourceknock starting: interface '%s' (%zu trigger(s))",
           g_cfg.interface, g_cfg.n_triggers);

    daemon_t d;
    memset(&d, 0, sizeof(d));
    d.n_triggers = g_cfg.n_triggers;
    d.ts = calloc(d.n_triggers, sizeof(*d.ts));
    if (!d.ts) {
        fprintf(stderr, "out of memory allocating trigger state\n");
        return 1;
    }

    /* Per-trigger: reward table (namespaced by service) + state machine. */
    for (size_t i = 0; i < d.n_triggers; i++) {
        const trigger_t *tr = &g_cfg.triggers[i];
        trigger_state_t *t = &d.ts[i];
        t->tr = tr;

        char table[128];
        build_table_name(table, sizeof(table), tr->service);

        if (reward_init(&t->reward, table, tr->ports, tr->n_ports,
                        tr->protocol, tr->fallback_ttl) != 0) {
            fprintf(stderr, "reward init failed for trigger '%s'\n", tr->service);
            return 1;
        }

        knock_sequence_t seq = { .ports = tr->sequence, .len = tr->seq_len };
        t->ctx = kn_create(&seq, tr->window);
        if (!t->ctx) {
            fprintf(stderr, "state machine create failed for trigger '%s'\n",
                    tr->service);
            return 1;
        }
        kn_set_complete(t->ctx, on_complete, t);

        /* Optional admin/revoke sequence on its own state machine. */
        if (tr->admin_seq_len > 0) {
            knock_sequence_t admin_seq =
                { .ports = tr->admin_sequence, .len = tr->admin_seq_len };
            t->admin_ctx = kn_create(&admin_seq, tr->window);
            if (!t->admin_ctx) {
                fprintf(stderr,
                        "admin state machine create failed for trigger '%s'\n",
                        tr->service);
                return 1;
            }
            kn_set_complete(t->admin_ctx, on_revoke, t);
        }
    }

    /* capture */
    capture_t cap;
    if (capture_open(&cap, g_cfg.interface, on_packet, &d) != 0) {
        fprintf(stderr, "capture open failed (need root?)\n");
        return 1;
    }

    cap.stop = &g_stop;

    sk_log("listening for knocks on '%s'...", g_cfg.interface);
    int rc = capture_run(&cap);

    /* shutdown */
    capture_close(&cap);
    for (size_t i = 0; i < d.n_triggers; i++) {
        reward_flush(&d.ts[i].reward);
        kn_free(d.ts[i].ctx);
        kn_free(d.ts[i].admin_ctx);
    }
    free(d.ts);
    sk_log("sourceknock stopped");
    return rc == 0 ? 0 : 1;
}
