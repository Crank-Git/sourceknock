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

static void ipstr(const struct in_addr *ip, char *out, size_t n)
{
    inet_ntop(AF_INET, &ip->s_addr, out, n);
}

/* ---- per-client "armed" list for close_on_connect ---- */
typedef struct {
    config_t  *cfg;
    reward_t   reward;
    kn_ctx_t  *ctx;
    struct { struct in_addr ip; double deadline; } armed[64];
    int         n_armed;
} daemon_t;

static int find_armed(daemon_t *d, const struct in_addr *ip)
{
    for (int i = 0; i < d->n_armed; i++)
        if (memcmp(&d->armed[i].ip, ip, sizeof(*ip)) == 0)
            return i;
    return -1;
}

static void arm_ip(daemon_t *d, const struct in_addr *ip, double deadline)
{
    if (d->n_armed >= 64) return;
    d->armed[d->n_armed].ip = *ip;
    d->armed[d->n_armed].deadline = deadline;
    d->n_armed++;
}

static void drop_armed(daemon_t *d, int idx)
{
    for (; idx < d->n_armed - 1; idx++)
        d->armed[idx] = d->armed[idx + 1];
    d->n_armed--;
}

/* Remove armed entries whose deadline has passed (safety net). */
static void cleanup_armed(daemon_t *d, double now)
{
    int i = 0;
    while (i < d->n_armed) {
        if (d->armed[i].deadline <= now) {
            char s[48];
            ipstr(&d->armed[i].ip, s, sizeof(s));
            sk_log("fallback_ttl reached: closing port for %s (no connect)", s);
            reward_close(&d->reward, &d->armed[i].ip);
            drop_armed(d, i);
        } else {
            i++;
        }
    }
}

/* Called by the state machine when a sequence completes. */
static void on_complete(kn_ctx_t *ctx, const struct in_addr *ip, void *arg)
{
    (void)ctx;
    daemon_t *d = arg;
    trigger_mode_t mode = d->cfg->trigger.mode;
    char s[48];
    ipstr(ip, s, sizeof(s));

    double timeout = (mode == MODE_FIXED_TTL)
        ? d->cfg->trigger.duration : 0.0;  /* 0 => no timeout */
    const char *proto = (d->cfg->trigger.protocol == PROTO_UDP) ? "udp" : "tcp";

    if (reward_open(&d->reward, ip, timeout) == 0) {
        if (mode == MODE_FIXED_TTL)
            sk_log("knock OK from %s: opened %d/%s for %.0fs",
                 s, d->cfg->trigger.port, proto, d->cfg->trigger.duration);
        else
            sk_log("knock OK from %s: opened %d/%s (closes on connect, %.0fs max)",
                 s, d->cfg->trigger.port, proto, d->cfg->trigger.fallback_ttl);
        if (mode == MODE_CLOSE_ON_CONNECT)
            arm_ip(d, ip, mono() + d->cfg->trigger.fallback_ttl);
    } else {
        sk_log("knock OK from %s but reward_open FAILED", s);
    }
}

/* Called for every captured packet. */
static void on_packet(const pkt_info_t *pkt, double ts, void *arg)
{
    daemon_t *d = arg;
    char s[48];
    ipstr(&pkt->ip, s, sizeof(s));

    kn_result_t r = kn_feed(d->ctx, &pkt->ip, pkt->sport, ts);
    if (r == KNOCK_RESET)
        sk_log("incomplete/wrong knock from %s: progress reset", s);

    /* close_on_connect: a packet to the service dest port after arming
     * is the actual connection -> close the port. */
    if (d->cfg->trigger.mode == MODE_CLOSE_ON_CONNECT &&
        pkt->dport == d->cfg->trigger.port) {
        int idx = find_armed(d, &pkt->ip);
        if (idx >= 0) {
            reward_close(&d->reward, &pkt->ip);
            drop_armed(d, idx);
            sk_log("connect from %s to %d: closing port",
                 s, d->cfg->trigger.port);
        }
    }

    cleanup_armed(d, ts);
}

int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : "/etc/sourceknock.conf";

    char err[256];
    if (config_parse_file(path, err, sizeof(err)) != 0) {
        fprintf(stderr, "config error: %s\n", err);
        return 1;
    }

    if (!g_cfg.has_trigger || !g_cfg.trigger.sequence) {
        fprintf(stderr, "config '%s': no valid [trigger] with sequence\n", path);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    sk_log("sourceknock starting: interface '%s'", g_cfg.interface);

    daemon_t d;
    memset(&d, 0, sizeof(d));
    d.cfg = &g_cfg;

    /* reward layer (nftables) */
    if (reward_init(&d.reward, g_cfg.trigger.port, g_cfg.trigger.protocol,
                    g_cfg.trigger.fallback_ttl) != 0) {
        fprintf(stderr, "reward init failed\n");
        return 1;
    }

    /* state machine */
    knock_sequence_t seq = { .ports = g_cfg.trigger.sequence,
                             .len = g_cfg.trigger.seq_len };
    d.ctx = kn_create(&seq, g_cfg.trigger.window);
    if (!d.ctx) {
        fprintf(stderr, "state machine create failed\n");
        return 1;
    }
    kn_set_complete(d.ctx, on_complete, &d);

    /* capture */
    capture_t cap;
    if (capture_open(&cap, g_cfg.interface, on_packet, &d) != 0) {
        fprintf(stderr, "capture open failed (need root?)\n");
        kn_free(d.ctx);
        return 1;
    }

    cap.stop = &g_stop;

    sk_log("listening for knocks on '%s'...", g_cfg.interface);
    int rc = capture_run(&cap);

    /* shutdown */
    capture_close(&cap);
    reward_flush(&d.reward);
    kn_free(d.ctx);
    sk_log("sourceknock stopped");
    return rc == 0 ? 0 : 1;
}
