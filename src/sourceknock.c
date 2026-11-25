/*
 * sourceknock - a port-knocking daemon that knocks via SOURCE ports.
 *
 * The client sends packets whose SOURCE ports spell out a secret sequence.
 * Once the sequence is seen (in order, within the window) from a given IP,
 * the daemon temporarily opens the hidden service port for that IP via
 * nftables.
 *
 * Usage: sourceknock [-t] [config-file]
 *   -t  check the config and exit (0 = usable), without touching nftables
 *
 * SIGHUP reloads the config: a bad one is refused and the running config
 * kept; a good one is applied without dropping clients already let in.
 */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700 /* realpath() */
#define _DEFAULT_SOURCE /* IFF_UP, getifaddrs() */
#include "capture.h"
#include "close.h"
#include "config.h"
#include "packet.h"
#include "reward.h"
#include "rolling.h"
#include "state.h"
#include "totp.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Absolute path of the running config: the owner mark of every table. */
static char g_config_abs[PATH_MAX];

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_reload = 0;
static void on_signal(int sig)
{
    if (sig == SIGHUP)
        g_reload = 1;
    else
        g_stop = 1;
}

static double mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void sk_log(const char *fmt, ...)
{
    /* Wall-clock time for humans; knock timing uses mono() instead. */
    char ts[32];
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
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
typedef struct
{
    int family;
    union
    {
        struct in_addr v4;
        struct in6_addr v6;
    } addr;
    double deadline;
} armed_entry_t;

typedef struct
{
    const trigger_t *tr; /* back-reference to config */
    reward_t reward;
    kn_ctx_t *ctx;       /* primary: completes -> open the port */
    kn_ctx_t *admin_ctx; /* optional: completes -> revoke (remove IP) */
    /* secret_file triggers use these instead of ctx / admin_ctx. */
    int rolling;
    rolling_t roll;        /* time-based knock -> open */
    rolling_t roll_revoke; /* time-based revoke knock -> remove IP */
    /* close_on_connect clients awaiting their connection. Growable: the nft
     * element carries the real fallback_ttl, so this list only drives the
     * early close and logging, and must never silently drop a client. */
    armed_entry_t *armed;
    int n_armed;
    int cap_armed;
} trigger_state_t;

typedef struct
{
    trigger_state_t *ts; /* one entry per trigger */
    size_t n_triggers;
} daemon_t;

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
    /* A re-knock from an armed client just refreshes its deadline. */
    int idx = find_armed(ts, family, ip);
    if (idx >= 0)
    {
        ts->armed[idx].deadline = deadline;
        return;
    }
    if (ts->n_armed == ts->cap_armed)
    {
        int ncap = ts->cap_armed ? ts->cap_armed * 2 : 16;
        armed_entry_t *na = realloc(ts->armed, (size_t)ncap * sizeof(*na));
        if (!na)
        {
            /* The kernel still expires the element at fallback_ttl. */
            sk_log("[%s] out of memory tracking armed client", ts->tr->service);
            return;
        }
        ts->armed = na;
        ts->cap_armed = ncap;
    }
    memset(&ts->armed[ts->n_armed], 0, sizeof(ts->armed[ts->n_armed]));
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
    for (size_t i = 0; i < tr->n_ports && off < n - 1; i++)
    {
        int w =
            snprintf(out + off, n - off, "%s%d", i ? "," : "", tr->ports[i]);
        if (w < 0)
            break;
        off += (size_t)w;
    }
    out[off] = '\0';
}

/* Forget armed entries whose fallback_ttl has passed. The nft element was
 * added with fallback_ttl as its timeout, so the kernel has already closed the
 * port (even if this daemon saw no packets, or wasn't running); this only
 * tidies our list and logs it. */
static void cleanup_armed(trigger_state_t *ts, double now)
{
    int i = 0;
    while (i < ts->n_armed)
    {
        if (ts->armed[i].deadline <= now)
        {
            char s[48];
            ipstr(ts->armed[i].family, &ts->armed[i].addr, s, sizeof(s));
            sk_log("[%s] fallback_ttl reached for %s (no connect): port closed",
                   ts->tr->service, s);
            drop_armed(ts, i);
        }
        else
        {
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

    /* Every non-permanent mode gets a kernel-enforced timeout, so the port
     * closes even if the daemon never sees another packet or dies. */
    double timeout = 0.0;
    if (tr->mode == MODE_FIXED_TTL)
        timeout = tr->duration;
    else if (tr->mode == MODE_CLOSE_ON_CONNECT)
        timeout = tr->fallback_ttl;
    const char *proto = (tr->protocol == PROTO_UDP) ? "udp" : "tcp";

    if (reward_open(&ts->reward, family, ip, timeout) == 0)
    {
        char ports[128];
        fmt_ports(tr, ports, sizeof(ports));
        if (tr->mode == MODE_FIXED_TTL)
            sk_log("[%s] knock OK from %s: opened %s/%s for %.0fs", tr->service,
                   s, ports, proto, tr->duration);
        else if (tr->mode == MODE_PERMANENT)
            sk_log("[%s] knock OK from %s: opened %s/%s (permanent)",
                   tr->service, s, ports, proto);
        else
            sk_log("[%s] knock OK from %s: opened %s/%s (closes on connect, "
                   "%.0fs max)",
                   tr->service, s, ports, proto, tr->fallback_ttl);
        if (tr->mode == MODE_CLOSE_ON_CONNECT)
            arm_ip(ts, family, ip, mono() + tr->fallback_ttl);
    }
    else
    {
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

    if (reward_close(&ts->reward, family, ip) == 0)
    {
        sk_log("[%s] admin revoke from %s: removed %s/%s", tr->service, s,
               ports, tr->protocol == PROTO_UDP ? "udp" : "tcp");
    }
    else
    {
        sk_log("[%s] admin revoke from %s: %s not currently allowed",
               tr->service, s, ports);
    }
}

/* rolling_t completion hooks for secret_file triggers. */
static void roll_open(int family, const void *ip, void *arg)
{
    on_complete(NULL, family, ip, arg);
}
static void roll_revoke(int family, const void *ip, void *arg)
{
    on_revoke(NULL, family, ip, arg);
}

/* Called for every captured packet: run it against every trigger. */
static void on_packet(const pkt_info_t *pkt, const char *iface, double ts,
                      void *arg)
{
    daemon_t *d = arg;
    char s[48];

    /* Ignore multicast/broadcast (control-plane) frames: they can't be a
     * knock and would otherwise corrupt the per-client sequence state. */
    if (pkt_is_control(pkt))
        return;

    ipstr(pkt->family, &pkt->addr, s, sizeof(s));

    for (size_t i = 0; i < d->n_triggers; i++)
    {
        trigger_state_t *t = &d->ts[i];
        kn_result_t r = KNOCK_IGNORE;

        /* A trigger only sees frames from its own interface. */
        if (strcmp(t->tr->interface, iface) != 0)
            continue;

        /* With knock_port set, only frames sent to that port are part of a
         * knock; anything else (other traffic from the same client, replies
         * to the server's own outbound connections) can't advance or reset
         * it. */
        if (knock_counts(t->tr, pkt->dport) && t->rolling)
        {
            long step = totp_step((long)time(NULL));
            int replay;
            r = rolling_feed(&t->roll, step, pkt->family, &pkt->addr,
                             pkt->sport, ts, &replay);
            if (replay)
                sk_log("[%s] repeated knock from %s ignored: that time "
                       "step's knock was already used",
                       t->tr->service, s);
            else if (r == KNOCK_RESET)
                sk_log("[%s] incomplete/wrong knock from %s: progress reset",
                       t->tr->service, s);
            rolling_feed(&t->roll_revoke, step, pkt->family, &pkt->addr,
                         pkt->sport, ts, &replay);
        }
        else if (knock_counts(t->tr, pkt->dport))
        {
            r = kn_feed(t->ctx, pkt->family, &pkt->addr, pkt->sport, ts);
            if (r == KNOCK_RESET)
                sk_log("[%s] incomplete/wrong knock from %s: progress reset",
                       t->tr->service, s);

            /* Optional admin/revoke sequence runs on its own state machine
             * so it never interferes with the primary knock. */
            if (t->admin_ctx)
                kn_feed(t->admin_ctx, pkt->family, &pkt->addr, pkt->sport, ts);
        }

        /* close_on_connect: a packet to the service dest port after arming
         * is the actual connection -> close the port. The arming knock
         * itself (KNOCK_TRIGGER) must NOT close the port the instant it
         * opens — for UDP there is no handshake, so only a subsequent
         * packet to the service port ends access. */
        int idx = find_armed(t, pkt->family, &pkt->addr);
        if (should_close(t->tr, idx >= 0, pkt, r))
        {
            reward_close(&t->reward, pkt->family, &pkt->addr);
            drop_armed(t, idx);
            char ports[128];
            fmt_ports(t->tr, ports, sizeof(ports));
            sk_log("[%s] connect from %s to %d: closing %s", t->tr->service, s,
                   pkt->dport, ports);
        }
        cleanup_armed(t, ts);
    }
}

/* Load each secret_file trigger's key. Returns 0, or -1 (reason logged). */
static int load_keys(unsigned char (*keys)[TOTP_KEY_MAX], size_t *keylens)
{
    for (size_t i = 0; i < g_cfg.n_triggers; i++)
    {
        const trigger_t *tr = &g_cfg.triggers[i];
        char err[320];
        if (tr->secret_file[0] &&
            totp_key_mode_warning(tr->secret_file, err, sizeof(err)))
            fprintf(stderr, "[%s] warning: %s\n", tr->service, err);
        if (tr->secret_file[0] &&
            totp_load_key(tr->secret_file, keys[i], &keylens[i], err,
                          sizeof(err)) != 0)
        {
            fprintf(stderr, "[%s] %s\n", tr->service, err);
            return -1;
        }
    }
    return 0;
}

/* The warning for a trigger whose ports stay open on the host's other
 * interfaces that are up (see config_open_interfaces_warning). Returns 1 with
 * the text in `msg`, else 0. */
static int open_interfaces_warning(const trigger_t *tr, char *msg, size_t n)
{
    struct ifaddrs *all;
    if (getifaddrs(&all) != 0)
        return 0;
    size_t count = 0;
    for (struct ifaddrs *a = all; a; a = a->ifa_next)
        count++;
    int warn = 0;
    const char **names = calloc(count ? count : 1, sizeof(*names));
    int *flags = calloc(count ? count : 1, sizeof(*flags));
    if (names && flags)
    {
        /* getifaddrs() lists an interface once per address; keep one entry
         * per name. */
        size_t k = 0;
        for (struct ifaddrs *a = all; a; a = a->ifa_next)
        {
            size_t j = 0;
            while (j < k && strcmp(names[j], a->ifa_name) != 0)
                j++;
            if (j == k)
            {
                names[k] = a->ifa_name;
                flags[k++] = (a->ifa_flags & IFF_UP) != 0;
            }
        }
        k = config_keep_up_interfaces(names, flags, k);
        warn = config_open_interfaces_warning(tr, names, k, msg, n);
    }
    free(names);
    free(flags);
    freeifaddrs(all);
    return warn;
}

/* `-t`: everything startup would refuse that can be checked without
 * privileges, so a config can be checked before restarting the daemon (a
 * restart onto a bad config leaves the old tables closing the ports). */
static int check_config(const char *path)
{
    int bad = 0;
    for (size_t i = 0; i < g_cfg.n_triggers; i++)
    {
        const trigger_t *tr = &g_cfg.triggers[i];
        char why[160];
        if (config_weak_sequence(tr, why, sizeof(why)))
            fprintf(stderr, "[%s] warning: %s\n", tr->service, why);
        char open_msg[320];
        if (open_interfaces_warning(tr, open_msg, sizeof(open_msg)))
            fprintf(stderr, "[%s] warning: %s\n", tr->service, open_msg);
        if (if_nametoindex(tr->interface) == 0)
        {
            fprintf(stderr, "[%s] interface '%s' does not exist\n", tr->service,
                    tr->interface);
            bad = 1;
        }
    }
    unsigned char(*keys)[TOTP_KEY_MAX] =
        calloc(g_cfg.n_triggers, sizeof(*keys));
    size_t *keylens = calloc(g_cfg.n_triggers, sizeof(*keylens));
    if (!keys || !keylens || load_keys(keys, keylens) != 0)
        bad = 1;
    free(keys);
    free(keylens);
    if (bad)
        return 1;
    printf("config '%s' OK (%zu trigger(s))\n", path, g_cfg.n_triggers);
    return 0;
}

/* Free a daemon's in-memory state. Its nft tables are left alone. */
static void daemon_free(daemon_t *d, capture_t *caps, size_t n_caps)
{
    for (size_t k = 0; k < n_caps; k++)
        capture_close(&caps[k]);
    free(caps);
    for (size_t i = 0; i < d->n_triggers; i++)
    {
        kn_free(d->ts[i].ctx);
        kn_free(d->ts[i].admin_ctx);
        rolling_free(&d->ts[i].roll);
        rolling_free(&d->ts[i].roll_revoke);
        free(d->ts[i].armed);
    }
    free(d->ts);
    d->ts = NULL;
    d->n_triggers = 0;
}

/* Remove tables of triggers that aren't in `d` (renamed or dropped). */
static void prune(const daemon_t *d)
{
    const char **keep = calloc(d->n_triggers, sizeof(*keep));
    if (!keep)
    {
        sk_log("out of memory: skipping stale table cleanup");
        return;
    }
    for (size_t i = 0; i < d->n_triggers; i++)
        keep[i] = d->ts[i].reward.table;
    reward_prune_stale(g_config_abs, keep, d->n_triggers);
    free(keep);
}

/* Build captures, tables and state machines for g_cfg into `d`. Packets are
 * dispatched with `live` as their argument (where `d` will end up). On
 * failure returns -1 with nothing allocated; with `destroy_on_fail` the
 * tables it programmed are deleted (startup), otherwise they are left for the
 * caller to repair (reload). */
static int daemon_build(daemon_t *d, daemon_t *live, capture_t **caps_out,
                        size_t *n_caps_out, int destroy_on_fail)
{
    memset(d, 0, sizeof(*d));
    size_t n = g_cfg.n_triggers;
    unsigned char(*keys)[TOTP_KEY_MAX] = calloc(n, sizeof(*keys));
    size_t *keylens = calloc(n, sizeof(*keylens));
    capture_t *caps = calloc(n, sizeof(*caps));
    d->ts = calloc(n, sizeof(*d->ts));
    size_t n_caps = 0;
    if (!keys || !keylens || !caps || !d->ts)
    {
        fprintf(stderr, "out of memory building trigger state\n");
        goto fail;
    }
    d->n_triggers = n;

    /* Keys first, then one capture per distinct trigger interface: an
     * unreadable secret or an unusable interface (no CAP_NET_RAW, a link type
     * we can't parse) should fail before any firewall rule is touched. A
     * missing interface is retried instead. */
    if (load_keys(keys, keylens) != 0)
        goto fail;
    for (size_t i = 0; i < n; i++)
    {
        const char *ifn = g_cfg.triggers[i].interface;
        size_t c = 0;
        while (c < n_caps && strcmp(caps[c].interface, ifn) != 0)
            c++;
        if (c < n_caps)
            continue; /* already open */
        if (capture_open(&caps[n_caps], ifn, on_packet, live) < 0)
        {
            fprintf(stderr, "capture open failed (need root?)\n");
            goto fail;
        }
        n_caps++;
    }

    /* Per-trigger: reward table (namespaced by service) + state machine. */
    long step = totp_step((long)time(NULL));
    for (size_t i = 0; i < n; i++)
    {
        const trigger_t *tr = &g_cfg.triggers[i];
        trigger_state_t *t = &d->ts[i];
        t->tr = tr;

        /* Validated by the config parser: fits, and unique per trigger. */
        char table[CONFIG_TABLE_NAME_MAX];
        config_table_name(tr->service, table, sizeof(table));

        char why[160];
        if (config_weak_sequence(tr, why, sizeof(why)))
            sk_log("[%s] warning: %s", tr->service, why);
        char open_msg[320];
        if (open_interfaces_warning(tr, open_msg, sizeof(open_msg)))
            sk_log("[%s] warning: %s", tr->service, open_msg);

        if (reward_init(&t->reward, table, g_config_abs, tr->interface,
                        tr->close_on, tr->ports, tr->n_ports, tr->protocol,
                        tr->fallback_ttl, tr->max_allowed) != 0)
        {
            fprintf(stderr, "reward init failed for trigger '%s'\n",
                    tr->service);
            goto fail;
        }

        if (tr->secret_file[0])
        {
            t->rolling = 1;
            if (rolling_init(&t->roll, keys[i], keylens[i], TOTP_LABEL_KNOCK,
                             tr->window, step, roll_open, t) != 0 ||
                rolling_init(&t->roll_revoke, keys[i], keylens[i],
                             TOTP_LABEL_REVOKE, tr->window, step, roll_revoke,
                             t) != 0)
            {
                fprintf(stderr, "out of memory for trigger '%s'\n",
                        tr->service);
                goto fail;
            }
            continue;
        }

        knock_sequence_t seq = {.ports = tr->sequence, .len = tr->seq_len};
        t->ctx = kn_create(&seq, tr->window);
        if (!t->ctx)
        {
            fprintf(stderr, "state machine create failed for trigger '%s'\n",
                    tr->service);
            goto fail;
        }
        kn_set_complete(t->ctx, on_complete, t);

        /* Optional admin/revoke sequence on its own state machine. */
        if (tr->admin_seq_len > 0)
        {
            knock_sequence_t admin_seq = {.ports = tr->admin_sequence,
                                          .len = tr->admin_seq_len};
            t->admin_ctx = kn_create(&admin_seq, tr->window);
            if (!t->admin_ctx)
            {
                fprintf(stderr,
                        "admin state machine create failed for trigger '%s'\n",
                        tr->service);
                goto fail;
            }
            kn_set_complete(t->admin_ctx, on_revoke, t);
        }
    }
    memset(keys, 0, n * sizeof(*keys));
    free(keys);
    free(keylens);

    /* Only once every current table is in place. */
    prune(d);
    *caps_out = caps;
    *n_caps_out = n_caps;
    return 0;

fail:
    if (keys)
        memset(keys, 0, n * sizeof(*keys));
    free(keys);
    free(keylens);
    if (destroy_on_fail && d->ts)
    {
        /* Startup: remove the tables we programmed, so we never exit leaving
         * a service port closed with no daemon to open it. */
        for (size_t i = 0; i < d->n_triggers; i++)
            reward_destroy(&d->ts[i].reward);
    }
    if (d->ts)
        daemon_free(d, caps, n_caps);
    else
    {
        for (size_t k = 0; k < n_caps; k++)
            capture_close(&caps[k]);
        free(caps);
    }
    return -1;
}

/* Reprogram `d`'s tables from its current config (after a failed reload
 * changed some of them). The allowed sets keep their elements. */
static void restore_rules(daemon_t *d)
{
    for (size_t i = 0; i < d->n_triggers; i++)
    {
        trigger_state_t *t = &d->ts[i];
        const trigger_t *tr = t->tr;
        char
            table[sizeof(t->reward.table)]; /* reward_init() clears t->reward */
        strcpy(table, t->reward.table);
        if (reward_init(&t->reward, table, g_config_abs, tr->interface,
                        tr->close_on, tr->ports, tr->n_ports, tr->protocol,
                        tr->fallback_ttl, tr->max_allowed) != 0)
            sk_log("[%s] could not restore its nft table", tr->service);
    }
    prune(d);
}

/* SIGHUP: apply the config at `path`. A config that doesn't parse or can't be
 * built is refused and the running one kept. Clients already let in stay in
 * (the tables of triggers that remain keep their allowed sets). */
static void reload(const char *path, daemon_t *d, capture_t **caps,
                   size_t *n_caps)
{
    sk_log("reload: reading '%s'", path);
    config_t old = g_cfg; /* take the running config out of g_cfg */
    g_cfg.triggers = NULL;
    g_cfg.n_triggers = 0;

    char err[256];
    if (config_parse_file(path, err, sizeof(err)) != 0)
    {
        sk_log("reload: config error: %s; keeping the running config", err);
        config_free();
        g_cfg = old;
        return;
    }
    if (g_cfg.n_triggers == 0)
    {
        sk_log("reload: no [trigger] sections; keeping the running config");
        config_free();
        g_cfg = old;
        return;
    }

    daemon_t nd;
    capture_t *ncaps = NULL;
    size_t nn = 0;
    if (daemon_build(&nd, d, &ncaps, &nn, 0) != 0)
    {
        sk_log("reload: could not apply the new config; keeping the running "
               "config");
        config_free();
        g_cfg = old;
        restore_rules(d);
        return;
    }

    /* Carry per-trigger runtime state over to triggers that stay. */
    for (size_t i = 0; i < nd.n_triggers; i++)
    {
        trigger_state_t *nt = &nd.ts[i];
        for (size_t j = 0; j < d->n_triggers; j++)
        {
            trigger_state_t *ot = &d->ts[j];
            if (strcmp(nt->reward.table, ot->reward.table) != 0)
                continue;
            /* Used time steps, so a reload can't reopen one (replay). */
            if (nt->rolling && ot->rolling)
            {
                rolling_carry_used(&nt->roll, &ot->roll);
                rolling_carry_used(&nt->roll_revoke, &ot->roll_revoke);
            }
            /* Clients armed for close_on_connect still close on connect. */
            if (nt->tr->mode == MODE_CLOSE_ON_CONNECT &&
                ot->tr->mode == MODE_CLOSE_ON_CONNECT)
            {
                nt->armed = ot->armed;
                nt->n_armed = ot->n_armed;
                nt->cap_armed = ot->cap_armed;
                ot->armed = NULL;
            }
        }
    }

    daemon_free(d, *caps, *n_caps);
    config_t newcfg = g_cfg;
    g_cfg = old;
    config_free(); /* the old config */
    g_cfg = newcfg;
    *d = nd;
    *caps = ncaps;
    *n_caps = nn;
    sk_log("reload: applied (%zu trigger(s))", d->n_triggers);
}

static void log_listening(const capture_t *caps, size_t n_caps)
{
    char ifs[256];
    size_t off = 0;
    for (size_t k = 0; k < n_caps && off < sizeof(ifs); k++)
    {
        int w = snprintf(ifs + off, sizeof(ifs) - off, "%s'%s'", k ? ", " : "",
                         caps[k].interface);
        if (w < 0)
            break;
        off += (size_t)w;
    }
    sk_log("listening for knocks on %s...", ifs);
}

int main(int argc, char **argv)
{
    int check = argc > 1 && strcmp(argv[1], "-t") == 0;
    const char *path = (argc > 1 + check) ? argv[1 + check]
                                          : "/etc/sourceknock/sourceknock.conf";

    char err[256];
    if (config_parse_file(path, err, sizeof(err)) != 0)
    {
        fprintf(stderr, "config error: %s\n", err);
        return 1;
    }

    if (g_cfg.n_triggers == 0)
    {
        fprintf(stderr, "config '%s': no [trigger] sections\n", path);
        return 1;
    }

    /* The config's absolute path marks every table this daemon creates, so
     * two daemons with different configs never delete each other's tables. */
    char mark[160];
    if (!realpath(path, g_config_abs) ||
        reward_owner_mark(mark, sizeof(mark), g_config_abs) != 0)
    {
        fprintf(stderr,
                "config '%s': its absolute path cannot mark nft tables (at "
                "most 116 characters, no quote, backslash or control "
                "character)\n",
                path);
        config_free();
        return 1;
    }

    if (check)
    {
        int rc = check_config(path);
        config_free();
        return rc;
    }

    /* sigaction, not signal(): signal()'s semantics depend on feature macros
     * (BSD semantics add SA_RESTART, so recvfrom() would never return EINTR)
     * and System V semantics reset the handler after the first signal. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* no SA_RESTART: let a signal interrupt poll() */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    sk_log("sourceknock starting (%zu trigger(s))", g_cfg.n_triggers);

    daemon_t d;
    capture_t *caps = NULL;
    size_t n_caps = 0;
    if (daemon_build(&d, &d, &caps, &n_caps, 1) != 0)
    {
        config_free();
        return 1;
    }

    log_listening(caps, n_caps);
    int rc;
    for (;;)
    {
        rc = capture_run(caps, n_caps, &g_stop, &g_reload);
        if (rc != 0 || g_stop)
            break;
        g_reload = 0;
        reload(path, &d, &caps, &n_caps);
        log_listening(caps, n_caps);
    }

    /* shutdown */
    for (size_t i = 0; i < d.n_triggers; i++)
        reward_flush(&d.ts[i].reward);
    daemon_free(&d, caps, n_caps);
    config_free();
    sk_log("sourceknock stopped");
    return rc == 0 ? 0 : 1;
}
