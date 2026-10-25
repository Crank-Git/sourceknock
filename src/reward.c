/* reward.c - nftables reward mechanism (Linux). */
#include "reward.h"

#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Run `nft <args...>`. Returns child exit status, -1 on exec failure. */
static int run_nft(char **args)
{
    pid_t pid = fork();
    if (pid == 0)
    {
        /* The daemon runs as root; don't let a hostile PATH redirect the
         * nft binary. Pin a sane PATH in the child before exec. */
        setenv("PATH", "/usr/sbin:/sbin:/usr/bin:/bin", 1);
        execvp("nft", args);
        fprintf(stderr, "reward: exec nft failed: %s\n", strerror(errno));
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -1;
}

/* Run `nft <cmd>` where cmd is whitespace-separated tokens. Returns 0 on
 * nft exit 0. */
static int run_nft_str(const char *cmd)
{
    char work[512];
    char *argv[64];
    /* argv[0] is the program name execvp() runs; it must be "nft", not the
     * command verb. Passing the verb ("delete", "add", ...) as argv[0] makes
     * nft see no verb and default to ADD, so reward_close() re-added the very
     * element it was deleting. Tokens start at argv[1]. */
    argv[0] = "nft";
    int n = 1;

    strncpy(work, cmd, sizeof(work) - 1);
    work[sizeof(work) - 1] = '\0';

    char *tok = strtok(work, " \t\n");
    while (tok && n < 63)
    {
        argv[n++] = tok;
        tok = strtok(NULL, " \t\n");
    }
    if (n == 1) /* program name only, no verb given */
        return -1;
    argv[n] = NULL;

    int rc = run_nft(argv);
    if (rc != 0)
        fprintf(stderr, "reward: nft '%s' failed (exit %d)\n", cmd, rc);
    return rc == 0 ? 0 : -1;
}

/* Format a timeout in seconds as an nft duration string. */
static void fmt_timeout(char *out, size_t outlen, double secs)
{
    long s = (long)secs;
    if (s % 60 == 0 && s >= 60)
        /* nft duration units are single-letter: s/m/h/d. The word "min" is
         * rejected by modern nft, so emit "m" for minutes. */
        snprintf(out, outlen, "%ldm", s / 60);
    else
        snprintf(out, outlen, "%lds", s);
}

static const char *proto_str(proto_t proto)
{
    return proto == PROTO_UDP ? "udp" : "tcp";
}

int reward_init(reward_t *r, const char *table, const uint16_t *ports,
                size_t n_ports, proto_t proto, double fallback_ttl)
{
    memset(r, 0, sizeof(*r));
    strncpy(r->table, table, sizeof(r->table) - 1);
    strncpy(r->chain, "service", sizeof(r->chain) - 1);
    strncpy(r->set_v4, "allowed_v4", sizeof(r->set_v4) - 1);
    strncpy(r->set_v6, "allowed_v6", sizeof(r->set_v6) - 1);
    r->ports = ports;
    r->n_ports = n_ports;
    r->proto = proto;
    r->fallback_ttl = fallback_ttl > 0 ? fallback_ttl : 30.0;

    char cmd[512];

    /* Table (ignore "already exists"). */
    snprintf(cmd, sizeof(cmd), "add table %s", r->table);
    run_nft_str(cmd);

    /* Per-family allowed sets (per-element timeout). */
    snprintf(cmd, sizeof(cmd),
             "add set %s %s { type ipv4_addr; flags timeout; size 256; }",
             r->table, r->set_v4);
    run_nft_str(cmd);
    snprintf(cmd, sizeof(cmd),
             "add set %s %s { type ipv6_addr; flags timeout; size 256; }",
             r->table, r->set_v6);
    run_nft_str(cmd);

    /* Base chain, policy accept so other traffic is unaffected. */
    snprintf(
        cmd, sizeof(cmd),
        "add chain %s %s { type filter hook input priority 0; policy accept; }",
        r->table, r->chain);
    run_nft_str(cmd);

    /* Clear any prior rules (idempotent re-init). */
    snprintf(cmd, sizeof(cmd), "flush chain %s %s", r->table, r->chain);
    run_nft_str(cmd);

    /* One accept (per family) + one drop rule per service port. The drop rule
     * matches both families in an inet table. Adding an IP to the allowed set
     * opens every port, since each accept rule references that set. */
    for (size_t i = 0; i < n_ports; i++)
    {
        uint16_t port = ports[i];
        snprintf(cmd, sizeof(cmd),
                 "add rule %s %s ip saddr @%s %s dport %d accept", r->table,
                 r->chain, r->set_v4, proto_str(proto), port);
        run_nft_str(cmd);
        snprintf(cmd, sizeof(cmd),
                 "add rule %s %s ip6 saddr @%s %s dport %d accept", r->table,
                 r->chain, r->set_v6, proto_str(proto), port);
        run_nft_str(cmd);

        snprintf(cmd, sizeof(cmd), "add rule %s %s %s dport %d drop", r->table,
                 r->chain, proto_str(proto), port);
        run_nft_str(cmd);
    }

    r->initialized = 1;
    fprintf(stderr, "reward: %zu service port(s) managed by table %s\n",
            n_ports, r->table);
    return 0;
}

/* Select the allowed set for a family. Returns NULL for an unknown family. */
static const char *set_for_family(reward_t *r, int family)
{
    return family == AF_INET6 ? r->set_v6 : r->set_v4;
}

int reward_open(reward_t *r, int family, const void *ip, double timeout)
{
    if (!r->initialized)
        return -1;
    const char *set = set_for_family(r, family);
    if (!set)
        return -1;
    char ipstr[48];
    int af = family == AF_INET6 ? AF_INET6 : AF_INET;
    if (inet_ntop(af, ip, ipstr, sizeof(ipstr)) == NULL)
        return -1;

    char cmd[512];
    char to[32];
    if (timeout > 0)
    {
        fmt_timeout(to, sizeof(to), timeout);
        snprintf(cmd, sizeof(cmd), "add element %s %s { %s timeout %s }",
                 r->table, set, ipstr, to);
    }
    else
    {
        snprintf(cmd, sizeof(cmd), "add element %s %s { %s }", r->table, set,
                 ipstr);
    }
    return run_nft_str(cmd);
}

int reward_close(reward_t *r, int family, const void *ip)
{
    if (!r->initialized)
        return -1;
    const char *set = set_for_family(r, family);
    if (!set)
        return -1;
    int af = family == AF_INET6 ? AF_INET6 : AF_INET;
    char ipstr[48];
    if (inet_ntop(af, ip, ipstr, sizeof(ipstr)) == NULL)
        return -1;

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "delete element %s %s { %s }", r->table, set,
             ipstr);
    return run_nft_str(cmd);
}

int reward_flush(reward_t *r)
{
    if (!r->initialized)
        return -1;
    char cmd[512];
    /* Remove every element from both family sets. */
    snprintf(cmd, sizeof(cmd), "delete element %s %s { * }", r->table,
             r->set_v4);
    run_nft_str(cmd);
    snprintf(cmd, sizeof(cmd), "delete element %s %s { * }", r->table,
             r->set_v6);
    return run_nft_str(cmd);
}
