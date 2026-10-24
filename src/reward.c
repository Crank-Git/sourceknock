/* reward.c - nftables reward mechanism (Linux). */
#include "reward.h"

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <arpa/inet.h>

/* Run `nft <args...>`. Returns child exit status, -1 on exec failure. */
static int run_nft(char **args)
{
    pid_t pid = fork();
    if (pid == 0) {
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
    int n = 0;

    strncpy(work, cmd, sizeof(work) - 1);
    work[sizeof(work) - 1] = '\0';

    char *tok = strtok(work, " \t\n");
    while (tok && n < 63) {
        argv[n++] = tok;
        tok = strtok(NULL, " \t\n");
    }
    if (n == 0)
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
        snprintf(out, outlen, "%ldmin", s / 60);
    else
        snprintf(out, outlen, "%lds", s);
}

static const char *proto_str(proto_t proto)
{
    return proto == PROTO_UDP ? "udp" : "tcp";
}

int reward_init(reward_t *r, uint16_t port, proto_t proto, double fallback_ttl)
{
    memset(r, 0, sizeof(*r));
    strncpy(r->table, "inet sourceknock", sizeof(r->table) - 1);
    strncpy(r->chain, "service", sizeof(r->chain) - 1);
    strncpy(r->set, "allowed", sizeof(r->set) - 1);
    r->port = port;
    r->proto = proto;
    r->fallback_ttl = fallback_ttl > 0 ? fallback_ttl : 30.0;

    char cmd[512];

    /* Table (ignore "already exists"). */
    snprintf(cmd, sizeof(cmd), "add table %s", r->table);
    run_nft_str(cmd);

    /* Set (type in_addr, per-element timeout). */
    snprintf(cmd, sizeof(cmd),
             "add set %s %s { type ipv4_addr; flags timeout; size 256; }",
             r->table, r->set);
    run_nft_str(cmd);

    /* Base chain, policy accept so other traffic is unaffected. */
    snprintf(cmd, sizeof(cmd),
             "add chain %s %s { type filter hook input priority 0; policy accept; }",
             r->table, r->chain);
    run_nft_str(cmd);

    /* Clear any prior rules (idempotent re-init). */
    snprintf(cmd, sizeof(cmd), "flush chain %s %s", r->table, r->chain);
    run_nft_str(cmd);

    /* accept for allowed IPs, then drop the port for everyone else. */
    snprintf(cmd, sizeof(cmd),
             "add rule %s %s ip saddr @%s %s dport %d accept",
             r->table, r->chain, r->set, proto_str(proto), port);
    run_nft_str(cmd);

    snprintf(cmd, sizeof(cmd),
             "add rule %s %s %s dport %d drop",
             r->table, r->chain, proto_str(proto), port);
    run_nft_str(cmd);

    r->initialized = 1;
    fprintf(stderr, "reward: service port %d/%s managed by table %s\n",
            port, proto_str(proto), r->table);
    return 0;
}

int reward_open(reward_t *r, const struct in_addr *ip, double timeout)
{
    if (!r->initialized) return -1;
    char ipstr[64];
    inet_ntop(AF_INET, &ip->s_addr, ipstr, sizeof(ipstr));

    char cmd[512];
    char to[32];
    if (timeout > 0) {
        fmt_timeout(to, sizeof(to), timeout);
        snprintf(cmd, sizeof(cmd),
                 "add element %s %s { %s timeout %s }",
                 r->table, r->set, ipstr, to);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "add element %s %s { %s }",
                 r->table, r->set, ipstr);
    }
    return run_nft_str(cmd);
}

int reward_close(reward_t *r, const struct in_addr *ip)
{
    if (!r->initialized) return -1;
    char ipstr[64];
    inet_ntop(AF_INET, &ip->s_addr, ipstr, sizeof(ipstr));

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "delete element %s %s { %s }",
             r->table, r->set, ipstr);
    return run_nft_str(cmd);
}

int reward_flush(reward_t *r)
{
    if (!r->initialized) return -1;
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "delete element %s %s { * }",
             r->table, r->set);
    return run_nft_str(cmd);
}
