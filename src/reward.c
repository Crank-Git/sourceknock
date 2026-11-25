/* reward.c - nftables reward mechanism (Linux). */
/* Must precede every include (see capture.c). */
#define _POSIX_C_SOURCE 200809L
#include "reward.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Run `nft <args...>`. Returns child exit status, -1 on exec failure. With
 * `quiet`, nft's own error output is discarded (for commands whose failure is
 * expected, e.g. deleting an element that may not exist). */
static int run_nft(char **args, int quiet)
{
    pid_t pid = fork();
    if (pid == 0)
    {
        if (quiet && !freopen("/dev/null", "w", stderr))
            _exit(127);
        /* The daemon runs as root; don't let a hostile PATH redirect the
         * nft binary. Pin a sane PATH in the child before exec. */
        setenv("PATH", "/usr/sbin:/sbin:/usr/bin:/bin", 1);
        execvp("nft", args);
        fprintf(stderr, "reward: exec nft failed: %s\n", strerror(errno));
        _exit(127);
    }
    if (pid < 0)
    {
        fprintf(stderr, "reward: fork(): %s\n", strerror(errno));
        return -1;
    }
    int status = 0;
    pid_t w;
    do
        w = waitpid(pid, &status, 0);
    while (w < 0 && errno == EINTR);
    if (w < 0)
    {
        fprintf(stderr, "reward: waitpid(): %s\n", strerror(errno));
        return -1;
    }
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -1;
}

/* Run `nft <cmd>` where cmd is whitespace-separated tokens. Returns 0 on
 * nft exit 0. */
static int run_nft_cmd(const char *cmd, int quiet)
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

    int rc = run_nft(argv, quiet);
    if (rc != 0 && !quiet)
        fprintf(stderr, "reward: nft '%s' failed (exit %d)\n", cmd, rc);
    return rc == 0 ? 0 : -1;
}

static int run_nft_str(const char *cmd) { return run_nft_cmd(cmd, 0); }

/* Format a timeout in seconds as an nft duration string. */
static void fmt_timeout(char *out, size_t outlen, double secs)
{
    long s = (long)secs;
    if ((double)s != secs)
    {
        /* Fractional seconds (e.g. fallback_ttl = 1.5): use milliseconds
         * rather than truncating, which could produce a 0s timeout. */
        long ms = (long)(secs * 1000.0 + 0.5);
        snprintf(out, outlen, "%ldms", ms > 0 ? ms : 1);
    }
    else if (s % 60 == 0 && s >= 60)
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

/* Append printf-style text at buf[*used]. Returns -1 when it does not fit. */
static int emit(char *buf, size_t len, size_t *used, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
static int emit(char *buf, size_t len, size_t *used, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *used, len - *used, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= len - *used)
        return -1;
    *used += (size_t)n;
    return 0;
}

#define OWNER_PREFIX "sourceknock:"
#define COMMENT_MAX 128 /* nft refuses a longer comment */

int reward_owner_mark(char *out, size_t len, const char *config_path)
{
    size_t plen = strlen(OWNER_PREFIX);
    size_t n = strlen(config_path);
    if (n == 0 || plen + n > COMMENT_MAX || plen + n >= len)
        return -1;
    for (size_t i = 0; i < n; i++)
    {
        unsigned char c = (unsigned char)config_path[i];
        if (c < 0x20 || c == 0x7f || c == '"' || c == '\\')
            return -1;
    }
    memcpy(out, OWNER_PREFIX, plen);
    memcpy(out + plen, config_path, n + 1);
    return 0;
}

int reward_parse_owner(const char *listing, char *out, size_t len)
{
    /* Skip the "table inet NAME {" line; the table's comment is the next
     * non-blank line when it exists. */
    const char *p = strchr(listing, '\n');
    if (!p)
        return 0;
    while (*p == '\n' || *p == ' ' || *p == '\t')
        p++;
    static const char key[] = "comment \"";
    if (strncmp(p, key, strlen(key)) != 0)
        return 0;
    p += strlen(key);
    const char *end = p;
    while (*end && *end != '"' && *end != '\n')
        end++;
    if (*end != '"' || (size_t)(end - p) >= len)
        return 0;
    memcpy(out, p, (size_t)(end - p));
    out[end - p] = '\0';
    return 1;
}

int reward_script(char *buf, size_t len, const char *table,
                  const char *config_path, const char *iface,
                  close_on_t close_on, const uint16_t *ports, size_t n_ports,
                  proto_t proto, long max_allowed)
{
    if (len == 0)
        return -1;
    buf[0] = '\0';
    char owner[COMMENT_MAX + 1];
    if (reward_owner_mark(owner, sizeof(owner), config_path) != 0)
        return -1;
    size_t u = 0;
    const char *chain = "service";
    const char *v4 = "allowed_v4";
    const char *v6 = "allowed_v6";
    int bad = 0; /* any emit() that did not fit */

    /* `add` is idempotent for an identical table/set/chain, so only a real
     * conflict fails the transaction. The comment marks the table as ours; on
     * a table that already exists nft keeps the old comment. */
    bad |=
        emit(buf, len, &u, "add table %s { comment \"%s\"; }\n", table, owner);

    /* Per-family allowed sets (per-element timeout). */
    bad |= emit(buf, len, &u,
                "add set %s %s { type ipv4_addr; flags timeout; size %ld; }\n",
                table, v4, max_allowed);
    bad |= emit(buf, len, &u,
                "add set %s %s { type ipv6_addr; flags timeout; size %ld; }\n",
                table, v6, max_allowed);

    /* Base chain, policy accept so other traffic is unaffected. */
    bad |= emit(buf, len, &u,
                "add chain %s %s { type filter hook input priority 0; policy "
                "accept; }\n",
                table, chain);

    /* Clear any prior rules (idempotent re-init). */
    bad |= emit(buf, len, &u, "flush chain %s %s\n", table, chain);

    /* Let established flows through before any drop rule. A drop in any base
     * chain is final in nftables (an accept elsewhere can't override it), so
     * without this, removing an IP from the allowed set - TTL expiry, close on
     * connect, admin revoke - and even starting the daemon would cut sessions
     * that are already open. Only NEW connections are gated by the knock. */
    bad |= emit(buf, len, &u,
                "add rule %s %s ct state established,related accept\n", table,
                chain);

    /* One accept (per family) + one drop rule per service port. The drop rule
     * matches both families in an inet table. Adding an IP to the allowed set
     * opens every port, since each accept rule references that set. */
    for (size_t i = 0; i < n_ports; i++)
    {
        unsigned port = ports[i];
        bad |= emit(buf, len, &u,
                    "add rule %s %s ip saddr @%s %s dport %u accept\n", table,
                    chain, v4, proto_str(proto), port);
        bad |= emit(buf, len, &u,
                    "add rule %s %s ip6 saddr @%s %s dport %u accept\n", table,
                    chain, v6, proto_str(proto), port);

        /* TCP sessions that were open before conntrack started tracking them
         * (e.g. the admin's SSH session when the daemon first starts on a host
         * with no other stateful firewall) show up as ct state "new" on their
         * first mid-stream packet. Accept segments that carry ACK but not SYN:
         * they can never open a connection (that needs a SYN), and a stray ACK
         * gets a RST whether or not the port is open, so this leaks nothing to
         * a scanner. Once accepted, conntrack picks the flow up. */
        if (proto == PROTO_TCP)
            bad |= emit(buf, len, &u,
                        "add rule %s %s tcp dport %u tcp flags & (syn | ack) "
                        "== ack accept\n",
                        table, chain, port);

        /* close_on = interface: only the trigger's own interface, so other
         * interfaces (a VPN, loopback) are left alone and never lock anyone
         * out. close_on = all: every interface, so the port is closed on a
         * second public interface too. */
        if (close_on == CLOSE_ON_ALL)
            bad |= emit(buf, len, &u, "add rule %s %s %s dport %u drop\n",
                        table, chain, proto_str(proto), port);
        else
            bad |= emit(buf, len, &u,
                        "add rule %s %s iifname \"%s\" %s dport %u drop\n",
                        table, chain, iface, proto_str(proto), port);
    }
    return bad ? -1 : 0;
}

/* Feed `script` to `nft -f -` on stdin. nft applies the whole script as one
 * netlink transaction: it either all takes effect or none of it does, so a
 * failure never leaves a drop rule without its accept rules. Returns 0 on nft
 * exit 0. */
static int run_nft_script(const char *script)
{
    int fds[2];
    if (pipe(fds) < 0)
    {
        fprintf(stderr, "reward: pipe(): %s\n", strerror(errno));
        return -1;
    }
    pid_t pid = fork();
    if (pid == 0)
    {
        close(fds[1]);
        if (dup2(fds[0], STDIN_FILENO) < 0)
            _exit(127);
        close(fds[0]);
        /* Same pinned PATH as run_nft(). */
        setenv("PATH", "/usr/sbin:/sbin:/usr/bin:/bin", 1);
        execlp("nft", "nft", "-f", "-", (char *)NULL);
        fprintf(stderr, "reward: exec nft failed: %s\n", strerror(errno));
        _exit(127);
    }
    close(fds[0]);
    if (pid < 0)
    {
        fprintf(stderr, "reward: fork(): %s\n", strerror(errno));
        close(fds[1]);
        return -1;
    }
    /* nft may exit before it reads everything; a write to the closed pipe
     * must return EPIPE here, not kill the daemon with SIGPIPE. */
    void (*old_pipe)(int) = signal(SIGPIPE, SIG_IGN);
    size_t off = 0, len = strlen(script);
    int werr = 0;
    while (off < len)
    {
        ssize_t w = write(fds[1], script + off, len - off);
        if (w < 0)
        {
            if (errno == EINTR)
                continue;
            werr = 1;
            break;
        }
        off += (size_t)w;
    }
    close(fds[1]);
    signal(SIGPIPE, old_pipe);

    int status = 0;
    pid_t w;
    do
        w = waitpid(pid, &status, 0);
    while (w < 0 && errno == EINTR);
    if (w < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0 || werr)
    {
        fprintf(stderr, "reward: nft -f - failed\n");
        return -1;
    }
    return 0;
}

int reward_init(reward_t *r, const char *table, const char *config_path,
                const char *iface, close_on_t close_on, const uint16_t *ports,
                size_t n_ports, proto_t proto, double fallback_ttl,
                long max_allowed)
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

    /* The fixed lines and each port's rules stay well inside these bounds
     * (table and interface names are at most 64 bytes each, the owner mark
     * 128). */
    size_t cap = 1280 + n_ports * 640;
    char *script = malloc(cap);
    if (!script)
        return -1;
    int failed = reward_script(script, cap, r->table, config_path, iface,
                               close_on, ports, n_ports, proto, max_allowed);
    if (!failed)
        failed = run_nft_script(script);
    free(script);

    if (failed)
    {
        /* The script is one nft transaction, so a failed run applied nothing:
         * no half-built table exists. Do not delete the table. On a reload it
         * is the live one, and deleting it would open the port and empty the
         * allowed sets. */
        fprintf(stderr,
                "reward: could not program nftables table %s (is nft "
                "installed, and do we have CAP_NET_ADMIN?)\n",
                r->table);
        return -1;
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
        /* `add element` on an element that already exists is a no-op and
         * keeps its old timeout, so a re-knock would not restart the clock.
         * Drop any existing element first (it may well not exist). */
        snprintf(cmd, sizeof(cmd), "delete element %s %s { %s }", r->table, set,
                 ipstr);
        run_nft_cmd(cmd, 1);
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

int reward_destroy(reward_t *r)
{
    if (!r->initialized)
        return -1;
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "delete table %s", r->table);
    r->initialized = 0;
    return run_nft_str(cmd);
}

/* Read all of a command's stdout (up to cap-1 bytes) into `buf`. Returns 0 on
 * success, -1 when it cannot run or exits non-zero. */
static int read_cmd(const char *cmd, char *buf, size_t cap)
{
    FILE *f = popen(cmd, "r");
    if (!f)
        return -1;
    size_t used = 0, n;
    char chunk[512];
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0)
    {
        if (used + n >= cap)
            n = cap - 1 - used; /* keep draining so nft does not get SIGPIPE */
        memcpy(buf + used, chunk, n);
        used += n;
    }
    buf[used] = '\0';
    return pclose(f) == 0 ? 0 : -1;
}

/* Only characters that need no shell quoting: the name goes into a command. */
static int safe_table_name(const char *name)
{
    for (const char *c = name; *c; c++)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') ||
              (*c >= '0' && *c <= '9') || *c == '_' || *c == '-' || *c == '.'))
            return 0;
    return 1;
}

int reward_prune_stale(const char *config_path, const char *const *keep,
                       size_t n_keep)
{
    char mine[COMMENT_MAX + 1];
    if (reward_owner_mark(mine, sizeof(mine), config_path) != 0)
        return -1;
    /* Same pinned PATH as run_nft(). */
    FILE *f =
        popen("PATH=/usr/sbin:/sbin:/usr/bin:/bin nft list tables inet", "r");
    if (!f)
    {
        fprintf(stderr, "reward: cannot list nft tables: %s\n",
                strerror(errno));
        return -1;
    }
    int rc = 0;
    char line[320];
    char name[256];
    while (fgets(line, sizeof(line), f))
    {
        if (sscanf(line, "table inet %255s", name) != 1 ||
            strncmp(name, "sourceknock_", strlen("sourceknock_")) != 0)
            continue;
        char full[300];
        snprintf(full, sizeof(full), "inet %s", name);
        int kept = 0;
        for (size_t i = 0; i < n_keep && !kept; i++)
            kept = strcmp(full, keep[i]) == 0;
        if (kept)
            continue;

        /* Delete only a table that carries our mark. */
        char owner[COMMENT_MAX + 1] = "";
        int has_owner = 0;
        if (safe_table_name(name))
        {
            char cmd[400];
            char listing[4096];
            snprintf(cmd, sizeof(cmd),
                     "PATH=/usr/sbin:/sbin:/usr/bin:/bin nft list table inet "
                     "%s 2>/dev/null",
                     name);
            if (read_cmd(cmd, listing, sizeof(listing)) == 0)
                has_owner = reward_parse_owner(listing, owner, sizeof(owner));
        }
        if (!has_owner || strcmp(owner, mine) != 0)
        {
            fprintf(stderr,
                    "reward: warning: table %s is not owned by this config "
                    "(%s); leaving it\n",
                    full, has_owner ? owner : "no owner mark");
            continue;
        }
        char cmd[320];
        snprintf(cmd, sizeof(cmd), "delete table %s", full);
        if (run_nft_str(cmd) == 0)
            fprintf(stderr, "reward: removed stale table %s (not in config)\n",
                    full);
        else
            rc = -1;
    }
    if (pclose(f) != 0)
    {
        fprintf(stderr, "reward: 'nft list tables' failed\n");
        rc = -1;
    }
    return rc;
}

int reward_flush(reward_t *r)
{
    if (!r->initialized)
        return -1;
    char cmd[512];
    /* Remove every element from both family sets. (`delete element ... { * }`
     * is not valid nft syntax; it always failed, so nothing was flushed.) */
    snprintf(cmd, sizeof(cmd), "flush set %s %s", r->table, r->set_v4);
    int rc = run_nft_str(cmd);
    snprintf(cmd, sizeof(cmd), "flush set %s %s", r->table, r->set_v6);
    return run_nft_str(cmd) | rc;
}
