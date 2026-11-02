/* config.c - minimal INI parser. */
/* POSIX: strdup / strtok_r are not in strict ISO C. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

config_t g_cfg;

static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return s;
}

/* Split "a,b,c" into uint16 tokens. Caller frees returned array. */
static char *parse_sequence(char *val, uint16_t **out, size_t *out_len,
                            char *err, size_t errlen)
{
    *out = NULL;
    *out_len = 0;
    size_t cap = 8;
    uint16_t *arr = malloc(cap * sizeof(*arr));
    if (!arr)
    {
        snprintf(err, errlen, "out of memory parsing sequence");
        return err;
    }
    char *save = NULL;
    char *tok = strtok_r(val, ",", &save);
    while (tok)
    {
        char *t = trim(tok);
        if (*t == '\0')
        {
            tok = strtok_r(NULL, ",", &save);
            continue;
        }
        char *endp = NULL;
        long v = strtol(t, &endp, 10);
        /* 0 can't be a knock port: binding source port 0 means "any". */
        if (*endp != '\0' || endp == t || v < 1 || v > 65535)
        {
            snprintf(err, errlen, "invalid port in sequence: '%s'", t);
            free(arr);
            return err;
        }
        if (*out_len == cap)
        {
            cap *= 2;
            uint16_t *na = realloc(arr, cap * sizeof(*na));
            if (!na)
            {
                free(arr);
                snprintf(err, errlen, "out of memory");
                return err;
            }
            arr = na;
        }
        arr[(*out_len)++] = (uint16_t)v;
        tok = strtok_r(NULL, ",", &save);
    }
    if (*out_len == 0)
    {
        snprintf(err, errlen, "empty sequence");
        free(arr);
        return err;
    }
    *out = arr;
    return NULL;
}

/* Parse a service-port spec into a growable uint16 array. Accepts a single
 * port, a comma-separated list, and inclusive ranges, e.g. "22", "80, 443",
 * or "8000-8002" (which expands to 8000, 8001, 8002). Each port must be in
 * 1..65535. Caller frees returned array. */
static char *parse_ports(char *val, uint16_t **out, size_t *out_len, char *err,
                         size_t errlen)
{
    *out = NULL;
    *out_len = 0;
    size_t cap = 8;
    uint16_t *arr = malloc(cap * sizeof(*arr));
    if (!arr)
    {
        snprintf(err, errlen, "out of memory parsing ports");
        return err;
    }
    char *save = NULL;
    char *tok = strtok_r(val, ",", &save);
    while (tok)
    {
        char *t = trim(tok);
        if (*t == '\0')
        {
            tok = strtok_r(NULL, ",", &save);
            continue;
        }
        char *endp = NULL;
        long lo = strtol(t, &endp, 10);
        long hi = lo;     /* default: single port */
        if (*endp == '-') /* optional inclusive range lo-hi */
            hi = strtol(endp + 1, &endp, 10);
        if (*endp != '\0' || lo < 1 || lo > 65535 || hi < 1 || hi > 65535 ||
            hi < lo)
        {
            snprintf(err, errlen, "invalid port or range: '%s'", t);
            free(arr);
            return err;
        }
        for (long v = lo; v <= hi; v++)
        {
            if (*out_len == cap)
            {
                cap *= 2;
                uint16_t *na = realloc(arr, cap * sizeof(*na));
                if (!na)
                {
                    free(arr);
                    snprintf(err, errlen, "out of memory");
                    return err;
                }
                arr = na;
            }
            arr[(*out_len)++] = (uint16_t)v;
        }
        tok = strtok_r(NULL, ",", &save);
    }
    if (*out_len == 0)
    {
        snprintf(err, errlen, "empty port list");
        free(arr);
        return err;
    }
    *out = arr;
    return NULL;
}

static proto_t parse_proto(const char *s, char *err, size_t errlen)
{
    if (strcmp(s, "tcp") == 0)
        return PROTO_TCP;
    if (strcmp(s, "udp") == 0)
        return PROTO_UDP;
    snprintf(err, errlen, "protocol must be 'tcp' or 'udp' (got '%s')", s);
    return PROTO_NONE;
}

static trigger_mode_t parse_mode(const char *s, char *err, size_t errlen)
{
    if (strcmp(s, "fixed_ttl") == 0)
        return MODE_FIXED_TTL;
    if (strcmp(s, "close_on_connect") == 0)
        return MODE_CLOSE_ON_CONNECT;
    if (strcmp(s, "permanent") == 0)
        return MODE_PERMANENT;
    snprintf(err, errlen,
             "mode must be 'fixed_ttl', 'close_on_connect', or 'permanent' "
             "(got '%s')",
             s);
    return (trigger_mode_t)-1;
}

static void free_triggers(trigger_t *trigs, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        free(trigs[i].sequence);
        free(trigs[i].ports);
        free(trigs[i].admin_sequence);
    }
    free(trigs);
}

void config_free(void)
{
    free_triggers(g_cfg.triggers, g_cfg.n_triggers);
    g_cfg.triggers = NULL;
    g_cfg.n_triggers = 0;
}

int config_table_name(const char *service, char *out, size_t outlen)
{
    int n = snprintf(out, outlen, "inet sourceknock_");
    if (n < 0 || (size_t)n >= outlen)
        return -1;
    size_t i = (size_t)n;
    for (; *service; service++)
    {
        if (i + 1 >= outlen)
            return -1; /* would be truncated */
        char c = *service;
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '_';
        out[i++] = ok ? c : '_';
    }
    out[i] = '\0';
    return 0;
}

int config_weak_sequence(const trigger_t *tr, char *msg, size_t msglen)
{
    if (tr->seq_len < 3)
    {
        snprintf(msg, msglen,
                 "sequence has only %zu port(s); use at least 3 so random "
                 "traffic can't complete it",
                 tr->seq_len);
        return 1;
    }
    for (size_t i = 0; i < tr->seq_len; i++)
    {
        if (tr->sequence[i] >= 32768 && tr->sequence[i] <= 60999)
        {
            snprintf(msg, msglen,
                     "sequence port %u is in the Linux ephemeral range "
                     "(32768-60999), which ordinary outgoing connections use",
                     tr->sequence[i]);
            return 1;
        }
    }
    return 0;
}

int config_parse_string(const char *text, char *err, size_t errlen)
{
    if (!text)
    {
        snprintf(err, errlen, "null config");
        return -1;
    }
    config_free(); /* a re-parse replaces (and frees) the previous config */
    memset(&g_cfg, 0, sizeof(g_cfg));
    strncpy(g_cfg.interface, "lo", sizeof(g_cfg.interface) - 1);

    /* Growable list of triggers, one per [trigger:NAME] section. */
    trigger_t *trigs = NULL;
    size_t n = 0, cap = 0;
    trigger_t *cur = NULL; /* the trigger currently being populated */
    char line[1024];
    char *section = NULL; /* "global" or "trigger:NAME" */
    const char *p = text;
    char errmsg[256];

    /* Advance `p` past each newline inside the body, so `continue` is safe. */
    while (*p)
    {
        /* grab next line */
        size_t i = 0;
        while (*p && *p != '\n' && i < sizeof(line) - 1)
            line[i++] = *p++;
        line[i] = '\0';
        if (*p == '\n')
            p++; /* consume the newline */

        char *s = trim(line);
        if (*s == '\0' || *s == '#' || *s == ';')
            continue;

        if (*s == '[')
        {
            char *end = strchr(s, ']');
            if (!end)
            {
                snprintf(err, errlen, "malformed section header");
                goto fail;
            }
            *end = '\0';
            free(section);
            section = strdup(trim(s + 1));
            if (!section)
            {
                snprintf(err, errlen, "out of memory");
                goto fail;
            }

            if (strcmp(section, "global") == 0)
            {
                cur = NULL;
            }
            else if (strncmp(section, "trigger:", 8) == 0)
            {
                if (*trim(section + 8) == '\0')
                {
                    snprintf(err, errlen, "[trigger:] needs a name");
                    goto fail;
                }
                if (n == cap)
                {
                    size_t ncap = cap ? cap * 2 : 4;
                    trigger_t *nt = realloc(trigs, ncap * sizeof(*trigs));
                    if (!nt)
                    {
                        snprintf(err, errlen, "out of memory");
                        goto fail;
                    }
                    trigs = nt;
                    cap = ncap;
                }
                memset(&trigs[n], 0, sizeof(*trigs));
                strncpy(trigs[n].service, section + 8,
                        sizeof(trigs[n].service) - 1);
                trigs[n].protocol = PROTO_TCP;
                trigs[n].mode = MODE_FIXED_TTL;
                trigs[n].window = 5.0;
                trigs[n].duration = 30.0;
                trigs[n].fallback_ttl = 300.0; /* safety max open time */
                n++;
                cur = &trigs[n - 1];
            }
            else
            {
                snprintf(err, errlen, "unknown section '%s'", trim(s + 1));
                goto fail;
            }
            continue;
        }

        char *eq = strchr(s, '=');
        if (!eq)
            continue;
        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);

        if (!section)
        {
            snprintf(err, errlen, "key '%s' outside of any section", key);
            goto fail;
        }
        if (strcmp(section, "global") == 0)
        {
            if (strcmp(key, "interface") == 0)
            {
                strncpy(g_cfg.interface, val, sizeof(g_cfg.interface) - 1);
            }
            else
            {
                snprintf(err, errlen, "unknown [global] key '%s'", key);
                goto fail;
            }
        }
        else if (cur)
        {
            if (strcmp(key, "service") == 0)
            {
                strncpy(cur->service, val, sizeof(cur->service) - 1);
            }
            else if (strcmp(key, "port") == 0)
            {
                free(cur->ports); /* a repeated key replaces the old value */
                cur->ports = NULL;
                cur->n_ports = 0;
                char *pe = parse_ports(val, &cur->ports, &cur->n_ports, errmsg,
                                       sizeof(errmsg));
                if (pe)
                {
                    snprintf(err, errlen, "%s", pe);
                    goto fail;
                }
            }
            else if (strcmp(key, "protocol") == 0)
            {
                cur->protocol = parse_proto(val, err, errlen);
                if (cur->protocol == PROTO_NONE)
                    goto fail;
            }
            else if (strcmp(key, "sequence") == 0)
            {
                size_t cnt;
                free(cur->sequence);
                cur->sequence = NULL;
                cur->seq_len = 0;
                char *pe = parse_sequence(val, &cur->sequence, &cnt, errmsg,
                                          sizeof(errmsg));
                if (pe)
                {
                    snprintf(err, errlen, "%s", pe);
                    goto fail;
                }
                cur->seq_len = cnt;
            }
            else if (strcmp(key, "admin_sequence") == 0)
            {
                /* Optional revoke knock. Reuses the sequence parser; an empty
                 * value leaves admin_sequence NULL (no revoke configured). */
                size_t cnt;
                free(cur->admin_sequence);
                cur->admin_sequence = NULL;
                cur->admin_seq_len = 0;
                char *ae = parse_sequence(val, &cur->admin_sequence, &cnt,
                                          errmsg, sizeof(errmsg));
                if (ae)
                {
                    snprintf(err, errlen, "%s", ae);
                    goto fail;
                }
                cur->admin_seq_len = cnt;
            }
            else if (strcmp(key, "window") == 0)
            {
                char *e;
                cur->window = strtod(val, &e);
                if (*e || cur->window <= 0)
                {
                    snprintf(err, errlen, "invalid window");
                    goto fail;
                }
            }
            else if (strcmp(key, "mode") == 0)
            {
                cur->mode = parse_mode(val, err, errlen);
                if (cur->mode == (trigger_mode_t)-1)
                    goto fail;
            }
            else if (strcmp(key, "duration") == 0)
            {
                char *e;
                cur->duration = strtod(val, &e);
                if (*e || cur->duration <= 0)
                {
                    snprintf(err, errlen, "invalid duration");
                    goto fail;
                }
            }
            else if (strcmp(key, "fallback_ttl") == 0)
            {
                char *e;
                cur->fallback_ttl = strtod(val, &e);
                if (*e || cur->fallback_ttl <= 0)
                {
                    snprintf(err, errlen, "invalid fallback_ttl");
                    goto fail;
                }
            }
            else
            {
                snprintf(err, errlen, "unknown [trigger:%s] key '%s'",
                         cur->service, key);
                goto fail;
            }
        }
        else
        {
            snprintf(err, errlen, "key '%s' outside of any section", key);
            goto fail;
        }
    }

    /* validation: every trigger needs a sequence and at least one port, and
     * each trigger's nft table name must fit and be unique. */
    for (size_t i = 0; i < n; i++)
    {
        if (!trigs[i].sequence || trigs[i].seq_len == 0)
        {
            snprintf(err, errlen, "trigger '%s': sequence is required",
                     trigs[i].service);
            goto fail;
        }
        if (!trigs[i].ports || trigs[i].n_ports == 0)
        {
            snprintf(err, errlen,
                     "trigger '%s': port is required (the service port(s) "
                     "the knock opens)",
                     trigs[i].service);
            goto fail;
        }
        if (trigs[i].service[0] == '\0')
        {
            snprintf(err, errlen, "trigger %zu: service name is empty", i + 1);
            goto fail;
        }
        char ti[CONFIG_TABLE_NAME_MAX];
        if (config_table_name(trigs[i].service, ti, sizeof(ti)) != 0)
        {
            snprintf(err, errlen,
                     "trigger '%s': service name too long for an nft table "
                     "name (max %d characters)",
                     trigs[i].service,
                     CONFIG_TABLE_NAME_MAX - 1 -
                         (int)strlen("inet sourceknock_"));
            goto fail;
        }
        for (size_t j = 0; j < i; j++)
        {
            char tj[CONFIG_TABLE_NAME_MAX];
            config_table_name(trigs[j].service, tj, sizeof(tj));
            if (strcmp(ti, tj) == 0)
            {
                snprintf(err, errlen,
                         "triggers '%s' and '%s' would share the nft table "
                         "'%s'; give them distinct service names",
                         trigs[j].service, trigs[i].service, ti);
                goto fail;
            }
        }
    }

    g_cfg.triggers = trigs;
    g_cfg.n_triggers = n;
    free(section);
    return 0;

fail:
    free_triggers(trigs, n);
    free(section);
    g_cfg.triggers = NULL;
    g_cfg.n_triggers = 0;
    return -1;
}

int config_parse_file(const char *path, char *err, size_t errlen)
{
    FILE *f = fopen(path, "r");
    if (!f)
    {
        snprintf(err, errlen, "cannot open config '%s': %s", path,
                 strerror(errno));
        return -1;
    }
    /* read whole file */
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0)
    {
        fclose(f);
        snprintf(err, errlen, "cannot size config");
        return -1;
    }
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(sz + 1);
    if (!buf)
    {
        fclose(f);
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    if (fread(buf, 1, sz, f) != (size_t)sz)
    {
        fclose(f);
        free(buf);
        snprintf(err, errlen, "read error");
        return -1;
    }
    buf[sz] = '\0';
    fclose(f);

    int rc = config_parse_string(buf, err, errlen);
    free(buf);
    return rc;
}
