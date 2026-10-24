/* config.c - minimal INI parser. */
/* POSIX: strdup / strtok_r are not in strict ISO C. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

config_t g_cfg;

static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) *--end = '\0';
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
    if (!arr) {
        snprintf(err, errlen, "out of memory parsing sequence");
        return err;
    }
    char *save = NULL;
    char *tok = strtok_r(val, ",", &save);
    while (tok) {
        char *t = trim(tok);
        if (*t == '\0') { tok = strtok_r(NULL, ",", &save); continue; }
        char *endp = NULL;
        long v = strtol(t, &endp, 10);
        if (*endp != '\0' || v < 0 || v > 65535) {
            snprintf(err, errlen, "invalid port in sequence: '%s'", t);
            free(arr);
            return err;
        }
        if (*out_len == cap) {
            cap *= 2;
            uint16_t *na = realloc(arr, cap * sizeof(*na));
            if (!na) { free(arr); snprintf(err, errlen, "out of memory"); return err; }
            arr = na;
        }
        arr[(*out_len)++] = (uint16_t)v;
        tok = strtok_r(NULL, ",", &save);
    }
    if (*out_len == 0) {
        snprintf(err, errlen, "empty sequence");
        free(arr);
        return err;
    }
    *out = arr;
    *out_len = *out_len;
    return NULL;
}

static proto_t parse_proto(const char *s, char *err, size_t errlen)
{
    if (strcmp(s, "tcp") == 0) return PROTO_TCP;
    if (strcmp(s, "udp") == 0) return PROTO_UDP;
    snprintf(err, errlen, "protocol must be 'tcp' or 'udp' (got '%s')", s);
    return PROTO_NONE;
}

static trigger_mode_t parse_mode(const char *s, char *err, size_t errlen)
{
    if (strcmp(s, "fixed_ttl") == 0)  return MODE_FIXED_TTL;
    if (strcmp(s, "close_on_connect") == 0) return MODE_CLOSE_ON_CONNECT;
    snprintf(err, errlen, "mode must be 'fixed_ttl' or 'close_on_connect' (got '%s')", s);
    return (trigger_mode_t)-1;
}

int config_parse_string(const char *text, char *err, size_t errlen)
{
    if (!text) { snprintf(err, errlen, "null config"); return -1; }
    memset(&g_cfg, 0, sizeof(g_cfg));
    strncpy(g_cfg.interface, "lo", sizeof(g_cfg.interface) - 1);

    strncpy(g_cfg.trigger.service, "service", sizeof(g_cfg.trigger.service) - 1);
    g_cfg.trigger.protocol = PROTO_TCP;
    g_cfg.trigger.mode = MODE_FIXED_TTL;
    g_cfg.trigger.window = 5.0;
    g_cfg.trigger.duration = 30.0;

    char line[1024];
    char *section = NULL;   /* "global" or "trigger:NAME" */
    const char *p = text;
    char errmsg[256];

    /* Advance `p` past each newline inside the body, so `continue` is safe. */
    while (*p) {
        /* grab next line */
        size_t i = 0;
        while (*p && *p != '\n' && i < sizeof(line) - 1) line[i++] = *p++;
        line[i] = '\0';
        if (*p == '\n') p++;   /* consume the newline */

        char *s = trim(line);
        if (*s == '\0' || *s == '#' || *s == ';') continue;

        if (*s == '[') {
            char *end = strchr(s, ']');
            if (!end) { snprintf(err, errlen, "malformed section header"); return -1; }
            *end = '\0';
            free(section);
            section = strdup(trim(s + 1));
            continue;
        }

        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);

        if (strcmp(section, "global") == 0) {
            if (strcmp(key, "interface") == 0) {
                strncpy(g_cfg.interface, val, sizeof(g_cfg.interface) - 1);
            } else {
                snprintf(errmsg, sizeof(errmsg), "unknown [global] key '%s'", key);
                snprintf(err, errlen, "%s", errmsg);
                return -1;
            }
        } else if (strncmp(section, "trigger:", 8) == 0) {
            trigger_t *tr = &g_cfg.trigger;
            if (strcmp(key, "service") == 0) {
                strncpy(tr->service, val, sizeof(tr->service) - 1);
            } else if (strcmp(key, "port") == 0) {
                char *e; long v = strtol(val, &e, 10);
                if (*e || v < 0 || v > 65535) { snprintf(err, errlen, "invalid port"); return -1; }
                tr->port = (uint16_t)v;
            } else if (strcmp(key, "protocol") == 0) {
                tr->protocol = parse_proto(val, err, errlen);
                if (tr->protocol == PROTO_NONE) return -1;
            } else if (strcmp(key, "sequence") == 0) {
                size_t n;
                char *pe = parse_sequence(val, &tr->sequence, &n, errmsg, sizeof(errmsg));
                if (pe) { snprintf(err, errlen, "%s", pe); return -1; }
                tr->seq_len = n;
            } else if (strcmp(key, "window") == 0) {
                char *e; tr->window = strtod(val, &e);
                if (*e || tr->window <= 0) { snprintf(err, errlen, "invalid window"); return -1; }
            } else if (strcmp(key, "mode") == 0) {
                tr->mode = parse_mode(val, err, errlen);
                if (tr->mode == (trigger_mode_t)-1) return -1;
            } else if (strcmp(key, "duration") == 0) {
                char *e; tr->duration = strtod(val, &e);
                if (*e || tr->duration <= 0) { snprintf(err, errlen, "invalid duration"); return -1; }
            } else {
                snprintf(err, errlen, "unknown [trigger] key '%s'", key);
                return -1;
            }
        } else {
            snprintf(err, errlen, "key '%s' outside of any section", key);
            return -1;
        }
    }

    free(section);

    /* validation */
    if (!g_cfg.trigger.sequence || g_cfg.trigger.seq_len == 0) {
        snprintf(err, errlen, "trigger.sequence is required");
        return -1;
    }
    if (!g_cfg.has_trigger) { /* nothing enforced yet; accept */ }
    g_cfg.has_trigger = 1;
    return 0;
}

int config_parse_file(const char *path, char *err, size_t errlen)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(err, errlen, "cannot open config '%s': %s", path, strerror(errno));
        return -1;
    }
    /* read whole file */
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0) { fclose(f); snprintf(err, errlen, "cannot size config"); return -1; }
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); snprintf(err, errlen, "out of memory"); return -1; }
    if (fread(buf, 1, sz, f) != (size_t)sz) {
        fclose(f); free(buf); snprintf(err, errlen, "read error"); return -1;
    }
    buf[sz] = '\0';
    fclose(f);

    int rc = config_parse_string(buf, err, errlen);
    free(buf);
    return rc;
}
