/*
 * config.h - INI-style configuration (knockd-flavoured).
 *
 * Pure parsing (no I/O beyond reading a file / a string), so it is unit
 * testable here. The daemon owns opening the file and applying the config.
 */
#ifndef SOURCEKNOCK_CONFIG_H
#define SOURCEKNOCK_CONFIG_H

#include "packet.h"
#include <stddef.h>
#include <stdint.h>

typedef enum
{
    MODE_FIXED_TTL = 0,    /* keep the port open for `duration` seconds */
    MODE_CLOSE_ON_CONNECT, /* close as soon as the client connects */
    MODE_PERMANENT         /* open with no timeout; revoke via admin_sequence */
} trigger_mode_t;

typedef struct
{
    char service[64];
    uint16_t *ports;    /* hidden service ports to open */
    size_t n_ports;     /* number of entries in `ports` */
    proto_t protocol;   /* PROTO_TCP / PROTO_UDP */
    uint16_t *sequence; /* source-port knock sequence */
    size_t seq_len;
    uint16_t *admin_sequence; /* optional: revoke knock (removes IP) */
    size_t admin_seq_len;
    double window; /* whole sequence must finish within this */
    trigger_mode_t mode;
    double duration;     /* seconds, for MODE_FIXED_TTL */
    double fallback_ttl; /* safety max open time (close_on_connect) */
} trigger_t;

typedef struct
{
    char interface[64];
    trigger_t *triggers; /* n_triggers entries; each owns `sequence` */
    size_t n_triggers;
} config_t;

/* Populate *cfg from a NUL-terminated config string. Returns 0 on success,
 * -1 on error (message written to `err`, up to errlen). */
int config_parse_string(const char *text, char *err, size_t errlen);

/* Load from a file path. Returns 0 on success. */
int config_parse_file(const char *path, char *err, size_t errlen);

/* Free the triggers owned by g_cfg (safe to call more than once). */
void config_free(void);

/* Size of reward_t's table buffer: the full nft table name incl. NUL. */
#define CONFIG_TABLE_NAME_MAX 64

/* Build the nft table name for a service: "inet sourceknock_<service>", with
 * the service sanitized to [A-Za-z0-9_]. Returns -1 (instead of truncating)
 * if it would not fit in `outlen`. */
int config_table_name(const char *service, char *out, size_t outlen);

/* Returns 1 and a human-readable reason in `msg` if the trigger's sequence is
 * weak (fewer than 3 ports, or a port in the Linux ephemeral range that
 * ordinary outgoing traffic uses), else 0. Advisory: the daemon warns. */
int config_weak_sequence(const trigger_t *tr, char *msg, size_t msglen);

extern config_t g_cfg; /* populated by the above; used by the daemon */

#endif /* SOURCEKNOCK_CONFIG_H */
