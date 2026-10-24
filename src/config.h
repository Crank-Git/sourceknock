/*
 * config.h - INI-style configuration (knockd-flavoured).
 *
 * Pure parsing (no I/O beyond reading a file / a string), so it is unit
 * testable here. The daemon owns opening the file and applying the config.
 */
#ifndef SOURCEKNOCK_CONFIG_H
#define SOURCEKNOCK_CONFIG_H

#include <stddef.h>
#include <stdint.h>
#include "packet.h"

typedef enum {
    MODE_FIXED_TTL = 0,     /* keep the port open for `duration` seconds */
    MODE_CLOSE_ON_CONNECT   /* close as soon as the client connects */
} trigger_mode_t;

typedef struct {
    char        service[64];
    uint16_t   *ports;              /* hidden service ports to open */
    size_t      n_ports;            /* number of entries in `ports` */
    proto_t     protocol;           /* PROTO_TCP / PROTO_UDP */
    uint16_t   *sequence;           /* source-port knock sequence */
    size_t      seq_len;
    double      window;             /* whole sequence must finish within this */
    trigger_mode_t mode;
    double      duration;           /* seconds, for MODE_FIXED_TTL */
    double      fallback_ttl;       /* safety max open time (close_on_connect) */
} trigger_t;

typedef struct {
    char        interface[64];
    trigger_t  *triggers;   /* n_triggers entries; each owns `sequence` */
    size_t      n_triggers;
} config_t;

/* Populate *cfg from a NUL-terminated config string. Returns 0 on success,
 * -1 on error (message written to `err`, up to errlen). */
int config_parse_string(const char *text, char *err, size_t errlen);

/* Load from a file path. Returns 0 on success. */
int config_parse_file(const char *path, char *err, size_t errlen);

extern config_t g_cfg;   /* populated by the above; used by the daemon */

#endif /* SOURCEKNOCK_CONFIG_H */
