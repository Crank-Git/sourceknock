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
    uint16_t    port;               /* hidden service port to open */
    proto_t     protocol;           /* PROTO_TCP / PROTO_UDP */
    uint16_t   *sequence;           /* source-port knock sequence */
    size_t      seq_len;
    double      window;             /* whole sequence must finish within this */
    trigger_mode_t mode;
    double      duration;           /* seconds, for MODE_FIXED_TTL */
} trigger_t;

typedef struct {
    char        interface[64];
    trigger_t   trigger;
    int         has_trigger;
} config_t;

/* Populate *cfg from a NUL-terminated config string. Returns 0 on success,
 * -1 on error (message written to `err`, up to errlen). */
int config_parse_string(const char *text, char *err, size_t errlen);

/* Load from a file path. Returns 0 on success. */
int config_parse_file(const char *path, char *err, size_t errlen);

extern config_t g_cfg;   /* populated by the above; used by the daemon */

#endif /* SOURCEKNOCK_CONFIG_H */
