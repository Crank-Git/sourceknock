// sourceknock - Developed by acidvegas in C (https://github.com/acidvegas)
// src/totp.h

/*
 * totp.h - time-based knock sequences from a shared secret (pure, portable).
 *
 * Like a 2FA code: the sequence for a trigger is derived from a secret key
 * and the current 30-second time step, so a knock someone saw stops working
 * once its step has passed. Both the daemon and the knock client use this.
 *
 *   mac   = HMAC-SHA256(key, "sourceknock-v1:" label ":" be64(step))
 *   port i = TOTP_PORT_MIN + be16(mac[2i..2i+1]) % TOTP_PORT_SPAN
 *
 * Ports stay in 1024..32767: no root needed on the client, and clear of the
 * Linux ephemeral range that ordinary outgoing connections use.
 */
#ifndef SOURCEKNOCK_TOTP_H
#define SOURCEKNOCK_TOTP_H

#include <stddef.h>
#include <stdint.h>

#define TOTP_STEP 30 /* seconds per time step */
#define TOTP_SEQ_LEN 4
#define TOTP_PORT_MIN 1024
#define TOTP_PORT_SPAN (32768 - TOTP_PORT_MIN)
#define TOTP_KEY_MIN 16  /* bytes */
#define TOTP_KEY_MAX 256 /* bytes */

#define TOTP_LABEL_KNOCK "knock"
#define TOTP_LABEL_REVOKE "revoke"

/* SHA-256 of `len` bytes into `out` (32 bytes). */
void totp_sha256(const void *data, size_t len, unsigned char out[32]);

/* HMAC-SHA256 (RFC 2104) into `out` (32 bytes). */
void totp_hmac_sha256(const void *key, size_t keylen, const void *msg,
                      size_t msglen, unsigned char out[32]);

/* The time step that unix time `t` falls in. */
long totp_step(long t);

/* The TOTP_SEQ_LEN-port sequence for `label` at time step `step`. */
void totp_sequence(const unsigned char *key, size_t keylen, const char *label,
                   long step, uint16_t out[TOTP_SEQ_LEN]);

/* Read a key file: its bytes, with trailing whitespace removed, are the key.
 * Returns 0 and fills key/keylen, or -1 with a reason in `err`. */
int totp_load_key(const char *path, unsigned char key[TOTP_KEY_MAX],
                  size_t *keylen, char *err, size_t errlen);

/* Check that the group and other users cannot read a key file. Returns 1 and
 * fills `msg` (path, mode and the chmod fix) when `mode & 077` is not zero.
 * Returns 0 otherwise. A stat() failure also returns 0: totp_load_key()
 * reports that error. */
int totp_key_mode_warning(const char *path, char *msg, size_t msglen);

#endif /* SOURCEKNOCK_TOTP_H */
