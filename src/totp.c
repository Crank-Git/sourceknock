// sourceknock - Developed by acidvegas in C (https://github.com/acidvegas)
// src/totp.c

/* totp.c - SHA-256, HMAC-SHA256 and time-based knock sequences. */
#include "totp.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* ---- SHA-256 (FIPS 180-4) ---- */

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

typedef struct
{
    uint32_t h[8];
    unsigned char buf[64];
    size_t buflen;
    uint64_t total; /* bytes */
} sha256_t;

static uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_block(sha256_t *s, const unsigned char *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 |
               (uint32_t)p[4 * i + 2] << 8 | (uint32_t)p[4 * i + 3];
    for (int i = 16; i < 64; i++)
    {
        uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4],
             f = s->h[5], g = s->h[6], h = s->h[7];
    for (int i = 0; i < 64; i++)
    {
        uint32_t t1 = h + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) +
                      ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) +
                      ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    s->h[0] += a;
    s->h[1] += b;
    s->h[2] += c;
    s->h[3] += d;
    s->h[4] += e;
    s->h[5] += f;
    s->h[6] += g;
    s->h[7] += h;
}

static void sha256_init(sha256_t *s)
{
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                   0xa54ff53a, 0x510e527f, 0x9b05688c,
                                   0x1f83d9ab, 0x5be0cd19};
    memcpy(s->h, iv, sizeof(iv));
    s->buflen = 0;
    s->total = 0;
}

static void sha256_update(sha256_t *s, const void *data, size_t len)
{
    const unsigned char *p = data;
    s->total += len;
    while (len)
    {
        size_t n = 64 - s->buflen;
        if (n > len)
            n = len;
        memcpy(s->buf + s->buflen, p, n);
        s->buflen += n;
        p += n;
        len -= n;
        if (s->buflen == 64)
        {
            sha256_block(s, s->buf);
            s->buflen = 0;
        }
    }
}

static void sha256_final(sha256_t *s, unsigned char out[32])
{
    uint64_t bits = s->total * 8;
    unsigned char pad = 0x80;
    sha256_update(s, &pad, 1);
    pad = 0;
    while (s->buflen != 56)
        sha256_update(s, &pad, 1);
    unsigned char len[8];
    for (int i = 0; i < 8; i++)
        len[i] = (unsigned char)(bits >> (56 - 8 * i));
    sha256_update(s, len, 8);
    for (int i = 0; i < 8; i++)
    {
        out[4 * i] = (unsigned char)(s->h[i] >> 24);
        out[4 * i + 1] = (unsigned char)(s->h[i] >> 16);
        out[4 * i + 2] = (unsigned char)(s->h[i] >> 8);
        out[4 * i + 3] = (unsigned char)s->h[i];
    }
}

void totp_sha256(const void *data, size_t len, unsigned char out[32])
{
    sha256_t s;
    sha256_init(&s);
    sha256_update(&s, data, len);
    sha256_final(&s, out);
}

/* ---- HMAC-SHA256 (RFC 2104) ---- */

void totp_hmac_sha256(const void *key, size_t keylen, const void *msg,
                      size_t msglen, unsigned char out[32])
{
    unsigned char k[64] = {0};
    if (keylen > 64)
        totp_sha256(key, keylen, k); /* long keys are hashed first */
    else
        memcpy(k, key, keylen);

    unsigned char ipad[64], opad[64];
    for (int i = 0; i < 64; i++)
    {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    unsigned char inner[32];
    sha256_t s;
    sha256_init(&s);
    sha256_update(&s, ipad, 64);
    sha256_update(&s, msg, msglen);
    sha256_final(&s, inner);
    sha256_init(&s);
    sha256_update(&s, opad, 64);
    sha256_update(&s, inner, 32);
    sha256_final(&s, out);
}

/* ---- knock sequences ---- */

long totp_step(long t)
{
    return t >= 0 ? t / TOTP_STEP : -((-t + TOTP_STEP - 1) / TOTP_STEP);
}

void totp_sequence(const unsigned char *key, size_t keylen, const char *label,
                   long step, uint16_t out[TOTP_SEQ_LEN])
{
    unsigned char msg[96];
    int n = snprintf((char *)msg, sizeof(msg) - 8, "sourceknock-v1:%s:", label);
    size_t len = (size_t)n;
    uint64_t s = (uint64_t)step;
    for (int i = 0; i < 8; i++)
        msg[len++] = (unsigned char)(s >> (56 - 8 * i));
    unsigned char mac[32];
    totp_hmac_sha256(key, keylen, msg, len, mac);
    for (int i = 0; i < TOTP_SEQ_LEN; i++)
    {
        unsigned v = (unsigned)mac[2 * i] << 8 | mac[2 * i + 1];
        out[i] = (uint16_t)(TOTP_PORT_MIN + v % TOTP_PORT_SPAN);
    }
}

int totp_load_key(const char *path, unsigned char key[TOTP_KEY_MAX],
                  size_t *keylen, char *err, size_t errlen)
{
    FILE *f = fopen(path, "rb");
    if (!f)
    {
        snprintf(err, errlen, "cannot read secret_file '%s': %s", path,
                 strerror(errno));
        return -1;
    }
    unsigned char buf[TOTP_KEY_MAX + 1];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    while (n > 0 && isspace(buf[n - 1]))
        n--;
    if (n > TOTP_KEY_MAX)
    {
        snprintf(err, errlen, "secret_file '%s': longer than %d bytes", path,
                 TOTP_KEY_MAX);
        return -1;
    }
    if (n < TOTP_KEY_MIN)
    {
        snprintf(err, errlen,
                 "secret_file '%s': secret is %zu byte(s), need at least %d",
                 path, n, TOTP_KEY_MIN);
        return -1;
    }
    memcpy(key, buf, n);
    *keylen = n;
    return 0;
}
