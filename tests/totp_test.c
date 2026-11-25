// sourceknock - Developed by acidvegas in C (https://github.com/acidvegas)
// tests/totp_test.c

/* totp_test.c - SHA-256 / HMAC against published vectors, and sequences. */
#include <stdio.h>
#include <string.h>

#include "test.h"
#include "totp.h"

static void hex(const unsigned char *b, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++)
        sprintf(out + 2 * i, "%02x", b[i]);
}

static void check_sha(const char *msg, size_t len, const char *want)
{
    unsigned char d[32];
    char h[65];
    totp_sha256(msg, len, d);
    hex(d, 32, h);
    CHECK_EQ_STR(h, want);
}

/* FIPS 180-2 examples, plus lengths around the 55/56/64-byte padding edges. */
static void test_sha256(void)
{
    check_sha(
        "", 0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    check_sha(
        "abc", 3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const char *m2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    check_sha(
        m2, strlen(m2),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    static char a[1000000];
    memset(a, 'a', sizeof(a));
    check_sha(
        a, sizeof(a),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

static void check_hmac(const void *key, size_t kl, const void *msg, size_t ml,
                       const char *want)
{
    unsigned char d[32];
    char h[65];
    totp_hmac_sha256(key, kl, msg, ml, d);
    hex(d, 32, h);
    CHECK_EQ_STR(h, want);
}

/* RFC 4231 test cases 1, 2, 3 and 6 (a key longer than the block size). */
static void test_hmac(void)
{
    unsigned char k1[20];
    memset(k1, 0x0b, sizeof(k1));
    check_hmac(
        k1, 20, "Hi There", 8,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    check_hmac(
        "Jefe", 4, "what do ya want for nothing?", 28,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    unsigned char k3[20], m3[50];
    memset(k3, 0xaa, sizeof(k3));
    memset(m3, 0xdd, sizeof(m3));
    check_hmac(
        k3, 20, m3, 50,
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    unsigned char k6[131];
    memset(k6, 0xaa, sizeof(k6));
    const char *m6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    check_hmac(
        k6, sizeof(k6), m6, strlen(m6),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

static void test_step(void)
{
    CHECK_EQ_INT(totp_step(0), 0);
    CHECK_EQ_INT(totp_step(29), 0);
    CHECK_EQ_INT(totp_step(30), 1);
    CHECK_EQ_INT(totp_step(1700000000), 1700000000 / 30);
    CHECK_EQ_INT(totp_step(-1), -1);
}

/* Deterministic, in range, and different per key, label and step. */
static void test_sequence(void)
{
    const unsigned char key[] = "0123456789abcdef0123456789abcdef";
    uint16_t a[TOTP_SEQ_LEN], b[TOTP_SEQ_LEN];
    totp_sequence(key, 32, TOTP_LABEL_KNOCK, 1000, a);
    totp_sequence(key, 32, TOTP_LABEL_KNOCK, 1000, b);
    CHECK(memcmp(a, b, sizeof(a)) == 0);
    for (int i = 0; i < TOTP_SEQ_LEN; i++)
        CHECK(a[i] >= 1024 && a[i] <= 32767);
    totp_sequence(key, 32, TOTP_LABEL_KNOCK, 1001, b);
    CHECK(memcmp(a, b, sizeof(a)) != 0);
    totp_sequence(key, 32, TOTP_LABEL_REVOKE, 1000, b);
    CHECK(memcmp(a, b, sizeof(a)) != 0);
    totp_sequence((const unsigned char *)"0123456789abcdef0123456789abcdeX", 32,
                  TOTP_LABEL_KNOCK, 1000, b);
    CHECK(memcmp(a, b, sizeof(a)) != 0);

    /* Pinned output (cross-checked with Python's hmac module): the daemon
     * and every client build must derive the same ports. */
    char got[64];
    snprintf(got, sizeof(got), "%u,%u,%u,%u", a[0], a[1], a[2], a[3]);
    CHECK_EQ_STR(got, "16041,27812,1929,8622");
}

static void test_load_key(void)
{
    char err[256];
    unsigned char key[TOTP_KEY_MAX];
    size_t kl = 0;
    const char *p = "totp_test.key";
    FILE *f = fopen(p, "w");
    fputs("0123456789abcdef0123\n\n", f);
    fclose(f);
    CHECK_EQ_INT(totp_load_key(p, key, &kl, err, sizeof(err)), 0);
    CHECK_EQ_INT(kl, 20); /* trailing newlines dropped */
    f = fopen(p, "w");
    fputs("short\n", f);
    fclose(f);
    CHECK_EQ_INT(totp_load_key(p, key, &kl, err, sizeof(err)), -1);
    CHECK(strstr(err, "at least") != NULL);
    remove(p);
    CHECK_EQ_INT(totp_load_key(p, key, &kl, err, sizeof(err)), -1);
    CHECK(strstr(err, "cannot read") != NULL);
}

int main(void)
{
    printf("== totp tests ==\n");
    TEST_RUN(test_sha256);
    TEST_RUN(test_hmac);
    TEST_RUN(test_step);
    TEST_RUN(test_sequence);
    TEST_RUN(test_load_key);
    TEST_SUMMARY();
}
