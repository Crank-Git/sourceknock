/* packet_test.c - unit tests for byte-frame parsing. */
#include <string.h>

#include "test.h"
#include "packet.h"

/* Build an Ethernet-II + IPv4 + L4 frame in `buf`. */
static void build_frame(unsigned char *buf, unsigned proto_byte,
                        unsigned sport, unsigned sip0, unsigned sip1,
                        unsigned sip2, unsigned sip3)
{
    memset(buf, 0, 64);
    /* Ethernet header */
    buf[12] = 0x08; buf[13] = 0x00;   /* ethertype IPv4 (BE) */
    /* IPv4 header */
    buf[14] = 0x45;                    /* version 4, IHL 5 */
    buf[14 + 8] = 20;                  /* total length (lo) */
    buf[14 + 9] = proto_byte;          /* L4 protocol */
    buf[14 + 4] = sip0; buf[14 + 5] = sip1;
    buf[14 + 6] = sip2; buf[14 + 7] = sip3;
    /* L4 source port (BE) */
    unsigned off = 14 + 20;
    buf[off]     = (sport >> 8) & 0xff;
    buf[off + 1] = sport & 0xff;
}

static void test_tcp(void)
{
    unsigned char buf[64];
    build_frame(buf, IPPROTO_TCP, 0x1234, 10, 0, 0, 99);
    pkt_info_t info;
    int rc = pkt_parse(buf, sizeof(buf), ARPHRD_ETHER, &info);
    CHECK(rc == 1);
    CHECK_EQ_INT(info.proto, PROTO_TCP);
    CHECK_EQ_INT(info.sport, 0x1234);
    CHECK_EQ_INT(info.ip.s_addr, (10 << 24) | (0 << 16) | (0 << 8) | 99);
}

static void test_udp(void)
{
    unsigned char buf[64];
    build_frame(buf, IPPROTO_UDP, 0x5a5a, 192, 168, 1, 22);
    pkt_info_t info;
    int rc = pkt_parse(buf, sizeof(buf), ARPHRD_ETHER, &info);
    CHECK(rc == 1);
    CHECK_EQ_INT(info.proto, PROTO_UDP);
    CHECK_EQ_INT(info.sport, 0x5a5a);
}

static void test_loopback(void)
{
    unsigned char buf[64];
    memset(buf, 0, 64);
    buf[0] = 0x08; buf[1] = 0x00;   /* lo: BE protocol = IPv4 */
    /* IP starts at offset 2 */
    buf[2] = 0x45;
    buf[2 + 9] = IPPROTO_TCP;
    buf[2 + 4] = 172; buf[2 + 5] = 16; buf[2 + 6] = 0; buf[2 + 7] = 5;
    buf[2 + 20] = 0xab; buf[2 + 21] = 0xcd;   /* sport */
    pkt_info_t info;
    int rc = pkt_parse(buf, sizeof(buf), ARPHRD_LOOPBACK, &info);
    CHECK(rc == 1);
    CHECK_EQ_INT(info.proto, PROTO_TCP);
    CHECK_EQ_INT(info.sport, 0xabcd);
    unsigned exp = (172u << 24) | (16u << 16) | (0u << 8) | 5u; /* 172.16.0.5 */
    CHECK_EQ_INT(info.ip.s_addr, exp);
}

static void test_non_ipv4_ignored(void)
{
    unsigned char buf[64];
    memset(buf, 0, 64);
    buf[12] = 0x86; buf[13] = 0xdd;   /* IPv6 ethertype */
    pkt_info_t info;
    CHECK(pkt_parse(buf, sizeof(buf), ARPHRD_ETHER, &info) == 0);
}

static void test_too_short(void)
{
    unsigned char buf[8];
    memset(buf, 0, sizeof(buf));
    pkt_info_t info;
    CHECK(pkt_parse(buf, sizeof(buf), ARPHRD_ETHER, &info) == 0);
}

int main(void)
{
    printf("== packet parsing tests ==\n");
    TEST_RUN(test_tcp);
    TEST_RUN(test_udp);
    TEST_RUN(test_loopback);
    TEST_RUN(test_non_ipv4_ignored);
    TEST_RUN(test_too_short);
    TEST_SUMMARY();
}
