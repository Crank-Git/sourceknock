/* packet_test.c - unit tests for byte-frame parsing. */
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "test.h"
#include "packet.h"

/* Build an Ethernet-II + IPv4 + L4 frame in `buf`. */
static void build_frame(unsigned char *buf, unsigned proto_byte,
                        unsigned sport, unsigned dport, unsigned sip0,
                        unsigned sip1, unsigned sip2, unsigned sip3)
{
    memset(buf, 0, 64);
    /* Ethernet header */
    buf[12] = 0x08; buf[13] = 0x00;   /* ethertype IPv4 (BE) */
    /* IPv4 header */
    buf[14] = 0x45;                    /* version 4, IHL 5 */
    buf[14 + 8] = 20;                  /* total length (lo) */
    buf[14 + 9] = proto_byte;          /* L4 protocol */
    buf[14 + 12] = sip0; buf[14 + 13] = sip1;
    buf[14 + 14] = sip2; buf[14 + 15] = sip3;
    /* L4 source port (offset 0) and dest port (offset 2), both BE */
    unsigned off = 14 + 20;
    buf[off]     = (sport >> 8) & 0xff;
    buf[off + 1] = sport & 0xff;
    buf[off + 2] = (dport >> 8) & 0xff;
    buf[off + 3] = dport & 0xff;
}

static void test_tcp(void)
{
    unsigned char buf[64];
    build_frame(buf, IPPROTO_TCP, 0x1234, 0x5678, 10, 0, 0, 99);
    pkt_info_t info;
    int rc = pkt_parse(buf, sizeof(buf), ARPHRD_ETHER, &info);
    CHECK(rc == 1);
    CHECK_EQ_INT(info.family, AF_INET);
    CHECK_EQ_INT(info.proto, PROTO_TCP);
    CHECK_EQ_INT(info.sport, 0x1234);
    CHECK_EQ_INT(info.dport, 0x5678);
    char s[32];
    inet_ntop(AF_INET, &info.addr.v4, s, sizeof(s));
    CHECK_EQ_STR(s, "10.0.0.99");
}

static void test_udp(void)
{
    unsigned char buf[64];
    build_frame(buf, IPPROTO_UDP, 0x5a5a, 0x9abc, 192, 168, 1, 22);
    pkt_info_t info;
    int rc = pkt_parse(buf, sizeof(buf), ARPHRD_ETHER, &info);
    CHECK(rc == 1);
    CHECK_EQ_INT(info.family, AF_INET);
    CHECK_EQ_INT(info.proto, PROTO_UDP);
    CHECK_EQ_INT(info.sport, 0x5a5a);
    CHECK_EQ_INT(info.dport, 0x9abc);
}

static void test_loopback(void)
{
    unsigned char buf[64];
    memset(buf, 0, 64);
    buf[0] = 0x08; buf[1] = 0x00;   /* lo: BE protocol = IPv4 */
    /* IP starts at offset 2 */
    buf[2] = 0x45;
    buf[2 + 9] = IPPROTO_TCP;
    buf[2 + 12] = 172; buf[2 + 13] = 16; buf[2 + 14] = 0; buf[2 + 15] = 5;
    buf[2 + 20] = 0xab; buf[2 + 21] = 0xcd;   /* sport */
    pkt_info_t info;
    int rc = pkt_parse(buf, sizeof(buf), ARPHRD_LOOPBACK, &info);
    CHECK(rc == 1);
    CHECK_EQ_INT(info.family, AF_INET);
    CHECK_EQ_INT(info.proto, PROTO_TCP);
    CHECK_EQ_INT(info.sport, 0xabcd);
    char s[32];
    inet_ntop(AF_INET, &info.addr.v4, s, sizeof(s));
    CHECK_EQ_STR(s, "172.16.0.5");
}

/* Build an Ethernet-II + IPv6 + TCP frame in `buf`. */
static void build_frame_v6(unsigned char *buf, unsigned sport, unsigned dport)
{
    memset(buf, 0, 96);
    /* Ethernet header: IPv6 ethertype */
    buf[12] = 0x86; buf[13] = 0xdd;
    /* IPv6 header: version 6, no extension headers, next header = TCP */
    buf[14] = 0x60;              /* version 6, traffic class, flow */
    buf[14 + 6] = IPPROTO_TCP;   /* next header */
    /* 16-byte source address: fe80::1234 */
    static const unsigned char src6[16] = {
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34
    };
    memcpy(&buf[14 + 8], src6, 16);
    /* L4 source port (offset 0) and dest port (offset 2), both BE */
    unsigned off = 14 + 40;
    buf[off]     = (sport >> 8) & 0xff;
    buf[off + 1] = sport & 0xff;
    buf[off + 2] = (dport >> 8) & 0xff;
    buf[off + 3] = dport & 0xff;
}

static void test_tcp_v6(void)
{
    unsigned char buf[96];
    build_frame_v6(buf, 0x5a5a, 0x0d0e);
    pkt_info_t info;
    int rc = pkt_parse(buf, sizeof(buf), ARPHRD_ETHER, &info);
    CHECK(rc == 1);
    CHECK_EQ_INT(info.family, AF_INET6);
    CHECK_EQ_INT(info.proto, PROTO_TCP);
    CHECK_EQ_INT(info.sport, 0x5a5a);
    CHECK_EQ_INT(info.dport, 0x0d0e);
    char s[64];
    inet_ntop(AF_INET6, &info.addr.v6, s, sizeof(s));
    CHECK_EQ_STR(s, "fe80::1234");
}

static void test_loopback_v6(void)
{
    unsigned char buf[96];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x86; buf[1] = 0xdd;   /* lo: BE protocol = IPv6 */
    /* IPv6 starts at offset 2 */
    buf[2] = 0x60;                   /* version 6 */
    buf[2 + 6] = IPPROTO_UDP;        /* next header */
    buf[2 + 8] = 0xfe; buf[2 + 9] = 0x80;
    buf[2 + 16] = 0xaa; buf[2 + 17] = 0xbb;  /* source addr hi */
    unsigned off = 2 + 40;
    buf[off]     = (0xccdd >> 8) & 0xff;
    buf[off + 1] = 0xccdd & 0xff;
    buf[off + 2] = (0x1f20 >> 8) & 0xff;   /* dport */
    buf[off + 3] = 0x1f20 & 0xff;
    pkt_info_t info;
    int rc = pkt_parse(buf, sizeof(buf), ARPHRD_LOOPBACK, &info);
    CHECK(rc == 1);
    CHECK_EQ_INT(info.family, AF_INET6);
    CHECK_EQ_INT(info.proto, PROTO_UDP);
    CHECK_EQ_INT(info.sport, 0xccdd);
    CHECK_EQ_INT(info.dport, 0x1f20);
}

static void test_v6_ext_header_walk(void)
{
    /* IPv6 + hop-by-hop options (next header 0) + TCP. The parser must walk
     * the extension header to reach the TCP ports. */
    unsigned char buf[128];
    memset(buf, 0, sizeof(buf));
    buf[12] = 0x86; buf[13] = 0xdd;              /* ethertype IPv6 */
    buf[14] = 0x60;                              /* version 6 */
    buf[14 + 6] = 0;                             /* next header = hop-by-hop */
    buf[14 + 8] = 0xfe; buf[14 + 9] = 0x80;      /* source fe80:: */
    /* hop-by-hop header: next header=TCP(6), extlen=0 (one 8-byte opt) */
    buf[14 + 40] = IPPROTO_TCP;
    buf[14 + 41] = 0;                            /* ext header length = 0 */
    unsigned off = 14 + 40 + 8;                  /* TCP after the ext header */
    buf[off]     = (0x1234 >> 8) & 0xff;
    buf[off + 1] = 0x1234 & 0xff;
    pkt_info_t info;
    int rc = pkt_parse(buf, sizeof(buf), ARPHRD_ETHER, &info);
    CHECK(rc == 1);
    CHECK_EQ_INT(info.family, AF_INET6);
    CHECK_EQ_INT(info.proto, PROTO_TCP);
    CHECK_EQ_INT(info.sport, 0x1234);
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
    TEST_RUN(test_tcp_v6);
    TEST_RUN(test_loopback_v6);
    TEST_RUN(test_v6_ext_header_walk);
    TEST_SUMMARY();
}
