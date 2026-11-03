/* packet_test.c - unit tests for byte-frame parsing. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include "packet.h"
#include "test.h"

/* Build an Ethernet-II + IPv4 + L4 frame in `buf`. */
static void build_frame(unsigned char *buf, unsigned proto_byte, unsigned sport,
                        unsigned dport, unsigned sip0, unsigned sip1,
                        unsigned sip2, unsigned sip3)
{
    memset(buf, 0, 64);
    /* Ethernet header */
    buf[12] = 0x08;
    buf[13] = 0x00; /* ethertype IPv4 (BE) */
    /* IPv4 header */
    buf[14] = 0x45;           /* version 4, IHL 5 */
    buf[14 + 8] = 20;         /* total length (lo) */
    buf[14 + 9] = proto_byte; /* L4 protocol */
    buf[14 + 12] = sip0;
    buf[14 + 13] = sip1;
    buf[14 + 14] = sip2;
    buf[14 + 15] = sip3;
    /* L4 source port (offset 0) and dest port (offset 2), both BE */
    unsigned off = 14 + 20;
    buf[off] = (sport >> 8) & 0xff;
    buf[off + 1] = sport & 0xff;
    buf[off + 2] = (dport >> 8) & 0xff;
    buf[off + 3] = dport & 0xff;
}

static void test_tcp(void)
{
    unsigned char buf[64];
    build_frame(buf, IPPROTO_TCP, 0x1234, 0x5678, 10, 0, 0, 99);
    pkt_info_t info;
    int rc = pkt_parse(buf, sizeof(buf), PKT_ARPHRD_ETHER, &info);
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
    int rc = pkt_parse(buf, sizeof(buf), PKT_ARPHRD_ETHER, &info);
    CHECK(rc == 1);
    CHECK_EQ_INT(info.family, AF_INET);
    CHECK_EQ_INT(info.proto, PROTO_UDP);
    CHECK_EQ_INT(info.sport, 0x5a5a);
    CHECK_EQ_INT(info.dport, 0x9abc);
}

/* Linux lo (ARPHRD_LOOPBACK = 772) delivers a 14-byte Ethernet header with
 * zeroed MACs, exactly like Ethernet. */
static void test_loopback(void)
{
    unsigned char buf[64];
    memset(buf, 0, 64);
    buf[12] = 0x08;
    buf[13] = 0x00; /* ethertype IPv4 */
    buf[14] = 0x45;
    buf[14 + 9] = IPPROTO_TCP;
    buf[14 + 12] = 127;
    buf[14 + 15] = 1;
    buf[14 + 20] = 0xab;
    buf[14 + 21] = 0xcd; /* sport */
    pkt_info_t info;
    int rc = pkt_parse(buf, sizeof(buf), PKT_ARPHRD_LOOPBACK, &info);
    CHECK(rc == 1);
    CHECK_EQ_INT(info.family, AF_INET);
    CHECK_EQ_INT(info.proto, PROTO_TCP);
    CHECK_EQ_INT(info.sport, 0xabcd);
    char s[32];
    inet_ntop(AF_INET, &info.addr.v4, s, sizeof(s));
    CHECK_EQ_STR(s, "127.0.0.1");
}

/* Build an Ethernet-II + IPv6 + TCP frame in `buf`. */
static void build_frame_v6(unsigned char *buf, unsigned sport, unsigned dport)
{
    memset(buf, 0, 96);
    /* Ethernet header: IPv6 ethertype */
    buf[12] = 0x86;
    buf[13] = 0xdd;
    /* IPv6 header: version 6, no extension headers, next header = TCP */
    buf[14] = 0x60;            /* version 6, traffic class, flow */
    buf[14 + 6] = IPPROTO_TCP; /* next header */
    /* 16-byte source address: fe80::1234 */
    static const unsigned char src6[16] = {0xfe, 0x80, 0, 0, 0, 0, 0,    0,
                                           0,    0,    0, 0, 0, 0, 0x12, 0x34};
    memcpy(&buf[14 + 8], src6, 16);
    /* L4 source port (offset 0) and dest port (offset 2), both BE */
    unsigned off = 14 + 40;
    buf[off] = (sport >> 8) & 0xff;
    buf[off + 1] = sport & 0xff;
    buf[off + 2] = (dport >> 8) & 0xff;
    buf[off + 3] = dport & 0xff;
}

static void test_tcp_v6(void)
{
    unsigned char buf[96];
    build_frame_v6(buf, 0x5a5a, 0x0d0e);
    pkt_info_t info;
    int rc = pkt_parse(buf, sizeof(buf), PKT_ARPHRD_ETHER, &info);
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
    build_frame_v6(buf, 0xccdd, 0x1f20);
    pkt_info_t info;
    int rc = pkt_parse(buf, sizeof(buf), PKT_ARPHRD_LOOPBACK, &info);
    CHECK(rc == 1);
    CHECK_EQ_INT(info.family, AF_INET6);
    CHECK_EQ_INT(info.sport, 0xccdd);
    CHECK_EQ_INT(info.dport, 0x1f20);
}

static void test_v6_ext_header_walk(void)
{
    /* IPv6 + hop-by-hop options (next header 0) + TCP. The parser must walk
     * the extension header to reach the TCP ports. */
    unsigned char buf[128];
    memset(buf, 0, sizeof(buf));
    buf[12] = 0x86;
    buf[13] = 0xdd;  /* ethertype IPv6 */
    buf[14] = 0x60;  /* version 6 */
    buf[14 + 6] = 0; /* next header = hop-by-hop */
    buf[14 + 8] = 0xfe;
    buf[14 + 9] = 0x80; /* source fe80:: */
    /* hop-by-hop header: next header=TCP(6), extlen=0 (one 8-byte opt) */
    buf[14 + 40] = IPPROTO_TCP;
    buf[14 + 41] = 0;           /* ext header length = 0 */
    unsigned off = 14 + 40 + 8; /* TCP after the ext header */
    buf[off] = (0x1234 >> 8) & 0xff;
    buf[off + 1] = 0x1234 & 0xff;
    pkt_info_t info;
    int rc = pkt_parse(buf, sizeof(buf), PKT_ARPHRD_ETHER, &info);
    CHECK(rc == 1);
    CHECK_EQ_INT(info.family, AF_INET6);
    CHECK_EQ_INT(info.proto, PROTO_TCP);
    CHECK_EQ_INT(info.sport, 0x1234);
}

static void test_non_ipv4_ignored(void)
{
    unsigned char buf[64];
    memset(buf, 0, 64);
    buf[12] = 0x86;
    buf[13] = 0xdd; /* IPv6 ethertype */
    pkt_info_t info;
    CHECK(pkt_parse(buf, sizeof(buf), PKT_ARPHRD_ETHER, &info) == 0);
}

static void test_too_short(void)
{
    unsigned char buf[8];
    memset(buf, 0, sizeof(buf));
    pkt_info_t info;
    CHECK(pkt_parse(buf, sizeof(buf), PKT_ARPHRD_ETHER, &info) == 0);
}

/* ---- issue #38: raw-IP links (no link header) ---- */

/* IPv4 + UDP starting at offset 0, as tun/wg/ipip/ppp deliver it. */
static size_t build_raw_v4(unsigned char *buf, unsigned sport, unsigned dport)
{
    memset(buf, 0, 64);
    buf[0] = 0x45;
    buf[9] = IPPROTO_UDP;
    buf[12] = 10;
    buf[13] = 30;
    buf[14] = 0;
    buf[15] = 1;
    buf[20] = (sport >> 8) & 0xff;
    buf[21] = sport & 0xff;
    buf[22] = (dport >> 8) & 0xff;
    buf[23] = dport & 0xff;
    return 28;
}

static void test_raw_ip_links(void)
{
    const unsigned int raw[] = {PKT_ARPHRD_NONE,    PKT_ARPHRD_PPP,
                                PKT_ARPHRD_RAWIP,   PKT_ARPHRD_TUNNEL,
                                PKT_ARPHRD_TUNNEL6, PKT_ARPHRD_SIT};
    unsigned char buf[64];
    size_t n = build_raw_v4(buf, 1100, 51820);
    for (size_t i = 0; i < sizeof(raw) / sizeof(raw[0]); i++)
    {
        pkt_info_t info;
        CHECK_EQ_INT(pkt_parse(buf, n, raw[i], &info), 1);
        CHECK_EQ_INT(info.family, AF_INET);
        CHECK_EQ_INT(info.proto, PROTO_UDP);
        CHECK_EQ_INT(info.sport, 1100);
        CHECK_EQ_INT(info.dport, 51820);
        char s[32];
        inet_ntop(AF_INET, &info.addr.v4, s, sizeof(s));
        CHECK_EQ_STR(s, "10.30.0.1");
    }
    /* The same bytes read as Ethernet are garbage: that was the bug. */
    pkt_info_t info;
    CHECK_EQ_INT(pkt_parse(buf, n, PKT_ARPHRD_ETHER, &info), 0);
}

static void test_raw_ip_v6(void)
{
    unsigned char eth[96];
    build_frame_v6(eth, 0x4321, 0x0016);
    /* strip the 14-byte Ethernet header */
    pkt_info_t info;
    CHECK_EQ_INT(pkt_parse(eth + 14, sizeof(eth) - 14, PKT_ARPHRD_NONE, &info),
                 1);
    CHECK_EQ_INT(info.family, AF_INET6);
    CHECK_EQ_INT(info.proto, PROTO_TCP);
    CHECK_EQ_INT(info.sport, 0x4321);
    CHECK_EQ_INT(info.dport, 0x0016);
}

static void test_raw_ip_malformed(void)
{
    unsigned char buf[64];
    pkt_info_t info;
    size_t n = build_raw_v4(buf, 1, 2);
    CHECK_EQ_INT(pkt_parse(buf, 0, PKT_ARPHRD_NONE, &info), 0);
    CHECK_EQ_INT(pkt_parse(buf, 1, PKT_ARPHRD_NONE, &info), 0);
    CHECK_EQ_INT(pkt_parse(buf, 20, PKT_ARPHRD_NONE, &info), 0); /* no L4 */
    CHECK_EQ_INT(pkt_parse(buf, n - 1, PKT_ARPHRD_NONE, &info), 0);
    buf[0] = 0x55; /* version 5 */
    CHECK_EQ_INT(pkt_parse(buf, n, PKT_ARPHRD_NONE, &info), 0);
    buf[0] = 0x44; /* IHL < 5 */
    CHECK_EQ_INT(pkt_parse(buf, n, PKT_ARPHRD_NONE, &info), 0);
}

/* Link types we can't parse return 0 instead of being read as Ethernet,
 * including the bogus "loopback = 79" the parser used to use. */
static void test_unsupported_links(void)
{
    unsigned char eth[96];
    build_frame_v6(eth, 1, 2);
    const unsigned int bad[] = {0, 79, PKT_ARPHRD_IPGRE, 801, 803, 0xFFFF};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        pkt_info_t info;
        CHECK_EQ_INT(pkt_parse(eth, sizeof(eth), bad[i], &info), 0);
        CHECK_EQ_INT(pkt_link_kind(bad[i]), PKT_LINK_UNSUPPORTED);
    }
}

static void test_link_kind_table(void)
{
    CHECK_EQ_INT(pkt_link_kind(PKT_ARPHRD_ETHER), PKT_LINK_ETHER);
    CHECK_EQ_INT(pkt_link_kind(PKT_ARPHRD_LOOPBACK), PKT_LINK_ETHER);
    CHECK_EQ_INT(pkt_link_kind(PKT_ARPHRD_NONE), PKT_LINK_RAWIP);
    CHECK_EQ_INT(pkt_link_kind(PKT_ARPHRD_PPP), PKT_LINK_RAWIP);
    CHECK_EQ_INT(pkt_link_kind(PKT_ARPHRD_RAWIP), PKT_LINK_RAWIP);
    CHECK_EQ_INT(pkt_link_kind(PKT_ARPHRD_TUNNEL), PKT_LINK_RAWIP);
    CHECK_EQ_INT(pkt_link_kind(PKT_ARPHRD_TUNNEL6), PKT_LINK_RAWIP);
    CHECK_EQ_INT(pkt_link_kind(PKT_ARPHRD_SIT), PKT_LINK_RAWIP);
    /* the real Linux values, not just our names for them */
    CHECK_EQ_INT(PKT_ARPHRD_LOOPBACK, 772);
    CHECK_EQ_INT(PKT_ARPHRD_NONE, 65534);
    CHECK_EQ_STR(pkt_link_name(PKT_ARPHRD_TUNNEL), "ipip tunnel");
    CHECK_EQ_STR(pkt_link_name(12345), "unknown");
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
    TEST_RUN(test_raw_ip_links);
    TEST_RUN(test_raw_ip_v6);
    TEST_RUN(test_raw_ip_malformed);
    TEST_RUN(test_unsupported_links);
    TEST_RUN(test_link_kind_table);
    TEST_RUN(test_v6_ext_header_walk);
    TEST_SUMMARY();
}
