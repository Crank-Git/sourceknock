/*
 * packet.h - extract (src ip, src port, proto) from a captured frame.
 *
 * Pure byte-buffer parsing, no sockets. Feeds synthetic buffers in tests.
 * Understands Ethernet II + IPv4 + TCP/UDP. Returns nothing else so the
 * caller (capture.c) owns the frame buffer.
 */
#ifndef SOURCEKNOCK_PACKET_H
#define SOURCEKNOCK_PACKET_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

/* Linux link-layer types (ARPHRD_* values from <linux/if_arp.h>), named here
 * so the pure parser and its tests build on any OS. */
#define PKT_ARPHRD_ETHER 1
#define PKT_ARPHRD_PPP 512
#define PKT_ARPHRD_RAWIP 519
#define PKT_ARPHRD_TUNNEL 768  /* ipip */
#define PKT_ARPHRD_TUNNEL6 769 /* ip6tnl */
#define PKT_ARPHRD_LOOPBACK 772
#define PKT_ARPHRD_SIT 776
#define PKT_ARPHRD_IPGRE 778
#define PKT_ARPHRD_NONE 0xFFFE /* tun, WireGuard */

/* How frames on a link type are framed, as AF_PACKET (SOCK_RAW) delivers
 * them. */
typedef enum
{
    PKT_LINK_UNSUPPORTED = 0, /* we can't find the IP header reliably */
    PKT_LINK_ETHER,           /* 14-byte Ethernet II header (incl. Linux lo) */
    PKT_LINK_RAWIP /* no link header: frame starts at the IP header */
} pkt_link_t;

/* Classify a link type. GRE (PKT_ARPHRD_IPGRE) is unsupported: a multipoint
 * GRE device puts the outer IP + GRE header in front of the frame. */
pkt_link_t pkt_link_kind(unsigned int hatype);

/* Short human-readable name of a link type, for logs. */
const char *pkt_link_name(unsigned int hatype);

typedef enum
{
    PKT_NONE = 0, /* not something we understand */
    PKT_IPV4,     /* IPv4 we could parse */
    PKT_IPV6,     /* IPv6 we could parse */
} pkt_kind_t;

typedef enum
{
    PROTO_NONE = 0,
    PROTO_TCP,
    PROTO_UDP
} proto_t;

typedef struct
{
    int family; /* AF_INET or AF_INET6 */
    union
    {
        struct in_addr v4;
        struct in6_addr v6;
    } addr; /* source address */
    union
    {
        struct in_addr v4;
        struct in6_addr v6;
    } dst;          /* destination address */
    uint16_t sport; /* host-byte-order source port */
    uint16_t dport; /* host-byte-order destination port (0 if n/a) */
    proto_t proto;
} pkt_info_t;

/* Length in bytes of the address stored for a given family. */
static inline size_t pkt_addr_len(int family)
{
    return family == AF_INET6 ? sizeof(struct in6_addr)
                              : sizeof(struct in_addr);
}

/*
 * Parse a frame starting at `buf`. `hatype` is the interface's link type
 * (PKT_ARPHRD_*, as in sockaddr_ll.sll_hatype). Recognises Ethernet-framed
 * links (Ethernet, Linux loopback) and raw-IP links (tun/WireGuard, PPP, ipip,
 * ...), and both IPv4 and IPv6 network headers (IPv6 extension headers are
 * walked, bounded). Returns 1 + fills `out` on success, 0 if the frame is not
 * parseable or the link type is unsupported. Never reads past `len` bytes.
 */
int pkt_parse(const unsigned char *buf, size_t len, unsigned int hatype,
              pkt_info_t *out);

/* True if the packet's source or destination is multicast/broadcast (i.e. a
 * control-plane frame such as mDNS/LLMNR/NDP that must never count as a knock).
 * IPv4 multicast is 224.0.0.0/4, limited broadcast is 255.255.255.255; IPv6
 * multicast is ff00::/8. */
int pkt_is_control(const pkt_info_t *p);

#endif /* SOURCEKNOCK_PACKET_H */
