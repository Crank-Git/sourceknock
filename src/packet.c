/* packet.c - link/layer4 parsing. */
#include "packet.h"

#include <string.h>

/* ARPHRD_ values we care about. */
#define ARPHRD_ETHER 1
#define ARPHRD_LOOPBACK 79

/* EtherType / IPv6 next-header protocol numbers. */
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD

/* Read a big-endian 16-bit field. Returns 0 on overrun. */
static uint16_t be16(const unsigned char *p, size_t len, size_t off)
{
    if (off + 2 > len)
        return 0;
    return (uint16_t)((p[off] << 8) | p[off + 1]);
}

/* Copy the 4-byte network-order address into an in_addr. Storing the raw wire
 * bytes (not a host-order integer) is what inet_ntop/inet_pton expect. */
static int be32_ip(const unsigned char *p, size_t len, size_t off,
                   struct in_addr *out)
{
    if (off + 4 > len)
        return 0;
    memcpy(out, &p[off], 4);
    return 1;
}

/* IPv6 next-header values that are extension headers we walk past. */
static int is_ext_header(int nh)
{
    return nh == 0 || nh == 4 || nh == 43 || nh == 44 || nh == 60;
}

/* Locate the L4 payload for an IPv6 datagram at `ip_off`. Walk the bounded
 * chain of extension headers (fragment, hop-by-hop, routing, destination
 * options, ...). Returns the L4 offset and sets *nh to the L4 protocol, or 0
 * if the datagram is too short / has too many headers / ends in an
 * unparseable next header (e.g. ESP/ICMPv6/no-next-header). */
static int ipv6_l4(const unsigned char *buf, size_t len, size_t ip_off,
                   size_t *l4off, int *nh)
{
    if (ip_off + 40 > len)
        return 0;
    int next = buf[ip_off + 6]; /* next header field */
    size_t off = ip_off + 40;   /* L4 starts after the fixed header */
    int hops = 0;
    while (is_ext_header(next))
    {
        if (++hops > 8)
            return 0; /* pathological chain */
        if (next == 44)
        { /* fragment: fixed 8 bytes. The Fragment header's Next Header
             field is at offset 0 (RFC 8200), not after the header. */
            if (off + 8 > len)
                return 0;
            next = buf[off];
            off += 8;
        }
        else
        { /* options/routing: len byte at +1 */
            if (off + 2 > len)
                return 0;
            uint8_t extlen = buf[off + 1];
            size_t elen = (size_t)(extlen + 1) * 8;
            if (elen > len - off)
                return 0;
            next = buf[off];
            off += elen;
        }
    }
    *l4off = off;
    *nh = next;
    return 1;
}

static int parse_ipv4(const unsigned char *buf, size_t len, size_t ip_off,
                      pkt_info_t *out)
{
    if (ip_off + 20 > len)
        return 0;
    uint8_t vihl = buf[ip_off];
    if ((vihl >> 4) != 4)
        return 0; /* not IPv4 */
    uint8_t ihl = (vihl & 0x0f) * 4;
    if (ihl < 20 || ip_off + ihl > len)
        return 0;
    uint8_t l4proto = buf[ip_off + 9];
    const unsigned char *iph = buf + ip_off + ihl;
    size_t l4len = len - (ip_off + ihl);

    struct in_addr src;
    /* IPv4 source address is at offset 12 within the IP header. */
    if (!be32_ip(buf, len, ip_off + 12, &src))
        return 0;

    /* --- L4: source port (offset 0), dest port (offset 2) --- */
    if (l4proto == IPPROTO_TCP && l4len >= 8)
    {
        out->family = AF_INET;
        out->addr.v4 = src;
        out->proto = PROTO_TCP;
        out->sport = be16(iph, l4len, 0);
        out->dport = be16(iph, l4len, 2);
        return 1;
    }
    if (l4proto == IPPROTO_UDP && l4len >= 8)
    {
        out->family = AF_INET;
        out->addr.v4 = src;
        out->proto = PROTO_UDP;
        out->sport = be16(iph, l4len, 0);
        out->dport = be16(iph, l4len, 2);
        return 1;
    }
    return 0;
}

static int parse_ipv6(const unsigned char *buf, size_t len, size_t ip_off,
                      pkt_info_t *out)
{
    size_t l4off;
    int nh;
    if (!ipv6_l4(buf, len, ip_off, &l4off, &nh))
        return 0;
    if (nh != IPPROTO_TCP && nh != IPPROTO_UDP)
        return 0; /* encrypted/other L4: can't read ports */

    struct in6_addr src;
    if (ip_off + 24 > len)
        return 0;
    memcpy(&src, &buf[ip_off + 8], 16); /* IPv6 source is at offset 8 (16 B) */

    const unsigned char *l4 = buf + l4off;
    size_t l4len = len - l4off;
    if (l4len < 8)
        return 0;

    if (nh == IPPROTO_TCP)
    {
        out->family = AF_INET6;
        out->addr.v6 = src;
        out->proto = PROTO_TCP;
        out->sport = be16(l4, l4len, 0);
        out->dport = be16(l4, l4len, 2);
        return 1;
    }
    out->family = AF_INET6;
    out->addr.v6 = src;
    out->proto = PROTO_UDP;
    out->sport = be16(l4, l4len, 0);
    out->dport = be16(l4, l4len, 2);
    return 1;
}

int pkt_parse(const unsigned char *buf, size_t len, unsigned int link_type,
              pkt_info_t *out)
{
    if (!buf || !out)
        return 0;
    memset(out, 0, sizeof(*out));

    /* --- locate the L3 header depending on link layer --- */
    size_t ip_off;

    if (link_type == ARPHRD_LOOPBACK)
    {
        /* Linux lo: 2-byte BE protocol, then the L3 packet. */
        uint16_t proto = be16(buf, len, 0);
        if (proto != ETHERTYPE_IPV4 && proto != ETHERTYPE_IPV6)
            return 0;
        if (2 >= len)
            return 0;
        ip_off = 2;
    }
    else
    {
        /* Ethernet II: ethertype at offset 12. */
        if (len < 14)
            return 0;
        uint16_t ethertype = be16(buf, len, 12);
        if (ethertype != ETHERTYPE_IPV4 && ethertype != ETHERTYPE_IPV6)
            return 0;
        ip_off = 14;
    }

    if ((buf[ip_off] >> 4) == 4)
        return parse_ipv4(buf, len, ip_off, out);
    if ((buf[ip_off] >> 4) == 6)
        return parse_ipv6(buf, len, ip_off, out);
    return 0;
}
