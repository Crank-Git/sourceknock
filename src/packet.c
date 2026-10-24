/* packet.c - link/layer4 parsing. */
#include "packet.h"

#include <string.h>

/* ARPHRD_ values we care about. */
#define ARPHRD_ETHER      1
#define ARPHRD_LOOPBACK  79

/* Read a big-endian 16-bit field. Returns 0 on overrun. */
static uint16_t be16(const unsigned char *p, size_t len, size_t off)
{
    if (off + 2 > len)
        return 0;
    return (uint16_t)((p[off] << 8) | p[off + 1]);
}

/* Copy the 4-byte network-order source address into an in_addr. Storing the
 * raw wire bytes (not a host-order integer) is what inet_ntop/inet_pton expect. */
static int be32_ip(const unsigned char *p, size_t len, size_t off,
                   struct in_addr *out)
{
    if (off + 4 > len)
        return 0;
    memcpy(out, &p[off], 4);
    return 1;
}

int pkt_parse(const unsigned char *buf, size_t len, unsigned int link_type,
              pkt_info_t *out)
{
    if (!buf || !out)
        return 0;
    memset(out, 0, sizeof(*out));

    /* --- locate the IPv4 header depending on link layer --- */
    const unsigned char *iph;
    size_t ip_off;

    if (link_type == ARPHRD_LOOPBACK) {
        /* Linux lo: 2-byte BE protocol, then the IP packet. */
        uint16_t proto = be16(buf, len, 0);
        if (proto != 0x0800)      /* not IPv4 */
            return 0;
        ip_off = 2;
    } else {
        /* Ethernet II: ethertype at offset 12. */
        if (len < 14)
            return 0;
        uint16_t ethertype = be16(buf, len, 12);
        if (ethertype != 0x0800)  /* not IPv4 */
            return 0;
        ip_off = 14;
    }

    /* --- IPv4 header --- */
    if (ip_off + 20 > len)
        return 0;
    uint8_t vihl = buf[ip_off];
    if ((vihl >> 4) != 4)
        return 0;                       /* not IPv4 */
    uint8_t ihl = (vihl & 0x0f) * 4;
    if (ihl < 20)
        return 0;
    uint8_t l4proto = buf[ip_off + 9];
    iph = buf + ip_off + ihl;
    size_t l4len = len - (ip_off + ihl);

    struct in_addr src;
    /* IPv4 source address is at offset 12 within the IP header. */
    if (!be32_ip(buf, len, ip_off + 12, &src))
        return 0;

    /* --- L4: source port (offset 0), dest port (offset 4) --- */
    if (l4proto == IPPROTO_TCP && l4len >= 8) {
        out->proto = PROTO_TCP;
        out->sport = be16(iph, l4len, 0);
        out->dport = be16(iph, l4len, 4);
        out->ip = src;
        return 1;
    }
    if (l4proto == IPPROTO_UDP && l4len >= 8) {
        out->proto = PROTO_UDP;
        out->sport = be16(iph, l4len, 0);
        out->dport = be16(iph, l4len, 4);
        out->ip = src;
        return 1;
    }

    return 0;
}
