/*
 * packet.h - extract (src ip, src port, proto) from a captured frame.
 *
 * Pure byte-buffer parsing, no sockets. Feeds synthetic buffers in tests.
 * Understands Ethernet II + IPv4 + TCP/UDP. Returns nothing else so the
 * caller (capture.c) owns the frame buffer.
 */
#ifndef SOURCEKNOCK_PACKET_H
#define SOURCEKNOCK_PACKET_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

/* Link-layer ARPHRD_ types. Defined by <net/if_arp.h> on Linux; provide
 * portable fallbacks so the pure parser + tests build on non-Linux too. */
#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER      1
#endif
#ifndef ARPHRD_LOOPBACK
#define ARPHRD_LOOPBACK  79
#endif

typedef enum {
    PKT_NONE = 0,   /* not something we understand */
    PKT_IPV4,       /* IPv4 we could parse */
    PKT_IPV6,       /* IPv6 we could parse */
} pkt_kind_t;

typedef enum {
    PROTO_NONE = 0,
    PROTO_TCP,
    PROTO_UDP
} proto_t;

typedef struct {
    int  family;   /* AF_INET or AF_INET6 */
    union {
        struct in_addr  v4;
        struct in6_addr v6;
    } addr;
    uint16_t sport;   /* host-byte-order source port */
    uint16_t dport;   /* host-byte-order destination port (0 if n/a) */
    proto_t proto;
} pkt_info_t;

/* Length in bytes of the address stored for a given family. */
static inline size_t pkt_addr_len(int family)
{
    return family == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr);
}

/*
 * Parse a frame starting at `buf`. `link` tells us the link-layer type
 * (AF_PACKET h_type, e.g. ARPHRD_ETHER). Recognises Ethernet-II + loopback
 * link layers and both IPv4 and IPv6 network headers (IPv6 extension headers
 * are walked, bounded). Returns 1 + fills `out` on success, 0 if the frame is
 * not parseable. Never reads past `len` bytes.
 */
int pkt_parse(const unsigned char *buf, size_t len, unsigned int link_type,
              pkt_info_t *out);

#endif /* SOURCEKNOCK_PACKET_H */
