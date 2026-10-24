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
} pkt_kind_t;

typedef enum {
    PROTO_NONE = 0,
    PROTO_TCP,
    PROTO_UDP
} proto_t;

typedef struct {
    struct in_addr ip;
    uint16_t       sport;   /* host-byte-order source port */
    uint16_t       dport;   /* host-byte-order destination port (0 if n/a) */
    proto_t        proto;
} pkt_info_t;

/*
 * Parse a frame starting at `buf`. `link` tells us the link-layer type
 * (AF_PACKET h_type, e.g. ARPHRD_ETHER). Returns 1 + fills `out` on success,
 * 0 if the frame is not parseable. Never reads past `len` bytes.
 */
int pkt_parse(const unsigned char *buf, size_t len, unsigned int link_type,
              pkt_info_t *out);

#endif /* SOURCEKNOCK_PACKET_H */
