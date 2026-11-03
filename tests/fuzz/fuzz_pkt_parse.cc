/*
 * fuzz_pkt_parse.cc - libFuzzer target for pkt_parse().
 *
 * Feeds arbitrary / mutated frame bytes to pkt_parse(), the untrusted-network
 * frame parser in packet.c. This is the buffer-overflow / out-of-bounds-read
 * surface (variable-length Ethernet/IPv6 headers, a bounded IPv6 extension
 * header chain). Built with -fsanitize=fuzzer,address so ASan reports any
 * memory error the fuzzer triggers.
 *
 * The first input byte selects the link-layer type (see link_for()) so every
 * framing path is exercised; the rest is the raw frame.
 */
/* packet.h is C; wrap it so the C++ translation unit gets C linkage / no
 * name mangling for the pkt_* declarations it pulls in. */
extern "C"
{
#include "packet.h"
}

#include <stddef.h>
#include <stdint.h>

/* Selector byte -> link type, shared with seed_check.c / make_seeds.py:
 * 0 loopback, 1 Ethernet, 2 raw IP (tun/wg), 3 unsupported (GRE). */
static unsigned int link_for(uint8_t sel)
{
    static const unsigned int links[4] = {PKT_ARPHRD_LOOPBACK, PKT_ARPHRD_ETHER,
                                          PKT_ARPHRD_NONE, PKT_ARPHRD_IPGRE};
    return links[sel % 4];
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0; /* nothing to parse */

    pkt_info_t info;
    /* pkt_parse is bounds-checked and never reads past `size`. Under ASan a
     * violated guard would be caught here; a clean return just means the
     * frame was rejected (0) or parsed (1) without a memory error. The frame
     * is everything after the selector byte. */
    (void)pkt_parse(data + 1, size - 1, link_for(data[0]), &info);
    return 0;
}
