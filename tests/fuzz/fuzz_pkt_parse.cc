/*
 * fuzz_pkt_parse.cc - libFuzzer target for pkt_parse().
 *
 * Feeds arbitrary / mutated frame bytes to pkt_parse(), the untrusted-network
 * frame parser in packet.c. This is the buffer-overflow / out-of-bounds-read
 * surface (variable-length Ethernet/IPv6 headers, a bounded IPv6 extension
 * header chain). Built with -fsanitize=fuzzer,address so ASan reports any
 * memory error the fuzzer triggers.
 *
 * The first input byte selects the link-layer type (ARPHRD_LOOPBACK vs
 * ARPHRD_ETHER) so both code paths are exercised; the rest is the raw frame.
 */
/* packet.h is C; wrap it so the C++ translation unit gets C linkage / no
 * name mangling for the pkt_* declarations it pulls in. */
extern "C" {
#include "packet.h"
}

#include <stddef.h>
#include <stdint.h>

/* ARPHRD_ values (also provided by packet.h as portable fallbacks). */
#ifndef ARPHRD_LOOPBACK
#define ARPHRD_LOOPBACK 79
#endif
#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0; /* nothing to parse */

    /* First byte selects the link layer; 0 == loopback, anything else ==
     * Ethernet-II. This routes the fuzzer at both pkt_parse entry paths. */
    unsigned int link = (data[0] == 0) ? ARPHRD_LOOPBACK : ARPHRD_ETHER;

    pkt_info_t info;
    /* pkt_parse is bounds-checked and never reads past `size`. Under ASan a
     * violated guard would be caught here; a clean return just means the
     * frame was rejected (0) or parsed (1) without a memory error. */
    (void)pkt_parse(data, size, link, &info);
    return 0;
}
