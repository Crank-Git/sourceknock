#!/usr/bin/env python3
"""Generate libFuzzer seed corpus for fuzz_pkt_parse().

Each seed is a raw frame. The first byte selects the link layer (0 ==
ARPHRD_LOOPBACK, anything else == ARPHRD_ETHER); the rest is the frame body
exactly as pkt_parse() sees it. Covers IPv4, IPv6, the IPv6 extension-header
walk, both link layers, and malformed/truncated inputs.

Run from this directory:  python3 make_seeds.py
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "corpus", "pkt_parse")

ETH = 0x01  # link-layer selector -> Ethernet-II
LO  = 0x00  # link-layer selector -> loopback


def be16(v):
    return ((v >> 8) & 0xFF).to_bytes(1, "big") + (v & 0xFF).to_bytes(1, "big")


def eth_header(etype):
    # dst MAC (6) + src MAC (6) + ethertype (2, big-endian)
    return b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + be16(etype)


def ipv4(proto, sip=(10, 0, 0, 99), dip=(10, 0, 0, 2), ihl=5):
    hdr = bytearray(40)
    hdr[0] = (4 << 4) | (ihl * 4 // 4)          # version 4, IHL
    hdr[1] = 0                                    # DSCP/ECN
    total = ihl * 4 + 20                          # IP + a 20-byte L4 header
    hdr[2], hdr[3] = (total >> 8) & 0xFF, total & 0xFF
    hdr[8] = 0                                    # TTL
    hdr[9] = proto                                # L4 protocol
    hdr[12:16] = bytes(sip)
    hdr[16:20] = bytes(dip)
    return hdr


def tcp(sport, dport):
    # src port, dst port, then a minimal (20-byte) header.
    return be16(sport) + be16(dport) + b"\x00" * 16


def udp(sport, dport):
    return be16(sport) + be16(dport) + b"\x00" * 4


def ipv6(nh, sip, dip, l4):
    hdr = bytearray(40)
    hdr[0] = 6 << 4                               # version 6
    hdr[2] = 0                                    # flow label (hi)
    hdr[4] = (len(l4) >> 8) & 0xff                # payload length (be, hi)
    hdr[5] = len(l4) & 0xff                       # payload length (be, lo)
    hdr[7] = 64                                   # hop limit
    hdr[6] = nh                                 # next header (L4 / ext)
    hdr[8:24] = sip
    hdr[24:40] = dip
    return hdr + l4


def write(name, link, frame):
    path = os.path.join(CORPUS, name)
    with open(path, "wb") as f:
        f.write(bytes([link]) + frame)
    print(f"wrote {path} ({len(frame)} frame bytes)")


def main():
    os.makedirs(CORPUS, exist_ok=True)

    # --- Ethernet + IPv4 ---
    write("ipv4_tcp.eth", ETH, eth_header(0x0800) + bytes(ipv4(6, sip=(10, 0, 0, 99))) + tcp(0x1234, 0x5678))
    write("ipv4_udp.eth", ETH, eth_header(0x0800) + bytes(ipv4(17, sip=(192, 168, 1, 22))) + udp(0x5a5a, 0x9abc))
    # IPv4 with header options (IHL = 6 -> 24-byte header).
    write("ipv4_ihl_opts.eth", ETH, eth_header(0x0800) + bytes(ipv4(6, sip=(172, 16, 5, 7), ihl=6)) + tcp(4000, 22))

    # --- Ethernet + IPv6 (plain + one fragment extension header) ---
    write("ipv6_tcp.eth", ETH, eth_header(0x86dd) + ipv6(6, bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                                                        bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
                                                        tcp(0x1111, 0x2222)))
    # Fragment header (nh=44) is a fixed 8 bytes; next header then points at UDP.
    frag = bytes([17, 0, 0, 0, 0, 0, 0, 0])  # next header = UDP, offset 0, etc.
    write("ipv6_frag.eth", ETH, eth_header(0x86dd) + ipv6(44, bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                                                           bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
                                                           frag + udp(0x3333, 0x4444)))
    # Two extension headers before TCP: hop-by-options (next=routing 43),
    # then routing (next=TCP 6). Ext-len byte (offset 1) is 0 == one 8-byte
    # unit; offset 0 is the *next* header so the walk continues.
    hop = bytes([43, 0, 0, 0, 0, 0, 0, 0])     # next = routing(43), extlen 0
    route = bytes([6, 0, 0, 0, 0, 0, 0, 0])    # next = TCP(6), extlen 0
    write("ipv6_two_ext.eth", ETH, eth_header(0x86dd) + ipv6(0, bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                                                            bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
                                                            hop + route + tcp(0x5555, 0x6666)))

    # --- Loopback link layer (2-byte BE protocol prefix) ---
    write("loopback_ipv4.eth", LO, be16(0x0800) + bytes(ipv4(6, sip=(127, 0, 0, 1))) + tcp(0x7777, 0x8888))

    # --- Malformed / truncated (must parse to 0, never crash) ---
    write("too_short.eth", ETH, b"\x00\x11")                       # < 14 bytes
    write("bad_ethertype.eth", ETH, b"\x00" * 14 + b"\x00\x00")    # non-IP ethertype
    write("truncated_ipv4.eth", ETH, eth_header(0x0800) + b"\x45\x00\x00")  # IP header cut off
    # Header-only Ethernet frame: exactly 14 bytes (dst+src+ethertype 0x0800),
    # no L3 payload. ip_off == len, so buf[ip_off] would read 1 byte past the
    # end. Must parse to 0 (regression for an ASan heap-buffer-overflow).
    write("header_only_ipv4.eth", ETH, eth_header(0x0800))
    write("all_zero.eth", ETH, b"\x00" * 8)                        # garbage
    write("one_byte.eth", ETH, b"\x01")                            # single byte


if __name__ == "__main__":
    main()
