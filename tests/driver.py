#!/usr/bin/env python3
"""Helper for tests/e2e_integration.sh.

  knock <client_ip> <server_ip> <delay_s> <sport1,sport2,...> [dest_port]
      Send one UDP datagram per source port (bound to that source port) so the
      daemon reads the knock sequence from the clients' source ports.

  probe <server_ip> <port> <timeout_s> [source_ip]
      Attempt a TCP connect (optionally from source_ip); exit 0 if the port is
      reachable, 1 otherwise.

  hold <server_ip> <port> <seconds> [ready_file]
      Open one TCP connection and keep exchanging data with the echo listener
      for <seconds>. Exit 0 only if the connection was established and every
      ping was echoed back; exit 1 as soon as one is lost. If ready_file is
      given it is created once the connection is established.

  flags <client_ip> <server_ip> <dport> <SYN|ACK|FIN|NULL>
      Send one raw TCP segment with the given flags (needs root) and print the
      flags of the reply, or "none" if nothing came back within 1s. Lets the
      harness check what a scanner sees on the hidden port.
"""
import random
import select
import socket
import struct
import sys
import time


def knock(client_ip, server_ip, delay, ports, dest_port=2222):
    # The daemon only reads the SOURCE port, so the destination port is
    # arbitrary; knock against the hidden service port by default.
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((client_ip, p))  # fix the source port the daemon will read
        try:
            s.sendto(b"x", (server_ip, dest_port))
        finally:
            s.close()
        if delay:
            time.sleep(delay)


def probe(server_ip, port, timeout, source_ip=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if source_ip:
            s.bind((source_ip, 0))
        s.connect((server_ip, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def hold(server_ip, port, seconds, ready=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect((server_ip, port))
    except OSError as e:
        print(f"hold: connect failed: {e}", file=sys.stderr)
        return False
    if ready:
        open(ready, "w").close()
    end = time.time() + seconds
    n = 0
    try:
        while time.time() < end:
            msg = b"ping%d\n" % n
            s.sendall(msg)
            got = b""
            while len(got) < len(msg):
                chunk = s.recv(len(msg) - len(got))
                if not chunk:
                    raise OSError("connection closed by peer")
                got += chunk
            if got != msg:
                raise OSError(f"bad echo {got!r}")
            n += 1
            time.sleep(0.2)
    except OSError as e:
        print(f"hold: lost after {n} pings: {e}", file=sys.stderr)
        return False
    finally:
        s.close()
    print(f"hold: {n} pings echoed over {seconds}s")
    return True


def _csum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


FLAG_BITS = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08, "ACK": 0x10}


def flags(client_ip, server_ip, dport, kind):
    bits = 0 if kind == "NULL" else FLAG_BITS[kind]
    sport = random.randint(40000, 60000)
    seq = random.randint(0, 2**32 - 1)
    ack = random.randint(0, 2**32 - 1) if bits & FLAG_BITS["ACK"] else 0
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, bits, 64240, 0, 0)
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(client_ip),
                         socket.inet_aton(server_ip), 0, socket.IPPROTO_TCP, len(hdr))
    hdr = hdr[:16] + struct.pack("!H", _csum(pseudo + hdr)) + hdr[18:]
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.bind((client_ip, 0))
    s.sendto(hdr, (server_ip, 0))
    end = time.time() + 1.0
    try:
        while time.time() < end:
            r, _, _ = select.select([s], [], [], max(0.0, end - time.time()))
            if not r:
                break
            pkt, (src, _) = s.recvfrom(65535)
            ihl = (pkt[0] & 0x0F) * 4
            rsport, rdport = struct.unpack("!HH", pkt[ihl:ihl + 4])
            if src != server_ip or rsport != dport or rdport != sport:
                continue
            f = pkt[ihl + 13]
            return "|".join(n for n, b in FLAG_BITS.items() if f & b) or "NULL"
    finally:
        s.close()
    return "none"


def main(argv):
    if argv[1] == "knock":
        _, _, client, server, delay, ports, *rest = argv
        dest = int(rest[0]) if rest else 2222
        knock(client, server, float(delay), [int(x) for x in ports.split(",")], dest)
        return 0
    if argv[1] == "probe":
        _, _, server, port, timeout, *rest = argv
        src = rest[0] if rest else None
        return 0 if probe(server, int(port), float(timeout), src) else 1
    if argv[1] == "hold":
        _, _, server, port, seconds, *rest = argv
        ready = rest[0] if rest else None
        return 0 if hold(server, int(port), float(seconds), ready) else 1
    if argv[1] == "flags":
        _, _, client, server, dport, kind = argv
        print(flags(client, server, int(dport), kind))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
