#!/usr/bin/env python3
"""Helper for tests/e2e_integration.sh.

  knock <client_ip> <server_ip> <delay_s> <sport1,sport2,...> [dest_port]
      Send one UDP datagram per source port (bound to that source port) so the
      daemon reads the knock sequence from the clients' source ports.

  probe <server_ip> <port> <timeout_s>
      Attempt a TCP connect; exit 0 if the port is reachable, 1 otherwise.
"""
import socket
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


def probe(server_ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((server_ip, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def main(argv):
    if argv[1] == "knock":
        _, _, client, server, delay, ports, *rest = argv
        dest = int(rest[0]) if rest else 2222
        knock(client, server, float(delay), [int(x) for x in ports.split(",")], dest)
        return 0
    if argv[1] == "probe":
        _, _, server, port, timeout = argv
        return 0 if probe(server, int(port), float(timeout)) else 1
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
