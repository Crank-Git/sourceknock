#!/usr/bin/env python3
"""Minimal TCP listener used by tests/e2e_integration.sh.

Binds to <host>:<port> (default 10.20.0.2:2222) inside the test network
namespace, signals readiness by touching <ready_file>, then accepts and
discards connections until killed. The daemon's nft rule must let the probe
reach this listener for the port to count as "open".
"""
import os
import socket
import sys
import time

HOST = os.environ.get("SK_LISTEN_HOST", "10.20.0.2")
port = int(sys.argv[1]) if len(sys.argv) > 1 else 2222
ready = sys.argv[2] if len(sys.argv) > 2 else "/tmp/skdev/listen_up"
end = time.time() + 90

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, port))
s.listen(32)
open(ready, "w").close()

while time.time() < end:
    try:
        conn, _ = s.accept()
        conn.close()
    except OSError:
        break
