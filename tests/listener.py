#!/usr/bin/env python3
"""Minimal TCP echo listener used by tests/e2e_integration.sh.

Binds to <host>:<port> (default 10.20.0.2:2222) inside the test network
namespace, signals readiness by touching <ready_file>, then echoes back
whatever each connection sends until the peer closes or the listener is
killed. The daemon's nft rule must let the probe reach this listener for the
port to count as "open"; echoing lets the harness confirm that data keeps
flowing on a long-lived connection, not just that the handshake succeeded.
"""
import os
import socket
import sys
import threading
import time

HOST = os.environ.get("SK_LISTEN_HOST", "10.20.0.2")
port = int(sys.argv[1]) if len(sys.argv) > 1 else 2222
# The ready path is required: the harness passes a private temp-file path so
# the listener never depends on a pre-existing scratch directory.
if len(sys.argv) < 3:
    sys.stderr.write("usage: listener.py <port> <ready_file>\n")
    sys.exit(2)
ready = sys.argv[2]
end = time.time() + 300


def echo(conn):
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(data)
    except OSError:
        pass
    finally:
        conn.close()


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, port))
s.listen(32)
s.settimeout(1.0)
open(ready, "w").close()

while time.time() < end:
    try:
        conn, _ = s.accept()
    except socket.timeout:
        continue
    except OSError:
        break
    conn.settimeout(None)
    threading.Thread(target=echo, args=(conn,), daemon=True).start()
