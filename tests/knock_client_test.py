#!/usr/bin/env python3
"""Tests for the sourceknock-knock client (run by `make test`).

  python3 tests/knock_client_test.py ./sourceknock-knock

Runs the real binary against local UDP receivers and checks what arrives on
the wire: one datagram per sequence port, from exactly that SOURCE port, in
order, to the requested destination port; IPv4 and IPv6; plus argument and
bind-error handling. Works on Linux and macOS without root.
"""
import os
import platform
import socket
import subprocess
import sys

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "./sourceknock-knock")
passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
        print(f"  FAIL {label} {detail}")


def run(*args):
    return subprocess.run([BIN, *args], capture_output=True, text=True, timeout=20)


def receive(family, addr, seq, extra=()):
    """Run the client at a fresh receiver; return [(sport, payload), ...]."""
    r = socket.socket(family, socket.SOCK_DGRAM)
    r.bind((addr, 0))
    r.settimeout(2.0)
    port = r.getsockname()[1]
    p = run("-p", str(port), "-d", "20", *extra, addr, ",".join(map(str, seq)))
    got = []
    try:
        for _ in seq:
            data, peer = r.recvfrom(64)
            got.append((peer[1], data))
    except socket.timeout:
        pass
    r.close()
    return p, got


def test_ipv4_order_and_source_ports():
    seq = [47101, 47202, 47303, 47101]
    p, got = receive(socket.AF_INET, "127.0.0.1", seq)
    check("ipv4 exit 0", p.returncode == 0, p.stderr)
    check("ipv4 sports in order", [g[0] for g in got] == seq, str(got))
    check("ipv4 payload", all(g[1] == b"k" for g in got), str(got))


def test_ipv4_with_source_address():
    seq = [47111, 47222]
    p, got = receive(socket.AF_INET, "127.0.0.1", seq, ("-s", "127.0.0.1", "-4"))
    check("-s/-4 exit 0", p.returncode == 0, p.stderr)
    check("-s/-4 sports", [g[0] for g in got] == seq, str(got))


def test_ipv6():
    if not socket.has_ipv6:
        return
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.bind(("::1", 0))
        s.close()
    except OSError:
        print("  (skip: no ::1)")
        return
    seq = [47131, 47232, 47333]
    p, got = receive(socket.AF_INET6, "::1", seq, ("-6",))
    check("ipv6 exit 0", p.returncode == 0, p.stderr)
    check("ipv6 sports in order", [g[0] for g in got] == seq, str(got))


def test_bad_arguments():
    for args in (["127.0.0.1", "7000,abc"], ["127.0.0.1", "0"],
                 ["127.0.0.1", "70000"], ["127.0.0.1", ""], ["127.0.0.1", "1,,2"],
                 ["127.0.0.1"], [], ["-p", "0", "127.0.0.1", "1"],
                 ["-p", "x", "127.0.0.1", "1"], ["-d", "-5", "127.0.0.1", "1"],
                 ["-z", "127.0.0.1", "1"]):
        p = run(*args)
        check(f"bad args {args} -> exit 2", p.returncode == 2, f"rc={p.returncode} {p.stderr}")
    p = run("-h")
    check("-h exit 0", p.returncode == 0 and "usage" in p.stdout)
    p = run("no-such-host.invalid", "1000")
    check("unresolvable host -> exit 1", p.returncode == 1, p.stderr)


def test_source_port_in_use():
    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    holder.bind(("127.0.0.1", 47404))
    p = run("-s", "127.0.0.1", "-p", "9", "127.0.0.1", "47404")
    holder.close()
    check("source port in use -> exit 1", p.returncode == 1, p.stderr)
    check("source port in use explained", "another socket" in p.stderr, p.stderr)


def test_privileged_port_needs_root():
    if os.geteuid() == 0 or platform.system() != "Linux":
        return  # macOS lets anyone bind <1024
    try:
        with open("/proc/sys/net/ipv4/ip_unprivileged_port_start") as f:
            if int(f.read()) <= 80:
                return
    except OSError:
        pass
    p = run("-p", "9", "127.0.0.1", "80")
    check("privileged source port -> exit 1", p.returncode == 1, p.stderr)
    check("privileged port explained", "need root" in p.stderr, p.stderr)


if __name__ == "__main__":
    print("== knock client tests ==")
    for t in (test_ipv4_order_and_source_ports, test_ipv4_with_source_address,
              test_ipv6, test_bad_arguments, test_source_port_in_use,
              test_privileged_port_needs_root):
        print(f"[run] {t.__name__}")
        t()
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
