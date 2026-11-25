#!/usr/bin/env python3
"""Tests for the sourceknock-knock client (run by `make test`).

  python3 tests/knock_client_test.py ./sourceknock-knock

Runs the real binary against local UDP receivers and checks what arrives on
the wire: one datagram per sequence port, from exactly that SOURCE port, in
order, to the requested destination port; IPv4 and IPv6; plus argument and
bind-error handling. Works on Linux and macOS without root.
"""
import hashlib
import hmac
import os
import platform
import socket
import struct
import subprocess
import sys
import tempfile
import time

# Keep the client's step records out of the real home directory.
os.environ["XDG_STATE_HOME"] = tempfile.mkdtemp()
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


def receive(family, addr, seq, extra=(), count=None):
    """Run the client at a fresh receiver; return [(sport, payload), ...].
    With `seq` None the client derives the sequence itself (-K in `extra`)."""
    r = socket.socket(family, socket.SOCK_DGRAM)
    r.bind((addr, 0))
    r.settimeout(2.0)
    port = r.getsockname()[1]
    tail = [addr] if seq is None else [addr, ",".join(map(str, seq))]
    p = run("-p", str(port), "-d", "20", *extra, *tail)
    got = []
    try:
        for _ in range(count if seq is None else len(seq)):
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


def totp_ports(key, label, step):
    """The spec in src/totp.h, computed independently of the C code."""
    mac = hmac.new(key, f"sourceknock-v1:{label}:".encode() + struct.pack(">q", step),
                   hashlib.sha256).digest()
    return [1024 + int.from_bytes(mac[2 * i:2 * i + 2], "big") % 31744 for i in range(4)]


def test_keyfile():
    """-K derives the time-based sequence (-r the revoke one) from a secret."""
    d = tempfile.mkdtemp()
    key = b"client-test-secret-0123456789"
    path = os.path.join(d, "k.key")
    with open(path, "wb") as f:
        f.write(key + b"\n")
    os.chmod(path, 0o600)
    for label, extra in (("knock", ["-K", path]), ("revoke", ["-K", path, "-r"])):
        step = int(time.time()) // 30
        p, got = receive(socket.AF_INET, "127.0.0.1", None, extra, count=4)
        sports = [g[0] for g in got]
        want = [totp_ports(key, label, s) for s in (step, step + 1)]
        check(f"-K {label} exit 0", p.returncode == 0, p.stderr)
        check(f"-K {label} sends the derived ports", sports in want, f"{sports} vs {want}")
    for args in (["-r", "127.0.0.1", "1,2,3"], ["-K", path, "127.0.0.1", "1,2,3"]):
        p = run(*args)
        check(f"bad args {args} -> exit 2", p.returncode == 2, f"rc={p.returncode}")
    with open(path, "wb") as f:
        f.write(b"short\n")
    p = run("-K", path, "127.0.0.1")
    check("short secret -> exit 1", p.returncode == 1 and "at least" in p.stderr, p.stderr)
    os.remove(path)
    p = run("-K", path, "127.0.0.1")
    check("missing secret file -> exit 1", p.returncode == 1, p.stderr)
    os.rmdir(d)


def knock_state(extra_env, key_path, *extra):
    """Run `-K` once at a local receiver; return (process, sports)."""
    r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    r.bind(("127.0.0.1", 0))
    r.settimeout(1.0)
    env = dict(os.environ, **extra_env)
    p = subprocess.run([BIN, "-p", str(r.getsockname()[1]), "-d", "20", "-K", key_path,
                        *extra, "127.0.0.1"], capture_output=True, text=True,
                       timeout=20, env=env)
    got = []
    try:
        for _ in range(4):
            got.append(r.recvfrom(64)[1][1])
    except socket.timeout:
        pass
    r.close()
    return p, got


def test_keyfile_state():
    """-K falls back to the next step after a used one, then refuses."""
    d = tempfile.mkdtemp()
    key = b"client-test-secret-0123456789"
    path = os.path.join(d, "k.key")
    with open(path, "wb") as f:
        f.write(key + b"\n")
    os.chmod(path, 0o600)
    env = {"XDG_STATE_HOME": os.path.join(d, "state")}
    if time.time() % 30 > 24:  # keep the three knocks inside one step
        time.sleep(7)
    step = int(time.time()) // 30
    cur, nxt = (totp_ports(key, "knock", s) for s in (step, step + 1))

    p, got = knock_state(env, path)
    check("state: first knock exit 0", p.returncode == 0, p.stderr)
    check("state: first knock = current step", got == cur, f"{got} vs {cur}")
    mode = None
    for root, _, files in os.walk(env["XDG_STATE_HOME"]):
        for name in files:
            mode = os.stat(os.path.join(root, name)).st_mode & 0o777
    check("state: file mode 0600", mode == 0o600, str(mode))

    p, got = knock_state(env, path)
    check("state: second knock exit 0", p.returncode == 0, p.stderr)
    check("state: second knock = next step", got == nxt, f"{got} vs {nxt}")

    p, got = knock_state(env, path)
    check("state: third knock exit 1", p.returncode == 1, f"rc={p.returncode}")
    check("state: third knock sends nothing", got == [], str(got))
    check("state: third knock says how long to wait",
          "wait" in p.stderr and " s" in p.stderr, p.stderr)

    p, got = knock_state(env, path, "-r")
    check("state: revoke has its own entry", p.returncode == 0 and
          got == totp_ports(key, "revoke", step), f"{got} {p.stderr}")

    other = {"XDG_STATE_HOME": os.path.join(d, "state2")}
    p, got = knock_state(other, path)
    check("state: new state dir starts over", got == cur, f"{got} vs {cur}")

    # A regular file where the directory belongs: warn once, still knock.
    blocker = os.path.join(d, "blocker")
    open(blocker, "w").close()
    p, got = knock_state({"XDG_STATE_HOME": blocker}, path)
    check("state: unwritable dir still knocks", p.returncode == 0 and got == cur,
          f"{got} vs {cur} {p.stderr}")
    check("state: unwritable dir warns once",
          p.stderr.count("warning") == 1, p.stderr)
    subprocess.run(["rm", "-rf", d])


def test_keyfile_mode_warning():
    """-K warns on stderr about a key file others can read, and still knocks."""
    d = tempfile.mkdtemp()
    key = b"client-test-secret-0123456789"
    path = os.path.join(d, "k.key")
    with open(path, "wb") as f:
        f.write(key + b"\n")
    env = {"XDG_STATE_HOME": os.path.join(d, "state")}
    os.chmod(path, 0o600)
    p, _ = knock_state(env, path)
    check("mode: 0600 key gives no warning", "mode" not in p.stderr, p.stderr)
    os.chmod(path, 0o644)
    p, got = knock_state({"XDG_STATE_HOME": os.path.join(d, "state2")}, path)
    check("mode: 0644 key still knocks", p.returncode == 0 and len(got) == 4,
          f"{got} {p.stderr}")
    check("mode: 0644 key warns with path, mode and fix",
          path in p.stderr and "0644" in p.stderr and "chmod 600" in p.stderr,
          p.stderr)
    subprocess.run(["rm", "-rf", d])


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
              test_ipv6, test_bad_arguments, test_keyfile, test_keyfile_state, test_keyfile_mode_warning,
              test_source_port_in_use,
              test_privileged_port_needs_root):
        print(f"[run] {t.__name__}")
        t()
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
