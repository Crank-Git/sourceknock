# sourceknock

[![CI](https://github.com/Crank-Git/sourceknock/actions/workflows/ci.yml/badge.svg)](https://github.com/Crank-Git/sourceknock/actions/workflows/ci.yml)
[![Release](https://github.com/Crank-Git/sourceknock/actions/workflows/release.yml/badge.svg)](https://github.com/Crank-Git/sourceknock/actions/workflows/release.yml)

A port-knocking daemon that knocks via **source ports** instead of destination
ports. Standard port knocking encodes the secret in the *destination* port
sequence — a network scanner sees a client hammering a list of ports and can
fingerprint it. `sourceknock` keeps the destination fixed and varies the
**source port** instead, so the knock doesn't stand out to a destination-port
scan.

> **Threat model:** source ports are trivially spoofable, like any L4 header
> field. This gives you *stealth / obfuscation* (the attack surface stays
> invisible, noisy scans look normal), **not** authentication. The real security
> still comes from your service auth (SSH keys/passwords). Don't rely on
> sourceknock as the only control.

## How it works

1. The daemon captures the frames an interface receives (`AF_PACKET`, root).
2. For each packet it extracts the **source port** (and source IP). Both IPv4
   and IPv6 frames are captured and decoded (IPv6 extension headers are walked,
   bounded).
3. A small state machine follows each client that is partway through a knock
   (bounded; ordinary traffic creates no state). When it sees the configured
   ordered sequence within the timing window, it "triggers".
4. On trigger the daemon programs **nftables** to allow that client's IP to
   reach the hidden service port(s), then closes it again (after a fixed TTL,
   on first connect, or on an admin revoke). Connections already established
   keep working when it closes.

```
client (sourceknock-knock)          server (sourceknock)
------                              --------------------
UDP sport=7000 -> dst=X:PORT        \
UDP sport=8000 -> dst=X:PORT     ==>  state machine sees 7000,8000,9000
UDP sport=9000 -> dst=X:PORT        /   -> adds src IP to nft "allowed" set
TCP sport=<ephemeral> -> dst=X:22   ->  port 22 now reachable for this IP
```

`PORT` is any port unless the trigger sets `knock_port` (see
[Configuration](#configuration)).

## Layout

| File | Purpose |
|------|---------|
| `src/state.c`   | Pure knock-sequence state machine (no OS deps), bounded client table |
| `src/packet.c`  | Parse Ethernet / raw-IP frames (IPv4, IPv6) into (src IP, sport, dport, proto) |
| `src/config.c`  | INI-style config parser and validation (knockd-flavored) |
| `src/close.c`   | Pure per-packet decisions: does a frame count toward a knock (`knock_port`), does it close a `close_on_connect` port |
| `src/capture.c` | `AF_PACKET` raw-socket capture (Linux): link-type detection, received frames only |
| `src/reward.c`  | nftables management: open/close the service port for a client IP |
| `src/sourceknock.c` | Daemon: wires capture -> state machine -> reward |
| `src/knock.c`   | `sourceknock-knock`, the client that sends a knock (Linux/macOS) |
| `tests/`        | Unit tests (any OS), knock-client tests, e2e and systemd tests (Linux + root), fuzz target |
| `contrib/systemd/` | `sourceknock.service` and the `sourceknock@.service` template |
| `man/`          | `sourceknock(1)`, `sourceknock-knock(1)` |
| `examples/`     | Sample configs (SSH, web, WireGuard) |

The core (state machine, packet parsing, config, per-packet decisions) is
deliberately free of socket code so it unit-tests anywhere. The Linux-only
layers (`AF_PACKET`, nftables) live in `capture.c` / `reward.c`.

## Build & test

```sh
make test      # unit tests + knock-client tests (any OS with a C compiler + python3)
make test-asan # the same under ASan + LeakSanitizer + UBSan
make client    # build the sourceknock-knock client (Linux, macOS)
make daemon    # build the sourceknock daemon (Linux only; needs kernel headers)
make fuzz      # 60s libFuzzer run on the packet parser (Linux, clang)
```

The daemon-level tests need Linux and root (for `AF_PACKET`, network
namespaces and `nft`); see [CONTRIBUTING](CONTRIBUTING.md):

```sh
make daemon client
sudo bash tests/e2e_integration.sh tests/e2e_fixed.conf
sudo bash tests/e2e_integration.sh tests/e2e_close.conf
sudo bash tests/systemd_smoke.sh   # needs a running systemd
```

## Continuous Integration

CI runs on every push and pull request (GitHub Actions):

- **Unit + client tests** (`make test`) on Linux and macOS.
- **Sanitizers** (`make test-asan`: ASan + LeakSanitizer + UBSan) on Linux.
- **Daemon + client build** and a bounded **libFuzzer** run on the packet
  parser, on Linux.
- **End-to-end tests** on Linux: the real daemon in a network namespace with
  real nftables, in both `fixed_ttl` and `close_on_connect` modes (knock/open/
  close, long-lived sessions surviving the close, what scans see, startup
  failures, many clients, loopback and ipip links, `knock_port`, shutdown).
- **systemd units**: installs and starts both units on the runner and checks
  they run unprivileged with only `CAP_NET_RAW` + `CAP_NET_ADMIN`.
- **Format / lint / secrets**: clang-format, clang-tidy (advisory), gitleaks.

Workflow definitions live in `.github/workflows/`.

## Releases

Cut a release by pushing a `v*` tag on `main`. CI runs the tests, builds the
Linux daemon and knock client, and publishes both as GitHub Release
artifacts:

```sh
git tag -a v1.1.0 -m "sourceknock 1.1.0"
git push origin v1.1.0
```

The release attaches `sourceknock` and `sourceknock-knock` built on
`ubuntu-latest` (x86-64 Linux). On macOS, build the client with `make client`.

## Configuration

```ini
[global]
interface = eth0

[trigger:ssh]
service = ssh
# hidden service port(s) to open
port = 22
# tcp or udp
protocol = tcp
# ordered source-port knock
sequence = 7000,8000,9000
# whole sequence must complete within N seconds
window = 5
# fixed_ttl | close_on_connect | permanent
mode = fixed_ttl
# seconds the port stays open (fixed_ttl)
duration = 30
# safety max open time (close_on_connect)
fallback_ttl = 300
# optional revoke knock (permanent mode)
admin_sequence = 9000,8000,7000
# optional: only frames sent to this destination port count toward the knock
# (then knock with `sourceknock-knock -p 4444 ...`)
# knock_port = 4444
```

> **Note:** the parser strips only full-line comments (lines starting with `#`
> or `;`). Inline comments after a value are **not** stripped, so keep value
> lines free of trailing `#`/`;` (see the notes in `examples/`).

The daemon refuses to start on a config it can't use: a key outside any
section, a trigger without `port` or `sequence`, a source port of 0 in a
sequence, or two triggers whose service names map to the same nftables table
(names are sanitized to `[A-Za-z0-9_]`, so `web-1` and `web_1` collide, and must
be at most 46 characters). It logs a warning (but starts) for a sequence
shorter than 3 ports or one using the Linux ephemeral range 32768-60999, which
ordinary outgoing connections use.

Closing the port (TTL expiry, close on connect, admin revoke) only blocks
**new** connections. Sessions that are already established keep working: the
service chain accepts `ct state established,related` ahead of its drop rules,
and, for TCP, lets through non-SYN segments that carry ACK so sessions that
predate the daemon (e.g. the SSH session you install it from) survive startup.
Those segments can't open a connection, and a stray ACK gets the same RST a
closed port sends, so a scan still sees nothing.

- `mode = fixed_ttl` — keep the port open for `duration` seconds, then close.
- `mode = close_on_connect` — close as soon as the client makes a connection
  (with `fallback_ttl` as a safety net so a client that never connects can't
  leave the port open forever). The safety net is the nft element's own
  timeout, so the kernel closes the port even if the daemon sees no further
  traffic, is stopped, or crashes.
  - **TCP:** the first packet to a service port (the connection's SYN) closes
    the port.
  - **UDP:** there is no handshake, so the first *subsequent* UDP packet to a
    service port closes the port. The arming knock itself does **not** close
    the port the instant it opens — only a later packet to the service port
    does.
- `mode = permanent` — open the port with no timeout, so access persists past
  any TTL without re-knocking. Pair with an optional `admin_sequence` to revoke:
  when that separate knock completes, the client's IP is removed from the allowed
  set and the port closes again. The admin sequence runs on its own state machine
  (keyed by source port), so it never interferes with the primary knock.
- `knock_port` (optional) — only frames sent to this **destination** port count
  toward the knock (primary and admin sequences). Without it, every TCP/UDP
  frame from a client counts, so other traffic from the same address (an
  existing session, a browser, other hosts behind the same NAT) can reset a
  knock in progress, and replies to the server's own outbound connections
  (which arrive from the remote's service port) can look like knock steps.
  Send the knock to this port (pick one nothing listens on, and not a service
  port, so in `close_on_connect` mode a re-knock can't close the port). The
  close-on-connect detection is unaffected.
- `port` accepts a single port, a comma-separated list, or an inclusive range,
  e.g. `port = 22`, `port = 80, 443`, or `port = 8000-8002`. On a successful
  knock **all** listed ports are opened for the client (each port gets its own
  nftables accept/drop rule, sharing one per-family "allowed" set). Ports must
  be in 1..65535.

## Knocking

Use the bundled client, `sourceknock-knock` (`make client`, installed by
`make install`; builds on Linux and macOS). It sends one UDP datagram per
sequence port, each from that **source** port, in order, then exits:

```sh
sourceknock-knock server.example.com 7000,8000,9000
ssh user@server.example.com
```

Options: `-p PORT` destination port (the trigger's `knock_port`, if it sets
one; default 9), `-d MS` delay between steps (default 50; keep the whole knock
inside `window`), `-s ADDR` local address, `-4`/`-6`. Source ports below 1024
need root on Linux. See `man sourceknock-knock`.

```sh
# a trigger with knock_port = 4444, over IPv6
sourceknock-knock -6 -p 4444 server.example.com 7000,8000,9000
```

Release builds of the client are attached to each
[GitHub release](https://github.com/Crank-Git/sourceknock/releases).

### NAT

The knock lives in the source port, so anything that rewrites source ports
breaks it. Most home routers keep the client's source port when it is free;
carrier-grade NAT (common on mobile networks) and some corporate firewalls
pick their own, and then no knock can arrive intact. To check a network, knock
a host where you can watch the traffic and compare the source ports that
arrive with the ones you sent:

```sh
# on the server (or any host you control)
sudo tcpdump -ni eth0 udp and dst port 9
# from the client
sourceknock-knock server.example.com 7000,8000,9000
```

If the ports in the capture are not 7000, 8000, 9000, that network rewrites
them; knock from elsewhere (or over a VPN that preserves ports).

## Running

Run it directly (needs root / `CAP_NET_RAW` for the raw socket and
`CAP_NET_ADMIN` for nftables):

```sh
sudo ./sourceknock /path/to/sourceknock.conf
```

With no argument it reads `/etc/sourceknock/sourceknock.conf`.

### systemd

On systemd hosts, install with `make install` (needs root). This places the
daemon and `sourceknock-knock` in `/usr/local/bin`, the man pages in
`/usr/local/share/man/man1`, and the units in `/etc/systemd/system`, then
reloads systemd:

```sh
sudo make install
```

The units run the daemon as the unprivileged `sourceknock` user, granted only
`CAP_NET_RAW` and `CAP_NET_ADMIN` (not root). Create that user first if it
doesn't exist:

```sh
sudo useradd --system --user-group --home-dir /var/lib/sourceknock --no-create-home sourceknock
```

Then drop in a config at `/etc/sourceknock/sourceknock.conf` and start it:

```sh
# default unit -> /etc/sourceknock/sourceknock.conf
sudo systemctl enable --now sourceknock

# or a per-instance config via the template unit:
#   /etc/sourceknock/myconf.conf
#   sudo systemctl enable --now sourceknock@myconf
```

Stop / remove:

```sh
sudo systemctl disable --now sourceknock   # then:
sudo make uninstall
```

Stopping the daemon removes every allowed client but **leaves its nftables
table in place**, so the service port stays closed (fail closed) until the
daemon starts again. To open the port to everyone again after removing
sourceknock, delete the table:

```sh
sudo nft delete table inet sourceknock_ssh   # one per [trigger:<service>]
```

## IPv4 & IPv6

`sourceknock` captures **both** IPv4 and IPv6 traffic. IPv6 source addresses are
keyed independently from IPv4 in the state machine, and the reward layer keeps
separate `allowed_v4` / `allowed_v6` nftables sets (an `inet` table matches both
families, so a single set of rules opens the port for either family). IPv6
extension headers are walked (fragment, hop-by-hop, routing, destination
options), bounded to 8 hops; encrypted L4 (ESP/AH) or non-TCP/UDP next headers
are not decoded.

## Notes / limitations

- Linux only (`AF_PACKET`, nftables).
- Supported capture interfaces: Ethernet and loopback, and raw-IP links with
  no link header: tun and WireGuard (`wg0`), PPP, and ipip / ip6tnl / sit
  tunnels. The daemon logs the link type at startup and refuses anything else
  (e.g. GRE, whose multipoint mode prefixes each frame with an outer header)
  instead of running and never matching a knock.
- nftables set syntax targets modern `nft` (validated on 1.0.9).
- Only frames the host *receives* count toward a knock; frames it sends
  (including loopback's second copy of every frame) are ignored.
- A repeat of a knock step that was already matched is ignored rather than
  resetting the knock, so clients whose knock packets get retransmitted (e.g.
  knocking with TCP `connect()`, whose SYNs are resent every ~1s) still work.
  Any other port mid-sequence resets it.
- At most 4096 clients per trigger are tracked mid-knock at once; beyond that
  the oldest in-progress knock is dropped. Clients that never send the first
  knock port cost nothing.
- Source ports are spoofable — this is obfuscation, not authentication.

## Troubleshooting

### The daemon won't start

The daemon checks everything at startup and exits non-zero with a reason
instead of running half-configured. Any nft table it already programmed is
removed again, so a failed start leaves the host as it was.

- **"capture open failed (need root?)"** — `AF_PACKET` raw sockets need root
  or `CAP_NET_RAW`. Run it as root, or under the systemd unit (which grants
  only `CAP_NET_RAW` + `CAP_NET_ADMIN` to the unprivileged `sourceknock` user —
  see [Running](#running)).
- **"cannot find interface"** — check `[global] interface =`.
- **"has link type ... which sourceknock can't read knocks from"** — see the
  supported interfaces under [Notes / limitations](#notes--limitations).
- **"could not program nftables table"** — `nft` is missing, or the process
  lacks `CAP_NET_ADMIN`, or an existing object in `inet sourceknock_<service>`
  conflicts (delete that table and retry).
- **"config error: ..."** — the message names the key or trigger; see
  [Configuration](#configuration).

### The port never opens

- **Wrong interface.** `[global] interface =` must be the daemon's capture
  interface (the one that sees the client's frames), not the client's.
- **No knock seen.** The knock is encoded in the client's **source** port, not
  the destination port. Knock with `sourceknock-knock`, which binds each step
  to the right source port. If the trigger sets `knock_port`, pass it with
  `-p`. Each completed knock logs `knock OK from <ip>`; a wrong step logs
  `progress reset`.
- **NAT rewrote the source ports.** See [NAT](#nat).
- **Sequence/window mismatch.** The ordered source-port sequence and the
  window must match between client and daemon. See the samples in
  [examples](examples) and the full field reference in the
  [README Configuration](#configuration) section (or `man 1 sourceknock`).
- **nftables missing or too old.** The daemon needs `nft` and modern set
  syntax (validated on 1.0.9). Install nftables (`apt install nftables`), and
  note that on GitHub's ubuntu runner the `nftables` package must be installed
  explicitly (the `nft` package name does not exist there).

### The port stays open (TTL / close-on-connect not firing)

- In `fixed_ttl` mode the port closes after `duration` seconds (nft element
  timeout). In `close_on_connect` it closes on the first connection, with
  `fallback_ttl` as a kernel-enforced safety net (also an nft element
  timeout). Knocking again while the port is open restarts the timer.
- For UDP there is no handshake, so `close_on_connect` fires on the first
  subsequent UDP packet to the service port — the arming knock itself does not
  close the port the instant it opens.

### Checking what the daemon programmed

The daemon namespaces its nftables table by service name (`inet
sourceknock_<service>`), with separate `allowed_v4` / `allowed_v6` sets:

```sh
nft list set inet sourceknock_ssh allowed_v4
```

If the table is missing, the daemon isn't running (it refuses to start rather
than run without one; see above). `journalctl -u sourceknock` (or `-u
sourceknock@<instance>`) shows the daemon's own logs.

### IPv6 notes

IPv6 source addresses are keyed independently from IPv4, and the daemon walks
IPv6 extension headers (bounded to 8 hops). Encrypted L4 (ESP/AH) or
non-TCP/UDP next headers are not decoded, so a knock over those protocols
cannot be matched. Ensure your client actually sends over the family you
configured.

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 Crank-Git.
