# Configuration reference

Every key and mode the daemon reads. The [README](../README.md#configuration) has the short version, and `man 1 sourceknock` has the same fields.

## Example

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

## Startup checks

The daemon refuses to start on a config it can't use: a key outside any
section, a trigger without `port` or `sequence`, a source port of 0 in a
sequence, or two triggers whose service names map to the same nftables table
(names are sanitized to `[A-Za-z0-9_]`, so `web-1` and `web_1` collide, and must
be at most 46 characters). It logs a warning (but starts) for a sequence
shorter than 3 ports or one using the Linux ephemeral range 32768-60999, which
ordinary outgoing connections use.

## What closing means

Closing the port (TTL expiry, close on connect, admin revoke) only blocks
**new** connections. Sessions that are already established keep working: the
service chain accepts `ct state established,related` ahead of its drop rules,
and, for TCP, lets through non-SYN segments that carry ACK so sessions that
predate the daemon (e.g. the SSH session you install it from) survive startup.
Those segments can't open a connection, and a stray ACK gets the same RST a
closed port sends, so a scan still sees nothing.

## Keys and modes

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

## IPv4 and IPv6

`sourceknock` captures **both** IPv4 and IPv6 traffic. IPv6 source addresses are
keyed independently from IPv4 in the state machine, and the reward layer keeps
separate `allowed_v4` / `allowed_v6` nftables sets (an `inet` table matches both
families, so a single set of rules opens the port for either family). IPv6
extension headers are walked (fragment, hop-by-hop, routing, destination
options), bounded to 8 hops; encrypted L4 (ESP/AH) or non-TCP/UDP next headers
are not decoded.
