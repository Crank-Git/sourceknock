# sourceknock

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

1. The daemon captures packets on an interface (`AF_PACKET`, root).
2. For each packet it extracts the **source port** (and source IP). Both IPv4
   and IPv6 frames are captured and decoded (IPv6 extension headers are walked,
   bounded).
3. A small state machine watches each client's stream of source ports. When it
   sees the configured ordered sequence within the timing window, it "triggers".
4. On trigger the daemon programs **nftables** to temporarily allow that client's
   IP to reach the hidden service port, then closes it again (after a fixed TTL,
   or on first connect).

```
client                              server
----                              --------
TCP sport=7000 ->  dst=X:PORT      \
TCP sport=8000 ->  dst=X:PORT   ==>  state machine sees 7000,8000,9000
TCP sport=9000 ->  dst=X:PORT      /   -> adds src IP to nft "allowed" set
TCP sport=<ephemeral> -> dst=X:22  ->   port 22 now reachable for this IP
```

## Layout

| File | Purpose |
|------|---------|
| `src/state.c`   | Pure knock-sequence state machine (no OS deps) |
| `src/packet.c`  | Parse Ethernet/IPv4/IPv6 frames into (src IP, sport, dport, proto) |
| `src/config.c`  | INI-style config parser (knockd-flavoured) |
| `src/capture.c` | `AF_PACKET` raw-socket capture (Linux) with frame de-duplication |
| `src/reward.c`  | nftables management: open/close the service port for a client IP |
| `src/sourceknock.c` | Daemon: wires capture -> state machine -> reward |
| `tests/`        | Unit tests (run on any OS) |

The core (state machine, packet parsing, config) is deliberately free of socket
code so it unit-tests anywhere. The Linux-only layers (`AF_PACKET`, nftables)
live in `capture.c` / `reward.c`.

## Build & test

```sh
make test      # build + run unit tests (any OS with a C compiler)
make daemon    # build the sourceknock daemon (Linux only; needs kernel headers)
```

Integration testing needs Linux + root (for `AF_PACKET` and `nft`).

## Configuration

```ini
[global]
interface = eth0

[trigger:ssh]
service = ssh
port = 22                 # hidden service port to open
protocol = tcp            # tcp or udp
sequence = 7000,8000,9000 # ordered source-port knock
window = 5                # whole sequence must complete within N seconds
mode = fixed_ttl          # fixed_ttl | close_on_connect
duration = 30             # seconds the port stays open (fixed_ttl)
fallback_ttl = 300        # safety max open time (close_on_connect)
```

- `mode = fixed_ttl` — keep the port open for `duration` seconds, then close.
- `mode = close_on_connect` — close as soon as the client makes a connection
  (with `fallback_ttl` as a safety net so a client that never connects can't
  leave the port open forever).

## Running

```sh
sudo ./sourceknock /path/to/sourceknock.conf
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
- nftables set syntax targets modern `nft` (validated on 1.0.9).
- De-duplication drops near-identical frames within a 0.5s window, which
  handles loopback/interfaces that deliver each frame twice.
- Source ports are spoofable — this is obfuscation, not authentication.
