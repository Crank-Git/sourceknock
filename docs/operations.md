# Operations

Running the daemon, the systemd units, NAT, limits, and troubleshooting. Install and the quick start are in the [README](../README.md).

## Running

Run it directly (needs root / `CAP_NET_RAW` for the raw socket and
`CAP_NET_ADMIN` for nftables):

```sh
sudo ./sourceknock /path/to/sourceknock.conf
```

With no argument it reads `/etc/sourceknock/sourceknock.conf`.

Check a config before (re)starting the daemon:

```sh
sourceknock -t /etc/sourceknock/sourceknock.conf && sudo systemctl restart sourceknock
```

`-t` exits 0 if the daemon would accept the config and 1 with the reason if
not; it needs no privileges and doesn't touch nftables. This matters because a
daemon that refuses a new config exits and leaves the previous run's tables in
place, closing the ports with nothing to open them.

## systemd

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

Apply config changes with a reload rather than a restart:

```sh
sudo systemctl reload sourceknock   # sends SIGHUP
```

A reload re-reads the config (and any `secret_file`). A config that doesn't
parse, or can't be applied, is refused with the reason in the log and the
running config is kept. A good one is applied in place: clients already let in
stay in (a restart would drop them), new triggers get their tables, and removed
triggers' tables are deleted.

Each daemon marks every table it creates with the absolute path of its config
as an nft table comment (`sourceknock:/etc/sourceknock/myconf.conf`). On start
and on reload the daemon deletes any `inet sourceknock_*` table that is not in
its config and carries its own mark, so a trigger you renamed or removed does
not leave its port closed behind it. A table with no mark, or with the mark of
another config, is never deleted: the daemon logs one warning that names it.
So you can run several daemons on one host (for example
`sourceknock@web` and `sourceknock@ssh`), each with its own config. Give the
configs different `service` names, because a table name must be unique.

The check that refuses two triggers on one port runs per config. Two daemons
must not manage the same port: each daemon's table drops the port, so a knock
that opens it in one table leaves the other table dropping it. A trigger with `close_on = all` drops its port on every interface, so it
also drops that port for any other daemon that manages it.

Requirements and limits:

- nftables with table comments. This was tested with nft 1.0.9; the kernel
  support for comments is in Linux 5.10 and later. If `nft` rejects the
  comment, the daemon refuses to start. It logs `reward: nft -f - failed`
  and `could not program nftables table`, with the `nft` error above them.
- The absolute config path may have at most 116 characters, and no quote,
  backslash or control character, because nft limits a comment to 128
  characters. The daemon refuses a longer path.
- `add table` does not change the comment of a table that exists already. A
  table made by an earlier version has no mark, so the daemon keeps it and
  warns. Delete it once (`nft delete table inet sourceknock_<service>`) and
  reload to get a marked table. Moving or renaming a config file changes its
  mark in the same way: the tables with the old mark stay until you delete
  them.

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

## NAT

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

## Notes and limitations

- Linux only (`AF_PACKET`, nftables).
- An interface that goes down, is deleted, or doesn't exist yet at startup
  (e.g. a VPN that comes up later) doesn't stop the daemon: it logs it, keeps
  that trigger's ports closed, keeps serving the other interfaces, and starts
  reading knocks there again within a second of the interface being up.
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
- **"interface '...' does not exist"** (from `-t`) — check `[global]
  interface =` and any per-trigger `interface =`. The daemon itself still
  starts with a missing interface (see below); `-t` reports it so a typo
  doesn't go unnoticed.
- **"has link type ... which sourceknock can't read knocks from"** — see the
  supported interfaces under [Notes and limitations](#notes-and-limitations).
- **"could not program nftables table"** — `nft` is missing, or the process
  lacks `CAP_NET_ADMIN`, or an existing object in `inet sourceknock_<service>`
  conflicts (delete that table and retry).
- **"config error: ..."** — the message names the key or trigger; see
  [Configuration reference](configuration.md).

### The port never opens

- **Wrong interface.** The trigger's interface (`interface =` in the trigger,
  else `[global]`) must be the one that sees the client's frames on the
  server, not the client's.
- **No knock seen.** The knock is encoded in the client's **source** port, not
  the destination port. Knock with `sourceknock-knock`, which binds each step
  to the right source port. If the trigger sets `knock_port`, pass it with
  `-p`. Each completed knock logs `knock OK from <ip>`; a wrong step logs
  `progress reset`.
- **NAT rewrote the source ports.** See [NAT](#nat).
- **Sequence/window mismatch.** The ordered source-port sequence and the
  window must match between client and daemon. See the samples in
  [examples](../examples) and the full field reference in the
  [configuration reference](configuration.md) (or `man 1 sourceknock`).
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
