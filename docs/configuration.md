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
# optional: this trigger's interface (defaults to [global] interface)
# interface = wg0
# optional: where the drop rules apply, interface (default) or all
# close_on = all
```

> **Note:** comments start with `#` or `;`, either on their own line or after
> a value (`port = 22  # ssh`). A `#` or `;` inside a word, such as in a path,
> is kept.

## Startup checks

The daemon refuses to start on a config it can't use: a key outside any
section, a trigger without `port` or `sequence`, a source port of 0 in a
sequence, two triggers whose service names map to the same nftables table
(names are sanitized to `[A-Za-z0-9_]`, so `web-1` and `web_1` collide, and must
be at most 46 characters), or two triggers that manage the same port and
protocol on the same interface (each one's drop rule would block the other's
clients, so nobody could get in), or two triggers that manage the same port and
protocol when either one uses `close_on = all` (that drop rule covers every
interface). A `close_on` value other than `interface` or `all` is an error. It
logs a warning (but starts) for a sequence
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

- `interface` — the interface a trigger reads knocks from **and** closes its
  ports on. Set it in `[global]` as the default for every trigger, and
  optionally per trigger to override it, so one daemon can guard services on
  several interfaces (e.g. `eth0` and `wg0`). The drop rules match only packets
  arriving on that interface: the same port reached over any other interface
  (a VPN such as `tailscale0`, or `lo`) is not touched, so it can't lock you
  out there. The exception is `close_on = all` (below), which closes the
  ports on every interface. Ethernet, loopback, tun, WireGuard, PPP and ipip / ip6tnl / sit
  links work.

- `close_on = interface | all` — where the drop rules apply. Set it in
  `[global]` as the default for every trigger, and optionally per trigger to
  override it. The built-in default is `interface`.
  - `interface`: the drop rules match only the trigger's interface (see
    above). A host with a second public interface, or with IPv6 on another
    interface, keeps the port open there with no knock. At start, at reload
    and in `sourceknock -t`, the daemon logs one warning for each such trigger.
    It lists the other interfaces on the host that are up (not `lo`) and says
    to set `close_on = all`:
    `[ssh] warning: close_on = interface leaves its ports open on eth1; set close_on = all to block them`.
  - `all`: the drop rules have no interface match, so the port is closed on
    every interface, including `lo`. Local clients on the host need a knock
    too. Knocks are still read only on the trigger's `interface`. Two triggers
    can not share a port and protocol when either one uses `all`.

- `mode = fixed_ttl` — keep the port open for `duration` seconds, then close.
- `mode = close_on_connect` — close as soon as the client makes a connection
  (with `fallback_ttl` as a safety net so a client that never connects can't
  leave the port open forever). The safety net is the nft element's own
  timeout, so the kernel closes the port even if the daemon sees no further
  traffic, is stopped, or crashes.
  - **TCP:** the first new connection (a SYN) to a service port closes the
    port. Packets of a session that is already open (keepalives, data) don't,
    so knocking again while connected still lets a second connection in.
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
  TCP segments of a flow that is already open (ACK set) never count,
  so a busy TCP session can't reset a knock. UDP traffic from the same client
  (for example a WireGuard or QUIC flow) still counts: **set `knock_port` on
  every trigger whose clients can have such a UDP flow open while they knock**,
  or the knock fails at random with
  `incomplete/wrong knock ... progress reset` in the log.
  Send the knock to this port (pick one nothing listens on, and not a service
  port, so in `close_on_connect` mode a re-knock can't close the port). The
  close-on-connect detection is unaffected.
- `max_allowed` (optional, default 256) — the most client addresses let in at
  once, per address family (the size of the nftables allowed sets). When it's
  full, a correct knock logs `reward_open FAILED` and doesn't open the port.
- `port` accepts a single port, a comma-separated list, or an inclusive range,
  e.g. `port = 22`, `port = 80, 443`, or `port = 8000-8002`. On a successful
  knock **all** listed ports are opened for the client (each port gets its own
  nftables accept/drop rule, sharing one per-family "allowed" set). Ports must
  be in 1..65535.

## Time-based knocks

Set `secret_file` instead of `sequence` and the knock is derived from a shared
secret and the clock, like a 2FA code:

- Every 30 seconds there is a new 4-port sequence (ports 1024-32767), computed
  as HMAC-SHA256 of the secret and the time step.
- The daemon accepts the previous, current and next step, so client and
  server clocks may differ by about 30 seconds. **Keep both clocks synced**
  (NTP; Ubuntu does this by default). A server clock that drifts further makes
  every knock fail.
- Each step's sequence opens the port **once**. Repeating it, from any
  address, is refused and logged ("already used"), so a knock someone sees
  can't be replayed.
- `sourceknock-knock -K` records the last step it sent for each key file and
  host in `$XDG_STATE_HOME/sourceknock/` (default
  `~/.local/state/sourceknock/`, files mode 0600). When the current step is
  used, it sends the next step, so you can knock twice within 30 seconds. A
  third knock in that time exits with status 1 and prints how many seconds to
  wait. If the record cannot be read or written, the client prints one
  warning and knocks with the current step.
- The record is local to one client. Two clients that share a secret do not
  share it, so they can send the same step; the daemon refuses the second.
- The revoke knock is derived from the same secret (`sourceknock-knock -K
  FILE -r`); `admin_sequence` can't be combined with `secret_file`.

Create a secret (at least 16 bytes; the file's bytes, minus trailing
whitespace, are the key). The file should have mode 0600, owned by the user that
runs the daemon (the daemon warns when group or other users can read it):

```sh
head -c 32 /dev/urandom | base64 | sudo tee /etc/sourceknock/ssh.key >/dev/null
sudo chown sourceknock:sourceknock /etc/sourceknock/ssh.key
sudo chmod 0600 /etc/sourceknock/ssh.key
```

Copy the same file to each client (keep it private) and knock with
`sourceknock-knock -K ~/.config/sourceknock/ssh.key server.example.com`. The
secret is read at start and on every reload, so a new secret takes effect with
`systemctl reload sourceknock`.

If the group or other users can read a key file, the daemon logs a warning
at start, at reload and in `sourceknock -t`, and `sourceknock-knock -K` prints
it on stderr. Both still use the key. Fix it with `chmod 600 FILE`.

## IPv4 and IPv6

`sourceknock` captures **both** IPv4 and IPv6 traffic. IPv6 source addresses are
keyed independently from IPv4 in the state machine, and the reward layer keeps
separate `allowed_v4` / `allowed_v6` nftables sets (an `inet` table matches both
families, so a single set of rules opens the port for either family). IPv6
extension headers are walked (fragment, hop-by-hop, routing, destination
options), bounded to 8 hops; encrypted L4 (ESP/AH) or non-TCP/UDP next headers
are not decoded.
