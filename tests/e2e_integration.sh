#!/usr/bin/env bash
# End-to-end integration test for the sourceknock daemon (issue #18).
#
#   tests/e2e_integration.sh <config-file> [sequence]
#
# Topology: the client lives on the host; the daemon + a stand-in service live
# inside a network namespace. A veth pair bridges them (client 10.20.0.1 <->
# server 10.20.0.2), so every client frame arrives as RX on the daemon's
# capture interface. We then drive a full cycle and assert the port opens on
# knock and closes again (after the fixed TTL, or on the first connect for
# close_on_connect mode). Exits non-zero if any expectation is wrong.
#
# Requires: root (sudo) for network namespaces + AF_PACKET + nftables, and a
# Linux host. Built to run on CI's ubuntu runner (privileged) or any netns-capable
# box. Needs the daemon built at <repo>/sourceknock.
set -u

CONF="${1:?usage: e2e_integration.sh <config-file> [sequence]}"
SEQ_ARG="${2:-}"
NS=e2e
CLIENT=10.20.0.1      # host side of the veth
SERVER=10.20.0.2      # inside the netns (runs the daemon + listener)

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$(cd "$HERE/.." && pwd)/sourceknock"
DRIVER="$HERE/driver.py"
LISTENER="$HERE/listener.py"
# Work in a private temp dir so the test is hermetic: it must run with no
# pre-existing scratch dir (e.g. on CI's ubuntu runner). WORK is removed by
# cleanup().
WORK="$(mktemp -d)"
LOG="$WORK/daemon.log"
UP="$WORK/listen_up"

pass=0; fail=0
check() { # label expected_open(1/0)
  local label="$1" want="$2" got="$3"
  if [ "$want" = "$got" ]; then
    echo "PASS  $label (open=$got)"; pass=$((pass+1))
  else
    echo "FAIL  $label (want open=$want got=$got)"; fail=$((fail+1))
  fi
}
probe() { python3 "$DRIVER" probe "$SERVER" "$PORT" 1.0; }

MODE="$(awk -F= '/^[[:space:]]*mode[[:space:]]*/{gsub(/[^a-z_]/,"",$2);print $2;exit}' "$CONF")"
PORT="$(awk -F= '/^[[:space:]]*port[[:space:]]*/{gsub(/[^0-9]/,"",$2);print $2;exit}' "$CONF")"
SEQ="${SEQ_ARG:-$(awk -F= '/^[[:space:]]*sequence[[:space:]]*/{gsub(/[^0-9,]/,"",$2);print $2;exit}' "$CONF")}"
DURATION="$(awk -F= '/^[[:space:]]*duration[[:space:]]*/{gsub(/[^0-9]/,"",$2);print $2;exit}' "$CONF")"
DURATION="${DURATION:-4}"
FALLBACK="$(awk -F= '/^[[:space:]]*fallback_ttl[[:space:]]*/{gsub(/[^0-9]/,"",$2);print $2;exit}' "$CONF")"
FALLBACK="${FALLBACK:-300}"
SERVICE="$(awk -F= '/^[[:space:]]*service[[:space:]]*/{gsub(/[^A-Za-z0-9_]/,"",$2);print $2;exit}' "$CONF")"

cleanup() {
  sudo pkill -f 'sourceknock .*/sourceknock.conf' 2>/dev/null
  sudo pkill -f 'listener\.py' 2>/dev/null
  sudo ip netns del "$NS" 2>/dev/null
  sudo pkill -9 -f "$BIN" 2>/dev/null
  sudo ip addr del $CLIENT/24 dev e2e-c 2>/dev/null
  sudo ip link del e2e-c 2>/dev/null
  sudo ip link del sktun0 2>/dev/null
  # tidy leftover state from a previous interrupted run
  sudo ip netns del e2etest 2>/dev/null
  sudo ip link del e2etest-c 2>/dev/null
  sudo ip link del e2etest-s 2>/dev/null
  # On failure, leave a trail so the next CI run is self-explaining.
  if [ "${fail:-0}" -ne 0 ]; then
    echo "----- daemon.log (last 30) -----"
    tail -n 30 "$WORK/daemon.log" 2>/dev/null
    echo "----- listener.log (last 30) -----"
    tail -n 30 "$WORK/listener.log" 2>/dev/null
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "FAIL daemon not built at $BIN (run 'make daemon')"; exit 1; }

sudo ip netns del "$NS" 2>/dev/null
sudo ip netns add "$NS"
sudo ip link add e2e-c type veth peer name e2e-s
sudo ip link set e2e-s netns "$NS"
sudo ip addr add $CLIENT/24 dev e2e-c
sudo ip link set e2e-c up
sudo ip netns exec "$NS" ip addr add $SERVER/24 dev e2e-s
sudo ip netns exec "$NS" ip link set e2e-s up
sudo ip netns exec "$NS" ip link set lo up

rm -f "$UP"
SK_LISTEN_HOST=$SERVER sudo ip netns exec "$NS" setsid python3 "$LISTENER" "$PORT" "$UP" >"$WORK/listener.log" 2>&1 </dev/null &
for _ in $(seq 1 50); do [ -f "$UP" ] && break; sleep 0.1; done
[ -f "$UP" ] || { echo "FAIL listener never came up"; fail=$((fail+1)); echo "RESULT: $pass passed, $fail failed"; exit 1; }

# ---- startup failures must refuse to run AND leave the host as it was ----
# Each case: the daemon exits non-zero, never reports "listening for knocks",
# leaves no sourceknock table behind, and the service port is still reachable
# exactly as it was before the daemon ran.
nft_tables() { sudo ip netns exec "$NS" nft list tables 2>/dev/null | grep -c sourceknock; }
expect_refuse() { # label conf [nocap]
  local label="$1" conf="$2" out="$WORK/refuse.log" rc
  if [ "${3:-}" = "nocap" ]; then
    # Drop CAP_NET_ADMIN from the bounding set: still root, raw sockets work,
    # but nft can't touch the ruleset.
    sudo ip netns exec "$NS" timeout 10 capsh --drop=cap_net_admin -- -c "exec '$BIN' '$conf'" >"$out" 2>&1 </dev/null; rc=$?
  else
    sudo ip netns exec "$NS" timeout 10 "$BIN" "$conf" >"$out" 2>&1 </dev/null; rc=$?
  fi
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ] && ! grep -q "listening for knocks" "$out"; then
    check "$label: refuses to start (exit $rc)" 1 1
  else
    check "$label: refuses to start (exit $rc)" 1 0; tail -5 "$out"
  fi
  local left; left="$(nft_tables)"
  if [ "$left" = "0" ]; then check "$label: no table left behind" 1 1; else check "$label: no table left behind ($left)" 1 0; fi
  if probe; then check "$label: port untouched" 1 1; else check "$label: port untouched" 1 0; fi
  sudo ip netns exec "$NS" nft flush ruleset
}

echo "--- startup failures ---"
expect_refuse "no CAP_NET_ADMIN" "$CONF" nocap
grep -q "could not program nftables" "$WORK/refuse.log" && check "no CAP_NET_ADMIN: says why" 1 1 || check "no CAP_NET_ADMIN: says why" 1 0

sed 's/^interface = .*/interface = sk-nosuch0/' "$CONF" > "$WORK/badif.conf"
expect_refuse "unknown interface" "$WORK/badif.conf"

# An nft object the daemon can't reconcile (allowed_v4 with the wrong type).
sudo ip netns exec "$NS" nft add table inet "sourceknock_$SERVICE"
sudo ip netns exec "$NS" nft add set inet "sourceknock_$SERVICE" allowed_v4 '{ type ipv6_addr; }'
expect_refuse "conflicting nft set" "$CONF"

# Second trigger fails after the first was fully programmed: the first
# trigger's table must be removed too, or its drop rule would lock the port.
{ cat "$CONF"; printf '\n[trigger:other]\nservice = other\nport = %s\nsequence = 4400,5500,6600\n' "$((PORT+5))"; } > "$WORK/two.conf"
sudo ip netns exec "$NS" nft add table inet sourceknock_other
sudo ip netns exec "$NS" nft add set inet sourceknock_other allowed_v4 '{ type ipv6_addr; }'
expect_refuse "second trigger fails" "$WORK/two.conf"

# Wait for a file to appear (up to ~5s).
wait_file() { for _ in $(seq 1 50); do [ -f "$1" ] && return 0; sleep 0.1; done; return 1; }

# A connection established BEFORE the daemon starts must survive startup: the
# daemon's drop rule may only block new connections, never existing flows.
echo "--- connection opened before daemon start (expect it to survive) ---"
python3 "$DRIVER" hold "$SERVER" "$PORT" 3 "$WORK/pre_up" >"$WORK/pre_hold.log" 2>&1 &
PRE_HOLD=$!
wait_file "$WORK/pre_up" || echo "pre-start hold never connected"

start_daemon() {
  : > "$LOG"
  sudo ip netns exec "$NS" setsid "$BIN" "$CONF" >"$LOG" 2>&1 </dev/null &
  DAEMON_PID=$!
  for _ in $(seq 1 50); do grep -q "listening for knocks" "$LOG" 2>/dev/null && return 0; sleep 0.1; done
  return 1
}
start_daemon || { echo "FAIL daemon never started"; tail -5 "$LOG"; fail=$((fail+1)); echo "RESULT: $pass passed, $fail failed"; exit 1; }

if wait $PRE_HOLD; then check "pre-start connection survives daemon start" 1 1; else check "pre-start connection survives daemon start" 1 0; cat "$WORK/pre_hold.log"; fi

echo "mode=$MODE port=$PORT seq=$SEQ duration=$DURATION"
echo "--- probe BEFORE knock (expect closed) ---"
if probe; then check "pre-knock closed" 0 1; else check "pre-knock closed" 0 0; fi

# What a scanner sees on the hidden port before any knock. Connection attempts
# and FIN/NULL scans must be silently dropped. A bare ACK is let through (so
# sessions that predate conntrack survive) and must look exactly like an ACK
# to a port nothing listens on: a RST, never an "open" tell.
echo "--- scanner view of the hidden port (no knock) ---"
expect_flags() { # label dport kind want
  local got; got="$(sudo python3 "$DRIVER" flags "$CLIENT" "$SERVER" "$2" "$3")"
  if [ "$got" = "$4" ]; then echo "PASS  $1 ($3 -> $got)"; pass=$((pass+1));
  else echo "FAIL  $1 ($3 -> $got, want $4)"; fail=$((fail+1)); fi
}
UNUSED_PORT=$((PORT+1))
ACK_UNUSED="$(sudo python3 "$DRIVER" flags "$CLIENT" "$SERVER" "$UNUSED_PORT" ACK)"
expect_flags "SYN scan dropped" "$PORT" SYN none
expect_flags "FIN scan dropped" "$PORT" FIN none
expect_flags "NULL scan dropped" "$PORT" NULL none
expect_flags "ACK scan same as an unused port" "$PORT" ACK "$ACK_UNUSED"

echo "--- sending knock $SEQ ---"
python3 "$DRIVER" knock "$CLIENT" "$SERVER" 0.05 "$SEQ" "$PORT"
sleep 0.5

echo "--- probe AFTER knock (expect open) ---"
if probe; then check "post-knock open" 1 1; else check "post-knock open" 1 0; fi

if [ "$MODE" = "close_on_connect" ]; then
  # The probe above reached the listener (port was open); the daemon has now
  # closed it. A second probe must fail.
  echo "--- second probe after connect (expect closed) ---"
  sleep 0.3
  if probe; then check "post-connect closed" 0 1; else check "post-connect closed" 0 0; fi

  # Closing the port must only stop NEW connections: a session opened by the
  # knock keeps exchanging data after the port closes behind it.
  echo "--- knock again, hold a session open past the close (expect it to survive) ---"
  python3 "$DRIVER" knock "$CLIENT" "$SERVER" 0.05 "$SEQ" "$PORT"
  sleep 0.5
  python3 "$DRIVER" hold "$SERVER" "$PORT" 3 >"$WORK/hold.log" 2>&1 &
  HOLD=$!
  sleep 1
  if probe; then check "new connection refused while session open" 0 1; else check "new connection refused while session open" 0 0; fi
  if wait $HOLD; then check "session survives close_on_connect" 1 1; else check "session survives close_on_connect" 1 0; cat "$WORK/hold.log"; fi

  # fallback_ttl must be enforced by the kernel, not by the daemon noticing a
  # later packet: knock, then send NOTHING to the server until it has passed.
  echo "--- knock, stay silent for fallback_ttl=${FALLBACK}s (expect closed) ---"
  python3 "$DRIVER" knock "$CLIENT" "$SERVER" 0.05 "$SEQ" "$PORT"
  sleep $((FALLBACK+1))
  if probe; then check "fallback_ttl closes on a quiet interface" 0 1; else check "fallback_ttl closes on a quiet interface" 0 0; fi

  # ...and must still hold if the daemon dies right after arming the port.
  echo "--- knock, SIGKILL the daemon, wait fallback_ttl (expect closed) ---"
  python3 "$DRIVER" knock "$CLIENT" "$SERVER" 0.05 "$SEQ" "$PORT"
  sleep 0.5
  sudo pkill -9 -f "$BIN"
  sleep $((FALLBACK+1))
  if probe; then check "fallback_ttl closes after daemon SIGKILL" 0 1; else check "fallback_ttl closes after daemon SIGKILL" 0 0; fi
  start_daemon || { echo "FAIL daemon did not restart"; fail=$((fail+1)); }

  # More armed clients than the old fixed 64-slot table: every one of them must
  # be able to connect, and every element must expire at fallback_ttl.
  echo "--- 70 clients knock at once ---"
  MANY=70
  for i in $(seq 1 $MANY); do sudo ip addr add 10.20.0.$((99+i))/24 dev e2e-c 2>/dev/null; done
  # Each client knocks in order; the clients run concurrently so all of them
  # are armed well inside fallback_ttl.
  KPIDS=()
  for i in $(seq 1 $MANY); do python3 "$DRIVER" knock "10.20.0.$((99+i))" "$SERVER" 0.05 "$SEQ" "$PORT" & KPIDS+=($!); done
  wait "${KPIDS[@]}"
  sleep 1
  allowed() { sudo ip netns exec "$NS" nft list set inet "sourceknock_$SERVICE" allowed_v4 | grep -oE '10\.20\.0\.1[0-9][0-9]' | sort -u | wc -l | tr -d ' '; }
  n="$(allowed)"; if [ "$n" = "$MANY" ]; then check "all $MANY clients armed ($n)" 1 1; else check "all $MANY clients armed ($n)" 1 0; fi
  LAST=10.20.0.$((99+MANY))
  if python3 "$DRIVER" probe "$SERVER" "$PORT" 1.0 "$LAST"; then check "client #$MANY can connect" 1 1; else check "client #$MANY can connect" 1 0; fi
  sleep $((FALLBACK+1))
  n="$(allowed)"; if [ "$n" = "0" ]; then check "every armed element expired ($n left)" 1 1; else check "every armed element expired ($n left)" 1 0; fi
  for i in $(seq 1 $MANY); do sudo ip addr del 10.20.0.$((99+i))/24 dev e2e-c 2>/dev/null; done
else
  # Open a session right after the knock and keep it busy past the TTL: the
  # element expiring must only stop NEW connections.
  python3 "$DRIVER" hold "$SERVER" "$PORT" $((DURATION+2)) >"$WORK/hold.log" 2>&1 &
  HOLD=$!
  echo "--- waiting ${DURATION}s for nft TTL ---"
  sleep $((DURATION+1))
  echo "--- probe AFTER ttl (expect closed) ---"
  if probe; then check "post-ttl closed" 0 1; else check "post-ttl closed" 0 0; fi
  if wait $HOLD; then check "session survives ttl expiry" 1 1; else check "session survives ttl expiry" 1 0; cat "$WORK/hold.log"; fi

  # Deterministic version: a repeat of an earlier step lands after a later
  # one (A, B, A, C). It must be ignored, not reset the knock.
  echo "--- knock with a late repeat of an earlier step ---"
  sleep $((DURATION+1)) # let the previous element expire
  IFS=, read -ra SP3 <<<"$SEQ"
  python3 "$DRIVER" knock "$CLIENT" "$SERVER" 0.05 "${SP3[0]},${SP3[1]},${SP3[0]},${SP3[2]}" "$PORT"
  sleep 0.3
  if probe; then check "late repeat of an earlier step is ignored" 1 1; else check "late repeat of an earlier step is ignored" 1 0; fi

  # Knock with TCP connects whose SYNs are dropped (the port is closed), so
  # the kernel retransmits each SYN ~1s later, after the knock has moved on.
  # A retransmitted step must not reset progress.
  echo "--- knock with retransmitting TCP connects ---"
  sleep $((DURATION+1)) # let the previous element expire
  if probe; then check "closed before tcp knock" 0 1; else check "closed before tcp knock" 0 0; fi
  python3 "$DRIVER" knock-tcp "$CLIENT" "$SERVER" 1.3 "$SEQ" "$PORT"
  sleep 0.3
  if probe; then check "tcp connect knock opens despite SYN retransmits" 1 1; else check "tcp connect knock opens despite SYN retransmits" 1 0; grep -E "reset|knock" "$LOG" | tail -5; fi

  # A re-knock while the port is still open must restart the TTL, not leave
  # the original expiry in place.
  echo "--- knock, re-knock near expiry (expect the TTL to restart) ---"
  python3 "$DRIVER" knock "$CLIENT" "$SERVER" 0.05 "$SEQ" "$PORT"
  sleep $((DURATION-1))
  python3 "$DRIVER" knock "$CLIENT" "$SERVER" 0.05 "$SEQ" "$PORT"
  sleep 2
  if probe; then check "re-knock restarts the ttl" 1 1; else check "re-knock restarts the ttl" 1 0; fi
fi

# The server's OWN frames never count: sending from the knock source ports
# (outgoing, src = the server) must not open the port for the server.
echo "--- server sends from the knock ports (expect no knock) ---"
IFS=, read -ra SEQ_PORTS <<<"$SEQ"
for p in "${SEQ_PORTS[@]}"; do
  sudo ip netns exec "$NS" python3 -c "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('$SERVER',$p)); s.sendto(b'x',('$CLIENT',9))"
  sleep 0.05
done
sleep 0.5
if sudo ip netns exec "$NS" nft list set inet "sourceknock_$SERVICE" allowed_v4 | grep -q "$SERVER"; then
  check "server's own outgoing frames are not a knock" 1 0
else
  check "server's own outgoing frames are not a knock" 1 1
fi

# Loopback delivers every frame twice to AF_PACKET (once outgoing, once
# incoming). A knock over lo must be seen exactly once.
echo "--- knock over loopback (each frame counted once) ---"
LO_PORT=$((PORT+7))
printf '[global]\ninterface = lo\n[trigger:loe2e]\nport = %s\nsequence = %s\nwindow = 5\nmode = fixed_ttl\nduration = 30\n' "$LO_PORT" "$SEQ" > "$WORK/lo.conf"
sudo ip netns exec "$NS" setsid "$BIN" "$WORK/lo.conf" >"$WORK/lo.log" 2>&1 </dev/null &
LO_PID=$!
for _ in $(seq 1 50); do grep -q "listening for knocks" "$WORK/lo.log" && break; sleep 0.1; done
sudo ip netns exec "$NS" python3 "$DRIVER" knock 127.0.0.1 127.0.0.1 0.05 "$SEQ" "$LO_PORT"
sleep 0.5
oks="$(grep -c "knock OK" "$WORK/lo.log")"; resets="$(grep -c "progress reset" "$WORK/lo.log")"
if [ "$oks" = "1" ] && [ "$resets" = "0" ]; then check "loopback knock counted once (ok=$oks reset=$resets)" 1 1; else check "loopback knock counted once (ok=$oks reset=$resets)" 1 0; cat "$WORK/lo.log"; fi
if sudo ip netns exec "$NS" nft list set inet sourceknock_loe2e allowed_v4 | grep -q 127.0.0.1; then check "loopback knock opens" 1 1; else check "loopback knock opens" 1 0; fi
sudo kill -TERM "$LO_PID" 2>/dev/null; sudo pkill -TERM -f "$WORK/lo.conf"; wait "$LO_PID" 2>/dev/null

# Raw-IP links (no Ethernet header): an ipip tunnel over the veth. Frames on
# it start at the IP header; parsing them as Ethernet never matched a knock.
echo "--- knock over an ipip tunnel (raw IP link) ---"
sudo ip link add sktun0 type ipip local "$CLIENT" remote "$SERVER"
sudo ip addr add 10.30.0.1/30 dev sktun0
sudo ip link set sktun0 up
sudo ip netns exec "$NS" ip link add sktun0 type ipip local "$SERVER" remote "$CLIENT"
sudo ip netns exec "$NS" ip addr add 10.30.0.2/30 dev sktun0
sudo ip netns exec "$NS" ip link set sktun0 up
TUN_PORT=$((PORT+9))
printf '[global]\ninterface = sktun0\n[trigger:tune2e]\nport = %s\nsequence = %s\nwindow = 5\nmode = fixed_ttl\nduration = 30\n' "$TUN_PORT" "$SEQ" > "$WORK/tun.conf"
sudo ip netns exec "$NS" setsid "$BIN" "$WORK/tun.conf" >"$WORK/tun.log" 2>&1 </dev/null &
TUN_PID=$!
for _ in $(seq 1 50); do grep -q "listening for knocks" "$WORK/tun.log" && break; sleep 0.1; done
grep -q "link ipip tunnel" "$WORK/tun.log" && check "tunnel link type detected" 1 1 || { check "tunnel link type detected" 1 0; cat "$WORK/tun.log"; }
python3 "$DRIVER" knock 10.30.0.1 10.30.0.2 0.05 "$SEQ" "$TUN_PORT"
sleep 0.5
if sudo ip netns exec "$NS" nft list set inet sourceknock_tune2e allowed_v4 2>/dev/null | grep -q 10.30.0.1; then
  check "knock over ipip tunnel opens" 1 1
else
  check "knock over ipip tunnel opens" 1 0; cat "$WORK/tun.log"
fi
sudo kill -TERM "$TUN_PID" 2>/dev/null; sudo pkill -TERM -f "$WORK/tun.conf"; wait "$TUN_PID" 2>/dev/null

# A link type we can't parse is refused at startup (multipoint GRE puts its
# outer header in front of each frame), not run and silently never matched.
echo "--- unsupported link type (gre) is refused ---"
sudo ip netns exec "$NS" ip link add skgre0 type gre local "$SERVER"
sudo ip netns exec "$NS" ip link set skgre0 up
sed 's/^interface = .*/interface = skgre0/' "$CONF" > "$WORK/gre.conf"
sed -i 's/^\[trigger:.*\]/[trigger:gree2e]/; s/^service = .*/service = gree2e/' "$WORK/gre.conf"
sudo ip netns exec "$NS" timeout 10 "$BIN" "$WORK/gre.conf" >"$WORK/gre.log" 2>&1 </dev/null; rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ] && grep -q "can't read knocks from" "$WORK/gre.log"; then
  check "gre link refused with a reason (exit $rc)" 1 1
else
  check "gre link refused with a reason (exit $rc)" 1 0; cat "$WORK/gre.log"
fi
sudo ip netns exec "$NS" ip link del skgre0

# Log timestamps are wall-clock time (not time since boot).
echo "--- log timestamps ---"
first_ts="$(grep -oE '^\[[0-9]{2}:[0-9]{2}:[0-9]{2}\]' "$LOG" | head -1 | tr -d '[]')"
to_secs() { IFS=: read -r h m s <<<"$1"; echo $((10#$h*3600 + 10#$m*60 + 10#$s)); }
if [ -n "$first_ts" ]; then
  d=$(( ( $(to_secs "$(date +%H:%M:%S)") - $(to_secs "$first_ts") + 86400 ) % 86400 ))
  if [ "$d" -le 300 ]; then check "log time is wall clock ($first_ts)" 1 1; else check "log time is wall clock ($first_ts, ${d}s off)" 1 0; fi
else
  check "log has timestamps" 1 0
fi

# SIGTERM on an idle interface: the daemon must exit promptly and cleanly
# (exit 0) and flush its allowed sets on the way out.
echo "--- SIGTERM on an idle interface ---"
python3 "$DRIVER" knock "$CLIENT" "$SERVER" 0.05 "$SEQ" "$PORT"
sleep 2 # nothing else reaches the capture interface after this
t0=$(date +%s%N)
sudo pkill -TERM -x sourceknock
wait "$DAEMON_PID"; rc=$?
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
if [ "$rc" -eq 0 ]; then check "SIGTERM exits 0" 1 1; else check "SIGTERM exits 0 (got $rc)" 1 0; fi
if [ "$ms" -le 1500 ]; then check "SIGTERM exits within 1.5s (${ms}ms)" 1 1; else check "SIGTERM exits within 1.5s (${ms}ms)" 1 0; fi
grep -q "sourceknock stopped" "$LOG" && check "clean shutdown logged" 1 1 || check "clean shutdown logged" 1 0
left="$(sudo ip netns exec "$NS" nft list set inet "sourceknock_$SERVICE" allowed_v4 2>/dev/null | grep -c "$CLIENT")"
if [ "$left" = "0" ]; then check "allowed set flushed on shutdown" 1 1; else check "allowed set flushed on shutdown" 1 0; fi

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
