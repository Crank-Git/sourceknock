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

cleanup() {
  sudo pkill -f 'sourceknock .*/sourceknock.conf' 2>/dev/null
  sudo pkill -f 'listener\.py' 2>/dev/null
  sudo ip netns del "$NS" 2>/dev/null
  sudo ip addr del $CLIENT/24 dev e2e-c 2>/dev/null
  sudo ip link del e2e-c 2>/dev/null
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

: > "$LOG"
sudo ip netns exec "$NS" setsid "$BIN" "$CONF" >"$LOG" 2>&1 </dev/null &
for _ in $(seq 1 50); do grep -q "listening for knocks" "$LOG" 2>/dev/null && break; sleep 0.1; done
grep -q "listening for knocks" "$LOG" || { echo "FAIL daemon never started"; tail -5 "$LOG"; fail=$((fail+1)); echo "RESULT: $pass passed, $fail failed"; exit 1; }

echo "mode=$MODE port=$PORT seq=$SEQ duration=$DURATION"
echo "--- probe BEFORE knock (expect closed) ---"
if probe; then check "pre-knock closed" 0 1; else check "pre-knock closed" 0 0; fi

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
else
  echo "--- waiting ${DURATION}s for nft TTL ---"
  sleep $((DURATION+1))
  echo "--- probe AFTER ttl (expect closed) ---"
  if probe; then check "post-ttl closed" 0 1; else check "post-ttl closed" 0 0; fi
fi

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
