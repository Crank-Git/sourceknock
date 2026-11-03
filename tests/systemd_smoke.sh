#!/usr/bin/env bash
# systemd smoke test for the shipped units (issue #33).
#
#   sudo tests/systemd_smoke.sh
#
# Installs the daemon + units (`make install`), creates the `sourceknock`
# user, and starts both the default unit and the template unit against a dummy
# interface. Asserts each one actually comes up as the unprivileged user with
# only CAP_NET_RAW + CAP_NET_ADMIN, logs "listening for knocks", and programs
# its nft table. Needs root and a running systemd (the GitHub ubuntu runner,
# or a container booted with systemd as PID 1). Exits non-zero on any failure.
set -u
cd "$(dirname "$0")/.."

pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }

IF=skdummy0
UNITS="sourceknock.service sourceknock@smoke.service"

cleanup() {
  systemctl stop $UNITS 2>/dev/null
  ip link del "$IF" 2>/dev/null
  nft delete table inet sourceknock_smoke_ssh 2>/dev/null
  nft delete table inet sourceknock_smoke_alt 2>/dev/null
  rm -f /etc/sourceknock/sourceknock.conf /etc/sourceknock/smoke.conf
}
trap cleanup EXIT

make daemon >/dev/null && make install >/dev/null || { echo "FAIL make install"; exit 1; }
id sourceknock >/dev/null 2>&1 || useradd --system --user-group \
  --home-dir /var/lib/sourceknock --no-create-home sourceknock

# The shipped units must verify with no diagnostics at all: systemd only
# *warns* about unknown or removed directives (e.g. "Support for option
# Capabilities= has been removed and it is ignored") and carries on.
for u in sourceknock.service sourceknock@smoke.service; do
  out="$(systemd-analyze verify "$u" 2>&1)"
  if [ -n "$out" ]; then bad "$u: systemd-analyze verify: $out"; else ok "$u verifies cleanly"; fi
done

ip link add "$IF" type dummy && ip link set "$IF" up
conf() { # service seq
  printf '[global]\ninterface = %s\n[trigger:%s]\nport = 2222\nsequence = %s\n' "$IF" "$1" "$2"
}
conf smoke_ssh 7000,8000,9000 > /etc/sourceknock/sourceknock.conf
conf smoke_alt 7100,8100,9100 > /etc/sourceknock/smoke.conf

check_unit() { # unit table
  local unit="$1" table="$2"
  systemctl reset-failed "$unit" 2>/dev/null
  systemctl start "$unit"
  for _ in $(seq 1 50); do
    journalctl -u "$unit" --no-pager -q 2>/dev/null | grep -q "listening for knocks" && break
    sleep 0.1
  done
  if journalctl -u "$unit" --no-pager -q | grep -q "listening for knocks"; then
    ok "$unit: listening for knocks"
  else
    bad "$unit: never reached 'listening for knocks'"
    journalctl -u "$unit" --no-pager -q | tail -10
  fi
  sleep 1 # would be restart-looping by now if it had crashed
  if [ "$(systemctl is-active "$unit")" = "active" ]; then ok "$unit: active"; else bad "$unit: $(systemctl is-active "$unit")"; fi

  local pid; pid="$(systemctl show -p MainPID --value "$unit")"
  if [ "$pid" -gt 0 ] 2>/dev/null; then
    local user; user="$(ps -o user= -p "$pid" | tr -d ' ')"
    [ "$user" = "sourceknock" ] && ok "$unit: runs as sourceknock" || bad "$unit: runs as '$user'"
    # CAP_NET_ADMIN is bit 12, CAP_NET_RAW bit 13: effective set == exactly those.
    local eff; eff="$(awk '/^CapEff/{print $2}' "/proc/$pid/status")"
    [ "$((16#$eff))" = "$(( (1<<12) | (1<<13) ))" ] && ok "$unit: CapEff = NET_ADMIN+NET_RAW only ($eff)" || bad "$unit: CapEff $eff"
  else
    bad "$unit: no main pid"
  fi

  if nft list chain inet "$table" service 2>/dev/null | grep -q "dport 2222 drop"; then
    ok "$unit: programmed nft table $table"
  else
    bad "$unit: nft table $table missing"
  fi

  systemctl stop "$unit"
  if journalctl -u "$unit" --no-pager -q | grep -q "sourceknock stopped"; then ok "$unit: clean stop"; else bad "$unit: no clean stop"; fi
}

check_unit sourceknock.service sourceknock_smoke_ssh
check_unit sourceknock@smoke.service sourceknock_smoke_alt

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
