#!/usr/bin/env bash
# End-to-end test of a real Linux guest: boots it under libvirt/KVM in each
# network mode and checks, from inside the guest, what the firewall allows.
#
# Needs a Linux host with: root, KVM, libvirt (virtqemud, virtnetworkd, dnsmasq),
# qemu, nftables, xorriso, go, ssh, and a cloud-init-capable qcow2 base image
# (default: the Arch cloud image). Run:  sudo scripts/integration-linux-guest.sh
#
# Deliberately not `set -e`: every check runs and is tallied, because the point
# is to see exactly which boundaries held.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${LIMBO_IT_DIR:-/var/lib/limbo/it}"
BASE="${LIMBO_IT_IMAGE:-/var/lib/limbo/images/arch-cloudimg.qcow2}"
export LIMBO_STATE_DIR="$WORK/state"
GUEST=itest
PASS=0
FAIL=0

mkdir -p "$WORK" "$LIMBO_STATE_DIR"
cd "$REPO" && go build -o "$WORK/limbo" ./cmd/limbo || { echo "build failed"; exit 2; }
LIMBO="$WORK/limbo"

[ -f "$WORK/key" ] || ssh-keygen -q -t ed25519 -N '' -f "$WORK/key"
SHA=$(sha256sum "$BASE" | cut -d' ' -f1)

ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
expect() { # expect <pass|fail> <description> <command...>: command must succeed / must not succeed
  want=$1; desc=$2; shift 2
  if "$@" >/dev/null 2>&1; then got=pass; else got=fail; fi
  if [ "$got" = "$want" ]; then ok "$desc"; else bad "$desc (wanted $want, got $got)"; fi
}

manifest() { # manifest <network-json-fragment>
  cat >"$WORK/$GUEST.json" <<EOF
{
  "name": "$GUEST", "os": "linux",
  "image": {"path": "$BASE", "sha256": "$SHA"},
  "cpus": 2, "memory_mb": 2048,
  $1
  "disposable": true,
  "console_log": "$WORK/$GUEST.console",
  "access": {"user": "analyst"},
  "app": {"name": "Shell", "exec": "true"},
  "provision": {"ssh_public_key": "$(cat "$WORK/key.pub")", "seed_iso": "$WORK/seed.iso"}
}
EOF
}

gssh() { ssh -i "$WORK/key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=5 -o LogLevel=ERROR "analyst@$GIP" "$@"; }

# tcp <ip> <port> from inside the guest, 4s timeout
gtcp() { gssh "timeout 4 bash -c '</dev/tcp/$1/$2'"; }

run_mode() { # run_mode <name> <network-json-fragment>
  mode=$1
  echo "== mode: $mode"
  manifest "$2"
  "$LIMBO" seed --iso "$WORK/seed.iso" "$WORK/$GUEST.json" "$WORK/seed" >/dev/null || { bad "seed"; return; }
  GIP=$("$LIMBO" plan "$WORK/$GUEST.json" | grep -o 'analyst@[0-9.]*' | head -1 | cut -d@ -f2)
  GW="${GIP%.*}.1"

  : >"$WORK/$GUEST.console"
  if "$LIMBO" up "$WORK/$GUEST.json"; then ok "limbo up"; else bad "limbo up"; "$LIMBO" down "$WORK/$GUEST.json" >/dev/null 2>&1; return; fi

  up=no
  t0=$SECONDS
  for _ in $(seq 1 "${LIMBO_IT_BOOT_WAIT:-100}"); do
    if gssh true 2>/dev/null; then up=yes; break; fi
    sleep 3
  done
  if [ "$up" = yes ]; then ok "guest booted and ssh works at $GIP (after $((SECONDS-t0))s)"; else
    bad "guest never became reachable at $GIP"
    echo "--- diagnostics (console tail)"
    tail -40 "$WORK/$GUEST.console" 2>&1
    virsh -c qemu:///system net-dhcp-leases "limbo-$GUEST" 2>&1 | grep -v setlocale
    ip -br addr show "lb-$GUEST" 2>&1
    ip neigh show dev "lb-$GUEST" 2>&1
    ping -c1 -W2 "$GIP" 2>&1 | tail -2
    nft list table inet "limbo_$GUEST" 2>&1 | head -30
    ssh -i "$WORK/key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 "analyst@$GIP" true 2>&1 | tail -3
    "$LIMBO" down "$WORK/$GUEST.json" >/dev/null 2>&1; return
  fi

  case "$mode" in
  none)
    expect fail "guest cannot reach the internet (1.1.1.1:443)" gtcp 1.1.1.1 443
    expect fail "guest cannot reach a host service on the gateway ($GW:8000)" gtcp "$GW" 8000
    expect fail "guest cannot resolve names" gssh "getent hosts example.com"
    ;;
  internet-only)
    expect pass "guest can reach the internet (1.1.1.1:443)" gtcp 1.1.1.1 443
    expect pass "guest can resolve names via the gateway" gssh "getent hosts example.com"
    expect fail "guest cannot reach a host service on the gateway ($GW:8000)" gtcp "$GW" 8000
    HOSTIP=$(ip -4 route get 1.1.1.1 | grep -o 'src [0-9.]*' | cut -d' ' -f2)
    expect fail "guest cannot reach the host's LAN address ($HOSTIP:8000)" gtcp "$HOSTIP" 8000
    expect fail "guest cannot reach RFC1918 space (192.168.1.1:80)" gtcp 192.168.1.1 80
    ;;
  allowlist)
    expect pass "guest can reach the allowed destination (1.1.1.1:443)" gtcp 1.1.1.1 443
    expect fail "guest cannot reach other internet hosts (9.9.9.9:443)" gtcp 9.9.9.9 443
    expect fail "guest cannot reach a host service on the gateway ($GW:8000)" gtcp "$GW" 8000
    expect fail "guest gets no DNS in allowlist mode" gssh "getent hosts example.com"
    ;;
  esac

  expect pass "host can still reach the guest (ssh) while filtered" gssh true
  "$LIMBO" down "$WORK/$GUEST.json" && ok "limbo down" || bad "limbo down"
  expect fail "libvirt domain removed" virsh -c qemu:///system dominfo "limbo-$GUEST"
  expect fail "libvirt network removed" virsh -c qemu:///system net-info "limbo-$GUEST"
  expect fail "nftables table removed" nft list table inet "limbo_$GUEST"
}

# A host service the guest must never be able to reach in any mode.
python3 -m http.server 8000 --bind 0.0.0.0 >/dev/null 2>&1 &
HTTP=$!
trap 'kill $HTTP 2>/dev/null; "$LIMBO" down "$WORK/$GUEST.json" >/dev/null 2>&1' EXIT
sleep 1

want() { [ -z "${LIMBO_IT_MODES:-}" ] || [[ " $LIMBO_IT_MODES " == *" $1 "* ]]; }
want none && run_mode none ''
want internet-only && run_mode internet-only '"network": {"mode": "internet-only"},'
want allowlist && run_mode allowlist '"network": {"mode": "allowlist", "allow": [{"addr": "1.1.1.1", "port": 443}]},'


# Two guests at once: one must not be able to reach the other, even though both
# have internet access, and the host must still reach each.
run_isolation() {
  echo "== isolation between two guests"
  GUEST=isoa; manifest '"network": {"mode": "internet-only"},'
  A_IP=$("$LIMBO" plan "$WORK/isoa.json" | grep -o 'analyst@[0-9.]*' | head -1 | cut -d@ -f2)
  GUEST=isob; manifest '"network": {"mode": "internet-only"},'
  B_IP=$("$LIMBO" plan "$WORK/isob.json" | grep -o 'analyst@[0-9.]*' | head -1 | cut -d@ -f2)
  [ "$A_IP" != "$B_IP" ] && ok "guests have distinct subnets ($A_IP, $B_IP)" || { bad "subnet collision"; return; }
  "$LIMBO" seed --iso "$WORK/seed.iso" "$WORK/isoa.json" "$WORK/seed" >/dev/null
  "$LIMBO" up "$WORK/isoa.json" && "$LIMBO" up "$WORK/isob.json" && ok "both guests up" || { bad "bring-up"; GUEST=isoa "$LIMBO" down "$WORK/isoa.json" >/dev/null 2>&1; "$LIMBO" down "$WORK/isob.json" >/dev/null 2>&1; return; }
  for ip in "$A_IP" "$B_IP"; do
    GIP=$ip; up=no
    for _ in $(seq 1 "${LIMBO_IT_BOOT_WAIT:-100}"); do gssh true 2>/dev/null && { up=yes; break; }; sleep 3; done
    [ "$up" = yes ] && ok "guest at $ip reachable from host" || bad "guest at $ip never reachable"
  done
  GIP=$A_IP
  expect fail "guest A cannot reach guest B ($B_IP:22)" gtcp "$B_IP" 22
  expect fail "guest A cannot reach guest B's gateway ($(echo "$B_IP" | sed 's/\.2$/.1/'):22)" gtcp "$(echo "$B_IP" | sed 's/\.2$/.1/')" 22
  GIP=$B_IP
  expect fail "guest B cannot reach guest A ($A_IP:22)" gtcp "$A_IP" 22
  expect pass "guest B still has internet" gtcp 1.1.1.1 443
  "$LIMBO" down "$WORK/isoa.json" >/dev/null 2>&1 && "$LIMBO" down "$WORK/isob.json" >/dev/null 2>&1 && ok "both guests down" || bad "teardown"
}
want isolation && run_isolation

echo "== audit log"
n=$(wc -l <"$LIMBO_STATE_DIR/events.jsonl")
[ "$n" -gt 0 ] && ok "events.jsonl has $n events" || bad "no events written"

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
