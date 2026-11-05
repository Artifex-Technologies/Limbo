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
  : >"$WORK/$GUEST.console"
  if "$LIMBO" up --i-know "$WORK/$GUEST.json"; then ok "limbo up"; else bad "limbo up"; "$LIMBO" down --i-know "$WORK/$GUEST.json" >/dev/null 2>&1; return; fi
  # The subnet is given at up and recorded (it used to come from a hash of the name).
  GIP=$("$LIMBO" address "$WORK/$GUEST.json")
  GW="${GIP%.*}.1"

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
    "$LIMBO" down --i-know "$WORK/$GUEST.json" >/dev/null 2>&1; return
  fi

  case "$mode" in
  none)
    expect fail "guest cannot reach the internet (1.1.1.1:443)" gtcp 1.1.1.1 443
    expect fail "guest cannot reach a host service on the gateway ($GW:8000)" gtcp "$GW" 8000
    expect fail "guest cannot resolve names" gssh "getent hosts example.com"
    ;;
  internet-only)
    # Guest network events (package flows): read the kernel's log group while the guest is probed below.
    "$LIMBO" net watch --seconds 45 >"$WORK/net.jsonl" 2>"$WORK/net.err" &
    NETW=$!
    sleep 1
    expect pass "guest can reach the internet (1.1.1.1:443)" gtcp 1.1.1.1 443
    expect pass "guest can resolve names via the gateway" gssh "getent hosts example.com"
    expect fail "guest cannot reach a host service on the gateway ($GW:8000)" gtcp "$GW" 8000
    HOSTIP=$(ip -4 route get 1.1.1.1 | grep -o 'src [0-9.]*' | cut -d' ' -f2)
    expect fail "guest cannot reach the host's LAN address ($HOSTIP:8000)" gtcp "$HOSTIP" 8000
    expect fail "guest cannot reach RFC1918 space (192.168.1.1:80)" gtcp 192.168.1.1 80
    gssh "for p in \$(seq 3000 3025); do timeout 1 bash -c \"</dev/tcp/10.255.255.1/\$p\" 2>/dev/null; done; true"
    sleep 3; kill "$NETW" 2>/dev/null; wait "$NETW" 2>/dev/null
    expect pass "net.flow: the allowed connection to 1.1.1.1:443 was reported" sh -c "grep '\"kind\":\"net.flow\"' '$WORK/net.jsonl' | grep '\"dst\":\"1.1.1.1\"' | grep -q '\"dport\":\"443\"'"
    expect pass "net.anomaly host_probe: the host service attempt was reported" grep -q '"reason":"host_probe"' "$WORK/net.jsonl"
    expect pass "net.anomaly lan_probe: the private-range attempt was reported" grep -q '"reason":"lan_probe"' "$WORK/net.jsonl"
    expect pass "net.anomaly scan: many refused destinations were reported" grep -q '"reason":"scan"' "$WORK/net.jsonl"
    expect fail "net watch ran without errors" grep -q . "$WORK/net.err"
    ;;
  allowlist)
    expect pass "guest can reach the allowed destination (1.1.1.1:443)" gtcp 1.1.1.1 443
    expect fail "guest cannot reach other internet hosts (9.9.9.9:443)" gtcp 9.9.9.9 443
    expect fail "guest cannot reach a host service on the gateway ($GW:8000)" gtcp "$GW" 8000
    expect fail "guest gets no DNS in allowlist mode" gssh "getent hosts example.com"
    ;;
  esac

  # IPv6: the guest's network gives it none, and the firewall drops what the guest makes itself.
  expect fail "guest has no IPv6 way out (2606:4700:4700::1111:443)" gssh "timeout 4 bash -c '</dev/tcp/2606:4700:4700::1111/443'"
  expect fail "nothing on the guest's link answers IPv6 (no neighbour after an all-nodes ping)" \
    gssh "ping -6 -c2 -W2 ff02::1%eth0 >/dev/null 2>&1; ip -6 neigh | grep -q ."
  if [ "$mode" = internet-only ]; then
    expect pass "the loaded firewall drops guest IPv6 before its accept" sh -c "nft list table inet limbo_$GUEST | grep -q 'meta nfproto ipv6 goto blocked'"
  fi
  # The guest presents exactly the host key limbo seed made (what limbo launch pins).
  expect pass "guest's host key is the one made at seed" sh -c \
    "ssh-keyscan -T 5 -t ed25519 $GIP 2>/dev/null | awk '{print \$2\" \"\$3}' | grep -qxF \"\$(cut -d' ' -f1,2 $WORK/seed/ssh_host_ed25519_key.pub)\""

  expect pass "host can still reach the guest (ssh) while filtered" gssh true
  "$LIMBO" down --i-know "$WORK/$GUEST.json" && ok "limbo down" || bad "limbo down"
  expect fail "libvirt domain removed" virsh -c qemu:///system dominfo "limbo-$GUEST"
  expect fail "libvirt network removed" virsh -c qemu:///system net-info "limbo-$GUEST"
  expect fail "nftables table removed" nft list table inet "limbo_$GUEST"
}

# A host service the guest must never be able to reach in any mode.
python3 -m http.server 8000 --bind 0.0.0.0 >/dev/null 2>&1 &
HTTP=$!
trap 'kill $HTTP 2>/dev/null; "$LIMBO" down --i-know "$WORK/$GUEST.json" >/dev/null 2>&1' EXIT
sleep 1

want() { [ -z "${LIMBO_IT_MODES:-}" ] || [[ " $LIMBO_IT_MODES " == *" $1 "* ]]; }
want none && run_mode none ''
want internet-only && run_mode internet-only '"network": {"mode": "internet-only"},'
want allowlist && run_mode allowlist '"network": {"mode": "allowlist", "allow": [{"addr": "1.1.1.1", "port": 443}]},'


# A persistent guest boots from its own overlay, keeps what it wrote across down/up, and never changes the base image.
run_persistent() {
  echo "== persistent guest on its own overlay"
  GUEST=itpers; manifest ''
  sed -i 's/"disposable": true/"disposable": false/' "$WORK/$GUEST.json"
  BASESUM=$(sha256sum "$BASE" | cut -d' ' -f1)
  "$LIMBO" up --i-know "$WORK/$GUEST.json" && ok "persistent guest up" || { bad "persistent up"; "$LIMBO" down --i-know "$WORK/$GUEST.json" >/dev/null 2>&1; return; }
  DISK="$LIMBO_STATE_DIR/$GUEST.disk.qcow2"
  qemu-img info -U "$DISK" 2>/dev/null | grep -q "backing file: $BASE" && ok "it boots from its own overlay backed by the base image" || bad "no overlay at $DISK"
  GIP=$("$LIMBO" address "$WORK/$GUEST.json"); up=no
  for _ in $(seq 1 "${LIMBO_IT_BOOT_WAIT:-100}"); do gssh true 2>/dev/null && { up=yes; break; }; sleep 3; done
  [ "$up" = yes ] && ok "persistent guest reachable at $GIP" || { bad "persistent guest never reachable"; "$LIMBO" down --i-know "$WORK/$GUEST.json" >/dev/null 2>&1; return; }
  gssh "echo kept > ~/marker && sync" && ok "guest wrote a file" || bad "guest could not write"
  # limbo launch --check: every launch check but the window, against the key limbo seed made and pinned.
  PIN=$(cut -d' ' -f1,2 "$WORK/seed/ssh_host_ed25519_key.pub")
  python3 - "$WORK/$GUEST.json" "$PIN" "$WORK/launch-good.json" "$WORK/launch-bad.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
m["clipboard"] = "text"
m["provision"]["host_key"] = sys.argv[2]
json.dump(m, open(sys.argv[3], "w"))
m["provision"]["host_key"] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
json.dump(m, open(sys.argv[4], "w"))
PY
  "$LIMBO" launch --i-know --check --identity "$WORK/key" "$WORK/launch-good.json" >"$WORK/launch-good.out" 2>&1
  expect pass "launch --check: ssh reaches the guest with the pinned key" grep -q "^ok    ssh reaches the guest" "$WORK/launch-good.out"
  "$LIMBO" launch --i-know --check --identity "$WORK/key" "$WORK/launch-bad.json" >"$WORK/launch-bad.out" 2>&1
  expect pass "launch --check: a different pinned key is refused" grep -q "^FAIL  ssh with the pinned key failed" "$WORK/launch-bad.out"
  "$LIMBO" down --i-know "$WORK/$GUEST.json" && ok "persistent guest down" || bad "persistent down"
  [ -f "$DISK" ] && ok "its overlay survives down" || bad "overlay deleted at down"
  [ "$(sha256sum "$BASE" | cut -d' ' -f1)" = "$BASESUM" ] && ok "base image unchanged" || bad "base image changed"
  "$LIMBO" up --i-know "$WORK/$GUEST.json" >/dev/null && GIP=$("$LIMBO" address "$WORK/$GUEST.json") && up=no
  for _ in $(seq 1 "${LIMBO_IT_BOOT_WAIT:-100}"); do gssh true 2>/dev/null && { up=yes; break; }; sleep 3; done
  expect pass "what it wrote is still there after down and up" gssh "grep -qx kept ~/marker"
  "$LIMBO" down --i-know "$WORK/$GUEST.json" >/dev/null 2>&1
  rm -f "$DISK"
  GUEST=itest
}
want persistent && run_persistent

# Two guests at once: one must not be able to reach the other, even though both
# have internet access, and the host must still reach each.
run_isolation() {
  echo "== isolation between two guests"
  GUEST=isoa; manifest '"network": {"mode": "internet-only"},'
  GUEST=isob; manifest '"network": {"mode": "internet-only"},'
  "$LIMBO" seed --iso "$WORK/seed.iso" "$WORK/isoa.json" "$WORK/seed" >/dev/null
  "$LIMBO" up --i-know "$WORK/isoa.json" && "$LIMBO" up --i-know "$WORK/isob.json" && ok "both guests up" || { bad "bring-up"; GUEST=isoa "$LIMBO" down --i-know "$WORK/isoa.json" >/dev/null 2>&1; "$LIMBO" down --i-know "$WORK/isob.json" >/dev/null 2>&1; return; }
  A_IP=$("$LIMBO" address "$WORK/isoa.json")
  B_IP=$("$LIMBO" address "$WORK/isob.json")
  [ -n "$A_IP" ] && [ "${A_IP%.*}" != "${B_IP%.*}" ] && ok "guests have distinct subnets ($A_IP, $B_IP)" || bad "subnet collision ($A_IP, $B_IP)"
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
  "$LIMBO" down --i-know "$WORK/isoa.json" >/dev/null 2>&1 && "$LIMBO" down --i-know "$WORK/isob.json" >/dev/null 2>&1 && ok "both guests down" || bad "teardown"
}
want isolation && run_isolation

echo "== audit log"
n=$(wc -l <"$LIMBO_STATE_DIR/events.jsonl")
[ "$n" -gt 0 ] && ok "events.jsonl has $n events" || bad "no events written"

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
