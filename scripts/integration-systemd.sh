#!/usr/bin/env bash
# Runs Limbo and Heimdall under their REAL systemd units, with their hardening, as
# the packages would install them. Sandboxing options (ProtectSystem, ProtectHome,
# PrivateTmp ...) routinely break a service in ways unit tests cannot see.
#
# It installs files into /usr/bin, /usr/lib/systemd/system, /usr/lib/sysusers.d and
# /etc/limbo, /etc/chymaera-sentry, and removes them again on exit. Use a test
# machine. Needs systemd, libvirt, the Arch cloud image, and the Heimdall repo.
#   sudo scripts/integration-systemd.sh
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SENTRY_REPO="${SENTRY_REPO:-$(cd "$REPO/.." && pwd)/Heimdall}"
BASE="${LIMBO_IT_IMAGE:-/var/lib/limbo/images/arch-cloudimg.qcow2}"
WORK=/var/lib/limbo-itsd-scratch
PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
waitfor() { n=$1; shift; for _ in $(seq 1 "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
jget() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval('d'+sys.argv[1]))" "$1"; }

STATE=/var/lib/limbo/state
[ -d "$STATE" ] && { echo "refusing: $STATE already exists (a real Limbo state?)"; exit 2; }
mkdir -p "$WORK"

cleanup() {
  systemctl stop chymaera-sentry.service limbo.service 2>/dev/null
  rm -f /usr/bin/limbo /usr/bin/sentryd \
        /usr/lib/systemd/system/limbo.service /usr/lib/systemd/system/chymaera-sentry.service \
        /usr/lib/sysusers.d/limbo.conf /usr/lib/sysusers.d/chymaera-sentry.conf
  rm -rf /etc/systemd/system/chymaera-sentry.service.d /etc/limbo /etc/chymaera-sentry "$STATE" /var/lib/chymaera-sentry "$WORK"
  systemctl daemon-reload
  userdel chymaera-sentry 2>/dev/null
}
trap cleanup EXIT

echo "== install exactly what the packages install"
( cd "$REPO" && go build -o /usr/bin/limbo ./cmd/limbo ) || { echo "limbo build failed"; exit 2; }
( cd "$SENTRY_REPO" && go build -o /usr/bin/sentryd ./cmd/sentryd ) || { echo "sentryd build failed"; exit 2; }
install -Dm644 "$REPO/packaging/arch/limbo.service" /usr/lib/systemd/system/limbo.service
install -Dm644 "$REPO/packaging/arch/limbo.sysusers" /usr/lib/sysusers.d/limbo.conf
install -Dm644 "$SENTRY_REPO/packaging/arch/chymaera-sentry.service" /usr/lib/systemd/system/chymaera-sentry.service
install -Dm644 "$SENTRY_REPO/packaging/arch/chymaera-sentry.sysusers" /usr/lib/sysusers.d/chymaera-sentry.conf
install -Dm644 "$SENTRY_REPO/packaging/arch/limbo-integration.conf.example" /etc/systemd/system/chymaera-sentry.service.d/limbo.conf
install -dm755 /etc/limbo/validation; install -dm700 /etc/limbo/keys
systemd-sysusers /usr/lib/sysusers.d/limbo.conf /usr/lib/sysusers.d/chymaera-sentry.conf 2>&1 | grep -v setlocale
systemctl daemon-reload
id -nG chymaera-sentry | grep -qw limbo-sentry && bad "the Heimdall user is already in limbo-sentry; this test would not exercise the drop-in" || ok "the Heimdall user starts WITHOUT the group (the drop-in must be what grants it)"
getent group limbo-sentry >/dev/null && getent group limbo-agent >/dev/null && ok "sysusers created the limbo-sentry and limbo-agent groups" || bad "groups missing"

echo "== limbo.service under its hardening"
systemctl start limbo.service
waitfor 20 systemctl is-active --quiet limbo.service && ok "limbo.service is active" || { bad "limbo.service failed"; journalctl -u limbo.service --no-pager | tail -15; }
waitfor 10 test -S /run/limbo/admin.sock && ok "sockets created under /run/limbo (RuntimeDirectory)" || bad "no sockets"
[ "$(stat -c '%a' /run/limbo/admin.sock)" = 600 ] && [ "$(stat -c '%a %G' /run/limbo/control.sock)" = "660 limbo-sentry" ] && [ "$(stat -c '%a %G' /run/limbo/agent.sock)" = "660 limbo-agent" ] && ok "socket modes and groups are right under the unit" || bad "socket perms: $(stat -c '%n %a %G' /run/limbo/*.sock | tr '\n' ' ')"
[ "$(stat -c '%a %G' $STATE/events.jsonl)" = "640 limbo-sentry" ] && ok "audit log is 640 limbo-sentry" || bad "log perms $(stat -c '%a %G' $STATE/events.jsonl 2>&1)"
limbo quarantine list >/dev/null 2>&1 && ok "'limbo quarantine list' works as root against the service" || bad "admin CLI failed"

echo "== a validation run through the service (qemu-img, virsh, xorriso, ssh under the sandbox)"
ssh-keygen -q -t ed25519 -N '' -f /etc/limbo/keys/validation
SHA=$(sha256sum "$BASE" | cut -d' ' -f1)
python3 - <<PY
import json
m={"name":"template","os":"linux","image":{"path":"$BASE","sha256":"$SHA"},"cpus":2,"memory_mb":2048,
   "network":{"mode":"none"},"disposable":True,"access":{"user":"analyst"},"app":{"name":"x","exec":"true"},
   "provision":{"ssh_public_key":open("/etc/limbo/keys/validation.pub").read().strip()}}
json.dump({"manifest":m,"ssh_identity":"/etc/limbo/keys/validation","max_seconds":120},open("/etc/limbo/validation/sandbox-check.json","w"))
PY
id itsd-agent >/dev/null 2>&1 || useradd -M -s /usr/bin/nologin -G limbo-agent itsd-agent
trap 'cleanup; userdel itsd-agent 2>/dev/null' EXIT
rid=$(cd / && runuser -u itsd-agent -- curl -s --unix-socket /run/limbo/agent.sock -X POST -H 'Content-Type: application/json' \
  -d '{"profile":"sandbox-check","command":"echo from-the-service; id -un","timeout_seconds":90}' http://l/v1/runs | jget "['id']")
R=""
for _ in $(seq 1 60); do
  R=$(cd / && runuser -u itsd-agent -- curl -s --unix-socket /run/limbo/agent.sock http://l/v1/runs/$rid)
  [ "$(echo "$R" | jget "['status']" 2>/dev/null)" != running ] && break; sleep 3
done
[ "$(echo "$R" | jget "['status']")" = done ] && echo "$R" | jget "['stdout']" | grep -q from-the-service && ok "a validation run completes under the unit's sandbox" || bad "run under the unit: $(echo "$R" | head -c 600)"

echo "== chymaera-sentry.service under ITS hardening, using Limbo"
install -dm755 /etc/chymaera-sentry
cat >/etc/chymaera-sentry/config.json <<EOF
{ "limbo_event_log": "$STATE/events.jsonl",
  "limbo_control_socket": "/run/limbo/control.sock",
  "limbo_state_path": "/var/lib/chymaera-sentry/limbo-offset",
  "limbo_poll_interval_seconds": 1, "api_addr": "", "net_ports": [], "telemetry_interval_seconds": 3600 }
EOF
chmod 644 /etc/chymaera-sentry/config.json
systemctl start chymaera-sentry.service
waitfor 15 systemctl is-active --quiet chymaera-sentry.service && ok "chymaera-sentry.service is active with the drop-in" || { bad "sentry service failed"; journalctl -u chymaera-sentry.service --no-pager | tail -15; }
sleep 3
journalctl -u chymaera-sentry.service --no-pager | grep -q "watching Limbo event log" && ok "Heimdall (sandboxed, unprivileged) opened Limbo's log" || bad "Heimdall did not start watching: $(journalctl -u chymaera-sentry.service --no-pager | tail -5)"
# A synthetic event for a guest Limbo never started. Heimdall should reach the control
# socket (through its sandbox) and be told no such guest exists: proof of connectivity
# and permission without touching a real guest.
printf '{"time":"%s","kind":"policy.remove","guest":"ghost","detail":{}}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$STATE/events.jsonl"
printf '{"time":"%s","kind":"guest.start","guest":"ghost","detail":{}}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$STATE/events.jsonl"
waitfor 20 sh -c "journalctl -u chymaera-sentry.service --no-pager | grep -q 'no record of a running guest'" \
  && ok "Heimdall reached control.sock from inside its sandbox (Limbo answered: no such guest)" \
  || bad "Heimdall could not reach control.sock: $(journalctl -u chymaera-sentry.service --no-pager | grep -i -E 'quarantine|limbo' | tail -4)"
[ -f /var/lib/chymaera-sentry/limbo-offset ] && ok "Heimdall persisted its read offset under its own state directory" || bad "no offset file"
# With the group Heimdall's service has, it must be able to READ the log and not WRITE it.
if systemd-run --quiet --pipe --wait -p User=chymaera-sentry -p SupplementaryGroups=limbo-sentry sh -c "echo x >> $STATE/events.jsonl" 2>/dev/null; then
  bad "a process with Heimdall's user and group could WRITE Limbo's audit log"
else
  ok "with Heimdall's user and group, Limbo's audit log is not writable"
fi
systemd-run --quiet --pipe --wait -p User=chymaera-sentry -p SupplementaryGroups=limbo-sentry head -c 1 "$STATE/events.jsonl" >/dev/null 2>&1 \
  && ok "...but it is readable" || bad "the log is not readable with the Heimdall group"

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
