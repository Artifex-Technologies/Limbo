#!/usr/bin/env bash
# Full-chain test with every real component: a real guest, a real `limbo serve`,
# the real `sentryd` run as an unprivileged user, and Sarina's real service
# (backed by a fake model that records what it was asked).
#
# The one synthetic piece is the trigger: Limbo does not itself emit
# "firewall removed under a running guest", so the test deletes the guest's
# firewall table for real and appends the matching event to the log. Everything
# after that, Heimdall's detection, the quarantine, the repair, the advisory, the
# human verdict, is the real code path.
#
#   sudo scripts/integration-chain.sh        (needs the Heimdall and Sarina repos beside this one)
#   sudo SARINA_BIN=/path/to/sarina scripts/integration-chain.sh   (Sarina's Go binary instead of the Python service)
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
GH="$(cd "$REPO/.." && pwd)"
SENTRY_REPO="${SENTRY_REPO:-$GH/Heimdall}"
SARINA_REPO="${SARINA_REPO:-$GH/Sarina}"
WORK="${LIMBO_IT_DIR:-/var/lib/limbo/itc}"
BASE="${LIMBO_IT_IMAGE:-/var/lib/limbo/images/arch-cloudimg.qcow2}"
export LIMBO_STATE_DIR="$WORK/state"
RUN=/run/limbo-itc
GUEST=itc
PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
expect() { want=$1; desc=$2; shift 2
  if "$@" >/dev/null 2>&1; then got=pass; else got=fail; fi
  [ "$got" = "$want" ] && ok "$desc" || bad "$desc (wanted $want, got $got)"; }
waitfor() { # waitfor <seconds> <command...>
  n=$1; shift; for _ in $(seq 1 "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }

rm -rf "$WORK/state" "$WORK/sentry" "$WORK/model.jsonl" "$WORK/sarina-sessions"
mkdir -p "$WORK/bin" "$WORK/state" "$WORK/profiles" "$WORK/sarina-cwd" "$WORK/sarina-sessions" "$WORK/sentry"
cd "$REPO" && go build -o "$WORK/bin/limbo" ./cmd/limbo || { echo "limbo build failed"; exit 2; }
( cd "$SENTRY_REPO" && go build -o "$WORK/bin/sentryd" ./cmd/sentryd ) || { echo "sentryd build failed"; exit 2; }
chmod 755 "$WORK" "$WORK/bin" "$WORK/bin/limbo" "$WORK/bin/sentryd"
LIMBO="$WORK/bin/limbo"
[ -f "$WORK/key" ] || ssh-keygen -q -t ed25519 -N '' -f "$WORK/key"
SHA=$(sha256sum "$BASE" | cut -d' ' -f1)

groupadd -f limbo-sentry; groupadd -f limbo-agent
id itq-sentry >/dev/null 2>&1 || useradd -M -s /usr/bin/nologin -G limbo-sentry itq-sentry
chown itq-sentry "$WORK/sentry"
as() { u=$1; shift; (cd / && runuser -u "$u" -- "$@"); }
jget() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval('d'+sys.argv[1]))" "$1"; }

PIDS=""
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null; done
  "$LIMBO" down "$WORK/$GUEST.json" >/dev/null 2>&1
  nft delete table inet "limbo_$GUEST" >/dev/null 2>&1
}
trap cleanup EXIT

# --- Sarina's real service, with a fake model behind it --------------------------
python3 "$REPO/scripts/fake_model.py" 8998 "$WORK/model.jsonl" & PIDS="$PIDS $!"
if [ -n "${SARINA_BIN:-}" ]; then
  # Sarina's Go binary; discovery off so the scripted fake model does not count the probe as a step.
  ( cd / && exec env SARINA_CONTEXT_DISCOVERY=0 "$SARINA_BIN" service --port 8899 --token chain-token \
      --base-url http://127.0.0.1:8998/v1 --model fake --api-key x \
      --session-dir "$WORK/sarina-sessions" --scratchpad-root "$WORK/sarina-scratch" ) >"$WORK/sarina.log" 2>&1 & PIDS="$PIDS $!"
else
( cd "$SARINA_REPO" && exec python3 -m sarina.service --port 8899 --token chain-token \
    --base-url http://127.0.0.1:8998/v1 --model fake --api-key x \
    --session-dir "$WORK/sarina-sessions" --scratchpad-root "$WORK/sarina-scratch" ) >"$WORK/sarina.log" 2>&1 & PIDS="$PIDS $!"
fi

# --- Limbo ----------------------------------------------------------------------
mkdir -p "$RUN"; chmod 755 "$RUN"
"$LIMBO" serve --run-dir "$RUN" --state-dir "$LIMBO_STATE_DIR" --profile-dir "$WORK/profiles" >"$WORK/serve.log" 2>&1 &
SERVE=$!; PIDS="$PIDS $SERVE"
waitfor 20 test -S "$RUN/control.sock" || { echo "limbo serve did not start"; cat "$WORK/serve.log"; exit 2; }

cat >"$WORK/$GUEST.json" <<EOF
{ "name": "$GUEST", "os": "linux",
  "image": {"path": "$BASE", "sha256": "$SHA"}, "cpus": 2, "memory_mb": 2048,
  "network": {"mode": "internet-only"}, "disposable": true,
  "access": {"user": "analyst"}, "app": {"name": "Shell", "exec": "true"},
  "provision": {"ssh_public_key": "$(cat "$WORK/key.pub")", "seed_iso": "$WORK/seed.iso"} }
EOF
GIP=$("$LIMBO" plan "$WORK/$GUEST.json" | grep -o 'analyst@[0-9.]*' | head -1 | cut -d@ -f2)
GW="${GIP%.*}.1"
gssh() { ssh -i "$WORK/key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR "analyst@$GIP" "$@"; }
gtcp() { gssh "timeout 4 bash -c '</dev/tcp/$1/$2'"; }

# A host service the guest must never reach.
python3 -m http.server 8000 --bind 0.0.0.0 >/dev/null 2>&1 & PIDS="$PIDS $!"

echo "== setup"
waitfor 30 curl -s -o /dev/null http://127.0.0.1:8899/healthz && ok "Sarina's real service is up (fake model behind it)" || bad "sarina-service did not start: $(tail -3 "$WORK/sarina.log")"
stat -c '%a %G' "$LIMBO_STATE_DIR/events.jsonl" | grep -q '^640 limbo-sentry$' && ok "event log is 640 group limbo-sentry (Heimdall can read, not write)" || bad "event log perms: $(stat -c '%a %G' "$LIMBO_STATE_DIR/events.jsonl")"

# --- sentryd, as an unprivileged user ----------------------------------------------
cat >"$WORK/sentry.json" <<EOF
{ "limbo_event_log": "$LIMBO_STATE_DIR/events.jsonl",
  "limbo_state_path": "$WORK/sentry/offset",
  "limbo_poll_interval_seconds": 1,
  "limbo_control_socket": "$RUN/control.sock",
  "sarina_url": "http://127.0.0.1:8899",
  "sarina_token": "chain-token",
  "sarina_cwd": "$WORK/sarina-cwd",
  "api_addr": "", "telemetry_interval_seconds": 3600,
  "net_ports": [], "ring_size": 100 }
EOF
chmod 644 "$WORK/sentry.json"
as itq-sentry "$WORK/bin/sentryd" run --config "$WORK/sentry.json" >"$WORK/sentry.out" 2>"$WORK/sentry.err" &
SENTRY=$!; PIDS="$PIDS $SENTRY"
waitfor 15 grep -q "Limbo quarantine response enabled" "$WORK/sentry.err" && ok "sentryd (unprivileged) started with the response enabled" || bad "sentryd: $(cat "$WORK/sentry.err" | head -5)"

echo "== a healthy guest start must NOT trigger anything"
"$LIMBO" seed --iso "$WORK/seed.iso" "$WORK/$GUEST.json" "$WORK/seed" >/dev/null
"$LIMBO" up "$WORK/$GUEST.json" && ok "limbo up" || bad "limbo up"
waitfor 90 gssh true && ok "guest booted" || { bad "guest never booted"; echo "passed=$PASS failed=$FAIL"; exit 1; }
sleep 4
expect pass "guest reaches the internet (healthy)" gtcp 1.1.1.1 443
expect fail "guest cannot reach the host service (healthy)" gtcp "$GW" 8000
[ ! -s "$WORK/sentry.out" ] && ok "Heimdall raised no alerts for a normal start (no false positive)" || bad "false alert: $(head -c 300 "$WORK/sentry.out")"
"$LIMBO" quarantine --socket "$RUN/admin.sock" list | grep -q "$GUEST" && bad "a healthy guest was quarantined" || ok "no quarantine was opened"

echo "== tamper: the firewall is removed under the running guest"
nft delete table inet "limbo_$GUEST" && ok "firewall table deleted (real)" || bad "could not delete table"
expect pass "now UNFILTERED: guest can reach the host service" gtcp "$GW" 8000
printf '{"time":"%s","kind":"policy.remove","guest":"%s","detail":{"note":"integration-chain: synthetic trigger event"}}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$GUEST" >>"$LIMBO_STATE_DIR/events.jsonl"

waitfor 40 sh -c "! timeout 4 ssh -i $WORK/key -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 analyst@$GIP \"timeout 3 bash -c '</dev/tcp/$GW/8000'\"" \
  && ok "Heimdall restricted the guest: the host service is unreachable again" || bad "guest still reaches the host service"
expect fail "restricted: guest cannot reach the internet" gtcp 1.1.1.1 443
expect pass "restricted: host can still reach the guest to investigate" gssh true
nft list table inet "limbo_$GUEST" >/dev/null 2>&1 && ok "the missing firewall table was recreated (deny-all)" || bad "no firewall table after the response"

echo "== the record"
LIST=$("$LIMBO" quarantine --socket "$RUN/admin.sock" list)
echo "$LIST" | grep -q "$GUEST.*open.*restrict.*sentry:limbo-guest" && ok "quarantine is open at 'restrict', opened by sentry:limbo-guest" || bad "record: $LIST"
QID=$(echo "$LIST" | awk -v g="$GUEST" '$2==g {print $1; exit}')
grep -q "quarantined (" "$WORK/sentry.err" && ok "Heimdall logged the quarantine" || bad "no quarantine log line: $(cat "$WORK/sentry.err")"
grep -q '"detector_id":"limbo-guest"' "$WORK/sentry.out" && ok "Heimdall still wrote its own alert" || bad "alert not written"

echo "== Sarina's advisory"
waitfor 40 sh -c "$LIMBO quarantine --socket $RUN/admin.sock show $QID | grep -q 'ADVISORY from sarina'" && ok "an advisory from Sarina was attached" || bad "no advisory: $(tail -5 "$WORK/sentry.err")"
SHOW=$("$LIMBO" quarantine --socket "$RUN/admin.sock" show "$QID")
echo "$SHOW" | grep -qi "untrusted" && ok "the human sees it labelled untrusted" || bad "advisory not labelled"
echo "$SHOW" | grep -q "IGNORE PREVIOUS INSTRUCTIONS" && ok "the hostile text in the advisory is shown, not obeyed" || bad "advisory text missing"
echo "$SHOW" | grep -q "status=open" && ok "the advisory changed nothing: record is still open" || bad "status changed: $(echo "$SHOW" | head -1)"
[ -s "$WORK/model.jsonl" ] && ok "Sarina's service really called the model backend" || bad "model backend never called"
# Not "no shell tool": allow_shell=false only denies at call time and the model was
# still offered ~70 tools (web_fetch, memory_add ...). The session must have NONE.
python3 - "$WORK/model.jsonl" <<'PY' && ok "the advisory session offered the model NO tools at all" || bad "the advisory session offered the model tools"
import json, sys
tools = set()
requests = 0
for line in open(sys.argv[1]):
    requests += 1
    body = json.loads(line)
    for t in body.get("tools") or []:
        tools.add(t["function"]["name"])
print("requests:", requests, "tools offered to the model:", sorted(tools), file=sys.stderr)
sys.exit(1 if tools or requests == 0 else 0)
PY
grep -q "UNTRUSTED EVIDENCE" "$WORK/model.jsonl" && ok "the evidence reached the model fenced as untrusted" || bad "prompt not fenced"

echo "== the human decides"
SUDO_USER=greg "$LIMBO" quarantine --socket "$RUN/admin.sock" verdict "$QID" safe --note "chain test" >/dev/null
sleep 1
"$LIMBO" quarantine --socket "$RUN/admin.sock" show "$QID" | grep -q "status=safe" && ok "verdict: safe, recorded" || bad "verdict not recorded"
waitfor 20 gtcp 1.1.1.1 443 && ok "safe: the original policy is restored (internet works)" || bad "internet not restored"
expect fail "safe: the host service is still blocked by the restored policy" gtcp "$GW" 8000

echo "== Limbo outage: Heimdall must keep alerting"
kill "$SERVE"; sleep 1
BEFORE=$(wc -l <"$WORK/sentry.out")
printf '{"time":"%s","kind":"policy.remove","guest":"%s","detail":{"note":"second synthetic trigger, limbo is down"}}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$GUEST" >>"$LIMBO_STATE_DIR/events.jsonl"
waitfor 15 sh -c "[ \$(wc -l <$WORK/sentry.out) -gt $BEFORE ]" && ok "Heimdall still raised the alert while Limbo was unreachable" || bad "alert lost during Limbo outage"
kill -0 "$SENTRY" 2>/dev/null && ok "sentryd is still running" || bad "sentryd died"
grep -q "could not quarantine" "$WORK/sentry.err" && ok "the failed quarantine attempt was reported" || bad "failure not logged"

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
