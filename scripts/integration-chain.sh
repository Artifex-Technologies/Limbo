#!/usr/bin/env bash
# Full-chain test with every real component: a real guest, a real `limbo serve`,
# the real `heimdalld` run as an unprivileged user, and Sarina's real service
# (backed by a fake model that records what it was asked).
#
# The one synthetic piece is the trigger: Limbo does not itself emit
# "firewall removed under a running guest", so the test deletes the guest's
# firewall table for real and appends the matching event to the log. Everything
# after that, Heimdall's detection, the quarantine, the repair, the advisory, the
# human verdict, is the real code path.
#
#   sudo scripts/integration-chain.sh        (needs the Heimdall repo beside this one; Sarina's Go binary, /usr/bin/sarina)
#   sudo SARINA_BIN=/path/to/sarina scripts/integration-chain.sh   (another build of Sarina)
#
# Its own services use ports of their own (Sarina 18899, the fake model 18998, the host service 18000), never the
# installed sarina-service's 8899; heimdalld's every state path is in the test folder, never /var/lib/heimdall. When
# UFW is active, a temporary UFW rule lets the guest's bridge reach the host service, so that Limbo's own table is the
# one thing between them (as the tamper check needs); it is removed at exit.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
. "$REPO/scripts/rust-daemon.sh"
GH="$(cd "$REPO/.." && pwd)"
HEIMDALL_REPO="${HEIMDALL_REPO:-$GH/Heimdall}"
SARINA_REPO="${SARINA_REPO:-$GH/Sarina}"
. "$REPO/scripts/it-common.sh"
SPORT=18899; MPORT=18998; HPORT=18000
pick_sarina
need_free_ports $SPORT $MPORT $HPORT
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

rm -rf "$WORK/state" "$WORK/heimdall" "$WORK/model.jsonl" "$WORK/sarina-sessions"
mkdir -p "$WORK/bin" "$WORK/state" "$WORK/profiles" "$WORK/sarina-cwd" "$WORK/sarina-sessions" "$WORK/heimdall"
cd "$REPO" && go build -o "$WORK/bin/limbo" ./cmd/limbo || { echo "limbo build failed"; exit 2; }
( cd "$HEIMDALL_REPO" && go build -o "$WORK/bin/heimdalld" ./cmd/heimdalld ) || { echo "heimdalld build failed"; exit 2; }
chmod 755 "$WORK" "$WORK/bin" "$WORK/bin/limbo" "$WORK/bin/heimdalld"
LIMBO="$WORK/bin/limbo"
use_rust_daemon
[ -f "$WORK/key" ] || ssh-keygen -q -t ed25519 -N '' -f "$WORK/key"
SHA=$(sha256sum "$BASE" | cut -d' ' -f1)

groupadd -f limbo-heimdall; groupadd -f limbo-agent
id itq-heimdall >/dev/null 2>&1 || useradd -M -s /usr/bin/nologin -G limbo-heimdall itq-heimdall
chown itq-heimdall "$WORK/heimdall"
as() { u=$1; shift; (cd / && runuser -u "$u" -- "$@"); }
jget() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval('d'+sys.argv[1]))" "$1"; }
# The test's heimdalld (user itq-heimdall) is stopped before and after (scripts/it-common.sh). Before 2026-11-11 it was
# started in a subshell and outlived each run: earlier runs' heimdallds kept watching the same event log and control
# socket, opened the quarantine first with their old configuration (Sarina on the installed 8899, Heimdall's real state
# paths), and the advisory never came.
stop_test_heimdalld

PIDS=""
UFW_RULE=""
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null; done
  stop_test_heimdalld
  "$LIMBO" down --i-know "$WORK/$GUEST.json" >/dev/null 2>&1
  nft delete table inet "limbo_$GUEST" >/dev/null 2>&1
  [ -n "$UFW_RULE" ] && ufw --force delete $UFW_RULE >/dev/null 2>&1
}
trap cleanup EXIT

# --- Sarina's real service, with a fake model behind it --------------------------
python3 "$REPO/scripts/fake_model.py" $MPORT "$WORK/model.jsonl" & PIDS="$PIDS $!"
# Sarina's Go binary (pick_sarina); discovery off so the scripted fake model does not count the probe as a step.
( cd / && exec env SARINA_CONTEXT_DISCOVERY=0 "$SARINA_BIN" service --port $SPORT --token chain-token \
    --base-url http://127.0.0.1:$MPORT/v1 --model fake --api-key x \
    --session-dir "$WORK/sarina-sessions" --scratchpad-root "$WORK/sarina-scratch" ) >"$WORK/sarina.log" 2>&1 &
SARINA=$!; PIDS="$PIDS $SARINA"

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
GIP=""  # set after up: the subnet is given then (limbo address)
GW="${GIP%.*}.1"
gssh() { ssh -i "$WORK/key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR "analyst@$GIP" "$@"; }
gtcp() { gssh "timeout 4 bash -c '</dev/tcp/$1/$2'"; }

# A host service the guest must never reach.
python3 -m http.server $HPORT --bind 0.0.0.0 --directory "$WORK/bin" >/dev/null 2>&1 & PIDS="$PIDS $!"
# UFW drops a guest's packets to the host by default: then the tamper check below could never see the guest get
# through, whatever Limbo did. A rule for this bridge and port only leaves Limbo's own table as the one barrier.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  UFW_RULE="allow in on lb-$GUEST to any port $HPORT proto tcp comment limbo-integration-chain"
  if ufw insert 1 $UFW_RULE >/dev/null 2>&1 || ufw $UFW_RULE >/dev/null 2>&1; then
    echo "== UFW is active: a temporary rule lets lb-$GUEST reach port $HPORT (removed at exit)"
  else
    echo "== UFW is active and the temporary rule could not be added: the UNFILTERED check will fail"; UFW_RULE=""
  fi
fi

echo "== setup"
waitfor 10 curl -s -o /dev/null "http://127.0.0.1:$HPORT/" && ok "the host service answers on the host (port $HPORT)" || bad "the host service did not start"
waitfor 30 curl -s -o /dev/null http://127.0.0.1:$SPORT/healthz && kill -0 "$SARINA" 2>/dev/null \
  && ok "Sarina's real service is up (fake model behind it)" || bad "sarina-service did not start: $(tail -3 "$WORK/sarina.log")"
stat -c '%a %G' "$LIMBO_STATE_DIR/events.jsonl" | grep -q '^640 limbo-heimdall$' && ok "event log is 640 group limbo-heimdall (Heimdall can read, not write)" || bad "event log perms: $(stat -c '%a %G' "$LIMBO_STATE_DIR/events.jsonl")"

# --- heimdalld, as an unprivileged user ----------------------------------------------
# Every path heimdalld keeps state in or reads its intelligence from is in the test folder (its defaults are the real
# /var/lib/heimdall and /etc/heimdall), and the host-wide watchers this test is not about are off.
H="$WORK/heimdall"
cat >"$WORK/heimdall.json" <<EOF
{ "limbo_event_log": "$LIMBO_STATE_DIR/events.jsonl",
  "limbo_state_path": "$H/offset",
  "limbo_poll_interval_seconds": 1,
  "limbo_control_socket": "$RUN/control.sock",
  "sarina_url": "http://127.0.0.1:$SPORT",
  "sarina_token": "chain-token",
  "sarina_cwd": "$WORK/sarina-cwd",
  "api_addr": "", "telemetry_interval_seconds": 3600,
  "net_ports": [], "ring_size": 100,
$(heimdall_isolation "$H") }
EOF
chmod 644 "$WORK/heimdall.json"
# exec: $! is runuser itself, which passes the kill on to heimdalld (a plain subshell would die alone)
(cd / && exec runuser -u itq-heimdall -- "$WORK/bin/heimdalld" run --config "$WORK/heimdall.json") >"$WORK/heimdall.out" 2>"$WORK/heimdall.err" &
HEIMDALL=$!; PIDS="$PIDS $HEIMDALL"
waitfor 15 grep -q "Limbo quarantine response enabled" "$WORK/heimdall.err" && ok "heimdalld (unprivileged) started with the response enabled" || bad "heimdalld: $(cat "$WORK/heimdall.err" | head -5)"

echo "== a healthy guest start must NOT trigger anything"
"$LIMBO" seed --iso "$WORK/seed.iso" "$WORK/$GUEST.json" "$WORK/seed" >/dev/null
"$LIMBO" up --i-know "$WORK/$GUEST.json" && ok "limbo up" || bad "limbo up"
GIP=$("$LIMBO" address "$WORK/$GUEST.json"); GW="${GIP%.*}.1"  # given at up
waitfor 90 gssh true && ok "guest booted" || { bad "guest never booted"; echo "passed=$PASS failed=$FAIL"; exit 1; }
sleep 4
expect pass "guest reaches the internet (healthy)" gtcp 1.1.1.1 443
expect fail "guest cannot reach the host service (healthy)" gtcp "$GW" $HPORT
# A false alert is one about the guest start: the limbo-guest detector, or any alert naming Limbo, the guest, its
# bridge or tap. Heimdall's host-wide detectors (hardening, remote-access, package audit, ...) also report this
# computer's own state when heimdalld starts with a fresh state folder; those are shown, not counted.
false_alerts() { python3 - "$WORK/heimdall.out" "$GUEST" <<'PY'
import json, sys
guest = sys.argv[2]
marks = ("limbo", guest, "lb-" + guest, "vl-" + guest)
bad = []
for line in open(sys.argv[1], errors="replace"):
    try:
        a = json.loads(line)
    except ValueError:
        bad.append(line.strip()[:300]); continue
    if a.get("detector_id") == "limbo-guest" or any(m in line.lower() for m in marks):
        bad.append(line.strip()[:300])
    else:
        print("  (about the host, not the guest: not counted) %s %s: %s" % (
            a.get("severity"), a.get("detector_id"), a.get("summary", "")[:120]), file=sys.stderr)
print("\n".join(bad))
PY
}
FA=$(false_alerts)
[ -z "$FA" ] && ok "Heimdall raised no alerts for a normal start (no false positive)" || bad "false alert: $FA"
"$LIMBO" quarantine --socket "$RUN/admin.sock" list | grep -q "$GUEST" && bad "a healthy guest was quarantined" || ok "no quarantine was opened"

echo "== tamper: the firewall is removed under the running guest"
nft delete table inet "limbo_$GUEST" && ok "firewall table deleted (real)" || bad "could not delete table"
expect pass "now UNFILTERED: guest can reach the host service" gtcp "$GW" $HPORT
printf '{"time":"%s","kind":"policy.remove","guest":"%s","detail":{"note":"integration-chain: synthetic trigger event"}}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$GUEST" >>"$LIMBO_STATE_DIR/events.jsonl"

waitfor 40 sh -c "! timeout 4 ssh -i $WORK/key -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 analyst@$GIP \"timeout 3 bash -c '</dev/tcp/$GW/$HPORT'\"" \
  && ok "Heimdall restricted the guest: the host service is unreachable again" || bad "guest still reaches the host service"
expect fail "restricted: guest cannot reach the internet" gtcp 1.1.1.1 443
expect pass "restricted: host can still reach the guest to investigate" gssh true
nft list table inet "limbo_$GUEST" >/dev/null 2>&1 && ok "the missing firewall table was recreated (deny-all)" || bad "no firewall table after the response"

echo "== the record"
LIST=$("$LIMBO" quarantine --socket "$RUN/admin.sock" list)
echo "$LIST" | grep -q "$GUEST.*open.*restrict.*heimdall:limbo-guest" && ok "quarantine is open at 'restrict', opened by heimdall:limbo-guest" || bad "record: $LIST"
QID=$(echo "$LIST" | awk -v g="$GUEST" '$2==g {print $1; exit}')
grep -q "quarantined (" "$WORK/heimdall.err" && ok "Heimdall logged the quarantine" || bad "no quarantine log line: $(cat "$WORK/heimdall.err")"
grep -q '"detector_id":"limbo-guest"' "$WORK/heimdall.out" && ok "Heimdall still wrote its own alert" || bad "alert not written"

echo "== Sarina's advisory"
N=$(pgrep -u itq-heimdall -x heimdalld | wc -l)
[ "$N" = 1 ] && ok "exactly one test heimdalld is running (this run's)" || bad "$N test heimdallds are running"
# The advisory is asked for when Heimdall opens the quarantine and arrives after Sarina's model answers: wait for it,
# and on failure show what this run's heimdalld and Sarina said about it (not the last lines of an unrelated watcher).
waitfor 60 sh -c "$LIMBO quarantine --socket $RUN/admin.sock show $QID | grep -q 'ADVISORY from sarina'" && ok "an advisory from Sarina was attached" \
  || bad "no advisory: heimdalld: $(grep -iE 'advis|sarina|quarantin' "$WORK/heimdall.err" | tail -5); sarina: $(tail -3 "$WORK/sarina.log"); model requests: $(wc -l <"$WORK/model.jsonl" 2>/dev/null || echo 0)"
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
expect fail "safe: the host service is still blocked by the restored policy" gtcp "$GW" $HPORT

echo "== Limbo outage: Heimdall must keep alerting"
kill "$SERVE"; sleep 1
BEFORE=$(wc -l <"$WORK/heimdall.out")
printf '{"time":"%s","kind":"policy.remove","guest":"%s","detail":{"note":"second synthetic trigger, limbo is down"}}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$GUEST" >>"$LIMBO_STATE_DIR/events.jsonl"
waitfor 15 sh -c "[ \$(wc -l <$WORK/heimdall.out) -gt $BEFORE ]" && ok "Heimdall still raised the alert while Limbo was unreachable" || bad "alert lost during Limbo outage"
kill -0 "$HEIMDALL" 2>/dev/null && ok "heimdalld is still running" || bad "heimdalld died"
grep -q "could not quarantine" "$WORK/heimdall.err" && ok "the failed quarantine attempt was reported" || bad "failure not logged"

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
