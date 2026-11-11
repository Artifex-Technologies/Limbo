#!/usr/bin/env bash
# The owner's root checks of the Rust daemon (docs/RUST_PORT.md "Commands for the owner"): the read-only rehearsal on
# a copy of this computer's Limbo state, then each real-guest script twice, first with the Go daemon (the baseline)
# and then with limbo-rs. A check that fails both times is the script's or this computer's; only a check that passes
# with Go and fails with Rust counts against the port. Logs and a summary go to OUTDIR (handed to the sudo user).
#
#   sudo bash scripts/rust-checks.sh GO_LIMBO LIMBO_RS OUTDIR
#
# Nothing is installed; limbo.service, /var/lib/limbo/state and /etc/limbo are not touched (the scripts use their own
# folders under /var/lib/limbo/it*, /run/limbo-it*, and test users and groups, as they always have).
set -u
[ "$(id -u)" = 0 ] || { echo "run it as root (sudo)"; exit 2; }
[ $# -eq 3 ] || { echo "usage: sudo bash scripts/rust-checks.sh GO_LIMBO LIMBO_RS OUTDIR"; exit 2; }
GO=$(realpath "$1"); RS=$(realpath "$2"); OUT=$3
REPO="$(cd "$(dirname "$0")/.." && pwd)"
[ -x "$GO" ] && [ -x "$RS" ] || { echo "$GO and $RS must be executables"; exit 2; }
mkdir -p "$OUT"; chmod 700 "$OUT"

echo "== rehearsal (read-only, a copy of the real state, both daemons in namespaces)"
LD=$(mktemp -d /tmp/limbo-ld-host.XXXXXX)
python3 -I "$REPO/rust/parity/daemon-differential.py" --from-host --go "$GO" --rs "$RS" --out "$LD" --idle 5 >"$OUT/rehearsal.log" 2>&1
echo "rehearsal exit $? : $(tail -1 "$OUT/rehearsal.log")" | tee "$OUT/summary.txt"
rm -rf "$LD"   # it held copies of the state and the license folder

for s in quarantine chain sarina; do
  echo "== integration-$s.sh: Go daemon (baseline)"
  env -u LIMBO_RS bash "$REPO/scripts/integration-$s.sh" >"$OUT/$s-go.log" 2>&1
  echo "== integration-$s.sh: limbo-rs"
  LIMBO_RS="$RS" bash "$REPO/scripts/integration-$s.sh" >"$OUT/$s-rs.log" 2>&1
  python3 -I - "$s" "$OUT/$s-go.log" "$OUT/$s-rs.log" >>"$OUT/summary.txt" <<'PY'
import re, sys
name, go, rs = sys.argv[1:]
def checks(path):
    out, total = {}, ""
    for line in open(path, errors="replace"):
        m = re.match(r"  (PASS|FAIL)  (.*)", line)
        if m:
            # a check's name is its text before any detail (": ..." or " (wanted ...)")
            key = re.split(r": | \(wanted ", m.group(2))[0].strip()
            out.setdefault(key, m.group(1))
        elif line.startswith("passed="):
            total = line.strip()
    return out, total
g, gt = checks(go)
r, rt = checks(rs)
print("integration-%s.sh   Go: %s   Rust: %s" % (name, gt or "(no total)", rt or "(no total)"))
for k in sorted(set(g) | set(r)):
    a, b = g.get(k, "-"), r.get(k, "-")
    if a != b:
        print("  DIFFERS  Go %s  Rust %s  %s" % (a, b, k))
    elif a == "FAIL":
        print("  fails with both (script or this computer)  %s" % k)
PY
done
chown -R "${SUDO_USER:-root}:" "$OUT"
echo
cat "$OUT/summary.txt"
