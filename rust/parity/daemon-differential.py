#!/usr/bin/env python3
"""The Go and the Rust `limbo serve` on the same scripted socket traffic, compared.

Each daemon runs unprivileged inside its own user, mount and network namespace (`unshare -rmn`): root there, nobody
outside. /etc/limbo is a private bind mount of an empty folder (no host policy), the network namespace has only
loopback, and every program Limbo runs (virsh, qemu-img, nft, ssh, xorriso, ufw, clamscan, ...) is a fake on PATH that
records its arguments and input. Nothing touches the host's libvirt, firewall, /var/lib/limbo or /etc/limbo.

The same script of requests goes to admin.sock, control.sock, agent.sock and user.sock of each daemon: instances,
Settings-page changes, holds and verdicts, licenses, the exchange outbox with a ClamAV hit, validation, bundle and
sample runs and their failures, the containment lock, the password switch, and NFLOG packets from nft rules inside the
namespace. Then the answers, events.jsonl, the commands the fakes saw and the state files are normalised (times, ids,
pids, the scratch folder) and compared. Memory (VmRSS, PSS, threads) and CPU (idle and during the script) are read
from /proc for both.

    python3 -I rust/parity/daemon-differential.py --go GO_LIMBO --rs LIMBO_RS --out DIR [--idle 60]

Exit status 0 when the two agree.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))

SHA_PAD = "0" * 64

FAKE = r"""#!/bin/bash
# a fake host program: records what it was asked, behaves just enough
R="__ROOT__"
me=$(basename "$0")
{ printf '%s' "$me"; for a in "$@"; do printf ' %s' "$a"; done; printf '\n'; } >> "$R/tools.log"
case "$me" in
  nft)
    if [ "$1" = "-f" ]; then sed 's/^/  | /' >> "$R/tools.log"; fi ;;
  virsh)
    shift 2
    mkdir -p "$R/virsh/defined" "$R/virsh/running"
    case "$1" in
      define) n=$(sed -n 's:.*<name>\(.*\)</name>.*:\1:p' "$2" | head -1); touch "$R/virsh/defined/$n" ;;
      start) [ -e "$R/virsh/defined/$2" ] || { echo "error: failed to get domain '$2'" >&2; exit 1; }; touch "$R/virsh/running/$2" ;;
      destroy) [ -e "$R/virsh/running/$2" ] || { echo "error: domain is not running" >&2; exit 1; }; rm -f "$R/virsh/running/$2" ;;
      undefine) [ -e "$R/virsh/defined/$2" ] || { echo "error: failed to get domain '$2'" >&2; exit 1; }; rm -f "$R/virsh/defined/$2" ;;
      dominfo) [ -e "$R/virsh/defined/$2" ] || { echo "error: failed to get domain '$2'" >&2; exit 1; } ;;
      list) ls "$R/virsh/running" ;;
    esac ;;
  qemu-img)
    if [ "$1" = "create" ]; then
      out="${@: -1}"; base="$5"
      python3 -I -c 'import struct,sys; b=sys.argv[2].encode(); h=b"QFI\xfb"+struct.pack(">I",3)+struct.pack(">Q",104)+struct.pack(">I",len(b))+b"\0"*4+struct.pack(">Q",10<<30)+b"\0"*(104-32)+b; open(sys.argv[1],"wb").write(h)' "$out" "$base"
    fi ;;
  xorriso)
    while [ $# -gt 0 ]; do [ "$1" = "-o" ] && { : > "$2"; }; shift; done ;;
  ssh)
    cmd="${@: -1}"
    [ "$cmd" = "true" ] && exit 0
    if [ -t 0 ]; then sum=none; else sum=$(sha256sum | cut -c1-16); fi
    echo "  | stdin $sum" >> "$R/tools.log"
    case "$cmd" in
      *fail-ssh*) echo "ssh: connect to host port 22: Connection refused" >&2; exit 255 ;;
      *big-output*) head -c 100000 /dev/zero | tr '\0' 'y'; exit 0 ;;
      *binary-output*) printf 'a\x01b\x1b[31mc\xff\xfed\n'; echo warn >&2; exit 0 ;;
      *exit\ 3*) echo partial; exit 3 ;;
      *slow-command*) echo started; exec sleep 30 ;;
      *) echo "ran: ${cmd:0:60}"; echo "stdin: $sum"; exit 0 ;;
    esac ;;
  clamscan)
    f="${@: -1}"
    if grep -q EICAR "$f"; then echo "$f: Eicar-Signature FOUND"; exit 1; fi
    exit 0 ;;
esac
exit 0
"""

TOOLS = ["virsh", "qemu-img", "qemu-system-x86_64", "dnsmasq", "nft", "ssh", "xorriso", "ufw", "clamscan"]


def qcow2(size_gib):
    import struct
    h = b"QFI\xfb" + struct.pack(">I", 3) + b"\0" * 16 + struct.pack(">Q", size_gib << 30)
    return h + b"\0" * (128 - len(h))


def write(path, data, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())
    os.chmod(path, mode)


def build_tree(root, images):
    """The folders a daemon starts from (every file the test's, so root's inside the namespace)."""
    if os.path.exists(root):
        shutil.rmtree(root)
    os.makedirs(root)
    for d, m in [("bin", 0o755), ("state", 0o700), ("run", 0o755), ("profiles", 0o755), ("instances", 0o755),
                 ("licenses", 0o700), ("etc-limbo", 0o755), ("inbox", 0o700), ("limbo", 0o755),
                 ("limbo/exchange", 0o700), ("limbo/exchange/office", 0o700), ("keys", 0o700)]:
        os.makedirs(os.path.join(root, d), exist_ok=True)
        os.chmod(os.path.join(root, d), m)
    for t in TOOLS:
        write(os.path.join(root, "bin", t), FAKE.replace("__ROOT__", root), 0o755)
    write(os.path.join(root, "etc-limbo", "settings.json"), '{\n  "ask_password": false\n}\n', 0o644)
    write(os.path.join(root, "keys", "id_ed25519"), "not a key", 0o600)
    img = os.path.join(images, "base.qcow2")
    sha = hashlib.sha256(open(img, "rb").read()).hexdigest()
    key = os.path.join(root, "keys", "id_ed25519")

    def profile(name, extra_manifest="", extra="", sha_=None, image=None, disposable=True):
        man = ('{"name":"p","os":"linux","disposable":%s,"image":{"path":"%s","sha256":"%s"},'
               '"access":{"user":"vet","sudo":true},"app":{"name":"Shell","exec":"bash"},'
               '"provision":{"ssh_public_key":"ssh-ed25519 AAAAC3Nza vet@limbo","packages":["nmap"]}%s}') % (
            "true" if disposable else "false", image or img, sha_ or sha, extra_manifest)
        write(os.path.join(root, "profiles", name + ".json"),
              '{"manifest":%s,"ssh_identity":"%s","max_seconds":120%s}' % (man, key, extra), 0o644)

    profile("arch-update", extra=',"allow_bundle":true')
    profile("sealed", extra_manifest=',"access":{"user":"vet"}', extra=',"allow_sample":true')
    profile("netted", extra_manifest=',"network":{"mode":"internet-only"}')
    profile("broken", extra=',"surprise":1')
    profile("kept", disposable=False)
    profile("noimage", image=os.path.join(images, "missing.qcow2"))
    profile("mismatch", sha_="1" * 64)
    write(os.path.join(root, "profiles", "Bad_Name.json"), "{}", 0o644)
    write(os.path.join(root, "limbo", "exchange", "office", "report.txt"), "quarterly numbers\n", 0o644)
    write(os.path.join(root, "limbo", "exchange", "office", "eicar.txt"), "X5O EICAR-STANDARD-ANTIVIRUS-TEST-FILE\n", 0o644)
    write(os.path.join(root, "limbo", "exchange", "office", "sub", "notes.md"), "# notes\n", 0o644)
    write(os.path.join(root, "limbo", "exchange", "office", "bad\x01name.txt"), "x", 0o644)
    write(os.path.join(root, "inbox", "sample.bin"), b"MZ\x90\x00 sample", 0o600)
    return sha


def manifest(img, sha, name="office", extra=""):
    return ('{"name":"%s","os":"linux","image":{"path":"%s","sha256":"%s"},"access":{"user":"analyst"},'
            '"app":{"name":"LibreOffice","exec":"soffice"},"disk_gb":20%s}') % (name, img, sha, extra)


def script(img, sha):
    """(socket, method, path, body, wait-for-run). {run} in a path is the last run started."""
    m = manifest(img, sha)
    tar = base64.b64encode(b"main.py\0" + b"print('hi')\n" * 4).decode()
    s = [
        ("user", "GET", "/v1/status", ""),
        ("user", "GET", "/v1/settings", ""),
        ("admin", "POST", "/v1/instances", '{"manifest":%s,"owner":""}' % m),
        ("admin", "POST", "/v1/instances", '{"manifest":%s,"owner":""}' % m),
        ("admin", "POST", "/v1/instances", '{"manifest":%s,"owner":"Not A User"}' % manifest(img, sha, "lab2")),
        ("admin", "POST", "/v1/instances", '{"manifest":%s}' % manifest(img, sha, "lab3", ',"disposable":true')),
        ("admin", "POST", "/v1/instances", '{"manifest":%s}' % manifest(img, sha, "r1234abcd")),
        ("admin", "POST", "/v1/instances", '{"manifest":{"name":"x","bogus":1}}'),
        ("admin", "POST", "/v1/instances", '{"owner":"a"}'),
        ("user", "GET", "/v1/instances", ""),
        ("user", "POST", "/v1/instances/office/settings", '{"cpus":2,"memory_mb":2048,"clipboard":"text"}'),
        ("user", "POST", "/v1/instances/office/settings", '{"cpus":999}'),
        ("user", "POST", "/v1/instances/office/settings", '{"disk_gb":1}'),
        ("user", "POST", "/v1/instances/office/settings", '{"devices":["0000:03:00.0"]}'),
        ("user", "POST", "/v1/instances/office/settings", '{}'),
        ("user", "POST", "/v1/instances/office/settings", '{"network":{"mode":"internet-only"}}'),
        ("admin", "POST", "/v1/instances/office/settings", '{"network":{"mode":"allowlist","allow":[{"addr":"1.1.1.1","port":53,"proto":"udp"}]}}'),
        ("admin", "POST", "/v1/instances/office/settings", '{"network":{"mode":"allowlist"}}'),
        ("user", "POST", "/v1/instances/office/settings", '{"shared_folder":"on"}'),
        ("user", "POST", "/v1/instances/ghost/start", "{}"),
        ("user", "POST", "/v1/instances/office/start", "{}"),
        ("user", "POST", "/v1/instances/office/start", "{}"),
        ("user", "GET", "/v1/instances/office", ""),
        ("user", "POST", "/v1/instances/office/settings", '{"memory_mb":3072}'),
        ("user", "GET", "/v1/instances/office", ""),
        ("user", "GET", "/v1/exchange/office", ""),
        ("user", "POST", "/v1/exchange/office/take", '{"path":"report.txt"}'),
        ("user", "POST", "/v1/exchange/office/take", '{"path":"eicar.txt"}'),
        ("user", "POST", "/v1/exchange/office/take", '{"path":"../etc/passwd"}'),
        ("user", "POST", "/v1/exchange/office/take", '{"path":"sub/notes.md"}'),
        ("user", "POST", "/v1/exchange/office/take", '{"path":"missing.txt"}'),
        ("user", "GET", "/v1/exchange/office", ""),
        ("control", "POST", "/v1/quarantine", '{"guest":"office","reason":"probed the host","source":"heimdall:limbo-guest","evidence":{"dst":"10.213.1.1"}}'),
        ("control", "POST", "/v1/quarantine", '{"guest":"office","reason":"again","level":"isolate"}'),
        ("control", "GET", "/v1/guests/office", ""),
        ("control", "GET", "/v1/guests/ghost", ""),
        ("control", "GET", "/v1/quarantine", ""),
        ("user", "GET", "/v1/status", ""),
        ("user", "POST", "/v1/instances/office/stop", "{}"),
        ("user", "POST", "/v1/exchange/office/take", '{"path":"sub/notes.md"}'),
        ("user", "POST", "/v1/instances/office/free-space", '{"confirm":true}'),
        ("control", "POST", "/v1/quarantine/{q1}/advisory", '{"source":"sarina","text":"looks like a scanner\\u001b[0m"}'),
        ("control", "POST", "/v1/quarantine/{q1}/raise", '{"level":"restrict"}'),
        ("admin", "POST", "/v1/quarantine/{q1}/verdict", '{"verdict":"safe","by":"root","note":"false alarm"}'),
        ("admin", "GET", "/v1/quarantine/{q1}", ""),
        ("user", "POST", "/v1/instances/office/stop", "{}"),
        ("user", "POST", "/v1/instances/office/stop", "{}"),
        ("user", "POST", "/v1/instances/office/free-space", '{"confirm":false}'),
        ("user", "POST", "/v1/instances/office/free-space", '{"confirm":true}'),
        ("admin", "POST", "/v1/licenses", '{"name":"Windows 11 Pro","key":"abcde-12345-fghij-67890-klmno"}'),
        ("admin", "POST", "/v1/licenses", '{"name":"again","key":"ABCDE-12345-FGHIJ-67890-KLMNO"}'),
        ("admin", "POST", "/v1/licenses", '{"name":"bad","key":"nope"}'),
        ("admin", "POST", "/v1/licenses", '{"name":"has ABCDE-12345-FGHIJ in it","key":"QQQQQ-12345-FGHIJ-67890-KLMNO"}'),
        ("user", "GET", "/v1/licenses", ""),
        ("user", "POST", "/v1/licenses/{lic1}/assign", '{"guest":"office"}'),
        ("admin", "GET", "/v1/licenses/{lic1}/key", ""),
        ("admin", "GET", "/v1/licenses/lic-00000000/key", ""),
        ("admin", "DELETE", "/v1/licenses/{lic1}", ""),
        ("agent", "GET", "/v1/profiles", ""),
        ("agent", "POST", "/v1/runs", '{"profile":"arch-update","command":"uname -a","timeout_seconds":30}'),
        ("agent", "WAIT", "{run}", ""),
        ("agent", "POST", "/v1/runs", '{"profile":"arch-update","command":"python3 main.py","bundle":"%s"}' % tar),
        ("agent", "WAIT", "{run}", ""),
        ("agent", "POST", "/v1/runs", '{"profile":"netted","command":"echo hi; exit 3"}'),
        ("agent", "WAIT", "{run}", ""),
        ("agent", "POST", "/v1/runs", '{"profile":"arch-update","command":"big-output"}'),
        ("agent", "WAIT", "{run}", ""),
        ("agent", "POST", "/v1/runs", '{"profile":"arch-update","command":"binary-output"}'),
        ("agent", "WAIT", "{run}", ""),
        ("agent", "POST", "/v1/runs", '{"profile":"arch-update","command":"fail-ssh"}'),
        ("agent", "WAIT", "{run}", ""),
        ("agent", "POST", "/v1/runs", '{"profile":"broken","command":"true"}'),
        ("agent", "POST", "/v1/runs", '{"profile":"kept","command":"true"}'),
        ("agent", "POST", "/v1/runs", '{"profile":"noimage","command":"true"}'),
        ("agent", "POST", "/v1/runs", '{"profile":"mismatch","command":"true"}'),
        ("agent", "WAIT", "{run}", ""),
        ("agent", "POST", "/v1/runs", '{"profile":"nope","command":"true"}'),
        ("agent", "POST", "/v1/runs", '{"profile":"Bad_Name","command":"true"}'),
        ("agent", "POST", "/v1/runs", '{"profile":"arch-update","command":""}'),
        ("agent", "POST", "/v1/runs", '{"profile":"sealed","command":"x","bundle":"aGk="}'),
        ("agent", "GET", "/v1/runs/r00000000", ""),
        ("admin", "POST", "/v1/sample-runs", '{"profile":"sealed","command":"file sample","sample":"sample.bin"}'),
        ("admin", "WAIT", "{run}", ""),
        ("admin", "POST", "/v1/sample-runs", '{"profile":"arch-update","command":"file sample","sample":"sample.bin"}'),
        ("admin", "POST", "/v1/sample-runs", '{"profile":"sealed","command":"x","sample":"../etc/passwd"}'),
        ("admin", "POST", "/v1/sample-runs", '{"profile":"sealed","command":"x","sample":"absent.bin"}'),
        ("admin", "CONTAIN", "", ""),
        ("agent", "POST", "/v1/runs", '{"profile":"arch-update","command":"true"}'),
        ("admin", "UNCONTAIN", "", ""),
        ("admin", "POST", "/v1/agent-runs/stop", "{}"),
        ("agent", "POST", "/v1/runs", '{"profile":"arch-update","command":"slow-command","timeout_seconds":2}'),
        ("agent", "WAIT", "{run}", ""),
        ("agent", "POST", "/v1/runs", '{"profile":"arch-update","command":"slow-command"}'),
        ("admin", "SLEEP", "", ""),
        ("admin", "POST", "/v1/agent-runs/stop", "{}"),
        ("agent", "WAIT", "{run}", ""),
        ("agent", "GET", "/v1/profiles", ""),
        ("admin", "POST", "/v1/guests/office/down", "{}"),
        ("admin", "POST", "/v1/settings", '{"ask_password":true}'),
        ("user", "GET", "/v1/settings", ""),
        ("user", "POST", "/v1/instances/office/start", "{}"),
        ("admin", "POST", "/v1/instances/office/start", "{}"),
        ("control", "POST", "/v1/quarantine", '{"guest":"office","reason":"second look"}'),
        ("admin", "POST", "/v1/quarantine/{q2}/verdict", '{"verdict":"dangerous","by":"root"}'),
        ("admin", "POST", "/v1/quarantine/{q2}/close", '{"by":"root"}'),
        ("admin", "POST", "/v1/instances/office/stop", "{}"),
        ("admin", "POST", "/v1/quarantine/{q2}/close", '{"by":"root"}'),
        ("admin", "DELETE", "/v1/instances/office", '{"delete_disk":true}'),
        ("admin", "GET", "/v1/instances", ""),
        ("admin", "POST", "/v1/settings", '{"ask_password":false}'),
        ("admin", "NFLOG", "", ""),
        ("user", "GET", "/v1/status", ""),
    ]
    return s


def copy_host_state(root):
    """--from-host (root only): this computer's real Limbo state, copied, so both daemons start from what the Go daemon
    wrote. Guests' disks are left out; the copies stay root-only and are deleted with the scratch folder."""
    def cp(src, dst, skip=()):
        if not os.path.exists(src):
            return
        if os.path.isdir(src):
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(src, dst, symlinks=True, ignore=shutil.ignore_patterns(*skip))
        else:
            shutil.copy2(src, dst)
    cp("/var/lib/limbo/state", os.path.join(root, "state"), ("*.qcow2", "exchange-scratch", "exchange-held", "runs", "events.jsonl"))
    cp("/etc/limbo/validation", os.path.join(root, "profiles"))
    cp("/etc/limbo/instances", os.path.join(root, "instances"))
    cp("/etc/limbo/licenses", os.path.join(root, "licenses"))
    cp("/etc/limbo/settings.json", os.path.join(root, "etc-limbo", "settings.json"))
    os.chmod(os.path.join(root, "state"), 0o700)


def readonly_script(root):
    """What the Settings page, Heimdall and Sarina read, for every guest the copied state knows: nothing changes."""
    names = set()
    for d in (os.path.join(root, "instances"), os.path.join(root, "state")):
        for n in os.listdir(d) if os.path.isdir(d) else []:
            if n.endswith(".manifest.json"):
                names.add(n[: -len(".manifest.json")])
            elif n.endswith(".json") and d.endswith("instances"):
                names.add(n[:-5])
    s = [("user", "GET", "/v1/status", ""), ("user", "GET", "/v1/settings", ""), ("user", "GET", "/v1/instances", ""),
         ("admin", "GET", "/v1/quarantine", ""), ("control", "GET", "/v1/quarantine", ""), ("agent", "GET", "/v1/profiles", ""),
         ("admin", "GET", "/v1/licenses", "")]
    for n in sorted(names):
        s += [("user", "GET", "/v1/instances/" + n, ""), ("control", "GET", "/v1/guests/" + n, ""),
              ("admin", "GET", "/v1/exchange/" + n, "")]
    return s


def http(sock, method, path, body):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(60)
    s.connect(sock)
    b = body.encode()
    s.sendall(("%s %s HTTP/1.1\r\nHost: limbo\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (method, path, len(b))).encode() + b)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    head, _, payload = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for l in lines[1:]:
        k, _, v = l.partition(":")
        headers[k.strip().lower()] = v.strip()
    if headers.get("transfer-encoding") == "chunked":
        out, rest = b"", payload
        while rest:
            size, _, rest = rest.partition(b"\r\n")
            n = int(size.split(b";")[0], 16)
            if n == 0:
                break
            out, rest = out + rest[:n], rest[n + 2:]
        payload = out
    return status, headers, payload


def proc_figures(pid):
    out = {}
    try:
        for line in open("/proc/%d/status" % pid):
            k, _, v = line.partition(":")
            if k in ("VmRSS", "VmHWM", "Threads", "RssAnon"):
                out[k] = v.strip()
        for line in open("/proc/%d/smaps_rollup" % pid):
            k, _, v = line.partition(":")
            if k in ("Pss", "Pss_Anon", "Private_Dirty"):
                out[k] = v.strip()
        f = open("/proc/%d/stat" % pid).read().rsplit(")", 1)[1].split()
        out["cpu_ticks"] = int(f[11]) + int(f[12])
        # context switches of every thread (the process's own status file counts its first thread only)
        total = 0
        for t in os.listdir("/proc/%d/task" % pid):
            st = open("/proc/%d/task/%s/status" % (pid, t)).read()
            m = re.search(r"voluntary_ctxt_switches:\s+(\d+)\s+nonvoluntary_ctxt_switches:\s+(\d+)", st, re.S)
            if m:
                total += int(m.group(1)) + int(m.group(2))
        out["ctx_switches"] = total
    except OSError as e:
        out["error"] = str(e)
    return out


def inner(args):
    """Inside the namespaces: start the daemon, run the script, collect everything."""
    root, images = args.root, args.images
    subprocess.run(["mount", "--bind", os.path.join(root, "etc-limbo"), "/etc/limbo"], check=False,
                   stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=False)
    env = {"PATH": os.path.join(root, "bin") + ":/usr/bin", "HOME": root, "LANG": "C"}
    cmd = [args.daemon, "serve", "--state-dir", os.path.join(root, "state"), "--run-dir", os.path.join(root, "run"),
           "--profile-dir", os.path.join(root, "profiles"), "--inbox", os.path.join(root, "inbox"),
           "--contained-marker", os.path.join(root, "contained"), "--heimdall-group", "", "--agent-group", "",
           "--users-group", "root", "--instances-dir", os.path.join(root, "instances"),
           "--settings", os.path.join(root, "etc-limbo", "settings.json"), "--licenses-dir", os.path.join(root, "licenses"),
           "--limbo-root", os.path.join(root, "limbo"), "--exchange-root", os.path.join(root, "limbo", "exchange")]
    err = open(os.path.join(root, "daemon.err"), "wb")
    t0 = time.time()
    p = subprocess.Popen(cmd, env=env, cwd=root, stdout=err, stderr=err)
    socks = {n: os.path.join(root, "run", n + ".sock") for n in ("admin", "control", "agent", "user")}
    while not all(os.path.exists(s) for s in socks.values()):
        if p.poll() is not None or time.time() - t0 > 20:
            err.close()
            print(open(os.path.join(root, "daemon.err")).read(), file=sys.stderr)
            sys.exit("the daemon did not start")
        time.sleep(0.02)
    started = time.time() - t0
    time.sleep(args.settle)
    fig = {"start_seconds": round(started, 3), "after_start": proc_figures(p.pid)}
    modes = {n: oct(stat.S_IMODE(os.stat(s).st_mode)) for n, s in socks.items()}
    img = os.path.join(images, "base.qcow2")
    sha = hashlib.sha256(open(img, "rb").read()).hexdigest()
    results, qids, lics, runs = [], [], [], []
    steps = readonly_script(root) if args.from_host else script(img, sha)
    for who, method, path, body in steps:
        for i, q in enumerate(qids):
            path = path.replace("{q%d}" % (i + 1), q)
        for i, l in enumerate(lics):
            path = path.replace("{lic%d}" % (i + 1), l)
        if method == "CONTAIN":
            open(os.path.join(root, "contained"), "w").close()
            continue
        if method == "UNCONTAIN":
            os.unlink(os.path.join(root, "contained"))
            continue
        if method == "SLEEP":
            time.sleep(1.5)
            continue
        if method == "NFLOG":
            nflog_traffic()
            time.sleep(0.5)
            continue
        if method == "WAIT":
            if not runs:
                continue
            rid = runs[-1]
            route = "/v1/runs/" + rid
            for _ in range(600):
                st, hd, pl = http(socks[who], "GET", route, "")
                if st != 200 or json.loads(pl).get("status") != "running":
                    break
                time.sleep(0.05)
            results.append({"who": who, "method": "GET", "path": route, "status": st, "body": pl.decode("utf-8", "replace"),
                            "type": hd.get("content-type", "")})
            continue
        st, hd, pl = http(socks[who], method, path, body)
        text = pl.decode("utf-8", "replace")
        for q in re.findall(r"q-[0-9a-f]{12}", text):
            if q not in qids:
                qids.append(q)
        for l in re.findall(r"lic-[0-9a-f]{8}", text):
            if l not in lics:
                lics.append(l)
        if method == "POST" and path.endswith("runs") and st == 202:
            runs.append(json.loads(text)["id"])
        r = {"who": who, "method": method, "path": path, "status": st, "type": hd.get("content-type", ""), "body": text}
        if "x-limbo-sha256" in hd:
            r["sha256"] = hd["x-limbo-sha256"]
            r["scan"] = hd.get("x-limbo-scan", "")
        results.append(r)
    fig["after_script"] = proc_figures(p.pid)
    fig["script_seconds"] = round(time.time() - t0 - started - args.settle, 3)
    # idle: nothing asked for args.idle seconds
    a = proc_figures(p.pid)
    time.sleep(args.idle)
    b = proc_figures(p.pid)
    fig["idle_seconds"] = args.idle
    fig["idle_cpu_ticks"] = b.get("cpu_ticks", 0) - a.get("cpu_ticks", 0)
    fig["idle_ctx_switches"] = b.get("ctx_switches", 0) - a.get("ctx_switches", 0)
    fig["after_idle"] = b
    p.send_signal(signal.SIGTERM)
    try:
        code = p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
        code = "killed"
    err.close()
    left = sorted(n for n in socks if os.path.exists(socks[n]))
    files = {}
    for dp, dn, fn in os.walk(os.path.join(root, "state")):
        dn.sort()
        for n in sorted(fn):
            full = os.path.join(dp, n)
            if n.endswith(".lock") or "exchange-scratch" in full:
                continue
            rel = os.path.relpath(full, root)
            data = open(full, "rb").read()
            files[rel] = {"mode": oct(stat.S_IMODE(os.stat(full).st_mode)),
                          "data": data.decode("utf-8", "replace") if n.endswith((".json", ".xml", ".jsonl")) or "runs" in rel else hashlib.sha256(data).hexdigest()}
    # (with --from-host the license files hold real keys: they are not put in the report)
    for d in ("instances", "etc-limbo", "limbo/exchange") + (() if args.from_host else ("licenses",)):
        for dp, dn, fn in os.walk(os.path.join(root, d)):
            dn.sort()
            for n in sorted(fn):
                full = os.path.join(dp, n)
                rel = os.path.relpath(full, root)
                data = open(full, "rb").read()
                files[rel] = {"mode": oct(stat.S_IMODE(os.stat(full).st_mode)), "data": data.decode("utf-8", "replace")}
    report = {"results": results, "socket_modes": modes, "exit": code, "sockets_left": left, "figures": fig,
              "stderr": open(os.path.join(root, "daemon.err"), errors="replace").read(),
              "tools": open(os.path.join(root, "tools.log"), errors="replace").read() if os.path.exists(os.path.join(root, "tools.log")) else "",
              "events": open(os.path.join(root, "state", "events.jsonl"), errors="replace").read(),
              "files": files, "qids": qids, "lics": lics, "runs": runs}
    json.dump(report, open(args.report, "w"), indent=1)


def nflog_traffic():
    """Packets from nft rules in this namespace's loopback, logged to Limbo's group with guests' prefixes."""
    rules = """table inet difftest {
  chain out {
    type filter hook output priority 0; policy accept;
    udp dport 9 log prefix "limbo:office:h" group 7213
    udp dport 10 log prefix "limbo:office:d" group 7213
    udp dport 11 log prefix "limbo:web:a" group 7213
    tcp dport 12 log prefix "limbo:web:d" group 7213
    udp dport 13 log prefix "other:x:a" group 7213
  }
}
"""
    subprocess.run(["/usr/bin/nft", "-f", "-"], input=rules.encode(), check=False)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for port in (9, 10, 11, 13):
        for host in ("127.0.0.1", "127.0.0.2", "127.0.0.3"):
            for _ in range(3):
                s.sendto(b"x", (host, port))
    s.close()
    for host in ("127.0.0.1", "127.0.0.4"):
        t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        t.settimeout(0.2)
        try:
            t.connect((host, 12))
        except OSError:
            pass
        t.close()
    # a scan: 25 distinct refused destinations
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(25):
        s.sendto(b"x", ("127.0.1.%d" % (i + 1), 10))
    s.close()


def normalise(rep, root, images):
    """Everything that may differ between two correct runs, made equal: the scratch folder, times, ids, pids."""
    ids = {}

    def idmap(prefix, found):
        for i, x in enumerate(found):
            ids[x] = "%s%0*d" % (prefix, len(x) - len(prefix), i + 1)

    idmap("q-", rep["qids"])
    idmap("lic-", rep["lics"])
    idmap("r", rep["runs"])
    # run ids that only the logs know (refused runs have none; started ones are in rep["runs"])
    text = json.dumps(rep)
    for r in re.findall(r"\br[0-9a-f]{8}\b", text):
        if r not in ids and r != "r00000000":
            ids[r] = "r%08d" % (len(ids) + 1)

    def n(s):
        if not isinstance(s, str):
            return s
        s = s.replace(root, "$ROOT").replace(images, "$IMAGES")
        for k, v in ids.items():
            s = s.replace(k, v)
        s = re.sub(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z", "T", s)
        s = re.sub(r"pid=\d+", "pid=P", s)
        s = re.sub(r'"(mtime_ns|ctime_ns|dev|ino)": \d+', r'"\1": N', s)
        s = re.sub(r"\.(lic|image-proofs|settings)-[0-9a-f]+", r".\1-X", s)
        s = re.sub(r"take-[0-9a-f]+", "take-X", s)
        return s

    def walk(x):
        if isinstance(x, dict):
            return {n(k): walk(v) for k, v in x.items()}
        if isinstance(x, list):
            return [walk(v) for v in x]
        return n(x)

    out = walk({k: rep[k] for k in ("results", "socket_modes", "exit", "sockets_left", "stderr", "tools", "events", "files")})
    # the events log as one line per event, its keys parsed (Go and Rust both write sorted detail keys)
    out["events"] = [l for l in out["events"].split("\n") if l]
    out["tools"] = out["tools"].split("\n")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go")
    ap.add_argument("--rs")
    ap.add_argument("--out")
    ap.add_argument("--idle", type=float, default=30)
    ap.add_argument("--settle", type=float, default=2)
    ap.add_argument("--inner", action="store_true")
    ap.add_argument("--daemon")
    ap.add_argument("--root")
    ap.add_argument("--images")
    ap.add_argument("--report")
    ap.add_argument("--from-host", action="store_true",
                    help="root only: start both daemons from a copy of this computer's Limbo state and only read")
    args = ap.parse_args()
    if args.inner:
        return inner(args)
    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    images = os.path.join(out, "images")
    os.makedirs(images, exist_ok=True)
    os.chmod(images, 0o755)
    write(os.path.join(images, "base.qcow2"), qcow2(10), 0o644)
    reps = {}
    for name, binary in (("go", args.go), ("rs", args.rs)):
        root = os.path.join(out, name)
        build_tree(root, images)
        if args.from_host:
            if os.geteuid() != 0:
                sys.exit("--from-host reads /var/lib/limbo and /etc/limbo: run it as root")
            os.chmod(out, 0o700)
            copy_host_state(root)
        rep = os.path.join(out, name + "-report.json")
        cmd = ["unshare", "-rmn", sys.executable, "-I", os.path.abspath(__file__), "--inner", "--daemon", os.path.abspath(binary),
               "--root", root, "--images", images, "--report", rep, "--idle", str(args.idle), "--settle", str(args.settle)]
        if args.from_host:
            cmd.append("--from-host")
        r = subprocess.run(cmd)
        if r.returncode != 0:
            sys.exit("%s: the run failed" % name)
        reps[name] = json.load(open(rep))
        reps[name + "_norm"] = normalise(reps[name], root, images)
    a, b = reps["go_norm"], reps["rs_norm"]
    diffs = []

    def cmp(path, x, y):
        if type(x) != type(y):
            diffs.append((path, x, y))
        elif isinstance(x, dict):
            for k in sorted(set(x) | set(y)):
                cmp(path + "/" + k, x.get(k), y.get(k))
        elif isinstance(x, list):
            if len(x) != len(y):
                diffs.append((path + " (length %d vs %d)" % (len(x), len(y)), x, y))
            for i, (p, q) in enumerate(zip(x, y)):
                cmp("%s[%d]" % (path, i), p, q)
        elif x != y:
            diffs.append((path, x, y))

    cmp("", a, b)
    json.dump({"go": a, "rs": b, "diffs": [{"at": p, "go": x, "rs": y} for p, x, y in diffs]}, open(os.path.join(out, "differential.json"), "w"), indent=1)
    fig = {k: reps[k]["figures"] for k in ("go", "rs")}
    json.dump(fig, open(os.path.join(out, "figures.json"), "w"), indent=1)
    print("requests: %d, events: %d (go) %d (rs), host commands: %d, state files: %d" % (
        len(a["results"]), len(a["events"]), len(b["events"]), len(a["tools"]), len(a["files"])))
    for k in ("go", "rs"):
        f = fig[k]
        print("%s: start %.2fs; after start %s PSS %s, threads %s; after the script %s PSS %s; idle %ss: %d CPU ticks, %d context switches" % (
            k, f["start_seconds"], f["after_start"].get("VmRSS"), f["after_start"].get("Pss"), f["after_start"].get("Threads"),
            f["after_script"].get("VmRSS"), f["after_script"].get("Pss"), f["idle_seconds"], f["idle_cpu_ticks"], f["idle_ctx_switches"]))
    if diffs:
        print("%d DIFFERENCES (details in %s):" % (len(diffs), os.path.join(out, "differential.json")))
        for p, x, y in diffs[:40]:
            print("  %s\n    go: %r\n    rs: %r" % (p, str(x)[:300], str(y)[:300]))
        sys.exit(1)
    print("NO DIFFERENCE: answers, events, host commands and state files are identical once normalised")


if __name__ == "__main__":
    main()
