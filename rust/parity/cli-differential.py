#!/usr/bin/env python3
"""The Go and the Rust socket-client commands (limbo quarantine | settings | instance | license | exchange) on the same
scripted socket, compared.

A fake server listens on a unix socket in a scratch folder, records every request it gets (method, target, Host,
Content-Length, Referer, Transfer-Encoding, the other header names, the body) and answers each with the next raw
response of the case's script (or hangs up). Each case runs the Go binary and then limbo-rs with the same arguments,
environment, stdin, working folder (made afresh with the same files) and script, and compares stdout, stderr, the exit
status, the requests and the files the command left. The answers include what no Limbo daemon sends (redirect chains,
malformed status lines, chunked bodies cut short, JSON of the wrong shape) so the client's error paths are compared
too; not bytes after a complete answer (Go then logs "Unsolicited response received on idle HTTP channel" with a time
stamp, when its read loop happens to see them before the process exits). User-Agent and Accept-Encoding are not compared: the Go transport adds them, limbo-rs does not, no daemon reads
them.

    python3 -I rust/parity/cli-differential.py --go GO_LIMBO --rs LIMBO_RS [--out DIR] [--only SUBSTRING] [--show]

Runs as an ordinary user (no root, no namespaces). Exit status 0 when the two agree on every case.
"""

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

SHA_A = hashlib.sha256(b"hello from the guest\n").hexdigest()


def resp(body=b"", status="200 OK", headers=(), cl=True, proto="HTTP/1.1"):
    if isinstance(body, str):
        body = body.encode()
    h = [f"{proto} {status}"]
    if cl:
        h.append(f"Content-Length: {len(body)}")
    h.extend(headers)
    return ("\r\n".join(h) + "\r\n\r\n").encode() + body


def ok(obj, status="200 OK", headers=()):
    body = obj if isinstance(obj, (str, bytes)) else json.dumps(obj)
    return resp(body, status, ("Content-Type: application/json",) + tuple(headers))


def err(status, error, code=None, extra=None):
    o = {"error": error}
    if code:
        o.update({"code": code, "message": error, "remedy": "try again"})
    if extra:
        o.update(extra)
    return ok(o, status)


def redirect(status, loc):
    return resp(b"", status, (f"Location: {loc}", "Connection: close"))


HANGUP = "hangup"

REC = {
    "id": "q-0123456789ab", "guest": "lab", "reason": "port scan from guest", "source": "heimdall:limbo-guest",
    "level": "isolate", "status": "open", "opened": "2026-11-10T09:00:00.123Z",
    "evidence": {"zeta": "last", "alpha": "first", "mid": "tab\there"},
    "advisory": [{"source": "sarina", "time": "2026-11-10T09:05:00+02:00", "text": "looks like nmap"}],
    "verdict": {"value": "dangerous", "by": "alice", "note": "confirmed", "time": "2026-11-10T10:00:00Z"},
}
REC2 = {"id": "q-2", "guest": "w\u00e9b", "reason": "manual", "source": "human:bob", "level": "restrict", "status": "closed",
        "opened": "0001-01-01T00:00:00Z"}
ROW = {"name": "lab", "kind": "persistent", "os": "linux", "state": "running", "cpus": 2, "memory_mb": 2048,
       "network": "none", "disk": {"own_bytes": 1288490188, "base_bytes": 3 << 30}, "held_by_heimdall": False,
       "owner": "alice", "pending": True}
ROW2 = {"name": "win11-office", "kind": "disposable", "os": "windows", "state": "stopped", "cpus": 8, "memory_mb": 16384,
        "network": "internet-only", "disk": {"own_bytes": 0, "base_bytes": 12 << 30}, "held_by_heimdall": True, "owner": ""}
STATUS = {"version": "0.1.0-dev", "kvm": True, "ask_password": False, "space": {"total_bytes": 5 << 30}, "extra": [1, 2]}
LICS = {"licenses": [{"id": "l-1", "name": "Windows 11 Pro, old PC", "masked": "XXXXX-...-ABCDE", "assigned": ["win11", "lab"]},
                     {"id": "l-2", "name": "spare", "masked": "XXXXX", "assigned": None}]}
MANIFEST = json.dumps({
    "name": "lab", "os": "linux",
    "image": {"path": "/var/lib/limbo/base.qcow2", "sha256": "0" * 64},
    "access": {"user": "analyst"}, "app": {"name": "Wireshark", "exec": "wireshark"},
})


def C(name, args, answers=(), env=None, stdin=b"", files=None, sock=True):
    """One case: `args` after the command, with {S} for the socket and --socket {S} put first when sock is true."""
    return {"name": name, "args": (["--socket", "{S}"] if sock else []) + list(args), "answers": list(answers),
            "env": env or {}, "stdin": stdin, "files": files or {}}


def cases():
    cs = []
    q = lambda name, args, *a, **k: cs.append(dict(C(name, args, *a, **k), cmd="quarantine"))
    s = lambda name, args, *a, **k: cs.append(dict(C(name, args, *a, **k), cmd="settings"))
    i = lambda name, args, *a, **k: cs.append(dict(C(name, args, *a, **k), cmd="instance"))
    lic = lambda name, args, *a, **k: cs.append(dict(C(name, args, *a, **k), cmd="license"))
    x = lambda name, args, *a, **k: cs.append(dict(C(name, args, *a, **k), cmd="exchange"))

    # ---- quarantine ----
    q("q no args", [], sock=False)
    q("q socket only", [])
    q("q list empty", ["list"], [ok([])])
    q("q list two", ["list"], [ok([REC, REC2])])
    q("q list null", ["list"], [ok("null")])
    q("q list error json", ["list"], [err("500 Internal Server Error", "boom")])
    q("q list error text", ["list"], [resp("not json", "500 Internal Server Error")])
    q("q list own reason", ["list"], [resp("", "404 Gone Fishing")])
    q("q list status only", ["list"], [resp("", "418")])
    q("q list bad json", ["list"], [ok("[{")])
    q("q list type error", ["list"], [ok([{"id": 5}])])
    q("q list nested type error", ["list"], [ok([{"id": "a", "evidence": {"k": 1}}])])
    q("q list bad time", ["list"], [ok([{"id": "a", "opened": "yesterday"}])])
    for n, t in enumerate(['yesterday', '2026-13-01T00:00:00Z', '2026-02-30T00:00:00Z', '2026-11-10T9:00:00Z', '2026-11-10T09:00:00,5Z', '2026-11-10T09:00:00+24:00', '2026-11-10T09:00:00+01:60', '2026-11-10T09:00:00+25:00', '2026-11-10T09:00:00', '2026-11-10T09:00:00Zx', '2026-11-10T24:00:00Z', '2026-11-10 09:00:00Z', '2026-11-10T09:00:60Z', '2026-11-10T09:00:00.Z', '20a6-11-10T09:00:00Z', '2026-11-10T09:00:00+0100', '2026-11-10T09:00:00é', '2026-1-10T09:00:00Z', '']):
        q(f"q list time {n}", ["list"], [ok([{"id": "a", "opened": t}])])
    q("q list ERROR key", ["list"], [ok({"ERROR": "upper"}, "400 Bad Request")])
    q("q list error not string", ["list"], [ok({"error": 5}, "400 Bad Request")])
    q("q list empty error", ["list"], [ok({"error": ""}, "403 Forbidden")])
    q("q list trailing data", ["list"], [ok("[] []")])
    q("q show no id", ["show"])
    q("q show", ["show", "q-1"], [ok(REC)])
    q("q show minimal", ["show", "q-2"], [ok(REC2)])
    q("q show space", ["show", "a b"], [ok(REC2)])
    q("q show escape", ["show", "%zz"])
    q("q show percent ok", ["show", "%41%2F"], [ok(REC2)])
    q("q show query", ["show", "a?b=c"], [ok(REC2)])
    q("q show fragment", ["show", "a#frag"], [ok(REC2)])
    q("q show control", ["show", "a\tb"])
    q("q show unicode", ["show", "w\u00e9b\u2028"], [ok(REC2)])
    q("q show dotdot redirect", ["show", "../x"], [redirect("301 Moved Permanently", "/v1/x"), ok(REC2)])
    q("q show null", ["show", "q-1"], [ok("null")])
    q("q show array", ["show", "q-1"], [ok("[]")])
    q("q restrict", ["restrict", "lab"], [ok({"applied": True})], env={"SUDO_USER": "alice"})
    q("q restrict flags", ["restrict", "lab", "--reason", "it <scans> & more", "-level=isolate"],
      [ok({"applied": False, "error": "no such guest"})])
    q("q restrict float", ["restrict", "lab"], [ok({"applied": 1.5, "error": 3})])
    q("q restrict empty obj", ["restrict", "lab"], [ok({})])
    q("q restrict null", ["restrict", "lab"], [ok("null")])
    q("q restrict array", ["restrict", "lab"], [ok("[1]")])
    q("q restrict dup", ["restrict", "lab"], [ok('{"applied":true,"applied":[1,"a",null,{"z":1,"a":2}]}')])
    q("q restrict no guest", ["restrict"])
    q("q restrict too many", ["restrict", "a", "b"])
    q("q restrict no user", ["restrict", "lab"], [ok({"applied": True})], env={"USER": ""})
    q("q verdict bad", ["verdict", "q-1", "maybe"])
    q("q verdict short", ["verdict", "q-1"])
    q("q verdict safe", ["verdict", "q-1", "safe", "--note", "fine, checked"], [ok(REC), ok({"ok": True})],
      env={"SUDO_USER": "alice"})
    q("q verdict dangerous", ["--note=x", "verdict", "q-1", "dangerous"], [ok(REC2), ok("null")])
    q("q verdict conflict", ["verdict", "q-1", "safe"], [ok(REC), err("409 Conflict", "already decided")])
    q("q verdict bad answer", ["verdict", "q-1", "safe"], [ok(REC), ok("")])
    q("q verdict get fails", ["verdict", "q-1", "safe"], [err("404 Not Found", "no such record")])
    q("q close", ["close", "q-1"], [ok("")])
    q("q close fail", ["close", "q-1"], [err("404 Not Found", "no such record")])
    q("q close no id", ["close"])
    q("q unknown", ["frobnicate"])
    q("q help", ["-h"], sock=False)
    q("q bad flag", ["--bogus", "list"])
    q("q flag missing value", ["list", "--note"])
    # the connection
    if not os.path.exists("/run/limbo"):  # never on a host where a real daemon listens
        q("q default socket", ["list"], sock=False)
    cs.append(dict(C("q socket missing", ["--socket", "{D}/nope.sock", "list"], sock=False), cmd="quarantine"))
    cs.append(dict(C("q socket is dir", ["--socket", "{D}", "list"], sock=False), cmd="quarantine"))
    cs.append(dict(C("q socket empty", ["--socket", "", "list"], sock=False), cmd="quarantine"))
    cs.append(dict(C("q socket relative", ["--socket", "nope.sock", "list"], sock=False), cmd="quarantine"))
    cs.append(dict(C("q socket regular file", ["--socket", "f", "list"], sock=False, files={"f": "x"}), cmd="quarantine"))
    cs.append(dict(C("q socket too long", ["--socket", "/" + "a" * 120, "list"], sock=False), cmd="quarantine"))
    cs.append(dict(C("q socket abstract", ["--socket", "@limbo-cli-differential-nothing", "list"], sock=False), cmd="quarantine"))
    q("q hangup", ["list"], [HANGUP])
    q("q partial status", ["list"], [b"HTTP/1.1 200 OK\r\n"])
    q("q garbage", ["list"], [b"garbage\r\n\r\n"])
    q("q bad code", ["list"], [b"HTTP/1.1 2000 OK\r\n\r\n"])
    q("q bad version", ["list"], [b"HTTP/9 200 OK\r\n\r\n"])
    q("q bad header", ["list"], [b"HTTP/1.1 200 OK\r\nNo colon\r\n\r\n"])
    q("q bad length", ["list"], [b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n[]"])
    q("q short body", ["list"], [b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n[]"])
    q("q close delimited", ["list"], [b"HTTP/1.1 200 OK\r\n\r\n" + json.dumps([REC2]).encode()])
    q("q http10", ["list"], [b"HTTP/1.0 200 OK\r\n\r\n[]"])
    q("q chunked", ["show", "q-2"], [b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"id\"\r\n7;x=y\r\n:\"q-2\"}\r\n0\r\n\r\n"])
    q("q chunked cut", ["show", "q-2"], [b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"id\"\r\n"])
    q("q chunked bad", ["show", "q-2"], [b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"])
    q("q gzip te", ["list"], [b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n[]"])
    q("q continue", ["list"], [b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]"])
    q("q 204", ["close", "q-1"], [resp("", "204 No Content")])
    q("q restrict huge number", ["restrict", "lab"], [ok('{"applied":true,"x":[1,{"y":1e400}]}')])
    q("q 304", ["list"], [resp("", "304 Not Modified", cl=False)])
    # redirects
    q("q 302 post", ["restrict", "lab"], [redirect("302 Found", "/v1/q2"), ok({"applied": True})])
    q("q 303 post", ["restrict", "lab"], [redirect("303 See Other", "elsewhere"), ok({"applied": True})])
    q("q 307 post", ["restrict", "lab"], [redirect("307 Temporary Redirect", "/v1/q3?x=1"), ok({"applied": True})])
    q("q 308 post", ["restrict", "lab"], [redirect("308 Permanent Redirect", "http://other/v1/q4"), ok({"applied": True})])
    q("q 301 then 307", ["restrict", "lab"], [redirect("301 Moved Permanently", "/a"), redirect("307 Temporary Redirect", "/b"),
                                              ok({"applied": True})])
    q("q 307 then 301 then 308", ["restrict", "lab"], [redirect("307 Temporary Redirect", "/a"),
                                                       redirect("301 Moved Permanently", "/b"),
                                                       redirect("308 Permanent Redirect", "/c"), ok({"applied": True})])
    q("q redirect 9", ["list"], [redirect("302 Found", f"/r{n}") for n in range(9)] + [ok([])])
    q("q redirect 10", ["list"], [redirect("302 Found", f"/r{n}") for n in range(10)] + [ok([])])
    q("q redirect no location", ["list"], [resp("", "301 Moved Permanently")])
    q("q redirect bad location", ["list"], [redirect("302 Found", "/a%zz")])
    q("q redirect ftp", ["list"], [redirect("302 Found", "ftp://x/y")])
    q("q redirect no host", ["list"], [redirect("302 Found", "http:///nohost")])
    q("q redirect fragment", ["show", "a#f"], [redirect("302 Found", "/b"), ok(REC2)])
    q("q redirect userinfo", ["list"], [redirect("302 Found", "http://u:p@limbo/v1/q"), redirect("302 Found", "/z"), ok([])])
    q("q redirect then hangup", ["list"], [redirect("302 Found", "/x"), HANGUP])
    q("q redirect query only", ["list"], [redirect("307 Temporary Redirect", "?page=2"), ok([])])
    q("q redirect error object", ["close", "q-1"], [redirect("307 Temporary Redirect", "/v1/again"), err("400 Bad Request", "nope")])

    # ---- settings ----
    show = [ok(STATUS), ok({"instances": [ROW, ROW2]}), ok(LICS)]
    s("s no args", [])
    s("s show", ["show"], show)
    s("s show json", ["show", "--json"], show)
    s("s show bare rows", ["show"], [ok(STATUS), ok([ROW]), ok(LICS)])
    s("s show bare rows json", ["-json", "show"], [ok(STATUS), ok([ROW]), ok('{"licenses":null}')])
    s("s show status error", ["show"], [err("503 Service Unavailable", "busy", "busy")])
    s("s show status error json", ["show", "--json"], [err("503 Service Unavailable", "busy", "busy")])
    s("s show status error empty json", ["show", "--json"], [resp("", "503 Service Unavailable")])
    s("s show licenses error", ["show"], [ok(STATUS), ok({"instances": []}), err("500 Internal Server Error", "lic")])
    s("s show instances text", ["show"], [ok(STATUS), ok("oops"), ok(LICS)])
    s("s show instances text json", ["show", "--json"], [ok(STATUS), ok("oops"), ok(LICS)])
    s("s show no instances key", ["show"], [ok(STATUS), ok({"other": 1}), ok(LICS)])
    s("s show status partial", ["show"], [ok({"version": 5, "kvm": True, "Ask_Password": True, "space": {"total_bytes": 1.5}}),
                                         ok({"instances": [{"name": "x", "cpus": "two", "memory_mb": 3}]}), ok(LICS)])
    s("s show status bad", ["show"], [ok("{bad"), ok({"instances": None}), ok(LICS)])
    s("s show html chars json", ["show", "--json"], [ok({"version": "<a&b>", "x": "\u2028"}), ok({"instances": []}), ok({"licenses": []})])
    s("s show spaces json", ["show", "--json"], [ok(' { "version" : "1" } '), ok('{"instances" : [ ] }'), ok({"licenses": []})])
    s("s show instances wrong type", ["show"], [ok(STATUS), ok({"instances": "x"}), ok(LICS)])
    s("s password user sock", ["password", "on"], sock=False)
    s("s password explicit user sock", ["--socket", "/run/limbo/user.sock", "password", "on"], sock=False)
    s("s password on", ["password", "on"], [ok({"ask_password": True})])
    s("s password off json", ["password", "off", "--json"], [ok({"ask_password": False})])
    s("s password refused", ["password", "on"], [err("403 Forbidden", "root only", "forbidden")])
    s("s password refused json", ["password", "on", "--json"], [err("403 Forbidden", "root only", "forbidden")])
    s("s password maybe", ["password", "maybe"])
    s("s password none", ["password"])
    s("s unknown", ["nope"])
    s("s help", ["--help"])

    # ---- instance ----
    i("i no args", [])
    i("i list", ["list"], [ok([ROW, ROW2])])
    i("i list wrapped", ["list"], [ok({"instances": [ROW2]})])
    i("i list json", ["list", "--json"], [ok({"instances": [ROW2]})])
    i("i list error", ["list"], [err("500 Internal Server Error", "broken", "internal")])
    i("i list error json", ["list", "--json"], [err("500 Internal Server Error", "broken", "internal")])
    i("i list bad", ["list"], [ok("5")])
    i("i list field type", ["list"], [ok([{"name": "a", "disk": {"own_bytes": "x"}}])])
    i("i show", ["show", "lab"], [ok(ROW)])
    i("i show json", ["show", "lab", "--json"], [ok(ROW)])
    i("i show no name", ["show"])
    i("i show bad answer", ["show", "lab"], [ok("not json")])
    i("i start", ["start", "lab"], [ok(ROW)])
    i("i stop", ["stop", "lab"], [ok(ROW2)])
    i("i start refused json", ["start", "lab", "--json"], [err("409 Conflict", "held", "held_by_heimdall")])
    i("i start refused", ["start", "lab"], [err("409 Conflict", "held", "held_by_heimdall")])
    i("i set all", ["set", "lab", "--cpus", "4", "--memory-mb", "4096", "--disk-gb", "64", "--shared-folder", "on",
                    "--clipboard", "text", "--devices", "0000:01:00.0, 5059:4040,,", "--network", "allowlist",
                    "--allow", "1.2.3.4:tcp:443, 10.0.0.0/24:udp:53,,[2001:db8::1]:tcp:22"], [ok(ROW)])
    i("i set none", ["set", "lab"], [ok(ROW)])
    i("i set devices empty", ["set", "lab", "--devices", ""], [ok(ROW)])
    i("i set negative", ["set", "lab", "--cpus", "-1", "--memory-mb=0x10"], [ok(ROW)])
    i("i set network only", ["set", "lab", "--network", "none"], [ok(ROW)])
    i("i set allow alone", ["set", "lab", "--allow", "1.2.3.4:tcp:443"])
    i("i set allow bad", ["set", "lab", "--network", "allowlist", "--allow", "1.2.3.4"])
    i("i set allow port", ["set", "lab", "--network", "allowlist", "--allow", "1.2.3.4:tcp:https"])
    i("i set allow sign", ["set", "lab", "--network", "allowlist", "--allow", "a:b:+5,:x:-1"], [ok(ROW)])
    i("i set html", ["set", "lab", "--clipboard", "<text>&"], [ok(ROW)])
    i("i set bad int", ["set", "lab", "--cpus", "two"])
    i("i free-space yes", ["free-space", "lab", "--yes"], [ok({"freed_bytes": 123456})])
    i("i free-space typed", ["free-space", "lab"], [ok({"freed_bytes": 1})], stdin=b"  yes \nmore\n")
    i("i free-space no", ["free-space", "lab"], stdin=b"no\n")
    i("i free-space eof", ["free-space", "lab"], stdin=b"yes")
    i("i free-space empty", ["free-space", "lab"])
    i("i free-space devnull", ["free-space", "lab"], stdin=None)
    i("i free-space json", ["free-space", "lab", "--yes", "--json"], [ok({"freed_bytes": 2})])
    files = {"m.json": MANIFEST, "bad.json": '{"name":"lab"}', "unknown.json": MANIFEST.replace('"os"', '"clipbaord":"x","os"'),
             "dir.json/": None}
    i("i add", ["add", "m.json"], [ok(ROW)], env={"SUDO_USER": "alice"}, files=files)
    i("i add owner", ["add", "m.json", "--owner", "bob"], [ok(ROW)], env={"SUDO_USER": "alice"}, files=files)
    i("i add pkexec root", ["add", "m.json"], [ok(ROW)], env={"PKEXEC_UID": "0"}, files=files)
    i("i add pkexec bad", ["add", "m.json"], [ok(ROW)], env={"PKEXEC_UID": "abc"}, files=files)
    i("i add pkexec unknown", ["add", "m.json"], [ok(ROW)], env={"PKEXEC_UID": "987654"}, files=files)
    i("i add nobody", ["add", "m.json"], [ok(ROW)], files=files)
    i("i add missing", ["add", "nope.json"], files=files)
    i("i add invalid", ["add", "bad.json"], files=files)
    i("i add unknown field", ["add", "unknown.json"], files=files)
    i("i add dir", ["add", "dir.json"], files=files)
    i("i add refused json", ["add", "m.json", "--json"], [err("403 Forbidden", "root only", "forbidden")], files=files)
    i("i remove", ["remove", "lab", "--delete-disk"], [ok({"removed": "lab"})])
    i("i remove keep", ["remove", "lab"], [ok({"removed": "lab", "freed_bytes": 0})])
    i("i remove 307", ["remove", "lab"], [redirect("307 Temporary Redirect", "/v1/instances/lab2"), ok({"removed": "lab2"})])
    i("i remove 301", ["remove", "lab"], [redirect("301 Moved Permanently", "/v1/instances/lab2"), ok({"removed": "lab2"})])
    i("i unknown", ["frob", "x"])
    i("i start user sock", ["start", "lab"], sock=False) if not os.path.exists("/run/limbo") else None
    i("i explicit user sock", ["--socket", "/run/limbo/user.sock", "list"], sock=False) if not os.path.exists("/run/limbo") else None
    i("i start escape", ["start", "%zz"], sock=False)
    i("i start escape user sock", ["--socket", "/run/limbo/user.sock", "start", "%zz"], sock=False)

    # ---- license ----
    lic("l no args", [])
    lic("l list", ["list"], [ok(LICS)])
    lic("l list json", ["list", "--json"], [ok(LICS)])
    lic("l list keys any case", ["list"], [ok({"Licenses": [{"ID": "x", "NAME": "n", "masked": "m", "assigned": ["a"]}]})])
    lic("l list bad", ["list"], [ok({"licenses": [{"id": 1}]})])
    lic("l add", ["add", "--name", "Windows 11 Pro, old PC"], [ok({"id": "l-3"})], stdin=b"ABCDE-12345-FGHIJ\n")
    lic("l add spaces", ["add", "--name", "x"], [ok({"id": "l-3"})], stdin="\u00a0 KEY \u2003\n".encode())
    lic("l add bytes", ["add"], [ok({"id": "l-3"})], stdin=b"K\xff\xfeY<&>\n")
    lic("l add long", ["add"], [ok({"id": "l-3"})], stdin=b"k" * 300)
    lic("l add cut rune", ["add"], [ok({"id": "l-3"})], stdin=b"k" * 255 + "\u00e9".encode())
    lic("l add devnull", ["add"], [ok({"id": "l-3"})], stdin=None)
    lic("l add extra arg", ["add", "x"])
    lic("l add refused", ["add"], [err("400 Bad Request", "not a key", "bad_request")], stdin=b"x\n")
    lic("l remove", ["remove", "l-1"], [ok({"removed": "l-1"})])
    lic("l reveal", ["reveal", "l-1"], [ok({"key": "ABCDE"})])
    lic("l reveal text", ["reveal", "l-1"], [ok("  plain\ttext \n")])
    lic("l assign", ["assign", "l-1", "win11"], [ok({"ok": True})])
    lic("l unassign json", ["unassign", "l-1", "win11", "--json"], [ok({"ok": True})])
    lic("l assign short", ["assign", "l-1"])
    lic("l remove refused", ["remove", "l-9"], [err("404 Not Found", "no such license", "license_unknown")])
    lic("l remove refused json", ["remove", "l-9", "--json"], [err("404 Not Found", "no such license", "license_unknown")])
    lic("l unknown", ["what"])

    # ---- exchange ----
    xf = {"files": [{"path": "report.txt", "size": 2048}, {"path": "we\u00efrd \"name\"\x01", "size": 5 << 20}], "unlisted": 2}
    x("x no args", [])
    x("x list no guest", ["list"])
    x("x list", ["list", "lab"], [ok(xf)])
    x("x list json", ["list", "lab", "--json"], [ok(xf)])
    x("x list empty", ["list", "lab"], [ok({"files": [], "unlisted": 0})])
    x("x list bad", ["list", "lab"], [ok({"files": "x"})])
    x("x list refused", ["list", "lab"], [err("404 Not Found", "no outbox", "no_exchange")])
    x("x unknown", ["frob", "lab"])
    x("x take short", ["take", "lab", "a"])
    body = b"hello from the guest\n"
    good = resp(body, headers=(f"X-Limbo-Sha256: {SHA_A}", "X-Limbo-Scan: clean"))
    x("x take", ["take", "lab", "report.txt", "out.txt"], [good])
    x("x take json", ["take", "lab", "report.txt", "./sub/../out.txt", "--json"], [good], files={"sub/": None})
    x("x take exists", ["take", "lab", "report.txt", "out.txt"], [good], files={"out.txt": "mine"})
    x("x take symlink", ["take", "lab", "report.txt", "out.txt"], [good], files={"out.txt@": "target"})
    x("x take no dir", ["take", "lab", "report.txt", "missing/out.txt"], [good])
    x("x take damaged", ["take", "lab", "report.txt", "out.txt"], [resp(body, headers=("X-Limbo-Sha256: 00",))])
    x("x take no sha", ["take", "lab", "report.txt", "out.txt"], [resp(body)])
    x("x take truncated", ["take", "lab", "report.txt", "out.txt"],
      [b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nX-Limbo-Sha256: " + SHA_A.encode() + b"\r\n\r\nhello"])
    x("x take chunked", ["take", "lab", "report.txt", "out.txt"],
      [b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Limbo-Sha256: " + SHA_A.encode() + b"\r\n\r\n6\r\nhello \r\nf\r\nfrom the guest\n\r\n0\r\n\r\n"])
    x("x take chunked bad", ["take", "lab", "report.txt", "out.txt"],
      [b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nhello X\r\n"])
    x("x take close delimited", ["take", "lab", "report.txt", "out.txt"],
      [b"HTTP/1.1 200 OK\r\nX-Limbo-Sha256: " + SHA_A.encode() + b"\r\n\r\n" + body])
    x("x take refused", ["take", "lab", "virus.exe", "out.exe"], [err("409 Conflict", "ClamAV found Eicar", "infected")])
    x("x take refused json", ["take", "lab", "virus.exe", "out.exe", "--json"], [err("409 Conflict", "ClamAV found Eicar", "infected")])
    x("x take refused text", ["take", "lab", "a", "b"], [resp("nope", "404 Not Found")])
    x("x take refused empty json", ["take", "lab", "a", "b", "--json"], [resp("", "404 Not Found")])
    x("x take 204", ["take", "lab", "a", "b"], [resp("", "204 No Content")])
    x("x take 301", ["take", "lab", "a", "b"], [redirect("301 Moved Permanently", "/v1/exchange/lab/take2"), good])
    x("x take 307", ["take", "lab", "a", "b"], [redirect("307 Temporary Redirect", "/v1/exchange/lab/take2"), good])
    x("x take escape", ["take", "%zz", "a", "b"])
    x("x take hangup", ["take", "lab", "a", "b"], [HANGUP])
    x("x take socket missing", ["--socket", "{D}/none", "take", "lab", "a", "b"], sock=False)
    x("x take scan html", ["take", "lab", "a", "b", "--json"],
      [resp(body, headers=(f"X-Limbo-Sha256: {SHA_A}", "X-Limbo-Scan: <clean&ok>"))])
    return [c for c in cs if c]


class Server:
    """The scripted socket: records requests, answers from the case's list in order."""

    def __init__(self, path, answers):
        self.path = path
        self.answers = list(answers)
        self.requests = []
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(path)
        self.sock.listen(16)
        self.stop = False
        self.t = threading.Thread(target=self.loop, daemon=True)
        self.t.start()

    def loop(self):
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, conn):
        conn.settimeout(10)
        buf = b""
        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    d = conn.recv(65536)
                    if not d:
                        return
                    buf += d
                head, buf = buf.split(b"\r\n\r\n", 1)
                lines = head.split(b"\r\n")
                method, target, version = (lines[0].split(b" ", 2) + [b"", b""])[:3]
                hdrs = {}
                names = []
                for ln in lines[1:]:
                    k, _, v = ln.partition(b":")
                    k = k.decode("latin-1").strip().lower()
                    hdrs.setdefault(k, v.strip().decode("latin-1"))
                    names.append(k)
                n = int(hdrs.get("content-length", "0") or 0)
                while len(buf) < n:
                    d = conn.recv(65536)
                    if not d:
                        break
                    buf += d
                body, buf = buf[:n], buf[n:]
                self.requests.append({
                    "method": method.decode("latin-1"), "target": target.decode("latin-1"), "version": version.decode("latin-1"),
                    "host": hdrs.get("host"), "content-length": hdrs.get("content-length"), "referer": hdrs.get("referer"),
                    "transfer-encoding": hdrs.get("transfer-encoding"), "authorization": hdrs.get("authorization"),
                    "other headers": sorted(set(names) - {"host", "content-length", "referer", "transfer-encoding", "authorization",
                                                          "user-agent", "accept-encoding"}),
                    "body": body.decode("utf-8", "backslashreplace"),
                })
                a = self.answers.pop(0) if self.answers else resp("no answer scripted", "599 Script Ended")
                if a == HANGUP:
                    return
                conn.sendall(a)
                # one answer per connection: the client opens a new one (Go's transport reuses only what stays open)
                return
        except OSError:
            return
        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()

    def close(self):
        self.stop = True
        self.sock.close()
        try:
            os.unlink(self.path)
        except OSError:
            pass


def make_files(work, files):
    for name, content in files.items():
        p = os.path.join(work, name.rstrip("/@"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if name.endswith("/"):
            os.makedirs(p, exist_ok=True)
        elif name.endswith("@"):
            os.symlink(content, p)
        else:
            with open(p, "w") as f:
                f.write(content)


def snapshot(work):
    out = {}
    for root, dirs, fnames in os.walk(work):
        for n in sorted(dirs + fnames):
            p = os.path.join(root, n)
            rel = os.path.relpath(p, work)
            st = os.lstat(p)
            if os.path.islink(p):
                out[rel] = "link -> " + os.readlink(p)
            elif os.path.isdir(p):
                out[rel] = "dir %o" % (st.st_mode & 0o7777)
            else:
                with open(p, "rb") as f:
                    out[rel] = "file %o %s" % (st.st_mode & 0o7777, hashlib.sha256(f.read()).hexdigest()[:16])
    return out


def run_one(binary, case, base):
    work = os.path.join(base, "w")
    sockp = os.path.join(base, "s")
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    make_files(work, case["files"])
    srv = Server(sockp, case["answers"])
    args = [a.replace("{S}", sockp).replace("{D}", base) for a in case["args"]]
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": work, "USER": "tester"}
    env.update(case["env"])
    env = {k: v for k, v in env.items()}
    stdin = case["stdin"]
    try:
        if stdin is None:
            with open(os.devnull, "rb") as dn:
                p = subprocess.run([binary, case["cmd"]] + args, cwd=work, env=env, stdin=dn, capture_output=True, timeout=30)
        else:
            p = subprocess.run([binary, case["cmd"]] + args, cwd=work, env=env, input=stdin, capture_output=True, timeout=30)
        res = {"stdout": p.stdout.decode("utf-8", "backslashreplace"), "stderr": p.stderr.decode("utf-8", "backslashreplace"),
               "exit": p.returncode}
    except subprocess.TimeoutExpired:
        res = {"stdout": "", "stderr": "TIMEOUT", "exit": -1}
    finally:
        srv.close()
    res["requests"] = srv.requests
    res["files"] = snapshot(work)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", required=True)
    ap.add_argument("--rs", required=True)
    ap.add_argument("--out", help="scratch folder (short: the socket lives in it); default a new one in the temp folder")
    ap.add_argument("--only", default="", help="run only the cases whose name contains this")
    ap.add_argument("--show", action="store_true", help="print each case's Go result")
    a = ap.parse_args()
    go, rs = os.path.abspath(a.go), os.path.abspath(a.rs)
    base = a.out or tempfile.mkdtemp(prefix="lcd")
    os.makedirs(base, exist_ok=True)
    if len(os.path.join(base, "s")) >= 100:
        sys.exit(f"{base}: too long for a socket path")
    os.umask(0o022)
    cs = [c for c in cases() if a.only in c["name"]]
    bad = 0
    comparisons = 0
    for c in cs:
        g = run_one(go, c, base)
        r = run_one(rs, c, base)
        diffs = [k for k in ("stdout", "stderr", "exit", "requests", "files") if g[k] != r[k]]
        comparisons += 5
        if a.show:
            print(f"== {c['name']}: {json.dumps(g, indent=1, ensure_ascii=False)}")
        if diffs:
            bad += 1
            print(f"DIFF {c['name']}: {' '.join(c['args'])}")
            for k in diffs:
                print(f"  {k}:\n    go: {json.dumps(g[k], ensure_ascii=False)}\n    rs: {json.dumps(r[k], ensure_ascii=False)}")
    shutil.rmtree(os.path.join(base, "w"), ignore_errors=True)
    print(f"{len(cs)} cases, {comparisons} comparisons (stdout, stderr, exit status, requests, files): "
          + ("NO DIFFERENCE" if bad == 0 else f"{bad} cases differ"))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
