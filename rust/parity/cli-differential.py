#!/usr/bin/env python3
"""The Go and the Rust CLI commands, compared: the socket-client commands (limbo quarantine | settings | instance | license
| exchange) on the same scripted socket, and the manifest commands (version, validate, plan, address, an unknown
command; local_cases) on the same files, limbo report on the same log and records, and limbo analyze (an inbox
here, the scripted socket; analyze_cases), limbo image (records here, the trusted ones under `unshare -r`;
image_cases).

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

Runs as an ordinary user (no root; the image cases that need root's files run under `unshare -r`). Exit status 0 when the two agree on every case.
"""

import argparse
import hashlib
import json
import os
import re
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


HOST_KEY = "ssh-ed25519 " + "A" * 68
WIN_HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtq1lTZ8bS0bYpDn3m0Yy3uKQ0o4m6F1rYqJcVv8hJX limbo-win"


def mf(**over):
    """A manifest (JSON text) from MANIFEST with fields replaced (None drops one)."""
    m = json.loads(MANIFEST)
    for k, v in over.items():
        if v is None:
            m.pop(k, None)
        else:
            m[k] = v
    return json.dumps(m)


WIN = mf(name="win", os="windows", clipboard="text", access={"user": "analyst"},
         app={"name": "Notepad", "exec": "C:\\Windows\\notepad.exe"},
         windows={"iso": "{W}/win.iso", "license_file": "{W}/lic.txt"})


def local_cases():
    """The commands that read a manifest and the files here (cli/local.rs): no socket."""
    cs = []

    def L(name, cmd, args, files=None, env=None, stdin=b"", norm=None):
        cs.append({"name": name if cmd in ("report", "seed") else "m " + name[2:], "cmd": cmd, "args": list(args), "answers": [],
                   "env": env or {}, "stdin": stdin, "files": files or {}, "norm": norm or []})

    lin = {"m.json": MANIFEST}
    pinned = {"m.json": mf(clipboard="text", provision={"host_key": HOST_KEY})}
    L("l no command", None, [])
    L("l version", "version", [])
    L("l version args", "version", ["x", "--bogus"])
    for cmd in ("validate", "plan", "address", "frobnicate", ""):
        L(f"l {cmd} no manifest", cmd, [])
        L(f"l {cmd} missing file", cmd, ["nope.json"])
        L(f"l {cmd} folder", cmd, ["d"], {"d/": ""})
        L(f"l {cmd} help", cmd, ["-h"])
        L(f"l {cmd} bad flag", cmd, ["--bogus", "m.json"], lin)
        L(f"l {cmd} ok", cmd, ["m.json"], lin)
    L("l validate flags", "validate", ["-state-dir", "s", "--iso=x", "-i-know", "--seconds", "5", "-check", "-identity", "k", "m.json"], lin)
    L("l validate after positional", "validate", ["m.json", "--bogus"], lin)
    L("l validate dashdash", "validate", ["--", "-m.json"], {"-m.json": MANIFEST})
    L("l validate seconds bad", "validate", ["--seconds", "x", "m.json"], lin)
    L("l validate seconds range", "validate", ["--seconds", "99999999999999999999", "m.json"], lin)
    L("l validate flag no value", "validate", ["m.json", "-state-dir"][::-1], lin)
    L("l validate bool value", "validate", ["-check=maybe", "m.json"], lin)
    L("l validate state-dir empty value", "validate", ["-state-dir=", "m.json"], lin)
    for n, doc in enumerate([
        "", "{", "[]", "null", "{} {}", MANIFEST + " trailing", MANIFEST + "{", '{"name": 5}', '{"nmae": "x"}',
        mf(name="Bad Name"), mf(os="macos"), mf(image=None), mf(cpus=-1), mf(memory_mb=1 << 40),
        mf(network={"mode": "allowlist", "allow": [{"addr": "192.0.2.0/24", "port": 443, "proto": "tcp"}]}),
        mf(network={"mode": "allowlist", "allow": [{"addr": "not-an-ip"}]}),
        mf(network={"mode": "internet-only"}), mf(network={"mode": "bridge"}),
        mf(clipboard="text"), mf(clipboard="all"), mf(disposable=True), mf(exchange_dir="/tmp/x", exchange_writable=True),
        mf(provision={"host_key": "ssh-rsa AAAA"}), mf(provision={"host_key": HOST_KEY + " with comment"}),
        mf(devices={"usb": ["1234:abcd"]}, disposable=True), mf(devices={"pci": ["0000:01:00.0"]}, disposable=True),
        mf(devices={"usb": ["zz"]}), mf(console_log="/tmp/c.log"), mf(disk_gb=5000), mf(subnet=7),
        WIN, mf(name="w\u00e9b"), "\ufeff" + MANIFEST, '{"name": "a\\u0000b"}',
    ]):
        L(f"l validate doc {n}", "validate", ["m.json"], {"m.json": doc})
        L(f"l plan doc {n}", "plan", ["m.json"], {"m.json": doc})
    L("l plan pinned", "plan", ["m.json"], pinned)
    L("l plan pinned identity", "plan", ["--identity", "/k", "m.json"], pinned)
    L("l plan state-dir", "plan", ["-state-dir", "/var/lib/elsewhere/../st", "m.json"], pinned)
    L("l plan state env", "plan", ["m.json"], pinned, env={"LIMBO_STATE_DIR": "rel/state"})
    L("l plan no home", "plan", ["m.json"], pinned, env={"HOME": None})
    L("l plan home slash", "plan", ["m.json"], pinned, env={"HOME": "/x/y/"})
    L("l plan home dot", "plan", ["m.json"], pinned, env={"HOME": "."})
    L("l plan help home", "plan", ["-help"], env={"HOME": "/h"})
    L("l plan disposable", "plan", ["m.json"], {"m.json": mf(disposable=True, clipboard="text", provision={"host_key": HOST_KEY})})
    L("l plan win no files", "plan", ["m.json"], {"m.json": WIN})
    L("l plan win iso only", "plan", ["m.json"], {"m.json": WIN, "win.iso": "iso"})
    L("l plan win empty lic", "plan", ["m.json"], {"m.json": WIN, "win.iso": "iso", "lic.txt": ""})
    L("l plan win lic folder", "plan", ["m.json"], {"m.json": WIN, "win.iso": "iso", "lic.txt/": ""})
    L("l plan win both", "plan", ["m.json"], {"m.json": WIN, "win.iso": "iso", "lic.txt": "key"})
    L("l plan win iso link", "plan", ["m.json"], {"m.json": WIN, "real.iso": "iso", "win.iso@": "real.iso", "lic.txt": "key"})
    L("l plan win clip off", "plan", ["m.json"], {"m.json": WIN.replace('"clipboard": "text"', '"clipboard": "off"'),
                                                  "win.iso": "iso", "lic.txt": "key"})
    L("l plan win unattended key", "plan", ["m.json"], {"m.json": mf(
        name="win2", os="windows", access={"user": "analyst"}, app={"name": "a,b", "exec": "x y"},
        windows={"iso": "{W}/win.iso", "license_file": "{W}/lic.txt"}, provision={"host_key": WIN_HOST_KEY}),
        "win.iso": "iso", "lic.txt": "key"})
    L("l plan allowlist", "plan", ["m.json"], {"m.json": mf(network={"mode": "allowlist", "allow": [
        {"addr": "192.0.2.10", "port": 443, "proto": "tcp"}, {"addr": "2001:db8::/32", "proto": "udp", "port": 53},
        {"addr": "198.51.100.0/24", "port": 22}]})})
    L("l plan usb", "plan", ["m.json"], {"m.json": mf(devices={"usb": ["1234:abcd"]}, disposable=True)})
    subs = {"lab": 7, "other": 9, "BAD": 3, "big": 300}
    st = ".local/state/limbo/subnets.json"
    L("l address not up", "address", ["m.json"], lin)
    L("l address up", "address", ["m.json"], {"m.json": MANIFEST, st: json.dumps(subs)})
    L("l address state-dir", "address", ["--state-dir", "s", "m.json"], {"m.json": MANIFEST, "s/subnets.json": '{"lab": 254}'})
    L("l address zero", "address", ["m.json"], {"m.json": MANIFEST, st: '{"lab": 0}'})
    L("l address dup", "address", ["m.json"], {"m.json": MANIFEST, st: '{"lab": 4, "lab": 5}'})
    L("l address float", "address", ["m.json"], {"m.json": MANIFEST, st: '{"lab": 4.0}'})
    L("l address bad json", "address", ["m.json"], {"m.json": MANIFEST, st: '{"lab": 4'})
    L("l address wrong type", "address", ["m.json"], {"m.json": MANIFEST, st: '{"lab": 4, "x": "y"}'})
    L("l address array", "address", ["m.json"], {"m.json": MANIFEST, st: "[1]"})
    L("l address folder", "address", ["m.json"], {"m.json": MANIFEST, st + "/": ""})
    L("l address env", "address", ["m.json"], {"m.json": MANIFEST, "e/subnets.json": '{"lab": 33}'}, env={"LIMBO_STATE_DIR": "e"})
    L("l frobnicate state", "frobnicate", ["-state-dir", "x", "m.json"], lin)
    L("l plan non-utf8 manifest", "plan", ["m.json"], {"m.json": mf(app={"name": "W", "exec": "a\u00ffb"})})
    report_cases(L)
    seed_cases(L)
    return cs


def ev(t, kind, guest="lab", **detail):
    e = {"time": t, "kind": kind, "guest": guest}
    if detail:
        e["detail"] = detail
    return json.dumps(e)


LONG_CMD = "echo " + "\u00e9" * 50 + " && " + "x" * 40
EVENTS = "\n".join([
    ev("2026-11-01T10:00:00Z", "guest.start"),
    ev("2026-11-01T09:00:00+02:00", "guest.define"),
    "",
    "   \t",
    "not json",
    '{"time": "2026-11-01T10:00:00Z", "kind": ""}',
    '{"time": "2026-11-01T10:00:00Z", "guest": "lab"}',
    '{"time": "yesterday", "kind": "guest.stop"}',
    '{"time": "2026-11-01T10:00:00Z", "kind": "guest.stop", "detail": {"n": 1}}',
    '{"time": "2026-11-01T10:05:00,5Z", "KIND": "guest.stop", "Guest": "lab", "extra": [1]}\r',
    '{"time": "2026-11-01T10:06:00Z", "kind": "policy.apply", "guest": "lab", "detail": null}',
    '{"time": "2026-11-01T10:07:00Z", "kind": "x", "kind": "policy.remove", "guest": "lab", "detail": {"a": "1", "a": "2"}} ',
    ev("2026-11-02T08:00:00Z", "run.start", "r-1", command="nmap -sV 198.51.100.0/24 | tee `out` *bold* [link](x) <b>"),
    ev("2026-11-02T08:01:00Z", "run.end", "r-1", status="done", exit_code="0"),
    ev("2026-11-02T08:02:00Z", "run.start", "r-2", command=LONG_CMD),
    ev("2026-11-02T08:03:00Z", "run.end", "r-2", status="timeout"),
    ev("2026-11-02T08:04:00Z", "run.start", "r-3", command=""),
    ev("2026-11-02T08:05:00Z", "run.end", "r-3", status="failed", exit_code="2"),
    ev("2026-11-02T08:06:00Z", "run.start", "r-4"),
    ev("2026-11-02T08:07:00Z", "run.end", "r-9", status="done"),
    ev("2026-11-02T08:08:00Z", "run.start", "r-1", command="again"),
    ev("2026-11-03T00:00:00Z", "image.rejected", "", reason="weekly check: changed", path="/var/lib/limbo/images/a.qcow2"),
    ev("2026-11-03T00:01:00Z", "gate.blocked", "w\u00e9b|x", reason="guest is quarantined (q-1, open)"),
    ev("2026-11-03T00:02:00Z", "policy.restrict", "lab", level="restrict", note="tab\there\nnewline\u0007bell\u202eRLO\u200bzw"),
    ev("2026-11-03T00:03:00Z", "policy.release", "lab"),
    ev("2026-11-03T00:04:00Z", "link.down", "lab", why="x" * 170),
    ev("2026-11-03T00:05:00Z", "link.up", "lab", why="\u00e9" * 100),
    ev("2026-10-01T00:00:00Z", "guest.start", "old"),
    ev("0001-01-01T00:00:00Z", "guest.start", "zero"),
    ev("2026-11-03T00:06:00Z", "net.flow", "other", dst="192.0.2.1", bytes="12"),
]) + "\n"


def qrec(id, guest, status, opened, **more):
    r = {"id": id, "guest": guest, "reason": "port scan from guest", "source": "heimdall:limbo-guest", "level": "isolate",
         "status": status, "opened": opened}
    r.update(more)
    return json.dumps(r, indent=2)


QDIR = ".local/state/limbo/quarantine/"
RECS = {
    QDIR + "q-1.json": qrec("q-1", "lab", "open", "2026-11-03T00:00:00Z",
                            evidence={"zeta": "last", "alpha": "first `x` | y", "mid": "tab\there"},
                            advisory=[{"source": "sarina", "time": "2026-11-03T01:00:00+02:00",
                                       "text": "looks like nmap\n```\n# not a heading\n````x\u0007\u202e\n\n"}]),
    QDIR + "q-2.json": qrec("q-2", "w\u00e9b", "safe", "2026-11-02T00:00:00Z",
                            verdict={"value": "safe", "by": "alice", "note": "fine <ok>", "time": "2026-11-02T03:00:00Z"}),
    QDIR + "q-3.json": qrec("q-3", "lab", "dangerous", "2026-11-01T00:00:00Z",
                            verdict={"value": "dangerous", "by": "bob", "note": "", "time": "2026-11-01T05:00:00-05:00"},
                            advisory=[{"source": "a", "time": "2026-11-01T00:00:00Z", "text": ""},
                                      {"source": "b`b", "time": "2026-11-01T00:00:01Z", "text": "````````"}]),
    QDIR + "q-4.json": qrec("q-4", "other", "closed", "2026-10-01T00:00:00Z"),
    QDIR + "q-5.json": qrec("q-5", "other", "stra\u00dfe-\u1f80-\u0149", "2026-09-01T00:00:00Z"),
    QDIR + "notes.txt": "ignored",
    QDIR + "sub.json/": "",
}
ST = ".local/state/limbo/"


def report_cases(L):
    """limbo report: the event log and the quarantine records here, rendered."""
    gen = [(r"Generated \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\.", "Generated NOW.")]
    rel = gen + [(r"since \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\.", "since REL.")]
    full = dict(RECS, **{ST + "events.jsonl": EVENTS})
    L("report empty", "report", [], norm=gen)
    L("report full", "report", [], full, norm=gen)
    L("report guest", "report", ["--guest", "lab"], full, norm=gen)
    L("report guest md", "report", ["-guest=w\u00e9b|x"], full, norm=gen)
    L("report guest none", "report", ["--guest", "nobody"], full, norm=gen)
    for s in ["2026-11-02", "2026-11-03", "2000-01-01", "2026-02-29", "2024-02-29", "2026-13-01", "2026-1-01", "20261-01-01",
              "0000-01-01", "2026-11-02x", "7d", "3650d", "1d", "0d", "-1d", "+2d", " 3d", "\t4d", "\n5d", "\r\n5d", "5xd",
              "99999999999999999999d", "106752d", "24h", "1h30m", "1.5h", ".5h", "1.h", "0", "-24h", "+24h", "0h", "1\u00b5s",
              "1\u03bcs", "1us", "5", "h", "", "d", "1e3h", "9223372036854775807ns", "9223372036854775808ns", "2562047h",
              "2562048h", "1.00000000000000000001h", "\u3000" + "2d", "1d2"]:
        L(f"report since {s!r}", "report", ["--since", s], full, norm=gen if re.fullmatch(r"\d{4}-\d\d-\d\d", s) else rel)
    L("report since then guest", "report", ["--since", "2026-11-02", "--guest", "lab"], full, norm=gen)
    L("report out", "report", ["--out", "r.md"], full, norm=gen)
    L("report out exists", "report", ["--out", "r.md"], dict(full, **{"r.md": "old"}), norm=gen)
    L("report out folder", "report", ["--out", "d"], dict(full, **{"d/": ""}), norm=gen)
    L("report out missing dir", "report", ["--out", "no/r.md"], full, norm=gen)
    L("report positional", "report", ["extra", "--guest", "lab"], full, norm=gen)
    L("report bad flag", "report", ["--bogus"], full, norm=gen)
    L("report help", "report", ["-h"], full, norm=gen)
    L("report flag no value", "report", ["--since"], full, norm=gen)
    L("report state-dir", "report", ["--state-dir", "s"], {"s/events.jsonl": EVENTS}, norm=gen)
    L("report state env", "report", [], {"e/events.jsonl": EVENTS}, env={"LIMBO_STATE_DIR": "e"}, norm=gen)
    L("report state empty", "report", ["--state-dir", ""], {"events.jsonl": EVENTS}, norm=gen)
    L("report events folder", "report", [], {ST + "events.jsonl/": ""}, norm=gen)
    L("report events link loop", "report", [], {ST + "events.jsonl@": "events.jsonl"}, norm=gen)
    L("report state is file", "report", ["--state-dir", "f"], {"f": "x"}, norm=gen)
    L("report quarantine is file", "report", [], {ST + "quarantine": "x"}, norm=gen)
    L("report corrupt record", "report", [], {QDIR + "q-9.json": "{"}, norm=gen)
    L("report corrupt record type", "report", [], {QDIR + "q-9.json": '{"id": 5}'}, norm=gen)
    L("report record bad time", "report", [], {QDIR + "q-9.json": '{"id": "q", "opened": "x"}'}, norm=gen)
    L("report record link to folder", "report", [], {QDIR + "d/": "", QDIR + "l.json@": "d"}, norm=gen)
    L("report record dup id", "report", [], {QDIR + "a.json": qrec("q", "a", "open", "2026-11-01T00:00:00Z"),
                                              QDIR + "b.json": qrec("q", "b", "safe", "2026-11-02T00:00:00Z")}, norm=gen)
    L("report bytes in log", "report", [], {ST + "events.jsonl": b'{"time":"2026-11-01T00:00:00Z","kind":"k\xff\xe2\x82","guest":"g\xc3"}\n'
                                             + b'{"time":"2026-11-01T00:00:01Z","kind":"run.start","guest":"r","detail":{"command":"'
                                             + b"\xe2\x82\xac" * 30 + b'"}}\n'}, norm=gen)
    big = '{"time":"2026-11-01T00:00:00Z","kind":"k","guest":"g","detail":{"x":"%s"}}'
    pad = len(big) - 2
    for n, extra in [("fits", (1 << 20) - 1), ("one over", 1 << 20)]:
        line = big % ("y" * (extra - pad))
        L(f"report line {n}", "report", [], {ST + "events.jsonl": ev("2026-11-01T00:00:00Z", "a") + "\n" + line + "\n"}, norm=gen)
        L(f"report last line {n}", "report", [], {ST + "events.jsonl": line[:-1] + "}"}, norm=gen)
    L("report last line at limit", "report", [], {ST + "events.jsonl": big % ("y" * ((1 << 20) - pad))}, norm=gen)
    L("report last line under limit", "report", [], {ST + "events.jsonl": big % ("y" * ((1 << 20) - 1 - pad))}, norm=gen)
    L("report no home", "report", [], env={"HOME": None}, norm=gen)


def analyze_cases():
    """limbo analyze: the sample copied into an inbox here, the run asked for and polled (every 3 s) on the socket."""
    cs = []
    norm = [(r"\.incoming-\d+", ".incoming-N")]
    base = {"inbox/": "", "sample.bin": "MZ\x00 not really a program\n"}

    def A(name, args, answers=(), files=None, sock=True, inbox=True):
        pre = ["--inbox", "{W}/inbox"] if inbox else []
        c = C(name, pre + list(args), answers, files=dict(base, **(files or {})), sock=sock)
        cs.append(dict(c, cmd="analyze", norm=norm))

    go = ok({"id": "r00000001", "status": "running"}, "202 Accepted")
    done = ok({"id": "r00000001", "status": "done", "stdout": "== triage\nPE32 executable\n", "stderr": "warn: stripped\n",
               "exit_code": 0})
    A("an no args", [], sock=False, inbox=False)
    A("an too many", ["a", "b", "c"])
    A("an bad flag", ["--bogus", "sample.bin"])
    A("an help", ["-h"])
    A("an flag after file", ["sample.bin", "--json"], [go, done])
    A("an missing file", ["nope.bin"])
    A("an file is folder", ["inbox"])
    A("an inbox missing flag", ["--inbox", "{W}/nowhere", "sample.bin"], inbox=False)
    A("an inbox is file", ["--inbox", "{W}/sample.bin", "sample.bin"], inbox=False)
    A("an inbox slash", ["--inbox", "{W}/inbox/", "sample.bin"], [err("400 Bad Request", "no such profile")], inbox=False)
    A("an socket missing", ["--socket", "{D}/none", "sample.bin"], sock=False)
    A("an refused", ["sample.bin"], [err("400 Bad Request", "profile_unknown: no profile \"x\"", "profile_unknown")])
    A("an refused no error", ["sample.bin"], [ok({"id": ""}, "202 Accepted")])
    A("an refused number", ["sample.bin"], [ok({"error": 1.5e21}, "409 Conflict")])
    A("an refused map", ["sample.bin"], [ok({"error": {"b": [1, "x", None], "a": True}}, "409 Conflict")])
    A("an 200 with id", ["sample.bin"], [ok({"id": "r1"})])
    A("an 202 id number", ["sample.bin"], [ok({"id": 5}, "202 Accepted")])
    A("an 202 array", ["sample.bin"], [ok([{"id": "r1"}], "202 Accepted")])
    A("an 202 bad json", ["sample.bin"], [ok('{"id": "r1"', "202 Accepted")])
    A("an 202 empty", ["sample.bin"], [resp("", "202 Accepted")])
    A("an 202 trailing", ["--timeout", "-400", "sample.bin"], [ok('{"id": "r1"} garbage', "202 Accepted")])
    A("an 202 dup id", ["--timeout", "-400", "sample.bin"], [ok('{"id": "r1", "id": "r2"}', "202 Accepted")])
    A("an hangup", ["sample.bin"], [HANGUP])
    A("an post 307", ["--timeout=-400", "sample.bin"], [redirect("307 Temporary Redirect", "/v1/sample-runs2"), go])
    A("an post 301", ["--timeout=-400", "sample.bin"], [redirect("301 Moved Permanently", "/v1/sample-runs2"), go])
    A("an past deadline", ["--timeout", "-400", "-profile", "p<1>&", "sample.bin", "cat sample | xxd <x> & echo é"], [go])
    A("an done", ["sample.bin"], [go, done])
    A("an done json", ["--json", "sample.bin"], [go, done])
    A("an running then done", ["sample.bin"], [go, go, done])
    A("an error", ["sample.bin"], [go, ok({"status": "failed", "stdout": "", "error": "boot_failed: the guest did not boot"})])
    A("an error json", ["-json", "sample.bin"], [go, ok({"status": "failed", "error": "boot_failed"})])
    A("an stdout kinds", ["sample.bin"], [go, ok({"status": "done", "stdout": {"z": 1, "a": [True, None, 2.5e-7]}, "stderr": 7})])
    A("an no stdout", ["sample.bin"], [go, ok({"status": "done"})])
    A("an result not json", ["sample.bin"], [go, resp("<html>oops</html>", "500 Internal Server Error")])
    A("an result not json json", ["--json", "sample.bin"], [go, resp("<html>oops</html>", "500 Internal Server Error")])
    A("an result status number", ["sample.bin"], [go, ok({"status": 1, "stdout": "x"})])
    A("an result hangup", ["sample.bin"], [go, HANGUP])
    A("an not finished", ["--timeout", "-398", "sample.bin"], [go, go, go])
    A("an id escape", ["sample.bin"], [ok({"id": "%zz"}, "202 Accepted")])
    A("an id query", ["sample.bin"], [ok({"id": "a b?c=d#e"}, "202 Accepted"), done])
    A("an command arg", ["--profile", "decompile", "--timeout", "60", "sample.bin", "strings -n 8 sample"], [go, done])
    return cs


FAKE_PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtq1lTZ8bS0bYpDn3m0Yy3uKQ0o4m6F1rYqJcVv8hJX"
# Fakes for the programs seed runs (never the real ones: a real key pair or ISO differs on every run). Files ending in
# "*" are made executable.
FAKE_KEYGEN = r"""#!/bin/sh
PATH=/usr/bin:/bin
f=; c=
while [ $# -gt 0 ]; do
  case "$1" in -f) f=$2; shift ;; -C) c=$2; shift ;; esac
  shift
done
priv='-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----\n'
case "$FAKE_KEYGEN" in
  fail) echo "Saving key \"$f\" failed: Permission denied"; echo "to stderr" >&2; exit 3 ;;
  nopub) printf -- "$priv" > "$f"; exit 0 ;;
  onefield) printf -- "$priv" > "$f"; echo "onefield" > "$f.pub"; exit 0 ;;
  notopenssh) printf -- '-----BEGIN PRIVATE KEY-----\nx\n' > "$f" ;;
  *) printf -- "$priv" > "$f" ;;
esac
printf '%s %s\n' "PUBKEY" "$c" > "$f.pub"
""".replace("PUBKEY", FAKE_PUB)
FAKE_XORRISO = r"""#!/bin/sh
PATH=/usr/bin:/bin
o=; d=; v=
while [ $# -gt 0 ]; do
  case "$1" in -o) o=$2; shift ;; -V) v=$2; shift ;; -as|mkisofs|-J|-r) ;; *) d=$1 ;; esac
  shift
done
if [ "$FAKE_XORRISO" = fail ]; then echo "xorriso : FAILURE : Cannot write '$o'"; echo "and to stderr" >&2; exit 5; fi
(echo "label $v"; cd "$d" && for x in *; do printf '%s %s\n' "$x" "$(wc -c < "$x")"; done) > "$o"
"""


def seed_cases(L):
    """limbo seed: the host key pair (fake ssh-keygen), the cloud-init files or the Windows answer file, the CD (fake
    xorriso)."""
    bins = {"bin/ssh-keygen*": FAKE_KEYGEN, "bin/xorriso*": FAKE_XORRISO, "kg/ssh-keygen*": FAKE_KEYGEN, "empty/": ""}
    env = {"PATH": "{W}/bin"}
    pw = [(r"\A[a-km-zA-HJ-NP-Z2-9]{20}\n\Z", "PW\n"), (r"<Value>[a-km-zA-HJ-NP-Z2-9]{20}</Value>", "<Value>PW</Value>")]
    lin = dict(bins, **{"m.json": MANIFEST})
    pinned = dict(bins, **{"m.json": mf(provision={"ssh_public_key": "ssh-ed25519 AAAAkey me@host", "host_key": FAKE_PUB + " limbo-lab"})})
    other_pin = dict(bins, **{"m.json": mf(provision={"ssh_public_key": "ssh-ed25519 AAAAkey me@host",
                                                       "host_key": "ssh-ed25519 " + "B" * 68})})
    lin_key = dict(bins, **{"m.json": mf(provision={"ssh_public_key": "ssh-ed25519 AAAAkey me@host", "packages": ["nmap", "tcpdump"]},
                                         access={"user": "analyst", "sudo": True})})
    win = mf(name="win", os="windows", access={"user": "analyst"}, app={"name": "Notepad", "exec": "notepad.exe"},
             provision={"ssh_public_key": "ssh-ed25519 AAAAkey me@host"},
             windows={"iso": "{W}/win.iso", "license_file": "{W}/lic.txt"})
    wfiles = dict(bins, **{"m.json": win})
    S = lambda name, args, files, e=None, norm=None: L(name, "seed", args, files, env=dict(env, **(e or {})), norm=norm)
    S("seed no dir", ["m.json"], lin)
    S("seed three args", ["m.json", "out", "x"], lin)
    S("seed linux no key", ["m.json", "out"], lin)
    S("seed linux", ["m.json", "out"], lin_key)
    S("seed linux pinned", ["m.json", "out"], dict(pinned))
    S("seed linux other pin", ["m.json", "out"], other_pin)
    S("seed linux reuse", ["m.json", "out"], dict(pinned, **{"out/ssh_host_ed25519_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nold\n",
                                                             "out/ssh_host_ed25519_key.pub": "  " + FAKE_PUB + "  old comment \n\n"}))
    S("seed linux reuse no pub", ["m.json", "out"], dict(pinned, **{"out/ssh_host_ed25519_key": "x"}))
    S("seed linux private folder", ["m.json", "out"], dict(pinned, **{"out/ssh_host_ed25519_key/": ""}))
    S("seed linux private link", ["m.json", "out"], dict(pinned, **{"out/ssh_host_ed25519_key@": "nowhere"}))
    S("seed linux keygen fails", ["m.json", "out"], pinned, {"FAKE_KEYGEN": "fail"})
    S("seed linux keygen no pub", ["m.json", "out"], pinned, {"FAKE_KEYGEN": "nopub"})
    S("seed linux keygen one field", ["m.json", "out"], pinned, {"FAKE_KEYGEN": "onefield"})
    S("seed linux keygen not openssh", ["m.json", "out"], dict(lin_key), {"FAKE_KEYGEN": "notopenssh"})
    S("seed linux no keygen", ["m.json", "out"], pinned, {"PATH": "{W}/empty"})
    S("seed linux keygen relative", ["m.json", "out"], pinned, {"PATH": "bin"})
    S("seed linux keygen empty path", ["m.json", "out"], pinned, {"PATH": ""})
    S("seed linux keygen by path entry", ["m.json", "out"], pinned, {"PATH": "{W}/empty:{W}/kg"})
    S("seed linux iso", ["--iso", "{W}/seed.iso", "m.json", "out"], pinned)
    S("seed linux iso relative", ["-iso=seed.iso", "m.json", "out"], pinned)
    S("seed linux iso fails", ["--iso", "seed.iso", "m.json", "out"], pinned, {"FAKE_XORRISO": "fail"})
    S("seed linux no xorriso", ["--iso", "seed.iso", "m.json", "out"], pinned, {"PATH": "{W}/kg"})
    S("seed linux xorriso not executable", ["--iso", "seed.iso", "m.json", "out"], dict(pinned, **{"nx/xorriso": FAKE_XORRISO}),
      {"PATH": "{W}/kg:{W}/nx"})
    S("seed linux dir is file", ["m.json", "f"], dict(pinned, **{"f": "x"}))
    S("seed linux dir nested", ["m.json", "a/b/c"], pinned)
    S("seed linux dir under file", ["m.json", "f/b"], dict(pinned, **{"f": "x"}))
    S("seed linux user-data folder", ["m.json", "out"], dict(pinned, **{"out/user-data/": ""}))
    S("seed linux meta-data folder", ["m.json", "out"], dict(pinned, **{"out/meta-data/": ""}))
    S("seed linux after flags", ["m.json", "out", "--iso", "x.iso"], pinned)
    S("seed win fresh", ["m.json", "out"], wfiles, norm=pw)
    S("seed win fresh iso", ["--iso", "{W}/w.iso", "m.json", "out"], wfiles, norm=pw)
    good = "Pa55word-is-long enough"
    S("seed win password", ["m.json", "out"], dict(wfiles, **{"out/windows-password": "  " + good + "\n\n"}))
    S("seed win password xml", ["m.json", "out"], dict(wfiles, **{"out/windows-password": "<a&b>\"quote\" 'é' ok\n"}))
    S("seed win password short", ["m.json", "out"], dict(wfiles, **{"out/windows-password": "short\n"}))
    S("seed win password control", ["m.json", "out"], dict(wfiles, **{"out/windows-password": "long enough \x01 here\n"}))
    S("seed win password long", ["m.json", "out"], dict(wfiles, **{"out/windows-password": "x" * 128}))
    S("seed win password 127", ["m.json", "out"], dict(wfiles, **{"out/windows-password": "é" * 127}))
    S("seed win password bytes", ["m.json", "out"], dict(wfiles, **{"out/windows-password": b"bytes \xff\xfe in a password"}))
    S("seed win password folder", ["m.json", "out"], dict(wfiles, **{"out/windows-password/": ""}))
    S("seed win cd is file", ["m.json", "out"], dict(wfiles, **{"out/windows-password": good, "out/cd": "x"}))
    S("seed win cd file folder", ["m.json", "out"], dict(wfiles, **{"out/windows-password": good, "out/cd/limbo-setup.ps1/": ""}))
    S("seed win iso", ["--iso", "w.iso", "m.json", "out"], dict(wfiles, **{"out/windows-password": good}))
    S("seed win iso fails", ["--iso", "w.iso", "m.json", "out"], dict(wfiles, **{"out/windows-password": good}), {"FAKE_XORRISO": "fail"})
    S("seed win long name", ["m.json", "out"], dict(bins, **{"m.json": win.replace('"win"', '"abcdefghijkl"'),
                                                             "out/windows-password": good}))
    S("seed win no ssh key", ["m.json", "out"], dict(bins, **{"m.json": mf(
        name="win", os="windows", access={"user": "analyst"}, app={"name": "N", "exec": "n.exe"},
        windows={"iso": "{W}/win.iso", "license_file": "{W}/lic.txt"}), "out/windows-password": good}))
    S("seed win private not a key", ["m.json", "out"], dict(wfiles, **{"out/windows-password": good,
                                                                       "out/ssh_host_ed25519_key": "nothing",
                                                                       "out/ssh_host_ed25519_key.pub": FAKE_PUB}))
    S("seed win pub bytes", ["m.json", "out"], dict(wfiles, **{"out/windows-password": good,
                                                               "out/ssh_host_ed25519_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n\xff\n",
                                                               "out/ssh_host_ed25519_key.pub": FAKE_PUB.encode() + b" c\xffomment\n"}))
    S("seed linux pub bytes", ["m.json", "out"], dict(lin_key, **{"out/ssh_host_ed25519_key": b"-----BEGIN OPENSSH PRIVATE KEY-----\n\xff\n",
                                                                  "out/ssh_host_ed25519_key.pub": FAKE_PUB.encode() + b" c\xffomment\n"}))
    S("seed linux pub bytes in key", ["m.json", "out"], dict(lin_key, **{"out/ssh_host_ed25519_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n",
                                                                         "out/ssh_host_ed25519_key.pub": b"ssh-ed25519 \xff\xfe more"}))


def proofs_prep(records, chmods=(), version=1, raw=None, extra=None):
    """A case's prep: the record file written after the case's files exist, each record with the image's real
    signature (device, inode, size, times) unless it overrides them. records: (image name under img/, sha256 or None for
    the file's own, overrides dict)."""

    def prep(work):
        for rel, mode in chmods:
            if not rel.startswith("st"):
                os.chmod(os.path.join(work, rel), mode)
        imgs = []
        for name, sha, over in records:
            p = os.path.join(work, "img", name) if not name.startswith("/") else name
            try:
                st = os.lstat(p)
                sig = {"dev": st.st_dev, "ino": st.st_ino, "size": st.st_size, "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns}
                own = hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.isfile(p) else "0" * 64
            except OSError:
                sig, own = {"dev": 1, "ino": 2, "size": 3, "mtime_ns": 4, "ctime_ns": 5}, "0" * 64
            r = {"path": p}
            r.update(sig)
            r.update({"sha256": sha or own, "hashed_at": "2026-03-08T09:30:00Z"})
            r.update(over)
            imgs.append(r)
        doc = raw if raw is not None else json.dumps({"version": version, "images": imgs, **(extra or {})}, indent=2)
        with open(os.path.join(work, "st", "image-proofs.json"), "w") as f:
            f.write(doc)
        for rel, mode in chmods:
            if rel.startswith("st"):
                os.chmod(os.path.join(work, rel), mode)

    return prep


def image_cases():
    """limbo image list | verify. The trusted record is root's: those cases run under `unshare -r` (uid 0 in a user
    namespace, so the files made here are root's), with --state-dir here and --i-know."""
    cs = []
    norm = [(r"\(hashed in [^)]*\)", "(hashed in T)"), (r'"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z"', '"NOW"'),
            (r'"(dev|ino|mtime_ns|ctime_ns)": \d+', r'"\1": N')]

    def I(name, args, files=None, prep=None, env=None, root=True, state=True):
        pre = (["--state-dir", "st"] if state else []) + (["--i-know"] if root and state else [])
        cs.append({"name": name, "cmd": "image", "args": pre + list(args), "answers": [], "env": env or {}, "stdin": b"",
                   "files": dict({"st/": "", "img/": ""}, **(files or {})), "norm": norm, "prep": prep, "userns": root})

    imgs = {"img/a.qcow2": "base image a\n", "img/b.qcow2": "b" * 3000, "img/c.qcow2": "c", "img/e.qcow2": "e",
            "img/f@": "a.qcow2", "img/g/": "", "img/sub/h.qcow2": "h", "img/big.qcow2": "x" * (5 << 20)}
    good = [("a.qcow2", None, {}), ("big.qcow2", None, {"hashed_at": "2026-11-01T08:59:59Z"})]
    every = good + [
        ("b.qcow2", None, {"mtime_ns": 1, "hashed_at": "2026-11-01T09:00:00Z"}),
        ("c.qcow2", None, {"refused_at": "2026-11-02T00:00:00Z", "found": "f" * 64, "hashed_at": "2026-07-01T23:59:00+00:00"}),
        ("d.qcow2", None, {"hashed_at": "2025-12-31T23:30:00Z"}),
        ("e.qcow2", None, {}), ("f", None, {}), ("g", None, {}), ("sub/h.qcow2", None, {})]
    chm = [("img/e.qcow2", 0o664), ("img/sub", 0o775)]
    I("image no args", [], root=False)
    I("image two args", ["list", "verify"], root=False)
    I("image bogus", ["frob"], root=False)
    I("image bad flag", ["--bogus", "list"], root=False)
    I("image help", ["-h"], root=False)
    I("image list missing", ["list"])
    I("image list missing user", ["list"], root=False)
    I("image list not root's", ["list"], imgs, proofs_prep(good), root=False)
    I("image list root no i-know", ["--state-dir", "st", "list"], state=False)
    I("image list root daemon folder by env", ["list", "--i-know"], env={"LIMBO_STATE_DIR": "{W}/st"}, state=False)
    I("image list", ["list"], imgs, proofs_prep(every, chm))
    for tz in ["UTC", "America/New_York", ":Asia/Kolkata", "", "Bogus/Zone", "<+03>-3", "EST5EDT", "/usr/share/zoneinfo/Australia/Lord_Howe",
               ":/usr/share/zoneinfo/Pacific/Chatham", "/etc/localtime", "/nowhere", "{W}/img/a.qcow2", "../../../../usr/share/zoneinfo/Europe/Paris",
               "Europe/London", "America/Sao_Paulo", None]:
        I(f"image list TZ {tz!r}", ["list"], imgs, proofs_prep(every, chm), env={"TZ": tz} if tz is not None else {})
    I("image list empty", ["list"], imgs, proofs_prep([]))
    I("image list images null", ["list"], imgs, proofs_prep([], raw='{"version": 1, "images": null}'))
    for n, (raw, extra) in enumerate([
            ("", None), ("{", None), ("[]", None), ('{"version": 2, "images": []}', None), ('{"version": 1}', None),
            ('{"version": 1, "images": []} {}', None), ('{"version": 1, "images": []}\n\n  ', None), ('{"version": "1"}', None),
            ('{"version": 1, "images": [{"dev": "x"}]}', None), ('{"version": 1, "images": [{"path": "/a", "size": 1.5}]}', None),
            ('{"version": 1, "images": [{"path": "/a", "Dev": -1}]}', None), ('{"version": 1, "bogus": 1}', None),
            ('{"version": 1, "images": [{"path": "a", "sha256": "' + "0" * 64 + '", "size": 1, "hashed_at": "2026-01-01T00:00:00Z"}]}', None),
            ('{"version": 1, "images": [{"path": "/a/../b", "sha256": "' + "0" * 64 + '", "size": 1, "hashed_at": "2026-01-01T00:00:00Z"}]}', None),
            ('{"version": 1, "images": [{"path": "/a", "sha256": "' + "A" * 64 + '", "size": 1, "hashed_at": "2026-01-01T00:00:00Z"}]}', None),
            ('{"version": 1, "images": [{"path": "/a", "sha256": "' + "0" * 64 + '", "size": -1, "hashed_at": "2026-01-01T00:00:00Z"}]}', None),
            ('{"version": 1, "images": [{"path": "/a", "sha256": "' + "0" * 64 + '", "size": 1}]}', None),
            ('{"version": 1, "images": [{"path": "/a", "sha256": "' + "0" * 64 + '", "size": 1, "hashed_at": "2026-01-01T00:00:00Z", "found": "x"}]}', None),
            ('{"version": 1, "images": [{"path": "/a", "sha256": "' + "0" * 64 + '", "size": 1, "hashed_at": "2026-01-01T00:00:00Z", "found": "' + "1" * 64 + '"}]}', None),
            ('{"version": 1, "images": [{"path": "/a", "sha256": "' + "0" * 64 + '", "size": 1, "hashed_at": "2026-01-01T00:00:00Z"}, {"path": "/a", "sha256": "' + "0" * 64 + '", "size": 1, "hashed_at": "2026-01-01T00:00:00Z"}]}', None),
            ('{"version": 1, "images": [' + ",".join(['{"path": "/a%d", "sha256": "%s", "size": 1, "hashed_at": "2026-01-01T00:00:00Z"}' % (i, "0" * 64) for i in range(1001)]) + ']}', None),
            (" " * ((1 << 20) + 1), None)]):
        I(f"image list damaged {n}", ["list"], imgs, proofs_prep([], raw=raw))
    I("image list record group-writable", ["list"], imgs, proofs_prep(good, [("st/image-proofs.json", 0o664)]))
    I("image list folder group-writable", ["list"], imgs, proofs_prep(good, [("st", 0o775)]))
    I("image list record is folder", ["list"], dict(imgs, **{"st/image-proofs.json/": ""}))
    I("image list record is link", ["list"], dict(imgs, **{"st/real.json": '{"version": 1, "images": []}', "st/image-proofs.json@": "real.json"}))
    I("image list state is file", ["--state-dir", "f", "--i-know", "list"], {"f": "x"}, state=False)
    I("image verify not root", ["verify"], imgs, proofs_prep(good), root=False)
    I("image verify missing", ["verify"])
    I("image verify empty", ["verify"], imgs, proofs_prep([]))
    I("image verify ok", ["verify"], imgs, proofs_prep(good))
    changed = [("a.qcow2", "1" * 64, {}), ("b.qcow2", "2" * 64, {"mtime_ns": 5}),
               ("c.qcow2", "3" * 64, {"refused_at": "2026-11-02T00:00:00Z", "found": hashlib.sha256(b"c").hexdigest()}),
               ("e.qcow2", "4" * 64, {"refused_at": "2026-11-02T00:00:00Z", "found": "5" * 64})]
    I("image verify changed", ["verify"], imgs, proofs_prep(changed))
    I("image verify every kind", ["verify"], imgs, proofs_prep(every, chm))
    I("image verify ignored", ["verify"], imgs, proofs_prep([], raw="{"))
    I("image verify log is folder", ["verify"], dict(imgs, **{"st/events.jsonl/": ""}), proofs_prep(good))
    I("image verify log appended", ["verify"], dict(imgs, **{"st/events.jsonl": '{"time":"2026-01-01T00:00:00Z","kind":"x","guest":""}\n'}),
      proofs_prep(changed))
    I("image verify state folder group-writable", ["verify"], imgs, proofs_prep(changed, [("st", 0o775)]))
    return cs


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
        p = os.path.join(work, name.rstrip("/@*"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if name.endswith("/"):
            os.makedirs(p, exist_ok=True)
        elif name.endswith("@"):
            os.symlink(content, p)
        elif isinstance(content, bytes):
            with open(p, "wb") as f:
                f.write(content)
        else:
            with open(p, "w") as f:
                f.write(content.replace("{W}", work))
        if name.endswith("*"):
            os.chmod(p, 0o755)


def normalize(data, norm):
    """The case's (pattern, replacement) pairs applied: what differs between two runs by design (the time now)."""
    for pat, rep in norm:
        data = re.sub(pat.encode(), rep.encode(), data)
    return data


def snapshot(work, norm=()):
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
                    out[rel] = "file %o %s" % (st.st_mode & 0o7777, hashlib.sha256(normalize(f.read(), norm)).hexdigest()[:16])
    return out


def run_one(binary, case, base):
    work = os.path.join(base, "w")
    sockp = os.path.join(base, "s")
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    make_files(work, case["files"])
    if case.get("prep"):
        case["prep"](work)
    srv = Server(sockp, case["answers"])
    args = [a.replace("{S}", sockp).replace("{D}", base).replace("{W}", work) for a in case["args"]]
    # LIMBO_RS_NO_GO: limbo-rs fails a command it has not ported instead of handing it to a Go limbo
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": work, "USER": "tester", "LIMBO_RS_NO_GO": "1"}
    env.update({k: v.replace("{W}", work) if isinstance(v, str) else v for k, v in case["env"].items()})
    env = {k: v for k, v in env.items() if v is not None}
    argv = [binary] + ([case["cmd"]] if case["cmd"] is not None else []) + args
    if case.get("userns"):
        # uid 0 in a user namespace: the files made here are root's there (no real root)
        argv = [shutil.which("unshare") or "/usr/bin/unshare", "-r"] + argv
    stdin = case["stdin"]
    try:
        if stdin is None:
            with open(os.devnull, "rb") as dn:
                p = subprocess.run(argv, cwd=work, env=env, stdin=dn, capture_output=True, timeout=30)
        else:
            p = subprocess.run(argv, cwd=work, env=env, input=stdin, capture_output=True, timeout=30)
        norm = case.get("norm", [])
        res = {"stdout": normalize(p.stdout, norm).decode("utf-8", "backslashreplace"),
               "stderr": normalize(p.stderr, norm).decode("utf-8", "backslashreplace"),
               "exit": p.returncode}
    except subprocess.TimeoutExpired:
        res = {"stdout": "", "stderr": "TIMEOUT", "exit": -1}
    finally:
        srv.close()
    res["requests"] = srv.requests
    res["files"] = snapshot(work, case.get("norm", []))
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
    cs = [c for c in cases() + local_cases() + analyze_cases() + image_cases() if a.only in c["name"]]
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
