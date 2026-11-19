# Network mode `sinkhole`: a sample that calls home reaches a log on this computer

Built 2026-11-18 as phase 1 of R8 in my reference plan (in my private plans, not in this repository). I decided that day that
running a sample in Limbo is in scope (my decision 7 there, and docs/ARCHITECTURE.md section 9, item 1), sinkhole first. Real egress (phase 2,
a throwaway tunnel) is chosen when it is built; until then **a sample run has no route out**.

A guest in mode `sinkhole` sits on its own isolated bridge with no route off the host. Every name it looks up resolves to its
own gateway address, every TCP connection and UDP datagram it sends, to any address, lands on a small responder on the host's
side of that bridge, and the responder writes down what was asked: names, protocol, port, the first bytes, timing. Nothing is
forwarded anywhere, so the far side of a call never sees this computer's address: there is no far side.

It fits sample runs (`limbo analyze`, docs/SAMPLES.md) and app vetting (what does this program try to reach the first time it
runs?). Mode `none` stays for guests that need no network at all.

## How it is wired

| Piece | What it does |
| --- | --- |
| libvirt network (`virt::network_xml`) | Isolated, as mode `none`: no `<forward>`, so libvirt itself also refuses to forward from the bridge. One addition: dnsmasq announces the gateway as the guest's router (`dhcp-option=option:router,10.213.X.1`), because an isolated network otherwise gives no default route and a sample calling an address it carries would fail inside the guest instead of reaching the log. |
| the guest's table (`policy::nft`, `limbo_<guest>`) | A `sinkhole` chain (nat, prerouting, priority -100) on the guest's bridge `lb-<guest>`: DHCP is left alone; IPv4 UDP to port 53, to any address, is redirected to the responder's DNS port 7253; every IPv4 TCP connection to its TCP port 7280; every other IPv4 UDP datagram to its UDP port 7281, with the destination port kept in the packet mark. The input chain accepts only those redirected packets, on the gateway address (`ct status dnat`); everything else to the host goes to `hostblocked` (logged, dropped). The forward chain drops everything from the bridge (`blocked`, logged), as in mode `none`. IPv6 is dropped as in every mode. |
| a hold (quarantine) | Replaces the table with mode `none`'s, as for every guest: the redirect is gone, the guest reaches nothing, not even the sinkhole. A release puts the sinkhole table back. |
| UFW, when it is on (`hostfw`) | Opens DHCP (67/udp) and the responder's three ports on the guest's bridge, which is what UFW sees after the redirect. No route rule: a sinkhole guest is never forwarded. |
| the responder (`limbo sinkhole-responder`, `sinkhole/responder.rs`) | One process per guest, run by `limbo serve` as the account **`limbo-sinkhole`** (the package's sysusers file: no login, no home, no group but its own, owns nothing). Started with an empty environment in `/`, no new privileges, no core files, no file writes (RLIMIT_FSIZE 0), at most 128 descriptors, every descriptor of the daemon closed at exec. It binds **only the guest's gateway address** 10.213.X.1, on 7253/udp, 7280/tcp and 7281/udp, opens no file and writes one JSON line per record to the daemon on a pipe. It refuses to run as root (root inside a test's own user namespace is not root). Threads, no async runtime, at most 32 connections at once. |
| the daemon's side (`sinkhole::Service`) | Starts the responder after the guest's network exists and before its table loads and the guest starts (a responder that does not say it is ready within 5 s fails the start, and the start is undone); stops it at teardown; starts it again at daemon start for a sinkhole guest still running. The responder ends by itself when the daemon's pipe closes. Each line it sends is read as data: only known kinds and keys are kept, every value bounded and escaped again, numbers and addresses checked. |

Only `limbo serve` runs a sinkhole guest (sample and validation runs, the Settings page's guests): it is the one process that
lives as long as the guest. `limbo up` from the command line refuses one with a clear reason, as it refuses a missing account.

### What the responder answers

- **DNS** (UDP, and TCP on port 53): an A (or ANY) question in class IN is answered with the gateway address, TTL 30 s. Every
  other type, AAAA included, gets "no error, no data": the guest has no IPv6, so a resolver falls back to A at once.
- **TCP**: accepted, then read for up to 5 seconds (1.5 s of silence ends it) and at most 4 KiB, or until a whole message is in.
  An HTTP request gets `HTTP/1.1 200 OK` with an empty body. A TLS ClientHello has its server name (SNI) read; no handshake is
  made. Then the connection is closed. The address and port the guest asked for come from the connection's NAT record
  (SO_ORIGINAL_DST).
- **UDP**: each datagram's first bytes and the port it was sent to (from the packet mark, SO_RCVMARK). The address it was sent
  to is not known for UDP. Nothing is sent back.

## What is recorded

Events in the audit log (docs/EVENTS.md "Network mode sinkhole"): `sinkhole.start`, `sinkhole.dns` (once per name and type),
`sinkhole.connect` (each TCP connection; the first datagram per UDP port), `sinkhole.capped` (once, at 256 records per
guest; the rest are counted, not written) and `sinkhole.stop` with the totals. The same records are the `sinkhole` part of a
run's result (`GET /v1/runs/{id}`, on the admin and agent sockets alike), `limbo analyze` prints them after the run's output,
and `limbo report` has a "Sinkhole" section when there are any.

Everything in them that the guest chose (names, bytes, server names, request lines) is **untrusted**: it is printable ASCII
only (any other byte as `\xNN`, a backslash doubled), bounded (first bytes: 512 raw bytes, at most 2,048 characters escaped),
written by the responder that way and checked again by the daemon, and shown labelled as guest data.

## Profiles

- `examples/malware-analysis.json` (the sealed sample profile `limbo analyze` and Heimdall's immunity use): `none` →
  `sinkhole`. A sample run is still sealed (no route out, no sudo, no shared folder, no devices); what changes is that a
  call-home, from the sample or from an analysis tool a crafted file has taken over, now lands in the log instead of failing
  silently. The cost: the guest can reach one more thing on the host, the responder, which is small, unprivileged and bound to
  the guest's own bridge. A sealed profile may be `none` or `sinkhole` (`runs.rs`); a profile that keeps `none` works as
  before.
- `examples/app-vetting.json` (new): the same sealed shape for watching what a program tries to reach the first time it runs,
  for example `sudo limbo analyze --profile app-vetting ./prog 'cp sample /tmp/prog && chmod +x /tmp/prog && timeout 60 /tmp/prog'`.
- Unchanged: `agent-profile.json` (Sarina's agents need no network), `validation-profile.json` and `analysis-linux.json`
  (they need a real destination, given in an allowlist).

## The isolation test (release check)

`sh scripts/netns-sinkhole.sh` (no root; CI runs it on every change) builds `rust/limbo/tests/sinkhole_netns.rs` and runs it
inside a throwaway user and network namespace (`unshare -rn`), so nothing reaches the real network, the real nftables or any
Limbo socket. Three namespaces: a guest (veth into the bridge `lb-sh`, default route via 10.213.7.1), the host (the guest's
real table from `policy::nft`, the real responder started by the real `sinkhole::Service`, forwarding on and a masquerade to
its uplink, the worst case for a host) and an outside (the home router and the internet, 192.0.2.2 and 198.51.100.7, with a
counter of every packet that arrives).

- **sinkhole:** DNS to any server is answered with 10.213.7.1, AAAA with no data; an HTTP request to 198.51.100.7 gets the
  sinkhole's empty 200; a TLS ClientHello, a UDP datagram, a connection to the home router's address and one to the host's
  own all land in the log with the right address, port, server name, request line and first bytes; ICMP and a raw IP protocol
  get no answer. The outside counter does not move.
- **none** (and a held guest, which gets none's table): DNS, HTTP and connections time out, ICMP and raw IP get nothing out. The
  outside counter does not move.
- **internet-only, the control:** the same HTTP request reaches the outside's listener and the ICMP echo is answered; the
  counter moves. So a quiet outside means the rules held, not that the harness could not see a leak. (Checked once by hand
  as well: a sinkhole table that let TCP 80 through failed the test.)

Result 2026-11-18 on my PC (kernel 7.3, nftables 1.1.7): passed. It needs unprivileged user namespaces and the bridge, veth
and nftables NAT modules loaded, which a user namespace cannot load itself (on a host that has run a Limbo guest they are).

## Not verified yet, and limits

- **Not run with a real guest under libvirt.** The table, the responder and the daemon's side are proved in the namespace test
  and by unit tests; libvirt's handling of the `dnsmasq:options` router announcement on an isolated network (libvirt writes an
  empty router option of its own for isolated networks; which one dnsmasq keeps is the open question), UFW on a real host, and
  a real sample run through `limbo serve` are not. If the router option loses, a guest still has DNS through the sinkhole but
  no default route, so calls to hard-coded addresses fail inside the guest instead of reaching the log. The owner steps below
  check it.
- UDP records carry the destination port but not the address; TCP records carry both.
- A sample can tell it is in a sinkhole (every name resolves to one private address, every port answers). That is the nature of
  a sinkhole; phase 2 (real egress through a throwaway tunnel) is the answer when a sample must see the real far side.
- No TLS handshake is made (only the server name is read), so HTTPS payloads are not seen.
- Windows guests are untested in this mode.

## Owner steps (root; on my PC)

```bash
# 1. the package with this change (it brings the limbo-sinkhole account through sysusers), then the daemon, when no run is active
sudo systemctl restart limbo.service
getent passwd limbo-sinkhole                       # the account exists, uid not 0
# 2. my real sample profile to sinkhole (the file has one "mode" key, network.mode)
sudo sed -i 's/"mode": *"none"/"mode": "sinkhole"/' /etc/limbo/validation/malware-analysis.json
sudo grep -n '"mode"' /etc/limbo/validation/malware-analysis.json
# 3. the first real run: a harmless "sample" whose command calls home in every way
printf 'hello\n' > /tmp/harmless.txt
sudo limbo analyze /tmp/harmless.txt 'ip route; getent hosts callhome.example; for h in 198.51.100.7 callhome.example; do timeout 5 bash -c "exec 3<>/dev/tcp/$h/80; printf \"GET /beacon HTTP/1.0\\r\\n\\r\\n\" >&3; head -n 1 <&3"; done'
#    expected: a "default via 10.213.X.1" route, callhome.example -> 10.213.X.1, "HTTP/1.1 200 OK" twice, and the
#    "== sinkhole" list after the output with the DNS question and both connections
# 4. the events
sudo grep '"kind":"sinkhole\.' /var/lib/limbo/state/events.jsonl | tail -n 20
```

If step 3 shows no default route, the router announcement lost to libvirt's own (see above): calls by name still reach the
sinkhole, calls to a bare address do not.
