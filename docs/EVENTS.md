# Limbo event log (contract with Heimdall)

Path: `<state-dir>/events.jsonl` (default `~/.local/state/limbo/`; under
`limbo serve`, `/var/lib/limbo/state/`). Append-only, one JSON object per line,
synced after every write. Heimdall reads it and must never write to it.

Permissions under `limbo serve`: mode `0640`, group `limbo-heimdall`, with the
state directory traversable (`x`) but not listable, so Heimdall can open the file
by its exact path and read nothing else. Everything else under the state
directory (quarantine records, manifest copies, evidence) stays root-only.

```json
{"time":"2026-10-04T12:00:00Z","kind":"guest.start","guest":"analysis","detail":{"k":"v"}}
```

`detail` is a flat map of strings. Adding a kind or a detail key is
backwards compatible; renaming or removing either is a contract change and needs
`CONTRACT:` in the commit message plus a matching change in Heimdall.

## Guest lifecycle

| kind | when | detail |
| --- | --- | --- |
| `image.verified` | base image checksum matched | `sha256` |
| `image.rejected` | checksum mismatch; nothing else was touched | `reason` |
| `gate.blocked` | Windows guest lacked ISO/license, or the guest is quarantined | `reason` |
| `guest.define` | before network/domain definition | `os`, `network` |
| `policy.apply` | before the firewall table loads | `table` |
| `guest.start` | before the guest is started | — |
| `app.launch` | before the display client starts | `app` |
| `guest.stop` | before teardown | — |
| `policy.remove` | after the firewall table is removed | — |

Events are written *before* the action they describe, so a crash mid-action
still leaves the intent on record.

## Quarantine and validation runs (docs/QUARANTINE.md)

Every event written by the API server carries `principal` (`admin`, `control`
or `agent`, i.e. which socket was used) and `peer` (`uid=N pid=N`, from
`SO_PEERCRED`) in `detail`. Socket permissions are the access control; these
fields are the evidence of who used them.

| kind | when | detail |
| --- | --- | --- |
| `quarantine.open` | a guest was put under quarantine | `id`, `level`, `reason`, `source` |
| `quarantine.raise` | a level was raised or a hold re-asserted | `id`, `level` |
| `quarantine.advisory` | an opinion (e.g. Sarina's) was attached; changes nothing | `id`, `source` |
| `quarantine.verdict` | a human's decision, or closing a dangerous record | `id`, `verdict` (`safe`/`dangerous`/`closed`), `by`, `note` |
| `policy.restrict` | the guest's firewall was replaced with deny-all | `table` |
| `policy.release` | the manifest's firewall was restored (a `safe` verdict) | `table` |
| `link.down` / `link.up` | the guest's virtual link was cut / restored | `interface` |
| `run.start` | a validation run began (guest name is the run id) | `profile`, `command_sha256`, `command` (first 200 bytes) |
| `run.end` | a validation run finished | `status`, `exit_code`, `code` (when not a plain result), `teardown` (`failed` if cleanup did not finish) |
| `run.error` | a run was refused, failed, timed out, or an orphan was reaped at startup (guest is the run id, or the profile name for a refusal) | `code` (a stable code from docs/INTEGRATION-FAILURES.md), `during` (`startup reap` only) |

**Heimdall treats `policy.restrict` / `policy.release` as informational.** In
particular `policy.release` after a `safe` verdict is not a "policy applied
twice" anomaly. A `quarantine.verdict` is written *before* it takes effect and a
verdict that cannot be logged does not happen.

## Guest network (package flows)

Written by `limbo serve` from what the guests' firewalls log (NFLOG group 7213, rate-limited
in the kernel). Only `limbo serve` writes them; a guest started from the command line while
serve is not running produces none. Every value is a string. Destinations are addresses
the guest chose: data, not names to look up.

| kind | when | detail |
| --- | --- | --- |
| `net.flow` | the first time a guest opens a connection to a destination (allowed by its policy) | `proto` (`tcp`/`udp`/`icmp`/...), `dst`, `dport` (when the protocol has ports), `icmp_type` (ICMP), `verdict` = `allowed`, `scope` (`internet`, `lan`, ...) |
| `net.blocked` | the first time a guest is refused a destination | as `net.flow`, with `verdict` = `dropped` and `scope` one of `host` (addressed to the host itself), `lan` (private, link-local or CGNAT ranges: the LAN and other guests), `loopback`, `ipv6`, `internet` (allowlist mode), `other` |
| `net.anomaly` | a guest's refusals look like probing | `reason` (below), `proto`, `dst`, `dport`, `count` (times since the last report); for `scan` also `window_seconds`, `threshold` |
| `net.capped` | a guest used its budget of 256 distinct `net.flow`/`net.blocked` events; further ones are not written (anomalies still are) | `limit` |

`net.anomaly` reasons, each reported at most once per guest per 10 minutes:

- `host_probe`: TCP or UDP to the host itself, except DNS to the guest's own gateway (a guest
  in `none` or `allowlist` mode asks for DNS it does not get; that is a refusal, not a probe).
- `lan_probe`: anything to private, link-local, CGNAT or loopback addresses (the LAN, the router,
  other guests).
- `scan`: 20 distinct refused destinations (address and port) within a minute.
- `ipv6`: IPv6 sent off the guest's link (a guest has no IPv6; link-local chatter does not count).

"First time" is per guest while `limbo serve` runs; it is forgotten when the guest is torn
down (the name may be reused) and when serve restarts. Heimdall may raise a finding on
`net.anomaly` and restrict the guest through `control.sock`; Limbo itself only reports. Since 2026-11-07 `net.anomaly`
carries `scope` too (`host`, `lan`, `loopback`, `internet` or `other`, as `net.blocked` does), so a reader need not work it
out from `reason`.

## The Settings page (docs/SETTINGS_PAGE.md)

Written by the API server; each carries `principal` (`admin` or `user`) and `peer`.
Informational for Heimdall: none of them loosens a guest Heimdall holds (those
requests are refused before anything is written).

| kind | when | detail |
| --- | --- | --- |
| `instance.request` | a person asked to start or stop a registered instance (engine events follow) | `action` |
| `instance.change` | a person changed an instance's settings, or freed its disk | `changed` (comma-separated keys, or `free_space`) |
| `instance.add` / `instance.remove` | root registered or removed an instance | `owner` / `delete_disk` |
| `settings.change` | root turned the password switch on or off (written before it takes effect; not saved if it cannot be written) | `ask_password` |
| `license.add` / `license.remove` / `license.reveal` / `license.assign` / `license.unassign` | a Windows license was stored, removed, shown in full, or (un)assigned | `id` (never the key) |

## Files leaving a guest (package exchange)

| kind | when | detail |
| --- | --- | --- |
| `exchange.file` | a file left a guest's outbox, scanned clean by ClamAV (written before it is handed out; not handed out if it cannot be written) | `path` (from the guest: untrusted, control characters replaced, 200 chars), `sha256`, `size`, `scan` |
| `exchange.held` | ClamAV knew the file: it was moved to `/var/lib/limbo/state/exchange-held/<sha256>` (root-only) and not handed out | `path`, `sha256`, `size`, `signature` |
| `exchange.fail` | the file could not be scanned, so it stayed in the outbox | `path`, `sha256`, `size`, `reason` |

Heimdall may treat `exchange.held` as a finding (the sha256 names the held copy root can
take into Heimdall's immunity quarantine). Nothing in Heimdall consumes these yet.

## The Wine backend (package wine, docs/ARCHITECTURE.md section 13)

Written by `limbo wine`, which runs as the person, into the person's own log
(`~/.local/state/limbo/events.jsonl`, or `--state-dir`), not the daemon's. `guest` is
`wine:<prefix>` (`wine` when a refusal comes before a prefix is known); no virtual machine can
have that name. Every event carries `prefix`, `program` (as given: untrusted, control characters
replaced, 200 bytes), `via` (`cli`, or `path` for Limbo's `wine` on PATH) and, for `via=path`,
`parent` (the calling program's name, such as `winetricks`).

| kind | when | detail |
| --- | --- | --- |
| `wine.setup` | before a prefix is made, or its Windows version set | `run`, `step` (`create` or `windows`), `arch` (create), `windows` |
| `wine.start` | before a program's sandbox starts (a run that cannot be logged does not happen) | `run`, `record` (the run's `run.json`), `network` (`none` or `host`), `gpu` (`on`/`off`), `display` (`wayland,x11`, `wayland`, `x11` or `none`), `audio` (`pulse`, `pipewire` or `none`), `share` and `share_rw` (comma-separated paths, `%` and `,` escaped as `%25`/`%2C`), `sha256` (when the program names a host file), `trace` (`on` when traced) |
| `wine.stop` | after the sandbox ended, or a prefix's setup failed | `run`, `record`, `exit_code`, `seconds`, `status` (`exited`, `stopped`, `sandbox_failed`, `setup_failed`), `stopped` (the signal limbo stopped it on), `during`=`setup` and `step` for a setup failure |
| `wine.refused` | `limbo wine` refused to run: as root, without bubblewrap or Wine, a share it will not give, a program outside the sandbox, a busy prefix, a `WINEPREFIX` outside Limbo's prefixes | `reason` |

The run record (`record`) is JSON with the run's whole story: profile and its SHA-256, program,
arguments, the program file's SHA-256, times, status, exit status and what the sandbox was
allowed. Heimdall's `limbo-guest` detector ignores these kinds today.

Not yet emitted (planned): guest-agent health.
