# Limbo in Settings (approved 2026-11-04, backend built 2026-11-05)

Matt's idea (2026-11-04): a Limbo page in Yggdrasil's Settings where the person using the computer decides whether Limbo changes ask
for their password, plus figures such as how much space each instance uses.

Status (2026-11-05): Limbo's side is built and unit-tested (the socket, the switch, instances, licenses, outboxes, the CLI); see
"Protocol" below, which the Settings page is written against. Not yet installed on the owner's PC (it needs the new package and a
restart of `limbo.service`), so `user.sock` has not served a real page yet. The page itself (Rust, Yggdrasil) is another session's
work.

## Today

- Sarina uses Limbo through `agent.sock` (group `limbo-agent`) and Heimdall through `control.sock` (group `limbo-heimdall`). Neither
  needs a password, and this proposal does not change that.
- Everything a person does (`up`, `down`, `analyze`, quarantine verdicts) goes through `admin.sock`, which only root can use, so
  every change needs sudo.
- Since 2026-11-05 there is also `user.sock` for the page (below); with the switch on (the default) it only reads.

## The page

Settings > Security > Limbo (next to Heimdall):

1. **Status:** whether Limbo is installed and running, whether KVM is available, and the total space Limbo uses.
2. **Instances:** one row per guest, showing:
   - its name and system (Linux or Windows);
   - its state (running, stopped or held by quarantine);
   - its disk use (base image plus the guest's own changes);
   - the memory and processors it is given, and whether it has network.

   Start and Stop buttons, and "Free space" for a stopped guest's changes.
3. **Quarantine:** not on this page. Heimdall decides what is held (files on the host, and guests it asks Limbo to restrict), so
   the quarantine screen and the Safe / Dangerous verdict live on Heimdall's page (Settings > Security). That one screen shows held
   files and held guests together. Here, a held guest's row says "held by Heimdall" and links to it. Limbo still keeps a guest's
   verdict record, because it owns the guest, and still requires the password for it (Matt agreed, 2026-11-04).
4. **Ask for my password for Limbo changes:** on by default, which is how Limbo works today. Turning it off or back on always
   asks for the password (pkexec).

## What the switch covers

With the switch **off**, members of a new group `limbo-users` may, through a new `user.sock`:

- start and stop their guests;
- change a guest's processors, memory and disk size;
- change a guest's shared folders, clipboard and devices.

**Always behind the password, whatever the switch says** (recommended):

- quarantine verdicts, and anything that loosens a guest Heimdall restricted (its network, its devices);
- the switch itself;
- adding or removing a person or service from `limbo-users`, `limbo-agent` or `limbo-heimdall`.

The reason: any program running as you can use a socket you can use, including a hostile one. If verdicts did not need the
password, malware in a browser could declare its own sample safe or free a guest Heimdall locked.

## Windows licenses

Matt's addition (2026-11-04): license key management on the same page, for programs that need more of Windows than Wine can give.

What it is for:

- Wine never needs a Windows license, because it rebuilds Windows' functions rather than running Windows.
- A program that does not work under Wine can run in a real Windows guest instead, and a Windows guest needs a license and an
  installation ISO that you supply.
- Limbo already refuses to create a Windows guest without both (`internal/license`). Today that means placing the files by hand.

What the page would do:

- **Add a license:** type the key or choose a file, and give it a name (for example "Windows 11 Pro, from my old PC").
  - It is stored root-only (`/etc/limbo/licenses/`, mode 0600).
  - Adding, removing or showing a key in full asks for the password, whatever the switch says.
  - Elsewhere it appears masked (`XXXXX-...-7K2QF`).
- **Choose the ISO** for Windows guests, which you supply. Limbo never downloads Windows.
- **Assign a license** to a Windows guest, and see which guests use which license.
- **Never:**
  - the key never goes into a log, a report or an alert;
  - it never goes to Sarina or Heimdall through their sockets;
  - it goes to a guest only while that guest's Windows installs.

Whether a key is valid stays between you and Microsoft. Limbo only checks that one was given.

Status: the Windows code in Limbo is written but has never run, so the license part is the last thing to build.

## Figures without a password

The page shows figures (instances, states, disk use, memory) even with the switch on. They come through read-only routes on
`user.sock` (GET only), so looking never needs sudo.

## Later (wanted)

Possible additions:

- per-guest network rules (which hosts a guest may reach);
- snapshots ("go back to how it was yesterday");
- a default memory and processor limit for new guests;
- the audit log in plain words;
- a one-click `limbo report`.

## Decided

- 2026-11-04 (Matt): quarantine verdicts and loosening a restricted guest always need the password, whatever the switch says. The
  quarantine screen belongs with Heimdall.
- 2026-11-04 (Matt): the "Later, if wanted" items are wanted.

## Protocol

This is the contract the Settings page (Yggdrasil, Rust) is written against. Adding a route or a JSON key is compatible; renaming
or removing one is a contract change (`CONTRACT:` in the commit, and a note in Yggdrasil).

### Sockets and who reaches them

| Socket | Mode | Who | What |
| --- | --- | --- | --- |
| `/run/limbo/user.sock` | `0660 root:limbo-users` | the person (members of `limbo-users`) | read the figures; change their guests while the switch is off |
| `/run/limbo/admin.sock` | `0600 root` | root (`sudo`, `pkexec`) | everything on `user.sock`, always, plus the root-only routes below |

`control.sock` (Heimdall) and `agent.sock` (Sarina) have none of these routes. `user.sock` exists only when the `limbo-users` group
does (`sudo limbo setup`, or the package's sysusers file); adding a person to it is `sudo gpasswd -a USER limbo-users` (root only,
never through Limbo; they must log in again).

Each socket speaks HTTP/1.1. Any `Host` works. Bodies are JSON (`Content-Type: application/json`), at most 64 KiB, and **unknown
keys are refused** (400), so a misspelt setting is an error, not ignored. A route that does not exist on a socket answers 404 (or
405 for a wrong method).

The page never needs to speak HTTP: every route has a `limbo` command, and `--json` prints the socket's answer unchanged (on
failure the error object below, on stdout, with exit status 1). As root (`pkexec limbo ...`) the command uses `admin.sock`; otherwise
`user.sock`. `--socket PATH` overrides.

### Errors

Every failure is a JSON object, with an HTTP status:

```json
{"error": "password_required: Limbo changes need the password on this computer. Remedy: use the password: ...",
 "code": "password_required", "message": "Limbo changes need the password on this computer", "remedy": "use the password: ..."}
```

`error` is the one line to show; `code` is what to act on. `message` and `remedy` may be absent for internal errors.

| code | status | meaning | what the page does |
| --- | --- | --- | --- |
| `password_required` | 403 | the switch is on (or its file is unreadable or tampered with) | run the same action as `pkexec limbo ...` |
| `unknown_caller` | 403 | the kernel did not say who is connecting | show the error |
| `not_owner` | 403 | the instance belongs to another account | show "belongs to OWNER"; offer the password |
| `held_by_heimdall` | 409 | Heimdall (or a person) holds the guest | link to Heimdall's page (Settings > Security) |
| `running` | 409 | must be stopped first (start of a running guest, free space, remove) | offer Stop |
| `not_running` | 409 | stop of a stopped guest | refresh |
| `not_an_instance` | 409 | a run or a hand-started guest: shown, not changed here | no buttons on that row |
| `exists` | 409 | instance or license already there | |
| `out_of_range` | 400 | a value outside the bounds (message says which) | show the message next to the field |
| `confirm_required` | 400 | free space without `{"confirm": true}` | ask first |
| `bad_request` | 400 | malformed body, unknown key, bad name | |
| `bad_key` / `bad_name` | 400 | license key not five groups of five; name empty, too long, or containing a key | |
| `not_found` | 404 | no such instance, license or outbox | refresh |
| `start_failed` / `stop_failed` | 500 | libvirt or the firewall refused; message says why | show it; `limbo doctor` |
| `scanner_unavailable` | 503 | ClamAV could not scan: the file stays in the outbox | show it |
| `infected` | 409 | ClamAV knew the file: it was held, not handed out | show it; it is on Heimdall's page once Heimdall takes it |
| `too_large` / `not_a_file` / `copy_failed` | 413/400/500 | outbox file problems | |
| `internal` | 500 | anything else | |

### Read-only routes (both sockets, whatever the switch says)

`GET /v1/status` (`limbo settings show --json` returns this as `status`, together with `instances` and `licenses`):

```json
{"version": "0.1.0-dev", "running": true, "kvm": true, "ask_password": true,
 "space": {"total_bytes": 21474836480, "images_bytes": 8589934592, "guests_bytes": 1073741824,
           "evidence_bytes": 0, "exchange_bytes": 4096},
 "instances": {"total": 3, "running": 1, "held": 0}}
```

`running` is always true when Limbo answers; if the socket is missing or refuses the connection, show "Limbo is not running" (check
`systemctl is-active limbo` and whether `limbo` is installed). `total_bytes` is everything under `/var/lib/limbo` plus base images of
registered instances kept elsewhere; the other figures are parts of it.

`GET /v1/settings` → `{"ask_password": true}`

`GET /v1/instances` → `{"instances": [Instance, ...]}` (never null; registered instances first, then runs and hand-started guests).
`GET /v1/instances/{name}` → `Instance`. An Instance:

```json
{"name": "lab", "kind": "instance", "os": "linux", "state": "running", "running": true,
 "cpus": 2, "memory_mb": 4096, "network": "none",
 "disk": {"base_bytes": 2147483648, "own_bytes": 52428800, "virtual_bytes": 21474836480, "disk_gb": 0},
 "shared_folder": "off", "clipboard": "off", "devices": [], "disposable": false,
 "owner": "matt", "mine": true,
 "hold": null, "held_by_heimdall": false,
 "pending": false, "license": "",
 "overrides": {"cpus": 2}}
```

- `kind`: `instance` (registered; may be changed), `run` (a validation or sample run, Sarina's or Heimdall's), `manual` (started by
  hand with `limbo up`). Only `instance` rows get buttons.
- `state`: `running`, `stopped` or `held`. `held` wins: a held guest may be running or stopped (see `running`).
- `hold`: null, or `{"id": "q-...", "status": "open"|"dangerous", "level": "restrict"|"isolate", "by": "heimdall"|"person",
  "since": "RFC 3339 time"}`. Show "held by Heimdall" (`held_by_heimdall` is `by == "heimdall"`) and link to Heimdall's page.
- `network`: what the manifest gives (`none`, `allowlist`, `internet-only`); a hold cuts it whatever this says. Changing it is not
  offered: it is root's manifest.
- `disk`: `base_bytes` is the base image (shared by every guest built from it, so do not add it up across rows), `own_bytes` the
  guest's own changes (what "Free space" deletes), `virtual_bytes` the size the guest sees (0 if unknown), `disk_gb` the size asked for
  (0: the image's own).
- `shared_folder`: `off`, `read-only` (a host folder root chose, the guest cannot write to it), or `writable` (the guest's outbox;
  see "Files from a guest").
- `mine`: the caller may change it (ownership only; the switch is separate). `owner` is empty when any member may.
- `pending`: changed while running; the change applies at the next start.
- `license`: the id of the Windows license assigned to it, or `""`.
- `overrides`: what was changed from the manifest (keys absent when unchanged).

`GET /v1/licenses` → `{"licenses": [{"id": "lic-1a2b3c4d", "name": "Windows 11 Pro, old PC", "masked": "XXXXX-XXXXX-XXXXX-XXXXX-7K2QF",
"added": "RFC 3339 time", "assigned": ["win11"]}]}`. Keys are always masked here.

`GET /v1/exchange/{guest}` → `{"guest": "lab", "files": [{"path": "report/scan.csv", "size": 1234, "modified": "RFC 3339 time"}],
"unlisted": 0}`. `path` comes from the guest: **untrusted text**; show it as data (no markup, no links). `unlisted` counts entries not
shown (not plain files, names with control or invisible characters, or past 1000).

### Changes (user.sock only while the switch is off; admin.sock always)

| Route | Body | Answer | CLI |
| --- | --- | --- | --- |
| `POST /v1/instances/{name}/start` | none | Instance | `limbo instance start NAME` |
| `POST /v1/instances/{name}/stop` | none | Instance | `limbo instance stop NAME` |
| `POST /v1/instances/{name}/settings` | any of `{"cpus": N, "memory_mb": N, "disk_gb": N, "shared_folder": "on"\|"off", "clipboard": "off"\|"text", "devices": ["0000:03:00.0"]}` | Instance | `limbo instance set NAME --cpus N --memory-mb N --disk-gb N --shared-folder on\|off --clipboard off\|text --devices A,B` |
| `POST /v1/instances/{name}/free-space` | `{"confirm": true}` | `{"freed_bytes": N}` | `limbo instance free-space NAME --yes` |
| `POST /v1/licenses/{id}/assign` | `{"guest": "win11"}` | License (masked) | `limbo license assign ID GUEST` |
| `POST /v1/licenses/{id}/unassign` | `{"guest": "win11"}` | License (masked) | `limbo license unassign ID GUEST` |
| `POST /v1/exchange/{guest}/take` | `{"path": "as listed"}` | the file's bytes (see below) | `limbo exchange take GUEST PATH DEST` |

Bounds (`out_of_range` otherwise): `cpus` 1 to the computer's processor count; `memory_mb` 512 to the computer's memory minus 2048
MiB; `disk_gb` from the disk's current size (rounded up to whole GiB) to 4096, because a disk only grows; `devices` only addresses the
instance's manifest already names (the host's passthrough policy and `sudo limbo passthrough approve` still decide at start);
`shared_folder` `on` gives the manifest's own share, or, if it has none, the guest's outbox. A change to a running guest is saved and
`pending` until its next start. Start, stop and changes are refused with `held_by_heimdall` for a held guest unless root asks; free
space is refused for a held guest whoever asks (its disk is evidence). Licenses can be assigned to Windows instances only.

### Root only (admin.sock; from the page: `pkexec limbo ...`)

| Route | Body | Answer | CLI |
| --- | --- | --- | --- |
| `POST /v1/settings` | `{"ask_password": true\|false}` | `{"ask_password": ...}` | `limbo settings password on\|off` |
| `POST /v1/instances` | `{"manifest": {...}, "owner": "account"}` | Instance | `limbo instance add MANIFEST [--owner USER]` (owner defaults to the sudo/pkexec user) |
| `DELETE /v1/instances/{name}` | `{"delete_disk": false}` | `{"removed": "name"}` | `limbo instance remove NAME [--delete-disk]` |
| `POST /v1/licenses` | `{"name": "...", "key": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"}` | License (masked) | `limbo license add --name NAME`, key on stdin |
| `DELETE /v1/licenses/{id}` | none | `{"removed": "id"}` | `limbo license remove ID` |
| `GET /v1/licenses/{id}/key` | none | `{"id": "...", "key": "..."}` | `limbo license reveal ID` |

Never through Limbo at all: quarantine verdicts on this page (they are Heimdall's page; Limbo's own route stays on `admin.sock`),
loosening a held guest, and group membership.

The switch is the file `/etc/limbo/settings.json` (`{"ask_password": false}`, root's, mode 0644). A missing file means on. A file that
is malformed, not root's, writable by others or a link means on. Changing it is logged before it is saved, and not saved if it cannot
be logged. Turning it on or off always goes through `pkexec`.

A license key is never put on a command line (the process table is readable by every account): the page pipes it to
`pkexec limbo license add --name NAME` on stdin. It is stored in `/etc/limbo/licenses/<id>.json` (folder 0700, file 0600), shown
masked everywhere except `GET /v1/licenses/{id}/key`, never logged (events carry the id only), and never reachable from Heimdall's or
Sarina's sockets. It is meant to reach a guest only while its Windows installs; that installer does not exist yet (no Windows ISO or
license has been available to build it against), so today a key is stored and assigned, never sent anywhere.

### Files from a guest

A guest whose shared folder is `writable` writes into its own outbox, `/var/lib/limbo/exchange/<name>`, which only root can open.
Nothing there reaches the person until it is taken:

1. `POST /v1/exchange/{guest}/take` copies the file into a root-only scratch folder (so the guest cannot change it afterwards).
2. ClamAV scans the copy (`clamdscan --fdpass`, or `clamscan` if clamd is not running).
3. Clean: the answer is `200`, `Content-Type: application/octet-stream`, the file's bytes, `X-Limbo-Sha256: <hex>`,
   `X-Limbo-Scan: clean`; event `exchange.file`. Known to ClamAV: `409 infected`; the file leaves the outbox into a root-only held
   folder (`/var/lib/limbo/state/exchange-held/<sha256>`), event `exchange.held`. Not scanned (ClamAV missing or broken): `503
   scanner_unavailable`, the file stays, event `exchange.fail`.
4. The page (or `limbo exchange take`) writes the bytes where the person chose, as the person, mode 0644, refusing to overwrite or to
   follow a link, and checks the hash.

Taking a file follows the switch, needs ownership on `user.sock`, and is refused for a held guest unless root asks. A writable share
must also be on a host mount with `nosuid,nodev` (the guest's root writes there as the host's root); on a system where
`/var/lib/limbo` is not, "shared folder on" is refused at start with a message saying so.

### Events (docs/EVENTS.md)

`instance.request` (`action` start/stop), `instance.change` (`changed`: the keys, or `free_space`), `instance.add`,
`instance.remove`, `settings.change` (`ask_password`), `license.add` / `license.remove` / `license.reveal` / `license.assign` /
`license.unassign` (`id` only), `exchange.file` / `exchange.held` / `exchange.fail`. Each carries `principal` (`admin` or `user`)
and `peer`.
