# Contracts with other repositories

What other projects of the Artifex Ecosystem rely on from Limbo, and what Limbo relies on from them. One section per
contract: what, who uses it, where in the code. A change to any of them says `CONTRACT:` in the commit message, changes this
file in the same commit, and is told to the other repository's maintainers. Adding an event kind, a detail key or a JSON
field is backwards compatible; renaming or removing one, or changing a route, mode or group, is not.

## The sockets and their route tables

- **What:** HTTP/1.1 over unix sockets in `/run/limbo/`, each with its own route table, so a forbidden action does not exist on
  a socket rather than being checked and refused. Bodies are JSON, at most 64 KiB, unknown keys refused (400).

  | Socket | Mode | Who |
  | --- | --- | --- |
  | `control.sock` | 0660, group `limbo-heimdall` | Heimdall: open a quarantine, raise its level, attach an advisory, list, `GET /v1/guests/{name}` (200 `{"name","exists":true}` or 404 `{"exists":false}`; a guest whose manifest copy is gone exists while the hypervisor has it, as for a hold, 2026-11-25). No route releases a guest, lifts a hold, lowers a level, tears a guest down or gives a verdict. |
  | `agent.sock` | 0660, group `limbo-agent` | Sarina: `GET /v1/profiles`, `POST /v1/runs`, `GET /v1/runs/{id}` (validation runs in disposable guests). Never quarantines, never a guest it did not create, never a manifest of its choosing. |
  | `user.sock` | 0660, group `limbo-users` | the person and Yggdrasil Settings > Security > Limbo: the figures always; changes to their own guests only while the password switch is off ([SETTINGS_PAGE.md](SETTINGS_PAGE.md)) |
  | `admin.sock` | 0600 root | `sudo limbo ...`, `pkexec limbo ...`: everything, verdicts, licences, `POST /v1/sample-runs` (Heimdall's immunity analysis, run as root), `POST /v1/agent-runs/stop` (Heimdall's containment), `POST /v1/settings/defaults` (a new instance's processors and memory, 2026-11-25; Settings through `pkexec limbo settings defaults`) |

- **Who:** Heimdall (`control.sock`, `admin.sock` from its root units), Sarina (`agent.sock`), Yggdrasil Settings
  (`user.sock`, `pkexec limbo` for root routes). Specs: [QUARANTINE.md](QUARANTINE.md), [SETTINGS_PAGE.md](SETTINGS_PAGE.md),
  [INTEGRATION-FAILURES.md](INTEGRATION-FAILURES.md) (Sarina's error codes), [SAMPLES.md](SAMPLES.md).
- **Where:** `rust/limbo/src/api.rs` (`routes`; tests pin every table), `serve.rs`.
- **An Instance** (`GET /v1/instances`, `limbo settings show --json`; shape in [SETTINGS_PAGE.md](SETTINGS_PAGE.md)) carries
  `network` and, since 2026-11-25, `allow`: the effective allow list (`[{"addr","port","proto"}]`, the manifest's or root's
  override, never null; empty unless `network` is `allowlist`), so Settings edits the list without losing the manifest's
  entries.

## The event log: `events.jsonl`

- **What:** append-only, one JSON object per line with `time`, `kind`, `guest` and a flat, string-valued `detail`. The daemon's
  log is `/var/lib/limbo/state/events.jsonl`, `root:limbo-heimdall` 0640; `limbo wine` writes the person's own
  `~/.local/state/limbo/events.jsonl`. Every kind and key: [EVENTS.md](EVENTS.md).
- **Who:** Heimdall (`limbo-guest`, `limbo-network`, `limbo-exchange` detectors; its responder).
- **Where:** `rust/limbo/src/events.rs`.

## Guest network names

- **What:** a guest's tap is `vl-<guest>` on its bridge `lb-<guest>`. Heimdall's remote-access watch treats exactly that pair
  as Limbo's own and reports any other tunnel.
- **Who:** Heimdall.
- **Where:** `rust/limbo/src/virt.rs` (`tap_name`, `bridge_name`, marked CONTRACT).

## Held files

- **What:** a file leaving a guest's outbox that ClamAV knows is held root-only at
  `/var/lib/limbo/state/exchange-held/<sha256>` (event `exchange.held` names it); Limbo's copy stays.
- **Who:** Heimdall's root side copies it into its immunity store (`heimdalld immunity take-limbo`).
- **Where:** `rust/limbo/src/exchange.rs`.

## The sinkhole's responder

- **What:** in network mode `sinkhole`, `limbo sinkhole-responder` runs per guest as the account `limbo-sinkhole`
  (`/usr/bin/limbo`), bound only to the guest's gateway address (10.213.X.1) on 7253/udp, 7280/tcp and 7281/udp, between the
  events `sinkhole.start` and `sinkhole.stop`. A run's result may carry `sinkhole` (`{"totals":{...},"records":[...]}`, every
  value a string, guest data). [SINKHOLE.md](SINKHOLE.md).
- **Who:** Heimdall (its local-ports watch; the immunity report), Sarina (a run's result).
- **Where:** `rust/limbo/src/sinkhole/`.

## Host policy: the OS's ID

- **What:** device passthrough (PCI and USB) is refused unconditionally when `/etc/os-release` has `ID=lykanos` (or the old
  `chymaera`); on `ID=labyrinth` it follows the root-owned `/etc/limbo/host-policy.json` (`pci_allow`, `usb_allow`,
  `usb_standing`); any other OS or read error is a refusal.
- **Who:** provided by LykanOS and Labyrinth OS (their os-release IDs).
- **Where:** `rust/limbo/src/hostpolicy.rs`.

## Groups and accounts

- **What:** `limbo-heimdall` (Heimdall's service reads the log and reaches `control.sock`; Heimdall's drop-in
  `limbo-integration.conf.example` gives it the group), `limbo-agent` (Sarina's account reaches `agent.sock`), `limbo-users`
  (people who use Settings' Limbo page), `limbo-sinkhole` (the responder). Created by `packaging/arch/limbo.sysusers`.
- **Who:** Heimdall, Sarina, Labyrinth OS's and LykanOS's images, Yggdrasil Settings.
- **Where:** `packaging/arch/limbo.sysusers`.

## Game time (Limbo asks Yggdrasil)

- **What:** `limbo-image-verify.service` (the weekly base-image check) waits while a game runs, through its drop-in
  `limbo-image-verify-gametime.conf`, which asks `/usr/bin/yggdrasil-gametime` only when it exists.
- **Who:** provided by Yggdrasil.
- **Where:** `packaging/arch/limbo-image-verify-gametime.conf`.

## Containment (Limbo reads Heimdall's lock)

- **What:** while Heimdall's lock `/etc/heimdall/contained` exists, Limbo stops the runs Sarina's agents started and refuses
  new ones.
- **Who:** provided by Heimdall (its docs/CONTRACTS.md, "Containment").
- **Where:** `rust/limbo/src/serve.rs`.
