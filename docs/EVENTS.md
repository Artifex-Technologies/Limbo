# Limbo event log (contract with Heimdall)

Path: `<state-dir>/events.jsonl` (default `~/.local/state/limbo/`; under
`limbo serve`, `/var/lib/limbo/state/`). Append-only, one JSON object per line,
synced after every write. Heimdall reads it and must never write to it.

Permissions under `limbo serve`: mode `0640`, group `limbo-sentry`, with the
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

Not yet emitted (planned): guest network destinations, exchange-directory file
hashes, guest-agent health.
