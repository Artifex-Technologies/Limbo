# CLAUDE.md — Limbo

Seamless Windows and Linux guest apps on a Linux host, sandboxed, aimed at
network/infrastructure security analysis and reporting. Read
`docs/ARCHITECTURE.md` before making design decisions; it records the
reasoning and what is unverified.

## State

Go module, stdlib only. First slice built (see `docs/ARCHITECTURE.md` §12 for the
per-package verification table and known weaknesses). Nothing has been run
against real libvirt or a live guest.

```bash
go vet ./... && go test ./...      # works on Windows or Linux
```

**Run on a real Linux host (Labyrinth OS, 2026-10-14):** `go vet` and `go test ./...` pass natively, and
`scripts/integration-linux-guest.sh` passes 43/43 with real guests under libvirt/KVM. That run found two defects
unit tests could not: a host firewall that drops by default (UFW, enabled on Labyrinth OS) starved the guest of
DHCP because Limbo's table cannot override someone else's drop, now handled by `internal/hostfw`; and
`limbo setup` created no groups when run from a bare binary instead of the package. UFW's `route` rules are
deleted with `ufw route delete ...` (not `ufw delete route ...`); the real run caught that too. Not run on this
host yet: the quarantine, chain, Sarina and systemd integration scripts, and any Windows guest.

Development machine was Windows, but the code targets Linux: guest/host paths use
package `path`, not `filepath`. The Arch WSL distro (`wsl -d archlinux`) now has
libvirt 12, QEMU, nftables, xorriso and working nested KVM (`/dev/kvm`), so
real guests can be booted there. A cloud-init Arch base image lives at
`/var/lib/limbo/images/arch-cloudimg.qcow2` (not in git; re-download from
`geo.mirror.pkgbuild.com/images/latest/` if missing).

**Run the real-guest test after any change to `internal/policy`, `internal/virt`
or `internal/engine`** (unit tests and `nft -c` cannot catch what it caught: the
firewall once loaded cleanly and blocked nothing because it matched the wrong
interface):

```bash
wsl -d archlinux -- bash -c "cd /mnt/c/Users/grego/OneDrive/Documentos/GitHub/Limbo && bash scripts/integration-linux-guest.sh"
# LIMBO_IT_MODES="none" limits it to one network mode; LIMBO_IT_BOOT_WAIT=N sets boot wait (x3s)
```

Gotchas when scripting from Windows: Git Bash rewrites `/tmp/...` paths handed to
Windows binaries, and PowerShell expands `$(...)` inside `wsl -- bash -c "..."`;
put anything non-trivial in a script file instead. Tool-written Python/sed that
contains backslash-n in Go source gets turned into a real newline; use the
editor for those lines.

The real-guest tests, each of which has caught defects unit tests could not:

| Script | Covers |
| --- | --- |
| `scripts/integration-linux-guest.sh` | boot in each network mode, what the firewall allows, two guests cannot reach each other, teardown |
| `scripts/integration-quarantine.sh` | `limbo serve`, socket permissions with real unprivileged users, quarantine lifecycle, verdicts, validation runs |
| `scripts/integration-chain.sh` | real guest + real daemon + real `heimdalld` (unprivileged) + Sarina's real service behind a fake model |
| `scripts/integration-sarina.sh` | Sarina's real agent loop and real service (fake model that issues scripted tool calls) driving real validation runs: tool schema, permission gate, allowlist, untrusted labelling of results |
| `scripts/integration-systemd.sh` | the real unit files and their hardening, as the packages install them (installs and removes files; test machine only) |

Run the first three after changing `internal/policy`, `internal/virt`,
`internal/engine`, `internal/api`, `internal/runs` or `internal/quarantine`.

Tooling traps seen here (all cost time): the Bash tool and shell heredocs turn
`\n` and `\u...` inside scripted edits into real newlines/characters, which
breaks Go and Python source; use the Write tool for files that contain escapes,
and the Edit tool for single lines. Never leave a raw invisible character
(bidi override, zero-width) in source: write it as an escape. `limbo report`'s
tests do exactly that.

Other Claude sessions work in the sibling repos at the same time (check with
ListAgents). In any repo other than this one, **stage by explicit path, never
`git add -A` / `git add .` / `git commit -a`**: doing exactly that once committed
another session's uncommitted files and deletions in Sarina (undone within minutes,
nothing lost). Check `git status` first and leave what is not yours alone.

Commit per logical section, with the Co-Authored-By trailer.

## Rules that matter here

- **Sandbox defaults are deny-first.** No shared folders, no LAN access, no
  clipboard/USB by default. Any convenience that widens the boundary is an
  explicit per-app profile setting, never a default.
- **Automated actors may restrict, never loosen.** Heimdall reaches Limbo only
  through `control.sock`, which has no route to release a guest, lift a hold,
  lower a level, tear a guest down or give a verdict; Sarina only through
  `agent.sock`. Each socket has its own route table, so a forbidden action does
  not exist there rather than being checked and refused. Never add a loosening
  route to `control.sock` or `agent.sock`, and never let a verdict happen
  without an audit record. `internal/api/api_test.go` pins the route tables.
- **Text from a guest, or from a model reading guest data, is untrusted
  everywhere it is shown** (CLI, report, API). Bound it, strip control
  characters, label it. An advisory never changes state.
- **Wine is not a security boundary.** The Wine backend must not run without
  bubblewrap-style confinement.
- **No macOS guests.** Limbo is a Linux project; don't add macOS tooling.
- **Windows is license-gated.** Never download, bundle or auto-install Windows.
  Windows code paths require a user-supplied ISO and license, no-op without
  them, and are labelled unverified until run for real. Build and test against
  Linux guests first.
- **CAD/GPU for desktop use is deferred.** Don't start it, and don't claim it works untested.
  The one exception (owner's decision, 2026-10-10) is **PCI passthrough for driver
  testing**: `manifest.devices.pci`, disposable Linux guests only, set by a
  root-owned profile (never by a caller). The host decides, not the profile:
  `internal/hostpolicy` refuses on Chymaera OS unconditionally (hard-coded), and
  allows on Labyrinth OS only for devices in the root-owned
  `/etc/limbo/host-policy.json` `pci_allow`. Any other OS, or any read error, is a
  refusal. Each test window also needs a human: `sudo limbo passthrough approve` (terminal,
  typed "yes", time-limited, refused while host apps use the device; a failed
  rebind blocks passthrough until reboot). That command writes a root file; it
  has no socket route and must never get one. Never add a way for
  `agent.sock`/`control.sock` to choose a device or approve a window.
  **Unverified**: no real VFIO device has been passed through yet. Labyrinth
  (CachyOS-based) must ship `ID=labyrinth` in its os-release; it does not yet.
- **Write our own implementations of what the references do.** Owner's
  decision (2026-10-04): the references are for ideas, not code. Limbo is MPL-2.0
  (owner's decision, 2026-10-05); Bottles and Prism Launcher are GPL-3.0, so copy
  nothing from them (or from any GPL source); build Limbo-specific versions
  instead. Do not add a dependency whose license is incompatible with MPL-2.0
  distribution without asking.
- **README references table** lists what was borrowed from each reference;
  update it when you adopt something, and check licenses before copying code.
- Loopback-only APIs; fail closed on policy errors; never commit real guest
  data, keys, or event logs.

## Ecosystem

Siblings: `Chymaera_OS` (host distro, Arch/Hyprland), `Heimdall`
(Go security daemon), `Sarina` (agent). Heimdall integration is specified in
`docs/ARCHITECTURE.md` §8. Anything that changes a cross-repo contract needs
`CONTRACT:` in the commit message and a matching update in the other repo's
CLAUDE.md. Heimdall currently has no write path into other projects beyond one
narrow exception; Limbo quarantine actions need an explicit decision there
first.

## Coordination Log (newest first)

### 2026-10-10 — Sentry renamed to Heimdall
- Chymaera_Sentry is now Heimdall. Group `limbo-sentry` -> `limbo-heimdall`
  (`limbo.sysusers`, `setup`, `serve`), flag `--sentry-group` -> `--heimdall-group`,
  binary `sentryd` -> `heimdalld`, service/user `chymaera-sentry` -> `heimdall` in the
  integration scripts. Test source strings follow Heimdall's `heimdall:<detector>`.
- Existing hosts need the group renamed (`groupmod -n limbo-heimdall limbo-sentry`).
— Signed: Limbo / Claude Sonnet 5.5

### 2026-10-06 (2) — An invalid profile is no longer silently absent
- `GET /v1/profiles` keeps `profiles` (names) and `details`, and gains
  `skipped`: an array, never null, of `{name, code, reason, remedy}` for every
  profile file that exists but is not offered (`profile_invalid`,
  `image_missing`, `image_mismatch`). `name` is empty unless the file name
  matches the profile-name regexp; `reason` is a fixed sentence (no host path,
  no parser/libvirt text, under 120 chars). At most 20 entries sorted by name,
  then `{"name":"","code":"more","reason":"N more profiles skipped","remedy":
  "see the Limbo log or 'limbo doctor'"}`. Read-only; nothing in it changes policy.
- Mechanism: `internal/runs/profiles_scan.go`. Computed on request (one scan
  feeds profiles, details and skipped). The image checksum is cached by the
  image's size and mtime so listing does not re-hash a multi-GB image. A profile
  whose image is missing or altered now leaves `profiles` too (it could not run
  anyway), so a profile is in exactly one of the two.
- Each failure is written to the events log once (`run.error`,
  `detail.code`, `detail.during="profile scan"`) per file and code; it is
  forgotten when the profile becomes usable, so a regression logs again.
- `limbo doctor` lists skipped profiles (informational, does not change its exit
  status). `RunService` gained `Skipped() any`. Tests in
  `internal/runs/profiles_scan_test.go` (Linux-tagged) and `internal/api/api_test.go`.
- For Sarina: client should render `skipped`; older clients ignore the key.
— Signed: Limbo / Claude Sonnet 5.5

### 2026-10-06 — Agent-socket failures are coded, logged and recoverable
- Every failure on `agent.sock` now carries a stable `code`, a plain `message`
  and a one-line `remedy`, and the legacy `error` field is the single line
  `<code>: <message>. Remedy: <hint>` because Sarina's Go client
  (`Sarina/go/limbo`) shows only `error` to the model. Codes: `bad_request`,
  `profile_invalid`, `profile_unknown`, `busy` (HTTP 429), `image_missing`,
  `image_mismatch`, `boot_failed`, `boot_timeout`, `command_timeout`,
  `guest_killed`, `host_resources`, `virt_unavailable`, `run_failed`,
  `run_unknown`, plus informational `output_truncated` and `teardown_failed` on
  a normal `done` result. A command's non-zero exit stays a plain result (no
  code); only Limbo's own failure is an error. New event `run.error` (and `code`
  on `run.end`); `docs/EVENTS.md` updated (additive).
- Leak fixes: a run whose teardown fails keeps its `state/runs/<id>` directory
  as a marker, and `limbo serve` now reaps such leftovers (and guests orphaned
  by a crash/restart) at startup. Guest output is made valid UTF-8 with control
  characters removed before it is published.
- Runbook: `docs/INTEGRATION-FAILURES.md`. Tests: `internal/runs/failures_test.go`,
  `internal/api/agent_errors_test.go` (fakes only; run `GOOS=linux`, the runs
  tests are Linux-tagged). Not exercised against a real guest.
- Sarina-side observations (not edited): the client renders only `error` and
  ignores `code`/`remedy` (fine now, since `error` embeds both); it renders a
  `failed` run as a normal tool result with `error:` text and `Succeeded()`
  false, and a `timeout` run the same way, so the model must read the code; an
  invalid profile is simply missing from `/v1/profiles`, which Sarina reports as
  "no validation profiles" without a reason.
— Signed: Limbo / Claude Sonnet 5.5
