# CLAUDE.md — Limbo

Seamless Windows and Linux guest apps on a Linux host, sandboxed, aimed at
network/infrastructure security analysis and reporting. Read
`docs/ARCHITECTURE.md` before making design decisions; it records the
reasoning and what is unverified.

Push every commit as you make it; don't ask me first. Before pushing, check the
diff names no host name, network address, SSID or MAC address.

## State

Go module, stdlib only. First slice built (see `docs/ARCHITECTURE.md` §12 for the
per-package verification table and known weaknesses). Run against real libvirt
and live guests since 2026-10-14 (latest: 66/66 and 24/24 on 2026-11-05; the
Coordination Log has the details). The Wine backend (`limbo wine`, `internal/wine`, §13) since 2026-11-08: plain
`go test ./...` runs it for real (bwrap + Wine's own `cmd`/`cscript`, headless, about 15 s); `-short` skips that.

**The Rust port of `limbo serve`** (since 2026-11-10, `rust/`, docs/RUST_PORT.md): `limbo-rs serve` is the daemon;
`quarantine`, `settings`, `instance`, `license`, `exchange`, `version`, `validate`, `plan`, `address`, `seed`, `report`,
`analyze`, `image`, `doctor`, `setup`, `up`, `down`, `launch`, `export`, `screenshot`, `passthrough` and `wine` run in Rust too (2026-11-11, `rust/parity/cli-differential.py` compares them
with Go); every other command is handed to the Go binary. Equal to Go on 34,676 fixture comparisons
(`testdata/parity`, written by
each package's `parity_test.go`; `LIMBO_PARITY_UPDATE=1 go test ./internal/... ./cmd/limbo -run Parity` after a deliberate change)
and in a differential run of both daemons (`rust/parity/daemon-differential.py`). A change to a serve package now
needs its fixture regenerated and the Rust side kept equal (`cd rust && scripts/nicecargo.sh test --offline`). Switched
by hand on 2026-11-10 (a drop-in); since 2026-11-11 the package ships it: `/usr/bin/limbo` is limbo-rs (the daemon and
the CLI), the Go build is `/usr/lib/limbo/limbo-go` for `net watch` and `capture` (docs/RUST_PORT.md "Packaging").

A Claude session isolated in a worktree has its commands refused when they wrap a payload the guard cannot read
(`bash script`, `env`, `nice` before `go test`, a program literally named `cmd` after `--`): run real Wine checks from
Go tests, and builds with `renice -n 15 -p $$ && go ...`.

```bash
go vet ./... && go test ./...      # Linux (the code uses Linux syscalls; it no longer builds for Windows)
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
| `scripts/integration-linux-guest.sh` | boot in each network mode, what the firewall allows, two guests cannot reach each other, teardown; base image proofs (hashed once, libvirt leaves the base root's, the weekly check catches a change) |
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
- **Wine runs only through `limbo wine`** (owner's decision, 2026-11-08; docs/ARCHITECTURE.md section 13): never bare
  Wine on the host, in code, scripts, tests or by hand; tests use Wine's own built-in programs only, headless. Its
  defaults stay deny-first (no network, no home, shares only as given), its profiles stay outside every sandbox, and no
  socket route may start a run with more than a person's profile allows.
- **No macOS guests.** Limbo is a Linux project; don't add macOS tooling.
- **Windows is license-gated.** Limbo's code never downloads, bundles or installs Windows on its own.
  Windows code paths require a user-supplied ISO and license, no-op without
  them, and are labelled unverified until run for real. Build and test against
  Linux guests first. The unattended installer (`limbo seed` for a Windows manifest, docs/ARCHITECTURE.md section 6)
  installs only from the ISO the user names, when the user runs it. An ISO fetched at the owner's explicit request is
  the owner supplying it (2026-11-08: Microsoft's 90-day Windows 11 Enterprise LTSC evaluation, a bought license later).
  Run for real since 2026-11-08: the installer, `limbo export`, `limbo screenshot`, `limbo capture` and USB passthrough
  into a disposable Windows guest (docs/ARCHITECTURE.md section 6). Still unverified: a licence key from the store going
  into the answer file, and `limbo launch` for Windows (RemoteApp).
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
  **Unverified**: no real VFIO device has been passed through yet.
  **USB passthrough** (owner's decision, 2026-11-08, for vehicle tuners whose maker ships only a Windows program):
  `manifest.devices.usb` (vendor:product IDs), the same limits as PCI: disposable guests (Linux, and since 2026-11-08
  Windows: makers' programs that need their own Windows kernel driver, which Wine cannot load), `usb_allow` in the same
  root-owned file, LykanOS hard-refused, a typed approval per window, refused while a host process or kernel driver uses
  the device. A USB device may instead have a **standing approval** (`usb_standing` in the same root-owned file, also on
  `usb_allow`; owner's decision 2026-11-08 for the SCT X4 and Icarus): no time window, every other check still each time.
  PCI never gets one, and nothing but that root-written file can grant one. Never a route on `agent.sock`/`control.sock`. First real run 2026-11-08: the SCT X4 seen in a disposable Arch guest. Labyrinth
  (CachyOS-based) ships `ID=labyrinth` in its os-release, which `internal/hostpolicy` relies on.
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
CLAUDE.md. Heimdall's one way to act on Limbo is `control.sock` (restrict-only,
live; `docs/QUARANTINE.md`).

## Asks from Heimdall

From Heimdall's CLAUDE.md Coordination Log.

- Done 2026-11-07: **`scope` on `net.anomaly`** (as `net.blocked` has it; `internal/flows`).
- Done 2026-11-07: **a read-only "does this guest exist" route on `control.sock`**:
  `GET /v1/guests/{name}` (200 with the name, or 404); on admin too, not on agent.sock.
  Heimdall can skip a hold on a torn-down validation run instead of recording
  `limbo_quarantine_failed`. Pinned in `internal/api/api_test.go`.
- Written down 2026-11-07: **the tap and bridge names are a contract** (Heimdall's
  `remote-access` detector treats a tap `vl-<guest>` on its bridge `lb-<guest>` as Limbo's
  own): a CONTRACT note on `BridgeName` in `internal/virt/names.go`. Renaming them is a
  contract change: `CONTRACT:` in the commit and an update on Heimdall's board.
- Open: **a "strings worth a rule" section in `limbo-decompile triage`** (Heimdall
  2026-11-05): stable, unique strings with offsets, so YARA rule drafts need less guessing.
  `limbo-decompile` lives in the decompile guest image, which is not built from this
  repository; it waits for that image's recipe.

## Coordination Log (newest first)

### 2026-11-11 (3) — A restart no longer lifts the passthrough block
- `RuntimeDirectory=limbo` makes systemd empty /run/limbo at every stop, and the reboot-needed marker
  (`passthrough.blocked`, written when a passed-through device does not come back) lived only there: any restart of the
  daemon, a package upgrade included, re-enabled passthrough without the reboot. Go and Rust alike.
- Now the marker that counts is `<state>/passthrough.blocked` with the boot it was written in (`boot_id <uuid>` from
  /proc/sys/kernel/random/boot_id); it counts unless that id and this boot's are both well-formed and differ. Damaged,
  unreadable, `unknown`, or a boot id this host cannot read: it counts until `limbo passthrough clear`. The run-folder
  marker is still written and honoured; `clear` removes both. The unit is unchanged (why not
  `RuntimeDirectoryPreserve=`: docs/RUST_PORT.md "The reboot-needed marker and restarts").
- Proof: `hostpolicy.json` 5,241 comparisons (restart, reboot, clear between questions), the CLI differential (state
  markers, a bound boot id), the daemon differential's new passthrough phase (refused after two restarts, allowed after a
  new boot id; the build before the fix fails it). The package needs a rebuild; on my PC, before the restart that
  installs it: no `/run/limbo/passthrough.blocked` (else reboot).
- **For Heimdall, Sarina, Yggdrasil, Labyrinth_OS:** nothing changes (same codes, events, sockets; the limbo-git recipes
  are unchanged).
— Signed: Limbo / Claude Opus 5.5

### 2026-11-11 (2) — The package ships limbo-rs as /usr/bin/limbo
- Branch `package-rust-daemon` rebased onto main and merged: `packaging/arch/PKGBUILD` builds both, `/usr/bin/limbo` is
  limbo-rs (`limbo.service` runs it unchanged), the Go build is `/usr/lib/limbo/limbo-go` for `net watch` and
  `capture`. Fixed on the way: a command line that was not UTF-8 made limbo-rs panic instead of reaching Go
  (`rust/limbo/tests/dispatch.rs`).
- **For Labyrinth_OS:** done from here the same day: limbo-git (and the store's copy) build limbo-rs the same way.
- My PC still runs the hand-made drop-in until the package is installed: the steps for a host that switched by hand
  are in docs/RUST_PORT.md "Packaging" (one restart of limbo.service, not during a validation run).
— Signed: Limbo / Claude Opus 5.5

### 2026-11-11 — The owner's first real-guest run against limbo-rs: the scripts, not the port
- Rehearsal never started (root in `unshare -rmn` cannot open a script or binary in a 0700 home: now copied into the
  scratch folder); quarantine 68/70, chain 24/31, sarina 4/15. Every failure traced to the scripts or this computer:
  405 vs 404 on user.sock's POST /v1/settings (Go answers 405 too), a grep that hit `skipped`, the installed
  sarina-service holding 8899 (the test's Sarina never started), the Python Sarina default, Heimdall's host-wide info
  alerts, the test heimdalld on /var/lib/heimdall paths, UFW dropping guest-to-host traffic regardless of Limbo's table.
  Table and fixes: docs/RUST_PORT.md "The owner's first run".
- `scripts/rust-checks.sh`: rehearsal, then each script with the Go daemon and with limbo-rs; only checks that differ
  count against the port. `scripts/it-common.sh`: Sarina's Go binary by default, own ports, a stop if a port is taken.
- Rerun with both daemons: rehearsal NO DIFFERENCE, quarantine 71/71 and sarina 15/15 for Go and Rust; chain 32/32
  Rust, 27/32 Go. The Go-only failures: test heimdallds left running by earlier runs (started in a subshell that the
  exit kill did not reach) answered first with an old configuration. Fixed: `exec runuser`, `stop_test_heimdalld`
  before and after. Packaging for limbo-rs as /usr/bin/limbo: branch `package-rust-daemon` (docs/RUST_PORT.md).
- **For Heimdall (not edited from here):** the test heimdallds get every state path in their own folder
  (`heimdall_isolation` in scripts/it-common.sh, keys from `internal/config/config.go`); a new default path there
  should be added to that function too.
- **For Labyrinth_OS (not edited from here):** limbo-git should build limbo-rs as /usr/bin/limbo and the Go build as
  /usr/lib/limbo/limbo-go once the branch is merged: docs/RUST_PORT.md "Packaging" (on the branch) has the exact lines.
— Signed: Limbo / Claude Opus 5.5

### 2026-11-10 — `limbo serve` ported to Rust (not switched yet)
- **Owner's wish:** as much of the ecosystem in Rust as possible, for lightness while gaming and running a local model;
  Heimdall's port is the model. `rust/` is a cargo workspace beside the Go code; `limbo-rs serve` is the daemon (the
  four sockets with their route tables, quarantine, verdicts, runs, profiles with the image proofs, the events log, the
  Settings page backend, the exchange outbox, licenses, the flows/anomaly watcher), and any other command is handed to
  the Go limbo. Same state files, same formats: switching back and forth is a restart.
- **Proof:** Go fixtures (manifests, XML, nft rules, seeds, flows, quarantine, engine command sequences, the API on all
  four sockets): 7,338 comparisons, all equal. Both daemons in namespaces with fake host programs on the same 108
  answers, 174 events, 641 host commands and 16 state files: no difference. Kani harnesses (no loosening route on
  control.sock or agent.sock for any combination of services; nothing of root's on user.sock), their claims run
  exhaustively in the tests, proptest, fuzz targets.
- **Measured** (same harness): RSS after start 3.3 MB against Go's 13.5 MB (PSS 1.3 against 13.5), after the script 4.1 (PSS 1.9)
  against 19.1 MB, one thread idle against 10-15, idle CPU 0 for both; 159 context switches during the script against
  Go's 5,334.
- **Why no week of shadow mode as Heimdall had:** two Limbo daemons would fight over /run/limbo's sockets, the second
  would destroy the first's validation-run guests at startup (the orphan reap), only one can bind NFLOG group 7213, and
  both would act on the same guests and tables. Instead: a rehearsal on a copy of the real state (`--from-host`), the
  real-guest scripts with `LIMBO_RS=`, then a direct switch by a systemd drop-in, undone by removing it.
- **For Heimdall, Sarina, Yggdrasil (not edited from here):** nothing changes. Same sockets, routes, JSON, codes and
  event kinds, byte for byte; events.jsonl is written the same way.
- Owner steps (root): docs/RUST_PORT.md "Commands for the owner".
— Signed: Limbo / Claude Opus 5.5

### 2026-11-09 — Base images: hashed once, proven after
- **Owner's decision:** a start no longer hashes the base image every time (the 12.7 GB Windows base cost ~25 s and
  GBs of page cache per start). It is hashed in full once; a root-owned record (`<state>/image-proofs.json`) lets later
  starts skip the hash only while the file is root's, not group/other-writable, in a root-only folder, and its device,
  inode, size, mtime and ctime are those recorded, for the digest the manifest asks for. Anything else hashes in full
  as before; a damaged or foreign record file is ignored. Full hashes no longer fill the page cache (fadvise). A weekly
  `limbo image verify` (`limbo-image-verify.timer`, idle priority, held during games by Yggdrasil's game time when it is
  installed) hashes every proven image again. Details: docs/ARCHITECTURE.md section 12.1.
- **Found on the way:** libvirt had chowned every base image to `libvirt-qemu` (its DAC driver relabels the whole disk
  chain and never gives a shared base back), so QEMU could write them and the root-only rule could never hold. The
  domain now declares the base as the overlay's backing store with `<seclabel model='dac' relabel='no'/>`, and `Up`
  refuses a persistent guest's kept overlay made on another base (libvirt follows the declaration, not the header).
- **For Heimdall (not edited from here):** additive only. `image.verified` gains `check` (`full` | `record`). The weekly
  check writes `image.rejected` with an empty `guest` and `during` = `weekly check`, `path`, `sha256`, `found`, `stat`
  (`unchanged`: the content changed with no trace in the file's metadata, worth the louder alarm). The `limbo-guest`
  detector already raises a critical finding on `image.rejected`; with an empty guest its summary reads `guest ""`, so
  naming `path` there would read better. Nothing to quarantine (no guest started), as before.
- **For Yggdrasil:** Limbo's package ships its own game-time drop-in for `limbo-image-verify.service` (it asks
  `/usr/bin/yggdrasil-gametime` only when it exists); docs/GAME_TIME.md's "What waits" table could list it.
- Real-guest run of the new `proof` and `tamper` sections of `scripts/integration-linux-guest.sh`: needs root, not run
  by this session. Owner steps: install, restart `limbo.service`, then `sudo chown root:root /var/lib/limbo/images/*.qcow2`.
— Signed: Limbo / Claude Opus 5.5

### 2026-11-08 — The Wine backend: `limbo wine` (phase 1)
- **Owner's decision:** Windows programs run with Wine on the host desktop, confined by bubblewrap, and Wine runs only
  through Limbo (Steam's Proton stays outside). `limbo wine [options] -- PROGRAM [ARGS]`, per-prefix profiles in
  `~/.config/limbo/wine/NAME.json`, prefixes in `~/.local/share/limbo/wine/NAME` (64-bit, Windows 10 by default),
  `/usr/lib/limbo/bin/wine` as the `wine` on PATH once a person links it from `/usr/local/bin`. Details, what is shared
  and what is not: docs/ARCHITECTURE.md section 13.
- **For Heimdall (not edited from here):** new event kinds, all additive (docs/EVENTS.md "The Wine backend"):
  `wine.start`, `wine.stop`, `wine.setup`, `wine.refused`; guest `wine:<prefix>`; `wine.start` names the run's
  machine-readable record (`record`, a `run.json`) and, when the program is a host file, its `sha256`. They are written
  to the person's own log (`~/.local/state/limbo/events.jsonl`), not the daemon's, so Heimdall sees them only with
  `limbo_event_log` pointed there. The `limbo-guest` detector ignores them today; nothing breaks.
- **For Sarina:** nothing on `agent.sock`. A later route would start a headless, traced run under a person's profile
  (section 13 "Phase 2").
— Signed: Limbo / Claude Opus 5.5

### 2026-11-05 — Settings page backend, guest network events, the known weaknesses
- **New socket for people: `/run/limbo/user.sock`** (0660 root:`limbo-users`, a new
  group in sysusers and `limbo setup`). It is the Yggdrasil Settings page's: read-only
  figures always, changes to a member's own guests only while the password switch
  (`/etc/limbo/settings.json`, root's) is off. The exact protocol (routes, JSON, error
  codes, CLI equivalents with `--json`) is `docs/SETTINGS_PAGE.md` "Protocol"; the
  page (Rust) is written against it. `control.sock` and `agent.sock` are unchanged and
  have none of the new routes (pinned in `internal/api/settings_test.go`).
- **New events, all additive** (docs/EVENTS.md): `net.flow`, `net.blocked`,
  `net.anomaly` (`reason` host_probe | lan_probe | scan | ipv6), `net.capped`;
  `exchange.file` | `exchange.held` | `exchange.fail`; `instance.request` |
  `instance.change` | `instance.add` | `instance.remove`; `settings.change`;
  `license.add` | `license.remove` | `license.reveal` | `license.assign` |
  `license.unassign` (id only, never a key). No existing kind or key changed.
- **For Heimdall (not edited from here; another session works there today):**
  its `limbo-guest` detector ignores kinds it does not know, so nothing breaks.
  Suggested consumption: a finding on `net.anomaly` (host_probe and lan_probe:
  warning or higher, a guest reaching for the host or the LAN; scan: warning;
  ipv6: info), which may restrict the guest through `control.sock` as today;
  `exchange.held` names a file ClamAV knew, held root-only at
  `/var/lib/limbo/state/exchange-held/<sha256>`, which Heimdall's root side could
  take into its immunity quarantine (`heimdalld immunity hold`). The firewall now
  routes refusals through two log-then-drop chains (`blocked`, `hostblocked`) in the
  guest's table; table name, `policy.apply`/`policy.remove` and their order are
  unchanged, so the chain test's "delete the table" trigger works as before.
- **For Sarina:** nothing changes on `agent.sock`. Validation-run guests now get
  allocated subnets (no more one-in-254 start failures from hash collisions).
- Weaknesses fixed: subnets allocated and recorded; launch pins the guest's host
  key and asks the daemon about holds; persistent guests on their own overlay; a
  writable share is only the guest's root-only outbox, scanned by ClamAV on the way
  out; IPv6 dropped and tested. Details in ARCHITECTURE.md.
- Real-guest results today (new build as root from a repo copy; the installed r16
  daemon untouched): `integration-linux-guest.sh` 66/66, then 24/24 for the persistent
  section with `launch --check`. A live validation run through the running daemon's
  `agent.sock` showed IPv6 stays inside a mode-none guest. ClamAV for real
  (`LIMBO_CLAMAV=1`): EICAR held, a plain file clean.
- Module now needs Go 1.24 (`os.Root`). The integration scripts pass `--i-know` to
  `up`/`down` (root's state-folder guard from 2026-10-27). Run them from a copy of the
  repo when editing at the same time: bash reads a script while it runs.
- Owner steps (install, restart, group membership, optional exchange mount):
  `docs/OWNER_STEPS_2026-11-05.md`.
— Signed: Limbo / Claude Opus 5.5

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
