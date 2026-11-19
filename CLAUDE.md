# CLAUDE.md — Limbo

## 1. What this is

Limbo runs Windows and Linux programs on a Linux host in sandboxes: disposable libvirt/KVM guests with nftables policies
(`limbo up`, validation runs for Sarina, sealed sample runs, quarantine that Heimdall may tighten and only a human loosens),
and Windows programs on the desktop through Wine inside bubblewrap (`limbo wine`). Rust only since 2026-11-15: `rust/limbo`
builds `limbo-rs`, installed as `/usr/bin/limbo`, the daemon (`limbo serve`) and every command. Read
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before design decisions; the port and its proofs: [docs/RUST_PORT.md](docs/RUST_PORT.md).

## 2. Build and test

Memory-capped and at low priority (games and the local model run on this computer):

```bash
cd rust
systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 env CARGO_BUILD_JOBS=4 \
  scripts/nicecargo.sh test --offline        # every fixture, the properties, the fuzz bodies, dispatch, packaging
scripts/nicecargo.sh clippy --all-targets && cargo fmt --all --check
systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 env CARGO_BUILD_JOBS=4 \
  scripts/nicecargo.sh build --release --bins --example usbmon_fake
cd .. && sh scripts/netns-sinkhole.sh         # no root: the analysis networks' isolation in a throwaway namespace
sh rust/parity/go-limbo.sh /tmp/limbo-go      # the Go referee, built from the pinned commit 86a479f
python3 -I rust/parity/cli-differential.py --go /tmp/limbo-go --rs rust/target/release/limbo-rs --out /tmp/lcd
python3 -I rust/parity/daemon-differential.py --go /tmp/limbo-go --rs rust/target/release/limbo-rs --out /tmp/ld --idle 5
```

`scripts/netns-sinkhole.sh` is the release check that no analysis profile (`sinkhole`, `none`) reaches the home connection:
run it after any change to `policy`, `virt`, `hostfw` or `sinkhole`.

The real-guest tests need root and a real hypervisor; each has caught defects unit tests could not. Run the first three after
changing `policy`, `virt`, `engine`, `api`, `runs` or `quarantine` (the scripts test `$LIMBO_BIN`, else
`rust/target/release/limbo-rs`):

| Script | Covers |
| --- | --- |
| `scripts/integration-linux-guest.sh` | boot in each network mode, what the firewall allows, two guests cannot reach each other, teardown; base image proofs |
| `scripts/integration-quarantine.sh` | `limbo serve`, socket permissions with real unprivileged users, quarantine lifecycle, verdicts, validation runs |
| `scripts/integration-chain.sh` | real guest + real daemon + real `heimdalld` (unprivileged) + Sarina's real service behind a fake model |
| `scripts/integration-sarina.sh` | Sarina's real agent loop and service (a fake model with scripted tool calls) driving real validation runs |
| `scripts/integration-systemd.sh` | the real unit files and their hardening as installed (installs and removes files: test machine only) |

`scripts/rust-checks.sh` runs the rehearsal on a copy of this computer's state and each script with both daemons.
`LIMBO_IT_MODES="none"` limits a script to one network mode; `LIMBO_IT_BOOT_WAIT=N` sets the boot wait (x3 s). Run the
scripts from a copy of the repository while editing: bash reads a script while it runs.

CI (`.github/workflows/rust.yml`, on pushes that touch `rust/`, `testdata/`, `packaging/`, `scripts/netns-sinkhole.sh`,
`VERSION`): fmt, clippy `-D warnings`, the tests, the sinkhole namespace check, the CLI and daemon differential runs against
the Go referee (with real nft for NFLOG), `cargo audit` (weekly too). Watch a push by its full SHA: `gh run list --commit <sha>`.

## 3. Rules

- **Privacy.** Never write a host name, network address, SSID, MAC address, serial or the owner's name into a commit, code,
  test or doc; check the diff before pushing. Never commit real guest data, keys, licence keys or event logs.
- **Push as you go.** Push every commit as you make it; don't ask first. Stage by explicit path, never `git add -A`,
  `git add .` or `git commit -a` (other sessions' files are in sibling checkouts); `git pull --rebase` before pushing.
- **Deny-first sandboxes.** No shared folders, no LAN access, no clipboard or USB by default. Anything that widens the
  boundary is an explicit per-app profile setting, never a default.
- **A sample run has no route out** (my decision, 2026-11-18): a sealed profile is `none` or `sinkhole`, never a mode that
  forwards. The sinkhole's responder never runs as root and binds only the guest's gateway address; what it reports is
  guest data (escaped, bounded, labelled).
- **Automated actors may restrict, never loosen.** Heimdall reaches Limbo only through `control.sock`, Sarina only through
  `agent.sock`; each socket has its own route table, so a forbidden action does not exist there. Never add a loosening route
  to either, and never let a verdict happen without an audit record. `rust/limbo/src/api.rs`'s tests pin the tables.
- **Guest text is untrusted** everywhere it is shown (CLI, report, API), and so is a model's text about guest data: bound
  it, strip control characters, label it. An advisory never changes state.
- **Wine runs only through `limbo wine`** (my decision, 2026-11-08; docs/ARCHITECTURE.md section 13): never bare Wine on
  the host, in code, scripts, tests or by hand. Wine is no security boundary; it never runs without the bubblewrap sandbox.
  Tests use Wine's own built-in programs only, headless. Its defaults stay deny-first, its profiles stay outside every
  sandbox, and no socket route may start a run with more than a person's profile allows.
- **No macOS guests.**
- **Windows is licence-gated.** Limbo never downloads, bundles or installs Windows on its own; Windows paths need an ISO
  and licence the user supplies, no-op without them, and are labelled unverified until run for real. An ISO fetched at my
  explicit request is me supplying it (2026-11-08: Microsoft's 90-day Windows 11 Enterprise LTSC evaluation).
- **Device passthrough** (PCI for driver testing, my decision 2026-10-10; USB for makers' tools, 2026-11-08): disposable
  guests only, set by a root-owned profile, never by a caller. The host decides (`hostpolicy.rs`): refused on LykanOS
  unconditionally (`ID=lykanos`, or the old `chymaera`), on Labyrinth OS only for devices in the root-owned
  `/etc/limbo/host-policy.json` (`pci_allow`, `usb_allow`), any other OS or read error refused. Each window needs a typed
  `sudo limbo passthrough approve`, refused while the host uses the device; a USB device may instead have a standing
  approval (`usb_standing`, same root file); PCI never. No socket route may choose a device or approve a window.
- **CAD/GPU for desktop use is deferred.** Don't start it, and don't claim it works untested.
- **Our own implementations.** The references are for ideas, not code (my decision, 2026-10-04). Limbo is MPL-2.0: copy
  nothing from GPL sources (Bottles, Prism Launcher); ask before a dependency whose licence does not fit. The README's
  references table lists what was taken from each; update it when adopting something.
- Loopback-only APIs; fail closed on policy errors.

## 4. Contracts

All in [docs/CONTRACTS.md](docs/CONTRACTS.md), one section each. A change to one says `CONTRACT:` in the commit message and
updates that file in the same commit.

- Provided here: the four sockets and their route tables (Heimdall, Sarina, Settings); `events.jsonl` (docs/EVENTS.md); the
  tap and bridge names; held files; the sinkhole responder; the groups and accounts.
- Used from others: the OS's `ID` in `/etc/os-release` (Labyrinth OS, LykanOS); Heimdall's lock `/etc/heimdall/contained`
  (Heimdall docs/CONTRACTS.md); Yggdrasil's `yggdrasil-gametime` (the weekly image check waits during games).

## 5. Open work

docs/plans/BACKLOG.md and docs/plans/LOG.md (private; ask the owner).

## 6. Know-how

- Layout: `rust/limbo/src/` (one module per former Go package: `policy.rs`, `virt.rs`, `engine.rs`, `api.rs`, `runs.rs`,
  `quarantine.rs`, `flows.rs`, `exchange.rs`, `hostpolicy.rs`, `sinkhole/`, `wine/`, `cli/`), `rust/parity/` (the
  differential harnesses and `go-limbo.sh`), `testdata/parity/` (what the Go tests of 86a479f wrote; the Go limbo stays the
  referee of every proof), `packaging/arch/` (PKGBUILD, unit, sysusers, the weekly image check), `packaging/wine/wine` (the
  `wine` on PATH that hands to `limbo wine`), `examples/` (profiles and manifests), `scripts/` (real-guest tests). The Go
  package names in older docs (`internal/policy`, ...) are the Rust modules of the same names.
- UFW drops by default on Labyrinth OS and Limbo's table cannot override someone else's drop: `hostfw.rs` adds the rules
  a guest needs. UFW's route rules are deleted with `ufw route delete ...`, not `ufw delete route ...`.
- `RuntimeDirectory=limbo` empties /run/limbo at every stop: state that must survive a restart lives in the state folder
  (the passthrough block marker names its boot).
- Restarting `limbo.service` while a validation run executes destroys that run's guest (the startup reap): restart when
  Sarina is not running one.
- Tooling trap: shell heredocs and scripted edits turn `\n` and `\u...` into real characters; use the editor for source with
  escapes, and never leave a raw invisible character (bidi override, zero-width) in source: write it as an escape (`limbo
  report`'s tests do exactly that).
- A cloud-init Arch base image for tests lives at `/var/lib/limbo/images/arch-cloudimg.qcow2` (not in git; from
  `geo.mirror.pkgbuild.com/images/latest/`). Base images are root's and hashed once, then proven (docs/ARCHITECTURE.md 12.1).
