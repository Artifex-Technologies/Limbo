<p align="center"><img src="docs/icon.png" width="128" alt="Limbo icon"></p>

# Limbo

[![rust](https://github.com/Artifex-Technologies/Limbo/actions/workflows/rust.yml/badge.svg)](https://github.com/Artifex-Technologies/Limbo/actions/workflows/rust.yml)

Run Windows and Linux guest applications on a Linux host as seamless,
native-looking windows, each inside a sandbox you control. Built first for
**network and infrastructure security analysis and reporting**: run
Windows-only and untrusted-input tooling without exposing the host. Part of the
Artifex ecosystem: it ships in Labyrinth OS (package `limbo-git`), is meant for
LykanOS (formerly Chymaera OS) too, and is watched by
[Heimdall](https://github.com/Artifex-Technologies/Heimdall).

**Sample runs** ([docs/SAMPLES.md](docs/SAMPLES.md)): one hostile file analysed in a sealed guest (no route out, no sudo, no shared
folder) for Heimdall's quarantine, `sudo limbo analyze FILE`. Its network is the **sinkhole**
([docs/SINKHOLE.md](docs/SINKHOLE.md)): every name resolves to the guest's own gateway and every connection lands on a logging
responder there, so a sample that calls home reaches a log on this computer, never the internet. While Heimdall has contained Sarina, her agents' runs are refused and
stopped.

**Status: working for Linux guests, verified against real guests; Windows
guests are written but have never run.** Linux guests boot under libvirt/KVM with
per-guest firewalls that were tested from inside the guest; quarantine, human
verdicts, validation runs and the Heimdall/Sarina integrations were tested with a
real daemon, real sockets, real unprivileged users and real systemd units. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) section 12 for exactly what is and
is not verified.

**How it is tested.** Every change to the Rust code runs the `rust` workflow: formatting, clippy, the tests, and the
differential runs, in which the Rust daemon and CLI and the last Go limbo get the same socket traffic and must answer the
same; it also puts a sinkhole guest's real firewall tables in a throwaway network namespace to show an analysis network
reaches nothing else, and audits the dependencies. The method and the numbers are in [docs/RUST_PORT.md](docs/RUST_PORT.md);
the real-guest tests are the `scripts/integration-*.sh` runs that [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) section 12
describes.

```
(cd rust && cargo build --release --locked)  # rust/target/release/limbo-rs is limbo (the package installs it as /usr/bin/limbo)
limbo doctor                                 # what is installed, what is missing
sudo limbo setup                             # installs libvirt, QEMU, ... (Limbo ships without them)
limbo plan examples/analysis-linux.json      # safe anywhere: prints what `up` would apply
sudo limbo up examples/analysis-linux.json   # Linux host with libvirt + nftables
limbo address examples/analysis-linux.json   # its address (given at up)
limbo launch --check examples/analysis-linux.json   # every launch check, no window (needs provision.host_key: see limbo seed)
limbo launch examples/analysis-linux.json
sudo limbo down examples/analysis-linux.json

sudo limbo serve                             # the control API (quarantine, validation runs)
sudo limbo quarantine list                   # what is held, and why
sudo limbo quarantine show ID                # evidence and advisories (labelled untrusted)
sudo limbo quarantine verdict ID safe|dangerous --note "..."   # only a human can
limbo report --since 7d --out report.md      # Markdown evidence report

limbo settings show                          # the Settings page's figures (members of limbo-users; docs/SETTINGS_PAGE.md)
limbo instance start|stop|set NAME ...       # needs the password unless "Ask for my password" is off
sudo limbo settings password on|off          # that switch
limbo exchange take GUEST FILE DEST          # a file out of a guest's outbox, scanned by ClamAV first
sudo limbo net watch                         # guests' connections and refusals, live (serve logs them as net.* events)
sudo limbo image list                        # base images proven by a full hash: a start skips the hash while unchanged
sudo limbo image verify                      # hash each again (weekly by limbo-image-verify.timer); refuses any that changed
```

## Windows programs with Wine: `limbo wine`

Windows programs, games included, run with Wine on the desktop, each prefix inside its own bubblewrap sandbox, and
Wine runs only through Limbo (Steam's Proton stays with Steam). By default the sandbox has the system read-only, the
display (Wayland and X11), sound and the graphics card (Vulkan layers such as Kairos load), a private home holding only
the prefix, and **no network and none of your files**; everything else is an explicit flag or profile setting.
Details, and exactly what is shared: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) section 13.

```
limbo wine -- notepad                                    # prefix "default": ~/.local/share/limbo/wine/default
limbo wine --prefix game --share ~/Downloads/Installers -- ~/Downloads/Installers/setup.exe
limbo wine --prefix game --share-rw ~/Games/Foo --network -- 'C:\Program Files\Foo\Foo.exe'
limbo wine --headless --trace --prefix tools --share ~/Tools -- ~/Tools/scan.exe   # no display or sound; a behaviour trace
limbo wine --windows win7 --prefix old -- 'C:\Old\old.exe'   # new prefixes are 64-bit and report Windows 10
limbo wine --dry-run -- notepad                          # the whole sandbox, changing nothing
sudo ln -s /usr/lib/limbo/bin/wine /usr/local/bin/wine   # then anything that runs `wine` lands in the sandbox
```

Per-prefix settings live in `~/.config/limbo/wine/NAME.json` ([`examples/wine-profile.json`](examples/wine-profile.json)).
Every run is logged (`wine.start`/`wine.stop` in `~/.local/state/limbo/events.jsonl`) with a `run.json` record. Files
nobody trusts go to `limbo analyze` (a sealed VM), not here.

## Scope

- Guests: **Linux** (built first, no license needed) and **Windows**
  (license-gated, see below). No macOS — Limbo is a Linux project, and Apple's
  license only allows macOS VMs on Apple hardware.
- CAD/3D workloads are deferred.
- Deny-by-default network, filesystem, clipboard and devices, configured per app.
- **Quarantine.** Heimdall watches Limbo's audit log and, when a guest runs outside
  its safety rules, asks Limbo to cut its network. Heimdall can only *restrict*:
  the socket it uses has no route to release a guest. A **human** gives the
  verdict (safe or dangerous). Sarina adds an advisory opinion that is untrusted
  and changes nothing. Details: [`docs/QUARANTINE.md`](docs/QUARANTINE.md).
- **Validation runs.** Sarina can run a command in a disposable guest to try an
  update or install before the real system is touched, using a profile a human
  wrote. A passing run is evidence, never permission.
- **Reports.** `limbo report` turns the audit log and quarantine records into a
  Markdown document, with everything from a guest escaped.

## Windows license

Nothing in this repo downloads, bundles or installs Windows. The Windows
backend is written to require a user-supplied ISO and license; without them it
does nothing, and its code is marked unverified until it has run for real.

## Why Rust: measured

Old: the Go limbo of `86a479f`, the last commit with the Go sources (`rust/parity/go-limbo.sh` builds it, `CGO_ENABLED=0`).
New: the Rust release build. Same computer, measured 2026-11-25; change is new against old, so a minus is a gain.

**The daemon** (`limbo serve`), both in the daemon differential's namespaces with the same fake tools, the same 109
requests (validation and sample runs among them) and the same NFLOG traffic (`rust/parity/daemon-differential.py`; it
compares every answer, event, host command and state file, and found no difference):

| | Go | Rust | Change |
| --- | --- | --- | --- |
| memory after start (RSS / PSS) | 13.5 / 13.5 MB | 3.7 / 1.6 MB | −73 % / −88 % |
| memory after the requests (RSS / PSS) | 19.5 / 19.4 MB | 4.6 / 2.4 MB | −76 % / −88 % |
| threads | 9 | 1 | |
| idle (5 s here, 60 s on 2026-11-10): CPU, context switches | 0, 0 | 0, 0 | both sleep until a socket or NFLOG wakes them |

On my PC the installed daemon has stayed at about 4 MB resident and one thread after hours of use (the Go one grew to 18.8 MB).

**The command line**, on commands that need no daemon and no root (`rust/parity/measure-cli.py`: a small C launcher reports
wall time, CPU and peak RSS from `wait4`; 30 runs each, alternating, at nice 19; the median, p10-p90 in brackets; the floor,
`/usr/bin/true`, is 0.43 ms and 1.7 MB; the outputs are the same):

| Command | Go | Rust | Change | peak RSS Go → Rust |
| --- | --- | --- | --- | --- |
| no arguments (the usage) | 1.94 ms (1.71-2.09) | 0.60 ms (0.57-0.68) | −69 % | 10.7 → 2.8 MB |
| `validate` a manifest | 2.16 ms (1.99-2.40) | 0.71 ms (0.67-0.75) | −67 % | 10.9 → 3.8 MB |
| `plan` a manifest (domain XML, firewall rules) | 2.25 ms (1.90-2.41) | 0.75 ms (0.69-0.78) | −67 % | 10.9 → 4.0 MB |
| `doctor` (starts the tools it checks) | 5.16 ms (4.88-5.44) | 3.52 ms (3.36-3.66) | −32 % | 10.7 → 3.8 MB |

Most of a short Go command's time is starting the Go runtime. **Size:** 9.0 MB stripped for Go, 2.6 MB for Rust, the one
binary with the daemon and every command (Wine's sandbox, the network capture and the passthrough checks included).

**What the port found in the old code** (docs/RUST_PORT.md): `license.Check` and `limbo seed` depended on Go's map order
(which file a failed check named, what a failed write left behind), and a restart of the daemon lifted the passthrough
block (`RuntimeDirectory=limbo` empties /run/limbo; the marker now lives in the state folder and names its boot). Each was
fixed in Go and Rust alike. The differential runs also caught the port's own first-build mistakes before the switch (runs
of bad bytes in guest output, a killed command's exit, a command's end noticed only every 25 ms, now a pidfd). What
differs on purpose, and every proof: [docs/RUST_PORT.md](docs/RUST_PORT.md).

## References

Each is a design reference, not a dependency. Limbo borrows ideas and writes its
own implementations; no code is copied (Bottles and Prism are GPL-3.0; Limbo is
MPL-2.0, so nothing may be copied from them). What is adopted is recorded here.

| Project | What it is | What Limbo takes from it |
| --- | --- | --- |
| [Bottles](https://github.com/bottlesdevs/Bottles) | Wine prefix manager | One prefix per app with its own settings (`limbo wine` profiles, built 2026-11-08); no runner or dependency management |
| [Prism Launcher](https://github.com/PrismLauncher/PrismLauncher) | Minecraft launcher | UX model: one isolated instance per app, library-style GUI |
| [Wine](https://github.com/wine-mirror/wine) | Windows API layer | The backend for Windows programs on the desktop (`limbo wine`), always inside bubblewrap; run as a separate program |
| [bubblewrap](https://github.com/containers/bubblewrap) | Unprivileged sandbox | The Wine backend's sandbox, run as a separate program (LGPL-2.0-or-later; nothing copied) |
| [Flatpak](https://github.com/flatpak/flatpak) | Desktop app sandbox on bubblewrap | Ideas only: how a desktop app's sandbox reaches the display, sound and graphics card (Wayland/X11/PulseAudio sockets, a rewritten X authority) |
| [macos-parallels-build-vms](https://github.com/paullalonde/macos-parallels-build-vms) | Scripted macOS VM builds on Parallels | How unattended guest builds are structured; translated to Windows/Linux on libvirt, nothing macOS- or Parallels-specific |
| [VirtualBox](https://github.com/VirtualBox/virtualbox) | Hypervisor | Compared against and not chosen; KVM/libvirt is the target |
| [WinApps](https://github.com/winapps-org/winapps) | Windows apps on Linux via RDP RemoteApp | The seamless-window mechanism for Windows guests |
| Parallels (Coherence mode) | Commercial; not open | The experience Limbo aims to match |
| [Heimdall](https://github.com/Artifex-Technologies/Heimdall) | Security daemon (sibling repo) | Consumes Limbo's event log; proposes quarantine |

Reference claims in the docs come from prior knowledge until Milestone 0
verifies them against current source.

## Version

`VERSION` is Limbo's own version (1.0.0 since 2026-11-11, its first numbered release); its package is `limbo-git` `VERSION-<build number>`. How the numbers work and how to make a release: [Labyrinth_OS docs/VERSIONING.md](https://github.com/Artifex-Technologies/Labyrinth_OS/blob/main/docs/VERSIONING.md).

## Artifex Ecosystem

| Repository | What it is |
| --- | --- |
| [Labyrinth_OS](https://github.com/Artifex-Technologies/Labyrinth_OS) | privacy- and security-first Linux distribution (CachyOS-based), made for gaming too |
| [LykanOS](https://github.com/Artifex-Technologies/LykanOS) | the security edition, built on the same desktop and tools |
| [Yggdrasil](https://github.com/Artifex-Technologies/Yggdrasil) | the desktop environment both systems use (panel, Settings, Agora, Minos, the compositor) |
| [Sarina](https://github.com/Artifex-Technologies/Sarina) | optional local AI assistant that runs on this computer |
| [Heimdall](https://github.com/Artifex-Technologies/Heimdall) | the security agent: watches the computer, its network and Sarina |
| [Limbo](https://github.com/Artifex-Technologies/Limbo) | **this repository**: disposable sandboxes for apps, Windows programs and untrusted files |
| [Kairos](https://github.com/Artifex-Technologies/Kairos) | frame generation for games (a Vulkan layer) |
| [Argus_App](https://github.com/Artifex-Technologies/Argus_App) | desktop console for the Flipper Zero (a qFlipper fork) |
| [Argus_Firmware](https://github.com/Artifex-Technologies/Argus_Firmware) | Flipper Zero firmware fork |
| [Daedalus_CAD](https://github.com/Artifex-Technologies/Daedalus_CAD) | 3D modelling and CAD (SketchUp-style) |
| [Icarus](https://github.com/Artifex-Technologies/Icarus) | vehicle diagnostics and tuning |

## License

MPL 2.0. See [`LICENSE`](LICENSE).
