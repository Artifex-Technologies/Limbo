# Limbo

Run Windows and Linux guest applications on a Linux host as seamless,
native-looking windows, each inside a sandbox you control. Built first for
**network and infrastructure security analysis and reporting**: run
Windows-only and untrusted-input tooling without exposing the host. Part of the
Artifex ecosystem: it ships in Labyrinth OS (package `limbo-git`), is meant for
LykanOS (formerly Chymaera OS) too, and is watched by
[Heimdall](https://github.com/Artifex-Technologies/Heimdall).

**Sample runs** ([docs/SAMPLES.md](docs/SAMPLES.md)): one hostile file analysed in a sealed guest (no network, no sudo, no shared
folder) for Heimdall's quarantine, `sudo limbo analyze FILE`. While Heimdall has contained Sarina, her agents' runs are refused and
stopped.

**Status: working for Linux guests, verified against real guests; Windows
guests are written but have never run.** Linux guests boot under libvirt/KVM with
per-guest firewalls that were tested from inside the guest; quarantine, human
verdicts, validation runs and the Heimdall/Sarina integrations were tested with a
real daemon, real sockets, real unprivileged users and real systemd units. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) section 12 for exactly what is and
is not verified.

```
go build ./cmd/limbo
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

## References

Each is a design reference, not a dependency. Limbo borrows ideas and writes its
own implementations; no code is copied (Bottles and Prism are GPL-3.0; Limbo is
MPL-2.0, so nothing may be copied from them). What is adopted is recorded here.

| Project | What it is | What Limbo takes from it |
| --- | --- | --- |
| [Bottles](https://github.com/bottlesdevs/Bottles) | Wine prefix manager | One prefix per app with its own settings (`limbo wine` profiles, built 2026-11-08); runner and dependency management later |
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

## License

MPL 2.0. See [`LICENSE`](LICENSE).
