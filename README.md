# Limbo

Run Windows and Linux guest applications on a Linux host as seamless,
native-looking windows, each inside a sandbox you control. Built first for
**network and infrastructure security analysis and reporting**: run
Windows-only and untrusted-input tooling without exposing the host. Part of the
Artifex ecosystem: it ships in Labyrinth OS (package `limbo-git`), is meant for
Niflheim OS (formerly Chymaera OS) too, and is watched by
[Heimdall](https://github.com/Artifex-Technologies/Heimdall).

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
limbo launch examples/analysis-linux.json
sudo limbo down examples/analysis-linux.json

sudo limbo serve                             # the control API (quarantine, validation runs)
sudo limbo quarantine list                   # what is held, and why
sudo limbo quarantine show ID                # evidence and advisories (labelled untrusted)
sudo limbo quarantine verdict ID safe|dangerous --note "..."   # only a human can
limbo report --since 7d --out report.md      # Markdown evidence report
```

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
| [Bottles](https://github.com/bottlesdevs/Bottles) | Wine prefix manager | Per-app environments, runner and dependency management (Wine backend, later) |
| [Prism Launcher](https://github.com/PrismLauncher/PrismLauncher) | Minecraft launcher | UX model: one isolated instance per app, library-style GUI |
| [Wine](https://github.com/wine-mirror/wine) | Windows API layer | Optional lightweight backend, always inside a sandbox |
| [macos-parallels-build-vms](https://github.com/paullalonde/macos-parallels-build-vms) | Scripted macOS VM builds on Parallels | How unattended guest builds are structured; translated to Windows/Linux on libvirt, nothing macOS- or Parallels-specific |
| [VirtualBox](https://github.com/VirtualBox/virtualbox) | Hypervisor | Compared against and not chosen; KVM/libvirt is the target |
| [WinApps](https://github.com/winapps-org/winapps) | Windows apps on Linux via RDP RemoteApp | The seamless-window mechanism for Windows guests |
| Parallels (Coherence mode) | Commercial; not open | The experience Limbo aims to match |
| [Heimdall](https://github.com/Artifex-Technologies/Heimdall) | Security daemon (sibling repo) | Consumes Limbo's event log; proposes quarantine |

Reference claims in the docs come from prior knowledge until Milestone 0
verifies them against current source.

## License

MPL 2.0. See [`LICENSE`](LICENSE).
