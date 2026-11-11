//! `limbo doctor` and `limbo setup` (cmd/limbo/setup.go, internal/deps), line for line: what is installed and what is
//! missing, and the root-only setup that installs it (pacman), makes the groups and enables libvirt (systemctl). Same
//! output, errors and programs run as Go; rust/parity/cli-differential.py compares the two binaries with fake programs
//! on PATH and the profile folder in a mount namespace of its own.

use super::commands::{trim_space, Fail, Io};
use super::flags::{parse_interspersed, FlagSet};
use super::goexec;
use crate::events::Recorder;
use crate::image::Proofs;
use crate::{engine, runs, sys};
use std::sync::Arc;

/// deps.Required: (command, package, purpose).
pub const REQUIRED: [(&str, &str, &str); 7] = [
    ("virsh", "libvirt", "defines, starts and stops guests"),
    ("qemu-img", "qemu-base", "creates the per-guest disposable overlay"),
    ("qemu-system-x86_64", "qemu-base", "the hypervisor (KVM)"),
    ("dnsmasq", "dnsmasq", "DHCP and DNS on each guest's private network"),
    ("nft", "nftables", "each guest's firewall"),
    ("ssh", "openssh", "validation runs reach the guest over ssh"),
    ("xorriso", "libisoburn", "builds the cloud-init seed disk"),
];

const LIBVIRT_SOCKETS: [&str; 5] =
    ["virtlogd.socket", "virtqemud.socket", "virtnetworkd.socket", "virtstoraged.socket", "virtnodedevd.socket"];
const WINE_SHIM: &str = "/usr/lib/limbo/bin/wine";

/// deps.Missing: the required commands not on PATH.
pub fn missing() -> Vec<(&'static str, &'static str, &'static str)> {
    REQUIRED.iter().copied().filter(|(c, _, _)| goexec::look_path(c).is_err()).collect()
}

/// deps.Packages: the packages of the missing commands, once each, sorted.
pub fn packages(missing: &[(&str, &str, &str)]) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for (_, p, _) in missing {
        if !out.iter().any(|x| x == p) {
            out.push(p.to_string());
        }
    }
    out.sort();
    out
}

fn exists(p: &str) -> bool {
    std::fs::metadata(p).is_ok()
}

fn has_group(name: &str) -> bool {
    goexec::run("getent", &["group".to_string(), name.to_string()]).is_ok()
}

/// fmt's %-20s: padded with spaces to 20 characters.
fn pad20(s: &str) -> String {
    let n = s.chars().count();
    format!("{s}{}", " ".repeat(20usize.saturating_sub(n)))
}

/// What realSetupEnv's skippedProfiles finds: the validation profiles that exist but are not offered.
fn skipped_profiles() -> Vec<runs::Skipped> {
    let ev: Arc<Recorder> = Arc::new(Recorder::default()); // Go's Manager here has no event log
    let eng = Arc::new(engine::Engine::new(Arc::new(engine::Exec), ev.clone(), ""));
    let mut m = runs::Manager::new("/etc/limbo/validation", "", eng, Arc::new(runs::Ssh), ev);
    m.images = Arc::new(Proofs::new(&sys::join(&[super::local::DAEMON_STATE_DIR, crate::image::PROOFS_FILE]), 0));
    m.skipped_all()
}

fn doctor_wine(io: &mut Io) {
    let _ = writeln!(io.out, "\nWine backend (limbo wine; optional):");
    let line = |io: &mut Io, good: bool, ok: &str, note: &str| {
        if good {
            let _ = writeln!(io.out, "  ok       {ok}");
        } else {
            let _ = writeln!(io.out, "  NOTE     {note}");
        }
    };
    line(
        io,
        exists("/usr/bin/bwrap"),
        "bubblewrap (the sandbox every Wine run is in)",
        "bubblewrap is not installed: limbo wine refuses to run without it (sudo pacman -S bubblewrap)",
    );
    let has_wine = exists("/usr/bin/wine");
    line(io, has_wine, "wine", "Wine is not installed (sudo pacman -S wine, or wine-staging)");
    if !has_wine {
        return;
    }
    match goexec::look_path("wine") {
        Ok(p) => {
            let real = std::fs::canonicalize(&p).map(|r| r.to_string_lossy().into_owned()).unwrap_or_else(|_| p.clone());
            if real == WINE_SHIM {
                line(io, true, &format!("`wine` on PATH is Limbo's ({p}): programs that run wine land in the sandbox"), "");
            } else {
                line(
                    io,
                    false,
                    "",
                    &format!("`wine` on PATH is {p}: a program that runs wine bypasses Limbo. To send it through Limbo: sudo ln -s {WINE_SHIM} /usr/local/bin/wine"),
                );
            }
        }
        Err(_) => line(io, false, "", "no `wine` on PATH"),
    }
}

/// doctor: what is and is not ready; whether Limbo can run guests here. Changes nothing.
pub fn doctor(io: &mut Io) -> bool {
    let mut ok = true;
    let _ = writeln!(io.out, "Runtime dependencies:");
    let miss = missing();
    for (c, p, purpose) in REQUIRED {
        if miss.iter().any(|m| m.0 == c) {
            let _ = writeln!(io.out, "  MISSING  {} {purpose} (package {p})", pad20(c));
            ok = false;
        } else {
            let _ = writeln!(io.out, "  ok       {} {purpose}", pad20(c));
        }
    }
    let _ = writeln!(io.out, "\nSystem:");
    let mut check = |io: &mut Io, good: bool, okm: &str, bad: &str| {
        if good {
            let _ = writeln!(io.out, "  ok       {okm}");
        } else {
            let _ = writeln!(io.out, "  MISSING  {bad}");
            ok = false;
        }
    };
    check(
        io,
        exists("/dev/kvm"),
        "/dev/kvm (hardware virtualization is available)",
        "/dev/kvm: no hardware virtualization here (enable VT-x/AMD-V, or nested virtualization in a VM)",
    );
    let groups = has_group("limbo-heimdall") && has_group("limbo-agent") && has_group("limbo-users");
    check(
        io,
        groups,
        "groups limbo-heimdall, limbo-agent and limbo-users exist",
        "groups limbo-heimdall / limbo-agent / limbo-users: run `sudo limbo setup` (or install the package so sysusers creates them)",
    );
    let sk = skipped_profiles();
    if !sk.is_empty() {
        let _ = writeln!(io.out, "\nValidation profiles that exist but are not offered:");
        for s in &sk {
            let name = if s.name.is_empty() { "(unnamed file)" } else { s.name.as_str() };
            let _ = writeln!(io.out, "  SKIPPED  {} {}: {}. {}", pad20(name), s.code, s.reason, s.remedy);
        }
    }
    doctor_wine(io);
    if !miss.is_empty() {
        let _ = writeln!(io.out, "\nFix: sudo limbo setup   (installs: {})", packages(&miss).join(" "));
    }
    ok
}

pub fn doctor_cmd(args: &[String], io: &mut Io) -> Result<(), Fail> {
    let mut fs = FlagSet::new("doctor");
    let mut stderr = vec![];
    let r = parse_interspersed(&mut fs, args.to_vec(), &mut stderr);
    let _ = io.err.write_all(&stderr);
    r.map_err(Fail::Msg)?;
    if !doctor(io) {
        return Err(Fail::Msg("doctor: Limbo cannot run guests on this system yet".into()));
    }
    Ok(())
}

/// env.run: the program with this process's stdin, stdout and stderr (what it prints is the person's to see).
fn run_visible(io: &mut Io, name: &str, args: &[String]) -> Result<(), String> {
    let _ = io.out.flush();
    goexec::run_inherit(name, args)
}

/// env.confirm: the prompt, then one line of stdin starting with y or Y.
fn confirm(io: &mut Io, prompt: &str) -> bool {
    let _ = write!(io.out, "{prompt} [y/N] ");
    let _ = io.out.flush();
    // bufio.Reader.ReadString('\n') over stdin: one read of up to 4096 bytes at a time until a newline or the end
    let mut line = vec![];
    let mut buf = [0u8; 4096];
    loop {
        match io.stdin.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if let Some(i) = buf[..n].iter().position(|&c| c == b'\n') {
                    line.extend_from_slice(&buf[..=i]);
                    break;
                }
                line.extend_from_slice(&buf[..n]);
            }
        }
    }
    let t = crate::gotext::to_lower(&crate::gotext::lossy(trim_space(&line)));
    t.starts_with('y')
}

pub fn setup_cmd(args: &[String], io: &mut Io) -> Result<(), Fail> {
    let mut fs = FlagSet::new("setup");
    fs.bool("yes", false, "do not ask for confirmation");
    fs.bool("upgrade", false, "run a full system upgrade (pacman -Syu) before installing; needed when the package database is stale");
    fs.bool("enable-service", false, "also enable and start limbo.service (the control API)");
    let mut stderr = vec![];
    let r = parse_interspersed(&mut fs, args.to_vec(), &mut stderr);
    let _ = io.err.write_all(&stderr);
    r.map_err(Fail::Msg)?;
    let (yes, upgrade, service) = (fs.is_true("yes"), fs.is_true("upgrade"), fs.is_true("enable-service"));
    if io.euid != 0 {
        return Err(Fail::Msg("setup: must run as root (it installs packages and enables services): sudo limbo setup".into()));
    }
    let miss = missing();
    let pkgs = packages(&miss);
    let _ = writeln!(io.out, "Limbo setup will:");
    if !pkgs.is_empty() {
        let verb = if upgrade { "pacman -Syu --needed  (a FULL system upgrade, then these)" } else { "pacman -S --needed" };
        let _ = writeln!(io.out, "  - install: {}   [{verb}]", pkgs.join(" "));
    } else {
        let _ = writeln!(io.out, "  - install nothing: every runtime dependency is already present");
    }
    let _ = writeln!(io.out, "  - enable libvirt's socket-activated daemons ({})", LIBVIRT_SOCKETS.join(", "));
    let _ = writeln!(
        io.out,
        "  - create the limbo-heimdall, limbo-agent and limbo-users groups (from the package's sysusers file, or directly when run without the package)"
    );
    if service {
        let _ = writeln!(io.out, "  - enable and start limbo.service (the control API)");
    }
    let _ = writeln!(io.out);
    if !yes && !confirm(io, "Proceed?") {
        return Err(Fail::Msg("setup: cancelled; nothing was changed".into()));
    }
    let s = |v: &[&str]| -> Vec<String> { v.iter().map(|x| x.to_string()).collect() };
    if !pkgs.is_empty() {
        if goexec::look_path("pacman").is_err() {
            return Err(Fail::Msg(format!(
                "setup: this system has no pacman; install these with your package manager and run `limbo doctor`: {}",
                pkgs.join(" ")
            )));
        }
        let mut a = if upgrade { s(&["-Syu", "--needed", "--noconfirm"]) } else { s(&["-S", "--needed", "--noconfirm"]) };
        a.extend(pkgs.iter().cloned());
        if let Err(e) = run_visible(io, "pacman", &a) {
            return Err(Fail::Msg(format!(
                "setup: pacman failed: {e}\n\nIf it says a package was not found or a dependency conflicts, the package database is probably out of date.\n\
                 Update the system first (sudo pacman -Syu) and run `sudo limbo setup` again,\nor run `sudo limbo setup --upgrade` to do both now."
            )));
        }
    }
    if exists("/usr/lib/sysusers.d/limbo.conf") {
        run_visible(io, "systemd-sysusers", &s(&["/usr/lib/sysusers.d/limbo.conf"]))
            .map_err(|e| Fail::Msg(format!("setup: creating groups: {e}")))?;
    } else {
        for g in ["limbo-heimdall", "limbo-agent", "limbo-users"] {
            if has_group(g) {
                continue;
            }
            run_visible(io, "groupadd", &s(&["--system", g])).map_err(|e| Fail::Msg(format!("setup: creating group {g}: {e}")))?;
        }
    }
    let mut a = s(&["enable", "--now"]);
    a.extend(s(&LIBVIRT_SOCKETS));
    run_visible(io, "systemctl", &a).map_err(|e| Fail::Msg(format!("setup: enabling libvirt: {e}")))?;
    if service {
        run_visible(io, "systemctl", &s(&["enable", "--now", "limbo.service"]))
            .map_err(|e| Fail::Msg(format!("setup: enabling limbo.service: {e}")))?;
    }
    let _ = writeln!(io.out, "\nSetup finished. Checking:");
    if !doctor(io) {
        return Err(Fail::Msg("setup: finished, but `limbo doctor` still reports problems (above)".into()));
    }
    Ok(())
}
