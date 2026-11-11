//! The Go CLI's guest commands (cmd/limbo/main.go: act, prepareLaunch, launchCheck, export, screenshot,
//! giveToSudoUser): `limbo up | down | launch | export | screenshot`. up and down drive the engine the daemon uses
//! (crate::engine, pinned by `engine.json`); launch gates on the hold and the pinned key and hands the terminal to
//! waypipe or FreeRDP. Same output, errors, events, files and host commands as Go; rust/parity/cli-differential.py
//! compares the two binaries with fake host programs.

use super::commands::{self, Fail, Io};
use super::goexec;
use crate::engine::{self, Ctx, Engine};
use crate::events::{self, Emitter};
use crate::gotext::{self, quote};
use crate::hostpolicy::Policy;
use crate::image::{self, Proofs};
use crate::manifest::Manifest;
use crate::quarantine::Store;
use crate::virt::{self, Subnets};
use crate::{detail, gojson, launch, license, sys};
use std::sync::Arc;

/// deps.Preflight: every runtime command on PATH, or what is missing and the one command that fixes it.
fn preflight() -> Result<(), String> {
    let missing = super::setup::missing();
    if missing.is_empty() {
        return Ok(());
    }
    let parts: Vec<String> = missing.iter().map(|(c, p, _)| format!("{c} ({p})")).collect();
    Err(format!("Limbo's runtime dependencies are not installed: {}. Run: sudo limbo setup", parts.join(", ")))
}

/// act: up, down and launch (the state folder already checked).
pub fn act(cmd: &str, mut m: Manifest, state: &str, check: bool, identity: &str, io: &mut Io) -> Result<(), Fail> {
    if cmd == "up" || cmd == "down" {
        preflight()?;
    }
    let log = Arc::new(events::Logger::open_go(&sys::join(&[state, "events.jsonl"]))?);
    let store = Arc::new(Store::open(&sys::join(&[state, "quarantine"]))?);
    let mut e = Engine::new(Arc::new(engine::Exec), log.clone(), state);
    e.holds = Some(store.clone());
    e.hardware = Some(Arc::new(Policy::new(state, "")));
    e.ufw_active = Some(crate::hostfw::ufw_active);
    e.exchange_root = crate::instances::DEFAULT_EXCHANGE_ROOT.into();
    e.subnets = Some(Subnets { path: sys::join(&[state, "subnets.json"]), in_use: None });
    e.images = Some(Arc::new(Proofs::new(&sys::join(&[state, image::PROOFS_FILE]), 0)));
    let ctx = Ctx::background();
    match cmd {
        "up" => return e.up(&ctx, &mut m).map_err(|e| Fail::Msg(e.to_string())),
        "down" => return e.down(&ctx, &m).map_err(|e| Fail::Msg(e.to_string())),
        _ => {}
    }
    let (c, tmp) = prepare_launch(&m, state, &store, log.as_ref(), io)?;
    let _cleanup = Remove(tmp);
    let c = launch::with_identity(c, identity);
    if check {
        return launch_check(&m, &c, io);
    }
    log.emit(events::APP_LAUNCH, &m.name, detail([("app", &m.app.name)])).map_err(|e| Fail::Msg(sys::go_err(&e)))?;
    let _ = io.out.flush();
    goexec::run_inherit(&c.args[0], &c.args[1..]).map_err(Fail::Msg)
}

/// Removes the known_hosts file when the launch ends (Go's deferred cleanup).
struct Remove(String);

impl Drop for Remove {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// launchView: what a person's launch asks Limbo about the guest.
#[derive(Default)]
struct View {
    running: bool,
    address: String,
    hold: Option<Hold>,
}
#[derive(Default)]
struct Hold {
    id: String,
    status: String,
}
crate::go_struct!(Hold as "" { id: "id" => "string", status: "status" => "string" });
crate::go_struct!(View as "main.launchView" {
    running: "running" => "bool", address: "address" => "string",
    hold: "hold" => "*struct { ID string \"json:\\\"id\\\"\"; Status string \"json:\\\"status\\\"\" }",
});

fn ask_limbo(name: &str) -> Result<View, String> {
    let raw = commands::do_json(commands::USER_SOCK, "GET", &format!("/v1/instances/{name}"), None)?;
    gojson::unmarshal(&raw, View::default(), "main.launchView").map_err(|e| e.0)
}

/// prepareLaunch: every check launch needs, and the client's command with the known_hosts file it reads.
fn prepare_launch(m: &Manifest, state: &str, store: &Store, log: &dyn Emitter, io: &Io) -> Result<(launch::Command, String), Fail> {
    let refuse = |reason: String| -> Fail {
        let _ = log.emit(events::GATE_BLOCKED, &m.name, detail([("reason", &reason)]));
        Fail::Msg(format!("engine: guest is quarantined: {reason}"))
    };
    let addr = if io.euid == 0 {
        if let Some(rec) = crate::quarantine::Holder::holding(store, &m.name) {
            return Err(refuse(format!("guest is quarantined ({}, {})", rec.id, rec.status)));
        }
        super::local::guest_address(m, state)?
    } else {
        let v = ask_limbo(&m.name).map_err(|e| {
            format!(
                "launch: Limbo could not be asked whether {} is held ({e}); a person's launch goes through user.sock: join the \
                 limbo-users group (sudo gpasswd -a $USER limbo-users, then log in again)",
                m.name
            )
        })?;
        if let Some(h) = &v.hold {
            return Err(refuse(format!("guest is quarantined ({}, {})", h.id, h.status)));
        }
        if !v.running || v.address.is_empty() {
            return Err(Fail::Msg(format!("launch: {} is not running", m.name)));
        }
        v.address
    };
    if let Err(e) = license::check(m) {
        let _ = log.emit(events::GATE_BLOCKED, &m.name, detail([("reason", &e)]));
        return Err(Fail::Msg(e));
    }
    let (n, v) = sscanf_dotted(&addr);
    if n != 4 || v[0] != 10 || v[1] != 213 || v[2] < 1 || v[2] > 254 || v[3] != 2 {
        return Err(Fail::Msg(format!("launch: {} is not a Limbo guest address", quote(&addr))));
    }
    let mut cp = m.clone();
    cp.subnet = v[2];
    let line = launch::known_hosts_line(&cp)?;
    let path = create_temp("limbo-known-hosts-", (io.env)("TMPDIR"))?;
    let cleanup = Remove(path.clone());
    sys::write_file(&path, line.as_bytes(), 0o600).map_err(|e| sys::go_path_error("write", &path, &e))?;
    let c = launch::build(&cp, &path)?;
    std::mem::forget(cleanup);
    Ok((c, path))
}

/// os.CreateTemp("", PREFIX+"*"): os.TempDir() ($TMPDIR, else /tmp) joined as Go joins it (no cleaning), a random
/// uint32 in decimal, made 0600 and never an existing file.
fn create_temp(prefix: &str, tmpdir: String) -> Result<String, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = if tmpdir.is_empty() { "/tmp".to_string() } else { tmpdir };
    let base = if dir.ends_with('/') { format!("{dir}{prefix}") } else { format!("{dir}/{prefix}") };
    let mut tries = 0;
    loop {
        let mut b = [0u8; 4];
        let _ = rustix::rand::getrandom(&mut b, rustix::rand::GetRandomFlags::empty());
        let name = format!("{base}{}", u32::from_ne_bytes(b));
        match std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&name) {
            Ok(_) => return Ok(name),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && tries < 10_000 => tries += 1,
            Err(e) => return Err(sys::go_path_error("open", &name, &e)),
        }
    }
}

/// `fmt.Sscanf(s, "%d.%d.%d.%d", ...)`: how many of the four were read, and their values.
pub fn sscanf_dotted(s: &str) -> (usize, [i64; 4]) {
    let mut v = [0i64; 4];
    let mut rest = s;
    for i in 0..4 {
        if i > 0 {
            match rest.strip_prefix('.') {
                Some(r) => rest = r,
                None => return (i, v),
            }
        }
        match super::local::scan_int(rest) {
            Some((x, used)) => {
                v[i] = x;
                rest = &rest[used..];
            }
            None => return (i, v),
        }
    }
    (4, v)
}

/// launchCheck: the gates passed; then ssh with the pinned key, the app and waypipe in the guest, waypipe and a
/// Wayland display here. One line per check; an error if any failed.
fn launch_check(m: &Manifest, c: &launch::Command, io: &mut Io) -> Result<(), Fail> {
    let _ = writeln!(io.out, "ok    {} is running, not held, and its host key is pinned", m.name);
    let mut failed = 0;
    let mut report = |io: &mut Io, ok: bool, good: &[u8], bad: &[u8]| {
        if ok {
            let _ = io.out.write_all(b"ok    ");
            let _ = io.out.write_all(good);
        } else {
            let _ = io.out.write_all(b"FAIL  ");
            let _ = io.out.write_all(bad);
            failed += 1;
        }
        let _ = io.out.write_all(b"\n");
    };
    let app: Vec<&str> = gotext::fields(&m.app.exec).collect();
    let mut remote = "true".to_string();
    if let Some(a) = app.first() {
        remote = format!("command -v -- {} >/dev/null && command -v waypipe >/dev/null", shell_quote(a));
    }
    for (i, r) in ["true", remote.as_str()].iter().enumerate() {
        let args = launch::check_args(c, r)?;
        let (out, err) = goexec::combined_output_timeout(&args[0], &args[1..], std::time::Duration::from_secs(20));
        let mut msg = commands::trim_space(&out).to_vec();
        msg.truncate(200);
        if i == 0 {
            let mut bad = b"ssh with the pinned key failed: ".to_vec();
            bad.extend_from_slice(&msg);
            report(io, err.is_ok(), b"ssh reaches the guest and it shows the pinned host key", &bad);
            if err.is_err() {
                break;
            }
        } else if app.is_empty() {
            report(io, false, b"", b"app.exec names no program to look for in the guest");
        } else {
            report(
                io,
                err.is_ok(),
                format!("the guest has {} and waypipe", quote(app[0])).as_bytes(),
                format!("the guest lacks {} or waypipe (install them in its image)", quote(app[0])).as_bytes(),
            );
        }
    }
    let wp = goexec::look_path("waypipe").is_ok();
    report(io, wp, b"waypipe is installed here", b"waypipe is not installed here (sudo pacman -S waypipe)");
    let wl = !(io.env)("WAYLAND_DISPLAY").is_empty();
    report(io, wl, b"a Wayland display is here", b"no Wayland display here (WAYLAND_DISPLAY is not set): run launch from the desktop");
    if failed > 0 {
        return Err(Fail::Msg(format!("launch check: {failed} of the checks failed")));
    }
    Ok(())
}

/// shellQuote: one word for the guest's shell.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// giveToSudoUser: a file root made, handed to the person who ran sudo.
fn give_to_sudo_user(io: &Io, path: &str) {
    let uid = (io.env)("SUDO_UID").parse::<i64>();
    let gid = (io.env)("SUDO_GID").parse::<i64>();
    if let (true, Ok(uid), Ok(gid)) = (io.euid == 0, uid, gid) {
        if let Ok(p) = std::ffi::CString::new(path) {
            // SAFETY: a valid C string; chown follows the link as os.Chown does; the ids are truncated to 32 bits as
            // the system call takes them
            unsafe {
                libc::chown(p.as_ptr(), uid as u32, gid as u32);
            }
        }
    }
}

const CONNECT: &str = "qemu:///system";

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// export: a stopped guest's disk as one standalone image at `out`, with its SHA-256 for a manifest.
pub fn export(m: &Manifest, state: &str, out: &str, io: &mut Io) -> Result<(), Fail> {
    if !out.starts_with('/') {
        return Err("export: the output image needs an absolute path".into());
    }
    if std::fs::symlink_metadata(out).is_ok() {
        return Err(Fail::Msg(format!("export: {out} exists; pick a new name")));
    }
    let (st, r) = goexec::output("virsh", &strs(&["-c", CONNECT, "domstate", &virt::domain_name(m)]));
    if r.is_ok() && !st.windows(8).any(|w| w == b"shut off") {
        return Err(Fail::Msg(format!(
            "export: {} is {}; it must be shut off (limbo down after it finishes)",
            m.name,
            gotext::lossy(commands::trim_space(&st))
        )));
    }
    let disk = sys::join(&[state, &virt::disk_name(m)]);
    if std::fs::metadata(&disk).is_err() {
        return Err(Fail::Msg(format!("export: {} has no disk in {state} (a disposable guest's disk is gone after down)", m.name)));
    }
    let (b, r) = goexec::combined_output("qemu-img", &strs(&["convert", "-O", "qcow2", &disk, out]));
    if let Err(e) = r {
        return Err(Fail::Msg(format!("qemu-img convert: {e}: {}", gotext::lossy(&b))));
    }
    give_to_sudo_user(io, out);
    let f = std::fs::File::open(out).map_err(|e| sys::go_path_error("open", out, &e))?;
    let sum = image::hash_open(&f).map_err(|e| sys::go_path_error("read", out, &e))?;
    let _ = writeln!(io.out, "wrote {out}\n  \"image\": {{\"path\": {}, \"sha256\": {}}}", quote(out), quote(&sum));
    Ok(())
}

/// screenshot: what the guest's screen shows, saved by libvirt.
pub fn screenshot(m: &Manifest, out: &str, io: &mut Io) -> Result<(), Fail> {
    if !out.starts_with('/') {
        return Err("screenshot: the output file needs an absolute path".into());
    }
    let (b, r) = goexec::combined_output("virsh", &strs(&["-c", CONNECT, "screenshot", &virt::domain_name(m), out]));
    if let Err(e) = r {
        return Err(Fail::Msg(format!("virsh screenshot: {e}: {}", gotext::lossy(&b))));
    }
    give_to_sudo_user(io, out);
    let _ = writeln!(io.out, "wrote {out}");
    Ok(())
}
