//! Bringing a guest up and down (Go: internal/engine and internal/runner). The ordering rule that matters: the guest's
//! firewall table is loaded before the guest starts, and anything that fails after partial setup is torn back down. All
//! side effects go through a Runner, so the tests and the Go fixtures compare the exact command sequence.

use crate::events::{self, Emitter};
use crate::hostpolicy::{Policy, Refused};
use crate::image::{CheckErr, Proofs};
use crate::manifest::{self, Manifest};
use crate::quarantine::{self, Holder};
use crate::virt::{self, Subnets};
use crate::{detail, disk, exchange, gotext, hostfw, license, policy, sys, Detail};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CONNECT: &str = "qemu:///system";

/// Go's context, as far as the engine needs it: a deadline and cancel flags (a child is cancelled with its parents).
#[derive(Clone, Default)]
pub struct Ctx {
    pub deadline: Option<Instant>,
    pub cancels: Vec<Arc<AtomicBool>>,
}

impl Ctx {
    pub fn background() -> Ctx {
        Ctx::default()
    }
    pub fn with_timeout(&self, d: Duration) -> Ctx {
        let dl = Instant::now() + d;
        Ctx { deadline: Some(self.deadline.map_or(dl, |x| x.min(dl))), cancels: self.cancels.clone() }
    }
    /// A child context and the flag that cancels it.
    pub fn with_cancel(&self) -> (Ctx, Arc<AtomicBool>) {
        let c = Arc::new(AtomicBool::new(false));
        let mut child = self.clone();
        child.cancels.push(c.clone());
        (child, c)
    }
    pub fn deadline_exceeded(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }
    pub fn cancelled(&self) -> bool {
        self.cancels.iter().any(|c| c.load(Ordering::SeqCst))
    }
    pub fn done(&self) -> bool {
        self.deadline_exceeded() || self.cancelled()
    }
}

/// Why a command failed, as Go's exec reports it, with what runs classify on.
#[derive(Clone, Debug, PartialEq)]
pub struct CmdErr {
    pub text: String,
    pub not_found: bool,
}

/// Executes host commands. `Exec` is the real one; the tests record instead.
pub trait Runner: Send + Sync {
    fn run(&self, ctx: &Ctx, stdin: &str, name: &str, args: &[String]) -> Result<(), CmdErr>;
    fn output(&self, ctx: &Ctx, name: &str, args: &[String]) -> Result<String, CmdErr>;
}

pub struct Exec;

/// Waits for a child until it exits or the context ends (then it is killed): (status, killed). The wait sleeps in
/// poll(2) on a pidfd, so a command's end is seen at once; a cancel is noticed within 100 ms.
pub fn wait_ctx(ctx: &Ctx, child: &mut std::process::Child) -> std::io::Result<(std::process::ExitStatus, bool)> {
    if ctx.deadline.is_none() && ctx.cancels.is_empty() {
        return child.wait().map(|s| (s, false));
    }
    let pidfd = rustix::process::Pid::from_raw(child.id() as i32)
        .and_then(|p| rustix::process::pidfd_open(p, rustix::process::PidfdFlags::empty()).ok());
    loop {
        if let Some(s) = child.try_wait()? {
            return Ok((s, false));
        }
        if ctx.done() {
            let _ = child.kill();
            return child.wait().map(|s| (s, true));
        }
        let mut wait_ms: u64 = 100;
        if let Some(d) = ctx.deadline {
            wait_ms = wait_ms.min(d.saturating_duration_since(Instant::now()).as_millis() as u64 + 1);
        }
        match &pidfd {
            Some(fd) => {
                let mut fds = [rustix::event::PollFd::new(fd, rustix::event::PollFlags::IN)];
                let t = rustix::event::Timespec { tv_sec: (wait_ms / 1000) as i64, tv_nsec: ((wait_ms % 1000) * 1_000_000) as i64 };
                let _ = rustix::event::poll(&mut fds, Some(&t));
            }
            None => std::thread::sleep(Duration::from_millis(wait_ms.min(25))),
        }
    }
}

pub fn status_text(s: &std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (s.code(), s.signal()) {
        (Some(c), _) => format!("exit status {c}"),
        (None, Some(sig)) => format!("signal: {}", signal_name(sig)),
        _ => "exit status -1".into(),
    }
}

fn signal_name(sig: i32) -> &'static str {
    match sig {
        libc::SIGKILL => "killed",
        libc::SIGTERM => "terminated",
        libc::SIGINT => "interrupt",
        libc::SIGSEGV => "segmentation fault",
        libc::SIGABRT => "aborted",
        libc::SIGPIPE => "broken pipe",
        libc::SIGHUP => "hangup",
        _ => "signal",
    }
}

/// exec.LookPath's error, as Go words it.
pub fn not_found(name: &str) -> CmdErr {
    CmdErr { text: format!("exec: {}: executable file not found in $PATH", gotext::quote(name)), not_found: true }
}

fn cmd_err(name: &str, args: &[String], what: &str, stderr: &[u8]) -> String {
    format!("{name} {}: {what}: {}", args.join(" "), gotext::trim_space(&gotext::lossy(stderr)))
}

impl Runner for Exec {
    fn run(&self, ctx: &Ctx, stdin: &str, name: &str, args: &[String]) -> Result<(), CmdErr> {
        if ctx.done() {
            let why = if ctx.cancelled() { "context canceled" } else { "context deadline exceeded" };
            return Err(CmdErr { text: cmd_err(name, args, why, b""), not_found: false });
        }
        let Some(path) = exchange::look_path(name) else {
            let nf = not_found(name);
            return Err(CmdErr { text: cmd_err(name, args, &nf.text, b""), not_found: true });
        };
        let mut c = Command::new(path);
        c.args(args).stdout(Stdio::null()).stderr(Stdio::piped());
        c.stdin(if stdin.is_empty() { Stdio::null() } else { Stdio::piped() });
        let mut child = c.spawn().map_err(|e| CmdErr { text: cmd_err(name, args, &sys::go_err(&e), b""), not_found: false })?;
        if !stdin.is_empty() {
            if let Some(mut w) = child.stdin.take() {
                let s = stdin.to_string();
                std::thread::spawn(move || {
                    let _ = w.write_all(s.as_bytes());
                });
            }
        }
        let mut errb = Vec::new();
        let mut se = child.stderr.take();
        let reader = std::thread::spawn(move || {
            let mut b = Vec::new();
            if let Some(s) = se.as_mut() {
                let _ = s.read_to_end(&mut b);
            }
            b
        });
        let (st, _) =
            wait_ctx(ctx, &mut child).map_err(|e| CmdErr { text: cmd_err(name, args, &sys::go_err(&e), b""), not_found: false })?;
        if let Ok(b) = reader.join() {
            errb = b;
        }
        if st.success() {
            return Ok(());
        }
        Err(CmdErr { text: cmd_err(name, args, &status_text(&st), &errb), not_found: false })
    }

    fn output(&self, ctx: &Ctx, name: &str, args: &[String]) -> Result<String, CmdErr> {
        let Some(path) = exchange::look_path(name) else {
            let nf = not_found(name);
            return Err(CmdErr { text: cmd_err(name, args, &nf.text, b""), not_found: true });
        };
        let mut child = Command::new(path)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CmdErr { text: cmd_err(name, args, &sys::go_err(&e), b""), not_found: false })?;
        let mut so = child.stdout.take();
        let mut se = child.stderr.take();
        let out_t = std::thread::spawn(move || {
            let mut b = Vec::new();
            let mut chunk = [0u8; 8192];
            if let Some(s) = so.as_mut() {
                while let Ok(n) = s.read(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    // at most 1 MiB is kept; the rest is read and dropped (Go's limitWriter)
                    let room = (1usize << 20).saturating_sub(b.len());
                    b.extend_from_slice(&chunk[..n.min(room)]);
                }
            }
            b
        });
        let err_t = std::thread::spawn(move || {
            let mut b = Vec::new();
            if let Some(s) = se.as_mut() {
                let _ = s.read_to_end(&mut b);
            }
            b
        });
        let (st, _) = wait_ctx(ctx, &mut child).map_err(|e| CmdErr { text: sys::go_err(&e), not_found: false })?;
        let out = out_t.join().unwrap_or_default();
        let errb = err_t.join().unwrap_or_default();
        if st.success() {
            return Ok(gotext::lossy_owned(out));
        }
        Err(CmdErr { text: cmd_err(name, args, &status_text(&st), &errb), not_found: false })
    }
}

/// What can go wrong in the engine, with what callers tell apart.
#[derive(Clone, Debug, PartialEq)]
pub enum EngineErr {
    Quarantined(String),
    Hardware(Refused),
    NoPolicy,
    Image(CheckErr),
    Cmd(CmdErr),
    Other(String),
}

impl std::fmt::Display for EngineErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineErr::Quarantined(r) => write!(f, "engine: guest is quarantined: {r}"),
            EngineErr::Hardware(r) => write!(f, "engine: hardware passthrough denied: {r}"),
            EngineErr::NoPolicy => f.write_str("engine: hardware passthrough denied: no host policy is configured"),
            EngineErr::Image(e) => write!(f, "{e}"),
            EngineErr::Cmd(c) => f.write_str(&c.text),
            EngineErr::Other(s) => f.write_str(s),
        }
    }
}

fn other(e: impl std::fmt::Display) -> EngineErr {
    EngineErr::Other(e.to_string())
}

fn io_other(e: std::io::Error) -> EngineErr {
    EngineErr::Other(sys::go_err(&e))
}

pub struct Engine {
    pub runner: Arc<dyn Runner>,
    pub events: Arc<dyn Emitter>,
    pub state_dir: String,
    pub holds: Option<Arc<dyn Holder>>,
    pub hardware: Option<Arc<Policy>>,
    pub ufw_active: Option<fn() -> bool>,
    pub exchange_root: String,
    pub subnets: Option<Subnets>,
    pub images: Option<Arc<Proofs>>,
    before: Mutex<BTreeMap<String, Option<BTreeMap<String, String>>>>,
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// Where Up leaves the copy of a guest's manifest.
pub fn manifest_path(state_dir: &str, guest: &str) -> String {
    sys::join(&[state_dir, &format!("{guest}.manifest.json")])
}

/// The manifest Up recorded for a guest, read back by name only.
pub fn load_guest(state_dir: &str, guest: &str) -> Result<Manifest, String> {
    let probe = Manifest { name: guest.to_string(), ..Manifest::default() };
    probe.validate_name()?;
    let m = manifest::load(&manifest_path(state_dir, guest))
        .map_err(|e| format!("engine: no record of a running guest {}: {e}", gotext::quote(guest)))?;
    if m.name != guest {
        return Err(format!("engine: manifest record for {} names a different guest", gotext::quote(guest)));
    }
    Ok(m)
}

impl Engine {
    pub fn new(runner: Arc<dyn Runner>, events: Arc<dyn Emitter>, state_dir: &str) -> Engine {
        Engine {
            runner,
            events,
            state_dir: state_dir.to_string(),
            holds: None,
            hardware: None,
            ufw_active: None,
            exchange_root: String::new(),
            subnets: None,
            images: None,
            before: Mutex::new(BTreeMap::new()),
        }
    }

    fn emit(&self, kind: &str, guest: &str, d: Detail) -> Result<(), EngineErr> {
        self.events.emit(kind, guest, d).map_err(io_other)
    }

    fn virsh(&self, ctx: &Ctx, args: &[&str]) -> Result<(), EngineErr> {
        let mut a = s(&["-c", CONNECT]);
        a.extend(args.iter().map(|x| x.to_string()));
        self.runner.run(ctx, "", "virsh", &a).map_err(EngineErr::Cmd)
    }

    pub fn check_hardware(&self, m: &Manifest) -> Result<(), EngineErr> {
        if !m.devices.any() {
            return Ok(());
        }
        match &self.hardware {
            None => Err(EngineErr::NoPolicy),
            Some(h) => h.check(m).map_err(EngineErr::Hardware),
        }
    }

    pub fn ready_hardware(&self, m: &Manifest) -> Result<(), EngineErr> {
        if !m.devices.any() {
            return Ok(());
        }
        match &self.hardware {
            None => Err(EngineErr::NoPolicy),
            Some(h) => h.ready(m).map_err(EngineErr::Hardware),
        }
    }

    /// Verifies, configures and starts the guest. `m.subnet` is set to the guest's allocated subnet.
    pub fn up(&self, ctx: &Ctx, m: &mut Manifest) -> Result<(), EngineErr> {
        let g = m.name.clone();
        if let Some(h) = &self.holds {
            if let Some(rec) = h.holding(&g) {
                let reason = format!("guest is quarantined ({}, {})", rec.id, rec.status);
                let _ = self.events.emit(events::GATE_BLOCKED, &g, detail([("reason", &reason)]));
                return Err(EngineErr::Quarantined(reason));
            }
        }
        for check in [Self::check_hardware, Self::ready_hardware] {
            if let Err(e) = check(self, m) {
                let _ = self.events.emit(
                    events::GATE_BLOCKED,
                    &g,
                    detail([("reason", &e.to_string()), ("pci", &m.devices.pci().join(",")), ("usb", &m.devices.usb().join(","))]),
                );
                return Err(e);
            }
        }
        if !m.devices.pci().is_empty() {
            let b = self.hardware.as_ref().map(|h| h.before(m));
            self.before.lock().unwrap_or_else(|e| e.into_inner()).insert(g.clone(), b);
        }
        if let Err(e) = self.exchange_safe(m) {
            let _ = self.events.emit(events::GATE_BLOCKED, &g, detail([("reason", &e)]));
            return Err(EngineErr::Other(e));
        }
        if let Err(e) = license::check(m) {
            let _ = self.events.emit(events::GATE_BLOCKED, &g, detail([("reason", &e)]));
            return Err(EngineErr::Other(e));
        }
        let (how, r) = match &self.images {
            Some(p) => p.check(&m.image.path, &m.image.sha256),
            None => Proofs::new("", 0).check(&m.image.path, &m.image.sha256),
        };
        if let Err(e) = r {
            let _ = self.events.emit(events::IMAGE_REJECTED, &g, detail([("reason", &e.to_string())]));
            return Err(EngineErr::Image(e));
        }
        self.emit(events::IMAGE_VERIFIED, &g, detail([("sha256", &m.image.sha256), ("check", how)]))?;
        if let Some(sn) = &self.subnets {
            match sn.allocate(&g) {
                Ok(x) => m.subnet = x,
                Err(e) => {
                    let _ = self.events.emit(events::GATE_BLOCKED, &g, detail([("reason", &e)]));
                    return Err(EngineErr::Other(e));
                }
            }
        }
        let r = self.up_defined(ctx, m);
        if r.is_err() {
            if let Some(sn) = &self.subnets {
                let _ = sn.release(&g);
            }
        }
        r
    }

    fn up_defined(&self, ctx: &Ctx, m: &Manifest) -> Result<(), EngineErr> {
        let g = &m.name;
        let root_disk = sys::join(&[&self.state_dir, &virt::disk_name(m)]);
        let net_xml = virt::network_xml(m);
        let dom_xml = virt::domain_xml(m, &root_disk).map_err(other)?;
        let rules = policy::nft(m).map_err(other)?;
        sys::mkdir_all(&self.state_dir, 0o700).map_err(io_other)?;
        let net_path = sys::join(&[&self.state_dir, &format!("{g}.network.xml")]);
        let dom_path = sys::join(&[&self.state_dir, &format!("{g}.domain.xml")]);
        sys::write_file(&net_path, net_xml.as_bytes(), 0o600).map_err(|e| other(sys::go_path_error("open", &net_path, &e)))?;
        sys::write_file(&dom_path, dom_xml.as_bytes(), 0o600).map_err(|e| other(sys::go_path_error("open", &dom_path, &e)))?;
        let mp = manifest_path(&self.state_dir, g);
        sys::write_file(&mp, crate::gojson::indent(&m.json(), "  ").as_bytes(), 0o600)
            .map_err(|e| other(sys::go_path_error("open", &mp, &e)))?;
        let mut define = detail([("os", &m.os), ("network", &m.network.mode)]);
        if !m.devices.pci().is_empty() {
            define.insert("pci".into(), m.devices.pci().join(","));
        }
        if !m.devices.usb().is_empty() {
            define.insert("usb".into(), m.devices.usb().join(","));
        }
        self.emit(events::GUEST_DEFINE, g, define)?;
        let r = (|| {
            self.prepare_disk(ctx, m, &root_disk)?;
            self.virsh(ctx, &["net-define", &net_path])?;
            self.virsh(ctx, &["net-start", &virt::network_name(m)])?;
            self.emit(events::POLICY_APPLY, g, detail([("table", &policy::table_name(m))]))?;
            self.runner
                .run(ctx, &rules, "nft", &s(&["-f", "-"]))
                .map_err(|e| EngineErr::Cmd(CmdErr { text: format!("engine: loading firewall rules: {}", e.text), ..e }))?;
            self.open_host_firewall(ctx, m)?;
            self.virsh(ctx, &["define", &dom_path])?;
            self.emit(events::GUEST_START, g, Detail::new())?;
            self.virsh(ctx, &["start", &virt::domain_name(m)])
        })();
        if r.is_err() {
            let _ = self.teardown(&Ctx::background(), m);
        }
        r
    }

    fn prepare_disk(&self, ctx: &Ctx, m: &Manifest, overlay: &str) -> Result<(), EngineErr> {
        let mut fresh = m.disposable;
        if !fresh {
            if std::fs::symlink_metadata(overlay).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
                fresh = true;
            } else {
                kept_overlay_on(overlay, &m.image.path).map_err(EngineErr::Other)?;
            }
        }
        if fresh {
            let _ = std::fs::remove_file(overlay);
            self.runner
                .run(ctx, "", "qemu-img", &s(&["create", "-f", "qcow2", "-b", &m.image.path, "-F", "qcow2", overlay]))
                .map_err(|e| EngineErr::Cmd(CmdErr { text: format!("engine: creating the guest's overlay: {}", e.text), ..e }))?;
        }
        if m.disk_gb > 0 {
            self.runner.run(ctx, "", "qemu-img", &s(&["resize", "-f", "qcow2", overlay, &format!("{}G", m.disk_gb)])).map_err(|e| {
                EngineErr::Cmd(CmdErr {
                    text: format!("engine: growing the guest's disk to {} GiB (a disk can only grow): {}", m.disk_gb, e.text),
                    ..e
                })
            })?;
        }
        Ok(())
    }

    /// Stops the guest and removes everything Up made; every step runs, failures joined.
    pub fn down(&self, ctx: &Ctx, m: &Manifest) -> Result<(), EngineErr> {
        self.emit(events::GUEST_STOP, &m.name, Detail::new())?;
        self.teardown(ctx, m)
    }

    fn teardown(&self, ctx: &Ctx, m: &Manifest) -> Result<(), EngineErr> {
        let mut errs: Vec<String> = vec![];
        let dn = virt::domain_name(m);
        let nn = virt::network_name(m);
        for step in [["destroy", &dn], ["undefine", &dn], ["net-destroy", &nn], ["net-undefine", &nn]] {
            if let Err(e) = self.virsh(ctx, &step) {
                errs.push(e.to_string());
            }
        }
        if m.disposable {
            if let Err(e) = self.discard_overlay(m) {
                errs.push(e);
            }
        }
        if let Err(e) = self.close_host_firewall(ctx, m) {
            errs.push(e);
        }
        if let Err(e) = self.runner.run(ctx, "", "nft", &s(&["delete", "table", "inet", &policy::table_name(m)])) {
            errs.push(e.text);
        }
        self.settle_hardware(m);
        if let Err(e) = self.events.emit(events::POLICY_REMOVE, &m.name, Detail::new()) {
            errs.push(sys::go_err(&e));
        }
        if let Some(sn) = &self.subnets {
            if let Err(e) = sn.release(&m.name) {
                errs.push(e);
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(EngineErr::Other(errs.join("\n")))
        }
    }

    fn settle_hardware(&self, m: &Manifest) {
        if m.devices.pci().is_empty() {
            return;
        }
        let Some(h) = &self.hardware else { return };
        let before = self.before.lock().unwrap_or_else(|e| e.into_inner()).remove(&m.name).flatten();
        if let Err(e) = h.after(m, before.as_ref()) {
            let _ = self.events.emit(events::HARDWARE_STUCK, &m.name, detail([("reason", &e), ("pci", &m.devices.pci().join(","))]));
        }
    }

    fn open_host_firewall(&self, ctx: &Ctx, m: &Manifest) -> Result<(), EngineErr> {
        if !self.ufw_active.is_some_and(|f| f()) {
            return Ok(());
        }
        for args in hostfw::ufw_open(&virt::bridge_name(m)) {
            if let Err(e) = self.runner.run(ctx, "", "ufw", &args) {
                return Err(EngineErr::Cmd(CmdErr {
                    text: format!("engine: opening the bridge in the host firewall (ufw {}): {}", args.join(" "), e.text),
                    ..e
                }));
            }
        }
        Ok(())
    }

    fn close_host_firewall(&self, ctx: &Ctx, m: &Manifest) -> Result<(), String> {
        if !self.ufw_active.is_some_and(|f| f()) {
            return Ok(());
        }
        let mut errs = vec![];
        for args in hostfw::ufw_close(&virt::bridge_name(m)) {
            if let Err(e) = self.runner.run(ctx, "", "ufw", &args) {
                errs.push(format!("ufw {}: {}", args.join(" "), e.text));
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("\n"))
        }
    }

    fn exchange_safe(&self, m: &Manifest) -> Result<(), String> {
        if m.exchange_dir.is_empty() || !m.exchange_writable {
            return Ok(());
        }
        let own = sys::join(&[&self.exchange_root, &m.name]);
        if self.exchange_root.is_empty() || m.exchange_dir != own {
            return Err(format!(
                "exchange_dir {} is writable for the guest, but a guest may only write to its own outbox {own}, where nothing reaches a person before ClamAV has scanned it (limbo exchange take)",
                m.exchange_dir
            ));
        }
        exchange::prepare(&self.exchange_root, &m.name)?;
        match sys::mount_nosuid_nodev(&m.exchange_dir) {
            Err(e) => Err(format!("exchange_dir {}: {}", m.exchange_dir, sys::go_err(&e))),
            Ok(false) => Err(format!("exchange_dir {} is writable for the guest but its mount allows setuid programs and device nodes: put it on a mount with nosuid,nodev (for example a bind mount of the folder onto itself with those options), or make the share read-only", m.exchange_dir)),
            Ok(true) => Ok(()),
        }
    }

    // ---- holds (Go: engine/hold.go) ----

    /// The deny-all ruleset in place of the guest's, atomically; attempted even if the event cannot be written.
    pub fn restrict(&self, ctx: &Ctx, m: &Manifest) -> Result<(), EngineErr> {
        let rules = policy::nft_restrict(m).map_err(other)?;
        let log_err = self.events.emit(events::POLICY_RESTRICT, &m.name, detail([("table", &policy::table_name(m))]));
        self.runner
            .run(ctx, &rules, "nft", &s(&["-f", "-"]))
            .map_err(|e| EngineErr::Cmd(CmdErr { text: format!("engine: restricting {}: {}", m.name, e.text), ..e }))?;
        log_err.map_err(io_other)
    }

    pub fn isolate(&self, ctx: &Ctx, m: &Manifest) -> Result<(), EngineErr> {
        self.restrict(ctx, m)?;
        let log_err = self.events.emit(events::LINK_DOWN, &m.name, detail([("interface", &virt::tap_name(m))]));
        self.virsh(ctx, &["domif-setlink", &virt::domain_name(m), &virt::tap_name(m), "down"])
            .map_err(|e| EngineErr::Other(format!("engine: taking link down for {}: {e}", m.name)))?;
        log_err.map_err(io_other)
    }

    pub fn hold(&self, ctx: &Ctx, m: &Manifest, level: &str) -> Result<(), EngineErr> {
        match level {
            quarantine::LEVEL_RESTRICT => self.restrict(ctx, m),
            quarantine::LEVEL_ISOLATE => self.isolate(ctx, m),
            _ => Err(EngineErr::Other(quarantine::QErr::BadLevel.text().into())),
        }
    }

    /// Restores the manifest's firewall and the link. Loosens, so it fails closed on the audit log.
    pub fn release(&self, ctx: &Ctx, m: &Manifest) -> Result<(), EngineErr> {
        let rules = policy::nft_release(m).map_err(other)?;
        self.emit(events::POLICY_RELEASE, &m.name, detail([("table", &policy::table_name(m))]))?;
        self.runner
            .run(ctx, &rules, "nft", &s(&["-f", "-"]))
            .map_err(|e| EngineErr::Cmd(CmdErr { text: format!("engine: releasing {}: {}", m.name, e.text), ..e }))?;
        self.emit(events::LINK_UP, &m.name, detail([("interface", &virt::tap_name(m))]))?;
        self.virsh(ctx, &["domif-setlink", &virt::domain_name(m), &virt::tap_name(m), "up"])
    }

    fn discard_overlay(&self, m: &Manifest) -> Result<(), String> {
        let ov = sys::join(&[&self.state_dir, &virt::overlay_name(m)]);
        match std::fs::metadata(&ov) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(sys::go_path_error("stat", &ov, &e)),
            Ok(_) => {}
        }
        if let Some(h) = &self.holds {
            if let Some(rec) = h.holding(&m.name) {
                if rec.status == quarantine::STATUS_DANGEROUS {
                    let dir = sys::join(&[&self.state_dir, "evidence"]);
                    sys::mkdir_all(&dir, 0o700).map_err(|e| sys::go_path_error("mkdir", &dir, &e))?;
                    let to = sys::join(&[&dir, &format!("{}.overlay.qcow2", rec.id)]);
                    return std::fs::rename(&ov, &to).map_err(|e| format!("rename {ov} {to}: {}", sys::go_err(&e)));
                }
            }
        }
        std::fs::remove_file(&ov).map_err(|e| sys::go_path_error("remove", &ov, &e))
    }

    /// The guest exists in libvirt.
    pub fn defined(&self, ctx: &Ctx, m: &Manifest) -> bool {
        self.virsh(ctx, &["dominfo", &virt::domain_name(m)]).is_ok()
    }

    /// Removes a torn-down guest's definitions and manifest copy, unless it is held.
    pub fn clean_state(&self, m: &Manifest) {
        if let Some(h) = &self.holds {
            if h.holding(&m.name).is_some() {
                return;
            }
        }
        for f in [format!("{}.network.xml", m.name), format!("{}.domain.xml", m.name), format!("{}.manifest.json", m.name)] {
            let _ = std::fs::remove_file(sys::join(&[&self.state_dir, &f]));
        }
    }

    /// The libvirt domains running now, in one virsh call.
    pub fn running_domains(&self, ctx: &Ctx) -> Result<std::collections::HashSet<String>, CmdErr> {
        let out = self.runner.output(ctx, "virsh", &s(&["-c", CONNECT, "list", "--name", "--state-running"]))?;
        Ok(out.split('\n').map(gotext::trim_space).filter(|n| !n.is_empty()).map(String::from).collect())
    }
}

/// A persistent guest's kept overlay must be based on the manifest's image.
fn kept_overlay_on(overlay: &str, base: &str) -> Result<(), String> {
    let mut b = disk::backing_file(overlay).map_err(|e| format!("engine: reading the guest's own disk {overlay}: {e}"))?;
    if b == base {
        return Ok(());
    }
    if !b.is_empty() && !b.starts_with('/') {
        b = sys::join(&[&sys::dir(overlay), &b]);
    }
    if !b.is_empty() {
        if let (Ok(fb), Ok(fm)) = (std::fs::metadata(&b), std::fs::metadata(base)) {
            use std::os::unix::fs::MetadataExt;
            if fb.dev() == fm.dev() && fb.ino() == fm.ino() {
                return Ok(());
            }
        }
    }
    Err(format!(
        "engine: the guest's own disk {overlay} is based on {}, but its manifest names {base}; put that image back in the manifest, or free the guest's space (its own disk) to start again from the manifest's image",
        gotext::quote(&b)
    ))
}

/// A runner that records each command and answers from a script (tests and the Go fixtures).
#[derive(Default)]
pub struct FakeRunner {
    pub calls: Mutex<Vec<(String, Vec<String>, String)>>,
    /// a command line ("virsh -c qemu:///system start limbo-x") that fails, with its stderr
    pub fail: Mutex<BTreeMap<String, String>>,
    /// what `virsh ... list --name --state-running` prints
    pub running: Mutex<String>,
}

impl Runner for FakeRunner {
    fn run(&self, _ctx: &Ctx, stdin: &str, name: &str, args: &[String]) -> Result<(), CmdErr> {
        let line = format!("{name} {}", args.join(" "));
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).push((name.to_string(), args.to_vec(), stdin.to_string()));
        if let Some(stderr) =
            self.fail.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|(k, _)| line.starts_with(k.as_str())).map(|x| x.1.clone())
        {
            return Err(CmdErr { text: cmd_err(name, args, "exit status 1", stderr.as_bytes()), not_found: false });
        }
        Ok(())
    }
    fn output(&self, _ctx: &Ctx, name: &str, args: &[String]) -> Result<String, CmdErr> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).push((name.to_string(), args.to_vec(), String::new()));
        Ok(self.running.lock().unwrap_or_else(|e| e.into_inner()).clone())
    }
}
