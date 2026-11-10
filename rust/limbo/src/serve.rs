//! `limbo serve`: the sockets, one per principal, and the guests' network events (Go: cmd/limbo/serve_linux.go).
//!
//! One thread waits in poll(2) on the listening sockets, the NFLOG socket and a signalfd; an idle daemon does nothing.
//! Each connection is answered on a short-lived thread of its own (a request may start a guest, which takes seconds),
//! and each validation run has its own thread (package runs). Startup does what the Go daemon does, in the same order,
//! with the same refusals and messages.

use crate::api::{self, Peer, Principal, Server, SettingsFile};
use crate::engine::{self, Engine};
use crate::events::{self, Emitter, Logger};
use crate::flows::{self, Aggregator};
use crate::gotime::Time;
use crate::hostpolicy::{self, Policy};
use crate::image::{self, Proofs};
use crate::instances;
use crate::quarantine::Store;
use crate::runs::{self, Manager};
use crate::virt::{self, Subnets};
use crate::{exchange, gotext, http, license, osuser, settings, sys, Detail};
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The flags, as Go's flag package reads them.
#[derive(Clone, Debug)]
pub struct Flags {
    pub state_dir: String,
    pub run_dir: String,
    pub heimdall_group: String,
    pub agent_group: String,
    pub profile_dir: String,
    pub inbox: String,
    pub contained: String,
    pub users_group: String,
    pub instances_dir: String,
    pub settings: String,
    pub licenses_dir: String,
    pub limbo_root: String,
    pub exchange_root: String,
}

fn default_state_dir() -> String {
    if let Ok(d) = std::env::var("LIMBO_STATE_DIR") {
        if !d.is_empty() {
            return d;
        }
    }
    if rustix::process::geteuid().is_root() {
        return "/var/lib/limbo/state".into();
    }
    match std::env::var("HOME") {
        Ok(h) if !h.is_empty() => sys::join(&[&h, ".local", "state", "limbo"]),
        _ => "limbo-state".into(),
    }
}

impl Default for Flags {
    fn default() -> Self {
        Flags {
            state_dir: default_state_dir(),
            run_dir: "/run/limbo".into(),
            heimdall_group: "limbo-heimdall".into(),
            agent_group: "limbo-agent".into(),
            profile_dir: "/etc/limbo/validation".into(),
            inbox: "/var/lib/limbo/inbox".into(),
            contained: "/etc/heimdall/contained".into(),
            users_group: "limbo-users".into(),
            instances_dir: instances::DEFAULT_DIR.into(),
            settings: settings::DEFAULT_PATH.into(),
            licenses_dir: license::DEFAULT_DIR.into(),
            limbo_root: instances::DEFAULT_LIMBO_ROOT.into(),
            exchange_root: instances::DEFAULT_EXCHANGE_ROOT.into(),
        }
    }
}

/// Go's flag parsing: "-name value", "--name value", "-name=value"; "--" or a non-flag ends the flags.
pub fn parse_flags(args: &[String]) -> Result<Flags, String> {
    let mut f = Flags::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" || !a.starts_with('-') || a == "-" {
            break;
        }
        let name = a.trim_start_matches('-');
        let (name, inline) = match name.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (name, None),
        };
        let slot: &mut String = match name {
            "state-dir" => &mut f.state_dir,
            "run-dir" => &mut f.run_dir,
            "heimdall-group" => &mut f.heimdall_group,
            "agent-group" => &mut f.agent_group,
            "profile-dir" => &mut f.profile_dir,
            "inbox" => &mut f.inbox,
            "contained-marker" => &mut f.contained,
            "users-group" => &mut f.users_group,
            "instances-dir" => &mut f.instances_dir,
            "settings" => &mut f.settings,
            "licenses-dir" => &mut f.licenses_dir,
            "limbo-root" => &mut f.limbo_root,
            "exchange-root" => &mut f.exchange_root,
            "h" | "help" => return Err("flag: help requested".into()),
            other => return Err(format!("flag provided but not defined: -{other}")),
        };
        match inline {
            Some(v) => *slot = v,
            None => {
                i += 1;
                match args.get(i) {
                    Some(v) => *slot = v.clone(),
                    None => return Err(format!("flag needs an argument: -{name}")),
                }
            }
        }
        i += 1;
    }
    Ok(f)
}

/// The programs Limbo shells out to (Go: internal/deps).
const REQUIRED: &[(&str, &str)] = &[
    ("virsh", "libvirt"),
    ("qemu-img", "qemu-base"),
    ("qemu-system-x86_64", "qemu-base"),
    ("dnsmasq", "dnsmasq"),
    ("nft", "nftables"),
    ("ssh", "openssh"),
    ("xorriso", "libisoburn"),
];

pub fn preflight() -> Result<(), String> {
    let missing: Vec<String> =
        REQUIRED.iter().filter(|(c, _)| exchange::look_path(c).is_none()).map(|(c, p)| format!("{c} ({p})")).collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(format!("Limbo's runtime dependencies are not installed: {}. Run: sudo limbo setup", missing.join(", ")))
}

/// A folder only root may write (or a missing one).
fn check_profile_dir(dir: &str, what: &str) -> Result<(), String> {
    let m = match std::fs::metadata(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(sys::go_path_error("stat", dir, &e)),
        Ok(m) => m,
    };
    let st = sys::Stat::of(&m);
    if !st.is_dir() {
        return Err(format!("serve: {dir} is not a directory"));
    }
    if st.perm() & 0o022 != 0 {
        return Err(format!("serve: {dir} is group- or world-writable; refusing to load {what} from it"));
    }
    if st.uid != 0 {
        return Err(format!("serve: {dir} is not owned by root; refusing to load {what} from it"));
    }
    Ok(())
}

fn check_host_policy(file: &str) -> Result<(), String> {
    let m = match std::fs::metadata(file) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(sys::go_path_error("stat", file, &e)),
        Ok(m) => m,
    };
    let st = sys::Stat::of(&m);
    if st.perm() & 0o022 != 0 {
        return Err(format!("serve: {file} is group- or world-writable; refusing to start"));
    }
    if st.uid != 0 {
        return Err(format!("serve: {file} is not owned by root; refusing to start"));
    }
    Ok(())
}

fn share_event_log(state_dir: &str, log_path: &str, group: &str) -> Result<(), String> {
    sys::chmod(state_dir, 0o711).map_err(|e| sys::go_path_error("chmod", state_dir, &e))?;
    let Some(gid) = osuser::group_gid(group) else {
        eprintln!("limbo: group {} not found; the event log stays root-only and Heimdall cannot read it", gotext::quote(group));
        return Ok(());
    };
    rustix::fs::chown(log_path, None, Some(rustix::fs::Gid::from_raw(gid)))
        .map_err(|e| sys::go_path_error("chown", log_path, &e.into()))?;
    sys::chmod(log_path, 0o640).map_err(|e| sys::go_path_error("chmod", log_path, &e))
}

/// The socket at `path`, made with the umask tightened, then given its group and final mode before it is used.
pub fn listen(path: &str, mode: u32, group: &str) -> Result<UnixListener, String> {
    if let Ok(m) = std::fs::symlink_metadata(path) {
        use std::os::unix::fs::FileTypeExt;
        if !m.file_type().is_socket() {
            return Err(format!("api: {path} exists and is not a socket"));
        }
        std::fs::remove_file(path).map_err(|e| sys::go_path_error("remove", path, &e))?;
    }
    let old = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o177));
    let l = UnixListener::bind(path);
    rustix::process::umask(old);
    let l = l.map_err(|e| format!("listen unix {path}: bind: {}", sys::go_err(&e)))?;
    let fail = |e: String| {
        let _ = std::fs::remove_file(path);
        Err(e)
    };
    if !group.is_empty() {
        let Some(gid) = osuser::group_gid(group) else {
            return fail(format!(
                "api: group {} for {path} does not exist (create it first, e.g. via sysusers): group: unknown group {group}",
                gotext::quote(group)
            ));
        };
        if let Err(e) = rustix::fs::chown(path, None, Some(rustix::fs::Gid::from_raw(gid))) {
            return fail(sys::go_path_error("chown", path, &e.into()));
        }
    }
    if let Err(e) = sys::chmod(path, mode) {
        return fail(sys::go_path_error("chmod", path, &e));
    }
    Ok(l)
}

/// Passes events through, and tells the flow aggregator when a guest is torn down (the name may be reused).
struct Forgetting {
    log: Arc<Logger>,
    agg: Arc<Mutex<Aggregator>>,
}

impl Emitter for Forgetting {
    fn emit(&self, kind: &str, guest: &str, d: Detail) -> io::Result<()> {
        if kind == events::POLICY_REMOVE {
            self.agg.lock().unwrap_or_else(|e| e.into_inner()).forget(guest);
        }
        self.log.emit(kind, guest, d)
    }
}

fn kvm() -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata("/dev/kvm").is_ok_and(|m| m.file_type().is_char_device())
}

/// The connections being answered now; past the bound a new one waits for a slot.
static CONNS: AtomicUsize = AtomicUsize::new(0);
const MAX_CONNS: usize = 128;

fn answer(srv: Arc<Server>, p: Principal, s: UnixStream) {
    let peer = match rustix::net::sockopt::socket_peercred(&s) {
        Ok(c) => Peer { uid: Some(c.uid.as_raw()), pid: c.pid.as_raw_nonzero().get() },
        Err(_) => Peer::default(),
    };
    let _ = s.set_read_timeout(Some(http::HEADER_TIMEOUT));
    let _ = s.set_write_timeout(Some(Duration::from_secs(60)));
    let req = match http::read_request(&s) {
        Ok(r) => r,
        Err(http::ReadErr::Closed) => return,
        Err(http::ReadErr::Status(st, text)) => {
            let _ = std::io::Write::write_all(
                &mut &s,
                format!("HTTP/1.1 {text}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n{text}").as_bytes(),
            );
            let _ = st;
            return;
        }
    };
    let _ = s.set_read_timeout(None);
    // a handler that panics loses this connection, not the daemon (Go's server recovers a handler's panic too)
    let resp = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| srv.handle(p, peer, &req)));
    if let Ok(resp) = resp {
        let _ = http::write_response(&s, &req.method, resp);
    }
}

fn block_signals() -> Result<OwnedFd, String> {
    // SAFETY: plain libc calls on a local sigset; the fd returned is owned here
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
        if libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
            return Err("serve: cannot block signals".into());
        }
        let fd = libc::signalfd(-1, &set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
        if fd < 0 {
            return Err(format!("serve: signalfd: {}", sys::go_err(&io::Error::last_os_error())));
        }
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// Runs the daemon until SIGINT or SIGTERM. The error is what the Go daemon would print after "limbo: ".
pub fn run(args: &[String]) -> Result<(), String> {
    let f = parse_flags(args)?;
    sys::one_arena();
    if !rustix::process::geteuid().is_root() {
        return Err("serve: must run as root (it manages libvirt and nftables)".into());
    }
    preflight()?;
    check_profile_dir(&f.profile_dir, "validation profiles")?;
    check_profile_dir(&f.instances_dir, "validation profiles")?;
    let log_path = sys::join(&[&f.state_dir, "events.jsonl"]);
    let log = Arc::new(Logger::open(&log_path).map_err(|e| sys::go_path_error("open", &log_path, &e))?);
    share_event_log(&f.state_dir, &log_path, &f.heimdall_group)?;
    let store = Arc::new(Store::open(&sys::join(&[&f.state_dir, "quarantine"]))?);
    check_host_policy(hostpolicy::DEFAULT_CONFIG)?;

    let agg = Arc::new(Mutex::new(Aggregator::new(Some(log.clone() as Arc<dyn Emitter>), Time::now)));
    {
        let state = f.state_dir.clone();
        agg.lock().unwrap_or_else(|e| e.into_inner()).gateway =
            Some(Box::new(move |g: &str| engine::load_guest(&state, g).ok().map(|m| flows::Ip::V4(virt::addr(&m).gateway))));
    }
    let emitter: Arc<dyn Emitter> = Arc::new(Forgetting { log: log.clone(), agg: agg.clone() });
    let mut eng = Engine::new(Arc::new(engine::Exec), emitter, &f.state_dir);
    eng.holds = Some(store.clone());
    eng.hardware = Some(Arc::new(Policy::new(&f.state_dir, &f.run_dir)));
    eng.ufw_active = Some(crate::hostfw::ufw_active);
    eng.exchange_root = f.exchange_root.clone();
    eng.subnets = Some(Subnets { path: sys::join(&[&f.state_dir, "subnets.json"]), in_use: None });
    eng.images = Some(Arc::new(Proofs::new(&sys::join(&[&f.state_dir, image::PROOFS_FILE]), 0)));
    let eng = Arc::new(eng);

    let mut mgr = Manager::new(&f.profile_dir, &f.state_dir, eng.clone(), Arc::new(runs::Ssh), log.clone());
    sys::mkdir_all(&f.inbox, 0o700).map_err(|e| sys::go_path_error("mkdir", &f.inbox, &e))?;
    let _ = sys::chmod(&f.inbox, 0o700);
    mgr.sample_dir = f.inbox.clone();
    let marker = f.contained.clone();
    mgr.contained = Some(Box::new(move || std::fs::symlink_metadata(&marker).is_ok()));
    let mgr = runs::into_arc(mgr);
    let n = mgr.reap_orphans();
    if n > 0 {
        eprintln!("limbo serve: destroyed {n} guest(s) left by an interrupted run");
    }

    let exch = exchange::Service {
        root: f.exchange_root.clone(),
        scratch: sys::join(&[&f.state_dir, "exchange-scratch"]),
        held: sys::join(&[&f.state_dir, "exchange-held"]),
        scanner: Some(Box::new(exchange::ClamAV)),
        events: Some(log.clone()),
    };
    let mut inst = instances::Service::new(&f.instances_dir, &f.state_dir, &f.limbo_root, &f.exchange_root, eng.clone());
    inst.holds = Some(store.clone());
    inst.events = Some(log.clone());
    inst.host_limits = Some(instances::host_limits);
    let licenses: Option<Arc<license::Store>> = match license::Store::open(&f.licenses_dir, true) {
        Ok(l) => Some(Arc::new(l)),
        Err(e) => {
            eprintln!("limbo serve: Windows licenses unavailable: {e}");
            None
        }
    };
    if let Some(l) = &licenses {
        let l = l.clone();
        inst.license_of = Some(Box::new(move |g: &str| l.assigned_to(g)));
    }
    let srv = Arc::new(Server {
        store,
        actions: Arc::new(api::EngineActions(eng.clone())),
        events: log.clone(),
        runs: Some(mgr.clone() as Arc<dyn api::RunService>),
        instances: Some(Arc::new(inst)),
        licenses: licenses.map(|l| l as Arc<dyn api::LicenseService>),
        settings: Some(Arc::new(SettingsFile { path: f.settings.clone(), require_root: true })),
        exchange: Some(Arc::new(exch)),
        kvm,
    });

    sys::mkdir_all(&f.run_dir, 0o755).map_err(|e| sys::go_path_error("mkdir", &f.run_dir, &e))?;
    let mut socks: Vec<(&str, Principal, u32, String)> = vec![
        ("admin.sock", Principal::Admin, 0o600, String::new()),
        ("control.sock", Principal::Control, 0o660, f.heimdall_group.clone()),
        ("agent.sock", Principal::Agent, 0o660, f.agent_group.clone()),
    ];
    if osuser::group_gid(&f.users_group).is_some() {
        socks.push(("user.sock", Principal::User, 0o660, f.users_group.clone()));
    } else {
        eprintln!(
            "limbo: group {} not found; user.sock (the Settings page) is not offered. Run: sudo limbo setup",
            gotext::quote(&f.users_group)
        );
    }
    // signals are taken through a signalfd, so every thread made from here on has them blocked
    let sigfd = block_signals()?;
    let mut listeners: Vec<(UnixListener, Principal, String)> = vec![];
    for (name, who, mode, group) in &socks {
        let path = sys::join(&[&f.run_dir, name]);
        match listen(&path, *mode, group) {
            Ok(l) => {
                eprintln!("limbo: {} listening on {path} (mode {:o}, group {})", who.as_str(), mode, gotext::quote(group));
                l.set_nonblocking(true).map_err(|e| sys::go_err(&e))?;
                listeners.push((l, *who, path));
            }
            Err(e) => {
                for (_, _, p) in &listeners {
                    let _ = std::fs::remove_file(p);
                }
                return Err(e);
            }
        }
    }
    let nflog = match flows::listen(crate::policy::NFLOG_GROUP) {
        Ok(fd) => Some(fd),
        Err(e) => {
            eprintln!("limbo serve: guest network events unavailable: {e}");
            None
        }
    };
    let r = serve_loop(&srv, &listeners, nflog.as_ref(), &sigfd, &agg);
    for (_, _, p) in &listeners {
        let _ = std::fs::remove_file(p);
    }
    r
}

fn serve_loop(
    srv: &Arc<Server>,
    listeners: &[(UnixListener, Principal, String)],
    nflog_fd: Option<&OwnedFd>,
    sigfd: &OwnedFd,
    agg: &Arc<Mutex<Aggregator>>,
) -> Result<(), String> {
    use rustix::event::{poll, PollFd, PollFlags};
    let mut buf = vec![0u8; 1 << 16];
    let mut last_trim = std::time::Instant::now();
    let mut nflog = nflog_fd;
    loop {
        let mut fds: Vec<PollFd> = listeners.iter().map(|(l, _, _)| PollFd::new(l, PollFlags::IN)).collect();
        fds.push(PollFd::new(sigfd, PollFlags::IN));
        if let Some(n) = nflog {
            fds.push(PollFd::new(n, PollFlags::IN));
        }
        match poll(&mut fds, None) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(format!("serve: poll: {}", sys::go_err(&e.into()))),
        }
        let ready: Vec<bool> = fds.iter().map(|p| !p.revents().is_empty()).collect();
        drop(fds);
        if ready[listeners.len()] {
            return Ok(());
        }
        for (i, (l, who, _)) in listeners.iter().enumerate() {
            if !ready[i] {
                continue;
            }
            while let Ok((s, _)) = l.accept() {
                let _ = s.set_nonblocking(false);
                while CONNS.load(Ordering::SeqCst) >= MAX_CONNS {
                    std::thread::sleep(Duration::from_millis(5));
                }
                CONNS.fetch_add(1, Ordering::SeqCst);
                let srv = srv.clone();
                let who = *who;
                let spawned = std::thread::Builder::new().name("conn".into()).stack_size(256 << 10).spawn(move || {
                    answer(srv, who, s);
                    // the last connection out hands freed heap back (a burst of requests leaves nothing behind)
                    if CONNS.fetch_sub(1, Ordering::SeqCst) == 1 {
                        sys::trim();
                    }
                });
                if spawned.is_err() {
                    CONNS.fetch_sub(1, Ordering::SeqCst);
                }
            }
        }
        if let Some(n) = nflog {
            if ready[listeners.len() + 1] {
                loop {
                    match rustix::io::read(n, &mut buf[..]) {
                        Ok(0) => break,
                        Ok(k) => {
                            let mut a = agg.lock().unwrap_or_else(|e| e.into_inner());
                            for (prefix, payload) in flows::parse_messages(&buf[..k]) {
                                if let Some(p) = flows::decode(&prefix, &payload) {
                                    a.handle(&p);
                                }
                            }
                        }
                        // ENOBUFS: the kernel dropped copies we were too slow for
                        Err(rustix::io::Errno::AGAIN) => break,
                        Err(rustix::io::Errno::INTR) | Err(rustix::io::Errno::NOBUFS) => continue,
                        Err(e) => {
                            eprintln!("limbo serve: guest network events stopped: flows: reading NFLOG: {}", sys::go_err(&e.into()));
                            nflog = None;
                            break;
                        }
                    }
                }
            }
        }
        // freed heap goes back to the system at most once a minute (a burst of requests or a run leaves none behind)
        if last_trim.elapsed() > Duration::from_secs(60) && CONNS.load(Ordering::SeqCst) == 0 {
            // SAFETY: malloc_trim only returns free memory to the system
            unsafe {
                libc::malloc_trim(0);
            }
            last_trim = std::time::Instant::now();
        }
        let _ = (sigfd.as_fd().as_raw_fd(), &listeners);
    }
}
