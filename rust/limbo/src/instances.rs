//! What the Settings page shows and changes (Go: internal/instances): registered instances, their figures, the few
//! things a person may change, laid over the manifest at start within its bounds. Who may ask is the api's business; the
//! rules here hold whoever asks: an owner's instance only by them (or root), a held guest never except by root, a held
//! guest's disk is evidence.

use crate::engine::{Ctx, Engine};
use crate::events::Emitter;
use crate::gojson::{self, Obj};
use crate::gotime::Time;
use crate::manifest::{self, Manifest, Network};
use crate::quarantine::Holder;
use crate::{detail, disk, go_struct, gotext, sys, virt, Detail, Refusal};
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Arc, Mutex};

pub const DEFAULT_DIR: &str = "/etc/limbo/instances";
pub const DEFAULT_LIMBO_ROOT: &str = "/var/lib/limbo";
pub const DEFAULT_EXCHANGE_ROOT: &str = "/var/lib/limbo/exchange";

pub const CODE_NOT_FOUND: &str = "not_found";
pub const CODE_BAD_REQUEST: &str = "bad_request";
pub const CODE_OUT_OF_RANGE: &str = "out_of_range";
pub const CODE_NOT_OWNER: &str = "not_owner";
pub const CODE_HELD: &str = "held_by_heimdall";
pub const CODE_RUNNING: &str = "running";
pub const CODE_NOT_RUNNING: &str = "not_running";
pub const CODE_READ_ONLY: &str = "not_an_instance";
pub const CODE_START_FAILED: &str = "start_failed";
pub const CODE_STOP_FAILED: &str = "stop_failed";
pub const CODE_EXISTS: &str = "exists";

pub const EVENT_REQUEST: &str = "instance.request";
pub const EVENT_CHANGE: &str = "instance.change";
pub const EVENT_ADD: &str = "instance.add";
pub const EVENT_REMOVE: &str = "instance.remove";

const HOST_RESERVE_MB: i64 = 2048;

/// Who asked: root (admin socket) or a member of limbo-users (user.sock).
#[derive(Clone, Debug, Default)]
pub struct Caller {
    pub admin: bool,
    pub uid: i64,
    pub user: String,
}

fn refuse(status: u16, code: &str, remedy: &str, msg: String) -> Refusal {
    Refusal::new(Some(status), code, remedy, msg)
}

#[derive(Clone, Debug, Default)]
pub struct Entry {
    pub manifest: Manifest,
    pub owner: String,
}
go_struct!(Entry as "instances.Entry" { manifest: "manifest" => "manifest.Manifest", owner: "owner" => "string" });

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Overrides {
    pub cpus: i64,
    pub memory_mb: i64,
    pub disk_gb: i64,
    pub shared_folder: String,
    pub clipboard: String,
    pub devices: Option<Vec<String>>,
    pub network: Option<Network>,
}
go_struct!(Overrides as "instances.Overrides" {
    cpus: "cpus" => "int", memory_mb: "memory_mb" => "int", disk_gb: "disk_gb" => "int", shared_folder: "shared_folder" => "string",
    clipboard: "clipboard" => "string", devices: "devices" => "*[]string", network: "network" => "*manifest.Network",
});

impl Overrides {
    pub fn json(&self) -> String {
        let mut o = Obj::new()
            .int_omit("cpus", self.cpus)
            .int_omit("memory_mb", self.memory_mb)
            .int_omit("disk_gb", self.disk_gb)
            .str_omit("shared_folder", &self.shared_folder)
            .str_omit("clipboard", &self.clipboard);
        if let Some(d) = &self.devices {
            o = o.strs("devices", d);
        }
        if let Some(n) = &self.network {
            o = o.raw("network", &n.json());
        }
        o.end()
    }
}

/// A change request; absent fields stay as they are.
#[derive(Clone, Debug, Default)]
pub struct Change {
    pub cpus: Option<i64>,
    pub memory_mb: Option<i64>,
    pub disk_gb: Option<i64>,
    pub shared_folder: Option<String>,
    pub clipboard: Option<String>,
    pub devices: Option<Vec<String>>,
    pub network: Option<Network>,
}
go_struct!(Change as "instances.Change" {
    cpus: "cpus" => "*int", memory_mb: "memory_mb" => "*int", disk_gb: "disk_gb" => "*int", shared_folder: "shared_folder" => "*string",
    clipboard: "clipboard" => "*string", devices: "devices" => "*[]string", network: "network" => "*manifest.Network",
});

#[derive(Clone, Debug, PartialEq)]
pub struct Hold {
    pub id: String,
    pub status: String,
    pub level: String,
    pub by: String,
    pub since: Time,
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct DiskFig {
    pub base_bytes: i64,
    pub own_bytes: i64,
    pub virtual_bytes: i64,
    pub disk_gb: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct View {
    pub name: String,
    pub kind: String,
    pub os: String,
    pub state: String,
    pub running: bool,
    pub address: String,
    pub cpus: i64,
    pub memory_mb: i64,
    pub network: String,
    pub disk: DiskFig,
    pub shared_folder: String,
    pub clipboard: String,
    pub devices: Vec<String>,
    pub disposable: bool,
    pub owner: String,
    pub mine: bool,
    pub hold: Option<Hold>,
    pub held_by_heimdall: bool,
    pub pending: bool,
    pub license: String,
    pub overrides: Overrides,
}

impl View {
    pub fn json(&self) -> String {
        let hold = match &self.hold {
            None => "null".to_string(),
            Some(h) => Obj::new()
                .str("id", &h.id)
                .str("status", &h.status)
                .str("level", &h.level)
                .str("by", &h.by)
                .str("since", &h.since.rfc3339_nano())
                .end(),
        };
        Obj::new()
            .str("name", &self.name)
            .str("kind", &self.kind)
            .str("os", &self.os)
            .str("state", &self.state)
            .bool("running", self.running)
            .str("address", &self.address)
            .int("cpus", self.cpus)
            .int("memory_mb", self.memory_mb)
            .str("network", &self.network)
            .raw(
                "disk",
                &Obj::new()
                    .int("base_bytes", self.disk.base_bytes)
                    .int("own_bytes", self.disk.own_bytes)
                    .int("virtual_bytes", self.disk.virtual_bytes)
                    .int("disk_gb", self.disk.disk_gb)
                    .end(),
            )
            .str("shared_folder", &self.shared_folder)
            .str("clipboard", &self.clipboard)
            .strs("devices", &self.devices)
            .bool("disposable", self.disposable)
            .str("owner", &self.owner)
            .bool("mine", self.mine)
            .raw("hold", &hold)
            .bool("held_by_heimdall", self.held_by_heimdall)
            .bool("pending", self.pending)
            .str("license", &self.license)
            .raw("overrides", &self.overrides.json())
            .end()
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Space {
    pub total_bytes: i64,
    pub images_bytes: i64,
    pub guests_bytes: i64,
    pub evidence_bytes: i64,
    pub exchange_bytes: i64,
}

impl Space {
    pub fn json(&self) -> String {
        Obj::new()
            .int("total_bytes", self.total_bytes)
            .int("images_bytes", self.images_bytes)
            .int("guests_bytes", self.guests_bytes)
            .int("evidence_bytes", self.evidence_bytes)
            .int("exchange_bytes", self.exchange_bytes)
            .end()
    }
}

pub struct Service {
    pub dir: String,
    pub state_dir: String,
    pub limbo_root: String,
    pub exchange_root: String,
    pub guests: Arc<Engine>,
    pub holds: Option<Arc<dyn Holder>>,
    pub events: Option<Arc<dyn Emitter>>,
    pub license_of: Option<Box<dyn Fn(&str) -> String + Send + Sync>>,
    pub host_limits: Option<fn() -> (i64, i64)>,
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

/// `^[a-z_][a-z0-9_-]{0,31}$` (manifest's user rule)
fn user_ok(n: &str) -> bool {
    manifest::user_ok(n)
}

fn not_found(name: &str) -> Refusal {
    refuse(
        404,
        CODE_NOT_FOUND,
        "list the instances (GET /v1/instances) for the names that exist",
        format!("there is no instance named {}", gotext::quote(name)),
    )
}

fn shared(m: &Manifest) -> &'static str {
    if m.exchange_dir.is_empty() {
        "off"
    } else if m.exchange_writable {
        "writable"
    } else {
        "read-only"
    }
}

impl Service {
    pub fn new(dir: &str, state_dir: &str, limbo_root: &str, exchange_root: &str, guests: Arc<Engine>) -> Service {
        Service {
            dir: dir.into(),
            state_dir: state_dir.into(),
            limbo_root: limbo_root.into(),
            exchange_root: exchange_root.into(),
            guests,
            holds: None,
            events: None,
            license_of: None,
            host_limits: None,
            locks: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self, name: &str) -> Arc<Mutex<()>> {
        self.locks.lock().unwrap_or_else(|e| e.into_inner()).entry(name.to_string()).or_default().clone()
    }

    fn entry_path(&self, name: &str) -> String {
        sys::join(&[&self.dir, &format!("{name}.json")])
    }
    fn override_path(&self, name: &str) -> String {
        sys::join(&[&self.state_dir, "instances", &format!("{name}.json")])
    }

    fn load(&self, name: &str) -> Result<Entry, Refusal> {
        if !manifest::name_ok(name) {
            return Err(not_found(name));
        }
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.entry_path(name))
            .map_err(|_| not_found(name))?;
        let mut b = Vec::new();
        let _ = std::io::Read::read_to_end(&mut f, &mut b);
        let q = gotext::quote(name);
        let (mut e, r) = gojson::decode(&b, Entry::default(), "instances.Entry", true);
        if r.is_err() {
            return Err(refuse(
                500,
                CODE_BAD_REQUEST,
                "ask root to fix or re-add it (limbo instance add)",
                format!("the record of instance {q} is damaged"),
            ));
        }
        match manifest::parse(e.manifest.json().as_bytes()) {
            Ok(m) if m.name == name => e.manifest = m,
            _ => {
                return Err(refuse(
                    500,
                    CODE_BAD_REQUEST,
                    "ask root to fix or re-add it (limbo instance add)",
                    format!("the manifest of instance {q} is not valid"),
                ))
            }
        }
        Ok(e)
    }

    fn overrides(&self, name: &str) -> Overrides {
        match std::fs::read(self.override_path(name)) {
            // Go ignores the error and keeps what was read before it
            Ok(b) => match gojson::parse(&b) {
                Ok(v) => {
                    let mut o = Overrides::default();
                    let mut cx = gojson::Ctx::new(false);
                    gojson::FromGo::read(&mut o, &v, &mut cx, "instances.Overrides");
                    o
                }
                Err(_) => Overrides::default(),
            },
            Err(_) => Overrides::default(),
        }
    }

    fn save_overrides(&self, name: &str, o: &Overrides) -> Result<(), String> {
        let p = self.override_path(name);
        sys::mkdir_all(sys::dir(&p), 0o700).map_err(|e| sys::go_err(&e))?;
        let tmp = format!("{p}.tmp");
        sys::write_file(&tmp, gojson::indent(&o.json(), "  ").as_bytes(), 0o600).map_err(|e| sys::go_path_error("open", &tmp, &e))?;
        std::fs::rename(&tmp, &p).map_err(|e| sys::go_err(&e))
    }

    /// The manifest an instance starts from: its own, with the person's changes laid over it.
    pub fn effective(&self, e: &Entry, o: &Overrides) -> Result<Manifest, Refusal> {
        let mut m = e.manifest.clone();
        // Go copies the device lists with append(nil, ...): an empty list becomes nil (written as null)
        m.devices.pci = m.devices.pci.filter(|v| !v.is_empty());
        m.devices.usb = m.devices.usb.filter(|v| !v.is_empty());
        if o.cpus > 0 {
            m.cpus = o.cpus;
        }
        if o.memory_mb > 0 {
            m.memory_mb = o.memory_mb;
        }
        if o.disk_gb > 0 {
            m.disk_gb = o.disk_gb;
        }
        match o.shared_folder.as_str() {
            "off" => {
                m.exchange_dir = String::new();
                m.exchange_writable = false;
            }
            "on" if m.exchange_dir.is_empty() => {
                m.exchange_dir = sys::join(&[&self.exchange_root, &m.name]);
                m.exchange_writable = true;
            }
            _ => {}
        }
        if !o.clipboard.is_empty() {
            m.clipboard = o.clipboard.clone();
        }
        if let Some(devs) = &o.devices {
            let (mut pci, mut usb) = (None::<Vec<String>>, None::<Vec<String>>);
            for d in devs {
                if manifest::usb_id_ok(d) {
                    usb.get_or_insert_with(Vec::new).push(d.clone());
                } else {
                    pci.get_or_insert_with(Vec::new).push(d.clone());
                }
            }
            m.devices.pci = pci;
            m.devices.usb = usb;
        }
        if let Some(n) = &o.network {
            m.network = Network { mode: n.mode.clone(), allow: n.allow.clone().filter(|a| !a.is_empty()) };
        }
        m.validate().map_err(|e| refuse(400, CODE_OUT_OF_RANGE, "choose values the guest's manifest allows", e))?;
        Ok(m)
    }

    fn hold(&self, name: &str) -> Option<Hold> {
        let rec = self.holds.as_ref()?.holding(name)?;
        let by = if rec.source.starts_with("human") || rec.source.starts_with("admin") { "person" } else { "heimdall" };
        Some(Hold { id: rec.id, status: rec.status, level: rec.level, by: by.into(), since: rec.opened })
    }

    fn started_from(&self, name: &str) -> Result<Manifest, String> {
        manifest::load(&sys::join(&[&self.state_dir, &format!("{name}.manifest.json")]))
    }

    fn running(&self) -> HashSet<String> {
        self.guests.running_domains(&Ctx::background()).unwrap_or_default()
    }

    fn view(&self, m: &Manifest, kind: &str, e: Option<&Entry>, o: &Overrides, running: &HashSet<String>, c: &Caller) -> View {
        let mut v = View {
            name: m.name.clone(),
            kind: kind.into(),
            os: m.os.clone(),
            state: "stopped".into(),
            running: running.contains(&virt::domain_name(m)),
            address: String::new(),
            cpus: m.cpus,
            memory_mb: m.memory_mb,
            network: m.network.mode.clone(),
            disk: DiskFig::default(),
            shared_folder: shared(m).into(),
            clipboard: m.clipboard.clone(),
            devices: m.devices.all(),
            disposable: m.disposable,
            owner: String::new(),
            mine: false,
            hold: None,
            held_by_heimdall: false,
            pending: false,
            license: String::new(),
            overrides: o.clone(),
        };
        if v.running {
            v.state = "running".into();
        }
        if let Ok(cur) = self.started_from(&m.name) {
            if cur.subnet > 0 && (v.running || self.guests.defined(&Ctx::background(), &cur)) {
                v.address = virt::ip4(virt::addr(&cur).guest);
            }
        }
        if let Some(h) = self.hold(&m.name) {
            v.held_by_heimdall = h.by == "heimdall";
            v.hold = Some(h);
            v.state = "held".into();
        }
        let own = sys::join(&[&self.state_dir, &virt::disk_name(m)]);
        v.disk =
            DiskFig { base_bytes: disk::allocated(&m.image.path), own_bytes: disk::allocated(&own), virtual_bytes: 0, disk_gb: m.disk_gb };
        if let Ok(n) = disk::virtual_size(&own) {
            v.disk.virtual_bytes = n;
        } else if let Ok(n) = disk::virtual_size(&m.image.path) {
            v.disk.virtual_bytes = n;
        }
        if let Some(e) = e {
            v.owner = e.owner.clone();
            v.mine = c.admin || e.owner.is_empty() || e.owner == c.user;
            if v.running {
                if let Ok(cur) = self.started_from(&m.name) {
                    v.pending = cur.cpus != m.cpus
                        || cur.memory_mb != m.memory_mb
                        || cur.disk_gb != m.disk_gb
                        || shared(&cur) != shared(m)
                        || cur.clipboard != m.clipboard
                        || cur.devices.all().join(",") != m.devices.all().join(",");
                }
            }
        }
        if let Some(f) = &self.license_of {
            v.license = f(&m.name);
        }
        v
    }

    /// Every instance, then every other guest Limbo has running, sorted by kind then name.
    pub fn list(&self, c: &Caller) -> Vec<View> {
        let running = self.running();
        let mut out = vec![];
        let mut seen = HashSet::new();
        for (file, _) in sys::read_dir_sorted(&self.dir).unwrap_or_default() {
            let Some(name) = file.strip_suffix(".json") else { continue };
            if !manifest::name_ok(name) {
                continue;
            }
            let Ok(e) = self.load(name) else { continue };
            let o = self.overrides(name);
            let m = self.effective(&e, &o).unwrap_or_else(|_| e.manifest.clone());
            out.push(self.view(&m, "instance", Some(&e), &o, &running, c));
            seen.insert(name.to_string());
        }
        let mut others = vec![];
        for (file, _) in sys::read_dir_sorted(&self.state_dir).unwrap_or_default() {
            let Some(name) = file.strip_suffix(".manifest.json") else { continue };
            if seen.contains(name) || !manifest::name_ok(name) {
                continue;
            }
            let Ok(m) = self.started_from(name) else { continue };
            if m.name != name {
                continue;
            }
            let kind = if crate::runs::run_id_ok(name) { "run" } else { "manual" };
            others.push(self.view(&m, kind, None, &Overrides::default(), &running, c));
        }
        others.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.name.cmp(&b.name)));
        out.extend(others);
        out
    }

    pub fn get(&self, name: &str, c: &Caller) -> Result<View, Refusal> {
        self.list(c).into_iter().find(|v| v.name == name).ok_or_else(|| not_found(name))
    }

    pub fn space(&self) -> Space {
        let mut sp = Space {
            total_bytes: disk::usage(&self.limbo_root),
            images_bytes: disk::usage(&sys::join(&[&self.limbo_root, "images"])),
            guests_bytes: 0,
            evidence_bytes: disk::usage(&sys::join(&[&self.state_dir, "evidence"])),
            exchange_bytes: disk::usage(&self.exchange_root),
        };
        for (f, ft) in sys::read_dir_sorted(&self.state_dir).unwrap_or_default() {
            if f.ends_with(".qcow2") && ft.is_file() {
                sp.guests_bytes += disk::allocated(&sys::join(&[&self.state_dir, &f]));
            }
        }
        let mut base = HashSet::new();
        let root = format!("{}/", sys::clean(&self.limbo_root));
        for (f, _) in sys::read_dir_sorted(&self.dir).unwrap_or_default() {
            let Some(name) = f.strip_suffix(".json") else { continue };
            if let Ok(e) = self.load(name) {
                let p = sys::clean(&e.manifest.image.path);
                if !base.contains(&p) && !p.starts_with(&root) {
                    sp.total_bytes += disk::allocated(&p);
                    base.insert(p);
                }
            }
        }
        sp
    }

    fn may_change(&self, name: &str, c: &Caller) -> Result<Entry, Refusal> {
        let e = match self.load(name) {
            Ok(e) => e,
            Err(err) => {
                if manifest::name_ok(name) && std::fs::metadata(sys::join(&[&self.state_dir, &format!("{name}.manifest.json")])).is_ok() {
                    return Err(refuse(
                        409,
                        CODE_READ_ONLY,
                        "only guests registered as instances (limbo instance add) can be changed here",
                        format!("{} is a run or a guest started by hand, not an instance", gotext::quote(name)),
                    ));
                }
                return Err(err);
            }
        };
        let q = gotext::quote(name);
        if !c.admin && !e.owner.is_empty() && e.owner != c.user {
            return Err(refuse(
                403,
                CODE_NOT_OWNER,
                &format!("ask {} or use the password", e.owner),
                format!("instance {q} belongs to {}", e.owner),
            ));
        }
        if let Some(h) = self.hold(name) {
            if !c.admin {
                return Err(refuse(
                    409,
                    CODE_HELD,
                    "decide about it on Heimdall's page (Settings > Security), which needs the password",
                    format!("instance {q} is held ({}, {})", h.id, h.status),
                ));
            }
        }
        Ok(e)
    }

    fn audit(&self, kind: &str, guest: &str, c: &Caller, mut d: Detail) -> Result<(), Refusal> {
        let Some(ev) = &self.events else { return Ok(()) };
        d.insert("principal".into(), if c.admin { "admin" } else { "user" }.into());
        d.insert("peer".into(), format!("uid={}", c.uid));
        ev.emit(kind, guest, d).map_err(|e| Refusal::new(Some(500), "internal", "", sys::go_err(&e)))
    }

    pub fn start(&self, name: &str, c: &Caller) -> Result<View, Refusal> {
        let e = self.may_change(name, c)?;
        let l = self.lock(name);
        let _g = l.lock().unwrap_or_else(|x| x.into_inner());
        let o = self.overrides(name);
        let mut m = self.effective(&e, &o)?;
        if self.running().contains(&virt::domain_name(&m)) {
            return Err(refuse(
                409,
                CODE_RUNNING,
                "stop it first, or leave it running",
                format!("instance {} is already running", gotext::quote(name)),
            ));
        }
        self.audit(EVENT_REQUEST, name, c, detail([("action", "start")]))?;
        let ctx = Ctx::background();
        if self.guests.defined(&ctx, &m) {
            let prev = self.started_from(name).unwrap_or_else(|_| m.clone());
            let _ = self.guests.down(&ctx, &prev);
        }
        if let Err(err) = self.guests.up(&ctx, &mut m) {
            return Err(refuse(
                500,
                CODE_START_FAILED,
                "see 'limbo doctor' and the Limbo log",
                format!("instance {} did not start: {err}", gotext::quote(name)),
            ));
        }
        drop(_g);
        self.get(name, c)
    }

    pub fn stop(&self, name: &str, c: &Caller) -> Result<View, Refusal> {
        self.may_change(name, c)?;
        let l = self.lock(name);
        let _g = l.lock().unwrap_or_else(|x| x.into_inner());
        let ctx = Ctx::background();
        let q = gotext::quote(name);
        let m = match self.started_from(name) {
            Ok(m) if self.guests.defined(&ctx, &m) => m,
            _ => return Err(refuse(409, CODE_NOT_RUNNING, "nothing to do", format!("instance {q} is not running"))),
        };
        self.audit(EVENT_REQUEST, name, c, detail([("action", "stop")]))?;
        if let Err(err) = self.guests.down(&ctx, &m) {
            return Err(refuse(
                500,
                CODE_STOP_FAILED,
                "see the Limbo log; root can run 'limbo down'",
                format!("instance {q} did not stop cleanly: {err}"),
            ));
        }
        self.guests.clean_state(&m);
        drop(_g);
        self.get(name, c)
    }

    pub fn configure(&self, name: &str, ch: &Change, c: &Caller) -> Result<View, Refusal> {
        let e = self.may_change(name, c)?;
        let l = self.lock(name);
        let g = l.lock().unwrap_or_else(|x| x.into_inner());
        let mut o = self.overrides(name);
        let (cpus, mem_mb) = self.host_limits.map(|f| f()).unwrap_or((64, 1 << 20));
        let bad = |remedy: String, msg: String| refuse(400, CODE_OUT_OF_RANGE, &remedy, msg);
        let mut changed: Vec<&str> = vec![];
        if let Some(n) = ch.cpus {
            if n < 1 || n > cpus {
                return Err(bad(format!("choose 1 to {cpus}"), format!("processors must be 1 to {cpus} (this computer has {cpus})")));
            }
            o.cpus = n;
            changed.push("cpus");
        }
        if let Some(n) = ch.memory_mb {
            let limit = (mem_mb - HOST_RESERVE_MB).max(512);
            if n < 512 || n > limit {
                return Err(bad(
                    format!("choose 512 to {limit} MiB"),
                    format!("memory must be 512 to {limit} MiB (the computer keeps {HOST_RESERVE_MB} MiB for itself)"),
                ));
            }
            o.memory_mb = n;
            changed.push("memory_mb");
        }
        if let Some(n) = ch.disk_gb {
            let mut cur = 0i64;
            if let Ok(m) = self.effective(&e, &o) {
                if let Ok(x) = disk::virtual_size(&sys::join(&[&self.state_dir, &virt::disk_name(&m)])) {
                    cur = x;
                } else if let Ok(x) = disk::virtual_size(&m.image.path) {
                    cur = x;
                }
            }
            let min = ((cur + ((1 << 30) - 1)) >> 30).max(1);
            if n < min || n > manifest::MAX_DISK_GB {
                return Err(bad(
                    format!("choose {min} to {} GiB", manifest::MAX_DISK_GB),
                    format!("a disk can only grow: {min} to {} GiB", manifest::MAX_DISK_GB),
                ));
            }
            o.disk_gb = n;
            changed.push("disk_gb");
        }
        if let Some(sf) = &ch.shared_folder {
            if sf != "off" && sf != "on" {
                return Err(bad("send \"off\" or \"on\"".into(), "shared_folder must be off or on".into()));
            }
            o.shared_folder = sf.clone();
            changed.push("shared_folder");
        }
        if let Some(cb) = &ch.clipboard {
            if cb != manifest::CLIP_OFF && cb != manifest::CLIP_TEXT {
                return Err(bad("send \"off\" or \"text\"".into(), "clipboard must be off or text".into()));
            }
            o.clipboard = cb.clone();
            changed.push("clipboard");
        }
        if let Some(devs) = &ch.devices {
            let allowed: HashSet<String> = e.manifest.devices.all().into_iter().collect();
            let mut seen = HashSet::new();
            for d in devs {
                if !allowed.contains(d) || !seen.insert(d.clone()) {
                    return Err(bad(
                        "choose among the devices the instance's manifest names".into(),
                        format!(
                            "device {} is not one the manifest names (devices are given by root, then the host's passthrough policy)",
                            gotext::quote(d)
                        ),
                    ));
                }
            }
            o.devices = Some(devs.clone());
            changed.push("devices");
        }
        let mut d = Detail::new();
        if let Some(n) = &ch.network {
            if !c.admin {
                return Err(refuse(
                    403,
                    CODE_NOT_OWNER,
                    "Settings asks for the password and changes it as root",
                    "a guest's network is changed by an administrator only".into(),
                ));
            }
            if let Some(h) = self.hold(name) {
                return Err(refuse(
                    409,
                    CODE_HELD,
                    "decide about it on Heimdall's page (Settings > Security) first",
                    format!("instance {} is held ({}): its network stays as it is", gotext::quote(name), h.id),
                ));
            }
            let n = Network { mode: n.mode.clone(), allow: n.allow.clone().filter(|a| !a.is_empty()) };
            n.validate().map_err(|err| bad("none, internet-only, or allowlist with at least one address:proto:port".into(), err))?;
            d.insert("network".into(), n.mode.clone());
            o.network = Some(n);
            changed.push("network");
        }
        if changed.is_empty() {
            return Err(bad(
                "send at least one of cpus, memory_mb, disk_gb, shared_folder, clipboard, devices, network".into(),
                "nothing to change".into(),
            ));
        }
        self.effective(&e, &o)?;
        d.insert("changed".into(), changed.join(","));
        self.audit(EVENT_CHANGE, name, c, d)?;
        self.save_overrides(name, &o).map_err(|err| Refusal::new(Some(500), "internal", "", err))?;
        drop(g);
        self.get(name, c)
    }

    pub fn free_space(&self, name: &str, c: &Caller) -> Result<i64, Refusal> {
        let e = self.may_change(name, c)?;
        let q = gotext::quote(name);
        if let Some(h) = self.hold(name) {
            return Err(refuse(
                409,
                CODE_HELD,
                "its disk is evidence; decide about it on Heimdall's page first",
                format!("instance {q} is held ({})", h.id),
            ));
        }
        let l = self.lock(name);
        let _g = l.lock().unwrap_or_else(|x| x.into_inner());
        let m = &e.manifest;
        if self.running().contains(&virt::domain_name(m)) || self.guests.defined(&Ctx::background(), m) {
            return Err(refuse(409, CODE_RUNNING, "stop it first", format!("instance {q} is running")));
        }
        let p = sys::join(&[&self.state_dir, &virt::persistent_disk_name(m)]);
        let n = disk::allocated(&p);
        self.audit(EVENT_CHANGE, name, c, detail([("changed", "free_space")]))?;
        match std::fs::remove_file(&p) {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
                Err(Refusal::new(Some(500), "internal", "", sys::go_path_error("remove", &p, &err)))
            }
            _ => Ok(n),
        }
    }

    /// Registers an instance (root only). `raw` is the manifest as the caller sent it (Go marshals and parses it).
    pub fn add(&self, m: &Manifest, owner: &str, c: &Caller) -> Result<View, Refusal> {
        if !c.admin {
            return Err(refuse(403, CODE_BAD_REQUEST, "use the password (sudo or pkexec)", "only root registers instances".into()));
        }
        let pm = manifest::parse(m.json().as_bytes())
            .map_err(|e| refuse(400, CODE_BAD_REQUEST, "fix the manifest ('limbo validate FILE')", e))?;
        if pm.disposable {
            return Err(refuse(
                400,
                CODE_BAD_REQUEST,
                "set \"disposable\": false; disposable guests are for runs",
                "an instance is kept, so it cannot be disposable".into(),
            ));
        }
        if crate::runs::run_id_ok(&pm.name) {
            return Err(refuse(
                400,
                CODE_BAD_REQUEST,
                "choose another name",
                format!("names like {} are kept for runs", gotext::quote(&pm.name)),
            ));
        }
        if !owner.is_empty() && !user_ok(owner) {
            return Err(refuse(
                400,
                CODE_BAD_REQUEST,
                "give an account name",
                format!("owner {} is not an account name", gotext::quote(owner)),
            ));
        }
        let l = self.lock(&pm.name);
        let _g = l.lock().unwrap_or_else(|x| x.into_inner());
        if std::fs::symlink_metadata(self.entry_path(&pm.name)).is_ok() {
            return Err(refuse(
                409,
                CODE_EXISTS,
                "remove it first, or choose another name",
                format!("instance {} already exists", gotext::quote(&pm.name)),
            ));
        }
        let internal = |e: std::io::Error| Refusal::new(Some(500), "internal", "", sys::go_err(&e));
        sys::mkdir_all(&self.dir, 0o755).map_err(internal)?;
        let doc = Obj::new().raw("manifest", &pm.json()).str_omit("owner", owner).end();
        let tmp = format!("{}.tmp", self.entry_path(&pm.name));
        sys::write_file(&tmp, gojson::indent(&doc, "  ").as_bytes(), 0o644).map_err(internal)?;
        std::fs::rename(&tmp, self.entry_path(&pm.name)).map_err(internal)?;
        let _ = self.audit(EVENT_ADD, &pm.name, c, detail([("owner", owner)]));
        let e = Entry { manifest: pm.clone(), owner: owner.into() };
        Ok(self.view(&pm, "instance", Some(&e), &Overrides::default(), &HashSet::new(), c))
    }

    pub fn remove(&self, name: &str, delete_disk: bool, c: &Caller) -> Result<(), Refusal> {
        if !c.admin {
            return Err(refuse(403, CODE_BAD_REQUEST, "use the password (sudo or pkexec)", "only root removes instances".into()));
        }
        let e = self.load(name)?;
        let l = self.lock(name);
        let _g = l.lock().unwrap_or_else(|x| x.into_inner());
        let q = gotext::quote(name);
        if self.guests.defined(&Ctx::background(), &e.manifest) {
            return Err(refuse(409, CODE_RUNNING, "stop it first", format!("instance {q} is running")));
        }
        if delete_disk {
            if let Some(h) = self.hold(name) {
                return Err(refuse(
                    409,
                    CODE_HELD,
                    "its disk is evidence; decide about it on Heimdall's page first",
                    format!("instance {q} is held ({})", h.id),
                ));
            }
        }
        let _ = self.audit(EVENT_REMOVE, name, c, detail([("delete_disk", if delete_disk { "true" } else { "false" })]));
        std::fs::remove_file(self.entry_path(name))
            .map_err(|err| Refusal::new(Some(500), "internal", "", sys::go_path_error("remove", &self.entry_path(name), &err)))?;
        let _ = std::fs::remove_file(self.override_path(name));
        if delete_disk {
            let _ = std::fs::remove_file(sys::join(&[&self.state_dir, &virt::persistent_disk_name(&e.manifest)]));
        }
        Ok(())
    }
}

/// The host's processors and memory (MiB).
pub fn host_limits() -> (i64, i64) {
    let mut mem = 0;
    if let Ok(t) = std::fs::read_to_string("/proc/meminfo") {
        for line in t.lines() {
            if let Some(r) = line.strip_prefix("MemTotal:") {
                let kb: i64 = r.trim().trim_end_matches("kB").trim().parse().unwrap_or(0);
                mem = kb / 1024;
                break;
            }
        }
    }
    // Go's runtime.NumCPU: the CPUs this process may run on (no cgroup quota, unlike available_parallelism)
    let cpus = rustix::thread::sched_getaffinity(None).map(|s| s.count() as i64).unwrap_or(1);
    (cpus, mem)
}
