//! Whether this host lets a guest have real hardware, and whether now is a safe moment (Go: internal/hostpolicy, the
//! parts limbo serve uses). LykanOS never (hard-coded), Labyrinth only for devices on root's list, any other OS never;
//! a person's approval, nothing on the host using the device, no earlier damage. Everything fails closed. Approving
//! is `limbo passthrough approve` at a terminal (cli/passthrough.rs): no socket route can approve, here or in Go.

use crate::gotime::Time;
use crate::manifest::{self, Devices, Manifest};
use crate::{go_struct, gojson, gotext, sys};
use std::collections::{BTreeMap, HashSet};

pub const DEFAULT_CONFIG: &str = "/etc/limbo/host-policy.json";
const CONFIG_REL: &str = "etc/limbo/host-policy.json";
const OS_RELEASE_REL: &str = "etc/os-release";
const PCI_REL: &str = "sys/bus/pci/devices";
const USB_REL: &str = "sys/bus/usb/devices";
const APPROVAL_FILE: &str = "passthrough-approval.json";
const BLOCKED_FILE: &str = "passthrough.blocked";
const MAX_WHO: usize = 10;

/// Why hardware is refused: the kinds runs tell apart.
#[derive(Clone, Debug, PartialEq)]
pub enum Refused {
    Denied(String),
    NeedsApproval,
    Busy(Vec<String>),
    RebootNeeded,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Denied(r) => write!(f, "hardware passthrough denied: {r}"),
            Refused::NeedsApproval => f.write_str("no passthrough approval is in effect"),
            Refused::Busy(who) => write!(f, "the device is in use on the host by: {}", who.join(", ")),
            Refused::RebootNeeded => f.write_str("a passthrough device did not return to the host cleanly; reboot the host"),
        }
    }
}

fn deny(s: String) -> Refused {
    Refused::Denied(s)
}

#[derive(Default)]
struct Config {
    pci_allow: Option<Vec<String>>,
    usb_allow: Option<Vec<String>>,
    usb_standing: Option<Vec<String>>,
}
go_struct!(Config as "hostpolicy.Config" { pci_allow: "pci_allow" => "[]string", usb_allow: "usb_allow" => "[]string", usb_standing: "usb_standing" => "[]string" });

/// A person's permission, for a limited time, to hand the named devices to guests (root's file in the state folder).
#[derive(Default)]
pub struct Approval {
    pub devices: Option<Vec<String>>,
    pub expires: Time,
    pub by: String,
}

/// MaxApproval: how long one approval can last at most (2 hours, in nanoseconds).
pub const MAX_APPROVAL: i64 = 2 * 3600 * 1_000_000_000;
go_struct!(Approval as "hostpolicy.Approval" { devices: "devices" => "[]string", expires: "expires" => "time.Time", by: "by" => "string" });

/// The host's policy. `root` is where the host's files are read from ("/" in production, a folder in tests).
pub struct Policy {
    pub root: String,
    pub state_dir: String,
    pub run_dir: String,
    pub now: fn() -> Time,
    /// process label -> the files it holds open (None: /proc)
    pub open_files: Option<Box<dyn Fn() -> BTreeMap<String, Vec<String>> + Send + Sync>>,
    pub driver: Option<Box<dyn Fn(&str) -> String + Send + Sync>>,
    pub usb_driver: Option<Box<dyn Fn(&str) -> String + Send + Sync>>,
}

impl Policy {
    pub fn new(state_dir: &str, run_dir: &str) -> Policy {
        Policy {
            root: "/".into(),
            state_dir: state_dir.into(),
            run_dir: run_dir.into(),
            now: Time::now,
            open_files: None,
            driver: None,
            usb_driver: None,
        }
    }

    fn at(&self, rel: &str) -> String {
        sys::join(&[&self.root, rel])
    }

    fn read_trim(&self, rel: &str) -> String {
        std::fs::read(self.at(rel)).map(|b| gotext::trim_space(&gotext::lossy(&b)).to_string()).unwrap_or_default()
    }

    fn config(&self) -> Result<Config, Refused> {
        let b = std::fs::read(self.at(CONFIG_REL)).map_err(|_| deny("the host has no passthrough device list".into()))?;
        gojson::unmarshal(&b, Config::default(), "hostpolicy.Config")
            .map_err(|_| deny("the host's passthrough device list is unreadable".into()))
    }

    pub fn standing(&self) -> (Vec<String>, Vec<String>) {
        let Ok(cfg) = self.config() else { return (vec![], vec![]) };
        let allowed: HashSet<String> = cfg.usb_allow.unwrap_or_default().iter().map(|a| gotext::to_lower(a)).collect();
        let (mut standing, mut ignored) = (vec![], vec![]);
        for s in cfg.usb_standing.unwrap_or_default() {
            let id = gotext::to_lower(&s);
            if manifest::usb_id_ok(&id) && allowed.contains(&id) {
                standing.push(id);
            } else {
                ignored.push(s);
            }
        }
        (standing, ignored)
    }

    pub fn host_id(&self) -> String {
        let Ok(b) = std::fs::read(self.at(OS_RELEASE_REL)) else { return String::new() };
        for line in gotext::lossy(&b).split('\n') {
            let line = gotext::trim_space(line.strip_suffix('\r').unwrap_or(line));
            if let Some(v) = line.strip_prefix("ID=") {
                return gotext::to_lower(v.trim_matches(['"', '\'']));
            }
        }
        String::new()
    }

    /// May the host ever give these devices (static).
    pub fn check(&self, m: &Manifest) -> Result<(), Refused> {
        if !m.devices.any() {
            return Ok(());
        }
        let id = self.host_id();
        if id == "lykanos" || id == "chymaera" {
            return Err(deny(format!("this host ({id}) does not allow hardware passthrough")));
        }
        if id != "labyrinth" {
            return Err(deny("this host's OS does not allow hardware passthrough".into()));
        }
        let cfg = self.config()?;
        let allowed: HashSet<String> = cfg.pci_allow.unwrap_or_default().iter().map(|a| gotext::to_lower(a)).collect();
        self.check_usb(m.devices.usb(), &cfg.usb_allow.unwrap_or_default())?;
        let want: HashSet<&String> = m.devices.pci().iter().collect();
        for a in m.devices.pci() {
            if !allowed.contains(a) {
                return Err(deny(format!("device {a} is not on the host's passthrough list")));
            }
            let dev = format!("{PCI_REL}/{a}");
            if std::fs::metadata(self.at(&dev)).is_err() {
                return Err(deny(format!("device {a} is not present on the host")));
            }
            if self.read_trim(&format!("{dev}/boot_vga")) == "1" {
                return Err(deny(format!("device {a} is the host's boot display")));
            }
            let members = sys::read_dir_sorted(&self.at(&format!("{dev}/iommu_group/devices"))).unwrap_or_default();
            if members.is_empty() {
                return Err(deny(format!("device {a} has no IOMMU group (is the IOMMU enabled?)")));
            }
            for (n, _) in members {
                if want.contains(&n) || self.read_trim(&format!("{PCI_REL}/{n}/class")).starts_with("0x0604") {
                    continue;
                }
                return Err(deny(format!("device {a} shares an IOMMU group with {n}, which was not requested")));
            }
        }
        Ok(())
    }

    fn check_usb(&self, ids: &[String], allow: &[String]) -> Result<(), Refused> {
        let ok: HashSet<String> = allow.iter().map(|a| gotext::to_lower(a)).collect();
        for id in ids {
            if !ok.contains(id) {
                return Err(deny(format!("USB device {id} is not on the host's passthrough list")));
            }
            let devs = self.usb_devices(id);
            if devs.is_empty() {
                return Err(deny(format!("USB device {id} is not plugged in")));
            }
            if devs.len() > 1 {
                return Err(deny(format!("{} USB devices with ID {id} are plugged in; leave only the one to pass through", devs.len())));
            }
            if self.read_trim(&format!("{USB_REL}/{}/bDeviceClass", devs[0])) == "09" {
                return Err(deny(format!("USB device {id} is a hub")));
            }
        }
        Ok(())
    }

    fn usb_devices(&self, id: &str) -> Vec<String> {
        let (vendor, product) = id.split_once(':').unwrap_or((id, ""));
        let mut out = vec![];
        for (n, _) in sys::read_dir_sorted(&self.at(USB_REL)).unwrap_or_default() {
            if n.contains(':') {
                continue;
            }
            let dir = format!("{USB_REL}/{n}");
            if gotext::to_lower(&self.read_trim(&format!("{dir}/idVendor"))) == vendor
                && gotext::to_lower(&self.read_trim(&format!("{dir}/idProduct"))) == product
            {
                out.push(n);
            }
        }
        out
    }

    fn approval_path(&self) -> String {
        sys::join(&[&self.state_dir, APPROVAL_FILE])
    }

    fn blocked_path(&self) -> String {
        let d = if self.run_dir.is_empty() { "/run/limbo" } else { &self.run_dir };
        sys::join(&[d, BLOCKED_FILE])
    }

    /// The devices approved now (an approval file that is unreadable, damaged, expired or readable by others counts as none).
    fn approved(&self) -> Option<Vec<String>> {
        if self.state_dir.is_empty() {
            return None;
        }
        let m = std::fs::metadata(self.approval_path()).ok()?;
        if !m.is_file() || sys::Stat::of(&m).perm() & 0o077 != 0 {
            return None;
        }
        let b = std::fs::read(self.approval_path()).ok()?;
        let a = gojson::unmarshal(&b, Approval::default(), "hostpolicy.Approval").ok()?;
        if !(self.now)().before(&a.expires) {
            return None;
        }
        Some(a.devices.unwrap_or_default())
    }

    /// Approval: the approval in effect, or None (unreadable, damaged, expired or readable by others counts as none).
    pub fn approval(&self) -> Option<Approval> {
        if self.state_dir.is_empty() {
            return None;
        }
        let m = std::fs::metadata(self.approval_path()).ok()?;
        if !m.is_file() || sys::Stat::of(&m).perm() & 0o077 != 0 {
            return None;
        }
        let b = std::fs::read(self.approval_path()).ok()?;
        let a = gojson::unmarshal(&b, Approval::default(), "hostpolicy.Approval").ok()?;
        if !(self.now)().before(&a.expires) {
            return None;
        }
        Some(a)
    }

    /// CanApprove: the devices are eligible here (check) and nothing on the host uses them; writes nothing.
    pub fn can_approve(&self, devs: &[String]) -> Result<(), Refused> {
        if self.blocked() {
            return Err(Refused::RebootNeeded);
        }
        let m = Manifest { devices: split(devs), ..Default::default() };
        self.check(&m)?;
        let who = self.busy(&m.devices);
        if !who.is_empty() {
            return Err(Refused::Busy(who));
        }
        Ok(())
    }

    /// Approve: records the approval of `devs` for `d` nanoseconds, after the same checks as can_approve.
    pub fn approve(&self, devs: &[String], d: i64, by: &str) -> Result<Approval, String> {
        if self.state_dir.is_empty() {
            return Err("hostpolicy: no state directory".into());
        }
        if d <= 0 || d > MAX_APPROVAL {
            return Err("hostpolicy: an approval lasts between 1 minute and 2h0m0s".into());
        }
        self.can_approve(devs).map_err(|e| e.to_string())?;
        let a = Approval { devices: Some(devs.to_vec()), expires: (self.now)().add(d).utc(), by: by.to_string() };
        let b = gojson::Obj::new().strs("devices", devs).str("expires", &a.expires.rfc3339_nano()).str("by", by).end();
        sys::go_mkdir_all(&self.state_dir, 0o700)?;
        let tmp = format!("{}.tmp", self.approval_path());
        sys::write_file(&tmp, b.as_bytes(), 0o600).map_err(|e| sys::go_path_error("open", &tmp, &e))?;
        std::fs::rename(&tmp, self.approval_path()).map_err(|e| format!("rename {tmp} {}: {}", self.approval_path(), sys::go_err(&e)))?;
        Ok(a)
    }

    /// Revoke: ends any approval now.
    pub fn revoke(&self) -> Result<(), String> {
        if self.state_dir.is_empty() {
            return Ok(());
        }
        go_remove(&self.approval_path())
    }

    /// Clear: removes the reboot-needed marker.
    pub fn clear(&self) -> Result<(), String> {
        go_remove(&self.blocked_path())
    }

    pub fn blocked(&self) -> bool {
        std::fs::metadata(self.blocked_path()).is_ok()
    }

    /// Is handing the guest its devices safe right now.
    pub fn ready(&self, m: &Manifest) -> Result<(), Refused> {
        if !m.devices.any() {
            return Ok(());
        }
        if self.blocked() {
            return Err(Refused::RebootNeeded);
        }
        let mut have: HashSet<String> = self.approved().unwrap_or_default().into_iter().collect();
        have.extend(self.standing().0);
        if m.devices.all().iter().any(|d| !have.contains(d)) {
            return Err(Refused::NeedsApproval);
        }
        let who = self.busy(&m.devices);
        if !who.is_empty() {
            return Err(Refused::Busy(who));
        }
        Ok(())
    }

    fn busy(&self, d: &Devices) -> Vec<String> {
        let mut exact: HashSet<String> = HashSet::new();
        let mut prefix: Vec<String> = vec![];
        let mut who: Vec<String> = vec![];
        for id in d.usb() {
            for dev in self.usb_devices(id) {
                let dir = format!("{USB_REL}/{dev}");
                let bus: i64 = gotext::atoi(&self.read_trim(&format!("{dir}/busnum"))).unwrap_or(0);
                let num: i64 = gotext::atoi(&self.read_trim(&format!("{dir}/devnum"))).unwrap_or(0);
                exact.insert(format!("/dev/bus/usb/{bus:03}/{num:03}"));
                for (n, _) in sys::read_dir_sorted(&self.at(USB_REL)).unwrap_or_default() {
                    if !n.starts_with(&format!("{dev}:")) {
                        continue;
                    }
                    let drv = self.usb_driver(&n);
                    if !drv.is_empty() && drv != "usbfs" {
                        who.push(format!("the host's {drv} driver"));
                    }
                }
            }
        }
        for a in d.pci() {
            let dev = format!("{PCI_REL}/{a}");
            for (n, _) in sys::read_dir_sorted(&self.at(&format!("{dev}/drm"))).unwrap_or_default() {
                exact.insert(format!("/dev/dri/{n}"));
            }
            for (n, _) in sys::read_dir_sorted(&self.at(&format!("{dev}/sound"))).unwrap_or_default() {
                if let Some(c) = n.strip_prefix("card") {
                    prefix.push(format!("/dev/snd/controlC{c}"));
                    prefix.push(format!("/dev/snd/pcmC{c}D"));
                }
            }
            if self.read_trim(&format!("{dev}/vendor")) == "0x10de" {
                prefix.push("/dev/nvidia".into());
            }
        }
        let open = match &self.open_files {
            Some(f) => f(),
            None => scan_proc(),
        };
        for (label, files) in open {
            if files.iter().any(|f| exact.contains(f) || prefix.iter().any(|p| f.starts_with(p.as_str()))) {
                who.push(label);
            }
        }
        who.sort();
        if who.len() > MAX_WHO {
            let more = who.len() - MAX_WHO;
            who.truncate(MAX_WHO);
            who.push(format!("and {more} more"));
        }
        who
    }

    fn usb_driver(&self, iface: &str) -> String {
        if let Some(f) = &self.usb_driver {
            return f(iface);
        }
        std::fs::read_link(format!("/sys/bus/usb/devices/{iface}/driver")).map(|t| sys::base(&t.to_string_lossy())).unwrap_or_default()
    }

    fn driver(&self, addr: &str) -> String {
        if let Some(f) = &self.driver {
            return f(addr);
        }
        std::fs::read_link(format!("/sys/bus/pci/devices/{addr}/driver")).map(|t| sys::base(&t.to_string_lossy())).unwrap_or_default()
    }

    /// The host driver of each requested PCI device, to compare with after teardown.
    pub fn before(&self, m: &Manifest) -> BTreeMap<String, String> {
        m.devices.pci().iter().map(|a| (a.clone(), self.driver(a))).collect()
    }

    /// After teardown, every device must be back under its driver; if not, a reboot is needed (a marker in the run
    /// folder blocks every later passthrough start).
    pub fn after(&self, m: &Manifest, before: Option<&BTreeMap<String, String>>) -> Result<(), String> {
        for a in m.devices.pci() {
            let now = self.driver(a);
            let want = before.and_then(|b| b.get(a));
            if want.is_some_and(|w| *w != now) || (want.is_none() && now == "vfio-pci") {
                let why = format!("device {a} is bound to {} after teardown", gotext::quote(&now));
                let p = self.blocked_path();
                if sys::mkdir_all(sys::dir(&p), 0o755).is_ok() {
                    let _ = sys::write_file(&p, format!("{why}\n").as_bytes(), 0o600);
                }
                return Err(why);
            }
        }
        Ok(())
    }
}

/// For every process: the files it holds open.
fn scan_proc() -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    let Ok(rd) = std::fs::read_dir("/proc") else { return out };
    for e in rd.flatten() {
        let pid = e.file_name().to_string_lossy().into_owned();
        if gotext::atoi(&pid).is_none() {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        let files: Vec<String> =
            fds.flatten().filter_map(|fd| std::fs::read_link(fd.path()).ok()).map(|t| t.to_string_lossy().into_owned()).collect();
        if files.is_empty() {
            continue;
        }
        let comm =
            std::fs::read(format!("/proc/{pid}/comm")).map(|b| gotext::trim_space(&gotext::lossy(&b)).to_string()).unwrap_or_default();
        out.insert(format!("{comm} ({pid})"), files);
    }
    out
}

/// split: the named devices sorted into PCI addresses and USB IDs by their form (a USB ID is vendor:product).
fn split(devs: &[String]) -> Devices {
    let (mut pci, mut usb) = (None::<Vec<String>>, None::<Vec<String>>);
    for x in devs {
        if manifest::usb_id_ok(x) {
            usb.get_or_insert_with(Vec::new).push(x.clone());
        } else {
            pci.get_or_insert_with(Vec::new).push(x.clone());
        }
    }
    Devices { pci, usb }
}

/// os.Remove, and its error unless the path did not exist (as `!os.IsNotExist(err)` reads it): unlink, then rmdir;
/// when both fail, rmdir's error unless it is ENOTDIR.
fn go_remove(p: &str) -> Result<(), String> {
    let Err(e) = std::fs::remove_file(p) else { return Ok(()) };
    let e = match std::fs::remove_dir(p) {
        Ok(()) => return Ok(()),
        Err(e1) if e1.raw_os_error() != Some(libc::ENOTDIR) => e1,
        Err(_) => e,
    };
    if e.kind() == std::io::ErrorKind::NotFound {
        return Ok(());
    }
    Err(sys::go_path_error("remove", p, &e))
}
