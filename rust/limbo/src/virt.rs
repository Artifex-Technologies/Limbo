//! A manifest turned into libvirt definitions, the guests' names and their subnets (Go: internal/virt). The XML is
//! written as Go's encoding/xml MarshalIndent writes it, byte for byte, with every value escaped (a manifest value can
//! never leave its attribute).

use crate::gojson;
use crate::manifest::{self, Manifest};
use crate::sys;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub fn domain_name(m: &Manifest) -> String {
    format!("limbo-{}", m.name)
}
pub fn network_name(m: &Manifest) -> String {
    format!("limbo-{}", m.name)
}
/// CONTRACT (Heimdall relies on it, 2026-11-07): a tap named tap_name on the bridge named bridge_name is Limbo's own guest.
pub fn bridge_name(m: &Manifest) -> String {
    format!("lb-{}", m.name)
}
pub fn tap_name(m: &Manifest) -> String {
    format!("vl-{}", m.name)
}
pub fn overlay_name(m: &Manifest) -> String {
    format!("{}.overlay.qcow2", m.name)
}
pub fn persistent_disk_name(m: &Manifest) -> String {
    format!("{}.disk.qcow2", m.name)
}
pub fn disk_name(m: &Manifest) -> String {
    if m.disposable {
        overlay_name(m)
    } else {
        persistent_disk_name(m)
    }
}

/// A guest's addressing in 10.213.X.0/24.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Addressing {
    pub gateway: [u8; 4],
    pub guest: [u8; 4],
    pub mac: String,
}

pub fn ip4(a: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

pub fn addr(m: &Manifest) -> Addressing {
    let h = Sha256::digest(m.name.as_bytes());
    let mut x = 1 + (h[0] as i64) % 254;
    if (1..=254).contains(&m.subnet) {
        x = m.subnet;
    }
    Addressing {
        gateway: [10, 213, x as u8, 1],
        guest: [10, 213, x as u8, 2],
        mac: format!("52:54:00:{:02x}:{:02x}:{:02x}", h[1], h[2], h[3]),
    }
}

// ---- XML, as encoding/xml writes it ----

/// One element: its attributes (only the non-empty ones are written, as `omitempty` does), its text or its children.
struct El {
    name: &'static str,
    attrs: Vec<(&'static str, String)>,
    text: Option<String>,
    kids: Vec<El>,
}

fn el(name: &'static str) -> El {
    El { name, attrs: Vec::new(), text: None, kids: Vec::new() }
}

impl El {
    /// An attribute always written (no omitempty).
    fn at(mut self, k: &'static str, v: impl Into<String>) -> El {
        self.attrs.push((k, v.into()));
        self
    }
    /// An attribute left out when empty (Go's attrs struct, all omitempty).
    fn ao(self, k: &'static str, v: &str) -> El {
        if v.is_empty() {
            self
        } else {
            self.at(k, v)
        }
    }
    fn text(mut self, t: impl Into<String>) -> El {
        self.text = Some(t.into());
        self
    }
    fn kid(mut self, k: El) -> El {
        self.kids.push(k);
        self
    }
}

/// Go's EscapeText/EscapeString: the five specials and the white space Go writes as character references; a character
/// XML does not allow becomes U+FFFD.
fn esc(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c if !in_char_range(c) => out.push('\u{FFFD}'),
            c => out.push(c),
        }
    }
}

fn in_char_range(c: char) -> bool {
    let r = c as u32;
    r == 0x09
        || r == 0x0A
        || r == 0x0D
        || (0x20..=0xD7FF).contains(&r)
        || (0xE000..=0xFFFD).contains(&r)
        || (0x10000..=0x10FFFF).contains(&r)
}

fn render(e: &El, depth: usize, out: &mut String) {
    if depth > 0 {
        out.push('\n');
    }
    out.push_str(&"  ".repeat(depth));
    out.push('<');
    out.push_str(e.name);
    for (k, v) in &e.attrs {
        out.push(' ');
        out.push_str(k);
        out.push_str("=\"");
        esc(v, out);
        out.push('"');
    }
    out.push('>');
    if let Some(t) = &e.text {
        esc(t, out);
    }
    for k in &e.kids {
        render(k, depth + 1, out);
    }
    if !e.kids.is_empty() {
        out.push('\n');
        out.push_str(&"  ".repeat(depth));
    }
    out.push_str("</");
    out.push_str(e.name);
    out.push('>');
}

fn marshal(e: &El) -> String {
    let mut s = String::new();
    render(e, 0, &mut s);
    s.push('\n');
    s
}

fn pci_hostdev(a: &str) -> Result<El, String> {
    let b = a.as_bytes();
    if b.len() != 12 || b[4] != b':' || b[7] != b':' || b[10] != b'.' {
        return Err(format!("virt: bad PCI address {}", crate::gotext::quote(a)));
    }
    Ok(el("hostdev").at("mode", "subsystem").at("type", "pci").at("managed", "yes").kid(
        el("source").kid(
            el("address")
                .at("domain", format!("0x{}", &a[0..4]))
                .at("bus", format!("0x{}", &a[5..7]))
                .at("slot", format!("0x{}", &a[8..10]))
                .at("function", format!("0x{}", &a[11..12])),
        ),
    ))
}

fn usb_hostdev(id: &str) -> Result<El, String> {
    if !manifest::usb_id_ok(id) {
        return Err(format!("virt: bad USB ID {}", crate::gotext::quote(id)));
    }
    Ok(el("hostdev")
        .at("mode", "subsystem")
        .at("type", "usb")
        .kid(el("source").kid(el("vendor").at("id", format!("0x{}", &id[0..4]))).kid(el("product").at("id", format!("0x{}", &id[5..9])))))
}

struct Disk<'a> {
    device: &'a str,
    driver_type: &'a str,
    file: &'a str,
    backing: Option<&'a str>,
    dev: &'a str,
    bus: &'a str,
    boot: Option<i32>,
    readonly: bool,
}

fn disk_el(d: &Disk) -> El {
    let mut e = el("disk")
        .at("type", "file")
        .at("device", d.device)
        .kid(el("driver").ao("type", d.driver_type).ao("name", "qemu"))
        .kid(el("source").ao("file", d.file));
    if let Some(base) = d.backing {
        e = e.kid(
            el("backingStore")
                .at("type", "file")
                .kid(el("format").ao("type", "qcow2"))
                .kid(el("source").at("file", base).kid(el("seclabel").at("model", "dac").at("relabel", "no"))),
        );
    }
    e = e.kid(el("target").ao("dev", d.dev).ao("bus", d.bus));
    if let Some(o) = d.boot {
        e = e.kid(el("boot").at("order", o.to_string()));
    }
    if d.readonly {
        e = e.kid(el("readonly"));
    }
    e
}

/// The libvirt domain. `root_disk` is the overlay the guest boots from, never the base image.
pub fn domain_xml(m: &Manifest, root_disk: &str) -> Result<String, String> {
    let win = m.os == manifest::OS_WINDOWS;
    let (bus, nic, root_dev, seed_dev) = if win { ("sata", "e1000e", "sda", "sdb") } else { ("virtio", "virtio", "vda", "sda") };
    let mut d = el("domain")
        .at("type", "kvm")
        .kid(el("name").text(domain_name(m)))
        .kid(el("memory").at("unit", "MiB").text(m.memory_mb.to_string()));
    d = d.kid(el("vcpu").text(m.cpus.to_string()));
    if !m.exchange_dir.is_empty() {
        d = d.kid(el("memoryBacking").kid(el("source").ao("type", "memfd")).kid(el("access").ao("mode", "shared")));
    }
    d = d.kid(el("os").kid(el("type").at("arch", "x86_64").at("machine", "q35").text("hvm")));
    let mut feat = el("features").kid(el("acpi")).kid(el("apic"));
    if win {
        feat = feat.kid(el("hyperv").kid(el("relaxed").ao("state", "on")).kid(el("spinlocks").at("state", "on").at("retries", "8191")));
    }
    d = d.kid(feat);
    d = d.kid(el("cpu").ao("mode", "host-passthrough"));
    d = d.kid(el("on_poweroff").text("destroy")).kid(el("on_reboot").text("restart")).kid(el("on_crash").text("destroy"));

    let mut dev = el("devices");
    let win_iso = win && !m.windows.iso.is_empty();
    dev = dev.kid(disk_el(&Disk {
        device: "disk",
        driver_type: "qcow2",
        file: root_disk,
        backing: Some(&m.image.path),
        dev: root_dev,
        bus,
        boot: win_iso.then_some(1),
        readonly: false,
    }));
    if !m.provision.seed_iso.is_empty() {
        dev = dev.kid(disk_el(&Disk {
            device: "cdrom",
            driver_type: "raw",
            file: &m.provision.seed_iso,
            backing: None,
            dev: seed_dev,
            bus: "sata",
            boot: None,
            readonly: true,
        }));
    }
    if win_iso {
        dev = dev.kid(disk_el(&Disk {
            device: "cdrom",
            driver_type: "raw",
            file: &m.windows.iso,
            backing: None,
            dev: "sdc",
            bus: "sata",
            boot: Some(2),
            readonly: true,
        }));
    }
    let a = addr(m);
    dev = dev.kid(
        el("interface")
            .at("type", "network")
            .kid(el("mac").ao("address", &a.mac))
            .kid(el("source").ao("network", &network_name(m)))
            .kid(el("target").ao("dev", &tap_name(m)))
            .kid(el("model").ao("type", nic)),
    );
    if !m.exchange_dir.is_empty() {
        let mut fs = el("filesystem")
            .at("type", "mount")
            .at("accessmode", "passthrough")
            .kid(el("driver").ao("type", "virtiofs"))
            .kid(el("source").ao("dir", &m.exchange_dir))
            .kid(el("target").ao("dir", "limbo-exchange"));
        if !m.exchange_writable {
            fs = fs.kid(el("readonly"));
        }
        dev = dev.kid(fs);
    }
    if !m.console_log.is_empty() {
        dev = dev.kid(el("serial").at("type", "file").kid(el("source").ao("path", &m.console_log)).kid(el("target").at("port", "0")));
    }
    dev = dev.kid(el("channel").at("type", "unix").kid(el("target").ao("type", "virtio").ao("name", "org.qemu.guest_agent.0")));
    dev = dev.kid(el("video").kid(el("model").ao("type", if win { "vga" } else { "none" })));
    dev = dev.kid(el("memballoon").ao("model", "none"));
    for p in m.devices.pci() {
        dev = dev.kid(pci_hostdev(p)?);
    }
    for u in m.devices.usb() {
        dev = dev.kid(usb_hostdev(u)?);
    }
    d = d.kid(dev);
    Ok(marshal(&d))
}

/// The guest's private network: isolated for mode none (no forward), NAT otherwise.
pub fn network_xml(m: &Manifest) -> String {
    let a = addr(m);
    let mut n = el("network").kid(el("name").text(network_name(m)));
    if m.network.mode != manifest::NET_NONE {
        n = n.kid(el("forward").ao("mode", "nat"));
    }
    n = n.kid(el("bridge").ao("name", &bridge_name(m)));
    n = n.kid(
        el("ip")
            .at("address", ip4(a.gateway))
            .at("netmask", "255.255.255.0")
            .kid(el("dhcp").kid(el("host").at("mac", &a.mac).at("name", &m.name).at("ip", ip4(a.guest)))),
    );
    marshal(&n)
}

// ---- subnets ----

/// Each guest's own 10.213.X.0/24, recorded in `<state>/subnets.json` under an exclusive lock.
pub struct Subnets {
    pub path: String,
    /// Subnets a host interface already uses; None reads the real interfaces.
    pub in_use: Option<fn() -> Vec<i64>>,
}

pub const ERR_NO_SUBNET: &str = "virt: all 254 guest subnets (10.213.1-254.0/24) are in use";

impl Subnets {
    fn lock(&self) -> std::io::Result<sys::FileLock> {
        sys::mkdir_all(sys::dir(&self.path), 0o700)?;
        sys::lock_file(&format!("{}.lock", self.path))
    }

    fn read(&self) -> BTreeMap<String, i64> {
        let mut out = BTreeMap::new();
        let Ok(b) = std::fs::read(&self.path) else { return out };
        let Ok(raw) = gojson::unmarshal(&b, BTreeMap::<String, i64>::new(), "map[string]int") else { return out };
        for (name, x) in raw {
            if (1..=254).contains(&x) && manifest::name_ok(&name) {
                out.insert(name, x);
            }
        }
        out
    }

    fn write(&self, m: &BTreeMap<String, i64>) -> std::io::Result<()> {
        let mut s = String::from("{");
        for (i, (k, v)) in m.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            gojson::write_str(&mut s, k);
            s.push(':');
            s.push_str(&v.to_string());
        }
        s.push('}');
        let b = gojson::indent(&s, "  ") + "\n";
        let tmp = format!("{}.tmp", self.path);
        sys::write_file(&tmp, b.as_bytes(), 0o644)?;
        sys::chmod(&tmp, 0o644)?;
        std::fs::rename(&tmp, &self.path)
    }

    /// The guest's X, recording the lowest free one if it has none.
    pub fn allocate(&self, name: &str) -> Result<i64, String> {
        if !manifest::name_ok(name) {
            return Err(format!("virt: bad guest name {}", crate::gotext::quote(name)));
        }
        let _l = self.lock().map_err(|e| sys::go_err(&e))?;
        let mut m = self.read();
        if let Some(&x) = m.get(name) {
            return Ok(x);
        }
        let mut taken: std::collections::HashSet<i64> = m.values().copied().collect();
        let used = match self.in_use {
            Some(f) => f(),
            None => host_subnets(),
        };
        taken.extend(used);
        for x in 1..=254 {
            if !taken.contains(&x) {
                m.insert(name.to_string(), x);
                return self.write(&m).map(|_| x).map_err(|e| sys::go_err(&e));
            }
        }
        Err(ERR_NO_SUBNET.into())
    }

    pub fn lookup(&self, name: &str) -> Option<i64> {
        self.read().get(name).copied()
    }

    pub fn release(&self, name: &str) -> Result<(), String> {
        let _l = self.lock().map_err(|e| sys::go_err(&e))?;
        let mut m = self.read();
        if m.remove(name).is_none() {
            return Ok(());
        }
        self.write(&m).map_err(|e| sys::go_err(&e))
    }
}

/// The X of every 10.213.X.0/24 a host interface has an address in.
pub fn host_subnets() -> Vec<i64> {
    let mut out = Vec::new();
    // SAFETY: getifaddrs fills a list we only read and then free with freeifaddrs
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut p = ifap;
        while !p.is_null() {
            let a = (*p).ifa_addr;
            if !a.is_null() && (*a).sa_family as i32 == libc::AF_INET {
                let sin = a as *const libc::sockaddr_in;
                let b = (*sin).sin_addr.s_addr.to_ne_bytes();
                if b[0] == 10 && b[1] == 213 {
                    out.push(b[2] as i64);
                }
            }
            p = (*p).ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}
