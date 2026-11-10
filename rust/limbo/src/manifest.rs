//! The per-guest description Limbo works from (Go: internal/manifest). Every default is the restrictive one, unknown
//! fields are refused, and the names spliced into libvirt and nftables identifiers are checked by their own rules.

use crate::go_struct;
use crate::gojson::{self, Obj};
use crate::gotext::quote;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const OS_LINUX: &str = "linux";
pub const OS_WINDOWS: &str = "windows";
pub const NET_NONE: &str = "none";
pub const NET_ALLOWLIST: &str = "allowlist";
pub const NET_INTERNET_ONLY: &str = "internet-only";
pub const CLIP_OFF: &str = "off";
pub const CLIP_TEXT: &str = "text";
pub const MAX_DISK_GB: i64 = 4096;
const MAX_PCI: usize = 4;
const MAX_USB: usize = 4;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Image {
    pub path: String,
    pub sha256: String,
}
go_struct!(Image as "manifest.Image" { path: "path" => "string", sha256: "sha256" => "string" });

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Allow {
    pub addr: String,
    pub port: i64,
    pub proto: String,
}
go_struct!(Allow as "manifest.Allow" { addr: "addr" => "string", port: "port" => "int", proto: "proto" => "string" });

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Network {
    pub mode: String,
    /// None is Go's nil slice (written as null).
    pub allow: Option<Vec<Allow>>,
}
go_struct!(Network as "manifest.Network" { mode: "mode" => "string", allow: "allow" => "[]manifest.Allow" });

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Access {
    pub user: String,
    pub sudo: bool,
}
go_struct!(Access as "manifest.Access" { user: "user" => "string", sudo: "sudo" => "bool" });

#[derive(Clone, Debug, Default, PartialEq)]
pub struct App {
    pub name: String,
    pub exec: String,
}
go_struct!(App as "manifest.App" { name: "name" => "string", exec: "exec" => "string" });

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Provision {
    pub ssh_public_key: String,
    pub packages: Option<Vec<String>>,
    pub seed_iso: String,
    pub host_key: String,
}
go_struct!(Provision as "manifest.Provision" {
    ssh_public_key: "ssh_public_key" => "string", packages: "packages" => "[]string", seed_iso: "seed_iso" => "string",
    host_key: "host_key" => "string",
});

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Windows {
    pub iso: String,
    pub license_file: String,
}
go_struct!(Windows as "manifest.Windows" { iso: "iso" => "string", license_file: "license_file" => "string" });

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Devices {
    pub pci: Option<Vec<String>>,
    pub usb: Option<Vec<String>>,
}
go_struct!(Devices as "manifest.Devices" { pci: "pci" => "[]string", usb: "usb" => "[]string" });

impl Devices {
    pub fn pci(&self) -> &[String] {
        self.pci.as_deref().unwrap_or(&[])
    }
    pub fn usb(&self) -> &[String] {
        self.usb.as_deref().unwrap_or(&[])
    }
    pub fn any(&self) -> bool {
        !self.pci().is_empty() || !self.usb().is_empty()
    }
    /// Every requested device, PCI addresses first.
    pub fn all(&self) -> Vec<String> {
        self.pci().iter().chain(self.usb()).cloned().collect()
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Manifest {
    pub name: String,
    pub os: String,
    pub image: Image,
    pub cpus: i64,
    pub memory_mb: i64,
    pub disk_gb: i64,
    pub network: Network,
    pub exchange_dir: String,
    pub exchange_writable: bool,
    pub clipboard: String,
    pub disposable: bool,
    pub console_log: String,
    pub subnet: i64,
    pub access: Access,
    pub app: App,
    pub provision: Provision,
    pub windows: Windows,
    pub devices: Devices,
}
go_struct!(Manifest as "manifest.Manifest" {
    name: "name" => "string", os: "os" => "string", image: "image" => "manifest.Image", cpus: "cpus" => "int",
    memory_mb: "memory_mb" => "int", disk_gb: "disk_gb" => "int", network: "network" => "manifest.Network",
    exchange_dir: "exchange_dir" => "string", exchange_writable: "exchange_writable" => "bool", clipboard: "clipboard" => "string",
    disposable: "disposable" => "bool", console_log: "console_log" => "string", subnet: "subnet" => "int",
    access: "access" => "manifest.Access", app: "app" => "manifest.App", provision: "provision" => "manifest.Provision",
    windows: "windows" => "manifest.Windows", devices: "devices" => "manifest.Devices",
});

fn opt_strs(v: &Option<Vec<String>>) -> String {
    match v {
        Some(v) => gojson::strs(v),
        None => "null".into(),
    }
}

impl Network {
    pub fn json(&self) -> String {
        let allow = match &self.allow {
            None => "null".to_string(),
            Some(a) => gojson::list(
                &a.iter().map(|x| Obj::new().str("addr", &x.addr).int("port", x.port).str("proto", &x.proto).end()).collect::<Vec<_>>(),
            ),
        };
        Obj::new().str("mode", &self.mode).raw("allow", &allow).end()
    }
}

impl Manifest {
    /// Go's json.Marshal of the manifest (the copy Up saves, and what Parse reads back).
    pub fn json(&self) -> String {
        Obj::new()
            .str("name", &self.name)
            .str("os", &self.os)
            .raw("image", &Obj::new().str("path", &self.image.path).str("sha256", &self.image.sha256).end())
            .int("cpus", self.cpus)
            .int("memory_mb", self.memory_mb)
            .int_omit("disk_gb", self.disk_gb)
            .raw("network", &self.network.json())
            .str("exchange_dir", &self.exchange_dir)
            .bool("exchange_writable", self.exchange_writable)
            .str("clipboard", &self.clipboard)
            .bool("disposable", self.disposable)
            .str("console_log", &self.console_log)
            .int_omit("subnet", self.subnet)
            .raw("access", &Obj::new().str("user", &self.access.user).bool("sudo", self.access.sudo).end())
            .raw("app", &Obj::new().str("name", &self.app.name).str("exec", &self.app.exec).end())
            .raw(
                "provision",
                &Obj::new()
                    .str("ssh_public_key", &self.provision.ssh_public_key)
                    .raw("packages", &opt_strs(&self.provision.packages))
                    .str("seed_iso", &self.provision.seed_iso)
                    .str("host_key", &self.provision.host_key)
                    .end(),
            )
            .raw("windows", &Obj::new().str("iso", &self.windows.iso).str("license_file", &self.windows.license_file).end())
            .raw("devices", &Obj::new().raw("pci", &opt_strs(&self.devices.pci)).raw("usb", &opt_strs(&self.devices.usb)).end())
            .end()
    }

    fn apply_defaults(&mut self) {
        if self.cpus == 0 {
            self.cpus = 2;
        }
        if self.memory_mb == 0 {
            self.memory_mb = 4096;
        }
        if self.network.mode.is_empty() {
            self.network.mode = NET_NONE.into();
        }
        if self.clipboard.is_empty() {
            self.clipboard = CLIP_OFF.into();
        }
        if let Some(a) = &mut self.network.allow {
            for x in a {
                if x.proto.is_empty() {
                    x.proto = "tcp".into();
                }
            }
        }
    }

    /// Only the name.
    pub fn validate_name(&self) -> Result<(), String> {
        if name_ok(&self.name) {
            Ok(())
        } else {
            Err(format!("manifest: name {} must match ^[a-z][a-z0-9-]{{0,11}}$", quote(&self.name)))
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validate_name()?;
        if self.os != OS_LINUX && self.os != OS_WINDOWS {
            return Err(format!("manifest: os must be \"linux\" or \"windows\", got {}", quote(&self.os)));
        }
        if !self.image.path.starts_with('/') {
            return Err("manifest: image.path must be absolute".into());
        }
        if self.image.sha256.len() != 64 || !self.image.sha256.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            return Err("manifest: image.sha256 must be 64 lowercase hex characters".into());
        }
        if self.cpus < 1 || self.cpus > 64 {
            return Err("manifest: cpus out of range".into());
        }
        if self.memory_mb < 512 {
            return Err("manifest: memory_mb must be at least 512".into());
        }
        if self.subnet < 0 || self.subnet > 254 {
            return Err("manifest: subnet out of range".into());
        }
        if self.disk_gb < 0 || self.disk_gb > MAX_DISK_GB {
            return Err(format!("manifest: disk_gb must be 0 (the image's size) to {MAX_DISK_GB}"));
        }
        if self.clipboard != CLIP_OFF && self.clipboard != CLIP_TEXT {
            return Err("manifest: clipboard must be \"off\" or \"text\"".into());
        }
        let clean_abs = |p: &str| p.starts_with('/') && path_clean(p) == p;
        if !self.exchange_dir.is_empty() && !clean_abs(&self.exchange_dir) {
            return Err("manifest: exchange_dir must be an absolute, clean path".into());
        }
        if !self.console_log.is_empty() && !clean_abs(&self.console_log) {
            return Err("manifest: console_log must be an absolute, clean path".into());
        }
        if !self.provision.seed_iso.is_empty() && !clean_abs(&self.provision.seed_iso) {
            return Err("manifest: provision.seed_iso must be an absolute, clean path".into());
        }
        if !self.provision.host_key.is_empty() && !host_key_ok(&self.provision.host_key) {
            return Err("manifest: provision.host_key must be one line \"ssh-ed25519 AAAA...\" (as limbo seed prints it)".into());
        }
        if !user_ok(&self.access.user) {
            return Err("manifest: access.user missing or invalid".into());
        }
        if self.app.exec.is_empty() || self.app.name.contains([',', '\n', '\r']) || self.app.name.is_empty() {
            return Err("manifest: app.name and app.exec are required (app.name may not contain commas)".into());
        }
        if self.os == OS_WINDOWS && self.app.exec.contains(',') {
            return Err("manifest: app.exec may not contain commas for Windows guests".into());
        }
        self.validate_devices()?;
        self.network.validate()
    }

    fn validate_devices(&self) -> Result<(), String> {
        let d = &self.devices;
        if !d.any() {
            return Ok(());
        }
        if !d.pci().is_empty() && (!self.disposable || self.os != OS_LINUX) {
            return Err("manifest: devices.pci requires a disposable Linux guest".into());
        }
        if !self.disposable {
            return Err("manifest: devices.usb requires a disposable guest".into());
        }
        if d.usb().len() > MAX_USB {
            return Err(format!("manifest: devices.usb lists more than {MAX_USB} devices"));
        }
        let mut seen = std::collections::HashSet::new();
        for id in d.usb() {
            if !usb_id_ok(id) {
                return Err(format!("manifest: devices.usb {} is not a USB ID like 5059:4040 (vendor:product, lowercase hex)", quote(id)));
            }
            if !seen.insert(id) {
                return Err(format!("manifest: devices.usb lists {} twice", quote(id)));
            }
        }
        if d.pci().len() > MAX_PCI {
            return Err(format!("manifest: devices.pci lists more than {MAX_PCI} devices"));
        }
        let mut seen = std::collections::HashSet::new();
        for a in d.pci() {
            if !pci_ok(a) {
                return Err(format!("manifest: devices.pci {} is not a PCI address like 0000:03:00.0 (lowercase)", quote(a)));
            }
            if !seen.insert(a) {
                return Err(format!("manifest: devices.pci lists {} twice", quote(a)));
            }
        }
        Ok(())
    }
}

impl Network {
    pub fn allow(&self) -> &[Allow] {
        self.allow.as_deref().unwrap_or(&[])
    }

    pub fn validate(&self) -> Result<(), String> {
        match self.mode.as_str() {
            NET_NONE | NET_INTERNET_ONLY => {
                if !self.allow().is_empty() {
                    return Err("manifest: network.allow only applies to mode \"allowlist\"".into());
                }
            }
            NET_ALLOWLIST => {
                if self.allow().is_empty() {
                    return Err("manifest: mode \"allowlist\" needs at least one network.allow entry".into());
                }
            }
            _ => return Err("manifest: network.mode must be none, allowlist or internet-only".into()),
        }
        for a in self.allow() {
            a.prefix()?;
            if a.port < 1 || a.port > 65535 {
                return Err(format!("manifest: allow {}: port out of range", quote(&a.addr)));
            }
            if a.proto != "tcp" && a.proto != "udp" {
                return Err(format!("manifest: allow {}: proto must be tcp or udp", quote(&a.addr)));
            }
        }
        Ok(())
    }
}

impl Allow {
    /// The address as a masked prefix (a bare IP is a /32 or /128), as Go's netip parses it.
    pub fn prefix(&self) -> Result<Prefix, String> {
        if let Some(p) = parse_prefix(&self.addr) {
            return Ok(p.masked());
        }
        match parse_addr(&self.addr) {
            Some(a) => {
                let bits = a.bit_len();
                Ok(Prefix { addr: a.without_zone(), bits })
            }
            None => Err(format!("manifest: allow addr {} is not an IP or CIDR", quote(&self.addr))),
        }
    }
}

/// Reads, defaults and validates a manifest file.
pub fn load(path: &str) -> Result<Manifest, String> {
    let b = std::fs::read(path).map_err(|e| crate::sys::go_path_error("open", path, &e))?;
    parse(&b)
}

/// Decodes (unknown fields refused), defaults and validates.
pub fn parse(b: &[u8]) -> Result<Manifest, String> {
    let (mut m, r) = gojson::decode(b, Manifest::default(), "manifest.Manifest", true);
    r.map_err(|e| format!("manifest: {e}"))?;
    m.apply_defaults();
    m.validate()?;
    Ok(m)
}

/// `^[a-z][a-z0-9-]{0,11}$`
pub fn name_ok(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= 12
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// `^[a-z_][a-z0-9_-]{0,31}$`
pub fn user_ok(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// `^[0-9a-f]{4}:[0-9a-f]{4}$`
pub fn usb_id_ok(s: &str) -> bool {
    let b = s.as_bytes();
    let hex = |c: &u8| c.is_ascii_digit() || (b'a'..=b'f').contains(c);
    b.len() == 9 && b[4] == b':' && b[..4].iter().all(hex) && b[5..].iter().all(hex)
}

/// `^[0-9a-f]{4}:[0-9a-f]{2}:[0-1][0-9a-f]\.[0-7]$`
pub fn pci_ok(s: &str) -> bool {
    let b = s.as_bytes();
    let hex = |c: &u8| c.is_ascii_digit() || (b'a'..=b'f').contains(c);
    b.len() == 12
        && b[..4].iter().all(hex)
        && b[4] == b':'
        && b[5..7].iter().all(hex)
        && b[7] == b':'
        && (b[8] == b'0' || b[8] == b'1')
        && hex(&b[9])
        && b[10] == b'.'
        && (b'0'..=b'7').contains(&b[11])
}

/// `^ssh-ed25519 [A-Za-z0-9+/=]{60,80}( [^\r\n]*)?$`
pub fn host_key_ok(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("ssh-ed25519 ") else { return false };
    let key_len = rest.bytes().take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=')).count();
    // the class is greedy but may give back: any split with 60..=80 key characters followed by end or a space works
    (60..=80.min(key_len)).any(|n| {
        let tail = &rest[n..];
        tail.is_empty() || (tail.starts_with(' ') && !tail.contains(['\r', '\n']))
    })
}

/// Go's path.Clean (the same as filepath.Clean on Linux).
pub fn path_clean(p: &str) -> String {
    crate::sys::clean(p)
}

// ---- Go's netip, as far as the manifest needs it ----

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Addr {
    V4([u8; 4]),
    V6([u8; 16], String),
}

impl Addr {
    pub fn bit_len(&self) -> u8 {
        match self {
            Addr::V4(_) => 32,
            Addr::V6(..) => 128,
        }
    }
    pub fn is6(&self) -> bool {
        matches!(self, Addr::V6(..))
    }
    fn without_zone(&self) -> Addr {
        match self {
            Addr::V6(b, _) => Addr::V6(*b, String::new()),
            a => a.clone(),
        }
    }
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Addr::V4(b) => write!(f, "{}", Ipv4Addr::from(*b)),
            Addr::V6(b, zone) => {
                let a = Ipv6Addr::from(*b);
                if let Some(v4) = a.to_ipv4_mapped() {
                    write!(f, "::ffff:{v4}")?;
                } else {
                    write!(f, "{}", go_v6(b))?;
                }
                if !zone.is_empty() {
                    write!(f, "%{zone}")?;
                }
                Ok(())
            }
        }
    }
}

/// Go netip's IPv6 text: RFC 5952, the longest run of two or more zero groups shortened (the first of equal runs).
fn go_v6(b: &[u8; 16]) -> String {
    let g: Vec<u16> = (0..8).map(|i| u16::from_be_bytes([b[2 * i], b[2 * i + 1]])).collect();
    let (mut best, mut best_len, mut i) = (usize::MAX, 0usize, 0usize);
    while i < 8 {
        if g[i] == 0 {
            let s = i;
            while i < 8 && g[i] == 0 {
                i += 1;
            }
            if i - s >= 2 && i - s > best_len {
                best = s;
                best_len = i - s;
            }
        } else {
            i += 1;
        }
    }
    let mut out = String::new();
    let mut i = 0;
    while i < 8 {
        if i == best {
            out.push_str("::");
            i += best_len;
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        out.push_str(&format!("{:x}", g[i]));
        i += 1;
    }
    out
}

/// netip.ParseAddr.
pub fn parse_addr(s: &str) -> Option<Addr> {
    if s.contains(':') {
        let (ip, zone) = match s.split_once('%') {
            Some((ip, z)) => {
                if z.is_empty() {
                    return None;
                }
                (ip, z.to_string())
            }
            None => (s, String::new()),
        };
        let a: Ipv6Addr = ip.parse().ok()?;
        Some(Addr::V6(a.octets(), zone))
    } else {
        // Rust refuses leading zeros and out-of-range fields, as netip does
        let a: Ipv4Addr = s.parse().ok()?;
        Some(Addr::V4(a.octets()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub addr: Addr,
    pub bits: u8,
}

impl Prefix {
    pub fn masked(&self) -> Prefix {
        let mask = |bytes: &mut [u8]| {
            for (i, x) in bytes.iter_mut().enumerate() {
                let keep = (self.bits as usize).saturating_sub(i * 8).min(8);
                *x &= if keep == 0 { 0 } else { 0xffu8 << (8 - keep) };
            }
        };
        let addr = match &self.addr {
            Addr::V4(b) => {
                let mut b = *b;
                mask(&mut b);
                Addr::V4(b)
            }
            Addr::V6(b, _) => {
                let mut b = *b;
                mask(&mut b);
                Addr::V6(b, String::new())
            }
        };
        Prefix { addr, bits: self.bits }
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.bits)
    }
}

/// netip.ParsePrefix.
pub fn parse_prefix(s: &str) -> Option<Prefix> {
    let (a, bits) = s.rsplit_once('/')?;
    if a.contains('%') {
        return None;
    }
    let addr = parse_addr(a)?;
    if bits.is_empty() || !bits.bytes().all(|c| c.is_ascii_digit()) || (bits.len() > 1 && bits.starts_with('0')) {
        return None;
    }
    let n: u32 = bits.parse().ok()?;
    if n > addr.bit_len() as u32 {
        return None;
    }
    Some(Prefix { addr, bits: n as u8 })
}
