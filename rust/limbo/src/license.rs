//! The Windows gate and the license keys (Go: internal/license). A key leaves this module only masked, except through
//! reveal (the admin socket). The store's files are the Go daemon's, in the same format.

use crate::gojson::{self, Obj};
use crate::gotime::Time;
use crate::manifest::{self, Manifest};
use crate::{go_struct, gotext, sys};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Mutex;

pub const DEFAULT_DIR: &str = "/etc/limbo/licenses";
pub const ERR_WINDOWS_NOT_CONFIGURED: &str = "Windows guest not configured: supply windows.iso and windows.license_file in the manifest";

/// Nil for a non-Windows guest; for Windows both files must exist and be non-empty regular files.
pub fn check(m: &Manifest) -> Result<(), String> {
    if m.os != manifest::OS_WINDOWS {
        return Ok(());
    }
    if m.windows.iso.is_empty() || m.windows.license_file.is_empty() {
        return Err(ERR_WINDOWS_NOT_CONFIGURED.into());
    }
    // Go ranges over a map here, so which missing file it names first varies; the ISO is checked first here
    for (label, p) in [("windows.iso", &m.windows.iso), ("windows.license_file", &m.windows.license_file)] {
        let ok = std::fs::metadata(p).map(|md| md.is_file() && md.len() > 0).unwrap_or(false);
        if !ok {
            return Err(format!("{ERR_WINDOWS_NOT_CONFIGURED} ({label} {} is missing or empty)", gotext::quote(p)));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LErr {
    BadKey,
    BadName,
    NoLicense,
    BadGuest,
    TooMany,
    Duplicate,
    UnsafeStore,
    StoreFailed,
}

impl LErr {
    pub fn text(self) -> &'static str {
        match self {
            LErr::BadKey => "license: that is not a Windows product key (five groups of five letters or digits, separated by hyphens)",
            LErr::BadName => "license: the name must be 1-80 printable characters and must not contain a key",
            LErr::NoLicense => "license: there is no license with that id",
            LErr::BadGuest => "license: not a guest name",
            LErr::TooMany => "license: too many licenses or assignments",
            LErr::Duplicate => "license: that key is already stored",
            LErr::UnsafeStore => "license: the license folder is not root-only (0700, owned by root)",
            LErr::StoreFailed => "license: storing the key failed",
        }
    }
}

/// A store failure: a rule (with its own answer) or the disk.
#[derive(Debug)]
pub enum Error {
    L(LErr),
    Io(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::L(l) => f.write_str(l.text()),
            Error::Io(s) => f.write_str(s),
        }
    }
}

impl From<LErr> for Error {
    fn from(l: LErr) -> Self {
        Error::L(l)
    }
}

fn io(e: std::io::Error) -> Error {
    Error::Io(sys::go_err(&e))
}

#[derive(Clone, Debug, Default)]
struct Entry {
    id: String,
    name: String,
    key: String,
    added: Time,
    assigned: Option<Vec<String>>,
}
go_struct!(Entry as "license.entry" {
    id: "id" => "string", name: "name" => "string", key: "key" => "string", added: "added" => "time.Time",
    assigned: "assigned" => "[]string",
});

/// What may be shown anywhere: the last group of the key only.
#[derive(Clone, Debug, PartialEq)]
pub struct Masked {
    pub id: String,
    pub name: String,
    pub masked: String,
    pub added: Time,
    pub assigned: Vec<String>,
}

impl Masked {
    pub fn json(&self) -> String {
        Obj::new()
            .str("id", &self.id)
            .str("name", &self.name)
            .str("masked", &self.masked)
            .str("added", &self.added.rfc3339_nano())
            .strs("assigned", &self.assigned)
            .end()
    }
}

impl Entry {
    fn assigned(&self) -> &[String] {
        self.assigned.as_deref().unwrap_or(&[])
    }
    fn masked(&self) -> Masked {
        Masked {
            id: self.id.clone(),
            name: self.name.clone(),
            masked: mask_key(&self.key),
            added: self.added,
            assigned: self.assigned().to_vec(),
        }
    }
    fn json(&self) -> String {
        Obj::new()
            .str("id", &self.id)
            .str("name", &self.name)
            .str("key", &self.key)
            .str("added", &self.added.rfc3339_nano())
            .strs_nil("assigned", self.assigned.as_deref())
            .end()
    }
}

pub struct Store {
    pub dir: String,
    mu: Mutex<()>,
}

/// `^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$`
fn key_ok(k: &str) -> bool {
    let b = k.as_bytes();
    b.len() == 29 && b.iter().enumerate().all(|(i, c)| if i % 6 == 5 { *c == b'-' } else { c.is_ascii_uppercase() || c.is_ascii_digit() })
}

/// `(?i)[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}` anywhere in the text.
fn key_like(s: &str) -> bool {
    // (?i) folds the long s and the Kelvin sign onto s and k, so Go's class takes them too
    let b: Vec<char> = s.chars().collect();
    let al = |c: char| c.is_ascii_alphanumeric() || c == '\u{17F}' || c == '\u{212A}';
    (0..b.len().saturating_sub(16)).any(|i| (0..17).all(|j| if j % 6 == 5 { b[i + j] == '-' } else { al(b[i + j]) }))
}

/// `^lic-[0-9a-f]{8}$`
pub fn id_ok(id: &str) -> bool {
    id.len() == 12 && id.starts_with("lic-") && id[4..].bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub fn normalize_key(k: &str) -> Result<String, LErr> {
    let k = gotext::trim_space(k).to_uppercase();
    if !key_ok(&k) {
        return Err(LErr::BadKey);
    }
    Ok(k)
}

pub fn mask_key(k: &str) -> String {
    if k.len() < 5 {
        return "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX".into();
    }
    format!("XXXXX-XXXXX-XXXXX-XXXXX-{}", gotext::lossy(&k.as_bytes()[k.len() - 5..]))
}

fn clean_name(n: &str) -> Result<String, LErr> {
    let n = gotext::trim_space(n);
    if n.is_empty() || n.len() > 80 || key_like(n) || !n.chars().all(gotext::is_print) {
        return Err(LErr::BadName);
    }
    Ok(n.to_string())
}

impl Store {
    /// Prepares the folder (0700) and refuses one others could read or write, or one not root's.
    pub fn open(dir: &str, require_root: bool) -> Result<Store, String> {
        sys::mkdir_all(dir, 0o700).map_err(|e| sys::go_path_error("mkdir", dir, &e))?;
        let m = std::fs::symlink_metadata(dir).map_err(|e| sys::go_path_error("lstat", dir, &e))?;
        let st = sys::Stat::of(&m);
        if !st.is_dir() || st.perm() & 0o077 != 0 || (require_root && st.uid != 0) {
            return Err(LErr::UnsafeStore.text().into());
        }
        Ok(Store { dir: dir.to_string(), mu: Mutex::new(()) })
    }

    fn read(&self, id: &str) -> Result<Entry, LErr> {
        if !id_ok(id) {
            return Err(LErr::NoLicense);
        }
        let path = sys::join(&[&self.dir, &format!("{id}.json")]);
        let b = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .and_then(|mut f| {
                let mut b = Vec::new();
                std::io::Read::read_to_end(&mut f, &mut b).map(|_| b)
            })
            .map_err(|_| LErr::NoLicense)?;
        let (mut e, r) = gojson::decode(&b, Entry::default(), "license.entry", false);
        if r.is_err() || e.id != id {
            return Err(LErr::NoLicense);
        }
        if e.assigned.is_none() {
            e.assigned = Some(Vec::new());
        }
        Ok(e)
    }

    fn load(&self) -> Result<Vec<Entry>, Error> {
        let mut out = Vec::new();
        for (name, _) in sys::read_dir_sorted(&self.dir).map_err(io)? {
            let Some(id) = name.strip_suffix(".json") else { continue };
            if !id_ok(id) {
                continue;
            }
            if let Ok(e) = self.read(id) {
                out.push(e);
            }
        }
        out.sort_by(|a, b| a.added.cmp(&b.added).then_with(|| a.id.cmp(&b.id)));
        Ok(out)
    }

    fn write(&self, e: &Entry) -> Result<(), Error> {
        use std::io::Write;
        let (mut f, tmp) = sys::create_temp(&self.dir, ".lic-*").map_err(io)?;
        let r = (|| {
            sys::chmod(&tmp, 0o600)?;
            f.write_all(e.json().as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, sys::join(&[&self.dir, &format!("{}.json", e.id)]))
        })();
        let _ = std::fs::remove_file(&tmp);
        r.map_err(io)
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.mu.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn add(&self, name: &str, key: &str) -> Result<Masked, Error> {
        let k = normalize_key(key)?;
        let n = clean_name(name)?;
        let _g = self.guard();
        let all = self.load()?;
        if all.len() >= 64 {
            return Err(LErr::TooMany.into());
        }
        if all.iter().any(|e| e.key == k) {
            return Err(LErr::Duplicate.into());
        }
        let now = Time::now().utc().truncate(1_000_000_000);
        let e = Entry { id: format!("lic-{}", sys::rand_hex(4)), name: n, key: k, added: now, assigned: Some(Vec::new()) };
        self.write(&e).map_err(|_| Error::L(LErr::StoreFailed))?;
        Ok(e.masked())
    }

    pub fn list(&self) -> Result<Vec<Masked>, Error> {
        let _g = self.guard();
        Ok(self.load()?.iter().map(Entry::masked).collect())
    }

    pub fn remove(&self, id: &str) -> Result<(), Error> {
        let _g = self.guard();
        self.read(id)?;
        std::fs::remove_file(sys::join(&[&self.dir, &format!("{id}.json")])).map_err(io)
    }

    pub fn reveal(&self, id: &str) -> Result<String, Error> {
        let _g = self.guard();
        Ok(self.read(id)?.key)
    }

    pub fn assign(&self, id: &str, guest: &str) -> Result<Masked, Error> {
        if !manifest::name_ok(guest) {
            return Err(LErr::BadGuest.into());
        }
        let _g = self.guard();
        let mut all = self.load()?;
        let Some(ti) = all.iter().position(|e| e.id == id) else { return Err(LErr::NoLicense.into()) };
        for (i, e) in all.iter_mut().enumerate() {
            if i != ti && e.assigned().iter().any(|g| g == guest) {
                e.assigned = Some(e.assigned().iter().filter(|g| *g != guest).cloned().collect());
                self.write(e)?;
            }
        }
        let t = &mut all[ti];
        if !t.assigned().iter().any(|g| g == guest) {
            if t.assigned().len() >= 32 {
                return Err(LErr::TooMany.into());
            }
            let mut a = t.assigned().to_vec();
            a.push(guest.to_string());
            a.sort();
            t.assigned = Some(a);
            self.write(t)?;
        }
        Ok(t.masked())
    }

    pub fn unassign(&self, id: &str, guest: &str) -> Result<Masked, Error> {
        if !manifest::name_ok(guest) {
            return Err(LErr::BadGuest.into());
        }
        let _g = self.guard();
        let mut e = self.read(id)?;
        if e.assigned().iter().any(|g| g == guest) {
            e.assigned = Some(e.assigned().iter().filter(|g| *g != guest).cloned().collect());
            self.write(&e)?;
        }
        Ok(e.masked())
    }

    /// The id of the license a guest uses, or "".
    pub fn assigned_to(&self, guest: &str) -> String {
        let _g = self.guard();
        match self.load() {
            Ok(all) => all.iter().find(|e| e.assigned().iter().any(|g| g == guest)).map(|e| e.id.clone()).unwrap_or_default(),
            Err(_) => String::new(),
        }
    }
}
