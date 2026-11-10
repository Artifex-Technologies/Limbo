//! The way out of a guest's shared folder (Go: internal/exchange). A file leaves a root-only outbox only as a private
//! copy that ClamAV scanned clean; a known file is held, a scan that cannot run hands nothing out. The outbox is never
//! left: every path is opened beneath it (openat2 RESOLVE_BENEATH, the last part never through a link), as Go's os.Root.

use crate::events::Emitter;
use crate::gojson::{self, Obj};
use crate::gotime::Time;
use crate::{gotext, sys, Detail, Refusal};
use rustix::fs::{Mode, OFlags, ResolveFlags};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, Write};
use std::os::fd::OwnedFd;

pub const MAX_FILE_BYTES: i64 = 2 << 30;
const MAX_LISTED: usize = 1000;
const MAX_PATH_BYTES: usize = 512;
const MAX_WALK: usize = 20000;

pub const EVENT_FILE: &str = "exchange.file";
pub const EVENT_HELD: &str = "exchange.held";
pub const EVENT_FAIL: &str = "exchange.fail";
pub const CLEAN: &str = "clean";
pub const INFECTED: &str = "infected";

/// Scans one file: Ok((CLEAN|INFECTED, signature)), Err when it could not be scanned.
pub trait Scanner: Send + Sync {
    fn scan(&self, path: &str) -> Result<(String, String), String>;
}

pub struct Service {
    pub root: String,
    pub scratch: String,
    pub held: String,
    pub scanner: Option<Box<dyn Scanner>>,
    pub events: Option<std::sync::Arc<dyn Emitter>>,
}

pub struct File {
    pub path: String,
    pub size: i64,
    pub modified: Time,
}

pub struct Listing {
    pub guest: String,
    pub files: Vec<File>,
    pub unlisted: i64,
}

impl Listing {
    pub fn json(&self) -> String {
        let files: Vec<String> = self
            .files
            .iter()
            .map(|f| Obj::new().str("path", &f.path).int("size", f.size).str("modified", &f.modified.rfc3339_nano()).end())
            .collect();
        Obj::new().str("guest", &self.guest).raw("files", &gojson::list(&files)).int("unlisted", self.unlisted).end()
    }
}

/// A file that passed the scan: a private copy, removed on drop.
pub struct Taken {
    pub file: std::fs::File,
    pub path: String,
    pub sha256: String,
    pub size: i64,
    tmp: String,
}

impl Drop for Taken {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.tmp);
    }
}

fn refuse(status: u16, code: &str, remedy: &str, msg: String) -> Refusal {
    Refusal::new(Some(status), code, remedy, msg)
}

/// Makes the outbox (and the root above it) root-only. The engine calls it before a guest with a writable share starts.
pub fn prepare(root: &str, guest: &str) -> Result<(), String> {
    if !crate::manifest::name_ok(guest) {
        return Err("exchange: bad guest name".into());
    }
    for d in [root.to_string(), sys::join(&[root, guest])] {
        sys::mkdir_all(&d, 0o700).map_err(|e| sys::go_path_error("mkdir", &d, &e))?;
        let m = std::fs::symlink_metadata(&d).map_err(|e| sys::go_path_error("lstat", &d, &e))?;
        if !m.is_dir() {
            return Err(format!("exchange: {d} is not a folder"));
        }
        sys::chmod(&d, 0o700).map_err(|e| sys::go_path_error("chmod", &d, &e))?;
    }
    Ok(())
}

/// Shown to people: valid UTF-8, no control or invisible formatting characters, bounded.
fn safe_name(p: &str) -> bool {
    !p.is_empty() && p.len() <= MAX_PATH_BYTES && !p.contains('\u{FFFD}') && !p.chars().any(|c| gotext::is_control(c) || gotext::is_cf(c))
}

fn clean_rel(p: &str) -> Option<String> {
    if !safe_name(p) || p.starts_with('/') || p.contains('\\') {
        return None;
    }
    let c = sys::clean(p);
    if c != p || c == "." || c == ".." || c.starts_with("../") {
        return None;
    }
    Some(c)
}

/// Go's exchange clip: control and format characters as '?', at most n bytes.
pub fn clip(s: &str, n: usize) -> String {
    let mut out = String::new();
    for mut c in s.chars() {
        if gotext::is_control(c) || gotext::is_cf(c) {
            c = '?';
        }
        if out.len() + c.len_utf8() > n {
            break;
        }
        out.push(c);
    }
    out
}

fn beneath(dir: &OwnedFd, rel: &str, flags: OFlags) -> rustix::io::Result<OwnedFd> {
    rustix::fs::openat2(
        dir,
        rel,
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS,
    )
}

impl Service {
    pub fn outbox(&self, guest: &str) -> String {
        sys::join(&[&self.root, guest])
    }

    fn open(&self, guest: &str) -> Result<OwnedFd, Refusal> {
        if !crate::manifest::name_ok(guest) {
            return Err(refuse(404, "not_found", "give a guest's name", format!("there is no guest named {}", gotext::quote(guest))));
        }
        let dir = self.outbox(guest);
        let no_outbox = || refuse(404, "not_found", "turn on the guest's shared folder first", format!("guest {} has no outbox", gotext::quote(guest)));
        match std::fs::symlink_metadata(&dir) {
            Ok(m) if m.is_dir() => {}
            _ => return Err(no_outbox()),
        }
        rustix::fs::open(&dir, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
            .map_err(|e| Refusal::new(Some(500), "internal", "", sys::go_path_error("openat", &dir, &e.into())))
    }

    /// What a guest left in its outbox.
    pub fn list(&self, guest: &str) -> Result<Listing, Refusal> {
        let root = self.open(guest)?;
        let mut out = Listing { guest: guest.to_string(), files: Vec::new(), unlisted: 0 };
        let mut n = 0usize;
        // depth first, each folder's entries in name order (fs.WalkDir)
        fn walk(dfd: &OwnedFd, prefix: &str, out: &mut Listing, n: &mut usize) -> bool {
            let names = match read_names(dfd) {
                Ok(v) => v,
                Err(_) => {
                    out.unlisted += 1;
                    return true;
                }
            };
            for name in names {
                let p = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
                *n += 1;
                if *n > MAX_WALK {
                    return false;
                }
                let st = match rustix::fs::statat(dfd, name.as_str(), rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(st) => st,
                    Err(_) => {
                        out.unlisted += 1;
                        continue;
                    }
                };
                let ft = rustix::fs::FileType::from_raw_mode(st.st_mode);
                if ft == rustix::fs::FileType::Directory {
                    if !safe_name(&p) {
                        out.unlisted += 1;
                        continue;
                    }
                    match beneath(dfd, &name, OFlags::RDONLY | OFlags::DIRECTORY) {
                        Ok(sub) => {
                            if !walk(&sub, &p, out, n) {
                                return false;
                            }
                        }
                        Err(_) => {
                            *n += 1;
                            out.unlisted += 1;
                        }
                    }
                    continue;
                }
                if ft != rustix::fs::FileType::RegularFile || !safe_name(&p) || out.files.len() >= MAX_LISTED {
                    out.unlisted += 1;
                    continue;
                }
                out.files.push(File {
                    path: p,
                    size: st.st_size,
                    modified: Time::from_unix(st.st_mtime, st.st_mtime_nsec as u32),
                });
            }
            true
        }
        walk(&root, "", &mut out, &mut n);
        out.files.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    fn emit(&self, kind: &str, guest: &str, d: Detail) -> std::io::Result<()> {
        match &self.events {
            Some(e) => e.emit(kind, guest, d),
            None => Ok(()),
        }
    }

    /// Copies one file out of the outbox, scans the copy, and returns it if ClamAV finds nothing.
    pub fn take(&self, guest: &str, rel: &str, mut detail: Detail) -> Result<Taken, Refusal> {
        let Some(p) = clean_rel(rel) else {
            return Err(refuse(400, "bad_request", "use a path exactly as the listing shows it", "that is not a file name in the outbox".into()));
        };
        let root = self.open(guest)?;
        let src = beneath(&root, &p, OFlags::RDONLY | OFlags::NONBLOCK).map_err(|_| {
            refuse(404, "not_found", "list the outbox again", format!("there is no such file in {guest}'s outbox"))
        })?;
        let mut src = std::fs::File::from(src);
        let md = src.metadata();
        if !md.as_ref().is_ok_and(|m| m.is_file()) {
            return Err(refuse(400, "not_a_file", "only plain files can be taken out", "that is not a plain file".into()));
        }
        if md.map(|m| m.len() as i64).unwrap_or(0) > MAX_FILE_BYTES {
            return Err(refuse(413, "too_large", "split it inside the guest", format!("the file is larger than {MAX_FILE_BYTES} bytes")));
        }
        let internal = |e: std::io::Error| Refusal::new(Some(500), "internal", "", sys::go_err(&e));
        for d in [&self.scratch, &self.held] {
            sys::mkdir_all(d, 0o700).map_err(internal)?;
        }
        let (mut tmp, tmp_path) = sys::create_temp(&self.scratch, "take-*").map_err(internal)?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 64 << 10];
        let mut n: i64 = 0;
        let copied: std::io::Result<()> = (|| {
            let mut lim = (&mut src).take(MAX_FILE_BYTES as u64 + 1);
            loop {
                let k = lim.read(&mut buf)?;
                if k == 0 {
                    break;
                }
                tmp.write_all(&buf[..k])?;
                h.update(&buf[..k]);
                n += k as i64;
            }
            if n > MAX_FILE_BYTES {
                return Err(std::io::Error::other("the file grew past the limit while it was copied"));
            }
            Ok(())
        })();
        if let Err(e) = copied {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(refuse(500, "copy_failed", "try again", format!("copying the file failed: {}", sys::go_err(&e))));
        }
        let sum = sys::hex(&h.finalize());
        detail.insert("path".into(), clip(&p, 200));
        detail.insert("sha256".into(), sum.clone());
        detail.insert("size".into(), n.to_string());
        let scanned = match &self.scanner {
            None => Err("no scanner configured".to_string()),
            Some(s) => s.scan(&tmp_path),
        };
        let (result, sig) = match scanned {
            Ok(x) => x,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                detail.insert("reason".into(), clip(&e, 200));
                let _ = self.emit(EVENT_FAIL, guest, detail);
                return Err(refuse(
                    503,
                    "scanner_unavailable",
                    "make sure ClamAV works ('clamscan --version'; its database is updated by freshclam), then try again",
                    "the file could not be scanned, so it stays in the outbox".into(),
                ));
            }
        };
        if result != CLEAN {
            let held = sys::join(&[&self.held, &sum]);
            drop(tmp);
            let _ = std::fs::rename(&tmp_path, &held);
            let _ = sys::chmod(&held, 0o400);
            let _ = rustix::fs::unlinkat(&root, p.as_str(), rustix::fs::AtFlags::empty());
            detail.insert("signature".into(), clip(&sig, 200));
            let _ = self.emit(EVENT_HELD, guest, detail);
            return Err(refuse(
                409,
                "infected",
                "nothing to do: it is held, and Heimdall can take it into its quarantine",
                format!("ClamAV knows this file ({}); it was held and not handed out", clip(&sig, 120)),
            ));
        }
        detail.insert("scan".into(), CLEAN.into());
        if let Err(e) = self.emit(EVENT_FILE, guest, detail) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(Refusal::new(Some(500), "internal", "", format!("cannot record the file in the audit log: {}", sys::go_err(&e))));
        }
        if let Err(e) = tmp.seek(std::io::SeekFrom::Start(0)) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(internal(e));
        }
        Ok(Taken { file: tmp, path: p, sha256: sum, size: n, tmp: tmp_path })
    }
}

fn read_names(dfd: &OwnedFd) -> rustix::io::Result<Vec<String>> {
    let dup = rustix::fs::openat(dfd, ".", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())?;
    let mut d = rustix::fs::Dir::read_from(&dup)?;
    let mut names = Vec::new();
    while let Some(e) = d.read() {
        let e = e?;
        let b = e.file_name().to_bytes();
        if b == b"." || b == b".." {
            continue;
        }
        names.push(gotext::lossy(b));
    }
    names.sort();
    Ok(names)
}

/// clamdscan (the running clamd), else clamscan. Exit 0 clean, 1 a match, anything else an error.
pub struct ClamAV;

pub fn look_path(name: &str) -> Option<String> {
    let path = std::env::var("PATH").unwrap_or_default();
    for d in path.split(':') {
        let d = if d.is_empty() { "." } else { d };
        let p = format!("{d}/{name}");
        if let Ok(m) = std::fs::metadata(&p) {
            use std::os::unix::fs::PermissionsExt;
            if m.is_file() && m.permissions().mode() & 0o111 != 0 {
                return Some(p);
            }
        }
    }
    None
}

impl Scanner for ClamAV {
    fn scan(&self, p: &str) -> Result<(String, String), String> {
        let mut last = String::new();
        for argv in [vec!["clamdscan", "--no-summary", "--fdpass", "--", p], vec!["clamscan", "--no-summary", "--", p]] {
            if look_path(argv[0]).is_none() {
                last = format!("exec: {}: executable file not found in $PATH", gotext::quote(argv[0]));
                continue;
            }
            let out = std::process::Command::new(argv[0]).args(&argv[1..]).stdin(std::process::Stdio::null()).stderr(std::process::Stdio::null()).output();
            match out {
                Ok(o) if o.status.success() => return Ok((CLEAN.into(), String::new())),
                Ok(o) if o.status.code() == Some(1) => {
                    let mut sig = "unknown signature".to_string();
                    for line in gotext::lossy(&o.stdout).trim().split('\n') {
                        if let Some(s) = line.strip_suffix(" FOUND") {
                            if let Some(i) = s.find(": ") {
                                if i + 2 < s.len() {
                                    sig = s[i + 2..].to_string();
                                }
                            }
                        }
                    }
                    return Ok((INFECTED.into(), sig));
                }
                Ok(o) => last = format!("{}: exit status {}", argv[0], o.status.code().unwrap_or(-1)),
                Err(e) => last = format!("{}: {}", argv[0], sys::go_err(&e)),
            }
        }
        if last.is_empty() {
            last = "no ClamAV scanner found".into();
        }
        Err(last)
    }
}
