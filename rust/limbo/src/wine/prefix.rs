//! The prefix's own files beside it, outside every sandbox (Go: internal/wine/prefix.go): Limbo's record of what it set,
//! the lock that keeps two runs off one prefix, the marker of a prefix being made, and Limbo's folders.

use crate::gojson::{self, Obj};
use crate::gotext::quote;
use crate::gotime::Time;
use crate::sys;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, Read};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};

/// What Limbo last set in a prefix (Root/.NAME.json).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PrefixRecord {
    pub arch: String,
    pub windows: String,
    pub updated: Time,
}

crate::go_struct!(PrefixRecord as "wine.prefixRecord" {
    arch: "arch" => "string",
    windows: "windows" => "string",
    updated: "updated" => "time.Time",
});

impl PrefixRecord {
    /// json.MarshalIndent(r, "", "  ") and a newline, as writePrefixRecord writes it.
    pub fn to_json(&self) -> String {
        let compact = Obj::new().str("arch", &self.arch).str("windows", &self.windows).str("updated", &self.updated.rfc3339_nano()).end();
        gojson::indent(&compact, "  ") + "\n"
    }
}

/// readPrefixRecord: the record, or None when it cannot be read.
pub fn read_prefix_record(path: &str) -> Option<PrefixRecord> {
    let b = read_small(path, 4 << 10).ok()?;
    gojson::unmarshal(&b, PrefixRecord::default(), "wine.prefixRecord").ok()
}

pub fn write_prefix_record(path: &str, r: &PrefixRecord) -> Result<(), String> {
    write_file_atomic(path, r.to_json().as_bytes())
}

/// prefixExists: Wine has made the prefix (its machine registry is a regular file).
pub fn prefix_exists(prefix: &str) -> bool {
    std::fs::metadata(sys::join(&[prefix, "system.reg"])).is_ok_and(|m| m.is_file())
}

/// prefixArch: "#arch=..." among the registry's first ten lines (bufio.Scanner: a line of 64 KiB or more ends the
/// scan), or "".
pub fn prefix_arch(prefix: &str) -> String {
    let Ok(f) = File::open(sys::join(&[prefix, "system.reg"])) else { return String::new() };
    let mut r = std::io::BufReader::new(f);
    for _ in 0..10 {
        let mut line = Vec::new();
        match (&mut r).take(64 << 10).read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return String::new(),
            Ok(_) => {}
        }
        let terminated = line.last() == Some(&b'\n');
        if terminated {
            line.pop();
        }
        if line.len() >= 64 << 10 {
            return String::new();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let text = crate::gotext::lossy(&line);
        if let Some(a) = crate::gotext::trim_space(&text).strip_prefix("#arch=") {
            return a.to_string();
        }
    }
    String::new()
}

/// ErrBusy's text.
pub const ERR_BUSY: &str = "prefix in use";

/// lockPrefix: holds the prefix for one run (flock, released when the file closes).
pub fn lock_prefix(d: &super::Dirs, name: &str) -> Result<File, String> {
    let path = d.lock_file(name);
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .map_err(|e| sys::go_path_error("open", &path, &e))?;
    if rustix::fs::flock(&f, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_err() {
        let mut b = [0u8; 16];
        let n = f.read_at(&mut b, 0).unwrap_or(0);
        drop(f);
        let text = crate::gotext::lossy(&b[..n]);
        let holder = crate::gotext::trim_space(&text);
        let holder = match go_atoi(holder) {
            true => format!("pid {holder}"),
            false => "another process".into(),
        };
        return Err(format!(
            "wine: prefix {} is already running in another limbo wine ({holder}), and Wine cannot share a prefix between two sandboxes: wait for it to finish (or stop it), or use another --prefix ({ERR_BUSY})",
            quote(name)
        ));
    }
    let _ = f.set_len(0);
    let _ = f.write_at(format!("{}\n", std::process::id()).as_bytes(), 0);
    Ok(f)
}

/// Whether strconv.Atoi accepts s (an optional sign, decimal digits, within int64).
fn go_atoi(s: &str) -> bool {
    let d = s.strip_prefix(['+', '-']).unwrap_or(s);
    !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit()) && s.parse::<i64>().is_ok()
}

/// ensureDir: a folder of Limbo's (0700), not a symlink, the person's own.
pub fn ensure_dir(p: &str) -> Result<(), String> {
    sys::go_mkdir_all(p, 0o700)?;
    let m = std::fs::symlink_metadata(p).map_err(|e| sys::go_path_error("lstat", p, &e))?;
    if !m.is_dir() {
        return Err(format!("wine: {p} is not a folder (a symlink is not accepted)"));
    }
    let uid = rustix::process::getuid().as_raw();
    if m.uid() != uid {
        return Err(format!("wine: {p} belongs to uid {}, not you", m.uid()));
    }
    Ok(())
}

/// writeFileAtomic: a temporary file beside it, then a rename.
pub fn write_file_atomic(path: &str, b: &[u8]) -> Result<(), String> {
    let dir = sys::dir(path);
    let (mut f, tmp) = sys::create_temp(&dir, ".tmp-").map_err(|e| format!("open {dir}/.tmp-*: {}", sys::go_err(&e)))?;
    if let Err(e) = std::io::Write::write_all(&mut f, b) {
        let _ = std::fs::remove_file(&tmp);
        return Err(sys::go_path_error("write", &tmp, &e));
    }
    drop(f);
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("rename {tmp} {path}: {}", sys::go_err(&e)));
    }
    Ok(())
}

/// exists: Lstat does not say "no such file".
pub fn exists(p: &str) -> bool {
    !matches!(std::fs::symlink_metadata(p), Err(e) if e.raw_os_error() == Some(libc::ENOENT))
}

/// readSmall: a regular file of at most max bytes.
pub fn read_small(p: &str, max: u64) -> std::io::Result<Vec<u8>> {
    let f = File::open(p)?;
    let m = f.metadata()?;
    if !m.is_file() || m.len() > max {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }
    let mut b = Vec::new();
    f.take(max).read_to_end(&mut b)?;
    Ok(b)
}
