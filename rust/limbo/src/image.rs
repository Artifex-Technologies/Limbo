//! Base images proven before use (Go: internal/image, image.go and proofs.go; the weekly check stays in Go). Hashed in
//! full once; a root-owned record lets a later start skip the hash only while the file provably is the one hashed
//! (owner, mode, folder, device, inode, size, mtime and ctime). The record file is the Go daemon's, read and written in
//! the same format: either daemon trusts what the other proved.

use crate::gojson::{self, Obj};
use crate::gotime::Time;
use crate::{go_struct, sys};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Mutex;

pub const PROOFS_FILE: &str = "image-proofs.json";
pub const BY_RECORD: &str = "record";
pub const BY_HASH: &str = "full";
pub const BY_MEMORY: &str = "memory";

const FILE_VERSION: i64 = 1;
const MAX_FILE_SIZE: usize = 1 << 20;
const MAX_RECORDS: usize = 1000;
const READ_CHUNK: usize = 1 << 20;
const DROP_CHUNK: u64 = 8 << 20;

/// A failed check: a mismatch (the file is not what the manifest says) or the file's own error.
#[derive(Debug, Clone, PartialEq)]
pub enum CheckErr {
    Mismatch(String),
    /// The file is missing or unreadable; `not_exist` says which (runs classify a missing image apart).
    Io {
        text: String,
        not_exist: bool,
    },
}

impl std::fmt::Display for CheckErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckErr::Mismatch(s) => f.write_str(s),
            CheckErr::Io { text, .. } => f.write_str(text),
        }
    }
}

fn mismatch(path: &str, want: &str, got: &str) -> CheckErr {
    CheckErr::Mismatch(format!("image: checksum mismatch: {path}: manifest says {want}, file is {got}"))
}

fn io_err(op: &str, path: &str, e: &std::io::Error) -> CheckErr {
    CheckErr::Io { text: sys::go_path_error(op, path, e), not_exist: e.kind() == std::io::ErrorKind::NotFound }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sig {
    pub dev: u64,
    pub ino: u64,
    pub size: i64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
}

impl Sig {
    fn of(st: &sys::Stat) -> Sig {
        Sig { dev: st.dev, ino: st.ino, size: st.size, mtime_ns: st.mtime_ns, ctime_ns: st.ctime_ns }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Record {
    pub path: String,
    pub sig: Sig,
    pub sha256: String,
    pub hashed_at: Time,
    pub refused_at: Option<Time>,
    pub found: String,
}

// Go embeds Sig in Record, so its fields are read as the record's own. (Go names a type error in them
// Record.images.Sig.dev, the port Record.images.dev; the text only ever says why a damaged file was ignored.)
impl gojson::FromGo for Record {
    fn read(&mut self, v: &gojson::Value, cx: &mut gojson::Ctx, ty: &str) {
        const NAMES: &[&str] = &["path", "dev", "ino", "size", "mtime_ns", "ctime_ns", "sha256", "hashed_at", "refused_at", "found"];
        cx.read_struct(v, "Record", ty, NAMES, |i, val, cx| match i {
            0 => self.path.read(val, cx, "string"),
            1 => self.sig.dev.read(val, cx, "uint64"),
            2 => self.sig.ino.read(val, cx, "uint64"),
            3 => self.sig.size.read(val, cx, "int64"),
            4 => self.sig.mtime_ns.read(val, cx, "int64"),
            5 => self.sig.ctime_ns.read(val, cx, "int64"),
            6 => self.sha256.read(val, cx, "string"),
            7 => self.hashed_at.read(val, cx, "time.Time"),
            8 => self.refused_at.read(val, cx, "*time.Time"),
            _ => self.found.read(val, cx, "string"),
        });
    }
}

impl Record {
    pub fn refused(&self) -> bool {
        self.refused_at.is_some()
    }

    fn json(&self) -> String {
        let mut o = Obj::new()
            .str("path", &self.path)
            .raw("dev", &self.sig.dev.to_string())
            .raw("ino", &self.sig.ino.to_string())
            .int("size", self.sig.size)
            .int("mtime_ns", self.sig.mtime_ns)
            .int("ctime_ns", self.sig.ctime_ns)
            .str("sha256", &self.sha256)
            .str("hashed_at", &self.hashed_at.rfc3339_nano());
        if let Some(t) = &self.refused_at {
            o = o.str("refused_at", &t.rfc3339_nano());
        }
        o.str_omit("found", &self.found).end()
    }

    fn valid(&self) -> Result<(), String> {
        let hex = |s: &str| s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
        let q = crate::gotext::quote(&self.path);
        if !self.path.starts_with('/') || sys::clean(&self.path) != self.path {
            return Err(format!("record path {q} is not a clean absolute path"));
        }
        if !hex(&self.sha256) {
            return Err(format!("record for {}: bad sha256", self.path));
        }
        if !self.found.is_empty() && !hex(&self.found) {
            return Err(format!("record for {}: bad found", self.path));
        }
        if self.sig.size < 0 || self.hashed_at.is_zero() {
            return Err(format!("record for {}: bad size or time", self.path));
        }
        if self.refused_at.is_none() != self.found.is_empty() {
            return Err(format!("record for {}: a refusal needs both its time and what was found", self.path));
        }
        Ok(())
    }
}

#[derive(Default)]
struct RecordFile {
    version: i64,
    images: Option<Vec<Record>>,
}
go_struct!(RecordFile as "image.recordFile" { version: "version" => "int", images: "images" => "[]image.Record" });

/// One record for `limbo image list`.
#[derive(Clone, Debug)]
pub struct Status {
    pub record: Record,
    /// Whether a start would skip the hash now (for a manifest asking for the recorded SHA-256); `why` says why not.
    pub quick: bool,
    pub why: String,
}

pub const RESULT_OK: &str = "ok";
pub const RESULT_DROPPED: &str = "dropped";
pub const RESULT_CHANGED: &str = "changed";
pub const RESULT_GONE: &str = "gone";
pub const RESULT_ERROR: &str = "error";

/// One recorded image's result in the weekly check (Go's Outcome).
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    pub path: String,
    pub result: &'static str,
    pub detail: String,
    pub recorded: String,
    pub found: String,
    /// The file's device, inode, size and times were still those recorded (a change with no trace in its metadata).
    pub stat_same: bool,
    /// Not refused before for the same content (so the event is not repeated every week).
    pub newly_refused: bool,
    pub took_ns: i64,
}

/// How the weekly check failed: the record file was ignored (Go's ErrRecordsIgnored, with why), or anything else.
#[derive(Debug)]
pub enum VerifyErr {
    Ignored(String),
    Other(String),
}

/// What load made of the record file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileState {
    Missing,
    Ok,
    Ignored,
}

/// Remembers which images were hashed in full (the record file) and, for listings, what this process hashed itself.
pub struct Proofs {
    pub path: String,
    pub owner: u32,
    memory: Mutex<BTreeMap<String, (Sig, String)>>,
    pub now: fn() -> Time,
}

impl Proofs {
    pub fn new(path: &str, owner: u32) -> Proofs {
        Proofs { path: path.to_string(), owner, memory: Mutex::new(BTreeMap::new()), now: Time::now }
    }

    /// Proves that `path` has SHA-256 `want`: from its record when every rule holds, by a full hash otherwise.
    pub fn check(&self, path: &str, want: &str) -> (&'static str, Result<(), CheckErr>) {
        let path = sys::clean(path);
        if !self.path.is_empty() {
            let recs = self.load().0;
            if let Some(rec) = recs.get(&path) {
                if !rec.refused() && rec.sha256 == want {
                    if let Ok(s) = self.eligible(&path) {
                        if s == rec.sig {
                            return (BY_RECORD, Ok(()));
                        }
                    }
                }
            }
        }
        self.hash(&path, want)
    }

    /// Check for listing profiles, never for a start: also takes what this process hashed itself, unchanged since.
    pub fn check_cached(&self, path: &str, want: &str) -> (&'static str, Result<(), CheckErr>) {
        let path = sys::clean(path);
        let recs = self.load().0;
        let rec = recs.get(&path);
        if rec.is_some_and(|r| r.refused()) {
            return self.hash(&path, want);
        }
        if let Some(rec) = rec.filter(|r| r.sha256 == want) {
            if let Ok(s) = self.eligible(&path) {
                if s == rec.sig {
                    return (BY_RECORD, Ok(()));
                }
            }
        }
        let mem = self.memory.lock().unwrap_or_else(|e| e.into_inner()).get(&path).cloned();
        if let Some((sig, sum)) = mem {
            if sum == want {
                if let Ok(m) = std::fs::metadata(&path) {
                    if Sig::of(&sys::Stat::of(&m)) == sig {
                        return (BY_MEMORY, Ok(()));
                    }
                }
            }
        }
        self.hash(&path, want)
    }

    fn hash(&self, path: &str, want: &str) -> (&'static str, Result<(), CheckErr>) {
        let (sum, before, stable) = match hash_path(path) {
            Ok(x) => x,
            Err(e) => return (BY_HASH, Err(e)),
        };
        if sum != want {
            return (BY_HASH, Err(mismatch(path, want, &sum)));
        }
        if !stable {
            return (BY_HASH, Ok(()));
        }
        self.memory.lock().unwrap_or_else(|e| e.into_inner()).insert(path.to_string(), (before, sum.clone()));
        if !self.path.is_empty() && rustix::process::geteuid().as_raw() == self.owner {
            if let Ok(s) = self.eligible(path) {
                if s == before {
                    let rec = Record {
                        path: path.to_string(),
                        sig: before,
                        sha256: sum,
                        hashed_at: (self.now)().utc(),
                        refused_at: None,
                        found: String::new(),
                    };
                    let _ = self.update(|recs| {
                        recs.insert(rec.path.clone(), rec.clone());
                    });
                }
            }
        }
        (BY_HASH, Ok(()))
    }

    fn owner_name(&self) -> String {
        if self.owner == 0 {
            "root".into()
        } else {
            format!("uid {}", self.owner)
        }
    }

    /// The ownership rules on the image and its folder; never follows a link at the last step.
    fn eligible(&self, path: &str) -> Result<Sig, String> {
        let m = std::fs::symlink_metadata(path).map_err(|e| sys::go_path_error("lstat", path, &e))?;
        let st = sys::Stat::of(&m);
        if !st.is_regular() {
            return Err("not a regular file (a link or something else)".into());
        }
        if st.uid != self.owner {
            return Err(format!("owned by uid {}, not {}", st.uid, self.owner_name()));
        }
        if st.perm() & 0o022 != 0 {
            return Err("writable by group or others".into());
        }
        self.own_folder(&sys::dir(path))?;
        Ok(Sig::of(&st))
    }

    fn own_folder(&self, dir: &str) -> Result<(), String> {
        let m = std::fs::metadata(dir).map_err(|e| sys::go_path_error("stat", dir, &e))?;
        let st = sys::Stat::of(&m);
        if !st.is_dir() {
            return Err(format!("{dir} is not a folder"));
        }
        if st.uid != self.owner {
            return Err(format!("its folder {dir} is owned by uid {}, not {}", st.uid, self.owner_name()));
        }
        if st.perm() & 0o022 != 0 {
            return Err(format!("its folder {dir} is writable by group or others"));
        }
        Ok(())
    }

    /// The trusted records, keyed by path (empty when the file is missing, damaged or not Owner's), and why the file was
    /// ignored (`Some` only then).
    pub fn load(&self) -> (BTreeMap<String, Record>, Option<String>) {
        let (m, _, why) = self.load_why();
        (m, why)
    }

    /// Go's loadWhy: the records, what was made of the file, and why it was ignored (Go's texts).
    pub fn load_why(&self) -> (BTreeMap<String, Record>, FileState, Option<String>) {
        let empty = BTreeMap::new();
        if self.path.is_empty() {
            return (empty, FileState::Missing, None);
        }
        let m = match std::fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (empty, FileState::Missing, None),
            Err(e) => return (empty, FileState::Ignored, Some(sys::go_path_error("lstat", &self.path, &e))),
            Ok(m) => m,
        };
        let st = sys::Stat::of(&m);
        if !st.is_regular() {
            return (empty, FileState::Ignored, Some("the record file is not a regular file".into()));
        }
        if st.uid != self.owner {
            return (empty, FileState::Ignored, Some(format!("the record file is owned by uid {}, not {}", st.uid, self.owner_name())));
        }
        if st.perm() & 0o022 != 0 {
            return (empty, FileState::Ignored, Some("the record file is writable by group or others".into()));
        }
        if let Err(e) = self.own_folder(&sys::dir(&self.path)) {
            return (empty, FileState::Ignored, Some(format!("the record file's folder: {e}")));
        }
        let mut f = match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&self.path) {
            Ok(f) => f,
            Err(e) => return (empty, FileState::Ignored, Some(sys::go_path_error("open", &self.path, &e))),
        };
        match f.metadata() {
            Ok(fm) if sys::Stat::of(&fm).dev == st.dev && sys::Stat::of(&fm).ino == st.ino => {}
            _ => return (empty, FileState::Ignored, Some("the record file changed while it was opened".into())),
        }
        let mut b = Vec::new();
        if let Err(e) = (&mut f).take(MAX_FILE_SIZE as u64 + 1).read_to_end(&mut b) {
            return (empty, FileState::Ignored, Some(sys::go_path_error("read", &self.path, &e)));
        }
        if b.len() > MAX_FILE_SIZE {
            return (empty, FileState::Ignored, Some("the record file is too large".into()));
        }
        let (v, more) = match gojson::parse_first_more(&b) {
            Ok(x) => x,
            Err(e) => return (empty, FileState::Ignored, Some(format!("the record file is damaged: {e}"))),
        };
        let mut cx = gojson::Ctx::new(true);
        let mut rf = RecordFile::default();
        gojson::FromGo::read(&mut rf, &v, &mut cx, "image.recordFile");
        if let Err(e) = cx.finish() {
            return (empty, FileState::Ignored, Some(format!("the record file is damaged: {e}")));
        }
        if more {
            return (empty, FileState::Ignored, Some("the record file is damaged: data after the record".into()));
        }
        if rf.version != FILE_VERSION {
            return (empty, FileState::Ignored, Some(format!("the record file has version {}, not {FILE_VERSION}", rf.version)));
        }
        let images = rf.images.unwrap_or_default();
        if images.len() > MAX_RECORDS {
            return (empty, FileState::Ignored, Some("the record file holds too many records".into()));
        }
        let mut out = BTreeMap::new();
        for r in images {
            if let Err(e) = r.valid() {
                return (empty, FileState::Ignored, Some(format!("the record file is damaged: {e}")));
            }
            if out.contains_key(&r.path) {
                return (empty, FileState::Ignored, Some(format!("the record file is damaged: {} twice", r.path)));
            }
            out.insert(r.path.clone(), r);
        }
        (out, FileState::Ok, None)
    }

    /// Go's List: every record (sorted by path) with whether a start would skip the hash now and why not, what load
    /// made of the file, and why it was ignored.
    pub fn list(&self) -> (Vec<Status>, FileState, Option<String>) {
        let (recs, st, why) = self.load_why();
        let out = recs
            .into_values()
            .map(|r| {
                let (quick, why) = if r.refused() {
                    (false, format!("refused by the weekly check: it hashed to {}", r.found))
                } else {
                    match self.eligible(&r.path) {
                        Err(e) => (false, e),
                        Ok(sig) if sig != r.sig => (false, "changed since it was hashed (the next start hashes it in full)".into()),
                        Ok(_) => (true, String::new()),
                    }
                };
                Status { record: r, quick, why }
            })
            .collect();
        (out, st, why)
    }

    /// Go's VerifyAll, the weekly check: every recorded image hashed in full again and compared with its record, each
    /// reported as soon as it is done, then the records renewed, dropped or marked refused (only where nobody replaced
    /// them meanwhile). `Err(Ignored(why))` when the record file cannot be trusted.
    pub fn verify_all(&self, report: &mut dyn FnMut(&Outcome)) -> Result<Vec<Outcome>, VerifyErr> {
        if self.path.is_empty() {
            return Err(VerifyErr::Other("image proofs: no record file".into()));
        }
        let (recs, st, why) = self.load_why();
        if st == FileState::Ignored {
            return Err(VerifyErr::Ignored(why.unwrap_or_default()));
        }
        let mut outs = vec![];
        let mut apply: Vec<(Record, Option<Record>)> = vec![]; // (as checked, replacement or None to drop)
        for (path, rec) in recs {
            let start = std::time::Instant::now();
            let mut o = Outcome { path: path.clone(), recorded: rec.sha256.clone(), ..Default::default() };
            let r = hash_path(&path);
            o.took_ns = start.elapsed().as_nanos() as i64;
            match r {
                Err(CheckErr::Io { not_exist: true, .. }) => {
                    o.result = RESULT_GONE;
                    o.detail = "the file is not there any more".into();
                    apply.push((rec, None));
                }
                Err(e) => {
                    o.result = RESULT_ERROR;
                    o.detail = e.to_string();
                }
                Ok((_, _, false)) => {
                    o.result = RESULT_DROPPED;
                    o.detail = "it changed while it was read".into();
                    apply.push((rec, None));
                }
                Ok((sum, before, true)) if sum == rec.sha256 => match self.eligible(&path) {
                    Err(e) => {
                        o.result = RESULT_DROPPED;
                        o.detail = format!("not eligible for the quick check: {e}");
                        apply.push((rec, None));
                    }
                    Ok(sig) if sig != before => {
                        o.result = RESULT_DROPPED;
                        o.detail = "the path names another file than the one read".into();
                        apply.push((rec, None));
                    }
                    Ok(_) => {
                        o.result = RESULT_OK;
                        let renewed = Record {
                            path: path.clone(),
                            sig: before,
                            sha256: sum,
                            hashed_at: (self.now)().utc(),
                            refused_at: None,
                            found: String::new(),
                        };
                        apply.push((rec, Some(renewed)));
                    }
                },
                Ok((sum, before, true)) => {
                    o.result = RESULT_CHANGED;
                    o.stat_same = before == rec.sig;
                    o.newly_refused = !rec.refused() || rec.found != sum;
                    o.detail = format!("it hashes to {sum}, not to the {} it was proven to have", rec.sha256);
                    let mut refused = rec.clone();
                    if o.newly_refused {
                        refused.refused_at = Some((self.now)().utc());
                        refused.found = sum.clone();
                    }
                    o.found = sum;
                    apply.push((rec, Some(refused)));
                }
            }
            report(&o);
            outs.push(o);
        }
        if apply.is_empty() {
            return Ok(outs);
        }
        self.update(|cur| {
            for (was, now) in apply {
                // only a record nobody replaced meanwhile (Go's sameRecord: times compared as instants)
                if cur.get(&was.path).is_some_and(|r| *r == was) {
                    match now {
                        Some(n) => {
                            cur.insert(was.path.clone(), n);
                        }
                        None => {
                            cur.remove(&was.path);
                        }
                    }
                }
            }
        })
        .map_err(VerifyErr::Other)?;
        Ok(outs)
    }

    fn update(&self, change: impl FnOnce(&mut BTreeMap<String, Record>)) -> Result<(), String> {
        self.own_folder(&sys::dir(&self.path)).map_err(|e| format!("image proofs: not written: {e}"))?;
        let lock = format!("{}.lock", self.path);
        let _l = sys::lock_file(&lock).map_err(|e| sys::go_path_error("open", &lock, &e))?;
        let mut recs = self.load().0;
        change(&mut recs);
        self.save(&recs).map_err(|e| sys::go_err(&e))
    }

    fn save(&self, recs: &BTreeMap<String, Record>) -> std::io::Result<()> {
        // sorted by path (the map's order), at most MAX_RECORDS
        let items: Vec<String> = recs.values().take(MAX_RECORDS).map(Record::json).collect();
        let doc = Obj::new().int("version", FILE_VERSION).raw("images", &gojson::list(&items)).end();
        let b = gojson::indent(&doc, "  ") + "\n";
        let (mut f, tmp) = sys::create_temp(&sys::dir(&self.path), ".image-proofs-*")?;
        let r = (|| {
            use std::io::Write;
            sys::chmod(&tmp, 0o600)?;
            f.write_all(b.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.path)
        })();
        if r.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        r
    }
}

/// Opens and hashes the file (following a link, as before), with its signature when opened and whether it was the same
/// after the hash.
fn hash_path(path: &str) -> Result<(String, Sig, bool), CheckErr> {
    let f = std::fs::File::open(path).map_err(|e| io_err("open", path, &e))?;
    let before = Sig::of(&sys::Stat::of(&f.metadata().map_err(|e| io_err("stat", path, &e))?));
    let sum = hash_open(&f).map_err(|e| io_err("read", path, &e))?;
    let after = Sig::of(&sys::Stat::of(&f.metadata().map_err(|e| io_err("stat", path, &e))?));
    Ok((sum, before, after == before))
}

/// SHA-256 of the file from its current offset, dropping what was read from the page cache as it goes.
pub fn hash_open(mut f: &std::fs::File) -> std::io::Result<String> {
    use rustix::fs::Advice;
    sys::fadvise(f, 0, 0, Advice::Sequential);
    let mut h = Sha256::new();
    let mut buf = vec![0u8; READ_CHUNK];
    let (mut off, mut kept) = (0u64, 0u64);
    loop {
        let n = match f.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                sys::fadvise(f, 0, 0, Advice::DontNeed);
                return Err(e);
            }
        };
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        off += n as u64;
        if off - kept >= DROP_CHUNK {
            sys::fadvise(f, kept, off - kept, Advice::DontNeed);
            kept = off;
        }
    }
    sys::fadvise(f, 0, 0, Advice::DontNeed);
    Ok(sys::hex(&h.finalize()))
}
